//! Structural-composer concurrent-write precedence + dedup
//! (v3.0.0, CIRISPersist#116 — CEG 0.2 §6.1 conformance).
//!
//! # What this module is
//!
//! Persist stores the four structural composers
//! ([`super::types::attestation_type::DELEGATES_TO`] /
//! [`super::types::attestation_type::SUPERSEDES`] /
//! [`super::types::attestation_type::WITHDRAWS`] /
//! [`super::types::attestation_type::RECANTS`]) on
//! `federation_attestations` as audit-trail rows. Each composer
//! references an upstream attestation via its envelope's
//! `references_attestation_id` field
//! ([CEG §3.2](../../../CIRISRegistry/FSD/CEG/03_primitives.md)).
//!
//! Two disciplines apply:
//!
//! 1. **Dedup at write** — a replay of the same composer is a typed
//!    `Ok(())` no-op. The dedup key is the triple
//!    `(references_attestation_id, attestation_type, attesting_key_id)`
//!    — same shape as the V043 master-key idempotent contract and the
//!    `holds_bytes` SHA-collapse pattern. Backends call
//!    [`is_dedup_match`] before INSERT.
//!
//! 2. **Precedence at read** — when two structural composers from
//!    the same attester target the same upstream attestation, the
//!    consumer-visible "current effective state" is the
//!    precedence-winner per CEG §6.1:
//!    - **`recants` outranks `withdraws` outranks `supersedes`**
//!      regardless of `signed_at` (a falsity admission cannot be
//!      subsumed by a retraction or replacement).
//!    - Same-`attestation_type` ties: largest `asserted_at` wins.
//!    - Same-`asserted_at` ties: lexicographically smallest
//!      `attestation_id` wins (stable, deterministic — closes CEG
//!      §6.1 footnote 3).
//!
//!    The WRITE path stores everything (so the audit chain is
//!    complete); the READ path applies precedence so consumers see
//!    a stable answer.
//!
//! # Cross-attester chains
//!
//! Per CEG §6.1 rule 4, two attesters emitting composers against the
//! same upstream are TWO independent chains — the consumer sees both
//! and applies §8 composition policy. This module's
//! [`precedence_winner`] groups by `(attesting_key_id,
//! references_attestation_id)` and returns one winner per group;
//! callers that want a single "the winner" answer collapse the
//! per-attester winners with their own policy.
//!
//! # Scope
//!
//! - `DELEGATES_TO` is NOT subject to the §6.1 precedence rule —
//!   delegation is a forward-looking authorization, not a composer
//!   over a prior attestation. It carries a different envelope shape
//!   (`delegated_scope[]` etc., no `references_attestation_id`).
//!   Dedup on delegates_to is out of scope for this module.
//! - `SCORES` is not a structural composer.

use super::types::{attestation_type, Attestation};

/// Extract `references_attestation_id` from a structural composer's
/// envelope. Returns `None` for envelopes that lack the field, have
/// it as a non-string, or for non-composer rows. The four structural
/// composers ([`attestation_type::SUPERSEDES`] /
/// [`attestation_type::WITHDRAWS`] / [`attestation_type::RECANTS`])
/// REQUIRE this field per CEG §3.2; an emitter that omits it produces
/// a row this helper treats as un-grouped (it won't dedup or apply
/// precedence — the read-side composition policy decides what to do
/// with an envelope that fails its own schema).
pub fn references_attestation_id_from_envelope(envelope: &serde_json::Value) -> Option<&str> {
    envelope
        .get("references_attestation_id")
        .and_then(|v| v.as_str())
}

/// True iff the attestation type is one of the three structural
/// composers subject to the CEG §6.1 dedup + precedence rule
/// ([`attestation_type::SUPERSEDES`] / [`attestation_type::WITHDRAWS`]
/// / [`attestation_type::RECANTS`]). `DELEGATES_TO` is excluded — see
/// module docs §"Scope".
pub fn is_structural_composer(attestation_type_str: &str) -> bool {
    matches!(
        attestation_type_str,
        attestation_type::SUPERSEDES | attestation_type::WITHDRAWS | attestation_type::RECANTS
    )
}

/// Numeric rank for the §6.1 precedence rule. **Higher rank wins.**
/// Values are stable token-shape: `RECANTS=3 > WITHDRAWS=2 >
/// SUPERSEDES=1`. Non-composers return 0 (they never win precedence
/// because they're not in the structural-composer set).
pub fn composer_rank(attestation_type_str: &str) -> u8 {
    match attestation_type_str {
        attestation_type::RECANTS => 3,
        attestation_type::WITHDRAWS => 2,
        attestation_type::SUPERSEDES => 1,
        _ => 0,
    }
}

/// Returns `true` iff `candidate` is a structural composer whose
/// `(references_attestation_id, attestation_type, attesting_key_id)`
/// matches `existing`. Used by both backends' `put_attestation` to
/// short-circuit dedup before INSERT.
///
/// Both rows must already be structural composers; a candidate that
/// is not a composer returns `false` (callers should skip the dedup
/// check entirely for non-composers).
pub fn is_dedup_match(existing: &Attestation, candidate: &Attestation) -> bool {
    if !is_structural_composer(&candidate.attestation_type) {
        return false;
    }
    if existing.attestation_type != candidate.attestation_type {
        return false;
    }
    if existing.attesting_key_id != candidate.attesting_key_id {
        return false;
    }
    let existing_ref = references_attestation_id_from_envelope(&existing.attestation_envelope);
    let candidate_ref = references_attestation_id_from_envelope(&candidate.attestation_envelope);
    match (existing_ref, candidate_ref) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

/// Apply the CEG §6.1 precedence rule to a slice of structural
/// composers and return the winner.
///
/// The caller is responsible for narrowing the slice to composers
/// from a SINGLE `(attesting_key_id, references_attestation_id)`
/// group — per CEG §6.1 rule 4, cross-attester chains are evaluated
/// independently and DO NOT collapse to a single winner here.
///
/// Tie-break order (largest-wins):
/// 1. `composer_rank` ([`composer_rank`])
/// 2. `asserted_at` (latest wins)
/// 3. lexicographic `attestation_id` (smallest wins — note the
///    inversion: every other axis is largest-wins, this one is
///    smallest-wins because §6.1 names lex-smallest as the
///    stable tie-break)
///
/// Returns `None` for an empty slice.
pub fn precedence_winner<'a>(group: &'a [&'a Attestation]) -> Option<&'a Attestation> {
    if group.is_empty() {
        return None;
    }
    let mut best = group[0];
    for candidate in &group[1..] {
        if wins(candidate, best) {
            best = candidate;
        }
    }
    Some(best)
}

/// True iff `a` outranks `b` per the §6.1 precedence rule. Private
/// helper for [`precedence_winner`]; exposed via the public surface
/// as the precedence rule itself.
fn wins(a: &Attestation, b: &Attestation) -> bool {
    let ra = composer_rank(&a.attestation_type);
    let rb = composer_rank(&b.attestation_type);
    if ra != rb {
        return ra > rb;
    }
    // Same type — latest signed_at wins.
    if a.asserted_at != b.asserted_at {
        return a.asserted_at > b.asserted_at;
    }
    // Same signed_at — lex-smallest attestation_id wins. Note this
    // is the inversion: a < b means a wins. Matches CEG §6.1 rule 3
    // verbatim.
    a.attestation_id < b.attestation_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn comp(
        id: &str,
        attester: &str,
        ty: &str,
        upstream: &str,
        ts: chrono::DateTime<chrono::Utc>,
    ) -> Attestation {
        Attestation {
            attestation_id: id.into(),
            attesting_key_id: attester.into(),
            attested_key_id: attester.into(),
            attestation_type: ty.into(),
            weight: None,
            asserted_at: ts,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "references_attestation_id": upstream,
                "withdrawal_reason": "test",
            }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.into(),
            scrub_timestamp: ts,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
        }
    }

    fn t(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    #[test]
    fn structural_composer_set() {
        assert!(is_structural_composer("supersedes"));
        assert!(is_structural_composer("withdraws"));
        assert!(is_structural_composer("recants"));
        // Excluded — see module docs §"Scope".
        assert!(!is_structural_composer("delegates_to"));
        assert!(!is_structural_composer("scores"));
        assert!(!is_structural_composer("garbage"));
    }

    #[test]
    fn ranks_recants_above_withdraws_above_supersedes() {
        assert!(composer_rank("recants") > composer_rank("withdraws"));
        assert!(composer_rank("withdraws") > composer_rank("supersedes"));
        assert_eq!(composer_rank("scores"), 0);
    }

    #[test]
    fn extracts_references_id_from_envelope() {
        let env = serde_json::json!({"references_attestation_id": "upstream-1"});
        assert_eq!(
            references_attestation_id_from_envelope(&env),
            Some("upstream-1")
        );
        let no = serde_json::json!({"score": 1.0});
        assert_eq!(references_attestation_id_from_envelope(&no), None);
        let wrong_type = serde_json::json!({"references_attestation_id": 42});
        assert_eq!(references_attestation_id_from_envelope(&wrong_type), None);
    }

    #[test]
    fn dedup_matches_on_triple() {
        let a = comp("a", "attester-1", "withdraws", "upstream-1", t(0));
        let b = comp("b", "attester-1", "withdraws", "upstream-1", t(60));
        assert!(is_dedup_match(&a, &b));
        // Different attestation_type → not a dedup match.
        let c = comp("c", "attester-1", "recants", "upstream-1", t(0));
        assert!(!is_dedup_match(&a, &c));
        // Different attester → not a match.
        let d = comp("d", "attester-2", "withdraws", "upstream-1", t(0));
        assert!(!is_dedup_match(&a, &d));
        // Different upstream → not a match.
        let e = comp("e", "attester-1", "withdraws", "upstream-2", t(0));
        assert!(!is_dedup_match(&a, &e));
        // Non-composer candidate → not a match (caller should skip the
        // dedup check entirely; the helper returns false defensively).
        let s = comp("s", "attester-1", "scores", "upstream-1", t(0));
        assert!(!is_dedup_match(&a, &s));
    }

    #[test]
    fn precedence_recants_wins_over_withdraws_regardless_of_time() {
        let recants = comp("r", "attester-1", "recants", "upstream-1", t(0));
        let withdraws_later = comp("w", "attester-1", "withdraws", "upstream-1", t(86_400));
        let group: Vec<&Attestation> = vec![&recants, &withdraws_later];
        let winner = precedence_winner(&group).expect("non-empty");
        assert_eq!(winner.attestation_id, "r");
    }

    #[test]
    fn precedence_withdraws_wins_over_supersedes_regardless_of_time() {
        let supersedes_later = comp("s", "attester-1", "supersedes", "upstream-1", t(86_400));
        let withdraws_earlier = comp("w", "attester-1", "withdraws", "upstream-1", t(0));
        let group: Vec<&Attestation> = vec![&supersedes_later, &withdraws_earlier];
        let winner = precedence_winner(&group).expect("non-empty");
        assert_eq!(winner.attestation_id, "w");
    }

    #[test]
    fn precedence_latest_signed_at_wins_within_same_type() {
        let earlier = comp("a", "attester-1", "withdraws", "upstream-1", t(0));
        let later = comp("b", "attester-1", "withdraws", "upstream-1", t(60));
        let group: Vec<&Attestation> = vec![&earlier, &later];
        let winner = precedence_winner(&group).expect("non-empty");
        assert_eq!(winner.attestation_id, "b");
    }

    #[test]
    fn precedence_lex_smallest_attestation_id_breaks_signed_at_tie() {
        let big = comp("zzz", "attester-1", "withdraws", "upstream-1", t(0));
        let small = comp("aaa", "attester-1", "withdraws", "upstream-1", t(0));
        let mid = comp("mmm", "attester-1", "withdraws", "upstream-1", t(0));
        let group: Vec<&Attestation> = vec![&big, &small, &mid];
        let winner = precedence_winner(&group).expect("non-empty");
        // CEG §6.1 rule 3 — lex-smallest wins on signed_at tie.
        assert_eq!(winner.attestation_id, "aaa");
    }

    #[test]
    fn precedence_empty_group_returns_none() {
        let group: Vec<&Attestation> = vec![];
        assert!(precedence_winner(&group).is_none());
    }
}
