//! Structural-composer concurrent-write precedence + dedup
//! (v3.0.0, CIRISPersist#116 — CEG 0.2 §6.1 conformance).
//!
//! # What this module is
//!
//! Persist stores the four structural composers
//! ([`super::types::attestation_type::DELEGATES_TO`] /
//! [`super::types::attestation_type::SUPERSEDES`] /
//! [`attestation_type::WITHDRAWS`] /
//! [`attestation_type::RECANTS`]) on
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
        .get(crate::federation::envelope::paths::REFERENCES_ATTESTATION_ID)
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

/// v36.0.0 (CIRISPersist#686) — is `g` (a `withdraws`/`recants` composer)
/// ENTITLED to retract `target`?
///
/// The #656 entitlement predicate, hoisted out of
/// `admission::retracted_edge_ids` so the consolidated fold below and every
/// future fold share ONE spelling:
///
/// 1. the target's own attester (self-retraction — §6.1 rule 1);
/// 2. a member of the target's `subject_key_ids` (subject-side revocation —
///    rule 2);
/// 3. a key the WRITE door already resolved authority for
///    (`withdraws_admission_rule.is_some()` — the BFS-derived rules 3/4 that
///    no sync fold can recompute).
///
/// `withdraws_admission_rule` is `None` for several distinct reasons
/// (deferred out-of-order admission, malformed, non-`withdraws`), so arm 3
/// is only ever an ADMITTING arm, never the sole test.
pub fn retraction_entitled(g: &Attestation, target: &Attestation) -> bool {
    g.attesting_key_id == target.attesting_key_id
        || target.subject_key_ids.contains(&g.attesting_key_id)
        || g.withdraws_admission_rule.is_some()
}

/// v36.0.0 (CIRISPersist#686) — **THE consolidated retraction fold.**
///
/// Three folds used to decide "retracted" and disagreed:
/// `trust_root::tombstoned_ids` had §6.1 precedence but NO entitlement check
/// (so on the two many-attester trust-root slices — the conferral walk and
/// the family-charter filter — a foreign, unentitled `withdraws` admitted
/// through the out-of-order window severed a conferral or silently emptied a
/// charter quorum's candidate set); `admission::retracted_edge_ids` had the
/// #656 entitlement gate but no precedence (any entitled retraction killed,
/// with no §6.1 winner). Neither alone was sufficient, so the consolidated
/// fold is a SYNTHESIS, not a selection. Both former folds now delegate here.
///
/// The rule, per target id:
///
/// 1. collect every structural composer in `rows` naming the target;
/// 2. drop a `withdraws`/`recants` whose attester is not
///    [`retraction_entitled`] against the target row — resolved from THIS
///    same slice, adding no read. A retraction whose target is not in the
///    slice is dropped too (*a retraction I cannot resolve is a retraction I
///    do not apply* — membership tests at every call site made such an entry
///    inert already, so this is behaviour-preserving there and fail-secure
///    everywhere else). `supersedes` rows are not filtered: they rank BELOW
///    both retraction forms, so an unentitled `supersedes` can never flip a
///    target dead;
/// 3. the §6.1 [`precedence_winner`] of what remains decides: dead iff the
///    winner is `withdraws` or `recants`.
///
/// The WRITE-door refusal (`check_withdraws_admission` →
/// `WithdrawsNotAdmitted` for an unentitled retraction of a locally-present
/// target) is deliberately unchanged and load-bearing: it is what keeps this
/// read-side fold unreachable for in-order traffic, and the #686 witnesses
/// pin it as leg A on both trust-root planes.
pub fn retired_ids(rows: &[&Attestation]) -> std::collections::HashSet<String> {
    use std::collections::HashMap;
    let by_id: HashMap<&str, &Attestation> = rows
        .iter()
        .map(|r| (r.attestation_id.as_str(), *r))
        .collect();
    let mut by_target: HashMap<&str, Vec<&Attestation>> = HashMap::new();
    for row in rows {
        if !is_structural_composer(&row.attestation_type) {
            continue;
        }
        let Some(target) = references_attestation_id_from_envelope(&row.attestation_envelope)
        else {
            continue;
        };
        let is_retraction = row.attestation_type == attestation_type::WITHDRAWS
            || row.attestation_type == attestation_type::RECANTS;
        if is_retraction {
            // The entitlement gate (#686/#656). Fail-secure toward RETENTION:
            // an unresolvable or unentitled retraction does not enter the
            // precedence group at all.
            match by_id.get(target) {
                Some(target_row) if retraction_entitled(row, target_row) => {}
                _ => continue,
            }
        }
        by_target.entry(target).or_default().push(row);
    }
    let mut dead = std::collections::HashSet::new();
    for (target, composers) in by_target {
        if let Some(winner) = precedence_winner(&composers) {
            if winner.attestation_type == attestation_type::WITHDRAWS
                || winner.attestation_type == attestation_type::RECANTS
            {
                dead.insert(target.to_owned());
            }
        }
    }
    dead
}

/// CIRISPersist#579 (CC 4.5.1.1, rc3) — the shared, backend-agnostic witness
/// that **the pointer confers no subject authority**.
///
/// rc3 removed one of this pointer's three readings: *"under subject-binding
/// (pointer = data subject) → **not admitted**. Subject authority rides
/// `subject_key_ids` and nothing else … a processor MUST NOT establish
/// `data_subject` from `references_attestation_id`."*
///
/// Removing a *semantic claim about what a reference means* changes which rows
/// count as being ABOUT a data subject — consent, erasure and reachability all
/// key on that. So the claim that persist never took the reading is not
/// asserted here, it is exercised: through the REAL write path, on every
/// backend, with positive controls on both sides so a green run cannot mean
/// "nothing happened".
///
/// - The **removal**: `S`, the subject of `P`, may NOT revoke `R` — a row whose
///   only relation to `S` is that it points at `P`. Under the dropped reading
///   `S` would be `R`'s data subject and rule 2 would admit.
/// - **Control A** (subject authority is live): `S` MAY revoke `P` itself,
///   admitted under rule 2 — so the refusal above is about the pointer, not a
///   broken fixture.
/// - **Control B** (the admitted reading is live): `P`'s producer revokes `R`,
///   and the tombstone fold FOLLOWS THE POINTER to retire it — the removal did
///   not make the pointer inert, it removed one of its three meanings.
/// - The **read surface**: a subject-keyed query for `S` returns `P` and never
///   `R`. This is the erasure/DSAR shape (`attestations.where(s ∈
///   subject_key_ids)`, CC 4.5.2.2 GDPR Art. 20). All three backends implement
///   it; a backend that answered `Unsupported` would skip this arm and run the
///   rest, and any OTHER error fails loudly rather than skipping.
#[cfg(test)]
pub(crate) mod test_support {
    use crate::federation::types::{attestation_tier, attestation_type, Attestation};
    use crate::federation::{FederationDirectory, SignedAttestation};

    /// The family whose vendored `ci_axes.data_subject.wire_fields` names
    /// `references_attestation_id` ("the load-bearing pointer … resolving to
    /// the certified attestation") — i.e. the exact place the dropped reading
    /// would have applied. Registered at CC 3.1.2, unreserved.
    ///
    /// The `:v1` is persist's, not the catalogue's: the catalogued stem carries
    /// no `:v<N>` segment and the CEG §13.1 four-test gate refuses a `scores`
    /// dimension without one, so the catalogued spelling cannot reach the wire
    /// here at all. (Same for the other three families whose `data_subject`
    /// axis names the pointer — a second, independent reason the dropped
    /// reading was unreachable in persist; recorded for the re-vendor.)
    const DIMENSION: &str = "transparency_log:inclusion:v1";

    fn row(
        id: &str,
        attester: &str,
        subjects: &[&str],
        ty: &str,
        envelope: serde_json::Value,
    ) -> Attestation {
        let (och, ed_sig, pqc_sig) =
            crate::federation::tier_ingest::test_support::sign_envelope(attester, &envelope);
        let now = chrono::Utc::now();
        let mut sealed_row_ = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: attester.to_owned(),
            attestation_type: ty.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: attester.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: subjects.iter().map(|s| (*s).to_owned()).collect(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        crate::federation::tier_ingest::test_support::seal_row_in_place(attester, &mut sealed_row_);
        crate::federation::tier_ingest::test_support::reseal(&mut sealed_row_);
        sealed_row_
    }

    /// Ids visible to a LIVE-lifecycle read under `filter`, or `None` only when
    /// the backend genuinely has no such read surface.
    ///
    /// A blanket `Err(_) => None` would let any backend failure quietly skip
    /// every read assertion below — the vacuous-pass shape this whole witness
    /// exists to avoid. Only [`Error::Unsupported`](crate::federation::Error)
    /// buys the skip; anything else is a real failure and panics.
    async fn visible_ids(
        dir: &dyn FederationDirectory,
        filter: crate::read::AttestationFilter,
    ) -> Option<Vec<String>> {
        match dir.list_scores("", filter, None, 100).await {
            Ok(page) => Some(page.items.into_iter().map(|a| a.attestation_id).collect()),
            Err(crate::federation::Error::Unsupported { .. }) => None,
            Err(e) => panic!("list_scores failed for a reason other than Unsupported: {e}"),
        }
    }

    /// The erasure/DSAR shape: everything ABOUT `subject`.
    async fn subject_visible_ids(
        dir: &dyn FederationDirectory,
        subject: &str,
    ) -> Option<Vec<String>> {
        visible_ids(
            dir,
            crate::read::AttestationFilter {
                subject_key_id: Some(subject.to_owned()),
                ..Default::default()
            },
        )
        .await
    }

    /// Run the witness against one backend. `suffix` scopes every key id so a
    /// shared postgres test database does not collide across runs.
    pub(crate) async fn exercise_pointer_confers_no_subject_authority(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        let producer = format!("prod-579-{suffix}");
        let subject = format!("subj-579-{suffix}");
        for k in [&producer, &subject] {
            crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
        }

        // P — the row that genuinely names `subject` as its data subject.
        let p_id = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: row(
                &p_id,
                &producer,
                &[&subject],
                attestation_type::SCORES,
                serde_json::json!({ "dimension": DIMENSION, "score": 1.0 }),
            ),
        })
        .await
        .expect("P admits");

        // R — points AT P and names nobody. Under the dropped subject-binding
        // reading this row would be "about" `subject`.
        let r_id = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: row(
                &r_id,
                &producer,
                &[],
                attestation_type::SCORES,
                serde_json::json!({
                    "dimension": DIMENSION,
                    "score": 1.0,
                    "references_attestation_id": p_id,
                }),
            ),
        })
        .await
        .expect("R admits");

        // ── read surface: what is ABOUT the subject? P, never R. ──
        if let Some(ids) = subject_visible_ids(dir, &subject).await {
            assert!(
                ids.contains(&p_id),
                "the subject-keyed read must return P — its subject_key_ids names {subject}"
            );
            assert!(
                !ids.contains(&r_id),
                "R reached the subject-keyed read for {subject} THROUGH ITS POINTER. That is the \
                 subject-binding reading CC 4.5.1.1 (rc3) forbids, and it is what makes erasure \
                 and DSAR export over-collect: got {ids:?}"
            );
        }

        // ── THE REMOVAL: the pointer confers no revocation authority. ──
        let err = dir
            .put_attestation(SignedAttestation {
                attestation: row(
                    &uuid::Uuid::new_v4().to_string(),
                    &subject,
                    &[],
                    attestation_type::WITHDRAWS,
                    serde_json::json!({
                        "references_attestation_id": r_id,
                        "withdrawal_reason": "subject-binding reading (must not admit)",
                    }),
                ),
            })
            .await
            .expect_err(
                "a subject of P must NOT be able to revoke R merely because R points at P — \
                 admitting this IS the pointer-decides-authority shape rc3 closed",
            );
        assert_eq!(
            err.kind(),
            "federation_withdraws_not_admitted",
            "the refusal must be the AUTHORITY refusal, not an unrelated gate — a test that \
             passes for the wrong reason witnesses nothing"
        );

        // ── control B: the ADMITTED reading is still live. The producer's
        //    withdraws follows the same pointer to retire R. ──
        let wr_id = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: row(
                &wr_id,
                &producer,
                &[],
                attestation_type::WITHDRAWS,
                serde_json::json!({
                    "references_attestation_id": r_id,
                    "withdrawal_reason": "producer authority (rule 1)",
                }),
            ),
        })
        .await
        .expect("the producer's own withdraws admits under rule 1");
        let stored = dir
            .get_attestation(&wr_id)
            .await
            .expect("get withdraws")
            .expect("withdraws stored");
        assert_eq!(
            super::references_attestation_id_from_envelope(&stored.attestation_envelope),
            Some(r_id.as_str()),
            "the stored composer still NAMES its target through the pointer — the removed \
             reading is one of three, not the field's only job"
        );
        // …and the read side FOLLOWED that pointer: R leaves the live view, P
        // (untouched) stays. This is the admitted `recipient_revoke` reading
        // doing exactly the work rc3 preserved.
        if let Some(ids) = visible_ids(
            dir,
            crate::read::AttestationFilter {
                attesting_key_id: Some(producer.clone()),
                dimension_exact: Some(DIMENSION.to_owned()),
                ..Default::default()
            },
        )
        .await
        {
            assert!(
                !ids.contains(&r_id),
                "the producer's withdraws named R through the pointer — the live view must drop \
                 it. If R is still here the pointer is no longer read as the revoke target, and \
                 the removal took the admitted reading with it: {ids:?}"
            );
            assert!(
                ids.contains(&p_id),
                "P is untouched and must remain visible — the fold retires the row NAMED by the \
                 pointer, not everything near it: {ids:?}"
            );
        }

        // ── control A: subject authority itself is live, via subject_key_ids. ──
        let wp_id = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(SignedAttestation {
            attestation: row(
                &wp_id,
                &subject,
                &[],
                attestation_type::WITHDRAWS,
                serde_json::json!({
                    "references_attestation_id": p_id,
                    "withdrawal_reason": "subject authority (rule 2)",
                }),
            ),
        })
        .await
        .expect("the SUBJECT of P may revoke P — rule 2, on subject_key_ids");
        let admitted = dir
            .get_attestation(&wp_id)
            .await
            .expect("get subject withdraws")
            .expect("subject withdraws stored");
        assert_eq!(
            admitted.withdraws_admission_rule,
            Some(2),
            "admitted under rule 2 (direct subject authority) — this is the control that makes \
             the refusal above meaningful"
        );

        // ── what the subject's revocation does NOT do, recorded because it
        //    surprised this test into being right. The §6.1 lifecycle fold is
        //    PER ATTESTER (rule 4: cross-attester composers are independent
        //    chains), so `S`'s admitted revocation does not hide the
        //    producer's row from the producer's own chain — it is an admitted,
        //    stored consent act that the consumer composes. That is a
        //    composition-policy fact about `subject_key_ids` authority; it is
        //    NOT the pointer conferring anything, which is the whole point.
        if let Some(ids) = subject_visible_ids(dir, &subject).await {
            assert!(
                ids.contains(&p_id),
                "P must still be visible on the producer's chain: a cross-attester revocation is \
                 admitted (rule 2, above) and composed by the consumer, not folded into the \
                 producer's own lifecycle (CEG §6.1 rule 4): {ids:?}"
            );
            assert!(
                !ids.contains(&r_id),
                "R must never appear in a subject-keyed read for {subject} — not before the \
                 withdraws, and not after: {ids:?}"
            );
        }
    }
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
            cohort_scope: "federation".to_string(),
            tier: crate::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
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
