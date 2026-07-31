//! v17.4.0 (FSD-005 Appendix C) — the `resolve_scores` composition fold.
//!
//! This is the backend-agnostic half of `resolve_scores`: each backend does
//! its own scope-gated candidate fetch (the projection seek), then hands the
//! rows here for the precedence + aggregation fold. Keeping the fold in ONE
//! place is what lets the composite substrate op (the #329 pattern) run the
//! whole verdict inside persist's `.so` identically across sqlite / postgres /
//! memory (backend parity is the conformance HARD requirement).
//!
//! # The fold (Appendix C.3)
//!
//! 1. **Precedence** — group each attester's structural composers
//!    (`supersedes` / `withdraws` / `recants`) by the upstream `scores` row
//!    they reference, pick the CEG §6.1 precedence winner
//!    ([`super::precedence`]), and classify each `scores` row as *removed*
//!    (withdrawn/recanted → out of the fold entirely), *superseded* (replaced
//!    → not the head), or *live*.
//! 2. **Latest-wins per attester** — among an attester's live rows keep the
//!    single latest (`asserted_at`, then lex-smallest id) as that attester's
//!    HEAD. Each attester contributes exactly one head.
//! 3. **Aggregate by polarity** (CC 4.4.2) — `signed` → mean(score×confidence);
//!    `boolean-via-score` → min(score). Other polarity columns map to the
//!    signed default with a server-tier refinement TODO.
//! 4. **Band** — map the scalar aggregate + contributor count + contradictions
//!    to a qualitative [`ConfidenceBand`]; the float never crosses the wire.
//!
//! **Withheld (scope-gated-out) rows never reach this fold** — the backend
//! applies the §4.3 caller gate in SQL, so a gated-out row is absent from both
//! the returned rows AND the aggregate (no verdict-differencing).

use chrono::{DateTime, Utc};

use super::precedence;
use super::types::{attestation_type, Attestation};
use crate::read::{ComposedVerdict, ConfidenceBand};

/// The CC 4.4.2 aggregation polarity for a dimension's column.
///
/// Persist has no dimension→polarity registry (that is server-tier, which
/// owns the family/column vocabulary); the caller names the composition
/// `policy` and persist executes it. v17.4.0 honors the `signed` mean default
/// and the `boolean-via-score` min; every other policy maps to the signed
/// default (the server refines with a real column resolver).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Polarity {
    /// `mean(score × confidence)` — the CC 4.4.2 default.
    SignedMean,
    /// `min(score)` — boolean-via-score (all-must-hold AND semantics).
    BooleanMin,
}

/// Resolve the caller's `policy` id to a polarity + the canonical policy id
/// recorded in [`ComposedVerdict::policy_applied`].
fn resolve_policy(policy: &str) -> (Polarity, &'static str) {
    match policy {
        "cc-4.4.2-boolean-min" | "boolean-min" | "boolean-via-score" => {
            (Polarity::BooleanMin, "cc-4.4.2-boolean-min")
        }
        // signed mean is the default; unknown/other policies map here
        // (server-tier refines truth_grounding discounts, bonds, caps — all
        // additive trace fields, never a contract change).
        _ => (Polarity::SignedMean, "cc-4.4.2-signed-mean"),
    }
}

/// Envelope `score` (defaults 0.0 if absent/non-numeric).
fn score_of(a: &Attestation) -> f64 {
    a.attestation_envelope
        .get("score")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
}

/// Confidence for a row: the row `weight` if present, else envelope
/// `confidence`, else 1.0 (a bare assertion is full-confidence).
fn confidence_of(a: &Attestation) -> f64 {
    a.weight
        .or_else(|| {
            a.attestation_envelope
                .get("confidence")
                .and_then(|v| v.as_f64())
        })
        .unwrap_or(1.0)
}

/// The per-head contribution value under a polarity.
fn value_of(a: &Attestation, polarity: Polarity) -> f64 {
    match polarity {
        Polarity::SignedMean => score_of(a) * confidence_of(a),
        Polarity::BooleanMin => score_of(a),
    }
}

/// Lifecycle classification of a `scores` row after precedence.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RowState {
    Live,
    Superseded,
    Withdrawn,
    Recanted,
}

impl RowState {
    fn as_str(self) -> &'static str {
        match self {
            RowState::Live => "live",
            RowState::Superseded => "superseded",
            RowState::Withdrawn => "withdrawn",
            RowState::Recanted => "recanted",
        }
    }
}

/// v17.5.0 (CIRISPersist#456) the `resolve_scores` fold-input bound.
///
/// The admission-path fold fetches at most this many candidate rows
/// (newest-first), so the bound keeps exactly the rows per-attester
/// latest-wins needs; ancient superseded rows beyond it cannot change a live
/// verdict. A candidate set that hits the cap surfaces
/// `"candidates_truncated": true` in the trace. An unbounded audit walk uses
/// `list_scores` or `list_attestation_log` with a client fold, never this
/// admission-path handle.
pub const RESOLVE_CANDIDATE_CAP: i64 = 4096;

/// v22.0.0 (CIRISPersist#543 / AV-73) — the CC 3.1 dimension family carrying
/// the ATTESTED anti-collusion witness-diversity signal:
///
/// > `witness_diversity:{contribution_id}` | Witness set meets jurisdictional +
/// > organizational + software-stack + cell-expertise bars (P10). N=3 default.
/// > | boolean-via-score
///
/// It is `boolean-via-score`, so CC 4.4.2 folds it by **Min** — any single
/// "bars NOT met" attestation sinks the set, fail-secure.
///
/// Persist READS this signal; it never infers it. FSD-005 §7 RT-M4 is explicit
/// that "diversity attributes are attested, not self-declared — else a ring
/// varies declared attributes to inflate `witness_diversity`, defeating the gate
/// it leans on." Deriving diversity from registration metadata persist happens
/// to hold would be exactly that self-declaration.
pub const WITNESS_DIVERSITY_PREFIX: &str = "witness_diversity:";

/// Compose the [`ComposedVerdict`] from scope-gated candidate rows — the
/// backend-agnostic `resolve_scores` fold, kept in ONE place so the composite
/// substrate op (the #329 pattern) folds identically across sqlite / postgres
/// / memory (backend parity is a conformance HARD requirement).
///
/// - `scores_rows` — the subject-gated, `RESOLVE_CANDIDATE_CAP`-bounded
///   candidate rows (any type; only `attestation_type == "scores"` data rows
///   contribute to the aggregate).
/// - `composers` — the `supersedes` / `withdraws` / `recants` rows (from the
///   same attesters) that MAY retract a candidate; fetched separately by the
///   backend because a composer need not name the subject itself.
/// - `policy` — the requested composition policy id (CC 4.4.3).
/// - `trace` — when true, populate [`ComposedVerdict::trace`] with the full
///   derivation incl. `candidates_truncated` (the OPEN escape hatch).
/// - `now` — the wall clock for `age_of_head` (a parameter for deterministic
///   tests).
pub fn compose_verdict(
    scores_rows: Vec<Attestation>,
    composers: Vec<Attestation>,
    policy: &str,
    trace: bool,
    now: DateTime<Utc>,
) -> ComposedVerdict {
    let (polarity, policy_id) = resolve_policy(policy);
    // #456 — the backends LIMIT the fetch at RESOLVE_CANDIDATE_CAP; a full
    // batch therefore MEANS possible truncation, surfaced in the trace.
    let candidates_truncated = scores_rows.len() as i64 >= RESOLVE_CANDIDATE_CAP;

    // Only genuine `scores` data rows aggregate.
    let data: Vec<Attestation> = scores_rows
        .into_iter()
        .filter(|a| a.attestation_type == attestation_type::SCORES)
        .collect();

    // ── 1. precedence: classify each scores row via its winning composer ──
    // Group composers by (attester, references_attestation_id); the CEG §6.1
    // precedence winner per group determines the retraction that applies.
    let mut retraction: std::collections::HashMap<(String, String), RowState> =
        std::collections::HashMap::new();
    {
        let mut groups: std::collections::HashMap<(String, String), Vec<&Attestation>> =
            std::collections::HashMap::new();
        for c in &composers {
            if !precedence::is_structural_composer(&c.attestation_type) {
                continue;
            }
            let Some(refs) =
                precedence::references_attestation_id_from_envelope(&c.attestation_envelope)
            else {
                continue;
            };
            groups
                .entry((c.attesting_key_id.clone(), refs.to_string()))
                .or_default()
                .push(c);
        }
        for (key, group) in groups {
            if let Some(winner) = precedence::precedence_winner(&group) {
                let state = match winner.attestation_type.as_str() {
                    attestation_type::RECANTS => RowState::Recanted,
                    attestation_type::WITHDRAWS => RowState::Withdrawn,
                    attestation_type::SUPERSEDES => RowState::Superseded,
                    _ => continue,
                };
                retraction.insert(key, state);
            }
        }
    }

    // Per-row state: keyed by the row's OWN (attester, id) so a composer from
    // the same attester referencing it retracts it.
    let state_of = |row: &Attestation| -> RowState {
        retraction
            .get(&(row.attesting_key_id.clone(), row.attestation_id.clone()))
            .copied()
            .unwrap_or(RowState::Live)
    };

    // ── 2. latest-wins per attester over LIVE rows ──
    // A row is live iff not removed (withdrawn/recanted) AND not superseded.
    let mut heads: std::collections::HashMap<String, &Attestation> =
        std::collections::HashMap::new();
    for row in &data {
        if state_of(row) != RowState::Live {
            continue;
        }
        heads
            .entry(row.attesting_key_id.clone())
            .and_modify(|cur| {
                // latest asserted_at wins; tie → lex-smallest id (stable).
                let newer = row.asserted_at > cur.asserted_at
                    || (row.asserted_at == cur.asserted_at
                        && row.attestation_id < cur.attestation_id);
                if newer {
                    *cur = row;
                }
            })
            .or_insert(row);
    }

    let head_rows: Vec<&Attestation> = heads.values().copied().collect();
    let contributor_count = head_rows.len() as u32;

    // ── 3. aggregate by polarity ──
    let values: Vec<f64> = head_rows.iter().map(|r| value_of(r, polarity)).collect();
    let aggregate = match polarity {
        Polarity::SignedMean => {
            if values.is_empty() {
                0.0
            } else {
                values.iter().sum::<f64>() / values.len() as f64
            }
        }
        Polarity::BooleanMin => values.iter().cloned().fold(f64::INFINITY, f64::min),
    };

    // The global head = latest-asserted head (the "believed" claim).
    let global_head = head_rows.iter().copied().max_by(|a, b| {
        a.asserted_at
            .cmp(&b.asserted_at)
            .then_with(|| b.attestation_id.cmp(&a.attestation_id))
    });

    // ── open contradictions: heads whose sign opposes the believed sign ──
    let believed_positive = match polarity {
        Polarity::SignedMean => aggregate >= 0.0,
        Polarity::BooleanMin => global_head
            .map(|h| value_of(h, polarity) > 0.0)
            .unwrap_or(true),
    };
    let open_contradictions = head_rows
        .iter()
        .filter(|r| {
            let v = value_of(r, polarity);
            match polarity {
                Polarity::SignedMean => (v < 0.0) == believed_positive && v != 0.0,
                Polarity::BooleanMin => (v > 0.0) != believed_positive,
            }
        })
        .count() as u32;

    // ── 4. witness diversity (v22.0.0, CIRISPersist#543 / AV-73) ──
    //
    // THE ANTI-COLLUSION n — the field FSD-005 App C §C.3 has always declared
    // ("the anti-collusion n (NOT n_eff)") and persist has always returned
    // `None`. Returning `None` is what made FSD-005 §7 RT-M4 live: "a brigade of
    // M sock keys posting corroborating scores (open-emit, no bond, cost = M key
    // admissions) moves the mean; **the diversity gate never fires**."
    // `contributor_count` counts KEYS, and keys are free.
    //
    // CC 3.1 defines the signal as an ATTESTED claim, not a computed one:
    //   `witness_diversity:{contribution_id}` | Witness set meets jurisdictional
    //   + organizational + software-stack + cell-expertise bars (P10). N=3
    //   default. | boolean-via-score
    // and FSD-005 §7 RT-M4 is explicit that it MUST stay attested: "Diversity
    // attributes are attested, not self-declared — else a ring varies declared
    // attributes to inflate `witness_diversity`, defeating the gate it leans on."
    // So persist does NOT infer diversity from registration data (that would be
    // precisely the self-declaration RT-M4 forbids); it reads the attested rows
    // and otherwise reports honestly that it does not know.
    //
    // `boolean-via-score` per CC 4.4.2 folds by MIN — any negative trumps
    // positive, fail-secure — so a single "bars NOT met" attestation sinks it.
    let diversity_rows: Vec<&Attestation> = data
        .iter()
        .filter(|a| {
            super::admission::envelope_dimension(&a.attestation_envelope)
                .is_some_and(|d| d.starts_with(WITNESS_DIVERSITY_PREFIX))
                && state_of(a) == RowState::Live
        })
        .collect();
    let witness_diversity: Option<f64> = if diversity_rows.is_empty() {
        None
    } else {
        Some(
            diversity_rows
                .iter()
                .map(|a| value_of(a, Polarity::BooleanMin))
                .fold(f64::INFINITY, f64::min),
        )
    };

    // ── 5. band ──
    let band = classify(
        polarity,
        contributor_count,
        aggregate,
        open_contradictions,
        witness_diversity,
    );

    let age_of_head = global_head.map(|h| {
        let delta = now.signed_duration_since(h.asserted_at);
        delta.to_std().unwrap_or(std::time::Duration::ZERO)
    });

    let trace_val = if trace {
        Some(build_trace(
            policy_id,
            polarity,
            aggregate,
            &data,
            &state_of,
            &heads,
            candidates_truncated,
        ))
    } else {
        None
    };

    ComposedVerdict {
        band,
        contributor_count,
        witness_diversity,
        open_contradictions,
        age_of_head,
        policy_applied: policy_id.to_string(),
        trace: trace_val,
    }
}

/// Map the scalar aggregate to a qualitative band.
///
/// v22.0.0 (CIRISPersist#543 / AV-73) — `witness_diversity` is now an INPUT,
/// and `WellEstablished` is unreachable without it. See
/// [`WITNESS_DIVERSITY_PREFIX`] for why counting keys cannot substitute.
fn classify(
    polarity: Polarity,
    contributor_count: u32,
    aggregate: f64,
    open_contradictions: u32,
    witness_diversity: Option<f64>,
) -> ConfidenceBand {
    if contributor_count == 0 {
        return ConfidenceBand::InsufficientWitnesses;
    }
    // THE DIVERSITY BAR (CIRISPersist#543 / AV-73). `WellEstablished` requires
    // an ATTESTED positive `witness_diversity` — absence is NOT permission.
    //
    // Key count is not witness count: minting keys is free, so `contributor_count
    // >= 3` alone is a headcount an adversary buys, not corroboration it earns.
    // CC's own thesis is that "what an adversary must defeat is correlation, not
    // headcount", and CC 6.2.3.1 discounts correlated sources to `Signal_eff → 1`
    // "regardless of clique size" — naming SHARED STEWARD LINEAGE as a
    // correlation input. So three keys under one operator are one witness, and
    // the only thing that says otherwise is an attested `witness_diversity:*`
    // row certifying the jurisdictional / organizational / software-stack /
    // cell-expertise bars (CC 3.1, N=3 default).
    //
    // Fail-secure on absence: an unknown diversity caps at `Supported`, never
    // `WellEstablished`. This is the difference between "we have not established
    // this" and "this is established" — and it is the whole of AV-73, because
    // the Sybil brigade's M sock scores now buy `Supported` at most, forever.
    //
    // Note this bar does NOT require distinct trust ROOTS: CC asks for
    // jurisdiction/org/stack/expertise diversity, which is orthogonal to rooting
    // (the canonical founder set is `registry_steward_{us,eu,apac}` — one root,
    // three jurisdictions, bars met by construction). Same-root corroboration is
    // the intended topology; same-OPERATOR corroboration is the attack.
    let diversity_established = witness_diversity.is_some_and(|d| d > 0.0);
    match polarity {
        Polarity::SignedMean => {
            if aggregate < 0.0 {
                ConfidenceBand::Refuted
            } else if open_contradictions > 0 {
                ConfidenceBand::Contested
            } else if aggregate >= 0.66 && contributor_count >= 3 && diversity_established {
                ConfidenceBand::WellEstablished
            } else if aggregate >= 0.33 {
                ConfidenceBand::Supported
            } else {
                ConfidenceBand::Weak
            }
        }
        Polarity::BooleanMin => {
            if aggregate >= 1.0 {
                if contributor_count >= 3 && diversity_established {
                    ConfidenceBand::WellEstablished
                } else {
                    ConfidenceBand::Supported
                }
            } else if open_contradictions > 0 {
                ConfidenceBand::Contested
            } else {
                ConfidenceBand::Refuted
            }
        }
    }
}

/// Build the derivation trace (the OPEN escape hatch). Every future fold input
/// appears as a NEW field here — never a signature change.
#[allow(clippy::too_many_arguments)]
fn build_trace(
    policy_id: &str,
    polarity: Polarity,
    aggregate: f64,
    data: &[Attestation],
    state_of: &dyn Fn(&Attestation) -> RowState,
    heads: &std::collections::HashMap<String, &Attestation>,
    candidates_truncated: bool,
) -> serde_json::Value {
    let head_ids: std::collections::HashSet<&String> =
        heads.values().map(|h| &h.attestation_id).collect();
    let inputs: Vec<serde_json::Value> = data
        .iter()
        .map(|r| {
            serde_json::json!({
                "attester": r.attesting_key_id,
                "attestation_id": r.attestation_id,
                "score": score_of(r),
                "confidence": confidence_of(r),
                "epistemic_mode": r.attestation_envelope.get("epistemic_mode"),
                "asserted_at": r.asserted_at.to_rfc3339(),
                "lifecycle_state": state_of(r).as_str(),
                "is_head": head_ids.contains(&r.attestation_id),
            })
        })
        .collect();
    serde_json::json!({
        "policy": policy_id,
        "polarity": match polarity {
            Polarity::SignedMean => "signed_mean",
            Polarity::BooleanMin => "boolean_min",
        },
        "aggregate": aggregate,
        "contributor_count": heads.len(),
        // #456 — true ⇒ the candidate fetch hit RESOLVE_CANDIDATE_CAP; the
        // verdict is over the newest cap rows (audit reads use the unbounded
        // list handles, not this).
        "candidates_truncated": candidates_truncated,
        "inputs": inputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0).unwrap()
    }

    fn scores_row(id: &str, attester: &str, score: f64, confidence: f64, ts: i64) -> Attestation {
        Attestation {
            attestation_id: id.into(),
            attesting_key_id: attester.into(),
            attested_key_id: "subj".into(),
            attestation_type: attestation_type::SCORES.into(),
            weight: Some(confidence),
            asserted_at: t(ts),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": "trust:demo",
                "score": score,
                "confidence": confidence,
            }),
            original_content_hash: "dead".into(),
            scrub_signature_classical: "c".into(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.into(),
            scrub_timestamp: t(ts),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec!["subj".into()],
            withdraws_admission_rule: None,
            cohort_scope: "federation".into(),
            tier: attestation_type_tier_federation(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    fn attestation_type_tier_federation() -> String {
        crate::federation::types::attestation_tier::FEDERATION.to_string()
    }

    /// A `witness_diversity:{contribution_id}` attestation (CC 3.1,
    /// boolean-via-score): `score > 0` ⇒ the jurisdictional / organizational /
    /// software-stack / cell-expertise bars are met.
    fn diversity_row(id: &str, attester: &str, score: f64, ts: i64) -> Attestation {
        let mut r = scores_row(id, attester, score, 1.0, ts);
        r.attestation_envelope = serde_json::json!({
            "dimension": format!("{WITNESS_DIVERSITY_PREFIX}contrib-1"),
            "score": score,
            "confidence": 1.0,
        });
        r
    }

    /// v22.0.0 (CIRISPersist#543 / AV-73) — **THE SYBIL-BRIGADE WITNESS.**
    ///
    /// FSD-005 §7 RT-M4: "a brigade of M sock keys posting corroborating scores
    /// (open-emit, no bond, cost = M key admissions) moves the mean; **the
    /// diversity gate never fires.**" It never fired because
    /// `witness_diversity` was hardcoded `None` and the band keyed on
    /// `contributor_count` — a headcount an adversary buys.
    ///
    /// Pins all three arms: the brigade cannot reach `WellEstablished`; an
    /// ATTESTED diversity certificate unlocks it; and a NEGATIVE certificate
    /// (bars examined and NOT met) sinks it again via the boolean-via-score Min
    /// fold — so the gate cannot be opened by simply adding more rows.
    #[test]
    fn sybil_brigade_cannot_reach_well_established_without_attested_diversity_543() {
        // Five sock keys, unanimous and emphatic — the brigade.
        let brigade: Vec<Attestation> = (0..5)
            .map(|i| scores_row(&format!("s{i}"), &format!("sock-{i}"), 1.0, 1.0, 10 + i))
            .collect();

        let v = compose_verdict(
            brigade.clone(),
            vec![],
            "cc-4.4.2-signed-mean",
            false,
            t(100),
        );
        assert_eq!(v.contributor_count, 5, "the brigade IS five distinct keys");
        assert_eq!(
            v.witness_diversity, None,
            "no attested diversity ⇒ persist reports honestly that it does not know"
        );
        assert_eq!(
            v.band,
            ConfidenceBand::Supported,
            "AV-73: five colluding keys with a perfect aggregate must NOT reach \
             WellEstablished — key count is not witness count"
        );

        // The same brigade, now with an ATTESTED positive diversity certificate.
        let mut with_diversity = brigade.clone();
        with_diversity.push(diversity_row("d1", "auditor", 1.0, 20));
        let v = compose_verdict(
            with_diversity,
            vec![],
            "cc-4.4.2-signed-mean",
            false,
            t(100),
        );
        assert_eq!(v.witness_diversity, Some(1.0));
        assert_eq!(
            v.band,
            ConfidenceBand::WellEstablished,
            "an ATTESTED diversity certificate is what unlocks the top band"
        );

        // And a NEGATIVE certificate sinks it — boolean-via-score folds by Min
        // (CC 4.4.2), so "bars examined, NOT met" beats any number of positives.
        let mut contested = brigade;
        contested.push(diversity_row("d1", "auditor", 1.0, 20));
        contested.push(diversity_row("d2", "auditor-2", -1.0, 21));
        let v = compose_verdict(contested, vec![], "cc-4.4.2-signed-mean", false, t(100));
        assert_eq!(
            v.witness_diversity,
            Some(-1.0),
            "Min fold — any negative trumps positive, fail-secure"
        );
        assert_ne!(
            v.band,
            ConfidenceBand::WellEstablished,
            "a refuted diversity claim must not leave the top band reachable"
        );
    }

    fn composer(id: &str, attester: &str, ty: &str, upstream: &str, ts: i64) -> Attestation {
        let mut r = scores_row(id, attester, 0.0, 1.0, ts);
        r.attestation_type = ty.into();
        r.attestation_envelope = serde_json::json!({ "references_attestation_id": upstream });
        r
    }

    #[test]
    fn signed_mean_supported() {
        let rows = vec![
            scores_row("a", "k1", 0.5, 1.0, 0),
            scores_row("b", "k2", 0.5, 1.0, 0),
        ];
        let v = compose_verdict(rows, vec![], "cc-4.4.2-signed-mean", false, t(100));
        assert_eq!(v.contributor_count, 2);
        assert_eq!(v.band, ConfidenceBand::Supported);
        assert_eq!(v.open_contradictions, 0);
    }

    #[test]
    fn latest_wins_supersede_replaces_head() {
        // k1 asserts 0.9 at t0, then a NEW scores row 0.1 at t60 while a
        // supersedes retires the old one → head is the new low row.
        let rows = vec![
            scores_row("old", "k1", 0.9, 1.0, 0),
            scores_row("new", "k1", 0.1, 1.0, 60),
        ];
        let comps = vec![composer(
            "sup",
            "k1",
            attestation_type::SUPERSEDES,
            "old",
            60,
        )];
        let v = compose_verdict(rows, comps, "cc-4.4.2-signed-mean", true, t(100));
        assert_eq!(v.contributor_count, 1);
        // only "new" (0.1) is live → aggregate 0.1 → Weak
        assert_eq!(v.band, ConfidenceBand::Weak);
    }

    #[test]
    fn withdraws_removes_from_fold() {
        let rows = vec![
            scores_row("a", "k1", 0.9, 1.0, 0),
            scores_row("b", "k2", 0.9, 1.0, 0),
        ];
        let comps = vec![composer("w", "k1", attestation_type::WITHDRAWS, "a", 60)];
        let v = compose_verdict(rows, comps, "cc-4.4.2-signed-mean", false, t(100));
        assert_eq!(v.contributor_count, 1); // k1 gone
    }

    #[test]
    fn refuted_when_head_negative() {
        let rows = vec![scores_row("a", "k1", -0.8, 1.0, 0)];
        let v = compose_verdict(rows, vec![], "cc-4.4.2-signed-mean", false, t(100));
        assert_eq!(v.band, ConfidenceBand::Refuted);
    }

    #[test]
    fn boolean_min_contested_on_mixed() {
        let rows = vec![
            scores_row("a", "k1", 1.0, 1.0, 0),
            scores_row("b", "k2", 0.0, 1.0, 0),
        ];
        let v = compose_verdict(rows, vec![], "cc-4.4.2-boolean-min", false, t(100));
        // min = 0, mixed sign → Contested
        assert_eq!(v.band, ConfidenceBand::Contested);
        assert!(v.open_contradictions >= 1);
    }

    #[test]
    fn empty_is_insufficient() {
        let v = compose_verdict(vec![], vec![], "cc-4.4.2-signed-mean", false, t(100));
        assert_eq!(v.band, ConfidenceBand::InsufficientWitnesses);
        assert_eq!(v.contributor_count, 0);
        assert!(v.age_of_head.is_none());
    }

    #[test]
    fn trace_carries_derivation() {
        let rows = vec![scores_row("a", "k1", 0.7, 1.0, 0)];
        let v = compose_verdict(rows, vec![], "cc-4.4.2-signed-mean", true, t(100));
        let tr = v.trace.expect("trace present");
        assert_eq!(tr["policy"], "cc-4.4.2-signed-mean");
        assert_eq!(tr["inputs"][0]["attester"], "k1");
        assert_eq!(tr["inputs"][0]["lifecycle_state"], "live");
        // #456 — a below-cap candidate set is NOT truncated.
        assert_eq!(tr["candidates_truncated"], false);
    }

    #[test]
    fn candidates_truncated_flag_at_cap() {
        // #456 — the backends LIMIT the fetch at RESOLVE_CANDIDATE_CAP; a full
        // batch (>= cap rows reaching the fold) sets the trace flag. One
        // attester's newest score is the live head regardless, so the verdict
        // is still well-formed over the (bounded) newest window.
        let cap = RESOLVE_CANDIDATE_CAP as usize;
        let rows: Vec<Attestation> = (0..cap)
            .map(|i| scores_row(&format!("r{i}"), "k1", 0.5, 1.0, i as i64))
            .collect();
        let v = compose_verdict(rows, vec![], "cc-4.4.2-signed-mean", true, t(1_000_000));
        assert_eq!(v.trace.unwrap()["candidates_truncated"], true);
        // below cap → false.
        let rows: Vec<Attestation> = (0..cap - 1)
            .map(|i| scores_row(&format!("r{i}"), "k1", 0.5, 1.0, i as i64))
            .collect();
        let v = compose_verdict(rows, vec![], "cc-4.4.2-signed-mean", true, t(1_000_000));
        assert_eq!(v.trace.unwrap()["candidates_truncated"], false);
    }
}
