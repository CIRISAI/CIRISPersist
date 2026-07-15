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

/// Compose the [`ComposedVerdict`] from scope-gated candidate rows.
///
/// - `scores_rows` — the subject-gated candidate rows (any type; only
///   `attestation_type == "scores"` data rows contribute to the aggregate).
/// - `composers` — the `supersedes` / `withdraws` / `recants` rows (from the
///   same attesters) that MAY retract a candidate; fetched separately by the
///   backend because a composer need not name the subject itself.
/// - `policy` — the requested composition policy id.
/// - `trace` — when true, populate [`ComposedVerdict::trace`] with the full
///   derivation (the OPEN escape hatch).
/// - `now` — the wall clock for `age_of_head`.
pub fn compose_verdict(
    scores_rows: Vec<Attestation>,
    composers: Vec<Attestation>,
    policy: &str,
    trace: bool,
    now: DateTime<Utc>,
) -> ComposedVerdict {
    let (polarity, policy_id) = resolve_policy(policy);

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

    // ── 4. band ──
    let band = classify(polarity, contributor_count, aggregate, open_contradictions);

    let age_of_head = global_head.map(|h| {
        let delta = now.signed_duration_since(h.asserted_at);
        delta.to_std().unwrap_or(std::time::Duration::ZERO)
    });

    let trace_val = if trace {
        Some(build_trace(
            policy_id, polarity, aggregate, &data, &state_of, &heads,
        ))
    } else {
        None
    };

    ComposedVerdict {
        band,
        contributor_count,
        witness_diversity: None,
        open_contradictions,
        age_of_head,
        policy_applied: policy_id.to_string(),
        trace: trace_val,
    }
}

/// Map the scalar aggregate to a qualitative band.
fn classify(
    polarity: Polarity,
    contributor_count: u32,
    aggregate: f64,
    open_contradictions: u32,
) -> ConfidenceBand {
    if contributor_count == 0 {
        return ConfidenceBand::InsufficientWitnesses;
    }
    match polarity {
        Polarity::SignedMean => {
            if aggregate < 0.0 {
                ConfidenceBand::Refuted
            } else if open_contradictions > 0 {
                ConfidenceBand::Contested
            } else if aggregate >= 0.66 && contributor_count >= 3 {
                ConfidenceBand::WellEstablished
            } else if aggregate >= 0.33 {
                ConfidenceBand::Supported
            } else {
                ConfidenceBand::Weak
            }
        }
        Polarity::BooleanMin => {
            if aggregate >= 1.0 {
                if contributor_count >= 3 {
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
fn build_trace(
    policy_id: &str,
    polarity: Polarity,
    aggregate: f64,
    data: &[Attestation],
    state_of: &dyn Fn(&Attestation) -> RowState,
    heads: &std::collections::HashMap<String, &Attestation>,
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
        }
    }

    fn attestation_type_tier_federation() -> String {
        crate::federation::types::attestation_tier::FEDERATION.to_string()
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
    }
}
