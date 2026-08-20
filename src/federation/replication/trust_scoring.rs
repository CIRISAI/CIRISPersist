//! Trust-scoring trait + the pure aggregate-helper.
//!
//! v3.4.0 (CIRISPersist#123). The trait is object-safe via
//! [`async_trait`] — the [`AdmissionGate`](super::AdmissionGate) holds
//! `Arc<dyn TrustScoring>`. Each call hits the trait once; no cache
//! (per-call SQL is cheaper than the stale-cache bug class).

use crate::federation::Attestation;

/// v3.4.0 (CIRISPersist#123) — typed errors from the trust-score
/// resolver. The admission gate maps these onto the per-write error
/// surface (`BlobError` / `federation::Error` / `cirisnode::Error`).
#[derive(Debug, thiserror::Error)]
pub enum TrustScoringError {
    /// The `key_id` is not present in `federation_keys`. The
    /// [`AdmissionGate`](super::AdmissionGate) translates this to
    /// `Ok(0.0)` — an unknown key has no trust.
    #[error("key_id not found: {0}")]
    KeyNotFound(String),

    /// Backend-level failure (DB pool, SQL execute, etc.).
    #[error("backend: {0}")]
    Backend(String),
}

impl TrustScoringError {
    /// Stable telemetry token.
    pub fn kind(&self) -> &'static str {
        match self {
            TrustScoringError::KeyNotFound(_) => "trust_scoring_key_not_found",
            TrustScoringError::Backend(_) => "trust_scoring_backend",
        }
    }
}

/// v3.4.0 (CIRISPersist#123) — async, object-safe trust-score
/// resolver. Backends implement against the federation directory's
/// attestation graph; the memory shim returns a trivial answer.
///
/// **v38.0.0 (CIRISPersist#748) — `recursion_depth` is RETIRED.** The
/// parameter promised a `delegates_to` BFS that no implementation ever
/// performed: every impl in this tree bound `_recursion_depth`, every
/// construction site passed a literal `0`, and no attenuation rule for a
/// multi-hop walk was ever specified anywhere — so depth-1 scoring was
/// decorative end-to-end, a knob wearing a real one's clothes. The
/// contract is now what the code always did: a per-call AGGREGATE over
/// `scores` attestations directly targeting `key_id`
/// ([`aggregate_trust_score`]). Transitive propagation is deliberately
/// the CONSUMER's: graph walks are an explicit architectural non-goal of
/// this substrate (THREAT_MODEL.md AV-29 records the non-goal as the
/// mitigation) — the exposed edges are
/// [`crate::federation::topology::build_delegation_graph`] and
/// `FederationDirectory::{list_attestations_for, list_attestations_by}`,
/// and a consumer that wants friend-of-friends composes them under its
/// own, stated attenuation rule.
#[async_trait::async_trait]
pub trait TrustScoring: Send + Sync {
    /// Resolve the aggregate trust score for `key_id` over the `scores`
    /// attestations directly targeting it. Returns a value in
    /// `[0.0, 1.0]`.
    async fn trust_score(&self, key_id: &str) -> Result<f64, TrustScoringError>;
}

/// v3.4.0 (CIRISPersist#123) — pure aggregate helper. Folds a slice of
/// `scores`-typed attestations into a `[0.0, 1.0]` aggregate score.
///
/// Formula (architect's plan §3 + FSD §6 NodeCoreCore weighted
/// aggregate): `min(1.0, sum(attestation.weight.unwrap_or(1.0)) /
/// scorer_count)` where `scorer_count` is the number of distinct
/// `attesting_key_id`s in `scores`. The clamp keeps the output in
/// range even if a single attester emits multiple `scores` rows; the
/// distinct-attester divisor is the "consensus mass" denominator.
///
/// Returns `0.0` for an empty slice — no attesters means no trust.
pub fn aggregate_trust_score(scores: &[Attestation]) -> f64 {
    if scores.is_empty() {
        return 0.0;
    }
    let mut attesters = std::collections::HashSet::new();
    let mut weight_sum = 0.0_f64;
    for s in scores {
        attesters.insert(s.attesting_key_id.as_str());
        weight_sum += s.weight.unwrap_or(1.0);
    }
    let scorer_count = attesters.len().max(1) as f64;
    let raw = weight_sum / scorer_count;
    if raw.is_nan() {
        0.0
    } else {
        raw.clamp(0.0, 1.0)
    }
}

/// v3.4.0 (CIRISPersist#123) — trivial in-memory implementation of
/// [`TrustScoring`] used by the memory backend, tests, and the
/// architect's plan §"Memory backend" minimal shim.
///
/// Returns the pre-registered score for `key_id` if present, else
/// `TrustScoringError::KeyNotFound`. The
/// [`AdmissionGate`](super::AdmissionGate) translates the
/// `KeyNotFound` arm to a `0.0` rejection at the configured
/// threshold — an unknown key has no trust.
#[derive(Debug, Clone, Default)]
pub struct MemoryTrustScoring {
    scores: std::collections::HashMap<String, f64>,
}

impl MemoryTrustScoring {
    /// Construct an empty scorer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set / overwrite the score for `key_id`.
    pub fn set_score(&mut self, key_id: impl Into<String>, score: f64) {
        self.scores.insert(key_id.into(), score.clamp(0.0, 1.0));
    }
}

#[async_trait::async_trait]
impl TrustScoring for MemoryTrustScoring {
    async fn trust_score(&self, key_id: &str) -> Result<f64, TrustScoringError> {
        match self.scores.get(key_id) {
            Some(s) => Ok(*s),
            None => Err(TrustScoringError::KeyNotFound(key_id.to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::types::attestation_type;

    fn att(attesting: &str, weight: Option<f64>) -> Attestation {
        Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: attesting.to_owned(),
            attested_key_id: "target".to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight,
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: serde_json::json!({}),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: attesting.to_owned(),
            scrub_timestamp: chrono::Utc::now(),
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

    #[test]
    fn empty_scores_is_zero() {
        assert_eq!(aggregate_trust_score(&[]), 0.0);
    }

    #[test]
    fn single_attester_default_weight_returns_one() {
        let s = vec![att("k1", None)];
        assert_eq!(aggregate_trust_score(&s), 1.0);
    }

    #[test]
    fn multiple_distinct_attesters_average() {
        // Three distinct attesters, weights 0.6 + 0.4 + 0.5 = 1.5,
        // divisor 3 → 0.5.
        let s = vec![
            att("k1", Some(0.6)),
            att("k2", Some(0.4)),
            att("k3", Some(0.5)),
        ];
        let got = aggregate_trust_score(&s);
        assert!((got - 0.5).abs() < 1e-9, "got {got}");
    }

    #[test]
    fn clamps_above_one() {
        // Single attester with weight 5.0 → clamped to 1.0.
        let s = vec![att("k1", Some(5.0))];
        assert_eq!(aggregate_trust_score(&s), 1.0);
    }
}
