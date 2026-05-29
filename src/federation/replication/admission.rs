//! Admission-gate wrapper composing a [`TrustScoring`] + threshold.
//!
//! v3.4.0 (CIRISPersist#123). The four write paths
//! (`put_blob`, `put_attestation`, `put_revocation`, `put_contribution`)
//! all call [`AdmissionGate::check`] BEFORE any DB work — trust is
//! the cheapest reject AND the one that leaks the least information.
//! An unauthorized writer shouldn't learn "your bytes matched the SHA"
//! or "your FK target exists."

use std::sync::Arc;

use super::trust_scoring::{TrustScoring, TrustScoringError};

/// v3.4.0 (CIRISPersist#123) — thin composition of `TrustScoring +
/// threshold + recursion_depth`. Each write site calls
/// [`Self::check`]; on `Ok(score)` the site proceeds, on
/// `Err(TrustGateRejection)` the site rejects with its typed
/// per-surface error.
#[derive(Clone)]
pub struct AdmissionGate {
    scoring: Arc<dyn TrustScoring>,
    threshold: f64,
    recursion_depth: u8,
}

/// v3.4.0 (CIRISPersist#123) — typed outcome of an admission check
/// that fell below the configured threshold. Sites translate this into
/// their own typed error variant (`BlobError::TrustBelowThreshold`,
/// `federation::Error::TrustBelowThreshold`,
/// `cirisnode::Error::InvalidArgument`).
#[derive(Debug, Clone)]
pub struct TrustGateRejection {
    /// The attesting key the gate evaluated.
    pub key_id: String,
    /// The aggregate score returned by [`TrustScoring`].
    pub score: f64,
    /// The threshold the score fell below.
    pub threshold: f64,
}

impl AdmissionGate {
    /// Construct a new gate. `threshold` outside `[0.0, 1.0]` is
    /// clamped — keeps callers honest without a typed error here.
    pub fn new(scoring: Arc<dyn TrustScoring>, threshold: f64, recursion_depth: u8) -> Self {
        Self {
            scoring,
            threshold: threshold.clamp(0.0, 1.0),
            recursion_depth,
        }
    }

    /// Threshold the gate evaluates against. Clamped to `[0.0, 1.0]`.
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Recursion depth resolved at construction.
    pub fn recursion_depth(&self) -> u8 {
        self.recursion_depth
    }

    /// v3.5.1 (CIRISPersist#129) — extract a clone of the inner
    /// `Arc<dyn TrustScoring>` for cohabitation consumers that need
    /// the scorer directly (CIRISEdge `init_edge_runtime` short-
    /// circuit auto-derivation). Symmetric to
    /// [`BackendDispatch`-as-`BlackholeRules`](crate::engine::BackendDispatch)
    /// access for the deny-list trait — the substrate exposes its
    /// trait-keyed handles so consumers don't have to re-wire scoring
    /// from scratch.
    pub fn scoring_arc(&self) -> Arc<dyn TrustScoring> {
        self.scoring.clone()
    }

    /// Check whether `key_id` clears the gate. Returns:
    ///
    /// - `Ok(Ok(score))` — the key cleared at `score >= threshold`.
    /// - `Ok(Err(TrustGateRejection { … }))` — the key scored below
    ///   threshold.
    /// - `Err(TrustScoringError)` — the resolver failed.
    ///
    /// `TrustScoringError::KeyNotFound` is converted to a rejection
    /// at score `0.0` — an unknown key has no trust, and the site's
    /// downstream code (FK validation) will likely return a typed
    /// `InvalidArgument` if reached. Keeping the rejection here lets
    /// the trust gate stay first in the ordering without leaking
    /// "does this key exist" information.
    pub async fn check(
        &self,
        key_id: &str,
    ) -> Result<Result<f64, TrustGateRejection>, TrustScoringError> {
        // Bootstrap-permissive optimization: threshold 0.0 admits
        // everything without dispatching to the resolver.
        if self.threshold <= 0.0 {
            return Ok(Ok(0.0));
        }
        let score = match self.scoring.trust_score(key_id, self.recursion_depth).await {
            Ok(s) => s,
            Err(TrustScoringError::KeyNotFound(_)) => 0.0,
            Err(other) => return Err(other),
        };
        if score >= self.threshold {
            Ok(Ok(score))
        } else {
            Ok(Err(TrustGateRejection {
                key_id: key_id.to_owned(),
                score,
                threshold: self.threshold,
            }))
        }
    }
}

impl AdmissionGate {
    /// Run the gate and translate its outcome into a
    /// [`crate::federation::BlobError`] result. The blob-write paths
    /// (`put_blob`) call this; rejection becomes
    /// [`crate::federation::BlobError::TrustBelowThreshold`].
    pub async fn check_blob(&self, key_id: &str) -> Result<(), crate::federation::BlobError> {
        let outcome = self
            .check(key_id)
            .await
            .map_err(|e| crate::federation::BlobError::Backend(format!("trust_scoring: {e}")))?;
        match outcome {
            Ok(_) => Ok(()),
            Err(rej) => Err(crate::federation::BlobError::TrustBelowThreshold {
                key_id: rej.key_id,
                score: rej.score,
                threshold: rej.threshold,
            }),
        }
    }

    /// Run the gate and translate its outcome into a
    /// [`crate::federation::Error`] result. The attestation /
    /// revocation write paths call this; rejection becomes
    /// [`crate::federation::Error::TrustBelowThreshold`].
    pub async fn check_federation(&self, key_id: &str) -> Result<(), crate::federation::Error> {
        let outcome = self
            .check(key_id)
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("trust_scoring: {e}")))?;
        match outcome {
            Ok(_) => Ok(()),
            Err(rej) => Err(crate::federation::Error::TrustBelowThreshold {
                key_id: rej.key_id,
                score: rej.score,
                threshold: rej.threshold,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;
    use std::sync::Mutex;

    struct FixedScores {
        scores: HashMap<String, f64>,
    }

    #[async_trait]
    impl TrustScoring for FixedScores {
        async fn trust_score(
            &self,
            key_id: &str,
            _recursion_depth: u8,
        ) -> Result<f64, TrustScoringError> {
            match self.scores.get(key_id) {
                Some(s) => Ok(*s),
                None => Err(TrustScoringError::KeyNotFound(key_id.to_owned())),
            }
        }
    }

    fn fixed(pairs: &[(&str, f64)]) -> Arc<dyn TrustScoring> {
        let mut m = HashMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_owned(), *v);
        }
        Arc::new(FixedScores { scores: m })
    }

    #[tokio::test]
    async fn threshold_zero_short_circuits_to_admit() {
        // Even an "unknown key" admits at threshold 0.0 — the gate
        // does not even hit the resolver.
        struct PanicResolver;
        #[async_trait]
        impl TrustScoring for PanicResolver {
            async fn trust_score(
                &self,
                _key_id: &str,
                _depth: u8,
            ) -> Result<f64, TrustScoringError> {
                panic!("threshold 0.0 must short-circuit");
            }
        }
        let gate = AdmissionGate::new(Arc::new(PanicResolver), 0.0, 0);
        let outcome = gate.check("any").await.unwrap();
        assert!(outcome.is_ok());
    }

    #[tokio::test]
    async fn admit_when_score_meets_threshold() {
        let gate = AdmissionGate::new(fixed(&[("k1", 0.8)]), 0.5, 0);
        let outcome = gate.check("k1").await.unwrap();
        assert_eq!(outcome.expect("admitted"), 0.8);
    }

    #[tokio::test]
    async fn reject_when_score_below_threshold() {
        let gate = AdmissionGate::new(fixed(&[("k1", 0.3)]), 0.5, 0);
        let outcome = gate.check("k1").await.unwrap();
        let rej = outcome.expect_err("rejected");
        assert_eq!(rej.key_id, "k1");
        assert_eq!(rej.score, 0.3);
        assert_eq!(rej.threshold, 0.5);
    }

    #[tokio::test]
    async fn unknown_key_becomes_zero_score_rejection() {
        let gate = AdmissionGate::new(fixed(&[]), 0.5, 0);
        let outcome = gate.check("missing").await.unwrap();
        let rej = outcome.expect_err("rejected");
        assert_eq!(rej.score, 0.0);
    }

    #[tokio::test]
    async fn resolver_backend_error_surfaces() {
        struct Erroring;
        #[async_trait]
        impl TrustScoring for Erroring {
            async fn trust_score(
                &self,
                _key_id: &str,
                _depth: u8,
            ) -> Result<f64, TrustScoringError> {
                Err(TrustScoringError::Backend("boom".into()))
            }
        }
        let gate = AdmissionGate::new(Arc::new(Erroring), 0.5, 0);
        let err = gate.check("k1").await.expect_err("backend error");
        assert_eq!(err.kind(), "trust_scoring_backend");
    }

    #[tokio::test]
    async fn threshold_clamped_to_unit_range() {
        let gate = AdmissionGate::new(fixed(&[("k1", 1.0)]), 2.0, 0);
        assert_eq!(gate.threshold(), 1.0);
        // Threshold below 0 is clamped to 0 → admit.
        let gate_neg = AdmissionGate::new(fixed(&[("k1", 1.0)]), -1.0, 0);
        assert_eq!(gate_neg.threshold(), 0.0);
        let outcome = gate_neg.check("k1").await.unwrap();
        assert!(outcome.is_ok());
    }

    // Mutex import not needed elsewhere but kept to silence clippy on
    // some toolchains; no-op when unused.
    #[allow(dead_code)]
    fn _force_mutex(_m: Mutex<()>) {}
}
