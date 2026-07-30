//! Admission-gate wrapper composing a [`TrustScoring`] + threshold.
//!
//! v3.4.0 (CIRISPersist#123). The four write paths
//! (`put_blob`, `put_attestation`, `put_revocation`, `put_contribution`)
//! all call [`AdmissionGate::check`] BEFORE any DB work — trust is
//! the cheapest reject AND the one that leaks the least information.
//! An unauthorized writer shouldn't learn "your bytes matched the SHA"
//! or "your FK target exists."

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — how many attestation
/// writes ONE peer may land per [`PER_PEER_ATTESTATION_WRITE_WINDOW`].
///
/// A **substrate constant**, deliberately not an operator knob (the
/// [`crate::witness::WITNESS_CORPUS_K`] precedent): a quota a deployer can
/// raise is a quota an attacker's deployment has already raised, and the
/// number exists to bound *substrate* amplification, not to express a
/// per-deployment policy. 600 writes / 60s = 10 writes/second sustained
/// from a single `attesting_key_id` — orders of magnitude above what any
/// honest replication peer, genesis bake, or bulk-ingest loop produces,
/// and far below what a bootstrap flooder needs to be interesting.
pub const PER_PEER_ATTESTATION_WRITES_PER_WINDOW: u32 = 600;

/// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — the window
/// [`PER_PEER_ATTESTATION_WRITES_PER_WINDOW`] is measured over. Doubles as
/// the token bucket's refill period: tokens accrue continuously at
/// `WRITES_PER_WINDOW / WINDOW`, so a peer that has been idle for a full
/// window starts again with a full burst allowance.
pub const PER_PEER_ATTESTATION_WRITE_WINDOW: Duration = Duration::from_secs(60);

/// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — how many distinct peers
/// one [`PeerWriteQuota`] tracks before it prunes.
///
/// The quota itself must not become the memory-amplification vector it
/// exists to close: without this cap a flooder rotating `attesting_key_id`
/// per write would grow the bucket map without bound. At the cap the map
/// evicts every bucket that has refilled to full (i.e. every peer idle for
/// a whole window — indistinguishable from one never seen), so the
/// retained set is bounded by *peers with live traffic*.
pub const PER_PEER_QUOTA_TRACKED_PEERS_CAP: usize = 4096;

/// One peer's token bucket. `tokens` is fractional so the refill is
/// continuous rather than stepped at window boundaries.
struct PeerBucket {
    tokens: f64,
    last_seen: Instant,
}

/// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — per-peer write quota for
/// the attestation write path, keyed on `attesting_key_id`.
///
/// [`crate::federation::Error::RateLimited`] has been DECLARED since the
/// first federation cut, with a doc promising a quota — and was never
/// constructed anywhere. This is the construction site. A token bucket per
/// peer, capacity [`PER_PEER_ATTESTATION_WRITES_PER_WINDOW`], refilling
/// over [`PER_PEER_ATTESTATION_WRITE_WINDOW`].
///
/// # Placement
///
/// Held **per backend instance** (the
/// [`RepositoryStatsCache`](crate::ceg::aggregates::repository::RepositoryStatsCache)
/// precedent), never as a process global: the quota is node-local
/// admission state, and a process global would leak one engine's traffic
/// into another's budget (and one test's into the next's).
///
/// It runs ahead of every other gate in `put_attestation` — including the
/// trust gate — because it is the only check that consults NO shared
/// state. It answers "you are writing too fast", never "that key exists",
/// so it leaks strictly less than the trust threshold it precedes, while
/// bounding the recursive directory walk that
/// [`AdmissionGate::check_federation`] performs at any threshold > 0.
pub struct PeerWriteQuota {
    buckets: std::sync::Mutex<HashMap<String, PeerBucket>>,
}

impl Default for PeerWriteQuota {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerWriteQuota {
    /// A fresh quota with every peer at full allowance.
    pub fn new() -> Self {
        Self {
            buckets: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Charge one write against `key_id`'s bucket.
    ///
    /// `Ok(())` — admitted, one token spent.
    /// `Err(`[`Error::RateLimited`](crate::federation::Error::RateLimited)`)`
    /// — the peer is over quota; `retry_after_seconds` is the wall-clock
    /// wait until one token has accrued (always ≥ 1).
    pub fn check(&self, key_id: &str) -> Result<(), crate::federation::Error> {
        self.check_at(key_id, Instant::now())
    }

    /// Clock-injected core of [`Self::check`]. Private: the window is a
    /// substrate constant and callers do not get to pick "now" in
    /// production — only the unit tests below advance the clock.
    fn check_at(&self, key_id: &str, now: Instant) -> Result<(), crate::federation::Error> {
        let capacity = f64::from(PER_PEER_ATTESTATION_WRITES_PER_WINDOW);
        let per_second = capacity / PER_PEER_ATTESTATION_WRITE_WINDOW.as_secs_f64();

        let mut buckets = self.buckets.lock().unwrap_or_else(|p| p.into_inner());

        // Bound the map before admitting a peer we have never seen (see
        // PER_PEER_QUOTA_TRACKED_PEERS_CAP): drop every bucket that has
        // refilled to full, which is exactly the set whose state carries
        // no information a fresh bucket wouldn't.
        if buckets.len() >= PER_PEER_QUOTA_TRACKED_PEERS_CAP && !buckets.contains_key(key_id) {
            buckets.retain(|_, b| {
                let elapsed = now.saturating_duration_since(b.last_seen).as_secs_f64();
                b.tokens + elapsed * per_second < capacity
            });
        }

        let bucket = buckets.entry(key_id.to_owned()).or_insert(PeerBucket {
            tokens: capacity,
            last_seen: now,
        });
        let elapsed = now
            .saturating_duration_since(bucket.last_seen)
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * per_second).min(capacity);
        bucket.last_seen = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }
        let deficit = 1.0 - bucket.tokens;
        let retry_after_seconds = (deficit / per_second).ceil().max(1.0) as u64;
        Err(crate::federation::Error::RateLimited {
            retry_after_seconds,
        })
    }

    /// How many peers this quota is currently tracking. Observability for
    /// the [`PER_PEER_QUOTA_TRACKED_PEERS_CAP`] prune.
    pub fn tracked_peers(&self) -> usize {
        self.buckets.lock().unwrap_or_else(|p| p.into_inner()).len()
    }
}

/// v22.0.0 (CIRISPersist#543 finding 4, AV-76) — the shared assertion
/// bodies proving the `put_attestation` gate ORDER, run identically
/// against every backend.
///
/// The order is a security property, not an implementation detail, and
/// #541 is the standing reminder of what happens when two backends'
/// write paths drift: the bodies live HERE, once, and each backend's test
/// module calls them, so a divergence is a compile-or-fail, never a
/// silent asymmetry.
#[cfg(test)]
pub mod gate_order_test_support {
    use crate::federation::types::{
        attestation_tier, Attestation, KeyRecord, SignedAttestation, SignedKeyRecord,
    };
    use crate::federation::FederationDirectory;

    /// A key with REAL deterministic hybrid pubkeys, so the tier-3 crypto
    /// gate resolves the attester and then rejects on the SIGNATURE
    /// (rather than short-circuiting on an unknown attester).
    fn key_with_real_pubkeys(key_id: &str) -> KeyRecord {
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: key_id.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// A federation-tier row whose scrub signature is garbage — it can
    /// never clear the tier-3 hybrid verify.
    fn unverifiable_row(key_id: &str, tier: &str, cohort_scope: &str) -> Attestation {
        Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: key_id.into(),
            attested_key_id: key_id.into(),
            attestation_type: "attestation:self_verify".into(),
            weight: Some(1.0),
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: serde_json::json!({}),
            original_content_hash: "abcdef01".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: cohort_scope.into(),
            tier: tier.into(),
            promoted_at: None,
        }
    }

    /// **The headline AV-76 assertion.** A federation-tier row that fails
    /// the crypto verify AND would fail a DB-walk authority gate must be
    /// refused on the CRYPTO, proving the walk never ran.
    ///
    /// The tripwire is `cohort_scope = "family"`: a legal closed-set value
    /// (so the pure tier-1 `check_cohort_scope` admits it) that the AV-45
    /// membership walk `check_write_cohort_scope_for` then refuses,
    /// because `put_attestation` supplies no `cohort_target_id`. That walk
    /// resolves the writer's occurrence→identity binding and lists its
    /// families and communities — three directory reads.
    ///
    /// BEFORE this cut the walk sat at position 6 of 21 and the crypto at
    /// position 20, so this row came back `federation_write_scope_refused`
    /// — the substrate had paid for three reads on a row whose signature
    /// was never going to verify. AFTER, crypto is position 11 and the
    /// walk position 12.
    pub async fn assert_crypto_verdict_precedes_the_authority_walk<F>(dir: &F, tag: &str)
    where
        F: FederationDirectory + ?Sized,
    {
        let key_id = format!("av76c{tag}");
        dir.put_public_key(SignedKeyRecord {
            record: key_with_real_pubkeys(&key_id),
        })
        .await
        .expect("register attester");

        let row = unverifiable_row(&key_id, attestation_tier::FEDERATION, "family");
        let err = dir
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect_err("an unverifiable federation-tier row must be refused");
        assert_eq!(
            err.kind(),
            "federation_federation_tier_unverified",
            "AV-76: the crypto verdict must precede the DB-walk authority \
             gates — got {err:?}, which means an authority gate ran first \
             on a row whose signature can never verify"
        );
    }

    /// The counter-witness to the assertion above: the authority walk was
    /// REORDERED, not removed. The same row at LOCAL tier — where the
    /// crypto gate is a documented no-op (CC 5.3.2.2 deferred signature) —
    /// must still be refused by the AV-45 membership walk.
    pub async fn assert_authority_walk_still_rejects_when_crypto_is_a_noop<F>(dir: &F, tag: &str)
    where
        F: FederationDirectory + ?Sized,
    {
        let key_id = format!("av76w{tag}");
        dir.put_public_key(SignedKeyRecord {
            record: key_with_real_pubkeys(&key_id),
        })
        .await
        .expect("register attester");

        let row = unverifiable_row(&key_id, attestation_tier::LOCAL, "family");
        let err = dir
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect_err("an unprovable family downgrade must still be refused");
        assert_eq!(
            err.kind(),
            "federation_write_scope_refused",
            "AV-76 moved the AV-45 membership walk; it must not have \
             weakened it — got {err:?}"
        );
    }

    /// The tier-1 half of AV-76: the pure envelope gates now precede the
    /// single unavoidable directory read (the attester `identity_type`
    /// lookup, D2).
    ///
    /// The row's attester is deliberately UNREGISTERED, so the directory
    /// read would return the typed `federation_invalid_argument` ("does
    /// not exist in federation_keys") — which is exactly what this row
    /// used to come back with, because `check_envelope_size_admission` ran
    /// at position 14 and the lookup at position 2. An envelope that can
    /// never be admitted must not buy a directory read.
    pub async fn assert_pure_envelope_gates_precede_the_directory_read<F>(dir: &F, tag: &str)
    where
        F: FederationDirectory + ?Sized,
    {
        // Comfortably past MAX_ATTESTATION_ENVELOPE_BYTES (1 MiB) once
        // canonicalized.
        let oversized = serde_json::json!({ "pad": "x".repeat(2 * 1024 * 1024) });
        let mut row = unverifiable_row(
            &format!("av76-unregistered-{tag}"),
            attestation_tier::FEDERATION,
            "self",
        );
        row.attestation_envelope = oversized;

        let err = dir
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect_err("an oversized envelope must be refused");
        assert_eq!(
            err.kind(),
            "federation_envelope_too_large",
            "AV-76: the pure envelope-size gate must precede the attester \
             directory read — got {err:?}"
        );
    }

    /// The per-peer write quota, proven WIRED into `put_attestation` (the
    /// bucket arithmetic itself is unit-tested in this module's `tests`).
    ///
    /// Every write here is refused by the pure tier-1 `check_cohort_scope`
    /// (`global` is a §8.1.8 feed-name, never a wire value) — so the rows
    /// never reach the DB, and what the assertion isolates is that the
    /// quota is charged AHEAD of that, on the very first gate: the
    /// N+1th write from one peer inside one window comes back
    /// `federation_rate_limited`, the typed error that this cut gave its
    /// first construction site.
    pub async fn assert_per_peer_write_quota_is_wired<F>(dir: &F, tag: &str)
    where
        F: FederationDirectory + ?Sized,
    {
        let key_id = format!("av76q{tag}");
        let n = super::PER_PEER_ATTESTATION_WRITES_PER_WINDOW;
        for i in 0..n {
            let row = unverifiable_row(&key_id, attestation_tier::FEDERATION, "global");
            let err = dir
                .put_attestation(SignedAttestation { attestation: row })
                .await
                .expect_err("the `global` cohort_scope is never a wire value");
            assert_eq!(
                err.kind(),
                "federation_cohort_scope_rejected",
                "write {i} of {n} must be inside quota and fail on the \
                 closed-set value instead — got {err:?}"
            );
        }
        let row = unverifiable_row(&key_id, attestation_tier::FEDERATION, "global");
        let err = dir
            .put_attestation(SignedAttestation { attestation: row })
            .await
            .expect_err("the N+1th write in the window must be refused");
        assert_eq!(
            err.kind(),
            "federation_rate_limited",
            "AV-76: the per-peer quota must be charged on the first gate — \
             got {err:?}"
        );

        // And it is PER PEER: a second peer is unaffected by the first's
        // flood (a shared counter would be a trivial cross-peer DoS).
        let other = unverifiable_row(
            &format!("av76q2{tag}"),
            attestation_tier::FEDERATION,
            "global",
        );
        let err = dir
            .put_attestation(SignedAttestation { attestation: other })
            .await
            .expect_err("still an invalid cohort_scope");
        assert_eq!(
            err.kind(),
            "federation_cohort_scope_rejected",
            "one peer's exhausted bucket must not spend another's — got {err:?}"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
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

    // ── v22.0.0 (CIRISPersist#543 finding 4, AV-76) — per-peer quota ──

    /// The headline property: the N+1th write inside one window is
    /// RateLimited, and the typed error is the one that was DECLARED but
    /// never constructed before this cut.
    #[test]
    fn n_plus_first_write_in_window_is_rate_limited() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        for i in 0..PER_PEER_ATTESTATION_WRITES_PER_WINDOW {
            quota
                .check_at("peer-a", t0)
                .unwrap_or_else(|e| panic!("write {i} inside quota must admit: {e}"));
        }
        let err = quota
            .check_at("peer-a", t0)
            .expect_err("the N+1th write in the window must be refused");
        match err {
            crate::federation::Error::RateLimited {
                retry_after_seconds,
            } => {
                assert!(
                    retry_after_seconds >= 1,
                    "retry_after must be actionable, got {retry_after_seconds}"
                );
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
        assert_eq!(err.kind(), "federation_rate_limited");
    }

    /// The quota is PER PEER: peer-a exhausting its bucket must not spend
    /// peer-b's. (A shared counter would be a trivial cross-peer DoS —
    /// one flooder silences the mesh.)
    #[test]
    fn quota_is_keyed_per_peer() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        for _ in 0..PER_PEER_ATTESTATION_WRITES_PER_WINDOW {
            quota.check_at("peer-a", t0).expect("peer-a fills its own");
        }
        assert!(quota.check_at("peer-a", t0).is_err());
        quota
            .check_at("peer-b", t0)
            .expect("peer-b's bucket is untouched by peer-a's flood");
    }

    /// Tokens accrue continuously, so a peer that waits the full window
    /// is whole again — the quota throttles, it does not ban.
    #[test]
    fn bucket_refills_over_the_window() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        for _ in 0..PER_PEER_ATTESTATION_WRITES_PER_WINDOW {
            quota.check_at("peer-a", t0).expect("initial burst admits");
        }
        assert!(quota.check_at("peer-a", t0).is_err());

        // Half a window back ⇒ half the allowance.
        let half = t0 + PER_PEER_ATTESTATION_WRITE_WINDOW / 2;
        for _ in 0..(PER_PEER_ATTESTATION_WRITES_PER_WINDOW / 2) {
            quota.check_at("peer-a", half).expect("half-window refill");
        }
        assert!(quota.check_at("peer-a", half).is_err());

        // A full window after that ⇒ full allowance again.
        let full = half + PER_PEER_ATTESTATION_WRITE_WINDOW;
        for _ in 0..PER_PEER_ATTESTATION_WRITES_PER_WINDOW {
            quota.check_at("peer-a", full).expect("full-window refill");
        }
        assert!(quota.check_at("peer-a", full).is_err());
    }

    /// The quota must not become the memory amplifier it exists to close:
    /// a flooder rotating `attesting_key_id` per write is bounded by the
    /// tracked-peer cap once the rotated buckets go idle.
    #[test]
    fn tracked_peer_set_is_bounded_against_key_rotation() {
        let quota = PeerWriteQuota::new();
        let t0 = Instant::now();
        for i in 0..PER_PEER_QUOTA_TRACKED_PEERS_CAP {
            quota
                .check_at(&format!("rotating-{i}"), t0)
                .expect("admits");
        }
        assert_eq!(quota.tracked_peers(), PER_PEER_QUOTA_TRACKED_PEERS_CAP);
        // A full window later every one of those buckets has refilled, so
        // the next never-seen peer prunes them all.
        let later = t0 + PER_PEER_ATTESTATION_WRITE_WINDOW * 2;
        quota.check_at("rotating-fresh", later).expect("admits");
        assert_eq!(
            quota.tracked_peers(),
            1,
            "idle (fully refilled) buckets must be pruned at the cap"
        );
    }
}
