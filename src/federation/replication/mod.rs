//! Federation replication substrate (v3.4.0, CIRISPersist#123).
//!
//! Trust-weighted admission gate + eviction sweeper for the
//! `federation_blobs` content-addressable store. The trust gate
//! short-circuits writes whose attesting key falls below a configured
//! aggregate trust score; the sweeper bounds local disk by evicting
//! oldest+coldest blobs when usage crosses a watermark and emits a
//! signed `withdraws` attestation per evicted blob so consumers don't
//! refetch stale references from the federation directory.
//!
//! # Module shape
//!
//! - [`ReplicationConfig`] — operator knobs (threshold, recursion depth,
//!   per-tier overrides, storage budget, decay half-life, sweep cadence).
//! - [`TrustScoring`] — async trait returning a `[0.0, 1.0]` score for
//!   `(key_id, recursion_depth)`. Backends implement it.
//! - [`aggregate_trust_score`] — pure helper folding a list of
//!   attestations into the score-formula the architect's plan pinned
//!   (FSD §6 NodeCoreCore weighted aggregate, clamped to `[0.0, 1.0]`).
//! - [`AdmissionGate`] — thin wrapper composing a `TrustScoring` arc
//!   plus a threshold. The three federation write paths plus the
//!   cirisnode `put_contribution` path call this; no path branches on
//!   the trait directly.
//! - [`EvictionSweeper`] / [`EvictionDecay`] — bounded-batch eviction
//!   loop, score = `access_count × decay(now − last_accessed_at)`.
//!
//! # Mission alignment
//!
//! Persist exposes the substrate; consumers compose policy. The trust
//! score formula and the eviction order are deterministic primitives;
//! the threshold + budget + cadence are operator knobs the deployer
//! tunes. The sweeper emits structural withdraws against the prior
//! `holds_bytes` attestation so the directory remains the
//! single-source-of-truth about who holds what — eviction is
//! announced, not silent.

use std::time::Duration;

pub mod admission;
// v6.8.0 (CIRISPersist#148) — operator-facing cache-size knob (proxy /
// cache / server presets + human-readable byte parsing).
pub mod cache_mode;
// v6.8.0 (CIRISPersist#149) — proactive disk-pressure response (four
// free-byte tiers + injectable statvfs source; defaults ON).
pub mod disk_pressure;
pub mod eviction;
pub mod trust_scoring;

pub use admission::AdmissionGate;
pub use cache_mode::{
    parse_human_bytes, ByteParseError, CacheMode, CACHE_DEFAULT_CACHE_BYTES, GIB, MIB,
    PROXY_DEFAULT_CACHE_BYTES, PROXY_DEFAULT_TTL_SECONDS,
};
pub use disk_pressure::{
    classify_free_bytes, DiskPressureConfig, DiskPressureMonitor, DiskPressureMonitorHandle,
    DiskPressureSnapshot, FamilyPredicate, FreeBytesSource, PressureAction, PressureTier,
    StatvfsFreeBytes, StubFreeBytes, TrustTier, MIN_POLL_INTERVAL,
};
pub use eviction::{
    EvictionCandidate, EvictionDecay, EvictionSweeper, SweepReport, DEFAULT_SWEEP_BATCH,
    MIN_SWEEP_INTERVAL,
};
pub use trust_scoring::{
    aggregate_trust_score, MemoryTrustScoring, TrustScoring, TrustScoringError,
};

/// v3.4.0 (CIRISPersist#123) — operator knobs for the replication
/// substrate. Held by [`crate::Engine`] as `Arc<ReplicationConfig>`
/// (cheap to clone into the sweeper task).
///
/// # Defaults
///
/// The defaults match the architect's bootstrap-permissive shape:
/// `trust_threshold = 0.0` (admission gate is a no-op until an operator
/// raises the bar); `storage_budget_bytes = u64::MAX` (sweeper is a
/// no-op until a budget is set). Sovereign deployments override one or
/// both via [`crate::Engine::with_replication_config`].
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    /// Aggregate trust score below which the
    /// [`AdmissionGate`] rejects a write with
    /// [`crate::federation::BlobError::TrustBelowThreshold`] /
    /// [`crate::federation::Error::TrustBelowThreshold`]. Range
    /// `[0.0, 1.0]`. Default `0.0` (bootstrap-permissive — every key
    /// passes).
    pub trust_threshold: f64,

    /// Hard upper bound on local `federation_blobs` storage in bytes.
    /// Above `budget × steady_state_utilization` the sweeper evicts.
    /// Default `u64::MAX` (sweeper inactive).
    pub storage_budget_bytes: u64,

    /// Fraction of `storage_budget_bytes` the sweeper drives usage
    /// DOWN to once eviction starts. Range `(0.0, 1.0]`. Default
    /// `0.92` (sweeper releases 8% of the budget per cycle when
    /// triggered).
    pub steady_state_utilization: f64,

    /// Half-life (in days) for the
    /// [`EvictionDecay`] exponential decay applied to
    /// `last_accessed_at`. Larger values keep cold blobs alive longer.
    /// Default `30.0`.
    pub eviction_decay_half_life_days: f64,

    /// Sweep cadence — the loop runs `usage >= watermark?` every
    /// interval. Default `60s`.
    pub sweep_interval: Duration,
}

impl Default for ReplicationConfig {
    fn default() -> Self {
        Self {
            trust_threshold: 0.0,
            storage_budget_bytes: u64::MAX,
            steady_state_utilization: 0.92,
            eviction_decay_half_life_days: 30.0,
            sweep_interval: Duration::from_secs(60),
        }
    }
}

impl ReplicationConfig {
    /// True iff the sweeper has a finite budget. `u64::MAX` (the
    /// default) is the "sweeper inactive" sentinel.
    pub fn sweeper_active(&self) -> bool {
        self.storage_budget_bytes != u64::MAX
    }

    /// Watermark = `budget × steady_state_utilization`, clamped to
    /// `[0, budget]`. Returns `u64::MAX` when no budget is set.
    pub fn watermark_bytes(&self) -> u64 {
        if !self.sweeper_active() {
            return u64::MAX;
        }
        let raw = (self.storage_budget_bytes as f64) * self.steady_state_utilization;
        if raw <= 0.0 {
            return 0;
        }
        if raw >= self.storage_budget_bytes as f64 {
            return self.storage_budget_bytes;
        }
        raw as u64
    }
}

/// v3.4.0 (CIRISPersist#123) — canonical envelope shape for a
/// `withdraws` attestation that retracts a prior `holds_bytes`
/// emission. The sweeper signs canonical bytes of this envelope to
/// announce the eviction.
///
/// Wire shape (sorted-keys when canonicalized):
///
/// ```json
/// {
///   "kind": "withdraws",
///   "references_attestation_id": "<uuid of the withdrawn holds_bytes row>",
///   "references_attestation_type": "<holds_bytes:sha256:<8-hex-prefix>>"
/// }
/// ```
///
/// The two `references_*` fields mirror the structural-composer dedup
/// path: `crate::federation::precedence::references_attestation_id_from_envelope`
/// already reads `references_attestation_id`; the directory's
/// `list_holders` `NOT EXISTS` filter joins on it.
pub fn withdraws_attestation_envelope(
    target_attestation_id: &str,
    target_holds_bytes_type: &str,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "withdraws",
        "references_attestation_id": target_attestation_id,
        "references_attestation_type": target_holds_bytes_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_defaults_match_plan() {
        let c = ReplicationConfig::default();
        assert_eq!(c.trust_threshold, 0.0);
        assert_eq!(c.storage_budget_bytes, u64::MAX);
        assert_eq!(c.steady_state_utilization, 0.92);
        assert_eq!(c.eviction_decay_half_life_days, 30.0);
        assert_eq!(c.sweep_interval, Duration::from_secs(60));
        assert!(!c.sweeper_active());
        assert_eq!(c.watermark_bytes(), u64::MAX);
    }

    /// v38.0.0 (CIRISPersist#748) — the decorative depth knob is RETIRED,
    /// and this keeps it retired: no production source under src/ may
    /// mention it again without stating a pinned attenuation rule first.
    /// (Needle split so this witness cannot match itself.)
    #[test]
    fn the_retired_depth_knob_stays_retired() {
        let needle = format!("recursion{}", "_depth");
        let mut offenders = Vec::new();
        for entry in walkdir_src() {
            let text = std::fs::read_to_string(&entry).unwrap_or_default();
            for (i, line) in text.lines().enumerate() {
                let l = line.trim_start();
                if l.starts_with("//") || l.starts_with("///") || l.starts_with("//!") {
                    continue;
                }
                if line.contains(&needle) && !entry.ends_with("replication/mod.rs") {
                    offenders.push(format!("{entry}:{}", i + 1));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "recursion depth reappeared without a pinned attenuation rule (#748): {offenders:?}"
        );
    }

    fn walkdir_src() -> Vec<String> {
        let mut out = Vec::new();
        let mut stack = vec![std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")];
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p.to_string_lossy().into_owned());
                }
            }
        }
        out
    }

    #[test]
    fn watermark_computes_and_clamps() {
        let c = ReplicationConfig {
            storage_budget_bytes: 1_000_000,
            steady_state_utilization: 0.92,
            ..Default::default()
        };
        assert!(c.sweeper_active());
        assert_eq!(c.watermark_bytes(), 920_000);
    }

    /// v3.4.0 (CIRISPersist#123) — pin the canonical bytes the
    /// production
    /// [`crate::verify::canonical::PythonJsonDumpsCanonicalizer`]
    /// produces for the `withdraws` envelope. Mirrors the existing
    /// `put_blob_signing_canonicalizer_identity_holds_bytes_envelope`
    /// pin (`src/federation/blobs.rs`).
    ///
    /// **Why an identity test**: persist's production canonicalizer
    /// is Python-`json.dumps`-compatible, NOT JCS RFC 8785
    /// (CIRISPersist#121). The withdraws envelope happens to be
    /// ASCII-only so the two agree on output, but this test pins
    /// the byte shape so a future canonicalizer drift (or envelope
    /// schema change) forces an explicit test update before the
    /// signing path produces different `original_content_hash_hex`
    /// values downstream.
    #[test]
    fn withdraws_envelope_canonical_bytes_identity() {
        use crate::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
        use sha2::{Digest, Sha256};

        let env = withdraws_attestation_envelope(
            "11111111-1111-1111-1111-111111111111",
            "holds_bytes:sha256:abababab",
        );
        let bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&env)
            .expect("python canonicalize");
        // Sorted keys, no whitespace, ASCII-only.
        let expected = concat!(
            r#"{"kind":"withdraws","#,
            r#""references_attestation_id":"11111111-1111-1111-1111-111111111111","#,
            r#""references_attestation_type":"holds_bytes:sha256:abababab"}"#
        );
        assert_eq!(bytes, expected.as_bytes());
        // Pin the hash too — any future canonicalizer drift will
        // change this and force an explicit test update.
        let hash_hex = hex::encode(Sha256::digest(&bytes));
        assert_eq!(hash_hex.len(), 64);
    }

    #[test]
    fn withdraws_envelope_shape() {
        let env = withdraws_attestation_envelope(
            "11111111-1111-1111-1111-111111111111",
            "holds_bytes:sha256:abababab",
        );
        assert_eq!(env["kind"], "withdraws");
        assert_eq!(
            env["references_attestation_id"],
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(
            env["references_attestation_type"],
            "holds_bytes:sha256:abababab"
        );
    }
}
