//! Eviction sweeper — bounded-batch LRU+frequency eviction over
//! `federation_blobs`, plus signed `withdraws` emission against the
//! prior `holds_bytes` attestation per evicted row.
//!
//! v3.4.0 (CIRISPersist#123). The sweeper owns one
//! [`tokio::task::JoinHandle`]; the `EngineCell` singleton holds the
//! handle so `Engine::from_shared` cohabitation views do NOT spawn a
//! second sweeper. Loop body factors out into
//! [`Engine::sweep_evictions_once`](crate::Engine::sweep_evictions_once)
//! so Pi-cron callers can drive a single pass without holding the loop.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// v3.4.0 (CIRISPersist#123) — pure decay helper. Exponential decay
/// over time-since-last-access with a configurable half-life.
///
/// `weight(now, last_accessed_at) = 0.5 ^ (Δt_days / half_life_days)`
///
/// Score the sweeper sorts by is `access_count × weight` — ASC, so
/// the LOWEST score evicts first. Lower `weight` (older row) and
/// lower `access_count` (less referenced) both pull the row toward
/// eviction.
#[derive(Debug, Clone, Copy)]
pub struct EvictionDecay {
    half_life_days: f64,
}

impl EvictionDecay {
    /// Construct with the configured half-life. `half_life_days <= 0`
    /// is clamped to a small positive epsilon — the sweeper still
    /// runs sanely (rows decay almost instantly).
    pub fn new(half_life_days: f64) -> Self {
        Self {
            half_life_days: if half_life_days > 0.0 {
                half_life_days
            } else {
                f64::EPSILON
            },
        }
    }

    /// Compute the decay weight for a row last accessed at
    /// `last_accessed_at` relative to wall-clock `now`. Returns a
    /// `(0.0, 1.0]` value (1.0 when `last_accessed_at >= now`, decays
    /// asymptotically toward 0 as age grows).
    pub fn weight(&self, now: DateTime<Utc>, last_accessed_at: DateTime<Utc>) -> f64 {
        let delta = now.signed_duration_since(last_accessed_at);
        let delta_secs = delta.num_seconds() as f64;
        if delta_secs <= 0.0 {
            return 1.0;
        }
        let half_life_secs = self.half_life_days * 86_400.0;
        let exponent = delta_secs / half_life_secs;
        // 0.5^exponent
        0.5_f64.powf(exponent)
    }

    /// Score = `access_count × decay_weight`. Lower scores evict
    /// first. `access_count` is bumped by every get_blob / has_blob
    /// hit (V053 access tracking). The `+1` on access_count keeps
    /// fresh-but-untouched rows from collapsing to a uniform 0 score
    /// (any never-read row would tie at exactly 0 otherwise; ties
    /// resolve by last_accessed_at via the composite ORDER BY).
    pub fn score(
        &self,
        now: DateTime<Utc>,
        last_accessed_at: DateTime<Utc>,
        access_count: u64,
    ) -> f64 {
        let w = self.weight(now, last_accessed_at);
        ((access_count + 1) as f64) * w
    }
}

/// v3.4.0 (CIRISPersist#123) — one candidate row returned by a
/// backend's sweeper scan. Carries everything the Engine needs to:
/// 1. compute the decay-weighted eviction score (Rust-side ranking),
/// 2. look up the prior `holds_bytes` attestation_id by SHA,
/// 3. tally `bytes_freed` per delete.
#[derive(Debug, Clone)]
pub struct EvictionCandidate {
    /// Content address.
    pub sha256: [u8; 32],
    /// Bytes the row holds (matches `federation_blobs.size_bytes`).
    pub size_bytes: u64,
    /// Monotonic read-hit counter.
    pub access_count: u64,
    /// Wall-clock of the most recent read hit (or first_seen_at for
    /// never-read rows).
    pub last_accessed_at: chrono::DateTime<chrono::Utc>,
    /// v6.8.0 (CIRISPersist#149) — the `attesting_key_id` of the
    /// most-recent `holds_bytes` attestation this engine emitted for
    /// the SHA, when known. Used by the disk-pressure
    /// force-evict-proxy-first hint to classify a candidate as
    /// local/family (protected) vs federation/proxy (evict first).
    /// `None` ⇒ provenance unknown; treated as proxy under pressure
    /// (fail-toward-eviction is safe: an unattributed blob we can
    /// re-fetch is the right thing to shed first).
    pub attesting_key_id: Option<String>,
    /// v13.0.0 (§Q B5 / CIRISPersist#370) — the row's
    /// `federation_blobs.media_type`, the substrate's per-blob corpus-class
    /// token. The sweep matches it against the installed
    /// `StorageBudgetV1.pinned_class` set to classify the candidate as
    /// PINNED (evict last, cache-before-pinned) vs cache. `None` ⇒ no
    /// class ⇒ never pinned (fail-toward-eviction, same posture as
    /// `attesting_key_id`).
    pub media_type: Option<String>,
}

/// v3.4.0 (CIRISPersist#123) — outcome of one sweep cycle.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SweepReport {
    /// Bytes the table held before the cycle.
    pub bytes_before: u64,
    /// Bytes the table holds after the cycle.
    pub bytes_after: u64,
    /// Rows the sweeper deleted.
    pub rows_evicted: u64,
    /// Of `rows_evicted`, how many had a `withdraws` attestation
    /// emitted successfully. Failures (FK violations against a
    /// previously-deleted attestation, signer transient errors) are
    /// logged via tracing and counted as `withdraws_failed` rather
    /// than aborting the sweep — the row is still gone locally.
    pub withdraws_emitted: u64,
    /// Failed `withdraws` emissions.
    pub withdraws_failed: u64,
}

impl SweepReport {
    /// True when no eviction work happened (usage already below
    /// watermark, or storage budget is `u64::MAX`).
    pub fn is_noop(&self) -> bool {
        self.rows_evicted == 0
            && self.withdraws_emitted == 0
            && self.bytes_before == self.bytes_after
    }

    /// Convenience accessor: `bytes_before − bytes_after`. Saturating
    /// (concurrent writes between the pre- and post-sample may push
    /// `bytes_after > bytes_before`; we report `0` in that case).
    pub fn bytes_freed(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }
}

/// v3.4.0 (CIRISPersist#123) — the spawned eviction loop handle.
///
/// Built and held by the PyO3 [`EngineCell`](crate::ffi::pyo3) and by
/// sovereign-mode `Engine::with_replication_config + spawn_sweeper()`
/// — never by [`Engine::from_shared`] (cohabitation views must not
/// duplicate the sweeper).
pub struct EvictionSweeper {
    join_handle: tokio::task::JoinHandle<()>,
    shutdown: std::sync::Arc<tokio::sync::Notify>,
}

impl EvictionSweeper {
    /// Construct from a freshly-spawned join handle + the shutdown
    /// notifier the spawned task awaits.
    pub fn new(
        join_handle: tokio::task::JoinHandle<()>,
        shutdown: std::sync::Arc<tokio::sync::Notify>,
    ) -> Self {
        Self {
            join_handle,
            shutdown,
        }
    }

    /// Signal the sweeper to stop. The spawned task drops out of its
    /// loop on the next `sweep_interval` tick or immediately if it's
    /// currently sleeping.
    pub fn stop(self) -> tokio::task::JoinHandle<()> {
        self.shutdown.notify_one();
        self.join_handle
    }
}

/// Cadence cap so an operator-tunable [`ReplicationConfig::sweep_interval`]
/// of zero doesn't tightloop on a misconfiguration.
pub const MIN_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Default batch size for one sweep cycle — bounded so the sweeper
/// runs in predictable transaction size against any deployment.
pub const DEFAULT_SWEEP_BATCH: i64 = 1000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decay_weight_one_for_just_accessed() {
        let d = EvictionDecay::new(30.0);
        let now = Utc::now();
        // last_accessed_at == now → weight 1.0.
        let w = d.weight(now, now);
        assert!((w - 1.0).abs() < 1e-9);
    }

    #[test]
    fn decay_weight_half_at_one_half_life() {
        let d = EvictionDecay::new(30.0); // 30 days
        let now: DateTime<Utc> = "2026-05-29T00:00:00Z".parse().unwrap();
        let one_half_life_ago = now - chrono::Duration::days(30);
        let w = d.weight(now, one_half_life_ago);
        // 0.5^1 = 0.5
        assert!((w - 0.5).abs() < 1e-6, "got {w}");
    }

    #[test]
    fn decay_weight_quarter_at_two_half_lives() {
        let d = EvictionDecay::new(30.0);
        let now: DateTime<Utc> = "2026-05-29T00:00:00Z".parse().unwrap();
        let two_half_lives_ago = now - chrono::Duration::days(60);
        let w = d.weight(now, two_half_lives_ago);
        assert!((w - 0.25).abs() < 1e-6, "got {w}");
    }

    #[test]
    fn score_orders_eviction_correctly() {
        // Fresh + many reads should outrank cold + no reads.
        let d = EvictionDecay::new(30.0);
        let now: DateTime<Utc> = "2026-05-29T00:00:00Z".parse().unwrap();
        let fresh = d.score(now, now, 10);
        let cold = d.score(now, now - chrono::Duration::days(120), 0);
        assert!(
            fresh > cold,
            "fresh-hot must outrank cold-untouched (fresh={fresh}, cold={cold})"
        );
    }

    #[test]
    fn negative_half_life_clamped_to_epsilon() {
        let d = EvictionDecay::new(-1.0);
        let now: DateTime<Utc> = "2026-05-29T00:00:00Z".parse().unwrap();
        // With an epsilon half-life, any past row decays to ~0
        // quickly without panicking.
        let w = d.weight(now, now - chrono::Duration::seconds(1));
        assert!((0.0..=1.0).contains(&w));
    }

    #[test]
    fn sweep_report_default_is_noop() {
        let r = SweepReport::default();
        assert!(r.is_noop());
    }
}
