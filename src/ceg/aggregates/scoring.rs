//! Section E + F — Scoring factor aggregates (CIRIS Capacity Score
//! primitives) and Coherence Ratchet divergence/drift/gap rows.
//!
//! Moved + merged in v4.0 (FSD §3.3): the section-E scoring shapes from
//! `src/read/scoring.rs` and the section-F Coherence-Ratchet input rows
//! (`DivergenceRow`, `TemporalDriftRow`, `OverrideRateRow`,
//! `HashChainGap`) that previously lived in `src/read/trace.rs` are
//! co-located here under the aggregates namespace.
//!
//! `api/scoring.py` runs N agents × M factors × window each pass; today
//! that's raw SQL. The clean substrate surface is one bundled aggregate
//! primitive returning everything any single factor calculation needs
//! in one DB round-trip — plus granular sub-primitives the bundled one
//! composes from, so analysts can ask narrower questions.
//!
//! This module defines the typed shapes; the [`crate::ceg::ReadEngine`]
//! trait carries the methods; the Postgres backend implements them.
//!
//! ## Capacity Score factor mapping
//!
//! Per Accord §"Capacity Score" the formula is `C × I_int × R × I_inc × S`:
//!
//! - **C — Core Identity**: `identity_changes` + `conscience_overrides`
//!   over the window. Stable identity = low changes + few overrides.
//! - **I_int — Integrity**: `audit_chain_total` + `audit_chain_gaps` —
//!   completeness of the agent's audit chain.
//! - **R — Resilience**: `recovery_events` (override → next-trace-pass
//!   intervals) + `drift_z_score` against a baseline window.
//! - **I_inc — Incompleteness Awareness**: `calibration_error` (ECE on
//!   epistemic_certainty vs outcome) + `unsafe_action_rate`.
//! - **S — Sustained Coherence**: `coherence_decay_series` for
//!   time-decay weighting in lens.
//!
//! Persist exposes the inputs; lens composes the formula. Persist does
//! NOT bake C/I_int/R/I_inc/S coefficients (those are lens policy).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ceg::types::{Aggregate, DeviationMetric, TimeWindow};

// ─── Section E — Scoring factor aggregates ─────────────────────────

/// Stable cache method-id for `aggregate_scoring_factors_batch`
/// (CIRISPersist#195, FSD §7.2). The batch result (a `Vec` of
/// per-agent aggregates) is cached as ONE entry keyed on the sorted
/// requested-agent set, so the streaming singular path
/// (`aggregate_scoring_factors`, routed through batch-of-one) and the
/// fleet batch path share the same cache entry shape.
pub const SCORING_FACTORS_METHOD_ID: &str = "aggregate_scoring_factors_batch:v1.0";

/// A scoring-factors cache, owned per backend instance (FSD §7.1 — "one
/// cache per cohab process"), mirroring
/// [`RepositoryStatsCache`](crate::ceg::aggregates::repository::RepositoryStatsCache).
///
/// The whole batch result is cached as one `Vec<ScoringFactorAggregate>`
/// entry keyed on the sorted agent set + window + baseline + ingest
/// watermark (see [`scoring_factors_cache_key`]). Scoped to the backend
/// instance so a Postgres engine never serves an entry a prior SQLite
/// engine wrote, and `reset_engine` drops its cache.
pub type ScoringFactorsCache = crate::cache::Cache<Vec<ScoringFactorAggregate>>;

/// Build the [`crate::cache::CacheKey`] for an
/// `aggregate_scoring_factors_batch` call (CIRISPersist#195, FSD §7.2 /
/// §7.3).
///
/// The **filter_digest** slot folds, in order, everything that changes
/// the answer for a fixed scope:
///
/// - the `agent_id_hashes` **sorted** — set-semantics, so caller order
///   never changes the key (two callers requesting the same agent set in
///   a different order share the entry);
/// - the main `window` (since + until);
/// - the optional `baseline_window` (present/absent + its bounds);
/// - the **ingest watermark** — `max(ts)` over the requested agents under
///   the same scope predicate the compute applies. This is the §7.3
///   invalidation signal for this primitive: new ingest for any requested
///   agent advances the watermark → new key → miss → recompute. TTL still
///   bounds staleness on top of this.
///
/// The `scope_digest` slot reuses repository's
/// [`scope_digest_for`](crate::ceg::aggregates::repository::scope_digest_for)
/// (§7.3 scope-disjoint). Window bounds + `bucket` are passed exactly as
/// in `repository_stats_cache_key` so write-invalidation buckets line up.
pub fn scoring_factors_cache_key(
    agent_id_hashes: &[String],
    window: &TimeWindow,
    baseline_window: Option<&TimeWindow>,
    scope: &crate::scope::CallerScope,
    ingest_watermark_ms: i64,
    invalidation_bucket: std::time::Duration,
) -> crate::cache::CacheKey {
    use crate::ceg::types::filter::canonical_window_bytes;

    let scope_digest = crate::ceg::aggregates::repository::scope_digest_for(scope);

    let mut h = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut h, b"ScoringFactorsFilter:v1.0\0");
    // Sorted agent set — caller order must not matter (set-semantics).
    let mut agents: Vec<&String> = agent_id_hashes.iter().collect();
    agents.sort();
    sha2::Digest::update(&mut h, (agents.len() as u64).to_le_bytes());
    for a in agents {
        sha2::Digest::update(&mut h, (a.len() as u64).to_le_bytes());
        sha2::Digest::update(&mut h, a.as_bytes());
    }
    // Main window.
    sha2::Digest::update(&mut h, b"|w\0");
    sha2::Digest::update(&mut h, canonical_window_bytes(window));
    // Optional baseline window (present/absent is part of the key).
    sha2::Digest::update(&mut h, b"|b\0");
    match baseline_window {
        Some(b) => {
            sha2::Digest::update(&mut h, [1u8]);
            sha2::Digest::update(&mut h, canonical_window_bytes(b));
        }
        None => sha2::Digest::update(&mut h, [0u8]),
    }
    // Ingest watermark — the invalidation signal (load-bearing).
    sha2::Digest::update(&mut h, b"|iw\0");
    sha2::Digest::update(&mut h, ingest_watermark_ms.to_le_bytes());
    let filter_digest: [u8; 32] = sha2::Digest::finalize(h).into();

    crate::cache::CacheKey::new(
        SCORING_FACTORS_METHOD_ID,
        &filter_digest,
        &scope_digest,
        window.since.timestamp_millis(),
        window.until.timestamp_millis(),
        invalidation_bucket,
    )
}

/// Reorder a cached batch result onto the caller's requested
/// `agent_id_hashes` order (CIRISPersist#195).
///
/// The cache entry is shared set-wise (the key folds the *sorted* agent
/// set), but `aggregate_scoring_factors_batch` returns one aggregate per
/// agent in **input order**. On a hit we therefore remap the cached set
/// onto the requested order so two callers requesting the same set in
/// different orders each get their own order back. Any requested agent
/// not present in the cached set (shouldn't happen — same set produced
/// the entry) is dropped; the result length matches the cached set.
pub fn reorder_scoring_to_input(
    cached: Vec<ScoringFactorAggregate>,
    agent_id_hashes: &[String],
) -> Vec<ScoringFactorAggregate> {
    use std::collections::HashMap;
    let mut by_agent: HashMap<&str, ScoringFactorAggregate> = cached
        .iter()
        .map(|a| (a.agent_id_hash.as_str(), a.clone()))
        .collect();
    let mut out = Vec::with_capacity(agent_id_hashes.len());
    for h in agent_id_hashes {
        if let Some(a) = by_agent.remove(h.as_str()) {
            out.push(a);
        }
    }
    out
}

/// Approximate the resident byte size of a batch result for the cache's
/// `max_bytes` accounting (§7.2), mirroring repository's `estimate_size`.
/// Sums a coarse per-aggregate estimate (fixed scalars plus the variable
/// `recovery_events` / `coherence_decay_series` vecs + the agent-hash
/// string). Exactness is not load-bearing — LRU budgeting only.
pub fn estimate_size(batch: &[ScoringFactorAggregate]) -> usize {
    let base = std::mem::size_of::<Vec<ScoringFactorAggregate>>();
    base + batch
        .iter()
        .map(|a| {
            std::mem::size_of::<ScoringFactorAggregate>()
                + a.agent_id_hash.len()
                + a.recovery_events.len() * (std::mem::size_of::<RecoveryEvent>() + 64)
                + a.coherence_decay_series.len() * std::mem::size_of::<CoherencePoint>()
        })
        .sum::<usize>()
}

/// One bundled aggregate covering every factor input for a single
/// agent + window. Lens consumes this to compute the Capacity Score
/// factors without further DB round-trips.
///
/// AV-43 (read-side adversary): aggregates return computed statistics,
/// not per-trace content. Callers running narrow windows apply
/// k-anonymity policy at their layer (e.g., refuse to compute scores
/// when `trace_count < threshold`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScoringFactorAggregate {
    /// Agent identity (echoed for batch-result mapping).
    pub agent_id_hash: String,
    /// Window the aggregate is computed over (echoed for caller
    /// convenience).
    pub window: TimeWindow,
    /// Total traces observed in the window. Lens applies k-anonymity
    /// at its layer based on this count.
    pub trace_count: i64,

    // ── Factor C: Core Identity ──
    /// Count of `agent_id_hash` transitions for this agent's
    /// `agent_name` within the window.
    pub identity_changes: i64,
    /// Count of `action_was_overridden = true` traces in the window.
    pub conscience_overrides: i64,

    // ── Factor I_int: Integrity ──
    /// Total audit-chain entries observed (sum of
    /// `audit_sequence_number` count across `ACTION_RESULT` rows).
    pub audit_chain_total: i64,
    /// Detected gaps in the audit-chain sequence
    /// (count of `HashChainGap` rows over the window).
    pub audit_chain_gaps: i64,
    /// Audit entries with non-null `audit_signature`.
    pub audit_signed_total: i64,

    // ── Factor R: Resilience ──
    /// Override → next-trace-pass intervals. One entry per recovery
    /// event observed in the window.
    pub recovery_events: Vec<RecoveryEvent>,
    /// Z-score vs the optional `baseline_window`. `None` if no
    /// baseline was supplied or if either window has insufficient
    /// samples.
    pub drift_z_score: Option<f64>,

    // ── Factor I_inc: Incompleteness Awareness ──
    /// Expected Calibration Error on `epistemic_certainty` vs
    /// outcome. `None` if epistemic_certainty isn't recorded in the
    /// agent's traces yet.
    pub calibration_error: Option<f64>,
    /// `unsafe_action_count / trace_count`. An "unsafe action" is a
    /// trace where the conscience reported a fail AND the action was
    /// executed (overridden in the wrong direction).
    pub unsafe_action_rate: f64,

    // ── Factor S: Sustained Coherence ──
    /// Coherence pass-rate sampled at fixed-cadence subwindows
    /// across the main window. Lens applies time-decay weighting.
    pub coherence_decay_series: Vec<CoherencePoint>,

    /// Unix-ms the aggregate was computed against the backend (the
    /// *cached* time when `cache_hit`). Mirrors
    /// [`RepositoryStatistics::evaluated_at_unix_ms`](crate::ceg::aggregates::repository::RepositoryStatistics).
    /// CIRISPersist#195.
    #[serde(default)]
    pub evaluated_at_unix_ms: i64,
    /// `true` iff served from the substrate cache (§7). CIRISPersist#195.
    #[serde(default)]
    pub cache_hit: bool,
}

impl Aggregate for ScoringFactorAggregate {
    /// The window trace count is the scope-filtered windowed sample
    /// denominator (FSD §6.1) — lens applies its k-anonymity policy
    /// against this (AV-43).
    fn sample_count(&self) -> i64 {
        self.trace_count
    }
    fn evaluated_at_unix_ms(&self) -> i64 {
        self.evaluated_at_unix_ms
    }
    fn cache_hit(&self) -> bool {
        self.cache_hit
    }
}

/// One recovery event — the agent's conscience overrode an action
/// at trace_a, then the agent's NEXT trace passed conscience.
/// Interval = trace_b.started_at - trace_a.completed_at.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoveryEvent {
    /// Override-trace identifier.
    pub override_trace_id: String,
    /// Wall-clock when override happened
    /// (`override_trace.completed_at`).
    pub override_at: DateTime<Utc>,
    /// Recovery-trace identifier (next trace by `started_at`).
    pub recovery_trace_id: String,
    /// Wall-clock when recovery started.
    pub recovery_at: DateTime<Utc>,
    /// Recovery latency in seconds (`recovery_at - override_at`).
    pub recovery_latency_seconds: f64,
}

/// One sample point in `coherence_decay_series`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoherencePoint {
    /// Subwindow start.
    pub at: DateTime<Utc>,
    /// `coherence_passed = true` count in the subwindow.
    pub coherence_passed_count: i64,
    /// Trace count in the subwindow.
    pub trace_count: i64,
    /// `coherence_passed_count / trace_count`. `0.0` when no traces.
    pub coherence_pass_rate: f64,
}

/// Granular audit-chain aggregate. Returned by
/// [`crate::ceg::ReadEngine::aggregate_audit_chain`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditChainAggregate {
    /// Total audit entries observed in the filter window.
    pub audit_total: i64,
    /// Audit entries with non-null `audit_signature`.
    pub audit_signed: i64,
    /// Audit entries with non-null `audit_entry_hash`.
    pub audit_hashed: i64,
    /// Detected gaps (count of contiguous-sequence breaks).
    pub gap_count: i64,
}

// ─── Section F — Coherence Ratchet inputs ──────────────────────────

/// One agent's divergence from the deployment-domain peer mean over
/// a window. Lens computes detection (clustering, threshold) from
/// these inputs; persist provides the windowed peer-mean reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DivergenceRow {
    /// Agent identity.
    pub agent_id_hash: String,
    /// Optional human-readable agent name.
    pub agent_name: Option<String>,
    /// Z-score against the domain peer mean.
    pub z_score: f64,
    /// Which metric drove the divergence.
    pub deviation_metric: DeviationMetric,
    /// Trace count contributing to this z-score (lens-side k-anon
    /// filtering — see AV-43 in THREAT_MODEL.md).
    pub sample_count: i64,
}

/// Drift between two windows for a single agent on a single metric.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemporalDriftRow {
    /// The metric this row reports.
    pub deviation_metric: DeviationMetric,
    /// Baseline (earlier) window.
    pub baseline_window: TimeWindow,
    /// Comparison (later) window.
    pub comparison_window: TimeWindow,
    /// `comparison_mean - baseline_mean`.
    pub mean_shift: f64,
    /// `comparison_var / baseline_var`.
    pub variance_ratio: f64,
    /// Significance metric (z-score under normal-mean approximation).
    /// Lens applies its own p-value mapping.
    pub significance: f64,
}

/// One detected gap in the agent's audit-chain sequence number
/// timeline. `gap_start_seq` is the last-seen seq before the gap;
/// `gap_end_seq` is the first-seen seq after.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HashChainGap {
    /// Agent identity.
    pub agent_id_hash: String,
    /// Last sequence number seen before the gap.
    pub gap_start_seq: i64,
    /// First sequence number seen after the gap.
    pub gap_end_seq: i64,
    /// Wall-clock of the last pre-gap entry.
    pub gap_start_ts: DateTime<Utc>,
    /// Wall-clock of the first post-gap entry.
    pub gap_end_ts: DateTime<Utc>,
}

/// One agent's conscience-override rate over a window, with the
/// deployment-domain average for ratio computation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OverrideRateRow {
    /// Agent identity.
    pub agent_id_hash: String,
    /// Optional human-readable agent name.
    pub agent_name: Option<String>,
    /// Deployment domain (echoed for caller convenience).
    pub deployment_domain: Option<String>,
    /// Number of conscience overrides observed in the window.
    pub override_count: i64,
    /// Total trace count in the window (denominator).
    pub trace_count: i64,
    /// `override_count / trace_count`. `0.0` when `trace_count == 0`.
    pub override_rate: f64,
    /// Average override rate across all agents in the same domain.
    pub domain_avg_rate: f64,
    /// `override_rate / domain_avg_rate`. `1.0` when both are equal;
    /// >1.0 means this agent overrides more than peers.
    pub multiple_of_domain_avg: f64,
}
