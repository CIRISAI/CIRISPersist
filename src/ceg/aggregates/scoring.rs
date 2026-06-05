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

use crate::ceg::types::{DeviationMetric, TimeWindow};

// ─── Section E — Scoring factor aggregates ─────────────────────────

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
