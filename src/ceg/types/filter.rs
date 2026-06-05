//! [`TraceFilter`] — filter struct for trace queries (sections A / E) —
//! and [`DeviationMetric`], the Coherence Ratchet divergence
//! discriminator (section F).
//!
//! Moved from `src/read/types.rs` in v4.0 (FSD §3.3). No behaviour
//! change; the `Filter` trait + composable filter primitives the FSD
//! §5 names land in a LATER v4.0 commit — this file holds only the
//! v3.x filter shapes relocated under the new namespace.

use serde::{Deserialize, Serialize};

use super::window::TimeWindow;
use crate::schema::TraceLevel;

/// Filter struct for [`crate::ceg::ReadEngine::list_trace_summaries`]
/// and the granular `count_*` primitives.
///
/// Every field is optional; an empty filter returns the full table
/// (subject to the caller's `limit`). Filters compose AND-style — a
/// filter with `agent_id_hash = Some` AND `time_window = Some` returns
/// rows matching BOTH.
///
/// **Index coverage** (CIRISPersist#23 §"Hot-path requirements" #4):
/// every filter combination MUST hit an existing index on
/// `cirislens.trace_events`. The Postgres impl validates this against
/// the v0.4.x index set
/// (`trace_events_journey`, `trace_events_agent_ts`,
/// `trace_events_type_ts`, `trace_events_deployment_*`). New filter
/// combinations that miss every index ship with their index in the
/// same migration as the read primitive that needs them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceFilter {
    /// Window on `started_at` (= the trace's first component
    /// timestamp). `None` returns all timestamps.
    pub time_window: Option<TimeWindow>,

    /// Filter by `agent_id_hash`. `None` returns all agents.
    /// **AV-9**: trace-scoped reads MUST gate on `agent_id_hash`
    /// at the caller's authorization layer; this filter narrows
    /// the result set but does not itself authenticate.
    pub agent_id_hash: Option<String>,

    /// Filter by human-readable agent name. `None` returns all.
    pub agent_name: Option<String>,

    /// Filter by `deployment_profile.deployment_domain`. `None`
    /// returns all domains.
    pub deployment_domain: Option<String>,

    /// Filter by `deployment_profile.deployment_type` (`production` /
    /// `staging` / `research` / etc.).
    pub deployment_type: Option<String>,

    /// Filter by [`TraceLevel`]. `None` returns all levels.
    pub trace_level: Option<TraceLevel>,

    /// Filter by signature_verified. `None` returns both verified
    /// and (in legacy / pre-v0.1.3 rows) unverified — but per
    /// MISSION.md §3 anti-pattern #2 the production substrate
    /// never persists `signature_verified=false`, so this filter
    /// is effectively a tautology in v0.4.x+ corpora and exposed
    /// for forward-compat only.
    pub signature_verified: Option<bool>,

    /// Filter by wire-format schema version (`"2.7.0"` / `"2.7.9"` /
    /// `"2.7.legacy"`). `None` returns all versions.
    pub schema_version: Option<String>,

    /// Filter by cognitive_state tag (`work` / `wakeup` / `dream` /
    /// etc.). `None` returns all states.
    pub cognitive_state: Option<String>,
}

/// Discriminator for [`crate::ceg::ReadEngine::cross_agent_divergence`]
/// — which DMA / conscience metric drives the z-score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviationMetric {
    /// Common Sense DMA plausibility score.
    CsdmaPlausibility,
    /// Domain-Specific DMA domain-alignment score.
    DsdmaDomainAlignment,
    /// Identity DMA effective-K coefficient.
    IdmaKEff,
    /// Identity DMA correlation-risk metric.
    IdmaCorrelationRisk,
    /// Conscience override rate (overrides / traces).
    ConscienceOverrideRate,
}

impl DeviationMetric {
    /// JSONB path on `trace_events.payload` for this metric, where
    /// applicable. Returns `None` for metrics computed at the
    /// trace-row level (override rate is a count over rows, not a
    /// payload extraction).
    pub fn payload_path(&self) -> Option<&'static str> {
        match self {
            DeviationMetric::CsdmaPlausibility => Some("$.csdma_plausibility_score"),
            DeviationMetric::DsdmaDomainAlignment => Some("$.dsdma_domain_alignment"),
            DeviationMetric::IdmaKEff => Some("$.idma_k_eff"),
            DeviationMetric::IdmaCorrelationRisk => Some("$.idma_correlation_risk"),
            DeviationMetric::ConscienceOverrideRate => None,
        }
    }
}
