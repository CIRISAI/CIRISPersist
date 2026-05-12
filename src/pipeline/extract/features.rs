//! Typed feature struct produced by the extract stage.
//!
//! Lifted from CIRISLensCore `src/extract/features.rs` (v0.6.0-α3).
//! Continuous cost/tokens/model features are P0 inputs to the
//! declared-vs-inferred mismatch detection (LC-AV-2). Resourcing tier
//! (TRACE_WIRE_FORMAT.md §3.3) is a derived analytic and is NOT a
//! Phase 1 cohort axis — cohort cells are the 5-tuple of
//! wire-declared axes only.
//!
//! Persist-side adaptation: `Serialize + Deserialize` derives added
//! to every type so [`Features`] round-trips through the
//! `cirislens.trace_events.extracted_features` JSONB column added in
//! V009.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Trace-level features computed in the extract stage.
///
/// Consumed by cohort routing and detector evaluation; persisted via
/// the [`extracted_features`](super) JSONB column when the pipeline
/// runs. Single-trace lifetime; not aggregated across traces.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Features {
    /// 5 wire-declared cohort axes from the agent-signed
    /// `deployment_profile` block (CIRISAgent#718). Phase 1 cohort
    /// cell is exactly this tuple.
    pub declared: DeclaredCohortAxes,

    /// Per-event_type timestamps lifted from trace components.
    pub step_timestamps: StepTimestamps,

    /// Numeric privacy-safe metrics about observation complexity.
    pub observation_weights: ObservationWeights,

    /// Models observed in `LLM_CALL` components. Input to the
    /// resourcing classifier and to LC-AV-2 mismatch detection.
    pub models_used: Vec<String>,

    /// Per-event_type full-component JSON blobs (`DMA_RESULTS`,
    /// `ASPDMA_RESULT`, etc.). Keys are the static event_type
    /// strings the legacy code uses.
    pub component_blobs: HashMap<String, Value>,

    /// Continuous cost feature. P0 input to LC-AV-2 declared-vs-
    /// inferred mismatch. Dollars per trace.
    pub cost_estimate: f64,

    /// Total tokens observed across the trace's `LLM_CALL`
    /// components. P0 input to LC-AV-2.
    pub total_tokens: u64,

    /// Coarse model class observed. P0 input to LC-AV-2.
    pub model_class: ModelClass,
}

/// 6-tuple cohort axes — the agent-declared `deployment_profile`
/// block (CIRISAgent FSD `TRACE_WIRE_FORMAT.md` §3.2,
/// RATCHET-confirmed 2026-05-04).
///
/// `deployment_resourcing` (lens-computed, §3.3) is NOT in the
/// cohort key — used for explainability/analytics only.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeclaredCohortAxes {
    /// Agent role (e.g. `"ally"`).
    pub agent_role: Option<String>,
    /// Agent template (e.g. `"ally-v3-default"`).
    pub agent_template: Option<String>,
    /// Deployment domain (e.g. `"moderation"`).
    pub deployment_domain: Option<String>,
    /// Deployment type (e.g. `"production"`).
    pub deployment_type: Option<String>,
    /// Deployment region (e.g. `"US"`).
    pub deployment_region: Option<String>,
    /// Deployment trust mode (e.g. `"federated_peer"`).
    pub deployment_trust_mode: Option<String>,
}

/// Per-step timestamps lifted from trace components. `None` when the
/// trace does not contain that event_type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StepTimestamps {
    /// `THOUGHT_START` component timestamp.
    pub thought_start: Option<DateTime<Utc>>,
    /// `SNAPSHOT_AND_CONTEXT` component timestamp.
    pub snapshot: Option<DateTime<Utc>>,
    /// `DMA_RESULTS` component timestamp.
    pub dma_results: Option<DateTime<Utc>>,
    /// `ASPDMA_RESULT` component timestamp.
    pub aspdma: Option<DateTime<Utc>>,
    /// `IDMA_RESULT` component timestamp.
    pub idma: Option<DateTime<Utc>>,
    /// `TSASPDMA_RESULT` component timestamp.
    pub tsaspdma: Option<DateTime<Utc>>,
    /// `CONSCIENCE_RESULT` component timestamp.
    pub conscience: Option<DateTime<Utc>>,
    /// `ACTION_RESULT` component timestamp.
    pub action_result: Option<DateTime<Utc>>,
}

/// Observation-complexity numerics. Privacy-safe by construction
/// (counts only, no text content). `None` when the corresponding
/// event_type is absent or the source field is missing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObservationWeights {
    /// `relevant_memories.len()` from `SNAPSHOT_AND_CONTEXT`.
    pub memory_count: Option<u32>,
    /// `context_tokens` / `total_tokens` / estimated from
    /// `gathered_context.len()` from `SNAPSHOT_AND_CONTEXT`.
    pub context_tokens: Option<u32>,
    /// `conversation_history.len()` from `SNAPSHOT_AND_CONTEXT`.
    pub conversation_turns: Option<u32>,
    /// `action_options` / `evaluated_actions` / `alternatives` len
    /// from `ASPDMA_RESULT`.
    pub alternatives_considered: Option<u32>,
    /// `checks` / `ethical_checks` / `check_results` len from
    /// `CONSCIENCE_RESULT`, with fallback to per-flag counting.
    pub conscience_checks_count: Option<u32>,
}

/// Model class observed in `LLM_CALL` components. Phase 1 keeps this
/// open-ended; specific bucketing (small / mid / large) is
/// RATCHET-calibrated and not normative at v0.1.0.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum ModelClass {
    /// No `LLM_CALL` components in the trace, or `models_used` was
    /// absent.
    #[default]
    Unknown,
    /// Specific model identifier observed (e.g. `"claude-3-opus"`,
    /// `"gpt-4"`). Multiple distinct models in one trace flatten to
    /// the first observed; downstream LC-AV-2 detection works on
    /// `models_used: Vec<String>` directly when full distribution
    /// matters.
    Named(String),
}
