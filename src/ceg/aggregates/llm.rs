//! Section D — LLM call cost-aggregate primitives.
//!
//! Moved from `src/read/llm.rs` in v4.0 (FSD §3.3) — the cost-rollup
//! shapes live here; the list-shaped types (filter, cursor, page) moved
//! to `src/ceg/list/llm.rs`.
//!
//! [`crate::ceg::ReadEngine::aggregate_llm_costs`] returns rolled-up
//! cost statistics broken down by model / agent / deployment domain.
//!
//! Aggregation requires joining `trace_llm_calls` to `trace_events`
//! because the per-call rows don't carry `agent_id_hash` /
//! `deployment_domain` — those live on the parent reasoning event.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ceg::types::TimeWindow;

/// Per-model cost rollup. One row per distinct `model` in the window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelCostStats {
    /// Provider-reported model identifier.
    pub model: String,
    /// Number of LLM calls.
    pub call_count: i64,
    /// Sum of `prompt_tokens` across calls (NULLs treated as 0).
    pub prompt_tokens: i64,
    /// Sum of `completion_tokens` across calls (NULLs treated as 0).
    pub completion_tokens: i64,
    /// Sum of `cost_usd` across calls (NULLs treated as 0.0).
    pub cost_usd: f64,
    /// Count of calls where `status != Ok`.
    pub error_count: i64,
}

/// Per-agent cost rollup. One row per distinct `agent_id_hash` in
/// the window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentCostStats {
    /// Stable agent identifier (sha256 of public key).
    pub agent_id_hash: String,
    /// Human-readable name, when present on the parent traces.
    pub agent_name: Option<String>,
    /// Number of LLM calls attributed to this agent.
    pub call_count: i64,
    /// Sum of `prompt_tokens`.
    pub prompt_tokens: i64,
    /// Sum of `completion_tokens`.
    pub completion_tokens: i64,
    /// Sum of `cost_usd`.
    pub cost_usd: f64,
}

/// Per-deployment-domain cost rollup. One row per distinct
/// `deployment_domain`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DomainCostStats {
    /// Deployment domain tag from the parent trace's
    /// deployment_profile.
    pub deployment_domain: String,
    /// Number of LLM calls.
    pub call_count: i64,
    /// Sum of `cost_usd`.
    pub cost_usd: f64,
}

/// Window-level totals across every LLM call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TotalCostStats {
    /// Total LLM calls in the window.
    pub call_count: i64,
    /// Total prompt tokens.
    pub prompt_tokens: i64,
    /// Total completion tokens.
    pub completion_tokens: i64,
    /// Total USD cost.
    pub cost_usd: f64,
    /// Total non-Ok calls.
    pub error_count: i64,
}

/// Cost aggregate output. Same shape the lens cost dashboard already
/// computes via raw SQL; this primitive replaces the carve-out.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmCostAggregate {
    /// The window the aggregate covers. `None` when the filter has
    /// no `time_window` (then the aggregate spans every LLM call
    /// matching the other filter fields).
    pub time_window: Option<TimeWindow>,

    /// Per-model breakdown.
    pub by_model: HashMap<String, ModelCostStats>,

    /// Per-agent breakdown (keyed by `agent_id_hash`).
    pub by_agent: HashMap<String, AgentCostStats>,

    /// Per-deployment-domain breakdown.
    pub by_domain: HashMap<String, DomainCostStats>,

    /// Window-level totals.
    pub totals: TotalCostStats,
}
