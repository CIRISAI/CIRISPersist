//! Section D — LLM call surface primitives.
//!
//! Drives `/cost`, `/latency`, model-breakdown dashboards, and
//! prompt-hash analysis. Two primitives:
//!
//! - [`super::ReadEngine::list_llm_calls`] — cursor-paged listing of
//!   `cirislens.trace_llm_calls` rows, filterable by time / agent /
//!   model / status / trace / thought.
//! - [`super::ReadEngine::aggregate_llm_costs`] — rolled-up cost
//!   statistics broken down by model / agent / deployment domain.
//!
//! Aggregation requires joining `trace_llm_calls` to `trace_events`
//! because the per-call rows don't carry `agent_id_hash` /
//! `deployment_domain` — those live on the parent reasoning event.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::TimeWindow;
use crate::schema::LlmCallStatus;
use crate::store::types::TraceLlmCallRow;

/// Filter for [`super::ReadEngine::list_llm_calls`] and
/// [`super::ReadEngine::aggregate_llm_costs`]. Composes AND-style;
/// every field is optional.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmCallFilter {
    /// Window on `ts` (the LLM call's wall-clock start time).
    pub time_window: Option<TimeWindow>,

    /// Filter by parent agent. AV-9: trace-scoped reads MUST be
    /// authorized at the caller's layer; this filter narrows the
    /// result set but does not itself authenticate.
    pub agent_id_hash: Option<String>,

    /// Filter by human-readable agent name (e.g. `Scout`).
    pub agent_name: Option<String>,

    /// Filter by `deployment_domain` (drives per-deployment cost
    /// dashboards).
    pub deployment_domain: Option<String>,

    /// Filter by provider-reported model identifier.
    pub model: Option<String>,

    /// Filter by call status (`Ok`, `Timeout`, `RateLimited`, etc.).
    pub status: Option<LlmCallStatus>,

    /// Filter by a specific trace.
    pub trace_id: Option<String>,

    /// Filter by a specific thought.
    pub thought_id: Option<String>,
}

/// Opaque cursor for [`super::ReadEngine::list_llm_calls`].
///
/// Built around the `(ts, trace_id, attempt_index)` tuple — paged
/// queries order by `ts DESC, trace_id DESC, attempt_index DESC`
/// (newest-first). The triple is unique within `trace_llm_calls` —
/// at most one row per `(trace_id, parent_event_id, attempt_index)`
/// per V001, and `parent_event_id` is determined by `ts` within a
/// trace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmCallCursor {
    /// Cursor format version. v0.5.5 ships `"v1"`.
    pub version: String,

    /// `ts` of the last LLM call row on the previous page.
    pub last_ts: DateTime<Utc>,

    /// `trace_id` of the last row.
    pub last_trace_id: String,

    /// `attempt_index` of the last row (tiebreaker within a trace).
    pub last_attempt_index: u32,
}

impl LlmCallCursor {
    /// Construct a v1 cursor from the trailing edge of a result page.
    pub fn from_trailing(
        last_ts: DateTime<Utc>,
        last_trace_id: String,
        last_attempt_index: u32,
    ) -> Self {
        LlmCallCursor {
            version: "v1".to_owned(),
            last_ts,
            last_trace_id,
            last_attempt_index,
        }
    }
}

/// One page of LLM call rows, newest-first by `ts`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmCallListPage {
    /// LLM call rows in `ts DESC, trace_id DESC, attempt_index DESC` order.
    pub items: Vec<TraceLlmCallRow>,
    /// Cursor for the next page; `None` when there are no more rows.
    pub next_cursor: Option<LlmCallCursor>,
}

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
