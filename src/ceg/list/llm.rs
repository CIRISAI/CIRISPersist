//! Section D — LLM call listing primitives.
//!
//! Moved from `src/read/llm.rs` in v4.0 (FSD §3.3) — the list-shaped
//! types (filter, cursor, page) live here; the cost-rollup aggregate
//! shapes moved to `src/ceg/aggregates/llm.rs`.
//!
//! Drives `/cost`, `/latency`, model-breakdown dashboards, and
//! prompt-hash analysis via
//! [`crate::ceg::ReadEngine::list_llm_calls`] — cursor-paged listing of
//! `cirislens.trace_llm_calls` rows, filterable by time / agent /
//! model / status / trace / thought.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ceg::types::TimeWindow;
use crate::schema::LlmCallStatus;
use crate::store::types::TraceLlmCallRow;

/// Filter for [`crate::ceg::ReadEngine::list_llm_calls`] and
/// [`crate::ceg::ReadEngine::aggregate_llm_costs`]. Composes AND-style;
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

/// Opaque cursor for [`crate::ceg::ReadEngine::list_llm_calls`].
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
