//! Row-shaped types — what the Backend trait reads and writes.
//!
//! # Mission alignment (MISSION.md §2 — `store/`)
//!
//! Same row shape across backends (Postgres, SQLite, in-memory test).
//! Naming and column types here mirror
//! `context/lens_027_trace_events.sql` so the SQL writer is a
//! straightforward field-by-field map. Drift between this struct and
//! the SQL schema is the failure mode that breaks corpus
//! reconstruction; reviewers MUST cross-check against the migration
//! file when updating either.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::schema::{LlmCallStatus, ReasoningEventType, TraceLevel};

/// A row landing on `cirislens.trace_events`
/// (`context/lens_027_trace_events.sql` lines 13-38).
///
/// Mission constraint: `payload` IS the agent's testimony kept
/// verbatim (the JSONB column). Typed accessors live on the wire
/// type [`crate::schema::TraceComponent`]; once decomposed to a row,
/// the typed extracts have already been pulled into the denormalized
/// columns (`cost_*`, `attempt_index`, etc.) and the `payload` blob
/// is the on-disk archive of the original `data` dict.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceEventRow {
    pub trace_id: String,
    pub thought_id: String,
    pub task_id: Option<String>,

    /// Derived from `event_type` per the H3ERE step sequence; phase 1
    /// approximation pulls it from `data["step_point"]` if present,
    /// else infers a default from `event_type`.
    pub step_point: Option<String>,

    pub event_type: ReasoningEventType,
    pub attempt_index: u32,
    pub ts: DateTime<Utc>,

    pub agent_name: Option<String>,
    pub agent_id_hash: String,
    pub cognitive_state: Option<String>,

    pub trace_level: TraceLevel,
    pub payload: serde_json::Map<String, serde_json::Value>,

    /// Denormalized cost columns — populated only on the
    /// `ACTION_RESULT` row (TRACE_WIRE_FORMAT.md §5.9). Other rows
    /// leave these `None`.
    pub cost_llm_calls: Option<i32>,
    pub cost_tokens: Option<i32>,
    pub cost_usd: Option<f64>,

    /// Per-trace agent signature (carried verbatim from the
    /// CompleteTrace; identical across all rows of the same trace).
    pub signature: String,
    pub signing_key_id: String,
    /// True after [`crate::verify::verify_trace`] returned `Ok` for
    /// this row's parent CompleteTrace; never persisted as `false`
    /// for unverified bytes (MISSION.md §3 anti-pattern #2 —
    /// "store first, verify later" is rejected).
    pub signature_verified: bool,

    pub schema_version: String,
    /// True after the scrubber pass ran.
    pub pii_scrubbed: bool,

    // ─── v0.1.3 scrub envelope columns (FSD §3.7; THREAT_MODEL.md
    // AV-24/25). Always populated on rows produced by the v0.1.3+
    // pipeline; pre-v0.1.3 rows have these as None.
    /// sha256 of canonical(component.data_pre_scrub) — proves what
    /// the scrubber input was without retaining the original bytes.
    pub original_content_hash: Option<String>,
    /// base64(ed25519_sign(canonical(component.data_post_scrub))) —
    /// cryptographic proof that *this deployment* processed *this
    /// payload* at *this time*, verifiable by any peer with the
    /// deployment's published public key.
    pub scrub_signature: Option<String>,
    /// The deployment's signing-key id (lens-scrub-v1, etc.). Same
    /// key as the agent's wire-format §8 key on Phase 2+
    /// deployments — single-key principle.
    pub scrub_key_id: Option<String>,
    /// When the scrub+sign happened. Bounds the window between the
    /// trace's `completed_at` and lens handling.
    pub scrub_timestamp: Option<chrono::DateTime<chrono::Utc>>,
}

/// A row landing on `cirislens.trace_llm_calls`
/// (`context/lens_027_trace_events.sql` lines 58-103).
///
/// Phase 1: produced for every `LLM_CALL` component
/// (TRACE_WIRE_FORMAT.md §5.10). Linked to its parent `trace_events`
/// row via `parent_event_id` once the parent insert returns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceLlmCallRow {
    pub trace_id: String,
    pub thought_id: String,
    pub task_id: Option<String>,

    /// FK to `trace_events.event_id` once the parent insert returns
    /// the row's PK. `None` until the parent is persisted.
    pub parent_event_id: Option<i64>,
    pub parent_event_type: ReasoningEventType,
    pub parent_attempt_index: u32,

    /// Monotonic per `(thought_id, parent_event_id)`; for our purposes
    /// the same as `LlmCallSummary.attempt_index`.
    pub attempt_index: u32,

    pub ts: DateTime<Utc>,

    pub duration_ms: f64,
    pub handler_name: String,
    pub service_name: String,

    pub model: Option<String>,
    pub base_url: Option<String>,
    pub response_model: Option<String>,

    pub prompt_tokens: Option<i32>,
    pub completion_tokens: Option<i32>,
    pub prompt_bytes: Option<i32>,
    pub completion_bytes: Option<i32>,
    pub cost_usd: Option<f64>,

    pub status: LlmCallStatus,
    pub error_class: Option<String>,
    pub attempt_count: Option<i32>,
    pub retry_count: Option<i32>,

    pub prompt_hash: Option<String>,
    /// FULL trace-level only.
    pub prompt: Option<String>,
    /// FULL trace-level only.
    pub response_text: Option<String>,
}

/// Phase 2 stub — agent audit-log entry shape (FSD §4.1).
///
/// Carried as a placeholder type so the Backend trait surface can
/// reference it from Phase 1; full impl + DAO migration in Phase 2.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence_number: i64,
    pub previous_hash: String,
    pub entry_hash: String,
    pub signature: String,
    pub signing_key_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub event_summary: String,
    pub agent_id: String,
    /// JSONB payload — the audit event's full data dict.
    pub payload: serde_json::Value,
}

/// Phase 2 stub — service correlation shape (FSD §4.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceCorrelation {
    pub correlation_id: String,
    pub service_type: String,
    pub correlation_type: String,
    pub timestamp: DateTime<Utc>,
    pub agent_id: String,
    pub payload: serde_json::Value,
}

/// Phase 3 stub — task shape (FSD §5.1).
///
/// Mission constraint: multi-occurrence semantics preserved verbatim
/// (FSD §5.6) — `agent_occurrence_id` namespace and `try_claim_shared_task`
/// race-claim are first-class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    pub task_id: String,
    pub agent_occurrence_id: String,
    pub channel_id: String,
    pub description: String,
    pub status: String,
    pub priority: u8,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub task_type: Option<String>,
    pub signed_by: Option<String>,
    pub signature: Option<String>,
    pub signed_at: Option<DateTime<Utc>>,
}

/// Phase 3 stub — graph node shape (FSD §5.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    pub node_id: String,
    pub node_type: String,
    pub scope: String,
    pub agent_occurrence_id: String,
    pub attributes_json: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: i32,
}

/// Phase 3 stub — `try_claim_shared_task` parameter group
/// (FSD §5.6 — multi-occurrence atomicity primitive).
#[derive(Debug, Clone)]
pub struct ClaimParams<'a> {
    pub task_type: &'a str,
    pub occurrence_id: &'a str,
    pub channel_id: &'a str,
    pub description: &'a str,
    pub priority: u8,
    pub now: DateTime<Utc>,
}
