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
    /// Stable trace identifier (CompleteTrace.trace_id).
    pub trace_id: String,
    /// Thought-iteration identifier within the trace.
    pub thought_id: String,
    /// Optional originating task identifier; absent for traces that
    /// originate outside a task (passive observations, etc.).
    pub task_id: Option<String>,

    /// Derived from `event_type` per the H3ERE step sequence; phase 1
    /// approximation pulls it from `data["step_point"]` if present,
    /// else infers a default from `event_type`.
    pub step_point: Option<String>,

    /// Typed event kind (THOUGHT_START / CONSCIENCE_RESULT / etc.).
    pub event_type: ReasoningEventType,
    /// Per-`(thought_id, event_type)` attempt counter. Bounded by
    /// `schema::MAX_ATTEMPT_INDEX` (THREAT_MODEL.md AV-17).
    pub attempt_index: u32,
    /// Wall-clock at which the event happened.
    pub ts: DateTime<Utc>,

    /// Optional human-readable agent name (debug / display only).
    pub agent_name: Option<String>,
    /// SHA-256 digest of the agent's identity tuple (the dedup-key
    /// prefix; THREAT_MODEL.md AV-9).
    pub agent_id_hash: String,
    /// Cognitive-state tag for the agent at the moment of the event.
    pub cognitive_state: Option<String>,

    /// Trace verbosity level (generic / detailed / full_traces).
    pub trace_level: TraceLevel,
    /// Verbatim component data dict (post-scrub if the scrubber
    /// modified it; pre-scrub bytes are NOT retained).
    pub payload: serde_json::Map<String, serde_json::Value>,

    /// Denormalized cost columns — populated only on the
    /// `ACTION_RESULT` row (TRACE_WIRE_FORMAT.md §5.9). Other rows
    /// leave these `None`.
    pub cost_llm_calls: Option<i32>,
    /// LLM token cost summed over the trace's LLM calls.
    pub cost_tokens: Option<i32>,
    /// USD cost summed over the trace's LLM calls.
    pub cost_usd: Option<f64>,

    /// Per-trace agent signature (carried verbatim from the
    /// CompleteTrace; identical across all rows of the same trace).
    pub signature: String,
    /// Identifier for the agent's signing key (looked up against
    /// `accord_public_keys`).
    pub signing_key_id: String,
    /// True after [`crate::verify::verify_trace`] returned `Ok` for
    /// this row's parent CompleteTrace; never persisted as `false`
    /// for unverified bytes (MISSION.md §3 anti-pattern #2 —
    /// "store first, verify later" is rejected).
    pub signature_verified: bool,

    /// Wire-format schema version the trace was emitted under.
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
    /// Trace this LLM call belongs to.
    pub trace_id: String,
    /// Thought-iteration this call happened inside.
    pub thought_id: String,
    /// Originating task, if any.
    pub task_id: Option<String>,

    /// FK to `trace_events.event_id` once the parent insert returns
    /// the row's PK. `None` until the parent is persisted.
    pub parent_event_id: Option<i64>,
    /// Event type of the parent reasoning event that triggered this
    /// LLM call.
    pub parent_event_type: ReasoningEventType,
    /// `attempt_index` of the parent event (used for FK uniqueness).
    pub parent_attempt_index: u32,

    /// Monotonic per `(thought_id, parent_event_id)`; for our purposes
    /// the same as `LlmCallSummary.attempt_index`.
    pub attempt_index: u32,

    /// Wall-clock when the LLM call started.
    pub ts: DateTime<Utc>,

    /// Round-trip duration in milliseconds.
    pub duration_ms: f64,
    /// Agent handler that issued the call (debug / aggregation).
    pub handler_name: String,
    /// Logical service name (e.g. "openai", "anthropic").
    pub service_name: String,

    /// Model identifier reported by the provider.
    pub model: Option<String>,
    /// Provider base URL, if non-default.
    pub base_url: Option<String>,
    /// Provider's response_model identifier when present.
    pub response_model: Option<String>,

    /// Prompt-side token count.
    pub prompt_tokens: Option<i32>,
    /// Completion-side token count.
    pub completion_tokens: Option<i32>,
    /// Prompt byte length (UTF-8).
    pub prompt_bytes: Option<i32>,
    /// Completion byte length (UTF-8).
    pub completion_bytes: Option<i32>,
    /// USD cost of the call as reported by the provider.
    pub cost_usd: Option<f64>,

    /// Outcome of the call (ok / timeout / rate_limited / etc.).
    pub status: LlmCallStatus,
    /// Provider-specific error class on failure.
    pub error_class: Option<String>,
    /// Total attempt count across retries.
    pub attempt_count: Option<i32>,
    /// Number of retries that fired.
    pub retry_count: Option<i32>,

    /// SHA-256 of the prompt content (de-dup / aggregation key).
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
    /// Monotonic per-agent audit sequence number.
    pub sequence_number: i64,
    /// Hash chain link — sha256 of the previous entry.
    pub previous_hash: String,
    /// sha256 of this entry's canonical payload.
    pub entry_hash: String,
    /// Ed25519 signature over `entry_hash`.
    pub signature: String,
    /// Signing-key id (looked up via `accord_public_keys`).
    pub signing_key_id: String,
    /// Wall-clock when the entry was minted.
    pub timestamp: DateTime<Utc>,
    /// Audit event type (string-keyed for forward compatibility).
    pub event_type: String,
    /// Operator-readable summary of the event.
    pub event_summary: String,
    /// Agent identifier emitting the entry.
    pub agent_id: String,
    /// JSONB payload — the audit event's full data dict.
    pub payload: serde_json::Value,
}

/// Phase 2 stub — service correlation shape (FSD §4.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceCorrelation {
    /// Correlation identifier (UUID-shaped).
    pub correlation_id: String,
    /// Service type the correlation belongs to.
    pub service_type: String,
    /// Correlation kind — RPC, queue handoff, etc.
    pub correlation_type: String,
    /// Wall-clock of the correlation.
    pub timestamp: DateTime<Utc>,
    /// Agent identifier.
    pub agent_id: String,
    /// JSONB payload with the correlation's full data dict.
    pub payload: serde_json::Value,
}

/// Phase 3 stub — task shape (FSD §5.1).
///
/// Mission constraint: multi-occurrence semantics preserved verbatim
/// (FSD §5.6) — `agent_occurrence_id` namespace and `try_claim_shared_task`
/// race-claim are first-class.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Task {
    /// Task identifier (stable across occurrences).
    pub task_id: String,
    /// Agent occurrence identifier; namespaces tasks per-agent.
    pub agent_occurrence_id: String,
    /// Channel the task was created on.
    pub channel_id: String,
    /// Operator-readable task description.
    pub description: String,
    /// Task status (pending / claimed / completed / failed / etc.).
    pub status: String,
    /// Numeric priority (lower = higher priority).
    pub priority: u8,
    /// When the task was created.
    pub created_at: DateTime<Utc>,
    /// When the task was last updated.
    pub updated_at: DateTime<Utc>,
    /// Task-type tag for routing / filtering.
    pub task_type: Option<String>,
    /// Identifier of the agent that signed this task (FSD §5.1
    /// signed-task primitive).
    pub signed_by: Option<String>,
    /// Ed25519 signature over the canonical task payload.
    pub signature: Option<String>,
    /// When the signature was issued.
    pub signed_at: Option<DateTime<Utc>>,
}

/// Phase 3 stub — graph node shape (FSD §5.1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    /// Node identifier.
    pub node_id: String,
    /// Node type tag.
    pub node_type: String,
    /// Scope namespace (per-agent, per-deployment, etc.).
    pub scope: String,
    /// Agent occurrence identifier.
    pub agent_occurrence_id: String,
    /// JSONB attributes blob.
    pub attributes_json: serde_json::Value,
    /// When the node was created.
    pub created_at: DateTime<Utc>,
    /// When the node was last updated.
    pub updated_at: DateTime<Utc>,
    /// Optimistic-concurrency version counter.
    pub version: i32,
}

/// Phase 3 stub — `try_claim_shared_task` parameter group
/// (FSD §5.6 — multi-occurrence atomicity primitive).
#[derive(Debug, Clone)]
pub struct ClaimParams<'a> {
    /// Task-type to claim.
    pub task_type: &'a str,
    /// Occurrence identifier requesting the claim.
    pub occurrence_id: &'a str,
    /// Channel scope of the claim.
    pub channel_id: &'a str,
    /// Description of the claimed task (used when creating).
    pub description: &'a str,
    /// Numeric priority of the claim.
    pub priority: u8,
    /// Wall-clock at the moment of claim.
    pub now: DateTime<Utc>,
}
