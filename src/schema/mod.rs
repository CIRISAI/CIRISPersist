//! Wire-format schema — concrete types for everything that crosses the
//! lens ingest boundary.
//!
//! # Mission alignment (MISSION.md §2 — `schema/`)
//!
//! Carry the wire-format contract verbatim. The trace's shape is the
//! agent's testimony; ambiguity in the parser is a way for a Sybil or
//! a buggy pipeline to claim something the agent didn't say.
//!
//! Constraint: zero `serde_json::Value` in **verify** hot paths. The
//! persistence path stores `data` as opaque JSONB (it's the agent's
//! testimony, kept verbatim); typed accessors extract the fields the
//! lens reasons over (`attempt_index`, audit anchor on `ACTION_RESULT`,
//! cost denormalization, `LLM_CALL` parent linkage). MDD's
//! anti-untyped rule applies to *crossing interface boundaries with
//! untyped state*; storing the agent's `data` blob unchanged is *not*
//! that — it is the contract. Reasoning over it without a typed
//! accessor would be.
//!
//! Source-of-truth: `context/TRACE_WIRE_FORMAT.md` (vendored copy of
//! the agent's `FSD/TRACE_WIRE_FORMAT.md`, pinned to agent 2.7.8 /
//! schema version `2.7.0`).

pub mod envelope;
pub mod events;
pub mod trace;
pub mod version;

pub use envelope::{BatchEnvelope, BatchEvent, CorrelationMetadata, TraceLevel};
pub use events::{
    AuditAnchor, ComponentType, CostSummary, LlmCallStatus, LlmCallSummary, ReasoningEventType,
};
pub use trace::{CompleteTrace, TraceComponent};
pub use version::{SchemaVersion, SUPPORTED_VERSIONS};

/// Schema-layer errors.
///
/// Mission (MISSION.md §3 anti-pattern #4): every failure mode is a
/// defined variant. No string-typed `.parse::<_>().unwrap()` in
/// production paths.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// JSON parse failure.
    #[error("malformed JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// `trace_schema_version` outside the supported set
    /// (FSD §3.4 robustness primitive #3 — schema-version gate).
    #[error("unsupported trace_schema_version: {got:?}; supported = {supported:?}")]
    UnsupportedSchemaVersion {
        got: String,
        supported: &'static [&'static str],
    },

    /// `trace_level` not one of `generic` / `detailed` / `full_traces`.
    #[error("unknown trace_level: {0:?}")]
    UnknownTraceLevel(String),

    /// Required field missing per the wire-format spec.
    #[error("missing required field: {0}")]
    MissingField(&'static str),

    /// A typed accessor on a component's `data` blob found a field
    /// of the wrong JSON shape.
    #[error("field {field} has wrong type in component data: expected {expected}, got {got}")]
    FieldTypeMismatch {
        field: &'static str,
        expected: &'static str,
        got: &'static str,
    },

    /// `attempt_index` (FSD §3.3 step 4 / TRACE_WIRE_FORMAT.md §6) is
    /// non-negative; a negative value would corrupt the
    /// `(trace_id, thought_id, event_type, attempt_index)` dedup key.
    #[error("attempt_index must be non-negative, got {0}")]
    NegativeAttemptIndex(i64),
}
