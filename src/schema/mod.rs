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

    /// THREAT_MODEL.md AV-6: a component's `data` blob is nested
    /// past [`MAX_DATA_DEPTH`]. Deserialization-bomb defense; bounds
    /// allocation in case an attacker submits deeply-nested JSON
    /// inside the `data` field that the typed envelope would
    /// otherwise pass through unchecked.
    #[error("component data blob exceeds max depth ({0})")]
    DataTooDeep(usize),
}

impl Error {
    /// Stable string-token identifying the error variant.
    ///
    /// THREAT_MODEL.md AV-15: this is what crosses HTTP / PyO3
    /// boundaries. The verbose `Display` form (which can include
    /// attacker-supplied content) goes to tracing logs only.
    /// Callers map kinds to status codes / detail bodies.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Json(_) => "schema_malformed_json",
            Error::UnsupportedSchemaVersion { .. } => "schema_unsupported_version",
            Error::UnknownTraceLevel(_) => "schema_unknown_trace_level",
            Error::MissingField(_) => "schema_missing_field",
            Error::FieldTypeMismatch { .. } => "schema_field_type_mismatch",
            Error::NegativeAttemptIndex(_) => "schema_negative_attempt_index",
            Error::DataTooDeep(_) => "schema_data_too_deep",
        }
    }
}

/// Maximum nesting depth of any component's `data` blob.
///
/// 32 levels is generous for the production wire format
/// (`SNAPSHOT_AND_CONTEXT.system_snapshot` is the deepest legitimate
/// shape and tops out around 8 levels). An attacker submitting
/// `{"a":{"a":{"a":...}}}` 64-deep is rejected at parse time with
/// [`Error::DataTooDeep`].
pub const MAX_DATA_DEPTH: usize = 32;

/// Walk a `data` object's values and reject if depth exceeds
/// [`MAX_DATA_DEPTH`].
///
/// Called by [`envelope::BatchEnvelope::from_json`] over each
/// component's `data` field after typed parse succeeds. Bounded
/// recursion (the function itself uses Rust's stack and our own
/// depth counter; no allocation amplification — walks borrowed
/// data, no clones).
pub(crate) fn check_data_depth(
    data: &serde_json::Map<String, serde_json::Value>,
) -> Result<(), Error> {
    fn walk(v: &serde_json::Value, depth: usize) -> Result<(), Error> {
        if depth > MAX_DATA_DEPTH {
            return Err(Error::DataTooDeep(MAX_DATA_DEPTH));
        }
        match v {
            serde_json::Value::Array(items) => {
                for item in items {
                    walk(item, depth + 1)?;
                }
            }
            serde_json::Value::Object(map) => {
                for child in map.values() {
                    walk(child, depth + 1)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    // The outer `data` map itself counts as depth 1; children at
    // depth 2.
    for v in data.values() {
        walk(v, 1)?;
    }
    Ok(())
}
