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
pub mod wire_datetime;

pub use envelope::{BatchEnvelope, BatchEvent, CorrelationMetadata, TraceLevel};
pub use events::{
    AuditAnchor, ComponentType, CostSummary, LlmCallStatus, LlmCallSummary, ReasoningEventType,
};
pub use trace::{CompleteTrace, DeploymentProfile, TraceComponent};
pub use version::{SchemaVersion, SUPPORTED_VERSIONS};
pub use wire_datetime::WireDateTime;

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
        /// Version string the agent shipped.
        got: String,
        /// Allow-list of supported wire-format versions.
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
        /// Name of the field that failed type-check.
        field: &'static str,
        /// Expected JSON shape (e.g. "non-negative integer").
        expected: &'static str,
        /// Actual JSON shape observed in the payload.
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

    /// THREAT_MODEL.md AV-17 (v0.1.3): `attempt_index` exceeds
    /// [`MAX_ATTEMPT_INDEX`]. Pre-fix, `as u32` / `as i32` casts
    /// silently truncated values above the boundary, allowing an
    /// adversary to submit `2^32` and have it land at 0,
    /// colliding with a legitimate retry-0 row on the dedup tuple.
    #[error("attempt_index out of range: got {got}, max {max}")]
    AttemptIndexOutOfRange {
        /// The (out-of-range) value the agent shipped.
        got: i64,
        /// Configured maximum (`MAX_ATTEMPT_INDEX`).
        max: u32,
    },
}

/// Maximum legitimate `attempt_index` value.
///
/// THREAT_MODEL.md AV-17: real retry counts in the production
/// agent (`recursive_processing.py`) are bounded by 5; 1024 is
/// generous safety headroom while still catching adversarial
/// out-of-range submissions before they hit `as u32` truncation.
/// `overflow-checks = true` on the release profile is the
/// belt-and-suspenders backstop.
pub const MAX_ATTEMPT_INDEX: u32 = 1024;

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
            Error::AttemptIndexOutOfRange { .. } => "schema_attempt_index_out_of_range",
        }
    }

    /// v0.4.6 (CIRISPersist#22) — Variant-specific detail string.
    ///
    /// `kind()` returns the stable enum-discriminant token (e.g.
    /// `"schema_missing_field"`); `detail()` returns the variant's
    /// dynamic content (e.g. `"attempt_index"` for the missing-field
    /// case) so callers can surface "WHICH field" to operators
    /// without sourcediving the persist crate.
    ///
    /// THREAT_MODEL.md AV-15-safe by construction: every value
    /// returned here is either a `&'static str` from a closed enum
    /// of accessor names, a typed integer (`i64`, `u32`, `usize`),
    /// or an operator-supplied configuration string already
    /// surfaced through other paths (`UnsupportedSchemaVersion.got`
    /// is the version stamp the agent put on the wire; if it's
    /// adversarial that's already the lens's problem at the parse
    /// layer). No raw user-payload strings cross this boundary.
    ///
    /// Returns `None` for `Json` because `serde_json::Error`'s
    /// `Display` form may include parser-position text that echoes
    /// untrusted bytes; callers wanting that level of detail use
    /// the `tracing` log path.
    pub fn detail(&self) -> Option<String> {
        match self {
            // v1.1.0 (CIRISPersist#44 + CIRISLens#13): surface
            // serde_json's structural Display message — field name from
            // the Rust struct, line/column position, expected type.
            // AV-15: operator-actionable, not attacker-content-bearing
            // (the strings come from the Rust struct definitions and
            // structural offsets, not raw payload). Bridge investigators
            // get "missing field `component_type` at line 1 column 247"
            // instead of None.
            Error::Json(e) => Some(e.to_string()),
            Error::UnsupportedSchemaVersion { got, .. } => Some(got.clone()),
            Error::UnknownTraceLevel(s) => Some(s.clone()),
            Error::MissingField(name) => Some((*name).to_string()),
            Error::FieldTypeMismatch {
                field,
                expected,
                got,
            } => Some(format!("{field}:expected={expected},got={got}")),
            Error::NegativeAttemptIndex(n) => Some(n.to_string()),
            Error::DataTooDeep(d) => Some(d.to_string()),
            Error::AttemptIndexOutOfRange { got, max } => Some(format!("got={got},max={max}")),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// v1.1.0 (CIRISPersist#44): Error::Json(_)::detail() returns the
    /// serde_json Display message, not None. Operator-actionable.
    #[test]
    fn json_error_detail_surfaces_serde_json_message() {
        let raw = br#"{"trace_schema_version":"2.7.9"}"#;
        let err: serde_json::Error = serde_json::from_slice::<i32>(raw).unwrap_err();
        let kind_token = Error::Json(err).kind();
        assert_eq!(kind_token, "schema_malformed_json");

        let err2: serde_json::Error = serde_json::from_slice::<i32>(raw).unwrap_err();
        let detail = Error::Json(err2).detail();
        let s = detail.expect("v1.1.0 — Json::detail must be Some");
        assert!(
            !s.is_empty(),
            "v1.1.0 — Json::detail must carry the serde_json message"
        );
    }

    /// v1.1.0 (CIRISPersist#44): missing-field deserialize surfaces
    /// the field name in detail() via serde_json's Display impl.
    #[test]
    fn json_error_detail_carries_missing_field_name() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        struct Required {
            component_type: String,
            data: serde_json::Value,
        }

        let raw = br#"{"data":{"a":1}}"#;
        let err = serde_json::from_slice::<Required>(raw).unwrap_err();
        let detail = Error::Json(err).detail().expect("Json::detail is Some");
        assert!(
            detail.contains("component_type"),
            "Json::detail should name the missing field; got: {detail}"
        );
    }
}
