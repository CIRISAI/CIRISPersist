//! Service correlations substrate (v1.5.11, CIRISPersist#59 #3).
//!
//! Third of 11 substrate absorptions ending CIRISAgent's direct
//! libsqlite access to `ciris_engine.db`. Absorbs the agent's
//! `service_correlations` table — a dual-purpose store backing FOUR
//! sub-shapes discriminated by the `correlation_type` column:
//!
//! - `service_interaction` — RPC-level request/response correlation
//!   tracking for the agent's outbound service calls
//! - `metric` — TSDB-style numeric metric points
//!   (metric_name + metric_value + timestamp)
//! - `trace` — OTLP-style distributed-trace spans
//!   (trace_id + span_id + parent_span_id)
//! - `log` — structured log records (log_level + tags)
//!
//! The trait exposes 4 methods:
//!
//! - **`record_correlation`** — `correlation_id`-keyed INSERT with
//!   `ON CONFLICT DO NOTHING`. First writer wins; subsequent writers
//!   are silent no-ops (idempotent re-record on retry). The caller
//!   advances state via `update_correlation_status` — that is the
//!   only path for mutating an in-flight correlation.
//!
//! - **`get_correlation`** — point lookup by id.
//!
//! - **`update_correlation_status`** — focused status update + optional
//!   `response_data` merge (COALESCE — pass `Some(Value::Null)` to
//!   overwrite with NULL). Refreshes `updated_at` to NOW. Returns
//!   `false` when the correlation doesn't exist (no error — agent
//!   treats as "stale id, drop").
//!
//! - **`query_correlations`** — cursor-paged read. Filter by any of:
//!   `service_type`, `correlation_type`, `trace_id` (distributed-
//!   trace assembly), `metric_name` (TSDB-style metric queries),
//!   event-time window (`timestamp_after` / `timestamp_before`),
//!   row-update window (`updated_after` / `updated_before`),
//!   `retention_policy`, `agent_occurrence_id`. Cursor pagination on
//!   `(updated_at, correlation_id)`.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `correlations_invalid_argument`, `correlations_not_found`,
//!   `correlations_conflict`, `correlations_backend`,
//!   `correlations_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::CorrelationService;
pub use types::{
    Correlation, CorrelationCursor, CorrelationFilter, CorrelationListPage, CorrelationStatus,
    CorrelationType, RetentionPolicy,
};

/// correlations-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty correlation_id,
    /// unknown status / correlation_type / retention_policy string,
    /// malformed JSON, out-of-range limit, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Uniqueness conflict that the trait surface should not retry.
    /// (`record_correlation`'s ON CONFLICT DO NOTHING means a re-
    /// record is NOT a Conflict — it's a silent no-op. This variant
    /// covers genuine collisions only.)
    #[error("conflict: {0}")]
    Conflict(String),

    /// Backend-level error (connection, transaction, lock).
    #[error("backend: {0}")]
    Backend(String),

    /// Internal serialization / type-conversion bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "correlations_invalid_argument",
            Error::NotFound(_) => "correlations_not_found",
            Error::Conflict(_) => "correlations_conflict",
            Error::Backend(_) => "correlations_backend",
            Error::Internal(_) => "correlations_internal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_tokens_stable() {
        assert_eq!(
            Error::InvalidArgument("x".into()).kind(),
            "correlations_invalid_argument"
        );
        assert_eq!(Error::NotFound("x".into()).kind(), "correlations_not_found");
        assert_eq!(Error::Conflict("x".into()).kind(), "correlations_conflict");
        assert_eq!(Error::Backend("x".into()).kind(), "correlations_backend");
        assert_eq!(Error::Internal("x".into()).kind(), "correlations_internal");
    }
}
