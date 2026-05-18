//! Deferral-reports substrate (v1.5.14, CIRISPersist#59 #6).
//!
//! Sixth of 11 substrate absorptions ending CIRISAgent's direct
//! libsqlite access to `ciris_engine.db`. Absorbs the agent's
//! `deferral_reports` table — WA (Wise-Authority) deferrals
//! pointing back into the agent's (task, thought) reasoning chain.
//!
//! # Schema extension over the agent's table
//!
//! The agent's `deferral_reports` is a 5-column table
//! (`message_id`, `task_id`, `thought_id`, `package_json`,
//! `created_at`). Persist extends with 2 nullable columns —
//! `resolved_at` + `resolution_notes` — supporting the
//! `list_active_deferrals` (WA deferrals awaiting resolution)
//! hot path. Both columns are nullable so back-compat with the
//! agent's pre-extension shape is preserved.
//!
//! Until the agent picks up `resolve_deferral`, callers can carry
//! resolution metadata in `package`; the new columns are nullable
//! so agent-shape rows decode cleanly.
//!
//! Column `package_json` is renamed to `package` on both backends.
//! On PG, JSONB is the column type — idiomatic to drop the
//! `_json` suffix since the type indicates content. On SQLite the
//! rename keeps cross-backend parity. The wire format
//! (`serde_json::Value`) is unchanged on both backends.
//!
//! # Trait surface
//!
//! 4 methods on [`DeferralReportService`]:
//!
//! - **`record_deferral`** — `INSERT OR IGNORE` on `message_id`,
//!   returns [`crate::ClaimResult`] with the row this caller wrote
//!   (race winner) or the existing row (race loser). Idempotent.
//! - **`get_deferral`** — point lookup.
//! - **`list_active_deferrals`** — WA queue: filters on
//!   `resolved_at IS NULL`, newest-first by `created_at`. Optional
//!   `task_id` / `thought_id` / `created_after` / `created_before`
//!   narrowing.
//! - **`resolve_deferral`** — atomic state advance: sets
//!   `resolved_at` + `resolution_notes`. Returns `false` for
//!   missing row.
//!
//! # FK semantics
//!
//! Both `task_id` → `cirislens.tasks(task_id)` and
//! `thought_id` → `cirislens.thoughts(thought_id)` are NOT NULL
//! FKs. On PG both are `DEFERRABLE INITIALLY DEFERRED` so a
//! single tx can write `(task, thought, deferral_report)` in
//! order. On SQLite the FKs are immediate; agent callers ensure
//! parent rows exist before recording.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `deferral_reports_invalid_argument`,
//!   `deferral_reports_not_found`,
//!   `deferral_reports_conflict`, `deferral_reports_backend`,
//!   `deferral_reports_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::DeferralReportService;
pub use types::{DeferralFilter, DeferralReport};

/// deferral_reports-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty message_id /
    /// task_id / thought_id, out-of-range limit, malformed JSON.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found (currently unused by the trait surface —
    /// `get_deferral` returns `Option`, `resolve_deferral` returns
    /// `bool` — reserved for future variants).
    #[error("not found: {0}")]
    NotFound(String),

    /// FK violation (task_id / thought_id dangling) or other
    /// constraint conflict the trait surface should not retry.
    /// Idempotent `record_deferral` race is NOT a Conflict —
    /// that's `ClaimResult::AlreadyClaimed`.
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
            Error::InvalidArgument(_) => "deferral_reports_invalid_argument",
            Error::NotFound(_) => "deferral_reports_not_found",
            Error::Conflict(_) => "deferral_reports_conflict",
            Error::Backend(_) => "deferral_reports_backend",
            Error::Internal(_) => "deferral_reports_internal",
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
            "deferral_reports_invalid_argument"
        );
        assert_eq!(
            Error::NotFound("x".into()).kind(),
            "deferral_reports_not_found"
        );
        assert_eq!(
            Error::Conflict("x".into()).kind(),
            "deferral_reports_conflict"
        );
        assert_eq!(
            Error::Backend("x".into()).kind(),
            "deferral_reports_backend"
        );
        assert_eq!(
            Error::Internal("x".into()).kind(),
            "deferral_reports_internal"
        );
    }
}
