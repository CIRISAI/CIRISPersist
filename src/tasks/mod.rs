//! Agent tasks substrate (v1.5.9, CIRISPersist#59 #1).
//!
//! First of 11 substrate absorptions ending CIRISAgent's direct
//! libsqlite access to `ciris_engine.db`. Absorbs the agent's
//! `tasks` table:
//!
//! - **`upsert_task`** — task_id-keyed idempotent upsert. Re-insert
//!   with same payload is a no-op; re-insert with differing payload
//!   overwrites the mutable columns (description, context, outcome,
//!   …) while preserving `created_at` and `retry_count` history.
//!
//! - **`update_task_status`** — focused status-only update plus
//!   optional `outcome_json` merge. Returns false when the task
//!   doesn't exist (no error — agent treats this as "stale id, drop").
//!
//! - **`try_claim_shared_task`** — atomic `INSERT-OR-IGNORE` keyed on
//!   `task_id`. First caller wins with `ClaimResult::Stored`; losers
//!   get `AlreadyClaimed` referencing the existing row. Race-safe on
//!   the PK. Used for multi-occurrence coordination where N callers
//!   try to "own" a shared task without writing N rows.
//!
//! - **`list_tasks`** — cursor-paged tenant-style listing with filter
//!   on (occurrence, status, channel, parent, time-window). Hits the
//!   `tasks_status_occurrence` index in the happy path.
//!
//! - **`delete_task`** — by-id delete; FK-cascade semantics are FK-
//!   default (PG: REJECT if children exist via the DEFERRABLE
//!   self-FK; SQLite: REJECT via the standard self-FK). Returns
//!   `true` if a row was deleted.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `tasks_invalid_argument`, `tasks_not_found`, `tasks_conflict`,
//!   `tasks_backend`, `tasks_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::TaskService;
pub use types::{Task, TaskCursor, TaskFilter, TaskListPage, TaskStatus};

/// tasks-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty task_id,
    /// unknown status string, malformed JSON, out-of-range limit, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found (e.g. delete on missing parent reference).
    #[error("not found: {0}")]
    NotFound(String),

    /// Uniqueness or FK conflict that the trait surface should not
    /// retry (e.g. parent_task_id reference to a nonexistent row).
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
            Error::InvalidArgument(_) => "tasks_invalid_argument",
            Error::NotFound(_) => "tasks_not_found",
            Error::Conflict(_) => "tasks_conflict",
            Error::Backend(_) => "tasks_backend",
            Error::Internal(_) => "tasks_internal",
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
            "tasks_invalid_argument"
        );
        assert_eq!(Error::NotFound("x".into()).kind(), "tasks_not_found");
        assert_eq!(Error::Conflict("x".into()).kind(), "tasks_conflict");
        assert_eq!(Error::Backend("x".into()).kind(), "tasks_backend");
        assert_eq!(Error::Internal("x".into()).kind(), "tasks_internal");
    }
}
