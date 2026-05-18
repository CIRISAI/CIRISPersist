//! Scheduled tasks substrate (v1.5.12, CIRISPersist#59 #4).
//!
//! Fourth of 11 substrate absorptions ending CIRISAgent's direct
//! libsqlite access to `ciris_engine.db`. Absorbs the agent's
//! `scheduled_tasks` table — the scheduler's record of deferred or
//! cron-driven follow-up work spawned from a thought.
//!
//! The trait exposes 3 methods:
//!
//! - **`upsert_scheduled_task`** — `id`-keyed UPSERT. Every column
//!   except `created_at` is overwritten on conflict; `created_at`
//!   stays at its original value so re-upsert doesn't clobber the
//!   row's creation time.
//!
//! - **`list_due_scheduled_tasks`** — hot-path scheduler tick query.
//!   Returns rows where `next_trigger_at <= now`, status is
//!   `PENDING` or `ACTIVE`, scoped to an occurrence. Hits the
//!   `scheduled_tasks_due` partial index. Ordered ASC by
//!   `next_trigger_at` for fair scheduling.
//!
//! - **`update_after_trigger`** — post-fire bookkeeping. Updates
//!   `last_triggered_at`, optionally `next_trigger_at`,
//!   `deferral_count`, `deferral_history`, and optionally advances
//!   `status`. Returns `false` when the row doesn't exist.
//!
//! # Status vocabulary
//!
//! Note: `scheduled_tasks.status` is UPPERCASE (`PENDING | ACTIVE |
//! COMPLETE | FAILED`) — different from `tasks` / `thoughts` which
//! use lowercase vocabularies. The agent's table declaration is
//! authoritative; persist follows it verbatim. The Rust enum variant
//! names stay TitleCase (`Pending` / `Active` / `Complete` /
//! `Failed`) and `as_sql_str` emits uppercase.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `scheduled_tasks_invalid_argument`,
//!   `scheduled_tasks_not_found`, `scheduled_tasks_conflict`,
//!   `scheduled_tasks_backend`, `scheduled_tasks_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::ScheduledTaskService;
pub use types::{ScheduledTask, ScheduledTaskStatus};

/// scheduled-tasks-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty id, unknown status
    /// string, malformed JSON, out-of-range limit, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// FK violation against `cirislens.thoughts`, uniqueness
    /// collision, or other constraint conflict the trait surface
    /// should not retry.
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
            Error::InvalidArgument(_) => "scheduled_tasks_invalid_argument",
            Error::NotFound(_) => "scheduled_tasks_not_found",
            Error::Conflict(_) => "scheduled_tasks_conflict",
            Error::Backend(_) => "scheduled_tasks_backend",
            Error::Internal(_) => "scheduled_tasks_internal",
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
            "scheduled_tasks_invalid_argument"
        );
        assert_eq!(
            Error::NotFound("x".into()).kind(),
            "scheduled_tasks_not_found"
        );
        assert_eq!(
            Error::Conflict("x".into()).kind(),
            "scheduled_tasks_conflict"
        );
        assert_eq!(
            Error::Backend(("x").into()).kind(),
            "scheduled_tasks_backend"
        );
        assert_eq!(
            Error::Internal("x".into()).kind(),
            "scheduled_tasks_internal"
        );
    }
}
