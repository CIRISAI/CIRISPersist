//! Maintenance-locks substrate (v1.5.15, CIRISPersist#59 #7).
//!
//! Seventh of 11 substrate absorptions ending CIRISAgent's direct
//! libsqlite access to `ciris_engine.db`. Absorbs the agent's
//! `consolidation_locks` table, generalized to a generic
//! `maintenance_locks` family per the spec.
//!
//! # The lock model
//!
//! Row-as-mutex. One row per `lock_key`:
//!   * `locked_by IS NULL` → not held.
//!   * `locked_by IS NOT NULL` AND `now < locked_at + timeout` →
//!     actively held.
//!   * `locked_by IS NOT NULL` AND `now >= locked_at + timeout` →
//!     expired, eligible to be stolen by the next acquire.
//!
//! TSDB-consolidation workers use this primitive today to ensure
//! only one worker runs the consolidation pass at a time. The
//! mechanism is not consolidation-specific: any worker mints a
//! `lock_key`, calls [`MaintenanceLockService::try_acquire_lock`],
//! and releases via [`MaintenanceLockService::release_lock`] when
//! done. A crashed holder's lock is reclaimed automatically once
//! `lock_timeout_seconds` elapses since `locked_at` (stale-lock
//! steal semantics).
//!
//! # Schema extension over the agent's table
//!
//! Agent's `consolidation_locks` is a 4-column SQLite table
//! (`lock_key`, `locked_by`, `locked_at`, `lock_timeout_seconds`).
//! Persist extends with 1 nullable column — `metadata` JSONB — for
//! lock-holder context (worker id, occurrence id, pid, etc.). The
//! new column is nullable so back-compat with the agent's
//! pre-extension 4-column shape is preserved.
//!
//! # Trait surface
//!
//! 3 methods on [`MaintenanceLockService`]:
//!
//! - **`try_acquire_lock`** — atomic UPSERT-with-WHERE. Returns
//!   `Some(lock)` on win (clean acquire or steal-the-stale);
//!   `None` when held by another active caller.
//! - **`release_lock`** — caller-matched release. Returns `true`
//!   on success; `false` when not held by caller (no-op).
//! - **`get_lock`** — observability read. Returns `None` when
//!   the row doesn't exist; `Some(lock)` otherwise (caller
//!   checks [`MaintenanceLock::is_expired`] for staleness).
//!
//! # Lock-expiry semantics across backends
//!
//! Both PG and SQLite stamp `locked_at` server-side (`NOW()` on PG,
//! `datetime('now', 'subsec')` on SQLite — both UTC). Both backends
//! evaluate "is this lock expired?" server-side in the same
//! statement that does the acquire, using the same server clock.
//! This guarantees that on a given wall-clock moment, both backends
//! return the same answer for the same input row.
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `maintenance_locks_invalid_argument`,
//!   `maintenance_locks_not_found`,
//!   `maintenance_locks_conflict`,
//!   `maintenance_locks_backend`,
//!   `maintenance_locks_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::MaintenanceLockService;
pub use types::{MaintenanceLock, DEFAULT_LOCK_TIMEOUT_SECONDS};

/// maintenance_locks-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — empty `lock_key` /
    /// `locked_by`, non-positive timeout, malformed metadata JSON.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found (currently unused by the trait surface — both
    /// `get_lock` and `release_lock` model the "row doesn't exist"
    /// case as `Option::None` / `bool` false respectively. Reserved
    /// for future variants).
    #[error("not found: {0}")]
    NotFound(String),

    /// Constraint conflict (e.g. CHECK on
    /// `lock_timeout_seconds > 0`) that the trait surface should not
    /// retry. Acquire-contention (another holder owns the lock and
    /// it's not expired) is NOT a `Conflict` — it's
    /// `Ok(None)` on `try_acquire_lock`, signalling "try again
    /// later" without an exception.
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
            Error::InvalidArgument(_) => "maintenance_locks_invalid_argument",
            Error::NotFound(_) => "maintenance_locks_not_found",
            Error::Conflict(_) => "maintenance_locks_conflict",
            Error::Backend(_) => "maintenance_locks_backend",
            Error::Internal(_) => "maintenance_locks_internal",
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
            "maintenance_locks_invalid_argument"
        );
        assert_eq!(
            Error::NotFound("x".into()).kind(),
            "maintenance_locks_not_found"
        );
        assert_eq!(
            Error::Conflict("x".into()).kind(),
            "maintenance_locks_conflict"
        );
        assert_eq!(
            Error::Backend("x".into()).kind(),
            "maintenance_locks_backend"
        );
        assert_eq!(
            Error::Internal("x".into()).kind(),
            "maintenance_locks_internal"
        );
    }
}
