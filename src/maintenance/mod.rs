//! Maintenance service (v1.2.0, CIRISPersist#48).
//!
//! Absorbs the operations side of the agent's
//! `DatabaseMaintenanceService`. Scheduling stays at the agent's
//! `TaskSchedulerService`; this trait is the operation-side surface.
//!
//! # Module layout
//!
//! - [`types`] — typed report shapes ([`VacuumReport`],
//!   [`ArchiveReport`], [`PruneReport`], [`MaintenanceReport`]) and
//!   the [`ArchiveWindow`] knob.
//! - [`service`] — the [`MaintenanceService`] trait surface.
//! - [`postgres`] / [`sqlite`] — backend impls (feature-gated).
//! - [`vocabulary`] — v25.1.0 (CIRISPersist#582) the **vocabulary
//!   tightening** sweep: a one-time (and re-runnable) maintenance action
//!   that retires a non-conformant wire identifier from stored
//!   attestations by SUPERSEDING the rows that carry it. Same idiom as
//!   the rest of this module (typed report, per-phase counts,
//!   idempotent, every backend); unlike the others it needs a signer, so
//!   it is reached through [`crate::Engine::tighten_vocabulary`] rather
//!   than the raw-connection [`MaintenanceService`] trait.
//!
//! # Per-module retention defaults
//!
//! The substrate-default
//! [`MaintenanceService::archive_expired`](MaintenanceService::archive_expired)
//! call deletes:
//!
//! | Module                | Cutoff column                                    | Default window |
//! | --------------------- | ------------------------------------------------ | -------------- |
//! | telemetry             | `expires_at` (V015 existing column)              | row-defined    |
//! | secrets access_log    | `created_at`                                     | 30 days        |
//! | incidents (closed)    | `last_seen_at` (no `updated_at` exists)          | 90 days        |
//! | federation_keys       | `valid_until`                                    | 180 days       |
//!
//! Telemetry uses the per-row `expires_at` set by the producer (V015
//! `cirisgraph.telemetry_metrics.expires_at`); the other modules
//! use a fixed default window relative to `NOW()` (overridable via
//! [`ArchiveWindow::Custom`]).
//!
//! No new schema migrations are introduced — the impls query
//! existing columns.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;
pub mod vocabulary;

pub use service::MaintenanceService;
pub use types::{
    validate_sql_identifier, ArchiveReport, ArchiveWindow, MaintenanceReport, PruneReport,
    RetentionPolicy, RetentionPolicyRow, RetentionReport, VacuumReport,
};
pub use vocabulary::{
    run_vocabulary_tightening, TighteningAction, TighteningFamily, TighteningOutcome,
    TighteningSkip, VocabularyTightening, VocabularyTighteningReport,
};

/// Maintenance-layer errors. Surface kinds map onto the PyO3 typed
/// exception hierarchy via
/// [`crate::ffi::pyo3::translate_error_kind`].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Backend-level failure (pool exhaustion, statement error,
    /// rusqlite I/O failure, etc.). Caller MAY retry with backoff.
    #[error("backend: {0}")]
    Backend(String),

    /// Caller passed invalid arguments. Caller MUST NOT retry.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Substrate-internal bug (e.g., a serialization invariant the
    /// trait surface owns was violated). Caller MUST NOT retry.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    /// Maps onto the PyO3 typed exception hierarchy via
    /// [`crate::ffi::pyo3::translate_error_kind`].
    pub fn kind(&self) -> &'static str {
        match self {
            Error::Backend(_) => "maintenance_backend",
            Error::InvalidArgument(_) => "maintenance_invalid_argument",
            Error::Internal(_) => "maintenance_internal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_tokens_stable() {
        assert_eq!(Error::Backend("x".into()).kind(), "maintenance_backend");
        assert_eq!(
            Error::InvalidArgument("x".into()).kind(),
            "maintenance_invalid_argument"
        );
        assert_eq!(Error::Internal("x".into()).kind(), "maintenance_internal");
    }
}
