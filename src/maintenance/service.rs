//! [`MaintenanceService`] trait surface (v1.2.0, CIRISPersist#48).
//!
//! Operation-side of the agent's `DatabaseMaintenanceService`.
//! Scheduling stays on the agent side (the agent's
//! `TaskSchedulerService` decides *when* to run); this trait is the
//! operation-side that decides *what* runs.

use std::future::Future;

use chrono::{DateTime, Utc};

use super::types::{ArchiveReport, ArchiveWindow, MaintenanceReport, PruneReport, VacuumReport};
use super::Error;

/// v1.2.0 (CIRISPersist#48) — operation surface for substrate
/// maintenance. Implementations exist per backend
/// ([`postgres`](super::postgres) / [`sqlite`](super::sqlite)) and
/// orchestrate VACUUM, expired-row archival, and audit-chain prune
/// without taking on scheduling concerns.
///
/// Trait uses RPITIT (`impl Future<Output = …> + Send`) so it is
/// **NOT object-safe** — `Arc<dyn MaintenanceService>` won't
/// compile. Consumers `match` on
/// [`BackendDispatch`](crate::engine::BackendDispatch) and call the
/// concrete backend Arc.
pub trait MaintenanceService: Send + Sync {
    /// Run a substrate-wide VACUUM (Postgres: `VACUUM ANALYZE` via a
    /// dedicated non-transactional client; SQLite: `VACUUM; ANALYZE;`
    /// via `tokio::task::spawn_blocking`).
    ///
    /// Returns a [`VacuumReport`] carrying the dialect identifier
    /// and elapsed time.
    fn vacuum_substrate(&self) -> impl Future<Output = Result<VacuumReport, Error>> + Send;

    /// Walk each substrate module that owns a retention column and
    /// DELETE rows past their cutoff. Returns per-module removal
    /// counts.
    ///
    /// See [`ArchiveWindow`] for the substrate-default vs custom
    /// cutoff semantics. The per-module table coverage is defined
    /// in the backend impls.
    fn archive_expired(
        &self,
        window: ArchiveWindow,
    ) -> impl Future<Output = Result<ArchiveReport, Error>> + Send;

    /// Prune audit-chain entries strictly older than `before` for
    /// the named `tenant`. Returns a [`PruneReport`] with the new
    /// genesis anchor (chain stays verifiable after prune).
    ///
    /// **v1.2.0 stub.** The full prune-with-anchor semantics depend
    /// on CIRISAgent#760 Counter-RII review-window answers (how long
    /// must the chain remain re-derivable for steward review?). The
    /// stub returns
    /// `PruneReport { entries_removed: 0, new_anchor_id: None }`.
    /// A real implementation lands once that review-window guidance
    /// is in hand.
    fn prune_audit_chain(
        &self,
        tenant: &str,
        before: DateTime<Utc>,
    ) -> impl Future<Output = Result<PruneReport, Error>> + Send;

    /// Umbrella orchestration:
    ///   1. [`vacuum_substrate`](Self::vacuum_substrate)
    ///   2. [`archive_expired`](Self::archive_expired)
    ///      with [`ArchiveWindow::SubstrateDefault`]
    ///   3. (No prune by default — callers run
    ///      [`prune_audit_chain`](Self::prune_audit_chain) on a
    ///      tenant-scoped schedule).
    ///
    /// Failures in any phase short-circuit the umbrella; partial
    /// state is preserved (each step commits independently before
    /// the next runs).
    fn maintain(&self) -> impl Future<Output = Result<MaintenanceReport, Error>> + Send;
}
