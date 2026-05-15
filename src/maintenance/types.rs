//! v1.2.0 (CIRISPersist#48) — typed shapes for the
//! [`MaintenanceService`](super::MaintenanceService) trait surface.
//!
//! Reports are plain serde structs so they cross the PyO3 FFI as
//! JSON strings (mirrors the v0.6.1 secrets / v0.8.x telemetry
//! pattern) and so the agent-side
//! `DatabaseMaintenanceService.maintain()` shim can decode them
//! field-for-field.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// v1.2.0 (CIRISPersist#48) — typed window for
/// [`MaintenanceService::archive_expired`](super::MaintenanceService::archive_expired).
///
/// Substrate-defined defaults per module (telemetry raw observations
/// use the existing `expires_at` column from V015; the other modules
/// fall back to fixed retention defaults — see
/// [`postgres`](super::postgres) / [`sqlite`](super::sqlite) impl
/// doc-comments for the per-module cutoff). Callers can override the
/// fixed-default policy with an explicit
/// [`ArchiveWindow::Custom`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ArchiveWindow {
    /// Use the substrate-recommended cutoff per module.
    SubstrateDefault,
    /// Explicit cutoff — rows with `created_at < (now - window)`
    /// (or the equivalent per-module timestamp column) are archived.
    Custom {
        /// Window length in whole seconds. Callers asking for "30
        /// days" pass `30 * 86_400`.
        seconds: u64,
    },
}

/// v1.2.0 (CIRISPersist#48) — result of
/// [`MaintenanceService::vacuum_substrate`](super::MaintenanceService::vacuum_substrate).
///
/// `dialect` is `String` rather than `&'static str` so the report
/// is `Deserialize` on the PyO3 / lens-side decode path. Backend
/// impls populate it with the literal `"postgres"` or `"sqlite"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VacuumReport {
    /// `"postgres"` or `"sqlite"` — which backend ran the VACUUM.
    pub dialect: String,
    /// Wall-clock elapsed time of the vacuum statement, in
    /// milliseconds.
    pub elapsed_ms: u32,
}

/// v1.2.0 (CIRISPersist#48) — result of
/// [`MaintenanceService::archive_expired`](super::MaintenanceService::archive_expired).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveReport {
    /// Rows removed per substrate module. Keys are stable module
    /// names: `"telemetry"`, `"secrets_access_log"`,
    /// `"incidents"`, `"federation_keys_expired"`.
    pub per_module: HashMap<String, usize>,
    /// Sum of [`per_module`](Self::per_module) values.
    pub total_removed: usize,
}

/// v1.2.0 (CIRISPersist#48) — result of
/// [`MaintenanceService::prune_audit_chain`](super::MaintenanceService::prune_audit_chain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PruneReport {
    /// Audit-chain entries removed across the prune call.
    pub entries_removed: usize,
    /// New genesis anchor ID for the post-prune chain. `None`
    /// when no entries were removed (chain is unchanged).
    pub new_anchor_id: Option<String>,
}

/// v1.2.0 (CIRISPersist#48) — umbrella result of
/// [`MaintenanceService::maintain`](super::MaintenanceService::maintain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaintenanceReport {
    /// Sub-report from the VACUUM phase.
    pub vacuum: VacuumReport,
    /// Sub-report from the archive_expired phase (substrate-default
    /// cutoffs).
    pub archive: ArchiveReport,
    /// Wall-clock start of the umbrella run.
    pub started_at: DateTime<Utc>,
    /// Wall-clock elapsed time of the umbrella run, in
    /// milliseconds. Sum of the VACUUM + archive phases plus the
    /// per-call orchestration overhead.
    pub elapsed_ms: u32,
}
