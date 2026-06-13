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

// ── Retention (CIRISPersist#209) ───────────────────────────────────

/// v5.9.0 (CIRISPersist#209) — a per-table retention policy for the
/// pressure-gated sweeper. `min_keep_secs` is the **sacred floor**: rows
/// younger than it are never deleted, regardless of pressure. The pair
/// `pressure_trigger_bytes` / `pressure_target_bytes` (both `Some` =
/// pressure-gated; both `None` = flat drop-after-`min_keep`) gate the
/// sweep on `pg_database_size` (SQLite: page_count × page_size): below
/// trigger is a total no-op (no churn); at/above, the sweeper deletes
/// rows older than `min_keep` aiming to get back under target. `interval_secs`
/// is advisory cadence for the caller's scheduler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Sacred floor — rows younger than this are never deleted.
    pub min_keep_secs: u64,
    /// The time column to order/cut on (the hypertable time column).
    /// Default `"ts"`. Validated as a strict SQL identifier.
    #[serde(default = "default_time_column")]
    pub time_column: String,
    /// High-water mark (bytes): sweep only when db size ≥ this. `None`
    /// (with `pressure_target_bytes` `None`) = flat schedule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_trigger_bytes: Option<u64>,
    /// Low-water mark (bytes): sweep aims to get db size below this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pressure_target_bytes: Option<u64>,
    /// Advisory sweeper cadence (seconds). The substrate doesn't schedule
    /// itself; the caller honours this.
    pub interval_secs: u64,
}

fn default_time_column() -> String {
    "ts".to_string()
}

/// A stored retention policy together with the table it governs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicyRow {
    /// The (validated-identifier) table the policy applies to.
    pub table_name: String,
    /// The policy.
    pub policy: RetentionPolicy,
}

/// v5.9.0 (CIRISPersist#209) — per-table outcome of one
/// [`run_retention`](super::MaintenanceService::run_retention) pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionReport {
    /// The table swept.
    pub table_name: String,
    /// Did a DELETE run this pass? `false` = no-op (pressure-gated and
    /// below the trigger).
    pub swept: bool,
    /// Rows deleted this pass.
    pub rows_deleted: usize,
    /// DB size (bytes) observed at the start of this table's pass.
    pub db_size_bytes: u64,
    /// Pressure-gated but still ≥ target after sweeping everything older
    /// than `min_keep` — the operator must lower `min_keep` or raise the
    /// cap (CEG §8.1.11.3-style observability; the "RetentionExhausted"
    /// condition). Note: a row-`DELETE` doesn't reclaim Postgres heap
    /// until VACUUM, so this is best-effort under the v1 DELETE strategy;
    /// precise until-target reclaim awaits the `drop_chunks`/partition
    /// path (deferred per #209).
    pub exhausted: bool,
}

/// Reject anything that isn't a strict `snake_case` SQL identifier
/// (optionally `schema.table`). **Security-critical**: `table_name` /
/// `time_column` are interpolated into `DELETE` SQL (identifiers can't be
/// bound), so this is the injection gate — no quotes, whitespace,
/// semicolons, or comment markers can pass.
pub fn validate_sql_identifier(ident: &str) -> Result<(), super::Error> {
    fn part_ok(p: &str) -> bool {
        let mut chars = p.chars();
        matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c == '_')
            && p.chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    }
    let parts: Vec<&str> = ident.split('.').collect();
    if (1..=2).contains(&parts.len()) && parts.iter().all(|p| part_ok(p)) {
        Ok(())
    } else {
        Err(super::Error::Backend(format!(
            "invalid SQL identifier {ident:?} (expected snake_case `table` or `schema.table`)"
        )))
    }
}
