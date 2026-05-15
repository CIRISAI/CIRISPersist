//! SQLite impl of [`MaintenanceService`] (v1.2.0, CIRISPersist#48).
//!
//! Mirrors the Postgres impl with SQLite-dialect translations:
//!
//! - `NOW()` → `datetime('now')` / `datetime('now', '-<n> seconds')`
//! - `INTERVAL '30 days'` → `datetime('now', '-30 days')` (precomputed
//!   as `datetime('now', '-<n> seconds')` via the integer-seconds
//!   knob from [`ArchiveWindow::Custom`])
//! - Schema-prefix tables use the flat-prefix SQLite convention
//!   (`cirisgraph_telemetry_metrics`, `cirislens_secrets_access_log`,
//!   `cirislens_incident_records`, `federation_keys`).
//!
//! VACUUM in SQLite rebuilds the DB file and can take a while on
//! large databases. The impl runs `VACUUM; ANALYZE;` via
//! `tokio::task::spawn_blocking` to keep the runtime responsive
//! (the rusqlite `Connection` is `!Send` so we can't `.await`
//! across it without the spawn_blocking).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use tokio::sync::Mutex;

use super::service::MaintenanceService;
use super::types::{ArchiveReport, ArchiveWindow, MaintenanceReport, PruneReport, VacuumReport};
use super::Error;

/// v1.2.0 (CIRISPersist#48) — SQLite-backed
/// [`MaintenanceService`](super::MaintenanceService) impl.
pub struct SqliteMaintenanceBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteMaintenanceBackend {
    /// Construct from a shared connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    Error::Backend(format!("{op}: {e}"))
}

fn fixed_seconds(window: ArchiveWindow, default_days: i64) -> i64 {
    match window {
        ArchiveWindow::SubstrateDefault => default_days * 86_400,
        ArchiveWindow::Custom { seconds } => seconds as i64,
    }
}

impl MaintenanceService for SqliteMaintenanceBackend {
    async fn vacuum_substrate(&self) -> Result<VacuumReport, Error> {
        let conn = self.conn.clone();
        let started = Instant::now();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let guard = conn.blocking_lock();
            // VACUUM rebuilds the file; ANALYZE refreshes the stat1
            // tables. Run as a single batch so SQLite sees them
            // back-to-back without dropping the file lock.
            guard
                .execute_batch("VACUUM; ANALYZE;")
                .map_err(|e| map_sqlite_error(e, "VACUUM"))
        })
        .await
        .map_err(|e| Error::Backend(format!("vacuum spawn_blocking join: {e}")))??;
        let elapsed_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
        Ok(VacuumReport {
            dialect: "sqlite".to_owned(),
            elapsed_ms,
        })
    }

    async fn archive_expired(&self, window: ArchiveWindow) -> Result<ArchiveReport, Error> {
        let secrets_secs = fixed_seconds(window, 30);
        let incidents_secs = fixed_seconds(window, 90);
        let federation_secs = fixed_seconds(window, 180);
        // Telemetry: SubstrateDefault uses the producer-set
        // `expires_at`; Custom mode applies a wholesale
        // `observed_at < now - secs` cutoff.
        let telemetry_custom_secs = match window {
            ArchiveWindow::SubstrateDefault => None,
            ArchiveWindow::Custom { seconds } => Some(seconds as i64),
        };

        let conn = self.conn.clone();
        let report = tokio::task::spawn_blocking(move || -> Result<ArchiveReport, Error> {
            let guard = conn.blocking_lock();
            let mut per_module: HashMap<String, usize> = HashMap::new();
            let mut total: usize = 0;

            // Note on datetime comparisons: rows in these tables
            // are stored in a mix of RFC3339 (`T` separator,
            // micros suffix) and SQLite-default
            // (`YYYY-MM-DD HH:MM:SS` space separator) formats.
            // Direct `<` string compare is unsafe across the two
            // shapes (space < `T` lexicographically). We use
            // `julianday()` which parses both and gives a single
            // numeric scalar that's safe to compare against
            // `julianday('now')` regardless of input format.

            // ── telemetry ─────────────────────────────────────────
            let telemetry_n = match telemetry_custom_secs {
                None => guard
                    .execute(
                        "DELETE FROM cirisgraph_telemetry_metrics \
                         WHERE julianday(expires_at) < julianday('now')",
                        [],
                    )
                    .map_err(|e| map_sqlite_error(e, "DELETE telemetry"))?,
                Some(secs) => {
                    let cutoff = format!("-{secs} seconds");
                    guard
                        .execute(
                            "DELETE FROM cirisgraph_telemetry_metrics \
                             WHERE julianday(observed_at) < julianday('now', ?1)",
                            [cutoff],
                        )
                        .map_err(|e| map_sqlite_error(e, "DELETE telemetry (custom)"))?
                }
            };
            per_module.insert("telemetry".to_owned(), telemetry_n);
            total += telemetry_n;

            // ── secrets access_log ────────────────────────────────
            let secrets_cutoff = format!("-{secrets_secs} seconds");
            let secrets_n = guard
                .execute(
                    "DELETE FROM cirislens_secrets_access_log \
                     WHERE julianday(created_at) < julianday('now', ?1)",
                    [secrets_cutoff],
                )
                .map_err(|e| map_sqlite_error(e, "DELETE secrets access_log"))?;
            per_module.insert("secrets_access_log".to_owned(), secrets_n);
            total += secrets_n;

            // ── incidents (closed) ────────────────────────────────
            let incidents_cutoff = format!("-{incidents_secs} seconds");
            let incidents_n = guard
                .execute(
                    "DELETE FROM cirislens_incident_records \
                     WHERE state = 'closed' \
                       AND julianday(last_seen_at) < julianday('now', ?1)",
                    [incidents_cutoff],
                )
                .map_err(|e| map_sqlite_error(e, "DELETE incidents"))?;
            per_module.insert("incidents".to_owned(), incidents_n);
            total += incidents_n;

            // ── federation_keys (expired by valid_until) ──────────
            let federation_cutoff = format!("-{federation_secs} seconds");
            let federation_n = guard
                .execute(
                    "DELETE FROM federation_keys \
                     WHERE valid_until IS NOT NULL \
                       AND julianday(valid_until) < julianday('now', ?1)",
                    [federation_cutoff],
                )
                .map_err(|e| map_sqlite_error(e, "DELETE federation_keys"))?;
            per_module.insert("federation_keys_expired".to_owned(), federation_n);
            total += federation_n;

            Ok(ArchiveReport {
                per_module,
                total_removed: total,
            })
        })
        .await
        .map_err(|e| Error::Backend(format!("archive spawn_blocking join: {e}")))??;
        Ok(report)
    }

    async fn prune_audit_chain(
        &self,
        _tenant: &str,
        _before: DateTime<Utc>,
    ) -> Result<PruneReport, Error> {
        // v1.2.0 stub — mirrors the PG impl. Counter-RII
        // review-window dependency (CIRISAgent#760) blocks the real
        // semantics.
        Ok(PruneReport {
            entries_removed: 0,
            new_anchor_id: None,
        })
    }

    async fn maintain(&self) -> Result<MaintenanceReport, Error> {
        let started_at = Utc::now();
        let started = Instant::now();
        let vacuum = self.vacuum_substrate().await?;
        let archive = self
            .archive_expired(ArchiveWindow::SubstrateDefault)
            .await?;
        let elapsed_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
        Ok(MaintenanceReport {
            vacuum,
            archive,
            started_at,
            elapsed_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use chrono::Duration;
    use rusqlite::params;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteMaintenanceBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteMaintenanceBackend::new(backend.conn_handle());
        (backend, svc)
    }

    fn fmt(dt: DateTime<Utc>) -> String {
        dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
    }

    /// v1.2.0 (CIRISPersist#48) Test 1 — VACUUM succeeds on a
    /// freshly-migrated in-memory DB.
    #[tokio::test]
    async fn maintenance_vacuum_runs_clean() {
        let (_b, svc) = fresh_backend().await;
        let report = svc.vacuum_substrate().await.expect("vacuum");
        assert_eq!(report.dialect, "sqlite");
        // VACUUM on a fresh empty DB is essentially instant on
        // modern hardware; assert it ran (non-panic) rather than a
        // strict time floor. CI runners can clock 0ms.
        let _ = report.elapsed_ms;
    }

    /// v1.2.0 (CIRISPersist#48) Test 2 — archive_expired removes
    /// telemetry rows whose `expires_at` is in the past.
    #[tokio::test]
    async fn maintenance_archive_expired_telemetry() {
        let (backend, svc) = fresh_backend().await;
        let conn = backend.conn_handle();

        let observed = Utc::now() - Duration::hours(2);
        let expires = Utc::now() - Duration::hours(1);
        {
            let guard = conn.lock().await;
            guard
                .execute(
                    "INSERT INTO cirisgraph_telemetry_metrics (\
                        metric_id, metric_name, tenant_id, value, labels, \
                        observed_at, expires_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        Uuid::new_v4().to_string(),
                        "test.metric",
                        "tnt-mnt",
                        1.0f64,
                        "{}",
                        fmt(observed),
                        fmt(expires),
                    ],
                )
                .unwrap();
        }

        let report = svc
            .archive_expired(ArchiveWindow::SubstrateDefault)
            .await
            .expect("archive_expired");
        assert_eq!(report.per_module.get("telemetry").copied(), Some(1));
        assert!(report.total_removed >= 1);

        let guard = conn.lock().await;
        let remaining: i64 = guard
            .query_row(
                "SELECT COUNT(*) FROM cirisgraph_telemetry_metrics \
                 WHERE tenant_id = ?1",
                ["tnt-mnt"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
    }

    /// v1.2.0 (CIRISPersist#48) Test 3 — archive_expired removes
    /// secrets access_log rows past the 30-day default.
    #[tokio::test]
    async fn maintenance_archive_expired_secrets_access_log() {
        let (backend, svc) = fresh_backend().await;
        let conn = backend.conn_handle();

        let stale = Utc::now() - Duration::days(60);
        {
            let guard = conn.lock().await;
            guard
                .execute(
                    "INSERT INTO cirislens_secrets_access_log (\
                        secret_uuid, accessor, operation, action_type, \
                        purpose, success, error, trace_id, thought_id, created_at\
                     ) VALUES (NULL, ?1, 'store', NULL, NULL, 1, NULL, NULL, NULL, ?2)",
                    params!["test-accessor", fmt(stale)],
                )
                .unwrap();
        }

        let report = svc
            .archive_expired(ArchiveWindow::SubstrateDefault)
            .await
            .expect("archive_expired");
        assert_eq!(
            report.per_module.get("secrets_access_log").copied(),
            Some(1)
        );

        let guard = conn.lock().await;
        let remaining: i64 = guard
            .query_row(
                "SELECT COUNT(*) FROM cirislens_secrets_access_log \
                 WHERE accessor = ?1",
                ["test-accessor"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 0);
    }

    /// v1.2.0 (CIRISPersist#48) Test 4 — maintain() umbrella runs
    /// both vacuum + archive in sequence.
    #[tokio::test]
    async fn maintenance_maintain_umbrella_runs_all() {
        let (backend, svc) = fresh_backend().await;
        let conn = backend.conn_handle();

        let observed = Utc::now() - Duration::hours(2);
        let expires = Utc::now() - Duration::hours(1);
        let stale_secrets = Utc::now() - Duration::days(60);
        let stale_incident = Utc::now() - Duration::days(180);
        {
            let guard = conn.lock().await;
            // 1 expired telemetry row.
            guard
                .execute(
                    "INSERT INTO cirisgraph_telemetry_metrics (\
                        metric_id, metric_name, tenant_id, value, labels, \
                        observed_at, expires_at\
                     ) VALUES (?1, 'umb.metric', 'tnt-umb', 1.0, '{}', ?2, ?3)",
                    params![Uuid::new_v4().to_string(), fmt(observed), fmt(expires),],
                )
                .unwrap();
            // 1 stale secrets access_log row.
            guard
                .execute(
                    "INSERT INTO cirislens_secrets_access_log (\
                        secret_uuid, accessor, operation, action_type, \
                        purpose, success, error, trace_id, thought_id, created_at\
                     ) VALUES (NULL, 'umb-acc', 'store', NULL, NULL, 1, NULL, NULL, NULL, ?1)",
                    params![fmt(stale_secrets)],
                )
                .unwrap();
            // 1 closed incident past 90 days.
            guard
                .execute(
                    "INSERT INTO cirislens_incident_records (\
                        incident_id, tenant_id, severity, category, title, \
                        description, correlation_keys, state, first_seen_at, \
                        last_seen_at, resolved_at, resolution_notes, occurrences, \
                        persist_row_hash\
                     ) VALUES (?1, 'tnt-umb', 'error', 'service_failure', \
                        'umbrella test', NULL, '[]', 'closed', ?2, ?2, ?2, NULL, 1, \
                        'h-stub')",
                    params![Uuid::new_v4().to_string(), fmt(stale_incident)],
                )
                .unwrap();
        }

        let report = svc.maintain().await.expect("maintain");
        assert_eq!(report.vacuum.dialect, "sqlite");
        assert!(report.archive.total_removed >= 3);
        assert_eq!(report.archive.per_module.get("telemetry").copied(), Some(1));
        assert_eq!(
            report.archive.per_module.get("secrets_access_log").copied(),
            Some(1)
        );
        assert_eq!(report.archive.per_module.get("incidents").copied(), Some(1));
    }

    /// v1.2.0 (CIRISPersist#48) Test 5 — prune_audit_chain is a
    /// stub that returns zero entries removed. Real prune semantics
    /// gated on CIRISAgent#760.
    #[tokio::test]
    async fn maintenance_prune_audit_chain_is_stub() {
        let (_b, svc) = fresh_backend().await;
        let report = svc
            .prune_audit_chain("any-tenant", Utc::now())
            .await
            .expect("prune");
        assert_eq!(report.entries_removed, 0);
        assert!(report.new_anchor_id.is_none());
    }
}
