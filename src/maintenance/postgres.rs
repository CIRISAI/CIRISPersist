//! PostgreSQL impl of [`MaintenanceService`] (v1.2.0,
//! CIRISPersist#48).
//!
//! Operation-side absorbed from the agent's
//! `DatabaseMaintenanceService`. Per-module retention defaults are
//! documented on [`super`] — this module owns the SQL.
//!
//! # Transaction handling
//!
//! Postgres `VACUUM` cannot run inside a transaction block — the
//! statement is parsed at top level and refuses to execute under
//! `BEGIN`. The impl uses `client.batch_execute("VACUUM ANALYZE")`
//! on a dedicated client checked out from the deadpool, which runs
//! the statement at top-level (deadpool's `get()` returns a
//! transaction-free client; tokio-postgres' `batch_execute` doesn't
//! wrap in `BEGIN`/`COMMIT`).
//!
//! The `archive_expired` `DELETE`s and the `prune_audit_chain` stub
//! each run on their own pooled client; we don't wrap them in a
//! single transaction because the DELETEs target disjoint tables
//! and partial progress is acceptable (each module's DELETE is
//! idempotent — a re-run after a transient failure replays cleanly).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};

use super::service::MaintenanceService;
use super::types::{
    ArchiveReport, ArchiveWindow, MaintenanceReport, PruneReport, RetentionPolicy,
    RetentionPolicyRow, RetentionReport, VacuumReport,
};
use super::Error;
use crate::store::postgres::PostgresBackend;

/// v1.2.0 (CIRISPersist#48) — PG-backed
/// [`MaintenanceService`](super::MaintenanceService) impl. Holds an
/// `Arc<PostgresBackend>` so the FFI dispatcher in
/// [`crate::ffi::pyo3`] can share the same pool the rest of the
/// substrate uses.
pub struct PostgresMaintenanceBackend {
    backend: Arc<PostgresBackend>,
}

impl PostgresMaintenanceBackend {
    /// Construct from a shared [`PostgresBackend`] arc.
    pub fn new(backend: Arc<PostgresBackend>) -> Self {
        Self { backend }
    }
}

fn map_pg_error(e: tokio_postgres::Error, op: &str) -> Error {
    let detail = e
        .as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string());
    Error::Backend(format!("{op}: {detail}"))
}

/// Compute the cutoff seconds for an archive window.
///
/// PG `make_interval(secs => …)` expects `double precision`, not
/// bigint — binding i64 raises `WrongType { postgres: Float8,
/// rust: "i64" }`. Returning f64 lines up the bind types.
fn fixed_seconds(window: ArchiveWindow, default_days: f64) -> f64 {
    match window {
        ArchiveWindow::SubstrateDefault => default_days * 86_400.0,
        ArchiveWindow::Custom { seconds } => seconds as f64,
    }
}

impl MaintenanceService for PostgresMaintenanceBackend {
    async fn vacuum_substrate(&self) -> Result<VacuumReport, Error> {
        // VACUUM cannot run inside a transaction. Deadpool's
        // `get()` returns a transaction-free client; tokio-postgres'
        // `batch_execute` runs the statement at top level.
        let client = self
            .backend
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("vacuum pool: {e}")))?;
        let started = Instant::now();
        client
            .batch_execute("VACUUM ANALYZE")
            .await
            .map_err(|e| map_pg_error(e, "VACUUM ANALYZE"))?;
        let elapsed_ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
        Ok(VacuumReport {
            dialect: "postgres".to_owned(),
            elapsed_ms,
        })
    }

    async fn archive_expired(&self, window: ArchiveWindow) -> Result<ArchiveReport, Error> {
        let client = self
            .backend
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("archive pool: {e}")))?;

        let mut per_module: HashMap<String, usize> = HashMap::new();
        let mut total: usize = 0;

        // ── telemetry: rows past their own expires_at ────────────
        //
        // V015 defines `cirisgraph.telemetry_metrics.expires_at`
        // (TIMESTAMPTZ NOT NULL); producers set it on insert
        // (default observed_at + 24h). Substrate-default mode
        // honors the producer-set expiry. Custom mode overrides
        // with `created_at < NOW() - INTERVAL '<seconds> seconds'`
        // (telemetry has no created_at, but observed_at fills the
        // same role).
        let telemetry_n = match window {
            ArchiveWindow::SubstrateDefault => client
                .execute(
                    "DELETE FROM cirisgraph.telemetry_metrics \
                     WHERE expires_at < NOW()",
                    &[],
                )
                .await
                .map_err(|e| map_pg_error(e, "DELETE telemetry"))?,
            ArchiveWindow::Custom { seconds } => {
                let secs = seconds as f64;
                client
                    .execute(
                        "DELETE FROM cirisgraph.telemetry_metrics \
                         WHERE observed_at < NOW() - make_interval(secs => $1)",
                        &[&secs],
                    )
                    .await
                    .map_err(|e| map_pg_error(e, "DELETE telemetry (custom)"))?
            }
        };
        per_module.insert("telemetry".to_owned(), telemetry_n as usize);
        total += telemetry_n as usize;

        // ── secrets access_log: 30-day default ───────────────────
        let secrets_secs = fixed_seconds(window, 30.0);
        let secrets_n = client
            .execute(
                "DELETE FROM cirislens_secrets.access_log \
                 WHERE created_at < NOW() - make_interval(secs => $1)",
                &[&secrets_secs],
            )
            .await
            .map_err(|e| map_pg_error(e, "DELETE secrets access_log"))?;
        per_module.insert("secrets_access_log".to_owned(), secrets_n as usize);
        total += secrets_n as usize;

        // ── incidents (closed): 90-day default ───────────────────
        //
        // V016 does NOT carry an `updated_at` column. `last_seen_at`
        // is the closest analog — it tracks when the incident was
        // most recently observed; for closed incidents that's
        // effectively the resolution timestamp.
        let incidents_secs = fixed_seconds(window, 90.0);
        let incidents_n = client
            .execute(
                "DELETE FROM cirislens.incident_records \
                 WHERE state = 'closed' \
                   AND last_seen_at < NOW() - make_interval(secs => $1)",
                &[&incidents_secs],
            )
            .await
            .map_err(|e| map_pg_error(e, "DELETE incidents"))?;
        per_module.insert("incidents".to_owned(), incidents_n as usize);
        total += incidents_n as usize;

        // ── federation_keys (expired by valid_until): 180-day
        //    default ────────────────────────────────────────────
        //
        // `federation_keys` doesn't store revocation state directly
        // (revocations live in `federation_revocations`); the
        // analog operational signal is `valid_until` (key expiry).
        // Keys whose validity ended more than the cutoff ago are
        // safe to archive.
        let federation_secs = fixed_seconds(window, 180.0);
        let federation_n = client
            .execute(
                "DELETE FROM cirislens.federation_keys \
                 WHERE valid_until IS NOT NULL \
                   AND valid_until < NOW() - make_interval(secs => $1)",
                &[&federation_secs],
            )
            .await
            .map_err(|e| map_pg_error(e, "DELETE federation_keys"))?;
        per_module.insert("federation_keys_expired".to_owned(), federation_n as usize);
        total += federation_n as usize;

        Ok(ArchiveReport {
            per_module,
            total_removed: total,
        })
    }

    async fn prune_audit_chain(
        &self,
        _tenant: &str,
        _before: DateTime<Utc>,
    ) -> Result<PruneReport, Error> {
        // v1.2.0 stub. The full prune-with-anchor semantics depend
        // on CIRISAgent#760 Counter-RII review-window answers (how
        // long must the chain remain re-derivable for steward
        // review?). Real implementation lands once that
        // review-window guidance is in hand.
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

    // ── Retention (CIRISPersist#209) ───────────────────────────────

    async fn set_retention(
        &self,
        table_name: String,
        policy: RetentionPolicy,
    ) -> Result<(), Error> {
        crate::maintenance::validate_sql_identifier(&table_name)?;
        crate::maintenance::validate_sql_identifier(&policy.time_column)?;
        let client = self
            .backend
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("retention pool: {e}")))?;
        client
            .execute(
                "INSERT INTO cirislens.retention_policies \
                    (table_name, time_column, min_keep_secs, pressure_trigger_bytes, \
                     pressure_target_bytes, interval_secs, updated_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, now()) \
                 ON CONFLICT (table_name) DO UPDATE SET \
                    time_column = EXCLUDED.time_column, \
                    min_keep_secs = EXCLUDED.min_keep_secs, \
                    pressure_trigger_bytes = EXCLUDED.pressure_trigger_bytes, \
                    pressure_target_bytes = EXCLUDED.pressure_target_bytes, \
                    interval_secs = EXCLUDED.interval_secs, \
                    updated_at = now()",
                &[
                    &table_name,
                    &policy.time_column,
                    &(policy.min_keep_secs as i64),
                    &policy.pressure_trigger_bytes.map(|v| v as i64),
                    &policy.pressure_target_bytes.map(|v| v as i64),
                    &(policy.interval_secs as i64),
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "set_retention"))?;
        Ok(())
    }

    async fn get_retention(&self, table_name: &str) -> Result<Option<RetentionPolicy>, Error> {
        let client = self
            .backend
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("retention pool: {e}")))?;
        let row = client
            .query_opt(
                "SELECT time_column, min_keep_secs, pressure_trigger_bytes, \
                    pressure_target_bytes, interval_secs \
                 FROM cirislens.retention_policies WHERE table_name = $1",
                &[&table_name],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_retention"))?;
        Ok(row.map(|r| pg_row_to_retention_policy(&r)))
    }

    async fn list_retention(&self) -> Result<Vec<RetentionPolicyRow>, Error> {
        let client = self
            .backend
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("retention pool: {e}")))?;
        let rows = client
            .query(
                "SELECT table_name, time_column, min_keep_secs, pressure_trigger_bytes, \
                    pressure_target_bytes, interval_secs \
                 FROM cirislens.retention_policies ORDER BY table_name",
                &[],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_retention"))?;
        Ok(rows
            .iter()
            .map(|r| RetentionPolicyRow {
                table_name: r.get("table_name"),
                policy: pg_row_to_retention_policy(r),
            })
            .collect())
    }

    async fn run_retention(&self, now: DateTime<Utc>) -> Result<Vec<RetentionReport>, Error> {
        let policies = self.list_retention().await?;
        let client = self
            .backend
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("retention pool: {e}")))?;
        let mut reports = Vec::with_capacity(policies.len());
        for row in policies {
            // Defense in depth — stored rows should already be valid, but
            // these reach DELETE SQL un-bindable, so re-validate.
            crate::maintenance::validate_sql_identifier(&row.table_name)?;
            crate::maintenance::validate_sql_identifier(&row.policy.time_column)?;
            let db_size: i64 = client
                .query_one("SELECT pg_database_size(current_database())", &[])
                .await
                .map_err(|e| map_pg_error(e, "pg_database_size"))?
                .get(0);
            let db_size = db_size.max(0) as u64;
            let cutoff = now - chrono::Duration::seconds(row.policy.min_keep_secs as i64);
            let pressure_gated = row.policy.pressure_trigger_bytes.is_some()
                && row.policy.pressure_target_bytes.is_some();
            let do_sweep = match row.policy.pressure_trigger_bytes {
                Some(trigger) if pressure_gated => db_size >= trigger,
                _ => true, // flat schedule
            };
            let mut swept = false;
            let mut rows_deleted = 0usize;
            let mut exhausted = false;
            if do_sweep {
                // table_name + time_column are validated identifiers; cutoff is bound.
                let sql = format!(
                    "DELETE FROM {} WHERE {} < $1",
                    row.table_name, row.policy.time_column
                );
                let n = client
                    .execute(sql.as_str(), &[&cutoff])
                    .await
                    .map_err(|e| map_pg_error(e, "run_retention DELETE"))?;
                rows_deleted = n as usize;
                swept = true;
                if let (true, Some(target)) = (pressure_gated, row.policy.pressure_target_bytes) {
                    // Best-effort: a row DELETE doesn't reclaim heap until
                    // VACUUM, so this measures the not-yet-reclaimed size —
                    // precise targeting awaits the drop_chunks path (#209).
                    let after: i64 = client
                        .query_one("SELECT pg_database_size(current_database())", &[])
                        .await
                        .map_err(|e| map_pg_error(e, "pg_database_size"))?
                        .get(0);
                    exhausted = after.max(0) as u64 >= target;
                }
            }
            reports.push(RetentionReport {
                table_name: row.table_name,
                swept,
                rows_deleted,
                db_size_bytes: db_size,
                exhausted,
            });
        }
        Ok(reports)
    }
}

fn pg_row_to_retention_policy(r: &tokio_postgres::Row) -> RetentionPolicy {
    RetentionPolicy {
        min_keep_secs: r.get::<_, i64>("min_keep_secs").max(0) as u64,
        time_column: r.get("time_column"),
        pressure_trigger_bytes: r
            .get::<_, Option<i64>>("pressure_trigger_bytes")
            .map(|v| v.max(0) as u64),
        pressure_target_bytes: r
            .get::<_, Option<i64>>("pressure_target_bytes")
            .map(|v| v.max(0) as u64),
        interval_secs: r.get::<_, i64>("interval_secs").max(0) as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Backend;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    async fn fresh_backend() -> Option<(Arc<PostgresBackend>, PostgresMaintenanceBackend)> {
        let dsn = pg_dsn()?;
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let arc = Arc::new(backend);
        let svc = PostgresMaintenanceBackend::new(arc.clone());
        Some((arc, svc))
    }

    /// CIRISPersist#209 — retention CRUD + flat sweep on live PG:
    /// `pg_database_size` measured, the validated-identifier DELETE drops
    /// rows past `min_keep`, recent rows kept. Uses a unique temp table
    /// (cleaned up) to stay isolated on the shared serial DB.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_retention_crud_and_flat_sweep() {
        let Some((arc, svc)) = fresh_backend().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let tbl = format!("ret_test_{}", Uuid::new_v4().simple());
        let now = Utc::now();
        {
            let client = arc.pool().get().await.unwrap();
            client
                .execute(
                    &format!("CREATE TABLE {tbl} (ts TIMESTAMPTZ NOT NULL, v INT)"),
                    &[],
                )
                .await
                .unwrap();
            client
                .execute(
                    &format!("INSERT INTO {tbl} (ts, v) VALUES ($1, 1), ($2, 2)"),
                    &[
                        &(now - chrono::Duration::days(40)),
                        &(now - chrono::Duration::hours(1)),
                    ],
                )
                .await
                .unwrap();
        }
        let pol = RetentionPolicy {
            min_keep_secs: 30 * 86_400,
            time_column: "ts".into(),
            pressure_trigger_bytes: None,
            pressure_target_bytes: None,
            interval_secs: 3_600,
        };
        svc.set_retention(tbl.clone(), pol).await.unwrap();
        assert_eq!(
            svc.get_retention(&tbl)
                .await
                .unwrap()
                .unwrap()
                .min_keep_secs,
            30 * 86_400
        );
        assert!(svc
            .list_retention()
            .await
            .unwrap()
            .iter()
            .any(|r| r.table_name == tbl));

        let reports = svc.run_retention(now).await.unwrap();
        let r = reports.iter().find(|r| r.table_name == tbl).unwrap();
        assert!(r.swept);
        assert_eq!(
            r.rows_deleted, 1,
            "40d row past the 30d floor deleted; recent kept"
        );
        assert!(r.db_size_bytes > 0, "pg_database_size measured");

        // cleanup — drop the temp table + its policy row.
        let client = arc.pool().get().await.unwrap();
        client
            .execute(&format!("DROP TABLE {tbl}"), &[])
            .await
            .unwrap();
        client
            .execute(
                "DELETE FROM cirislens.retention_policies WHERE table_name = $1",
                &[&tbl],
            )
            .await
            .unwrap();
    }

    /// v1.2.0 (CIRISPersist#48) PG Test 1 — VACUUM ANALYZE runs
    /// clean against a migrated DB. Gated on
    /// `CIRIS_PERSIST_TEST_PG_URL`.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn maintenance_pg_vacuum_runs_clean() {
        let Some((_arc, svc)) = fresh_backend().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let report = svc.vacuum_substrate().await.expect("vacuum");
        assert_eq!(report.dialect, "postgres");
    }

    /// v1.2.0 (CIRISPersist#48) PG Test 2 — archive_expired removes
    /// telemetry rows whose `expires_at` is in the past.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn maintenance_pg_archive_expired_telemetry() {
        let Some((arc, svc)) = fresh_backend().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let tenant = format!("mnt-pg-{}", Uuid::new_v4().simple());

        // Insert one row past its expires_at.
        {
            let client = arc.pool().get().await.unwrap();
            client
                .execute(
                    "INSERT INTO cirisgraph.telemetry_metrics (\
                        metric_id, metric_name, tenant_id, value, labels, \
                        observed_at, expires_at\
                     ) VALUES ($1::uuid, $2, $3, $4, $5, NOW() - INTERVAL '2 hours', \
                        NOW() - INTERVAL '1 hour')",
                    // labels is JSONB — bind via serde_json::Value, not &str.
                    // tokio-postgres can't auto-cast str→jsonb even with $5::jsonb
                    // (the param-type negotiation runs before the SQL cast).
                    &[
                        &Uuid::new_v4(),
                        &"mnt.test.metric",
                        &tenant,
                        &1.0f64,
                        &serde_json::json!({}),
                    ],
                )
                .await
                .unwrap();
        }

        let report = svc
            .archive_expired(ArchiveWindow::SubstrateDefault)
            .await
            .expect("archive_expired");
        assert!(
            report.per_module.get("telemetry").copied().unwrap_or(0) >= 1,
            "expected telemetry removals >= 1, got {:?}",
            report.per_module
        );

        // Cleanup any residual.
        let client = arc.pool().get().await.unwrap();
        client
            .execute(
                "DELETE FROM cirisgraph.telemetry_metrics WHERE tenant_id = $1",
                &[&tenant],
            )
            .await
            .unwrap();
    }

    /// v1.2.0 (CIRISPersist#48) PG Test 3 — prune_audit_chain is a
    /// stub that returns zero entries removed.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn maintenance_pg_prune_audit_chain_is_stub() {
        let Some((_arc, svc)) = fresh_backend().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let report = svc
            .prune_audit_chain("any-tenant", Utc::now())
            .await
            .expect("prune");
        assert_eq!(report.entries_removed, 0);
        assert!(report.new_anchor_id.is_none());
    }

    /// v1.2.0 (CIRISPersist#48) PG Test 4 — umbrella maintain()
    /// runs vacuum + archive.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn maintenance_pg_maintain_umbrella_runs_all() {
        let Some((_arc, svc)) = fresh_backend().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let report = svc.maintain().await.expect("maintain");
        assert_eq!(report.vacuum.dialect, "postgres");
        // archive may be zero on a clean DB; just assert the keys
        // are populated.
        assert!(report.archive.per_module.contains_key("telemetry"));
        assert!(report.archive.per_module.contains_key("secrets_access_log"));
        assert!(report.archive.per_module.contains_key("incidents"));
        assert!(report
            .archive
            .per_module
            .contains_key("federation_keys_expired"));
    }
}
