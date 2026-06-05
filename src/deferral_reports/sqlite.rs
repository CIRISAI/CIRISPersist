//! SQLite impl of [`DeferralReportService`] (v1.5.14,
//! CIRISPersist#59 #6).
//!
//! Mirrors the v1.5.14 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ                            → TEXT (RFC 3339)
//!   JSONB                                  → TEXT (raw JSON string)
//!   ON CONFLICT (message_id) DO NOTHING    → INSERT OR IGNORE
//!   DEFERRABLE INITIALLY DEFERRED FKs      → immediate FKs (SQLite
//!                                            doesn't honor DEFERRABLE
//!                                            without per-tx
//!                                            `PRAGMA defer_foreign_keys=1`)
//!
//! Threading: `tokio::task::spawn_blocking` + `conn.lock()`
//! per the existing pattern.
//!
//! `record_deferral` uses the same ClaimResult shape as the v1.5.9
//! tasks `try_claim_shared_task` SQLite path: `INSERT OR IGNORE`
//! followed by an in-transaction `SELECT` so the race-loser reads
//! back the existing row.
#![allow(clippy::redundant_closure_call)]
// v3.14.0 (CIRISPersist#158) — inline-sync rewrite of all
// tokio::task::spawn_blocking sites uses (closure)() to invoke
// the closure inline. Clippy's redundant_closure_call lint flags
// this; we allow it because the mechanical transformation kept
// each closure's typed return signature load-bearing for error
// propagation and any other refactor would be a much larger diff.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{params, types::Value as SqlValue, Connection, OptionalExtension};

use super::service::DeferralReportService;
use super::types::{DeferralFilter, DeferralReport};
use super::Error;
use crate::ClaimResult;

/// SQLite-backed [`DeferralReportService`] impl.
pub struct SqliteDeferralReportBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteDeferralReportBackend {
    /// Construct from a shared connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if err.code == ErrorCode::ConstraintViolation {
            let s = e.to_string();
            if s.contains("FOREIGN KEY") {
                return Error::Conflict(format!("{op}: {e}"));
            }
            return Error::InvalidArgument(format!("{op}: {e}"));
        }
    }
    Error::Backend(format!("{op}: {e}"))
}

fn parse_datetime(s: &str) -> Result<DateTime<Utc>, Error> {
    let normalized = if s.contains('T') {
        s.to_owned()
    } else {
        format!("{}+00:00", s.replacen(' ', "T", 1))
    };
    chrono::DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::Backend(format!("datetime parse: {e} (raw={s})")))
}

fn fmt_datetime(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn parse_datetime_opt(s: Option<String>) -> Result<Option<DateTime<Utc>>, Error> {
    match s {
        None => Ok(None),
        Some(raw) => parse_datetime(&raw).map(Some),
    }
}

fn encode_json_opt(v: Option<&serde_json::Value>) -> Result<Option<String>, Error> {
    match v {
        None => Ok(None),
        Some(value) => serde_json::to_string(value)
            .map(Some)
            .map_err(|e| Error::Internal(format!("json encode: {e}"))),
    }
}

fn decode_json_opt(s: Option<String>) -> Result<Option<serde_json::Value>, Error> {
    match s {
        None => Ok(None),
        Some(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|e| Error::Backend(format!("json decode: {e} (raw={raw})"))),
    }
}

fn validate_report(r: &DeferralReport) -> Result<(), Error> {
    if r.message_id.is_empty() {
        return Err(Error::InvalidArgument("message_id required".into()));
    }
    if r.task_id.is_empty() {
        return Err(Error::InvalidArgument("task_id required".into()));
    }
    if r.thought_id.is_empty() {
        return Err(Error::InvalidArgument("thought_id required".into()));
    }
    Ok(())
}

fn decode_deferral_row(row: &rusqlite::Row<'_>) -> Result<DeferralReport, Error> {
    let message_id: String = row
        .get("message_id")
        .map_err(|e| Error::Backend(format!("decode message_id: {e}")))?;
    let task_id: String = row
        .get("task_id")
        .map_err(|e| Error::Backend(format!("decode task_id: {e}")))?;
    let thought_id: String = row
        .get("thought_id")
        .map_err(|e| Error::Backend(format!("decode thought_id: {e}")))?;
    let package_raw: Option<String> = row
        .get("package")
        .map_err(|e| Error::Backend(format!("decode package: {e}")))?;
    let created_at_str: String = row
        .get("created_at")
        .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?;
    let resolved_at_str: Option<String> = row
        .get("resolved_at")
        .map_err(|e| Error::Backend(format!("decode resolved_at: {e}")))?;
    let resolution_notes: Option<String> = row
        .get("resolution_notes")
        .map_err(|e| Error::Backend(format!("decode resolution_notes: {e}")))?;
    Ok(DeferralReport {
        message_id,
        task_id,
        thought_id,
        package: decode_json_opt(package_raw)?,
        created_at: parse_datetime(&created_at_str)?,
        resolved_at: parse_datetime_opt(resolved_at_str)?,
        resolution_notes,
    })
}

impl DeferralReportService for SqliteDeferralReportBackend {
    async fn record_deferral(
        &self,
        report: DeferralReport,
    ) -> Result<ClaimResult<DeferralReport>, Error> {
        validate_report(&report)?;
        let package_str = encode_json_opt(report.package.as_ref())?;
        let created_at_str = fmt_datetime(report.created_at);
        let resolved_at_str = report.resolved_at.map(fmt_datetime);
        let message_id_for_lookup = report.message_id.clone();

        let conn = self.conn.clone();
        let (won, row): (bool, DeferralReport) =
            (move || -> Result<(bool, DeferralReport), Error> {
                let mut guard = conn.lock();
                let tx = guard
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(|e| map_sqlite_error(e, "record_deferral begin"))?;
                let changed = tx
                    .execute(
                        "INSERT OR IGNORE INTO cirislens_deferral_reports (\
                            message_id, task_id, thought_id, package, \
                            created_at, resolved_at, resolution_notes\
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                        params![
                            report.message_id,
                            report.task_id,
                            report.thought_id,
                            package_str,
                            created_at_str,
                            resolved_at_str,
                            report.resolution_notes,
                        ],
                    )
                    .map_err(|e| map_sqlite_error(e, "record_deferral insert"))?;
                let won = changed > 0;
                // Re-read regardless of outcome — winner gets back
                // their own row, loser gets back the EXISTING row.
                let row = tx
                    .query_row(
                        "SELECT message_id, task_id, thought_id, package, \
                                created_at, resolved_at, resolution_notes \
                         FROM cirislens_deferral_reports WHERE message_id = ?1",
                        params![message_id_for_lookup],
                        |row| Ok(decode_deferral_row(row)),
                    )
                    .map_err(|e| map_sqlite_error(e, "record_deferral readback"))??;
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "record_deferral commit"))?;
                Ok((won, row))
            })()?;

        if won {
            Ok(ClaimResult::Stored(row))
        } else {
            Ok(ClaimResult::AlreadyClaimed(row))
        }
    }

    async fn get_deferral(&self, message_id: &str) -> Result<Option<DeferralReport>, Error> {
        if message_id.is_empty() {
            return Err(Error::InvalidArgument("message_id required".into()));
        }
        let message_id_owned = message_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Option<DeferralReport>, Error> {
            let guard = conn.lock();
            let row_opt = guard
                .query_row(
                    "SELECT message_id, task_id, thought_id, package, \
                            created_at, resolved_at, resolution_notes \
                     FROM cirislens_deferral_reports WHERE message_id = ?1",
                    params![message_id_owned],
                    |row| Ok(decode_deferral_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_deferral query"))?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(r?)),
            }
        })()
    }

    async fn list_active_deferrals(
        &self,
        filter: DeferralFilter,
        limit: i64,
    ) -> Result<Vec<DeferralReport>, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let mut where_parts: Vec<String> = vec!["resolved_at IS NULL".into()];
        let mut sql_params: Vec<SqlValue> = Vec::new();
        if let Some(task_id) = filter.task_id {
            sql_params.push(SqlValue::Text(task_id));
            where_parts.push(format!("task_id = ?{}", sql_params.len()));
        }
        if let Some(thought_id) = filter.thought_id {
            sql_params.push(SqlValue::Text(thought_id));
            where_parts.push(format!("thought_id = ?{}", sql_params.len()));
        }
        if let Some(after) = filter.created_after {
            sql_params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push(format!("created_at >= ?{}", sql_params.len()));
        }
        if let Some(before) = filter.created_before {
            sql_params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push(format!("created_at <= ?{}", sql_params.len()));
        }
        sql_params.push(SqlValue::Integer(limit));
        let p_limit = sql_params.len();
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT message_id, task_id, thought_id, package, \
                    created_at, resolved_at, resolution_notes \
             FROM cirislens_deferral_reports \
             WHERE {where_sql} \
             ORDER BY created_at DESC, message_id DESC \
             LIMIT ?{p_limit}"
        );
        let conn = self.conn.clone();
        (move || -> Result<Vec<DeferralReport>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "list_active_deferrals prepare"))?;
            let rows_iter = stmt
                .query_map(rusqlite::params_from_iter(sql_params.iter()), |row| {
                    Ok(decode_deferral_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "list_active_deferrals query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "list_active_deferrals row"))??);
            }
            Ok(items)
        })()
    }

    async fn resolve_deferral(
        &self,
        message_id: &str,
        resolved_at: DateTime<Utc>,
        resolution_notes: Option<String>,
    ) -> Result<bool, Error> {
        if message_id.is_empty() {
            return Err(Error::InvalidArgument("message_id required".into()));
        }
        let message_id_owned = message_id.to_owned();
        let resolved_at_str = fmt_datetime(resolved_at);
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let guard = conn.lock();
            let changed = guard
                .execute(
                    "UPDATE cirislens_deferral_reports SET \
                        resolved_at = ?1, \
                        resolution_notes = ?2 \
                     WHERE message_id = ?3",
                    params![resolved_at_str, resolution_notes, message_id_owned],
                )
                .map_err(|e| map_sqlite_error(e, "resolve_deferral exec"))?;
            Ok(changed > 0)
        })()
    }
}

#[cfg(test)]
#[cfg(all(feature = "cirislens_tasks", feature = "cirislens_thoughts"))]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use crate::tasks::sqlite::SqliteTaskBackend;
    use crate::tasks::types::{Task, TaskStatus};
    use crate::tasks::TaskService;
    use crate::thoughts::sqlite::SqliteThoughtBackend;
    use crate::thoughts::types::{Thought, ThoughtStatus, ThoughtType};
    use crate::thoughts::ThoughtService;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteDeferralReportBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteDeferralReportBackend::new(backend.conn_handle());
        (backend, svc)
    }

    /// Seed a parent task + parent thought, return `(task_id,
    /// thought_id)` for use on deferral reports.
    async fn seed_parents(b: &SqliteBackend) -> (String, String) {
        let tasks = SqliteTaskBackend::new(b.conn_handle());
        let thoughts = SqliteThoughtBackend::new(b.conn_handle());
        let task_id = format!("task-{}", Uuid::new_v4().simple());
        let thought_id = format!("thought-{}", Uuid::new_v4().simple());
        let now = Utc::now();
        let task = Task {
            task_id: task_id.clone(),
            channel_id: "ch-1".into(),
            description: "parent".into(),
            status: TaskStatus::Active,
            priority: 0,
            created_at: now,
            updated_at: now,
            parent_task_id: None,
            context: None,
            outcome: None,
            signed_by: None,
            signature: None,
            signed_at: None,
            retry_count: 0,
            updated_info_available: false,
            updated_info_content: None,
            agent_occurrence_id: "occ-test".into(),
            images: None,
        };
        tasks.upsert_task(task).await.unwrap();
        let thought = Thought {
            thought_id: thought_id.clone(),
            source_task_id: task_id.clone(),
            channel_id: Some("ch-1".into()),
            thought_type: ThoughtType::standard(),
            status: ThoughtStatus::Pending,
            created_at: now,
            updated_at: now,
            round_number: 0,
            content: "parent thought".into(),
            context: None,
            thought_depth: 0,
            ponder_notes: None,
            parent_thought_id: None,
            final_action: None,
            agent_occurrence_id: "occ-test".into(),
        };
        thoughts.upsert_thought(thought).await.unwrap();
        (task_id, thought_id)
    }

    fn mk_report(message_id: &str, task_id: &str, thought_id: &str) -> DeferralReport {
        DeferralReport {
            message_id: message_id.to_owned(),
            task_id: task_id.to_owned(),
            thought_id: thought_id.to_owned(),
            package: Some(serde_json::json!({"reason": "out_of_scope"})),
            created_at: Utc::now(),
            resolved_at: None,
            resolution_notes: None,
        }
    }

    /// Whether SQLite's FK pragma is on for the test connection.
    /// Mirrors the scheduled_tasks pattern — migrations don't enable
    /// it; substrate tests skip the FK rejection check when it's off.
    async fn fk_pragma_on(b: &SqliteBackend) -> bool {
        let conn = b.conn_handle();
        (move || -> bool {
            let guard = conn.lock();
            guard
                .query_row("PRAGMA foreign_keys", params![], |row| row.get::<_, i64>(0))
                .map(|v| v == 1)
                .unwrap_or(false)
        })()
    }

    #[tokio::test]
    async fn record_get_round_trip_all_7_columns() {
        let (b, svc) = fresh_backend().await;
        let (task_id, thought_id) = seed_parents(&b).await;
        let mid = format!("msg-{}", Uuid::new_v4().simple());
        let now = Utc::now();
        let r = DeferralReport {
            message_id: mid.clone(),
            task_id: task_id.clone(),
            thought_id: thought_id.clone(),
            package: Some(serde_json::json!({"k": "v", "n": 42})),
            created_at: now,
            resolved_at: None,
            resolution_notes: None,
        };
        let outcome = svc.record_deferral(r.clone()).await.unwrap();
        assert!(matches!(outcome, ClaimResult::Stored(_)));

        let got = svc.get_deferral(&mid).await.unwrap().expect("present");
        assert_eq!(got.message_id, r.message_id);
        assert_eq!(got.task_id, r.task_id);
        assert_eq!(got.thought_id, r.thought_id);
        assert_eq!(got.package, r.package);
        assert!(got.resolved_at.is_none());
        assert!(got.resolution_notes.is_none());
        let drift = (got.created_at - now).num_seconds().abs();
        assert!(drift <= 1, "created_at preserved: {drift}s drift");
    }

    #[tokio::test]
    async fn fk_rejects_nonexistent_task_or_thought() {
        let (b, svc) = fresh_backend().await;
        if !fk_pragma_on(&b).await {
            eprintln!(
                "SQLite foreign_keys pragma off — skipping FK rejection check. Migrations \
                 don't enable it by default; substrate tests rely on the agent host enabling it."
            );
            return;
        }

        // No seed_parents — both FKs dangle.
        let mid = format!("msg-{}", Uuid::new_v4().simple());
        let bogus_task = format!("task-bogus-{}", Uuid::new_v4().simple());
        let bogus_thought = format!("thought-bogus-{}", Uuid::new_v4().simple());
        let r = mk_report(&mid, &bogus_task, &bogus_thought);
        let res = svc.record_deferral(r).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected FK Conflict for dangling task+thought, got {res:?}"
        );

        // Seed only the task — thought_id still dangles.
        let (task_id, _thought_id) = seed_parents(&b).await;
        let mid2 = format!("msg-{}", Uuid::new_v4().simple());
        let bogus_thought2 = format!("thought-bogus-{}", Uuid::new_v4().simple());
        let r2 = mk_report(&mid2, &task_id, &bogus_thought2);
        let res = svc.record_deferral(r2).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected FK Conflict for dangling thought, got {res:?}"
        );
    }

    #[tokio::test]
    async fn record_already_claimed_returns_existing_row() {
        let (b, svc) = fresh_backend().await;
        let (task_id, thought_id) = seed_parents(&b).await;
        let mid = format!("msg-{}", Uuid::new_v4().simple());
        let r1 = mk_report(&mid, &task_id, &thought_id);
        let out1 = svc.record_deferral(r1.clone()).await.unwrap();
        assert!(matches!(out1, ClaimResult::Stored(_)));

        // Second record with same message_id but different package —
        // should NOT overwrite. Loser reads back the existing row.
        let mut r2 = r1.clone();
        r2.package = Some(serde_json::json!({"reason": "overwritten?"}));
        let out2 = svc.record_deferral(r2).await.unwrap();
        assert!(matches!(out2, ClaimResult::AlreadyClaimed(_)));
        let existing = out2.into_reference();
        assert_eq!(existing.package, r1.package, "loser sees original row");
    }

    #[tokio::test]
    async fn list_active_filters_resolved() {
        let (b, svc) = fresh_backend().await;
        let (task_id, thought_id) = seed_parents(&b).await;
        // 3 deferrals — record all, then resolve 2 of them.
        let mut mids = Vec::new();
        for _ in 0..3 {
            let mid = format!("msg-{}", Uuid::new_v4().simple());
            mids.push(mid.clone());
            let r = mk_report(&mid, &task_id, &thought_id);
            svc.record_deferral(r).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        let now = Utc::now();
        assert!(svc
            .resolve_deferral(&mids[0], now, Some("approved".into()))
            .await
            .unwrap());
        assert!(svc
            .resolve_deferral(&mids[1], now, Some("denied".into()))
            .await
            .unwrap());

        // Filter on this test's task_id so we don't pick up rows
        // from sibling tests (in-memory DB is fresh per test, so this
        // is defensive — but match the postgres test shape).
        let active = svc
            .list_active_deferrals(
                DeferralFilter {
                    task_id: Some(task_id.clone()),
                    ..Default::default()
                },
                100,
            )
            .await
            .unwrap();
        assert_eq!(active.len(), 1, "only 1 unresolved deferral");
        assert_eq!(active[0].message_id, mids[2]);
    }

    #[tokio::test]
    async fn list_active_filter_by_task_and_window() {
        let (b, svc) = fresh_backend().await;
        let (task_id, thought_id) = seed_parents(&b).await;
        let (task_id_b, thought_id_b) = seed_parents(&b).await;
        // Insert 2 rows under task_id, 1 under task_id_b. All
        // unresolved.
        let mid_a1 = format!("msg-{}", Uuid::new_v4().simple());
        let mid_a2 = format!("msg-{}", Uuid::new_v4().simple());
        let mid_b1 = format!("msg-{}", Uuid::new_v4().simple());
        for (mid, t, th) in [
            (&mid_a1, &task_id, &thought_id),
            (&mid_a2, &task_id, &thought_id),
            (&mid_b1, &task_id_b, &thought_id_b),
        ] {
            svc.record_deferral(mk_report(mid, t, th)).await.unwrap();
        }

        // Filter by task_id.
        let active_a = svc
            .list_active_deferrals(
                DeferralFilter {
                    task_id: Some(task_id.clone()),
                    ..Default::default()
                },
                100,
            )
            .await
            .unwrap();
        assert_eq!(active_a.len(), 2);

        // Filter by created_after in the future — should return 0.
        let active_none = svc
            .list_active_deferrals(
                DeferralFilter {
                    task_id: Some(task_id.clone()),
                    created_after: Some(Utc::now() + chrono::Duration::hours(1)),
                    ..Default::default()
                },
                100,
            )
            .await
            .unwrap();
        assert_eq!(active_none.len(), 0);
    }

    #[tokio::test]
    async fn resolve_missing_returns_false() {
        let (_b, svc) = fresh_backend().await;
        let mid = format!("msg-bogus-{}", Uuid::new_v4().simple());
        let ok = svc.resolve_deferral(&mid, Utc::now(), None).await.unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn resolve_then_get_reflects_resolution() {
        let (b, svc) = fresh_backend().await;
        let (task_id, thought_id) = seed_parents(&b).await;
        let mid = format!("msg-{}", Uuid::new_v4().simple());
        svc.record_deferral(mk_report(&mid, &task_id, &thought_id))
            .await
            .unwrap();
        let resolved_at = Utc::now();
        let ok = svc
            .resolve_deferral(&mid, resolved_at, Some("approved".into()))
            .await
            .unwrap();
        assert!(ok);
        let got = svc.get_deferral(&mid).await.unwrap().expect("present");
        assert!(got.resolved_at.is_some());
        assert_eq!(got.resolution_notes.as_deref(), Some("approved"));
    }
}
