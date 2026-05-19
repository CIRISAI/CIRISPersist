//! PostgreSQL impl of [`DeferralReportService`] (v1.5.14,
//! CIRISPersist#59 #6).
//!
//! 7 columns. JSON column `package` rides as `serde_json::Value`
//! (JSONB on the PG side); timestamps cross as
//! `chrono::DateTime<Utc>` (TIMESTAMPTZ). FKs to
//! `cirislens.tasks(task_id)` + `cirislens.thoughts(thought_id)`
//! are both `DEFERRABLE INITIALLY DEFERRED`.
//!
//! Like the v1.5.9 tasks `try_claim_shared_task` pattern,
//! [`DeferralReportService::record_deferral`] uses `INSERT ...
//! ON CONFLICT (message_id) DO NOTHING RETURNING message_id`
//! followed by a `SELECT` on the same tx so the loser caller
//! reads back the existing row.

use chrono::{DateTime, Utc};

use super::service::DeferralReportService;
use super::types::{DeferralFilter, DeferralReport};
use super::Error;
use crate::store::postgres::PostgresBackend;
use crate::ClaimResult;

fn map_pg_error(e: tokio_postgres::Error, op: &str) -> Error {
    use tokio_postgres::error::SqlState;
    let code = e.as_db_error().map(|d| d.code().clone());
    let detail = e
        .as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string());
    match code {
        Some(c) if c == SqlState::CHECK_VIOLATION => {
            Error::InvalidArgument(format!("{op} CHECK: {detail}"))
        }
        Some(c) if c == SqlState::FOREIGN_KEY_VIOLATION => {
            Error::Conflict(format!("{op} FK: {detail}"))
        }
        Some(c) if c == SqlState::UNIQUE_VIOLATION => {
            Error::Conflict(format!("{op} UNIQUE: {detail}"))
        }
        _ => Error::Backend(format!("{op}: {detail}")),
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

fn decode_deferral_row(row: &tokio_postgres::Row) -> Result<DeferralReport, Error> {
    Ok(DeferralReport {
        message_id: row
            .try_get("message_id")
            .map_err(|e| Error::Backend(format!("decode message_id: {e}")))?,
        task_id: row
            .try_get("task_id")
            .map_err(|e| Error::Backend(format!("decode task_id: {e}")))?,
        thought_id: row
            .try_get("thought_id")
            .map_err(|e| Error::Backend(format!("decode thought_id: {e}")))?,
        package: row
            .try_get("package")
            .map_err(|e| Error::Backend(format!("decode package: {e}")))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?,
        resolved_at: row
            .try_get("resolved_at")
            .map_err(|e| Error::Backend(format!("decode resolved_at: {e}")))?,
        resolution_notes: row
            .try_get("resolution_notes")
            .map_err(|e| Error::Backend(format!("decode resolution_notes: {e}")))?,
    })
}

impl DeferralReportService for PostgresBackend {
    async fn record_deferral(
        &self,
        report: DeferralReport,
    ) -> Result<ClaimResult<DeferralReport>, Error> {
        validate_report(&report)?;
        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin tx: {e}")))?;
        // INSERT ... ON CONFLICT (message_id) DO NOTHING — PG
        // suppresses the INSERT on PK conflict; RETURNING is empty
        // on conflict.
        let inserted = tx
            .query_opt(
                "INSERT INTO cirislens.deferral_reports (\
                    message_id, task_id, thought_id, package, \
                    created_at, resolved_at, resolution_notes\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7) \
                 ON CONFLICT (message_id) DO NOTHING \
                 RETURNING message_id",
                &[
                    &report.message_id,
                    &report.task_id,
                    &report.thought_id,
                    &report.package,
                    &report.created_at,
                    &report.resolved_at,
                    &report.resolution_notes,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_deferral insert"))?;
        let won = inserted.is_some();
        // Re-read regardless of outcome so the loser gets the
        // existing row.
        let row = tx
            .query_one(
                "SELECT message_id, task_id, thought_id, package, \
                        created_at, resolved_at, resolution_notes \
                 FROM cirislens.deferral_reports WHERE message_id = $1",
                &[&report.message_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_deferral readback"))?;
        let row = decode_deferral_row(&row)?;
        // FKs are DEFERRABLE INITIALLY DEFERRED so a dangling
        // task_id/thought_id surfaces at COMMIT, not at INSERT.
        // Route the commit error through map_pg_error so
        // FOREIGN_KEY_VIOLATION classifies as Conflict instead of
        // a generic Backend error.
        tx.commit()
            .await
            .map_err(|e| map_pg_error(e, "record_deferral commit"))?;
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
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT message_id, task_id, thought_id, package, \
                        created_at, resolved_at, resolution_notes \
                 FROM cirislens.deferral_reports WHERE message_id = $1",
                &[&message_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_deferral"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_deferral_row(&row)?)),
        }
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
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(task_id) = filter.task_id {
            params.push(Box::new(task_id));
            where_parts.push(format!("task_id = ${}", params.len()));
        }
        if let Some(thought_id) = filter.thought_id {
            params.push(Box::new(thought_id));
            where_parts.push(format!("thought_id = ${}", params.len()));
        }
        if let Some(after) = filter.created_after {
            params.push(Box::new(after));
            where_parts.push(format!("created_at >= ${}", params.len()));
        }
        if let Some(before) = filter.created_before {
            params.push(Box::new(before));
            where_parts.push(format!("created_at <= ${}", params.len()));
        }
        params.push(Box::new(limit));
        let p_limit = params.len();
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT message_id, task_id, thought_id, package, \
                    created_at, resolved_at, resolution_notes \
             FROM cirislens.deferral_reports \
             WHERE {where_sql} \
             ORDER BY created_at DESC, message_id DESC \
             LIMIT ${p_limit}"
        );
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| map_pg_error(e, "list_active_deferrals"))?;
        let mut items: Vec<DeferralReport> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_deferral_row(row)?);
        }
        Ok(items)
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
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let changed = client
            .execute(
                "UPDATE cirislens.deferral_reports SET \
                    resolved_at = $1, \
                    resolution_notes = $2 \
                 WHERE message_id = $3",
                &[&resolved_at, &resolution_notes, &message_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "resolve_deferral"))?;
        Ok(changed > 0)
    }
}

#[cfg(test)]
#[cfg(all(feature = "cirislens_tasks", feature = "cirislens_thoughts"))]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    /// Seed a parent task + parent thought, return `(task_id,
    /// thought_id)` for use on deferral reports.
    async fn seed_parents(backend: &PostgresBackend) -> (String, String) {
        use crate::tasks::types::{Task, TaskStatus};
        use crate::tasks::TaskService;
        use crate::thoughts::types::{Thought, ThoughtStatus, ThoughtType};
        use crate::thoughts::ThoughtService;
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
        TaskService::upsert_task(backend, task).await.unwrap();
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
        ThoughtService::upsert_thought(backend, thought)
            .await
            .unwrap();
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

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn deferral_pg_record_get_round_trip_all_7_columns() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let (task_id, thought_id) = seed_parents(&backend).await;
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
        let outcome = DeferralReportService::record_deferral(&backend, r.clone())
            .await
            .unwrap();
        assert!(matches!(outcome, ClaimResult::Stored(_)));

        let got = backend.get_deferral(&mid).await.unwrap().expect("present");
        assert_eq!(got.message_id, r.message_id);
        assert_eq!(got.task_id, r.task_id);
        assert_eq!(got.thought_id, r.thought_id);
        assert_eq!(got.package, r.package);
        assert!(got.resolved_at.is_none());
        assert!(got.resolution_notes.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn deferral_pg_fk_rejects_nonexistent_task_or_thought() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // No seed_parents — both FKs dangle.
        let mid = format!("msg-{}", Uuid::new_v4().simple());
        let bogus_task = format!("task-bogus-{}", Uuid::new_v4().simple());
        let bogus_thought = format!("thought-bogus-{}", Uuid::new_v4().simple());
        let r = mk_report(&mid, &bogus_task, &bogus_thought);
        let res = DeferralReportService::record_deferral(&backend, r).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected FK Conflict for dangling task+thought, got {res:?}"
        );

        // Seed only the task — thought_id still dangles.
        let (task_id, _thought_id) = seed_parents(&backend).await;
        let mid2 = format!("msg-{}", Uuid::new_v4().simple());
        let bogus_thought2 = format!("thought-bogus-{}", Uuid::new_v4().simple());
        let r2 = mk_report(&mid2, &task_id, &bogus_thought2);
        let res = DeferralReportService::record_deferral(&backend, r2).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected FK Conflict for dangling thought, got {res:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn deferral_pg_record_already_claimed_returns_existing_row() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let (task_id, thought_id) = seed_parents(&backend).await;
        let mid = format!("msg-{}", Uuid::new_v4().simple());
        let r1 = mk_report(&mid, &task_id, &thought_id);
        let out1 = DeferralReportService::record_deferral(&backend, r1.clone())
            .await
            .unwrap();
        assert!(matches!(out1, ClaimResult::Stored(_)));

        // Second record with same message_id but different package —
        // should NOT overwrite. Loser reads back the existing row.
        let mut r2 = r1.clone();
        r2.package = Some(serde_json::json!({"reason": "overwritten?"}));
        let out2 = DeferralReportService::record_deferral(&backend, r2)
            .await
            .unwrap();
        assert!(matches!(out2, ClaimResult::AlreadyClaimed(_)));
        let existing = out2.into_reference();
        assert_eq!(existing.package, r1.package, "loser sees original row");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn deferral_pg_list_active_filters_resolved() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let (task_id, thought_id) = seed_parents(&backend).await;
        // 3 deferrals — record all, then resolve 2 of them.
        let mut mids = Vec::new();
        for _ in 0..3 {
            let mid = format!("msg-{}", Uuid::new_v4().simple());
            mids.push(mid.clone());
            let r = mk_report(&mid, &task_id, &thought_id);
            DeferralReportService::record_deferral(&backend, r)
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        // Resolve the first 2; leave the 3rd active.
        let now = Utc::now();
        assert!(backend
            .resolve_deferral(&mids[0], now, Some("approved".into()))
            .await
            .unwrap());
        assert!(backend
            .resolve_deferral(&mids[1], now, Some("denied".into()))
            .await
            .unwrap());

        // Filter on this test's task_id so we don't pick up rows
        // from other serial tests.
        let active = backend
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
    #[serial_test::serial(postgres)]
    async fn deferral_pg_list_active_filter_by_task_and_window() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let (task_id, thought_id) = seed_parents(&backend).await;
        let (task_id_b, thought_id_b) = seed_parents(&backend).await;
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
            DeferralReportService::record_deferral(&backend, mk_report(mid, t, th))
                .await
                .unwrap();
        }

        // Filter by task_id.
        let active_a = backend
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
        let active_none = backend
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
    #[serial_test::serial(postgres)]
    async fn deferral_pg_resolve_missing_returns_false() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let mid = format!("msg-bogus-{}", Uuid::new_v4().simple());
        let ok = backend
            .resolve_deferral(&mid, Utc::now(), None)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn deferral_pg_resolve_then_get_reflects_resolution() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let (task_id, thought_id) = seed_parents(&backend).await;
        let mid = format!("msg-{}", Uuid::new_v4().simple());
        DeferralReportService::record_deferral(&backend, mk_report(&mid, &task_id, &thought_id))
            .await
            .unwrap();
        let resolved_at = Utc::now();
        let ok = backend
            .resolve_deferral(&mid, resolved_at, Some("approved".into()))
            .await
            .unwrap();
        assert!(ok);
        let got = backend.get_deferral(&mid).await.unwrap().expect("present");
        assert!(got.resolved_at.is_some());
        assert_eq!(got.resolution_notes.as_deref(), Some("approved"));
    }
}
