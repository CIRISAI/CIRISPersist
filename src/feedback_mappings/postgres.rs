//! PostgreSQL impl of [`FeedbackMappingService`] (v1.5.18,
//! CIRISPersist#59 #10).
//!
//! 5 columns. Timestamps ride as `chrono::DateTime<Utc>`
//! (TIMESTAMPTZ). Three of five columns are nullable; the FK on
//! `target_thought_id` is DEFERRABLE INITIALLY DEFERRED so a
//! one-tx ceremony writing both the thought + feedback row in
//! either order is supported.
//!
//! `record_feedback` uses `INSERT ... ON CONFLICT (feedback_id) DO
//! NOTHING RETURNING feedback_id` followed by an in-tx `SELECT` so
//! the race-loser reads back the existing row. Same ClaimResult
//! shape as the v1.5.14 deferral_reports + v1.5.16 creation_ceremonies
//! + v1.5.17 continuity_awareness impls.

use super::service::FeedbackMappingService;
use super::types::{FeedbackFilter, FeedbackMapping};
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
        Some(c) if c == SqlState::UNIQUE_VIOLATION => {
            Error::Conflict(format!("{op} UNIQUE: {detail}"))
        }
        Some(c) if c == SqlState::NOT_NULL_VIOLATION => {
            Error::InvalidArgument(format!("{op} NOT NULL: {detail}"))
        }
        Some(c) if c == SqlState::FOREIGN_KEY_VIOLATION => {
            Error::Conflict(format!("{op} FK: {detail}"))
        }
        _ => Error::Backend(format!("{op}: {detail}")),
    }
}

fn validate_feedback(f: &FeedbackMapping) -> Result<(), Error> {
    if f.feedback_id.is_empty() {
        return Err(Error::InvalidArgument("feedback_id required".into()));
    }
    Ok(())
}

fn decode_row(row: &tokio_postgres::Row) -> Result<FeedbackMapping, Error> {
    Ok(FeedbackMapping {
        feedback_id: row
            .try_get("feedback_id")
            .map_err(|e| Error::Backend(format!("decode feedback_id: {e}")))?,
        source_message_id: row
            .try_get("source_message_id")
            .map_err(|e| Error::Backend(format!("decode source_message_id: {e}")))?,
        target_thought_id: row
            .try_get("target_thought_id")
            .map_err(|e| Error::Backend(format!("decode target_thought_id: {e}")))?,
        feedback_type: row
            .try_get("feedback_type")
            .map_err(|e| Error::Backend(format!("decode feedback_type: {e}")))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?,
    })
}

const SELECT_COLUMNS: &str =
    "feedback_id, source_message_id, target_thought_id, feedback_type, created_at";

impl FeedbackMappingService for PostgresBackend {
    async fn record_feedback(
        &self,
        feedback: FeedbackMapping,
    ) -> Result<ClaimResult<FeedbackMapping>, Error> {
        validate_feedback(&feedback)?;
        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin tx: {e}")))?;
        let inserted = tx
            .query_opt(
                "INSERT INTO cirislens.feedback_mappings (\
                    feedback_id, source_message_id, target_thought_id, \
                    feedback_type, created_at\
                 ) VALUES ($1, $2, $3, $4, $5) \
                 ON CONFLICT (feedback_id) DO NOTHING \
                 RETURNING feedback_id",
                &[
                    &feedback.feedback_id,
                    &feedback.source_message_id,
                    &feedback.target_thought_id,
                    &feedback.feedback_type,
                    &feedback.created_at,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_feedback insert"))?;
        let won = inserted.is_some();
        let row = tx
            .query_one(
                &format!(
                    "SELECT {SELECT_COLUMNS} FROM cirislens.feedback_mappings \
                     WHERE feedback_id = $1"
                ),
                &[&feedback.feedback_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_feedback readback"))?;
        let row = decode_row(&row)?;
        tx.commit()
            .await
            .map_err(|e| map_pg_error(e, "record_feedback commit"))?;
        if won {
            Ok(ClaimResult::Stored(row))
        } else {
            Ok(ClaimResult::AlreadyClaimed(row))
        }
    }

    async fn list_feedback_for_thought(
        &self,
        thought_id: &str,
        limit: i64,
    ) -> Result<Vec<FeedbackMapping>, Error> {
        if thought_id.is_empty() {
            return Err(Error::InvalidArgument("thought_id required".into()));
        }
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                &format!(
                    "SELECT {SELECT_COLUMNS} FROM cirislens.feedback_mappings \
                     WHERE target_thought_id = $1 \
                     ORDER BY created_at DESC, feedback_id DESC \
                     LIMIT $2"
                ),
                &[&thought_id, &limit],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_feedback_for_thought"))?;
        let mut items = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_row(row)?);
        }
        Ok(items)
    }

    async fn list_feedback(
        &self,
        filter: FeedbackFilter,
        limit: i64,
    ) -> Result<Vec<FeedbackMapping>, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(src) = filter.source_message_id {
            params.push(Box::new(src));
            where_parts.push(format!("source_message_id = ${}", params.len()));
        }
        if let Some(ftype) = filter.feedback_type {
            params.push(Box::new(ftype));
            where_parts.push(format!("feedback_type = ${}", params.len()));
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
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {} ", where_parts.join(" AND "))
        };
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM cirislens.feedback_mappings \
             {where_sql}\
             ORDER BY created_at DESC, feedback_id DESC \
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
            .map_err(|e| map_pg_error(e, "list_feedback"))?;
        let mut items = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_row(row)?);
        }
        Ok(items)
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

    /// Seed a parent task + parent thought so feedback rows that
    /// carry a `target_thought_id` have an FK target. Returns the
    /// thought id.
    async fn seed_thought(backend: &PostgresBackend) -> String {
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
        thought_id
    }

    fn mk_feedback(thought_id: Option<String>) -> FeedbackMapping {
        let unique = Uuid::new_v4().simple().to_string();
        FeedbackMapping {
            feedback_id: format!("fb-{unique}"),
            source_message_id: Some(format!("msg-{unique}")),
            target_thought_id: thought_id,
            feedback_type: Some("approval".into()),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn feedback_pg_record_round_trip_all_5_columns() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let thought_id = seed_thought(&backend).await;
        let f = mk_feedback(Some(thought_id.clone()));
        let outcome = FeedbackMappingService::record_feedback(&backend, f.clone())
            .await
            .unwrap();
        assert!(matches!(outcome, ClaimResult::Stored(_)));

        let got = FeedbackMappingService::list_feedback_for_thought(&backend, &thought_id, 10)
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        let got = &got[0];
        assert_eq!(got.feedback_id, f.feedback_id);
        assert_eq!(got.source_message_id, f.source_message_id);
        assert_eq!(got.target_thought_id, f.target_thought_id);
        assert_eq!(got.feedback_type, f.feedback_type);
        let drift = (got.created_at - f.created_at).num_seconds().abs();
        assert!(drift <= 1, "created_at preserved: {drift}s drift");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn feedback_pg_record_already_claimed_returns_existing_row() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let thought_id = seed_thought(&backend).await;
        let f1 = mk_feedback(Some(thought_id.clone()));
        let out1 = FeedbackMappingService::record_feedback(&backend, f1.clone())
            .await
            .unwrap();
        assert!(matches!(out1, ClaimResult::Stored(_)));

        // Second record with same feedback_id but different
        // feedback_type — should NOT overwrite.
        let mut f2 = f1.clone();
        f2.feedback_type = Some("correction".into());
        let out2 = FeedbackMappingService::record_feedback(&backend, f2)
            .await
            .unwrap();
        assert!(matches!(out2, ClaimResult::AlreadyClaimed(_)));
        let existing = out2.into_reference();
        assert_eq!(
            existing.feedback_type, f1.feedback_type,
            "loser sees original row"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn feedback_pg_fk_rejects_nonexistent_thought_when_set() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let bogus = format!("thought-bogus-{}", Uuid::new_v4().simple());
        let f = mk_feedback(Some(bogus));
        let res = FeedbackMappingService::record_feedback(&backend, f).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected FK Conflict for dangling target_thought_id, got {res:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn feedback_pg_null_target_thought_passes_fk() {
        // FK only fires for non-NULL values. NULL target_thought_id
        // bypasses the check natively on PG.
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let f = mk_feedback(None);
        let out = FeedbackMappingService::record_feedback(&backend, f.clone())
            .await
            .unwrap();
        assert!(matches!(out, ClaimResult::Stored(_)));
        let stored = out.into_reference();
        assert!(stored.target_thought_id.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn feedback_pg_list_for_thought_returns_3_desc() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let thought_id = seed_thought(&backend).await;
        // Insert 3 feedback rows pointing at the same thought at
        // staggered timestamps.
        let now = Utc::now();
        let mut ids = Vec::new();
        for i in 0..3 {
            let unique = Uuid::new_v4().simple().to_string();
            let f = FeedbackMapping {
                feedback_id: format!("fb-{unique}"),
                source_message_id: Some(format!("msg-{i}")),
                target_thought_id: Some(thought_id.clone()),
                feedback_type: Some(format!("type-{i}")),
                created_at: now - chrono::Duration::hours(2 - i as i64),
            };
            ids.push(f.feedback_id.clone());
            FeedbackMappingService::record_feedback(&backend, f)
                .await
                .unwrap();
        }
        // ids[0] is oldest, ids[2] is newest.

        let got = FeedbackMappingService::list_feedback_for_thought(&backend, &thought_id, 10)
            .await
            .unwrap();
        assert_eq!(got.len(), 3);
        // DESC: newest first.
        assert_eq!(got[0].feedback_id, ids[2]);
        assert_eq!(got[1].feedback_id, ids[1]);
        assert_eq!(got[2].feedback_id, ids[0]);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn feedback_pg_list_filters_by_source_message_type_and_window() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // 3 feedback rows under a unique message-id prefix so this
        // test doesn't pick up siblings from other serial(postgres)
        // tests.
        let unique = Uuid::new_v4().simple().to_string();
        let msg_a = format!("msg-A-{unique}");
        let msg_b = format!("msg-B-{unique}");

        let now = Utc::now();
        let mk = |fid: &str, msg: &str, ftype: &str| FeedbackMapping {
            feedback_id: fid.to_owned(),
            source_message_id: Some(msg.to_owned()),
            target_thought_id: None,
            feedback_type: Some(ftype.to_owned()),
            created_at: now,
        };
        let f_a1 = mk(&format!("fb-a1-{unique}"), &msg_a, "approval");
        let f_a2 = mk(&format!("fb-a2-{unique}"), &msg_a, "correction");
        let f_b1 = mk(&format!("fb-b1-{unique}"), &msg_b, "approval");
        for f in [&f_a1, &f_a2, &f_b1] {
            FeedbackMappingService::record_feedback(&backend, f.clone())
                .await
                .unwrap();
        }

        // Filter by source_message_id = msg_a → 2 rows.
        let by_src = FeedbackMappingService::list_feedback(
            &backend,
            FeedbackFilter {
                source_message_id: Some(msg_a.clone()),
                ..Default::default()
            },
            100,
        )
        .await
        .unwrap();
        assert_eq!(by_src.len(), 2);

        // Filter by feedback_type = approval AND source_message_id =
        // msg_a → 1 row (f_a1).
        let combined = FeedbackMappingService::list_feedback(
            &backend,
            FeedbackFilter {
                source_message_id: Some(msg_a.clone()),
                feedback_type: Some("approval".into()),
                ..Default::default()
            },
            100,
        )
        .await
        .unwrap();
        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].feedback_id, f_a1.feedback_id);

        // Filter by created_after in the future + msg_a → 0 rows.
        let future = FeedbackMappingService::list_feedback(
            &backend,
            FeedbackFilter {
                source_message_id: Some(msg_a.clone()),
                created_after: Some(Utc::now() + chrono::Duration::hours(1)),
                ..Default::default()
            },
            100,
        )
        .await
        .unwrap();
        assert_eq!(future.len(), 0);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn feedback_pg_validate_required_columns() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let mut f = mk_feedback(None);
        f.feedback_id = String::new();
        let res = FeedbackMappingService::record_feedback(&backend, f).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));
    }
}
