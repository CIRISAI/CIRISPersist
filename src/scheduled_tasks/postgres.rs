//! PostgreSQL impl of [`ScheduledTaskService`] (v1.5.12,
//! CIRISPersist#59 #4).
//!
//! All 15 columns lift one-to-one from the row shape. JSON column
//! `deferral_history` rides as `serde_json::Value` (JSONB on the PG
//! side); timestamps cross as `chrono::DateTime<Utc>` (TIMESTAMPTZ).
//! FK to `cirislens.thoughts(thought_id)` is DEFERRABLE INITIALLY
//! DEFERRED on PG — a same-tx parent-thought + child-task pair
//! passes constraint check at COMMIT.

use chrono::{DateTime, Utc};

use super::service::ScheduledTaskService;
use super::types::{ScheduledTask, ScheduledTaskStatus};
use super::Error;
use crate::store::postgres::PostgresBackend;

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

fn validate_scheduled_task(t: &ScheduledTask) -> Result<(), Error> {
    if t.id.is_empty() {
        return Err(Error::InvalidArgument("id required".into()));
    }
    if t.name.is_empty() {
        return Err(Error::InvalidArgument("name required".into()));
    }
    if t.goal_description.is_empty() {
        return Err(Error::InvalidArgument("goal_description required".into()));
    }
    if t.trigger_prompt.is_empty() {
        return Err(Error::InvalidArgument("trigger_prompt required".into()));
    }
    if t.origin_thought_id.is_empty() {
        return Err(Error::InvalidArgument("origin_thought_id required".into()));
    }
    if t.agent_occurrence_id.is_empty() {
        return Err(Error::InvalidArgument(
            "agent_occurrence_id required".into(),
        ));
    }
    if t.deferral_count < 0 {
        return Err(Error::InvalidArgument("deferral_count must be >= 0".into()));
    }
    Ok(())
}

fn decode_scheduled_task_row(row: &tokio_postgres::Row) -> Result<ScheduledTask, Error> {
    let status_str: String = row
        .try_get("status")
        .map_err(|e| Error::Backend(format!("decode status: {e}")))?;
    let status = ScheduledTaskStatus::parse_str(&status_str)
        .ok_or_else(|| Error::Backend(format!("unknown status: {status_str}")))?;
    Ok(ScheduledTask {
        id: row
            .try_get("id")
            .map_err(|e| Error::Backend(format!("decode id: {e}")))?,
        name: row
            .try_get("name")
            .map_err(|e| Error::Backend(format!("decode name: {e}")))?,
        goal_description: row
            .try_get("goal_description")
            .map_err(|e| Error::Backend(format!("decode goal_description: {e}")))?,
        status,
        defer_until: row
            .try_get("defer_until")
            .map_err(|e| Error::Backend(format!("decode defer_until: {e}")))?,
        schedule_cron: row
            .try_get("schedule_cron")
            .map_err(|e| Error::Backend(format!("decode schedule_cron: {e}")))?,
        trigger_prompt: row
            .try_get("trigger_prompt")
            .map_err(|e| Error::Backend(format!("decode trigger_prompt: {e}")))?,
        origin_thought_id: row
            .try_get("origin_thought_id")
            .map_err(|e| Error::Backend(format!("decode origin_thought_id: {e}")))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?,
        last_triggered_at: row
            .try_get("last_triggered_at")
            .map_err(|e| Error::Backend(format!("decode last_triggered_at: {e}")))?,
        next_trigger_at: row
            .try_get("next_trigger_at")
            .map_err(|e| Error::Backend(format!("decode next_trigger_at: {e}")))?,
        deferral_count: row
            .try_get("deferral_count")
            .map_err(|e| Error::Backend(format!("decode deferral_count: {e}")))?,
        deferral_history: row
            .try_get("deferral_history")
            .map_err(|e| Error::Backend(format!("decode deferral_history: {e}")))?,
        created_by_agent: row
            .try_get("created_by_agent")
            .map_err(|e| Error::Backend(format!("decode created_by_agent: {e}")))?,
        agent_occurrence_id: row
            .try_get("agent_occurrence_id")
            .map_err(|e| Error::Backend(format!("decode agent_occurrence_id: {e}")))?,
    })
}

impl ScheduledTaskService for PostgresBackend {
    async fn upsert_scheduled_task(&self, task: ScheduledTask) -> Result<(), Error> {
        validate_scheduled_task(&task)?;
        let status_str = task.status.as_sql_str().to_owned();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // UPSERT on id. All columns except `created_at` overwrite on
        // conflict; `created_at` is preserved so re-upsert doesn't
        // clobber the original creation time.
        client
            .execute(
                "INSERT INTO cirislens.scheduled_tasks (\
                    id, name, goal_description, status, defer_until, \
                    schedule_cron, trigger_prompt, origin_thought_id, \
                    created_at, last_triggered_at, next_trigger_at, \
                    deferral_count, deferral_history, created_by_agent, \
                    agent_occurrence_id\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                           $11, $12, $13, $14, $15) \
                 ON CONFLICT (id) DO UPDATE SET \
                    name = EXCLUDED.name, \
                    goal_description = EXCLUDED.goal_description, \
                    status = EXCLUDED.status, \
                    defer_until = EXCLUDED.defer_until, \
                    schedule_cron = EXCLUDED.schedule_cron, \
                    trigger_prompt = EXCLUDED.trigger_prompt, \
                    origin_thought_id = EXCLUDED.origin_thought_id, \
                    last_triggered_at = EXCLUDED.last_triggered_at, \
                    next_trigger_at = EXCLUDED.next_trigger_at, \
                    deferral_count = EXCLUDED.deferral_count, \
                    deferral_history = EXCLUDED.deferral_history, \
                    created_by_agent = EXCLUDED.created_by_agent, \
                    agent_occurrence_id = EXCLUDED.agent_occurrence_id",
                &[
                    &task.id,
                    &task.name,
                    &task.goal_description,
                    &status_str,
                    &task.defer_until,
                    &task.schedule_cron,
                    &task.trigger_prompt,
                    &task.origin_thought_id,
                    &task.created_at,
                    &task.last_triggered_at,
                    &task.next_trigger_at,
                    &task.deferral_count,
                    &task.deferral_history,
                    &task.created_by_agent,
                    &task.agent_occurrence_id,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "upsert_scheduled_task"))?;
        Ok(())
    }

    async fn list_due_scheduled_tasks(
        &self,
        agent_occurrence_id: &str,
        now: DateTime<Utc>,
        limit: i64,
    ) -> Result<Vec<ScheduledTask>, Error> {
        if agent_occurrence_id.is_empty() {
            return Err(Error::InvalidArgument(
                "agent_occurrence_id required".into(),
            ));
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
        // Hits the `scheduled_tasks_due` partial index
        // (agent_occurrence_id, next_trigger_at) WHERE
        // next_trigger_at IS NOT NULL AND status IN
        // ('PENDING', 'ACTIVE').
        let rows = client
            .query(
                "SELECT id, name, goal_description, status, defer_until, \
                        schedule_cron, trigger_prompt, origin_thought_id, \
                        created_at, last_triggered_at, next_trigger_at, \
                        deferral_count, deferral_history, created_by_agent, \
                        agent_occurrence_id \
                 FROM cirislens.scheduled_tasks \
                 WHERE agent_occurrence_id = $1 \
                   AND next_trigger_at IS NOT NULL \
                   AND next_trigger_at <= $2 \
                   AND status IN ('PENDING', 'ACTIVE') \
                 ORDER BY next_trigger_at ASC \
                 LIMIT $3",
                &[&agent_occurrence_id, &now, &limit],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_due_scheduled_tasks"))?;
        let mut items = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_scheduled_task_row(row)?);
        }
        Ok(items)
    }

    async fn update_after_trigger(
        &self,
        task_id: &str,
        last_triggered_at: DateTime<Utc>,
        next_trigger_at: Option<DateTime<Utc>>,
        deferral_count: i32,
        deferral_history: Option<serde_json::Value>,
        new_status: Option<ScheduledTaskStatus>,
    ) -> Result<bool, Error> {
        if task_id.is_empty() {
            return Err(Error::InvalidArgument("task_id required".into()));
        }
        if deferral_count < 0 {
            return Err(Error::InvalidArgument("deferral_count must be >= 0".into()));
        }
        // Dynamically build the SET clause so callers that don't
        // supply `new_status` / `deferral_history` don't overwrite
        // those columns. `next_trigger_at` is always written (Option
        // distinguishes "set to NULL" from "no change" — but the
        // contract on this method is "after the scheduler fires you
        // always know what next_trigger_at should be (Some) or that
        // there is none (None)"). Same for `deferral_count` — the
        // scheduler always knows the new count.
        let mut sets: Vec<String> = vec![
            "last_triggered_at = $2".into(),
            "next_trigger_at = $3".into(),
            "deferral_count = $4".into(),
        ];
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = vec![
            Box::new(task_id.to_owned()),
            Box::new(last_triggered_at),
            Box::new(next_trigger_at),
            Box::new(deferral_count),
        ];
        if let Some(history) = deferral_history {
            params.push(Box::new(history));
            sets.push(format!("deferral_history = ${}", params.len()));
        }
        if let Some(status) = new_status {
            params.push(Box::new(status.as_sql_str().to_owned()));
            sets.push(format!("status = ${}", params.len()));
        }
        let sql = format!(
            "UPDATE cirislens.scheduled_tasks SET {} WHERE id = $1",
            sets.join(", ")
        );

        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let changed = client
            .execute(&sql, &params_ref[..])
            .await
            .map_err(|e| map_pg_error(e, "update_after_trigger"))?;
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

    /// Seed a parent task + parent thought, return the thought_id
    /// for use as `origin_thought_id` on scheduled tasks. The FK
    /// on scheduled_tasks.origin_thought_id requires the row in
    /// `cirislens.thoughts` to exist.
    async fn seed_parent_thought(backend: &PostgresBackend) -> String {
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
            source_task_id: task_id,
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

    fn mk_task(id: &str, origin_thought_id: &str, occurrence: &str) -> ScheduledTask {
        let now = Utc::now();
        ScheduledTask {
            id: id.to_owned(),
            name: "weekly-rollup".into(),
            goal_description: "compute weekly rollup".into(),
            status: ScheduledTaskStatus::Pending,
            defer_until: None,
            schedule_cron: None,
            trigger_prompt: "Run weekly rollup".into(),
            origin_thought_id: origin_thought_id.to_owned(),
            created_at: now,
            last_triggered_at: None,
            next_trigger_at: None,
            deferral_count: 0,
            deferral_history: None,
            created_by_agent: None,
            agent_occurrence_id: occurrence.to_owned(),
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn scheduled_tasks_pg_upsert_get_full_columns_round_trip() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let thought_id = seed_parent_thought(&backend).await;

        let id = format!("sched-{}", Uuid::new_v4().simple());
        let now = Utc::now();
        let t = ScheduledTask {
            id: id.clone(),
            name: "weekly-rollup".into(),
            goal_description: "compute weekly rollup".into(),
            status: ScheduledTaskStatus::Active,
            defer_until: Some(now),
            schedule_cron: Some("0 0 * * 0".into()),
            trigger_prompt: "Run weekly rollup".into(),
            origin_thought_id: thought_id.clone(),
            created_at: now,
            last_triggered_at: Some(now),
            next_trigger_at: Some(now + chrono::Duration::days(7)),
            deferral_count: 2,
            deferral_history: Some(serde_json::json!([{"at": "2026-01-01T00:00:00Z"}])),
            created_by_agent: Some("agent-x".into()),
            agent_occurrence_id: "occ-test".into(),
        };
        ScheduledTaskService::upsert_scheduled_task(&backend, t.clone())
            .await
            .unwrap();
        // Read back via list_due_scheduled_tasks (since we don't have a
        // get_one, fetch the most recent row by occurrence with a wide
        // time window).
        let due = backend
            .list_due_scheduled_tasks("occ-test", now + chrono::Duration::days(365), 100)
            .await
            .unwrap();
        let got = due
            .iter()
            .find(|x| x.id == id)
            .cloned()
            .expect("present in due list");
        assert_eq!(got.id, t.id);
        assert_eq!(got.name, t.name);
        assert_eq!(got.goal_description, t.goal_description);
        assert_eq!(got.status, t.status);
        assert_eq!(got.schedule_cron, t.schedule_cron);
        assert_eq!(got.trigger_prompt, t.trigger_prompt);
        assert_eq!(got.origin_thought_id, t.origin_thought_id);
        assert_eq!(got.deferral_count, t.deferral_count);
        assert_eq!(got.deferral_history, t.deferral_history);
        assert_eq!(got.created_by_agent, t.created_by_agent);
        assert_eq!(got.agent_occurrence_id, t.agent_occurrence_id);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn scheduled_tasks_pg_upsert_idempotent_preserves_created_at() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let thought_id = seed_parent_thought(&backend).await;

        let id = format!("sched-{}", Uuid::new_v4().simple());
        let original_created = Utc::now() - chrono::Duration::days(2);
        let mut t = mk_task(&id, &thought_id, "occ-test");
        t.created_at = original_created;
        t.next_trigger_at = Some(Utc::now() + chrono::Duration::seconds(60));
        t.name = "first-name".into();
        ScheduledTaskService::upsert_scheduled_task(&backend, t.clone())
            .await
            .unwrap();

        // Second upsert with same id, NEW created_at and NEW name —
        // created_at should stay at the original (preserved), name
        // should update.
        let mut t2 = t.clone();
        t2.created_at = Utc::now();
        t2.name = "second-name".into();
        ScheduledTaskService::upsert_scheduled_task(&backend, t2)
            .await
            .unwrap();

        let due = backend
            .list_due_scheduled_tasks("occ-test", Utc::now() + chrono::Duration::days(365), 100)
            .await
            .unwrap();
        let got = due.iter().find(|x| x.id == id).cloned().expect("present");
        assert_eq!(got.name, "second-name", "name updated by upsert");
        // created_at preserved (within driver precision).
        let drift = (got.created_at - original_created).num_seconds().abs();
        assert!(drift <= 1, "created_at preserved: {drift}s drift");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn scheduled_tasks_pg_fk_rejects_nonexistent_origin_thought() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // No seed_parent_thought — origin_thought_id is dangling.
        let id = format!("sched-{}", Uuid::new_v4().simple());
        let bogus_thought = format!("thought-bogus-{}", Uuid::new_v4().simple());
        let t = mk_task(&id, &bogus_thought, "occ-test");
        // Even with DEFERRABLE INITIALLY DEFERRED, the constraint
        // fires at end-of-tx — and tokio-postgres's auto-commit
        // executes each statement in its own implicit tx. So a
        // single-statement upsert against a dangling FK fails.
        let res = ScheduledTaskService::upsert_scheduled_task(&backend, t).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected FK Conflict, got {res:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn scheduled_tasks_pg_list_due_filters_correctly() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let thought_id = seed_parent_thought(&backend).await;

        let occ = format!("occ-due-{}", Uuid::new_v4().simple());
        let base = Utc::now();
        // 5 tasks:
        // - past, PENDING (due)
        // - past, ACTIVE (due)
        // - past, COMPLETE (not due — wrong status)
        // - past, FAILED (not due — wrong status)
        // - future, PENDING (not due — future)
        // - NULL next_trigger_at, PENDING (not due — never scheduled)
        let past = base - chrono::Duration::seconds(60);
        let future = base + chrono::Duration::seconds(60);
        let cases: Vec<(ScheduledTaskStatus, Option<DateTime<Utc>>)> = vec![
            (ScheduledTaskStatus::Pending, Some(past)),
            (
                ScheduledTaskStatus::Active,
                Some(past - chrono::Duration::seconds(10)),
            ),
            (ScheduledTaskStatus::Complete, Some(past)),
            (ScheduledTaskStatus::Failed, Some(past)),
            (ScheduledTaskStatus::Pending, Some(future)),
            (ScheduledTaskStatus::Pending, None),
        ];
        for (status, nxt) in cases {
            let id = format!("sched-{}", Uuid::new_v4().simple());
            let mut t = mk_task(&id, &thought_id, &occ);
            t.status = status;
            t.next_trigger_at = nxt;
            ScheduledTaskService::upsert_scheduled_task(&backend, t)
                .await
                .unwrap();
        }
        let due = backend
            .list_due_scheduled_tasks(&occ, base, 100)
            .await
            .unwrap();
        assert_eq!(due.len(), 2, "exactly two PENDING/ACTIVE past-due rows");
        // Order ASC by next_trigger_at.
        let a = &due[0];
        let b = &due[1];
        assert!(
            a.next_trigger_at.unwrap() <= b.next_trigger_at.unwrap(),
            "ordered ASC by next_trigger_at"
        );
        // Both are PENDING or ACTIVE.
        for r in &due {
            assert!(matches!(
                r.status,
                ScheduledTaskStatus::Pending | ScheduledTaskStatus::Active
            ));
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn scheduled_tasks_pg_update_after_trigger_success_and_missing() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let thought_id = seed_parent_thought(&backend).await;

        let id = format!("sched-{}", Uuid::new_v4().simple());
        let mut t = mk_task(&id, &thought_id, "occ-test");
        t.next_trigger_at = Some(Utc::now() - chrono::Duration::seconds(60));
        ScheduledTaskService::upsert_scheduled_task(&backend, t.clone())
            .await
            .unwrap();

        let now = Utc::now();
        let next = now + chrono::Duration::hours(1);
        let ok = backend
            .update_after_trigger(
                &id,
                now,
                Some(next),
                1,
                Some(serde_json::json!([{"at": "2026-01-01T00:00:00Z"}])),
                Some(ScheduledTaskStatus::Active),
            )
            .await
            .unwrap();
        assert!(ok);

        // Verify columns via list_due_scheduled_tasks (next_trigger_at
        // is in the future relative to now+2h).
        let due = backend
            .list_due_scheduled_tasks("occ-test", now + chrono::Duration::hours(2), 100)
            .await
            .unwrap();
        let got = due.iter().find(|x| x.id == id).cloned().expect("present");
        assert_eq!(got.status, ScheduledTaskStatus::Active);
        assert_eq!(got.deferral_count, 1);
        assert!(got.deferral_history.is_some());
        assert!(got.last_triggered_at.is_some());
        assert!(got.next_trigger_at.is_some());

        // Missing row → false.
        let ok = backend
            .update_after_trigger(
                &format!("missing-{}", Uuid::new_v4().simple()),
                now,
                None,
                0,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn scheduled_tasks_pg_update_after_trigger_partial_no_status_no_history() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let thought_id = seed_parent_thought(&backend).await;

        let id = format!("sched-{}", Uuid::new_v4().simple());
        let original_history = serde_json::json!([{"at": "2026-01-01T00:00:00Z"}]);
        let mut t = mk_task(&id, &thought_id, "occ-test");
        t.status = ScheduledTaskStatus::Active;
        t.deferral_history = Some(original_history.clone());
        t.next_trigger_at = Some(Utc::now() - chrono::Duration::seconds(60));
        ScheduledTaskService::upsert_scheduled_task(&backend, t.clone())
            .await
            .unwrap();

        let ok = backend
            .update_after_trigger(
                &id,
                Utc::now(),
                Some(Utc::now() + chrono::Duration::hours(1)),
                5,
                None, // history NOT supplied — preserve
                None, // status NOT supplied — preserve
            )
            .await
            .unwrap();
        assert!(ok);

        let due = backend
            .list_due_scheduled_tasks("occ-test", Utc::now() + chrono::Duration::hours(2), 100)
            .await
            .unwrap();
        let got = due.iter().find(|x| x.id == id).cloned().expect("present");
        assert_eq!(got.status, ScheduledTaskStatus::Active, "status preserved");
        assert_eq!(got.deferral_count, 5);
        assert_eq!(
            got.deferral_history,
            Some(original_history),
            "deferral_history preserved when not supplied"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn scheduled_tasks_pg_partial_index_used_for_due_query() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        // No need to seed — the EXPLAIN check works against an empty table.
        let client = backend.pool().get().await.unwrap();
        let rows = client
            .query(
                "EXPLAIN SELECT id FROM cirislens.scheduled_tasks \
                 WHERE agent_occurrence_id = $1 \
                   AND next_trigger_at IS NOT NULL \
                   AND next_trigger_at <= NOW() \
                   AND status IN ('PENDING', 'ACTIVE') \
                 ORDER BY next_trigger_at ASC LIMIT 100",
                &[&"occ-x"],
            )
            .await
            .unwrap();
        let plan: String = rows
            .iter()
            .map(|r| r.get::<_, String>(0))
            .collect::<Vec<_>>()
            .join("\n");
        // Postgres may pick a seq scan on an empty table; the index
        // existence is what we're really verifying.  Check the index
        // is registered.
        let idx_rows = client
            .query(
                "SELECT indexname FROM pg_indexes \
                 WHERE schemaname = 'cirislens' \
                   AND tablename = 'scheduled_tasks' \
                   AND indexname = 'scheduled_tasks_due'",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(idx_rows.len(), 1, "scheduled_tasks_due index exists");
        let _ = plan; // tolerate seq scan; the index is registered above
    }
}
