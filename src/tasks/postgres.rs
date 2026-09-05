//! PostgreSQL impl of [`TaskService`] (v1.5.9, CIRISPersist#59 #1).
//!
//! All 18 columns lift one-to-one from the row shape. JSON columns
//! ride across the wire as `serde_json::Value` (JSONB on the PG
//! side); timestamps cross as `chrono::DateTime<Utc>` (TIMESTAMPTZ);
//! booleans as native `bool`. Self-FK on `parent_task_id` is
//! DEFERRABLE INITIALLY DEFERRED (V024) so bulk INSERT of a parent +
//! child in the same tx passes constraint check at COMMIT.

use super::service::TaskService;
use super::types::{Task, TaskCursor, TaskFilter, TaskListPage, TaskStatus, TaskUpsertOutcome};
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

fn validate_task(t: &Task) -> Result<(), Error> {
    if t.task_id.is_empty() {
        return Err(Error::InvalidArgument("task_id required".into()));
    }
    if t.channel_id.is_empty() {
        return Err(Error::InvalidArgument("channel_id required".into()));
    }
    if t.description.is_empty() {
        return Err(Error::InvalidArgument("description required".into()));
    }
    if t.agent_occurrence_id.is_empty() {
        return Err(Error::InvalidArgument(
            "agent_occurrence_id required".into(),
        ));
    }
    if t.retry_count < 0 {
        return Err(Error::InvalidArgument(format!(
            "retry_count must be >= 0, got {}",
            t.retry_count
        )));
    }
    Ok(())
}

fn decode_task_row(row: &tokio_postgres::Row) -> Result<Task, Error> {
    let status_str: String = row
        .try_get("status")
        .map_err(|e| Error::Backend(format!("decode status: {e}")))?;
    let status = TaskStatus::parse_str(&status_str)
        .ok_or_else(|| Error::Backend(format!("unknown status: {status_str}")))?;
    Ok(Task {
        task_id: row
            .try_get("task_id")
            .map_err(|e| Error::Backend(format!("decode task_id: {e}")))?,
        channel_id: row
            .try_get("channel_id")
            .map_err(|e| Error::Backend(format!("decode channel_id: {e}")))?,
        description: row
            .try_get("description")
            .map_err(|e| Error::Backend(format!("decode description: {e}")))?,
        status,
        priority: row
            .try_get("priority")
            .map_err(|e| Error::Backend(format!("decode priority: {e}")))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|e| Error::Backend(format!("decode updated_at: {e}")))?,
        parent_task_id: row
            .try_get("parent_task_id")
            .map_err(|e| Error::Backend(format!("decode parent_task_id: {e}")))?,
        context: row
            .try_get("context_json")
            .map_err(|e| Error::Backend(format!("decode context_json: {e}")))?,
        outcome: row
            .try_get("outcome_json")
            .map_err(|e| Error::Backend(format!("decode outcome_json: {e}")))?,
        retry_count: row
            .try_get("retry_count")
            .map_err(|e| Error::Backend(format!("decode retry_count: {e}")))?,
        signed_by: row
            .try_get("signed_by")
            .map_err(|e| Error::Backend(format!("decode signed_by: {e}")))?,
        signature: row
            .try_get("signature")
            .map_err(|e| Error::Backend(format!("decode signature: {e}")))?,
        signed_at: row
            .try_get("signed_at")
            .map_err(|e| Error::Backend(format!("decode signed_at: {e}")))?,
        updated_info_available: row
            .try_get("updated_info_available")
            .map_err(|e| Error::Backend(format!("decode updated_info_available: {e}")))?,
        updated_info_content: row
            .try_get("updated_info_content")
            .map_err(|e| Error::Backend(format!("decode updated_info_content: {e}")))?,
        agent_occurrence_id: row
            .try_get("agent_occurrence_id")
            .map_err(|e| Error::Backend(format!("decode agent_occurrence_id: {e}")))?,
        images: row
            .try_get("images_json")
            .map_err(|e| Error::Backend(format!("decode images_json: {e}")))?,
    })
}

/// Extract the `context.correlation_id` string from the task's
/// `context_json`. Returns `Some(id)` only when the field is present
/// and a non-empty string (matches the V036 partial-index WHERE
/// clause).
fn correlation_id_from_task(task: &Task) -> Option<&str> {
    let ctx = task.context.as_ref()?;
    ctx.get("correlation_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

impl TaskService for PostgresBackend {
    async fn upsert_task(&self, task: Task) -> Result<TaskUpsertOutcome, Error> {
        validate_task(&task)?;
        let status_str = task.status.as_sql_str().to_owned();
        let correlation_id = correlation_id_from_task(&task).map(str::to_owned);
        let agent_occurrence = task.agent_occurrence_id.clone();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let insert_res = client
            .execute(
                "INSERT INTO cirislens.tasks (\
                    task_id, channel_id, description, status, priority, \
                    created_at, updated_at, parent_task_id, context_json, outcome_json, \
                    retry_count, signed_by, signature, signed_at, \
                    updated_info_available, updated_info_content, \
                    agent_occurrence_id, images_json\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                           $15, $16, $17, $18) \
                 ON CONFLICT (task_id) DO UPDATE SET \
                    channel_id = EXCLUDED.channel_id, \
                    created_at = EXCLUDED.created_at, \
                    description = EXCLUDED.description, \
                    status = EXCLUDED.status, \
                    priority = EXCLUDED.priority, \
                    updated_at = EXCLUDED.updated_at, \
                    parent_task_id = EXCLUDED.parent_task_id, \
                    context_json = EXCLUDED.context_json, \
                    outcome_json = EXCLUDED.outcome_json, \
                    retry_count = EXCLUDED.retry_count, \
                    signed_by = EXCLUDED.signed_by, \
                    signature = EXCLUDED.signature, \
                    signed_at = EXCLUDED.signed_at, \
                    updated_info_available = EXCLUDED.updated_info_available, \
                    updated_info_content = EXCLUDED.updated_info_content, \
                    agent_occurrence_id = EXCLUDED.agent_occurrence_id, \
                    images_json = EXCLUDED.images_json",
                &[
                    &task.task_id,
                    &task.channel_id,
                    &task.description,
                    &status_str,
                    &task.priority,
                    &task.created_at,
                    &task.updated_at,
                    &task.parent_task_id,
                    &task.context,
                    &task.outcome,
                    &task.retry_count,
                    &task.signed_by,
                    &task.signature,
                    &task.signed_at,
                    &task.updated_info_available,
                    &task.updated_info_content,
                    &task.agent_occurrence_id,
                    &task.images,
                ],
            )
            .await;
        match insert_res {
            Ok(_) => {
                // Re-read the row so callers always get the canonical
                // post-upsert shape (matters for the ON CONFLICT path
                // where some columns differ from the caller's input).
                let row = client
                    .query_one(
                        "SELECT task_id, channel_id, description, status, priority, \
                                created_at, updated_at, parent_task_id, context_json, outcome_json, \
                                retry_count, signed_by, signature, signed_at, \
                                updated_info_available, updated_info_content, \
                                agent_occurrence_id, images_json \
                         FROM cirislens.tasks WHERE task_id = $1",
                        &[&task.task_id],
                    )
                    .await
                    .map_err(|e| map_pg_error(e, "upsert_task readback"))?;
                Ok(TaskUpsertOutcome::Stored(decode_task_row(&row)?))
            }
            Err(e) => {
                // V036 correlation-id unique violation → dedup path.
                // Identify by SqlState UNIQUE_VIOLATION + constraint
                // name `tasks_correlation_id_unique`. Anything else
                // (including PK conflict, which would never reach
                // here since ON CONFLICT(task_id) handles it) bubbles
                // up as Conflict/Backend per map_pg_error.
                let is_correlation_conflict = e
                    .as_db_error()
                    .map(|d| {
                        d.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION
                            && d.constraint() == Some("tasks_correlation_id_unique")
                    })
                    .unwrap_or(false);
                if is_correlation_conflict {
                    let Some(cid) = correlation_id else {
                        // Theoretical: unique-constraint fired with no
                        // correlation_id → schema invariant broken.
                        return Err(Error::Backend(format!(
                            "upsert_task: tasks_correlation_id_unique fired with no correlation_id: {e}"
                        )));
                    };
                    let row = client
                        .query_one(
                            "SELECT task_id, channel_id, description, status, priority, \
                                    created_at, updated_at, parent_task_id, context_json, outcome_json, \
                                    retry_count, signed_by, signature, signed_at, \
                                    updated_info_available, updated_info_content, \
                                    agent_occurrence_id, images_json \
                             FROM cirislens.tasks \
                             WHERE agent_occurrence_id = $1 \
                               AND context_json->>'correlation_id' = $2",
                            &[&agent_occurrence, &cid],
                        )
                        .await
                        .map_err(|e| map_pg_error(e, "upsert_task correlation readback"))?;
                    Ok(TaskUpsertOutcome::AlreadyExists(decode_task_row(&row)?))
                } else {
                    Err(map_pg_error(e, "upsert_task"))
                }
            }
        }
    }

    async fn get_task(&self, task_id: &str) -> Result<Option<Task>, Error> {
        if task_id.is_empty() {
            return Err(Error::InvalidArgument("task_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT task_id, channel_id, description, status, priority, \
                        created_at, updated_at, parent_task_id, context_json, outcome_json, \
                        retry_count, signed_by, signature, signed_at, \
                        updated_info_available, updated_info_content, \
                        agent_occurrence_id, images_json \
                 FROM cirislens.tasks WHERE task_id = $1",
                &[&task_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_task"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_task_row(&row)?)),
        }
    }

    async fn list_tasks(
        &self,
        filter: TaskFilter,
        cursor: Option<TaskCursor>,
        limit: i64,
    ) -> Result<TaskListPage, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(occ) = filter.agent_occurrence_id {
            params.push(Box::new(occ));
            where_parts.push(format!("agent_occurrence_id = ${}", params.len()));
        }
        if let Some(status) = filter.status {
            params.push(Box::new(status.as_sql_str().to_owned()));
            where_parts.push(format!("status = ${}", params.len()));
        }
        if let Some(ch) = filter.channel_id {
            params.push(Box::new(ch));
            where_parts.push(format!("channel_id = ${}", params.len()));
        }
        if let Some(parent) = filter.parent_task_id {
            params.push(Box::new(parent));
            where_parts.push(format!("parent_task_id = ${}", params.len()));
        }
        if let Some(after) = filter.updated_after {
            params.push(Box::new(after));
            where_parts.push(format!("updated_at >= ${}", params.len()));
        }
        if let Some(before) = filter.updated_before {
            params.push(Box::new(before));
            where_parts.push(format!("updated_at <= ${}", params.len()));
        }
        if let Some(before) = filter.created_before {
            params.push(Box::new(before));
            where_parts.push(format!("created_at < ${}", params.len()));
        }
        if let Some(after) = filter.created_after {
            params.push(Box::new(after));
            where_parts.push(format!("created_at >= ${}", params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "TaskCursor version {} unsupported",
                    cur.version
                )));
            }
            params.push(Box::new(cur.last_ts));
            let p_ts = params.len();
            params.push(Box::new(cur.last_id.clone()));
            let p_id = params.len();
            where_parts.push(format!("(updated_at, task_id) < (${p_ts}, ${p_id})"));
        }
        params.push(Box::new(limit));
        let p_limit = params.len();
        let where_sql = if where_parts.is_empty() {
            "TRUE".to_string()
        } else {
            where_parts.join(" AND ")
        };
        let sql = format!(
            "SELECT task_id, channel_id, description, status, priority, \
                    created_at, updated_at, parent_task_id, context_json, outcome_json, \
                    retry_count, signed_by, signature, signed_at, \
                    updated_info_available, updated_info_content, \
                    agent_occurrence_id, images_json \
             FROM cirislens.tasks \
             WHERE {where_sql} \
             ORDER BY updated_at DESC, task_id DESC \
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
            .map_err(|e| map_pg_error(e, "list_tasks"))?;
        let mut items: Vec<Task> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_task_row(row)?);
        }
        let next_cursor = if items.len() == limit as usize {
            items
                .last()
                .map(|last| TaskCursor::from_trailing(last.updated_at, last.task_id.clone()))
        } else {
            None
        };
        Ok(TaskListPage { items, next_cursor })
    }

    async fn update_task_status(
        &self,
        task_id: &str,
        new_status: TaskStatus,
        outcome: Option<serde_json::Value>,
    ) -> Result<bool, Error> {
        if task_id.is_empty() {
            return Err(Error::InvalidArgument("task_id required".into()));
        }
        let status_str = new_status.as_sql_str().to_owned();
        let now = chrono::Utc::now();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let changed = client
            .execute(
                "UPDATE cirislens.tasks SET \
                    status = $1, \
                    updated_at = $2, \
                    outcome_json = COALESCE($3, outcome_json) \
                 WHERE task_id = $4",
                &[&status_str, &now, &outcome, &task_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "update_task_status"))?;
        Ok(changed > 0)
    }

    async fn try_claim_shared_task(&self, task: Task) -> Result<ClaimResult<Task>, Error> {
        validate_task(&task)?;
        let status_str = task.status.as_sql_str().to_owned();
        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin tx: {e}")))?;
        // INSERT ... ON CONFLICT (task_id) DO NOTHING — PG suppresses
        // the INSERT on PK conflict and reports 0 changes via the
        // RETURNING-clause being empty.
        let inserted = tx
            .query_opt(
                "INSERT INTO cirislens.tasks (\
                    task_id, channel_id, description, status, priority, \
                    created_at, updated_at, parent_task_id, context_json, outcome_json, \
                    retry_count, signed_by, signature, signed_at, \
                    updated_info_available, updated_info_content, \
                    agent_occurrence_id, images_json\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                           $15, $16, $17, $18) \
                 ON CONFLICT (task_id) DO NOTHING \
                 RETURNING task_id",
                &[
                    &task.task_id,
                    &task.channel_id,
                    &task.description,
                    &status_str,
                    &task.priority,
                    &task.created_at,
                    &task.updated_at,
                    &task.parent_task_id,
                    &task.context,
                    &task.outcome,
                    &task.retry_count,
                    &task.signed_by,
                    &task.signature,
                    &task.signed_at,
                    &task.updated_info_available,
                    &task.updated_info_content,
                    &task.agent_occurrence_id,
                    &task.images,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "try_claim_shared_task insert"))?;
        let won = inserted.is_some();

        // Re-read regardless of outcome so loser gets the existing
        // row.
        let row = tx
            .query_one(
                "SELECT task_id, channel_id, description, status, priority, \
                        created_at, updated_at, parent_task_id, context_json, outcome_json, \
                        retry_count, signed_by, signature, signed_at, \
                        updated_info_available, updated_info_content, \
                        agent_occurrence_id, images_json \
                 FROM cirislens.tasks WHERE task_id = $1",
                &[&task.task_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "try_claim_shared_task readback"))?;
        let row = decode_task_row(&row)?;
        tx.commit()
            .await
            .map_err(|e| Error::Backend(format!("commit: {e}")))?;
        if won {
            Ok(ClaimResult::Stored(row))
        } else {
            Ok(ClaimResult::AlreadyClaimed(row))
        }
    }

    async fn delete_task(&self, task_id: &str) -> Result<bool, Error> {
        if task_id.is_empty() {
            return Err(Error::InvalidArgument("task_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let changed = client
            .execute(
                "DELETE FROM cirislens.tasks WHERE task_id = $1",
                &[&task_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "delete_task"))?;
        Ok(changed > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        crate::test_pg::dsn()
    }

    fn mk_task(id: &str, status: TaskStatus, occurrence: &str) -> Task {
        let now = Utc::now();
        Task {
            task_id: id.to_owned(),
            channel_id: "chan-default".into(),
            description: format!("desc-{id}"),
            status,
            priority: 0,
            created_at: now,
            updated_at: now,
            parent_task_id: None,
            context: None,
            outcome: None,
            retry_count: 0,
            signed_by: None,
            signature: None,
            signed_at: None,
            updated_info_available: false,
            updated_info_content: None,
            agent_occurrence_id: occurrence.to_owned(),
            images: None,
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_upsert_get_full_columns_round_trip() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let parent_id = format!("p-{}", Uuid::new_v4().simple());
        let child_id = format!("c-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&parent_id, TaskStatus::Pending, "occ-1"))
            .await
            .unwrap();

        let now = Utc::now();
        let task = Task {
            task_id: child_id.clone(),
            channel_id: "chan-x".into(),
            description: "do the thing".into(),
            status: TaskStatus::Active,
            priority: 7,
            created_at: now,
            updated_at: now,
            parent_task_id: Some(parent_id.clone()),
            context: Some(serde_json::json!({"k": "v"})),
            outcome: Some(serde_json::json!({"ok": true})),
            retry_count: 2,
            signed_by: Some("agent-key".into()),
            signature: Some("sig==".into()),
            signed_at: Some(now),
            updated_info_available: true,
            updated_info_content: Some("see addendum".into()),
            agent_occurrence_id: "occ-1".into(),
            images: Some(serde_json::json!(["sha:aaa"])),
        };
        TaskService::upsert_task(&backend, task.clone())
            .await
            .unwrap();
        let got = backend.get_task(&child_id).await.unwrap().expect("present");
        assert_eq!(got.task_id, task.task_id);
        assert_eq!(got.status, task.status);
        assert_eq!(got.priority, task.priority);
        assert_eq!(got.context, task.context);
        assert_eq!(got.outcome, task.outcome);
        assert_eq!(got.retry_count, task.retry_count);
        assert_eq!(got.updated_info_available, task.updated_info_available);
        assert_eq!(got.images, task.images);
        assert_eq!(got.parent_task_id, Some(parent_id));
    }

    /// v41.2.0 (CIRISPersist#810, CIRISAgent#1077) — the SQLite twin of
    /// `every_agent_status_survives_all_three_doors_810`, on the backend
    /// production actually runs. V136 widens the CHECK by DROP/ADD
    /// CONSTRAINT here rather than by rebuild, so this is a genuinely
    /// different mechanism reaching the same admission, not the same code
    /// exercised twice.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_every_agent_status_survives_all_three_doors_810() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let occ = format!("occ-{}", Uuid::new_v4().simple());

        for wire in [
            "pending",
            "active",
            "completed",
            "failed",
            "deferred",
            "rejected",
        ] {
            let status = TaskStatus::parse_str(wire)
                .unwrap_or_else(|| panic!("persist refuses the agent's `{wire}`"));

            let id = format!("t-{}", Uuid::new_v4().simple());
            TaskService::upsert_task(&backend, mk_task(&id, status, &occ))
                .await
                .unwrap_or_else(|e| panic!("upsert `{wire}`: {e}"));
            assert_eq!(
                backend
                    .get_task(&id)
                    .await
                    .unwrap()
                    .expect("present")
                    .status,
                status
            );

            let moved = format!("m-{}", Uuid::new_v4().simple());
            TaskService::upsert_task(&backend, mk_task(&moved, TaskStatus::Active, &occ))
                .await
                .unwrap();
            assert!(
                TaskService::update_task_status(&backend, &moved, status, None)
                    .await
                    .unwrap_or_else(|e| panic!("update_task_status `{wire}`: {e}"))
            );
            assert_eq!(
                backend
                    .get_task(&moved)
                    .await
                    .unwrap()
                    .expect("present")
                    .status,
                status
            );

            let page = TaskService::list_tasks(
                &backend,
                TaskFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    status: Some(status),
                    ..Default::default()
                },
                None,
                50,
            )
            .await
            .unwrap();
            let ids: Vec<&str> = page.items.iter().map(|t| t.task_id.as_str()).collect();
            assert!(
                ids.contains(&id.as_str()) && ids.contains(&moved.as_str()),
                "`{wire}` must be expressible as a list filter; got {ids:?}"
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_upsert_idempotent_then_overwrites_mutable_cols() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id = format!("t-{}", Uuid::new_v4().simple());
        let mut t = mk_task(&id, TaskStatus::Pending, "occ-1");
        t.description = "first".into();
        TaskService::upsert_task(&backend, t.clone()).await.unwrap();
        TaskService::upsert_task(&backend, t.clone()).await.unwrap();
        let got = backend.get_task(&id).await.unwrap().expect("present");
        assert_eq!(got.description, "first");
        let original_created = got.created_at;

        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let mut t2 = t.clone();
        t2.description = "second".into();
        t2.status = TaskStatus::Active;
        t2.updated_at = Utc::now();
        TaskService::upsert_task(&backend, t2).await.unwrap();
        let got2 = backend.get_task(&id).await.unwrap().expect("present");
        assert_eq!(got2.description, "second");
        assert_eq!(got2.status, TaskStatus::Active);
        assert_eq!(got2.created_at, original_created);
    }

    /// v1.6.3 (CIRISPersist#71) — task_upsert honors caller-supplied
    /// `created_at` on UPDATE. Mirrors the SQLite test.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_upsert_honors_supplied_created_at_on_update() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = format!("t-{}", Uuid::new_v4().simple());
        let initial = mk_task(&id, TaskStatus::Pending, "occ-1");
        TaskService::upsert_task(&backend, initial.clone())
            .await
            .unwrap();
        let mut backdated = initial.clone();
        backdated.created_at = chrono::Utc::now() - chrono::Duration::hours(24);
        TaskService::upsert_task(&backend, backdated.clone())
            .await
            .unwrap();
        let got = backend.get_task(&id).await.unwrap().expect("present");
        let drift = (got.created_at - backdated.created_at).num_seconds().abs();
        assert!(drift <= 1, "created_at honored: drift {drift}s");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_list_with_filter_and_cursor() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let mut ids = Vec::new();
        for i in 0..5 {
            let id = format!("t{i}-{}", Uuid::new_v4().simple());
            ids.push(id.clone());
            let t = mk_task(&id, TaskStatus::Pending, &occ);
            TaskService::upsert_task(&backend, t).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        // Page 1.
        let page1 = backend
            .list_tasks(
                TaskFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    ..Default::default()
                },
                None,
                2,
            )
            .await
            .unwrap();
        assert_eq!(page1.items.len(), 2);
        assert!(page1.next_cursor.is_some());
        // Walk through.
        let page2 = backend
            .list_tasks(
                TaskFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    ..Default::default()
                },
                page1.next_cursor,
                2,
            )
            .await
            .unwrap();
        assert_eq!(page2.items.len(), 2);
        let page3 = backend
            .list_tasks(
                TaskFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    ..Default::default()
                },
                page2.next_cursor,
                2,
            )
            .await
            .unwrap();
        assert_eq!(page3.items.len(), 1);
        assert!(page3.next_cursor.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_update_status_outcome_merge_and_missing_row() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&id, TaskStatus::Pending, "occ-1"))
            .await
            .unwrap();
        let ok = backend
            .update_task_status(&id, TaskStatus::Active, None)
            .await
            .unwrap();
        assert!(ok);
        let got = backend.get_task(&id).await.unwrap().expect("present");
        assert_eq!(got.status, TaskStatus::Active);
        assert!(got.outcome.is_none());

        let ok = backend
            .update_task_status(
                &id,
                TaskStatus::Completed,
                Some(serde_json::json!({"final": "ok"})),
            )
            .await
            .unwrap();
        assert!(ok);
        let got = backend.get_task(&id).await.unwrap().expect("present");
        assert_eq!(got.outcome, Some(serde_json::json!({"final": "ok"})));

        let ok = backend
            .update_task_status(
                &format!("missing-{}", Uuid::new_v4().simple()),
                TaskStatus::Failed,
                None,
            )
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_try_claim_shared_clean_then_already_claimed() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id = format!("shared-{}", Uuid::new_v4().simple());
        let t = mk_task(&id, TaskStatus::Pending, "occ-A");
        let r1 = TaskService::try_claim_shared_task(&backend, t.clone())
            .await
            .unwrap();
        assert!(matches!(r1, ClaimResult::Stored(_)));

        let mut t2 = mk_task(&id, TaskStatus::Active, "occ-B");
        t2.channel_id = "chan-other".into();
        let r2 = TaskService::try_claim_shared_task(&backend, t2)
            .await
            .unwrap();
        assert!(matches!(r2, ClaimResult::AlreadyClaimed(_)));
        let existing = r2.into_reference();
        // Loser sees the ORIGINAL row (occ-A pending).
        assert_eq!(existing.agent_occurrence_id, "occ-A");
        assert_eq!(existing.status, TaskStatus::Pending);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_delete_success_then_idempotent_false() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&id, TaskStatus::Pending, "occ-1"))
            .await
            .unwrap();
        let first = backend.delete_task(&id).await.unwrap();
        assert!(first);
        let second = backend.delete_task(&id).await.unwrap();
        assert!(!second);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_parent_fk_existing_parent_ok_nonexistent_rejects() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let parent_id = format!("p-{}", Uuid::new_v4().simple());
        let child_id = format!("c-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&parent_id, TaskStatus::Pending, "occ-1"))
            .await
            .unwrap();
        let mut child = mk_task(&child_id, TaskStatus::Pending, "occ-1");
        child.parent_task_id = Some(parent_id.clone());
        TaskService::upsert_task(&backend, child).await.unwrap();

        let mut orphan = mk_task(
            &format!("o-{}", Uuid::new_v4().simple()),
            TaskStatus::Pending,
            "occ-1",
        );
        orphan.parent_task_id = Some(format!("ghost-{}", Uuid::new_v4().simple()));
        // DEFERRABLE INITIALLY DEFERRED — autocommit single-stmt
        // INSERT triggers constraint check at the implicit COMMIT
        // of the autocommit transaction, so this still rejects.
        let err = TaskService::upsert_task(&backend, orphan)
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Conflict(_)),
            "expected Conflict (FK), got {err:?}"
        );
    }

    // ── v1.5.21 (CIRISPersist#62) created_before/created_after ───────

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_list_filter_created_range() {
        use crate::store::backend::Backend;
        use chrono::Duration as ChronoDuration;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let now = Utc::now();
        // 3 tasks: -72h / -24h / now. created_at exact, updated_at
        // matches so the cursor on (updated_at, task_id) doesn't
        // shadow the filter.
        let mut ids: Vec<(String, i64)> = Vec::new();
        for (label, offset_h) in &[("a", -72i64), ("b", -24), ("c", 0)] {
            let id = format!("{label}-{}", Uuid::new_v4().simple());
            ids.push((id.clone(), *offset_h));
            let mut t = mk_task(&id, TaskStatus::Pending, &occ);
            t.created_at = now + ChronoDuration::hours(*offset_h);
            t.updated_at = t.created_at;
            TaskService::upsert_task(&backend, t).await.unwrap();
        }

        // created_before -12h → keeps a (-72h) and b (-24h).
        let page = backend
            .list_tasks(
                TaskFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    created_before: Some(now - ChronoDuration::hours(12)),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);

        // created_after -48h → keeps b (-24h) and c (now).
        let page = backend
            .list_tasks(
                TaskFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    created_after: Some(now - ChronoDuration::hours(48)),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);

        // [-48h, -12h] window → keeps only b (-24h).
        let page = backend
            .list_tasks(
                TaskFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    created_after: Some(now - ChronoDuration::hours(48)),
                    created_before: Some(now - ChronoDuration::hours(12)),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert!(page.items[0].task_id.starts_with("b-"));
    }

    // ── v1.5.22 (CIRISPersist#61) correlation_id dedup ───────────────

    fn mk_task_with_correlation(id: &str, occ: &str, correlation_id: &str) -> Task {
        let mut t = mk_task(id, TaskStatus::Pending, occ);
        t.context = Some(serde_json::json!({"correlation_id": correlation_id}));
        t
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_upsert_returns_stored_on_clean_insert() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = format!("t-{}", Uuid::new_v4().simple());
        let outcome =
            TaskService::upsert_task(&backend, mk_task(&id, TaskStatus::Pending, "occ-1"))
                .await
                .unwrap();
        match outcome {
            TaskUpsertOutcome::Stored(row) => assert_eq!(row.task_id, id),
            other => panic!("expected Stored, got {other:?}"),
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_upsert_returns_already_exists_on_correlation_collision() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let cid = format!("upstream-{}", Uuid::new_v4().simple());
        let first_id = format!("t1-{}", Uuid::new_v4().simple());
        let _ = TaskService::upsert_task(&backend, mk_task_with_correlation(&first_id, &occ, &cid))
            .await
            .unwrap();

        let second_id = format!("t2-{}", Uuid::new_v4().simple());
        let outcome =
            TaskService::upsert_task(&backend, mk_task_with_correlation(&second_id, &occ, &cid))
                .await
                .unwrap();
        match outcome {
            TaskUpsertOutcome::AlreadyExists(row) => {
                assert_eq!(row.task_id, first_id);
                assert_ne!(row.task_id, second_id);
            }
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_upsert_correlation_scope_isolated_per_occurrence() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let cid = format!("upstream-{}", Uuid::new_v4().simple());
        let id1 = format!("t1-{}", Uuid::new_v4().simple());
        let id2 = format!("t2-{}", Uuid::new_v4().simple());
        let occ_a = format!("occ-a-{}", Uuid::new_v4().simple());
        let occ_b = format!("occ-b-{}", Uuid::new_v4().simple());

        let _ = TaskService::upsert_task(&backend, mk_task_with_correlation(&id1, &occ_a, &cid))
            .await
            .unwrap();
        let outcome =
            TaskService::upsert_task(&backend, mk_task_with_correlation(&id2, &occ_b, &cid))
                .await
                .unwrap();
        match outcome {
            TaskUpsertOutcome::Stored(row) => assert_eq!(row.task_id, id2),
            other => panic!("expected Stored across occurrences, got {other:?}"),
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tasks_pg_upsert_re_upsert_same_task_id_returns_stored() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let cid = format!("upstream-{}", Uuid::new_v4().simple());
        let id = format!("t-{}", Uuid::new_v4().simple());
        let t1 = mk_task_with_correlation(&id, &occ, &cid);
        let _ = TaskService::upsert_task(&backend, t1.clone())
            .await
            .unwrap();

        // Re-upsert: same task_id, different mutables. ON CONFLICT
        // (task_id) UPDATE wins; correlation index does NOT trip.
        let mut t2 = t1;
        t2.description = "updated-by-second-call".into();
        let outcome = TaskService::upsert_task(&backend, t2).await.unwrap();
        match outcome {
            TaskUpsertOutcome::Stored(row) => {
                assert_eq!(row.task_id, id);
                assert_eq!(row.description, "updated-by-second-call");
            }
            other => panic!("expected Stored on re-upsert, got {other:?}"),
        }
    }
}
