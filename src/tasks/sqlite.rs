//! SQLite impl of [`TaskService`] (v1.5.9, CIRISPersist#59 #1).
//!
//! Mirrors the v1.5.9 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ              → TEXT (RFC 3339)
//!   BOOLEAN                  → INTEGER (0/1)
//!   JSONB                    → TEXT (raw JSON string)
//!   ON CONFLICT (task_id) DO UPDATE … → ON CONFLICT (task_id) DO UPDATE …
//!   ON CONFLICT (task_id) DO NOTHING  → INSERT OR IGNORE
//!
//! Threading: `tokio::task::spawn_blocking` + `conn.blocking_lock()`
//! per the existing pattern (mirrors `src/incident/sqlite.rs`).

use std::sync::Arc;

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use tokio::sync::Mutex;

use super::service::TaskService;
use super::types::{Task, TaskCursor, TaskFilter, TaskListPage, TaskStatus, TaskUpsertOutcome};
use super::Error;
use crate::ClaimResult;

/// SQLite-backed [`TaskService`] impl.
pub struct SqliteTaskBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTaskBackend {
    /// Construct from a shared connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if err.code == ErrorCode::ConstraintViolation {
            // FK conflict → Conflict (caller can't retry, must
            // resolve the reference). Other CHECK / UNIQUE
            // violations → InvalidArgument.
            let s = e.to_string();
            if s.contains("FOREIGN KEY") {
                return Error::Conflict(format!("{op}: {e}"));
            }
            return Error::InvalidArgument(format!("{op}: {e}"));
        }
    }
    Error::Backend(format!("{op}: {e}"))
}

/// `true` when the rusqlite error is a UNIQUE-constraint violation
/// on `tasks_correlation_id_unique` (V036). Matches by extended
/// error-code + substring of the index name in the message — SQLite
/// surfaces the index name in the error text for constraint
/// violations.
fn is_correlation_unique_violation(e: &rusqlite::Error) -> bool {
    if let rusqlite::Error::SqliteFailure(err, _msg) = e {
        // 2067 = SQLITE_CONSTRAINT_UNIQUE (extended)
        if err.extended_code == 2067 {
            return e.to_string().contains("tasks_correlation_id_unique");
        }
    }
    false
}

/// Extract `context.correlation_id` from a task. Mirrors the PG-side
/// helper.
fn correlation_id_from_task(task: &Task) -> Option<&str> {
    let ctx = task.context.as_ref()?;
    ctx.get("correlation_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
}

fn parse_datetime(s: &str) -> Result<chrono::DateTime<chrono::Utc>, Error> {
    let normalized = if s.contains('T') {
        s.to_owned()
    } else {
        format!("{}+00:00", s.replacen(' ', "T", 1))
    };
    chrono::DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| Error::Backend(format!("datetime parse: {e} (raw={s})")))
}

fn fmt_datetime(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
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

#[allow(clippy::type_complexity)]
fn decode_task_row(row: &rusqlite::Row<'_>) -> Result<Task, Error> {
    let task_id: String = row
        .get("task_id")
        .map_err(|e| Error::Backend(format!("decode task_id: {e}")))?;
    let channel_id: String = row
        .get("channel_id")
        .map_err(|e| Error::Backend(format!("decode channel_id: {e}")))?;
    let description: String = row
        .get("description")
        .map_err(|e| Error::Backend(format!("decode description: {e}")))?;
    let status_str: String = row
        .get("status")
        .map_err(|e| Error::Backend(format!("decode status: {e}")))?;
    let status = TaskStatus::parse_str(&status_str)
        .ok_or_else(|| Error::Backend(format!("unknown status: {status_str}")))?;
    let priority: i32 = row
        .get("priority")
        .map_err(|e| Error::Backend(format!("decode priority: {e}")))?;
    let created_at_str: String = row
        .get("created_at")
        .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?;
    let updated_at_str: String = row
        .get("updated_at")
        .map_err(|e| Error::Backend(format!("decode updated_at: {e}")))?;
    let parent_task_id: Option<String> = row
        .get("parent_task_id")
        .map_err(|e| Error::Backend(format!("decode parent_task_id: {e}")))?;
    let context_raw: Option<String> = row
        .get("context_json")
        .map_err(|e| Error::Backend(format!("decode context_json: {e}")))?;
    let outcome_raw: Option<String> = row
        .get("outcome_json")
        .map_err(|e| Error::Backend(format!("decode outcome_json: {e}")))?;
    let retry_count: i32 = row
        .get("retry_count")
        .map_err(|e| Error::Backend(format!("decode retry_count: {e}")))?;
    let signed_by: Option<String> = row
        .get("signed_by")
        .map_err(|e| Error::Backend(format!("decode signed_by: {e}")))?;
    let signature: Option<String> = row
        .get("signature")
        .map_err(|e| Error::Backend(format!("decode signature: {e}")))?;
    let signed_at_str: Option<String> = row
        .get("signed_at")
        .map_err(|e| Error::Backend(format!("decode signed_at: {e}")))?;
    let signed_at = match signed_at_str {
        Some(s) => Some(parse_datetime(&s)?),
        None => None,
    };
    let updated_info_int: i64 = row
        .get("updated_info_available")
        .map_err(|e| Error::Backend(format!("decode updated_info_available: {e}")))?;
    let updated_info_content: Option<String> = row
        .get("updated_info_content")
        .map_err(|e| Error::Backend(format!("decode updated_info_content: {e}")))?;
    let agent_occurrence_id: String = row
        .get("agent_occurrence_id")
        .map_err(|e| Error::Backend(format!("decode agent_occurrence_id: {e}")))?;
    let images_raw: Option<String> = row
        .get("images_json")
        .map_err(|e| Error::Backend(format!("decode images_json: {e}")))?;
    Ok(Task {
        task_id,
        channel_id,
        description,
        status,
        priority,
        created_at: parse_datetime(&created_at_str)?,
        updated_at: parse_datetime(&updated_at_str)?,
        parent_task_id,
        context: decode_json_opt(context_raw)?,
        outcome: decode_json_opt(outcome_raw)?,
        retry_count,
        signed_by,
        signature,
        signed_at,
        updated_info_available: updated_info_int != 0,
        updated_info_content,
        agent_occurrence_id,
        images: decode_json_opt(images_raw)?,
    })
}

impl TaskService for SqliteTaskBackend {
    async fn upsert_task(&self, task: Task) -> Result<TaskUpsertOutcome, Error> {
        validate_task(&task)?;
        let context_str = encode_json_opt(task.context.as_ref())?;
        let outcome_str = encode_json_opt(task.outcome.as_ref())?;
        let images_str = encode_json_opt(task.images.as_ref())?;
        let created_at_str = fmt_datetime(task.created_at);
        let updated_at_str = fmt_datetime(task.updated_at);
        let signed_at_str = task.signed_at.map(fmt_datetime);
        let status_str = task.status.as_sql_str().to_owned();
        let updated_info_int: i64 = if task.updated_info_available { 1 } else { 0 };
        let correlation_id = correlation_id_from_task(&task).map(str::to_owned);
        let task_id_owned = task.task_id.clone();
        let agent_occurrence = task.agent_occurrence_id.clone();

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<TaskUpsertOutcome, Error> {
            let mut guard = conn.blocking_lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "upsert_task begin"))?;
            let insert_res = tx.execute(
                "INSERT INTO cirislens_tasks (\
                    task_id, channel_id, description, status, priority, \
                    created_at, updated_at, parent_task_id, context_json, outcome_json, \
                    retry_count, signed_by, signature, signed_at, \
                    updated_info_available, updated_info_content, \
                    agent_occurrence_id, images_json\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                           ?15, ?16, ?17, ?18) \
                 ON CONFLICT(task_id) DO UPDATE SET \
                    channel_id = excluded.channel_id, \
                    description = excluded.description, \
                    status = excluded.status, \
                    priority = excluded.priority, \
                    created_at = excluded.created_at, \
                    updated_at = excluded.updated_at, \
                    parent_task_id = excluded.parent_task_id, \
                    context_json = excluded.context_json, \
                    outcome_json = excluded.outcome_json, \
                    retry_count = excluded.retry_count, \
                    signed_by = excluded.signed_by, \
                    signature = excluded.signature, \
                    signed_at = excluded.signed_at, \
                    updated_info_available = excluded.updated_info_available, \
                    updated_info_content = excluded.updated_info_content, \
                    agent_occurrence_id = excluded.agent_occurrence_id, \
                    images_json = excluded.images_json",
                params![
                    task.task_id,
                    task.channel_id,
                    task.description,
                    status_str,
                    task.priority,
                    created_at_str,
                    updated_at_str,
                    task.parent_task_id,
                    context_str,
                    outcome_str,
                    task.retry_count,
                    task.signed_by,
                    task.signature,
                    signed_at_str,
                    updated_info_int,
                    task.updated_info_content,
                    task.agent_occurrence_id,
                    images_str,
                ],
            );
            match insert_res {
                Ok(_) => {
                    let row = tx
                        .query_row(
                            "SELECT task_id, channel_id, description, status, priority, \
                                    created_at, updated_at, parent_task_id, context_json, outcome_json, \
                                    retry_count, signed_by, signature, signed_at, \
                                    updated_info_available, updated_info_content, \
                                    agent_occurrence_id, images_json \
                             FROM cirislens_tasks WHERE task_id = ?1",
                            params![task_id_owned],
                            |row| Ok(decode_task_row(row)),
                        )
                        .map_err(|e| map_sqlite_error(e, "upsert_task readback"))??;
                    tx.commit()
                        .map_err(|e| map_sqlite_error(e, "upsert_task commit"))?;
                    Ok(TaskUpsertOutcome::Stored(row))
                }
                Err(ref e) if is_correlation_unique_violation(e) => {
                    let Some(cid) = correlation_id else {
                        return Err(Error::Backend(format!(
                            "upsert_task: tasks_correlation_id_unique fired with no correlation_id: {e}"
                        )));
                    };
                    let row = tx
                        .query_row(
                            "SELECT task_id, channel_id, description, status, priority, \
                                    created_at, updated_at, parent_task_id, context_json, outcome_json, \
                                    retry_count, signed_by, signature, signed_at, \
                                    updated_info_available, updated_info_content, \
                                    agent_occurrence_id, images_json \
                             FROM cirislens_tasks \
                             WHERE agent_occurrence_id = ?1 \
                               AND json_extract(context_json, '$.correlation_id') = ?2",
                            params![agent_occurrence, cid],
                            |row| Ok(decode_task_row(row)),
                        )
                        .map_err(|e| map_sqlite_error(e, "upsert_task correlation readback"))??;
                    tx.commit()
                        .map_err(|e| map_sqlite_error(e, "upsert_task commit"))?;
                    Ok(TaskUpsertOutcome::AlreadyExists(row))
                }
                Err(e) => Err(map_sqlite_error(e, "upsert_task insert")),
            }
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn get_task(&self, task_id: &str) -> Result<Option<Task>, Error> {
        if task_id.is_empty() {
            return Err(Error::InvalidArgument("task_id required".into()));
        }
        let conn = self.conn.clone();
        let task_id_owned = task_id.to_owned();
        tokio::task::spawn_blocking(move || -> Result<Option<Task>, Error> {
            let guard = conn.blocking_lock();
            let row_opt = guard
                .query_row(
                    "SELECT task_id, channel_id, description, status, priority, \
                            created_at, updated_at, parent_task_id, context_json, outcome_json, \
                            retry_count, signed_by, signature, signed_at, \
                            updated_info_available, updated_info_content, \
                            agent_occurrence_id, images_json \
                     FROM cirislens_tasks WHERE task_id = ?1",
                    params![task_id_owned],
                    |row| Ok(decode_task_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_task query"))?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(r?)),
            }
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
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
        let mut sql_params: Vec<SqlValue> = Vec::new();
        if let Some(occ) = filter.agent_occurrence_id {
            sql_params.push(SqlValue::Text(occ));
            where_parts.push(format!("agent_occurrence_id = ?{}", sql_params.len()));
        }
        if let Some(status) = filter.status {
            sql_params.push(SqlValue::Text(status.as_sql_str().to_owned()));
            where_parts.push(format!("status = ?{}", sql_params.len()));
        }
        if let Some(ch) = filter.channel_id {
            sql_params.push(SqlValue::Text(ch));
            where_parts.push(format!("channel_id = ?{}", sql_params.len()));
        }
        if let Some(parent) = filter.parent_task_id {
            sql_params.push(SqlValue::Text(parent));
            where_parts.push(format!("parent_task_id = ?{}", sql_params.len()));
        }
        if let Some(after) = filter.updated_after {
            sql_params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push(format!("updated_at >= ?{}", sql_params.len()));
        }
        if let Some(before) = filter.updated_before {
            sql_params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push(format!("updated_at <= ?{}", sql_params.len()));
        }
        if let Some(before) = filter.created_before {
            sql_params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push(format!("created_at < ?{}", sql_params.len()));
        }
        if let Some(after) = filter.created_after {
            sql_params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push(format!("created_at >= ?{}", sql_params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "TaskCursor version {} unsupported",
                    cur.version
                )));
            }
            sql_params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
            let p_ts = sql_params.len();
            sql_params.push(SqlValue::Text(cur.last_id.clone()));
            let p_id = sql_params.len();
            where_parts.push(format!("(updated_at, task_id) < (?{p_ts}, ?{p_id})"));
        }
        sql_params.push(SqlValue::Integer(limit));
        let p_limit = sql_params.len();
        let where_sql = if where_parts.is_empty() {
            "1=1".to_string()
        } else {
            where_parts.join(" AND ")
        };
        let sql = format!(
            "SELECT task_id, channel_id, description, status, priority, \
                    created_at, updated_at, parent_task_id, context_json, outcome_json, \
                    retry_count, signed_by, signature, signed_at, \
                    updated_info_available, updated_info_content, \
                    agent_occurrence_id, images_json \
             FROM cirislens_tasks \
             WHERE {where_sql} \
             ORDER BY updated_at DESC, task_id DESC \
             LIMIT ?{p_limit}"
        );
        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        tokio::task::spawn_blocking(move || -> Result<TaskListPage, Error> {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "list_tasks prepare"))?;
            let rows_iter = stmt
                .query_map(params_from_iter(sql_params.iter()), |row| {
                    Ok(decode_task_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "list_tasks query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "list_tasks row"))??);
            }
            let next_cursor = if items.len() == limit_usize {
                items
                    .last()
                    .map(|last| TaskCursor::from_trailing(last.updated_at, last.task_id.clone()))
            } else {
                None
            };
            Ok(TaskListPage { items, next_cursor })
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
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
        let outcome_str = encode_json_opt(outcome.as_ref())?;
        let now_str = fmt_datetime(chrono::Utc::now());
        let status_sql = new_status.as_sql_str().to_owned();
        let task_id_owned = task_id.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<bool, Error> {
            let guard = conn.blocking_lock();
            // COALESCE($outcome, outcome_json) — preserve existing
            // outcome if caller didn't supply one. Caller can pass
            // serde_json::Value::Null explicitly via Some(Value::Null)
            // to overwrite with NULL.
            let changed = guard
                .execute(
                    "UPDATE cirislens_tasks SET \
                        status = ?1, \
                        updated_at = ?2, \
                        outcome_json = COALESCE(?3, outcome_json) \
                     WHERE task_id = ?4",
                    params![status_sql, now_str, outcome_str, task_id_owned],
                )
                .map_err(|e| map_sqlite_error(e, "update_task_status exec"))?;
            Ok(changed > 0)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn try_claim_shared_task(&self, task: Task) -> Result<ClaimResult<Task>, Error> {
        validate_task(&task)?;
        let context_str = encode_json_opt(task.context.as_ref())?;
        let outcome_str = encode_json_opt(task.outcome.as_ref())?;
        let images_str = encode_json_opt(task.images.as_ref())?;
        let created_at_str = fmt_datetime(task.created_at);
        let updated_at_str = fmt_datetime(task.updated_at);
        let signed_at_str = task.signed_at.map(fmt_datetime);
        let status_sql = task.status.as_sql_str().to_owned();
        let updated_info_int: i64 = if task.updated_info_available { 1 } else { 0 };
        let task_id_for_lookup = task.task_id.clone();

        let conn = self.conn.clone();
        let (won, row): (bool, Task) =
            tokio::task::spawn_blocking(move || -> Result<(bool, Task), Error> {
                let mut guard = conn.blocking_lock();
                let tx = guard
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(|e| map_sqlite_error(e, "try_claim_shared_task begin"))?;
                let changed = tx
                    .execute(
                        "INSERT OR IGNORE INTO cirislens_tasks (\
                            task_id, channel_id, description, status, priority, \
                            created_at, updated_at, parent_task_id, context_json, outcome_json, \
                            retry_count, signed_by, signature, signed_at, \
                            updated_info_available, updated_info_content, \
                            agent_occurrence_id, images_json\
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, \
                                   ?14, ?15, ?16, ?17, ?18)",
                        params![
                            task.task_id,
                            task.channel_id,
                            task.description,
                            status_sql,
                            task.priority,
                            created_at_str,
                            updated_at_str,
                            task.parent_task_id,
                            context_str,
                            outcome_str,
                            task.retry_count,
                            task.signed_by,
                            task.signature,
                            signed_at_str,
                            updated_info_int,
                            task.updated_info_content,
                            task.agent_occurrence_id,
                            images_str,
                        ],
                    )
                    .map_err(|e| map_sqlite_error(e, "try_claim_shared_task insert"))?;
                let won = changed > 0;
                // Re-read the row — winner gets back their own row,
                // loser gets back the EXISTING row.
                let row = tx
                    .query_row(
                        "SELECT task_id, channel_id, description, status, priority, \
                                created_at, updated_at, parent_task_id, context_json, outcome_json, \
                                retry_count, signed_by, signature, signed_at, \
                                updated_info_available, updated_info_content, \
                                agent_occurrence_id, images_json \
                         FROM cirislens_tasks WHERE task_id = ?1",
                        params![task_id_for_lookup],
                        |row| Ok(decode_task_row(row)),
                    )
                    .map_err(|e| map_sqlite_error(e, "try_claim_shared_task readback"))??;
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "try_claim_shared_task commit"))?;
                Ok((won, row))
            })
            .await
            .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))??;

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
        let task_id_owned = task_id.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<bool, Error> {
            let guard = conn.blocking_lock();
            // SQLite needs PRAGMA foreign_keys=ON for the self-FK to
            // be enforced. The store opens connections with FK on
            // already (see store::sqlite::SqliteBackend); we don't
            // toggle it per-call.
            let changed = guard
                .execute(
                    "DELETE FROM cirislens_tasks WHERE task_id = ?1",
                    params![task_id_owned],
                )
                .map_err(|e| map_sqlite_error(e, "delete_task exec"))?;
            Ok(changed > 0)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteTaskBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteTaskBackend::new(backend.conn_handle());
        (backend, svc)
    }

    fn mk_task(id: &str, status: TaskStatus, occurrence: &str) -> Task {
        let now = chrono::Utc::now();
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
    async fn upsert_get_round_trip_all_17_columns() {
        let (_b, svc) = fresh_backend().await;
        let now = chrono::Utc::now();
        let parent = format!("parent-{}", Uuid::new_v4().simple());
        // Insert the parent first so the FK self-reference is valid.
        let parent_task = mk_task(&parent, TaskStatus::Pending, "occ-1");
        svc.upsert_task(parent_task).await.unwrap();

        let child = format!("child-{}", Uuid::new_v4().simple());
        let task = Task {
            task_id: child.clone(),
            channel_id: "chan-x".into(),
            description: "do the thing".into(),
            status: TaskStatus::Active,
            priority: 7,
            created_at: now,
            updated_at: now,
            parent_task_id: Some(parent.clone()),
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
        svc.upsert_task(task.clone()).await.unwrap();
        let got = svc.get_task(&child).await.unwrap().expect("present");
        // Compare every field. Timestamps round-trip through RFC 3339
        // with microsecond precision — the test now is far enough
        // sub-second that an exact eq might miss; clamp to micros.
        assert_eq!(got.task_id, task.task_id);
        assert_eq!(got.channel_id, task.channel_id);
        assert_eq!(got.description, task.description);
        assert_eq!(got.status, task.status);
        assert_eq!(got.priority, task.priority);
        assert_eq!(got.parent_task_id, task.parent_task_id);
        assert_eq!(got.context, task.context);
        assert_eq!(got.outcome, task.outcome);
        assert_eq!(got.retry_count, task.retry_count);
        assert_eq!(got.signed_by, task.signed_by);
        assert_eq!(got.signature, task.signature);
        assert!(got.signed_at.is_some());
        assert_eq!(got.updated_info_available, task.updated_info_available);
        assert_eq!(got.updated_info_content, task.updated_info_content);
        assert_eq!(got.agent_occurrence_id, task.agent_occurrence_id);
        assert_eq!(got.images, task.images);
    }

    #[tokio::test]
    async fn upsert_idempotent_same_payload_noop_diff_payload_overwrites() {
        let (_b, svc) = fresh_backend().await;
        let id = format!("t-{}", Uuid::new_v4().simple());
        let mut t = mk_task(&id, TaskStatus::Pending, "occ-1");
        t.description = "first".into();
        svc.upsert_task(t.clone()).await.unwrap();
        // Same payload — idempotent.
        svc.upsert_task(t.clone()).await.unwrap();
        let got = svc.get_task(&id).await.unwrap().expect("present");
        assert_eq!(got.description, "first");

        // Different payload — mutable cols overwritten; created_at
        // unchanged.
        let original_created = got.created_at;
        // give it a moment so updated_at can advance
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let mut t2 = t.clone();
        t2.description = "second".into();
        t2.status = TaskStatus::Active;
        t2.updated_at = chrono::Utc::now();
        svc.upsert_task(t2).await.unwrap();
        let got2 = svc.get_task(&id).await.unwrap().expect("present");
        assert_eq!(got2.description, "second");
        assert_eq!(got2.status, TaskStatus::Active);
        assert_eq!(
            got2.created_at, original_created,
            "created_at preserved when caller supplies the same value"
        );
    }

    /// v1.6.3 (CIRISPersist#71) — task_upsert honors caller-supplied
    /// `created_at` on UPDATE (was: preserved original). Backs the
    /// agent's test-scaffolding pattern that backdates rows to
    /// exercise stale-task code paths in `try_claim_shared_task`.
    #[tokio::test]
    async fn upsert_honors_supplied_created_at_on_update() {
        let (_b, svc) = fresh_backend().await;
        let id = format!("t-{}", Uuid::new_v4().simple());
        let initial = mk_task(&id, TaskStatus::Pending, "occ-1");
        svc.upsert_task(initial.clone()).await.unwrap();

        // Re-upsert with an EARLIER created_at — should win.
        let mut backdated = initial.clone();
        backdated.created_at = chrono::Utc::now() - chrono::Duration::hours(24);
        svc.upsert_task(backdated.clone()).await.unwrap();
        let got = svc.get_task(&id).await.unwrap().expect("present");
        let drift = (got.created_at - backdated.created_at).num_seconds().abs();
        assert!(
            drift <= 1,
            "created_at honored: expected ~{}, got {} (drift {drift}s)",
            backdated.created_at,
            got.created_at
        );
    }

    #[tokio::test]
    async fn list_with_filter_status_channel_occurrence() {
        let (_b, svc) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        // 3 tasks: pending+chan-a, active+chan-a, completed+chan-b.
        let t1 = {
            let mut t = mk_task(
                &format!("t1-{}", Uuid::new_v4().simple()),
                TaskStatus::Pending,
                &occ,
            );
            t.channel_id = "chan-a".into();
            t
        };
        let t2 = {
            let mut t = mk_task(
                &format!("t2-{}", Uuid::new_v4().simple()),
                TaskStatus::Active,
                &occ,
            );
            t.channel_id = "chan-a".into();
            t
        };
        let t3 = {
            let mut t = mk_task(
                &format!("t3-{}", Uuid::new_v4().simple()),
                TaskStatus::Completed,
                &occ,
            );
            t.channel_id = "chan-b".into();
            t
        };
        svc.upsert_task(t1.clone()).await.unwrap();
        svc.upsert_task(t2.clone()).await.unwrap();
        svc.upsert_task(t3.clone()).await.unwrap();

        // Filter by occurrence: all 3.
        let page = svc
            .list_tasks(
                TaskFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 3);

        // Filter by status=Active + occurrence: 1.
        let page = svc
            .list_tasks(
                TaskFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    status: Some(TaskStatus::Active),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].task_id, t2.task_id);

        // Filter by channel: chan-a → 2.
        let page = svc
            .list_tasks(
                TaskFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    channel_id: Some("chan-a".into()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);
    }

    #[tokio::test]
    async fn list_cursor_pagination() {
        let (_b, svc) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        // Insert 5 tasks, spaced out so updated_at ordering is
        // deterministic.
        let mut ids = Vec::new();
        for i in 0..5 {
            let id = format!("t{i}-{}", Uuid::new_v4().simple());
            ids.push(id.clone());
            let t = mk_task(&id, TaskStatus::Pending, &occ);
            svc.upsert_task(t).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        // Page 1: 2 items, next_cursor set.
        let page1 = svc
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
        // Page 2.
        let page2 = svc
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
        // Page 3: 1 item, no next cursor (under limit).
        let page3 = svc
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
        // Union of pages == ids set.
        let mut seen: Vec<String> = page1
            .items
            .iter()
            .chain(page2.items.iter())
            .chain(page3.items.iter())
            .map(|t| t.task_id.clone())
            .collect();
        seen.sort();
        let mut expected = ids.clone();
        expected.sort();
        assert_eq!(seen, expected);
    }

    #[tokio::test]
    async fn update_task_status_success_missing_outcome_merge() {
        let (_b, svc) = fresh_backend().await;
        let id = format!("t-{}", Uuid::new_v4().simple());
        let t = mk_task(&id, TaskStatus::Pending, "occ-1");
        svc.upsert_task(t).await.unwrap();

        // Update to Active without outcome — outcome stays NULL.
        let ok = svc
            .update_task_status(&id, TaskStatus::Active, None)
            .await
            .unwrap();
        assert!(ok);
        let got = svc.get_task(&id).await.unwrap().expect("present");
        assert_eq!(got.status, TaskStatus::Active);
        assert!(got.outcome.is_none());

        // Update to Completed with outcome — outcome lands.
        let ok = svc
            .update_task_status(
                &id,
                TaskStatus::Completed,
                Some(serde_json::json!({"final": "ok"})),
            )
            .await
            .unwrap();
        assert!(ok);
        let got = svc.get_task(&id).await.unwrap().expect("present");
        assert_eq!(got.status, TaskStatus::Completed);
        assert_eq!(got.outcome, Some(serde_json::json!({"final": "ok"})));

        // Missing task → false (not an error).
        let ok = svc
            .update_task_status("nonexistent", TaskStatus::Failed, None)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn try_claim_shared_clean_insert_then_already_claimed() {
        let (_b, svc) = fresh_backend().await;
        let id = format!("shared-{}", Uuid::new_v4().simple());
        let t = mk_task(&id, TaskStatus::Pending, "occ-A");

        // First caller wins.
        let r1 = svc.try_claim_shared_task(t.clone()).await.unwrap();
        assert!(matches!(r1, ClaimResult::Stored(_)));
        let stored_task = r1.into_reference();
        assert_eq!(stored_task.task_id, id);

        // Second caller — with DIFFERENT payload — loses. Returns
        // the EXISTING row (occ-A, not occ-B).
        let mut t2 = mk_task(&id, TaskStatus::Active, "occ-B");
        t2.channel_id = "chan-other".into();
        let r2 = svc.try_claim_shared_task(t2).await.unwrap();
        assert!(matches!(r2, ClaimResult::AlreadyClaimed(_)));
        let claimed_task = r2.into_reference();
        assert_eq!(claimed_task.task_id, id);
        assert_eq!(claimed_task.agent_occurrence_id, "occ-A");
        assert_eq!(claimed_task.status, TaskStatus::Pending);
    }

    #[tokio::test]
    async fn delete_task_success_then_idempotent_false() {
        let (_b, svc) = fresh_backend().await;
        let id = format!("t-{}", Uuid::new_v4().simple());
        svc.upsert_task(mk_task(&id, TaskStatus::Pending, "occ-1"))
            .await
            .unwrap();
        let first = svc.delete_task(&id).await.unwrap();
        assert!(first);
        let second = svc.delete_task(&id).await.unwrap();
        assert!(!second);
    }

    #[tokio::test]
    async fn parent_fk_insert_child_nonexistent_parent_rejects() {
        let (_b, svc) = fresh_backend().await;
        let child_id = format!("child-{}", Uuid::new_v4().simple());
        let mut t = mk_task(&child_id, TaskStatus::Pending, "occ-1");
        t.parent_task_id = Some("does-not-exist".into());
        let err = svc.upsert_task(t).await.unwrap_err();
        assert!(
            matches!(err, Error::Conflict(_)),
            "expected Conflict (FK), got {err:?}"
        );
    }

    #[tokio::test]
    async fn parent_fk_insert_child_existing_parent_ok() {
        let (_b, svc) = fresh_backend().await;
        let parent_id = format!("p-{}", Uuid::new_v4().simple());
        let child_id = format!("c-{}", Uuid::new_v4().simple());
        svc.upsert_task(mk_task(&parent_id, TaskStatus::Pending, "occ-1"))
            .await
            .unwrap();
        let mut t = mk_task(&child_id, TaskStatus::Pending, "occ-1");
        t.parent_task_id = Some(parent_id);
        svc.upsert_task(t).await.unwrap();
        let got = svc.get_task(&child_id).await.unwrap().expect("present");
        assert!(got.parent_task_id.is_some());
    }

    // ── v1.5.21 (CIRISPersist#62) created_before/created_after ───────

    #[tokio::test]
    async fn list_filter_created_before_excludes_newer() {
        use chrono::Duration as ChronoDuration;
        let (_b, svc) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let now = chrono::Utc::now();

        // Older task: created_at 1 day ago.
        let old_id = format!("old-{}", Uuid::new_v4().simple());
        let mut older = mk_task(&old_id, TaskStatus::Pending, &occ);
        older.created_at = now - ChronoDuration::days(1);
        older.updated_at = older.created_at;
        svc.upsert_task(older).await.unwrap();

        // Newer task: created_at right now.
        let new_id = format!("new-{}", Uuid::new_v4().simple());
        let mut newer = mk_task(&new_id, TaskStatus::Pending, &occ);
        newer.created_at = now;
        newer.updated_at = now;
        svc.upsert_task(newer).await.unwrap();

        // created_before midpoint → only older survives.
        let cutoff = now - ChronoDuration::hours(1);
        let page = svc
            .list_tasks(
                TaskFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    created_before: Some(cutoff),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].task_id, old_id);
    }

    #[tokio::test]
    async fn list_filter_created_after_excludes_older() {
        use chrono::Duration as ChronoDuration;
        let (_b, svc) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let now = chrono::Utc::now();

        let old_id = format!("old-{}", Uuid::new_v4().simple());
        let mut older = mk_task(&old_id, TaskStatus::Pending, &occ);
        older.created_at = now - ChronoDuration::days(1);
        older.updated_at = older.created_at;
        svc.upsert_task(older).await.unwrap();

        let new_id = format!("new-{}", Uuid::new_v4().simple());
        let mut newer = mk_task(&new_id, TaskStatus::Pending, &occ);
        newer.created_at = now;
        newer.updated_at = now;
        svc.upsert_task(newer).await.unwrap();

        let cutoff = now - ChronoDuration::hours(1);
        let page = svc
            .list_tasks(
                TaskFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    created_after: Some(cutoff),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].task_id, new_id);
    }

    #[tokio::test]
    async fn list_filter_created_range_combination() {
        use chrono::Duration as ChronoDuration;
        let (_b, svc) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let now = chrono::Utc::now();

        // 3 tasks: -3d, -1d, now. Window: [-2d, -12h] keeps only -1d.
        for (label, offset_h) in &[("a", -72), ("b", -24), ("c", 0)] {
            let id = format!("{label}-{}", Uuid::new_v4().simple());
            let mut t = mk_task(&id, TaskStatus::Pending, &occ);
            t.created_at = now + ChronoDuration::hours(*offset_h);
            t.updated_at = t.created_at;
            svc.upsert_task(t).await.unwrap();
        }

        let page = svc
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
    async fn upsert_task_returns_stored_envelope_on_clean_insert() {
        let (_b, svc) = fresh_backend().await;
        let id = format!("t-{}", Uuid::new_v4().simple());
        let t = mk_task(&id, TaskStatus::Pending, "occ-1");
        let outcome = svc.upsert_task(t).await.unwrap();
        match outcome {
            TaskUpsertOutcome::Stored(row) => assert_eq!(row.task_id, id),
            other => panic!("expected Stored, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upsert_task_returns_stored_on_same_task_id_re_upsert() {
        let (_b, svc) = fresh_backend().await;
        let id = format!("t-{}", Uuid::new_v4().simple());
        let occ = "occ-1";
        let cid = format!("upstream-{}", Uuid::new_v4().simple());
        let t1 = mk_task_with_correlation(&id, occ, &cid);
        let _ = svc.upsert_task(t1.clone()).await.unwrap();

        // Re-upsert same task_id (mutables change): ON CONFLICT(task_id)
        // UPDATE wins — should NOT trip the correlation unique index.
        let mut t2 = t1.clone();
        t2.description = "updated".into();
        let outcome = svc.upsert_task(t2).await.unwrap();
        match outcome {
            TaskUpsertOutcome::Stored(row) => {
                assert_eq!(row.task_id, id);
                assert_eq!(row.description, "updated");
            }
            other => panic!("expected Stored on re-upsert, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upsert_task_returns_already_exists_on_correlation_collision() {
        let (_b, svc) = fresh_backend().await;
        let occ = "occ-1";
        let cid = format!("upstream-{}", Uuid::new_v4().simple());
        let first_id = format!("t1-{}", Uuid::new_v4().simple());
        let first = mk_task_with_correlation(&first_id, occ, &cid);
        let _ = svc.upsert_task(first.clone()).await.unwrap();

        // Different task_id, same (occ, correlation_id) → dedup.
        let second_id = format!("t2-{}", Uuid::new_v4().simple());
        let second = mk_task_with_correlation(&second_id, occ, &cid);
        let outcome = svc.upsert_task(second).await.unwrap();
        match outcome {
            TaskUpsertOutcome::AlreadyExists(row) => {
                // Canonical row is the FIRST, not the caller's.
                assert_eq!(row.task_id, first_id);
                assert_ne!(row.task_id, second_id);
            }
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upsert_task_correlation_index_scoped_to_occurrence() {
        // Same correlation_id under different occurrence is allowed.
        let (_b, svc) = fresh_backend().await;
        let cid = format!("upstream-{}", Uuid::new_v4().simple());
        let id1 = format!("t1-{}", Uuid::new_v4().simple());
        let id2 = format!("t2-{}", Uuid::new_v4().simple());

        let _ = svc
            .upsert_task(mk_task_with_correlation(&id1, "occ-a", &cid))
            .await
            .unwrap();
        let outcome = svc
            .upsert_task(mk_task_with_correlation(&id2, "occ-b", &cid))
            .await
            .unwrap();
        match outcome {
            TaskUpsertOutcome::Stored(row) => assert_eq!(row.task_id, id2),
            other => panic!("expected Stored across occurrences, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upsert_task_no_correlation_id_inserts_normally() {
        // Tasks without correlation_id (or with NULL context) don't
        // participate in the partial index — even thousands of them
        // can coexist without dedup.
        let (_b, svc) = fresh_backend().await;
        let occ = "occ-1";
        for _ in 0..3 {
            let id = format!("t-{}", Uuid::new_v4().simple());
            let outcome = svc
                .upsert_task(mk_task(&id, TaskStatus::Pending, occ))
                .await
                .unwrap();
            assert!(matches!(outcome, TaskUpsertOutcome::Stored(_)));
        }
    }
}
