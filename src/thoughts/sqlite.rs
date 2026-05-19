//! SQLite impl of [`ThoughtService`] (v1.5.10, CIRISPersist#59 #2).
//!
//! Mirrors the v1.5.10 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ              → TEXT (RFC 3339)
//!   JSONB                    → TEXT (raw JSON string)
//!   ON CONFLICT (thought_id) DO UPDATE … → ON CONFLICT (thought_id) DO UPDATE …
//!   WITH RECURSIVE descendants(...) AS  → identical (SQLite 3.8.3+)
//!
//! Threading: `tokio::task::spawn_blocking` + `conn.blocking_lock()`
//! per the existing pattern (mirrors `src/tasks/sqlite.rs`).

use std::sync::Arc;

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use tokio::sync::Mutex;

use super::service::ThoughtService;
use super::types::{
    Thought, ThoughtCursor, ThoughtFilter, ThoughtListPage, ThoughtStatus, ThoughtType,
};
use super::Error;

/// SQLite-backed [`ThoughtService`] impl.
pub struct SqliteThoughtBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteThoughtBackend {
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

fn validate_thought(t: &Thought) -> Result<(), Error> {
    if t.thought_id.is_empty() {
        return Err(Error::InvalidArgument("thought_id required".into()));
    }
    if t.source_task_id.is_empty() {
        return Err(Error::InvalidArgument("source_task_id required".into()));
    }
    if t.content.is_empty() {
        return Err(Error::InvalidArgument("content required".into()));
    }
    if t.agent_occurrence_id.is_empty() {
        return Err(Error::InvalidArgument(
            "agent_occurrence_id required".into(),
        ));
    }
    if t.thought_type.as_str().is_empty() {
        return Err(Error::InvalidArgument("thought_type required".into()));
    }
    if t.round_number < 0 {
        return Err(Error::InvalidArgument(format!(
            "round_number must be >= 0, got {}",
            t.round_number
        )));
    }
    if t.thought_depth < 0 {
        return Err(Error::InvalidArgument(format!(
            "thought_depth must be >= 0, got {}",
            t.thought_depth
        )));
    }
    Ok(())
}

fn decode_thought_row(row: &rusqlite::Row<'_>) -> Result<Thought, Error> {
    let thought_id: String = row
        .get("thought_id")
        .map_err(|e| Error::Backend(format!("decode thought_id: {e}")))?;
    let source_task_id: String = row
        .get("source_task_id")
        .map_err(|e| Error::Backend(format!("decode source_task_id: {e}")))?;
    let channel_id: Option<String> = row
        .get("channel_id")
        .map_err(|e| Error::Backend(format!("decode channel_id: {e}")))?;
    let thought_type_str: String = row
        .get("thought_type")
        .map_err(|e| Error::Backend(format!("decode thought_type: {e}")))?;
    let status_str: String = row
        .get("status")
        .map_err(|e| Error::Backend(format!("decode status: {e}")))?;
    let status = ThoughtStatus::parse_str(&status_str)
        .ok_or_else(|| Error::Backend(format!("unknown status: {status_str}")))?;
    let created_at_str: String = row
        .get("created_at")
        .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?;
    let updated_at_str: String = row
        .get("updated_at")
        .map_err(|e| Error::Backend(format!("decode updated_at: {e}")))?;
    let round_number: i32 = row
        .get("round_number")
        .map_err(|e| Error::Backend(format!("decode round_number: {e}")))?;
    let content: String = row
        .get("content")
        .map_err(|e| Error::Backend(format!("decode content: {e}")))?;
    let context_raw: Option<String> = row
        .get("context_json")
        .map_err(|e| Error::Backend(format!("decode context_json: {e}")))?;
    let thought_depth: i32 = row
        .get("thought_depth")
        .map_err(|e| Error::Backend(format!("decode thought_depth: {e}")))?;
    let ponder_notes_raw: Option<String> = row
        .get("ponder_notes_json")
        .map_err(|e| Error::Backend(format!("decode ponder_notes_json: {e}")))?;
    let parent_thought_id: Option<String> = row
        .get("parent_thought_id")
        .map_err(|e| Error::Backend(format!("decode parent_thought_id: {e}")))?;
    let final_action_raw: Option<String> = row
        .get("final_action_json")
        .map_err(|e| Error::Backend(format!("decode final_action_json: {e}")))?;
    let agent_occurrence_id: String = row
        .get("agent_occurrence_id")
        .map_err(|e| Error::Backend(format!("decode agent_occurrence_id: {e}")))?;
    Ok(Thought {
        thought_id,
        source_task_id,
        channel_id,
        thought_type: ThoughtType(thought_type_str),
        status,
        created_at: parse_datetime(&created_at_str)?,
        updated_at: parse_datetime(&updated_at_str)?,
        round_number,
        content,
        context: decode_json_opt(context_raw)?,
        thought_depth,
        ponder_notes: decode_json_opt(ponder_notes_raw)?,
        parent_thought_id,
        final_action: decode_json_opt(final_action_raw)?,
        agent_occurrence_id,
    })
}

impl ThoughtService for SqliteThoughtBackend {
    async fn upsert_thought(&self, thought: Thought) -> Result<(), Error> {
        validate_thought(&thought)?;
        let context_str = encode_json_opt(thought.context.as_ref())?;
        let ponder_notes_str = encode_json_opt(thought.ponder_notes.as_ref())?;
        let final_action_str = encode_json_opt(thought.final_action.as_ref())?;
        let created_at_str = fmt_datetime(thought.created_at);
        let updated_at_str = fmt_datetime(thought.updated_at);
        let status_str = thought.status.as_sql_str().to_owned();
        let thought_type_str = thought.thought_type.0.clone();

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let mut guard = conn.blocking_lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "upsert_thought begin"))?;
            // ON CONFLICT (thought_id) DO UPDATE — preserves created_at
            // (excluded.created_at is ignored). Every other column is
            // updated from the new row.
            tx.execute(
                "INSERT INTO cirislens_thoughts (\
                    thought_id, source_task_id, channel_id, thought_type, status, \
                    created_at, updated_at, round_number, content, context_json, \
                    thought_depth, ponder_notes_json, parent_thought_id, \
                    final_action_json, agent_occurrence_id\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                           ?15) \
                 ON CONFLICT(thought_id) DO UPDATE SET \
                    source_task_id = excluded.source_task_id, \
                    channel_id = excluded.channel_id, \
                    thought_type = excluded.thought_type, \
                    status = excluded.status, \
                    updated_at = excluded.updated_at, \
                    round_number = excluded.round_number, \
                    content = excluded.content, \
                    context_json = excluded.context_json, \
                    thought_depth = excluded.thought_depth, \
                    ponder_notes_json = excluded.ponder_notes_json, \
                    parent_thought_id = excluded.parent_thought_id, \
                    final_action_json = excluded.final_action_json, \
                    agent_occurrence_id = excluded.agent_occurrence_id",
                params![
                    thought.thought_id,
                    thought.source_task_id,
                    thought.channel_id,
                    thought_type_str,
                    status_str,
                    created_at_str,
                    updated_at_str,
                    thought.round_number,
                    thought.content,
                    context_str,
                    thought.thought_depth,
                    ponder_notes_str,
                    thought.parent_thought_id,
                    final_action_str,
                    thought.agent_occurrence_id,
                ],
            )
            .map_err(|e| map_sqlite_error(e, "upsert_thought insert"))?;
            tx.commit()
                .map_err(|e| map_sqlite_error(e, "upsert_thought commit"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn get_thought(&self, thought_id: &str) -> Result<Option<Thought>, Error> {
        if thought_id.is_empty() {
            return Err(Error::InvalidArgument("thought_id required".into()));
        }
        let conn = self.conn.clone();
        let thought_id_owned = thought_id.to_owned();
        tokio::task::spawn_blocking(move || -> Result<Option<Thought>, Error> {
            let guard = conn.blocking_lock();
            let row_opt = guard
                .query_row(
                    "SELECT thought_id, source_task_id, channel_id, thought_type, status, \
                            created_at, updated_at, round_number, content, context_json, \
                            thought_depth, ponder_notes_json, parent_thought_id, \
                            final_action_json, agent_occurrence_id \
                     FROM cirislens_thoughts WHERE thought_id = ?1",
                    params![thought_id_owned],
                    |row| Ok(decode_thought_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_thought query"))?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(r?)),
            }
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn list_thoughts(
        &self,
        filter: ThoughtFilter,
        cursor: Option<ThoughtCursor>,
        limit: i64,
    ) -> Result<ThoughtListPage, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let mut where_parts: Vec<String> = Vec::new();
        let mut sql_params: Vec<SqlValue> = Vec::new();
        if let Some(task) = filter.source_task_id {
            sql_params.push(SqlValue::Text(task));
            where_parts.push(format!("source_task_id = ?{}", sql_params.len()));
        }
        if let Some(status) = filter.status {
            sql_params.push(SqlValue::Text(status.as_sql_str().to_owned()));
            where_parts.push(format!("status = ?{}", sql_params.len()));
        }
        if let Some(occ) = filter.agent_occurrence_id {
            sql_params.push(SqlValue::Text(occ));
            where_parts.push(format!("agent_occurrence_id = ?{}", sql_params.len()));
        }
        if let Some(parent) = filter.parent_thought_id {
            sql_params.push(SqlValue::Text(parent));
            where_parts.push(format!("parent_thought_id = ?{}", sql_params.len()));
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
                    "ThoughtCursor version {} unsupported",
                    cur.version
                )));
            }
            sql_params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
            let p_ts = sql_params.len();
            sql_params.push(SqlValue::Text(cur.last_id.clone()));
            let p_id = sql_params.len();
            where_parts.push(format!("(updated_at, thought_id) < (?{p_ts}, ?{p_id})"));
        }
        sql_params.push(SqlValue::Integer(limit));
        let p_limit = sql_params.len();
        let where_sql = if where_parts.is_empty() {
            "1=1".to_string()
        } else {
            where_parts.join(" AND ")
        };
        let sql = format!(
            "SELECT thought_id, source_task_id, channel_id, thought_type, status, \
                    created_at, updated_at, round_number, content, context_json, \
                    thought_depth, ponder_notes_json, parent_thought_id, \
                    final_action_json, agent_occurrence_id \
             FROM cirislens_thoughts \
             WHERE {where_sql} \
             ORDER BY updated_at DESC, thought_id DESC \
             LIMIT ?{p_limit}"
        );
        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        tokio::task::spawn_blocking(move || -> Result<ThoughtListPage, Error> {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "list_thoughts prepare"))?;
            let rows_iter = stmt
                .query_map(params_from_iter(sql_params.iter()), |row| {
                    Ok(decode_thought_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "list_thoughts query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "list_thoughts row"))??);
            }
            let next_cursor = if items.len() == limit_usize {
                items.last().map(|last| {
                    ThoughtCursor::from_trailing(last.updated_at, last.thought_id.clone())
                })
            } else {
                None
            };
            Ok(ThoughtListPage { items, next_cursor })
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn update_thought_status(
        &self,
        thought_id: &str,
        new_status: ThoughtStatus,
        final_action: Option<serde_json::Value>,
    ) -> Result<bool, Error> {
        if thought_id.is_empty() {
            return Err(Error::InvalidArgument("thought_id required".into()));
        }
        let final_action_str = encode_json_opt(final_action.as_ref())?;
        let now_str = fmt_datetime(chrono::Utc::now());
        let status_sql = new_status.as_sql_str().to_owned();
        let thought_id_owned = thought_id.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<bool, Error> {
            let guard = conn.blocking_lock();
            // COALESCE($final_action, final_action_json) — preserve
            // existing value if caller didn't supply one. Caller can
            // pass serde_json::Value::Null via Some(Value::Null) to
            // overwrite with NULL.
            let changed = guard
                .execute(
                    "UPDATE cirislens_thoughts SET \
                        status = ?1, \
                        updated_at = ?2, \
                        final_action_json = COALESCE(?3, final_action_json) \
                     WHERE thought_id = ?4",
                    params![status_sql, now_str, final_action_str, thought_id_owned],
                )
                .map_err(|e| map_sqlite_error(e, "update_thought_status exec"))?;
            Ok(changed > 0)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn get_descendants(&self, thought_id: &str) -> Result<Vec<Thought>, Error> {
        if thought_id.is_empty() {
            return Err(Error::InvalidArgument("thought_id required".into()));
        }
        let thought_id_owned = thought_id.to_owned();
        let conn = self.conn.clone();
        // Recursive CTE walks the parent_thought_id chain from the
        // root. Same shape as the PG impl + cirisgraph's k-hop CTE
        // (`src/graph/sqlite.rs`). Ordering: `thought_depth ASC,
        // thought_id ASC` for deterministic output.
        tokio::task::spawn_blocking(move || -> Result<Vec<Thought>, Error> {
            let guard = conn.blocking_lock();
            let sql = "WITH RECURSIVE descendants AS ( \
                SELECT thought_id, source_task_id, channel_id, thought_type, status, \
                       created_at, updated_at, round_number, content, context_json, \
                       thought_depth, ponder_notes_json, parent_thought_id, \
                       final_action_json, agent_occurrence_id \
                  FROM cirislens_thoughts \
                  WHERE thought_id = ?1 \
                UNION ALL \
                SELECT t.thought_id, t.source_task_id, t.channel_id, t.thought_type, t.status, \
                       t.created_at, t.updated_at, t.round_number, t.content, t.context_json, \
                       t.thought_depth, t.ponder_notes_json, t.parent_thought_id, \
                       t.final_action_json, t.agent_occurrence_id \
                  FROM cirislens_thoughts t \
                  JOIN descendants d ON t.parent_thought_id = d.thought_id \
            ) \
            SELECT thought_id, source_task_id, channel_id, thought_type, status, \
                   created_at, updated_at, round_number, content, context_json, \
                   thought_depth, ponder_notes_json, parent_thought_id, \
                   final_action_json, agent_occurrence_id \
            FROM descendants \
            ORDER BY thought_depth ASC, thought_id ASC";
            let mut stmt = guard
                .prepare(sql)
                .map_err(|e| map_sqlite_error(e, "get_descendants prepare"))?;
            let rows_iter = stmt
                .query_map(params![thought_id_owned], |row| Ok(decode_thought_row(row)))
                .map_err(|e| map_sqlite_error(e, "get_descendants query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "get_descendants row"))??);
            }
            Ok(items)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn delete_thought(&self, thought_id: &str) -> Result<bool, Error> {
        if thought_id.is_empty() {
            return Err(Error::InvalidArgument("thought_id required".into()));
        }
        let thought_id_owned = thought_id.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<bool, Error> {
            let guard = conn.blocking_lock();
            // The store always opens connections with
            // `PRAGMA foreign_keys = ON` so the self-FK on
            // `parent_thought_id` rejects a delete that would orphan
            // children. Caller deletes leaves-first or walks
            // `get_descendants` before issuing the delete.
            let changed = guard
                .execute(
                    "DELETE FROM cirislens_thoughts WHERE thought_id = ?1",
                    params![thought_id_owned],
                )
                .map_err(|e| map_sqlite_error(e, "delete_thought exec"))?;
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
    use crate::tasks::sqlite::SqliteTaskBackend;
    use crate::tasks::{Task, TaskService, TaskStatus};
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteTaskBackend, SqliteThoughtBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let tasks = SqliteTaskBackend::new(backend.conn_handle());
        let thoughts = SqliteThoughtBackend::new(backend.conn_handle());
        (backend, tasks, thoughts)
    }

    fn mk_task(id: &str, occurrence: &str) -> Task {
        let now = chrono::Utc::now();
        Task {
            task_id: id.to_owned(),
            channel_id: "chan-default".into(),
            description: format!("desc-{id}"),
            status: TaskStatus::Pending,
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

    fn mk_thought(id: &str, task_id: &str, status: ThoughtStatus, occurrence: &str) -> Thought {
        let now = chrono::Utc::now();
        Thought {
            thought_id: id.to_owned(),
            source_task_id: task_id.to_owned(),
            channel_id: None,
            thought_type: ThoughtType::standard(),
            status,
            created_at: now,
            updated_at: now,
            round_number: 0,
            content: format!("content-{id}"),
            context: None,
            thought_depth: 0,
            ponder_notes: None,
            parent_thought_id: None,
            final_action: None,
            agent_occurrence_id: occurrence.to_owned(),
        }
    }

    #[tokio::test]
    async fn upsert_get_round_trip_all_14_columns() {
        let (_b, tasks, thoughts) = fresh_backend().await;
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        tasks.upsert_task(mk_task(&task_id, "occ-1")).await.unwrap();

        let id = format!("th-{}", Uuid::new_v4().simple());
        let now = chrono::Utc::now();
        let t = Thought {
            thought_id: id.clone(),
            source_task_id: task_id.clone(),
            channel_id: Some("chan-x".into()),
            thought_type: ThoughtType::reflection(),
            status: ThoughtStatus::Processing,
            created_at: now,
            updated_at: now,
            round_number: 3,
            content: "reasoning now".into(),
            context: Some(serde_json::json!({"k": "v"})),
            thought_depth: 1,
            ponder_notes: Some(serde_json::json!(["n1", "n2"])),
            parent_thought_id: None,
            final_action: Some(serde_json::json!({"act": "speak"})),
            agent_occurrence_id: "occ-1".into(),
        };
        thoughts.upsert_thought(t.clone()).await.unwrap();
        let got = thoughts.get_thought(&id).await.unwrap().expect("present");
        assert_eq!(got.thought_id, t.thought_id);
        assert_eq!(got.source_task_id, t.source_task_id);
        assert_eq!(got.channel_id, t.channel_id);
        assert_eq!(got.thought_type, t.thought_type);
        assert_eq!(got.status, t.status);
        assert_eq!(got.round_number, t.round_number);
        assert_eq!(got.content, t.content);
        assert_eq!(got.context, t.context);
        assert_eq!(got.thought_depth, t.thought_depth);
        assert_eq!(got.ponder_notes, t.ponder_notes);
        assert_eq!(got.parent_thought_id, t.parent_thought_id);
        assert_eq!(got.final_action, t.final_action);
        assert_eq!(got.agent_occurrence_id, t.agent_occurrence_id);
    }

    #[tokio::test]
    async fn upsert_idempotent_same_payload_noop_diff_payload_overwrites() {
        let (_b, tasks, thoughts) = fresh_backend().await;
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        tasks.upsert_task(mk_task(&task_id, "occ-1")).await.unwrap();

        let id = format!("th-{}", Uuid::new_v4().simple());
        let mut t = mk_thought(&id, &task_id, ThoughtStatus::Pending, "occ-1");
        t.content = "first".into();
        thoughts.upsert_thought(t.clone()).await.unwrap();
        // Same payload — idempotent.
        thoughts.upsert_thought(t.clone()).await.unwrap();
        let got = thoughts.get_thought(&id).await.unwrap().expect("present");
        assert_eq!(got.content, "first");

        // Different payload — mutable cols overwritten; created_at
        // unchanged.
        let original_created = got.created_at;
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let mut t2 = t.clone();
        t2.content = "second".into();
        t2.status = ThoughtStatus::Processing;
        t2.updated_at = chrono::Utc::now();
        thoughts.upsert_thought(t2).await.unwrap();
        let got2 = thoughts.get_thought(&id).await.unwrap().expect("present");
        assert_eq!(got2.content, "second");
        assert_eq!(got2.status, ThoughtStatus::Processing);
        assert_eq!(got2.created_at, original_created);
    }

    #[tokio::test]
    async fn fk_to_tasks_rejects_nonexistent_task() {
        let (_b, _tasks, thoughts) = fresh_backend().await;
        let ghost_task = format!("ghost-{}", Uuid::new_v4().simple());
        let id = format!("th-{}", Uuid::new_v4().simple());
        let t = mk_thought(&id, &ghost_task, ThoughtStatus::Pending, "occ-1");
        let err = thoughts.upsert_thought(t).await.unwrap_err();
        assert!(
            matches!(err, Error::Conflict(_)),
            "expected Conflict (FK), got {err:?}"
        );
    }

    #[tokio::test]
    async fn self_fk_parent_thought_rejects_nonexistent() {
        let (_b, tasks, thoughts) = fresh_backend().await;
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        tasks.upsert_task(mk_task(&task_id, "occ-1")).await.unwrap();

        let id = format!("th-{}", Uuid::new_v4().simple());
        let mut t = mk_thought(&id, &task_id, ThoughtStatus::Pending, "occ-1");
        t.parent_thought_id = Some(format!("ghost-{}", Uuid::new_v4().simple()));
        let err = thoughts.upsert_thought(t).await.unwrap_err();
        assert!(
            matches!(err, Error::Conflict(_)),
            "expected Conflict (FK), got {err:?}"
        );
    }

    #[tokio::test]
    async fn list_filter_by_task_status_occurrence() {
        let (_b, tasks, thoughts) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        tasks.upsert_task(mk_task(&task_id, &occ)).await.unwrap();

        let ids: Vec<String> = (0..3)
            .map(|i| format!("th{i}-{}", Uuid::new_v4().simple()))
            .collect();
        // 1 pending, 2 processing.
        for (i, id) in ids.iter().enumerate() {
            let status = if i == 0 {
                ThoughtStatus::Pending
            } else {
                ThoughtStatus::Processing
            };
            thoughts
                .upsert_thought(mk_thought(id, &task_id, status, &occ))
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        // Filter by source_task_id → 3.
        let page = thoughts
            .list_thoughts(
                ThoughtFilter {
                    source_task_id: Some(task_id.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 3);

        // Filter by occurrence + Processing → 2.
        let page = thoughts
            .list_thoughts(
                ThoughtFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    status: Some(ThoughtStatus::Processing),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);

        // Filter by occurrence only → 3.
        let page = thoughts
            .list_thoughts(
                ThoughtFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 3);
    }

    #[tokio::test]
    async fn list_cursor_pagination() {
        let (_b, tasks, thoughts) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        tasks.upsert_task(mk_task(&task_id, &occ)).await.unwrap();
        let mut ids = Vec::new();
        for i in 0..5 {
            let id = format!("th{i}-{}", Uuid::new_v4().simple());
            ids.push(id.clone());
            thoughts
                .upsert_thought(mk_thought(&id, &task_id, ThoughtStatus::Pending, &occ))
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        let filter = ThoughtFilter {
            agent_occurrence_id: Some(occ.clone()),
            ..Default::default()
        };
        let page1 = thoughts
            .list_thoughts(filter.clone(), None, 2)
            .await
            .unwrap();
        assert_eq!(page1.items.len(), 2);
        assert!(page1.next_cursor.is_some());
        let page2 = thoughts
            .list_thoughts(filter.clone(), page1.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(page2.items.len(), 2);
        let page3 = thoughts
            .list_thoughts(filter.clone(), page2.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(page3.items.len(), 1);
        assert!(page3.next_cursor.is_none());
        // Union covers ids.
        let mut seen: Vec<String> = page1
            .items
            .iter()
            .chain(page2.items.iter())
            .chain(page3.items.iter())
            .map(|t| t.thought_id.clone())
            .collect();
        seen.sort();
        let mut expected = ids.clone();
        expected.sort();
        assert_eq!(seen, expected);
    }

    #[tokio::test]
    async fn update_status_success_final_action_merge_missing_row() {
        let (_b, tasks, thoughts) = fresh_backend().await;
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        tasks.upsert_task(mk_task(&task_id, "occ-1")).await.unwrap();

        let id = format!("th-{}", Uuid::new_v4().simple());
        thoughts
            .upsert_thought(mk_thought(&id, &task_id, ThoughtStatus::Pending, "occ-1"))
            .await
            .unwrap();

        // Status update without final_action — final_action stays NULL.
        let ok = thoughts
            .update_thought_status(&id, ThoughtStatus::Processing, None)
            .await
            .unwrap();
        assert!(ok);
        let got = thoughts.get_thought(&id).await.unwrap().expect("present");
        assert_eq!(got.status, ThoughtStatus::Processing);
        assert!(got.final_action.is_none());

        // Update to Completed with final_action — final_action lands.
        let ok = thoughts
            .update_thought_status(
                &id,
                ThoughtStatus::Completed,
                Some(serde_json::json!({"action": "speak"})),
            )
            .await
            .unwrap();
        assert!(ok);
        let got = thoughts.get_thought(&id).await.unwrap().expect("present");
        assert_eq!(got.status, ThoughtStatus::Completed);
        assert_eq!(
            got.final_action,
            Some(serde_json::json!({"action": "speak"}))
        );

        // Missing thought → false (not an error).
        let ok = thoughts
            .update_thought_status("nonexistent", ThoughtStatus::Failed, None)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn get_descendants_3_level_tree_returns_7_rows() {
        let (_b, tasks, thoughts) = fresh_backend().await;
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        tasks.upsert_task(mk_task(&task_id, "occ-1")).await.unwrap();

        // 3-level tree: root → 2 children → 1 grandchild each → 7 rows.
        let root = format!("root-{}", Uuid::new_v4().simple());
        let mut th = mk_thought(&root, &task_id, ThoughtStatus::Pending, "occ-1");
        th.thought_depth = 0;
        thoughts.upsert_thought(th).await.unwrap();

        let mut child_ids = Vec::new();
        for ci in 0..2 {
            let child_id = format!("c{ci}-{}", Uuid::new_v4().simple());
            child_ids.push(child_id.clone());
            let mut th = mk_thought(&child_id, &task_id, ThoughtStatus::Pending, "occ-1");
            th.parent_thought_id = Some(root.clone());
            th.thought_depth = 1;
            thoughts.upsert_thought(th).await.unwrap();
        }
        for child_id in &child_ids {
            for gi in 0..2 {
                let g_id = format!("g{gi}-{}", Uuid::new_v4().simple());
                let mut th = mk_thought(&g_id, &task_id, ThoughtStatus::Pending, "occ-1");
                th.parent_thought_id = Some(child_id.clone());
                th.thought_depth = 2;
                thoughts.upsert_thought(th).await.unwrap();
            }
        }

        let descendants = thoughts.get_descendants(&root).await.unwrap();
        // root (1) + children (2) + grandchildren (4) = 7
        assert_eq!(descendants.len(), 7);
        // First row is the root.
        assert_eq!(descendants[0].thought_id, root);
        assert_eq!(descendants[0].thought_depth, 0);
        // Next two at depth 1, last four at depth 2.
        assert!(descendants
            .iter()
            .skip(1)
            .take(2)
            .all(|t| t.thought_depth == 1));
        assert!(descendants.iter().skip(3).all(|t| t.thought_depth == 2));
    }

    #[tokio::test]
    async fn get_descendants_unknown_root_returns_empty() {
        let (_b, _tasks, thoughts) = fresh_backend().await;
        let v = thoughts
            .get_descendants(&format!("ghost-{}", Uuid::new_v4().simple()))
            .await
            .unwrap();
        assert!(v.is_empty());
    }

    #[tokio::test]
    async fn get_descendants_single_leaf_returns_self_only() {
        let (_b, tasks, thoughts) = fresh_backend().await;
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        tasks.upsert_task(mk_task(&task_id, "occ-1")).await.unwrap();
        let id = format!("th-{}", Uuid::new_v4().simple());
        thoughts
            .upsert_thought(mk_thought(&id, &task_id, ThoughtStatus::Pending, "occ-1"))
            .await
            .unwrap();
        let v = thoughts.get_descendants(&id).await.unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].thought_id, id);
    }

    // ── v1.5.20 (CIRISPersist#60) delete_thought + FK cascade ────────

    #[tokio::test]
    async fn delete_thought_returns_true_then_false() {
        let (_b, tasks, thoughts) = fresh_backend().await;
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        tasks.upsert_task(mk_task(&task_id, "occ-1")).await.unwrap();
        let id = format!("th-{}", Uuid::new_v4().simple());
        thoughts
            .upsert_thought(mk_thought(&id, &task_id, ThoughtStatus::Pending, "occ-1"))
            .await
            .unwrap();

        let first = thoughts.delete_thought(&id).await.unwrap();
        assert!(first);
        let second = thoughts.delete_thought(&id).await.unwrap();
        assert!(!second);
        assert!(thoughts.get_thought(&id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn delete_thought_empty_id_rejected() {
        let (_b, _tasks, thoughts) = fresh_backend().await;
        let err = thoughts.delete_thought("").await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn delete_thought_parent_with_children_rejects() {
        let (_b, tasks, thoughts) = fresh_backend().await;
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        tasks.upsert_task(mk_task(&task_id, "occ-1")).await.unwrap();

        let parent = format!("p-{}", Uuid::new_v4().simple());
        thoughts
            .upsert_thought(mk_thought(
                &parent,
                &task_id,
                ThoughtStatus::Pending,
                "occ-1",
            ))
            .await
            .unwrap();
        let child = format!("c-{}", Uuid::new_v4().simple());
        let mut child_t = mk_thought(&child, &task_id, ThoughtStatus::Pending, "occ-1");
        child_t.parent_thought_id = Some(parent.clone());
        thoughts.upsert_thought(child_t).await.unwrap();

        // Parent has a child via parent_thought_id self-FK — strict.
        let err = thoughts.delete_thought(&parent).await.unwrap_err();
        assert!(
            matches!(err, Error::Conflict(_)),
            "expected Conflict (FK), got {err:?}"
        );

        // Leaves-first works.
        assert!(thoughts.delete_thought(&child).await.unwrap());
        assert!(thoughts.delete_thought(&parent).await.unwrap());
    }

    // ── v1.5.21 (CIRISPersist#62) created_before/created_after ───────

    #[tokio::test]
    async fn list_filter_created_range_combination() {
        use chrono::Duration as ChronoDuration;
        let (_b, tasks, thoughts) = fresh_backend().await;
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        tasks.upsert_task(mk_task(&task_id, "occ-1")).await.unwrap();

        let now = chrono::Utc::now();
        // 3 thoughts at -72h / -24h / now.
        for (label, offset_h) in &[("a", -72), ("b", -24), ("c", 0)] {
            let id = format!("{label}-{}", Uuid::new_v4().simple());
            let mut t = mk_thought(&id, &task_id, ThoughtStatus::Pending, "occ-1");
            t.created_at = now + ChronoDuration::hours(*offset_h);
            t.updated_at = t.created_at;
            thoughts.upsert_thought(t).await.unwrap();
        }

        let page = thoughts
            .list_thoughts(
                ThoughtFilter {
                    agent_occurrence_id: Some("occ-1".into()),
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
        assert!(page.items[0].thought_id.starts_with("b-"));
    }

    #[tokio::test]
    async fn task_delete_cascades_to_thoughts() {
        // V035: source_task_id FK is ON DELETE CASCADE. Deleting a
        // parent task takes its thoughts with it.
        let (_b, tasks, thoughts) = fresh_backend().await;
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        tasks.upsert_task(mk_task(&task_id, "occ-1")).await.unwrap();

        // Two flat thoughts (no parent_thought_id chain so the self-FK
        // doesn't interfere).
        let th1 = format!("th1-{}", Uuid::new_v4().simple());
        let th2 = format!("th2-{}", Uuid::new_v4().simple());
        thoughts
            .upsert_thought(mk_thought(&th1, &task_id, ThoughtStatus::Pending, "occ-1"))
            .await
            .unwrap();
        thoughts
            .upsert_thought(mk_thought(&th2, &task_id, ThoughtStatus::Pending, "occ-1"))
            .await
            .unwrap();

        assert!(tasks.delete_task(&task_id).await.unwrap());

        // Both thoughts are gone via cascade.
        assert!(thoughts.get_thought(&th1).await.unwrap().is_none());
        assert!(thoughts.get_thought(&th2).await.unwrap().is_none());
    }
}
