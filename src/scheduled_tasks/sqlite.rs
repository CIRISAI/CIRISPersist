//! SQLite impl of [`ScheduledTaskService`] (v1.5.12,
//! CIRISPersist#59 #4).
//!
//! Mirrors the v1.5.12 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ                  → TEXT (RFC 3339)
//!   JSONB                        → TEXT (raw JSON string)
//!   ON CONFLICT (id) DO UPDATE   → identical
//!   FK to cirislens_thoughts     → immediate (SQLite doesn't honor
//!                                  DEFERRABLE without per-tx
//!                                  `PRAGMA defer_foreign_keys=1`)
//!
//! Threading: `tokio::task::spawn_blocking` + `conn.lock()`
//! per the existing pattern.
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
use rusqlite::{params, Connection};

use super::service::ScheduledTaskService;
use super::types::{ScheduledTask, ScheduledTaskStatus};
use super::Error;

/// SQLite-backed [`ScheduledTaskService`] impl.
pub struct SqliteScheduledTaskBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteScheduledTaskBackend {
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

fn decode_scheduled_task_row(row: &rusqlite::Row<'_>) -> Result<ScheduledTask, Error> {
    let id: String = row
        .get("id")
        .map_err(|e| Error::Backend(format!("decode id: {e}")))?;
    let name: String = row
        .get("name")
        .map_err(|e| Error::Backend(format!("decode name: {e}")))?;
    let goal_description: String = row
        .get("goal_description")
        .map_err(|e| Error::Backend(format!("decode goal_description: {e}")))?;
    let status_str: String = row
        .get("status")
        .map_err(|e| Error::Backend(format!("decode status: {e}")))?;
    let status = ScheduledTaskStatus::parse_str(&status_str)
        .ok_or_else(|| Error::Backend(format!("unknown status: {status_str}")))?;
    let defer_until_str: Option<String> = row
        .get("defer_until")
        .map_err(|e| Error::Backend(format!("decode defer_until: {e}")))?;
    let schedule_cron: Option<String> = row
        .get("schedule_cron")
        .map_err(|e| Error::Backend(format!("decode schedule_cron: {e}")))?;
    let trigger_prompt: String = row
        .get("trigger_prompt")
        .map_err(|e| Error::Backend(format!("decode trigger_prompt: {e}")))?;
    let origin_thought_id: String = row
        .get("origin_thought_id")
        .map_err(|e| Error::Backend(format!("decode origin_thought_id: {e}")))?;
    let created_at_str: String = row
        .get("created_at")
        .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?;
    let last_triggered_at_str: Option<String> = row
        .get("last_triggered_at")
        .map_err(|e| Error::Backend(format!("decode last_triggered_at: {e}")))?;
    let next_trigger_at_str: Option<String> = row
        .get("next_trigger_at")
        .map_err(|e| Error::Backend(format!("decode next_trigger_at: {e}")))?;
    let deferral_count: i32 = row
        .get("deferral_count")
        .map_err(|e| Error::Backend(format!("decode deferral_count: {e}")))?;
    let deferral_history_raw: Option<String> = row
        .get("deferral_history")
        .map_err(|e| Error::Backend(format!("decode deferral_history: {e}")))?;
    let created_by_agent: Option<String> = row
        .get("created_by_agent")
        .map_err(|e| Error::Backend(format!("decode created_by_agent: {e}")))?;
    let agent_occurrence_id: String = row
        .get("agent_occurrence_id")
        .map_err(|e| Error::Backend(format!("decode agent_occurrence_id: {e}")))?;
    Ok(ScheduledTask {
        id,
        name,
        goal_description,
        status,
        defer_until: parse_datetime_opt(defer_until_str)?,
        schedule_cron,
        trigger_prompt,
        origin_thought_id,
        created_at: parse_datetime(&created_at_str)?,
        last_triggered_at: parse_datetime_opt(last_triggered_at_str)?,
        next_trigger_at: parse_datetime_opt(next_trigger_at_str)?,
        deferral_count,
        deferral_history: decode_json_opt(deferral_history_raw)?,
        created_by_agent,
        agent_occurrence_id,
    })
}

impl ScheduledTaskService for SqliteScheduledTaskBackend {
    async fn upsert_scheduled_task(&self, task: ScheduledTask) -> Result<(), Error> {
        validate_scheduled_task(&task)?;
        let status_str = task.status.as_sql_str().to_owned();
        let defer_until_str = task.defer_until.map(fmt_datetime);
        let created_at_str = fmt_datetime(task.created_at);
        let last_triggered_at_str = task.last_triggered_at.map(fmt_datetime);
        let next_trigger_at_str = task.next_trigger_at.map(fmt_datetime);
        let deferral_history_str = encode_json_opt(task.deferral_history.as_ref())?;

        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let mut guard = conn.lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "upsert_scheduled_task begin"))?;
            tx.execute(
                "INSERT INTO cirislens_scheduled_tasks (\
                    id, name, goal_description, status, defer_until, \
                    schedule_cron, trigger_prompt, origin_thought_id, \
                    created_at, last_triggered_at, next_trigger_at, \
                    deferral_count, deferral_history, created_by_agent, \
                    agent_occurrence_id\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, \
                           ?11, ?12, ?13, ?14, ?15) \
                 ON CONFLICT(id) DO UPDATE SET \
                    name = excluded.name, \
                    goal_description = excluded.goal_description, \
                    status = excluded.status, \
                    defer_until = excluded.defer_until, \
                    schedule_cron = excluded.schedule_cron, \
                    trigger_prompt = excluded.trigger_prompt, \
                    origin_thought_id = excluded.origin_thought_id, \
                    last_triggered_at = excluded.last_triggered_at, \
                    next_trigger_at = excluded.next_trigger_at, \
                    deferral_count = excluded.deferral_count, \
                    deferral_history = excluded.deferral_history, \
                    created_by_agent = excluded.created_by_agent, \
                    agent_occurrence_id = excluded.agent_occurrence_id",
                params![
                    task.id,
                    task.name,
                    task.goal_description,
                    status_str,
                    defer_until_str,
                    task.schedule_cron,
                    task.trigger_prompt,
                    task.origin_thought_id,
                    created_at_str,
                    last_triggered_at_str,
                    next_trigger_at_str,
                    task.deferral_count,
                    deferral_history_str,
                    task.created_by_agent,
                    task.agent_occurrence_id,
                ],
            )
            .map_err(|e| map_sqlite_error(e, "upsert_scheduled_task insert"))?;
            tx.commit()
                .map_err(|e| map_sqlite_error(e, "upsert_scheduled_task commit"))?;
            Ok(())
        })()
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
        let occ_owned = agent_occurrence_id.to_owned();
        let now_str = fmt_datetime(now);
        let conn = self.conn.clone();
        (move || -> Result<Vec<ScheduledTask>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(
                    "SELECT id, name, goal_description, status, defer_until, \
                            schedule_cron, trigger_prompt, origin_thought_id, \
                            created_at, last_triggered_at, next_trigger_at, \
                            deferral_count, deferral_history, created_by_agent, \
                            agent_occurrence_id \
                     FROM cirislens_scheduled_tasks \
                     WHERE agent_occurrence_id = ?1 \
                       AND next_trigger_at IS NOT NULL \
                       AND next_trigger_at <= ?2 \
                       AND status IN ('PENDING', 'ACTIVE') \
                     ORDER BY next_trigger_at ASC \
                     LIMIT ?3",
                )
                .map_err(|e| map_sqlite_error(e, "list_due_scheduled_tasks prepare"))?;
            let rows_iter = stmt
                .query_map(params![occ_owned, now_str, limit], |row| {
                    Ok(decode_scheduled_task_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "list_due_scheduled_tasks query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "list_due_scheduled_tasks row"))??);
            }
            Ok(items)
        })()
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
        let last_triggered_at_str = fmt_datetime(last_triggered_at);
        let next_trigger_at_str = next_trigger_at.map(fmt_datetime);
        let deferral_history_str = match deferral_history {
            Some(v) => Some(encode_json_opt(Some(&v))?.unwrap()),
            None => None,
        };
        let status_str = new_status.map(|s| s.as_sql_str().to_owned());
        let task_id_owned = task_id.to_owned();

        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let guard = conn.lock();
            // Dynamically build SET clause so callers that don't
            // supply history/status don't overwrite those columns.
            let mut sets: Vec<String> = vec![
                "last_triggered_at = ?2".into(),
                "next_trigger_at = ?3".into(),
                "deferral_count = ?4".into(),
            ];
            let mut sql_params: Vec<rusqlite::types::Value> = vec![
                rusqlite::types::Value::Text(task_id_owned.clone()),
                rusqlite::types::Value::Text(last_triggered_at_str),
                match next_trigger_at_str {
                    Some(s) => rusqlite::types::Value::Text(s),
                    None => rusqlite::types::Value::Null,
                },
                rusqlite::types::Value::Integer(deferral_count as i64),
            ];
            if let Some(history) = deferral_history_str {
                sql_params.push(rusqlite::types::Value::Text(history));
                sets.push(format!("deferral_history = ?{}", sql_params.len()));
            }
            if let Some(status) = status_str {
                sql_params.push(rusqlite::types::Value::Text(status));
                sets.push(format!("status = ?{}", sql_params.len()));
            }
            let sql = format!(
                "UPDATE cirislens_scheduled_tasks SET {} WHERE id = ?1",
                sets.join(", ")
            );
            let changed = guard
                .execute(&sql, rusqlite::params_from_iter(sql_params.iter()))
                .map_err(|e| map_sqlite_error(e, "update_after_trigger exec"))?;
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

    async fn fresh_backend() -> (SqliteBackend, SqliteScheduledTaskBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteScheduledTaskBackend::new(backend.conn_handle());
        (backend, svc)
    }

    async fn seed_parent_thought(b: &SqliteBackend) -> String {
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
        thoughts.upsert_thought(thought).await.unwrap();
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
    async fn upsert_round_trip_all_15_columns() {
        let (b, svc) = fresh_backend().await;
        let thought_id = seed_parent_thought(&b).await;
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
        svc.upsert_scheduled_task(t.clone()).await.unwrap();
        // Verify via raw SQL fetch (we don't expose get_one; the due-list
        // would skip this row due to the far-future next_trigger_at).
        let conn = b.conn_handle();
        let id_owned = id.clone();
        let got = (move || -> ScheduledTask {
            let guard = conn.lock();
            guard
                .query_row(
                    "SELECT id, name, goal_description, status, defer_until, \
                            schedule_cron, trigger_prompt, origin_thought_id, \
                            created_at, last_triggered_at, next_trigger_at, \
                            deferral_count, deferral_history, created_by_agent, \
                            agent_occurrence_id \
                     FROM cirislens_scheduled_tasks WHERE id = ?1",
                    params![id_owned],
                    |row| Ok(decode_scheduled_task_row(row)),
                )
                .unwrap()
                .unwrap()
        })();
        assert_eq!(got.id, t.id);
        assert_eq!(got.name, t.name);
        assert_eq!(got.goal_description, t.goal_description);
        assert_eq!(got.status, t.status);
        assert!(got.defer_until.is_some());
        assert_eq!(got.schedule_cron, t.schedule_cron);
        assert_eq!(got.trigger_prompt, t.trigger_prompt);
        assert_eq!(got.origin_thought_id, t.origin_thought_id);
        assert!(got.last_triggered_at.is_some());
        assert!(got.next_trigger_at.is_some());
        assert_eq!(got.deferral_count, t.deferral_count);
        assert_eq!(got.deferral_history, t.deferral_history);
        assert_eq!(got.created_by_agent, t.created_by_agent);
        assert_eq!(got.agent_occurrence_id, t.agent_occurrence_id);
    }

    #[tokio::test]
    async fn upsert_idempotent_preserves_created_at() {
        let (b, svc) = fresh_backend().await;
        let thought_id = seed_parent_thought(&b).await;
        let id = format!("sched-{}", Uuid::new_v4().simple());
        let original_created = Utc::now() - chrono::Duration::days(2);
        let mut t = mk_task(&id, &thought_id, "occ-test");
        t.created_at = original_created;
        t.name = "first-name".into();
        svc.upsert_scheduled_task(t.clone()).await.unwrap();

        let mut t2 = t.clone();
        t2.created_at = Utc::now();
        t2.name = "second-name".into();
        svc.upsert_scheduled_task(t2).await.unwrap();

        let conn = b.conn_handle();
        let id_owned = id.clone();
        let got = (move || -> ScheduledTask {
            let guard = conn.lock();
            guard
                .query_row(
                    "SELECT id, name, goal_description, status, defer_until, \
                            schedule_cron, trigger_prompt, origin_thought_id, \
                            created_at, last_triggered_at, next_trigger_at, \
                            deferral_count, deferral_history, created_by_agent, \
                            agent_occurrence_id \
                     FROM cirislens_scheduled_tasks WHERE id = ?1",
                    params![id_owned],
                    |row| Ok(decode_scheduled_task_row(row)),
                )
                .unwrap()
                .unwrap()
        })();
        assert_eq!(got.name, "second-name");
        let drift = (got.created_at - original_created).num_seconds().abs();
        assert!(drift <= 1, "created_at preserved: {drift}s drift");
    }

    #[tokio::test]
    async fn fk_rejects_nonexistent_origin_thought() {
        let (b, svc) = fresh_backend().await;
        // PRAGMA foreign_keys is enforced; verify.
        let conn = b.conn_handle();
        let pragma_on = (move || -> bool {
            let guard = conn.lock();
            guard
                .query_row("PRAGMA foreign_keys", params![], |row| row.get::<_, i64>(0))
                .map(|v| v == 1)
                .unwrap_or(false)
        })();
        if !pragma_on {
            eprintln!(
                "SQLite foreign_keys pragma off — skipping FK rejection check. Migrations \
                 don't enable it by default; substrate tests rely on the agent host enabling it."
            );
            return;
        }
        let id = format!("sched-{}", Uuid::new_v4().simple());
        let bogus_thought = format!("thought-bogus-{}", Uuid::new_v4().simple());
        let t = mk_task(&id, &bogus_thought, "occ-test");
        let res = svc.upsert_scheduled_task(t).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected FK Conflict, got {res:?}"
        );
    }

    #[tokio::test]
    async fn list_due_filters_correctly_and_orders_asc() {
        let (b, svc) = fresh_backend().await;
        let thought_id = seed_parent_thought(&b).await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let base = Utc::now();
        let past = base - chrono::Duration::seconds(60);
        let further_past = base - chrono::Duration::seconds(120);
        let future = base + chrono::Duration::seconds(60);
        let cases: Vec<(ScheduledTaskStatus, Option<DateTime<Utc>>)> = vec![
            (ScheduledTaskStatus::Pending, Some(past)),
            (ScheduledTaskStatus::Active, Some(further_past)),
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
            svc.upsert_scheduled_task(t).await.unwrap();
        }
        let due = svc.list_due_scheduled_tasks(&occ, base, 100).await.unwrap();
        assert_eq!(due.len(), 2, "exactly two PENDING/ACTIVE past-due rows");
        // ASC by next_trigger_at — the Active row (further_past) sorts first.
        assert_eq!(due[0].status, ScheduledTaskStatus::Active);
        assert_eq!(due[1].status, ScheduledTaskStatus::Pending);
        assert!(due[0].next_trigger_at.unwrap() <= due[1].next_trigger_at.unwrap());
    }

    #[tokio::test]
    async fn update_after_trigger_success_and_missing_row() {
        let (b, svc) = fresh_backend().await;
        let thought_id = seed_parent_thought(&b).await;
        let id = format!("sched-{}", Uuid::new_v4().simple());
        let mut t = mk_task(&id, &thought_id, "occ-test");
        t.next_trigger_at = Some(Utc::now() - chrono::Duration::seconds(60));
        svc.upsert_scheduled_task(t.clone()).await.unwrap();

        let now = Utc::now();
        let next = now + chrono::Duration::hours(1);
        let ok = svc
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

        let due = svc
            .list_due_scheduled_tasks("occ-test", now + chrono::Duration::hours(2), 100)
            .await
            .unwrap();
        let got = due.iter().find(|x| x.id == id).cloned().expect("present");
        assert_eq!(got.status, ScheduledTaskStatus::Active);
        assert_eq!(got.deferral_count, 1);
        assert!(got.deferral_history.is_some());

        let ok = svc
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
    async fn update_after_trigger_partial_preserves_status_and_history() {
        let (b, svc) = fresh_backend().await;
        let thought_id = seed_parent_thought(&b).await;
        let id = format!("sched-{}", Uuid::new_v4().simple());
        let original_history = serde_json::json!([{"at": "2026-01-01T00:00:00Z"}]);
        let mut t = mk_task(&id, &thought_id, "occ-test");
        t.status = ScheduledTaskStatus::Active;
        t.deferral_history = Some(original_history.clone());
        t.next_trigger_at = Some(Utc::now() - chrono::Duration::seconds(60));
        svc.upsert_scheduled_task(t.clone()).await.unwrap();

        let ok = svc
            .update_after_trigger(
                &id,
                Utc::now(),
                Some(Utc::now() + chrono::Duration::hours(1)),
                5,
                None,
                None,
            )
            .await
            .unwrap();
        assert!(ok);

        let due = svc
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
    async fn status_check_constraint_rejects_lowercase() {
        let (b, _svc) = fresh_backend().await;
        // No need to seed thought — CHECK fires before FK.
        let conn = b.conn_handle();
        let res = (move || -> rusqlite::Result<usize> {
            let guard = conn.lock();
            guard.execute(
                "INSERT INTO cirislens_scheduled_tasks (\
                    id, name, goal_description, status, trigger_prompt, \
                    origin_thought_id, created_at, deferral_count, agent_occurrence_id\
                 ) VALUES ('id', 'n', 'g', 'pending', 'p', \
                           't', '2026-01-01T00:00:00.000000+00:00', 0, 'occ')",
                params![],
            )
        })();
        assert!(
            res.is_err(),
            "expected CHECK violation on lowercase 'pending' (vocabulary is UPPERCASE)"
        );
    }

    #[tokio::test]
    async fn status_check_constraint_rejects_completed() {
        let (b, _svc) = fresh_backend().await;
        // 'completed' (tasks vocab) is NOT in scheduled_tasks's set.
        let conn = b.conn_handle();
        let res = (move || -> rusqlite::Result<usize> {
            let guard = conn.lock();
            guard.execute(
                "INSERT INTO cirislens_scheduled_tasks (\
                    id, name, goal_description, status, trigger_prompt, \
                    origin_thought_id, created_at, deferral_count, agent_occurrence_id\
                 ) VALUES ('id', 'n', 'g', 'COMPLETED', 'p', \
                           't', '2026-01-01T00:00:00.000000+00:00', 0, 'occ')",
                params![],
            )
        })();
        assert!(
            res.is_err(),
            "expected CHECK violation on 'COMPLETED' (set is COMPLETE not COMPLETED)"
        );
    }
}
