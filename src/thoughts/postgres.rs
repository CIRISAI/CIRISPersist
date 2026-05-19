//! PostgreSQL impl of [`ThoughtService`] (v1.5.10, CIRISPersist#59 #2).
//!
//! All 14 columns lift one-to-one from the row shape. JSON columns
//! ride across the wire as `serde_json::Value` (JSONB on the PG
//! side); timestamps cross as `chrono::DateTime<Utc>` (TIMESTAMPTZ).
//! FK to `cirislens.tasks(task_id)` + self-FK on
//! `parent_thought_id` are both DEFERRABLE INITIALLY DEFERRED (V025)
//! so bulk INSERT of a task + first thought (or parent + child
//! thoughts) in the same tx passes constraint check at COMMIT.

use super::service::ThoughtService;
use super::types::{
    Thought, ThoughtCursor, ThoughtFilter, ThoughtListPage, ThoughtStatus, ThoughtType,
};
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

fn decode_thought_row(row: &tokio_postgres::Row) -> Result<Thought, Error> {
    let status_str: String = row
        .try_get("status")
        .map_err(|e| Error::Backend(format!("decode status: {e}")))?;
    let status = ThoughtStatus::parse_str(&status_str)
        .ok_or_else(|| Error::Backend(format!("unknown status: {status_str}")))?;
    let thought_type_str: String = row
        .try_get("thought_type")
        .map_err(|e| Error::Backend(format!("decode thought_type: {e}")))?;
    Ok(Thought {
        thought_id: row
            .try_get("thought_id")
            .map_err(|e| Error::Backend(format!("decode thought_id: {e}")))?,
        source_task_id: row
            .try_get("source_task_id")
            .map_err(|e| Error::Backend(format!("decode source_task_id: {e}")))?,
        channel_id: row
            .try_get("channel_id")
            .map_err(|e| Error::Backend(format!("decode channel_id: {e}")))?,
        thought_type: ThoughtType(thought_type_str),
        status,
        created_at: row
            .try_get("created_at")
            .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|e| Error::Backend(format!("decode updated_at: {e}")))?,
        round_number: row
            .try_get("round_number")
            .map_err(|e| Error::Backend(format!("decode round_number: {e}")))?,
        content: row
            .try_get("content")
            .map_err(|e| Error::Backend(format!("decode content: {e}")))?,
        context: row
            .try_get("context_json")
            .map_err(|e| Error::Backend(format!("decode context_json: {e}")))?,
        thought_depth: row
            .try_get("thought_depth")
            .map_err(|e| Error::Backend(format!("decode thought_depth: {e}")))?,
        ponder_notes: row
            .try_get("ponder_notes_json")
            .map_err(|e| Error::Backend(format!("decode ponder_notes_json: {e}")))?,
        parent_thought_id: row
            .try_get("parent_thought_id")
            .map_err(|e| Error::Backend(format!("decode parent_thought_id: {e}")))?,
        final_action: row
            .try_get("final_action_json")
            .map_err(|e| Error::Backend(format!("decode final_action_json: {e}")))?,
        agent_occurrence_id: row
            .try_get("agent_occurrence_id")
            .map_err(|e| Error::Backend(format!("decode agent_occurrence_id: {e}")))?,
    })
}

impl ThoughtService for PostgresBackend {
    async fn upsert_thought(&self, thought: Thought) -> Result<(), Error> {
        validate_thought(&thought)?;
        let status_str = thought.status.as_sql_str().to_owned();
        let thought_type_str = thought.thought_type.0.clone();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        client
            .execute(
                "INSERT INTO cirislens.thoughts (\
                    thought_id, source_task_id, channel_id, thought_type, status, \
                    created_at, updated_at, round_number, content, context_json, \
                    thought_depth, ponder_notes_json, parent_thought_id, \
                    final_action_json, agent_occurrence_id\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
                           $15) \
                 ON CONFLICT (thought_id) DO UPDATE SET \
                    source_task_id = EXCLUDED.source_task_id, \
                    channel_id = EXCLUDED.channel_id, \
                    thought_type = EXCLUDED.thought_type, \
                    status = EXCLUDED.status, \
                    updated_at = EXCLUDED.updated_at, \
                    round_number = EXCLUDED.round_number, \
                    content = EXCLUDED.content, \
                    context_json = EXCLUDED.context_json, \
                    thought_depth = EXCLUDED.thought_depth, \
                    ponder_notes_json = EXCLUDED.ponder_notes_json, \
                    parent_thought_id = EXCLUDED.parent_thought_id, \
                    final_action_json = EXCLUDED.final_action_json, \
                    agent_occurrence_id = EXCLUDED.agent_occurrence_id",
                &[
                    &thought.thought_id,
                    &thought.source_task_id,
                    &thought.channel_id,
                    &thought_type_str,
                    &status_str,
                    &thought.created_at,
                    &thought.updated_at,
                    &thought.round_number,
                    &thought.content,
                    &thought.context,
                    &thought.thought_depth,
                    &thought.ponder_notes,
                    &thought.parent_thought_id,
                    &thought.final_action,
                    &thought.agent_occurrence_id,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "upsert_thought"))?;
        Ok(())
    }

    async fn get_thought(&self, thought_id: &str) -> Result<Option<Thought>, Error> {
        if thought_id.is_empty() {
            return Err(Error::InvalidArgument("thought_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT thought_id, source_task_id, channel_id, thought_type, status, \
                        created_at, updated_at, round_number, content, context_json, \
                        thought_depth, ponder_notes_json, parent_thought_id, \
                        final_action_json, agent_occurrence_id \
                 FROM cirislens.thoughts WHERE thought_id = $1",
                &[&thought_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_thought"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_thought_row(&row)?)),
        }
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
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(task) = filter.source_task_id {
            params.push(Box::new(task));
            where_parts.push(format!("source_task_id = ${}", params.len()));
        }
        if let Some(status) = filter.status {
            params.push(Box::new(status.as_sql_str().to_owned()));
            where_parts.push(format!("status = ${}", params.len()));
        }
        if let Some(occ) = filter.agent_occurrence_id {
            params.push(Box::new(occ));
            where_parts.push(format!("agent_occurrence_id = ${}", params.len()));
        }
        if let Some(parent) = filter.parent_thought_id {
            params.push(Box::new(parent));
            where_parts.push(format!("parent_thought_id = ${}", params.len()));
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
                    "ThoughtCursor version {} unsupported",
                    cur.version
                )));
            }
            params.push(Box::new(cur.last_ts));
            let p_ts = params.len();
            params.push(Box::new(cur.last_id.clone()));
            let p_id = params.len();
            where_parts.push(format!("(updated_at, thought_id) < (${p_ts}, ${p_id})"));
        }
        params.push(Box::new(limit));
        let p_limit = params.len();
        let where_sql = if where_parts.is_empty() {
            "TRUE".to_string()
        } else {
            where_parts.join(" AND ")
        };
        let sql = format!(
            "SELECT thought_id, source_task_id, channel_id, thought_type, status, \
                    created_at, updated_at, round_number, content, context_json, \
                    thought_depth, ponder_notes_json, parent_thought_id, \
                    final_action_json, agent_occurrence_id \
             FROM cirislens.thoughts \
             WHERE {where_sql} \
             ORDER BY updated_at DESC, thought_id DESC \
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
            .map_err(|e| map_pg_error(e, "list_thoughts"))?;
        let mut items: Vec<Thought> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_thought_row(row)?);
        }
        let next_cursor = if items.len() == limit as usize {
            items
                .last()
                .map(|last| ThoughtCursor::from_trailing(last.updated_at, last.thought_id.clone()))
        } else {
            None
        };
        Ok(ThoughtListPage { items, next_cursor })
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
        let status_str = new_status.as_sql_str().to_owned();
        let now = chrono::Utc::now();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let changed = client
            .execute(
                "UPDATE cirislens.thoughts SET \
                    status = $1, \
                    updated_at = $2, \
                    final_action_json = COALESCE($3, final_action_json) \
                 WHERE thought_id = $4",
                &[&status_str, &now, &final_action, &thought_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "update_thought_status"))?;
        Ok(changed > 0)
    }

    async fn get_descendants(&self, thought_id: &str) -> Result<Vec<Thought>, Error> {
        if thought_id.is_empty() {
            return Err(Error::InvalidArgument("thought_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // Recursive CTE walks the parent_thought_id chain from the
        // root. UNION ALL is safe because the tree has acyclic
        // structure (parent_thought_id is a strict tree edge); if a
        // pathological caller inserts a cycle, the recursion budget
        // is bounded by PG's `max_stack_depth` (default 2 MB ~ ~50
        // levels). Deterministic ordering by depth + id.
        let rows = client
            .query(
                "WITH RECURSIVE descendants AS ( \
                    SELECT thought_id, source_task_id, channel_id, thought_type, status, \
                           created_at, updated_at, round_number, content, context_json, \
                           thought_depth, ponder_notes_json, parent_thought_id, \
                           final_action_json, agent_occurrence_id \
                      FROM cirislens.thoughts \
                      WHERE thought_id = $1 \
                    UNION ALL \
                    SELECT t.thought_id, t.source_task_id, t.channel_id, t.thought_type, t.status, \
                           t.created_at, t.updated_at, t.round_number, t.content, t.context_json, \
                           t.thought_depth, t.ponder_notes_json, t.parent_thought_id, \
                           t.final_action_json, t.agent_occurrence_id \
                      FROM cirislens.thoughts t \
                      JOIN descendants d ON t.parent_thought_id = d.thought_id \
                 ) \
                 SELECT thought_id, source_task_id, channel_id, thought_type, status, \
                        created_at, updated_at, round_number, content, context_json, \
                        thought_depth, ponder_notes_json, parent_thought_id, \
                        final_action_json, agent_occurrence_id \
                 FROM descendants \
                 ORDER BY thought_depth ASC, thought_id ASC",
                &[&thought_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_descendants"))?;
        let mut items: Vec<Thought> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_thought_row(row)?);
        }
        Ok(items)
    }

    async fn delete_thought(&self, thought_id: &str) -> Result<bool, Error> {
        if thought_id.is_empty() {
            return Err(Error::InvalidArgument("thought_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let changed = client
            .execute(
                "DELETE FROM cirislens.thoughts WHERE thought_id = $1",
                &[&thought_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "delete_thought"))?;
        Ok(changed > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::{Task, TaskService, TaskStatus};
    use chrono::Utc;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    fn mk_task(id: &str, occurrence: &str) -> Task {
        let now = Utc::now();
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
        let now = Utc::now();
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
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_upsert_get_full_columns_round_trip() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let task_id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&task_id, "occ-1"))
            .await
            .unwrap();

        let id = format!("th-{}", Uuid::new_v4().simple());
        let now = Utc::now();
        let thought = Thought {
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
        backend.upsert_thought(thought.clone()).await.unwrap();
        let got = backend.get_thought(&id).await.unwrap().expect("present");
        assert_eq!(got.thought_id, thought.thought_id);
        assert_eq!(got.source_task_id, thought.source_task_id);
        assert_eq!(got.channel_id, thought.channel_id);
        assert_eq!(got.thought_type, thought.thought_type);
        assert_eq!(got.status, thought.status);
        assert_eq!(got.round_number, thought.round_number);
        assert_eq!(got.content, thought.content);
        assert_eq!(got.context, thought.context);
        assert_eq!(got.thought_depth, thought.thought_depth);
        assert_eq!(got.ponder_notes, thought.ponder_notes);
        assert_eq!(got.final_action, thought.final_action);
        assert_eq!(got.agent_occurrence_id, thought.agent_occurrence_id);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_upsert_idempotent_then_overwrites_mutable_cols() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let task_id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&task_id, "occ-1"))
            .await
            .unwrap();

        let id = format!("th-{}", Uuid::new_v4().simple());
        let mut t = mk_thought(&id, &task_id, ThoughtStatus::Pending, "occ-1");
        t.content = "first".into();
        backend.upsert_thought(t.clone()).await.unwrap();
        backend.upsert_thought(t.clone()).await.unwrap();
        let got = backend.get_thought(&id).await.unwrap().expect("present");
        assert_eq!(got.content, "first");
        let original_created = got.created_at;

        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let mut t2 = t.clone();
        t2.content = "second".into();
        t2.status = ThoughtStatus::Processing;
        t2.updated_at = Utc::now();
        backend.upsert_thought(t2).await.unwrap();
        let got2 = backend.get_thought(&id).await.unwrap().expect("present");
        assert_eq!(got2.content, "second");
        assert_eq!(got2.status, ThoughtStatus::Processing);
        assert_eq!(got2.created_at, original_created);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_list_filter_by_task_status_occurrence() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&task_id, &occ))
            .await
            .unwrap();
        // 3 thoughts under one task in this occurrence.
        let mut ids = Vec::new();
        for i in 0..3 {
            let id = format!("th{i}-{}", Uuid::new_v4().simple());
            ids.push(id.clone());
            let status = if i == 0 {
                ThoughtStatus::Pending
            } else {
                ThoughtStatus::Processing
            };
            let t = mk_thought(&id, &task_id, status, &occ);
            backend.upsert_thought(t).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }

        // Filter by source_task_id.
        let page = backend
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
        let page = backend
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
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_list_cursor_pagination() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let task_id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&task_id, &occ))
            .await
            .unwrap();
        let mut ids = Vec::new();
        for i in 0..5 {
            let id = format!("th{i}-{}", Uuid::new_v4().simple());
            ids.push(id.clone());
            let t = mk_thought(&id, &task_id, ThoughtStatus::Pending, &occ);
            backend.upsert_thought(t).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        let filter = ThoughtFilter {
            agent_occurrence_id: Some(occ.clone()),
            ..Default::default()
        };
        let page1 = backend
            .list_thoughts(filter.clone(), None, 2)
            .await
            .unwrap();
        assert_eq!(page1.items.len(), 2);
        assert!(page1.next_cursor.is_some());
        let page2 = backend
            .list_thoughts(filter.clone(), page1.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(page2.items.len(), 2);
        let page3 = backend
            .list_thoughts(filter.clone(), page2.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(page3.items.len(), 1);
        assert!(page3.next_cursor.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_update_status_final_action_merge_and_missing_row() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let task_id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&task_id, "occ-1"))
            .await
            .unwrap();

        let id = format!("th-{}", Uuid::new_v4().simple());
        backend
            .upsert_thought(mk_thought(&id, &task_id, ThoughtStatus::Pending, "occ-1"))
            .await
            .unwrap();
        let ok = backend
            .update_thought_status(&id, ThoughtStatus::Processing, None)
            .await
            .unwrap();
        assert!(ok);
        let got = backend.get_thought(&id).await.unwrap().expect("present");
        assert_eq!(got.status, ThoughtStatus::Processing);
        assert!(got.final_action.is_none());

        let ok = backend
            .update_thought_status(
                &id,
                ThoughtStatus::Completed,
                Some(serde_json::json!({"action": "speak"})),
            )
            .await
            .unwrap();
        assert!(ok);
        let got = backend.get_thought(&id).await.unwrap().expect("present");
        assert_eq!(
            got.final_action,
            Some(serde_json::json!({"action": "speak"}))
        );

        let ok = backend
            .update_thought_status(
                &format!("missing-{}", Uuid::new_v4().simple()),
                ThoughtStatus::Failed,
                None,
            )
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_fk_to_tasks_rejects_nonexistent_task() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let ghost_task = format!("ghost-{}", Uuid::new_v4().simple());
        let id = format!("th-{}", Uuid::new_v4().simple());
        let t = mk_thought(&id, &ghost_task, ThoughtStatus::Pending, "occ-1");
        let err = backend.upsert_thought(t).await.unwrap_err();
        assert!(
            matches!(err, Error::Conflict(_)),
            "expected Conflict (FK), got {err:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_self_fk_parent_thought_rejects_nonexistent() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let task_id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&task_id, "occ-1"))
            .await
            .unwrap();

        let id = format!("th-{}", Uuid::new_v4().simple());
        let mut t = mk_thought(&id, &task_id, ThoughtStatus::Pending, "occ-1");
        t.parent_thought_id = Some(format!("ghost-{}", Uuid::new_v4().simple()));
        let err = backend.upsert_thought(t).await.unwrap_err();
        assert!(
            matches!(err, Error::Conflict(_)),
            "expected Conflict (FK), got {err:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_get_descendants_3_level_tree_returns_7_rows() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let task_id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&task_id, "occ-1"))
            .await
            .unwrap();

        // 3-level tree: root → 2 children → 1 grandchild each → 7 rows.
        let root = format!("root-{}", Uuid::new_v4().simple());
        let mut th = mk_thought(&root, &task_id, ThoughtStatus::Pending, "occ-1");
        th.thought_depth = 0;
        backend.upsert_thought(th).await.unwrap();

        let mut child_ids = Vec::new();
        for ci in 0..2 {
            let child_id = format!("c{ci}-{}", Uuid::new_v4().simple());
            child_ids.push(child_id.clone());
            let mut th = mk_thought(&child_id, &task_id, ThoughtStatus::Pending, "occ-1");
            th.parent_thought_id = Some(root.clone());
            th.thought_depth = 1;
            backend.upsert_thought(th).await.unwrap();
        }
        for child_id in &child_ids {
            for gi in 0..2 {
                let g_id = format!("g{gi}-{}", Uuid::new_v4().simple());
                let mut th = mk_thought(&g_id, &task_id, ThoughtStatus::Pending, "occ-1");
                th.parent_thought_id = Some(child_id.clone());
                th.thought_depth = 2;
                backend.upsert_thought(th).await.unwrap();
            }
        }

        let descendants = backend.get_descendants(&root).await.unwrap();
        // root (1) + children (2) + grandchildren (4) = 7
        assert_eq!(descendants.len(), 7);
        // Ordering: depth-0 first, then depth-1, then depth-2.
        assert_eq!(descendants[0].thought_depth, 0);
        assert_eq!(descendants[0].thought_id, root);
        assert!(descendants
            .iter()
            .skip(1)
            .take(2)
            .all(|t| t.thought_depth == 1));
        assert!(descendants.iter().skip(3).all(|t| t.thought_depth == 2));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_get_descendants_unknown_root_returns_empty() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let v = backend
            .get_descendants(&format!("ghost-{}", Uuid::new_v4().simple()))
            .await
            .unwrap();
        assert!(v.is_empty());
    }

    // ── v1.5.20 (CIRISPersist#60) delete_thought + FK cascade ────────

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_delete_thought_returns_true_then_false() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let task_id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&task_id, "occ-1"))
            .await
            .unwrap();
        let id = format!("th-{}", Uuid::new_v4().simple());
        backend
            .upsert_thought(mk_thought(&id, &task_id, ThoughtStatus::Pending, "occ-1"))
            .await
            .unwrap();

        let first = backend.delete_thought(&id).await.unwrap();
        assert!(first);
        let second = backend.delete_thought(&id).await.unwrap();
        assert!(!second);
        assert!(backend.get_thought(&id).await.unwrap().is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_delete_thought_empty_id_rejected() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let err = backend.delete_thought("").await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_delete_thought_parent_with_children_rejects() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let task_id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&task_id, "occ-1"))
            .await
            .unwrap();

        let parent = format!("p-{}", Uuid::new_v4().simple());
        backend
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
        backend.upsert_thought(child_t).await.unwrap();

        let err = backend.delete_thought(&parent).await.unwrap_err();
        assert!(
            matches!(err, Error::Conflict(_)),
            "expected Conflict (FK), got {err:?}"
        );

        assert!(backend.delete_thought(&child).await.unwrap());
        assert!(backend.delete_thought(&parent).await.unwrap());
    }

    // ── v1.5.21 (CIRISPersist#62) created_before/created_after ───────

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_list_filter_created_range() {
        use crate::store::backend::Backend;
        use chrono::Duration as ChronoDuration;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let task_id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&task_id, "occ-1"))
            .await
            .unwrap();

        let now = Utc::now();
        for (label, offset_h) in &[("a", -72i64), ("b", -24), ("c", 0)] {
            let id = format!("{label}-{}", Uuid::new_v4().simple());
            let mut t = mk_thought(&id, &task_id, ThoughtStatus::Pending, "occ-1");
            t.created_at = now + ChronoDuration::hours(*offset_h);
            t.updated_at = t.created_at;
            backend.upsert_thought(t).await.unwrap();
        }

        let page = backend
            .list_thoughts(
                ThoughtFilter {
                    source_task_id: Some(task_id.clone()),
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
    #[serial_test::serial(postgres)]
    async fn thoughts_pg_task_delete_cascades_to_thoughts() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let task_id = format!("t-{}", Uuid::new_v4().simple());
        TaskService::upsert_task(&backend, mk_task(&task_id, "occ-1"))
            .await
            .unwrap();
        let th1 = format!("th1-{}", Uuid::new_v4().simple());
        let th2 = format!("th2-{}", Uuid::new_v4().simple());
        backend
            .upsert_thought(mk_thought(&th1, &task_id, ThoughtStatus::Pending, "occ-1"))
            .await
            .unwrap();
        backend
            .upsert_thought(mk_thought(&th2, &task_id, ThoughtStatus::Pending, "occ-1"))
            .await
            .unwrap();

        assert!(TaskService::delete_task(&backend, &task_id).await.unwrap());

        assert!(backend.get_thought(&th1).await.unwrap().is_none());
        assert!(backend.get_thought(&th2).await.unwrap().is_none());
    }
}
