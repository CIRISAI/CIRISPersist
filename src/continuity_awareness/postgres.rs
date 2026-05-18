//! PostgreSQL impl of [`ContinuityAwarenessService`] (v1.5.17,
//! CIRISPersist#59 #9).
//!
//! 14 columns. Timestamps ride as `chrono::DateTime<Utc>`
//! (TIMESTAMPTZ); `preservation_scope` rides as the SQL string from
//! [`GraphScope::as_sql_str`] with a CHECK over the 4-value scope
//! vocabulary. `unfinished_tasks` + `deferred_goals` ride as
//! `Option<serde_json::Value>` (JSONB on the wire).
//!
//! `record_shutdown` uses `INSERT ... ON CONFLICT (id) DO NOTHING
//! RETURNING id` followed by an in-tx `SELECT` so the race-loser
//! reads back the existing row. Same ClaimResult shape as the
//! v1.5.14 deferral_reports + v1.5.16 creation_ceremonies impls.
//!
//! # Cross-substrate FK enforcement
//!
//! The `(preservation_node_id, preservation_scope)` pair references
//! `cirisgraph.nodes(node_id, scope)`. The FK is DEFERRABLE
//! INITIALLY DEFERRED so a one-tx ceremony that writes the
//! preservation node + the continuity row can run with the node
//! INSERT *after* the continuity INSERT — the check fires at
//! commit time. Callers using `record_shutdown` in isolation MUST
//! have written the cirisgraph node already; a missing parent
//! surfaces as `Error::Conflict` (PG error class 23503, FK
//! violation).

use super::service::ContinuityAwarenessService;
use super::types::ContinuityAwareness;
use super::Error;
use crate::graph::types::GraphScope;
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

fn validate_record(c: &ContinuityAwareness) -> Result<(), Error> {
    if c.id.is_empty() {
        return Err(Error::InvalidArgument("id required".into()));
    }
    if c.agent_id.is_empty() {
        return Err(Error::InvalidArgument("agent_id required".into()));
    }
    if c.shutdown_reason.is_empty() {
        return Err(Error::InvalidArgument("shutdown_reason required".into()));
    }
    if c.initiated_by.is_empty() {
        return Err(Error::InvalidArgument("initiated_by required".into()));
    }
    if c.preservation_node_id.is_empty() {
        return Err(Error::InvalidArgument(
            "preservation_node_id required".into(),
        ));
    }
    if c.reactivation_count < 0 {
        return Err(Error::InvalidArgument(
            "reactivation_count must be >= 0".into(),
        ));
    }
    Ok(())
}

fn decode_row(row: &tokio_postgres::Row) -> Result<ContinuityAwareness, Error> {
    let scope_str: String = row
        .try_get("preservation_scope")
        .map_err(|e| Error::Backend(format!("decode preservation_scope: {e}")))?;
    let preservation_scope = GraphScope::from_sql_str(&scope_str).ok_or_else(|| {
        Error::Backend(format!(
            "decode preservation_scope: unknown vocabulary `{scope_str}`"
        ))
    })?;
    Ok(ContinuityAwareness {
        id: row
            .try_get("id")
            .map_err(|e| Error::Backend(format!("decode id: {e}")))?,
        agent_id: row
            .try_get("agent_id")
            .map_err(|e| Error::Backend(format!("decode agent_id: {e}")))?,
        shutdown_timestamp: row
            .try_get("shutdown_timestamp")
            .map_err(|e| Error::Backend(format!("decode shutdown_timestamp: {e}")))?,
        is_terminal: row
            .try_get("is_terminal")
            .map_err(|e| Error::Backend(format!("decode is_terminal: {e}")))?,
        shutdown_reason: row
            .try_get("shutdown_reason")
            .map_err(|e| Error::Backend(format!("decode shutdown_reason: {e}")))?,
        expected_reactivation: row
            .try_get("expected_reactivation")
            .map_err(|e| Error::Backend(format!("decode expected_reactivation: {e}")))?,
        initiated_by: row
            .try_get("initiated_by")
            .map_err(|e| Error::Backend(format!("decode initiated_by: {e}")))?,
        final_thoughts: row
            .try_get("final_thoughts")
            .map_err(|e| Error::Backend(format!("decode final_thoughts: {e}")))?,
        unfinished_tasks: row
            .try_get("unfinished_tasks")
            .map_err(|e| Error::Backend(format!("decode unfinished_tasks: {e}")))?,
        reactivation_instructions: row
            .try_get("reactivation_instructions")
            .map_err(|e| Error::Backend(format!("decode reactivation_instructions: {e}")))?,
        deferred_goals: row
            .try_get("deferred_goals")
            .map_err(|e| Error::Backend(format!("decode deferred_goals: {e}")))?,
        preservation_node_id: row
            .try_get("preservation_node_id")
            .map_err(|e| Error::Backend(format!("decode preservation_node_id: {e}")))?,
        preservation_scope,
        reactivation_count: row
            .try_get("reactivation_count")
            .map_err(|e| Error::Backend(format!("decode reactivation_count: {e}")))?,
    })
}

const SELECT_COLUMNS: &str = "id, agent_id, shutdown_timestamp, is_terminal, shutdown_reason, \
     expected_reactivation, initiated_by, final_thoughts, unfinished_tasks, \
     reactivation_instructions, deferred_goals, preservation_node_id, \
     preservation_scope, reactivation_count";

impl ContinuityAwarenessService for PostgresBackend {
    async fn record_shutdown(
        &self,
        record: ContinuityAwareness,
    ) -> Result<ClaimResult<ContinuityAwareness>, Error> {
        validate_record(&record)?;
        let scope_str = record.preservation_scope.as_sql_str();
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
                "INSERT INTO cirislens.continuity_awareness (\
                    id, agent_id, shutdown_timestamp, is_terminal, shutdown_reason, \
                    expected_reactivation, initiated_by, final_thoughts, unfinished_tasks, \
                    reactivation_instructions, deferred_goals, preservation_node_id, \
                    preservation_scope, reactivation_count\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
                 ON CONFLICT (id) DO NOTHING \
                 RETURNING id",
                &[
                    &record.id,
                    &record.agent_id,
                    &record.shutdown_timestamp,
                    &record.is_terminal,
                    &record.shutdown_reason,
                    &record.expected_reactivation,
                    &record.initiated_by,
                    &record.final_thoughts,
                    &record.unfinished_tasks,
                    &record.reactivation_instructions,
                    &record.deferred_goals,
                    &record.preservation_node_id,
                    &scope_str,
                    &record.reactivation_count,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_shutdown insert"))?;
        let won = inserted.is_some();
        let row = tx
            .query_one(
                &format!(
                    "SELECT {SELECT_COLUMNS} FROM cirislens.continuity_awareness \
                     WHERE id = $1"
                ),
                &[&record.id],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_shutdown readback"))?;
        let row = decode_row(&row)?;
        tx.commit()
            .await
            .map_err(|e| map_pg_error(e, "record_shutdown commit"))?;
        if won {
            Ok(ClaimResult::Stored(row))
        } else {
            Ok(ClaimResult::AlreadyClaimed(row))
        }
    }

    async fn get_latest_shutdown(
        &self,
        agent_id: &str,
    ) -> Result<Option<ContinuityAwareness>, Error> {
        if agent_id.is_empty() {
            return Err(Error::InvalidArgument("agent_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                &format!(
                    "SELECT {SELECT_COLUMNS} FROM cirislens.continuity_awareness \
                     WHERE agent_id = $1 \
                     ORDER BY shutdown_timestamp DESC \
                     LIMIT 1"
                ),
                &[&agent_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_latest_shutdown"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_row(&row)?)),
        }
    }

    async fn record_reactivation(&self, agent_id: &str) -> Result<bool, Error> {
        if agent_id.is_empty() {
            return Err(Error::InvalidArgument("agent_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let changed = client
            .execute(
                "UPDATE cirislens.continuity_awareness SET \
                    reactivation_count = reactivation_count + 1 \
                 WHERE id = ( \
                    SELECT id FROM cirislens.continuity_awareness \
                    WHERE agent_id = $1 AND is_terminal = FALSE \
                    ORDER BY shutdown_timestamp DESC \
                    LIMIT 1 \
                 )",
                &[&agent_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_reactivation"))?;
        Ok(changed > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::types::GraphNode;
    use crate::graph::GraphService;
    use chrono::Utc;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    fn mk_node(node_id: &str, scope: GraphScope) -> GraphNode {
        GraphNode {
            node_id: node_id.to_owned(),
            scope,
            node_type: "agent".into(),
            attributes: serde_json::json!({"test": true}),
            version: 1,
            updated_by: "test-runner".into(),
            updated_at: Utc::now(),
            created_at: Utc::now(),
            signature: None,
            signing_key_id: None,
            signature_verified: false,
        }
    }

    fn mk_record(suffix: &str, node_id: &str, scope: GraphScope) -> ContinuityAwareness {
        let unique = Uuid::new_v4().simple().to_string();
        ContinuityAwareness {
            id: format!("shutdown-{suffix}-{unique}"),
            agent_id: format!("agent-{unique}"),
            shutdown_timestamp: Utc::now(),
            is_terminal: false,
            shutdown_reason: "planned restart".into(),
            expected_reactivation: Some(Utc::now() + chrono::Duration::minutes(5)),
            initiated_by: "operator".into(),
            final_thoughts: "see you soon".into(),
            unfinished_tasks: Some(serde_json::json!(["task-1", "task-2"])),
            reactivation_instructions: Some("resume from task-1".into()),
            deferred_goals: Some(serde_json::json!(["goal-a"])),
            preservation_node_id: node_id.to_owned(),
            preservation_scope: scope,
            reactivation_count: 0,
        }
    }

    /// Insert a graph_nodes row so the FK on the continuity row can
    /// land. Returns `(node_id, scope)` for the caller to thread
    /// into `preservation_node_id` / `preservation_scope`.
    async fn ensure_graph_node(backend: &PostgresBackend, suffix: &str) -> (String, GraphScope) {
        let nid = format!("agent:{suffix}-{}", Uuid::new_v4().simple());
        backend
            .upsert_node(mk_node(&nid, GraphScope::Identity), 0, false)
            .await
            .unwrap();
        (nid, GraphScope::Identity)
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn continuity_pg_record_get_round_trip_all_14_columns() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let (nid, scope) = ensure_graph_node(&backend, "rt").await;
        let r = mk_record("rt", &nid, scope);
        let outcome = ContinuityAwarenessService::record_shutdown(&backend, r.clone())
            .await
            .unwrap();
        assert!(matches!(outcome, ClaimResult::Stored(_)));

        let got = backend
            .get_latest_shutdown(&r.agent_id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.id, r.id);
        assert_eq!(got.agent_id, r.agent_id);
        assert_eq!(got.is_terminal, r.is_terminal);
        assert_eq!(got.shutdown_reason, r.shutdown_reason);
        assert_eq!(got.initiated_by, r.initiated_by);
        assert_eq!(got.final_thoughts, r.final_thoughts);
        assert_eq!(got.unfinished_tasks, r.unfinished_tasks);
        assert_eq!(got.reactivation_instructions, r.reactivation_instructions);
        assert_eq!(got.deferred_goals, r.deferred_goals);
        assert_eq!(got.preservation_node_id, r.preservation_node_id);
        assert_eq!(got.preservation_scope, r.preservation_scope);
        assert_eq!(got.reactivation_count, r.reactivation_count);
        let drift = (got.shutdown_timestamp - r.shutdown_timestamp)
            .num_seconds()
            .abs();
        assert!(drift <= 1, "shutdown_timestamp preserved: {drift}s drift");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn continuity_pg_record_already_claimed_returns_existing_row() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let (nid, scope) = ensure_graph_node(&backend, "dup").await;
        let r1 = mk_record("dup", &nid, scope);
        let out1 = ContinuityAwarenessService::record_shutdown(&backend, r1.clone())
            .await
            .unwrap();
        assert!(matches!(out1, ClaimResult::Stored(_)));

        // Second record with same id but different shutdown_reason —
        // should NOT overwrite.
        let mut r2 = r1.clone();
        r2.shutdown_reason = "overwritten?".into();
        let out2 = ContinuityAwarenessService::record_shutdown(&backend, r2)
            .await
            .unwrap();
        assert!(matches!(out2, ClaimResult::AlreadyClaimed(_)));
        let existing = out2.into_reference();
        assert_eq!(
            existing.shutdown_reason, r1.shutdown_reason,
            "loser sees original row"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn continuity_pg_fk_rejects_missing_graph_node() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // No graph_nodes row inserted — FK should reject at commit.
        let bogus_nid = format!("agent:bogus-{}", Uuid::new_v4().simple());
        let r = mk_record("fk", &bogus_nid, GraphScope::Identity);
        let res = ContinuityAwarenessService::record_shutdown(&backend, r).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected Conflict (FK violation), got {res:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn continuity_pg_get_latest_returns_newest() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let (nid, scope) = ensure_graph_node(&backend, "lat").await;
        // 3 shutdowns for the same agent at staggered timestamps.
        let mut r1 = mk_record("lat1", &nid, scope);
        let agent_id = r1.agent_id.clone();
        let mut r2 = mk_record("lat2", &nid, scope);
        let mut r3 = mk_record("lat3", &nid, scope);
        r2.agent_id = agent_id.clone();
        r3.agent_id = agent_id.clone();
        r1.shutdown_timestamp = Utc::now() - chrono::Duration::hours(2);
        r2.shutdown_timestamp = Utc::now() - chrono::Duration::hours(1);
        r3.shutdown_timestamp = Utc::now();

        for r in [&r1, &r2, &r3] {
            ContinuityAwarenessService::record_shutdown(&backend, r.clone())
                .await
                .unwrap();
        }

        let got = backend
            .get_latest_shutdown(&agent_id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.id, r3.id, "expected the newest of the three");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn continuity_pg_get_latest_returns_none_for_unknown_agent() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let unknown = format!("agent-nonexistent-{}", Uuid::new_v4().simple());
        let got = backend.get_latest_shutdown(&unknown).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn continuity_pg_record_reactivation_increments() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let (nid, scope) = ensure_graph_node(&backend, "rea").await;
        let r = mk_record("rea", &nid, scope);
        let agent_id = r.agent_id.clone();
        assert!(!r.is_terminal);
        ContinuityAwarenessService::record_shutdown(&backend, r.clone())
            .await
            .unwrap();

        let updated = backend.record_reactivation(&agent_id).await.unwrap();
        assert!(updated);
        let got = backend
            .get_latest_shutdown(&agent_id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.reactivation_count, 1);

        // Second call → 2.
        let updated = backend.record_reactivation(&agent_id).await.unwrap();
        assert!(updated);
        let got = backend
            .get_latest_shutdown(&agent_id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.reactivation_count, 2);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn continuity_pg_record_reactivation_skips_terminal_and_missing() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // No shutdowns → false.
        let unknown = format!("agent-{}", Uuid::new_v4().simple());
        let updated = backend.record_reactivation(&unknown).await.unwrap();
        assert!(!updated);

        // Terminal-only shutdown → false.
        let (nid, scope) = ensure_graph_node(&backend, "term").await;
        let mut r = mk_record("term", &nid, scope);
        r.is_terminal = true;
        let agent_id = r.agent_id.clone();
        ContinuityAwarenessService::record_shutdown(&backend, r)
            .await
            .unwrap();
        let updated = backend.record_reactivation(&agent_id).await.unwrap();
        assert!(!updated);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn continuity_pg_scope_check_rejects_unknown_value() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // Bypass the typed enum to write an arbitrary scope string
        // directly — verify the CHECK constraint kicks in at the
        // database layer.
        let client = backend.pool().get().await.unwrap();
        let now = Utc::now();
        let cid = format!("shutdown-bad-{}", Uuid::new_v4().simple());
        let res = client
            .execute(
                "INSERT INTO cirislens.continuity_awareness (\
                    id, agent_id, shutdown_timestamp, is_terminal, shutdown_reason, \
                    initiated_by, final_thoughts, preservation_node_id, \
                    preservation_scope, reactivation_count\
                 ) VALUES ($1, 'a', $2, FALSE, 'r', 'i', 'ft', 'p', $3, 0)",
                &[&cid, &now, &"WEIRD_SCOPE"],
            )
            .await;
        assert!(
            res.is_err(),
            "CHECK on preservation_scope should reject unknown values"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn continuity_pg_validate_required_columns() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let mut r = mk_record("val", "graph:dummy", GraphScope::Identity);
        r.id = String::new();
        let res = ContinuityAwarenessService::record_shutdown(&backend, r).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));

        let mut r = mk_record("val", "graph:dummy", GraphScope::Identity);
        r.shutdown_reason = String::new();
        let res = ContinuityAwarenessService::record_shutdown(&backend, r).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));
    }
}
