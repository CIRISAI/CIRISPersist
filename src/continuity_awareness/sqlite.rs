//! SQLite impl of [`ContinuityAwarenessService`] (v1.5.17,
//! CIRISPersist#59 #9).
//!
//! Mirrors the v1.5.17 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ                         → TEXT (RFC 3339)
//!   BOOLEAN                             → INTEGER (0 / 1)
//!   JSONB                               → TEXT JSON (encoded /
//!                                          decoded via serde_json)
//!   ON CONFLICT (id) DO NOTHING         → INSERT OR IGNORE
//!   FK DEFERRABLE INITIALLY DEFERRED    → immediate enforcement
//!                                          (SQLite has only
//!                                          immediate FK mode with
//!                                          PRAGMA foreign_keys=ON)
//!
//! Threading: `tokio::task::spawn_blocking` + `conn.lock()`
//! per the existing pattern.
//!
//! `record_shutdown` uses the same ClaimResult shape as v1.5.16
//! creation_ceremonies: `INSERT OR IGNORE` followed by an
//! in-transaction `SELECT` so the race-loser reads back the
//! existing row.
//!
//! # Cross-substrate FK
//!
//! The store layer always sets `PRAGMA foreign_keys = ON`, so the
//! FK to `cirisgraph_nodes(node_id, scope)` is enforced at insert
//! time. Callers MUST have written the cirisgraph node row first;
//! a missing parent surfaces as `Error::Conflict` (rusqlite
//! `ConstraintViolation`).
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
use rusqlite::{params, Connection, OptionalExtension};

use super::service::ContinuityAwarenessService;
use super::types::ContinuityAwareness;
use super::Error;
use crate::graph::types::GraphScope;
use crate::ClaimResult;

/// SQLite-backed [`ContinuityAwarenessService`] impl.
pub struct SqliteContinuityAwarenessBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteContinuityAwarenessBackend {
    /// Construct from a shared connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if err.code == ErrorCode::ConstraintViolation {
            // SQLite collapses CHECK / NOT NULL / FK / UNIQUE
            // under one ErrorCode; distinguish by the extended
            // code so FK violations come through as Conflict
            // (parity with PG) and CHECK / NOT NULL come through
            // as InvalidArgument.
            let extended = err.extended_code;
            // 787 = SQLITE_CONSTRAINT_FOREIGNKEY
            // 1555 = SQLITE_CONSTRAINT_PRIMARYKEY
            // 2067 = SQLITE_CONSTRAINT_UNIQUE
            if extended == 787 {
                return Error::Conflict(format!("{op} FK: {e}"));
            }
            if extended == 1555 || extended == 2067 {
                return Error::Conflict(format!("{op} UNIQUE: {e}"));
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

fn encode_optional_json(v: &Option<serde_json::Value>) -> Result<Option<String>, Error> {
    match v {
        None => Ok(None),
        Some(j) => serde_json::to_string(j)
            .map(Some)
            .map_err(|e| Error::Internal(format!("encode JSON: {e}"))),
    }
}

fn decode_optional_json(s: Option<String>) -> Result<Option<serde_json::Value>, Error> {
    match s {
        None => Ok(None),
        Some(s) if s.is_empty() => Ok(None),
        Some(s) => serde_json::from_str(&s)
            .map(Some)
            .map_err(|e| Error::Backend(format!("decode JSON: {e} (raw={s})"))),
    }
}

fn decode_row(row: &rusqlite::Row<'_>) -> Result<ContinuityAwareness, Error> {
    let id: String = row
        .get("id")
        .map_err(|e| Error::Backend(format!("decode id: {e}")))?;
    let agent_id: String = row
        .get("agent_id")
        .map_err(|e| Error::Backend(format!("decode agent_id: {e}")))?;
    let shutdown_timestamp_str: String = row
        .get("shutdown_timestamp")
        .map_err(|e| Error::Backend(format!("decode shutdown_timestamp: {e}")))?;
    let is_terminal_int: i64 = row
        .get("is_terminal")
        .map_err(|e| Error::Backend(format!("decode is_terminal: {e}")))?;
    let shutdown_reason: String = row
        .get("shutdown_reason")
        .map_err(|e| Error::Backend(format!("decode shutdown_reason: {e}")))?;
    let expected_reactivation_str: Option<String> = row
        .get("expected_reactivation")
        .map_err(|e| Error::Backend(format!("decode expected_reactivation: {e}")))?;
    let initiated_by: String = row
        .get("initiated_by")
        .map_err(|e| Error::Backend(format!("decode initiated_by: {e}")))?;
    let final_thoughts: String = row
        .get("final_thoughts")
        .map_err(|e| Error::Backend(format!("decode final_thoughts: {e}")))?;
    let unfinished_tasks_str: Option<String> = row
        .get("unfinished_tasks")
        .map_err(|e| Error::Backend(format!("decode unfinished_tasks: {e}")))?;
    let reactivation_instructions: Option<String> = row
        .get("reactivation_instructions")
        .map_err(|e| Error::Backend(format!("decode reactivation_instructions: {e}")))?;
    let deferred_goals_str: Option<String> = row
        .get("deferred_goals")
        .map_err(|e| Error::Backend(format!("decode deferred_goals: {e}")))?;
    let preservation_node_id: String = row
        .get("preservation_node_id")
        .map_err(|e| Error::Backend(format!("decode preservation_node_id: {e}")))?;
    let scope_str: String = row
        .get("preservation_scope")
        .map_err(|e| Error::Backend(format!("decode preservation_scope: {e}")))?;
    let reactivation_count: i64 = row
        .get("reactivation_count")
        .map_err(|e| Error::Backend(format!("decode reactivation_count: {e}")))?;

    let preservation_scope = GraphScope::from_sql_str(&scope_str).ok_or_else(|| {
        Error::Backend(format!(
            "decode preservation_scope: unknown vocabulary `{scope_str}`"
        ))
    })?;
    let expected_reactivation = match expected_reactivation_str {
        None => None,
        Some(s) => Some(parse_datetime(&s)?),
    };

    Ok(ContinuityAwareness {
        id,
        agent_id,
        shutdown_timestamp: parse_datetime(&shutdown_timestamp_str)?,
        is_terminal: is_terminal_int != 0,
        shutdown_reason,
        expected_reactivation,
        initiated_by,
        final_thoughts,
        unfinished_tasks: decode_optional_json(unfinished_tasks_str)?,
        reactivation_instructions,
        deferred_goals: decode_optional_json(deferred_goals_str)?,
        preservation_node_id,
        preservation_scope,
        reactivation_count: i32::try_from(reactivation_count)
            .map_err(|e| Error::Backend(format!("decode reactivation_count: {e}")))?,
    })
}

const SELECT_COLUMNS: &str = "id, agent_id, shutdown_timestamp, is_terminal, shutdown_reason, \
     expected_reactivation, initiated_by, final_thoughts, unfinished_tasks, \
     reactivation_instructions, deferred_goals, preservation_node_id, \
     preservation_scope, reactivation_count";

impl ContinuityAwarenessService for SqliteContinuityAwarenessBackend {
    async fn record_shutdown(
        &self,
        record: ContinuityAwareness,
    ) -> Result<ClaimResult<ContinuityAwareness>, Error> {
        validate_record(&record)?;
        let id_for_lookup = record.id.clone();
        let shutdown_timestamp_str = fmt_datetime(record.shutdown_timestamp);
        let expected_reactivation_str = record.expected_reactivation.map(fmt_datetime);
        let scope_str = record.preservation_scope.as_sql_str().to_owned();
        let unfinished_tasks_str = encode_optional_json(&record.unfinished_tasks)?;
        let deferred_goals_str = encode_optional_json(&record.deferred_goals)?;
        let is_terminal_int: i64 = if record.is_terminal { 1 } else { 0 };

        let conn = self.conn.clone();
        let (won, row): (bool, ContinuityAwareness) =
            (move || -> Result<(bool, ContinuityAwareness), Error> {
                let mut guard = conn.lock();
                let tx = guard
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(|e| map_sqlite_error(e, "record_shutdown begin"))?;
                let changed = tx
                    .execute(
                        "INSERT OR IGNORE INTO cirislens_continuity_awareness (\
                            id, agent_id, shutdown_timestamp, is_terminal, shutdown_reason, \
                            expected_reactivation, initiated_by, final_thoughts, \
                            unfinished_tasks, reactivation_instructions, deferred_goals, \
                            preservation_node_id, preservation_scope, reactivation_count\
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                        params![
                            record.id,
                            record.agent_id,
                            shutdown_timestamp_str,
                            is_terminal_int,
                            record.shutdown_reason,
                            expected_reactivation_str,
                            record.initiated_by,
                            record.final_thoughts,
                            unfinished_tasks_str,
                            record.reactivation_instructions,
                            deferred_goals_str,
                            record.preservation_node_id,
                            scope_str,
                            record.reactivation_count,
                        ],
                    )
                    .map_err(|e| map_sqlite_error(e, "record_shutdown insert"))?;
                let won = changed > 0;
                let row = tx
                    .query_row(
                        &format!(
                            "SELECT {SELECT_COLUMNS} FROM cirislens_continuity_awareness \
                             WHERE id = ?1"
                        ),
                        params![id_for_lookup],
                        |row| Ok(decode_row(row)),
                    )
                    .map_err(|e| map_sqlite_error(e, "record_shutdown readback"))??;
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "record_shutdown commit"))?;
                Ok((won, row))
            })()?;

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
        let agent_id_owned = agent_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Option<ContinuityAwareness>, Error> {
            let guard = conn.lock();
            let row_opt = guard
                .query_row(
                    &format!(
                        "SELECT {SELECT_COLUMNS} FROM cirislens_continuity_awareness \
                         WHERE agent_id = ?1 \
                         ORDER BY shutdown_timestamp DESC \
                         LIMIT 1"
                    ),
                    params![agent_id_owned],
                    |row| Ok(decode_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_latest_shutdown query"))?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(r?)),
            }
        })()
    }

    async fn record_reactivation(&self, agent_id: &str) -> Result<bool, Error> {
        if agent_id.is_empty() {
            return Err(Error::InvalidArgument("agent_id required".into()));
        }
        let agent_id_owned = agent_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let guard = conn.lock();
            let changed = guard
                .execute(
                    "UPDATE cirislens_continuity_awareness SET \
                        reactivation_count = reactivation_count + 1 \
                     WHERE id = ( \
                        SELECT id FROM cirislens_continuity_awareness \
                        WHERE agent_id = ?1 AND is_terminal = 0 \
                        ORDER BY shutdown_timestamp DESC \
                        LIMIT 1 \
                     )",
                    params![agent_id_owned],
                )
                .map_err(|e| map_sqlite_error(e, "record_reactivation exec"))?;
            Ok(changed > 0)
        })()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::sqlite::SqliteGraphBackend;
    use crate::graph::types::GraphNode;
    use crate::graph::GraphService;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use uuid::Uuid;

    async fn fresh_backend() -> (
        SqliteBackend,
        SqliteContinuityAwarenessBackend,
        SqliteGraphBackend,
    ) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteContinuityAwarenessBackend::new(backend.conn_handle());
        let graph = SqliteGraphBackend::new(backend.conn_handle());
        (backend, svc, graph)
    }

    fn mk_graph_node(node_id: &str, scope: GraphScope) -> GraphNode {
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

    async fn ensure_graph_node(graph: &SqliteGraphBackend, suffix: &str) -> (String, GraphScope) {
        let nid = format!("agent:{suffix}-{}", Uuid::new_v4().simple());
        graph
            .upsert_node(mk_graph_node(&nid, GraphScope::Identity), 0, false)
            .await
            .unwrap();
        (nid, GraphScope::Identity)
    }

    #[tokio::test]
    async fn record_get_round_trip_all_14_columns() {
        let (_b, svc, graph) = fresh_backend().await;
        let (nid, scope) = ensure_graph_node(&graph, "rt").await;
        let now = Utc::now();
        let mut r = mk_record("rt", &nid, scope);
        r.shutdown_timestamp = now;
        let outcome = svc.record_shutdown(r.clone()).await.unwrap();
        assert!(matches!(outcome, ClaimResult::Stored(_)));

        let got = svc
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
        let drift = (got.shutdown_timestamp - now).num_seconds().abs();
        assert!(drift <= 1, "shutdown_timestamp preserved: {drift}s drift");
    }

    #[tokio::test]
    async fn record_already_claimed_returns_existing_row() {
        let (_b, svc, graph) = fresh_backend().await;
        let (nid, scope) = ensure_graph_node(&graph, "dup").await;
        let r1 = mk_record("dup", &nid, scope);
        let out1 = svc.record_shutdown(r1.clone()).await.unwrap();
        assert!(matches!(out1, ClaimResult::Stored(_)));

        let mut r2 = r1.clone();
        r2.shutdown_reason = "overwritten?".into();
        let out2 = svc.record_shutdown(r2).await.unwrap();
        assert!(matches!(out2, ClaimResult::AlreadyClaimed(_)));
        let existing = out2.into_reference();
        assert_eq!(
            existing.shutdown_reason, r1.shutdown_reason,
            "loser sees original row"
        );
    }

    #[tokio::test]
    async fn fk_rejects_missing_graph_node() {
        let (_b, svc, _graph) = fresh_backend().await;
        // No graph_nodes row inserted — FK should reject.
        let bogus_nid = format!("agent:bogus-{}", Uuid::new_v4().simple());
        let r = mk_record("fk", &bogus_nid, GraphScope::Identity);
        let res = svc.record_shutdown(r).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected Conflict (FK violation), got {res:?}"
        );
    }

    #[tokio::test]
    async fn get_latest_returns_newest() {
        let (_b, svc, graph) = fresh_backend().await;
        let (nid, scope) = ensure_graph_node(&graph, "lat").await;
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
            svc.record_shutdown(r.clone()).await.unwrap();
        }

        let got = svc
            .get_latest_shutdown(&agent_id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.id, r3.id, "expected the newest of the three");
    }

    #[tokio::test]
    async fn get_latest_returns_none_for_unknown_agent() {
        let (_b, svc, _graph) = fresh_backend().await;
        let unknown = format!("agent-nonexistent-{}", Uuid::new_v4().simple());
        let got = svc.get_latest_shutdown(&unknown).await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn record_reactivation_increments() {
        let (_b, svc, graph) = fresh_backend().await;
        let (nid, scope) = ensure_graph_node(&graph, "rea").await;
        let r = mk_record("rea", &nid, scope);
        let agent_id = r.agent_id.clone();
        assert!(!r.is_terminal);
        svc.record_shutdown(r.clone()).await.unwrap();

        let updated = svc.record_reactivation(&agent_id).await.unwrap();
        assert!(updated);
        let got = svc
            .get_latest_shutdown(&agent_id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.reactivation_count, 1);

        let updated = svc.record_reactivation(&agent_id).await.unwrap();
        assert!(updated);
        let got = svc
            .get_latest_shutdown(&agent_id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.reactivation_count, 2);
    }

    #[tokio::test]
    async fn record_reactivation_skips_terminal_and_missing() {
        let (_b, svc, graph) = fresh_backend().await;

        // No shutdowns → false.
        let unknown = format!("agent-{}", Uuid::new_v4().simple());
        let updated = svc.record_reactivation(&unknown).await.unwrap();
        assert!(!updated);

        // Terminal-only shutdown → false.
        let (nid, scope) = ensure_graph_node(&graph, "term").await;
        let mut r = mk_record("term", &nid, scope);
        r.is_terminal = true;
        let agent_id = r.agent_id.clone();
        svc.record_shutdown(r).await.unwrap();
        let updated = svc.record_reactivation(&agent_id).await.unwrap();
        assert!(!updated);
    }

    #[tokio::test]
    async fn scope_check_rejects_unknown_value() {
        let (b, _svc, _graph) = fresh_backend().await;
        let conn = b.conn_handle();
        let now = fmt_datetime(Utc::now());
        let cid = format!("shutdown-bad-{}", Uuid::new_v4().simple());
        let res = (move || {
            let guard = conn.lock();
            guard.execute(
                "INSERT INTO cirislens_continuity_awareness (\
                    id, agent_id, shutdown_timestamp, is_terminal, shutdown_reason, \
                    initiated_by, final_thoughts, preservation_node_id, \
                    preservation_scope, reactivation_count\
                 ) VALUES (?1, 'a', ?2, 0, 'r', 'i', 'ft', 'p', ?3, 0)",
                params![cid, now, "WEIRD_SCOPE"],
            )
        })();
        assert!(
            res.is_err(),
            "CHECK on preservation_scope should reject unknown values"
        );
    }

    #[tokio::test]
    async fn validate_required_columns() {
        let (_b, svc, _graph) = fresh_backend().await;
        let mut r = mk_record("val", "graph:dummy", GraphScope::Identity);
        r.id = String::new();
        let res = svc.record_shutdown(r).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));

        let mut r = mk_record("val", "graph:dummy", GraphScope::Identity);
        r.shutdown_reason = String::new();
        let res = svc.record_shutdown(r).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));
    }
}
