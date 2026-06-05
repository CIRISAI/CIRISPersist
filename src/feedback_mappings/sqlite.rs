//! SQLite impl of [`FeedbackMappingService`] (v1.5.18,
//! CIRISPersist#59 #10).
//!
//! Mirrors the v1.5.18 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ                          → TEXT (RFC 3339)
//!   ON CONFLICT (feedback_id) DO NOTHING → INSERT OR IGNORE
//!   DEFERRABLE INITIALLY DEFERRED        → immediate (SQLite has
//!                                          only immediate FK mode
//!                                          with PRAGMA
//!                                          foreign_keys=ON)
//!
//! Threading: `tokio::task::spawn_blocking` + `conn.lock()`
//! per the existing pattern.
//!
//! `record_feedback` uses the same ClaimResult shape as the v1.5.17
//! continuity_awareness path: `INSERT OR IGNORE` followed by an
//! in-transaction `SELECT` so the race-loser reads back the existing
//! row.
//!
//! # Nullable FK passthrough
//!
//! `target_thought_id` is nullable. SQLite's FK enforcement matches
//! PG's: NULL FKs pass the constraint check without lookup. The FK
//! only fires when the column is non-NULL and the referenced
//! `cirislens_thoughts(thought_id)` row doesn't exist; that surfaces
//! as `Error::Conflict` (rusqlite extended code 787,
//! `SQLITE_CONSTRAINT_FOREIGNKEY`).
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
use rusqlite::{params, types::Value as SqlValue, Connection};

use super::service::FeedbackMappingService;
use super::types::{FeedbackFilter, FeedbackMapping};
use super::Error;
use crate::ClaimResult;

/// SQLite-backed [`FeedbackMappingService`] impl.
pub struct SqliteFeedbackMappingBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteFeedbackMappingBackend {
    /// Construct from a shared connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if err.code == ErrorCode::ConstraintViolation {
            // SQLite collapses CHECK / NOT NULL / FK / UNIQUE under
            // one ErrorCode; distinguish by extended code so FK
            // violations surface as Conflict (parity with PG) and
            // everything else (CHECK / NOT NULL) as InvalidArgument.
            let extended = err.extended_code;
            // 787  = SQLITE_CONSTRAINT_FOREIGNKEY
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

fn validate_feedback(f: &FeedbackMapping) -> Result<(), Error> {
    if f.feedback_id.is_empty() {
        return Err(Error::InvalidArgument("feedback_id required".into()));
    }
    Ok(())
}

fn decode_row(row: &rusqlite::Row<'_>) -> Result<FeedbackMapping, Error> {
    let feedback_id: String = row
        .get("feedback_id")
        .map_err(|e| Error::Backend(format!("decode feedback_id: {e}")))?;
    let source_message_id: Option<String> = row
        .get("source_message_id")
        .map_err(|e| Error::Backend(format!("decode source_message_id: {e}")))?;
    let target_thought_id: Option<String> = row
        .get("target_thought_id")
        .map_err(|e| Error::Backend(format!("decode target_thought_id: {e}")))?;
    let feedback_type: Option<String> = row
        .get("feedback_type")
        .map_err(|e| Error::Backend(format!("decode feedback_type: {e}")))?;
    let created_at_str: String = row
        .get("created_at")
        .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?;
    Ok(FeedbackMapping {
        feedback_id,
        source_message_id,
        target_thought_id,
        feedback_type,
        created_at: parse_datetime(&created_at_str)?,
    })
}

const SELECT_COLUMNS: &str =
    "feedback_id, source_message_id, target_thought_id, feedback_type, created_at";

impl FeedbackMappingService for SqliteFeedbackMappingBackend {
    async fn record_feedback(
        &self,
        feedback: FeedbackMapping,
    ) -> Result<ClaimResult<FeedbackMapping>, Error> {
        validate_feedback(&feedback)?;
        let created_at_str = fmt_datetime(feedback.created_at);
        let id_for_lookup = feedback.feedback_id.clone();

        let conn = self.conn.clone();
        let (won, row): (bool, FeedbackMapping) =
            (move || -> Result<(bool, FeedbackMapping), Error> {
                let mut guard = conn.lock();
                let tx = guard
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(|e| map_sqlite_error(e, "record_feedback begin"))?;
                let changed = tx
                    .execute(
                        "INSERT OR IGNORE INTO cirislens_feedback_mappings (\
                            feedback_id, source_message_id, target_thought_id, \
                            feedback_type, created_at\
                         ) VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            feedback.feedback_id,
                            feedback.source_message_id,
                            feedback.target_thought_id,
                            feedback.feedback_type,
                            created_at_str,
                        ],
                    )
                    .map_err(|e| map_sqlite_error(e, "record_feedback insert"))?;
                let won = changed > 0;
                let row = tx
                    .query_row(
                        &format!(
                            "SELECT {SELECT_COLUMNS} FROM cirislens_feedback_mappings \
                             WHERE feedback_id = ?1"
                        ),
                        params![id_for_lookup],
                        |row| Ok(decode_row(row)),
                    )
                    .map_err(|e| map_sqlite_error(e, "record_feedback readback"))??;
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "record_feedback commit"))?;
                Ok((won, row))
            })()?;

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
        let thought_id_owned = thought_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Vec<FeedbackMapping>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(&format!(
                    "SELECT {SELECT_COLUMNS} FROM cirislens_feedback_mappings \
                     WHERE target_thought_id = ?1 \
                     ORDER BY created_at DESC, feedback_id DESC \
                     LIMIT ?2"
                ))
                .map_err(|e| map_sqlite_error(e, "list_feedback_for_thought prepare"))?;
            let rows_iter = stmt
                .query_map(params![thought_id_owned, limit], |row| Ok(decode_row(row)))
                .map_err(|e| map_sqlite_error(e, "list_feedback_for_thought query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "list_feedback_for_thought row"))??);
            }
            Ok(items)
        })()
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
        let mut sql_params: Vec<SqlValue> = Vec::new();
        if let Some(src) = filter.source_message_id {
            sql_params.push(SqlValue::Text(src));
            where_parts.push(format!("source_message_id = ?{}", sql_params.len()));
        }
        if let Some(ftype) = filter.feedback_type {
            sql_params.push(SqlValue::Text(ftype));
            where_parts.push(format!("feedback_type = ?{}", sql_params.len()));
        }
        if let Some(after) = filter.created_after {
            sql_params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push(format!("created_at >= ?{}", sql_params.len()));
        }
        if let Some(before) = filter.created_before {
            sql_params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push(format!("created_at <= ?{}", sql_params.len()));
        }
        sql_params.push(SqlValue::Integer(limit));
        let p_limit = sql_params.len();
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {} ", where_parts.join(" AND "))
        };
        let sql = format!(
            "SELECT {SELECT_COLUMNS} FROM cirislens_feedback_mappings \
             {where_sql}\
             ORDER BY created_at DESC, feedback_id DESC \
             LIMIT ?{p_limit}"
        );
        let conn = self.conn.clone();
        (move || -> Result<Vec<FeedbackMapping>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "list_feedback prepare"))?;
            let rows_iter = stmt
                .query_map(rusqlite::params_from_iter(sql_params.iter()), |row| {
                    Ok(decode_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "list_feedback query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "list_feedback row"))??);
            }
            Ok(items)
        })()
    }
}

#[cfg(test)]
#[cfg(all(feature = "cirislens_tasks", feature = "cirislens_thoughts"))]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteFeedbackMappingBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteFeedbackMappingBackend::new(backend.conn_handle());
        (backend, svc)
    }

    /// Seed a parent task + parent thought, return the thought_id.
    /// Same shape as the deferral_reports SQLite test helper.
    async fn seed_thought(b: &SqliteBackend) -> String {
        use crate::tasks::sqlite::SqliteTaskBackend;
        use crate::tasks::types::{Task, TaskStatus};
        use crate::tasks::TaskService;
        use crate::thoughts::sqlite::SqliteThoughtBackend;
        use crate::thoughts::types::{Thought, ThoughtStatus, ThoughtType};
        use crate::thoughts::ThoughtService;
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
        thoughts.upsert_thought(thought).await.unwrap();
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

    /// Whether SQLite's FK pragma is on for the test connection.
    /// Mirrors the deferral_reports / scheduled_tasks pattern.
    async fn fk_pragma_on(b: &SqliteBackend) -> bool {
        let conn = b.conn_handle();
        (move || -> bool {
            let guard = conn.lock();
            guard
                .query_row("PRAGMA foreign_keys", params![], |row| row.get::<_, i64>(0))
                .map(|v| v == 1)
                .unwrap_or(false)
        })()
    }

    #[tokio::test]
    async fn record_round_trip_all_5_columns() {
        let (b, svc) = fresh_backend().await;
        let thought_id = seed_thought(&b).await;
        let now = Utc::now();
        let f = FeedbackMapping {
            feedback_id: format!("fb-{}", Uuid::new_v4().simple()),
            source_message_id: Some("msg-abc".into()),
            target_thought_id: Some(thought_id.clone()),
            feedback_type: Some("approval".into()),
            created_at: now,
        };
        let outcome = svc.record_feedback(f.clone()).await.unwrap();
        assert!(matches!(outcome, ClaimResult::Stored(_)));

        let got = svc
            .list_feedback_for_thought(&thought_id, 10)
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        let got = &got[0];
        assert_eq!(got.feedback_id, f.feedback_id);
        assert_eq!(got.source_message_id, f.source_message_id);
        assert_eq!(got.target_thought_id, f.target_thought_id);
        assert_eq!(got.feedback_type, f.feedback_type);
        let drift = (got.created_at - now).num_seconds().abs();
        assert!(drift <= 1, "created_at preserved: {drift}s drift");
    }

    #[tokio::test]
    async fn record_already_claimed_returns_existing_row() {
        let (b, svc) = fresh_backend().await;
        let thought_id = seed_thought(&b).await;
        let f1 = mk_feedback(Some(thought_id));
        let out1 = svc.record_feedback(f1.clone()).await.unwrap();
        assert!(matches!(out1, ClaimResult::Stored(_)));

        // Second record with same feedback_id but different
        // feedback_type — should NOT overwrite.
        let mut f2 = f1.clone();
        f2.feedback_type = Some("correction".into());
        let out2 = svc.record_feedback(f2).await.unwrap();
        assert!(matches!(out2, ClaimResult::AlreadyClaimed(_)));
        let existing = out2.into_reference();
        assert_eq!(
            existing.feedback_type, f1.feedback_type,
            "loser sees original row"
        );
    }

    #[tokio::test]
    async fn fk_rejects_nonexistent_thought_when_set() {
        let (b, svc) = fresh_backend().await;
        if !fk_pragma_on(&b).await {
            eprintln!(
                "SQLite foreign_keys pragma off — skipping FK rejection check. \
                 SqliteBackend is supposed to set this on; investigate if seen."
            );
            return;
        }
        let bogus = format!("thought-bogus-{}", Uuid::new_v4().simple());
        let f = mk_feedback(Some(bogus));
        let res = svc.record_feedback(f).await;
        assert!(
            matches!(res, Err(Error::Conflict(_))),
            "expected FK Conflict for dangling target_thought_id, got {res:?}"
        );
    }

    #[tokio::test]
    async fn null_target_thought_passes_fk() {
        // FK only fires for non-NULL values. NULL target_thought_id
        // bypasses the check natively on SQLite too.
        let (_b, svc) = fresh_backend().await;
        let f = mk_feedback(None);
        let out = svc.record_feedback(f.clone()).await.unwrap();
        assert!(matches!(out, ClaimResult::Stored(_)));
        let stored = out.into_reference();
        assert!(stored.target_thought_id.is_none());
        assert_eq!(stored.feedback_id, f.feedback_id);
    }

    #[tokio::test]
    async fn list_for_thought_returns_3_desc() {
        let (b, svc) = fresh_backend().await;
        let thought_id = seed_thought(&b).await;
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
            svc.record_feedback(f).await.unwrap();
        }
        // ids[0] is oldest, ids[2] is newest.
        let got = svc
            .list_feedback_for_thought(&thought_id, 10)
            .await
            .unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0].feedback_id, ids[2]);
        assert_eq!(got[1].feedback_id, ids[1]);
        assert_eq!(got[2].feedback_id, ids[0]);
    }

    #[tokio::test]
    async fn list_filters_by_source_message_type_and_window() {
        let (_b, svc) = fresh_backend().await;
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
            svc.record_feedback(f.clone()).await.unwrap();
        }

        // Filter by source_message_id = msg_a → 2 rows.
        let by_src = svc
            .list_feedback(
                FeedbackFilter {
                    source_message_id: Some(msg_a.clone()),
                    ..Default::default()
                },
                100,
            )
            .await
            .unwrap();
        assert_eq!(by_src.len(), 2);

        // Combined filter: msg_a AND approval → 1 row (f_a1).
        let combined = svc
            .list_feedback(
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

        // Time-window filter — future created_after → 0.
        let future = svc
            .list_feedback(
                FeedbackFilter {
                    source_message_id: Some(msg_a),
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
    async fn validate_required_columns() {
        let (_b, svc) = fresh_backend().await;
        let mut f = mk_feedback(None);
        f.feedback_id = String::new();
        let res = svc.record_feedback(f).await;
        assert!(matches!(res, Err(Error::InvalidArgument(_))));
    }
}
