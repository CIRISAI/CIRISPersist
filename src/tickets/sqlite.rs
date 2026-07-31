//! SQLite impl of [`TicketService`] (v1.5.13, CIRISPersist#59 #5).
//!
//! Mirrors the v1.5.13 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ                  → TEXT (RFC 3339)
//!   JSONB                        → TEXT (raw JSON string)
//!   BOOLEAN                      → INTEGER (0 / 1)
//!   ON CONFLICT (ticket_id) DO UPDATE   → identical
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
use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};

use super::service::TicketService;
use super::types::{Ticket, TicketCursor, TicketFilter, TicketListPage, TicketStatus};
use super::Error;

/// SQLite-backed [`TicketService`] impl.
pub struct SqliteTicketBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTicketBackend {
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

fn encode_json(v: &serde_json::Value) -> Result<String, Error> {
    serde_json::to_string(v).map_err(|e| Error::Internal(format!("json encode: {e}")))
}

fn decode_json(s: &str) -> Result<serde_json::Value, Error> {
    serde_json::from_str(s).map_err(|e| Error::Backend(format!("json decode: {e} (raw={s})")))
}

fn validate_ticket(t: &Ticket) -> Result<(), Error> {
    if t.ticket_id.is_empty() {
        return Err(Error::InvalidArgument("ticket_id required".into()));
    }
    if t.sop.is_empty() {
        return Err(Error::InvalidArgument("sop required".into()));
    }
    if t.ticket_type.is_empty() {
        return Err(Error::InvalidArgument("ticket_type required".into()));
    }
    if t.email.is_empty() {
        return Err(Error::InvalidArgument("email required".into()));
    }
    if t.agent_occurrence_id.is_empty() {
        return Err(Error::InvalidArgument(
            "agent_occurrence_id required".into(),
        ));
    }
    if !(1..=10).contains(&t.priority) {
        return Err(Error::InvalidArgument(format!(
            "priority must be in [1, 10], got {}",
            t.priority
        )));
    }
    Ok(())
}

fn decode_ticket_row(row: &rusqlite::Row<'_>) -> Result<Ticket, Error> {
    let ticket_id: String = row
        .get("ticket_id")
        .map_err(|e| Error::Backend(format!("decode ticket_id: {e}")))?;
    let sop: String = row
        .get("sop")
        .map_err(|e| Error::Backend(format!("decode sop: {e}")))?;
    let ticket_type: String = row
        .get("ticket_type")
        .map_err(|e| Error::Backend(format!("decode ticket_type: {e}")))?;
    let status_str: String = row
        .get("status")
        .map_err(|e| Error::Backend(format!("decode status: {e}")))?;
    let status = TicketStatus::parse_str(&status_str)
        .ok_or_else(|| Error::Backend(format!("unknown status: {status_str}")))?;
    let priority: i32 = row
        .get("priority")
        .map_err(|e| Error::Backend(format!("decode priority: {e}")))?;
    let email: String = row
        .get("email")
        .map_err(|e| Error::Backend(format!("decode email: {e}")))?;
    let user_identifier: Option<String> = row
        .get("user_identifier")
        .map_err(|e| Error::Backend(format!("decode user_identifier: {e}")))?;
    let submitted_at_str: String = row
        .get("submitted_at")
        .map_err(|e| Error::Backend(format!("decode submitted_at: {e}")))?;
    let deadline_str: Option<String> = row
        .get("deadline")
        .map_err(|e| Error::Backend(format!("decode deadline: {e}")))?;
    let last_updated_str: String = row
        .get("last_updated")
        .map_err(|e| Error::Backend(format!("decode last_updated: {e}")))?;
    let completed_at_str: Option<String> = row
        .get("completed_at")
        .map_err(|e| Error::Backend(format!("decode completed_at: {e}")))?;
    let metadata_raw: String = row
        .get("metadata")
        .map_err(|e| Error::Backend(format!("decode metadata: {e}")))?;
    let notes: Option<String> = row
        .get("notes")
        .map_err(|e| Error::Backend(format!("decode notes: {e}")))?;
    let automated_int: i64 = row
        .get("automated")
        .map_err(|e| Error::Backend(format!("decode automated: {e}")))?;
    let correlation_id: Option<String> = row
        .get("correlation_id")
        .map_err(|e| Error::Backend(format!("decode correlation_id: {e}")))?;
    let agent_occurrence_id: String = row
        .get("agent_occurrence_id")
        .map_err(|e| Error::Backend(format!("decode agent_occurrence_id: {e}")))?;
    let created_at_str: String = row
        .get("created_at")
        .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?;
    Ok(Ticket {
        ticket_id,
        sop,
        ticket_type,
        status,
        priority,
        email,
        user_identifier,
        submitted_at: parse_datetime(&submitted_at_str)?,
        deadline: parse_datetime_opt(deadline_str)?,
        last_updated: parse_datetime(&last_updated_str)?,
        completed_at: parse_datetime_opt(completed_at_str)?,
        metadata: decode_json(&metadata_raw)?,
        notes,
        automated: automated_int != 0,
        correlation_id,
        agent_occurrence_id,
        created_at: parse_datetime(&created_at_str)?,
    })
}

impl TicketService for SqliteTicketBackend {
    async fn upsert_ticket(&self, ticket: Ticket) -> Result<(), Error> {
        validate_ticket(&ticket)?;
        let status_str = ticket.status.as_sql_str().to_owned();
        let submitted_at_str = fmt_datetime(ticket.submitted_at);
        let deadline_str = ticket.deadline.map(fmt_datetime);
        let last_updated_str = fmt_datetime(ticket.last_updated);
        let completed_at_str = ticket.completed_at.map(fmt_datetime);
        let metadata_str = encode_json(&ticket.metadata)?;
        let automated_int: i64 = if ticket.automated { 1 } else { 0 };
        let created_at_str = fmt_datetime(ticket.created_at);

        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let mut guard = conn.lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "upsert_ticket begin"))?;
            tx.execute(
                "INSERT INTO cirislens_tickets (\
                    ticket_id, sop, ticket_type, status, priority, \
                    email, user_identifier, submitted_at, deadline, \
                    last_updated, completed_at, metadata, notes, \
                    automated, correlation_id, agent_occurrence_id, \
                    created_at\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, \
                           ?11, ?12, ?13, ?14, ?15, ?16, ?17) \
                 ON CONFLICT(ticket_id) DO UPDATE SET \
                    sop = excluded.sop, \
                    ticket_type = excluded.ticket_type, \
                    status = excluded.status, \
                    priority = excluded.priority, \
                    email = excluded.email, \
                    user_identifier = excluded.user_identifier, \
                    deadline = excluded.deadline, \
                    last_updated = excluded.last_updated, \
                    completed_at = excluded.completed_at, \
                    metadata = excluded.metadata, \
                    notes = excluded.notes, \
                    automated = excluded.automated, \
                    correlation_id = excluded.correlation_id, \
                    agent_occurrence_id = excluded.agent_occurrence_id",
                params![
                    ticket.ticket_id,
                    ticket.sop,
                    ticket.ticket_type,
                    status_str,
                    ticket.priority,
                    ticket.email,
                    ticket.user_identifier,
                    submitted_at_str,
                    deadline_str,
                    last_updated_str,
                    completed_at_str,
                    metadata_str,
                    ticket.notes,
                    automated_int,
                    ticket.correlation_id,
                    ticket.agent_occurrence_id,
                    created_at_str,
                ],
            )
            .map_err(|e| map_sqlite_error(e, "upsert_ticket insert"))?;
            tx.commit()
                .map_err(|e| map_sqlite_error(e, "upsert_ticket commit"))?;
            Ok(())
        })()
    }

    async fn get_ticket(&self, ticket_id: &str) -> Result<Option<Ticket>, Error> {
        if ticket_id.is_empty() {
            return Err(Error::InvalidArgument("ticket_id required".into()));
        }
        let conn = self.conn.clone();
        let ticket_id_owned = ticket_id.to_owned();
        (move || -> Result<Option<Ticket>, Error> {
            let guard = conn.lock();
            let row_opt = guard
                .query_row(
                    "SELECT ticket_id, sop, ticket_type, status, priority, \
                            email, user_identifier, submitted_at, deadline, \
                            last_updated, completed_at, metadata, notes, \
                            automated, correlation_id, agent_occurrence_id, \
                            created_at \
                     FROM cirislens_tickets WHERE ticket_id = ?1",
                    params![ticket_id_owned],
                    |row| Ok(decode_ticket_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_ticket query"))?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(r?)),
            }
        })()
    }

    async fn list_tickets(
        &self,
        filter: TicketFilter,
        cursor: Option<TicketCursor>,
        limit: i64,
    ) -> Result<TicketListPage, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let mut where_parts: Vec<String> = Vec::new();
        let mut sql_params: Vec<SqlValue> = Vec::new();
        if let Some(sop) = filter.sop {
            sql_params.push(SqlValue::Text(sop));
            where_parts.push(format!("sop = ?{}", sql_params.len()));
        }
        if let Some(tt) = filter.ticket_type {
            sql_params.push(SqlValue::Text(tt));
            where_parts.push(format!("ticket_type = ?{}", sql_params.len()));
        }
        if let Some(status) = filter.status {
            sql_params.push(SqlValue::Text(status.as_sql_str().to_owned()));
            where_parts.push(format!("status = ?{}", sql_params.len()));
        }
        if let Some(email) = filter.email {
            sql_params.push(SqlValue::Text(email));
            where_parts.push(format!("email = ?{}", sql_params.len()));
        }
        if let Some(occ) = filter.agent_occurrence_id {
            sql_params.push(SqlValue::Text(occ));
            where_parts.push(format!("agent_occurrence_id = ?{}", sql_params.len()));
        }
        if let Some(automated) = filter.automated {
            sql_params.push(SqlValue::Integer(if automated { 1 } else { 0 }));
            where_parts.push(format!("automated = ?{}", sql_params.len()));
        }
        if let Some(deadline_before) = filter.deadline_before {
            sql_params.push(SqlValue::Text(fmt_datetime(deadline_before)));
            where_parts.push(format!(
                "deadline IS NOT NULL AND deadline <= ?{}",
                sql_params.len()
            ));
        }
        if let Some(after) = filter.last_updated_after {
            sql_params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push(format!("last_updated >= ?{}", sql_params.len()));
        }
        if let Some(before) = filter.last_updated_before {
            sql_params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push(format!("last_updated <= ?{}", sql_params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "TicketCursor version {} unsupported",
                    cur.version
                )));
            }
            sql_params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
            let p_ts = sql_params.len();
            sql_params.push(SqlValue::Text(cur.last_id.clone()));
            let p_id = sql_params.len();
            where_parts.push(format!("(last_updated, ticket_id) < (?{p_ts}, ?{p_id})"));
        }
        sql_params.push(SqlValue::Integer(limit));
        let p_limit = sql_params.len();
        let where_sql = if where_parts.is_empty() {
            "1=1".to_string()
        } else {
            where_parts.join(" AND ")
        };
        let sql = format!(
            "SELECT ticket_id, sop, ticket_type, status, priority, \
                    email, user_identifier, submitted_at, deadline, \
                    last_updated, completed_at, metadata, notes, \
                    automated, correlation_id, agent_occurrence_id, \
                    created_at \
             FROM cirislens_tickets \
             WHERE {where_sql} \
             ORDER BY last_updated DESC, ticket_id DESC \
             LIMIT ?{p_limit}"
        );
        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        (move || -> Result<TicketListPage, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "list_tickets prepare"))?;
            let rows_iter = stmt
                .query_map(params_from_iter(sql_params.iter()), |row| {
                    Ok(decode_ticket_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "list_tickets query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "list_tickets row"))??);
            }
            let next_cursor = if items.len() == limit_usize {
                items.last().map(|last| {
                    TicketCursor::from_trailing(last.last_updated, last.ticket_id.clone())
                })
            } else {
                None
            };
            Ok(TicketListPage { items, next_cursor })
        })()
    }

    async fn assign_ticket(
        &self,
        ticket_id: &str,
        user_identifier: &str,
        new_status: Option<TicketStatus>,
    ) -> Result<bool, Error> {
        if ticket_id.is_empty() {
            return Err(Error::InvalidArgument("ticket_id required".into()));
        }
        if user_identifier.is_empty() {
            return Err(Error::InvalidArgument("user_identifier required".into()));
        }
        let status_str = new_status
            .unwrap_or(TicketStatus::Assigned)
            .as_sql_str()
            .to_owned();
        let now_str = fmt_datetime(chrono::Utc::now());
        let ticket_id_owned = ticket_id.to_owned();
        let user_identifier_owned = user_identifier.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let mut guard = conn.lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "assign_ticket begin"))?;
            // Lookup-then-update pattern matches the PG impl for
            // idempotent re-assign + clean missing-row detection.
            let existing: Option<Option<String>> = tx
                .query_row(
                    "SELECT user_identifier FROM cirislens_tickets WHERE ticket_id = ?1",
                    params![ticket_id_owned],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "assign_ticket lookup"))?;
            match existing {
                None => {
                    // Missing row.
                    tx.commit()
                        .map_err(|e| map_sqlite_error(e, "assign_ticket commit"))?;
                    Ok(false)
                }
                Some(current_user) => {
                    if current_user.as_deref() == Some(user_identifier_owned.as_str()) {
                        // Re-assign to same user: no-op.
                        tx.commit()
                            .map_err(|e| map_sqlite_error(e, "assign_ticket commit"))?;
                        return Ok(true);
                    }
                    let changed = tx
                        .execute(
                            "UPDATE cirislens_tickets SET \
                                user_identifier = ?1, \
                                status = ?2, \
                                last_updated = ?3 \
                             WHERE ticket_id = ?4",
                            params![user_identifier_owned, status_str, now_str, ticket_id_owned],
                        )
                        .map_err(|e| map_sqlite_error(e, "assign_ticket update"))?;
                    tx.commit()
                        .map_err(|e| map_sqlite_error(e, "assign_ticket commit"))?;
                    Ok(changed > 0)
                }
            }
        })()
    }

    async fn update_ticket_status(
        &self,
        ticket_id: &str,
        new_status: TicketStatus,
        completed_at: Option<DateTime<Utc>>,
        notes: Option<String>,
    ) -> Result<bool, Error> {
        if ticket_id.is_empty() {
            return Err(Error::InvalidArgument("ticket_id required".into()));
        }
        let status_str = new_status.as_sql_str().to_owned();
        let now_str = fmt_datetime(chrono::Utc::now());
        let completed_at_str = completed_at.map(fmt_datetime);
        let ticket_id_owned = ticket_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let guard = conn.lock();
            let mut sets: Vec<String> = vec!["status = ?2".into(), "last_updated = ?3".into()];
            let mut sql_params: Vec<SqlValue> = vec![
                SqlValue::Text(ticket_id_owned),
                SqlValue::Text(status_str),
                SqlValue::Text(now_str),
            ];
            if let Some(ts) = completed_at_str {
                sql_params.push(SqlValue::Text(ts));
                sets.push(format!("completed_at = ?{}", sql_params.len()));
            }
            if let Some(n) = notes {
                sql_params.push(SqlValue::Text(n));
                sets.push(format!("notes = ?{}", sql_params.len()));
            }
            let sql = format!(
                "UPDATE cirislens_tickets SET {} WHERE ticket_id = ?1",
                sets.join(", ")
            );
            let changed = guard
                .execute(&sql, params_from_iter(sql_params.iter()))
                .map_err(|e| map_sqlite_error(e, "update_ticket_status exec"))?;
            Ok(changed > 0)
        })()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteTicketBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteTicketBackend::new(backend.conn_handle());
        (backend, svc)
    }

    fn mk_ticket(id: &str, occurrence: &str) -> Ticket {
        let now = Utc::now();
        Ticket {
            ticket_id: id.to_owned(),
            sop: "SOP-1".into(),
            ticket_type: "support".into(),
            status: TicketStatus::Pending,
            priority: 5,
            email: "user@example.com".into(),
            user_identifier: None,
            submitted_at: now,
            deadline: None,
            last_updated: now,
            completed_at: None,
            metadata: serde_json::json!({}),
            notes: None,
            automated: false,
            correlation_id: None,
            agent_occurrence_id: occurrence.to_owned(),
            created_at: now,
        }
    }

    #[tokio::test]
    async fn upsert_get_round_trip_all_17_columns() {
        let (_b, svc) = fresh_backend().await;
        let id = format!("ticket-{}", Uuid::new_v4().simple());
        let now = Utc::now();
        let t = Ticket {
            ticket_id: id.clone(),
            sop: "SOP-104".into(),
            ticket_type: "user_request".into(),
            status: TicketStatus::InProgress,
            priority: 3,
            email: "user@example.com".into(),
            user_identifier: Some("agent-x".into()),
            submitted_at: now,
            deadline: Some(now + chrono::Duration::days(1)),
            last_updated: now,
            completed_at: None,
            metadata: serde_json::json!({"k": "v", "n": 42}),
            notes: Some("working".into()),
            automated: true,
            correlation_id: Some(format!("corr-{}", Uuid::new_v4().simple())),
            agent_occurrence_id: "occ-1".into(),
            created_at: now,
        };
        svc.upsert_ticket(t.clone()).await.unwrap();
        let got = svc.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.ticket_id, t.ticket_id);
        assert_eq!(got.sop, t.sop);
        assert_eq!(got.ticket_type, t.ticket_type);
        assert_eq!(got.status, t.status);
        assert_eq!(got.priority, t.priority);
        assert_eq!(got.email, t.email);
        assert_eq!(got.user_identifier, t.user_identifier);
        assert_eq!(got.metadata, t.metadata);
        assert_eq!(got.notes, t.notes);
        assert_eq!(got.automated, t.automated);
        assert_eq!(got.correlation_id, t.correlation_id);
        assert_eq!(got.agent_occurrence_id, t.agent_occurrence_id);
        assert!(got.deadline.is_some());
        assert!(got.completed_at.is_none());
    }

    #[tokio::test]
    async fn upsert_idempotent_preserves_created_at_and_submitted_at() {
        let (_b, svc) = fresh_backend().await;
        let id = format!("ticket-{}", Uuid::new_v4().simple());
        let original_created = Utc::now() - chrono::Duration::days(2);
        let original_submitted = Utc::now() - chrono::Duration::days(1);
        let mut t = mk_ticket(&id, "occ-1");
        t.created_at = original_created;
        t.submitted_at = original_submitted;
        t.sop = "SOP-first".into();
        svc.upsert_ticket(t.clone()).await.unwrap();

        let mut t2 = t.clone();
        t2.created_at = Utc::now();
        t2.submitted_at = Utc::now();
        t2.sop = "SOP-second".into();
        svc.upsert_ticket(t2).await.unwrap();

        let got = svc.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.sop, "SOP-second");
        let created_drift = (got.created_at - original_created).num_seconds().abs();
        assert!(created_drift <= 1);
        let submitted_drift = (got.submitted_at - original_submitted).num_seconds().abs();
        assert!(submitted_drift <= 1);
    }

    /// v24.1.0 (CIRISPersist#560) — a PROPOSED ticket stores, reads back as
    /// `proposed`, and is filterable — on sqlite, where the V028 CHECK
    /// (rebuilt by V115) is the gate that would otherwise reject it.
    ///
    /// Then the property the status exists for: approval is a STATUS
    /// TRANSITION, not a metadata edit. `update_ticket_status` carries the
    /// proposal into executable work in one auditable write.
    #[tokio::test]
    async fn proposed_status_round_trips_and_is_approvable_sqlite_560() {
        let (_b, svc) = fresh_backend().await;
        let id = format!("ticket-{}", Uuid::new_v4().simple());
        let mut t = mk_ticket(&id, "occ-560");
        t.status = TicketStatus::Proposed;
        svc.upsert_ticket(t).await.expect(
            "a `proposed` ticket must STORE — before V115 the V028 CHECK \
             rejected it and the consumer had to overload `blocked`",
        );
        let got = svc.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.status, TicketStatus::Proposed);
        assert!(
            !got.status.is_authorized(),
            "an unapproved proposal is not work a discovery query may hand out"
        );

        // Filterable as its own state — the operator-visible half of the ask:
        // a blocked-ticket queue no longer contains proposals.
        let page = svc
            .list_tickets(
                TicketFilter {
                    status: Some(TicketStatus::Proposed),
                    agent_occurrence_id: Some("occ-560".into()),
                    ..Default::default()
                },
                None,
                50,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1, "the proposal is findable BY STATUS");
        assert_eq!(page.items[0].ticket_id, id);

        // Approval: one status write, no metadata edit.
        assert!(svc
            .update_ticket_status(&id, TicketStatus::Pending, None, None)
            .await
            .unwrap());
        let approved = svc.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(approved.status, TicketStatus::Pending);
        assert!(approved.status.is_authorized(), "approval grants authority");
    }

    #[tokio::test]
    async fn status_check_constraint_rejects_unknown_value() {
        let (b, _svc) = fresh_backend().await;
        let conn = b.conn_handle();
        let res = (move || -> rusqlite::Result<usize> {
            let guard = conn.lock();
            guard.execute(
                "INSERT INTO cirislens_tickets (\
                    ticket_id, sop, ticket_type, status, priority, \
                    email, submitted_at, last_updated, created_at\
                 ) VALUES ('id', 'sop', 'tt', 'bogus_status', 5, 'u@x.com', \
                           '2026-01-01T00:00:00.000000+00:00', \
                           '2026-01-01T00:00:00.000000+00:00', \
                           '2026-01-01T00:00:00.000000+00:00')",
                params![],
            )
        })();
        assert!(res.is_err(), "expected CHECK violation on bogus status");
    }

    #[tokio::test]
    async fn priority_check_constraint_rejects_out_of_range_via_trait_validation() {
        let (_b, svc) = fresh_backend().await;
        for bad in [0i32, 11, -1] {
            let id = format!("ticket-{}", Uuid::new_v4().simple());
            let mut t = mk_ticket(&id, "occ-1");
            t.priority = bad;
            let res = svc.upsert_ticket(t).await;
            assert!(
                matches!(res, Err(Error::InvalidArgument(_))),
                "priority {bad} should be rejected, got {res:?}"
            );
        }
    }

    #[tokio::test]
    async fn priority_check_constraint_rejects_out_of_range_at_sql_layer() {
        // Bypass trait-level validation by going directly through
        // raw SQL — verifies the schema-layer CHECK fires.
        let (b, _svc) = fresh_backend().await;
        let conn = b.conn_handle();
        for bad in [0i32, 11, -1] {
            let conn = conn.clone();
            let res = (move || -> rusqlite::Result<usize> {
                let guard = conn.lock();
                guard.execute(
                    "INSERT INTO cirislens_tickets (\
                        ticket_id, sop, ticket_type, status, priority, \
                        email, submitted_at, last_updated, created_at\
                     ) VALUES (?1, 'sop', 'tt', 'pending', ?2, 'u@x.com', \
                               '2026-01-01T00:00:00.000000+00:00', \
                               '2026-01-01T00:00:00.000000+00:00', \
                               '2026-01-01T00:00:00.000000+00:00')",
                    params![format!("id-{bad}"), bad],
                )
            })();
            assert!(
                res.is_err(),
                "expected CHECK violation on priority {bad} at SQL layer"
            );
        }
    }

    #[tokio::test]
    #[allow(clippy::type_complexity)]
    async fn list_filtered_by_sop_status_email_automated_deadline() {
        let (_b, svc) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let base = Utc::now();
        let cases: Vec<(&str, TicketStatus, &str, bool, Option<DateTime<Utc>>)> = vec![
            (
                "SOP-A",
                TicketStatus::Pending,
                "a@x.com",
                false,
                Some(base - chrono::Duration::hours(1)),
            ),
            (
                "SOP-A",
                TicketStatus::InProgress,
                "a@x.com",
                true,
                Some(base - chrono::Duration::hours(2)),
            ),
            (
                "SOP-A",
                TicketStatus::Completed,
                "a@x.com",
                false,
                Some(base - chrono::Duration::hours(3)),
            ),
            ("SOP-B", TicketStatus::Pending, "b@x.com", false, None),
            (
                "SOP-B",
                TicketStatus::Pending,
                "b@x.com",
                true,
                Some(base + chrono::Duration::hours(1)),
            ),
            (
                "SOP-A",
                TicketStatus::Pending,
                "c@x.com",
                false,
                Some(base - chrono::Duration::minutes(5)),
            ),
        ];
        for (sop, status, email, automated, deadline) in cases {
            let id = format!("ticket-{}", Uuid::new_v4().simple());
            let mut t = mk_ticket(&id, &occ);
            t.sop = sop.into();
            t.status = status;
            t.email = email.into();
            t.automated = automated;
            t.deadline = deadline;
            svc.upsert_ticket(t).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        let page = svc
            .list_tickets(
                TicketFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    sop: Some("SOP-A".into()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 4);
        let page = svc
            .list_tickets(
                TicketFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    status: Some(TicketStatus::Pending),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 4);
        let page = svc
            .list_tickets(
                TicketFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    email: Some("a@x.com".into()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 3);
        let page = svc
            .list_tickets(
                TicketFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    automated: Some(true),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2);
        let page = svc
            .list_tickets(
                TicketFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    deadline_before: Some(base),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 4);
    }

    #[tokio::test]
    async fn cursor_pagination() {
        let (_b, svc) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let mut ids = Vec::new();
        for _ in 0..5 {
            let id = format!("ticket-{}", Uuid::new_v4().simple());
            ids.push(id.clone());
            svc.upsert_ticket(mk_ticket(&id, &occ)).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        let filter = TicketFilter {
            agent_occurrence_id: Some(occ.clone()),
            ..Default::default()
        };
        let p1 = svc.list_tickets(filter.clone(), None, 2).await.unwrap();
        assert_eq!(p1.items.len(), 2);
        assert!(p1.next_cursor.is_some());
        let p2 = svc
            .list_tickets(filter.clone(), p1.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 2);
        let p3 = svc
            .list_tickets(filter.clone(), p2.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(p3.items.len(), 1);
        assert!(p3.next_cursor.is_none());
        let mut seen: Vec<String> = p1
            .items
            .iter()
            .chain(p2.items.iter())
            .chain(p3.items.iter())
            .map(|t| t.ticket_id.clone())
            .collect();
        seen.sort();
        let mut expected = ids.clone();
        expected.sort();
        assert_eq!(seen, expected);
    }

    #[tokio::test]
    async fn assign_success_missing_and_reassign_noop() {
        let (_b, svc) = fresh_backend().await;
        let id = format!("ticket-{}", Uuid::new_v4().simple());
        svc.upsert_ticket(mk_ticket(&id, "occ-1")).await.unwrap();

        // First assign: success.
        let ok = svc.assign_ticket(&id, "agent-x", None).await.unwrap();
        assert!(ok);
        let got = svc.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.user_identifier.as_deref(), Some("agent-x"));
        assert_eq!(got.status, TicketStatus::Assigned);

        // Re-assign same user: idempotent no-op, still true.
        let ok = svc.assign_ticket(&id, "agent-x", None).await.unwrap();
        assert!(ok);

        // Re-assign to a different user with caller-supplied InProgress.
        let ok = svc
            .assign_ticket(&id, "agent-y", Some(TicketStatus::InProgress))
            .await
            .unwrap();
        assert!(ok);
        let got = svc.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.user_identifier.as_deref(), Some("agent-y"));
        assert_eq!(got.status, TicketStatus::InProgress);

        // Missing row: false.
        let ok = svc
            .assign_ticket(
                &format!("missing-{}", Uuid::new_v4().simple()),
                "agent-x",
                None,
            )
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn update_status_success_missing_terminal_with_completed_at() {
        let (_b, svc) = fresh_backend().await;
        let id = format!("ticket-{}", Uuid::new_v4().simple());
        svc.upsert_ticket(mk_ticket(&id, "occ-1")).await.unwrap();

        // Non-terminal transition.
        let ok = svc
            .update_ticket_status(&id, TicketStatus::InProgress, None, None)
            .await
            .unwrap();
        assert!(ok);
        let got = svc.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.status, TicketStatus::InProgress);
        assert!(got.completed_at.is_none());

        // Terminal transition: caller supplies completed_at + notes.
        let finished = Utc::now();
        let ok = svc
            .update_ticket_status(
                &id,
                TicketStatus::Completed,
                Some(finished),
                Some("wrapped".into()),
            )
            .await
            .unwrap();
        assert!(ok);
        let got = svc.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.status, TicketStatus::Completed);
        assert!(got.completed_at.is_some());
        assert_eq!(got.notes.as_deref(), Some("wrapped"));

        // Missing row: false.
        let ok = svc
            .update_ticket_status(
                &format!("missing-{}", Uuid::new_v4().simple()),
                TicketStatus::Failed,
                Some(Utc::now()),
                None,
            )
            .await
            .unwrap();
        assert!(!ok);
    }
}
