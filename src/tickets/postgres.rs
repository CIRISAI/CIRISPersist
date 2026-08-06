//! PostgreSQL impl of [`TicketService`] (v1.5.13, CIRISPersist#59
//! #5).
//!
//! All 17 columns lift one-to-one from the row shape. JSON column
//! `metadata` rides as `serde_json::Value` (JSONB on the PG side);
//! timestamps cross as `chrono::DateTime<Utc>` (TIMESTAMPTZ);
//! `automated` is native `bool` (BOOLEAN on the PG side). No FKs on
//! this table — `correlation_id` is a free-form string pointer that
//! may target a span in another substrate or another occurrence's
//! correlations.

use chrono::{DateTime, Utc};

use super::service::TicketService;
use super::types::{Ticket, TicketCursor, TicketFilter, TicketListPage, TicketStatus};
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

fn decode_ticket_row(row: &tokio_postgres::Row) -> Result<Ticket, Error> {
    let status_str: String = row
        .try_get("status")
        .map_err(|e| Error::Backend(format!("decode status: {e}")))?;
    let status = TicketStatus::parse_str(&status_str)
        .ok_or_else(|| Error::Backend(format!("unknown status: {status_str}")))?;
    Ok(Ticket {
        ticket_id: row
            .try_get("ticket_id")
            .map_err(|e| Error::Backend(format!("decode ticket_id: {e}")))?,
        sop: row
            .try_get("sop")
            .map_err(|e| Error::Backend(format!("decode sop: {e}")))?,
        ticket_type: row
            .try_get("ticket_type")
            .map_err(|e| Error::Backend(format!("decode ticket_type: {e}")))?,
        status,
        priority: row
            .try_get("priority")
            .map_err(|e| Error::Backend(format!("decode priority: {e}")))?,
        email: row
            .try_get("email")
            .map_err(|e| Error::Backend(format!("decode email: {e}")))?,
        user_identifier: row
            .try_get("user_identifier")
            .map_err(|e| Error::Backend(format!("decode user_identifier: {e}")))?,
        submitted_at: row
            .try_get("submitted_at")
            .map_err(|e| Error::Backend(format!("decode submitted_at: {e}")))?,
        deadline: row
            .try_get("deadline")
            .map_err(|e| Error::Backend(format!("decode deadline: {e}")))?,
        last_updated: row
            .try_get("last_updated")
            .map_err(|e| Error::Backend(format!("decode last_updated: {e}")))?,
        completed_at: row
            .try_get("completed_at")
            .map_err(|e| Error::Backend(format!("decode completed_at: {e}")))?,
        metadata: row
            .try_get("metadata")
            .map_err(|e| Error::Backend(format!("decode metadata: {e}")))?,
        notes: row
            .try_get("notes")
            .map_err(|e| Error::Backend(format!("decode notes: {e}")))?,
        automated: row
            .try_get("automated")
            .map_err(|e| Error::Backend(format!("decode automated: {e}")))?,
        correlation_id: row
            .try_get("correlation_id")
            .map_err(|e| Error::Backend(format!("decode correlation_id: {e}")))?,
        agent_occurrence_id: row
            .try_get("agent_occurrence_id")
            .map_err(|e| Error::Backend(format!("decode agent_occurrence_id: {e}")))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?,
    })
}

impl TicketService for PostgresBackend {
    async fn upsert_ticket(&self, ticket: Ticket) -> Result<(), Error> {
        validate_ticket(&ticket)?;
        let status_str = ticket.status.as_sql_str().to_owned();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // UPSERT on ticket_id. All columns except `created_at` and
        // `submitted_at` overwrite on conflict; both creation-time
        // columns are preserved so re-upsert doesn't clobber when
        // the ticket was created / submitted.
        client
            .execute(
                "INSERT INTO cirislens.tickets (\
                    ticket_id, sop, ticket_type, status, priority, \
                    email, user_identifier, submitted_at, deadline, \
                    last_updated, completed_at, metadata, notes, \
                    automated, correlation_id, agent_occurrence_id, \
                    created_at\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                           $11, $12, $13, $14, $15, $16, $17) \
                 ON CONFLICT (ticket_id) DO UPDATE SET \
                    sop = EXCLUDED.sop, \
                    ticket_type = EXCLUDED.ticket_type, \
                    status = EXCLUDED.status, \
                    priority = EXCLUDED.priority, \
                    email = EXCLUDED.email, \
                    user_identifier = EXCLUDED.user_identifier, \
                    deadline = EXCLUDED.deadline, \
                    last_updated = EXCLUDED.last_updated, \
                    completed_at = EXCLUDED.completed_at, \
                    metadata = EXCLUDED.metadata, \
                    notes = EXCLUDED.notes, \
                    automated = EXCLUDED.automated, \
                    correlation_id = EXCLUDED.correlation_id, \
                    agent_occurrence_id = EXCLUDED.agent_occurrence_id",
                &[
                    &ticket.ticket_id,
                    &ticket.sop,
                    &ticket.ticket_type,
                    &status_str,
                    &ticket.priority,
                    &ticket.email,
                    &ticket.user_identifier,
                    &ticket.submitted_at,
                    &ticket.deadline,
                    &ticket.last_updated,
                    &ticket.completed_at,
                    &ticket.metadata,
                    &ticket.notes,
                    &ticket.automated,
                    &ticket.correlation_id,
                    &ticket.agent_occurrence_id,
                    &ticket.created_at,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "upsert_ticket"))?;
        Ok(())
    }

    async fn get_ticket(&self, ticket_id: &str) -> Result<Option<Ticket>, Error> {
        if ticket_id.is_empty() {
            return Err(Error::InvalidArgument("ticket_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT ticket_id, sop, ticket_type, status, priority, \
                        email, user_identifier, submitted_at, deadline, \
                        last_updated, completed_at, metadata, notes, \
                        automated, correlation_id, agent_occurrence_id, \
                        created_at \
                 FROM cirislens.tickets WHERE ticket_id = $1",
                &[&ticket_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_ticket"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_ticket_row(&row)?)),
        }
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
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(sop) = filter.sop {
            params.push(Box::new(sop));
            where_parts.push(format!("sop = ${}", params.len()));
        }
        if let Some(tt) = filter.ticket_type {
            params.push(Box::new(tt));
            where_parts.push(format!("ticket_type = ${}", params.len()));
        }
        if let Some(status) = filter.status {
            params.push(Box::new(status.as_sql_str().to_owned()));
            where_parts.push(format!("status = ${}", params.len()));
        }
        if let Some(email) = filter.email {
            params.push(Box::new(email));
            where_parts.push(format!("email = ${}", params.len()));
        }
        if let Some(occ) = filter.agent_occurrence_id {
            params.push(Box::new(occ));
            where_parts.push(format!("agent_occurrence_id = ${}", params.len()));
        }
        if let Some(automated) = filter.automated {
            params.push(Box::new(automated));
            where_parts.push(format!("automated = ${}", params.len()));
        }
        if let Some(deadline_before) = filter.deadline_before {
            params.push(Box::new(deadline_before));
            // `deadline IS NOT NULL AND deadline <= ?` so callers
            // doing a "due-deadline" scan don't accidentally pick up
            // tickets without a deadline.
            where_parts.push(format!(
                "deadline IS NOT NULL AND deadline <= ${}",
                params.len()
            ));
        }
        if let Some(after) = filter.last_updated_after {
            params.push(Box::new(after));
            where_parts.push(format!("last_updated >= ${}", params.len()));
        }
        if let Some(before) = filter.last_updated_before {
            params.push(Box::new(before));
            where_parts.push(format!("last_updated <= ${}", params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "TicketCursor version {} unsupported",
                    cur.version
                )));
            }
            params.push(Box::new(cur.last_ts));
            let p_ts = params.len();
            params.push(Box::new(cur.last_id.clone()));
            let p_id = params.len();
            where_parts.push(format!("(last_updated, ticket_id) < (${p_ts}, ${p_id})"));
        }
        params.push(Box::new(limit));
        let p_limit = params.len();
        let where_sql = if where_parts.is_empty() {
            "TRUE".to_string()
        } else {
            where_parts.join(" AND ")
        };
        let sql = format!(
            "SELECT ticket_id, sop, ticket_type, status, priority, \
                    email, user_identifier, submitted_at, deadline, \
                    last_updated, completed_at, metadata, notes, \
                    automated, correlation_id, agent_occurrence_id, \
                    created_at \
             FROM cirislens.tickets \
             WHERE {where_sql} \
             ORDER BY last_updated DESC, ticket_id DESC \
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
            .map_err(|e| map_pg_error(e, "list_tickets"))?;
        let mut items: Vec<Ticket> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_ticket_row(row)?);
        }
        let next_cursor = if items.len() == limit as usize {
            items
                .last()
                .map(|last| TicketCursor::from_trailing(last.last_updated, last.ticket_id.clone()))
        } else {
            None
        };
        Ok(TicketListPage { items, next_cursor })
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
        let now = chrono::Utc::now();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // First: confirm the ticket exists (so we can return
        // false for missing rows distinct from
        // "exists+already-assigned-to-same-user").
        let row_opt = client
            .query_opt(
                "SELECT user_identifier FROM cirislens.tickets WHERE ticket_id = $1",
                &[&ticket_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "assign_ticket lookup"))?;
        let existing_user: Option<String> = match row_opt {
            None => return Ok(false),
            Some(row) => row
                .try_get("user_identifier")
                .map_err(|e| Error::Backend(format!("decode user_identifier: {e}")))?,
        };
        // Re-assigning to the same user is a no-op (idempotent).
        // Row exists, so return true.
        if existing_user.as_deref() == Some(user_identifier) {
            return Ok(true);
        }
        let changed = client
            .execute(
                "UPDATE cirislens.tickets SET \
                    user_identifier = $1, \
                    status = $2, \
                    last_updated = $3 \
                 WHERE ticket_id = $4",
                &[&user_identifier, &status_str, &now, &ticket_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "assign_ticket update"))?;
        Ok(changed > 0)
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
        let now = chrono::Utc::now();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // Dynamically build the SET clause so callers that don't
        // supply `completed_at` / `notes` don't overwrite those
        // columns. `status` + `last_updated` are always written.
        let mut sets: Vec<String> = vec!["status = $2".into(), "last_updated = $3".into()];
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = vec![
            Box::new(ticket_id.to_owned()),
            Box::new(status_str),
            Box::new(now),
        ];
        if let Some(ts) = completed_at {
            params.push(Box::new(ts));
            sets.push(format!("completed_at = ${}", params.len()));
        }
        if let Some(n) = notes {
            params.push(Box::new(n));
            sets.push(format!("notes = ${}", params.len()));
        }
        let sql = format!(
            "UPDATE cirislens.tickets SET {} WHERE ticket_id = $1",
            sets.join(", ")
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let changed = client
            .execute(&sql, &params_ref[..])
            .await
            .map_err(|e| map_pg_error(e, "update_ticket_status"))?;
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

    /// v24.1.0 (CIRISPersist#560) — the `proposed` witness on POSTGRES, where
    /// the V115 twin drops the V028 CHECK **by discovery** and re-adds the
    /// 9-value one. Same body as the sqlite test: store, read back, filter by
    /// status, then approve as a status TRANSITION.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn proposed_status_round_trips_and_is_approvable_postgres_560() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id = format!("ticket-{}", Uuid::new_v4().simple());
        let occurrence = format!("occ-560-{}", Uuid::new_v4().simple());
        let mut t = mk_ticket(&id, &occurrence);
        t.status = TicketStatus::Proposed;
        TicketService::upsert_ticket(&backend, t).await.expect(
            "a `proposed` ticket must STORE — before V115 the V028 CHECK \
             rejected it with 23514 and the consumer had to overload `blocked`",
        );
        let got = backend.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.status, TicketStatus::Proposed);
        assert!(!got.status.is_authorized());

        let page = backend
            .list_tickets(
                TicketFilter {
                    status: Some(TicketStatus::Proposed),
                    agent_occurrence_id: Some(occurrence),
                    ..Default::default()
                },
                None,
                50,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1, "the proposal is findable BY STATUS");
        assert_eq!(page.items[0].ticket_id, id);

        assert!(backend
            .update_ticket_status(&id, TicketStatus::Pending, None, None)
            .await
            .unwrap());
        let approved = backend.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(approved.status, TicketStatus::Pending);
        assert!(approved.status.is_authorized(), "approval grants authority");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tickets_pg_upsert_get_full_columns_round_trip() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

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
            notes: Some("working on it".into()),
            automated: true,
            correlation_id: Some(format!("corr-{}", Uuid::new_v4().simple())),
            agent_occurrence_id: "occ-1".into(),
            created_at: now,
        };
        TicketService::upsert_ticket(&backend, t.clone())
            .await
            .unwrap();
        let got = backend.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.ticket_id, t.ticket_id);
        assert_eq!(got.sop, t.sop);
        assert_eq!(got.ticket_type, t.ticket_type);
        assert_eq!(got.status, t.status);
        assert_eq!(got.priority, t.priority);
        assert_eq!(got.email, t.email);
        assert_eq!(got.user_identifier, t.user_identifier);
        // TIMESTAMPTZ stores microsecond precision; the wire nanos
        // truncate. Assert presence + same-second match instead of
        // bit-for-bit equality.
        assert!(got.deadline.is_some());
        let deadline_drift = (got.deadline.unwrap() - t.deadline.unwrap())
            .num_seconds()
            .abs();
        assert!(
            deadline_drift <= 1,
            "deadline preserved: {deadline_drift}s drift"
        );
        assert_eq!(got.completed_at, t.completed_at);
        assert_eq!(got.metadata, t.metadata);
        assert_eq!(got.notes, t.notes);
        assert_eq!(got.automated, t.automated);
        assert_eq!(got.correlation_id, t.correlation_id);
        assert_eq!(got.agent_occurrence_id, t.agent_occurrence_id);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tickets_pg_upsert_idempotent_preserves_created_at_and_submitted_at() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id = format!("ticket-{}", Uuid::new_v4().simple());
        let original_created = Utc::now() - chrono::Duration::days(2);
        let original_submitted = Utc::now() - chrono::Duration::days(1);
        let mut t = mk_ticket(&id, "occ-1");
        t.created_at = original_created;
        t.submitted_at = original_submitted;
        t.sop = "SOP-first".into();
        TicketService::upsert_ticket(&backend, t.clone())
            .await
            .unwrap();

        // Second upsert with same id, NEW created_at + submitted_at +
        // sop. Both creation-time columns should stay at the
        // original; sop should update.
        let mut t2 = t.clone();
        t2.created_at = Utc::now();
        t2.submitted_at = Utc::now();
        t2.sop = "SOP-second".into();
        TicketService::upsert_ticket(&backend, t2).await.unwrap();

        let got = backend.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.sop, "SOP-second", "sop updated by upsert");
        let created_drift = (got.created_at - original_created).num_seconds().abs();
        assert!(
            created_drift <= 1,
            "created_at preserved: {created_drift}s drift"
        );
        let submitted_drift = (got.submitted_at - original_submitted).num_seconds().abs();
        assert!(
            submitted_drift <= 1,
            "submitted_at preserved: {submitted_drift}s drift"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tickets_pg_status_check_rejects_unknown_value() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let client = backend.pool().get().await.unwrap();
        let res = client
            .execute(
                "INSERT INTO cirislens.tickets (\
                    ticket_id, sop, ticket_type, status, email, \
                    submitted_at, last_updated\
                 ) VALUES ($1, 'SOP-1', 'support', 'bogus_status', 'u@x.com', \
                           NOW(), NOW())",
                &[&format!("ticket-{}", Uuid::new_v4().simple())],
            )
            .await;
        assert!(res.is_err(), "expected CHECK violation on bogus status");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tickets_pg_priority_check_rejects_out_of_range() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        for bad_priority in [0i32, 11, -1] {
            let id = format!("ticket-{}", Uuid::new_v4().simple());
            let mut t = mk_ticket(&id, "occ-1");
            t.priority = bad_priority;
            let res = TicketService::upsert_ticket(&backend, t).await;
            assert!(
                matches!(res, Err(Error::InvalidArgument(_))),
                "priority {bad_priority} should be rejected by trait-level validation, got {res:?}"
            );
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    #[allow(clippy::type_complexity)]
    async fn tickets_pg_list_filtered_by_sop_status_email_automated_deadline() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let base = Utc::now();
        // 6 tickets — varied sop / status / email / automated / deadline.
        let cases: Vec<(&str, TicketStatus, &str, bool, Option<DateTime<Utc>>)> = vec![
            (
                "SOP-A",
                TicketStatus::Pending,
                "a@x.com",
                false,
                Some(base - chrono::Duration::hours(1)),
            ), // due
            (
                "SOP-A",
                TicketStatus::InProgress,
                "a@x.com",
                true,
                Some(base - chrono::Duration::hours(2)),
            ), // due
            (
                "SOP-A",
                TicketStatus::Completed,
                "a@x.com",
                false,
                Some(base - chrono::Duration::hours(3)),
            ), // not due (terminal)
            ("SOP-B", TicketStatus::Pending, "b@x.com", false, None),
            (
                "SOP-B",
                TicketStatus::Pending,
                "b@x.com",
                true,
                Some(base + chrono::Duration::hours(1)),
            ), // future
            (
                "SOP-A",
                TicketStatus::Pending,
                "c@x.com",
                false,
                Some(base - chrono::Duration::minutes(5)),
            ), // due
        ];
        for (sop, status, email, automated, deadline) in cases {
            let id = format!("ticket-{}", Uuid::new_v4().simple());
            let mut t = mk_ticket(&id, &occ);
            t.sop = sop.into();
            t.status = status;
            t.email = email.into();
            t.automated = automated;
            t.deadline = deadline;
            TicketService::upsert_ticket(&backend, t).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        // sop filter
        let page = backend
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
        assert_eq!(page.items.len(), 4, "SOP-A count");
        // status filter
        let page = backend
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
        assert_eq!(page.items.len(), 4, "Pending count");
        // email filter
        let page = backend
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
        assert_eq!(page.items.len(), 3, "a@x.com count");
        // automated=true filter
        let page = backend
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
        assert_eq!(page.items.len(), 2, "automated=true count");
        // deadline_before — past deadlines (3 rows have past deadline,
        // but `Completed` is included here because the filter doesn't
        // exclude terminal-state by itself — pair with status filter
        // for the "due, non-terminal" hot path).
        let page = backend
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
        assert_eq!(page.items.len(), 4, "deadline_before=now count");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tickets_pg_cursor_pagination() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let mut ids = Vec::new();
        for _ in 0..5 {
            let id = format!("ticket-{}", Uuid::new_v4().simple());
            ids.push(id.clone());
            TicketService::upsert_ticket(&backend, mk_ticket(&id, &occ))
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        let filter = TicketFilter {
            agent_occurrence_id: Some(occ.clone()),
            ..Default::default()
        };
        let p1 = backend.list_tickets(filter.clone(), None, 2).await.unwrap();
        assert_eq!(p1.items.len(), 2);
        assert!(p1.next_cursor.is_some());
        let p2 = backend
            .list_tickets(filter.clone(), p1.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 2);
        let p3 = backend
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
    #[serial_test::serial(postgres)]
    async fn tickets_pg_assign_success_missing_and_reassign_noop() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id = format!("ticket-{}", Uuid::new_v4().simple());
        TicketService::upsert_ticket(&backend, mk_ticket(&id, "occ-1"))
            .await
            .unwrap();

        // First assign: success.
        let ok = backend.assign_ticket(&id, "agent-x", None).await.unwrap();
        assert!(ok);
        let got = backend.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.user_identifier.as_deref(), Some("agent-x"));
        assert_eq!(got.status, TicketStatus::Assigned);

        // Re-assign to same user: no-op (returns true since row
        // exists in assigned state).
        let ok = backend.assign_ticket(&id, "agent-x", None).await.unwrap();
        assert!(ok, "re-assign to same user returns true (idempotent)");

        // Re-assign with caller-supplied new_status = InProgress.
        let ok = backend
            .assign_ticket(&id, "agent-y", Some(TicketStatus::InProgress))
            .await
            .unwrap();
        assert!(ok);
        let got = backend.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.user_identifier.as_deref(), Some("agent-y"));
        assert_eq!(got.status, TicketStatus::InProgress);

        // Missing row → false.
        let ok = backend
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
    #[serial_test::serial(postgres)]
    async fn tickets_pg_update_status_success_missing_and_terminal_with_completed_at() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id = format!("ticket-{}", Uuid::new_v4().simple());
        TicketService::upsert_ticket(&backend, mk_ticket(&id, "occ-1"))
            .await
            .unwrap();

        // Non-terminal transition: completed_at = None, notes = None.
        let ok = backend
            .update_ticket_status(&id, TicketStatus::InProgress, None, None)
            .await
            .unwrap();
        assert!(ok);
        let got = backend.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.status, TicketStatus::InProgress);
        assert!(got.completed_at.is_none());
        assert!(got.notes.is_none());

        // Terminal transition: caller supplies completed_at + notes.
        let finished = Utc::now();
        let ok = backend
            .update_ticket_status(
                &id,
                TicketStatus::Completed,
                Some(finished),
                Some("wrapped".into()),
            )
            .await
            .unwrap();
        assert!(ok);
        let got = backend.get_ticket(&id).await.unwrap().expect("present");
        assert_eq!(got.status, TicketStatus::Completed);
        assert!(got.completed_at.is_some());
        assert_eq!(got.notes.as_deref(), Some("wrapped"));

        // Missing row → false.
        let ok = backend
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
