//! PostgreSQL impl of [`IncidentService`] (v0.8.3, CIRISPersist#37).
//!
//! Correlation-keyed dedup: `record_incident` runs a JSONB `?|`
//! probe against open/investigating incidents in the same
//! `(tenant_id, category)` BEFORE the INSERT; matched incidents
//! get an UPDATE with `occurrences = occurrences + 1` and
//! `last_seen_at = NOW()`. State transitions go through an
//! AV-55-guarded UPDATE with `WHERE state = $expected_previous`.

use super::service::IncidentService;
use super::types::{
    Incident, IncidentCursor, IncidentFilter, IncidentListPage, IncidentRef, IncidentSeverity,
    IncidentState, IncidentTransition,
};
use super::{Error, MAX_CORRELATION_KEYS, MAX_CORRELATION_KEY_BYTES};
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
        _ => Error::Backend(format!("{op}: {detail}")),
    }
}

/// AV-56: enforce correlation_keys bounds at trait surface.
fn validate_correlation_keys(keys: &[String]) -> Result<(), Error> {
    if keys.len() > MAX_CORRELATION_KEYS {
        return Err(Error::InvalidArgument(format!(
            "correlation_keys: {} exceeds MAX_CORRELATION_KEYS={}",
            keys.len(),
            MAX_CORRELATION_KEYS
        )));
    }
    for k in keys {
        if k.is_empty() {
            return Err(Error::InvalidArgument(
                "correlation_keys: empty strings not allowed".into(),
            ));
        }
        if k.len() > MAX_CORRELATION_KEY_BYTES {
            return Err(Error::InvalidArgument(format!(
                "correlation_keys: one key is {} bytes, exceeds MAX_CORRELATION_KEY_BYTES={}",
                k.len(),
                MAX_CORRELATION_KEY_BYTES
            )));
        }
    }
    Ok(())
}

fn parse_incident_id(s: &str) -> Result<uuid::Uuid, Error> {
    uuid::Uuid::parse_str(s).map_err(|e| Error::InvalidArgument(format!("incident_id parse: {e}")))
}

fn decode_incident_row(row: &tokio_postgres::Row) -> Result<Incident, Error> {
    let id: uuid::Uuid = row
        .try_get("incident_id")
        .map_err(|e| Error::Backend(format!("decode incident_id: {e}")))?;
    let state_str: String = row
        .try_get("state")
        .map_err(|e| Error::Backend(format!("decode state: {e}")))?;
    let state = IncidentState::from_sql_str(&state_str)
        .ok_or_else(|| Error::Backend(format!("unknown state: {state_str}")))?;
    let severity_str: String = row
        .try_get("severity")
        .map_err(|e| Error::Backend(format!("decode severity: {e}")))?;
    let severity = IncidentSeverity::from_sql_str(&severity_str)
        .ok_or_else(|| Error::Backend(format!("unknown severity: {severity_str}")))?;
    let corr_json: serde_json::Value = row
        .try_get("correlation_keys")
        .map_err(|e| Error::Backend(format!("decode correlation_keys: {e}")))?;
    let correlation_keys: Vec<String> = serde_json::from_value(corr_json)
        .map_err(|e| Error::Backend(format!("correlation_keys JSONB decode: {e}")))?;
    Ok(Incident {
        incident_id: id.to_string(),
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|e| Error::Backend(format!("decode tenant_id: {e}")))?,
        severity,
        category: row
            .try_get("category")
            .map_err(|e| Error::Backend(format!("decode category: {e}")))?,
        title: row
            .try_get("title")
            .map_err(|e| Error::Backend(format!("decode title: {e}")))?,
        description: row
            .try_get("description")
            .map_err(|e| Error::Backend(format!("decode description: {e}")))?,
        correlation_keys,
        state,
        first_seen_at: row
            .try_get("first_seen_at")
            .map_err(|e| Error::Backend(format!("decode first_seen_at: {e}")))?,
        last_seen_at: row
            .try_get("last_seen_at")
            .map_err(|e| Error::Backend(format!("decode last_seen_at: {e}")))?,
        resolved_at: row
            .try_get("resolved_at")
            .map_err(|e| Error::Backend(format!("decode resolved_at: {e}")))?,
        resolution_notes: row
            .try_get("resolution_notes")
            .map_err(|e| Error::Backend(format!("decode resolution_notes: {e}")))?,
        occurrences: row
            .try_get("occurrences")
            .map_err(|e| Error::Backend(format!("decode occurrences: {e}")))?,
        // v1.5.5 — forensic fields. All NULL for pre-V022 rows or
        // non-EXCEPTION incidents; try_get on Option<_> returns
        // None for SQL NULL, so this is safe across the upgrade
        // boundary.
        incident_type: row
            .try_get("incident_type")
            .map_err(|e| Error::Backend(format!("decode incident_type: {e}")))?,
        source_component: row
            .try_get("source_component")
            .map_err(|e| Error::Backend(format!("decode source_component: {e}")))?,
        handler_name: row
            .try_get("handler_name")
            .map_err(|e| Error::Backend(format!("decode handler_name: {e}")))?,
        exception_type: row
            .try_get("exception_type")
            .map_err(|e| Error::Backend(format!("decode exception_type: {e}")))?,
        stack_trace: row
            .try_get("stack_trace")
            .map_err(|e| Error::Backend(format!("decode stack_trace: {e}")))?,
        filename: row
            .try_get("filename")
            .map_err(|e| Error::Backend(format!("decode filename: {e}")))?,
        line_number: row
            .try_get("line_number")
            .map_err(|e| Error::Backend(format!("decode line_number: {e}")))?,
        function_name: row
            .try_get("function_name")
            .map_err(|e| Error::Backend(format!("decode function_name: {e}")))?,
        impact: row
            .try_get("impact")
            .map_err(|e| Error::Backend(format!("decode impact: {e}")))?,
        urgency: row
            .try_get("urgency")
            .map_err(|e| Error::Backend(format!("decode urgency: {e}")))?,
        detection_method: row
            .try_get("detection_method")
            .map_err(|e| Error::Backend(format!("decode detection_method: {e}")))?,
    })
}

impl IncidentService for PostgresBackend {
    async fn record_incident(&self, incident: Incident) -> Result<String, Error> {
        if incident.tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id required".into()));
        }
        if incident.category.is_empty() {
            return Err(Error::InvalidArgument("category required".into()));
        }
        if incident.title.is_empty() {
            return Err(Error::InvalidArgument("title required".into()));
        }
        // v1.5.5 — only rank-0 states (Open / Recurring) are
        // legal initial states for a fresh INSERT. Investigating
        // / Resolved / Closed must be reached through
        // `transition_state` so the AV-55 monotonicity guards
        // (notes-required + rank-increasing) are enforced.
        if !matches!(
            incident.state,
            IncidentState::Open | IncidentState::Recurring
        ) {
            return Err(Error::InvalidArgument(format!(
                "record_incident: initial state must be Open or Recurring, got {:?}",
                incident.state
            )));
        }
        validate_correlation_keys(&incident.correlation_keys)?;

        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin tx: {e}")))?;

        // Correlation-key match probe — only against OPEN /
        // INVESTIGATING incidents for the same (tenant, category).
        // JSONB `?|` returns true if the LHS contains ANY of the
        // string keys in the RHS text[] array.
        let dup_row_opt = if incident.correlation_keys.is_empty() {
            None
        } else {
            tx.query_opt(
                "SELECT incident_id FROM cirislens.incident_records \
                 WHERE tenant_id = $1 \
                   AND category = $2 \
                   AND state IN ('open', 'investigating') \
                   AND correlation_keys ?| $3 \
                 ORDER BY last_seen_at DESC \
                 LIMIT 1 \
                 FOR UPDATE",
                &[
                    &incident.tenant_id,
                    &incident.category,
                    &incident.correlation_keys,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_incident dedup probe"))?
        };

        let landed_id = if let Some(row) = dup_row_opt {
            // Dedup path — bump existing.
            let existing_id: uuid::Uuid = row
                .try_get("incident_id")
                .map_err(|e| Error::Backend(format!("decode dup id: {e}")))?;
            tx.execute(
                "UPDATE cirislens.incident_records SET \
                    occurrences = occurrences + 1, \
                    last_seen_at = NOW() \
                 WHERE incident_id = $1",
                &[&existing_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_incident dedup bump"))?;
            existing_id.to_string()
        } else {
            // Fresh insert.
            let new_id = parse_incident_id(&incident.incident_id)?;
            let corr_json = serde_json::to_value(&incident.correlation_keys)
                .map_err(|e| Error::Internal(format!("correlation_keys serialize: {e}")))?;
            // v1.5.5 (CIRISPersist#56) — INSERT extended to carry
            // the 11 forensic columns. State now flows from the
            // incident payload (was hard-coded to 'open' in V016);
            // v1.5.5 admits 'recurring' as a valid initial state
            // for "open with identified pattern" records. AV-55
            // forward-only transition rules still apply once a row
            // is in the table.
            tx.execute(
                "INSERT INTO cirislens.incident_records (\
                    incident_id, tenant_id, severity, category, title, description, \
                    correlation_keys, state, first_seen_at, last_seen_at, occurrences, \
                    persist_row_hash, \
                    incident_type, source_component, handler_name, exception_type, \
                    stack_trace, filename, line_number, function_name, impact, urgency, \
                    detection_method\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, \
                           $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)",
                &[
                    &new_id,
                    &incident.tenant_id,
                    &incident.severity.as_sql_str(),
                    &incident.category,
                    &incident.title,
                    &incident.description,
                    &corr_json,
                    &incident.state.as_sql_str(),
                    &incident.first_seen_at,
                    &incident.last_seen_at,
                    &incident.occurrences.max(1),
                    &new_id.to_string(), // persist_row_hash placeholder
                    &incident.incident_type,
                    &incident.source_component,
                    &incident.handler_name,
                    &incident.exception_type,
                    &incident.stack_trace,
                    &incident.filename,
                    &incident.line_number,
                    &incident.function_name,
                    &incident.impact,
                    &incident.urgency,
                    &incident.detection_method,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_incident insert"))?;
            new_id.to_string()
        };

        tx.commit()
            .await
            .map_err(|e| Error::Backend(format!("commit: {e}")))?;
        Ok(landed_id)
    }

    async fn transition_state(&self, transition: IncidentTransition) -> Result<(), Error> {
        // AV-55: notes required for Resolved/Closed transitions.
        if matches!(
            transition.new_state,
            IncidentState::Resolved | IncidentState::Closed
        ) && transition.resolution_notes.is_none()
        {
            return Err(Error::InvalidArgument(format!(
                "resolution_notes required for transition to {:?}",
                transition.new_state
            )));
        }
        let id = parse_incident_id(&transition.incident_id)?;

        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin tx: {e}")))?;

        // Read current state under FOR UPDATE for AV-55 check.
        let current_row = tx
            .query_opt(
                "SELECT state FROM cirislens.incident_records \
                 WHERE incident_id = $1 FOR UPDATE",
                &[&id],
            )
            .await
            .map_err(|e| map_pg_error(e, "transition_state read"))?;
        let current_state_str: String = current_row
            .ok_or_else(|| Error::NotFound(format!("incident_id {id}")))?
            .try_get("state")
            .map_err(|e| Error::Backend(format!("decode current state: {e}")))?;
        let current_state = IncidentState::from_sql_str(&current_state_str)
            .ok_or_else(|| Error::Backend(format!("unknown current state: {current_state_str}")))?;

        if !current_state.can_transition_to(transition.new_state) {
            return Err(Error::InvalidTransition(format!(
                "{:?} → {:?} is not a legal forward transition",
                current_state, transition.new_state
            )));
        }

        // Resolved/Closed: stamp resolved_at + notes (preserved
        // through subsequent transitions; e.g. resolved → closed
        // keeps the original resolved_at).
        let now = chrono::Utc::now();
        match transition.new_state {
            IncidentState::Resolved => {
                tx.execute(
                    "UPDATE cirislens.incident_records SET \
                        state = $1, \
                        resolved_at = $2, \
                        resolution_notes = $3, \
                        last_seen_at = $2 \
                     WHERE incident_id = $4",
                    &[
                        &transition.new_state.as_sql_str(),
                        &now,
                        &transition.resolution_notes,
                        &id,
                    ],
                )
                .await
                .map_err(|e| map_pg_error(e, "transition_state to resolved"))?;
            }
            IncidentState::Closed => {
                // Closed: keep existing resolved_at if set, else
                // stamp it now. Update notes if caller provided.
                tx.execute(
                    "UPDATE cirislens.incident_records SET \
                        state = $1, \
                        resolved_at = COALESCE(resolved_at, $2), \
                        resolution_notes = COALESCE($3, resolution_notes), \
                        last_seen_at = $2 \
                     WHERE incident_id = $4",
                    &[
                        &transition.new_state.as_sql_str(),
                        &now,
                        &transition.resolution_notes,
                        &id,
                    ],
                )
                .await
                .map_err(|e| map_pg_error(e, "transition_state to closed"))?;
            }
            _ => {
                // Investigating: just flip state + last_seen_at.
                tx.execute(
                    "UPDATE cirislens.incident_records SET \
                        state = $1, \
                        last_seen_at = $2 \
                     WHERE incident_id = $3",
                    &[&transition.new_state.as_sql_str(), &now, &id],
                )
                .await
                .map_err(|e| map_pg_error(e, "transition_state to investigating"))?;
            }
        }

        tx.commit()
            .await
            .map_err(|e| Error::Backend(format!("commit: {e}")))?;
        Ok(())
    }

    async fn list_incidents(
        &self,
        filter: IncidentFilter,
        cursor: Option<IncidentCursor>,
        limit: i64,
    ) -> Result<IncidentListPage, Error> {
        if filter.tenant_id.is_empty() {
            return Err(Error::InvalidArgument(
                "tenant_id required (no cross-tenant reads)".into(),
            ));
        }
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }

        let mut where_parts: Vec<String> = vec!["tenant_id = $1".to_string()];
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            vec![Box::new(filter.tenant_id)];
        if let Some(state) = filter.state {
            params.push(Box::new(state.as_sql_str().to_owned()));
            where_parts.push(format!("state = ${}", params.len()));
        }
        if let Some(sev) = filter.severity {
            params.push(Box::new(sev.as_sql_str().to_owned()));
            where_parts.push(format!("severity = ${}", params.len()));
        }
        if let Some(cat) = filter.category {
            params.push(Box::new(cat));
            where_parts.push(format!("category = ${}", params.len()));
        }
        if !filter.has_correlation_keys.is_empty() {
            params.push(Box::new(filter.has_correlation_keys));
            where_parts.push(format!("correlation_keys ?& ${}", params.len()));
        }
        if let Some(after) = filter.first_seen_after {
            params.push(Box::new(after));
            where_parts.push(format!("first_seen_at >= ${}", params.len()));
        }
        if let Some(before) = filter.first_seen_before {
            params.push(Box::new(before));
            where_parts.push(format!("first_seen_at <= ${}", params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "IncidentCursor version {} unsupported",
                    cur.version
                )));
            }
            let last_uuid = parse_incident_id(&cur.last_id)?;
            params.push(Box::new(cur.last_ts));
            let p_ts = params.len();
            params.push(Box::new(last_uuid));
            let p_id = params.len();
            where_parts.push(format!("(first_seen_at, incident_id) < (${p_ts}, ${p_id})"));
        }
        params.push(Box::new(limit));
        let p_limit = params.len();
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT incident_id, tenant_id, severity, category, title, description, \
                    correlation_keys, state, first_seen_at, last_seen_at, \
                    resolved_at, resolution_notes, occurrences, \
                    incident_type, source_component, handler_name, exception_type, \
                    stack_trace, filename, line_number, function_name, impact, urgency, \
                    detection_method \
             FROM cirislens.incident_records \
             WHERE {where_sql} \
             ORDER BY first_seen_at DESC, incident_id DESC \
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
            .map_err(|e| map_pg_error(e, "list_incidents"))?;
        let mut items: Vec<Incident> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_incident_row(row)?);
        }
        let next_cursor = if items.len() == limit as usize {
            items.last().map(|last| {
                IncidentCursor::from_trailing(last.first_seen_at, last.incident_id.clone())
            })
        } else {
            None
        };
        Ok(IncidentListPage { items, next_cursor })
    }

    async fn correlate(&self, tenant_id: &str, key: &str) -> Result<Vec<IncidentRef>, Error> {
        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id required".into()));
        }
        if key.is_empty() {
            return Err(Error::InvalidArgument("key must be non-empty".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT incident_id, severity, category, state, last_seen_at \
                 FROM cirislens.incident_records \
                 WHERE tenant_id = $1 AND correlation_keys ? $2 \
                 ORDER BY last_seen_at DESC",
                &[&tenant_id, &key],
            )
            .await
            .map_err(|e| map_pg_error(e, "correlate"))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let id: uuid::Uuid = row
                .try_get("incident_id")
                .map_err(|e| Error::Backend(format!("decode incident_id: {e}")))?;
            let sev_str: String = row
                .try_get("severity")
                .map_err(|e| Error::Backend(format!("decode severity: {e}")))?;
            let st_str: String = row
                .try_get("state")
                .map_err(|e| Error::Backend(format!("decode state: {e}")))?;
            out.push(IncidentRef {
                incident_id: id.to_string(),
                severity: IncidentSeverity::from_sql_str(&sev_str)
                    .ok_or_else(|| Error::Backend(format!("unknown severity: {sev_str}")))?,
                category: row
                    .try_get("category")
                    .map_err(|e| Error::Backend(format!("decode category: {e}")))?,
                state: IncidentState::from_sql_str(&st_str)
                    .ok_or_else(|| Error::Backend(format!("unknown state: {st_str}")))?,
                last_seen_at: row
                    .try_get("last_seen_at")
                    .map_err(|e| Error::Backend(format!("decode last_seen_at: {e}")))?,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    fn mk_incident(
        tenant_id: &str,
        category: &str,
        severity: IncidentSeverity,
        title: &str,
        correlation_keys: Vec<String>,
    ) -> Incident {
        let now = Utc::now();
        Incident {
            incident_id: Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_owned(),
            severity,
            category: category.to_owned(),
            title: title.to_owned(),
            description: None,
            correlation_keys,
            state: IncidentState::Open,
            first_seen_at: now,
            last_seen_at: now,
            resolved_at: None,
            resolution_notes: None,
            occurrences: 1,
            // v1.5.5 forensic fields default to None in the test
            // helper — exercises the back-compat path for existing
            // lifecycle tests.
            incident_type: None,
            source_component: None,
            handler_name: None,
            exception_type: None,
            stack_trace: None,
            filename: None,
            line_number: None,
            function_name: None,
            impact: None,
            urgency: None,
            detection_method: None,
        }
    }

    /// v0.8.3 (CIRISPersist#37) — full lifecycle:
    /// - new incident records → row inserted
    /// - second record with overlapping correlation_keys → dedup
    /// - AV-56: too-many-keys + too-long-key reject
    /// - AV-55: open → investigating → resolved (with notes) → closed
    /// - AV-55: backflow reject
    /// - correlate(tenant, key) returns the right rows
    /// - list_incidents with filter combinations
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn incident_round_trip_full_lifecycle() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let tenant = format!("inc-{}", Uuid::new_v4().simple());

        // 1. Insert: a fresh incident lands.
        let inc1 = mk_incident(
            &tenant,
            "service_failure",
            IncidentSeverity::Error,
            "LLM timeout",
            vec!["service:llm".into(), "model:opus".into()],
        );
        let id1 = backend.record_incident(inc1.clone()).await.unwrap();
        assert_eq!(id1, inc1.incident_id);

        // 2. Dedup: second record with overlapping keys bumps the
        //    first one's occurrences instead of inserting.
        let inc2 = mk_incident(
            &tenant,
            "service_failure",
            IncidentSeverity::Error,
            "LLM timeout (recurrence)",
            vec!["service:llm".into(), "extra:key".into()],
        );
        let id2 = backend.record_incident(inc2).await.unwrap();
        assert_eq!(id2, id1, "dedup landed on the original incident_id");

        // Verify occurrences bumped.
        let page = backend
            .list_incidents(
                IncidentFilter {
                    tenant_id: tenant.clone(),
                    state: None,
                    severity: None,
                    category: Some("service_failure".into()),
                    has_correlation_keys: vec![],
                    first_seen_after: None,
                    first_seen_before: None,
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1, "one row (deduped)");
        assert_eq!(page.items[0].occurrences, 2);

        // 3. Different category — same keys — new row (dedup is
        //    scoped per (tenant, category)).
        let inc_other_cat = mk_incident(
            &tenant,
            "rate_anomaly",
            IncidentSeverity::Warning,
            "Burst detected",
            vec!["service:llm".into()],
        );
        let id_other = backend.record_incident(inc_other_cat).await.unwrap();
        assert_ne!(id_other, id1);

        // 4. AV-56: oversized correlation_keys reject.
        let too_many = mk_incident(
            &tenant,
            "test",
            IncidentSeverity::Info,
            "too many keys",
            (0..40).map(|i| format!("k-{i}")).collect(),
        );
        let err = backend.record_incident(too_many).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));

        let too_long_key = mk_incident(
            &tenant,
            "test",
            IncidentSeverity::Info,
            "too-long key",
            vec!["x".repeat(MAX_CORRELATION_KEY_BYTES + 1)],
        );
        let err = backend.record_incident(too_long_key).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));

        // 5. State machine: open → investigating → resolved → closed.
        backend
            .transition_state(IncidentTransition {
                incident_id: id1.clone(),
                new_state: IncidentState::Investigating,
                resolution_notes: None,
            })
            .await
            .unwrap();

        // 5b. AV-55 backflow reject.
        let backflow = backend
            .transition_state(IncidentTransition {
                incident_id: id1.clone(),
                new_state: IncidentState::Open,
                resolution_notes: None,
            })
            .await
            .unwrap_err();
        assert!(
            matches!(backflow, Error::InvalidTransition(_)),
            "expected InvalidTransition on backflow, got {backflow:?}"
        );

        // 5c. AV-55 notes required on resolved.
        let no_notes = backend
            .transition_state(IncidentTransition {
                incident_id: id1.clone(),
                new_state: IncidentState::Resolved,
                resolution_notes: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(no_notes, Error::InvalidArgument(_)));

        // 5d. Real resolve.
        backend
            .transition_state(IncidentTransition {
                incident_id: id1.clone(),
                new_state: IncidentState::Resolved,
                resolution_notes: Some("model fell back to claude-haiku".into()),
            })
            .await
            .unwrap();
        // 5e. Closed.
        backend
            .transition_state(IncidentTransition {
                incident_id: id1.clone(),
                new_state: IncidentState::Closed,
                resolution_notes: Some("monitoring period expired".into()),
            })
            .await
            .unwrap();

        // 5f. Resolved → Investigating reject (regression).
        let regression = backend
            .transition_state(IncidentTransition {
                incident_id: id1.clone(),
                new_state: IncidentState::Investigating,
                resolution_notes: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(regression, Error::InvalidTransition(_)));

        // 6. After closing id1, a new incident with overlapping
        //    correlation_keys for the same (tenant, category)
        //    should NOT dedup against the closed row.
        let inc_reopen = mk_incident(
            &tenant,
            "service_failure",
            IncidentSeverity::Error,
            "LLM timeout (post-close)",
            vec!["service:llm".into()],
        );
        let id_reopen = backend.record_incident(inc_reopen.clone()).await.unwrap();
        assert_ne!(
            id_reopen, id1,
            "closed incident should NOT dedup new records"
        );

        // 7. correlate: find incidents naming 'service:llm'.
        let refs = backend.correlate(&tenant, "service:llm").await.unwrap();
        // Should match: id1 (closed), id_other (rate_anomaly), id_reopen.
        assert!(refs.len() >= 3);

        // 8. list_incidents with state filter — only open incidents
        //    for tenant.
        let open_page = backend
            .list_incidents(
                IncidentFilter {
                    tenant_id: tenant.clone(),
                    state: Some(IncidentState::Open),
                    severity: None,
                    category: None,
                    has_correlation_keys: vec![],
                    first_seen_after: None,
                    first_seen_before: None,
                },
                None,
                100,
            )
            .await
            .unwrap();
        // id_other + id_reopen are still open.
        assert!(open_page
            .items
            .iter()
            .all(|i| i.state == IncidentState::Open));
        assert!(open_page.items.iter().any(|i| i.incident_id == id_reopen));

        // 9. AV-51-style: empty tenant_id rejects.
        let no_tenant = backend
            .list_incidents(
                IncidentFilter {
                    tenant_id: String::new(),
                    state: None,
                    severity: None,
                    category: None,
                    has_correlation_keys: vec![],
                    first_seen_after: None,
                    first_seen_before: None,
                },
                None,
                10,
            )
            .await
            .unwrap_err();
        assert!(matches!(no_tenant, Error::InvalidArgument(_)));

        // 10. Transition on non-existent incident → NotFound.
        let missing = backend
            .transition_state(IncidentTransition {
                incident_id: Uuid::new_v4().to_string(),
                new_state: IncidentState::Investigating,
                resolution_notes: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(missing, Error::NotFound(_)));
    }

    /// v1.5.5 (CIRISPersist#56) — D1-full forensic fields round-trip
    /// across INSERT + SELECT. Populates all 11 forensic columns,
    /// reads back via list_incidents, asserts every field.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn incident_forensic_fields_round_trip() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let tenant = format!("inc-forensic-{}", Uuid::new_v4().simple());
        let now = Utc::now();
        let inc = Incident {
            incident_id: Uuid::new_v4().to_string(),
            tenant_id: tenant.clone(),
            severity: IncidentSeverity::High,
            category: "exception".into(),
            title: "ValueError in dispatch".into(),
            description: Some("payload decode failed".into()),
            correlation_keys: vec!["component:dispatch".into(), "problem:p-42".into()],
            state: IncidentState::Open,
            first_seen_at: now,
            last_seen_at: now,
            resolved_at: None,
            resolution_notes: None,
            occurrences: 1,
            incident_type: Some("EXCEPTION".into()),
            source_component: Some("dispatch_handler".into()),
            handler_name: Some("on_message".into()),
            exception_type: Some("ValueError".into()),
            stack_trace: Some("Traceback (most recent call last):\n  …".into()),
            filename: Some("ciris_agent/dispatch.py".into()),
            line_number: Some(142),
            function_name: Some("on_message".into()),
            impact: Some("medium".into()),
            urgency: Some("high".into()),
            detection_method: Some("exception_hook".into()),
        };
        let id = backend.record_incident(inc.clone()).await.unwrap();
        assert_eq!(id, inc.incident_id);

        let page = backend
            .list_incidents(
                IncidentFilter {
                    tenant_id: tenant.clone(),
                    state: None,
                    severity: None,
                    category: Some("exception".into()),
                    has_correlation_keys: vec![],
                    first_seen_after: None,
                    first_seen_before: None,
                },
                None,
                10,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        let got = &page.items[0];
        assert_eq!(got.severity, IncidentSeverity::High);
        assert_eq!(got.incident_type.as_deref(), Some("EXCEPTION"));
        assert_eq!(got.source_component.as_deref(), Some("dispatch_handler"));
        assert_eq!(got.handler_name.as_deref(), Some("on_message"));
        assert_eq!(got.exception_type.as_deref(), Some("ValueError"));
        assert!(got.stack_trace.is_some());
        assert_eq!(got.filename.as_deref(), Some("ciris_agent/dispatch.py"));
        assert_eq!(got.line_number, Some(142));
        assert_eq!(got.function_name.as_deref(), Some("on_message"));
        assert_eq!(got.impact.as_deref(), Some("medium"));
        assert_eq!(got.urgency.as_deref(), Some("high"));
        assert_eq!(got.detection_method.as_deref(), Some("exception_hook"));
    }

    /// v1.5.5 — Recurring as an initial state. Confirms record →
    /// list-filter-by-state=Recurring returns the row.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn incident_recurring_initial_state_round_trip() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let tenant = format!("inc-recurring-{}", Uuid::new_v4().simple());
        let now = Utc::now();
        let mut inc = mk_incident(
            &tenant,
            "service_failure",
            IncidentSeverity::Warning,
            "recurring LLM timeout pattern",
            vec!["service:llm".into(), "problem:p-42".into()],
        );
        inc.state = IncidentState::Recurring;
        inc.first_seen_at = now;
        inc.last_seen_at = now;
        let id = backend.record_incident(inc.clone()).await.unwrap();

        // Filter by state=Recurring returns it.
        let page = backend
            .list_incidents(
                IncidentFilter {
                    tenant_id: tenant.clone(),
                    state: Some(IncidentState::Recurring),
                    severity: None,
                    category: None,
                    has_correlation_keys: vec![],
                    first_seen_after: None,
                    first_seen_before: None,
                },
                None,
                10,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].incident_id, id);
        assert_eq!(page.items[0].state, IncidentState::Recurring);

        // Recurring → Investigating is a legal forward transition
        // (rank 0 → 1).
        backend
            .transition_state(IncidentTransition {
                incident_id: id.clone(),
                new_state: IncidentState::Investigating,
                resolution_notes: None,
            })
            .await
            .unwrap();
    }

    /// v1.5.5 — record_incident rejects an initial state that is
    /// not Open or Recurring (Investigating/Resolved/Closed must
    /// arrive via transition_state).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn incident_reject_non_initial_state_at_record() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let tenant = format!("inc-noinit-{}", Uuid::new_v4().simple());
        let mut inc = mk_incident(
            &tenant,
            "service_failure",
            IncidentSeverity::Error,
            "should reject",
            vec!["service:llm".into()],
        );
        inc.state = IncidentState::Investigating;
        let err = backend.record_incident(inc).await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "expected InvalidArgument, got {err:?}"
        );
    }
}
