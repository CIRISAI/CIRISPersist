//! SQLite impl of [`IncidentService`] (v0.8.7, CIRISPersist#38).
//!
//! Mirrors v0.8.3 Postgres impl. JSONB-array correlation matching
//! translates to `json_each(...)` joins instead of `?|` / `?&` / `?`
//! operators. AV-55 state-machine + AV-56 bounds preserved.

use std::sync::Arc;

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use tokio::sync::Mutex;

use super::service::IncidentService;
use super::types::{
    Incident, IncidentCursor, IncidentFilter, IncidentListPage, IncidentRef, IncidentSeverity,
    IncidentState, IncidentTransition,
};
use super::{Error, MAX_CORRELATION_KEYS, MAX_CORRELATION_KEY_BYTES};

/// SQLite-backed [`IncidentService`] impl.
pub struct SqliteIncidentBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteIncidentBackend {
    /// Construct from a shared connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if let ErrorCode::ConstraintViolation = err.code {
            return Error::InvalidArgument(format!("{op}: {e}"));
        }
    }
    Error::Backend(format!("{op}: {e}"))
}

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

fn decode_incident_row(row: &rusqlite::Row<'_>) -> Result<Incident, Error> {
    let state_str: String = row
        .get("state")
        .map_err(|e| Error::Backend(format!("decode state: {e}")))?;
    let state = IncidentState::from_sql_str(&state_str)
        .ok_or_else(|| Error::Backend(format!("unknown state: {state_str}")))?;
    let severity_str: String = row
        .get("severity")
        .map_err(|e| Error::Backend(format!("decode severity: {e}")))?;
    let severity = IncidentSeverity::from_sql_str(&severity_str)
        .ok_or_else(|| Error::Backend(format!("unknown severity: {severity_str}")))?;
    let corr_str: String = row
        .get("correlation_keys")
        .map_err(|e| Error::Backend(format!("decode correlation_keys: {e}")))?;
    let correlation_keys: Vec<String> = serde_json::from_str(&corr_str)
        .map_err(|e| Error::Backend(format!("correlation_keys JSON decode: {e}")))?;
    let first_seen_str: String = row
        .get("first_seen_at")
        .map_err(|e| Error::Backend(format!("decode first_seen_at: {e}")))?;
    let last_seen_str: String = row
        .get("last_seen_at")
        .map_err(|e| Error::Backend(format!("decode last_seen_at: {e}")))?;
    let resolved_at: Option<String> = row
        .get("resolved_at")
        .map_err(|e| Error::Backend(format!("decode resolved_at: {e}")))?;
    let resolved_at = match resolved_at {
        Some(s) => Some(parse_datetime(&s)?),
        None => None,
    };
    Ok(Incident {
        incident_id: row
            .get("incident_id")
            .map_err(|e| Error::Backend(format!("decode incident_id: {e}")))?,
        tenant_id: row
            .get("tenant_id")
            .map_err(|e| Error::Backend(format!("decode tenant_id: {e}")))?,
        severity,
        category: row
            .get("category")
            .map_err(|e| Error::Backend(format!("decode category: {e}")))?,
        title: row
            .get("title")
            .map_err(|e| Error::Backend(format!("decode title: {e}")))?,
        description: row
            .get("description")
            .map_err(|e| Error::Backend(format!("decode description: {e}")))?,
        correlation_keys,
        state,
        first_seen_at: parse_datetime(&first_seen_str)?,
        last_seen_at: parse_datetime(&last_seen_str)?,
        resolved_at,
        resolution_notes: row
            .get("resolution_notes")
            .map_err(|e| Error::Backend(format!("decode resolution_notes: {e}")))?,
        occurrences: row
            .get("occurrences")
            .map_err(|e| Error::Backend(format!("decode occurrences: {e}")))?,
    })
}

impl IncidentService for SqliteIncidentBackend {
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
        validate_correlation_keys(&incident.correlation_keys)?;
        let corr_str = serde_json::to_string(&incident.correlation_keys)
            .map_err(|e| Error::Internal(format!("correlation_keys serialize: {e}")))?;
        let first_seen_str = fmt_datetime(incident.first_seen_at);
        let last_seen_str = fmt_datetime(incident.last_seen_at);

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<String, Error> {
            let mut guard = conn.blocking_lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "record_incident begin"))?;

            // Correlation-key dedup probe. SQLite has no JSONB `?|`;
            // instead we EXISTS-join json_each on both sides — the
            // existing row's correlation_keys array AND the new
            // incident's keys — and pick the most-recent match.
            let dup_row_opt = if incident.correlation_keys.is_empty() {
                None
            } else {
                tx.query_row(
                    "SELECT incident_id FROM cirislens_incident_records ir \
                     WHERE ir.tenant_id = ?1 \
                       AND ir.category = ?2 \
                       AND ir.state IN ('open', 'investigating') \
                       AND EXISTS ( \
                           SELECT 1 \
                           FROM json_each(ir.correlation_keys) AS existing_key \
                           JOIN json_each(?3) AS new_key \
                             ON existing_key.value = new_key.value \
                       ) \
                     ORDER BY ir.last_seen_at DESC \
                     LIMIT 1",
                    params![incident.tenant_id, incident.category, corr_str],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "record_incident dedup probe"))?
            };

            let landed_id = if let Some(existing_id) = dup_row_opt {
                tx.execute(
                    "UPDATE cirislens_incident_records SET \
                        occurrences = occurrences + 1, \
                        last_seen_at = datetime('now', 'subsec') \
                     WHERE incident_id = ?1",
                    params![existing_id],
                )
                .map_err(|e| map_sqlite_error(e, "record_incident bump"))?;
                existing_id
            } else {
                let new_id = incident.incident_id.clone();
                tx.execute(
                    "INSERT INTO cirislens_incident_records (\
                        incident_id, tenant_id, severity, category, title, description, \
                        correlation_keys, state, first_seen_at, last_seen_at, occurrences, \
                        persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'open', ?8, ?9, ?10, ?11)",
                    params![
                        new_id,
                        incident.tenant_id,
                        incident.severity.as_sql_str(),
                        incident.category,
                        incident.title,
                        incident.description,
                        corr_str,
                        first_seen_str,
                        last_seen_str,
                        incident.occurrences.max(1),
                        new_id,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "record_incident insert"))?;
                new_id
            };

            tx.commit()
                .map_err(|e| map_sqlite_error(e, "record_incident commit"))?;
            Ok(landed_id)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn transition_state(&self, transition: IncidentTransition) -> Result<(), Error> {
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

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let mut guard = conn.blocking_lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "transition_state begin"))?;

            let current_state_str: String = tx
                .query_row(
                    "SELECT state FROM cirislens_incident_records WHERE incident_id = ?1",
                    params![transition.incident_id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "transition_state read"))?
                .ok_or_else(|| {
                    Error::NotFound(format!("incident_id {}", transition.incident_id))
                })?;
            let current_state =
                IncidentState::from_sql_str(&current_state_str).ok_or_else(|| {
                    Error::Backend(format!("unknown current state: {current_state_str}"))
                })?;

            if !current_state.can_transition_to(transition.new_state) {
                return Err(Error::InvalidTransition(format!(
                    "{:?} → {:?} is not a legal forward transition",
                    current_state, transition.new_state
                )));
            }

            let now_str = fmt_datetime(chrono::Utc::now());
            match transition.new_state {
                IncidentState::Resolved => {
                    tx.execute(
                        "UPDATE cirislens_incident_records SET \
                            state = ?1, \
                            resolved_at = ?2, \
                            resolution_notes = ?3, \
                            last_seen_at = ?2 \
                         WHERE incident_id = ?4",
                        params![
                            transition.new_state.as_sql_str(),
                            now_str,
                            transition.resolution_notes,
                            transition.incident_id,
                        ],
                    )
                    .map_err(|e| map_sqlite_error(e, "transition to resolved"))?;
                }
                IncidentState::Closed => {
                    tx.execute(
                        "UPDATE cirislens_incident_records SET \
                            state = ?1, \
                            resolved_at = COALESCE(resolved_at, ?2), \
                            resolution_notes = COALESCE(?3, resolution_notes), \
                            last_seen_at = ?2 \
                         WHERE incident_id = ?4",
                        params![
                            transition.new_state.as_sql_str(),
                            now_str,
                            transition.resolution_notes,
                            transition.incident_id,
                        ],
                    )
                    .map_err(|e| map_sqlite_error(e, "transition to closed"))?;
                }
                _ => {
                    tx.execute(
                        "UPDATE cirislens_incident_records SET \
                            state = ?1, \
                            last_seen_at = ?2 \
                         WHERE incident_id = ?3",
                        params![
                            transition.new_state.as_sql_str(),
                            now_str,
                            transition.incident_id,
                        ],
                    )
                    .map_err(|e| map_sqlite_error(e, "transition to investigating"))?;
                }
            }
            tx.commit()
                .map_err(|e| map_sqlite_error(e, "transition commit"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
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
        let mut where_parts: Vec<String> = vec!["tenant_id = ?".to_string()];
        let mut params: Vec<SqlValue> = vec![SqlValue::Text(filter.tenant_id)];
        if let Some(state) = filter.state {
            params.push(SqlValue::Text(state.as_sql_str().to_owned()));
            where_parts.push("state = ?".to_string());
        }
        if let Some(sev) = filter.severity {
            params.push(SqlValue::Text(sev.as_sql_str().to_owned()));
            where_parts.push("severity = ?".to_string());
        }
        if let Some(cat) = filter.category {
            params.push(SqlValue::Text(cat));
            where_parts.push("category = ?".to_string());
        }
        if !filter.has_correlation_keys.is_empty() {
            // ?& semantics: ALL required keys must be present.
            // EXISTS subquery for each key checks presence via
            // json_each.
            for k in &filter.has_correlation_keys {
                params.push(SqlValue::Text(k.clone()));
                where_parts.push(format!(
                    "EXISTS (SELECT 1 FROM json_each(correlation_keys) WHERE value = ?{})",
                    params.len()
                ));
            }
        }
        if let Some(after) = filter.first_seen_after {
            params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push("first_seen_at >= ?".to_string());
        }
        if let Some(before) = filter.first_seen_before {
            params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push("first_seen_at <= ?".to_string());
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "IncidentCursor version {} unsupported",
                    cur.version
                )));
            }
            params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
            params.push(SqlValue::Text(cur.last_id.clone()));
            where_parts.push("(first_seen_at, incident_id) < (?, ?)".to_string());
        }
        params.push(SqlValue::Integer(limit));
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT incident_id, tenant_id, severity, category, title, description, \
                    correlation_keys, state, first_seen_at, last_seen_at, \
                    resolved_at, resolution_notes, occurrences \
             FROM cirislens_incident_records \
             WHERE {where_sql} \
             ORDER BY first_seen_at DESC, incident_id DESC \
             LIMIT ?"
        );
        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        tokio::task::spawn_blocking(move || -> Result<IncidentListPage, Error> {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "list_incidents prepare"))?;
            let rows_iter = stmt
                .query_map(params_from_iter(params.iter()), |row| {
                    Ok(decode_incident_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "list_incidents query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "list_incidents row"))??);
            }
            let next_cursor = if items.len() == limit_usize {
                items.last().map(|last| {
                    IncidentCursor::from_trailing(last.first_seen_at, last.incident_id.clone())
                })
            } else {
                None
            };
            Ok(IncidentListPage { items, next_cursor })
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn correlate(&self, tenant_id: &str, key: &str) -> Result<Vec<IncidentRef>, Error> {
        if tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id required".into()));
        }
        if key.is_empty() {
            return Err(Error::InvalidArgument("key must be non-empty".into()));
        }
        let conn = self.conn.clone();
        let tenant_id = tenant_id.to_owned();
        let key = key.to_owned();
        tokio::task::spawn_blocking(move || -> Result<Vec<IncidentRef>, Error> {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(
                    "SELECT incident_id, severity, category, state, last_seen_at \
                     FROM cirislens_incident_records \
                     WHERE tenant_id = ?1 \
                       AND EXISTS ( \
                           SELECT 1 FROM json_each(correlation_keys) WHERE value = ?2 \
                       ) \
                     ORDER BY last_seen_at DESC",
                )
                .map_err(|e| map_sqlite_error(e, "correlate prepare"))?;
            let rows_iter = stmt
                .query_map(params![tenant_id, key], |row| {
                    let id: String = row.get(0)?;
                    let sev_str: String = row.get(1)?;
                    let cat: String = row.get(2)?;
                    let st_str: String = row.get(3)?;
                    let last_seen_str: String = row.get(4)?;
                    Ok((id, sev_str, cat, st_str, last_seen_str))
                })
                .map_err(|e| map_sqlite_error(e, "correlate query"))?;
            let mut out = Vec::new();
            for r in rows_iter {
                let (id, sev_str, cat, st_str, last_seen_str) =
                    r.map_err(|e| map_sqlite_error(e, "correlate row"))?;
                out.push(IncidentRef {
                    incident_id: id,
                    severity: IncidentSeverity::from_sql_str(&sev_str)
                        .ok_or_else(|| Error::Backend(format!("unknown severity: {sev_str}")))?,
                    category: cat,
                    state: IncidentState::from_sql_str(&st_str)
                        .ok_or_else(|| Error::Backend(format!("unknown state: {st_str}")))?,
                    last_seen_at: parse_datetime(&last_seen_str)?,
                });
            }
            Ok(out)
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

    async fn fresh_backend() -> (SqliteBackend, SqliteIncidentBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteIncidentBackend::new(backend.conn_handle());
        (backend, svc)
    }

    fn mk_incident(
        tenant_id: &str,
        category: &str,
        severity: IncidentSeverity,
        title: &str,
        correlation_keys: Vec<String>,
    ) -> Incident {
        let now = chrono::Utc::now();
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
        }
    }

    /// v0.8.7 SQLite parity: full lifecycle mirroring v0.8.3 Postgres
    /// — record / dedup / cross-category isolation / AV-56 / state
    /// machine / correlate / list filters / tenant isolation.
    #[tokio::test]
    async fn cirisincident_sqlite_round_trip_full_lifecycle() {
        let (_b, svc) = fresh_backend().await;
        let tenant = format!("inc-{}", Uuid::new_v4().simple());

        // 1. Insert.
        let inc1 = mk_incident(
            &tenant,
            "service_failure",
            IncidentSeverity::Error,
            "LLM timeout",
            vec!["service:llm".into(), "model:opus".into()],
        );
        let id1 = svc.record_incident(inc1.clone()).await.unwrap();
        assert_eq!(id1, inc1.incident_id);

        // 2. Dedup.
        let inc2 = mk_incident(
            &tenant,
            "service_failure",
            IncidentSeverity::Error,
            "LLM timeout (recurrence)",
            vec!["service:llm".into(), "extra:key".into()],
        );
        let id2 = svc.record_incident(inc2).await.unwrap();
        assert_eq!(id2, id1, "dedup landed on original incident_id");

        let page = svc
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
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].occurrences, 2);

        // 3. Different category → new row.
        let inc_other_cat = mk_incident(
            &tenant,
            "rate_anomaly",
            IncidentSeverity::Warning,
            "Burst",
            vec!["service:llm".into()],
        );
        let id_other = svc.record_incident(inc_other_cat).await.unwrap();
        assert_ne!(id_other, id1);

        // 4. AV-56 oversized reject.
        let too_many = mk_incident(
            &tenant,
            "test",
            IncidentSeverity::Info,
            "too many",
            (0..40).map(|i| format!("k-{i}")).collect(),
        );
        let err = svc.record_incident(too_many).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));

        // 5. State machine.
        svc.transition_state(IncidentTransition {
            incident_id: id1.clone(),
            new_state: IncidentState::Investigating,
            resolution_notes: None,
        })
        .await
        .unwrap();

        // 5b. Backflow reject.
        let backflow = svc
            .transition_state(IncidentTransition {
                incident_id: id1.clone(),
                new_state: IncidentState::Open,
                resolution_notes: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(backflow, Error::InvalidTransition(_)));

        // 5c. Notes required on resolved.
        let no_notes = svc
            .transition_state(IncidentTransition {
                incident_id: id1.clone(),
                new_state: IncidentState::Resolved,
                resolution_notes: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(no_notes, Error::InvalidArgument(_)));

        // 5d. Resolve + close.
        svc.transition_state(IncidentTransition {
            incident_id: id1.clone(),
            new_state: IncidentState::Resolved,
            resolution_notes: Some("fixed".into()),
        })
        .await
        .unwrap();
        svc.transition_state(IncidentTransition {
            incident_id: id1.clone(),
            new_state: IncidentState::Closed,
            resolution_notes: Some("closed".into()),
        })
        .await
        .unwrap();

        // 6. Post-close: new incident with overlapping key does NOT
        //    dedup against closed row.
        let inc_reopen = mk_incident(
            &tenant,
            "service_failure",
            IncidentSeverity::Error,
            "LLM timeout (post-close)",
            vec!["service:llm".into()],
        );
        let id_reopen = svc.record_incident(inc_reopen).await.unwrap();
        assert_ne!(id_reopen, id1);

        // 7. correlate.
        let refs = svc.correlate(&tenant, "service:llm").await.unwrap();
        assert!(refs.len() >= 3);

        // 8. list with state filter — open only.
        let open_page = svc
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
        assert!(open_page
            .items
            .iter()
            .all(|i| i.state == IncidentState::Open));

        // 9. Empty tenant_id reject.
        let no_tenant = svc
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

        // 10. Transition on missing incident → NotFound.
        let missing = svc
            .transition_state(IncidentTransition {
                incident_id: Uuid::new_v4().to_string(),
                new_state: IncidentState::Investigating,
                resolution_notes: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(missing, Error::NotFound(_)));
    }
}
