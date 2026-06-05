//! SQLite impl of [`CorrelationService`] (v1.5.11,
//! CIRISPersist#59 #3).
//!
//! Mirrors the v1.5.11 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ              → TEXT (RFC 3339)
//!   JSONB                    → TEXT (raw JSON string)
//!   ON CONFLICT (correlation_id) DO NOTHING → identical
//!   metric_value REAL        → f64 (SQLite REAL is 8-byte IEEE 754)
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

use parking_lot::Mutex;
use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};

use super::service::CorrelationService;
use super::types::{
    Correlation, CorrelationCursor, CorrelationFilter, CorrelationListPage, CorrelationStatus,
    CorrelationType, RetentionPolicy,
};
use super::Error;

/// SQLite-backed [`CorrelationService`] impl.
pub struct SqliteCorrelationBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteCorrelationBackend {
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

fn parse_datetime_opt(s: Option<String>) -> Result<Option<chrono::DateTime<chrono::Utc>>, Error> {
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

fn validate_correlation(c: &Correlation) -> Result<(), Error> {
    if c.correlation_id.is_empty() {
        return Err(Error::InvalidArgument("correlation_id required".into()));
    }
    if c.service_type.is_empty() {
        return Err(Error::InvalidArgument("service_type required".into()));
    }
    if c.handler_name.is_empty() {
        return Err(Error::InvalidArgument("handler_name required".into()));
    }
    if c.action_type.is_empty() {
        return Err(Error::InvalidArgument("action_type required".into()));
    }
    if c.agent_occurrence_id.is_empty() {
        return Err(Error::InvalidArgument(
            "agent_occurrence_id required".into(),
        ));
    }
    Ok(())
}

fn decode_correlation_row(row: &rusqlite::Row<'_>) -> Result<Correlation, Error> {
    let correlation_id: String = row
        .get("correlation_id")
        .map_err(|e| Error::Backend(format!("decode correlation_id: {e}")))?;
    let service_type: String = row
        .get("service_type")
        .map_err(|e| Error::Backend(format!("decode service_type: {e}")))?;
    let handler_name: String = row
        .get("handler_name")
        .map_err(|e| Error::Backend(format!("decode handler_name: {e}")))?;
    let action_type: String = row
        .get("action_type")
        .map_err(|e| Error::Backend(format!("decode action_type: {e}")))?;
    let request_raw: Option<String> = row
        .get("request_data")
        .map_err(|e| Error::Backend(format!("decode request_data: {e}")))?;
    let response_raw: Option<String> = row
        .get("response_data")
        .map_err(|e| Error::Backend(format!("decode response_data: {e}")))?;
    let status_str: String = row
        .get("status")
        .map_err(|e| Error::Backend(format!("decode status: {e}")))?;
    let status = CorrelationStatus::parse_str(&status_str)
        .ok_or_else(|| Error::Backend(format!("unknown status: {status_str}")))?;
    let created_at_str: String = row
        .get("created_at")
        .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?;
    let updated_at_str: String = row
        .get("updated_at")
        .map_err(|e| Error::Backend(format!("decode updated_at: {e}")))?;
    let ctype_str: String = row
        .get("correlation_type")
        .map_err(|e| Error::Backend(format!("decode correlation_type: {e}")))?;
    let correlation_type = CorrelationType::parse_str(&ctype_str)
        .ok_or_else(|| Error::Backend(format!("unknown correlation_type: {ctype_str}")))?;
    let timestamp_str: Option<String> = row
        .get("timestamp")
        .map_err(|e| Error::Backend(format!("decode timestamp: {e}")))?;
    let metric_name: Option<String> = row
        .get("metric_name")
        .map_err(|e| Error::Backend(format!("decode metric_name: {e}")))?;
    let metric_value: Option<f64> = row
        .get("metric_value")
        .map_err(|e| Error::Backend(format!("decode metric_value: {e}")))?;
    let log_level: Option<String> = row
        .get("log_level")
        .map_err(|e| Error::Backend(format!("decode log_level: {e}")))?;
    let trace_id: Option<String> = row
        .get("trace_id")
        .map_err(|e| Error::Backend(format!("decode trace_id: {e}")))?;
    let span_id: Option<String> = row
        .get("span_id")
        .map_err(|e| Error::Backend(format!("decode span_id: {e}")))?;
    let parent_span_id: Option<String> = row
        .get("parent_span_id")
        .map_err(|e| Error::Backend(format!("decode parent_span_id: {e}")))?;
    let tags_raw: Option<String> = row
        .get("tags")
        .map_err(|e| Error::Backend(format!("decode tags: {e}")))?;
    let rp_str: String = row
        .get("retention_policy")
        .map_err(|e| Error::Backend(format!("decode retention_policy: {e}")))?;
    let retention_policy = RetentionPolicy::parse_str(&rp_str)
        .ok_or_else(|| Error::Backend(format!("unknown retention_policy: {rp_str}")))?;
    let agent_occurrence_id: String = row
        .get("agent_occurrence_id")
        .map_err(|e| Error::Backend(format!("decode agent_occurrence_id: {e}")))?;
    Ok(Correlation {
        correlation_id,
        service_type,
        handler_name,
        action_type,
        request_data: decode_json_opt(request_raw)?,
        response_data: decode_json_opt(response_raw)?,
        status,
        created_at: parse_datetime(&created_at_str)?,
        updated_at: parse_datetime(&updated_at_str)?,
        correlation_type,
        timestamp: parse_datetime_opt(timestamp_str)?,
        metric_name,
        metric_value,
        log_level,
        trace_id,
        span_id,
        parent_span_id,
        tags: decode_json_opt(tags_raw)?,
        retention_policy,
        agent_occurrence_id,
    })
}

impl CorrelationService for SqliteCorrelationBackend {
    async fn record_correlation(&self, correlation: Correlation) -> Result<(), Error> {
        validate_correlation(&correlation)?;
        let request_str = encode_json_opt(correlation.request_data.as_ref())?;
        let response_str = encode_json_opt(correlation.response_data.as_ref())?;
        let tags_str = encode_json_opt(correlation.tags.as_ref())?;
        let created_at_str = fmt_datetime(correlation.created_at);
        let updated_at_str = fmt_datetime(correlation.updated_at);
        let status_str = correlation.status.as_sql_str().to_owned();
        let ctype_str = correlation.correlation_type.as_sql_str().to_owned();
        let rp_str = correlation.retention_policy.as_sql_str().to_owned();
        let timestamp_str = correlation.timestamp.map(fmt_datetime);

        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let mut guard = conn.lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "record_correlation begin"))?;
            // ON CONFLICT DO NOTHING — first writer wins; idempotent
            // retry. Caller advances state via update_correlation_status.
            tx.execute(
                "INSERT INTO cirislens_service_correlations (\
                    correlation_id, service_type, handler_name, action_type, \
                    request_data, response_data, status, created_at, updated_at, \
                    correlation_type, timestamp, metric_name, metric_value, \
                    log_level, trace_id, span_id, parent_span_id, tags, \
                    retention_policy, agent_occurrence_id\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, \
                           ?14, ?15, ?16, ?17, ?18, ?19, ?20) \
                 ON CONFLICT(correlation_id) DO NOTHING",
                params![
                    correlation.correlation_id,
                    correlation.service_type,
                    correlation.handler_name,
                    correlation.action_type,
                    request_str,
                    response_str,
                    status_str,
                    created_at_str,
                    updated_at_str,
                    ctype_str,
                    timestamp_str,
                    correlation.metric_name,
                    correlation.metric_value,
                    correlation.log_level,
                    correlation.trace_id,
                    correlation.span_id,
                    correlation.parent_span_id,
                    tags_str,
                    rp_str,
                    correlation.agent_occurrence_id,
                ],
            )
            .map_err(|e| map_sqlite_error(e, "record_correlation insert"))?;
            tx.commit()
                .map_err(|e| map_sqlite_error(e, "record_correlation commit"))?;
            Ok(())
        })()
    }

    async fn get_correlation(&self, correlation_id: &str) -> Result<Option<Correlation>, Error> {
        if correlation_id.is_empty() {
            return Err(Error::InvalidArgument("correlation_id required".into()));
        }
        let conn = self.conn.clone();
        let correlation_id_owned = correlation_id.to_owned();
        (move || -> Result<Option<Correlation>, Error> {
            let guard = conn.lock();
            let row_opt = guard
                .query_row(
                    "SELECT correlation_id, service_type, handler_name, action_type, \
                            request_data, response_data, status, created_at, updated_at, \
                            correlation_type, timestamp, metric_name, metric_value, \
                            log_level, trace_id, span_id, parent_span_id, tags, \
                            retention_policy, agent_occurrence_id \
                     FROM cirislens_service_correlations WHERE correlation_id = ?1",
                    params![correlation_id_owned],
                    |row| Ok(decode_correlation_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_correlation query"))?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(r?)),
            }
        })()
    }

    async fn update_correlation_status(
        &self,
        correlation_id: &str,
        new_status: CorrelationStatus,
        response_data: Option<serde_json::Value>,
    ) -> Result<bool, Error> {
        if correlation_id.is_empty() {
            return Err(Error::InvalidArgument("correlation_id required".into()));
        }
        let response_data_str = encode_json_opt(response_data.as_ref())?;
        let now_str = fmt_datetime(chrono::Utc::now());
        let status_sql = new_status.as_sql_str().to_owned();
        let correlation_id_owned = correlation_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let guard = conn.lock();
            // COALESCE(?response_data, response_data) — preserve
            // existing value if caller didn't supply one. Caller can
            // pass serde_json::Value::Null via Some(Value::Null) to
            // overwrite with NULL (encoded as the JSON string "null").
            let changed = guard
                .execute(
                    "UPDATE cirislens_service_correlations SET \
                        status = ?1, \
                        updated_at = ?2, \
                        response_data = COALESCE(?3, response_data) \
                     WHERE correlation_id = ?4",
                    params![status_sql, now_str, response_data_str, correlation_id_owned],
                )
                .map_err(|e| map_sqlite_error(e, "update_correlation_status exec"))?;
            Ok(changed > 0)
        })()
    }

    async fn query_correlations(
        &self,
        filter: CorrelationFilter,
        cursor: Option<CorrelationCursor>,
        limit: i64,
    ) -> Result<CorrelationListPage, Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let mut where_parts: Vec<String> = Vec::new();
        let mut sql_params: Vec<SqlValue> = Vec::new();
        if let Some(service_type) = filter.service_type {
            sql_params.push(SqlValue::Text(service_type));
            where_parts.push(format!("service_type = ?{}", sql_params.len()));
        }
        if let Some(ct) = filter.correlation_type {
            sql_params.push(SqlValue::Text(ct.as_sql_str().to_owned()));
            where_parts.push(format!("correlation_type = ?{}", sql_params.len()));
        }
        if let Some(trace_id) = filter.trace_id {
            sql_params.push(SqlValue::Text(trace_id));
            where_parts.push(format!("trace_id = ?{}", sql_params.len()));
        }
        if let Some(metric_name) = filter.metric_name {
            sql_params.push(SqlValue::Text(metric_name));
            where_parts.push(format!("metric_name = ?{}", sql_params.len()));
        }
        if let Some(occ) = filter.agent_occurrence_id {
            sql_params.push(SqlValue::Text(occ));
            where_parts.push(format!("agent_occurrence_id = ?{}", sql_params.len()));
        }
        if let Some(rp) = filter.retention_policy {
            sql_params.push(SqlValue::Text(rp.as_sql_str().to_owned()));
            where_parts.push(format!("retention_policy = ?{}", sql_params.len()));
        }
        if let Some(after) = filter.timestamp_after {
            sql_params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push(format!("timestamp >= ?{}", sql_params.len()));
        }
        if let Some(before) = filter.timestamp_before {
            sql_params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push(format!("timestamp <= ?{}", sql_params.len()));
        }
        if let Some(after) = filter.updated_after {
            sql_params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push(format!("updated_at >= ?{}", sql_params.len()));
        }
        if let Some(before) = filter.updated_before {
            sql_params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push(format!("updated_at <= ?{}", sql_params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "CorrelationCursor version {} unsupported",
                    cur.version
                )));
            }
            sql_params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
            let p_ts = sql_params.len();
            sql_params.push(SqlValue::Text(cur.last_id.clone()));
            let p_id = sql_params.len();
            where_parts.push(format!("(updated_at, correlation_id) < (?{p_ts}, ?{p_id})"));
        }
        sql_params.push(SqlValue::Integer(limit));
        let p_limit = sql_params.len();
        let where_sql = if where_parts.is_empty() {
            "1=1".to_string()
        } else {
            where_parts.join(" AND ")
        };
        let sql = format!(
            "SELECT correlation_id, service_type, handler_name, action_type, \
                    request_data, response_data, status, created_at, updated_at, \
                    correlation_type, timestamp, metric_name, metric_value, \
                    log_level, trace_id, span_id, parent_span_id, tags, \
                    retention_policy, agent_occurrence_id \
             FROM cirislens_service_correlations \
             WHERE {where_sql} \
             ORDER BY updated_at DESC, correlation_id DESC \
             LIMIT ?{p_limit}"
        );
        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        (move || -> Result<CorrelationListPage, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "query_correlations prepare"))?;
            let rows_iter = stmt
                .query_map(params_from_iter(sql_params.iter()), |row| {
                    Ok(decode_correlation_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "query_correlations query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "query_correlations row"))??);
            }
            let next_cursor = if items.len() == limit_usize {
                items.last().map(|last| {
                    CorrelationCursor::from_trailing(last.updated_at, last.correlation_id.clone())
                })
            } else {
                None
            };
            Ok(CorrelationListPage { items, next_cursor })
        })()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteCorrelationBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let correlations = SqliteCorrelationBackend::new(backend.conn_handle());
        (backend, correlations)
    }

    fn mk_correlation(id: &str, occurrence: &str) -> Correlation {
        let now = chrono::Utc::now();
        Correlation {
            correlation_id: id.to_owned(),
            service_type: "llm".into(),
            handler_name: "speak".into(),
            action_type: "speak".into(),
            request_data: None,
            response_data: None,
            status: CorrelationStatus::Pending,
            created_at: now,
            updated_at: now,
            correlation_type: CorrelationType::ServiceInteraction,
            timestamp: None,
            metric_name: None,
            metric_value: None,
            log_level: None,
            trace_id: None,
            span_id: None,
            parent_span_id: None,
            tags: None,
            retention_policy: RetentionPolicy::Raw,
            agent_occurrence_id: occurrence.to_owned(),
        }
    }

    #[tokio::test]
    async fn record_get_round_trip_all_18_columns() {
        let (_b, correlations) = fresh_backend().await;
        let id = format!("corr-{}", Uuid::new_v4().simple());
        let now = chrono::Utc::now();
        let c = Correlation {
            correlation_id: id.clone(),
            service_type: "llm".into(),
            handler_name: "speak_handler".into(),
            action_type: "speak".into(),
            request_data: Some(serde_json::json!({"prompt": "hi"})),
            response_data: Some(serde_json::json!({"text": "hello"})),
            status: CorrelationStatus::Completed,
            created_at: now,
            updated_at: now,
            correlation_type: CorrelationType::Trace,
            timestamp: Some(now),
            metric_name: Some("tokens_used".into()),
            metric_value: Some(42.5),
            log_level: Some("INFO".into()),
            trace_id: Some(format!("trace-{}", Uuid::new_v4().simple())),
            span_id: Some(format!("span-{}", Uuid::new_v4().simple())),
            parent_span_id: Some(format!("span-{}", Uuid::new_v4().simple())),
            tags: Some(serde_json::json!({"region": "us"})),
            retention_policy: RetentionPolicy::Aggregated,
            agent_occurrence_id: "occ-1".into(),
        };
        correlations.record_correlation(c.clone()).await.unwrap();
        let got = correlations
            .get_correlation(&id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.correlation_id, c.correlation_id);
        assert_eq!(got.service_type, c.service_type);
        assert_eq!(got.handler_name, c.handler_name);
        assert_eq!(got.action_type, c.action_type);
        assert_eq!(got.request_data, c.request_data);
        assert_eq!(got.response_data, c.response_data);
        assert_eq!(got.status, c.status);
        assert_eq!(got.correlation_type, c.correlation_type);
        assert_eq!(got.metric_name, c.metric_name);
        assert_eq!(got.metric_value, c.metric_value);
        assert_eq!(got.log_level, c.log_level);
        assert_eq!(got.trace_id, c.trace_id);
        assert_eq!(got.span_id, c.span_id);
        assert_eq!(got.parent_span_id, c.parent_span_id);
        assert_eq!(got.tags, c.tags);
        assert_eq!(got.retention_policy, c.retention_policy);
        assert_eq!(got.agent_occurrence_id, c.agent_occurrence_id);
    }

    #[tokio::test]
    async fn record_idempotent_do_nothing() {
        let (_b, correlations) = fresh_backend().await;
        let id = format!("corr-{}", Uuid::new_v4().simple());
        let mut c = mk_correlation(&id, "occ-1");
        c.service_type = "first-write".into();
        correlations.record_correlation(c.clone()).await.unwrap();
        // Second record with same id but different service_type — no-op.
        let mut c2 = c.clone();
        c2.service_type = "second-write-should-be-ignored".into();
        correlations.record_correlation(c2).await.unwrap();

        let got = correlations
            .get_correlation(&id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(
            got.service_type, "first-write",
            "ON CONFLICT DO NOTHING — first writer wins"
        );
    }

    #[tokio::test]
    async fn update_status_success_response_merge_missing_row() {
        let (_b, correlations) = fresh_backend().await;
        let id = format!("corr-{}", Uuid::new_v4().simple());
        correlations
            .record_correlation(mk_correlation(&id, "occ-1"))
            .await
            .unwrap();

        let ok = correlations
            .update_correlation_status(&id, CorrelationStatus::Active, None)
            .await
            .unwrap();
        assert!(ok);
        let got = correlations
            .get_correlation(&id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.status, CorrelationStatus::Active);
        assert!(got.response_data.is_none());

        let ok = correlations
            .update_correlation_status(
                &id,
                CorrelationStatus::Completed,
                Some(serde_json::json!({"text": "hello"})),
            )
            .await
            .unwrap();
        assert!(ok);
        let got = correlations
            .get_correlation(&id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.status, CorrelationStatus::Completed);
        assert_eq!(
            got.response_data,
            Some(serde_json::json!({"text": "hello"}))
        );

        // Status update WITHOUT response_data — existing preserved.
        let ok = correlations
            .update_correlation_status(&id, CorrelationStatus::Failed, None)
            .await
            .unwrap();
        assert!(ok);
        let got = correlations
            .get_correlation(&id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.status, CorrelationStatus::Failed);
        assert_eq!(
            got.response_data,
            Some(serde_json::json!({"text": "hello"}))
        );

        // Missing row → false (not an error).
        let ok = correlations
            .update_correlation_status("nonexistent", CorrelationStatus::Failed, None)
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    async fn query_filter_service_type() {
        let (_b, correlations) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        for _ in 0..3 {
            let id = format!("corr-{}", Uuid::new_v4().simple());
            let mut c = mk_correlation(&id, &occ);
            c.service_type = "llm".into();
            correlations.record_correlation(c).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        for _ in 0..2 {
            let id = format!("corr-{}", Uuid::new_v4().simple());
            let mut c = mk_correlation(&id, &occ);
            c.service_type = "audit".into();
            correlations.record_correlation(c).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        let page = correlations
            .query_correlations(
                CorrelationFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    service_type: Some("llm".into()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 3);
        let page = correlations
            .query_correlations(
                CorrelationFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    service_type: Some("audit".into()),
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
    async fn query_filter_metric_name_tsdb_hot_path() {
        let (_b, correlations) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let metric = format!("tokens_used-{}", Uuid::new_v4().simple());
        let base = chrono::Utc::now();
        for i in 0..4 {
            let id = format!("corr-{}", Uuid::new_v4().simple());
            let mut c = mk_correlation(&id, &occ);
            c.correlation_type = CorrelationType::Metric;
            c.metric_name = Some(metric.clone());
            c.metric_value = Some(i as f64);
            c.timestamp = Some(base + chrono::Duration::seconds(i));
            correlations.record_correlation(c).await.unwrap();
        }
        let page = correlations
            .query_correlations(
                CorrelationFilter {
                    correlation_type: Some(CorrelationType::Metric),
                    metric_name: Some(metric.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 4);
        for item in &page.items {
            assert_eq!(item.correlation_type, CorrelationType::Metric);
            assert_eq!(item.metric_name.as_deref(), Some(metric.as_str()));
        }
    }

    #[tokio::test]
    async fn query_filter_trace_id_assembly() {
        let (_b, correlations) = fresh_backend().await;
        let trace = format!("trace-{}", Uuid::new_v4().simple());
        let occ = "occ-1";
        for i in 0..3 {
            let id = format!("corr-{}", Uuid::new_v4().simple());
            let mut c = mk_correlation(&id, occ);
            c.correlation_type = CorrelationType::Trace;
            c.trace_id = Some(trace.clone());
            c.span_id = Some(format!("span-{i}-{}", Uuid::new_v4().simple()));
            correlations.record_correlation(c).await.unwrap();
        }
        let page = correlations
            .query_correlations(
                CorrelationFilter {
                    trace_id: Some(trace.clone()),
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
    async fn query_filter_timestamp_window() {
        let (_b, correlations) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let base = chrono::Utc::now();
        for i in 0..5 {
            let id = format!("corr-{}", Uuid::new_v4().simple());
            let mut c = mk_correlation(&id, &occ);
            c.timestamp = Some(base + chrono::Duration::seconds(i * 10));
            correlations.record_correlation(c).await.unwrap();
        }
        // Window [base + 15s, base + 35s] → seconds 20, 30 → 2.
        let after = base + chrono::Duration::seconds(15);
        let before = base + chrono::Duration::seconds(35);
        let page = correlations
            .query_correlations(
                CorrelationFilter {
                    agent_occurrence_id: Some(occ.clone()),
                    timestamp_after: Some(after),
                    timestamp_before: Some(before),
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
    async fn cursor_pagination() {
        let (_b, correlations) = fresh_backend().await;
        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let mut ids = Vec::new();
        for _ in 0..5 {
            let id = format!("corr-{}", Uuid::new_v4().simple());
            ids.push(id.clone());
            correlations
                .record_correlation(mk_correlation(&id, &occ))
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        let filter = CorrelationFilter {
            agent_occurrence_id: Some(occ.clone()),
            ..Default::default()
        };
        let p1 = correlations
            .query_correlations(filter.clone(), None, 2)
            .await
            .unwrap();
        assert_eq!(p1.items.len(), 2);
        assert!(p1.next_cursor.is_some());
        let p2 = correlations
            .query_correlations(filter.clone(), p1.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 2);
        let p3 = correlations
            .query_correlations(filter.clone(), p2.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(p3.items.len(), 1);
        assert!(p3.next_cursor.is_none());
        // Union covers ids.
        let mut seen: Vec<String> = p1
            .items
            .iter()
            .chain(p2.items.iter())
            .chain(p3.items.iter())
            .map(|c| c.correlation_id.clone())
            .collect();
        seen.sort();
        let mut expected = ids.clone();
        expected.sort();
        assert_eq!(seen, expected);
    }

    #[tokio::test]
    async fn span_tree_parent_span_query_via_filter() {
        let (b, correlations) = fresh_backend().await;
        let trace = format!("trace-{}", Uuid::new_v4().simple());
        let root_span = format!("span-root-{}", Uuid::new_v4().simple());
        let child1 = format!("span-c1-{}", Uuid::new_v4().simple());
        let child2 = format!("span-c2-{}", Uuid::new_v4().simple());
        let grandchild = format!("span-g-{}", Uuid::new_v4().simple());

        // Root.
        let mut c = mk_correlation(&format!("corr-{}", Uuid::new_v4().simple()), "occ-1");
        c.correlation_type = CorrelationType::Trace;
        c.trace_id = Some(trace.clone());
        c.span_id = Some(root_span.clone());
        correlations.record_correlation(c).await.unwrap();
        // 2 children of root.
        for child_span in [&child1, &child2] {
            let mut c = mk_correlation(&format!("corr-{}", Uuid::new_v4().simple()), "occ-1");
            c.correlation_type = CorrelationType::Trace;
            c.trace_id = Some(trace.clone());
            c.span_id = Some((*child_span).clone());
            c.parent_span_id = Some(root_span.clone());
            correlations.record_correlation(c).await.unwrap();
        }
        // 1 grandchild under child1.
        let mut c = mk_correlation(&format!("corr-{}", Uuid::new_v4().simple()), "occ-1");
        c.correlation_type = CorrelationType::Trace;
        c.trace_id = Some(trace.clone());
        c.span_id = Some(grandchild.clone());
        c.parent_span_id = Some(child1.clone());
        correlations.record_correlation(c).await.unwrap();

        // All 4 on the same trace_id.
        let page = correlations
            .query_correlations(
                CorrelationFilter {
                    trace_id: Some(trace.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 4);

        // Direct children of root via the parent_span_id index.
        // Validated via a raw SQL probe — the trait surface
        // doesn't expose parent_span_id filtering directly, but
        // the migration declares the index supports the walk.
        let conn = b.conn_handle();
        let root_span_owned = root_span.clone();
        let count = (move || -> i64 {
            let guard = conn.lock();
            guard
                .query_row(
                    "SELECT COUNT(*) FROM cirislens_service_correlations \
                     WHERE parent_span_id = ?1",
                    params![root_span_owned],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap()
        })();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn status_check_constraint_rejects_unknown_value() {
        let (b, _correlations) = fresh_backend().await;
        let conn = b.conn_handle();
        let res = (move || -> rusqlite::Result<usize> {
            let guard = conn.lock();
            guard.execute(
                "INSERT INTO cirislens_service_correlations (\
                    correlation_id, service_type, handler_name, action_type, status, \
                    created_at, updated_at, correlation_type, retention_policy, \
                    agent_occurrence_id\
                 ) VALUES ('id', 'svc', 'h', 'a', 'bogus_status', \
                           '2026-01-01T00:00:00.000000+00:00', \
                           '2026-01-01T00:00:00.000000+00:00', \
                           'service_interaction', 'raw', 'occ-1')",
                params![],
            )
        })();
        assert!(res.is_err(), "expected CHECK violation on bogus status");
    }

    #[tokio::test]
    async fn correlation_type_check_constraint_rejects_unknown_value() {
        let (b, _correlations) = fresh_backend().await;
        let conn = b.conn_handle();
        let res = (move || -> rusqlite::Result<usize> {
            let guard = conn.lock();
            guard.execute(
                "INSERT INTO cirislens_service_correlations (\
                    correlation_id, service_type, handler_name, action_type, status, \
                    created_at, updated_at, correlation_type, retention_policy, \
                    agent_occurrence_id\
                 ) VALUES ('id', 'svc', 'h', 'a', 'pending', \
                           '2026-01-01T00:00:00.000000+00:00', \
                           '2026-01-01T00:00:00.000000+00:00', \
                           'bogus_type', 'raw', 'occ-1')",
                params![],
            )
        })();
        assert!(
            res.is_err(),
            "expected CHECK violation on bogus correlation_type"
        );
    }

    #[tokio::test]
    async fn retention_policy_check_constraint_rejects_unknown_value() {
        let (b, _correlations) = fresh_backend().await;
        let conn = b.conn_handle();
        let res = (move || -> rusqlite::Result<usize> {
            let guard = conn.lock();
            guard.execute(
                "INSERT INTO cirislens_service_correlations (\
                    correlation_id, service_type, handler_name, action_type, status, \
                    created_at, updated_at, correlation_type, retention_policy, \
                    agent_occurrence_id\
                 ) VALUES ('id', 'svc', 'h', 'a', 'pending', \
                           '2026-01-01T00:00:00.000000+00:00', \
                           '2026-01-01T00:00:00.000000+00:00', \
                           'service_interaction', 'bogus_policy', 'occ-1')",
                params![],
            )
        })();
        assert!(
            res.is_err(),
            "expected CHECK violation on bogus retention_policy"
        );
    }
}
