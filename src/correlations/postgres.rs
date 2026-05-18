//! PostgreSQL impl of [`CorrelationService`] (v1.5.11,
//! CIRISPersist#59 #3).
//!
//! All 18 columns lift one-to-one from the row shape. JSON columns
//! (`request_data`, `response_data`, `tags`) ride across the wire
//! as `serde_json::Value` (JSONB on the PG side); timestamps cross
//! as `chrono::DateTime<Utc>` (TIMESTAMPTZ). `metric_value` is
//! `f64` on the wire and `REAL` (4-byte) on disk — the agent's
//! existing column shape matches this. No FKs on the table; the
//! `parent_span_id` link is a string pointer that may target a span
//! in another substrate or another occurrence's correlations.

use super::service::CorrelationService;
use super::types::{
    Correlation, CorrelationCursor, CorrelationFilter, CorrelationListPage, CorrelationStatus,
    CorrelationType, RetentionPolicy,
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

fn decode_correlation_row(row: &tokio_postgres::Row) -> Result<Correlation, Error> {
    let status_str: String = row
        .try_get("status")
        .map_err(|e| Error::Backend(format!("decode status: {e}")))?;
    let status = CorrelationStatus::parse_str(&status_str)
        .ok_or_else(|| Error::Backend(format!("unknown status: {status_str}")))?;
    let ctype_str: String = row
        .try_get("correlation_type")
        .map_err(|e| Error::Backend(format!("decode correlation_type: {e}")))?;
    let correlation_type = CorrelationType::parse_str(&ctype_str)
        .ok_or_else(|| Error::Backend(format!("unknown correlation_type: {ctype_str}")))?;
    let rp_str: String = row
        .try_get("retention_policy")
        .map_err(|e| Error::Backend(format!("decode retention_policy: {e}")))?;
    let retention_policy = RetentionPolicy::parse_str(&rp_str)
        .ok_or_else(|| Error::Backend(format!("unknown retention_policy: {rp_str}")))?;
    // metric_value is REAL on disk (f32); lift to f64 at the trait
    // boundary. tokio_postgres requires an explicit f32 try_get here
    // — the wire type doesn't auto-widen.
    let metric_value: Option<f32> = row
        .try_get("metric_value")
        .map_err(|e| Error::Backend(format!("decode metric_value: {e}")))?;
    Ok(Correlation {
        correlation_id: row
            .try_get("correlation_id")
            .map_err(|e| Error::Backend(format!("decode correlation_id: {e}")))?,
        service_type: row
            .try_get("service_type")
            .map_err(|e| Error::Backend(format!("decode service_type: {e}")))?,
        handler_name: row
            .try_get("handler_name")
            .map_err(|e| Error::Backend(format!("decode handler_name: {e}")))?,
        action_type: row
            .try_get("action_type")
            .map_err(|e| Error::Backend(format!("decode action_type: {e}")))?,
        request_data: row
            .try_get("request_data")
            .map_err(|e| Error::Backend(format!("decode request_data: {e}")))?,
        response_data: row
            .try_get("response_data")
            .map_err(|e| Error::Backend(format!("decode response_data: {e}")))?,
        status,
        created_at: row
            .try_get("created_at")
            .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|e| Error::Backend(format!("decode updated_at: {e}")))?,
        correlation_type,
        timestamp: row
            .try_get("timestamp")
            .map_err(|e| Error::Backend(format!("decode timestamp: {e}")))?,
        metric_name: row
            .try_get("metric_name")
            .map_err(|e| Error::Backend(format!("decode metric_name: {e}")))?,
        metric_value: metric_value.map(|v| v as f64),
        log_level: row
            .try_get("log_level")
            .map_err(|e| Error::Backend(format!("decode log_level: {e}")))?,
        trace_id: row
            .try_get("trace_id")
            .map_err(|e| Error::Backend(format!("decode trace_id: {e}")))?,
        span_id: row
            .try_get("span_id")
            .map_err(|e| Error::Backend(format!("decode span_id: {e}")))?,
        parent_span_id: row
            .try_get("parent_span_id")
            .map_err(|e| Error::Backend(format!("decode parent_span_id: {e}")))?,
        tags: row
            .try_get("tags")
            .map_err(|e| Error::Backend(format!("decode tags: {e}")))?,
        retention_policy,
        agent_occurrence_id: row
            .try_get("agent_occurrence_id")
            .map_err(|e| Error::Backend(format!("decode agent_occurrence_id: {e}")))?,
    })
}

impl CorrelationService for PostgresBackend {
    async fn record_correlation(&self, correlation: Correlation) -> Result<(), Error> {
        validate_correlation(&correlation)?;
        let status_str = correlation.status.as_sql_str().to_owned();
        let ctype_str = correlation.correlation_type.as_sql_str().to_owned();
        let rp_str = correlation.retention_policy.as_sql_str().to_owned();
        let metric_value_f32: Option<f32> = correlation.metric_value.map(|v| v as f32);
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // ON CONFLICT DO NOTHING — first writer wins; idempotent
        // retry. Caller advances state via update_correlation_status.
        client
            .execute(
                "INSERT INTO cirislens.service_correlations (\
                    correlation_id, service_type, handler_name, action_type, \
                    request_data, response_data, status, created_at, updated_at, \
                    correlation_type, timestamp, metric_name, metric_value, \
                    log_level, trace_id, span_id, parent_span_id, tags, \
                    retention_policy, agent_occurrence_id\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                           $14, $15, $16, $17, $18, $19, $20) \
                 ON CONFLICT (correlation_id) DO NOTHING",
                &[
                    &correlation.correlation_id,
                    &correlation.service_type,
                    &correlation.handler_name,
                    &correlation.action_type,
                    &correlation.request_data,
                    &correlation.response_data,
                    &status_str,
                    &correlation.created_at,
                    &correlation.updated_at,
                    &ctype_str,
                    &correlation.timestamp,
                    &correlation.metric_name,
                    &metric_value_f32,
                    &correlation.log_level,
                    &correlation.trace_id,
                    &correlation.span_id,
                    &correlation.parent_span_id,
                    &correlation.tags,
                    &rp_str,
                    &correlation.agent_occurrence_id,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_correlation"))?;
        Ok(())
    }

    async fn get_correlation(&self, correlation_id: &str) -> Result<Option<Correlation>, Error> {
        if correlation_id.is_empty() {
            return Err(Error::InvalidArgument("correlation_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT correlation_id, service_type, handler_name, action_type, \
                        request_data, response_data, status, created_at, updated_at, \
                        correlation_type, timestamp, metric_name, metric_value, \
                        log_level, trace_id, span_id, parent_span_id, tags, \
                        retention_policy, agent_occurrence_id \
                 FROM cirislens.service_correlations WHERE correlation_id = $1",
                &[&correlation_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_correlation"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_correlation_row(&row)?)),
        }
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
        let status_str = new_status.as_sql_str().to_owned();
        let now = chrono::Utc::now();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let changed = client
            .execute(
                "UPDATE cirislens.service_correlations SET \
                    status = $1, \
                    updated_at = $2, \
                    response_data = COALESCE($3, response_data) \
                 WHERE correlation_id = $4",
                &[&status_str, &now, &response_data, &correlation_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "update_correlation_status"))?;
        Ok(changed > 0)
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
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(service_type) = filter.service_type {
            params.push(Box::new(service_type));
            where_parts.push(format!("service_type = ${}", params.len()));
        }
        if let Some(ct) = filter.correlation_type {
            params.push(Box::new(ct.as_sql_str().to_owned()));
            where_parts.push(format!("correlation_type = ${}", params.len()));
        }
        if let Some(trace_id) = filter.trace_id {
            params.push(Box::new(trace_id));
            where_parts.push(format!("trace_id = ${}", params.len()));
        }
        if let Some(metric_name) = filter.metric_name {
            params.push(Box::new(metric_name));
            where_parts.push(format!("metric_name = ${}", params.len()));
        }
        if let Some(occ) = filter.agent_occurrence_id {
            params.push(Box::new(occ));
            where_parts.push(format!("agent_occurrence_id = ${}", params.len()));
        }
        if let Some(rp) = filter.retention_policy {
            params.push(Box::new(rp.as_sql_str().to_owned()));
            where_parts.push(format!("retention_policy = ${}", params.len()));
        }
        if let Some(after) = filter.timestamp_after {
            params.push(Box::new(after));
            where_parts.push(format!("timestamp >= ${}", params.len()));
        }
        if let Some(before) = filter.timestamp_before {
            params.push(Box::new(before));
            where_parts.push(format!("timestamp <= ${}", params.len()));
        }
        if let Some(after) = filter.updated_after {
            params.push(Box::new(after));
            where_parts.push(format!("updated_at >= ${}", params.len()));
        }
        if let Some(before) = filter.updated_before {
            params.push(Box::new(before));
            where_parts.push(format!("updated_at <= ${}", params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "CorrelationCursor version {} unsupported",
                    cur.version
                )));
            }
            params.push(Box::new(cur.last_ts));
            let p_ts = params.len();
            params.push(Box::new(cur.last_id.clone()));
            let p_id = params.len();
            where_parts.push(format!("(updated_at, correlation_id) < (${p_ts}, ${p_id})"));
        }
        params.push(Box::new(limit));
        let p_limit = params.len();
        let where_sql = if where_parts.is_empty() {
            "TRUE".to_string()
        } else {
            where_parts.join(" AND ")
        };
        let sql = format!(
            "SELECT correlation_id, service_type, handler_name, action_type, \
                    request_data, response_data, status, created_at, updated_at, \
                    correlation_type, timestamp, metric_name, metric_value, \
                    log_level, trace_id, span_id, parent_span_id, tags, \
                    retention_policy, agent_occurrence_id \
             FROM cirislens.service_correlations \
             WHERE {where_sql} \
             ORDER BY updated_at DESC, correlation_id DESC \
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
            .map_err(|e| map_pg_error(e, "query_correlations"))?;
        let mut items: Vec<Correlation> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_correlation_row(row)?);
        }
        let next_cursor = if items.len() == limit as usize {
            items.last().map(|last| {
                CorrelationCursor::from_trailing(last.updated_at, last.correlation_id.clone())
            })
        } else {
            None
        };
        Ok(CorrelationListPage { items, next_cursor })
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

    fn mk_correlation(id: &str, occurrence: &str) -> Correlation {
        let now = Utc::now();
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
    #[serial_test::serial(postgres)]
    async fn correlations_pg_record_get_full_columns_round_trip() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id = format!("corr-{}", Uuid::new_v4().simple());
        let now = Utc::now();
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
            metric_value: Some(42.0),
            log_level: Some("INFO".into()),
            trace_id: Some(format!("trace-{}", Uuid::new_v4().simple())),
            span_id: Some(format!("span-{}", Uuid::new_v4().simple())),
            parent_span_id: Some(format!("span-{}", Uuid::new_v4().simple())),
            tags: Some(serde_json::json!({"region": "us"})),
            retention_policy: RetentionPolicy::Aggregated,
            agent_occurrence_id: "occ-1".into(),
        };
        CorrelationService::record_correlation(&backend, c.clone())
            .await
            .unwrap();
        let got = backend
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
        // metric_value is REAL (f32) on disk — f64 lift is lossy but
        // 42.0 round-trips exactly.
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
    #[serial_test::serial(postgres)]
    async fn correlations_pg_record_idempotent_do_nothing() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id = format!("corr-{}", Uuid::new_v4().simple());
        let mut c = mk_correlation(&id, "occ-1");
        c.service_type = "first-write".into();
        CorrelationService::record_correlation(&backend, c.clone())
            .await
            .unwrap();

        // Second record with same id but different service_type — no-op.
        let mut c2 = c.clone();
        c2.service_type = "second-write-should-be-ignored".into();
        CorrelationService::record_correlation(&backend, c2)
            .await
            .unwrap();

        let got = backend
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
    #[serial_test::serial(postgres)]
    async fn correlations_pg_update_status_success_response_merge_missing_row() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id = format!("corr-{}", Uuid::new_v4().simple());
        CorrelationService::record_correlation(&backend, mk_correlation(&id, "occ-1"))
            .await
            .unwrap();

        let ok = backend
            .update_correlation_status(&id, CorrelationStatus::Active, None)
            .await
            .unwrap();
        assert!(ok);
        let got = backend
            .get_correlation(&id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.status, CorrelationStatus::Active);
        assert!(got.response_data.is_none());

        let ok = backend
            .update_correlation_status(
                &id,
                CorrelationStatus::Completed,
                Some(serde_json::json!({"text": "hello"})),
            )
            .await
            .unwrap();
        assert!(ok);
        let got = backend
            .get_correlation(&id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.status, CorrelationStatus::Completed);
        assert_eq!(
            got.response_data,
            Some(serde_json::json!({"text": "hello"}))
        );

        // Status update WITHOUT response_data — existing response_data
        // preserved.
        let ok = backend
            .update_correlation_status(&id, CorrelationStatus::Failed, None)
            .await
            .unwrap();
        assert!(ok);
        let got = backend
            .get_correlation(&id)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.status, CorrelationStatus::Failed);
        assert_eq!(
            got.response_data,
            Some(serde_json::json!({"text": "hello"}))
        );

        // Missing row → false.
        let ok = backend
            .update_correlation_status(
                &format!("missing-{}", Uuid::new_v4().simple()),
                CorrelationStatus::Failed,
                None,
            )
            .await
            .unwrap();
        assert!(!ok);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn correlations_pg_query_filter_service_type() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let occ = format!("occ-{}", Uuid::new_v4().simple());
        // 3 llm, 2 audit
        for _ in 0..3 {
            let id = format!("corr-{}", Uuid::new_v4().simple());
            let mut c = mk_correlation(&id, &occ);
            c.service_type = "llm".into();
            CorrelationService::record_correlation(&backend, c)
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        for _ in 0..2 {
            let id = format!("corr-{}", Uuid::new_v4().simple());
            let mut c = mk_correlation(&id, &occ);
            c.service_type = "audit".into();
            CorrelationService::record_correlation(&backend, c)
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
        let page = backend
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
        let page = backend
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
    #[serial_test::serial(postgres)]
    async fn correlations_pg_query_filter_metric_name_tsdb_hot_path() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let metric = format!("tokens_used-{}", Uuid::new_v4().simple());
        let base = Utc::now();
        for i in 0..4 {
            let id = format!("corr-{}", Uuid::new_v4().simple());
            let mut c = mk_correlation(&id, &occ);
            c.correlation_type = CorrelationType::Metric;
            c.metric_name = Some(metric.clone());
            c.metric_value = Some(i as f64);
            c.timestamp = Some(base + chrono::Duration::seconds(i));
            CorrelationService::record_correlation(&backend, c)
                .await
                .unwrap();
        }
        let page = backend
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
    #[serial_test::serial(postgres)]
    async fn correlations_pg_query_filter_trace_id_assembly() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let trace = format!("trace-{}", Uuid::new_v4().simple());
        let occ = "occ-1";
        // Three spans on the same trace_id.
        for i in 0..3 {
            let id = format!("corr-{}", Uuid::new_v4().simple());
            let mut c = mk_correlation(&id, occ);
            c.correlation_type = CorrelationType::Trace;
            c.trace_id = Some(trace.clone());
            c.span_id = Some(format!("span-{i}-{}", Uuid::new_v4().simple()));
            CorrelationService::record_correlation(&backend, c)
                .await
                .unwrap();
        }
        let page = backend
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
    #[serial_test::serial(postgres)]
    async fn correlations_pg_query_filter_timestamp_window() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let occ = format!("occ-{}", Uuid::new_v4().simple());
        let base = Utc::now();
        for i in 0..5 {
            let id = format!("corr-{}", Uuid::new_v4().simple());
            let mut c = mk_correlation(&id, &occ);
            c.timestamp = Some(base + chrono::Duration::seconds(i * 10));
            CorrelationService::record_correlation(&backend, c)
                .await
                .unwrap();
        }
        // Window [base + 15s, base + 35s] → seconds 20, 30 → 2.
        let after = base + chrono::Duration::seconds(15);
        let before = base + chrono::Duration::seconds(35);
        let page = backend
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
    #[serial_test::serial(postgres)]
    async fn correlations_pg_cursor_pagination() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let occ = format!("occ-{}", Uuid::new_v4().simple());
        for _ in 0..5 {
            let id = format!("corr-{}", Uuid::new_v4().simple());
            CorrelationService::record_correlation(&backend, mk_correlation(&id, &occ))
                .await
                .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(3)).await;
        }
        let filter = CorrelationFilter {
            agent_occurrence_id: Some(occ.clone()),
            ..Default::default()
        };
        let p1 = backend
            .query_correlations(filter.clone(), None, 2)
            .await
            .unwrap();
        assert_eq!(p1.items.len(), 2);
        assert!(p1.next_cursor.is_some());
        let p2 = backend
            .query_correlations(filter.clone(), p1.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 2);
        let p3 = backend
            .query_correlations(filter.clone(), p2.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(p3.items.len(), 1);
        assert!(p3.next_cursor.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn correlations_pg_span_tree_parent_span_query() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

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
        CorrelationService::record_correlation(&backend, c)
            .await
            .unwrap();
        // 2 children of root.
        for child_span in [&child1, &child2] {
            let mut c = mk_correlation(&format!("corr-{}", Uuid::new_v4().simple()), "occ-1");
            c.correlation_type = CorrelationType::Trace;
            c.trace_id = Some(trace.clone());
            c.span_id = Some((*child_span).clone());
            c.parent_span_id = Some(root_span.clone());
            CorrelationService::record_correlation(&backend, c)
                .await
                .unwrap();
        }
        // 1 grandchild under child1.
        let mut c = mk_correlation(&format!("corr-{}", Uuid::new_v4().simple()), "occ-1");
        c.correlation_type = CorrelationType::Trace;
        c.trace_id = Some(trace.clone());
        c.span_id = Some(grandchild.clone());
        c.parent_span_id = Some(child1.clone());
        CorrelationService::record_correlation(&backend, c)
            .await
            .unwrap();

        // The four rows live on the same trace_id; assemble.
        let page = backend
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

        // Children of root: query expressed in the schema by walking
        // parent_span_id. There is no specific filter field for
        // parent_span_id at the trait surface (callers can iterate
        // on the trace_id assembly above and tree-walk client-side,
        // or extend the filter later). Validate the index supports
        // such walks via a raw query — this is the contract the
        // partial-index migration declares.
        let client = backend.pool().get().await.unwrap();
        let rows = client
            .query(
                "SELECT COUNT(*)::BIGINT FROM cirislens.service_correlations \
                 WHERE parent_span_id = $1",
                &[&root_span],
            )
            .await
            .unwrap();
        let count: i64 = rows[0].get(0);
        assert_eq!(count, 2);
    }
}
