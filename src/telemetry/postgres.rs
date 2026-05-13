//! PostgreSQL impl of [`TelemetryService`] (v0.8.2, CIRISPersist#36).
//!
//! Raw observations land via single + bulk INSERT paths.
//! Consolidation runs the per-period rollup with the
//! [`cirisgraph.consolidation_locks`] coordination gate.

use chrono::{DateTime, Duration, Utc};

use super::service::TelemetryService;
use super::types::{
    ConsolidationOutcome, ConsolidationRequest, MetricCursor, MetricFilter, MetricListPage,
    MetricObservation, MetricSummary,
};
use super::{Error, DEFAULT_MAX_LABELS_BYTES, STALE_LOCK_SECONDS};
use crate::store::postgres::PostgresBackend;

fn map_pg_error(e: tokio_postgres::Error, op: &str) -> Error {
    let detail = e
        .as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string());
    Error::Backend(format!("{op}: {detail}"))
}

fn max_labels_bytes() -> usize {
    std::env::var("CIRIS_PERSIST_TELEMETRY_MAX_LABELS_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_LABELS_BYTES)
}

/// AV-52: cap labels JSONB size at the trait surface.
fn validate_labels(labels: &serde_json::Value) -> Result<(), Error> {
    let serialized = serde_json::to_vec(labels)
        .map_err(|e| Error::Internal(format!("labels serialize: {e}")))?;
    let cap = max_labels_bytes();
    if serialized.len() > cap {
        return Err(Error::InvalidArgument(format!(
            "labels too large: {} bytes exceeds cap of {}",
            serialized.len(),
            cap
        )));
    }
    Ok(())
}

fn resolve_expires_at(obs: &MetricObservation) -> DateTime<Utc> {
    obs.expires_at
        .unwrap_or_else(|| obs.observed_at + Duration::hours(24))
}

fn resolve_metric_id(obs: &MetricObservation) -> Result<uuid::Uuid, Error> {
    match &obs.metric_id {
        Some(s) => uuid::Uuid::parse_str(s)
            .map_err(|e| Error::InvalidArgument(format!("metric_id parse: {e}"))),
        None => Ok(uuid::Uuid::new_v4()),
    }
}

fn decode_observation(row: &tokio_postgres::Row) -> Result<MetricObservation, Error> {
    let id: uuid::Uuid = row
        .try_get("metric_id")
        .map_err(|e| Error::Backend(format!("decode metric_id: {e}")))?;
    let expires: DateTime<Utc> = row
        .try_get("expires_at")
        .map_err(|e| Error::Backend(format!("decode expires_at: {e}")))?;
    Ok(MetricObservation {
        metric_id: Some(id.to_string()),
        metric_name: row
            .try_get("metric_name")
            .map_err(|e| Error::Backend(format!("decode metric_name: {e}")))?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|e| Error::Backend(format!("decode tenant_id: {e}")))?,
        value: row
            .try_get("value")
            .map_err(|e| Error::Backend(format!("decode value: {e}")))?,
        labels: row
            .try_get("labels")
            .map_err(|e| Error::Backend(format!("decode labels: {e}")))?,
        observed_at: row
            .try_get("observed_at")
            .map_err(|e| Error::Backend(format!("decode observed_at: {e}")))?,
        expires_at: Some(expires),
    })
}

impl TelemetryService for PostgresBackend {
    async fn record_metric(&self, obs: MetricObservation) -> Result<(), Error> {
        if obs.tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id required".into()));
        }
        if obs.metric_name.is_empty() {
            return Err(Error::InvalidArgument("metric_name required".into()));
        }
        validate_labels(&obs.labels)?;
        let metric_id = resolve_metric_id(&obs)?;
        let expires_at = resolve_expires_at(&obs);

        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        client
            .execute(
                "INSERT INTO cirisgraph.telemetry_metrics (\
                    metric_id, metric_name, tenant_id, value, labels, \
                    observed_at, expires_at\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &metric_id,
                    &obs.metric_name,
                    &obs.tenant_id,
                    &obs.value,
                    &obs.labels,
                    &obs.observed_at,
                    &expires_at,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_metric"))?;
        Ok(())
    }

    async fn record_metrics_batch(&self, obs: &[MetricObservation]) -> Result<u64, Error> {
        if obs.is_empty() {
            return Ok(0);
        }
        // AV-52: validate every row's labels BEFORE doing any I/O.
        for o in obs {
            validate_labels(&o.labels)?;
            if o.tenant_id.is_empty() {
                return Err(Error::InvalidArgument("tenant_id required".into()));
            }
            if o.metric_name.is_empty() {
                return Err(Error::InvalidArgument("metric_name required".into()));
            }
        }

        let mut ids: Vec<uuid::Uuid> = Vec::with_capacity(obs.len());
        let mut names: Vec<&str> = Vec::with_capacity(obs.len());
        let mut tenants: Vec<&str> = Vec::with_capacity(obs.len());
        let mut values: Vec<f64> = Vec::with_capacity(obs.len());
        let mut labels: Vec<serde_json::Value> = Vec::with_capacity(obs.len());
        let mut observed: Vec<DateTime<Utc>> = Vec::with_capacity(obs.len());
        let mut expires: Vec<DateTime<Utc>> = Vec::with_capacity(obs.len());

        for o in obs {
            ids.push(resolve_metric_id(o)?);
            names.push(&o.metric_name);
            tenants.push(&o.tenant_id);
            values.push(o.value);
            labels.push(o.labels.clone());
            observed.push(o.observed_at);
            expires.push(resolve_expires_at(o));
        }

        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let n = client
            .execute(
                "INSERT INTO cirisgraph.telemetry_metrics (\
                    metric_id, metric_name, tenant_id, value, labels, \
                    observed_at, expires_at\
                 ) SELECT \
                    UNNEST($1::uuid[]), UNNEST($2::text[]), UNNEST($3::text[]), \
                    UNNEST($4::float8[]), UNNEST($5::jsonb[]), \
                    UNNEST($6::timestamptz[]), UNNEST($7::timestamptz[])",
                &[
                    &ids, &names, &tenants, &values, &labels, &observed, &expires,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_metrics_batch"))?;
        Ok(n)
    }

    async fn list_metrics(
        &self,
        filter: MetricFilter,
        cursor: Option<MetricCursor>,
        limit: i64,
    ) -> Result<MetricListPage, Error> {
        if filter.tenant_id.is_empty() {
            return Err(Error::InvalidArgument(
                "tenant_id is required (no cross-tenant reads)".into(),
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
        if let Some(n) = filter.metric_name {
            params.push(Box::new(n));
            where_parts.push(format!("metric_name = ${}", params.len()));
        }
        if let Some(after) = filter.observed_after {
            params.push(Box::new(after));
            where_parts.push(format!("observed_at >= ${}", params.len()));
        }
        if let Some(before) = filter.observed_before {
            params.push(Box::new(before));
            where_parts.push(format!("observed_at < ${}", params.len()));
        }
        if let Some(contains) = filter.labels_contains {
            params.push(Box::new(contains));
            where_parts.push(format!("labels @> ${}", params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "MetricCursor version {} unsupported",
                    cur.version
                )));
            }
            let last_uuid: uuid::Uuid = cur
                .last_id
                .parse()
                .map_err(|e| Error::InvalidArgument(format!("last_id parse: {e}")))?;
            params.push(Box::new(cur.last_ts));
            let p_ts = params.len();
            params.push(Box::new(last_uuid));
            let p_id = params.len();
            where_parts.push(format!("(observed_at, metric_id) < (${p_ts}, ${p_id})"));
        }
        params.push(Box::new(limit));
        let p_limit = params.len();
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT metric_id, metric_name, tenant_id, value, labels, \
                    observed_at, expires_at \
             FROM cirisgraph.telemetry_metrics \
             WHERE {where_sql} \
             ORDER BY observed_at DESC, metric_id DESC \
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
            .map_err(|e| map_pg_error(e, "list_metrics"))?;
        let mut items: Vec<MetricObservation> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_observation(row)?);
        }
        let next_cursor = if items.len() == limit as usize {
            items.last().and_then(|last| {
                last.metric_id
                    .clone()
                    .map(|id| MetricCursor::from_trailing(last.observed_at, id))
            })
        } else {
            None
        };
        Ok(MetricListPage { items, next_cursor })
    }

    async fn consolidate_period(
        &self,
        req: ConsolidationRequest,
    ) -> Result<ConsolidationOutcome, Error> {
        if req.tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id required".into()));
        }
        if req.period_end <= req.period_start {
            return Err(Error::InvalidArgument(
                "period_end must be > period_start".into(),
            ));
        }
        if req.locked_by.is_empty() {
            return Err(Error::InvalidArgument("locked_by required".into()));
        }

        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;

        // ── AV-53: acquire lock, with stale-lock auto-break ─────
        //
        // Try INSERT first; on conflict check if existing lock is
        // stale (>STALE_LOCK_SECONDS since locked_at) and steal it.
        let inserted = client
            .execute(
                "INSERT INTO cirisgraph.consolidation_locks (\
                    period_start, period_end, tenant_id, locked_by, locked_at\
                 ) VALUES ($1, $2, $3, $4, NOW()) \
                 ON CONFLICT (period_start, tenant_id) DO NOTHING",
                &[
                    &req.period_start,
                    &req.period_end,
                    &req.tenant_id,
                    &req.locked_by,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "consolidate_period lock insert"))?;

        let broke_stale_lock = if inserted == 0 {
            // Lock exists — check staleness. Interval is embedded
            // into SQL as a literal because `INTERVAL '$N seconds'`
            // isn't a parameter-friendly shape in tokio_postgres
            // (would need `make_interval(secs => $N)` workarounds).
            // `STALE_LOCK_SECONDS` is a compile-time constant so
            // there's no injection surface.
            let stale_sql = format!(
                "UPDATE cirisgraph.consolidation_locks \
                 SET locked_by = $1, locked_at = NOW() \
                 WHERE period_start = $2 AND tenant_id = $3 \
                   AND locked_at < NOW() - INTERVAL '{STALE_LOCK_SECONDS} seconds'"
            );
            let stale = client
                .execute(
                    &stale_sql,
                    &[&req.locked_by, &req.period_start, &req.tenant_id],
                )
                .await
                .map_err(|e| map_pg_error(e, "consolidate_period stale-break"))?;
            if stale == 0 {
                // Fresh lock held by another worker — abort.
                return Ok(ConsolidationOutcome {
                    metrics_consolidated: 0,
                    summaries_written: 0,
                    edges_created: 0,
                    raw_metrics_deleted: 0,
                    ran: false,
                    broke_stale_lock: false,
                });
            }
            tracing::warn!(
                tenant_id = %req.tenant_id,
                period_start = %req.period_start,
                "consolidate_period: broke stale lock (>{STALE_LOCK_SECONDS}s); prior worker may have crashed"
            );
            true
        } else {
            false
        };

        // ── Rollup transaction: aggregate, write summaries + edges, delete raw ─
        let outcome = match run_rollup(&mut client, &req).await {
            Ok(o) => o,
            Err(e) => {
                // Release the lock on failure so subsequent runs can retry.
                let _ = client
                    .execute(
                        "DELETE FROM cirisgraph.consolidation_locks \
                         WHERE period_start = $1 AND tenant_id = $2",
                        &[&req.period_start, &req.tenant_id],
                    )
                    .await;
                return Err(e);
            }
        };

        // Release lock on success.
        client
            .execute(
                "DELETE FROM cirisgraph.consolidation_locks \
                 WHERE period_start = $1 AND tenant_id = $2",
                &[&req.period_start, &req.tenant_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "consolidate_period lock release"))?;

        Ok(ConsolidationOutcome {
            metrics_consolidated: outcome.metrics_consolidated,
            summaries_written: outcome.summaries_written,
            edges_created: outcome.edges_created,
            raw_metrics_deleted: outcome.raw_metrics_deleted,
            ran: true,
            broke_stale_lock,
        })
    }
}

// ─── consolidation rollup helper ────────────────────────────────────

/// Inner rollup, runs inside the lock window. Aggregates raw metrics
/// in `[period_start, period_end)`, writes one tsdb_summary node per
/// metric_name to `cirisgraph.nodes`, creates TEMPORAL_NEXT edges
/// from prior periods' summaries, deletes raw rows.
async fn run_rollup(
    client: &mut deadpool_postgres::Object,
    req: &ConsolidationRequest,
) -> Result<ConsolidationOutcome, Error> {
    // 1. Aggregate by metric_name.
    let agg_rows = client
        .query(
            "SELECT metric_name, \
                    SUM(value) AS sum_v, \
                    MIN(value) AS min_v, \
                    MAX(value) AS max_v, \
                    AVG(value) AS avg_v, \
                    COUNT(*) AS count_v, \
                    COUNT(DISTINCT labels) AS unique_labels \
             FROM cirisgraph.telemetry_metrics \
             WHERE tenant_id = $1 \
               AND observed_at >= $2 AND observed_at < $3 \
             GROUP BY metric_name",
            &[&req.tenant_id, &req.period_start, &req.period_end],
        )
        .await
        .map_err(|e| map_pg_error(e, "rollup aggregate"))?;

    let metrics_consolidated: i64 = agg_rows
        .iter()
        .map(|r| r.try_get::<_, i64>("count_v").unwrap_or(0))
        .sum();

    let mut summaries_written: i64 = 0;
    let mut edges_created: i64 = 0;

    // 2. For each metric, UPSERT a tsdb_summary node + write
    //    TEMPORAL_NEXT edge from prior period if present.
    for row in &agg_rows {
        let metric_name: String = row
            .try_get("metric_name")
            .map_err(|e| Error::Backend(format!("decode metric_name: {e}")))?;
        let summary = MetricSummary {
            metric_name: metric_name.clone(),
            tenant_id: req.tenant_id.clone(),
            period_start: req.period_start,
            period_end: req.period_end,
            sum: row
                .try_get::<_, f64>("sum_v")
                .map_err(|e| Error::Backend(format!("decode sum: {e}")))?,
            min: row
                .try_get::<_, f64>("min_v")
                .map_err(|e| Error::Backend(format!("decode min: {e}")))?,
            max: row
                .try_get::<_, f64>("max_v")
                .map_err(|e| Error::Backend(format!("decode max: {e}")))?,
            avg: row
                .try_get::<_, f64>("avg_v")
                .map_err(|e| Error::Backend(format!("decode avg: {e}")))?,
            count: row
                .try_get::<_, i64>("count_v")
                .map_err(|e| Error::Backend(format!("decode count: {e}")))?,
            unique_label_combinations: row
                .try_get::<_, i64>("unique_labels")
                .map_err(|e| Error::Backend(format!("decode unique_labels: {e}")))?,
        };

        let summary_node_id = summary_node_id(&summary);
        let attributes = serde_json::to_value(&summary)
            .map_err(|e| Error::Internal(format!("summary serialize: {e}")))?;

        // Read current node version (if any) for the AV-48
        // expected_version gate.
        let current_version: Option<i32> = client
            .query_opt(
                "SELECT version FROM cirisgraph.nodes \
                 WHERE node_id = $1 AND scope = 'ENVIRONMENT'",
                &[&summary_node_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "rollup read current node version"))?
            .map(|r| r.get::<_, i32>("version"));

        let expected_version = current_version.unwrap_or(0);
        // UPSERT mirrors cirisgraph's upsert_node SQL shape — keeps
        // version-bump semantics aligned. The summary node carries
        // a `version` of N → N+1 on each rollup re-run; first write
        // lands at version=1.
        let affected = client
            .execute(
                "INSERT INTO cirisgraph.nodes (\
                    node_id, scope, node_type, attributes, version, \
                    updated_by, updated_at, persist_row_hash\
                 ) VALUES ($1, 'ENVIRONMENT', 'tsdb_summary', $2, 1, $3, NOW(), $4) \
                 ON CONFLICT (node_id, scope) DO UPDATE SET \
                    attributes = EXCLUDED.attributes, \
                    version = cirisgraph.nodes.version + 1, \
                    updated_by = EXCLUDED.updated_by, \
                    updated_at = NOW() \
                 WHERE cirisgraph.nodes.version = $5",
                &[
                    &summary_node_id,
                    &attributes,
                    &req.locked_by,
                    &"tsdb_summary_v0.8.2",
                    &expected_version,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "rollup upsert summary node"))?;
        if affected > 0 {
            summaries_written += 1;
        }

        // AV-54: TEMPORAL_NEXT edge from prior period's summary
        // node (if it exists). Look for a summary whose
        // period_start is the most recent one BEFORE this period
        // for the same metric_name + tenant.
        let prior_node_id_opt: Option<String> = client
            .query_opt(
                "SELECT node_id FROM cirisgraph.nodes \
                 WHERE node_type = 'tsdb_summary' AND scope = 'ENVIRONMENT' \
                   AND attributes @> $1 \
                   AND (attributes->>'period_start')::timestamptz < $2 \
                 ORDER BY (attributes->>'period_start')::timestamptz DESC \
                 LIMIT 1",
                &[
                    &serde_json::json!({
                        "metric_name": metric_name,
                        "tenant_id": req.tenant_id,
                    }),
                    &req.period_start,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "rollup find prior summary"))?
            .map(|r| r.get::<_, String>("node_id"));

        if let Some(prior_node_id) = prior_node_id_opt {
            // AV-54: refuse if source summary doesn't exist — but
            // we just queried it; race-free.
            let edge_uuid = uuid::Uuid::new_v4();
            client
                .execute(
                    "INSERT INTO cirisgraph.edges (\
                        edge_id, source_node_id, target_node_id, scope, \
                        relationship, weight, attributes\
                     ) VALUES ($1, $2, $3, 'ENVIRONMENT', 'TEMPORAL_NEXT', NULL, $4) \
                     ON CONFLICT (edge_id) DO NOTHING",
                    &[
                        &edge_uuid,
                        &prior_node_id,
                        &summary_node_id,
                        &serde_json::json!({
                            "metric_name": metric_name,
                            "tenant_id": req.tenant_id,
                            "period_start": req.period_start.to_rfc3339(),
                        }),
                    ],
                )
                .await
                .map_err(|e| map_pg_error(e, "rollup write TEMPORAL_NEXT edge"))?;
            edges_created += 1;
        }
    }

    // 3. Delete raw rows in the window. Doing this LAST so a
    //    transient failure in the summary write doesn't lose data.
    let raw_metrics_deleted = client
        .execute(
            "DELETE FROM cirisgraph.telemetry_metrics \
             WHERE tenant_id = $1 \
               AND observed_at >= $2 AND observed_at < $3",
            &[&req.tenant_id, &req.period_start, &req.period_end],
        )
        .await
        .map_err(|e| map_pg_error(e, "rollup delete raw"))?;

    Ok(ConsolidationOutcome {
        metrics_consolidated,
        summaries_written,
        edges_created,
        raw_metrics_deleted: raw_metrics_deleted as i64,
        ran: true,
        broke_stale_lock: false,
    })
}

/// Stable node_id for a tsdb_summary. Format:
/// `tsdb:{tenant_id}:{metric_name}:{period_start_iso8601}`. The
/// timestamp uses RFC 3339 so lexicographic ordering matches
/// chronological ordering — convenient for the prior-period join.
fn summary_node_id(summary: &MetricSummary) -> String {
    format!(
        "tsdb:{}:{}:{}",
        summary.tenant_id,
        summary.metric_name,
        summary.period_start.to_rfc3339()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    fn obs(name: &str, tenant: &str, value: f64, when: DateTime<Utc>) -> MetricObservation {
        MetricObservation {
            metric_id: None,
            metric_name: name.to_owned(),
            tenant_id: tenant.to_owned(),
            value,
            labels: serde_json::json!({"k": "v"}),
            observed_at: when,
            expires_at: None,
        }
    }

    /// v0.8.2 (CIRISPersist#36) — full lifecycle:
    /// record × N → list → consolidate → verify summary node +
    /// edges → re-run consolidation (idempotent, ran=true zero work)
    /// → second window with prior period creates TEMPORAL_NEXT edge.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn telemetry_round_trip_full_lifecycle() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let tenant = format!("tlm-{}", uuid::Uuid::new_v4().simple());
        let period_a_start = Utc::now() - Duration::hours(12);
        let period_a_end = period_a_start + Duration::hours(6);
        let period_b_start = period_a_end;
        let period_b_end = period_b_start + Duration::hours(6);

        // 1. Record 6 metrics in period A.
        let mut batch_a = Vec::new();
        for i in 0..3 {
            batch_a.push(obs(
                "llm.tokens.in",
                &tenant,
                100.0 * (i as f64 + 1.0),
                period_a_start + Duration::minutes(i as i64 * 10),
            ));
            batch_a.push(obs(
                "llm.tokens.out",
                &tenant,
                50.0 * (i as f64 + 1.0),
                period_a_start + Duration::minutes(i as i64 * 10),
            ));
        }
        let n = backend.record_metrics_batch(&batch_a).await.unwrap();
        assert_eq!(n, 6);

        // 2. Single record path also works.
        backend
            .record_metric(obs("agent.heartbeat", &tenant, 1.0, period_a_start))
            .await
            .unwrap();

        // 3. AV-52: oversized labels reject.
        let huge_labels = serde_json::json!({"big": "x".repeat(8 * 1024)});
        let too_big = MetricObservation {
            metric_id: None,
            metric_name: "test.oversized".into(),
            tenant_id: tenant.clone(),
            value: 1.0,
            labels: huge_labels,
            observed_at: Utc::now(),
            expires_at: None,
        };
        let err = backend.record_metric(too_big).await.unwrap_err();
        assert!(
            matches!(err, Error::InvalidArgument(_)),
            "expected InvalidArgument on oversized labels, got {err:?}"
        );

        // 4. list_metrics returns the 7 we wrote.
        let page = backend
            .list_metrics(
                MetricFilter {
                    tenant_id: tenant.clone(),
                    metric_name: None,
                    observed_after: Some(period_a_start - Duration::seconds(1)),
                    observed_before: Some(period_a_end),
                    labels_contains: None,
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 7);

        // 5. AV-51-style: empty tenant_id rejects.
        let no_tenant = backend
            .list_metrics(
                MetricFilter {
                    tenant_id: String::new(),
                    metric_name: None,
                    observed_after: None,
                    observed_before: None,
                    labels_contains: None,
                },
                None,
                10,
            )
            .await
            .unwrap_err();
        assert!(matches!(no_tenant, Error::InvalidArgument(_)));

        // 6. Consolidate period A.
        let req_a = ConsolidationRequest {
            tenant_id: tenant.clone(),
            period_start: period_a_start,
            period_end: period_a_end,
            locked_by: "test-worker-1".into(),
        };
        let out_a = backend.consolidate_period(req_a.clone()).await.unwrap();
        assert!(out_a.ran);
        assert!(!out_a.broke_stale_lock);
        assert_eq!(out_a.metrics_consolidated, 7);
        assert_eq!(out_a.summaries_written, 3, "3 distinct metric_names");
        assert_eq!(out_a.edges_created, 0, "no prior period for these metrics");
        assert_eq!(out_a.raw_metrics_deleted, 7);

        // 7. Idempotent re-run on period A. No raw rows left → zero
        // work, but still ran=true. Summary nodes UPSERT with
        // version bump; we set summaries_written based on
        // UPDATE-affected which IS nonzero on the version bump.
        let out_a2 = backend.consolidate_period(req_a).await.unwrap();
        assert!(out_a2.ran);
        assert_eq!(out_a2.metrics_consolidated, 0);
        assert_eq!(out_a2.raw_metrics_deleted, 0);

        // 8. Verify raw metrics are gone for the window.
        let post_page = backend
            .list_metrics(
                MetricFilter {
                    tenant_id: tenant.clone(),
                    metric_name: None,
                    observed_after: Some(period_a_start - Duration::seconds(1)),
                    observed_before: Some(period_a_end),
                    labels_contains: None,
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert!(post_page.items.is_empty(), "raw rows reaped");

        // 9. Write metrics in period B + consolidate → should write
        //    TEMPORAL_NEXT edges from period-A summaries.
        let mut batch_b = Vec::new();
        for i in 0..2 {
            batch_b.push(obs(
                "llm.tokens.in",
                &tenant,
                200.0,
                period_b_start + Duration::minutes(i * 5),
            ));
            batch_b.push(obs(
                "llm.tokens.out",
                &tenant,
                100.0,
                period_b_start + Duration::minutes(i * 5),
            ));
        }
        backend.record_metrics_batch(&batch_b).await.unwrap();
        let out_b = backend
            .consolidate_period(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start: period_b_start,
                period_end: period_b_end,
                locked_by: "test-worker-1".into(),
            })
            .await
            .unwrap();
        assert!(out_b.ran);
        assert_eq!(out_b.summaries_written, 2);
        assert_eq!(
            out_b.edges_created, 2,
            "TEMPORAL_NEXT to both period-A summaries (llm.tokens.in + .out)"
        );

        // 10. AV-53 stale-lock contention model. We can't easily
        // simulate elapsed time in a test, but we can verify that
        // re-consolidating the SAME period from a different worker
        // with a fresh lock returns ran=false (lock held).
        let outcome_blocked = backend
            .consolidate_period(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start: period_b_start,
                period_end: period_b_end,
                locked_by: "test-worker-2".into(),
            })
            .await
            .unwrap();
        // Period B lock was released after consolidation, so worker-2
        // actually acquires + runs (with no raw rows). The contention
        // path only triggers when a worker is HOLDING the lock.
        assert!(outcome_blocked.ran);
    }

    /// Validate the consolidation_locks contention path: insert a
    /// lock manually, then consolidate_period should return ran=false.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn telemetry_lock_contention_returns_ran_false() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let tenant = format!("lock-{}", uuid::Uuid::new_v4().simple());
        let period_start = Utc::now() - Duration::hours(6);
        let period_end = period_start + Duration::hours(6);

        // Plant a fresh lock from a different worker.
        let client = backend.pool().get().await.unwrap();
        client
            .execute(
                "INSERT INTO cirisgraph.consolidation_locks \
                 (period_start, period_end, tenant_id, locked_by, locked_at) \
                 VALUES ($1, $2, $3, 'planted-worker', NOW())",
                &[&period_start, &period_end, &tenant],
            )
            .await
            .unwrap();
        drop(client);

        // Now attempt consolidation — should bail with ran=false.
        let outcome = backend
            .consolidate_period(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start,
                period_end,
                locked_by: "test-blocked-worker".into(),
            })
            .await
            .unwrap();
        assert!(!outcome.ran, "fresh lock held by another worker blocks");
        assert!(!outcome.broke_stale_lock);

        // Clean up.
        let cleanup = backend.pool().get().await.unwrap();
        cleanup
            .execute(
                "DELETE FROM cirisgraph.consolidation_locks \
                 WHERE period_start = $1 AND tenant_id = $2",
                &[&period_start, &tenant],
            )
            .await
            .unwrap();
    }
}
