//! PostgreSQL impl of [`TelemetryService`] (v0.8.2, CIRISPersist#36).
//!
//! Raw observations land via single + bulk INSERT paths.
//! Consolidation runs the per-period rollup with the
//! [`cirisgraph.consolidation_locks`] coordination gate.

use chrono::{DateTime, Duration, Utc};

use super::service::TelemetryService;
use super::types::{
    ConsolidationLevel, ConsolidationOutcome, ConsolidationRequest, MetricCursor, MetricFilter,
    MetricListPage, MetricObservation, MetricSummary,
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

    // ── v1.6.0 (CIRISPersist#63) TSDB query / prune surface ─────────

    async fn query_summaries(
        &self,
        level: ConsolidationLevel,
        tenant_id: &str,
        from: chrono::DateTime<chrono::Utc>,
        to: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<MetricSummary>, Error> {
        if from >= to {
            return Err(Error::InvalidArgument(format!(
                "from ({from}) must be < to ({to})"
            )));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT attributes FROM cirisgraph.nodes \
                 WHERE node_type = 'tsdb_summary' AND scope = 'ENVIRONMENT' \
                   AND consolidation_level = $1 \
                   AND attributes->>'tenant_id' = $2 \
                   AND ((attributes->>'period_start')::timestamptz) >= $3 \
                   AND ((attributes->>'period_start')::timestamptz) <  $4 \
                 ORDER BY (attributes->>'period_start')::timestamptz ASC, \
                          attributes->>'metric_name' ASC",
                &[&level.as_str(), &tenant_id, &from, &to],
            )
            .await
            .map_err(|e| map_pg_error(e, "query_summaries"))?;
        let mut out: Vec<MetricSummary> = Vec::with_capacity(rows.len());
        for r in &rows {
            let attrs: serde_json::Value = r
                .try_get("attributes")
                .map_err(|e| Error::Backend(format!("decode attributes: {e}")))?;
            let summary: MetricSummary = serde_json::from_value(attrs)
                .map_err(|e| Error::Backend(format!("MetricSummary decode: {e}")))?;
            out.push(summary);
        }
        Ok(out)
    }

    async fn get_summary(
        &self,
        level: ConsolidationLevel,
        tenant_id: &str,
        metric_name: &str,
        period_start: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<MetricSummary>, Error> {
        // Build the deterministic key the rollup write path uses
        // (mirrors `summary_node_id` below).
        let key = format!(
            "tsdb:{}:{}:{}:{}",
            level.as_str(),
            tenant_id,
            metric_name,
            period_start.to_rfc3339()
        );
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT attributes FROM cirisgraph.nodes \
                 WHERE node_id = $1 AND scope = 'ENVIRONMENT' \
                   AND node_type = 'tsdb_summary'",
                &[&key],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_summary"))?;
        let Some(row) = row_opt else { return Ok(None) };
        let attrs: serde_json::Value = row
            .try_get("attributes")
            .map_err(|e| Error::Backend(format!("decode attributes: {e}")))?;
        let summary: MetricSummary = serde_json::from_value(attrs)
            .map_err(|e| Error::Backend(format!("MetricSummary decode: {e}")))?;
        Ok(Some(summary))
    }

    async fn prune_summaries(
        &self,
        level: ConsolidationLevel,
        tenant_id: &str,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, Error> {
        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin tx: {e}")))?;

        // Find pruning candidates first — caller-side cascade for the
        // TEMPORAL_NEXT edges (V013 allows dangling edges so cascade
        // is application-layer, mirroring the cirisgraph.delete_node
        // contract).
        let victim_rows = tx
            .query(
                "SELECT node_id FROM cirisgraph.nodes \
                 WHERE node_type = 'tsdb_summary' AND scope = 'ENVIRONMENT' \
                   AND consolidation_level = $1 \
                   AND attributes->>'tenant_id' = $2 \
                   AND ((attributes->>'period_end')::timestamptz) < $3",
                &[&level.as_str(), &tenant_id, &before],
            )
            .await
            .map_err(|e| map_pg_error(e, "prune_summaries select victims"))?;
        if victim_rows.is_empty() {
            tx.commit()
                .await
                .map_err(|e| Error::Backend(format!("commit: {e}")))?;
            return Ok(0);
        }
        let node_ids: Vec<String> = victim_rows
            .iter()
            .map(|r| r.try_get::<_, String>("node_id"))
            .collect::<Result<_, _>>()
            .map_err(|e| Error::Backend(format!("decode victim node_id: {e}")))?;

        // Cascade edges (incoming + outgoing) referencing victim nodes.
        tx.execute(
            "DELETE FROM cirisgraph.edges \
             WHERE scope = 'ENVIRONMENT' \
               AND (source_node_id = ANY($1) OR target_node_id = ANY($1))",
            &[&node_ids],
        )
        .await
        .map_err(|e| map_pg_error(e, "prune_summaries cascade edges"))?;

        let deleted = tx
            .execute(
                "DELETE FROM cirisgraph.nodes \
                 WHERE node_id = ANY($1) AND scope = 'ENVIRONMENT'",
                &[&node_ids],
            )
            .await
            .map_err(|e| map_pg_error(e, "prune_summaries delete nodes"))?;
        tx.commit()
            .await
            .map_err(|e| Error::Backend(format!("commit: {e}")))?;
        Ok(deleted)
    }

    async fn count_edges_by_relationship_in_window(
        &self,
        from: chrono::DateTime<chrono::Utc>,
        to: chrono::DateTime<chrono::Utc>,
    ) -> Result<std::collections::HashMap<String, u64>, Error> {
        if from >= to {
            return Err(Error::InvalidArgument(format!(
                "from ({from}) must be < to ({to})"
            )));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT relationship, COUNT(*)::BIGINT AS c \
                 FROM cirisgraph.edges \
                 WHERE scope = 'ENVIRONMENT' \
                   AND created_at >= $1 AND created_at < $2 \
                 GROUP BY relationship",
                &[&from, &to],
            )
            .await
            .map_err(|e| map_pg_error(e, "count_edges_by_relationship_in_window"))?;
        let mut out: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
        for r in &rows {
            let rel: String = r
                .try_get("relationship")
                .map_err(|e| Error::Backend(format!("decode relationship: {e}")))?;
            let c: i64 = r
                .try_get("c")
                .map_err(|e| Error::Backend(format!("decode count: {e}")))?;
            out.insert(rel, c.max(0) as u64);
        }
        Ok(out)
    }
}

// ─── consolidation rollup helper ────────────────────────────────────

/// Inner rollup, runs inside the lock window. Aggregates raw metrics
/// in `[period_start, period_end)`, writes one tsdb_summary node per
/// metric_name to `cirisgraph.nodes`, creates TEMPORAL_NEXT edges
/// from prior periods' summaries, deletes raw rows.
/// Aggregate row shared by both rollup paths (raw vs. tier-summary).
struct AggRow {
    metric_name: String,
    sum_v: f64,
    min_v: f64,
    max_v: f64,
    avg_v: f64,
    count_v: i64,
    unique_labels: i64,
}

async fn aggregate_basic_from_raw(
    client: &mut deadpool_postgres::Object,
    req: &ConsolidationRequest,
) -> Result<Vec<AggRow>, Error> {
    let rows = client
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
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        out.push(AggRow {
            metric_name: r
                .try_get("metric_name")
                .map_err(|e| Error::Backend(format!("decode metric_name: {e}")))?,
            sum_v: r
                .try_get("sum_v")
                .map_err(|e| Error::Backend(format!("decode sum_v: {e}")))?,
            min_v: r
                .try_get("min_v")
                .map_err(|e| Error::Backend(format!("decode min_v: {e}")))?,
            max_v: r
                .try_get("max_v")
                .map_err(|e| Error::Backend(format!("decode max_v: {e}")))?,
            avg_v: r
                .try_get("avg_v")
                .map_err(|e| Error::Backend(format!("decode avg_v: {e}")))?,
            count_v: r
                .try_get("count_v")
                .map_err(|e| Error::Backend(format!("decode count_v: {e}")))?,
            unique_labels: r
                .try_get("unique_labels")
                .map_err(|e| Error::Backend(format!("decode unique_labels: {e}")))?,
        });
    }
    Ok(out)
}

/// Roll up the previous tier's summary rows. Per (metric_name + tenant)
/// group: new count = sum(input counts), new sum = sum(input sums),
/// new min = min(input mins), new max = max(input maxes), new avg =
/// new sum / new count.
async fn aggregate_higher_tier(
    client: &mut deadpool_postgres::Object,
    req: &ConsolidationRequest,
    input_tier: ConsolidationLevel,
) -> Result<Vec<AggRow>, Error> {
    let rows = client
        .query(
            "SELECT attributes->>'metric_name'                              AS metric_name, \
                    SUM((attributes->>'sum')::float8)                        AS sum_v, \
                    MIN((attributes->>'min')::float8)                        AS min_v, \
                    MAX((attributes->>'max')::float8)                        AS max_v, \
                    SUM((attributes->>'count')::bigint)::bigint              AS count_v, \
                    SUM((attributes->>'unique_label_combinations')::bigint)::bigint AS unique_labels \
             FROM cirisgraph.nodes \
             WHERE node_type = 'tsdb_summary' AND scope = 'ENVIRONMENT' \
               AND consolidation_level = $1 \
               AND attributes->>'tenant_id' = $2 \
               AND ((attributes->>'period_start')::timestamptz) >= $3 \
               AND ((attributes->>'period_end')::timestamptz)   <= $4 \
             GROUP BY attributes->>'metric_name'",
            &[
                &input_tier.as_str(),
                &req.tenant_id,
                &req.period_start,
                &req.period_end,
            ],
        )
        .await
        .map_err(|e| map_pg_error(e, "rollup aggregate higher tier"))?;
    let mut out = Vec::with_capacity(rows.len());
    for r in &rows {
        let count_v: i64 = r
            .try_get("count_v")
            .map_err(|e| Error::Backend(format!("decode count_v: {e}")))?;
        let sum_v: f64 = r
            .try_get("sum_v")
            .map_err(|e| Error::Backend(format!("decode sum_v: {e}")))?;
        let avg_v = if count_v > 0 {
            sum_v / count_v as f64
        } else {
            0.0
        };
        out.push(AggRow {
            metric_name: r
                .try_get("metric_name")
                .map_err(|e| Error::Backend(format!("decode metric_name: {e}")))?,
            sum_v,
            min_v: r
                .try_get("min_v")
                .map_err(|e| Error::Backend(format!("decode min_v: {e}")))?,
            max_v: r
                .try_get("max_v")
                .map_err(|e| Error::Backend(format!("decode max_v: {e}")))?,
            avg_v,
            count_v,
            unique_labels: r
                .try_get("unique_labels")
                .map_err(|e| Error::Backend(format!("decode unique_labels: {e}")))?,
        });
    }
    Ok(out)
}

async fn run_rollup(
    client: &mut deadpool_postgres::Object,
    req: &ConsolidationRequest,
) -> Result<ConsolidationOutcome, Error> {
    // 1. Aggregate by metric_name — source depends on tier.
    //    Basic: raw observations.
    //    Daily/Weekly/Monthly: previous tier's summary rows in the
    //    same period window.
    let agg_rows = match req.level.input_tier() {
        None => aggregate_basic_from_raw(client, req).await?,
        Some(input_tier) => aggregate_higher_tier(client, req, input_tier).await?,
    };

    let metrics_consolidated: i64 = agg_rows.iter().map(|r| r.count_v).sum();

    let mut summaries_written: i64 = 0;
    let mut edges_created: i64 = 0;

    // 2. For each metric, UPSERT a tsdb_summary node + write
    //    TEMPORAL_NEXT edge from prior period if present.
    for row in &agg_rows {
        let metric_name = row.metric_name.clone();
        let summary = MetricSummary {
            metric_name: metric_name.clone(),
            tenant_id: req.tenant_id.clone(),
            period_start: req.period_start,
            period_end: req.period_end,
            sum: row.sum_v,
            min: row.min_v,
            max: row.max_v,
            avg: row.avg_v,
            count: row.count_v,
            unique_label_combinations: row.unique_labels,
            consolidation_level: req.level,
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
        // lands at version=1. V019: consolidation_level is a real
        // column (the value lives in attributes too, but the column
        // is the indexable surface for the rollup probes).
        let affected = client
            .execute(
                "INSERT INTO cirisgraph.nodes (\
                    node_id, scope, node_type, attributes, version, \
                    updated_by, updated_at, persist_row_hash, consolidation_level\
                 ) VALUES ($1, 'ENVIRONMENT', 'tsdb_summary', $2, 1, $3, NOW(), $4, $6) \
                 ON CONFLICT (node_id, scope) DO UPDATE SET \
                    attributes = EXCLUDED.attributes, \
                    version = cirisgraph.nodes.version + 1, \
                    updated_by = EXCLUDED.updated_by, \
                    updated_at = NOW(), \
                    consolidation_level = EXCLUDED.consolidation_level \
                 WHERE cirisgraph.nodes.version = $5",
                &[
                    &summary_node_id,
                    &attributes,
                    &req.locked_by,
                    &"tsdb_summary_v0.8.2",
                    &expected_version,
                    &req.level.as_str(),
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
        // for the same metric_name + tenant + level (chain stays
        // tier-local — basic → basic, daily → daily, etc.).
        let prior_node_id_opt: Option<String> = client
            .query_opt(
                "SELECT node_id FROM cirisgraph.nodes \
                 WHERE node_type = 'tsdb_summary' AND scope = 'ENVIRONMENT' \
                   AND consolidation_level = $3 \
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
                    &req.level.as_str(),
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

    // 3. Delete raw rows in the window — only on the Basic tier.
    //    Higher tiers aggregate prior-tier summaries; the raw
    //    table is already empty by the time they run. Doing this
    //    LAST so a transient failure in the summary write doesn't
    //    lose data.
    let raw_metrics_deleted: u64 = if matches!(req.level, ConsolidationLevel::Basic) {
        client
            .execute(
                "DELETE FROM cirisgraph.telemetry_metrics \
                 WHERE tenant_id = $1 \
                   AND observed_at >= $2 AND observed_at < $3",
                &[&req.tenant_id, &req.period_start, &req.period_end],
            )
            .await
            .map_err(|e| map_pg_error(e, "rollup delete raw"))?
    } else {
        0
    };

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
/// `tsdb:{level}:{tenant_id}:{metric_name}:{period_start_iso8601}`.
/// Level is part of the key so different tiers' summaries for the
/// same (tenant, metric, period_start) don't collide on the
/// (node_id, scope) primary key. The timestamp uses RFC 3339 so
/// lexicographic ordering matches chronological ordering —
/// convenient for the prior-period join.
fn summary_node_id(summary: &MetricSummary) -> String {
    format!(
        "tsdb:{}:{}:{}:{}",
        summary.consolidation_level.as_str(),
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
            level: ConsolidationLevel::Basic,
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
                level: ConsolidationLevel::Basic,
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
                level: ConsolidationLevel::Basic,
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
                level: ConsolidationLevel::Basic,
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

    /// v1.0.0 (CIRISAgent#756 Q7) — Daily tier rollup. Four basic-
    /// tier summaries spanning a day → one daily-tier summary per
    /// metric. Asserts the input counts/sums roll up correctly.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn telemetry_daily_tier_rolls_up_basic() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let tenant = format!("tier-{}", uuid::Uuid::new_v4().simple());
        let day_start = Utc::now() - Duration::days(2);
        let day_end = day_start + Duration::hours(24);

        // 4 basic-tier 6h windows fill the day.
        for i in 0..4 {
            let p_start = day_start + Duration::hours(i * 6);
            let p_end = p_start + Duration::hours(6);
            // 3 raw observations per window.
            let batch = vec![
                obs("rpm", &tenant, 10.0, p_start),
                obs("rpm", &tenant, 20.0, p_start + Duration::minutes(60)),
                obs("rpm", &tenant, 30.0, p_start + Duration::minutes(120)),
            ];
            backend.record_metrics_batch(&batch).await.unwrap();
            let out = backend
                .consolidate_period(ConsolidationRequest {
                    tenant_id: tenant.clone(),
                    period_start: p_start,
                    period_end: p_end,
                    locked_by: "tier-worker".into(),
                    level: ConsolidationLevel::Basic,
                })
                .await
                .unwrap();
            assert!(out.ran);
            assert_eq!(out.summaries_written, 1);
            assert_eq!(out.metrics_consolidated, 3);
        }

        // Now roll up the day → daily tier.
        let out_daily = backend
            .consolidate_period(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start: day_start,
                period_end: day_end,
                locked_by: "tier-worker".into(),
                level: ConsolidationLevel::Daily,
            })
            .await
            .unwrap();
        assert!(out_daily.ran);
        assert_eq!(out_daily.summaries_written, 1, "one daily summary for rpm");
        assert_eq!(
            out_daily.metrics_consolidated, 12,
            "4 basic summaries × 3 raw obs each = 12 total count"
        );
        assert_eq!(
            out_daily.raw_metrics_deleted, 0,
            "higher tiers don't touch the raw table"
        );

        // Verify the daily summary row carries consolidation_level='daily'.
        let client = backend.pool().get().await.unwrap();
        let row = client
            .query_one(
                "SELECT consolidation_level, attributes \
                 FROM cirisgraph.nodes \
                 WHERE node_type = 'tsdb_summary' \
                   AND consolidation_level = 'daily' \
                   AND attributes->>'tenant_id' = $1 \
                   AND attributes->>'metric_name' = 'rpm'",
                &[&tenant],
            )
            .await
            .unwrap();
        let lvl: String = row.get("consolidation_level");
        assert_eq!(lvl, "daily");
        let attrs: serde_json::Value = row.get("attributes");
        assert_eq!(attrs["consolidation_level"], "daily");
        assert_eq!(attrs["count"].as_i64(), Some(12));
        assert_eq!(attrs["sum"].as_f64(), Some(240.0)); // (10+20+30)*4
        assert_eq!(attrs["min"].as_f64(), Some(10.0));
        assert_eq!(attrs["max"].as_f64(), Some(30.0));
        assert_eq!(attrs["avg"].as_f64(), Some(20.0));
    }

    // ── v1.6.0 (CIRISPersist#63) TSDB query / prune tests ──────────

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tsdb_pg_query_get_prune_round_trip() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let tenant = format!("tlm-{}", uuid::Uuid::new_v4().simple());
        let now = chrono::Utc::now();
        let period_start = now - Duration::hours(6);
        let period_end = now;

        for i in 0..3 {
            backend
                .record_metric(MetricObservation {
                    metric_id: None,
                    metric_name: "metric_a".into(),
                    tenant_id: tenant.clone(),
                    value: 10.0 * (i as f64 + 1.0),
                    labels: serde_json::json!({"k": "v"}),
                    observed_at: period_start + Duration::minutes(i as i64 * 10),
                    expires_at: None,
                })
                .await
                .unwrap();
        }
        backend
            .consolidate_period(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start,
                period_end,
                locked_by: "w".into(),
                level: ConsolidationLevel::Basic,
            })
            .await
            .unwrap();

        // query_summaries returns the one summary.
        let rows = backend
            .query_summaries(
                ConsolidationLevel::Basic,
                &tenant,
                period_start - Duration::hours(1),
                period_end + Duration::hours(1),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].metric_name, "metric_a");
        assert_eq!(rows[0].count, 3);
        assert_eq!(rows[0].sum, 60.0);
        assert_eq!(rows[0].consolidation_level, ConsolidationLevel::Basic);

        // get_summary point lookup.
        let got = backend
            .get_summary(ConsolidationLevel::Basic, &tenant, "metric_a", period_start)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.metric_name, "metric_a");
        let missing = backend
            .get_summary(ConsolidationLevel::Basic, &tenant, "absent", period_start)
            .await
            .unwrap();
        assert!(missing.is_none());

        // prune_summaries: cutoff = period_end + 1h → drops the row.
        let deleted = backend
            .prune_summaries(
                ConsolidationLevel::Basic,
                &tenant,
                period_end + Duration::hours(1),
            )
            .await
            .unwrap();
        assert_eq!(deleted, 1);
        let after = backend
            .query_summaries(
                ConsolidationLevel::Basic,
                &tenant,
                period_start - Duration::hours(1),
                period_end + Duration::hours(2),
            )
            .await
            .unwrap();
        assert!(after.is_empty());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn tsdb_pg_count_edges_by_relationship_in_window() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let tenant = format!("tlm-{}", uuid::Uuid::new_v4().simple());
        let now = chrono::Utc::now();
        let a_start = now - Duration::hours(12);
        let a_end = a_start + Duration::hours(6);
        let b_start = a_end;
        let b_end = b_start + Duration::hours(6);

        for start in [&a_start, &b_start] {
            backend
                .record_metric(MetricObservation {
                    metric_id: None,
                    metric_name: "m1".into(),
                    tenant_id: tenant.clone(),
                    value: 1.0,
                    labels: serde_json::json!({"k": "v"}),
                    observed_at: *start,
                    expires_at: None,
                })
                .await
                .unwrap();
        }
        backend
            .consolidate_period(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start: a_start,
                period_end: a_end,
                locked_by: "w".into(),
                level: ConsolidationLevel::Basic,
            })
            .await
            .unwrap();
        backend
            .consolidate_period(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start: b_start,
                period_end: b_end,
                locked_by: "w".into(),
                level: ConsolidationLevel::Basic,
            })
            .await
            .unwrap();

        let map = backend
            .count_edges_by_relationship_in_window(
                a_start - Duration::hours(1),
                now + Duration::hours(1),
            )
            .await
            .unwrap();
        assert!(
            map.get("TEMPORAL_NEXT").copied().unwrap_or(0) >= 1,
            "expected ≥1 TEMPORAL_NEXT edge (one per consecutive metric); got map={map:?}"
        );
    }
}
