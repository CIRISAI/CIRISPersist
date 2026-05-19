//! SQLite impl of [`TelemetryService`] (v0.8.6, CIRISPersist#38).
//!
//! Mirrors v0.8.2 Postgres impl with SQLite-dialect translations.
//! Summary node writes go through the same `cirisgraph_nodes` table
//! the v0.8.4 SQLite cirisgraph impl manages; this module's
//! consolidator UPSERTs directly via SQL rather than calling
//! through a `GraphService` to avoid the trait-handle plumbing.

use std::sync::Arc;

use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use tokio::sync::Mutex;

use super::service::TelemetryService;
use super::types::{
    AuditSummary, ConsolidationLevel, ConsolidationOutcome, ConsolidationRequest,
    ConversationSummary, MetricCursor, MetricFilter, MetricListPage, MetricObservation,
    MetricSummary, TaskSummary, TraceSummary, TypedConsolidationOutcome,
};
use super::{Error, DEFAULT_MAX_LABELS_BYTES, STALE_LOCK_SECONDS};

/// SQLite-backed [`TelemetryService`] impl.
pub struct SqliteTelemetryBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteTelemetryBackend {
    /// Construct from a shared connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    Error::Backend(format!("{op}: {e}"))
}

fn max_labels_bytes() -> usize {
    std::env::var("CIRIS_PERSIST_TELEMETRY_MAX_LABELS_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_LABELS_BYTES)
}

fn validate_labels(labels: &serde_json::Value) -> Result<String, Error> {
    let s = serde_json::to_string(labels)
        .map_err(|e| Error::Internal(format!("labels serialize: {e}")))?;
    let cap = max_labels_bytes();
    if s.len() > cap {
        return Err(Error::InvalidArgument(format!(
            "labels too large: {} bytes exceeds cap of {}",
            s.len(),
            cap
        )));
    }
    Ok(s)
}

fn resolve_expires_at(obs: &MetricObservation) -> chrono::DateTime<chrono::Utc> {
    obs.expires_at
        .unwrap_or_else(|| obs.observed_at + chrono::Duration::hours(24))
}

fn resolve_metric_id(obs: &MetricObservation) -> Result<String, Error> {
    match &obs.metric_id {
        Some(s) => Ok(s.clone()),
        None => Ok(uuid::Uuid::new_v4().to_string()),
    }
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

/// Truncate to microsecond precision. Duplicated locally rather than
/// pulled from `crate::audit::verify` so the `telemetry` feature
/// stays decoupled from `cirisaudit`. (Future: lift to a shared
/// `crate::util::time` once a third consumer appears.)
fn truncate_to_micros(dt: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    use chrono::Timelike as _;
    let micros = dt.nanosecond() / 1000;
    dt.with_nanosecond(micros * 1000).unwrap_or(dt)
}

fn decode_observation(row: &rusqlite::Row<'_>) -> Result<MetricObservation, Error> {
    let labels_str: String = row
        .get("labels")
        .map_err(|e| Error::Backend(format!("decode labels: {e}")))?;
    let labels: serde_json::Value = serde_json::from_str(&labels_str)
        .map_err(|e| Error::Backend(format!("labels JSON decode: {e}")))?;
    let observed_at_str: String = row
        .get("observed_at")
        .map_err(|e| Error::Backend(format!("decode observed_at: {e}")))?;
    let expires_at_str: String = row
        .get("expires_at")
        .map_err(|e| Error::Backend(format!("decode expires_at: {e}")))?;
    Ok(MetricObservation {
        metric_id: Some(
            row.get("metric_id")
                .map_err(|e| Error::Backend(format!("decode metric_id: {e}")))?,
        ),
        metric_name: row
            .get("metric_name")
            .map_err(|e| Error::Backend(format!("decode metric_name: {e}")))?,
        tenant_id: row
            .get("tenant_id")
            .map_err(|e| Error::Backend(format!("decode tenant_id: {e}")))?,
        value: row
            .get("value")
            .map_err(|e| Error::Backend(format!("decode value: {e}")))?,
        labels,
        observed_at: parse_datetime(&observed_at_str)?,
        expires_at: Some(parse_datetime(&expires_at_str)?),
    })
}

impl TelemetryService for SqliteTelemetryBackend {
    async fn record_metric(&self, obs: MetricObservation) -> Result<(), Error> {
        if obs.tenant_id.is_empty() {
            return Err(Error::InvalidArgument("tenant_id required".into()));
        }
        if obs.metric_name.is_empty() {
            return Err(Error::InvalidArgument("metric_name required".into()));
        }
        let labels_str = validate_labels(&obs.labels)?;
        let metric_id = resolve_metric_id(&obs)?;
        let expires_at = resolve_expires_at(&obs);

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), Error> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO cirisgraph_telemetry_metrics (\
                        metric_id, metric_name, tenant_id, value, labels, \
                        observed_at, expires_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        metric_id,
                        obs.metric_name,
                        obs.tenant_id,
                        obs.value,
                        labels_str,
                        fmt_datetime(obs.observed_at),
                        fmt_datetime(expires_at),
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "record_metric"))?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn record_metrics_batch(&self, obs: &[MetricObservation]) -> Result<u64, Error> {
        if obs.is_empty() {
            return Ok(0);
        }
        // Validate every row's labels before any I/O.
        let mut rows: Vec<(String, String, String, f64, String, String, String)> =
            Vec::with_capacity(obs.len());
        for o in obs {
            if o.tenant_id.is_empty() {
                return Err(Error::InvalidArgument("tenant_id required".into()));
            }
            if o.metric_name.is_empty() {
                return Err(Error::InvalidArgument("metric_name required".into()));
            }
            let labels_str = validate_labels(&o.labels)?;
            rows.push((
                resolve_metric_id(o)?,
                o.metric_name.clone(),
                o.tenant_id.clone(),
                o.value,
                labels_str,
                fmt_datetime(o.observed_at),
                fmt_datetime(resolve_expires_at(o)),
            ));
        }
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<u64, Error> {
            let mut guard = conn.blocking_lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "record_metrics_batch begin"))?;
            let mut inserted: u64 = 0;
            {
                let mut stmt = tx
                    .prepare(
                        "INSERT INTO cirisgraph_telemetry_metrics (\
                            metric_id, metric_name, tenant_id, value, labels, \
                            observed_at, expires_at\
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    )
                    .map_err(|e| map_sqlite_error(e, "record_metrics_batch prepare"))?;
                for (id, name, tnt, val, lbl, obs_at, exp_at) in &rows {
                    stmt.execute(params![id, name, tnt, val, lbl, obs_at, exp_at])
                        .map_err(|e| map_sqlite_error(e, "record_metrics_batch insert"))?;
                    inserted += 1;
                }
            }
            tx.commit()
                .map_err(|e| map_sqlite_error(e, "record_metrics_batch commit"))?;
            Ok(inserted)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
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
        let mut where_parts: Vec<String> = vec!["tenant_id = ?".to_string()];
        let mut params: Vec<SqlValue> = vec![SqlValue::Text(filter.tenant_id)];
        if let Some(n) = filter.metric_name {
            params.push(SqlValue::Text(n));
            where_parts.push("metric_name = ?".to_string());
        }
        if let Some(after) = filter.observed_after {
            params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push("observed_at >= ?".to_string());
        }
        if let Some(before) = filter.observed_before {
            params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push("observed_at < ?".to_string());
        }
        if let Some(contains) = filter.labels_contains {
            // SQLite has no JSONB @>; translate top-level object
            // keys to individual json_extract equality checks.
            if let Some(obj) = contains.as_object() {
                for (k, v) in obj {
                    let json_path = format!("$.{k}");
                    let v_str = serde_json::to_string(v)
                        .map_err(|e| Error::Internal(format!("labels_contains serialize: {e}")))?;
                    params.push(SqlValue::Text(json_path));
                    params.push(SqlValue::Text(v_str));
                    where_parts.push(format!(
                        "json_extract(labels, ?{}) = json(?{})",
                        params.len() - 1,
                        params.len()
                    ));
                }
            } else {
                return Err(Error::InvalidArgument(
                    "labels_contains must be a JSON object".into(),
                ));
            }
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "MetricCursor version {} unsupported",
                    cur.version
                )));
            }
            params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
            params.push(SqlValue::Text(cur.last_id.clone()));
            where_parts.push("(observed_at, metric_id) < (?, ?)".to_string());
        }
        params.push(SqlValue::Integer(limit));
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT metric_id, metric_name, tenant_id, value, labels, \
                    observed_at, expires_at \
             FROM cirisgraph_telemetry_metrics \
             WHERE {where_sql} \
             ORDER BY observed_at DESC, metric_id DESC \
             LIMIT ?"
        );

        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        tokio::task::spawn_blocking(move || -> Result<MetricListPage, Error> {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "list_metrics prepare"))?;
            let rows_iter = stmt
                .query_map(params_from_iter(params.iter()), |row| {
                    Ok(decode_observation(row))
                })
                .map_err(|e| map_sqlite_error(e, "list_metrics query"))?;
            let mut items = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "list_metrics row"))??);
            }
            let next_cursor = if items.len() == limit_usize {
                items.last().and_then(|last| {
                    last.metric_id
                        .clone()
                        .map(|id| MetricCursor::from_trailing(last.observed_at, id))
                })
            } else {
                None
            };
            Ok(MetricListPage { items, next_cursor })
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
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
        let period_start_str = fmt_datetime(req.period_start);
        let period_end_str = fmt_datetime(req.period_end);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<ConsolidationOutcome, Error> {
            let mut guard = conn.blocking_lock();
            // AV-53 lock acquire (INSERT … ON CONFLICT DO NOTHING).
            let inserted = guard
                .execute(
                    "INSERT INTO cirisgraph_consolidation_locks (\
                        period_start, period_end, tenant_id, locked_by, locked_at\
                     ) VALUES (?1, ?2, ?3, ?4, datetime('now', 'subsec')) \
                     ON CONFLICT (period_start, tenant_id) DO NOTHING",
                    params![
                        period_start_str,
                        period_end_str,
                        req.tenant_id,
                        req.locked_by
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "consolidate_period lock insert"))?;

            let broke_stale_lock = if inserted == 0 {
                // AV-53 stale-lock auto-break.
                let stale_sql = format!(
                    "UPDATE cirisgraph_consolidation_locks SET \
                        locked_by = ?1, locked_at = datetime('now', 'subsec') \
                     WHERE period_start = ?2 AND tenant_id = ?3 \
                       AND locked_at < datetime('now', '-{STALE_LOCK_SECONDS} seconds')"
                );
                let stale = guard
                    .execute(
                        &stale_sql,
                        params![req.locked_by, period_start_str, req.tenant_id],
                    )
                    .map_err(|e| map_sqlite_error(e, "consolidate_period stale-break"))?;
                if stale == 0 {
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
                    period_start = %period_start_str,
                    "consolidate_period (sqlite): broke stale lock (>{STALE_LOCK_SECONDS}s)"
                );
                true
            } else {
                false
            };

            // Rollup transaction.
            let outcome = match run_rollup(&mut guard, &req, &period_start_str, &period_end_str) {
                Ok(o) => o,
                Err(e) => {
                    let _ = guard.execute(
                        "DELETE FROM cirisgraph_consolidation_locks \
                         WHERE period_start = ?1 AND tenant_id = ?2",
                        params![period_start_str, req.tenant_id],
                    );
                    return Err(e);
                }
            };

            // Release lock.
            guard
                .execute(
                    "DELETE FROM cirisgraph_consolidation_locks \
                     WHERE period_start = ?1 AND tenant_id = ?2",
                    params![period_start_str, req.tenant_id],
                )
                .map_err(|e| map_sqlite_error(e, "consolidate_period lock release"))?;

            Ok(ConsolidationOutcome {
                metrics_consolidated: outcome.metrics_consolidated,
                summaries_written: outcome.summaries_written,
                edges_created: outcome.edges_created,
                raw_metrics_deleted: outcome.raw_metrics_deleted,
                ran: true,
                broke_stale_lock,
            })
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
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
        let level_str = level.as_str().to_owned();
        let tenant_owned = tenant_id.to_owned();
        let from_str = fmt_datetime(from);
        let to_str = fmt_datetime(to);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<MetricSummary>, Error> {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(
                    "SELECT attributes FROM cirisgraph_nodes \
                     WHERE node_type = 'tsdb_summary' AND scope = 'ENVIRONMENT' \
                       AND consolidation_level = ?1 \
                       AND json_extract(attributes, '$.tenant_id') = ?2 \
                       AND json_extract(attributes, '$.period_start') >= ?3 \
                       AND json_extract(attributes, '$.period_start') <  ?4 \
                     ORDER BY json_extract(attributes, '$.period_start') ASC, \
                              json_extract(attributes, '$.metric_name') ASC",
                )
                .map_err(|e| map_sqlite_error(e, "query_summaries prepare"))?;
            let rows = stmt
                .query_map(params![level_str, tenant_owned, from_str, to_str], |row| {
                    row.get::<_, String>(0)
                })
                .map_err(|e| map_sqlite_error(e, "query_summaries query"))?;
            let mut out: Vec<MetricSummary> = Vec::new();
            for r in rows {
                let s = r.map_err(|e| map_sqlite_error(e, "query_summaries row"))?;
                let summary: MetricSummary = serde_json::from_str(&s)
                    .map_err(|e| Error::Backend(format!("MetricSummary decode: {e} (raw={s})")))?;
                out.push(summary);
            }
            Ok(out)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn get_summary(
        &self,
        level: ConsolidationLevel,
        tenant_id: &str,
        metric_name: &str,
        period_start: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<MetricSummary>, Error> {
        // V019 invariant: the SQLite consolidation write path
        // truncates period_start to microseconds before building the
        // summary node_id (see `truncate_to_micros` above). Mirror
        // that here so callers can pass an unmodified
        // `chrono::Utc::now()` derivative (which may carry nanoseconds
        // and would otherwise miss the row).
        let period_start = truncate_to_micros(period_start);
        let key = format!(
            "tsdb:{}:{}:{}:{}",
            level.as_str(),
            tenant_id,
            metric_name,
            period_start.to_rfc3339()
        );
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Option<MetricSummary>, Error> {
            let guard = conn.blocking_lock();
            let row_opt = guard
                .query_row(
                    "SELECT attributes FROM cirisgraph_nodes \
                     WHERE node_id = ?1 AND scope = 'ENVIRONMENT' \
                       AND node_type = 'tsdb_summary'",
                    params![key],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_summary"))?;
            let Some(s) = row_opt else { return Ok(None) };
            let summary: MetricSummary = serde_json::from_str(&s)
                .map_err(|e| Error::Backend(format!("MetricSummary decode: {e} (raw={s})")))?;
            Ok(Some(summary))
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn prune_summaries(
        &self,
        level: ConsolidationLevel,
        tenant_id: &str,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, Error> {
        let level_str = level.as_str().to_owned();
        let tenant_owned = tenant_id.to_owned();
        let before_str = fmt_datetime(before);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<u64, Error> {
            let mut guard = conn.blocking_lock();
            let tx = guard
                .transaction()
                .map_err(|e| map_sqlite_error(e, "prune_summaries begin"))?;

            let mut victim_ids: Vec<String> = {
                let mut stmt = tx
                    .prepare(
                        "SELECT node_id FROM cirisgraph_nodes \
                         WHERE node_type = 'tsdb_summary' AND scope = 'ENVIRONMENT' \
                           AND consolidation_level = ?1 \
                           AND json_extract(attributes, '$.tenant_id') = ?2 \
                           AND json_extract(attributes, '$.period_end') < ?3",
                    )
                    .map_err(|e| map_sqlite_error(e, "prune_summaries select prepare"))?;
                let rows = stmt
                    .query_map(params![level_str, tenant_owned, before_str], |row| {
                        row.get::<_, String>(0)
                    })
                    .map_err(|e| map_sqlite_error(e, "prune_summaries select"))?;
                let mut out: Vec<String> = Vec::new();
                for r in rows {
                    out.push(r.map_err(|e| map_sqlite_error(e, "prune_summaries row"))?);
                }
                out
            };
            if victim_ids.is_empty() {
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "prune_summaries commit"))?;
                return Ok(0);
            }

            // Cascade incident edges. SQLite doesn't support ANY()
            // arrays — iterate.
            let mut total_deleted: u64 = 0;
            for vid in victim_ids.drain(..) {
                tx.execute(
                    "DELETE FROM cirisgraph_edges \
                     WHERE scope = 'ENVIRONMENT' \
                       AND (source_node_id = ?1 OR target_node_id = ?1)",
                    params![vid],
                )
                .map_err(|e| map_sqlite_error(e, "prune_summaries cascade edges"))?;
                let deleted = tx
                    .execute(
                        "DELETE FROM cirisgraph_nodes \
                         WHERE node_id = ?1 AND scope = 'ENVIRONMENT'",
                        params![vid],
                    )
                    .map_err(|e| map_sqlite_error(e, "prune_summaries delete node"))?;
                total_deleted += deleted as u64;
            }
            tx.commit()
                .map_err(|e| map_sqlite_error(e, "prune_summaries commit"))?;
            Ok(total_deleted)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
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
        let from_str = fmt_datetime(from);
        let to_str = fmt_datetime(to);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<std::collections::HashMap<String, u64>, Error> {
                let guard = conn.blocking_lock();
                // SQLite cirisgraph_edges.created_at uses the
                // `datetime('now', 'subsec')` default which produces
                // the space-separated form
                // `YYYY-MM-DD HH:MM:SS.sss` — not RFC 3339. A raw
                // lex compare against our RFC-3339-formatted bounds
                // (`YYYY-MM-DDTHH:MM:SS.sss+00:00`) would miss every
                // stored row because ' ' (0x20) < 'T' (0x54) at the
                // T-separator position. Wrap both sides in SQLite's
                // `datetime()` function which canonicalizes both
                // formats to UTC `YYYY-MM-DD HH:MM:SS` for the
                // compare. Defeats index use on `created_at` but the
                // edge table is small and this is observability-tier.
                let mut stmt = guard
                    .prepare(
                        "SELECT relationship, COUNT(*) FROM cirisgraph_edges \
                         WHERE scope = 'ENVIRONMENT' \
                           AND datetime(created_at) >= datetime(?1) \
                           AND datetime(created_at) <  datetime(?2) \
                         GROUP BY relationship",
                    )
                    .map_err(|e| {
                        map_sqlite_error(e, "count_edges_by_relationship_in_window prepare")
                    })?;
                let rows = stmt
                    .query_map(params![from_str, to_str], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })
                    .map_err(|e| {
                        map_sqlite_error(e, "count_edges_by_relationship_in_window query")
                    })?;
                let mut out: std::collections::HashMap<String, u64> =
                    std::collections::HashMap::new();
                for r in rows {
                    let (rel, c) = r.map_err(|e| {
                        map_sqlite_error(e, "count_edges_by_relationship_in_window row")
                    })?;
                    out.insert(rel, c.max(0) as u64);
                }
                Ok(out)
            },
        )
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    // ── v1.6.2 (CIRISPersist#68) typed-summary consolidate methods ──

    async fn consolidate_tasks(
        &self,
        req: ConsolidationRequest,
    ) -> Result<TypedConsolidationOutcome, Error> {
        validate_typed_req(&req)?;
        let period_start_str = fmt_datetime(req.period_start);
        let period_end_str = fmt_datetime(req.period_end);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<TypedConsolidationOutcome, Error> {
            let mut guard = conn.blocking_lock();

            let mut by_status: std::collections::HashMap<String, i64> =
                std::collections::HashMap::new();
            let mut total_tasks: i64 = 0;
            {
                let mut stmt = guard
                    .prepare(
                        "SELECT status, COUNT(*) AS c \
                           FROM cirislens_tasks \
                          WHERE agent_occurrence_id = ?1 \
                            AND created_at >= ?2 AND created_at < ?3 \
                          GROUP BY status",
                    )
                    .map_err(|e| map_sqlite_error(e, "consolidate_tasks histogram prepare"))?;
                let rows = stmt
                    .query_map(
                        params![req.tenant_id, period_start_str, period_end_str],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .map_err(|e| map_sqlite_error(e, "consolidate_tasks histogram query"))?;
                for r in rows {
                    let (s, c) =
                        r.map_err(|e| map_sqlite_error(e, "consolidate_tasks histogram row"))?;
                    total_tasks += c;
                    by_status.insert(s, c);
                }
            }

            // Mean thought_depth — COALESCE to 0.0 so no-thoughts
            // windows still emit a numeric value.
            let mean_thought_depth: f64 = guard
                .query_row(
                    "SELECT COALESCE(AVG(thought_depth), 0.0) AS mean_d \
                       FROM cirislens_thoughts \
                      WHERE agent_occurrence_id = ?1 \
                        AND created_at >= ?2 AND created_at < ?3",
                    params![req.tenant_id, period_start_str, period_end_str],
                    |row| row.get(0),
                )
                .map_err(|e| map_sqlite_error(e, "consolidate_tasks mean depth"))?;

            let summary = TaskSummary {
                tenant_id: req.tenant_id.clone(),
                period_start: truncate_to_micros(req.period_start),
                period_end: truncate_to_micros(req.period_end),
                total_tasks,
                by_status,
                mean_thought_depth,
                consolidation_level: req.level,
            };
            let attrs = serde_json::to_string(&summary)
                .map_err(|e| Error::Internal(format!("TaskSummary serialize: {e}")))?;
            let summary_written = upsert_typed_summary(
                &mut guard,
                "task_summary",
                &req.tenant_id,
                summary.period_start,
                req.level,
                &attrs,
                &req.locked_by,
            )?;
            Ok(TypedConsolidationOutcome {
                summary_written,
                source_rows: total_tasks,
            })
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn consolidate_conversations(
        &self,
        req: ConsolidationRequest,
    ) -> Result<TypedConsolidationOutcome, Error> {
        validate_typed_req(&req)?;
        let period_start_str = fmt_datetime(req.period_start);
        let period_end_str = fmt_datetime(req.period_end);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<TypedConsolidationOutcome, Error> {
            let mut guard = conn.blocking_lock();

            // SQLite stores request_data as TEXT (raw JSON string).
            // `json_extract(request_data, '$.actor_id')` returns the
            // scalar value (or NULL if absent / not JSON). NULLs are
            // already excluded by `COUNT(DISTINCT)` (per SQL spec),
            // so the count matches PG's `request_data->>'actor_id'`.
            let (total_messages, unique_actors): (i64, i64) = guard
                .query_row(
                    "SELECT COUNT(*), \
                            COUNT(DISTINCT json_extract(request_data, '$.actor_id')) \
                       FROM cirislens_service_correlations \
                      WHERE agent_occurrence_id = ?1 \
                        AND timestamp >= ?2 AND timestamp < ?3 \
                        AND lower(action_type) IN \
                            ('speak', 'observe', 'speak_action', 'observe_action')",
                    params![req.tenant_id, period_start_str, period_end_str],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|e| map_sqlite_error(e, "consolidate_conversations aggregate"))?;

            let summary = ConversationSummary {
                tenant_id: req.tenant_id.clone(),
                period_start: truncate_to_micros(req.period_start),
                period_end: truncate_to_micros(req.period_end),
                total_messages,
                unique_actors,
                consolidation_level: req.level,
            };
            let attrs = serde_json::to_string(&summary)
                .map_err(|e| Error::Internal(format!("ConversationSummary serialize: {e}")))?;
            let summary_written = upsert_typed_summary(
                &mut guard,
                "conversation_summary",
                &req.tenant_id,
                summary.period_start,
                req.level,
                &attrs,
                &req.locked_by,
            )?;
            Ok(TypedConsolidationOutcome {
                summary_written,
                source_rows: total_messages,
            })
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn consolidate_traces(
        &self,
        req: ConsolidationRequest,
    ) -> Result<TypedConsolidationOutcome, Error> {
        validate_typed_req(&req)?;
        let period_start_str = fmt_datetime(req.period_start);
        let period_end_str = fmt_datetime(req.period_end);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<TypedConsolidationOutcome, Error> {
            let mut guard = conn.blocking_lock();

            let mut by_action_type: std::collections::HashMap<String, i64> =
                std::collections::HashMap::new();
            let mut total_traces: i64 = 0;
            {
                let mut stmt = guard
                    .prepare(
                        "SELECT action_type, COUNT(*) AS c \
                           FROM cirislens_service_correlations \
                          WHERE agent_occurrence_id = ?1 \
                            AND correlation_type = 'trace' \
                            AND timestamp >= ?2 AND timestamp < ?3 \
                          GROUP BY action_type",
                    )
                    .map_err(|e| map_sqlite_error(e, "consolidate_traces histogram prepare"))?;
                let rows = stmt
                    .query_map(
                        params![req.tenant_id, period_start_str, period_end_str],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .map_err(|e| map_sqlite_error(e, "consolidate_traces histogram query"))?;
                for r in rows {
                    let (a, c) =
                        r.map_err(|e| map_sqlite_error(e, "consolidate_traces histogram row"))?;
                    total_traces += c;
                    by_action_type.insert(a, c);
                }
            }

            let summary = TraceSummary {
                tenant_id: req.tenant_id.clone(),
                period_start: truncate_to_micros(req.period_start),
                period_end: truncate_to_micros(req.period_end),
                total_traces,
                by_action_type,
                consolidation_level: req.level,
            };
            let attrs = serde_json::to_string(&summary)
                .map_err(|e| Error::Internal(format!("TraceSummary serialize: {e}")))?;
            let summary_written = upsert_typed_summary(
                &mut guard,
                "trace_summary",
                &req.tenant_id,
                summary.period_start,
                req.level,
                &attrs,
                &req.locked_by,
            )?;
            Ok(TypedConsolidationOutcome {
                summary_written,
                source_rows: total_traces,
            })
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn consolidate_audit(
        &self,
        req: ConsolidationRequest,
    ) -> Result<TypedConsolidationOutcome, Error> {
        validate_typed_req(&req)?;
        let period_start_str = fmt_datetime(req.period_start);
        let period_end_str = fmt_datetime(req.period_end);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<TypedConsolidationOutcome, Error> {
            let mut guard = conn.blocking_lock();

            // V014 audit_log: tenant_id column (not occurrence proxy)
            // + recorded_at (not created_at).
            let mut by_action_type: std::collections::HashMap<String, i64> =
                std::collections::HashMap::new();
            let mut total_events: i64 = 0;
            {
                let mut stmt = guard
                    .prepare(
                        "SELECT action_type, COUNT(*) AS c \
                           FROM cirislens_audit_log \
                          WHERE tenant_id = ?1 \
                            AND recorded_at >= ?2 AND recorded_at < ?3 \
                          GROUP BY action_type",
                    )
                    .map_err(|e| map_sqlite_error(e, "consolidate_audit histogram prepare"))?;
                let rows = stmt
                    .query_map(
                        params![req.tenant_id, period_start_str, period_end_str],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
                    )
                    .map_err(|e| map_sqlite_error(e, "consolidate_audit histogram query"))?;
                for r in rows {
                    let (a, c) =
                        r.map_err(|e| map_sqlite_error(e, "consolidate_audit histogram row"))?;
                    total_events += c;
                    by_action_type.insert(a, c);
                }
            }

            let unique_actors: i64 = guard
                .query_row(
                    "SELECT COUNT(DISTINCT actor_id) \
                       FROM cirislens_audit_log \
                      WHERE tenant_id = ?1 \
                        AND recorded_at >= ?2 AND recorded_at < ?3",
                    params![req.tenant_id, period_start_str, period_end_str],
                    |row| row.get(0),
                )
                .map_err(|e| map_sqlite_error(e, "consolidate_audit unique_actors"))?;

            let summary = AuditSummary {
                tenant_id: req.tenant_id.clone(),
                period_start: truncate_to_micros(req.period_start),
                period_end: truncate_to_micros(req.period_end),
                total_events,
                by_action_type,
                unique_actors,
                consolidation_level: req.level,
            };
            let attrs = serde_json::to_string(&summary)
                .map_err(|e| Error::Internal(format!("AuditSummary serialize: {e}")))?;
            let summary_written = upsert_typed_summary(
                &mut guard,
                "audit_summary",
                &req.tenant_id,
                summary.period_start,
                req.level,
                &attrs,
                &req.locked_by,
            )?;
            Ok(TypedConsolidationOutcome {
                summary_written,
                source_rows: total_events,
            })
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn query_summary_nodes(
        &self,
        node_type: &str,
        level: ConsolidationLevel,
        tenant_id: &str,
        from: chrono::DateTime<chrono::Utc>,
        to: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<serde_json::Value>, Error> {
        validate_summary_node_type(node_type)?;
        if from >= to {
            return Err(Error::InvalidArgument(format!(
                "from ({from}) must be < to ({to})"
            )));
        }
        let node_type_owned = node_type.to_owned();
        let level_str = level.as_str().to_owned();
        let tenant_owned = tenant_id.to_owned();
        // V019 invariant: the SQLite consolidation write path
        // truncates period_start to microseconds (matches the
        // metric-summary path's `truncate_to_micros` discipline).
        // Mirror that bound here so a caller passing nanosecond-
        // precision boundaries still includes rows stored with
        // microsecond precision.
        let from_str = fmt_datetime(truncate_to_micros(from));
        let to_str = fmt_datetime(truncate_to_micros(to));
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<serde_json::Value>, Error> {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(
                    "SELECT attributes FROM cirisgraph_nodes \
                     WHERE node_type = ?1 AND scope = 'ENVIRONMENT' \
                       AND consolidation_level = ?2 \
                       AND json_extract(attributes, '$.tenant_id') = ?3 \
                       AND json_extract(attributes, '$.period_start') >= ?4 \
                       AND json_extract(attributes, '$.period_start') <  ?5 \
                     ORDER BY json_extract(attributes, '$.period_start') ASC",
                )
                .map_err(|e| map_sqlite_error(e, "query_summary_nodes prepare"))?;
            let rows = stmt
                .query_map(
                    params![node_type_owned, level_str, tenant_owned, from_str, to_str],
                    |row| row.get::<_, String>(0),
                )
                .map_err(|e| map_sqlite_error(e, "query_summary_nodes query"))?;
            let mut out: Vec<serde_json::Value> = Vec::new();
            for r in rows {
                let s = r.map_err(|e| map_sqlite_error(e, "query_summary_nodes row"))?;
                let v: serde_json::Value = serde_json::from_str(&s)
                    .map_err(|e| Error::Backend(format!("attributes decode: {e} (raw={s})")))?;
                out.push(v);
            }
            Ok(out)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }
}

/// Validate `ConsolidationRequest` fields shared across the four
/// typed-summary consolidate methods. No lock acquisition in v1.6.2.
fn validate_typed_req(req: &ConsolidationRequest) -> Result<(), Error> {
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
    Ok(())
}

fn validate_summary_node_type(node_type: &str) -> Result<(), Error> {
    match node_type {
        "task_summary" | "conversation_summary" | "trace_summary" | "audit_summary" => Ok(()),
        _ => Err(Error::InvalidArgument(format!(
            "unknown summary node_type: {node_type}"
        ))),
    }
}

fn typed_summary_node_id(
    node_type: &str,
    tenant_id: &str,
    period_start: chrono::DateTime<chrono::Utc>,
) -> String {
    format!(
        "tsdb:{}:{}:{}",
        node_type,
        tenant_id,
        period_start.to_rfc3339()
    )
}

/// UPSERT one typed-summary node into `cirisgraph_nodes`. Returns
/// `true` on affected ≥1.
fn upsert_typed_summary(
    conn: &mut Connection,
    node_type: &str,
    tenant_id: &str,
    period_start: chrono::DateTime<chrono::Utc>,
    level: ConsolidationLevel,
    attributes_str: &str,
    locked_by: &str,
) -> Result<bool, Error> {
    let node_id = typed_summary_node_id(node_type, tenant_id, period_start);
    let current_version: Option<i32> = conn
        .query_row(
            "SELECT version FROM cirisgraph_nodes \
             WHERE node_id = ?1 AND scope = 'ENVIRONMENT'",
            params![node_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| map_sqlite_error(e, "typed upsert read version"))?;
    let expected_version = current_version.unwrap_or(0);
    let row_hash = format!("{node_type}_v1.6.2");
    let now_str = fmt_datetime(chrono::Utc::now());
    let affected = conn
        .execute(
            "INSERT INTO cirisgraph_nodes (\
                node_id, scope, node_type, attributes, version, \
                updated_by, updated_at, persist_row_hash, consolidation_level\
             ) VALUES (?1, 'ENVIRONMENT', ?8, ?2, 1, ?3, ?4, ?5, ?7) \
             ON CONFLICT (node_id, scope) DO UPDATE SET \
                attributes = excluded.attributes, \
                version = cirisgraph_nodes.version + 1, \
                updated_by = excluded.updated_by, \
                updated_at = excluded.updated_at, \
                consolidation_level = excluded.consolidation_level \
             WHERE cirisgraph_nodes.version = ?6",
            params![
                node_id,
                attributes_str,
                locked_by,
                now_str,
                row_hash,
                expected_version,
                level.as_str(),
                node_type,
            ],
        )
        .map_err(|e| map_sqlite_error(e, "typed upsert"))?;
    Ok(affected > 0)
}

struct AggRow {
    metric_name: String,
    sum_v: f64,
    min_v: f64,
    max_v: f64,
    avg_v: f64,
    count_v: i64,
    unique_labels: i64,
}

fn aggregate_basic_from_raw(
    conn: &Connection,
    req: &ConsolidationRequest,
    period_start_str: &str,
    period_end_str: &str,
) -> Result<Vec<AggRow>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT metric_name, \
                    SUM(value)              AS sum_v, \
                    MIN(value)              AS min_v, \
                    MAX(value)              AS max_v, \
                    AVG(value)              AS avg_v, \
                    COUNT(*)                AS count_v, \
                    COUNT(DISTINCT labels)  AS unique_labels \
             FROM cirisgraph_telemetry_metrics \
             WHERE tenant_id = ?1 \
               AND observed_at >= ?2 AND observed_at < ?3 \
             GROUP BY metric_name",
        )
        .map_err(|e| map_sqlite_error(e, "rollup aggregate prepare"))?;
    let rows: Vec<AggRow> = stmt
        .query_map(
            params![req.tenant_id, period_start_str, period_end_str],
            |row| {
                Ok(AggRow {
                    metric_name: row.get(0)?,
                    sum_v: row.get(1)?,
                    min_v: row.get(2)?,
                    max_v: row.get(3)?,
                    avg_v: row.get(4)?,
                    count_v: row.get(5)?,
                    unique_labels: row.get(6)?,
                })
            },
        )
        .map_err(|e| map_sqlite_error(e, "rollup aggregate query"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| map_sqlite_error(e, "rollup aggregate collect"))?;
    Ok(rows)
}

/// Higher-tier rollup: read prior-tier summary rows from
/// `cirisgraph_nodes` (filtered by `consolidation_level`) and
/// aggregate them per metric_name. SQLite stores summary attributes
/// as TEXT, so numeric fields come back via json_extract as REAL/INT.
fn aggregate_higher_tier(
    conn: &Connection,
    req: &ConsolidationRequest,
    period_start_str: &str,
    period_end_str: &str,
    input_tier: ConsolidationLevel,
) -> Result<Vec<AggRow>, Error> {
    let mut stmt = conn
        .prepare(
            "SELECT json_extract(attributes, '$.metric_name')                     AS metric_name, \
                    SUM(CAST(json_extract(attributes, '$.sum') AS REAL))           AS sum_v, \
                    MIN(CAST(json_extract(attributes, '$.min') AS REAL))           AS min_v, \
                    MAX(CAST(json_extract(attributes, '$.max') AS REAL))           AS max_v, \
                    SUM(CAST(json_extract(attributes, '$.count') AS INTEGER))      AS count_v, \
                    SUM(CAST(json_extract(attributes, '$.unique_label_combinations') AS INTEGER)) AS unique_labels \
             FROM cirisgraph_nodes \
             WHERE node_type = 'tsdb_summary' AND scope = 'ENVIRONMENT' \
               AND consolidation_level = ?1 \
               AND json_extract(attributes, '$.tenant_id') = ?2 \
               AND json_extract(attributes, '$.period_start') >= ?3 \
               AND json_extract(attributes, '$.period_end')   <= ?4 \
             GROUP BY json_extract(attributes, '$.metric_name')",
        )
        .map_err(|e| map_sqlite_error(e, "rollup higher tier prepare"))?;
    let rows: Vec<AggRow> = stmt
        .query_map(
            params![
                input_tier.as_str(),
                req.tenant_id,
                period_start_str,
                period_end_str,
            ],
            |row| {
                // SELECT: 0=metric_name, 1=sum_v, 2=min_v, 3=max_v,
                //         4=count_v, 5=unique_labels. avg is derived.
                let count_v: i64 = row.get(4)?;
                let sum_v: f64 = row.get(1)?;
                let avg_v = if count_v > 0 {
                    sum_v / count_v as f64
                } else {
                    0.0
                };
                Ok(AggRow {
                    metric_name: row.get(0)?,
                    sum_v,
                    min_v: row.get(2)?,
                    max_v: row.get(3)?,
                    avg_v,
                    count_v,
                    unique_labels: row.get(5)?,
                })
            },
        )
        .map_err(|e| map_sqlite_error(e, "rollup higher tier query"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| map_sqlite_error(e, "rollup higher tier collect"))?;
    Ok(rows)
}

fn run_rollup(
    conn: &mut Connection,
    req: &ConsolidationRequest,
    period_start_str: &str,
    period_end_str: &str,
) -> Result<ConsolidationOutcome, Error> {
    // 1. Aggregate by metric_name — source depends on tier.
    //    Basic = raw observations; higher tiers = prior-tier summaries.
    //    SQLite's COUNT(DISTINCT) on TEXT works directly for the basic
    //    path — labels is canonical-JSON string, so identical labels
    //    share the same string.
    let rows: Vec<AggRow> = match req.level.input_tier() {
        None => aggregate_basic_from_raw(conn, req, period_start_str, period_end_str)?,
        Some(input_tier) => {
            aggregate_higher_tier(conn, req, period_start_str, period_end_str, input_tier)?
        }
    };

    let metrics_consolidated: i64 = rows.iter().map(|r| r.count_v).sum();
    let mut summaries_written: i64 = 0;
    let mut edges_created: i64 = 0;

    let now_str = fmt_datetime(chrono::Utc::now());

    // Truncate timestamps to microsecond precision before serializing
    // into attributes JSON. SQLite stores attributes as TEXT and the
    // prior-period probe compares them lexicographically — micros-vs-
    // nanos precision mismatch in chrono's default serde RFC 3339
    // output would otherwise make a nano-precision stored string
    // sort BELOW a micros-precision query bound at the same logical
    // instant (because '7' < 'Z' at the precision-suffix position),
    // producing false-positive "prior period exists" matches within
    // the same period.
    let period_start_micros = truncate_to_micros(req.period_start);
    let period_end_micros = truncate_to_micros(req.period_end);

    for agg in &rows {
        let summary = MetricSummary {
            metric_name: agg.metric_name.clone(),
            tenant_id: req.tenant_id.clone(),
            period_start: period_start_micros,
            period_end: period_end_micros,
            sum: agg.sum_v,
            min: agg.min_v,
            max: agg.max_v,
            avg: agg.avg_v,
            count: agg.count_v,
            unique_label_combinations: agg.unique_labels,
            consolidation_level: req.level,
        };
        let summary_node_id = summary_node_id(&summary);
        let attributes_str = serde_json::to_string(&summary)
            .map_err(|e| Error::Internal(format!("summary serialize: {e}")))?;

        // Read current version (if any).
        let current_version: Option<i32> = conn
            .query_row(
                "SELECT version FROM cirisgraph_nodes \
                 WHERE node_id = ?1 AND scope = 'ENVIRONMENT'",
                params![summary_node_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| map_sqlite_error(e, "rollup read summary version"))?;
        let expected_version = current_version.unwrap_or(0);

        // UPSERT — same shape as cirisgraph sqlite::upsert_node.
        // V019: consolidation_level is a real column.
        let affected = conn
            .execute(
                "INSERT INTO cirisgraph_nodes (\
                    node_id, scope, node_type, attributes, version, \
                    updated_by, updated_at, persist_row_hash, consolidation_level\
                 ) VALUES (?1, 'ENVIRONMENT', 'tsdb_summary', ?2, 1, ?3, ?4, ?5, ?7) \
                 ON CONFLICT (node_id, scope) DO UPDATE SET \
                    attributes = excluded.attributes, \
                    version = cirisgraph_nodes.version + 1, \
                    updated_by = excluded.updated_by, \
                    updated_at = excluded.updated_at, \
                    consolidation_level = excluded.consolidation_level \
                 WHERE cirisgraph_nodes.version = ?6",
                params![
                    summary_node_id,
                    attributes_str,
                    req.locked_by,
                    now_str,
                    "tsdb_summary_v0.8.6",
                    expected_version,
                    req.level.as_str(),
                ],
            )
            .map_err(|e| map_sqlite_error(e, "rollup upsert summary node"))?;
        if affected > 0 {
            summaries_written += 1;
        }

        // AV-54: prior period's summary → TEMPORAL_NEXT edge.
        // SQLite json_extract on attributes for the predicate.
        // Chain stays tier-local (basic→basic, daily→daily, …) per
        // CIRISAgent#756 Q7.
        let prior_node_id_opt: Option<String> = conn
            .query_row(
                "SELECT node_id FROM cirisgraph_nodes \
                 WHERE node_type = 'tsdb_summary' AND scope = 'ENVIRONMENT' \
                   AND consolidation_level = ?4 \
                   AND json_extract(attributes, '$.metric_name') = ?1 \
                   AND json_extract(attributes, '$.tenant_id')   = ?2 \
                   AND json_extract(attributes, '$.period_start') < ?3 \
                 ORDER BY json_extract(attributes, '$.period_start') DESC \
                 LIMIT 1",
                params![
                    agg.metric_name,
                    req.tenant_id,
                    period_start_str,
                    req.level.as_str()
                ],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|e| map_sqlite_error(e, "rollup find prior summary"))?;

        if let Some(prior_node_id) = prior_node_id_opt {
            let edge_attrs = serde_json::json!({
                "metric_name": agg.metric_name,
                "tenant_id": req.tenant_id,
                "period_start": period_start_str,
            })
            .to_string();
            let edge_id = uuid::Uuid::new_v4().to_string();
            conn.execute(
                "INSERT INTO cirisgraph_edges (\
                    edge_id, source_node_id, target_node_id, scope, \
                    relationship, weight, attributes\
                 ) VALUES (?1, ?2, ?3, 'ENVIRONMENT', 'TEMPORAL_NEXT', NULL, ?4) \
                 ON CONFLICT (edge_id) DO NOTHING",
                params![edge_id, prior_node_id, summary_node_id, edge_attrs],
            )
            .map_err(|e| map_sqlite_error(e, "rollup write TEMPORAL_NEXT"))?;
            edges_created += 1;
        }
    }

    // Only the Basic tier touches the raw observations table.
    // Higher tiers aggregate prior-tier summaries; raw rows are
    // already gone by the time those run.
    let raw_metrics_deleted = if matches!(req.level, ConsolidationLevel::Basic) {
        conn.execute(
            "DELETE FROM cirisgraph_telemetry_metrics \
             WHERE tenant_id = ?1 \
               AND observed_at >= ?2 AND observed_at < ?3",
            params![req.tenant_id, period_start_str, period_end_str],
        )
        .map_err(|e| map_sqlite_error(e, "rollup delete raw"))?
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

fn summary_node_id(summary: &MetricSummary) -> String {
    // V019: tier prefix prevents collisions between basic/daily/
    // weekly/monthly summaries for the same (tenant, metric, period).
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
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use chrono::Duration;

    async fn fresh_backend() -> (SqliteBackend, SqliteTelemetryBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let tlm = SqliteTelemetryBackend::new(backend.conn_handle());
        (backend, tlm)
    }

    fn obs(
        name: &str,
        tenant: &str,
        value: f64,
        when: chrono::DateTime<chrono::Utc>,
    ) -> MetricObservation {
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

    /// v0.8.6 SQLite parity: full lifecycle mirroring v0.8.2 Postgres
    /// (record × N → list → consolidate → idempotent re-run → period
    /// B with TEMPORAL_NEXT → AV-52 oversized reject → AV-53 lock
    /// contention).
    #[tokio::test]
    async fn telemetry_sqlite_round_trip_full_lifecycle() {
        let (_b, tlm) = fresh_backend().await;
        let tenant = format!("tlm-{}", uuid::Uuid::new_v4().simple());
        let period_a_start = chrono::Utc::now() - Duration::hours(12);
        let period_a_end = period_a_start + Duration::hours(6);
        let period_b_start = period_a_end;
        let period_b_end = period_b_start + Duration::hours(6);

        // 1. Bulk record.
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
        let n = tlm.record_metrics_batch(&batch_a).await.unwrap();
        assert_eq!(n, 6);

        // 2. Single record.
        tlm.record_metric(obs("agent.heartbeat", &tenant, 1.0, period_a_start))
            .await
            .unwrap();

        // 3. AV-52 oversized labels.
        let big = MetricObservation {
            metric_id: None,
            metric_name: "test.oversized".into(),
            tenant_id: tenant.clone(),
            value: 1.0,
            labels: serde_json::json!({"big": "x".repeat(8 * 1024)}),
            observed_at: chrono::Utc::now(),
            expires_at: None,
        };
        let err = tlm.record_metric(big).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));

        // 4. list_metrics.
        let page = tlm
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

        // 5. Empty-tenant reject.
        let no_tenant = tlm
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
        let out_a = tlm
            .consolidate_period(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start: period_a_start,
                period_end: period_a_end,
                locked_by: "test-worker-1".into(),
                level: ConsolidationLevel::Basic,
            })
            .await
            .unwrap();
        assert!(out_a.ran);
        assert_eq!(out_a.metrics_consolidated, 7);
        assert_eq!(out_a.summaries_written, 3);
        assert_eq!(out_a.edges_created, 0);
        assert_eq!(out_a.raw_metrics_deleted, 7);

        // 7. Idempotent re-run (zero work).
        let out_a2 = tlm
            .consolidate_period(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start: period_a_start,
                period_end: period_a_end,
                locked_by: "test-worker-1".into(),
                level: ConsolidationLevel::Basic,
            })
            .await
            .unwrap();
        assert!(out_a2.ran);
        assert_eq!(out_a2.metrics_consolidated, 0);
        assert_eq!(out_a2.raw_metrics_deleted, 0);

        // 8. Period B with TEMPORAL_NEXT.
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
        tlm.record_metrics_batch(&batch_b).await.unwrap();
        let out_b = tlm
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
        assert_eq!(out_b.edges_created, 2);
    }

    /// AV-53 lock contention: planted-lock blocks new acquirer.
    #[tokio::test]
    async fn telemetry_sqlite_lock_contention_returns_ran_false() {
        let (b, tlm) = fresh_backend().await;
        let tenant = format!("lock-{}", uuid::Uuid::new_v4().simple());
        let period_start = chrono::Utc::now() - Duration::hours(6);
        let period_end = period_start + Duration::hours(6);

        // Plant a fresh lock.
        let conn = b.conn_handle();
        let guard = conn.lock().await;
        guard
            .execute(
                "INSERT INTO cirisgraph_consolidation_locks \
                 (period_start, period_end, tenant_id, locked_by, locked_at) \
                 VALUES (?1, ?2, ?3, 'planted-worker', datetime('now', 'subsec'))",
                params![
                    fmt_datetime(period_start),
                    fmt_datetime(period_end),
                    &tenant
                ],
            )
            .unwrap();
        drop(guard);

        let outcome = tlm
            .consolidate_period(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start,
                period_end,
                locked_by: "test-blocked-worker".into(),
                level: ConsolidationLevel::Basic,
            })
            .await
            .unwrap();
        assert!(!outcome.ran);
        assert!(!outcome.broke_stale_lock);
    }

    /// v1.0.0 (CIRISAgent#756 Q7) — Basic-tier single-window sanity:
    /// 4 raw observations across a 6h window produce one MetricSummary
    /// with level=Basic, count=4. Asserts the consolidation_level
    /// column lands on the underlying node row too.
    #[tokio::test]
    async fn telemetry_sqlite_basic_tier_writes_level_column() {
        let (b, tlm) = fresh_backend().await;
        let tenant = format!("tier-{}", uuid::Uuid::new_v4().simple());
        let p_start = chrono::Utc::now() - Duration::hours(12);
        let p_end = p_start + Duration::hours(6);

        let batch = (0..4)
            .map(|i| {
                obs(
                    "qps",
                    &tenant,
                    (i as f64 + 1.0) * 10.0,
                    p_start + Duration::minutes(i as i64 * 30),
                )
            })
            .collect::<Vec<_>>();
        tlm.record_metrics_batch(&batch).await.unwrap();

        let out = tlm
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
        assert_eq!(out.metrics_consolidated, 4);
        assert_eq!(out.raw_metrics_deleted, 4);

        // Verify the column landed.
        let conn = b.conn_handle();
        let guard = conn.lock().await;
        let (lvl, attrs_str): (String, String) = guard
            .query_row(
                "SELECT consolidation_level, attributes FROM cirisgraph_nodes \
                 WHERE node_type = 'tsdb_summary' \
                   AND json_extract(attributes, '$.tenant_id') = ?1 \
                   AND json_extract(attributes, '$.metric_name') = 'qps'",
                params![tenant],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(lvl, "basic");
        let attrs: serde_json::Value = serde_json::from_str(&attrs_str).unwrap();
        assert_eq!(attrs["consolidation_level"], "basic");
        assert_eq!(attrs["count"].as_i64(), Some(4));
    }

    /// v1.0.0 (CIRISAgent#756 Q7) — Daily-tier rollup: 4 basic-tier
    /// 6h summaries spanning a day → one daily-tier summary per
    /// metric. Sum/count/min/max math is asserted; raw table is NOT
    /// touched by the daily pass.
    #[tokio::test]
    async fn telemetry_sqlite_daily_tier_rolls_up_basic() {
        let (b, tlm) = fresh_backend().await;
        let tenant = format!("tier-{}", uuid::Uuid::new_v4().simple());
        let day_start = chrono::Utc::now() - Duration::days(2);
        let day_end = day_start + Duration::hours(24);

        // 4 basic-tier 6h windows fill the day; 3 raw obs each.
        for i in 0..4 {
            let p_start = day_start + Duration::hours(i * 6);
            let p_end = p_start + Duration::hours(6);
            let batch = vec![
                obs("rpm", &tenant, 10.0, p_start),
                obs("rpm", &tenant, 20.0, p_start + Duration::minutes(60)),
                obs("rpm", &tenant, 30.0, p_start + Duration::minutes(120)),
            ];
            tlm.record_metrics_batch(&batch).await.unwrap();
            let out = tlm
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

        // Roll up to daily.
        let out_daily = tlm
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
        assert_eq!(out_daily.summaries_written, 1);
        assert_eq!(
            out_daily.metrics_consolidated, 12,
            "4 basic summaries × 3 raw obs each = 12 total count"
        );
        assert_eq!(
            out_daily.raw_metrics_deleted, 0,
            "higher tiers don't touch the raw table"
        );

        // Verify the daily row.
        let conn = b.conn_handle();
        let guard = conn.lock().await;
        let (lvl, attrs_str): (String, String) = guard
            .query_row(
                "SELECT consolidation_level, attributes FROM cirisgraph_nodes \
                 WHERE node_type = 'tsdb_summary' \
                   AND consolidation_level = 'daily' \
                   AND json_extract(attributes, '$.tenant_id') = ?1 \
                   AND json_extract(attributes, '$.metric_name') = 'rpm'",
                params![tenant],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(lvl, "daily");
        let attrs: serde_json::Value = serde_json::from_str(&attrs_str).unwrap();
        assert_eq!(attrs["consolidation_level"], "daily");
        assert_eq!(attrs["count"].as_i64(), Some(12));
        assert_eq!(attrs["sum"].as_f64(), Some(240.0)); // (10+20+30)*4
        assert_eq!(attrs["min"].as_f64(), Some(10.0));
        assert_eq!(attrs["max"].as_f64(), Some(30.0));
        assert_eq!(attrs["avg"].as_f64(), Some(20.0));
    }

    // ── v1.6.0 (CIRISPersist#63) TSDB query / prune tests ──────────

    /// Roll up 2 metrics → query_summaries returns both ordered by
    /// `(period_start ASC, metric_name ASC)`.
    #[tokio::test]
    async fn tsdb_query_summaries_returns_consolidated_rows() {
        let (_b, tlm) = fresh_backend().await;
        let tenant = format!("tlm-{}", uuid::Uuid::new_v4().simple());
        let now = chrono::Utc::now();
        let period_start = now - Duration::hours(6);
        let period_end = now;

        for i in 0..3 {
            tlm.record_metric(obs(
                "metric_a",
                &tenant,
                10.0 * (i as f64 + 1.0),
                period_start + Duration::minutes(i as i64 * 10),
            ))
            .await
            .unwrap();
            tlm.record_metric(obs(
                "metric_b",
                &tenant,
                5.0 * (i as f64 + 1.0),
                period_start + Duration::minutes(i as i64 * 10),
            ))
            .await
            .unwrap();
        }

        tlm.consolidate_period(ConsolidationRequest {
            tenant_id: tenant.clone(),
            period_start,
            period_end,
            locked_by: "worker".into(),
            level: ConsolidationLevel::Basic,
        })
        .await
        .unwrap();

        let rows = tlm
            .query_summaries(
                ConsolidationLevel::Basic,
                &tenant,
                period_start - Duration::hours(1),
                period_end + Duration::hours(1),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        // Sorted by metric_name ASC for the same period_start.
        assert_eq!(rows[0].metric_name, "metric_a");
        assert_eq!(rows[1].metric_name, "metric_b");
        assert_eq!(rows[0].count, 3);
        assert_eq!(rows[0].sum, 60.0); // 10+20+30
        assert_eq!(rows[0].consolidation_level, ConsolidationLevel::Basic);
    }

    #[tokio::test]
    async fn tsdb_query_summaries_invalid_window_rejected() {
        let (_b, tlm) = fresh_backend().await;
        let now = chrono::Utc::now();
        let err = tlm
            .query_summaries(ConsolidationLevel::Basic, "t", now, now)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn tsdb_get_summary_round_trips_one_row() {
        let (_b, tlm) = fresh_backend().await;
        let tenant = format!("tlm-{}", uuid::Uuid::new_v4().simple());
        let now = chrono::Utc::now();
        let period_start = now - Duration::hours(6);
        let period_end = now;
        for i in 0..2 {
            tlm.record_metric(obs(
                "single_metric",
                &tenant,
                7.0 * (i as f64 + 1.0),
                period_start + Duration::minutes(i as i64 * 10),
            ))
            .await
            .unwrap();
        }
        tlm.consolidate_period(ConsolidationRequest {
            tenant_id: tenant.clone(),
            period_start,
            period_end,
            locked_by: "w".into(),
            level: ConsolidationLevel::Basic,
        })
        .await
        .unwrap();

        let got = tlm
            .get_summary(
                ConsolidationLevel::Basic,
                &tenant,
                "single_metric",
                period_start,
            )
            .await
            .unwrap()
            .expect("summary present");
        assert_eq!(got.metric_name, "single_metric");
        assert_eq!(got.count, 2);
        assert_eq!(got.sum, 21.0);

        let missing = tlm
            .get_summary(
                ConsolidationLevel::Basic,
                &tenant,
                "absent_metric",
                period_start,
            )
            .await
            .unwrap();
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn tsdb_prune_summaries_removes_old_with_cascade() {
        let (_b, tlm) = fresh_backend().await;
        let tenant = format!("tlm-{}", uuid::Uuid::new_v4().simple());
        let now = chrono::Utc::now();

        // 3 periods at -18h, -12h, -6h.
        let starts: Vec<_> = (1..=3).map(|i| now - Duration::hours(6 * i)).collect();
        for start in &starts {
            tlm.record_metric(obs("rpm", &tenant, 1.0, *start))
                .await
                .unwrap();
            tlm.consolidate_period(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start: *start,
                period_end: *start + Duration::hours(6),
                locked_by: "w".into(),
                level: ConsolidationLevel::Basic,
            })
            .await
            .unwrap();
        }

        // Prune before -10h cutoff. period_end values are 0h, -6h,
        // -12h for the -6h/-12h/-18h period_starts respectively. Only
        // -12h period_end < -10h (the -18h-start period); the others'
        // period_end is more recent than the cutoff.
        let cutoff = now - Duration::hours(10);
        let deleted = tlm
            .prune_summaries(ConsolidationLevel::Basic, &tenant, cutoff)
            .await
            .unwrap();
        assert_eq!(deleted, 1, "only the -18h period was pruned");

        // Remaining: the -6h and -12h period_start rows.
        let rows = tlm
            .query_summaries(
                ConsolidationLevel::Basic,
                &tenant,
                now - Duration::hours(72),
                now + Duration::hours(1),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
    }

    // ── v1.6.2 (CIRISPersist#68) typed-summary consolidate tests ────

    fn seed_task(
        conn: &Connection,
        task_id: &str,
        tenant: &str,
        status: &str,
        when: chrono::DateTime<chrono::Utc>,
    ) {
        let when_str = fmt_datetime(when);
        conn.execute(
            "INSERT INTO cirislens_tasks (\
                task_id, channel_id, description, status, priority, \
                created_at, updated_at, agent_occurrence_id\
             ) VALUES (?1, 'chan', 'desc', ?2, 0, ?3, ?3, ?4)",
            params![task_id, status, when_str, tenant],
        )
        .unwrap();
    }

    fn seed_thought(
        conn: &Connection,
        thought_id: &str,
        source_task_id: &str,
        tenant: &str,
        depth: i64,
        when: chrono::DateTime<chrono::Utc>,
    ) {
        let when_str = fmt_datetime(when);
        conn.execute(
            "INSERT INTO cirislens_thoughts (\
                thought_id, source_task_id, status, created_at, updated_at, \
                content, thought_depth, agent_occurrence_id\
             ) VALUES (?1, ?2, 'completed', ?3, ?3, 'c', ?4, ?5)",
            params![thought_id, source_task_id, when_str, depth, tenant],
        )
        .unwrap();
    }

    fn seed_correlation(
        conn: &Connection,
        correlation_id: &str,
        tenant: &str,
        action_type: &str,
        correlation_type: &str,
        request_data: Option<&str>,
        when: chrono::DateTime<chrono::Utc>,
    ) {
        let when_str = fmt_datetime(when);
        conn.execute(
            "INSERT INTO cirislens_service_correlations (\
                correlation_id, service_type, handler_name, action_type, \
                request_data, status, created_at, updated_at, \
                correlation_type, timestamp, retention_policy, \
                agent_occurrence_id\
             ) VALUES (?1, 'svc', 'h', ?2, ?3, 'completed', ?4, ?4, \
                       ?5, ?4, 'raw', ?6)",
            params![
                correlation_id,
                action_type,
                request_data,
                when_str,
                correlation_type,
                tenant,
            ],
        )
        .unwrap();
    }

    fn seed_audit(
        conn: &Connection,
        entry_id: &str,
        sequence_number: i64,
        tenant: &str,
        actor_id: &str,
        action_type: &str,
        when: chrono::DateTime<chrono::Utc>,
    ) {
        let when_str = fmt_datetime(when);
        // sha256 prev_hash zero-sentinel; entry_hash unique placeholder.
        let prev: [u8; 32] = [0; 32];
        let entry: Vec<u8> = (0..32)
            .map(|i: u8| i.wrapping_add(sequence_number as u8))
            .collect();
        conn.execute(
            "INSERT INTO cirislens_audit_log (\
                entry_id, sequence_number, tenant_id, actor_id, action_type, \
                subject_kind, subject_id, payload, prev_hash, entry_hash, \
                recorded_at, signature, signing_key_id, signature_verified, \
                persist_row_hash\
             ) VALUES (?1, ?2, ?3, ?4, ?5, 'task', 'sub', '{}', ?6, ?7, ?8, \
                       'sig', 'k', 0, 'rh')",
            params![
                entry_id,
                sequence_number,
                tenant,
                actor_id,
                action_type,
                prev.as_slice(),
                entry.as_slice(),
                when_str,
            ],
        )
        .unwrap();
    }

    /// TaskSummary happy path: 3 tasks + 2 thoughts in window →
    /// status histogram + mean_thought_depth, summary node landed.
    #[tokio::test]
    async fn tsdb_consolidate_tasks_writes_task_summary() {
        let (b, tlm) = fresh_backend().await;
        let tenant = format!("task-{}", uuid::Uuid::new_v4().simple());
        let period_start = chrono::Utc::now() - Duration::hours(6);
        let period_end = period_start + Duration::hours(6);

        {
            let conn = b.conn_handle();
            let guard = conn.lock().await;
            seed_task(&guard, "t1", &tenant, "completed", period_start);
            seed_task(
                &guard,
                "t2",
                &tenant,
                "completed",
                period_start + Duration::minutes(10),
            );
            seed_task(
                &guard,
                "t3",
                &tenant,
                "failed",
                period_start + Duration::minutes(20),
            );
            seed_thought(&guard, "th1", "t1", &tenant, 1, period_start);
            seed_thought(&guard, "th2", "t2", &tenant, 3, period_start);
        }

        let outcome = tlm
            .consolidate_tasks(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start,
                period_end,
                locked_by: "w".into(),
                level: ConsolidationLevel::Basic,
            })
            .await
            .unwrap();
        assert!(outcome.summary_written);
        assert_eq!(outcome.source_rows, 3);

        let rows = tlm
            .query_summary_nodes(
                "task_summary",
                ConsolidationLevel::Basic,
                &tenant,
                period_start - Duration::hours(1),
                period_end + Duration::hours(1),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        let attrs = &rows[0];
        assert_eq!(attrs["tenant_id"], tenant);
        assert_eq!(attrs["total_tasks"].as_i64(), Some(3));
        assert_eq!(attrs["by_status"]["completed"].as_i64(), Some(2));
        assert_eq!(attrs["by_status"]["failed"].as_i64(), Some(1));
        assert_eq!(attrs["mean_thought_depth"].as_f64(), Some(2.0));
        assert_eq!(attrs["consolidation_level"], "basic");
    }

    /// ConversationSummary happy path: 4 SPEAK/OBSERVE correlations
    /// across 2 actors → total + distinct actor count.
    #[tokio::test]
    async fn tsdb_consolidate_conversations_writes_summary() {
        let (b, tlm) = fresh_backend().await;
        let tenant = format!("conv-{}", uuid::Uuid::new_v4().simple());
        let period_start = chrono::Utc::now() - Duration::hours(6);
        let period_end = period_start + Duration::hours(6);

        {
            let conn = b.conn_handle();
            let guard = conn.lock().await;
            seed_correlation(
                &guard,
                "c1",
                &tenant,
                "SPEAK",
                "service_interaction",
                Some(r#"{"actor_id":"alice"}"#),
                period_start,
            );
            seed_correlation(
                &guard,
                "c2",
                &tenant,
                "observe",
                "service_interaction",
                Some(r#"{"actor_id":"alice"}"#),
                period_start + Duration::minutes(5),
            );
            seed_correlation(
                &guard,
                "c3",
                &tenant,
                "speak_action",
                "service_interaction",
                Some(r#"{"actor_id":"bob"}"#),
                period_start + Duration::minutes(10),
            );
            seed_correlation(
                &guard,
                "c4",
                &tenant,
                "observe_action",
                "service_interaction",
                Some(r#"{"actor_id":"bob"}"#),
                period_start + Duration::minutes(15),
            );
            // Off-action — should be excluded.
            seed_correlation(
                &guard,
                "c5_offshape",
                &tenant,
                "tool",
                "service_interaction",
                Some(r#"{"actor_id":"carol"}"#),
                period_start + Duration::minutes(20),
            );
        }

        let outcome = tlm
            .consolidate_conversations(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start,
                period_end,
                locked_by: "w".into(),
                level: ConsolidationLevel::Basic,
            })
            .await
            .unwrap();
        assert!(outcome.summary_written);
        assert_eq!(outcome.source_rows, 4);

        let rows = tlm
            .query_summary_nodes(
                "conversation_summary",
                ConsolidationLevel::Basic,
                &tenant,
                period_start - Duration::hours(1),
                period_end + Duration::hours(1),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["total_messages"].as_i64(), Some(4));
        assert_eq!(rows[0]["unique_actors"].as_i64(), Some(2));
    }

    /// TraceSummary happy path: trace correlations grouped by
    /// action_type. Non-trace rows excluded.
    #[tokio::test]
    async fn tsdb_consolidate_traces_writes_summary() {
        let (b, tlm) = fresh_backend().await;
        let tenant = format!("trace-{}", uuid::Uuid::new_v4().simple());
        let period_start = chrono::Utc::now() - Duration::hours(6);
        let period_end = period_start + Duration::hours(6);

        {
            let conn = b.conn_handle();
            let guard = conn.lock().await;
            seed_correlation(&guard, "tr1", &tenant, "call", "trace", None, period_start);
            seed_correlation(
                &guard,
                "tr2",
                &tenant,
                "call",
                "trace",
                None,
                period_start + Duration::minutes(5),
            );
            seed_correlation(
                &guard,
                "tr3",
                &tenant,
                "tool_invoke",
                "trace",
                None,
                period_start + Duration::minutes(10),
            );
            // Non-trace correlation — excluded.
            seed_correlation(
                &guard,
                "tr4_skip",
                &tenant,
                "call",
                "service_interaction",
                None,
                period_start + Duration::minutes(15),
            );
        }

        let outcome = tlm
            .consolidate_traces(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start,
                period_end,
                locked_by: "w".into(),
                level: ConsolidationLevel::Basic,
            })
            .await
            .unwrap();
        assert!(outcome.summary_written);
        assert_eq!(outcome.source_rows, 3);

        let rows = tlm
            .query_summary_nodes(
                "trace_summary",
                ConsolidationLevel::Basic,
                &tenant,
                period_start - Duration::hours(1),
                period_end + Duration::hours(1),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["total_traces"].as_i64(), Some(3));
        assert_eq!(rows[0]["by_action_type"]["call"].as_i64(), Some(2));
        assert_eq!(rows[0]["by_action_type"]["tool_invoke"].as_i64(), Some(1));
    }

    /// AuditSummary happy path: audit_log over the window, action
    /// histogram + unique_actors.
    #[tokio::test]
    async fn tsdb_consolidate_audit_writes_summary() {
        let (b, tlm) = fresh_backend().await;
        let tenant = format!("aud-{}", uuid::Uuid::new_v4().simple());
        let period_start = chrono::Utc::now() - Duration::hours(6);
        let period_end = period_start + Duration::hours(6);

        {
            let conn = b.conn_handle();
            let guard = conn.lock().await;
            seed_audit(
                &guard,
                &uuid::Uuid::new_v4().to_string(),
                1,
                &tenant,
                "alice",
                "task_signed",
                period_start,
            );
            seed_audit(
                &guard,
                &uuid::Uuid::new_v4().to_string(),
                2,
                &tenant,
                "alice",
                "task_signed",
                period_start + Duration::minutes(5),
            );
            seed_audit(
                &guard,
                &uuid::Uuid::new_v4().to_string(),
                3,
                &tenant,
                "bob",
                "config_changed",
                period_start + Duration::minutes(10),
            );
            // Out of window — excluded.
            seed_audit(
                &guard,
                &uuid::Uuid::new_v4().to_string(),
                4,
                &tenant,
                "carol",
                "wa_intervention",
                period_end + Duration::minutes(5),
            );
        }

        let outcome = tlm
            .consolidate_audit(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start,
                period_end,
                locked_by: "w".into(),
                level: ConsolidationLevel::Basic,
            })
            .await
            .unwrap();
        assert!(outcome.summary_written);
        assert_eq!(outcome.source_rows, 3);

        let rows = tlm
            .query_summary_nodes(
                "audit_summary",
                ConsolidationLevel::Basic,
                &tenant,
                period_start - Duration::hours(1),
                period_end + Duration::hours(1),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["total_events"].as_i64(), Some(3));
        assert_eq!(rows[0]["by_action_type"]["task_signed"].as_i64(), Some(2));
        assert_eq!(
            rows[0]["by_action_type"]["config_changed"].as_i64(),
            Some(1)
        );
        assert_eq!(rows[0]["unique_actors"].as_i64(), Some(2));
    }

    /// `query_summary_nodes` rejects unknown node_type.
    #[tokio::test]
    async fn tsdb_query_summary_nodes_rejects_unknown_type() {
        let (_b, tlm) = fresh_backend().await;
        let now = chrono::Utc::now();
        let err = tlm
            .query_summary_nodes(
                "bogus_summary",
                ConsolidationLevel::Basic,
                "t",
                now - Duration::hours(1),
                now,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    /// `query_summary_nodes` rejects inverted window.
    #[tokio::test]
    async fn tsdb_query_summary_nodes_rejects_inverted_window() {
        let (_b, tlm) = fresh_backend().await;
        let now = chrono::Utc::now();
        let err = tlm
            .query_summary_nodes("task_summary", ConsolidationLevel::Basic, "t", now, now)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    /// Empty source window → summary_written=true (UPSERT version
    /// bump still affects a row on second run; first write still
    /// emits the node even with zero source rows so downstream
    /// queries see the empty-period bucket).
    #[tokio::test]
    async fn tsdb_consolidate_tasks_empty_window_still_writes() {
        let (_b, tlm) = fresh_backend().await;
        let tenant = format!("empty-{}", uuid::Uuid::new_v4().simple());
        let period_start = chrono::Utc::now() - Duration::hours(6);
        let period_end = period_start + Duration::hours(6);

        let outcome = tlm
            .consolidate_tasks(ConsolidationRequest {
                tenant_id: tenant.clone(),
                period_start,
                period_end,
                locked_by: "w".into(),
                level: ConsolidationLevel::Basic,
            })
            .await
            .unwrap();
        // Source rows zero, but the summary node was written so the
        // agent UI can render an "empty period" cell.
        assert!(outcome.summary_written);
        assert_eq!(outcome.source_rows, 0);

        let rows = tlm
            .query_summary_nodes(
                "task_summary",
                ConsolidationLevel::Basic,
                &tenant,
                period_start - Duration::hours(1),
                period_end + Duration::hours(1),
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["total_tasks"].as_i64(), Some(0));
        assert_eq!(rows[0]["mean_thought_depth"].as_f64(), Some(0.0));
    }

    /// Validation rejects empty tenant / inverted window / empty
    /// locked_by uniformly across all four consolidate methods.
    #[tokio::test]
    async fn tsdb_consolidate_typed_validation_errors() {
        let (_b, tlm) = fresh_backend().await;
        let now = chrono::Utc::now();
        let bad_tenant = ConsolidationRequest {
            tenant_id: "".into(),
            period_start: now - Duration::hours(1),
            period_end: now,
            locked_by: "w".into(),
            level: ConsolidationLevel::Basic,
        };
        assert!(matches!(
            tlm.consolidate_tasks(bad_tenant.clone()).await.unwrap_err(),
            Error::InvalidArgument(_)
        ));
        assert!(matches!(
            tlm.consolidate_conversations(bad_tenant.clone())
                .await
                .unwrap_err(),
            Error::InvalidArgument(_)
        ));
        assert!(matches!(
            tlm.consolidate_traces(bad_tenant.clone())
                .await
                .unwrap_err(),
            Error::InvalidArgument(_)
        ));
        assert!(matches!(
            tlm.consolidate_audit(bad_tenant).await.unwrap_err(),
            Error::InvalidArgument(_)
        ));

        let inverted = ConsolidationRequest {
            tenant_id: "t".into(),
            period_start: now,
            period_end: now - Duration::hours(1),
            locked_by: "w".into(),
            level: ConsolidationLevel::Basic,
        };
        assert!(matches!(
            tlm.consolidate_tasks(inverted).await.unwrap_err(),
            Error::InvalidArgument(_)
        ));
    }

    #[tokio::test]
    async fn tsdb_count_edges_by_relationship_in_window_groups() {
        // Stand up two consecutive periods: persist auto-creates
        // TEMPORAL_NEXT edges between them (one per metric_name in
        // the second period). Then count.
        let (_b, tlm) = fresh_backend().await;
        let tenant = format!("tlm-{}", uuid::Uuid::new_v4().simple());
        let now = chrono::Utc::now();
        let a_start = now - Duration::hours(12);
        let a_end = a_start + Duration::hours(6);
        let b_start = a_end;
        let b_end = b_start + Duration::hours(6);

        for start in [&a_start, &b_start] {
            tlm.record_metric(obs("m1", &tenant, 1.0, *start))
                .await
                .unwrap();
            tlm.record_metric(obs("m2", &tenant, 2.0, *start))
                .await
                .unwrap();
        }
        tlm.consolidate_period(ConsolidationRequest {
            tenant_id: tenant.clone(),
            period_start: a_start,
            period_end: a_end,
            locked_by: "w".into(),
            level: ConsolidationLevel::Basic,
        })
        .await
        .unwrap();
        tlm.consolidate_period(ConsolidationRequest {
            tenant_id: tenant.clone(),
            period_start: b_start,
            period_end: b_end,
            locked_by: "w".into(),
            level: ConsolidationLevel::Basic,
        })
        .await
        .unwrap();

        let map = tlm
            .count_edges_by_relationship_in_window(a_start, now + Duration::hours(1))
            .await
            .unwrap();
        // 2 TEMPORAL_NEXT edges expected (one per metric, period B → A).
        assert!(
            map.get("TEMPORAL_NEXT").copied().unwrap_or(0) >= 2,
            "expected ≥2 TEMPORAL_NEXT edges, got map={map:?}"
        );
    }
}
