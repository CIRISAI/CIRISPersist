//! `TelemetryService` trait surface (v0.8.2, CIRISPersist#36).
//!
//! 4 methods: 2 writes + 1 read + 1 consolidation operation.

use std::future::Future;

use super::types::{
    ConsolidationLevel, ConsolidationOutcome, ConsolidationRequest, MetricCursor, MetricFilter,
    MetricListPage, MetricObservation, MetricSummary, TypedConsolidationOutcome,
};
use super::Error;
use chrono::{DateTime, Utc};

/// Telemetry write + read + consolidation surface absorbed from
/// CIRISAgent's TelemetryService + TSDBConsolidationService.
pub trait TelemetryService: Send + Sync {
    /// Record a single observation. AV-52: rejects labels JSONB
    /// over the configured size cap. Auto-fills `metric_id` if the
    /// caller passed `None`; auto-fills `expires_at` to
    /// `observed_at + 24h` if not specified.
    fn record_metric(
        &self,
        obs: MetricObservation,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Bulk-record N observations in one round trip (UNNEST-backed).
    /// Returns the count of rows actually inserted. AV-52 size cap
    /// applies per-row.
    fn record_metrics_batch(
        &self,
        obs: &[MetricObservation],
    ) -> impl Future<Output = Result<u64, Error>> + Send;

    /// Cursor-paged listing scoped to one tenant. Newest-first by
    /// `observed_at`.
    fn list_metrics(
        &self,
        filter: MetricFilter,
        cursor: Option<MetricCursor>,
        limit: i64,
    ) -> impl Future<Output = Result<MetricListPage, Error>> + Send;

    /// Run the rollup for one `(period_start, period_end,
    /// tenant_id)` window:
    ///
    /// 1. Acquire `cirisgraph.consolidation_locks` row. On
    ///    contention, check staleness (AV-53) — break + take over
    ///    if >1h old, else return `ran=false` immediately.
    /// 2. Compute per-`metric_name` aggregates over raw metrics
    ///    in the window.
    /// 3. UPSERT one `tsdb_summary` node per metric into
    ///    `cirisgraph.nodes` (scope=`Environment`).
    /// 4. Create `TEMPORAL_NEXT` edges from prior period's summary
    ///    nodes when present (AV-54).
    /// 5. DELETE raw rows in the window.
    /// 6. Release the lock.
    ///
    /// Idempotent: running twice with the same `period_start`
    /// returns `ran=true` the first time (rolling up and deleting
    /// raw), and `ran=true` with zero work the second time (the
    /// already-existing summary node's UPSERT version-bumps no-op'd
    /// and there are no raw rows left to delete).
    fn consolidate_period(
        &self,
        req: ConsolidationRequest,
    ) -> impl Future<Output = Result<ConsolidationOutcome, Error>> + Send;

    // ── TSDB query / prune surface (v1.6.0, CIRISPersist#63) ────────

    /// v1.6.0 — Return every `MetricSummary` whose
    /// `(consolidation_level, tenant_id)` matches and whose
    /// `period_start ∈ [from, to)`. Ordered by `period_start ASC,
    /// metric_name ASC`.
    ///
    /// Backs the agent's "Basic (6h) / extensive (week) / profound
    /// (month) period-window queries" requirement (CIRISPersist#63):
    /// caller passes the window bounds and the desired tier; persist
    /// emits a single `SELECT … FROM cirisgraph.nodes WHERE
    /// consolidation_level = ? AND attributes->>'tenant_id' = ? AND
    /// (attributes->>'period_start')::timestamptz IN [from, to)` —
    /// no client-side scan/filter.
    fn query_summaries(
        &self,
        level: ConsolidationLevel,
        tenant_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> impl Future<Output = Result<Vec<MetricSummary>, Error>> + Send;

    /// v1.6.0 — Point-lookup of one summary by the deterministic
    /// `(level, tenant_id, metric_name, period_start)` key. Returns
    /// `None` when no row matches.
    fn get_summary(
        &self,
        level: ConsolidationLevel,
        tenant_id: &str,
        metric_name: &str,
        period_start: DateTime<Utc>,
    ) -> impl Future<Output = Result<Option<MetricSummary>, Error>> + Send;

    /// v1.6.0 — Delete summary nodes older than `before` for the
    /// given `(level, tenant_id)`. Returns the count of rows deleted.
    /// Also cascades the agent-application-layer convention of
    /// removing incident edges from a deleted summary (TEMPORAL_NEXT
    /// edges sourced at or pointing at the pruned nodes are deleted
    /// in the same transaction).
    ///
    /// Used by CIRISAgent#763 Phase 3b's TSDB retention sweep: once
    /// daily summaries roll up basic ones, the basic-tier rows are
    /// purged after a retention window passes.
    fn prune_summaries(
        &self,
        level: ConsolidationLevel,
        tenant_id: &str,
        before: DateTime<Utc>,
    ) -> impl Future<Output = Result<u64, Error>> + Send;

    /// v1.6.0 — Histogram of edges in `[from, to)` grouped by
    /// `relationship`. Filter on `cirisgraph.edges.scope =
    /// 'ENVIRONMENT'` (the TSDB scope) + `created_at` window.
    /// Returns `{relationship: count}` — the agent's
    /// `edge_manager.py` rolls these counts into the daily summary's
    /// attributes for cross-period observability.
    ///
    /// Returns an empty map when no edges match (not an error).
    fn count_edges_by_relationship_in_window(
        &self,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> impl Future<Output = Result<std::collections::HashMap<String, u64>, Error>> + Send;

    // ── v1.6.2 (CIRISPersist#68) non-metric summary types ───────────
    //
    // The agent's TSDB pipeline produces FIVE summary node types, of
    // which one (`tsdb_summary`) is the metric rollup covered by
    // `consolidate_period` above. The remaining four —
    // `task_summary`, `conversation_summary`, `trace_summary`,
    // `audit_summary` — aggregate non-metric source data:
    //
    //   task_summary         ← cirislens.tasks + cirislens.thoughts
    //   conversation_summary ← cirislens.service_correlations
    //                          (action_type ∈ speak/observe shapes)
    //   trace_summary        ← cirislens.service_correlations
    //                          (correlation_type = 'trace')
    //   audit_summary        ← cirislens.audit_log
    //
    // Each emits a `*_summary` graph node into `cirisgraph.nodes`
    // (scope `ENVIRONMENT`) carrying the aggregation result as the
    // JSON `attributes` blob. v1.6.2 covers Basic-tier rollups only;
    // higher-tier rollups of typed summaries are a future cut.
    //
    // No lock acquisition — caller (agent) is single-threaded for
    // non-metric consolidation. (Lock-arbitration parity with
    // `consolidate_period` is a v1.7.x extension if concurrent
    // consolidations land.)

    /// v1.6.2 (CIRISPersist#68) — Consolidate task/thought source
    /// data over `[period_start, period_end)` into a `TaskSummary`
    /// node. `total_tasks` is the count over `cirislens.tasks`
    /// (filtered by `agent_occurrence_id = tenant_id`,
    /// `created_at ∈ window`); `by_status` is the
    /// `GROUP BY status` histogram; `mean_thought_depth` is
    /// `AVG(thought_depth)` over `cirislens.thoughts` for the same
    /// window (0.0 when no thoughts).
    fn consolidate_tasks(
        &self,
        req: ConsolidationRequest,
    ) -> impl Future<Output = Result<TypedConsolidationOutcome, Error>> + Send;

    /// v1.6.2 — Consolidate conversation-shaped service correlations
    /// (`action_type` ∈ `speak | observe | speak_action |
    /// observe_action`, case-insensitive) over the window into a
    /// `ConversationSummary` node. `total_messages` is the matching
    /// row count; `unique_actors` is the distinct
    /// `request_data->>'actor_id'` count.
    fn consolidate_conversations(
        &self,
        req: ConsolidationRequest,
    ) -> impl Future<Output = Result<TypedConsolidationOutcome, Error>> + Send;

    /// v1.6.2 — Consolidate trace-shaped service correlations
    /// (`correlation_type = 'trace'`) over the window into a
    /// `TraceSummary` node. `total_traces` is the matching row
    /// count; `by_action_type` is the `GROUP BY action_type`
    /// histogram.
    fn consolidate_traces(
        &self,
        req: ConsolidationRequest,
    ) -> impl Future<Output = Result<TypedConsolidationOutcome, Error>> + Send;

    /// v1.6.2 — Consolidate audit-log rows over the window into an
    /// `AuditSummary` node. `total_events` is the row count;
    /// `by_action_type` is the histogram; `unique_actors` is the
    /// distinct `actor_id` count. Note: `cirislens.audit_log` uses
    /// `tenant_id` (NOT `agent_occurrence_id`) and `recorded_at`
    /// (NOT `created_at`) — schema's direct shape.
    fn consolidate_audit(
        &self,
        req: ConsolidationRequest,
    ) -> impl Future<Output = Result<TypedConsolidationOutcome, Error>> + Send;

    /// v1.6.2 — Query typed summary nodes by `node_type`. Returns
    /// the raw JSON attributes for each matching row so callers
    /// deserialize per-summary-type (`TaskSummary`,
    /// `ConversationSummary`, `TraceSummary`, `AuditSummary`) on
    /// their side. Ordered by `period_start ASC`.
    ///
    /// `node_type` is one of `"task_summary" |
    /// "conversation_summary" | "trace_summary" | "audit_summary"`.
    /// `level` filters the `consolidation_level` column;
    /// `tenant_id` matches `attributes->>'tenant_id'`; `from` / `to`
    /// bracket `attributes->>'period_start'` (half-open).
    fn query_summary_nodes(
        &self,
        node_type: &str,
        level: ConsolidationLevel,
        tenant_id: &str,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> impl Future<Output = Result<Vec<serde_json::Value>, Error>> + Send;
}
