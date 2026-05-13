//! `TelemetryService` trait surface (v0.8.2, CIRISPersist#36).
//!
//! 4 methods: 2 writes + 1 read + 1 consolidation operation.

use std::future::Future;

use super::types::{
    ConsolidationOutcome, ConsolidationRequest, MetricCursor, MetricFilter, MetricListPage,
    MetricObservation,
};
use super::Error;

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
}
