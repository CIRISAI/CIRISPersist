//! `CorrelationService` trait surface (v1.5.11, CIRISPersist#59 #3).
//!
//! 4 methods. Same `impl Future<...> + Send` GAT pattern as the
//! rest of v0.8.x / v1.x substrate traits.

use std::future::Future;

use super::types::{
    Correlation, CorrelationCursor, CorrelationFilter, CorrelationListPage, CorrelationStatus,
};
use super::Error;

/// Service correlations substrate trait — absorbs CIRISAgent's
/// `service_correlations` table. Dual-purpose schema (service
/// interaction + TSDB metric + distributed-trace span + log).
pub trait CorrelationService: Send + Sync {
    /// Record a correlation. INSERT-OR-IGNORE keyed on
    /// `correlation_id`. First writer wins; a second call with the
    /// same `correlation_id` is a silent no-op (idempotent retry
    /// semantics). State advancement is the caller's responsibility
    /// — use [`Self::update_correlation_status`] to advance an in-
    /// flight correlation.
    ///
    /// # ON CONFLICT contract
    ///
    /// We deliberately chose `ON CONFLICT (correlation_id) DO NOTHING`
    /// over an upsert. The agent retries its outbound RPCs by re-
    /// calling `record_correlation` with the same `correlation_id`;
    /// silent no-op means the retry doesn't clobber any state the
    /// agent already advanced via `update_correlation_status`.
    /// Final-state correlations are immutable through this trait
    /// surface.
    fn record_correlation(
        &self,
        correlation: Correlation,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Read one correlation by id. Returns `None` if no matching row.
    fn get_correlation(
        &self,
        correlation_id: &str,
    ) -> impl Future<Output = Result<Option<Correlation>, Error>> + Send;

    /// Focused status update + optional `response_data` merge.
    /// Refreshes `updated_at` to NOW. Returns `false` if the
    /// correlation doesn't exist (no error — callers treat as
    /// "stale id, drop").
    ///
    /// `response_data` semantics: `None` preserves the existing
    /// value; `Some(Value::Null)` overwrites with NULL;
    /// `Some(other)` writes the value into `response_data`.
    fn update_correlation_status(
        &self,
        correlation_id: &str,
        new_status: CorrelationStatus,
        response_data: Option<serde_json::Value>,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    /// Hot-path read. Cursor-paged listing. Newest-first by
    /// `updated_at`. Filter by any combination of
    /// `service_type`, `correlation_type`, `trace_id`,
    /// `metric_name`, event-time window
    /// (`timestamp_after` / `timestamp_before`), row-update window
    /// (`updated_after` / `updated_before`), `retention_policy`,
    /// `agent_occurrence_id`.
    ///
    /// Index dispatch hints:
    /// - `agent_occurrence_id` + `service_type` →
    ///   `service_correlations_service_recency`
    /// - `correlation_type` + `timestamp` window →
    ///   `service_correlations_type_time`
    /// - `trace_id` →
    ///   `service_correlations_trace_id` (partial)
    /// - `metric_name` + `timestamp` window →
    ///   `service_correlations_metric_time` (partial)
    fn query_correlations(
        &self,
        filter: CorrelationFilter,
        cursor: Option<CorrelationCursor>,
        limit: i64,
    ) -> impl Future<Output = Result<CorrelationListPage, Error>> + Send;
}
