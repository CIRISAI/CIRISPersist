//! Telemetry + TSDB consolidation (v0.8.2, CIRISPersist#36).
//!
//! Absorbs CIRISAgent's `TelemetryService` + `TSDBConsolidationService`
//! surfaces. Raw observations land in `cirisgraph.telemetry_metrics`
//! (high-frequency, 24h-lived); the 6-hour consolidator rolls them
//! up into `tsdb_summary` nodes in `cirisgraph.nodes` (V013) with
//! `TEMPORAL_NEXT` / `TEMPORAL_PREV` edges between adjacent
//! summaries.
//!
//! # Why two storage shapes (not one)
//!
//! Raw observations are write-hot (100s/sec under load) but
//! short-lived. They don't carry the audit envelope or version-
//! tracking that cirisgraph nodes do — making them graph nodes
//! would force the cirisgraph write path to absorb the hot-write
//! cost. The split keeps cirisgraph cheap + auditable for the
//! agent's semantic graph, and gives telemetry a flat-table fast
//! path. The rolled-up summary (which IS a graph node) carries the
//! audit envelope on behalf of the period it summarizes.
//!
//! # Consolidation flow
//!
//! For one `(period_start, period_end, tenant_id)` window:
//!
//! 1. Acquire row in `cirisgraph.consolidation_locks` via
//!    `INSERT … ON CONFLICT DO NOTHING`. On contention, check the
//!    existing lock's `locked_at` — if stale (>1h), break and take
//!    over (AV-53). Otherwise refuse the consolidation.
//! 2. Read raw metrics in `[period_start, period_end)` grouped by
//!    `metric_name`.
//! 3. Compute per-metric aggregates: `sum`, `min`, `max`, `avg`,
//!    `count`, observed `unique_label_combinations` count.
//! 4. For each metric, UPSERT a `tsdb_summary` node into
//!    `cirisgraph.nodes` (scope=`Environment`, node_id=
//!    `tsdb:{metric_name}:{period_start.iso8601}`).
//! 5. Create `TEMPORAL_NEXT` edge from prior period's summary node
//!    (if present) to this one (AV-54 — chain integrity).
//! 6. DELETE raw rows in the period.
//! 7. Release the lock row.
//!
//! # Threat-model anchors (THREAT_MODEL.md §4)
//!
//! - **AV-52** — metric label cardinality + size cap (default 4 KiB
//!   per labels JSONB; max distinct values per (tenant, name)
//!   capped at 1000 in 24h on the runtime path).
//! - **AV-53** — consolidation lock starvation: stale locks
//!   auto-break with a warn log.
//! - **AV-54** — TEMPORAL_NEXT chain integrity: refuse to write a
//!   TEMPORAL_NEXT edge whose source summary node doesn't exist.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::TelemetryService;
pub use types::{
    ConsolidationOutcome, ConsolidationRequest, MetricFilter, MetricListPage, MetricObservation,
    MetricSummary,
};

/// Telemetry-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — labels exceed size cap
    /// (AV-52), period_end ≤ period_start, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// AV-53: another consolidator is actively holding the lock for
    /// this (period, tenant) pair and the lock isn't stale.
    #[error("lock contention: {0}")]
    LockContention(String),

    /// Backend-level error.
    #[error("backend: {0}")]
    Backend(String),

    /// Trait method declared but backend doesn't implement it.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),

    /// Internal serialization / type-conversion bug.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "telemetry_invalid_argument",
            Error::LockContention(_) => "telemetry_lock_contention",
            Error::Backend(_) => "telemetry_backend",
            Error::NotImplemented(_) => "telemetry_not_implemented",
            Error::Internal(_) => "telemetry_internal",
        }
    }
}

/// AV-52: default per-row labels JSONB size cap. Bytes.
/// Configurable per deployment via
/// `CIRIS_PERSIST_TELEMETRY_MAX_LABELS_BYTES` env.
pub const DEFAULT_MAX_LABELS_BYTES: usize = 4 * 1024;

/// AV-53: a consolidation lock is considered stale (eligible for
/// auto-break) after this many seconds since `locked_at`. Default
/// 3600 (1h) — long enough to cover even the slowest legitimate
/// rollup; short enough to recover from a crashed worker quickly.
pub const STALE_LOCK_SECONDS: i64 = 3600;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_tokens_stable() {
        assert_eq!(
            Error::InvalidArgument("x".into()).kind(),
            "telemetry_invalid_argument"
        );
        assert_eq!(
            Error::LockContention("x".into()).kind(),
            "telemetry_lock_contention"
        );
        assert_eq!(Error::Backend("x".into()).kind(), "telemetry_backend");
        assert_eq!(
            Error::NotImplemented("x").kind(),
            "telemetry_not_implemented"
        );
        assert_eq!(Error::Internal("x".into()).kind(), "telemetry_internal");
    }

    #[test]
    fn av_52_default_cap_is_4_kib() {
        assert_eq!(DEFAULT_MAX_LABELS_BYTES, 4096);
    }

    #[test]
    fn av_53_stale_threshold_is_1h() {
        assert_eq!(STALE_LOCK_SECONDS, 3600);
    }
}
