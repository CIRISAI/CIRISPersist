//! Telemetry + TSDB consolidation wire types (v0.8.2, CIRISPersist#36).

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One raw observation. Mirrors `cirisgraph.telemetry_metrics` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricObservation {
    /// Optional — caller-supplied UUID; backend generates if empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric_id: Option<String>,
    pub metric_name: String,
    pub tenant_id: String,
    pub value: f64,
    /// AV-52: labels JSONB size-capped at the trait surface
    /// (default [`super::DEFAULT_MAX_LABELS_BYTES`]).
    #[serde(default)]
    pub labels: serde_json::Value,
    pub observed_at: DateTime<Utc>,
    /// Optional TTL override; defaults to `observed_at + 24h`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Per-metric rollup result for one consolidation period. Stored
/// as the `attributes` JSONB blob on the `tsdb_summary` graph node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricSummary {
    pub metric_name: String,
    pub tenant_id: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub count: i64,
    /// AV-52 observability — number of distinct label-set
    /// combinations seen across the window. High cardinality is a
    /// signal of label-axis abuse.
    pub unique_label_combinations: i64,
}

/// Filter for `TelemetryService::list_metrics`. `tenant_id` is
/// required (AV-51 isolation pattern; consistent with cirisaudit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricFilter {
    pub tenant_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric_name: Option<String>,
    /// Inclusive lower bound on `observed_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_after: Option<DateTime<Utc>>,
    /// Exclusive upper bound on `observed_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_before: Option<DateTime<Utc>>,
    /// JSONB containment predicate (e.g. `{"region": "us-west"}`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub labels_contains: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricCursor {
    pub version: String,
    pub last_ts: DateTime<Utc>,
    pub last_id: String,
}

impl MetricCursor {
    pub fn from_trailing(last_ts: DateTime<Utc>, last_id: String) -> Self {
        Self {
            version: "v1".to_owned(),
            last_ts,
            last_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricListPage {
    pub items: Vec<MetricObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<MetricCursor>,
}

/// One consolidation invocation request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsolidationRequest {
    pub tenant_id: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    /// Identifier for the worker invoking the consolidation —
    /// stored on the lock row + summary attributes for forensics.
    pub locked_by: String,
}

/// Result of one `consolidate_period` call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsolidationOutcome {
    /// Total raw metrics scanned in the window.
    pub metrics_consolidated: i64,
    /// Distinct (metric_name) groups → one summary node each.
    pub summaries_written: i64,
    /// Number of TEMPORAL_NEXT edges written to prior period's
    /// summaries.
    pub edges_created: i64,
    /// Raw rows deleted after rollup.
    pub raw_metrics_deleted: i64,
    /// True when the lock was acquired and consolidation ran;
    /// false when an existing fresh lock blocked the run.
    pub ran: bool,
    /// True when the consolidator broke a stale lock (>1h) on
    /// acquisition. Telemetry-actionable signal — operators should
    /// investigate the previous worker's failure mode.
    pub broke_stale_lock: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_observation_serde_round_trip() {
        let m = MetricObservation {
            metric_id: None,
            metric_name: "llm.tokens.in".into(),
            tenant_id: "agent-datum".into(),
            value: 1234.0,
            labels: serde_json::json!({"model": "claude-opus-4-7"}),
            observed_at: Utc::now(),
            expires_at: None,
        };
        let s = serde_json::to_string(&m).unwrap();
        let back: MetricObservation = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn consolidation_outcome_serde() {
        let o = ConsolidationOutcome {
            metrics_consolidated: 100,
            summaries_written: 5,
            edges_created: 4,
            raw_metrics_deleted: 100,
            ran: true,
            broke_stale_lock: false,
        };
        let s = serde_json::to_string(&o).unwrap();
        let back: ConsolidationOutcome = serde_json::from_str(&s).unwrap();
        assert_eq!(o, back);
    }
}
