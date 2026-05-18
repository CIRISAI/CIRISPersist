//! Service correlations substrate wire types (v1.5.11,
//! CIRISPersist#59 #3).
//!
//! Mirrors the row shape of `cirislens.service_correlations`
//! (Postgres) / `cirislens_service_correlations` (SQLite). JSON-
//! string columns (`request_data`, `response_data`, `tags`) lift to
//! `serde_json::Value` so callers don't round-trip through string on
//! every put/get; Postgres maps them as `JSONB`, SQLite stores them
//! as TEXT.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Correlation lifecycle status. Five values per CIRISAgent 2.8.13's
/// `service_correlations.status` vocabulary. Persist does not enforce
/// transition monotonicity at the trait surface — the agent owns the
/// state machine and persist accepts whatever the agent asserts. The
/// CHECK constraint at the schema layer keeps the vocabulary closed-
/// set so a bad caller can't write an unknown status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationStatus {
    #[default]
    Pending,
    Active,
    Completed,
    Failed,
    Cancelled,
}

impl CorrelationStatus {
    /// Stable SQL CHECK value.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            CorrelationStatus::Pending => "pending",
            CorrelationStatus::Active => "active",
            CorrelationStatus::Completed => "completed",
            CorrelationStatus::Failed => "failed",
            CorrelationStatus::Cancelled => "cancelled",
        }
    }

    /// Inverse of [`Self::as_sql_str`].
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(CorrelationStatus::Pending),
            "active" => Some(CorrelationStatus::Active),
            "completed" => Some(CorrelationStatus::Completed),
            "failed" => Some(CorrelationStatus::Failed),
            "cancelled" => Some(CorrelationStatus::Cancelled),
            _ => None,
        }
    }
}

/// Correlation sub-shape discriminator. The substrate's table is
/// dual-purpose; this column distinguishes the four sub-shapes the
/// agent multiplexes through one table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationType {
    /// RPC-level service-interaction tracking.
    #[default]
    ServiceInteraction,
    /// TSDB-style numeric metric point.
    Metric,
    /// OTLP-style distributed-trace span.
    Trace,
    /// Structured log record.
    Log,
}

impl CorrelationType {
    /// Stable SQL CHECK value.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            CorrelationType::ServiceInteraction => "service_interaction",
            CorrelationType::Metric => "metric",
            CorrelationType::Trace => "trace",
            CorrelationType::Log => "log",
        }
    }

    /// Inverse of [`Self::as_sql_str`].
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "service_interaction" => Some(CorrelationType::ServiceInteraction),
            "metric" => Some(CorrelationType::Metric),
            "trace" => Some(CorrelationType::Trace),
            "log" => Some(CorrelationType::Log),
            _ => None,
        }
    }
}

/// TSDB consolidation policy. Per-row tag so a downstream
/// consolidator can scan rows by policy and roll `raw` rows up into
/// `aggregated` / `summary` while leaving `retained_indefinitely`
/// rows alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionPolicy {
    #[default]
    Raw,
    Aggregated,
    Summary,
    RetainedIndefinitely,
}

impl RetentionPolicy {
    /// Stable SQL CHECK value.
    pub fn as_sql_str(self) -> &'static str {
        match self {
            RetentionPolicy::Raw => "raw",
            RetentionPolicy::Aggregated => "aggregated",
            RetentionPolicy::Summary => "summary",
            RetentionPolicy::RetainedIndefinitely => "retained_indefinitely",
        }
    }

    /// Inverse of [`Self::as_sql_str`].
    pub fn parse_str(s: &str) -> Option<Self> {
        match s {
            "raw" => Some(RetentionPolicy::Raw),
            "aggregated" => Some(RetentionPolicy::Aggregated),
            "summary" => Some(RetentionPolicy::Summary),
            "retained_indefinitely" => Some(RetentionPolicy::RetainedIndefinitely),
            _ => None,
        }
    }
}

/// One row of the agent's `service_correlations` substrate.
///
/// 18 columns total. The `correlation_type` column discriminates
/// between the four sub-shapes the table multiplexes
/// (`service_interaction` / `metric` / `trace` / `log`); the other
/// columns are only meaningful for their owning sub-shape. JSON
/// columns (`request_data`, `response_data`, `tags`) lift to
/// `serde_json::Value` so callers carry decoded values across the
/// trait boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Correlation {
    pub correlation_id: String,
    pub service_type: String,
    pub handler_name: String,
    pub action_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_data: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_data: Option<serde_json::Value>,
    #[serde(default)]
    pub status: CorrelationStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub correlation_type: CorrelationType,
    /// Event time — distinct from the row's `created_at`. Used for
    /// metric / trace time-window scans (a metric point's `timestamp`
    /// is when the measurement was taken; `created_at` is when the
    /// row landed in persist).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric_value: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<serde_json::Value>,
    #[serde(default)]
    pub retention_policy: RetentionPolicy,
    /// Multi-occurrence scoping. Default `"default"` for single-
    /// occurrence callers — matches the SQL column DEFAULT.
    pub agent_occurrence_id: String,
}

/// Filter for [`super::CorrelationService::query_correlations`].
///
/// All fields optional. Hot-path index dispatch:
///
/// - `agent_occurrence_id` + `service_type` →
///   `service_correlations_service_recency`
/// - `correlation_type` + `timestamp` window →
///   `service_correlations_type_time`
/// - `trace_id` →
///   `service_correlations_trace_id` (partial)
/// - `metric_name` + `timestamp` window →
///   `service_correlations_metric_time` (partial)
///
/// `timestamp_after` / `timestamp_before` filter on the EVENT
/// `timestamp` column — used for metric / trace time-window scans.
/// `updated_after` / `updated_before` filter on the row's
/// `updated_at` — used for cursor pagination + row-update queries.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CorrelationFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_type: Option<CorrelationType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metric_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_occurrence_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy: Option<RetentionPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_before: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_after: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_before: Option<DateTime<Utc>>,
}

/// Cursor for query-correlations pagination. Captures the trailing
/// `(updated_at, correlation_id)` tuple of the previous page so the
/// next page's WHERE-clause is
/// `(updated_at, correlation_id) < (last_ts, last_id)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationCursor {
    pub version: String,
    pub last_ts: DateTime<Utc>,
    pub last_id: String,
}

impl CorrelationCursor {
    /// Build a v1 cursor from a trailing row.
    pub fn from_trailing(last_ts: DateTime<Utc>, last_id: String) -> Self {
        Self {
            version: "v1".to_owned(),
            last_ts,
            last_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrelationListPage {
    pub items: Vec<Correlation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<CorrelationCursor>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_sql_round_trip() {
        for s in [
            CorrelationStatus::Pending,
            CorrelationStatus::Active,
            CorrelationStatus::Completed,
            CorrelationStatus::Failed,
            CorrelationStatus::Cancelled,
        ] {
            assert_eq!(CorrelationStatus::parse_str(s.as_sql_str()), Some(s));
        }
        assert_eq!(CorrelationStatus::parse_str("UNKNOWN"), None);
    }

    #[test]
    fn correlation_type_sql_round_trip() {
        for ct in [
            CorrelationType::ServiceInteraction,
            CorrelationType::Metric,
            CorrelationType::Trace,
            CorrelationType::Log,
        ] {
            assert_eq!(CorrelationType::parse_str(ct.as_sql_str()), Some(ct));
        }
        assert_eq!(CorrelationType::parse_str("UNKNOWN"), None);
    }

    #[test]
    fn retention_policy_sql_round_trip() {
        for rp in [
            RetentionPolicy::Raw,
            RetentionPolicy::Aggregated,
            RetentionPolicy::Summary,
            RetentionPolicy::RetainedIndefinitely,
        ] {
            assert_eq!(RetentionPolicy::parse_str(rp.as_sql_str()), Some(rp));
        }
        assert_eq!(RetentionPolicy::parse_str("UNKNOWN"), None);
    }

    #[test]
    fn enums_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&CorrelationStatus::Active).unwrap(),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&CorrelationType::Metric).unwrap(),
            "\"metric\""
        );
        assert_eq!(
            serde_json::to_string(&RetentionPolicy::RetainedIndefinitely).unwrap(),
            "\"retained_indefinitely\""
        );
    }

    #[test]
    fn enums_defaults() {
        assert_eq!(CorrelationStatus::default(), CorrelationStatus::Pending);
        assert_eq!(
            CorrelationType::default(),
            CorrelationType::ServiceInteraction
        );
        assert_eq!(RetentionPolicy::default(), RetentionPolicy::Raw);
    }

    #[test]
    fn correlation_serde_round_trip_full_columns() {
        let now = Utc::now();
        let c = Correlation {
            correlation_id: "corr-abc".into(),
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
            trace_id: Some("trace-1".into()),
            span_id: Some("span-1".into()),
            parent_span_id: Some("span-0".into()),
            tags: Some(serde_json::json!({"k": "v"})),
            retention_policy: RetentionPolicy::Aggregated,
            agent_occurrence_id: "occ-1".into(),
        };
        let s = serde_json::to_string(&c).unwrap();
        let back: Correlation = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn correlation_serde_minimal_columns_back_compat() {
        let now = Utc::now();
        let json = serde_json::json!({
            "correlation_id": "corr-min",
            "service_type": "llm",
            "handler_name": "speak_handler",
            "action_type": "speak",
            "created_at": now.to_rfc3339(),
            "updated_at": now.to_rfc3339(),
            "agent_occurrence_id": "default"
        });
        let c: Correlation = serde_json::from_value(json).unwrap();
        assert_eq!(c.status, CorrelationStatus::Pending);
        assert_eq!(c.correlation_type, CorrelationType::ServiceInteraction);
        assert_eq!(c.retention_policy, RetentionPolicy::Raw);
        assert!(c.request_data.is_none());
        assert!(c.response_data.is_none());
        assert!(c.timestamp.is_none());
        assert!(c.metric_name.is_none());
        assert!(c.metric_value.is_none());
        assert!(c.log_level.is_none());
        assert!(c.trace_id.is_none());
        assert!(c.span_id.is_none());
        assert!(c.parent_span_id.is_none());
        assert!(c.tags.is_none());
    }

    #[test]
    fn cursor_from_trailing_sets_version_v1() {
        let now = Utc::now();
        let c = CorrelationCursor::from_trailing(now, "id-x".into());
        assert_eq!(c.version, "v1");
        assert_eq!(c.last_id, "id-x");
        assert_eq!(c.last_ts, now);
    }
}
