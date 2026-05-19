//! Telemetry + TSDB consolidation wire types (v0.8.2, CIRISPersist#36).

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Telemetry consolidation tier (CIRISAgent#756 Q7).
///
/// Multi-tier rollup pattern — different tiers compact raw
/// observations at different period granularities. Load-bearing
/// for 4GB RAM target on sovereign-mode / Pi deployments (the
/// agent's TSDBConsolidationService tier strategy).
///
/// Wire shape: snake_case strings (matches agent's TSDB vocab).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConsolidationLevel {
    /// 6-hour basic tier — raw observations compacted to per-metric
    /// summaries within a 6-hour window. Highest resolution; held
    /// for short retention.
    #[default]
    Basic,
    /// Daily tier — 24-hour windows. Rolls up basic tiers.
    Daily,
    /// Weekly tier — 7-day windows. Rolls up daily tiers.
    Weekly,
    /// Monthly tier — calendar-month windows. Rolls up weekly tiers.
    /// Lowest resolution; longest retention.
    Monthly,
}

impl ConsolidationLevel {
    /// Wire-shape token (snake_case). Matches the serde representation.
    pub fn as_str(self) -> &'static str {
        match self {
            ConsolidationLevel::Basic => "basic",
            ConsolidationLevel::Daily => "daily",
            ConsolidationLevel::Weekly => "weekly",
            ConsolidationLevel::Monthly => "monthly",
        }
    }

    /// Parse a wire-shape token. Returns `None` for unknown values.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "basic" => Some(ConsolidationLevel::Basic),
            "daily" => Some(ConsolidationLevel::Daily),
            "weekly" => Some(ConsolidationLevel::Weekly),
            "monthly" => Some(ConsolidationLevel::Monthly),
            _ => None,
        }
    }

    /// The tier this tier rolls up FROM. `Basic` rolls up from raw
    /// observations (no input tier — returns `None`); higher tiers
    /// roll up from the previous tier's summaries.
    pub fn input_tier(self) -> Option<Self> {
        match self {
            ConsolidationLevel::Basic => None,
            ConsolidationLevel::Daily => Some(ConsolidationLevel::Basic),
            ConsolidationLevel::Weekly => Some(ConsolidationLevel::Daily),
            ConsolidationLevel::Monthly => Some(ConsolidationLevel::Weekly),
        }
    }
}

impl std::fmt::Display for ConsolidationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

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
    /// CIRISAgent#756 Q7 — which tier this summary belongs to.
    /// `Basic` (default) means raw observations; higher tiers are
    /// rollups of the previous tier's summaries.
    #[serde(default)]
    pub consolidation_level: ConsolidationLevel,
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
    /// CIRISAgent#756 Q7 — which tier to write. `Basic` (default)
    /// aggregates raw observations in the window; higher tiers
    /// aggregate the previous tier's summaries. Wire-default keeps
    /// existing JSON callers (e.g. PyO3) on Basic without changes.
    #[serde(default)]
    pub level: ConsolidationLevel,
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

// ─── v1.6.2 (CIRISPersist#68) typed-summary structs ──────────────────
//
// The agent pipeline produces four NON-METRIC summary node types in
// addition to `tsdb_summary` (which `MetricSummary` covers). v1.6.2
// gives each its own typed Summary + a unified `query_summary_nodes`
// reader. The summaries are stored as JSON attributes on
// `cirisgraph.nodes` rows with `node_type` ∈
// `{"task_summary", "conversation_summary", "trace_summary",
//   "audit_summary"}` and `scope = 'ENVIRONMENT'`.
//
// All four share a `consolidation_level` field (default Basic) — the
// agent only emits Basic-tier rollups for non-metric source data in
// 2.9.0 Phase 3b; higher-tier rollups of these are a future cut.

/// Task lifecycle rollup. Aggregates `cirislens.tasks` (status
/// histogram) + `cirislens.thoughts` (mean thought_depth).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskSummary {
    pub tenant_id: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_tasks: i64,
    pub by_status: std::collections::HashMap<String, i64>,
    pub mean_thought_depth: f64,
    #[serde(default)]
    pub consolidation_level: ConsolidationLevel,
}

/// Conversation rollup. Aggregates `cirislens.service_correlations`
/// rows whose `action_type` is one of the speak/observe shapes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConversationSummary {
    pub tenant_id: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_messages: i64,
    pub unique_actors: i64,
    #[serde(default)]
    pub consolidation_level: ConsolidationLevel,
}

/// Distributed-trace rollup. Aggregates `cirislens.service_correlations`
/// rows where `correlation_type = 'trace'`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceSummary {
    pub tenant_id: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_traces: i64,
    pub by_action_type: std::collections::HashMap<String, i64>,
    #[serde(default)]
    pub consolidation_level: ConsolidationLevel,
}

/// Audit-event rollup. Aggregates `cirislens.audit_log` rows.
/// Note: audit_log uses `tenant_id` directly (not
/// `agent_occurrence_id`) and `recorded_at` (not `created_at`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditSummary {
    pub tenant_id: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_events: i64,
    pub by_action_type: std::collections::HashMap<String, i64>,
    pub unique_actors: i64,
    #[serde(default)]
    pub consolidation_level: ConsolidationLevel,
}

/// Outcome envelope shared by all four typed consolidate methods.
/// `summary_written` is true iff a row landed in `cirisgraph.nodes`
/// (UPSERT affected ≥1 row); `source_rows` is the count of source
/// rows scanned in the window (raw `tasks` count, raw
/// `service_correlations` count, etc.).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypedConsolidationOutcome {
    pub summary_written: bool,
    pub source_rows: i64,
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

    #[test]
    fn consolidation_level_wire_round_trip() {
        for lvl in [
            ConsolidationLevel::Basic,
            ConsolidationLevel::Daily,
            ConsolidationLevel::Weekly,
            ConsolidationLevel::Monthly,
        ] {
            let s = serde_json::to_string(&lvl).unwrap();
            let back: ConsolidationLevel = serde_json::from_str(&s).unwrap();
            assert_eq!(lvl, back);
            assert_eq!(ConsolidationLevel::from_wire_str(lvl.as_str()), Some(lvl));
            assert_eq!(lvl.to_string(), lvl.as_str());
        }
        assert_eq!(ConsolidationLevel::from_wire_str("bogus"), None);
        assert_eq!(ConsolidationLevel::default(), ConsolidationLevel::Basic);
    }

    #[test]
    fn consolidation_level_input_tier_chain() {
        assert_eq!(ConsolidationLevel::Basic.input_tier(), None);
        assert_eq!(
            ConsolidationLevel::Daily.input_tier(),
            Some(ConsolidationLevel::Basic)
        );
        assert_eq!(
            ConsolidationLevel::Weekly.input_tier(),
            Some(ConsolidationLevel::Daily)
        );
        assert_eq!(
            ConsolidationLevel::Monthly.input_tier(),
            Some(ConsolidationLevel::Weekly)
        );
    }

    #[test]
    fn consolidation_request_default_level_is_basic() {
        // Wire compatibility: existing JSON without `level` parses as
        // Basic (matches the PyO3 wrapper's no-level behavior).
        let json = r#"{"tenant_id":"t","period_start":"2026-01-01T00:00:00Z","period_end":"2026-01-01T06:00:00Z","locked_by":"w"}"#;
        let req: ConsolidationRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.level, ConsolidationLevel::Basic);
    }
}
