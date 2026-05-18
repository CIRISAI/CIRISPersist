//! Continuity-awareness substrate wire types (v1.5.17,
//! CIRISPersist#59 #9).
//!
//! Mirrors the row shape of `cirislens.continuity_awareness`
//! (Postgres) / `cirislens_continuity_awareness` (SQLite). 14
//! columns matching CIRISAgent v2.8.13's `continuity_awareness`
//! verbatim — per-shutdown record giving the next boot a
//! "where did I leave off" surface.
//!
//! `preservation_scope` rides the existing
//! [`crate::graph::types::GraphScope`] enum (LOCAL / IDENTITY /
//! ENVIRONMENT / COMMUNITY) — the cross-substrate FK to
//! `cirisgraph.nodes` pins the same vocabulary on both sides.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::graph::types::GraphScope;

/// One row of the `continuity_awareness` substrate.
///
/// 14 columns. Matches the agent's column-for-column. First
/// substrate with a cross-substrate FK:
/// `(preservation_node_id, preservation_scope)` references
/// `cirisgraph.nodes(node_id, scope)`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContinuityAwareness {
    /// Caller-supplied shutdown record identifier. NOT NULL, PK.
    pub id: String,
    /// Identity of the agent whose shutdown this row records.
    pub agent_id: String,
    /// Wall-clock time at which the shutdown happened.
    pub shutdown_timestamp: DateTime<Utc>,
    /// Terminal shutdown? `true` means the agent is not expected
    /// to reactivate from this shutdown; `false` means a planned
    /// pause / restart that should be matched by a subsequent
    /// `record_reactivation`.
    pub is_terminal: bool,
    /// Free-form reason text for the shutdown. NOT NULL — the
    /// ceremony is supposed to carry the reason.
    pub shutdown_reason: String,
    /// Optional expected-reactivation wall-clock time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_reactivation: Option<DateTime<Utc>>,
    /// Identity of the party that initiated the shutdown (agent,
    /// operator, WA, etc.).
    pub initiated_by: String,
    /// Free-form final-thoughts text — the agent's last words for
    /// the next boot. NOT NULL — the ceremony carries this even
    /// if it's the empty string semantics, but the column itself
    /// must be present.
    pub final_thoughts: String,
    /// Optional JSON-shaped array of unfinished task descriptors.
    /// PG promotes this to JSONB; SQLite carries as TEXT JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unfinished_tasks: Option<serde_json::Value>,
    /// Optional free-form text instructing the next boot how to
    /// resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reactivation_instructions: Option<String>,
    /// Optional JSON-shaped array of deferred-goal descriptors.
    /// PG promotes this to JSONB; SQLite carries as TEXT JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred_goals: Option<serde_json::Value>,
    /// Component 1 of the cross-substrate FK to
    /// `cirisgraph.nodes(node_id, scope)`: the node_id portion.
    pub preservation_node_id: String,
    /// Component 2 of the cross-substrate FK: the scope portion.
    /// Defaults to `IDENTITY` per the agent's column default.
    pub preservation_scope: GraphScope,
    /// Number of times this non-terminal shutdown has been
    /// successfully reactivated. Starts at 0, increments via
    /// `record_reactivation`. CHECK (>= 0) at the DB layer.
    pub reactivation_count: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_full() -> ContinuityAwareness {
        ContinuityAwareness {
            id: "shutdown-abc".into(),
            agent_id: "agent-x".into(),
            shutdown_timestamp: Utc::now(),
            is_terminal: false,
            shutdown_reason: "planned restart".into(),
            expected_reactivation: Some(Utc::now() + chrono::Duration::minutes(5)),
            initiated_by: "operator".into(),
            final_thoughts: "see you in a minute".into(),
            unfinished_tasks: Some(serde_json::json!(["task-1", "task-2"])),
            reactivation_instructions: Some("resume from task-1 first".into()),
            deferred_goals: Some(serde_json::json!(["goal-a"])),
            preservation_node_id: "agent:x".into(),
            preservation_scope: GraphScope::Identity,
            reactivation_count: 0,
        }
    }

    #[test]
    fn continuity_serde_round_trip_all_14_columns() {
        let c = mk_full();
        let s = serde_json::to_string(&c).unwrap();
        let back: ContinuityAwareness = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn continuity_serde_minimal_required_columns() {
        let now = Utc::now();
        let json = serde_json::json!({
            "id": "shutdown-min",
            "agent_id": "agent-y",
            "shutdown_timestamp": now.to_rfc3339(),
            "is_terminal": true,
            "shutdown_reason": "terminal",
            "initiated_by": "agent",
            "final_thoughts": "goodbye",
            "preservation_node_id": "agent:y",
            "preservation_scope": "IDENTITY",
            "reactivation_count": 0,
        });
        let c: ContinuityAwareness = serde_json::from_value(json).unwrap();
        assert!(c.expected_reactivation.is_none());
        assert!(c.unfinished_tasks.is_none());
        assert!(c.reactivation_instructions.is_none());
        assert!(c.deferred_goals.is_none());
        assert_eq!(c.preservation_scope, GraphScope::Identity);
        assert!(c.is_terminal);
    }

    #[test]
    fn continuity_scope_wire_format_is_uppercase() {
        let c = mk_full();
        let s = serde_json::to_string(&c).unwrap();
        // GraphScope serde is `rename_all = "UPPERCASE"`.
        assert!(
            s.contains("\"preservation_scope\":\"IDENTITY\""),
            "wire JSON: {s}"
        );
    }
}
