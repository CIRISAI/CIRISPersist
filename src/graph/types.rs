//! cirisgraph wire types (v0.8.0, CIRISPersist#34).
//!
//! Schema parity with CIRISAgent's `graph_nodes` / `graph_edges`
//! (verified via deepwiki). Shapes are federation-stable — wire
//! changes within v0.8.x are additive only; breaking shape changes
//! get a new column + migration.

#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// GraphScope tier — taken straight from CIRISAgent's enum (verified
/// via deepwiki). Determines visibility + isolation:
///
/// - **Local** — process-local; agent-private, never federated.
/// - **Identity** — agent self-knowledge; signed by the agent's
///   own identity key.
/// - **Environment** — ambient platform / channel context; shared
///   within a deployment.
/// - **Community** — federation-shared knowledge; visible to peers
///   per the federation policy.
///
/// AV-47: read methods on [`super::GraphService`] take this enum
/// non-optionally — type system forces every caller to name the
/// scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum GraphScope {
    Local,
    Identity,
    Environment,
    Community,
}

impl GraphScope {
    /// Stable SQL-CHECK string for this scope variant. The V013
    /// migration's CHECK constraint pins these exact values.
    pub fn as_sql_str(&self) -> &'static str {
        match self {
            GraphScope::Local => "LOCAL",
            GraphScope::Identity => "IDENTITY",
            GraphScope::Environment => "ENVIRONMENT",
            GraphScope::Community => "COMMUNITY",
        }
    }

    /// Parse a SQL CHECK value back to the typed variant. Returns
    /// [`Option::None`] for unknown values (forward-compat — caller
    /// surfaces as `Error::Backend`).
    pub fn from_sql_str(s: &str) -> Option<Self> {
        match s {
            "LOCAL" => Some(GraphScope::Local),
            "IDENTITY" => Some(GraphScope::Identity),
            "ENVIRONMENT" => Some(GraphScope::Environment),
            "COMMUNITY" => Some(GraphScope::Community),
            _ => None,
        }
    }
}

/// A typed graph node — mirrors `cirisgraph.nodes` row shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphNode {
    pub node_id: String,
    pub scope: GraphScope,
    /// Free-form type label owned by the agent's taxonomy
    /// (`agent`, `user`, `channel`, `config`, `tsdb_data`,
    /// `tsdb_summary`, etc.).
    pub node_type: String,
    /// JSONB attributes blob. AV-45: size-capped at the trait
    /// surface (default 1 MiB; configurable).
    pub attributes: serde_json::Value,
    /// AV-48 optimistic-concurrency version. Starts at 1; clients
    /// pass `expected_version` to [`super::GraphService::upsert_node`]
    /// and the call returns `Error::Conflict` if the current row's
    /// version differs.
    pub version: i32,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// Optional audit envelope. Agent-written rows from the v0.8.0
    /// API populate these; legacy / ETL'd rows leave them None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signing_key_id: Option<String>,
    #[serde(default)]
    pub signature_verified: bool,
}

/// A typed directed edge — mirrors `cirisgraph.edges` row shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEdge {
    pub edge_id: String,
    pub source_node_id: String,
    pub target_node_id: String,
    pub scope: GraphScope,
    /// Relationship label owned by the agent's vocabulary
    /// (`SUMMARIZES`, `TEMPORAL_NEXT`, `TEMPORAL_PREV`, `OWNS`,
    /// `HAS_MEMBER`, etc.).
    pub relationship: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<f64>,
    #[serde(default)]
    pub attributes: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Direction filter for [`super::GraphService::get_edges_for_node`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeDirection {
    /// Edges where `source_node_id == node_id` (outgoing).
    Outgoing,
    /// Edges where `target_node_id == node_id` (incoming).
    Incoming,
    /// Both directions, union'd.
    Both,
}

/// Filter for [`super::GraphService::query_nodes`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeFilter {
    /// Required: at least one scope must be named (AV-47 — never
    /// allow "all scopes" wildcard read).
    pub scope: Option<GraphScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_type: Option<String>,
    /// JSONB containment predicate — passed as the `@>` operator
    /// right-hand side. e.g. `{"tags": ["audit"]}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes_contains: Option<serde_json::Value>,
    /// Inclusive lower bound on `updated_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_after: Option<DateTime<Utc>>,
    /// Inclusive upper bound on `updated_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_before: Option<DateTime<Utc>>,
}

/// Cursor-paged result page for [`super::GraphService::query_nodes`].
/// Mirrors the v0.5.5 §I cursor shape used by the cirisnode track —
/// defined locally to keep cirisgraph independent of the cirisnode
/// feature gate. (Future v0.9.x refactor: lift to a shared
/// `crate::pagination::ListCursor` module once a third consumer
/// emerges.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeListPage {
    pub items: Vec<GraphNode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<ListCursor>,
}

/// `(updated_at, node_id)`-tuple cursor for newest-first paging.
/// Same shape as `cirisnode::ListCursor`; defined separately to
/// avoid cross-feature coupling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListCursor {
    /// Cursor format version. v0.8.0 ships `"v1"`.
    pub version: String,
    /// `updated_at` of the trailing row.
    pub last_ts: DateTime<Utc>,
    /// `node_id` of the trailing row.
    pub last_id: String,
}

impl ListCursor {
    /// Construct a v1 cursor from the trailing row of a result page.
    pub fn from_trailing(last_ts: DateTime<Utc>, last_id: String) -> Self {
        ListCursor {
            version: "v1".to_owned(),
            last_ts,
            last_id,
        }
    }
}

/// Per-call traversal config for
/// [`super::GraphService::traverse_k_hop`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraversalConfig {
    /// Bounded by [`super::MAX_KHOP_DEPTH`] (AV-46). Caller-
    /// supplied depth above the cap rejects as
    /// `Error::InvalidArgument`.
    pub max_depth: usize,
    /// AV-46: required allow-list of relationship labels. The
    /// trait method refuses an empty list — "all edges" wildcard
    /// is not a valid input.
    pub edge_relationships: Vec<String>,
    /// Direction to follow from each frontier node.
    pub direction: EdgeDirection,
    /// Per-recursion-level fan-out bound. Default 1024; CTE uses
    /// this as a `LIMIT` per step so a high-fan-out node cannot
    /// alone exhaust the call's memory.
    #[serde(default = "default_per_level_limit")]
    pub per_level_limit: usize,
}

fn default_per_level_limit() -> usize {
    1024
}

/// One result row from [`super::GraphService::traverse_k_hop`]:
/// a reachable node + the depth at which it was first reached.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KhopEntry {
    pub node: GraphNode,
    /// 0 for the start node itself; 1 for direct neighbors; etc.
    pub depth: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graph_scope_sql_str_round_trip() {
        for scope in [
            GraphScope::Local,
            GraphScope::Identity,
            GraphScope::Environment,
            GraphScope::Community,
        ] {
            let s = scope.as_sql_str();
            assert_eq!(GraphScope::from_sql_str(s), Some(scope));
        }
        assert_eq!(GraphScope::from_sql_str("UNKNOWN_SCOPE"), None);
    }

    #[test]
    fn graph_scope_serde_uppercase() {
        let s = serde_json::to_string(&GraphScope::Identity).unwrap();
        assert_eq!(s, "\"IDENTITY\"");
        let back: GraphScope = serde_json::from_str("\"COMMUNITY\"").unwrap();
        assert_eq!(back, GraphScope::Community);
    }

    #[test]
    fn edge_direction_serde_snake_case() {
        let s = serde_json::to_string(&EdgeDirection::Outgoing).unwrap();
        assert_eq!(s, "\"outgoing\"");
    }

    #[test]
    fn node_filter_default_empty() {
        let f = NodeFilter::default();
        assert!(f.scope.is_none());
        assert!(f.node_type.is_none());
        assert!(f.attributes_contains.is_none());
    }

    #[test]
    fn graph_node_serde_round_trip() {
        let node = GraphNode {
            node_id: "agent:datum-v3".into(),
            scope: GraphScope::Identity,
            node_type: "agent".into(),
            attributes: serde_json::json!({"role": "datum"}),
            version: 3,
            updated_by: "wa-2025-06-14-ROOT00".into(),
            updated_at: Utc::now(),
            created_at: Utc::now(),
            signature: None,
            signing_key_id: None,
            signature_verified: false,
        };
        let s = serde_json::to_string(&node).unwrap();
        let back: GraphNode = serde_json::from_str(&s).unwrap();
        assert_eq!(node, back);
    }

    #[test]
    fn traversal_config_default_per_level_limit() {
        let cfg: TraversalConfig = serde_json::from_str(
            r#"{"max_depth": 3, "edge_relationships": ["OWNS"], "direction": "outgoing"}"#,
        )
        .unwrap();
        assert_eq!(cfg.per_level_limit, 1024);
    }
}
