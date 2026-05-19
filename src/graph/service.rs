//! `GraphService` trait surface (v0.8.0, CIRISPersist#34).
//!
//! 7 methods: 3 typed-writes + 4 reads. Same `impl Future<...> + Send`
//! GAT pattern as `NodeCoreService` / `SecretsService` — no
//! `async_trait` dep.
//!
//! # Threat-model anchors (THREAT_MODEL.md §4)
//!
//! - **AV-45** — attributes-JSONB size cap enforced at
//!   `upsert_node` entry; default `super::DEFAULT_MAX_ATTRIBUTES_BYTES`.
//! - **AV-46** — k-hop depth bounded at `super::MAX_KHOP_DEPTH`;
//!   `traverse_k_hop` rejects above-cap depth or empty
//!   relationship allow-list.
//! - **AV-47** — every read method takes `scope` non-optionally;
//!   `query_nodes` returns `Error::InvalidArgument` if the filter's
//!   `scope` is `None` (no implicit "all scopes" reads).
//! - **AV-48** — `upsert_node` requires `expected_version` matching
//!   the current row's `version`; mismatch → `Error::Conflict`.

use std::future::Future;

use super::types::{
    EdgeDirection, GraphEdge, GraphNode, GraphScope, KhopEntry, ListCursor, NodeFilter,
    NodeListPage, TraversalConfig,
};
use super::Error;

/// cirisgraph trait surface. 3 typed-writes + 4 reads per FSD-graph
/// §1.
///
/// # `expected_version` semantics on writes
///
/// New rows: caller passes `expected_version = 0`. Persist
/// INSERTs at `version = 1`. Existing rows: caller reads the
/// current row (sees `version = N`), passes `expected_version = N`
/// on write; persist UPSERTs at `version = N + 1`. Mismatch
/// (concurrent writer raced ahead) → `Error::Conflict`.
pub trait GraphService: Send + Sync {
    // ── Typed writes ────────────────────────────────────────────

    /// Verify-and-insert (or update) a graph node. AV-48 optimistic-
    /// concurrency gate: pass `expected_version = 0` for new rows
    /// or the current row's `version` for updates. AV-45: rejects
    /// when serialized attributes exceed the configured size cap —
    /// unless `bulk_import = true` (v1.3.2, CIRISPersist#50), which
    /// skips the cap for one-time historical migration. Use sparingly
    /// — the cap is a load-bearing safety check on the hot path.
    fn upsert_node(
        &self,
        node: GraphNode,
        expected_version: i32,
        bulk_import: bool,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Insert a directed edge. Idempotent on `edge_id` PK; collision
    /// surfaces as `Error::Conflict` (caller decides whether to
    /// treat as no-op). `bulk_import` mirrors `upsert_node` semantics
    /// for symmetry — edges have no attributes-size cap today, so
    /// the flag is a no-op currently but reserved.
    fn upsert_edge(
        &self,
        edge: GraphEdge,
        bulk_import: bool,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Soft- or hard-delete a node. Hard delete also removes any
    /// edges that name the node as source or target (cascading
    /// only at the application layer, not via schema FK — the V013
    /// migration permits dangling edges by design).
    fn delete_node(
        &self,
        node_id: &str,
        scope: GraphScope,
        hard: bool,
    ) -> impl Future<Output = Result<bool, Error>> + Send;

    // ── Reads ───────────────────────────────────────────────────

    /// Point-lookup one node by `(node_id, scope)`. Returns
    /// `Ok(None)` if the row doesn't exist (NOT `Error::NotFound`
    /// — that variant is reserved for cases where the caller asserts
    /// the row should exist).
    fn get_node(
        &self,
        node_id: &str,
        scope: GraphScope,
    ) -> impl Future<Output = Result<Option<GraphNode>, Error>> + Send;

    /// Edges incident to one node (incoming, outgoing, or both),
    /// optionally filtered to a relationship allow-list. Returns
    /// the empty vec when no edges match — not an error.
    fn get_edges_for_node(
        &self,
        node_id: &str,
        scope: GraphScope,
        direction: EdgeDirection,
        relationship_filter: Option<&[String]>,
    ) -> impl Future<Output = Result<Vec<GraphEdge>, Error>> + Send;

    /// AV-46 bounded k-hop traversal. Walks the graph from
    /// `start_node` following only edges in `cfg.edge_relationships`,
    /// up to `cfg.max_depth` hops. Returns nodes paired with the
    /// depth at which they were first discovered (BFS shortest-
    /// path semantics).
    ///
    /// Rejects with `Error::InvalidArgument` if:
    /// - `cfg.max_depth > MAX_KHOP_DEPTH` (16 absolute cap)
    /// - `cfg.edge_relationships.is_empty()` (no wildcard reads)
    fn traverse_k_hop(
        &self,
        start_node_id: &str,
        scope: GraphScope,
        cfg: TraversalConfig,
    ) -> impl Future<Output = Result<Vec<KhopEntry>, Error>> + Send;

    /// Cursor-paged node listing. Newest-first by `updated_at`;
    /// cursor shape matches v0.5.5 §I `ListCursor`. Filter MUST
    /// name a scope (AV-47).
    fn query_nodes(
        &self,
        filter: NodeFilter,
        cursor: Option<ListCursor>,
        limit: i64,
    ) -> impl Future<Output = Result<NodeListPage, Error>> + Send;

    // ── Count primitives (v1.5.25, CIRISPersist#65) ─────────────

    /// v1.5.25 — Count nodes matching the filter. Honors all
    /// `NodeFilter` keys including the v1.5.25 `exclude` rule.
    /// Filter MUST name a scope (AV-47).
    fn count_nodes(&self, filter: NodeFilter) -> impl Future<Output = Result<u64, Error>> + Send;

    /// v1.5.25 — Count edges within a scope. Hot-path observation:
    /// the agent's API routes need a total-edges figure for
    /// dashboard tiles; this is a single
    /// `SELECT COUNT(*) FROM graph_edges WHERE scope = $1` and
    /// fires the existing `(scope, …)` indexes.
    fn count_edges(&self, scope: GraphScope) -> impl Future<Output = Result<u64, Error>> + Send;

    /// v1.5.25 — Group-by-type histogram of nodes in a scope.
    /// Returns a map `{node_type: count}` for the dashboard
    /// "memory composition by type" tile. Filter MUST name a scope
    /// (AV-47).
    fn count_nodes_by_type(
        &self,
        scope: GraphScope,
    ) -> impl Future<Output = Result<std::collections::HashMap<String, u64>, Error>> + Send;
}
