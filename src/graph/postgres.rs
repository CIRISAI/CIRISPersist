//! PostgreSQL impl of [`GraphService`] (v0.8.0, CIRISPersist#34).
//!
//! Backed by V013's `cirisgraph.{nodes,edges}` tables. K-hop
//! traversal uses a recursive CTE bounded by [`super::MAX_KHOP_DEPTH`]
//! plus per-level fan-out limit (AV-46). Cursor pagination follows
//! the v0.5.5 §I `(updated_at, node_id)` tuple shape.

use super::service::GraphService;
use super::types::{
    EdgeDirection, GraphEdge, GraphNode, GraphScope, KhopEntry, ListCursor, NodeFilter,
    NodeListPage, TraversalConfig,
};
use super::{Error, DEFAULT_MAX_ATTRIBUTES_BYTES, MAX_KHOP_DEPTH};
use crate::store::postgres::PostgresBackend;

// ─── helpers ────────────────────────────────────────────────────────

/// Translate tokio_postgres errors into typed [`Error`] variants.
/// SQLSTATE 23505 → Conflict; 23503 → InvalidArgument (FK); 23514 →
/// InvalidArgument (CHECK); everything else → Backend.
fn map_pg_error(e: tokio_postgres::Error, op: &str) -> Error {
    use tokio_postgres::error::SqlState;
    let code = e.as_db_error().map(|d| d.code().clone());
    let detail = e
        .as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string());
    match code {
        Some(c) if c == SqlState::UNIQUE_VIOLATION => Error::Conflict(format!("{op}: {detail}")),
        Some(c) if c == SqlState::FOREIGN_KEY_VIOLATION => {
            Error::InvalidArgument(format!("{op} FK: {detail}"))
        }
        Some(c) if c == SqlState::CHECK_VIOLATION => {
            Error::InvalidArgument(format!("{op} CHECK: {detail}"))
        }
        _ => Error::Backend(format!("{op}: {detail}")),
    }
}

/// AV-45 attribute-size guard. Caller-tunable via
/// `CIRIS_PERSIST_GRAPH_MAX_ATTRIBUTES_BYTES`; falls back to
/// [`DEFAULT_MAX_ATTRIBUTES_BYTES`] (1 MiB).
fn max_attributes_bytes() -> usize {
    std::env::var("CIRIS_PERSIST_GRAPH_MAX_ATTRIBUTES_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_ATTRIBUTES_BYTES)
}

/// AV-45: serialize the attributes to JSON bytes once, return them
/// plus the parsed [`serde_json::Value`] for the DB binding. Refuses
/// payloads above the configured size cap unless `bulk_import` is
/// true (v1.3.2, CIRISPersist#50 — migration-only escape hatch).
fn encode_attributes(
    attrs: &serde_json::Value,
    bulk_import: bool,
) -> Result<serde_json::Value, Error> {
    let serialized = serde_json::to_vec(attrs)
        .map_err(|e| Error::Internal(format!("attributes serialize: {e}")))?;
    let cap = max_attributes_bytes();
    if !bulk_import && serialized.len() > cap {
        return Err(Error::AttributesTooLarge {
            bytes: serialized.len(),
            cap,
        });
    }
    Ok(attrs.clone())
}

fn direction_clause(direction: EdgeDirection) -> &'static str {
    match direction {
        EdgeDirection::Outgoing => "source_node_id = $1 AND scope = $2",
        EdgeDirection::Incoming => "target_node_id = $1 AND scope = $2",
        EdgeDirection::Both => "(source_node_id = $1 OR target_node_id = $1) AND scope = $2",
    }
}

/// Decode one row from a `SELECT * FROM cirisgraph.nodes` query.
/// Uses positional column access for compile-time stability against
/// schema additions.
fn decode_node_row(row: &tokio_postgres::Row) -> Result<GraphNode, Error> {
    let scope_str: String = row
        .try_get("scope")
        .map_err(|e| Error::Backend(format!("decode scope: {e}")))?;
    let scope = GraphScope::from_sql_str(&scope_str)
        .ok_or_else(|| Error::Backend(format!("unknown scope: {scope_str}")))?;
    Ok(GraphNode {
        node_id: row
            .try_get("node_id")
            .map_err(|e| Error::Backend(format!("decode node_id: {e}")))?,
        scope,
        node_type: row
            .try_get("node_type")
            .map_err(|e| Error::Backend(format!("decode node_type: {e}")))?,
        attributes: row
            .try_get("attributes")
            .map_err(|e| Error::Backend(format!("decode attributes: {e}")))?,
        version: row
            .try_get("version")
            .map_err(|e| Error::Backend(format!("decode version: {e}")))?,
        updated_by: row
            .try_get("updated_by")
            .map_err(|e| Error::Backend(format!("decode updated_by: {e}")))?,
        updated_at: row
            .try_get("updated_at")
            .map_err(|e| Error::Backend(format!("decode updated_at: {e}")))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?,
        signature: row
            .try_get("signature")
            .map_err(|e| Error::Backend(format!("decode signature: {e}")))?,
        signing_key_id: row
            .try_get("signing_key_id")
            .map_err(|e| Error::Backend(format!("decode signing_key_id: {e}")))?,
        signature_verified: row
            .try_get("signature_verified")
            .map_err(|e| Error::Backend(format!("decode signature_verified: {e}")))?,
    })
}

fn decode_edge_row(row: &tokio_postgres::Row) -> Result<GraphEdge, Error> {
    let scope_str: String = row
        .try_get("scope")
        .map_err(|e| Error::Backend(format!("decode edge scope: {e}")))?;
    let scope = GraphScope::from_sql_str(&scope_str)
        .ok_or_else(|| Error::Backend(format!("unknown edge scope: {scope_str}")))?;
    let edge_uuid: uuid::Uuid = row
        .try_get("edge_id")
        .map_err(|e| Error::Backend(format!("decode edge_id: {e}")))?;
    Ok(GraphEdge {
        edge_id: edge_uuid.to_string(),
        source_node_id: row
            .try_get("source_node_id")
            .map_err(|e| Error::Backend(format!("decode source: {e}")))?,
        target_node_id: row
            .try_get("target_node_id")
            .map_err(|e| Error::Backend(format!("decode target: {e}")))?,
        scope,
        relationship: row
            .try_get("relationship")
            .map_err(|e| Error::Backend(format!("decode relationship: {e}")))?,
        weight: row
            .try_get("weight")
            .map_err(|e| Error::Backend(format!("decode weight: {e}")))?,
        attributes: row
            .try_get("attributes")
            .map_err(|e| Error::Backend(format!("decode edge attributes: {e}")))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| Error::Backend(format!("decode edge created_at: {e}")))?,
    })
}

// ─── GraphService impl ──────────────────────────────────────────────

impl GraphService for PostgresBackend {
    async fn upsert_node(
        &self,
        node: GraphNode,
        expected_version: i32,
        bulk_import: bool,
    ) -> Result<(), Error> {
        if expected_version < 0 {
            return Err(Error::InvalidArgument(
                "expected_version must be >= 0".into(),
            ));
        }
        if node.version < 1 {
            return Err(Error::InvalidArgument("node.version must be >= 1".into()));
        }
        let attrs = encode_attributes(&node.attributes, bulk_import)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;

        // AV-48: optimistic-concurrency gate. The UPSERT only fires
        // when no row exists yet (expected_version = 0) OR the
        // current row's version matches expected_version. Mismatch
        // returns affected=0; we map that to Error::Conflict.
        //
        // v1.3.1 (CIRISPersist#49): honor caller-supplied timestamps
        // verbatim. The pre-v1.3.1 SQL used `NOW()` for both INSERT
        // and ON CONFLICT updated_at, which destroyed temporal
        // ordering on bulk historical imports (CIRISAgent 2.9.0
        // cutover migrating legacy graph_nodes rows). `node.updated_at`
        // and `node.created_at` are now passed through.
        let sql = "\
            INSERT INTO cirisgraph.nodes (\
                node_id, scope, node_type, attributes, version, \
                updated_by, updated_at, created_at, signature, signing_key_id, \
                signature_verified, persist_row_hash\
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
            ON CONFLICT (node_id, scope) DO UPDATE SET \
                node_type = EXCLUDED.node_type, \
                attributes = EXCLUDED.attributes, \
                version = cirisgraph.nodes.version + 1, \
                updated_by = EXCLUDED.updated_by, \
                updated_at = EXCLUDED.updated_at, \
                signature = EXCLUDED.signature, \
                signing_key_id = EXCLUDED.signing_key_id, \
                signature_verified = EXCLUDED.signature_verified, \
                persist_row_hash = EXCLUDED.persist_row_hash \
            WHERE cirisgraph.nodes.version = $13";

        // For new rows (expected_version=0) the WHERE clause on the
        // ON CONFLICT branch evaluates against the existing row's
        // version — and since there IS no existing row, ON CONFLICT
        // doesn't fire, the INSERT lands. For existing rows the
        // WHERE pins version-match.
        let scope_str = node.scope.as_sql_str();
        let signature_verified = node.signature_verified;
        let persist_row_hash: Option<&str> = node.signature.as_deref(); // placeholder; canonical hash in v0.8.0.x
        let affected = client
            .execute(
                sql,
                &[
                    &node.node_id,
                    &scope_str,
                    &node.node_type,
                    &attrs,
                    &node.version,
                    &node.updated_by,
                    &node.updated_at,
                    &node.created_at,
                    &node.signature,
                    &node.signing_key_id,
                    &signature_verified,
                    &persist_row_hash,
                    &expected_version,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "upsert_node"))?;
        if affected == 0 {
            return Err(Error::Conflict(format!(
                "version mismatch: expected_version={expected_version} did not match current row \
                 (or insert raced with concurrent writer)"
            )));
        }
        Ok(())
    }

    async fn upsert_edge(&self, edge: GraphEdge, bulk_import: bool) -> Result<(), Error> {
        let edge_uuid: uuid::Uuid = edge
            .edge_id
            .parse()
            .map_err(|e| Error::InvalidArgument(format!("edge_id parse: {e}")))?;
        let attrs = encode_attributes(&edge.attributes, bulk_import)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // v1.3.1 (CIRISPersist#49): honor caller-supplied
        // `edge.created_at` for bulk historical imports. ON CONFLICT
        // DO NOTHING — edges are insert-only; existing rows keep
        // their original created_at.
        client
            .execute(
                "INSERT INTO cirisgraph.edges (\
                    edge_id, source_node_id, target_node_id, scope, \
                    relationship, weight, attributes, created_at\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT (edge_id) DO NOTHING",
                &[
                    &edge_uuid,
                    &edge.source_node_id,
                    &edge.target_node_id,
                    &edge.scope.as_sql_str(),
                    &edge.relationship,
                    &edge.weight,
                    &attrs,
                    &edge.created_at,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "upsert_edge"))?;
        Ok(())
    }

    async fn delete_node(
        &self,
        node_id: &str,
        scope: GraphScope,
        hard: bool,
    ) -> Result<bool, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        if hard {
            // Application-layer cascade: delete edges first, then the
            // node. (V013 has no FK; the schema permits dangling
            // edges, but hard delete should sweep them.)
            client
                .execute(
                    "DELETE FROM cirisgraph.edges WHERE \
                     (source_node_id = $1 OR target_node_id = $1) AND scope = $2",
                    &[&node_id, &scope.as_sql_str()],
                )
                .await
                .map_err(|e| map_pg_error(e, "delete_node (edges)"))?;
            let n = client
                .execute(
                    "DELETE FROM cirisgraph.nodes WHERE node_id = $1 AND scope = $2",
                    &[&node_id, &scope.as_sql_str()],
                )
                .await
                .map_err(|e| map_pg_error(e, "delete_node"))?;
            Ok(n > 0)
        } else {
            // Soft delete: mark via JSONB attribute `_deleted = true`.
            // Caller queries with `attributes_contains: {"_deleted": true}`
            // to find tombstones.
            let n = client
                .execute(
                    "UPDATE cirisgraph.nodes SET \
                        attributes = jsonb_set(attributes, '{_deleted}', 'true'::jsonb), \
                        version = version + 1, \
                        updated_at = NOW() \
                     WHERE node_id = $1 AND scope = $2",
                    &[&node_id, &scope.as_sql_str()],
                )
                .await
                .map_err(|e| map_pg_error(e, "soft delete_node"))?;
            Ok(n > 0)
        }
    }

    async fn get_node(&self, node_id: &str, scope: GraphScope) -> Result<Option<GraphNode>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT node_id, scope, node_type, attributes, version, \
                        updated_by, updated_at, created_at, \
                        signature, signing_key_id, signature_verified \
                 FROM cirisgraph.nodes \
                 WHERE node_id = $1 AND scope = $2",
                &[&node_id, &scope.as_sql_str()],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_node"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_node_row(&row)?)),
        }
    }

    async fn get_edges_for_node(
        &self,
        node_id: &str,
        scope: GraphScope,
        direction: EdgeDirection,
        relationship_filter: Option<&[String]>,
    ) -> Result<Vec<GraphEdge>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let where_dir = direction_clause(direction);
        let scope_str = scope.as_sql_str();
        let rows = match relationship_filter {
            None | Some([]) => {
                let sql = format!(
                    "SELECT edge_id, source_node_id, target_node_id, scope, \
                            relationship, weight, attributes, created_at \
                     FROM cirisgraph.edges \
                     WHERE {where_dir} \
                     ORDER BY created_at DESC"
                );
                client
                    .query(&sql, &[&node_id, &scope_str])
                    .await
                    .map_err(|e| map_pg_error(e, "get_edges_for_node"))?
            }
            Some(rels) => {
                let rels_owned: Vec<String> = rels.to_vec();
                let sql = format!(
                    "SELECT edge_id, source_node_id, target_node_id, scope, \
                            relationship, weight, attributes, created_at \
                     FROM cirisgraph.edges \
                     WHERE {where_dir} AND relationship = ANY($3::text[]) \
                     ORDER BY created_at DESC"
                );
                client
                    .query(&sql, &[&node_id, &scope_str, &rels_owned])
                    .await
                    .map_err(|e| map_pg_error(e, "get_edges_for_node (filtered)"))?
            }
        };
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(decode_edge_row(row)?);
        }
        Ok(out)
    }

    async fn traverse_k_hop(
        &self,
        start_node_id: &str,
        scope: GraphScope,
        cfg: TraversalConfig,
    ) -> Result<Vec<KhopEntry>, Error> {
        // AV-46: depth + relationship-allow-list bounds enforced
        // BEFORE the CTE runs.
        if cfg.max_depth == 0 {
            return Err(Error::InvalidArgument("max_depth must be >= 1".into()));
        }
        if cfg.max_depth > MAX_KHOP_DEPTH {
            return Err(Error::InvalidArgument(format!(
                "max_depth {} exceeds bound MAX_KHOP_DEPTH={}",
                cfg.max_depth, MAX_KHOP_DEPTH
            )));
        }
        if cfg.edge_relationships.is_empty() {
            return Err(Error::InvalidArgument(
                "edge_relationships must be non-empty (no wildcard traversal)".into(),
            ));
        }
        if cfg.per_level_limit == 0 {
            return Err(Error::InvalidArgument(
                "per_level_limit must be >= 1".into(),
            ));
        }

        let direction_edge_predicate = match cfg.direction {
            EdgeDirection::Outgoing => {
                "e.source_node_id = f.node_id AND e.scope = $2 AND e.relationship = ANY($3::text[])"
            }
            EdgeDirection::Incoming => {
                "e.target_node_id = f.node_id AND e.scope = $2 AND e.relationship = ANY($3::text[])"
            }
            EdgeDirection::Both => {
                "(e.source_node_id = f.node_id OR e.target_node_id = f.node_id) AND e.scope = $2 \
                 AND e.relationship = ANY($3::text[])"
            }
        };
        let next_node_expr = match cfg.direction {
            EdgeDirection::Outgoing => "e.target_node_id",
            EdgeDirection::Incoming => "e.source_node_id",
            EdgeDirection::Both => {
                "CASE WHEN e.source_node_id = f.node_id THEN e.target_node_id ELSE e.source_node_id END"
            }
        };

        // Recursive CTE: BFS from start_node out to max_depth hops,
        // bounded by per_level_limit at each step.
        let max_depth_i32 = cfg.max_depth as i32;
        let per_level_i64 = cfg.per_level_limit as i64;
        let scope_str = scope.as_sql_str();
        let sql = format!(
            "WITH RECURSIVE frontier AS (\
                SELECT node_id, scope, 0 AS depth \
                FROM cirisgraph.nodes \
                WHERE node_id = $1 AND scope = $2 \
              UNION \
                SELECT next_node_id, $2 AS scope, depth + 1 AS depth FROM (\
                    SELECT {next_node_expr} AS next_node_id, f.depth \
                    FROM frontier f \
                    JOIN cirisgraph.edges e ON {direction_edge_predicate} \
                    WHERE f.depth < $4 \
                    LIMIT $5\
                ) AS step\
            ) \
            SELECT n.node_id, n.scope, n.node_type, n.attributes, n.version, \
                   n.updated_by, n.updated_at, n.created_at, \
                   n.signature, n.signing_key_id, n.signature_verified, \
                   MIN(f.depth) AS depth \
            FROM frontier f \
            JOIN cirisgraph.nodes n ON n.node_id = f.node_id AND n.scope = f.scope \
            GROUP BY n.node_id, n.scope, n.node_type, n.attributes, n.version, \
                     n.updated_by, n.updated_at, n.created_at, \
                     n.signature, n.signing_key_id, n.signature_verified \
            ORDER BY depth ASC, n.node_id ASC"
        );
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                &sql,
                &[
                    &start_node_id,
                    &scope_str,
                    &cfg.edge_relationships,
                    &max_depth_i32,
                    &per_level_i64,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "traverse_k_hop"))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            let depth: i32 = row
                .try_get("depth")
                .map_err(|e| Error::Backend(format!("decode khop depth: {e}")))?;
            let node = decode_node_row(row)?;
            out.push(KhopEntry {
                node,
                depth: depth as usize,
            });
        }
        Ok(out)
    }

    async fn query_nodes(
        &self,
        filter: NodeFilter,
        cursor: Option<ListCursor>,
        limit: i64,
    ) -> Result<NodeListPage, Error> {
        // AV-47: scope is required (no implicit "all scopes" reads).
        let scope = filter
            .scope
            .ok_or_else(|| Error::InvalidArgument("NodeFilter.scope is required (AV-47)".into()))?;
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }

        let mut where_parts: Vec<String> = vec!["scope = $1".to_string()];
        let scope_str = scope.as_sql_str().to_string();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> =
            vec![Box::new(scope_str)];

        if let Some(nt) = filter.node_type {
            params.push(Box::new(nt));
            where_parts.push(format!("node_type = ${}", params.len()));
        }
        if let Some(contains) = filter.attributes_contains {
            params.push(Box::new(contains));
            where_parts.push(format!("attributes @> ${}", params.len()));
        }
        if let Some(after) = filter.updated_after {
            params.push(Box::new(after));
            where_parts.push(format!("updated_at >= ${}", params.len()));
        }
        if let Some(before) = filter.updated_before {
            params.push(Box::new(before));
            where_parts.push(format!("updated_at <= ${}", params.len()));
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "ListCursor version {} unsupported (expected v1)",
                    cur.version
                )));
            }
            params.push(Box::new(cur.last_ts));
            let p_ts = params.len();
            params.push(Box::new(cur.last_id.clone()));
            let p_id = params.len();
            where_parts.push(format!("(updated_at, node_id) < (${p_ts}, ${p_id})"));
        }
        params.push(Box::new(limit));
        let p_limit = params.len();
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT node_id, scope, node_type, attributes, version, \
                    updated_by, updated_at, created_at, \
                    signature, signing_key_id, signature_verified \
             FROM cirisgraph.nodes \
             WHERE {where_sql} \
             ORDER BY updated_at DESC, node_id DESC \
             LIMIT ${p_limit}"
        );

        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| map_pg_error(e, "query_nodes"))?;
        let mut items: Vec<GraphNode> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(decode_node_row(row)?);
        }
        let next_cursor = if items.len() == limit as usize {
            items
                .last()
                .map(|last| ListCursor::from_trailing(last.updated_at, last.node_id.clone()))
        } else {
            None
        };
        Ok(NodeListPage { items, next_cursor })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    fn fixture_node(node_id: &str, scope: GraphScope, node_type: &str) -> GraphNode {
        GraphNode {
            node_id: node_id.to_owned(),
            scope,
            node_type: node_type.to_owned(),
            attributes: serde_json::json!({"created_in": "test"}),
            version: 1,
            updated_by: "test-runner".into(),
            updated_at: now(),
            created_at: now(),
            signature: None,
            signing_key_id: None,
            signature_verified: false,
        }
    }

    fn fixture_edge(src: &str, dst: &str, scope: GraphScope, rel: &str) -> GraphEdge {
        GraphEdge {
            edge_id: Uuid::new_v4().to_string(),
            source_node_id: src.to_owned(),
            target_node_id: dst.to_owned(),
            scope,
            relationship: rel.to_owned(),
            weight: None,
            attributes: serde_json::json!({}),
            created_at: now(),
        }
    }

    /// v0.8.0 (CIRISPersist#34) — end-to-end round trip:
    /// upsert → get → upsert-with-version-conflict → query → edges → k-hop.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn cirisgraph_round_trip_full_lifecycle() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let suffix = Uuid::new_v4().simple().to_string();
        let n_a = format!("test:a-{suffix}");
        let n_b = format!("test:b-{suffix}");
        let n_c = format!("test:c-{suffix}");

        // 1. Insert 3 nodes (expected_version=0 for new rows).
        for nid in [&n_a, &n_b, &n_c] {
            backend
                .upsert_node(fixture_node(nid, GraphScope::Local, "test"), 0, false)
                .await
                .unwrap();
        }

        // 2. get_node round-trip.
        let got = backend
            .get_node(&n_a, GraphScope::Local)
            .await
            .unwrap()
            .expect("node a present");
        assert_eq!(got.node_id, n_a);
        assert_eq!(got.scope, GraphScope::Local);
        assert_eq!(got.version, 1);

        // 3. AV-48: version conflict on stale update.
        let conflict = backend
            .upsert_node(fixture_node(&n_a, GraphScope::Local, "test"), 0, false)
            .await
            .unwrap_err();
        assert!(
            matches!(conflict, Error::Conflict(_)),
            "expected Conflict on expected_version=0 for existing row, got {conflict:?}"
        );

        // 4. Update with correct expected_version succeeds.
        let mut updated = got.clone();
        updated.attributes = serde_json::json!({"updated": true});
        backend.upsert_node(updated, 1, false).await.unwrap();
        let post = backend
            .get_node(&n_a, GraphScope::Local)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(post.version, 2);

        // 5. AV-45: oversized attributes reject.
        let mut huge = fixture_node(&format!("test:huge-{suffix}"), GraphScope::Local, "test");
        let big_string = "x".repeat(2 * 1024 * 1024); // 2 MiB > 1 MiB default cap
        huge.attributes = serde_json::json!({"payload": big_string});
        let too_big = backend.upsert_node(huge, 0, false).await.unwrap_err();
        assert!(
            // v1.3.2 (CIRISPersist#50): AV-45 now surfaces as the
            // typed `AttributesTooLarge { bytes, cap }` variant.
            matches!(too_big, Error::AttributesTooLarge { .. }),
            "expected InvalidArgument on oversized attributes, got {too_big:?}"
        );

        // 6. Edges: a -OWNS-> b -OWNS-> c -SUMMARIZES-> a (cycle).
        backend
            .upsert_edge(fixture_edge(&n_a, &n_b, GraphScope::Local, "OWNS"), false)
            .await
            .unwrap();
        backend
            .upsert_edge(fixture_edge(&n_b, &n_c, GraphScope::Local, "OWNS"), false)
            .await
            .unwrap();
        backend
            .upsert_edge(
                fixture_edge(&n_c, &n_a, GraphScope::Local, "SUMMARIZES"),
                false,
            )
            .await
            .unwrap();

        // 7. get_edges_for_node directional.
        let out = backend
            .get_edges_for_node(&n_a, GraphScope::Local, EdgeDirection::Outgoing, None)
            .await
            .unwrap();
        assert_eq!(out.len(), 1, "a has one outgoing edge (to b)");
        let in_ = backend
            .get_edges_for_node(&n_a, GraphScope::Local, EdgeDirection::Incoming, None)
            .await
            .unwrap();
        assert_eq!(in_.len(), 1, "a has one incoming edge (from c)");
        let both = backend
            .get_edges_for_node(&n_a, GraphScope::Local, EdgeDirection::Both, None)
            .await
            .unwrap();
        assert_eq!(both.len(), 2);

        // 8. Relationship filter.
        let only_summarizes = backend
            .get_edges_for_node(
                &n_a,
                GraphScope::Local,
                EdgeDirection::Both,
                Some(&["SUMMARIZES".to_owned()]),
            )
            .await
            .unwrap();
        assert_eq!(only_summarizes.len(), 1);
        assert_eq!(only_summarizes[0].relationship, "SUMMARIZES");

        // 9. AV-46: k-hop bounds enforced.
        let bad_depth = backend
            .traverse_k_hop(
                &n_a,
                GraphScope::Local,
                TraversalConfig {
                    max_depth: MAX_KHOP_DEPTH + 1,
                    edge_relationships: vec!["OWNS".into()],
                    direction: EdgeDirection::Outgoing,
                    per_level_limit: 1024,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(bad_depth, Error::InvalidArgument(_)));
        let empty_rels = backend
            .traverse_k_hop(
                &n_a,
                GraphScope::Local,
                TraversalConfig {
                    max_depth: 3,
                    edge_relationships: vec![],
                    direction: EdgeDirection::Outgoing,
                    per_level_limit: 1024,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(empty_rels, Error::InvalidArgument(_)));

        // 10. Real 2-hop traverse: a -OWNS-> b -OWNS-> c.
        let khop = backend
            .traverse_k_hop(
                &n_a,
                GraphScope::Local,
                TraversalConfig {
                    max_depth: 3,
                    edge_relationships: vec!["OWNS".into()],
                    direction: EdgeDirection::Outgoing,
                    per_level_limit: 1024,
                },
            )
            .await
            .unwrap();
        // Reach a (depth=0), b (depth=1), c (depth=2). Order by depth ASC.
        assert_eq!(khop.len(), 3);
        assert_eq!(khop[0].depth, 0);
        assert_eq!(khop[0].node.node_id, n_a);
        assert!(khop.iter().any(|e| e.node.node_id == n_b && e.depth == 1));
        assert!(khop.iter().any(|e| e.node.node_id == n_c && e.depth == 2));

        // 11. query_nodes with scope + type filter.
        let page = backend
            .query_nodes(
                NodeFilter {
                    scope: Some(GraphScope::Local),
                    node_type: Some("test".into()),
                    attributes_contains: None,
                    updated_after: None,
                    updated_before: None,
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert!(page.items.len() >= 3, "at least our 3 fixtures present");

        // 12. AV-47: query_nodes refuses None scope.
        let no_scope = backend
            .query_nodes(NodeFilter::default(), None, 10)
            .await
            .unwrap_err();
        assert!(matches!(no_scope, Error::InvalidArgument(_)));

        // 13. delete_node hard cascade.
        let deleted = backend
            .delete_node(&n_a, GraphScope::Local, true)
            .await
            .unwrap();
        assert!(deleted);
        let gone = backend.get_node(&n_a, GraphScope::Local).await.unwrap();
        assert!(gone.is_none(), "hard-deleted node should be gone");
    }
}
