//! SQLite impl of [`LegacyMigrationService`] (v1.6.4, CIRISPersist#70).
//!
//! Mirrors the PG impl with the SQLite-specific dialect adjustments:
//!
//! - No schema namespace — `options.legacy_schema != "public"` is
//!   rejected with `Error::InvalidArgument` (SQLite can't honor it).
//! - Legacy tables may be absent (fresh installs that never ran
//!   the 2.8.x agent). We probe `sqlite_master` first and return a
//!   zeroed-counter `outcome = "ok"` if they're not there.
//! - Datetimes arrive as `TEXT` (RFC 3339 or the legacy
//!   `'YYYY-MM-DD HH:MM:SS'` `CURRENT_TIMESTAMP` default). We
//!   normalize the latter to RFC 3339 before parsing.
//! - Attributes arrive as `TEXT`; we parse to `serde_json::Value`
//!   for the upsert call.
//!
//! Threading: `tokio::task::spawn_blocking` + `conn.blocking_lock()`
//! per the existing pattern. The read loop is one blocking task;
//! each per-row write is its own async call (because
//! [`crate::graph::sqlite::SqliteGraphBackend::upsert_node`] itself
//! goes through spawn_blocking).

use std::collections::HashSet;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use tokio::sync::Mutex;

use super::service::LegacyMigrationService;
use super::types::{LegacyMigrationOptions, LegacyMigrationStats};
use super::Error;
use crate::graph;

/// One legacy node row pulled from `graph_nodes`. Carries the raw
/// SQLite-side strings + parsed pieces; the upsert call materializes
/// the final `GraphNode` per the per-row decision tree.
struct LegacyNodeRow {
    node_id: String,
    scope_raw: String,
    node_type: String,
    attributes_text: Option<String>,
    version: Option<i32>,
    updated_by: Option<String>,
    updated_at_str: Option<String>,
    created_at_str: String,
}

/// One legacy edge row pulled from `graph_edges`.
struct LegacyEdgeRow {
    edge_id: String,
    source_node_id: String,
    target_node_id: String,
    scope_raw: String,
    relationship: String,
    weight: Option<f64>,
    attributes_text: Option<String>,
    created_at_str: String,
}

/// SQLite-backed [`LegacyMigrationService`] impl. Holds a shared
/// connection handle so it can share the same SQLite file/in-memory
/// connection as [`crate::store::sqlite::SqliteBackend`].
pub struct SqliteLegacyMigrationBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteLegacyMigrationBackend {
    /// Construct from an existing connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    Error::Backend(format!("{op}: {e}"))
}

/// Normalize the legacy SQLite datetime (which may be
/// `CURRENT_TIMESTAMP`'s `YYYY-MM-DD HH:MM:SS` form, RFC 3339, or
/// some other free-form text) to a parseable `DateTime<Utc>`.
fn parse_legacy_datetime(s: &str) -> Result<DateTime<Utc>, Error> {
    let normalized = if s.contains('T') {
        s.to_owned()
    } else {
        // `YYYY-MM-DD HH:MM:SS` -> `YYYY-MM-DDTHH:MM:SS+00:00`
        format!("{}+00:00", s.replacen(' ', "T", 1))
    };
    chrono::DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::Backend(format!("datetime parse: {e} (raw={s})")))
}

fn normalize_scope_str(raw: &str) -> Result<graph::GraphScope, Error> {
    let upper = raw.to_uppercase();
    graph::GraphScope::from_sql_str(&upper)
        .ok_or_else(|| Error::InvalidArgument(format!("unknown legacy scope: {raw:?}")))
}

fn parse_attrs(text: Option<&str>) -> Result<serde_json::Value, Error> {
    match text {
        None | Some("") => Ok(serde_json::Value::Object(Default::default())),
        Some(s) => serde_json::from_str(s)
            .map_err(|e| Error::Backend(format!("attributes JSON decode: {e}"))),
    }
}

/// Synchronously read every legacy node row inside a spawn_blocking
/// task. Returns the parsed Vec or a `Backend` error on read fail.
async fn read_legacy_nodes(conn: &Arc<Mutex<Connection>>) -> Result<Vec<LegacyNodeRow>, Error> {
    let conn = conn.clone();
    tokio::task::spawn_blocking(move || -> Result<Vec<LegacyNodeRow>, Error> {
        let guard = conn.blocking_lock();
        // 8-column shape per CIRISAgent's pre-v2.9.0 schema. The
        // signature envelope columns are NOT read — they're set to
        // None/false on the write side (cirisgraph.nodes carries
        // them as nullable).
        let mut stmt = guard
            .prepare(
                "SELECT node_id, scope, node_type, attributes_json, version, \
                        updated_by, updated_at, created_at \
                 FROM graph_nodes",
            )
            .map_err(|e| map_sqlite_error(e, "prepare graph_nodes"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(LegacyNodeRow {
                    node_id: row.get::<_, String>("node_id")?,
                    scope_raw: row.get::<_, String>("scope")?,
                    node_type: row.get::<_, String>("node_type")?,
                    attributes_text: row.get::<_, Option<String>>("attributes_json")?,
                    version: row.get::<_, Option<i32>>("version")?,
                    updated_by: row.get::<_, Option<String>>("updated_by")?,
                    updated_at_str: row.get::<_, Option<String>>("updated_at")?,
                    created_at_str: row.get::<_, String>("created_at")?,
                })
            })
            .map_err(|e| map_sqlite_error(e, "query graph_nodes"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| map_sqlite_error(e, "graph_nodes row"))?);
        }
        Ok(out)
    })
    .await
    .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
}

async fn read_legacy_edges(conn: &Arc<Mutex<Connection>>) -> Result<Vec<LegacyEdgeRow>, Error> {
    let conn = conn.clone();
    tokio::task::spawn_blocking(move || -> Result<Vec<LegacyEdgeRow>, Error> {
        let guard = conn.blocking_lock();
        let mut stmt = guard
            .prepare(
                "SELECT edge_id, source_node_id, target_node_id, scope, \
                        relationship, weight, attributes_json, created_at \
                 FROM graph_edges",
            )
            .map_err(|e| map_sqlite_error(e, "prepare graph_edges"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok(LegacyEdgeRow {
                    edge_id: row.get::<_, String>("edge_id")?,
                    source_node_id: row.get::<_, String>("source_node_id")?,
                    target_node_id: row.get::<_, String>("target_node_id")?,
                    scope_raw: row.get::<_, String>("scope")?,
                    relationship: row.get::<_, String>("relationship")?,
                    weight: row.get::<_, Option<f64>>("weight")?,
                    attributes_text: row.get::<_, Option<String>>("attributes_json")?,
                    created_at_str: row.get::<_, String>("created_at")?,
                })
            })
            .map_err(|e| map_sqlite_error(e, "query graph_edges"))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r.map_err(|e| map_sqlite_error(e, "graph_edges row"))?);
        }
        Ok(out)
    })
    .await
    .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
}

/// Probe `sqlite_master` for a table by name. Used to detect
/// "fresh install, no legacy data" so we can return a graceful
/// zeroed `outcome = "ok"` instead of failing the read SQL.
async fn legacy_table_exists(conn: &Arc<Mutex<Connection>>, name: &str) -> Result<bool, Error> {
    let conn = conn.clone();
    let name = name.to_owned();
    tokio::task::spawn_blocking(move || -> Result<bool, Error> {
        let guard = conn.blocking_lock();
        let exists: bool = guard
            .query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?1",
                params![name],
                |_| Ok(true),
            )
            .or_else(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => Ok(false),
                other => Err(map_sqlite_error(other, "probe sqlite_master")),
            })?;
        Ok(exists)
    })
    .await
    .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
}

/// Snapshot present (node_id, scope) tuples in `cirisgraph_nodes`
/// for dangling-FK detection. Returns the empty set if the table
/// doesn't exist yet (caller's graph schema hasn't been migrated —
/// unusual but possible mid-bootstrap).
async fn snapshot_present_nodes(
    conn: &Arc<Mutex<Connection>>,
) -> Result<HashSet<(String, String)>, Error> {
    if !legacy_table_exists(conn, "cirisgraph_nodes").await? {
        return Ok(HashSet::new());
    }
    let conn = conn.clone();
    tokio::task::spawn_blocking(move || -> Result<HashSet<(String, String)>, Error> {
        let guard = conn.blocking_lock();
        let mut stmt = guard
            .prepare("SELECT node_id, scope FROM cirisgraph_nodes")
            .map_err(|e| map_sqlite_error(e, "prepare cirisgraph_nodes"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>("node_id")?,
                    row.get::<_, String>("scope")?,
                ))
            })
            .map_err(|e| map_sqlite_error(e, "query cirisgraph_nodes"))?;
        let mut out: HashSet<(String, String)> = HashSet::new();
        for r in rows {
            out.insert(r.map_err(|e| map_sqlite_error(e, "cirisgraph_nodes row"))?);
        }
        Ok(out)
    })
    .await
    .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
}

async fn snapshot_present_edge_ids(
    conn: &Arc<Mutex<Connection>>,
) -> Result<HashSet<String>, Error> {
    if !legacy_table_exists(conn, "cirisgraph_edges").await? {
        return Ok(HashSet::new());
    }
    let conn = conn.clone();
    tokio::task::spawn_blocking(move || -> Result<HashSet<String>, Error> {
        let guard = conn.blocking_lock();
        let mut stmt = guard
            .prepare("SELECT edge_id FROM cirisgraph_edges")
            .map_err(|e| map_sqlite_error(e, "prepare cirisgraph_edges"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>("edge_id"))
            .map_err(|e| map_sqlite_error(e, "query cirisgraph_edges"))?;
        let mut out: HashSet<String> = HashSet::new();
        for r in rows {
            out.insert(r.map_err(|e| map_sqlite_error(e, "cirisgraph_edges row"))?);
        }
        Ok(out)
    })
    .await
    .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
}

impl LegacyMigrationService for SqliteLegacyMigrationBackend {
    async fn run_legacy_graph_migration(
        &self,
        options: LegacyMigrationOptions,
    ) -> Result<LegacyMigrationStats, Error> {
        // SQLite has no schema namespace; we can't honor a
        // non-default value here, so reject up front.
        if options.legacy_schema != "public" {
            return Err(Error::InvalidArgument(format!(
                "SQLite has no schema namespace; legacy_schema must be \"public\" \
                 (got {:?})",
                options.legacy_schema
            )));
        }

        let mut stats = LegacyMigrationStats::empty();

        // Graceful no-op if the legacy tables aren't present yet —
        // fresh installs that never ran the 2.8.x agent take this
        // path so the bootstrap layer can still write its sentinel.
        let nodes_present = legacy_table_exists(&self.conn, "graph_nodes").await?;
        let edges_present = legacy_table_exists(&self.conn, "graph_edges").await?;
        if !nodes_present && !edges_present {
            stats.finalize_outcome();
            return Ok(stats);
        }

        let cap = options
            .attributes_cap_bytes
            .unwrap_or(graph::DEFAULT_MAX_ATTRIBUTES_BYTES);
        let stop_at = options.stop_after_errors.unwrap_or(100);

        // Materialize the graph backend ONCE — every per-row upsert
        // goes through it. Cheap (it's just an Arc<Mutex<Connection>>).
        use graph::GraphService;
        let graph_be = crate::graph::sqlite::SqliteGraphBackend::new(self.conn.clone());

        // ── nodes ────────────────────────────────────────────
        if nodes_present {
            let node_rows = read_legacy_nodes(&self.conn).await?;
            for row in node_rows {
                stats.nodes_read += 1;

                let scope = match normalize_scope_str(&row.scope_raw) {
                    Ok(s) => s,
                    Err(e) => {
                        stats.errors += 1;
                        if stats.first_error_at_node_id.is_none() {
                            stats.first_error_at_node_id = Some(row.node_id.clone());
                            stats.first_error_message = Some(format!("scope normalize: {e}"));
                        }
                        tracing::warn!(node_id = %row.node_id, error = %e, "scope normalize failed");
                        if stats.errors as u64 >= stop_at {
                            break;
                        }
                        continue;
                    }
                };

                let attrs_value = match parse_attrs(row.attributes_text.as_deref()) {
                    Ok(v) => v,
                    Err(e) => {
                        stats.errors += 1;
                        if stats.first_error_at_node_id.is_none() {
                            stats.first_error_at_node_id = Some(row.node_id.clone());
                            stats.first_error_message = Some(format!("attributes parse: {e}"));
                        }
                        tracing::warn!(node_id = %row.node_id, error = %e, "attributes parse failed");
                        if stats.errors as u64 >= stop_at {
                            break;
                        }
                        continue;
                    }
                };

                let serialized_len = match serde_json::to_vec(&attrs_value) {
                    Ok(buf) => buf.len(),
                    Err(e) => {
                        stats.errors += 1;
                        if stats.first_error_at_node_id.is_none() {
                            stats.first_error_at_node_id = Some(row.node_id.clone());
                            stats.first_error_message = Some(format!("attributes serialize: {e}"));
                        }
                        tracing::warn!(node_id = %row.node_id, error = %e, "attributes serialize failed");
                        if stats.errors as u64 >= stop_at {
                            break;
                        }
                        continue;
                    }
                };
                if serialized_len > cap {
                    stats.nodes_skipped_too_large += 1;
                    tracing::info!(
                        node_id = %row.node_id, bytes = serialized_len, cap = cap,
                        "legacy node attributes exceed cap, skipping"
                    );
                    continue;
                }

                if options.dry_run {
                    continue;
                }

                let created_at = match parse_legacy_datetime(&row.created_at_str) {
                    Ok(dt) => dt,
                    Err(e) => {
                        stats.errors += 1;
                        if stats.first_error_at_node_id.is_none() {
                            stats.first_error_at_node_id = Some(row.node_id.clone());
                            stats.first_error_message = Some(format!("created_at parse: {e}"));
                        }
                        tracing::warn!(node_id = %row.node_id, error = %e, "created_at parse failed");
                        if stats.errors as u64 >= stop_at {
                            break;
                        }
                        continue;
                    }
                };
                let updated_at = match row.updated_at_str.as_deref() {
                    Some(s) => parse_legacy_datetime(s).unwrap_or(created_at),
                    None => created_at,
                };

                let version = row.version.unwrap_or(1).max(1);
                let updated_by = row
                    .updated_by
                    .unwrap_or_else(|| "legacy_unattributed".to_owned());

                let node = graph::GraphNode {
                    node_id: row.node_id.clone(),
                    scope,
                    node_type: row.node_type,
                    attributes: attrs_value,
                    version,
                    updated_by,
                    updated_at,
                    created_at,
                    // 8-column legacy shape has no audit envelope —
                    // default to None / false on the write side.
                    signature: None,
                    signing_key_id: None,
                    signature_verified: false,
                };

                match graph_be.upsert_node(node, 0, true).await {
                    Ok(()) => stats.nodes_written += 1,
                    Err(graph::Error::Conflict(_)) => {
                        stats.nodes_skipped_already_present += 1;
                    }
                    Err(e) => {
                        stats.errors += 1;
                        if stats.first_error_at_node_id.is_none() {
                            stats.first_error_at_node_id = Some(row.node_id.clone());
                            stats.first_error_message = Some(format!("node upsert: {e}"));
                        }
                        tracing::warn!(node_id = %row.node_id, error = %e, "legacy node upsert failed");
                        if stats.errors as u64 >= stop_at {
                            break;
                        }
                    }
                }
            }
        }

        // ── edges ────────────────────────────────────────────
        if edges_present {
            let edge_rows = read_legacy_edges(&self.conn).await?;
            let present_nodes = snapshot_present_nodes(&self.conn).await?;
            let present_edges = snapshot_present_edge_ids(&self.conn).await?;

            for row in edge_rows {
                stats.edges_read += 1;

                if options.dry_run {
                    continue;
                }

                let scope = match normalize_scope_str(&row.scope_raw) {
                    Ok(s) => s,
                    Err(e) => {
                        stats.errors += 1;
                        tracing::warn!(edge_id = %row.edge_id, error = %e, "edge scope normalize failed");
                        if stats.errors as u64 >= stop_at {
                            break;
                        }
                        continue;
                    }
                };
                let scope_sql_str = scope.as_sql_str().to_owned();

                if !present_nodes.contains(&(row.source_node_id.clone(), scope_sql_str.clone()))
                    || !present_nodes.contains(&(row.target_node_id.clone(), scope_sql_str.clone()))
                {
                    stats.edges_skipped_dangling_fk += 1;
                    continue;
                }

                if present_edges.contains(&row.edge_id) {
                    stats.edges_skipped_already_present += 1;
                    continue;
                }

                let attrs_value = match parse_attrs(row.attributes_text.as_deref()) {
                    Ok(v) => v,
                    Err(e) => {
                        stats.errors += 1;
                        tracing::warn!(edge_id = %row.edge_id, error = %e, "edge attributes parse failed");
                        if stats.errors as u64 >= stop_at {
                            break;
                        }
                        continue;
                    }
                };

                let created_at = match parse_legacy_datetime(&row.created_at_str) {
                    Ok(dt) => dt,
                    Err(e) => {
                        stats.errors += 1;
                        tracing::warn!(edge_id = %row.edge_id, error = %e, "edge created_at parse failed");
                        if stats.errors as u64 >= stop_at {
                            break;
                        }
                        continue;
                    }
                };

                let edge = graph::GraphEdge {
                    edge_id: row.edge_id.clone(),
                    source_node_id: row.source_node_id,
                    target_node_id: row.target_node_id,
                    scope,
                    relationship: row.relationship,
                    weight: row.weight,
                    attributes: attrs_value,
                    created_at,
                };

                match graph_be.upsert_edge(edge, true).await {
                    Ok(()) => stats.edges_written += 1,
                    Err(graph::Error::InvalidArgument(detail)) if detail.contains("FK") => {
                        stats.edges_skipped_dangling_fk += 1;
                    }
                    Err(graph::Error::Conflict(_)) => {
                        stats.edges_skipped_already_present += 1;
                    }
                    Err(e) => {
                        stats.errors += 1;
                        tracing::warn!(edge_id = %row.edge_id, error = %e, "legacy edge upsert failed");
                        if stats.errors as u64 >= stop_at {
                            break;
                        }
                    }
                }
            }
        }

        stats.finalize_outcome();
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteLegacyMigrationBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteLegacyMigrationBackend::new(backend.conn_handle());
        (backend, svc)
    }

    /// Create the legacy 2.8.x SQLite-shaped tables. The legacy
    /// agent SQLite schema is the 8-column shape (no audit envelope);
    /// we add the 3 envelope columns the substrate looks for so the
    /// PG and SQLite reads share the same row shape.
    async fn ensure_legacy_tables(backend: &SqliteBackend) {
        let conn = backend.conn_handle();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            guard
                .execute_batch(
                    // 8-column shape mirrors CIRISAgent's pre-v2.9.0
                    // schema verbatim — catches regressions if anyone
                    // re-adds signature columns to the SELECT.
                    "CREATE TABLE IF NOT EXISTS graph_nodes (\
                        node_id TEXT NOT NULL,\
                        scope TEXT NOT NULL,\
                        node_type TEXT NOT NULL,\
                        attributes_json TEXT,\
                        version INTEGER DEFAULT 1,\
                        updated_by TEXT,\
                        updated_at TEXT,\
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,\
                        PRIMARY KEY (node_id, scope)\
                     );\
                     CREATE TABLE IF NOT EXISTS graph_edges (\
                        edge_id TEXT PRIMARY KEY,\
                        source_node_id TEXT NOT NULL,\
                        target_node_id TEXT NOT NULL,\
                        scope TEXT NOT NULL,\
                        relationship TEXT NOT NULL,\
                        weight REAL DEFAULT 1.0,\
                        attributes_json TEXT,\
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP\
                     );",
                )
                .unwrap();
        })
        .await
        .unwrap();
    }

    async fn seed_node(
        backend: &SqliteBackend,
        node_id: &str,
        scope: &str,
        attrs: serde_json::Value,
    ) {
        let conn = backend.conn_handle();
        let nid = node_id.to_owned();
        let sc = scope.to_owned();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO graph_nodes (node_id, scope, node_type, attributes_json, \
                        version, updated_by, updated_at, created_at\
                     ) VALUES (?1, ?2, 'agent', ?3, 1, 'legacy_unattributed', \
                               '2025-01-01T00:00:00+00:00', '2025-01-01T00:00:00+00:00')",
                    params![nid, sc, attrs.to_string()],
                )
                .unwrap();
        })
        .await
        .unwrap();
    }

    async fn seed_edge(backend: &SqliteBackend, edge_id: &str, src: &str, tgt: &str, scope: &str) {
        let conn = backend.conn_handle();
        let eid = edge_id.to_owned();
        let s = src.to_owned();
        let t = tgt.to_owned();
        let sc = scope.to_owned();
        tokio::task::spawn_blocking(move || {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO graph_edges (edge_id, source_node_id, target_node_id, \
                        scope, relationship, weight, attributes_json, created_at\
                     ) VALUES (?1, ?2, ?3, ?4, 'OWNS', 1.0, '{}', \
                               '2025-01-01T00:00:00+00:00')",
                    params![eid, s, t, sc],
                )
                .unwrap();
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn happy_path_three_nodes_two_edges_writes_all() {
        let (sqlite, svc) = fresh_backend().await;
        ensure_legacy_tables(&sqlite).await;
        seed_node(&sqlite, "n1", "local", serde_json::json!({"k": "v1"})).await;
        seed_node(&sqlite, "n2", "local", serde_json::json!({"k": "v2"})).await;
        seed_node(&sqlite, "n3", "local", serde_json::json!({"k": "v3"})).await;
        let e1 = Uuid::new_v4().to_string();
        let e2 = Uuid::new_v4().to_string();
        seed_edge(&sqlite, &e1, "n1", "n2", "local").await;
        seed_edge(&sqlite, &e2, "n2", "n3", "local").await;

        let stats = svc
            .run_legacy_graph_migration(LegacyMigrationOptions::default())
            .await
            .unwrap();
        assert_eq!(stats.outcome, "ok", "got {stats:?}");
        assert_eq!(stats.nodes_read, 3);
        assert_eq!(stats.nodes_written, 3);
        assert_eq!(stats.edges_read, 2);
        assert_eq!(stats.edges_written, 2);
        assert_eq!(stats.errors, 0);

        // Verify via GraphService — rows are really in cirisgraph_nodes.
        use graph::GraphService;
        let graph_be = graph::sqlite::SqliteGraphBackend::new(sqlite.conn_handle());
        let got = graph_be
            .get_node("n1", graph::GraphScope::Local)
            .await
            .unwrap();
        assert!(got.is_some(), "n1 should exist after migration");
    }

    #[tokio::test]
    async fn rerun_is_idempotent_existing_rows_skipped() {
        let (sqlite, svc) = fresh_backend().await;
        ensure_legacy_tables(&sqlite).await;
        seed_node(&sqlite, "n1", "local", serde_json::json!({})).await;
        seed_node(&sqlite, "n2", "local", serde_json::json!({})).await;
        seed_node(&sqlite, "n3", "local", serde_json::json!({})).await;
        let e1 = Uuid::new_v4().to_string();
        let e2 = Uuid::new_v4().to_string();
        seed_edge(&sqlite, &e1, "n1", "n2", "local").await;
        seed_edge(&sqlite, &e2, "n2", "n3", "local").await;

        let first = svc
            .run_legacy_graph_migration(LegacyMigrationOptions::default())
            .await
            .unwrap();
        assert_eq!(first.nodes_written, 3);
        assert_eq!(first.edges_written, 2);

        let second = svc
            .run_legacy_graph_migration(LegacyMigrationOptions::default())
            .await
            .unwrap();
        assert_eq!(second.nodes_skipped_already_present, 3);
        assert_eq!(second.edges_skipped_already_present, 2);
        assert_eq!(second.nodes_written, 0);
        assert_eq!(second.edges_written, 0);
        assert_eq!(second.outcome, "ok");
    }

    #[tokio::test]
    async fn oversized_attributes_skipped_not_written() {
        let (sqlite, svc) = fresh_backend().await;
        ensure_legacy_tables(&sqlite).await;
        // 1.5 MiB blob — > 1 MiB cap.
        let huge_str = "x".repeat(1_572_864);
        seed_node(
            &sqlite,
            "huge",
            "local",
            serde_json::json!({"blob": huge_str}),
        )
        .await;
        seed_node(&sqlite, "small", "local", serde_json::json!({})).await;

        let stats = svc
            .run_legacy_graph_migration(LegacyMigrationOptions::default())
            .await
            .unwrap();
        assert_eq!(stats.nodes_skipped_too_large, 1);
        assert_eq!(stats.nodes_written, 1, "small node should still write");

        use graph::GraphService;
        let graph_be = graph::sqlite::SqliteGraphBackend::new(sqlite.conn_handle());
        let huge_got = graph_be
            .get_node("huge", graph::GraphScope::Local)
            .await
            .unwrap();
        assert!(huge_got.is_none(), "oversized must not have landed");
        let small_got = graph_be
            .get_node("small", graph::GraphScope::Local)
            .await
            .unwrap();
        assert!(small_got.is_some());
    }

    #[tokio::test]
    async fn dry_run_reads_but_doesnt_write() {
        let (sqlite, svc) = fresh_backend().await;
        ensure_legacy_tables(&sqlite).await;
        seed_node(&sqlite, "n1", "local", serde_json::json!({})).await;
        seed_node(&sqlite, "n2", "local", serde_json::json!({})).await;

        let opts = LegacyMigrationOptions {
            dry_run: true,
            ..Default::default()
        };
        let stats = svc.run_legacy_graph_migration(opts).await.unwrap();
        assert_eq!(stats.nodes_read, 2);
        assert_eq!(stats.nodes_written, 0);
        assert_eq!(stats.outcome, "ok");

        use graph::GraphService;
        let graph_be = graph::sqlite::SqliteGraphBackend::new(sqlite.conn_handle());
        let got = graph_be
            .get_node("n1", graph::GraphScope::Local)
            .await
            .unwrap();
        assert!(got.is_none(), "dry_run must not have written n1");
    }

    #[tokio::test]
    async fn dangling_edge_fk_counted_not_errored() {
        let (sqlite, svc) = fresh_backend().await;
        ensure_legacy_tables(&sqlite).await;
        let e_id = Uuid::new_v4().to_string();
        seed_edge(&sqlite, &e_id, "absent-src", "absent-tgt", "local").await;

        let stats = svc
            .run_legacy_graph_migration(LegacyMigrationOptions::default())
            .await
            .unwrap();
        assert_eq!(stats.edges_skipped_dangling_fk, 1);
        assert_eq!(stats.errors, 0);
    }

    #[tokio::test]
    async fn legacy_tables_absent_returns_zero_counts() {
        let (_sqlite, svc) = fresh_backend().await;
        // NO ensure_legacy_tables — fresh install.
        let stats = svc
            .run_legacy_graph_migration(LegacyMigrationOptions::default())
            .await
            .unwrap();
        assert_eq!(stats.outcome, "ok");
        assert_eq!(stats.nodes_read, 0);
        assert_eq!(stats.nodes_written, 0);
        assert_eq!(stats.edges_read, 0);
        assert_eq!(stats.edges_written, 0);
        assert_eq!(stats.errors, 0);
    }

    #[tokio::test]
    async fn non_public_legacy_schema_rejected() {
        let (_sqlite, svc) = fresh_backend().await;
        let opts = LegacyMigrationOptions {
            legacy_schema: "other".into(),
            ..Default::default()
        };
        let r = svc.run_legacy_graph_migration(opts).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
    }
}
