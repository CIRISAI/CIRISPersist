//! SQLite impl of [`GraphService`] (v0.8.4, CIRISPersist#38).
//!
//! Mirrors the v0.8.0 Postgres impl with SQLite-dialect translations:
//! JSONB → TEXT (canonical JSON via serde_json), GIN-on-attributes →
//! expression-indexed `json_extract`, UUID → TEXT, TIMESTAMPTZ →
//! RFC 3339 TEXT. Recursive CTE shape is identical (SQLite 3.8.3+
//! supports `WITH RECURSIVE`); the only structural difference is
//! that SQLite doesn't bind `text[]` params natively — the
//! relationship allow-list goes via a `json_each(?)` join against
//! a JSON-array param.
//!
//! # AV anchors (same set as Postgres impl)
//!
//! - **AV-45** — attributes size cap at the trait surface (default
//!   1 MiB; configurable via `CIRIS_PERSIST_GRAPH_MAX_ATTRIBUTES_BYTES`).
//! - **AV-46** — k-hop depth bound `MAX_KHOP_DEPTH=16` + required
//!   non-empty edge_relationships allow-list.
//! - **AV-47** — scope required in every read.
//! - **AV-48** — optimistic-concurrency `expected_version` gate via
//!   `UPDATE … WHERE version = ?`.
#![allow(clippy::redundant_closure_call)]
// v3.14.0 (CIRISPersist#158) — inline-sync rewrite of all
// tokio::task::spawn_blocking sites uses (closure)() to invoke
// the closure inline. Clippy's redundant_closure_call lint flags
// this; we allow it because the mechanical transformation kept
// each closure's typed return signature load-bearing for error
// propagation and any other refactor would be a much larger diff.

use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};

use super::service::GraphService;
use super::types::{
    EdgeDirection, GraphEdge, GraphNode, GraphScope, KhopEntry, ListCursor, NodeFilter,
    NodeListPage, TraversalConfig,
};
use super::{Error, DEFAULT_MAX_ATTRIBUTES_BYTES, MAX_KHOP_DEPTH};

/// SQLite-backed [`GraphService`] impl. Wraps an `Arc<Mutex<Connection>>`
/// matching the Phase 1 [`crate::store::sqlite::SqliteBackend`] pattern —
/// rusqlite is synchronous, so every method runs the SQL inside
/// `tokio::task::spawn_blocking`.
pub struct SqliteGraphBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteGraphBackend {
    /// Construct from an existing connection handle. Typical usage
    /// shares the same connection with
    /// [`crate::store::sqlite::SqliteBackend`].
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        match err.code {
            ErrorCode::ConstraintViolation => {
                return Error::Conflict(format!("{op}: {e}"));
            }
            ErrorCode::TypeMismatch => {
                return Error::InvalidArgument(format!("{op}: {e}"));
            }
            _ => {}
        }
    }
    Error::Backend(format!("{op}: {e}"))
}

fn max_attributes_bytes() -> usize {
    std::env::var("CIRIS_PERSIST_GRAPH_MAX_ATTRIBUTES_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_ATTRIBUTES_BYTES)
}

/// AV-45: cap attributes size + return canonical JSON text for the
/// SQLite TEXT column. `bulk_import = true` (v1.3.2, CIRISPersist#50)
/// skips the cap for migration use cases.
/// CIRISPersist#58 defense-in-depth: serde_json::to_string is
/// guaranteed to produce valid UTF-8 by construction, but assert it
/// explicitly so a future regression surfaces at write time (with the
/// caller's full context) rather than at read time (with no context).
fn assert_valid_utf8_or_describe(s: &str, ctx: &str) -> Result<(), Error> {
    // String is always valid UTF-8 in Rust; the assertion here is a
    // belt-and-suspenders check that std::str::from_utf8(s.as_bytes())
    // succeeds. If it ever fails the std lib is broken; logged
    // deliberately as Internal so it surfaces as 5xx not caller-fault.
    if std::str::from_utf8(s.as_bytes()).is_err() {
        return Err(Error::Internal(format!(
            "invariant violated: {ctx} produced non-UTF-8 String (length={})",
            s.len()
        )));
    }
    Ok(())
}

fn encode_attributes(attrs: &serde_json::Value, bulk_import: bool) -> Result<String, Error> {
    let s = serde_json::to_string(attrs)
        .map_err(|e| Error::Internal(format!("attributes serialize: {e}")))?;
    // CIRISPersist#58 defense-in-depth.
    assert_valid_utf8_or_describe(&s, "encode_attributes (serde_json::to_string)")?;
    let cap = max_attributes_bytes();
    if !bulk_import && s.len() > cap {
        return Err(Error::AttributesTooLarge {
            bytes: s.len(),
            cap,
        });
    }
    Ok(s)
}

fn decode_attributes(s: &str) -> Result<serde_json::Value, Error> {
    serde_json::from_str(s).map_err(|e| Error::Backend(format!("attributes JSON decode: {e}")))
}

/// v1.5.6 (CIRISPersist#58) — Read the `attributes` TEXT column with a
/// detailed diagnostic on UTF-8 decode failure. rusqlite's default
/// `row.get::<_, String>("attributes")` errors with "Conversion error
/// from type Text at index: 3, invalid utf-8 sequence of N bytes from
/// index P" — which surfaces the failure but tells the caller nothing
/// about which node, what the surrounding bytes look like, or how
/// large the column is. The agent-side bug report on #58 couldn't
/// diagnose because the error didn't carry that context.
///
/// This helper:
/// 1. Tries the normal `String` get first (fast path; valid UTF-8).
/// 2. On failure, falls back to `Vec<u8>` get + manual UTF-8 validation
///    via `std::str::from_utf8`.
/// 3. Returns a detailed `Error::Backend` carrying: total byte length,
///    position of the invalid byte, hex dump of ±32 bytes around the
///    failure, and the agent-visible `node_id` so CI logs are
///    actionable.
fn read_attributes_text(row: &rusqlite::Row<'_>, node_id: &str) -> Result<String, Error> {
    match row.get::<_, String>("attributes") {
        Ok(s) => Ok(s),
        Err(_) => {
            // Fallback: read as raw bytes and pinpoint the failure.
            let raw: Vec<u8> = row.get("attributes").map_err(|e| {
                Error::Backend(format!(
                    "decode attributes: node_id={node_id}: raw read failed: {e}"
                ))
            })?;
            match std::str::from_utf8(&raw) {
                Ok(s) => Ok(s.to_owned()), // shouldn't happen — String get failed, bytes valid
                Err(utf8_err) => {
                    let bad_pos = utf8_err.valid_up_to();
                    let bad_len = utf8_err.error_len().unwrap_or(1);
                    let total_len = raw.len();
                    // Hex dump of ±32 bytes around bad_pos.
                    let lo = bad_pos.saturating_sub(32);
                    let hi = (bad_pos + bad_len + 32).min(total_len);
                    let mut hex = String::new();
                    for (i, b) in raw[lo..hi].iter().enumerate() {
                        let abs = lo + i;
                        if abs == bad_pos {
                            hex.push('[');
                        }
                        hex.push_str(&format!("{b:02x}"));
                        if abs == bad_pos + bad_len - 1 {
                            hex.push(']');
                        } else {
                            hex.push(' ');
                        }
                    }
                    // Surrounding printable context (replace invalid
                    // bytes with • for readability).
                    let ctx: String = raw[lo..hi]
                        .iter()
                        .map(|&b| {
                            if b.is_ascii() && !b.is_ascii_control() {
                                b as char
                            } else {
                                '•'
                            }
                        })
                        .collect();
                    Err(Error::Backend(format!(
                        "decode attributes: node_id={node_id}: invalid UTF-8 at byte {bad_pos} \
                         (sequence length {bad_len}); attributes column is {total_len} bytes total. \
                         hex (±32 around failure, [] = invalid bytes): {hex}. \
                         ascii context (• = non-printable): {ctx:?}. \
                         original error: {utf8_err}"
                    )))
                }
            }
        }
    }
}

fn parse_datetime(s: &str) -> Result<chrono::DateTime<chrono::Utc>, Error> {
    // SQLite stores RFC 3339 / SQLite-default `YYYY-MM-DD HH:MM:SS.sssssssss`
    // depending on how the row was written. chrono's `parse_from_rfc3339`
    // handles the rusqlite-emit shape; for the column-default
    // `datetime('now', 'subsec')` form (which uses SQLite's space
    // separator), normalize to RFC 3339 first.
    let normalized = if s.contains('T') {
        s.to_owned()
    } else {
        format!("{}+00:00", s.replacen(' ', "T", 1))
    };
    chrono::DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| Error::Backend(format!("datetime parse: {e} (raw={s})")))
}

fn fmt_datetime(dt: chrono::DateTime<chrono::Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// v1.6.1 (CIRISPersist#67) — emit the WHERE-clause fragment for an
/// `AttributeMatch` filter onto the supplied `where_parts` + `params`
/// vectors. SQLite has no JSONB containment operator, so:
///
/// - `equals_any`: `json_extract(attributes, '$.<path>') IN (?, ?, …)`
/// - `array_contains_any`: `EXISTS (SELECT 1 FROM
///   json_each(json_extract(attributes, '$.<path>')) WHERE value IN
///   (?, ?, …))`
///
/// Both OR-combine when present. Path is interpolated into the SQL
/// (not bound) so callers must use a single-segment attribute key —
/// validated up-front to be alphanumeric/underscore only so a hostile
/// caller can't inject SQL via the JSON path.
fn push_attribute_match_clause(
    am: &super::types::AttributeMatch,
    where_parts: &mut Vec<String>,
    params: &mut Vec<SqlValue>,
) -> Result<(), Error> {
    if am.path.is_empty() {
        return Err(Error::InvalidArgument(
            "AttributeMatch.path must be non-empty".into(),
        ));
    }
    if !am
        .path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(Error::InvalidArgument(format!(
            "AttributeMatch.path must be alphanumeric/underscore (got {:?})",
            am.path
        )));
    }
    let json_path = format!("$.{}", am.path);
    let mut or_arms: Vec<String> = Vec::new();

    if let Some(values) = am.equals_any.clone() {
        if !values.is_empty() {
            let placeholders: Vec<String> = values
                .iter()
                .map(|v| {
                    params.push(SqlValue::Text(v.clone()));
                    format!("?{}", params.len())
                })
                .collect();
            or_arms.push(format!(
                "json_extract(attributes, '{}') IN ({})",
                json_path,
                placeholders.join(", ")
            ));
        }
    }
    if let Some(values) = am.array_contains_any.clone() {
        if !values.is_empty() {
            let placeholders: Vec<String> = values
                .iter()
                .map(|v| {
                    params.push(SqlValue::Text(v.clone()));
                    format!("?{}", params.len())
                })
                .collect();
            // Guard the json_each walk with a json_type check —
            // calling json_each on a non-array (or non-object) value
            // raises "malformed JSON" at SQLite. When the same `path`
            // arm of the OR also has `equals_any` set against scalar
            // rows, those scalar rows would otherwise blow up here.
            or_arms.push(format!(
                "(json_type(attributes, '{json_path}') = 'array' \
                  AND EXISTS (SELECT 1 FROM json_each(json_extract(attributes, '{json_path}')) \
                              WHERE value IN ({placeholders})))",
                json_path = json_path,
                placeholders = placeholders.join(", ")
            ));
        }
    }
    if !or_arms.is_empty() {
        if or_arms.len() == 1 {
            where_parts.push(or_arms.pop().unwrap());
        } else {
            where_parts.push(format!("({})", or_arms.join(" OR ")));
        }
    }
    Ok(())
}

fn decode_node_row(row: &rusqlite::Row<'_>) -> Result<GraphNode, Error> {
    let scope_str: String = row
        .get("scope")
        .map_err(|e| Error::Backend(format!("decode scope: {e}")))?;
    let scope = GraphScope::from_sql_str(&scope_str)
        .ok_or_else(|| Error::Backend(format!("unknown scope: {scope_str}")))?;
    // Read node_id first so the diagnostic in read_attributes_text can
    // include it in the error message (CIRISPersist#58 — actionable
    // CI logs when attributes UTF-8 decode fails).
    let node_id: String = row
        .get("node_id")
        .map_err(|e| Error::Backend(format!("decode node_id: {e}")))?;
    let attrs_str = read_attributes_text(row, &node_id)?;
    let updated_at_str: String = row
        .get("updated_at")
        .map_err(|e| Error::Backend(format!("decode updated_at: {e}")))?;
    let created_at_str: String = row
        .get("created_at")
        .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?;
    Ok(GraphNode {
        node_id,
        scope,
        node_type: row
            .get("node_type")
            .map_err(|e| Error::Backend(format!("decode node_type: {e}")))?,
        attributes: decode_attributes(&attrs_str)?,
        version: row
            .get("version")
            .map_err(|e| Error::Backend(format!("decode version: {e}")))?,
        updated_by: row
            .get("updated_by")
            .map_err(|e| Error::Backend(format!("decode updated_by: {e}")))?,
        updated_at: parse_datetime(&updated_at_str)?,
        created_at: parse_datetime(&created_at_str)?,
        signature: row
            .get::<_, Option<String>>("signature")
            .map_err(|e| Error::Backend(format!("decode signature: {e}")))?,
        signing_key_id: row
            .get::<_, Option<String>>("signing_key_id")
            .map_err(|e| Error::Backend(format!("decode signing_key_id: {e}")))?,
        signature_verified: {
            let v: i64 = row
                .get("signature_verified")
                .map_err(|e| Error::Backend(format!("decode signature_verified: {e}")))?;
            v != 0
        },
    })
}

fn decode_edge_row(row: &rusqlite::Row<'_>) -> Result<GraphEdge, Error> {
    let scope_str: String = row
        .get("scope")
        .map_err(|e| Error::Backend(format!("decode edge scope: {e}")))?;
    let scope = GraphScope::from_sql_str(&scope_str)
        .ok_or_else(|| Error::Backend(format!("unknown edge scope: {scope_str}")))?;
    let attrs_str: String = row
        .get("attributes")
        .map_err(|e| Error::Backend(format!("decode edge attributes: {e}")))?;
    let created_at_str: String = row
        .get("created_at")
        .map_err(|e| Error::Backend(format!("decode edge created_at: {e}")))?;
    Ok(GraphEdge {
        edge_id: row
            .get("edge_id")
            .map_err(|e| Error::Backend(format!("decode edge_id: {e}")))?,
        source_node_id: row
            .get("source_node_id")
            .map_err(|e| Error::Backend(format!("decode source: {e}")))?,
        target_node_id: row
            .get("target_node_id")
            .map_err(|e| Error::Backend(format!("decode target: {e}")))?,
        scope,
        relationship: row
            .get("relationship")
            .map_err(|e| Error::Backend(format!("decode relationship: {e}")))?,
        weight: row
            .get("weight")
            .map_err(|e| Error::Backend(format!("decode weight: {e}")))?,
        attributes: decode_attributes(&attrs_str)?,
        created_at: parse_datetime(&created_at_str)?,
    })
}

impl GraphService for SqliteGraphBackend {
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
        let scope_str = node.scope.as_sql_str().to_owned();
        let sig_verified_int: i64 = if node.signature_verified { 1 } else { 0 };
        // v1.3.1 (CIRISPersist#49): honor caller-supplied timestamps
        // verbatim. The pre-v1.3.1 behavior stamped `chrono::Utc::now()`
        // on every write, which destroyed temporal ordering on bulk
        // historical imports (CIRISAgent 2.9.0 cutover migrating
        // legacy graph_nodes rows). `node.updated_at` and
        // `node.created_at` are both required fields per the wire
        // schema; pass them through to the row.
        let updated_at = fmt_datetime(node.updated_at);
        let created_at = fmt_datetime(node.created_at);
        let conn = self.conn.clone();
        let node_id = node.node_id;
        let node_type = node.node_type;
        let updated_by = node.updated_by;
        let signature = node.signature;
        let signing_key_id = node.signing_key_id;
        let persist_row_hash = signature.clone();
        let version = node.version;
        (move || -> Result<(), Error> {
            let guard = conn.lock();
            let affected = guard
                .execute(
                    "INSERT INTO cirisgraph_nodes (\
                        node_id, scope, node_type, attributes, version, \
                        updated_by, updated_at, created_at, signature, signing_key_id, \
                        signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12) \
                     ON CONFLICT (node_id, scope) DO UPDATE SET \
                        node_type = excluded.node_type, \
                        attributes = excluded.attributes, \
                        version = cirisgraph_nodes.version + 1, \
                        updated_by = excluded.updated_by, \
                        updated_at = excluded.updated_at, \
                        signature = excluded.signature, \
                        signing_key_id = excluded.signing_key_id, \
                        signature_verified = excluded.signature_verified, \
                        persist_row_hash = excluded.persist_row_hash \
                     WHERE cirisgraph_nodes.version = ?13",
                    params![
                        node_id,
                        scope_str,
                        node_type,
                        attrs,
                        version,
                        updated_by,
                        updated_at,
                        created_at,
                        signature,
                        signing_key_id,
                        sig_verified_int,
                        persist_row_hash,
                        expected_version,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "upsert_node"))?;
            // AV-48: SQLite returns affected=1 for both INSERT and
            // matched UPDATE; affected=0 means the ON CONFLICT
            // WHERE clause didn't match → version mismatch.
            // Distinguish fresh-insert (expected_version=0, no
            // existing row) from version-mismatched-update by
            // re-checking: if affected=0 AND a row exists, it's a
            // version conflict.
            if affected == 0 {
                let exists: bool = guard
                    .query_row(
                        "SELECT 1 FROM cirisgraph_nodes WHERE node_id = ?1 AND scope = ?2",
                        params![&node_id, &scope_str],
                        |_| Ok(true),
                    )
                    .optional()
                    .map_err(|e| map_sqlite_error(e, "upsert_node post-check"))?
                    .unwrap_or(false);
                if exists {
                    return Err(Error::Conflict(format!(
                        "version mismatch: expected_version={expected_version} did not match \
                         current row for ({node_id}, {scope_str})"
                    )));
                }
            }
            drop(guard);
            Ok(())
        })()
    }

    async fn upsert_edge(&self, edge: GraphEdge, bulk_import: bool) -> Result<(), Error> {
        let attrs = encode_attributes(&edge.attributes, bulk_import)?;
        let scope_str = edge.scope.as_sql_str().to_owned();
        // v1.3.1 (CIRISPersist#49): honor caller-supplied
        // `edge.created_at` for bulk historical imports.
        let created_at = fmt_datetime(edge.created_at);
        let conn = self.conn.clone();
        let edge_id = edge.edge_id;
        let source = edge.source_node_id;
        let target = edge.target_node_id;
        let relationship = edge.relationship;
        let weight = edge.weight;
        (move || -> Result<(), Error> {
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT INTO cirisgraph_edges (\
                        edge_id, source_node_id, target_node_id, scope, \
                        relationship, weight, attributes, created_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) \
                     ON CONFLICT (edge_id) DO NOTHING",
                    params![
                        edge_id,
                        source,
                        target,
                        scope_str,
                        relationship,
                        weight,
                        attrs,
                        created_at,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "upsert_edge"))?;
            Ok(())
        })()
    }

    async fn delete_node(
        &self,
        node_id: &str,
        scope: GraphScope,
        hard: bool,
    ) -> Result<bool, Error> {
        let conn = self.conn.clone();
        let node_id = node_id.to_owned();
        let scope_str = scope.as_sql_str().to_owned();
        (move || -> Result<bool, Error> {
            let guard = conn.lock();
            if hard {
                guard
                    .execute(
                        "DELETE FROM cirisgraph_edges \
                         WHERE (source_node_id = ?1 OR target_node_id = ?1) AND scope = ?2",
                        params![&node_id, &scope_str],
                    )
                    .map_err(|e| map_sqlite_error(e, "delete_node (edges)"))?;
                let n = guard
                    .execute(
                        "DELETE FROM cirisgraph_nodes WHERE node_id = ?1 AND scope = ?2",
                        params![&node_id, &scope_str],
                    )
                    .map_err(|e| map_sqlite_error(e, "delete_node"))?;
                Ok(n > 0)
            } else {
                let now = fmt_datetime(chrono::Utc::now());
                let n = guard
                    .execute(
                        "UPDATE cirisgraph_nodes SET \
                            attributes = json_set(attributes, '$._deleted', json('true')), \
                            version = version + 1, \
                            updated_at = ?1 \
                         WHERE node_id = ?2 AND scope = ?3",
                        params![now, &node_id, &scope_str],
                    )
                    .map_err(|e| map_sqlite_error(e, "soft delete_node"))?;
                Ok(n > 0)
            }
        })()
    }

    async fn get_node(&self, node_id: &str, scope: GraphScope) -> Result<Option<GraphNode>, Error> {
        let conn = self.conn.clone();
        let node_id = node_id.to_owned();
        let scope_str = scope.as_sql_str().to_owned();
        (move || -> Result<Option<GraphNode>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(
                    "SELECT node_id, scope, node_type, attributes, version, \
                            updated_by, updated_at, created_at, \
                            signature, signing_key_id, signature_verified \
                     FROM cirisgraph_nodes \
                     WHERE node_id = ?1 AND scope = ?2",
                )
                .map_err(|e| map_sqlite_error(e, "get_node prepare"))?;
            let row_opt = stmt
                .query_row(params![&node_id, &scope_str], |row| {
                    Ok(decode_node_row(row))
                })
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_node"))?;
            match row_opt {
                None => Ok(None),
                Some(Ok(node)) => Ok(Some(node)),
                Some(Err(e)) => Err(e),
            }
        })()
    }

    async fn get_edges_for_node(
        &self,
        node_id: &str,
        scope: GraphScope,
        direction: EdgeDirection,
        relationship_filter: Option<&[String]>,
    ) -> Result<Vec<GraphEdge>, Error> {
        let where_dir = match direction {
            EdgeDirection::Outgoing => "source_node_id = ?1 AND scope = ?2",
            EdgeDirection::Incoming => "target_node_id = ?1 AND scope = ?2",
            EdgeDirection::Both => "(source_node_id = ?1 OR target_node_id = ?1) AND scope = ?2",
        };
        let conn = self.conn.clone();
        let node_id = node_id.to_owned();
        let scope_str = scope.as_sql_str().to_owned();
        let rels: Option<Vec<String>> = relationship_filter
            .filter(|r| !r.is_empty())
            .map(|r| r.to_vec());
        (move || -> Result<Vec<GraphEdge>, Error> {
            let guard = conn.lock();
            let sql_base = format!(
                "SELECT edge_id, source_node_id, target_node_id, scope, \
                        relationship, weight, attributes, created_at \
                 FROM cirisgraph_edges \
                 WHERE {where_dir}"
            );
            let (sql, params_vec): (String, Vec<SqlValue>) = match rels {
                None => (
                    format!("{sql_base} ORDER BY created_at DESC"),
                    vec![SqlValue::Text(node_id), SqlValue::Text(scope_str)],
                ),
                Some(rels) => {
                    // SQLite doesn't bind text[]; pass as JSON array
                    // + use json_each to expand. Filter via
                    // `relationship IN (SELECT value FROM
                    // json_each(?))`.
                    let rels_json = serde_json::to_string(&rels).map_err(|e| {
                        Error::Internal(format!("relationship_filter serialize: {e}"))
                    })?;
                    (
                        format!(
                            "{sql_base} AND relationship IN (SELECT value FROM json_each(?3)) \
                             ORDER BY created_at DESC"
                        ),
                        vec![
                            SqlValue::Text(node_id),
                            SqlValue::Text(scope_str),
                            SqlValue::Text(rels_json),
                        ],
                    )
                }
            };
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "get_edges_for_node prepare"))?;
            let rows_iter = stmt
                .query_map(params_from_iter(params_vec.iter()), |row| {
                    Ok(decode_edge_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "get_edges_for_node query"))?;
            let mut out = Vec::new();
            for r in rows_iter {
                out.push(r.map_err(|e| map_sqlite_error(e, "get_edges_for_node row"))??);
            }
            Ok(out)
        })()
    }

    async fn traverse_k_hop(
        &self,
        start_node_id: &str,
        scope: GraphScope,
        cfg: TraversalConfig,
    ) -> Result<Vec<KhopEntry>, Error> {
        // Same AV-46 bounds as Postgres impl.
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

        // SQLite's recursive CTE syntax forbids LIMIT inside the
        // recursive arm + doesn't allow it to reference `frontier`
        // from a subquery. We restructure: the recursive arm joins
        // frontier+edges directly (no subquery), and the per-level
        // fan-out bound moves to an OUTER LIMIT on the join'd row
        // set (caller can post-filter if even tighter bounds are
        // needed). `max_depth` still strictly bounds the
        // recursion. AV-46's primary defense (depth cap) is
        // preserved; per-level fan-out is best-effort on SQLite.
        let (next_node_expr, edge_join) = match cfg.direction {
            EdgeDirection::Outgoing => (
                "e.target_node_id",
                "JOIN cirisgraph_edges e ON e.source_node_id = f.node_id AND e.scope = ?2 \
                 AND e.relationship IN (SELECT value FROM json_each(?3))",
            ),
            EdgeDirection::Incoming => (
                "e.source_node_id",
                "JOIN cirisgraph_edges e ON e.target_node_id = f.node_id AND e.scope = ?2 \
                 AND e.relationship IN (SELECT value FROM json_each(?3))",
            ),
            EdgeDirection::Both => (
                "CASE WHEN e.source_node_id = f.node_id THEN e.target_node_id \
                 ELSE e.source_node_id END",
                "JOIN cirisgraph_edges e ON \
                    (e.source_node_id = f.node_id OR e.target_node_id = f.node_id) \
                    AND e.scope = ?2 \
                    AND e.relationship IN (SELECT value FROM json_each(?3))",
            ),
        };
        let sql = format!(
            "WITH RECURSIVE frontier(node_id, scope, depth) AS (\
                SELECT node_id, scope, 0 \
                FROM cirisgraph_nodes \
                WHERE node_id = ?1 AND scope = ?2 \
              UNION \
                SELECT {next_node_expr}, ?2, f.depth + 1 \
                FROM frontier f \
                {edge_join} \
                WHERE f.depth < ?4\
            ) \
            SELECT n.node_id, n.scope, n.node_type, n.attributes, n.version, \
                   n.updated_by, n.updated_at, n.created_at, \
                   n.signature, n.signing_key_id, n.signature_verified, \
                   MIN(f.depth) AS depth \
            FROM frontier f \
            JOIN cirisgraph_nodes n ON n.node_id = f.node_id AND n.scope = f.scope \
            GROUP BY n.node_id, n.scope, n.node_type, n.attributes, n.version, \
                     n.updated_by, n.updated_at, n.created_at, \
                     n.signature, n.signing_key_id, n.signature_verified \
            ORDER BY depth ASC, n.node_id ASC \
            LIMIT ?5"
        );

        let rels_json = serde_json::to_string(&cfg.edge_relationships)
            .map_err(|e| Error::Internal(format!("rels serialize: {e}")))?;
        let max_depth_i64 = cfg.max_depth as i64;
        // SQLite outer-LIMIT bound: max_depth × per_level_limit upper
        // estimate. Conservative — keeps a runaway query bounded by
        // the same product the Postgres impl bounds.
        let outer_limit = max_depth_i64.saturating_mul(cfg.per_level_limit as i64);
        let conn = self.conn.clone();
        let start_id = start_node_id.to_owned();
        let scope_str = scope.as_sql_str().to_owned();
        (move || -> Result<Vec<KhopEntry>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "traverse_k_hop prepare"))?;
            let rows_iter = stmt
                .query_map(
                    params![start_id, scope_str, rels_json, max_depth_i64, outer_limit],
                    |row| {
                        let depth: i64 = row.get("depth")?;
                        Ok((depth, decode_node_row(row)))
                    },
                )
                .map_err(|e| map_sqlite_error(e, "traverse_k_hop query"))?;
            let mut out = Vec::new();
            for r in rows_iter {
                let (depth, node_res) = r.map_err(|e| map_sqlite_error(e, "khop row"))?;
                out.push(KhopEntry {
                    node: node_res?,
                    depth: depth as usize,
                });
            }
            Ok(out)
        })()
    }

    async fn query_nodes(
        &self,
        filter: NodeFilter,
        cursor: Option<ListCursor>,
        limit: i64,
    ) -> Result<NodeListPage, Error> {
        let scope = filter
            .scope
            .ok_or_else(|| Error::InvalidArgument("NodeFilter.scope is required (AV-47)".into()))?;
        if !(1..=10_000).contains(&limit) {
            return Err(Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }

        let mut where_parts: Vec<String> = vec!["scope = ?".to_string()];
        let scope_str = scope.as_sql_str().to_owned();
        let mut params: Vec<SqlValue> = vec![SqlValue::Text(scope_str)];

        if let Some(nt) = filter.node_type {
            params.push(SqlValue::Text(nt));
            where_parts.push("node_type = ?".to_string());
        }
        if let Some(contains) = filter.attributes_contains {
            // SQLite has no native JSONB containment. Translate
            // `attributes @> {k: v}` to per-key `json_extract` equals
            // checks. Only top-level object key/value pairs supported
            // in this filter shape — caller can pre-filter complex
            // attrs in application code.
            if let Some(obj) = contains.as_object() {
                for (k, v) in obj {
                    let json_path = format!("$.{k}");
                    let v_str = serde_json::to_string(v).map_err(|e| {
                        Error::Internal(format!("attributes_contains serialize: {e}"))
                    })?;
                    params.push(SqlValue::Text(json_path));
                    params.push(SqlValue::Text(v_str));
                    where_parts.push(format!(
                        "json_extract(attributes, ?{}) = json(?{})",
                        params.len() - 1,
                        params.len()
                    ));
                }
            } else {
                return Err(Error::InvalidArgument(
                    "attributes_contains must be a JSON object".into(),
                ));
            }
        }
        if let Some(after) = filter.updated_after {
            params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push("updated_at >= ?".to_string());
        }
        if let Some(before) = filter.updated_before {
            params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push("updated_at <= ?".to_string());
        }
        if let Some(rule) = filter.exclude {
            params.push(SqlValue::Text(rule.node_type));
            params.push(SqlValue::Text(rule.node_id_pattern));
            where_parts.push("NOT (node_type = ? AND node_id LIKE ?)".to_string());
        }
        if let Some(am) = filter.attribute_match {
            push_attribute_match_clause(&am, &mut where_parts, &mut params)?;
        }
        if let Some(cur) = &cursor {
            if cur.version != "v1" {
                return Err(Error::InvalidArgument(format!(
                    "ListCursor version {} unsupported (expected v1)",
                    cur.version
                )));
            }
            params.push(SqlValue::Text(fmt_datetime(cur.last_ts)));
            params.push(SqlValue::Text(cur.last_id.clone()));
            where_parts.push("(updated_at, node_id) < (?, ?)".to_string());
        }
        params.push(SqlValue::Integer(limit));
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT node_id, scope, node_type, attributes, version, \
                    updated_by, updated_at, created_at, \
                    signature, signing_key_id, signature_verified \
             FROM cirisgraph_nodes \
             WHERE {where_sql} \
             ORDER BY updated_at DESC, node_id DESC \
             LIMIT ?"
        );

        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        (move || -> Result<NodeListPage, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "query_nodes prepare"))?;
            let rows_iter = stmt
                .query_map(params_from_iter(params.iter()), |row| {
                    Ok(decode_node_row(row))
                })
                .map_err(|e| map_sqlite_error(e, "query_nodes query"))?;
            let mut items: Vec<GraphNode> = Vec::new();
            for r in rows_iter {
                items.push(r.map_err(|e| map_sqlite_error(e, "query_nodes row"))??);
            }
            let next_cursor = if items.len() == limit_usize {
                items
                    .last()
                    .map(|last| ListCursor::from_trailing(last.updated_at, last.node_id.clone()))
            } else {
                None
            };
            Ok(NodeListPage { items, next_cursor })
        })()
    }

    async fn count_nodes(&self, filter: NodeFilter) -> Result<u64, Error> {
        let scope = filter
            .scope
            .ok_or_else(|| Error::InvalidArgument("NodeFilter.scope is required (AV-47)".into()))?;
        let mut where_parts: Vec<String> = vec!["scope = ?".to_string()];
        let scope_str = scope.as_sql_str().to_owned();
        let mut params: Vec<SqlValue> = vec![SqlValue::Text(scope_str)];

        if let Some(nt) = filter.node_type {
            params.push(SqlValue::Text(nt));
            where_parts.push("node_type = ?".to_string());
        }
        if let Some(contains) = filter.attributes_contains {
            if let Some(obj) = contains.as_object() {
                for (k, v) in obj {
                    let json_path = format!("$.{k}");
                    let v_str = serde_json::to_string(v).map_err(|e| {
                        Error::Internal(format!("attributes_contains serialize: {e}"))
                    })?;
                    params.push(SqlValue::Text(json_path));
                    params.push(SqlValue::Text(v_str));
                    where_parts.push(format!(
                        "json_extract(attributes, ?{}) = json(?{})",
                        params.len() - 1,
                        params.len()
                    ));
                }
            } else {
                return Err(Error::InvalidArgument(
                    "attributes_contains must be a JSON object".into(),
                ));
            }
        }
        if let Some(after) = filter.updated_after {
            params.push(SqlValue::Text(fmt_datetime(after)));
            where_parts.push("updated_at >= ?".to_string());
        }
        if let Some(before) = filter.updated_before {
            params.push(SqlValue::Text(fmt_datetime(before)));
            where_parts.push("updated_at <= ?".to_string());
        }
        if let Some(rule) = filter.exclude {
            params.push(SqlValue::Text(rule.node_type));
            params.push(SqlValue::Text(rule.node_id_pattern));
            where_parts.push("NOT (node_type = ? AND node_id LIKE ?)".to_string());
        }
        if let Some(am) = filter.attribute_match {
            push_attribute_match_clause(&am, &mut where_parts, &mut params)?;
        }
        let where_sql = where_parts.join(" AND ");
        let sql = format!("SELECT COUNT(*) FROM cirisgraph_nodes WHERE {where_sql}");

        let conn = self.conn.clone();
        (move || -> Result<u64, Error> {
            let guard = conn.lock();
            let count: i64 = guard
                .query_row(&sql, params_from_iter(params.iter()), |row| row.get(0))
                .map_err(|e| map_sqlite_error(e, "count_nodes"))?;
            Ok(count.max(0) as u64)
        })()
    }

    async fn count_edges(&self, scope: GraphScope) -> Result<u64, Error> {
        let scope_str = scope.as_sql_str().to_owned();
        let conn = self.conn.clone();
        (move || -> Result<u64, Error> {
            let guard = conn.lock();
            let count: i64 = guard
                .query_row(
                    "SELECT COUNT(*) FROM cirisgraph_edges WHERE scope = ?1",
                    params![scope_str],
                    |row| row.get(0),
                )
                .map_err(|e| map_sqlite_error(e, "count_edges"))?;
            Ok(count.max(0) as u64)
        })()
    }

    async fn count_nodes_by_type(
        &self,
        scope: GraphScope,
    ) -> Result<std::collections::HashMap<String, u64>, Error> {
        let scope_str = scope.as_sql_str().to_owned();
        let conn = self.conn.clone();
        (move || -> Result<std::collections::HashMap<String, u64>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(
                    "SELECT node_type, COUNT(*) FROM cirisgraph_nodes \
                         WHERE scope = ?1 GROUP BY node_type",
                )
                .map_err(|e| map_sqlite_error(e, "count_nodes_by_type prepare"))?;
            let rows = stmt
                .query_map(params![scope_str], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                })
                .map_err(|e| map_sqlite_error(e, "count_nodes_by_type query"))?;
            let mut out: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
            for r in rows {
                let (nt, c) = r.map_err(|e| map_sqlite_error(e, "count_nodes_by_type row"))?;
                out.insert(nt, c.max(0) as u64);
            }
            Ok(out)
        })()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteGraphBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let graph = SqliteGraphBackend::new(backend.conn_handle());
        (backend, graph)
    }

    fn fixture_node(node_id: &str, scope: GraphScope, node_type: &str) -> GraphNode {
        GraphNode {
            node_id: node_id.to_owned(),
            scope,
            node_type: node_type.to_owned(),
            attributes: serde_json::json!({"created_in": "test"}),
            version: 1,
            updated_by: "test-runner".into(),
            updated_at: chrono::Utc::now(),
            created_at: chrono::Utc::now(),
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
            created_at: chrono::Utc::now(),
        }
    }

    /// v0.8.4 SQLite parity: same lifecycle as the v0.8.0 Postgres
    /// test (upsert → get → version conflict → AV-45 → edges → AV-46
    /// → k-hop → query → AV-47 → cascade delete) — all via SQLite.
    #[tokio::test]
    async fn cirisgraph_sqlite_round_trip_full_lifecycle() {
        let (_b, graph) = fresh_backend().await;

        let suffix = Uuid::new_v4().simple().to_string();
        let n_a = format!("test:a-{suffix}");
        let n_b = format!("test:b-{suffix}");
        let n_c = format!("test:c-{suffix}");

        // 1. Insert 3 nodes.
        for nid in [&n_a, &n_b, &n_c] {
            graph
                .upsert_node(fixture_node(nid, GraphScope::Local, "test"), 0, false)
                .await
                .unwrap();
        }

        // 2. get_node round-trip.
        let got = graph
            .get_node(&n_a, GraphScope::Local)
            .await
            .unwrap()
            .expect("node a");
        assert_eq!(got.node_id, n_a);
        assert_eq!(got.version, 1);

        // 3. AV-48: version conflict.
        let conflict = graph
            .upsert_node(fixture_node(&n_a, GraphScope::Local, "test"), 0, false)
            .await
            .unwrap_err();
        assert!(matches!(conflict, Error::Conflict(_)));

        // 4. Update with correct version succeeds.
        let mut updated = got.clone();
        updated.attributes = serde_json::json!({"updated": true});
        graph.upsert_node(updated, 1, false).await.unwrap();
        let post = graph
            .get_node(&n_a, GraphScope::Local)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(post.version, 2);

        // 5. AV-45: oversized attributes reject.
        let mut huge = fixture_node("test:huge", GraphScope::Local, "test");
        huge.attributes = serde_json::json!({"payload": "x".repeat(2 * 1024 * 1024)});
        let too_big = graph.upsert_node(huge, 0, false).await.unwrap_err();
        // v1.3.2 (CIRISPersist#50): AV-45 now surfaces as the typed
        // `AttributesTooLarge { bytes, cap }` variant rather than the
        // opaque `InvalidArgument` string the pre-v1.3.2 impl used.
        assert!(matches!(too_big, Error::AttributesTooLarge { .. }));

        // 6. Edges: a -OWNS-> b -OWNS-> c -SUMMARIZES-> a (cycle).
        graph
            .upsert_edge(fixture_edge(&n_a, &n_b, GraphScope::Local, "OWNS"), false)
            .await
            .unwrap();
        graph
            .upsert_edge(fixture_edge(&n_b, &n_c, GraphScope::Local, "OWNS"), false)
            .await
            .unwrap();
        graph
            .upsert_edge(
                fixture_edge(&n_c, &n_a, GraphScope::Local, "SUMMARIZES"),
                false,
            )
            .await
            .unwrap();

        // 7. Directional edges.
        let out = graph
            .get_edges_for_node(&n_a, GraphScope::Local, EdgeDirection::Outgoing, None)
            .await
            .unwrap();
        assert_eq!(out.len(), 1);
        let in_ = graph
            .get_edges_for_node(&n_a, GraphScope::Local, EdgeDirection::Incoming, None)
            .await
            .unwrap();
        assert_eq!(in_.len(), 1);

        // 8. Relationship filter (json_each path).
        let only_sum = graph
            .get_edges_for_node(
                &n_a,
                GraphScope::Local,
                EdgeDirection::Both,
                Some(&["SUMMARIZES".to_owned()]),
            )
            .await
            .unwrap();
        assert_eq!(only_sum.len(), 1);
        assert_eq!(only_sum[0].relationship, "SUMMARIZES");

        // 9. AV-46 bounds.
        let bad_depth = graph
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

        // 10. Real 2-hop traverse via recursive CTE.
        let khop = graph
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
        assert_eq!(khop.len(), 3);
        assert_eq!(khop[0].depth, 0);
        assert_eq!(khop[0].node.node_id, n_a);
        assert!(khop.iter().any(|e| e.node.node_id == n_b && e.depth == 1));
        assert!(khop.iter().any(|e| e.node.node_id == n_c && e.depth == 2));

        // 11. query_nodes with scope + type.
        let page = graph
            .query_nodes(
                NodeFilter {
                    scope: Some(GraphScope::Local),
                    node_type: Some("test".into()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert!(page.items.len() >= 3);

        // 12. AV-47 None scope rejects.
        let no_scope = graph
            .query_nodes(NodeFilter::default(), None, 10)
            .await
            .unwrap_err();
        assert!(matches!(no_scope, Error::InvalidArgument(_)));

        // 13. Hard cascade delete.
        let deleted = graph
            .delete_node(&n_a, GraphScope::Local, true)
            .await
            .unwrap();
        assert!(deleted);
        assert!(graph
            .get_node(&n_a, GraphScope::Local)
            .await
            .unwrap()
            .is_none());
    }

    /// v1.3.1 (CIRISPersist#49): supplied `updated_at` / `created_at`
    /// on `upsert_node` must round-trip verbatim. Regression test for
    /// the bulk-historical-import case (CIRISAgent 2.9.0 cutover) —
    /// pre-v1.3.1 the impl stamped wall-clock now, destroying
    /// temporal ordering on migrated rows.
    #[tokio::test]
    async fn upsert_node_preserves_supplied_timestamps() {
        let (_b, graph) = fresh_backend().await;
        let historical = chrono::DateTime::parse_from_rfc3339("2022-01-15T10:30:00.000000+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let node = GraphNode {
            node_id: "probe-49".into(),
            scope: GraphScope::Local,
            node_type: "config".into(),
            attributes: serde_json::json!({}),
            version: 1,
            updated_by: "test".into(),
            updated_at: historical,
            created_at: historical,
            signature: None,
            signing_key_id: None,
            signature_verified: false,
        };
        graph.upsert_node(node, 0, false).await.unwrap();
        let got = graph
            .get_node("probe-49", GraphScope::Local)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            got.created_at, historical,
            "v1.3.1 (#49): created_at must round-trip verbatim"
        );
        assert_eq!(
            got.updated_at, historical,
            "v1.3.1 (#49): updated_at must round-trip verbatim"
        );
    }

    /// v1.3.1 (CIRISPersist#49): same regression for upsert_edge —
    /// edge.created_at must round-trip rather than getting stamped
    /// now().
    #[tokio::test]
    async fn upsert_edge_preserves_supplied_created_at() {
        let (_b, graph) = fresh_backend().await;
        // Seed nodes (edges reference them by id but the impl doesn't
        // enforce FK at the SQL layer; still seed for hygiene).
        for nid in ["src-49", "dst-49"] {
            graph
                .upsert_node(fixture_node(nid, GraphScope::Local, "test"), 0, false)
                .await
                .unwrap();
        }
        let historical = chrono::DateTime::parse_from_rfc3339("2021-08-04T12:00:00.000000+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let edge_id = Uuid::new_v4().to_string();
        let edge = GraphEdge {
            edge_id: edge_id.clone(),
            source_node_id: "src-49".into(),
            target_node_id: "dst-49".into(),
            scope: GraphScope::Local,
            relationship: "related".into(),
            weight: None,
            attributes: serde_json::json!({}),
            created_at: historical,
        };
        graph.upsert_edge(edge, false).await.unwrap();
        let edges = graph
            .get_edges_for_node("src-49", GraphScope::Local, EdgeDirection::Outgoing, None)
            .await
            .unwrap();
        let stored = edges.iter().find(|e| e.edge_id == edge_id).unwrap();
        assert_eq!(
            stored.created_at, historical,
            "v1.3.1 (#49): edge created_at must round-trip verbatim"
        );
    }

    /// v1.3.2 (CIRISPersist#50): `bulk_import=true` skips the AV-45
    /// attributes-size cap for one-time historical migration. The
    /// row should land successfully even when serialized attrs
    /// exceed `DEFAULT_MAX_ATTRIBUTES_BYTES`. Mirrors the
    /// `conversation_summary` 1.67 MiB case from datum's cutover.
    #[tokio::test]
    async fn upsert_node_bulk_import_skips_attribute_cap() {
        let (_b, graph) = fresh_backend().await;
        // Build a node whose serialized attributes exceed the 1 MiB
        // default cap. Use a 1.5 MiB string blob to mimic a long-form
        // conversation_summary payload.
        let blob = "x".repeat(1_500_000);
        let huge = GraphNode {
            node_id: "huge-50".into(),
            scope: GraphScope::Local,
            node_type: "conversation_summary".into(),
            attributes: serde_json::json!({"text": blob}),
            version: 1,
            updated_by: "migrate".into(),
            updated_at: chrono::Utc::now(),
            created_at: chrono::Utc::now(),
            signature: None,
            signing_key_id: None,
            signature_verified: false,
        };
        // Default (bulk_import=false) rejects with the typed
        // AttributesTooLarge error.
        let rejected = graph.upsert_node(huge.clone(), 0, false).await.unwrap_err();
        match rejected {
            Error::AttributesTooLarge { bytes, cap } => {
                assert!(bytes > cap, "bytes {bytes} should exceed cap {cap}");
                assert_eq!(cap, DEFAULT_MAX_ATTRIBUTES_BYTES);
            }
            other => panic!("expected AttributesTooLarge, got {other:?}"),
        }
        // bulk_import=true lands the row.
        graph.upsert_node(huge, 0, true).await.unwrap();
        let got = graph
            .get_node("huge-50", GraphScope::Local)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.node_type, "conversation_summary");
    }

    /// CIRISPersist#58 regression: when the attributes column contains
    /// non-UTF-8 bytes (either via a non-persist writer or external
    /// corruption), get_node must surface a diagnostic that includes
    /// the node_id + total bytes + position of the invalid byte +
    /// hex dump of surrounding context. Without this, agent CI logs
    /// only carry "Conversion error from type Text at index: 3" with
    /// no way to find the root cause upstream.
    #[tokio::test]
    async fn get_node_diagnostic_on_invalid_utf8_attributes() {
        let (backend, graph) = fresh_backend().await;
        // First, upsert a clean node — guarantees the row exists and
        // also exercises the encode_attributes UTF-8 invariant check.
        let clean = fixture_node("ally/identity", GraphScope::Identity, "IDENTITY");
        graph.upsert_node(clean, 0, false).await.unwrap();

        // Now inject a non-UTF-8 byte (0xC0 — invalid start byte) at
        // a deterministic position inside the attributes column via
        // raw SQL. Simulates the kind of corruption the agent observed
        // in CI without us needing to find the upstream root cause.
        let conn = backend.conn_handle();
        let _ = (move || -> Result<(), rusqlite::Error> {
            let guard = conn.lock();
            // Build a 1 KB attributes string with a planted invalid byte.
            let prefix = "{\"padding\":\"".repeat(60); // ~800 bytes of valid JSON-ish
            let mut bytes: Vec<u8> = prefix.into_bytes();
            bytes.push(0xC0); // invalid start byte at known position
            bytes.extend_from_slice(b"\",\"k\":\"v\"}".repeat(10).as_slice());
            // Bind as BLOB to bypass SQLite's normal TEXT semantics
            // (rusqlite would refuse to bind a non-UTF-8 String).
            guard.execute(
                "UPDATE cirisgraph_nodes SET attributes = ?1 WHERE node_id = 'ally/identity'",
                rusqlite::params![bytes],
            )?;
            Ok(())
        })();

        // Now get_node should fail with the diagnostic error.
        let err = graph
            .get_node("ally/identity", GraphScope::Identity)
            .await
            .expect_err("get_node should fail on invalid UTF-8 attributes");
        let msg = format!("{err}");
        // The diagnostic must carry: node_id, byte position, hex dump
        // marker, and total length — all the things agent CI logs
        // need to find the upstream root cause.
        assert!(msg.contains("ally/identity"), "missing node_id: {msg}");
        assert!(
            msg.contains("invalid UTF-8 at byte"),
            "missing byte pos: {msg}"
        );
        assert!(msg.contains("hex"), "missing hex dump: {msg}");
        assert!(msg.contains("c0"), "missing the invalid byte 0xC0: {msg}");
        assert!(msg.contains("bytes total"), "missing total length: {msg}");
    }

    // ── v1.5.25 (CIRISPersist#65) count + exclude tests ─────────────

    #[tokio::test]
    async fn count_nodes_returns_total_in_scope() {
        let (_b, graph) = fresh_backend().await;
        let suffix = Uuid::new_v4().simple().to_string();
        for i in 0..5 {
            let nid = format!("count:{i}-{suffix}");
            graph
                .upsert_node(fixture_node(&nid, GraphScope::Local, "test"), 0, false)
                .await
                .unwrap();
        }
        // Insert a different-scope node — should NOT count toward Local.
        let other_scope_id = format!("count:other-{suffix}");
        graph
            .upsert_node(
                fixture_node(&other_scope_id, GraphScope::Environment, "test"),
                0,
                false,
            )
            .await
            .unwrap();

        let count = graph
            .count_nodes(NodeFilter {
                scope: Some(GraphScope::Local),
                ..Default::default()
            })
            .await
            .unwrap();
        // At least our 5 (other tests may also have inserted in-mem; check >= 5).
        assert!(count >= 5, "got {count}");
    }

    #[tokio::test]
    async fn count_nodes_honors_exclude_rule() {
        let (_b, graph) = fresh_backend().await;
        let suffix = Uuid::new_v4().simple().to_string();
        // 3 tsdb_data nodes named `metric_*` (target of exclusion).
        for i in 0..3 {
            let nid = format!("metric_{i}-{suffix}");
            graph
                .upsert_node(fixture_node(&nid, GraphScope::Local, "tsdb_data"), 0, false)
                .await
                .unwrap();
        }
        // 2 tsdb_data nodes NOT named metric_* (kept).
        for i in 0..2 {
            let nid = format!("summary_{i}-{suffix}");
            graph
                .upsert_node(fixture_node(&nid, GraphScope::Local, "tsdb_data"), 0, false)
                .await
                .unwrap();
        }
        // 1 other-typed node (kept regardless of pattern).
        let other_id = format!("memory_x-{suffix}");
        graph
            .upsert_node(
                fixture_node(&other_id, GraphScope::Local, "memory"),
                0,
                false,
            )
            .await
            .unwrap();

        let count_all = graph
            .count_nodes(NodeFilter {
                scope: Some(GraphScope::Local),
                ..Default::default()
            })
            .await
            .unwrap();

        let count_excluded = graph
            .count_nodes(NodeFilter {
                scope: Some(GraphScope::Local),
                exclude: Some(crate::graph::NodeExcludeRule {
                    node_type: "tsdb_data".into(),
                    node_id_pattern: "metric_%".into(),
                }),
                ..Default::default()
            })
            .await
            .unwrap();

        // 3 metric_* rows should be excluded.
        assert_eq!(count_excluded + 3, count_all);
    }

    #[tokio::test]
    async fn count_edges_in_scope() {
        let (_b, graph) = fresh_backend().await;
        let suffix = Uuid::new_v4().simple().to_string();
        let a = format!("e:a-{suffix}");
        let b = format!("e:b-{suffix}");
        graph
            .upsert_node(fixture_node(&a, GraphScope::Local, "test"), 0, false)
            .await
            .unwrap();
        graph
            .upsert_node(fixture_node(&b, GraphScope::Local, "test"), 0, false)
            .await
            .unwrap();
        for _ in 0..4 {
            graph
                .upsert_edge(fixture_edge(&a, &b, GraphScope::Local, "rel"), false)
                .await
                .unwrap();
        }
        let count = graph.count_edges(GraphScope::Local).await.unwrap();
        assert!(count >= 4, "got {count}");
    }

    #[tokio::test]
    async fn count_nodes_by_type_groups_correctly() {
        let (_b, graph) = fresh_backend().await;
        let suffix = Uuid::new_v4().simple().to_string();
        // 3 memory + 2 concept + 1 tsdb_summary.
        for (label, ty, n) in &[
            ("m", "memory", 3),
            ("c", "concept", 2),
            ("t", "tsdb_summary", 1),
        ] {
            for i in 0..*n {
                let nid = format!("{label}{i}-{suffix}");
                graph
                    .upsert_node(fixture_node(&nid, GraphScope::Local, ty), 0, false)
                    .await
                    .unwrap();
            }
        }
        let map = graph.count_nodes_by_type(GraphScope::Local).await.unwrap();
        // The map may have prior in-mem rows; just check our types.
        assert!(map.get("memory").copied().unwrap_or(0) >= 3);
        assert!(map.get("concept").copied().unwrap_or(0) >= 2);
        assert!(map.get("tsdb_summary").copied().unwrap_or(0) >= 1);
    }

    #[tokio::test]
    async fn count_nodes_missing_scope_rejected() {
        let (_b, graph) = fresh_backend().await;
        let err = graph.count_nodes(NodeFilter::default()).await.unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn query_nodes_honors_exclude_rule_in_listing() {
        let (_b, graph) = fresh_backend().await;
        let suffix = Uuid::new_v4().simple().to_string();
        // 2 metric tsdb_data + 1 summary tsdb_data.
        for i in 0..2 {
            graph
                .upsert_node(
                    fixture_node(
                        &format!("metric_{i}-{suffix}"),
                        GraphScope::Local,
                        "tsdb_data",
                    ),
                    0,
                    false,
                )
                .await
                .unwrap();
        }
        graph
            .upsert_node(
                fixture_node(&format!("summary-{suffix}"), GraphScope::Local, "tsdb_data"),
                0,
                false,
            )
            .await
            .unwrap();

        let page = graph
            .query_nodes(
                NodeFilter {
                    scope: Some(GraphScope::Local),
                    node_type: Some("tsdb_data".into()),
                    exclude: Some(crate::graph::NodeExcludeRule {
                        node_type: "tsdb_data".into(),
                        node_id_pattern: "metric_%".into(),
                    }),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        // Filter to OUR suffix to exclude prior in-mem state.
        let ours: Vec<_> = page
            .items
            .iter()
            .filter(|n| n.node_id.contains(&suffix))
            .collect();
        assert_eq!(ours.len(), 1);
        assert!(ours[0].node_id.starts_with("summary-"));
    }

    // ── v1.6.1 (CIRISPersist#67) attribute_match tests ──────────────

    /// Helper — build a node with caller-controlled attributes.
    fn fixture_node_with_attrs(
        node_id: &str,
        node_type: &str,
        attrs: serde_json::Value,
    ) -> GraphNode {
        let mut n = fixture_node(node_id, GraphScope::Local, node_type);
        n.attributes = attrs;
        n
    }

    #[tokio::test]
    async fn attribute_match_equals_any_filters_by_created_by() {
        let (_b, graph) = fresh_backend().await;
        let suffix = Uuid::new_v4().simple().to_string();

        // Three nodes with different `created_by`:
        graph
            .upsert_node(
                fixture_node_with_attrs(
                    &format!("alice-{suffix}"),
                    "memory",
                    serde_json::json!({"created_by": "alice"}),
                ),
                0,
                false,
            )
            .await
            .unwrap();
        graph
            .upsert_node(
                fixture_node_with_attrs(
                    &format!("bob-{suffix}"),
                    "memory",
                    serde_json::json!({"created_by": "bob"}),
                ),
                0,
                false,
            )
            .await
            .unwrap();
        graph
            .upsert_node(
                fixture_node_with_attrs(
                    &format!("carol-{suffix}"),
                    "memory",
                    serde_json::json!({"created_by": "carol"}),
                ),
                0,
                false,
            )
            .await
            .unwrap();

        // Filter to {alice, bob} — should return 2 rows.
        let page = graph
            .query_nodes(
                NodeFilter {
                    scope: Some(GraphScope::Local),
                    attribute_match: Some(crate::graph::AttributeMatch {
                        path: "created_by".into(),
                        equals_any: Some(vec!["alice".into(), "bob".into()]),
                        array_contains_any: None,
                    }),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        let ours: Vec<_> = page
            .items
            .iter()
            .filter(|n| n.node_id.contains(&suffix))
            .collect();
        assert_eq!(ours.len(), 2);
        let names: std::collections::HashSet<&str> =
            ours.iter().map(|n| n.node_id.as_str()).collect();
        assert!(names.iter().any(|n| n.starts_with("alice-")));
        assert!(names.iter().any(|n| n.starts_with("bob-")));
    }

    #[tokio::test]
    async fn attribute_match_array_contains_any_filters_user_list() {
        let (_b, graph) = fresh_backend().await;
        let suffix = Uuid::new_v4().simple().to_string();

        graph
            .upsert_node(
                fixture_node_with_attrs(
                    &format!("a-{suffix}"),
                    "memory",
                    serde_json::json!({"user_list": ["alice", "bob"]}),
                ),
                0,
                false,
            )
            .await
            .unwrap();
        graph
            .upsert_node(
                fixture_node_with_attrs(
                    &format!("b-{suffix}"),
                    "memory",
                    serde_json::json!({"user_list": ["carol"]}),
                ),
                0,
                false,
            )
            .await
            .unwrap();
        graph
            .upsert_node(
                fixture_node_with_attrs(
                    &format!("c-{suffix}"),
                    "memory",
                    serde_json::json!({"user_list": ["dave", "alice"]}),
                ),
                0,
                false,
            )
            .await
            .unwrap();

        // user_list ∋ alice → matches a-* and c-*.
        let page = graph
            .query_nodes(
                NodeFilter {
                    scope: Some(GraphScope::Local),
                    attribute_match: Some(crate::graph::AttributeMatch {
                        path: "user_list".into(),
                        equals_any: None,
                        array_contains_any: Some(vec!["alice".into()]),
                    }),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        let ours: Vec<_> = page
            .items
            .iter()
            .filter(|n| n.node_id.contains(&suffix))
            .collect();
        assert_eq!(ours.len(), 2);
    }

    #[tokio::test]
    async fn attribute_match_or_combines_equals_and_array_contains() {
        let (_b, graph) = fresh_backend().await;
        let suffix = Uuid::new_v4().simple().to_string();

        // a: created_by=alice (scalar match arm)
        graph
            .upsert_node(
                fixture_node_with_attrs(
                    &format!("a-{suffix}"),
                    "memory",
                    serde_json::json!({"created_by": "alice"}),
                ),
                0,
                false,
            )
            .await
            .unwrap();
        // b: user_list=[bob] (array-contains arm — same path different shape)
        graph
            .upsert_node(
                fixture_node_with_attrs(
                    &format!("b-{suffix}"),
                    "memory",
                    serde_json::json!({"created_by": ["bob"]}),
                ),
                0,
                false,
            )
            .await
            .unwrap();
        // c: created_by=eve (neither arm matches → excluded)
        graph
            .upsert_node(
                fixture_node_with_attrs(
                    &format!("c-{suffix}"),
                    "memory",
                    serde_json::json!({"created_by": "eve"}),
                ),
                0,
                false,
            )
            .await
            .unwrap();

        let page = graph
            .query_nodes(
                NodeFilter {
                    scope: Some(GraphScope::Local),
                    attribute_match: Some(crate::graph::AttributeMatch {
                        path: "created_by".into(),
                        equals_any: Some(vec!["alice".into()]),
                        array_contains_any: Some(vec!["bob".into()]),
                    }),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        let ours: Vec<_> = page
            .items
            .iter()
            .filter(|n| n.node_id.contains(&suffix))
            .collect();
        assert_eq!(ours.len(), 2, "alice (scalar) + bob (array) match");
    }

    #[tokio::test]
    async fn attribute_match_count_nodes_honors_filter() {
        let (_b, graph) = fresh_backend().await;
        let suffix = Uuid::new_v4().simple().to_string();
        for who in &["alice", "bob", "carol", "alice"] {
            graph
                .upsert_node(
                    fixture_node_with_attrs(
                        &format!("{who}-{}-{suffix}", Uuid::new_v4().simple()),
                        "memory",
                        serde_json::json!({"created_by": who}),
                    ),
                    0,
                    false,
                )
                .await
                .unwrap();
        }
        let n = graph
            .count_nodes(NodeFilter {
                scope: Some(GraphScope::Local),
                attribute_match: Some(crate::graph::AttributeMatch {
                    path: "created_by".into(),
                    equals_any: Some(vec!["alice".into()]),
                    array_contains_any: None,
                }),
                ..Default::default()
            })
            .await
            .unwrap();
        // We inserted 2 alice nodes for this suffix. May also include
        // leftover alice nodes from other tests; just check >= 2.
        assert!(n >= 2);
    }

    #[tokio::test]
    async fn attribute_match_empty_path_rejected() {
        let (_b, graph) = fresh_backend().await;
        let err = graph
            .query_nodes(
                NodeFilter {
                    scope: Some(GraphScope::Local),
                    attribute_match: Some(crate::graph::AttributeMatch {
                        path: "".into(),
                        equals_any: Some(vec!["x".into()]),
                        array_contains_any: None,
                    }),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn attribute_match_path_with_sql_injection_rejected() {
        let (_b, graph) = fresh_backend().await;
        let err = graph
            .query_nodes(
                NodeFilter {
                    scope: Some(GraphScope::Local),
                    attribute_match: Some(crate::graph::AttributeMatch {
                        path: "x'; DROP TABLE--".into(),
                        equals_any: Some(vec!["x".into()]),
                        array_contains_any: None,
                    }),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)));
    }

    /// CIRISPersist#58 defense-in-depth: encode_attributes guards
    /// against future regressions that might somehow produce non-UTF-8
    /// output. serde_json::to_string is UTF-8-safe by construction
    /// today; this test pins that invariant.
    #[test]
    fn encode_attributes_always_produces_valid_utf8() {
        // Tricky inputs: nested objects, unicode strings, escape
        // sequences, large nested arrays.
        let inputs = vec![
            serde_json::json!({"k": "v"}),
            serde_json::json!({"unicode": "日本語🎯"}),
            serde_json::json!({"escapes": "\u{0001}\u{007F}\n\r\t\\\""}),
            serde_json::json!({"nested": {"a": [1, 2, {"b": "c"}]}}),
        ];
        for v in inputs {
            let encoded = encode_attributes(&v, false).expect("encode succeeds");
            assert!(std::str::from_utf8(encoded.as_bytes()).is_ok());
        }
    }
}
