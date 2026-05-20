//! PostgreSQL impl of [`LegacyMigrationService`] (v1.6.4,
//! CIRISPersist#70).
//!
//! Reads the legacy 2.8.x agent tables — `{legacy_schema}.graph_nodes`
//! and `{legacy_schema}.graph_edges` — via the shared `PostgresBackend`
//! pool and re-upserts each row through
//! `crate::graph::GraphService::upsert_node` /
//! `crate::graph::GraphService::upsert_edge`.
//!
//! # `legacy_schema` interpolation
//!
//! The schema name is interpolated into the SELECT SQL because PG
//! doesn't allow parameter binding for object identifiers. To stay
//! defensive against SQL-injection from a misconfigured caller we
//! validate the schema string against a permissive identifier regex
//! (lowercase letters / digits / underscores, leading letter or
//! underscore, ≤ 63 chars matching PG's NAMEDATALEN-1) before
//! splicing. Default `"public"` and the common operator overrides
//! (`"app"`, `"agent"`, etc.) all pass this filter.

use std::collections::HashSet;

use super::service::LegacyMigrationService;
use super::types::{LegacyMigrationOptions, LegacyMigrationStats};
use super::Error;
use crate::graph::{self, GraphScope};
use crate::store::postgres::PostgresBackend;

fn map_pg_error(e: tokio_postgres::Error, op: &str) -> Error {
    let detail = e
        .as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string());
    Error::Backend(format!("{op}: {detail}"))
}

/// Parse a legacy timestamp string into a UTC `DateTime`
/// (CIRISPersist#72). The legacy 2.8.x agent schema declares
/// `created_at` / `updated_at` as `timestamp without time zone`;
/// the read SELECT casts them `::text`. This accepts both:
///
/// - **RFC 3339 / ISO 8601 with offset** — `timestamptz` columns
///   render as `2026-01-21 20:07:17.391754+00` or
///   `...T...+00:00`; parsed via `DateTime::parse_from_rfc3339`
///   after normalizing the space separator to `T`.
/// - **Naive (no offset)** — `timestamp` columns render as
///   `2026-01-21 20:07:17.391754` (or without sub-seconds);
///   parsed as `NaiveDateTime` and assumed UTC, mirroring the
///   pre-absorption `migrate_to_persist.py::normalize_datetime()`.
fn parse_legacy_timestamp(raw: &str) -> Result<chrono::DateTime<chrono::Utc>, Error> {
    let trimmed = raw.trim();
    // Normalize the PG `::text` space separator to the RFC 3339 'T'
    // for the offset-bearing attempt.
    let t_form = trimmed.replacen(' ', "T", 1);
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&t_form) {
        return Ok(dt.with_timezone(&chrono::Utc));
    }
    // PG `::text` of a timestamptz uses a 2-digit offset (`+00`),
    // which RFC 3339 rejects — retry with `:00` appended.
    if let Some(stripped) = t_form.strip_suffix("+00") {
        if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&format!("{stripped}+00:00")) {
            return Ok(dt.with_timezone(&chrono::Utc));
        }
    }
    // Naive forms — with and without fractional seconds. Assume UTC.
    for fmt in ["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(&t_form, fmt) {
            return Ok(chrono::DateTime::from_naive_utc_and_offset(
                naive,
                chrono::Utc,
            ));
        }
    }
    Err(Error::InvalidArgument(format!(
        "unparseable legacy timestamp: {raw:?}"
    )))
}

/// Validate that a caller-supplied legacy schema name is a safe PG
/// identifier. PG identifiers are case-folded to lowercase when
/// unquoted; we accept the lowercase form only to avoid the quoting
/// minefield. Returns the verbatim string when valid (caller splices
/// it into the SQL directly).
fn validate_legacy_schema(s: &str) -> Result<&str, Error> {
    if s.is_empty() || s.len() > 63 {
        return Err(Error::InvalidArgument(format!(
            "legacy_schema length out of range: {} (must be 1..=63)",
            s.len()
        )));
    }
    let mut chars = s.chars();
    let first = chars.next().unwrap();
    if !(first.is_ascii_lowercase() || first == '_') {
        return Err(Error::InvalidArgument(format!(
            "legacy_schema must start with lowercase letter or underscore (got {first:?})"
        )));
    }
    for c in chars {
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(Error::InvalidArgument(format!(
                "legacy_schema contains invalid character {c:?}"
            )));
        }
    }
    Ok(s)
}

/// Normalize a legacy scope string to the modern uppercase form. The
/// agent's 2.8.x writer used lowercase scopes; the persist schema's
/// CHECK constraint requires uppercase. Already-uppercase values
/// pass through unchanged.
fn normalize_scope_str(raw: &str) -> Result<GraphScope, Error> {
    let upper = raw.to_uppercase();
    GraphScope::from_sql_str(&upper)
        .ok_or_else(|| Error::InvalidArgument(format!("unknown legacy scope: {raw:?}")))
}

/// Read every node from `{schema}.graph_nodes` and re-upsert into
/// `cirisgraph.nodes`. Mutates `stats` in place.
async fn migrate_nodes(
    backend: &PostgresBackend,
    schema: &str,
    options: &LegacyMigrationOptions,
    stats: &mut LegacyMigrationStats,
) -> Result<(), Error> {
    use graph::GraphService;

    let cap = options
        .attributes_cap_bytes
        .unwrap_or(graph::DEFAULT_MAX_ATTRIBUTES_BYTES);
    let stop_at = options.stop_after_errors.unwrap_or(100);

    let client = backend
        .pool()
        .get()
        .await
        .map_err(|e| Error::Backend(format!("pool: {e}")))?;

    // Schema interpolation is safe because `schema` passed
    // `validate_legacy_schema` above (lowercase identifier chars
    // only).
    //
    // 8-column shape per CIRISAgent's pre-v2.9.0 schema (verified
    // via deepwiki against memory_query_helpers.py /
    // memory_queries.py / get_all_graph_nodes / sql_builders.py —
    // none of them SELECT signature columns). The cirisgraph.nodes
    // destination has signature columns but they're nullable; we
    // default them to NULL/false on the read side. The agent's
    // newer audit-envelope signing happens at write time on the new
    // cirisgraph schema, not on the legacy reader path.
    //
    // v1.6.5 (CIRISPersist#72): `created_at` / `updated_at` are
    // cast `::text` in the SELECT. The legacy 2.8.x agent schema
    // declares them `timestamp without time zone` (NaiveDateTime),
    // not `timestamptz` — tokio-postgres refuses to decode a
    // `timestamp` value into `chrono::DateTime<Utc>`. The `::text`
    // cast sidesteps the type mismatch entirely: a `timestamptz`
    // renders as `2026-01-21 20:07:17.391754+00`, a `timestamp` as
    // `2026-01-21 20:07:17.391754` — `parse_legacy_timestamp` below
    // accepts both (naive → UTC-assumed, mirroring the old
    // migrate_to_persist.py `normalize_datetime()`).
    let sql = format!(
        "SELECT node_id, scope, node_type, attributes_json, version, \
                updated_by, updated_at::text AS updated_at, \
                created_at::text AS created_at \
         FROM {schema}.graph_nodes"
    );
    let rows = client
        .query(&sql, &[])
        .await
        .map_err(|e| map_pg_error(e, "read legacy graph_nodes"))?;

    for row in &rows {
        stats.nodes_read += 1;

        let node_id: String = match row.try_get("node_id") {
            Ok(v) => v,
            Err(e) => {
                stats.errors += 1;
                if stats.first_error_at_node_id.is_none() {
                    stats.first_error_at_node_id = Some(format!("<decode failure: {e}>"));
                }
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };
        let scope_raw: String = match row.try_get("scope") {
            Ok(v) => v,
            Err(e) => {
                stats.errors += 1;
                if stats.first_error_at_node_id.is_none() {
                    stats.first_error_at_node_id = Some(node_id.clone());
                }
                tracing::warn!(node_id = %node_id, error = %e, "legacy scope decode failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };
        let scope = match normalize_scope_str(&scope_raw) {
            Ok(s) => s,
            Err(e) => {
                stats.errors += 1;
                if stats.first_error_at_node_id.is_none() {
                    stats.first_error_at_node_id = Some(node_id.clone());
                }
                tracing::warn!(node_id = %node_id, error = %e, "legacy scope normalize failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };

        // attributes_json arrives as JSONB; decode to serde_json::Value.
        let attrs_value: serde_json::Value = row
            .try_get::<_, Option<serde_json::Value>>("attributes_json")
            .map(|opt| opt.unwrap_or(serde_json::Value::Object(Default::default())))
            .unwrap_or(serde_json::Value::Object(Default::default()));

        // Size check against the operator-overridable cap. We
        // re-serialize once for an accurate byte count (the row's
        // JSONB storage shape differs from the JSON-text length
        // any caller would see).
        let serialized_len = match serde_json::to_vec(&attrs_value) {
            Ok(buf) => buf.len(),
            Err(e) => {
                stats.errors += 1;
                if stats.first_error_at_node_id.is_none() {
                    stats.first_error_at_node_id = Some(node_id.clone());
                }
                tracing::warn!(node_id = %node_id, error = %e, "attributes serialize failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };
        if serialized_len > cap {
            stats.nodes_skipped_too_large += 1;
            tracing::info!(
                node_id = %node_id, bytes = serialized_len, cap = cap,
                "legacy node attributes exceed cap, skipping"
            );
            continue;
        }

        let node_type: String = match row.try_get("node_type") {
            Ok(v) => v,
            Err(e) => {
                stats.errors += 1;
                if stats.first_error_at_node_id.is_none() {
                    stats.first_error_at_node_id = Some(node_id.clone());
                }
                tracing::warn!(node_id = %node_id, error = %e, "decode node_type failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };
        let version: i32 = row
            .try_get::<_, Option<i32>>("version")
            .ok()
            .flatten()
            .unwrap_or(1);
        let updated_by: String = row
            .try_get::<_, Option<String>>("updated_by")
            .ok()
            .flatten()
            .unwrap_or_else(|| "legacy_unattributed".to_owned());
        // created_at / updated_at arrive as `::text` (see SELECT
        // above) so a legacy `timestamp without time zone` column
        // doesn't fail the typed decode. parse_legacy_timestamp
        // accepts RFC 3339 and naive forms.
        let created_at_raw: String = match row.try_get::<_, Option<String>>("created_at") {
            Ok(Some(v)) => v,
            Ok(None) | Err(_) => {
                stats.errors += 1;
                if stats.first_error_at_node_id.is_none() {
                    stats.first_error_at_node_id = Some(node_id.clone());
                    stats.first_error_message =
                        Some("created_at is NULL or undecodable".to_owned());
                }
                tracing::warn!(node_id = %node_id, "decode created_at failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };
        let created_at = match parse_legacy_timestamp(&created_at_raw) {
            Ok(v) => v,
            Err(e) => {
                stats.errors += 1;
                if stats.first_error_at_node_id.is_none() {
                    stats.first_error_at_node_id = Some(node_id.clone());
                    stats.first_error_message =
                        Some(format!("created_at parse: {e} (raw={created_at_raw})"));
                }
                tracing::warn!(node_id = %node_id, error = %e, "parse created_at failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };
        let updated_at: chrono::DateTime<chrono::Utc> = row
            .try_get::<_, Option<String>>("updated_at")
            .ok()
            .flatten()
            .and_then(|s| parse_legacy_timestamp(&s).ok())
            .unwrap_or(created_at);
        // Legacy 8-column shape has no signature envelope — default
        // to None / false. The destination cirisgraph.nodes columns
        // are nullable.
        let signature: Option<String> = None;
        let signing_key_id: Option<String> = None;
        let signature_verified: bool = false;

        if options.dry_run {
            // Don't write, but DO count this row as "read" — we
            // already incremented `nodes_read` at the top of the
            // loop. The dry-run path returns without touching
            // `nodes_written` (or the per-error counters from the
            // upsert) so the report cleanly answers "what would
            // happen if I ran for real."
            continue;
        }

        let node = graph::GraphNode {
            node_id: node_id.clone(),
            scope,
            node_type,
            attributes: attrs_value,
            version: if version < 1 { 1 } else { version },
            updated_by,
            updated_at,
            created_at,
            signature,
            signing_key_id,
            signature_verified,
        };

        // `bulk_import = true` skips the graph layer's AV-45 cap —
        // we already checked our own cap above.
        match backend.upsert_node(node, 0, true).await {
            Ok(()) => {
                stats.nodes_written += 1;
            }
            Err(graph::Error::Conflict(_)) => {
                stats.nodes_skipped_already_present += 1;
            }
            Err(e) => {
                stats.errors += 1;
                if stats.first_error_at_node_id.is_none() {
                    stats.first_error_at_node_id = Some(node_id.clone());
                    stats.first_error_message = Some(format!("node upsert: {e}"));
                }
                tracing::warn!(node_id = %node_id, error = %e, "legacy node upsert failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
            }
        }
    }
    Ok(())
}

/// Load the set of `(node_id, scope_str)` pairs currently present
/// in `cirisgraph.nodes`. Used to detect dangling-FK edges before
/// we try to insert them (V013 doesn't enforce the FK at the schema
/// level by design — we do the check at the substrate layer to
/// preserve the agent-side script's behavior).
async fn snapshot_present_nodes(
    backend: &PostgresBackend,
) -> Result<HashSet<(String, String)>, Error> {
    let client = backend
        .pool()
        .get()
        .await
        .map_err(|e| Error::Backend(format!("pool: {e}")))?;
    let rows = client
        .query("SELECT node_id, scope FROM cirisgraph.nodes", &[])
        .await
        .map_err(|e| map_pg_error(e, "snapshot cirisgraph.nodes"))?;
    let mut out: HashSet<(String, String)> = HashSet::with_capacity(rows.len());
    for row in &rows {
        let nid: String = row
            .try_get("node_id")
            .map_err(|e| Error::Backend(format!("snapshot decode node_id: {e}")))?;
        let sc: String = row
            .try_get("scope")
            .map_err(|e| Error::Backend(format!("snapshot decode scope: {e}")))?;
        out.insert((nid, sc));
    }
    Ok(out)
}

/// Load the set of edge_ids currently present in `cirisgraph.edges`
/// (used to count `edges_skipped_already_present` on re-runs — the
/// GraphService trait swallows duplicate inserts via
/// `ON CONFLICT DO NOTHING`, so we need our own pre-check to
/// distinguish "wrote" vs "was already there").
async fn snapshot_present_edge_ids(backend: &PostgresBackend) -> Result<HashSet<String>, Error> {
    let client = backend
        .pool()
        .get()
        .await
        .map_err(|e| Error::Backend(format!("pool: {e}")))?;
    let rows = client
        .query("SELECT edge_id::text AS edge_id FROM cirisgraph.edges", &[])
        .await
        .map_err(|e| map_pg_error(e, "snapshot cirisgraph.edges"))?;
    let mut out: HashSet<String> = HashSet::with_capacity(rows.len());
    for row in &rows {
        let eid: String = row
            .try_get("edge_id")
            .map_err(|e| Error::Backend(format!("snapshot decode edge_id: {e}")))?;
        out.insert(eid);
    }
    Ok(out)
}

/// Read every edge from `{schema}.graph_edges` and re-upsert into
/// `cirisgraph.edges`. Mutates `stats` in place.
#[allow(clippy::too_many_lines)]
async fn migrate_edges(
    backend: &PostgresBackend,
    schema: &str,
    options: &LegacyMigrationOptions,
    stats: &mut LegacyMigrationStats,
) -> Result<(), Error> {
    use graph::GraphService;

    let stop_at = options.stop_after_errors.unwrap_or(100);

    let client = backend
        .pool()
        .get()
        .await
        .map_err(|e| Error::Backend(format!("pool: {e}")))?;
    // created_at::text — same #72 rationale as the node read.
    let sql = format!(
        "SELECT edge_id, source_node_id, target_node_id, scope, relationship, \
                weight, attributes_json, created_at::text AS created_at \
         FROM {schema}.graph_edges"
    );
    let rows = client
        .query(&sql, &[])
        .await
        .map_err(|e| map_pg_error(e, "read legacy graph_edges"))?;
    drop(client);

    let present_nodes = snapshot_present_nodes(backend).await?;
    let present_edges = snapshot_present_edge_ids(backend).await?;

    for row in &rows {
        stats.edges_read += 1;

        let edge_id: String = match row.try_get("edge_id") {
            Ok(v) => v,
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(error = %e, "legacy edge_id decode failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };

        if options.dry_run {
            continue;
        }

        let source: String = match row.try_get("source_node_id") {
            Ok(v) => v,
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(edge_id = %edge_id, error = %e, "decode source failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };
        let target: String = match row.try_get("target_node_id") {
            Ok(v) => v,
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(edge_id = %edge_id, error = %e, "decode target failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };
        let scope_raw: String = match row.try_get("scope") {
            Ok(v) => v,
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(edge_id = %edge_id, error = %e, "decode scope failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };
        let scope = match normalize_scope_str(&scope_raw) {
            Ok(s) => s,
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(edge_id = %edge_id, error = %e, "edge scope normalize failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };
        let scope_sql_str = scope.as_sql_str().to_owned();

        // Dangling-FK check — V013 doesn't enforce the FK at the
        // schema level by design; we do it here to mirror the
        // agent-side script.
        if !present_nodes.contains(&(source.clone(), scope_sql_str.clone()))
            || !present_nodes.contains(&(target.clone(), scope_sql_str.clone()))
        {
            stats.edges_skipped_dangling_fk += 1;
            continue;
        }

        // Already-present check — distinguishes second-run "skipped"
        // from first-run "wrote" since the GraphService trait
        // collapses both into `Ok(())`.
        if present_edges.contains(&edge_id) {
            stats.edges_skipped_already_present += 1;
            continue;
        }

        let relationship: String = match row.try_get("relationship") {
            Ok(v) => v,
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(edge_id = %edge_id, error = %e, "decode relationship failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
                continue;
            }
        };
        let weight: Option<f64> = row.try_get::<_, Option<f64>>("weight").ok().flatten();
        let attrs_value: serde_json::Value = row
            .try_get::<_, Option<serde_json::Value>>("attributes_json")
            .map(|opt| opt.unwrap_or(serde_json::Value::Object(Default::default())))
            .unwrap_or(serde_json::Value::Object(Default::default()));
        let created_at: chrono::DateTime<chrono::Utc> =
            match row.try_get::<_, Option<String>>("created_at") {
                Ok(Some(raw)) => match parse_legacy_timestamp(&raw) {
                    Ok(v) => v,
                    Err(e) => {
                        stats.errors += 1;
                        if stats.first_error_message.is_none() {
                            stats.first_error_message =
                                Some(format!("edge created_at parse: {e} (raw={raw})"));
                        }
                        tracing::warn!(edge_id = %edge_id, error = %e, "parse created_at failed");
                        if stats.errors as u64 >= stop_at {
                            break;
                        }
                        continue;
                    }
                },
                Ok(None) | Err(_) => {
                    stats.errors += 1;
                    if stats.first_error_message.is_none() {
                        stats.first_error_message =
                            Some("edge created_at is NULL or undecodable".to_owned());
                    }
                    tracing::warn!(edge_id = %edge_id, "decode created_at failed");
                    if stats.errors as u64 >= stop_at {
                        break;
                    }
                    continue;
                }
            };

        let edge = graph::GraphEdge {
            edge_id: edge_id.clone(),
            source_node_id: source,
            target_node_id: target,
            scope,
            relationship,
            weight,
            attributes: attrs_value,
            created_at,
        };

        match backend.upsert_edge(edge, true).await {
            Ok(()) => {
                stats.edges_written += 1;
            }
            Err(graph::Error::InvalidArgument(detail)) if detail.contains("FK") => {
                // Defensive: today V013 has no FK so this branch
                // shouldn't fire, but if an operator adds one this
                // catches it.
                stats.edges_skipped_dangling_fk += 1;
            }
            Err(graph::Error::Conflict(_)) => {
                // Race with another writer landed first.
                stats.edges_skipped_already_present += 1;
            }
            Err(e) => {
                stats.errors += 1;
                tracing::warn!(edge_id = %edge_id, error = %e, "legacy edge upsert failed");
                if stats.errors as u64 >= stop_at {
                    break;
                }
            }
        }
    }
    Ok(())
}

impl LegacyMigrationService for PostgresBackend {
    async fn run_legacy_graph_migration(
        &self,
        options: LegacyMigrationOptions,
    ) -> Result<LegacyMigrationStats, Error> {
        let schema = validate_legacy_schema(&options.legacy_schema)?.to_owned();
        let mut stats = LegacyMigrationStats::empty();
        migrate_nodes(self, &schema, &options, &mut stats).await?;
        // Even if migrate_nodes hit `stop_after_errors`, we attempt
        // edges too — the bound is a soft halt on the inner loop,
        // and an operator who's already over budget on nodes can
        // still benefit from observing the edge counters. (The
        // edge loop honors `stop_after_errors` independently.)
        migrate_edges(self, &schema, &options, &mut stats).await?;
        stats.finalize_outcome();
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::backend::Backend;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    /// Create the legacy 2.8.x agent-shaped tables (in the `public`
    /// schema) used to seed our fixtures. The qa-postgres container
    /// is shared with other tests so we tag every row with a UUID
    /// suffix and clean up at end via the `test_cleanup` helper.
    async fn ensure_legacy_tables(backend: &PostgresBackend) {
        let client = backend.pool().get().await.unwrap();
        client
            .batch_execute(
                // 8-column shape mirrors CIRISAgent's pre-v2.9.0
                // schema verbatim — catches regressions if anyone
                // re-adds signature columns to the SELECT.
                "CREATE TABLE IF NOT EXISTS public.graph_nodes (\
                    node_id TEXT NOT NULL,\
                    scope TEXT NOT NULL,\
                    node_type TEXT NOT NULL,\
                    attributes_json JSONB,\
                    version INTEGER DEFAULT 1,\
                    updated_by TEXT,\
                    updated_at TIMESTAMPTZ,\
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),\
                    PRIMARY KEY (node_id, scope)\
                );\
                 CREATE TABLE IF NOT EXISTS public.graph_edges (\
                    edge_id TEXT PRIMARY KEY,\
                    source_node_id TEXT NOT NULL,\
                    target_node_id TEXT NOT NULL,\
                    scope TEXT NOT NULL,\
                    relationship TEXT NOT NULL,\
                    weight DOUBLE PRECISION DEFAULT 1.0,\
                    attributes_json JSONB,\
                    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()\
                );",
            )
            .await
            .unwrap();
    }

    /// Remove the seeded legacy rows tagged with our test prefix.
    /// We can't `DROP TABLE` because we share the schema with other
    /// tests and don't know who else seeded data; per-prefix delete
    /// is the conservative cleanup.
    async fn cleanup_legacy(backend: &PostgresBackend, prefix: &str) {
        let client = backend.pool().get().await.unwrap();
        let _ = client
            .execute(
                "DELETE FROM public.graph_edges WHERE edge_id LIKE $1",
                &[&format!("{prefix}%")],
            )
            .await;
        let _ = client
            .execute(
                "DELETE FROM public.graph_nodes WHERE node_id LIKE $1",
                &[&format!("{prefix}%")],
            )
            .await;
        let _ = client
            .execute(
                "DELETE FROM cirisgraph.edges WHERE source_node_id LIKE $1 \
                                              OR target_node_id LIKE $1",
                &[&format!("{prefix}%")],
            )
            .await;
        let _ = client
            .execute(
                "DELETE FROM cirisgraph.nodes WHERE node_id LIKE $1",
                &[&format!("{prefix}%")],
            )
            .await;
    }

    async fn seed_node(
        backend: &PostgresBackend,
        node_id: &str,
        scope: &str,
        attrs: serde_json::Value,
    ) {
        let client = backend.pool().get().await.unwrap();
        client
            .execute(
                "INSERT INTO public.graph_nodes (\
                    node_id, scope, node_type, attributes_json, version, \
                    updated_by, updated_at, created_at\
                 ) VALUES ($1, $2, $3, $4, 1, 'legacy_unattributed', NOW(), NOW())",
                &[&node_id, &scope, &"agent", &attrs],
            )
            .await
            .unwrap();
    }

    async fn seed_edge(
        backend: &PostgresBackend,
        edge_id: &str,
        src: &str,
        tgt: &str,
        scope: &str,
    ) {
        let client = backend.pool().get().await.unwrap();
        client
            .execute(
                "INSERT INTO public.graph_edges (\
                    edge_id, source_node_id, target_node_id, scope, \
                    relationship, weight, attributes_json, created_at\
                 ) VALUES ($1, $2, $3, $4, 'OWNS', 1.0, '{}'::jsonb, NOW())",
                &[&edge_id, &src, &tgt, &scope],
            )
            .await
            .unwrap();
    }

    fn unique_prefix() -> String {
        format!("legmig-{}-", Uuid::new_v4().simple())
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn validate_legacy_schema_accepts_default() {
        assert_eq!(validate_legacy_schema("public").unwrap(), "public");
        assert_eq!(
            validate_legacy_schema("_underscore").unwrap(),
            "_underscore"
        );
        assert_eq!(validate_legacy_schema("agent_v2").unwrap(), "agent_v2");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn validate_legacy_schema_rejects_unsafe_input() {
        assert!(validate_legacy_schema("").is_err());
        assert!(validate_legacy_schema("Public").is_err()); // uppercase
        assert!(validate_legacy_schema("public; DROP").is_err());
        assert!(validate_legacy_schema("a-b").is_err());
        assert!(validate_legacy_schema(&"x".repeat(64)).is_err());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn happy_path_three_nodes_two_edges_writes_all() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        ensure_legacy_tables(&backend).await;

        let prefix = unique_prefix();
        cleanup_legacy(&backend, &prefix).await; // start clean

        let n1 = format!("{prefix}n1");
        let n2 = format!("{prefix}n2");
        let n3 = format!("{prefix}n3");
        seed_node(&backend, &n1, "local", serde_json::json!({"k": "v1"})).await;
        seed_node(&backend, &n2, "local", serde_json::json!({"k": "v2"})).await;
        seed_node(&backend, &n3, "local", serde_json::json!({"k": "v3"})).await;
        let e1_id = Uuid::new_v4().to_string();
        let e2_id = Uuid::new_v4().to_string();
        seed_edge(&backend, &e1_id, &n1, &n2, "local").await;
        seed_edge(&backend, &e2_id, &n2, &n3, "local").await;

        let stats = backend
            .run_legacy_graph_migration(LegacyMigrationOptions::default())
            .await
            .unwrap();

        // Other tests may share `public.graph_nodes`; assert
        // RELATIVE counts (>=) for the rows we seeded.
        assert!(
            stats.nodes_written >= 3,
            "expected >= 3 nodes_written, got {stats:?}"
        );
        assert!(
            stats.edges_written >= 2,
            "expected >= 2 edges_written, got {stats:?}"
        );
        assert_eq!(stats.errors, 0, "no errors expected, got {stats:?}");
        assert!(stats.outcome == "ok" || stats.outcome == "partial");

        // Verify the rows actually landed in cirisgraph.
        use graph::GraphService;
        let got = backend.get_node(&n1, GraphScope::Local).await.unwrap();
        assert!(got.is_some(), "n1 not present in cirisgraph.nodes");
        cleanup_legacy(&backend, &prefix).await;
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn rerun_is_idempotent_existing_rows_skipped() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        ensure_legacy_tables(&backend).await;

        let prefix = unique_prefix();
        cleanup_legacy(&backend, &prefix).await;

        let n1 = format!("{prefix}n1");
        let n2 = format!("{prefix}n2");
        seed_node(&backend, &n1, "local", serde_json::json!({})).await;
        seed_node(&backend, &n2, "local", serde_json::json!({})).await;
        let e1_id = Uuid::new_v4().to_string();
        seed_edge(&backend, &e1_id, &n1, &n2, "local").await;

        let first = backend
            .run_legacy_graph_migration(LegacyMigrationOptions::default())
            .await
            .unwrap();
        assert!(first.nodes_written >= 2);
        assert!(first.edges_written >= 1);

        let second = backend
            .run_legacy_graph_migration(LegacyMigrationOptions::default())
            .await
            .unwrap();
        // The second run's "written" delta against our seeded rows
        // should be zero — all 2 of ours hit `already_present`.
        assert!(
            second.nodes_skipped_already_present >= 2,
            "expected our 2 nodes skipped, got {second:?}"
        );
        assert!(
            second.edges_skipped_already_present >= 1,
            "expected our edge skipped, got {second:?}"
        );
        cleanup_legacy(&backend, &prefix).await;
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn oversized_attributes_skipped_not_written() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        ensure_legacy_tables(&backend).await;

        let prefix = unique_prefix();
        cleanup_legacy(&backend, &prefix).await;

        let nid = format!("{prefix}huge");
        // 1.5 MiB blob — exceeds the 1 MiB default cap.
        let huge_str = "x".repeat(1_572_864);
        seed_node(
            &backend,
            &nid,
            "local",
            serde_json::json!({"blob": huge_str}),
        )
        .await;

        let stats = backend
            .run_legacy_graph_migration(LegacyMigrationOptions::default())
            .await
            .unwrap();
        assert!(
            stats.nodes_skipped_too_large >= 1,
            "expected >= 1 nodes_skipped_too_large, got {stats:?}"
        );

        // Verify it really isn't in cirisgraph.
        use graph::GraphService;
        let got = backend.get_node(&nid, GraphScope::Local).await.unwrap();
        assert!(got.is_none(), "oversized node should not have landed");
        cleanup_legacy(&backend, &prefix).await;
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn dry_run_reads_but_doesnt_write() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        ensure_legacy_tables(&backend).await;

        let prefix = unique_prefix();
        cleanup_legacy(&backend, &prefix).await;

        let n1 = format!("{prefix}n1");
        let n2 = format!("{prefix}n2");
        seed_node(&backend, &n1, "local", serde_json::json!({})).await;
        seed_node(&backend, &n2, "local", serde_json::json!({})).await;

        let opts = LegacyMigrationOptions {
            dry_run: true,
            ..Default::default()
        };
        let stats = backend.run_legacy_graph_migration(opts).await.unwrap();
        assert!(stats.nodes_read >= 2);
        assert_eq!(stats.nodes_written, 0, "dry_run must not write");

        use graph::GraphService;
        let got = backend.get_node(&n1, GraphScope::Local).await.unwrap();
        assert!(got.is_none(), "dry_run must not have written n1");
        cleanup_legacy(&backend, &prefix).await;
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn dangling_edge_fk_counted_not_errored() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        ensure_legacy_tables(&backend).await;

        let prefix = unique_prefix();
        cleanup_legacy(&backend, &prefix).await;

        // Seed an edge whose source + target nodes are absent from
        // both legacy graph_nodes and cirisgraph.nodes.
        let e_id = Uuid::new_v4().to_string();
        let absent_src = format!("{prefix}absent-src");
        let absent_tgt = format!("{prefix}absent-tgt");
        seed_edge(&backend, &e_id, &absent_src, &absent_tgt, "local").await;

        let stats = backend
            .run_legacy_graph_migration(LegacyMigrationOptions::default())
            .await
            .unwrap();
        assert!(
            stats.edges_skipped_dangling_fk >= 1,
            "expected >= 1 dangling edge, got {stats:?}"
        );
        assert_eq!(stats.errors, 0, "dangling FK must not raise");
        cleanup_legacy(&backend, &prefix).await;
    }

    /// CIRISPersist#72 — legacy 2.8.x agent schema declares
    /// `created_at` / `updated_at` as `timestamp without time zone`
    /// (NOT `timestamptz`). Pre-fix, every node errored on the typed
    /// decode and Postgres production upgrades copied 0 rows. This
    /// test seeds a dedicated schema with naive-timestamp columns
    /// and confirms the migration succeeds end-to-end.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn naive_timestamp_legacy_columns_migrate_ok() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // Dedicated schema so the naive-timestamp DDL doesn't collide
        // with the shared `public.graph_nodes` (timestamptz) other
        // tests created. Also exercises the `legacy_schema` override.
        let client = backend.pool().get().await.unwrap();
        client
            .batch_execute(
                "DROP SCHEMA IF EXISTS legacy_naive_probe CASCADE;\
                 CREATE SCHEMA legacy_naive_probe;\
                 CREATE TABLE legacy_naive_probe.graph_nodes (\
                    node_id text NOT NULL, scope text NOT NULL, \
                    node_type text NOT NULL, attributes_json jsonb, \
                    version integer DEFAULT 1, updated_by text, \
                    updated_at timestamp without time zone, \
                    created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP, \
                    PRIMARY KEY (node_id, scope));\
                 CREATE TABLE legacy_naive_probe.graph_edges (\
                    edge_id text PRIMARY KEY, source_node_id text, \
                    target_node_id text, scope text, relationship text, \
                    weight real DEFAULT 1.0, attributes_json jsonb, \
                    created_at timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP);",
            )
            .await
            .unwrap();

        let prefix = unique_prefix();
        let n1 = format!("{prefix}naive-n1");
        let n2 = format!("{prefix}naive-n2");
        // Naive timestamp literals — no offset, exactly the shape a
        // legacy `timestamp` column yields under `::text`.
        client
            .execute(
                "INSERT INTO legacy_naive_probe.graph_nodes \
                 (node_id, scope, node_type, attributes_json, version, \
                  updated_by, updated_at, created_at) \
                 VALUES ($1,'local','concept','{\"k\":\"v\"}'::jsonb,1,'t', \
                         '2026-01-21 20:07:17.391754', \
                         '2026-01-21 20:07:17.410044'), \
                        ($2,'local','concept','{\"k\":\"v\"}'::jsonb,1,'t', \
                         '2026-01-21 20:07:18', '2026-01-21 20:07:18')",
                &[&n1, &n2],
            )
            .await
            .unwrap();
        let e_id = Uuid::new_v4().to_string();
        client
            .execute(
                "INSERT INTO legacy_naive_probe.graph_edges \
                 (edge_id, source_node_id, target_node_id, scope, \
                  relationship, weight, attributes_json, created_at) \
                 VALUES ($1,$2,$3,'local','RELATED',1.0,'{}'::jsonb, \
                         '2026-01-21 20:07:19.5')",
                &[&e_id, &n1, &n2],
            )
            .await
            .unwrap();
        drop(client);

        let opts = LegacyMigrationOptions {
            legacy_schema: "legacy_naive_probe".to_owned(),
            ..LegacyMigrationOptions::default()
        };
        let stats = backend.run_legacy_graph_migration(opts).await.unwrap();
        assert_eq!(
            stats.errors, 0,
            "naive-timestamp nodes must not error, got {stats:?}"
        );
        assert_eq!(stats.nodes_written, 2, "both nodes written: {stats:?}");
        assert_eq!(stats.edges_written, 1, "edge written: {stats:?}");
        assert_eq!(stats.outcome, "ok");
        assert!(stats.first_error_message.is_none());

        // Verify the naive created_at landed as UTC.
        use graph::GraphService;
        let got = backend
            .get_node(&n1, GraphScope::Local)
            .await
            .unwrap()
            .expect("n1 in cirisgraph");
        assert_eq!(
            got.created_at.to_rfc3339(),
            "2026-01-21T20:07:17.410044+00:00"
        );

        // Cleanup.
        let client = backend.pool().get().await.unwrap();
        let _ = client
            .batch_execute("DROP SCHEMA IF EXISTS legacy_naive_probe CASCADE;")
            .await;
        let _ = client
            .execute(
                "DELETE FROM cirisgraph.nodes WHERE node_id LIKE $1",
                &[&format!("{prefix}%")],
            )
            .await;
    }

    /// CIRISPersist#72 helper-coverage — `parse_legacy_timestamp`
    /// accepts the three shapes the `::text` cast can yield.
    #[test]
    fn parse_legacy_timestamp_accepts_naive_and_tz_forms() {
        // Naive with fractional seconds (legacy `timestamp` column).
        let a = parse_legacy_timestamp("2026-01-21 20:07:17.391754").unwrap();
        assert_eq!(a.to_rfc3339(), "2026-01-21T20:07:17.391754+00:00");
        // Naive without fractional seconds.
        let b = parse_legacy_timestamp("2026-01-21 20:07:18").unwrap();
        assert_eq!(b.to_rfc3339(), "2026-01-21T20:07:18+00:00");
        // timestamptz `::text` 2-digit offset.
        let c = parse_legacy_timestamp("2026-01-21 20:07:17.391754+00").unwrap();
        assert_eq!(c.to_rfc3339(), "2026-01-21T20:07:17.391754+00:00");
        // Full RFC 3339.
        let d = parse_legacy_timestamp("2026-01-21T20:07:17.391754+00:00").unwrap();
        assert_eq!(d.to_rfc3339(), "2026-01-21T20:07:17.391754+00:00");
        // Garbage rejects.
        assert!(parse_legacy_timestamp("not-a-timestamp").is_err());
    }
}
