//! Legacy graph-migration substrate (v1.6.4, CIRISPersist#70).
//!
//! Absorbs CIRISAgent's `tools/ops/migrate_to_persist.py` reader —
//! the LAST raw-SQL gap in CIRISAgent 2.9.0. With this substrate
//! landed and consumed, the agent can drop `psycopg2` (PG path)
//! and `sqlite3` (SQLite path) from production `requirements.txt`.
//!
//! # What it does
//!
//! Reads the legacy 2.8.x agent graph tables — `public.graph_nodes`
//! and `public.graph_edges` on PG; `graph_nodes` and `graph_edges`
//! on SQLite — and re-upserts the rows via the existing
//! `crate::graph::GraphService::upsert_node` /
//! `crate::graph::GraphService::upsert_edge` surface into the
//! modern `cirisgraph.nodes` and `cirisgraph.edges` substrate. The
//! re-upsert uses `bulk_import = true` so the per-row AV-45 cap is
//! skipped at the graph layer — this substrate re-checks the cap
//! itself against an operator-overridable bound
//! (`types::LegacyMigrationOptions::attributes_cap_bytes`).
//!
//! # Idempotency
//!
//! Re-running is safe. The migration walks every legacy row but
//! the modern substrate enforces its own PK + version semantics:
//!
//! - `upsert_node` with `expected_version = 0` against an existing
//!   row returns [`crate::graph::Error::Conflict`] — we count that
//!   as `nodes_skipped_already_present` and continue.
//! - `upsert_edge` is `ON CONFLICT (edge_id) DO NOTHING` at the PG
//!   layer (and same idiom on SQLite), so re-running collapses to
//!   a no-op. We don't get a `Conflict` back for that path; instead
//!   the second run's "already present" count is tracked via
//!   `edges_skipped_already_present` — see the impl notes for how
//!   each backend distinguishes "wrote" vs "was already there".
//!
//! # Per-row decision tree (in order)
//!
//! For each legacy node:
//!
//! 1. Parse the legacy scope string into `crate::graph::GraphScope`
//!    via `crate::graph::GraphScope::from_sql_str`. Lowercase
//!    legacy values (`"local"`, `"identity"`, `"environment"`,
//!    `"community"`) are normalized to uppercase first.
//! 2. Re-serialize the attributes JSON and check size against
//!    `options.attributes_cap_bytes` (defaults to
//!    `crate::graph::DEFAULT_MAX_ATTRIBUTES_BYTES`, 1 MiB) —
//!    skip (`nodes_skipped_too_large`) if over.
//! 3. If `options.dry_run`, increment `nodes_read` and continue
//!    without writing.
//! 4. Call `upsert_node` with `expected_version = 0` + `bulk_import = true`.
//!    On `Ok` increment `nodes_written`. On `Conflict` increment
//!    `nodes_skipped_already_present`. On other errors increment
//!    `errors` + record `first_error_at_node_id` (if unset). If
//!    `errors >= options.stop_after_errors.unwrap_or(100)`, break
//!    the loop.
//!
//! For each legacy edge:
//!
//! 1. If `options.dry_run`, increment `edges_read` and continue.
//! 2. Call `upsert_edge` with `bulk_import = true`. On `Ok` we count
//!    the edge as written (`edges_written`) — the second-run
//!    "already present" distinction is observed by the backend
//!    impl via a pre-call existence probe rather than via the
//!    GraphService trait surface, which silently swallows
//!    duplicates.
//! 3. On `InvalidArgument` that looks like an FK violation (source
//!    or target node not present in `cirisgraph.nodes`), increment
//!    `edges_skipped_dangling_fk`. The PG layer's `map_pg_error`
//!    maps PG SQLSTATE `23503` to `InvalidArgument`; we don't enforce
//!    a graph-edges FK in V013 by design, so this path fires only
//!    when an upstream consumer added one.
//! 4. Other errors increment `errors`.
//!
//! # Outcome semantics
//!
//! - `errors == 0` → `"ok"`
//! - `errors > 0 && nodes_written == 0` → `"errors"`
//! - `errors > 0 && nodes_written > 0` → `"partial"`
//!
//! # Threat-model anchors (THREAT_MODEL.md)
//!
//! - **AV-15** — stable `kind()` tokens for FFI translation:
//!   `legacy_migration_invalid_argument`,
//!   `legacy_migration_not_found`,
//!   `legacy_migration_conflict`,
//!   `legacy_migration_backend`,
//!   `legacy_migration_internal`.

#[cfg(feature = "postgres")]
pub mod postgres;
pub mod service;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod types;

pub use service::LegacyMigrationService;
pub use types::{LegacyMigrationOptions, LegacyMigrationStats};

/// legacy-migration-layer errors.
///
/// THREAT_MODEL.md AV-15: stable `kind()` tokens for HTTP / PyO3
/// sanitization. Verbose `Display` messages stay in tracing only.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Caller passed invalid arguments — unknown legacy scope value,
    /// SQLite caller asked for non-`"public"` schema, etc.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// Row not found. Reserved — the migration's only "missing data"
    /// case is the legacy tables themselves, which the SQLite impl
    /// handles as a graceful no-op (returns `outcome = "ok"`, zero
    /// counts) rather than an error.
    #[error("not found: {0}")]
    NotFound(String),

    /// Constraint conflict. Reserved — per-row conflicts are
    /// surfaced via [`types::LegacyMigrationStats`] counters
    /// (`nodes_skipped_already_present`,
    /// `edges_skipped_already_present`), not raised out of the
    /// trait.
    #[error("conflict: {0}")]
    Conflict(String),

    /// Backend-level error (connection, transaction, lock).
    #[error("backend: {0}")]
    Backend(String),

    /// Internal serialization / type-conversion bug. Indicates a
    /// persist bug; operators should file an issue.
    #[error("internal: {0}")]
    Internal(String),
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    /// Mirrors the kind() convention from
    /// `crate::secrets::SecretsError` / `crate::cirisnode::Error` /
    /// `crate::service_token_revocation::Error`.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::InvalidArgument(_) => "legacy_migration_invalid_argument",
            Error::NotFound(_) => "legacy_migration_not_found",
            Error::Conflict(_) => "legacy_migration_conflict",
            Error::Backend(_) => "legacy_migration_backend",
            Error::Internal(_) => "legacy_migration_internal",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_tokens_stable() {
        assert_eq!(
            Error::InvalidArgument("x".into()).kind(),
            "legacy_migration_invalid_argument"
        );
        assert_eq!(
            Error::NotFound("x".into()).kind(),
            "legacy_migration_not_found"
        );
        assert_eq!(
            Error::Conflict("x".into()).kind(),
            "legacy_migration_conflict"
        );
        assert_eq!(
            Error::Backend("x".into()).kind(),
            "legacy_migration_backend"
        );
        assert_eq!(
            Error::Internal("x".into()).kind(),
            "legacy_migration_internal"
        );
    }
}
