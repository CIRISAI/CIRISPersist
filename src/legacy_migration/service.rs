//! `LegacyMigrationService` trait surface (v1.6.4, CIRISPersist#70).
//!
//! Single-method trait. Same `impl Future<...> + Send` GAT pattern
//! as the rest of the v0.8.x / v1.x substrate traits — no
//! `async_trait` dep.

use std::future::Future;

use super::types::{LegacyMigrationOptions, LegacyMigrationStats};
use super::Error;

/// Legacy graph-migration substrate trait — absorbs CIRISAgent's
/// `tools/ops/migrate_to_persist.py` reader.
pub trait LegacyMigrationService: Send + Sync {
    /// Read `<schema>.graph_nodes` + `<schema>.graph_edges` (legacy
    /// 2.8.x agent schema, per
    /// [`LegacyMigrationOptions::legacy_schema`]) and re-upsert
    /// into `cirisgraph.nodes` + `cirisgraph.edges`. Returns
    /// per-row counters.
    ///
    /// Idempotent: re-running is safe. Existing substrate rows are
    /// skipped via `expected_version` mismatch (counts as
    /// `nodes_skipped_already_present`) / PK collision (counts as
    /// `edges_skipped_already_present`).
    ///
    /// `dry_run = true` reads + parses + size-checks every row but
    /// does not write. `attributes_cap_bytes = Some(n)` overrides
    /// the default 1 MiB cap (the underlying `upsert_node` is
    /// called with `bulk_import = true` so the graph layer's cap
    /// is bypassed; this substrate re-checks against the
    /// operator-supplied bound itself).
    ///
    /// `stop_after_errors = Some(n)` halts the loop once the error
    /// count reaches `n` — partial progress so far is returned in
    /// the stats (with `outcome = "partial"` if any nodes were
    /// written, `"errors"` otherwise).
    fn run_legacy_graph_migration(
        &self,
        options: LegacyMigrationOptions,
    ) -> impl Future<Output = Result<LegacyMigrationStats, Error>> + Send;
}
