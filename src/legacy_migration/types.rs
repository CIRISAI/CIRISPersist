//! Legacy migration wire types (v1.6.4, CIRISPersist#70).
//!
//! Both shapes round-trip through the PyO3 FFI as JSON strings so
//! the agent-side caller can decode with `pydantic.model_validate_json`.

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

/// Operator-supplied knobs for one migration run.
///
/// All fields default to safe values so a caller can pass `{}`
/// (decodes to `LegacyMigrationOptions::default()`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LegacyMigrationOptions {
    /// If true, only count what would be migrated; don't write.
    /// The size cap is still checked against legacy rows so the
    /// dry-run report matches what a real run would produce.
    #[serde(default)]
    pub dry_run: bool,

    /// Override the attributes size cap. `None` = inherit the
    /// persist default ([`crate::graph::DEFAULT_MAX_ATTRIBUTES_BYTES`],
    /// 1 MiB). `Some(n)` sets the cap to `n` bytes for THIS migration
    /// only — written via `bulk_import = true` on the underlying
    /// `upsert_node` call (which skips the cap entirely at the graph
    /// layer); this substrate re-checks against the operator-supplied
    /// bound itself so the count stays honest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes_cap_bytes: Option<usize>,

    /// Legacy schema name (Postgres only). Default `"public"`.
    /// Allows operators with non-default agent schemas to override.
    /// SQLite has no schema namespace; the SQLite impl rejects any
    /// non-`"public"` value with `Error::InvalidArgument`.
    #[serde(default = "default_legacy_schema")]
    pub legacy_schema: String,

    /// Stop after this many errors. `None` = no bound. Defaults to
    /// `Some(100)` to match the agent-side script's `--max-errors`
    /// flag. A `0` value behaves like "stop on first error" (the
    /// counter is incremented BEFORE the bound check).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_after_errors: Option<u64>,
}

fn default_legacy_schema() -> String {
    "public".to_owned()
}

impl Default for LegacyMigrationOptions {
    fn default() -> Self {
        Self {
            dry_run: false,
            attributes_cap_bytes: None,
            legacy_schema: default_legacy_schema(),
            stop_after_errors: Some(100),
        }
    }
}

/// Result of a migration run.
///
/// `outcome` is the discriminator the agent's bootstrap path uses
/// to decide whether to write the `.persist_migrated` sentinel — it
/// writes only on `"ok"`; `"partial"` / `"errors"` leaves the
/// sentinel absent so the next boot retries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LegacyMigrationStats {
    /// `"ok"` | `"errors"` | `"partial"`.
    pub outcome: String,
    pub nodes_read: i64,
    pub nodes_written: i64,
    pub nodes_skipped_already_present: i64,
    pub nodes_skipped_too_large: i64,
    pub edges_read: i64,
    pub edges_written: i64,
    pub edges_skipped_already_present: i64,
    pub edges_skipped_dangling_fk: i64,
    pub errors: i64,
    /// Set to the first node_id whose upsert raised an unhandled
    /// error (NOT counted in `nodes_skipped_*`). Useful for the
    /// agent's bootstrap log line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_error_at_node_id: Option<String>,
}

impl LegacyMigrationStats {
    /// Zero counters + `outcome = "ok"` baseline. The impl mutates
    /// counters in place and computes the final `outcome` via
    /// [`LegacyMigrationStats::finalize_outcome`] before returning.
    pub fn empty() -> Self {
        Self {
            outcome: "ok".to_owned(),
            nodes_read: 0,
            nodes_written: 0,
            nodes_skipped_already_present: 0,
            nodes_skipped_too_large: 0,
            edges_read: 0,
            edges_written: 0,
            edges_skipped_already_present: 0,
            edges_skipped_dangling_fk: 0,
            errors: 0,
            first_error_at_node_id: None,
        }
    }

    /// Pick the discriminator value based on the counters. Called
    /// at the tail of every run so the outcome is consistent across
    /// both backend impls.
    pub fn finalize_outcome(&mut self) {
        self.outcome = if self.errors > 0 && self.nodes_written > 0 {
            "partial".to_owned()
        } else if self.errors > 0 {
            "errors".to_owned()
        } else {
            "ok".to_owned()
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_default_is_safe() {
        let o = LegacyMigrationOptions::default();
        assert!(!o.dry_run);
        assert!(o.attributes_cap_bytes.is_none());
        assert_eq!(o.legacy_schema, "public");
        assert_eq!(o.stop_after_errors, Some(100));
    }

    #[test]
    fn options_decodes_empty_object_to_default() {
        // The PyO3 surface lets the caller pass `{}` — make sure
        // that round-trips to the default shape (with the
        // legacy_schema + stop_after_errors defaults baked in via
        // serde `default = …`).
        let o: LegacyMigrationOptions = serde_json::from_str("{}").unwrap();
        assert_eq!(o.legacy_schema, "public");
        assert!(!o.dry_run);
    }

    #[test]
    fn options_round_trip_all_fields() {
        let o = LegacyMigrationOptions {
            dry_run: true,
            attributes_cap_bytes: Some(2_097_152),
            legacy_schema: "other_schema".into(),
            stop_after_errors: None,
        };
        let s = serde_json::to_string(&o).unwrap();
        let back: LegacyMigrationOptions = serde_json::from_str(&s).unwrap();
        assert_eq!(o, back);
    }

    #[test]
    fn stats_finalize_outcome_ok_when_no_errors() {
        let mut s = LegacyMigrationStats::empty();
        s.nodes_written = 5;
        s.finalize_outcome();
        assert_eq!(s.outcome, "ok");
    }

    #[test]
    fn stats_finalize_outcome_errors_when_zero_writes() {
        let mut s = LegacyMigrationStats::empty();
        s.errors = 3;
        s.finalize_outcome();
        assert_eq!(s.outcome, "errors");
    }

    #[test]
    fn stats_finalize_outcome_partial_when_writes_and_errors() {
        let mut s = LegacyMigrationStats::empty();
        s.errors = 1;
        s.nodes_written = 4;
        s.finalize_outcome();
        assert_eq!(s.outcome, "partial");
    }

    #[test]
    fn stats_round_trip_with_first_error_at_node_id() {
        let mut s = LegacyMigrationStats::empty();
        s.errors = 1;
        s.first_error_at_node_id = Some("agent:datum-v3".into());
        s.finalize_outcome();
        let j = serde_json::to_string(&s).unwrap();
        let back: LegacyMigrationStats = serde_json::from_str(&j).unwrap();
        assert_eq!(back, s);
        assert!(j.contains("first_error_at_node_id"));
    }

    #[test]
    fn stats_skips_none_first_error_at_node_id_in_wire_form() {
        let s = LegacyMigrationStats::empty();
        let j = serde_json::to_string(&s).unwrap();
        assert!(
            !j.contains("first_error_at_node_id"),
            "None should be skipped"
        );
    }
}
