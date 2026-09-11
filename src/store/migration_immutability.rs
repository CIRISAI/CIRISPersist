//! **The migration-immutability gate** (v44.1.1, CIRISPersist#840).
//!
//! `refinery` checksums a migration's *entire file text* —
//! `SipHasher13(name, version, sql)` — and aborts on any divergence between
//! the applied row and the file. A one-word edit inside a SQL comment
//! (`4847ede5`, the `ENCRYPTED_AT_REST.md` → `BLOB_ENCRYPTION_AT_REST.md`
//! rename) therefore bricked every node that had applied V070 before it, on
//! every release from v43.0.0 through v44.1.0.
//!
//! This module is the gate that makes the class unrepeatable, plus the
//! narrow repair for the nodes the break already reached. See
//! `FSD/MIGRATION_IMMUTABILITY.md` (I43, I44).
//!
//! The constants and the repair statement are pure and carry NO backend
//! `cfg`: they are just text. The witnesses do carry one, because computing
//! a checksum means calling `refinery`, which only a backend feature links —
//! certify's five `axis-*-none` legs build this crate with no backend at
//! all, and an ungated caller of backend plumbing reds exactly there.

// Which of these items is live depends on the backend feature set: the
// sqlite constants are dead under `--features postgres` and vice versa, and
// BOTH are live in the from-disk witnesses, which must compile with NO
// backend at all (certify's five `axis-*-none` legs). A backend `cfg` on a
// pure constant is the mistake that costs a certification run, so the items
// stay unconditional and carry the allow instead.

/// The one version #840 broke.
pub(crate) const V070_VERSION: i32 = 70;
/// V070's refinery *name* — the file stem with the `V070__` prefix stripped.
pub(crate) const V070_NAME: &str = "ceg_018_at_rest_blob_key_grants";

/// What `4847ede5` changed, as the substitution itself. The repair's two
/// pinned checksums are proved against this by
/// [`tests::the_pinned_checksums_are_the_two_variants_of_v070`]: applying it
/// to the shipped file reproduces the bricked text byte for byte.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) const V070_BREAKING_EDIT: (&str, &str) = (
    "-- ENCRYPTED_AT_REST.md §4.3.",
    "-- BLOB_ENCRYPTION_AT_REST.md §4.3.",
);

/// The checksum every node recorded that applied V070 from a release at or
/// before v42.1.0 — the bytes the tree ships again as of v44.1.1.
#[allow(dead_code)]
pub(crate) const V070_CANONICAL_CHECKSUM_SQLITE: &str = "7163486563775091993";
/// The checksum a node recorded that applied V070 from v43.0.0–v44.1.0.
#[allow(dead_code)]
pub(crate) const V070_BRICKED_CHECKSUM_SQLITE: &str = "13308137435046530964";
/// Postgres twin of [`V070_CANONICAL_CHECKSUM_SQLITE`]. The dialects ship
/// different text, so they check differently.
#[allow(dead_code)]
pub(crate) const V070_CANONICAL_CHECKSUM_POSTGRES: &str = "15706685101112936341";
/// Postgres twin of [`V070_BRICKED_CHECKSUM_SQLITE`].
#[allow(dead_code)]
pub(crate) const V070_BRICKED_CHECKSUM_POSTGRES: &str = "10440797932346982783";

/// Which dialect's constants a repair should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Dialect {
    Sqlite,
    Postgres,
}

impl Dialect {
    #[allow(dead_code)]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Dialect::Sqlite => "sqlite",
            Dialect::Postgres => "postgres",
        }
    }

    /// The schema-history table this backend runs refinery against.
    pub(crate) fn history_table(self) -> &'static str {
        match self {
            // sqlite takes refinery's default.
            Dialect::Sqlite => "refinery_schema_history",
            Dialect::Postgres => "ciris_persist_schema_history",
        }
    }

    fn canonical_checksum(self) -> &'static str {
        match self {
            Dialect::Sqlite => V070_CANONICAL_CHECKSUM_SQLITE,
            Dialect::Postgres => V070_CANONICAL_CHECKSUM_POSTGRES,
        }
    }

    fn bricked_checksum(self) -> &'static str {
        match self {
            Dialect::Sqlite => V070_BRICKED_CHECKSUM_SQLITE,
            Dialect::Postgres => V070_BRICKED_CHECKSUM_POSTGRES,
        }
    }
}

/// #840 (I44) — the repair, as one conditional UPDATE.
///
/// Narrow on purpose: version 70, that exact name, and the ONE literal
/// checksum the broken releases wrote. A row that diverged for any other
/// reason is left alone and still aborts the boot, which is the correct
/// outcome — this is not a general checksum-repair facility.
///
/// `$1`-style placeholders differ per dialect, so the statement is built
/// with its literals inline; every one of them is a compile-time constant
/// of this module, never caller data.
#[allow(dead_code)]
pub(crate) fn repair_statement(dialect: Dialect) -> String {
    format!(
        "UPDATE {table} SET checksum = '{canonical}' \
         WHERE version = {version} AND name = '{name}' AND checksum = '{bricked}'",
        table = dialect.history_table(),
        canonical = dialect.canonical_checksum(),
        version = V070_VERSION,
        name = V070_NAME,
        bricked = dialect.bricked_checksum(),
    )
}

/// #840 (I44) — is the schema-history table present? A fresh database has
/// none, and the repair must be a silent no-op there rather than an error.
#[allow(dead_code)]
pub(crate) const SQLITE_HISTORY_TABLE_PROBE: &str =
    "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'refinery_schema_history'";

/// Postgres twin of [`SQLITE_HISTORY_TABLE_PROBE`].
#[allow(dead_code)]
pub(crate) const POSTGRES_HISTORY_TABLE_PROBE: &str =
    "SELECT to_regclass('ciris_persist_schema_history') IS NOT NULL";

/// Parse `evidence/migration_checksums.tsv` into `(dialect, version) -> (name, checksum)`.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
fn read_manifest(text: &str) -> std::collections::BTreeMap<(String, i32), (String, String)> {
    let mut out = std::collections::BTreeMap::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            cols.len(),
            4,
            "evidence/migration_checksums.tsv: expected 4 tab-separated columns, got {}: {line}",
            cols.len()
        );
        let version: i32 = cols[1]
            .parse()
            .unwrap_or_else(|_| panic!("bad version column: {line}"));
        out.insert(
            (cols[0].to_string(), version),
            (cols[2].to_string(), cols[3].to_string()),
        );
    }
    out
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
#[allow(dead_code)]
fn manifest_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("evidence/migration_checksums.tsv")
}

/// Every migration file in the tree, as `(dialect, version, name, checksum)`,
/// computed with refinery's own hasher.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
fn checksums_on_disk() -> Vec<(String, i32, String, String)> {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let mut out = Vec::new();
    for dialect in ["sqlite", "postgres"] {
        let dir = root.join(dialect).join("lens");
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read {dir:?}: {e}"))
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "sql"))
            .collect();
        entries.sort();
        for path in entries {
            let stem = path.file_stem().unwrap().to_string_lossy().to_string();
            let sql = std::fs::read_to_string(&path).unwrap();
            let m = refinery::Migration::unapplied(&stem, &sql)
                .unwrap_or_else(|e| panic!("refinery could not parse {stem}: {e}"));
            out.push((
                dialect.to_string(),
                m.version() as i32,
                m.name().to_string(),
                m.checksum().to_string(),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Appends** rows for migrations not yet in
    /// `evidence/migration_checksums.tsv`. Run it when you ADD a migration:
    ///
    /// ```text
    /// cargo test --features sqlite emit_migration_checksum_manifest -- --ignored
    /// ```
    ///
    /// It is append-only, and that is the point. A regenerating emitter would
    /// silently re-bless an edit to a SHIPPED migration — the exact thing
    /// #840 was — the first time someone ran it to clear a red. So an
    /// existing row whose checksum no longer matches the file is a hard
    /// refusal here too: revert the edit, or write a new migration.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[test]
    #[ignore = "writes evidence/migration_checksums.tsv; run deliberately"]
    fn emit_migration_checksum_manifest() {
        let path = manifest_path();
        let existing_text = std::fs::read_to_string(&path).unwrap_or_default();
        let existing = read_manifest(&existing_text);

        let mut added = Vec::new();
        let mut edited = Vec::new();
        for (dialect, version, name, checksum) in checksums_on_disk() {
            match existing.get(&(dialect.clone(), version)) {
                Some((pinned_name, pinned_checksum)) => {
                    if pinned_name != &name || pinned_checksum != &checksum {
                        edited.push(format!(
                            "{dialect} V{version:03} {name}: pinned {pinned_checksum}, on disk                              {checksum}"
                        ));
                    }
                }
                None => added.push(format!("{dialect}\t{version}\t{name}\t{checksum}")),
            }
        }

        assert!(
            edited.is_empty(),
            "refusing to re-pin {} SHIPPED migration(s) — this emitter only ADDS rows.\n  {}\n\
             Revert the edit, or make the correction a NEW migration (#840).",
            edited.len(),
            edited.join("\n  ")
        );

        if added.is_empty() {
            eprintln!("manifest already covers every migration; nothing to add");
            return;
        }
        let mut out = existing_text;
        if !out.ends_with('\n') {
            out.push('\n');
        }
        for row in &added {
            out.push_str(row);
            out.push('\n');
        }
        std::fs::write(&path, out).unwrap();
        eprintln!("appended {} row(s) to {path:?}", added.len());
    }

    /// **I43 — a migration file that has shipped in a release is immutable.**
    ///
    /// The manifest is the record of what the fleet applied. Editing a
    /// shipped migration changes its checksum and bricks every node that
    /// already ran it (#840), so the fix for a bad migration is always a NEW
    /// migration.
    ///
    /// If this fails for a file you just ADDED, add its row. If it fails for
    /// a file you EDITED, revert the edit — the row is not the thing to
    /// change.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[test]
    fn shipped_migration_bytes_never_change() {
        let manifest = read_manifest(&std::fs::read_to_string(manifest_path()).unwrap());
        let disk = checksums_on_disk();

        // A from-disk gate that simply finds nothing must not pass: assert
        // the count both ways before comparing any value.
        assert!(
            disk.len() > 140,
            "only {} migration files found — the scan is broken, not the tree",
            disk.len()
        );
        assert_eq!(
            manifest.len(),
            disk.len(),
            "evidence/migration_checksums.tsv has {} rows for {} migration files on disk",
            manifest.len(),
            disk.len()
        );

        let mut changed = Vec::new();
        for (dialect, version, name, checksum) in &disk {
            match manifest.get(&(dialect.clone(), *version)) {
                None => changed.push(format!(
                    "{dialect} V{version:03} {name}: on disk, NOT in the manifest — a new \
                     migration: add the row `{dialect}\t{version}\t{name}\t{checksum}`"
                )),
                Some((pinned_name, pinned_checksum)) => {
                    if pinned_name != name || pinned_checksum != checksum {
                        changed.push(format!(
                            "{dialect} V{version:03} {name}: checksum {checksum} but the fleet \
                             applied {pinned_checksum} (name pinned {pinned_name}) — this file \
                             has SHIPPED; editing it bricks every node that ran it (#840). \
                             Revert the edit and write a new migration instead."
                        ));
                    }
                }
            }
        }
        for (dialect, version) in manifest.keys() {
            if !disk.iter().any(|(d, v, _, _)| d == dialect && v == version) {
                changed.push(format!(
                    "{dialect} V{version:03}: pinned in the manifest, MISSING on disk — a \
                     shipped migration was deleted or renamed"
                ));
            }
        }
        assert!(
            changed.is_empty(),
            "migration bytes changed:\n  {}",
            changed.join("\n  ")
        );
    }

    /// #840 — the two pinned V070 checksums are what they claim to be:
    /// the shipped file's, and the shipped file's with `4847ede5`'s one-word
    /// comment edit applied. Recomputed from the file, so the repair cannot
    /// carry a stale literal, and the numbers are spelled out rather than
    /// derived from the same call the repair uses.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[test]
    fn the_pinned_checksums_are_the_two_variants_of_v070() {
        for (dialect, canonical, bricked) in [
            (
                Dialect::Sqlite,
                V070_CANONICAL_CHECKSUM_SQLITE,
                V070_BRICKED_CHECKSUM_SQLITE,
            ),
            (
                Dialect::Postgres,
                V070_CANONICAL_CHECKSUM_POSTGRES,
                V070_BRICKED_CHECKSUM_POSTGRES,
            ),
        ] {
            let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("migrations")
                .join(dialect.as_str())
                .join("lens/V070__ceg_018_at_rest_blob_key_grants.sql");
            let shipped = std::fs::read_to_string(&path).unwrap();
            let stem = "V070__ceg_018_at_rest_blob_key_grants";

            let (from, to) = V070_BREAKING_EDIT;
            assert!(
                shipped.contains(from),
                "{}: the shipped V070 no longer contains {from:?} — the repair's premise is \
                 gone; #840's edit cannot be reproduced and the pinned bricked checksum is \
                 unprovable",
                dialect.as_str()
            );
            let broken = shipped.replace(from, to);
            assert_ne!(shipped, broken, "the substitution changed nothing");

            let m_canon = refinery::Migration::unapplied(stem, &shipped).unwrap();
            let m_brick = refinery::Migration::unapplied(stem, &broken).unwrap();

            assert_eq!(
                m_canon.checksum().to_string(),
                canonical,
                "{}: pinned CANONICAL checksum is not the shipped file's",
                dialect.as_str()
            );
            assert_eq!(
                m_brick.checksum().to_string(),
                bricked,
                "{}: pinned BRICKED checksum is not that of the v43.0.0–v44.1.0 text",
                dialect.as_str()
            );
            assert_ne!(canonical, bricked, "the two variants must differ");
            assert_eq!(m_canon.version() as i32, V070_VERSION);
            assert_eq!(m_canon.name(), V070_NAME);
        }
    }

    /// The repair names one version, one name and one checksum, and writes
    /// one. A statement that matched on version alone would rewrite a
    /// genuinely divergent row and hide a real break.
    #[test]
    fn the_repair_is_narrow() {
        for dialect in [Dialect::Sqlite, Dialect::Postgres] {
            let sql = repair_statement(dialect);
            assert!(sql.starts_with(&format!(
                "UPDATE {} SET checksum = ",
                dialect.history_table()
            )));
            assert!(sql.contains("WHERE version = 70 AND name = 'ceg_018_at_rest_blob_key_grants'"));
            assert!(
                sql.contains(&format!("checksum = '{}'", dialect.bricked_checksum())),
                "the repair must match ONLY the bricked checksum"
            );
            assert!(sql.contains(&format!(
                "SET checksum = '{}'",
                dialect.canonical_checksum()
            )));
            // No data from anywhere but this module's constants.
            assert!(!sql.contains('$') && !sql.contains('?'));
        }
    }
}
