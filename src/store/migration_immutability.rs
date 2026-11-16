//! **The migration-immutability gate** (v44.1.1, CIRISPersist#840), pointed
//! at edition 2 (v62.0.0, slice E2b).
//!
//! The runner checksums a migration's *entire file text* —
//! `SipHasher13(name, version, sql)`, refinery's — and refuses a divergence
//! between the applied row and the file. A one-word edit inside a SQL comment
//! bricked every node that had applied edition 1's V070 (#840). The rule
//! stands for edition 2: **from v62 on, the shipped baseline
//! (`V300__edition2_baseline.sql`, each dialect) and every migration appended
//! after it are immutable as BYTES**; a correction is always a new migration.
//!
//! Edition 1 (V001..V216) is retired with its repairs: a v62 node deletes an
//! edition-1 store rather than continuing it ([`crate::store::edition_upgrade`]),
//! so the V070 checksum repair and the #845 portable-default rewrite have
//! nothing left to repair. #845's property stays as a gate: no shipped
//! migration names the `subsec` modifier (SQLite < 3.42 evaluates it to NULL).
//!
//! The constants are pure text with NO backend `cfg`; the checksum witnesses
//! carry one, because computing a checksum calls the runner, which only a
//! backend feature links — certify's five `axis-*-none` legs build this crate
//! with no backend at all.

/// #845 — the default expression edition 1's sqlite migrations wrote, which
/// SQLite < 3.42 evaluates to NULL. No shipped migration may name it.
#[cfg(test)]
pub(crate) const SQLITE_SUBSEC_DEFAULT: &str = "datetime('now', 'subsec')";
/// #845 — the portable form: byte-identical output (`YYYY-MM-DD HH:MM:SS.SSS`)
/// on every SQLite this crate has linked. The edition-2 baseline carries it.
#[cfg(test)]
pub(crate) const SQLITE_PORTABLE_DEFAULT: &str = "strftime('%Y-%m-%d %H:%M:%f', 'now')";

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
fn manifest_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("evidence/migration_checksums.tsv")
}

/// Every migration file name in the tree, as `(dialect, version, stem)`.
#[cfg(test)]
fn files_on_disk() -> Vec<(String, i32, std::path::PathBuf)> {
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
            let version: i32 = stem
                .strip_prefix('V')
                .and_then(|r| r.split_once("__"))
                .and_then(|(v, _)| v.parse().ok())
                .unwrap_or_else(|| panic!("{stem}: not V{{n}}__{{name}}"));
            out.push((dialect.to_string(), version, path));
        }
    }
    out
}

/// Every migration file in the tree, as `(dialect, version, name, checksum)`,
/// computed with the runner's (refinery's) hasher.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
fn checksums_on_disk() -> Vec<(String, i32, String, String)> {
    files_on_disk()
        .into_iter()
        .map(|(dialect, version, path)| {
            let stem = path.file_stem().unwrap().to_string_lossy().to_string();
            let name = stem.split_once("__").unwrap().1.to_owned();
            let sql = std::fs::read_to_string(&path).unwrap();
            let sum = crate::store::migration_runner::checksum(&name, version, &sql).to_string();
            (dialect, version, name, sum)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **Appends** rows for migrations not yet in
    /// `evidence/migration_checksums.tsv`. Run it when you ADD a migration
    /// (V301 and after):
    ///
    /// ```text
    /// cargo test --features sqlite emit_migration_checksum_manifest -- --ignored
    /// ```
    ///
    /// Append-only, and that is the point: a regenerating emitter would
    /// silently re-bless an edit to a SHIPPED migration — the exact thing
    /// #840 was. An existing row whose checksum no longer matches the file is
    /// a hard refusal: revert the edit, or write a new migration.
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
                            "{dialect} V{version:03} {name}: pinned {pinned_checksum}, on disk \
                             {checksum}"
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

    /// **I43 — a shipped migration is immutable; from v62 that is the
    /// edition-2 baseline and everything after it.**
    ///
    /// If this fails for a file you just ADDED, add its row. If it fails for
    /// a file you EDITED, revert the edit — the row is not the thing to
    /// change.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    #[test]
    fn shipped_migration_bytes_never_change() {
        let manifest = read_manifest(&std::fs::read_to_string(manifest_path()).unwrap());
        let disk = checksums_on_disk();

        // A from-disk gate that simply finds nothing must not pass: the
        // baseline is on disk for both dialects, and every file is pinned.
        let baseline = crate::store::edition_baseline::EDITION_TWO_BASELINE;
        for dialect in ["sqlite", "postgres"] {
            assert!(
                disk.iter()
                    .any(|(d, v, _, _)| d == dialect && *v == baseline),
                "{dialect}: the V{baseline} baseline is not on disk — the scan is broken"
            );
        }
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

    /// **I1952 (from disk) — edition 2 begins at the baseline.** Each
    /// dialect's first migration is `V300__edition2_baseline`, and no file is
    /// numbered below it: edition 1's files are retired, and an edition-2
    /// version can never be read as an edition-1 one.
    #[test]
    fn edition_two_begins_at_the_baseline() {
        let baseline = crate::store::edition_baseline::EDITION_TWO_BASELINE;
        let files = files_on_disk();
        for dialect in ["sqlite", "postgres"] {
            let mine: Vec<_> = files.iter().filter(|(d, _, _)| d == dialect).collect();
            assert!(!mine.is_empty(), "{dialect}: no migrations on disk");
            let (_, v, path) = mine[0];
            assert_eq!(
                (*v, path.file_name().unwrap().to_string_lossy().to_string()),
                (baseline, format!("V{baseline}__edition2_baseline.sql")),
                "{dialect}: edition 2's first migration is the baseline"
            );
            let below: Vec<_> = mine.iter().filter(|(_, v, _)| *v < baseline).collect();
            assert!(
                below.is_empty(),
                "{dialect}: {} migration(s) below the V{baseline} baseline",
                below.len()
            );
        }
    }

    /// **I56 (#845) — no shipped migration names `subsec`.** A file that
    /// reintroduces the modifier reds here before it reaches a bookworm host.
    #[test]
    fn no_migration_uses_subsec() {
        let mut offenders = Vec::new();
        let mut scanned = 0usize;
        for (dialect, _, path) in files_on_disk() {
            scanned += 1;
            let n = std::fs::read_to_string(&path)
                .unwrap()
                .matches("subsec")
                .count();
            if n > 0 {
                offenders.push(format!("{dialect}/{}: {n}", path.display()));
            }
        }
        assert!(scanned >= 2, "the scan found {scanned} file(s)");
        assert!(
            offenders.is_empty(),
            "`subsec` in a shipped migration — SQLite < 3.42 (Debian bookworm) evaluates it to \
             NULL (#845). Use {SQLITE_PORTABLE_DEFAULT:?}. Offenders:\n  {}",
            offenders.join("\n  ")
        );
    }

    /// **I57 (#845) — the bookworm witness checks for the modifier by its
    /// exact spelling**, so what CI proves on 3.40.1 is this gate's property.
    #[test]
    fn the_bookworm_witness_carries_the_literal() {
        let script = std::fs::read_to_string(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("scripts/sqlite_portability_witness.sh"),
        )
        .expect("scripts/sqlite_portability_witness.sh");
        assert!(
            script.contains(SQLITE_SUBSEC_DEFAULT),
            "the witness must name the default it refuses, {SQLITE_SUBSEC_DEFAULT:?}"
        );
        assert!(
            script.contains("V300__"),
            "the witness must apply the edition-2 baseline"
        );
    }

    /// **I58 (#845) — the `subsec` modifier appears in no source file but
    /// this one.** Runtime statements that evaluated it wrote NULL on SQLite
    /// < 3.42. Doc comments are held to it too, so nobody copies the old
    /// spelling out of one.
    #[test]
    fn the_subsec_modifier_appears_in_no_source_but_this_file() {
        fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
            for e in std::fs::read_dir(dir).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    out.push(p);
                }
            }
        }
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = Vec::new();
        walk(&root, &mut files);
        assert!(files.len() > 100, "the scan found {} files", files.len());
        let me = root.join("store/migration_immutability.rs");
        let mut offenders = Vec::new();
        for f in files {
            if f == me {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap();
            for (i, line) in text.lines().enumerate() {
                if line.contains("'subsec'") {
                    offenders.push(format!(
                        "{}:{}",
                        f.strip_prefix(&root).unwrap().display(),
                        i + 1
                    ));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "the `subsec` modifier is NULL on SQLite < 3.42 (#845); use \
             {SQLITE_PORTABLE_DEFAULT:?}. Found at:\n  {}",
            offenders.join("\n  ")
        );
    }
}
