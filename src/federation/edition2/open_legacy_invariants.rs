//! **I2347** (v62.0.0 C2-fix2, ruling 4): a V300 store's open runs no legacy
//! step. A V300 store carries nothing forward (`store::edition_upgrade`
//! deletes an earlier store), so there is nothing for the v58/v59 key-plane
//! rehome, its report, the v59 framed-revocation carrier migration or the
//! v52-shape community-trust count to find. They are deleted, with their
//! callers.
//!
//! - C2-fix3: the same for the v61 group-plane rehome (v60 typed rows given
//!   their row once) and the v61.3.0 cosigned re-index at open (rows indexed
//!   under `sha256(bytes)` before v61.3.0 moved to the act's hash; every V300
//!   write indexes under `attestation_wire_hash` already).
//! - From disk: no Rust source under `src/` (comment lines stripped) names
//!   any of them. The needles are built from parts, so this file does not
//!   spell them.
//! - On sqlite and postgres: a fresh V300 store opens, and opens again (the
//!   open's data sweeps re-run), with nothing written to the edition-2
//!   statement store.

/// The deleted names, from parts.
fn needles() -> Vec<String> {
    [
        ("rehome_legacy", "_key_plane"),
        ("rehome_key_plane", "_at_open"),
        ("rehome_key_plane", "_before_write"),
        ("KeyPlane", "RehomeReport"),
        ("key_plane", "_rehomed"),
        ("migrate_legacy", "_framed"),
        ("framed_of", "_columns"),
        ("Carrier", "Migration"),
        ("legacy_community_trust", "_grants_at_open"),
        ("log_legacy_node", "_authored_grants"),
        ("is_legacy_node", "_authored_grant"),
        ("revocation_row", "_if_hybrid"),
        ("sqlite_rehome", "_revocation"),
        ("pg_rehome", "_revocation"),
        // v62.0.0 C2-fix3: the v60 group-plane rehome and the v61.3.0
        // cosigned re-index at open.
        ("rehome_group", "_records"),
        ("GroupRehome", "Report"),
        ("unlinked_group", "_objects"),
        ("reindex_cosigned", "_group_rows_at_open"),
        ("cosigned_group", "_row_ids"),
    ]
    .iter()
    .map(|(a, b)| format!("{a}{b}"))
    .collect()
}

#[test]
fn i2347_no_source_names_a_legacy_open_step() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let needles = needles();
    let (mut files, mut hits) = (0usize, Vec::new());
    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            if p.extension().is_none_or(|x| x != "rs") {
                continue;
            }
            files += 1;
            let text = std::fs::read_to_string(&p).unwrap();
            for (n, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for needle in &needles {
                    if line.contains(needle.as_str()) {
                        hits.push(format!("{}:{}: {needle}", p.display(), n + 1));
                    }
                }
            }
        }
    }
    assert!(files > 100, "I2347: the source walk collapsed ({files})");
    assert!(
        hits.is_empty(),
        "I2347: a legacy open step is back (ruling 4; a V300 store carries nothing forward): \
         {hits:#?}"
    );
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
async fn opens_clean(d: &dyn crate::federation::FederationDirectory, what: &str) {
    assert_eq!(
        d.edition2_statements_since(None, 10).await.unwrap(),
        vec![],
        "I2347 {what}: the open wrote no statement"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2347_a_fresh_v300_open_sqlite() {
    use crate::store::Backend as _;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c2fix2.db").to_str().unwrap().to_owned();
    let b = crate::store::sqlite::SqliteBackend::open(path.clone())
        .await
        .unwrap();
    b.run_migrations().await.expect("I2347: the first open");
    opens_clean(&b, "first").await;
    drop(b);
    let b = crate::store::sqlite::SqliteBackend::open(path.clone())
        .await
        .unwrap();
    b.run_migrations().await.expect("I2347: the re-open");
    opens_clean(&b, "re-open").await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2347_a_fresh_v300_open_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        return;
    };
    for what in ["first", "re-open"] {
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations()
            .await
            .unwrap_or_else(|e| panic!("I2347 {what}: {e:?}"));
        opens_clean(&b, what).await;
    }
}
