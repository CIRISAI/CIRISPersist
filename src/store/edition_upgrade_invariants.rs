//! v62.0.0 (slice E2b) — the edition-2 baseline and the upgrade that deletes
//! the earlier store: I1953–I1959 (I1950 sits beside the baseline in
//! `edition_baseline.rs`, I1951 with the runner, I1952 with the immutability
//! gate).
//!
//! An edition-1 store is built here as the baseline WITHOUT the edition-2
//! additions (and with `federation_keys`' edition-2 columns, which the
//! upgrade never reads), under edition 1's applied history
//! (`tests/fixtures/edition1_schema/{dialect}.history`, every row an
//! edition-1 store recorded). I1950 proves that schema IS edition 1's at
//! V216, so the store under test is the store a v61 node leaves behind.

#![allow(clippy::unwrap_used, clippy::expect_used)]
// The shared imports and seed serve the backend witnesses; without a backend
// only the classification test is left.
#![cfg_attr(not(feature = "sqlite"), allow(dead_code))]
#![cfg_attr(
    not(any(feature = "sqlite", feature = "postgres")),
    allow(unused_imports)
)]

use super::edition_upgrade::{
    delete_earlier_store, EarlierStoreRefusal, StoreFinding, StoreTarget, UpgradeMode,
};
use std::collections::BTreeMap;

/// The seeded planes and their row counts (beyond what the baseline seeds).
fn seeded() -> BTreeMap<&'static str, u64> {
    BTreeMap::from([("hard_case_events", 3), ("cirislens_pseudonyms", 2)])
}

/// I1959 — the pure classification, no database.
#[test]
fn i1959_history_classification() {
    use super::edition_upgrade::{classify_history, Classified, EDITION_ONE_V001};
    let v1 = |sum| (1, "trace_events".to_owned(), sum);
    let sum = EDITION_ONE_V001.1;
    assert_eq!(classify_history(&[], sum), Classified::Empty);
    assert_eq!(
        classify_history(&[(300, "edition2_baseline".into(), 7)], sum),
        Classified::EditionTwo { head: 300 }
    );
    assert_eq!(
        classify_history(&[v1(sum), (216, "x".into(), 1)], sum),
        Classified::EditionOne {
            head: 216,
            migrations: 2
        }
    );
    for (rows, why) in [
        (vec![v1(sum ^ 1)], "a V001 of another checksum"),
        (vec![(1, "other".to_owned(), sum)], "a V001 of another name"),
        (vec![(3, "x".to_owned(), 1)], "no V001"),
        (
            vec![v1(sum), (217, "x".into(), 1)],
            "a version edition 1 never shipped",
        ),
        (
            vec![v1(sum), (300, "x".into(), 1)],
            "edition 1 mixed with edition 2",
        ),
    ] {
        assert!(
            matches!(classify_history(&rows, sum), Classified::Foreign(_)),
            "I1959: {why} is not persist's edition 1"
        );
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use rusqlite::Connection;

    fn sha(path: &str) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(std::fs::read(path).unwrap()))
    }

    /// An edition-1 store at `path`, checkpointed into the main file and
    /// closed (a v61 node's store after a clean shutdown).
    pub(crate) fn edition_one(path: &str) {
        let mut c = Connection::open(path).unwrap();
        c.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        crate::store::migration_runner::run_sqlite(
            &mut c,
            &crate::store::migration_runner::sqlite_migrations(),
            None,
            &crate::host::clock::now,
        )
        .unwrap();
        for t in crate::store::edition_baseline::EDITION_TWO_ADDITIONS {
            c.execute_batch(&format!("DROP TABLE {t};")).unwrap();
        }
        // v62.0.0 (PRE4-V300-f) — edition 1 named the delivery-ack table
        // by its earlier name.
        let (was, now) = crate::store::edition_baseline::DELIVERY_ACK_RENAME;
        c.execute_batch(&format!("ALTER TABLE {now} RENAME TO {was};"))
            .unwrap();
        c.execute_batch("DELETE FROM refinery_schema_history;")
            .unwrap();
        for (v, n, sum) in crate::store::migration_runner::edition_one_history("sqlite") {
            c.execute(
                "INSERT INTO refinery_schema_history VALUES (?1, ?2, '2026-09-01T00:00:00Z', ?3)",
                rusqlite::params![v, n, sum],
            )
            .unwrap();
        }
        c.execute_batch(
            "INSERT INTO hard_case_events (event_id, kind, emitted_at) VALUES \
               ('e1', 'sample', '2026-09-01T00:00:00Z'), ('e2', 'sample', '2026-09-01T00:00:00Z'), \
               ('e3', 'promotion_overdue', '2026-09-01T00:00:00Z'); \
             INSERT INTO cirislens_pseudonyms (original_hash, pseudonym, class) VALUES \
               (x'01', 'p1', 'name'), (x'02', 'p2', 'name');",
        )
        .unwrap();
        drop(c);
    }

    /// Each hold plane, seeded on an edition-1 store.
    pub(crate) const HOLDS: &[(&str, &str)] = &[
        (
            "hard_case:legal_hold",
            "INSERT INTO hard_case_events (event_id, kind, emitted_at) VALUES \
             ('h1', 'legal_hold', '2026-09-01T00:00:00Z')",
        ),
        (
            "attestation:hard_case:legal_hold",
            "PRAGMA foreign_keys = OFF; INSERT INTO attestation_subjects (subject_key_id, \
             dimension, asserted_at, attestation_id, tier, cohort_scope) VALUES ('s', \
             'hard_case:legal_hold:case-9', '2026-09-01T00:00:00Z', 'a1', 'local', 'all')",
        ),
        (
            "community:legal_hold",
            "INSERT INTO federation_communities (community_key_id, community_name, members, \
             founded_at, consensus_protocol, policy_blob, persist_row_hash, admitted_at) VALUES \
             ('c1', 'c', '[]', '2026-09-01T00:00:00Z', 'majority', \
             '{\"affiliations\":true,\"affiliation_config\":{\"legal_hold\":{\"hold_id\":\"h1\"}}}', \
             'h', '2026-09-01T00:00:00Z')",
        ),
        (
            "takedown:counter_noticed",
            "INSERT INTO cirisnode_scheduled_takedown_actions (notice_contribution_id, \
             scheduled_eviction_at, status) VALUES ('n1', '2026-10-01T00:00:00Z', \
             'counter_noticed')",
        ),
    ];

    fn history(path: &str) -> Vec<(i32, String)> {
        let c = Connection::open(path).unwrap();
        let mut st = c
            .prepare("SELECT version, name FROM refinery_schema_history ORDER BY version")
            .unwrap();
        let v = st
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        v
    }

    fn count(path: &str, table: &str) -> i64 {
        Connection::open(path)
            .unwrap()
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
            .unwrap()
    }

    /// **I1953 (sqlite) — a fresh open applies the baseline only.** A new
    /// file opened through `SqliteBackend::open` (the Engine's and the
    /// wheel's door) carries exactly one history row, V300, and its open
    /// found nothing earlier.
    #[tokio::test]
    async fn i1953_a_fresh_open_applies_the_baseline_only_sqlite() {
        use crate::store::Backend as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh.db").display().to_string();
        let b = crate::store::sqlite::SqliteBackend::open(&path)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        assert_eq!(
            b.last_edition_upgrade().map(|r| (r.finding, r.deleted)),
            Some((StoreFinding::Absent, false)),
            "I1953: nothing earlier"
        );
        drop(b);
        assert_eq!(
            history(&path),
            vec![(300, "edition2_baseline".to_owned())],
            "I1953: the baseline alone"
        );
        assert_eq!(count(&path, "store_edition_deletions"), 0);
    }

    /// **I1954 (sqlite) — an edition-1 store is deleted and replaced.** The
    /// open counts every plane (the seeded ones exactly), deletes the file
    /// and its sidecars, builds a fresh edition-2 store, and records the
    /// deletion there (local tier, edition 1's head and history length, the
    /// counts, the rows); none of the earlier rows remain. A second open
    /// finds edition 2 and deletes nothing.
    #[tokio::test]
    async fn i1954_an_edition_one_store_is_deleted_and_replaced_sqlite() {
        use crate::store::Backend as _;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v61.db").display().to_string();
        edition_one(&path);
        // A leftover sidecar of the earlier store goes with it.
        std::fs::write(format!("{path}-journal"), b"earlier").unwrap();
        let migrations = crate::store::migration_runner::edition_one_history("sqlite").len();

        let b = crate::store::sqlite::SqliteBackend::open(&path)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let report = b.last_edition_upgrade().expect("the open looked");
        assert!(report.deleted, "I1954: deleted");
        assert!(report.deleted_at.is_some());
        let StoreFinding::EditionOne(earlier) = &report.finding else {
            panic!("I1954: {:?}", report.finding)
        };
        assert_eq!(earlier.head, 216);
        assert_eq!(earlier.migrations, migrations as u64);
        assert!(earlier.legal_holds.is_empty());
        for (t, n) in seeded() {
            assert_eq!(earlier.plane_counts.get(t), Some(&n), "I1954: {t} counted");
        }
        assert_eq!(
            earlier.plane_counts.get("trace_events_factor_rollup_meta"),
            Some(&1),
            "I1954: the baseline's seeded row counted"
        );
        assert_eq!(
            earlier.rows,
            earlier.plane_counts.values().sum::<u64>(),
            "I1954: rows is the sum"
        );
        assert!(
            !earlier.plane_counts.contains_key("refinery_schema_history"),
            "I1954: the history is not a plane"
        );
        drop(b);

        assert_eq!(history(&path), vec![(300, "edition2_baseline".to_owned())]);
        assert_eq!(
            count(&path, "hard_case_events"),
            0,
            "I1954: nothing carries"
        );
        assert_eq!(count(&path, "cirislens_pseudonyms"), 0);
        assert!(
            !std::path::Path::new(&format!("{path}-journal")).exists(),
            "I1954: the sidecar went too"
        );
        let rec = crate::store::edition_upgrade::sqlite::records(&path);
        assert_eq!(rec.len(), 1, "I1954: one record");
        let (tier, head, migs, counts, rows) = &rec[0];
        assert_eq!(tier, "local");
        assert_eq!(*head, 216);
        assert_eq!(*migs, migrations as i64);
        let counts: BTreeMap<String, u64> = serde_json::from_str(counts).unwrap();
        assert_eq!(&counts, &earlier.plane_counts, "I1954: the counts recorded");
        assert_eq!(*rows, earlier.rows as i64);

        let again = crate::store::sqlite::SqliteBackend::open(&path)
            .await
            .unwrap();
        assert_eq!(
            again.last_edition_upgrade().map(|r| (r.finding, r.deleted)),
            Some((StoreFinding::EditionTwo { head: 300 }, false)),
            "I1954: the second open deletes nothing"
        );
        drop(again);
        assert_eq!(
            crate::store::edition_upgrade::sqlite::records(&path).len(),
            1
        );
    }

    /// **I1954b (sqlite) — the Engine's open upgrades the same way**: the
    /// `sqlite:///` DSN every consumer (the wheel's `Engine(...)` included)
    /// opens through deletes an edition-1 store and records it.
    #[tokio::test]
    async fn i1954b_the_engine_open_deletes_an_edition_one_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("engine.db").display().to_string();
        edition_one(&path);
        let engine = crate::Engine::with_signer_pre_genesis(
            crate::federation::tier_ingest::test_support::local_signer("i1954b"),
            &format!("sqlite:///{path}"),
        )
        .await
        .expect("I1954b: the engine opens");
        let report = engine
            .sqlite_backend()
            .unwrap()
            .last_edition_upgrade()
            .unwrap();
        assert!(report.deleted, "I1954b: deleted through the Engine");
        drop(engine);
        assert_eq!(
            crate::store::edition_upgrade::sqlite::records(&path).len(),
            1
        );
        assert_eq!(count(&path, "cirislens_pseudonyms"), 0);
    }

    /// **I1955 (sqlite) — a live legal hold stops it, deleting nothing.** For
    /// each hold plane: the open refuses with `LegalHold` naming the plane,
    /// and the earlier store's file is byte-identical afterwards.
    #[tokio::test]
    async fn i1955_a_live_legal_hold_stops_the_deletion_sqlite() {
        for (plane, seed) in HOLDS {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("held.db").display().to_string();
            edition_one(&path);
            Connection::open(&path)
                .unwrap()
                .execute_batch(seed)
                .unwrap();
            let before = sha(&path);
            let err = crate::store::sqlite::SqliteBackend::open(&path)
                .await
                .err()
                .unwrap_or_else(|| panic!("I1955 {plane}: the open must refuse"));
            match &err {
                crate::store::Error::EarlierStore(EarlierStoreRefusal::LegalHold { holds }) => {
                    assert!(holds.contains(&format!("{plane}=1")), "I1955: {holds}");
                }
                other => panic!("I1955 {plane}: {other:?}"),
            }
            assert_eq!(err.kind(), "store_earlier_store_legal_hold");
            assert_eq!(sha(&path), before, "I1955 {plane}: not one byte deleted");
            assert_eq!(
                history(&path).len(),
                200 - 3,
                "I1955 {plane}: edition 1 stays"
            );
        }
    }

    /// **I1956 (sqlite) — the dry run deletes nothing.** It reports the
    /// counts and the guard's answer (a hold included, as a finding, not an
    /// error), and the file is byte-identical.
    #[tokio::test]
    async fn i1956_the_dry_run_deletes_nothing_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dry.db").display().to_string();
        edition_one(&path);
        Connection::open(&path)
            .unwrap()
            .execute_batch(HOLDS[3].1)
            .unwrap();
        let before = sha(&path);
        let r = delete_earlier_store(StoreTarget::Sqlite(&path), UpgradeMode::DryRun)
            .await
            .unwrap();
        assert_eq!(r.mode, UpgradeMode::DryRun);
        assert!(!r.deleted && r.deleted_at.is_none());
        let StoreFinding::EditionOne(e) = &r.finding else {
            panic!("I1956: {:?}", r.finding)
        };
        assert_eq!(e.head, 216);
        assert_eq!(e.plane_counts.get("hard_case_events"), Some(&3));
        assert_eq!(
            e.legal_holds,
            BTreeMap::from([("takedown:counter_noticed".to_owned(), 1)]),
            "I1956: the guard's answer, reported"
        );
        assert_eq!(sha(&path), before, "I1956: not one byte changed");
        // The same store without the hold: still nothing deleted.
        Connection::open(&path)
            .unwrap()
            .execute_batch("DELETE FROM cirisnode_scheduled_takedown_actions")
            .unwrap();
        let before = sha(&path);
        let r = delete_earlier_store(StoreTarget::Sqlite(&path), UpgradeMode::DryRun)
            .await
            .unwrap();
        assert!(matches!(&r.finding, StoreFinding::EditionOne(e) if e.legal_holds.is_empty()));
        assert!(!r.deleted);
        assert_eq!(
            sha(&path),
            before,
            "I1956: the dry run of a deletable store"
        );
        // And the entry point's Delete mode does delete it.
        let r = delete_earlier_store(StoreTarget::Sqlite(&path), UpgradeMode::Delete)
            .await
            .unwrap();
        assert!(r.deleted, "I1956: Delete mode deletes");
        assert_eq!(history(&path), vec![(300, "edition2_baseline".to_owned())]);
    }

    /// **I1957 (sqlite) — a database persist did not create is never
    /// touched.** A file of someone else's tables (no persist history), and
    /// one whose history does not begin with persist's V001, refuse with
    /// `Foreign` and stay byte-identical.
    #[tokio::test]
    async fn i1957_a_foreign_database_is_refused_untouched_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("host.db").display().to_string();
        Connection::open(&a)
            .unwrap()
            .execute_batch("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT); INSERT INTO notes (body) VALUES ('mine');")
            .unwrap();
        let b = dir.path().join("other.db").display().to_string();
        edition_one(&b);
        Connection::open(&b)
            .unwrap()
            .execute_batch("UPDATE refinery_schema_history SET checksum = '1' WHERE version = 1")
            .unwrap();
        for path in [a, b] {
            let before = sha(&path);
            let err = crate::store::sqlite::SqliteBackend::open(&path)
                .await
                .err()
                .expect("I1957: refused");
            assert!(
                matches!(
                    &err,
                    crate::store::Error::EarlierStore(EarlierStoreRefusal::Foreign { .. })
                ),
                "I1957: {err:?}"
            );
            assert_eq!(err.kind(), "store_foreign_store");
            assert_eq!(sha(&path), before, "I1957: untouched");
        }
    }

    /// **I1958 (sqlite) — a single-process host refuses an edition-1 store
    /// it cannot delete**, and deletes nothing.
    #[tokio::test]
    async fn i1958_a_single_process_host_refuses_an_edition_one_store() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("opfs.db").display().to_string();
        edition_one(&path);
        let rows = count(&path, "hard_case_events");
        let err = crate::store::sqlite::SqliteBackend::open_on_host(
            &path,
            crate::store::HostStoreProfile::SingleProcess,
        )
        .await
        .err()
        .expect("I1958: refused");
        assert!(
            matches!(
                &err,
                crate::store::Error::EarlierStore(EarlierStoreRefusal::SingleProcessHost)
            ),
            "I1958: {err:?}"
        );
        assert_eq!(count(&path, "hard_case_events"), rows);
        assert_eq!(history(&path).len(), 200 - 3);
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;

    /// An edition-1 store in the database at `dsn`.
    async fn edition_one(dsn: &str) {
        let mut c = crate::store::postgres::dedicated_connect_to(dsn)
            .await
            .unwrap();
        crate::store::migration_runner::run_postgres(
            &mut c,
            &crate::store::migration_runner::postgres_migrations(),
            None,
            &crate::host::clock::now,
        )
        .await
        .unwrap();
        for t in crate::store::edition_baseline::EDITION_TWO_ADDITIONS {
            c.batch_execute(&format!("DROP TABLE cirislens.{t};"))
                .await
                .unwrap();
        }
        // v62.0.0 (PRE4-V300-f) — edition 1 named the delivery-ack table
        // by its earlier name (EDITION_ONE_PG_RELATIONS lists that name).
        let (was, now) = crate::store::edition_baseline::DELIVERY_ACK_RENAME;
        c.batch_execute(&format!("ALTER TABLE cirislens.{now} RENAME TO {was};"))
            .await
            .unwrap();
        c.batch_execute("DELETE FROM ciris_persist_schema_history;")
            .await
            .unwrap();
        for (v, n, sum) in crate::store::migration_runner::edition_one_history("postgres") {
            c.execute(
                "INSERT INTO ciris_persist_schema_history VALUES ($1, $2, '2026-09-01T00:00:00Z', $3)",
                &[&v, &n, &sum],
            )
            .await
            .unwrap();
        }
        c.batch_execute(
            "INSERT INTO cirislens.hard_case_events (event_id, kind, emitted_at) VALUES \
               ('e1', 'sample', now()), ('e2', 'sample', now()), ('e3', 'promotion_overdue', now()); \
             INSERT INTO cirislens_pseudonyms (original_hash, pseudonym, class) VALUES \
               ('\\x01', 'p1', 'name'), ('\\x02', 'p2', 'name');",
        )
        .await
        .unwrap();
    }

    const HOLDS: &[(&str, &str)] = &[
        (
            "hard_case:legal_hold",
            "INSERT INTO cirislens.hard_case_events (event_id, kind, emitted_at) VALUES \
             ('h1', 'legal_hold', now())",
        ),
        (
            "community:legal_hold",
            "INSERT INTO cirislens.federation_communities (community_key_id, community_name, \
             members, founded_at, consensus_protocol, policy_blob, persist_row_hash, admitted_at) \
             VALUES ('c1', 'c', '[]', now(), 'majority', \
             '{\"affiliations\":true,\"affiliation_config\":{\"legal_hold\":{\"hold_id\":\"h1\"}}}', \
             'h', now())",
        ),
        (
            "takedown:counter_noticed",
            "INSERT INTO cirisnode.scheduled_takedown_actions (notice_contribution_id, \
             scheduled_eviction_at, status) VALUES ('n1', now(), 'counter_noticed')",
        ),
    ];

    async fn client(dsn: &str) -> tokio_postgres::Client {
        crate::store::postgres::dedicated_connect_to(dsn)
            .await
            .unwrap()
    }

    async fn one(c: &tokio_postgres::Client, sql: &str) -> i64 {
        c.query_one(sql, &[]).await.unwrap().get(0)
    }

    async fn history(c: &tokio_postgres::Client) -> Vec<(i32, String)> {
        c.query(
            "SELECT version, name FROM ciris_persist_schema_history ORDER BY version",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect()
    }

    /// Everything outside persist's footprint, as rows: what I1957 checks
    /// is untouched.
    async fn host_objects(c: &tokio_postgres::Client) -> Vec<String> {
        c.query(
            "SELECT n.nspname::text || '.' || k.relname::text || ':' || k.relkind::text FROM pg_class k \
             JOIN pg_namespace n ON n.oid = k.relnamespace \
             WHERE n.nspname IN ('host_app', 'public') AND k.relname NOT IN \
             ('cirislens_pseudonyms', 'cirislens_pseudonyms_pkey', \
              'cirislens_pseudonyms_pseudonym_key', 'cirislens_pseudonyms_class', \
              'ciris_persist_schema_history', 'ciris_persist_schema_history_pkey') \
             ORDER BY 1",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect()
    }

    /// **I1953 (postgres) — a fresh open applies the baseline only.**
    #[tokio::test]
    async fn i1953_a_fresh_open_applies_the_baseline_only_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        assert_eq!(
            b.last_edition_upgrade().map(|r| (r.finding, r.deleted)),
            Some((StoreFinding::Absent, false))
        );
        let c = client(&dsn).await;
        assert_eq!(
            history(&c).await,
            vec![(300, "edition2_baseline".to_owned())]
        );
        assert_eq!(
            one(&c, "SELECT count(*) FROM cirislens.store_edition_deletions").await,
            0
        );
    }

    /// **I1954 (postgres) — an edition-1 store is deleted and replaced**,
    /// counted, and recorded; a second open deletes nothing.
    #[tokio::test]
    async fn i1954_an_edition_one_store_is_deleted_and_replaced_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        edition_one(&dsn).await;
        let migrations = crate::store::migration_runner::edition_one_history("postgres").len();
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let report = b.last_edition_upgrade().unwrap();
        assert!(report.deleted, "I1954: deleted");
        let StoreFinding::EditionOne(earlier) = &report.finding else {
            panic!("I1954: {:?}", report.finding)
        };
        assert_eq!((earlier.head, earlier.migrations), (216, migrations as u64));
        assert_eq!(
            earlier.plane_counts.get("cirislens.hard_case_events"),
            Some(&3)
        );
        assert_eq!(earlier.plane_counts.get("cirislens_pseudonyms"), Some(&2));
        assert_eq!(
            earlier
                .plane_counts
                .get("cirislens.trace_events_factor_rollup_meta"),
            Some(&1)
        );
        assert_eq!(earlier.rows, earlier.plane_counts.values().sum::<u64>());
        let c = client(&dsn).await;
        assert_eq!(
            history(&c).await,
            vec![(300, "edition2_baseline".to_owned())]
        );
        assert_eq!(
            one(&c, "SELECT count(*) FROM cirislens.hard_case_events").await,
            0
        );
        assert_eq!(
            one(&c, "SELECT count(*) FROM cirislens_pseudonyms").await,
            0
        );
        let rec = c
            .query(
                "SELECT tier, earlier_head, earlier_migrations, plane_counts, rows_deleted \
                 FROM cirislens.store_edition_deletions",
                &[],
            )
            .await
            .unwrap();
        assert_eq!(rec.len(), 1, "I1954: one record");
        let (tier, head, migs, counts, rows): (String, i32, i32, String, i64) = (
            rec[0].get(0),
            rec[0].get(1),
            rec[0].get(2),
            rec[0].get(3),
            rec[0].get(4),
        );
        assert_eq!(
            (tier.as_str(), head, migs),
            ("local", 216, migrations as i32)
        );
        let counts: BTreeMap<String, u64> = serde_json::from_str(&counts).unwrap();
        assert_eq!(&counts, &earlier.plane_counts, "I1954: the counts recorded");
        assert_eq!(rows, earlier.rows as i64);

        // Another process opening the same database: edition 2, nothing more.
        let r = crate::store::edition_upgrade::delete_earlier_store(
            StoreTarget::Postgres(&dsn),
            UpgradeMode::DryRun,
        )
        .await
        .unwrap();
        assert_eq!(r.finding, StoreFinding::EditionTwo { head: 300 });
    }

    /// **I1955 (postgres) — a live legal hold stops it, deleting nothing.**
    #[tokio::test]
    async fn i1955_a_live_legal_hold_stops_the_deletion_postgres() {
        use crate::store::Backend as _;
        for (plane, seed) in HOLDS {
            let Some(dsn) = crate::test_pg::empty_dsn() else {
                return;
            };
            edition_one(&dsn).await;
            let c = client(&dsn).await;
            c.batch_execute(seed).await.unwrap();
            let (h, rows) = (
                history(&c).await,
                one(&c, "SELECT count(*) FROM cirislens.hard_case_events").await,
            );
            let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .unwrap();
            let err = b.run_migrations().await.expect_err("I1955: refused");
            match &err {
                crate::store::Error::EarlierStore(EarlierStoreRefusal::LegalHold { holds }) => {
                    assert!(holds.contains(&format!("{plane}=1")), "I1955: {holds}");
                }
                other => panic!("I1955 {plane}: {other:?}"),
            }
            assert_eq!(history(&c).await, h, "I1955 {plane}: edition 1 stays");
            assert_eq!(
                one(&c, "SELECT count(*) FROM cirislens.hard_case_events").await,
                rows,
                "I1955 {plane}: nothing deleted"
            );
        }
    }

    /// **I1956 (postgres) — the dry run deletes nothing**, and reports the
    /// counts and the guard's answer.
    #[tokio::test]
    async fn i1956_the_dry_run_deletes_nothing_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        edition_one(&dsn).await;
        let c = client(&dsn).await;
        c.batch_execute(HOLDS[0].1).await.unwrap();
        let h = history(&c).await;
        let r = delete_earlier_store(StoreTarget::Postgres(&dsn), UpgradeMode::DryRun)
            .await
            .unwrap();
        assert!(!r.deleted);
        let StoreFinding::EditionOne(e) = &r.finding else {
            panic!("I1956: {:?}", r.finding)
        };
        assert_eq!(e.plane_counts.get("cirislens.hard_case_events"), Some(&4));
        assert_eq!(
            e.legal_holds,
            BTreeMap::from([("hard_case:legal_hold".to_owned(), 1)])
        );
        assert_eq!(history(&c).await, h, "I1956: nothing deleted");
        assert_eq!(
            one(&c, "SELECT count(*) FROM cirislens.hard_case_events").await,
            4
        );
    }

    /// **I1957 (postgres) — persist never touches a foreign schema.**
    ///
    /// (a) A host's own schema, its table in `public`, and its rows survive
    ///     the deletion of persist's store beside them, untouched.
    /// (b) A host view that depends on a persist table would be dropped by
    ///     the cascade: the deletion rolls back and refuses, and everything
    ///     (persist's store included) is as it was.
    /// (c) A table persist's edition 1 never created, inside a persist
    ///     schema, refuses: the schema is not persist's alone.
    /// (d) Persist's schema names without persist's history refuse: persist
    ///     did not create them.
    #[tokio::test]
    async fn i1957_a_foreign_schema_is_never_touched_postgres() {
        use crate::store::Backend as _;
        let host = "CREATE SCHEMA host_app; \
             CREATE TABLE host_app.ledger (id int PRIMARY KEY, body text); \
             INSERT INTO host_app.ledger VALUES (1, 'mine'), (2, 'also mine'); \
             CREATE TABLE public.host_notes (id int PRIMARY KEY); \
             INSERT INTO public.host_notes VALUES (7);";

        // (a)
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        edition_one(&dsn).await;
        let c = client(&dsn).await;
        c.batch_execute(host).await.unwrap();
        let objects = host_objects(&c).await;
        assert!(objects.len() >= 4, "I1957a: {objects:?}");
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        assert!(b.last_edition_upgrade().unwrap().deleted, "I1957a: deleted");
        assert_eq!(
            host_objects(&c).await,
            objects,
            "I1957a: host objects untouched"
        );
        assert_eq!(one(&c, "SELECT count(*) FROM host_app.ledger").await, 2);
        assert_eq!(one(&c, "SELECT count(*) FROM public.host_notes").await, 1);

        // (b)
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        edition_one(&dsn).await;
        let c = client(&dsn).await;
        c.batch_execute(host).await.unwrap();
        c.batch_execute(
            "CREATE VIEW host_app.my_cases AS SELECT event_id FROM cirislens.hard_case_events",
        )
        .await
        .unwrap();
        let (objects, h) = (host_objects(&c).await, history(&c).await);
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        let err = b.run_migrations().await.expect_err("I1957b: refused");
        assert!(
            matches!(
                &err,
                crate::store::Error::EarlierStore(EarlierStoreRefusal::Foreign { .. })
            ),
            "I1957b: {err:?}"
        );
        assert_eq!(host_objects(&c).await, objects, "I1957b: the view stands");
        assert_eq!(history(&c).await, h, "I1957b: rolled back");
        assert_eq!(one(&c, "SELECT count(*) FROM host_app.my_cases").await, 3);

        // (c)
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        edition_one(&dsn).await;
        let c = client(&dsn).await;
        c.batch_execute("CREATE TABLE cirislens.host_extra (id int); INSERT INTO cirislens.host_extra VALUES (1);")
            .await
            .unwrap();
        let h = history(&c).await;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        let err = b.run_migrations().await.expect_err("I1957c: refused");
        assert!(
            matches!(&err, crate::store::Error::EarlierStore(EarlierStoreRefusal::Foreign { detail }) if detail.contains("host_extra")),
            "I1957c: {err:?}"
        );
        assert_eq!(history(&c).await, h);
        assert_eq!(
            one(&c, "SELECT count(*) FROM cirislens.host_extra").await,
            1
        );

        // (d)
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let c = client(&dsn).await;
        c.batch_execute("CREATE SCHEMA cirislens; CREATE TABLE cirislens.theirs (id int); INSERT INTO cirislens.theirs VALUES (1);")
            .await
            .unwrap();
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        let err = b.run_migrations().await.expect_err("I1957d: refused");
        assert!(
            matches!(
                &err,
                crate::store::Error::EarlierStore(EarlierStoreRefusal::Foreign { .. })
            ),
            "I1957d: {err:?}"
        );
        assert_eq!(one(&c, "SELECT count(*) FROM cirislens.theirs").await, 1);
    }
}
