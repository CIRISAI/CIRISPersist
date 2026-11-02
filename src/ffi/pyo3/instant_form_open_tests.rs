//! v61 (CC 2.6.2) — **the Python open settles stored instant forms.**
//!
//! Every host opens persist from Python (`Engine(dsn, …)`), and that
//! constructor builds its engine through the shared constructor, which ran no
//! boot legs: the V211 DDL ran and the open-time pass never did. I-IFP-10
//! seeds a v60-shaped node through the I-IFP-1 seam (this node's own
//! offset-form `scores` row and a peer's), opens it through
//! [`PyEngine::new`](super::PyEngine), and counts from disk.

use super::{BackendDispatch, PyEngine};
use crate::federation::instant_form_invariants::bodies as b;
use crate::federation::tier_ingest::test_support as ts;
use pyo3::prelude::*;

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The fixture identity `ts::local_signer(alias)` uses, as the two seed
/// files the Python constructor reads.
fn seed_files(dir: &std::path::Path, alias: &str) -> (String, String) {
    let seed = ts::seed_for(alias);
    let ed = dir.join("ed.seed");
    let pqc = dir.join("pqc.seed");
    std::fs::write(&ed, seed).unwrap();
    std::fs::write(&pqc, seed).unwrap();
    (ed.display().to_string(), pqc.display().to_string())
}

/// Seed through a Rust engine, drop it, then open through the Python
/// constructor.
fn seed_then_open_from_python(
    dsn: &str,
    alias: &str,
    dir: &std::path::Path,
) -> (b::V60Seeded, PyEngine) {
    let tag = alias.to_owned();
    let seeded = runtime().block_on(async {
        let engine = crate::Engine::with_signer_pre_genesis(ts::local_signer(alias), dsn)
            .await
            .unwrap();
        engine
            .register_self_federation_key(
                crate::federation::types::identity_type::NODE,
                alias,
                None,
                serde_json::json!({}),
                vec![],
            )
            .await
            .unwrap();
        #[cfg(feature = "sqlite")]
        if let Some(sq) = engine.sqlite_backend() {
            let sq = sq.clone();
            return b::seed_v60_own_and_foreign(&engine, sq.as_ref(), &tag).await;
        }
        #[cfg(feature = "postgres")]
        if let Some(pg) = engine.postgres_backend() {
            let pg = pg.clone();
            return b::seed_v60_own_and_foreign(&engine, pg.as_ref(), &tag).await;
        }
        unreachable!("an engine has a backend")
    });
    let (ed, pqc) = seed_files(dir, alias);
    Python::initialize();
    let engine = Python::attach(|py| {
        PyEngine::new(
            py,
            dsn,
            alias,
            None,
            Some(alias.to_owned()),
            Some(ed),
            Some(alias.to_owned()),
            Some(pqc),
            None,
            None,
            false,
            false,
            false,
            None,
            None,
            None,
            None,
        )
    })
    .expect("I-IFP-10: the Python open");
    (seeded, engine)
}

fn assert_settled(engine: &PyEngine, seeded: &b::V60Seeded, who: &str) {
    let rt = runtime();
    match &engine.backend {
        #[cfg(feature = "sqlite")]
        BackendDispatch::Sqlite(sq) => {
            let sq = sq.clone();
            rt.block_on(b::assert_v60_settled_from_disk(sq.as_ref(), seeded, who));
        }
        #[cfg(feature = "postgres")]
        BackendDispatch::Postgres(pg) => {
            let pg = pg.clone();
            rt.block_on(b::assert_v60_settled_from_disk(pg.as_ref(), seeded, who));
        }
    }
}

/// After the open, `settle_instant_forms_json()` reports the pass again and
/// re-states nothing: the own row's re-statement is counted `already_healed`,
/// twice in a row.
fn assert_counts_idempotent(engine: &PyEngine, who: &str) {
    for call in 1..=2 {
        let json = Python::attach(|py| engine.settle_instant_forms_json(py))
            .unwrap_or_else(|e| panic!("{who}: settle_instant_forms_json: {e}"));
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        for key in [
            "scanned",
            "violations",
            "healed",
            "already_healed",
            "heal_refused",
            "own_left",
            "kept_in_force",
            "set_aside",
        ] {
            assert!(v.get(key).is_some(), "{who}: the counts name {key}: {json}");
        }
        assert_eq!(
            (
                &v["violations"],
                &v["healed"],
                &v["already_healed"],
                &v["set_aside"],
                &v["heal_refused"]
            ),
            (
                &serde_json::json!(1),
                &serde_json::json!(0),
                &serde_json::json!(1),
                &serde_json::json!(0),
                &serde_json::json!(0)
            ),
            "{who}: call {call} re-states nothing: {json}"
        );
    }
}

/// I-IFP-10 (sqlite) — the Python open re-states this node's offset-form
/// row and removes the peer's, recording it once.
#[cfg(feature = "sqlite")]
#[test]
fn i_ifp_10_the_python_open_settles_instant_forms_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let dsn = format!("sqlite:///{}", dir.path().join("node.db").display());
    let alias = format!("ifpy{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let (seeded, engine) = seed_then_open_from_python(&dsn, &alias, dir.path());
    assert_settled(&engine, &seeded, "I-IFP-10 sqlite");
    assert_counts_idempotent(&engine, "I-IFP-10 sqlite");
}

/// I-IFP-10 (postgres) — the same, on Postgres.
#[cfg(feature = "postgres")]
#[test]
fn i_ifp_10_the_python_open_settles_instant_forms_postgres() {
    let Some(dsn) = crate::test_pg::isolated_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let alias = format!("ifpy{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
    let (seeded, engine) = seed_then_open_from_python(&dsn, &alias, dir.path());
    assert_settled(&engine, &seeded, "I-IFP-10 postgres");
    assert_counts_idempotent(&engine, "I-IFP-10 postgres");
}
