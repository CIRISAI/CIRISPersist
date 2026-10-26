//! v60.0.0 (CIRISPersist#1002; steward ruling 2026-10-25, "parity even for
//! genesis") — **I1324–I1327: every genesis door runs on both backends, on a
//! scratch its backend provisions, and leaves nothing behind.**
//!
//! - I1324 `verify_ceremony_outputs` admits a minted ceremony and refuses a
//!   tampered one at the quorum stage — after the scratch was provisioned —
//!   on each backend's scratch.
//! - I1325 `CeremonyState::finish` runs the doors on each backend's scratch.
//! - I1326 `AmendState::plan` / `finish` turn a v3 bundle into a v4 on each.
//! - I1327 the import door installs the bundle on a node of each backend,
//!   that node provisioning its own scratch.
//!
//! On postgres every leg ends by counting the scratch databases THIS process
//! created (`ciris_genesis_scratch_{pid}_…`): zero, on success and on the
//! refusal. Its own process (the test anchor is armed through the
//! environment, the #738 rule).

#![cfg(feature = "test-anchor")]

use ciris_persist::federation::genesis::amend::AmendState;
use ciris_persist::federation::genesis::ceremony::CeremonyState;
use ciris_persist::federation::genesis::scratch::GenesisScratch;
use ciris_persist::federation::genesis::*;
use ciris_persist::federation::FederationDirectory;

const SEEDS: [[u8; 32]; 3] = [[0x51; 32], [0x52; 32], [0x53; 32]];
const NODE_SEED: [u8; 32] = [0x5E; 32];

struct Armed;

impl Armed {
    fn with(block: &TestAnchorBlock) -> Self {
        for (k, v) in block.env_pairs() {
            std::env::set_var(k, v);
        }
        for k in ["ENVIRONMENT", "CIRIS_ENV", "CIRIS_ENVIRONMENT"] {
            std::env::remove_var(k);
        }
        Self
    }
}

impl Drop for Armed {
    fn drop(&mut self) {
        clear_test_ceremony_outputs();
        for k in TEST_ANCHOR_ENV_VARS {
            std::env::remove_var(k);
        }
    }
}

fn at(offset_secs: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() + chrono::Duration::seconds(offset_secs)
}

/// A bundle whose holder authorizations no longer verify (one byte of the
/// authorized charter changed): refused at `ceremony_bundle_quorum`, a stage
/// that runs on the provisioned scratch.
fn tampered(c: &TestCeremonyOutputs) -> String {
    let mut b = c.bundle.clone();
    b.produced_at = at(1).to_rfc3339();
    serde_json::to_string(&b).unwrap()
}

/// The four doors against one scratch provider.
async fn every_door(scratch: &dyn GenesisScratch, tag: &str) {
    // I1324
    let c = mint_test_ceremony(&SEEDS, &NODE_SEED, at(-60)).expect("mint");
    let _armed = Armed::with(&c.block);
    let ok = verify_ceremony_outputs(&c.bundle_json().unwrap(), scratch)
        .await
        .unwrap_or_else(|e| panic!("{tag} I1324: the minted bundle verifies: {e}"));
    assert_eq!(ok.quorum_verified, 3, "{tag} I1324");
    let refused = verify_ceremony_outputs(&tampered(&c), scratch)
        .await
        .expect_err("I1324: a tampered bundle is refused");
    assert_ne!(
        refused.reason,
        CeremonyOutputsRefusal::ScratchDirectory,
        "{tag} I1324: the refusal is the bundle's, not the scratch's: {refused}"
    );
    assert_ne!(
        refused.reason,
        CeremonyOutputsRefusal::Malformed,
        "{tag} I1324: refused after the scratch was provisioned: {refused}"
    );

    // I1325
    let (_block, holders, inputs) =
        test_ceremony_inputs(&SEEDS, &NODE_SEED, at(-60), None).expect("inputs");
    let mut state = CeremonyState::plan(inputs).expect("plan");
    sign_every_item(&mut state, &holders).expect("sign");
    let done = state
        .finish(scratch)
        .await
        .unwrap_or_else(|e| panic!("{tag} I1325: finish runs the doors: {e}"));
    assert_eq!(done.verified.quorum_verified, 3, "{tag} I1325");

    // I1326
    let v3 = mint_test_ceremony_versioned(&SEEDS, &NODE_SEED, at(-60), None, Some(3)).unwrap();
    let v3_json = v3.bundle_json().unwrap();
    let row = test_serve_transport_destination(&NODE_SEED, at(-30), 0x71, 0x72).unwrap();
    let mut amend = AmendState::plan(&v3_json, vec![row], scratch)
        .await
        .unwrap_or_else(|e| panic!("{tag} I1326: the pinned v3 verifies: {e}"));
    let bytes = amend.authz_bytes().unwrap();
    for h in &holders[..2] {
        amend
            .add_authorization(test_amend_authorization(h, &bytes))
            .unwrap();
    }
    let amended = amend
        .finish(scratch)
        .await
        .unwrap_or_else(|e| panic!("{tag} I1326: the amend finishes: {e}"));
    assert_eq!(amended.bundle.version, 4, "{tag} I1326");
    assert_eq!(amended.verified.quorum_verified, 2, "{tag} I1326");
}

/// I1327 — the import door on a fresh node, the node's own scratch. The
/// caller mints `c`, arms its anchor, then seeds the node (the holders a node
/// seeds are the armed roster's).
async fn import_on<D: FederationDirectory + GenesisScratch>(
    node: &D,
    c: &TestCeremonyOutputs,
    tag: &str,
) {
    let r = install_genesis_bundle_roster(node, node, &c.bundle)
        .await
        .unwrap_or_else(|e| panic!("{tag} I1327: the import door installs: {e:?}"));
    assert!(!r.records.is_empty(), "{tag} I1327: records reported");
    assert!(
        node.lookup_community(
            ciris_persist::federation::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID
        )
        .await
        .unwrap()
        .is_some(),
        "{tag} I1327: the birth is held on the node"
    );
    let err = install_genesis_bundle_roster(node, node, &{
        let mut b = c.bundle.clone();
        b.produced_at = at(1).to_rfc3339();
        b
    })
    .await
    .expect_err("I1327: a tampered bundle installs nothing");
    assert!(
        matches!(
            err,
            ciris_persist::federation::Error::GenesisBundleInvalid { .. }
        ),
        "{tag} I1327: {err:?}"
    );
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;

    #[serial_test::serial(test_anchor_env)]
    #[tokio::test]
    async fn i1324_to_i1326_every_door_on_the_sqlite_scratch() {
        every_door(
            &ciris_persist::store::test_backend::test_backend(),
            "sqlite",
        )
        .await;
    }

    #[serial_test::serial(test_anchor_env)]
    #[tokio::test]
    async fn i1327_the_import_door_on_a_sqlite_node() {
        use ciris_persist::store::Backend as _;
        let c = mint_test_ceremony(&SEEDS, &NODE_SEED, at(-60)).expect("mint");
        let _armed = Armed::with(&c.block);
        let node = ciris_persist::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        node.run_migrations().await.unwrap();
        node.seed_genesis_accord_holders(&effective_accord_holder_records())
            .await
            .unwrap();
        import_on(&node, &c, "sqlite").await;
    }
}

#[cfg(feature = "postgres")]
mod postgres {
    use super::*;
    use ciris_persist::store::postgres::{PostgresBackend, GENESIS_SCRATCH_DB_PREFIX};
    use ciris_persist::store::Backend as _;

    /// The scratch databases this process created that still exist.
    async fn my_scratches(base: &str) -> i64 {
        let (admin, conn) = tokio_postgres::connect(base, tokio_postgres::NoTls)
            .await
            .expect("connect to the base test database");
        tokio::spawn(conn);
        admin
            .query_one(
                "SELECT count(*) FROM pg_database WHERE datname LIKE $1",
                &[&format!(
                    "{GENESIS_SCRATCH_DB_PREFIX}{}_%",
                    std::process::id()
                )],
            )
            .await
            .unwrap()
            .get(0)
    }

    #[serial_test::serial(test_anchor_env)]
    #[tokio::test]
    async fn i1324_to_i1326_every_door_on_the_postgres_scratch() {
        let Ok(base) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let provider = PostgresBackend::connect(&base).await.unwrap();
        every_door(&provider, "postgres").await;
        assert_eq!(my_scratches(&base).await, 0, "I1324–I1326: no scratch left");
        eprintln!("i1324_to_i1326 postgres: RAN");
    }

    #[serial_test::serial(test_anchor_env)]
    #[tokio::test]
    async fn i1327_the_import_door_on_a_postgres_node() {
        let Ok(base) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let c = mint_test_ceremony(&SEEDS, &NODE_SEED, at(-60)).expect("mint");
        let _armed = Armed::with(&c.block);
        // A node of its own: a database the test creates and drops.
        let name = format!("ciris_t_{}_i1327", std::process::id());
        let (admin, conn) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(conn);
        admin
            .batch_execute(&format!("CREATE DATABASE \"{name}\""))
            .await
            .unwrap();
        let cut = base.rfind('/').expect("dsn has a database");
        let node = PostgresBackend::connect(&format!("{}/{name}", &base[..cut]))
            .await
            .unwrap();
        node.run_migrations().await.unwrap();
        node.seed_genesis_accord_holders(&effective_accord_holder_records())
            .await
            .unwrap();
        import_on(&node, &c, "postgres").await;
        drop(node);
        let _ = admin
            .batch_execute(&format!("DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"))
            .await;
        assert_eq!(my_scratches(&base).await, 0, "I1327: no scratch left");
        eprintln!("i1327 postgres: RAN");
    }

    /// The scratch itself: released, it is gone; dropped unreleased (an early
    /// return, a panic) it is gone too.
    #[serial_test::serial(test_anchor_env)]
    #[tokio::test(flavor = "multi_thread")]
    async fn i1328_the_postgres_scratch_is_dropped_released_or_not() {
        let Ok(base) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let provider = PostgresBackend::connect(&base).await.unwrap();
        let holders = effective_accord_holder_records();
        let s = provider.provision_genesis_scratch(&holders).await.unwrap();
        assert_eq!(my_scratches(&base).await, 1, "I1328: provisioned");
        assert!(
            s.directory()
                .lookup_public_key(&holders[0].record.key_id)
                .await
                .unwrap()
                .is_some(),
            "I1328: the scratch holds the holders"
        );
        s.release().await.unwrap();
        assert_eq!(my_scratches(&base).await, 0, "I1328: released");
        let s = provider.provision_genesis_scratch(&holders).await.unwrap();
        assert_eq!(my_scratches(&base).await, 1);
        drop(s);
        assert_eq!(my_scratches(&base).await, 0, "I1328: dropped unreleased");
        eprintln!("i1328 postgres: RAN");
    }
}
