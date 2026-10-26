//! v59.0.0 (CIRISPersist#1106; CC 5.3.4 rc9 `0edac07`,
//! `CLM-bundle-seeds-transit-pairs`) — **I1157–I1159: the genesis bundle seeds
//! the serve nodes' transit pairs (v4), they rotate by holder quorum, and an
//! AMEND turns a v3 bundle into a v4 at the charter's quorum.** Its own
//! process: every test arms the test-anchor override through the environment
//! (the #738 rule).

#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use ciris_persist::federation::genesis::amend::{
    AmendState, AMEND_CARRIED_BYTES_CHANGED, AMEND_QUORUM_NOT_MET,
};
use ciris_persist::federation::genesis::*;
use ciris_persist::federation::self_at_login::transit_kex_pair_for;
use ciris_persist::federation::transport_rebind::{
    REBIND_WITHOUT_HOLDER_QUORUM, SERVE_TRANSIT_PAIR_ROTATION_BEFORE_REBIND,
};
use ciris_persist::federation::{Error, FederationDirectory, SignedAttestation};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;

/// The genesis scratch the doors replay on: an in-memory SQLite clone
/// (CIRISPersist#1002; the postgres scratch is witnessed in
/// `genesis_scratch_parity.rs`).
fn scratch() -> ciris_persist::store::sqlite::SqliteBackend {
    ciris_persist::store::test_backend::test_backend()
}

const SEEDS: [[u8; 32]; 3] = [[0x31; 32], [0x32; 32], [0x33; 32]];
const NODE_SEED: [u8; 32] = [0x4E; 32];

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

async fn sqlite() -> SqliteBackend {
    let b = SqliteBackend::open_in_memory().await.unwrap();
    b.run_migrations().await.unwrap();
    b.seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed holders");
    b
}

/// A postgres backend on a database of its own, with its drop guard; `None`
/// without a test database.
#[cfg(feature = "postgres")]
async fn postgres() -> Option<(ciris_persist::store::postgres::PostgresBackend, PgDrop)> {
    let base = std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()?;
    let cut = base.rfind('/').expect("dsn has a database");
    let name = format!(
        "ciris_t_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let (admin, conn) = tokio_postgres::connect(&base, tokio_postgres::NoTls)
        .await
        .expect("connect to the base test database");
    tokio::spawn(conn);
    admin
        .batch_execute(&format!("CREATE DATABASE \"{name}\""))
        .await
        .expect("create this test's database");
    let b = ciris_persist::store::postgres::PostgresBackend::connect(&format!(
        "{}/{name}",
        &base[..cut]
    ))
    .await
    .unwrap();
    b.run_migrations().await.unwrap();
    b.seed_genesis_accord_holders(&effective_accord_holder_records())
        .await
        .expect("seed holders");
    Some((b, PgDrop { base, name }))
}

#[cfg(feature = "postgres")]
struct PgDrop {
    base: String,
    name: String,
}

#[cfg(feature = "postgres")]
impl PgDrop {
    async fn drop_db(self) {
        if let Ok((admin, conn)) = tokio_postgres::connect(&self.base, tokio_postgres::NoTls).await
        {
            tokio::spawn(conn);
            let _ = admin
                .batch_execute(&format!(
                    "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
                    self.name
                ))
                .await;
        }
    }
}

/// Run `$body(d, tag, $args...)` against a fresh sqlite and (with a test
/// database) postgres node.
macro_rules! on_each_backend {
    ($body:ident $(, $arg:expr)*) => {{
        $body(&sqlite().await, "sqlite" $(, $arg)*).await;
        #[cfg(feature = "postgres")]
        if let Some((b, guard)) = postgres().await {
            $body(&b, "postgres" $(, $arg)*).await;
            guard.drop_db().await;
            eprintln!("postgres: RAN");
        }
    }};
}

/// Boot `d` from `bundle` (installed as the ceremony's): the open's seed.
async fn boot(d: &dyn FederationDirectory, bundle: &GenesisBundle, tag: &str) {
    install_test_ceremony_outputs(bundle.clone());
    seed_family_and_canonical(d)
        .await
        .unwrap_or_else(|e| panic!("{tag}: the boot seed: {e:?}"));
    assert!(
        matches!(genesis_posture(d).await, GenesisPosture::Entrenched),
        "{tag}: entrenched"
    );
}

fn x_of(pair: &ciris_persist::federation::self_at_login::TransitKexPair) -> u8 {
    pair.x25519[0]
}

/// **I1157** — a fresh node opens from a v4 bundle and resolves a Rooted
/// transit pair for every serve node, offline.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i1157_a_fresh_node_resolves_the_serve_pairs_offline() {
    let c = mint_test_ceremony(&SEEDS, &NODE_SEED, at(-5)).expect("mint");
    assert_eq!(c.bundle.version, 4);
    assert_eq!(c.bundle.serve_transport_destinations.len(), 1);
    let _armed = Armed::with(&c.block);
    verify_ceremony_outputs(&c.bundle_json().unwrap(), &scratch())
        .await
        .expect("I1157: the v4 outputs verify");
    on_each_backend!(resolves_offline, &c.bundle);
}

async fn resolves_offline(d: &dyn FederationDirectory, tag: &str, bundle: &GenesisBundle) {
    boot(d, bundle, tag).await;
    let pair = transit_kex_pair_for(d, TEST_CEREMONY_NODE_KEY_ID)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{tag} I1157: a Rooted pair for the serve node"));
    assert_eq!(x_of(&pair), 0x71, "{tag} I1157: the bundle's pair");
}

/// **I1157** (refusals) — a row signed by a key that is not a serve node, and
/// a row with no transit pair, fail the WHOLE bundle closed; a v3 bundle
/// verifies and seeds no pair; the v4 digest binds the member.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i1157_the_bundle_rows_are_checked() {
    let c = mint_test_ceremony(&SEEDS, &NODE_SEED, at(-5)).expect("mint");
    let _armed = Armed::with(&c.block);
    let refused = |b: &GenesisBundle, what: &str| match check_serve_transport_destinations(b) {
        Err(Error::GenesisBundleInvalid { detail })
            if detail.starts_with(SERVE_TRANSPORT_DESTINATION_INVALID) => {}
        other => panic!("I1157: {what}: {other:?}"),
    };
    // Signed by a non-serve key.
    let mut by_holder = c.bundle.clone();
    by_holder.serve_transport_destinations[0].attesting_key_id =
        c.bundle.holders[0].record.key_id.clone();
    refused(&by_holder, "a row by a non-serve key");
    assert!(
        verify_ceremony_outputs(&serde_json::to_string(&by_holder).unwrap(), &scratch())
            .await
            .is_err()
    );
    // No transit pair.
    let mut no_pair = c.bundle.clone();
    no_pair.serve_transport_destinations[0]
        .signed_envelope
        .as_object_mut()
        .unwrap()
        .remove("transit_kex_pubkeys");
    refused(&no_pair, "a row with no pair");
    // The v4 digest binds the member: a row swapped after authorization.
    let mut swapped = c.bundle.clone();
    swapped.serve_transport_destinations[0] =
        test_serve_transport_destination(&NODE_SEED, at(-4), 0x75, 0x76).unwrap();
    check_serve_transport_destinations(&swapped).expect("the swapped row is well formed");
    assert_ne!(
        ciris_persist::federation::genesis::bundle::authorization_digest(&swapped).unwrap(),
        ciris_persist::federation::genesis::bundle::authorization_digest(&c.bundle).unwrap(),
        "I1157: the v4 digest binds the transport rows"
    );
    assert!(
        verify_ceremony_outputs(&serde_json::to_string(&swapped).unwrap(), &scratch())
            .await
            .is_err(),
        "I1157: a row swapped after authorization fails the quorum"
    );
    // A v3 bundle verifies and seeds no pair.
    let v3 = mint_test_ceremony_versioned(&SEEDS, &NODE_SEED, at(-5), None, Some(3)).unwrap();
    assert_eq!(v3.bundle.version, 3);
    assert!(v3.bundle.serve_transport_destinations.is_empty());
    let v3_json = v3.bundle_json().unwrap();
    assert!(
        !v3_json.contains("serve_transport_destinations"),
        "I1157: a v3 bundle's wire is unchanged"
    );
    verify_ceremony_outputs(&v3_json, &scratch())
        .await
        .expect("I1157: a v3 bundle verifies");
    let d = sqlite().await;
    boot(&d, &v3.bundle, "sqlite v3").await;
    assert!(
        transit_kex_pair_for(&d, TEST_CEREMONY_NODE_KEY_ID)
            .await
            .unwrap()
            .is_none(),
        "I1157: a v3 bundle seeds no pair"
    );
}

/// **I1157** (v3 digest unchanged) — the v53.1.1 final genesis (v3), whose
/// authorizations the production holders signed over the pre-v59 preimage,
/// still verifies: the v3 preimage is byte-identical. The v3 bytes are kept as
/// a fixture since v59.1.0 baked the v4 amend.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i1157_the_v3_preimage_is_unchanged() {
    let v3 = parse_genesis_bundle(include_str!("fixtures/genesis/canonical_seed.v3.json"))
        .expect("the v3 fixture parses");
    assert_eq!(v3.version, 3);
    let d = sqlite().await;
    verify_bundle_quorum(&d, &v3)
        .await
        .expect("I1157: the v3 final genesis's authorizations still verify");
}

/// **I1158** — a seated serve node's bundle-pinned pair rotates by holder
/// quorum: the node alone is refused; one holder's re-bind is refused; a
/// strict-majority re-bind supersedes and resolves.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i1158_a_serve_pair_rotates_by_holder_quorum() {
    let c = mint_test_ceremony(&SEEDS, &NODE_SEED, at(-60)).expect("mint");
    let _armed = Armed::with(&c.block);
    let holders = test_ceremony_holders(&SEEDS).unwrap();
    on_each_backend!(rotates_by_quorum, &c.bundle, &holders);
}

async fn rotates_by_quorum(
    d: &dyn FederationDirectory,
    tag: &str,
    bundle: &GenesisBundle,
    holders: &[ciris_persist::federation::accord_test_support::Identity],
) {
    boot(d, bundle, tag).await;
    let rotated =
        test_serve_transport_destination_at_epoch(&NODE_SEED, at(-1), 0x73, 0x74, 2).unwrap();
    match d.put_signed_transport_destination(&rotated).await {
        Err(Error::InvalidArgument(m))
            if m.starts_with(SERVE_TRANSIT_PAIR_ROTATION_BEFORE_REBIND) => {}
        other => panic!("{tag} I1158: the node alone rotated: {other:?}"),
    }
    assert_eq!(
        x_of(
            &transit_kex_pair_for(d, TEST_CEREMONY_NODE_KEY_ID)
                .await
                .unwrap()
                .unwrap()
        ),
        0x71,
        "{tag} I1158: the pinned pair stands"
    );
    let one = test_rebind_row(&[&holders[0]], &rotated, at(0)).unwrap();
    match d
        .put_attestation(SignedAttestation { attestation: one })
        .await
    {
        Err(Error::InvalidArgument(m)) if m.starts_with(REBIND_WITHOUT_HOLDER_QUORUM) => {}
        other => panic!("{tag} I1158: one holder re-bound: {other:?}"),
    }
    let two = test_rebind_row(&[&holders[0], &holders[2]], &rotated, at(0)).unwrap();
    d.put_attestation(SignedAttestation { attestation: two })
        .await
        .unwrap_or_else(|e| panic!("{tag} I1158: a 2-of-3 re-bind: {e}"));
    assert_eq!(
        x_of(
            &transit_kex_pair_for(d, TEST_CEREMONY_NODE_KEY_ID)
                .await
                .unwrap()
                .unwrap()
        ),
        0x73,
        "{tag} I1158: the quorum re-bind supersedes and resolves"
    );
}

/// **I1159 — the AMEND stays 2-of-3.** A v3 bundle amended with the serve
/// node's transport row and authorized by EACH pair of holders (A+B, B+C,
/// A+C) finishes through `verify_ceremony_outputs`, and a fresh node booted
/// from it through the open's seed (`seed_family_and_canonical`) is
/// entrenched and resolves the Rooted pair; one holder (even twice) is
/// refused; an amend that alters a carried byte is refused.
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i1159_amend_is_two_of_three_for_every_holder_pair() {
    let v3 = mint_test_ceremony_versioned(&SEEDS, &NODE_SEED, at(-60), None, Some(3)).unwrap();
    let _armed = Armed::with(&v3.block);
    let v3_json = v3.bundle_json().unwrap();
    let holders = test_ceremony_holders(&SEEDS).unwrap();
    let row = test_serve_transport_destination(&NODE_SEED, at(-30), 0x71, 0x72).unwrap();
    for pair in [[0usize, 1], [1, 2], [0, 2]] {
        let mut amend = AmendState::plan(&v3_json, vec![row.clone()], &scratch())
            .await
            .expect("the pinned v3 verifies");
        let bytes = amend.authz_bytes().unwrap();
        for i in pair {
            amend
                .add_authorization(test_amend_authorization(&holders[i], &bytes))
                .unwrap();
        }
        let done = amend
            .finish(&scratch())
            .await
            .unwrap_or_else(|e| panic!("I1159 {pair:?}: the amend finishes: {e}"));
        assert_eq!(done.bundle.version, 4);
        assert_eq!(done.verified.quorum_verified, 2, "I1159 {pair:?}");
        let (tag, d) = ("sqlite", sqlite().await);
        boot(&d, &done.bundle, tag).await;
        assert_eq!(
            x_of(
                &transit_kex_pair_for(&d, TEST_CEREMONY_NODE_KEY_ID)
                    .await
                    .unwrap()
                    .unwrap_or_else(|| panic!("{tag} I1159 {pair:?}: a Rooted pair"))
            ),
            0x71
        );
        clear_test_ceremony_outputs();
    }
    // One holder, even twice: refused.
    let mut one = AmendState::plan(&v3_json, vec![row.clone()], &scratch())
        .await
        .unwrap();
    let bytes = one.authz_bytes().unwrap();
    for _ in 0..2 {
        one.add_authorization(test_amend_authorization(&holders[0], &bytes))
            .unwrap();
    }
    match one.assemble() {
        Err(e) if e.token == AMEND_QUORUM_NOT_MET => {}
        other => panic!("I1159: one holder amended: {other:?}"),
    }
    // A carried byte altered: refused.
    let mut altered = AmendState::plan(&v3_json, vec![row], &scratch())
        .await
        .unwrap();
    altered.base.produced_at = at(0).to_rfc3339();
    let bytes = altered.authz_bytes().unwrap();
    for i in [0, 1] {
        altered
            .add_authorization(test_amend_authorization(&holders[i], &bytes))
            .unwrap();
    }
    match altered.assemble() {
        Err(e) if e.token == AMEND_CARRIED_BYTES_CHANGED => {}
        other => panic!("I1159: an altered carried byte: {other:?}"),
    }
}
