//! v62.0.0 (RL-fix4; CC 5.4.6 "Who carries what", CC 5.3.4, CC 5.4.3; the
//! Constitution's M3 ruling) — **relay eligibility is carriage by consent**,
//! on sqlite and postgres, through `trust_root::resolve_transit_eligibility`
//! (the verb Edge's TransitGate calls). Each witness reads A's own directory,
//! which holds what the planes delivered to it: R's key record, R's own
//! bind (route + transit key), and the owner bindings.
//!
//! - **I2255** (own-node arm) — R is one of A's owner's own nodes: eligible,
//!   arm `own_node`, on a ROOTLESS node; `valid_until` is R's own signed
//!   bound.
//! - **I2256** (opt-out) — the same, but R's own bind carries
//!   `onion_relay: {opt_out: true}`: refused `opted_out`.
//! - **I2257** (no contact representable, no stranger) — R owned by another
//!   person (a contact of B, never of A's owner): refused
//!   `relay_contact_grant_not_representable`; an unowned R sharing no root:
//!   refused `no_consent_from_owner`; neither is a carrier, and the onion arm
//!   gives nothing without a root.
//! - **I2258** (seat arm) — R a seat of the bundle in force: eligible, arm
//!   `seat`.
//! - **I2259** (rooted, own-node, no shared root) — once A's node is ROOTED,
//!   its own node R that trusts no root is still eligible, arm `own_node`:
//!   the rooted case is not stricter than the text.

use ciris_verify_core::cde::Value;

use super::fixture_occurrence::{occurrence_bind_voices, BindOptions};
use super::fixture_switch as e2;
use super::ingest::{put_statement, INGEST_TIER};
use crate::federation::key_grant_invariants::two_node::own_key;
use crate::federation::trust_root::{resolve_transit_eligibility, TransitArm, TransitRefusal};
use crate::federation::FederationDirectory;

/// A node key `seed` on `d` with its own self-pair bind carrying a route and
/// the transit key `transit` (and `extra`); owned by `owner` when given.
async fn relay(
    d: &dyn FederationDirectory,
    seed: &str,
    owner: Option<&str>,
    transit: u8,
    extra: Vec<(&'static str, Value)>,
) -> String {
    let k = e2::put_key(d, seed, &["node"]).await;
    if let Some(o) = owner {
        own_key(d, o, &k, seed).await;
    }
    let (head, _) = super::occurrence::current_roster_heads(d, &k)
        .await
        .unwrap()
        .expect("the node's key heads its own roster");
    let mut members = vec![
        (
            "transport_destination",
            super::rootless_mesh_invariants::transport(
                transit.wrapping_add(0x80),
                transit.wrapping_add(0x81),
            ),
        ),
        ("transit_xwing_pubkey", Value::Bytes(vec![transit; 1216])),
    ];
    members.extend(extra);
    let opts = BindOptions {
        extra: members,
        head: Some(head),
        ..BindOptions::default()
    };
    for st in occurrence_bind_voices(seed, seed, seed, "server", &opts) {
        put_statement(d, &st, None, INGEST_TIER)
            .await
            .unwrap_or_else(|e| panic!("{seed}'s own bind: {e}"));
    }
    k
}

fn opt_out() -> Value {
    super::door_invariants::fixture::map(vec![("opt_out", Value::Bool(true))])
}

/// The witnesses on one backend, rootless at the start; `node_seed` is the
/// directory's node key (`set_node_key_id(e2::kid(node_seed))`).
pub(crate) async fn body(d: &dyn FederationDirectory, node_seed: &str, tag: &str) {
    let run = uuid::Uuid::new_v4().simple().to_string();
    let owner = format!("rl4-owner-{tag}-{run}");
    let other_owner = format!("rl4-other-owner-{tag}-{run}");
    e2::put_key(d, &owner, &["user"]).await;
    e2::put_key(d, &other_owner, &["user"]).await;
    // A: this node, owned by `owner`.
    let a = e2::put_key(d, node_seed, &["node"]).await;
    own_key(d, &owner, &a, node_seed).await;

    // I2255 — the own-node arm, rootless.
    let mine = relay(
        d,
        &format!("rl4-mine-{tag}-{run}"),
        Some(&owner),
        0x31,
        vec![],
    )
    .await;
    let v = resolve_transit_eligibility(d, &a, &mine).await.unwrap();
    assert!(
        v.eligible && v.arm == Some(TransitArm::OwnNode) && v.refusal.is_none(),
        "[{tag}] I2255: A's owner's own node is a carrier, rootless: {v:?}"
    );

    // I2256 — the opt-out marker on R's own bind.
    let quiet = relay(
        d,
        &format!("rl4-quiet-{tag}-{run}"),
        Some(&owner),
        0x41,
        vec![("onion_relay", opt_out())],
    )
    .await;
    let v = resolve_transit_eligibility(d, &a, &quiet).await.unwrap();
    assert!(
        !v.eligible && v.refusal == Some(TransitRefusal::OptedOut),
        "[{tag}] I2256: an opted-out node carries nobody: {v:?}"
    );

    // I2257 — another person's node (B's contact relay), and a stranger.
    let theirs = relay(
        d,
        &format!("rl4-theirs-{tag}-{run}"),
        Some(&other_owner),
        0x51,
        vec![],
    )
    .await;
    let v = resolve_transit_eligibility(d, &a, &theirs).await.unwrap();
    assert!(
        !v.eligible && v.refusal == Some(TransitRefusal::RelayContactGrantNotRepresentable),
        "[{tag}] I2257: a node of another owner is no carrier until a contact grant exists: {v:?}"
    );
    let stranger = relay(d, &format!("rl4-stranger-{tag}-{run}"), None, 0x61, vec![]).await;
    let v = resolve_transit_eligibility(d, &a, &stranger).await.unwrap();
    assert!(
        !v.eligible && v.refusal == Some(TransitRefusal::NoConsentFromOwner),
        "[{tag}] I2257: a stranger is not a carrier, and no root means no onion arm: {v:?}"
    );

    // I2258 — the seat arm.
    super::fixture_genesis::install_v2(d).await.unwrap();
    let seat = super::fixture_genesis::bundle_v2()
        .serve_node_identity_ref(0)
        .to_owned();
    let v = resolve_transit_eligibility(d, &a, &seat).await.unwrap();
    assert!(
        v.eligible && v.arm == Some(TransitArm::Seat),
        "[{tag}] I2258: a seat is a carrier by its seat: {v:?}"
    );

    // I2259 — A rooted; its own node R trusts no root: still own_node.
    super::fixture_trust_root::rooted_trust_root(
        d,
        &super::fixture_genesis::HOLDER_SEEDS,
        "quorum:2/3",
    )
    .await;
    assert!(
        super::serve::node_is_rooted(
            d,
            &a,
            u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap()
        )
        .await
        .unwrap(),
        "[{tag}] I2259: precondition, A's node is rooted"
    );
    let v = resolve_transit_eligibility(d, &a, &mine).await.unwrap();
    assert!(
        v.eligible && v.arm == Some(TransitArm::OwnNode),
        "[{tag}] I2259: a rooted node uses its own node with no shared root: {v:?}"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2255_to_i2259_relay_eligibility_by_consent_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    let node = "rl4-node-sqlite";
    b.set_node_key_id(e2::kid(node));
    Box::pin(body(&b, node, "sqlite")).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2255_to_i2259_relay_eligibility_by_consent_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    let node = "rl4-node-postgres";
    b.set_node_key_id(e2::kid(node));
    Box::pin(body(&b, node, "postgres")).await;
}
