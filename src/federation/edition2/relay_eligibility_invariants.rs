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
//! - **I2257** (no grant, no stranger) — R owned by another person with no
//!   grant from A's owner: refused `no_grant_from_owner`; an unowned R
//!   sharing no root: refused `no_grant_from_owner`; neither is a carrier,
//!   and the onion arm gives nothing without a root.
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
        !v.eligible && v.refusal == Some(TransitRefusal::NoGrantFromOwner),
        "[{tag}] I2257: a node of another owner with no grant from A's owner: {v:?}"
    );
    let stranger = relay(d, &format!("rl4-stranger-{tag}-{run}"), None, 0x61, vec![]).await;
    let v = resolve_transit_eligibility(d, &a, &stranger).await.unwrap();
    assert!(
        !v.eligible && v.refusal == Some(TransitRefusal::NoGrantFromOwner),
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

/// A live `consent:replication:v1` grant by `author` (a seed) naming `peer`
/// (an identity-ref), any scope, at `at_s` (POSIX s, inside the author's
/// key window from 0). Its stored row.
async fn grant(
    d: &dyn FederationDirectory,
    author: &str,
    peer: &str,
    at_s: i64,
) -> crate::federation::Attestation {
    use crate::federation::grant_scope_invariants::bodies::row;
    use crate::federation::types::attestation_type;
    let at = chrono::DateTime::<chrono::Utc>::from_timestamp(at_s, 0).expect("an instant");
    let r = row(
        &uuid::Uuid::new_v4().to_string(),
        author,
        author,
        author,
        attestation_type::SCORES,
        serde_json::json!({
            "dimension": crate::federation::consent_peer_set::DIMENSION,
            "payload": {"grants": "replication", "attestation_prefixes": ["rl5:"]},
        }),
        vec![peer.to_owned()],
        at,
    );
    e2::put_signed(d, &r)
        .await
        .unwrap_or_else(|e| panic!("{author}'s grant naming {peer}: {e}"));
    d.get_attestation(&r.attestation_id)
        .await
        .unwrap()
        .expect("the grant is held")
}

/// `author` withdraws its grant `g`.
async fn withdraw(d: &dyn FederationDirectory, author: &str, g: &crate::federation::Attestation) {
    let w = e2::composer_of(
        crate::federation::types::attestation_type::WITHDRAWS,
        g,
        author,
    );
    e2::put_signed(d, &w)
        .await
        .unwrap_or_else(|e| panic!("{author} withdraws its grant: {e}"));
}

/// **I2260–I2266** — the contact arm (RL-fix5; CC 5.4.6, the
/// Constitution's ruling: `consent:replication:v1` IS the contact grant),
/// on A's directory, with the two grants arriving in either order
/// (`r_first`):
///
/// - I2260 one grant alone is not a contact (`no_grant_from_owner` /
///   `no_reciprocal_grant`);
/// - I2261 mutual grants plus R's relay offer: eligible, arm `contact`,
///   each grant naming the OTHER side's OWNER (the node bound to it);
/// - I2262 mutual grants but R opted out: `opted_out`;
/// - I2263 a rooted A with no root shared with R still gets `contact`;
/// - I2264 withdrawing either grant ends it, by the failed conjunct's name.
pub(crate) async fn contact_body(
    d: &dyn FederationDirectory,
    node_seed: &str,
    tag: &str,
    r_first: bool,
) {
    let run = uuid::Uuid::new_v4().simple().to_string();
    let owner_a = format!("rl5-owner-a-{tag}-{run}");
    let owner_r = format!("rl5-owner-r-{tag}-{run}");
    e2::put_key(d, &owner_a, &["user"]).await;
    e2::put_key(d, &owner_r, &["user"]).await;
    let a = e2::put_key(d, node_seed, &["node"]).await;
    own_key(d, &owner_a, &a, node_seed).await;
    let r = relay(
        d,
        &format!("rl5-relay-{tag}-{run}"),
        Some(&owner_r),
        0x91,
        vec![],
    )
    .await;
    let quiet = relay(
        d,
        &format!("rl5-quiet-{tag}-{run}"),
        Some(&owner_r),
        0xA1,
        vec![("onion_relay", opt_out())],
    )
    .await;
    let (ka, kr) = (e2::kid(&owner_a), e2::kid(&owner_r));
    // I2260 — one side alone.
    let (g_a, g_r) = if r_first {
        let g_r = grant(d, &owner_r, &ka, 1_790_000_000).await;
        let v = resolve_transit_eligibility(d, &a, &r).await.unwrap();
        assert!(
            !v.eligible && v.refusal == Some(TransitRefusal::NoGrantFromOwner),
            "[{tag}] I2260: R's grant alone is not A's yes: {v:?}"
        );
        (grant(d, &owner_a, &kr, 1_790_000_100).await, g_r)
    } else {
        let g_a = grant(d, &owner_a, &kr, 1_790_000_000).await;
        let v = resolve_transit_eligibility(d, &a, &r).await.unwrap();
        assert!(
            !v.eligible && v.refusal == Some(TransitRefusal::NoReciprocalGrant),
            "[{tag}] I2260: A's grant alone is not a contact: {v:?}"
        );
        (g_a, grant(d, &owner_r, &ka, 1_790_000_100).await)
    };
    // I2261 — mutual, each naming the other side's owner.
    let v = resolve_transit_eligibility(d, &a, &r).await.unwrap();
    assert!(
        v.eligible && v.arm == Some(TransitArm::Contact) && v.refusal.is_none(),
        "[{tag}] I2261: mutual grants and R's offer make R a contact carrier: {v:?}"
    );
    // I2262 — mutual, but R opted out.
    let v = resolve_transit_eligibility(d, &a, &quiet).await.unwrap();
    assert!(
        !v.eligible && v.refusal == Some(TransitRefusal::OptedOut),
        "[{tag}] I2262: a contact that opted out carries nobody: {v:?}"
    );
    // I2263 — A rooted; R shares no root: still the contact arm.
    super::fixture_trust_root::rooted_trust_root(
        d,
        &super::fixture_genesis::HOLDER_SEEDS,
        "quorum:2/3",
    )
    .await;
    let v = resolve_transit_eligibility(d, &a, &r).await.unwrap();
    assert!(
        v.eligible && v.arm == Some(TransitArm::Contact),
        "[{tag}] I2263: a rooted node keeps the contact arm with no shared root: {v:?}"
    );
    // I2264 — a withdrawal ends it going forward.
    if r_first {
        withdraw(d, &owner_a, &g_a).await;
        let v = resolve_transit_eligibility(d, &a, &r).await.unwrap();
        assert!(
            !v.eligible && v.refusal == Some(TransitRefusal::NoGrantFromOwner),
            "[{tag}] I2264: A's owner withdrew its grant: {v:?}"
        );
    } else {
        withdraw(d, &owner_r, &g_r).await;
        let v = resolve_transit_eligibility(d, &a, &r).await.unwrap();
        assert!(
            !v.eligible && v.refusal == Some(TransitRefusal::NoReciprocalGrant),
            "[{tag}] I2264: R's owner withdrew its grant: {v:?}"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2260_to_i2264_contact_arm_sqlite() {
    use crate::store::Backend as _;
    for r_first in [false, true] {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let node = "rl5-node-sqlite";
        b.set_node_key_id(e2::kid(node));
        Box::pin(contact_body(&b, node, "sqlite", r_first)).await;
    }
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2260_to_i2264_contact_arm_postgres() {
    use crate::store::Backend as _;
    for r_first in [false, true] {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        let node = "rl5-node-postgres";
        b.set_node_key_id(e2::kid(node));
        Box::pin(contact_body(&b, node, "postgres", r_first)).await;
    }
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
