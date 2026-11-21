//! v62.0.0 (PR-fix1; CC 3.2 T8, CC 5.3.4) — **the peer verdict**
//! ([`peer_rooting`]) on sqlite and postgres, over the test genesis bundle
//! (`fixture_genesis::install_v2`) and W1b's rooted trust root (founded by
//! the bundle's three holders at `quorum:2/3`, chartered, accepted by this
//! node). Every instant is the bundle's or a key window's; `at` is the
//! signer-stamped instant a caller would pass.
//!
//! - **I2216** — before any genesis is held, every peer waits:
//!   `cannot_tell_yet` / `no_genesis_or_root_lineage_held`.
//! - **I2217** — with the bundle in force and the reader's acceptance of the
//!   accord-born root: a holder is `Rooted` via `AccordHolder`, a serve seat
//!   via `ServeSeat` (by composite, kid and Ed25519-half claims), a peer the
//!   root conferred `infra:serve` on via `ConferredSeat` on the delegation
//!   plane.
//! - **I2218** — T4 / T8 (ii): the same verdicts 200 days later, with no
//!   drill or heartbeat row ever held (a drill-red root).
//! - **I2219** — a reader whose owner accepts no root: the same seat is
//!   `no_acceptance_edge` (the conferred peer names its root).
//! - **I2220** — key legs: a wrong claim is `pubkey_mismatch`; text that
//!   names no key is `unknown_key`; a key never put waits
//!   `key_record_not_held`; a revoked key is `key_revoked`.
//! - **I2221** — an ordinary live node is `peer_no_conferral`, owned or not.
//! - **I2222** — a founder of the root resigns, leaving `M` active founders:
//!   the holder is `Stalled` (valid, serves the federation tier, T7).
//! - **I2223** — the reader withdraws its acceptance edge: `edge_or_charter_withdrawn`.
//! - **I2225b** — an acceptance edge naming a head other than the held one
//!   (witnessed mode off: the anchored head) attaches nothing: the holder is
//!   not Rooted for that reader, and the mesh planes still cross (T8 iv).
//! - **I2224** — the capsule op `PeerRooting` answers what the Rust verb
//!   answers; `attach_reading` finds the root attachable (witnessed mode off,
//!   the held head named).

use super::fixture_genesis;
use super::fixture_switch as e2;
use super::fixture_trust_root::put_conferral;
use super::peer_rooting::{
    attach_reading, peer_rooting, CannotTellYet, ClaimedKeyWire, NotRootedReason, PeerRooting,
    Plane, RootedVia,
};
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::trust_root::INFRA_SERVE_SCOPE;
use crate::federation::FederationDirectory;
use crate::ffi::directory_capsule::{dispatch_directory_op, DirectoryOp, DirectoryOpResult};

/// The reader node's E0 seed.
const NODE: &str = "pr-fix1-node";

fn now_ms() -> u64 {
    u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap()
}

async fn verdict(
    d: &dyn FederationDirectory,
    reader: &str,
    peer: &str,
    claim: ClaimedKeyWire,
    at: u64,
) -> PeerRooting {
    let parsed = claim.composite().expect("a fixture claim parses");
    let claim = claim.as_claim(parsed.as_ref()).expect("a claim");
    Box::pin(peer_rooting(d, reader, peer, claim, at))
        .await
        .expect("peer_rooting: a directory read")
}

fn composite(k: &ciris_crypto::composite::CompositeSigningKey) -> ClaimedKeyWire {
    ClaimedKeyWire::Composite(k.public_key().as_bytes().to_vec())
}

/// `(root, plane, via)` of a Rooted verdict, else a panic naming `why`.
fn rooted(v: &PeerRooting, why: &str) -> (String, Plane, RootedVia) {
    match v {
        PeerRooting::Rooted {
            root, plane, via, ..
        } => (root.clone(), *plane, *via),
        other => panic!("{why}: Rooted, not {other:?}"),
    }
}

fn not_rooted(v: &PeerRooting) -> &NotRootedReason {
    match v {
        PeerRooting::NotRooted { reason } => reason,
        other => panic!("NotRooted, not {other:?}"),
    }
}

pub(crate) async fn body(d: &dyn FederationDirectory) {
    let reader = d.node_key_id().expect("the runner set the node key");
    let c = fixture_genesis::bundle_v2();
    let holder = c.holder_identity_ref(0).to_owned();
    let seat = c.serve_node_identity_ref(0).to_owned();

    // ── I2216: nothing held ──
    for (peer, claim) in [
        (holder.clone(), composite(&c.holder_key(0))),
        (seat.clone(), ClaimedKeyWire::Kid(c.seats[0].kid)),
        (
            e2::kid("pr-fix1-anyone"),
            ClaimedKeyWire::Kid(e2::kid_digest("pr-fix1-anyone")),
        ),
    ] {
        let v = verdict(d, &reader, &peer, claim, now_ms()).await;
        assert_eq!(
            v,
            PeerRooting::CannotTellYet {
                missing: CannotTellYet::NoGenesisOrRootLineageHeld
            },
            "I2216: no genesis held: {peer} waits"
        );
        // Rootless is a supported state: the mesh planes still cross (CC 5.3.4).
        assert!(
            v.mesh_planes_may_cross() && !v.federation_tier_may_cross(),
            "I2216: a pre-genesis reader serves {peer} the mesh planes, not the federation tier"
        );
    }

    // ── the bundle in force + the accord-born root this node accepts ──
    let r = e2::rooted_trust_root(d, &fixture_genesis::HOLDER_SEEDS, "quorum:2/3").await;
    let conferred = e2::kid("pr-fix1-conferred");
    put_conferral(d, &r, "pr-fix1-conferred", &[INFRA_SERVE_SCOPE])
        .await
        .expect("I2217: the root confers infra:serve");
    let at = now_ms();

    // ── I2217: a holder, a seat, a conferred seat ──
    let v = verdict(d, &reader, &holder, composite(&c.holder_key(0)), at).await;
    assert_eq!(
        rooted(&v, "I2217 holder"),
        (r.root.clone(), Plane::Ceremony, RootedVia::AccordHolder),
        "I2217: a holder of the bundle in force"
    );
    assert!(v.federation_tier_may_cross(), "I2217");
    let seat_ed25519 = super::composite::ed25519_public(c.serve_node_key(0).public_key())
        .expect("I2217: the seat key's Ed25519 half");
    for claim in [
        composite(&c.serve_node_key(0)),
        ClaimedKeyWire::Kid(c.seats[0].kid),
        ClaimedKeyWire::Ed25519Half(seat_ed25519),
    ] {
        let v = verdict(d, &reader, &seat, claim.clone(), at).await;
        assert_eq!(
            rooted(&v, "I2217 seat"),
            (r.root.clone(), Plane::Ceremony, RootedVia::ServeSeat),
            "I2217: a serve seat, claimed as {claim:?}"
        );
    }
    let v = verdict(
        d,
        &reader,
        &conferred,
        ClaimedKeyWire::Kid(e2::kid_digest("pr-fix1-conferred")),
        at,
    )
    .await;
    assert_eq!(
        rooted(&v, "I2217 conferred"),
        (r.root.clone(), Plane::Delegation, RootedVia::ConferredSeat),
        "I2217: a seat the root conferred"
    );

    // ── I2218: a drill-red root (no drill row, 200 days on) moves nothing ──
    let later = at + 200 * fixture_genesis::DAY_MS;
    for (peer, claim) in [
        (holder.clone(), composite(&c.holder_key(0))),
        (seat.clone(), ClaimedKeyWire::Kid(c.seats[0].kid)),
    ] {
        assert_eq!(
            verdict(d, &reader, &peer, claim.clone(), later).await,
            verdict(d, &reader, &peer, claim, at).await,
            "I2218: liveness is a signal, never a validity leg (CC 3.2 T4, T8 ii)"
        );
    }

    // ── I2219: a reader whose owner accepts no root ──
    let other = e2::put_key(d, "pr-fix1-other-reader", &["node"]).await;
    assert_eq!(
        not_rooted(&verdict(d, &other, &seat, ClaimedKeyWire::Kid(c.seats[0].kid), at).await),
        &NotRootedReason::NoAcceptanceEdge { root: None },
        "I2219: a seat, for a reader that accepts nothing"
    );
    assert_eq!(
        not_rooted(
            &verdict(
                d,
                &other,
                &conferred,
                ClaimedKeyWire::Kid(e2::kid_digest("pr-fix1-conferred")),
                at
            )
            .await
        ),
        &NotRootedReason::NoAcceptanceEdge {
            root: Some(r.root.clone())
        },
        "I2219: a conferred seat names the root the reader does not accept"
    );

    // ── I2220: the key legs ──
    for claim in [
        composite(&c.holder_key(1)),
        ClaimedKeyWire::Kid(c.holders[1].kid),
        ClaimedKeyWire::Ed25519Half(
            super::composite::ed25519_public(c.holder_key(1).public_key()).expect("a half"),
        ),
    ] {
        assert_eq!(
            not_rooted(&verdict(d, &reader, &holder, claim.clone(), at).await),
            &NotRootedReason::PubkeyMismatch,
            "I2220: holder 0 claimed as holder 1's key {claim:?}"
        );
    }
    assert_eq!(
        not_rooted(
            &verdict(
                d,
                &reader,
                "not-an-identity-ref",
                ClaimedKeyWire::Kid([0; 32]),
                at
            )
            .await
        ),
        &NotRootedReason::UnknownKey,
        "I2220: text that names no key"
    );
    let never = e2::kid("pr-fix1-never-put");
    assert_eq!(
        verdict(
            d,
            &reader,
            &never,
            ClaimedKeyWire::Kid(e2::kid_digest("pr-fix1-never-put")),
            at
        )
        .await,
        PeerRooting::CannotTellYet {
            missing: CannotTellYet::KeyRecordNotHeld {
                missing: vec![never.clone()]
            }
        },
        "I2220: a key record not held waits (CC 2.7.3)"
    );
    let revoked = e2::put_key(d, "pr-fix1-revoked", &["node"]).await;
    e2::put_statement(
        d,
        &e2::key_revocation("pr-fix1-revoked", "pr-fix1-revoked", None),
    )
    .await
    .expect("I2220: the key revokes itself");
    assert_eq!(
        not_rooted(
            &verdict(
                d,
                &reader,
                &revoked,
                ClaimedKeyWire::Kid(e2::kid_digest("pr-fix1-revoked")),
                now_ms() + 60_000
            )
            .await
        ),
        &NotRootedReason::Revoked,
        "I2220: a revoked key"
    );

    // ── I2221: ordinary nodes ──
    let plain = e2::put_key(d, "pr-fix1-plain", &["node"]).await;
    assert_eq!(
        not_rooted(
            &verdict(
                d,
                &reader,
                &plain,
                ClaimedKeyWire::Kid(e2::kid_digest("pr-fix1-plain")),
                at
            )
            .await
        ),
        &NotRootedReason::NoConferral { owned: false },
        "I2221: an unowned ordinary node"
    );
    e2::put_key(d, "pr-fix1-owner", &["user"]).await;
    let owned = e2::put_key(d, "pr-fix1-owned", &["node"]).await;
    let binding = ts::owner_binding_attestation(
        &uuid::Uuid::new_v4().to_string(),
        "pr-fix1-owner",
        "pr-fix1-owned",
    );
    e2::land_owner_binding(d, &binding, "pr-fix1-owned")
        .await
        .expect("I2221: the owner binding lands");
    assert_eq!(
        crate::federation::admission::owner_of(d, &owned)
            .await
            .unwrap(),
        Some(e2::kid("pr-fix1-owner")),
        "I2221: the node is owned"
    );
    assert_eq!(
        not_rooted(
            &verdict(
                d,
                &reader,
                &owned,
                ClaimedKeyWire::Kid(e2::kid_digest("pr-fix1-owned")),
                at
            )
            .await
        ),
        &NotRootedReason::NoConferral { owned: true },
        "I2221: an ordinary owned node is not rooted, and not a fault"
    );

    // ── I2224: the capsule op answers the verb; the root is attachable ──
    for (peer, claim) in [
        (holder.clone(), composite(&c.holder_key(0))),
        (
            plain.clone(),
            ClaimedKeyWire::Kid(e2::kid_digest("pr-fix1-plain")),
        ),
    ] {
        let want = verdict(d, &reader, &peer, claim.clone(), at).await;
        match Box::pin(dispatch_directory_op(
            d,
            DirectoryOp::PeerRooting {
                reader_node: reader.clone(),
                peer_identity_ref: peer.clone(),
                claimed_key: claim,
                at_ms: at,
            },
        ))
        .await
        {
            DirectoryOpResult::PeerRooting(got) => {
                assert_eq!(got, want, "I2224: the op answers the verb for {peer}");
            }
            other => panic!("I2224: {other:?}"),
        }
    }
    assert_eq!(
        attach_reading(d, &reader, &r.root, at).await.unwrap(),
        None,
        "I2224: the held head is attachable (witnessed mode off)"
    );

    // ── I2225b (CC 3.2 T8 (iv), T4a, witnessed mode off): an edge naming a
    // head other than the anchored one never yields Rooted on attach ──
    let late = e2::put_key(d, "pr-fix1-late-reader", &["node"]).await;
    let stale = crate::federation::operational::test_support::e2_acceptance_statement(
        "pr-fix1-late-reader",
        &r.root,
        Some(&"00".repeat(32)),
        at,
        None,
    );
    let _ = e2::put_statement(d, &stale).await;
    let v = verdict(d, &late, &holder, composite(&c.holder_key(0)), at).await;
    assert!(
        !v.federation_tier_may_cross() && v.mesh_planes_may_cross(),
        "I2225b: an edge on a head this node does not hold attaches nothing: {v:?}"
    );

    // ── I2222: a founder resigns; M founders remain ──
    let tip = super::genesis::genesis_in_force(d)
        .await
        .unwrap()
        .tips()
        .iter()
        .map(|t| t.asserted_at)
        .max()
        .expect("a tip");
    let resigned_at = i64::try_from(tip + 120_000)
        .ok()
        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_millis)
        .expect("an instant");
    let resignation = super::group::MembershipRecord::CommunityRemoval(
        crate::federation::types::CommunityMembershipRevocation {
            community_key_id: r.root.clone(),
            removed_identity_key_id: r.founders[2].clone(),
            removed_at: resigned_at,
            effective_at: resigned_at,
            reason: None,
            witness_set: Vec::new(),
            persist_row_hash: String::new(),
        },
    );
    let key2 = r.founder_key(2);
    e2::put_voices(
        d,
        &e2::membership_voices(&resignation, Some(&r.birth), &[&key2]),
    )
    .await
    .expect("I2222: a founder resigns alone");
    let at2 = now_ms();
    let v = verdict(d, &reader, &holder, composite(&c.holder_key(0)), at2).await;
    match &v {
        PeerRooting::Stalled { root, via, .. } => {
            assert_eq!(root, &r.root, "I2222");
            assert_eq!(*via, RootedVia::AccordHolder, "I2222");
        }
        other => panic!("I2222: two of three founders at quorum:2/3 is Stalled: {other:?}"),
    }
    assert!(
        v.federation_tier_may_cross(),
        "I2222: Stalled is valid and serves (CC 3.2 T7)"
    );
    assert_eq!(v.as_str(), "community_liveness_stalled", "I2222");

    // ── I2223: the reader withdraws its acceptance ──
    let w = e2::trust_withdraws_statement(&reader, &r.root, &r.acceptance, at2);
    e2::put_statement(d, &w)
        .await
        .expect("I2223: the reader withdraws its acceptance");
    assert_eq!(
        not_rooted(
            &verdict(
                d,
                &reader,
                &holder,
                composite(&c.holder_key(0)),
                at2 + 1_000
            )
            .await
        ),
        &NotRootedReason::EdgeOrCharterWithdrawn {
            root: r.root.clone()
        },
        "I2223: un-trust is one row (CC 3.2 T3)"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2216_i2224_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    let node = e2::put_key(&b, NODE, &["node"]).await;
    b.set_node_key_id(node);
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2216_i2224_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    let node = e2::put_key(&b, NODE, &["node"]).await;
    b.set_node_key_id(node);
    Box::pin(body(&b)).await;
}
