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
//!   root conferred `infra:serve` on via `ConferredSeat` on the ceremony
//!   plane (R2-planes: the root's grant is counted over the holders).
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
        (r.lineage.clone(), Plane::Ceremony, RootedVia::AccordHolder),
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
            (r.lineage.clone(), Plane::Ceremony, RootedVia::ServeSeat),
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
        (r.lineage.clone(), Plane::Ceremony, RootedVia::ConferredSeat),
        "I2217: a seat the root conferred, by its counted grant: the CEREMONY plane (R2-planes)"
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
            root: Some(r.lineage.clone())
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
        attach_reading(d, &reader, &r.lineage, at).await.unwrap(),
        None,
        "I2224: the held head is attachable (witnessed mode off)"
    );

    // ── I2225b (CC 3.2 T8 (iv), T4a, witnessed mode off): an edge naming a
    // head other than the anchored one never yields Rooted on attach ──
    let late = e2::put_key(d, "pr-fix1-late-reader", &["node"]).await;
    let stale = crate::federation::operational::test_support::e2_acceptance_statement(
        "pr-fix1-late-reader",
        &r.lineage,
        &"00".repeat(32),
        at,
        None,
    );
    let _ = e2::put_statement(d, &stale).await;
    let v = verdict(d, &late, &holder, composite(&c.holder_key(0)), at).await;
    assert!(
        !v.federation_tier_may_cross() && v.mesh_planes_may_cross(),
        "I2225b: an edge on a head this node does not hold attaches nothing: {v:?}"
    );

    // LEAD-root1 (CC 3.2 T5) — I2222 ("a founder resigns from the root
    // community; M founders remain: the root STALLS") is DELETED with the
    // root community: the root is the bundle's lineage, and a holder leaves
    // it by a later bundle counted over its predecessor's holders (T6), which
    // the genesis witnesses cover (`genesis_invariants`, the
    // `later_removed_holder_counts` vector).
    // ── I2223: the reader withdraws its acceptance ──
    let at2 = now_ms();
    let w = e2::trust_withdraws_statement(&reader, &r.lineage, &r.acceptance, at2);
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
            root: r.lineage.clone()
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

// ─────────────────────────────────────────────────────────────────────────
//  KB-fix2 — the BUNDLE root (CC 3.2 at rc22 `87abd2d`)
// ─────────────────────────────────────────────────────────────────────────

/// **I2405–I2409** — the peer verdict when the root a reader accepts is the
/// bundle's lineage, named by its `family_key_id` (no room, no W1b root):
///
/// - **I2405** a ROOTLESS reader (no bundle held): a holder waits
///   `no_genesis_or_root_lineage_held`, and the verdict names the plane that
///   waits: the mesh planes cross, the federation tier does not (CC 5.3.4).
/// - **I2406** the bundle in force, the reader accepting nothing: the holder
///   is `no_acceptance_edge` (no root named: the reader accepts none).
/// - **I2407** the reader's own edge to the bundle root (by `family_key_id`,
///   naming the bundle in force): a holder is `Rooted` via `AccordHolder` and
///   a serve seat via `ServeSeat`, both on the ceremony plane, and the root a
///   host reads is `"humanity-accord"`.
/// - **I2408** a later bundle of the lineage: the same verdict, no
///   re-acceptance.
/// - **I2409** a delegation seat under the bundle root's counted grant
///   ([`delegation_seat_body`]).
pub(crate) async fn bundle_root_body(d: &dyn FederationDirectory) {
    let seed = "kb2-reader-node";
    let reader = e2::kid(seed);
    let c = fixture_genesis::bundle_v2();
    let holder = c.holder_identity_ref(0).to_owned();
    let seat = c.serve_node_identity_ref(0).to_owned();

    // I2405 — rootless.
    let v = verdict(d, &reader, &holder, composite(&c.holder_key(0)), now_ms()).await;
    assert_eq!(
        v,
        PeerRooting::CannotTellYet {
            missing: CannotTellYet::NoGenesisOrRootLineageHeld
        },
        "I2405: a rootless reader cannot tell yet"
    );
    assert!(
        v.mesh_planes_may_cross() && !v.federation_tier_may_cross(),
        "I2405: the plane that waits is the federation tier; the mesh planes cross"
    );

    fixture_genesis::install_v2(d)
        .await
        .expect("the ceremony installs");
    let _ = e2::put_key(d, seed, &["node"]).await;
    let root = fixture_genesis::FAMILY_KEY_ID.to_owned();

    // I2406 — no acceptance.
    let v = verdict(d, &reader, &holder, composite(&c.holder_key(0)), now_ms()).await;
    assert_eq!(
        not_rooted(&v),
        &NotRootedReason::NoAcceptanceEdge { root: None },
        "I2406: the reader accepts no root (a ceremony seat reaches only accepted roots)"
    );

    // I2407 — the reader accepts the bundle root.
    let tip = {
        let g = super::genesis::genesis_in_force(d).await.expect("genesis");
        hex::encode(g.tips().first().expect("a tip").object_id)
    };
    let edge = super::fixture_trust_root::bundle_acceptance_statement(
        d,
        &e2::signing_key(seed),
        &reader,
        &tip,
    )
    .await
    .expect("I2407: the edge signs");
    e2::put_statement(d, &edge)
        .await
        .expect("I2407: the acceptance edge lands");
    let at = now_ms();
    let v = verdict(d, &reader, &holder, composite(&c.holder_key(0)), at).await;
    assert_eq!(
        rooted(&v, "I2407 holder"),
        (root.clone(), Plane::Ceremony, RootedVia::AccordHolder),
        "I2407: a holder, under the bundle root"
    );
    let v = verdict(d, &reader, &seat, ClaimedKeyWire::Kid(c.seats[0].kid), at).await;
    assert_eq!(
        rooted(&v, "I2407 seat"),
        (root.clone(), Plane::Ceremony, RootedVia::ServeSeat),
        "I2407: a serve seat, under the bundle root"
    );

    // I2408 — a later bundle: no re-acceptance.
    let later = fixture_genesis::later_v2(
        fixture_genesis::bundle_v2(),
        &[1, 2, 3, 4, 5, 6, 7],
        &fixture_genesis::SERVE_NODE_SEEDS,
        &[1, 2, 3, 4, 5, 6, 7],
    );
    fixture_genesis::install_ceremony_v2(d, &later)
        .await
        .expect("I2408: the later bundle installs");
    let v = verdict(d, &reader, &holder, composite(&c.holder_key(0)), now_ms()).await;
    assert_eq!(
        rooted(&v, "I2408 holder"),
        (root, Plane::Ceremony, RootedVia::AccordHolder),
        "I2408: still Rooted across the lineage"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2405_i2408_bundle_root_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(bundle_root_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2405_i2408_bundle_root_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(bundle_root_body(&b)).await;
}

/// **I2409** — a DELEGATION seat under the bundle root (KB-fix2 on KR-fix2's
/// counted grant and KR-fix3a's wiring): a `node` worker granted
/// `infra:serve` by two of the three holders of the bundle in force (a row
/// counted over the bundle it names, `refs.head`) is `peer_no_conferral` for
/// a reader accepting the bundle root until the worker's OWNER accepts the
/// grant; then it is `Rooted` on the ceremony plane (R2-planes: a counted
/// grant is a row counted over the holders) via `ConferredSeat`,
/// and its root is the bundle's `family_key_id`, never the holder who
/// authored the first voice.
pub(crate) async fn delegation_seat_body(d: &dyn FederationDirectory) {
    use super::scope_resolution_invariants as sr;
    fixture_genesis::install_v2(d)
        .await
        .expect("the ceremony installs");
    let reader = sr::accepting_node(d, "kb2-delegation-reader").await;
    let (worker, owner_seed) = sr::worker_with_owner(d, "kb2del").await;
    let head = super::genesis::genesis_in_force(d)
        .await
        .expect("genesis")
        .tips()
        .first()
        .expect("a tip")
        .object_id;
    let at = sr::grant_instant(d).await;
    let grant = sr::land_grant(d, &worker, INFRA_SERVE_SCOPE, &head, at, "I2409").await;
    let claim = || ClaimedKeyWire::Kid(e2::kid_digest("w-kb2del"));

    let v = verdict(d, &reader, &worker, claim(), now_ms()).await;
    assert!(
        matches!(not_rooted(&v), NotRootedReason::NoConferral { .. }),
        "I2409: an unaccepted root grant confers nothing: {v:?}"
    );

    sr::owner_accepts(d, &owner_seed, &grant, "I2409").await;
    let v = verdict(d, &reader, &worker, claim(), now_ms()).await;
    assert_eq!(
        rooted(&v, "I2409 worker"),
        (
            fixture_genesis::FAMILY_KEY_ID.to_owned(),
            Plane::Ceremony,
            RootedVia::ConferredSeat
        ),
        "I2409: the accepted root grant seats the worker under the bundle root, on the \
         CEREMONY plane (a row counted over the holders; R2-planes)"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2409_delegation_seat_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(delegation_seat_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2409_delegation_seat_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(delegation_seat_body(&b)).await;
}
