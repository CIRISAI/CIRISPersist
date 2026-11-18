//! v61.4.0 — I1803–I1807, **the seat door (CC C559, DERIVED, pending
//! text)**: a minter gives a newcomer its current epoch key at the seat,
//! without a content write.
//!
//! - **I1803** (sqlite, postgres) — nothing due: the current epoch is wrapped
//!   to the newcomer's live devices and its rows are emitted to exactly them;
//!   nothing is minted, the counter does not move, no content is written; a
//!   keyless newcomer is excluded (no grant, no row); a re-run writes nothing;
//!   a non-member is not seated (C559 a, d, f).
//! - **I1804** (sqlite, postgres) — rotation due (a removal effective after
//!   the current epoch was minted): the seat rotates this minter's counter,
//!   mints the new epoch with NO content, wraps it to every current member's
//!   live devices (the newcomer included, the removed member's device not),
//!   disables the old epoch, and emits; a second seat mints nothing (C559 b).
//! - **I1805** (sqlite, postgres) — only this node's own counter: a node that
//!   has minted nothing in the room is not a minter and writes nothing; an
//!   epoch another node minted is reported and never touched (C559 e).
//! - **I1806** (sqlite, postgres) — the empty epoch a seat mints is tolerated
//!   by what reads epochs: the next seal binds into it (no second rotation)
//!   and the newcomer reads it; a later rotation's sweep disables and
//!   DESTROYS the empty past epoch cleanly (nothing sealed, nothing blocked,
//!   nothing failed) while the content epoch is blocked under `retain =
//!   None` and evicted under `retain = 0` exactly as before (C559 c).
//! - **I1807** (sqlite, postgres) — the Engine door: `seat_community_member`
//!   emits the newcomer's rows through the seal's emission path.

//!
//! v62.0.0 (E3b) — the room is edition 2 (the fold room's fixtures,
//! [`key_grant_fold_invariants`](super::key_grant_fold_invariants)): kids
//! everywhere, the roster as `group:roster` voices, a removal as
//! `membership:removal` voices, and the minter node alice's by the OWNER
//! RELATION (her owner binding + the node's own self-occurrence), never an
//! occurrence of her (`occurrence_binds_machine_to_person`). Device seeds
//! lead with their distinguishing part (a signer seeds from a key id's first
//! 32 bytes).

#![cfg(test)]

use crate::federation::community_dek::orchestrate::{
    encrypt_and_cascade_community, read_for_community_viewer, seat_community_member,
    sweep_rotated_epochs,
};
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::key_grant::emit_epoch_key_grant_with_local_signer;
use crate::federation::key_grant_fold_invariants::{found_room, leave, occurrence, own_node};
use crate::federation::key_grant_invariants::two_node::{node_as, Node};
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::types::identity_type::{NODE, USER};
use crate::federation::{BlobStorage, DekKeyState, FederationDirectory, GrantWrap};
use std::collections::BTreeSet;

/// The seeds a [`Room`] was built from (the fixtures sign with seeds; the
/// stored rows and every production query name their kids).
pub(crate) struct RoomSeeds {
    pub comm: String,
    pub alice: String,
    pub bob: String,
    pub rex: String,
    pub nina: String,
    pub kay: String,
    pub n_devs: Vec<String>,
    pub k0: String,
}

/// A room whose roster already names the newcomers (`nina`, keyed devices;
/// `kay`, a keyless device) — their devices are added after the first seal,
/// so the seal finds them absent and the seat is what reaches them. Every
/// field but `s` is a kid.
pub(crate) struct Room {
    pub comm: String,
    pub bob: String,
    pub nina: String,
    pub kay: String,
    pub b0: String,
    pub r0: String,
    pub n_devs: Vec<String>,
    pub k0: String,
    pub s: RoomSeeds,
}

/// The seat room on the minter `n` (brought up from `node_seed`, a NODE key
/// alice owns).
pub(crate) async fn seed<B>(n: &Node<'_, B>, node_seed: &str, tag: &str) -> Room
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let run = uuid::Uuid::new_v4().simple().to_string();
    let comm = format!("{tag}-comm-{run}");
    let alice = format!("{tag}-alice-{run}");
    let bob = format!("{tag}-bob-{run}");
    let rex = format!("{tag}-rex-{run}");
    let nina = format!("{tag}-nina-{run}");
    let kay = format!("{tag}-kay-{run}");
    ts::register_hybrid_key_as(n.backend, &comm, &comm, USER).await;
    for m in [&alice, &bob, &rex, &nina, &kay] {
        ts::register_hybrid_key_as(n.backend, m, m, USER).await;
    }
    let (b0, r0) = (format!("d0-{bob}"), format!("d0-{rex}"));
    own_node(n, node_seed, &alice).await;
    occurrence(n, &bob, &b0, true).await;
    occurrence(n, &rex, &r0, true).await;
    found_room(
        n,
        &comm,
        "seat room",
        &[&alice, &bob, &rex, &nina, &kay],
        chrono::Utc::now() - chrono::Duration::hours(1),
    )
    .await;
    let n_devs = vec![format!("d0-{nina}"), format!("d1-{nina}")];
    let k0 = format!("d0-{kay}");
    Room {
        comm: e2::kid(&comm),
        bob: e2::kid(&bob),
        nina: e2::kid(&nina),
        kay: e2::kid(&kay),
        b0: e2::kid(&b0),
        r0: e2::kid(&r0),
        n_devs: n_devs.iter().map(|d| e2::kid(d)).collect(),
        k0: e2::kid(&k0),
        s: RoomSeeds {
            comm,
            alice,
            bob,
            rex,
            nina,
            kay,
            n_devs,
            k0,
        },
    }
}

/// The newcomers' devices appear (after the first seal).
async fn newcomers_arrive<B>(n: &Node<'_, B>, room: &Room)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    for d in &room.s.n_devs {
        occurrence(n, &room.s.nina, d, true).await;
    }
    occurrence(n, &room.s.kay, &room.s.k0, false).await;
}

/// `who` (a seed) leaves, effective now: their own voice plus alice's,
/// nina's and kay's (never removed here), a majority of the roster outright
/// whichever of rex / bob leaves.
async fn remove<B>(n: &Node<'_, B>, room: &Room, who: &str)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let at = crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
    leave(
        n,
        &room.s.comm,
        who,
        at,
        &[who, &room.s.alice, &room.s.nina, &room.s.kay],
    )
    .await;
}

/// The minter node of a seat witness: `{tag}-minter`, a NODE key.
async fn minter<'a, B>(backend: &'a B, tag: &str) -> (Node<'a, B>, String)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let alias = format!("{tag}-minter");
    (node_as(backend, &alias, NODE).await, alias)
}

async fn recipients<B: BlobStorage + Sync>(
    b: &B,
    room: &Room,
    m: &str,
    e: u64,
) -> BTreeSet<String> {
    b.community_dek_member_grant_recipients(&room.comm, m, e)
        .await
        .unwrap()
        .into_iter()
        .collect()
}

async fn emitted_to<B>(n: &Node<'_, B>, room: &Room, epoch: u64) -> BTreeSet<String>
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let out = emit_epoch_key_grant_with_local_signer(n.backend, &n.signer, &room.comm, epoch)
        .await
        .unwrap();
    let mut to = BTreeSet::new();
    for id in out.map(|o| o.attestation_ids).unwrap_or_default() {
        let a = n
            .backend
            .get_attestation(&id)
            .await
            .unwrap()
            .expect("stored");
        to.insert(a.attested_key_id);
    }
    to
}

fn set(v: &[&String]) -> BTreeSet<String> {
    v.iter().map(|s| (*s).clone()).collect()
}

/// I1803 — nothing due.
pub(crate) async fn i1803_nothing_due_wraps_never_mints<B>(backend: &B, tag: &str)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let (n, alias) = minter(backend, tag).await;
    let room = seed(&n, &alias, tag).await;
    let sealed = encrypt_and_cascade_community(backend, &room.comm, b"x", None, Some(&n.key))
        .await
        .unwrap();
    let e0 = sealed.epoch;
    let _ = emitted_to(&n, &room, e0).await;
    newcomers_arrive(&n, &room).await;
    let objects = backend
        .community_dek_epoch_object_count(&room.comm, &n.key, e0)
        .await
        .unwrap();
    let now = chrono::Utc::now();
    let s = seat_community_member(backend, &room.comm, &n.key, &room.nina, now)
        .await
        .unwrap();
    assert_eq!(s.skipped, None, "{tag} I1803: {s:?}");
    assert_eq!(s.epoch, Some(e0), "{tag} I1803: the current epoch");
    assert!(
        !s.minted && s.rotated_from.is_none(),
        "{tag} I1803 (a): never mints: {s:?}"
    );
    assert_eq!(
        s.newcomer_granted.iter().collect::<BTreeSet<_>>(),
        room.n_devs.iter().collect(),
        "{tag} I1803: the newcomer's live devices"
    );
    assert!(s.emit, "{tag} I1803: rows owed");
    assert_eq!(
        backend
            .community_dek_current_epoch(&room.comm, &n.key)
            .await
            .unwrap(),
        e0,
        "{tag} I1803 (a): the counter does not move"
    );
    assert_eq!(
        backend
            .community_dek_epochs(&room.comm, &n.key)
            .await
            .unwrap()
            .len(),
        1,
        "{tag} I1803 (a): one minted epoch"
    );
    assert_eq!(
        backend
            .community_dek_epoch_object_count(&room.comm, &n.key, e0)
            .await
            .unwrap(),
        objects,
        "{tag} I1803: no content written"
    );
    assert_eq!(
        emitted_to(&n, &room, e0).await,
        room.n_devs.iter().cloned().collect(),
        "{tag} I1803: rows to exactly the newcomer's devices"
    );
    // (d) keyless: excluded, no grant, no row.
    let k = seat_community_member(backend, &room.comm, &n.key, &room.kay, now)
        .await
        .unwrap();
    assert!(k.excluded.contains(&room.k0), "{tag} I1803 (d): {k:?}");
    assert!(k.granted.is_empty() && !k.minted, "{tag} I1803 (d): {k:?}");
    assert!(
        !recipients(backend, &room, &n.key, e0)
            .await
            .contains(&room.k0),
        "{tag} I1803 (d): the keyless device holds no grant"
    );
    // (f) re-run: nothing.
    let before = recipients(backend, &room, &n.key, e0).await;
    let again = seat_community_member(backend, &room.comm, &n.key, &room.nina, now)
        .await
        .unwrap();
    assert!(
        again.granted.is_empty() && !again.minted && !again.emit,
        "{tag} I1803 (f): {again:?}"
    );
    assert_eq!(recipients(backend, &room, &n.key, e0).await, before);
    assert!(
        emitted_to(&n, &room, e0).await.is_empty(),
        "{tag} I1803 (f): no rows"
    );
    // Not a member: not seated.
    let stranger = e2::kid(&format!("{tag}-stranger"));
    let x = seat_community_member(backend, &room.comm, &n.key, &stranger, now)
        .await
        .unwrap();
    assert_eq!(x.skipped, Some("not_a_member"), "{tag} I1803: {x:?}");
    assert_eq!(recipients(backend, &room, &n.key, e0).await, before);
}

/// I1804 — rotation due.
pub(crate) async fn i1804_rotation_due_rotates_once_at_the_seat<B>(backend: &B, tag: &str)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let (n, alias) = minter(backend, tag).await;
    let room = seed(&n, &alias, tag).await;
    let e0 = encrypt_and_cascade_community(backend, &room.comm, b"x", None, Some(&n.key))
        .await
        .unwrap()
        .epoch;
    let _ = emitted_to(&n, &room, e0).await;
    remove(&n, &room, &room.s.rex).await;
    newcomers_arrive(&n, &room).await;
    let now = chrono::Utc::now();
    let s = seat_community_member(backend, &room.comm, &n.key, &room.nina, now)
        .await
        .unwrap();
    let e1 = s.epoch.expect("an epoch");
    assert!(
        s.minted && e1 > e0,
        "{tag} I1804: rotated at the seat: {s:?}"
    );
    assert_eq!(s.rotated_from, Some(e0), "{tag} I1804");
    assert_eq!(
        backend
            .community_dek_current_epoch(&room.comm, &n.key)
            .await
            .unwrap(),
        e1
    );
    assert_eq!(
        backend
            .community_dek_key_state(&room.comm, &n.key, e0)
            .await
            .unwrap(),
        Some(DekKeyState::Disabled),
        "{tag} I1804: the old epoch is rotated past"
    );
    let want = set(&[&n.key, &room.b0, &room.n_devs[0], &room.n_devs[1]]);
    assert_eq!(
        recipients(backend, &room, &n.key, e1).await,
        want,
        "{tag} I1804: every live device, never the removed one's"
    );
    assert_eq!(
        backend
            .community_dek_epoch_object_count(&room.comm, &n.key, e1)
            .await
            .unwrap(),
        0,
        "{tag} I1804: minted with NO content"
    );
    assert_eq!(
        emitted_to(&n, &room, e1).await,
        want,
        "{tag} I1804: rows to every live device"
    );
    // (b) the second seat mints nothing.
    for who in [&room.nina, &room.bob] {
        let again = seat_community_member(backend, &room.comm, &n.key, who, chrono::Utc::now())
            .await
            .unwrap();
        assert!(
            !again.minted && again.epoch == Some(e1),
            "{tag} I1804 (b): {again:?}"
        );
        assert!(again.granted.is_empty(), "{tag} I1804 (b): {again:?}");
    }
    assert_eq!(
        backend
            .community_dek_epochs(&room.comm, &n.key)
            .await
            .unwrap()
            .len(),
        2,
        "{tag} I1804 (b): one removal, one rotation"
    );
    let _ = &room.r0;
}

/// I1805 — only this node's own counter.
pub(crate) async fn i1805_only_this_minters_counter<B>(backend: &B, tag: &str)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let (n, alias) = minter(backend, tag).await;
    let room = seed(&n, &alias, tag).await;
    newcomers_arrive(&n, &room).await;
    let other = format!("{tag}-other-minter");
    // A peer's epoch 3, as this node holds it after admitting its rows.
    backend
        .community_dek_put_member_grants(
            &room.comm,
            &other,
            3,
            &[GrantWrap {
                recipient_key_id: n.key.clone(),
                wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.into(),
                wrapped_dek: "d3JhcA".into(),
            }],
        )
        .await
        .unwrap();
    let held = backend
        .community_dek_member_grant_recipients(&room.comm, &other, 3)
        .await
        .unwrap();
    let s = seat_community_member(backend, &room.comm, &n.key, &room.nina, chrono::Utc::now())
        .await
        .unwrap();
    assert_eq!(s.skipped, Some("not_a_minter"), "{tag} I1805: {s:?}");
    assert_eq!(
        s.minted_elsewhere,
        vec![(other.clone(), 3)],
        "{tag} I1805 (e): reported"
    );
    assert!(
        backend
            .community_dek_epochs(&room.comm, &n.key)
            .await
            .unwrap()
            .is_empty(),
        "{tag} I1805: a non-minter mints nothing"
    );
    // Now this node mints; the seat moves only its own epoch.
    let e0 = encrypt_and_cascade_community(backend, &room.comm, b"x", None, Some(&n.key))
        .await
        .unwrap()
        .epoch;
    let s = seat_community_member(backend, &room.comm, &n.key, &room.nina, chrono::Utc::now())
        .await
        .unwrap();
    assert_eq!(s.epoch, Some(e0), "{tag} I1805");
    assert_eq!(
        s.minted_elsewhere,
        vec![(other.clone(), 3)],
        "{tag} I1805 (e)"
    );
    assert_eq!(
        backend
            .community_dek_member_grant_recipients(&room.comm, &other, 3)
            .await
            .unwrap(),
        held,
        "{tag} I1805 (e): never touched"
    );
    assert!(
        backend
            .community_dek_epochs(&room.comm, &other)
            .await
            .unwrap()
            .is_empty(),
        "{tag} I1805 (e): no state under the peer's counter"
    );
}

/// I1806 — the empty epoch is tolerated.
pub(crate) async fn i1806_the_empty_epoch_is_tolerated<B>(backend: &B, tag: &str)
where
    B: BlobStorage + FederationDirectory + Sync,
{
    let (n, alias) = minter(backend, tag).await;
    let room = seed(&n, &alias, tag).await;
    let first =
        encrypt_and_cascade_community(backend, &room.comm, b"e0 content", None, Some(&n.key))
            .await
            .unwrap();
    let e0 = first.epoch;
    remove(&n, &room, &room.s.rex).await;
    newcomers_arrive(&n, &room).await;
    let e1 = seat_community_member(backend, &room.comm, &n.key, &room.nina, chrono::Utc::now())
        .await
        .unwrap()
        .epoch
        .unwrap();
    remove(&n, &room, &room.s.bob).await;
    let s2 = seat_community_member(backend, &room.comm, &n.key, &room.nina, chrono::Utc::now())
        .await
        .unwrap();
    let e2 = s2.epoch.unwrap();
    assert!(
        s2.minted && e2 > e1 && e1 > e0,
        "{tag} I1806: {e0} {e1} {e2}"
    );
    // The sweep: the empty past epoch is destroyed cleanly, the content
    // epoch blocked (retain = None).
    let sweep = sweep_rotated_epochs(backend, &room.comm, &n.signer, chrono::Utc::now())
        .await
        .unwrap();
    assert!(
        sweep.destroyed.contains(&e1),
        "{tag} I1806: the empty epoch is destroyed: {sweep:?}"
    );
    assert_eq!(
        sweep.blocked,
        vec![(e0, 1)],
        "{tag} I1806: the content epoch is retained"
    );
    assert!(sweep.failed.is_empty(), "{tag} I1806: {sweep:?}");
    // The next seal binds into the seat's empty epoch: no second rotation.
    let sealed =
        encrypt_and_cascade_community(backend, &room.comm, b"e2 content", None, Some(&n.key))
            .await
            .unwrap();
    assert_eq!(
        sealed.epoch, e2,
        "{tag} I1806: the seal joins the seat's epoch"
    );
    assert_eq!(
        read_for_community_viewer(backend, &sealed.at_rest_sha256, &room.n_devs[0])
            .await
            .unwrap(),
        b"e2 content",
        "{tag} I1806: the newcomer reads content sealed in the seat's epoch"
    );
    // Retention, as before: retain 0 evicts the content epoch.
    backend
        .community_dek_set_retain_past_epochs(&room.comm, &n.key, Some(0))
        .await
        .unwrap();
    let sweep = sweep_rotated_epochs(backend, &room.comm, &n.signer, chrono::Utc::now())
        .await
        .unwrap();
    assert!(
        sweep.destroyed.contains(&e0) && sweep.failed.is_empty(),
        "{tag} I1806: {sweep:?}"
    );
    assert_eq!(
        backend
            .community_dek_key_state(&room.comm, &n.key, e2)
            .await
            .unwrap(),
        Some(DekKeyState::Enabled),
        "{tag} I1806: the current epoch is untouched"
    );
}

macro_rules! runners {
    ($m:ident, $fresh:expr) => {
        mod $m {
            fn tag(t: &str) -> String {
                format!("{t}-{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
            }
            #[tokio::test]
            async fn i1803() {
                let Some(b) = $fresh.await else { return };
                super::i1803_nothing_due_wraps_never_mints(&b, &tag("i1803")).await
            }
            #[tokio::test]
            async fn i1804() {
                let Some(b) = $fresh.await else { return };
                super::i1804_rotation_due_rotates_once_at_the_seat(&b, &tag("i1804")).await
            }
            #[tokio::test]
            async fn i1805() {
                let Some(b) = $fresh.await else { return };
                super::i1805_only_this_minters_counter(&b, &tag("i1805")).await
            }
            #[tokio::test]
            async fn i1806() {
                let Some(b) = $fresh.await else { return };
                super::i1806_the_empty_epoch_is_tolerated(&b, &tag("i1806")).await
            }
        }
    };
}

#[cfg(feature = "sqlite")]
runners!(sqlite, async {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
});

#[cfg(feature = "postgres")]
runners!(postgres, async {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
        return None;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
});

/// I1807 — the Engine door emits the newcomer's rows.
async fn i1807_engine_door(engine: crate::Engine, alias: &str) {
    use crate::federation::types::cohort_scope::COMMUNITY;
    engine
        .register_self_federation_key(USER, None, None)
        .await
        .expect("register the engine's own key");
    let key = engine.local_derived_key_id().await.unwrap();
    macro_rules! body {
        ($b:expr) => {{
            let b = $b;
            let id = b.load_or_init_content_kem_identity().await.unwrap();
            let n = Node {
                backend: b,
                signer: ts::local_signer(alias),
                key: key.clone(),
                kem: crate::federation::EncryptionPubkeys {
                    x25519_base64: id.x25519_pubkey_b64,
                    ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
                },
            };
            // v62.0.0 (E3b): still held for P8 (the Engine producer); the
            // engine's key must be a NODE alice owns for this seed.
            let room = seed(&n, alias, alias).await;
            engine
                .put_blob_scoped(COMMUNITY, Some(&room.comm), b"minutes", None, None)
                .await
                .expect("the seal through the door");
            newcomers_arrive(&n, &room).await;
            let out = engine
                .seat_community_member(&room.comm, &room.nina)
                .await
                .expect("the seat door");
            assert!(!out.seat.minted, "I1807: {out:?}");
            let emission = out.emission.expect("I1807: the rows were emitted");
            let mut to = BTreeSet::new();
            for id in &emission.attestation_ids {
                to.insert(
                    b.get_attestation(id)
                        .await
                        .unwrap()
                        .unwrap()
                        .attested_key_id,
                );
            }
            assert_eq!(
                to,
                room.n_devs.iter().cloned().collect(),
                "I1807: {emission:?}"
            );
            let again = engine
                .seat_community_member(&room.comm, &room.nina)
                .await
                .unwrap();
            assert!(
                again.emission.is_none() && again.seat.granted.is_empty(),
                "I1807 (f): {again:?}"
            );
        }};
    }
    // The `return` keeps postgres off a sqlite engine; with no postgres arm
    // compiled it is the last statement (a sqlite-only clippy red).
    #[cfg(feature = "sqlite")]
    #[cfg_attr(not(feature = "postgres"), allow(clippy::needless_return))]
    if let Some(b) = engine.sqlite_backend() {
        body!(b.as_ref());
        return;
    }
    #[cfg(feature = "postgres")]
    if let Some(b) = engine.postgres_backend() {
        body!(b.as_ref());
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i1807_sqlite() {
    Box::pin(
        crate::federation::edition2::fixture_switch::with_earlier_form_async(async {
            let alias = format!("i1807-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
            let e =
                crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), "sqlite::memory:")
                    .await
                    .unwrap();
            i1807_engine_door(e, &alias).await;
        }),
    )
    .await
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i1807_postgres() {
    Box::pin(
        crate::federation::edition2::fixture_switch::with_earlier_form_async(async {
            let Some(dsn) = crate::test_pg::isolated_dsn() else {
                eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
                return;
            };
            let alias = format!("i1807-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
            let e = crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), &dsn)
                .await
                .unwrap();
            i1807_engine_door(e, &alias).await;
        }),
    )
    .await
}
