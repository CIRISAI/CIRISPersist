//! v62.0.0 slice E1 (CIRISPersist#1274; CC rc20 3.3.6.2 "A seat's transit
//! key", CC 8.11.28) — **I1874 / I1875: the pre-cut X-Wing re-bind, and THE
//! RULE that a seated serve node's `transit_xwing_pubkey` is live only by an
//! admitted `transport:canonical_rebind` carrying exactly that row.**
//!
//! Eric's ruling: the earlier-form re-bind row carries the UNCHANGED v1
//! `transit_kex_pubkeys` plus `transit_xwing_pubkey` (standard base64 of
//! exactly 1216 bytes: ML-KEM-768 1184 ‖ X25519 32), signed over the whole
//! envelope at a new epoch. CC 8.11.28: "A `transport:canonical_rebind` row of
//! the earlier form may carry both this pair and `transit_xwing_pubkey`."
//!
//! **I1874** (the committed form of the v61 probe posted on #1274), per
//! backend:
//! (a) the 2-of-3 re-bind is ADMITTED;
//! (b) the carried row is APPLIED by the transport door (live epoch 2);
//! (c) `transit_kex_pair()` and `transit_kex_pair_for` return the UNCHANGED
//!     pinned v1 pair;
//! (d) the member is preserved byte for byte, stored, served, and stored
//!     identically by a peer applying the served re-bind;
//! (e) v62: `rebind_held_for` returns the carried row, and
//!     `transit_xwing_pubkey_for` resolves the X-Wing key on the re-bound
//!     node and on the peer.
//! Negative control: a one-holder re-bind is refused
//! `transport_rebind_without_holder_quorum`.
//!
//! **I1875 — the seat ALONE.** The same TD put by the seat with no re-bind
//! (a v1 re-assertion: the pinned pair is unchanged, so `check_serve_rotation`
//! admits it) is stored and served, but its X-Wing key is NOT live:
//! `rebind_held_for` is `None` and `transit_xwing_pubkey_for` is `None`.
//! CC 3.3.6.2: "A seated serve node's new transit key moves by
//! `transport:canonical_rebind`, counted by the accord's holders, before the
//! handshake changes."
//!
//! Its own process: arms the test-anchor override through the environment.

#![cfg(all(feature = "test-anchor", feature = "sqlite"))]

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ciris_persist::federation::accord_test_support::Identity;
use ciris_persist::federation::genesis::*;
use ciris_persist::federation::self_at_login::{
    self as sal, transit_kex_pair_for, transit_xwing_pubkey_for, SignedTransportDestination,
    TransitKexPair, TransportDestinationApplyOutcome,
};
use ciris_persist::federation::transport_rebind::{rebind_held_for, REBIND_WITHOUT_HOLDER_QUORUM};
use ciris_persist::federation::wire_index::content_hash_of;
use ciris_persist::federation::{Error, FederationDirectory, SignedAttestation};
use ciris_persist::store::backend::Backend as _;
use ciris_persist::store::sqlite::SqliteBackend;

const SEEDS: [[u8; 32]; 3] = [[0x31; 32], [0x32; 32], [0x33; 32]];
const NODE_SEED: [u8; 32] = [0x4E; 32];
/// The new envelope member (Eric's ruling), persist's constant.
const XWING_MEMBER: &str = sal::TRANSIT_XWING_PUBKEY_MEMBER;
/// ML-KEM-768 1184 ‖ X25519 32.
const XWING_LEN: usize = sal::XWING_PUBKEY_LEN;

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

/// A postgres backend on a database of its own. PANICS without a test DSN —
/// a PG leg without a DSN must not pass in 0.00s.
#[cfg(feature = "postgres")]
async fn postgres() -> (ciris_persist::store::postgres::PostgresBackend, PgDrop) {
    let base = std::env::var("CIRIS_PERSIST_TEST_PG_URL")
        .expect("the postgres probe needs CIRIS_PERSIST_TEST_PG_URL (scripts/pg_test_db.sh)");
    let cut = base.rfind('/').expect("dsn has a database");
    let name = format!(
        "ciris_t_xw_{}_{}",
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
    (b, PgDrop { base, name })
}

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

/// 1216 deterministic pseudo-random bytes (synthetic; xorshift64*).
fn xwing_bytes() -> Vec<u8> {
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;
    (0..XWING_LEN)
        .map(|_| {
            s ^= s >> 12;
            s ^= s << 25;
            s ^= s >> 27;
            (s.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8
        })
        .collect()
}

/// The pinned row's envelope, re-signed by the node at `epoch`/`asserted_at`
/// with its `transit_kex_pubkeys` member copied VERBATIM, plus (optionally)
/// the new `transit_xwing_pubkey` member. Every other typed field equals the
/// pinned row's.
fn xwing_td(
    pinned: &SignedTransportDestination,
    asserted_at: chrono::DateTime<chrono::Utc>,
    epoch: u64,
    with_xwing: bool,
) -> SignedTransportDestination {
    let asserted_at =
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(asserted_at.timestamp_millis())
            .unwrap();
    let mut row = pinned.transport_destination.clone();
    row.asserted_at = asserted_at;
    row.epoch = epoch;
    let mut envelope = serde_json::to_value(&row).unwrap();
    let obj = envelope.as_object_mut().unwrap();
    obj.insert(
        sal::TRANSIT_KEX_PUBKEYS_MEMBER.to_owned(),
        pinned
            .signed_envelope
            .get(sal::TRANSIT_KEX_PUBKEYS_MEMBER)
            .expect("the pinned row carries a v1 pair")
            .clone(),
    );
    if with_xwing {
        obj.insert(
            XWING_MEMBER.to_owned(),
            serde_json::Value::String(B64.encode(xwing_bytes())),
        );
    }
    let node = Identity::from_seeds(
        TEST_CEREMONY_NODE_KEY_ID,
        &NODE_SEED,
        &test_anchor_mldsa_seed(&NODE_SEED),
    )
    .unwrap();
    let bytes = ciris_persist::verify::canonical::ceg_produce_canonicalize(&envelope).unwrap();
    let (ed, mldsa) = node.sign_bytes(&bytes);
    SignedTransportDestination {
        transport_destination: row,
        attesting_key_id: TEST_CEREMONY_NODE_KEY_ID.to_owned(),
        signed_envelope: envelope,
        signature: ciris_verify_core::transport_binding::TransportBindingSignature {
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: Some(mldsa),
        },
    }
}

async fn live_reticulum(d: &dyn FederationDirectory) -> SignedTransportDestination {
    d.list_signed_transport_destinations_for(TEST_CEREMONY_NODE_KEY_ID)
        .await
        .unwrap()
        .into_iter()
        .find(|b| {
            b.transport_destination.transport_kind == "reticulum"
                && b.transport_destination.retired_at.is_none()
        })
        .expect("a live reticulum binding")
}

fn assert_v1_pair(tag: &str, what: &str, got: &TransitKexPair, pinned: &TransitKexPair) {
    assert_eq!(got, pinned, "{tag} {what}: the UNCHANGED pinned v1 pair");
}

/// (d) — the stored / served row is the producer's row, byte for byte.
fn assert_preserved(
    tag: &str,
    what: &str,
    got: &SignedTransportDestination,
    want: &SignedTransportDestination,
) {
    assert_eq!(
        got.signed_envelope
            .get(XWING_MEMBER)
            .and_then(|v| v.as_str()),
        Some(B64.encode(xwing_bytes()).as_str()),
        "{tag} {what}: `{XWING_MEMBER}` preserved"
    );
    assert_eq!(
        B64.decode(got.signed_envelope[XWING_MEMBER].as_str().unwrap())
            .unwrap()
            .len(),
        XWING_LEN
    );
    assert_eq!(
        got.signed_envelope, want.signed_envelope,
        "{tag} {what}: the whole envelope"
    );
    assert_eq!(
        ciris_persist::verify::canonical::ceg_produce_canonicalize(&got.signed_envelope).unwrap(),
        ciris_persist::verify::canonical::ceg_produce_canonicalize(&want.signed_envelope).unwrap(),
        "{tag} {what}: the JCS bytes"
    );
    assert_eq!(got.signature, want.signature, "{tag} {what}: the signature");
    assert_eq!(
        got.transport_destination, want.transport_destination,
        "{tag} {what}: the typed projection"
    );
    assert_eq!(got, want, "{tag} {what}: the whole wrapper");
    assert_eq!(
        content_hash_of(got).unwrap(),
        content_hash_of(want).unwrap(),
        "{tag} {what}: the wrapper content hash is the producer's"
    );
}

async fn probe(
    tag: &str,
    a: &dyn FederationDirectory,
    b: &dyn FederationDirectory,
    c: &dyn FederationDirectory,
    bundle: &GenesisBundle,
    holders: &[Identity],
) {
    let pinned = &bundle.serve_transport_destinations[0];
    let pinned_pair = pinned.transit_kex_pair().unwrap().unwrap();
    let when = at(-2);
    let td = xwing_td(pinned, when, 2, true);
    let control = xwing_td(pinned, when, 2, false);
    // Content hash changes only as expected: the same row without the member
    // hashes differently (the envelope is hash-covered), the projection is
    // identical, and the pair is identical.
    assert_eq!(td.transport_destination, control.transport_destination);
    assert_ne!(
        content_hash_of(&td).unwrap(),
        content_hash_of(&control).unwrap()
    );
    assert_eq!(td.transit_kex_pair().unwrap().unwrap(), pinned_pair);
    eprintln!(
        "{tag}: hashes pinned={} xwing={} control(no member)={}",
        content_hash_of(pinned).unwrap(),
        content_hash_of(&td).unwrap(),
        content_hash_of(&control).unwrap()
    );

    // ── Node A: the negative (one holder) then the quorum re-bind. ──
    boot(a, bundle, tag).await;
    let one = test_rebind_row(&[&holders[0]], &td, at(-1)).unwrap();
    match a
        .put_attestation(SignedAttestation { attestation: one })
        .await
    {
        Err(Error::InvalidArgument(m)) if m.starts_with(REBIND_WITHOUT_HOLDER_QUORUM) => {
            eprintln!("{tag} NEG one-holder re-bind refused: {m}");
        }
        other => panic!("{tag} NEG: a one-holder re-bind was not refused: {other:?}"),
    }
    let still = live_reticulum(a).await;
    assert_eq!(
        still.transport_destination.epoch, 1,
        "{tag} NEG: the pinned row stands"
    );
    assert!(still.signed_envelope.get(XWING_MEMBER).is_none());

    let rebind = test_rebind_row(&[&holders[0], &holders[2]], &td, at(0)).unwrap();
    // (a)
    a.put_attestation(SignedAttestation {
        attestation: rebind.clone(),
    })
    .await
    .unwrap_or_else(|e| panic!("{tag} (a): the 2-of-3 xwing re-bind refused: {e}"));
    eprintln!("{tag} (a) ADMITTED: 2-of-3 re-bind carrying the xwing TD");
    // (b)
    let live = live_reticulum(a).await;
    assert_eq!(
        live.transport_destination.epoch, 2,
        "{tag} (b): the carried row is live"
    );
    assert_eq!(
        a.put_signed_transport_destination(&td).await.unwrap(),
        TransportDestinationApplyOutcome::Unchanged,
        "{tag} (b): the carried row is what the door stored"
    );
    eprintln!("{tag} (b) APPLIED: live binding is epoch 2, re-put Unchanged");
    // (c)
    assert_v1_pair(
        tag,
        "(c) transit_kex_pair()",
        &live.transit_kex_pair().unwrap().unwrap(),
        &pinned_pair,
    );
    let resolved = transit_kex_pair_for(a, TEST_CEREMONY_NODE_KEY_ID)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{tag} (c): the resolver returns a pair"));
    assert_v1_pair(tag, "(c) transit_kex_pair_for", &resolved, &pinned_pair);
    eprintln!("{tag} (c) UNCHANGED v1 pair from transit_kex_pair() and transit_kex_pair_for");
    // (d) stored
    assert_preserved(tag, "(d) stored", &live, &td);
    // (d) served on the TD serve cursor
    let served = a
        .list_signed_transport_destinations_since(None, 1000)
        .await
        .unwrap();
    let served_td = served
        .iter()
        .map(|s| &s.destination)
        .find(|d| {
            d.transport_destination.occurrence_key_id == TEST_CEREMONY_NODE_KEY_ID
                && d.transport_destination.transport_kind == "reticulum"
        })
        .unwrap_or_else(|| panic!("{tag} (d): the TD is served"));
    assert_preserved(tag, "(d) served TD", served_td, &td);
    // (d) the served re-bind attestation row is the one we built
    let served_atts = a.list_attestations_since(None, 1000).await.unwrap();
    let served_rebind = served_atts
        .iter()
        .map(|s| &s.attestation)
        .find(|x| x.attestation_id == rebind.attestation_id)
        .unwrap_or_else(|| panic!("{tag} (d): the re-bind row is served"))
        .clone();
    assert_eq!(
        served_rebind.original_content_hash,
        rebind.original_content_hash
    );
    assert_eq!(
        served_rebind.attestation_envelope,
        rebind.attestation_envelope
    );
    assert_eq!(
        served_rebind.attestation_envelope["transport_destination"]["signed_envelope"]
            [XWING_MEMBER],
        serde_json::Value::String(B64.encode(xwing_bytes())),
        "{tag} (d): the served re-bind row carries the member"
    );
    eprintln!("{tag} (d) PRESERVED stored + served (TD cursor and re-bind row), hash unchanged");
    // (e) v62 — the held re-bind names the live row, so the X-Wing key is live.
    assert_eq!(
        rebind_held_for(a, TEST_CEREMONY_NODE_KEY_ID)
            .await
            .unwrap()
            .as_ref(),
        Some(&td),
        "I1874 {tag} (e): rebind_held_for returns the carried row"
    );
    let xw = transit_xwing_pubkey_for(a, TEST_CEREMONY_NODE_KEY_ID)
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("I1874 {tag} (e): the re-bound X-Wing key is live"));
    assert_eq!(xw.as_bytes().as_slice(), xwing_bytes().as_slice());
    assert_eq!(xw.ml_kem_768(), &xwing_bytes()[..1184]);
    assert_eq!(xw.x25519(), &xwing_bytes()[1184..]);

    // ── Node B (a peer): apply the SERVED re-bind row. ──
    boot(b, bundle, tag).await;
    b.put_attestation(SignedAttestation {
        attestation: served_rebind,
    })
    .await
    .unwrap_or_else(|e| panic!("{tag} (d) peer: the served re-bind refused: {e}"));
    let peer_live = live_reticulum(b).await;
    assert_preserved(tag, "(d) peer stored", &peer_live, &td);
    let peer_pair = transit_kex_pair_for(b, TEST_CEREMONY_NODE_KEY_ID)
        .await
        .unwrap()
        .unwrap();
    assert_v1_pair(tag, "(d) peer resolver", &peer_pair, &pinned_pair);
    // and the served TD wrapper itself, offered to the peer directly: Unchanged
    assert_eq!(
        b.put_signed_transport_destination(served_td).await.unwrap(),
        TransportDestinationApplyOutcome::Unchanged
    );
    eprintln!("{tag} (d) PEER applied the served re-bind; envelope + member identical");
    assert!(
        transit_xwing_pubkey_for(b, TEST_CEREMONY_NODE_KEY_ID)
            .await
            .unwrap()
            .is_some(),
        "I1874 {tag} (e) peer: the re-bound X-Wing key is live on the peer"
    );

    // ── Node C: the SEAT-ALONE control (no re-bind). ──
    boot(c, bundle, tag).await;
    let outcome = c.put_signed_transport_destination(&td).await;
    eprintln!("{tag} SEAT-ALONE outcome: {outcome:?}");
    assert_eq!(
        outcome.unwrap_or_else(|e| panic!("{tag} SEAT-ALONE refused: {e}")),
        TransportDestinationApplyOutcome::Superseded,
        "{tag} SEAT-ALONE: admitted (re-asserts the pinned pair)"
    );
    let c_live = live_reticulum(c).await;
    assert_preserved(tag, "seat-alone stored", &c_live, &td);
    let c_pair = transit_kex_pair_for(c, TEST_CEREMONY_NODE_KEY_ID)
        .await
        .unwrap()
        .unwrap();
    assert_v1_pair(tag, "seat-alone resolver", &c_pair, &pinned_pair);
    // I1875 — THE RULE: stored and served, but NOT live.
    assert_eq!(
        c_live
            .transit_xwing_pubkey()
            .unwrap()
            .map(|k| k.as_bytes().to_vec()),
        Some(xwing_bytes()),
        "I1875 {tag}: the seat-alone row carries the key as signed"
    );
    assert!(
        rebind_held_for(c, TEST_CEREMONY_NODE_KEY_ID)
            .await
            .unwrap()
            .is_none(),
        "I1875 {tag}: no re-bind is held for the seat"
    );
    assert!(
        transit_xwing_pubkey_for(c, TEST_CEREMONY_NODE_KEY_ID)
            .await
            .unwrap()
            .is_none(),
        "I1875 {tag}: a seat-published X-Wing key is NOT live without an admitted re-bind \
         (CC 3.3.6.2)"
    );
}

#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i1874_i1875_xwing_rebind_sqlite() {
    let c = mint_test_ceremony(&SEEDS, &NODE_SEED, at(-60)).expect("mint");
    let _armed = Armed::with(&c.block);
    let holders = test_ceremony_holders(&SEEDS).unwrap();
    let (a, b, n) = (sqlite().await, sqlite().await, sqlite().await);
    probe("sqlite", &a, &b, &n, &c.bundle, &holders).await;
    eprintln!("sqlite: RAN");
}

#[cfg(feature = "postgres")]
#[serial_test::serial(test_anchor_env)]
#[tokio::test]
async fn i1874_i1875_xwing_rebind_postgres() {
    let c = mint_test_ceremony(&SEEDS, &NODE_SEED, at(-60)).expect("mint");
    let _armed = Armed::with(&c.block);
    let holders = test_ceremony_holders(&SEEDS).unwrap();
    let (a, ga) = postgres().await;
    let (b, gb) = postgres().await;
    let (n, gc) = postgres().await;
    probe("postgres", &a, &b, &n, &c.bundle, &holders).await;
    for g in [ga, gb, gc] {
        g.drop_db().await;
    }
    eprintln!("postgres: RAN");
}
