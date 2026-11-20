//! v62.0.0 (ceremony gap 2 and gap 3 item 3; CC 3.3.6.2, CC 3.4.7) — **the
//! edition-2 "is a re-bind held for this seat" read and the X-Wing transit
//! pair**, on sqlite and postgres.
//!
//! - **I2368** — no genesis bundle held, or an identity-ref that is not a seat
//!   of the bundle in force (a holder): [`rebind_held_for`] is `None`.
//! - **I2369** — a seat of the bundle in force with only its binding is
//!   `None`; one holder's voice (short of the count) is still `None`; at a
//!   strict majority of the bundle's holders the re-bind is returned with its
//!   row id, its key and the bundle it is counted over. Its key is the key
//!   `transit_xwing_pubkey_for` makes live.
//! - **I2370** — a later bundle that re-seats the seat on new X-Wing keys
//!   leaves the re-bind counted over the earlier bundle behind: `None`, and
//!   the seat's live key is the new binding's (with I3241).
//! - **I2371** — `transit_kex_pair_for` answers an edition-2 seat: the
//!   ML-KEM-768 and X25519 halves of its live X-Wing key, the binding's
//!   first and the counted re-bind's after.
//! - **I2372** — the capsule op `RebindHeldFor` answers what the Rust read
//!   answers (`None` before, the re-bind after).

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::genesis::XWING_PUBKEY_LEN;
use ciris_verify_core::edition2::Digest32;

use super::fixture_genesis;
use super::fixture_switch as e2;
use super::group_fixtures::row_id_of;
use super::ingest::StatementOutcome;
use super::transport_rebind::{
    rebind_held_for, HeldRebind, REBIND_FAMILY, REBIND_ROW_TYPE, TRANSIT_MEMBER,
};
use crate::federation::self_at_login::{transit_kex_pair_for, transit_xwing_pubkey_for};
use crate::federation::FederationDirectory;
use crate::ffi::directory_capsule::{
    dispatch_directory_op, DirectoryOp, DirectoryOpResult, Edition2HeldRebind,
};

/// One holder's voice of a `transport:canonical_rebind` about `seat`,
/// counted over the bundle `head`.
fn voice(
    key: &CompositeSigningKey,
    iss: &str,
    seat: &str,
    transit: &[u8],
    at_ms: u64,
    head: &Digest32,
) -> Vec<u8> {
    let mut members = vec![
        (Value::Text("asserted_at".into()), Value::Uint(at_ms)),
        (
            Value::Text(TRANSIT_MEMBER.into()),
            Value::Bytes(transit.to_vec()),
        ),
        (
            Value::Text("refs".into()),
            Value::Map(vec![(
                Value::Text("head".into()),
                ciris_verify_core::edition2::row_ref(head),
            )]),
        ),
    ];
    members.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
    ciris_verify_core::edition2::sign_row_statement(
        key,
        iss,
        seat,
        REBIND_ROW_TYPE,
        REBIND_FAMILY,
        &Value::Map(members),
        vec![],
    )
    .expect("a holder signs a re-bind")
}

/// Another X-Wing key: both halves (pk_M 0..1184, pk_X 1184..1216) changed.
fn other_key(k: &[u8; XWING_PUBKEY_LEN], n: u8) -> [u8; XWING_PUBKEY_LEN] {
    let mut o = *k;
    o[0] ^= n;
    o[1200] ^= n;
    o
}

fn now_ms() -> u64 {
    u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap()
}

async fn held(d: &dyn FederationDirectory, seat: &str) -> Option<HeldRebind> {
    rebind_held_for(d, seat).await.expect("a directory read")
}

async fn via_capsule(d: &dyn FederationDirectory, seat: &str) -> Option<Edition2HeldRebind> {
    match Box::pin(dispatch_directory_op(
        d,
        DirectoryOp::RebindHeldFor {
            seat_identity_ref: seat.to_owned(),
        },
    ))
    .await
    {
        DirectoryOpResult::RebindHeld(r) => r,
        other => panic!("I2372: {other:?}"),
    }
}

/// The halves a pair read of `key` must carry: (ML-KEM-768, X25519).
fn halves(key: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (key[..1184].to_vec(), key[1184..].to_vec())
}

async fn pair_halves(d: &dyn FederationDirectory, seat: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    transit_kex_pair_for(d, seat)
        .await
        .expect("a directory read")
        .map(|p| (p.ml_kem_768.to_vec(), p.x25519.to_vec()))
}

pub(crate) async fn body(d: &dyn FederationDirectory) {
    let c = fixture_genesis::bundle_v2();
    let seat = &c.seats[0];

    // ── I2368: nothing held ──
    assert_eq!(held(d, &seat.identity_ref).await, None, "I2368: no bundle");
    assert_eq!(via_capsule(d, &seat.identity_ref).await, None, "I2372");

    fixture_genesis::install_v2(d)
        .await
        .expect("I2369: the test ceremony installs");

    // ── I2368: not a seat ──
    assert_eq!(
        held(d, c.holder_identity_ref(0)).await,
        None,
        "I2368: a holder is not a seat"
    );

    // ── I2369 / I2371: the binding alone ──
    assert_eq!(
        held(d, &seat.identity_ref).await,
        None,
        "I2369: the binding is no re-bind"
    );
    assert_eq!(
        pair_halves(d, &seat.identity_ref).await,
        Some(halves(&seat.transit_xwing_pubkey)),
        "I2371: the pair is the binding's X-Wing key"
    );

    // ── I2369: short, then counted ──
    let rebound = other_key(&seat.transit_xwing_pubkey, 0x5c);
    let at = now_ms();
    let first = voice(
        &c.holder_key(0),
        c.holder_identity_ref(0),
        &seat.identity_ref,
        &rebound,
        at,
        &c.object_id,
    );
    let o = e2::put_statement(d, &first)
        .await
        .expect("I2369: a holder's voice is kept");
    assert!(
        matches!(o, StatementOutcome::Pending { .. }),
        "I2369: one of three is short: {o:?}"
    );
    assert_eq!(
        held(d, &seat.identity_ref).await,
        None,
        "I2369: a short re-bind is not held"
    );
    let second = voice(
        &c.holder_key(1),
        c.holder_identity_ref(1),
        &seat.identity_ref,
        &rebound,
        at,
        &c.object_id,
    );
    let o = e2::put_statement(d, &second)
        .await
        .expect("I2369: the second holder's voice");
    assert!(
        matches!(o, StatementOutcome::Row { .. }),
        "I2369: two of three meet the count: {o:?}"
    );
    let want = HeldRebind {
        row_id: row_id_of(&first),
        transit_xwing_pubkey: rebound,
        head: super::names::RowId(c.object_id),
    };
    assert_eq!(
        held(d, &seat.identity_ref).await,
        Some(want.clone()),
        "I2369: the counted re-bind"
    );
    assert_eq!(
        transit_xwing_pubkey_for(d, &seat.identity_ref)
            .await
            .unwrap()
            .map(|k| k.as_bytes().to_vec()),
        Some(rebound.to_vec()),
        "I2369: its key is the live key"
    );
    assert_eq!(
        via_capsule(d, &seat.identity_ref).await,
        Some(Edition2HeldRebind::from(&want)),
        "I2372: the op answers the read"
    );
    assert_eq!(
        pair_halves(d, &seat.identity_ref).await,
        Some(halves(&rebound)),
        "I2371: the pair follows the counted re-bind"
    );

    // ── I2370: a re-seat leaves it behind ──
    let reseat =
        fixture_genesis::reseat_xwing_v2(c, seat.seed, 1, &fixture_genesis::HOLDER_SEEDS[..2]);
    fixture_genesis::install_ceremony_v2(d, &reseat)
        .await
        .expect("I2370: the re-seating bundle installs");
    assert_eq!(
        held(d, &seat.identity_ref).await,
        None,
        "I2370: a re-bind over a bundle the re-seat left behind is not held"
    );
    assert_eq!(
        via_capsule(d, &seat.identity_ref).await,
        None,
        "I2372: after the re-seat"
    );
    let new_key = reseat.seats[0].transit_xwing_pubkey;
    assert_eq!(
        transit_xwing_pubkey_for(d, &seat.identity_ref)
            .await
            .unwrap()
            .map(|k| k.as_bytes().to_vec()),
        Some(new_key.to_vec()),
        "I2370: the re-seat's binding is live"
    );
    assert_eq!(
        pair_halves(d, &seat.identity_ref).await,
        Some(halves(&new_key)),
        "I2371: the pair follows the re-seat"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2368_i2372_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2368_i2372_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}
