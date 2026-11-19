//! **I2101** (v62.0.0, JSON-cut slice A): a statement's `kid` must be a key
//! of its `iss` (CC 2.6.1.7, the key-chain rule; CC-READING(next-edition)).
//!
//! - A key signing as its own identity is admitted.
//! - A key signing as another identity is refused `kid_not_of_iss`.
//! - A rotated key is a key of its identity: its own statement and its
//!   predecessor's, both under the identity, over one record that names the
//!   predecessor's record by `refs.target`. It signs as that identity and is
//!   admitted; as another identity it is refused.
//! - A missing link waits (retryable): the predecessor's statement (naming
//!   the predecessor), or the named record (naming the record).
//! - A rotation without the new key's own statement is not yet a key of the
//!   identity: it WAITS on that voice (v62.0.0 R1 round 3; CC 2.6.1.9,
//!   CIRISVerify 23.3.1 `MissingKey::Voice`), and stands once it arrives.
//! - A predecessor record that does not cover the rotation's instant hands
//!   on nothing.
//! - Two rotations of one predecessor record, neither naming the other,
//!   hand on nothing; a "rival" whose named record does not cover its
//!   instant is no rival and blocks nothing.
//! - A `key:record` about a key that only ANOTHER key signed never makes it
//!   a key of the signer's identity: naming no predecessor it attaches
//!   nothing (`kid_not_of_iss`); naming the signer's own record it is a
//!   rotation short of the new key's voice, and waits on it.
//! - A key the accord's genesis bundle in force seats for a holder is that
//!   holder's (a recovery has no rotation record); with no bundle held it
//!   waits; seated for one holder, it is not another's.
//! - A `key:revocation` is honoured only when its signer's key is of the
//!   `iss` whose standing is asked.
//! - The same at the store door (`put_statement`), on sqlite and postgres.

use std::sync::Arc;

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::{cose_key, sign_row_statement};

use super::door::admit_row;
use super::door_invariants::fixture::*;
use super::liveness::{BundleSeats, ChainMissing, HeldKeys, KeyOf, Liveness, RevokerStanding};
use super::names::RowId;
use crate::federation::{malformed_row, Error};

/// A `key:record` of `subject` under the identity `iss`, signed by
/// `signer`, naming `target` (a predecessor's record, or the key's own
/// earlier record).
pub(crate) fn record_under(
    signer: &CompositeSigningKey,
    subject: &CompositeSigningKey,
    iss: &str,
    at: u64,
    target: Option<&RowId>,
) -> Vec<u8> {
    let mut m = vec![
        ("key", cose_key(subject.public_key())),
        ("identity_type", text_set(&["user"])),
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iss.to_owned())),
    ];
    if let Some(t) = target {
        m.push(("refs", map(vec![("target", ref2(&t.0))])));
    }
    sign_row_statement(
        signer,
        iss,
        &iref(subject),
        "scores",
        "key:record",
        &map(m),
        vec![],
    )
    .unwrap()
}

/// An authored score row signed by `k` under the identity `iss`.
pub(crate) fn row_as(k: &CompositeSigningKey, iss: &str, at: u64) -> Vec<u8> {
    let m = vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(iss.to_owned())),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        (
            "dimension",
            Value::Text("evidence:safety_battery:capture:a:b:v1".into()),
        ),
    ];
    sign_row_statement(
        k,
        iss,
        iss,
        "scores",
        "evidence:.suite:.kind:.cell:.prefix",
        &map(m),
        vec![],
    )
    .unwrap()
}

pub(crate) fn rid(st: &[u8]) -> RowId {
    RowId::of_statement(st).unwrap()
}

fn verdict(held: &HeldKeys, st: &[u8]) -> String {
    match admit_row(st, held, None, SelectContext::default()) {
        Ok(_) => "valid".into(),
        Err(Error::AttesterKeyUnknown { .. }) => "waiting".into(),
        Err(Error::MalformedRow {
            reason, message, ..
        }) => format!("{reason}: {message}"),
        Err(e) => format!("{e:?}"),
    }
}

fn is_reason(v: &str, r: &str) -> bool {
    v.starts_with(&format!("{r}:"))
}

#[test]
fn i2101_a_key_signs_only_as_its_own_identity() {
    let (a, b) = (key(80), key(81));
    let held = holding(&[&a, &b]);
    assert_eq!(
        verdict(&held, &row_as(&a, &iref(&a), 5_000)),
        "valid",
        "I2101 self"
    );
    let v = verdict(&held, &row_as(&a, &iref(&b), 5_000));
    assert!(
        is_reason(&v, malformed_row::KID_NOT_OF_ISS),
        "I2101 as another: {v}"
    );
    // An identity that is not held at all: the key is still not of it.
    let v = verdict(&held, &row_as(&a, &iref(&key(82)), 5_000));
    assert!(
        is_reason(&v, malformed_row::KID_NOT_OF_ISS),
        "I2101 unheld iss: {v}"
    );
}

/// The genesis key `g`, its record, and a rotation to `n` carrying both
/// voices.
fn rotated() -> (
    CompositeSigningKey,
    CompositeSigningKey,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
) {
    let (g, n) = (key(83), key(84));
    let g_rec = key_record(&g, &["user"], 0, None);
    let target = rid(&g_rec);
    let by_n = record_under(&n, &n, &iref(&g), 1_000, Some(&target));
    let by_g = record_under(&g, &n, &iref(&g), 1_000, Some(&target));
    assert_eq!(rid(&by_n), rid(&by_g), "one row, two voices");
    (g, n, g_rec, by_n, by_g)
}

#[test]
fn i2101_a_rotated_key_is_a_key_of_its_identity() {
    let (g, n, g_rec, by_n, by_g) = rotated();
    let mut held = HeldKeys::new();
    for st in [g_rec, by_n, by_g] {
        held.insert_record(st);
    }
    assert_eq!(held.key_of(&kid(&n), &kid(&g)), KeyOf::Yes, "I2101");
    assert_eq!(
        verdict(&held, &row_as(&n, &iref(&g), 5_000)),
        "valid",
        "I2101 rotated key as its identity"
    );
    // A key is always its own genesis key's (the chain is asked only when
    // `kid` is not `iss`): a live rotated key may sign as itself.
    assert_eq!(verdict(&held, &row_as(&n, &iref(&n), 5_000)), "valid");
    // It is not a key of another held identity.
    let other = key(104);
    held.insert_record(key_record(&other, &["user"], 0, None));
    let v = verdict(&held, &row_as(&n, &iref(&other), 5_000));
    assert!(is_reason(&v, malformed_row::KID_NOT_OF_ISS), "I2101 {v}");
    // The genesis key is still its identity's key.
    assert_eq!(verdict(&held, &row_as(&g, &iref(&g), 5_000)), "valid");
}

#[test]
fn i2101_a_missing_rotation_link_waits() {
    let (g, n, g_rec, by_n, _by_g) = rotated();
    // The predecessor's statement over the rotation is not held.
    let mut held = HeldKeys::new();
    held.insert_record(g_rec.clone());
    held.insert_record(by_n.clone());
    assert_eq!(
        held.key_of(&kid(&n), &kid(&g)),
        KeyOf::Waiting(vec![ChainMissing::Kid(kid(&g))]),
        "I2101 the wait names the predecessor"
    );
    assert_eq!(verdict(&held, &row_as(&n, &iref(&g), 5_000)), "waiting");
    // The predecessor's own record (the one `target` names) is not held.
    let (g2, n2) = (key(85), key(86));
    let g2_rec = key_record(&g2, &["user"], 0, None);
    let mut held = HeldKeys::new();
    held.insert_record(record_under(
        &n2,
        &n2,
        &iref(&g2),
        1_000,
        Some(&rid(&g2_rec)),
    ));
    held.insert_record(record_under(
        &g2,
        &n2,
        &iref(&g2),
        1_000,
        Some(&rid(&g2_rec)),
    ));
    assert_eq!(
        held.key_of(&kid(&n2), &kid(&g2)),
        KeyOf::Waiting(vec![ChainMissing::Record(rid(&g2_rec).0)]),
        "I2101 the wait names the record"
    );
    assert_eq!(
        verdict(&held, &row_as(&n2, &iref(&g2), 5_000)),
        "waiting",
        "I2101 target unheld"
    );
    // Once the link arrives, the key is of its identity.
    held.insert_record(g2_rec);
    assert_eq!(verdict(&held, &row_as(&n2, &iref(&g2), 5_000)), "valid");
}

/// v62.0.0 (R1 round 3; CC 2.6.1.9, CIRISVerify 23.3.1
/// `rotation_lacks_possession`) — the predecessor's voice over a sound
/// rotation, the new key's own statement not held: the rotation WAITS on
/// that voice (never refused, never valid), and stands once it arrives.
#[test]
fn i2101_a_rotation_without_the_new_keys_statement_waits_on_it() {
    let (g, n, g_rec, by_n, by_g) = rotated();
    let row = rid(&by_g).0;
    let mut held = HeldKeys::new();
    held.insert_record(g_rec);
    held.insert_record(by_g);
    assert_eq!(
        held.key_of(&kid(&n), &kid(&g)),
        KeyOf::Waiting(vec![ChainMissing::Voice { kid: kid(&n), row }]),
        "I2101 no own statement: waits on it"
    );
    assert_eq!(
        verdict(&held, &row_as(&n, &iref(&g), 5_000)),
        "waiting",
        "I2101"
    );
    held.insert_record(by_n);
    assert_eq!(held.key_of(&kid(&n), &kid(&g)), KeyOf::Yes, "I2101");
    assert_eq!(verdict(&held, &row_as(&n, &iref(&g), 5_000)), "valid");
}

#[test]
fn i2101_a_predecessor_record_must_cover_the_rotation() {
    let (g, n) = (key(98), key(99));
    // A node record of g ending at 1_500; the rotation is signed at 2_000.
    let g_rec = key_record(&g, &["node"], 0, Some(1_500));
    let t = rid(&g_rec);
    let mut held = HeldKeys::new();
    held.insert_record(g_rec);
    held.insert_record(record_under(&n, &n, &iref(&g), 2_000, Some(&t)));
    held.insert_record(record_under(&g, &n, &iref(&g), 2_000, Some(&t)));
    assert_ne!(
        held.key_of(&kid(&n), &kid(&g)),
        KeyOf::Yes,
        "I2101 not covered"
    );
}

#[test]
fn i2101_two_rotations_of_one_record_hand_on_nothing() {
    let (g, n, g_rec, by_n, by_g) = rotated();
    let m = key(100);
    let t = rid(&g_rec);
    let mut held = HeldKeys::new();
    for st in [g_rec, by_n, by_g] {
        held.insert_record(st);
    }
    assert_eq!(
        held.key_of(&kid(&n), &kid(&g)),
        KeyOf::Yes,
        "I2101 one rotation"
    );
    held.insert_record(record_under(&m, &m, &iref(&g), 1_200, Some(&t)));
    held.insert_record(record_under(&g, &m, &iref(&g), 1_200, Some(&t)));
    assert_eq!(held.key_of(&kid(&n), &kid(&g)), KeyOf::No, "I2101 rival: n");
    assert_eq!(held.key_of(&kid(&m), &kid(&g)), KeyOf::No, "I2101 rival: m");
    // A rival carrying only its own statement is no rotation, and no rival.
    let (g3, n3, g3_rec, by_n3, by_g3) = {
        let (g3, n3) = (key(101), key(102));
        let r = key_record(&g3, &["user"], 0, None);
        let t3 = rid(&r);
        let a = record_under(&n3, &n3, &iref(&g3), 1_000, Some(&t3));
        let b = record_under(&g3, &n3, &iref(&g3), 1_000, Some(&t3));
        (g3, n3, r, a, b)
    };
    let mut held = HeldKeys::new();
    let t3 = rid(&g3_rec);
    for st in [g3_rec, by_n3, by_g3] {
        held.insert_record(st);
    }
    let m3 = key(103);
    held.insert_record(record_under(&m3, &m3, &iref(&g3), 1_200, Some(&t3)));
    assert_eq!(
        held.key_of(&kid(&n3), &kid(&g3)),
        KeyOf::Yes,
        "I2101 no rival"
    );
}

#[test]
fn i2101_a_rival_that_its_named_record_does_not_cover_blocks_nothing() {
    let (g, n, m) = (key(124), key(125), key(126));
    // g's first node record covers [0, 1_500]; a second covers [1_600, ...].
    let first = key_record(&g, &["node"], 0, Some(1_500));
    let second = key_record(&g, &["node"], 1_600, Some(1_600 + 1_000_000));
    let t = rid(&first);
    let mut held = HeldKeys::new();
    for st in [
        first,
        second,
        // The rotation to n at 1_000, inside `first`.
        record_under(&n, &n, &iref(&g), 1_000, Some(&t)),
        record_under(&g, &n, &iref(&g), 1_000, Some(&t)),
    ] {
        held.insert_record(st);
    }
    assert_eq!(
        held.key_of(&kid(&n), &kid(&g)),
        KeyOf::Yes,
        "I2101 rotation"
    );
    // A "rival" at 2_000 names `first`, which does not cover 2_000 (g's
    // statement is valid then only through `second`): no rival.
    held.insert_record(record_under(&m, &m, &iref(&g), 2_000, Some(&t)));
    held.insert_record(record_under(&g, &m, &iref(&g), 2_000, Some(&t)));
    assert_eq!(
        held.key_of(&kid(&n), &kid(&g)),
        KeyOf::Yes,
        "I2101 a rival outside its named record blocks nothing"
    );
    assert_ne!(
        held.key_of(&kid(&m), &kid(&g)),
        KeyOf::Yes,
        "I2101 nor is it a rotation"
    );
}

#[test]
fn i2101_a_record_signed_by_another_key_attaches_nothing() {
    let (a, c) = (key(87), key(88));
    // C signs a record of A's key under C's identity; A never signs it.
    let c_rec = key_record(&c, &["user"], 0, None);
    let mut held = holding(&[&c]);
    // Naming no predecessor, it attaches nothing.
    held.insert_record(record_under(&c, &a, &iref(&c), 1_000, None));
    assert_eq!(held.key_of(&kid(&a), &kid(&c)), KeyOf::No, "I2101");
    let v = verdict(&held, &row_as(&a, &iref(&c), 5_000));
    assert!(
        is_reason(&v, malformed_row::KID_NOT_OF_ISS),
        "I2101 never C's key: {v}"
    );
    // v62.0.0 (R1 round 3; CC 2.6.1.9): naming C's own record, it is a
    // rotation C → A short of A's voice. It waits on that voice, and is
    // still never C's key while A has not signed it.
    let named = record_under(&c, &a, &iref(&c), 1_000, Some(&rid(&c_rec)));
    let row = rid(&named).0;
    held.insert_record(named);
    assert_eq!(
        held.key_of(&kid(&a), &kid(&c)),
        KeyOf::Waiting(vec![ChainMissing::Voice { kid: kid(&a), row }]),
        "I2101 waits on A's own voice"
    );
    assert_eq!(verdict(&held, &row_as(&a, &iref(&c), 5_000)), "waiting");
    // With A's own genesis record held, A signs as itself, and still not C.
    held.insert_record(key_record(&a, &["user"], 0, None));
    assert_eq!(verdict(&held, &row_as(&a, &iref(&a), 5_000)), "valid");
    assert_ne!(
        verdict(&held, &row_as(&a, &iref(&c), 5_000)),
        "valid",
        "I2101 never C's key"
    );
}

#[test]
fn i2101_a_key_the_bundle_seats_for_a_holder_is_the_holders() {
    let (x, y, recovered) = (key(120), key(121), key(122));
    let holder = |k: &CompositeSigningKey| key_record(k, &["accord_holder"], 0, None);
    let base = || {
        let mut h = HeldKeys::new();
        for st in [
            holder(&x),
            holder(&y),
            key_record(&recovered, &["accord_holder"], 0, None),
        ] {
            h.insert_record(st);
        }
        h
    };
    // The bundle in force seats `recovered` for X (a recovery: no rotation
    // record links it to X's genesis key).
    let held = base().with_seats(BundleSeats::held([
        (iref(&x), kid(&recovered)),
        (iref(&y), kid(&y)),
    ]));
    assert_eq!(
        held.key_of(&kid(&recovered), &kid(&x)),
        KeyOf::Yes,
        "I2101 seat"
    );
    assert_eq!(
        verdict(&held, &row_as(&recovered, &iref(&x), 5_000)),
        "valid",
        "I2101 a seated key signs as its holder"
    );
    let v = verdict(&held, &row_as(&recovered, &iref(&y), 5_000));
    assert!(
        is_reason(&v, malformed_row::KID_NOT_OF_ISS),
        "I2101 seated for X, signing as Y: {v}"
    );
    // No bundle held: a key signing as a holder's identity waits on it.
    let held = base().with_seats(BundleSeats::not_held());
    assert_eq!(
        held.key_of(&kid(&recovered), &kid(&x)),
        KeyOf::Waiting(vec![ChainMissing::Bundle]),
        "I2101 bundle not held"
    );
    assert_eq!(
        verdict(&held, &row_as(&recovered, &iref(&x), 5_000)),
        "waiting"
    );
    // ...but not as an identity that holds no accord seat.
    let plain = key(123);
    let mut held = base();
    held.insert_record(key_record(&plain, &["user"], 0, None));
    let v = verdict(&held, &row_as(&recovered, &iref(&plain), 5_000));
    assert!(is_reason(&v, malformed_row::KID_NOT_OF_ISS), "I2101 {v}");
}

struct Owner(String);
impl RevokerStanding for Owner {
    fn may_revoke(&self, revoker: &str, _subject: &str) -> bool {
        revoker == self.0
    }
}

#[test]
fn i2101_a_revocation_counts_only_under_a_key_of_its_iss() {
    let (owner, other, subject) = (key(89), key(90), key(91));
    let mut held =
        holding(&[&owner, &other, &subject]).with_standing(Arc::new(Owner(iref(&owner))));
    // `other` signs a revocation of `subject` under the owner's identity.
    let m = vec![
        ("asserted_at", Value::Uint(2_000)),
        ("author", Value::Text(iref(&owner))),
    ];
    let under_owner = sign_row_statement(
        &other,
        &iref(&owner),
        &iref(&subject),
        "scores",
        "key:revocation",
        &map(m),
        vec![],
    )
    .unwrap();
    held.insert_revocation(under_owner);
    assert!(
        matches!(held.liveness(&kid(&subject), 5_000), Liveness::Live(_)),
        "I2101 not under a key of its iss: not honoured"
    );
    held.insert_revocation(revocation(&owner, &subject, 2_000, None));
    assert!(
        matches!(held.liveness(&kid(&subject), 5_000), Liveness::Revoked),
        "I2101 the owner's own key: honoured"
    );
}

#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn body(d: &dyn crate::federation::FederationDirectory) {
    use super::ingest::{put_statement, INGEST_TIER};
    let put = |st: Vec<u8>| async move { put_statement(d, &st, None, INGEST_TIER).await };
    let reason = |e: &Error| match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    };
    let (a, b) = (key(92), key(93));
    put(key_record(&a, &["user"], 0, None)).await.unwrap();
    put(key_record(&b, &["user"], 0, None)).await.unwrap();
    put(row_as(&a, &iref(&a), 5_000))
        .await
        .expect("I2101 store: a key as its own identity");
    let e = put(row_as(&a, &iref(&b), 5_000)).await.unwrap_err();
    assert_eq!(reason(&e), malformed_row::KID_NOT_OF_ISS, "I2101 store");

    // A rotation, its new key's voice first: it waits on the predecessor.
    let (g, n) = (key(94), key(95));
    let g_rec = key_record(&g, &["user"], 0, None);
    let target = rid(&g_rec);
    put(g_rec).await.unwrap();
    let by_n = record_under(&n, &n, &iref(&g), 1_000, Some(&target));
    let by_g = record_under(&g, &n, &iref(&g), 1_000, Some(&target));
    let e = put(by_n.clone()).await.unwrap_err();
    assert_eq!(
        e.kind(),
        "federation_attester_key_unknown",
        "I2101 store: waits"
    );
    let e = put(row_as(&n, &iref(&g), 5_000)).await.unwrap_err();
    assert_eq!(e.kind(), "federation_attester_key_unknown", "I2101 store");
    // The predecessor's voice, then the new key's: the rotation stands.
    put(by_g)
        .await
        .expect("I2101 store: the predecessor's voice");
    put(by_n).await.expect("I2101 store: the new key's voice");
    put(row_as(&n, &iref(&g), 6_000))
        .await
        .expect("I2101 store: the rotated key as its identity");
    let e = put(row_as(&n, &iref(&a), 6_000)).await.unwrap_err();
    assert_eq!(reason(&e), malformed_row::KID_NOT_OF_ISS, "I2101 store");

    // C's record about A2 (A2 never signs it) makes A2 nothing.
    let (a2, c) = (key(96), key(97));
    put(key_record(&c, &["user"], 0, None)).await.unwrap();
    put(record_under(&c, &a2, &iref(&c), 1_000, None))
        .await
        .expect("I2101 store: held, inert");
    put(key_record(&a2, &["user"], 0, None)).await.unwrap();
    let e = put(row_as(&a2, &iref(&c), 5_000)).await.unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::KID_NOT_OF_ISS,
        "I2101 store: {e:?}"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2101_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2101_postgres() {
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
