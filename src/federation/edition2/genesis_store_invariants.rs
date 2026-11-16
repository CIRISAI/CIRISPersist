//! **I1911**: the genesis door, the bundle in force, and canonical standing
//! under ruling C, on sqlite and postgres.
//!
//! - `put_genesis_bundle` verifies a bundle's generic rules, then refuses
//!   `genesis_bundle_reader_unavailable` at the placement step (Verify's
//!   bundle reader, TODO(verify-bundle-reader)). It stores nothing.
//! - The bundles in force follow `refs.prev` from a fresh genesis, never
//!   instants:
//!   - a v2 naming the v1 is the tip;
//!   - two fresh geneses are two tips (a fork);
//!   - a pin roots only its own lineage.
//! - Ruling C at `is_canonical` / `is_canonical_effective`: an edition-2 key
//!   (an identity-ref) is canonical exactly when it is in `serve_nodes` of
//!   every bundle in force. A seat a later bundle drops is not canonical.
//!   With no bundle held, no edition-2 key is canonical.

use std::collections::BTreeSet;

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::{verify_object_statement, Digest32, ObjectVerdict};

use super::door_invariants::fixture::*;
use super::genesis::{
    bundles_in_force, put_genesis_bundle, BundleContext, CountRule, GENESIS_BUNDLE_TYP,
};
use super::genesis_invariants::voice_over;
use super::ingest::{put_statement, INGEST_TIER};
use super::names::RowId;
use super::store::HeldObject;
use crate::federation::{malformed_row, Error, FederationDirectory};

fn bundle_payload(
    version: u64,
    prev: Option<&Digest32>,
    holders: &[String],
    seats: &[String],
) -> Value {
    let h: Vec<&str> = holders.iter().map(String::as_str).collect();
    let s: Vec<&str> = seats.iter().map(String::as_str).collect();
    let mut m = vec![
        ("version", Value::Uint(version)),
        ("asserted_at", Value::Uint(1_000 * version)),
        ("holders", text_set(&h)),
        ("serve_nodes", text_set(&s)),
    ];
    if let Some(p) = prev {
        m.push(("refs", map(vec![("prev", ref2(p))])));
    }
    map(m)
}

/// Hold a bundle's voices directly (the door refuses until Verify's reader).
async fn hold(d: &dyn FederationDirectory, ks: &[CompositeSigningKey], payload: &Value) -> RowId {
    let held = holding(&ks.iter().collect::<Vec<_>>());
    let iat = payload
        .get_text("asserted_at")
        .and_then(Value::as_u64)
        .unwrap()
        / 1000;
    let mut id = None;
    for k in ks {
        let v = voice_over(k, payload, Some(iat));
        let ObjectVerdict::Valid(o) = verify_object_statement(&v, &held) else {
            panic!("fixture voice");
        };
        id = Some(RowId(o.object_id));
        d.put_edition2_object(&HeldObject {
            object_id: RowId(o.object_id),
            statement_id: o.statement_id,
            typ: o.typ,
            kid: o.kid,
            iss: o.iss,
            bytes: v,
        })
        .await
        .unwrap();
    }
    id.unwrap()
}

pub(crate) async fn body(d: &dyn FederationDirectory) {
    let hs = [key(70), key(71), key(72)];
    let seat = key(73);
    let seat2 = key(74);
    let hrefs: Vec<String> = hs.iter().map(iref).collect();
    let canonical = |k: &CompositeSigningKey| {
        let r = iref(k);
        async move {
            crate::federation::admission::is_canonical_effective(d, &r)
                .await
                .unwrap()
        }
    };
    assert!(
        !canonical(&seat).await,
        "I1911: no bundle held, no canonical"
    );

    // The door: generic rules hold, placement waits on Verify's reader.
    for k in &hs {
        put_statement(
            d,
            &key_record(k, &["accord_holder"], 0, None),
            None,
            INGEST_TIER,
        )
        .await
        .unwrap();
    }
    let p1 = bundle_payload(1, None, &hrefs, &[iref(&seat)]);
    let voices: Vec<Vec<u8>> = hs.iter().map(|k| voice_over(k, &p1, Some(1))).collect();
    let r: BTreeSet<Digest32> = hs.iter().map(kid).collect();
    let none = BTreeSet::new();
    let e = put_genesis_bundle(
        d,
        &voices,
        &BundleContext {
            roster: &r,
            count: CountRule::Every,
            must_sign: &none,
            pin: None,
            predecessor: None,
        },
    )
    .await
    .unwrap_err();
    assert!(
        matches!(&e, Error::MalformedRow { reason, .. } if *reason == malformed_row::GENESIS_BUNDLE_READER_UNAVAILABLE),
        "I1911: {e:?}"
    );
    assert!(
        d.edition2_objects(GENESIS_BUNDLE_TYP)
            .await
            .unwrap()
            .is_empty(),
        "I1911: the door stored nothing"
    );

    // The lineage: v1, then v2 naming it and dropping the seat for seat2.
    let v1 = hold(d, &hs, &p1).await;
    assert!(canonical(&seat).await, "I1911 C: the seat of v1");
    assert!(!canonical(&seat2).await, "I1911 C: not a seat");
    assert!(!canonical(&hs[0]).await, "I1911 C: a holder is no seat");
    let p2 = bundle_payload(2, Some(&v1.0), &hrefs, &[iref(&seat2)]);
    let v2 = hold(d, &hs, &p2).await;
    let tips = bundles_in_force(d, None).await.unwrap();
    assert_eq!(tips.len(), 1, "I1911: one tip");
    assert_eq!(tips[0].object_id, Some(v2), "I1911: v2 is in force");
    assert!(
        !canonical(&seat).await,
        "I1911 C: dropped by a later bundle"
    );
    assert!(canonical(&seat2).await, "I1911 C: seated by v2");

    // A second fresh genesis: a fork, two tips; only what both name counts.
    let other = [key(75), key(76), key(77)];
    let orefs: Vec<String> = other.iter().map(iref).collect();
    let f1 = hold(d, &other, &bundle_payload(1, None, &orefs, &[iref(&seat2)])).await;
    assert_eq!(
        bundles_in_force(d, None).await.unwrap().len(),
        2,
        "I1911: fork"
    );
    assert!(canonical(&seat2).await, "I1911: both tips seat it");
    let f2 = hold(
        d,
        &other,
        &bundle_payload(2, Some(&f1.0), &orefs, &[iref(&seat)]),
    )
    .await;
    assert!(!canonical(&seat2).await, "I1911: one tip drops it");
    // A pin roots only its lineage.
    let pinned = bundles_in_force(d, Some(&f1.0)).await.unwrap();
    assert_eq!(pinned.len(), 1);
    assert_eq!(pinned[0].object_id, Some(f2), "I1911: pinned lineage");
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i1911_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.conn_handle()
        .lock()
        .execute_batch(super::store::SQLITE_DDL)
        .unwrap();
    Box::pin(body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i1911_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.pool()
        .get()
        .await
        .unwrap()
        .batch_execute(super::store::POSTGRES_DDL)
        .await
        .unwrap();
    Box::pin(body(&b)).await;
}

/// TODO(verify-bundle-reader): the door end to end, once Verify's bundle
/// reader yields the placement. A bundle the door admits is held and in
/// force, and its seats are canonical.
#[test]
#[ignore = "TODO(verify-bundle-reader): CIRISVerify's bundle reader is not at Verify 23.1.3"]
fn i1911_the_door_holds_a_placed_bundle() {
    unimplemented!("waits on Verify's bundle reader API");
}
