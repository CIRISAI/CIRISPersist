//! **I2310–I2320**: the genesis door, the genesis in force, canonical
//! standing under ruling C and the accord's halt roster, on sqlite and
//! postgres, over CIRISVerify 23.3.1's vectors (bundles v3, reseat v2)
//! (`tests/vectors/verify_v23/genesis/`, pinned by I2300).
//!
//! - I2310: a fresh node is pre-genesis. Nothing is in force, no key is
//!   canonical, nothing is served, and the halt roster is not held, so a
//!   halt WAITS.
//! - I2311: a JSON bundle (the earlier form) at `put_genesis_bundle` is
//!   `earlier_form_object`; rows alone are `genesis_bundle_malformed`
//!   (`no_voice`). Nothing is stored.
//! - I2312: the first bundle with no anchor is `genesis_bundle_not_anchored`
//!   and roots nothing; its rows are not stored either.
//! - I2313: the first bundle without its named rows WAITS (the retryable
//!   unknown-signer error), and nothing is stored.
//! - I2314: the first bundle with its rows and the anchor is placed:
//!   - its voices and named rows are held, and each seat binding is in the
//!     occurrence table;
//!   - its seats are canonical (`is_canonical_effective`), its holders are
//!     not;
//!   - the halt roster of its accord holds each holder at its placed key,
//!     and no other accord has one;
//!   - re-offering it is idempotent.
//! - I2315: a later bundle short of a strict majority is
//!   `genesis_bundle_count_unmet`: it concludes nothing, and the bundle in
//!   force is unchanged.
//! - I2316: a counted later bundle (no anchor needed) becomes the head, and
//!   canonical standing follows its seats.
//! - I2317: what the node serves (`genesis_statements`) reproduces the
//!   lineage on a fresh node rooted by the first bundle's object id. With no
//!   anchor it roots nothing there.
//! - I2318: two counted successors of one bundle are a fork, held as tips.
//!   Only the seats and holders common to both count.
//! - I2319: a recovery (one statement under the committed recovery key)
//!   re-seats only its holder: the halt roster holds that holder at the new
//!   key and no longer at the old one.
//! - I2321: the genesis posture reads the bundle in force: `pre_genesis` at
//!   the roster leg on a fresh node (and `require_constitutional_root`
//!   refuses `federation_no_constitutional_root_yet`); `entrenched` once the
//!   first bundle is placed (and the chokepoint passes).
//! - I2322: a named row is the same row inside a bundle and alone (CC ruling
//!   (a)). A first bundle whose seat binding lacks `device_class` (required
//!   on every `identity:occurrence` payload, CC 3.3.6) is Valid to Verify's
//!   reader, and refused whole at the door under the row's own token,
//!   `edition2_payload_invalid`: no voice and no named row is stored.
//! - I2320: a re-seat: a binding the placed key did not sign is
//!   `genesis_bundle_row_invalid` (`row_signer`), and nothing is stored. The
//!   import is ONE transaction: the counted re-seat with a fault injected
//!   after every write and before the commit leaves NOTHING (no voice, no
//!   named row, no key read model, no occurrence row; the bundle in force
//!   unchanged). The
//!   counted re-seat keeps the seat canonical under its identity-ref, at the
//!   new key.

use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::accord_halt::HaltRoster;
use ciris_verify_core::edition2::{identity_ref_thumbprint, Digest32, KeyDirectory, KeyLookup};
use serde_json::Value as J;

use super::genesis::{
    add_test_attestation_root, bundle_seats_in_force, genesis_in_force, genesis_statements,
    is_canonical_by_bundle, put_genesis_bundle, put_genesis_bundle_with, Anchor, WriteFault,
    GENESIS_BUNDLE_TYP,
};
use super::genesis_invariants::vectors::{self, anchor, case, hex32, offered, rows, statements};
use super::halt::roster_in_force;
use super::liveness::{BundleSeats, Seat};
use super::names::RowId;
use crate::federation::{malformed_row, Error, FederationDirectory};

fn reason(e: &Error) -> &'static str {
    match e {
        Error::MalformedRow { reason, .. } => reason,
        other => other.kind(),
    }
}

fn message(e: &Error) -> String {
    match e {
        Error::MalformedRow { message, .. } => message.clone(),
        other => format!("{other:?}"),
    }
}

fn expect0(c: &J) -> &J {
    &c["expect"][0]
}

fn oid(c: &J) -> Digest32 {
    hex32(expect0(c)["object_id"].as_str().unwrap())
}

fn irefs(c: &J, member: &str) -> Vec<String> {
    expect0(c)["placement"][member]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["identity_ref"].as_str().unwrap().to_owned())
        .collect()
}

fn holder_kids(c: &J) -> Vec<(String, Digest32)> {
    expect0(c)["placement"]["holders"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["identity_ref"].as_str().unwrap().to_owned(),
                hex32(x["kid"].as_str().unwrap()),
            )
        })
        .collect()
}

/// Does the roster place `kid` for the holder `iref` (its key-of-issuer
/// answer)? Verify's `HaltRoster` keeps its lookup private; this reads it
/// through `KeyDirectory`.
fn places(roster: &HaltRoster, kid: &Digest32, iref: &str) -> bool {
    let iss = identity_ref_thumbprint(iref).unwrap();
    matches!(roster.lookup(kid, 0), KeyLookup::Held(_))
        && matches!(
            roster.key_of(kid, &iss),
            ciris_verify_core::edition2::KeyOf::Yes
        )
}

fn holds_kid(roster: &HaltRoster, kid: &Digest32) -> bool {
    matches!(roster.lookup(kid, 0), KeyLookup::Held(_))
}

async fn canonical(d: &dyn FederationDirectory, iref: &str) -> bool {
    let by_bundle = is_canonical_by_bundle(d, iref).await.unwrap();
    let effective = crate::federation::admission::is_canonical_effective(d, iref)
        .await
        .unwrap();
    assert_eq!(by_bundle, effective, "ruling C reads one fold: {iref}");
    by_bundle
}

async fn held_voices(d: &dyn FederationDirectory) -> usize {
    d.edition2_objects(GENESIS_BUNDLE_TYP).await.unwrap().len()
}

fn register_roots() {
    add_test_attestation_root(vectors::root_der(vectors::v2()));
    add_test_attestation_root(vectors::root_der(vectors::reseat()));
}

/// Place a case's offer (bundles and rows) under its own anchor.
async fn place(d: &dyn FederationDirectory, f: &J, id: &str) {
    let c = case(f, id);
    let a = anchor(c);
    let out = put_genesis_bundle(d, &offered(f, c), a.as_ref())
        .await
        .unwrap_or_else(|e| panic!("{id}: {e:?}"));
    assert!(!out.placed.is_empty(), "{id}: placed");
}

/// The test key of a vector party, by its identity-ref (Verify's rule: key
/// n is ML-DSA-65 seed [n; 32], Ed25519 seed [n + 100; 32], the door
/// fixtures' `key(n)`).
fn party_key(f: &J, iref: &str) -> ciris_crypto::composite::CompositeSigningKey {
    let n = f["parties"]
        .as_object()
        .unwrap()
        .values()
        .find(|p| p["iss"] == iref)
        .unwrap_or_else(|| panic!("no party {iref}"))["n"]
        .as_u64()
        .unwrap();
    super::door_invariants::fixture::key(u8::try_from(n).unwrap())
}

/// `v` with every byte string equal to `old` replaced by `new`, and every
/// array of arrays (a `refs` set) re-sorted in CDE order.
fn recite(v: &Value, old: &Digest32, new: &Digest32) -> Value {
    match v {
        Value::Bytes(b) if b.as_slice() == old.as_slice() => Value::Bytes(new.to_vec()),
        Value::Map(m) => Value::Map(
            m.iter()
                .map(|(k, x)| (k.clone(), recite(x, old, new)))
                .collect(),
        ),
        Value::Array(a) => {
            let mut out: Vec<Value> = a.iter().map(|x| recite(x, old, new)).collect();
            if !out.is_empty() && out.iter().all(|x| x.as_array().is_some()) {
                out.sort_by_key(cde::encode);
            }
            Value::Array(out)
        }
        Value::Tag(t, x) => Value::Tag(*t, Box::new(recite(x, old, new))),
        other => other.clone(),
    }
}

/// `first_valid`'s offer with its first seat's binding lacking `member`.
/// Where the vendored binding already lacks it, the vector is the case as
/// is. (Verify 23.3.0's v2 vectors predated CC 3.3.6's occurrence members;
/// 23.3.1's v3 bindings carry all three, so the binding is re-signed.)
/// Otherwise the binding is re-signed by its seat without the member and
/// the bundle re-cited and re-signed by every holder.
fn first_valid_binding_without(f: &J, member: &str) -> Vec<Vec<u8>> {
    let c = case(f, "first_valid");
    let mut rs = rows(f, c);
    let seat = &expect0(c)["placement"]["seats"][0];
    let old_id = hex32(seat["binding"].as_str().unwrap());
    let parts = |b: &[u8]| -> (Value, Value) {
        let Value::Tag(18, inner) = cde::decode(b).unwrap() else {
            panic!("a COSE_Sign1");
        };
        let a = inner.as_array().unwrap();
        (
            cde::decode(a[0].as_bytes().unwrap()).unwrap(),
            cde::decode(a[2].as_bytes().unwrap()).unwrap(),
        )
    };
    let (protected, payload) = parts(&rs[&old_id]);
    let Value::Map(members) = &payload else {
        panic!("a payload map");
    };
    if !members.iter().any(|(k, _)| k.as_text() == Some(member)) {
        return offered(f, c);
    }
    let stripped = Value::Map(
        members
            .iter()
            .filter(|(k, _)| k.as_text() != Some(member))
            .cloned()
            .collect(),
    );
    let text = |v: Option<&Value>| v.and_then(Value::as_text).unwrap().to_owned();
    let cwt = protected.get_int(15).unwrap();
    let new = ciris_verify_core::edition2::sign_row_statement(
        &party_key(f, seat["identity_ref"].as_str().unwrap()),
        &text(cwt.get_int(1)),
        &text(cwt.get_int(2)),
        &text(protected.get_int(-70001)),
        &text(protected.get_int(-70002)),
        &stripped,
        vec![],
    )
    .unwrap();
    let new_id = RowId::of_statement(&new).unwrap().0;
    rs.remove(&old_id);
    rs.insert(new_id, new);
    let (_, bundle) = parts(&statements(f, c)[0]);
    let bundle = recite(&bundle, &old_id, &new_id);
    let iat = bundle
        .get_text("asserted_at")
        .and_then(Value::as_u64)
        .unwrap()
        / 1000;
    let mut out: Vec<Vec<u8>> = irefs(c, "holders")
        .iter()
        .map(|h| super::genesis_invariants::voice_over(&party_key(f, h), &bundle, Some(iat)))
        .collect();
    out.extend(rs.into_values());
    out
}

/// I2322: a bundle naming a row its own door refuses is refused whole.
pub(crate) async fn body_named_rows(d: &dyn FederationDirectory) {
    register_roots();
    let f = vectors::v2();
    let first = case(f, "first_valid");
    let an = anchor(first).unwrap();
    let offer = first_valid_binding_without(f, "device_class");
    let e = put_genesis_bundle(d, &offer, Some(&an)).await.unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I2322: the binding's own refusal: {e:?}"
    );
    // The first missing member is named; at Verify 23.3.1's v3 vectors only
    // `device_class` is missing (re-signed without it).
    assert!(message(&e).contains("identity:occurrence"), "I2322: {e:?}");
    assert_eq!(held_voices(d).await, 0, "I2322: no voice stored");
    for s in &offer {
        if let Some(id) = RowId::of_statement(s) {
            assert!(
                d.edition2_voices(&id).await.unwrap().is_empty(),
                "I2322: no named row stored ({})",
                id.hex()
            );
        }
    }
    assert!(
        !genesis_in_force(d).await.unwrap().is_held(),
        "I2322: still pre-genesis"
    );
}

/// I2310–I2317 on one store, I2317's fresh node on `fresh`.
pub(crate) async fn body(d: &dyn FederationDirectory, fresh: &dyn FederationDirectory) {
    register_roots();
    let f = vectors::v2();
    let first = case(f, "first_valid");
    let first_oid = oid(first);
    let accord = expect0(first)["placement"]["family_key_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let seats = irefs(first, "seats");
    let holders = irefs(first, "holders");
    let an = anchor(first).expect("first_valid carries an anchor");

    // I2310: pre-genesis.
    let g = genesis_in_force(d).await.unwrap();
    assert!(!g.is_held(), "I2310: nothing in force");
    for s in &seats {
        assert!(!canonical(d, s).await, "I2310: no bundle, no canonical");
    }
    assert!(
        roster_in_force(d, &accord).await.unwrap().is_none(),
        "I2310: no roster held: a halt waits"
    );
    assert_eq!(
        bundle_seats_in_force(d).await.unwrap(),
        BundleSeats::not_held(),
        "I2310"
    );
    assert!(
        genesis_statements(d).await.unwrap().is_empty(),
        "I2310: nothing served"
    );
    let posture = crate::federation::genesis::genesis_posture(d).await;
    assert_eq!(posture.as_str(), "pre_genesis", "I2321: {posture:?}");
    assert_eq!(
        posture.leg(),
        Some(crate::federation::genesis::GenesisLeg::Anchor),
        "I2321"
    );
    let e = crate::federation::genesis::require_constitutional_root(d, "witness")
        .await
        .unwrap_err();
    assert_eq!(e.kind(), "federation_no_constitutional_root_yet", "I2321");

    // I2311: the earlier form, and rows alone.
    let e = put_genesis_bundle(
        d,
        &[br#"{"version":4,"family_key_id":"humanity-accord"}"#.to_vec()],
        Some(&an),
    )
    .await
    .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_EARLIER_FORM_OBJECT,
        "I2311: {e:?}"
    );
    let only_rows: Vec<Vec<u8>> = rows(f, first).into_values().collect();
    let e = put_genesis_bundle(d, &only_rows, Some(&an))
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_MALFORMED,
        "I2311: {e:?}"
    );
    assert!(message(&e).starts_with("no_voice"), "I2311: {e:?}");
    assert_eq!(held_voices(d).await, 0, "I2311: nothing stored");

    // I2312: no anchor roots nothing.
    let e = put_genesis_bundle(d, &offered(f, first), None)
        .await
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_NOT_ANCHORED,
        "I2312: {e:?}"
    );
    assert_eq!(held_voices(d).await, 0, "I2312: nothing stored");
    for id in rows(f, first).keys() {
        assert!(
            d.edition2_voices(&RowId(*id)).await.unwrap().is_empty(),
            "I2312: no named row stored"
        );
    }

    // I2313: without its named rows the bundle waits.
    let e = put_genesis_bundle(d, &statements(f, first), Some(&an))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, Error::AttesterKeyUnknown { .. }),
        "I2313: retryable: {e:?}"
    );
    assert_eq!(held_voices(d).await, 0, "I2313: nothing stored");

    // I2314: placed.
    let out = put_genesis_bundle(d, &offered(f, first), Some(&an))
        .await
        .unwrap();
    assert_eq!(out.placed.len(), 1, "I2314");
    assert_eq!(out.placed[0].object_id, first_oid, "I2314");
    assert!(out.not_placed.is_empty(), "I2314");
    let voices = held_voices(d).await;
    assert_eq!(
        voices,
        statements(f, first).len(),
        "I2314: every voice held"
    );
    for id in rows(f, first).keys() {
        assert!(
            !d.edition2_voices(&RowId(*id)).await.unwrap().is_empty(),
            "I2314: the named row {} is held",
            hex::encode(id)
        );
    }
    for s in &seats {
        assert!(canonical(d, s).await, "I2314 C: a seat is canonical");
        assert!(
            !d.list_identity_occurrences_for(s).await.unwrap().is_empty(),
            "I2314: the seat's binding is in the occurrence table"
        );
    }
    for h in &holders {
        assert!(!canonical(d, h).await, "I2314 C: a holder is no seat");
    }
    let roster = roster_in_force(d, &accord)
        .await
        .unwrap()
        .expect("I2314: the roster is held");
    assert_eq!(roster.bundle(), &first_oid, "I2314");
    for (iref, kid) in holder_kids(first) {
        assert!(places(&roster, &kid, &iref), "I2314");
    }
    assert!(
        roster_in_force(d, "another-accord")
            .await
            .unwrap()
            .is_none(),
        "I2314: another accord has no roster here"
    );
    let bs = bundle_seats_in_force(d).await.unwrap();
    for (iref, kid) in holder_kids(first) {
        assert_eq!(bs.seat(&iref, &kid), Seat::Seated, "I2314");
    }
    assert!(
        crate::federation::genesis::genesis_posture(d)
            .await
            .entrenched(),
        "I2321: rooted by the bundle in force"
    );
    crate::federation::genesis::require_constitutional_root(d, "witness")
        .await
        .expect("I2321: the roster is seated");
    let again = put_genesis_bundle(d, &offered(f, first), Some(&an))
        .await
        .unwrap();
    assert_eq!(again.placed.len(), 1, "I2314: idempotent");
    assert_eq!(held_voices(d).await, voices, "I2314: idempotent");

    // I2315: a minority concludes nothing. v62.0.0 (wave GC5; CC 2.6.1.11):
    // it is HELD (its voices kept, its reason recorded), never refused.
    let minority = case(f, "later_minority");
    let out = put_genesis_bundle(d, &offered(f, minority), None)
        .await
        .unwrap();
    assert!(out.placed.is_empty(), "I2315: concludes nothing: {out:?}");
    assert_eq!(
        out.not_placed.first().map(|n| n.token),
        Some(malformed_row::GENESIS_BUNDLE_COUNT_UNMET),
        "I2315: {out:?}"
    );
    assert_eq!(
        super::fold::why_held(d, &RowId(oid(minority)))
            .await
            .unwrap()
            .map(|h| h.reason),
        Some(malformed_row::GENESIS_BUNDLE_COUNT_UNMET.to_owned()),
        "I2315: held, its reason the count"
    );
    assert!(held_voices(d).await > voices, "I2315: its voices are kept");
    let g = genesis_in_force(d).await.unwrap();
    assert_eq!(
        g.head.as_ref().map(|p| p.object_id),
        Some(first_oid),
        "I2315"
    );

    // I2316: the counted later bundle is the head.
    let later = case(f, "later_valid");
    let out = put_genesis_bundle(d, &offered(f, later), None)
        .await
        .unwrap();
    assert_eq!(out.placed[0].object_id, oid(later), "I2316");
    let g = genesis_in_force(d).await.unwrap();
    assert_eq!(
        g.head.as_ref().map(|p| p.object_id),
        Some(oid(later)),
        "I2316: the head"
    );
    assert_eq!(g.valid.len(), 2, "I2316: the lineage");
    let later_seats = irefs(later, "seats");
    for s in &later_seats {
        assert!(canonical(d, s).await, "I2316 C: a seat of the head");
    }
    for s in seats.iter().filter(|s| !later_seats.contains(s)) {
        assert!(!canonical(d, s).await, "I2316 C: dropped by the head");
    }

    // I2317: what is served reproduces the lineage on a fresh node.
    let served = genesis_statements(d).await.unwrap();
    assert!(!served.is_empty(), "I2317");
    let e = put_genesis_bundle(fresh, &served, None).await.unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_NOT_ANCHORED,
        "I2317: no anchor roots nothing: {e:?}"
    );
    assert_eq!(held_voices(fresh).await, 0, "I2317");
    let out = put_genesis_bundle(fresh, &served, Some(&Anchor::ObjectId(first_oid)))
        .await
        .unwrap();
    assert_eq!(out.placed.len(), 2, "I2317: the whole lineage");
    let there = genesis_in_force(fresh).await.unwrap();
    assert_eq!(
        there.head.as_ref().map(|p| p.object_id),
        Some(oid(later)),
        "I2317: the same head"
    );
    for s in &later_seats {
        assert!(canonical(fresh, s).await, "I2317 C");
    }
}

/// I2318–I2320, each on its own store.
pub(crate) async fn body_lineages(
    forked: &dyn FederationDirectory,
    recovered: &dyn FederationDirectory,
    reseated: &dyn FederationDirectory,
) {
    register_roots();
    let f = vectors::v2();

    // I2318: a fork of successors.
    place(forked, f, "first_valid").await;
    let fork = case(f, "fork_of_successors");
    let out = put_genesis_bundle(forked, &offered(f, fork), None)
        .await
        .unwrap();
    assert_eq!(out.placed.len(), 2, "I2318: both successors placed");
    let g = genesis_in_force(forked).await.unwrap();
    assert!(g.head.is_none(), "I2318: no head");
    assert_eq!(g.forks.len(), 1, "I2318: one fork");
    assert_eq!(g.tips().len(), 2, "I2318: two tips");
    let common = &fork["forks"]["common"];
    let strs = |k: &str| -> Vec<String> {
        common[k]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect()
    };
    let common_seats = strs("seats");
    for t in g.tips() {
        for s in &t.seats {
            assert_eq!(
                canonical(forked, &s.identity_ref).await,
                common_seats.contains(&s.identity_ref),
                "I2318 C: only what both tips seat"
            );
        }
    }
    let accord = g.family_key_id().unwrap().to_owned();
    let roster = roster_in_force(forked, &accord).await.unwrap().unwrap();
    let common_holders = strs("holders");
    let held: Vec<String> = g.holders().iter().map(|h| h.identity_ref.clone()).collect();
    assert_eq!(held, common_holders, "I2318: the common holders");
    for h in g.holders() {
        assert!(
            places(&roster, &h.kid, &h.identity_ref),
            "I2318: the roster holds each common holder"
        );
    }

    // I2319: a recovery re-seats its holder alone.
    place(recovered, f, "first_valid").await;
    let first = case(f, "first_valid");
    let rec = case(f, "recovery_valid");
    let out = put_genesis_bundle(recovered, &offered(f, rec), None)
        .await
        .unwrap();
    let who = out.placed[0].recovered.clone().expect("I2319: a recovery");
    let old = holder_kids(first)
        .into_iter()
        .find(|(i, _)| *i == who)
        .unwrap()
        .1;
    let new = holder_kids(rec)
        .into_iter()
        .find(|(i, _)| *i == who)
        .unwrap()
        .1;
    assert_ne!(old, new, "I2319: a new key");
    let accord = out.placed[0].family_key_id.clone();
    let roster = roster_in_force(recovered, &accord).await.unwrap().unwrap();
    assert!(places(&roster, &new, &who), "I2319");
    assert!(!holds_kid(&roster, &old), "I2319: the old key");
    for (iref, kid) in holder_kids(first).into_iter().filter(|(i, _)| *i != who) {
        assert!(places(&roster, &kid, &iref), "I2319: the others unchanged");
    }

    // I2320: a re-seat.
    let r = vectors::reseat();
    place(reseated, r, "first_valid").await;
    let _voices = held_voices(reseated).await;
    let bad = case(r, "reseat_binding_signed_by_old_key");
    // v62.0.0 (wave GC5; CC 2.6.1.11) — a named Invalid row: the bundle is
    // HELD, concluding nothing, never refused.
    let out = put_genesis_bundle(reseated, &offered(r, bad), None)
        .await
        .unwrap();
    assert!(out.placed.is_empty(), "I2320: concludes nothing: {out:?}");
    let n = out.not_placed.first().expect("I2320: not placed");
    assert_eq!(
        n.token,
        malformed_row::GENESIS_BUNDLE_ROW_INVALID,
        "I2320: {out:?}"
    );
    assert_eq!(n.detail.as_deref(), Some("row_signer"), "I2320: {out:?}");
    assert_eq!(
        super::fold::why_held(reseated, &RowId(oid(bad)))
            .await
            .unwrap()
            .map(|h| h.reason),
        Some(malformed_row::GENESIS_BUNDLE_ROW_INVALID.to_owned()),
        "I2320: held"
    );
    assert_eq!(
        genesis_in_force(reseated)
            .await
            .unwrap()
            .head
            .map(|p| p.object_id),
        Some(oid(case(r, "first_valid"))),
        "I2320: the held bundle is not in force"
    );
    let voices = held_voices(reseated).await;
    // The counted re-seat, with the write failing inside its transaction
    // after every row, key read model and voice was written: NOTHING stays.
    let good = case(r, "reseat_seat_new_key");
    let new_kid = hex32(r["parties"]["S1N"]["kid"].as_str().unwrap());
    let s1_iss = r["parties"]["S1"]["iss"].as_str().unwrap();
    let occurrences_before = reseated
        .list_identity_occurrences_for(s1_iss)
        .await
        .unwrap();
    assert!(
        !occurrences_before.is_empty(),
        "I2320: the first bundle's seat binding is in the occurrence table"
    );
    let e = put_genesis_bundle_with(reseated, &offered(r, good), None, WriteFault::BeforeCommit)
        .await
        .unwrap_err();
    assert!(
        message(&e).contains("injected fault before commit"),
        "I2320: the fault is the transaction's, not a gate's: {e:?}"
    );
    assert_eq!(held_voices(reseated).await, voices, "I2320: no voice stays");
    let first_rows = rows(r, case(r, "first_valid"));
    for id in rows(r, good)
        .keys()
        .filter(|id| !first_rows.contains_key(*id))
    {
        assert!(
            reseated
                .edition2_voices(&RowId(*id))
                .await
                .unwrap()
                .is_empty(),
            "I2320: the re-seat's named row {} does not stay",
            hex::encode(id)
        );
    }
    assert!(
        reseated
            .lookup_public_key(&ciris_verify_core::edition2::identity_ref(&new_kid))
            .await
            .unwrap()
            .is_none(),
        "I2320: the new key's read model does not stay"
    );
    assert_eq!(
        reseated
            .list_identity_occurrences_for(s1_iss)
            .await
            .unwrap(),
        occurrences_before,
        "I2320: no occurrence row stays (the re-seat binding's would replace it)"
    );
    assert_eq!(
        genesis_in_force(reseated)
            .await
            .unwrap()
            .head
            .map(|p| p.object_id),
        Some(oid(case(r, "first_valid"))),
        "I2320: the bundle in force is unchanged"
    );
    place(reseated, r, "reseat_seat_new_key").await;
    let s1 = &r["parties"]["S1"];
    let iss = s1["iss"].as_str().unwrap();
    assert!(canonical(reseated, iss).await, "I2320 C: still canonical");
    let g = genesis_in_force(reseated).await.unwrap();
    assert_eq!(g.seat(iss).unwrap().kid, new_kid, "I2320: at the new key");
}

#[cfg(feature = "sqlite")]
async fn sqlite() -> crate::store::sqlite::SqliteBackend {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b
}

#[cfg(feature = "postgres")]
async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
    use crate::store::Backend as _;
    let dsn = crate::test_pg::isolated_dsn()?;
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Some(b)
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2310_to_i2317_sqlite() {
    let (d, fresh) = (sqlite().await, sqlite().await);
    Box::pin(body(&d, &fresh)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2318_to_i2320_sqlite() {
    let (a, b, c) = (sqlite().await, sqlite().await, sqlite().await);
    Box::pin(body_lineages(&a, &b, &c)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2310_to_i2317_postgres() {
    let (Some(d), Some(fresh)) = (postgres().await, postgres().await) else {
        return;
    };
    Box::pin(body(&d, &fresh)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2318_to_i2320_postgres() {
    let (Some(a), Some(b), Some(c)) = (postgres().await, postgres().await, postgres().await) else {
        return;
    };
    Box::pin(body_lineages(&a, &b, &c)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2322_sqlite() {
    let d = sqlite().await;
    Box::pin(body_named_rows(&d)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2322_postgres() {
    let Some(d) = postgres().await else {
        return;
    };
    Box::pin(body_named_rows(&d)).await;
}
