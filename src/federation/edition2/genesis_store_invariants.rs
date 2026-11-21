//! **I2390–I2393** (the REAL YubiKey PIV custody chains through the
//! custody path; see `mod real_custody` at the end of this file).
//!
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
//! - I2323 (ceremony gap 4): the genesis import door crosses the capsule
//!   (`PutGenesisBundle`): a bundle every anchored holder signed is placed; one
//!   holder short is `genesis_bundle_count_unmet` and stores nothing; two
//!   first bundles are a fork of the genesis (no tip, `common` null, no
//!   canonical seat); an object-id anchor voids any other genesis
//!   (`genesis_bundle_not_anchored`).

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
    // v62.0.0 (Verify 23.3.1) — Verify's bundle reader reads the binding
    // itself (an occurrence binding with no `device_class` is Invalid in its
    // place) and refuses the bundle `genesis_bundle_row_invalid` before the
    // named rows reach their own doors: refused whole, by the reader's token.
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_ROW_INVALID,
        "I2322: the binding's refusal, read by Verify's bundle reader: {e:?}"
    );
    assert!(message(&e).contains("row_invalid"), "I2322: {e:?}");
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

/// One op through the capsule's wire: the op and its result each cross as
/// serialized bytes (the C-ABI's encoding), dispatched by persist over `d`.
async fn through_capsule(
    d: &dyn FederationDirectory,
    op: crate::ffi::directory_capsule::DirectoryOp,
) -> crate::ffi::directory_capsule::DirectoryOpResult {
    use crate::ffi::directory_capsule::{dispatch_directory_op, DirectoryOp, DirectoryOpResult};
    let op: DirectoryOp = serde_json::from_slice(&serde_json::to_vec(&op).unwrap()).unwrap();
    let r = dispatch_directory_op(d, op).await;
    serde_json::from_slice::<DirectoryOpResult>(&serde_json::to_vec(&r).unwrap())
        .unwrap()
        .into_flattened()
}

/// A vector case's anchor on the wire.
fn wire_anchor(c: &J) -> Option<crate::ffi::directory_capsule::GenesisAnchor> {
    use crate::ffi::directory_capsule::GenesisAnchor;
    anchor(c).map(|a| match a {
        Anchor::Thumbprints(t) => GenesisAnchor::Thumbprints(t.into_iter().collect()),
        Anchor::ObjectId(o) => GenesisAnchor::ObjectId(o),
    })
}

/// `PutGenesisBundle` with a vector case's offer and anchor.
async fn import_case(
    d: &dyn FederationDirectory,
    f: &J,
    id: &str,
) -> crate::ffi::directory_capsule::DirectoryOpResult {
    let c = case(f, id);
    through_capsule(
        d,
        crate::ffi::directory_capsule::DirectoryOp::PutGenesisBundle {
            statements: offered(f, c),
            anchor: wire_anchor(c),
        },
    )
    .await
}

/// **I2323 (ceremony gap 4): the genesis import door crosses the capsule**
/// (`PutGenesisBundle`, the op a Python or capsule host imports a genesis
/// through), on four fresh stores:
/// - `accepted`: a first bundle every anchored holder signed is placed; its
///   tip is in force (and `BundlesInForce` answers it);
/// - `missing`: the same bundle one holder short is refused
///   `genesis_bundle_count_unmet`, and nothing is stored;
/// - `forked`: two first bundles under one thumbprint anchor are both placed,
///   and are a fork of the genesis: no tip is in force, the tips share
///   nothing (`common` null), no seat is canonical;
/// - `voided`: under an object-id anchor only that genesis roots; the other
///   is not placed, `genesis_bundle_not_anchored`.
///
/// A bundle/1 JSON at the op is `earlier_form_object`.
pub(crate) async fn body_capsule(
    accepted: &dyn FederationDirectory,
    missing: &dyn FederationDirectory,
    forked: &dyn FederationDirectory,
    voided: &dyn FederationDirectory,
) {
    use crate::ffi::directory_capsule::{DirectoryOp, DirectoryOpResult};
    register_roots();
    let f = vectors::v2();

    // accepted
    let first = case(f, "first_valid");
    match import_case(accepted, f, "first_valid").await {
        DirectoryOpResult::GenesisAdmission(a) => {
            assert_eq!(a.placed.len(), 1, "I2323 accepted");
            assert_eq!(a.placed[0].object_id, oid(first), "I2323 accepted");
            assert!(a.not_placed.is_empty(), "I2323 accepted");
            assert_eq!(a.tips.len(), 1, "I2323 accepted: in force");
            assert_eq!(a.tips[0].object_id, oid(first), "I2323 accepted");
        }
        other => panic!("I2323 accepted: {other:?}"),
    }
    match through_capsule(accepted, DirectoryOp::BundlesInForce {}).await {
        DirectoryOpResult::BundlesInForce(v) => {
            assert_eq!(v.len(), 1, "I2323 accepted: BundlesInForce");
            assert_eq!(v[0].object_id, oid(first), "I2323 accepted");
        }
        other => panic!("I2323 accepted: {other:?}"),
    }
    match through_capsule(
        accepted,
        DirectoryOp::PutGenesisBundle {
            statements: vec![br#"{"version":4,"family_key_id":"humanity-accord"}"#.to_vec()],
            anchor: None,
        },
    )
    .await
    {
        DirectoryOpResult::Err(e) => assert!(
            e.contains("earlier_form_object"),
            "I2323: a bundle/1 JSON at the op: {e}"
        ),
        other => panic!("I2323 earlier form: {other:?}"),
    }

    // missing
    match import_case(missing, f, "missing_holder_signature").await {
        DirectoryOpResult::Err(e) => assert!(
            e.contains(malformed_row::GENESIS_BUNDLE_COUNT_UNMET),
            "I2323 missing: {e}"
        ),
        other => panic!("I2323 missing: {other:?}"),
    }
    assert_eq!(
        held_voices(missing).await,
        0,
        "I2323 missing: nothing stored"
    );
    assert!(
        !genesis_in_force(missing).await.unwrap().is_held(),
        "I2323 missing: pre-genesis"
    );

    // forked
    let fork = case(f, "fork_of_the_genesis");
    assert!(
        fork["forks"]["common"].is_null(),
        "I2323 forked: Verify's vector says the tips share nothing"
    );
    match import_case(forked, f, "fork_of_the_genesis").await {
        DirectoryOpResult::GenesisAdmission(a) => {
            assert_eq!(a.placed.len(), 2, "I2323 forked: both first bundles placed");
            assert!(a.tips.is_empty(), "I2323 forked: no tip is in force");
        }
        other => panic!("I2323 forked: {other:?}"),
    }
    let g = genesis_in_force(forked).await.unwrap();
    assert!(g.common.is_none(), "I2323 forked: common null");
    assert!(g.head.is_none(), "I2323 forked: no head");
    assert!(
        g.forks
            .iter()
            .any(|k| matches!(k, super::genesis::Fork::Genesis { bundles } if bundles.len() == 2)),
        "I2323 forked: a fork of the genesis: {:?}",
        g.forks
    );
    for p in &g.valid {
        for s in &p.seats {
            assert!(
                !canonical(forked, &s.identity_ref).await,
                "I2323 forked: no seat is canonical on a fork of the genesis"
            );
        }
    }
    match through_capsule(forked, DirectoryOp::BundlesInForce {}).await {
        DirectoryOpResult::BundlesInForce(v) => {
            assert!(v.is_empty(), "I2323 forked: BundlesInForce is empty");
        }
        other => panic!("I2323 forked: {other:?}"),
    }

    // voided
    let void = case(f, "object_id_anchor_voids_the_other");
    let anchored = hex32(void["anchor"]["object_id"].as_str().unwrap());
    match import_case(voided, f, "object_id_anchor_voids_the_other").await {
        DirectoryOpResult::GenesisAdmission(a) => {
            assert_eq!(a.placed.len(), 1, "I2323 voided: only the anchored genesis");
            assert_eq!(a.placed[0].object_id, anchored, "I2323 voided");
            assert_eq!(a.not_placed.len(), 1, "I2323 voided: the other");
            assert_ne!(a.not_placed[0].object_id, anchored, "I2323 voided");
            assert_eq!(
                a.not_placed[0].token,
                malformed_row::GENESIS_BUNDLE_NOT_ANCHORED,
                "I2323 voided"
            );
            assert_eq!(a.tips.len(), 1, "I2323 voided: one genesis in force");
            assert_eq!(a.tips[0].object_id, anchored, "I2323 voided");
        }
        other => panic!("I2323 voided: {other:?}"),
    }
}

/// v62.0.0 (C4-fix, ceremony gap 3; CC 4.2.2.1) — **I2390–I2393: the REAL
/// YubiKey PIV custody evidence crosses the edition-2 custody path.** Every
/// other edition-2 custody fixture is a MOCK 2-cert chain; these witnesses
/// carry the July holders' (A1, B1, C1) real slot-9c leaves and the real
/// 4-cert path `9c → f9 → Yubico PIV Attestation B 1 → Yubico Attestation
/// Intermediate B 1 → Yubico Attestation Root 1`
/// ([`super::fixture_genesis_real_custody`], public material only).
///
/// - I2390 (pure): each fixture certificate is the one its holder's custody
///   envelope committed to, and each holder's chain verifies to Verify's
///   BAKED Yubico root (the only `KeyAttestation` root the baked store
///   resolves for `yubikey-piv`, pinned by its SHA-256) for the holder's own
///   Ed25519 key: `YubiKey_5_FIPS`, firmware 5.7.4, FIPS, touch always, the
///   holder's serial.
/// - I2391 (pure): an edition-2 `key:record` payload over the composite of
///   the holder's July halves, carrying `attestation_evidence` =
///   {`hardware_class`, `pq_custody: removable_offline`, `chain`: four CBOR
///   byte strings, leaf FIRST}, is read by Verify's `check_key_record`
///   (class and `pq_custody` read back, four certificates), and the custody
///   gate's check over it (leaf, the path above, the record key's Ed25519
///   half, the baked root) is `Ok`. The evidence carries no nonce or
///   challenge, and none is asked for: PIV attests at key generation.
/// - I2392 (pure): the shapes the path refuses. A chain of hex TEXT strings,
///   or one hex string, or an empty array, is
///   `key_record_bad_attestation_evidence`; truncated (no `Intermediate B
///   1`), reordered, leaf not first, the leaf alone, or one byte of f9
///   flipped does not verify; `pq_custody: same_element` is read as such
///   (the gate seats only `removable_offline`).
/// - I2393 (sqlite, postgres): through `put_genesis_bundle`, a first bundle
///   whose holder 1 record (signed by its test key) carries the REAL A1
///   chain as CBOR byte strings, leaf first, is refused
///   `genesis_holder_custody` / `custody_attested_key_mismatch`. That detail
///   arises only after the four-cert chain verified to the baked root (the
///   MOCK root answers `ChainInvalid`, which the gate does not report over a
///   root that verified), so the door parsed, walked and rooted the real
///   bytes. Truncated or reordered: `custody_chain_invalid`. As hex text:
///   `genesis_bundle_row_invalid` / `key_record_bad_attestation_evidence`.
///   After each, nothing is stored and the node is still pre-genesis; then
///   the same ceremony with its mock chains is placed (the control).
///
/// v62.0.0 (C4-fix2; CC rc21 ad52eb6, CC 4.2.3 "One device per holder") —
/// **I2394–I2395**:
///
/// The device is keyed on the HARDWARE CLASS and the provenance of the
/// anchor the leaf's chain verifies to, never on a build flag (C4-fix3):
/// the same code runs in every build, and a production store (Verify's
/// baked, vendor-sourced Yubico root only) seats no leaf that would take the
/// fingerprint arm.
///
/// - I2394 (pure): the July leaves name three token serials (A1 38165850,
///   B1 38165563, C1 38165401; extension `1.3.6.1.4.1.41482.3.7`) though
///   they share one f9, and `distinct_devices` passes them; the same leaf
///   twice is `holder_device_shared`; a vendor-rooted YubiKey leaf with no
///   serial, no leaf, or another class is `holder_device_unnamed`; a leaf
///   with no serial reaching only a caller-supplied anchor (the vector /
///   MOCK PKI) is its own device by fingerprint.
/// - I2395 (sqlite, postgres): through `put_genesis_bundle`, a first bundle
///   whose holders 1 and 2 name one serial in DISTINCT leaves, or whose
///   holders 1 and 2 carry ONE leaf (two distinct composite keys sharing
///   their Ed25519 half, which the leaf attests, so both pass custody), is
///   refused `holder_device_shared` and nothing is stored; the same holders
///   with three distinct serials are placed.
///
/// The real July chains cannot be placed through the door (no holder-signed
/// statements exist for the July keys; §3 witness 5), so their distinct
/// serials are witnessed at the judge (I2394), which the door calls.
mod real_custody {
    use super::*;
    use base64::Engine as _;
    use ciris_crypto::composite::{CompositePublicKey, MLDSA65_PK_LEN};
    use ciris_verify_core::accord_custody_attestation::{
        verify_yubikey_piv_attestation, CustodyError, CustodyVerdict,
    };
    use ciris_verify_core::edition2::keys::{check_key_record, KeyRecord, PqCustody};
    use ciris_verify_core::edition2::{cose_key, identity_ref, thumbprint};
    use ciris_verify_core::trust_anchor_store::{baked, environments, Purpose};
    use sha2::{Digest as _, Sha256};

    use super::super::fixture_genesis::{
        ceremony_v2, ceremony_v2_with_holder_evidence, ceremony_v2_with_holders,
        install_ceremony_v2, mock_attestation_root_der, CeremonySpec, HolderOverride,
        TestCeremonyV2,
    };
    use super::super::fixture_genesis_custody::{
        HOLDER_CHAINS_HEX, MALFORMED_SERIAL_CHAIN_HEX, SERIAL_BASE, SERIAL_CHAINS_HEX,
        SHARED_SERIAL_CHAIN_HEX,
    };
    use super::super::fixture_genesis_real_custody::{
        RealHolder, GENESIS_2_SHA256, REAL_CHAIN_HEX, REAL_CHAIN_SHA256, REAL_HOLDERS,
    };
    use super::super::genesis::{
        device_of, distinct_devices, yubikey_serial, DeviceName, HolderDevice,
    };

    const CLASS: &str = "YubiKey_5_FIPS";

    fn der(hex_text: &str) -> Vec<u8> {
        hex::decode(hex_text).expect("fixture hex")
    }

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    fn leaf(h: &RealHolder) -> Vec<u8> {
        der(h.leaf_9c_hex)
    }

    /// `[f9, PIV Attestation B 1, Attestation Intermediate B 1]`.
    fn above() -> Vec<Vec<u8>> {
        REAL_CHAIN_HEX.iter().map(|h| der(h)).collect()
    }

    fn ed(h: &RealHolder) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(h.ed25519_b64)
            .expect("fixture base64")
    }

    /// The composite of the holder's July halves (`ML-DSA-65 ‖ Ed25519`).
    fn composite(h: &RealHolder) -> CompositePublicKey {
        let mldsa = base64::engine::general_purpose::STANDARD
            .decode(h.mldsa65_b64)
            .expect("fixture base64");
        CompositePublicKey::from_halves(&mldsa, &ed(h)).expect("the July halves compose")
    }

    /// Verify's baked Yubico root: the one `KeyAttestation` root the baked
    /// store resolves for `yubikey-piv`, at its pinned SHA-256.
    fn baked_root() -> Vec<u8> {
        let store = baked::default_store();
        let roots = store.resolve_x509(Purpose::KeyAttestation, environments::YUBIKEY_PIV);
        assert_eq!(roots.len(), 1, "the baked store carries one PIV root");
        let root = roots[0].to_vec();
        assert_eq!(sha(&root), baked::YUBICO_ROOT_SHA256, "the pinned root");
        assert_eq!(
            baked::yubico_attestation_root().expect("the baked root loads"),
            root
        );
        root
    }

    fn verify(
        leaf: &[u8],
        above: &[Vec<u8>],
        root: &[u8],
        ed: &[u8],
    ) -> Result<CustodyVerdict, CustodyError> {
        let above: Vec<&[u8]> = above.iter().map(Vec::as_slice).collect();
        verify_yubikey_piv_attestation(leaf, &above, root, ed)
    }

    fn text(s: &str) -> Value {
        Value::Text(s.to_owned())
    }

    /// A deterministic map: entries sorted by their keys' encodings.
    fn map(mut m: Vec<(&str, Value)>) -> Value {
        m.sort_by_key(|(k, _)| cde::encode(&text(k)));
        Value::Map(m.into_iter().map(|(k, v)| (text(k), v)).collect())
    }

    /// `attestation_evidence` with exactly the three members CC 4.2.2.1
    /// names: no nonce, no challenge.
    fn evidence(chain: Value, pq_custody: &str) -> Value {
        map(vec![
            ("hardware_class", text(CLASS)),
            ("pq_custody", text(pq_custody)),
            ("chain", chain),
        ])
    }

    fn bstrs(certs: &[Vec<u8>]) -> Value {
        Value::Array(certs.iter().cloned().map(Value::Bytes).collect())
    }

    /// The leaf-first path as CBOR byte strings: `[9c, f9, B 1, Int B 1]`.
    fn real_chain(h: &RealHolder) -> Vec<Vec<u8>> {
        let mut c = vec![leaf(h)];
        c.extend(above());
        c
    }

    /// An edition-2 `key:record` payload for `key` carrying `ev`.
    fn record_payload(key: &CompositePublicKey, ev: Value) -> Value {
        let iref = identity_ref(&thumbprint(key));
        map(vec![
            ("key", cose_key(key)),
            ("author", text(&iref)),
            ("asserted_at", Value::Uint(1_780_000_000_000)),
            ("identity_type", Value::Array(vec![text("accord_holder")])),
            ("attestation_evidence", ev),
        ])
    }

    /// The custody gate's check over a read record (Verify's `custody_gate`
    /// is private): the leaf, the path above it, the record key's Ed25519
    /// half, against `root`.
    fn gate(rec: &KeyRecord, root: &[u8]) -> Result<CustodyVerdict, CustodyError> {
        let (leaf, above) = rec.chain.split_first().expect("a chain");
        verify(leaf, above, root, &rec.key.as_bytes()[MLDSA65_PK_LEN..])
    }

    /// **I2390** — the fixture is the holders' committed bytes, and each real
    /// 4-cert chain verifies to Verify's baked Yubico root.
    #[test]
    fn i2390_each_real_chain_verifies_to_the_baked_yubico_root() {
        assert_eq!(
            GENESIS_2_SHA256,
            "5c474b7993d0c148336da47fd7958baa0a0840521faaf0c2d534a2df9e766972"
        );
        for (c, pin) in above().iter().zip(REAL_CHAIN_SHA256) {
            assert_eq!(
                sha(c),
                pin,
                "I2390: a chain certificate is its pinned bytes"
            );
        }
        let root = baked_root();
        for h in &REAL_HOLDERS {
            assert_eq!(sha(&leaf(h)), h.leaf_9c_sha256, "I2390: {} leaf", h.name);
            let v = verify(&leaf(h), &above(), &root, &ed(h))
                .unwrap_or_else(|e| panic!("I2390: {} does not verify: {e}", h.name));
            assert_eq!(v.hardware_class, CLASS, "I2390: {}", h.name);
            assert_eq!(v.firmware, "5.7.4", "I2390: {}", h.name);
            assert_eq!(v.serial, Some(h.serial), "I2390: {}", h.name);
            assert!(v.fips_certified && v.touch_always, "I2390: {}", h.name);
        }
    }

    /// **I2391** — the edition-2 `key:record` reads the real evidence (CBOR
    /// byte strings, leaf first), and the gate's check over it passes for the
    /// record's own key. No nonce is carried or needed.
    #[test]
    fn i2391_the_edition2_record_reads_the_real_chain_with_no_nonce() {
        let root = baked_root();
        for h in &REAL_HOLDERS {
            let key = composite(h);
            let ev = evidence(bstrs(&real_chain(h)), "removable_offline");
            assert_eq!(
                ev.as_map().map(<[(Value, Value)]>::len),
                Some(3),
                "I2391: class, pq_custody and chain only: no nonce, no challenge"
            );
            let rec = check_key_record(&record_payload(&key, ev))
                .unwrap_or_else(|e| panic!("I2391: {}: {}", h.name, e.token()));
            assert_eq!(rec.chain.len(), 4, "I2391: {}: leaf + 3", h.name);
            assert_eq!(
                rec.chain[0],
                leaf(h),
                "I2391: {}: the leaf is first",
                h.name
            );
            assert_eq!(rec.hardware_class.as_deref(), Some(CLASS), "I2391");
            assert_eq!(rec.pq_custody, Some(PqCustody::RemovableOffline), "I2391");
            let v = gate(&rec, &root)
                .unwrap_or_else(|e| panic!("I2391: {}: the gate's check: {e}", h.name));
            assert_eq!(v.hardware_class, rec.hardware_class.clone().unwrap());
            assert_eq!(v.serial, Some(h.serial), "I2391: {}", h.name);
        }
    }

    /// **I2392** — the chain shapes the path refuses.
    #[test]
    fn i2392_wrong_chain_shapes_are_refused() {
        let root = baked_root();
        let h = &REAL_HOLDERS[0];
        let key = composite(h);
        let read = |chain: Value| {
            check_key_record(&record_payload(&key, evidence(chain, "removable_offline")))
        };
        let bad = "key_record_bad_attestation_evidence";
        // Hex TEXT: an array of hex strings, or one hex string, or nothing.
        let hex_texts = Value::Array(
            real_chain(h)
                .iter()
                .map(|c| Value::Text(hex::encode(c)))
                .collect(),
        );
        assert_eq!(
            read(hex_texts).unwrap_err().token(),
            bad,
            "I2392: hex text array"
        );
        let one = Value::Text(real_chain(h).iter().map(hex::encode).collect());
        assert_eq!(read(one).unwrap_err().token(), bad, "I2392: one hex string");
        assert_eq!(
            read(Value::Array(Vec::new())).unwrap_err().token(),
            bad,
            "I2392: an empty chain"
        );
        // Byte strings, but not the path: each reads, and fails the walk.
        let (leaf9c, path) = (leaf(h), above());
        let chain_invalid = |c: Vec<Vec<u8>>, what: &str| {
            let rec = read(bstrs(&c)).unwrap_or_else(|e| panic!("I2392 {what}: {}", e.token()));
            match gate(&rec, &root) {
                Err(CustodyError::ChainInvalid { .. } | CustodyError::CertParse { .. }) => {}
                other => panic!("I2392 {what}: want a broken chain, got {other:?}"),
            }
        };
        chain_invalid(
            vec![leaf9c.clone(), path[0].clone(), path[1].clone()],
            "truncated (no Intermediate B 1)",
        );
        chain_invalid(
            vec![
                leaf9c.clone(),
                path[0].clone(),
                path[2].clone(),
                path[1].clone(),
            ],
            "reordered",
        );
        chain_invalid(
            vec![
                path[0].clone(),
                leaf9c.clone(),
                path[1].clone(),
                path[2].clone(),
            ],
            "leaf not first",
        );
        chain_invalid(vec![leaf9c.clone()], "the leaf alone");
        let mut flipped = path.clone();
        let mid = flipped[0].len() / 2;
        flipped[0][mid] ^= 0x01;
        let mut c = vec![leaf9c];
        c.extend(flipped);
        chain_invalid(c, "one byte of f9 flipped");
        // pq_custody is read as stated; the gate seats only removable_offline.
        let rec = check_key_record(&record_payload(
            &key,
            evidence(bstrs(&real_chain(h)), "same_element"),
        ))
        .unwrap();
        assert_eq!(rec.pq_custody, Some(PqCustody::SameElement), "I2392");
    }

    /// The holder-1 record carries the REAL A1 evidence; holders 2 and 3 keep
    /// their MOCK chains (their root registered, as the install helper does).
    fn with_holder1(spec: &CeremonySpec, chain: Value) -> TestCeremonyV2 {
        ceremony_v2_with_holder_evidence(
            spec,
            spec.holders[0],
            evidence(chain, "removable_offline"),
        )
    }

    async fn offer(d: &dyn FederationDirectory, t: &TestCeremonyV2) -> Error {
        let mut statements: Vec<Vec<u8>> = t
            .rows_in_put_order()
            .into_iter()
            .map(|r| r.statement.clone())
            .collect();
        statements.extend(t.voices.iter().cloned());
        put_genesis_bundle(d, &statements, Some(&t.anchor()))
            .await
            .expect_err("I2393: the bundle is not placed")
    }

    async fn still_pre_genesis(d: &dyn FederationDirectory, t: &TestCeremonyV2, what: &str) {
        let g = genesis_in_force(d).await.unwrap();
        assert!(
            g.head.is_none() && g.valid.is_empty(),
            "I2393 {what}: pre-genesis"
        );
        assert_eq!(held_voices(d).await, 0, "I2393 {what}: no voice stored");
        assert!(
            d.edition2_voices(&RowId(t.holders[0].record.row_id))
                .await
                .unwrap()
                .is_empty(),
            "I2393 {what}: the holder record is not stored"
        );
        assert!(
            roster_in_force(d, &t.spec.family_key_id)
                .await
                .unwrap()
                .is_none(),
            "I2393 {what}: no halt roster"
        );
    }

    /// **I2393** — the real chain through the bundle door.
    pub(super) async fn body_real_custody(d: &dyn FederationDirectory) {
        add_test_attestation_root(mock_attestation_root_der());
        let spec = CeremonySpec::standard();
        let a1 = &REAL_HOLDERS[0];
        let (leaf9c, path) = (leaf(a1), above());

        let real = with_holder1(&spec, bstrs(&real_chain(a1)));
        let e = offer(d, &real).await;
        assert_eq!(
            reason(&e),
            malformed_row::GENESIS_HOLDER_CUSTODY,
            "I2393: {e:?}"
        );
        assert!(
            message(&e).starts_with("custody_attested_key_mismatch"),
            "I2393: the real chain verified to the baked root and reached the key \
             comparison: {e:?}"
        );
        still_pre_genesis(d, &real, "real chain").await;

        for (what, chain) in [
            (
                "truncated",
                vec![leaf9c.clone(), path[0].clone(), path[1].clone()],
            ),
            (
                "reordered",
                vec![
                    leaf9c.clone(),
                    path[0].clone(),
                    path[2].clone(),
                    path[1].clone(),
                ],
            ),
        ] {
            let t = with_holder1(&spec, bstrs(&chain));
            let e = offer(d, &t).await;
            assert_eq!(
                reason(&e),
                malformed_row::GENESIS_HOLDER_CUSTODY,
                "I2393 {what}: {e:?}"
            );
            assert!(
                message(&e).starts_with("custody_chain_invalid"),
                "I2393 {what}: {e:?}"
            );
            still_pre_genesis(d, &t, what).await;
        }

        let hex_texts = Value::Array(
            real_chain(a1)
                .iter()
                .map(|c| Value::Text(hex::encode(c)))
                .collect(),
        );
        let t = with_holder1(&spec, hex_texts);
        let e = offer(d, &t).await;
        assert_eq!(
            reason(&e),
            malformed_row::GENESIS_BUNDLE_ROW_INVALID,
            "I2393 hex text: {e:?}"
        );
        assert!(
            message(&e).starts_with("key_record_bad_attestation_evidence"),
            "I2393 hex text: {e:?}"
        );
        still_pre_genesis(d, &t, "hex text").await;

        // The control: the same ceremony with every holder's MOCK chain is
        // placed, so each refusal above is the chain's.
        let control = ceremony_v2(&spec);
        install_ceremony_v2(d, &control)
            .await
            .unwrap_or_else(|e| panic!("I2393 control: {e:?}"));
        assert!(
            genesis_in_force(d).await.unwrap().head.is_some(),
            "I2393 control: placed"
        );
    }

    /// A MOCK chain from a `(seed, [leaf, f9])` table.
    fn mock_chain(table: &[(u8, [&str; 2])], seed: u8) -> Vec<Vec<u8>> {
        table
            .iter()
            .find(|(n, _)| *n == seed)
            .map(|(_, c)| c.iter().map(|h| der(h)).collect())
            .unwrap_or_else(|| panic!("no mock chain for seed {seed}"))
    }

    /// A holder whose `YubiKey_5_FIPS` leaf is judged by [`device_of`].
    fn device<'a>(iref: &'a str, leaf: Option<&Vec<u8>>, vendor_rooted: bool) -> HolderDevice<'a> {
        HolderDevice {
            identity_ref: iref,
            device: device_of(CLASS, leaf.map(Vec::as_slice), vendor_rooted),
        }
    }

    /// `distinct_devices`' refusal over `hs`: (reason, message).
    fn refusal(hs: &[HolderDevice<'_>]) -> (&'static str, String) {
        let e = distinct_devices("b", hs).unwrap_err();
        (reason(&e), message(&e))
    }

    /// **I2394** — one device per holder, at the judge, keyed on the hardware
    /// class and the anchor's provenance (no build flag).
    #[test]
    fn i2394_one_device_per_holder_at_the_judge() {
        let leaves: Vec<Vec<u8>> = REAL_HOLDERS.iter().map(leaf).collect();
        let serials: Vec<Option<u64>> = leaves.iter().map(|l| yubikey_serial(l)).collect();
        assert_eq!(
            serials,
            vec![Some(38_165_850), Some(38_165_563), Some(38_165_401)],
            "I2394: A1, B1, C1 name three serials"
        );
        for (h, s) in REAL_HOLDERS.iter().zip(&serials) {
            assert_eq!(*s, Some(u64::from(h.serial)), "I2394: {}", h.name);
        }
        // Vendor-rooted (the baked Yubico root): the device is the serial.
        // The three share one f9 (the fixture carries one chain) and pass.
        let real: Vec<HolderDevice<'_>> = REAL_HOLDERS
            .iter()
            .zip(&leaves)
            .map(|(h, l)| device(h.name, Some(l), true))
            .collect();
        for (d, s) in real.iter().zip(&serials) {
            assert_eq!(d.device, s.map(DeviceName::Serial), "I2394: the serial");
        }
        distinct_devices("b", &real).expect("I2394: three devices");
        let twice = [
            device("A1", Some(&leaves[0]), true),
            device("X", Some(&leaves[0]), true),
        ];
        let (r, m) = refusal(&twice);
        assert_eq!(r, malformed_row::HOLDER_DEVICE_SHARED, "I2394: {m}");
        assert!(m.contains("38165850"), "I2394: names the serial: {m}");
        // A leaf naming a serial is that serial whatever its anchor.
        assert_eq!(
            device("A1", Some(&leaves[0]), false).device,
            Some(DeviceName::Serial(38_165_850))
        );
        // A YubiKey leaf naming NO serial: vendor-rooted, it names no device
        // (what a production store sees); reaching only a caller-supplied
        // anchor (the vector / MOCK PKI), it is its own device by fingerprint.
        let m1 = mock_chain(&HOLDER_CHAINS_HEX, 1);
        let m2 = mock_chain(&HOLDER_CHAINS_HEX, 2);
        assert_eq!(
            yubikey_serial(&m1[0]),
            None,
            "I2394: the vector PKI's leaves carry no serial"
        );
        let (r, _) = refusal(&[device("1", Some(&m1[0]), true)]);
        assert_eq!(
            r,
            malformed_row::HOLDER_DEVICE_UNNAMED,
            "I2394: vendor-rooted, no serial"
        );
        assert!(matches!(
            device("1", Some(&m1[0]), false).device,
            Some(DeviceName::LeafFingerprint(_))
        ));
        distinct_devices(
            "b",
            &[
                device("1", Some(&m1[0]), false),
                device("2", Some(&m2[0]), false),
            ],
        )
        .expect("I2394: two mock leaves, two devices");
        let (r, _) = refusal(&[
            device("1", Some(&m1[0]), false),
            device("2", Some(&m1[0]), false),
        ]);
        assert_eq!(
            r,
            malformed_row::HOLDER_DEVICE_SHARED,
            "I2394: one mock leaf twice"
        );
        // No leaf, or a class that names no device: unnamed.
        let (r, _) = refusal(&[device("1", None, false)]);
        assert_eq!(r, malformed_row::HOLDER_DEVICE_UNNAMED, "I2394: no leaf");
        for class in ["TPM_2_0", "Apple_Secure_Enclave", "MOCK"] {
            assert_eq!(
                device_of(class, Some(leaves[0].as_slice()), true),
                None,
                "I2394: {class}"
            );
        }
        // The serial-bearing mock leaves read back; the shared one names 1's.
        for n in 1..=3u8 {
            let c = mock_chain(&SERIAL_CHAINS_HEX, n);
            assert_eq!(
                yubikey_serial(&c[0]),
                Some(SERIAL_BASE + u64::from(n)),
                "I2394"
            );
        }
        assert_eq!(
            yubikey_serial(&der(SHARED_SERIAL_CHAIN_HEX[0])),
            Some(SERIAL_BASE + 1),
            "I2394: the shared-serial leaf"
        );
        // Bytes that are not a certificate name nothing.
        assert_eq!(
            yubikey_serial(&leaves[0][..40]),
            None,
            "I2394: a truncated leaf"
        );
        assert_eq!(yubikey_serial(&[]), None);
    }

    /// **I2172** (VA-custody; CIRISVerify 23.3.3) — a leaf whose serial
    /// extension is no DER INTEGER is refused by the judge, not read as "no
    /// serial": Verify's `CustodyError::SerialMalformed` ("the 9c serial
    /// extension is not a DER INTEGER fitting u32"). Compared by the error's
    /// text, so it COMPILES on 23.3.2 too, where the leaf verifies (serial
    /// `None`): ignored until VA-repin, which deletes the `#[ignore]`.
    #[test]
    #[ignore = "VA-repin: green on CIRISVerify 23.3.3 only (custody_serial_malformed); the re-pin deletes this ignore"]
    fn i2172_a_malformed_serial_extension_is_refused_by_the_judge() {
        let chain: Vec<Vec<u8>> = MALFORMED_SERIAL_CHAIN_HEX.iter().map(|h| der(h)).collect();
        // Holder 1's Ed25519 half: seed [101; 32] (the generator's `ed_pub(1)`).
        let ed = {
            use ciris_crypto::ClassicalSigner as _;
            ciris_crypto::Ed25519Signer::from_seed(&[101; 32])
                .expect("I2172: an Ed25519 seed")
                .public_key()
                .expect("I2172: the public key")
        };
        let e = verify(&chain[0], &chain[1..], &mock_attestation_root_der(), &ed)
            .expect_err("I2172: a malformed serial extension is refused");
        assert!(
            e.to_string()
                .contains("serial extension is not a DER INTEGER"),
            "I2172: refused as a malformed serial, by name: {e}"
        );
        // The persist reader names no device from it (never a serial).
        assert_eq!(yubikey_serial(&chain[0]), None, "I2172: no serial read");
    }

    /// **I2173** (VA-custody; sqlite, postgres; CIRISVerify 23.3.3) —
    /// through `put_genesis_bundle`, a first bundle whose holder 1 carries the
    /// malformed-serial chain is refused `genesis_holder_custody` /
    /// `custody_serial_malformed` and nothing is stored. Ignored until
    /// VA-repin (on 23.3.2 the bundle is placed).
    pub(super) async fn body_malformed_serial(d: &dyn FederationDirectory) {
        add_test_attestation_root(mock_attestation_root_der());
        let spec = CeremonySpec::standard();
        let chain: Vec<Vec<u8>> = MALFORMED_SERIAL_CHAIN_HEX.iter().map(|h| der(h)).collect();
        let t = with_holder1(&spec, bstrs(&chain));
        let e = offer(d, &t).await;
        assert_eq!(
            reason(&e),
            malformed_row::GENESIS_HOLDER_CUSTODY,
            "I2173: {e:?}"
        );
        assert!(
            message(&e).starts_with("custody_serial_malformed"),
            "I2173: refused by name: {e:?}"
        );
        still_pre_genesis(d, &t, "malformed serial").await;
    }

    fn holder(seed: u8, mldsa: u8, ed: u8, chain: Vec<Vec<u8>>) -> HolderOverride {
        HolderOverride {
            seed,
            mldsa_seed: [mldsa; 32],
            ed25519_seed: [ed; 32],
            evidence: evidence(bstrs(&chain), "removable_offline"),
        }
    }

    /// **I2395** — one device per holder, through the bundle door.
    pub(super) async fn body_one_device(d: &dyn FederationDirectory) {
        add_test_attestation_root(mock_attestation_root_der());
        let spec = CeremonySpec::standard();
        let serial = |n: u8| holder(n, n, n + 100, mock_chain(&SERIAL_CHAINS_HEX, n));

        // Holders 1 and 2 name one serial in two distinct leaves.
        let shared_chain: Vec<Vec<u8>> = SHARED_SERIAL_CHAIN_HEX.iter().map(|h| der(h)).collect();
        let t = ceremony_v2_with_holders(
            &spec,
            &[serial(1), holder(2, 2, 102, shared_chain), serial(3)],
        );
        let e = offer(d, &t).await;
        assert_eq!(
            reason(&e),
            malformed_row::HOLDER_DEVICE_SHARED,
            "I2395 serial: {e:?}"
        );
        assert!(
            message(&e).contains(&format!("YubiKey serial {}", SERIAL_BASE + 1)),
            "I2395 serial: {e:?}"
        );
        still_pre_genesis(d, &t, "one serial").await;

        // Holders 1 and 2 carry ONE leaf: holder 2's key shares holder 1's
        // Ed25519 half (seed 101), so the leaf attests both and both pass
        // custody; only the device rule refuses the seat.
        let t = ceremony_v2_with_holders(
            &spec,
            &[holder(2, 2, 101, mock_chain(&HOLDER_CHAINS_HEX, 1))],
        );
        let e = offer(d, &t).await;
        assert_eq!(
            reason(&e),
            malformed_row::HOLDER_DEVICE_SHARED,
            "I2395 leaf: {e:?}"
        );
        still_pre_genesis(d, &t, "one leaf").await;

        // Three serials: placed.
        let t = ceremony_v2_with_holders(&spec, &[serial(1), serial(2), serial(3)]);
        install_ceremony_v2(d, &t)
            .await
            .unwrap_or_else(|e| panic!("I2395 three serials: {e:?}"));
        assert!(
            genesis_in_force(d).await.unwrap().head.is_some(),
            "I2395: placed"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2395_sqlite() {
    let d = sqlite().await;
    Box::pin(real_custody::body_one_device(&d)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
#[ignore = "VA-repin: green on CIRISVerify 23.3.3 only (custody_serial_malformed); the re-pin deletes this ignore"]
async fn i2173_sqlite() {
    let d = sqlite().await;
    Box::pin(real_custody::body_malformed_serial(&d)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
#[ignore = "VA-repin: green on CIRISVerify 23.3.3 only (custody_serial_malformed); the re-pin deletes this ignore"]
async fn i2173_postgres() {
    let Some(d) = postgres().await else {
        return;
    };
    Box::pin(real_custody::body_malformed_serial(&d)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2395_postgres() {
    let Some(d) = postgres().await else {
        return;
    };
    Box::pin(real_custody::body_one_device(&d)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2323_genesis_import_crosses_the_capsule_sqlite() {
    let (a, b, c, d) = (
        sqlite().await,
        sqlite().await,
        sqlite().await,
        sqlite().await,
    );
    Box::pin(body_capsule(&a, &b, &c, &d)).await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2393_sqlite() {
    let d = sqlite().await;
    Box::pin(real_custody::body_real_custody(&d)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2323_genesis_import_crosses_the_capsule_postgres() {
    let (Some(a), Some(b), Some(c), Some(d)) = (
        postgres().await,
        postgres().await,
        postgres().await,
        postgres().await,
    ) else {
        return;
    };
    Box::pin(body_capsule(&a, &b, &c, &d)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2393_postgres() {
    let Some(d) = postgres().await else {
        return;
    };
    Box::pin(real_custody::body_real_custody(&d)).await;
}
