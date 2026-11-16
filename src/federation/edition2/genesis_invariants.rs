//! **I1907**: the genesis bundle's generic rules (CC 2.6.1.11, CC 5.3.4, and
//! the settled bundle/2 rule, CIRISPersist#1274).
//!
//! - The fresh genesis (`version` 1, no `prev`) counts only when every
//!   holder of the roster signed. One holder short, a stranger standing in,
//!   or a holder whose key is not held is `genesis_bundle_count_unmet`, which
//!   concludes nothing and is never a finding against the bundle.
//! - The voices share one object id, computed here (`["CEG-object/2", typ,
//!   null, payload]`). A voice over other payload bytes is another object: it
//!   is not counted and not merged. A pin that differs is
//!   `genesis_bundle_not_pinned`.
//! - `genesis_bundle_malformed` covers:
//!   - `iat` absent or not ⌊asserted_at / 1000⌋ (`iat_mismatch`);
//!   - `version` 1 with a prev, a version other than 1 without one, or a
//!     version not prev's plus one (`version_prev_mismatch`).
//! - A later bundle counts a strict majority of its predecessor's holders,
//!   plus every holder it adds.
//! - A row statement offered as a voice is `edition2_not_a_row`. A JSON
//!   bundle is `earlier_form_object`.
//! - Ruling C: a seat is canonical exactly when its identity-ref is in
//!   `serve_nodes` of the bundle in force. A key in both `holders` and
//!   `serve_nodes` is `holders_seats_overlap`.
//! - A seat's X-Wing keys come from its binding. `transit_xwing_pubkey` and
//!   `onion_hop_xwing_pubkey` are 1216 bytes each, signed by the seat, with
//!   no shared half. The v1 pair, another signer, a short key, a missing
//!   onion key or a shared half is `genesis_bundle_seat_binding`.

use std::collections::BTreeSet;

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::{sig_structure, Digest32};

use super::door::admit_row;
use super::door_invariants::fixture::*;
use super::genesis::{
    group_by_object, seat_xwing_from_binding, verify_bundle, BundleContext, BundleInForce,
    CountRule, GENESIS_BUNDLE_TYP,
};
use super::names::RowId;
use crate::federation::{malformed_row, Error};

/// One holder's voice over a bundle payload `{version, asserted_at, refs?}`,
/// its `iat` derived from `asserted_at`.
pub(crate) fn bundle_voice(
    k: &CompositeSigningKey,
    version: u64,
    prev: Option<&Digest32>,
    asserted_at: u64,
) -> Vec<u8> {
    let mut m = vec![
        ("version", Value::Uint(version)),
        ("asserted_at", Value::Uint(asserted_at)),
    ];
    if let Some(p) = prev {
        m.push(("refs", map(vec![("prev", ref2(p))])));
    }
    voice_over(k, &map(m), Some(asserted_at / 1000))
}

/// One voice over any payload: a `ceg-object-statement` built by hand
/// (Verify publishes the reader, not an object producer).
pub(crate) fn voice_over(k: &CompositeSigningKey, payload: &Value, iat: Option<u64>) -> Vec<u8> {
    let mut claims = vec![(Value::int(1), Value::Text(iref(k)))];
    if let Some(i) = iat {
        claims.push((Value::int(6), Value::Uint(i)));
    }
    claims.push((Value::int(-70003), Value::Uint(2)));
    let protected = cde::encode(&Value::Map(vec![
        (Value::int(1), Value::int(-70100)),
        (Value::int(4), Value::Bytes(kid(k).to_vec())),
        (Value::int(15), Value::Map(claims)),
        (Value::int(16), Value::Text(GENESIS_BUNDLE_TYP.into())),
    ]));
    let payload_bytes = cde::encode(payload);
    let sig = k.sign(&sig_structure(&protected, &payload_bytes)).unwrap();
    cde::encode(&Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(vec![]),
            Value::Bytes(payload_bytes),
            Value::Bytes(sig),
        ])),
    ))
}

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

fn holders() -> [CompositeSigningKey; 3] {
    [key(40), key(41), key(42)]
}

fn roster(ks: &[CompositeSigningKey]) -> BTreeSet<Digest32> {
    ks.iter().map(kid).collect()
}

fn none() -> BTreeSet<Digest32> {
    BTreeSet::new()
}

#[test]
fn i1907_the_fresh_genesis_needs_every_holder() {
    let hs = holders();
    let held = holding(&[&hs[0], &hs[1], &hs[2], &key(43)]);
    let (r, ms) = (roster(&hs), none());
    let cx = BundleContext {
        roster: &r,
        count: CountRule::Every,
        must_sign: &ms,
        pin: None,
        predecessor: None,
    };
    let all: Vec<Vec<u8>> = hs.iter().map(|k| bundle_voice(k, 1, None, 5_000)).collect();
    let b = verify_bundle(&all, &held, &cx).unwrap();
    assert_eq!(
        (b.version, b.prev, b.signed_by.len()),
        (1, None, 3),
        "I1907"
    );
    let pb = super::door::raw_payload(&all[0]).unwrap();
    assert_eq!(
        b.object_id,
        RowId::of_object(GENESIS_BUNDLE_TYP, None, &pb),
        "I1907"
    );
    assert_eq!(group_by_object(&all).len(), 1, "I1907: one object");
    for (what, voices, h) in [
        ("short", all[..2].to_vec(), held.clone()),
        (
            "stranger",
            vec![
                all[0].clone(),
                all[1].clone(),
                bundle_voice(&key(43), 1, None, 5_000),
            ],
            held.clone(),
        ),
        ("unheld", all.clone(), holding(&[&hs[0], &hs[1]])),
    ] {
        let e = verify_bundle(&voices, &h, &cx).unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::GENESIS_BUNDLE_COUNT_UNMET,
            "I1907 {what}"
        );
    }
}

#[test]
fn i1907_one_payload_one_id_and_the_pin() {
    let hs = holders();
    let held = holding(&[&hs[0], &hs[1], &hs[2]]);
    let (r, ms) = (roster(&hs), none());
    let all: Vec<Vec<u8>> = hs.iter().map(|k| bundle_voice(k, 1, None, 5_000)).collect();
    let free = BundleContext {
        roster: &r,
        count: CountRule::Every,
        must_sign: &ms,
        pin: None,
        predecessor: None,
    };
    let id = verify_bundle(&all, &held, &free).unwrap().object_id;
    // A voice over other bytes is another object: not counted.
    let mut differs = all.clone();
    differs[2] = bundle_voice(&hs[2], 1, None, 6_000);
    assert_eq!(group_by_object(&differs).len(), 2, "I1907");
    let e = verify_bundle(&differs, &held, &free).unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_COUNT_UNMET,
        "I1907 other object"
    );
    let pinned = BundleContext {
        pin: Some(&id.0),
        ..free.clone()
    };
    assert!(verify_bundle(&all, &held, &pinned).is_ok(), "I1907 pin");
    let mut other = id.0;
    other[31] ^= 1;
    let wrong = BundleContext {
        pin: Some(&other),
        ..free.clone()
    };
    let e = verify_bundle(&all, &held, &wrong).unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_NOT_PINNED,
        "I1907"
    );
}

#[test]
fn i1907_iat_is_required_and_derived() {
    let hs = holders();
    let held = holding(&[&hs[0], &hs[1], &hs[2]]);
    let (r, ms) = (roster(&hs), none());
    let cx = BundleContext {
        roster: &r,
        count: CountRule::Every,
        must_sign: &ms,
        pin: None,
        predecessor: None,
    };
    let payload = map(vec![
        ("version", Value::Uint(1)),
        ("asserted_at", Value::Uint(5_999)),
    ]);
    for (what, iat) in [
        ("absent", None),
        ("off by one", Some(6)),
        ("ms not s", Some(5_999)),
    ] {
        let voices: Vec<Vec<u8>> = hs.iter().map(|k| voice_over(k, &payload, iat)).collect();
        let e = verify_bundle(&voices, &held, &cx).unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::GENESIS_BUNDLE_MALFORMED,
            "I1907 iat {what}"
        );
        assert!(message(&e).starts_with("iat_mismatch"), "I1907 iat {what}");
    }
    let voices: Vec<Vec<u8>> = hs
        .iter()
        .map(|k| voice_over(k, &payload, Some(5)))
        .collect();
    assert!(
        verify_bundle(&voices, &held, &cx).is_ok(),
        "I1907 iat = floor"
    );
}

#[test]
fn i1907_version_prev_and_the_later_count() {
    let hs = holders();
    let added = key(46);
    let held = holding(&[&hs[0], &hs[1], &hs[2], &added]);
    let (r, ms) = (roster(&hs), none());
    let every = BundleContext {
        roster: &r,
        count: CountRule::Every,
        must_sign: &ms,
        pin: None,
        predecessor: None,
    };
    let v = |ver, prev: Option<&Digest32>| -> Vec<Vec<u8>> {
        hs.iter()
            .map(|k| bundle_voice(k, ver, prev, 1_000))
            .collect()
    };
    let p: Digest32 = [5; 32];
    for (what, voices) in [("2 no prev", v(2, None)), ("1 with prev", v(1, Some(&p)))] {
        let e = verify_bundle(&voices, &held, &every).unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::GENESIS_BUNDLE_MALFORMED,
            "I1907 {what}"
        );
        assert!(
            message(&e).starts_with("version_prev_mismatch"),
            "I1907 {what}"
        );
    }
    let must = [kid(&added)].into_iter().collect::<BTreeSet<_>>();
    let later = BundleContext {
        roster: &r,
        count: CountRule::StrictMajority,
        must_sign: &none(),
        pin: None,
        predecessor: Some((&p, 1)),
    };
    let two: Vec<Vec<u8>> = hs[..2]
        .iter()
        .map(|k| bundle_voice(k, 2, Some(&p), 1_000))
        .collect();
    assert_eq!(
        verify_bundle(&two, &held, &later).unwrap().prev,
        Some(RowId(p)),
        "I1907 2 of 3"
    );
    let e = verify_bundle(&two[..1], &held, &later).unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_COUNT_UNMET,
        "I1907 1 of 3"
    );
    // An added holder must sign beside the majority.
    let with_added = BundleContext {
        must_sign: &must,
        ..later.clone()
    };
    let e = verify_bundle(&two, &held, &with_added).unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_COUNT_UNMET,
        "I1907 added absent"
    );
    let mut three = two.clone();
    three.push(bundle_voice(&added, 2, Some(&p), 1_000));
    assert!(
        verify_bundle(&three, &held, &with_added).is_ok(),
        "I1907 added signed"
    );
    let skip: Vec<Vec<u8>> = hs[..2]
        .iter()
        .map(|k| bundle_voice(k, 3, Some(&p), 1_000))
        .collect();
    let e = verify_bundle(&skip, &held, &later).unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::GENESIS_BUNDLE_MALFORMED,
        "I1907 skip"
    );
}

#[test]
fn i1907_rows_and_json_are_not_bundles() {
    let hs = holders();
    let held = holding(&[&hs[0], &hs[1], &hs[2]]);
    let (r, ms) = (roster(&hs), none());
    let cx = BundleContext {
        roster: &r,
        count: CountRule::Every,
        must_sign: &ms,
        pin: None,
        predecessor: None,
    };
    let row = row_with_refs(&hs[0], 1, map(vec![("target", ref2(&[1; 32]))]));
    let e = verify_bundle(&[row], &held, &cx).unwrap_err();
    assert_eq!(reason(&e), malformed_row::EDITION2_NOT_A_ROW, "I1907");
    let e = verify_bundle(&[br#"{"version":4}"#.to_vec()], &held, &cx).unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_EARLIER_FORM_OBJECT,
        "I1907"
    );
}

#[test]
fn i1907_ruling_c_canonical_is_membership_in_serve_nodes() {
    let hs = holders();
    let seat = key(47);
    let stranger = key(48);
    let held = holding(&[&hs[0], &hs[1], &hs[2]]);
    let (r, ms) = (roster(&hs), none());
    let cx = BundleContext {
        roster: &r,
        count: CountRule::Every,
        must_sign: &ms,
        pin: None,
        predecessor: None,
    };
    let payload = |hold: Vec<&str>, seats: Vec<&str>| {
        map(vec![
            ("version", Value::Uint(1)),
            ("asserted_at", Value::Uint(2_000)),
            ("holders", text_set(&hold)),
            ("serve_nodes", text_set(&seats)),
        ])
    };
    let hrefs: Vec<String> = hs.iter().map(iref).collect();
    let hr: Vec<&str> = hrefs.iter().map(String::as_str).collect();
    let seat_ref = iref(&seat);
    let p = payload(hr.clone(), vec![&seat_ref]);
    let voices: Vec<Vec<u8>> = hs.iter().map(|k| voice_over(k, &p, Some(2))).collect();
    let b = verify_bundle(&voices, &held, &cx).unwrap();
    let f = BundleInForce::of(&b).unwrap();
    assert!(f.is_canonical(&seat_ref), "I1907 C: the seat");
    assert!(!f.is_canonical(&iref(&stranger)), "I1907 C: not a seat");
    assert!(
        !f.is_canonical(&hrefs[0]),
        "I1907 C: a holder is not a seat"
    );
    // A key both holder and seat.
    let p = payload(hr.clone(), vec![hr[0]]);
    let voices: Vec<Vec<u8>> = hs.iter().map(|k| voice_over(k, &p, Some(2))).collect();
    let e = BundleInForce::of(&verify_bundle(&voices, &held, &cx).unwrap()).unwrap_err();
    assert!(message(&e).starts_with("holders_seats_overlap"), "I1907");
}

fn binding(seat: &CompositeSigningKey, extra: Vec<(&str, Value)>) -> Vec<u8> {
    let mut m = vec![
        ("asserted_at", Value::Uint(10)),
        ("author", Value::Text(iref(seat))),
    ];
    m.extend(extra);
    ciris_verify_core::edition2::sign_row_statement(
        seat,
        &iref(seat),
        &iref(seat),
        "scores",
        "key:revocation",
        &map(m),
        vec![],
    )
    .unwrap()
}

#[test]
fn i1907_a_seats_xwing_keys_come_from_its_binding() {
    let seat = key(44);
    let other = key(45);
    let held = holding(&[&seat, &other]);
    let transit = vec![7u8; 1216];
    let onion = vec![8u8; 1216];
    let admit = |st: Vec<u8>| admit_row(&st, &held, None, SelectContext::default()).unwrap();
    let both = |t: &[u8], o: &[u8]| {
        vec![
            ("transit_xwing_pubkey", Value::Bytes(t.to_vec())),
            ("onion_hop_xwing_pubkey", Value::Bytes(o.to_vec())),
        ]
    };
    let ok = admit(binding(&seat, both(&transit, &onion)));
    let (t, o) = seat_xwing_from_binding(&ok, &kid(&seat)).unwrap();
    assert_eq!(
        (t.to_vec(), o.to_vec()),
        (transit.clone(), onion.clone()),
        "I1907"
    );
    let mut shared_x = onion.clone();
    shared_x[1184..].copy_from_slice(&transit[1184..]);
    let mut v1 = both(&transit, &onion);
    v1.push((
        "transit_kex_pubkeys",
        map(vec![("x25519", Value::Bytes(vec![1; 32]))]),
    ));
    for (what, row, signer) in [
        (
            "other signer",
            admit(binding(&other, both(&transit, &onion))),
            kid(&seat),
        ),
        (
            "short",
            admit(binding(&seat, both(&transit[..1215], &onion))),
            kid(&seat),
        ),
        (
            "no onion",
            admit(binding(
                &seat,
                vec![("transit_xwing_pubkey", Value::Bytes(transit.clone()))],
            )),
            kid(&seat),
        ),
        (
            "shared half",
            admit(binding(&seat, both(&transit, &shared_x))),
            kid(&seat),
        ),
        ("v1 pair", admit(binding(&seat, v1)), kid(&seat)),
    ] {
        let e = seat_xwing_from_binding(&row, &signer).unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::GENESIS_BUNDLE_SEAT_BINDING,
            "I1907 {what}"
        );
    }
}
