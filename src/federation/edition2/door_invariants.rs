//! The edition-2 door's witnesses (slice E2a, CIRISPersist#1274).
//!
//! - **I1902**: the door refuses an earlier-form object by name. A JSON
//!   object (the CC 8.11 form, the very `SignedAttestation` JSON persist's
//!   earlier doors take), a JSON array, and bytes in no form are each
//!   `earlier_form_object`. A non-row object at a row door is
//!   `edition2_not_a_row`.
//! - **I1903**: an edition-1 `row-ref` anywhere in `refs` is refused
//!   `row_ref_edition_1`, under `target`, `head`, a set member, `also.cites`
//!   and `also.ack`. The refusal is structural: it is the same with the
//!   signer's key held or not.
//! - **I1904**: the row id is node-computed. It equals an independent
//!   recomputation (a hand-built CBOR array, hashed here). It is the same for
//!   two voices over one payload, and differs with any one of type, family,
//!   sub, author and payload. An offered id that differs is refused
//!   `row_id_mismatch`. The names are the `refs` row ids, edition 2 only.
//!   A row cannot name itself: the id hashes the payload that carries its
//!   names.

use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::{self, Value};
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::{
    cose_key, identity_ref, sign_row_statement, thumbprint, Digest32,
};
use sha2::Digest as _;

use super::door::{admit_row, input_form, InputForm};
use super::liveness::HeldKeys;
use super::names::{names_of, RowId};
use crate::federation::{malformed_row, Error};

/// Fixtures shared by the edition-2 witnesses.
pub(crate) mod fixture {
    use super::*;

    /// A deterministic composite key (Verify's vector seed rule).
    pub(crate) fn key(n: u8) -> CompositeSigningKey {
        CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32])
    }

    /// A key's identity reference.
    pub(crate) fn iref(k: &CompositeSigningKey) -> String {
        identity_ref(&thumbprint(k.public_key()))
    }

    /// A key's kid.
    pub(crate) fn kid(k: &CompositeSigningKey) -> Digest32 {
        thumbprint(k.public_key())
    }

    /// `[2, [-16, d]]`.
    pub(crate) fn ref2(d: &Digest32) -> Value {
        ciris_verify_core::edition2::row_ref(d)
    }

    /// `[1, [-16, d]]`: an edition-1 row-ref (Verify 23.3.0 dropped its
    /// `edition2::earlier` builder; the shape is built here).
    pub(crate) fn ref1(d: &Digest32) -> Value {
        Value::Array(vec![
            Value::Uint(1),
            ciris_verify_core::edition2::hash_digest_value(d),
        ])
    }

    fn t(s: &str) -> Value {
        Value::Text(s.into())
    }

    /// A deterministic map: entries sorted by their keys' encodings.
    pub(crate) fn map(mut m: Vec<(&str, Value)>) -> Value {
        m.sort_by_key(|(k, _)| cde::encode(&t(k)));
        Value::Map(m.into_iter().map(|(k, v)| (t(k), v)).collect())
    }

    /// A sorted CBOR set of text.
    pub(crate) fn text_set(xs: &[&str]) -> Value {
        let mut e: Vec<Value> = xs.iter().map(|x| t(x)).collect();
        e.sort_by_key(cde::encode);
        Value::Array(e)
    }

    /// A self-signed `key:record` of `k`, authored by `k`.
    pub(crate) fn key_record(
        k: &CompositeSigningKey,
        roles: &[&str],
        at: u64,
        until: Option<u64>,
    ) -> Vec<u8> {
        let mut m = vec![
            ("key", cose_key(k.public_key())),
            ("identity_type", text_set(roles)),
            ("asserted_at", Value::Uint(at)),
            ("author", t(&iref(k))),
        ];
        if let Some(u) = until {
            m.push(("valid_until", Value::Uint(u)));
        }
        sign_row_statement(
            k,
            &iref(k),
            &iref(k),
            "scores",
            "key:record",
            &map(m),
            vec![],
        )
        .unwrap()
    }

    /// A `key:revocation` of `subject`, signed by `signer`.
    pub(crate) fn revocation(
        signer: &CompositeSigningKey,
        subject: &CompositeSigningKey,
        at: u64,
        revoked_after: Option<u64>,
    ) -> Vec<u8> {
        let mut m = vec![
            ("asserted_at", Value::Uint(at)),
            ("author", t(&iref(signer))),
        ];
        if let Some(b) = revoked_after {
            m.push(("revoked_after", Value::Uint(b)));
        }
        sign_row_statement(
            signer,
            &iref(signer),
            &iref(subject),
            "scores",
            "key:revocation",
            &map(m),
            vec![],
        )
        .unwrap()
    }

    /// An authored `key:revocation`-family row of `k` about itself carrying
    /// `refs` (a family that needs no dimension; the door's rules are
    /// family-agnostic).
    pub(crate) fn row_with_refs(k: &CompositeSigningKey, at: u64, refs: Value) -> Vec<u8> {
        let m = vec![
            ("asserted_at", Value::Uint(at)),
            ("author", t(&iref(k))),
            ("refs", refs),
        ];
        sign_row_statement(
            k,
            &iref(k),
            &iref(k),
            "scores",
            "key:revocation",
            &map(m),
            vec![],
        )
        .unwrap()
    }

    /// A reader holding `k`'s node record from 0 to the bound.
    pub(crate) fn holding(ks: &[&CompositeSigningKey]) -> HeldKeys {
        let mut h = HeldKeys::new();
        for k in ks {
            h.insert_record(key_record(k, &["user"], 0, None)).unwrap();
        }
        h
    }
}

use fixture::*;

fn reason(e: &Error) -> &'static str {
    match e {
        Error::MalformedRow { reason, .. } => reason,
        other => other.kind(),
    }
}

#[test]
fn i1902_earlier_form_objects_are_refused_by_name() {
    let held = holding(&[]);
    let json_attestation = br#"{"attestation":{"attestation_id":"a","attesting_key_id":"k"}}"#;
    for (what, bytes) in [
        ("json object", json_attestation.to_vec()),
        ("json with whitespace", b"  \n{\"a\":1}".to_vec()),
        ("json array", b"[1,2]".to_vec()),
        ("bytes in no form", vec![0x01, 0x02, 0x03]),
        ("empty", vec![]),
    ] {
        let e = admit_row(&bytes, &held, None, SelectContext::default()).unwrap_err();
        assert_eq!(
            reason(&e),
            malformed_row::EDITION2_EARLIER_FORM_OBJECT,
            "I1902 {what}"
        );
    }
    assert_eq!(input_form(b"{}"), InputForm::EarlierForm);
    assert_eq!(input_form(&[0xd2, 0x84]), InputForm::Statement);
    assert_eq!(input_form(&[0xa0]), InputForm::Unrecognized);
}

#[test]
fn i1902_an_object_is_not_a_row() {
    // A genesis-bundle object statement offered at the row door.
    let k = key(3);
    let voice = super::genesis_invariants::bundle_voice(&k, 1, None, 1000);
    let e = admit_row(&voice, &holding(&[&k]), None, SelectContext::default()).unwrap_err();
    assert_eq!(reason(&e), malformed_row::EDITION2_NOT_A_ROW, "I1902");
}

#[test]
fn i1903_edition_one_row_refs_are_refused_wherever_they_stand() {
    let k = key(4);
    let d: Digest32 = [9; 32];
    let e: Digest32 = [10; 32];
    let mut set = vec![ref1(&d), ref2(&e)];
    set.sort_by_key(cde::encode);
    let cases: Vec<(&str, Value)> = vec![
        ("target", map(vec![("target", ref1(&d))])),
        ("head", map(vec![("head", ref1(&d))])),
        (
            "further_heads set",
            map(vec![("further_heads", Value::Array(set.clone()))]),
        ),
        (
            "also.cites",
            map(vec![(
                "also",
                map(vec![("cites", Value::Array(vec![ref1(&d)]))]),
            )]),
        ),
        (
            "also.ack",
            map(vec![(
                "also",
                map(vec![("ack", Value::Array(vec![ref1(&d)]))]),
            )]),
        ),
    ];
    for (what, refs) in cases {
        let st = row_with_refs(&k, 1000, refs);
        // Held or not, the answer is the same: it is structural.
        for held in [holding(&[&k]), holding(&[])] {
            let err = admit_row(&st, &held, None, SelectContext::default()).unwrap_err();
            assert_eq!(
                reason(&err),
                malformed_row::EDITION2_ROW_REF_EDITION_1,
                "I1903 {what}"
            );
        }
    }
    // The same rows naming edition-2 refs pass.
    let ok = row_with_refs(&k, 1000, map(vec![("target", ref2(&d))]));
    let row = admit_row(&ok, &holding(&[&k]), None, SelectContext::default()).unwrap();
    assert_eq!(row.names.len(), 1);
    assert_eq!(row.names[0].role, "target");
    assert_eq!(row.names[0].row, RowId(d));
}

/// The row id, recomputed with a CBOR encoder written here: a definite
/// array of six, the tag-free text and byte heads by hand.
fn independent_row_id(
    row_type: &str,
    family: &str,
    sub: &str,
    author: Option<&str>,
    payload: &[u8],
) -> [u8; 32] {
    fn head(major: u8, n: usize, out: &mut Vec<u8>) {
        let m = major << 5;
        match n {
            0..=23 => out.push(m | n as u8),
            24..=0xff => out.extend([m | 24, n as u8]),
            0x100..=0xffff => {
                out.push(m | 25);
                out.extend((n as u16).to_be_bytes());
            }
            _ => {
                out.push(m | 26);
                out.extend((n as u32).to_be_bytes());
            }
        }
    }
    let mut out = vec![0x86];
    for s in ["CEG-row/2", row_type, family, sub] {
        head(3, s.len(), &mut out);
        out.extend(s.as_bytes());
    }
    match author {
        None => out.push(0xf6),
        Some(a) => {
            head(3, a.len(), &mut out);
            out.extend(a.as_bytes());
        }
    }
    head(2, payload.len(), &mut out);
    out.extend(payload);
    sha2::Sha256::digest(out).into()
}

#[test]
fn i1904_the_row_id_is_node_computed() {
    let k = key(5);
    let st = row_with_refs(&k, 2000, map(vec![("target", ref2(&[1; 32]))]));
    let row = admit_row(&st, &holding(&[&k]), None, SelectContext::default()).unwrap();
    let pb = super::door::raw_payload(&st).unwrap();
    assert_eq!(
        row.row_id.0,
        independent_row_id(
            &row.row_type,
            &row.family,
            &row.sub,
            row.author.as_deref(),
            &pb
        ),
        "I1904: the door's id is SHA-256(CDE([CEG-row/2, type, family, sub, author, payload]))"
    );
    // Each input moves the id.
    let base = independent_row_id("scores", "f", "s", Some("a"), b"p");
    for other in [
        independent_row_id("withdraws", "f", "s", Some("a"), b"p"),
        independent_row_id("scores", "g", "s", Some("a"), b"p"),
        independent_row_id("scores", "f", "t", Some("a"), b"p"),
        independent_row_id("scores", "f", "s", None, b"p"),
        independent_row_id("scores", "f", "s", Some("a"), b"q"),
    ] {
        assert_ne!(base, other, "I1904");
    }
    assert_eq!(
        RowId::of_row("scores", "f", "s", Some("a"), b"p").0,
        base,
        "I1904: RowId::of_row"
    );
}

#[test]
fn i1904_an_offered_id_is_never_used() {
    let k = key(6);
    let st = row_with_refs(&k, 3000, map(vec![("target", ref2(&[2; 32]))]));
    let held = holding(&[&k]);
    let row = admit_row(&st, &held, None, SelectContext::default()).unwrap();
    let mut wrong = row.row_id.0;
    wrong[0] ^= 1;
    let e = admit_row(&st, &held, Some(&wrong), SelectContext::default()).unwrap_err();
    assert_eq!(reason(&e), malformed_row::EDITION2_ROW_ID_MISMATCH, "I1904");
    // A peer offering the row under the id of ANOTHER held row is refused too.
    let other = row_with_refs(&k, 3001, map(vec![("target", ref2(&[2; 32]))]));
    let other = admit_row(&other, &held, None, SelectContext::default()).unwrap();
    let e = admit_row(&st, &held, Some(&other.row_id.0), SelectContext::default()).unwrap_err();
    assert_eq!(reason(&e), malformed_row::EDITION2_ROW_ID_MISMATCH, "I1904");
    assert!(admit_row(&st, &held, Some(&row.row_id.0), SelectContext::default()).is_ok());
}

#[test]
fn i1904_names_come_from_refs_and_a_row_cannot_name_itself() {
    let k = key(7);
    let held = holding(&[&k]);
    let a = admit_row(
        &row_with_refs(&k, 10, map(vec![("target", ref2(&[3; 32]))])),
        &held,
        None,
        SelectContext::default(),
    )
    .unwrap();
    // A second row names the first; its names are exactly that id.
    let b = admit_row(
        &row_with_refs(&k, 11, map(vec![("prev", ref2(&a.row_id.0))])),
        &held,
        None,
        SelectContext::default(),
    )
    .unwrap();
    assert_eq!(names_of(&b.payload).unwrap()[0].row, a.row_id, "I1904");
    // Whatever id a row names, its own id differs (the id hashes the names).
    for n in 0..16u8 {
        let target: Digest32 = [n; 32];
        let r = admit_row(
            &row_with_refs(&k, 12, map(vec![("target", ref2(&target))])),
            &held,
            None,
            SelectContext::default(),
        )
        .unwrap();
        assert!(r.names.iter().all(|nm| nm.row != r.row_id), "I1904");
    }
}
