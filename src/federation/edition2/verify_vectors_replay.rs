//! **I1901** — CIRISVerify 23.1.3's edition-2 row-statement known answers,
//! replayed through persist's door (`tests/vectors/verify_v23/edition2/
//! row_statements_v1.json`, re-pinned from Verify's `23.1.3` tag).
//!
//! What persist asserts, case set by case set:
//! - `valid`: each statement passes [`admit_row`], with the vector's row id,
//!   kid and iss. There are two exceptions:
//!   - `second_voice` fills a role only the vector's stated TEST family model
//!     names. Under CC's vendored model, which the door reads, it is
//!     `edition2_family_invalid` (`iss_not_in_role`). Verify's statement
//!     reader still calls it Valid.
//!   - `counted_with_refs` is author-less in a family the vendored model
//!     names authored: `edition2_family_invalid` (`author_column`).
//!   - `names_earlier_form`, which persist refuses `row_ref_edition_1`.
//!     Verify's reader admits an edition-1 `row-ref`. CC rc20 `0c9e17c` (CC
//!     2.6.1.3, 2.6.1.12) says no row of this form names an object of the
//!     earlier form, and the door holds that.
//! - `refusals`: each Invalid case is refused `edition2_statement_invalid`
//!   with Verify's own reason. The Waiting case is the retryable
//!   unknown-signer error, naming the vector's key.
//! - `key_records`: each payload's end rule, Verify's token, equals the
//!   door's refusal: `key_record_out_of_window`, the typed mixed-set error,
//!   or `edition2_statement_invalid`.
//! - `key_directory`, through persist's [`HeldKeys`]:
//!   - `held_through_chain` and `deep_waiting` agree with Verify, and so
//!     does `record_breaks_end_rule` (Invalid);
//!   - `held_in_part` waits on the key itself: persist never holds a key in
//!     part by an earlier-form commitment (CC 2.6.1.12);
//!   - `after_valid_until` is retryable (waits on the key), not Invalid.
//!     CC 2.4.1.1 says "A row whose signed instant no held record of its key
//!     covers is retryable", and a renewal may revive the key.
//! - `objects`: the header verdicts agree, and persist's object id equals
//!   the vector's.

use std::collections::BTreeMap;

use ciris_crypto::composite::{CompositePublicKey, CompositeSigningKey};
use ciris_verify_core::cde;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::keys::check_key_record;
use ciris_verify_core::edition2::{identity_ref, thumbprint, Digest32, KeyDirectory};
use serde_json::Value as J;

use super::door::{admit_row, key_record_refusal};
use super::liveness::HeldKeys;
use crate::federation::{malformed_row, Error};

const FILE: &str =
    include_str!("../../../tests/vectors/verify_v23/edition2/row_statements_v1.json");

fn key(n: u8) -> CompositeSigningKey {
    CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32])
}

fn dir(seeds: impl IntoIterator<Item = u8>) -> BTreeMap<Digest32, CompositePublicKey> {
    seeds
        .into_iter()
        .map(|n| {
            let k = key(n);
            (thumbprint(k.public_key()), k.public_key().clone())
        })
        .collect()
}

fn hx(v: &J) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

fn seeds(c: &J) -> Vec<u8> {
    c["held_key_seeds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| u8::try_from(n.as_u64().unwrap()).unwrap())
        .collect()
}

/// The door's answer, spelled like the vector's `expect`.
fn label(r: &Result<super::door::AdmittedRow, Error>) -> String {
    match r {
        Ok(_) => "valid".into(),
        Err(Error::MalformedRow {
            reason, message, ..
        }) if *reason == malformed_row::EDITION2_STATEMENT_INVALID => format!("invalid:{message}"),
        Err(Error::MalformedRow { reason, .. }) => format!("refused:{reason}"),
        Err(Error::AttesterKeyUnknown {
            attesting_key_id, ..
        }) => format!("waiting:{attesting_key_id}"),
        Err(e) => format!("error:{}", e.kind()),
    }
}

fn file() -> J {
    serde_json::from_str(FILE).unwrap()
}

#[test]
fn i1901_valid_statements_pass_the_door() {
    let f = file();
    let cases = f["valid"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let n = u8::try_from(c["key_seed"].as_u64().unwrap()).unwrap();
        let got = admit_row(
            &hx(&c["statement_hex"]),
            &dir([n]),
            None,
            SelectContext::default(),
        );
        if id == "counted_with_refs" {
            // A counted (author-less) row in a family CC's vendored model
            // names authored: the author column (the vector's test model
            // calls the family counted).
            assert_eq!(
                label(&got),
                format!("refused:{}", malformed_row::EDITION2_FAMILY_INVALID),
                "I1901 {id}: CC's vendored model, not the vector's test model"
            );
            continue;
        }
        if id == "second_voice" {
            // The vector's second voice fills a role of its stated TEST
            // family model; under CC's vendored model (the door's) the
            // family names no such role.
            assert_eq!(
                label(&got),
                format!("refused:{}", malformed_row::EDITION2_FAMILY_INVALID),
                "I1901 {id}: CC's vendored model, not the vector's test model"
            );
            assert!(matches!(
                ciris_verify_core::edition2::verify_row_statement(
                    &hx(&c["statement_hex"]),
                    &dir([n])
                ),
                ciris_verify_core::edition2::Verdict::Valid(_)
            ));
            continue;
        }
        if id == "names_earlier_form" {
            assert_eq!(
                label(&got),
                format!("refused:{}", malformed_row::EDITION2_ROW_REF_EDITION_1),
                "I1901 {id}: Verify admits it; CC rc20 refuses a row naming the earlier form"
            );
            continue;
        }
        let row = got.unwrap_or_else(|e| panic!("I1901 {id}: {e:?}"));
        assert_eq!(
            row.row_id.hex(),
            c["row_id_hex"].as_str().unwrap(),
            "I1901 {id}"
        );
        assert_eq!(
            hex::encode(row.kid),
            c["kid_hex"].as_str().unwrap(),
            "I1901 {id}"
        );
        assert_eq!(row.iss, c["iss"].as_str().unwrap(), "I1901 {id}");
        // The offered id is honoured only when it is the computed one.
        let rid: Digest32 = hx(&c["row_id_hex"]).try_into().unwrap();
        assert!(admit_row(
            &hx(&c["statement_hex"]),
            &dir([n]),
            Some(&rid),
            SelectContext::default()
        )
        .is_ok());
    }
}

#[test]
fn i1901_refusals_give_verifys_reasons() {
    let f = file();
    let cases = f["refusals"].as_array().unwrap();
    assert_eq!(cases.len(), 40);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let expect = c["expect"].as_str().unwrap();
        let got = label(&admit_row(
            &hx(&c["statement_hex"]),
            &dir(seeds(c)),
            None,
            SelectContext::default(),
        ));
        let want = match expect.strip_prefix("waiting:kid:") {
            Some(k) => {
                let kid: Digest32 = hex::decode(k).unwrap().try_into().unwrap();
                format!("waiting:{}", identity_ref(&kid))
            }
            None => expect.to_owned(),
        };
        // `edition_1` names the CWT edition claim, not a row-ref: Verify's
        // reason stands. `untagged` bytes are in no form at persist's door.
        let want = if id == "untagged" {
            format!("refused:{}", malformed_row::EDITION2_EARLIER_FORM_OBJECT)
        } else {
            want
        };
        assert_eq!(got, want, "I1901 {id}");
    }
}

#[test]
fn i1901_key_record_end_rule_is_the_doors() {
    let f = file();
    let cases = f["key_records"].as_array().unwrap();
    assert_eq!(cases.len(), 17);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let p = cde::decode(&hx(&c["payload_hex"])).unwrap();
        let want = c["expect"].as_str().unwrap();
        match check_key_record(&p) {
            Ok(_) => assert_eq!(want, "ok", "I1901 {id}"),
            Err(e) => {
                assert_eq!(e.token(), want, "I1901 {id}: Verify's token");
                let door = key_record_refusal("sub", &p, &e);
                match (want, &door) {
                    ("key_record_mixed_roles", Error::IdentitySetMixesPersonAndMachine { .. }) => {}
                    ("key_record_out_of_window", Error::MalformedRow { reason, .. })
                        if *reason == malformed_row::KEY_RECORD_OUT_OF_WINDOW => {}
                    (_, Error::MalformedRow { reason, .. })
                        if *reason == malformed_row::EDITION2_STATEMENT_INVALID
                            && want != "key_record_mixed_roles"
                            && want != "key_record_out_of_window" => {}
                    _ => panic!("I1901 {id}: {want} became {door:?}"),
                }
            }
        }
    }
}

#[test]
fn i1901_key_directory_through_persists_reading() {
    let f = file();
    let cases = f["key_directory"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let mut held = HeldKeys::new();
        for r in c["records_hex"].as_array().unwrap() {
            held.insert_record(hx(r)).unwrap();
        }
        // Persist never holds a key in part: `partial` is not inserted.
        let st = hx(&c["statement_hex"]);
        let got = label(&admit_row(&st, &held, None, SelectContext::default()));
        let expect = c["expect"].as_str().unwrap();
        let want = match id {
            "held_in_part" | "after_valid_until" => {
                // Waits on the statement's own signing key.
                let (protected, _) = super::liveness::statement_parts(&st).unwrap();
                let kid: Digest32 = protected
                    .get_int(4)
                    .and_then(cde::Value::as_bytes)
                    .unwrap()
                    .try_into()
                    .unwrap();
                format!("waiting:{}", identity_ref(&kid))
            }
            _ => match expect.strip_prefix("waiting:kid:") {
                Some(k) => {
                    let kid: Digest32 = hex::decode(k).unwrap().try_into().unwrap();
                    format!("waiting:{}", identity_ref(&kid))
                }
                None => expect.to_owned(),
            },
        };
        assert_eq!(got, want, "I1901 {id} (Verify: {expect})");
    }
}

#[test]
fn i1901_object_headers_and_ids() {
    use ciris_verify_core::edition2::{verify_object_statement, ObjectVerdict};
    let f = file();
    for c in f["objects"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        let bytes = hx(&c["statement_hex"]);
        let got = match verify_object_statement(&bytes, &dir(seeds(c))) {
            ObjectVerdict::Valid(o) => {
                let pb = super::door::raw_payload(&bytes).unwrap();
                let ours = super::names::RowId::of_object(&o.typ, o.author.as_deref(), &pb);
                assert_eq!(
                    ours.hex(),
                    c["object_id_hex"].as_str().unwrap(),
                    "I1901 {id}"
                );
                "valid".to_owned()
            }
            ObjectVerdict::Invalid(i) => format!("invalid:{}", super::door::invalid_label(&i)),
            ObjectVerdict::Waiting { .. } => "waiting".into(),
        };
        assert_eq!(got, c["expect"].as_str().unwrap(), "I1901 {id}");
        // At a ROW door, every object is refused: the row type is absent.
        let r = admit_row(&bytes, &dir(seeds(c)), None, SelectContext::default());
        assert!(r.is_err(), "I1901 {id}: an object is not a row");
    }
}

/// The lookups the door makes resolve through `KeyDirectory` alone: a
/// persist `HeldKeys` with nothing held answers Waiting on the asked kid.
#[test]
fn i1901_an_empty_reader_waits() {
    let k: Digest32 = [7; 32];
    assert!(matches!(
        HeldKeys::new().lookup(&k, 0),
        ciris_verify_core::edition2::KeyLookup::Waiting(_)
    ));
}
