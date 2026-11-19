//! **I1901** — CIRISVerify's edition-2 row-statement known answers,
//! replayed through persist's door (`tests/vectors/verify_v23/edition2/
//! row_statements_v3.json`, re-pinned from Verify's `v23.3.0` tag, slice C3;
//! v1 retired). **I2365**–**I2367** (slice C3) add the key-of-issuer check's
//! known answers (`edition2/key_of_iss_v1.json`).
//!
//! What persist asserts, case set by case set:
//! - `valid`: each statement passes [`admit_row`], with the vector's row id,
//!   kid and iss (CC's v1.0-rc20 vendored model reads every one valid, the
//!   vector's `family_vendored_expect`).
//! - `refusals`: each Invalid case is refused `edition2_statement_invalid`
//!   with Verify's own reason. The Waiting case is the retryable
//!   unknown-signer error, naming the vector's key. Two exceptions:
//!   - `untagged` bytes are in no form at persist's door
//!     (`edition2_earlier_form_object`);
//!   - `names_earlier_form` and `row_ref_edition_1` (an edition-1
//!     `row-ref`): persist's door names them first, `row_ref_edition_1`
//!     (CC 2.6.1.3); Verify's reader alone gives the vector's reason.
//! - `key_records`: each payload's end rule, Verify's token, equals the
//!   door's refusal: `key_record_out_of_window`, the typed mixed-set error,
//!   or `edition2_statement_invalid`.
//! - `key_directory`, through persist's [`HeldKeys`] (I2365): Verify's
//!   reader over persist's directory gives the vector's exact verdict, and
//!   the door the matching refusal. `after_valid_until` waits on a record of
//!   the key covering the instant (`MissingKey::CoveringRecord`, CC 2.4.1.1).
//! - `objects`: the header verdicts agree, and persist's object id equals
//!   the vector's.
//! - `key_of_iss_v1.json` (I2366): every case through Verify's reader with
//!   persist's directory (a raw key map, or [`HeldKeys`] holding the
//!   vector's records in order), whose `KeyDirectory::key_of` is
//!   [`HeldKeys::key_of`], gives the vector's verdict. Three stated
//!   divergences, each kept by A's I2101 witnesses:
//!   - `rotation_without_predecessor_statement` waits on the predecessor key
//!     here (a door receives a rotation's voices one at a time; "a missing
//!     link waits"), where Verify's directory answers `kid_not_of_iss`;
//!   - `rotation_genesis_not_held` and `rotation_two_hops_middle_missing`
//!     wait in both, but persist names the record `target` names where
//!     Verify names the predecessor key its statement waits on.
//! - (I2367) the same cases at persist's door: `kid_not_of_iss` is refused
//!   by that token, a wait is the retryable unknown-signer error.
//!
//! v62.0.0 (R1, CIRISVerify 23.3.1, CC v1.0-rc21-wire e6fd7c6). The two v1
//! files stay byte-identical (Verify keeps them so), and so does what persist
//! asserts of them, with one move Verify records in its own replay: the key
//! record `node_at_asserted` (a `valid_until` equal to `asserted_at`) is
//! `key_record_out_of_window` under rc21's strict end rule, where v1 says
//! `ok`. Verify 23.3.1's own `KeyRecordDirectory` now waits where v1 said
//! `kid_not_of_iss` for a rotation lacking a voice (`MissingKey::Voice`), so
//! I2366's first stated divergence is persist's reading against the v1
//! FILE, no longer against Verify's directory.
//! - `key_of_iss_v2.json` (I4020, I4021): the rc21 key check's known answers.
//!   The cases whose directory is key records alone (the end rule of step
//!   4, half-open coverage, rotation voices, and `location_proof` authored by
//!   its subject) through Verify's reader over persist's [`HeldKeys`]; the
//!   cases that need an admitted occurrence, an eviction or a bundle's seats
//!   are listed and not replayed here (persist's occurrence and seat arms are
//!   loaded from the store, I3020 and slice C3, not from a vector's list).
//! - (I4022, I4023; R1 round 3) three of the four cases the Verify 23.3.1 tag
//!   added, where persist's own door can carry them: an integer-keyed
//!   occurrence (pure gates), a forged record of another key, and an
//!   eviction whose signer is not held (the store door, sqlite and pg).
//! - (R1 round 3) `rotation_lacks_possession` now matches: persist's
//!   [`HeldKeys::key_of`] waits on a rotation's missing own voice
//!   (`ChainMissing::Voice`), and v1's `rotation_without_own_statement` is
//!   the fourth stated divergence from the v1 file.

use std::collections::BTreeMap;

use ciris_crypto::composite::{CompositePublicKey, CompositeSigningKey};
use ciris_verify_core::cde;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::family::{
    verify_row_in_family, FamilyVerdict, VendoredFamilyModel,
};
use ciris_verify_core::edition2::keys::check_key_record;
use ciris_verify_core::edition2::{
    identity_ref, thumbprint, verify_row_statement, Digest32, KeyDirectory, MissingKey, Verdict,
};
use serde_json::Value as J;

use super::door::{admit_row, fault_label, invalid_label, key_record_refusal};
use super::liveness::HeldKeys;
use crate::federation::{malformed_row, Error};

/// The vector's waiting label, built so no literal reads as a family prefix
/// to the family-rules discovery scan.
const WAITING_KID: &str = concat!("waiting", ":kid:");
const COLON: char = ':';

const FILE: &str =
    include_str!("../../../tests/vectors/verify_v23/edition2/row_statements_v3.json");
const KEY_OF_ISS: &str =
    include_str!("../../../tests/vectors/verify_v23/edition2/key_of_iss_v1.json");
/// v62.0.0 (R1, R1d) — CIRISVerify 23.3.1's `key_of_iss_v2.json` (31 cases at
/// the tag b0933ba;
/// SHA-256 pinned in `verify_v23_vectors`, I1850).
const KEY_OF_ISS_V2: &str =
    include_str!("../../../tests/vectors/verify_v23/edition2/key_of_iss_v2.json");

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
        }) => format!("waiting{COLON}{attesting_key_id}"),
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
    assert_eq!(cases.len(), 4);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        assert_eq!(
            c["family_vendored_expect"], "valid",
            "I1901 {id}: CC's vendored model reads it valid"
        );
        let n = u8::try_from(c["key_seed"].as_u64().unwrap()).unwrap();
        let got = admit_row(
            &hx(&c["statement_hex"]),
            &dir([n]),
            None,
            SelectContext::default(),
        );
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
    assert_eq!(cases.len(), 42);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let expect = c["expect"].as_str().unwrap();
        let got = label(&admit_row(
            &hx(&c["statement_hex"]),
            &dir(seeds(c)),
            None,
            SelectContext::default(),
        ));
        let want = match expect.strip_prefix(WAITING_KID) {
            Some(k) => {
                let kid: Digest32 = hex::decode(k).unwrap().try_into().unwrap();
                format!("waiting{COLON}{}", identity_ref(&kid))
            }
            None => expect.to_owned(),
        };
        // `edition_1` names the CWT edition claim, not a row-ref: Verify's
        // reason stands. `untagged` bytes are in no form at persist's door.
        // An edition-1 row-ref is named by persist's door first; Verify's
        // reader alone gives the vector's reason.
        let want = match id {
            "untagged" => format!("refused:{}", malformed_row::EDITION2_EARLIER_FORM_OBJECT),
            "names_earlier_form" | "row_ref_edition_1" => {
                assert_eq!(
                    reader_label(&verify_row_statement(
                        &hx(&c["statement_hex"]),
                        &dir(seeds(c))
                    )),
                    expect,
                    "I1901 {id}: Verify's reader"
                );
                format!("refused:{}", malformed_row::EDITION2_ROW_REF_EDITION_1)
            }
            _ => want,
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
        // v62.0.0 (R1; CIRISVerify 23.3.1, CC rc21): a record covers
        // [asserted_at, valid_until), so an end at its own instant covers
        // nothing; the file stays as published (Verify's own replay records
        // the same move).
        let want = match id {
            "node_at_asserted" => "key_record_out_of_window",
            _ => c["expect"].as_str().unwrap(),
        };
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

/// I1901 / I2365 — the key-directory cases through persist's [`HeldKeys`]:
/// Verify's reader over it gives the vector's exact verdict, and the door
/// the matching refusal (a wait names the key, also for a covering record).
#[test]
fn i1901_i2365_key_directory_through_persists_reading() {
    let f = file();
    let cases = f["key_directory"].as_array().unwrap();
    assert_eq!(cases.len(), 4);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let mut held = HeldKeys::new();
        for r in c["records_hex"].as_array().unwrap() {
            held.insert_record(hx(r)).unwrap();
        }
        let st = hx(&c["statement_hex"]);
        let expect = c["expect"].as_str().unwrap();
        assert_eq!(
            reader_label(&verify_row_statement(&st, &held)),
            expect,
            "I2365 {id}: Verify's reader over persist's directory"
        );
        let got = label(&admit_row(&st, &held, None, SelectContext::default()));
        let want = match waiting_kid(expect) {
            Some(kid) => format!("waiting{COLON}{}", identity_ref(&kid)),
            None => expect.to_owned(),
        };
        assert_eq!(got, want, "I1901 {id} at the door");
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

/// Verify's verdict, spelled like the vectors' `expect`.
fn reader_label(v: &Verdict) -> String {
    match v {
        Verdict::Valid(_) => "valid".into(),
        Verdict::Invalid(i) => format!("invalid{COLON}{}", invalid_label(i)),
        Verdict::Waiting { missing } => missing_label(missing),
    }
}

/// The first missing link, spelled like the vectors' `expect`.
fn missing_label(missing: &[MissingKey]) -> String {
    match missing.first() {
        Some(MissingKey::Kid(k)) => format!("{WAITING_KID}{}", hex::encode(k)),
        Some(MissingKey::CoveringRecord { kid, at_ms }) => format!(
            "waiting{COLON}covering_record{COLON}{}{COLON}{at_ms}",
            hex::encode(kid)
        ),
        Some(MissingKey::Record(r)) => format!("waiting{COLON}record{COLON}{}", hex::encode(r)),
        // v62.0.0 (R1; CIRISVerify 23.3.1) — the two links rc21 adds.
        Some(MissingKey::Voice { kid, row }) => format!(
            "waiting{COLON}voice{COLON}{}{COLON}{}",
            hex::encode(kid),
            hex::encode(row)
        ),
        Some(MissingKey::Bundle(b)) => format!("waiting{COLON}bundle{COLON}{}", hex::encode(b)),
        other => format!("{other:?}"),
    }
}

/// The key a `waiting:kid:<hex>` or `waiting:covering_record:<hex>:<at>`
/// expectation names: the door names it by its identity reference.
fn waiting_kid(expect: &str) -> Option<Digest32> {
    let mut parts = expect.split(COLON);
    if parts.next() != Some("waiting") {
        return None;
    }
    match (parts.next(), parts.next()) {
        (Some("kid" | "covering_record"), Some(k)) => hex::decode(k).ok()?.try_into().ok(),
        _ => None,
    }
}

fn key_of_file() -> J {
    serde_json::from_str(KEY_OF_ISS).unwrap()
}

/// The directory a `key_of_iss_v1.json` case names: a raw key map, or
/// persist's [`HeldKeys`] holding its records in order.
fn key_of_directory(c: &J) -> Box<dyn KeyDirectory> {
    match c["directory"].as_str().unwrap() {
        "raw" => Box::new(dir(seeds(c))),
        "records" => {
            let mut held = HeldKeys::new();
            for r in c["records_hex"].as_array().unwrap() {
                held.insert_record(hx(r)).unwrap();
            }
            Box::new(held)
        }
        d => panic!("directory {d}"),
    }
}

/// The record row the signing key's own held record names in
/// `refs.target` (its predecessor's record).
fn own_record_target(c: &J, st: &[u8]) -> Digest32 {
    let kid = super::ingest::statement_kid(st).unwrap();
    c["records_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(hx)
        .find(|r| super::ingest::statement_kid(r) == Some(kid))
        .and_then(|r| super::liveness::statement_parts(&r))
        .and_then(|(_, p)| super::names::names_of(&p).ok())
        .and_then(|n| super::names::single(&n, "target"))
        .unwrap()
        .0
}

/// The row of the held rotation record: the one held record that names a
/// predecessor's record in `refs.target`.
fn rotation_row(c: &J) -> super::names::RowId {
    let named: Vec<super::names::RowId> = c["records_hex"]
        .as_array()
        .unwrap()
        .iter()
        .map(hx)
        .filter(|r| {
            super::liveness::statement_parts(r)
                .and_then(|(_, p)| super::names::names_of(&p).ok())
                .and_then(|n| super::names::single(&n, "target"))
                .is_some()
        })
        .map(|r| super::names::RowId::of_statement(&r).unwrap())
        .collect();
    assert_eq!(named.len(), 1, "one rotation record");
    named[0]
}

/// What persist answers where it differs from Verify's `KeyRecordDirectory`
/// (module docs): persist's verdict for the case, or `None` where they agree.
fn key_of_divergence(c: &J) -> Option<String> {
    let st = hx(&c["statement_hex"]);
    match c["id"].as_str().unwrap() {
        // B's statement over B2's rotation record is not held at all: the
        // rotation waits on B (key seed 2), I2101 "a missing link waits".
        // Verify: kid_not_of_iss.
        "rotation_without_predecessor_statement" => Some(format!(
            "{WAITING_KID}{}",
            hex::encode(thumbprint(key(2).public_key()))
        )),
        // The predecessor's statement is held and waits on its key, whose
        // record is not held: persist names the record `target` names
        // (I2101); Verify names the predecessor key. Both wait.
        "rotation_genesis_not_held" | "rotation_two_hops_middle_missing" => Some(format!(
            "waiting{COLON}record{COLON}{}",
            hex::encode(own_record_target(c, &st))
        )),
        // v62.0.0 (R1 round 3; CC 2.6.1.9) — B's statement over B2's rotation
        // is held, B2's own is not: the rotation waits on B2's voice over
        // that row, as Verify 23.3.1's own directory now answers (its replay
        // records the move; key_of_iss_v2 `rotation_lacks_possession`). The
        // v1 file says kid_not_of_iss.
        "rotation_without_own_statement" => Some(format!(
            "waiting{COLON}voice{COLON}{}{COLON}{}",
            hex::encode(super::ingest::statement_kid(&st).unwrap()),
            rotation_row(c).hex()
        )),
        _ => None,
    }
}

/// I2366 — the key-of-issuer check's known answers through Verify's reader
/// over persist's directory, whose `KeyDirectory::key_of` is
/// [`HeldKeys::key_of`]: one verdict for the reader and the door.
#[test]
fn i2366_key_of_iss_through_persists_directory() {
    let f = key_of_file();
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 24, "I2366: every case is replayed");
    let mut diverged = 0usize;
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let st = hx(&c["statement_hex"]);
        let keys = key_of_directory(c);
        let got = match c["level"].as_str().unwrap() {
            "statement" => reader_label(&verify_row_statement(&st, keys.as_ref())),
            "family" => {
                assert_eq!(c["model"], "vendored", "I2366 {id}");
                match verify_row_in_family(&st, keys.as_ref(), &VendoredFamilyModel) {
                    FamilyVerdict::Valid { .. } => "valid".into(),
                    FamilyVerdict::Invalid(i) => format!("invalid{COLON}{}", invalid_label(&i)),
                    FamilyVerdict::FamilyInvalid(fault) => {
                        format!("family_invalid{COLON}{}", fault_label(&fault))
                    }
                    FamilyVerdict::Waiting(m) => missing_label(&m),
                }
            }
            l => panic!("level {l}"),
        };
        let want = match key_of_divergence(c) {
            Some(ours) => {
                diverged += 1;
                ours
            }
            None => c["expect"].as_str().unwrap().to_owned(),
        };
        assert_eq!(got, want, "I2366 {id} (Verify: {})", c["expect"]);
    }
    assert_eq!(
        diverged, 4,
        "I2366: the four stated divergences are replayed"
    );
}

/// I2367 — the same cases at persist's door: `kid_not_of_iss` is refused by
/// that token, a wait is the retryable unknown-signer error. (A valid case
/// is the reader's to answer: these rows carry no `dimension`, so the door's
/// family step is not what they test.)
#[test]
fn i2367_key_of_iss_at_the_door() {
    let f = key_of_file();
    let mut refused = 0usize;
    for c in f["cases"].as_array().unwrap() {
        if c["level"] != "statement" {
            continue;
        }
        let id = c["id"].as_str().unwrap();
        let st = hx(&c["statement_hex"]);
        let keys = key_of_directory(c);
        let got = admit_row(&st, keys.as_ref(), None, SelectContext::default());
        let expect =
            key_of_divergence(c).unwrap_or_else(|| c["expect"].as_str().unwrap().to_owned());
        let mut parts = expect.split(COLON);
        match (parts.next(), parts.next()) {
            (Some("invalid"), Some("kid_not_of_iss")) => {
                refused += 1;
                assert_eq!(
                    label(&got),
                    format!("refused:{}", malformed_row::KID_NOT_OF_ISS),
                    "I2367 {id}"
                );
            }
            (Some("waiting"), _) => assert!(
                matches!(got, Err(Error::AttesterKeyUnknown { .. })),
                "I2367 {id}: {}",
                label(&got)
            ),
            _ => {}
        }
    }
    // R1 round 3: `rotation_without_own_statement` waits here (the fourth
    // divergence), so seven of the file's eight kid_not_of_iss cases refuse.
    assert_eq!(refused, 7, "I2367: the kid_not_of_iss cases ran");
}

// ─────────────────────────────────────────────────────────────────────────
//  v62.0.0 (R1) — CIRISVerify 23.3.1's `key_of_iss_v2.json`
// ─────────────────────────────────────────────────────────────────────────

/// The `key_of_iss_v2.json` cases whose directory names an admitted
/// occurrence, an eviction, a bundle's seats or a pending bundle: persist
/// loads those arms from the store (the occurrence arm, I3020; the seat arm,
/// slice C3), so they are not replayed from the vector's lists.
const KEY_OF_ISS_V2_NOT_REPLAYED: [&str; 20] = [
    "seated_by_bundle",
    "seat_ended",
    "bundle_pending",
    "seated_key_no_record",
    "occurrence_binds",
    "occurrence_lacks_possession",
    "occurrence_lacks_identity_voice",
    "agent_under_person",
    "agent_record_under_person",
    "occurrence_evicted",
    "evicted_later",
    "eviction_by_stranger",
    "occurrence_names_no_head",
    "occurrence_of_other_identity",
    "occurrence_ended",
    "occurrence_voiced_by_stranger",
    // R1d (Verify tag 23.3.1, b0933ba, after PR head fad948e): four cases more,
    // each with an occurrence, an eviction or a bundle's seats. R1 round 3:
    // `occurrence_integer_key` is replayed at the door's pure gates (I4023),
    // `eviction_signer_not_held` and `forged_record_does_not_unperson` at the
    // store door (I4022). `seat_shadows_bad_record` is not: Verify's seats
    // carry their keys, while persist's seat arm names kids and reads each
    // seat's key from its bundle-placed record, so a seat whose own record is
    // bad has no persist analogue.
    "eviction_signer_not_held",
    "forged_record_does_not_unperson",
    "seat_shadows_bad_record",
    "occurrence_integer_key",
];

fn key_of_v2_file() -> J {
    serde_json::from_str(KEY_OF_ISS_V2).unwrap()
}

/// A verdict's class, as `key_of_iss_v2.json` compares it: `valid`, the
/// refusal with its token, or `waiting` (persist names a missing link by its
/// own reading, I2101, so a wait is compared as a wait).
fn v2_class(label: &str) -> String {
    if label.starts_with(concat!("waiting", ":")) {
        "waiting".to_owned()
    } else {
        label.to_owned()
    }
}

/// I4020 — every case of `key_of_iss_v2.json` (CIRISVerify 23.3.1's, pinned
/// by I1850) is either replayed (I4021) or named as not replayed.
#[test]
fn i4020_key_of_iss_v2_cases_are_replayed_or_named() {
    let f = key_of_v2_file();
    let ids: Vec<&str> = f["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids.len(), 31, "I4020: the case list");
    for id in KEY_OF_ISS_V2_NOT_REPLAYED {
        assert!(ids.contains(&id), "I4020: {id} is a case");
    }
}

/// I4021 — the rc21 key check over key records alone, through Verify's
/// reader over persist's [`HeldKeys`] (whose `key_of` is the door's): the
/// end rule of step 4 (`valid_until_not_after_asserted_at`, and persist's
/// door refuses it by that token), half-open coverage (the last covered
/// millisecond is valid, the end instant waits on a covering record),
/// rotation voices (a complete rotation is valid; a missing voice or record
/// waits, never refuses), and `location_proof` authored by its subject alone
/// under CC's vendored family model (`family:iss_not_in_role` otherwise).
#[test]
fn i4021_key_of_iss_v2_through_persists_directory() {
    let f = key_of_v2_file();
    let mut replayed = 0usize;
    for c in f["cases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        if KEY_OF_ISS_V2_NOT_REPLAYED.contains(&id) {
            assert!(
                !c["occurrences_hex"].as_array().unwrap().is_empty()
                    || !c["evictions_hex"].as_array().unwrap().is_empty()
                    || !c["seats"].as_array().unwrap().is_empty()
                    || c.get("pending_bundle_hex").is_some(),
                "I4021 {id}: listed as not replayed, but its directory is records alone"
            );
            continue;
        }
        let mut held = HeldKeys::new();
        for r in c["records_hex"].as_array().unwrap() {
            held.insert_record(hx(r)).unwrap();
        }
        let st = hx(&c["statement_hex"]);
        let expect = c["expect"].as_str().unwrap();
        let got = match c["level"].as_str().unwrap() {
            "statement" => reader_label(&verify_row_statement(&st, &held)),
            "family" => {
                assert_eq!(c["model"], "vendored", "I4021 {id}");
                match verify_row_in_family(&st, &held, &VendoredFamilyModel) {
                    FamilyVerdict::Valid { .. } => "valid".into(),
                    FamilyVerdict::Invalid(i) => format!("invalid{COLON}{}", invalid_label(&i)),
                    FamilyVerdict::FamilyInvalid(fault) => {
                        format!("family{COLON}{}", fault_label(&fault))
                    }
                    FamilyVerdict::Waiting(m) => missing_label(&m),
                }
            }
            l => panic!("level {l}"),
        };
        assert_eq!(
            v2_class(&got),
            v2_class(expect),
            "I4021 {id}: Verify 23.3.1 says {expect}, persist's reading {got}"
        );
        // The end rule at persist's door: refused by persist's token.
        if expect == concat!("invalid", ":valid_until_not_after_asserted_at") {
            let door = admit_row(&st, &held, None, SelectContext::default());
            assert_eq!(
                label(&door),
                format!(
                    "refused{COLON}{}",
                    malformed_row::VALID_UNTIL_NOT_AFTER_ASSERTED_AT
                ),
                "I4021 {id} at the door"
            );
        }
        replayed += 1;
    }
    assert_eq!(
        replayed,
        31 - KEY_OF_ISS_V2_NOT_REPLAYED.len(),
        "I4021: every records-only case ran"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  v62.0.0 (R1 round 3) — the four cases the tag added, where persist can
//  replay them
// ─────────────────────────────────────────────────────────────────────────

fn key_of_v2_case(id: &str) -> J {
    key_of_v2_file()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no case {id}"))
        .clone()
}

fn hexes(c: &J, list: &str) -> Vec<Vec<u8>> {
    c[list].as_array().unwrap().iter().map(hx).collect()
}

/// I4023 — `occurrence_integer_key` (CIRISVerify 23.3.1 tag b0933ba): an
/// `identity:occurrence` payload with an integer-keyed member. Persist's
/// door refuses each of its statements by the family's closed payload map
/// (`edition2_payload_invalid`, "a member key is not text"; the open tail
/// is `* tstr => ceg-value`), so the occurrence never binds, and the case's
/// statement, signed by the device as the identity over the identity's and
/// the device's records alone, is `kid_not_of_iss`, Verify's answer.
#[test]
fn i4023_an_integer_keyed_occurrence_binds_nothing() {
    let c = key_of_v2_case("occurrence_integer_key");
    let mut held = HeldKeys::new();
    for r in hexes(&c, "records_hex") {
        held.insert_record(r).unwrap();
    }
    let occurrences = hexes(&c, "occurrences_hex");
    assert_eq!(occurrences.len(), 2, "I4023: both voices");
    for st in &occurrences {
        match super::door::pure_statement_gates(st, &held) {
            Err(Error::MalformedRow { reason, .. }) => assert_eq!(
                reason,
                malformed_row::EDITION2_PAYLOAD_INVALID,
                "I4023: the closed payload map"
            ),
            other => panic!("I4023: an integer-keyed occurrence passed the gates: {other:?}"),
        }
    }
    let st = hx(&c["statement_hex"]);
    assert_eq!(
        v2_class(&reader_label(&verify_row_statement(&st, &held))),
        v2_class(c["expect"].as_str().unwrap()),
        "I4023: {}",
        c["expect"]
    );
}

/// I4022 — two of the tag's cases at the store door (`put_statement`), on
/// sqlite and postgres:
///
/// - `forged_record_does_not_unperson`: S files a `key:record` of A's key
///   saying `agent`. Whatever the door does with it, A's own key stays a
///   person's (its projection never reads `agent`), and the agent key E
///   signing as A is `kid_not_of_iss` over the store's own key plane
///   (`held_keys_for`), Verify's answer.
/// - `eviction_signer_not_held`: an eviction of D signed by a key Z whose
///   record is not held never lands (no revocation is recorded for A), so it
///   evicts nothing.
///
/// The cases' occurrence voices are not replayed here: the vector signs the
/// occurrence key's own voice with `iss` = the identity, where persist's
/// door and CC's rc21 cell (`second_signers [{role: occurrence, member:
/// occurrence_key_id}]`) read that voice with `iss` = the occurrence key.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn i4022_body(d: &dyn crate::federation::FederationDirectory) {
    use super::ingest::{held_keys_for, put_statement, INGEST_TIER};
    let put = |st: Vec<u8>| async move { put_statement(d, &st, None, INGEST_TIER).await };

    // forged_record_does_not_unperson
    let c = key_of_v2_case("forged_record_does_not_unperson");
    let records = hexes(&c, "records_hex");
    assert_eq!(records.len(), 3, "I4022: recA, forged, recE");
    put(records[0].clone())
        .await
        .expect("I4022: A's own record");
    let forged = put(records[1].clone()).await;
    assert!(
        !matches!(forged, Ok(super::ingest::StatementOutcome::Row { .. })),
        "I4022: S's record of A's key lands no row: {forged:?}"
    );
    put(records[2].clone())
        .await
        .expect("I4022: E's own record");
    let a_ref = super::liveness::statement_parts(&records[0])
        .and_then(|(protected, _)| {
            protected
                .get_int(15)?
                .get_int(1)?
                .as_text()
                .map(str::to_owned)
        })
        .expect("I4022: A's iss");
    let a_types = d
        .lookup_public_key(&a_ref)
        .await
        .unwrap()
        .expect("I4022: A's own record is projected")
        .identity_type;
    assert!(
        a_types.contains("user") && !a_types.contains("agent"),
        "I4022: A's key is still a person's: {a_types:?}"
    );
    let st = hx(&c["statement_hex"]);
    let held = held_keys_for(d, &st).await.unwrap();
    assert_eq!(
        v2_class(&reader_label(&verify_row_statement(&st, &held))),
        v2_class(c["expect"].as_str().unwrap()),
        "I4022 forged_record_does_not_unperson"
    );

    // eviction_signer_not_held
    let c = key_of_v2_case("eviction_signer_not_held");
    for r in hexes(&c, "records_hex") {
        // recA is held already; recD is new. Re-offering is idempotent.
        put(r).await.expect("I4022: a held record");
    }
    let evictions = hexes(&c, "evictions_hex");
    assert_eq!(evictions.len(), 1, "I4022: one eviction");
    let e = put(evictions[0].clone()).await;
    assert!(
        !matches!(e, Ok(super::ingest::StatementOutcome::Row { .. })),
        "I4022: an eviction by a key not held lands nothing: {e:?}"
    );
    assert!(
        d.list_identity_occurrence_revocations_for(&a_ref)
            .await
            .unwrap()
            .is_empty(),
        "I4022: no revocation is recorded for A"
    );
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4022_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i4022_body(&b)).await;
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4022_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(i4022_body(&b)).await;
}
