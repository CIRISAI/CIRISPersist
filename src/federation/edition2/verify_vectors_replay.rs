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
//!   K1-fix3's DEPARTURE on `held_through_chain` (B's node record with A's
//!   voice alone; CC 2.4.1.1, "Each key's own holder signs its record") is
//!   closed by CIRISVerify 23.3.2, which drops its reader's fallback to a
//!   record another key signed: the file and persist agree (R1-v2332).
//! - `objects`: the header verdicts agree, and persist's object id equals
//!   the vector's.
//! - `key_of_iss_v1.json` (I2366): every case through Verify's reader with
//!   persist's directory (a raw key map, or [`HeldKeys`] holding the
//!   vector's records in order), whose `KeyDirectory::key_of` is
//!   [`HeldKeys::key_of`], gives the vector's verdict. Five stated
//!   divergences from the v1 FILE, each kept by A's I2101 witnesses:
//!   - `rotation_without_predecessor_statement` waits on the predecessor key
//!     here (a door receives a rotation's voices one at a time; "a missing
//!     link waits"), where Verify's directory answers `kid_not_of_iss`;
//!   - `rotation_genesis_not_held` and `rotation_two_hops_middle_missing`
//!     wait in both, but persist names the record `target` names where
//!     Verify names the predecessor key its statement waits on;
//!   - `rotation_without_own_statement` and `record_by_other_key_only` (a
//!     record held only in another key's voice) wait on the signing key's
//!     own voice (CC 2.4.1.1; R1 round 3, R1-v2332), as Verify 23.3.2's
//!     directory does, where the v1 file says `kid_not_of_iss`.
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
//! - `key_of_iss_v3.json` (I4020, I4021): the rc21 key check's known answers.
//!   The cases whose directory is key records alone (the end rule of step
//!   4, half-open coverage, rotation voices, and `location_proof` authored by
//!   its subject) through Verify's reader over persist's [`HeldKeys`]; the
//!   cases that need an admitted occurrence or an eviction are replayed at
//!   the store door instead (I4024), and the ones holding a bundle's seats
//!   are not replayed (persist's occurrence and seat arms are loaded from
//!   the store, I3020 and slice C3, not from a vector's list).
//! - (I4022, I4023, I4024; R1 round 3, R1-v2332) the occurrence and eviction
//!   cases: an integer-keyed occurrence refused by the pure gates (I4023), a
//!   forged record of another key leaving A a person (I4022), and EVERY
//!   occurrence and eviction case at the store door by the file's verdict
//!   (I4024, sqlite and pg; CIRISVerify 23.3.2's file, whose possession voice
//!   is signed as the occurrence key, CC rc21 90d537b).
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
    include_str!("../../../tests/vectors/verify_v23/edition2/row_statements_v4.json");
const KEY_OF_ISS: &str =
    include_str!("../../../tests/vectors/verify_v23/edition2/key_of_iss_v1.json");
/// v62.0.0 (R1-v2332) — CIRISVerify 23.3.2's `key_of_iss_v3.json` (32 cases;
/// a NEW file beside v2, whose possession voice is signed as the occurrence
/// key, CC rc21 90d537b; SHA-256 pinned in `verify_v23_vectors`, I1850).
/// v2 (23.3.1, the possession voice signed as the identity) is retired.
const KEY_OF_ISS_V3: &str =
    include_str!("../../../tests/vectors/verify_v23/edition2/key_of_iss_v3.json");

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

/// The reasons persist's door refuses by VERIFY's own token: each `Invalid`
/// with a stable `token()`, which the door maps to the malformed-row reason of
/// the same spelling (`kid_not_of_iss`, `valid_until_not_after_asserted_at`,
/// `body_number_unrepresentable`). Read from Verify, never restated.
fn verify_token_reasons() -> Vec<&'static str> {
    use ciris_verify_core::edition2::Invalid;
    [
        Invalid::KidNotOfIss,
        Invalid::ValidUntilNotAfterAssertedAt,
        Invalid::BodyNumberUnrepresentable,
        // v62.0.0 (PIN-verify-23.6; CIRISVerify 23.6.0).
        Invalid::GroupIdNotOfFounding,
        Invalid::TrustedThroughTooMany,
        Invalid::KeepsCitesNoEnd,
        Invalid::AckNamesTooMany,
        Invalid::TrustAcceptsClassesMalformed,
        Invalid::TrustAcceptsDepthOutOfRange,
    ]
    .iter()
    .filter_map(Invalid::token)
    .collect()
}

/// The door's answer, spelled like the vector's `expect`. A refusal by one of
/// Verify's own tokens ([`verify_token_reasons`]) reads as Verify's verdict,
/// `invalid:<token>` (v62.0.0, R1-v2332): the same refusal, named the same.
fn label(r: &Result<super::door::AdmittedRow, Error>) -> String {
    match r {
        Ok(_) => "valid".into(),
        Err(Error::MalformedRow {
            reason, message, ..
        }) if *reason == malformed_row::EDITION2_STATEMENT_INVALID => format!("invalid:{message}"),
        Err(Error::MalformedRow { reason, .. }) if verify_token_reasons().contains(reason) => {
            format!("invalid:{reason}")
        }
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

/// v62.0.0 (PIN-fix6; CIRISVerify's answer, 2026-11-21) — **the
/// reader-valid vectors persist's payload table refuses.** `row_statements_v4`
/// is a released, sha-pinned file and stays as it is (Verify conforms these in
/// its next set). Each statement is VALID to Verify's reader and REFUSED at
/// persist's door by the CC payload table (`payloads::check_by_id`,
/// `edition2_payload_invalid`), for the reason beside it. Listed, asserted
/// refused, and counted: never a silent skip. A change in either reader
/// re-opens the line.
const READER_VALID_TABLE_REFUSED: &[(&str, &str)] = &[
    (
        "counted_with_refs",
        "a supersedes names no refs.target (persist's door rule) and its group:roster \
         payload carries none of the roster's members (`list`, `body`, `salt` instead)",
    ),
    (
        "second_voice",
        "the same payload as counted_with_refs: no refs.target, no group:roster members",
    ),
];

#[test]
fn i1901_valid_statements_pass_the_door() {
    let f = file();
    let cases = f["valid"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    assert_eq!(
        READER_VALID_TABLE_REFUSED.len(),
        2,
        "I1901 the reader-valid / table-refused list is counted"
    );
    let mut table_refused = 0;
    for c in cases {
        let id = c["id"].as_str().unwrap();
        assert_eq!(
            c["family_vendored_expect"], "valid",
            "I1901 {id}: CC's vendored model reads it valid"
        );
        let n = u8::try_from(c["key_seed"].as_u64().unwrap()).unwrap();
        if let Some((_, why)) = READER_VALID_TABLE_REFUSED.iter().find(|(v, _)| *v == id) {
            let st = hx(&c["statement_hex"]);
            assert!(
                matches!(verify_row_statement(&st, &dir([n])), Verdict::Valid(_)),
                "I1901 {id}: Verify's reader still reads it valid"
            );
            match admit_row(&st, &dir([n]), None, SelectContext::default()) {
                Err(Error::MalformedRow { reason, .. })
                    if reason == malformed_row::EDITION2_PAYLOAD_INVALID => {}
                other => panic!(
                    "I1901 {id} ({why}): persist's payload table refuses it \
                     edition2_payload_invalid, got {other:?}"
                ),
            }
            table_refused += 1;
            continue;
        }
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
    assert_eq!(
        table_refused,
        READER_VALID_TABLE_REFUSED.len(),
        "I1901 every listed vector was met and refused"
    );
}

#[test]
fn i1901_refusals_give_verifys_reasons() {
    let f = file();
    let cases = f["refusals"].as_array().unwrap();
    assert_eq!(cases.len(), 50);
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
            // v62.0.0 (wave P1d) — the family's closed payload map runs with
            // the door's pure gates, before Verify's verdict, and names a
            // missing required `asserted_at` first; Verify's reader alone
            // gives the vector's reason. Both refuse the statement.
            "no_asserted_at" => {
                assert_eq!(
                    reader_label(&verify_row_statement(
                        &hx(&c["statement_hex"]),
                        &dir(seeds(c))
                    )),
                    expect,
                    "I1901 {id}: Verify's reader"
                );
                format!("refused:{}", malformed_row::EDITION2_PAYLOAD_INVALID)
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
    assert_eq!(cases.len(), 6);
    for c in cases {
        let id = c["id"].as_str().unwrap();
        let mut held = HeldKeys::new();
        for r in c["records_hex"].as_array().unwrap() {
            held.insert_record(hx(r)).unwrap();
        }
        let st = hx(&c["statement_hex"]);
        // v62.0.0 (R1-v2332) — K1-fix3's DEPARTURE (`held_through_chain`,
        // B's node record with A's voice alone) is gone: CIRISVerify 23.3.2
        // drops the reader's fallback to a record another key signed (CC
        // 2.4.1.1, "Each key's own holder signs its record") and regenerates
        // the file (row_statements v4), so persist's kernel reading and the
        // vector agree, and every case is compared with the file as it is.
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
        // v62.0.0 (R1-v2332) — row_statements_v4's spelling: the key whose
        // own voice is missing (the row is not named).
        Some(MissingKey::Voice { kid, .. }) => {
            format!("waiting{COLON}voice{COLON}{}", hex::encode(kid))
        }
        Some(MissingKey::Bundle(b)) => format!("waiting{COLON}bundle{COLON}{}", hex::encode(b)),
        // v62.0.0 (PIN-fix5b; CIRISVerify 23.4.1) — a composer's target row.
        Some(MissingKey::Row(r)) => format!("waiting{COLON}row{COLON}{}", hex::encode(r)),
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
        (Some("kid" | "covering_record" | "voice"), Some(k)) => {
            hex::decode(k).ok()?.try_into().ok()
        }
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
        // v62.0.0 (R1 round 3, R1-v2332; CC 2.6.1.9, CC 2.4.1.1) — a record
        // held only in another key's voice (B's over B2's rotation; A's over
        // a record of C) waits on the signing key's OWN voice, as Verify
        // 23.3.2's directory answers (`resolve`: no third party makes a key
        // live; row_statements_v4 `record_not_own_voice`). The v1 file says
        // kid_not_of_iss.
        "rotation_without_own_statement" | "record_by_other_key_only" => Some(format!(
            "waiting{COLON}voice{COLON}{}",
            hex::encode(super::ingest::statement_kid(&st).unwrap())
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
        diverged, 5,
        "I2366: the five stated divergences are replayed"
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
                    format!("invalid:{}", malformed_row::KID_NOT_OF_ISS),
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
    // R1 round 3 and R1-v2332: `rotation_without_own_statement` and
    // `record_by_other_key_only` wait here (stated divergences), so six of
    // the file's eight kid_not_of_iss cases refuse.
    assert_eq!(refused, 6, "I2367: the kid_not_of_iss cases ran");
}

// ─────────────────────────────────────────────────────────────────────────
//  v62.0.0 (R1, R1-v2332) — CIRISVerify 23.3.2's `key_of_iss_v3.json`
// ─────────────────────────────────────────────────────────────────────────

/// v62.0.0 (R1-v2332) — the number of cases in `key_of_iss_v3.json`
/// (CIRISVerify 23.3.2: v2's 31, re-signed with the possession voice as the
/// occurrence key, plus `possession_signed_as_identity`). Checked against the
/// tag by `FSD/v62_wip/parallel/R1-v2332-finalize.py`; I1850 pins the bytes.
const KEY_OF_ISS_V3_CASES: usize = 32;

/// A case whose directory holds a bundle's seats or waits on a bundle: not
/// replayed. Verify's seats carry their keys (`hold_bundle_in_force`);
/// persist's seat arm names kids and reads each seat's key from its
/// bundle-placed record ([`super::liveness::BundleSeats`]), so a vector's
/// bare seat list has no persist analogue.
fn needs_seats(c: &J) -> bool {
    !c["seats"].as_array().unwrap().is_empty() || c.get("pending_bundle_hex").is_some()
}

/// A case whose directory admits an occurrence or an eviction: replayed at
/// the store door ([`i4024_case`]), where persist's occurrence arm is loaded
/// from the store (I3020), never from a vector's list.
fn needs_occurrence_arm(c: &J) -> bool {
    !c["occurrences_hex"].as_array().unwrap().is_empty()
        || !c["evictions_hex"].as_array().unwrap().is_empty()
}

fn key_of_v3_file() -> J {
    serde_json::from_str(KEY_OF_ISS_V3).unwrap()
}

/// A verdict's class, as `key_of_iss_v3.json` compares it: `valid`, the
/// refusal with its token, or `waiting` (persist names a missing link by its
/// own reading, I2101, so a wait is compared as a wait).
fn v3_class(label: &str) -> String {
    if label.starts_with(concat!("waiting", ":")) {
        "waiting".to_owned()
    } else {
        label.to_owned()
    }
}

/// I4020 — `key_of_iss_v3.json` (CIRISVerify 23.3.2's, pinned by I1850)
/// carries [`KEY_OF_ISS_V3_CASES`] cases; each is replayed by records alone
/// (I4021), at the store door (I4024), or, holding a bundle's seats, not at
/// all ([`needs_seats`]).
#[test]
fn i4020_key_of_iss_v3_cases_are_replayed_or_named() {
    let f = key_of_v3_file();
    let cases = f["cases"].as_array().unwrap();
    assert_eq!(cases.len(), KEY_OF_ISS_V3_CASES, "I4020: the case list");
    let seats = cases.iter().filter(|c| needs_seats(c)).count();
    let store = cases
        .iter()
        .filter(|c| !needs_seats(c) && needs_occurrence_arm(c))
        .count();
    assert!(
        seats >= 1 && store >= 1,
        "I4020: {seats} seat, {store} store cases"
    );
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
fn i4021_key_of_iss_v3_through_persists_directory() {
    let f = key_of_v3_file();
    let mut replayed = 0usize;
    for c in f["cases"].as_array().unwrap() {
        let id = c["id"].as_str().unwrap();
        if needs_seats(c) || needs_occurrence_arm(c) {
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
            v3_class(&got),
            v3_class(expect),
            "I4021 {id}: Verify says {expect}, persist's reading {got}"
        );
        // The end rule at persist's door: refused by persist's token.
        if expect == concat!("invalid", ":valid_until_not_after_asserted_at") {
            let door = admit_row(&st, &held, None, SelectContext::default());
            assert_eq!(
                label(&door),
                format!(
                    "invalid{COLON}{}",
                    malformed_row::VALID_UNTIL_NOT_AFTER_ASSERTED_AT
                ),
                "I4021 {id} at the door"
            );
        }
        replayed += 1;
    }
    assert!(
        replayed >= 11,
        "I4021: the records-only cases ran ({replayed})"
    );
}

// ─────────────────────────────────────────────────────────────────────────
//  v62.0.0 (R1 round 3) — the four cases the tag added, where persist can
//  replay them
// ─────────────────────────────────────────────────────────────────────────

fn key_of_v3_case(id: &str) -> J {
    key_of_v3_file()["cases"]
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

/// I4023 — `occurrence_integer_key` (CIRISVerify 23.3.1 tag b0933ba and on): an
/// `identity:occurrence` payload with an integer-keyed member. Persist's
/// door refuses each of its statements by the family's closed payload map
/// (`edition2_payload_invalid`, "a member key is not text"; the open tail
/// is `* tstr => ceg-value`), so the occurrence never binds, and the case's
/// statement, signed by the device as the identity over the identity's and
/// the device's records alone, is `kid_not_of_iss`, Verify's answer.
#[test]
fn i4023_an_integer_keyed_occurrence_binds_nothing() {
    let c = key_of_v3_case("occurrence_integer_key");
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
        v3_class(&reader_label(&verify_row_statement(&st, &held))),
        v3_class(c["expect"].as_str().unwrap()),
        "I4023: {}",
        c["expect"]
    );
}

/// I4022 — `forged_record_does_not_unperson` at the store door
/// (`put_statement`), on sqlite and postgres: S files a `key:record` of A's
/// key saying `agent`. Whatever the door does with it, A's own key stays a
/// person's (its projection never reads `agent`), and the agent key E
/// signing as A is `kid_not_of_iss` over the store's own key plane
/// (`held_keys_for`), Verify's answer. (I4024 replays every occurrence and
/// eviction case, this one included, by the file's verdict; I4022 keeps the
/// projection half.)
///
/// v62.0.0 (R1-v2332) — R1-fix2's stated divergence on
/// `eviction_signer_not_held` (the CIRISVerify v23.3.1 vector signed the possession voice
/// as the identity) is closed: CIRISVerify 23.3.2 regenerates the file with
/// the possession voice signed as the occurrence key (CC rc21 90d537b), and
/// I4024 replays the case as the file says.
/// Its two store assertions (the eviction by a key not held lands no row; no
/// revocation is recorded for A) are kept, in I4024's leg for that case
/// (`i4024_case`, sqlite and postgres), where the clock is pinned.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn i4022_body(d: &dyn crate::federation::FederationDirectory) {
    use super::ingest::{held_keys_for, put_statement, INGEST_TIER};
    let put = |st: Vec<u8>| async move { put_statement(d, &st, None, INGEST_TIER).await };

    let c = key_of_v3_case("forged_record_does_not_unperson");
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
        v3_class(&reader_label(&verify_row_statement(&st, &held))),
        v3_class(c["expect"].as_str().unwrap()),
        "I4022 forged_record_does_not_unperson"
    );
}

/// I4024 (R1-v2332) — **every occurrence and eviction case of
/// `key_of_iss_v3.json` at the store door**, on sqlite and postgres, a fresh
/// store per case: its records, occurrence voices and evictions are put
/// through `put_statement` (the door's refusals and waits are the replay;
/// a voice refused until another voice is held is re-offered, up to three
/// passes), then the case's statement is read by Verify's reader over the
/// store's own key plane (`held_keys_for`, whose occurrence arm is persist's,
/// I3020). The class is the file's: valid, the refusal's token, or a wait.
///
/// The clock is pinned one second after the statement's instant (the
/// vector's instants are fixed; the past-freshness bound W is read from
/// this node's clock, CC 3.3.6.4). Needs the CIRISVerify 23.3.2 file: the
/// v23.3.1 one signed the possession voice as the identity.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) async fn i4024_case(d: &dyn crate::federation::FederationDirectory, c: &J) {
    use super::ingest::{held_keys_for, put_statement, INGEST_TIER};
    let id = c["id"].as_str().unwrap();
    let st = hx(&c["statement_hex"]);
    let at = super::liveness::statement_parts(&st)
        .and_then(|(_, p)| p.get_text("asserted_at").and_then(cde::Value::as_u64))
        .expect("I4024: the statement's instant");
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        i64::try_from(at).expect("I4024: an instant in range") + 1_000,
    )
    .expect("I4024: a clock instant");
    crate::federation::steward_purge::test_clock::set(Some(now));
    let mut pending: Vec<Vec<u8>> = hexes(c, "records_hex");
    pending.extend(hexes(c, "occurrences_hex"));
    pending.extend(hexes(c, "evictions_hex"));
    for _ in 0..3 {
        let mut again = Vec::new();
        for s in pending {
            if put_statement(d, &s, None, INGEST_TIER).await.is_err() {
                again.push(s);
            }
        }
        pending = again;
        if pending.is_empty() {
            break;
        }
    }
    let held = held_keys_for(d, &st).await.unwrap();
    let got = reader_label(&verify_row_statement(&st, &held));
    // I4022's store half (R1 round 3, kept): `eviction_signer_not_held`'s
    // eviction, signed by a key Z whose record is not held, is offered once
    // more under the pinned clock; the store facts are asserted below.
    let unheld_eviction = if id == "eviction_signer_not_held" {
        let evictions = hexes(c, "evictions_hex");
        assert_eq!(evictions.len(), 1, "I4022: one eviction");
        let landed = put_statement(d, &evictions[0], None, INGEST_TIER).await;
        let a_ref = hexes(c, "records_hex")
            .first()
            .and_then(|r| super::liveness::statement_parts(r))
            .and_then(|(protected, _)| {
                protected
                    .get_int(15)?
                    .get_int(1)?
                    .as_text()
                    .map(str::to_owned)
            })
            .expect("I4022: A's iss");
        let revocations = d
            .list_identity_occurrence_revocations_for(&a_ref)
            .await
            .unwrap();
        Some((landed, revocations.len()))
    } else {
        None
    };
    crate::federation::steward_purge::test_clock::set(None);
    assert_eq!(
        v3_class(&got),
        v3_class(c["expect"].as_str().unwrap()),
        "I4024 {id}: Verify says {}, persist's store reads {got}",
        c["expect"]
    );
    // I4022 `eviction_signer_not_held`, the store stays clean: the verdict
    // above says the eviction evicted nothing; these say it never landed.
    if let Some((landed, revocations)) = unheld_eviction {
        assert!(
            !matches!(landed, Ok(super::ingest::StatementOutcome::Row { .. })),
            "I4022: an eviction by a key not held lands nothing: {landed:?}"
        );
        assert_eq!(revocations, 0, "I4022: no revocation is recorded for A");
    }
}

/// The I4024 cases: an occurrence or an eviction, and no bundle seats.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
fn i4024_cases() -> Vec<J> {
    let cases: Vec<J> = key_of_v3_file()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| !needs_seats(c) && needs_occurrence_arm(c))
        .cloned()
        .collect();
    assert!(
        cases.len() >= 15,
        "I4024: the store cases ({})",
        cases.len()
    );
    assert!(
        cases.iter().any(|c| c["id"] == "eviction_signer_not_held"),
        "I4022: the case whose store half I4024 carries is replayed"
    );
    cases
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i4024_sqlite() {
    use crate::store::Backend as _;
    for c in i4024_cases() {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(i4024_case(&b, &c)).await;
    }
}

#[cfg(feature = "postgres")]
#[tokio::test]
async fn i4024_postgres() {
    use crate::store::Backend as _;
    for c in i4024_cases() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(i4024_case(&b, &c)).await;
    }
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
