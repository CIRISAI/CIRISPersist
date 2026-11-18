//! v62.0.0 (wave T2) — **the typed planes' mapping, both ways** (pure: no
//! store). Each statement is built by the module's own payload writer,
//! admitted by the edition-2 door over the signer's key record, and read
//! back by the JSON form's OWN parser of the typed row, so a member the
//! projection misnames is a parser refusal here, not a silent gap.
//!
//! - **I3140** each family's header id is its typed plane; a composer of it
//!   and every other family are not.
//! - **I3141** a custody report reads back through `parse_custody_ack` (the
//!   gate's and the fold's parse); a family report's `family_id` is the
//!   cohort target the gate reads (`family_key_id`).
//! - **I3142** a key grant on each axis reads back through
//!   `KeyGrantRow::from_attestation` as the row it was written from.
//! - **I3143** a takedown notice reads back through `notice_row_shape`.
//! - **I3144** a delivery receipt's `chunk_root` reads back as hex, and
//!   every attestation-backed family's mapped row is the projection
//!   `check_carried_projection` re-derives (one projection).
//! - **I3145** a revocation's envelope carries the binding the revocation
//!   door checks; its reason is the `{reason}` leaf.
//! - **I3147** a revocation states `refs.head` and `refs.further_heads` (a
//!   set) as names.
//! - **I3146** an occurrence revocation reads back; an `occurrence_key_id`
//!   that is not the row's `sub` is `edition2_payload_invalid`.

use chrono::{TimeZone, Utc};
use ciris_crypto::composite::CompositeSigningKey;
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::sign_row_statement;
use ciris_verify_core::namespace_match::family_id;

use super::door::{admit_row, AdmittedRow};
use super::door_invariants::fixture::{holding, iref, key};
use super::ingest::{attestation_of, check_carried_projection, INGEST_TIER};
use super::typed::{
    custody_payload, delivery_receipt_payload, key_grant_payload, occurrence_revocation_of,
    occurrence_revocation_payload, revocation_of, revocation_payload, takedown_payload,
    typed_plane_of, NoticeText, TypedPlane, CUSTODY_PREFIX, DELIVERY_RECEIPT_PREFIX,
    KEY_GRANT_PREFIX, OCCURRENCE_REVOCATION_PREFIX, PLANES, REVOCATION_PREFIX, TAKEDOWN_PREFIX,
};
use crate::federation::blobs::GrantWrap;
use crate::federation::custody_ack::{parse_custody_ack, CustodyState};
use crate::federation::key_grant::{KeyGrantAxis, KeyGrantRow};
use crate::federation::types::IdentityOccurrenceRevocation;
use crate::federation::{malformed_row, Error};

type K = CompositeSigningKey;

fn at(ms: i64) -> chrono::DateTime<Utc> {
    Utc.timestamp_millis_opt(ms).single().unwrap()
}

/// `k` signs `p` under `prefix`'s family id about `sub`; the door admits it
/// over `k`'s own key record.
fn admitted(k: &K, sub: &str, prefix: &str, p: &Value) -> AdmittedRow {
    let st = sign_row_statement(k, &iref(k), sub, "scores", &family_id(prefix), p, vec![])
        .expect("sign");
    admit_row(&st, &holding(&[k]), None, SelectContext::default()).expect("the door admits it")
}

fn reason(e: &Error) -> String {
    match e {
        Error::MalformedRow { reason, .. } => (*reason).to_owned(),
        other => other.kind().to_owned(),
    }
}

fn notice() -> NoticeText {
    NoticeText {
        claim_text: "a claim".into(),
        good_faith_statement: "in good faith".into(),
        jurisdiction: "US".into(),
    }
}

/// I3140.
#[test]
fn i3140_each_family_is_its_typed_plane() {
    for (prefix, plane) in PLANES {
        assert_eq!(
            typed_plane_of("scores", &family_id(prefix)),
            Some(plane),
            "I3140 {prefix}"
        );
        for composer in ["withdraws", "recants", "supersedes"] {
            assert_eq!(
                typed_plane_of(composer, &family_id(prefix)),
                None,
                "I3140 a {composer} of {prefix} is the attestation plane's"
            );
        }
    }
    for other in ["group:roster", "identity:occurrence", "key:record"] {
        assert_eq!(
            typed_plane_of("scores", &family_id(other)),
            None,
            "I3140 {other}"
        );
    }
    assert_eq!(PLANES.len(), 7);
    assert!(PLANES.iter().any(|(_, p)| *p == TypedPlane::Cosign));
}

/// I3141.
#[test]
fn i3141_a_custody_report_reads_back_through_the_gates_parse() {
    let dev = key(31);
    let d = iref(&dev);
    let blob = [0x5a; 32];
    let p = custody_payload(
        &d,
        &blob,
        CustodyState::Here,
        Some(4096),
        "federation",
        None,
        1_000,
    )
    .unwrap();
    let a = attestation_of(&admitted(&dev, &d, CUSTODY_PREFIX, &p), INGEST_TIER).unwrap();
    let ack = parse_custody_ack(&a)
        .expect("I3141 well formed")
        .expect("I3141 a custody report");
    assert_eq!(ack.blob_sha256_hex, hex::encode(blob), "I3141 the address");
    assert_eq!(ack.state, CustodyState::Here, "I3141 the state");
    assert_eq!(ack.size, Some(4096), "I3141 the size");
    assert_eq!(ack.device_key_id, d, "I3141 the device");
    check_carried_projection(&a).expect("I3144 one projection (custody)");

    let fam = iref(&key(32));
    let p = custody_payload(
        &d,
        &blob,
        CustodyState::None,
        None,
        "family",
        Some(&fam),
        1_000,
    )
    .unwrap();
    let a = attestation_of(&admitted(&dev, &d, CUSTODY_PREFIX, &p), INGEST_TIER).unwrap();
    assert_eq!(
        crate::federation::admission::envelope_cohort_target(&a.attestation_envelope).unwrap(),
        Some(fam.as_str()),
        "I3141 the family is the cohort target the custody gate reads"
    );
    assert!(
        a.attestation_envelope.get("family_id").is_none(),
        "I3141 the CC 2.1 member is renamed, not doubled"
    );
    assert_eq!(
        parse_custody_ack(&a).unwrap().unwrap().state,
        CustodyState::None,
        "I3141 a none report"
    );
}

/// I3142.
#[test]
fn i3142_a_key_grant_reads_back_as_its_row_on_each_axis() {
    let owner = key(41);
    let o = iref(&owner);
    let rcpt = iref(&key(42));
    let wrap = GrantWrap {
        recipient_key_id: rcpt.clone(),
        wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.to_owned(),
        wrapped_dek: "{\"v\":2,\"ct\":\"AAAA\"}".to_owned(),
    };
    let community = iref(&key(43));
    let axes = [
        KeyGrantAxis::Content {
            at_rest_sha256: hex::encode([0x61; 32]),
            cohort_scope: "self".into(),
            owner_key_id: o.clone(),
        },
        KeyGrantAxis::Epoch {
            community_key_id: community.clone(),
            minter_key_id: o.clone(),
            epoch: 3,
        },
        KeyGrantAxis::Stream {
            stream_id: "t2-stream".into(),
            epoch: 2,
            cohort_scope: "community".into(),
            owner_key_id: o.clone(),
        },
    ];
    for axis in axes {
        let row = KeyGrantRow {
            axis,
            wrap: wrap.clone(),
        };
        let p = key_grant_payload(&o, &row, 1_000).unwrap();
        let a =
            attestation_of(&admitted(&owner, &rcpt, KEY_GRANT_PREFIX, &p), INGEST_TIER).unwrap();
        assert_eq!(
            KeyGrantRow::from_attestation(&a).expect("I3142 the grant gate's parse"),
            row,
            "I3142 {}",
            row.axis.token()
        );
        check_carried_projection(&a).expect("I3144 one projection (key grant)");
    }
}

/// I3143.
#[test]
fn i3143_a_takedown_notice_reads_back_through_the_notice_shape() {
    let c = key(51);
    let ci = iref(&c);
    let holder = iref(&key(52));
    let p = takedown_payload(
        "dmca512",
        &ci,
        &[0x71; 32],
        std::slice::from_ref(&holder),
        &notice(),
        9_000_000,
        1_000,
    )
    .unwrap();
    let a = attestation_of(&admitted(&c, &ci, TAKEDOWN_PREFIX, &p), INGEST_TIER).unwrap();
    let shape = crate::federation::takedown_tombstone::notice_row_shape(&a)
        .expect("I3143 the notice gate reads the projected envelope");
    assert_eq!(shape.content_sha256, hex::encode([0x71; 32]), "I3143");
    assert_eq!(shape.legal_basis, "dmca512", "I3143");
    assert_eq!(
        a.attestation_envelope["content_holder_key_ids"],
        serde_json::json!([holder]),
        "I3143 the holders under their earlier name"
    );
    check_carried_projection(&a).expect("I3144 one projection (takedown)");
}

/// I3144.
#[test]
fn i3144_a_delivery_receipt_states_its_root_as_hex() {
    let s = key(81);
    let si = iref(&s);
    let p = delivery_receipt_payload(&si, "t2-stream", 2, 17, &[0x3a; 32], 1_000);
    let a = attestation_of(&admitted(&s, &si, DELIVERY_RECEIPT_PREFIX, &p), INGEST_TIER).unwrap();
    assert_eq!(
        a.attestation_envelope["chunk_root"],
        serde_json::json!(hex::encode([0x3a; 32])),
        "I3144"
    );
    check_carried_projection(&a).expect("I3144 one projection (receipt)");
}

/// I3145.
#[test]
fn i3145_a_revocation_carries_the_doors_binding() {
    let r = key(61);
    let ri = iref(&r);
    let s = iref(&key(62));
    let p = revocation_payload(
        &ri,
        "agent",
        "compromise",
        at(1_000),
        at(2_000),
        Some(at(500)),
        None,
        None,
        3_000,
    )
    .unwrap();
    let row = admitted(&r, &s, REVOCATION_PREFIX, &p);
    let digest = "ab".repeat(32);
    let rev = revocation_of(&row, &digest).unwrap();
    crate::federation::admission::check_revocation_envelope_binding(&rev)
        .expect("I3145 the binding the revocation door checks");
    assert_eq!(rev.revocation_id, row.row_id.hex(), "I3145 the id");
    assert_eq!(rev.revoking_key_id, ri, "I3145 the revoker");
    assert_eq!(rev.revoked_key_id.as_deref(), Some(s.as_str()), "I3145");
    assert_eq!(rev.revoked_key_sha256_ed25519_raw, digest, "I3145");
    assert_eq!(rev.reason.as_deref(), Some("compromise"), "I3145 the leaf");
    assert_eq!(rev.revoked_after, Some(at(500)), "I3145");
    assert_eq!(
        rev.scrub_signature_pqc.as_deref(),
        Some(rev.scrub_signature_classical.as_str()),
        "I3145 the marker in both columns"
    );
}

/// I3146.
#[test]
fn i3146_an_occurrence_revocation_reads_back() {
    let id = key(71);
    let occ = iref(&key(72));
    let rev = IdentityOccurrenceRevocation {
        identity_key_id: iref(&id),
        occurrence_key_id: occ.clone(),
        revoked_at: at(1_000),
        effective_at: at(2_000),
        reason: None,
        witness_set: vec![],
        persist_row_hash: String::new(),
    };
    let p = occurrence_revocation_payload(
        &rev,
        &iref(&id),
        Some(3),
        &super::names::RowId([3; 32]),
        &[],
        3_000,
    )
    .unwrap();
    let got =
        occurrence_revocation_of(&admitted(&id, &occ, OCCURRENCE_REVOCATION_PREFIX, &p)).unwrap();
    assert_eq!(got.identity_key_id, iref(&id), "I3146");
    assert_eq!(got.occurrence_key_id, occ, "I3146");
    assert_eq!(got.effective_at, at(2_000), "I3146");
    assert_eq!(got.reason.as_deref(), Some("3"), "I3146 the code");
    let other = iref(&key(73));
    let e = occurrence_revocation_of(&admitted(&id, &other, OCCURRENCE_REVOCATION_PREFIX, &p))
        .unwrap_err();
    assert_eq!(
        reason(&e),
        malformed_row::EDITION2_PAYLOAD_INVALID,
        "I3146 the occurrence is the row's sub"
    );
}

/// I3147 — an occurrence revocation states its head, and the further tips it
/// merges as a set (`refs.further_heads`, sorted and unique), both read back
/// as the payload's names.
#[test]
fn i3147_a_revocation_names_its_head_and_further_heads() {
    use super::names::{names_of, RowId};
    let id = key(74);
    let rev = IdentityOccurrenceRevocation {
        identity_key_id: iref(&id),
        occurrence_key_id: iref(&key(75)),
        revoked_at: at(1_000),
        effective_at: at(1_000),
        reason: None,
        witness_set: vec![],
        persist_row_hash: String::new(),
    };
    let (head, f1, f2) = (RowId([1; 32]), RowId([2; 32]), RowId([3; 32]));
    let p =
        occurrence_revocation_payload(&rev, &iref(&id), None, &head, &[f2, f1, f2], 2_000).unwrap();
    let names = names_of(&p).expect("I3147 the refs read");
    let role = |r: &str| -> Vec<RowId> {
        names
            .iter()
            .filter(|n| n.role == r)
            .map(|n| n.row)
            .collect()
    };
    assert_eq!(role("head"), vec![head], "I3147 refs.head");
    let mut further = role("further_heads");
    further.sort();
    assert_eq!(further, vec![f1, f2], "I3147 refs.further_heads, a set");
    let plain = occurrence_revocation_payload(&rev, &iref(&id), None, &head, &[], 2_000).unwrap();
    assert!(
        names_of(&plain)
            .unwrap()
            .iter()
            .all(|n| n.role != "further_heads"),
        "I3147 no further_heads when none is merged"
    );
}
