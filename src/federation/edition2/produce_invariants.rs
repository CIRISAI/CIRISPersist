//! v62.0.0 (slice J0) — the producer primitive and the test codec.
//!
//! - **I2010 (`sign_row`).** A row signed with persist's own composite signer
//!   ([`super::produce::sign_row`], through `LocalSigner::sign_composite`)
//!   equals Verify's `sign_row_statement` over the same keys byte for byte,
//!   and the door admits it. A signer with no PQC half refuses by name.
//! - **I2011 (the codec round trip).** For each family the codec is checked
//!   on (the evidence `scores` family, `key:revocation`): a statement through
//!   [`super::codec::row_of`] and back through [`super::codec::statement_of`]
//!   is the same bytes; an earlier-form-shaped literal row through
//!   `statement_of` and `row_of` keeps its envelope (less the statement and
//!   the mirror), its type and its subject. [`super::codec::kid`] is the
//!   identity-ref `local_signer` signs as.
//! - **I2012 (`sign_object`).** An object voice signed with persist's signer
//!   equals the hand-built voice E2a's genesis witnesses read, byte for byte,
//!   and Verify's object reader finds it Valid under the signer's record.

use std::sync::Arc;

use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::{sign_row_statement, verify_object_statement, ObjectVerdict};

use super::codec::{key_for, kid as kid_of, row_of, statement_of};
use super::door::admit_row;
use super::door_invariants::fixture::{iref, key, key_record, map};
use super::genesis::GENESIS_BUNDLE_TYP;
use super::ingest::INGEST_TIER;
use super::liveness::HeldKeys;
use super::produce::{sign_object, sign_row, signer_identity, ProduceError};

/// The [`LocalSigner`](crate::signing::LocalSigner) over E2a's fixture key
/// `key(n)`: ML-DSA-65 seed `[n; 32]`, Ed25519 seed `[n + 100; 32]`.
fn local(n: u8) -> crate::signing::LocalSigner {
    let pqc = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[n; 32], "j0-pqc").unwrap();
    crate::signing::LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[n.wrapping_add(100); 32]),
        "j0".into(),
        Some(Arc::new(pqc)),
        Some("j0-pqc".into()),
    )
}

fn score_payload(author: &str, at: u64) -> Value {
    map(vec![
        ("asserted_at", Value::Uint(at)),
        ("author", Value::Text(author.to_owned())),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        (
            "dimension",
            Value::Text("evidence:safety_battery:capture:a:b:v1".into()),
        ),
    ])
}

const EVIDENCE_ROWS: &str = "evidence:.suite:.kind:.cell:.prefix";

#[tokio::test]
async fn i2010_sign_row_is_verifys_minter_and_the_door_admits_it() {
    let k = key(80);
    let signer = local(80);
    let (_, iss) = signer_identity(&signer).await.unwrap();
    assert_eq!(
        iss,
        iref(&k),
        "I2010: the signer signs as its composite's identity-ref"
    );
    let payload = score_payload(&iss, 5_000);
    let ours = sign_row(&signer, &iss, "scores", EVIDENCE_ROWS, &payload)
        .await
        .unwrap();
    let verifys =
        sign_row_statement(&k, &iss, &iss, "scores", EVIDENCE_ROWS, &payload, vec![]).unwrap();
    assert_eq!(ours, verifys, "I2010: byte for byte");
    let mut keys = HeldKeys::new();
    keys.insert_record(key_record(&k, &["user"], 0, None));
    let admitted = admit_row(&ours, &keys, None, SelectContext::default()).unwrap();
    assert_eq!(admitted.iss, iss);
    // With validity bounds: nbf / exp come from the payload.
    let bounded = map(vec![
        ("asserted_at", Value::Uint(5_000)),
        ("author", Value::Text(iss.clone())),
        ("valid_from", Value::Uint(6_000)),
        ("valid_until", Value::Uint(9_000)),
    ]);
    assert_eq!(
        sign_row(&signer, &iss, "scores", "key:revocation", &bounded)
            .await
            .unwrap(),
        sign_row_statement(&k, &iss, &iss, "scores", "key:revocation", &bounded, vec![]).unwrap(),
        "I2010: the time claims"
    );
    // A payload with no instant, and a signer with no PQC half, refuse.
    let none = map(vec![("author", Value::Text(iss.clone()))]);
    assert!(matches!(
        sign_row(&signer, &iss, "scores", EVIDENCE_ROWS, &none).await,
        Err(ProduceError::Payload(_))
    ));
    let classical_only = crate::signing::LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
        "j0-classical".into(),
        None,
        None,
    );
    assert!(matches!(
        sign_row(&classical_only, &iss, "scores", EVIDENCE_ROWS, &payload).await,
        Err(ProduceError::Signer(
            crate::signing::LocalSignerError::PqcNotConfigured
        ))
    ));
}

#[tokio::test]
async fn i2010_the_test_key_ids_name_the_test_signers() {
    let signer = crate::federation::tier_ingest::test_support::local_signer("j0-k1");
    let (_, iss) = signer_identity(&signer).await.unwrap();
    assert_eq!(
        iss,
        kid_of("j0-k1"),
        "I2010: kid() is local_signer's identity-ref"
    );
    let payload = score_payload(&iss, 7_000);
    assert_eq!(
        sign_row(&signer, &iss, "scores", EVIDENCE_ROWS, &payload)
            .await
            .unwrap(),
        sign_row_statement(
            &key_for("j0-k1"),
            &iss,
            &iss,
            "scores",
            EVIDENCE_ROWS,
            &payload,
            vec![]
        )
        .unwrap(),
        "I2010: key_for() is local_signer's composite"
    );
}

#[test]
fn i2011_the_codec_round_trips() {
    let k = key_for("j0-codec");
    let me = kid_of("j0-codec");
    let other = kid_of("j0-other");
    // Statement → row → statement, per family.
    let cases: Vec<(Vec<u8>, &str)> = vec![
        (
            sign_row_statement(
                &k,
                &me,
                &me,
                "scores",
                EVIDENCE_ROWS,
                &score_payload(&me, 5_000),
                vec![],
            )
            .unwrap(),
            EVIDENCE_ROWS,
        ),
        (
            sign_row_statement(
                &k,
                &me,
                &other,
                "scores",
                "key:revocation",
                &map(vec![
                    ("asserted_at", Value::Uint(6_000)),
                    ("author", Value::Text(me.clone())),
                    ("revoked_after", Value::Uint(7_000)),
                ]),
                vec![],
            )
            .unwrap(),
            "key:revocation",
        ),
    ];
    for (st, family) in &cases {
        let row = row_of(st, &k, INGEST_TIER).unwrap();
        assert_eq!(
            &statement_of(&row, family, &k),
            st,
            "I2011: {family}: statement → row → statement"
        );
        assert_eq!(super::codec::rid(&row), row.persist_row_hash, "I2011: rid");
    }
    // An earlier-form-shaped literal row → statement → row.
    let literal: crate::federation::types::Attestation =
        serde_json::from_value(serde_json::json!({
            "attestation_id": "literal",
            "attesting_key_id": "k1",
            "attested_key_id": me,
            "attestation_type": "scores",
            "asserted_at": "2026-01-02T03:04:05.678Z",
            "attestation_envelope": {
                "dimension": "evidence:safety_battery:capture:a:b:v1",
                "score": 0.75,
                "confidence": 0.9,
            },
            "original_content_hash": "",
            "scrub_signature_classical": "",
            "scrub_key_id": "k1",
            "scrub_timestamp": "2026-01-02T03:04:05.678Z",
            "persist_row_hash": "",
        }))
        .unwrap();
    let st = statement_of(&literal, EVIDENCE_ROWS, &k);
    let row = row_of(&st, &k, INGEST_TIER).unwrap();
    let strip = |a: &crate::federation::types::Attestation| {
        let mut e = a.attestation_envelope.clone();
        let o = e.as_object_mut().unwrap();
        o.remove(super::ingest::STATEMENT_MEMBER);
        o.remove("row");
        o.remove("author");
        o.remove("asserted_at");
        e
    };
    assert_eq!(strip(&row), strip(&literal), "I2011: the envelope survives");
    assert_eq!(row.attestation_type, literal.attestation_type);
    assert_eq!(row.attested_key_id, literal.attested_key_id);
    assert_eq!(
        row.asserted_at, literal.asserted_at,
        "I2011: the row's instant"
    );
    assert_eq!(
        row.attesting_key_id, me,
        "I2011: the signer signs as itself"
    );
    assert_eq!(statement_of(&row, EVIDENCE_ROWS, &k), st, "I2011: and back");
}

#[tokio::test]
async fn i2012_sign_object_is_the_voice_the_genesis_reader_reads() {
    let k = key(81);
    let signer = local(81);
    let payload = map(vec![
        ("version", Value::Uint(1)),
        ("asserted_at", Value::Uint(4_000)),
    ]);
    let ours = sign_object(&signer, GENESIS_BUNDLE_TYP, &payload, Some(4))
        .await
        .unwrap();
    assert_eq!(
        ours,
        super::genesis_invariants::voice_over(&k, &payload, Some(4)),
        "I2012: byte for byte"
    );
    let mut keys = HeldKeys::new();
    keys.insert_record(key_record(&k, &["user"], 0, None));
    assert!(
        matches!(
            verify_object_statement(&ours, &keys),
            ObjectVerdict::Valid(_)
        ),
        "I2012: Verify's object reader"
    );
    assert!(matches!(
        sign_object(&signer, GENESIS_BUNDLE_TYP, &Value::Uint(1), None).await,
        Err(ProduceError::Payload(_))
    ));
}

/// **I2013 (the kernel reads an edition-2 row by its own bytes).** The
/// adapter's view of a stored edition-2 row has the row id this node computes
/// from the carried statement and names exactly the row ids of its signed
/// `refs`; a peer-chosen `persist_row_hash` / `attestation_id` on the stored
/// row changes neither. An earlier-form row keeps its `persist_row_hash` id
/// until the JSON cut.
#[test]
fn i2013_the_kernel_reads_an_edition2_rows_own_id_and_refs() {
    use super::door_invariants::fixture::ref2;
    use crate::kernel::view::{attestation_view, row_id, RowId as KId};
    let k = key_for("j0-kernel");
    let me = kid_of("j0-kernel");
    let payload = map(vec![
        ("asserted_at", Value::Uint(5_000)),
        ("author", Value::Text(me.clone())),
        ("score", Value::Uint(750_000)),
        ("confidence", Value::Uint(900_000)),
        (
            "dimension",
            Value::Text("evidence:safety_battery:capture:a:b:v1".into()),
        ),
        (
            "refs",
            map(vec![(
                "also",
                map(vec![("cites", Value::Array(vec![ref2(&[0x31; 32])]))]),
            )]),
        ),
    ]);
    let st = sign_row_statement(&k, &me, &me, "scores", EVIDENCE_ROWS, &payload, vec![]).unwrap();
    let row = row_of(&st, &k, INGEST_TIER).unwrap();
    let mut keys = HeldKeys::new();
    keys.insert_record(key_record(&k, &["user"], 0, None));
    let computed = admit_row(&st, &keys, None, SelectContext::default())
        .unwrap()
        .row_id;
    let view = attestation_view(&row, &|_| None);
    assert_eq!(view.id, KId(computed.0), "I2013: the node-computed row id");
    assert_eq!(
        view.names,
        vec![KId([0x31; 32])],
        "I2013: the refs, and only them"
    );
    let mut forged = row.clone();
    forged.persist_row_hash = "ab".repeat(32);
    forged.attestation_id = "ab".repeat(32);
    assert_eq!(
        row_id(&forged),
        KId(computed.0),
        "I2013: a stated id is never read"
    );
    let mut earlier = row.clone();
    earlier
        .attestation_envelope
        .as_object_mut()
        .unwrap()
        .remove(super::ingest::STATEMENT_MEMBER);
    earlier.persist_row_hash = "cd".repeat(32);
    assert_eq!(
        row_id(&earlier),
        KId([0xcd; 32]),
        "I2013: the earlier form, until the cut"
    );
}
