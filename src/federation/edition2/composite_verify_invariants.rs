//! v62.0.0 (JSON-cut slice F, F0-cp5) — **the one directory-backed composite
//! verifier** ([`verify_composite_via_directory`]), witnessed on sqlite AND
//! postgres (I2877–I2881, I2885).
//!
//! RULINGS: "Composite signatures only. There are no standalone component
//! signers." Every refusal is by name, and only the waits are retryable.

use super::composite_verify::{
    verify_composite_via_directory, CompositeVerifyError, VERIFY_COMPONENT_SIGNATURE,
    VERIFY_COMPOSITE_INVALID, VERIFY_NOT_IDENTITY_REF, VERIFY_SIGNER_NOT_COVERED,
    VERIFY_SIGNER_REVOKED, VERIFY_SIGNER_WAITING, VERIFY_UNKNOWN_KEY,
};
use super::fixture_switch as e2;
use crate::federation::FederationDirectory;

/// A live `user` key.
const LIVE: &str = "f0-cp5-live";
/// A `node` key: its record has a window, so an instant before it is not
/// covered.
const NODE: &str = "f0-cp5-node";
/// A key that revokes itself.
const REVOKED: &str = "f0-cp5-revoked";
/// A key whose record is signed by [`ABSENT`], whose own record is never put.
const WAITING: &str = "f0-cp5-waiting";
/// Never put.
const ABSENT: &str = "f0-cp5-absent-signer";
/// Never put: a well-formed identity-ref this node does not hold.
const NEVER_HELD: &str = "f0-cp5-never-held";

const MSG: &[u8] = b"F0-cp5: the bytes a composite is over";

fn sign(seed: &str, msg: &[u8]) -> Vec<u8> {
    e2::signing_key(seed).sign(msg).expect("composite sign")
}

fn now() -> u64 {
    e2::ms(crate::host::clock::now())
}

async fn refusal<D: FederationDirectory + ?Sized>(
    d: &D,
    who: &str,
    sig: &[u8],
    at: u64,
    what: &str,
) -> CompositeVerifyError {
    match verify_composite_via_directory(d, MSG, who, sig, at).await {
        Ok(s) => panic!("{what}: verified as {}", s.identity_ref),
        Err(e) => e,
    }
}

async fn body(d: &dyn FederationDirectory) {
    let live = e2::put_key(d, LIVE, &["user"]).await;

    // ── I2877: a composite by a live edition-2 key verifies ──
    let ok = verify_composite_via_directory(d, MSG, &live, &sign(LIVE, MSG), now())
        .await
        .unwrap_or_else(|e| panic!("I2877: a live key's composite verifies: {e}"));
    assert_eq!(ok.identity_ref, live, "I2877: the signer named");
    assert_eq!(
        ok.record.kid,
        e2::kid_digest(LIVE),
        "I2877: its live record"
    );

    // ── I2878: a lone component half is refused by name, before any key
    //    is read (a never-held signer still answers the component token);
    //    a composite over other bytes, or with a byte flipped, is invalid ──
    for (len, what) in [
        (64, "a lone Ed25519 half"),
        (
            ciris_crypto::composite::MLDSA65_SIG_LEN,
            "a lone ML-DSA-65 half",
        ),
    ] {
        for who in [live.clone(), e2::kid(NEVER_HELD)] {
            let e = refusal(d, &who, &vec![7u8; len], now(), "I2878").await;
            assert_eq!(e.token(), VERIFY_COMPONENT_SIGNATURE, "I2878 {what}: {e}");
            assert!(!e.is_retryable(), "I2878 {what}: final");
        }
    }
    let mut flipped = sign(LIVE, MSG);
    flipped[100] ^= 0x01;
    let e = refusal(d, &live, &flipped, now(), "I2878 flipped").await;
    assert_eq!(e.token(), VERIFY_COMPOSITE_INVALID, "I2878 flipped: {e}");
    let e = refusal(d, &live, &sign(LIVE, b"other bytes"), now(), "I2878").await;
    assert_eq!(
        e.token(),
        VERIFY_COMPOSITE_INVALID,
        "I2878 other bytes: {e}"
    );
    let e = refusal(d, &live, &[0u8; 10], now(), "I2878 short").await;
    assert_eq!(e.token(), VERIFY_COMPOSITE_INVALID, "I2878 short: {e}");

    // ── I2879: an unknown key and a non-identity-ref are refused by name;
    //    neither is a wait ──
    let never = e2::kid(NEVER_HELD);
    let e = refusal(d, &never, &sign(NEVER_HELD, MSG), now(), "I2879").await;
    assert_eq!(e.token(), VERIFY_UNKNOWN_KEY, "I2879 unknown: {e}");
    assert!(!e.is_retryable(), "I2879 unknown: final");
    for label in ["cirislens-edge-test-1", "AAAA", ""] {
        let e = refusal(d, label, &sign(LIVE, MSG), now(), "I2879").await;
        assert_eq!(e.token(), VERIFY_NOT_IDENTITY_REF, "I2879 {label:?}: {e}");
    }

    // ── I2880: a revoked key is refused by name, final ──
    let revoked = e2::put_key(d, REVOKED, &["user"]).await;
    verify_composite_via_directory(d, MSG, &revoked, &sign(REVOKED, MSG), now())
        .await
        .unwrap_or_else(|e| panic!("I2880 control: live before the revocation: {e}"));
    e2::put_statement(d, &e2::key_revocation(REVOKED, REVOKED, None))
        .await
        .expect("I2880: the self-revocation is admitted");
    let e = refusal(d, &revoked, &sign(REVOKED, MSG), now(), "I2880").await;
    assert_eq!(e.token(), VERIFY_SIGNER_REVOKED, "I2880: {e}");
    assert!(!e.is_retryable(), "I2880: final");

    // ── I2881: a record waiting on a key not held, and an instant no record
    //    covers, are retryable waits ──
    e2::put_statement(
        d,
        &e2::key_record_with(
            WAITING,
            &["user"],
            &e2::KeyRecordOptions {
                signer: Some(ABSENT.to_owned()),
                ..Default::default()
            },
        ),
    )
    .await
    .expect("I2881: a record by an unheld signer is filed");
    let waiting = e2::kid(WAITING);
    let e = refusal(d, &waiting, &sign(WAITING, MSG), now(), "I2881").await;
    assert_eq!(e.token(), VERIFY_SIGNER_WAITING, "I2881 waiting: {e}");
    assert!(e.is_retryable(), "I2881 waiting: retryable");

    let node = e2::put_key(d, NODE, &["node"]).await;
    verify_composite_via_directory(d, MSG, &node, &sign(NODE, MSG), now())
        .await
        .unwrap_or_else(|e| panic!("I2881 control: the node key is live now: {e}"));
    let e = refusal(d, &node, &sign(NODE, MSG), 1, "I2881 not covered").await;
    assert_eq!(
        e.token(),
        VERIFY_SIGNER_NOT_COVERED,
        "I2881 not covered: {e}"
    );
    assert!(e.is_retryable(), "I2881 not covered: retryable");

    // ── I2885 (both backends): the capsule's composite op answers as the
    //    direct call; the retired bound-hybrid op is refused by name ──
    use crate::ffi::directory_capsule::{dispatch_directory_op, DirectoryOp, DirectoryOpResult};
    let op = |sig: Vec<u8>, who: &str, at: u64| DirectoryOp::VerifyCompositeViaDirectory {
        message: MSG.to_vec(),
        identity_ref: who.to_owned(),
        composite_sig: sig,
        at_ms: at,
    };
    match dispatch_directory_op(d, op(sign(LIVE, MSG), &live, now())).await {
        DirectoryOpResult::CompositeVerify(Ok(who)) => assert_eq!(who, live, "I2885"),
        other => panic!("I2885: a live key's composite verifies through the op: {other:?}"),
    }
    match dispatch_directory_op(d, op(sign(WAITING, MSG), &waiting, now())).await {
        DirectoryOpResult::CompositeVerify(Err(r)) => {
            assert_eq!(r.token, VERIFY_SIGNER_WAITING, "I2885: {r:?}");
            assert!(r.retryable, "I2885: a wait crosses the capsule as a wait");
        }
        other => panic!("I2885: the wait rides inside CompositeVerify: {other:?}"),
    }
    let retired = DirectoryOp::VerifyHybridViaDirectory {
        canonical_bytes: MSG.to_vec(),
        signing_key_id: live.clone(),
        ed25519_sig_b64: "AAAA".into(),
        ml_dsa_65_sig_b64: None,
        policy: crate::verify::hybrid::HybridPolicy::Strict,
        row_age: None,
    };
    match dispatch_directory_op(d, retired).await {
        DirectoryOpResult::TypedErr(e) => assert!(
            format!("{e:?}").contains("verify_hybrid_via_directory"),
            "I2885: the retired op is refused by name: {e:?}"
        ),
        other => panic!("I2885: the retired op is refused: {other:?}"),
    }
}

/// v62.0.0 (F0-cp5b; CC 6.1.3) — **I2887: a CC 6.1 object (the wholeness
/// witness) is admitted on ONE composite over its own binary preimage, and a
/// lone half or the earlier bound-hybrid pair is refused by name.** The
/// exemption CC 6.1 carries is the preimage form (no COSE), never the
/// signature. Through the trait door, as a host would reach it.
async fn wholeness(d: &dyn FederationDirectory) {
    use crate::verify::sig19::{Sig19, Sig19Error};
    use crate::witness::{build_local_witness, WitnessLeaf};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    const PRODUCER: &str = "f0-cp5b-witness-producer";
    let key = e2::signing_key(PRODUCER);
    let pk = key.public_key().as_bytes();
    let (mldsa, ed) = pk.split_at(ciris_crypto::composite::MLDSA65_PK_LEN);
    let (ed_b64, mldsa_b64) = (B64.encode(ed), B64.encode(mldsa));
    let peer = "f0-cp5b-peer";
    let witness = build_local_witness(
        peer,
        7,
        1_780_272_000_000,
        &[WitnessLeaf {
            claim_namespace: "scores:medical".into(),
            cohort_scope: "community".into(),
            anonymous_tier: false,
            leaf_bytes: b"f0-cp5b leaf".to_vec(),
        }],
    );
    let composite = key
        .sign(&witness.canonical_preimage())
        .expect("composite sign");

    // A lone Ed25519 half, and a lone ML-DSA-65 half, are refused by name at
    // the wire, before any key is read.
    for half in [&composite[composite.len() - 64..], &composite[..3309]] {
        match Sig19::from_wire(&B64.encode(half)) {
            Err(Sig19Error::ComponentSignature(m)) => assert!(
                m.starts_with(VERIFY_COMPONENT_SIGNATURE),
                "I2887: refused by name: {m}"
            ),
            other => panic!(
                "I2887: a lone {}-byte half is refused: {other:?}",
                half.len()
            ),
        }
    }
    // The earlier bound-hybrid pair is refused by name.
    assert_eq!(
        Sig19::from_wire(&format!(
            r#"{{"ed25519":"{}","ml_dsa_65":"{}"}}"#,
            B64.encode(&composite[composite.len() - 64..]),
            B64.encode(&composite[..3309])
        )),
        Err(Sig19Error::EarlierForm),
        "I2887: the bound-hybrid pair is refused by name"
    );

    // A composite over other bytes does not admit; nothing is stored.
    let other = Sig19::from_wire(&B64.encode(key.sign(b"not the preimage").unwrap()))
        .expect("a composite parses");
    d.put_wholeness_witness(&witness, &other, PRODUCER, &ed_b64, Some(&mldsa_b64), None)
        .await
        .expect_err("I2887: a composite over other bytes is refused");
    assert_eq!(
        d.last_witness_epoch_for_peer(peer).await.unwrap(),
        None,
        "I2887: nothing stored"
    );

    // The composite over the 6.1 preimage admits and is stored.
    let sig = Sig19::from_wire(&B64.encode(&composite)).expect("I2887: the composite parses");
    d.put_wholeness_witness(&witness, &sig, PRODUCER, &ed_b64, Some(&mldsa_b64), None)
        .await
        .unwrap_or_else(|e| panic!("I2887: the composite over the 6.1 preimage admits: {e}"));
    assert_eq!(
        d.last_witness_epoch_for_peer(peer).await.unwrap(),
        Some(7),
        "I2887: stored"
    );
}

/// v62.0.0 (F0-cp6d; CC's answer) — **I2892: fountain coding is
/// node-local.** A manifest produced by another node is refused by name
/// (`fountain_manifest_not_cc_object`) and nothing is stored; this node's own
/// manifest (unpinned, CC 1.13.4) is admitted and reads back in full, and the
/// publisher listing Edge's converger reads still finds it. `b`'s
/// `node_key_id` is `e2::kid(FOUNTAIN_NODE)`.
async fn fountain<B>(b: &B)
where
    B: crate::store::Backend + FederationDirectory,
{
    use crate::fountain::{
        symbol_sha256_hex, FountainAdmitError, FountainContent, FountainManifestV1,
        FountainSymbolV1, FOUNTAIN_MANIFEST_NOT_CC_OBJECT,
    };
    let me = e2::kid(FOUNTAIN_NODE);
    let sym = b"f0-cp6d-sym0".to_vec();
    let manifest = |content_id: &str, producer: &str| FountainManifestV1 {
        content_id: content_id.to_owned(),
        corpus_kind: "blob".into(),
        manifest_version: 1,
        n_source: 1,
        k_repair: 0,
        symbol_size: sym.len() as u32,
        original_content_length: sym.len() as u64,
        min_viable_symbols: 1,
        symbol_hashes: vec![symbol_sha256_hex(&sym)],
        envelope: serde_json::json!({}),
        signature: String::new(),
        signature_ml_dsa_65: String::new(),
        pqc_key_id: producer.to_owned(),
    };
    let symbols = |content_id: &str| {
        vec![FountainSymbolV1 {
            content_id: content_id.to_owned(),
            symbol_id: 0,
            retention_priority: 0,
            symbol_bytes: sym.clone(),
        }]
    };

    // A peer's manifest: refused by name, nothing stored.
    let peer = e2::kid("f0-cp6d-peer-node");
    let id = "f0-cp6d-peer";
    match b
        .put_fountain_content(&manifest(id, &peer), &symbols(id))
        .await
    {
        Err(crate::store::Error::FountainAdmit(FountainAdmitError::NotCcObject(m))) => {
            assert!(
                FountainAdmitError::NotCcObject(m.clone())
                    .to_string()
                    .starts_with(FOUNTAIN_MANIFEST_NOT_CC_OBJECT),
                "I2892: by name: {m}"
            );
        }
        other => panic!("I2892: a peer's manifest is refused by name: {other:?}"),
    }
    assert!(
        b.get_fountain_content(id, "blob").await.unwrap().is_none(),
        "I2892: nothing stored"
    );

    // This node's own fountain coding: admitted, read back in full.
    let id = "f0-cp6d-local";
    b.put_fountain_content(&manifest(id, &me), &symbols(id))
        .await
        .unwrap_or_else(|e| panic!("I2892: this node's own manifest is admitted: {e}"));
    match b.get_fountain_content(id, "blob").await.unwrap() {
        Some(FountainContent::Full {
            manifest: m,
            symbols: got,
        }) => {
            assert_eq!(m.pqc_key_id, me, "I2892: the producer is this node");
            assert_eq!(got, symbols(id), "I2892: the symbols decode as stored");
        }
        other => panic!("I2892: the local content reads back in full: {other:?}"),
    }
    assert!(
        crate::store::Backend::list_held_fountain_content(b, &me)
            .await
            .unwrap()
            .iter()
            .any(|h| h.content_id == id),
        "I2892: the publisher listing (Edge's converger) finds it"
    );
}

/// The node identity [`fountain`] runs under.
const FOUNTAIN_NODE: &str = "f0-cp6d-fountain-node";

/// v62.0.0 (F0-cp6b; CC 6.1.3) — **I2891: the calibration bundle crosses
/// nodes, so its signature is ONE composite under the steward's live
/// edition-2 key** (`derived::calibration_admit`): the bundle's two fields
/// carry the composite's halves; a lone half is refused by name, and a
/// bound-hybrid pair (the same two-field shape) fails the composite verify.
async fn calibration(d: &dyn FederationDirectory) {
    use crate::derived::calibration_admit::{verify_calibration_bundle, CalibrationSignatureError};
    const STEWARD: &str = "f0-cp6b-ratchet-steward";
    let steward = e2::put_key(d, STEWARD, &["user"]).await;
    let canonical = b"f0-cp6b calibration canonical bytes".to_vec();
    let sig = e2::signing_key(STEWARD)
        .sign(&canonical)
        .expect("composite sign");
    let bundle = |ed: &[u8], mldsa: &[u8]| crate::derived::CalibrationBundle {
        ratchet_calibration_version: 1,
        projection_version: "crc-v1".into(),
        calibrated_at: chrono::Utc::now(),
        calibration_corpus_sha256: "00".repeat(32),
        calibration_corpus_n: 1,
        sample_size_gate: 1,
        manifold_threshold_global: 1.0,
        projection_metadata: serde_json::json!({}),
        cohort_centroids: serde_json::json!({}),
        is_current: true,
        canonical_bytes: canonical.clone(),
        ed25519_sig: ed.to_vec(),
        ml_dsa_65_sig: mldsa.to_vec(),
        signing_key_id: steward.clone(),
        inserted_at: chrono::Utc::now(),
    };
    let (mldsa_half, ed_half) = sig.split_at(3309);
    verify_calibration_bundle(d, &bundle(ed_half, mldsa_half))
        .await
        .unwrap_or_else(|e| panic!("I2891: the composite's halves verify: {e}"));
    match verify_calibration_bundle(d, &bundle(ed_half, &[])).await {
        Err(CalibrationSignatureError::Composite(e)) => {
            assert_eq!(e.token(), VERIFY_COMPONENT_SIGNATURE, "I2891 lone: {e}");
        }
        other => panic!("I2891: a lone half is refused by name: {other:?}"),
    }
    let other = e2::signing_key(STEWARD).sign(b"other bytes").unwrap();
    let (m2, e2_) = other.split_at(3309);
    match verify_calibration_bundle(d, &bundle(e2_, m2)).await {
        Err(CalibrationSignatureError::Composite(e)) => {
            assert_eq!(
                e.token(),
                VERIFY_COMPOSITE_INVALID,
                "I2891 other bytes: {e}"
            );
        }
        other => panic!("I2891: a composite over other bytes is refused: {other:?}"),
    }
}

/// I2877–I2881, I2885, I2887, I2891 on sqlite.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2877_to_i2885_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
    Box::pin(wholeness(&b)).await;
    Box::pin(calibration(&b)).await;
}

/// I2877–I2881, I2885, I2887, I2891 on postgres.
#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2877_to_i2885_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    Box::pin(body(&b)).await;
    Box::pin(wholeness(&b)).await;
    Box::pin(calibration(&b)).await;
}

/// I2892 on sqlite.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2892_sqlite() {
    use crate::store::Backend as _;
    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid(FOUNTAIN_NODE));
    Box::pin(fountain(&b)).await;
}

/// I2892 on postgres.
#[cfg(feature = "postgres")]
#[tokio::test]
async fn i2892_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    b.run_migrations().await.unwrap();
    b.set_node_key_id(e2::kid(FOUNTAIN_NODE));
    Box::pin(fountain(&b)).await;
}
