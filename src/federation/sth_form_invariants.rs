//! v62.0.0 (slice D) — **the CIRISVerify 23 composite cut, witnessed (CC
//! rc20 "nothing carries": a v62 node writes and reads only composites).**
//! I1853–I1855, I1857.
//!
//! - **I1853** witness counting ([`sth_form::count_valid_witnesses`]): a
//!   cosignature counts under its witness's PINNED composite key; a repeated
//!   `witness_id` counts once; an untrusted witness, or one whose pinned key
//!   does not decode, does not count; a consistency proof that does not chain
//!   to the head does not count; a signature over other bytes, or under
//!   another key, does not count; an earlier-form (bound-hybrid) cosignature
//!   never counts. Run over a head from each of the three logs (audit,
//!   trust-grant receipt, stream).
//! - **I1854** heads are written as the composite (byte-equal to Verify's
//!   own `CompositeSigningKey` for the same keys) and verify under the pinned
//!   key; an earlier-form head is refused by name
//!   (`sth_signature_earlier_form`), never verified; bytes in no form are
//!   refused; a signer whose PQC half has no context-sign refuses by name.
//! - **I1855** the stream door (`put_stream_sth`, sqlite and postgres)
//!   verifies a composite producer and composite witnesses under their
//!   registered keys, refuses a duplicate, unknown or forged witness, refuses
//!   an earlier-form head and an earlier-form witness by name, and serves
//!   what it stored.
//! - **I1857** §19 objects: a wholeness witness and a storage-contention wire
//!   the node's signer writes (the composite) admit; a tampered composite is
//!   refused; the earlier bound-hybrid pair is refused by name
//!   (`sig19_earlier_form`, `storage_contention_earlier_form`).
//! - **I2751** (E6-fix6) the stream door reads the producer's LIVE key: a
//!   revoked producer's head is refused `verify_signer_revoked` (sqlite and
//!   postgres).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::composite::{CompositeSigningKey, MLDSA65_PK_LEN};
use ciris_verify_core::transparency::{SignedTreeHead, WitnessConsistencyProof, WitnessSignature};

use super::sth_form::{self, count_valid_witnesses, witness_quorum_met, PinnedKeys, PinnedWitness};

/// A composite test key from seeds `[n; 32]` (ML-DSA) and `[n + 1; 32]`
/// (Ed25519).
fn composite(n: u8) -> CompositeSigningKey {
    CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(1); 32])
}

fn pinned_of(c: &CompositeSigningKey) -> PinnedKeys {
    let pk = c.public_key().as_bytes();
    PinnedKeys {
        ed25519_base64: B64.encode(&pk[MLDSA65_PK_LEN..]),
        ml_dsa_65_base64: Some(B64.encode(&pk[..MLDSA65_PK_LEN])),
    }
}

/// The pinned keys of the bound-hybrid test signer over seeds
/// `([n + 1; 32], [n; 32])` (ML-DSA, Ed25519): a v61 witness.
fn earlier_keys(n: u8) -> PinnedKeys {
    pinned_of(&CompositeSigningKey::from_seeds(
        &[n.wrapping_add(1); 32],
        &[n; 32],
    ))
}

fn head(
    log_id: &str,
    tree_size: u64,
    root: [u8; 32],
    operator: &CompositeSigningKey,
) -> SignedTreeHead {
    let timestamp = crate::verify::utc::to_verify(
        "2026-11-15T12:00:00.123456Z"
            .parse::<chrono::DateTime<chrono::Utc>>()
            .unwrap(),
    )
    .unwrap();
    let bytes = SignedTreeHead::signing_bytes(log_id, tree_size, &root, timestamp);
    SignedTreeHead {
        log_id: log_id.to_owned(),
        tree_size,
        root_hash: root,
        timestamp,
        signature: operator.sign(&bytes).unwrap(),
        witness_signatures: Vec::new(),
    }
}

fn witness(id: &str, keys: PinnedKeys) -> PinnedWitness {
    PinnedWitness {
        witness_id: id.to_owned(),
        keys,
    }
}

/// The I1853 body over one log's head: every counting rule, against `sth`.
fn i1853_counting_rules(sth: &SignedTreeHead, log: &str) {
    let (w1, w2, w3) = (composite(0x11), composite(0x21), composite(0x31));
    let e1_keys = earlier_keys(0x41);
    let trusted = vec![
        witness("w1", pinned_of(&w1)),
        witness("w2", pinned_of(&w2)),
        witness("e1", e1_keys),
        witness(
            "bad-key",
            PinnedKeys {
                ed25519_base64: "not base64!".into(),
                ml_dsa_65_base64: Some("AAAA".into()),
            },
        ),
    ];
    let genesis = WitnessConsistencyProof::genesis();
    let mut h = sth.clone();
    h.witness_signatures = Vec::new();
    assert_eq!(
        count_valid_witnesses(&h, &trusted),
        0,
        "I1853 {log}: none cosigned"
    );

    // Two distinct trusted composite witnesses count.
    h.witness_signatures
        .push(h.cosign("w1", &w1, genesis.clone()).unwrap());
    h.witness_signatures
        .push(h.cosign("w2", &w2, genesis.clone()).unwrap());
    assert_eq!(
        count_valid_witnesses(&h, &trusted),
        2,
        "I1853 {log}: two witnesses"
    );

    // A duplicate witness_id counts once.
    h.witness_signatures
        .push(h.cosign("w1", &w1, genesis.clone()).unwrap());
    assert_eq!(
        count_valid_witnesses(&h, &trusted),
        2,
        "I1853 {log}: a repeat counts once"
    );

    // An untrusted witness does not count.
    h.witness_signatures
        .push(h.cosign("w3", &w3, genesis.clone()).unwrap());
    assert_eq!(
        count_valid_witnesses(&h, &trusted),
        2,
        "I1853 {log}: untrusted"
    );

    // A trusted id whose pinned key does not decode does not count.
    h.witness_signatures
        .push(h.cosign("bad-key", &w3, genesis.clone()).unwrap());
    assert_eq!(
        count_valid_witnesses(&h, &trusted),
        2,
        "I1853 {log}: undecodable key"
    );

    // A trusted witness signing with ANOTHER key (its id, w3's key) does not.
    let mut forged = h.clone();
    forged.witness_signatures = vec![h.cosign("w2", &w3, genesis.clone()).unwrap()];
    assert_eq!(
        count_valid_witnesses(&forged, &trusted),
        0,
        "I1853 {log}: wrong key"
    );

    // A consistency proof that does not chain to this head does not count,
    // even with a valid signature.
    let mut unchained = h.clone();
    let mut ws = h.cosign("w1", &w1, genesis.clone()).unwrap();
    ws.consistency_proof = WitnessConsistencyProof {
        prior_tree_size: sth.tree_size + 1,
        prior_root_hash: [0u8; 32],
        consistency_path: Vec::new(),
    };
    unchained.witness_signatures = vec![ws];
    assert_eq!(
        count_valid_witnesses(&unchained, &trusted),
        0,
        "I1853 {log}: an unchained proof"
    );

    // A cosignature over OTHER bytes (a different head) does not count.
    let mut other_head = sth.clone();
    other_head.tree_size += 1;
    let mut over_other = h.clone();
    over_other.witness_signatures = vec![WitnessSignature {
        witness_id: "w1".into(),
        signature: other_head
            .cosign("w1", &w1, genesis.clone())
            .unwrap()
            .signature,
        consistency_proof: genesis.clone(),
    }];
    assert_eq!(
        count_valid_witnesses(&over_other, &trusted),
        0,
        "I1853 {log}: a signature over other bytes"
    );

    // An earlier-form (bound-hybrid) cosignature by a trusted witness, over
    // the right bytes, never counts: a v62 node reads only composites.
    h.witness_signatures.push(WitnessSignature {
        witness_id: "e1".into(),
        signature: sth_form::test_support::earlier_bytes(
            [0x42; 32],
            [0x41; 32],
            &h.signing_bytes_of(),
        ),
        consistency_proof: genesis.clone(),
    });
    assert_eq!(
        count_valid_witnesses(&h, &trusted),
        2,
        "I1853 {log}: an earlier-form cosignature"
    );
    assert!(witness_quorum_met(&h, &trusted, 2), "I1853 {log}: quorum 2");
    assert!(
        !witness_quorum_met(&h, &trusted, 3),
        "I1853 {log}: quorum 3"
    );
    assert!(
        witness_quorum_met(&h, &[], 0),
        "I1853 {log}: a zero quorum is met"
    );
}

/// I1853 over the AUDIT log's head (a tenant tree in `merkle_sth_log`),
/// stored and served by the sqlite Merkle store.
#[cfg(all(feature = "sqlite", feature = "cirisaudit"))]
#[tokio::test]
async fn i1853_witness_counting_over_the_audit_head() {
    use crate::audit::merkle_leaf::AuditLeaf;
    use crate::store::Backend as _;
    use ciris_verify_core::transparency::{TransparencyLog, TransparencyStore};
    let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    backend.run_migrations().await.unwrap();
    let store: Arc<dyn TransparencyStore<AuditLeaf>> = Arc::new(
        crate::audit::merkle_store::SqliteMerkleStore::new(backend.conn_handle(), "i1853"),
    );
    let entry = crate::audit::types::AuditEntry {
        entry_id: "i1853-1".into(),
        sequence_number: 1,
        tenant_id: "i1853".into(),
        actor_id: "B64ACTOR".into(),
        action_type: "test_action".into(),
        subject_kind: "task".into(),
        subject_id: "subj-1".into(),
        payload: serde_json::json!({"seq": 1}),
        prev_hash: crate::audit::GENESIS_PREV_HASH.to_vec(),
        entry_hash: vec![0; 32],
        recorded_at: "2026-11-15T12:00:00Z".parse().unwrap(),
        signature: "B64SIG".into(),
    };
    store
        .append(AuditLeaf::with_chain_event_id(entry, 1))
        .unwrap();
    let log = TransparencyLog::<AuditLeaf>::for_log("tenant:i1853", store.clone());
    let operator = composite(0x01);
    let signed = log.sign_head(&operator).unwrap();
    let served = store.latest_sth().unwrap().expect("the head is served");
    assert_eq!(served.signature, signed.signature);
    i1853_counting_rules(&served, "audit");
}

/// I1853 over a STREAM log's head (producer-signed, over chunk shas).
#[test]
fn i1853_witness_counting_over_a_stream_head() {
    let producer = composite(0x03);
    let shas = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let root = {
        use ciris_verify_core::transparency::{InMemoryTransparencyStore, TransparencyStore};
        let s: InMemoryTransparencyStore<super::stream_sth::StreamChunkLeaf> =
            InMemoryTransparencyStore::new(None);
        for sha in &shas {
            s.append(super::stream_sth::StreamChunkLeaf::new(*sha))
                .unwrap();
        }
        s.root().unwrap()
    };
    let sth = head(
        &super::stream_sth::log_id_for_stream("i1853"),
        3,
        root,
        &producer,
    );
    super::stream_sth::recompute_and_assert_root(&sth, &shas).unwrap();
    i1853_counting_rules(&sth, "stream");
}

/// A [`LocalSigner`](crate::signing::LocalSigner) whose PQC half is the
/// keyring's software ML-DSA-65 signer over seed `[n; 32]` and whose Ed25519
/// seed is `[n + 1; 32]`, the same keys as [`composite`]`(n)`.
fn local_signer(n: u8) -> crate::signing::LocalSigner {
    let pqc = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[n; 32], "i1854-pqc").unwrap();
    crate::signing::LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[n.wrapping_add(1); 32]),
        "i1854".into(),
        Some(Arc::new(pqc)),
        Some("i1854-pqc".into()),
    )
}

/// I1854 — heads are written as the composite and read only as one.
#[tokio::test]
async fn i1854_heads_are_composites_and_the_earlier_form_is_refused_by_name() {
    let signer = local_signer(0x61);
    let keys = pinned_of(&composite(0x61));
    let probe = head("tenant:i1854", 2, [0x22; 32], &composite(0x61));
    let bytes = probe.signing_bytes_of();

    // Written: the composite, byte-equal to Verify's own key for the same
    // seeds (both halves are deterministic), verifying under the pinned key.
    let forward = sth_form::sign_sth(&signer, &bytes).await.unwrap();
    assert_eq!(forward, composite(0x61).sign(&bytes).unwrap());
    sth_form::verify_sth_signature(&probe, &forward, &keys).unwrap();
    // ... and not under another key.
    assert!(
        sth_form::verify_sth_signature(&probe, &forward, &pinned_of(&composite(0x71))).is_err()
    );

    // The earlier form (a v61 head, the signer's own keys, the right bytes)
    // is refused by name, never verified.
    let earlier = sth_form::test_support::earlier_bytes([0x61; 32], [0x62; 32], &bytes);
    assert_eq!(
        sth_form::classify(&earlier),
        Err(sth_form::SthFormRefusal::EarlierForm)
    );
    let err = sth_form::verify_sth_signature(&probe, &earlier, &keys).unwrap_err();
    assert!(
        err.to_string()
            .contains(sth_form::STH_SIGNATURE_EARLIER_FORM),
        "I1854: {err}"
    );
    // A head whose JSON carries the v22 signature OBJECT is refused by name.
    let mut v = serde_json::to_value(&probe).unwrap();
    v["signature"] = serde_json::from_slice(&earlier).unwrap();
    assert!(matches!(
        sth_form::sth_from_json(v),
        Err(sth_form::SthJsonError::Form(
            sth_form::SthFormRefusal::EarlierForm
        ))
    ));

    // Bytes in no form are refused, never absent.
    for junk in [&b""[..], b"{\"not\":\"a signature\"}", &[7u8; 100]] {
        assert!(
            matches!(
                sth_form::classify(junk),
                Err(sth_form::SthFormRefusal::Unrecognized { .. })
            ),
            "I1854: {junk:?}"
        );
        assert!(sth_form::verify_sth_signature(&probe, junk, &keys).is_err());
    }
}

/// A PQC signer with no context-sign (the keyring trait's default).
struct NoContextSign;

#[async_trait::async_trait]
impl ciris_keyring::PqcSigner for NoContextSign {
    fn algorithm(&self) -> ciris_keyring::PqcAlgorithm {
        ciris_keyring::PqcAlgorithm::MlDsa65
    }
    fn hardware_type(&self) -> ciris_keyring::HardwareType {
        ciris_keyring::HardwareType::SoftwareOnly
    }
    async fn public_key(&self) -> Result<Vec<u8>, ciris_keyring::KeyringError> {
        Ok(vec![0; MLDSA65_PK_LEN])
    }
    async fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, ciris_keyring::KeyringError> {
        Ok(vec![0; 3309])
    }
    async fn attestation(
        &self,
    ) -> Result<ciris_keyring::PlatformAttestation, ciris_keyring::KeyringError> {
        Err(ciris_keyring::KeyringError::NotSupported {
            operation: "test".into(),
        })
    }
    fn current_alias(&self) -> &str {
        "no-context-sign"
    }
    fn storage_descriptor(&self) -> ciris_keyring::StorageDescriptor {
        ciris_keyring::StorageDescriptor::InMemory
    }
}

/// I1854 — a signer that cannot context-sign refuses the composite by name;
/// there is no other form to fall back to.
#[tokio::test]
async fn i1854_a_signer_without_context_sign_refuses_the_composite_by_name() {
    let signer = crate::signing::LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[3; 32]),
        "i1854-stub".into(),
        Some(Arc::new(NoContextSign)),
        Some("stub".into()),
    );
    let err = sth_form::sign_sth(&signer, b"bytes").await.unwrap_err();
    assert!(
        matches!(err, crate::signing::LocalSignerError::CompositeUnavailable),
        "I1854: {err:?}"
    );
    assert!(err.to_string().contains("composite_signing_unavailable"));
}

/// I1857 — §19 objects: the node's signer writes the composite (the forward
/// builders), it admits, a tampered one does not, and the earlier pair is
/// refused by name.
#[tokio::test]
async fn i1857_sig19_objects_are_composites_and_the_earlier_pair_is_refused() {
    use crate::verify::sig19::{sign_sig19, verify_sig19, Sig19, Sig19Error};
    let signer = local_signer(0x81);
    let keys = pinned_of(&composite(0x81));
    let ed_pub = B64.decode(&keys.ed25519_base64).unwrap();
    let ml_pub = B64.decode(keys.ml_dsa_65_base64.as_ref().unwrap()).unwrap();

    // A wholeness witness through the admission gate.
    let leaves = vec![crate::witness::WitnessLeaf {
        claim_namespace: "scores:medical".into(),
        cohort_scope: "community".into(),
        anonymous_tier: false,
        leaf_bytes: b"leaf".to_vec(),
    }];
    let w = crate::witness::build_local_witness("peer-i1857", 1, 1000, &leaves);
    let sig = crate::witness::sign_wholeness_witness(&signer, &w)
        .await
        .unwrap();
    assert_eq!(
        sig.0,
        composite(0x81).sign(&w.canonical_preimage()).unwrap()
    );
    crate::witness::admit_witness(
        &w,
        &sig,
        "i1857-pqc",
        &keys.ed25519_base64,
        keys.ml_dsa_65_base64.as_deref(),
        None,
    )
    .unwrap_or_else(|e| panic!("I1857: the composite witness admits: {e}"));
    // A tampered composite is refused.
    let mut bad = sign_sig19(&signer, &w.canonical_preimage()).await.unwrap();
    bad.0[100] ^= 1;
    assert_eq!(
        verify_sig19(&w.canonical_preimage(), &bad, &ed_pub, &ml_pub),
        Err(Sig19Error::CompositeInvalid)
    );
    // The earlier pair, on the one-argument wire, is refused by name.
    assert_eq!(
        Sig19::from_wire(r#"{"ed25519":"AAAA","ml_dsa_65":"AAAA"}"#),
        Err(Sig19Error::EarlierForm)
    );

    // A storage-contention wire the node signs verifies; the earlier pair
    // on it is refused by name.
    use crate::fountain::storage_contention as sc;
    let payload = serde_json::json!({
        "node_id": "node-i1857",
        "epoch_id": "e1",
        "cohort_scope": "community",
        "size_cap_bytes": 1024,
        "remaining_budget_bytes": 4096,
        "want": ["cid-a", "cid-b"],
    })
    .to_string();
    let wire = sc::sign_corpus_want_wire(&signer, &payload).await.unwrap();
    let ml_b64 = keys.ml_dsa_65_base64.as_ref().unwrap();
    sc::verify_corpus_want_wire(&wire, &keys.ed25519_base64, ml_b64)
        .unwrap_or_else(|e| panic!("I1857: the composite corpus-want verifies: {e}"));
    let mut earlier: serde_json::Value = serde_json::from_str(&wire).unwrap();
    earlier["signature_ed25519_base64"] = serde_json::json!("AAAA");
    earlier["signature_ml_dsa_65_base64"] = serde_json::json!("AAAA");
    earlier["signature_composite_base64"] = serde_json::json!("");
    assert!(matches!(
        sc::verify_corpus_want_wire(&earlier.to_string(), &keys.ed25519_base64, ml_b64),
        Err(sc::StorageContentionError::EarlierForm)
    ));
}

/// The I1855 body: the stream door on one backend.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) mod bodies {
    use super::*;
    use crate::federation::{BlobBody, BlobStorage, FederationDirectory};
    use ciris_verify_core::transparency::WitnessSignature;

    /// v62 (E4): the test key `seed` names goes live as an edition-2
    /// `key:record` (self-signed, `user`: no start and no end, so the heads'
    /// FIXED 2026-11-15 instant stays inside the key's liveness on any run
    /// date — E0.api.md v1.6 fixed-instant rule; the door reads only the
    /// key), put through the statement door.
    /// Returns the key and its identity-ref, which is what the store names it
    /// by. The earlier form's hand-built `KeyRecord` offered to
    /// `put_public_key` is not how a key becomes live.
    async fn register<B: FederationDirectory>(
        backend: &B,
        seed: &str,
    ) -> (CompositeSigningKey, String) {
        use crate::federation::edition2::fixture_switch as e2;
        let id = e2::put_key(
            backend,
            seed,
            &[crate::federation::types::identity_type::USER],
        )
        .await;
        (e2::signing_key(seed), id)
    }

    /// I1855 on `backend` (a migrated, empty store). `tag` keeps postgres
    /// rows self-isolating.
    pub(crate) async fn i1855_the_stream_door_reads_only_composites<B>(backend: &B, tag: &str)
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        let (producer, producer_id) = register(backend, &format!("i1855-producer-{tag}")).await;
        let (w, witness_id) = register(backend, &format!("i1855-witness-{tag}")).await;
        let stream = format!("i1855-{tag}");
        let mut shas = Vec::new();
        for (seq, body) in [&b"AAAA"[..], b"BBBB", b"CC"].iter().enumerate() {
            shas.push(
                backend
                    .put_blob_chunk(&stream, seq as u64, BlobBody::Inline(body.to_vec()), 0)
                    .await
                    .unwrap(),
            );
        }
        let root = {
            use ciris_verify_core::transparency::{InMemoryTransparencyStore, TransparencyStore};
            let s: InMemoryTransparencyStore<super::super::stream_sth::StreamChunkLeaf> =
                InMemoryTransparencyStore::new(None);
            for sha in &shas[..2] {
                s.append(super::super::stream_sth::StreamChunkLeaf::new(*sha))
                    .unwrap();
            }
            s.root().unwrap()
        };
        let log_id = super::super::stream_sth::log_id_for_stream(&stream);
        let base = head(&log_id, 2, root, &producer);
        let genesis = WitnessConsistencyProof::genesis();

        // A forged producer signature (another key) is refused.
        let forged = head(&log_id, 2, root, &composite(0x95));
        assert!(
            backend.put_stream_sth(forged, &producer_id).await.is_err(),
            "I1855 {tag}: a producer signature under another key"
        );
        // A duplicate witness is refused at the door.
        let mut dup = base.clone();
        dup.witness_signatures = vec![
            dup.cosign(witness_id.clone(), &w, genesis.clone()).unwrap(),
            dup.cosign(witness_id.clone(), &w, genesis.clone()).unwrap(),
        ];
        assert!(backend.put_stream_sth(dup, &producer_id).await.is_err());
        // An unregistered witness is refused.
        let mut unknown = base.clone();
        unknown.witness_signatures =
            vec![unknown.cosign("i1855-nobody", &w, genesis.clone()).unwrap()];
        assert!(backend.put_stream_sth(unknown, &producer_id).await.is_err());
        // A registered witness signing with another key is refused.
        let mut wrong = base.clone();
        wrong.witness_signatures = vec![wrong
            .cosign(witness_id.clone(), &composite(0x97), genesis.clone())
            .unwrap()];
        assert!(backend.put_stream_sth(wrong, &producer_id).await.is_err());
        assert!(
            backend.latest_stream_sth(&stream).await.unwrap().is_none(),
            "I1855 {tag}: nothing refused was stored"
        );

        // The genuine composite head with its composite witness is admitted
        // and served as stored, and its witness counts.
        let mut genuine = base.clone();
        genuine.witness_signatures = vec![genuine
            .cosign(witness_id.clone(), &w, genesis.clone())
            .unwrap()];
        backend
            .put_stream_sth(genuine.clone(), &producer_id)
            .await
            .unwrap_or_else(|e| panic!("I1855 {tag}: the composite head admits: {e}"));
        let served = backend.latest_stream_sth(&stream).await.unwrap().unwrap();
        assert_eq!(served.signature, genuine.signature);
        assert_eq!(served.witness_signatures.len(), 1);
        assert_eq!(
            count_valid_witnesses(&served, &[witness(&witness_id, pinned_of(&w))]),
            1,
            "I1855 {tag}: the served witness counts"
        );

        // An earlier-form head (a v61 producer, its own registered keys, the
        // right root) is refused by name, and so is an earlier-form witness
        // on a composite head.
        // v62 (E4): the v61 producer holds a live key of its own; what it
        // offers is the earlier-form signature, refused by name before any
        // verify.
        let (_, old_id) = register(backend, &format!("i1855-earlier-{tag}")).await;
        let root3 = {
            use ciris_verify_core::transparency::{InMemoryTransparencyStore, TransparencyStore};
            let s: InMemoryTransparencyStore<super::super::stream_sth::StreamChunkLeaf> =
                InMemoryTransparencyStore::new(None);
            for sha in &shas {
                s.append(super::super::stream_sth::StreamChunkLeaf::new(*sha))
                    .unwrap();
            }
            s.root().unwrap()
        };
        let mut v61 = head(&log_id, 3, root3, &producer);
        v61.signature =
            sth_form::test_support::earlier_bytes([0xA2; 32], [0xA1; 32], &v61.signing_bytes_of());
        let err = backend.put_stream_sth(v61, &old_id).await.unwrap_err();
        assert!(
            err.to_string()
                .contains(sth_form::STH_SIGNATURE_EARLIER_FORM),
            "I1855 {tag}: {err}"
        );
        let mut mixed = head(&log_id, 3, root3, &producer);
        mixed.witness_signatures = vec![WitnessSignature {
            witness_id: old_id.clone(),
            signature: sth_form::test_support::earlier_bytes(
                [0xA2; 32],
                [0xA1; 32],
                &mixed.signing_bytes_of(),
            ),
            consistency_proof: genesis.clone(),
        }];
        let err = backend
            .put_stream_sth(mixed, &producer_id)
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(sth_form::STH_SIGNATURE_EARLIER_FORM),
            "I1855 {tag}: an earlier-form witness: {err}"
        );
        let served = backend.latest_stream_sth(&stream).await.unwrap().unwrap();
        assert_eq!(
            served.tree_size, 2,
            "I1855 {tag}: nothing refused was stored"
        );
    }

    /// The stream-log root over `shas` (the leaves `put_stream_sth` checks).
    fn stream_root(shas: &[[u8; 32]]) -> [u8; 32] {
        use ciris_verify_core::transparency::{InMemoryTransparencyStore, TransparencyStore};
        let s: InMemoryTransparencyStore<super::super::stream_sth::StreamChunkLeaf> =
            InMemoryTransparencyStore::new(None);
        for sha in shas {
            s.append(super::super::stream_sth::StreamChunkLeaf::new(*sha))
                .unwrap();
        }
        s.root().unwrap()
    }

    /// **I2751** (v62.0.0, E6-fix6; F0-cp6c §3) — **the stream door reads the
    /// producer's LIVE key.** A head from a live producer key lands; once that
    /// key is revoked (its own `key:revocation`), the next head it signs is
    /// refused by name (`verify_signer_revoked`) and nothing is stored. The
    /// door used to read the projected `federation_keys` row, which carries no
    /// revocation (CC 2.4.1.1, CC 2.6.1.7).
    pub(crate) async fn i2751_a_revoked_producer_is_refused<B>(backend: &B, tag: &str)
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        use crate::federation::edition2::composite_verify::VERIFY_SIGNER_REVOKED;
        use crate::federation::edition2::fixture_switch as e2;
        let seed = format!("i2751-producer-{tag}");
        let (producer, producer_id) = register(backend, &seed).await;
        let stream = format!("i2751-{tag}");
        let mut shas = Vec::new();
        for (seq, body) in [&b"AAAA"[..], b"BBBB", b"CC"].iter().enumerate() {
            shas.push(
                backend
                    .put_blob_chunk(&stream, seq as u64, BlobBody::Inline(body.to_vec()), 0)
                    .await
                    .unwrap(),
            );
        }
        let log_id = super::super::stream_sth::log_id_for_stream(&stream);

        // Live: the head lands.
        backend
            .put_stream_sth(
                head(&log_id, 2, stream_root(&shas[..2]), &producer),
                &producer_id,
            )
            .await
            .unwrap_or_else(|e| panic!("I2751 {tag}: a live producer's head lands: {e}"));

        // Revoked: the next head is refused by name, and nothing is stored.
        e2::put_statement(backend, &e2::key_revocation(&seed, &seed, None))
            .await
            .unwrap_or_else(|e| panic!("I2751 {tag}: the self-revocation is admitted: {e}"));
        let err = backend
            .put_stream_sth(
                head(&log_id, 3, stream_root(&shas), &producer),
                &producer_id,
            )
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains(VERIFY_SIGNER_REVOKED),
            "I2751 {tag}: a revoked producer is refused by name: {err}"
        );
        assert_eq!(
            backend
                .latest_stream_sth(&stream)
                .await
                .unwrap()
                .unwrap()
                .tree_size,
            2,
            "I2751 {tag}: the revoked producer's head was not stored"
        );
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i1855_the_stream_door_reads_only_composites_sqlite() {
    use crate::store::Backend as _;
    let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    backend.run_migrations().await.unwrap();
    bodies::i1855_the_stream_door_reads_only_composites(&backend, "sqlite").await;
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn i1855_the_stream_door_reads_only_composites_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("I1855: CIRIS_PERSIST_TEST_PG_URL unset; skipped");
        return;
    };
    let backend = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    backend.run_migrations().await.unwrap();
    bodies::i1855_the_stream_door_reads_only_composites(&backend, "postgres").await;
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i2751_a_revoked_producer_is_refused_sqlite() {
    use crate::store::Backend as _;
    let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    backend.run_migrations().await.unwrap();
    bodies::i2751_a_revoked_producer_is_refused(&backend, "sqlite").await;
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn i2751_a_revoked_producer_is_refused_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("I2751: CIRIS_PERSIST_TEST_PG_URL unset; skipped");
        return;
    };
    let backend = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    backend.run_migrations().await.unwrap();
    bodies::i2751_a_revoked_producer_is_refused(&backend, "postgres").await;
}
