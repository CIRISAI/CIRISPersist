//! v62.0.0 (slice D) — **the CIRISVerify 23 composite cut, witnessed.**
//! I1853–I1855, I1857.
//!
//! - **I1853** witness counting ([`sth_form::count_valid_witnesses`]): a
//!   cosignature counts under its witness's PINNED keys; a repeated
//!   `witness_id` counts once; an untrusted witness, or one whose pinned key
//!   does not decode, does not count; a consistency proof that does not chain
//!   to the head does not count; a signature over other bytes does not
//!   count; both forms count in one head. Run over a head from each of the
//!   three logs (audit, trust-grant receipt, stream).
//! - **I1854** heads are read by FORM and written by ceremony state (CC D4):
//!   before the ceremony row the earlier (bound-hybrid) form, which verifies
//!   by CC 8.11.12; after it the composite, which is the bytes Verify's own
//!   `CompositeSigningKey` produces for the same keys; bytes of neither form
//!   are refused; a signer whose PQC half has no context-sign refuses by
//!   name; a node holds no ceremony row today.
//! - **I1855** the stream door (`put_stream_sth`, sqlite and postgres)
//!   verifies a composite producer and composite witnesses under the
//!   producer's / witness's registered keys, refuses a duplicate, unknown or
//!   forged witness, still admits an earlier-form head, and serves what it
//!   stored.
//! - **I1857** §19 objects verify by form ([`crate::verify::sig19`]): a
//!   wholeness witness and a storage-contention wire signed by the node's
//!   signer in either form admit; a tampered composite, an earlier form
//!   without its ML-DSA-65 half, and a wire carrying both forms are refused.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ciris_crypto::composite::{CompositeSigningKey, MLDSA65_PK_LEN};
use ciris_verify_core::transparency::{SignedTreeHead, WitnessConsistencyProof, WitnessSignature};

use super::sth_form::{
    self, count_valid_witnesses, witness_quorum_met, CeremonyState, PinnedKeys, PinnedWitness,
    SignatureForm,
};

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

/// An earlier-form (bound-hybrid) test signer and its pinned keys.
fn earlier(n: u8) -> (Box<sth_form::test_support::EarlierSigner>, PinnedKeys) {
    use ciris_crypto::{ClassicalSigner as _, PqcSigner as _};
    let ed = ciris_crypto::Ed25519Signer::from_seed(&[n; 32]).unwrap();
    let ml = ciris_crypto::MlDsa65Signer::from_seed(&[n.wrapping_add(1); 32]).unwrap();
    let keys = PinnedKeys {
        ed25519_base64: B64.encode(ed.public_key().unwrap()),
        ml_dsa_65_base64: Some(B64.encode(ml.public_key().unwrap())),
    };
    (
        Box::new(ciris_crypto::HybridSigner::new(ed, ml).unwrap()),
        keys,
    )
}

fn head(
    log_id: &str,
    tree_size: u64,
    root: [u8; 32],
    operator: &CompositeSigningKey,
) -> SignedTreeHead {
    let timestamp: chrono::DateTime<chrono::Utc> = "2026-11-15T12:00:00.123456Z".parse().unwrap();
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
    let (e1, e1_keys) = earlier(0x41);
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

    // The earlier form counts under its pinned hybrid keys, beside composites.
    h.witness_signatures
        .push(sth_form::test_support::earlier_cosign(&h, "e1", &e1, genesis.clone()).unwrap());
    assert_eq!(
        count_valid_witnesses(&h, &trusted),
        3,
        "I1853 {log}: mixed forms"
    );
    assert!(witness_quorum_met(&h, &trusted, 3), "I1853 {log}: quorum 3");
    assert!(
        !witness_quorum_met(&h, &trusted, 4),
        "I1853 {log}: quorum 4"
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

/// I1853 over a TRUST-GRANT receipt's head: the receipt crosses as JSON, in
/// either form, and its head counts the same after the round trip.
#[test]
fn i1853_witness_counting_over_a_trust_grant_receipt_head() {
    let operator = composite(0x02);
    let receipt = super::trust_grant::TrustGrantReceipt {
        grant_id: uuid::Uuid::nil(),
        chain_event_id: 7,
        chain_event_hash: vec![9; 32],
        tenant_id: "t".into(),
        tree_size_at_emit: 5,
        sth: head("tenant:t", 5, [0x5A; 32], &operator),
    };
    let wire = serde_json::to_string(&receipt).unwrap();
    let back: super::trust_grant::TrustGrantReceipt = serde_json::from_str(&wire).unwrap();
    assert_eq!(back.sth.signature, receipt.sth.signature);
    sth_form::verify_sth_signature(&back.sth, &back.sth.signature, &pinned_of(&operator))
        .expect("I1853: the receipt head verifies after the round trip");
    i1853_counting_rules(&back.sth, "trust-grant");
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

/// I1854 — the write form follows the ceremony state; the read follows the
/// bytes.
#[tokio::test]
async fn i1854_heads_are_written_by_ceremony_state_and_read_by_form() {
    let signer = local_signer(0x61);
    let keys = pinned_of(&composite(0x61));
    let probe = head("tenant:i1854", 2, [0x22; 32], &composite(0x61));
    let bytes = probe.signing_bytes_of();

    // No ceremony row is held by any node today.
    assert_eq!(sth_form::ceremony_state(), CeremonyState::NotHeld);

    // Before the ceremony row: the earlier form, verifying by CC 8.11.12.
    let earlier = sth_form::sign_sth(&signer, &bytes, CeremonyState::NotHeld)
        .await
        .unwrap();
    assert_eq!(sth_form::form_of(&earlier), Some(SignatureForm::Earlier));
    assert_eq!(
        sth_form::verify_sth_signature(&probe, &earlier, &keys).unwrap(),
        SignatureForm::Earlier
    );

    // After it: the composite, byte-equal to Verify's own key for the same
    // seeds (both halves are deterministic), verifying under the pinned key.
    let forward = sth_form::sign_sth(&signer, &bytes, CeremonyState::Held)
        .await
        .unwrap();
    assert_eq!(sth_form::form_of(&forward), Some(SignatureForm::Composite));
    assert_eq!(forward, composite(0x61).sign(&bytes).unwrap());
    assert_eq!(
        sth_form::verify_sth_signature(&probe, &forward, &keys).unwrap(),
        SignatureForm::Composite
    );

    // Each form under the WRONG keys is refused, by its own rule.
    let other = pinned_of(&composite(0x71));
    assert!(sth_form::verify_sth_signature(&probe, &earlier, &other).is_err());
    assert!(sth_form::verify_sth_signature(&probe, &forward, &other).is_err());

    // Bytes of neither form are refused, never absent.
    for junk in [&b""[..], b"{\"not\":\"a signature\"}", &[7u8; 100]] {
        assert!(sth_form::classify(junk).is_err(), "I1854: {junk:?}");
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

/// I1854 — a signer that cannot context-sign refuses the composite by name,
/// and never falls back to the earlier form on its own.
#[tokio::test]
async fn i1854_a_signer_without_context_sign_refuses_the_composite_by_name() {
    let signer = crate::signing::LocalSigner::from_parts(
        ed25519_dalek::SigningKey::from_bytes(&[3; 32]),
        "i1854-stub".into(),
        Some(Arc::new(NoContextSign)),
        Some("stub".into()),
    );
    let err = sth_form::sign_sth(&signer, b"bytes", CeremonyState::Held)
        .await
        .unwrap_err();
    assert!(
        matches!(err, crate::signing::LocalSignerError::CompositeUnavailable),
        "I1854: {err:?}"
    );
    assert!(err.to_string().contains("composite_signing_unavailable"));
}

/// I1857 — §19 objects verify by form, both forms written by the node's
/// signer (the forward builders), and the refusals hold.
#[tokio::test]
async fn i1857_sig19_objects_verify_by_form() {
    use crate::verify::sig19::{sign_sig19, verify_sig19, Sig19, Sig19Error};
    let signer = local_signer(0x81);
    let keys = pinned_of(&composite(0x81));
    let ed_pub = B64.decode(&keys.ed25519_base64).unwrap();
    let ml_pub = B64.decode(keys.ml_dsa_65_base64.as_ref().unwrap()).unwrap();

    // A wholeness witness, in each form, through the admission gate.
    let leaves = vec![crate::witness::WitnessLeaf {
        claim_namespace: "scores:medical".into(),
        cohort_scope: "community".into(),
        anonymous_tier: false,
        leaf_bytes: b"leaf".to_vec(),
    }];
    let w = crate::witness::build_local_witness("peer-i1857", 1, 1000, &leaves);
    for ceremony in [CeremonyState::NotHeld, CeremonyState::Held] {
        let sig = crate::witness::sign_wholeness_witness(&signer, &w, ceremony)
            .await
            .unwrap();
        assert_eq!(sig.form(), ceremony.writes());
        crate::witness::admit_witness(
            &w,
            &sig,
            "i1857-pqc",
            &keys.ed25519_base64,
            keys.ml_dsa_65_base64.as_deref(),
            None,
        )
        .unwrap_or_else(|e| panic!("I1857: a {ceremony:?} witness admits: {e}"));
    }
    // A tampered composite and an earlier form without its PQC half: refused.
    let Sig19::Composite(mut c) = sign_sig19(&signer, &w.canonical_preimage(), CeremonyState::Held)
        .await
        .unwrap()
    else {
        panic!("I1857: Held writes the composite")
    };
    c[100] ^= 1;
    assert_eq!(
        verify_sig19(
            &w.canonical_preimage(),
            &Sig19::Composite(c),
            &ed_pub,
            &ml_pub
        ),
        Err(Sig19Error::CompositeInvalid)
    );
    let Sig19::Earlier { ed25519, .. } =
        sign_sig19(&signer, &w.canonical_preimage(), CeremonyState::NotHeld)
            .await
            .unwrap()
    else {
        panic!("I1857: NotHeld writes the earlier form")
    };
    let no_pqc = Sig19::Earlier {
        ed25519,
        mldsa65: None,
    };
    assert!(crate::witness::admit_witness(
        &w,
        &no_pqc,
        "i1857-pqc",
        &keys.ed25519_base64,
        keys.ml_dsa_65_base64.as_deref(),
        None
    )
    .is_err());

    // A storage-contention wire in each form verifies; both forms at once is
    // refused.
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
    let mut wires = Vec::new();
    for ceremony in [CeremonyState::NotHeld, CeremonyState::Held] {
        let wire = sc::sign_corpus_want_wire(&signer, &payload, ceremony)
            .await
            .unwrap();
        sc::verify_corpus_want_wire(
            &wire,
            &keys.ed25519_base64,
            keys.ml_dsa_65_base64.as_ref().unwrap(),
        )
        .unwrap_or_else(|e| panic!("I1857: a {ceremony:?} corpus-want verifies: {e}"));
        wires.push(serde_json::from_str::<serde_json::Value>(&wire).unwrap());
    }
    let mut both = wires[1].clone();
    both["signature_ed25519_base64"] = wires[0]["signature_ed25519_base64"].clone();
    both["signature_ml_dsa_65_base64"] = wires[0]["signature_ml_dsa_65_base64"].clone();
    assert!(sc::verify_corpus_want_wire(
        &both.to_string(),
        &keys.ed25519_base64,
        keys.ml_dsa_65_base64.as_ref().unwrap()
    )
    .is_err());
}

/// The I1855 body: the stream door on one backend.
#[cfg(any(feature = "sqlite", feature = "postgres"))]
pub(crate) mod bodies {
    use super::*;
    use crate::federation::{BlobBody, BlobStorage, FederationDirectory, SignedKeyRecord};

    async fn register<B: FederationDirectory>(backend: &B, key_id: &str, keys: &PinnedKeys) {
        let record = crate::federation::KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: keys.ed25519_base64.clone(),
            pubkey_ml_dsa_65_base64: keys.ml_dsa_65_base64.clone(),
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: key_id.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: Some(
                crate::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(
                ),
            ),
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        backend
            .put_public_key(SignedKeyRecord { record })
            .await
            .unwrap();
    }

    /// I1855 on `backend` (a migrated, empty store). `tag` keeps postgres
    /// rows self-isolating.
    pub(crate) async fn i1855_the_stream_door_verifies_by_form<B>(backend: &B, tag: &str)
    where
        B: FederationDirectory + BlobStorage + Sync,
    {
        let producer_id = format!("i1855-producer-{tag}");
        let witness_id = format!("i1855-witness-{tag}");
        let producer = composite(0x91);
        let w = composite(0x93);
        register(backend, &producer_id, &pinned_of(&producer)).await;
        register(backend, &witness_id, &pinned_of(&w)).await;
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

        // An earlier-form head (a v61 producer) at the next size still admits.
        let (old, old_keys) = earlier(0xA1);
        let old_id = format!("i1855-earlier-{tag}");
        register(backend, &old_id, &old_keys).await;
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
        v61.signature = sth_form::test_support::earlier_sign(&old, &v61.signing_bytes_of());
        backend
            .put_stream_sth(v61.clone(), &old_id)
            .await
            .unwrap_or_else(|e| panic!("I1855 {tag}: an earlier-form head admits: {e}"));
        let served = backend.latest_stream_sth(&stream).await.unwrap().unwrap();
        assert_eq!(
            sth_form::form_of(&served.signature),
            Some(SignatureForm::Earlier)
        );
        assert_eq!(served.signature, v61.signature);
    }
}

#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i1855_the_stream_door_verifies_by_form_sqlite() {
    use crate::store::Backend as _;
    let backend = crate::store::sqlite::SqliteBackend::open_in_memory()
        .await
        .unwrap();
    backend.run_migrations().await.unwrap();
    bodies::i1855_the_stream_door_verifies_by_form(&backend, "sqlite").await;
}

#[cfg(feature = "postgres")]
#[tokio::test(flavor = "multi_thread")]
async fn i1855_the_stream_door_verifies_by_form_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        eprintln!("I1855: CIRIS_PERSIST_TEST_PG_URL unset; skipped");
        return;
    };
    let backend = crate::store::postgres::PostgresBackend::connect(&dsn)
        .await
        .unwrap();
    backend.run_migrations().await.unwrap();
    bodies::i1855_the_stream_door_verifies_by_form(&backend, "postgres").await;
}
