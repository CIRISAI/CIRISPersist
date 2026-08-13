//! v4.1 (CIRISPersist#142, Cut C1b) — per-stream transparency log
//! (CEG 0.10 §10.5.1).
//!
//! Each live stream (Cut C1a) is its own RFC 6962 transparency log:
//! its `log_id` is `stream:<stream_id>`, and its **leaves are the chunk
//! hashes** already stored in `federation_stream_chunks` (Cut C1a). This
//! module does NOT duplicate leaf storage; it stores producer-signed
//! [`SignedTreeHead`]s in `federation_stream_sth` (V063) and computes
//! RFC 6962 inclusion / consistency proofs **over those chunk hashes**.
//!
//! # RFC 6962 is NOT reimplemented here
//!
//! Every root / proof computation delegates to CIRISVerify's
//! [`InMemoryTransparencyStore`] — the same store the audit
//! `merkle_store` uses (see `src/audit/merkle_store.rs`). We build the
//! store from the stream's chunk-hash leaves and call its
//! `root` / `inclusion_proof` / `consistency_proof`. Reimplementing the
//! tree math would subtly break proof compatibility with every other
//! CIRIS transparency consumer.
//!
//! # The anti-equivocation gate (`put_stream_sth`)
//!
//! Persist does NOT sign stream STHs (unlike the audit log). The
//! producer signs; persist's job is integrity-gating, in EXACTLY this
//! order:
//!
//! 1. Parse `stream_id` from `sth.log_id` (must be `stream:<id>`).
//! 2. Load the first `sth.tree_size` chunk hashes from
//!    `federation_stream_chunks` (seq ASC). Fewer than `tree_size`
//!    exist → reject ([`BlobError::InvalidArgument`]): the STH claims
//!    more leaves than persist holds.
//! 3. Build an [`InMemoryTransparencyStore`] from those leaves; compute
//!    its root.
//! 4. Assert `computed_root == sth.root_hash` — mismatch → reject. This
//!    is the anti-equivocation integrity gate; it is NOT optional.
//! 5. Verify the producer's hybrid signature over `sth.signing_bytes_of()`
//!    using the producer's public key resolved from `federation_keys`
//!    (the `producer_key_id`) — NOT the pubkeys embedded in the
//!    signature. Reject on a bad signature.
//! 6. Only then INSERT. A `(stream_id, tree_size)` PK conflict with a
//!    DIFFERENT root → reject (equivocation attempt); identical →
//!    idempotent OK.
//!
//! Steps 1–4 (pure, no I/O) live in this module
//! ([`parse_stream_id`], [`recompute_and_assert_root`]); steps 5–6 live
//! in the backend `BlobStorage` impls (they own the SQL + the
//! `FederationDirectory` the signature check resolves against).

use ciris_verify_core::transparency::{
    ConsistencyProof, InMemoryTransparencyStore, MerkleProof, SignedTreeHead, TransparencyError,
    TransparencyLeaf, TransparencyStore, WitnessSignature,
};

use super::BlobError;

/// The `log_id` prefix for a per-stream transparency log
/// (CEG §10.5.1). The full log_id is `stream:<stream_id>`.
pub const STREAM_LOG_ID_PREFIX: &str = "stream:";

/// v4.1 (Cut C1b) — the `log_id` for a stream's transparency log.
/// Mirrors `merkle_store::log_id_for_tenant` (`tenant:<id>`).
#[must_use]
pub fn log_id_for_stream(stream_id: &str) -> String {
    format!("{STREAM_LOG_ID_PREFIX}{stream_id}")
}

/// v4.1 (Cut C1b) — a [`TransparencyLeaf`] wrapping one stream chunk's
/// 32-byte SHA-256 (a `federation_stream_chunks.chunk_sha`).
///
/// Its [`canonical_bytes`](TransparencyLeaf::canonical_bytes) are the
/// 32 raw chunk-sha bytes — the leaf DATA. The CIRISVerify store
/// applies the RFC 6962 §2.1 `0x00` leaf-hash prefix on top. This
/// mirrors how [`AuditLeaf`](crate::audit) implements `TransparencyLeaf`
/// (the leaf returns its canonical content; the store does the hashing).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StreamChunkLeaf {
    /// The chunk's content address (SHA-256), the leaf data.
    pub chunk_sha: [u8; 32],
}

impl StreamChunkLeaf {
    /// Wrap a chunk SHA as a transparency leaf.
    #[must_use]
    pub fn new(chunk_sha: [u8; 32]) -> Self {
        Self { chunk_sha }
    }
}

impl TransparencyLeaf for StreamChunkLeaf {
    fn canonical_bytes(&self) -> Result<Vec<u8>, TransparencyError> {
        // The leaf data is the 32-byte chunk sha. The crate applies the
        // RFC 6962 0x00 leaf-hash prefix — we do NOT prefix here.
        Ok(self.chunk_sha.to_vec())
    }
}

/// v4.1 (Cut C1b) — parse the `stream_id` out of an STH `log_id`.
///
/// The log_id must be `stream:<stream_id>` (CEG §10.5.1); anything else
/// is rejected — a stream STH cannot describe a non-stream log.
///
/// # Errors
///
/// [`BlobError::InvalidArgument`] if `log_id` lacks the `stream:`
/// prefix or the `<stream_id>` is empty.
pub fn parse_stream_id(log_id: &str) -> Result<&str, BlobError> {
    let id = log_id.strip_prefix(STREAM_LOG_ID_PREFIX).ok_or_else(|| {
        BlobError::InvalidArgument(format!(
            "put_stream_sth: log_id {log_id:?} is not a stream log \
             (expected `stream:<id>`)"
        ))
    })?;
    if id.is_empty() {
        return Err(BlobError::InvalidArgument(
            "put_stream_sth: empty stream_id in log_id".into(),
        ));
    }
    Ok(id)
}

/// v4.1 (Cut C1b) — build an [`InMemoryTransparencyStore`] over a
/// stream's chunk-hash leaves.
///
/// The single place this module constructs the RFC 6962 store. The
/// `chunk_hashes` are the `federation_stream_chunks.chunk_sha` values in
/// `seq ASC` order; each becomes a [`StreamChunkLeaf`].
fn build_store(
    chunk_hashes: &[[u8; 32]],
) -> Result<InMemoryTransparencyStore<StreamChunkLeaf>, BlobError> {
    let store: InMemoryTransparencyStore<StreamChunkLeaf> = InMemoryTransparencyStore::new(None);
    for sha in chunk_hashes {
        store
            .append(StreamChunkLeaf::new(*sha))
            .map_err(|e| BlobError::Backend(format!("stream-sth append leaf: {e}")))?;
    }
    Ok(store)
}

/// v4.1 (Cut C1b) — **the anti-equivocation gate** (steps 2–4).
///
/// `chunk_hashes` MUST be the first `tree_size` chunk hashes of the
/// stream in seq order (the backend loads exactly that). This:
///
/// - rejects if `chunk_hashes.len() < tree_size` (the STH claims more
///   leaves than persist holds);
/// - builds the RFC 6962 store from the (first `tree_size`) leaves and
///   recomputes the root via [`InMemoryTransparencyStore`]; and
/// - asserts the recomputed root equals `sth.root_hash`.
///
/// Returns `Ok(())` only when persist's own chunks reproduce the STH's
/// claimed root. NO signature work here — that is step 5, in the backend.
///
/// # Errors
///
/// [`BlobError::InvalidArgument`] on an over-claimed `tree_size` or a
/// root mismatch.
pub fn recompute_and_assert_root(
    sth: &SignedTreeHead,
    chunk_hashes: &[[u8; 32]],
) -> Result<(), BlobError> {
    let tree_size = usize::try_from(sth.tree_size).map_err(|_| {
        BlobError::InvalidArgument("put_stream_sth: tree_size exceeds usize".into())
    })?;

    // Step 2: persist must hold at least `tree_size` chunks.
    if chunk_hashes.len() < tree_size {
        return Err(BlobError::InvalidArgument(format!(
            "put_stream_sth: STH claims tree_size {tree_size} but persist \
             holds only {} chunks for the stream",
            chunk_hashes.len()
        )));
    }

    // Step 3: build the RFC 6962 store over EXACTLY the first
    // `tree_size` leaves and recompute the root.
    let store = build_store(&chunk_hashes[..tree_size])?;
    let computed_root = store
        .root()
        .map_err(|e| BlobError::Backend(format!("stream-sth root: {e}")))?;

    // Step 4: the assertion. A producer-claimed root that does not match
    // persist's own chunks is an equivocation attempt → reject.
    if computed_root != sth.root_hash {
        return Err(BlobError::InvalidArgument(format!(
            "put_stream_sth: root mismatch — STH claims {} but persist's \
             {tree_size} chunks reproduce {} (anti-equivocation gate)",
            hex::encode(sth.root_hash),
            hex::encode(computed_root),
        )));
    }
    Ok(())
}

/// v4.1 (Cut C1b) — extract the base64 Ed25519 + optional ML-DSA-65
/// signature components from a stored/parsed [`SignedTreeHead`]'s
/// [`HybridSignature`](ciris_crypto::HybridSignature), for handing to
/// [`verify_hybrid_via_directory`](crate::verify::verify_hybrid_via_directory).
///
/// The directory path resolves the producer's PINNED public keys from
/// `federation_keys` (it does NOT trust the pubkeys embedded in the
/// signature), so a forged STH carrying its own keypair cannot
/// self-certify. ML-DSA-65 is returned `None` only for a
/// classical-only signature mode (the hybrid-pending window); a normal
/// hybrid STH returns `Some`.
#[must_use]
pub fn signature_b64_parts(sth: &SignedTreeHead) -> (String, Option<String>) {
    hybrid_signature_b64_parts(&sth.signature)
}

/// v31.0.0 (CIRISPersist#657) — the body of [`signature_b64_parts`], lifted so
/// the WITNESS cosignatures go through the identical projection the PRODUCER
/// signature does.
///
/// A [`WitnessSignature`] carries the same
/// [`HybridSignature`](ciris_crypto::HybridSignature) shape over the same
/// [`SignedTreeHead::signing_bytes_of`] bytes, so it must be decomposed the
/// same way — including the `ClassicalOnly ⇒ None` arm, which is what makes a
/// classical-only cosignature fail hybrid-Strict instead of silently verifying
/// on one leg. Two spellings of this projection would be one of them drifting.
#[must_use]
pub fn hybrid_signature_b64_parts(sig: &ciris_crypto::HybridSignature) -> (String, Option<String>) {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    let ed25519_sig_b64 = B64.encode(&sig.classical.signature);
    let pqc_sig_b64 = match sig.mode {
        ciris_crypto::SignatureMode::ClassicalOnly => None,
        _ => Some(B64.encode(&sig.pqc.signature)),
    };
    (ed25519_sig_b64, pqc_sig_b64)
}

/// v4.1 (Cut C1b) — RFC 6962 inclusion proof for `leaf_index` against a
/// tree of `tree_size` leaves, built from the stream's chunk hashes.
///
/// `chunk_hashes` is the stream's seq-ordered chunk hashes (the backend
/// loads up to `tree_size`). Returns `Ok(None)` if the stream has fewer
/// than `tree_size` chunks or `leaf_index >= tree_size`. Delegates the
/// proof math to [`InMemoryTransparencyStore`] — no reimpl.
pub fn inclusion_proof(
    chunk_hashes: &[[u8; 32]],
    leaf_index: u64,
    tree_size: u64,
) -> Result<Option<MerkleProof>, BlobError> {
    let size = usize::try_from(tree_size).map_err(|_| {
        BlobError::InvalidArgument("inclusion_proof: tree_size exceeds usize".into())
    })?;
    if chunk_hashes.len() < size || leaf_index >= tree_size {
        return Ok(None);
    }
    let store = build_store(&chunk_hashes[..size])?;
    let proof = store
        .inclusion_proof(leaf_index)
        .map_err(|e| BlobError::Backend(format!("stream inclusion_proof: {e}")))?;
    Ok(Some(proof))
}

/// v4.1 (Cut C1b) — RFC 6962 §2.1.2 consistency proof between
/// `from_size` and `to_size`, built from the stream's chunk hashes.
///
/// `chunk_hashes` is the stream's seq-ordered chunk hashes (the backend
/// loads up to `to_size`). Returns `Ok(None)` if the stream has fewer
/// than `to_size` chunks. The crate validates the `0 < from <= to`
/// range. Delegates to [`InMemoryTransparencyStore`] — no reimpl.
pub fn consistency_proof(
    chunk_hashes: &[[u8; 32]],
    from_size: u64,
    to_size: u64,
) -> Result<Option<ConsistencyProof>, BlobError> {
    let to = usize::try_from(to_size).map_err(|_| {
        BlobError::InvalidArgument("consistency_proof: to_size exceeds usize".into())
    })?;
    if chunk_hashes.len() < to {
        return Ok(None);
    }
    let store = build_store(&chunk_hashes[..to])?;
    let proof = store
        .consistency_proof(from_size, to_size)
        .map_err(|e| BlobError::Backend(format!("stream consistency_proof: {e}")))?;
    Ok(Some(proof))
}

// ────────────────────────────────────────────────────────────────────
// SignedTreeHead <-> row column helpers (dialect-independent)
//
// Mirror merkle_store's serialize_signature / serialize_witness_signatures
// so the audit log and the stream log share the exact same on-disk
// signature encoding (JSON-as-bytes for the signature, JSON text for the
// witness list).
// ────────────────────────────────────────────────────────────────────

/// JSON-serialize the producer's `HybridSignature` for the
/// `signature_blob` column. JSON-as-bytes so PG (BYTEA) and SQLite
/// (BLOB) share the exact same encoding. Mirrors
/// `merkle_store::serialize_signature`.
pub fn serialize_signature(sig: &ciris_crypto::HybridSignature) -> Result<Vec<u8>, BlobError> {
    serde_json::to_vec(sig)
        .map_err(|e| BlobError::Backend(format!("stream-sth signature serialize: {e}")))
}

/// Inverse of [`serialize_signature`].
pub fn deserialize_signature(bytes: &[u8]) -> Result<ciris_crypto::HybridSignature, BlobError> {
    serde_json::from_slice(bytes)
        .map_err(|e| BlobError::Backend(format!("stream-sth signature deserialize: {e}")))
}

/// JSON-serialize the witness cosignatures for the `witness_signatures`
/// column (PG JSONB / SQLite TEXT). Mirrors
/// `merkle_store::serialize_witness_signatures`.
///
/// v31.0.0 (CIRISPersist#657) — this doc used to say the witnesses were
/// "stored as-provided". CORRECTED IN PLACE rather than deleted, because that
/// sentence described the defect: an as-provided cosignature is a signature the
/// substrate keeps and serves back through
/// [`FederationDirectory`](super::FederationDirectory)'s STH reads without ever
/// having checked it, which is worse than not keeping it because it LOOKS like
/// evidence (the #556 preserve-set-equals-verified-set rule, on the
/// transparency plane). Every cosignature reaching this encoder has now passed
/// [`blobs::verify_stream_sth_witnesses`](super::blobs) at the door. There is
/// still no cosign QUORUM — a quorum is a policy the consumer sets — but there
/// is no longer an unverified one.
pub fn serialize_witness_signatures(witnesses: &[WitnessSignature]) -> Result<String, BlobError> {
    serde_json::to_string(witnesses)
        .map_err(|e| BlobError::Backend(format!("stream-sth witness sigs serialize: {e}")))
}

/// Inverse of [`serialize_witness_signatures`].
pub fn deserialize_witness_signatures(raw: &str) -> Result<Vec<WitnessSignature>, BlobError> {
    serde_json::from_str(raw)
        .map_err(|e| BlobError::Backend(format!("stream-sth witness sigs deserialize: {e}")))
}

/// Coerce a row's `root_hash` bytes into a fixed array.
pub fn root_hash_from_bytes(raw: &[u8]) -> Result<[u8; 32], BlobError> {
    raw.try_into().map_err(|_| {
        BlobError::Backend(format!(
            "stream-sth root_hash column expected 32 bytes, got {}",
            raw.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_verify_core::transparency::verify_inclusion;
    use sha2::{Digest, Sha256};

    fn sha(seed: u8) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([seed]);
        h.finalize().into()
    }

    #[test]
    fn leaf_canonical_bytes_are_the_raw_sha() {
        let leaf = StreamChunkLeaf::new(sha(7));
        assert_eq!(leaf.canonical_bytes().unwrap(), sha(7).to_vec());
    }

    #[test]
    fn log_id_round_trip() {
        let id = log_id_for_stream("abc");
        assert_eq!(id, "stream:abc");
        assert_eq!(parse_stream_id(&id).unwrap(), "abc");
    }

    #[test]
    fn parse_rejects_non_stream_log_id() {
        assert!(parse_stream_id("tenant:abc").is_err());
        assert!(parse_stream_id("stream:").is_err());
    }

    #[test]
    fn recomputed_root_matches_inmemory_store() {
        // Build the same store the production path builds and confirm
        // recompute_and_assert_root accepts the store's own root.
        let hashes = [sha(1), sha(2), sha(3)];
        let store = build_store(&hashes).unwrap();
        let root = store.root().unwrap();
        let sth = SignedTreeHead {
            log_id: log_id_for_stream("s1"),
            tree_size: 3,
            root_hash: root,
            timestamp: chrono::Utc::now(),
            signature: dummy_sig(),
            witness_signatures: Vec::new(),
        };
        recompute_and_assert_root(&sth, &hashes).unwrap();
    }

    #[test]
    fn root_mismatch_is_rejected() {
        let hashes = [sha(1), sha(2), sha(3)];
        let sth = SignedTreeHead {
            log_id: log_id_for_stream("s1"),
            tree_size: 3,
            root_hash: [0xFF; 32], // wrong root
            timestamp: chrono::Utc::now(),
            signature: dummy_sig(),
            witness_signatures: Vec::new(),
        };
        assert!(recompute_and_assert_root(&sth, &hashes).is_err());
    }

    #[test]
    fn over_claimed_tree_size_is_rejected() {
        let hashes = [sha(1), sha(2)];
        let store = build_store(&hashes).unwrap();
        let sth = SignedTreeHead {
            log_id: log_id_for_stream("s1"),
            tree_size: 5, // more than the 2 chunks held
            root_hash: store.root().unwrap(),
            timestamp: chrono::Utc::now(),
            signature: dummy_sig(),
            witness_signatures: Vec::new(),
        };
        assert!(recompute_and_assert_root(&sth, &hashes).is_err());
    }

    #[test]
    fn inclusion_proof_verifies() {
        let hashes = [sha(1), sha(2), sha(3), sha(4)];
        let proof = inclusion_proof(&hashes, 2, 4).unwrap().unwrap();
        assert!(verify_inclusion(&proof));
        // Out-of-range index → None.
        assert!(inclusion_proof(&hashes, 4, 4).unwrap().is_none());
    }

    #[test]
    fn consistency_proof_built() {
        let hashes = [sha(1), sha(2), sha(3), sha(4)];
        let proof = consistency_proof(&hashes, 2, 4).unwrap().unwrap();
        assert_eq!(proof.old_tree_size, 2);
        assert_eq!(proof.new_tree_size, 4);
        // to_size beyond held chunks → None.
        assert!(consistency_proof(&hashes, 2, 9).unwrap().is_none());
    }

    #[test]
    fn signature_round_trips_through_columns() {
        let sig = dummy_sig();
        let blob = serialize_signature(&sig).unwrap();
        let back = deserialize_signature(&blob).unwrap();
        assert_eq!(back.classical.signature, sig.classical.signature);
        let raw = serialize_witness_signatures(&[]).unwrap();
        assert_eq!(raw, "[]");
        assert!(deserialize_witness_signatures(&raw).unwrap().is_empty());
    }

    fn dummy_sig() -> ciris_crypto::HybridSignature {
        ciris_crypto::HybridSignature {
            crypto_kind: ciris_crypto::CRYPTO_KIND_CIRIS_V1,
            classical: ciris_crypto::TaggedClassicalSignature {
                algorithm: ciris_crypto::ClassicalAlgorithm::Ed25519,
                signature: vec![0u8; 64],
                public_key: vec![0u8; 32],
            },
            pqc: ciris_crypto::TaggedPqcSignature {
                algorithm: ciris_crypto::PqcAlgorithm::MlDsa65,
                signature: vec![0u8; 3309],
                public_key: vec![0u8; 1952],
            },
            mode: ciris_crypto::SignatureMode::HybridRequired,
        }
    }
}
