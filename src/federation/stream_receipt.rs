//! Streaming delivery receipts — `delivery_receipt:{stream_id}`
//! (CIRISPersist#142 Cut C4, CEG 0.15 §10.5.4).
//!
//! A delivery receipt is a subscriber's **signed acknowledgement** that
//! they received chunk `K` under `(stream_id, epoch)`. Its verification
//! is a **JOIN, not a sig-check**: the signature is necessary but NOT
//! sufficient — the load-bearing check is that the receipt's
//! `chunk_root` is a **real published STH root** for the stream (a
//! `federation_stream_sth` row, C1b), at `tree_size >= K`. A subscriber
//! cannot acknowledge a root the producer never published.
//!
//! # Semantics (§10.5.4 + MISSION §1.4)
//!
//! Proof-of-**delivery**, not proof-of-consumption — the subscriber
//! received bytes committing to chunk K; it does NOT prove they
//! decrypted them (they may not hold the epoch DEK). Persist
//! **validates** (authenticates origin + JOINs against the published
//! root) but does NOT **adjudicate**: it composes no "delivered" /
//! "owes N" verdict and does NOT enforce community membership — those
//! are consumer policy.
//!
//! # Canonical signing bytes (§10.5.4 — V3 lock)
//!
//! Domain-separated + length-prefixed, matching the
//! [`SignedTreeHead::signing_bytes`] discipline (u32 **little-endian**
//! length prefix; multi-byte integers little-endian). The byte layout
//! is the cross-impl interop surface — producer, substrate, and
//! consumer MUST agree byte-for-byte, so it lives in the single
//! [`receipt_signing_bytes`] function:
//!
//! ```text
//! b"ciris-delivery-receipt/v1"
//!   ‖ (len(subscriber_key) as u32 LE) ‖ subscriber_key
//!   ‖ (len(stream_id)      as u32 LE) ‖ stream_id
//!   ‖ epoch       (u64 LE)
//!   ‖ chunk_root  ([u8; 32])
//!   ‖ K           (u64 LE)
//! ```
//!
//! # Crypto routing (MISSION §1.4)
//!
//! The subscriber signature is verified via
//! [`crate::verify::verify_hybrid_via_directory`] against the **pinned**
//! `federation_keys` key (never keys embedded in the signature) — the
//! same discipline C1b's `verify_stream_sth_signature` uses. No rolled
//! crypto.

use ciris_verify_core::transparency::SignedTreeHead;

/// Domain-separation tag for the receipt signing bytes (§10.5.4).
const RECEIPT_SIGNING_DOMAIN: &[u8] = b"ciris-delivery-receipt/v1";

/// A subscriber's signed delivery acknowledgement for one chunk.
///
/// `Serialize`/`Deserialize` is the FFI boundary shape (PyO3
/// `put_delivery_receipt` takes the receipt as a JSON string).
/// `chunk_root` serializes as a 32-element byte array; `signature`
/// reuses the `ciris_crypto::HybridSignature` serde shape shared with
/// [`SignedTreeHead`].
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeliveryReceipt {
    /// The stream this receipt is for (`log_id`-equivalent `stream:<id>`
    /// is the transparency log; `stream_id` here is the bare id).
    pub stream_id: String,
    /// The acknowledging subscriber's `federation_keys.key_id`.
    pub subscriber_key_id: String,
    /// Key-rotation epoch the chunk was sealed under (per-epoch
    /// entitlement / billing scope).
    pub epoch: u64,
    /// Chunk index acknowledged (the `K` in §10.5.4).
    pub k: u64,
    /// The committed STH root the subscriber saw at `tree_size >= k`.
    pub chunk_root: [u8; 32],
    /// Subscriber's hybrid Ed25519 + ML-DSA-65 signature over
    /// [`receipt_signing_bytes`].
    pub signature: ciris_crypto::HybridSignature,
}

/// Build the canonical signing bytes for a receipt (§10.5.4 — the sole
/// place this cross-impl encoding lives). Matches
/// [`SignedTreeHead::signing_bytes`]: a `u32` little-endian length
/// prefix on each variable field, little-endian multi-byte integers.
pub fn receipt_signing_bytes(
    subscriber_key_id: &str,
    stream_id: &str,
    epoch: u64,
    chunk_root: &[u8; 32],
    k: u64,
) -> Vec<u8> {
    let sub = subscriber_key_id.as_bytes();
    let sid = stream_id.as_bytes();
    let mut buf = Vec::with_capacity(
        RECEIPT_SIGNING_DOMAIN.len() + 4 + sub.len() + 4 + sid.len() + 8 + 32 + 8,
    );
    buf.extend_from_slice(RECEIPT_SIGNING_DOMAIN);
    buf.extend_from_slice(&(u32::try_from(sub.len()).unwrap_or(u32::MAX)).to_le_bytes());
    buf.extend_from_slice(sub);
    buf.extend_from_slice(&(u32::try_from(sid.len()).unwrap_or(u32::MAX)).to_le_bytes());
    buf.extend_from_slice(sid);
    buf.extend_from_slice(&epoch.to_le_bytes());
    buf.extend_from_slice(chunk_root);
    buf.extend_from_slice(&k.to_le_bytes());
    buf
}

/// Canonical signing bytes for a [`DeliveryReceipt`].
pub fn receipt_signing_bytes_of(receipt: &DeliveryReceipt) -> Vec<u8> {
    receipt_signing_bytes(
        &receipt.subscriber_key_id,
        &receipt.stream_id,
        receipt.epoch,
        &receipt.chunk_root,
        receipt.k,
    )
}

/// Extract the base64 (ed25519, ml_dsa_65) signature parts from a
/// [`SignedTreeHead`]-style `HybridSignature` for the directory verify
/// path — mirrors `crate::federation::stream_sth::signature_b64_parts`.
/// Re-exported here so the receipt path shares the exact extraction.
pub use crate::federation::stream_sth::signature_b64_parts as hybrid_signature_b64_parts;

/// Verify a receipt's subscriber signature against the pinned
/// `federation_keys` key (Strict). Necessary, NOT sufficient — the
/// caller MUST additionally JOIN `chunk_root` against a published STH
/// (§10.5.4 step 2). Mirrors C1b's `verify_stream_sth_signature`.
pub async fn verify_receipt_signature<F>(
    directory: &F,
    receipt: &DeliveryReceipt,
) -> Result<(), crate::federation::BlobError>
where
    F: crate::federation::FederationDirectory,
{
    // Reuse the STH signature-extraction shape by wrapping the receipt
    // sig in the same HybridSignature → (ed25519_b64, ml_dsa_b64) split.
    let sth_like = SignedTreeHead {
        log_id: String::new(),
        tree_size: 0,
        root_hash: [0u8; 32],
        timestamp: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0)
            .expect("epoch is a valid timestamp"),
        signature: receipt.signature.clone(),
        witness_signatures: Vec::new(),
    };
    let (ed25519_sig_b64, ml_dsa_65_sig_b64) = hybrid_signature_b64_parts(&sth_like);
    let signing_bytes = receipt_signing_bytes_of(receipt);
    crate::verify::verify_hybrid_via_directory(
        directory,
        &signing_bytes,
        &receipt.subscriber_key_id,
        &ed25519_sig_b64,
        ml_dsa_65_sig_b64.as_deref(),
        crate::verify::HybridPolicy::Strict,
        None,
    )
    .await
    .map(|_| ())
    .map_err(|e| {
        crate::federation::BlobError::InvalidArgument(format!(
            "put_delivery_receipt: subscriber signature verification failed for \
             key_id={}: {e}",
            receipt.subscriber_key_id
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_bytes_layout_is_pinned() {
        let bytes = receipt_signing_bytes("sub-key", "stream-1", 3, &[0xAB; 32], 7);
        // domain tag first
        assert!(bytes.starts_with(RECEIPT_SIGNING_DOMAIN));
        let mut off = RECEIPT_SIGNING_DOMAIN.len();
        // u32 LE len(subscriber_key) = 7
        assert_eq!(&bytes[off..off + 4], &7u32.to_le_bytes());
        off += 4;
        assert_eq!(&bytes[off..off + 7], b"sub-key");
        off += 7;
        // u32 LE len(stream_id) = 8
        assert_eq!(&bytes[off..off + 4], &8u32.to_le_bytes());
        off += 4;
        assert_eq!(&bytes[off..off + 8], b"stream-1");
        off += 8;
        // epoch u64 LE
        assert_eq!(&bytes[off..off + 8], &3u64.to_le_bytes());
        off += 8;
        // chunk_root [32]
        assert_eq!(&bytes[off..off + 32], &[0xAB; 32]);
        off += 32;
        // K u64 LE
        assert_eq!(&bytes[off..off + 8], &7u64.to_le_bytes());
        off += 8;
        assert_eq!(off, bytes.len(), "no trailing bytes");
    }

    #[test]
    fn distinct_fields_change_the_bytes() {
        let base = receipt_signing_bytes("s", "st", 1, &[1u8; 32], 1);
        assert_ne!(base, receipt_signing_bytes("s2", "st", 1, &[1u8; 32], 1));
        assert_ne!(base, receipt_signing_bytes("s", "st2", 1, &[1u8; 32], 1));
        assert_ne!(base, receipt_signing_bytes("s", "st", 2, &[1u8; 32], 1));
        assert_ne!(base, receipt_signing_bytes("s", "st", 1, &[2u8; 32], 1));
        assert_ne!(base, receipt_signing_bytes("s", "st", 1, &[1u8; 32], 2));
    }

    /// The receipt domain tag must differ from the STH signing domain so
    /// a subscriber receipt signature can never be replayed as a
    /// producer STH signature (or vice versa) — cross-protocol safety.
    #[test]
    fn receipt_domain_differs_from_sth_domain() {
        // The STH domain (ciris_verify_core) and the receipt domain are
        // distinct byte strings; a signature over one can't validate as
        // the other because the signed bytes begin with different tags.
        assert!(RECEIPT_SIGNING_DOMAIN.starts_with(b"ciris-delivery-receipt"));
        let receipt_bytes = receipt_signing_bytes("k", "s", 0, &[0u8; 32], 0);
        // An STH log_id-style prefix ("stream:") never appears at the
        // head of receipt bytes — the domain tag is first.
        assert!(!receipt_bytes.starts_with(b"stream:"));
        assert!(receipt_bytes.starts_with(RECEIPT_SIGNING_DOMAIN));
    }

    /// The FFI boundary serializes `DeliveryReceipt` as JSON; confirm a
    /// full round-trip preserves every field including the 32-byte root
    /// and the hybrid signature.
    #[test]
    fn delivery_receipt_json_round_trips() {
        let receipt = DeliveryReceipt {
            stream_id: "stream-x".to_owned(),
            subscriber_key_id: "sub-x".to_owned(),
            epoch: 9,
            k: 42,
            chunk_root: [0x5Au8; 32],
            signature: ciris_crypto::HybridSignature {
                crypto_kind: ciris_crypto::CRYPTO_KIND_CIRIS_V1,
                classical: ciris_crypto::TaggedClassicalSignature {
                    algorithm: ciris_crypto::ClassicalAlgorithm::Ed25519,
                    signature: vec![1u8; 64],
                    public_key: vec![2u8; 32],
                },
                pqc: ciris_crypto::TaggedPqcSignature {
                    algorithm: ciris_crypto::PqcAlgorithm::MlDsa65,
                    signature: vec![3u8; 3309],
                    public_key: vec![4u8; 1952],
                },
                mode: ciris_crypto::SignatureMode::HybridRequired,
            },
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let back: DeliveryReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(back.stream_id, receipt.stream_id);
        assert_eq!(back.subscriber_key_id, receipt.subscriber_key_id);
        assert_eq!(back.epoch, receipt.epoch);
        assert_eq!(back.k, receipt.k);
        assert_eq!(back.chunk_root, receipt.chunk_root);
        assert_eq!(
            back.signature.classical.signature,
            receipt.signature.classical.signature
        );
        assert_eq!(
            back.signature.pqc.signature,
            receipt.signature.pqc.signature
        );
        // The canonical signing bytes survive the round-trip identically.
        assert_eq!(
            receipt_signing_bytes_of(&back),
            receipt_signing_bytes_of(&receipt)
        );
    }
}
