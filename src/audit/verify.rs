//! Hash-chain + signature verify helpers for audit log entries
//! (v0.8.1, CIRISPersist#35).
//!
//! # Canonical-bytes shape
//!
//! Reuses
//! `crate::verify::canonical::canonicalize_envelope_for_signing_v1_pinned`
//! — the V1Python-PINNED strip-then-canonicalize rule. The rule strips
//! the `signature` field at the top level of the JSON object; everything
//! else (entry_id, sequence_number, tenant_id, actor_id, action_type,
//! subject_kind, subject_id, payload, prev_hash, entry_hash,
//! recorded_at) participates in the signed body.
//!
//! **Why pinned (v35.0.0, CIRISPersist#714):** audit is the one plane
//! where signatures minted over V1Python bytes live in STORED rows that
//! persist RE-VERIFIES later — `verify_chain` re-derives `entry_hash`
//! and re-checks `signature` from the stored row, and the Merkle tree's
//! leaf hashes are over these same bytes. When #714 routed
//! `canonicalize_envelope_for_signing` through the produce gate
//! (`ceg_produce_canonicalize`, V2Jcs), following it would have taken
//! every existing audit chain dark on the first non-ASCII or
//! non-ES-float-token payload. The stored corpus binds the rule; a
//! future flip is a per-row version-gate migration, not a canonicalizer
//! edit.
//!
//! Note: `entry_hash` IS part of the signed body. That binds the
//! signature to the chain position — a chain-rewrite that flipped
//! `prev_hash` of subsequent entries would invalidate this entry's
//! signature too, even though `signature` itself was stripped.
//!
//! # Why local (not cirisnode::verify::verify_envelope_signed)
//!
//! Same shape as cirisnode v0.7.1's helper but defined locally to
//! keep audit independent of the cirisnode feature gate. Future
//! v0.9.x refactor: lift `verify_envelope_signed` to a shared
//! `crate::verify::envelope` module once a third consumer emerges
//! (planned alongside the analogous `ListCursor` lift from v0.8.0).

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::verify::canonical::canonicalize_envelope_for_signing_v1_pinned;
use crate::verify::hybrid::{verify_hybrid, HybridPolicy};

use super::types::AuditEntry;
use super::Error;

/// Produce canonical bytes for an audit entry (or any other
/// signable shape that uses the audit-plane `signature` strip
/// rule). PINNED to the V1Python canonicalization — see the module
/// doc: the stored chain + Merkle corpus re-verifies from storage,
/// so this plane does not follow the produce epoch.
pub fn canonical_bytes_for_entry<T: Serialize>(entry: &T) -> Result<Vec<u8>, Error> {
    let value = serde_json::to_value(entry)
        .map_err(|e| Error::Internal(format!("entry serialize: {e}")))?;
    canonicalize_envelope_for_signing_v1_pinned(&value)
        .map_err(|e| Error::Internal(format!("canonicalize: {e}")))
}

/// AV-49: re-derive `entry_hash` from canonical bytes. Caller-
/// supplied value must match (else
/// [`Error::ChainIntegrity`]).
///
/// `entry_hash` is itself in the entry — to avoid the self-
/// referential circularity, we zero out `entry_hash` AND
/// `signature` before canonicalizing. The signature, by contrast,
/// is over canonical bytes that INCLUDE the resolved `entry_hash`
/// (signature only strips `signature` itself per the persist-wide
/// canonicalizer rule) — that binds the signature to the chain
/// position so a chain-rewrite that flipped `prev_hash` of
/// subsequent entries would invalidate this entry's signature too.
pub fn compute_entry_hash(entry: &AuditEntry) -> Result<[u8; 32], Error> {
    let mut for_hash = entry.clone();
    for_hash.entry_hash = Vec::new();
    for_hash.signature = String::new();
    let canonical = canonical_bytes_for_entry(&for_hash)?;
    let mut hasher = Sha256::new();
    hasher.update(&canonical);
    Ok(hasher.finalize().into())
}

/// Truncate a UTC datetime to microsecond precision. Postgres
/// TIMESTAMPTZ is microsecond-precision, so callers MUST round
/// `recorded_at` to microseconds **before** computing
/// [`compute_entry_hash`] and signing — otherwise the post-storage
/// round-trip hash will differ from the pre-storage one and
/// [`AuditService::verify_chain`](super::AuditService::verify_chain)
/// will report `EntryHashMismatch` on every row.
///
/// Convenience helper to do that truncation. Suggested usage:
///
/// ```ignore
/// let mut entry = AuditEntry { recorded_at: truncate_to_micros(Utc::now()), … };
/// entry.entry_hash = compute_entry_hash(&entry)?.to_vec();
/// entry.signature  = sign_canonical_bytes(&entry, &key)?;
/// service.record_entry(entry).await?;
/// ```
pub fn truncate_to_micros(dt: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
    use chrono::Timelike as _;
    let micros = dt.nanosecond() / 1000;
    dt.with_nanosecond(micros * 1000).unwrap_or(dt)
}

/// Verify an audit entry's Ed25519 signature against the embedded
/// `actor_id` (which IS the pubkey, per the v0.7.1 self-signed
/// identity model).
///
/// Uses [`HybridPolicy::Ed25519Fallback`] — audit entries are
/// classical-only in v0.8.1 (no per-actor ML-DSA-65 key yet). The
/// hybrid path lands alongside the federation-wide PQC rollout.
pub fn verify_entry_signature(entry: &AuditEntry) -> Result<(), Error> {
    if entry.signature.is_empty() {
        return Err(Error::Signature("signature missing".into()));
    }
    if entry.actor_id.is_empty() {
        return Err(Error::InvalidArgument("actor_id missing".into()));
    }
    let canonical = canonical_bytes_for_entry(entry)?;
    verify_hybrid(
        &canonical,
        &entry.signature,
        None, // no PQC half yet
        &entry.actor_id,
        None,
        HybridPolicy::Ed25519Fallback,
        None,
    )
    .map_err(|e| Error::Signature(format!("{e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::AuditEntry;
    use crate::audit::GENESIS_PREV_HASH;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use chrono::Utc;
    use ed25519_dalek::{Signer as _, SigningKey};
    use uuid::Uuid;

    fn pubkey_b64(key: &SigningKey) -> String {
        B64.encode(key.verifying_key().to_bytes())
    }

    /// Build + sign a genesis-of-chain audit entry under one tenant.
    fn sign_genesis_entry(key: &SigningKey, tenant_id: &str) -> AuditEntry {
        let actor = pubkey_b64(key);
        let mut entry = AuditEntry {
            entry_id: Uuid::new_v4().to_string(),
            sequence_number: 1,
            tenant_id: tenant_id.to_owned(),
            actor_id: actor,
            action_type: "test_action".into(),
            subject_kind: "task".into(),
            subject_id: "test-task-1".into(),
            payload: serde_json::json!({"k": "v"}),
            prev_hash: GENESIS_PREV_HASH.to_vec(),
            entry_hash: vec![],
            recorded_at: truncate_to_micros(Utc::now()),
            signature: String::new(),
        };
        // entry_hash is derived from canonical(entry minus signature).
        // Since signature is empty going in, this also captures the
        // post-INSERT state when persist normalizes signature.
        let hash = compute_entry_hash(&entry).unwrap();
        entry.entry_hash = hash.to_vec();
        let canonical = canonical_bytes_for_entry(&entry).unwrap();
        let sig = key.sign(&canonical);
        entry.signature = B64.encode(sig.to_bytes());
        entry
    }

    #[test]
    fn entry_hash_round_trip() {
        let key = SigningKey::from_bytes(&[0x33; 32]);
        let entry = sign_genesis_entry(&key, "tenant-test-1");
        // Re-deriving from the signed entry must match — note that
        // signature is stripped by the canonicalizer, so the hash
        // is stable even after signing.
        let derived = compute_entry_hash(&entry).unwrap();
        assert_eq!(derived.to_vec(), entry.entry_hash);
    }

    #[test]
    fn verify_genesis_entry_signature() {
        let key = SigningKey::from_bytes(&[0x44; 32]);
        let entry = sign_genesis_entry(&key, "tenant-test-2");
        verify_entry_signature(&entry).expect("genesis entry must verify");
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let key = SigningKey::from_bytes(&[0x55; 32]);
        let mut entry = sign_genesis_entry(&key, "tenant-test-3");
        entry.payload = serde_json::json!({"k": "TAMPERED"});
        let err = verify_entry_signature(&entry).unwrap_err();
        assert!(matches!(err, Error::Signature(_)), "got {err:?}");
    }

    #[test]
    fn verify_rejects_wrong_actor_id() {
        let signer = SigningKey::from_bytes(&[0x66; 32]);
        let imposter = SigningKey::from_bytes(&[0x77; 32]);
        let mut entry = sign_genesis_entry(&signer, "tenant-test-4");
        entry.actor_id = pubkey_b64(&imposter);
        let err = verify_entry_signature(&entry).unwrap_err();
        assert!(matches!(err, Error::Signature(_)));
    }

    #[test]
    fn verify_rejects_empty_signature() {
        let key = SigningKey::from_bytes(&[0x88; 32]);
        let mut entry = sign_genesis_entry(&key, "tenant-test-5");
        entry.signature = String::new();
        let err = verify_entry_signature(&entry).unwrap_err();
        match err {
            Error::Signature(msg) => assert!(msg.contains("missing")),
            other => panic!("expected Signature, got {other:?}"),
        }
    }
}
