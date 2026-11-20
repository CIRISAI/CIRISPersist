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
//! # The signature (v62.0.0, F0-cp8)
//!
//! The canonical JSON above is the HASH plane: `entry_hash` and the Merkle
//! leaves are over it. The signature is ONE composite (ML-DSA-65-Ed25519)
//! over a binary, domain-separated preimage ([`entry_signing_preimage`],
//! CC 6.1.3's framing) that carries `entry_hash`, so it binds the chain
//! position: a rewrite that flipped a later entry's `prev_hash` invalidates
//! that entry's signature too. `actor_id` is the signer's identity-ref, and
//! the signature verifies under the signer's edition-2 `key:record`
//! ([`verify_entry_signature`]).
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

/// v62.0.0 (F0-cp8; CC 6.1.3, CC 2.6.1.7) — **the bytes an audit entry's ONE
/// composite signature is over**: the entry's body framed under the
/// [`SigningDomain::AuditEntry`](crate::federation::edition2::signing_domain::SigningDomain::AuditEntry)
/// domain ([`domain_preimage`](crate::federation::edition2::signing_domain::domain_preimage)).
/// The body is binary and length-prefixed (the framing
/// `SignedTreeHead::signing_bytes` and the delivery receipt use: a `u32`
/// little-endian length before each variable field, little-endian integers):
///
/// ```text
/// b"ciris.signing_domain/v1\0"                24 bytes, the framing tag
/// u32le(20) || b"ciris.audit_entry.v1"        the domain
/// u32le(len(tenant_id))  || tenant_id (UTF-8)
/// u32le(len(actor_id))   || actor_id  (UTF-8)  the signer's identity-ref
/// i64le(sequence_number)                       8 bytes
/// prev_hash                                    32 bytes
/// entry_hash                                   32 bytes
/// ```
///
/// `entry_hash` is SHA-256 of the entry's canonical JSON with `entry_hash`
/// and `signature` stripped ([`compute_entry_hash`]), so it binds every
/// other field (`entry_id`, `action_type`, `subject_*`, `payload`,
/// `recorded_at`); the tenant, signer, chain position and predecessor are
/// framed beside it so the preimage names them without a JSON parse. The
/// signature itself is never in it, and the Merkle leaf keeps stripping it
/// (`audit::merkle_leaf`): the leaf hashes the same canonical JSON as before.
///
/// # Errors
/// [`Error::InvalidArgument`] for a `prev_hash` / `entry_hash` that is not
/// 32 bytes, or a field longer than `u32::MAX` bytes.
pub fn entry_signing_preimage(entry: &AuditEntry) -> Result<Vec<u8>, Error> {
    fn framed(buf: &mut Vec<u8>, name: &str, field: &[u8]) -> Result<(), Error> {
        let len = u32::try_from(field.len())
            .map_err(|_| Error::InvalidArgument(format!("{name} is longer than u32::MAX bytes")))?;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(field);
        Ok(())
    }
    let prev: &[u8; 32] = entry.prev_hash.as_slice().try_into().map_err(|_| {
        Error::InvalidArgument(format!(
            "prev_hash must be 32 bytes, got {}",
            entry.prev_hash.len()
        ))
    })?;
    let hash: &[u8; 32] = entry.entry_hash.as_slice().try_into().map_err(|_| {
        Error::InvalidArgument(format!(
            "entry_hash must be 32 bytes, got {}",
            entry.entry_hash.len()
        ))
    })?;
    let mut buf =
        Vec::with_capacity(4 + entry.tenant_id.len() + 4 + entry.actor_id.len() + 8 + 32 + 32);
    framed(&mut buf, "tenant_id", entry.tenant_id.as_bytes())?;
    framed(&mut buf, "actor_id", entry.actor_id.as_bytes())?;
    buf.extend_from_slice(&entry.sequence_number.to_le_bytes());
    buf.extend_from_slice(prev);
    buf.extend_from_slice(hash);
    use crate::federation::edition2::signing_domain::{domain_preimage, SigningDomain};
    Ok(domain_preimage(SigningDomain::AuditEntry, &buf))
}

/// v62.0.0 (F0-cp8) — the instant (POSIX ms) a stored entry's signature is
/// re-checked at by a chain walk: its own `recorded_at`. The entry was
/// admitted at the instant it was recorded (`record_entry` /
/// `try_claim_event` check at the node's now); the walk asks whether the
/// signer's key covered the entry when it was written, so a key that has
/// since rotated out does not take the chain dark.
#[must_use]
pub fn stored_entry_instant_ms(entry: &AuditEntry) -> u64 {
    u64::try_from(entry.recorded_at.timestamp_millis()).unwrap_or(0)
}

/// **Verify an audit entry's ONE composite signature** (v62.0.0, F0-cp8; CC
/// 6.1.3, CC 2.6.1.7: composite signatures only): `signature` is the base64
/// ML-DSA-65-Ed25519 composite (3373 bytes) over
/// [`entry_signing_preimage`], verified under the live edition-2 `key:record`
/// of the signer `actor_id` names (an identity-ref) at `at_ms`, through the
/// one directory-backed verifier
/// ([`verify_composite_via_directory`](crate::federation::edition2::composite_verify::verify_composite_via_directory)).
///
/// In order, each refused by name:
/// - an empty `signature` (`signature missing`) or `actor_id`;
/// - an `entry_hash` that is not the entry's own ([`compute_entry_hash`]);
/// - a signature that is not standard base64;
/// - a lone Ed25519 (64 bytes) or ML-DSA-65 half: `verify_component_signature`
///   (the earlier entry form, a lone Ed25519 under an `actor_id` that was the
///   pubkey, is this refusal), any other length `verify_composite_invalid`;
/// - an `actor_id` that is not an identity-ref: `verify_not_identity_ref`;
/// - the signer's key plane at `at_ms`: `verify_unknown_key`,
///   `verify_signer_revoked`, `verify_signer_not_covered`,
///   `verify_signer_waiting`;
/// - a composite that does not verify: `verify_composite_invalid`.
///
/// Each is [`Error::Signature`] whose message leads with the token, except a
/// failed directory read, which is [`Error::Backend`] (`verify_directory`).
///
/// Before v62 an entry carried an inner Ed25519 signature under an `actor_id`
/// that was the pubkey, kept classical because no other node verified it (CC
/// 1.13.4). F0-cp8: the entry is signed under the signer's identity-ref, like
/// every other object a key signs, and the one deliberate classical verify
/// is gone.
///
/// # Errors
/// As above.
pub async fn verify_entry_signature<F>(dir: &F, entry: &AuditEntry, at_ms: u64) -> Result<(), Error>
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    use crate::federation::edition2::composite_verify::{
        verify_composite_via_directory, CompositeVerifyError,
    };
    if entry.signature.is_empty() {
        return Err(Error::Signature("signature missing".into()));
    }
    if entry.actor_id.is_empty() {
        return Err(Error::InvalidArgument("actor_id missing".into()));
    }
    let derived = compute_entry_hash(entry)?;
    if derived.as_slice() != entry.entry_hash.as_slice() {
        return Err(Error::ChainIntegrity(
            "entry_hash mismatch: the signed preimage binds the entry's own hash".into(),
        ));
    }
    use base64::Engine as _;
    let sig = base64::engine::general_purpose::STANDARD
        .decode(&entry.signature)
        .map_err(|e| Error::Signature(format!("signature base64: {e}")))?;
    let preimage = entry_signing_preimage(entry)?;
    match verify_composite_via_directory(dir, &preimage, &entry.actor_id, &sig, at_ms).await {
        Ok(_) => Ok(()),
        Err(e @ CompositeVerifyError::Directory(_)) => Err(Error::Backend(e.to_string())),
        Err(e) => Err(Error::Signature(e.to_string())),
    }
}

/// v62.0.0 (F0-cp8) — **seal an audit entry with `signer`'s composite key**:
/// the persist-side producer of the form [`verify_entry_signature`] admits.
///
/// - `actor_id` becomes the signer's identity-ref
///   ([`LocalSigner::federation_id`](crate::signing::LocalSigner::federation_id));
///   an entry that already names another signer is refused;
/// - `recorded_at` is truncated to microseconds ([`truncate_to_micros`]);
/// - `entry_hash` is computed ([`compute_entry_hash`]);
/// - `signature` is the base64 composite over [`entry_signing_preimage`].
///
/// The caller fills the chain position (`sequence_number`, `prev_hash`, from
/// `AuditService::next_chain_position`) and the content fields first.
///
/// # Errors
/// [`Error::InvalidArgument`] for an entry naming another signer or a
/// malformed `prev_hash`; [`Error::Signature`] when the signer cannot sign a
/// composite (no ML-DSA-65 half: `PqcNotConfigured`).
pub async fn seal_entry(
    signer: &crate::signing::LocalSigner,
    mut entry: AuditEntry,
) -> Result<AuditEntry, Error> {
    use base64::Engine as _;
    if signer.pqc_signer().is_none() {
        return Err(Error::Signature(
            "audit entry: the signer has no ML-DSA-65 half; an entry is signed with ONE \
             composite (CC 2.6.1.7)"
                .into(),
        ));
    }
    let identity_ref = signer.federation_id().await;
    if !entry.actor_id.is_empty() && entry.actor_id != identity_ref {
        return Err(Error::InvalidArgument(format!(
            "actor_id {} is not this signer ({identity_ref}); an entry is sealed by its actor",
            entry.actor_id
        )));
    }
    entry.actor_id = identity_ref;
    entry.recorded_at = truncate_to_micros(entry.recorded_at);
    entry.signature = String::new();
    entry.entry_hash = compute_entry_hash(&entry)?.to_vec();
    let preimage = entry_signing_preimage(&entry)?;
    let sig = signer
        .sign_composite(&preimage)
        .await
        .map_err(|e| Error::Signature(format!("audit entry composite sign: {e}")))?;
    entry.signature = base64::engine::general_purpose::STANDARD.encode(sig);
    Ok(entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::types::AuditEntry;
    use crate::audit::GENESIS_PREV_HASH;
    use chrono::Utc;

    fn unsigned_entry(tenant_id: &str) -> AuditEntry {
        let mut entry = AuditEntry {
            entry_id: "00000000-0000-4000-8000-000000000001".into(),
            sequence_number: 7,
            tenant_id: tenant_id.to_owned(),
            actor_id: "urn:ietf:params:oauth:ckt:sha-256:f0-cp8".into(),
            action_type: "test_action".into(),
            subject_kind: "task".into(),
            subject_id: "test-task-1".into(),
            payload: serde_json::json!({"k": "v"}),
            prev_hash: GENESIS_PREV_HASH.to_vec(),
            entry_hash: vec![],
            recorded_at: truncate_to_micros(Utc::now()),
            signature: String::new(),
        };
        entry.entry_hash = compute_entry_hash(&entry).unwrap().to_vec();
        entry
    }

    #[test]
    fn entry_hash_round_trip() {
        let mut entry = unsigned_entry("tenant-test-1");
        // `signature` is stripped from the hashed bytes, so the hash is
        // stable once the entry is signed.
        entry.signature = "c2ln".into();
        let derived = compute_entry_hash(&entry).unwrap();
        assert_eq!(derived.to_vec(), entry.entry_hash);
    }

    /// **I2894 — the audit entry's signing preimage, byte for byte** (the
    /// layout F0-cp8.md hands the Agent): the domain framing, the u32-LE framed
    /// tenant and signer, the i64-LE sequence number, then the two hashes.
    /// The signature is not in it.
    #[test]
    fn i2894_the_entry_signing_preimage_layout() {
        let mut entry = unsigned_entry("t1");
        let pre = entry_signing_preimage(&entry).unwrap();
        let mut want = b"ciris.signing_domain/v1\0".to_vec();
        want.extend_from_slice(&20u32.to_le_bytes());
        want.extend_from_slice(b"ciris.audit_entry.v1");
        want.extend_from_slice(&2u32.to_le_bytes());
        want.extend_from_slice(b"t1");
        let actor = entry.actor_id.as_bytes().to_vec();
        want.extend_from_slice(&u32::try_from(actor.len()).unwrap().to_le_bytes());
        want.extend_from_slice(&actor);
        want.extend_from_slice(&7i64.to_le_bytes());
        want.extend_from_slice(&GENESIS_PREV_HASH);
        want.extend_from_slice(&entry.entry_hash);
        assert_eq!(pre, want, "I2894: the preimage layout");
        entry.signature = "anything".into();
        assert_eq!(
            entry_signing_preimage(&entry).unwrap(),
            want,
            "I2894: the signature is not in its own preimage"
        );
        entry.entry_hash = vec![0; 31];
        assert!(
            matches!(
                entry_signing_preimage(&entry),
                Err(Error::InvalidArgument(_))
            ),
            "I2894: a hash that is not 32 bytes has no preimage"
        );
    }
}
