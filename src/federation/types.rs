//! Federation directory wire-format types.
//!
//! These shapes are the source of truth for both persist's backends
//! and CIRISRegistry's vendored
//! `rust-registry/src/federation/types.rs`. Field names + types must
//! match field-for-field between the two repos.
//!
//! # Identity, algorithm, and attestation type strings
//!
//! Persist stores these as TEXT columns (not enums) so new values can
//! be added by either side without a schema break. The constants in
//! [`identity_type`], [`algorithm`], and [`attestation_type`] are the
//! values both sides know about today; consumers may invent new
//! values as trust models evolve (the `attestation_type` "referred"
//! / "delegated_to" pattern is exactly this — neither was needed at
//! v0.2.0 design but the string-typed column accommodates them).
//!
//! # Canonical hashing
//!
//! [`KeyRecord::persist_row_hash`] is computed server-side by persist
//! via `crate::verify::canonical::PythonJsonDumpsCanonicalizer` (sorted
//! keys, no whitespace, `ensure_ascii=True`) over the row's
//! user-visible fields. Consumers store the hex string verbatim and
//! string-compare on cache divergence checks. Same shape for
//! [`Attestation::persist_row_hash`] and
//! [`Revocation::persist_row_hash`].
//!
//! See `docs/FEDERATION_DIRECTORY.md` §"persist_row_hash —
//! server-computed for cache divergence" for the architectural
//! rationale.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Identity classification per persist's `identity_type` column.
pub mod identity_type {
    /// Agent trace-signing keys.
    pub const AGENT: &str = "agent";
    /// Primitive build-signing keys (ciris-persist, ciris-agent, etc.).
    pub const PRIMITIVE: &str = "primitive";
    /// Steward keys (registry, persist, lens, agent — the trust roots).
    pub const STEWARD: &str = "steward";
    /// Per-org partner keys for commercial onboarding.
    pub const PARTNER: &str = "partner";
}

/// Algorithm strings matching persist's `algorithm` column.
pub mod algorithm {
    /// Raw Ed25519 32-byte verifying key.
    pub const ED25519: &str = "ed25519";
    /// ML-DSA-65 (post-quantum) verifying key.
    pub const ML_DSA_65: &str = "ml-dsa-65";
    /// Hybrid Ed25519 + ML-DSA-65 separator-encoded.
    pub const HYBRID: &str = "hybrid";
}

/// Attestation type strings (string set is open — consumers may invent
/// new types as trust models evolve).
pub mod attestation_type {
    /// "I have personally verified this key represents identity X."
    /// High-weight; what stewards do.
    pub const VOUCHES_FOR: &str = "vouches_for";
    /// "I observed this key in production traffic at time T, no
    /// anomalies." Low-weight; what passive observers do.
    pub const WITNESSES: &str = "witnesses";
    /// "I trust the key, and I trust its referrer to vouch for it."
    /// Transitive; weight decays per PoB §4.
    pub const REFERRED: &str = "referred";
    /// "This key may sign on my behalf within scope S." Used by
    /// hardware-backed re-signers and steward-key rotation.
    pub const DELEGATED_TO: &str = "delegated_to";
}

/// `federation_keys` row.
///
/// Field order matters for serde default JSON serialization (field
/// declaration order is the JSON key order). CIRISRegistry's vendored
/// shape mirrors this declaration order; changes here require a
/// matching change there to preserve `persist_row_hash` parity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyRecord {
    /// Canonical key identifier (matches `signature_key_id` on the
    /// trace-verification wire).
    pub key_id: String,
    /// Pubkey bytes, base64 standard alphabet.
    pub pubkey_base64: String,
    /// Algorithm string ([`algorithm::ED25519`], etc.).
    pub algorithm: String,
    /// Identity classification ([`identity_type::AGENT`], etc.).
    pub identity_type: String,
    /// Logical identity reference (shape varies by `identity_type`).
    pub identity_ref: String,
    /// When the key became valid.
    pub valid_from: DateTime<Utc>,
    /// When the key expires (`None` = no expiry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<DateTime<Utc>>,
    /// Canonical bytes of the registration envelope (verbatim).
    pub registration_envelope: serde_json::Value,
    /// SHA-256 of `registration_envelope`. Hex-encoded.
    pub original_content_hash: String,
    /// Ed25519 over `original_content_hash`. Base64-encoded.
    pub scrub_signature: String,
    /// `key_id` of the row that signed THIS row. Bootstrap rows have
    /// `scrub_key_id == key_id` (self-signed); all others reference
    /// an existing `federation_keys` row.
    pub scrub_key_id: String,
    /// When the scrub-signature was issued.
    pub scrub_timestamp: DateTime<Utc>,
    /// **Server-computed.** Hex-encoded SHA-256 over the canonical
    /// bytes of this row (via persist's
    /// `PythonJsonDumpsCanonicalizer`). Consumers store + string-
    /// compare; they don't reproduce the canonicalizer. Closes the
    /// shortest-round-trip drift class of cache-divergence bugs.
    pub persist_row_hash: String,
}

/// `federation_attestations` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    /// UUID identifier for this attestation row.
    pub attestation_id: String,
    /// Key making the attestation (must exist in `federation_keys`).
    pub attesting_key_id: String,
    /// Key being attested (must exist in `federation_keys`).
    pub attested_key_id: String,
    /// Attestation type ([`attestation_type::VOUCHES_FOR`], etc.).
    pub attestation_type: String,
    /// Optional weight signal carried by the attester.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<f64>,
    /// When the attestation was made.
    pub asserted_at: DateTime<Utc>,
    /// When the attestation expires (`None` = no expiry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Canonical bytes of the attestation envelope.
    pub attestation_envelope: serde_json::Value,
    /// SHA-256 of `attestation_envelope`. Hex-encoded.
    pub original_content_hash: String,
    /// Ed25519 over `original_content_hash`. Base64-encoded.
    pub scrub_signature: String,
    /// `key_id` that signed this row.
    pub scrub_key_id: String,
    /// When the scrub-signature was issued.
    pub scrub_timestamp: DateTime<Utc>,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

/// `federation_revocations` row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Revocation {
    /// UUID identifier for this revocation row.
    pub revocation_id: String,
    /// Key being revoked.
    pub revoked_key_id: String,
    /// Key issuing the revocation.
    pub revoking_key_id: String,
    /// Free-form reason; consumers parse if they care.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When the revocation was issued.
    pub revoked_at: DateTime<Utc>,
    /// When the revocation takes effect (may be retroactive or future).
    pub effective_at: DateTime<Utc>,
    /// Canonical bytes of the revocation envelope.
    pub revocation_envelope: serde_json::Value,
    /// SHA-256 of `revocation_envelope`. Hex-encoded.
    pub original_content_hash: String,
    /// Ed25519 over `original_content_hash`. Base64-encoded.
    pub scrub_signature: String,
    /// `key_id` that signed this row.
    pub scrub_key_id: String,
    /// When the scrub-signature was issued.
    pub scrub_timestamp: DateTime<Utc>,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

/// Wraps a [`KeyRecord`] payload that the caller has signed but
/// persist has not yet stored. Persist verifies the scrub-signature
/// on receipt before writing. The wrapper exists so write-path
/// signatures match read-path shapes (which include `persist_row_hash`
/// populated by persist) without forcing callers to compute that hash
/// themselves. On `put_public_key`, persist ignores the caller's
/// `persist_row_hash` field and computes its own.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedKeyRecord {
    /// The record being submitted. `persist_row_hash` is ignored on
    /// write — persist computes its own.
    pub record: KeyRecord,
}

/// Wraps an [`Attestation`] payload for write submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedAttestation {
    /// The attestation being submitted.
    pub attestation: Attestation,
}

/// Wraps a [`Revocation`] payload for write submission.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedRevocation {
    /// The revocation being submitted.
    pub revocation: Revocation,
}

/// Compute the canonical-bytes hash for a row used for
/// `persist_row_hash`. Persist calls this server-side on every write
/// path so consumers don't have to.
///
/// Uses [`crate::verify::canonical::PythonJsonDumpsCanonicalizer`] —
/// the same shape persist uses for trace canonical bytes — over the
/// row's serde-default JSON representation **excluding** the
/// `persist_row_hash` field itself (else the hash would depend on
/// itself).
///
/// Returns the hex-encoded SHA-256 string.
pub fn compute_persist_row_hash<T: Serialize>(row: &T) -> Result<String, super::Error> {
    use crate::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
    use sha2::{Digest, Sha256};

    // Serialize → Value → drop `persist_row_hash` field if present →
    // canonicalize → hash. Dropping `persist_row_hash` keeps the hash
    // stable across populate/depopulate cycles (read response carries
    // the field; write submission may or may not).
    let mut value = serde_json::to_value(row)
        .map_err(|e| super::Error::Backend(format!("serialize for hash: {e}")))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("persist_row_hash");
    }
    let bytes = PythonJsonDumpsCanonicalizer
        .canonicalize_value(&value)
        .map_err(|e| super::Error::Backend(format!("canonicalize for hash: {e}")))?;
    let digest = Sha256::digest(&bytes);
    Ok(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_key_record() -> KeyRecord {
        KeyRecord {
            key_id: "persist-steward".into(),
            pubkey_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            algorithm: algorithm::ED25519.into(),
            identity_type: identity_type::STEWARD.into(),
            identity_ref: "persist".into(),
            valid_from: DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
                .unwrap()
                .into(),
            valid_until: None,
            registration_envelope: serde_json::json!({"role": "persist-steward"}),
            original_content_hash: "deadbeef".into(),
            scrub_signature: "c2lnbmF0dXJl".into(),
            scrub_key_id: "persist-steward".into(),
            scrub_timestamp: DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
                .unwrap()
                .into(),
            persist_row_hash: String::new(),
        }
    }

    #[test]
    fn persist_row_hash_is_deterministic() {
        let row = fixture_key_record();
        let h1 = compute_persist_row_hash(&row).unwrap();
        let h2 = compute_persist_row_hash(&row).unwrap();
        assert_eq!(h1, h2, "hash must be deterministic across calls");
        assert_eq!(h1.len(), 64, "hex sha256 is 64 chars");
    }

    #[test]
    fn persist_row_hash_excludes_self() {
        // Two rows differing ONLY in their persist_row_hash field
        // should hash to the same value (the field excludes itself).
        let mut row1 = fixture_key_record();
        let mut row2 = fixture_key_record();
        row1.persist_row_hash = "before".into();
        row2.persist_row_hash = "after".into();
        assert_eq!(
            compute_persist_row_hash(&row1).unwrap(),
            compute_persist_row_hash(&row2).unwrap()
        );
    }

    #[test]
    fn persist_row_hash_changes_with_content() {
        let row1 = fixture_key_record();
        let mut row2 = fixture_key_record();
        row2.identity_ref = "different".into();
        assert_ne!(
            compute_persist_row_hash(&row1).unwrap(),
            compute_persist_row_hash(&row2).unwrap()
        );
    }

    #[test]
    fn key_record_serde_round_trip() {
        let row = fixture_key_record();
        let json = serde_json::to_string(&row).unwrap();
        let deser: KeyRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(row, deser);
    }
}
