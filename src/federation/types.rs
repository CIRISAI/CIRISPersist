//! Federation directory wire-format types.
//!
//! These shapes are the source of truth for both persist's backends
//! and CIRISRegistry's vendored
//! `rust-registry/src/federation/types.rs`. Field names + types must
//! match field-for-field between the two repos.
//!
//! # PQC strategy (v0.2.0): hot-path Ed25519, cold-path ML-DSA-65
//!
//! **Hybrid Ed25519 + ML-DSA-65 is the only signing scheme across
//! the federation.** Every row in the historical audit chain
//! converges to fully hybrid-signed. But the WRITE PATH accepts
//! Ed25519-only rows initially with the ML-DSA-65 signature
//! attached on the cold path — see `docs/FEDERATION_DIRECTORY.md`
//! §"Trust contract — eventual consistency as a federation
//! primitive" for the architectural rationale.
//!
//! Writer contract:
//!   1. Sign canonical_bytes with Ed25519 (synchronous, hot path).
//!   2. Write the row (PQC fields may be `None` at this step).
//!   3. **IMMEDIATELY** kick off ML-DSA-65 signing on the cold
//!      path — not delayed, not batched, just off the synchronous
//!      request path.
//!   4. Call `attach_pqc_signature` once the ML-DSA-65 sign
//!      completes. `pqc_completed_at` is timestamped.
//!
//! When quantum threat materializes, persist's runtime policy
//! flips (`require_pqc_on_write=true`); the kickoff step folds
//! into the synchronous path and PQC fields become required at
//! write time.
//!
//! Every key in the federation has TWO public-key components:
//!   - `pubkey_ed25519_base64` — 32 raw bytes, base64 standard, REQUIRED
//!   - `pubkey_ml_dsa_65_base64` — 1952 raw bytes, base64 standard,
//!     populated by `attach_pqc_signature` (`Option<String>`)
//!
//! Every signature in the federation has TWO components, bound:
//!   - `scrub_signature_classical` — `Ed25519.sign(canonical_bytes)`,
//!     REQUIRED
//!   - `scrub_signature_pqc` — `ML-DSA-65.sign(canonical_bytes ||
//!     classical_sig)`, populated by `attach_pqc_signature`
//!     (`Option<String>`)
//!
//! The bound signature pattern (PQC covers `data || classical`)
//! prevents stripping attacks where an attacker who breaks Ed25519
//! could otherwise replace the PQC signature with their own. This
//! matches CIRISVerify's `ManifestSignature` and `HybridSignature`
//! contracts (`ciris-verify-core/src/security/function_integrity.rs:149`,
//! `ciris-crypto/src/types.rs:156`).
//!
//! # Identity, algorithm, and attestation type strings
//!
//! Persist stores `identity_type` and `attestation_type` as TEXT
//! columns (not enums) so new values can be added by either side
//! without a schema break. `algorithm` is also TEXT but only
//! `"hybrid"` is accepted — the schema enforces it
//! (`CHECK (algorithm = 'hybrid')`), and persist's runtime rejects
//! writes with any other value. The column exists for forward compat
//! against future PQC schemes (ML-DSA-87, ML-DSA + ML-KEM, etc.) that
//! may emerge as the federation evolves.
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
///
/// **v0.2.0+ federation_keys writes MUST use [`HYBRID`].** Schema
/// enforces this with `CHECK (algorithm = 'hybrid')`. Other values
/// remain in this module only as forward-compat placeholders for
/// hypothetical future migration paths (e.g., upgrading legacy
/// agent trace-signing keys at v0.4.0+ if the agent fleet remains
/// Ed25519-only at that time — but the federation directory itself
/// is hybrid all the way down).
pub mod algorithm {
    /// Hybrid Ed25519 + ML-DSA-65. **The only valid value for
    /// federation_keys writes from v0.2.0 onward.** Bound signature
    /// protocol per CIRISVerify `HybridSignature`:
    /// `classical_sig = Ed25519.sign(canonical)`,
    /// `pqc_sig = ML-DSA-65.sign(canonical || classical_sig)`.
    /// Verification requires both signatures.
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
    /// Ed25519 32-byte raw public key, base64 standard. 44 chars.
    /// Always required.
    pub pubkey_ed25519_base64: String,
    /// ML-DSA-65 1952-byte raw public key, base64 standard.
    /// ~2604 chars. `None` until the cold-path PQC sign completes
    /// via `attach_pqc_signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey_ml_dsa_65_base64: Option<String>,
    /// Algorithm string. **v0.2.0+ writes MUST be [`algorithm::HYBRID`].**
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
    /// SHA-256 of canonical(registration_envelope). Hex-encoded.
    pub original_content_hash: String,
    /// Classical Ed25519 signature: `Ed25519.sign(canonical_bytes)`.
    /// Base64-encoded (88 chars for 64-byte sig). Always required.
    pub scrub_signature_classical: String,
    /// PQC ML-DSA-65 signature: `ML-DSA-65.sign(canonical || classical_sig)`.
    /// Bound to the classical signature to prevent stripping attacks.
    /// Base64-encoded (~4412 chars for 3309-byte sig — FIPS 204 final,
    /// `c_tilde_bytes=48`; closes CIRISPersist#8). The pre-FIPS-204-final
    /// figure of 3293 bytes was the round-3 era size; live `ml-dsa = 0.1.0-rc.3`
    /// and CIRISVerify v1.8.5 both emit 3309. Empirically confirmed by
    /// CIRISBridge's lens-steward bootstrap producing 4412-char base64
    /// signatures via `dilithium-py.ML_DSA_65.sign`.
    /// `None` until the cold-path PQC sign completes via
    /// `attach_pqc_signature`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
    /// `key_id` of the row that signed THIS row. Bootstrap rows have
    /// `scrub_key_id == key_id` (self-signed); all others reference
    /// an existing `federation_keys` row.
    pub scrub_key_id: String,
    /// When the scrub-signature was issued.
    pub scrub_timestamp: DateTime<Utc>,
    /// When the cold-path PQC components were attached. `None` while
    /// the row is hybrid-pending (Ed25519-only); populated by
    /// `attach_pqc_signature` once ML-DSA-65 fills in. Telemetry +
    /// observability signal — auditable answer to "when did this row
    /// become hybrid-secure?"
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_completed_at: Option<DateTime<Utc>>,
    /// **Server-computed.** Hex-encoded SHA-256 over the canonical
    /// bytes of this row (via persist's
    /// `PythonJsonDumpsCanonicalizer`). Consumers store + string-
    /// compare; they don't reproduce the canonicalizer. Closes the
    /// shortest-round-trip drift class of cache-divergence bugs.
    pub persist_row_hash: String,
}

impl KeyRecord {
    /// True iff both PQC components have been attached. Consumers
    /// composing strict-hybrid trust policy refuse rows where this
    /// returns false.
    pub fn is_pqc_complete(&self) -> bool {
        self.pubkey_ml_dsa_65_base64.is_some()
            && self.scrub_signature_pqc.is_some()
            && self.pqc_completed_at.is_some()
    }

    /// True iff the row is in the cold-path PQC-signing window
    /// (Ed25519-only, ML-DSA-65 in flight). Consumers composing
    /// soft-hybrid + freshness policies use this with their own age
    /// threshold to decide whether the row is acceptably-pending vs
    /// concerning-stale.
    pub fn is_pqc_pending(&self) -> bool {
        !self.is_pqc_complete()
    }
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
    /// SHA-256 of canonical(attestation_envelope). Hex-encoded.
    pub original_content_hash: String,
    /// Classical Ed25519 sig over canonical bytes. Base64. Required.
    pub scrub_signature_classical: String,
    /// PQC ML-DSA-65 sig over (canonical || classical_sig). Base64.
    /// `None` while the row is hybrid-pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
    /// `key_id` that signed this row.
    pub scrub_key_id: String,
    /// When the scrub-signature was issued.
    pub scrub_timestamp: DateTime<Utc>,
    /// When the PQC components were attached. `None` while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_completed_at: Option<DateTime<Utc>>,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

impl Attestation {
    /// True iff PQC components have been attached.
    pub fn is_pqc_complete(&self) -> bool {
        self.scrub_signature_pqc.is_some() && self.pqc_completed_at.is_some()
    }
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
    /// SHA-256 of canonical(revocation_envelope). Hex-encoded.
    pub original_content_hash: String,
    /// Classical Ed25519 sig over canonical bytes. Base64. Required.
    pub scrub_signature_classical: String,
    /// PQC ML-DSA-65 sig over (canonical || classical_sig). Base64.
    /// `None` while the row is hybrid-pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scrub_signature_pqc: Option<String>,
    /// `key_id` that signed this row.
    pub scrub_key_id: String,
    /// When the scrub-signature was issued.
    pub scrub_timestamp: DateTime<Utc>,
    /// When the PQC components were attached. `None` while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_completed_at: Option<DateTime<Utc>>,
    /// **Server-computed.** See [`KeyRecord::persist_row_hash`].
    pub persist_row_hash: String,
}

impl Revocation {
    /// True iff PQC components have been attached.
    pub fn is_pqc_complete(&self) -> bool {
        self.scrub_signature_pqc.is_some() && self.pqc_completed_at.is_some()
    }
}

/// One hybrid-pending federation row — minimum fields the sweep
/// needs to recompute the cold-path bound-signature input. Returned
/// by [`super::FederationDirectory::list_hybrid_pending_keys`] /
/// `_attestations` / `_revocations` (CIRISPersist#11, v0.3.2).
///
/// `id` is the row's primary key (`key_id` for `federation_keys`,
/// `attestation_id` / `revocation_id` for the others). `envelope` is
/// the JSONB column the original Ed25519 signature was computed over
/// — canonical bytes are recomputed via
/// `PythonJsonDumpsCanonicalizer::canonicalize_value` to feed the
/// bound-signature input. `classical_sig_b64` is the base64-encoded
/// Ed25519 signature that PQC will sign over alongside the canonical
/// bytes per the bound-signature contract.
#[derive(Debug, Clone, PartialEq)]
pub struct HybridPendingRow {
    /// Primary key of the hybrid-pending row.
    pub id: String,
    /// JSONB envelope the row's classical signature was computed over.
    pub envelope: serde_json::Value,
    /// Base64-encoded Ed25519 signature stored on the row.
    pub classical_sig_b64: String,
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
            // Test fixture only — 32 zero bytes for Ed25519 placeholder.
            pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            // Hybrid-complete fixture — both pubkeys + both sigs +
            // pqc_completed_at populated.
            pubkey_ml_dsa_65_base64: Some("AA".repeat(100)),
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type::STEWARD.into(),
            identity_ref: "persist".into(),
            valid_from: DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
                .unwrap()
                .into(),
            valid_until: None,
            registration_envelope: serde_json::json!({"role": "persist-steward"}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJlX2NsYXNzaWNhbA==".into(),
            scrub_signature_pqc: Some("c2lnbmF0dXJlX3BxYw==".into()),
            scrub_key_id: "persist-steward".into(),
            scrub_timestamp: DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
                .unwrap()
                .into(),
            pqc_completed_at: Some(
                DateTime::parse_from_rfc3339("2026-05-01T00:00:01Z")
                    .unwrap()
                    .into(),
            ),
            persist_row_hash: String::new(),
        }
    }

    /// Hybrid-pending shape — Ed25519-only, PQC fields None. The
    /// soft-PQC write window per §"Trust contract" in
    /// FEDERATION_DIRECTORY.md.
    fn fixture_hybrid_pending() -> KeyRecord {
        KeyRecord {
            pubkey_ml_dsa_65_base64: None,
            scrub_signature_pqc: None,
            pqc_completed_at: None,
            ..fixture_key_record()
        }
    }

    #[test]
    fn pqc_complete_vs_pending() {
        assert!(fixture_key_record().is_pqc_complete());
        assert!(!fixture_key_record().is_pqc_pending());
        assert!(!fixture_hybrid_pending().is_pqc_complete());
        assert!(fixture_hybrid_pending().is_pqc_pending());
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
