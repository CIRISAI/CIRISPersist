//! Envelope signature verification (v0.7.1).
//!
//! v0.7.0-α4 shipped a structural stub: `verify_envelope_signature`
//! checked that the signature fields were base64-decodable and that
//! `signed_at` was non-zero, but did not actually verify the
//! signature against any pubkey. v0.7.1 closes that gap.
//!
//! # Model
//!
//! Per `CIRISNodeCore/SCHEMA.md` §2.2, every `ContributorId`
//! (`author_id`, `voter_id`, `accuser_id`, `adjudicator_id`,
//! `requester_id`) **IS** the Ed25519 pubkey — base64-encoded.
//! Federation-consensus envelopes are self-signed against the
//! identity-as-pubkey embedded in the envelope itself; persist does
//! not need a federation_keys directory lookup for cirisnode-track
//! verification (in contrast to the v0.4.1 outbound-envelope path
//! that uses `verify_hybrid_via_directory`).
//!
//! # Canonical-bytes shape
//!
//! Reuses [`crate::verify::canonical::canonicalize_envelope_for_signing`]
//! — the same canonicalizer the agent / lens / edge envelopes use.
//! Persist owns one canonicalization rule across all envelope tracks.
//! The rule: serialize to JSON Value, strip the `signature` and
//! `signature_pqc` top-level fields, then run the Python-compatible
//! canonicalizer.
//!
//! Everything security-relevant lives outside the signature field:
//! `contribution_id`, `author_id`, `subject`, `payload`,
//! `witness_set`, `submitted_at` (for contributions); analogous
//! fields for the other envelope shapes. `signed_at` is the only
//! field inside `signature` and is intentionally not part of the
//! signed body — the envelope's own timestamp (`submitted_at`,
//! `cast_at`, `filed_at`, etc.) carries the asserted-at time.
//!
//! # Policy
//!
//! [`HybridPolicy::Ed25519Fallback`] for v0.7.1: classical-only
//! envelopes verify against Ed25519. Hybrid envelopes (Ed25519 +
//! ML-DSA-65) also accepted via the upstream
//! [`verify_hybrid`](crate::verify::hybrid::verify_hybrid) impl.
//! Tightening to [`HybridPolicy::Strict`] is a CIRISNodeCore-track
//! decision deferred to a later release once the contributor-key
//! ML-DSA-65 rollout completes federation-side.

use serde::Serialize;

use crate::verify::canonical::canonicalize_envelope_for_signing;
use crate::verify::hybrid::{verify_hybrid, HybridPolicy};

use super::types::HybridSignature;
use super::Error;

/// Produce canonical bytes for a federation-consensus envelope.
///
/// Serialize the envelope to JSON `Value`, strip the `signature`
/// field, and run the persist-owned canonicalizer. Returns the byte
/// stream that the signer signed over and that the verifier verifies
/// against.
pub fn canonical_bytes_for_envelope<T: Serialize>(envelope: &T) -> Result<Vec<u8>, Error> {
    let value = serde_json::to_value(envelope)
        .map_err(|e| Error::Internal(format!("envelope serialize: {e}")))?;
    canonicalize_envelope_for_signing(&value)
        .map_err(|e| Error::Internal(format!("canonicalize: {e}")))
}

/// Verify a federation-consensus envelope's signature against the
/// contributor's Ed25519 pubkey embedded in the envelope.
///
/// Caller passes:
/// - `envelope`: the typed envelope (Serialize impl)
/// - `sig`: the envelope's `signature` (HybridSignature)
/// - `contributor_pubkey_b64`: the contributor identity field that
///   per SCHEMA.md §2.2 IS the Ed25519 pubkey (standard base64,
///   exactly as `verify_hybrid` expects)
///
/// Returns `Error::Signature` with the underlying `VerifyError` kind
/// string on any failure. Stable tokens cross the FFI boundary; the
/// verbose detail goes to tracing only.
pub fn verify_envelope_signed<T: Serialize>(
    envelope: &T,
    sig: &HybridSignature,
    contributor_pubkey_b64: &str,
) -> Result<(), Error> {
    if sig.ed25519.is_empty() {
        return Err(Error::Signature("ed25519 signature missing".into()));
    }
    let canonical = canonical_bytes_for_envelope(envelope)?;
    verify_hybrid(
        &canonical,
        &sig.ed25519,
        sig.ml_dsa_65.as_deref(),
        contributor_pubkey_b64,
        // v0.7.1: no per-contributor ML-DSA-65 pubkey directory yet.
        // Hybrid envelopes are accepted only when the caller passes
        // BOTH signature AND pubkey — i.e., self-contained hybrid
        // verification. For the cirisnode track, contributor identity
        // is single-key (Ed25519); hybrid lands in a later release
        // alongside per-contributor PQC key registration.
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
    use crate::cirisnode::types::{Cell, ContributionEnvelope, ContributionType};
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use chrono::Utc;
    use ed25519_dalek::{Signer as _, SigningKey};
    use uuid::Uuid;

    /// Build an envelope + sign it with the supplied key. Returns the
    /// envelope with the live signature applied.
    fn sign_contribution(key: &SigningKey, author_id: &str) -> ContributionEnvelope {
        let mut env = ContributionEnvelope {
            contribution_id: Uuid::new_v4().to_string(),
            contribution_type: ContributionType::Proposal,
            author_id: author_id.to_owned(),
            subject: Cell {
                domain: "test-domain".into(),
                language: "en".into(),
                subject: Some("arc_question".into()),
            },
            payload: serde_json::json!({"q": "test"}),
            witness_set: None,
            signature: HybridSignature {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at: Utc::now(),
            },
            submitted_at: Utc::now(),
        };
        let canonical = canonical_bytes_for_envelope(&env).unwrap();
        let sig = key.sign(&canonical);
        env.signature.ed25519 = B64.encode(sig.to_bytes());
        env
    }

    #[test]
    fn verify_round_trip_accepts_legitimate_sig() {
        let key = SigningKey::from_bytes(&[0xAB; 32]);
        let pubkey = B64.encode(key.verifying_key().to_bytes());
        let env = sign_contribution(&key, &pubkey);
        verify_envelope_signed(&env, &env.signature, &pubkey)
            .expect("legitimate sig should verify");
    }

    #[test]
    fn verify_rejects_tampered_payload() {
        let key = SigningKey::from_bytes(&[0xCD; 32]);
        let pubkey = B64.encode(key.verifying_key().to_bytes());
        let mut env = sign_contribution(&key, &pubkey);
        // Tamper after sign — flip a payload field.
        env.payload = serde_json::json!({"q": "TAMPERED"});
        let err = verify_envelope_signed(&env, &env.signature, &pubkey).unwrap_err();
        assert!(
            matches!(err, Error::Signature(_)),
            "expected Signature, got {err:?}"
        );
    }

    #[test]
    fn verify_rejects_wrong_pubkey() {
        let signer = SigningKey::from_bytes(&[0xEE; 32]);
        let imposter = SigningKey::from_bytes(&[0xFF; 32]);
        let signer_pub = B64.encode(signer.verifying_key().to_bytes());
        let imposter_pub = B64.encode(imposter.verifying_key().to_bytes());
        let env = sign_contribution(&signer, &signer_pub);
        // Verify against a different pubkey.
        let err = verify_envelope_signed(&env, &env.signature, &imposter_pub).unwrap_err();
        assert!(matches!(err, Error::Signature(_)));
    }

    #[test]
    fn verify_rejects_empty_signature() {
        let key = SigningKey::from_bytes(&[0x11; 32]);
        let pubkey = B64.encode(key.verifying_key().to_bytes());
        let mut env = sign_contribution(&key, &pubkey);
        env.signature.ed25519 = String::new();
        let err = verify_envelope_signed(&env, &env.signature, &pubkey).unwrap_err();
        match err {
            Error::Signature(msg) => assert!(msg.contains("missing"), "got: {msg}"),
            other => panic!("expected Signature, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_malformed_base64() {
        let key = SigningKey::from_bytes(&[0x22; 32]);
        let pubkey = B64.encode(key.verifying_key().to_bytes());
        let mut env = sign_contribution(&key, &pubkey);
        env.signature.ed25519 = "not-valid-base64!@#$".to_owned();
        let err = verify_envelope_signed(&env, &env.signature, &pubkey).unwrap_err();
        assert!(matches!(err, Error::Signature(_)));
    }
}
