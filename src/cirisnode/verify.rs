//! Envelope signature verification (v0.7.1).
//!
//! v0.7.0-α4 shipped a structural stub: `verify_envelope_signature`
//! checked that the signature fields were base64-decodable and that
//! `signed_at` was non-zero, but did not actually verify the
//! signature against any pubkey. v0.7.1 closes that gap.
//!
//! # Model
//!
//! v62.0.0 (F0-cp5): the signer is an edition-2 identity-ref and its key is
//! read from the directory (see "Signer" below). The v0.7.1 model, where a
//! `ContributorId` IS the Ed25519 pubkey and no directory is read, is gone.
//!
//! # Canonical-bytes shape
//!
//! Reuses [`crate::verify::canonical::canonicalize_envelope_for_signing`]
//! — the same canonicalizer the agent / lens / edge envelopes use.
//! Persist owns one canonicalization rule across all envelope tracks.
//! The rule: serialize to JSON Value, strip the `signature` and
//! `signature_pqc` top-level fields, then canonicalize through the
//! CEG produce gate (`ceg_produce_canonicalize` — RFC 8785 JCS at the
//! current produce epoch; #714 routed this track through the gate
//! with the rest of the mesh). Contributions verify at the door only
//! — stored rows are never re-verified from storage — so signer and
//! door move through the flip together within a build.
//!
//! Everything security-relevant lives outside the signature field:
//! `contribution_id`, `author_id`, `subject`, `payload`,
//! `witness_set`, `submitted_at` (for contributions); analogous
//! fields for the other envelope shapes. `signed_at` is the only
//! field inside `signature` and is intentionally not part of the
//! signed body — the envelope's own timestamp (`submitted_at`,
//! `cast_at`, `filed_at`, etc.) carries the asserted-at time.
//!
//! # Signer (v62.0.0, F0-cp5; RULINGS "composite signatures only")
//!
//! The signer is named by its edition-2 **identity-ref**, not a pubkey
//! literal: `attested_by` (a promotion record) and `peer_key_id` (a delivery
//! attestation) are `urn:ietf:params:oauth:ckt:sha-256:…`, and the signer's
//! LIVE key is read from the directory by the shared
//! [`verify_composite_via_directory`]. The envelope carries ONE composite
//! (ML-DSA-65-Ed25519) signature. The earlier model (SCHEMA §2.2: the
//! identity field IS the Ed25519 pubkey, verified classical-only under a
//! PINNED `Ed25519Fallback`, CIRISPersist#1233) is gone: a pubkey literal is
//! refused `verify_not_identity_ref`, a lone Ed25519 half
//! `verify_component_signature`.

use serde::Serialize;

use crate::federation::edition2::composite_verify::{
    now_ms, verify_composite_via_directory, CompositeVerifyError,
};
use crate::federation::FederationDirectory;
use crate::verify::canonical::canonicalize_envelope_for_signing;

use super::federation_announcement::DeliveryAttestation;
use super::types::CompositeSignature;
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

/// A [`CompositeVerifyError`] as this track's [`Error`]: a failed directory
/// read is `Backend`; every refusal is `Signature`, led by its token.
fn refusal(e: CompositeVerifyError) -> Error {
    match e {
        CompositeVerifyError::Directory(inner) => Error::Backend(format!("key read: {inner}")),
        other => Error::Signature(format!("{other}")),
    }
}

/// Verify a federation-consensus envelope's ONE composite signature under
/// the LIVE edition-2 key of `signer_identity_ref` (v62.0.0, F0-cp5).
///
/// Caller passes:
/// - `dir`: the directory the signer's key plane is read from;
/// - `envelope`: the typed envelope (Serialize impl), whose `signature`
///   field is stripped before canonicalising;
/// - `sig`: the envelope's [`CompositeSignature`];
/// - `signer_identity_ref`: the signer field (e.g. `attested_by`).
///
/// # Errors
/// [`Error::Signature`] led by the refusal's token
/// (`verify_not_identity_ref`, `verify_unknown_key`,
/// `verify_component_signature`, …); [`Error::Backend`] for a failed read.
pub async fn verify_envelope_signed<T, F>(
    dir: &F,
    envelope: &T,
    sig: &CompositeSignature,
    signer_identity_ref: &str,
) -> Result<(), Error>
where
    T: Serialize,
    F: FederationDirectory + ?Sized,
{
    let raw = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        sig.composite.trim(),
    )
    .map_err(|e| Error::Signature(format!("signature.composite is not base64: {e}")))?;
    let canonical = canonical_bytes_for_envelope(envelope)?;
    verify_composite_via_directory(dir, &canonical, signer_identity_ref, &raw, now_ms())
        .await
        .map_err(refusal)?;
    Ok(())
}

/// Verify a [`DeliveryAttestation`]'s ONE composite over
/// [`DeliveryAttestation::canonical_bytes`] under `peer_key_id`'s LIVE
/// edition-2 key. Both backends' `put_delivery_attestation` call this, so
/// the accepted set cannot depend on the backend. Returns the composite's
/// raw bytes (what the row stores).
///
/// # Errors
/// As [`verify_envelope_signed`]; [`Error::InvalidArgument`] for a
/// signature that is not base64.
pub async fn verify_delivery_attestation<F>(
    dir: &F,
    attestation: &DeliveryAttestation,
) -> Result<Vec<u8>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let sig = attestation.signature_composite_bytes()?;
    let canonical = attestation
        .canonical_bytes()
        .map_err(|e| Error::Signature(format!("canonical_bytes: {e}")))?;
    verify_composite_via_directory(dir, &canonical, &attestation.peer_key_id, &sig, now_ms())
        .await
        .map_err(refusal)?;
    Ok(sig)
}

// v62.0.0 (F0-cp5) — the earlier pubkey-literal tests (round trip,
// tampered payload, wrong pubkey, empty / malformed Ed25519 half) asserted
// the classical-only identity-as-pubkey model and are deleted; the
// directory-backed witnesses are I2883 (`cirisnode::composite_invariants`,
// sqlite + postgres).
