//! v25.1.0 (CIRISPersist#582) — the backend-generic half of the signed
//! ATTESTATION-emit recipe, lifted out of [`crate::Engine`] so it has exactly
//! ONE implementation.
//!
//! (Not to be confused with [`super::emit`], which is the trust-grant /
//! audit-entry emit API.)
//!
//! `canonicalize → hash → hybrid-sign → assemble the 20-field
//! [`Attestation`] → put_attestation` was previously reachable only through an
//! [`Engine`](crate::Engine), which exists solely over the `sqlite` /
//! `postgres` dispatch. Anything wanting to emit against a bare
//! [`FederationDirectory`] — the in-memory backend, a directory-generic sweep
//! like [`crate::maintenance::vocabulary`] — had to hand-roll the recipe, and
//! a hand-rolled copy is how a fixture ends up certifying a path no host runs
//! (the AV-77 class, and the reason `emit_attestation` /
//! `emit_attestation_self` were single-sourced through one `assemble` in the
//! first place).
//!
//! So the recipe lives here and [`Engine`](crate::Engine) calls it. The
//! Engine-only step — the #509 promote-on-consent chokepoint, which needs the
//! engine's own derived identity — stays on the Engine, layered on top of the
//! [`EmittedAttestation`] this module returns.

use super::{Attestation, EmitAttestationInput, Error, FederationDirectory, SignedAttestation};

/// What [`assemble_and_put`] produced, plus the two facts the Engine's
/// post-emit consent chokepoint needs (so it never re-reads the row it just
/// wrote).
#[derive(Debug, Clone)]
pub struct EmittedAttestation {
    /// The new row's `attestation_id`.
    pub attestation_id: String,
    /// The row's `attesting_key_id` — the signer's DERIVED federation key_id.
    pub attesting_key_id: String,
    /// Was the emitted envelope's dimension the `consent:replication:v1`
    /// grant dimension? Drives the #509 promote-on-consent sweep.
    pub is_grant_dimension: bool,
}

/// Canonicalize an attestation envelope through the CEG produce gate (§0.9
/// JCS post-cut). The same bytes are both SHA-256'd into
/// `original_content_hash` and hybrid-signed, so the hash and the signature
/// can never cover different content.
pub fn canonicalize(envelope: &serde_json::Value) -> Result<Vec<u8>, Error> {
    crate::verify::canonical::ceg_produce_canonicalize(envelope)
        .map_err(|e| Error::Backend(format!("emit_attestation canonicalize: {e}")))
}

/// Assemble the 20-field [`Attestation`] from an already-derived `key_id`
/// (the attester/scrub — the #247 derived federation key_id, NEVER a caller
/// alias), the `canonical` bytes, the computed hybrid `sig`, and `input`;
/// then [`put_attestation`](FederationDirectory::put_attestation).
///
/// Both admission gates the emit chokepoint owns run here, so every emit path
/// enforces them identically:
///
/// - [`validate_subject_key_ids`](super::validate_subject_key_ids)
///   (CIRISPersist#293 / CC 2.6.3) — a non-canonical (uppercase / empty)
///   subject id is refused before the row is assembled.
/// - [`check_cohort_scope`](super::admission::check_cohort_scope)
///   (CIRISPersist#527) — the recipient axis is VALIDATED, never defaulted.
///   An empty scope must not be laundered into a federation-wide broadcast.
pub async fn assemble_and_put<D>(
    dir: &D,
    key_id: String,
    canonical: &[u8],
    sig: ciris_crypto::HybridSignature,
    input: EmitAttestationInput,
) -> Result<EmittedAttestation, Error>
where
    D: FederationDirectory + Sync + ?Sized,
{
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use sha2::{Digest, Sha256};

    super::validate_subject_key_ids(&input.subject_key_ids)?;

    let original_content_hash = hex::encode(Sha256::digest(canonical));
    let now = chrono::Utc::now();

    let attested_key_id = input.attested_key_id.unwrap_or_else(|| key_id.clone());
    super::admission::check_cohort_scope(&input.cohort_scope)?;
    let cohort_scope = input.cohort_scope;

    let row = Attestation {
        attestation_id: uuid::Uuid::new_v4().to_string(),
        attesting_key_id: key_id.clone(),
        attested_key_id,
        attestation_type: input.attestation_type,
        weight: input.weight,
        asserted_at: now,
        expires_at: input.expires_at,
        attestation_envelope: input.attestation_envelope.to_value(),
        original_content_hash,
        scrub_signature_classical: B64.encode(&sig.classical.signature),
        scrub_signature_pqc: Some(B64.encode(&sig.pqc.signature)),
        scrub_key_id: key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        subject_key_ids: input.subject_key_ids,
        withdraws_admission_rule: None,
        cohort_scope,
        tier: super::types::attestation_tier::FEDERATION.to_string(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    let emitted = EmittedAttestation {
        attestation_id: row.attestation_id.clone(),
        attesting_key_id: key_id,
        is_grant_dimension: super::admission::envelope_dimension(&row.attestation_envelope)
            == Some(super::consent_grammar::GRANT_DIMENSION),
    };

    dir.put_attestation(SignedAttestation { attestation: row })
        .await?;
    Ok(emitted)
}

/// The whole recipe over an explicit
/// [`LocalSigner`](crate::signing::LocalSigner) and a bare directory:
/// canonicalize → hybrid-sign → [`assemble_and_put`].
///
/// `attesting_key_id` / `scrub_key_id` are derived from the signer itself
/// ([`LocalSigner::derived_key_id`](crate::signing::LocalSigner::derived_key_id)),
/// never from a caller alias — the #247 floor.
///
/// [`crate::Engine::emit_attestation`] is exactly this plus the Engine-only
/// promote-on-consent chokepoint.
pub async fn emit_with_local_signer<D>(
    dir: &D,
    signer: &crate::signing::LocalSigner,
    input: EmitAttestationInput,
) -> Result<EmittedAttestation, Error>
where
    D: FederationDirectory + Sync + ?Sized,
{
    let key_id = signer.derived_key_id();
    let canonical = canonicalize(&input.attestation_envelope.to_value())?;
    let sig = signer.sign_hybrid(&canonical).await.map_err(|e| {
        Error::Backend(format!(
            "emit_attestation sign_hybrid: {e} — a conformant federation-tier emit requires a \
             hybrid (Ed25519 + ML-DSA-65) signer (CC 5.3.2.4.3.1)"
        ))
    })?;
    assemble_and_put(dir, key_id, &canonical, sig, input).await
}
