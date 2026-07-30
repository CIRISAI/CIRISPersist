//! Federation-tier ingest admission gate — PQC-mandatory hybrid-signature
//! verification at the bulk per-trace store/replicate path
//! (v9.0.0, CIRISPersist#237, CC 5.3.2.4.3.1).
//!
//! # Why this module exists
//!
//! CC 5.3.2.4.3 pins the substrate invariant
//! `tier = federation ⟹ hybrid signature present`, and CC 5.3.2.4.3.1
//! makes "present" mean **verified at the admission gate** — and binds
//! it to the **durable store + replication path, not only the
//! operational-authority gates**: *"every federation-tier attestation,
//! including the bulk per-trace / store-and-replicate path … MUST carry
//! (and a verifier MUST check on ingest) the ML-DSA-65 half exactly as a
//! key_grant does; there is no 'operational authority vs testimony leaf'
//! exemption."* Store-then-quarantine is explicitly non-conformant:
//! a substrate persisting/replicating a federation-tier row whose
//! envelope signature lacks a valid ML-DSA-65 half MUST reject it **at
//! the ingest gate**.
//!
//! Before v9.0.0, [`FederationDirectory::put_attestation`](crate::federation::FederationDirectory::put_attestation)
//! ran only [`AdmissionGate::check_federation`](crate::federation::AdmissionGate::check_federation)
//! — a trust-**threshold** check on the *key* — then INSERTed. The row's
//! envelope hybrid signature (`scrub_signature_classical` /
//! `scrub_signature_pqc`) was merely **stored**, never verified at the
//! federation-tier write/replicate path. The `tier = federation` label
//! was trusted. Hybrid-verify-at-gate existed only on
//! [`register_federation_key`](crate::Engine::register_federation_key)
//! ([`super::register`], v8.8.0) and the fountain store-path (v8.4.0) —
//! NOT on the federation-tier testimony corpus, the single most
//! forge-exposed surface in the federation (the "store at massive scale"
//! CEWP crux: content-addressing is no defense against a CRQC-era
//! adversary who breaks Ed25519, mints a backdated trace under a
//! historical key, and hashes *their own* forgery).
//!
//! [`verify_federation_tier_ingest`] closes that gap. It is the
//! federation-tier sibling of [`super::register::verify_key_registration`]
//! and shares its exact verify semantics.
//!
//! # The signing contract (byte-for-byte with `register.rs`)
//!
//! The canonical bytes the producer signed are
//! [`ceg_produce_canonicalize`](crate::verify::canonical::ceg_produce_canonicalize)`(attestation_envelope)`
//! — the same JCS/Python-compat produce gate the rest of the fabric
//! signs through (post-#871 the whole fabric is on JCS). The gate
//! cross-checks `SHA-256(canonical) == original_content_hash` first: a
//! producer that signed a *different* canonical form fails the hash
//! check with a clear error, and is **not stored** (fail-secure) —
//! exactly as [`super::register::verify_key_registration`] does.
//!
//! Verification runs in [`HybridPolicy::Strict`](crate::verify::HybridPolicy::Strict):
//! **both** Ed25519 over `JCS(envelope)` AND ML-DSA-65 over the bound
//! `JCS(envelope) ‖ ed25519_sig` ([CC 3.1.2.1] bound-payload form,
//! applied inside the hybrid verifier) are REQUIRED. There is no
//! `require_hybrid: false` posture (CC 5.3.2.4.3.1) — a classical-only /
//! hybrid-pending federation-tier row is rejected.
//!
//! The signature is verified against the attester's **REGISTERED**
//! pubkeys, resolved via
//! [`lookup_public_key`](crate::federation::FederationDirectory::lookup_public_key)
//! on `attesting_key_id` — **never** against pubkeys carried on the row
//! alone. An unknown/unregistered attester ⇒ rejected (fail-secure):
//! there are no pubkeys to verify against, so the row cannot be admitted.
//!
//! # The breaking boundary — local-tier is EXEMPT
//!
//! The mandate is at the **federation admission boundary only**. A
//! `tier = local` row (producer-only authority, signature deferred per
//! CC 5.3.2.2, visible only to the producing occurrence) is a no-op for
//! this gate — non-PQC producers are confined to local-tier until they
//! complete PQC wiring. This is the v9.0.0 BREAKING change: a
//! classical-only federation-tier write that was admitted pre-v9.0.0 is
//! now non-conformant and rejected here.
//!
//! # Fail-secure
//!
//! ANY missing/invalid signature, unknown attester, or canonicalizer
//! mismatch ⇒ a typed [`Error::FederationTierUnverified`] (stable
//! `kind()` token `"federation_federation_tier_unverified"`) and the row
//! is **NOT stored**. Verify-before-mutation (AV-9). The gate composes
//! with — does not replace — the existing
//! [`AdmissionGate::check_federation`](crate::federation::AdmissionGate)
//! trust-threshold check and the node-agency gate.
//!
//! [CC 3.1.2.1]: the bound-payload form `JCS(envelope) ‖ ed25519_sig`.

use sha2::{Digest, Sha256};

use super::types::attestation_tier;
use super::{Attestation, Error, FederationDirectory};
use crate::verify::canonical::ceg_produce_canonicalize;
use crate::verify::{verify_hybrid, HybridPolicy};

/// Verify a federation-tier [`Attestation`]'s envelope hybrid signature
/// against the §CC 5.3.2.4.3.1 ingest gate, BEFORE any store. Generic
/// over [`FederationDirectory`] so it composes against any backend
/// (postgres, sqlite, memory) — the directory is consulted to resolve
/// the attester's REGISTERED pubkeys.
///
/// **Local-tier rows are EXEMPT** (`Ok(())` no-op): the federation
/// admission boundary is the only place authority crosses, and a
/// local-tier row MAY defer its signature (CC 5.3.2.2).
///
/// For a federation-tier row this runs the **same** verify contract as
/// [`super::register::verify_key_registration`]:
/// 1. canonicalize `attestation_envelope` through
///    [`ceg_produce_canonicalize`] and cross-check
///    `SHA-256(canonical) == original_content_hash` (canonicalizer
///    agreement, fail-secure);
/// 2. resolve the attester's registered Ed25519 + ML-DSA-65 pubkeys via
///    [`FederationDirectory::lookup_public_key`] on `attesting_key_id`
///    (unknown attester ⇒ reject);
/// 3. [`verify_hybrid`] under [`HybridPolicy::Strict`] — both halves
///    REQUIRED.
///
/// On success returns `Ok(())`; the caller then stores the row. On ANY
/// failure returns [`Error::FederationTierUnverified`] and the caller
/// MUST NOT store the row.
pub async fn verify_federation_tier_ingest<F>(directory: &F, row: &Attestation) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    // Local-tier rows are EXEMPT (CC 5.3.2.2 deferred signature) — the
    // mandate is at the federation admission boundary only.
    if row.tier != attestation_tier::FEDERATION {
        return Ok(());
    }
    verify_row_hybrid_signature(directory, row).await
}

/// v12.6.0 (CIRISPersist#171, §10.1.3 transit-not-rest) — verify an
/// [`Attestation`] row's envelope bound-hybrid signature **regardless of
/// tier**. This is the tier-agnostic core [`verify_federation_tier_ingest`]
/// runs for federation rows; the §10.1.3 subject-side revocation transit
/// gate ([`super::admission::check_local_tier_eligibility`] /
/// [`super::admission::check_consent_record_admission`]) runs it on a
/// **local-tier** row so a subject revocation may *transit* the local write
/// path only if its bound-hybrid signature verifies (the operator decision:
/// accept on VALID crypto, never on an unsigned/forged revocation).
///
/// Same verify contract as the federation ingest gate: canonicalize the
/// envelope, cross-check `SHA-256(canonical) == original_content_hash`,
/// resolve the attester's REGISTERED pubkeys, [`verify_hybrid`] under
/// [`HybridPolicy::Strict`] (both Ed25519 + ML-DSA-65 REQUIRED; PQC
/// mandatory). ANY failure ⇒ [`Error::FederationTierUnverified`],
/// fail-secure, row NOT stored.
pub async fn verify_row_hybrid_signature<F>(directory: &F, row: &Attestation) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let reject = |reason: String| Error::FederationTierUnverified {
        attestation_id: row.attestation_id.clone(),
        attesting_key_id: row.attesting_key_id.clone(),
        reason,
    };

    let computed_hash = verify_envelope_hybrid_signature(
        directory,
        &row.attesting_key_id,
        &row.attestation_envelope,
        &row.scrub_signature_classical,
        row.scrub_signature_pqc.as_deref(),
    )
    .await
    .map_err(|e| match e {
        // Re-stamp the row's attestation_id onto the typed error (the
        // envelope-level helper has no row id).
        Error::FederationTierUnverified { reason, .. } => reject(reason),
        other => other,
    })?;

    // Cross-check the declared original_content_hash matches the envelope's
    // canonical SHA-256 (canonicalizer agreement, fail-secure).
    if computed_hash != row.original_content_hash {
        return Err(reject(format!(
            "original_content_hash mismatch: envelope canonicalizes to {computed_hash}, \
             row declares {}",
            row.original_content_hash
        )));
    }
    Ok(())
}

/// v21.0.0 (CIRISPersist#502 E1) — mechanistic admission for a replicated
/// `Revocation`: hybrid-Strict verify the scrub signature against the
/// **revoking** key's REGISTERED pubkeys. Before this, `put_revocation`
/// admitted on FK-existence + a trust-score threshold only — the scrub sig
/// was stored, never verified — so any linked peer could forge
/// `{revoked_key_id: victim, revoking_key_id: any-existing}` for a targeted
/// de-peer / trust DoS. Now the revocation must be signed by the key it
/// claims to act as, resolved from OUR directory.
pub async fn verify_revocation_admission<F>(
    directory: &F,
    row: &crate::federation::types::Revocation,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    verify_envelope_hybrid_signature(
        directory,
        &row.revoking_key_id,
        &row.revocation_envelope,
        &row.scrub_signature_classical,
        row.scrub_signature_pqc.as_deref(),
    )
    .await
    .map(|_| ())
}

/// v12.6.0 (CIRISPersist#171) — the envelope-level bound-hybrid verify
/// primitive shared by [`verify_row_hybrid_signature`] (row form) and the
/// §10.1.3 transit revocation local-write path (which has no assembled row
/// yet — it verifies before building one). Canonicalizes `envelope` through
/// the CEG produce gate, resolves `attesting_key_id`'s REGISTERED pubkeys via
/// the directory (unknown attester ⇒ reject, fail-secure), and runs
/// [`verify_hybrid`] under [`HybridPolicy::Strict`] (both halves REQUIRED,
/// PQC-mandatory per CC 5.3.2.4.3.1). On success returns the hex-encoded
/// `SHA-256(canonical)` (the row's `original_content_hash`); on ANY failure
/// returns [`Error::FederationTierUnverified`] with an empty `attestation_id`
/// (the caller re-stamps its own where one exists).
pub async fn verify_envelope_hybrid_signature<F>(
    directory: &F,
    attesting_key_id: &str,
    envelope: &serde_json::Value,
    scrub_signature_classical: &str,
    scrub_signature_pqc: Option<&str>,
) -> Result<String, Error>
where
    F: FederationDirectory + ?Sized,
{
    let reject = |reason: String| Error::FederationTierUnverified {
        attestation_id: String::new(),
        attesting_key_id: attesting_key_id.to_string(),
        reason,
    };

    // (1) Canonicalize through the CEG produce gate — the same canonical
    // form the producer signed — and compute its SHA-256.
    let canonical = ceg_produce_canonicalize(envelope)
        .map_err(|e| reject(format!("attestation_envelope canonicalize: {e}")))?;
    let computed_hash = hex::encode(Sha256::digest(&canonical));

    // (2) Resolve the attester's REGISTERED pubkeys — never pubkeys carried
    // on the row alone. Unknown/unregistered attester ⇒ reject (fail-secure).
    let attester = directory
        .lookup_public_key(attesting_key_id)
        .await
        .map_err(|e| reject(format!("attester lookup_public_key: {e} ({})", e.kind())))?
        .ok_or_else(|| {
            reject(format!(
                "attesting_key_id {attesting_key_id} is not registered — no pubkeys to \
                 verify the bound-hybrid signature against"
            ))
        })?;

    // (3) Strict hybrid verify: Ed25519 (over canonical) AND ML-DSA-65 (over
    // the bound canonical || classical_sig) both REQUIRED. A classical-only /
    // hybrid-pending signature is rejected — the CC 5.3.2.4.3.1 guard.
    verify_hybrid(
        &canonical,
        scrub_signature_classical,
        scrub_signature_pqc,
        &attester.pubkey_ed25519_base64,
        attester.pubkey_ml_dsa_65_base64.as_deref(),
        HybridPolicy::Strict,
        None,
    )
    .map_err(|e| reject(format!("hybrid-verify: {e} ({})", e.kind())))?;

    Ok(computed_hash)
}

/// v21.0.0 (CIRISPersist#502 E4) — mechanistic admission for a replicated
/// [`SignedFamily`](super::SignedFamily): hybrid-Strict verify the scrub
/// signature against the **claimed authority**'s REGISTERED pubkeys, over
/// [`super::types::Family::signing_envelope`]. Before this, `put_family`
/// admitted on FK-existence alone — a `Family` is a **keyless declaration**
/// (no signature at all was carried), so any linked peer could forge one
/// wholesale. Run BEFORE any DB work (mirrors the #502 E1
/// `verify_revocation_admission` shape this helper replicates for the family
/// plane).
pub async fn verify_family_admission<F>(
    directory: &F,
    signed: &super::SignedFamily,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    verify_envelope_hybrid_signature(
        directory,
        &signed.authority_key_id,
        &signed.family.signing_envelope(),
        &signed.scrub_signature_classical,
        signed.scrub_signature_pqc.as_deref(),
    )
    .await
    .map(|_| ())
}

/// v21.0.0 (CIRISPersist#502 E4) — mechanistic admission for a replicated
/// [`SignedCommunity`](super::SignedCommunity). Structural mirror of
/// [`verify_family_admission`]; verifies over
/// [`super::types::Community::signing_envelope`].
pub async fn verify_community_admission<F>(
    directory: &F,
    signed: &super::SignedCommunity,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    verify_envelope_hybrid_signature(
        directory,
        &signed.authority_key_id,
        &signed.community.signing_envelope(),
        &signed.scrub_signature_classical,
        signed.scrub_signature_pqc.as_deref(),
    )
    .await
    .map(|_| ())
}

/// v21.0.0 (CIRISPersist#502 E4) — mechanistic admission for a replicated
/// [`SignedFamilyMembershipRevocation`](super::SignedFamilyMembershipRevocation).
/// Structural mirror of [`verify_family_admission`]; verifies over
/// [`super::types::FamilyMembershipRevocation::signing_envelope`].
pub async fn verify_family_membership_revocation_admission<F>(
    directory: &F,
    signed: &super::SignedFamilyMembershipRevocation,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    verify_envelope_hybrid_signature(
        directory,
        &signed.authority_key_id,
        &signed.family_membership_revocation.signing_envelope(),
        &signed.scrub_signature_classical,
        signed.scrub_signature_pqc.as_deref(),
    )
    .await
    .map(|_| ())
}

/// v21.0.0 (CIRISPersist#502 E4) — mechanistic admission for a replicated
/// [`SignedCommunityMembershipRevocation`](super::SignedCommunityMembershipRevocation).
/// THE worst-case E4 closure: before this, a forged community-membership
/// removal admitted on FK-existence alone and rotated the CC 4.4.3.2.2
/// community DEK epoch — an unauthenticated forward-secrecy DoS. Structural
/// mirror of [`verify_family_admission`]; verifies over
/// [`super::types::CommunityMembershipRevocation::signing_envelope`].
pub async fn verify_community_membership_revocation_admission<F>(
    directory: &F,
    signed: &super::SignedCommunityMembershipRevocation,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    verify_envelope_hybrid_signature(
        directory,
        &signed.authority_key_id,
        &signed.community_membership_revocation.signing_envelope(),
        &signed.scrub_signature_classical,
        signed.scrub_signature_pqc.as_deref(),
    )
    .await
    .map(|_| ())
}

/// v21.0.0 (CIRISPersist#502 E4) — mechanistic admission for a replicated
/// [`SignedLocationProof`](super::SignedLocationProof). Structural mirror of
/// [`verify_family_admission`]; verifies over
/// [`super::types::LocationProof::signing_envelope`].
pub async fn verify_location_proof_admission<F>(
    directory: &F,
    signed: &super::SignedLocationProof,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    verify_envelope_hybrid_signature(
        directory,
        &signed.authority_key_id,
        &signed.location_proof.signing_envelope(),
        &signed.scrub_signature_classical,
        signed.scrub_signature_pqc.as_deref(),
    )
    .await
    .map(|_| ())
}

/// v9.0.0 (CIRISPersist#237) — shared test-support for the
/// federation-tier ingest gate. Mirrors
/// [`super::operational::test_support`]: a deterministic-per-`key_id`
/// hybrid keypair (so a registered key and a signed attestation derived
/// from the same `key_id` match without threading an identity object
/// through every call site), plus helpers to fill a [`KeyRecord`]'s
/// pubkeys and to sign an attestation envelope. Used by the
/// `put_attestation` test fixtures on all three backends to carry REAL
/// hybrid signatures now that the federation-tier ingest gate is
/// mandatory (CC 5.3.2.4.3.1).
// v21.15.0 (CIRISPersist#536) — also compiled under `feature = "test-anchor"`
// so `operational::test_support::establish_trust_root` (a downstream fixture)
// can reuse the deterministic `sign_envelope` / `hybrid_pubkeys` derivation.
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub(crate) mod test_support {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};

    /// Deterministic 32-byte seed for `key_id` — the first ≤32 bytes of
    /// the key_id over a `0x11` fill. Same shape as
    /// `register.rs::tests::signed_self_record`, so the two test corpora
    /// stay coherent.
    fn seed_for(key_id: &str) -> [u8; 32] {
        let mut seed = [0x11u8; 32];
        for (i, b) in key_id.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        seed
    }

    /// The Ed25519 signer for `key_id` (deterministic).
    fn ed_signer(key_id: &str) -> Ed25519Signer {
        Ed25519Signer::from_seed(&seed_for(key_id)).expect("ed seed")
    }

    /// The ML-DSA-65 signer for `key_id` (deterministic), **boxed** —
    /// `MlDsa65Signer` holds the multi-KiB secret key inline, so keeping
    /// it on the heap keeps test stack frames small (several of these in a
    /// single async test frame otherwise overflow the worker stack).
    fn mldsa_signer(key_id: &str) -> Box<MlDsa65Signer> {
        Box::new(MlDsa65Signer::from_seed(&seed_for(key_id)).expect("mldsa seed"))
    }

    /// `key_id`'s registered hybrid pubkeys, base64. Use these to fill a
    /// `KeyRecord`'s `pubkey_ed25519_base64` / `pubkey_ml_dsa_65_base64`
    /// so the registered key matches what [`sign_envelope`] signs with.
    pub fn hybrid_pubkeys(key_id: &str) -> (String, Option<String>) {
        let ed_pk = B64.encode(ed_signer(key_id).public_key().expect("ed pk"));
        let mldsa_pk = B64.encode(mldsa_signer(key_id).public_key().expect("mldsa pk"));
        (ed_pk, Some(mldsa_pk))
    }

    /// #249 Cut G3 — produce a [`ThresholdSignature`](ciris_verify_core::threshold::ThresholdSignature)
    /// for `key_id` over `bytes` using `key_id`'s deterministic hybrid keypair
    /// (the same pair [`hybrid_pubkeys`] registers). The ML-DSA-65 half signs
    /// the bound message `bytes ‖ ed25519_sig` (the stripping-attack guard the
    /// threshold verifier checks). Use to drive the quorum gate in tests.
    pub fn threshold_sign(
        key_id: &str,
        bytes: &[u8],
    ) -> ciris_verify_core::threshold::ThresholdSignature {
        let ed_sig = ed_signer(key_id).sign(bytes).expect("ed sign");
        let mut bound = bytes.to_vec();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa_signer(key_id).sign(&bound).expect("mldsa sign");
        ciris_verify_core::threshold::ThresholdSignature {
            member_id: key_id.to_string(),
            ed25519_signature_base64: B64.encode(&ed_sig),
            mldsa65_signature_base64: Some(B64.encode(&pqc_sig)),
        }
    }

    /// #249 Cut G3 — register `key_id` with its REAL deterministic hybrid
    /// pubkeys (matching [`hybrid_pubkeys`] / [`threshold_sign`]) via
    /// `put_public_key`, so a cosignature this key produces verifies against
    /// the stored roster. The registration row's own scrub fields are
    /// placeholders (`put_public_key` does not hybrid-verify the
    /// registration; only the PUBKEYS must be real).
    pub async fn register_hybrid_key<D: crate::federation::FederationDirectory + ?Sized>(
        dir: &D,
        key_id: &str,
    ) {
        register_hybrid_key_aliased(dir, key_id, key_id).await
    }

    /// #249 Cut G3.5 — register `key_id` carrying the hybrid pubkeys OF
    /// `pubkey_source_key_id` (so two distinct `key_id`s can share one pubkey).
    /// Used to drive verify's one-seat / one-human-one-seat rejection (two
    /// key_ids backed by the same pubkey in a roster).
    pub async fn register_hybrid_key_aliased<D: crate::federation::FederationDirectory + ?Sized>(
        dir: &D,
        key_id: &str,
        pubkey_source_key_id: &str,
    ) {
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(pubkey_source_key_id);
        let now = chrono::Utc::now();
        let rec = crate::federation::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: crate::federation::types::identity_type::AGENT.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        dir.put_public_key(crate::federation::SignedKeyRecord { record: rec })
            .await
            .expect("register hybrid key");
    }

    /// Build a PQC-configured [`crate::signing::LocalSigner`] whose
    /// Ed25519 + ML-DSA-65 keypair is the SAME deterministic pair as
    /// [`hybrid_pubkeys`] / [`sign_envelope`] for `key_id`. Use this to
    /// drive product code that hybrid-signs federation-tier withdraws
    /// (evict_actor / takedown handler) in tests, with `key_id`'s key
    /// registered via [`hybrid_pubkeys`] so the ingest gate verifies the
    /// emitted withdraws. `key_id` is the LocalSigner's `key_id` (the
    /// `attesting_key_id` on the emitted rows).
    ///
    /// `ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes` and
    /// `ciris_crypto::MlDsa65Signer::from_seed` derive the SAME ML-DSA-65
    /// keypair from the same seed (both feed the seed to the ml-dsa
    /// keygen), so the LocalSigner's PQC pubkey matches the registered
    /// `pubkey_ml_dsa_65_base64`; a debug_assert pins that invariant.
    pub fn local_signer(key_id: &str) -> std::sync::Arc<crate::signing::LocalSigner> {
        let seed = seed_for(key_id);
        let ed = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pqc = std::sync::Arc::new(
            ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&seed, key_id)
                .expect("mldsa seed length"),
        );
        // The keyring software signer's ML-DSA-65 keypair must match the
        // ciris_crypto signer's pubkey for the same seed (so the key
        // registered via `hybrid_pubkeys` verifies the emitted sig); if it
        // ever diverged, the ingest gate would reject the emitted withdraws
        // and the eviction/takedown tests would fail loudly.
        std::sync::Arc::new(crate::signing::LocalSigner::from_parts(
            ed,
            key_id.to_owned(),
            Some(pqc),
            Some(key_id.to_owned()),
        ))
    }

    /// Hybrid-sign `envelope` (through the CEG produce canonicalizer)
    /// with `signing_key_id`'s deterministic keys. Returns
    /// `(original_content_hash, scrub_signature_classical,
    /// scrub_signature_pqc)` — exactly the three fields the
    /// federation-tier ingest gate verifies. The PQC half signs the
    /// bound payload `canonical || ed25519_sig` (CC 3.1.2.1).
    pub fn sign_envelope(
        signing_key_id: &str,
        envelope: &serde_json::Value,
    ) -> (String, String, Option<String>) {
        let ed = ed_signer(signing_key_id);
        let mldsa = mldsa_signer(signing_key_id);
        let canonical = ceg_produce_canonicalize(envelope).expect("canonicalize");
        let original_content_hash = hex::encode(Sha256::digest(&canonical));
        let ed_sig = ed.sign(&canonical).expect("ed sign");
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).expect("mldsa sign");
        (
            original_content_hash,
            B64.encode(&ed_sig),
            Some(B64.encode(&pqc_sig)),
        )
    }

    /// v21.0.0 (CIRISPersist#502 E4) — sign a [`Family`](crate::federation::types::Family)
    /// for submission: hybrid-signs `family.signing_envelope()` with
    /// `authority_key_id`'s deterministic keypair and wraps the result as a
    /// [`SignedFamily`](crate::federation::SignedFamily). `authority_key_id`
    /// MUST already be registered (e.g. via [`register_hybrid_key`]) for the
    /// wrapped record to verify at `put_family`.
    pub fn sign_family(
        authority_key_id: &str,
        family: crate::federation::types::Family,
    ) -> crate::federation::SignedFamily {
        let (_hash, classical, pqc) = sign_envelope(authority_key_id, &family.signing_envelope());
        crate::federation::SignedFamily {
            family,
            authority_key_id: authority_key_id.to_owned(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// v21.0.0 (CIRISPersist#502 E4) — sign a
    /// [`Community`](crate::federation::types::Community) for submission.
    /// Mirrors [`sign_family`].
    pub fn sign_community(
        authority_key_id: &str,
        community: crate::federation::types::Community,
    ) -> crate::federation::SignedCommunity {
        let (_hash, classical, pqc) =
            sign_envelope(authority_key_id, &community.signing_envelope());
        crate::federation::SignedCommunity {
            community,
            authority_key_id: authority_key_id.to_owned(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// v21.0.0 (CIRISPersist#502 E4) — sign a
    /// [`FamilyMembershipRevocation`](crate::federation::types::FamilyMembershipRevocation)
    /// for submission. Mirrors [`sign_family`].
    pub fn sign_family_membership_revocation(
        authority_key_id: &str,
        revocation: crate::federation::types::FamilyMembershipRevocation,
    ) -> crate::federation::SignedFamilyMembershipRevocation {
        let (_hash, classical, pqc) =
            sign_envelope(authority_key_id, &revocation.signing_envelope());
        crate::federation::SignedFamilyMembershipRevocation {
            family_membership_revocation: revocation,
            authority_key_id: authority_key_id.to_owned(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// v21.0.0 (CIRISPersist#502 E4) — sign a
    /// [`CommunityMembershipRevocation`](crate::federation::types::CommunityMembershipRevocation)
    /// for submission. Mirrors [`sign_family`].
    pub fn sign_community_membership_revocation(
        authority_key_id: &str,
        revocation: crate::federation::types::CommunityMembershipRevocation,
    ) -> crate::federation::SignedCommunityMembershipRevocation {
        let (_hash, classical, pqc) =
            sign_envelope(authority_key_id, &revocation.signing_envelope());
        crate::federation::SignedCommunityMembershipRevocation {
            community_membership_revocation: revocation,
            authority_key_id: authority_key_id.to_owned(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// v21.0.0 (CIRISPersist#502 E4) — sign a
    /// [`LocationProof`](crate::federation::types::LocationProof) for
    /// submission. Mirrors [`sign_family`].
    pub fn sign_location_proof(
        authority_key_id: &str,
        proof: crate::federation::types::LocationProof,
    ) -> crate::federation::SignedLocationProof {
        let (_hash, classical, pqc) = sign_envelope(authority_key_id, &proof.signing_envelope());
        crate::federation::SignedLocationProof {
            location_proof: proof,
            authority_key_id: authority_key_id.to_owned(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
        }
    }

    /// v21.0.0 (CIRISPersist#502 E4) — build a signed
    /// [`RevokeSpec`](crate::federation::cohort::RevokeSpec) for
    /// `revoke_member` / `swap_member` whose authority signature matches
    /// EXACTLY what `FederationDirectory::revoke_member` constructs
    /// internally for the `Family`/`Community` cohorts — **`removed_at` is
    /// `effective_at`**, never a server-minted `now` (see the #502 E4 comment
    /// on `revoke_member`; the caller cannot predict a server timestamp, so
    /// the callee never mints one for a field it verifies). `SelfId` takes
    /// the trusted-local path (no gate) — its `RevokeSpec` carries empty
    /// authority fields, which is correct (nothing to verify there).
    pub fn sign_revoke_spec(
        cohort: crate::federation::cohort::Cohort,
        authority_key_id: &str,
        group_key_id: &str,
        removed_key_id: &str,
        effective_at: chrono::DateTime<chrono::Utc>,
        reason: Option<String>,
        witness_set: Vec<String>,
    ) -> crate::federation::cohort::RevokeSpec {
        use crate::federation::cohort::Cohort;
        let (scrub_signature_classical, scrub_signature_pqc) = match cohort {
            Cohort::Family => {
                let rec = crate::federation::types::FamilyMembershipRevocation {
                    family_key_id: group_key_id.to_owned(),
                    removed_identity_key_id: removed_key_id.to_owned(),
                    removed_at: effective_at,
                    effective_at,
                    reason: reason.clone(),
                    witness_set: witness_set.clone(),
                    persist_row_hash: String::new(),
                };
                let (_hash, c, p) = sign_envelope(authority_key_id, &rec.signing_envelope());
                (c, p)
            }
            Cohort::Community | Cohort::Affiliations => {
                let rec = crate::federation::types::CommunityMembershipRevocation {
                    community_key_id: group_key_id.to_owned(),
                    removed_identity_key_id: removed_key_id.to_owned(),
                    removed_at: effective_at,
                    effective_at,
                    reason: reason.clone(),
                    witness_set: witness_set.clone(),
                    persist_row_hash: String::new(),
                };
                let (_hash, c, p) = sign_envelope(authority_key_id, &rec.signing_envelope());
                (c, p)
            }
            Cohort::SelfId => (String::new(), None),
        };
        crate::federation::cohort::RevokeSpec {
            effective_at,
            reason,
            witness_set,
            authority_key_id: authority_key_id.to_owned(),
            scrub_signature_classical,
            scrub_signature_pqc,
        }
    }

    /// #371 — register `key_id` with its REAL deterministic hybrid pubkeys
    /// and an explicit `identity_type` (the [`register_hybrid_key`] shape,
    /// but e.g. `user`-role for `owner_of` granters or `node`-role for
    /// owned-node rows). Self-signed, deterministic timestamps so a rebuilt
    /// record is byte-identical.
    pub async fn register_identity_key<D: crate::federation::FederationDirectory + ?Sized>(
        dir: &D,
        key_id: &str,
        identity_type: &str,
    ) {
        let record = replicated_key_record(
            key_id,
            identity_type,
            key_id, // self-signed
            key_id,
            "register",
        );
        dir.put_public_key(crate::federation::SignedKeyRecord { record })
            .await
            .expect("register identity key");
    }

    /// #371 — build a fully-formed [`KeyRecord`](crate::federation::KeyRecord)
    /// for `key_id` carrying `key_id`'s REAL deterministic hybrid pubkeys,
    /// whose registration envelope is hybrid-signed by `signer_key_id`'s
    /// deterministic keys (through [`sign_envelope`], the exact shape
    /// `verify_key_registration` Strict-verifies). Deterministic timestamps,
    /// so building the same record twice is byte-identical (drives the
    /// idempotent-`Unchanged` arm of the #371 decision table).
    ///
    /// - `scrub_key_id == key_id` + `signer_key_id == key_id` ⇒ a verifiable
    ///   **self-signed** record (the in-place boot state).
    /// - `scrub_key_id != key_id` + `signer_key_id == scrub_key_id` ⇒ a
    ///   verifiable **granting-authority (anchor-scrubbed)** record —
    ///   register the scrubber first ([`register_hybrid_key`] /
    ///   [`register_identity_key`]) so the Strict gate resolves its pubkeys.
    /// - `signer_key_id != scrub_key_id` ⇒ a record whose scrub does NOT
    ///   verify (the bad-signer decision-table row).
    ///
    /// `nonce` is folded into the signed envelope, so two records for the
    /// same `key_id` with different nonces are distinct-but-valid versions
    /// (drives the conflicting-second-version / duplicity rows).
    pub fn replicated_key_record(
        key_id: &str,
        identity_type: &str,
        scrub_key_id: &str,
        signer_key_id: &str,
        nonce: &str,
    ) -> crate::federation::KeyRecord {
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        let envelope = serde_json::json!({
            "key_id": key_id,
            "purpose": "federation-peering",
            "nonce": nonce,
        });
        let (och, classical, pqc) = sign_envelope(signer_key_id, &envelope);
        let ts: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();
        crate::federation::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: ts,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: scrub_key_id.to_owned(),
            scrub_timestamp: ts,
            pqc_completed_at: Some(ts),
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// #371 — build a LIVE **owner-binding** `delegates_to(owner → node)`
    /// (the CC 1.13.3.3 / CC 3.2 ownership dimension the v12.6.0
    /// single-owner gate + `owner_of` key on), federation-tier
    /// hybrid-signed by `owner`'s deterministic keys so
    /// `verify_federation_tier_ingest` admits it. Register `owner` as a
    /// `user`-role key ([`register_identity_key`]) first.
    pub fn owner_binding_attestation(
        id: &str,
        owner: &str,
        node: &str,
    ) -> crate::federation::Attestation {
        use crate::federation::types::{
            attestation_tier, attestation_type, delegation_scope as ds, owner_binding,
        };
        let envelope = serde_json::json!({
            "id": id,
            "kind": "delegates_to",
            "dimension": owner_binding::DIMENSION,
            "delegation_purpose": owner_binding::PURPOSE,
            "scope": [ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
        });
        let (och, classical, pqc) = sign_envelope(owner, &envelope);
        let ts: chrono::DateTime<chrono::Utc> = "2026-05-01T00:00:00Z".parse().unwrap();
        crate::federation::Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: owner.to_owned(),
            attested_key_id: node.to_owned(),
            attestation_type: attestation_type::DELEGATES_TO.to_owned(),
            weight: Some(1.0),
            asserted_at: ts,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: owner.to_owned(),
            scrub_timestamp: ts,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
        }
    }
}

#[cfg(all(test, any(feature = "postgres", feature = "sqlite")))]
mod tests {
    //! v9.0.0 (CIRISPersist#237) — the CC 5.3.2.4.3.1 federation-tier
    //! ingest-gate matrix, run identically against sqlite and (when
    //! `CIRIS_PERSIST_TEST_PG_URL` is set) postgres via [`run_tier_ingest_matrix`].
    //! Test (b) — federation-tier with the ML-DSA-65 half MISSING ⇒
    //! REJECTED + NOT stored — is the load-bearing CC 5.3.2.4.3.1 guard;
    //! test (e) — LOCAL-tier without PQC ⇒ ADMITTED — proves the
    //! breaking-boundary exemption (local-tier producers are not
    //! over-rejected).

    use super::test_support::{hybrid_pubkeys, sign_envelope};
    use crate::engine::Engine;
    use crate::federation::types::{
        algorithm, attestation_tier, attestation_type, cohort_scope, identity_type,
    };
    use crate::federation::{
        Attestation, FederationDirectory, KeyRecord, SignedAttestation, SignedKeyRecord,
    };
    use crate::signing::LocalSigner;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;

    fn test_signer() -> Arc<LocalSigner> {
        let signing_key = SigningKey::from_bytes(&[0x5Au8; 32]);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "tier-ingest-test-steward".to_string(),
            None,
            None,
        ))
    }

    /// Register `key_id` with REAL deterministic hybrid pubkeys (the
    /// conformant state) via the directory's `put_public_key`. The
    /// registration row's own scrub-signature fields are placeholders —
    /// `put_public_key` does not hybrid-verify the registration (that gate
    /// is `register_federation_key`); only the PUBKEYS must be real for
    /// the federation-tier ingest gate to verify attestations.
    pub async fn register_hybrid_key(dir: &dyn FederationDirectory, key_id: &str) {
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        let now = chrono::Utc::now();
        let rec = KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: algorithm::HYBRID.to_owned(),
            identity_type: identity_type::AGENT.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        dir.put_public_key(SignedKeyRecord { record: rec })
            .await
            .expect("register hybrid key");
    }

    /// Build a `scores` Attestation by `attester` over a fresh envelope.
    /// `sign` controls whether the envelope is hybrid-signed (true) or
    /// carries placeholder/partial signatures. `tier` lets (e) write a
    /// local-tier row.
    fn att(attester: &str, attested: &str, id: &str, tier: &str) -> Attestation {
        let envelope = serde_json::json!({
            "id": id,
            "dimension": "identity_binding:v1",
            "score": 1.0,
            "confidence": 0.9,
        });
        let (och, classical, pqc) = sign_envelope(attester, &envelope);
        Attestation {
            // attestation_id is `::uuid`-cast on the PG write path — use a
            // real UUID (project_test_fixtures_uuid_vs_uuid_like); `id` is
            // carried in the signed envelope for per-case uniqueness.
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: attested.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: Some(1.0),
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: attester.to_owned(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: Some(chrono::Utc::now()),
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: if tier == attestation_tier::LOCAL {
                cohort_scope::SELF.to_owned()
            } else {
                attestation_tier::FEDERATION.to_owned()
            },
            tier: tier.to_owned(),
            promoted_at: None,
        }
    }

    /// The full CC 5.3.2.4.3.1 ingest-gate matrix, backend-agnostic — runs
    /// directly against a [`FederationDirectory`] so it covers the memory
    /// backend too (it runs there in production), not only the engine-wrapped
    /// sqlite + postgres backends.
    async fn run_tier_ingest_matrix(dir: &dyn FederationDirectory, tag: &str) {
        let attester = format!("ti-attester-{tag}");
        let attested = format!("ti-attested-{tag}");
        register_hybrid_key(dir, &attester).await;
        register_hybrid_key(dir, &attested).await;

        // (a) federation-tier with a VALID hybrid sig → ADMITTED + readable.
        let a = att(
            &attester,
            &attested,
            &format!("ti-a-{tag}"),
            attestation_tier::FEDERATION,
        );
        let a_id = a.attestation_id.clone();
        dir.put_attestation(SignedAttestation { attestation: a })
            .await
            .expect("(a) valid hybrid federation-tier row must be admitted");
        let by = dir.list_attestations_by(&attester).await.expect("list");
        assert!(
            by.iter().any(|r| r.attestation_id == a_id),
            "(a) admitted row must be readable"
        );

        // (b) federation-tier with the ML-DSA-65 half MISSING (classical-
        // only) → REJECTED + NOT stored. THE load-bearing CC 5.3.2.4.3.1 guard.
        let mut b = att(
            &attester,
            &attested,
            &format!("ti-b-{tag}"),
            attestation_tier::FEDERATION,
        );
        let b_id = b.attestation_id.clone();
        b.scrub_signature_pqc = None; // drop the PQC half
        b.pqc_completed_at = None;
        let err = dir
            .put_attestation(SignedAttestation { attestation: b })
            .await
            .expect_err("(b) classical-only federation-tier row must be REJECTED");
        assert_eq!(
            err.kind(),
            "federation_federation_tier_unverified",
            "(b) rejection must be the tier-ingest gate"
        );
        assert!(
            dir.get_attestation(&b_id).await.expect("get").is_none(),
            "(b) rejected row must NOT be stored (fail-secure)"
        );

        // (c) federation-tier with a TAMPERED ML-DSA-65 half → REJECTED.
        let mut c = att(
            &attester,
            &attested,
            &format!("ti-c-{tag}"),
            attestation_tier::FEDERATION,
        );
        let c_id = c.attestation_id.clone();
        // Re-sign a DIFFERENT envelope to get a valid-length-but-wrong PQC
        // sig, then keep the original envelope/hash → the PQC half no
        // longer verifies over the real bound input.
        let (_, _, wrong_pqc) = sign_envelope(
            &attester,
            &serde_json::json!({ "id": "not-the-real-envelope" }),
        );
        c.scrub_signature_pqc = wrong_pqc;
        let err = dir
            .put_attestation(SignedAttestation { attestation: c })
            .await
            .expect_err("(c) tampered ML-DSA-65 must be REJECTED");
        assert_eq!(err.kind(), "federation_federation_tier_unverified");
        assert!(dir.get_attestation(&c_id).await.expect("get").is_none());

        // (d) federation-tier from an UNREGISTERED attester → REJECTED
        // (no pubkeys to verify against). On the postgres/sqlite backends
        // the FK check also rejects an unknown attester, but the tier-
        // ingest gate (which runs there too, with the resolved-but-here
        // unregistered key) fails first with its own typed error on the
        // memory backend ordering; either way the row is not stored. We
        // assert non-storage + a rejection.
        let unreg = format!("ti-unreg-{tag}");
        let d = att(
            &unreg,
            &attested,
            &format!("ti-d-{tag}"),
            attestation_tier::FEDERATION,
        );
        let d_id = d.attestation_id.clone();
        let err = dir
            .put_attestation(SignedAttestation { attestation: d })
            .await
            .expect_err("(d) unregistered attester must be REJECTED");
        // The ingest gate's own rejection token (when it fires) or the
        // FK InvalidArgument (when the backend's FK check fires first) —
        // both are fail-secure non-stores.
        assert!(
            err.kind() == "federation_federation_tier_unverified"
                || err.kind() == "federation_invalid_argument",
            "(d) unexpected rejection kind: {}",
            err.kind()
        );
        assert!(dir.get_attestation(&d_id).await.expect("get").is_none());

        // (e) LOCAL-tier row WITHOUT a PQC half → ADMITTED (the exemption;
        // proves we don't over-reject local-tier). cohort_scope=self is
        // required at local tier by the existing v4.0 read-gate.
        let mut e = att(
            &attester,
            &attester,
            &format!("ti-e-{tag}"),
            attestation_tier::LOCAL,
        );
        let e_id = e.attestation_id.clone();
        e.scrub_signature_pqc = None; // local-tier may defer the signature
        e.pqc_completed_at = None;
        dir.put_attestation(SignedAttestation { attestation: e })
            .await
            .expect("(e) local-tier row without PQC must be ADMITTED (CC 5.3.2.2 exemption)");
        assert!(
            dir.get_attestation(&e_id).await.expect("get").is_some(),
            "(e) admitted local-tier row must be stored"
        );
    }

    /// QualReview (LOW): the gate runs on the MEMORY backend in production
    /// (`put_attestation` calls `verify_federation_tier_ingest`), so test the
    /// matrix directly against it too — no engine DSN dispatches to memory.
    #[tokio::test]
    async fn tier_ingest_matrix_memory() {
        let backend = crate::store::memory::MemoryBackend::new();
        run_tier_ingest_matrix(&backend, "memory").await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn tier_ingest_matrix_sqlite() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        let dir = engine.federation_directory();
        run_tier_ingest_matrix(&*dir, "sqlite").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn tier_ingest_matrix_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping tier_ingest_matrix_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let engine = Engine::with_signer(test_signer(), &dsn)
            .await
            .expect("construct postgres engine");
        let tag = format!("pg-{}", uuid::Uuid::new_v4().simple());
        let dir = engine.federation_directory();
        run_tier_ingest_matrix(&*dir, &tag).await;
    }
}
