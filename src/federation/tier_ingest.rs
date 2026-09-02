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

    // v24.0.0 (CIRISPersist#556) — EVERY scrub, not just the first.
    //
    // **The preserve set must equal the verified set** (#541). `additional_scrubs`
    // is the evidence a family trust root's charter is quorum-signed; if the
    // verifier looked only at scrub #1, the co-signatures would be
    // stored-but-unverified — a writer could append garbage or drop the real
    // ones and the row would still verify, silently downgrading a 2-of-3
    // charter to one seat. That is the exact class this substrate keeps
    // re-learning, so the extra scrubs are verified HERE, at the same
    // admission boundary, over the SAME canonical bytes.
    //
    // Fail-secure, and no new denial-of-service surface: an unverifiable
    // co-signature refuses the row exactly as an unverifiable BASE signature
    // already does, and anyone able to mangle the co-signatures in flight could
    // equally mangle the base one. An unresolvable co-signer is likewise a
    // refusal, for the same reason `attesting_key_id` must resolve — a verifier
    // that cannot check a signature must not pretend the signature is absent.
    //
    // Consequence, stated rather than discovered later: a co-signed row
    // replicates only to peers that know its co-signers. For accord holders —
    // the co-signers this field exists for — that is every node, because the
    // holder records are baked into the genesis seed.
    for (i, scrub) in row.additional_scrubs.iter().enumerate() {
        let scrub_hash = verify_envelope_hybrid_signature(
            directory,
            &scrub.scrub_key_id,
            &row.attestation_envelope,
            &scrub.scrub_signature_classical,
            scrub.scrub_signature_pqc.as_deref(),
        )
        .await
        .map_err(|e| match e {
            Error::FederationTierUnverified { reason, .. } => reject(format!(
                "additional_scrubs[{i}] by {}: {reason}",
                scrub.scrub_key_id
            )),
            other => other,
        })?;
        // Every scrub is over the SAME preimage — the rule `ScrubSig` is
        // documented with. Re-asserted rather than assumed: the helper
        // canonicalizes the envelope we handed it, so a mismatch here would
        // mean the canonicalizer disagreed with itself.
        debug_assert_eq!(scrub_hash, computed_hash);
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
///
/// # v31.0.0 (CIRISPersist#659) — the SUBJECT binds FIRST
///
/// Verifying the signature proves the revoker signed *some* envelope; it
/// proved nothing about the row that envelope arrived on. Every field the
/// substrate acts upon — `revoked_key_id` above all — was a plain column, so
/// one validly-signed revocation could be re-pasted at any subject and any
/// `revocation_id`, unboundedly often, with the producer's own signature
/// still verifying. [`check_revocation_envelope_binding`] therefore runs as
/// the FIRST statement here, ahead of the directory lookup this function
/// needs, so the refusal is a pure function of the row and cannot depend on
/// which keys this node happens to hold. Every backend's `put_revocation`
/// runs it at the very top of the door as well; it is here too so no future
/// door can acquire this plane without the binding.
///
/// [`check_revocation_envelope_binding`]: crate::federation::admission::check_revocation_envelope_binding
pub async fn verify_revocation_admission<F>(
    directory: &F,
    row: &crate::federation::types::Revocation,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    crate::federation::admission::check_revocation_envelope_binding(row)?;
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
///
/// # v31.0.0 (CIRISPersist#648) — the constitutional family id is RESERVED here
///
/// Until this cut the `humanity-accord` id was protected by an accident of
/// ordering rather than by a rule: the genesis seed was unconditional, so the
/// primary key was always already taken before any peer could reach this door,
/// and `put_family` refuses a collision that carries different content.
///
/// #648 makes boot-without-a-seed a supported state, which removes the
/// accident. What it would have opened is the sharpest hole in the issue: a
/// registered peer declares a `humanity-accord` family with itself as the sole
/// seat and `founder_only` as the protocol,
/// [`family_charter_threshold`](super::trust_root) resolves that to 1, and a
/// single signature charters the constitutional root of the mesh. The
/// signature check above would have passed — the peer really did sign it.
///
/// So the id is now reserved at the door. It enters this node's directory
/// through the genesis seeder and the assemble ceremony
/// ([`put_family_local`](FederationDirectory::put_family_local), which carries
/// no authority signature because a keyless family has none to carry) and
/// through nothing else. That single-door property is also what keeps a SECOND
/// ceremony from replacing a first: the seeder's own already-entrenched check
/// is a no-op, never an overwrite.
pub async fn verify_family_admission<F>(
    directory: &F,
    signed: &super::SignedFamily,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if signed.family.family_key_id
        == ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID
    {
        return Err(Error::ConstitutionalFamilyReserved {
            family_key_id: signed.family.family_key_id.clone(),
            attesting_key_id: signed.authority_key_id.clone(),
        });
    }
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

/// v38.5.0 (CIRISPersist#771) — **the attestation twin of
/// [`community_reput_verdict`]**: is a re-offered `attestation_id` the row we
/// already hold, or a different row wearing the same id?
///
/// Measured on the production canonical: 7,536 refusals in six hours, 428
/// distinct content hashes re-sent up to 82 times each, every one of them a
/// row the node ALREADY HELD. The plain INSERT raised a UNIQUE violation and
/// the error mapping defaulted it to `Error::Backend` — so "I already have
/// this", which is idempotent success, arrived at the sender wearing the same
/// token as "the database is broken" (`federation_backend`). The sender
/// cannot learn the row landed, so it retries forever, and the noise drowns
/// the genuine refusals that the consumer's `Duplicate` branch exists to keep
/// visible.
///
/// The line this draws is the same one the Key plane draws between
/// `AlreadyAnchoredIdentical` and `ConflictingVersion`, and the same one #758
/// drew for the roster: **identical bytes are a no-op, differing bytes under
/// an occupied id are a Conflict.** An id collision carrying different
/// content is not a duplicate — it is two rows claiming one identity, and
/// silently accepting either would be the opposite defect.
pub(crate) fn attestation_reput_verdict(
    stored_persist_row_hash: &str,
    offered_persist_row_hash: &str,
    attestation_id: &str,
) -> Result<(), crate::federation::Error> {
    if stored_persist_row_hash == offered_persist_row_hash {
        return Ok(());
    }
    Err(crate::federation::Error::Conflict(format!(
        "attestation {attestation_id} already exists with DIFFERENT content \
         (stored persist_row_hash {stored_persist_row_hash}, offered \
         {offered_persist_row_hash}) — a re-delivery of identical bytes is an \
         idempotent no-op, but a differing row under an occupied id is refused \
         (CIRISPersist#771)"
    )))
}

/// v38.2.0 (CIRISPersist#758) — **the re-put verdict for a convergent
/// community row**, spelled ONCE so the three backends cannot answer it
/// three ways (they did: sqlite and postgres refused every re-put with a PK
/// error, while memory silently OVERWROTE the stored row and its authority
/// signature — a peer's copy replacing the one this node authored).
///
/// # Why identical content is a no-op rather than an error
///
/// A community id may be DERIVED rather than minted: CIRISServer's pair
/// chat mints one deterministic community per member pair (`chat:pair:v1:` +
/// a hash of the sorted member ids), so both ends author byte-identical
/// roster content and each signs as ITSELF. Refusing that is refusing
/// convergence — the far side can never accept the peer's copy, and every
/// pair community carries a standing replication error.
///
/// # Why differing content is still a refusal
///
/// The permissive twin (`INSERT … DO NOTHING` and move on) is the opposite
/// defect: it silently accepts a DIFFERENT roster under an occupied id,
/// which is the one thing the community plane's identity has to mean. The
/// stored `persist_row_hash` decides — the same absorb-then-re-read shape
/// CIRISPersist#719 settled for `put_accord_participation`.
///
/// The authority signature is deliberately NOT part of the comparison: it
/// is a WITNESS to the row, not part of the row's identity. On an accepted
/// no-op the first-accepted signature is kept and the second is dropped
/// (see #758 for the dyad co-signature form that would retain both).
pub(crate) fn community_reput_verdict(
    stored_persist_row_hash: &str,
    offered_persist_row_hash: &str,
    community_key_id: &str,
) -> Result<(), crate::federation::Error> {
    if stored_persist_row_hash == offered_persist_row_hash {
        return Ok(());
    }
    Err(crate::federation::Error::Conflict(format!(
        "community {community_key_id} already exists with DIFFERENT content \
         (stored persist_row_hash {stored_persist_row_hash}, offered \
         {offered_persist_row_hash}) — a convergent re-put of identical content is \
         an idempotent no-op, but a differing roster under an occupied id is refused \
         (CIRISPersist#758)"
    )))
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

/// The [`Error::LocationAuthorityUnauthorized`] `rule` token for *"this node
/// holds no `delegates_to(subject → authority)` at all"* (v37.0.0,
/// CIRISPersist#734).
///
/// **This is the RETRYABLE one, and the distinction is the whole point of the
/// field.** Federation delivers rows out of order, so a legitimate delegate's
/// proof can arrive before the `delegates_to` that authorizes it, and persist
/// holds no deferral queue for location proofs — the refusal returns to the
/// caller and the row is gone unless the caller re-submits. A caller seeing
/// this token should retry once the authorizing edge has replicated; a caller
/// seeing either sibling token below should not, because those mean the edge
/// IS here and it is dead.
pub const LOCATION_AUTHORITY_RULE_NO_DELEGATION_EDGE: &str =
    "location_authority_no_delegation_edge";

/// The [`Error::LocationAuthorityUnauthorized`] `rule` token for *"the
/// `delegates_to` is here and has been retracted"* — a substantive verdict, not
/// a delivery-order artifact (v37.0.0, CIRISPersist#734).
pub const LOCATION_AUTHORITY_RULE_DELEGATION_RETRACTED: &str =
    "location_authority_delegation_retracted";

/// The [`Error::LocationAuthorityUnauthorized`] `rule` token for *"the
/// `delegates_to` is here and has lapsed"* — `expires_at` passed, or the CC
/// 3.4.12 adult-incapacity `valid_until` lapsed. A substantive verdict
/// (v37.0.0, CIRISPersist#734).
pub const LOCATION_AUTHORITY_RULE_DELEGATION_EXPIRED: &str =
    "location_authority_delegation_expired";

/// v21.0.0 (CIRISPersist#502 E4) — mechanistic admission for a replicated
/// [`SignedLocationProof`](super::SignedLocationProof). Structural mirror of
/// [`verify_family_admission`]; verifies over
/// [`super::types::LocationProof::signing_envelope`].
///
/// # v37.0.0 (CIRISPersist#734) — WHOSE signature, not just whether there is one
///
/// E4 gave this door one leg: the scrub signature must verify against
/// `authority_key_id`'s REGISTERED pubkeys. It never asked whether that
/// authority had any standing to speak about `subject_key_id`, and
/// [`SignedLocationProof::authority_key_id`](super::SignedLocationProof)
/// documented the gap as deliberate scope. The consequence was that **any**
/// registered key in the federation could assert a location for **any**
/// subject and produce a perfectly valid, admitted, wrong row.
///
/// The operator's ruling — *"the key is the subject itself or its delegates, no
/// one else could know where the subject is"* — closes it, and the
/// justification is epistemic rather than administrative, which is what makes
/// the rule tight instead of arbitrary. Location is SELF-KNOWLEDGE. A third
/// party asserting where a subject is has no source for the claim, so a
/// signature from one proves only that they signed it. The admissible
/// authority set is exactly
///
/// ```text
/// {location_proof.subject_key_id} ∪ {live delegates of subject_key_id}
/// ```
///
/// Note this is the ONE `authority_key_id` plane where that reasoning holds.
/// The family / community / membership-revocation siblings admit others BY
/// DESIGN — an authority legitimately speaks about parties who are not itself
/// — so the same tightening is NOT applied to them, and must not be by
/// analogy.
///
/// # Leg order is load-bearing
///
/// The signature runs FIRST, unchanged. A forged or unregistered authority
/// still fails as [`Error::SignatureInvalid`] exactly as it did before, which
/// keeps every pre-existing refusal stable and means the new refusal is only
/// ever reached by a genuinely registered key holding a genuinely valid
/// signature — precisely the hole, and precisely what E4 already covered on
/// the other side.
///
/// # This is the chokepoint
///
/// All three backends call this function as the sole gate on
/// [`FederationDirectory::put_location_proof`](super::FederationDirectory::put_location_proof),
/// and `store::parity` pins that the three call sequences agree. The
/// `ffi::directory_capsule` and `federation::directory_double` implementations
/// forward to an inner backend rather than writing, so they inherit the gate;
/// there is no `put_location_proof_local` bypass. Gating here therefore gates
/// every writer, which a gate on a per-backend helper would not.
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
    .await?;
    check_location_authority(
        directory,
        &signed.location_proof.subject_key_id,
        &signed.authority_key_id,
    )
    .await
}

/// v37.0.0 (CIRISPersist#734) — the authority leg of
/// [`verify_location_proof_admission`], split out so the rule has one name and
/// one body.
///
/// Admits when `authority` IS `subject` (self-knowledge, the ordinary case) or
/// when [`topology::live_delegate_standing`](super::topology::live_delegate_standing)
/// finds a live `delegates_to(subject → authority)`. Every other outcome is
/// [`Error::LocationAuthorityUnauthorized`], carrying the classified `rule`
/// token so the caller can tell a delivery-order artifact
/// ([`LOCATION_AUTHORITY_RULE_NO_DELEGATION_EDGE`], retryable) from a verdict.
async fn check_location_authority<F>(
    directory: &F,
    subject: &str,
    authority: &str,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    // Self-assertion — the subject speaking about itself. No read needed, and
    // it must hold even for a subject that has never issued an attestation.
    if authority == subject {
        return Ok(());
    }
    use super::topology::DelegateStanding;
    let standing =
        super::topology::live_delegate_standing(directory, subject, authority, chrono::Utc::now())
            .await?;
    let rule = match standing {
        DelegateStanding::Live => return Ok(()),
        DelegateStanding::NoEdge => LOCATION_AUTHORITY_RULE_NO_DELEGATION_EDGE,
        DelegateStanding::Retracted => LOCATION_AUTHORITY_RULE_DELEGATION_RETRACTED,
        DelegateStanding::Expired => LOCATION_AUTHORITY_RULE_DELEGATION_EXPIRED,
    };
    Err(Error::LocationAuthorityUnauthorized {
        subject_key_id: subject.to_owned(),
        offered_authority_key_id: authority.to_owned(),
        rule,
    })
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
/// v31.4.0 (CIRISPersist#664) — **`pub`, not `pub(crate)`: a downstream fixture
/// must be able to register the authority whose signature it is about to make.**
///
/// `cohort::test_support::admit_family` is already `pub`, and its own doc states
/// the precondition that `authority_key_id` MUST already be registered — via
/// `register_hybrid_key`, which lived behind a `pub(crate)` module. So a consumer
/// could **sign** an `AdmitSpec` and could not **register** the key that
/// signature verifies against: a fixture that fails closed with no way to open
/// it. Four independent downstream workstreams hit that wall (#604).
///
/// The whole module widens rather than the one function, because the same wall
/// is one call away in every direction — `sign_envelope`, `seal_row_in_place`
/// (which stamps the #598 instants AND the #643 row mirror as one step),
/// `seal_revocation`, `stamp_mirror`. A consumer building a valid row needs the
/// same helpers this crate's own fixtures need, and shipping half of them is how
/// the next `pub(crate)` wall gets discovered by someone else's blocked test.
///
/// This is **test-only surface**: the `#[cfg]` is unchanged, so nothing here
/// exists in a build that has not opted into `test-anchor`. Treat it as a
/// supported contract for fixtures and as nothing else — these helpers sign with
/// deterministic test keypairs and are not a production signing path.
#[cfg(any(test, feature = "test-anchor"))]
#[allow(dead_code)]
pub mod test_support {
    use super::*;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};

    /// Deterministic 32-byte seed for `key_id` — the first ≤32 bytes of
    /// the key_id over a `0x11` fill. Same shape as
    /// `register.rs::tests::signed_self_record`, so the two test corpora
    /// stay coherent.
    /// **Truncates at 32 bytes.** Two `key_id`s sharing a 32-byte prefix are
    /// therefore the SAME identity here — a real trap for a test that builds
    /// ids as `{long_tag}-victim` / `{long_tag}-attacker` and then believes it
    /// has two subjects. Put the distinguishing part FIRST, and assert the
    /// pubkeys differ (CIRISPersist#659 hit exactly this, on postgres only,
    /// where the tag carries a uuid).
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

    /// v38.0.0 (CIRISPersist#721) — wrap a [`TrustGrant`] with its
    /// granter's REAL deterministic hybrid signature over the pinned
    /// signing bytes, so the door's authority gate verifies against the
    /// pubkeys [`register_hybrid_key`] registered for `trusted_by`.
    pub fn signed_trust_grant(
        grant: crate::federation::TrustGrant,
    ) -> crate::federation::SignedTrustGrant {
        let bytes = crate::federation::admission::trust_grant_signing_bytes(&grant)
            .expect("trust grant canonicalizes");
        let sig = threshold_sign(&grant.trusted_by, &bytes);
        crate::federation::SignedTrustGrant {
            grant,
            signature_classical_base64: sig.ed25519_signature_base64,
            signature_pqc_base64: sig.mldsa65_signature_base64,
        }
    }

    /// v38.0.0 (CIRISPersist#721) — a signed trust revocation from
    /// `revoked_by`'s deterministic hybrid keys.
    pub fn signed_trust_revocation(
        key: &str,
        revoked_by: &str,
    ) -> crate::federation::SignedTrustRevocation {
        let revoked_at =
            crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now());
        let bytes = crate::federation::admission::trust_revocation_signing_bytes(
            key,
            revoked_by,
            &revoked_at,
        )
        .expect("trust revocation canonicalizes");
        let sig = threshold_sign(revoked_by, &bytes);
        crate::federation::SignedTrustRevocation {
            key: key.to_owned(),
            revoked_by: revoked_by.to_owned(),
            revoked_at,
            signature_classical_base64: sig.ed25519_signature_base64,
            signature_pqc_base64: sig.mldsa65_signature_base64,
        }
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
        register_hybrid_key_as(
            dir,
            key_id,
            pubkey_source_key_id,
            crate::federation::types::identity_type::AGENT,
        )
        .await
    }

    /// Register `key_id` with the deterministic test pubkeys of
    /// `pubkey_source_key_id` and the given `identity_type` — for fixtures
    /// whose doors care what KIND of key signs (a community member must be a
    /// human or steward-bound; an agent is not).
    pub async fn register_hybrid_key_as<D: crate::federation::FederationDirectory + ?Sized>(
        dir: &D,
        key_id: &str,
        pubkey_source_key_id: &str,
        identity_type: &str,
    ) {
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(pubkey_source_key_id);
        // v30.12.0 (CIRISPersist#634) — TRUNCATED TO MICROSECONDS. Postgres
        // `TIMESTAMPTZ` is microsecond precision while `Utc::now()` carries
        // nanoseconds, so timestamps minted here do not survive the round-trip
        // byte-for-byte on that backend.
        //
        // v31.0.0 (CIRISPersist#640) — this is NO LONGER what keeps the wire
        // index honest. #634 read the skew as a fixture property; it was not —
        // the write paths hashed the in-memory row while every read
        // re-serializes the reloaded one, so the same divergence was reachable
        // in production (`attach_key_pqc_signature` mints `pqc_completed_at` at
        // nanosecond precision; replication from a sqlite origin carries
        // nanosecond RFC-3339 over the wire). That is fixed at the source now:
        // every `federation_keys` writer indexes the row AS STORED. See
        // `wire_index::key_entry_as_stored`.
        //
        // The truncation stays because this fixture seeds hundreds of tests
        // that are about something else, and a microsecond-clean row keeps
        // them measuring what they are for. The #640 regression net is a
        // DEDICATED nanosecond-bearing witness
        // (`exercise_nanosecond_key_wire_ref_resolves`) — deliberately not
        // this shared helper, so the net cannot be silently disarmed by a
        // future fixture tidy-up.
        let now = {
            use chrono::Timelike as _;
            let dt = chrono::Utc::now();
            dt.with_nanosecond(dt.nanosecond() / 1_000 * 1_000)
                .unwrap_or(dt)
        };
        let rec = crate::federation::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
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

    /// v31.0.0 (CIRISPersist#659) — **seal a [`Revocation`](crate::federation::Revocation):
    /// bind its typed columns into `revocation_envelope`, then hybrid-sign the
    /// result** under the row's own `revoking_key_id` (the key
    /// [`super::verify_revocation_admission`] resolves pubkeys for — signing
    /// under any other produces a row no backend admits).
    ///
    /// The de-conferral twin of [`seal_row_in_place`]. Hand it a row whose
    /// typed columns are final and whose `original_content_hash` /
    /// `scrub_signature_*` are placeholders, and get back the same row sealed.
    /// The binding is stamped through
    /// [`bind_revocation_into_envelope`](crate::federation::admission::bind_revocation_into_envelope)
    /// — the SAME projection the gate compares against — so there is no second
    /// spelling here either, and a fixture cannot certify a revocation this
    /// substrate's own put door refuses.
    ///
    /// Note the instant truncation happens inside the producer, so a fixture
    /// carrying `Utc::now()` nanoseconds is silently made postgres-storable
    /// rather than dying at the gate. The witnesses that MEASURE the binding
    /// build their divergence deliberately, AFTER sealing — a fixture that
    /// merely forgot to seal is indistinguishable from a stale one.
    pub fn seal_revocation_in_place(row: &mut crate::federation::Revocation) {
        let signing_key_id = row.revoking_key_id.clone();
        crate::federation::admission::bind_revocation_into_envelope(row)
            .expect("the fixture revocation_envelope is a JSON object");
        let (och, sc, sp) = sign_envelope(&signing_key_id, &row.revocation_envelope);
        row.original_content_hash = och;
        row.scrub_signature_classical = sc;
        row.scrub_signature_pqc = sp;
    }

    /// [`seal_revocation_in_place`], by value.
    pub fn seal_revocation(
        mut row: crate::federation::Revocation,
    ) -> crate::federation::Revocation {
        seal_revocation_in_place(&mut row);
        row
    }

    /// v31.0.0 (CIRISPersist#656) — **a subject-side transit revocation whose
    /// signed envelope BINDS the row it will be stored as.**
    ///
    /// The §10.1.3 transit door is the one write path where persist is the
    /// RECEIVER of bytes it did not mint, so
    /// [`RowMirror::stamp_local_row`](crate::federation::envelope::RowMirror::stamp_local_row)
    /// declines to stamp and CHECKS instead. That makes the mirror the
    /// producer's to bind — which in turn means the producer must choose the
    /// `attestation_id` (it is one of the seven bound members), rather than
    /// letting persist mint a fresh v4. Every fixture that used to pass
    /// `attestation_id: None` and an unbound envelope was producing a row this
    /// substrate's own `put_attestation` refuses; this is the shape a real
    /// subject must send.
    ///
    /// The mirror is built through
    /// [`RowMirror::of`](crate::federation::envelope::RowMirror::of) over the
    /// row the input will become, so there is no second spelling of the
    /// projection here either.
    pub fn bound_transit_revocation_input(
        attestation_id: &str,
        subject: &str,
        target: &str,
        subject_key_ids: Vec<String>,
        cohort_scope: &str,
        asserted_at: chrono::DateTime<chrono::Utc>,
        extra: serde_json::Value,
    ) -> crate::federation::types::LocalAttestationInput {
        use crate::federation::types::{attestation_type, LocalAttestationInput};
        let asserted = crate::federation::admission::truncate_to_substrate_resolution(asserted_at);
        let mut envelope = serde_json::json!({
            "dimension": "consent:state:revoked:v1",
            "score": 1.0,
            "confidence": 0.9,
            crate::federation::envelope::paths::ASSERTED_AT: asserted.to_rfc3339(),
        });
        if let (Some(obj), Some(more)) = (envelope.as_object_mut(), extra.as_object()) {
            for (k, v) in more {
                obj.insert(k.clone(), v.clone());
            }
        }
        // THE MIRROR, from the row this input becomes
        // (`LocalAttestationInput::into_caller_signed_row`).
        let mut as_stored = crate::federation::types::Attestation {
            attestation_id: attestation_id.to_owned(),
            attesting_key_id: subject.to_owned(),
            attested_key_id: target.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: asserted,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: subject.to_owned(),
            scrub_timestamp: asserted,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: subject_key_ids.clone(),
            withdraws_admission_rule: None,
            cohort_scope: cohort_scope.to_owned(),
            tier: crate::federation::types::attestation_tier::LOCAL.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        crate::federation::envelope::RowMirror::stamp_row(&mut as_stored)
            .expect("the fixture row carries no weight, so the mirror cannot fail");
        let envelope = as_stored.attestation_envelope;
        let (_hash, sig_classical, sig_pqc) = sign_envelope(subject, &envelope);
        LocalAttestationInput {
            attestation_id: Some(attestation_id.to_owned()),
            attesting_key_id: subject.to_owned(),
            attested_key_id: Some(target.to_owned()),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(envelope)
                .expect("the fixture envelope is an object"),
            subject_key_ids,
            cohort_scope: cohort_scope.to_owned(),
            scrub_signature_classical: Some(sig_classical),
            scrub_signature_pqc: sig_pqc,
        }
    }

    /// v31.0.0 (CIRISPersist#643) — **stamp the typed-column mirror into a
    /// hand-built row's envelope, then hybrid-sign it.**
    ///
    /// The fixture corpus builds [`Attestation`] rows by hand and signs the
    /// envelope with [`sign_envelope`], which is exactly the producer shape the
    /// binding gate now constrains: the SEVEN typed columns must appear inside
    /// the SIGNED bytes (v31.0.0, CIRISPersist#658 — this said five; the
    /// authority is [`crate::federation::envelope::row_paths::ALL`]).
    /// Doing that by hand at every call site would be ~200
    /// copies of one projection, and a copy that drifts is a fixture certifying
    /// a row no host can write.
    ///
    /// So: hand it a row whose typed columns are final and whose
    /// `original_content_hash` / `scrub_signature_*` are placeholders, and get
    /// back the same row sealed — mirror stamped from
    /// [`RowMirror::of`](crate::federation::envelope::RowMirror::of) (the SAME
    /// projection the gate compares against), envelope canonicalized, hash and
    /// both signature halves filled in.
    ///
    /// v31.0.0 (CIRISPersist#598) — **also stamps `asserted_at` /
    /// `expires_at`.** It did not, when the #598 gate ran on `consent:state:*`
    /// only and the instants were one dimension's property; the gate now binds
    /// them on EVERY row, so a seal that left them out would produce a row
    /// this substrate's own put door refuses — a fixture corpus certifying a
    /// placement no host can write. The witnesses that measure the binding
    /// itself are therefore NOT fixtures that forgot to seal (that failure
    /// mode is indistinguishable from a stale fixture); they build the
    /// divergence deliberately, AFTER sealing.
    pub fn seal_row(signing_key_id: &str, mut row: Attestation) -> Attestation {
        seal_row_in_place(signing_key_id, &mut row);
        row
    }

    /// v31.0.0 (CIRISPersist#643) — [`seal_row`] in place, for the fixtures
    /// that MUTATE a built row (change the verb, swap the envelope, add
    /// subjects) and must re-seal afterwards. The whole corpus's `resign_*`
    /// helpers delegate here, so "re-sign after mutating" and "re-stamp the
    /// mirror after mutating" are ONE step that cannot be half-done.
    pub fn seal_row_in_place(signing_key_id: &str, row: &mut Attestation) {
        use crate::federation::envelope::paths;
        // v31.0.0 (CIRISPersist#598) — the INSTANTS are part of the seal, not a
        // separate step a fixture can forget. `check_instant_binding` now runs
        // on every dimension, so a row sealed without them is one this
        // substrate's own put door refuses.
        //
        // Through `envelope::stamp_signed_instants` — the SAME function the
        // production local-write door stamps with — so the fixture corpus
        // cannot certify a placement no host writes. It truncates the columns
        // before mirroring them and clears `expires_at` in both directions;
        // see its doc for why each of those is load-bearing.
        crate::federation::envelope::stamp_signed_instants(row).expect("envelope is an object");
        let mirror = crate::federation::envelope::RowMirror::of(row).expect("finite weight");
        row.attestation_envelope[paths::ROW] =
            serde_json::to_value(&mirror).expect("RowMirror serializes");
        let (och, sc, sp) = sign_envelope(signing_key_id, &row.attestation_envelope);
        row.original_content_hash = och;
        row.scrub_signature_classical = sc;
        row.scrub_signature_pqc = sp;
    }

    /// v31.0.0 (CIRISPersist#643) — [`seal_row_in_place`] under the row's OWN
    /// `attesting_key_id`, the overwhelmingly common fixture case.
    pub fn reseal(row: &mut Attestation) {
        let signer = row.attesting_key_id.clone();
        seal_row_in_place(&signer, row);
    }

    /// v31.0.0 (CIRISPersist#649) — **the fixture twin of
    /// `Engine::reseal_for_scope`**: re-stamp `row`'s typed-column mirror for
    /// the placement it is about to land at, then hybrid-sign the result with
    /// `signing_key_id`'s deterministic keys.
    ///
    /// Both placement-touching directory primitives
    /// ([`crate::federation::FederationDirectory::promote_attestation`] and
    /// [`crate::federation::FederationDirectory::set_attestation_cohort_scope`])
    /// take this bundle, because `cohort_scope` lives INSIDE the signed bytes
    /// and a placement change is therefore a re-sign. Fixtures use this rather
    /// than hand-rolling the recipe: a hand-rolled copy that forgets the
    /// re-stamp is the #649 defect wearing a test's clothes.
    ///
    /// `scrub_timestamp` is truncated to the substrate resolution so the
    /// postgres arm (microseconds) and the in-memory row agree — the #646
    /// nanosecond skew, avoided rather than re-measured.
    pub fn reseal_for_scope(
        signing_key_id: &str,
        row: &Attestation,
        cohort_scope: &str,
    ) -> crate::federation::AttestationReseal {
        let attestation_envelope = crate::federation::envelope::RowMirror::restamp_for_scope(
            &row.attestation_envelope,
            row,
            cohort_scope,
        )
        .expect("finite weight");
        reseal_over(signing_key_id, attestation_envelope)
    }

    /// v31.0.0 (CIRISPersist#649) — **the PRE-#649 shape, on purpose**: sign
    /// the row's CURRENT envelope, whose mirror still asserts the row's OLD
    /// `cohort_scope`, and hand it to a placement-touching primitive.
    ///
    /// This is what promotion did for the whole of #643's life, and the reason
    /// a promoted row was refused by every peer. It exists so the witness can
    /// exercise the defect itself rather than a description of it: a test that
    /// only ever passes the CORRECT bundle cannot tell whether the re-stamp is
    /// load-bearing.
    pub fn reseal_without_restamp(
        signing_key_id: &str,
        row: &Attestation,
    ) -> crate::federation::AttestationReseal {
        reseal_over(signing_key_id, row.attestation_envelope.clone())
    }

    /// v39.0.0 — the ACTOR's custody for a tier crossing: the attester's own
    /// hybrid signature over `JCS(envelope)` of the row as stored (canonical at
    /// rest, so the bytes are the ones `crossing::plan_enter_mesh`
    /// recomputes). Never re-stamps anything.
    pub fn actor_reseal(row: &Attestation) -> crate::federation::TierPromotionCustody {
        let mut envelope = row.attestation_envelope.clone();
        crate::federation::canonical_at_rest::canonicalize_in_place(&mut envelope)
            .expect("fixture envelope canonicalizes");
        crate::federation::TierPromotionCustody::ActorSigned(reseal_over(
            &row.attesting_key_id,
            envelope,
        ))
    }

    /// v39.0.0 — a NODE's custody for a tier crossing: `signing_key_id`'s
    /// hybrid signature over the same bytes, offered as a co-scrub
    /// (`cosigned_at` is stamped by the crossing, not here).
    pub fn node_coscrub(
        signing_key_id: &str,
        row: &Attestation,
    ) -> crate::federation::TierPromotionCustody {
        let mut envelope = row.attestation_envelope.clone();
        crate::federation::canonical_at_rest::canonicalize_in_place(&mut envelope)
            .expect("fixture envelope canonicalizes");
        let (_hash, classical, pqc) = sign_envelope(signing_key_id, &envelope);
        crate::federation::TierPromotionCustody::NodeCoScrub(crate::federation::types::ScrubSig {
            scrub_key_id: signing_key_id.to_owned(),
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            // The co-signer stamps its own instant; the crossing writes it.
            cosigned_at: Some(crate::federation::admission::render_signed_instant(
                chrono::Utc::now(),
            )),
        })
    }

    /// v39.0.0 — widen `prior` to `scope` by a `supersedes` signed by the
    /// prior's attester (its deterministic test key), through the ONE widening
    /// path (`FederationDirectory::widen_audience`). `strip` names payload
    /// members omitted on the way (listed in `differs_in`).
    pub async fn widen<D: crate::federation::FederationDirectory + ?Sized>(
        dir: &D,
        prior: &Attestation,
        audience: crate::federation::Audience,
        strip: &[String],
    ) -> Result<crate::federation::MeshCrossingOutcome, crate::federation::Error> {
        use crate::federation::{attestation_emit, crossing, CrossingBasis, SignedAttestation};
        let ci = describe_for(prior, audience, CrossingBasis::ProducerAuthority);
        let mut input = crossing::build_widening(prior, &ci.recipient_see, strip)?;
        let canonical = attestation_emit::stamp_and_canonicalize(
            &mut input,
            &prior.attesting_key_id,
            chrono::Utc::now(),
        )?;
        let sig = local_signer(&prior.attesting_key_id)
            .sign_hybrid(&canonical)
            .await
            .expect("test signer signs");
        let (row, _) =
            attestation_emit::assemble(prior.attesting_key_id.clone(), &canonical, sig, input)?;
        dir.widen_audience(
            &prior.attestation_id,
            &ci,
            SignedAttestation { attestation: row },
        )
        .await
    }

    /// v39.0.0 — the nine axes DERIVED from a row (the description a caller
    /// would state), with `recipient_see` set to `scope` and the basis given.
    /// Fixtures use it so every crossing states the checklist; a witness that
    /// wants a mismatch edits one field.
    pub fn describe_for(
        row: &Attestation,
        audience: crate::federation::Audience,
        basis: crate::federation::CrossingBasis,
    ) -> crate::federation::ContextualIntegrity {
        crate::federation::crossing::describe(row, audience, basis)
            .expect("fixture row is describable")
    }

    /// The nine axes of a row AT ITS OWN audience (`Audience::of_row`) — what a
    /// tier crossing states.
    pub fn describe_own(
        row: &Attestation,
        basis: crate::federation::CrossingBasis,
    ) -> crate::federation::ContextualIntegrity {
        let audience =
            crate::federation::Audience::of_row(row).expect("fixture row has an audience");
        describe_for(row, audience, basis)
    }

    fn reseal_over(
        signing_key_id: &str,
        attestation_envelope: serde_json::Value,
    ) -> crate::federation::AttestationReseal {
        let (original_content_hash, scrub_signature_classical, scrub_signature_pqc) =
            sign_envelope(signing_key_id, &attestation_envelope);
        crate::federation::AttestationReseal {
            attestation_envelope,
            original_content_hash,
            scrub_signature_classical,
            scrub_signature_pqc,
            scrub_key_id: signing_key_id.to_owned(),
            scrub_timestamp: crate::federation::admission::truncate_to_substrate_resolution(
                chrono::Utc::now(),
            ),
        }
    }

    /// v31.0.0 (CIRISPersist#643) — stamp **every tier-1 binding** and **do not
    /// sign**.
    ///
    /// For the witnesses whose whole point is a row that reaches a LATER gate:
    /// `unverifiable_row` must clear the tier-1 bindings and then be refused by
    /// the tier-3 hybrid verify, so sealing it with a valid signature would
    /// silently relocate what the test measures.
    ///
    /// v31.0.0 (CIRISPersist#598) — that means the INSTANTS as well as the
    /// mirror. `check_instant_binding` became a tier-1 gate on every dimension,
    /// so a row carrying only the mirror now dies at tier 1 — and a gate-ORDER
    /// witness that dies at the wrong tier is not measuring the order. Stamping
    /// them here rather than at the call sites keeps "clears tier 1, dies at
    /// tier 3" a property of ONE helper, so the next tier-1 gate is added in
    /// one place instead of silently disarming these witnesses.
    ///
    /// Still does not sign, which is the whole distinction from
    /// [`seal_row_in_place`].
    pub fn stamp_mirror(row: &mut Attestation) {
        crate::federation::envelope::stamp_signed_instants(row).expect("envelope is an object");
        crate::federation::envelope::RowMirror::stamp_row(row).expect("finite weight");
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

    /// v38.2.0 (CIRISPersist#757 / CIRISServer chat wiring) — **an
    /// owner-signed community row is expressible.**
    ///
    /// Before this cut it was not, anywhere on the substrate: every
    /// backend's `put_attestation` passed a hardcoded `None` target, so
    /// AV-45's community arm refused the placement outright, and the only
    /// other door — promotion — re-seals the envelope and stamps
    /// `scrub_key_id` with the promoting node's own key. A chat message or a
    /// testimony could therefore never carry its AUTHOR's signature at
    /// community scope, which is what author-only revocation and
    /// third-party verification of authorship both rest on.
    ///
    /// Three arms: a member's own row lands with the author's signature
    /// intact; a NON-member naming the same community is refused (the
    /// membership question AV-45 exists to ask, now askable); and a row
    /// naming no community at all is still refused, so the fix did not turn
    /// the community placement into a free-for-all.
    pub(crate) async fn exercise_owner_signed_community_row(
        dir: &dyn crate::federation::FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::types::{attestation_tier, attestation_type, cohort_scope};

        let cid = format!("chat-comm-757-{suffix}");
        let author = format!("author-757-{suffix}");
        let stranger = format!("stranger-757-{suffix}");
        register_hybrid_key(dir, &cid).await;
        for k in [&author, &stranger] {
            register_user_role_key(dir, k).await;
        }
        seed_two_member_community(dir, &cid, &author, &author).await;

        let row = |producer: &str, target: Option<&str>| {
            let mut env = serde_json::json!({ "dimension": "chat:message:v1" });
            if let Some(t) = target {
                env["community_id"] = serde_json::Value::String(t.to_owned());
            }
            crate::federation::types::Attestation {
                attestation_id: uuid::Uuid::new_v4().to_string(),
                attesting_key_id: producer.to_owned(),
                attested_key_id: producer.to_owned(),
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: None,
                asserted_at: chrono::Utc::now(),
                expires_at: None,
                attestation_envelope: env,
                original_content_hash: "ab".repeat(32),
                scrub_signature_classical: "c2ln".to_owned(),
                scrub_signature_pqc: None,
                scrub_key_id: producer.to_owned(),
                scrub_timestamp: chrono::Utc::now(),
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: vec![producer.to_owned()],
                withdraws_admission_rule: None,
                cohort_scope: cohort_scope::COMMUNITY.to_owned(),
                // FEDERATION tier, really signed (PR #759 review): the first
                // shape of this witness rode tier `local` with placeholder
                // signatures — and LANDED, because local tier defers
                // signature verification. That was itself the hole: a
                // community placement is a membership claim, and an
                // unverified membership claim is mintable by anyone. The
                // owner-signed path this witness certifies is the
                // federation-tier one, under the author's REAL hybrid
                // signature, verified by `verify_federation_tier_ingest` in
                // full.
                tier: attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            }
        };
        let row = |producer: &str, target: Option<&str>| {
            let mut r = row(producer, target);
            seal_row_in_place(producer, &mut r);
            r
        };

        // (1) THE UNBLOCK — a member's own community row, signed by the
        // author, admitted at the door that preserves that signature.
        let mine = row(&author, Some(&cid));
        let signed_author = mine.scrub_key_id.clone();
        dir.put_attestation(crate::federation::SignedAttestation { attestation: mine })
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "({suffix}) #757: a member's own community-scoped row must be expressible \
                     — this is the wall CIRISServer's chat wiring hit: {e}"
                )
            });
        assert_eq!(
            signed_author, author,
            "({suffix}) the row carries the AUTHOR's scrub key, not the node's"
        );

        // (PROBE) A member's row ABOUT A THIRD PARTY, published to the whole
        // community. AV-84 refuses this at the promote door; the put door
        // was SHUT, so nothing asked there. Opening the put door without
        // AV-84 would let it through.
        let mut third_party = row(&author, Some(&cid));
        third_party.attested_key_id = stranger.clone();
        third_party.subject_key_ids = vec![stranger.clone()];
        stamp_mirror(&mut third_party);
        let probe = dir
            .put_attestation(crate::federation::SignedAttestation {
                attestation: third_party,
            })
            .await;
        assert!(
            probe.is_err(),
            "({suffix}) #757 REGRESSION: a member placed a row ABOUT A THIRD PARTY into the \
             community plane. AV-84 (check_promotion_cohort_standing) refuses exactly this at \
             the promote door, and justifies being promote-only by asserting the put door is \
             SHUT. Opening the put door means AV-84 must run there too."
        );

        // (2) A non-member naming the same community is refused — the
        // membership question AV-45 exists to ask, now askable.
        let err = dir
            .put_attestation(crate::federation::SignedAttestation {
                attestation: row(&stranger, Some(&cid)),
            })
            .await
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "({suffix}) #757: a NON-member must not place a row into a community it \
                     does not belong to — reading the target must not become admitting anyone"
                )
            });
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("communit") || msg.to_lowercase().contains("scope"),
            "({suffix}) the refusal names the membership question: {msg}"
        );

        // (3) A community-scoped row naming NO community is still refused —
        // the placement is not a free-for-all now that the target is read.
        assert!(
            dir.put_attestation(crate::federation::SignedAttestation {
                attestation: row(&author, None)
            })
            .await
            .is_err(),
            "({suffix}) #757: a community placement with no named community must still refuse"
        );

        // (4) REVOCATION BITES AT THE WRITE DOOR. The roster is append-only;
        // effective membership is admitted AND NOT revoked (the #709 fold,
        // `active_community_members`). Raw `members` containment counts a
        // revoked member as a member — and through v38.0.0 that mismatch was
        // vacuously unreachable here, because the door refused everything.
        // Opening the door (#757) made the fold choice load-bearing: with the
        // raw fold, a REMOVED member keeps writing into the community's plane
        // forever, the exact failure the removal primitive exists to prevent.
        dir.put_community_membership_revocation(sign_community_membership_revocation(
            &cid,
            crate::federation::types::CommunityMembershipRevocation {
                community_key_id: cid.clone(),
                removed_identity_key_id: author.clone(),
                removed_at: chrono::Utc::now(),
                effective_at: chrono::Utc::now(),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("({suffix}) revoke author's membership: {e}"));
        assert!(
            dir.put_attestation(crate::federation::SignedAttestation {
                attestation: row(&author, Some(&cid)),
            })
            .await
            .is_err(),
            "({suffix}) #757: a REVOKED member wrote into the community plane — the write \
             gate consulted raw roster containment instead of the active fold \
             (admitted AND NOT revoked)"
        );

        // Arms 5-7 need an ACTIVE member (arm 4 revoked `author` out of
        // `cid`), so they run against a second community.
        let bob_observer = format!("observer-757-{suffix}");
        let cid2 = format!("chat-comm2-757-{suffix}");
        register_user_role_key(dir, &bob_observer).await;
        register_hybrid_key(dir, &cid2).await;
        seed_two_member_community(dir, &cid2, &bob_observer, &bob_observer).await;

        // (5) SPLIT-BRAIN TARGET REFUSES (PR #759 review). Membership was
        // proven for the FIRST alias only, while consumers that walk every
        // alias (the moderator gate) key the row on the second — a member of
        // C1 must not smuggle a row keyed on C2.
        let mut split = row(&bob_observer, Some(&cid2));
        split.attestation_envelope["community_key_id"] =
            serde_json::Value::String(format!("other-comm-757-{suffix}"));
        seal_row_in_place(&bob_observer, &mut split);
        let err = dir
            .put_attestation(crate::federation::SignedAttestation { attestation: split })
            .await
            .err()
            .unwrap_or_else(|| {
                panic!("({suffix}) PR#759: disagreeing cohort-target aliases must refuse")
            });
        assert!(
            format!("{err}").contains("aliases disagree"),
            "({suffix}) the refusal names the split-brain: {err}"
        );

        // (6) LOCAL TIER + TARGETED SCOPE REFUSES (PR #759 review). Local
        // rows defer signature verification, so a community placement there
        // is an unverified membership claim — the shape the FIRST version of
        // this witness accidentally proved mintable (placeholder signatures,
        // tier local, landed).
        let mut local = row(&bob_observer, Some(&cid2));
        local.tier = attestation_tier::LOCAL.to_owned();
        local.scrub_signature_classical = "c2ln".to_owned();
        local.scrub_signature_pqc = None;
        stamp_mirror(&mut local);
        let err = dir
            .put_attestation(crate::federation::SignedAttestation { attestation: local })
            .await
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "({suffix}) PR#759: a local-tier community placement carries an \
                     UNVERIFIED membership claim and must refuse"
                )
            });
        assert!(
            format!("{err}").contains("federation tier"),
            "({suffix}) the refusal names the federation-tier requirement: {err}"
        );

        // (7) A DEVICE OCCURRENCE WRITES AS ITS OWNING IDENTITY (PR #759
        // review). `attesting = O`, `attested = I`, `resolve(O) = I`: the
        // identity an occurrence resolves to is NOT a third party — it IS
        // the producer (#275 / §4.4). The string-compare form of AV-84
        // refused this as `AttestedParty`, which would have made
        // owner-attributed device chat unwriteable.
        let device = format!("device-757-{suffix}");
        register_user_role_key(dir, &device).await;
        dir.put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
            identity_key_id: bob_observer.clone(),
            occurrence_key_id: device.clone(),
            device_class: crate::federation::types::device_class::SERVER.into(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("({suffix}) bind device occurrence: {e}"));
        let mut via_device = row(&device, Some(&cid2));
        via_device.attested_key_id = bob_observer.clone();
        via_device.subject_key_ids = vec![bob_observer.clone()];
        seal_row_in_place(&device, &mut via_device);
        dir.put_attestation(crate::federation::SignedAttestation {
            attestation: via_device,
        })
        .await
        .unwrap_or_else(|e| {
            panic!(
                "({suffix}) PR#759: a device occurrence writing about its OWN owning \
                 identity is the producer, not a third party — refused with: {e}"
            )
        });

        // (8) AN UNKNOWN TIER REFUSES (PR #761 review). The SQL schemas
        // CHECK the tier vocabulary; memory checked nothing — and an unknown
        // tier is signature-EXEMPT (`verify_federation_tier_ingest` verifies
        // only `federation`), so tier "bogus" was a signature bypass on
        // exactly one backend. The vocabulary gate is tier-1 and
        // backend-shared, so all three answer alike.
        let mut bogus = row(&bob_observer, Some(&cid2));
        bogus.tier = "bogus".to_owned();
        stamp_mirror(&mut bogus);
        let err = dir
            .put_attestation(crate::federation::SignedAttestation { attestation: bogus })
            .await
            .err()
            .unwrap_or_else(|| {
                panic!("({suffix}) PR#761: an unknown tier is signature-exempt and must refuse")
            });
        assert!(
            format!("{err}").contains("vocabulary is closed"),
            "({suffix}) the refusal names the closed tier vocabulary: {err}"
        );

        // (9) A LOCAL ROW CANNOT BE RE-SCOPED INTO A TARGETED COHORT
        // (PR #761 review). `set_attestation_cohort_scope` preserves the
        // stored tier, so re-scoping a local (signature-deferred) row to
        // `community` would mint the same unverified membership claim the
        // put door now refuses — the recurring "a rule shipped behind one
        // door while the motion uses another" class, caught at the door
        // BESIDE the one the last fix gated.
        let mut local_row = row(&bob_observer, Some(&cid2));
        local_row.cohort_scope = crate::federation::types::cohort_scope::SELF.to_owned();
        local_row.tier = attestation_tier::LOCAL.to_owned();
        seal_row_in_place(&bob_observer, &mut local_row);
        let local_id = local_row.attestation_id.clone();
        dir.put_attestation(crate::federation::SignedAttestation {
            attestation: local_row.clone(),
        })
        .await
        .unwrap_or_else(|e| panic!("({suffix}) seed local self row: {e}"));
        // v39.0.0 — a scope change is a `supersedes` through `widen_audience`,
        // and a LOCAL prior is refused there: it must enter the mesh first.
        let stored_local = dir
            .get_attestation(&local_id)
            .await
            .unwrap()
            .expect("the local row exists");
        let err = test_support::widen(
            dir,
            &stored_local,
            crate::federation::Audience::Community {
                community_key_id: cid2.clone(),
            },
            &[],
        )
        .await
        .err()
        .unwrap_or_else(|| {
            panic!(
                "({suffix}) PR#761: widening a LOCAL row into a community is an \
                 unverified membership claim and must refuse"
            )
        });
        assert!(
            matches!(err, crate::federation::Error::WideningMalformed { .. })
                && format!("{err}").contains("enter_mesh first"),
            "({suffix}) the refusal names the crossing that must come first: {err}"
        );

        // (10) A REVOKED DEVICE LOSES ITS OWNER'S MEMBERSHIP (PR #761
        // review). `lookup_identity_for_occurrence` returns the HISTORICAL
        // binding — revocation leaves the row intact — so resolving through
        // it kept a lost/stolen device co-self with its former owner,
        // regaining exactly the family/community write access the
        // revocation exists to sever. Resolution now rides the ACTIVE fold;
        // the revoked device falls back to its singleton identity, which is
        // not a member.
        dir.put_identity_occurrence_revocation_local(
            crate::federation::types::IdentityOccurrenceRevocation {
                identity_key_id: bob_observer.clone(),
                occurrence_key_id: device.clone(),
                revoked_at: chrono::Utc::now(),
                effective_at: chrono::Utc::now(),
                reason: None,
                witness_set: vec![],
                persist_row_hash: String::new(),
            },
        )
        .await
        .unwrap_or_else(|e| panic!("({suffix}) revoke device binding: {e}"));
        let mut via_revoked = row(&device, Some(&cid2));
        via_revoked.attested_key_id = bob_observer.clone();
        via_revoked.subject_key_ids = vec![bob_observer.clone()];
        seal_row_in_place(&device, &mut via_revoked);
        assert!(
            dir.put_attestation(crate::federation::SignedAttestation {
                attestation: via_revoked,
            })
            .await
            .is_err(),
            "({suffix}) PR#761: a REVOKED device wrote with its former owner's community \
             membership — resolution consulted the historical binding, not the active fold"
        );
    }

    /// v38.6.0 (#773) — a live `delegates_to(owner → node)` carrying the
    /// CC 1.13.3.3 ownership dimension, sealed by the owner.
    pub(crate) async fn put_owner_binding(
        dir: &dyn crate::federation::FederationDirectory,
        owner: &str,
        node: &str,
    ) {
        use crate::federation::types::{attestation_type, delegation_scope as ds, owner_binding};
        let id = uuid::Uuid::new_v4().to_string();
        let mut row = bare_attestation(
            &id,
            owner,
            node,
            &serde_json::json!({
                "id": id,
                "kind": "delegates_to",
                "dimension": owner_binding::DIMENSION,
                "delegation_purpose": owner_binding::PURPOSE,
                "scope": [ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
            }),
        );
        row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        seal_row_in_place(owner, &mut row);
        dir.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .expect("put owner-binding");
    }

    /// v38.6.0 (#773) — a live custody claim `delegates_to(steward → subject)`.
    ///
    /// Carries the ownership dimension MARKER deliberately: an agent
    /// `can_accept_for_itself`, so `steward_bindings_of` counts only
    /// marker-bearing edges for it. An unmarked delegation to a party that
    /// can accept for itself is a capability conferral — giving them a job,
    /// not custody of them — and would not make the granter a steward.
    pub(crate) async fn put_steward_binding(
        dir: &dyn crate::federation::FederationDirectory,
        steward: &str,
        subject: &str,
    ) {
        use crate::federation::types::{attestation_type, delegation_scope as ds};
        let id = uuid::Uuid::new_v4().to_string();
        let mut row = bare_attestation(
            &id,
            steward,
            subject,
            &serde_json::json!({
                "id": id,
                "kind": "delegates_to",
                "dimension": crate::federation::types::owner_binding::DIMENSION,
                "delegation_purpose": crate::federation::types::owner_binding::PURPOSE,
                "scope": [ds::AGENCY_ACT_ON_BEHALF],
            }),
        );
        row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        seal_row_in_place(steward, &mut row);
        dir.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .expect("put steward-binding");
    }

    /// v38.6.0 (CIRISPersist#773, CC 3.4.7.3 Clause D) — **may_act_through:
    /// the node's ONE owner must appear in the agent's steward set.**
    ///
    /// Four arms, and the last two are the point. The asymmetry is
    /// load-bearing (ownership single-valued, stewardship multi-parent), so
    /// co-stewardship must SUFFICE — that is what makes the community-server
    /// case expressible without new grammar. And the fail-closed half is
    /// normative: "different humans" and "could not resolve the owner" must
    /// NOT share a return value, because on the person/node axis the
    /// signature failure is a silent withhold, where an unresolved walk
    /// reads as permission.
    pub(crate) async fn exercise_may_act_through(
        dir: &dyn crate::federation::FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::admission::may_act_through;

        let owner = format!("mat-owner-{suffix}");
        let other = format!("mat-other-{suffix}");
        let node = format!("mat-node-{suffix}");
        let unowned = format!("mat-unowned-{suffix}");
        let agent_ok = format!("mat-agent-ok-{suffix}");
        let agent_no = format!("mat-agent-no-{suffix}");
        for k in [&owner, &other] {
            register_user_role_key(dir, k).await;
        }
        for k in [&node, &unowned, &agent_ok, &agent_no] {
            register_hybrid_key(dir, k).await;
        }

        // owner --owner-binding--> node
        put_owner_binding(dir, &owner, &node).await;

        // CO-STEWARDSHIP, built the way this substrate actually expresses it.
        //
        // `steward_bindings_of` has TWO halves, and only together do they
        // give the multi-parent set CC 3.4.7.3 Clause D relies on:
        //
        //  1. the OCCURRENCE half — an agent that is an identity-occurrence
        //     of a USER is stewarded by that user;
        //  2. the DELEGATION half — for a party that
        //     `can_accept_for_itself` (an agent does), only a MARKER-bearing
        //     custody claim counts; an unmarked delegation is a capability
        //     conferral, giving them a job rather than custody of them.
        //
        // Two marker-bearing claims on ONE key is not a way to build it:
        // `check_single_node_owner_admission` fires on any marker-bearing
        // `delegates_to` regardless of the recipient's identity_type, so the
        // second is refused `NodeAlreadyOwned`. Hence occurrence + one
        // custody claim.
        dir.put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
            identity_key_id: other.clone(),
            occurrence_key_id: agent_ok.clone(),
            device_class: crate::federation::types::device_class::SERVER.into(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("bind agent_ok as an occurrence of `other`");
        put_steward_binding(dir, &owner, &agent_ok).await;

        // This agent's only steward is someone who owns no relevant node.
        put_steward_binding(dir, &other, &agent_no).await;

        // (1) Co-stewardship SUFFICES — the community-server case.
        assert!(
            may_act_through(dir, &agent_ok, &node).await.unwrap(),
            "({suffix}) #773 Clause D: the node's owner appears in the agent's steward set, \
             which is the whole rule — requiring a SINGLE shared human would wrongly imply \
             an agent has exactly one steward"
        );

        // (2) A steward set that EXCLUDES the node owner is inadmissible.
        assert!(
            !may_act_through(dir, &agent_no, &node).await.unwrap(),
            "({suffix}) #773: hosting an agent whose stewards exclude the node owner stays \
             inadmissible — CC defers that case to an explicit node-owner conferral"
        );

        // (3) An UNOWNED node is an ERROR, not `false`. Fail-closed, and
        // distinguishable from arm (2): a caller that cannot tell "no" from
        // "could not tell" will eventually treat one as the other.
        let err = may_act_through(dir, &agent_ok, &unowned)
            .await
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "({suffix}) #773: an unowned node must REFUSE, never answer — on this \
                     axis an unresolved walk that reads as permission is a silent withhold"
                )
            });
        assert!(
            format!("{err}").contains("no live owner-binding"),
            "({suffix}) and the refusal says which walk failed: {err}"
        );

        // (4) The two negative answers are DIFFERENT VALUES.
        assert!(
            may_act_through(dir, &agent_no, &node).await.is_ok(),
            "({suffix}) #773: 'different humans' is a resolved `Ok(false)` — it must not \
             collapse into the unresolved-owner error arm"
        );
    }

    /// v38.5.0 (CIRISPersist#771) — **a re-delivered row is a DUPLICATE, not
    /// a backend failure.**
    ///
    /// The production shape, exactly: the same signed attestation delivered
    /// twice. Before this cut the second delivery raised a UNIQUE violation
    /// that the error mapping defaulted to `Error::Backend`, so the sender
    /// saw `federation_backend` — indistinguishable from a broken database —
    /// and retried forever. 7,536 refusals in six hours on the canonical,
    /// 428 rows re-sent up to 82 times, none of them lost.
    ///
    /// Three arms: the first delivery reports `Inserted`; the byte-identical
    /// re-delivery reports `AlreadyHeld` (Ok, not Err); and a DIFFERENT row
    /// under the same id is still a typed `Conflict`, because two rows
    /// claiming one identity is a real disagreement and the fix for noisy
    /// refusals must not become "accept anything".
    pub(crate) async fn exercise_duplicate_is_already_held(
        dir: &dyn crate::federation::FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::AttestationOutcome;

        let a = format!("dup-a-771-{suffix}");
        let b = format!("dup-b-771-{suffix}");
        for k in [&a, &b] {
            register_hybrid_key(dir, k).await;
        }

        let id = uuid::Uuid::new_v4().to_string();
        let mut row = bare_attestation(
            &id,
            &a,
            &b,
            &serde_json::json!({ "id": id, "dimension": "scores:medical:v1" }),
        );
        row.attestation_type = crate::federation::types::attestation_type::SCORES.to_owned();
        seal_row_in_place(&a, &mut row);

        // (1) First delivery: a real state change.
        let first = dir
            .put_attestation(crate::federation::SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .unwrap_or_else(|e| panic!("({suffix}) first delivery must land: {e}"));
        assert_eq!(
            first,
            AttestationOutcome::Inserted,
            "({suffix}) #771: the first delivery is the anti-entropy progress signal"
        );

        // (2) THE STORM'S SHAPE — the identical row delivered again.
        let second = dir
            .put_attestation(crate::federation::SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "({suffix}) #771: a re-delivered IDENTICAL row must be idempotent \
                     success, not an error — reporting it as `federation_backend` is what \
                     made the sender retry forever (7,536 refusals / 6h): {e}"
                )
            });
        assert_eq!(
            second,
            AttestationOutcome::AlreadyHeld,
            "({suffix}) #771: and it must be distinguishable from Inserted, or the \
             consumer cannot count it as routine non-progress"
        );

        // (3) A DIFFERENT row under the same id is still refused.
        let mut impostor = row.clone();
        impostor.attestation_envelope["dimension"] =
            serde_json::Value::String("scores:dental:v1".into());
        seal_row_in_place(&a, &mut impostor);
        let err = dir
            .put_attestation(crate::federation::SignedAttestation {
                attestation: impostor,
            })
            .await
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "({suffix}) #771: a DIFFERENT row under an occupied id is two rows \
                     claiming one identity — quieting duplicates must not become \
                     accepting anything"
                )
            });
        assert!(
            matches!(err, crate::federation::Error::Conflict(_)),
            "({suffix}) #771: and the disagreement is TYPED, not a backend error: {err}"
        );
    }

    /// CIRISPersist#788 — the serve-tier ladder, on a real directory.
    ///
    /// The rung that had no resolver is `MeshServer`, and the thing worth
    /// witnessing is that it takes BOTH halves: the owner's conferral AND the
    /// subject's own claim. Either alone is `None`, which is what makes
    /// `claims_role` visibility-not-conferral (v19.0.0) enforceable rather than
    /// merely documented — registering the string buys nothing (AV-75).
    pub(crate) async fn exercise_resolve_serve_tier_788(
        dir: &dyn crate::federation::FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::trust_root::{resolve_serve_tier, ServeTier};
        use crate::federation::types::{attestation_type, delegation_scope as ds, owner_binding};

        let owner = format!("owner-788-{suffix}");
        let served = format!("node-788-{suffix}");
        let unclaimed = format!("quiet-788-{suffix}");
        let orphan = format!("orphan-788-{suffix}");
        let resolver = format!("resolver-788-{suffix}");
        register_user_role_key(dir, &owner).await;
        register_hybrid_key(dir, &resolver).await;
        // The claim rides `identity_type` as a SET — `claims_role` reads either
        // surface, and this is the one a node row actually carries.
        register_identity_key(dir, &served, "node,infra:serve").await;
        register_identity_key(dir, &unclaimed, "node").await;
        register_identity_key(dir, &orphan, "node,infra:serve").await;

        // Both nodes get the SAME owner-binding, bearing infra:serve. The only
        // difference between them is whether the subject claims the role, so
        // the assertions below isolate exactly that.
        for node in [&served, &unclaimed] {
            let id = uuid::Uuid::new_v4().to_string();
            let mut binding = bare_attestation(
                &id,
                &owner,
                node,
                &serde_json::json!({
                    "id": id,
                    "kind": "delegates_to",
                    "dimension": owner_binding::DIMENSION,
                    "delegation_purpose": owner_binding::PURPOSE,
                    "scope": [ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
                }),
            );
            binding.attestation_type = attestation_type::DELEGATES_TO.to_owned();
            seal_row_in_place(&owner, &mut binding);
            dir.put_attestation(crate::federation::SignedAttestation {
                attestation: binding,
            })
            .await
            .unwrap_or_else(|e| panic!("({suffix}) put owner-binding: {e}"));
        }

        // (1) Conferred AND claimed ⇒ MeshServer. This is the rung that had no
        // resolver at all: before #788 an owner-conferred-only server could not
        // be recognized as one, so a fleet's storage helpers were canonicals
        // only rather than "any conferred server helps".
        assert_eq!(
            resolve_serve_tier(dir, &served, &resolver)
                .await
                .unwrap_or_else(|e| panic!("({suffix}) resolve served: {e}")),
            ServeTier::MeshServer,
            "({suffix}) #788: an owner-conferred node that claims infra:serve is \
             a mesh server"
        );

        // (2) Conferred but NOT claimed ⇒ None. The owner offering the
        // capability is not the operator taking it up.
        assert_eq!(
            resolve_serve_tier(dir, &unclaimed, &resolver)
                .await
                .unwrap_or_else(|e| panic!("({suffix}) resolve unclaimed: {e}")),
            ServeTier::None,
            "({suffix}) #788: an owner may confer serve standing, but a node \
             that does not claim it is not serving"
        );

        // (3) Claimed but NOT conferred ⇒ None. The AV-75 property: the string
        // is free, so it must buy nothing on its own. `orphan` claims it and
        // has no owner-binding at all.
        assert_eq!(
            resolve_serve_tier(dir, &orphan, &resolver)
                .await
                .unwrap_or_else(|e| panic!("({suffix}) resolve orphan: {e}")),
            ServeTier::None,
            "({suffix}) #788: a self-asserted infra:serve with no owner \
             conferral confers nothing — claiming is VISIBILITY, never \
             conferral (v19.0.0)"
        );

        // (3b) OWNED, and the owner granted something else — still None.
        //
        // This is the case (3) cannot reach: `orphan` has no owner at all, so
        // it returns early at `owner_of` and never exercises the grant check.
        // A mutation that dropped the grant requirement entirely SURVIVED the
        // first draft of this witness for exactly that reason. The scope on
        // the binding is what must carry serve standing, so a binding bearing
        // only `infra:network_presence` must confer none of it.
        let owned_no_serve = format!("owned-ns-788-{suffix}");
        register_identity_key(dir, &owned_no_serve, "node,infra:serve").await;
        let id = uuid::Uuid::new_v4().to_string();
        let mut binding = bare_attestation(
            &id,
            &owner,
            &owned_no_serve,
            &serde_json::json!({
                "id": id,
                "kind": "delegates_to",
                "dimension": owner_binding::DIMENSION,
                "delegation_purpose": owner_binding::PURPOSE,
                "scope": [ds::INFRA_NETWORK_PRESENCE],
            }),
        );
        binding.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        seal_row_in_place(&owner, &mut binding);
        dir.put_attestation(crate::federation::SignedAttestation {
            attestation: binding,
        })
        .await
        .unwrap_or_else(|e| panic!("({suffix}) put presence-only binding: {e}"));

        assert_eq!(
            resolve_serve_tier(dir, &owned_no_serve, &resolver)
                .await
                .unwrap_or_else(|e| panic!("({suffix}) resolve owned_no_serve: {e}")),
            ServeTier::None,
            "({suffix}) #788: an owner-binding that does NOT bear infra:serve \
             confers no serve standing, however loudly the node claims it — \
             the SCOPE on the grant is the conferral, not the binding's \
             existence"
        );

        // (3d) A grant whose ENVELOPE `valid_until` has lapsed confers nothing,
        // even though the row's own `expires_at` is unset.
        //
        // #788 review: the authoritative owner-binding fold rejects a lapsed
        // envelope `valid_until`; this resolver checked only the row column,
        // so the two reads of "is this grant live" disagreed and the resolver
        // kept reporting `MeshServer` after the serve grant had ended. Written
        // with `expires_at` deliberately ABSENT so the envelope field is the
        // only thing that can refuse it — a mutation removing the envelope
        // check survives any fixture where the row column would also refuse.
        // TWO bindings, which is what makes this reachable at all. A single
        // lapsed binding is invisible to the defect: `owner_of` applies the
        // same liveness rule, so the node would have NO owner and the resolver
        // would return early without ever consulting the grant. The reviewer's
        // scenario is an owner REFRESH — a live binding keeps ownership
        // resolvable while an older serve grant has lapsed underneath it.
        let lapsed_node = format!("lapsed-788-{suffix}");
        register_identity_key(dir, &lapsed_node, "node,infra:serve").await;
        for (scope, valid_until) in [
            // The lapsed serve grant.
            (ds::INFRA_SERVE, Some("2020-01-01T00:00:00Z")),
            // The refresh: live, and deliberately NOT bearing infra:serve, so
            // ownership resolves while no live grant carries serve standing.
            (ds::INFRA_NETWORK_PRESENCE, None),
        ] {
            let id = uuid::Uuid::new_v4().to_string();
            let mut env = serde_json::json!({
                "id": id,
                "kind": "delegates_to",
                "dimension": owner_binding::DIMENSION,
                "delegation_purpose": owner_binding::PURPOSE,
                "scope": [scope],
            });
            if let Some(vu) = valid_until {
                env["valid_until"] = serde_json::Value::from(vu);
            }
            let mut binding = bare_attestation(&id, &owner, &lapsed_node, &env);
            binding.attestation_type = attestation_type::DELEGATES_TO.to_owned();
            binding.expires_at = None;
            seal_row_in_place(&owner, &mut binding);
            dir.put_attestation(crate::federation::SignedAttestation {
                attestation: binding,
            })
            .await
            .unwrap_or_else(|e| panic!("({suffix}) put binding: {e}"));
        }

        // Ownership still resolves — the refresh keeps it live. If this ever
        // returns None the case below is vacuous, so it is asserted rather
        // than assumed.
        assert_eq!(
            crate::federation::admission::owner_of(dir, &lapsed_node)
                .await
                .unwrap_or_else(|e| panic!("({suffix}) owner_of lapsed_node: {e}"))
                .as_deref(),
            Some(owner.as_str()),
            "({suffix}) the refresh binding must keep ownership resolvable, or \
             this case cannot reach the grant check it exists to test"
        );

        assert_eq!(
            resolve_serve_tier(dir, &lapsed_node, &resolver)
                .await
                .unwrap_or_else(|e| panic!("({suffix}) resolve lapsed: {e}")),
            ServeTier::None,
            "({suffix}) #788: a grant whose envelope `valid_until` has lapsed \
             is not live — checking only the row's `expires_at` makes this \
             resolver disagree with the authoritative owner-binding fold and \
             keep serving standing that has ended"
        );

        // (3e) An EXPIRED KEY holds no rung, however live its grants.
        //
        // #788 review (post-merge): `lookup_public_key` still returns a row
        // whose `valid_until` has passed, so a node whose KEY expired while
        // its owner binding and serve grant stayed live kept resolving
        // `MeshServer`. Built with a live conferral on purpose — the whole
        // point is that the grant outlasting the identity must not keep the
        // identity serving.
        let expired_node = format!("expired-788-{suffix}");
        dir.put_public_key(crate::federation::SignedKeyRecord {
            record: expired_key_record(
                &expired_node,
                "node,infra:serve",
                &expired_node,
                "expired-788",
                chrono::Utc::now() - chrono::Duration::hours(1),
            ),
        })
        .await
        .unwrap_or_else(|e| panic!("({suffix}) register expired key: {e}"));
        let id = uuid::Uuid::new_v4().to_string();
        let mut binding = bare_attestation(
            &id,
            &owner,
            &expired_node,
            &serde_json::json!({
                "id": id,
                "kind": "delegates_to",
                "dimension": owner_binding::DIMENSION,
                "delegation_purpose": owner_binding::PURPOSE,
                "scope": [ds::INFRA_SERVE],
            }),
        );
        binding.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        seal_row_in_place(&owner, &mut binding);
        dir.put_attestation(crate::federation::SignedAttestation {
            attestation: binding,
        })
        .await
        .unwrap_or_else(|e| panic!("({suffix}) put binding for expired node: {e}"));

        assert_eq!(
            resolve_serve_tier(dir, &expired_node, &resolver)
                .await
                .unwrap_or_else(|e| panic!("({suffix}) resolve expired: {e}")),
            ServeTier::None,
            "({suffix}) #788: a key whose own `valid_until` has passed holds no \
             serve rung, however live the conferral — a grant is authority \
             ABOUT a key, not a reason to keep honouring one whose validity \
             window has closed"
        );

        // (3c) A NON-NODE subject gets no serve standing, however conferred.
        //
        // #788 review: `infra:serve` is server-class, both rungs are defined
        // over a node, and nothing downstream re-checks it. Without this an
        // owner-bound AGENT key that self-claims the role would be handed
        // `MeshServer`, and a consumer using the tier as the trace serve gate
        // would authorize an agent key to serve. Same owner, same binding,
        // same claim as the passing case above — only the identity class
        // differs, so this isolates exactly that.
        let agent_claiming = format!("agent-serve-788-{suffix}");
        register_identity_key(dir, &agent_claiming, "agent,infra:serve").await;
        let id = uuid::Uuid::new_v4().to_string();
        let mut binding = bare_attestation(
            &id,
            &owner,
            &agent_claiming,
            &serde_json::json!({
                "id": id,
                "kind": "delegates_to",
                "dimension": owner_binding::DIMENSION,
                "delegation_purpose": owner_binding::PURPOSE,
                "scope": [ds::INFRA_SERVE],
            }),
        );
        binding.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        seal_row_in_place(&owner, &mut binding);
        dir.put_attestation(crate::federation::SignedAttestation {
            attestation: binding,
        })
        .await
        .unwrap_or_else(|e| panic!("({suffix}) put agent binding: {e}"));

        assert_eq!(
            resolve_serve_tier(dir, &agent_claiming, &resolver)
                .await
                .unwrap_or_else(|e| panic!("({suffix}) resolve agent: {e}")),
            ServeTier::None,
            "({suffix}) #788: infra:serve is SERVER-CLASS — an agent key with \
             a real owner conferral and a real claim still has no serve \
             standing, or the tier authorizes an agent to serve traces"
        );

        // (4) An unknown subject is absence, not an error: the lookup SUCCEEDED
        // and reported nothing. The distinction is the whole Exhibit-C contract
        // — see the ordering assertion below.
        assert_eq!(
            resolve_serve_tier(dir, &format!("ghost-788-{suffix}"), &resolver)
                .await
                .unwrap_or_else(|e| panic!("({suffix}) resolve ghost: {e}")),
            ServeTier::None,
            "({suffix}) #788: a key with no row has no serve standing"
        );

        // (5) The ladder is ORDERED, and consumers gate on `>=`. Spelled as a
        // comparison rather than three equalities because that is how the
        // consumer will use it, and an ordering that silently changed would
        // otherwise only show up at their call site.
        assert!(
            ServeTier::Canonical > ServeTier::MeshServer && ServeTier::MeshServer > ServeTier::None,
            "({suffix}) #788: the rungs must stay ordered least-to-most — \
             `tier >= MeshServer` is the shape edge gates on"
        );
    }

    /// v38.3.0 (CIRISPersist#765 + #764) — **a node speaks for its owner**:
    /// the exact shape CIRISServer's two-node chat ladder refused forever at
    /// v38.2's community door.
    ///
    /// The writer is a NODE whose identity-occurrence row is self-referential
    /// (the CIRISServer#454 sealing shape), so the occurrence axis resolves
    /// it to itself and it is a member of nothing. Its authority lives on
    /// the live `delegates_to(owner → node)` OWNER-BINDING (CC 1.13.3.3),
    /// which v38.2 never walked — the membership refusal was labelled
    /// TRANSIENT (`retry_after_community_roster`) but could never
    /// transition, because the roster's members are persons.
    ///
    /// Arms: the binding resolves BOTH directions (`owner_of` /
    /// `nodes_owned_by`, #764); the bound node's on-behalf community row
    /// LANDS node-signed; an unbound node refuses; a WITHDRAWN binding
    /// stops lifting (liveness is `owner_of`'s one fold, #578/#584); the
    /// bound node naming a THIRD person still refuses (the principal
    /// equivalence widens to the owner, never past it).
    pub(crate) async fn exercise_node_speaks_for_owner(
        dir: &dyn crate::federation::FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::types::{
            attestation_type, cohort_scope, delegation_scope as ds, owner_binding,
        };

        let owner = format!("owner-765-{suffix}");
        let node = format!("node-765-{suffix}");
        let stranger_node = format!("lone-node-765-{suffix}");
        let third = format!("third-765-{suffix}");
        let cid = format!("pair-765-{suffix}");
        register_user_role_key(dir, &owner).await;
        register_user_role_key(dir, &third).await;
        for k in [&node, &stranger_node, &cid] {
            register_hybrid_key(dir, k).await;
        }
        seed_two_member_community(dir, &cid, &owner, &owner).await;

        // The owner-binding: delegates_to(owner → node), the CC 1.13.3.3
        // ownership dimension, sealed by the OWNER, through the real door.
        let binding_id = uuid::Uuid::new_v4().to_string();
        let mut binding = bare_attestation(
            &binding_id,
            &owner,
            &node,
            &serde_json::json!({
                "id": binding_id,
                "kind": "delegates_to",
                "dimension": owner_binding::DIMENSION,
                "delegation_purpose": owner_binding::PURPOSE,
                "scope": [ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
            }),
        );
        binding.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        seal_row_in_place(&owner, &mut binding);
        dir.put_attestation(crate::federation::SignedAttestation {
            attestation: binding,
        })
        .await
        .unwrap_or_else(|e| panic!("({suffix}) put owner-binding: {e}"));

        // (1) BOTH directions resolve through the one fold (#764).
        assert_eq!(
            crate::federation::admission::owner_of(dir, &node)
                .await
                .unwrap()
                .as_deref(),
            Some(owner.as_str()),
            "({suffix}) owner_of walks the binding"
        );
        assert_eq!(
            crate::federation::admission::nodes_owned_by(dir, &owner)
                .await
                .unwrap(),
            vec![node.clone()],
            "({suffix}) #764: nodes_owned_by is owner_of's exact reverse"
        );

        // The on-behalf chat row: node-signed, about the owner, into the
        // owner's pair community.
        let chat_row = |producer: &str, about: &str| {
            let id = uuid::Uuid::new_v4().to_string();
            let mut r = bare_attestation(
                &id,
                producer,
                about,
                &serde_json::json!({
                    "id": id,
                    "dimension": "chat:message:v1",
                    "community_id": cid,
                    "on_behalf_of_key_id": about,
                }),
            );
            r.attestation_type = attestation_type::SCORES.to_owned();
            r.cohort_scope = cohort_scope::COMMUNITY.to_owned();
            r.subject_key_ids = vec![about.to_owned()];
            seal_row_in_place(producer, &mut r);
            r
        };

        // (2) THE LADDER ARM — the bound node's on-behalf row LANDS,
        // node-signed (authorship survives; attribution rides the envelope).
        dir.put_attestation(crate::federation::SignedAttestation {
            attestation: chat_row(&node, &owner),
        })
        .await
        .unwrap_or_else(|e| {
            panic!(
                "({suffix}) #765: the bound node's on-behalf community row must land — \
                 this is the refusal CIRISServer's ladder measured as a transient that \
                 never transitions: {e}"
            )
        });

        // (3) An UNBOUND node is nobody's principal — refused.
        assert!(
            dir.put_attestation(crate::federation::SignedAttestation {
                attestation: chat_row(&stranger_node, &owner),
            })
            .await
            .is_err(),
            "({suffix}) #765: an unbound node must not inherit anyone's membership"
        );

        // (4) The bound node naming a THIRD person refuses — the principal
        // equivalence class widens to the OWNER, never past it.
        assert!(
            dir.put_attestation(crate::federation::SignedAttestation {
                attestation: chat_row(&node, &third),
            })
            .await
            .is_err(),
            "({suffix}) #765: on-behalf covers the PRINCIPAL only — a third party is \
             still a third party"
        );

        // (5) A WITHDRAWN binding stops lifting — liveness is owner_of's one
        // fold, so the walk dies the moment the binding does.
        put_retraction(dir, &owner, &node, &binding_id, "withdraws")
            .await
            .unwrap_or_else(|e| panic!("({suffix}) withdraw the binding: {e}"));
        assert!(
            crate::federation::admission::nodes_owned_by(dir, &owner)
                .await
                .unwrap()
                .is_empty(),
            "({suffix}) #764: a withdrawn binding leaves the reverse walk empty"
        );
        assert!(
            dir.put_attestation(crate::federation::SignedAttestation {
                attestation: chat_row(&node, &owner),
            })
            .await
            .is_err(),
            "({suffix}) #765: a withdrawn owner-binding must stop lifting the node — \
             a decommissioned instrument keeps nothing"
        );
    }

    /// v38.2.0 — register `key_id` with real hybrid pubkeys as a USER-role
    /// identity, so it steward-binds ITSELF (clause 1 of
    /// `steward_bindings_of`). Non-infrastructure community membership is an
    /// authority act (CC 3.2 / CC 3.4.7.1) and the members of a chat are
    /// people; [`register_hybrid_key`] mints `agent`, which those gates
    /// correctly refuse.
    pub(crate) async fn register_user_role_key(
        dir: &dyn crate::federation::FederationDirectory,
        key_id: &str,
    ) {
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        let now = {
            use chrono::Timelike as _;
            let dt = chrono::Utc::now();
            dt.with_nanosecond(dt.nanosecond() / 1_000 * 1_000)
                .unwrap_or(dt)
        };
        let rec = crate::federation::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: crate::federation::types::identity_type::USER.to_owned(),
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
            .expect("register user-role key");
    }

    /// v38.2.0 — seed a community authored by its first member.
    pub(crate) async fn seed_two_member_community(
        dir: &dyn crate::federation::FederationDirectory,
        community_key_id: &str,
        member_a: &str,
        member_b: &str,
    ) {
        let member = |k: &str| crate::federation::types::CommunityMember {
            key_id: k.to_owned(),
            joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            role: Some("founder".into()),
        };
        let mut members = vec![member(member_a)];
        if member_b != member_a {
            members.push(member(member_b));
        }
        dir.put_community(sign_community(
            member_a,
            crate::federation::types::Community {
                community_key_id: community_key_id.to_owned(),
                community_name: "chat-pair".to_owned(),
                members,
                founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                consensus_protocol: crate::federation::types::consensus_protocol::UNANIMOUS.into(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("seed community");
    }

    /// v38.2.0 (CIRISPersist#758) — **the convergent-community re-put,
    /// asserted identically on every backend.**
    ///
    /// This defect WAS a backend divergence, so a one-backend witness would
    /// have proven nothing: sqlite and postgres refused every re-put with a
    /// PK error, while memory silently OVERWROTE the stored row and its
    /// authority signature. The three arms below are the three distinct
    /// facts — first write lands, identical re-put by a DIFFERENT authority
    /// is an idempotent no-op that does not disturb the stored row, and a
    /// DIFFERING roster under the same id is refused.
    pub(crate) async fn exercise_convergent_community_reput(
        dir: &dyn crate::federation::FederationDirectory,
        suffix: &str,
    ) {
        let cid = format!("chat-pair-758-{suffix}");
        let alice = format!("alice-758-{suffix}");
        let bob = format!("bob-758-{suffix}");
        register_hybrid_key(dir, &cid).await;
        // The members are USER-role from the START (a re-register with
        // different content is correctly refused), so they steward-bind
        // THEMSELVES via clause 1 of `steward_bindings_of` — non-infrastructure
        // community membership is an authority act (CC 3.2 / CC 3.4.7.1), and
        // the pair-chat members are people.
        for k in [&alice, &bob] {
            register_user_role_key(dir, k).await;
        }

        // Both ends DERIVE the same community from the same member pair, so
        // the content is byte-identical; only the signer differs.
        let derived = |name: &str| crate::federation::types::Community {
            community_key_id: cid.clone(),
            community_name: name.to_owned(),
            members: vec![
                crate::federation::types::CommunityMember {
                    key_id: alice.clone(),
                    joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                    role: Some("founder".into()),
                },
                crate::federation::types::CommunityMember {
                    key_id: bob.clone(),
                    joined_at: "2026-05-01T00:00:00Z".parse().unwrap(),
                    role: Some("founder".into()),
                },
            ],
            founded_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            consensus_protocol: crate::federation::types::consensus_protocol::UNANIMOUS.into(),
            policy_blob: None,
            persist_row_hash: String::new(),
        };

        // (1) Alice's end authors it.
        dir.put_community(sign_community(&alice, derived("pair-chat")))
            .await
            .unwrap_or_else(|e| panic!("({suffix}) the first author must land: {e}"));

        // (2) Bob's end replicates the IDENTICAL content, signed as itself.
        // Refusing this is refusing convergence; overwriting is worse.
        dir.put_community(sign_community(&bob, derived("pair-chat")))
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "({suffix}) #758: a convergent re-put of byte-identical content must be an \
                     idempotent no-op — the far side can never accept a peer's copy otherwise: {e}"
                )
            });

        // …and it did not DISTURB the stored row: the first-accepted
        // authority survives (memory used to replace it wholesale).
        let served = dir
            .list_signed_communities_since(None, u32::MAX)
            .await
            .expect("serve communities");
        let stored = served
            .iter()
            .find(|c| c.community.community.community_key_id == cid)
            .unwrap_or_else(|| panic!("({suffix}) the community must still be served"));
        assert_eq!(
            stored.community.authority_key_id, alice,
            "({suffix}) #758: the no-op must not replace the first-accepted authority"
        );
        assert_eq!(
            stored.community.community.members.len(),
            2,
            "({suffix}) the stored roster is untouched"
        );

        // (3) A DIFFERING roster under the same id is a real disagreement.
        let err = dir
            .put_community(sign_community(&bob, derived("a-different-community")))
            .await
            .err()
            .unwrap_or_else(|| {
                panic!(
                    "({suffix}) #758: differing content under an occupied community id must be \
                     REFUSED — accepting it silently is what `DO NOTHING` alone would have done"
                )
            });
        assert_eq!(
            err.kind(),
            "federation_conflict",
            "({suffix}) the refusal is a typed Conflict: {err}"
        );
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

    /// v37.0.0 (CIRISPersist#734) — a `delegates_to(granter → grantee)` really
    /// signed by `granter`, put through the REAL `put_attestation` door.
    /// `expires_at` is stamped BEFORE the seal (it is bound in both directions
    /// since #598, so setting the column afterwards is the divergence the gate
    /// refuses).
    async fn put_delegates_to<D: crate::federation::FederationDirectory + ?Sized>(
        dir: &D,
        granter: &str,
        grantee: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<String, crate::federation::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "references_attestation_id": id,
            "scope": ["act_on_behalf"],
        });
        let mut row = bare_attestation(&id, granter, grantee, &envelope);
        row.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.to_owned();
        row.expires_at = expires_at;
        seal_row_in_place(granter, &mut row);
        dir.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await?;
        Ok(id)
    }

    /// v37.0.0 (CIRISPersist#734) — retract `target_id` with a `withdraws` /
    /// `recants` composer authored by `granter` (the §6.1 / CEG §3.2.3 act).
    async fn put_retraction<D: crate::federation::FederationDirectory + ?Sized>(
        dir: &D,
        granter: &str,
        grantee: &str,
        target_id: &str,
        verb: &str,
    ) -> Result<(), crate::federation::Error> {
        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id,
            "references_attestation_id": target_id,
        });
        let mut row = bare_attestation(&id, granter, grantee, &envelope);
        row.attestation_type = verb.to_owned();
        seal_row_in_place(granter, &mut row);
        dir.put_attestation(crate::federation::SignedAttestation { attestation: row })
            .await
            .map(|_| ())
    }

    /// The unsealed skeleton [`put_delegates_to`] / [`put_retraction`] share.
    fn bare_attestation(
        id: &str,
        attester: &str,
        attested: &str,
        envelope: &serde_json::Value,
    ) -> Attestation {
        let now = chrono::Utc::now();
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: attester.to_owned(),
            attested_key_id: attested.to_owned(),
            attestation_type: String::new(),
            weight: Some(1.0),
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope.clone(),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            // Federation tier on purpose: the edge these witnesses build must
            // pass the same PQC-mandatory ingest gate a replicated one does. A
            // `local` row would skip it and the fixture would certify a
            // placement no peer accepts.
            tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// A resolution-7 location proof for `subject` at `asserted_at`. The cell
    /// is a fixed point in the Pacific; §0.8.1 caps admitted resolution at 7,
    /// so 7 is the finest a real producer may claim.
    fn location_proof_at(
        subject: &str,
        asserted_at: &str,
    ) -> crate::federation::types::LocationProof {
        let ll = h3o::LatLng::new(37.0, -122.0).expect("valid latlng");
        crate::federation::types::LocationProof {
            subject_key_id: subject.to_owned(),
            cell_id: ll.to_cell(h3o::Resolution::Seven).to_string(),
            cell_resolution: 7,
            asserted_at: asserted_at.parse().expect("rfc3339"),
            valid_until: None,
            attestation_evidence: None,
            withdrawn_at: None,
            persist_row_hash: String::new(),
        }
    }

    /// Unwrap the [`Error::LocationAuthorityUnauthorized`] fields, or panic
    /// naming what came back instead. Deliberately NOT tolerant of a
    /// neighbouring refusal: a witness that accepts "some error" cannot tell
    /// the authority gate from the signature gate one line above it, which is
    /// the entire distinction this cut is about.
    fn expect_location_authority_refusal(
        err: &crate::federation::Error,
        leg: &str,
    ) -> (String, String, &'static str) {
        match err {
            crate::federation::Error::LocationAuthorityUnauthorized {
                subject_key_id,
                offered_authority_key_id,
                rule,
            } => (
                subject_key_id.clone(),
                offered_authority_key_id.clone(),
                rule,
            ),
            other => panic!(
                "({leg}) expected LocationAuthorityUnauthorized, got {:?} ({other})",
                other.kind()
            ),
        }
    }

    /// **CIRISPersist#734 — WHOSE key may assert a location, on any backend.**
    ///
    /// The hole: E4 verified that the scrub signature matched
    /// `authority_key_id`'s registered pubkeys and stopped, so any registered
    /// key in the federation could assert a location for any subject and get a
    /// valid, admitted, wrong row. The rule that closes it is the operator's:
    /// *"the key is the subject itself or its delegates, no one else could know
    /// where the subject is."*
    ///
    /// | # | witness | what it pins |
    /// |---|---|---|
    /// | a | subject signs its own proof ⇒ ADMITTED | the ordinary case still works; the gate is not a wall |
    /// | b | a LIVE delegate signs ⇒ ADMITTED | the delegation leg is reachable, not decorative |
    /// | c | a REGISTERED third party with a VALID signature ⇒ REFUSED | **the hole.** Not "unregistered keys fail" — E4 already covered that |
    /// | d | the refused row is NOT stored | verify-before-mutation (AV-9) |
    /// | e | `withdraws` on the delegation ⇒ REFUSED, `..._retracted` | liveness clause (2)/(3), and the token is a VERDICT |
    /// | f | `recants` on the delegation ⇒ REFUSED, `..._retracted` | the two retraction verbs are wire-distinct and both kill |
    /// | g | expired delegation ⇒ REFUSED, `..._expired` | liveness clause (4) |
    /// | h | proof BEFORE its `delegates_to` ⇒ `..._no_delegation_edge`, then the SAME proof ADMITS once the edge lands | the out-of-order answer: the refusal is transient and the token says so |
    ///
    /// Leg (c) is the one that has to be built carefully. The third party is
    /// registered through the same `register_hybrid_key` every other key uses
    /// and signs with its own real deterministic keypair, so its signature
    /// genuinely verifies at the leg above — the refusal can only come from the
    /// authority leg. A witness that seeded an unregistered key would prove
    /// only that `SignatureInvalid` still fires.
    ///
    /// Legs (e)/(f)/(g) assert the `rule` TOKEN, not merely that a refusal
    /// occurred. The token is the caller's retry signal: `..._no_delegation_edge`
    /// may be a delivery-order artifact and is worth retrying, the other two are
    /// verdicts. A witness blind to which token came back would pass under a gate
    /// that reported every refusal as retryable, which is the same-outcome-through-
    /// the-wrong-mechanism shape.
    ///
    /// `tag` must be ≤ ~20 chars and is placed AFTER the distinguishing prefix
    /// on every key id: [`seed_for`] truncates at 32 bytes, so two ids sharing a
    /// 32-byte prefix are the SAME identity here.
    pub async fn exercise_location_proof_authority<D>(
        dir: &D,
        tag: &str,
    ) -> Result<(), crate::federation::Error>
    where
        D: crate::federation::FederationDirectory + ?Sized,
    {
        use crate::federation::types::attestation_type;

        let subject = format!("subj-{tag}");
        let delegate = format!("dlg-{tag}");
        let third = format!("third-{tag}");
        let withdrawn = format!("wdlg-{tag}");
        let recanted = format!("rdlg-{tag}");
        let expired = format!("xdlg-{tag}");
        let late = format!("late-{tag}");
        for k in [
            &subject, &delegate, &third, &withdrawn, &recanted, &expired, &late,
        ] {
            register_hybrid_key(dir, k).await;
        }
        // The fixture's own precondition: seven DISTINCT identities. If two
        // collided under the 32-byte seed truncation, legs (b) and (c) would be
        // the same key and (c) would pass for the wrong reason.
        assert_ne!(
            hybrid_pubkeys(&delegate),
            hybrid_pubkeys(&third),
            "({tag}) the delegate and the third party must be DIFFERENT identities \
             — `seed_for` truncates at 32 bytes"
        );

        // ── (a) the subject speaks about itself.
        dir.put_location_proof(sign_location_proof(
            &subject,
            location_proof_at(&subject, "2026-06-09T00:00:00Z"),
        ))
        .await
        .unwrap_or_else(|e| panic!("({tag}) (a) the subject may assert its OWN location: {e}"));

        // ── (b) a live delegate speaks for it.
        put_delegates_to(dir, &subject, &delegate, None).await?;
        dir.put_location_proof(sign_location_proof(
            &delegate,
            location_proof_at(&subject, "2026-06-09T01:00:00Z"),
        ))
        .await
        .unwrap_or_else(|e| {
            panic!(
                "({tag}) (b) a LIVE delegate may assert the subject's \
                                    location: {e}"
            )
        });

        // ── (c) THE HOLE. A registered third party, a valid signature, no
        //        delegation. Admitted before this cut.
        assert!(
            dir.lookup_public_key(&third).await?.is_some(),
            "({tag}) (c) the third party must be genuinely REGISTERED, or this leg \
             only re-proves that unregistered keys fail (which E4 already closed)"
        );
        let third_proof =
            sign_location_proof(&third, location_proof_at(&subject, "2026-06-09T02:00:00Z"));
        let err = dir
            .put_location_proof(third_proof)
            .await
            .expect_err("(c) a third party must NOT be able to assert where the subject is");
        let (got_subject, got_authority, got_rule) = expect_location_authority_refusal(&err, "c");
        assert_eq!(
            got_subject, subject,
            "({tag}) (c) the refusal must NAME the subject whose location was asserted"
        );
        assert_eq!(
            got_authority, third,
            "({tag}) (c) the refusal must NAME the authority that was offered"
        );
        assert_eq!(
            got_rule, "location_authority_no_delegation_edge",
            "({tag}) (c) a third party with no edge at all gets the ABSENT token"
        );
        assert_eq!(
            err.kind(),
            "federation_location_authority_unauthorized",
            "({tag}) (c) the stable wire token"
        );

        // ── (d) verify-before-mutation: nothing was written.
        let stored = dir.list_location_proofs_for(&subject).await?;
        assert_eq!(
            stored.len(),
            2,
            "({tag}) (d) exactly the two ADMITTED proofs are stored — the refused \
             third-party row must not be present: {stored:?}"
        );

        // ── (e) a WITHDRAWN delegation confers nothing.
        let w_edge = put_delegates_to(dir, &subject, &withdrawn, None).await?;
        put_retraction(
            dir,
            &subject,
            &withdrawn,
            &w_edge,
            attestation_type::WITHDRAWS,
        )
        .await?;
        let err = dir
            .put_location_proof(sign_location_proof(
                &withdrawn,
                location_proof_at(&subject, "2026-06-09T03:00:00Z"),
            ))
            .await
            .expect_err("(e) a withdrawn delegation must not confer authority");
        let (_, _, rule) = expect_location_authority_refusal(&err, "e");
        assert_eq!(
            rule, "location_authority_delegation_retracted",
            "({tag}) (e) a retracted edge is a VERDICT, never the retryable \
             absent-edge token"
        );

        // ── (f) `recants` is the other retraction verb and must kill too.
        let r_edge = put_delegates_to(dir, &subject, &recanted, None).await?;
        put_retraction(dir, &subject, &recanted, &r_edge, attestation_type::RECANTS).await?;
        let err = dir
            .put_location_proof(sign_location_proof(
                &recanted,
                location_proof_at(&subject, "2026-06-09T04:00:00Z"),
            ))
            .await
            .expect_err("(f) a recanted delegation must not confer authority");
        let (_, _, rule) = expect_location_authority_refusal(&err, "f");
        assert_eq!(
            rule, "location_authority_delegation_retracted",
            "({tag}) (f) `recants` and `withdraws` are wire-distinct and BOTH kill"
        );

        // ── (g) an EXPIRED delegation confers nothing.
        put_delegates_to(
            dir,
            &subject,
            &expired,
            Some(chrono::Utc::now() - chrono::Duration::hours(1)),
        )
        .await?;
        let err = dir
            .put_location_proof(sign_location_proof(
                &expired,
                location_proof_at(&subject, "2026-06-09T05:00:00Z"),
            ))
            .await
            .expect_err("(g) a lapsed delegation must not confer authority");
        let (_, _, rule) = expect_location_authority_refusal(&err, "g");
        assert_eq!(
            rule, "location_authority_delegation_expired",
            "({tag}) (g) a lapsed edge is a VERDICT, never the retryable \
             absent-edge token"
        );

        // ── (h) THE OUT-OF-ORDER LEG. A legitimate delegate's proof arrives
        //        BEFORE the `delegates_to` that authorizes it. Persist holds no
        //        deferral queue for location proofs, so the row is refused and
        //        dropped — but the refusal carries the RETRYABLE token, and the
        //        byte-identical proof is admitted once the edge lands. That is
        //        the whole contract: persist does not retry for you, and it
        //        tells you that retrying is worth it.
        let late_proof =
            sign_location_proof(&late, location_proof_at(&subject, "2026-06-09T06:00:00Z"));
        let err = dir
            .put_location_proof(late_proof.clone())
            .await
            .expect_err("(h) the authorizing edge has not arrived yet");
        let (_, _, rule) = expect_location_authority_refusal(&err, "h");
        assert_eq!(
            rule, "location_authority_no_delegation_edge",
            "({tag}) (h) an authorizer that has NOT ARRIVED must be reported as \
             absent — this token is the caller's signal that a retry is worth \
             making, and reporting a verdict here is how a legitimate row gets \
             permanently dropped"
        );
        put_delegates_to(dir, &subject, &late, None).await?;
        dir.put_location_proof(late_proof)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "({tag}) (h) the SAME proof must be admitted once \
                                        the authorizing edge lands — the refusal above is \
                                        transient, not a verdict: {e}"
                )
            });
        Ok(())
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
    /// CIRISPersist#788 — a record whose key validity window has CLOSED.
    ///
    /// `valid_until` has been a BOUND subject member since #750, so it cannot
    /// be set by mutating a minted record: the envelope binds it and the
    /// subject-binding gate refuses the mismatch. It has to be bound at mint
    /// time, and nothing in test-support could do that — which is why the
    /// serve-tier resolver shipped without noticing it never checked the
    /// subject key's own expiry.
    pub fn expired_key_record(
        key_id: &str,
        identity_type: &str,
        signer_key_id: &str,
        nonce: &str,
        valid_until: chrono::DateTime<chrono::Utc>,
    ) -> crate::federation::KeyRecord {
        let mut rec = replicated_key_record_with_expiry(
            key_id,
            identity_type,
            key_id,
            signer_key_id,
            nonce,
            Some(valid_until),
        );
        rec.valid_until = Some(valid_until);
        rec
    }

    /// The expiry-parameterised core of [`replicated_key_record`].
    pub fn replicated_key_record_with_expiry(
        key_id: &str,
        identity_type: &str,
        scrub_key_id: &str,
        signer_key_id: &str,
        nonce: &str,
        valid_until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> crate::federation::KeyRecord {
        let vu = valid_until.map(|t| t.to_rfc3339());
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        let mut envelope = serde_json::json!({
            "key_id": key_id,
            "purpose": "federation-peering",
            "nonce": nonce,
        });
        crate::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            key_id,
            identity_type,
            &ed_pk,
            mldsa_pk.as_deref(),
            vu.as_deref(),
        )
        .expect("bind the #659 subject into the registration envelope");
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
            valid_until,
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
    ///
    /// # v31.0.0 (CIRISPersist#659) — the subject is BOUND
    ///
    /// The envelope is stamped with `key_id`, `identity_type` and BOTH of the
    /// subject's pubkeys through the one shared
    /// [`crate::federation::admission::bind_subject_into_envelope`] before it is
    /// canonicalized and signed, so every record this helper builds satisfies
    /// `verify_key_registration`'s subject-binding gate by construction. This
    /// is a **preimage change** — the signed bytes differ from pre-#659 — but
    /// not a signature change: the subject's pubkeys are already derived here
    /// from `key_id`, so no call site moves.
    pub fn replicated_key_record(
        key_id: &str,
        identity_type: &str,
        scrub_key_id: &str,
        signer_key_id: &str,
        nonce: &str,
    ) -> crate::federation::KeyRecord {
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        let mut envelope = serde_json::json!({
            "key_id": key_id,
            "purpose": "federation-peering",
            "nonce": nonce,
        });
        crate::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            key_id,
            identity_type,
            &ed_pk,
            mldsa_pk.as_deref(),
            None,
        )
        .expect("bind the #659 subject into the registration envelope");
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
        seal_row(
            owner,
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
                additional_scrubs: Vec::new(),
            },
        )
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
        let mut sealed_row_ = Attestation {
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
            additional_scrubs: Vec::new(),
        };
        crate::federation::tier_ingest::test_support::seal_row_in_place(attester, &mut sealed_row_);
        crate::federation::tier_ingest::test_support::reseal(&mut sealed_row_);
        sealed_row_
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
    #[serial_test::serial(postgres)]
    async fn tier_ingest_matrix_postgres() {
        let Some(dsn) = crate::test_pg::dsn() else {
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
