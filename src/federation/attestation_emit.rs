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

/// v30.13.0 (CIRISPersist#598) — **stamp the row instants INTO the envelope,
/// then canonicalize it.** Every emit entry point calls THIS, not
/// [`canonicalize`], so there is no longer a canonicalize step that can be
/// reached with an unstamped envelope.
///
/// # The ordering defect this closes
///
/// The recipe used to be `canonicalize → hash → sign → assemble`, and
/// `assemble` sampled its OWN `chrono::Utc::now()` for `asserted_at` **after**
/// the bytes were already signed. That made envelope/column equality — the
/// property [`crate::federation::admission::check_consent_state_instant_binding`]
/// demands — structurally impossible to satisfy at the mint: the two values
/// came from two different clock reads, in that order, by construction. Not a
/// missing check; a missing possibility.
///
/// So the instant is sampled ONCE, here, before the bytes exist:
///
/// - `now` is truncated to the substrate resolution
///   ([`crate::federation::admission::truncate_to_substrate_resolution`]) so a
///   persist-minted row can never trip the sub-microsecond refusal that keeps
///   postgres and sqlite from disagreeing about ordering;
/// - it is written to `envelope.asserted_at` (a producer that set the field
///   ITSELF is honoured, not overwritten — that is the co-signed / staged-row
///   case, where the instant must survive being assembled later);
/// - `input.expires_at` is truncated the same way and mirrored to
///   `envelope.expires_at`, so the pair is bound in both directions.
///
/// [`assemble`] then READS both back out of the signed envelope. Signature,
/// hash and row column are three views of one instant.
///
/// # v30.13.0 (CIRISPersist#643) — and the five typed COLUMNS
///
/// The same treatment, for the same reason, applied to the columns that decide
/// what the row MEANS: `attestation_type` (the verb), `subject_key_ids` (which
/// grants revocation authority), `attested_key_id`, `cohort_scope` and
/// `weight`. They are stamped into
/// [`envelope.row`](crate::federation::envelope::RowMirror) here, before the
/// bytes exist, so
/// [`check_row_column_binding`](crate::federation::admission::check_row_column_binding)
/// is satisfiable at the mint rather than being a rule no producer could obey.
///
/// `attesting_key_id` is the signer's DERIVED federation key_id and is passed
/// in because the mirror must carry the EFFECTIVE `attested_key_id` — the
/// value [`assemble`] will place on the row, which for a self-attestation
/// (`input.attested_key_id == None`) is the signer's own id. Stamping the
/// caller's `Option` instead would bind a mirror that diverges from the row it
/// mints.
pub fn stamp_and_canonicalize(
    input: &mut EmitAttestationInput,
    attesting_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<u8>, Error> {
    use crate::federation::admission::truncate_to_substrate_resolution as trunc;
    if input.attestation_envelope.asserted_at.is_none() {
        input.attestation_envelope.asserted_at = Some(trunc(now).to_rfc3339());
    }
    input.expires_at = input.expires_at.map(trunc);
    input.attestation_envelope.expires_at = input.expires_at.map(|t| t.to_rfc3339());
    input.attestation_envelope.row = Some(crate::federation::envelope::RowMirror {
        // v30.13.0 (#643) — THE ROW ID IS MINTED HERE, before the bytes exist,
        // and [`assemble`] reads it back out. It used to be a fresh
        // `Uuid::new_v4()` sampled AFTER the signature — the same
        // sample-after-signing shape #598 found on `asserted_at`, and for the
        // same reason unbindable by construction. Minting it into the signed
        // bytes is also what makes a replay structurally impossible rather
        // than merely refused: the same envelope can only ever name one row.
        attestation_id: uuid::Uuid::new_v4().to_string(),
        attesting_key_id: attesting_key_id.to_owned(),
        attestation_type: input.attestation_type.clone(),
        attested_key_id: input
            .attested_key_id
            .clone()
            .unwrap_or_else(|| attesting_key_id.to_owned()),
        subject_key_ids: input.subject_key_ids.clone(),
        cohort_scope: input.cohort_scope.clone(),
        weight: match input.weight {
            None => None,
            Some(w) => Some(serde_json::Number::from_f64(w).ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "emit_attestation: `weight` {w} is not finite and cannot be bound into the \
                     signed envelope (CIRISPersist#643)"
                ))
            })?),
        },
    });
    canonicalize(&input.attestation_envelope.to_value())
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
    let (row, emitted) = assemble(key_id, canonical, sig, input)?;
    dir.put_attestation(SignedAttestation { attestation: row })
        .await?;
    Ok(emitted)
}

/// v30.0.0 (CIRISPersist#601 item 3 / CIRISPersist#596 item 3) — **the recipe
/// WITHOUT the put.**
///
/// Every sanctioned emit helper canonicalizes, signs, assembles **and puts**.
/// That is right for the ordinary path and wrong for two real ops, which asked
/// for it independently from two different planes:
///
/// - **A co-signed row.** A cold durable `mesh_config` under a family root needs
///   ≥m distinct seated holders' scrubs. A node cannot produce the canonical
///   bytes for co-signers without a row, and cannot make a row without storing
///   one.
/// - **A marker assembled elsewhere.** `record_quarantine_marker` takes an
///   already-signed [`Attestation`], so the one door built for tier 2 was
///   unreachable through the chokepoint built to stop hand-rolled rows.
///
/// Both consumers hand-rolled a 20-field row instead — *through* the chokepoint,
/// which is the outcome the chokepoint exists to prevent. **A gate with no
/// sanctioned path around it does not stop the traffic; it just stops seeing
/// it.**
///
/// This carries **the same two admission gates** as the put path — #293 subject
/// canonicality and #527 cohort_scope validate-never-default — because they are
/// properties of the ROW, not of storing it. A row that would be refused on the
/// way in must not become emittable by declining to store it here.
///
/// Returns the row and the [`EmittedAttestation`] summary the put path returns,
/// so a caller can assemble now and put later through the ordinary door.
pub fn assemble(
    key_id: String,
    canonical: &[u8],
    sig: ciris_crypto::HybridSignature,
    input: EmitAttestationInput,
) -> Result<(Attestation, EmittedAttestation), Error> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use sha2::{Digest, Sha256};

    super::validate_subject_key_ids(&input.subject_key_ids)?;

    let original_content_hash = hex::encode(Sha256::digest(canonical));
    // v30.13.0 (CIRISPersist#598) — THE INSTANT COMES OUT OF THE SIGNED
    // ENVELOPE. This line used to be `chrono::Utc::now()`: a SECOND clock
    // read, taken after `canonical` was already hashed and signed, so the row
    // column and the signed bytes disagreed by construction and no producer
    // could have made them agree. Reading it back out is what makes
    // `check_consent_state_instant_binding` satisfiable at all — see
    // [`stamp_and_canonicalize`], which every emit entry point goes through.
    let envelope_value = input.attestation_envelope.to_value();
    let now = {
        let raw = input
            .attestation_envelope
            .asserted_at
            .as_deref()
            .ok_or_else(|| {
                Error::InvalidArgument(
                    "emit_attestation: the envelope carries no `asserted_at` — assemble reads the \
                 row instant OUT of the signed envelope and never samples its own clock. Build \
                 the canonical bytes through `attestation_emit::stamp_and_canonicalize` \
                 (CIRISPersist#598)"
                        .into(),
                )
            })?;
        chrono::DateTime::parse_from_rfc3339(raw)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|e| {
                Error::InvalidArgument(format!(
                    "emit_attestation: envelope `asserted_at` is not RFC-3339: {e} \
                     (CIRISPersist#598)"
                ))
            })?
    };
    // The expiry column is derived from the SAME signed bytes, for the same
    // reason. A typed `expires_at` that the envelope does not carry would be
    // an unsigned expiry on a signed row — the exact divergence the binding
    // gate refuses at ingest, so it is refused at the mint too.
    let expires_at = match input.attestation_envelope.expires_at.as_deref() {
        Some(raw) => Some(
            chrono::DateTime::parse_from_rfc3339(raw)
                .map(|t| t.with_timezone(&chrono::Utc))
                .map_err(|e| {
                    Error::InvalidArgument(format!(
                        "emit_attestation: envelope `expires_at` is not RFC-3339: {e} \
                         (CIRISPersist#598)"
                    ))
                })?,
        ),
        None => None,
    };
    if expires_at != input.expires_at {
        return Err(Error::InvalidArgument(format!(
            "emit_attestation: typed `expires_at` {:?} diverges from the signed envelope's {:?} \
             (CIRISPersist#598)",
            input.expires_at.map(|t| t.to_rfc3339()),
            expires_at.map(|t| t.to_rfc3339()),
        )));
    }

    let attested_key_id = input.attested_key_id.unwrap_or_else(|| key_id.clone());
    super::admission::check_cohort_scope(&input.cohort_scope)?;
    let cohort_scope = input.cohort_scope;

    // v30.13.0 (CIRISPersist#643) — the row id comes OUT of the signed
    // envelope's mirror (see `stamp_and_canonicalize`), not from a fresh v4
    // minted after the signature existed.
    let attestation_id = input
        .attestation_envelope
        .row
        .as_ref()
        .map(|m| m.attestation_id.clone())
        .ok_or_else(|| {
            Error::InvalidArgument(
                "emit_attestation: the envelope carries no `row` mirror — assemble reads the row \
                 identity and the five typed columns OUT of the signed envelope. Build the \
                 canonical bytes through `attestation_emit::stamp_and_canonicalize` \
                 (CIRISPersist#643)"
                    .into(),
            )
        })?;
    let row = Attestation {
        attestation_id,
        attesting_key_id: key_id.clone(),
        attested_key_id,
        attestation_type: input.attestation_type,
        weight: input.weight,
        asserted_at: now,
        expires_at,
        attestation_envelope: envelope_value,
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
    // v30.13.0 (CIRISPersist#643) — the typed-column binding, asked at the
    // MINT. `put_attestation` asks it again at every door (that is where it
    // defends), but a row assembled here and put later — the co-signed
    // `mesh_config` / quarantine-marker paths `assemble`-without-put exists for
    // — should fail where it was built, naming the column, rather than at a
    // store call one layer away. Also catches an `input` whose envelope was
    // stamped for a DIFFERENT signer than the `key_id` assembling it.
    super::admission::check_row_column_binding(&row)?;
    let emitted = EmittedAttestation {
        attestation_id: row.attestation_id.clone(),
        attesting_key_id: key_id,
        is_grant_dimension: super::admission::envelope_dimension(&row.attestation_envelope)
            == Some(super::consent_grammar::GRANT_DIMENSION),
    };
    Ok((row, emitted))
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
    mut input: EmitAttestationInput,
) -> Result<EmittedAttestation, Error>
where
    D: FederationDirectory + Sync + ?Sized,
{
    let key_id = signer.derived_key_id();
    // v30.13.0 (CIRISPersist#598/#643) — stamp BEFORE signing (see
    // [`stamp_and_canonicalize`]); `assemble` then reads the instants back out
    // and `check_row_column_binding` re-checks the typed-column mirror at the
    // door.
    let canonical = stamp_and_canonicalize(&mut input, &key_id, chrono::Utc::now())?;
    let sig = signer.sign_hybrid(&canonical).await.map_err(|e| {
        Error::Backend(format!(
            "emit_attestation sign_hybrid: {e} — a conformant federation-tier emit requires a \
             hybrid (Ed25519 + ML-DSA-65) signer (CC 5.3.2.4.3.1)"
        ))
    })?;
    assemble_and_put(dir, key_id, &canonical, sig, input).await
}
