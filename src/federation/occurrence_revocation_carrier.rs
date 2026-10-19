//! v59.0.0 (CIRISPersist#1104; CC 3.1.5 rc9 `c901645`, registry pin
//! `27f6f519`, `CLM-occurrence-revocation-carrier`) — **the carrier of a
//! legacy occurrence revocation.**
//!
//! A framed, signed occurrence revocation held from before v59 (V200's
//! `legacy_framed` projection row) still revokes on the node that holds it,
//! but had no attestation row, so it could never replicate: a node added after
//! the upgrade would see the revoked occurrence as live. The carrier gives it
//! a row, `identity:occurrence_revocation:v1`, minted the way the key plane
//! mints its rows ([`super::key_plane`]):
//!
//! - attester = the revoker (the framed object's signer), attested = the
//!   identity whose occurrence it revokes;
//! - the framed object ([`FramedOccurrenceRevocation`]: signer, the exact
//!   signed envelope, its detached hybrid signature) under ONE envelope member,
//!   [`CARRIER_MEMBER`];
//! - the row's signature columns are the object's own hybrid signature (over
//!   `JCS(signed_envelope)`), its instant the envelope's `revoked_at`;
//! - id = the first 16 bytes of `sha256("ciris:identity:occurrence_revocation:v1:"
//!   ‖ JCS(object))`, as a UUID ([`ID_DOMAIN`]);
//! - `scores`, score −1, federation tier, `cohort_scope = federation` (the
//!   key plane's global reach: no consent gate, no subject pull — a stranger
//!   holding the occurrence receives it); never withdrawn.
//!
//! A receiver re-derives the row from the object it carries and refuses any
//! byte difference (the key plane's `check_canonical_plane_row`); the one
//! member outside the derivation is `additional_scrubs`, the roster
//! cosignatures below.
//!
//! # Admission is structural, never an instant
//!
//! The framed object's instant is signer-chosen, so "signed before the door"
//! is unverifiable: a thief holding one device could mint a backdated
//! revocation of the owner's other device (`formal/self_roster`
//! `unilateral3_stolen`). The carrier is therefore admitted
//! ([`check_carrier_admission`]) only when, whatever the instant:
//!
//! - **(A)** the identity is a `node` or `agent` (single-signer in any case),
//!   and the revoker acts for it; or
//! - **(B)** otherwise (a user self) the row is cosigned — each cosignature an
//!   `additional_scrubs` entry, hybrid over `JCS(row envelope)` — by a STRICT
//!   MAJORITY of the self's CURRENT live roster
//!   ([`super::self_roster::roster_now`]; the revoker counts when it is on
//!   the roster), counted with verify-core's `strict_majority`.
//!
//! Without that quorum the carrier is refused `federation_malformed_row` /
//! [`malformed_row::CARRIER_WITHOUT_ROSTER_QUORUM`](super::malformed_row::CARRIER_WITHOUT_ROSTER_QUORUM),
//! and the open's migration count line names the pair for its owner to
//! re-propose through the two-path door. Once admitted, the carrier is an
//! ordinary attestation row: it replicates, and every node that admits it
//! projects the revocation (`federation_identity_occurrence_revocations`).

use super::types::{attestation_type, identity_type, Attestation, IdentityOccurrenceRevocation};
use super::{Error, FederationDirectory};

/// The carrier's dimension.
pub const CARRIER_DIMENSION: &str = "identity:occurrence_revocation:v1";
/// The envelope member the framed object rides under.
pub const CARRIER_MEMBER: &str = "occurrence_revocation";
/// The id domain: id = `sha256(ID_DOMAIN ‖ JCS(object))`.
pub const ID_DOMAIN: &[u8] = b"ciris:identity:occurrence_revocation:v1:";

const FAMILY: super::key_plane::MintedFamily = super::key_plane::MintedFamily {
    dimension: CARRIER_DIMENSION,
    member: CARRIER_MEMBER,
    score: -1,
    id_domain: ID_DOMAIN,
};

/// The framed object a v57 / v58 node held: its signer, the EXACT envelope
/// the signer signed, and the detached hybrid signature over
/// `JCS(signed_envelope)`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FramedOccurrenceRevocation {
    /// The revoker.
    pub attesting_key_id: String,
    /// The signed envelope (`identity_key_id`, `occurrence_key_id`,
    /// `revoked_at`, `effective_at`, …).
    pub signed_envelope: serde_json::Value,
    /// The hybrid signature over `JCS(signed_envelope)`.
    pub signature: ciris_verify_core::transport_binding::TransportBindingSignature,
}

fn malformed(reason: &'static str, message: String) -> Error {
    Error::malformed_row("occurrence_revocation_carrier", reason, message)
}

impl FramedOccurrenceRevocation {
    fn field(&self, k: &str) -> Result<&str, Error> {
        self.signed_envelope
            .get(k)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                malformed(
                    super::malformed_row::ENVELOPE_MEMBER_MISSING,
                    format!("framed occurrence revocation: no string `{k}` in the signed envelope"),
                )
            })
    }

    fn instant(&self, k: &str) -> Result<chrono::DateTime<chrono::Utc>, Error> {
        chrono::DateTime::parse_from_rfc3339(self.field(k)?)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|e| {
                malformed(
                    super::malformed_row::ENVELOPE_MEMBER_INVALID,
                    format!("framed occurrence revocation: `{k}` is not RFC 3339: {e}"),
                )
            })
    }

    /// The revocation it states, read from the SIGNED envelope only.
    ///
    /// # Errors
    ///
    /// [`Error::MalformedRow`] for a missing or ill-typed member.
    pub fn revocation(&self) -> Result<IdentityOccurrenceRevocation, Error> {
        Ok(IdentityOccurrenceRevocation {
            identity_key_id: self.field("identity_key_id")?.to_owned(),
            occurrence_key_id: self.field("occurrence_key_id")?.to_owned(),
            revoked_at: self.instant("revoked_at")?,
            effective_at: self.instant("effective_at")?,
            reason: self
                .signed_envelope
                .get("reason")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            witness_set: vec![self.attesting_key_id.clone()],
            persist_row_hash: String::new(),
        })
    }
}

/// **The carrier row** of a framed object (pure, no gate).
///
/// # Errors
///
/// [`Error::MalformedRow`] for a malformed object.
pub fn carrier_row(framed: &FramedOccurrenceRevocation) -> Result<Attestation, Error> {
    let revocation = framed.revocation()?;
    let object = serde_json::to_value(framed)
        .map_err(|e| Error::Backend(format!("carrier object encode: {e}")))?;
    super::key_plane::minted_row(
        FAMILY,
        &framed.attesting_key_id,
        &revocation.identity_key_id,
        object,
        revocation.revoked_at,
        super::key_plane::PlaneSignature {
            scrub_key_id: framed.attesting_key_id.clone(),
            classical: framed.signature.ed25519_signature_base64.clone(),
            pqc: framed.signature.mldsa65_signature_base64.clone(),
            scrub_timestamp: revocation.revoked_at,
            pqc_completed_at: framed
                .signature
                .mldsa65_signature_base64
                .as_ref()
                .map(|_| revocation.revoked_at),
        },
    )
}

/// Is `row` a carrier (by its signed dimension)?
#[must_use]
pub fn is_carrier_row(row: &Attestation) -> bool {
    row.attestation_type == attestation_type::SCORES
        && super::admission::envelope_dimension(&row.attestation_envelope)
            == Some(CARRIER_DIMENSION)
}

/// The framed object a carrier row carries; `None` for any other row.
#[must_use]
pub fn carrier_of_row(row: &Attestation) -> Option<FramedOccurrenceRevocation> {
    if !is_carrier_row(row) {
        return None;
    }
    serde_json::from_value(row.attestation_envelope.get(CARRIER_MEMBER)?.clone()).ok()
}

/// The framed object's hybrid signature verifies, 1-of-1 and RequireHybrid,
/// over `JCS(signed_envelope)` against the revoker's HELD keys; the revoker
/// acts for the identity now (`signer_acts_for`).
async fn verify_framed<D>(dir: &D, framed: &FramedOccurrenceRevocation) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    use ciris_verify_core::threshold::{
        verify_threshold_signatures, ThresholdMember, ThresholdSignature,
    };
    let revocation = framed.revocation()?;
    if framed.field("attesting_key_id")? != framed.attesting_key_id {
        return Err(malformed(
            super::malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
            "framed occurrence revocation: the signer diverges from the signed envelope's \
             attesting_key_id"
                .to_owned(),
        ));
    }
    let Some(signer) = dir.lookup_public_key(&framed.attesting_key_id).await? else {
        return Err(Error::unknown_signer(
            &framed.attesting_key_id,
            "occurrence_revocation_carrier",
        ));
    };
    let bytes = crate::verify::canonical::ceg_produce_canonicalize(&framed.signed_envelope)
        .map_err(|e| {
            malformed(
                super::malformed_row::ENVELOPE_NOT_CANONICAL,
                format!("framed occurrence revocation canonicalize: {e}"),
            )
        })?;
    let members = [ThresholdMember {
        member_id: signer.key_id.clone(),
        ed25519_public_key_base64: signer.pubkey_ed25519_base64.clone(),
        mldsa65_public_key_base64: signer.pubkey_ml_dsa_65_base64.clone(),
        role: None,
    }];
    let sigs = [ThresholdSignature {
        member_id: framed.attesting_key_id.clone(),
        ed25519_signature_base64: framed.signature.ed25519_signature_base64.clone(),
        mldsa65_signature_base64: framed.signature.mldsa65_signature_base64.clone(),
    }];
    if framed.signature.mldsa65_signature_base64.is_none()
        || verify_threshold_signatures(&bytes, &members, &sigs, 1).is_err()
    {
        return Err(Error::SignatureInvalid(format!(
            "occurrence revocation carrier for {}: the framed object's hybrid signature does not \
             verify against {}'s held key (CC 3.1.5)",
            revocation.occurrence_key_id, framed.attesting_key_id
        )));
    }
    super::admission::check_signer_acts_for(
        dir,
        &framed.attesting_key_id,
        &revocation.identity_key_id,
        "occurrence_revocation_carrier",
    )
    .await
}

/// **The structural admission rule** (CC 3.1.5, CIRISPersist#1104): (A) a
/// `node` or `agent` identity's occurrence; (B) otherwise a strict majority of
/// the self's current live roster has signed the row (the revoker counted when
/// on the roster; each other cosigner an `additional_scrubs` entry verified
/// over `JCS(row envelope)`). Never reads the framed object's instant.
///
/// # Errors
///
/// [`malformed_row::CARRIER_WITHOUT_ROSTER_QUORUM`](super::malformed_row::CARRIER_WITHOUT_ROSTER_QUORUM)
/// without the quorum; a cosignature that does not verify refuses the row.
pub async fn check_carrier_admission<D>(
    dir: &D,
    row: &Attestation,
    framed: &FramedOccurrenceRevocation,
) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    let identity = framed.revocation()?.identity_key_id;
    let single_signer = dir.lookup_public_key(&identity).await?.is_some_and(|k| {
        identity_type::set_contains(&k.identity_type, identity_type::NODE)
            || identity_type::set_contains(&k.identity_type, identity_type::AGENT)
    });
    if single_signer {
        return Ok(());
    }
    let roster = super::self_roster::roster_now(dir, &identity).await?;
    let mut signed: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    if roster.contains(&framed.attesting_key_id) {
        signed.insert(&framed.attesting_key_id);
    }
    for (i, scrub) in row.additional_scrubs.iter().enumerate() {
        super::tier_ingest::verify_envelope_hybrid_signature(
            dir,
            &scrub.scrub_key_id,
            &row.attestation_envelope,
            &scrub.scrub_signature_classical,
            scrub.scrub_signature_pqc.as_deref(),
        )
        .await
        .map_err(|e| {
            Error::SignatureInvalid(format!(
                "occurrence revocation carrier {}: cosignature [{i}] by {} does not verify: {e}",
                row.attestation_id, scrub.scrub_key_id
            ))
        })?;
        if roster.contains(&scrub.scrub_key_id) {
            signed.insert(&scrub.scrub_key_id);
        }
    }
    let need = ciris_verify_core::accord_genesis::strict_majority(roster.len());
    if roster.is_empty() || signed.len() < need {
        return Err(malformed(
            super::malformed_row::CARRIER_WITHOUT_ROSTER_QUORUM,
            format!(
                "occurrence revocation carrier for {identity:?}: a user self's carrier needs a \
                 strict majority of its current live roster ({need} of {}); {} signed — re-propose \
                 the revocation through the two-path door (CC 3.1.5, 3.3.6.3)",
                roster.len(),
                signed.len()
            ),
        ));
    }
    Ok(())
}

/// **The receiver's rule** (the generic verify defers to it, as it does for
/// the key plane's rows): `Ok(false)` off the family; for a carrier, the row
/// is exactly the row its framed object plans to (cosignatures aside), the
/// framed signature verifies and the revoker acts for the identity, and the
/// structural admission holds — then `Ok(true)`.
///
/// # Errors
///
/// Each refusal, typed.
pub async fn verify_carrier_row<D>(dir: &D, row: &Attestation) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    if !is_carrier_row(row) {
        return Ok(false);
    }
    let framed = carrier_of_row(row).ok_or_else(|| {
        malformed(
            super::malformed_row::ENVELOPE_MEMBER_INVALID,
            format!(
                "carrier row {} carries no readable `{CARRIER_MEMBER}`",
                row.attestation_id
            ),
        )
    })?;
    let mut offered = row.clone();
    offered.additional_scrubs.clear();
    super::key_plane::check_canonical_plane_row(&offered, &carrier_row(&framed)?)?;
    verify_framed(dir, &framed).await?;
    check_carrier_admission(dir, row, &framed).await?;
    Ok(true)
}

/// v59.0.0 (CIRISPersist#1104) — what the open's carrier migration did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CarrierMigration {
    /// Carriers minted and admitted (or already held).
    pub minted: u64,
    /// User-self legacy revocations without the roster quorum, by
    /// `(identity, occurrence)`: they stay the local legacy projection, and
    /// their owner re-proposes through the door.
    pub without_quorum: Vec<(String, String)>,
    /// Legacy revocations that could not be carried for another reason (an
    /// unheld signer, a signature that does not verify), by pair.
    pub not_carried: Vec<(String, String)>,
}

/// The framed objects a backend's legacy projection rows hold, from their
/// `(attesting_key_id, signed_envelope, signature)` columns (JSON text). A
/// row whose columns do not parse is skipped (it is counted as legacy by the
/// open, never carried).
#[must_use]
pub fn framed_of_columns(rows: Vec<(String, String, String)>) -> Vec<FramedOccurrenceRevocation> {
    rows.into_iter()
        .filter_map(|(attesting_key_id, envelope, signature)| {
            Some(FramedOccurrenceRevocation {
                attesting_key_id,
                signed_envelope: serde_json::from_str(&envelope).ok()?,
                signature: serde_json::from_str(&signature).ok()?,
            })
        })
        .collect()
}

/// v59.0.0 (CIRISPersist#1104) — **the migration**: mint the carrier of each
/// held legacy framed occurrence revocation through the attestation door
/// (where the structural rule admits it), and name the rest. Nothing held is
/// rewritten: the legacy projection rows stay as they are.
///
/// # Errors
///
/// A backend failure; a refusal is counted, never raised.
pub async fn migrate_legacy_framed<D>(
    dir: &D,
    legacy: Vec<FramedOccurrenceRevocation>,
) -> Result<CarrierMigration, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut out = CarrierMigration::default();
    for framed in legacy {
        let Ok(revocation) = framed.revocation() else {
            continue;
        };
        let pair = (revocation.identity_key_id, revocation.occurrence_key_id);
        let row = match carrier_row(&framed) {
            Ok(r) => r,
            Err(_) => {
                out.not_carried.push(pair);
                continue;
            }
        };
        match dir
            .put_attestation(super::SignedAttestation { attestation: row })
            .await
        {
            Ok(_) => out.minted += 1,
            Err(Error::MalformedRow {
                reason: super::malformed_row::CARRIER_WITHOUT_ROSTER_QUORUM,
                ..
            }) => out.without_quorum.push(pair),
            Err(Error::Backend(e)) => return Err(Error::Backend(e)),
            Err(_) => out.not_carried.push(pair),
        }
    }
    Ok(out)
}
