//! v62.0.0 (slice J0, CIRISPersist#1274) — **the edition-2 key plane's read
//! models in the earlier store.**
//!
//! An edition-2 key lives in `ceg_statements` (its `key:record`s and
//! `key:revocation`s), and every edition-2 gate reads it from there through
//! [`HeldKeys`]. The earlier store still has readers of its own: the
//! attestation signer FKs (`federation_attestations.attesting_key_id` and
//! `scrub_key_id` → `federation_keys`), `lookup_public_key`, and the ~30
//! `revocations_for` / `revocations_for_subject` readers. This module keeps
//! one projection of each edition-2 key for them:
//!
//! - **the key** → `federation_keys`, `edition = 2`, keyed by its
//!   identity-ref ([`KeyProjection`]);
//! - **its honoured revocations** → `federation_revocations`
//!   ([`RevocationProjection`]): exactly the ones [`HeldKeys::liveness`]
//!   honours ([`HeldKeys::honoured_revocations`]).
//!
//! **One fold.** The projection is DERIVED from the held key plane every
//! time ([`project_key`]), through the same [`HeldKeys`] the gates read
//! ([`HeldKeys::valid_records`], [`HeldKeys::honoured_revocations`]). No
//! edition-2 gate reads the projection back: a corrupted projected row
//! changes no edition-2 verdict (I2006).
//!
//! **Cross-form standing is refused by name** ([`refuse_edition2_signer`],
//! [`refuse_edition2_projection`]): an earlier-form verification (a JSON row,
//! a JSON key registration, a plane object signed over its JCS image) whose
//! signer is an edition-2 key is `earlier_form_signer_is_edition2`. The
//! projected row is a read model, never a key an earlier-form signature can
//! be checked against (CC 2.6.1.12).

use std::sync::Arc;

use base64::Engine as _;
use chrono::{DateTime, Utc};
use ciris_verify_core::cde::Value;
use ciris_verify_core::edition2::family::SelectContext;
use ciris_verify_core::edition2::{identity_ref, is_identity_ref, Digest32};
use sha2::Digest as _;

use super::door::{admit_row, PLANE};
use super::ingest::{attestation_of, held_keys_for_kid, STATEMENT_MEMBER};
use super::liveness::{HeldKeys, HonouredRevocation, RevokerStanding, SelfOnly, ValidRecord};
use crate::federation::types::attestation_tier;
use crate::federation::{malformed_row, Error, FederationDirectory};

/// The `federation_keys.edition` of an edition-2 projection.
pub const EDITION_TWO: i16 = 2;

/// The `federation_keys.edition` of an earlier-form key.
pub const EDITION_ONE: i16 = 1;

/// The projection of an edition-2 key into `federation_keys`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyProjection {
    /// The key's identity-ref (`key_id` and `identity_ref`).
    pub key_id: String,
    /// The composite's Ed25519 half (32 bytes), standard base64.
    pub pubkey_ed25519_base64: String,
    /// The composite's ML-DSA-65 half (1952 bytes), standard base64.
    pub pubkey_ml_dsa_65_base64: String,
    /// The record's identity set, comma-joined (the earlier store's form).
    pub identity_type: String,
    /// The earliest `asserted_at` among the key's valid records.
    pub valid_from: DateTime<Utc>,
    /// The greatest end among them; `None` when one states no end.
    pub valid_until: Option<DateTime<Utc>>,
    /// The projected record's payload projection plus its statement (the
    /// mapping [`attestation_of`] gives a row).
    pub registration_envelope: serde_json::Value,
    /// SHA-256 of the envelope's JCS image, hex.
    pub original_content_hash: String,
    /// The record statement's composite signature, standard base64.
    pub scrub_signature_classical: String,
    /// The record's signer (its `iss`).
    pub scrub_key_id: String,
    /// The record's `asserted_at`. Also the row's `pqc_completed_at`: the
    /// composite carries its ML-DSA-65 half, so nothing is pending, and the
    /// earlier store's PQC sweep (`list_hybrid_pending_keys`) never offers
    /// a projection.
    pub scrub_timestamp: DateTime<Utc>,
    /// The record row's id, hex.
    pub persist_row_hash: String,
    /// `{hardware_class, pq_custody, chain}` from the record's payload, the
    /// chain as hex DER, leaf first.
    pub attestation_evidence: serde_json::Value,
    /// The projected record row's id.
    pub record_row_id: Digest32,
    /// The key's kid (thumbprint).
    pub kid: Digest32,
}

/// The projection of an honoured edition-2 `key:revocation` into
/// `federation_revocations`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationProjection {
    /// The revocation row's id, hex.
    pub revocation_id: String,
    /// The revoked key's identity-ref.
    pub revoked_key_id: String,
    /// The revoker's identity-ref.
    pub revoking_key_id: String,
    /// The payload's `reason`, if any.
    pub reason: Option<String>,
    /// The revocation's `asserted_at`.
    pub revoked_at: DateTime<Utc>,
    /// `revoked_after`, or `asserted_at` when it states none.
    pub effective_at: DateTime<Utc>,
    /// The payload's `revoked_after`, if any.
    pub revoked_after: Option<DateTime<Utc>>,
    /// The payload projection plus the statement.
    pub revocation_envelope: serde_json::Value,
    /// SHA-256 of the envelope's JCS image, hex.
    pub original_content_hash: String,
    /// The statement's composite signature, standard base64.
    pub scrub_signature_classical: String,
    /// The revoker's identity-ref.
    pub scrub_key_id: String,
    /// The revocation's `asserted_at`.
    pub scrub_timestamp: DateTime<Utc>,
    /// The revocation row's id, hex.
    pub persist_row_hash: String,
    /// SHA-256 of the revoked key's raw Ed25519 half, lowercase hex: the
    /// subject `revocations_for` resolves.
    pub revoked_key_sha256_ed25519_raw: String,
}

/// What one projection writes, in order: the keys (the subject, then any
/// revoker it names), then the revocations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectionSet {
    /// Upserted into `federation_keys`.
    pub keys: Vec<KeyProjection>,
    /// Inserted into `federation_revocations`, once each.
    pub revocations: Vec<RevocationProjection>,
}

fn instant(ms: u64) -> Result<DateTime<Utc>, Error> {
    i64::try_from(ms)
        .ok()
        .and_then(DateTime::<Utc>::from_timestamp_millis)
        .ok_or_else(|| {
            Error::malformed_row(
                PLANE,
                malformed_row::EDITION2_STATEMENT_INVALID,
                "malformed:instant (out of range)",
            )
        })
}

/// v62.0.0 (wave W1b; CC 4.2.2.1) — the key record's custody evidence as the
/// read model carries it: an object with only the members the record states
/// (`hardware_class` and `pq_custody` as text; `chain` as hex DER, leaf
/// first, only when non-empty), in the shape the hardware policy parses
/// (`hardware_attestation::AttestationEvidence::Edition2Custody`). An absent
/// member is ABSENT, never `null`; a record with no `attestation_evidence`
/// projects `null` (no evidence).
#[must_use]
pub fn attestation_evidence_of(payload: &Value) -> serde_json::Value {
    let Some(ev) = payload.get_text("attestation_evidence") else {
        return serde_json::Value::Null;
    };
    let mut out = serde_json::Map::new();
    for member in ["hardware_class", "pq_custody"] {
        if let Some(t) = ev.get_text(member).and_then(Value::as_text) {
            out.insert(member.to_owned(), serde_json::Value::String(t.to_owned()));
        }
    }
    let chain: Vec<serde_json::Value> = ev
        .get_text("chain")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_bytes)
                .map(|b| serde_json::Value::String(hex::encode(b)))
                .collect()
        })
        .unwrap_or_default();
    if !chain.is_empty() {
        out.insert("chain".to_owned(), serde_json::Value::Array(chain));
    }
    serde_json::Value::Object(out)
}

/// The record a key's projection names: the one with the greatest end (no
/// end is greatest), then the latest `asserted_at`, then the greatest row id.
fn projected_record(valid: &[ValidRecord]) -> Option<&ValidRecord> {
    valid.iter().max_by(|a, b| {
        let end = |v: &ValidRecord| v.record.valid_until.unwrap_or(u64::MAX);
        end(a)
            .cmp(&end(b))
            .then(a.record.asserted_at.cmp(&b.record.asserted_at))
            .then(a.row_id.cmp(&b.row_id))
    })
}

/// The projection of `kid` from a reading's valid records. `None` when no
/// held record of `kid` is valid (nothing to project).
///
/// # Errors
/// An instant out of range; a mapping that does not canonicalize.
pub fn key_projection(held: &HeldKeys, kid: &Digest32) -> Result<Option<KeyProjection>, Error> {
    let Ok(valid) = held.valid_records(kid) else {
        return Ok(None);
    };
    let Some(chosen) = projected_record(&valid) else {
        return Ok(None);
    };
    // The record is mapped as a row is (`attestation_of`), read over the
    // records alone: a revoked key's record still projects (its revocation is
    // the revocation read model's).
    let admitted = admit_row(
        &chosen.statement,
        &held.without_revocations(),
        None,
        SelectContext::default(),
    )?;
    let mapped = attestation_of(&admitted, attestation_tier::FEDERATION)?;
    let valid_from = valid
        .iter()
        .map(|v| v.record.asserted_at)
        .min()
        .unwrap_or(chosen.record.asserted_at);
    let valid_until = if valid.iter().any(|v| v.record.valid_until.is_none()) {
        None
    } else {
        valid.iter().filter_map(|v| v.record.valid_until).max()
    };
    // v62.0.0 (C5-fix3): the one composite split, by Verify's named layout.
    let (mldsa, ed) = super::composite::key_halves(&chosen.record.key).ok_or_else(|| {
        Error::Backend(format!(
            "key {} is not a {}-byte composite",
            identity_ref(kid),
            ciris_crypto::composite::PUBLIC_KEY_LEN
        ))
    })?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let iref = identity_ref(kid);
    Ok(Some(KeyProjection {
        key_id: iref,
        pubkey_ed25519_base64: b64.encode(ed),
        pubkey_ml_dsa_65_base64: b64.encode(mldsa),
        identity_type: chosen.record.identity_type.join(","),
        valid_from: instant(valid_from)?,
        valid_until: valid_until.map(instant).transpose()?,
        registration_envelope: mapped.attestation_envelope,
        original_content_hash: mapped.original_content_hash,
        scrub_signature_classical: mapped.scrub_signature_classical,
        scrub_key_id: admitted.iss,
        scrub_timestamp: instant(admitted.asserted_at_ms)?,
        persist_row_hash: admitted.row_id.hex(),
        attestation_evidence: attestation_evidence_of(&admitted.payload),
        record_row_id: chosen.row_id,
        kid: *kid,
    }))
}

/// The projection of one honoured revocation of `subject`.
///
/// # Errors
/// As [`key_projection`].
pub fn revocation_projection(
    held: &HeldKeys,
    subject: &KeyProjection,
    h: &HonouredRevocation,
) -> Result<RevocationProjection, Error> {
    let admitted = admit_row(
        &h.statement,
        &held.without_revocations(),
        None,
        SelectContext::default(),
    )?;
    let mapped = attestation_of(&admitted, attestation_tier::FEDERATION)?;
    let ed = base64::engine::general_purpose::STANDARD
        .decode(&subject.pubkey_ed25519_base64)
        .map_err(|e| Error::Backend(format!("projected Ed25519 half: {e}")))?;
    let revoked_at = instant(admitted.asserted_at_ms)?;
    let revoked_after = h.revoked_after.map(instant).transpose()?;
    Ok(RevocationProjection {
        revocation_id: admitted.row_id.hex(),
        revoked_key_id: subject.key_id.clone(),
        revoking_key_id: admitted.iss.clone(),
        reason: admitted
            .payload
            .get_text("reason")
            .and_then(Value::as_text)
            .map(str::to_owned),
        revoked_at,
        effective_at: revoked_after.unwrap_or(revoked_at),
        revoked_after,
        revocation_envelope: mapped.attestation_envelope,
        original_content_hash: mapped.original_content_hash,
        scrub_signature_classical: mapped.scrub_signature_classical,
        scrub_key_id: admitted.iss,
        scrub_timestamp: revoked_at,
        persist_row_hash: admitted.row_id.hex(),
        revoked_key_sha256_ed25519_raw: hex::encode(sha2::Sha256::digest(&ed)),
    })
}

/// Everything one key's projection writes, derived from `held`: the key, the
/// keys of the revokers its honoured revocations name (their FK target),
/// and those revocations. Empty when `kid` has no valid record.
///
/// # Errors
/// As [`key_projection`].
pub fn projection_set(held: &HeldKeys, kid: &Digest32) -> Result<ProjectionSet, Error> {
    let Some(key) = key_projection(held, kid)? else {
        return Ok(ProjectionSet::default());
    };
    let mut set = ProjectionSet {
        keys: vec![key.clone()],
        revocations: Vec::new(),
    };
    for h in held.honoured_revocations(kid) {
        if h.row.kid != *kid {
            // The revoker's own key row is the revocation's FK target. A
            // revoker with no valid record cannot have signed an honoured
            // revocation, so this projects.
            match key_projection(held, &h.row.kid)? {
                Some(r) => {
                    if !set.keys.iter().any(|k| k.key_id == r.key_id) {
                        set.keys.push(r);
                    }
                }
                None => continue,
            }
        }
        set.revocations.push(revocation_projection(held, &key, &h)?);
    }
    Ok(set)
}

/// **Project one edition-2 key** into the earlier store's read models, with
/// only the key itself as a revoker ([`SelfOnly`], what the gates read).
///
/// # Errors
/// Directory failures; [`Error::Conflict`] when `key_id` is held by an
/// earlier-form row.
pub async fn project_key<F>(dir: &F, kid: &Digest32) -> Result<ProjectionSet, Error>
where
    F: FederationDirectory + ?Sized,
{
    project_key_with(dir, kid, Arc::new(SelfOnly)).await
}

/// [`project_key`] with an owner / roster answer for revocations: a
/// revocation by another key projects only when `standing` admits it, as
/// [`HeldKeys::liveness`] reads it under the same standing.
///
/// # Errors
/// As [`project_key`].
pub async fn project_key_with<F>(
    dir: &F,
    kid: &Digest32,
    standing: Arc<dyn RevokerStanding>,
) -> Result<ProjectionSet, Error>
where
    F: FederationDirectory + ?Sized,
{
    let held = held_keys_for_kid(dir, kid).await?.with_standing(standing);
    let set = projection_set(&held, kid)?;
    if !set.keys.is_empty() {
        dir.upsert_edition2_key_projection(&set).await?;
    }
    Ok(set)
}

/// The edition a held `federation_keys` row records, read off the row itself:
/// 2 for an edition-2 projection (its id an identity-ref, its envelope
/// carrying the record statement), 1 otherwise. What
/// [`FederationDirectory::key_edition`] answers on a directory with no
/// `edition` column; the backends read the column, and I2001 witnesses the two
/// agree.
#[must_use]
pub fn edition_of_key_record(record: &crate::federation::KeyRecord) -> i16 {
    if is_identity_ref(&record.key_id)
        && record
            .registration_envelope
            .get(STATEMENT_MEMBER)
            .is_some_and(serde_json::Value::is_string)
    {
        EDITION_TWO
    } else {
        EDITION_ONE
    }
}

fn earlier_form_refusal(plane: &'static str, key_id: &str) -> Error {
    Error::malformed_row(
        plane,
        malformed_row::EARLIER_FORM_SIGNER_IS_EDITION2,
        format!(
            "{key_id} is an edition-2 key: an earlier-form signature gives it no standing, and \
             its projected row is a read model, never a key an earlier-form object verifies \
             under (CC 2.6.1.12)"
        ),
    )
}

/// **The cross-form refusal** at an earlier-form choke point: refused
/// `earlier_form_signer_is_edition2` when any of `signers` is an edition-2
/// key ([`FederationDirectory::key_edition`] = 2). Text that is not an
/// identity-ref is never an edition-2 key, so an earlier-form signer costs no
/// read.
///
/// # Errors
/// The refusal; directory read failures.
pub async fn refuse_edition2_signer<F>(
    dir: &F,
    plane: &'static str,
    signers: &[&str],
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    for signer in signers {
        if !is_identity_ref(signer) {
            continue;
        }
        if dir.key_edition(signer).await? == Some(EDITION_TWO) {
            return Err(earlier_form_refusal(plane, signer));
        }
    }
    Ok(())
}

/// [`refuse_edition2_signer`] for a row at an earlier-form verifier: a row
/// that carries an edition-2 statement is not an earlier-form verification
/// (its own door re-verifies it), so it passes; any other row is refused when
/// its attester or base scrubber is an edition-2 key.
///
/// # Errors
/// As [`refuse_edition2_signer`].
pub async fn refuse_edition2_row_signer<F>(
    dir: &F,
    plane: &'static str,
    row: &crate::federation::types::Attestation,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if row.attestation_envelope.get(STATEMENT_MEMBER).is_some() {
        return Ok(());
    }
    refuse_edition2_signer(
        dir,
        plane,
        &[row.attesting_key_id.as_str(), row.scrub_key_id.as_str()],
    )
    .await
}

/// The pure cross-form refusal: an earlier-form signature checked against a
/// key record that IS an edition-2 projection ([`edition_of_key_record`]).
///
/// # Errors
/// The refusal.
pub fn refuse_edition2_projection(
    plane: &'static str,
    record: &crate::federation::KeyRecord,
) -> Result<(), Error> {
    if edition_of_key_record(record) == EDITION_TWO {
        return Err(earlier_form_refusal(plane, &record.key_id));
    }
    Ok(())
}
