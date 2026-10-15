//! v58.0.0 (CIRISPersist#991 plane 1 of 3; CC 3.1.3, CC 3.3.6, CC 2.4.1.1;
//! CIRISConstitution#144/#145; `CLM-planes-as-rows`) — **the key plane as
//! rows.**
//!
//! A key's claim of itself, a key-plane revocation and an identity's
//! occurrence record were three tables of their own (`federation_keys`,
//! `federation_revocations`, `federation_identity_occurrences`), each with a
//! framed replication kind. From v58.0.0 each is a `scores` row on the
//! attestation plane, and the table is its projection:
//!
//! | family | attester | the row carries |
//! |---|---|---|
//! | `key:record:v1` | the key itself (`attesting_key_id = attested_key_id`) | [`KEY_RECORD_MEMBER`]: the key record, its registration envelope and its scrub set |
//! | `key:revocation:v1` | the revoker | [`REVOCATION_MEMBER`]: the signed revocation |
//! | `identity:occurrence:v1` | the occurrence's signer (the identity or a live occurrence of it) | [`IDENTITY_OCCURRENCE_MEMBER`]: the signed occurrence |
//!
//! # Who signs the row
//!
//! Persist MINTS each row from the signed object it verified — the
//! `trace:complete:v1` and `detection:*` precedent (v18.0.0, v57.0.0) — so no
//! producer changes its wire. The row's signature columns are the signed
//! object's own (`scrub_key_id`, `scrub_signature_classical`,
//! `scrub_signature_pqc`, `scrub_timestamp`, `pqc_completed_at`): the
//! signature covers the object's own signed bytes (for a key record, its
//! `registration_envelope`), which the row carries whole. Every other member
//! of the row is a pure function of that object: a receiver re-derives the
//! row from the object it carries and refuses a row that differs by one byte
//! ([`check_canonical_plane_row`]). That is the family's signature rule, and
//! the one place the attestation plane's generic verify defers to it
//! ([`verify_plane_row`]).
//!
//! # The key record: proof of possession
//!
//! A `key:record:v1` row is admitted by proof of possession against the keys
//! it carries: its base scrub is the key's own (`scrub_key_id == key_id`),
//! hybrid, verifying over the registration envelope with the pubkeys the
//! record carries
//! ([`register::verify_proof_of_possession`](super::register::verify_proof_of_possession)).
//! That is CC 3.1.3's one stated exception to resolving the attester through
//! a held row: the signer's key is not held when its own record arrives.
//! Anchor scrubs, root conferrals and accord co-scrubs ride as the record's
//! `additional_scrubs`, each over the same registration envelope.
//!
//! **The pre-rc8 conferral shape** (a ruling the operator can overturn): a
//! record whose BASE scrub is another key's — an anchor-scrubbed record, the
//! baked `ciris-canonical-1` seed, a key upgraded through
//! `adopt_scrub_upgrade` — carries no signature by the key itself. Its row
//! is minted all the same, verified against that signer's held pubkeys (the
//! ordinary resolve-the-attester rule, retryable until the signer is held),
//! so every verifiable record is on the plane and replicates as a row.
//! CC 3.1.3 makes such a record non-conformant (the anchor's scrub is a
//! cosignature on the key's own claim); re-minting it with the key's own base
//! scrub is a producer/ceremony change, flagged on CIRISPersist#991.
//!
//! A record that verifies under neither — a hybrid-pending (Ed25519-only)
//! record, an operator-added peer key with no registration signature, a
//! scrub that does not verify — is still HELD as a key (the directory
//! resolves it), but it has no row: its projection row's `attestation_id` is
//! NULL, and the rebuild gate ([`super::silo_projection`]) names it. A held
//! legacy record that verifies is rehomed by the first key-plane write after
//! the upgrade.
//!
//! # The order rule
//!
//! Every other row is admitted only once its signer's key is held; until
//! then the refusal is [`Error::AttesterKeyUnknown`](super::Error::AttesterKeyUnknown)
//! — the retryable ordering gap (CIRISPersist#1042), not a new error family.
//! The attestation door asks it through
//! [`AttestationStore::attesting_identity_type`](super::attestation_admit::AttestationStore::attesting_identity_type);
//! the key-plane doors ask it of the revoker and the occurrence signer.

use sha2::{Digest, Sha256};

use super::types::{attestation_tier, attestation_type, cohort_scope, Attestation, KeyRecord};
use super::Error;

/// `key:record:v1` — a key's claim of itself (CC 3.1.3).
pub const KEY_RECORD_DIMENSION: &str = "key:record:v1";
/// `key:revocation:v1` — a key-plane revocation (CC 3.1.3, CC 2.4.1.1).
pub const KEY_REVOCATION_DIMENSION: &str = "key:revocation:v1";
/// `identity:occurrence:v1` — an identity's occurrence record (CC 3.1.3,
/// CC 3.3.6).
pub const IDENTITY_OCCURRENCE_DIMENSION: &str = "identity:occurrence:v1";

/// The envelope member a `key:record:v1` row carries its key record under.
pub const KEY_RECORD_MEMBER: &str = "key_record";
/// The envelope member a `key:revocation:v1` row carries its revocation under.
pub const REVOCATION_MEMBER: &str = "revocation";
/// The envelope member an `identity:occurrence:v1` row carries its signed
/// occurrence under.
pub const IDENTITY_OCCURRENCE_MEMBER: &str = "identity_occurrence";

/// The three families of the key plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyPlaneFamily {
    /// `key:record:v1`.
    KeyRecord,
    /// `key:revocation:v1`.
    KeyRevocation,
    /// `identity:occurrence:v1`.
    IdentityOccurrence,
}

impl KeyPlaneFamily {
    /// Every family, in declaration order.
    pub const ALL: [KeyPlaneFamily; 3] = [
        Self::KeyRecord,
        Self::KeyRevocation,
        Self::IdentityOccurrence,
    ];

    /// The family's dimension.
    #[must_use]
    pub const fn dimension(self) -> &'static str {
        match self {
            Self::KeyRecord => KEY_RECORD_DIMENSION,
            Self::KeyRevocation => KEY_REVOCATION_DIMENSION,
            Self::IdentityOccurrence => IDENTITY_OCCURRENCE_DIMENSION,
        }
    }

    /// The envelope member the signed object rides under.
    #[must_use]
    pub const fn member(self) -> &'static str {
        match self {
            Self::KeyRecord => KEY_RECORD_MEMBER,
            Self::KeyRevocation => REVOCATION_MEMBER,
            Self::IdentityOccurrence => IDENTITY_OCCURRENCE_MEMBER,
        }
    }

    /// The `score` the row carries: the registry's polarity (`key:revocation`
    /// is `-1 only`; the other two are positive-only).
    #[must_use]
    pub const fn score(self) -> i64 {
        match self {
            Self::KeyRevocation => -1,
            Self::KeyRecord | Self::IdentityOccurrence => 1,
        }
    }

    /// The family a dimension names, if it is one of the three.
    #[must_use]
    pub fn of_dimension(dimension: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|f| f.dimension() == dimension)
    }

    /// The family of a row, read from its envelope's `dimension`.
    #[must_use]
    pub fn of_row(row: &Attestation) -> Option<Self> {
        super::admission::envelope_dimension(&row.attestation_envelope).and_then(Self::of_dimension)
    }

    /// The id domain: the row id is `sha256(domain ‖ JCS(object))`.
    const fn id_domain(self) -> &'static [u8] {
        match self {
            Self::KeyRecord => b"ciris:key:record:v1:",
            Self::KeyRevocation => b"ciris:key:revocation:v1:",
            Self::IdentityOccurrence => b"ciris:identity:occurrence:v1:",
        }
    }
}

/// Is this row one of the key plane's (by its signed dimension)?
#[must_use]
pub fn is_key_plane_row(row: &Attestation) -> bool {
    KeyPlaneFamily::of_row(row).is_some()
}

/// The signature a plane row carries: the signed object's own.
#[derive(Debug, Clone)]
pub(crate) struct PlaneSignature {
    /// Who signed the object.
    pub(crate) scrub_key_id: String,
    /// The Ed25519 half.
    pub(crate) classical: String,
    /// The ML-DSA-65 half.
    pub(crate) pqc: Option<String>,
    /// When the object was signed.
    pub(crate) scrub_timestamp: chrono::DateTime<chrono::Utc>,
    /// When the object became hybrid.
    pub(crate) pqc_completed_at: Option<chrono::DateTime<chrono::Utc>>,
}

fn canonical_bytes(v: &serde_json::Value) -> Result<Vec<u8>, Error> {
    crate::verify::canonical::ceg_produce_canonicalize(v).map_err(|e| {
        Error::malformed_row(
            "key_plane",
            super::malformed_row::ENVELOPE_NOT_CANONICAL,
            format!("key-plane object does not canonicalize: {e}"),
        )
    })
}

/// The row id of a family's object: the first 16 bytes of
/// `sha256(domain ‖ JCS(object))`, as a UUID. One signed object, one id, on
/// every node: a re-offer is the same row, and a changed object (a new
/// scrub, a completed hybrid, a rebind) is a new row that replaces the old.
pub(crate) fn plane_attestation_id(
    family: KeyPlaneFamily,
    object: &serde_json::Value,
) -> Result<String, Error> {
    let mut h = Sha256::new();
    h.update(family.id_domain());
    h.update(canonical_bytes(object)?);
    let digest = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    Ok(uuid::Uuid::from_bytes(b).to_string())
}

/// **The one row builder of the key plane.** Pure: the row is a function of
/// the family, the attester and subject, the signed object, its instant and
/// its signature.
///
/// `scores`, federation tier, `cohort_scope = federation` (keys, revocations
/// and occurrences are what trust resolution needs everywhere), no subjects,
/// no weight, no expiry (a key record's `valid_until` is the record's own,
/// read by the directory; a row expiry would let the TTL reaper take a key's
/// claim). Envelope `{dimension, score, confidence, <member>: object}` plus the
/// signed instant and the row mirror.
pub(crate) fn plane_row(
    family: KeyPlaneFamily,
    attesting_key_id: &str,
    attested_key_id: &str,
    object: serde_json::Value,
    asserted_at: chrono::DateTime<chrono::Utc>,
    signature: PlaneSignature,
) -> Result<Attestation, Error> {
    let mut object = object;
    super::canonical_at_rest::canonicalize_in_place(&mut object)?;
    let attestation_id = plane_attestation_id(family, &object)?;
    let mut members = serde_json::Map::new();
    members.insert("dimension".to_owned(), family.dimension().into());
    members.insert("score".to_owned(), family.score().into());
    members.insert("confidence".to_owned(), 1.into());
    members.insert(family.member().to_owned(), object);
    let envelope = serde_json::Value::Object(members);
    let mut row = Attestation {
        attestation_id,
        attesting_key_id: attesting_key_id.to_owned(),
        attested_key_id: attested_key_id.to_owned(),
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: String::new(),
        scrub_signature_classical: signature.classical,
        scrub_signature_pqc: signature.pqc,
        scrub_key_id: signature.scrub_key_id,
        scrub_timestamp: signature.scrub_timestamp,
        pqc_completed_at: signature.pqc_completed_at,
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    };
    // The signed instant and the row mirror, through the one placement every
    // persist-minted row uses.
    super::envelope::RowMirror::stamp_local_row(&mut row, false)?;
    super::canonical_at_rest::canonicalize_in_place(&mut row.attestation_envelope)?;
    super::admission::check_envelope_size_admission(&row.attestation_envelope)?;
    row.original_content_hash =
        hex::encode(Sha256::digest(canonical_bytes(&row.attestation_envelope)?));
    row.persist_row_hash = super::types::compute_persist_row_hash(&row)?;
    Ok(row)
}

/// The signed object a plane row carries, or `None` when the row is not of
/// `family` or carries no object.
#[must_use]
pub fn plane_object(row: &Attestation, family: KeyPlaneFamily) -> Option<&serde_json::Value> {
    if KeyPlaneFamily::of_row(row) != Some(family) {
        return None;
    }
    row.attestation_envelope.get(family.member())
}

/// **The family's signature rule, at a receiver**: a plane row is exactly the
/// row its own object plans to, column for column. `planned` is what the
/// family's plan built from the object the row carries.
pub(crate) fn check_canonical_plane_row(
    offered: &Attestation,
    planned: &Attestation,
) -> Result<(), Error> {
    let diverges = |member: &str| {
        Err(Error::malformed_row(
            "key_plane",
            super::malformed_row::TYPED_DIVERGES_FROM_ENVELOPE,
            format!(
                "key-plane row {}: `{member}` is not what the row's own signed object plans to \
                 (planned row {}) — a key-plane row is a pure function of the object it carries \
                 (CIRISPersist#991)",
                offered.attestation_id, planned.attestation_id
            ),
        ))
    };
    if offered.attestation_id != planned.attestation_id {
        return diverges("attestation_id");
    }
    if offered.attesting_key_id != planned.attesting_key_id {
        return diverges("attesting_key_id");
    }
    if offered.attested_key_id != planned.attested_key_id {
        return diverges("attested_key_id");
    }
    if offered.attestation_type != planned.attestation_type {
        return diverges("attestation_type");
    }
    if offered.weight.is_some() || offered.expires_at.is_some() {
        return diverges("weight/expires_at");
    }
    if offered.asserted_at != planned.asserted_at {
        return diverges("asserted_at");
    }
    if offered.cohort_scope != planned.cohort_scope {
        return diverges("cohort_scope");
    }
    if offered.tier != planned.tier {
        return diverges("tier");
    }
    if !offered.subject_key_ids.is_empty() || !offered.additional_scrubs.is_empty() {
        return diverges("subject_key_ids/additional_scrubs");
    }
    let mut offered_envelope = offered.attestation_envelope.clone();
    super::canonical_at_rest::canonicalize_in_place(&mut offered_envelope)?;
    if offered_envelope != planned.attestation_envelope {
        return diverges("attestation_envelope");
    }
    if offered.original_content_hash != planned.original_content_hash {
        return diverges("original_content_hash");
    }
    if offered.scrub_key_id != planned.scrub_key_id
        || offered.scrub_signature_classical != planned.scrub_signature_classical
        || offered.scrub_signature_pqc != planned.scrub_signature_pqc
        || offered.scrub_timestamp != planned.scrub_timestamp
        || offered.pqc_completed_at != planned.pqc_completed_at
    {
        return diverges("signature");
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
//  key:record:v1
// ─────────────────────────────────────────────────────────────────────────

/// The key record as the row carries it: every field of the record except the
/// two this node computes or overlays (`persist_row_hash`, recomputed;
/// `consent_role`, a mutable local role marker outside the signed
/// registration, CC 3.4.7.2 OQ-1).
pub fn key_record_object(record: &KeyRecord) -> Result<serde_json::Value, Error> {
    let mut v = serde_json::to_value(record)
        .map_err(|e| Error::Backend(format!("key record encode: {e}")))?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("persist_row_hash");
        obj.remove("consent_role");
    }
    Ok(v)
}

/// The held pubkeys of a record's base signer, when it is not the key itself.
pub type HeldSigner = Option<(String, Option<String>)>;

/// **The `key:record:v1` door's decision** (CC 3.1.3), once for every backend
/// and pure: the record's base scrub verifies — by the key itself against the
/// keys the record carries (proof of possession), or, in the pre-rc8
/// conferral shape, by another key against `held_signer`, that key's held
/// `(ed25519, ml_dsa_65)` (an unheld signer is the retryable ordering gap,
/// [`Error::AttesterKeyUnknown`]) — and the row is the record, attested by
/// the key about itself, signed with the record's own signature over its
/// registration envelope. Its signed instant is the record's
/// `scrub_timestamp` — the row's own instant, on a fresh registration and on
/// a rehomed legacy record alike.
pub fn plan_key_record_row(
    record: &KeyRecord,
    held_signer: &HeldSigner,
) -> Result<Attestation, Error> {
    if record.scrub_key_id == record.key_id {
        super::register::verify_proof_of_possession(record)?;
    } else {
        let Some((ed25519, ml_dsa_65)) = held_signer else {
            return Err(Error::unknown_signer(&record.scrub_key_id, "key_record"));
        };
        super::register::verify_record_signed_by(record, ed25519, ml_dsa_65.as_deref())?;
    }
    plane_row(
        KeyPlaneFamily::KeyRecord,
        &record.key_id,
        &record.key_id,
        key_record_object(record)?,
        record.scrub_timestamp,
        PlaneSignature {
            scrub_key_id: record.scrub_key_id.clone(),
            classical: record.scrub_signature_classical.clone(),
            pqc: record.scrub_signature_pqc.clone(),
            scrub_timestamp: record.scrub_timestamp,
            pqc_completed_at: record.pqc_completed_at,
        },
    )
}

/// **The projection** of a `key:record:v1` row: the record it carries, with
/// `persist_row_hash` recomputed. `consent_role` is `None` (the overlay is
/// not part of the claim). `None` for any other row.
#[must_use]
pub fn key_record_of_row(row: &Attestation) -> Option<KeyRecord> {
    let mut object = plane_object(row, KeyPlaneFamily::KeyRecord)?.clone();
    object.as_object_mut()?.insert(
        "persist_row_hash".to_owned(),
        serde_json::Value::String(String::new()),
    );
    let mut record: KeyRecord = serde_json::from_value(object).ok()?;
    record.consent_role = None;
    record.persist_row_hash = super::types::compute_persist_row_hash(&record).ok()?;
    Some(record)
}

/// The `key:record:v1` row a stored record has, or `None` when it verifies
/// under neither rule (held without a row; the rebuild gate names it). The
/// refusal is logged, never raised: every key-plane write calls this after it
/// has stored the record, and an unverifiable record is still a held key.
#[must_use]
pub fn key_record_row_if_verifiable(
    record: &KeyRecord,
    held_signer: &HeldSigner,
) -> Option<Attestation> {
    match plan_key_record_row(record, held_signer) {
        Ok(row) => Some(row),
        Err(e) => {
            tracing::debug!(
                key_id = %record.key_id,
                refusal = e.kind(),
                "key held without a key:record:v1 row: {e}"
            );
            None
        }
    }
}

/// The rebuild gate's rendering of one `federation_keys` projection row: the
/// record's claim (the row's object, `persist_row_hash` included) and the
/// `attestation_id` it names. Local overlays (`consent_role`, the trust
/// columns, `admitted_at`, `mutated_at`) are not part of the projection.
#[must_use]
pub fn render_key_projection(record: &KeyRecord, attestation_id: Option<&str>) -> String {
    let mut claim = key_record_object(record).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = claim.as_object_mut() {
        obj.insert(
            "persist_row_hash".to_owned(),
            serde_json::Value::String(record.persist_row_hash.clone()),
        );
        obj.insert(
            "attestation_id".to_owned(),
            attestation_id.map_or(serde_json::Value::Null, |a| {
                serde_json::Value::String(a.to_owned())
            }),
        );
    }
    crate::verify::canonical::ceg_produce_canonicalize(&claim)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// The from-rows rebuild of `federation_keys`: every `key:record:v1` row,
/// projected and rendered, in `key_id` order; and the live table rendered the
/// same way. A key held without its row, a row whose key is not held, or one
/// claim member that differs is a red.
#[must_use]
pub fn key_projection_rebuild(
    live: Vec<(KeyRecord, Option<String>)>,
    rows: &[Attestation],
) -> super::silo_projection::ProjectionRebuild {
    let mut live: Vec<(String, String)> = live
        .into_iter()
        .map(|(r, a)| (r.key_id.clone(), render_key_projection(&r, a.as_deref())))
        .collect();
    live.sort();
    let mut rebuilt: Vec<(String, String)> = rows
        .iter()
        .filter_map(|row| {
            key_record_of_row(row).map(|r| {
                (
                    r.key_id.clone(),
                    render_key_projection(&r, Some(&row.attestation_id)),
                )
            })
        })
        .collect();
    rebuilt.sort();
    super::silo_projection::ProjectionRebuild {
        live: live.into_iter().map(|(_, s)| s).collect(),
        rebuilt: rebuilt.into_iter().map(|(_, s)| s).collect(),
    }
}

/// **The family's signature rule** for a row that reaches the attestation
/// plane's generic verify ([`super::tier_ingest::verify_row_hybrid_signature`]):
/// the row is the canonical row of the object it carries, and the object's
/// own signature verifies (a non-self base signer resolved from `directory`).
/// `Ok(false)` when the row is not a key-plane row (the generic rule applies).
pub(crate) async fn verify_plane_row<F>(directory: &F, row: &Attestation) -> Result<bool, Error>
where
    F: super::FederationDirectory + ?Sized,
{
    match KeyPlaneFamily::of_row(row) {
        None => Ok(false),
        Some(KeyPlaneFamily::KeyRecord) => {
            let record = key_record_of_row(row).ok_or_else(|| {
                Error::malformed_row(
                    "key_record",
                    super::malformed_row::ENVELOPE_MEMBER_INVALID,
                    format!(
                        "key:record:v1 row {} carries no readable `{KEY_RECORD_MEMBER}`",
                        row.attestation_id
                    ),
                )
            })?;
            let held_signer = held_signer_of(directory, &record).await?;
            check_canonical_plane_row(row, &plan_key_record_row(&record, &held_signer)?)?;
            Ok(true)
        }
        Some(family) => Err(Error::FederationTierUnverified {
            attestation_id: row.attestation_id.clone(),
            attesting_key_id: row.attesting_key_id.clone(),
            reason: format!(
                "{} rows are admitted only through the key-plane door, never the generic \
                 attestation verify (CIRISPersist#991)",
                family.dimension()
            ),
        }),
    }
}

/// The held pubkeys of `record`'s base signer when it is not the key itself;
/// `None` for a self-scrubbed record or an unheld signer.
pub(crate) async fn held_signer_of<F>(
    directory: &F,
    record: &KeyRecord,
) -> Result<HeldSigner, Error>
where
    F: super::FederationDirectory + ?Sized,
{
    if record.scrub_key_id == record.key_id {
        return Ok(None);
    }
    Ok(directory
        .lookup_public_key(&record.scrub_key_id)
        .await?
        .map(|k| (k.pubkey_ed25519_base64, k.pubkey_ml_dsa_65_base64)))
}

// ─────────────────────────────────────────────────────────────────────────
//  key:revocation:v1
// ─────────────────────────────────────────────────────────────────────────

/// The revocation as the row carries it: every field but `persist_row_hash`
/// (recomputed).
pub fn revocation_object(
    revocation: &super::types::Revocation,
) -> Result<serde_json::Value, Error> {
    let mut v = serde_json::to_value(revocation)
        .map_err(|e| Error::Backend(format!("revocation encode: {e}")))?;
    if let Some(obj) = v.as_object_mut() {
        obj.remove("persist_row_hash");
    }
    Ok(v)
}

/// The `key:revocation:v1` row of a revocation (pure, no gate): attested and
/// attesting by the revoker (the subject is the digest the object names, CC
/// 2.4.1.1 — the revoked key need not be held), signed with the revocation's
/// own hybrid signature over its `revocation_envelope`, asserted at its
/// `scrub_timestamp`.
pub fn revocation_row(revocation: &super::types::Revocation) -> Result<Attestation, Error> {
    plane_row(
        KeyPlaneFamily::KeyRevocation,
        &revocation.revoking_key_id,
        &revocation.revoking_key_id,
        revocation_object(revocation)?,
        revocation.scrub_timestamp,
        PlaneSignature {
            scrub_key_id: revocation.scrub_key_id.clone(),
            classical: revocation.scrub_signature_classical.clone(),
            pqc: revocation.scrub_signature_pqc.clone(),
            scrub_timestamp: revocation.scrub_timestamp,
            pqc_completed_at: revocation.pqc_completed_at,
        },
    )
}

/// **The projection** of a `key:revocation:v1` row: the revocation it
/// carries, `persist_row_hash` recomputed. `None` for any other row.
#[must_use]
pub fn revocation_of_row(row: &Attestation) -> Option<super::types::Revocation> {
    let mut object = plane_object(row, KeyPlaneFamily::KeyRevocation)?.clone();
    object.as_object_mut()?.insert(
        "persist_row_hash".to_owned(),
        serde_json::Value::String(String::new()),
    );
    let mut revocation: super::types::Revocation = serde_json::from_value(object).ok()?;
    revocation.persist_row_hash = super::types::compute_persist_row_hash(&revocation).ok()?;
    Some(revocation)
}

/// Is `row` a `key:revocation:v1` row — the family that is never withdrawn
/// (CC 2.4.1.1 rule 0: "a `key:revocation:v1` row is withdrawn by nobody")?
#[must_use]
pub fn is_never_withdrawn(row: &Attestation) -> bool {
    KeyPlaneFamily::of_row(row) == Some(KeyPlaneFamily::KeyRevocation)
}

/// The rebuild gate's rendering of one `federation_revocations` projection
/// row: the revocation (`persist_row_hash` included) and the
/// `attestation_id` it names. The admission position is local.
#[must_use]
pub fn render_revocation_projection(
    revocation: &super::types::Revocation,
    attestation_id: Option<&str>,
) -> String {
    let mut v = serde_json::to_value(revocation).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = v.as_object_mut() {
        obj.insert(
            "attestation_id".to_owned(),
            attestation_id.map_or(serde_json::Value::Null, |a| {
                serde_json::Value::String(a.to_owned())
            }),
        );
    }
    crate::verify::canonical::ceg_produce_canonicalize(&v)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default()
}

/// The from-rows rebuild of `federation_revocations`, in `revocation_id`
/// order: a revocation held without its row (a pre-v58 Ed25519-only one), a
/// row whose revocation is not held, or one member that differs is a red.
#[must_use]
pub fn revocation_projection_rebuild(
    live: Vec<(super::types::Revocation, Option<String>)>,
    rows: &[Attestation],
) -> super::silo_projection::ProjectionRebuild {
    let mut live: Vec<(String, String)> = live
        .into_iter()
        .map(|(r, a)| {
            (
                r.revocation_id.clone(),
                render_revocation_projection(&r, a.as_deref()),
            )
        })
        .collect();
    live.sort();
    let mut rebuilt: Vec<(String, String)> = rows
        .iter()
        .filter_map(|row| {
            revocation_of_row(row).map(|r| {
                (
                    r.revocation_id.clone(),
                    render_revocation_projection(&r, Some(&row.attestation_id)),
                )
            })
        })
        .collect();
    rebuilt.sort();
    super::silo_projection::ProjectionRebuild {
        live: live.into_iter().map(|(_, s)| s).collect(),
        rebuilt: rebuilt.into_iter().map(|(_, s)| s).collect(),
    }
}

/// The `key:revocation:v1` row of a held legacy revocation, for the rehome:
/// `None` (held without a row; the gate names it) when it is not hybrid.
#[must_use]
pub fn revocation_row_if_hybrid(revocation: &super::types::Revocation) -> Option<Attestation> {
    if revocation.scrub_signature_pqc.is_none() || revocation.pqc_completed_at.is_none() {
        return None;
    }
    revocation_row(revocation)
        .map_err(|e| {
            tracing::debug!(
                revocation_id = %revocation.revocation_id,
                refusal = e.kind(),
                "revocation held without a key:revocation:v1 row: {e}"
            );
        })
        .ok()
}

/// A planned revocation: the projection row and its `key:revocation:v1` row,
/// stored by the executor in one step.
#[derive(Debug, Clone)]
pub(crate) struct PlannedRevocation {
    /// The `federation_revocations` row, `persist_row_hash` computed.
    pub(crate) revocation: super::types::Revocation,
    /// Its row on the plane.
    pub(crate) row: Attestation,
}

/// The key plane's executor: what a backend does for the shared plans.
/// Storage only — every refusal is the plan's.
#[async_trait::async_trait]
pub(crate) trait KeyPlaneStore: super::attestation_admit::AttestationStore {
    /// Store a planned revocation: the `federation_revocations` row (its
    /// admission position allocated here, `attestation_id` naming the row) and
    /// its `key:revocation:v1` row, in one transaction, then its wire-index
    /// entry.
    async fn store_planned_revocation(&self, planned: PlannedRevocation) -> Result<(), Error>;
}

/// **The `key:revocation:v1` door's decision** (CC 3.1.3, CC 2.4.1.1), once
/// for every backend — the gates each backend's `put_revocation` used to run
/// in its own copy, in the same order, then the row. `received_at` is the
/// receiving node's clock (the skew ceiling).
///
/// The gates: canonical at rest; the #659 envelope binding; the trust gate on
/// the revoker; a hex content hash; **hybrid** (an Ed25519-only revocation is
/// refused: a plane row's signature is hybrid — the v58 clean break that ends
/// the hybrid-pending revocation path); the revoker's hybrid signature,
/// resolved from this node's directory (an unheld revoker is the retryable
/// [`Error::AttesterKeyUnknown`] — the order rule); the moderation authority
/// for revoking another's key; the closed region set; the scrub-time skew
/// ceiling; the per-subject anti-rollback floor; the signed history bound;
/// and **`revoked_after` only lowering**
/// ([`check_revocation_bound_lowers`](super::register::check_revocation_bound_lowers)).
pub(crate) async fn plan_put_revocation<D>(
    dir: &D,
    revocation: super::types::Revocation,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<PlannedRevocation, Error>
where
    D: super::attestation_admit::AttestationStore,
{
    let mut row = revocation;
    // v31.0.0 (CIRISPersist#647) — CANONICAL AT REST.
    super::canonical_at_rest::canonicalize_in_place(&mut row.revocation_envelope)?;
    // v31.0.0 (CIRISPersist#659) — THE SUBJECT, before anything else: a pure
    // function of the row, ahead of the trust gate and the authority walk.
    super::admission::check_revocation_envelope_binding(&row)?;
    // v3.4.0 (CIRISPersist#123) — the trust gate; the revoker is the attester.
    if !row.revoking_key_id.is_empty() {
        if let Some(gate) = dir.admission_cx().admission_gate {
            gate.check_federation(&row.revoking_key_id).await?;
        }
    }
    // v31.0.0 (CIRISPersist#660) — a hex content hash, stated.
    super::admission::check_content_hash_hex("original_content_hash", &row.original_content_hash)?;
    // v58.0.0 (CIRISPersist#991) — hybrid, like every plane row.
    if row.scrub_signature_pqc.is_none() || row.pqc_completed_at.is_none() {
        return Err(Error::SignatureInvalid(format!(
            "key:revocation:v1 {}: Ed25519-only (hybrid-pending) — a plane row's signature is \
             hybrid (CC 2.4); the hybrid-pending revocation path ended in v58.0.0 \
             (CIRISPersist#991)",
            row.revocation_id
        )));
    }
    // v21.0.0 (CIRISPersist#502 E1) — the revoker's hybrid signature, resolved
    // from this node's directory.
    super::verify_revocation_admission(dir, &row).await?;
    // v30.8.0 (CIRISPersist#596 item 1) — revoking another's key is moderation.
    super::admission::check_revocation_authority(dir, &row).await?;
    super::check_observed_region(&row.observed_region)?;
    // v31.0.0 (CIRISPersist#659) — the anti-rollback dual, before the floor.
    super::admission::check_revocation_scrub_skew(
        &row,
        received_at,
        super::admission::DEFAULT_MAX_TOUCH_SKEW,
    )?;
    // v52.0.0 (#784) — per SUBJECT, and the subject is the digest.
    let held = dir
        .revocations_for_subject(&row.revoked_key_sha256_ed25519_raw)
        .await?;
    super::admission::check_revocation_anti_rollback(
        &row.revoked_key_sha256_ed25519_raw,
        held.iter().map(|r| r.scrub_timestamp).max(),
        row.scrub_timestamp,
    )?;
    // v25.1.0 (CIRISPersist#570 ask 4) — the signed, coherent history bound.
    super::check_revocation_bound(&row)?;
    // v58.0.0 (CIRISPersist#991, CC 2.4.1.1) — and it only ever lowers.
    super::register::check_revocation_bound_lowers(&held, &row)?;
    row.persist_row_hash = super::types::compute_persist_row_hash(&row)?;
    let plane = revocation_row(&row)?;
    Ok(PlannedRevocation {
        revocation: row,
        row: plane,
    })
}

/// The door every backend's `put_revocation` is: settle a held re-offer, plan,
/// store.
pub(crate) async fn put_revocation_planned<D>(
    dir: &D,
    revocation: super::SignedRevocation,
) -> Result<(), Error>
where
    D: KeyPlaneStore,
{
    if dir
        .revocations_for_subject(&revocation.revocation.revoked_key_sha256_ed25519_raw)
        .await?
        .iter()
        .any(|held| {
            held.revocation_id == revocation.revocation.revocation_id
                && held.original_content_hash == revocation.revocation.original_content_hash
        })
    {
        return Ok(());
    }
    let planned = plan_put_revocation(dir, revocation.revocation, chrono::Utc::now()).await?;
    dir.store_planned_revocation(planned).await
}

// ─────────────────────────────────────────────────────────────────────────
//  The door: a key-plane row arriving on the attestation plane
// ─────────────────────────────────────────────────────────────────────────

/// What applying a key-plane row did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyPlaneApplied {
    /// The object landed or changed what this node holds; its row with it.
    Changed,
    /// This node already holds exactly this object.
    Unchanged,
    /// Well-formed, not applied; the held state is untouched. The token is
    /// the family door's own refusal reason.
    Refused(&'static str),
}

/// **The key-plane door on the attestation plane** — where a `key:record:v1`,
/// `key:revocation:v1` or `identity:occurrence:v1` row arriving through
/// `put_attestation` or `apply_replicated_attestation` goes, ahead of the
/// generic plan (whose resolve-the-attester and verify-over-the-envelope rules
/// are not this family's). The row must be exactly the row its own signed
/// object plans to ([`check_canonical_plane_row`]); then the object goes
/// through its family's door — the same door a local write of the object
/// uses — which stores it and its row in one step.
///
/// - `key:record:v1`: proof of possession (or a held base signer, the
///   pre-rc8 conferral shape), then the replicated key apply
///   ([`FederationDirectory::apply_replicated_key_record`](super::FederationDirectory::apply_replicated_key_record)):
///   insert, scrub upgrade, canonical supersede, rebind, invalid-replace, or
///   a refusal naming its [`KeyRefusalReason`](super::register::KeyRefusalReason).
pub(crate) async fn apply_key_plane_row<D>(
    dir: &D,
    row: &Attestation,
) -> Result<KeyPlaneApplied, Error>
where
    D: super::FederationDirectory + ?Sized,
{
    match KeyPlaneFamily::of_row(row) {
        Some(KeyPlaneFamily::KeyRecord) => {
            let record = key_record_of_row(row).ok_or_else(|| {
                Error::malformed_row(
                    "key_record",
                    super::malformed_row::ENVELOPE_MEMBER_INVALID,
                    format!(
                        "key:record:v1 row {} carries no readable `{KEY_RECORD_MEMBER}`",
                        row.attestation_id
                    ),
                )
            })?;
            let held_signer = held_signer_of(dir, &record).await?;
            check_canonical_plane_row(row, &plan_key_record_row(&record, &held_signer)?)?;
            use super::register::ReplicatedKeyOutcome as O;
            Ok(
                match dir
                    .apply_replicated_key_record(super::SignedKeyRecord { record })
                    .await?
                {
                    O::Unchanged => KeyPlaneApplied::Unchanged,
                    O::Refused { reason } => KeyPlaneApplied::Refused(reason.as_str()),
                    O::Inserted
                    | O::Upgraded
                    | O::Rebound
                    | O::Superseded
                    | O::ScrubsRehydrated
                    | O::InvalidReplaced => KeyPlaneApplied::Changed,
                },
            )
        }
        Some(KeyPlaneFamily::KeyRevocation) => {
            let revocation = revocation_of_row(row).ok_or_else(|| {
                Error::malformed_row(
                    "key_revocation",
                    super::malformed_row::ENVELOPE_MEMBER_INVALID,
                    format!(
                        "key:revocation:v1 row {} carries no readable `{REVOCATION_MEMBER}`",
                        row.attestation_id
                    ),
                )
            })?;
            check_canonical_plane_row(row, &revocation_row(&revocation)?)?;
            let held = dir
                .revocations_for_subject(&revocation.revoked_key_sha256_ed25519_raw)
                .await?
                .iter()
                .any(|h| {
                    h.revocation_id == revocation.revocation_id
                        && h.original_content_hash == revocation.original_content_hash
                });
            if held {
                return Ok(KeyPlaneApplied::Unchanged);
            }
            dir.put_revocation(super::SignedRevocation { revocation })
                .await?;
            Ok(KeyPlaneApplied::Changed)
        }
        Some(family) => Err(Error::InvalidArgument(format!(
            "{} rows are not admitted through the attestation door yet",
            family.dimension()
        ))),
        None => Err(Error::InvalidArgument(format!(
            "row {} is not a key-plane row",
            row.attestation_id
        ))),
    }
}
