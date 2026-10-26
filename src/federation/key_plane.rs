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

/// v59.0.0 (sealed-transport floor, operator ruling 2026-10-19) — what the
/// one-way rehome at first open found: every v57-shape object it could give a
/// row now has one; these are what it could not. Logged at open, one line,
/// counted.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyPlaneRehomeReport {
    /// Keys held without a `key:record:v1` row (verify under neither rule).
    pub keys_without_row: u64,
    /// Key revocations held without a `key:revocation:v1` row.
    pub revocations_without_row: u64,
    /// Signed occurrences held without an `identity:occurrence:v1` row.
    pub occurrences_without_row: u64,
    /// Framed occurrence revocations kept as legacy projection rows (V200):
    /// still revoking, never re-signed, never un-revoked.
    pub legacy_framed_occurrence_revocations: u64,
    /// v59.0.0 (CIRISPersist#1104) — what the carrier migration did with
    /// them: minted carriers, and the user-self revocations without a roster
    /// quorum (named, for their owners to re-propose through the door).
    pub carriers: super::occurrence_revocation_carrier::CarrierMigration,
}

impl KeyPlaneRehomeReport {
    /// The counted log line.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub(crate) fn log(&self, backend: &'static str) {
        tracing::info!(
            backend,
            keys_without_row = self.keys_without_row,
            revocations_without_row = self.revocations_without_row,
            occurrences_without_row = self.occurrences_without_row,
            legacy_framed_occurrence_revocations = self.legacy_framed_occurrence_revocations,
            occurrence_revocation_carriers = self.carriers.minted,
            carriers_without_roster_quorum = ?self.carriers.without_quorum,
            carriers_not_carried = ?self.carriers.not_carried,
            "key-plane rehome at open (v59.0.0): every verifiable v57-shape record has its row; \
             the counted rest is held without one; a user self's legacy occurrence revocation \
             without a roster quorum stays local — its owner re-proposes it through the two-path \
             door (CIRISPersist#1104)"
        );
    }
}

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

    /// The family of a `scores` row, read from its envelope's `dimension`.
    /// A structural composer that names a key-plane dimension (an occurrence's
    /// `withdraws`) is not itself a key-plane row.
    #[must_use]
    pub fn of_row(row: &Attestation) -> Option<Self> {
        if row.attestation_type != attestation_type::SCORES {
            return None;
        }
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

/// v60.0.0 (CIRISPersist#1105) — the four families a key-plane HOLDINGS
/// read may name: the three [`KeyPlaneFamily`] dimensions and the
/// occurrence-revocation carrier
/// ([`occurrence_revocation_carrier::CARRIER_DIMENSION`](super::occurrence_revocation_carrier::CARRIER_DIMENSION)).
pub const HOLDINGS_FAMILIES: [&str; 4] = [
    KEY_RECORD_DIMENSION,
    KEY_REVOCATION_DIMENSION,
    IDENTITY_OCCURRENCE_DIMENSION,
    super::occurrence_revocation_carrier::CARRIER_DIMENSION,
];

/// v60.0.0 (CIRISPersist#1105) — refuse a holdings read for anything but a
/// key-plane family: the read is scoped to one family by construction, so a
/// dimension outside [`HOLDINGS_FAMILIES`] is a caller's error, not an empty
/// set (an empty answer would read as "this node holds none of them" to an
/// anti-entropy difference).
///
/// # Errors
///
/// [`Error::InvalidArgument`] naming the four families.
pub(crate) fn check_key_plane_holdings_family(family: &str) -> Result<&'static str, Error> {
    HOLDINGS_FAMILIES
        .into_iter()
        .find(|f| *f == family)
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "list_key_plane_wire_hashes_since: '{family}' is not a key-plane family \
                 (expected one of: {})",
                HOLDINGS_FAMILIES.join(", ")
            ))
        })
}

/// v60.0.0 (CIRISPersist#1105) — **a planned key-plane holdings page**: the
/// wire hashes (`signed_wire_index`, kind `Attestation`) of the `scores`
/// rows whose dimension is `family`, ordered by hash, after `after`, at most
/// `limit`. The hashes are the index's own, so they equal what this node
/// advertises (the #780 invariant), and the page is the family's slice of
/// [`FederationDirectory::list_wire_hashes_since`](super::FederationDirectory::list_wire_hashes_since)`("Attestation", ..)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyPlaneHoldingsRead {
    /// One of [`HOLDINGS_FAMILIES`].
    pub(crate) family: &'static str,
    /// Exclusive cursor; `""` starts at the first hash.
    pub(crate) after: String,
    /// Page size.
    pub(crate) limit: u32,
}

/// The wire kind the key-plane rows are indexed under.
pub(crate) const HOLDINGS_WIRE_KIND: &str = "Attestation";

#[cfg_attr(not(any(feature = "postgres", feature = "sqlite")), allow(dead_code))]
impl KeyPlaneHoldingsRead {
    /// The one statement, for `dialect`: the family's rows seek the
    /// `dimension`-leading index (V190), each joins its index entry on the
    /// `(kind, record_key)` index (V183). Binds: family, kind, cursor, limit.
    #[must_use]
    pub(crate) fn render(
        &self,
        dialect: super::attestation_query::Dialect,
    ) -> super::attestation_query::Statement {
        use super::attestation_query::{Bind, Dialect, Statement};
        let sql = match dialect {
            Dialect::Sqlite => {
                "SELECT w.content_hash FROM federation_attestations a \
                 JOIN signed_wire_index w ON w.kind = ?2 \
                  AND w.record_key = '{\"attestation_id\":\"' || a.attestation_id || '\"}' \
                 WHERE a.dimension = ?1 AND a.attestation_type = 'scores' \
                   AND w.content_hash > ?3 \
                 ORDER BY w.content_hash LIMIT ?4"
            }
            Dialect::Postgres => {
                "SELECT w.content_hash FROM cirislens.federation_attestations a \
                 JOIN cirislens.signed_wire_index w ON w.kind = $2 \
                  AND w.record_key = '{\"attestation_id\":\"' || a.attestation_id::text || '\"}' \
                 WHERE (a.dimension COLLATE \"C\") = $1 AND a.attestation_type = 'scores' \
                   AND w.content_hash > $3 \
                 ORDER BY w.content_hash LIMIT $4"
            }
        };
        Statement {
            sql: sql.to_owned(),
            binds: vec![
                Bind::Text(self.family.to_owned()),
                Bind::Text(HOLDINGS_WIRE_KIND.to_owned()),
                Bind::Text(self.after.clone()),
                Bind::Int(i64::from(self.limit)),
            ],
        }
    }
}

/// v60.0.0 (CIRISPersist#1105) — plan a holdings page: the family gate,
/// then the read.
///
/// # Errors
///
/// [`check_key_plane_holdings_family`]'s refusal.
pub(crate) fn plan_key_plane_holdings(
    family: &str,
    after_content_hash: Option<&str>,
    limit: u32,
) -> Result<KeyPlaneHoldingsRead, Error> {
    let family = check_key_plane_holdings_family(family)?;
    Ok(KeyPlaneHoldingsRead {
        family,
        after: after_content_hash.unwrap_or("").to_owned(),
        limit,
    })
}

/// v60.0.0 (CIRISPersist#1105) — the door every backend runs for
/// [`FederationDirectory::list_key_plane_wire_hashes_since`](super::FederationDirectory::list_key_plane_wire_hashes_since):
/// the plan, then the executor.
pub(crate) async fn list_key_plane_wire_hashes_planned<D>(
    dir: &D,
    family: &str,
    after_content_hash: Option<&str>,
    limit: u32,
) -> Result<Vec<String>, Error>
where
    D: KeyPlaneStore,
{
    let read = plan_key_plane_holdings(family, after_content_hash, limit)?;
    dir.read_key_plane_wire_hashes(read).await
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
///
/// The same rule names every row persist mints from a signed object it
/// verified: the key plane's three families and the self-roster proposal
/// (`super::self_roster`), each under its own id domain.
pub(crate) fn minted_attestation_id(
    id_domain: &[u8],
    object: &serde_json::Value,
) -> Result<String, Error> {
    let mut h = Sha256::new();
    h.update(id_domain);
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
    minted_row(
        MintedFamily {
            dimension: family.dimension(),
            member: family.member(),
            score: family.score(),
            id_domain: family.id_domain(),
        },
        attesting_key_id,
        attested_key_id,
        object,
        asserted_at,
        signature,
    )
}

/// What names a family of minted rows: its dimension, the envelope member
/// its signed object rides under, its score, and its id domain.
#[derive(Debug, Clone, Copy)]
pub(crate) struct MintedFamily {
    /// The row's `dimension`.
    pub(crate) dimension: &'static str,
    /// The envelope member carrying the signed object.
    pub(crate) member: &'static str,
    /// The row's `score`.
    pub(crate) score: i64,
    /// The id domain (`sha256(domain ‖ JCS(object))`).
    pub(crate) id_domain: &'static [u8],
}

/// [`plane_row`] for any [`MintedFamily`]: the one builder of a row persist
/// mints from a signed object, so the key plane and the self-roster proposal
/// (`super::self_roster`) cannot spell the row two ways.
pub(crate) fn minted_row(
    family: MintedFamily,
    attesting_key_id: &str,
    attested_key_id: &str,
    object: serde_json::Value,
    asserted_at: chrono::DateTime<chrono::Utc>,
    signature: PlaneSignature,
) -> Result<Attestation, Error> {
    let mut object = object;
    super::canonical_at_rest::canonicalize_in_place(&mut object)?;
    let attestation_id = minted_attestation_id(family.id_domain, &object)?;
    let mut members = serde_json::Map::new();
    members.insert("dimension".to_owned(), family.dimension.into());
    members.insert("score".to_owned(), family.score.into());
    members.insert("confidence".to_owned(), 1.into());
    members.insert(family.member.to_owned(), object);
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
        // v59.0.0 (CIRISPersist#1104, CC 3.1.5) — nor is an occurrence
        // revocation's carrier.
        || super::occurrence_revocation_carrier::is_carrier_row(row)
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
    revocation.scrub_signature_pqc.as_ref()?;
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

    /// v60.0.0 (CIRISPersist#934 step 3) — store a planned key-record write:
    /// the `federation_keys` write (its admission or serve position
    /// allocated here; the atomic re-assertion [`PlannedKeyRecord`] names,
    /// reported through [`PlannedKeyRecord::raced`] /
    /// [`PlannedKeyRecord::insert_held`]), then the key's `key:record:v1`
    /// row ([`key_record_row_step`] over the record as stored), in one
    /// transaction; then its wire-index entry.
    async fn store_planned_key_record(&self, planned: PlannedKeyRecord) -> Result<(), Error>;

    /// v60.0.0 (CIRISPersist#1105) — run a key-plane holdings page:
    /// [`KeyPlaneHoldingsRead::render`] on SQL, [`KeyPlaneHoldingsRead::admits`]
    /// over the held index on memory; hashes in order, at most `limit`.
    async fn read_key_plane_wire_hashes(
        &self,
        read: KeyPlaneHoldingsRead,
    ) -> Result<Vec<String>, Error>;
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
    // v58.0.0 (CIRISPersist#991) — hybrid, like every plane row. A revocation
    // that carries both halves is hybrid from its signing.
    if row.scrub_signature_pqc.is_some() && row.pqc_completed_at.is_none() {
        row.pqc_completed_at = Some(row.scrub_timestamp);
    }
    if row.scrub_signature_pqc.is_none() {
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

/// Is exactly this revocation held (the same record, every member)?
async fn is_held_revocation<D>(
    dir: &D,
    revocation: &super::types::Revocation,
) -> Result<bool, Error>
where
    D: super::FederationDirectory + ?Sized,
{
    let mut offered = revocation.clone();
    super::canonical_at_rest::canonicalize_in_place(&mut offered.revocation_envelope)?;
    if offered.scrub_signature_pqc.is_some() && offered.pqc_completed_at.is_none() {
        offered.pqc_completed_at = Some(offered.scrub_timestamp);
    }
    let hash = super::types::compute_persist_row_hash(&offered)?;
    Ok(dir
        .revocations_for_subject(&revocation.revoked_key_sha256_ed25519_raw)
        .await?
        .iter()
        .any(|held| {
            held.revocation_id == revocation.revocation_id && held.persist_row_hash == hash
        }))
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
    // A byte-identical re-offer of a held revocation settles before any verify
    // (the #672 rule): the whole record, not its id — a relay's re-pasted
    // column under a held id must still meet the binding gate.
    if is_held_revocation(dir, &revocation.revocation).await? {
        return Ok(());
    }
    let planned = plan_put_revocation(dir, revocation.revocation, chrono::Utc::now()).await?;
    dir.store_planned_revocation(planned).await
}

// ─────────────────────────────────────────────────────────────────────────
//  key:record:v1 — the write doors (v60.0.0, CIRISPersist#934 step 3)
// ─────────────────────────────────────────────────────────────────────────

/// v60.0.0 (CIRISPersist#934 step 3) — **which door a key-record write comes
/// through.** Every door that writes `federation_keys` (and with it the key's
/// `key:record:v1` row) names itself here; [`plan_key_record_write`] holds
/// each door's whole decision, once for every backend, and each backend's
/// [`KeyPlaneStore::store_planned_key_record`] only stores what the plan
/// decided.
#[derive(Debug)]
pub(crate) enum KeyRecordWrite<'a> {
    /// `put_public_key` (a local mint) and the replicated `Insert` arm.
    Put {
        /// The record as offered.
        record: KeyRecord,
        /// Which of the two insert doors (CC 3.4.7.3 Clause A gates minting).
        door: super::register::KeyDoor,
    },
    /// The genesis seed of one baked accord-holder record (CIRISPersist#347):
    /// every insert invariant but the fresh-nonce hardware gate; a held
    /// `key_id` is kept.
    SeedGenesis {
        /// The baked record.
        record: KeyRecord,
    },
    /// The self-signed → anchor-scrubbed upgrade (CIRISPersist#351).
    ScrubUpgrade {
        /// The anchor-scrubbed record.
        record: KeyRecord,
    },
    /// The canonical supersede (CIRISPersist#405): a strictly-newer,
    /// quorum-re-verified re-scrub of an anchored canonical row.
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    SupersedeCanonical {
        /// The successor record.
        record: KeyRecord,
    },
    /// The same-key rebind (CIRISPersist#864).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    Rebind {
        /// The holder's bound re-signing.
        record: KeyRecord,
    },
    /// The invalid-record replace (CIRISPersist#1044).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    InvalidReplace {
        /// The record that verifies.
        record: KeyRecord,
    },
    /// The authenticated genesis re-anchor (CIRISPersist#490).
    Reanchor {
        /// The record the bundle carries.
        record: KeyRecord,
        /// The bundle whose quorum authorises it.
        bundle: &'a super::genesis::GenesisBundle,
    },
    /// The hybrid completion: an Ed25519-only record gains its ML-DSA-65 key
    /// and signature (CIRISPersist#657).
    AttachPqc {
        /// The held key.
        key_id: &'a str,
        /// Its ML-DSA-65 public key.
        pubkey_ml_dsa_65_base64: &'a str,
        /// The PQC scrub signature.
        scrub_signature_pqc: &'a str,
    },
    /// Write back the `additional_scrubs` a pre-v53.1.4 door dropped
    /// (CIRISPersist#995 row 2).
    #[cfg(any(feature = "postgres", feature = "sqlite"))]
    RehydrateScrubs {
        /// The record whose hash the held row already binds.
        record: KeyRecord,
    },
}

/// When an [`PlannedKeyRecord::Insert`] finds its `key_id` held at write
/// time (a row that landed between the plan and the write).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnHeld {
    /// The held row must be byte-identical (same `persist_row_hash`); a
    /// differing one is [`Error::Conflict`].
    Conflict,
    /// The held row stays as it is (the genesis seed's `DO NOTHING`).
    Keep,
}

/// What an in-place rewrite re-asserts about the held row, atomically, at
/// write time (the `WHERE` of the SQL backends). The Ed25519 pubkey is
/// re-asserted by every guard.
// The supersede, replace and rehydrate shapes are written only by doors
// the SQL backends compile (`cfg(any(postgres, sqlite))`).
#[cfg_attr(not(any(feature = "postgres", feature = "sqlite")), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RewriteGuard {
    /// The held row is still self-signed (the scrub upgrade).
    SelfSigned,
    /// The held row is still the anchored version the policy was verified
    /// against (the canonical supersede).
    Anchored {
        /// That version's `persist_row_hash`.
        prior_hash: String,
    },
    /// The same pubkey, nothing else (the bundle-authorised re-anchor).
    SamePubkey,
}

/// **The plan's verdict for one key-record write**: exactly what the
/// executor stores. Every refusal has already been made.
// The supersede, replace and rehydrate shapes are written only by doors
// the SQL backends compile (`cfg(any(postgres, sqlite))`).
#[cfg_attr(not(any(feature = "postgres", feature = "sqlite")), allow(dead_code))]
#[derive(Debug, Clone)]
pub(crate) enum PlannedKeyRecord {
    /// A fresh row: `persist_row_hash` computed, `consent_role` in wire form.
    Insert {
        /// The record to insert.
        record: KeyRecord,
        /// A `key_id` held at write time.
        on_held: OnHeld,
    },
    /// Rewrite the whole registration of a held row in place (every column
    /// but the Ed25519 pubkey, `consent_role` and the trust overlays).
    Rewrite {
        /// The record to store.
        record: KeyRecord,
        /// What the write re-asserts.
        guard: RewriteGuard,
    },
    /// The rebind / invalid-replace: the held row's registration bytes go to
    /// `federation_key_registration_history` with its own hash and the kind,
    /// then the registration columns are rewritten — both only while the held
    /// row is still `existing_hash` (and self-signed, for a rebind).
    Replace {
        /// The record to store.
        record: KeyRecord,
        /// The held version the plan was made against.
        existing_hash: String,
        /// Which replacement.
        kind: super::types::KeyReplacementKind,
    },
    /// The hybrid completion of a held Ed25519-only row (only while its
    /// `pqc_completed_at` is still unset).
    CompletePqc {
        /// The held key.
        key_id: String,
        /// Its ML-DSA-65 public key.
        pubkey_ml_dsa_65_base64: String,
        /// The PQC scrub signature.
        scrub_signature_pqc: String,
        /// The completion instant (the receipt clock).
        completed_at: chrono::DateTime<chrono::Utc>,
        /// The completed record's `persist_row_hash`.
        persist_row_hash: String,
    },
    /// Write back `additional_scrubs` (only while the held row's hash is
    /// `record.persist_row_hash` and its scrub set is empty).
    RehydrateScrubs {
        /// The record, `persist_row_hash` computed.
        record: KeyRecord,
    },
}

impl PlannedKeyRecord {
    /// The key the write is about.
    #[must_use]
    pub(crate) fn key_id(&self) -> &str {
        match self {
            Self::Insert { record, .. }
            | Self::Rewrite { record, .. }
            | Self::Replace { record, .. }
            | Self::RehydrateScrubs { record } => &record.key_id,
            Self::CompletePqc { key_id, .. } => key_id,
        }
    }

    /// The refusal an executor reports when its write's atomic re-assertion
    /// matched `rows` rows instead of one (a concurrent mutation between the
    /// plan and the write): `None` when the write landed. One wording for
    /// every backend.
    #[must_use]
    pub(crate) fn raced(&self, rows: u64) -> Option<Error> {
        let kid = self.key_id();
        match self {
            // An insert that matched nothing is settled by the held row
            // ([`Self::insert_held`]), not here.
            Self::Insert { .. } => None,
            Self::Rewrite {
                guard: RewriteGuard::SamePubkey,
                ..
            } => (rows != 1).then(|| {
                Error::Backend(format!(
                    "reanchor {kid}: expected 1 row updated, got {rows}"
                ))
            }),
            _ if rows > 0 => None,
            Self::Rewrite {
                guard: RewriteGuard::SelfSigned,
                ..
            } => Some(Error::Conflict(format!(
                "adopt_scrub_upgrade {kid}: row changed concurrently"
            ))),
            Self::Rewrite { .. } => Some(Error::Conflict(format!(
                "supersede_canonical_record {kid}: row changed concurrently"
            ))),
            Self::Replace { kind, .. } => Some(Error::Conflict(format!(
                "{} key registration {kid}: row changed concurrently",
                kind.as_str()
            ))),
            Self::CompletePqc { .. } => Some(Error::Conflict(format!(
                "federation_keys row {kid} was concurrently completed"
            ))),
            Self::RehydrateScrubs { .. } => Some(Error::Conflict(format!(
                "rehydrate_dropped_key_scrubs {kid}: row changed concurrently"
            ))),
        }
    }

    /// An [`Self::Insert`] that found its `key_id` held at write time:
    /// `Ok(())` when the held row may stand (byte-identical, or
    /// [`OnHeld::Keep`]), else the conflict.
    pub(crate) fn insert_held(&self, held_hash: Option<&str>) -> Result<(), Error> {
        match self {
            Self::Insert {
                record,
                on_held: OnHeld::Conflict,
            } if held_hash.is_some_and(|h| h != record.persist_row_hash) => {
                Err(Error::Conflict(format!(
                    "key_id {} already exists with different content",
                    record.key_id
                )))
            }
            _ => Ok(()),
        }
    }
}

/// What [`plan_key_record_write`] decided.
#[derive(Debug, Clone)]
pub(crate) enum KeyRecordPlan {
    /// This node already holds exactly the record: nothing to write.
    Settled,
    /// Store this.
    Write(Box<PlannedKeyRecord>),
}

/// What a key-record write door did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyRecordWritten {
    /// The record (and its row) were written.
    Written,
    /// Already held exactly; nothing was written.
    Settled,
}

/// The two stored-column shapes every door checks before it writes: the
/// content hash is hex (the column is bytes) and the algorithm is hybrid.
fn check_key_record_columns(row: &KeyRecord, door: &str) -> Result<(), Error> {
    hex::decode(&row.original_content_hash)
        .map_err(|e| Error::InvalidArgument(format!("original_content_hash hex decode: {e}")))?;
    if row.algorithm != super::types::algorithm::HYBRID {
        return Err(Error::InvalidArgument(format!(
            "{door}algorithm must be 'hybrid' (got '{}')",
            row.algorithm
        )));
    }
    Ok(())
}

/// `consent_role`: the admissible-token gate (CC 3.4.7.2), then the wire
/// form (`'unregistered'` ⇔ `None`), so the hash is over what the read
/// surface returns.
fn admit_consent_role(row: &mut KeyRecord) -> Result<(), Error> {
    super::types::consent_role::check_admissible(row.consent_role.as_deref())?;
    row.consent_role = row
        .consent_role
        .as_deref()
        .and_then(super::types::consent_role::wire_from_stored)
        .map(str::to_owned);
    Ok(())
}

/// The insert doors' decision (`put_public_key`, the replicated `Insert`
/// arm): canonical at rest (#647), the envelope-attested roles lifted before
/// the role gates (#486), the 32-byte Ed25519 key (#275), CC 3.4.7.3 Clause A
/// on a local mint (#925), the hardware gate at receipt (#102, #901), the
/// consent-role token ahead of the four conferral walks (#365, #670), the
/// conferral gates, the stored-column shapes; then a held `key_id` settles
/// (byte-identical) or conflicts.
async fn plan_key_put(
    dir: &dyn super::FederationDirectory,
    mut row: KeyRecord,
    door: super::register::KeyDoor,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<KeyRecordPlan, Error> {
    super::canonical_at_rest::canonicalize_in_place(&mut row.registration_envelope)?;
    super::admission::lift_envelope_attested_roles(&mut row);
    super::register::validate_registration_pubkey(&row)?;
    if door == super::register::KeyDoor::LocalMint {
        super::register::check_node_identity_exclusive(&row)?;
    }
    dir.hardware_attestation_policy()
        .admit_key_record(&row, received_at)?;
    admit_consent_role(&mut row)?;
    super::admission::check_canonical_role_admission(dir, &row).await?;
    super::admission::check_infra_attest_role_admission(dir, &row).await?;
    super::admission::check_co_steward_role_admission(dir, &row).await?;
    super::admission::check_privileged_identity_type_admission(dir, &row).await?;
    row.persist_row_hash = super::types::compute_persist_row_hash(&row)?;
    check_key_record_columns(&row, "")?;
    match dir.lookup_public_key(&row.key_id).await? {
        Some(held) if held.persist_row_hash == row.persist_row_hash => Ok(KeyRecordPlan::Settled),
        Some(_) => Err(Error::Conflict(format!(
            "key_id {} already exists with different content",
            row.key_id
        ))),
        None => Ok(KeyRecordPlan::Write(Box::new(PlannedKeyRecord::Insert {
            record: row,
            on_held: OnHeld::Conflict,
        }))),
    }
}

/// The genesis seed's decision (CIRISPersist#347): every insert invariant
/// but the accord-holder fresh-nonce hardware gate — the pinned ceremony
/// bake IS the trust root, stale by design — and a held `key_id` is kept.
fn plan_key_seed(mut row: KeyRecord) -> Result<KeyRecordPlan, Error> {
    super::register::validate_registration_pubkey(&row)?;
    super::register::check_node_identity_exclusive(&row)?;
    check_key_record_columns(&row, "genesis seed ")?;
    admit_consent_role(&mut row)?;
    row.persist_row_hash = super::types::compute_persist_row_hash(&row)?;
    Ok(KeyRecordPlan::Write(Box::new(PlannedKeyRecord::Insert {
        record: row,
        on_held: OnHeld::Keep,
    })))
}

/// The scrub upgrade's decision (CIRISPersist#351): the incoming record is
/// granting-authority scrubbed; every gate the insert runs (the hardware
/// gate included, #543 H2 — this door can change `identity_type`); the held
/// row exists, keeps `node` (#925) and its Ed25519 pubkey, and is still
/// self-signed — an anchored one settles when byte-identical, else the
/// downgrade/replace is refused.
async fn plan_key_scrub_upgrade(
    dir: &dyn super::FederationDirectory,
    mut row: KeyRecord,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<KeyRecordPlan, Error> {
    super::admission::lift_envelope_attested_roles(&mut row);
    if row.scrub_key_id == row.key_id {
        return Err(Error::InvalidArgument(
            "adopt_scrub_upgrade requires a granting-authority record (scrub_key_id != key_id)"
                .into(),
        ));
    }
    super::register::validate_registration_pubkey(&row)?;
    super::register::check_node_identity_exclusive(&row)?;
    check_key_record_columns(&row, "adopt_scrub_upgrade ")?;
    dir.hardware_attestation_policy()
        .admit_key_record(&row, received_at)?;
    super::admission::check_canonical_role_admission(dir, &row).await?;
    super::admission::check_infra_attest_role_admission(dir, &row).await?;
    super::admission::check_co_steward_role_admission(dir, &row).await?;
    super::admission::check_privileged_identity_type_admission(dir, &row).await?;
    row.persist_row_hash = super::types::compute_persist_row_hash(&row)?;
    let existing = dir.lookup_public_key(&row.key_id).await?.ok_or_else(|| {
        Error::InvalidArgument(format!(
            "adopt_scrub_upgrade: no existing row for {} — use register_federation_key",
            row.key_id
        ))
    })?;
    super::register::check_node_identity_unchanged(&existing, &row)?;
    if existing.pubkey_ed25519_base64 != row.pubkey_ed25519_base64 {
        return Err(Error::Conflict(format!(
            "adopt_scrub_upgrade {}: pubkey change refused (different identity)",
            row.key_id
        )));
    }
    if existing.scrub_key_id != existing.key_id {
        return if existing.persist_row_hash == row.persist_row_hash {
            Ok(KeyRecordPlan::Settled)
        } else {
            Err(Error::Conflict(format!(
                "adopt_scrub_upgrade {}: already anchored to a different record \
                 (downgrade/replace refused)",
                row.key_id
            )))
        };
    }
    Ok(KeyRecordPlan::Write(Box::new(PlannedKeyRecord::Rewrite {
        record: row,
        guard: RewriteGuard::SelfSigned,
    })))
}

/// The canonical supersede's decision (CIRISPersist#405): an anchored
/// successor of an anchored row with the same pubkeys and `node` (#925); a
/// byte-identical re-offer settles there, ahead of every verify (#672); then
/// the role gates on the successor (#543 H2: rotation is not a
/// role-laundering path) and the supersede policy re-verified from this
/// node's own state (canonical scope, signed-envelope monotonicity, m-of-n).
#[cfg(any(feature = "postgres", feature = "sqlite"))]
async fn plan_key_supersede(
    dir: &dyn super::FederationDirectory,
    mut row: KeyRecord,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<KeyRecordPlan, Error> {
    super::register::validate_registration_pubkey(&row)?;
    super::register::check_node_identity_exclusive(&row)?;
    check_key_record_columns(&row, "supersede_canonical_record ")?;
    if row.scrub_key_id == row.key_id {
        return Err(Error::InvalidArgument(
            "supersede_canonical_record requires an anchor-scrubbed record \
             (scrub_key_id != key_id)"
                .into(),
        ));
    }
    let existing = dir.lookup_public_key(&row.key_id).await?.ok_or_else(|| {
        Error::InvalidArgument(format!(
            "supersede_canonical_record: no existing row for {}",
            row.key_id
        ))
    })?;
    super::register::check_node_identity_unchanged(&existing, &row)?;
    if existing.pubkey_ed25519_base64 != row.pubkey_ed25519_base64
        || existing.pubkey_ml_dsa_65_base64 != row.pubkey_ml_dsa_65_base64
    {
        return Err(Error::Conflict(format!(
            "supersede_canonical_record {}: pubkey change refused (different identity)",
            row.key_id
        )));
    }
    if existing.scrub_key_id == existing.key_id {
        return Err(Error::Conflict(format!(
            "supersede_canonical_record {}: existing row is self-signed (use adopt_scrub_upgrade)",
            row.key_id
        )));
    }
    // A byte-identical re-offer of the held row settles ahead of every verify
    // (the #672 rule): the held row already passed this door.
    row.persist_row_hash = super::types::compute_persist_row_hash(&row)?;
    if existing.persist_row_hash == row.persist_row_hash {
        return Ok(KeyRecordPlan::Settled);
    }
    dir.hardware_attestation_policy()
        .admit_key_record(&row, received_at)?;
    super::admission::check_infra_attest_role_admission(dir, &row).await?;
    super::admission::check_co_steward_role_admission(dir, &row).await?;
    super::admission::check_privileged_identity_type_admission(dir, &row).await?;
    if !super::register::verify_canonical_supersede(dir, &existing, &row).await? {
        return Err(Error::Conflict(format!(
            "supersede_canonical_record {}: supersede policy refused",
            row.key_id
        )));
    }
    Ok(KeyRecordPlan::Write(Box::new(PlannedKeyRecord::Rewrite {
        record: row,
        guard: RewriteGuard::Anchored {
            prior_hash: existing.persist_row_hash,
        },
    })))
}

/// The rebind / invalid-replace decision: the shared pre-check
/// (`register::prepare_rebind` / `prepare_invalid_replace`) builds the row
/// to write from the STORED row; a byte-identical one settles.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
async fn plan_key_replace(
    dir: &dyn super::FederationDirectory,
    row: KeyRecord,
    kind: super::types::KeyReplacementKind,
) -> Result<KeyRecordPlan, Error> {
    use super::register::RebindPrepared;
    use super::types::KeyReplacementKind;
    let signed = super::SignedKeyRecord { record: row };
    let prepared = match kind {
        KeyReplacementKind::Rebind => super::register::prepare_rebind(dir, signed).await?,
        _ => super::register::prepare_invalid_replace(dir, signed).await?,
    };
    match prepared {
        RebindPrepared::Unchanged => Ok(KeyRecordPlan::Settled),
        RebindPrepared::Replace { new, existing_hash } => {
            check_key_record_columns(&new, "")?;
            Ok(KeyRecordPlan::Write(Box::new(PlannedKeyRecord::Replace {
                record: *new,
                existing_hash,
                kind,
            })))
        }
    }
}

/// The genesis re-anchor's decision (CIRISPersist#490): the bundle quorum
/// re-verified from this node's own roster and pins; the record one the
/// bundle carries; the adopt-path gates; the held row exists, keeps `node`
/// (#925) and its Ed25519 pubkey, and the record is strictly newer
/// (`valid_from`, anti-rollback).
async fn plan_key_reanchor(
    dir: &dyn super::FederationDirectory,
    mut row: KeyRecord,
    bundle: &super::genesis::GenesisBundle,
) -> Result<KeyRecordPlan, Error> {
    super::genesis::verify_bundle_quorum(dir, bundle).await?;
    if !bundle.serve_nodes.iter().any(|sn| {
        sn.record.persist_row_hash == row.persist_row_hash
            && sn.record.key_id == row.key_id
            && sn.record.registration_envelope == row.registration_envelope
    }) {
        return Err(Error::GenesisBundleInvalid {
            detail: format!(
                "re-anchor record {} is not carried by the verified bundle",
                row.key_id
            ),
        });
    }
    super::admission::lift_envelope_attested_roles(&mut row);
    super::register::validate_registration_pubkey(&row)?;
    super::register::check_node_identity_exclusive(&row)?;
    super::admission::check_canonical_role_admission(dir, &row).await?;
    super::admission::check_infra_attest_role_admission(dir, &row).await?;
    super::admission::check_co_steward_role_admission(dir, &row).await?;
    super::admission::check_privileged_identity_type_admission(dir, &row).await?;
    row.persist_row_hash = super::types::compute_persist_row_hash(&row)?;
    let existing =
        dir.lookup_public_key(&row.key_id)
            .await?
            .ok_or_else(|| Error::GenesisBundleInvalid {
                detail: format!("re-anchor target {} has no existing row", row.key_id),
            })?;
    super::register::check_node_identity_unchanged(&existing, &row)?;
    if existing.pubkey_ed25519_base64 != row.pubkey_ed25519_base64 {
        return Err(Error::GenesisBundleInvalid {
            detail: format!("re-anchor {}: pubkey change refused", row.key_id),
        });
    }
    // Compared at the substrate's signed-instant resolution
    // (`truncate_to_substrate_resolution`), on both sides: postgres holds the
    // anchored instant rounded, so a nanosecond bundle record read as newer
    // than itself there and re-anchored twice (v60.0.0, found by I1189 on
    // postgres). The bake door's pre-check compares the same way (I1191).
    use super::admission::truncate_to_substrate_resolution as at_resolution;
    if at_resolution(row.valid_from) <= at_resolution(existing.valid_from) {
        return Err(Error::GenesisBundleInvalid {
            detail: format!(
                "re-anchor {}: valid_from not newer than anchored — rollback refused",
                row.key_id
            ),
        });
    }
    hex::decode(&row.original_content_hash)
        .map_err(|e| Error::InvalidArgument(format!("original_content_hash hex: {e}")))?;
    Ok(KeyRecordPlan::Write(Box::new(PlannedKeyRecord::Rewrite {
        record: row,
        guard: RewriteGuard::SamePubkey,
    })))
}

/// The hybrid completion's decision (CIRISPersist#657): the held row exists
/// and is not yet complete; verify-before-mutation over the row AS IT WOULD
/// BE STORED (the envelope names THIS ML-DSA key, #659, and the row
/// verifies hybrid-Strict with it); the completion instant is the receipt
/// clock, and the hash is the completed record's.
async fn plan_key_attach_pqc(
    dir: &dyn super::FederationDirectory,
    key_id: &str,
    pubkey_ml_dsa_65_base64: &str,
    scrub_signature_pqc: &str,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<KeyRecordPlan, Error> {
    let mut row = dir.lookup_public_key(key_id).await?.ok_or_else(|| {
        Error::InvalidArgument(format!("federation_keys row {key_id} does not exist"))
    })?;
    if row.is_pqc_complete() {
        return Err(Error::Conflict(format!(
            "federation_keys row {key_id} is already PQC-complete"
        )));
    }
    row.pubkey_ml_dsa_65_base64 = Some(pubkey_ml_dsa_65_base64.to_owned());
    row.scrub_signature_pqc = Some(scrub_signature_pqc.to_owned());
    super::admission::check_key_pqc_attachment(dir, &row).await?;
    row.pqc_completed_at = Some(received_at);
    row.persist_row_hash = String::new();
    let persist_row_hash = super::types::compute_persist_row_hash(&row)?;
    Ok(KeyRecordPlan::Write(Box::new(
        PlannedKeyRecord::CompletePqc {
            key_id: key_id.to_owned(),
            pubkey_ml_dsa_65_base64: pubkey_ml_dsa_65_base64.to_owned(),
            scrub_signature_pqc: scrub_signature_pqc.to_owned(),
            completed_at: received_at,
            persist_row_hash,
        },
    )))
}

/// v60.0.0 (CIRISPersist#934 step 3) — **the key-record write doors'
/// decision**, once for every backend: each door's gates, in the order its
/// three copies ran them, and the write they lead to. `received_at` is the
/// receiving node's clock (the hardware gate's freshness, the hybrid
/// completion's instant). The `key:record:v1` row is not planned here: it is
/// a pure function of the record AS STORED ([`key_record_row_step`]), so the
/// executor derives it after its write, in the same transaction.
pub(crate) async fn plan_key_record_write(
    dir: &dyn super::FederationDirectory,
    write: KeyRecordWrite<'_>,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<KeyRecordPlan, Error> {
    // Each arm propagates, so the parity scan follows it (#934).
    Ok(match write {
        KeyRecordWrite::Put { record, door } => {
            plan_key_put(dir, record, door, received_at).await?
        }
        KeyRecordWrite::SeedGenesis { record } => plan_key_seed(record)?,
        KeyRecordWrite::ScrubUpgrade { record } => {
            plan_key_scrub_upgrade(dir, record, received_at).await?
        }
        #[cfg(any(feature = "postgres", feature = "sqlite"))]
        KeyRecordWrite::SupersedeCanonical { record } => {
            plan_key_supersede(dir, record, received_at).await?
        }
        #[cfg(any(feature = "postgres", feature = "sqlite"))]
        KeyRecordWrite::Rebind { record } => {
            plan_key_replace(dir, record, super::types::KeyReplacementKind::Rebind).await?
        }
        #[cfg(any(feature = "postgres", feature = "sqlite"))]
        KeyRecordWrite::InvalidReplace { record } => {
            plan_key_replace(
                dir,
                record,
                super::types::KeyReplacementKind::InvalidReplaced,
            )
            .await?
        }
        KeyRecordWrite::Reanchor { record, bundle } => {
            plan_key_reanchor(dir, record, bundle).await?
        }
        KeyRecordWrite::AttachPqc {
            key_id,
            pubkey_ml_dsa_65_base64,
            scrub_signature_pqc,
        } => {
            plan_key_attach_pqc(
                dir,
                key_id,
                pubkey_ml_dsa_65_base64,
                scrub_signature_pqc,
                received_at,
            )
            .await?
        }
        #[cfg(any(feature = "postgres", feature = "sqlite"))]
        KeyRecordWrite::RehydrateScrubs { mut record } => {
            record.persist_row_hash = super::types::compute_persist_row_hash(&record)?;
            KeyRecordPlan::Write(Box::new(PlannedKeyRecord::RehydrateScrubs { record }))
        }
    })
}

/// The door every backend's key-record write is: plan, then store.
pub(crate) async fn key_record_write_planned<D>(
    dir: &D,
    write: KeyRecordWrite<'_>,
) -> Result<KeyRecordWritten, Error>
where
    D: KeyPlaneStore,
{
    match plan_key_record_write(dir, write, chrono::Utc::now()).await? {
        KeyRecordPlan::Settled => Ok(KeyRecordWritten::Settled),
        KeyRecordPlan::Write(planned) => {
            dir.store_planned_key_record(*planned).await?;
            Ok(KeyRecordWritten::Written)
        }
    }
}

/// The genesis seed of the HUMANITY_ACCORD holder rows (CIRISPersist#347),
/// one planned insert per baked record, each in its own write.
pub(crate) async fn seed_genesis_accord_holders_planned<D>(
    dir: &D,
    records: &[super::SignedKeyRecord],
) -> Result<(), Error>
where
    D: KeyPlaneStore,
{
    for sr in records {
        key_record_write_planned(
            dir,
            KeyRecordWrite::SeedGenesis {
                record: sr.record.clone(),
            },
        )
        .await?;
    }
    Ok(())
}

/// v60.0.0 (CIRISPersist#934 step 3; v13.0.0 CIRISPersist#371) — **the
/// upgrade-aware replicated key apply**, once for every backend: the
/// classification is
/// [`plan_replicated_key_apply`](super::register::plan_replicated_key_apply)'s,
/// and each arm is one of the key-record write doors above. Refusals are
/// outcomes, not errors; a `Conflict` from the store step (the row changed
/// between plan and write) is `StoreConflict`, fail-closed and re-offerable;
/// a CC 3.4.7.3 Clause A / `node`-immutability refusal on a rewrite is typed
/// (#925 review H3/M5), so the replication cursor records it and moves on.
#[cfg(any(feature = "postgres", feature = "sqlite"))]
pub(crate) async fn apply_replicated_key_record_planned<D>(
    dir: &D,
    record: super::SignedKeyRecord,
) -> Result<super::register::ReplicatedKeyOutcome, Error>
where
    D: KeyPlaneStore,
{
    use super::register::{KeyRefusalReason, ReplicatedKeyOutcome as O, ReplicatedKeyPlan as P};
    const RACED: O = O::Refused {
        reason: KeyRefusalReason::StoreConflict,
    };
    let typed = |e: Error| -> Result<O, Error> {
        match e {
            Error::NodeIdentityNotExclusive { .. } => Ok(O::Refused {
                reason: KeyRefusalReason::NodeIdentityFused,
            }),
            Error::NodeIdentityImmutable { .. } => Ok(O::Refused {
                reason: KeyRefusalReason::NodeIdentityChanged,
            }),
            Error::Conflict(_) => Ok(RACED),
            e => Err(e),
        }
    };
    let record = record.record;
    let (write, written) = match super::register::plan_replicated_key_apply(dir, &record).await? {
        P::Unchanged => return Ok(O::Unchanged),
        P::Refused { reason } => return Ok(O::Refused { reason }),
        P::Insert => {
            // v21.0.0 (CIRISPersist#502 E2) — the Strict hybrid PoP gate on
            // a replicated first sight; v54.1.0 (#1042) — a verify failure
            // is a TYPED refusal (retryable `attester_key_unknown` apart from
            // terminal `unverifiable_signature`). Nothing is written.
            if !super::register::record_is_role_gated(&record) {
                if let Err(e) = super::verify_key_registration(dir, &record).await {
                    return Ok(O::Refused {
                        reason: super::register::key_refusal_of_verify_error(e)?,
                    });
                }
            }
            let write = KeyRecordWrite::Put {
                record,
                door: super::register::KeyDoor::ReplicatedInsert,
            };
            return match key_record_write_planned(dir, write).await {
                Ok(_) => Ok(O::Inserted),
                Err(Error::Conflict(_)) => Ok(RACED),
                Err(e) => Err(e),
            };
        }
        P::RehydrateScrubs => (
            KeyRecordWrite::RehydrateScrubs { record },
            O::ScrubsRehydrated,
        ),
        P::Upgrade => (KeyRecordWrite::ScrubUpgrade { record }, O::Upgraded),
        P::Supersede => (KeyRecordWrite::SupersedeCanonical { record }, O::Superseded),
        P::Rebind => (KeyRecordWrite::Rebind { record }, O::Rebound),
        P::ReplaceInvalid => (
            KeyRecordWrite::InvalidReplace { record },
            O::InvalidReplaced,
        ),
    };
    match key_record_write_planned(dir, write).await {
        Ok(KeyRecordWritten::Written) => Ok(written),
        Ok(KeyRecordWritten::Settled) => Ok(O::Unchanged),
        Err(e) => typed(e),
    }
}

/// Test support: the canonical supersede door alone (the replicated apply
/// reaches it only through its classification), outcome as the apply reports
/// it.
#[cfg(all(test, any(feature = "postgres", feature = "sqlite")))]
pub(crate) async fn supersede_canonical_planned<D>(
    dir: &D,
    record: super::SignedKeyRecord,
) -> Result<super::register::ReplicatedKeyOutcome, Error>
where
    D: KeyPlaneStore,
{
    use super::register::ReplicatedKeyOutcome as O;
    let write = KeyRecordWrite::SupersedeCanonical {
        record: record.record,
    };
    Ok(match key_record_write_planned(dir, write).await? {
        KeyRecordWritten::Written => O::Superseded,
        KeyRecordWritten::Settled => O::Unchanged,
    })
}

/// What a key's `key:record:v1` row becomes after a write to its record.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum KeyRecordRowStep {
    /// The key's current row is already the row its record plans to.
    Keep,
    /// The key's rows leave the plane; `Some(row)` lands in their place (and
    /// the projection points at it), `None` when the record does not verify
    /// (held without a row; the rebuild gate names it) or the key is gone.
    Replace(Option<Box<Attestation>>),
}

/// v60.0.0 (CIRISPersist#934 step 3; v58.0.0 CIRISPersist#991, CC 3.1.3) —
/// **the `key:record:v1` row follows its record**: the row the record AS
/// STORED plans to ([`key_record_row_if_verifiable`]: proof of possession,
/// or `held_signer`, the base signer's held keys), given what the
/// projection's `attestation_id` names today. Every backend's executor reads
/// `stored` back inside its write's transaction (so the row is over the
/// precision that backend keeps) and applies the step there.
#[must_use]
pub(crate) fn key_record_row_step(
    stored: Option<&KeyRecord>,
    current: Option<&str>,
    held_signer: &HeldSigner,
) -> KeyRecordRowStep {
    let planned = stored.and_then(|record| key_record_row_if_verifiable(record, held_signer));
    match (current, planned) {
        (Some(cur), Some(row)) if cur == row.attestation_id => KeyRecordRowStep::Keep,
        (_, planned) => KeyRecordRowStep::Replace(planned.map(Box::new)),
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  identity:occurrence:v1
// ─────────────────────────────────────────────────────────────────────────

/// The signed occurrence as the row carries it: the occurrence (without its
/// recomputed `persist_row_hash`), its signer, the producer's signed envelope
/// and the detached hybrid signature over it.
pub fn occurrence_object(
    signed: &super::types::SignedIdentityOccurrence,
) -> Result<serde_json::Value, Error> {
    let mut v = serde_json::to_value(signed)
        .map_err(|e| Error::Backend(format!("identity occurrence encode: {e}")))?;
    if let Some(inner) = v
        .get_mut("identity_occurrence")
        .and_then(serde_json::Value::as_object_mut)
    {
        inner.remove("persist_row_hash");
    }
    Ok(v)
}

/// The `identity:occurrence:v1` row of a signed occurrence (pure, no gate):
/// attested by its signer (the identity or a live occurrence of it, CC 3.3.6)
/// about the identity, signed with the occurrence's own detached hybrid
/// signature over its signed envelope, asserted at the occurrence's own
/// `asserted_at`. Refused when the signature is Ed25519-only: a plane row's
/// signature is hybrid (CC 2.4).
pub fn occurrence_row(
    signed: &super::types::SignedIdentityOccurrence,
) -> Result<Attestation, Error> {
    let occurrence = &signed.identity_occurrence;
    let Some(pqc) = signed.signature.mldsa65_signature_base64.clone() else {
        return Err(Error::SignatureInvalid(format!(
            "identity:occurrence:v1 {}/{}: Ed25519-only signature — a plane row's signature is \
             hybrid (CC 2.4)",
            occurrence.identity_key_id, occurrence.occurrence_key_id
        )));
    };
    plane_row(
        KeyPlaneFamily::IdentityOccurrence,
        &signed.attesting_key_id,
        &occurrence.identity_key_id,
        occurrence_object(signed)?,
        occurrence.asserted_at,
        PlaneSignature {
            scrub_key_id: signed.attesting_key_id.clone(),
            classical: signed.signature.ed25519_signature_base64.clone(),
            pqc: Some(pqc),
            scrub_timestamp: occurrence.asserted_at,
            pqc_completed_at: Some(occurrence.asserted_at),
        },
    )
}

/// The row of a held signed occurrence, or `None` (held without a row; the
/// rebuild gate names it) when it is Ed25519-only.
#[must_use]
pub fn occurrence_row_if_hybrid(
    signed: &super::types::SignedIdentityOccurrence,
) -> Option<Attestation> {
    occurrence_row(signed)
        .map_err(|e| {
            tracing::debug!(
                identity_key_id = %signed.identity_occurrence.identity_key_id,
                occurrence_key_id = %signed.identity_occurrence.occurrence_key_id,
                refusal = e.kind(),
                "occurrence held without an identity:occurrence:v1 row: {e}"
            );
        })
        .ok()
}

/// **The projection** of an `identity:occurrence:v1` row: the signed
/// occurrence it carries, `persist_row_hash` recomputed. `None` for any other
/// row.
#[must_use]
pub fn occurrence_of_row(row: &Attestation) -> Option<super::types::SignedIdentityOccurrence> {
    let mut object = plane_object(row, KeyPlaneFamily::IdentityOccurrence)?.clone();
    object
        .get_mut("identity_occurrence")?
        .as_object_mut()?
        .insert(
            "persist_row_hash".to_owned(),
            serde_json::Value::String(String::new()),
        );
    let mut signed: super::types::SignedIdentityOccurrence = serde_json::from_value(object).ok()?;
    signed.identity_occurrence.persist_row_hash =
        super::types::compute_persist_row_hash(&signed.identity_occurrence).ok()?;
    Some(signed)
}

/// v58.0.0 (CIRISPersist#991, CC 3.3.6) — the occurrence revocation a
/// `withdraws` row is, when its target is a held `identity:occurrence:v1` row:
/// the pair, revoked and effective at the withdrawal's signed instant, its
/// `withdrawal_reason`. `None` for any other row (or an unheld target, whose
/// withdrawal the read side defers like every other).
pub(crate) async fn occurrence_withdrawal_of<D>(
    dir: &D,
    row: &Attestation,
) -> Result<Option<super::types::IdentityOccurrenceRevocation>, Error>
where
    D: super::FederationDirectory + ?Sized,
{
    if row.attestation_type != attestation_type::WITHDRAWS {
        return Ok(None);
    }
    let Some(target_id) =
        super::precedence::references_attestation_id_from_envelope(&row.attestation_envelope)
    else {
        return Ok(None);
    };
    let Some(target) = dir.get_attestation(target_id).await? else {
        return Ok(None);
    };
    let Some(signed) = occurrence_of_row(&target) else {
        return Ok(None);
    };
    Ok(Some(super::types::IdentityOccurrenceRevocation {
        identity_key_id: signed.identity_occurrence.identity_key_id,
        occurrence_key_id: signed.identity_occurrence.occurrence_key_id,
        revoked_at: row.asserted_at,
        effective_at: row.asserted_at,
        reason: row
            .attestation_envelope
            .get("withdrawal_reason")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        witness_set: Vec::new(),
        persist_row_hash: String::new(),
    }))
}

/// v59.0.0 (CIRISPersist#1104; for CIRISEdge) — **the one predicate**: does
/// `row` revoke an occurrence, and which? `Some((identity, occurrence))` for
/// a `withdraws` whose target is a held `identity:occurrence:v1` row, and for
/// an `identity:occurrence_revocation:v1` carrier; `None` for any other row
/// (or a `withdraws` whose target this node does not hold). Whether the row
/// is ADMITTED is the door's; this names what it would revoke.
///
/// # Errors
///
/// A backend failure reading the `withdraws` target.
pub async fn occurrence_revoked_by<D>(
    dir: &D,
    row: &Attestation,
) -> Result<Option<(String, String)>, Error>
where
    D: super::FederationDirectory + ?Sized,
{
    if let Some(framed) = super::occurrence_revocation_carrier::carrier_of_row(row) {
        return Ok(framed
            .revocation()
            .ok()
            .map(|r| (r.identity_key_id, r.occurrence_key_id)));
    }
    Ok(occurrence_withdrawal_of(dir, row)
        .await?
        .map(|r| (r.identity_key_id, r.occurrence_key_id)))
}

/// The rebuild gate's rendering of one SIGNED `federation_identity_occurrences`
/// row: the signed occurrence and the `attestation_id` it names. A
/// trusted-local (unsigned) occurrence is this node's own self-write, not a
/// claim on the plane, and is not part of the projection.
#[must_use]
pub fn render_occurrence_projection(
    signed: &super::types::SignedIdentityOccurrence,
    attestation_id: Option<&str>,
) -> String {
    let mut v = serde_json::to_value(signed).unwrap_or(serde_json::Value::Null);
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

/// The from-rows rebuild of the signed `federation_identity_occurrences`, in
/// `(identity_key_id, occurrence_key_id)` order.
#[must_use]
pub fn occurrence_projection_rebuild(
    live: Vec<(super::types::SignedIdentityOccurrence, Option<String>)>,
    rows: &[Attestation],
) -> super::silo_projection::ProjectionRebuild {
    let key = |s: &super::types::SignedIdentityOccurrence| {
        (
            s.identity_occurrence.identity_key_id.clone(),
            s.identity_occurrence.occurrence_key_id.clone(),
        )
    };
    let mut live: Vec<((String, String), String)> = live
        .into_iter()
        .map(|(s, a)| (key(&s), render_occurrence_projection(&s, a.as_deref())))
        .collect();
    live.sort();
    let mut rebuilt: Vec<((String, String), String)> = rows
        .iter()
        .filter_map(|row| {
            occurrence_of_row(row).map(|s| {
                (
                    key(&s),
                    render_occurrence_projection(&s, Some(&row.attestation_id)),
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
    // A byte-identical re-offer of a held row settles ahead of every verify
    // (the #672 rule): one signed object, one id, one row.
    if let Some(held) = dir.get_attestation(&row.attestation_id).await? {
        if held.persist_row_hash == super::types::compute_persist_row_hash(row)? {
            return Ok(KeyPlaneApplied::Unchanged);
        }
    }
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
            // v59.0.0 (CIRISPersist#1103, CC 2.6.8) — first contact: the id
            // names its own key (a held key under a non-matching id is
            // grandfathered where it is, never introduced again).
            super::register::check_key_id_fingerprint(dir, &record).await?;
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
            if is_held_revocation(dir, &revocation).await? {
                return Ok(KeyPlaneApplied::Unchanged);
            }
            dir.put_revocation(super::SignedRevocation { revocation })
                .await?;
            Ok(KeyPlaneApplied::Changed)
        }
        Some(KeyPlaneFamily::IdentityOccurrence) => {
            let signed = occurrence_of_row(row).ok_or_else(|| {
                Error::malformed_row(
                    "identity_occurrence",
                    super::malformed_row::ENVELOPE_MEMBER_INVALID,
                    format!(
                        "identity:occurrence:v1 row {} carries no readable \
                         `{IDENTITY_OCCURRENCE_MEMBER}`",
                        row.attestation_id
                    ),
                )
            })?;
            check_canonical_plane_row(row, &occurrence_row(&signed)?)?;
            let held = dir
                .list_signed_identity_occurrences_for(&signed.identity_occurrence.identity_key_id)
                .await?
                .into_iter()
                .any(|h| h == signed);
            if held {
                return Ok(KeyPlaneApplied::Unchanged);
            }
            dir.put_identity_occurrence(signed).await?;
            Ok(KeyPlaneApplied::Changed)
        }
        None => Err(Error::InvalidArgument(format!(
            "row {} is not a key-plane row",
            row.attestation_id
        ))),
    }
}

/// v58.0.0 (CIRISPersist#991) — every key record on the plane, as a peer pulls
/// it: the `key:record:v1` rows of the attestation stream, paged to the end.
/// A key held without a row (it verifies under neither rule) is not on the
/// plane and is not here.
pub async fn key_records_on_the_plane(
    dir: &dyn super::FederationDirectory,
) -> Result<Vec<KeyRecord>, Error> {
    const PAGE: u32 = 1_000;
    let mut out = Vec::new();
    let mut since = None;
    loop {
        let page = dir.list_attestations_since(since.clone(), PAGE).await?;
        let Some(last) = page.last() else { break };
        since = Some(last.resume_pair());
        let full = page.len() as u32 == PAGE;
        out.extend(
            page.iter()
                .filter_map(|s| key_record_of_row(&s.attestation)),
        );
        if !full {
            break;
        }
    }
    Ok(out)
}

/// Test support: the key plane as a replicating peer pulls it — through the
/// attestation stream (`list_attestations_since`), the framed key-plane
/// cursors being retired in v58.0.0. Compiled under `test-anchor` too: the
/// `*_invariants` modules consumers drive (e.g. `key_grant_invariants`) call it.
#[cfg(any(test, feature = "test-anchor"))]
// The no-backend builds hold only the memory backend, whose witnesses read
// the plane directly; the served-row reads are the SQL tests' fixtures.
// Under `test-anchor` without `test`, only the consumer-driven invariants
// call in, and they read occurrences alone.
#[cfg_attr(
    any(not(test), not(any(feature = "sqlite", feature = "postgres"))),
    allow(dead_code)
)]
pub(crate) mod test_support {
    use super::super::types::{ServedIdentityOccurrence, ServedKeyRecord};
    use super::super::{Error, FederationDirectory};

    async fn all_rows(
        d: &dyn FederationDirectory,
    ) -> Result<Vec<super::super::types::ServedAttestation>, Error> {
        let mut out = Vec::new();
        let mut since = None;
        loop {
            let page = d.list_attestations_since(since.clone(), 1_000).await?;
            let Some(last) = page.last() else { break };
            since = Some(last.resume_pair());
            let n = page.len();
            out.extend(page);
            if n < 1_000 {
                break;
            }
        }
        Ok(out)
    }

    /// Every `key:record:v1` row served past `since` — `(admitted_at, key_id)`
    /// of the row's serve position — as the record it carries.
    pub(crate) async fn served_key_records(
        d: &dyn FederationDirectory,
        since: Option<(chrono::DateTime<chrono::Utc>, String)>,
        limit: u32,
    ) -> Result<Vec<ServedKeyRecord>, Error> {
        let mut out: Vec<ServedKeyRecord> = all_rows(d)
            .await?
            .into_iter()
            .filter_map(|s| {
                super::key_record_of_row(&s.attestation).map(|record| ServedKeyRecord {
                    record,
                    admitted_at: s.admitted_at,
                })
            })
            .filter(|s| {
                since
                    .as_ref()
                    .is_none_or(|c| (s.admitted_at, s.record.key_id.clone()) > *c)
            })
            .collect();
        out.sort_by_key(ServedKeyRecord::resume_pair);
        out.truncate(limit as usize);
        Ok(out)
    }

    /// Every `key:revocation:v1` row served, as the revocation it carries.
    pub(crate) async fn served_revocations(
        d: &dyn FederationDirectory,
        limit: u32,
    ) -> Result<Vec<super::super::types::ServedRevocation>, Error> {
        let mut out: Vec<super::super::types::ServedRevocation> = all_rows(d)
            .await?
            .into_iter()
            .filter_map(|s| {
                super::revocation_of_row(&s.attestation).map(|revocation| {
                    super::super::types::ServedRevocation {
                        revocation,
                        admitted_at: s.admitted_at,
                    }
                })
            })
            .collect();
        out.truncate(limit as usize);
        Ok(out)
    }

    /// Every `identity:occurrence:v1` row served, as the signed occurrence it
    /// carries.
    pub(crate) async fn served_identity_occurrences(
        d: &dyn FederationDirectory,
        limit: u32,
    ) -> Result<Vec<ServedIdentityOccurrence>, Error> {
        let mut out: Vec<ServedIdentityOccurrence> = all_rows(d)
            .await?
            .into_iter()
            .filter_map(|s| {
                super::occurrence_of_row(&s.attestation).map(|occurrence| {
                    ServedIdentityOccurrence {
                        occurrence,
                        admitted_at: s.admitted_at,
                    }
                })
            })
            .collect();
        out.truncate(limit as usize);
        Ok(out)
    }
}
