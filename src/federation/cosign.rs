//! v61.3.0 (CIRISPersist#1252; CC 3.3.4 step 2, CC 3.1.3 `cosign:{state}`,
//! CC 2.4, CC 4.5.13; `CLM-cosign-collection-held`) — **the cosign hold.**
//!
//! A widening or removal of a quorum room (or family) needs the signatures
//! its `consensus_protocol` counts. Before this cut the typed door refused an
//! event that arrived with too few of them, and nothing collected the rest:
//! a room of three or more could not widen or remove inside the mesh. Now an
//! event whose ONLY refusal is the consensus shortfall is HELD, and its
//! cosignatures are collected as rows until the protocol is met.
//!
//! # When an event is held
//!
//! Only when every condition holds ([`hold`]):
//!
//! - the standing verdict is [`StandingVerdict::ConsensusShort`]
//!   (`roster_event_verdict`): detected structurally, every signer an ACTIVE
//!   member at the event's signed instant, the last-founder rule met as if
//!   admitted; and every later check of the door is met too (the member's
//!   acceptance of a growth, the infrastructure founder gates, the steward
//!   binding). Any other refusal refuses exactly as before: same error, same
//!   Python type.
//! - the door is the LOCAL door (not a replicated apply, not this module's
//!   own executor), on the node that speaks for the primary signer
//!   ([`self_collective::speaks_for`](super::self_collective::speaks_for)).
//!   A replicated under-signed event keeps its refusal: only the primary's
//!   node mints the pending row, and every other node carries its bytes.
//! - the primary has no other open pending event in the group (one open
//!   proposal per proposer, as on the self roster; V214's partial UNIQUE).
//!
//! The door then returns [`Error::RosterChangeNotLanded`]
//! (`federation_roster_change_not_landed`) and nothing changed on the roster.
//!
//! # The rows (`cosign:{state}`, CC 3.1.3)
//!
//! | row | dimension | attester → attested | id | carries |
//! |---|---|---|---|---|
//! | pending | [`DIMENSION_PENDING`] | primary → the member | the quorum key | [`PENDING_MEMBER`]: the event with no cosignature; the row's scrub is the primary's own signature |
//! | signature | [`DIMENSION_SIGNATURE`] | cosigner → the member | `sha256(domain ‖ quorum key ‖ signer)` | [`SIGNATURE_MEMBER`]: the quorum key, the signer and the unsigned event; exactly one `additional_scrubs` entry, the signer's hybrid signature over the event's signing bytes |
//!
//! **The quorum key** ([`quorum_key_of`]) is
//! `sha256("ciris-persist/cosign-pending/v1" ‖ JCS(the event with no
//! signature in it))`, the primary's included, as the key plane names a
//! minted row (first 16 bytes as a UUID). It names the act, not a signature
//! set: two nodes that assembled the act from different sufficient subsets,
//! or kept different randomised ML-DSA bytes, name it alike (CC 2.6.1.8,
//! built so v62 changes the encoding and not the mechanism).
//!
//! A cosignature is over the event's own signing bytes, the same bytes the
//! primary signed. A vote signed over its own row (the `objection:assent`
//! family) is never read as one.
//!
//! # The executor
//!
//! [`execute_for`] unions the held signature rows by signer (deterministic,
//! by key id), offers the merged event through the SAME typed door, and the
//! event lands as the existing widening or removal row. It runs after a cosign
//! row is admitted (the attestation door's hook) and in the sweep
//! [`execute_due`] (`Engine::execute_cosign_due`), which also expires.
//!
//! # The window (CC 3.3.4, 4.5.13)
//!
//! The single number the governance table names on `community_invite` /
//! `community_remove` (the `standing_72h` class, 259 200 s), unless the
//! community's signed record sets `policy_blob.cosign_window_secs`; a value
//! under the floor is refused as policy. Families take the default. Counted
//! from THIS node's first-held instant. Expiry drops only the pending and
//! signature rows: the typed door never asks the window, so an assembled
//! event that meets the protocol on its own signatures is admitted wherever
//! a hold lapsed.

use chrono::{DateTime, Utc};

use super::group_plane::{GroupKind, GroupPlaneFamily, GroupSigned};
use super::key_plane::{MintedFamily, MintedPlacement, PlaneSignature};
use super::types::{attestation_type, Attestation, RosterCosignature, ScrubSig};
use super::{Error, FederationDirectory, StandingVerdict};

/// The pending row's dimension (CC 3.1.3 `cosign:{state}`).
pub const DIMENSION_PENDING: &str = "cosign:pending:v1";
/// A cosignature row's dimension (CC 3.1.3 `cosign:{state}`).
pub const DIMENSION_SIGNATURE: &str = "cosign:signature:v1";
/// The envelope member a pending row carries its object under.
pub const PENDING_MEMBER: &str = "cosign_pending";
/// The envelope member a signature row carries its object under.
pub const SIGNATURE_MEMBER: &str = "cosign_signature";
/// The quorum key's id domain.
pub const PENDING_ID_DOMAIN: &[u8] = b"ciris-persist/cosign-pending/v1";
/// A signature row's id domain.
pub const SIGNATURE_ID_DOMAIN: &[u8] = b"ciris-persist/cosign-signature/v1";
/// The window's floor and the class default (CC 4.5.13 `standing_72h`).
pub const WINDOW_FLOOR_SECS: i64 = 259_200;
/// The community record's `policy_blob` member that sets its window.
pub const POLICY_BLOB_WINDOW: &str = "cosign_window_secs";
/// The governance reason a window under the floor is refused with.
pub const WINDOW_BELOW_FLOOR: &str = "cosign_window_below_floor";
/// The refusal token of a re-offer of a settled hold.
pub const COSIGN_PENDING_SETTLED: &str = "cosign_pending_settled";
/// The refusal token of a pending row this node would BEGIN to hold whose
/// event was signed more than one hold window before this node's receipt
/// (CC 3.3.4, rc18): stateless, beside [`COSIGN_PENDING_SETTLED`], so no node
/// holds a change later than two windows after its signed instant.
pub const COSIGN_PENDING_TOO_OLD: &str = "cosign_pending_too_old";
/// The refusal token of a second open pending event by one proposer.
pub const COSIGN_OPEN_PENDING_EXISTS: &str = "cosign_open_pending_exists";
/// The refusal token of a `withdraws` naming a signature row.
pub const COSIGN_SIGNATURE_IRREVOCABLE: &str = "cosign_signature_irrevocable";
/// The refusal token of a cosign row whose signer is not an active member.
pub const COSIGN_SIGNER_NOT_MEMBER: &str = "cosign_signer_not_member";

/// The settle outcomes a receipt is written with.
pub mod outcome {
    /// The assembled event landed (here, or arrived assembled).
    pub const LANDED: &str = "landed";
    /// The window closed first.
    pub const EXPIRED: &str = "expired";
    /// The proposer withdrew the pending row.
    pub const WITHDRAWN: &str = "withdrawn";
}

/// One hold this node holds or held (V214).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CosignReceipt {
    /// The pending row's `attestation_id`.
    pub quorum_key: String,
    /// `family` / `community`.
    pub group_kind: String,
    /// The group.
    pub group_key_id: String,
    /// The primary signer.
    pub proposer_key_id: String,
    /// When THIS node first held it: the window's start.
    pub received_at: DateTime<Utc>,
    /// When it was settled, if it was.
    pub settled_at: Option<DateTime<Utc>>,
    /// [`outcome`]'s token, if settled.
    pub outcome: Option<String>,
}

/// What the attestation executor writes beside a pending row, in its
/// transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReceiptSeed {
    /// `family` / `community`.
    pub(crate) group_kind: &'static str,
    /// The group.
    pub(crate) group_key_id: String,
    /// The primary signer.
    pub(crate) proposer_key_id: String,
    /// The first-held instant.
    pub(crate) received_at: DateTime<Utc>,
}

const PENDING_FAMILY: MintedFamily = MintedFamily {
    dimension: DIMENSION_PENDING,
    member: PENDING_MEMBER,
    score: 1,
    id_domain: PENDING_ID_DOMAIN,
};

const SIGNATURE_FAMILY: MintedFamily = MintedFamily {
    dimension: DIMENSION_SIGNATURE,
    member: SIGNATURE_MEMBER,
    score: 1,
    id_domain: SIGNATURE_ID_DOMAIN,
};

/// The members of a cosign row's object.
pub mod field {
    /// The assembled row's family dimension (`membership:widening:v1`, …).
    pub const EVENT_FAMILY: &str = "event_family";
    /// `family` / `community`.
    pub const GROUP_KIND: &str = "group_kind";
    /// The event with no signature in it.
    pub const EVENT: &str = "event";
    /// A signature row's quorum key.
    pub const QUORUM_KEY: &str = "quorum_key";
    /// A signature row's signer.
    pub const SIGNER_KEY_ID: &str = "signer_key_id";
}

/// The signed object's signature members, removed to name the act.
const SIGNATURE_MEMBERS: [&str; 3] = [
    "scrub_signature_classical",
    "scrub_signature_pqc",
    "cosignatures",
];

/// Is `signed` an event the hold covers: a widening or a removal (a
/// resignation is a member's own act, never short)?
#[must_use]
pub fn is_cosignable(signed: &GroupSigned) -> bool {
    matches!(
        signed.family(),
        GroupPlaneFamily::Widening | GroupPlaneFamily::Removal
    )
}

/// The event as the quorum key names it: the signed object with no signature
/// in it — the primary's scrub, its ML-DSA half and every cosignature gone;
/// the signer's id kept (it is part of what was said, not a signature).
///
/// # Errors
///
/// The object's encode refusal.
pub fn unsigned_event(signed: &GroupSigned) -> Result<serde_json::Value, Error> {
    let mut v = signed.object()?;
    if let Some(o) = v.as_object_mut() {
        for m in SIGNATURE_MEMBERS {
            o.remove(m);
        }
    }
    super::canonical_at_rest::canonicalize_in_place(&mut v)?;
    Ok(v)
}

/// **The quorum key** of an event: `sha256("ciris-persist/cosign-pending/v1"
/// ‖ JCS(`[`unsigned_event`]`))`, first 16 bytes as a UUID — the pending
/// row's id, the same on every node that holds the act however many and
/// whichever signatures it carries.
///
/// # Errors
///
/// The object's encode or canonicalization refusal.
pub fn quorum_key_of(signed: &GroupSigned) -> Result<String, Error> {
    super::key_plane::minted_attestation_id(PENDING_ID_DOMAIN, &unsigned_event(signed)?)
}

/// A signature row's id: `sha256("ciris-persist/cosign-signature/v1" ‖
/// quorum key ‖ signer)`, first 16 bytes as a UUID. One signer, one row: a
/// second (randomised) signature from the same signer is the same row.
#[must_use]
pub fn signature_row_id(quorum_key: &str, signer_key_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(SIGNATURE_ID_DOMAIN);
    h.update(quorum_key.as_bytes());
    h.update(signer_key_id.as_bytes());
    let digest = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    uuid::Uuid::from_bytes(b).to_string()
}

fn malformed(row: &Attestation, what: &str) -> Error {
    Error::malformed_row(
        "cosign",
        super::malformed_row::ENVELOPE_MEMBER_INVALID,
        format!(
            "cosign row {}: {what} (CIRISPersist#1252)",
            row.attestation_id
        ),
    )
}

fn hybrid_of(
    by: &str,
    classical: &str,
    pqc: Option<&str>,
    at: DateTime<Utc>,
) -> Result<PlaneSignature, Error> {
    let Some(pqc) = pqc else {
        return Err(Error::SignatureInvalid(format!(
            "cosign: {by}'s signature is Ed25519-only — a cosign row's signature is hybrid (CC 2.4)"
        )));
    };
    Ok(PlaneSignature {
        scrub_key_id: by.to_owned(),
        classical: classical.to_owned(),
        pqc: Some(pqc.to_owned()),
        scrub_timestamp: at,
        pqc_completed_at: Some(at),
    })
}

fn object_of(signed: &GroupSigned) -> Result<serde_json::Map<String, serde_json::Value>, Error> {
    let mut o = serde_json::Map::new();
    o.insert(
        field::EVENT_FAMILY.to_owned(),
        signed.family().dimension().into(),
    );
    o.insert(field::GROUP_KIND.to_owned(), signed.kind().as_str().into());
    o.insert(field::EVENT.to_owned(), unsigned_event(signed)?);
    Ok(o)
}

fn subject_of(signed: &GroupSigned) -> Result<&str, Error> {
    signed
        .member_key_id()
        .ok_or_else(|| Error::InvalidArgument("cosign: a group record is not held".into()))
}

/// **The pending row** of an event (pure): attested by its primary about the
/// member it adds or removes, named by the quorum key, signed with the
/// primary's own signature over the event's signing bytes, asserted at the
/// event's signed instant. The event's cosignatures are not in it: each
/// rides alone ([`signature_row`]).
///
/// # Errors
///
/// A record, or an Ed25519-only primary signature, is refused.
pub fn pending_row(signed: &GroupSigned) -> Result<Attestation, Error> {
    if !is_cosignable(signed) {
        return Err(Error::InvalidArgument(format!(
            "cosign: a {} is never held (CIRISPersist#1252)",
            signed.family().dimension()
        )));
    }
    let base = signed.with_cosignatures(Vec::new());
    let at = base.signed_instant();
    let (classical, pqc) = primary_signature(&base);
    super::key_plane::minted_row_named(
        PENDING_FAMILY,
        base.authority_key_id(),
        subject_of(&base)?,
        serde_json::Value::Object(object_of(&base)?),
        at,
        hybrid_of(base.authority_key_id(), &classical, pqc.as_deref(), at)?,
        MintedPlacement::federation(),
        quorum_key_of(&base)?,
    )
}

fn primary_signature(signed: &GroupSigned) -> (String, Option<String>) {
    let v = signed.object().unwrap_or_default();
    let classical = v
        .get("scrub_signature_classical")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let pqc = v
        .get("scrub_signature_pqc")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    (classical, pqc)
}

/// **A cosignature row** (pure): attested by the cosigner about the member,
/// named by `quorum key ‖ signer`, carrying the unsigned event so a receiver
/// verifies it alone. Its statement is the signer's hybrid signature over the
/// event's signing bytes: the row's own scrub, and its exactly one
/// `additional_scrubs` entry (CC 2.4's carrier shape, so a fold that counts
/// statements by signer reads it unchanged).
///
/// # Errors
///
/// A record, the primary signing as a cosigner, or an Ed25519-only signature.
pub fn signature_row(
    signed: &GroupSigned,
    cosignature: &RosterCosignature,
) -> Result<Attestation, Error> {
    if !is_cosignable(signed) {
        return Err(Error::InvalidArgument(format!(
            "cosign: a {} collects no cosignature (CIRISPersist#1252)",
            signed.family().dimension()
        )));
    }
    let base = signed.with_cosignatures(Vec::new());
    if cosignature.authority_key_id == base.authority_key_id() {
        return Err(Error::InvalidArgument(
            "cosign: the primary signer is no cosigner of its own event — a signature is \
             counted once"
                .into(),
        ));
    }
    let quorum_key = quorum_key_of(&base)?;
    let signer = cosignature.authority_key_id.as_str();
    let mut object = object_of(&base)?;
    object.insert(field::QUORUM_KEY.to_owned(), quorum_key.clone().into());
    object.insert(field::SIGNER_KEY_ID.to_owned(), signer.into());
    let at = base.signed_instant();
    let signature = hybrid_of(
        signer,
        &cosignature.scrub_signature_classical,
        cosignature.scrub_signature_pqc.as_deref(),
        at,
    )?;
    super::key_plane::minted_row_named(
        SIGNATURE_FAMILY,
        signer,
        subject_of(&base)?,
        serde_json::Value::Object(object),
        at,
        signature,
        MintedPlacement {
            additional_scrubs: vec![ScrubSig {
                scrub_key_id: signer.to_owned(),
                scrub_signature_classical: cosignature.scrub_signature_classical.clone(),
                scrub_signature_pqc: cosignature.scrub_signature_pqc.clone(),
                cosigned_at: None,
            }],
            ..MintedPlacement::federation()
        },
        signature_row_id(&quorum_key, signer),
    )
}

/// Which cosign row, by its signed dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CosignRow {
    /// `cosign:pending:v1`.
    Pending,
    /// `cosign:signature:v1`.
    Signature,
}

/// The cosign row `row` is, if it is one.
#[must_use]
pub fn cosign_row_kind(row: &Attestation) -> Option<CosignRow> {
    if row.attestation_type != attestation_type::SCORES {
        return None;
    }
    match super::admission::envelope_dimension(&row.attestation_envelope)? {
        DIMENSION_PENDING => Some(CosignRow::Pending),
        DIMENSION_SIGNATURE => Some(CosignRow::Signature),
        _ => None,
    }
}

/// Is `row` a cosign row?
#[must_use]
pub fn is_cosign_row(row: &Attestation) -> bool {
    cosign_row_kind(row).is_some()
}

/// A cosign row read back: the event (for a pending row, carrying the
/// primary's signature from the row's scrub; for a signature row, with no
/// signature at all) and, for a signature row, the cosignature.
#[derive(Debug, Clone, PartialEq)]
pub struct CosignRowRead {
    /// Which row.
    pub kind: CosignRow,
    /// The event.
    pub event: GroupSigned,
    /// The quorum key.
    pub quorum_key: String,
    /// A signature row's cosignature.
    pub cosignature: Option<RosterCosignature>,
}

/// Read a cosign row back to its event (and cosignature), and require the row
/// to be EXACTLY what that object mints (one byte off — a re-wrap of the
/// pending row on another node, a second scrub — is a refusal). `Ok(None)`
/// for a row that is not a cosign row.
///
/// # Errors
///
/// A malformed-row refusal.
pub fn read_row(row: &Attestation) -> Result<Option<CosignRowRead>, Error> {
    let Some(kind) = cosign_row_kind(row) else {
        return Ok(None);
    };
    let member = match kind {
        CosignRow::Pending => PENDING_MEMBER,
        CosignRow::Signature => SIGNATURE_MEMBER,
    };
    let object = row
        .attestation_envelope
        .get(member)
        .ok_or_else(|| malformed(row, &format!("no {member} member")))?;
    let str_of = |k: &str| object.get(k).and_then(serde_json::Value::as_str);
    let family = str_of(field::EVENT_FAMILY)
        .and_then(GroupPlaneFamily::of_dimension)
        .ok_or_else(|| malformed(row, "no readable event_family"))?;
    let group_kind = match str_of(field::GROUP_KIND) {
        Some(super::types::cohort_scope::FAMILY) => GroupKind::Family,
        Some(super::types::cohort_scope::COMMUNITY) => GroupKind::Community,
        _ => return Err(malformed(row, "no readable group_kind")),
    };
    let mut event = object
        .get(field::EVENT)
        .cloned()
        .ok_or_else(|| malformed(row, "no event"))?;
    let o = event
        .as_object_mut()
        .ok_or_else(|| malformed(row, "the event is not an object"))?;
    if kind == CosignRow::Pending {
        o.insert(
            "scrub_signature_classical".into(),
            row.scrub_signature_classical.clone().into(),
        );
        if let Some(pqc) = &row.scrub_signature_pqc {
            o.insert("scrub_signature_pqc".into(), pqc.clone().into());
        }
    }
    let event = GroupSigned::of_object(family, group_kind, &event)
        .ok_or_else(|| malformed(row, "the event does not read as its family's object"))?;
    if !is_cosignable(&event) {
        return Err(malformed(row, "the event is not a widening or removal"));
    }
    let quorum_key = quorum_key_of(&event)?;
    let (cosignature, planned) = match kind {
        CosignRow::Pending => (None, pending_row(&event)?),
        CosignRow::Signature => {
            if str_of(field::QUORUM_KEY) != Some(quorum_key.as_str()) {
                return Err(malformed(row, "quorum_key is not the event's"));
            }
            let signer =
                str_of(field::SIGNER_KEY_ID).ok_or_else(|| malformed(row, "no signer_key_id"))?;
            let c = RosterCosignature {
                authority_key_id: signer.to_owned(),
                scrub_signature_classical: row.scrub_signature_classical.clone(),
                scrub_signature_pqc: row.scrub_signature_pqc.clone(),
            };
            let planned = signature_row(&event, &c)?;
            (Some(c), planned)
        }
    };
    super::group_plane::check_canonical_group_row(row, &planned)?;
    Ok(Some(CosignRowRead {
        kind,
        event,
        quorum_key,
        cosignature,
    }))
}

/// **A cosign row's signature rule, at the attestation plane's generic
/// verify** (`tier_ingest::verify_row_hybrid_signature`): the row is exactly
/// what its object mints, and its one statement verifies — the primary's over
/// the event's signing bytes (the event's own door verification, with no
/// cosignature), or the cosigner's over the same bytes. `Ok(false)` for a row
/// that is not a cosign row.
pub(crate) async fn verify_row<D>(dir: &D, row: &Attestation) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    let Some(read) = read_row(row)? else {
        return Ok(false);
    };
    match read.kind {
        CosignRow::Pending => {
            super::group_plane::verify_signed_object(dir, &read.event).await?;
        }
        CosignRow::Signature => {
            let c = read
                .cosignature
                .as_ref()
                .ok_or_else(|| malformed(row, "no cosignature"))?;
            let envelope = read
                .event
                .plane_signing_envelope()
                .ok_or_else(|| malformed(row, "a record carries no cosignature"))?;
            super::tier_ingest::verify_envelope_hybrid_signature(
                dir,
                &c.authority_key_id,
                &envelope,
                &c.scrub_signature_classical,
                c.scrub_signature_pqc.as_deref(),
            )
            .await?;
        }
    }
    Ok(true)
}

/// The receipt seed a pending row opens, for the attestation plan (pure).
pub(crate) fn receipt_seed_of(
    row: &Attestation,
    received_at: DateTime<Utc>,
) -> Option<ReceiptSeed> {
    let read = read_row(row).ok().flatten()?;
    (read.kind == CosignRow::Pending).then(|| ReceiptSeed {
        group_kind: read.event.kind().as_str(),
        group_key_id: read.event.group_key_id().to_owned(),
        proposer_key_id: read.event.authority_key_id().to_owned(),
        received_at,
    })
}

/// The `(quorum key, signer)` a signature row records, for the attestation
/// plan (pure).
pub(crate) fn signature_seed_of(row: &Attestation) -> Option<(String, String)> {
    let read = read_row(row).ok().flatten()?;
    let c = read.cosignature?;
    Some((read.quorum_key, c.authority_key_id))
}

// ─────────────────────────────────────────────────────────────────────────
//  Membership at the event's instant
// ─────────────────────────────────────────────────────────────────────────

/// The group's active members at `at` (the authorized fold).
pub(crate) async fn active_members_at<D>(
    dir: &D,
    kind: GroupKind,
    group_key_id: &str,
    at: DateTime<Utc>,
) -> Result<Vec<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    Ok(match kind {
        GroupKind::Community => match dir.lookup_community(group_key_id).await? {
            Some(c) => Box::pin(super::authorized_community_roster_at(dir, &c, at))
                .await?
                .into_iter()
                .map(|m| m.key_id)
                .collect(),
            None => Vec::new(),
        },
        GroupKind::Family => match dir.lookup_family(group_key_id).await? {
            Some(f) => Box::pin(super::authorized_family_roster_at(dir, &f, at))
                .await?
                .into_iter()
                .map(|m| m.key_id)
                .collect(),
            None => Vec::new(),
        },
    })
}

fn not_member(group: &str, signer: &str) -> Error {
    Error::RosterAuthorityUnauthorized {
        group_key_id: group.to_owned(),
        offered_authority_key_id: signer.to_owned(),
        rule: COSIGN_SIGNER_NOT_MEMBER,
        shortfall: None,
    }
}

fn settled_refusal(quorum_key: &str, outcome: &str) -> Error {
    Error::InvalidArgument(format!(
        "{COSIGN_PENDING_SETTLED}: the hold {quorum_key} was settled `{outcome}` on this node — a \
         settled hold is not held again (CIRISPersist#1252)"
    ))
}

/// What the attestation door does with a cosign row ahead of its generic plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CosignAdmit {
    /// This node holds the row's id already (a re-offer, or the same signer's
    /// other randomised signature): nothing is written.
    Held,
    /// The row passes the hold's gates; the generic plan stores it.
    Store,
}

/// **The cosign rows' own gates**, at the attestation door ahead of the
/// generic plan (which verifies the statement through [`verify_row`]):
///
/// - a held id settles as held (one act, one pending row; one signer, one
///   signature row), never as a conflict;
/// - the row is exactly what its object mints (a re-wrap is refused);
/// - a settled hold is not held again ([`COSIGN_PENDING_SETTLED`]);
/// - the signer is an ACTIVE member of the group at the event's signed
///   instant (a stranger, or a removed member, cannot fill a hold), and a
///   signer who is no member at receipt signed inside W (CC 2.6.7:
///   [`Error::AssertedAtStale`]);
/// - a pending row: its event was signed within one hold window of this
///   node's receipt ([`COSIGN_PENDING_TOO_OLD`]);
/// - a pending row: its proposer holds no other open hold in the group
///   ([`COSIGN_OPEN_PENDING_EXISTS`]);
/// - a signature row: its pending row is held (an ordering gap is the
///   retryable `roster_authority_not_established`).
///
/// # Errors
///
/// The refusals above.
pub(crate) async fn admit_row<D>(dir: &D, row: &Attestation) -> Result<CosignAdmit, Error>
where
    D: FederationDirectory + ?Sized,
{
    if dir.get_attestation(&row.attestation_id).await?.is_some() {
        return Ok(CosignAdmit::Held);
    }
    let Some(read) = read_row(row)? else {
        return Ok(CosignAdmit::Store);
    };
    if let Some(r) = dir.cosign_receipt(&read.quorum_key).await? {
        if let Some(o) = r.outcome.as_deref() {
            return Err(settled_refusal(&read.quorum_key, o));
        }
    }
    let group = read.event.group_key_id().to_owned();
    let signed_at = read.event.signed_instant();
    let now = super::self_roster::roster_clock();
    let members = active_members_at(dir, read.event.kind(), &group, signed_at).await?;
    let signer = match &read.cosignature {
        Some(c) => c.authority_key_id.clone(),
        None => read.event.authority_key_id().to_owned(),
    };
    // rc18 (CC 2.6.7 W, in the form CC 3.3.6.3 gives it) — a signer who is no
    // longer an active member at receipt counts only while the signed instant
    // is inside W: an evicted member cannot sign into the window in which it
    // was still a member. A member still standing signs at any age.
    if super::self_roster::outside_past_freshness_window(signed_at, now)
        && !active_members_at(dir, read.event.kind(), &group, now)
            .await?
            .contains(&signer)
    {
        return Err(Error::AssertedAtStale {
            author: signer,
            standing_for: group,
            plane: "cosign",
            asserted_at: signed_at,
            w_secs: super::self_roster::PAST_FRESHNESS_W_SECS,
        });
    }
    if !members.contains(&signer) {
        return Err(not_member(&group, &signer));
    }
    match read.kind {
        CosignRow::Pending => {
            // rc18 (CC 3.3.4) — no hold BEGINS for an event signed more than
            // one hold window before this node's receipt.
            let blob = match read.event.kind() {
                GroupKind::Community => dir
                    .lookup_community(&group)
                    .await?
                    .and_then(|c| c.policy_blob),
                GroupKind::Family => None,
            };
            let window = window_secs(read.event.kind(), read.event.family(), blob.as_ref())?;
            if now - signed_at > chrono::Duration::seconds(window) {
                return Err(Error::InvalidArgument(format!(
                    "{COSIGN_PENDING_TOO_OLD}: the event of hold {} was signed at {signed_at}, \
                     more than its {window} s window before this node's receipt — a proposer \
                     that still wants the change signs it anew (CIRISPersist#1252, CC 3.3.4)",
                    read.quorum_key
                )));
            }
            let open = dir.list_open_cosign_receipts().await?;
            if open.iter().any(|r| {
                r.group_key_id == group
                    && r.group_kind == read.event.kind().as_str()
                    && r.proposer_key_id == signer
                    && r.quorum_key != read.quorum_key
            }) {
                return Err(Error::InvalidArgument(format!(
                    "{COSIGN_OPEN_PENDING_EXISTS}: {signer} already holds an open cosign hold in \
                     {group} — one open proposal per proposer (CIRISPersist#1252)"
                )));
            }
        }
        CosignRow::Signature => {
            if dir.get_attestation(&read.quorum_key).await?.is_none() {
                return Err(Error::RosterAuthorityUnauthorized {
                    group_key_id: group,
                    offered_authority_key_id: signer,
                    rule: super::ROSTER_AUTHORITY_RULE_NOT_ESTABLISHED,
                    shortfall: None,
                });
            }
        }
    }
    Ok(CosignAdmit::Store)
}

// ─────────────────────────────────────────────────────────────────────────
//  The hold, at the typed doors
// ─────────────────────────────────────────────────────────────────────────

tokio::task_local! {
    /// Set while [`execute_for`] offers a merged event through its typed
    /// door: the door neither holds it again nor reads a fresh receipt, and a
    /// window gate that bounds the local door on receipt reads the hold's
    /// first-held instant instead of the clock.
    static EXECUTING: DateTime<Utc>;
}

/// The first-held instant of the hold the current task executes, if it is
/// executing one (`open:self_admit`'s removal window is evaluated against it).
#[must_use]
pub(crate) fn executing_received_at() -> Option<DateTime<Utc>> {
    EXECUTING.try_with(|t| *t).ok()
}

/// Test-only: run `f` as the executor runs a held event's door (its hold
/// first received at `received_at`).
#[cfg(test)]
pub(crate) async fn test_executing<F: std::future::Future>(
    received_at: DateTime<Utc>,
    f: F,
) -> F::Output {
    EXECUTING.scope(received_at, f).await
}

/// The window of a group's holds, in seconds (CC 3.3.4, 4.5.13).
///
/// # Errors
///
/// [`Error::GovernancePolicyRefused`] for a community record whose
/// `policy_blob.cosign_window_secs` is not whole seconds at or above
/// [`WINDOW_FLOOR_SECS`]; the governance table's own refusal.
pub fn window_secs(
    kind: GroupKind,
    direction: GroupPlaneFamily,
    policy_blob: Option<&serde_json::Value>,
) -> Result<i64, Error> {
    let family = match direction {
        GroupPlaneFamily::Removal => "community_remove",
        _ => "community_invite",
    };
    let table = super::governance_policy::table()?;
    let row = table.row(family)?;
    let default = table
        .window_classes
        .get(&row.window_class)
        .copied()
        .filter(|w| *w == row.window_secs)
        .unwrap_or(WINDOW_FLOOR_SECS);
    if kind == GroupKind::Family {
        return Ok(default);
    }
    match policy_blob.and_then(|b| b.get(POLICY_BLOB_WINDOW)) {
        None => Ok(default),
        Some(v) => check_window_value(v),
    }
}

/// A `policy_blob.cosign_window_secs` value: whole seconds, at or above the
/// floor (CC 4.5.13: a window below its class's floor is refused as policy).
///
/// # Errors
///
/// [`Error::GovernancePolicyRefused`] (`cosign_window_below_floor`).
pub fn check_window_value(v: &serde_json::Value) -> Result<i64, Error> {
    match v.as_i64() {
        Some(w) if w >= WINDOW_FLOOR_SECS => Ok(w),
        _ => Err(Error::GovernancePolicyRefused {
            family: POLICY_BLOB_WINDOW.to_owned(),
            reason: WINDOW_BELOW_FLOOR,
        }),
    }
}

/// The community-record door's half of the window policy: a record whose
/// `policy_blob` sets `cosign_window_secs` under the floor is refused.
///
/// # Errors
///
/// [`check_window_value`]'s refusal.
pub fn check_community_record_window(row: &super::types::Community) -> Result<(), Error> {
    if let Some(v) = row
        .policy_blob
        .as_ref()
        .and_then(|b| b.get(POLICY_BLOB_WINDOW))
    {
        check_window_value(v)?;
    }
    Ok(())
}

/// **The hold, at a typed door** whose standing check returned
/// [`RosterAuthority::ConsensusShort`](super::RosterAuthority::ConsensusShort)
/// and whose later checks were all met. `signed` is the event as offered;
/// `shortfall` the refusal the door returns when it does not hold.
///
/// Holds — mints the pending row and a signature row for every cosignature
/// the event carries, through the attestation door, and returns
/// [`Error::RosterChangeNotLanded`] — only at the LOCAL door, outside the
/// executor, on the node that speaks for the primary, with no other open hold
/// of the primary in the group. Otherwise returns `shortfall`: exactly the
/// pre-#1252 refusal.
pub(crate) async fn hold<D>(dir: &D, signed: GroupSigned, shortfall: Error) -> Error
where
    D: FederationDirectory + ?Sized,
{
    match hold_inner(dir, &signed).await {
        Ok(Some(held)) => held,
        Ok(None) => shortfall,
        Err(e) => {
            tracing::warn!(error = %e, group = signed.group_key_id(), "cosign hold not taken");
            match e {
                // A policy refusal of the window is the door's answer.
                Error::GovernancePolicyRefused { .. } => e,
                _ => shortfall,
            }
        }
    }
}

async fn hold_inner<D>(dir: &D, signed: &GroupSigned) -> Result<Option<Error>, Error>
where
    D: FederationDirectory + ?Sized,
{
    if !is_cosignable(signed)
        || super::group_plane::applying_replicated_group_row()
        || executing_received_at().is_some()
    {
        return Ok(None);
    }
    let Some(me) = dir.node_key_id() else {
        return Ok(None);
    };
    let primary = signed.authority_key_id().to_owned();
    if !super::self_collective::speaks_for(dir, &me, &primary).await? {
        return Ok(None);
    }
    // The window is read (and a bad one refused) before anything is held.
    let blob = match signed.kind() {
        GroupKind::Community => dir
            .lookup_community(signed.group_key_id())
            .await?
            .and_then(|c| c.policy_blob),
        GroupKind::Family => None,
    };
    window_secs(signed.kind(), signed.family(), blob.as_ref())?;
    let pending = pending_row(signed)?;
    let quorum_key = pending.attestation_id.clone();
    if let Some(r) = dir.cosign_receipt(&quorum_key).await? {
        if r.outcome.is_some() {
            return Ok(None);
        }
    }
    let open = dir.list_open_cosign_receipts().await?;
    if open.iter().any(|r| {
        r.group_key_id == signed.group_key_id()
            && r.group_kind == signed.kind().as_str()
            && r.proposer_key_id == primary
            && r.quorum_key != quorum_key
    }) {
        tracing::info!(
            group = signed.group_key_id(),
            proposer = %primary,
            "cosign: the proposer holds another open hold in the group; refused as before"
        );
        return Ok(None);
    }
    if dir.get_attestation(&quorum_key).await?.is_none() {
        dir.put_attestation(super::SignedAttestation {
            attestation: pending,
        })
        .await?;
    }
    for c in signed.cosignatures() {
        let row = signature_row(signed, c)?;
        if dir.get_attestation(&row.attestation_id).await?.is_none() {
            dir.put_attestation(super::SignedAttestation { attestation: row })
                .await?;
        }
    }
    let signers = 1 + dir.list_cosign_signatures(&quorum_key).await?.len();
    Ok(Some(Error::RosterChangeNotLanded {
        group_key_id: signed.group_key_id().to_owned(),
        member_key_id: subject_of(signed)?.to_owned(),
        direction: match signed.family() {
            GroupPlaneFamily::Removal => "removal",
            _ => "widening",
        },
        quorum_key,
        signers,
    }))
}

/// A door's later check refused under a short verdict: the short event keeps
/// the shortfall refusal it met first before the split (`e` otherwise).
pub(crate) fn keep_shortfall(short: &mut Option<Error>, e: Error) -> Error {
    short.take().unwrap_or(e)
}

/// The door's step after its plan: with no shortfall, the event goes on to
/// the write (`Ok(signed)`); with one, it is [`hold`]'s answer
/// (`RosterChangeNotLanded`, or the shortfall refusal unchanged).
///
/// # Errors
///
/// [`hold`]'s answer.
pub(crate) async fn hold_if_short<D>(
    dir: &D,
    short: Option<Error>,
    signed: GroupSigned,
) -> Result<GroupSigned, Error>
where
    D: FederationDirectory + ?Sized,
{
    match short {
        None => Ok(signed),
        Some(shortfall) => Err(hold(dir, signed, shortfall).await),
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The executor
// ─────────────────────────────────────────────────────────────────────────

/// The quorum key a cosign row (or a `withdraws` of a pending row) concerns.
async fn quorum_key_concerned<D>(dir: &D, row: &Attestation) -> Option<String>
where
    D: FederationDirectory + ?Sized,
{
    if let Ok(Some(read)) = read_row(row) {
        return Some(read.quorum_key);
    }
    if row.attestation_type == attestation_type::WITHDRAWS {
        let target =
            super::precedence::references_attestation_id_from_envelope(&row.attestation_envelope)?;
        return dir
            .cosign_receipt(target)
            .await
            .ok()
            .flatten()
            .map(|r| r.quorum_key);
    }
    None
}

/// After a row is admitted (the attestation door's hook): execute the hold it
/// concerns. Never fails the admission that called it: the row is stored; a
/// failure to execute is logged and the sweep retries.
pub(crate) async fn after_admission<D>(dir: &D, row: &Attestation)
where
    D: FederationDirectory + ?Sized,
{
    #[cfg(test)]
    if test_hook::suppressed() {
        return;
    }
    let Some(quorum_key) = quorum_key_concerned(dir, row).await else {
        return;
    };
    if let Err(e) = Box::pin(execute_for(dir, &quorum_key)).await {
        tracing::warn!(quorum_key = %quorum_key, error = %e, "cosign execute");
    }
}

/// Did the proposer withdraw the pending row `quorum_key`?
async fn withdrawn_by_proposer<D>(dir: &D, quorum_key: &str, proposer: &str) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    let composers = dir
        .list_composers_referencing_any(&[quorum_key.to_owned()], None, None)
        .await?;
    Ok(composers.iter().any(|w| {
        w.attestation_type == attestation_type::WITHDRAWS
            && w.attesting_key_id == proposer
            && super::precedence::references_attestation_id_from_envelope(&w.attestation_envelope)
                == Some(quorum_key)
    }))
}

/// Does this node hold the act `event` names as its assembled row?
async fn assembled_held<D>(dir: &D, event: &GroupSigned) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    match dir.read_group_plane_object(&event.link()).await {
        Ok(Some((held, _))) => same_act(&held, event),
        Ok(None) | Err(Error::Unsupported { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Do `a` and `b` name the same act (the same event with no signature, every
/// instant at the substrate's microsecond resolution)?
///
/// # Errors
///
/// An encode refusal.
pub fn same_act(a: &GroupSigned, b: &GroupSigned) -> Result<bool, Error> {
    let at_substrate = |s: &GroupSigned| -> Result<serde_json::Value, Error> {
        let mut v = unsigned_event(s)?;
        super::types::truncate_instants_to_microseconds(&mut v);
        Ok(v)
    };
    Ok(a.family() == b.family() && at_substrate(a)? == at_substrate(b)?)
}

/// v61.3.0 (CIRISPersist#1252) — **does this node hold `offered`'s act under
/// another row?** The projection row the event lands in holds the same act
/// (the same event with no signature) and points at a row other than
/// `offered_row`: the held row's `attestation_id`. `None` otherwise (nothing
/// held, a different act under the same key, or the very row offered).
///
/// # Errors
///
/// The read's.
pub(crate) async fn held_equivalent<D>(
    dir: &D,
    offered: &GroupSigned,
    offered_row: &Attestation,
) -> Result<Option<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let held = match dir.read_group_plane_object(&offered.link()).await {
        Ok(Some((held, Some(id)))) => (held, id),
        Ok(_) | Err(Error::Unsupported { .. }) => return Ok(None),
        Err(e) => return Err(e),
    };
    if held.1 == offered_row.attestation_id || !same_act(&held.0, offered)? {
        return Ok(None);
    }
    Ok(Some(held.1))
}

/// What [`execute_for`] did with one hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Executed {
    /// The merged event landed through its typed door (or arrived assembled).
    Landed,
    /// The window closed: the rows are dropped.
    Expired,
    /// The proposer withdrew it: the rows are dropped.
    Withdrawn,
    /// Still short (or not executable now); the hold stays open.
    Open,
    /// Nothing to do: no open hold under that key.
    NotOpen,
}

/// **Execute one hold**: settle it when its proposer withdrew it, when its
/// window closed, or when the act is already held assembled; otherwise union
/// its signature rows by signer and offer the merged event through its typed
/// door. The door decides; nothing here re-derives standing.
pub async fn execute_for<D>(dir: &D, quorum_key: &str) -> Result<Executed, Error>
where
    D: FederationDirectory + ?Sized,
{
    let Some(receipt) = dir.cosign_receipt(quorum_key).await? else {
        return Ok(Executed::NotOpen);
    };
    if receipt.outcome.is_some() {
        return Ok(Executed::NotOpen);
    }
    let now = super::self_roster::roster_clock();
    let Some(pending) = dir.get_attestation(quorum_key).await? else {
        return Ok(Executed::NotOpen);
    };
    let Some(read) = read_row(&pending)? else {
        return Ok(Executed::NotOpen);
    };
    let event = read.event;
    if withdrawn_by_proposer(dir, quorum_key, event.authority_key_id()).await? {
        dir.drop_cosign_rows(quorum_key).await?;
        dir.settle_cosign_receipt(quorum_key, outcome::WITHDRAWN, now)
            .await?;
        return Ok(Executed::Withdrawn);
    }
    if assembled_held(dir, &event).await? {
        dir.settle_cosign_receipt(quorum_key, outcome::LANDED, now)
            .await?;
        return Ok(Executed::Landed);
    }
    let blob = match event.kind() {
        GroupKind::Community => dir
            .lookup_community(event.group_key_id())
            .await?
            .and_then(|c| c.policy_blob),
        GroupKind::Family => None,
    };
    let window = window_secs(event.kind(), event.family(), blob.as_ref())?;
    if now > receipt.received_at + chrono::Duration::seconds(window) {
        dir.drop_cosign_rows(quorum_key).await?;
        dir.settle_cosign_receipt(quorum_key, outcome::EXPIRED, now)
            .await?;
        return Ok(Executed::Expired);
    }
    let mut cosignatures = Vec::new();
    for (id, _) in dir.list_cosign_signatures(quorum_key).await? {
        let Some(row) = dir.get_attestation(&id).await? else {
            continue;
        };
        match read_row(&row) {
            Ok(Some(CosignRowRead {
                cosignature: Some(c),
                ..
            })) => cosignatures.push(c),
            _ => tracing::warn!(attestation_id = %id, "cosign: held signature row unreadable"),
        }
    }
    cosignatures.sort_by(|a, b| a.authority_key_id.cmp(&b.authority_key_id));
    cosignatures.dedup_by(|a, b| a.authority_key_id == b.authority_key_id);
    let merged = event.with_cosignatures(cosignatures);
    let offered = EXECUTING
        .scope(receipt.received_at, offer(dir, merged))
        .await;
    match offered {
        Ok(()) => {
            dir.settle_cosign_receipt(quorum_key, outcome::LANDED, now)
                .await?;
            Ok(Executed::Landed)
        }
        Err(e) => {
            tracing::debug!(quorum_key, error = %e, "cosign: the merged event did not land yet");
            Ok(Executed::Open)
        }
    }
}

/// Offer `merged` through the typed door its object names.
async fn offer<D>(dir: &D, merged: GroupSigned) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    match merged {
        GroupSigned::CommunityWidening(w) => dir.put_community_membership_widening(w).await,
        GroupSigned::CommunityRevocation(r) => dir.put_community_membership_revocation(r).await,
        GroupSigned::FamilyWidening(w) => dir.put_family_membership_widening(w).await,
        GroupSigned::FamilyRevocation(r) => dir.put_family_membership_revocation(r).await,
        GroupSigned::Family(_) | GroupSigned::Community(_) => Err(Error::InvalidArgument(
            "cosign: a group record is never held".into(),
        )),
    }
}

/// **The sweep**: [`execute_for`] every open hold on this node — what met
/// its protocol lands, what lapsed expires, what was withdrawn ends. Returns
/// how many landed.
pub async fn execute_due<D>(dir: &D) -> Result<usize, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut landed = 0;
    for r in dir.list_open_cosign_receipts().await? {
        if Box::pin(execute_for(dir, &r.quorum_key)).await? == Executed::Landed {
            landed += 1;
        }
    }
    Ok(landed)
}

// ─────────────────────────────────────────────────────────────────────────
//  Withdrawal
// ─────────────────────────────────────────────────────────────────────────

/// A `withdraws` naming a `cosign:signature:v1` row is REFUSED: a cosignature
/// already sent is irrevocable (the pending row's proposer withdraws the
/// pending row; an assembled event is retracted by a cosigned `withdraws`).
///
/// # Errors
///
/// [`Error::InvalidArgument`] ([`COSIGN_SIGNATURE_IRREVOCABLE`]).
pub(crate) fn check_withdraws_target(target: &Attestation) -> Result<(), Error> {
    if cosign_row_kind(target) == Some(CosignRow::Signature) {
        return Err(Error::InvalidArgument(format!(
            "{COSIGN_SIGNATURE_IRREVOCABLE}: withdraws names the cosignature row {} — a \
             cosignature already sent is irrevocable (CIRISPersist#1252, CC 3.1.3)",
            target.attestation_id
        )));
    }
    Ok(())
}

/// Is `standing` a hold candidate (for a caller holding a raw verdict)?
#[must_use]
pub fn is_short(standing: &StandingVerdict) -> bool {
    matches!(standing, StandingVerdict::ConsensusShort { .. })
}

// ─────────────────────────────────────────────────────────────────────────
//  Audience
// ─────────────────────────────────────────────────────────────────────────

/// **Who receives a cosign row** — [`may_receive`](super::replication_audience::may_receive)'s
/// first arm: a recipient whose principals (and itself) contain a member of
/// the group ACTIVE at the event's signed instant and still active now (CC
/// 3.3.4, rc18). A restriction only: it never admits anything else. Every kind of group,
/// public ones included; the invitee of a widening is not a member, the
/// target of a removal is. `Ok(None)` for a row that is not a cosign row.
///
/// # Errors
///
/// The roster fold's and the principal fold's.
pub async fn may_receive<D>(
    dir: &D,
    recipient: &str,
    row: &Attestation,
) -> Result<Option<super::replication_audience::Verdict>, Error>
where
    D: FederationDirectory + ?Sized,
{
    use super::replication_audience::{Reason, Verdict};
    if !is_cosign_row(row) {
        return Ok(None);
    }
    let Ok(Some(read)) = read_row(row) else {
        return Ok(Some(Verdict::No(Reason::Malformed)));
    };
    // rc18 (CC 3.3.4) — a member at the event's signed instant who is a
    // member still: a member removed since is served nothing.
    let now_members = active_members_at(
        dir,
        read.event.kind(),
        read.event.group_key_id(),
        chrono::Utc::now(),
    )
    .await?;
    let members: Vec<String> = active_members_at(
        dir,
        read.event.kind(),
        read.event.group_key_id(),
        read.event.signed_instant(),
    )
    .await?
    .into_iter()
    .filter(|m| now_members.contains(m))
    .collect();
    let mut principals: std::collections::HashSet<String> =
        super::self_collective::principals_of(dir, recipient)
            .await?
            .into_iter()
            .collect();
    principals.insert(recipient.to_owned());
    Ok(Some(if members.iter().any(|m| principals.contains(m)) {
        Verdict::Yes(Reason::Cohort)
    } else {
        Verdict::No(Reason::NotInAudience)
    }))
}

// ─────────────────────────────────────────────────────────────────────────
//  Withdraws by id (CC 2.4.1.1 rule 0, shape (a))
// ─────────────────────────────────────────────────────────────────────────

/// The row a `withdraws` naming `target_id` retracts on this node: the row
/// held under that id, else the assembled row an alias of it names (the same
/// act another node holds under `target_id`, recorded when its offer settled
/// as held equivalent). `None` when neither is held.
///
/// # Errors
///
/// The reads'.
pub async fn resolve_withdraws_target<D>(
    dir: &D,
    target_id: &str,
) -> Result<Option<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    if let Some(row) = dir.get_attestation(target_id).await? {
        return Ok(Some(row));
    }
    match dir.cosign_alias(target_id).await {
        Ok(Some((_, held))) => dir.get_attestation(&held).await,
        Ok(None) | Err(Error::Unsupported { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// v61.3.0 (CIRISPersist#1252, CC 2.4.1.1 rule 0) — **is the act `signed`
/// names retracted on this node?** A held `withdraws` names ANY row of the
/// act this node knows of: a held row of the same act (any subset of its
/// cosignatures, withdrawn rows included), an alias of the act (another
/// node's id for it, recorded at a held-equivalent settle), or `offered_id`.
/// Asked from stored rows, never from the order rows arrived in, so every
/// node that holds the act reads its retraction alike — the admission's
/// `after_withdraws` (which resolves through [`resolve_withdraws_target`]),
/// a later offer of another subset, and the projection rebuild.
///
/// # Errors
///
/// The reads'.
pub async fn act_retracted<D>(
    dir: &D,
    signed: &GroupSigned,
    offered_id: &str,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    if !is_cosignable(signed) {
        return Ok(false);
    }
    let mut ids = vec![offered_id.to_owned()];
    for row in held_rows_of_act(dir, signed).await? {
        ids.push(row.attestation_id);
    }
    match dir.list_cosign_aliases(&quorum_key_of(signed)?).await {
        Ok(aliases) => {
            for (alias, held) in aliases {
                ids.push(alias);
                ids.push(held);
            }
        }
        Err(Error::Unsupported { .. }) => {}
        Err(e) => return Err(e),
    }
    ids.sort();
    ids.dedup();
    Ok(dir
        .list_composers_referencing_any(&ids, None, None)
        .await?
        .iter()
        .any(|w| w.attestation_type == attestation_type::WITHDRAWS))
}

/// Every held group-plane row of `signed`'s act (withdrawn ones included):
/// the rows of its family placed at its group whose object names the same
/// act.
pub(crate) async fn held_rows_of_act<D>(
    dir: &D,
    signed: &GroupSigned,
) -> Result<Vec<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let rows = match dir
        .list_targeted_by_dimension_prefix(
            &[signed.kind().as_str()],
            signed.group_key_id(),
            signed.family().dimension(),
        )
        .await
    {
        Ok(rows) => rows,
        Err(Error::Unsupported { .. }) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut out = Vec::new();
    for row in rows {
        if let Ok(Some(held)) = super::group_plane::group_signed_of_row(&row) {
            if same_act(&held, signed)? {
                out.push(row);
            }
        }
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────
//  At open: the ref of a cosigned row moves once
// ─────────────────────────────────────────────────────────────────────────

/// The `attestation_id`s of every held cosignable group row that carries a
/// cosignature: rows indexed before v61.3.0 under `sha256(bytes)`, whose ref
/// moves once to [`attestation_wire_hash`](super::wire_index::attestation_wire_hash)
/// when the backend re-indexes them at open. Their ids are not re-keyed.
///
/// # Errors
///
/// The group-plane read's.
pub(crate) async fn cosigned_group_row_ids<D>(dir: &D) -> Result<Vec<String>, Error>
where
    D: super::group_plane::GroupPlaneStore + ?Sized,
{
    use super::group_plane::GroupPlaneTable as T;
    if !dir.group_plane_present().await? {
        return Ok(Vec::new());
    }
    let mut ids = Vec::new();
    for table in [
        T::FamilyWidenings,
        T::CommunityWidenings,
        T::FamilyRevocations,
        T::CommunityRevocations,
    ] {
        for row in dir.read_group_plane(table).await?.rows {
            if let Ok(Some(signed)) = super::group_plane::group_signed_of_row(&row) {
                if is_cosignable(&signed) && !signed.cosignatures().is_empty() {
                    ids.push(row.attestation_id);
                }
            }
        }
    }
    ids.sort();
    ids.dedup();
    Ok(ids)
}

/// Test-only: suppress [`after_admission`] on this thread, so a witness of
/// the sweep sees the rows the hook would otherwise have executed at once.
#[cfg(test)]
pub(crate) mod test_hook {
    use std::cell::Cell;
    thread_local! {
        static OFF: Cell<bool> = const { Cell::new(false) };
    }
    /// Suppress (`true`) or restore the hook on this thread.
    pub(crate) fn suppress(off: bool) {
        OFF.with(|c| c.set(off));
    }
    pub(super) fn suppressed() -> bool {
        OFF.with(Cell::get)
    }
}
