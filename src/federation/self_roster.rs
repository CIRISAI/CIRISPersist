//! v59.0.0 (CIRISPersist#1099; CC 3.3.6.3, CIRISConstitution#178;
//! `CLM-self-roster-two-paths`, `CLM-self-roster-authority`) — **the key
//! roster of a self, and its door.**
//!
//! A self is one fedID, a `user`-role identity (a node or an agent identity's
//! occurrences are not a roster, and are written as before). The keys that
//! may sign as it are its **roster**: the
//! genesis key (the fedID's own key) and every ACTIVE `identity_occurrence`
//! under it whose key carries the `user` role. A node's own key and an agent's
//! key are not roster keys: CC 3.3.6.3 keeps "the node's own key" apart from
//! the self's keys, and neither a node nor an agent accepts for itself (CC
//! 3.2, CC 3.4.7.3). Their occurrences under the self are KEM targets, written
//! as before (`signer_acts_for`), and this door does not gate them.
//!
//! # The door: one key of two or more proposes
//!
//! Before this cut any active occurrence added or revoked any other at once —
//! `formal/self_roster`'s **unilateral** configuration, which a stolen device
//! wins in two steps (`unilateral3_stolen`). Now an addition (a signed
//! `identity_occurrence` of a user-role key not on the roster) and an eviction
//! (a framed occurrence revocation, or a `withdraws` against the pair's
//! `identity:occurrence:v1` row, of a live roster key) are each a
//! **proposal**, decided by THE shared two-path function
//! ([`super::two_path::decide_all`]) under [`policy`]:
//!
//! - it lands at once by a strict majority of the live roster, proposer
//!   counted (at ONE key the addition is the owner's approval alone — the
//!   add-device flow, unchanged);
//! - or by the lone path, after [`W_SELF_SECS`] on THIS node's clock with no
//!   strict majority of the other members objecting, and for an eviction only
//!   if the target signed nothing since the proposal arrived.
//!
//! Every door that can change a roster — `put_identity_occurrence` and
//! `put_identity_occurrence_revocation` on all three backends, and the
//! attestation door for an occurrence `withdraws` — asks [`gate`] after its
//! signature gate and before any write. A change that lands proceeds exactly
//! as before. One that does not is HELD as a proposal row and the door
//! returns [`Error::SelfRosterNotLanded`]; when it later lands (an answer
//! arrives, or the window closes and [`execute_due`] runs), the executor
//! re-offers the same signed object through the same door, which now lets it
//! through. So the write path is never spelled twice: the plan is the shared
//! decision, the executors are the doors that already existed.
//!
//! # The rows
//!
//! | row | dimension | attester → attested | carries |
//! |---|---|---|---|
//! | proposal | [`DIMENSION_PROPOSAL`] | proposer → fedID | [`PROPOSAL_MEMBER`]: `{identity_key_id, kind, target_key_id, carrier, <carrier>}`, the signed object |
//! | assent | [`DIMENSION_ASSENT`] | roster key → fedID | `cohort: "self"`, `cohort_key_id`, `objects_to_attestation_id` |
//! | objection | [`DIMENSION_OBJECTION`] (`objection:raised:v1`) | roster key → fedID | the same members |
//!
//! All three live in CC 3.1.9.2's `objection:{state}` family (the reverse-
//! quorum shape CIRISConstitution#178 names); `proposal` and `assent` are new
//! states minted here and reported to CC for registration. The proposal row
//! is MINTED by persist from the signed object it carries, the key plane's
//! rule (`key_plane::minted_row`): its signature columns are the object's own,
//! every other column is a pure function of the object, and its id is
//! `sha256("ciris:objection:proposal:v1:" ‖ JCS(object))`, so every node that
//! holds the object names the same proposal and an answer signed on one node
//! counts on all of them. Answers are ordinary rows a roster key signs
//! ([`vote_envelope`]).
//!
//! **What a pre-v58 peer sees.** Nothing pending: the framed occurrence and
//! revocation planes serve the projection tables, which a proposal never
//! reaches. Once a proposal lands, the effect is written as any other (the
//! occurrence and its `identity:occurrence:v1` row; the revocation or the
//! `withdraws` row) and is served framed and as a row. A v58 peer receives the
//! proposal row itself on the attestation stream and refuses it (its
//! signature is the carried object's, which a v58 generic verify does not
//! read): it never applies a pending change as an effect.
//!
//! # Not carried in this cut (named, not hidden)
//!
//! - **The genesis key's eviction.** CC rules it evictable; no row carries it
//!   yet without colliding with the transport self-occurrence's revocation
//!   (`identity == occurrence`), so the door does not treat a revocation of
//!   the self-pair as a roster change and `signer_acts_for` still lets the
//!   genesis key act. Reported to CC.
//! - **Re-asserting a live key's occurrence** (new KEM keys, a new transport
//!   binding) is not a roster change and stays a `signer_acts_for` write.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};

use super::key_plane::{MintedFamily, PlaneSignature};
use super::two_path::{
    self, Answers, LandingPath, Proposal, ProposalKind, TwoPathDecision, TwoPathPolicy,
    TwoPathRefusal,
};
use super::types::{
    attestation_type, identity_type, Attestation, SignedIdentityOccurrence,
    SignedIdentityOccurrenceRevocation,
};
use super::{Error, FederationDirectory};

/// `W_self` (CC 3.3.6.3): the lone path's window, 86 400 s.
pub const W_SELF_SECS: i64 = 86_400;

/// The self roster's conditions on the two paths (CC 3.3.6.3).
#[must_use]
pub fn policy() -> TwoPathPolicy {
    TwoPathPolicy::self_roster(Duration::seconds(W_SELF_SECS))
}

/// The proposal row's dimension (CC 3.1.9.2 `objection:{state}`; minted here).
pub const DIMENSION_PROPOSAL: &str = "objection:proposal:v1";
/// An assent row's dimension (minted here).
pub const DIMENSION_ASSENT: &str = "objection:assent:v1";
/// An objection row's dimension: the reverse quorum's own.
pub const DIMENSION_OBJECTION: &str = super::reverse_quorum::DIMENSION_OBJECTION;
/// The `cohort` an answer names.
pub const COHORT_SELF: &str = "self";
/// The envelope member a proposal row carries its object under.
pub const PROPOSAL_MEMBER: &str = "roster_proposal";

/// The proposal row's family.
const PROPOSAL_FAMILY: MintedFamily = MintedFamily {
    dimension: DIMENSION_PROPOSAL,
    member: PROPOSAL_MEMBER,
    score: 1,
    id_domain: b"ciris:objection:proposal:v1:",
};

/// The members of a proposal object and of an answer envelope.
pub mod field {
    /// The self (fedID).
    pub const IDENTITY_KEY_ID: &str = "identity_key_id";
    /// `add` / `evict`.
    pub const KIND: &str = "kind";
    /// The key added or evicted.
    pub const TARGET_KEY_ID: &str = "target_key_id";
    /// Which signed object rides the proposal ([`super::carrier`]).
    pub const CARRIER: &str = "carrier";
    /// An answer's cohort (`self`).
    pub use super::super::reverse_quorum::field::COHORT;
    /// An answer's self.
    pub use super::super::reverse_quorum::field::COHORT_KEY_ID;
    /// Free text, never interpreted.
    pub use super::super::reverse_quorum::field::GROUNDS;
    /// The proposal an answer answers.
    pub use super::super::reverse_quorum::field::OBJECTS_TO;
}

/// The signed objects a proposal can carry. Each is also the member name.
pub mod carrier {
    /// A signed `identity_occurrence` (an addition).
    pub const IDENTITY_OCCURRENCE: &str = "identity_occurrence";
    /// A `withdraws` row against the pair's `identity:occurrence:v1` row.
    pub const WITHDRAWS: &str = "withdraws";
    /// A framed signed occurrence revocation.
    pub const OCCURRENCE_REVOCATION: &str = "identity_occurrence_revocation";
}

/// The node's clock for this door: THE purge clock (one clock read per door
/// call, no caller-chosen instant; the `cfg(test)` seam is the purge's), at
/// microseconds — the precision every backend stores (`TIMESTAMPTZ`), so a
/// receipt reads back as it was written.
pub(crate) fn roster_clock() -> DateTime<Utc> {
    chrono::SubsecRound::trunc_subsecs(super::steward_purge::purge_clock(), 6)
}

/// One proposal this node holds (V199): when it first held it, and whether it
/// has been settled.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SelfRosterReceipt {
    /// The proposal row's `attestation_id`.
    pub proposal_id: String,
    /// The self.
    pub identity_key_id: String,
    /// When THIS node first held it — the window's start.
    pub received_at: DateTime<Utc>,
    /// When it was settled, if it was.
    pub settled_at: Option<DateTime<Utc>>,
    /// `lands_quorum`, `lands_lone`, or a terminal refusal token.
    pub outcome: Option<String>,
}

/// The settle outcome a landing writes.
#[must_use]
pub const fn landed_outcome(path: LandingPath) -> &'static str {
    match path {
        LandingPath::Quorum => "lands_quorum",
        LandingPath::Lone => "lands_lone",
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The roster fold
// ─────────────────────────────────────────────────────────────────────────

/// Does `key`'s record carry the `user` role?
async fn is_user_key<D>(dir: &D, key: &str) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    Ok(dir
        .lookup_public_key(key)
        .await?
        .is_some_and(|k| identity_type::set_contains(&k.identity_type, identity_type::USER)))
}

/// **The live roster of `identity` now**: the genesis key and every ACTIVE
/// occurrence (revocations applied, the #421 re-establishment rule) whose key
/// is user-role.
pub async fn roster_now<D>(dir: &D, identity: &str) -> Result<BTreeSet<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut roster = BTreeSet::from([identity.to_owned()]);
    for o in dir.list_identity_occurrences_active(identity).await? {
        if o.occurrence_key_id != identity && is_user_key(dir, &o.occurrence_key_id).await? {
            roster.insert(o.occurrence_key_id);
        }
    }
    Ok(roster)
}

/// Was `key` a live roster key of `identity` at `at`? The genesis key always
/// is. Another key is when it is user-role and some admitted assertion of the
/// pair (the V161 history, or the held row) was signed at or before `at`,
/// unexpired at `at`, and not revoked by a revocation in effect at `at` that
/// came after it (the #421 rule, read at `at`).
pub async fn is_roster_key_at<D>(
    dir: &D,
    identity: &str,
    key: &str,
    at: DateTime<Utc>,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    if key == identity {
        return Ok(true);
    }
    if !is_user_key(dir, key).await? {
        return Ok(false);
    }
    let mut asserted: Vec<(DateTime<Utc>, Option<DateTime<Utc>>)> = dir
        .list_identity_occurrence_history_by_occurrence(key)
        .await?
        .into_iter()
        .filter(|h| h.identity_key_id == identity)
        .map(|h| (h.asserted_at, h.valid_until))
        .collect();
    asserted.extend(
        dir.list_identity_occurrences_by_occurrence_key(key)
            .await?
            .into_iter()
            .filter(|o| o.identity_key_id == identity)
            .map(|o| (o.asserted_at, o.valid_until)),
    );
    let revocations: Vec<DateTime<Utc>> = dir
        .list_identity_occurrence_revocations_for(identity)
        .await?
        .into_iter()
        .filter(|r| r.occurrence_key_id == key && r.effective_at <= at)
        .map(|r| r.effective_at)
        .collect();
    Ok(asserted.iter().any(|(asserted_at, valid_until)| {
        *asserted_at <= at
            && valid_until.is_none_or(|v| v > at)
            && !revocations
                .iter()
                .any(|effective| *effective >= *asserted_at)
    }))
}

/// **THE steward predicate** (CC 3.3.6.3, `CLM-self-roster-authority`;
/// CIRISServer#793): does `author` act as `steward` at `at`? It does when it
/// IS the steward, or when it is a live roster key of the steward's self at
/// `at` (the row's signed `asserted_at`) — any live roster key signs as the
/// fedID for every owner act; nothing is reserved to the genesis key. A key of
/// another self, or a key evicted before `at`, does not.
///
/// The consent fold's steward check
/// ([`grant_is_authored_for`](super::consent_by_humans::grant_is_authored_for),
/// and through it
/// [`consent_peers_by_principals`](super::consent_by_humans::consent_peers_by_principals))
/// and the one-responsible-steward gate
/// ([`check_single_node_owner_admission`](super::admission::check_single_node_owner_admission),
/// through [`self_of_at`]) ask this, and nothing else.
pub async fn acts_as_steward_at<D>(
    dir: &D,
    steward: &str,
    author: &str,
    at: DateTime<Utc>,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    if author == steward {
        return Ok(true);
    }
    is_roster_key_at(dir, steward, author, at).await
}

/// The self `key` signs as at `at`: the one user-role identity other than
/// `key` whose roster holds `key` at `at` ([`acts_as_steward_at`]), else `key`
/// itself (no such identity, or more than one: no single self to name).
pub async fn self_of_at<D>(dir: &D, key: &str, at: DateTime<Utc>) -> Result<String, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut candidates: BTreeSet<String> = dir
        .list_identity_occurrence_history_by_occurrence(key)
        .await?
        .into_iter()
        .map(|h| h.identity_key_id)
        .collect();
    candidates.extend(
        dir.list_identity_occurrences_by_occurrence_key(key)
            .await?
            .into_iter()
            .map(|o| o.identity_key_id),
    );
    let mut selves = Vec::new();
    for identity in candidates {
        if identity != key
            && is_user_key(dir, &identity).await?
            && acts_as_steward_at(dir, &identity, key, at).await?
        {
            selves.push(identity);
        }
    }
    Ok(match selves.as_slice() {
        [only] => only.clone(),
        _ => key.to_owned(),
    })
}

// ─────────────────────────────────────────────────────────────────────────
//  The proposal: what it carries, its row
// ─────────────────────────────────────────────────────────────────────────

/// The signed object a proposal carries, with what it changes.
#[derive(Debug, Clone, PartialEq)]
pub enum Carried {
    /// An addition: a signed occurrence of a key not on the roster.
    Occurrence(SignedIdentityOccurrence),
    /// An eviction by `withdraws` against the pair's occurrence row.
    Withdraws {
        /// The `withdraws` row, as its signer offered it.
        row: Attestation,
        /// The self.
        identity_key_id: String,
        /// The key it evicts.
        target_key_id: String,
    },
    /// An eviction by a framed signed revocation.
    Revocation(SignedIdentityOccurrenceRevocation),
}

impl Carried {
    /// Add or evict.
    #[must_use]
    pub fn kind(&self) -> ProposalKind {
        match self {
            Self::Occurrence(_) => ProposalKind::Add,
            Self::Withdraws { .. } | Self::Revocation(_) => ProposalKind::Evict,
        }
    }

    /// The self.
    #[must_use]
    pub fn identity_key_id(&self) -> &str {
        match self {
            Self::Occurrence(s) => &s.identity_occurrence.identity_key_id,
            Self::Withdraws {
                identity_key_id, ..
            } => identity_key_id,
            Self::Revocation(s) => &s.identity_occurrence_revocation.identity_key_id,
        }
    }

    /// The key added or evicted.
    #[must_use]
    pub fn target_key_id(&self) -> &str {
        match self {
            Self::Occurrence(s) => &s.identity_occurrence.occurrence_key_id,
            Self::Withdraws { target_key_id, .. } => target_key_id,
            Self::Revocation(s) => &s.identity_occurrence_revocation.occurrence_key_id,
        }
    }

    /// Who signed it.
    #[must_use]
    pub fn proposer(&self) -> &str {
        match self {
            Self::Occurrence(s) => &s.attesting_key_id,
            Self::Withdraws { row, .. } => &row.attesting_key_id,
            Self::Revocation(s) => &s.attesting_key_id,
        }
    }

    /// Its signed instant.
    #[must_use]
    pub fn asserted_at(&self) -> DateTime<Utc> {
        match self {
            Self::Occurrence(s) => s.identity_occurrence.asserted_at,
            Self::Withdraws { row, .. } => row.asserted_at,
            Self::Revocation(s) => s.identity_occurrence_revocation.revoked_at,
        }
    }

    fn carrier(&self) -> &'static str {
        match self {
            Self::Occurrence(_) => carrier::IDENTITY_OCCURRENCE,
            Self::Withdraws { .. } => carrier::WITHDRAWS,
            Self::Revocation(_) => carrier::OCCURRENCE_REVOCATION,
        }
    }

    /// The object the proposal row carries.
    fn object(&self) -> Result<serde_json::Value, Error> {
        let encode = |e: serde_json::Error| Error::Backend(format!("roster proposal encode: {e}"));
        let carried = match self {
            Self::Occurrence(s) => super::key_plane::occurrence_object(s)?,
            Self::Withdraws { row, .. } => {
                let mut v = serde_json::to_value(row).map_err(encode)?;
                if let Some(o) = v.as_object_mut() {
                    o.remove("persist_row_hash");
                    o.remove("withdraws_admission_rule");
                }
                v
            }
            Self::Revocation(s) => {
                let mut v = serde_json::to_value(s).map_err(encode)?;
                if let Some(inner) = v
                    .get_mut("identity_occurrence_revocation")
                    .and_then(serde_json::Value::as_object_mut)
                {
                    inner.remove("persist_row_hash");
                }
                v
            }
        };
        Ok(serde_json::json!({
            field::IDENTITY_KEY_ID: self.identity_key_id(),
            field::KIND: self.kind().as_str(),
            field::TARGET_KEY_ID: self.target_key_id(),
            field::CARRIER: self.carrier(),
            self.carrier(): carried,
        }))
    }

    /// The signature the proposal row carries: the object's own.
    fn signature(&self) -> Result<PlaneSignature, Error> {
        let hybrid = |classical: &str, pqc: &Option<String>, by: &str, at: DateTime<Utc>| {
            let Some(pqc) = pqc.clone() else {
                return Err(Error::SignatureInvalid(format!(
                    "{DIMENSION_PROPOSAL}: the carried object's signature is Ed25519-only — a \
                     minted row's signature is hybrid (CC 2.4)"
                )));
            };
            Ok(PlaneSignature {
                scrub_key_id: by.to_owned(),
                classical: classical.to_owned(),
                pqc: Some(pqc),
                scrub_timestamp: at,
                pqc_completed_at: Some(at),
            })
        };
        match self {
            Self::Occurrence(s) => hybrid(
                &s.signature.ed25519_signature_base64,
                &s.signature.mldsa65_signature_base64,
                &s.attesting_key_id,
                s.identity_occurrence.asserted_at,
            ),
            Self::Revocation(s) => hybrid(
                &s.signature.ed25519_signature_base64,
                &s.signature.mldsa65_signature_base64,
                &s.attesting_key_id,
                s.identity_occurrence_revocation.revoked_at,
            ),
            Self::Withdraws { row, .. } => {
                if row.scrub_signature_pqc.is_none() {
                    return hybrid("", &None, &row.scrub_key_id, row.scrub_timestamp);
                }
                Ok(PlaneSignature {
                    scrub_key_id: row.scrub_key_id.clone(),
                    classical: row.scrub_signature_classical.clone(),
                    pqc: row.scrub_signature_pqc.clone(),
                    scrub_timestamp: row.scrub_timestamp,
                    pqc_completed_at: row.pqc_completed_at,
                })
            }
        }
    }
}

/// **The proposal row** of a carried object (pure): attested by its proposer
/// about the self, signed with the object's own signature, asserted at the
/// object's own instant.
pub fn proposal_row(carried: &Carried) -> Result<Attestation, Error> {
    super::key_plane::minted_row(
        PROPOSAL_FAMILY,
        carried.proposer(),
        carried.identity_key_id(),
        carried.object()?,
        carried.asserted_at(),
        carried.signature()?,
    )
}

/// Is `row` a self-roster proposal row (by its signed dimension)?
#[must_use]
pub fn is_proposal_row(row: &Attestation) -> bool {
    row.attestation_type == attestation_type::SCORES
        && super::admission::envelope_dimension(&row.attestation_envelope)
            == Some(DIMENSION_PROPOSAL)
}

fn malformed(row: &Attestation, what: &str) -> Error {
    Error::malformed_row(
        "self_roster",
        super::malformed_row::ENVELOPE_MEMBER_INVALID,
        format!(
            "{DIMENSION_PROPOSAL} row {}: {what} (CIRISPersist#1099)",
            row.attestation_id
        ),
    )
}

/// The object a proposal row carries, read back. The withdraws carrier's
/// self and target are re-derived from the held occurrence row the
/// `withdraws` names, never taken from the object.
pub async fn carried_of_row<D>(dir: &D, row: &Attestation) -> Result<Carried, Error>
where
    D: FederationDirectory + ?Sized,
{
    let object = row
        .attestation_envelope
        .get(PROPOSAL_MEMBER)
        .ok_or_else(|| malformed(row, "no roster_proposal member"))?;
    let str_of = |k: &str| object.get(k).and_then(serde_json::Value::as_str);
    let carried_member = str_of(field::CARRIER).ok_or_else(|| malformed(row, "no carrier"))?;
    let inner = object
        .get(carried_member)
        .cloned()
        .ok_or_else(|| malformed(row, "the carrier member is absent"))?;
    let carried = match carried_member {
        carrier::IDENTITY_OCCURRENCE => {
            let mut inner = inner;
            if let Some(o) = inner
                .get_mut("identity_occurrence")
                .and_then(serde_json::Value::as_object_mut)
            {
                o.insert("persist_row_hash".to_owned(), String::new().into());
            }
            let mut s: SignedIdentityOccurrence = serde_json::from_value(inner)
                .map_err(|e| malformed(row, &format!("identity_occurrence: {e}")))?;
            s.identity_occurrence.persist_row_hash =
                super::types::compute_persist_row_hash(&s.identity_occurrence)?;
            Carried::Occurrence(s)
        }
        carrier::OCCURRENCE_REVOCATION => {
            let mut inner = inner;
            if let Some(o) = inner
                .get_mut("identity_occurrence_revocation")
                .and_then(serde_json::Value::as_object_mut)
            {
                o.insert("persist_row_hash".to_owned(), String::new().into());
            }
            let mut s: SignedIdentityOccurrenceRevocation = serde_json::from_value(inner)
                .map_err(|e| malformed(row, &format!("identity_occurrence_revocation: {e}")))?;
            s.identity_occurrence_revocation.persist_row_hash =
                super::types::compute_persist_row_hash(&s.identity_occurrence_revocation)?;
            Carried::Revocation(s)
        }
        carrier::WITHDRAWS => {
            let mut inner = inner;
            if let Some(o) = inner.as_object_mut() {
                o.insert("persist_row_hash".to_owned(), String::new().into());
            }
            let mut w: Attestation = serde_json::from_value(inner)
                .map_err(|e| malformed(row, &format!("withdraws: {e}")))?;
            w.persist_row_hash = super::types::compute_persist_row_hash(&w)?;
            let Some(rev) = super::key_plane::occurrence_withdrawal_of(dir, &w).await? else {
                return Err(Error::InvalidArgument(format!(
                    "{DIMENSION_PROPOSAL} row {}: the withdraws it carries names no held \
                     identity:occurrence:v1 row — re-offer once the occurrence row is held",
                    row.attestation_id
                )));
            };
            Carried::Withdraws {
                row: w,
                identity_key_id: rev.identity_key_id,
                target_key_id: rev.occurrence_key_id,
            }
        }
        other => return Err(malformed(row, &format!("unknown carrier {other:?}"))),
    };
    if str_of(field::IDENTITY_KEY_ID) != Some(carried.identity_key_id())
        || str_of(field::TARGET_KEY_ID) != Some(carried.target_key_id())
        || str_of(field::KIND) != Some(carried.kind().as_str())
    {
        return Err(malformed(
            row,
            "identity_key_id / target_key_id / kind disagree with the carried object",
        ));
    }
    Ok(carried)
}

/// **The proposal row's signature rule** at the attestation plane's generic
/// verify ([`super::tier_ingest::verify_row_hybrid_signature`]): the row is
/// exactly the row its carried object mints, and the object verifies as its
/// own door verifies it (signature, and a signer that acts for the self).
/// `Ok(false)` when the row is not a proposal row (the generic rule applies).
pub(crate) async fn verify_proposal_row<D>(dir: &D, row: &Attestation) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    if !is_proposal_row(row) {
        return Ok(false);
    }
    let carried = carried_of_row(dir, row).await?;
    super::key_plane::check_canonical_plane_row(row, &proposal_row(&carried)?)?;
    verify_carried(dir, &carried).await?;
    Ok(true)
}

/// The carried object verifies as its own door verifies it.
async fn verify_carried<D>(dir: &D, carried: &Carried) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    match carried {
        Carried::Occurrence(s) => super::admission::verify_signed_identity_occurrence(dir, s).await,
        Carried::Revocation(s) => {
            super::admission::verify_signed_identity_occurrence_revocation(dir, s).await
        }
        Carried::Withdraws {
            row,
            identity_key_id,
            ..
        } => {
            // The generic rule (a `withdraws` is never a minted row).
            super::tier_ingest::verify_envelope_signed_row(dir, row).await?;
            super::admission::check_signer_acts_for(
                dir,
                &row.attesting_key_id,
                identity_key_id,
                "self_roster",
            )
            .await
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Answers
// ─────────────────────────────────────────────────────────────────────────

/// The envelope of an answer to a proposal — an assent (`assent = true`) or
/// an objection — for a roster key to sign and put as a `scores` row
/// attested to the self (`attested_key_id = identity_key_id`). Defined here
/// so a producer and this node's fold agree byte for byte.
#[must_use]
pub fn vote_envelope(identity_key_id: &str, proposal_id: &str, assent: bool) -> serde_json::Value {
    serde_json::json!({
        "dimension": if assent { DIMENSION_ASSENT } else { DIMENSION_OBJECTION },
        "score": if assent { 1 } else { -1 },
        "confidence": 1,
        field::COHORT: COHORT_SELF,
        field::COHORT_KEY_ID: identity_key_id,
        field::OBJECTS_TO: proposal_id,
        field::GROUNDS: "",
    })
}

/// The self an answer row answers for, when it is one: a `scores` row on
/// [`DIMENSION_ASSENT`] / [`DIMENSION_OBJECTION`] naming `cohort: self`.
#[must_use]
pub fn answer_identity(row: &Attestation) -> Option<&str> {
    if row.attestation_type != attestation_type::SCORES {
        return None;
    }
    let dim = super::admission::envelope_dimension(&row.attestation_envelope)?;
    if dim != DIMENSION_ASSENT && dim != DIMENSION_OBJECTION {
        return None;
    }
    let env = &row.attestation_envelope;
    if env.get(field::COHORT)?.as_str()? != COHORT_SELF {
        return None;
    }
    env.get(field::COHORT_KEY_ID)?.as_str()
}

/// The held answers to `proposal`, and the target's latest signed act.
async fn answers_for<D>(
    dir: &D,
    identity: &str,
    proposal: &Proposal,
    rows: &[Attestation],
) -> Result<Answers, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut answers = Answers::default();
    let retired = super::admission::retracted_edge_ids(rows);
    for r in rows {
        if retired.contains(&r.attestation_id)
            || answer_identity(r) != Some(identity)
            || r.attestation_envelope
                .get(field::OBJECTS_TO)
                .and_then(serde_json::Value::as_str)
                != Some(proposal.id.as_str())
        {
            continue;
        }
        match super::admission::envelope_dimension(&r.attestation_envelope) {
            Some(DIMENSION_ASSENT) => {
                answers.approvers.insert(r.attesting_key_id.clone());
            }
            Some(DIMENSION_OBJECTION) => {
                answers.objectors.insert(r.attesting_key_id.clone());
            }
            _ => {}
        }
    }
    // Any signed act by the target answers (CC 3.3.6.3): its latest row.
    let one = std::num::NonZeroU32::new(1).expect("one");
    let mut pages = super::attestation_query::AttestationQuery::by(&proposal.target, one).pages();
    if let Some(page) = pages.next(dir).await? {
        answers
            .target_acts
            .extend(page.first().map(|a| a.asserted_at));
    }
    Ok(answers)
}

/// Every answer row held about `identity` (and the retractions naming them).
async fn answer_rows<D>(dir: &D, identity: &str) -> Result<Vec<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut rows = Vec::new();
    let mut pages = super::attestation_query::AttestationQuery::to(
        identity,
        super::attestation_query::FOLD_PAGE,
    )
    .dimension_any_of(&[DIMENSION_ASSENT, DIMENSION_OBJECTION])
    .pages();
    while let Some(page) = pages.next(dir).await? {
        rows.extend(page);
    }
    let ids: Vec<String> = rows.iter().map(|r| r.attestation_id.clone()).collect();
    if !ids.is_empty() {
        rows.extend(
            dir.list_composers_referencing_any(&ids, Some(identity), None)
                .await?,
        );
    }
    Ok(rows)
}

// ─────────────────────────────────────────────────────────────────────────
//  The plan: every open proposal of a self, decided
// ─────────────────────────────────────────────────────────────────────────

/// One open proposal of a self, as the door read it, with its decision.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Standing {
    /// The proposal.
    pub proposal: Proposal,
    /// Its decision at `decided_at`.
    pub decision: TwoPathDecision,
    /// The node's clock the decision was read at.
    pub decided_at: DateTime<Utc>,
    /// The keys whose assent counts toward the quorum.
    pub approvers: Vec<String>,
    /// The keys whose objection counts against the lone path.
    pub objectors: Vec<String>,
}

/// The plan for one self: the roster and every open proposal, decided at
/// `now`, `extra` (a proposal this node does not hold yet) included.
struct Plan {
    roster: BTreeSet<String>,
    entries: Vec<(Proposal, Answers, Carried, TwoPathDecision)>,
}

async fn plan<D>(
    dir: &D,
    identity: &str,
    extra: Option<(&Carried, &str)>,
    now: DateTime<Utc>,
) -> Result<Plan, Error>
where
    D: FederationDirectory + ?Sized,
{
    let roster = roster_now(dir, identity).await?;
    let mut held: Vec<(Proposal, Carried)> = Vec::new();
    for receipt in dir.list_open_self_roster_proposals(Some(identity)).await? {
        let Some(row) = dir.get_attestation(&receipt.proposal_id).await? else {
            continue;
        };
        let carried = match carried_of_row(dir, &row).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(proposal_id = %receipt.proposal_id, error = %e, "held roster proposal unreadable");
                continue;
            }
        };
        held.push((
            proposal_of(&carried, &receipt.proposal_id, receipt.received_at),
            carried,
        ));
    }
    if let Some((carried, id)) = extra {
        if !held.iter().any(|(p, _)| p.id == id) {
            held.push((proposal_of(carried, id, now), carried.clone()));
        }
    }
    let rows = answer_rows(dir, identity).await?;
    let mut with_answers = Vec::with_capacity(held.len());
    for (p, c) in held {
        let a = answers_for(dir, identity, &p, &rows).await?;
        with_answers.push((p, a, c));
    }
    let refs: Vec<(&Proposal, &Answers)> = with_answers.iter().map(|(p, a, _)| (p, a)).collect();
    let decided: Vec<(String, TwoPathDecision)> =
        two_path::decide_all(&roster, &refs, now, &policy())
            .into_iter()
            .map(|(p, d)| (p.id.clone(), d))
            .collect();
    let mut entries = Vec::with_capacity(decided.len());
    for (id, d) in decided {
        if let Some(pos) = with_answers.iter().position(|(p, _, _)| p.id == id) {
            let (p, a, c) = with_answers.swap_remove(pos);
            entries.push((p, a, c, d));
        }
    }
    Ok(Plan { roster, entries })
}

fn proposal_of(carried: &Carried, id: &str, received_at: DateTime<Utc>) -> Proposal {
    Proposal {
        id: id.to_owned(),
        kind: carried.kind(),
        proposer: carried.proposer().to_owned(),
        target: carried.target_key_id().to_owned(),
        asserted_at: carried.asserted_at(),
        received_at,
    }
}

/// **Every open proposal of `identity`, decided now** — what a host shows the
/// self's devices so they can answer.
pub async fn standing<D>(dir: &D, identity: &str) -> Result<Vec<Standing>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let now = roster_clock();
    let plan = plan(dir, identity, None, now).await?;
    Ok(plan
        .entries
        .into_iter()
        .map(|(proposal, answers, _, decision)| {
            let live = |s: &BTreeSet<String>| -> Vec<String> {
                s.iter()
                    .filter(|k| plan.roster.contains(*k) && **k != proposal.proposer)
                    .cloned()
                    .collect()
            };
            let objectors = live(&answers.objectors);
            let approvers = live(&answers.approvers)
                .into_iter()
                .filter(|k| !objectors.contains(k))
                .collect();
            Standing {
                proposal,
                decision,
                decided_at: now,
                approvers,
                objectors,
            }
        })
        .collect())
}

// ─────────────────────────────────────────────────────────────────────────
//  The gate: every door that can change a roster asks it
// ─────────────────────────────────────────────────────────────────────────

/// Is `carried` a change to the self's roster? An addition of a user-role key
/// not on it; an eviction of a key on it other than the genesis key.
async fn is_roster_change<D>(
    dir: &D,
    carried: &Carried,
    roster: &BTreeSet<String>,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    let (identity, target) = (carried.identity_key_id(), carried.target_key_id());
    // A self is a person (CC 3.3.6.3): a node or agent identity's
    // occurrences are not a roster.
    if target == identity || !is_user_key(dir, identity).await? {
        return Ok(false);
    }
    Ok(match carried.kind() {
        ProposalKind::Add => !roster.contains(target) && is_user_key(dir, target).await?,
        ProposalKind::Evict => roster.contains(target),
    })
}

/// **THE gate** (CC 3.3.6.3): may this roster change take effect now?
///
/// `Ok(())` when it is not a roster change, or when it lands (the door then
/// writes it exactly as before). Otherwise the change is held as a proposal
/// row (unless its proposer is not on the roster, which no answer can mend)
/// and [`Error::SelfRosterNotLanded`] is returned: nothing on the roster
/// changed.
pub async fn gate<D>(dir: &D, carried: Carried) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    let identity = carried.identity_key_id().to_owned();
    let roster = roster_now(dir, &identity).await?;
    if !is_roster_change(dir, &carried, &roster).await? {
        return Ok(());
    }
    let row = proposal_row(&carried)?;
    let id = row.attestation_id.clone();
    let now = roster_clock();
    let plan = plan(dir, &identity, Some((&carried, &id)), now).await?;
    let decision = plan
        .entries
        .iter()
        .find(|(p, ..)| p.id == id)
        .map(|(.., d)| *d)
        .ok_or_else(|| Error::Backend(format!("self-roster plan lost proposal {id}")))?;
    if let TwoPathDecision::Lands { path } = decision {
        if dir.get_attestation(&id).await?.is_some() {
            dir.note_self_roster_proposal(&id, &identity, now).await?;
            dir.settle_self_roster_proposal(&id, landed_outcome(path), now)
                .await?;
        }
        return Ok(());
    }
    // Terminal: no answer mends it. (`Cancelled` cannot arise under the self
    // roster's `AtWindow::StayOpen`; a policy that cancels settles it here.)
    let refused_for_good = matches!(
        decision,
        TwoPathDecision::Refused {
            reason: TwoPathRefusal::ProposerNotOnRoster
        } | TwoPathDecision::Cancelled
    );
    if !refused_for_good && dir.get_attestation(&id).await?.is_none() {
        dir.put_attestation(super::SignedAttestation { attestation: row })
            .await?;
    }
    if !refused_for_good {
        dir.note_self_roster_proposal(&id, &identity, now).await?;
    }
    let (earliest_lone_at, needs) = match decision {
        TwoPathDecision::Pending {
            earliest_lone_at,
            needs,
        } => (earliest_lone_at, needs),
        _ => (None, 0),
    };
    Err(Error::SelfRosterNotLanded {
        identity_key_id: identity,
        target_key_id: carried.target_key_id().to_owned(),
        kind: carried.kind().as_str(),
        proposal_id: id,
        decision: decision.token(),
        earliest_lone_at,
        needs,
    })
}

/// [`gate`] for a signed occurrence (`put_identity_occurrence`).
pub async fn gate_occurrence<D>(dir: &D, signed: &SignedIdentityOccurrence) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    gate(dir, Carried::Occurrence(signed.clone())).await
}

/// [`gate`] for a framed revocation (`put_identity_occurrence_revocation`).
pub async fn gate_revocation<D>(
    dir: &D,
    signed: &SignedIdentityOccurrenceRevocation,
) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    gate(dir, Carried::Revocation(signed.clone())).await
}

/// [`gate`] for a `withdraws` against an occurrence row (the attestation door).
pub async fn gate_withdrawal<D>(
    dir: &D,
    row: &Attestation,
    revocation: &super::types::IdentityOccurrenceRevocation,
) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    gate(
        dir,
        Carried::Withdraws {
            row: row.clone(),
            identity_key_id: revocation.identity_key_id.clone(),
            target_key_id: revocation.occurrence_key_id.clone(),
        },
    )
    .await
}

// ─────────────────────────────────────────────────────────────────────────
//  The executor
// ─────────────────────────────────────────────────────────────────────────

/// After a proposal or an answer row is admitted (the attestation door's
/// hook): record a proposal's arrival on this node's clock, then execute what
/// lands for its self. Never fails the admission that called it: the row is
/// stored; a failure to execute is logged and the sweep retries.
pub(crate) async fn after_admission<D>(dir: &D, row: &Attestation)
where
    D: FederationDirectory + ?Sized,
{
    let identity = if is_proposal_row(row) {
        if let Err(e) = dir
            .note_self_roster_proposal(&row.attestation_id, &row.attested_key_id, roster_clock())
            .await
        {
            tracing::warn!(proposal_id = %row.attestation_id, error = %e, "roster proposal receipt");
            return;
        }
        row.attested_key_id.clone()
    } else if let Some(identity) = answer_identity(row) {
        identity.to_owned()
    } else {
        return;
    };
    if let Err(e) = execute_for(dir, &identity).await {
        tracing::warn!(identity_key_id = %identity, error = %e, "self-roster execute");
    }
}

/// **Execute what lands** for one self: decide every open proposal, execute
/// the first that lands through its own door, re-read the roster, decide
/// again; settle a proposal whose proposer has left the roster. Returns how
/// many landed.
pub async fn execute_for<D>(dir: &D, identity: &str) -> Result<usize, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut landed = 0;
    let mut tried: BTreeSet<String> = BTreeSet::new();
    loop {
        let now = roster_clock();
        let plan = plan(dir, identity, None, now).await?;
        for (p, _, _, d) in &plan.entries {
            if matches!(
                d,
                TwoPathDecision::Refused {
                    reason: TwoPathRefusal::ProposerNotOnRoster,
                } | TwoPathDecision::Cancelled
            ) {
                dir.settle_self_roster_proposal(&p.id, d.token(), now)
                    .await?;
            }
        }
        let Some((p, _, carried, TwoPathDecision::Lands { path })) = plan
            .entries
            .into_iter()
            .find(|(p, .., d)| d.lands() && !tried.contains(&p.id))
        else {
            return Ok(landed);
        };
        tried.insert(p.id.clone());
        let applied = match carried {
            Carried::Occurrence(s) => dir.put_identity_occurrence(s).await,
            Carried::Revocation(s) => dir.put_identity_occurrence_revocation(s).await,
            Carried::Withdraws { row, .. } => dir
                .put_attestation(super::SignedAttestation { attestation: row })
                .await
                .map(|_| ()),
        };
        match applied {
            Ok(()) => {
                dir.settle_self_roster_proposal(&p.id, landed_outcome(path), now)
                    .await?;
                landed += 1;
            }
            Err(e) => {
                tracing::warn!(proposal_id = %p.id, error = %e, "a landing roster proposal did not apply");
            }
        }
    }
}

/// **The sweep**: [`execute_for`] every self with an open proposal on this
/// node — what lands by the lone path lands here, when its window closes.
/// Returns how many landed.
pub async fn execute_due<D>(dir: &D) -> Result<usize, Error>
where
    D: FederationDirectory + ?Sized,
{
    let selves: BTreeSet<String> = dir
        .list_open_self_roster_proposals(None)
        .await?
        .into_iter()
        .map(|r| r.identity_key_id)
        .collect();
    let mut landed = 0;
    for identity in selves {
        landed += execute_for(dir, &identity).await?;
    }
    Ok(landed)
}

// ─────────────────────────────────────────────────────────────────────────
//  The roster key's id (staged)
// ─────────────────────────────────────────────────────────────────────────

/// The device-derived roster key id prefix CC 3.3.6.3 refuses
/// (`device-<hex>-<fp>`, `CLM-self-roster-key-id`). **STAGED**: the refusal
/// lands when CIRISServer ships the `<fedID>-<own fingerprint>` form
/// (CIRISServer#793); until then this door accepts it, and
/// [`is_device_derived_roster_key_id`] only names it.
pub const DEVICE_DERIVED_ROSTER_KEY_PREFIX: &str = "device-";

/// Is `key_id` the device-derived spelling CC 3.3.6.3 will refuse? Staged:
/// nothing refuses on it yet.
#[must_use]
pub fn is_device_derived_roster_key_id(key_id: &str) -> bool {
    key_id.starts_with(DEVICE_DERIVED_ROSTER_KEY_PREFIX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// STAGED (`CLM-self-roster-key-id`, CIRISServer#793): the device-derived
    /// id is named, and NOT refused, in this cut. When Server ships the
    /// `<fedID>-<fp>` form the refusal lands and this test flips.
    #[test]
    fn device_derived_roster_key_id_is_named_not_refused_staged() {
        assert!(is_device_derived_roster_key_id(
            "device-8bd181c931ba-abcdefghij"
        ));
        assert!(!is_device_derived_roster_key_id(
            "alice-person-user-abcdefghij-klmnopqrst"
        ));
    }

    /// The answer envelope a producer signs names the self and the proposal,
    /// and reads back through [`answer_identity`].
    #[test]
    fn vote_envelope_round_trips() {
        let e = vote_envelope("alice", "p-1", true);
        assert_eq!(e["dimension"], DIMENSION_ASSENT);
        assert_eq!(e[field::COHORT], COHORT_SELF);
        assert_eq!(e[field::OBJECTS_TO], "p-1");
        let o = vote_envelope("alice", "p-1", false);
        assert_eq!(o["dimension"], "objection:raised:v1");
        assert_eq!(o["score"], -1);
    }
}
