//! v54.0.0 (CIRISPersist#1034, CC 4.4.3.2.8) — **an affiliation is declared,
//! and its config record is typed.**
//!
//! CC 4.4.3.2.8: an affiliation (`cohort_scope: affiliations`) is a community
//! record that gathers by necessity, shares all the community machinery, and
//! adds institutional governance "through one declared config record".
//! Everything in that record is "DECLARED at creation and visible to members on
//! joining". Before this cut persist had none of it:
//!
//! 1. **Nothing said a record IS an affiliation.** `Community` carries no
//!    cohort and `put_community` takes none, so any community could be
//!    addressed as `affiliations` and the reverse.
//! 2. **The config record had no storage, typing or admission.** "A value MUST
//!    resolve" (CC 4.4.3.2.8 A) was unenforced.
//!
//! # The discriminator lives in the SIGNED record
//!
//! The cohort is declared in the record's `policy_blob` as
//! [`POLICY_COHORT_FIELD`] (`"cohort_scope": "affiliations"`) — the label the
//! `Community` doc already names as `policy_blob`'s membership label
//! (CIRISEdge#48-A), and the key adopters' records already carry. Absent
//! means `community`, so every record founded without it keeps its bytes and
//! its meaning. What changes is that persist now READS it. It is persisted at founding because the record is — inside
//! the bytes its founders signed, covered by `persist_row_hash`, and carried
//! to every peer by the same replication that carries the roster. A database
//! column set by a door argument would be none of those: unsigned, local, and
//! absent on a replica. [`declared_cohort`] is the one reading.
//!
//! It is immutable: a supersession whose declared cohort differs from the held
//! record's is refused ([`Error::AffiliationCohortMismatch`]), and so is any
//! door that addresses a held record under the other cohort
//! ([`check_group_cohort`]) — the supersede doors, the membership write doors,
//! and the attestation write-scope gate's room lookup.
//!
//! # The config record
//!
//! [`AffiliationConfig`], at `policy_blob.affiliation_config`, types the limbs
//! CC names as fields: `affiliation_archetype`, `membership_basis`,
//! `classification_scheme`, `retention_policy`, `hierarchy`,
//! `designated_officials`, `compartments`, and `role_term`
//! (CIRISConstitution#163, the charter's term under the one-year ceiling).
//! Every other CC 4.4.3.2.8 limb (`legal_hold`, `erasure_policy`,
//! `lawful_access`, …) is carried verbatim in [`AffiliationConfig::other`]:
//! declared and visible, not yet typed. A config on a record that does not
//! declare `affiliations` is refused — the machinery is never forced on a body
//! that is "simply a community".
//!
//! [`check_community_record`] validates at founding (every backend's community
//! door) and on supersession (the shared supersede path).
//! [`AffiliationConfig::resolve`] is "a value MUST resolve": explicit field,
//! else the archetype's preset, else the canonical no-op default (one
//! `internal` class; retention `rotate-forward`).

use super::cohort::Cohort;
use super::types::Community;
use super::{Error, FederationDirectory};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The `policy_blob` member that declares a community-plane record's cohort
/// (the existing CIRISEdge#48-A membership label).
pub const POLICY_COHORT_FIELD: &str = "cohort_scope";
/// The `policy_blob` member that carries the CC 4.4.3.2.8 config record.
pub const POLICY_AFFILIATION_CONFIG_FIELD: &str = "affiliation_config";
/// The canonical no-op classification class (CC 4.4.3.2.8 A).
pub const DEFAULT_CLASS: &str = "internal";
/// The constitutional ceiling on a role term, in days: "at most one year
/// after `delegation_valid_from`" (CC 4.4.3.2.8 C, CIRISConstitution#163).
pub const ROLE_TERM_CEILING_DAYS: u32 = 365;
/// [`ROLE_TERM_CEILING_DAYS`] in seconds: CC pins the ceiling as exactly
/// `365 × 86400` s from `delegation_valid_from`. The ONE spelling of the
/// ceiling: the config check above (`role_term ≤ 365`, in days) and the
/// delegation walks' term lens
/// (`delegation_valid_until − delegation_valid_from ≤ 365 × 86400` s,
/// `admission::delegation_term_live_at`) both derive from
/// [`ROLE_TERM_CEILING_DAYS`] (CC 4.4.3.2.8 C; CIRISPersist#1032, #1034).
pub const ROLE_TERM_CEILING_SECONDS: i64 = ROLE_TERM_CEILING_DAYS as i64 * 86_400;

/// v61 S2 (CIRISPersist#1143; CC rc14 4.4.3.2.8, governance row
/// `affiliation_member_action`) — the [`Error::RosterAuthorityUnauthorized`]
/// rule: an act against a member of an affiliation with ONE deciding seat
/// carries no countersign from a key outside that seat.
pub const AFFILIATION_COUNTERSIGN_MISSING: &str = "affiliation_countersign_missing";

/// v62.0.0 (SL-fix3c; CC 4.4.3.12) — the voice role a designated official
/// fills on a counted act against a member in a one-seat affiliation
/// (`edition2::second_signer_voice::held_rows_for`'s `role`): its
/// countersign. Not a family's second-signer role: the families name none.
pub const AFFILIATION_COUNTERSIGN_ROLE: &str = "affiliation_countersign";

/// v62.0.0 (SL-fix2; CC 4.4.3.12) — **an affiliation's deciding seats** at
/// `at`: its active founders, or its active members where it names no
/// founder (the roster as authorized at `at`). The ONE reading of "the
/// deciding seat": [`check_one_voice_countersign`] asks it, and the door's
/// authorship context for the `slash` families (`edition2::typed::family_context`,
/// CC's `seats=one` selector) counts it, so the cell that makes a row counted
/// and the gate that asks for its countersign agree on how many seats there
/// are. Before v62.0.0 the door counted every listed member.
///
/// # Errors
/// Directory reads.
pub async fn deciding_seats<F>(
    dir: &F,
    community: &Community,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let roster = Box::pin(super::authorized_community_roster_at(dir, community, at)).await?;
    let founders: BTreeSet<String> = roster
        .iter()
        .filter(|m| m.role.as_deref() == Some(super::admission::MEMBER_ROLE_FOUNDER))
        .map(|m| m.key_id.clone())
        .collect();
    Ok(if founders.is_empty() {
        roster.into_iter().map(|m| m.key_id).collect()
    } else {
        founders
    })
}

/// v62.0.0 (SL-fix3a) — **an act against a member** that CC 4.4.3.12's
/// one-seat floor reaches at the edition-2 door, by the input that names the
/// room it is taken in. `membership:removal` is decided by the roster door
/// (`check_community_roster_authority_verdict`), not here.
#[derive(Debug, Clone, Copy)]
pub enum FloorAct<'a> {
    /// A `quarantine:{state}` marker or a `slashing:{outcome}` verdict: the
    /// room is the row's `community_id`.
    Slash {
        /// The row's `community_id`.
        community_id: &'a str,
    },
    /// A `takedown_notice:{basis}`: the room is a community the content's
    /// HELD binding rows place it in (never a community or scope the notice
    /// itself names: a signer-chosen input must not decide how many seats the
    /// signer needs), and the act is against a member only when the actor is
    /// not a signed subject of the content (an author's own takedown is its
    /// own act, as a resignation is).
    Takedown {
        /// The notice's `content_sha256` (64 hex).
        content_sha256: &'a str,
    },
}

/// v62.0.0 (SL-fix3a; CC 4.4.3.12) — **the one-seat affiliation whose floor
/// binds `act` by `actor` at `at`**, or `None`: a HELD record declaring
/// `cohort_scope: affiliations` whose [`deciding_seats`] at `at` number
/// exactly one. Never a plain community, never a room of two or more deciding
/// seats, never a room this node does not hold.
///
/// The ONE reading: the door's authorship context (`edition2::typed::family_context`:
/// CC's `group=affiliations & seats=one => counted` arm), the countersign
/// gates (`admission::check_delegated_duty_scores_admission`,
/// `takedown_tombstone::check_takedown_notice_row_admission`), the stored
/// attester (`edition2::voices::primary_voice`), the official's listing
/// (`second_signer_voice::held_rows_for`, role `affiliation_countersign`)
/// and the producer all ask it, so the cell that makes a row counted and the
/// gate that asks for its countersign cannot disagree.
///
/// # Errors
/// Directory reads; a held record whose cohort does not parse.
///
/// v62.0.0 (BF22, pass 4m4) — returns a `dyn Future + Send`, not an `async
/// fn`'s opaque type. This fn is reached again through its own takedown arm
/// (`content_binding` -> the tombstone and admission walks -> here), and an
/// opaque future carries its whole callee tree in its type: proving a store
/// open `Send` overflowed the compiler's recursion depth (E0275) in persist
/// and in any host that `tokio::spawn`s an open. The type ends at this box.
pub fn floor_affiliation<'a, F>(
    dir: &'a F,
    act: FloorAct<'a>,
    actor: &'a str,
    at: chrono::DateTime<chrono::Utc>,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Option<Community>, Error>> + Send + 'a>,
>
where
    F: FederationDirectory + ?Sized,
{
    Box::pin(floor_affiliation_body(dir, act, actor, at))
}

/// [`floor_affiliation`]'s body.
async fn floor_affiliation_body<F>(
    dir: &F,
    act: FloorAct<'_>,
    actor: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<Option<Community>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let candidates: Vec<String> = match act {
        FloorAct::Slash { community_id } => {
            if community_id.is_empty() {
                return Ok(None);
            }
            vec![community_id.to_owned()]
        }
        FloorAct::Takedown { content_sha256 } => {
            let Some(binding) = Box::pin(super::takedown_tombstone::content_binding(
                dir.as_dyn_directory(),
                content_sha256,
            ))
            .await?
            else {
                return Ok(None);
            };
            if binding.subjects.contains(actor) {
                return Ok(None);
            }
            binding.communities.into_iter().collect()
        }
    };
    for c in candidates {
        super::edition2::fold::reads(super::edition2::fold::Dep::key(&c));
        let Some(record) = dir.lookup_community(&c).await? else {
            continue;
        };
        if declared_cohort(&record)? != Cohort::Affiliations {
            continue;
        }
        if Box::pin(deciding_seats(dir, &record, at)).await?.len() == 1 {
            return Ok(Some(record));
        }
    }
    Ok(None)
}

/// v62.0.0 (SL-fix3d; CC 4.4.3.12 as ruled 11-21) — **the voices of a
/// countersigned act that still stand**: `voices` less every designated
/// official of `room` that has withdrawn its own countersign of `row` (a
/// held `withdraws` it authored naming the row). The act is a decision only
/// while both voices stand, so the countersign gates count these. The
/// withdrawal touches the row it names (`refs.target`), so the act re-folds
/// when it lands and un-concludes forward; what was done under it stands.
///
/// # Errors
/// Directory reads.
pub async fn standing_voices<F>(
    dir: &F,
    room: &Community,
    row: &super::Attestation,
    voices: BTreeSet<String>,
) -> Result<BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let officials = designated_official_keys(room)?;
    if officials.is_empty() || row.attestation_id.is_empty() {
        return Ok(voices);
    }
    if let Some(dep) = super::edition2::fold::Dep::row_hex(&row.attestation_id) {
        super::edition2::fold::reads(dep);
    }
    let withdrawn: BTreeSet<String> = dir
        .list_composers_referencing_any(std::slice::from_ref(&row.attestation_id), None, None)
        .await?
        .into_iter()
        .filter(|w| w.attestation_type == super::types::attestation_type::WITHDRAWS)
        .map(|w| w.attesting_key_id)
        .filter(|k| officials.contains(k))
        .collect();
    Ok(voices
        .into_iter()
        .filter(|v| !withdrawn.contains(v))
        .collect())
}

/// v62.0.0 (SL-fix3d; CC 4.4.3.12 as ruled 11-21: "it takes two voices to
/// hold power over a member and one to lay it down") — **the `withdraws` of
/// a countersigned act** (a counted quarantine marker, slashing verdict or
/// takedown notice in a one-seat affiliation, [`floor_affiliation`]).
/// `Ok(None)`: `target` is no such act (the caller's rules apply).
///
/// - by the act's actor (its stored attester, the deciding seat): rule 1,
///   the seat retracting its own decision;
/// - by a designated official that voiced it: admitted UNSTAMPED
///   (`Some(None)`): it retires nothing itself (the retraction folds honour
///   only the producer and a stamp), it withdraws the official's own voice,
///   which [`standing_voices`] then stops counting, so the act un-concludes
///   forward and waits for a countersign again;
/// - by anyone else: refused `WithdrawsNotAdmitted`.
///
/// # Errors
/// [`Error::WithdrawsNotAdmitted`]; directory reads.
pub async fn check_floor_act_withdrawal<F>(
    dir: &F,
    row: &super::Attestation,
    target: &super::Attestation,
) -> Result<Option<Option<u8>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if row.attestation_type != super::types::attestation_type::WITHDRAWS
        || !super::edition2::voices::carried_is_counted(target)
    {
        return Ok(None);
    }
    let env = &target.attestation_envelope;
    let text = |k: &str| env.get(k).and_then(serde_json::Value::as_str).unwrap_or("");
    let dimension = text("dimension");
    let act = if dimension.starts_with(super::admission::QUARANTINE_DIMENSION_PREFIX)
        || dimension.starts_with(super::admission::SLASHING_DIMENSION_PREFIX)
    {
        FloorAct::Slash {
            community_id: text(super::quarantine::field::COMMUNITY_ID),
        }
    } else if dimension.starts_with(super::takedown_tombstone::NOTICE_DIMENSION_PREFIX) {
        FloorAct::Takedown {
            content_sha256: text("content_sha256"),
        }
    } else {
        return Ok(None);
    };
    let Some(room) = Box::pin(floor_affiliation(
        dir,
        act,
        &target.attesting_key_id,
        target.asserted_at,
    ))
    .await?
    else {
        return Ok(None);
    };
    if row.attesting_key_id == target.attesting_key_id {
        return Ok(Some(Some(1)));
    }
    let voiced = super::edition2::voices::row_voice_issuers(dir.as_dyn_directory(), target).await?;
    if designated_official_keys(&room)?.contains(&row.attesting_key_id)
        && voiced.contains(&row.attesting_key_id)
    {
        return Ok(Some(None));
    }
    Err(Error::WithdrawsNotAdmitted {
        issuer: row.attesting_key_id.clone(),
        target_attestation_id: target.attestation_id.clone(),
        beyond_delegation_depth_cap: false,
    })
}

/// v62.0.0 (SL-fix3c) — the designated officials of `community` (the keys
/// that may countersign an act against a member in a one-seat affiliation,
/// CC 4.4.3.12). Empty for a record with no affiliation config.
///
/// # Errors
/// A malformed config record.
pub fn designated_official_keys(community: &Community) -> Result<BTreeSet<String>, Error> {
    Ok(affiliation_config_of(community)?
        .and_then(|c| c.designated_officials)
        .unwrap_or_default()
        .into_iter()
        .map(|o| o.key_id)
        .collect())
}

/// v61 S2 (CIRISPersist#1143; CC rc14 4.4.3.2.8,
/// `CLM-affiliation-one-voice-countersign`) — **one voice does not act
/// against a member alone.** Where an affiliation has ONE deciding seat (its
/// active founders, or its active members where it names no founder), an act
/// against a member — here, a `membership:removal` — is admitted only when a
/// key OUTSIDE the seat also signed it: a designated official
/// ([`AffiliationConfig::designated_officials`]) who is not the seat. A body
/// of two or more seats decides under its own protocol, which already
/// carries the second voice. Not an affiliation: no rule.
///
/// The review-holder of an overseeing body (CC's second outside key) has no
/// typed "overseeing body" in the config yet, and the "stands as a
/// reconsideration proposal" path has no held state: both are follow-ups;
/// this refuses instead.
///
/// v61.1.0 (D15; CIRISPersist#1198, CC 4.5.13) — "outside the seat" is asked
/// of PERSONS ([`key_person`](super::key_person)), as every room vote now
/// is: an official key that is a device of the seat's own person is not
/// outside it, and a countersign counts only when its signer speaks for a
/// person who holds no seat. The seat holder's second device naming itself an
/// official is still one voice. Judged as the keys stood at `at`.
///
/// # Errors
///
/// [`Error::RosterAuthorityUnauthorized`] with [`AFFILIATION_COUNTERSIGN_MISSING`];
/// a malformed declared cohort or config; directory reads.
pub async fn check_one_voice_countersign<F>(
    dir: &F,
    community: &Community,
    primary: &str,
    signers: &BTreeSet<String>,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if declared_cohort(community)? != Cohort::Affiliations {
        return Ok(());
    }
    // v62.0.0 (wave GC5; CC 2.7.3) — the roster, the officials' and the
    // seats' person records are other rows: declared, so the act re-folds
    // when one changes.
    super::edition2::fold::reads(super::edition2::fold::Dep::key(&community.community_key_id));
    let seats = Box::pin(deciding_seats(dir, community, at)).await?;
    if seats.len() != 1 {
        return Ok(());
    }
    let officials = designated_official_keys(community)?;
    for k in seats.iter().chain(&officials) {
        super::edition2::fold::reads(super::edition2::fold::Dep::key(k));
    }
    let selves = super::key_person::KeySelves::read(
        dir,
        seats
            .iter()
            .chain(&officials)
            .chain(signers)
            .cloned()
            .collect(),
    )
    .await?;
    let persons = selves.at(at);
    let seat_persons: BTreeSet<&str> = seats.iter().map(|k| persons.seat_person(k)).collect();
    // One check, on the signer's voice: an official countersigns only when it
    // speaks for a person who is not the seat's. `voice(k)` is `Some` only
    // where it equals `seat_person(k)`, so a seat key, or another device of
    // the seat's person, is refused here; no second filter on the officials.
    if signers.iter().any(|s| {
        officials.contains(s) && persons.voice(s).is_some_and(|p| !seat_persons.contains(p))
    }) {
        return Ok(());
    }
    // v62.0.0 (wave T1) — the countersign not voiced YET is a short count,
    // not a refusal: the edition-2 group door keeps the voice (Pending, held
    // `count_short` in the fold) and the official's later voice lands it.
    // Outside the door's attempt this is a no-op and the refusal stands.
    super::edition2::group::note_short();
    // v62.0.0 (wave GC5; CC 2.7.3, 4.4.3.12) — a countersign not yet held is
    // a voice short: the act is HELD, concluding nothing, and re-folds when
    // a further voice of it (or a roster / person change) lands. Outside a
    // fold attempt (the earlier-form door) it is the refusal it was.
    Err(super::edition2::fold::hold(
        super::edition2::fold::reason::AFFILIATION_COUNTERSIGN_MISSING,
        Error::RosterAuthorityUnauthorized {
            group_key_id: community.community_key_id.clone(),
            offered_authority_key_id: primary.to_owned(),
            rule: AFFILIATION_COUNTERSIGN_MISSING,
            shortfall: None,
        },
    ))
}

/// The refusal rules of [`Error::AffiliationConfigInvalid`]. Stable tokens;
/// append-only.
pub mod rule {
    /// `policy_blob.cohort_scope` is not `community` or `affiliations`.
    pub const COHORT_UNKNOWN: &str = "cohort_unknown";
    /// A config record on a record that does not declare `affiliations`.
    pub const CONFIG_ON_COMMUNITY: &str = "config_on_community";
    /// The config record does not parse as the typed record.
    pub const CONFIG_MALFORMED: &str = "config_malformed";
    /// `classification_scheme.classes` is empty, or a class name is empty or
    /// repeated.
    pub const CLASSIFICATION_INVALID: &str = "classification_invalid";
    /// `retention_policy` names a class the resolved scheme does not declare.
    pub const RETENTION_UNKNOWN_CLASS: &str = "retention_unknown_class";
    /// A class's retention floor lies past its ceiling (or a `permanent`
    /// class declares a ceiling).
    pub const RETENTION_FLOOR_ABOVE_CEILING: &str = "retention_floor_above_ceiling";
    /// A compartment name is empty or repeated, a class names a compartment
    /// that is not declared, or a compartment member is not on the roster
    /// ("membership ⊆ roster").
    pub const COMPARTMENT_INVALID: &str = "compartment_invalid";
    /// `role_term` is zero or past the one-year ceiling.
    pub const ROLE_TERM_OUT_OF_RANGE: &str = "role_term_out_of_range";
    /// `hierarchy.depth_cap` is zero or past the absolute delegation ceiling.
    pub const HIERARCHY_DEPTH_OUT_OF_RANGE: &str = "hierarchy_depth_out_of_range";
    /// A designated official names an empty role or key.
    pub const DESIGNATED_OFFICIAL_INVALID: &str = "designated_official_invalid";
    /// v60.0.0 (CIRISPersist#1036 item 3) — a `licence_audiences` entry names
    /// an empty licence class or a scope outside the closed `cohort_scope`
    /// set.
    pub const LICENCE_AUDIENCE_INVALID: &str = "licence_audience_invalid";
}

/// CC 4.4.3.2.8's named presets. Closed: a preset persist does not know
/// cannot resolve, and "a value MUST resolve".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AffiliationArchetype {
    /// A small committee served by construction (the holiday-party row).
    InformalAdhoc,
    /// A nonprofit board.
    NonprofitBoard,
    /// A healthcare provider.
    HealthcareProvider,
    /// A legal practice.
    LegalPractice,
    /// A government body.
    GovBody,
    /// An intergovernmental organisation (the UN / IGO row).
    Igo,
}

/// CC 4.4.3.2.8 — the necessity axis, orthogonal to `cohort_scope`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MembershipBasis {
    /// Voluntarily entered yet total (a collective settlement, an order).
    VoluntaryTotal,
    /// Ascribed (a member-state principal).
    Ascriptive,
    /// Assigned by role (the workplace committee).
    RoleAssigned,
    /// By employment contract.
    EmploymentContract,
}

/// One basis or several (CC's IGO row is `employment-contract + ascriptive`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MembershipBasisDecl {
    /// A single basis.
    One(MembershipBasis),
    /// Several.
    Many(Vec<MembershipBasis>),
}

impl MembershipBasisDecl {
    /// The declared set, sorted and deduplicated.
    #[must_use]
    pub fn set(&self) -> Vec<MembershipBasis> {
        let s: BTreeSet<MembershipBasis> = match self {
            Self::One(b) => std::iter::once(*b).collect(),
            Self::Many(v) => v.iter().copied().collect(),
        };
        s.into_iter().collect()
    }
}

/// One class of the sensitivity lattice and its bindings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassEntry {
    /// The class name (`content_class` value).
    pub name: String,
    /// The compartment this class binds to, if any; must be declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compartment: Option<String>,
    /// Non-erasable during retention (the declared N5 gate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub erasure_exempt: Option<bool>,
    /// The remaining bindings (`crypto_tier`, `disclosure_bar`,
    /// `external_controller`, …), carried verbatim.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// CC 4.4.3.2.8 A — an ordered lattice (lowest first) plus handling tags.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassificationScheme {
    /// The classes, lowest sensitivity first.
    pub classes: Vec<ClassEntry>,
    /// Open-vocabulary handling tags.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub handling_tags: Vec<String>,
}

/// A retention floor: a minimum in days, or `permanent`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RetentionFloor {
    /// Must not delete before this many days.
    Days(u32),
    /// The literal `"permanent"`.
    Permanent(PermanentToken),
}

/// The literal `"permanent"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermanentToken {
    /// `"permanent"`.
    Permanent,
}

/// One class's retention row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassRetention {
    /// The floor (`retain_minimum`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retain_minimum: Option<RetentionFloor>,
    /// The ceiling (`delete_after`), in days.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_after: Option<u32>,
    /// Days added to the floor for a record about a minor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minor_age_of_majority_offset: Option<u32>,
    /// The declared legal basis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legal_basis: Option<String>,
}

/// The literal `"rotate-forward"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RotateForward {
    /// `"rotate-forward"` — the CC 6.1.2 noise-floor default.
    RotateForward,
}

/// CC 4.4.3.2.8 A — retention: the noise-floor default, or per class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RetentionPolicy {
    /// `"rotate-forward"`.
    RotateForward(RotateForward),
    /// Per-class rows keyed by class name.
    PerClass(BTreeMap<String, ClassRetention>),
}

/// CC 4.4.3.2.8 C — hierarchy over `delegates_to`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hierarchy {
    /// The configurable depth cap (> the CC 4.1.1 default 5 for deep
    /// secretariats), never past the absolute ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub depth_cap: Option<u32>,
    /// Roles, branches and nested sub-affiliations, carried verbatim.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// CC 4.4.3.2.8 C — a named accountable-human root for an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesignatedOfficial {
    /// The office (`privacy_officer`, `records_officer`, …).
    pub role: String,
    /// The accountable human's key.
    pub key_id: String,
}

/// CC 4.4.3.2.8 B — a need-to-know sub-cohort, membership ⊆ roster.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Compartment {
    /// The compartment name.
    pub name: String,
    /// Members; each must be on the affiliation's roster.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    /// The per-member deny-list (ethical walls).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusions: Vec<String>,
}

/// v54.0.0 (CIRISPersist#1034, CC 4.4.3.2.8) — the typed config record.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct AffiliationConfig {
    /// The preset that pre-fills every unset field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affiliation_archetype: Option<AffiliationArchetype>,
    /// The necessity axis.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_basis: Option<MembershipBasisDecl>,
    /// MANDATORY-with-default limb.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub classification_scheme: Option<ClassificationScheme>,
    /// MANDATORY-with-default limb.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention_policy: Option<RetentionPolicy>,
    /// OPTIONAL limb.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hierarchy: Option<Hierarchy>,
    /// OPTIONAL limb.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub designated_officials: Option<Vec<DesignatedOfficial>>,
    /// OPTIONAL limb.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compartments: Option<Vec<Compartment>>,
    /// The charter's role term in days (CIRISConstitution#163), at most
    /// [`ROLE_TERM_CEILING_DAYS`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_term: Option<u32>,
    /// v60.0.0 (CIRISPersist#1036 item 3, CC 2.4.1.2.1, CIRISConstitution#162)
    /// — **the licence audience per licence class**: `{license_type:
    /// cohort_scope}`. "A licence has no public default: its `cohort_scope` is
    /// the authority's declared choice per licence class in the affiliation's
    /// charter, the smallest that fits." A class not named here has no
    /// declared choice, so its licences may take any scope but a commons one
    /// (the admission gate `admission::check_licence_audience`). Persist's
    /// spelling: CC names the declaration, not the member.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub licence_audiences: Option<BTreeMap<String, String>>,
    /// Every other declared CC 4.4.3.2.8 limb, carried verbatim.
    #[serde(flatten)]
    pub other: serde_json::Map<String, serde_json::Value>,
}

/// The config with every mandatory limb resolved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedAffiliationConfig {
    /// The preset, if one was declared.
    pub affiliation_archetype: Option<AffiliationArchetype>,
    /// The resolved basis set (empty when neither declared nor preset).
    pub membership_basis: Vec<MembershipBasis>,
    /// The resolved lattice, lowest first.
    pub classification_scheme: ClassificationScheme,
    /// The resolved retention.
    pub retention_policy: RetentionPolicy,
}

fn class(name: &str) -> ClassEntry {
    ClassEntry {
        name: name.to_owned(),
        compartment: None,
        erasure_exempt: None,
        other: serde_json::Map::new(),
    }
}

fn scheme(names: &[&str]) -> ClassificationScheme {
    ClassificationScheme {
        classes: names.iter().map(|n| class(n)).collect(),
        handling_tags: Vec::new(),
    }
}

/// The canonical no-op default (CC 4.4.3.2.8 A).
#[must_use]
pub fn default_classification() -> ClassificationScheme {
    scheme(&[DEFAULT_CLASS])
}

/// What an archetype pre-fills. Only values CC 4.4.3.2.8's own text gives are
/// filled (its instantiation table pins `informal_adhoc` and `igo`); every
/// other preset resolves each limb to the canonical default until CC publishes
/// the preset table.
fn preset(a: AffiliationArchetype) -> (Vec<MembershipBasis>, Option<ClassificationScheme>) {
    use MembershipBasis as B;
    match a {
        AffiliationArchetype::InformalAdhoc => (vec![B::RoleAssigned], None),
        AffiliationArchetype::Igo => (
            vec![B::Ascriptive, B::EmploymentContract],
            Some(scheme(&[
                "Unclassified",
                "Confidential",
                "Strictly-Confidential",
            ])),
        ),
        AffiliationArchetype::NonprofitBoard
        | AffiliationArchetype::HealthcareProvider
        | AffiliationArchetype::LegalPractice
        | AffiliationArchetype::GovBody => (Vec::new(), None),
    }
}

fn invalid(group: &str, rule: &'static str, detail: impl Into<String>) -> Error {
    Error::AffiliationConfigInvalid {
        group_key_id: group.to_owned(),
        rule,
        detail: detail.into(),
    }
}

impl AffiliationConfig {
    /// "A value MUST resolve": explicit field, else the archetype's preset,
    /// else the canonical no-op default.
    #[must_use]
    pub fn resolve(&self) -> ResolvedAffiliationConfig {
        let (preset_basis, preset_scheme) = self
            .affiliation_archetype
            .map(preset)
            .unwrap_or((Vec::new(), None));
        ResolvedAffiliationConfig {
            affiliation_archetype: self.affiliation_archetype,
            membership_basis: self
                .membership_basis
                .as_ref()
                .map(MembershipBasisDecl::set)
                .unwrap_or(preset_basis),
            classification_scheme: self
                .classification_scheme
                .clone()
                .or(preset_scheme)
                .unwrap_or_else(default_classification),
            retention_policy: self
                .retention_policy
                .clone()
                .unwrap_or(RetentionPolicy::RotateForward(RotateForward::RotateForward)),
        }
    }

    /// Validate against the record it rides on (`group` names it in a
    /// refusal; `roster` is its member key ids).
    ///
    /// # Errors
    /// [`Error::AffiliationConfigInvalid`] naming the [`rule`] that failed.
    pub fn validate(&self, group: &str, roster: &BTreeSet<&str>) -> Result<(), Error> {
        let resolved = self.resolve();
        let mut names = BTreeSet::new();
        if resolved.classification_scheme.classes.is_empty() {
            return Err(invalid(group, rule::CLASSIFICATION_INVALID, "no classes"));
        }
        for c in &resolved.classification_scheme.classes {
            if c.name.is_empty() || !names.insert(c.name.as_str()) {
                return Err(invalid(
                    group,
                    rule::CLASSIFICATION_INVALID,
                    format!("class name {:?} is empty or repeated", c.name),
                ));
            }
        }
        let mut compartments = BTreeSet::new();
        for comp in self.compartments.iter().flatten() {
            if comp.name.is_empty() || !compartments.insert(comp.name.as_str()) {
                return Err(invalid(
                    group,
                    rule::COMPARTMENT_INVALID,
                    format!("compartment name {:?} is empty or repeated", comp.name),
                ));
            }
            if let Some(m) = comp.members.iter().find(|m| !roster.contains(m.as_str())) {
                return Err(invalid(
                    group,
                    rule::COMPARTMENT_INVALID,
                    format!(
                        "compartment {:?} names {m:?}, who is not on the roster (membership ⊆ roster)",
                        comp.name
                    ),
                ));
            }
        }
        for c in &resolved.classification_scheme.classes {
            if let Some(comp) = &c.compartment {
                if !compartments.contains(comp.as_str()) {
                    return Err(invalid(
                        group,
                        rule::COMPARTMENT_INVALID,
                        format!("class {:?} binds undeclared compartment {comp:?}", c.name),
                    ));
                }
            }
        }
        if let RetentionPolicy::PerClass(rows) = &resolved.retention_policy {
            for (name, row) in rows {
                if !names.contains(name.as_str()) {
                    return Err(invalid(
                        group,
                        rule::RETENTION_UNKNOWN_CLASS,
                        format!("retention row for undeclared class {name:?}"),
                    ));
                }
                let floor_past_ceiling = match (&row.retain_minimum, row.delete_after) {
                    (Some(RetentionFloor::Permanent(_)), Some(_)) => true,
                    (Some(RetentionFloor::Days(min)), Some(max)) => min > &max,
                    _ => false,
                };
                if floor_past_ceiling {
                    return Err(invalid(
                        group,
                        rule::RETENTION_FLOOR_ABOVE_CEILING,
                        format!("class {name:?}: retain_minimum lies past delete_after"),
                    ));
                }
            }
        }
        if let Some(t) = self.role_term {
            // The same ceiling the term lens enforces on an edge, in the same
            // unit: `role_term × 86400 ≤ 365 × 86400` (CC 4.4.3.2.8 C).
            if t == 0 || i64::from(t) * 86_400 > ROLE_TERM_CEILING_SECONDS {
                return Err(invalid(
                    group,
                    rule::ROLE_TERM_OUT_OF_RANGE,
                    format!("role_term {t} days; 1..={ROLE_TERM_CEILING_DAYS} (one-year ceiling)"),
                ));
            }
        }
        if let Some(d) = self.hierarchy.as_ref().and_then(|h| h.depth_cap) {
            let ceiling = super::admission::MAX_WITHDRAWS_DELEGATION_DEPTH;
            if d == 0 || d as usize > ceiling {
                return Err(invalid(
                    group,
                    rule::HIERARCHY_DEPTH_OUT_OF_RANGE,
                    format!("hierarchy.depth_cap {d}; 1..={ceiling}"),
                ));
            }
        }
        if let Some(o) = self
            .designated_officials
            .iter()
            .flatten()
            .find(|o| o.role.is_empty() || o.key_id.is_empty())
        {
            return Err(invalid(
                group,
                rule::DESIGNATED_OFFICIAL_INVALID,
                format!("designated official {o:?} names an empty role or key"),
            ));
        }
        if let Some((class, scope)) = self
            .licence_audiences
            .iter()
            .flatten()
            .find(|(c, s)| c.is_empty() || !crate::federation::types::cohort_scope::is_valid(s))
        {
            return Err(invalid(
                group,
                rule::LICENCE_AUDIENCE_INVALID,
                format!(
                    "licence_audiences: class {class:?} → scope {scope:?}; a class is named and \
                     its scope is a cohort_scope"
                ),
            ));
        }
        Ok(())
    }
}

/// The cohort a community-plane record declares — the ONE reading.
///
/// `policy_blob` absent, not an object, or without [`POLICY_COHORT_FIELD`]
/// ⇒ [`Cohort::Community`] (every pre-v54 record). `"community"` /
/// `"affiliations"` ⇒ that cohort.
///
/// # Errors
/// [`Error::AffiliationConfigInvalid`] (`cohort_unknown`) for any other value:
/// malformed is a refusal, never absence.
pub fn declared_cohort(c: &Community) -> Result<Cohort, Error> {
    let Some(v) = c
        .policy_blob
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|o| o.get(POLICY_COHORT_FIELD))
    else {
        return Ok(Cohort::Community);
    };
    match v.as_str() {
        Some("community") => Ok(Cohort::Community),
        Some("affiliations") => Ok(Cohort::Affiliations),
        _ => Err(invalid(
            &c.community_key_id,
            rule::COHORT_UNKNOWN,
            format!("policy_blob.{POLICY_COHORT_FIELD} = {v}; expected \"community\" or \"affiliations\""),
        )),
    }
}

/// The record's typed config, if it carries one (no validation).
///
/// # Errors
/// `config_malformed` for a present member that does not parse.
pub fn affiliation_config_of(c: &Community) -> Result<Option<AffiliationConfig>, Error> {
    let Some(v) = c
        .policy_blob
        .as_ref()
        .and_then(serde_json::Value::as_object)
        .and_then(|o| o.get(POLICY_AFFILIATION_CONFIG_FIELD))
    else {
        return Ok(None);
    };
    serde_json::from_value(v.clone())
        .map(Some)
        .map_err(|e| invalid(&c.community_key_id, rule::CONFIG_MALFORMED, e.to_string()))
}

/// The resolved config of an affiliation record (`None` for a community).
/// An affiliation that declares no config resolves to the no-op default.
///
/// # Errors
/// As [`check_community_record`].
pub fn resolved_affiliation_config(
    c: &Community,
) -> Result<Option<ResolvedAffiliationConfig>, Error> {
    check_community_record(c)?;
    if declared_cohort(c)? != Cohort::Affiliations {
        return Ok(None);
    }
    Ok(Some(
        affiliation_config_of(c)?.unwrap_or_default().resolve(),
    ))
}

/// v54.0.0 (CIRISPersist#1034) — **the record-shape gate**, at founding (every
/// backend's community door) and on supersession: the declared cohort parses,
/// a config rides only on an affiliation, and an affiliation's config
/// validates against its own roster.
///
/// # Errors
/// [`Error::AffiliationConfigInvalid`].
pub fn check_community_record(c: &Community) -> Result<(), Error> {
    let cohort = declared_cohort(c)?;
    let config = affiliation_config_of(c)?;
    match (cohort, config) {
        (Cohort::Affiliations, config) => {
            let roster: BTreeSet<&str> = c.members.iter().map(|m| m.key_id.as_str()).collect();
            config
                .unwrap_or_default()
                .validate(&c.community_key_id, &roster)
        }
        (_, Some(_)) => Err(invalid(
            &c.community_key_id,
            rule::CONFIG_ON_COMMUNITY,
            format!(
                "policy_blob.{POLICY_AFFILIATION_CONFIG_FIELD} on a record that does not declare \
                 \"{POLICY_COHORT_FIELD}\": \"affiliations\" — a body with no use for institutional \
                 governance is simply a community (CC 4.4.3.2.8)"
            ),
        )),
        (_, None) => Ok(()),
    }
}

/// v60.0.0 (CIRISPersist#1048, CC 4.4.3.2.8 C) — the longest term, in
/// seconds, an edge in `c`'s hierarchy may carry: the charter's `role_term ×
/// 86400` when `c` is an affiliation that declares one, else `None` (only the
/// constitutional [`ROLE_TERM_CEILING_SECONDS`] binds). Never above the
/// ceiling: a record past it is refused at its door
/// ([`rule::ROLE_TERM_OUT_OF_RANGE`]), and the `min` keeps a record admitted
/// before that door from widening it.
///
/// # Errors
/// As [`check_community_record`]: a record whose cohort or config does not
/// parse is a refusal, never "no bound".
pub fn role_term_seconds(c: &Community) -> Result<Option<i64>, Error> {
    if declared_cohort(c)? != Cohort::Affiliations {
        return Ok(None);
    }
    Ok(affiliation_config_of(c)?
        .and_then(|cfg| cfg.role_term)
        .map(|t| (i64::from(t) * 86_400).min(ROLE_TERM_CEILING_SECONDS)))
}

/// Refuse when `c` declares a cohort other than `addressed`.
///
/// # Errors
/// [`Error::AffiliationCohortMismatch`]; [`declared_cohort`]'s refusal.
pub fn check_record_is(c: &Community, addressed: Cohort) -> Result<(), Error> {
    let declared = declared_cohort(c)?;
    if declared == addressed {
        return Ok(());
    }
    Err(Error::AffiliationCohortMismatch {
        group_key_id: c.community_key_id.clone(),
        declared: declared.as_str(),
        addressed: addressed.as_str(),
    })
}

/// v54.0.0 (CIRISPersist#1034) — **a door that addresses a held
/// community-plane record under `cohort` must find it declared so.** A no-op
/// for `family` / `self`, and for a record this node does not hold (each door
/// answers absence its own way).
///
/// # Errors
/// [`Error::AffiliationCohortMismatch`].
pub async fn check_group_cohort<F>(dir: &F, cohort: Cohort, group_key_id: &str) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if !matches!(cohort, Cohort::Community | Cohort::Affiliations) {
        return Ok(());
    }
    // v62.0.0 (wave GC5; CC 2.7.3) — the held record is another row: its
    // cohort is an input (declared), and a mismatch holds the row,
    // concluding nothing, never refused.
    super::edition2::fold::reads(super::edition2::fold::Dep::key(group_key_id));
    match dir.lookup_community(group_key_id).await? {
        Some(held) => check_record_is(&held, cohort).map_err(hold_cohort_mismatch),
        None => Ok(()),
    }
}

/// v62.0.0 (wave GC5; CC 2.7.3) — a HELD record's cohort that is not the one
/// the row addresses is a fold condition: [`Error::AffiliationCohortMismatch`]
/// is marked held ([`affiliation_cohort_mismatch`]); any other refusal (a
/// held record whose cohort does not parse) passes through unmarked.
///
/// [`affiliation_cohort_mismatch`]: super::edition2::fold::reason::AFFILIATION_COHORT_MISMATCH
pub(crate) fn hold_cohort_mismatch(e: Error) -> Error {
    if matches!(e, Error::AffiliationCohortMismatch { .. }) {
        super::edition2::fold::hold(
            super::edition2::fold::reason::AFFILIATION_COHORT_MISMATCH,
            e,
        )
    } else {
        e
    }
}
