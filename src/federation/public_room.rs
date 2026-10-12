//! v55.0.0 (CIRISPersist#1053, CC 3.2 `public`, CIRISConstitution#142) — **the
//! public community: a Commons-tier room with a roster.**
//!
//! "Subreddits or bitsavers" (CC 3.2). Three things, and nothing structural:
//!
//! 1. **The tier.** A community record whose `policy_blob.cohort_subkind` is
//!    `public` is Commons tier: its content at `cohort_scope: community` is
//!    plaintext with no DEK (the CC 4.4.3.2.1 `infrastructure` carve-out
//!    generalised — a room anyone may join has no confidentiality claim
//!    against the public), and its holding claims are at `federation` (CC
//!    3.1.3.3). [`is_public_community`] is the one predicate the write door
//!    (`resolve_write_tier`) and the community DEK cascade ask. The label
//!    alone decides: a public room is founded by anyone (CC 3.1.3.2), so
//!    there is no authority to check, and the label cannot be used to drop a
//!    private room's DEK because a record never crosses the `public`
//!    boundary ([`check_public_room_conformance`]).
//! 2. **Open admission.** A record MAY declare `admission: open`; it is
//!    admissible only on a `public` room (CC 3.2, verbatim: "an encrypted
//!    roster that anyone may join is a contradiction, and is refused"). The
//!    founder's standing `membership:proposal:v1` then names no invitee —
//!    `subject_key_ids` is resolved at acceptance — and the requester's own
//!    `membership:acceptance:v1` naming it is their consent; the widening
//!    that seats them is admitted under the room's `consensus_protocol` as
//!    now (`membership_acceptance`).
//! 3. **Discovery.** `community:listing:v1` is the room's own `scores` row at
//!    `federation`, by its founder or a current `moderate`-holder, carrying
//!    the name, description, `cohort_subkind`, admission policy, named
//!    moderator and `community_key_id` ([`check_community_listing_admission`]).
//!    "One live row per community" is a READ rule ([`live_listing`]): two
//!    nodes must not disagree about which rows exist, so the door admits an
//!    authorized row and the fold picks the room's one live listing.

use super::types::{attestation_type, cohort_scope as cs};
use super::{Attestation, Community, Error, FederationDirectory};

/// The `cohort_subkind` CC 3.2 codifies for a public room.
pub const COHORT_SUBKIND_PUBLIC: &str = "public";

/// The community-record member that declares the admission policy (CC 3.2).
pub const ADMISSION_MEMBER: &str = "admission";

/// The one admission value CC 3.2 names: anyone may join on their own
/// acceptance of the founder's standing proposal.
pub const ADMISSION_OPEN: &str = "open";

/// The listing leaf (CC 3.1.1, CIRISConstitution#142).
pub const LISTING_DIMENSION: &str = "community:listing:v1";

/// The listing family stem (closed to [`LISTING_DIMENSION`] by the registry).
pub const LISTING_FAMILY_STEM: &str = "community:listing:";

/// [`Error::CommunityConsensusProtocolViolation`] rule: `admission: open` on a
/// room that is not `public` (CC 3.2).
pub const PUBLIC_RULE_OPEN_ADMISSION_NOT_PUBLIC: &str = "open_admission_not_public";

/// [`Error::CommunityConsensusProtocolViolation`] rule: an `admission` member
/// that is not the string `open` (CC 3.2 names one value; absent is
/// invite-only).
pub const PUBLIC_RULE_ADMISSION_MALFORMED: &str = "admission_malformed";

/// [`Error::CommunityConsensusProtocolViolation`] rule: a version of a room
/// that changes whether it is `public`. A room's tier is a property of every
/// byte written to it — plaintext rows already readable by anyone cannot be
/// re-sealed, and a private room's members never consented to publication —
/// so the subkind is fixed at founding across the `public` boundary.
pub const PUBLIC_RULE_SUBKIND_CROSSES_PUBLIC: &str = "public_subkind_changed";

/// Refusal token: a `community:listing:v1` row that is not placed at
/// `federation`.
pub const LISTING_NOT_FEDERATION: &str = "community_listing_not_federation";

/// Refusal token: a listing that names no `community_key_id`, or misstates
/// the room's `cohort_subkind` / admission policy, or names no moderator.
pub const LISTING_MALFORMED: &str = "community_listing_malformed";

/// Refusal token: a listing for a room that is not `public`.
pub const LISTING_ROOM_NOT_PUBLIC: &str = "community_listing_room_not_public";

/// Refusal token: a listing signed by a key that is neither a founder nor a
/// current `moderate`-holder of the room it names.
pub const LISTING_SIGNER_NOT_AUTHORIZED: &str = "community_listing_signer_not_authorized";

/// Is `community` a `public` room (CC 3.2)? The one predicate the tier
/// decisions ask.
#[must_use]
pub fn is_public_community(community: &Community) -> bool {
    super::community_subkind(community) == Some(COHORT_SUBKIND_PUBLIC)
}

/// Does `community` declare `admission: open`?
#[must_use]
pub fn is_open_admission(community: &Community) -> bool {
    community
        .policy_blob
        .as_ref()
        .and_then(|b| b.get(ADMISSION_MEMBER))
        .and_then(serde_json::Value::as_str)
        == Some(ADMISSION_OPEN)
}

fn violation(community: &Community, rule: &'static str, detail: String) -> Error {
    Error::CommunityConsensusProtocolViolation {
        community_key_id: community.community_key_id.clone(),
        rule,
        detail,
    }
}

/// **CC 3.2 `public` conformance of a community record**, at every record
/// door (it runs inside `admission::check_infrastructure_community_conformance`):
///
/// - an `admission` member, when present, is the string `open`
///   ([`PUBLIC_RULE_ADMISSION_MALFORMED`]);
/// - `admission: open` only on a `public` room
///   ([`PUBLIC_RULE_OPEN_ADMISSION_NOT_PUBLIC`]);
/// - a version that supersedes a STORED record keeps the stored record's side
///   of the `public` boundary ([`PUBLIC_RULE_SUBKIND_CROSSES_PUBLIC`]).
///
/// # Errors
///
/// [`Error::CommunityConsensusProtocolViolation`] naming the rule; directory
/// errors.
pub async fn check_public_room_conformance(
    directory: &dyn FederationDirectory,
    community: &Community,
) -> Result<(), Error> {
    if let Some(admission) = community
        .policy_blob
        .as_ref()
        .and_then(|b| b.get(ADMISSION_MEMBER))
    {
        if admission.as_str() != Some(ADMISSION_OPEN) {
            return Err(violation(
                community,
                PUBLIC_RULE_ADMISSION_MALFORMED,
                format!(
                    "`{ADMISSION_MEMBER}` is {admission}; CC 3.2 names one value, \
                     `{ADMISSION_OPEN}` — a record without it is invite-only"
                ),
            ));
        }
        if !is_public_community(community) {
            return Err(violation(
                community,
                PUBLIC_RULE_OPEN_ADMISSION_NOT_PUBLIC,
                format!(
                    "`admission: open` is admissible only on a `public` community; this one is \
                     {:?} — an encrypted roster that anyone may join is a contradiction (CC 3.2)",
                    super::community_subkind(community)
                ),
            ));
        }
    }
    if let Some(stored) = directory
        .lookup_community(&community.community_key_id)
        .await?
    {
        if is_public_community(&stored) != is_public_community(community) {
            return Err(violation(
                community,
                PUBLIC_RULE_SUBKIND_CROSSES_PUBLIC,
                format!(
                    "the stored record is {:?} and this version is {:?}: a room's tier is fixed \
                     at founding across the `public` boundary — content already written is \
                     plaintext to everyone, or sealed to a roster that never consented to \
                     publication",
                    super::community_subkind(&stored),
                    super::community_subkind(community)
                ),
            ));
        }
    }
    Ok(())
}

/// Is `row` a listing row (any of the five types carrying the leaf)?
#[must_use]
pub fn is_listing_row(row: &Attestation) -> bool {
    super::admission::envelope_dimension(&row.attestation_envelope)
        .is_some_and(|d| d.starts_with(LISTING_FAMILY_STEM))
}

fn listing_refusal(token: &str, detail: impl std::fmt::Display) -> Error {
    Error::InvalidArgument(format!(
        "{token}: {detail} ({LISTING_DIMENSION}, CC 3.2 / CIRISConstitution#142)"
    ))
}

fn env_str<'a>(row: &'a Attestation, key: &str) -> Option<&'a str> {
    row.attestation_envelope.get(key).and_then(|v| v.as_str())
}

/// The room a listing row names (`community_key_id`), if any.
#[must_use]
pub fn listing_community(row: &Attestation) -> Option<&str> {
    env_str(row, "community_key_id").filter(|s| !s.is_empty())
}

/// **The `community:listing:v1` door** (CC 3.2, the registry's reserved rule:
/// "founder- or moderate-holder-signed for the community it names; one live
/// row per community; federation scope"). A no-op off the leaf. Refuses:
///
/// - a row not placed at `federation` ([`LISTING_NOT_FEDERATION`]);
/// - a row naming no `community_key_id` or no `moderator`
///   ([`LISTING_MALFORMED`]).
///
/// Where this node HOLDS the room's record it also refuses a room that is not
/// `public` ([`LISTING_ROOM_NOT_PUBLIC`]), a `cohort_subkind` or `admission`
/// member that is not the record's ([`LISTING_MALFORMED`]), and a signer that
/// is neither a founder on the room's effective roster nor a current named
/// `moderate`-holder ([`LISTING_SIGNER_NOT_AUTHORIZED`]). Where it does not
/// hold the record YET, the signer's authority cannot be asked, so the row is
/// refused RETRYABLY — [`Error::WriteScopeRefused`] with
/// `ScopeRefusalReason::MembershipUnresolved` (`scope_membership_unresolved`)
/// — and admitted when re-offered after the record lands (operator ruling
/// 2026-10-12: a gate asks about the signer).
///
/// # Errors
///
/// The refusal tokens above, as [`Error::InvalidArgument`]; the retryable
/// ordering gap; directory errors.
pub async fn check_community_listing_admission(
    directory: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<(), Error> {
    if !is_listing_row(row) {
        return Ok(());
    }
    if row.cohort_scope != cs::FEDERATION {
        return Err(listing_refusal(
            LISTING_NOT_FEDERATION,
            format!(
                "a listing is a federation-scoped row; this one is at {:?}",
                row.cohort_scope
            ),
        ));
    }
    let Some(community_key_id) = listing_community(row) else {
        return Err(listing_refusal(
            LISTING_MALFORMED,
            "a listing names the `community_key_id` of the room it lists",
        ));
    };
    if env_str(row, "moderator").is_none_or(str::is_empty) {
        return Err(listing_refusal(
            LISTING_MALFORMED,
            "a listing names the room's moderator (`moderator`): a public room has a named \
             `moderate`-holder from creation (CC 4.5.4)",
        ));
    }
    // A gate asks about the SIGNER's authority, and the room record is where
    // that authority lives: without it the signer cannot be checked, so the
    // row waits for the record — refused RETRYABLY as the ordering gap it is
    // (`scope_membership_unresolved`, the "roster not held here yet" shape,
    // CIRISPersist#797), and admitted when re-offered after the record lands.
    let Some(room) = directory.lookup_community(community_key_id).await? else {
        tracing::warn!(
            community_key_id = %community_key_id,
            attestation_id = %row.attestation_id,
            "ciris-persist: community:listing:v1 refused — room record not held yet; retryable"
        );
        return Err(Error::WriteScopeRefused(
            crate::scope::ScopeRefusalReason::MembershipUnresolved,
        ));
    };
    if !is_public_community(&room) {
        return Err(listing_refusal(
            LISTING_ROOM_NOT_PUBLIC,
            format!(
                "{community_key_id:?} is {:?}, not `public` — a private room's id arrives out \
                 of band and is never listed",
                super::community_subkind(&room)
            ),
        ));
    }
    let subkind_agrees = env_str(row, "cohort_subkind") == Some(COHORT_SUBKIND_PUBLIC);
    let room_admission = room
        .policy_blob
        .as_ref()
        .and_then(|b| b.get(ADMISSION_MEMBER))
        .and_then(serde_json::Value::as_str);
    let admission_agrees = env_str(row, ADMISSION_MEMBER) == room_admission;
    if !subkind_agrees || !admission_agrees {
        return Err(listing_refusal(
            LISTING_MALFORMED,
            format!(
                "the listing states cohort_subkind {:?} and admission {:?}; the room's record \
                 says {COHORT_SUBKIND_PUBLIC:?} and {room_admission:?}",
                env_str(row, "cohort_subkind"),
                env_str(row, ADMISSION_MEMBER)
            ),
        ));
    }
    let signer =
        super::admission::admission_identity_for_writer(directory, &row.attesting_key_id).await?;
    let founder = super::effective_roster(directory, &room)
        .await?
        .iter()
        .any(|m| {
            m.role.as_deref() == Some(super::admission::MEMBER_ROLE_FOUNDER)
                && (m.key_id == signer || m.key_id == row.attesting_key_id)
        });
    if founder {
        return Ok(());
    }
    for k in [row.attesting_key_id.as_str(), signer.as_str()] {
        if super::admission::is_named_moderator(
            directory,
            k,
            community_key_id,
            super::admission::DELEGATION_SCOPE_MODERATE,
        )
        .await?
        {
            return Ok(());
        }
    }
    Err(listing_refusal(
        LISTING_SIGNER_NOT_AUTHORIZED,
        format!(
            "{:?} is neither a founder of {community_key_id:?} nor a current `moderate`-holder",
            row.attesting_key_id
        ),
    ))
}

/// **The room's one live listing** (CC 3.2: "one live row per community"):
/// among the federation-scoped `community:listing:v1` rows held here naming
/// `community_key_id`, the latest by signed instant (ties by row hash) that is
/// not retired — a rename or policy change `supersedes` the row, closing the
/// room `withdraws` it. A read fold, never a stored verdict. `None` when the
/// room has no live listing here.
///
/// # Errors
///
/// Directory errors.
pub async fn live_listing<D>(
    directory: &D,
    community_key_id: &str,
) -> Result<Option<Attestation>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let rows: Vec<Attestation> = directory
        .list_targeted_by_dimension_prefix(&[cs::FEDERATION], community_key_id, LISTING_FAMILY_STEM)
        .await?
        .into_iter()
        .filter(|r| {
            r.attestation_type == attestation_type::SCORES
                || r.attestation_type == attestation_type::SUPERSEDES
        })
        .filter(|r| listing_community(r) == Some(community_key_id))
        .collect();
    let ids: Vec<String> = rows.iter().map(|r| r.attestation_id.clone()).collect();
    let composers = directory
        .list_composers_referencing_any(&ids, None, None)
        .await?;
    let refs: Vec<&Attestation> = rows.iter().chain(composers.iter()).collect();
    let retired = super::precedence::retired_ids(&refs);
    Ok(rows
        .into_iter()
        .filter(|r| !retired.contains(&r.attestation_id))
        .max_by(|a, b| {
            (a.asserted_at, &a.persist_row_hash).cmp(&(b.asserted_at, &b.persist_row_hash))
        }))
}
