//! v52.0.0 (CIRISPersist#955; CIRISConstitution#133; FSD
//! `MEMBERSHIP_ACCEPTANCE.md`) — **nobody joins a family or community without
//! their own signed acceptance.**
//!
//! Three claim dimensions on the attestation plane (`scores` rows, the family
//! in the envelope's `dimension`):
//!
//! - `membership:proposal:v1` — an inviter's offer to K, placed at the group,
//!   naming K in `subject_key_ids` (exactly one), `expires_at` required and at
//!   most 30 days out;
//! - `membership:acceptance:v1` / `membership:decline:v1` — K's reply, signed
//!   by K (or a device acting for K), attested to K, placed at the group, and
//!   binding the proposal's id, content hash and (acceptance) role.
//!
//! Every roster GROWTH — a widening that adds a key not active before its
//! instant — needs a live acceptance ([`check_growth_accepted`]). A founding
//! record admits only the members who signed it ([`check_founding_signers`]),
//! and a supersede never adds ([`check_supersede_adds_no_member`]).
//!
//! v55.0.0 (CIRISPersist#1053, CC 3.2 open admission, CIRISConstitution#142)
//! — a `public` room that declares `admission: open` admits on a **standing**
//! proposal: the founder's `membership:proposal:v1` names NO invitee
//! (`subject_key_ids` empty, "resolved at acceptance"), and any requester's
//! own `membership:acceptance:v1` naming it is that requester's consent. The
//! two-consents ruling is whole: the founder's act is a standing offer, the
//! joiner still signs, and the widening that seats them is admitted under the
//! room's `consensus_protocol` as now. A standing proposal is admitted only
//! from a founder of an open public room, and seats nobody once the room is
//! no longer open ([`RULE_OPEN_PROPOSAL_NOT_OPEN`]).

use super::attestation_query::{AttestationQuery, FOLD_PAGE};
use super::edition2::fold::{self, reason, Dep};
use super::types::{attestation_tier, attestation_type, cohort_scope};
use super::{Attestation, Error, FederationDirectory};

/// v62.0.0 (wave GC6; CC 2.7.3) — **a fold condition is unmet**: hold the
/// running fold attempt with `reason` ([`fold::hold`]) unless `e` is a
/// storage failure (a backend error, an unsupported directory, a write race),
/// which is never a reason to keep a row concluding nothing. Outside an
/// attempt (the earlier-form JSON door) it is the plain refusal.
pub(crate) fn hold_unless_storage(reason: &'static str, e: Error) -> Error {
    match e {
        Error::Backend(_) | Error::Unsupported { .. } | Error::Conflict(_) => e,
        other => fold::hold(reason, other),
    }
}

/// v62.0.0 (wave GC6) — the dependency of a row named by its attestation id,
/// when the id is an edition-2 row id (64 hex): `row:<hex>`.
pub(crate) fn row_dep(attestation_id: &str) -> Option<Dep> {
    let bytes = hex::decode(attestation_id).ok()?;
    let d: [u8; 32] = bytes.try_into().ok()?;
    Some(Dep::Row(super::edition2::names::RowId(d)))
}

/// The inviter's offer.
pub const PROPOSAL_DIMENSION: &str = "membership:proposal:v1";
/// K's acceptance of one proposal.
pub const ACCEPTANCE_DIMENSION: &str = "membership:acceptance:v1";
/// K's decline of one proposal.
pub const DECLINE_DIMENSION: &str = "membership:decline:v1";
/// The family stem.
pub const MEMBERSHIP_FAMILY_STEM: &str = "membership:";
/// A proposal lives at most 30 days after its `asserted_at`.
pub const MEMBERSHIP_PROPOSAL_MAX_TTL_SECS: i64 = 2_592_000;

/// RETRYABLE: no acceptance by the member is held here yet.
pub const RULE_ACCEPTANCE_UNRESOLVED: &str = "membership_acceptance_unresolved";
/// RETRYABLE: the reply's proposal is not held here yet.
pub const RULE_PROPOSAL_UNRESOLVED: &str = "membership_proposal_unresolved";
/// The member declined the proposal.
pub const RULE_DECLINED: &str = "membership_declined";
/// The proposal expired (or was withdrawn by its proposer).
pub const RULE_PROPOSAL_EXPIRED: &str = "membership_proposal_expired";
/// Group, hash, role or subject disagree with the proposal.
pub const RULE_ACCEPTANCE_MISMATCH: &str = "membership_acceptance_mismatch";
/// The member both accepted and declined the same proposal.
pub const RULE_REPLY_CONFLICT: &str = "membership_reply_conflict";
/// A founding-roster member who did not sign the founding record.
pub const RULE_FOUNDING_MEMBER_UNSIGNED: &str = "membership_founding_member_unsigned";
/// A supersede whose roster adds a member.
pub const RULE_SUPERSEDE_CANNOT_ADD: &str = "membership_supersede_cannot_add";
/// v55.0.0 (CIRISPersist#1053, CC 3.2) — a standing proposal (no invitee) for
/// a group that is not an open `public` room, or not from its founder; or an
/// acceptance of one whose room is no longer open at the growth.
pub const RULE_OPEN_PROPOSAL_NOT_OPEN: &str = "membership_open_proposal_not_open";
/// v62.0.0 (wave GC6; CC 2.7 rc21 X14) — a public room joiner's acceptance
/// from a key with no live federation-scope owner binding: it does not count
/// (held, never refused, on the edition-2 door).
pub const RULE_JOINER_OWNER_UNBOUND: &str = "joiner_owner_unbound";
/// v62.0.0 (K2-fix18; CC 3.4.13 Q5 "contactable and discoverable by
/// unconnected adults", CC 5.4.6) — the growth would list a person a held age
/// row places in a minor band on a `public` room's roster: HELD (never
/// refused) while the row stands ([`check_public_roster_not_minor`]). The
/// spelling of `fold::reason::gc6::MINOR_PUBLIC_ROSTER_ENTRY`.
pub const RULE_MINOR_PUBLIC_ROSTER_ENTRY: &str = "minor_public_roster_entry";

/// The retryable rules: rows arrive out of order and persist holds no
/// deferral queue, so the caller re-submits. v61 (CIRISPersist#1101): an
/// unannounced serve seat too, once the owner announces.
#[must_use]
pub fn is_retryable_rule(rule: &str) -> bool {
    rule == RULE_ACCEPTANCE_UNRESOLVED
        || rule == RULE_PROPOSAL_UNRESOLVED
        || rule == super::admission::SERVE_SEAT_OWNER_UNANNOUNCED
        || rule == RULE_JOINER_OWNER_UNBOUND
}

fn refuse(group: &str, member: &str, rule: &'static str) -> Error {
    Error::MembershipAcceptanceRefused {
        group_key_id: group.to_owned(),
        member_key_id: member.to_owned(),
        rule,
    }
}

/// Which membership row, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MembershipRow {
    /// `membership:proposal:v1`.
    Proposal,
    /// `membership:acceptance:v1`.
    Acceptance,
    /// `membership:decline:v1`.
    Decline,
}

/// The membership dimension of a `scores` row, if it carries one.
#[must_use]
pub fn membership_row(row: &Attestation) -> Option<MembershipRow> {
    if row.attestation_type != attestation_type::SCORES {
        return None;
    }
    match super::admission::envelope_dimension(&row.attestation_envelope)? {
        PROPOSAL_DIMENSION => Some(MembershipRow::Proposal),
        ACCEPTANCE_DIMENSION => Some(MembershipRow::Acceptance),
        DECLINE_DIMENSION => Some(MembershipRow::Decline),
        _ => None,
    }
}

/// AV-84's one exception: a proposal names its invitee — exactly one — in
/// `subject_key_ids`. Every other targeted row names only its producer.
#[must_use]
pub fn is_invitee_subject_list(row: &Attestation) -> bool {
    membership_row(row) == Some(MembershipRow::Proposal) && row.subject_key_ids.len() == 1
}

/// v55.0.0 (CIRISPersist#1053, CC 3.2) — a **standing** proposal: one that
/// names no invitee, addressed to any requester of an open public room.
#[must_use]
pub fn is_standing_proposal(row: &Attestation) -> bool {
    membership_row(row) == Some(MembershipRow::Proposal) && row.subject_key_ids.is_empty()
}

/// v53.0.0 (CIRISEdge#761) — **the roster plane a membership row is placed
/// on**: the family's, or the room's. `community` and `affiliations` are ONE
/// plane ([`TargetPlane::Room`](cohort_scope::TargetPlane::Room)): an
/// affiliation is a community record and runs "all the community machinery
/// (… `consensus_protocol` admission)" (CC 4.4.3.2.8), so its membership
/// ceremony is the community's. `None` for a scope no roster answers (self,
/// the commons). Every membership comparison of two scopes asks this.
pub(crate) fn membership_plane(scope: &str) -> Option<cohort_scope::TargetPlane> {
    match cohort_scope::Scope::parse(scope).map(cohort_scope::Scope::placement) {
        Some(cohort_scope::Placement::Targeted(plane)) => Some(plane),
        _ => None,
    }
}

/// v53.0.0 (CIRISEdge#761) — **the group a well-formed membership row is
/// about**, for the delivery rule ([`may_receive`](super::replication_audience::may_receive)):
/// `(stage, group)`, or `None` for a non-membership or malformed row.
#[must_use]
pub fn membership_group_of(row: &Attestation) -> Option<(MembershipRow, String)> {
    let kind = membership_row(row)?;
    Some((kind, group_of(row).ok()?))
}

/// v53.0.0 (CIRISEdge#761) — **the held federation-tier proposal an
/// acceptance or decline answers** (by `references_attestation_id`), if this
/// node holds it and the answer matches it. `None` for a proposal row, a
/// non-membership row, or an answer whose proposal is not held here.
pub async fn answered_proposal_of<F>(
    dir: &F,
    row: &Attestation,
) -> Result<Option<Attestation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    match membership_row(row) {
        Some(MembershipRow::Acceptance | MembershipRow::Decline) => {}
        _ => return Ok(None),
    }
    let Some(pid) = env_str(row, "references_attestation_id") else {
        return Ok(None);
    };
    Ok(dir
        .get_attestation(pid)
        .await?
        .filter(|p| p.tier == attestation_tier::FEDERATION)
        .and_then(as_proposal)
        .filter(|p| reply_matches(row, p))
        .map(|p| p.row))
}

/// Do two placements name the same membership plane?
pub(crate) fn same_membership_plane(a: &str, b: &str) -> bool {
    membership_plane(a).is_some() && membership_plane(a) == membership_plane(b)
}

fn group_kind_for_scope(scope: &str) -> Option<&'static str> {
    match membership_plane(scope)? {
        cohort_scope::TargetPlane::Family => Some("family"),
        cohort_scope::TargetPlane::Room => Some("community"),
    }
}

fn env_str<'a>(row: &'a Attestation, key: &str) -> Option<&'a str> {
    row.attestation_envelope.get(key).and_then(|v| v.as_str())
}

/// The offered role: absent / `null` is `None`.
fn env_role(row: &Attestation) -> Result<Option<String>, Error> {
    match row.attestation_envelope.get("role") {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
        Some(other) => Err(Error::InvalidArgument(format!(
            "membership row `role` must be a string or null, got {other}"
        ))),
    }
}

/// The group a membership row names: its cohort target, which the placement
/// must agree with (`family` ↔ `family_key_id`, `community` ↔ the room).
fn group_of(row: &Attestation) -> Result<String, Error> {
    let kind = group_kind_for_scope(&row.cohort_scope).ok_or_else(|| {
        Error::InvalidArgument(format!(
            "membership row at cohort_scope {:?}: it is placed at the group (`family` or \
             `community`)",
            row.cohort_scope
        ))
    })?;
    if env_str(row, "group_kind") != Some(kind) {
        return Err(Error::InvalidArgument(format!(
            "membership row: envelope `group_kind` must be {kind:?} at cohort_scope {:?}",
            row.cohort_scope
        )));
    }
    let target =
        super::admission::envelope_cohort_target(&row.attestation_envelope)?.ok_or_else(|| {
            Error::InvalidArgument("membership row names no group (cohort target)".into())
        })?;
    Ok(target.to_owned())
}

/// **The row rules** (pure): tier, placement, shape, TTL.
pub fn check_membership_row_shape(row: &Attestation) -> Result<(), Error> {
    let Some(kind) = membership_row(row) else {
        return Ok(());
    };
    if row.tier != attestation_tier::FEDERATION {
        return Err(Error::InvalidArgument(
            "membership rows are federation-tier (a local row defers its signature)".into(),
        ));
    }
    // v62.0.0 (KR-fix2) — a reply to a counted grant from the root is placed
    // at the federation scope and names no group: the root is the accord of
    // the bundle the grant names (`check_root_grant_reply`).
    if is_root_grant_reply(row) {
        for key in ["references_attestation_id", "proposal_hash"] {
            if env_str(row, key).is_none_or(str::is_empty) {
                return Err(Error::InvalidArgument(format!(
                    "root grant reply: envelope `{key}` is required"
                )));
            }
        }
        return Ok(());
    }
    group_of(row)?;
    env_role(row)?;
    match kind {
        MembershipRow::Proposal => {
            // v55.0.0 (CIRISPersist#1053) — one invitee, or none for a standing
            // proposal of an open public room (judged where the room is held).
            if row.subject_key_ids.len() > 1 {
                return Err(Error::InvalidArgument(format!(
                    "{PROPOSAL_DIMENSION}: names at most one invitee in subject_key_ids (none \
                     for a standing proposal of an open public room), got {}",
                    row.subject_key_ids.len()
                )));
            }
            let Some(expires_at) = row.expires_at else {
                return Err(Error::InvalidArgument(format!(
                    "{PROPOSAL_DIMENSION}: expires_at is required"
                )));
            };
            if expires_at <= row.asserted_at
                || expires_at
                    > row.asserted_at + chrono::Duration::seconds(MEMBERSHIP_PROPOSAL_MAX_TTL_SECS)
            {
                return Err(Error::InvalidArgument(format!(
                    "{PROPOSAL_DIMENSION}: expires_at must be after asserted_at and at most \
                     {MEMBERSHIP_PROPOSAL_MAX_TTL_SECS}s later"
                )));
            }
        }
        MembershipRow::Acceptance | MembershipRow::Decline => {
            for key in ["references_attestation_id", "proposal_hash"] {
                if env_str(row, key).is_none_or(str::is_empty) {
                    return Err(Error::InvalidArgument(format!(
                        "membership reply: envelope `{key}` is required"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// A held proposal as the gate reads it.
pub(crate) struct Proposal {
    pub(crate) row: Attestation,
    pub(crate) group: String,
    /// The invitee; `None` for a standing proposal (v55.0.0, CC 3.2), whose
    /// invitee is whoever accepts it.
    pub(crate) invitee: Option<String>,
    pub(crate) role: Option<String>,
    pub(crate) expires_at: chrono::DateTime<chrono::Utc>,
}

pub(crate) fn as_proposal(row: Attestation) -> Option<Proposal> {
    if membership_row(&row) != Some(MembershipRow::Proposal) {
        return None;
    }
    let group = group_of(&row).ok()?;
    if row.subject_key_ids.len() > 1 {
        return None;
    }
    let invitee = row.subject_key_ids.first().cloned();
    let role = env_role(&row).ok()?;
    let expires_at = row.expires_at?;
    Some(Proposal {
        row,
        group,
        invitee,
        role,
        expires_at,
    })
}

/// The reply's own claims about its proposal agree with the proposal.
fn reply_matches(reply: &Attestation, p: &Proposal) -> bool {
    group_of(reply).is_ok_and(|g| g == p.group)
        && same_membership_plane(&reply.cohort_scope, &p.row.cohort_scope)
        && env_str(reply, "proposal_hash") == Some(p.row.original_content_hash.as_str())
        && p.invitee
            .as_ref()
            .is_none_or(|i| reply.attested_key_id == *i)
        && (membership_row(reply) != Some(MembershipRow::Acceptance)
            || env_role(reply).ok().flatten() == p.role)
}

/// v62.0.0 (KR-fix10; CC 3.1.3.2, CC 3.3.6) — **did the party that signed
/// with `earlier` also sign with `later`?** The same key, or two keys of one
/// consenting person ([`consenting_person`](super::admission::consenting_person):
/// a person's devices). A node key is only ever itself: it never answers for
/// its owner, and its owner's other nodes never answer for it.
pub(crate) async fn same_consenting_party<F>(
    dir: &F,
    later: &str,
    earlier: &str,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if later == earlier {
        return Ok(true);
    }
    let Some(a) = super::admission::consenting_person(dir, later).await? else {
        return Ok(false);
    };
    Ok(super::admission::consenting_person(dir, earlier).await? == Some(a))
}

pub(crate) async fn proposal_withdrawn<F>(dir: &F, p: &Proposal) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    // KR-fix10 (CC 3.1.3.2) — the proposer's own key, or the proposer's
    // person; a node of the proposer's owner retracts nothing.
    for w in dir
        .list_attestations_referencing(&p.row.attestation_id)
        .await?
    {
        if w.attestation_type == attestation_type::WITHDRAWS
            && same_consenting_party(dir, &w.attesting_key_id, &p.row.attesting_key_id).await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Every federation-tier reply by `member` held here.
pub(crate) async fn replies_of<F>(dir: &F, member: &str) -> Result<Vec<Attestation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    // v53.1.6 — the member's `membership:*` rows (V178's attested+dimension
    // seek), not every row about the member; the filter is unchanged.
    let mut rows = Vec::new();
    let mut pages = AttestationQuery::to(member, FOLD_PAGE)
        .dimension_prefix(MEMBERSHIP_FAMILY_STEM)
        .pages();
    while let Some(page) = pages.next(dir).await? {
        rows.extend(page);
    }
    Ok(rows
        .into_iter()
        .filter(|r| {
            r.tier == attestation_tier::FEDERATION
                && matches!(
                    membership_row(r),
                    Some(MembershipRow::Acceptance | MembershipRow::Decline)
                )
        })
        .collect())
}

pub(crate) fn replies_to<'a>(
    replies: &'a [Attestation],
    proposal_id: &str,
) -> Vec<&'a Attestation> {
    replies
        .iter()
        .filter(|r| env_str(r, "references_attestation_id") == Some(proposal_id))
        .collect()
}

async fn group_is_held<F>(dir: &F, scope: &str, group: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(match membership_plane(scope) {
        Some(cohort_scope::TargetPlane::Family) => dir.lookup_family(group).await?.is_some(),
        _ => dir.lookup_community(group).await?.is_some(),
    })
}

/// **The write-scope door for attestations** (AV-45 plus the two membership
/// arms). Every backend's `put_attestation` calls this where it called
/// `check_write_cohort_scope_for`.
///
/// - A proposal whose group this node holds is judged by AV-45 (the proposer
///   must be a member) and, under `founder_only`, must come from a founder. A
///   proposal whose group is NOT held here is stored (the subject-apply arm):
///   this node cannot judge the proposer, and the proposer's standing is
///   judged where the roster lives, when the growth arrives. Only its subject
///   can read it here.
/// - A reply is admitted wherever its proposal is held: its signer acts for
///   the proposal's invitee, and group, hash and role agree. It never needs
///   the group's roster (K is not a member yet).
pub async fn check_attestation_write_scope<F>(
    dir: &F,
    row: &Attestation,
    write_path: &'static str,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(kind) = membership_row(row) else {
        return dir
            .check_write_cohort_scope_for(
                &row.attesting_key_id,
                write_path,
                &row.cohort_scope,
                super::admission::envelope_cohort_target(&row.attestation_envelope)?,
            )
            .await;
    };
    check_membership_row_shape(row)?;
    // v62.0.0 (KR-fix2; CC 3.2 as ruled 2026-11-21) — the grantee's consent
    // to a counted grant from the root: no group's roster is read.
    if is_root_grant_reply(row) {
        return check_root_grant_reply(dir, row, kind).await;
    }
    let group = group_of(row)?;
    // v61 S2 (CIRISPersist#1123) — a room stored under founder_only admits
    // no proposal and no acceptance (its one event is the escape).
    if membership_plane(&row.cohort_scope) == Some(cohort_scope::TargetPlane::Room)
        && matches!(kind, MembershipRow::Proposal | MembershipRow::Acceptance)
    {
        super::admission::refuse_membership_event_under_founder_only(
            dir,
            &group,
            match kind {
                MembershipRow::Proposal => "membership proposal",
                _ => "membership acceptance",
            },
        )
        .await?;
    }
    // v52.0.0 (#956) — no invitation to, or reply about, a dissolved family.
    if row.cohort_scope == cohort_scope::FAMILY {
        super::family_dissolution::refuse_if_held_family_dissolved(dir, &group).await?;
    }
    match kind {
        MembershipRow::Proposal => {
            // v62.0.0 (wave GC6; CC 2.7.3) — every rule below reads the
            // group's record and roster and the proposer's person binding:
            // declared on every path (the not-held one too), so the proposal
            // re-folds when the group, a seat or a binding arrives or is
            // withdrawn, and the concluded set does not depend on which came
            // first.
            fold::reads(Dep::key(&group));
            fold::reads(Dep::key(&row.attesting_key_id));
            if !group_is_held(dir, &row.cohort_scope, &group).await? {
                return Ok(());
            }
            dir.check_write_cohort_scope_for(
                &row.attesting_key_id,
                write_path,
                &row.cohort_scope,
                Some(&group),
            )
            .await
            .map_err(|e| hold_unless_storage(reason::MEMBERSHIP_PROPOSER_OUT_OF_SCOPE, e))?;
            if is_standing_proposal(row) {
                return check_standing_proposal(dir, row, &group).await;
            }
            check_proposer_under_founder_only(dir, row, &group).await
        }
        MembershipRow::Acceptance | MembershipRow::Decline => {
            let member = row.attested_key_id.as_str();
            let proposal_id = env_str(row, "references_attestation_id").unwrap_or_default();
            // v62.0.0 (wave GC6; CC 2.7.3) — the reply reads the proposal it
            // names, the member's other replies, and the person bindings of
            // its signer and the invitee: each arrival re-folds it.
            fold::reads(Dep::key(member));
            fold::reads(Dep::key(&row.attesting_key_id));
            if let Some(d) = row_dep(proposal_id) {
                fold::reads(d);
            }
            let referenced = dir
                .get_attestation(proposal_id)
                .await?
                .filter(|p| p.tier == attestation_tier::FEDERATION);
            // v62.0.0 (wave V1b; CC 4.4.3.12 "two consents") — an officer's
            // consent to a held counted appointment is its own acceptance
            // naming the appointment: the officer signs it, about the
            // affiliation the appointment names.
            if let Some(appointment) = referenced
                .as_ref()
                .filter(|a| super::admission::is_counted_officer_appointment_row(a))
            {
                return check_officer_reply(dir, row, kind, &group, appointment).await;
            }
            // A reply naming a proposal not held here WAITS for it (held,
            // re-folded when it lands), never refused.
            let Some(p) = referenced.and_then(as_proposal) else {
                return Err(fold::hold(
                    reason::MEMBERSHIP_PROPOSAL_UNRESOLVED,
                    refuse(&group, member, RULE_PROPOSAL_UNRESOLVED),
                ));
            };
            // v55.0.0 (CIRISPersist#1053) — a standing proposal's invitee is
            // resolved at acceptance: whoever the reply is attested to.
            let invitee_key = p.invitee.as_deref().unwrap_or(member);
            fold::reads(Dep::key(invitee_key));
            // KR-fix10 (CC 3.1.3.2: "The consent this section requires is the
            // joiner's own: a person's, or an agent's under its own key") —
            // the signer's own person, compared with the invitee as a SUBJECT
            // (its person, never its owner). A node key signing for a NAMED
            // invitee is refused by name (`node_gives_no_consent`): it is not
            // its owner's acceptance.
            //
            // OPEN CONFLICT, not decided here (see KR-fix10.md): a public
            // room's STANDING proposal is accepted by "a key with a live
            // federation-scope owner-binding" (CC 4.4.3.17 as corrected, X14,
            // enforced just below), and such a key is an owned node's or
            // agent's. That joiner signs about ITSELF with its own key (the
            // reply is attested to the signing key), which lifts nothing, so
            // this arm is left as it was; whether a node may be that joiner
            // at all is the two texts' question.
            let own_key_joins = p.invitee.is_none() && row.attesting_key_id == invitee_key;
            if !own_key_joins {
                let signer =
                    super::admission::consenting_identity(dir, &row.attesting_key_id).await?;
                let invitee = dir.active_identity_for_occurrence(invitee_key).await?;
                if signer != invitee {
                    return Err(fold::hold(
                        reason::MEMBERSHIP_ACCEPTANCE_MISMATCH,
                        refuse(&group, member, RULE_ACCEPTANCE_MISMATCH),
                    ));
                }
            }
            if !reply_matches(row, &p) {
                return Err(fold::hold(
                    reason::MEMBERSHIP_ACCEPTANCE_MISMATCH,
                    refuse(&group, member, RULE_ACCEPTANCE_MISMATCH),
                ));
            }
            // v62.0.0 (wave GC6; CC 2.7 rc21 X14, CC 4.4.3.17 corrected:
            // "That signature counts only from a key with a live
            // federation-scope owner-binding") — a joiner's acceptance of a
            // public room's STANDING proposal concludes nothing until the
            // joiner's key holds one (`public_room::joiner_owner_bound`, a
            // fold: held, re-folded when the binding lands or is withdrawn).
            // Applied on the edition-2 door (a fold attempt); the earlier-form
            // JSON door is shut in v62 and keeps its v61 answer until F0
            // deletes it.
            if fold::in_attempt()
                && p.invitee.is_none()
                && kind == MembershipRow::Acceptance
                && !super::public_room::joiner_owner_bound(dir, &row.attesting_key_id).await?
            {
                return Err(fold::hold(
                    reason::JOINER_OWNER_UNBOUND,
                    refuse(&group, member, RULE_JOINER_OWNER_UNBOUND),
                ));
            }
            let held = replies_of(dir, member).await?;
            let opposite = match kind {
                MembershipRow::Acceptance => MembershipRow::Decline,
                _ => MembershipRow::Acceptance,
            };
            if opposite_reply_stands(
                dir,
                row,
                &replies_to(&held, &p.row.attestation_id),
                opposite,
            )
            .await?
            {
                return Err(fold::hold(
                    reason::MEMBERSHIP_REPLY_CONFLICT,
                    refuse(&group, member, RULE_REPLY_CONFLICT),
                ));
            }
            Ok(())
        }
    }
}

/// v62.0.0 (KR-fix2) — is `row` **a reply to a counted grant from the root**
/// by its form: a `membership:acceptance` / `membership:decline` placed at
/// `cohort_scope: federation`? Every other membership row is placed at its
/// group (`family` / `community`, [`group_of`]); a federation-scope reply was
/// refused for naming no group before this arm, so the form is the root
/// grant's alone. The root is not named by the reply: it is the accord of the
/// bundle the grant it answers names.
#[must_use]
pub fn is_root_grant_reply(row: &Attestation) -> bool {
    matches!(
        membership_row(row),
        Some(MembershipRow::Acceptance | MembershipRow::Decline)
    ) && row.cohort_scope == cohort_scope::FEDERATION
}

/// The group id a root grant's reply is reported under in a refusal: the
/// trust root (no room, no family record).
const ROOT_GRANT_GROUP: &str = "trust-root";

/// v62.0.0 (KR-fix2; CC 3.2 as ruled 2026-11-21, CC 4.4.3.19) — **a reply to
/// a counted grant from the root** (the grant's second consent, the same
/// acceptance family as an officer's): it names a HELD counted root grant
/// (`references_attestation_id`; not held yet, it waits), is attested to the
/// grant's grantee, binds the grant's content hash, and is signed FOR the
/// grantee: by the grantee's person, or for a MACHINE grantee (a `node` or an
/// `agent`) by its OWNER at the reply's own instant
/// ([`admission::root_grant_consenter`](super::admission::root_grant_consenter)).
/// A machine with no owner bound yet waits (held, re-folded when the binding
/// lands). Never both an acceptance and a decline of one grant.
async fn check_root_grant_reply<F>(
    dir: &F,
    row: &Attestation,
    kind: MembershipRow,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let member = row.attested_key_id.as_str();
    let grant_id = env_str(row, "references_attestation_id").unwrap_or_default();
    fold::reads(Dep::key(member));
    fold::reads(Dep::key(&row.attesting_key_id));
    if let Some(d) = row_dep(grant_id) {
        fold::reads(d);
    }
    let Some(grant) = dir
        .get_attestation(grant_id)
        .await?
        .filter(|g| g.tier == attestation_tier::FEDERATION)
    else {
        // The grant is not held (or still short of its count): the reply
        // WAITS for it.
        return Err(fold::hold(
            reason::MEMBERSHIP_PROPOSAL_UNRESOLVED,
            refuse(ROOT_GRANT_GROUP, member, RULE_PROPOSAL_UNRESOLVED),
        ));
    };
    if !super::admission::is_counted_root_grant_row(&grant) {
        return Err(refuse(ROOT_GRANT_GROUP, member, RULE_ACCEPTANCE_MISMATCH));
    }
    // KR-fix5 — the signing key's OWN identity, never lifted to its owner: a
    // bound worker node's signature is not its owner's consent.
    if !super::admission::signs_for_root_grantee(
        dir,
        &row.attesting_key_id,
        &grant.attested_key_id,
        row.asserted_at,
    )
    .await?
        || member != grant.attested_key_id
        || env_str(row, "proposal_hash") != Some(grant.original_content_hash.as_str())
    {
        return Err(fold::hold(
            reason::MEMBERSHIP_ACCEPTANCE_MISMATCH,
            refuse(ROOT_GRANT_GROUP, member, RULE_ACCEPTANCE_MISMATCH),
        ));
    }
    let held = replies_of(dir, member).await?;
    let opposite = match kind {
        MembershipRow::Acceptance => MembershipRow::Decline,
        _ => MembershipRow::Acceptance,
    };
    if opposite_reply_stands(
        dir,
        row,
        &replies_to(&held, &grant.attestation_id),
        opposite,
    )
    .await?
    {
        return Err(fold::hold(
            reason::MEMBERSHIP_REPLY_CONFLICT,
            refuse(ROOT_GRANT_GROUP, member, RULE_REPLY_CONFLICT),
        ));
    }
    Ok(())
}

/// v62.0.0 (KR-fix2) — **has the grantee of the counted root grant `grant`
/// consented by `t`?** A held federation-tier `membership:acceptance:v1` at
/// the federation scope ([`is_root_grant_reply`]), attested to the grantee,
/// naming the grant, signed for the grantee (its person, or a machine
/// grantee's owner at the acceptance's own instant), asserted by `t`, and no
/// decline of it by `t`. The grant's count is the other consent
/// (`admission::check_root_grant_counted`); it confers only when both hold.
///
/// # Errors
/// Directory reads.
pub async fn root_grant_accepted_at<F>(
    dir: &F,
    grant: &Attestation,
    t: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let grantee = grant.attested_key_id.as_str();
    let held = replies_of(dir, grantee).await?;
    let replies: Vec<&Attestation> = replies_to(&held, &grant.attestation_id)
        .into_iter()
        .filter(|r| r.asserted_at <= t && is_root_grant_reply(r))
        .collect();
    if replies
        .iter()
        .any(|r| membership_row(r) == Some(MembershipRow::Decline))
    {
        return Ok(false);
    }
    for r in replies
        .iter()
        .filter(|r| membership_row(r) == Some(MembershipRow::Acceptance))
    {
        if super::admission::signs_for_root_grantee(
            dir,
            &r.attesting_key_id,
            grantee,
            r.asserted_at,
        )
        .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// v62.0.0 (wave V1b; CC 4.4.3.12) — **a reply to a counted officer
/// appointment**: signed for the officer (the appointment's attested key, by
/// person), attested to it, about the affiliation the appointment names,
/// binding the appointment's content hash; never both an acceptance and a
/// decline of one appointment.
async fn check_officer_reply<F>(
    dir: &F,
    row: &Attestation,
    kind: MembershipRow,
    group: &str,
    appointment: &Attestation,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let member = row.attested_key_id.as_str();
    // v62.0.0 (wave GC6) — the person bindings of the signer and the officer.
    fold::reads(Dep::key(&appointment.attested_key_id));
    // KR-fix10 — the officer's own consent: a node key is refused by name.
    let signer = super::admission::consenting_identity(dir, &row.attesting_key_id).await?;
    let officer = dir
        .active_identity_for_occurrence(&appointment.attested_key_id)
        .await?;
    let names = super::admission::envelope_cohort_target(&appointment.attestation_envelope)?;
    if signer != officer
        || member != appointment.attested_key_id
        || names != Some(group)
        || env_str(row, "proposal_hash") != Some(appointment.original_content_hash.as_str())
    {
        return Err(fold::hold(
            reason::MEMBERSHIP_ACCEPTANCE_MISMATCH,
            refuse(group, member, RULE_ACCEPTANCE_MISMATCH),
        ));
    }
    let held = replies_of(dir, member).await?;
    let opposite = match kind {
        MembershipRow::Acceptance => MembershipRow::Decline,
        _ => MembershipRow::Acceptance,
    };
    if opposite_reply_stands(
        dir,
        row,
        &replies_to(&held, &appointment.attestation_id),
        opposite,
    )
    .await?
    {
        return Err(fold::hold(
            reason::MEMBERSHIP_REPLY_CONFLICT,
            refuse(group, member, RULE_REPLY_CONFLICT),
        ));
    }
    Ok(())
}

/// v62.0.0 (wave GC6; CC 2.7.2 "one voice orders its own rows by signed
/// instant") — **does the held reply `r` conflict with `row`?** `r` is
/// another reply of the opposite kind to the same proposal.
///
/// - Inside a fold attempt (the edition-2 door, a re-fold), only an opposite
///   reply signed NO LATER than `row` conflicts: the earlier-signed reply
///   stands and the later one is held, whichever arrived first. A later
///   reply that concluded first is re-folded (it read `key:<member>`) and
///   un-concluded when the earlier one lands. Equal instants keep the held
///   (concluded) reply: an exact tie is the one order-dependent case.
/// - Outside an attempt (the earlier-form JSON door) any opposite reply
///   conflicts, as before.
fn conflicts_with(row: &Attestation, r: &Attestation, opposite: MembershipRow) -> bool {
    r.attestation_id != row.attestation_id
        && membership_row(r) == Some(opposite)
        && (!fold::in_attempt() || r.asserted_at <= row.asserted_at)
}

/// v62.0.0 (wave GC6) — **does an opposite reply stand against `row`?** One
/// of `replies` [`conflicts_with`] it and, inside a fold attempt, has not
/// been withdrawn by its own signer (by person). Each opposite reply is a
/// declared read (`row:<its id>`), so its withdrawal (which touches that
/// row) re-folds `row`: a reply held for a conflict concludes when the
/// earlier opposite reply is withdrawn. Outside an attempt a withdrawn reply
/// still conflicts, as before.
async fn opposite_reply_stands<F>(
    dir: &F,
    row: &Attestation,
    replies: &[&Attestation],
    opposite: MembershipRow,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    for r in replies.iter().copied() {
        if !conflicts_with(row, r, opposite) {
            continue;
        }
        if !fold::in_attempt() {
            return Ok(true);
        }
        if let Some(d) = row_dep(&r.attestation_id) {
            fold::reads(d);
        }
        if !reply_withdrawn(dir, r).await? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// v62.0.0 (wave GC6) — has `reply`'s signer (by person) withdrawn it? The
/// same rule [`proposal_withdrawn`] reads for a proposal.
async fn reply_withdrawn<F>(dir: &F, reply: &Attestation) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    for w in dir
        .list_attestations_referencing(&reply.attestation_id)
        .await?
    {
        if w.attestation_type == attestation_type::WITHDRAWS
            && same_consenting_party(dir, &w.attesting_key_id, &reply.attesting_key_id).await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// v62.0.0 (wave V1b; CC 4.4.3.12 "two consents") — **has the officer
/// accepted `appointment` by `t`?** A held federation-tier
/// `membership:acceptance:v1` attested to the appointment's officer, naming
/// the appointment (`references_attestation_id`), signed for the officer
/// (by person), asserted by `t`, and no decline of it by `t`. The
/// appointment's quorum is the other consent ([`admission`]'s counted rule);
/// the officer's seat stands only when both hold.
///
/// [`admission`]: super::admission
///
/// # Errors
///
/// Directory reads.
pub async fn officer_accepted_at<F>(
    dir: &F,
    appointment: &Attestation,
    t: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let officer = appointment.attested_key_id.as_str();
    let held = replies_of(dir, officer).await?;
    let replies: Vec<&Attestation> = replies_to(&held, &appointment.attestation_id)
        .into_iter()
        .filter(|r| r.asserted_at <= t)
        .collect();
    if replies
        .iter()
        .any(|r| membership_row(r) == Some(MembershipRow::Decline))
    {
        return Ok(false);
    }
    let person = dir.active_identity_for_occurrence(officer).await?;
    for r in replies
        .iter()
        .filter(|r| membership_row(r) == Some(MembershipRow::Acceptance))
    {
        // KR-fix10 — a node-signed reply is nobody's acceptance.
        if super::admission::consenting_person(dir, &r.attesting_key_id)
            .await?
            .as_deref()
            == Some(person.as_str())
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// v55.0.0 (CIRISPersist#1053, CC 3.2) — a standing proposal is admitted only
/// for an open `public` room, from one of its founders ("the founder's
/// standing proposal").
async fn check_standing_proposal<F>(dir: &F, row: &Attestation, group: &str) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (wave GC6) — the DOOR part, the row's own bytes: a standing
    // proposal is placed at a room. Refused, nothing kept.
    if membership_plane(&row.cohort_scope) != Some(cohort_scope::TargetPlane::Room) {
        return Err(refuse(
            group,
            &row.attesting_key_id,
            RULE_OPEN_PROPOSAL_NOT_OPEN,
        ));
    }
    // The FOLD part: the room's record, its founders, the proposer's
    // binding. Held, re-folded when any of them changes.
    fold::reads(Dep::key(group));
    fold::reads(Dep::key(&row.attesting_key_id));
    let open = match dir.lookup_community(group).await? {
        Some(c) => {
            super::public_room::is_public_community(&c)
                && super::public_room::is_open_admission(&c)
                && {
                    // KR-fix10 — a founder's standing is exercised by the
                    // founder's own key (or the founder key itself, a node
                    // seated in its own right); never by the founder's node.
                    let proposer =
                        super::admission::consenting_person(dir, &row.attesting_key_id).await?;
                    dir.active_community_members(group).await?.iter().any(|m| {
                        m.role.as_deref() == Some(super::admission::MEMBER_ROLE_FOUNDER)
                            && (Some(&m.key_id) == proposer.as_ref()
                                || m.key_id == row.attesting_key_id)
                    })
                }
        }
        None => false,
    };
    if open {
        Ok(())
    } else {
        Err(fold::hold(
            reason::MEMBERSHIP_OPEN_PROPOSAL_NOT_OPEN,
            refuse(group, &row.attesting_key_id, RULE_OPEN_PROPOSAL_NOT_OPEN),
        ))
    }
}

async fn check_proposer_under_founder_only<F>(
    dir: &F,
    row: &Attestation,
    group: &str,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (wave GC6) — the group's record (protocol), its founders and
    // the proposer's binding: a fold (the reads are the proposal arm's).
    fold::reads(Dep::key(group));
    fold::reads(Dep::key(&row.attesting_key_id));
    // KR-fix10 — the founder's own key: a founder's node is refused by name
    // unless the node is itself the listed founder (its raw key).
    let proposer = super::admission::consenting_person(dir, &row.attesting_key_id)
        .await?
        .unwrap_or_else(|| row.attesting_key_id.clone());
    let founder = Some(super::admission::MEMBER_ROLE_FOUNDER);
    let ok = if row.cohort_scope == cohort_scope::FAMILY {
        let Some(f) = dir.lookup_family(group).await? else {
            return Ok(());
        };
        !super::types::consensus_protocol::founders_hold_authority(&f.consensus_protocol)
            || dir
                .active_family_members(group)
                .await?
                .iter()
                .any(|m| m.key_id == proposer && m.role.as_deref() == founder)
    } else {
        let Some(c) = dir.lookup_community(group).await? else {
            return Ok(());
        };
        !super::types::consensus_protocol::founders_hold_authority(&c.consensus_protocol)
            || dir
                .active_community_members(group)
                .await?
                .iter()
                .any(|m| m.key_id == proposer && m.role.as_deref() == founder)
    };
    if ok {
        Ok(())
    } else {
        Err(fold::hold(
            reason::MEMBERSHIP_PROPOSER_NOT_FOUNDER,
            Error::InvalidArgument(format!(
                "{PROPOSAL_DIMENSION}: under founder_only or open:self_admit only a founder of {group} proposes"
            )),
        ))
    }
}

/// **A node gives no acceptance** (CIRISPersist#972; CC 3.1.3.2: "a node
/// member of an `infrastructure` community is seated by the founders' quorum
/// … the seat is valid when the founders' quorum signed the record and the
/// node's own key record carries the conferring family's m-of-n scrub").
///
/// The ONE predicate both the growth gate and the founding rule read: `member`
/// needs no acceptance in `community` at `at` iff the community is
/// `infrastructure`, the key is node-bearing at `at` (#925's predicate), and
/// its own key record carries the accord's m-of-n scrub. The founders' quorum
/// is the caller's roster-authority check and is not weakened here. A person
/// in the same community, and a node anywhere else, still needs what they
/// needed.
///
/// v61 (CIRISPersist#1101) — the announced-owner leg is the growth
/// gate's ([`check_growth_accepted`]), not this predicate's: the founding
/// record a genesis bundle carries seats its serve node before any owner
/// binding exists (the steward's ruling: nothing in genesis carries one).
pub async fn node_seated_without_acceptance<F>(
    dir: &F,
    community: &super::types::Community,
    member: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if super::community_subkind(community) != Some(super::admission::COHORT_SUBKIND_INFRASTRUCTURE)
    {
        return Ok(false);
    }
    if !super::is_node_bearing_key_at(dir, member, at).await? {
        return Ok(false);
    }
    // v62.0.0 (KR-fix13; CC 3.1.3.2, CC 4.4.3.19: in an infrastructure room
    // a node "gives NO acceptance: seated by the founders' count alone, for
    // the canonical room with the bundle's conferral") — THE CONFERRAL ON
    // v62 IS THE BUNDLE'S SEAT. A canonical install is a serve seat of the
    // genesis bundle in force (`is_canonical_by_bundle`). The earlier
    // conferral (the accord's co-scrub on the node's own key record) can
    // never pass on v62 (`verify_accord_family_coscrub` answers
    // `accord_conferral_awaits_trust_blessing_card`, TR-fix1), so before this
    // line NO node was ever seated without its own voice, and after KR-fix10
    // a node's acceptance of a named invitation is refused: a canonical
    // install could not be added to the room at all.
    if super::edition2::genesis::is_canonical_by_bundle(dir, member).await? {
        return Ok(true);
    }
    super::admission::key_record_carries_accord_scrub(dir, member).await
}

/// **The growth gate** (FSD §5): `member` joins `group` at `growth_instant`
/// with `role` only on an admitted acceptance of a live proposal for that
/// group and role, not declined, signed no later than the proposal's
/// `expires_at`, with the growth itself signed no later than it too. Every
/// instant compared is one the consenting parties signed.
pub async fn check_growth_accepted<F>(
    dir: &F,
    scope: &str,
    group: &str,
    member: &str,
    role: Option<&str>,
    growth_instant: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (wave GC6; CC 2.7.5 "a seat is two consents, whichever was
    // signed first") — the growth reads the member's replies, the proposals
    // they name, the room record and the member's owner binding: a fold.
    // Every refusal below is held with its own token as the reason, so the
    // growth concludes when the missing consent lands, in either order.
    fold::reads(Dep::key(member));
    fold::reads(Dep::key(group));
    // #972 — a node of an infrastructure community is seated by the founders'
    // quorum (the caller's standing check, already passed) and gives no
    // acceptance.
    if membership_plane(scope) == Some(cohort_scope::TargetPlane::Room) {
        if let Some(c) = dir.lookup_community(group).await? {
            if node_seated_without_acceptance(dir, &c, member, growth_instant).await? {
                // v61 (CIRISPersist#1101; CC 5.4.6, `CLM-serve-seat-announced`)
                // — a serve seat needs an announced owner: a live owner
                // binding at `cohort_scope: federation`, judged now. A later
                // announcement satisfies it, so the refusal is retryable.
                if !super::admission::serve_seat_owner_announced(dir, member).await? {
                    // v62.0.0 (CC 2.7 rc21 rulings, "local acts, already
                    // right": `serve_seat_owner_unannounced`, part_5 l.1091)
                    // — a node's own act, kept as the retryable refusal it
                    // was; NOT a fold hold.
                    return Err(refuse(
                        group,
                        member,
                        super::admission::SERVE_SEAT_OWNER_UNANNOUNCED,
                    ));
                }
                return Ok(());
            }
        }
    }
    let replies = replies_of(dir, member).await?;
    let mut worst: Option<&'static str> = None;
    let mut note = |rule: &'static str| {
        let rank = |r: &str| match r {
            RULE_DECLINED | RULE_REPLY_CONFLICT => 4,
            RULE_PROPOSAL_EXPIRED => 3,
            RULE_ACCEPTANCE_MISMATCH => 2,
            _ => 1,
        };
        if worst.is_none_or(|w| rank(rule) > rank(w)) {
            worst = Some(rule);
        }
    };
    for a in replies
        .iter()
        .filter(|r| membership_row(r) == Some(MembershipRow::Acceptance))
    {
        if !same_membership_plane(&a.cohort_scope, scope)
            || group_of(a).ok().as_deref() != Some(group)
        {
            continue;
        }
        let pid = env_str(a, "references_attestation_id").unwrap_or_default();
        if let Some(d) = row_dep(pid) {
            fold::reads(d);
        }
        let Some(p) = dir
            .get_attestation(pid)
            .await?
            .filter(|p| p.tier == attestation_tier::FEDERATION)
            .and_then(as_proposal)
        else {
            note(RULE_PROPOSAL_UNRESOLVED);
            continue;
        };
        if replies_to(&replies, &p.row.attestation_id)
            .iter()
            .any(|r| membership_row(r) == Some(MembershipRow::Decline))
        {
            note(RULE_DECLINED);
            continue;
        }
        if !reply_matches(a, &p) || p.role.as_deref() != role {
            note(RULE_ACCEPTANCE_MISMATCH);
            continue;
        }
        // v55.0.0 (CIRISPersist#1053, CC 3.2) — a standing proposal seats
        // only while its room is an open public room.
        if p.invitee.is_none() && !room_is_open(dir, scope, group).await? {
            note(RULE_OPEN_PROPOSAL_NOT_OPEN);
            continue;
        }
        if a.asserted_at > p.expires_at
            || growth_instant > p.expires_at
            || proposal_withdrawn(dir, &p).await?
        {
            note(RULE_PROPOSAL_EXPIRED);
            continue;
        }
        // v62.0.0 (K2-fix18) — the member's consent is met; a public room
        // still never LISTS a minor (a standing protection, class 2).
        check_public_roster_not_minor(dir, scope, group, member).await?;
        return Ok(());
    }
    // A member who only ever DECLINED an invitation to this group is refused
    // terminally, not "not held yet". Only when no acceptance for the group
    // exists: a decline of an older invitation must not turn a newer
    // acceptance whose proposal has not arrived into a terminal refusal.
    let in_group = |r: &&Attestation| {
        same_membership_plane(&r.cohort_scope, scope) && group_of(r).ok().as_deref() == Some(group)
    };
    let any_acceptance = replies
        .iter()
        .filter(in_group)
        .any(|r| membership_row(r) == Some(MembershipRow::Acceptance));
    if !any_acceptance
        && replies
            .iter()
            .filter(in_group)
            .any(|r| membership_row(r) == Some(MembershipRow::Decline))
    {
        note(RULE_DECLINED);
    }
    // Every rule `worst` can name is a registered fold reason (the RULE_*
    // tokens are `fold::reason`'s membership tokens, spelled the same).
    let rule = worst.unwrap_or(RULE_ACCEPTANCE_UNRESOLVED);
    Err(fold::hold(rule, refuse(group, member, rule)))
}

/// v62.0.0 (K2-fix18; CC 3.4.13 Q5, CC 5.4.6; class 2, K2-fix17.md) — **a
/// public room never lists a minor.** A roster entry on a `public` room makes
/// its member contactable and discoverable by unconnected adults, which the
/// Q5 hard floor forbids for a minor. So a growth of a `public` room
/// (`is_public_community`, at the room plane) whose member is, or acts for,
/// or is a node owned by, a person a HELD age row places in a minor band
/// (`age::age_band_held`: the rows held now, no instant, no expiry) is held
/// [`RULE_MINOR_PUBLIC_ROSTER_ENTRY`]. Every read declares `key:<person>`, so
/// a later minor row holds a concluded growth (re-fold) and its withdrawal,
/// or being outranked, restores it. A person with no age row is listed. A
/// private room, a family, the `self` cohort and every derived-plane path
/// are untouched (the person stays reachable through their own nodes and the
/// codes they hand out).
///
/// The node path: the owner seat read here is the kernel's RAW seat
/// (`kernel_owner_selves`), not `owner_of`, because `owner_of` already
/// drops a minor owner (CC 3.2 l.961) and would hide the very person this
/// asks about.
async fn check_public_roster_not_minor<F>(
    dir: &F,
    scope: &str,
    group: &str,
    member: &str,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if membership_plane(scope) != Some(cohort_scope::TargetPlane::Room) {
        return Ok(());
    }
    if !dir
        .lookup_community(group)
        .await?
        .is_some_and(|c| super::public_room::is_public_community(&c))
    {
        return Ok(());
    }
    let mut persons: std::collections::BTreeSet<String> =
        std::collections::BTreeSet::from([member.to_owned()]);
    persons.insert(dir.active_identity_for_occurrence(member).await?);
    persons.extend(
        super::admission::kernel_owner_selves(dir, member, crate::kernel::owner::Cosign::Required)
            .await?,
    );
    for p in &persons {
        fold::reads(Dep::key(p));
        if super::age::age_band_held(dir, p).await? == super::age::AgeBand::Minor {
            return Err(fold::hold(
                RULE_MINOR_PUBLIC_ROSTER_ENTRY,
                refuse(group, member, RULE_MINOR_PUBLIC_ROSTER_ENTRY),
            ));
        }
    }
    Ok(())
}

/// Is `group` (at `scope`) an open `public` room held here?
async fn room_is_open<F>(dir: &F, scope: &str, group: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if membership_plane(scope) != Some(cohort_scope::TargetPlane::Room) {
        return Ok(false);
    }
    Ok(dir.lookup_community(group).await?.is_some_and(|c| {
        super::public_room::is_public_community(&c) && super::public_room::is_open_admission(&c)
    }))
}

/// **The founding rule** (Q1): every member a founding record lists signed
/// it — its authority or a co-signer, compared as identities. Signing the
/// record is that member's consent; anyone else joins by proposal.
pub async fn check_founding_signers<F>(
    dir: &F,
    group: &str,
    members: &[&str],
    signers: &[&str],
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut signed = std::collections::BTreeSet::new();
    for s in signers {
        signed.insert((*s).to_owned());
        // KR-fix10 — a signer's voice is its own key's and its person's; a
        // node signer founds for nobody but itself.
        if let Some(person) = super::admission::consenting_person(dir, s).await? {
            signed.insert(person);
        }
    }
    for m in members {
        if signed.contains(*m) {
            continue;
        }
        if signed.contains(&dir.active_identity_for_occurrence(m).await?) {
            continue;
        }
        return Err(refuse(group, m, RULE_FOUNDING_MEMBER_UNSIGNED));
    }
    Ok(())
}

/// The founding rule for a COMMUNITY (#972): the persons it lists signed it
/// ([`check_founding_signers`]); a node of an `infrastructure` community is
/// seated by those signatures and never signs
/// ([`node_seated_without_acceptance`], at the record's `founded_at`).
pub async fn check_community_founding_signers<F>(
    dir: &F,
    community: &super::types::Community,
    signers: &[&str],
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut persons: Vec<&str> = Vec::with_capacity(community.members.len());
    for m in &community.members {
        if !node_seated_without_acceptance(dir, community, &m.key_id, community.founded_at).await? {
            persons.push(m.key_id.as_str());
        }
    }
    check_founding_signers(dir, &community.community_key_id, &persons, signers).await
}

/// **The supersede rule** (Q2): an amendment's roster may keep, re-list or
/// drop members but never add one. `allowed` is every key the group already
/// knows: the stored record's members and the currently active roster.
pub fn check_supersede_adds_no_member(
    group: &str,
    offered: &[&str],
    allowed: &std::collections::BTreeSet<String>,
) -> Result<(), Error> {
    // v62.0.0 (wave GC6) — `allowed` is read from the held record and
    // roster ([`supersede_allowed_members`] declares the group): a member
    // they lack is a fold condition, re-folded when the seat lands.
    match offered.iter().find(|m| !allowed.contains(**m)) {
        Some(m) => {
            fold::reads(Dep::key(m));
            Err(fold::hold(
                reason::MEMBERSHIP_SUPERSEDE_CANNOT_ADD,
                refuse(group, m, RULE_SUPERSEDE_CANNOT_ADD),
            ))
        }
        None => Ok(()),
    }
}

/// The keys a supersede of `group` may list: the stored record's members and
/// the active roster (widened members included).
pub async fn supersede_allowed_members<F>(
    dir: &F,
    cohort: super::Cohort,
    group: &str,
) -> Result<std::collections::BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    fold::reads(Dep::key(group));
    let mut out = std::collections::BTreeSet::new();
    match cohort {
        super::Cohort::Family => {
            if let Some(f) = dir.lookup_family(group).await? {
                out.extend(f.members.into_iter().map(|m| m.key_id));
                out.extend(
                    dir.active_family_members(group)
                        .await?
                        .into_iter()
                        .map(|m| m.key_id),
                );
            }
        }
        _ => {
            if let Some(c) = dir.lookup_community(group).await? {
                out.extend(c.members.into_iter().map(|m| m.key_id));
                out.extend(
                    dir.active_community_members(group)
                        .await?
                        .into_iter()
                        .map(|m| m.key_id),
                );
            }
        }
    }
    Ok(out)
}

/// The members and every member's active occurrence — the keys whose
/// proposals [`live_invitees_of`] counts (its pre-v53.1.6 universe).
async fn signers_of_members<F>(
    dir: &F,
    members: &[String],
) -> Result<std::collections::BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut signers: std::collections::BTreeSet<String> = members.iter().cloned().collect();
    for m in members {
        for o in crate::federation::replication_audience::devices_of(dir, m).await? {
            signers.insert(o.occurrence_key_id);
        }
    }
    Ok(signers)
}

/// v53.0.0 (CIRISEdge#761, CC 5.4.6) — **the live invitees of a private
/// group**: the subjects of held federation-tier proposals for `group` at
/// `scope` that are unexpired, not withdrawn by their proposer and not
/// declined by their invitee. A proposal comes from a member (AV-45), so the
/// proposals are found among the rows `members` (and their active
/// occurrences) signed. Sorted, deduped.
pub async fn live_invitees_of<F>(
    dir: &F,
    scope: &str,
    group: &str,
    members: &[String],
) -> Result<Vec<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let now = crate::host::clock::now();
    // v53.1.6 — the GROUP's proposal rows (V150's cohort_target seek: the
    // rows placed on this plane naming this group), not every row every
    // member and every member's occurrence ever authored. A proposal still
    // counts only when a member or a member's active occurrence authored it
    // (the old universe); the members' occurrences are resolved lazily, the
    // first time a non-member attester turns up, and once.
    let scopes: &[&str] = match membership_plane(scope) {
        Some(cohort_scope::TargetPlane::Family) => &[cohort_scope::FAMILY],
        Some(cohort_scope::TargetPlane::Room) => {
            &[cohort_scope::COMMUNITY, cohort_scope::AFFILIATIONS]
        }
        None => return Ok(Vec::new()),
    };
    let member_set: std::collections::BTreeSet<&str> = members.iter().map(String::as_str).collect();
    let candidates: Vec<Attestation> = match super::optional_capability::unsupported_is_none(
        dir.list_targeted_by_dimension_prefix(scopes, group, PROPOSAL_DIMENSION)
            .await,
        "membership_acceptance::proposal_candidates",
    )? {
        Some(rows) => rows,
        // Pin compatibility: a directory without the targeted seek reads
        // each signer's proposal rows by dimension (V137) — bounded, same set.
        None => {
            let mut rows = Vec::new();
            for s in &signers_of_members(dir, members).await? {
                let mut pages = AttestationQuery::by(s, FOLD_PAGE)
                    .dimension_prefix(PROPOSAL_DIMENSION)
                    .pages();
                while let Some(page) = pages.next(dir).await? {
                    rows.extend(page);
                }
            }
            rows
        }
    };
    let mut signers: Option<std::collections::BTreeSet<String>> = None;
    let mut out = std::collections::BTreeSet::new();
    for row in candidates {
        if row.tier != attestation_tier::FEDERATION {
            continue;
        }
        if !member_set.contains(row.attesting_key_id.as_str()) {
            if signers.is_none() {
                signers = Some(signers_of_members(dir, members).await?);
            }
            if !signers
                .as_ref()
                .is_some_and(|s| s.contains(&row.attesting_key_id))
            {
                continue;
            }
        }
        let Some(p) = as_proposal(row) else {
            continue;
        };
        if !same_membership_plane(&p.row.cohort_scope, scope)
            || p.group != group
            || p.expires_at <= now
        {
            continue;
        }
        if proposal_withdrawn(dir, &p).await? {
            continue;
        }
        // v55.0.0 (CIRISPersist#1053) — a standing proposal names nobody:
        // its requesters are not invitees until they accept.
        let Some(invitee) = p.invitee else {
            continue;
        };
        let replies = replies_of(dir, &invitee).await?;
        let declined = replies_to(&replies, &p.row.attestation_id)
            .iter()
            .any(|r| membership_row(r) == Some(MembershipRow::Decline));
        if !declined {
            out.insert(invitee);
        }
    }
    Ok(out.into_iter().collect())
}

/// The emit input for a proposal (the inviter signs it through any emit door).
#[must_use]
pub fn proposal_input(
    scope: &str,
    group: &str,
    invitee: &str,
    role: Option<&str>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> super::types::EmitAttestationInput {
    let target_key = if scope == cohort_scope::FAMILY {
        "family_key_id"
    } else {
        "community_key_id"
    };
    let mut extra = serde_json::Map::new();
    extra.insert(
        "group_kind".into(),
        group_kind_for_scope(scope).unwrap_or("community").into(),
    );
    extra.insert(target_key.into(), group.into());
    // CC 2.6.1.7 (rc12): `role` is OPTIONAL and absent when no role is
    // offered; an explicit `null` is refused `envelope_member_null`.
    if let Some(role) = role {
        extra.insert("role".into(), role.into());
    }
    let envelope = super::envelope::EnvelopeCore {
        dimension: Some(PROPOSAL_DIMENSION.to_owned()),
        extra,
        ..super::envelope::EnvelopeCore::default()
    };
    let mut input = super::types::EmitAttestationInput::with_envelope(
        attestation_type::SCORES,
        envelope,
        scope,
    );
    input.subject_key_ids = vec![invitee.to_owned()];
    input.expires_at = Some(expires_at);
    input
}

/// v55.0.0 (CIRISPersist#1053, CC 3.2) — the emit input for a founder's
/// STANDING proposal to an open public room: [`proposal_input`] at
/// `community` with no invitee (`subject_key_ids` empty, resolved at
/// acceptance).
#[must_use]
pub fn standing_proposal_input(
    community_key_id: &str,
    role: Option<&str>,
    expires_at: chrono::DateTime<chrono::Utc>,
) -> super::types::EmitAttestationInput {
    let mut input = proposal_input(
        cohort_scope::COMMUNITY,
        community_key_id,
        "",
        role,
        expires_at,
    );
    input.subject_key_ids = Vec::new();
    input
}

/// v62.0.0 (KR-fix6) — **a reply's envelope, for a signer whose pen is
/// elsewhere** (a hardware-held owner): exactly the members
/// [`reply_input`] gives the software producer (`dimension`,
/// `references_attestation_id`, `proposal_hash`, the group's members for a
/// group reply) plus the `cohort_scope` the producer states. Hand it to
/// `Engine::statement_draft("scores", &envelope, signer_iss, signer_kid_hex,
/// sub, asserted_at_ms, None)`, with `sub` = the proposal's
/// `attested_key_id` for a root grant; sign the draft; `submit_voice`. Both
/// paths then state the reply through `emit::row_payload`.
#[must_use]
pub fn reply_envelope(proposal: &Attestation, accept: bool) -> serde_json::Value {
    let input = reply_input(proposal, accept);
    let mut envelope = input.attestation_envelope.to_value();
    if let Some(o) = envelope.as_object_mut() {
        if !input.subject_key_ids.is_empty() {
            o.insert(
                "subject_key_ids".into(),
                serde_json::json!(input.subject_key_ids),
            );
        }
        o.insert(
            "cohort_scope".into(),
            serde_json::Value::String(input.cohort_scope.clone()),
        );
        o.retain(|_, v| !v.is_null());
    }
    envelope
}

/// The emit input for K's reply (acceptance or decline) to `proposal`.
#[must_use]
pub fn reply_input(proposal: &Attestation, accept: bool) -> super::types::EmitAttestationInput {
    // v62.0.0 (KR-fix2; CC 3.2 as ruled 2026-11-21) — a reply to a counted
    // grant from the root: placed at the federation scope, naming no group
    // (the root is the accord of the bundle the grant names), attested to the
    // grantee, binding the grant's id and content hash
    // ([`check_root_grant_reply`]). The signer must be the grantee's
    // consenter: for a `node` or `agent` grantee, its owner.
    if super::admission::is_counted_root_grant_row(proposal) {
        let mut extra = serde_json::Map::new();
        extra.insert(
            "proposal_hash".into(),
            proposal.original_content_hash.clone().into(),
        );
        let envelope = super::envelope::EnvelopeCore {
            dimension: Some(
                if accept {
                    ACCEPTANCE_DIMENSION
                } else {
                    DECLINE_DIMENSION
                }
                .to_owned(),
            ),
            references_attestation_id: Some(proposal.attestation_id.clone()),
            extra,
            ..super::envelope::EnvelopeCore::default()
        };
        let mut input = super::types::EmitAttestationInput::with_envelope(
            attestation_type::SCORES,
            envelope,
            cohort_scope::FEDERATION.to_owned(),
        );
        input.attested_key_id = Some(proposal.attested_key_id.clone());
        return input;
    }
    let mut extra = serde_json::Map::new();
    for key in [
        "group_kind",
        "family_key_id",
        "community_key_id",
        "community_id",
        "cohort_key_id",
    ] {
        if let Some(v) = proposal.attestation_envelope.get(key) {
            extra.insert(key.into(), v.clone());
        }
    }
    extra.insert(
        "proposal_hash".into(),
        proposal.original_content_hash.clone().into(),
    );
    // The acceptance restates the offered role, and carries none when none
    // was offered (absent, never `null`).
    if accept {
        if let Some(role) = proposal
            .attestation_envelope
            .get("role")
            .filter(|v| !v.is_null())
        {
            extra.insert("role".into(), role.clone());
        }
    }
    let envelope = super::envelope::EnvelopeCore {
        dimension: Some(
            if accept {
                ACCEPTANCE_DIMENSION
            } else {
                DECLINE_DIMENSION
            }
            .to_owned(),
        ),
        references_attestation_id: Some(proposal.attestation_id.clone()),
        extra,
        ..super::envelope::EnvelopeCore::default()
    };
    let mut input = super::types::EmitAttestationInput::with_envelope(
        attestation_type::SCORES,
        envelope,
        proposal.cohort_scope.clone(),
    );
    input.attested_key_id = proposal.subject_key_ids.first().cloned();
    input
}

/// v52.0.0 (CIRISPersist#955) — fixtures for a member's consent: a proposal
/// by one of the group's active founders (else the given signer) and the
/// member's own acceptance, both hybrid-signed with the deterministic test
/// signers and stored through the ordinary put door. Nothing here bypasses a
/// gate: the growth that follows is still judged by the group's standing and
/// by [`check_growth_accepted`].
#[cfg(any(test, feature = "test-anchor"))]
pub mod test_support {
    use super::{ACCEPTANCE_DIMENSION, PROPOSAL_DIMENSION};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, cohort_scope};
    use crate::federation::{Attestation, Error, FederationDirectory, SignedAttestation};
    use chrono::{DateTime, Duration, Utc};

    fn ms(t: DateTime<Utc>) -> DateTime<Utc> {
        DateTime::<Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms instant")
    }

    fn target_key(scope: &str) -> &'static str {
        if scope == cohort_scope::FAMILY {
            "family_key_id"
        } else {
            "community_key_id"
        }
    }

    fn sealed(
        signer: &str,
        attested: &str,
        scope: &str,
        envelope: serde_json::Value,
        at: DateTime<Utc>,
        expires_at: Option<DateTime<Utc>>,
        subjects: Vec<String>,
    ) -> Attestation {
        let mut r = ts::bare_attestation(
            &uuid::Uuid::new_v4().to_string(),
            signer,
            attested,
            &envelope,
        );
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.cohort_scope = scope.into();
        r.asserted_at = ms(at);
        r.scrub_timestamp = ms(at);
        r.expires_at = expires_at.map(ms);
        r.subject_key_ids = subjects;
        ts::seal_row_in_place(signer, &mut r);
        r
    }

    /// A proposal by `proposer` of `member` into `group` at `at` (30 days).
    #[must_use]
    pub fn proposal_row(
        proposer: &str,
        scope: &str,
        group: &str,
        member: &str,
        role: Option<&str>,
        at: DateTime<Utc>,
    ) -> Attestation {
        let mut envelope = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "dimension": PROPOSAL_DIMENSION,
            // v54.0.0 (#1034) — the production mapping (`affiliations`
            // is a room: `community`), not the raw scope.
            "group_kind": super::group_kind_for_scope(scope).unwrap_or("community"),
            target_key(scope): group,
        });
        // Absent when no role is offered, as the production emitter writes it.
        if let Some(role) = role {
            envelope["role"] = role.into();
        }
        sealed(
            proposer,
            proposer,
            scope,
            envelope,
            at,
            Some(at + Duration::seconds(super::MEMBERSHIP_PROPOSAL_MAX_TTL_SECS)),
            vec![member.to_owned()],
        )
    }

    /// `member`'s acceptance of `p` at `at`, signed by `member`.
    #[must_use]
    pub fn acceptance_row(member: &str, p: &Attestation, at: DateTime<Utc>) -> Attestation {
        let scope = p.cohort_scope.clone();
        let mut envelope = serde_json::json!({
            "id": uuid::Uuid::new_v4().to_string(),
            "dimension": ACCEPTANCE_DIMENSION,
            // v54.0.0 (#1034) — the production mapping (`affiliations`
            // is a room: `community`), not the raw scope.
            "group_kind": super::group_kind_for_scope(&scope).unwrap_or("community"),
            target_key(&scope): p.attestation_envelope.get(target_key(&scope)).cloned(),
            "references_attestation_id": p.attestation_id,
            "proposal_hash": p.original_content_hash,
        });
        // The acceptance restates the offered role, and carries none when none
        // was offered.
        if let Some(role) = p.attestation_envelope.get("role").filter(|v| !v.is_null()) {
            envelope["role"] = role.clone();
        }
        sealed(member, member, &scope, envelope, at, None, vec![])
    }

    async fn founder_of<D: FederationDirectory + ?Sized>(
        d: &D,
        scope: &str,
        group: &str,
    ) -> Result<Option<String>, Error> {
        let founder = Some(crate::federation::admission::MEMBER_ROLE_FOUNDER);
        Ok(if scope == cohort_scope::FAMILY {
            d.active_family_members(group)
                .await?
                .into_iter()
                .find(|m| m.role.as_deref() == founder)
                .map(|m| m.key_id)
        } else {
            d.active_community_members(group)
                .await?
                .into_iter()
                .find(|m| m.role.as_deref() == founder)
                .map(|m| m.key_id)
        })
    }

    /// **`member` consents to join `group` at `role`**: a proposal (by an
    /// active founder, else `fallback_proposer`) and the member's acceptance,
    /// both at `at`, stored in `d`.
    pub async fn consent<D: FederationDirectory + ?Sized>(
        d: &D,
        scope: &str,
        group: &str,
        fallback_proposer: &str,
        member: &str,
        role: Option<&str>,
        at: DateTime<Utc>,
    ) -> Result<(), Error> {
        let proposer = founder_of(d, scope, group)
            .await?
            .unwrap_or_else(|| fallback_proposer.to_owned());
        let p = proposal_row(&proposer, scope, group, member, role, at);
        d.put_attestation(SignedAttestation {
            attestation: p.clone(),
        })
        .await?;
        d.put_attestation(SignedAttestation {
            attestation: acceptance_row(member, &p, at),
        })
        .await
        .map(|_| ())
    }

    fn report(r: Result<(), Error>) {
        if let Err(e) = r {
            eprintln!("membership_acceptance::test_support: consent not written: {e}");
        }
    }

    /// Put a widening AFTER the member's consent: the fixture shape of the
    /// real flow (proposal → acceptance → widening). The consent is written
    /// best-effort — a fixture whose widening must be refused for another
    /// reason (an unregistered member, a signer without standing) is still
    /// refused by the door, by that reason or by the missing acceptance.
    #[allow(async_fn_in_trait)]
    pub trait ConsentedWidening {
        /// `put_community_membership_widening`, consented first.
        async fn put_community_membership_widening_consented(
            &self,
            w: crate::federation::SignedCommunityMembershipWidening,
        ) -> Result<(), Error>;
        /// `put_family_membership_widening`, consented first.
        async fn put_family_membership_widening_consented(
            &self,
            w: crate::federation::SignedFamilyMembershipWidening,
        ) -> Result<(), Error>;
        /// `add_community_member`, consented first.
        async fn add_community_member_consented(
            &self,
            group: &str,
            member: crate::federation::types::CommunityMember,
            spec: &crate::federation::cohort::AdmitSpec,
        ) -> Result<bool, Error>;
        /// `add_family_member`, consented first.
        async fn add_family_member_consented(
            &self,
            group: &str,
            member: crate::federation::types::FamilyMember,
            spec: &crate::federation::cohort::AdmitSpec,
        ) -> Result<bool, Error>;
        /// `add_member`, consented first.
        async fn add_member_consented(
            &self,
            cohort: crate::federation::Cohort,
            group: &str,
            member: crate::federation::RosterMember,
            spec: &crate::federation::cohort::AdmitSpec,
        ) -> Result<bool, Error>;
    }

    impl<T: FederationDirectory + ?Sized> ConsentedWidening for T {
        async fn put_community_membership_widening_consented(
            &self,
            w: crate::federation::SignedCommunityMembershipWidening,
        ) -> Result<(), Error> {
            report(consent_community_widening(self, &w).await);
            self.put_community_membership_widening(w).await
        }
        async fn put_family_membership_widening_consented(
            &self,
            w: crate::federation::SignedFamilyMembershipWidening,
        ) -> Result<(), Error> {
            report(consent_family_widening(self, &w).await);
            self.put_family_membership_widening(w).await
        }
        async fn add_community_member_consented(
            &self,
            group: &str,
            member: crate::federation::types::CommunityMember,
            spec: &crate::federation::cohort::AdmitSpec,
        ) -> Result<bool, Error> {
            report(
                consent(
                    self,
                    cohort_scope::COMMUNITY,
                    group,
                    &spec.authority_key_id,
                    &member.key_id,
                    member.role.as_deref(),
                    member.joined_at,
                )
                .await,
            );
            self.add_community_member(group, member, spec).await
        }
        async fn add_family_member_consented(
            &self,
            group: &str,
            member: crate::federation::types::FamilyMember,
            spec: &crate::federation::cohort::AdmitSpec,
        ) -> Result<bool, Error> {
            report(
                consent(
                    self,
                    cohort_scope::FAMILY,
                    group,
                    &spec.authority_key_id,
                    &member.key_id,
                    member.role.as_deref(),
                    member.joined_at,
                )
                .await,
            );
            self.add_family_member(group, member, spec).await
        }
        async fn add_member_consented(
            &self,
            cohort: crate::federation::Cohort,
            group: &str,
            member: crate::federation::RosterMember,
            spec: &crate::federation::cohort::AdmitSpec,
        ) -> Result<bool, Error> {
            // v54.0.0 (#1034) — an affiliation's proposal is placed at
            // `affiliations`: the write-scope gate reads the record's
            // declared cohort.
            let scope = match cohort {
                crate::federation::Cohort::Family => cohort_scope::FAMILY,
                crate::federation::Cohort::Affiliations => cohort_scope::AFFILIATIONS,
                _ => cohort_scope::COMMUNITY,
            };
            report(
                consent(
                    self,
                    scope,
                    group,
                    &spec.authority_key_id,
                    &member.key_id,
                    member.role.as_deref(),
                    member.joined_at,
                )
                .await,
            );
            self.add_member(cohort, group, member, spec).await
        }
    }

    /// [`consent`] for the member a signed community widening adds.
    pub async fn consent_community_widening<D: FederationDirectory + ?Sized>(
        d: &D,
        w: &crate::federation::SignedCommunityMembershipWidening,
    ) -> Result<(), Error> {
        let r = &w.community_membership_widening;
        consent(
            d,
            cohort_scope::COMMUNITY,
            &r.community_key_id,
            &w.authority_key_id,
            &r.member_key_id,
            r.role.as_deref(),
            r.effective_at,
        )
        .await
    }

    /// [`consent`] for the member a signed family widening adds.
    pub async fn consent_family_widening<D: FederationDirectory + ?Sized>(
        d: &D,
        w: &crate::federation::SignedFamilyMembershipWidening,
    ) -> Result<(), Error> {
        let r = &w.family_membership_widening;
        consent(
            d,
            cohort_scope::FAMILY,
            &r.family_key_id,
            &w.authority_key_id,
            &r.member_key_id,
            r.role.as_deref(),
            r.effective_at,
        )
        .await
    }
}
