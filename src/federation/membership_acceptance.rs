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
//!   naming the proposal by its row id in `refs.answers` (KR-fix32; the row
//!   id is the digest of its payload) and restating the (acceptance) role.
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
/// ACCEPT-tokens (CC 3.1.2.1, "concludes nothing") — a root grant's
/// acceptance signed by the grantee's own key (a machine's consent is its
/// owner's).
pub const RULE_ACCEPTANCE_BY_GRANTEE: &str = "acceptance_by_grantee";
/// ACCEPT-tokens (CC 3.1.2.1) — the acceptance's signer is not the owner of
/// the grantee's key (nor, for a person grantee, the person).
pub const RULE_ACCEPTANCE_NOT_BY_OWNER: &str = "acceptance_not_by_owner";
/// ACCEPT-tokens (CC 3.1.2.1) — the acceptance names another grant in
/// `refs.answers` (a held row that is no counted root grant).
pub const RULE_ACCEPTANCE_OTHER_GRANT: &str = "acceptance_other_grant";
/// ACCEPT-tokens (CC 3.1.2.1) — the acceptance's `sub` is not the grant's
/// grantee.
pub const RULE_ACCEPTANCE_OTHER_GRANTEE: &str = "acceptance_other_grantee";

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
        // v62.0.0 (KR-fix32; the Constitution's ruling (A)) — the answered
        // row is named by `refs.answers` (read back as
        // `references_attestation_id`); `proposal_hash` is gone (a row's id
        // IS the digest of its payload).
        if env_str(row, "references_attestation_id").is_none_or(str::is_empty) {
            return Err(Error::InvalidArgument(
                "root grant reply: the row it answers (refs.answers) is required".into(),
            ));
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
            // v62.0.0 (KR-fix32) — `proposal_hash` is gone, as above.
            if env_str(row, "references_attestation_id").is_none_or(str::is_empty) {
                return Err(Error::InvalidArgument(
                    "membership reply: the row it answers (refs.answers) is required".into(),
                ));
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

/// v62.0.0 (KR-fix17) — **the envelope of a `withdraws` of the held row
/// `target`, placed where the target is**: the composer's own envelope
/// (`withdraws_attestation_envelope`: the target's id and type) and, for a
/// target in a room (`community` / `affiliations`), that room restated as
/// `community_id` (a common member, so a composer may carry it; the serve
/// rule reads the composer's own placement). A family target restates
/// nothing: its family is read from the target ([`composer_placement`]).
///
/// The ONE envelope behind `Engine::withdraw_statement` (a software signer)
/// and `Engine::withdraw_statement_draft` (a key elsewhere). The row is
/// placed at `target.cohort_scope` and is about `target.attested_key_id`.
///
/// # Errors
/// A target whose envelope names two different cohorts.
pub fn withdrawal_envelope_of(target: &Attestation) -> Result<serde_json::Value, Error> {
    let mut envelope =
        super::withdraws_attestation_envelope(&target.attestation_id, &target.attestation_type);
    let room = super::admission::envelope_cohort_target(&target.attestation_envelope)?;
    if let (Some(room), Some(o)) = (room, envelope.as_object_mut()) {
        if cohort_scope::target_plane(&target.cohort_scope) == Some(cohort_scope::TargetPlane::Room)
        {
            o.insert(
                "community_id".to_owned(),
                serde_json::Value::String(room.to_owned()),
            );
        }
    }
    Ok(envelope)
}

/// v62.0.0 (KR-fix17) — the prefix of the refusal of a `withdraws` /
/// `recants` that is placed somewhere other than its target:
/// `composer_placed_apart_from_target: …`.
pub const COMPOSER_PLACED_APART_FROM_TARGET: &str = "composer_placed_apart_from_target";

/// v62.0.0 (KR-fix17) — where a retraction's write-scope question is asked:
/// its target's scope and room ([`composer_placement`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ComposerPlacement {
    /// The target row's `cohort_scope`.
    pub cohort_scope: String,
    /// The room or family the target row names, if any.
    pub target: Option<String>,
    /// The key that AUTHORED the target row (its `author`). `None` for a
    /// COUNTED row (no `author`: a quorum's act, CC 2.4.1.1 rule 0): nobody
    /// is its author, and no one voice of it retracts it alone.
    pub attester: Option<String>,
}

/// v62.0.0 (KR-fix17; CC 2.4.1.1: a retraction acts on the row it names) —
/// **the placement a `withdraws` / `recants` is judged at: its HELD TARGET's.**
///
/// `None`: `row` is not such a composer, or it is placed at no room and
/// names none (the commons or `self`, as `Engine::revoke_delegation` and the
/// erasure path place theirs): the caller's ordinary rule applies and no
/// roster is read, as before.
///
/// Otherwise the composer claims a room (it is placed at a targeted scope,
/// `family` / `community` / `affiliations`, or its envelope names a room or
/// family). Then:
/// - its target must be held, else the composer WAITS (`link_unheld`,
///   `WithdrawsTargetUnheld`, the hold the dimension gate already raises:
///   [`attestation_admit::withdraws_target_unheld`](super::attestation_admit::withdraws_target_unheld));
/// - its own `cohort_scope` must be the target's, and a room it names must be
///   the target's: otherwise refused [`COMPOSER_PLACED_APART_FROM_TARGET`]
///   (a member of room B could name B on a withdrawal of a room-A row and
///   have membership proved for B);
/// - the answer is the TARGET's scope and room, so the signer's membership
///   is asked about the room the withdrawn row is in. A composer that names
///   no room of its own (every edition-2 composer the fixtures and
///   `withdraws_attestation_envelope` build) is placed by its target.
///
/// Before KR-fix17 the room was read from the composer's own envelope only,
/// which carries none: every retraction placed at a room was refused
/// `NoCommunityMembership`, whoever signed it.
///
/// The target is read from its landed row (`get_attestation`, the mapped
/// names), else from its held statement
/// ([`edition2::typed::held_target_row`](super::edition2::typed::held_target_row),
/// the one reader of a composer's held target).
///
/// # Errors
/// The wait and the refusal above; directory reads.
pub async fn composer_placement<F>(
    dir: &F,
    row: &Attestation,
) -> Result<Option<ComposerPlacement>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use ciris_verify_core::cde::Value;
    if !super::edition2::emit::carries_no_dimension(&row.attestation_type) {
        return Ok(None);
    }
    let own_target = super::admission::envelope_cohort_target(&row.attestation_envelope)?;
    if !cohort_scope::is_targeted(&row.cohort_scope) && own_target.is_none() {
        return Ok(None);
    }
    let Some(named) = row
        .attestation_envelope
        .get(super::envelope::paths::REFERENCES_ATTESTATION_ID)
        .and_then(serde_json::Value::as_str)
    else {
        // A composer naming no target: Verify's reader refuses it.
        return Ok(None);
    };
    let placed = if let Some(t) = dir.get_attestation(named).await? {
        Some(ComposerPlacement {
            cohort_scope: t.cohort_scope.clone(),
            target: super::admission::envelope_cohort_target(&t.attestation_envelope)?
                .map(str::to_owned),
            // An authored row's attester is its author. A counted row
            // (it carries a statement and states no `author`) has none.
            attester: (!super::admission::is_counted_row(&t)).then(|| t.attesting_key_id.clone()),
        })
    } else {
        let held = match super::edition2::emit::carried_statement(row) {
            Some(st) => super::edition2::typed::held_target_row(dir, &st).await?,
            None => None,
        };
        held.map(|t| ComposerPlacement {
            cohort_scope: t
                .payload
                .get_text("cohort_scope")
                .and_then(Value::as_text)
                .unwrap_or(cohort_scope::FEDERATION)
                .to_owned(),
            target: super::admission::COHORT_TARGET_ENVELOPE_FIELDS
                .iter()
                .find_map(|f| t.payload.get_text(f).and_then(Value::as_text))
                .filter(|v| !v.is_empty())
                .map(str::to_owned),
            attester: t
                .payload
                .get_text("author")
                .and_then(Value::as_text)
                .map(str::to_owned),
        })
    };
    let Some(placed) = placed else {
        return Err(super::attestation_admit::withdraws_target_unheld(
            &row.attestation_id,
            named,
        ));
    };
    if row.cohort_scope != placed.cohort_scope
        || own_target.is_some_and(|own| placed.target.as_deref() != Some(own))
    {
        return Err(Error::InvalidArgument(format!(
            "{COMPOSER_PLACED_APART_FROM_TARGET}: {} {} is placed at {:?}{} and the row it names, \
             {named}, is at {:?}{}: a retraction is placed where its target is (CC 2.4.1.1)",
            row.attestation_type,
            row.attestation_id,
            row.cohort_scope,
            own_target.map(|t| format!(" in {t}")).unwrap_or_default(),
            placed.cohort_scope,
            placed
                .target
                .as_deref()
                .map(|t| format!(" in {t}"))
                .unwrap_or_default(),
        )));
    }
    Ok(Some(placed))
}

/// v62.0.0 (WD-fix16a; the join carriage, Constitution 11-23) — **is `row`
/// an owner binding placed at a group by a live invitee of that group?** The
/// binding names the group (`envelope_cohort_target`) at a targeted scope;
/// its owner (the payload's `author`, else the signer) is a live invitee of
/// the group (the subject of a held, unexpired, unwithdrawn, undeclined
/// proposal at it by a member, [`live_invitees_of`]) AND has answered it (a
/// held `membership:acceptance` by the owner at the group). Declared as reads of
/// the group and the owner, so a held binding re-folds when the invitation
/// arrives.
///
/// # Errors
/// Directory reads; a binding naming two groups.
pub(crate) async fn owner_binding_placed_by_an_invitee<F>(
    dir: &F,
    row: &Attestation,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if row.attestation_type != attestation_type::DELEGATES_TO
        || !super::admission::is_owner_binding_envelope(&row.attestation_envelope)
    {
        return Ok(false);
    }
    let Some(plane) = membership_plane(&row.cohort_scope) else {
        return Ok(false);
    };
    let Some(group) = super::admission::envelope_cohort_target(&row.attestation_envelope)? else {
        return Ok(false);
    };
    let owner = row
        .attestation_envelope
        .get("author")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(row.attesting_key_id.as_str());
    fold::reads(Dep::key(group));
    fold::reads(Dep::key(owner));
    // WD-fix16e — a private room takes no identity-key owner binding on the
    // invitation (its join is the room-key form, CC 3.1.3.2).
    if room_is_private(dir, group).await? {
        return Ok(false);
    }
    let kind = match plane {
        cohort_scope::TargetPlane::Family => super::group_plane::GroupKind::Family,
        cohort_scope::TargetPlane::Room => super::group_plane::GroupKind::Community,
    };
    let members =
        // v62.0.0 (HOLD-1d2) — a re-judgement reads the row's original receipt.
        super::cosign::active_members_at(dir, kind, group, crate::federation::attestation_admit::receipt_now()).await?;
    if members.is_empty() {
        return Ok(false);
    }
    if !live_invitees_of(dir, &row.cohort_scope, group, &members)
        .await?
        .iter()
        .any(|i| i == owner)
    {
        return Ok(false);
    }
    // ... and has ANSWERED it: a held acceptance by the owner at the group
    // (the answer envelope carries the acceptance before the binding), so
    // an invitee who has not accepted discloses nothing of its node to the
    // room.
    let mut pages = AttestationQuery::to(owner, FOLD_PAGE)
        .dimension_prefix(ACCEPTANCE_DIMENSION)
        .pages();
    while let Some(page) = pages.next(dir).await? {
        for a in page {
            if membership_row(&a) == Some(MembershipRow::Acceptance)
                && super::admission::envelope_cohort_target(&a.attestation_envelope)? == Some(group)
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// v62.0.0 (WD-fix16e; CC 3.1.3.2, the room-key form Eric ruled in for
/// v62.0) — **is `room` a PRIVATE room?** Its founding roster states
/// `membership: "private"` (`payloads::CLOSED_VALUES`: `private` | `public`;
/// absent reads public), carried into the community record's `policy_blob`
/// (`edition2::group::policy_blob_of`). A private room seats per-device ROOM
/// KEYS, not identities: the identity-key carriage below is not its form.
/// `false` when this node holds no record of `room` (it cannot tell).
///
/// # Errors
/// Directory reads.
pub(crate) async fn room_is_private<F>(dir: &F, room: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(dir
        .lookup_community(room)
        .await?
        .and_then(|c| c.policy_blob)
        .and_then(|b| {
            b.get("membership")
                .and_then(serde_json::Value::as_str)
                .map(|m| m == "private")
        })
        .unwrap_or(false))
}

/// The refusal of the identity-key carriage for a private room.
fn private_room_carriage_refused(what: &str, room: &str) -> Error {
    Error::InvalidArgument(format!(
        "{what}: {room} is a PRIVATE room (`membership: private`, CC 3.1.3.2): its roster seats \
         per-device room keys, and its join carries room-key rows, not an identity-key owner \
         binding; this carriage is for identity-seated rooms (a family, a public or \
         roster-visible room)"
    ))
}

/// The statements of a held edition-2 row (every voice), for an envelope.
async fn row_statements<F>(dir: &F, row: &Attestation, what: &str) -> Result<Vec<Vec<u8>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(rid) = super::edition2::voices::carried_row_id(row) else {
        return Err(Error::InvalidArgument(format!(
            "join carriage: the {what} {} is not an edition-2 row",
            row.attestation_id
        )));
    };
    dir.edition2_voices(&rid).await
}

/// The occurrence bind statements (every voice) `dir` holds for `identity`,
/// as its signed occurrence listing serves them (`ceg_statements`).
async fn occurrence_statements<F>(dir: &F, identity: &str) -> Result<Vec<Vec<u8>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut out = Vec::new();
    for occ in dir.list_signed_identity_occurrences_for(identity).await? {
        if let Some(all) = occ
            .signed_envelope
            .get("ceg_statements")
            .and_then(serde_json::Value::as_array)
        {
            for h in all.iter().filter_map(serde_json::Value::as_str) {
                if let Ok(b) = hex::decode(h) {
                    if !out.contains(&b) {
                        out.push(b);
                    }
                }
            }
        }
    }
    Ok(out)
}

/// Is `statement` a voice of an owner binding authored by `owner` and
/// placed at `group` (its payload's `cohort_scope` targeted, its group member
/// `community_id` / `community_key_id` / `family_id` / `family_key_id` =
/// `group`)?
fn binding_placed_at(statement: &[u8], owner: &str, group: &str) -> bool {
    use ciris_verify_core::cde::Value;
    let Some((_, payload)) = super::edition2::liveness::statement_parts(statement) else {
        return false;
    };
    let text = |m: &str| payload.get_text(m).and_then(Value::as_text);
    let targeted = text("cohort_scope").is_some_and(|s| membership_plane(s).is_some());
    let names_group = [
        "community_id",
        "community_key_id",
        "family_id",
        "family_key_id",
    ]
    .iter()
    .any(|m| text(m) == Some(group));
    targeted && names_group && text("author") == Some(owner)
}

/// The identity a membership row speaks for: its payload's `author`, else
/// its signer.
fn row_author(row: &Attestation) -> String {
    row.attestation_envelope
        .get("author")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(row.attesting_key_id.as_str())
        .to_owned()
}

/// v62.0.0 (WD-fix16a; the join carriage as Constitution ruled 11-23, the
/// form of the contact request) — **the rows of THE INVITATION envelope**,
/// which the host seals to the invitee's occurrence key: the inviter's
/// occurrence bind statements (every voice), then the proposal's own
/// statement(s). Nothing else (no roster: the invitee holds nothing of the
/// room before it is seated, CC 2.7.8). In receive order: offer each to the
/// invitee's replicated statement door, re-offering a wait.
///
/// # Errors
/// `InvalidArgument` when `proposal_attestation_id` is not a held
/// `membership:proposal` row; directory reads.
pub async fn join_invitation_rows<F>(
    dir: &F,
    proposal_attestation_id: &str,
) -> Result<Vec<Vec<u8>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let proposal = dir
        .get_attestation(proposal_attestation_id)
        .await?
        .filter(|r| membership_row(r) == Some(MembershipRow::Proposal))
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "join_invitation_rows: {proposal_attestation_id} is not a held membership proposal"
            ))
        })?;
    if let Some(group) = super::admission::envelope_cohort_target(&proposal.attestation_envelope)? {
        if membership_plane(&proposal.cohort_scope) == Some(cohort_scope::TargetPlane::Room)
            && room_is_private(dir, group).await?
        {
            return Err(private_room_carriage_refused("join_invitation_rows", group));
        }
    }
    let mut out = occurrence_statements(dir, &row_author(&proposal)).await?;
    for st in row_statements(dir, &proposal, "proposal").await? {
        if !out.contains(&st) {
            out.push(st);
        }
    }
    Ok(out)
}

/// v62.0.0 (WD-fix16a; the join carriage as Constitution ruled 11-23) —
/// **the rows of THE ANSWER envelope**, which the host seals to the
/// proposer's occurrence key: the joiner's occurrence bind statements, the
/// acceptance's own statement(s), then the joiner's owner binding(s)
/// RE-SIGNED AT `room` (every voice of each, of every node the joiner owns:
/// read from the statements the joiner's node KEEPS, since the binding is
/// held there while the room's roster is not). The proposer holds the room's
/// roster, so the binding is admitted
/// ([`owner_binding_placed_by_an_invitee`]); it is a row of the room, so
/// cohort delivery takes it to the other members.
///
/// # Errors
/// `InvalidArgument` when `acceptance_attestation_id` is not a held
/// `membership:acceptance` for `room`, or when the joiner holds no owner
/// binding placed at `room` (re-sign one at the room first); directory reads.
pub async fn join_answer_rows<F>(
    dir: &F,
    acceptance_attestation_id: &str,
    room: &str,
) -> Result<Vec<Vec<u8>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let acceptance = dir
        .get_attestation(acceptance_attestation_id)
        .await?
        .filter(|r| membership_row(r) == Some(MembershipRow::Acceptance))
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "join_answer_rows: {acceptance_attestation_id} is not a held membership acceptance"
            ))
        })?;
    if super::admission::envelope_cohort_target(&acceptance.attestation_envelope)? != Some(room) {
        return Err(Error::InvalidArgument(format!(
            "join_answer_rows: the acceptance {acceptance_attestation_id} is not about {room}"
        )));
    }
    // WD-fix16e — refused for a room this node knows is private. The joiner's
    // node holds no record of the room before it is seated (CC 2.7.8), so it
    // cannot always tell: the proposer's door is the second guard
    // ([`owner_binding_placed_by_an_invitee`] admits no identity-key binding
    // at a private room).
    if room_is_private(dir, room).await? {
        return Err(private_room_carriage_refused("join_answer_rows", room));
    }
    let joiner = acceptance.attested_key_id.clone();
    let mut out = occurrence_statements(dir, &joiner).await?;
    // The acceptance before the binding: the proposer admits a binding
    // placed at the room only from an invitee who has answered
    // ([`owner_binding_placed_by_an_invitee`]).
    for st in row_statements(dir, &acceptance, "acceptance").await? {
        if !out.contains(&st) {
            out.push(st);
        }
    }
    // The binding re-signed at the room is HELD on the joiner's own node
    // (the room's roster is not held there: CC 2.7.8), so it is read as the
    // statements the node keeps, not as a concluded row: every voice of an
    // owner binding of a node the joiner owns, authored by the joiner and
    // placed at `room`.
    let families = [
        ciris_verify_core::namespace_match::family_id(
            "ownership:{relation}:{target_kind}:{version}",
        ),
        super::edition2::emit::DELEGATES_TO_FAMILY.to_owned(),
    ];
    let mut placed = 0usize;
    for node in super::admission::nodes_owned_by(dir, &joiner).await? {
        for family in &families {
            for st in dir.edition2_statements_about(family, &node).await? {
                if binding_placed_at(&st, &joiner, room) && !out.contains(&st) {
                    placed += 1;
                    out.push(st);
                }
            }
        }
    }
    if placed == 0 {
        return Err(Error::InvalidArgument(format!(
            "join_answer_rows: {joiner} holds no owner binding placed at {room}: the answer \
             carries the joiner's binding re-signed at the room (CC 5.4.6); re-sign one first"
        )));
    }
    Ok(out)
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
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(kind) = membership_row(row) else {
        // v62.0.0 (KR-fix17; CC 2.4.1.1) — a RETRACTION (`withdraws` /
        // `recants`) is placed where its TARGET is: its room is the held
        // target's, never the composer's own word.
        if let Some(placed) = composer_placement(dir, row).await? {
            // v62.0.0 (KR-fix17 rev 3; CC 2.4.1.1, the table's rule 1: "the
            // key that signed T (T.attesting_key_id) | Condition: none";
            // confirmed by Constitution) — THE AUTHOR OF THE TARGET ROW,
            // RETRACTING IT, NEEDS NO MEMBERSHIP. A person's standing to
            // retract their own statement does not lapse when they leave the
            // room, and the retraction is placed where its target is: its
            // audience is the target's audience.
            // - "the key that signed T" is read as the IDENTITY: any of that
            //   person's own device keys (`same_consenting_party`: device to
            //   person), never a node for its owner.
            // - A COUNTED row is rule 0's, not this arm's: it has no author
            //   (`placed.attester` is `None`), so one voice of a quorum's act
            //   never retracts it alone.
            // - The former member is not in the room's audience and is served
            //   nothing back; this decision reads nothing they would have to
            //   be served. The door's answer is all they learn.
            // `withdraws` / `recants` only; a retraction carries no content.
            // Everyone else needs membership of the target's room, below.
            if let Some(author) = placed.attester.as_deref() {
                if same_consenting_party(dir, &row.attesting_key_id, author).await? {
                    return Ok(());
                }
            }
            // v62.0.0 (KR-fix30) — standing at the row's own instant.
            return dir
                .check_write_cohort_scope_for_at(
                    &row.attesting_key_id,
                    write_path,
                    &placed.cohort_scope,
                    placed.target.as_deref(),
                    Some(row.asserted_at),
                    Some(received_at),
                )
                .await;
        }
        // v62.0.0 (WD-fix16a; the join carriage as Constitution ruled 11-23:
        // "THE ANSWER, sealed to the proposer: the membership:acceptance +
        // the joiner's occurrence row(s) + the joiner's owner binding
        // RE-SIGNED AT R. The proposer holds R's roster so the binding is
        // admitted") — an owner binding PLACED at a group by a LIVE INVITEE
        // of that group is the joining step, not a write by a member: the
        // owner is not on R's roster yet, so the member test below would
        // hold it forever (its instant precedes the seat). Admitted on the
        // invitation: a held, unexpired, unwithdrawn, undeclined proposal at
        // the group naming the owner (`live_invitees_of`). Every other gate
        // (the owner's and the node's voices, the counted gate) is the
        // door's, unchanged.
        if owner_binding_placed_by_an_invitee(dir, row).await? {
            return Ok(());
        }
        // v62.0.0 (KR-fix30; the lead's ruling on I4310) — a row a member
        // wrote while a member counted when it was made: standing at the
        // row's own instant, within W, never "now".
        return dir
            .check_write_cohort_scope_for_at(
                &row.attesting_key_id,
                write_path,
                &row.cohort_scope,
                super::admission::envelope_cohort_target(&row.attestation_envelope)?,
                Some(row.asserted_at),
                Some(received_at),
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
    // v62.0.0 (LINEAGE-L6b (b)) — the v61 S2 "room stored under
    // founder_only" gates are DELETED: no such room can exist on a v62 node
    // (the edition upgrade deletes the earlier store, CC "nothing carries";
    // every edition-2 roster version, replicated or not, takes the record
    // door's Local branch, which refuses founder_only above the family;
    // the earlier-form replicated door is shut). A guard nothing reaches is
    // a comment (P/LINEAGE-L6b-b.md: the producer grep).
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
            // v62.0.0 (KR-fix30) — the proposer's standing at the
            // proposal's own instant.
            dir.check_write_cohort_scope_for_at(
                &row.attesting_key_id,
                write_path,
                &row.cohort_scope,
                Some(&group),
                Some(row.asserted_at),
                Some(received_at),
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
/// grant's grantee (named in `refs.answers`, KR-fix32), and is signed FOR the
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
    // ACCEPT-tokens (CC 3.1.2.1, each "concludes nothing": kept, held, never
    // refused) — the text's own token for each way an acceptance fails to
    // give the grantee's consent, one per case, in this order.
    if !super::admission::is_counted_root_grant_row(&grant) {
        return Err(fold::hold(
            reason::ACCEPTANCE_OTHER_GRANT,
            refuse(ROOT_GRANT_GROUP, member, RULE_ACCEPTANCE_OTHER_GRANT),
        ));
    }
    if member != grant.attested_key_id {
        return Err(fold::hold(
            reason::ACCEPTANCE_OTHER_GRANTEE,
            refuse(ROOT_GRANT_GROUP, member, RULE_ACCEPTANCE_OTHER_GRANTEE),
        ));
    }
    // KR-fix5 — the signing key's OWN identity, never lifted to its owner: a
    // bound worker node's signature is not its owner's consent.
    if row.attesting_key_id == grant.attested_key_id {
        return Err(fold::hold(
            reason::ACCEPTANCE_BY_GRANTEE,
            refuse(ROOT_GRANT_GROUP, member, RULE_ACCEPTANCE_BY_GRANTEE),
        ));
    }
    if !super::admission::signs_for_root_grantee(
        dir,
        &row.attesting_key_id,
        &grant.attested_key_id,
        row.asserted_at,
    )
    .await?
    {
        return Err(fold::hold(
            reason::ACCEPTANCE_NOT_BY_OWNER,
            refuse(ROOT_GRANT_GROUP, member, RULE_ACCEPTANCE_NOT_BY_OWNER),
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

/// v62.0.0 (KR-fix2, KR-fix18; CC 3.2, CC 2.4.1.1: a conferral is TWO
/// consents, the holders' counted grant and the grantee's separate
/// acceptance; "either may be taken back by the one who gave it, alone, and
/// the conferral holds only while both stand") — **the grantee's consent to
/// the counted root grant `grant`, as it stands at `t`: the acceptance row
/// that gives it, or `None`.**
///
/// An acceptance gives the consent when it is a held federation-tier
/// `membership:acceptance:v1` at the federation scope
/// ([`is_root_grant_reply`]), attested to the grantee, naming the grant,
/// signed FOR the grantee (its person, or a machine grantee's owner at the
/// acceptance's own instant: `admission::signs_for_root_grantee`), asserted
/// by `t`, and NOT WITHDRAWN BY ITS OWN SIGNER by `t`
/// ([`acceptance_withdrawn_by`]). No decline of the grant by `t`. KR-fix28:
/// for a machine grantee, the owner binding in force at the acceptance's
/// instant is the one in force at `t` (`admission::machine_owner_binding_at`):
/// after a re-binding the grant confers again only once the new owner
/// accepts it.
///
/// - **From then on.** A withdrawal counts from its own signed
///   `asserted_at`: read at an instant before it, the acceptance still
///   stands, so an act taken under the grant before the withdrawal verifies
///   as of its own instant.
/// - **A re-acceptance confers again.** A later acceptance of the same
///   standing grant is its own row; the withdrawal of an earlier one does
///   not reach it.
/// - **The grant is not touched.** It is the holders' act (rule 0); it
///   stands as history after the grantee has left.
///
/// # Errors
/// Directory reads.
pub async fn root_grant_acceptance_at<F>(
    dir: &F,
    grant: &Attestation,
    t: chrono::DateTime<chrono::Utc>,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    root_grant_acceptance_for(dir, grant, t, None).await
}

/// v62.0.0 (HEAD-4.rev3; KR-fix28's marked move, CC 2.4.1.1 "an act names
/// its head") — [`root_grant_acceptance_at`] for an ACT IN HAND: `act_head`
/// is the act's `refs.head`. For a machine grantee, a node's or agent's act
/// names its owner-binding row (`edition2::head_rule`), so the acceptance
/// stands for the act exactly when that binding row is among the bindings in
/// force at the acceptance's own instant: "the binding an act names" is read
/// from the act, not from the binding in force at its instant. `None` (no
/// act in hand: the grant listing, `admission::root_grants_for`; or an act
/// naming no head) keeps the instant form below.
///
/// # Errors
/// Directory reads.
pub async fn root_grant_acceptance_for<F>(
    dir: &F,
    grant: &Attestation,
    t: chrono::DateTime<chrono::Utc>,
    act_head: Option<&crate::federation::edition2::names::RowId>,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let grantee = grant.attested_key_id.as_str();
    let held = replies_of(dir, grantee).await?;
    let replies: Vec<&Attestation> = replies_to(&held, &grant.attestation_id)
        .into_iter()
        .filter(|r| r.asserted_at <= t && is_root_grant_reply(r))
        .collect();
    // v62.0.0 (KR-fix28; CC 3.2, as the Constitution ruled 2026-11-22) — a
    // machine grantee's acceptance is its owner's consent AS BOUND AT THE
    // ACCEPTANCE'S OWN INSTANT, and it stands only for acts under THAT
    // binding: a re-binding is a new owner-binding row, rows under it stand
    // on the new owner, who has consented to nothing until they accept the
    // grant themselves (the old owner's acceptance does not carry over, and
    // the old owner cannot withdraw or renew on the new owner's behalf).
    // v62.0.0 (HEAD-4.rev3) — "the binding an act names" is the act's
    // `refs.head` when the act is in hand (`act_head`); with no act in hand,
    // the binding in force at `t`.
    let binding_at_t = super::admission::machine_owner_binding_at(dir, grantee, t).await?;
    let names_the_binding = |at_acceptance: &super::admission::MachineOwner| match act_head {
        Some(h) => match at_acceptance {
            super::admission::MachineOwner::Bound { bindings, .. } => {
                bindings.iter().any(|b| *b == h.hex())
            }
            super::admission::MachineOwner::NotAMachine => true,
            super::admission::MachineOwner::Unbound => false,
        },
        None => *at_acceptance == binding_at_t,
    };
    if replies
        .iter()
        .any(|r| membership_row(r) == Some(MembershipRow::Decline))
    {
        return Ok(None);
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
            && names_the_binding(
                &super::admission::machine_owner_binding_at(dir, grantee, r.asserted_at).await?,
            )
            && !acceptance_withdrawn_by(dir, r, t).await?
        {
            return Ok(Some(r.attestation_id.clone()));
        }
    }
    Ok(None)
}

/// v62.0.0 (KR-fix18) — **is `row` the acceptance of a counted grant from
/// the root?** A federation-tier `membership:acceptance:v1` at the federation
/// scope whose `references_attestation_id` names a held counted root grant
/// (`admission::is_counted_root_grant_row`) attested to the same grantee.
///
/// # Errors
/// Directory reads.
pub async fn is_root_grant_acceptance<F>(dir: &F, row: &Attestation) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if row.tier != attestation_tier::FEDERATION
        || !is_root_grant_reply(row)
        || membership_row(row) != Some(MembershipRow::Acceptance)
    {
        return Ok(false);
    }
    let Some(grant_id) = env_str(row, "references_attestation_id") else {
        return Ok(false);
    };
    Ok(dir.get_attestation(grant_id).await?.is_some_and(|g| {
        super::admission::is_counted_root_grant_row(&g) && g.attested_key_id == row.attested_key_id
    }))
}

/// v62.0.0 (KR-fix18; CC 2.4.1.1 rule 1) — **has the signer of `acceptance`
/// taken it back by `t`?** A held `withdraws` naming the acceptance, signed
/// by the same consenting party ([`same_consenting_party`]: the same key, or
/// another key of the same person; never a node for its owner), whose own
/// signed `asserted_at` is at or before `t`. The door admits such a
/// withdrawal as the producer's own retraction (rule 1).
///
/// # Errors
/// Directory reads.
pub async fn acceptance_withdrawn_by<F>(
    dir: &F,
    acceptance: &Attestation,
    t: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    for w in dir
        .list_attestations_referencing(&acceptance.attestation_id)
        .await?
    {
        if w.attestation_type == attestation_type::WITHDRAWS
            && w.asserted_at <= t
            && same_consenting_party(dir, &w.attesting_key_id, &acceptance.attesting_key_id).await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// v62.0.0 (KR-fix2) — **has the grantee of the counted root grant `grant`
/// consented, as of `t`?** [`root_grant_acceptance_at`] names the acceptance.
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
    Ok(root_grant_acceptance_at(dir, grant, t).await?.is_some())
}

/// v62.0.0 (wave V1b; CC 4.4.3.12) — **a reply to a counted officer
/// appointment**: signed for the officer (the appointment's attested key, by
/// person), attested to it, about the affiliation the appointment names,
/// naming the appointment in `refs.answers` (KR-fix32); never both an acceptance and a
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
    if signer != officer || member != appointment.attested_key_id || names != Some(group) {
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
/// member of an `infrastructure` community is seated by the founders' quorum";
/// CC 4.4.3.19: in an infrastructure room a node "gives NO acceptance: seated
/// by the founders' count alone, for the canonical room with the bundle's
/// conferral").
///
/// The ONE predicate both the growth gate and the founding rule read: `member`
/// needs no acceptance in `community` at `at` iff the community is
/// `infrastructure`, the key is node-bearing at `at` (#925's predicate), and
///
/// - v62.0.0 (KR-fix23) — the community is any infrastructure room but the
///   canonical one: nothing more (the founders' count seats it);
/// - the community is THE CANONICAL room
///   ([`CIRIS_CANONICAL_COMMUNITY_KEY_ID`](super::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID)):
///   the bundle's conferral, which on v62 is a serve SEAT of the genesis
///   bundle in force (KR-fix13). (The earlier co-scrub on the node's own key
///   record is gone, KR-fix27.)
///
/// The founders' quorum is the caller's roster-authority check and is not
/// weakened here. A person in the same community, and a node in any room
/// that is not `infrastructure`, still needs what they needed (CC 4.4.3.19:
/// there a node is never a member; its owner is).
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
    // v62.0.0 (KR-fix23; CC 4.4.3.19, the text as written: "seated by the
    // founders' count alone") — in an infrastructure room that is not the
    // canonical one, a node is seated by the founders' count and nothing
    // else. (KR-fix13 asked every infrastructure room for the bundle's seat:
    // narrower than the text, so no other node could be seated without its
    // own voice, which KR-fix10 refuses.)
    if community.community_key_id != super::canonical_community::CIRIS_CANONICAL_COMMUNITY_KEY_ID {
        return Ok(true);
    }
    // v62.0.0 (KR-fix13; CC 3.1.3.2, CC 4.4.3.19: in an infrastructure room
    // a node "gives NO acceptance: seated by the founders' count alone, for
    // the canonical room with the bundle's conferral") — THE CONFERRAL ON
    // v62 IS THE BUNDLE'S SEAT. A canonical install is a serve seat of the
    // genesis bundle in force (`is_canonical_by_bundle`). The earlier
    // conferral (the accord's co-scrub on the node's own key record) is gone
    // (KR-fix27: an edition-2 key record carries no capability role; it
    // could never pass on v62), so before KR-fix13 NO node was ever seated
    // without its own voice, and after KR-fix10 a node's acceptance of a
    // named invitation is refused: a canonical install could not be added to
    // the room at all.
    super::edition2::genesis::is_canonical_by_bundle(dir, member).await
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

/// v62.0.0 (DUTY-D7a; CC 3.2 "the owner's acceptance": "It names in
/// refs.also.cites the owner-binding it is made under"; Constitution's Q2
/// ruling 11-24) — **the owner binding a root grant's acceptance cites**, for
/// the grant's grantee `grantee`:
///
/// - a person (no `node` / `agent` record): `None` (a person's acceptance
///   cites nothing);
/// - `explicit` (the caller names the row, `owner_binding_ref`): that row,
///   when it is a held owner binding over `grantee` (the caller's stated
///   choice of placement);
/// - else EXACTLY ONE row, the binding placed where the acceptance is placed:
///   a live owner binding over `grantee` at `cohort_scope: federation`. One
///   owner's re-signed rows are one ownership, so where the one owner holds
///   several federation rows the lowest row id is cited (deterministic on
///   every node).
///
/// # Errors
/// `InvalidArgument`: a machine grantee with no federation-placed binding
/// and no `explicit` row (an unannounced machine: name the row to cite), or
/// an `explicit` row that is no held owner binding over `grantee`; directory
/// reads.
pub async fn root_grant_acceptance_cites<F>(
    dir: &F,
    grantee: &str,
    explicit: Option<&str>,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::admission::{machine_owner_binding_at, owner_binding_marker, MachineOwner};
    if let Some(id) = explicit {
        let row = dir.get_attestation(id).await?;
        let ok = row.as_ref().is_some_and(|r| {
            r.attestation_type == attestation_type::DELEGATES_TO
                && r.attested_key_id == grantee
                && owner_binding_marker(&r.attestation_envelope)
        });
        if !ok {
            return Err(Error::InvalidArgument(format!(
                "root grant acceptance: {id} is no held owner binding over {grantee} \
                 (CC 3.2: the acceptance cites the owner-binding it is made under)"
            )));
        }
        return Ok(Some(id.to_owned()));
    }
    let bindings = match machine_owner_binding_at(dir, grantee, crate::host::clock::now()).await? {
        MachineOwner::NotAMachine => return Ok(None),
        MachineOwner::Unbound => Vec::new(),
        MachineOwner::Bound { bindings, .. } => bindings,
    };
    let mut federation = Vec::new();
    for id in bindings {
        if let Some(r) = dir.get_attestation(&id).await? {
            if r.cohort_scope == cohort_scope::FEDERATION {
                federation.push(id);
            }
        }
    }
    federation.sort();
    federation.into_iter().next().map(Some).ok_or_else(|| {
        Error::InvalidArgument(format!(
            "root grant acceptance: {grantee} is a machine with no federation-placed owner \
             binding, so an acceptance at federation has none to cite (CC 3.2, the Q2 ruling): \
             announce the binding, or name the row to cite ({})",
            super::edition2::payloads::OWNER_BINDING_REF_MEMBER
        ))
    })
}

/// v62.0.0 (DUTY-D7a) — [`reply_input`] for a counted root grant, with the
/// acceptance's `owner_binding_ref` (stated as `refs.also.cites`) filled by
/// [`root_grant_acceptance_cites`]. A decline, and any reply that is not to a
/// counted root grant, is [`reply_input`] unchanged.
///
/// # Errors
/// As [`root_grant_acceptance_cites`].
pub async fn root_grant_reply_input<F>(
    dir: &F,
    grant: &Attestation,
    accept: bool,
    explicit_binding: Option<&str>,
) -> Result<super::types::EmitAttestationInput, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut input = reply_input(grant, accept);
    if accept && super::admission::is_counted_root_grant_row(grant) {
        if let Some(cite) =
            root_grant_acceptance_cites(dir, &grant.attested_key_id, explicit_binding).await?
        {
            input.attestation_envelope.extra.insert(
                super::edition2::payloads::OWNER_BINDING_REF_MEMBER.to_owned(),
                serde_json::Value::String(cite),
            );
        }
    }
    Ok(input)
}

/// v62.0.0 (KR-fix6) — **a reply's envelope, for a signer whose pen is
/// elsewhere** (a hardware-held owner): exactly the members
/// [`reply_input`] gives the software producer (`dimension`,
/// `references_attestation_id` (stated as `refs.answers`), the group's members for a
/// group reply) plus the `cohort_scope` the producer states. Hand it to
/// `Engine::statement_draft("scores", &envelope, signer_iss, signer_kid_hex,
/// sub, asserted_at_ms, None)`, with `sub` = the proposal's
/// `attested_key_id` for a root grant; sign the draft; `submit_voice`. Both
/// paths then state the reply through `emit::row_payload`.
///
/// v62.0.0 (DUTY-D7a2; the Q2 ruling) — takes the reply's INPUT
/// ([`root_grant_reply_input`], which fills a root grant's cite, or
/// [`reply_input`]), so a hardware-pen draft states exactly what the software
/// producer states. `machine_grantee`: the grant's grantee is a `node` /
/// `agent` key (the caller read it; this draft holds no directory).
///
/// # Errors
/// `InvalidArgument` (no token): an acceptance of a counted root grant for a
/// MACHINE grantee whose input carries no cite (`owner_binding_ref`). Such a
/// row would land and confer nothing anywhere: draft it through
/// [`root_grant_reply_input`], or name the row.
pub fn reply_envelope(
    input: &super::types::EmitAttestationInput,
    machine_grantee: bool,
) -> Result<serde_json::Value, Error> {
    let root_grant_acceptance = input.attestation_envelope.dimension.as_deref()
        == Some(ACCEPTANCE_DIMENSION)
        && input.cohort_scope == cohort_scope::FEDERATION;
    if machine_grantee
        && root_grant_acceptance
        && !input
            .attestation_envelope
            .extra
            .contains_key(super::edition2::payloads::OWNER_BINDING_REF_MEMBER)
    {
        return Err(Error::InvalidArgument(format!(
            "reply_envelope: an acceptance of a root grant for a machine grantee cites the \
             owner binding it is made under (CC 3.2); this input names none \
             ({}): draft it through root_grant_reply_input",
            super::edition2::payloads::OWNER_BINDING_REF_MEMBER
        )));
    }
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
    Ok(envelope)
}

/// The emit input for K's reply (acceptance or decline) to `proposal`.
#[must_use]
pub fn reply_input(proposal: &Attestation, accept: bool) -> super::types::EmitAttestationInput {
    // v62.0.0 (KR-fix2; CC 3.2 as ruled 2026-11-21) — a reply to a counted
    // grant from the root: placed at the federation scope, naming no group
    // (the root is the accord of the bundle the grant names), attested to the
    // grantee, naming the grant by its row id (`refs.answers`, KR-fix32:
    // no `proposal_hash`, the row id IS the digest of the grant's payload)
    // ([`check_root_grant_reply`]). The signer must be the grantee's
    // consenter: for a `node` or `agent` grantee, its owner.
    if super::admission::is_counted_root_grant_row(proposal) {
        let extra = serde_json::Map::new();
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
    // v62.0.0 (KR-fix32) — no `proposal_hash`: the reply names the
    // proposal by its row id (`refs.answers`), the digest of its payload.
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
