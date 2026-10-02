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

use super::types::{attestation_tier, attestation_type, cohort_scope};
use super::{Attestation, Error, FederationDirectory};

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

/// The two retryable rules: rows arrive out of order and persist holds no
/// deferral queue, so the caller re-submits.
#[must_use]
pub fn is_retryable_rule(rule: &str) -> bool {
    rule == RULE_ACCEPTANCE_UNRESOLVED || rule == RULE_PROPOSAL_UNRESOLVED
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

fn group_kind_for_scope(scope: &str) -> Option<&'static str> {
    match scope {
        cohort_scope::FAMILY => Some("family"),
        cohort_scope::COMMUNITY => Some("community"),
        _ => None,
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
    group_of(row)?;
    env_role(row)?;
    match kind {
        MembershipRow::Proposal => {
            if row.subject_key_ids.len() != 1 {
                return Err(Error::InvalidArgument(format!(
                    "{PROPOSAL_DIMENSION}: names exactly one invitee in subject_key_ids, got {}",
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
struct Proposal {
    row: Attestation,
    group: String,
    invitee: String,
    role: Option<String>,
    expires_at: chrono::DateTime<chrono::Utc>,
}

fn as_proposal(row: Attestation) -> Option<Proposal> {
    if membership_row(&row) != Some(MembershipRow::Proposal) {
        return None;
    }
    let group = group_of(&row).ok()?;
    let invitee = row.subject_key_ids.first()?.clone();
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
        && reply.cohort_scope == p.row.cohort_scope
        && env_str(reply, "proposal_hash") == Some(p.row.original_content_hash.as_str())
        && reply.attested_key_id == p.invitee
        && (membership_row(reply) != Some(MembershipRow::Acceptance)
            || env_role(reply).ok().flatten() == p.role)
}

async fn proposal_withdrawn<F>(dir: &F, p: &Proposal) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let proposer =
        super::admission::admission_identity_for_writer(dir, &p.row.attesting_key_id).await?;
    for w in dir
        .list_attestations_referencing(&p.row.attestation_id)
        .await?
    {
        if w.attestation_type == attestation_type::WITHDRAWS
            && super::admission::admission_identity_for_writer(dir, &w.attesting_key_id).await?
                == proposer
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Every federation-tier reply by `member` held here.
async fn replies_of<F>(dir: &F, member: &str) -> Result<Vec<Attestation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(dir
        .list_attestations_for(member)
        .await?
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

fn replies_to<'a>(replies: &'a [Attestation], proposal_id: &str) -> Vec<&'a Attestation> {
    replies
        .iter()
        .filter(|r| env_str(r, "references_attestation_id") == Some(proposal_id))
        .collect()
}

async fn group_is_held<F>(dir: &F, scope: &str, group: &str) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(match scope {
        cohort_scope::FAMILY => dir.lookup_family(group).await?.is_some(),
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
    let group = group_of(row)?;
    // v52.0.0 (#956) — no invitation to, or reply about, a dissolved family.
    if row.cohort_scope == cohort_scope::FAMILY {
        super::family_dissolution::refuse_if_held_family_dissolved(dir, &group).await?;
    }
    match kind {
        MembershipRow::Proposal => {
            if !group_is_held(dir, &row.cohort_scope, &group).await? {
                return Ok(());
            }
            dir.check_write_cohort_scope_for(
                &row.attesting_key_id,
                write_path,
                &row.cohort_scope,
                Some(&group),
            )
            .await?;
            check_proposer_under_founder_only(dir, row, &group).await
        }
        MembershipRow::Acceptance | MembershipRow::Decline => {
            let member = row.attested_key_id.as_str();
            let proposal_id = env_str(row, "references_attestation_id").unwrap_or_default();
            let Some(p) = dir
                .get_attestation(proposal_id)
                .await?
                .filter(|p| p.tier == attestation_tier::FEDERATION)
                .and_then(as_proposal)
            else {
                return Err(refuse(&group, member, RULE_PROPOSAL_UNRESOLVED));
            };
            let signer =
                super::admission::admission_identity_for_writer(dir, &row.attesting_key_id).await?;
            let invitee = super::admission::admission_identity_for_writer(dir, &p.invitee).await?;
            if signer != invitee || !reply_matches(row, &p) {
                return Err(refuse(&group, member, RULE_ACCEPTANCE_MISMATCH));
            }
            let held = replies_of(dir, member).await?;
            let opposite = match kind {
                MembershipRow::Acceptance => MembershipRow::Decline,
                _ => MembershipRow::Acceptance,
            };
            if replies_to(&held, &p.row.attestation_id).iter().any(|r| {
                r.attestation_id != row.attestation_id && membership_row(r) == Some(opposite)
            }) {
                return Err(refuse(&group, member, RULE_REPLY_CONFLICT));
            }
            Ok(())
        }
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
    let proposer =
        super::admission::admission_identity_for_writer(dir, &row.attesting_key_id).await?;
    let founder = Some(super::admission::MEMBER_ROLE_FOUNDER);
    let ok = if row.cohort_scope == cohort_scope::FAMILY {
        let Some(f) = dir.lookup_family(group).await? else {
            return Ok(());
        };
        f.consensus_protocol != super::types::consensus_protocol::FOUNDER_ONLY
            || dir
                .active_family_members(group)
                .await?
                .iter()
                .any(|m| m.key_id == proposer && m.role.as_deref() == founder)
    } else {
        let Some(c) = dir.lookup_community(group).await? else {
            return Ok(());
        };
        c.consensus_protocol != super::types::consensus_protocol::FOUNDER_ONLY
            || dir
                .active_community_members(group)
                .await?
                .iter()
                .any(|m| m.key_id == proposer && m.role.as_deref() == founder)
    };
    if ok {
        Ok(())
    } else {
        Err(Error::InvalidArgument(format!(
            "{PROPOSAL_DIMENSION}: under founder_only only a founder of {group} proposes"
        )))
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
/// is the caller's roster-authority check and is not weakened here. The owner
/// binding is NOT read: it is `self`-scope on the node and no other node can
/// see it; the claim is enforced where the node operates. A person in the
/// same community, and a node anywhere else, still needs what they needed.
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
    // #972 — a node of an infrastructure community is seated by the founders'
    // quorum (the caller's standing check, already passed) and gives no
    // acceptance.
    if scope == cohort_scope::COMMUNITY {
        if let Some(c) = dir.lookup_community(group).await? {
            if node_seated_without_acceptance(dir, &c, member, growth_instant).await? {
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
        if a.cohort_scope != scope || group_of(a).ok().as_deref() != Some(group) {
            continue;
        }
        let pid = env_str(a, "references_attestation_id").unwrap_or_default();
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
        if a.asserted_at > p.expires_at
            || growth_instant > p.expires_at
            || proposal_withdrawn(dir, &p).await?
        {
            note(RULE_PROPOSAL_EXPIRED);
            continue;
        }
        return Ok(());
    }
    // A member who only ever DECLINED an invitation to this group is refused
    // terminally, not "not held yet". Only when no acceptance for the group
    // exists: a decline of an older invitation must not turn a newer
    // acceptance whose proposal has not arrived into a terminal refusal.
    let in_group =
        |r: &&Attestation| r.cohort_scope == scope && group_of(r).ok().as_deref() == Some(group);
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
    Err(refuse(
        group,
        member,
        worst.unwrap_or(RULE_ACCEPTANCE_UNRESOLVED),
    ))
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
        signed.insert(super::admission::admission_identity_for_writer(dir, s).await?);
    }
    for m in members {
        if signed.contains(*m) {
            continue;
        }
        if signed.contains(&super::admission::admission_identity_for_writer(dir, m).await?) {
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
    match offered.iter().find(|m| !allowed.contains(**m)) {
        Some(m) => Err(refuse(group, m, RULE_SUPERSEDE_CANNOT_ADD)),
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
    let now = chrono::Utc::now();
    let mut signers: std::collections::BTreeSet<String> = members.iter().cloned().collect();
    for m in members {
        for o in dir.list_identity_occurrences_active(m).await? {
            signers.insert(o.occurrence_key_id);
        }
    }
    let mut out = std::collections::BTreeSet::new();
    for s in &signers {
        for row in dir.list_attestations_by(s).await? {
            if row.tier != attestation_tier::FEDERATION {
                continue;
            }
            let Some(p) = as_proposal(row) else {
                continue;
            };
            if p.row.cohort_scope != scope || p.group != group || p.expires_at <= now {
                continue;
            }
            if proposal_withdrawn(dir, &p).await? {
                continue;
            }
            let replies = replies_of(dir, &p.invitee).await?;
            let declined = replies_to(&replies, &p.row.attestation_id)
                .iter()
                .any(|r| membership_row(r) == Some(MembershipRow::Decline));
            if !declined {
                out.insert(p.invitee);
            }
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
    extra.insert(
        "role".into(),
        role.map_or(serde_json::Value::Null, Into::into),
    );
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

/// The emit input for K's reply (acceptance or decline) to `proposal`.
#[must_use]
pub fn reply_input(proposal: &Attestation, accept: bool) -> super::types::EmitAttestationInput {
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
    if accept {
        extra.insert(
            "role".into(),
            proposal
                .attestation_envelope
                .get("role")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        );
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
        sealed(
            proposer,
            proposer,
            scope,
            serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "dimension": PROPOSAL_DIMENSION,
                "group_kind": scope,
                target_key(scope): group,
                "role": role,
            }),
            at,
            Some(at + Duration::seconds(super::MEMBERSHIP_PROPOSAL_MAX_TTL_SECS)),
            vec![member.to_owned()],
        )
    }

    /// `member`'s acceptance of `p` at `at`, signed by `member`.
    #[must_use]
    pub fn acceptance_row(member: &str, p: &Attestation, at: DateTime<Utc>) -> Attestation {
        let scope = p.cohort_scope.clone();
        sealed(
            member,
            member,
            &scope,
            serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "dimension": ACCEPTANCE_DIMENSION,
                "group_kind": scope,
                target_key(&scope): p.attestation_envelope.get(target_key(&scope)).cloned(),
                "references_attestation_id": p.attestation_id,
                "proposal_hash": p.original_content_hash,
                "role": p.attestation_envelope.get("role").cloned(),
            }),
            at,
            None,
            vec![],
        )
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
            let scope = if cohort == crate::federation::Cohort::Family {
                cohort_scope::FAMILY
            } else {
                cohort_scope::COMMUNITY
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
