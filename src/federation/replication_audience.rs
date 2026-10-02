//! v53.0.0 (CIRISPersist#963 / CIRISEdge#761, CC 3.3.7 / 5.4.6 / 6.1.5.3) —
//! **one audience resolver.**
//!
//! Every door that asks "may this node hold, receive or be sent this row"
//! answers through here, so the sender's set, the receiver's hold decision and
//! edge's serve gate cannot answer differently (the Live-filter-vs-door class).
//!
//! # The per-node allow list (operator ruling 2026-10-02, CC 3.3.7)
//!
//! A node is in a cohort's audience only through its OWNER's claim, and the
//! owner chooses, per node, which of their cohorts reach it ("don't replicate
//! adulthub content onto my work laptop"). The allow list is not a new row: it
//! is the optional `cohorts` member of the owner's `consent:replication` grant
//! FOR that node ([`ConsentTransferPolicy::cohorts`](super::consent_grammar::ConsentTransferPolicy::cohorts)).
//! A denied node is simply absent from the cohort's audience — a missing
//! grant, never an "excluded" state.
//!
//! With no `cohorts` member the node's CLASS decides, read from the
//! `device_class` of the node's identity occurrence for that owner (the
//! owner's own signed statement about the device — never the key record):
//!
//! | class | `device_class` | self | family | community / affiliations |
//! |---|---|---|---|---|
//! | personal | `phone` \| `laptop` | yes | yes | yes |
//! | server | `server` \| `embedded` \| `service` \| `agent` | no | no | yes |
//!
//! CC 3.3.7: "a server or infrastructure node receives no `self` or `family`
//! content unless the list names it". A list, when present, is exact for the
//! group scopes; `self` is never listed and always follows the class. A node
//! with no live occurrence for the owner is not one of the owner's devices and
//! receives none of the owner's content. The origin and refers-to arms
//! ([`may_receive`]) hold whatever the list says.
//!
//! # Public groups (CIRISEdge#761, CC 5.4.6)
//!
//! [`is_public_group`]: `infrastructure` communities (authority-gated), the
//! accord family, conferring families (a live `trust:charter:v1`) and the
//! deployment's WA family. Their records and membership planes reach every
//! peer; a private group's go only to [`may_receive_group_plane`]'s set.

use std::collections::{BTreeSet, HashSet};

use super::consent_grammar::{parse_grant_payload, CohortEntry, GRANT_DIMENSION};
use super::types::cohort_scope as cs;
use super::types::device_class;
use super::{Attestation, Error, FederationDirectory};

/// The class of a node AS ITS OWNER DECLARED IT (CC 3.3.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeClass {
    /// `phone` | `laptop`: by default every cohort its owner is in.
    Personal,
    /// `server` | `embedded` | `service` | `agent`: by default no `self` or
    /// `family` content.
    Server,
}

impl NodeClass {
    /// The class of a `device_class` token; `None` outside the closed set
    /// (fail closed: an unknown class is not one of the owner's devices).
    #[must_use]
    pub fn of_device_class(dc: &str) -> Option<Self> {
        match dc {
            device_class::PHONE | device_class::LAPTOP => Some(Self::Personal),
            device_class::SERVER
            | device_class::EMBEDDED
            | device_class::SERVICE
            | device_class::AGENT => Some(Self::Server),
            _ => None,
        }
    }
}

/// Which of an owner's content a decision is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerCohort<'a> {
    /// The owner's own `self` content.
    SelfContent,
    /// A group the owner is in: `scope` ∈ `family` | `community` |
    /// `affiliations`, `target` the group's key id.
    Group {
        /// The group's placement scope.
        scope: &'a str,
        /// The group's key id.
        target: &'a str,
    },
}

/// **The decision, pure.** `list` is the owner's allow list for the node
/// (`None` = no `cohorts` member on any live grant: the class default).
#[must_use]
pub fn class_allows(
    class: NodeClass,
    list: Option<&BTreeSet<CohortEntry>>,
    cohort: OwnerCohort<'_>,
) -> bool {
    match cohort {
        // `self` is never listed: it follows the class.
        OwnerCohort::SelfContent => class == NodeClass::Personal,
        OwnerCohort::Group { scope, target } => match list {
            Some(l) => l.contains(&CohortEntry {
                scope: scope.to_owned(),
                target: target.to_owned(),
            }),
            None => match class {
                NodeClass::Personal => true,
                NodeClass::Server => scope != cs::FAMILY,
            },
        },
    }
}

/// The class `owner` declared for `node`: the `device_class` of the newest
/// ACTIVE occurrence binding `(owner, node)` that resolves (the occurrence's
/// consent or this node's own trust — the #932 rule, through
/// `active_identities_for_occurrence`). `None` when the node is not one of
/// the owner's devices.
pub async fn owner_node_class<D>(
    dir: &D,
    owner: &str,
    node: &str,
) -> Result<Option<NodeClass>, Error>
where
    D: FederationDirectory + ?Sized,
{
    if owner == node {
        return Ok(None);
    }
    if !dir
        .active_identities_for_occurrence(node)
        .await?
        .iter()
        .any(|p| p == owner)
    {
        return Ok(None);
    }
    Ok(dir
        .list_identity_occurrences_active(owner)
        .await?
        .into_iter()
        .filter(|o| o.occurrence_key_id == node)
        .max_by_key(|o| o.asserted_at)
        .and_then(|o| NodeClass::of_device_class(&o.device_class)))
}

/// The owner's allow list for `node`: the `cohorts` member of `owner`'s LIVE
/// `consent:replication` grants FOR `node` (authored by `owner`, `for_key_id`
/// = `node`, unexpired, not retired by a `withdraws` / `recants` /
/// `supersedes` of the owner's). `None` when no live grant carries the
/// member. When several do, their lists INTERSECT: any live narrowing holds
/// until the owner retires it (editing the list is a `supersedes`, CC 3.3.7),
/// so the answer never widens past a list the owner still stands behind.
pub async fn owner_allow_list<D>(
    dir: &D,
    owner: &str,
    node: &str,
) -> Result<Option<BTreeSet<CohortEntry>>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let rows = dir.list_attestations_by(owner).await?;
    let retired: HashSet<&str> = rows
        .iter()
        .filter(|r| super::precedence::is_structural_composer(&r.attestation_type))
        .filter_map(|r| {
            super::precedence::references_attestation_id_from_envelope(&r.attestation_envelope)
        })
        .collect();
    let now = chrono::Utc::now();
    let mut acc: Option<BTreeSet<CohortEntry>> = None;
    for g in &rows {
        if g.attesting_key_id != owner
            || super::admission::envelope_dimension(&g.attestation_envelope)
                != Some(GRANT_DIMENSION)
            || super::consent_by_humans::for_key_id_of(&g.attestation_envelope) != Some(node)
            || retired.contains(g.attestation_id.as_str())
            || g.expires_at.is_some_and(|e| e <= now)
        {
            continue;
        }
        // A grant that does not parse was refused at admission; one held from
        // before the grammar is no allow list (fail toward the default, which
        // the class already bounds).
        let Ok(policy) = parse_grant_payload(&g.attestation_envelope) else {
            continue;
        };
        if policy.valid_until.is_some_and(|v| v <= now) {
            continue;
        }
        if let Some(list) = policy.cohorts {
            let set: BTreeSet<CohortEntry> = list.into_iter().collect();
            acc = Some(match acc {
                None => set,
                Some(prev) => prev.intersection(&set).cloned().collect(),
            });
        }
    }
    Ok(acc)
}

/// **Does `owner`'s `cohort` reach `node`?** [`class_allows`] over
/// [`owner_node_class`] and [`owner_allow_list`]; `false` when the node is not
/// one of the owner's devices.
pub async fn owner_node_receives<D>(
    dir: &D,
    owner: &str,
    node: &str,
    cohort: OwnerCohort<'_>,
) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    let Some(class) = owner_node_class(dir, owner, node).await? else {
        return Ok(false);
    };
    let list = owner_allow_list(dir, owner, node).await?;
    Ok(class_allows(class, list.as_ref(), cohort))
}

/// The nodes of `owner` that `cohort` reaches: the owner's ACTIVE occurrences
/// that resolve to the owner (#932) and pass [`owner_node_receives`]. Sorted.
pub async fn owner_nodes_receiving<D>(
    dir: &D,
    owner: &str,
    cohort: OwnerCohort<'_>,
) -> Result<Vec<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut nodes: BTreeSet<String> = BTreeSet::new();
    for o in dir.list_identity_occurrences_active(owner).await? {
        if o.occurrence_key_id != owner {
            nodes.insert(o.occurrence_key_id);
        }
    }
    let mut out = Vec::new();
    for n in nodes {
        if owner_node_receives(dir, owner, &n, cohort).await? {
            out.push(n);
        }
    }
    Ok(out)
}

/// **Is `group` a public group** (CC 5.4.6 / 4.4.3.2.1, CIRISEdge#761)? An
/// authority-gated `infrastructure` community, the accord family, a family
/// holding a live `trust:charter:v1` (a conferring family), or the
/// deployment's WA family (`ReclaimPolicy::WA_FAMILY_ENV`). Config- and
/// state-derived ids only; never a name match.
pub async fn is_public_group<D>(dir: &D, group: &str) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    if group == super::canonical_community::accord_family_key_id() {
        return Ok(true);
    }
    if super::ownership_reclaim::ReclaimPolicy::from_deployment_pin()
        .is_some_and(|p| p.wa_family_key_id == group)
    {
        return Ok(true);
    }
    match dir.lookup_community(group).await {
        Ok(Some(c)) => {
            if super::admission::is_authorized_infrastructure_community(dir, &c).await? {
                return Ok(true);
            }
        }
        Ok(None) | Err(Error::Unsupported { .. }) => {}
        Err(e) => return Err(e),
    }
    let about = dir.list_attestations_for(group).await?;
    let refs: Vec<&Attestation> = about.iter().collect();
    let dead = super::precedence::retired_ids(&refs);
    Ok(about.iter().any(|a| {
        a.attestation_type == super::types::attestation_type::DELEGATES_TO
            && a.attested_key_id == group
            && !dead.contains(&a.attestation_id)
            && super::admission::envelope_dimension(&a.attestation_envelope)
                == Some(super::trust_root::TRUST_CHARTER_DIMENSION)
    }))
}

/// Who a placed row's content reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    /// The commons, or a public group: every peer.
    Everyone,
    /// Exactly these nodes (possibly none).
    Nodes(BTreeSet<String>),
}

impl Audience {
    /// Does the audience contain `node`?
    #[must_use]
    pub fn contains(&self, node: &str) -> bool {
        match self {
            Self::Everyone => true,
            Self::Nodes(n) => n.contains(node),
        }
    }
}

/// **The audience of content placed at `cohort_scope` / `target`.**
///
/// - commons (`species` / `biosphere` / `federation`): [`Audience::Everyone`];
/// - `self` (`target` = the owner): the owner's nodes the class lets `self`
///   reach;
/// - `family` / `community` / `affiliations`: a public group reaches
///   everyone; else, per ACTIVE member, the member's nodes that member's
///   allow list lets the group reach, plus a member key that is itself a node
///   (a node's own membership is its own and no owner's list governs it);
/// - outside the closed set, or a targeted scope with no target: no nodes.
pub async fn audience_nodes<D>(
    dir: &D,
    cohort_scope: &str,
    target: Option<&str>,
) -> Result<Audience, Error>
where
    D: FederationDirectory + ?Sized,
{
    let Some(scope) = cs::Scope::parse(cohort_scope) else {
        return Ok(Audience::Nodes(BTreeSet::new()));
    };
    let Some(target) = target.filter(|t| !t.is_empty()) else {
        return Ok(match scope.placement() {
            cs::Placement::Commons => Audience::Everyone,
            _ => Audience::Nodes(BTreeSet::new()),
        });
    };
    let members: Vec<String> = match scope.placement() {
        cs::Placement::Commons => return Ok(Audience::Everyone),
        cs::Placement::SelfCollective => {
            return Ok(Audience::Nodes(
                owner_nodes_receiving(dir, target, OwnerCohort::SelfContent)
                    .await?
                    .into_iter()
                    .collect(),
            ));
        }
        cs::Placement::Targeted(_) if is_public_group(dir, target).await? => {
            return Ok(Audience::Everyone);
        }
        cs::Placement::Targeted(cs::TargetPlane::Family) => {
            match dir.active_family_members(target).await {
                Ok(m) => m.into_iter().map(|m| m.key_id).collect(),
                Err(Error::InvalidArgument(_)) => Vec::new(),
                Err(e) => return Err(e),
            }
        }
        cs::Placement::Targeted(cs::TargetPlane::Room) => {
            match dir.active_community_members(target).await {
                Ok(m) => m.into_iter().map(|m| m.key_id).collect(),
                Err(Error::InvalidArgument(_)) => Vec::new(),
                Err(e) => return Err(e),
            }
        }
    };
    let cohort = OwnerCohort::Group {
        scope: cohort_scope,
        target,
    };
    let mut out = BTreeSet::new();
    for m in &members {
        if is_node_key(dir, m).await? {
            out.insert(m.clone());
        }
        out.extend(owner_nodes_receiving(dir, m, cohort).await?);
    }
    Ok(Audience::Nodes(out))
}

async fn is_node_key<D>(dir: &D, k: &str) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    Ok(dir.lookup_public_key(k).await?.is_some_and(|r| {
        super::types::identity_type::set_contains(
            &r.identity_type,
            super::types::identity_type::NODE,
        )
    }))
}

/// Why [`may_receive`] answered as it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The row originates on the recipient (it signed it).
    Origin,
    /// The row refers to the recipient (attested, a subject, or the grant's
    /// `for_key_id`) — remote administration works (CC 6.1.5.3).
    RefersTo,
    /// The commons or a public group.
    Public,
    /// The recipient is in the row's cohort audience.
    Cohort,
    /// None of the above.
    NotInAudience,
    /// The row's placement could not be read (a split-brain target).
    Malformed,
}

/// The verdict of [`may_receive`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The recipient may receive the row.
    Yes(Reason),
    /// It may not.
    No(Reason),
}

impl Verdict {
    /// `true` for [`Verdict::Yes`].
    #[must_use]
    pub fn allowed(self) -> bool {
        matches!(self, Self::Yes(_))
    }
}

/// **May `recipient` receive `row`?** The arms, in order:
/// 1. origin — the recipient signed it;
/// 2. refers-to — the recipient is the row's `attested_key_id`, one of its
///    `subject_key_ids`, or the `for_key_id` it is FOR (so a node receives
///    its own grant, config and revocations, and a sibling node does not);
/// 3. an owner's grant FOR another node goes no further (a node receives
///    only its own allow list);
/// 4. the commons, or a public group;
/// 5. the row's cohort [`audience_nodes`] contains the recipient;
/// 6. else no.
pub async fn may_receive<D>(dir: &D, recipient: &str, row: &Attestation) -> Result<Verdict, Error>
where
    D: FederationDirectory + ?Sized,
{
    if row.attesting_key_id == recipient {
        return Ok(Verdict::Yes(Reason::Origin));
    }
    if row.attested_key_id == recipient
        || row.subject_key_ids.iter().any(|s| s == recipient)
        || super::consent_by_humans::for_key_id_of(&row.attestation_envelope) == Some(recipient)
    {
        return Ok(Verdict::Yes(Reason::RefersTo));
    }
    // CC 6.1.5.3 — "a node receives only its own allowlist": an owner's
    // grant FOR another node reaches that node (refers-to, above) and its
    // author, never a sibling, whatever scope it is placed at.
    if super::admission::envelope_dimension(&row.attestation_envelope) == Some(GRANT_DIMENSION)
        && super::consent_by_humans::for_key_id_of(&row.attestation_envelope).is_some()
    {
        return Ok(Verdict::No(Reason::NotInAudience));
    }
    // `self` content is its author's principals': a person's row, or one a
    // node of theirs signed (CC 3.3.6 — the self-collective IS the person).
    if cs::Scope::parse(&row.cohort_scope).map(cs::Scope::placement)
        == Some(cs::Placement::SelfCollective)
    {
        for p in super::self_collective::principals_of(dir, &row.attesting_key_id).await? {
            if owner_node_receives(dir, &p, recipient, OwnerCohort::SelfContent).await? {
                return Ok(Verdict::Yes(Reason::Cohort));
            }
        }
        return Ok(Verdict::No(Reason::NotInAudience));
    }
    let target = match super::admission::envelope_cohort_target(&row.attestation_envelope) {
        Ok(t) => t,
        Err(_) => return Ok(Verdict::No(Reason::Malformed)),
    };
    match audience_nodes(dir, &row.cohort_scope, target).await? {
        Audience::Everyone => Ok(Verdict::Yes(Reason::Public)),
        a if a.contains(recipient) => Ok(Verdict::Yes(Reason::Cohort)),
        _ => Ok(Verdict::No(Reason::NotInAudience)),
    }
}

/// **The membership-plane audience of a group (CIRISEdge#761, CC 5.4.6).**
/// May `recipient` receive the group's record and its membership planes
/// (widenings, revocations, listings)?
/// - a public group: yes, every peer;
/// - the recipient is a member key, or a node of an active member: yes;
/// - the recipient is a node of a LIVE invitee: yes, with the group's FULL
///   plane history (the invitee's node judges the widening that seats it
///   against every prior event);
/// - the recipient is a node of `named` (the member a row names — for a
///   revocation, the removed member): yes;
/// - else no.
///
/// Node-of here is a principal binding (`active_identities_for_occurrence` or
/// the key itself), not the per-node content allow list: a group's roster is
/// not content, and a member's node must be able to judge it.
pub async fn may_receive_group_plane<D>(
    dir: &D,
    recipient: &str,
    scope: &str,
    group: &str,
    named: Option<&str>,
) -> Result<Verdict, Error>
where
    D: FederationDirectory + ?Sized,
{
    if is_public_group(dir, group).await? {
        return Ok(Verdict::Yes(Reason::Public));
    }
    let mut principals: HashSet<String> = dir
        .active_identities_for_occurrence(recipient)
        .await?
        .into_iter()
        .collect();
    principals.insert(recipient.to_owned());
    if named.is_some_and(|n| principals.contains(n)) {
        return Ok(Verdict::Yes(Reason::RefersTo));
    }
    let members: Vec<String> = if scope == cs::FAMILY {
        match dir.active_family_members(group).await {
            Ok(m) => m.into_iter().map(|m| m.key_id).collect(),
            Err(Error::InvalidArgument(_)) => Vec::new(),
            Err(e) => return Err(e),
        }
    } else {
        match dir.active_community_members(group).await {
            Ok(m) => m.into_iter().map(|m| m.key_id).collect(),
            Err(Error::InvalidArgument(_)) => Vec::new(),
            Err(e) => return Err(e),
        }
    };
    if members.iter().any(|m| principals.contains(m)) {
        return Ok(Verdict::Yes(Reason::Cohort));
    }
    let invitees =
        super::membership_acceptance::live_invitees_of(dir, scope, group, &members).await?;
    if invitees.iter().any(|i| principals.contains(i)) {
        return Ok(Verdict::Yes(Reason::Cohort));
    }
    Ok(Verdict::No(Reason::NotInAudience))
}
