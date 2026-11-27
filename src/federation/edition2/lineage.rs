//! v62.0.0 (LINEAGE-L1; CC 2.7.8, CC 3.3.4 as settled 11-23) — **a group's
//! roster lineage.**
//!
//! CC 2.7.8: "A group's roster is a lineage. Each version names the heads it
//! extends and is counted over their members." CC 3.3.4 (the sentence added
//! 11-23): "A counted widening and a counted removal are each a version of
//! the roster's lineage (CC 2.7.8): each names the head it extends and is the
//! head for every row after it. A resignation is an end that names the head
//! it acts from and is no head itself, and the next counted version lists
//! that member out."
//!
//! So a NODE of a group's lineage is a concluded row of exactly these kinds
//! ([`is_head_row`], the ONE predicate every reader asks):
//!
//! - a `group:roster` version (it restates the record);
//! - a COUNTED `membership:{stage}` at leaf `widening` (it seats one member);
//! - a COUNTED `membership:{stage}` at leaf `removal` (it unseats one).
//!
//! A `membership:resignation` is never a node, nor is any other stage (a
//! proposal, an acceptance, a `keeps` row). A node's predecessors are the
//! heads it extends: `refs.head` and each of `refs.further_heads`. The
//! group's HEADS are its nodes that no other node of the group extends
//! ([`frontier`]).
//!
//! The node is written by the group door when the row LANDS
//! ([`record_landed`], `group::put_group_statement`). The group plane is
//! FINAL (`fold::GROUP_PLANE`): a landed row never un-concludes, so a node is
//! written once (idempotently) and never taken out. No purge path deletes
//! it, and the statement purge keeps a node's statement
//! (`purge_delete_tombstoned_statements`), so a lineage never loses a link.
//!
//! Stored in `ceg_group_lineage` / `ceg_group_lineage_extends` (V300,
//! PRE4-V300-b). The directory reads them through
//! [`FederationDirectory::group_lineage_nodes`]; its trait default
//! ([`derived_nodes`]) composes the same answer from routed reads, so a
//! directory with no table of its own (the capsule proxy) answers the same
//! nodes, slower.

use std::collections::{BTreeMap, BTreeSet};

use ciris_verify_core::cde::Value;
use ciris_verify_core::namespace_match;

use super::door::AdmittedRow;
use super::group::{
    FURTHER_HEADS_ROLE, GROUP_ROSTER_PREFIX, HEAD_ROLE, MEMBERSHIP_PREFIX, REMOVAL_LEAF,
    WIDENING_LEAF,
};
use super::liveness::statement_parts;
use super::names::{names_of, Name, RowId};
use crate::federation::group_plane::GroupKind;
use crate::federation::{Error, FederationDirectory};

/// What a lineage node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HeadOf {
    /// A `group:roster` version: the record restated.
    Roster,
    /// A counted `membership:widening`: one member seated.
    Widening,
    /// A counted `membership:removal`: one member unseated.
    Removal,
    /// v62.0.0 (LINEAGE-L1b; Constitution 11-23, "an open room's
    /// SELF-ADMISSION IS A HEAD") — a counted `membership:widening` in a
    /// group whose protocol at its base is `open:self_admit`, voiced by its
    /// member alone. The row alone does not say so ([`is_head_row`] reads it
    /// as a [`HeadOf::Widening`]); [`settle`] tells it apart from its voices
    /// and the protocol in force.
    SelfAdmission,
}

impl HeadOf {
    /// The stored spelling (`ceg_group_lineage.head_of`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Roster => "roster",
            Self::Widening => "widening",
            Self::Removal => "removal",
            Self::SelfAdmission => "self_admission",
        }
    }

    /// The kind a stored spelling names.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "roster" => Some(Self::Roster),
            "widening" => Some(Self::Widening),
            "removal" => Some(Self::Removal),
            "self_admission" => Some(Self::SelfAdmission),
            _ => None,
        }
    }
}

/// **THE predicate: is a row of `family_id` at `leaf` a node of its group's
/// lineage, and of which kind?** `counted`: the row names no `author`.
///
/// - `group:roster` → [`HeadOf::Roster`] (the roster door is its count);
/// - a counted `membership:{stage}` at `widening` / `removal` →
///   [`HeadOf::Widening`] / [`HeadOf::Removal`];
/// - everything else, a `membership:resignation` included (CC 3.3.4: "a
///   resignation is an end ... and is no head itself") → `None`.
///
/// Pure. Every reader of "which rows are heads" asks this one function.
#[must_use]
pub fn is_head_row(family_id: &str, leaf: Option<&str>, counted: bool) -> Option<HeadOf> {
    if family_id == namespace_match::family_id(GROUP_ROSTER_PREFIX) {
        return Some(HeadOf::Roster);
    }
    if family_id != namespace_match::family_id(MEMBERSHIP_PREFIX) || !counted {
        return None;
    }
    match leaf {
        Some(WIDENING_LEAF) => Some(HeadOf::Widening),
        Some(REMOVAL_LEAF) => Some(HeadOf::Removal),
        _ => None,
    }
}

/// One node of a group's lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageNode {
    /// The node's row id.
    pub row_id: RowId,
    /// Family or community.
    pub group_kind: GroupKind,
    /// The group's identity-ref.
    pub group: String,
    /// What the node is.
    pub head_of: HeadOf,
    /// The member a widening or removal is about; `None` on a roster version.
    pub subject: Option<String>,
    /// The heads it extends (`refs.head`, `refs.further_heads`), sorted, each
    /// once. Empty on a founding version.
    pub extends: Vec<RowId>,
    /// v62.0.0 (LINEAGE-L2) — the restating version this node's fold starts
    /// from (its nearest `group:roster` ancestor): the node itself on a
    /// roster version; on a widening or removal its predecessors' common
    /// base; `None` when their bases differ (a join over roster tips: the
    /// fold at a join is open with Kernel), and then a reader walks the
    /// predecessors ([`nearest_versions`]).
    pub base: Option<RowId>,
    /// v62.0.0 (LINEAGE-L1b) — the `consensus_protocol` in force AT this
    /// node: a roster version's own; a change's base's; `None` with no
    /// single base. Read by equality only (the strict fold, after the kernel
    /// pin).
    pub consensus_protocol: Option<String>,
    /// v62.0.0 (LINEAGE-L1b) — the policy in force AT this node, as the
    /// lowercase hex SHA-256 of the deterministic encoding of a roster
    /// version's `policy` member (`None` when it states none); a change
    /// carries its base's. Read by equality only.
    pub policy_digest: Option<String>,
    /// v62.0.0 (LINEAGE-L3e; Constitution: the entrenched flag is part of
    /// the protocol in force) — a family's `consensus_protocol_entrenched`
    /// at this node (a change carries its base's). `false` for a room, where
    /// the notion does not apply, and when the version states none.
    pub entrenched: bool,
}

impl LineageNode {
    /// v62.0.0 (LINEAGE-L3; for the kernel's coming `SeatRow::regime`) —
    /// **the regime in force at this node, as ONE comparable value**: the
    /// deterministic encoding of the array `[consensus_protocol, entrenched,
    /// policy_digest]` (each a text string; an absent policy is `null`).
    /// `None` when the node has no protocol (no single base). Both members
    /// are canonical when written: the protocol is the signed text as the
    /// roster version states it, and the policy digest is taken over the
    /// deterministic encoding of the `policy` value. So two heads under the
    /// same protocol and policy always compare equal, byte for byte. A
    /// v62.0.0 (LINEAGE-L3e) — `entrenched` (a bool) is in it, as
    /// Constitution ruled. A room's `membership` (private → public) is NOT
    /// (Kernel suggests it; Constitution has not ruled).
    #[must_use]
    pub fn regime(&self) -> Option<Vec<u8>> {
        let protocol = self.consensus_protocol.as_ref()?;
        let policy = self
            .policy_digest
            .as_ref()
            .map_or(Value::Null, |d| Value::Text(d.clone()));
        Some(ciris_verify_core::cde::encode(&Value::Array(vec![
            Value::Text(protocol.clone()),
            Value::Bool(self.entrenched),
            policy,
        ])))
    }
}

fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get_text(k).and_then(Value::as_text)
}

fn group_kind_of(payload: &Value) -> Option<GroupKind> {
    match text(payload, "group_kind")? {
        "family" => Some(GroupKind::Family),
        "community" => Some(GroupKind::Community),
        _ => None,
    }
}

fn extends_of(names: &[Name]) -> Vec<RowId> {
    let set: BTreeSet<RowId> = names
        .iter()
        .filter(|n| n.role == HEAD_ROLE || n.role == FURTHER_HEADS_ROLE)
        .map(|n| n.row)
        .collect();
    set.into_iter().collect()
}

/// The node a row is, from its own parts. `None` for a row the predicate
/// does not admit, a composer (it carries its target's family), and a
/// payload that does not name its group.
fn node_of_parts(
    row_id: RowId,
    row_type: &str,
    family: &str,
    sub: &str,
    author: Option<&str>,
    payload: &Value,
    names: &[Name],
) -> Option<LineageNode> {
    if super::emit::names_a_target(row_type) {
        return None;
    }
    let leaf = super::payloads::leaf_of(family, payload);
    let head_of = is_head_row(family, leaf, author.is_none())?;
    let group_kind = group_kind_of(payload)?;
    let (group, subject) = match head_of {
        HeadOf::Roster => (sub.to_owned(), None),
        HeadOf::Widening | HeadOf::Removal => (
            text(payload, "group")?.to_owned(),
            Some(text(payload, "member")?.to_owned()),
        ),
    };
    Some(LineageNode {
        row_id,
        group_kind,
        group,
        head_of,
        subject,
        extends: extends_of(names),
        base: (head_of == HeadOf::Roster).then_some(row_id),
        consensus_protocol: (head_of == HeadOf::Roster)
            .then(|| text(payload, "consensus_protocol").map(str::to_owned))
            .flatten(),
        policy_digest: (head_of == HeadOf::Roster)
            .then(|| payload.get_text("policy").map(policy_digest))
            .flatten(),
        entrenched: head_of == HeadOf::Roster
            && matches!(
                payload.get_text("consensus_protocol_entrenched"),
                Some(Value::Bool(true))
            ),
    })
}

/// The `policy_digest` of a roster version's `policy` member: the lowercase
/// hex SHA-256 of its deterministic encoding.
#[must_use]
pub fn policy_digest(policy: &Value) -> String {
    use sha2::Digest as _;
    hex::encode(sha2::Sha256::digest(ciris_verify_core::cde::encode(policy)))
}

/// **The node an admitted row is**, or `None` ([`is_head_row`]).
#[must_use]
pub fn node_of_row(row: &AdmittedRow) -> Option<LineageNode> {
    node_of_parts(
        row.row_id,
        &row.row_type,
        &row.family,
        &row.sub,
        row.author.as_deref(),
        &row.payload,
        &row.names,
    )
}

/// **The node a held statement is**, or `None`.
#[must_use]
pub fn node_of_statement(statement: &[u8]) -> Option<LineageNode> {
    let row_id = RowId::of_statement(statement)?;
    let (protected, payload) = statement_parts(statement)?;
    let row_type = protected.get_int(-70001).and_then(Value::as_text)?;
    let family = protected.get_int(-70002).and_then(Value::as_text)?;
    let sub = protected
        .get_int(15)
        .and_then(|c| c.get_int(2))
        .and_then(Value::as_text)?;
    let author = text(&payload, "author");
    let names = names_of(&payload).ok()?;
    node_of_parts(row_id, row_type, family, sub, author, &payload, &names)
}

/// **The group door's lineage write**: a row that LANDED (its count met,
/// its typed record written, or held as a tip beside the head) that the
/// predicate admits becomes a node. Idempotent; nothing for any other row.
///
/// # Errors
/// The store write.
pub async fn record_landed<F>(dir: &F, row: &AdmittedRow) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(node) = node_of_row(row) else {
        // v62.0.0 (LINEAGE-L3d) — a resignation is no node: an END, kept
        // with the head(s) it acts from.
        return match end_of_parts(
            row.row_id,
            &row.row_type,
            &row.family,
            &row.payload,
            &row.names,
        ) {
            Some(end) => dir.put_group_lineage_end(&end).await,
            None => Ok(()),
        };
    };
    let node = settle(dir, node).await?;
    dir.put_group_lineage_node(&node).await
}

/// The `membership:{stage}` leaf of a member's own leaving (CC 3.3.4).
pub const RESIGNATION_LEAF: &str = "resignation";

/// v62.0.0 (LINEAGE-L3d; CC 3.3.4) — **an end of a seat that is no head of
/// the lineage**: a landed `membership:resignation`, the member it ends and
/// the head(s) it acts from (`refs.head`, `refs.further_heads`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineageEnd {
    /// The end's row id.
    pub row_id: RowId,
    /// Family or community.
    pub group_kind: GroupKind,
    /// The group's identity-ref.
    pub group: String,
    /// The member whose seat it ends.
    pub member: String,
    /// The head it acts from (`refs.head`; the resignation door checks that
    /// one), sorted, each once.
    pub heads: Vec<RowId>,
}

fn end_of_parts(
    row_id: RowId,
    row_type: &str,
    family: &str,
    payload: &Value,
    names: &[Name],
) -> Option<LineageEnd> {
    if super::emit::names_a_target(row_type)
        || family != namespace_match::family_id(MEMBERSHIP_PREFIX)
        || super::payloads::leaf_of(family, payload) != Some(RESIGNATION_LEAF)
    {
        return None;
    }
    Some(LineageEnd {
        row_id,
        group_kind: group_kind_of(payload)?,
        group: text(payload, "group")?.to_owned(),
        member: text(payload, "member")?.to_owned(),
        // v62.0.0 (LINEAGE-L3S) — `refs.head` only: the resignation door
        // checks that one head (v62-resign), so a host-stated
        // `refs.further_heads` on an end is not read as a head it acts from.
        heads: names
            .iter()
            .filter(|n| n.role == HEAD_ROLE)
            .map(|n| n.row)
            .collect(),
    })
}

/// **The end a held statement is**, or `None` (LINEAGE-L3d).
#[must_use]
pub fn end_of_statement(statement: &[u8]) -> Option<LineageEnd> {
    let row_id = RowId::of_statement(statement)?;
    let (protected, payload) = statement_parts(statement)?;
    let row_type = protected.get_int(-70001).and_then(Value::as_text)?;
    let family = protected.get_int(-70002).and_then(Value::as_text)?;
    let names = names_of(&payload).ok()?;
    end_of_parts(row_id, row_type, family, &payload, &names)
}

/// **The ends of `group` composed from routed reads**: the trait default of
/// [`FederationDirectory::group_lineage_ends`] (the capsule proxy). The held
/// `membership:{stage}` statements about every member the group's typed
/// planes name, each kept when [`end_of_statement`] admits it for this group
/// and it is CONCLUDED here.
///
/// # Errors
/// Directory reads.
pub async fn derived_ends(
    dir: &dyn FederationDirectory,
    group: &str,
) -> Result<Vec<LineageEnd>, Error> {
    let mut members: BTreeSet<String> = BTreeSet::new();
    members.extend(
        dir.list_community_membership_revocations_for(group)
            .await?
            .into_iter()
            .map(|r| r.removed_identity_key_id),
    );
    members.extend(
        dir.list_family_membership_revocations_for(group)
            .await?
            .into_iter()
            .map(|r| r.removed_identity_key_id),
    );
    let membership = namespace_match::family_id(MEMBERSHIP_PREFIX);
    let mut out: BTreeMap<RowId, LineageEnd> = BTreeMap::new();
    for m in &members {
        for st in dir.edition2_statements_about(&membership, m).await? {
            let Some(end) = end_of_statement(&st) else {
                continue;
            };
            if end.group != group || out.contains_key(&end.row_id) {
                continue;
            }
            if super::verdict::row_state(dir, &end.row_id)
                .await?
                .is_concluded()
            {
                out.insert(end.row_id, end);
            }
        }
    }
    Ok(out.into_values().collect())
}

/// v62.0.0 (LINEAGE-L3d; the strict fold's second input) — **who resigned
/// since the restating version(s) behind `heads`**: the members whose
/// resignation acts from a head in the lineage past of `heads` (inclusive),
/// walked back to the restating version(s) exactly as [`members_at`] walks.
///
/// # Errors
/// Directory reads.
pub async fn resigned_at<F>(dir: &F, heads: &[RowId]) -> Result<BTreeSet<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::fold::{reads, Dep};
    let mut seen: BTreeSet<RowId> = BTreeSet::new();
    let mut group: Option<String> = None;
    let mut todo: Vec<RowId> = heads.to_vec();
    while let Some(h) = todo.pop() {
        if !seen.insert(h) {
            continue;
        }
        reads(Dep::Row(h));
        let Some(n) = dir.group_lineage_node(&h).await? else {
            continue;
        };
        if group.get_or_insert_with(|| n.group.clone()) != &n.group {
            continue;
        }
        if n.head_of != HeadOf::Roster {
            todo.extend(n.extends.iter().copied());
        }
    }
    let Some(group) = group else {
        return Ok(BTreeSet::new());
    };
    reads(Dep::key(&group));
    Ok(dir
        .group_lineage_ends(&group)
        .await?
        .into_iter()
        .filter(|e| e.heads.iter().any(|h| seen.contains(h)))
        .map(|e| e.member)
        .collect())
}

/// **What a change takes from its lineage and its voices** (one function;
/// a roster version is returned as read): its base ([`common_base`]); the
/// protocol and policy in force there (the base node's); and, for a
/// widening under `open:self_admit` voiced by its member alone,
/// [`HeadOf::SelfAdmission`] (LINEAGE-L1b).
///
/// # Errors
/// Directory reads.
pub async fn settle<F>(dir: &F, mut node: LineageNode) -> Result<LineageNode, Error>
where
    F: FederationDirectory + ?Sized,
{
    if node.head_of == HeadOf::Roster {
        return Ok(node);
    }
    node.base = common_base(dir, &node.extends).await?;
    if let Some(b) = node.base {
        if let Some(base) = dir.group_lineage_node(&b).await? {
            node.consensus_protocol = base.consensus_protocol;
            node.entrenched = base.entrenched;
            node.policy_digest = base.policy_digest;
        }
    }
    if node.head_of == HeadOf::Widening {
        let voices = voice_identities(dir, &node.row_id).await?;
        if is_self_admission(
            node.consensus_protocol.as_deref(),
            node.subject.as_deref(),
            &voices,
        ) {
            node.head_of = HeadOf::SelfAdmission;
        }
    }
    Ok(node)
}

/// **Is a counted widening a self-admission?** (LINEAGE-L1b; pure) Its
/// protocol in force is `open:self_admit`, and it has voices, every one of
/// them its member's (the identity each voice's key acts as).
#[must_use]
pub fn is_self_admission(protocol: Option<&str>, member: Option<&str>, voices: &[String]) -> bool {
    let open = protocol == Some(crate::federation::types::consensus_protocol::OPEN_SELF_ADMIT);
    match member {
        Some(m) => open && !voices.is_empty() && voices.iter().all(|v| v == m),
        None => false,
    }
}

/// The identity each held voice of `row_id` signs as: its `iss`, or the
/// identity that key is an occurrence of.
async fn voice_identities<F>(dir: &F, row_id: &RowId) -> Result<Vec<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut out = Vec::new();
    for st in dir.edition2_voices(row_id).await? {
        let Some(iss) = statement_parts(&st).and_then(|(protected, _)| {
            protected
                .get_int(15)
                .and_then(|c| c.get_int(1))
                .and_then(Value::as_text)
                .map(str::to_owned)
        }) else {
            continue;
        };
        let identity = dir.active_identity_for_occurrence(&iss).await?;
        out.push(if identity.is_empty() { iss } else { identity });
    }
    Ok(out)
}

/// v62.0.0 (LINEAGE-L2) — **the base a widening or removal extending
/// `extends` stands on**: the one base every predecessor node has; `None`
/// when they differ, when one has none, or when one is no node here.
///
/// # Errors
/// Directory reads.
pub async fn common_base<F>(dir: &F, extends: &[RowId]) -> Result<Option<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut base: Option<RowId> = None;
    for p in extends {
        let Some(b) = dir.group_lineage_node(p).await?.and_then(|n| n.base) else {
            return Ok(None);
        };
        match base {
            None => base = Some(b),
            Some(x) if x == b => {}
            Some(_) => return Ok(None),
        }
    }
    Ok(base)
}

/// v62.0.0 (LINEAGE-L2) — **the restating versions behind `heads`**: for a
/// roster version, itself; for a widening or removal, its base (or, at a
/// join over different bases, its predecessors' versions, walked); for a
/// row that is no node here (not held, not concluded, of no lineage),
/// itself, for the caller to read and wait on as it always did. Sorted, each
/// once. Every row it reads is declared to the running fold attempt.
///
/// What bounds it: each membership node carries its base, so a walk passes
/// at most one membership node per named head and never a restating
/// version; only a join over roster tips (no common base) walks further,
/// and then each node at most once.
///
/// # Errors
/// Directory reads.
pub async fn nearest_versions<F>(dir: &F, heads: &[RowId]) -> Result<Vec<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::fold::{reads, Dep};
    let mut out: BTreeSet<RowId> = BTreeSet::new();
    let mut seen: BTreeSet<RowId> = BTreeSet::new();
    let mut todo: Vec<RowId> = heads.to_vec();
    while let Some(h) = todo.pop() {
        if !seen.insert(h) {
            continue;
        }
        reads(Dep::Row(h));
        match dir.group_lineage_node(&h).await? {
            Some(n) if n.head_of != HeadOf::Roster => match n.base {
                Some(b) => {
                    reads(Dep::Row(b));
                    out.insert(b);
                }
                None => todo.extend(n.extends.iter().copied()),
            },
            _ => {
                out.insert(h);
            }
        }
    }
    Ok(out.into_iter().collect())
}

/// v62.0.0 (LINEAGE-L3; CC 2.7.8, CC 3.3.4) — **who is seated at
/// `heads`**: the lineage nodes in their past, back to the restating
/// version(s) each stands on, read by the kernel's seats
/// (`kernel::lineage::seated_at`, the ONE fold call): at one head every seat
/// standing in its past; at several heads the members common to all of them
/// (CC 2.7.8; kernel-v0.2.2). A head that is no node here seats nobody.
/// Every row read is declared to the running fold attempt.
///
/// What bounds it: the walk stops at each restating version, so it reads
/// the changes since the last version that restates the list, and the list
/// itself, never the group's age.
///
/// # Errors
/// Directory reads.
pub async fn members_at<F>(
    dir: &F,
    heads: &[RowId],
) -> Result<crate::kernel::lineage::SeatedAt, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::fold::{reads, Dep};
    use crate::federation::consensus::is_founder_role;
    use crate::kernel::lineage::{seated_at, EndView, NodeAct, NodeView, SeatedAt};
    let mut nodes: BTreeMap<RowId, NodeView> = BTreeMap::new();
    let mut named: BTreeMap<RowId, Vec<RowId>> = BTreeMap::new();
    let mut group: Option<String> = None;
    let mut founder_role: Option<String> = None;
    let mut todo: Vec<RowId> = heads.to_vec();
    while let Some(h) = todo.pop() {
        if nodes.contains_key(&h) {
            continue;
        }
        reads(Dep::Row(h));
        let Some(n) = dir.group_lineage_node(&h).await? else {
            continue;
        };
        if group.get_or_insert_with(|| n.group.clone()) != &n.group {
            continue;
        }
        let Some(st) = super::head_rule::held_statement(dir, &h).await? else {
            continue;
        };
        let Some((_, payload)) = statement_parts(&st) else {
            continue;
        };
        let act = match (n.head_of, n.subject.clone()) {
            (HeadOf::Roster, _) => {
                let listed = listed_members(&payload);
                note_founder_word(&mut founder_role, listed.iter().map(|(_, r)| r.as_deref()));
                NodeAct::Root(
                    listed
                        .into_iter()
                        .map(|(k, r)| {
                            let f = is_founder_role(r.as_deref());
                            (k, f)
                        })
                        .collect(),
                )
            }
            (HeadOf::Widening | HeadOf::SelfAdmission, Some(m)) => {
                let role = text(&payload, "role");
                note_founder_word(&mut founder_role, std::iter::once(role));
                NodeAct::Seat {
                    member: m,
                    founder: is_founder_role(role),
                    self_admit: n.head_of == HeadOf::SelfAdmission,
                }
            }
            (HeadOf::Removal, Some(m)) => NodeAct::Unseat(m),
            (_, None) => continue,
        };
        if n.head_of != HeadOf::Roster {
            todo.extend(n.extends.iter().copied());
        }
        // Every row the node's statement names (an end among them is read
        // below, once the group's ends are known).
        if let Ok(ns) = names_of(&payload) {
            named.insert(h, ns.iter().map(|x| x.row).collect());
        }
        nodes.insert(
            h,
            NodeView {
                id: h.0,
                extends: n.extends.iter().map(|e| e.0).collect(),
                ends: Vec::new(),
                act,
                voices: voice_identities(dir, &h).await?,
                protocol: n.consensus_protocol.clone(),
            },
        );
    }
    let Some(group) = group else {
        return Ok(SeatedAt::default());
    };
    // The ends acting from a node of the question; each node names those it
    // has in its past by its own refs.
    reads(Dep::key(&group));
    let ends: Vec<EndView> = dir
        .group_lineage_ends(&group)
        .await?
        .into_iter()
        .filter(|e| e.heads.iter().any(|h| nodes.contains_key(h)))
        .map(|e| EndView {
            id: e.row_id.0,
            member: e.member,
            heads: e.heads.iter().map(|h| h.0).collect(),
        })
        .collect();
    let end_ids: BTreeSet<[u8; 32]> = ends.iter().map(|e| e.id).collect();
    for (id, ns) in &named {
        if let Some(n) = nodes.get_mut(id) {
            n.ends = ns
                .iter()
                .map(|r| r.0)
                .filter(|r| end_ids.contains(r))
                .collect();
        }
    }
    let nodes: Vec<NodeView> = nodes.into_values().collect();
    let heads: Vec<[u8; 32]> = heads.iter().map(|h| h.0).collect();
    let mut at = seated_at(&nodes, &ends, &heads);
    at.founder_role = founder_role;
    Ok(at)
}

/// The founder role word as the rows state it: the first role the one
/// founder reader (`consensus::is_founder_role`) recognises, kept so a
/// caller writing a seat's role copies the row's word and names no role.
fn note_founder_word<'a>(word: &mut Option<String>, roles: impl Iterator<Item = Option<&'a str>>) {
    if word.is_some() {
        return;
    }
    for r in roles.flatten() {
        if crate::federation::consensus::is_founder_role(Some(r)) {
            *word = Some(r.to_owned());
            return;
        }
    }
}

/// v62.0.0 (LINEAGE-L4) — **the members seated at `named`, with their
/// role tags**, for a reader that counts an act over a head: at a widening
/// or removal (a lineage head that is no version), the seats there
/// ([`members_at`]): the founder seat under the rows' own founder word, any
/// other role as `listed` (the restating version's list) states it; at any
/// other head, `listed` unchanged.
///
/// # Errors
/// Directory reads.
pub async fn members_with_roles_at<F>(
    dir: &F,
    named: &RowId,
    listed: Vec<(String, Option<String>)>,
) -> Result<Vec<(String, Option<String>)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::consensus::is_founder_role;
    let is_change = dir
        .group_lineage_node(named)
        .await?
        .is_some_and(|n| n.head_of != HeadOf::Roster);
    if !is_change {
        return Ok(listed);
    }
    let at = members_at(dir, std::slice::from_ref(named)).await?;
    let roles: BTreeMap<String, Option<String>> = listed.into_iter().collect();
    Ok(at
        .members
        .iter()
        .map(|k| {
            let role = if at.founders.contains(k) {
                at.founder_role.clone()
            } else {
                roles
                    .get(k)
                    .cloned()
                    .flatten()
                    .filter(|r| !is_founder_role(Some(r.as_str())))
            };
            (k.clone(), role)
        })
        .collect())
}

/// A roster payload's listed members: each `members` entry's `key`, and
/// its `role` (if any).
fn listed_members(payload: &Value) -> Vec<(String, Option<String>)> {
    payload
        .get_text("members")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|m| {
                    let k = text(m, "key")?.to_owned();
                    Some((k, text(m, "role").map(str::to_owned)))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// v62.0.0 (LINEAGE-L2; interim until `members_at(head)`, LINEAGE-L3) —
/// **the restating version one head stands on**: a widening's or removal's
/// base; the head itself otherwise (a roster version, a row that is no node
/// here, a join whose bases differ). The readers that count an act over the
/// members a roster version LISTS read this version, as they read the
/// version itself before the head moved on a membership change.
///
/// # Errors
/// Directory reads.
pub async fn restating_version<F>(dir: &F, head: &RowId) -> Result<RowId, Error>
where
    F: FederationDirectory + ?Sized,
{
    super::fold::reads(super::fold::Dep::Row(*head));
    Ok(match dir.group_lineage_node(head).await? {
        Some(n) if n.head_of != HeadOf::Roster => n.base.unwrap_or(*head),
        _ => *head,
    })
}

/// **The heads of a lineage**: the nodes no other node extends, by row id.
/// Pure over the nodes given (all of one group).
#[must_use]
pub fn frontier(nodes: &[LineageNode]) -> Vec<RowId> {
    let named: BTreeSet<RowId> = nodes
        .iter()
        .flat_map(|n| n.extends.iter().copied())
        .collect();
    let mut out: Vec<RowId> = nodes
        .iter()
        .map(|n| n.row_id)
        .filter(|id| !named.contains(id))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// **The group's heads as this node holds them** ([`frontier`] over
/// [`FederationDirectory::group_lineage_nodes`]). Empty for a group with no
/// node held here.
///
/// # Errors
/// Directory reads.
pub async fn heads<F>(dir: &F, group: &str) -> Result<Vec<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(frontier(&dir.group_lineage_nodes(group).await?))
}

/// **The lineage nodes of `group`, composed from routed reads**: the
/// trait default of [`FederationDirectory::group_lineage_nodes`] for a
/// directory with no lineage table (the capsule proxy). The held
/// `group:roster` statements about the group, and the held
/// `membership:{stage}` statements about every member its typed widening and
/// revocation planes name, each kept when [`node_of_statement`] admits it for
/// this group and it is CONCLUDED here (`verdict::row_state`). The same nodes
/// the table holds; bounded by the group's history, not by one question
/// (the backends answer from the table).
///
/// # Errors
/// Directory reads.
pub async fn derived_nodes(
    dir: &dyn FederationDirectory,
    group: &str,
) -> Result<Vec<LineageNode>, Error> {
    let mut statements = dir
        .edition2_statements_about(&namespace_match::family_id(GROUP_ROSTER_PREFIX), group)
        .await?;
    let mut members: BTreeSet<String> = BTreeSet::new();
    members.extend(
        dir.list_community_membership_widenings_for(group)
            .await?
            .into_iter()
            .map(|w| w.member_key_id),
    );
    members.extend(
        dir.list_community_membership_revocations_for(group)
            .await?
            .into_iter()
            .map(|r| r.removed_identity_key_id),
    );
    members.extend(
        dir.list_family_membership_widenings_for(group)
            .await?
            .into_iter()
            .map(|w| w.member_key_id),
    );
    members.extend(
        dir.list_family_membership_revocations_for(group)
            .await?
            .into_iter()
            .map(|r| r.removed_identity_key_id),
    );
    let membership = namespace_match::family_id(MEMBERSHIP_PREFIX);
    for m in &members {
        statements.extend(dir.edition2_statements_about(&membership, m).await?);
    }
    let mut out: BTreeMap<RowId, LineageNode> = BTreeMap::new();
    for st in &statements {
        let Some(node) = node_of_statement(st) else {
            continue;
        };
        if node.group != group || out.contains_key(&node.row_id) {
            continue;
        }
        if !super::verdict::row_state(dir, &node.row_id)
            .await?
            .is_concluded()
        {
            continue;
        }
        out.insert(node.row_id, node);
    }
    // What each change takes from its lineage and voices (`settle`; its
    // reads go back through this directory, by row id).
    let mut settled = Vec::with_capacity(out.len());
    for node in out.into_values() {
        settled.push(settle(dir, node).await?);
    }
    Ok(settled)
}

/// **One lineage node, composed from routed reads**: the trait default of
/// [`FederationDirectory::group_lineage_node`] (the capsule proxy). The held
/// statement of `row_id` when [`node_of_statement`] admits it and it is
/// CONCLUDED here, its base read from its predecessors ([`common_base`]).
///
/// # Errors
/// Directory reads.
pub async fn derived_node(
    dir: &dyn FederationDirectory,
    row_id: &RowId,
) -> Result<Option<LineageNode>, Error> {
    let Some(st) = super::head_rule::held_statement(dir, row_id).await? else {
        return Ok(None);
    };
    let Some(mut node) = node_of_statement(&st) else {
        return Ok(None);
    };
    if !super::verdict::row_state(dir, row_id).await?.is_concluded() {
        return Ok(None);
    }
    node = settle(dir, node).await?;
    Ok(Some(node))
}

// ─────────────────────────────────────────────────────────────────────────
//  The two dialects (ceg_group_lineage, ceg_group_lineage_extends)
// ─────────────────────────────────────────────────────────────────────────

fn row_id_of_bytes(b: &[u8], table: &str) -> Result<RowId, Error> {
    <[u8; 32]>::try_from(b)
        .map(RowId)
        .map_err(|_| Error::Backend(format!("{table}: row id length")))
}

/// One `ceg_group_lineage` row: `(row_id, group_kind, group_key_id,
/// head_of, subject, base_row_id, consensus_protocol, policy_digest,
/// entrenched)`.
type NodeColumns = (
    Vec<u8>,
    String,
    String,
    String,
    Option<String>,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
    bool,
);

/// Assemble nodes from their rows and `(row_id, extends_row_id)` pairs.
fn assemble(
    rows: Vec<NodeColumns>,
    extends: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Vec<LineageNode>, Error> {
    let mut by: BTreeMap<RowId, Vec<RowId>> = BTreeMap::new();
    for (r, e) in extends {
        by.entry(row_id_of_bytes(&r, "ceg_group_lineage_extends")?)
            .or_default()
            .push(row_id_of_bytes(&e, "ceg_group_lineage_extends")?);
    }
    let mut out = Vec::with_capacity(rows.len());
    for (id, kind, group, head_of, subject, base, consensus_protocol, policy_digest, entrenched) in
        rows
    {
        let row_id = row_id_of_bytes(&id, "ceg_group_lineage")?;
        let group_kind = match kind.as_str() {
            "family" => GroupKind::Family,
            "community" => GroupKind::Community,
            other => {
                return Err(Error::Backend(format!(
                    "ceg_group_lineage: group_kind {other:?}"
                )))
            }
        };
        let head_of = HeadOf::parse(&head_of)
            .ok_or_else(|| Error::Backend(format!("ceg_group_lineage: head_of {head_of:?}")))?;
        let mut ext = by.remove(&row_id).unwrap_or_default();
        ext.sort();
        ext.dedup();
        out.push(LineageNode {
            row_id,
            group_kind,
            group,
            head_of,
            subject,
            extends: ext,
            base: base
                .map(|b| row_id_of_bytes(&b, "ceg_group_lineage"))
                .transpose()?,
            consensus_protocol,
            policy_digest,
            entrenched,
        });
    }
    Ok(out)
}

/// sqlite: write one node and its predecessors, idempotently, in one
/// transaction.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn put_node_sqlite(conn: &mut rusqlite::Connection, node: &LineageNode) -> Result<(), Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_group_lineage: {e}"));
    let tx = crate::store::sqlite_conn_model::write_tx(conn).map_err(be)?;
    tx.execute(
        "INSERT INTO ceg_group_lineage \
         (row_id, group_kind, group_key_id, head_of, subject, base_row_id, \
          consensus_protocol, policy_digest, entrenched) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9) ON CONFLICT (row_id) DO NOTHING",
        rusqlite::params![
            &node.row_id.0[..],
            node.group_kind.as_str(),
            node.group,
            node.head_of.as_str(),
            node.subject,
            node.base.map(|b| b.0.to_vec()),
            node.consensus_protocol,
            node.policy_digest,
            node.entrenched
        ],
    )
    .map_err(be)?;
    for e in &node.extends {
        tx.execute(
            "INSERT INTO ceg_group_lineage_extends (row_id, extends_row_id) VALUES (?1, ?2) \
             ON CONFLICT (row_id, extends_row_id) DO NOTHING",
            rusqlite::params![&node.row_id.0[..], &e.0[..]],
        )
        .map_err(be)?;
    }
    tx.commit().map_err(be)
}

/// sqlite: every node of `group`, by row id.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn nodes_sqlite(conn: &rusqlite::Connection, group: &str) -> Result<Vec<LineageNode>, Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_group_lineage: {e}"));
    let mut st = conn
        .prepare(
            "SELECT row_id, group_kind, group_key_id, head_of, subject, base_row_id, \
             consensus_protocol, policy_digest, entrenched \
             FROM ceg_group_lineage WHERE group_key_id = ?1 ORDER BY row_id",
        )
        .map_err(be)?;
    let rows: Vec<NodeColumns> = st
        .query_map(rusqlite::params![group], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
            ))
        })
        .map_err(be)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(be)?;
    let mut st = conn
        .prepare(
            "SELECT e.row_id, e.extends_row_id FROM ceg_group_lineage_extends e \
             JOIN ceg_group_lineage l ON l.row_id = e.row_id \
             WHERE l.group_key_id = ?1 ORDER BY e.row_id, e.extends_row_id",
        )
        .map_err(be)?;
    let extends: Vec<(Vec<u8>, Vec<u8>)> = st
        .query_map(rusqlite::params![group], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(be)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(be)?;
    assemble(rows, extends)
}

/// sqlite: the node whose row id is `row_id`, if it is one.
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn node_sqlite(
    conn: &rusqlite::Connection,
    row_id: &RowId,
) -> Result<Option<LineageNode>, Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_group_lineage: {e}"));
    let mut st = conn
        .prepare(
            "SELECT row_id, group_kind, group_key_id, head_of, subject, base_row_id, \
             consensus_protocol, policy_digest, entrenched \
             FROM ceg_group_lineage WHERE row_id = ?1",
        )
        .map_err(be)?;
    let rows: Vec<NodeColumns> = st
        .query_map(rusqlite::params![&row_id.0[..]], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
            ))
        })
        .map_err(be)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(be)?;
    let mut st = conn
        .prepare(
            "SELECT row_id, extends_row_id FROM ceg_group_lineage_extends WHERE row_id = ?1 \
             ORDER BY extends_row_id",
        )
        .map_err(be)?;
    let extends: Vec<(Vec<u8>, Vec<u8>)> = st
        .query_map(rusqlite::params![&row_id.0[..]], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(be)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(be)?;
    Ok(assemble(rows, extends)?.into_iter().next())
}

/// postgres: write one node and its predecessors, idempotently, on
/// `client` (the caller's transaction).
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn put_node_postgres<C>(client: &C, node: &LineageNode) -> Result<(), Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let be = |e: tokio_postgres::Error| Error::Backend(format!("ceg_group_lineage: {e}"));
    client
        .execute(
            "INSERT INTO cirislens.ceg_group_lineage \
             (row_id, group_kind, group_key_id, head_of, subject, base_row_id, \
              consensus_protocol, policy_digest, entrenched) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) ON CONFLICT (row_id) DO NOTHING",
            &[
                &&node.row_id.0[..],
                &node.group_kind.as_str(),
                &node.group,
                &node.head_of.as_str(),
                &node.subject,
                &node.base.map(|b| b.0.to_vec()),
                &node.consensus_protocol,
                &node.policy_digest,
                &node.entrenched,
            ],
        )
        .await
        .map_err(be)?;
    for e in &node.extends {
        client
            .execute(
                "INSERT INTO cirislens.ceg_group_lineage_extends (row_id, extends_row_id) \
                 VALUES ($1, $2) ON CONFLICT (row_id, extends_row_id) DO NOTHING",
                &[&&node.row_id.0[..], &&e.0[..]],
            )
            .await
            .map_err(be)?;
    }
    Ok(())
}

/// postgres: every node of `group`, by row id.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn nodes_postgres<C>(client: &C, group: &str) -> Result<Vec<LineageNode>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let be = |e: tokio_postgres::Error| Error::Backend(format!("ceg_group_lineage: {e}"));
    let rows: Vec<NodeColumns> = client
        .query(
            "SELECT row_id, group_kind, group_key_id, head_of, subject, base_row_id, \
             consensus_protocol, policy_digest, entrenched \
             FROM cirislens.ceg_group_lineage WHERE group_key_id = $1 ORDER BY row_id",
            &[&group],
        )
        .await
        .map_err(be)?
        .iter()
        .map(|r| {
            Ok((
                r.try_get(0)?,
                r.try_get(1)?,
                r.try_get(2)?,
                r.try_get(3)?,
                r.try_get(4)?,
                r.try_get(5)?,
                r.try_get(6)?,
                r.try_get(7)?,
                r.try_get(8)?,
            ))
        })
        .collect::<Result<_, tokio_postgres::Error>>()
        .map_err(be)?;
    let extends: Vec<(Vec<u8>, Vec<u8>)> = client
        .query(
            "SELECT e.row_id, e.extends_row_id FROM cirislens.ceg_group_lineage_extends e \
             JOIN cirislens.ceg_group_lineage l ON l.row_id = e.row_id \
             WHERE l.group_key_id = $1 ORDER BY e.row_id, e.extends_row_id",
            &[&group],
        )
        .await
        .map_err(be)?
        .iter()
        .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
        .collect::<Result<_, tokio_postgres::Error>>()
        .map_err(be)?;
    assemble(rows, extends)
}

/// postgres: the node whose row id is `row_id`, if it is one.
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn node_postgres<C>(client: &C, row_id: &RowId) -> Result<Option<LineageNode>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let be = |e: tokio_postgres::Error| Error::Backend(format!("ceg_group_lineage: {e}"));
    let rows: Vec<NodeColumns> = client
        .query(
            "SELECT row_id, group_kind, group_key_id, head_of, subject, base_row_id, \
             consensus_protocol, policy_digest, entrenched \
             FROM cirislens.ceg_group_lineage WHERE row_id = $1",
            &[&&row_id.0[..]],
        )
        .await
        .map_err(be)?
        .iter()
        .map(|r| {
            Ok((
                r.try_get(0)?,
                r.try_get(1)?,
                r.try_get(2)?,
                r.try_get(3)?,
                r.try_get(4)?,
                r.try_get(5)?,
                r.try_get(6)?,
                r.try_get(7)?,
                r.try_get(8)?,
            ))
        })
        .collect::<Result<_, tokio_postgres::Error>>()
        .map_err(be)?;
    let extends: Vec<(Vec<u8>, Vec<u8>)> = client
        .query(
            "SELECT row_id, extends_row_id FROM cirislens.ceg_group_lineage_extends \
             WHERE row_id = $1 ORDER BY extends_row_id",
            &[&&row_id.0[..]],
        )
        .await
        .map_err(be)?
        .iter()
        .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
        .collect::<Result<_, tokio_postgres::Error>>()
        .map_err(be)?;
    Ok(assemble(rows, extends)?.into_iter().next())
}

/// sqlite: write one end and its heads, idempotently, in one transaction
/// (LINEAGE-L3d).
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn put_end_sqlite(conn: &mut rusqlite::Connection, end: &LineageEnd) -> Result<(), Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_group_lineage_ends: {e}"));
    let tx = crate::store::sqlite_conn_model::write_tx(conn).map_err(be)?;
    tx.execute(
        "INSERT INTO ceg_group_lineage_ends (row_id, group_kind, group_key_id, member, end_kind) \
         VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT (row_id) DO NOTHING",
        rusqlite::params![
            &end.row_id.0[..],
            end.group_kind.as_str(),
            end.group,
            end.member,
            RESIGNATION_LEAF
        ],
    )
    .map_err(be)?;
    for h in &end.heads {
        tx.execute(
            "INSERT INTO ceg_group_lineage_end_heads (row_id, head_row_id) VALUES (?1, ?2) \
             ON CONFLICT (row_id, head_row_id) DO NOTHING",
            rusqlite::params![&end.row_id.0[..], &h.0[..]],
        )
        .map_err(be)?;
    }
    tx.commit().map_err(be)
}

/// One `ceg_group_lineage_ends` row: `(row_id, group_kind, group_key_id,
/// member)`.
type EndColumns = (Vec<u8>, String, String, String);

fn assemble_ends(
    rows: Vec<EndColumns>,
    heads: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Vec<LineageEnd>, Error> {
    let mut by: BTreeMap<RowId, Vec<RowId>> = BTreeMap::new();
    for (r, h) in heads {
        by.entry(row_id_of_bytes(&r, "ceg_group_lineage_end_heads")?)
            .or_default()
            .push(row_id_of_bytes(&h, "ceg_group_lineage_end_heads")?);
    }
    let mut out = Vec::with_capacity(rows.len());
    for (id, kind, group, member) in rows {
        let row_id = row_id_of_bytes(&id, "ceg_group_lineage_ends")?;
        let group_kind = match kind.as_str() {
            "family" => GroupKind::Family,
            "community" => GroupKind::Community,
            other => {
                return Err(Error::Backend(format!(
                    "ceg_group_lineage_ends: group_kind {other:?}"
                )))
            }
        };
        let mut heads = by.remove(&row_id).unwrap_or_default();
        heads.sort();
        heads.dedup();
        out.push(LineageEnd {
            row_id,
            group_kind,
            group,
            member,
            heads,
        });
    }
    Ok(out)
}

/// sqlite: every end of `group`, by row id (LINEAGE-L3d).
///
/// # Errors
/// sqlite errors.
#[cfg(feature = "sqlite")]
pub fn ends_sqlite(conn: &rusqlite::Connection, group: &str) -> Result<Vec<LineageEnd>, Error> {
    let be = |e: rusqlite::Error| Error::Backend(format!("ceg_group_lineage_ends: {e}"));
    let mut st = conn
        .prepare(
            "SELECT row_id, group_kind, group_key_id, member FROM ceg_group_lineage_ends \
             WHERE group_key_id = ?1 ORDER BY row_id",
        )
        .map_err(be)?;
    let rows: Vec<EndColumns> = st
        .query_map(rusqlite::params![group], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .map_err(be)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(be)?;
    let mut st = conn
        .prepare(
            "SELECT h.row_id, h.head_row_id FROM ceg_group_lineage_end_heads h \
             JOIN ceg_group_lineage_ends e ON e.row_id = h.row_id \
             WHERE e.group_key_id = ?1 ORDER BY h.row_id, h.head_row_id",
        )
        .map_err(be)?;
    let heads: Vec<(Vec<u8>, Vec<u8>)> = st
        .query_map(rusqlite::params![group], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(be)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(be)?;
    assemble_ends(rows, heads)
}

/// postgres: write one end and its heads on `client` (the caller's
/// transaction) (LINEAGE-L3d).
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn put_end_postgres<C>(client: &C, end: &LineageEnd) -> Result<(), Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let be = |e: tokio_postgres::Error| Error::Backend(format!("ceg_group_lineage_ends: {e}"));
    client
        .execute(
            "INSERT INTO cirislens.ceg_group_lineage_ends \
             (row_id, group_kind, group_key_id, member, end_kind) VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (row_id) DO NOTHING",
            &[
                &&end.row_id.0[..],
                &end.group_kind.as_str(),
                &end.group,
                &end.member,
                &RESIGNATION_LEAF,
            ],
        )
        .await
        .map_err(be)?;
    for h in &end.heads {
        client
            .execute(
                "INSERT INTO cirislens.ceg_group_lineage_end_heads (row_id, head_row_id) \
                 VALUES ($1, $2) ON CONFLICT (row_id, head_row_id) DO NOTHING",
                &[&&end.row_id.0[..], &&h.0[..]],
            )
            .await
            .map_err(be)?;
    }
    Ok(())
}

/// postgres: every end of `group`, by row id (LINEAGE-L3d).
///
/// # Errors
/// postgres errors.
#[cfg(feature = "postgres")]
pub async fn ends_postgres<C>(client: &C, group: &str) -> Result<Vec<LineageEnd>, Error>
where
    C: deadpool_postgres::GenericClient + Sync,
{
    let be = |e: tokio_postgres::Error| Error::Backend(format!("ceg_group_lineage_ends: {e}"));
    let rows: Vec<EndColumns> = client
        .query(
            "SELECT row_id, group_kind, group_key_id, member \
             FROM cirislens.ceg_group_lineage_ends WHERE group_key_id = $1 ORDER BY row_id",
            &[&group],
        )
        .await
        .map_err(be)?
        .iter()
        .map(|r| Ok((r.try_get(0)?, r.try_get(1)?, r.try_get(2)?, r.try_get(3)?)))
        .collect::<Result<_, tokio_postgres::Error>>()
        .map_err(be)?;
    let heads: Vec<(Vec<u8>, Vec<u8>)> = client
        .query(
            "SELECT h.row_id, h.head_row_id FROM cirislens.ceg_group_lineage_end_heads h \
             JOIN cirislens.ceg_group_lineage_ends e ON e.row_id = h.row_id \
             WHERE e.group_key_id = $1 ORDER BY h.row_id, h.head_row_id",
            &[&group],
        )
        .await
        .map_err(be)?
        .iter()
        .map(|r| Ok((r.try_get(0)?, r.try_get(1)?)))
        .collect::<Result<_, tokio_postgres::Error>>()
        .map_err(be)?;
    assemble_ends(rows, heads)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fid(p: &str) -> String {
        namespace_match::family_id(p)
    }

    /// I6900 — THE predicate's cells: a roster version and a COUNTED
    /// widening / removal are nodes; a resignation, an authored membership
    /// row, every other stage and every other family are not.
    #[test]
    fn i6900_the_one_predicate() {
        let m = fid(MEMBERSHIP_PREFIX);
        assert_eq!(
            is_head_row(&fid(GROUP_ROSTER_PREFIX), None, true),
            Some(HeadOf::Roster)
        );
        assert_eq!(
            is_head_row(&m, Some("widening"), true),
            Some(HeadOf::Widening)
        );
        assert_eq!(
            is_head_row(&m, Some("removal"), true),
            Some(HeadOf::Removal)
        );
        assert_eq!(
            is_head_row(&m, Some("resignation"), true),
            None,
            "I6900: a resignation is no head (CC 3.3.4)"
        );
        assert_eq!(is_head_row(&m, Some("resignation"), false), None);
        assert_eq!(
            is_head_row(&m, Some("widening"), false),
            None,
            "I6900: an authored widening is no version"
        );
        assert_eq!(is_head_row(&m, Some("removal"), false), None);
        for leaf in ["proposal", "acceptance", "decline", "keeps"] {
            assert_eq!(is_head_row(&m, Some(leaf), true), None, "I6900: {leaf}");
        }
        assert_eq!(is_head_row(&m, None, true), None);
        assert_eq!(is_head_row(&fid("key_grant:{axis}"), None, true), None);
        for h in [
            HeadOf::Roster,
            HeadOf::Widening,
            HeadOf::Removal,
            HeadOf::SelfAdmission,
        ] {
            assert_eq!(HeadOf::parse(h.as_str()), Some(h), "I6900: spelling");
        }
    }

    /// I6907 (LINEAGE-L1b) — a self-admission is a counted widening under
    /// `open:self_admit` voiced by its member alone: another protocol, a
    /// second voice, no voice or no member is a plain widening.
    #[test]
    fn i6907_a_self_admission_is_its_member_alone_under_open_self_admit() {
        use crate::federation::types::consensus_protocol as cp;
        let m = "member".to_owned();
        let open = Some(cp::OPEN_SELF_ADMIT);
        assert!(is_self_admission(
            open,
            Some("member"),
            std::slice::from_ref(&m)
        ));
        assert!(is_self_admission(
            open,
            Some("member"),
            &[m.clone(), m.clone()]
        ));
        assert!(!is_self_admission(
            Some(cp::MAJORITY),
            Some("member"),
            std::slice::from_ref(&m)
        ));
        assert!(!is_self_admission(
            None,
            Some("member"),
            std::slice::from_ref(&m)
        ));
        assert!(!is_self_admission(
            open,
            Some("member"),
            &[m.clone(), "other".into()]
        ));
        assert!(!is_self_admission(open, Some("member"), &[]));
        assert!(!is_self_admission(open, None, &[m]));
        assert_eq!(
            HeadOf::parse("self_admission"),
            Some(HeadOf::SelfAdmission),
            "I6907: the stored spelling"
        );
    }

    /// I6912 (LINEAGE-L3) — the regime is one value: equal protocol and
    /// policy compare equal; either differing does not; no protocol, none.
    #[test]
    fn i6912_the_regime_is_one_comparable_value() {
        let mut a = node(1, &[]);
        a.consensus_protocol = Some("majority".into());
        let mut b = node(2, &[1]);
        b.consensus_protocol = Some("majority".into());
        assert_eq!(a.regime(), b.regime(), "I6912: same protocol, no policy");
        let p = Value::Map(vec![(Value::Text("k".into()), Value::Uint(1))]);
        a.policy_digest = Some(policy_digest(&p));
        assert_ne!(a.regime(), b.regime(), "I6912: a policy differs");
        b.policy_digest = Some(policy_digest(&p.clone()));
        assert_eq!(a.regime(), b.regime(), "I6912: the same policy");
        b.entrenched = true;
        assert_ne!(
            a.regime(),
            b.regime(),
            "I6912: two tips differing only in the entrenched flag differ"
        );
        b.entrenched = false;
        assert_eq!(a.regime(), b.regime(), "I6912: the flag back, equal again");
        b.consensus_protocol = Some("unanimous".into());
        assert_ne!(a.regime(), b.regime(), "I6912: a protocol differs");
        b.consensus_protocol = None;
        assert_eq!(b.regime(), None, "I6912: no protocol, no regime");
    }

    /// I6913 (LINEAGE-L3c) — the lineage reads a role through the one
    /// founder reader: the role word the roster states is a founder, any
    /// other word or none is not.
    #[test]
    fn i6913_the_founder_role_is_read_through_the_one_reader() {
        use crate::federation::consensus::is_founder_role;
        let listed = listed_members(&Value::Map(vec![(
            Value::Text("members".into()),
            Value::Array(vec![
                Value::Map(vec![
                    (Value::Text("key".into()), Value::Text("a".into())),
                    (Value::Text("role".into()), Value::Text("founder".into())),
                ]),
                Value::Map(vec![(Value::Text("key".into()), Value::Text("b".into()))]),
            ]),
        )]));
        assert_eq!(listed.len(), 2, "I6913: both listed");
        assert!(is_founder_role(listed[0].1.as_deref()), "I6913: a founder");
        assert!(!is_founder_role(listed[1].1.as_deref()), "I6913: no role");
        assert!(!is_founder_role(Some("member")), "I6913: another word");
        let mut word = None;
        note_founder_word(&mut word, listed.iter().map(|(_, r)| r.as_deref()));
        assert_eq!(
            word.as_deref(),
            Some("founder"),
            "I6913: the rows' own word"
        );
    }

    fn node(id: u8, extends: &[u8]) -> LineageNode {
        LineageNode {
            row_id: RowId([id; 32]),
            group_kind: GroupKind::Community,
            group: "g".into(),
            head_of: if extends.is_empty() {
                HeadOf::Roster
            } else {
                HeadOf::Widening
            },
            subject: (!extends.is_empty()).then(|| "m".to_owned()),
            extends: extends.iter().map(|e| RowId([*e; 32])).collect(),
            base: extends.is_empty().then_some(RowId([id; 32])),
            consensus_protocol: None,
            policy_digest: None,
            entrenched: false,
        }
    }

    /// I6901 — the heads are the nodes no other node extends: one chain is
    /// one head; two rows extending one head are two tips; a row naming
    /// both makes one head again.
    #[test]
    fn i6901_the_frontier() {
        assert_eq!(frontier(&[]), Vec::<RowId>::new());
        let chain = [node(1, &[]), node(2, &[1]), node(3, &[2])];
        assert_eq!(frontier(&chain), vec![RowId([3; 32])], "I6901: one chain");
        let forked = [node(1, &[]), node(2, &[1]), node(3, &[1])];
        assert_eq!(
            frontier(&forked),
            vec![RowId([2; 32]), RowId([3; 32])],
            "I6901: two tips"
        );
        let joined = [node(1, &[]), node(2, &[1]), node(3, &[1]), node(4, &[2, 3])];
        assert_eq!(
            frontier(&joined),
            vec![RowId([4; 32])],
            "I6901: a join makes one head"
        );
        // A node whose predecessor this node does not hold is still a head
        // beside the others' (a held head only names what it extends).
        let gap = [node(2, &[1]), node(5, &[9])];
        assert_eq!(frontier(&gap), vec![RowId([2; 32]), RowId([5; 32])]);
    }
}
