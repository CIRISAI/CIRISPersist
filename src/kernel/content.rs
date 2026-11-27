//! v62.0.0 (CONTENT-A1; CC rc22 3.1.3.2 "A room's content after a member's
//! seat ends") — **the adapter to `ciris_kernel::content`.** The rule is
//! the Kernel crate's (kernel-v0.2.1 / v0.2.2; persist ships no port). This
//! module presents persist's held statements of one member in one room as
//! the crate's [`ContentRow`]s, the member's keys and the room's count as
//! its [`Seat`], and persist's held causal past as its `Past`, and asks.
//!
//! What is persist's here, and nothing else:
//!
//! - **the mapping** ([`room_row`], [`composer_row`]): which held statement
//!   is a Head, a Content row, an End, a Tips row, or Other, read from the
//!   statement's own bytes. The END is classified by its LEAF alone
//!   ([`end_of`]): a counted `membership:removal` is the count's end; a
//!   `membership:resignation` is the member's own. Who voiced a removal is
//!   never read (Constitution: "the leaf decides");
//! - **the member** ([`member_keys`]): the identity and every key that
//!   signed a statement authored as that identity (the person across their
//!   keys, retired devices included; an AGENT member's keys are the agent's
//!   only: its owner's key authors as the owner and is never the member);
//! - **the past** ([`HeldPast`]): `ceg_row_names` over the CAUSAL roles
//!   only, preloaded, since the crate's `Past` is synchronous. A predecessor
//!   (`prev`, `further_prev`) and a tip (`trusted_through`) are never in a
//!   row's causal past (CC 2.7.3's exception; the crate reads them from the
//!   rows);
//! - **the precondition** ([`kernel_in_play`]);
//! - **the heads and their seat marks** ([`head_rows`], [`seat_mark`]):
//!   v62.0.0 (CONTENT-A1.rev2; CC 2.7.8, CC 3.3.4 as settled 11-23) — the
//!   room's heads are its LINEAGE nodes (a `group:roster` version, a counted
//!   widening or self-admission, a counted removal: `edition2::lineage`'s
//!   one predicate), and what a head is to the member is read from the
//!   lineage's ONE definition of who is seated at a head
//!   (`edition2::lineage::members_at`). This module decides no seat;
//! - **a row naming several heads** ([`RoomRow::several_heads`]): NOT JUDGED
//!   YET, never judged on a chosen head (KERNEL on tips 11-23, item 2: the
//!   crate models one head per row);
//! - **the member's own removal** ([`present_own_removals`]): its End and a
//!   Head marked `Out`, under two ids (KERNEL on tips 11-23, item 3; deleted
//!   at the kernel tag that reads it itself).
//!
//! **The member is the VOICE.** Every member, author and signer here is a
//! statement's `iss` or its payload's `author` / `member`, never the signing
//! `kid`. In a private room `iss` is the voice and `kid` the room key that
//! signed (Constitution), so the member is the voice, never the room key
//! (P/CONTENT-voice-read.md; I6731).
//!
//! The crate's answer is final per row. Persist stores it (CONTENT-A6) and
//! reads it (CONTENT-A7); this module neither stores nor reads the store
//! beyond the statements and names it is handed or preloads.

use std::collections::{BTreeMap, BTreeSet};

use ciris_kernel::content::{self, Answers, ContentRow, Kind, Seat, SeatAt};
use ciris_verify_core::cde::Value;
use ciris_verify_core::namespace_match;

use crate::federation::edition2::group::{
    GROUP_ROSTER_PREFIX, KEEPS_LEAF, MEMBERSHIP_PREFIX, REMOVAL_LEAF, RESIGNATION_LEAF,
};
use crate::federation::edition2::lineage::{self, HeadOf, LineageNode};
use crate::federation::edition2::liveness::statement_parts;
use crate::federation::edition2::names::{names_of, single, Name, RowId};
use crate::federation::group_plane::GroupKind;
use crate::federation::{Error, FederationDirectory};

/// The synthetic key every COUNTED row of the room signs as, to the crate
/// (a counted removal, a counted `keeps` row): its voices are the count's,
/// and the count is one signer to the rule ([`Seat::counted`]).
pub const COUNT: &str = "count";

/// The `refs` roles that are a row's CAUSAL names: what its past is read
/// through. `prev`, `further_prev` and `trusted_through` are not among them
/// (nothing waits on them, and the crate reads them from the rows).
pub const CAUSAL_ROLES: &[&str] = &["head", "further_heads", "target", "answers"];

/// How far one row's causal past is walked (as
/// [`crate::federation::edition2::group::MAX_ROSTER_CHAIN`]).
pub const MAX_PAST: usize = 4096;

/// The room a call is about: its placement and its group's identity-ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Room {
    /// `community`, `affiliations` or `family`.
    pub scope: String,
    /// The group's identity-ref (`community_key_id` / `family_key_id`).
    pub group: String,
}

/// One held row as the crate reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoomRow {
    /// The row id.
    pub id: RowId,
    /// What it is to the member's seat.
    pub kind: Kind,
    /// The signing key's identity-ref (`iss`), or [`COUNT`] for a counted
    /// row.
    pub signer: String,
    /// `refs.head`.
    pub head: Option<RowId>,
    /// `refs.prev` and `refs.further_prev`.
    pub prev: Vec<RowId>,
    /// `refs.trusted_through`.
    pub tips: Vec<RowId>,
    /// The row a retraction retracts.
    pub retracts: Option<RowId>,
    /// The end a `keeps` row cites.
    pub extends: Option<RowId>,
    /// On a head: what the version is to the member ([`seat_mark`]).
    pub seat: SeatAt,
    /// v62.0.0 (CONTENT-A1.rev2) — a content row naming SEVERAL heads
    /// (`refs.further_heads` beside `refs.head`). The crate models one head
    /// per row (KERNEL on tips 11-23, item 2), so such a row is never handed
    /// to it ([`answers`] / [`changed`] leave it out) and is NOT JUDGED YET
    /// ([`not_judged`]). A retraction is never so marked: it takes effect
    /// whenever it is signed, whatever head it names.
    pub several_heads: bool,
}

impl ContentRow for RoomRow {
    type Id = RowId;
    type Key = String;
    fn id(&self) -> &RowId {
        &self.id
    }
    fn kind(&self) -> Kind {
        self.kind
    }
    fn signer(&self) -> &String {
        &self.signer
    }
    fn head(&self) -> Option<&RowId> {
        self.head.as_ref()
    }
    fn prev(&self) -> &[RowId] {
        &self.prev
    }
    fn tips(&self) -> &[RowId] {
        &self.tips
    }
    fn retracts(&self) -> Option<&RowId> {
        self.retracts.as_ref()
    }
    fn extends(&self) -> Option<&RowId> {
        self.extends.as_ref()
    }
    fn seat(&self) -> SeatAt {
        self.seat
    }
}

/// What kind of end of a seat a membership row is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndOf {
    /// A `membership:removal`: the group's COUNTED end.
    Removal,
    /// A `membership:resignation`: the member's OWN end.
    Resignation,
}

/// **THE end classification (one function; the leaf decides).** A
/// `membership:{stage}` row that is not a composer is an end of `member`'s
/// seat in `group` by its leaf: `removal` is the count's end, `resignation`
/// the member's own. A removal voiced only by the removed member is still a
/// removal: short of its count and held, never a resignation (Constitution's
/// ruling on persist's question 2). `None` for every other row.
#[must_use]
pub fn end_of(protected: &Value, payload: &Value, group: &str, member: &str) -> Option<EndOf> {
    let leaf = membership_leaf(protected, payload)?;
    if text(payload, "group") != Some(group) || text(payload, "member") != Some(member) {
        return None;
    }
    match leaf {
        l if l == REMOVAL_LEAF => Some(EndOf::Removal),
        l if l == RESIGNATION_LEAF => Some(EndOf::Resignation),
        _ => None,
    }
}

/// v62.0.0 (CONTENT-A1.rev2; replaces A1's BLOCKED `seat_at`) — **what a
/// lineage head is to the member**, read from the lineage's ONE definition
/// of who is seated at a head (`edition2::lineage::members_at`, the kernel's
/// seats over the lineage): `Out` where `member` is not seated at `node`;
/// `Admits` where it is seated there and not at the heads `node` extends
/// (a founding version extends none: its listed members are admitted
/// there); `Sits` otherwise. A re-admission after a removal is therefore a
/// new seat (`Admits`), and a row naming a head after the removal and before
/// it belongs to no seat (`Out`).
///
/// A JOIN naming two tips where only one seated the member reads `Admits`
/// (the members at several heads are those common to all, kernel-v0.2.2):
/// the strict fold at the kernel pin changes `members_at`, not this.
///
/// # Errors
/// Directory reads.
pub async fn seat_mark<F>(dir: &F, node: &LineageNode, member: &str) -> Result<SeatAt, Error>
where
    F: FederationDirectory + ?Sized,
{
    let at = lineage::members_at(dir, std::slice::from_ref(&node.row_id)).await?;
    if !at.members.contains(member) {
        return Ok(SeatAt::Out);
    }
    if node.extends.is_empty() {
        return Ok(SeatAt::Admits);
    }
    let before = lineage::members_at(dir, &node.extends).await?;
    Ok(if before.members.contains(member) {
        SeatAt::Sits
    } else {
        SeatAt::Admits
    })
}

/// The group kind a room's placement is a group of.
fn kind_of_scope(scope: &str) -> GroupKind {
    if scope == crate::federation::types::cohort_scope::FAMILY {
        GroupKind::Family
    } else {
        GroupKind::Community
    }
}

/// v62.0.0 (CONTENT-A1.rev2) — **the room's heads the crate is handed for
/// `member`**, and the member's own removals among the room's nodes.
///
/// The heads are the room's lineage nodes (`group_lineage_nodes`, the
/// lineage's one predicate) that `named` names (the heads the member's
/// rows and ends name), and every node that can ADMIT the member: each
/// restating version, and each widening or self-admission of the member
/// (the crate reads a row's seat from the admitting heads in its head's
/// past). Each is marked by [`seat_mark`]. The member's own counted
/// removals are not among the heads: they are returned apart for
/// [`present_own_removals`]. A named head that is no node of the room is not
/// presented (the crate answers the rows naming it `Undecided` on it).
///
/// # Errors
/// Directory reads.
pub async fn head_rows<F>(
    dir: &F,
    room: &Room,
    member: &str,
    named: &BTreeSet<RowId>,
) -> Result<(Vec<RoomRow>, BTreeSet<RowId>), Error>
where
    F: FederationDirectory + ?Sized,
{
    let kind = kind_of_scope(&room.scope);
    let mut heads = Vec::new();
    let mut own_removals = BTreeSet::new();
    for n in dir.group_lineage_nodes(&room.group).await? {
        if n.group_kind != kind || n.group != room.group {
            continue;
        }
        let of_member = n.subject.as_deref() == Some(member);
        let can_admit = match n.head_of {
            HeadOf::Roster => true,
            HeadOf::Widening | HeadOf::SelfAdmission => of_member,
            HeadOf::Removal => {
                if of_member {
                    own_removals.insert(n.row_id);
                    continue;
                }
                false
            }
        };
        if !can_admit && !named.contains(&n.row_id) {
            continue;
        }
        heads.push(RoomRow {
            id: n.row_id,
            kind: Kind::Head,
            signer: COUNT.to_owned(),
            head: None,
            prev: Vec::new(),
            tips: Vec::new(),
            retracts: None,
            extends: None,
            seat: seat_mark(dir, &n, member).await?,
            several_heads: false,
        });
    }
    Ok((heads, own_removals))
}

/// The heads `rows` name (a content row's, an end's, a `keeps` row's).
#[must_use]
pub fn named_heads(rows: &[RoomRow]) -> BTreeSet<RowId> {
    rows.iter()
        .filter(|r| r.kind != Kind::Head)
        .filter_map(|r| r.head)
        .collect()
}

/// v62.0.0 (CONTENT-A1.rev2) — the second id under which the member's own
/// removal `end` is presented as a head ([`present_own_removals`]): a label
/// this node computes, never a row id a peer can name.
#[must_use]
pub fn own_removal_head_id(end: &RowId) -> RowId {
    RowId(
        crate::kernel::view::RowId::of_label(&["content-own-removal-head", &hex::encode(end.0)]).0,
    )
}

/// v62.0.0 (CONTENT-A1.rev2; **KERNEL on tips 11-23, item 3**) — **the
/// member's own removal, presented twice.** A counted removal of the member
/// is the member's End AND a lineage head. In a call for anyone else it is
/// only a head ([`head_rows`]). In a call for the member (the kernel-v0.2.2
/// form) it is:
///
/// - the End, as handed in (it names the head it acts from, with its tips);
/// - a Head marked `Out` under a second id ([`own_removal_head_id`]),
///   naming that same predecessor head, with the End in its past.
///
/// Every row of the member that names the removal as its head is given the
/// second id, and `past` answers for the second id as for the row itself
/// ([`HeldPast::alias`]). A removal in `own_removals` that is not among
/// `rows` as an End (not retained) is not presented.
///
/// DELETE this function, [`own_removal_head_id`] and [`HeldPast::alias`]
/// when the kernel tag carrying CIRISKernel PR #36 is pinned: the crate
/// then reads an End a row names as its head as a head at which the member
/// is out, and the removal is handed in once, as the End.
pub fn present_own_removals(
    rows: &mut Vec<RoomRow>,
    own_removals: &BTreeSet<RowId>,
    past: &mut HeldPast,
) {
    let ends: Vec<(RowId, Option<RowId>)> = rows
        .iter()
        .filter(|r| r.kind == Kind::End && own_removals.contains(&r.id))
        .map(|r| (r.id, r.head))
        .collect();
    for (end, predecessor) in ends {
        let second = own_removal_head_id(&end);
        for r in rows.iter_mut() {
            if r.kind != Kind::Head && r.head == Some(end) {
                r.head = Some(second);
            }
        }
        rows.push(RoomRow {
            id: second,
            kind: Kind::Head,
            signer: COUNT.to_owned(),
            head: predecessor,
            prev: Vec::new(),
            tips: Vec::new(),
            retracts: None,
            extends: None,
            seat: SeatAt::Out,
            several_heads: false,
        });
        past.alias(second, end);
    }
}

fn text<'a>(v: &'a Value, k: &str) -> Option<&'a str> {
    v.get_text(k).and_then(Value::as_text)
}

fn membership_leaf<'a>(protected: &Value, payload: &'a Value) -> Option<&'a str> {
    let family = protected.get_int(-70002).and_then(Value::as_text)?;
    let row_type = protected.get_int(-70001).and_then(Value::as_text)?;
    if family != namespace_match::family_id(MEMBERSHIP_PREFIX)
        || crate::federation::edition2::emit::names_a_target(row_type)
    {
        return None;
    }
    crate::federation::edition2::payloads::leaf_of(MEMBERSHIP_PREFIX, payload)
}

fn iss_of(protected: &Value) -> Option<String> {
    protected
        .get_int(15)?
        .get_int(1)?
        .as_text()
        .map(str::to_owned)
}

fn all(names: &[Name], role: &str) -> Vec<RowId> {
    names
        .iter()
        .filter(|n| n.role == role)
        .map(|n| n.row)
        .collect()
}

/// The room a payload is placed at: its `cohort_scope` and its target alias
/// (`admission::COHORT_TARGET_ENVELOPE_FIELDS`, first populated).
fn placed_at(payload: &Value) -> Option<(&str, &str)> {
    let scope = text(payload, "cohort_scope")?;
    let target = crate::federation::admission::COHORT_TARGET_ENVELOPE_FIELDS
        .iter()
        .find_map(|f| text(payload, f).filter(|t| !t.is_empty()))?;
    Some((scope, target))
}

/// **One held statement as the crate reads it, for `member` in `room`**:
/// a roster version of the room (Head), the member's room content
/// (`edition2::room_content::is_room_content`, Content), an end of the
/// member's seat ([`end_of`], End), a `membership:keeps` row of the member
/// (Tips), or `None` (the crate is not handed it). A composer (an edit, a
/// retraction) is [`composer_row`]'s: it carries no dimension, so its
/// family alone does not place it.
#[must_use]
pub fn room_row(statement: &[u8], room: &Room, member: &str) -> Option<RoomRow> {
    let id = RowId::of_statement(statement)?;
    let (protected, payload) = statement_parts(statement)?;
    let family = protected.get_int(-70002).and_then(Value::as_text)?;
    let row_type = protected.get_int(-70001).and_then(Value::as_text)?;
    let iss = iss_of(&protected)?;
    let names = names_of(&payload).ok()?;
    let mut row = RoomRow {
        id,
        kind: Kind::Other,
        signer: iss,
        head: single(&names, "head"),
        prev: Vec::new(),
        tips: all(&names, "trusted_through"),
        retracts: None,
        extends: None,
        seat: SeatAt::Sits,
        several_heads: false,
    };
    if crate::federation::edition2::emit::names_a_target(row_type) {
        return None;
    }
    // v62.0.0 (CONTENT-A1.rev2) — a roster version is a head, and the heads
    // are the lineage's ([`head_rows`]), never mapped from bytes here.
    if family == namespace_match::family_id(GROUP_ROSTER_PREFIX) {
        return None;
    }
    if let Some(end) = end_of(&protected, &payload, &room.group, member) {
        row.kind = Kind::End;
        if end == EndOf::Removal {
            row.signer = COUNT.to_owned();
        }
        return Some(row);
    }
    if membership_leaf(&protected, &payload) == Some(KEEPS_LEAF) {
        if text(&payload, "group") != Some(room.group.as_str())
            || text(&payload, "member") != Some(member)
        {
            return None;
        }
        row.kind = Kind::Tips;
        row.extends = single(&names, "also:cites");
        if payload.get_text("author").is_none() {
            row.signer = COUNT.to_owned();
        }
        return Some(row);
    }
    let dimension = text(&payload, "dimension");
    let (scope, target) = placed_at(&payload)?;
    if scope != room.scope
        || target != room.group
        || !crate::federation::edition2::room_content::is_room_content(family, dimension, scope)
        || text(&payload, "author") != Some(member)
    {
        return None;
    }
    row.kind = Kind::Content;
    row.tips.clear();
    row.prev = all(&names, "prev");
    row.prev.extend(all(&names, "further_prev"));
    row.several_heads = !all(&names, "further_heads").is_empty();
    Some(row)
}

/// **A composer on one of the member's content rows**, as the crate reads
/// it: an EDIT (`supersedes`) is a Content row like any other (its own
/// head and predecessors); a RETRACTION (`withdraws` / `recants`) is a
/// Content row that `retracts` its target. `content` is the ids [`room_row`]
/// mapped to Content; a composer whose target is not one of them is
/// `None`. Whether a retraction is the member's own is the crate's
/// (`seat.member` over its signer).
#[must_use]
pub fn composer_row(statement: &[u8], content: &BTreeSet<RowId>) -> Option<RoomRow> {
    use crate::federation::types::attestation_type as at;
    let id = RowId::of_statement(statement)?;
    let (protected, payload) = statement_parts(statement)?;
    let row_type = protected.get_int(-70001).and_then(Value::as_text)?;
    let names = names_of(&payload).ok()?;
    let target = single(&names, "target")?;
    if !content.contains(&target) {
        return None;
    }
    let mut prev = all(&names, "prev");
    prev.extend(all(&names, "further_prev"));
    let retracts = match row_type {
        t if t == at::WITHDRAWS || t == at::RECANTS => Some(target),
        t if t == at::SUPERSEDES => None,
        _ => return None,
    };
    // An edit naming several heads is not judged yet; a retraction takes
    // effect whatever head it names.
    let several_heads = retracts.is_none() && !all(&names, "further_heads").is_empty();
    Some(RoomRow {
        id,
        kind: Kind::Content,
        signer: iss_of(&protected)?,
        head: single(&names, "head"),
        prev,
        tips: Vec::new(),
        retracts,
        extends: None,
        seat: SeatAt::Sits,
        several_heads,
    })
}

/// **The member's keys**: `member` itself and the `iss` of every statement
/// among `statements` whose payload `author` is `member`. The person across
/// their keys (a second device's retraction is the author's own); an
/// agent's keys only, for an agent member (its owner authors as itself).
#[must_use]
pub fn member_keys(statements: &[Vec<u8>], member: &str) -> BTreeSet<String> {
    let mut out: BTreeSet<String> = BTreeSet::from([member.to_owned()]);
    for st in statements {
        if let Some((protected, payload)) = statement_parts(st) {
            if text(&payload, "author") == Some(member) {
                if let Some(iss) = iss_of(&protected) {
                    out.insert(iss);
                }
            }
        }
    }
    out
}

/// **Every row of `member` in `room` the crate is handed**, from the held
/// `statements` (each voice of a row maps to the same row; one is kept):
/// [`room_row`] first, then [`composer_row`] over the content it found.
#[must_use]
pub fn rows_of(statements: &[Vec<u8>], room: &Room, member: &str) -> Vec<RoomRow> {
    let mut by: BTreeMap<RowId, RoomRow> = BTreeMap::new();
    for st in statements {
        if let Some(r) = room_row(st, room, member) {
            by.entry(r.id).or_insert(r);
        }
    }
    let content: BTreeSet<RowId> = by
        .values()
        .filter(|r| r.kind == Kind::Content)
        .map(|r| r.id)
        .collect();
    for st in statements {
        if let Some(r) = composer_row(st, &content) {
            by.entry(r.id).or_insert(r);
        }
    }
    by.into_values().collect()
}

/// **The precondition (CONTENT-A1): the crate is called for a (member,
/// room) only once an end of that member's seat is held.** The crate's
/// documented property (`ciris_kernel::content` module doc, "With no end
/// among the rows, nothing here is in play"; its test
/// `no_end_among_the_rows`): with no End among the rows, every content row
/// of the member that names a head at which it sits is counted, and in force
/// unless the member's own retraction of it is held (`no_end` /
/// `W.retracted`). Persist's existing retraction handling answers those
/// rows; this function says when the crate is in play.
#[must_use]
pub fn kernel_in_play(rows: &[RoomRow]) -> bool {
    rows.iter().any(|r| r.kind == Kind::End)
}

/// **The held causal past**, preloaded for the crate's synchronous `Past`:
/// for each row, the ids it reaches through [`CAUSAL_ROLES`] and `also:*`
/// (never `prev`, `further_prev`, `trusted_through`), and the first row the
/// walk met that is not held. `in_past(a, b)`: `a` reached from `b` ⇒ true;
/// else an unheld row on `b`'s walk ⇒ `Err(that row)` (persist holds the
/// answer and waits on it); else false.
#[derive(Clone, Debug, Default)]
pub struct HeldPast {
    reach: BTreeMap<RowId, (BTreeSet<RowId>, Option<RowId>)>,
    /// v62.0.0 (CONTENT-A1.rev2; [`present_own_removals`]) — a second id →
    /// the row it presents.
    aliases: BTreeMap<RowId, RowId>,
}

fn causal(role: &str) -> bool {
    CAUSAL_ROLES.contains(&role) || role.starts_with("also:")
}

/// A statement's causal names ([`CAUSAL_ROLES`] and `also:*`).
fn causal_names(statement: &[u8]) -> Option<Vec<RowId>> {
    let (_, payload) = statement_parts(statement)?;
    let names = names_of(&payload).ok()?;
    Some(
        names
            .into_iter()
            .filter(|n| causal(&n.role))
            .map(|n| n.row)
            .collect(),
    )
}

impl HeldPast {
    /// Walk each of `roots` through the causal names of the held
    /// statements, `offered` first (statements the caller holds in hand: a
    /// row being admitted now, before the store has it).
    ///
    /// # Errors
    /// Directory reads.
    pub async fn preload<F>(dir: &F, roots: &[RowId], offered: &[Vec<u8>]) -> Result<Self, Error>
    where
        F: FederationDirectory + ?Sized,
    {
        let mut direct: BTreeMap<RowId, Option<Vec<RowId>>> = BTreeMap::new();
        for st in offered {
            if let (Some(id), Some(ns)) = (RowId::of_statement(st), causal_names(st)) {
                direct.insert(id, Some(ns));
            }
        }
        let mut out = Self::default();
        for root in roots {
            let mut seen: BTreeSet<RowId> = BTreeSet::new();
            let mut unheld: Option<RowId> = None;
            let mut todo: Vec<RowId> = vec![*root];
            while let Some(id) = todo.pop() {
                if seen.len() >= MAX_PAST {
                    unheld = unheld.or(Some(id));
                    break;
                }
                if let std::collections::btree_map::Entry::Vacant(slot) = direct.entry(id) {
                    let voices = dir.edition2_voices(&id).await?;
                    let names = voices
                        .iter()
                        .find(|st| RowId::of_statement(st) == Some(id))
                        .and_then(|st| causal_names(st));
                    slot.insert(names);
                }
                match &direct[&id] {
                    None if id != *root => unheld = unheld.or(Some(id)),
                    None => {}
                    Some(ns) => {
                        for n in ns {
                            if seen.insert(*n) {
                                todo.push(*n);
                            }
                        }
                    }
                }
            }
            out.reach.insert(*root, (seen, unheld));
        }
        Ok(out)
    }

    /// From precomputed reach sets (tests; a caller that walked already).
    #[must_use]
    pub fn of(reach: BTreeMap<RowId, (BTreeSet<RowId>, Option<RowId>)>) -> Self {
        Self {
            reach,
            aliases: BTreeMap::new(),
        }
    }

    /// v62.0.0 (CONTENT-A1.rev2; KERNEL on tips 11-23, item 3; deleted with
    /// [`present_own_removals`]) — answer for `second` as for `of`, with `of`
    /// itself in `second`'s past (the Head presentation of an End names it).
    pub fn alias(&mut self, second: RowId, of: RowId) {
        self.aliases.insert(second, of);
    }

    fn real<'a>(&'a self, id: &'a RowId) -> &'a RowId {
        self.aliases.get(id).unwrap_or(id)
    }

    /// Is `a` in the causal past of `b`, or the row that must be held to
    /// tell.
    ///
    /// # Errors
    /// The unheld row on `b`'s walk.
    pub fn in_past(&self, a: &RowId, b: &RowId) -> Result<bool, RowId> {
        if self.aliases.get(b) == Some(a) {
            return Ok(true);
        }
        let (a, b) = (self.real(a), self.real(b));
        match self.reach.get(b) {
            Some((r, _)) if r.contains(a) => Ok(true),
            Some((_, Some(unheld))) => Err(*unheld),
            Some((_, None)) => Ok(false),
            None => Err(*b),
        }
    }
}

/// The crate's `Seat` over `keys` (the member's) and [`COUNT`].
fn with_seat<T>(keys: &BTreeSet<String>, f: impl FnOnce(&Seat<'_, String>) -> T) -> T {
    let member = |k: &String| keys.contains(k);
    let counted = |k: &String| k == COUNT;
    f(&Seat {
        member: &member,
        counted: &counted,
    })
}

/// **The crate's answers** for the member whose keys are `keys`, over
/// `rows` (one room), with `past`. Callers check [`kernel_in_play`] first.
#[must_use]
pub fn answers(rows: &[RoomRow], keys: &BTreeSet<String>, past: &HeldPast) -> Answers<RowId> {
    let refs: Vec<&RoomRow> = rows.iter().filter(|r| !r.several_heads).collect();
    let p = |a: &RowId, b: &RowId| past.in_past(a, b);
    with_seat(keys, |seat| content::answers(&refs, seat, &p))
}

/// **What one arriving row changes** (the crate's `changed`): the member's
/// rows whose answer moved, with the new answer. `rows` holds `arrived`.
#[must_use]
pub fn changed(
    rows: &[RoomRow],
    arrived: &RowId,
    keys: &BTreeSet<String>,
    past: &HeldPast,
) -> Answers<RowId> {
    let refs: Vec<&RoomRow> = rows.iter().filter(|r| !r.several_heads).collect();
    let p = |a: &RowId, b: &RowId| past.in_past(a, b);
    with_seat(keys, |seat| content::changed(&refs, arrived, seat, &p))
}

/// v62.0.0 (CONTENT-A1.rev2) — **the member's rows NOT JUDGED YET**: the
/// content rows naming several heads ([`RoomRow::several_heads`]), which
/// [`answers`] leaves out. Their answer waits on no row (Kernel extends the
/// crate to several heads once the fold at tips settles).
#[must_use]
pub fn not_judged(rows: &[RoomRow]) -> Vec<RowId> {
    rows.iter()
        .filter(|r| r.kind == Kind::Content && r.several_heads)
        .map(|r| r.id)
        .collect()
}

/// Every row id a call over `rows` may ask the past about: each row's own
/// id (the past is asked of ends and heads in a row's past).
#[must_use]
pub fn past_roots(rows: &[RoomRow]) -> Vec<RowId> {
    rows.iter().map(|r| r.id).collect()
}
