//! v62.0.0 (wave T1) — **who is served a statement that maps to no
//! attestation row.**
//!
//! [`super::serve::servable_to`] decides a statement's audience from the
//! attestation row it maps to. Several families keep their statements in
//! `ceg_statements` ONLY, with no `federation_attestations` row:
//! - the group planes (`group:roster`, and `membership:{stage}` at
//!   `widening` / `removal`), which land in their typed tables
//!   ([`super::group`]);
//! - a counted row whose voices are still short of its protocol
//!   (`StatementOutcome::Pending`);
//! - other statement-only families (cosign voices, admission units, ...).
//!
//! Withholding all of them, the old rule, meant a group never replicated:
//! the member's node could not learn its own roster. This module decides the
//! audience from the statement itself, with the same rules the JSON group
//! plane used (`replication_audience::may_receive_group_plane`):
//!
//! - **a group voice** is served to:
//!   - the group's audience as this node holds it: a public group's to every
//!     peer; otherwise the members' nodes, live invitees' nodes, and the node
//!     of the member the row names (for a removal, the removed member);
//!   - AND the members at the roster head the row names (`refs.head`), the
//!     members a roster version itself lists (a founding or a version still
//!     gathering voices must reach the members who are to sign it), and the
//!     held record's founders.
//!
//!   "Node of" is the principal fold (`self_collective::principals_of`).
//! - **any other statement** follows the scope it states (the CC 2.1
//!   `cohort_scope` payload member):
//!   - a commons scope is served to anyone;
//!   - a self / family / room scope only to a requester in its audience
//!     (`replication::hold::is_audience`, with the target from the payload's
//!     cohort-target member);
//!   - a statement that states no scope reads as `federation` (the
//!     attestation default; ruling), so it is served as the commons.
//!
//! - **a `cosign:{pending,signature}` voice** carries no scope of its own:
//!   it is served exactly to the audience of the event it cosigns, the row
//!   its `refs.target` names (a group voice, or a held row under its row's
//!   rule), read through `serve::servable_to` on that event's statement. A
//!   cosign naming a cosign is followed to its event, at most
//!   [`MAX_COSIGN_HOPS`]. An event this node does not hold is withheld.
//! - **`admission:unit`** (CC ruling): served by its OWN `cohort_scope`,
//!   like any scores row, through the scope rule below: an owner-alone unit
//!   is at `self` (its author's own hosts only), a counted unit at whatever
//!   scope its signers chose. No special case.
//!
//! - **no blanket "about the requester" rule** (CC 2.1): a statement that
//!   merely names a key is served by its scope rule like any other; the
//!   delivered key (an invitee, a grant recipient, an owner-binding's node)
//!   is the row path's ([`delivered_to_requester`]).
//!
//! Anonymous reads (no requester) are served the commons only, as before.

use std::collections::BTreeSet;

use ciris_verify_core::cde::Value;

use super::group::{
    group_plane_of, membership_of, roster_view, roster_view_of_statement, GroupPlane,
};
use super::ingest::json_of;
use super::liveness::statement_parts;
use super::names::{names_of, single};
use crate::federation::types::cohort_scope as cs;
use crate::federation::{Error, FederationDirectory};

/// The listed members' key ids of a `group:roster` payload.
fn listed_members(payload: &Value) -> BTreeSet<String> {
    payload
        .get_text("members")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|m| m.get_text("key").and_then(Value::as_text))
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// **May `requester` be served a statement this node holds no attestation
/// row for?** See the module doc. Called by `serve::servable_to` after its
/// purge check.
///
/// # Errors
/// Directory reads.
pub async fn servable_without_row<F>(
    dir: &F,
    statement: &[u8],
    requester: Option<&str>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some((protected, payload)) = statement_parts(statement) else {
        return Ok(false);
    };
    let text = |label: i64| protected.get_int(label).and_then(Value::as_text);
    let (Some(row_type), Some(family)) = (text(-70001), text(-70002)) else {
        return Ok(false);
    };
    let claims = protected.get_int(15);
    let sub = claims.and_then(|c| c.get_int(2)).and_then(Value::as_text);
    let iss = claims.and_then(|c| c.get_int(1)).and_then(Value::as_text);
    if family == ciris_verify_core::namespace_match::family_id(super::typed::COSIGN_PREFIX) {
        return cosign_servable(dir, &payload, requester).await;
    }
    if let Some(plane) = group_plane_of(row_type, family, &payload) {
        let Some(sub) = sub else {
            return Ok(false);
        };
        return Box::pin(group_servable(dir, plane, sub, &payload, requester)).await;
    }
    let Some(iss) = iss else {
        return Ok(false);
    };
    scope_servable(dir, iss, sub, statement, &payload, requester).await
}

/// How many `cosign` statements a cosign's `refs.target` chain follows to
/// reach the event.
pub const MAX_COSIGN_HOPS: usize = 4;

/// `serve::servable_to` behind a named, `Send` trait object: the cosign rule
/// asks it of the event a cosign names, and `servable_to` reaches the cosign
/// rule again only through this box, so the future's type is not recursive.
fn event_servable<'a, F>(
    dir: &'a F,
    statement: &'a [u8],
    requester: Option<&'a str>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool, Error>> + Send + 'a>>
where
    F: FederationDirectory + ?Sized,
{
    Box::pin(super::serve::servable_to(dir, statement, requester))
}

/// A cosign voice's audience: the audience of the event it cosigns.
async fn cosign_servable<F>(
    dir: &F,
    payload: &Value,
    requester: Option<&str>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let cosign = ciris_verify_core::namespace_match::family_id(super::typed::COSIGN_PREFIX);
    let mut payload = payload.clone();
    for _ in 0..MAX_COSIGN_HOPS {
        let Ok(names) = names_of(&payload) else {
            return Ok(false);
        };
        let Some(target) = single(&names, super::typed::TARGET_ROLE) else {
            return Ok(false);
        };
        let held = dir.edition2_voices(&target).await?;
        let Some(event) = held.first() else {
            return Ok(false);
        };
        let Some((protected, next)) = statement_parts(event) else {
            return Ok(false);
        };
        if protected.get_int(-70002).and_then(Value::as_text) == Some(cosign.as_str()) {
            payload = next;
            continue;
        }
        return event_servable(dir, event, requester).await;
    }
    Ok(false)
}

/// A group voice's audience.
async fn group_servable<F>(
    dir: &F,
    plane: GroupPlane,
    sub: &str,
    payload: &Value,
    requester: Option<&str>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(peer) = requester else {
        return Ok(false);
    };
    // What the row names: its group, the member it names, the head it is
    // counted over, the members it lists. A payload that does not read is
    // served to no one (it was admitted, so this is unreachable in practice).
    let (kind, group, named, head, mut party) = match plane {
        GroupPlane::Roster => {
            let Ok(v) = roster_view(sub, payload) else {
                return Ok(false);
            };
            let listed = listed_members(payload);
            (v.kind, v.group, None, v.head, listed)
        }
        GroupPlane::Widening | GroupPlane::Removal => {
            let Ok((v, _)) = membership_of(plane, sub, payload) else {
                return Ok(false);
            };
            (v.kind, v.group, Some(v.member), v.head, BTreeSet::new())
        }
    };
    if crate::federation::replication_audience::may_receive_group_plane(
        dir,
        peer,
        kind.as_str(),
        &group,
        named.as_deref(),
    )
    .await?
    .allowed()
    {
        return Ok(true);
    }
    // The members at the named head.
    if let Some(h) = head {
        if let Some(st) = dir.edition2_voices(&h).await?.first() {
            if let Ok(v) = roster_view_of_statement(st) {
                if v.group == group && v.kind == kind {
                    party.extend(listed_members(&v.payload));
                }
            }
        }
    }
    // The held record's founders.
    let founder = Some(crate::federation::admission::MEMBER_ROLE_FOUNDER);
    match kind {
        crate::federation::group_plane::GroupKind::Family => {
            if let Some(f) = dir.lookup_family(&group).await? {
                party.extend(
                    f.members
                        .into_iter()
                        .filter(|m| m.role.as_deref() == founder)
                        .map(|m| m.key_id),
                );
            }
        }
        crate::federation::group_plane::GroupKind::Community => {
            if let Some(c) = dir.lookup_community(&group).await? {
                party.extend(
                    c.members
                        .into_iter()
                        .filter(|m| m.role.as_deref() == founder)
                        .map(|m| m.key_id),
                );
            }
        }
    }
    if party.is_empty() {
        return Ok(false);
    }
    if party.contains(peer) {
        return Ok(true);
    }
    let principals = crate::federation::self_collective::principals_of(dir, peer).await?;
    Ok(principals.iter().any(|p| party.contains(p)))
}

/// v62.0.0 (wave T1; CC 2.1, "whom a targeted row may name") — **the keys
/// a row's family DELIVERS it to**, beyond the members at its head: a
/// membership proposal's invitee (`subject_key_ids`), a key grant's recipient
/// (`attested_key_id`), the owner's own node on an owner-binding (the bound
/// device). Empty for every other row: a row about a key reaches it only
/// through the audience rule.
#[must_use]
pub fn delivered_keys(row: &crate::federation::types::Attestation) -> Vec<String> {
    use crate::federation::membership_acceptance::{membership_row, MembershipRow};
    if membership_row(row) == Some(MembershipRow::Proposal) {
        return row.subject_key_ids.clone();
    }
    if crate::federation::key_grant::is_key_grant_row(row) {
        return vec![row.attested_key_id.clone()];
    }
    if let Some((_owner, node)) = crate::federation::owner_binding_of(row) {
        return vec![node];
    }
    Vec::new()
}

/// **Is `row` delivered to the requester?** The requester is one of
/// [`delivered_keys`], or a principal it acts for
/// (`self_collective::principals_of`: an invitee's node is served the
/// invitation delivered to its person).
///
/// # Errors
/// Directory reads.
pub async fn delivered_to_requester<F>(
    dir: &F,
    row: &crate::federation::types::Attestation,
    peer: &str,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let delivered: BTreeSet<String> = delivered_keys(row)
        .into_iter()
        .filter(|k| !k.is_empty())
        .collect();
    if delivered.is_empty() {
        return Ok(false);
    }
    if delivered.contains(peer) {
        return Ok(true);
    }
    let principals = crate::federation::self_collective::principals_of(dir, peer).await?;
    Ok(principals.iter().any(|p| delivered.contains(p)))
}

/// Any other statement-only row: the scope its payload states. `self` (and
/// `family`) go to `is_audience`'s self arm: the requester IS the author, or
/// a node whose owner principal is the author's and whose class lets the
/// author's `self` content reach it (`owner_node_receives`, the claimed-
/// nodes rule): the author's own hosts only. The author is the voice's
/// `iss` (an authored row's author signs it; each voice of a counted row is
/// judged by its own signer).
async fn scope_servable<F>(
    dir: &F,
    iss: &str,
    sub: Option<&str>,
    statement: &[u8],
    payload: &Value,
    requester: Option<&str>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    // One rule everywhere (ruling): an absent `cohort_scope` reads as
    // `federation`, the attestation default (`Attestation::cohort_scope`) and
    // P1e's `admission:unit` rule (an owner-alone row must state `self`).
    let scope = payload
        .get_text("cohort_scope")
        .and_then(Value::as_text)
        .unwrap_or(cs::FEDERATION);
    let placement = cs::Scope::parse(scope).map(cs::Scope::placement);
    match (placement, requester) {
        // v62.0.0 (RL-fix1; CC 5.3.4) — a federation-tier statement waits
        // for a root on a node that reaches none, unless the text lets it
        // cross (`serve::commons_servable`): its author and its subject are
        // the parties.
        (Some(cs::Placement::Commons), _) => {
            Box::pin(super::serve::commons_servable(
                dir,
                statement,
                requester,
                &[iss, sub.unwrap_or("")],
                false,
            ))
            .await
        }
        (None, _) | (Some(_), None) => Ok(false),
        (Some(_), Some(peer)) => {
            let envelope = json_of(payload);
            let target =
                crate::federation::admission::envelope_cohort_target(&envelope).unwrap_or(None);
            crate::federation::replication::hold::is_audience(
                dir,
                scope,
                target,
                iss,
                |author| author == peer,
                peer,
            )
            .await
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The copy rule: a row carries its audience to the rows it names
// ─────────────────────────────────────────────────────────────────────────

/// The `refs` roles a row names another row under (CC 2.6.1.3), as
/// `ceg_row_names` stores them.
pub const NAMING_ROLES: &[&str] = &[
    "also:cites",
    "also:ack",
    "head",
    "further_heads",
    "target",
    "prev",
    "answers",
    "trusted_through",
];

/// A statement's CWT `iss`.
fn statement_iss(statement: &[u8]) -> Option<String> {
    let (protected, _) = statement_parts(statement)?;
    protected
        .get_int(15)?
        .get_int(1)?
        .as_text()
        .map(str::to_owned)
}

/// **The room a statement sits in**: its scope and the scope's target, as
/// this node reads it. A group voice's room is its group (`family` /
/// `community` and the group key); a row with an attestation row, its
/// `cohort_scope` and cohort target; any other statement, its payload's
/// `cohort_scope` (absent: `federation`) and cohort target. A `self` room is
/// its author's self (the target is the signer, `iss`). `None` for bytes
/// that do not read.
///
/// # Errors
/// Directory reads.
pub async fn room_of<F>(
    dir: &F,
    statement: &[u8],
) -> Result<Option<(String, Option<String>)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some((protected, payload)) = statement_parts(statement) else {
        return Ok(None);
    };
    let text = |label: i64| protected.get_int(label).and_then(Value::as_text);
    let (Some(row_type), Some(family)) = (text(-70001), text(-70002)) else {
        return Ok(None);
    };
    let claims = protected.get_int(15);
    let sub = claims.and_then(|c| c.get_int(2)).and_then(Value::as_text);
    let iss = claims.and_then(|c| c.get_int(1)).and_then(Value::as_text);
    if let (Some(plane), Some(sub)) = (group_plane_of(row_type, family, &payload), sub) {
        let read = match plane {
            GroupPlane::Roster => roster_view(sub, &payload).map(|v| (v.kind, v.group)),
            GroupPlane::Widening | GroupPlane::Removal => {
                membership_of(plane, sub, &payload).map(|(v, _)| (v.kind, v.group))
            }
        };
        return Ok(read
            .ok()
            .map(|(kind, group)| (kind.as_str().to_owned(), Some(group))));
    }
    let Some(rid) = super::names::RowId::of_statement(statement) else {
        return Ok(None);
    };
    let (scope, target) = match dir.get_attestation(&rid.hex()).await? {
        Some(row) => {
            let target =
                crate::federation::admission::envelope_cohort_target(&row.attestation_envelope)
                    .unwrap_or(None)
                    .map(str::to_owned);
            (row.cohort_scope, target)
        }
        None => {
            let scope = payload
                .get_text("cohort_scope")
                .and_then(Value::as_text)
                .unwrap_or(cs::FEDERATION)
                .to_owned();
            let target = crate::federation::admission::envelope_cohort_target(&json_of(&payload))
                .unwrap_or(None)
                .map(str::to_owned);
            (scope, target)
        }
    };
    let target = if scope == cs::SELF {
        iss.map(str::to_owned)
    } else {
        target
    };
    Ok(Some((scope, target)))
}

/// v62.0.0 (T1-fix3; CC 2.7.5, "missing, and what is copied") — **does a
/// row naming this statement carry its audience to it, for `requester`?**
/// CC: "A row carries its audience to the rows it names when it is
/// concluded, sits in the same room, and its signer is already in the named
/// row's audience." For each held row `C` that names this statement's row
/// (under any [`NAMING_ROLES`] role, from `ceg_row_names`):
///
/// - `C` is concluded: no fold hold is recorded for it (`fold_held`);
/// - `C` sits in the same room ([`room_of`]);
/// - `C`'s signer is in this statement's audience by its own rule
///   (`serve::servable_by_own_rule` with the signer as the party);
/// - and `C` is served to `requester` by its own rule.
///
/// One hop: a row carried to `requester` does not in turn carry. Anonymous
/// reads are never carried (a carry only reaches a targeted room's
/// audience; a commons row is served to anyone already).
///
/// # Errors
/// Directory reads.
pub async fn carried_by_a_naming_row<F>(
    dir: &F,
    statement: &[u8],
    requester: Option<&str>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(peer) = requester else {
        return Ok(false);
    };
    let Some(named) = super::names::RowId::of_statement(statement) else {
        return Ok(false);
    };
    let Some(room) = room_of(dir, statement).await? else {
        return Ok(false);
    };
    let mut seen: BTreeSet<super::names::RowId> = BTreeSet::new();
    for role in NAMING_ROLES {
        for citer in dir.edition2_rows_naming(&named, role).await? {
            if !seen.insert(citer) {
                continue;
            }
            if dir.fold_held(&citer).await?.is_some() {
                continue;
            }
            let voices = dir.edition2_voices(&citer).await?;
            let Some(st) = voices.first() else {
                continue;
            };
            if room_of(dir, st).await?.as_ref() != Some(&room) {
                continue;
            }
            let Some(signer) = statement_iss(st) else {
                continue;
            };
            if !Box::pin(super::serve::servable_by_own_rule(
                dir,
                statement,
                Some(&signer),
            ))
            .await?
            {
                continue;
            }
            if Box::pin(super::serve::servable_by_own_rule(dir, st, Some(peer))).await? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
