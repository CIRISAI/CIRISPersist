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
//! - **a statement about the requester** (its `sub`, or an invitee in its
//!   `subject_key_ids`) is served to it, as a row about it is
//!   ([`names_the_requester`]): an invitee its own invitation.
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
    // A statement ABOUT the requester (its `sub`, or an invitee in its
    // `subject_key_ids`) is served to it, as for a row.
    if let Some(peer) = requester {
        let subjects: Vec<&str> = payload
            .get_text("subject_key_ids")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_text).collect())
            .unwrap_or_default();
        if names_the_requester(dir, sub.into_iter().chain(subjects), peer).await? {
            return Ok(true);
        }
    }
    scope_servable(dir, iss, &payload, requester).await
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

/// v62.0.0 (wave T1) — **is the requester one of `named`** (a row's
/// subject, an invitee it names)? The requester itself, or a principal it
/// acts for (`self_collective::principals_of`: a node's owner, an
/// occurrence's identity): an invitee's node is served the invitation about
/// its person. Empty names never match.
///
/// # Errors
/// Directory reads.
pub async fn names_the_requester<'a, F>(
    dir: &F,
    named: impl Iterator<Item = &'a str>,
    peer: &str,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let named: BTreeSet<&str> = named.filter(|n| !n.is_empty()).collect();
    if named.is_empty() {
        return Ok(false);
    }
    if named.contains(peer) {
        return Ok(true);
    }
    let principals = crate::federation::self_collective::principals_of(dir, peer).await?;
    Ok(principals.iter().any(|p| named.contains(p.as_str())))
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
        (Some(cs::Placement::Commons), _) => Ok(true),
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
