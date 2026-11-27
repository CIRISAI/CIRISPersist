//! v62.0.0 (CONTENT-A4; CC rc22 3.1.3.2 "A room's content after a member's
//! seat ends", R12) — **the producer names a content row's predecessors**:
//! `refs.prev` = the newest of its author's tips in the room, and
//! `refs.further_prev` = every OTHER tip (so branches rejoin at each post).
//! The text: "a content row names in refs.prev a row of the same author in
//! that room that its producer holds; a producer SHOULD name the newest it
//! holds". A draft with a single prev and no further_prev is conformant; the
//! door judges neither.
//!
//! - **The author's tips in a room** ([`author_tips`]): the rows of the
//!   series index (`edition2_room_series`, `ceg_room_content`) of (room,
//!   author), across the author's keys, that no other row of that series
//!   names as `prev` / `further_prev`. Newest first by THIS store's
//!   admission order, ties by row id: deterministic for an unchanged store.
//!   One function; CONTENT-A5's end and keeps drafts use it too.
//! - **`further_prev` waits for the Verify pin** ([`FURTHER_PREV_ON_THE_WIRE`]):
//!   Verify 23.5.0's reader refuses the role (`unexpected:refs`); 23.5.1's
//!   admits it. Until the pin the draft states `prev` alone.
//! - A backend without the index (the capsule proxy: `Unsupported`) drafts no
//!   predecessor: the row starts a branch, which nothing refuses.

use ciris_verify_core::cde::{self, Value};

use super::names::RowId;
use super::room_content::series_entry;
use crate::federation::{Error, FederationDirectory};

/// v62.0.0 (CONTENT-A4) — does a draft state `refs.further_prev`? `false`
/// until the Verify 23.5.1 pin (its reader carries the role); flipped there,
/// with the interim `produce::check_refs` arm deleted.
pub const FURTHER_PREV_ON_THE_WIRE: bool = false;

/// **The author's tips in the room** (`scope`, `target`): newest first.
/// Empty when the store holds none, or has no series index.
///
/// # Errors
/// Directory reads other than `Unsupported`.
pub async fn author_tips<F>(
    dir: &F,
    scope: &str,
    target: &str,
    author: &str,
) -> Result<Vec<RowId>, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(author_tips_at(dir, scope, target, author)
        .await?
        .into_iter()
        .map(|(_, id)| id)
        .collect())
}

/// v62.0.0 (CONTENT-A4b) — the most tips one draft reads: two rows' worth
/// of `refs.trusted_through` (64 on an end, the next 64 for a `keeps` row).
/// A member with more open tips than this names the newest; the rest are
/// named as the older ones are followed. Bounded per draft.
pub const TIPS_READ: u32 = 128;

/// [`author_tips`] with each tip's admission position, newest first, at most
/// [`TIPS_READ`].
///
/// # Errors
/// Directory reads other than `Unsupported`.
pub async fn author_tips_at<F>(
    dir: &F,
    scope: &str,
    target: &str,
    author: &str,
) -> Result<Vec<(i64, RowId)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (CONTENT-A4b) — read off the series index's `followed`
    // column: ONE indexed read, at most [`TIPS_READ`] rows, whatever the
    // series' length (was one name lookup per series row per role).
    match dir
        .edition2_room_tips(scope, target, author, TIPS_READ)
        .await
    {
        Ok(tips) => Ok(tips.into_iter().map(|(id, at)| (at, id)).collect()),
        Err(Error::Unsupported { .. }) => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// `payload` with `refs` joined by `extra` roles (each kept as given; a role
/// the payload already states is not replaced).
///
/// # Errors
/// `edition2_payload_invalid` for a `refs` that is not a map.
pub fn with_refs(payload: Value, extra: Vec<(&str, Value)>) -> Result<Value, Error> {
    let mut roles: Vec<(Value, Value)> = match payload.get_text("refs") {
        None => Vec::new(),
        Some(Value::Map(m)) => m.clone(),
        Some(_) => {
            return Err(Error::InvalidArgument(
                "edition2_payload_invalid: `refs` is not a map".into(),
            ))
        }
    };
    for (k, v) in extra {
        if !roles.iter().any(|(r, _)| r.as_text() == Some(k)) {
            roles.push((Value::Text(k.into()), v));
        }
    }
    super::emit::with_member(payload, "refs", super::emit::sorted_map(roles))
        .map_err(|e| super::emit::produce_error("refs", e))
}

/// A sorted, duplicate-free row-ref-set of `ids`.
#[must_use]
pub fn row_ref_set(ids: &[RowId]) -> Value {
    let mut a: Vec<Value> = ids
        .iter()
        .map(|i| ciris_verify_core::edition2::row_ref(&i.0))
        .collect();
    a.sort_by_key(cde::encode);
    a.dedup();
    Value::Array(a)
}

/// **The ONE producer step for predecessors** (after `head_rule::state_head`,
/// before the first voice signs): a room content row of an author
/// ([`series_entry`]) that names no `refs.prev` gets `prev` = the newest of
/// the author's tips in that room and, from the Verify pin on,
/// `further_prev` = the others. Every other payload, and one that already
/// names a predecessor, is returned unchanged.
///
/// # Errors
/// Directory reads; a `refs` that is not a map.
pub async fn state_prev<F>(
    dir: &F,
    row_type: &str,
    family_id: &str,
    payload: Value,
) -> Result<Value, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(entry) = series_entry(row_type, family_id, &payload) else {
        return Ok(payload);
    };
    let named = |role: &str| {
        payload
            .get_text("refs")
            .and_then(Value::as_map)
            .is_some_and(|m| m.iter().any(|(k, _)| k.as_text() == Some(role)))
    };
    if named("prev") || named("further_prev") {
        return Ok(payload);
    }
    let tips = author_tips(dir, &entry.scope, &entry.target, &entry.author).await?;
    let Some((newest, others)) = tips.split_first() else {
        return Ok(payload);
    };
    let mut extra = vec![("prev", ciris_verify_core::edition2::row_ref(&newest.0))];
    if FURTHER_PREV_ON_THE_WIRE && !others.is_empty() {
        extra.push(("further_prev", row_ref_set(others)));
    }
    with_refs(payload, extra)
}

/// v62.0.0 (CONTENT-A5) — the placements a group's content sits at: a
/// family's at `family`; a community's at `community` or, for an
/// affiliation, `affiliations`.
#[must_use]
pub fn room_scopes(group_kind: &str) -> &'static [&'static str] {
    use crate::federation::types::cohort_scope as cs;
    if group_kind == "family" {
        &[cs::FAMILY]
    } else {
        &[cs::COMMUNITY, cs::AFFILIATIONS]
    }
}

/// v62.0.0 (CONTENT-A5; CC rc22 3.1.3.2) — **`member`'s tips in `group`**,
/// over every placement of the group's content and every key of the
/// member, newest first by admission: what an end of the member's seat
/// names in `refs.trusted_through`. At most
/// [`TRUSTED_THROUGH_MAX`](super::produce::TRUSTED_THROUGH_MAX) are named
/// on one row; the rest ([`member_tips`]'s second half) go on `keeps` rows
/// ([`super::group::keeps_draft`]).
///
/// # Errors
/// Directory reads other than `Unsupported`.
pub async fn member_tips<F>(
    dir: &F,
    group_kind: &str,
    group: &str,
    member: &str,
) -> Result<(Vec<RowId>, Vec<RowId>), Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut all: Vec<(i64, RowId)> = Vec::new();
    for scope in room_scopes(group_kind) {
        all.extend(author_tips_at(dir, scope, group, member).await?);
    }
    all.sort();
    all.reverse();
    let mut ids: Vec<RowId> = all.into_iter().map(|(_, id)| id).collect();
    let rest = ids.split_off(ids.len().min(super::produce::TRUSTED_THROUGH_MAX));
    Ok((ids, rest))
}

/// v62.0.0 (CONTENT-A5) — **the producer step for an end's tips**: a
/// `membership:{stage}` `removal` or `resignation` row (not a composer)
/// that states no `refs.trusted_through` gets the member's newest tips in
/// the group ([`member_tips`], at most 64). Every other payload, and one
/// that already names tips, is unchanged. Tips past 64 are not stated here;
/// a counted `keeps` row carries them.
///
/// # Errors
/// Directory reads; a `refs` that is not a map.
pub async fn state_tips<F>(
    dir: &F,
    row_type: &str,
    family_id: &str,
    payload: Value,
) -> Result<Value, Error>
where
    F: FederationDirectory + ?Sized,
{
    use super::group::{MEMBERSHIP_PREFIX, REMOVAL_LEAF, RESIGNATION_LEAF};
    if super::emit::names_a_target(row_type)
        || family_id != ciris_verify_core::namespace_match::family_id(MEMBERSHIP_PREFIX)
    {
        return Ok(payload);
    }
    let leaf = super::payloads::leaf_of(MEMBERSHIP_PREFIX, &payload);
    if leaf != Some(REMOVAL_LEAF) && leaf != Some(RESIGNATION_LEAF) {
        return Ok(payload);
    }
    let names_tips = payload
        .get_text("refs")
        .and_then(Value::as_map)
        .is_some_and(|m| {
            m.iter()
                .any(|(k, _)| k.as_text() == Some("trusted_through"))
        });
    let text = |k: &str| {
        payload
            .get_text(k)
            .and_then(Value::as_text)
            .map(str::to_owned)
    };
    let (Some(kind), Some(group), Some(member)) =
        (text("group_kind"), text("group"), text("member"))
    else {
        return Ok(payload);
    };
    if names_tips {
        return Ok(payload);
    }
    let (tips, _) = member_tips(dir, &kind, &group, &member).await?;
    if tips.is_empty() {
        return Ok(payload);
    }
    with_refs(payload, vec![("trusted_through", row_ref_set(&tips))])
}
