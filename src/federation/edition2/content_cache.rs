//! v62.0.0 (CONTENT-A6; CC rc22 3.1.3.2) — **the cache of
//! `ciris_kernel::content`'s answers**, kept by the door.
//!
//! [`refresh`] recomputes one (member, room) whole and replaces its cached
//! answers. The crate's `changed` is itself two full reads of the member's
//! rows, so the result is the same, and one entry point is simpler to
//! witness. [`refresh_after`] runs it at the end of every statement's door,
//! for the (member, room)s that statement bears on:
//!
//! - a room content row of an author;
//! - a composer on one (an edit, a retraction);
//! - an end of a seat, or a `keeps` row (every placement of the group).
//!
//! **What is not stored.** A (member, room) with no concluded end is not
//! cached. Its rows are counted, and in force unless the author's own
//! retraction is held: the crate's documented no-end property
//! (`kernel::content::kernel_in_play`). A refresh that finds no concluded
//! end clears the member's cached rows (an end retracted).
//!
//! **Retractions and held composers.** A retraction is read whether or not
//! it is concluded (CC: "takes effect whenever it is signed, whether or not
//! the retraction itself counts or is kept"). So the composers gathered here
//! are the KEPT statements naming the member's rows, by design: the crate
//! decides, not this module.

use ciris_verify_core::cde::Value;

use super::content_store::{CachedAnswer, RetainedEnd};
use super::door::AdmittedRow;
use super::names::RowId;
use crate::federation::{Error, FederationDirectory};
use crate::kernel::content::{self as adapter, Room, RoomRow, COUNT};

fn group_kind_of(scope: &str) -> &'static str {
    if scope == crate::federation::types::cohort_scope::FAMILY {
        "family"
    } else {
        "community"
    }
}

/// `Unsupported` (a backend without the content tables) is no work.
fn supported<T>(r: Result<T, Error>) -> Result<Option<T>, Error> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(Error::Unsupported { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// A retained end as the crate reads it (the end's statement may be gone).
fn end_row(e: &RetainedEnd, member: &str) -> RoomRow {
    use ciris_kernel::content::{Kind, SeatAt};
    RoomRow {
        id: e.source,
        kind: if e.kind == super::group::KEEPS_LEAF {
            Kind::Tips
        } else {
            Kind::End
        },
        signer: if e.counted {
            COUNT.to_owned()
        } else {
            member.to_owned()
        },
        head: Some(e.head),
        prev: Vec::new(),
        tips: e.tips.clone(),
        retracts: None,
        extends: e.extends,
        seat: SeatAt::Sits,
    }
}

/// **Recompute `member`'s answers in the room (`scope`, `target`)** and
/// replace the cache.
///
/// # Errors
/// Directory reads and writes (other than `Unsupported`).
pub async fn refresh<F>(dir: &F, scope: &str, target: &str, member: &str) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(ends) = supported(
        dir.edition2_content_ends(group_kind_of(scope), target, member)
            .await,
    )?
    else {
        return Ok(());
    };
    if ends.is_empty() {
        return Ok(());
    }
    let mut retained = Vec::new();
    for e in ends {
        if super::verdict::row_state(dir, &e.source)
            .await?
            .is_concluded()
        {
            retained.push(e);
        }
    }
    if !retained.iter().any(|e| e.kind != super::group::KEEPS_LEAF) {
        dir.edition2_put_content_answers(scope, target, member, &[])
            .await?;
        return Ok(());
    }
    let series =
        supported(dir.edition2_room_series(scope, target, member).await)?.unwrap_or_default();
    let mut statements: Vec<Vec<u8>> = dir
        .edition2_statements_about(
            &ciris_verify_core::namespace_match::family_id(super::group::GROUP_ROSTER_PREFIX),
            target,
        )
        .await?;
    for (id, _) in &series {
        statements.extend(dir.edition2_voices(id).await?);
        for c in dir.edition2_rows_naming(id, "target").await? {
            statements.extend(dir.edition2_voices(&c).await?);
        }
    }
    let room = Room {
        scope: scope.to_owned(),
        group: target.to_owned(),
    };
    let mut rows = adapter::rows_of(&statements, &room, member);
    rows.extend(retained.iter().map(|e| end_row(e, member)));
    let roots: Vec<RowId> = rows.iter().map(|r| r.id).collect();
    let past = adapter::HeldPast::preload(dir, &roots, &[]).await?;
    let keys = adapter::member_keys(&statements, member);
    let answers: Vec<CachedAnswer> = adapter::answers(&rows, &keys, &past)
        .into_iter()
        .map(|(row, a)| match a {
            ciris_kernel::content::Answer::Judged(j) => CachedAnswer {
                row,
                counted: j.counted,
                in_force: j.in_force,
                rule: j.rule.as_str().to_owned(),
                undecided_on: None,
            },
            ciris_kernel::content::Answer::Undecided(on) => CachedAnswer {
                row,
                counted: false,
                in_force: false,
                rule: UNDECIDED.to_owned(),
                undecided_on: Some(on),
            },
        })
        .collect();
    dir.edition2_put_content_answers(scope, target, member, &answers)
        .await
}

/// The cache's rule for an `Answer::Undecided` (the crate's past could not
/// tell until a row is held).
pub const UNDECIDED: &str = "undecided";

/// The (scope, room, member)s a row of `row_type` / `family` with `payload`
/// bears on: a room content row's own; an end's or keeps row's at every
/// placement of its group. Empty for anything else.
fn bears_on(row_type: &str, family: &str, payload: &Value) -> Vec<(String, String, String)> {
    use super::group::{KEEPS_LEAF, MEMBERSHIP_PREFIX, REMOVAL_LEAF, RESIGNATION_LEAF};
    if let Some(e) = super::room_content::series_entry(row_type, family, payload) {
        return vec![(e.scope, e.target, e.author)];
    }
    if super::emit::names_a_target(row_type)
        || family != ciris_verify_core::namespace_match::family_id(MEMBERSHIP_PREFIX)
    {
        return Vec::new();
    }
    let leaf = super::payloads::leaf_of(MEMBERSHIP_PREFIX, payload);
    if !matches!(leaf, Some(l) if l == REMOVAL_LEAF || l == RESIGNATION_LEAF || l == KEEPS_LEAF) {
        return Vec::new();
    }
    let text = |k: &str| {
        payload
            .get_text(k)
            .and_then(Value::as_text)
            .map(str::to_owned)
    };
    let (Some(kind), Some(group), Some(member)) =
        (text("group_kind"), text("group"), text("member"))
    else {
        return Vec::new();
    };
    super::content_prev::room_scopes(&kind)
        .iter()
        .map(|s| ((*s).to_owned(), group.clone(), member.clone()))
        .collect()
}

/// **The (member, room)s an admitted statement bears on**, each refreshed:
/// its own ([`bears_on`]), or, for a composer, its target's (an edit or a
/// retraction of a content row; the withdrawal of an end).
///
/// # Errors
/// As [`refresh`].
pub async fn refresh_after<F>(dir: &F, admitted: &AdmittedRow) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (CONTENT-A6b) — a NEW own content row of an ENDED member whose
    // cache is current is answered alone ([`answer_one`]); every other
    // arrival recomputes the (member, room).
    if let Some(e) =
        super::room_content::series_entry(&admitted.row_type, &admitted.family, &admitted.payload)
    {
        if answer_one(dir, &e.scope, &e.target, &e.author, admitted).await? {
            return Ok(());
        }
    }
    let mut on = bears_on(&admitted.row_type, &admitted.family, &admitted.payload);
    if super::emit::names_a_target(&admitted.row_type) {
        if let Some(target) = super::names::single(&admitted.names, "target") {
            for st in dir.edition2_voices(&target).await? {
                let Some((protected, payload)) = super::liveness::statement_parts(&st) else {
                    continue;
                };
                let (Some(family), Some(row_type)) = (
                    protected.get_int(-70002).and_then(Value::as_text),
                    protected.get_int(-70001).and_then(Value::as_text),
                ) else {
                    continue;
                };
                on = bears_on(row_type, family, &payload);
                break;
            }
        }
    }
    for (scope, target, member) in on {
        refresh(dir, &scope, &target, &member).await?;
    }
    Ok(())
}

/// The concluded retained ends / keeps rows of `member` in the room, or
/// `None` when the backend has no content tables.
async fn concluded_ends<F>(
    dir: &F,
    scope: &str,
    target: &str,
    member: &str,
) -> Result<Option<Vec<RetainedEnd>>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(ends) = supported(
        dir.edition2_content_ends(group_kind_of(scope), target, member)
            .await,
    )?
    else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for e in ends {
        if super::verdict::row_state(dir, &e.source)
            .await?
            .is_concluded()
        {
            out.push(e);
        }
    }
    Ok(Some(out))
}

/// v62.0.0 (CONTENT-A6b; the lead's ruling 11-23: no O(n²) for an ended
/// member) — **the one-row step.** For an admitted room content row X of
/// `member` (its own row, not a composer), answer X ALONE and write its one
/// cache row, when every condition below holds; `Ok(false)` (the caller
/// recomputes the member) when any fails.
///
/// 1. `member` has a CONCLUDED end in the room. With none, X is `no_end`
///    (the crate's documented property) and nothing is cached: `Ok(true)`
///    with no write.
/// 2. No retained end or keeps row names X as a tip.
/// 3. No held row names X as `prev`, `further_prev`, `trusted_through` or
///    `target` (a retraction or edit of X that arrived first).
/// 4. The cache is current through X's predecessor: X names `refs.prev` P
///    and P has a cache row. (A first row after the end has none: the
///    member is recomputed, once, cheaply.)
///
/// **Why the other rows' answers cannot move.** The crate decides a row by
/// the ends that count (X is no End), the seats (X is no head), the
/// retractions held (X is no retraction), and the kept set: the union of
/// the walks from the tips read along same-member predecessors. A walk
/// reaches a row only through a tip naming it or a held row naming it as a
/// predecessor. By (2) and (3) nothing reaches X, so X's own predecessor
/// edges are never followed and the kept set is unchanged.
///
/// **Why X's answer is the crate's own.** X's answer reads: the ends and
/// their counting (each end's own past and the heads), X's head against the
/// ends' heads and the seats (E3, `no_seat`), the ends in X's causal past
/// (E4), a held retraction of X (none, by 3), and whether X is held good
/// (not, by 2 and 3). So `content::answers` over {the room's heads, the
/// retained ends and keeps rows, X} gives exactly the answer it gives over
/// the whole series. The crate is asked; persist approximates nothing.
/// X's `prev` is not an input to X's answer; it is read only for (4).
///
/// Reads, whatever the member's number of posts:
/// - the retained ends (one indexed probe, plus one tips probe per end on
///   sqlite);
/// - one verdict per retained end;
/// - four `ceg_row_names` probes for X;
/// - one cache probe for P;
/// - the room's roster statements;
/// - X's causal past, bounded by the roster lineage (`MAX_PAST`).
///
/// # Errors
/// Directory reads and the one write.
pub async fn answer_one<F>(
    dir: &F,
    scope: &str,
    target: &str,
    member: &str,
    admitted: &AdmittedRow,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(ends) = concluded_ends(dir, scope, target, member).await? else {
        return Ok(true);
    };
    if !ends.iter().any(|e| e.kind != super::group::KEEPS_LEAF) {
        // (1) No concluded end. A retained end that does not conclude yet is
        // the full refresh's (it clears the member's cache).
        return Ok(ends.is_empty());
    }
    let x = admitted.row_id;
    if ends.iter().any(|e| e.tips.contains(&x)) {
        return Ok(false);
    }
    for role in ["prev", "further_prev", "trusted_through", "target"] {
        if !dir.edition2_rows_naming(&x, role).await?.is_empty() {
            return Ok(false);
        }
    }
    let Some(prev) = super::names::single(&admitted.names, "prev") else {
        return Ok(false);
    };
    if dir.edition2_content_answer(&prev).await?.is_none() {
        return Ok(false);
    }
    let room = Room {
        scope: scope.to_owned(),
        group: target.to_owned(),
    };
    let mut statements: Vec<Vec<u8>> = dir
        .edition2_statements_about(
            &ciris_verify_core::namespace_match::family_id(super::group::GROUP_ROSTER_PREFIX),
            target,
        )
        .await?;
    statements.push(admitted.bytes.clone());
    let mut rows = adapter::rows_of(&statements, &room, member);
    rows.extend(ends.iter().map(|e| end_row(e, member)));
    let roots: Vec<RowId> = rows.iter().map(|r| r.id).collect();
    let past =
        adapter::HeldPast::preload(dir, &roots, std::slice::from_ref(&admitted.bytes)).await?;
    let keys = adapter::member_keys(std::slice::from_ref(&admitted.bytes), member);
    let Some(a) = adapter::answers(&rows, &keys, &past).remove(&x) else {
        return Ok(false);
    };
    let cached = match a {
        ciris_kernel::content::Answer::Judged(j) => CachedAnswer {
            row: x,
            counted: j.counted,
            in_force: j.in_force,
            rule: j.rule.as_str().to_owned(),
            undecided_on: None,
        },
        ciris_kernel::content::Answer::Undecided(on) => CachedAnswer {
            row: x,
            counted: false,
            in_force: false,
            rule: UNDECIDED.to_owned(),
            undecided_on: Some(on),
        },
    };
    dir.edition2_put_content_answer(scope, target, member, &cached)
        .await?;
    Ok(true)
}
