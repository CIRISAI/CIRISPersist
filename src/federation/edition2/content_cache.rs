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
