//! v62.0.0 (CONTENT-A3; the Constitution's room-content rule R1, names of
//! 2026-11-22) — **which rows are a room's CONTENT**: the rows that chain
//! by `refs.prev` and that an end's tips keep. This is persist's ADAPTER
//! side of the rule. The rule itself is `content_kept`.
//!
//! **The predicate is ONE function, [`is_room_content`].**
//! - **Today** it reads the constant [`ROOM_CONTENT`]. That is the
//!   Constitution's list, by leaf, and it is TO BE REPLACED.
//! - **At the CC tag that carries the `room_content` column** in
//!   `manifests/family_model.json` (by leaf, in the selector form the
//!   `names_head` column uses), the body becomes one read of
//!   `namespace::family_table`. The constant and its witness's list are then
//!   deleted. Re-vendoring the table is the only other change, and no caller
//!   moves.
//!
//! **What the list says.** A row is room content when BOTH hold:
//! - its family is content by leaf:
//!   - `chat:*` at leaf `message` or `reaction` only (every other chat
//!     leaf, `call`, `key_package`, `welcome`, `commit`, `delivery_ack` and
//!     any future one, is not);
//!   - `file:{version}`, `collection:{kind}`, `audio:*`, `image:*`,
//!     `video:*`, `film:*`, `model_3d:*`, `blog:*`, `news:*` and
//!     `encyclopedia:*` at every leaf;
//!   - every other family is false.
//! - it is placed at a room or a family: `cohort_scope` `community`,
//!   `affiliations` or `family`. Content at `self` or wider is no room's.

use ciris_verify_core::namespace_match;

use crate::federation::types::cohort_scope;

/// Which leaves of a family are room content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leaves {
    /// Every leaf.
    Every,
    /// Only these leaves (the dimension's segment after the family's
    /// literal prefix).
    Only(&'static [&'static str]),
}

/// v62.0.0 (CONTENT-A3) — **the Constitution's `room_content` list, TO BE
/// REPLACED** by the family table's `room_content` column at the CC tag that
/// carries it: `(registry prefix, leaves)`.
pub const ROOM_CONTENT: &[(&str, Leaves)] = &[
    ("chat:*", Leaves::Only(&["message", "reaction"])),
    ("file:{version}", Leaves::Every),
    ("collection:{kind}", Leaves::Every),
    ("audio:*", Leaves::Every),
    ("image:*", Leaves::Every),
    ("video:*", Leaves::Every),
    ("film:*", Leaves::Every),
    ("model_3d:*", Leaves::Every),
    ("blog:*", Leaves::Every),
    ("news:*", Leaves::Every),
    ("encyclopedia:*", Leaves::Every),
];

/// The placements content is a room's at.
pub const ROOM_PLACEMENTS: &[&str] = &[
    cohort_scope::COMMUNITY,
    cohort_scope::AFFILIATIONS,
    cohort_scope::FAMILY,
];

/// The leaf of `dimension` under the registry `prefix`: the segment after
/// the prefix's literal segments (`chat:message:v1` under `chat:*` is
/// `message`).
fn leaf_under<'a>(prefix: &str, dimension: &'a str) -> Option<&'a str> {
    let literal = prefix
        .split(':')
        .take_while(|s| !(s.starts_with('{') || *s == "*"))
        .count();
    dimension.split(':').nth(literal)
}

/// **Is a row of `family_id` (the header's family id, -70002) at
/// `dimension`, placed at `cohort_scope`, a room's content?** The ONE
/// predicate (R1): today [`ROOM_CONTENT`], at the CC pin the family table's
/// `room_content` column.
#[must_use]
pub fn is_room_content(family_id: &str, dimension: Option<&str>, scope: &str) -> bool {
    ROOM_PLACEMENTS.contains(&scope) && is_content_family(family_id, dimension)
}

/// The family half of [`is_room_content`]: the family and leaf, whatever the
/// placement.
#[must_use]
pub fn is_content_family(family_id: &str, dimension: Option<&str>) -> bool {
    ROOM_CONTENT.iter().any(|(prefix, leaves)| {
        namespace_match::family_id(prefix) == family_id
            && match leaves {
                Leaves::Every => true,
                Leaves::Only(set) => dimension
                    .and_then(|d| leaf_under(prefix, d))
                    .is_some_and(|l| set.contains(&l)),
            }
    })
}

/// v62.0.0 (CONTENT-A4) — **a row's place in its author's series**: the
/// room it is placed at and the author, when the row is room content
/// ([`is_room_content`]). A composer (it carries no dimension) has none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeriesEntry {
    /// `community`, `affiliations` or `family`.
    pub scope: String,
    /// The room's group identity-ref (the payload's cohort target alias).
    pub target: String,
    /// The author's identity-ref.
    pub author: String,
}

/// [`SeriesEntry`] of a payload of `family_id` and row type `row_type`, or
/// `None`: a composer, an unplaced row, a row with no `author`, a family that
/// is not room content.
#[must_use]
pub fn series_entry(
    row_type: &str,
    family_id: &str,
    payload: &ciris_verify_core::cde::Value,
) -> Option<SeriesEntry> {
    use ciris_verify_core::cde::Value;
    if super::emit::names_a_target(row_type) {
        return None;
    }
    let text = |k: &str| payload.get_text(k).and_then(Value::as_text);
    let scope = text("cohort_scope")?;
    let target = crate::federation::admission::COHORT_TARGET_ENVELOPE_FIELDS
        .iter()
        .find_map(|f| text(f).filter(|t| !t.is_empty()))?;
    let author = text("author")?;
    is_room_content(family_id, text("dimension"), scope).then(|| SeriesEntry {
        scope: scope.to_owned(),
        target: target.to_owned(),
        author: author.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    //! **I6706 (v62.0.0, CONTENT-A3)** — the predicate is the Constitution's
    //! list. The witness covers:
    //! - chat `message` and `reaction` in a room are content, and every other
    //!   chat leaf is not;
    //! - every listed family is content at a room or family placement, and
    //!   none is at `self` or `federation`;
    //! - every listed prefix is a family of the vendored table, with shape
    //!   `content` (an exact-match spelling);
    //! - every family R1 names false is a family of the table and is not
    //!   room content.
    use super::{is_content_family, is_room_content, Leaves, ROOM_CONTENT};
    use crate::federation::namespace::family_table::{table, Shape};
    use ciris_verify_core::namespace_match::family_id;

    #[test]
    fn i6706_room_content_is_the_constitutions_list() {
        let chat = family_id("chat:*");
        for leaf in ["message", "reaction"] {
            let d = format!("chat:{leaf}:v1");
            for scope in ["community", "affiliations", "family"] {
                assert!(
                    is_room_content(&chat, Some(&d), scope),
                    "I6706 chat {leaf} at {scope}"
                );
            }
            for scope in ["self", "federation"] {
                assert!(
                    !is_room_content(&chat, Some(&d), scope),
                    "I6706 chat {leaf} at {scope} is no room's"
                );
            }
        }
        for leaf in [
            "call",
            "key_package",
            "welcome",
            "commit",
            "delivery_ack",
            "future",
        ] {
            assert!(
                !is_room_content(&chat, Some(&format!("chat:{leaf}:v1")), "community"),
                "I6706 chat {leaf} is not content"
            );
        }
        assert!(
            !is_content_family(&chat, None),
            "I6706 a chat row with no leaf"
        );
        for (prefix, leaves) in ROOM_CONTENT {
            let id = family_id(prefix);
            let row = table()
                .by_family_id(&id)
                .unwrap_or_else(|| panic!("I6706 {prefix} is a family of the vendored table"));
            assert_eq!(
                row.shape,
                Shape::Content,
                "I6706 {prefix} is content-shaped"
            );
            if *leaves == Leaves::Every {
                assert!(
                    is_room_content(&id, Some("x:y:v1"), "community"),
                    "I6706 {prefix} at a room"
                );
            }
        }
        // The families R1 names FALSE (and the content-shaped families the
        // Constitution's OUT list names): each a family of the table, none
        // room content.
        for prefix in [
            "custody:{kind}",
            "content_rating:{scheme}:{rating}",
            "cw_class:{class}",
            "content_class:{class}",
            "vote:{contribution_id}",
            "event:attendance",
            "event:rsvp_count",
            "objection:{state}",
            "moderation:{allegation_type}",
            "watchlist:{id}",
            "ballot:moderator",
            "membership:{stage}",
            "key_grant:{axis}",
            "stream:head",
            "goal:{scale}",
            "approach:{goal_id}",
            "method:{approach_id}:{substrate_rung}",
            "event:lifecycle:{state}",
            "delivery_receipt:{stream_id}",
            "trace:{form}:{version}",
            "trace_summary:{kind}",
            "need:{domain}:{kind}",
            "identity_amendment",
            "device:label",
            "community:listing",
            "accord:invoke:notify:{notify_id}",
            "accord:invoke:drill:{drill_id}",
        ] {
            let id = family_id(prefix);
            assert!(
                table().by_family_id(&id).is_some(),
                "I6706 {prefix} is a family of the vendored table"
            );
            assert!(
                !is_room_content(&id, Some("x:message:v1"), "community"),
                "I6706 {prefix} is not room content"
            );
        }
    }
}
