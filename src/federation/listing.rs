//! v49.0.0 (CIRISPersist#912, FSD `ROOM_ROSTER_AUTHORITY.md` §11) — **the
//! membership listing plane**: CC 2's `listed`, a per-membership opt-in to
//! public roster visibility.
//!
//! CC 2 gives the field one value (`public`), a default (absent — a PRIVATE
//! roster, producer- and self-queryable, NEVER globally enumerable) and a
//! discipline: *opting into roster visibility is a one-way disclosure the
//! member chooses; the substrate does not solicit*, and producers MUST omit it
//! unless the subject opted in. This module is that discipline as code:
//!
//! - [`check_community_membership_listing`] — the ONE admission gate every
//!   backend's `put_community_membership_listing` runs. The clause that makes
//!   the field an opt-in rather than a power the room holds over its members
//!   is [`LISTED_RULE_NOT_SELF_ASSERTED`]: the row's signer must BE the member.
//! - [`listed_community_members_at`] — the ONE roster view a non-member may be
//!   served: active members (by the authorized fold) whose latest listing at or
//!   before the instant is `public`. Serving it is the host's endpoint gate;
//!   persist computes it and nothing else.
//!
//! The plane is forward-only. Clearing is a later row with `listed: None`;
//! nothing is rewritten. Un-listing stops new readers and does not unread what
//! was read while the member was listed — the substrate claims no more.

use super::types::{CommunityMember, CommunityMembershipListing};
use super::{Error, FederationDirectory, SignedCommunityMembershipListing};

/// The one admissible value of [`super::envelope::paths::LISTED`] (CC 2).
pub const LISTED_PUBLIC: &str = "public";

/// [`Error::MembershipListingRefused`] rule — the listing's signer is not the
/// membership's subject. A founder, a moderator or the room's protocol cannot
/// list a member; only the member can (CC 2: "the substrate does NOT
/// solicit"). Substantive, not retryable.
pub const LISTED_RULE_NOT_SELF_ASSERTED: &str = "envelope_listed_not_self_asserted";

/// [`Error::MembershipListingRefused`] rule — `listed` carries a value other
/// than [`LISTED_PUBLIC`]. CC gives exactly one; an open vocabulary would let a
/// producer write a visibility state no reader has agreed a meaning for.
pub const LISTED_RULE_BAD_VALUE: &str = "envelope_listed_bad_value";

/// [`Error::MembershipListingRefused`] rule — the listing names a group with no
/// listable roster. The plane references `federation_communities` only; a
/// FAMILY id is refused by this token (CC 5.2: family membership is
/// structurally invisible, there is nothing to list), and an id that names no
/// group at all is the FK's [`Error::InvalidArgument`]. The audience scopes
/// (`self`, `species`, `biosphere`, `federation`) have no group id to name.
pub const LISTED_RULE_SCOPE_INVALID: &str = "envelope_listed_scope_invalid";

fn refused(signed: &SignedCommunityMembershipListing, rule: &'static str) -> Error {
    Error::MembershipListingRefused {
        community_key_id: signed.community_membership_listing.community_key_id.clone(),
        offered_authority_key_id: signed.authority_key_id.clone(),
        rule,
    }
}

/// A listing may not be future-dated beyond the roster planes' skew bound: the
/// fold reads the latest row at or before an instant, and a far-future row
/// would sit unapplied for as long as its signer chose, then flip the member's
/// visibility with no fresh act.
pub fn reject_future_dated_community_listing(
    effective_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error> {
    let skew = super::community_dek::COMMUNITY_REVOCATION_MAX_FUTURE_SKEW_SECS;
    if effective_at > chrono::Utc::now() + chrono::Duration::seconds(skew) {
        return Err(Error::InvalidArgument(format!(
            "community membership listing effective_at {effective_at} is future-dated \
             (> now + {skew}s)"
        )));
    }
    Ok(())
}

/// v49.0.0 (CIRISPersist#912) — **the listing door**, shared by every backend:
///
/// 1. the hybrid signature verifies under `authority_key_id`;
/// 2. `authority_key_id == member_key_id`, else
///    [`LISTED_RULE_NOT_SELF_ASSERTED`] (the opt-in clause);
/// 3. `listed` is absent or [`LISTED_PUBLIC`], else [`LISTED_RULE_BAD_VALUE`];
/// 4. `effective_at` is not future-dated;
/// 5. the room exists — a family id is [`LISTED_RULE_SCOPE_INVALID`], an
///    unknown id [`Error::InvalidArgument`] (the V156 FK).
///
/// Membership is NOT checked: rows arrive out of order, so a listing by a key
/// that is not (yet) an active member is admitted and stored, and has effect
/// only while [`listed_community_members_at`]'s fold says the key is active.
pub async fn check_community_membership_listing<F>(
    directory: &F,
    signed: &SignedCommunityMembershipListing,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    super::verify_community_membership_listing_admission(directory, signed).await?;
    let row = &signed.community_membership_listing;
    if signed.authority_key_id != row.member_key_id {
        return Err(refused(signed, LISTED_RULE_NOT_SELF_ASSERTED));
    }
    if row.listed.as_deref().is_some_and(|v| v != LISTED_PUBLIC) {
        return Err(refused(signed, LISTED_RULE_BAD_VALUE));
    }
    reject_future_dated_community_listing(row.effective_at)?;
    if directory
        .lookup_community(&row.community_key_id)
        .await?
        .is_none()
    {
        if directory
            .lookup_family(&row.community_key_id)
            .await?
            .is_some()
        {
            return Err(refused(signed, LISTED_RULE_SCOPE_INVALID));
        }
        return Err(Error::InvalidArgument(format!(
            "{} does not exist in federation_communities",
            row.community_key_id
        )));
    }
    Ok(())
}

/// The member's deciding listing at `as_of` — the forward-only fold over ONE
/// membership span: among the rows made at or after `span_start` (the start of
/// the member's current span, [`super::RosterSpans`]; `None` = open to the
/// beginning of time) and at or before `as_of`, the latest. A row from before
/// the span — made before joining, or in an earlier membership ended by a
/// removal — does not count (v49 ruling 2026-09-25, CC 2 opt-in: a listing belongs to
/// the membership it was made in). The PK carries `effective_at`, so one
/// member has at most one row per instant and "latest" is total.
#[must_use]
pub fn latest_listing_at(
    listings: &[CommunityMembershipListing],
    member_key_id: &str,
    span_start: Option<chrono::DateTime<chrono::Utc>>,
    as_of: chrono::DateTime<chrono::Utc>,
) -> Option<CommunityMembershipListing> {
    listings
        .iter()
        .filter(|l| {
            l.member_key_id == member_key_id
                && l.effective_at <= as_of
                && span_start.is_none_or(|start| l.effective_at >= start)
        })
        .max_by_key(|l| l.effective_at)
        .cloned()
}

/// v49.0.0 (CIRISPersist#912) — **the publicly listed members of a room at
/// `as_of`**: the room's ACTIVE members by the authorized fold
/// ([`super::authorized_community_roster_spans_at`]) whose latest listing
/// WITHIN THEIR CURRENT MEMBERSHIP SPAN and at or before `as_of` is
/// [`LISTED_PUBLIC`], in roster order.
///
/// This is the ONLY roster view a non-member may be served — the one crack CC 2
/// opens in "never globally enumerable", made of the members who chose it.
/// Persist does not gate the endpoint that serves it; the host does. A removed
/// member drops out with their membership, and a removal ends every listing
/// made before it: re-added, they are unlisted until they list again. A
/// listing made before its signer became a member is stored and stays inert.
/// A role change of an active member does not restart the span.
/// [`Error::InvalidArgument`] for an unknown room.
pub async fn listed_community_members_at<F>(
    directory: &F,
    community_key_id: &str,
    as_of: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<CommunityMember>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let community = directory
        .lookup_community(community_key_id)
        .await?
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "listed_members names unknown community_key_id {community_key_id:?}"
            ))
        })?;
    let roster = Box::pin(super::authorized_community_roster_spans_at(
        directory, &community, as_of,
    ))
    .await?;
    let listings = directory
        .list_community_membership_listings_for(community_key_id)
        .await?;
    Ok(roster
        .into_iter()
        .filter(|(m, span_start)| {
            latest_listing_at(&listings, &m.key_id, *span_start, as_of)
                .and_then(|l| l.listed)
                .as_deref()
                == Some(LISTED_PUBLIC)
        })
        .map(|(m, _)| m)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(member: &str, at: &str, listed: Option<&str>) -> CommunityMembershipListing {
        CommunityMembershipListing {
            community_key_id: "room".into(),
            member_key_id: member.into(),
            effective_at: at.parse().unwrap(),
            listed: listed.map(str::to_owned),
            persist_row_hash: String::new(),
        }
    }

    /// The envelope carries `listed` under the vocabulary's own key, and only
    /// when set — CC 2 spells "private" as the member ABSENT.
    #[test]
    fn signing_envelope_spells_listed_by_the_vocabulary_key() {
        let set = row("bob", "2026-03-01T00:00:00Z", Some(LISTED_PUBLIC)).signing_envelope();
        assert_eq!(
            set.get(crate::federation::envelope::paths::LISTED),
            Some(&serde_json::json!("public"))
        );
        assert!(set.get("persist_row_hash").is_none());
        let cleared = row("bob", "2026-03-01T00:00:00Z", None).signing_envelope();
        assert!(cleared
            .get(crate::federation::envelope::paths::LISTED)
            .is_none());
    }

    /// The latest row at or before the instant decides; a later clear wins; a
    /// row after the instant has no effect yet.
    #[test]
    fn latest_listing_is_forward_only() {
        let rows = vec![
            row("bob", "2026-03-01T00:00:00Z", Some(LISTED_PUBLIC)),
            row("bob", "2026-03-05T00:00:00Z", None),
            row("carol", "2026-03-09T00:00:00Z", Some(LISTED_PUBLIC)),
        ];
        let at = |s: &str| s.parse().unwrap();
        let listed = |m: &str, s: &str| {
            latest_listing_at(&rows, m, None, at(s))
                .and_then(|l| l.listed)
                .is_some()
        };
        assert!(!listed("bob", "2026-02-28T00:00:00Z"));
        assert!(listed("bob", "2026-03-01T00:00:00Z"));
        assert!(listed("bob", "2026-03-04T23:59:59Z"));
        assert!(!listed("bob", "2026-03-05T00:00:00Z"));
        assert!(!listed("carol", "2026-03-08T00:00:00Z"));
        assert!(listed("carol", "2026-03-09T00:00:00Z"));
    }

    /// A row from before the span does not count; one AT the span start does.
    #[test]
    fn a_listing_belongs_to_its_span() {
        let rows = vec![row("bob", "2026-03-01T00:00:00Z", Some(LISTED_PUBLIC))];
        let at = |s: &str| -> chrono::DateTime<chrono::Utc> { s.parse().unwrap() };
        let now = at("2026-04-01T00:00:00Z");
        assert!(latest_listing_at(&rows, "bob", None, now).is_some());
        assert!(latest_listing_at(&rows, "bob", Some(at("2026-03-01T00:00:00Z")), now).is_some());
        assert!(latest_listing_at(&rows, "bob", Some(at("2026-03-02T00:00:00Z")), now).is_none());
    }

    /// The span fold: a record member is open to the beginning of time; a
    /// removal ends the span; a re-add starts a new one; a widening of an
    /// ACTIVE member (a role change) does not restart it.
    #[test]
    fn spans_restart_on_readmission_not_on_role_change() {
        use crate::federation::{authorized_roster_spans_at, RosterEvent, RosterRules};
        let at = |s: &str| -> chrono::DateTime<chrono::Utc> { s.parse().unwrap() };
        let m = |k: &str, role: Option<&str>| CommunityMember {
            key_id: k.into(),
            joined_at: at("2026-01-01T00:00:00Z"),
            role: role.map(str::to_owned),
        };
        // Legacy (signer-less) events count, so the fold applies each.
        let ev = |t: &str, is_add: bool, member: CommunityMember| RosterEvent {
            effective_at: at(t),
            is_add,
            member,
            signers: Default::default(),
            moderator_roots: Default::default(),
            reversed: false,
        };
        let record = vec![
            m("alice", Some("founder")),
            m("bob", None),
            m("carol", None),
        ];
        let events = vec![
            ev("2026-03-01T00:00:00Z", false, m("bob", None)),
            ev("2026-03-02T00:00:00Z", true, m("bob", None)),
            ev("2026-03-03T00:00:00Z", true, m("bob", Some("moderator"))),
            ev("2026-03-04T00:00:00Z", true, m("carol", Some("moderator"))),
            ev("2026-03-05T00:00:00Z", true, m("dave", None)),
            ev("2026-03-06T00:00:00Z", false, m("dave", None)),
        ];
        let rules = RosterRules {
            protocol: crate::federation::types::consensus_protocol::FOUNDER_ONLY,
            subkind: None,
            policy_blob: None,
        };
        let spans = authorized_roster_spans_at(&record, rules, &events, at("2026-04-01T00:00:00Z"));
        assert_eq!(
            spans.get("alice"),
            Some(&None),
            "a record member: open span"
        );
        assert_eq!(
            spans.get("bob"),
            Some(&Some(at("2026-03-02T00:00:00Z"))),
            "re-added at 03-02; the 03-03 role change does not restart it"
        );
        assert_eq!(
            spans.get("carol"),
            Some(&None),
            "a role change keeps the open span"
        );
        assert_eq!(spans.get("dave"), None, "removed: no span");
    }
}
