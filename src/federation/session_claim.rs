//! v38.7.0 (CIRISPersist#782) — **which occurrence of a self is handling a
//! given `(community, session)`.**
//!
//! A *self* is one federated identity plus the N nodes it stewards — its
//! occurrences. An attestation addressed to a fed id fans out to every one of
//! them, because a fed id has no transport path of its own. So delivery is
//! N-to-M and **exactly one occurrence may act**.
//!
//! # It is a NAT table, not a leader election
//!
//! A self is legitimately doing several things at once on different nodes: an
//! agent scouting in community A, another agent in the same community, the
//! person chatting in community B, the same person on video in B. Four
//! occurrences, four live sessions, two communities, concurrently and all
//! correct.
//!
//! So the claim is keyed by `(community, session)`. *"Which node is my self?"*
//! has no answer; *"which node is handling session z in community B?"* does.
//! Nothing here elects a node, and nothing here is chat-specific — it governs
//! any addressed, stateful exchange: a session, a claim flow, a moderation
//! duty, a request expecting one reply.
//!
//! # The invariant
//!
//! **An unclaimed attestation is not acted on. Ever.** Not by a quorum, not by
//! the lowest id, and **not by a single-node self**. Being the only occurrence
//! confers no authority to act; it means there is one place where nobody is
//! home.
//!
//! That is why [`handler_for`] returns `Option<String>` and why there is no
//! `Unattended` variant anywhere in this module. Attendance is encoded as
//! PRESENCE IN THE TABLE: an unattended occurrence is *absent*, not present
//! with a weak claim. A weak-claim variant is a value a careless comparison
//! can promote into a right to act, and this module deliberately does not
//! contain one.
//!
//! # What persist decides, and what it cannot
//!
//! Persist owns the rows, the projection ([`AttestationFamily::SessionClaim`](
//! super::namespace::AttestationFamily::SessionClaim)), the merge rule and
//! this read. It does **not** own attendance: *"a human is present here"* /
//! *"an agent is running here"* is not a storage fact and persist cannot know
//! it. When to claim, renew and release is the consumer's.
//!
//! Election does not belong on the transport plane either: replication
//! delivers the fan-out to EVERY occurrence and must not decide who may act,
//! or fan-out collapses into routing.

use super::Error;

/// v38.7.0 (#782) — the dimension a session claim rides.
///
/// Versioned because `DimensionAdmissionPolicy` refuses a dimension with no
/// version segment, and because the wire version IS the claim's contract
/// version.
pub const SESSION_CLAIM_DIMENSION: &str = "session:claim:v1";

/// v38.7.0 (#782) — the family stem persist rules on. Read by
/// `family_rules::persist_ruled_prefixes` at the const rather than
/// re-spelled there, so the classifier arm and the rules table cannot drift.
pub const SESSION_DIMENSION_PREFIX: &str = "session:";

/// One occurrence's claim on a `(community, session)`, as folded from a row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionClaim {
    /// The occurrence that claimed — the node that will act.
    pub occurrence_key_id: String,
    /// When it claimed. The producer's assertion, carried in the signed
    /// envelope; a renewal does NOT move it (see [`resolve_claim`]).
    pub claimed_at: chrono::DateTime<chrono::Utc>,
}

/// v38.7.0 (#782) — **the merge rule: earliest `claimed_at` wins, ties broken
/// on the lowest occurrence `key_id`.**
///
/// There is no compare-and-swap across a mesh, so concurrent claims are
/// EXPECTED rather than prevented, and settled by a rule every node computes
/// identically. Convergent from either arrival order, with no coordination
/// round-trip — the same class of fold persist already runs for
/// `withdraws`/`supersedes`, which is the argument for the rule living here:
/// every node type converges by construction instead of each consumer
/// reimplementing it.
///
/// The tie-break is not decoration. Two occurrences can assert the same
/// instant — clocks are coarse and a fan-out arrives at once — and without a
/// total order the two nodes would disagree about the survivor forever, each
/// correctly applying "earliest wins".
///
/// Returns `None` for an empty set: **no claim means nobody acts**, which is
/// the invariant, not a degenerate case to paper over.
///
/// Consumers must still make handling **idempotent per attestation id**:
/// determinism only bites once views agree, and replication lag means they
/// transiently do not.
#[must_use]
pub fn resolve_claim(claims: &[SessionClaim]) -> Option<SessionClaim> {
    claims
        .iter()
        .min_by(|a, b| {
            a.claimed_at
                .cmp(&b.claimed_at)
                .then_with(|| a.occurrence_key_id.cmp(&b.occurrence_key_id))
        })
        .cloned()
}

/// v38.7.0 (#782) — is this claim still live at `now`?
///
/// A dead node must not hold a session forever, so a claim goes stale and
/// becomes claimable again. Staleness is the CONSUMER's horizon — persist
/// cannot know whether a node is attending — so the caller passes it.
#[must_use]
pub fn claim_is_live(
    claim: &SessionClaim,
    now: chrono::DateTime<chrono::Utc>,
    ttl: chrono::Duration,
) -> bool {
    now.signed_duration_since(claim.claimed_at) < ttl
}

/// Read `(community_id, session_id, claimed_at)` out of a claim row's signed
/// envelope. `None` for any row that is not a well-formed claim — a row that
/// cannot say which session it claims is not a claim, and must not be folded
/// as one.
#[must_use]
pub fn claim_from_envelope(
    envelope: &serde_json::Value,
    occurrence_key_id: &str,
) -> Option<(String, String, SessionClaim)> {
    let community = envelope.get("community_id")?.as_str()?;
    let session = envelope.get("session_id")?.as_str()?;
    let claimed_at = envelope
        .get("claimed_at")?
        .as_str()?
        .parse::<chrono::DateTime<chrono::Utc>>()
        .ok()?;
    if community.is_empty() || session.is_empty() {
        return None;
    }
    Some((
        community.to_owned(),
        session.to_owned(),
        SessionClaim {
            occurrence_key_id: occurrence_key_id.to_owned(),
            claimed_at,
        },
    ))
}

/// v38.7.0 (#782) — **who handles `(community, session)` for this self?**
///
/// Walks the self's own occurrences ([`nodes_stewarded_by`](
/// super::admission::nodes_stewarded_by), which is withdraws-aware), reads
/// each one's claim rows, and folds them with [`resolve_claim`]. No new
/// backend read: a claim is a self-report, so it is found where the occurrence
/// that made it is the attested key.
///
/// `None` means **unclaimed — nobody acts**. It does not mean "pick someone".
pub async fn handler_for(
    directory: &dyn super::FederationDirectory,
    steward_user_key_id: &str,
    community_key_id: &str,
    session_id: &str,
    now: chrono::DateTime<chrono::Utc>,
    ttl: chrono::Duration,
) -> Result<Option<SessionClaim>, Error> {
    let occurrences = super::admission::nodes_stewarded_by(directory, steward_user_key_id).await?;
    let mut claims = Vec::new();
    for occurrence in occurrences {
        for row in directory.list_attestations_for(&occurrence).await? {
            if super::admission::envelope_dimension(&row.attestation_envelope)
                != Some(SESSION_CLAIM_DIMENSION)
            {
                continue;
            }
            // A claim is a SELF-REPORT: the occurrence claims for itself.
            // A row about an occurrence, authored by someone else, is not
            // that occurrence's claim and must not be folded as one.
            if row.attesting_key_id != occurrence || row.attested_key_id != occurrence {
                continue;
            }
            let Some((community, session, claim)) =
                claim_from_envelope(&row.attestation_envelope, &occurrence)
            else {
                continue;
            };
            if community == community_key_id
                && session == session_id
                && claim_is_live(&claim, now, ttl)
            {
                claims.push(claim);
            }
        }
    }
    Ok(resolve_claim(&claims))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("fixture instant")
    }
    fn claim(occ: &str, when: &str) -> SessionClaim {
        SessionClaim {
            occurrence_key_id: occ.to_owned(),
            claimed_at: at(when),
        }
    }

    /// #782 — **an unclaimed exchange is never acted on, and a LONE
    /// occurrence is not an exception.**
    ///
    /// The tempting shortcut is "if there is only one of me, it must be me".
    /// Being the only occurrence confers no authority to act; it means there
    /// is one place where nobody is home. This is asserted first because it
    /// is the invariant the whole plane rests on.
    #[test]
    fn an_unclaimed_session_has_no_handler_even_for_a_lone_occurrence_782() {
        assert_eq!(resolve_claim(&[]), None, "#782: no claim means NOBODY acts");
        // …and the type system carries it: there is no `Unattended` variant
        // to compare against, so absence cannot be promoted into a right.
        let lone = [claim("only-node", "2026-08-30T12:00:00Z")];
        assert_eq!(
            resolve_claim(&lone).map(|c| c.occurrence_key_id),
            Some("only-node".to_owned()),
            "#782: a lone occurrence that HAS claimed does hold the session — the rule is \
             about the claim, not about the count"
        );
    }

    /// #782 — four occurrences, four concurrent sessions, two communities.
    /// A self is legitimately doing several things at once, so the key is
    /// `(community, session)` and never "which node is my self".
    #[test]
    fn four_occurrences_hold_four_concurrent_sessions_782() {
        // Each session resolves independently; there is no global winner.
        let a = [claim("node-1", "2026-08-30T12:00:00Z")];
        let b = [claim("node-2", "2026-08-30T12:00:01Z")];
        let c = [claim("node-3", "2026-08-30T12:00:02Z")];
        let d = [claim("node-4", "2026-08-30T12:00:03Z")];
        let held: Vec<String> = [&a[..], &b[..], &c[..], &d[..]]
            .iter()
            .filter_map(|s| resolve_claim(s).map(|c| c.occurrence_key_id))
            .collect();
        assert_eq!(
            held,
            vec!["node-1", "node-2", "node-3", "node-4"],
            "#782: four sessions, four holders — an election would have collapsed these to one"
        );
    }

    /// #782 — concurrent claims CONVERGE, from either arrival order. There is
    /// no compare-and-swap across a mesh, so the rule must be order-free.
    #[test]
    fn concurrent_claims_converge_from_either_arrival_order_782() {
        let early = claim("node-b", "2026-08-30T12:00:00Z");
        let late = claim("node-a", "2026-08-30T12:00:05Z");
        let one = resolve_claim(&[early.clone(), late.clone()]);
        let other = resolve_claim(&[late, early]);
        assert_eq!(
            one, other,
            "#782: the survivor cannot depend on which claim this node saw first — that is \
             what makes the rule usable without a coordination round-trip"
        );
        assert_eq!(
            one.map(|c| c.occurrence_key_id),
            Some("node-b".to_owned()),
            "#782: earliest claimed_at wins — NOT the lowest id, which would have picked node-a"
        );
    }

    /// #782 — a simultaneous tie breaks on the lowest occurrence id.
    ///
    /// Not decoration: clocks are coarse and a fan-out arrives at once, so
    /// two occurrences CAN assert the same instant. Without a total order the
    /// two nodes disagree about the survivor forever, each correctly applying
    /// "earliest wins".
    #[test]
    fn a_simultaneous_tie_breaks_on_the_lowest_occurrence_id_782() {
        let same = "2026-08-30T12:00:00Z";
        let resolved = resolve_claim(&[claim("node-z", same), claim("node-a", same)]);
        assert_eq!(
            resolved.map(|c| c.occurrence_key_id),
            Some("node-a".to_owned()),
            "#782: a tie must resolve identically on every node, or both hold the session"
        );
    }

    /// #782 — a live claim is not stealable, and RENEWAL DOES NOT RESET
    /// `claimed_at`.
    ///
    /// If renewal moved the instant, a renewing holder would keep losing to
    /// any later claimant under "earliest wins" — the rule would invert its
    /// own purpose and hand the session to whoever arrived most recently.
    #[test]
    fn a_live_claim_is_not_stealable_and_renewal_keeps_its_instant_782() {
        let holder = claim("node-holder", "2026-08-30T12:00:00Z");
        let thief = claim("node-thief", "2026-08-30T12:00:30Z");
        assert_eq!(
            resolve_claim(&[holder.clone(), thief]).map(|c| c.occurrence_key_id),
            Some("node-holder".to_owned()),
            "#782: a later claim does not take a live session"
        );
        // A renewal is the SAME claim seen again: same instant, same holder.
        let renewed = holder.clone();
        assert_eq!(
            renewed.claimed_at, holder.claimed_at,
            "#782: renewal must not move `claimed_at`, or the holder loses its own session"
        );
    }

    /// #782 — a stale claim becomes claimable again. A dead node must not
    /// hold sessions forever; the horizon is the consumer's because persist
    /// cannot know whether a node is attending.
    #[test]
    fn a_stale_claim_is_no_longer_live_782() {
        let c = claim("node-dead", "2026-08-30T12:00:00Z");
        let ttl = chrono::Duration::seconds(60);
        assert!(claim_is_live(&c, at("2026-08-30T12:00:30Z"), ttl));
        assert!(
            !claim_is_live(&c, at("2026-08-30T12:01:30Z"), ttl),
            "#782: a claim outlives its holder unless staleness expires it"
        );
    }

    /// #782 — a row that cannot say WHICH session it claims is not a claim.
    /// Folding one as if it were would let a malformed or partial row take a
    /// session nobody claimed.
    #[test]
    fn a_row_that_names_no_session_is_not_a_claim_782() {
        for env in [
            serde_json::json!({ "community_id": "c1" }),
            serde_json::json!({ "session_id": "s1" }),
            serde_json::json!({ "community_id": "", "session_id": "s1", "claimed_at": "2026-08-30T12:00:00Z" }),
            serde_json::json!({ "community_id": "c1", "session_id": "s1", "claimed_at": "not-a-time" }),
        ] {
            assert!(
                claim_from_envelope(&env, "node-1").is_none(),
                "#782: {env} is not a well-formed claim and must not be folded as one"
            );
        }
        let good = serde_json::json!({
            "community_id": "c1",
            "session_id": "s1",
            "claimed_at": "2026-08-30T12:00:00Z",
        });
        assert!(claim_from_envelope(&good, "node-1").is_some());
    }

    /// #782 — the claim dimension is VERSIONED, because
    /// `DimensionAdmissionPolicy` refuses a dimension with no version segment
    /// and the wire version is the claim's contract version.
    #[test]
    fn the_claim_dimension_is_versioned_and_decided_782() {
        assert!(
            SESSION_CLAIM_DIMENSION.ends_with(":v1"),
            "#782: an unversioned dimension is refused at admission"
        );
        assert_eq!(
            crate::federation::namespace::attestation_family(SESSION_CLAIM_DIMENSION),
            crate::federation::namespace::AttestationFamily::SessionClaim,
            "#782: the dimension must resolve to its DECIDED family, not to the conservative \
             default — a defaulted cell is one sweep away from being widened to Global, which \
             would publish an attendance map of a person's devices"
        );
    }
}
