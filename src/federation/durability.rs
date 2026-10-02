//! v53.0.0 (CIRISPersist#963, CC 6.1.5.3) — **durability at every tier.**
//!
//! Before this release the target-replication model ran only at `community`
//! and wider: `self` / `family` bytes projected `SelfOwn`, so only the
//! producer advertised them and a family's other devices never
//! held-and-forwarded — no rarest-first, no repair, no measurable target on
//! the tier that carries a family's photos. CC 6.1.5.3 makes the machinery
//! available at every tier, bounded to the content's own audience.
//!
//! What persist owns here, and nothing more:
//!
//! - **the projection cell**: [`projection_for`](super::namespace::projection_for)
//!   resolves `FountainContent` at `self` / `family` to `Cohort`, and
//!   [`resolve_projection_recipients`](super::namespace::resolve_projection_recipients)
//!   answers that plane from the content's AUDIENCE. That one verb is both
//!   halves of a within-cohort holding claim: who a holding may be advertised
//!   to, and whose holding claim a node admits (the claimant must be in the
//!   same set). There is no second holding-claim predicate.
//! - **the audience of a stored blob**, [`content_audience`]: the S1 resolver
//!   ([`audience_nodes`](super::replication_audience::audience_nodes)) over
//!   the row's own provenance — never a sender's assertion.
//! - **the target**, [`durability_mode`]: below the §R-policy feasibility
//!   floor `C₁ = N + K` every audience node holds the full blob; at or above
//!   it the fountain tuple applies.
//!
//! **Consent is supreme** (CC 6.1.5.3 "What is unchanged"): the audience is
//! the claimed nodes under their owners' allow lists, so a node a cohort is
//! denied on is in no set computed here — not a target, not a deficit. A
//! deficit is reported; nothing here widens a set to meet it.

use std::collections::BTreeSet;

use super::replication_audience::{audience_nodes, Audience};
use super::types::cohort_scope as cs;
use super::{Error, FederationDirectory};

/// The shipped fountain tuple's source-symbol count `N` (CC 6.1.5 §R-policy,
/// restating CIRISEdge `DEFAULT_N_SOURCE`). CC restates the constant; it does
/// not define it, and neither does persist — this is the default a caller
/// uses when the content declares no tuple of its own.
pub const DEFAULT_N_SOURCE: usize = 20;

/// The shipped fountain tuple's repair-symbol count `K` (CC 6.1.5 §R-policy,
/// restating CIRISEdge `DEFAULT_K_REPAIR`).
pub const DEFAULT_K_REPAIR: usize = 6;

/// `C₁ = N + K` at the shipped tuple: the feasibility floor — a
/// one-symbol-per-peer spread of `N + K` distinct symbols needs that many
/// peers (CC 6.1.5 §R-policy derivation).
pub const DEFAULT_FEASIBILITY_FLOOR: usize = DEFAULT_N_SOURCE + DEFAULT_K_REPAIR;

/// How content of a given audience is placed (CC 6.1.5.3 "The target at
/// every tier").
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityMode {
    /// The audience is smaller than `N + K`: a symbol spread cannot be one
    /// per peer, so **every audience node holds the full blob** and the
    /// replication factor is the audience size. Most families.
    Full,
    /// The audience is `N + K` nodes or more: the §R-policy tuple (or the
    /// producer's declared tuple) applies.
    Tuple,
}

/// **The target mode for an audience of `audience_size` nodes**, given the
/// content's `n_plus_k` (the producer's declared tuple, else
/// [`DEFAULT_FEASIBILITY_FLOOR`]). Strictly *smaller than* `N + K` is
/// [`DurabilityMode::Full`]; exactly `N + K` is a feasible spread.
#[must_use]
pub fn durability_mode(audience_size: usize, n_plus_k: usize) -> DurabilityMode {
    if audience_size < n_plus_k {
        DurabilityMode::Full
    } else {
        DurabilityMode::Tuple
    }
}

/// Who a stored blob's content reaches, or why it cannot be said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentAudience {
    /// The commons, or a public group: every peer. No deficit is enumerable.
    Everyone,
    /// Exactly these claimed nodes (possibly none).
    Nodes(BTreeSet<String>),
    /// The row names no group its scope needs (a `family` / room row with no
    /// group key), or no author for `self` content: the audience cannot be
    /// resolved from the row, and nothing is reported as a target.
    Unresolvable,
}

/// **The audience of content stored at `cohort_scope`**, from the row's own
/// provenance (`author_key_id`, and `group_key_id` — the family or community
/// the row is bound to). One resolver
/// ([`audience_nodes`](super::replication_audience::audience_nodes)); this
/// only chooses its `target`:
///
/// - `self`: the author's principals (the human behind an occurrence or a
///   node, [`principals_of`](super::self_collective::principals_of)) — the
///   union of each principal's own nodes that `self` content reaches;
/// - `family` / `community` / `affiliations`: the named group;
/// - the commons: every peer.
pub async fn content_audience<D>(
    dir: &D,
    cohort_scope: &str,
    author_key_id: Option<&str>,
    group_key_id: Option<&str>,
) -> Result<ContentAudience, Error>
where
    D: FederationDirectory + ?Sized,
{
    let Some(scope) = cs::Scope::parse(cohort_scope) else {
        return Ok(ContentAudience::Unresolvable);
    };
    let from = |a: Audience| match a {
        Audience::Everyone => ContentAudience::Everyone,
        Audience::Nodes(n) => ContentAudience::Nodes(n),
    };
    match scope.placement() {
        cs::Placement::Commons => Ok(ContentAudience::Everyone),
        cs::Placement::SelfCollective => {
            let Some(author) = author_key_id.filter(|a| !a.is_empty()) else {
                return Ok(ContentAudience::Unresolvable);
            };
            let mut out = BTreeSet::new();
            for p in super::self_collective::principals_of(dir, author).await? {
                match audience_nodes(dir, cohort_scope, Some(&p)).await? {
                    Audience::Everyone => return Ok(ContentAudience::Everyone),
                    Audience::Nodes(n) => out.extend(n),
                }
            }
            Ok(ContentAudience::Nodes(out))
        }
        cs::Placement::Targeted(_) => match group_key_id.filter(|g| !g.is_empty()) {
            Some(group) => Ok(from(audience_nodes(dir, cohort_scope, Some(group)).await?)),
            None => Ok(ContentAudience::Unresolvable),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I413 / I414 (unit) — the boundary on both sides, with the shipped
    /// tuple written as a LITERAL (20 + 6), not derived from the consts.
    #[test]
    fn the_small_audience_rule_switches_at_exactly_n_plus_k() {
        assert_eq!(DEFAULT_FEASIBILITY_FLOOR, 26, "CC 6.1.5: C1 = N + K = 26");
        assert_eq!(durability_mode(0, 26), DurabilityMode::Full);
        assert_eq!(durability_mode(1, 26), DurabilityMode::Full);
        assert_eq!(durability_mode(25, 26), DurabilityMode::Full, "I413");
        assert_eq!(durability_mode(26, 26), DurabilityMode::Tuple, "I414");
        assert_eq!(durability_mode(27, 26), DurabilityMode::Tuple);
        // a producer's declared tuple moves the floor with it
        assert_eq!(durability_mode(9, 10), DurabilityMode::Full);
        assert_eq!(durability_mode(10, 10), DurabilityMode::Tuple);
    }
}
