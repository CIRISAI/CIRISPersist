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
//!   the row's own provenance — never a sender's assertion — and, for shared
//!   plaintext, over every room the bytes were written into (V184).
//! - **the target**, [`durability_mode`]: below the §R-policy feasibility
//!   floor `C₁ = N + K` every audience node holds the full blob; at or above
//!   it the fountain tuple applies.
//! - **the deficit**, [`durability_deficit`]: the audience nodes with a live
//!   `here` custody report (CIRISPersist#942's fold, never re-derived) and the
//!   rest.
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

/// The deficit's audience, as far as it can be enumerated.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "nodes")]
pub enum DeficitAudience {
    /// Exactly these claimed nodes.
    Nodes(Vec<String>),
    /// The commons or a public group: every peer, so no deficit is
    /// enumerable here (the §R-policy tuple governs).
    Everyone,
    /// The row's provenance names no group its scope needs: nothing is a
    /// target, and nothing is reported missing.
    Unresolvable,
}

/// **The durability deficit of one blob** (CC 6.1.5.3): its audience, the
/// audience nodes with a LIVE `here` custody report, and the rest.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DurabilityDeficit {
    /// Lowercase hex of the at-rest sha256.
    pub sha256_hex: String,
    /// The content's audience.
    pub audience: DeficitAudience,
    /// Audience nodes whose custody verdict is `here` (S2's fold: a live
    /// report, 72 h at the reader's clock). Sorted.
    pub live_here: Vec<String>,
    /// Audience nodes that are not `here`: `received`, `none`, `unknown`, or a
    /// lapsed report. Sorted. A node outside the audience is never listed.
    pub missing: Vec<String>,
    /// Full-blob or tuple placement for this audience (`None` when the
    /// audience is not enumerable).
    pub mode: Option<DurabilityMode>,
}

/// **The durability deficit of `at_rest_sha256`** for `viewer_key_id`,
/// authorized exactly as the custody view (a stranger is `NotGranted` and
/// learns nothing). The audience is [`content_audience`] over the row's own
/// provenance, or for a plaintext row the union over every room the bytes
/// were written into ([`blob_associations`](super::BlobStorage::blob_associations));
/// each audience node's verdict is S2's per-device fold
/// ([`custody_view`](super::custody_ack::custody_view) for the devices it
/// names, [`device_custody_of`](super::custody_ack::device_custody_of) for an
/// audience node it does not), at `now`. `stream_id` adds that stream's
/// delivery receipts, which read `received` — still missing: a receipt is not
/// a copy. Consent is supreme: a `here` from a node outside the audience is
/// not counted, and no node outside it is ever listed.
///
/// **What `here` asserts for a chunk DAG:** a report persist's engine files
/// for its own node means the manifest AND every chunk are held there
/// ([`custody_ack_input_for`](super::custody_ack::custody_ack_input_for)). A
/// report signed by another implementation asserts what that signer checked.
pub async fn durability_deficit<B>(
    backend: &B,
    at_rest_sha256: &[u8; 32],
    viewer_key_id: &str,
    stream_id: Option<&str>,
    n_plus_k: usize,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<DurabilityDeficit, super::BlobError>
where
    B: super::BlobStorage + FederationDirectory + Sync,
{
    use super::custody_ack::{custody_view, CustodyVerdict};
    use super::BlobError;
    let view = custody_view(backend, at_rest_sha256, viewer_key_id, stream_id, now).await?;
    let prov = backend
        .blob_provenance(at_rest_sha256)
        .await?
        .ok_or_else(|| BlobError::NotHeld {
            sha256_hex: hex::encode(at_rest_sha256),
        })?;
    // v53.1.2 (#984 row 4) — the group is the epoch binding's community for
    // a community row, else the group the row itself records (V177): a
    // family row has no binding, and resolved to nothing before.
    //
    // v54.0.0 (Codex round 2 on PR #1050) — a PLAINTEXT row is every room it
    // was written into (V184 `blob_associations`), and its provenance columns
    // name only the first. Resolved from the provenance alone, a node that is
    // only in a later room was in no audience: never a target, never missing,
    // while that room held no copy. The audience is the union over the
    // associations; a sealed row has none, and its room is its binding.
    let associations = backend.blob_associations(at_rest_sha256).await?;
    let rooms: Vec<(String, Option<String>)> = if associations.is_empty() {
        vec![(
            prov.cohort_scope.clone(),
            prov.community_key_id.clone().or(prov.group_key_id.clone()),
        )]
    } else {
        associations
    };
    let mut audience: Option<ContentAudience> = None;
    for (scope, group) in &rooms {
        let room = content_audience(
            backend,
            scope,
            prov.author_key_id.as_deref(),
            group.as_deref(),
        )
        .await
        .map_err(|e| BlobError::Backend(format!("durability deficit: audience: {e}")))?;
        audience = Some(union_audience(audience, room));
    }
    let audience = audience.unwrap_or(ContentAudience::Unresolvable);
    let known: std::collections::BTreeMap<String, CustodyVerdict> = view
        .devices
        .iter()
        .map(|d| (d.device_key_id.clone(), d.state))
        .collect();
    deficit_over(backend, &view.sha256_hex, audience, &known, n_plus_k, now)
        .await
        .map_err(|e| BlobError::Backend(format!("durability deficit: {e}")))
}

/// v54.0.0 (Codex round 2 on PR #1050) — two rooms' audiences as one: any
/// room that reaches everyone makes the content reach everyone; node sets
/// union; a room whose audience cannot be resolved adds no node, and the
/// union is unresolvable only when no room resolves.
fn union_audience(acc: Option<ContentAudience>, room: ContentAudience) -> ContentAudience {
    match (acc, room) {
        (None, r) => r,
        (Some(ContentAudience::Everyone), _) | (Some(_), ContentAudience::Everyone) => {
            ContentAudience::Everyone
        }
        (Some(ContentAudience::Nodes(mut a)), ContentAudience::Nodes(b)) => {
            a.extend(b);
            ContentAudience::Nodes(a)
        }
        (Some(ContentAudience::Nodes(a)), ContentAudience::Unresolvable)
        | (Some(ContentAudience::Unresolvable), ContentAudience::Nodes(a)) => {
            ContentAudience::Nodes(a)
        }
        (Some(ContentAudience::Unresolvable), ContentAudience::Unresolvable) => {
            ContentAudience::Unresolvable
        }
    }
}

/// **The deficit over a resolved audience** — the directory-only core of
/// [`durability_deficit`]. `known` holds verdicts already folded for this blob
/// (the custody view's, with its receipts); every other audience node is
/// folded here by [`device_custody_of`](super::custody_ack::device_custody_of)
/// with no receipt. Only a `here` verdict is a copy.
pub async fn deficit_over<D>(
    dir: &D,
    sha256_hex: &str,
    audience: ContentAudience,
    known: &std::collections::BTreeMap<String, super::custody_ack::CustodyVerdict>,
    n_plus_k: usize,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<DurabilityDeficit, Error>
where
    D: FederationDirectory + ?Sized,
{
    use super::custody_ack::{device_custody_of, CustodyVerdict};
    let nodes = match audience {
        ContentAudience::Everyone | ContentAudience::Unresolvable => {
            return Ok(DurabilityDeficit {
                sha256_hex: sha256_hex.to_owned(),
                audience: if audience == ContentAudience::Everyone {
                    DeficitAudience::Everyone
                } else {
                    DeficitAudience::Unresolvable
                },
                live_here: Vec::new(),
                missing: Vec::new(),
                mode: None,
            })
        }
        ContentAudience::Nodes(n) => n,
    };
    let mut live_here = Vec::new();
    let mut missing = Vec::new();
    for node in &nodes {
        let verdict = match known.get(node) {
            Some(v) => *v,
            None => {
                device_custody_of(dir, node, sha256_hex, None, now)
                    .await?
                    .state
            }
        };
        if verdict == CustodyVerdict::Here {
            live_here.push(node.clone());
        } else {
            missing.push(node.clone());
        }
    }
    Ok(DurabilityDeficit {
        sha256_hex: sha256_hex.to_owned(),
        mode: Some(durability_mode(nodes.len(), n_plus_k)),
        audience: DeficitAudience::Nodes(nodes.into_iter().collect()),
        live_here,
        missing,
    })
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
