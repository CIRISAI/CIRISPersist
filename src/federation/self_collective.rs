//! v46.3.0 (CIRISPersist#884, `FSD/SELF_COLLECTIVE_TRANSFER.md` §4) — **the
//! send set of a `SelfOwn`-projected record.**
//!
//! CC 5.2: self/family bytes are *delivered to admitted members of the
//! relevant self-collective … via the at-rest encryption flow, NOT via the
//! public holder-discovery directory*. Persist classified that plane
//! (`Projection::SelfOwn → RecipientBasis::OwnRoster`) and never resolved it;
//! the resolver a consumer had was [`consent_peers_by_principals`] — explicit
//! grants only — and CC 3.2 makes a person's consent to their own node a
//! category error, so no grant ever names an owner's second device. A `self`
//! row, and the `key_grant` set the retroactive re-key emits for it, reached
//! no second device at all (#884, edge `FSD/CONTENT_TRANSFER.md` §5.3 R2).
//!
//! This module is the resolver. It is a SIBLING of the consent read, not a
//! widening of it: the consent set stays a consent fact; the self-collective
//! is a cryptographic fact (CC 3.3.6) read from the occurrence plane.
//!
//! [`consent_peers_by_principals`]: super::consent_by_humans::consent_peers_by_principals

use std::collections::BTreeSet;

use super::types::cohort_scope;
use super::{Error, FederationDirectory};

/// **The principals of `k`** — the humans `k` speaks for, on the
/// self-collective plane: the identities `k` is an ACTIVE occurrence of
/// (#873's `active_identities_for_occurrence`), the node's OWNER
/// ([`owner_of`](super::admission::owner_of) — operator ruling, #884: a node
/// always has exactly one human owner, and what a node seals is the
/// human's), and `k` itself when it is a user-role key. Sorted, deduped.
/// An ambiguous owner (pre-#23 history) contributes no principal — fail
/// closed, as [`nodes_owned_by`](super::admission::nodes_owned_by) skips it.
///
/// Generic over an unsized directory so the hold path
/// ([`is_audience`](super::replication::hold::is_audience)) and the send set
/// read the SAME fold; the consent half of the send set keeps its own
/// (`steward_bindings_of`, the humans-consent spelling).
pub async fn principals_of<D>(dir: &D, k: &str) -> Result<Vec<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    let mut out = dir.active_identities_for_occurrence(k).await?;
    match super::admission::owner_of(dir, k).await {
        Ok(Some(owner)) => {
            // PR #889 review (P1) — a REVOKED occurrence does not get its
            // owner back through the owner binding. An occurrence
            // revocation is the owner's signed "k no longer acts for me"; a
            // live `delegates_to(owner → k)` beside it is the lost device's
            // shape, not a second vote. `k` bound to `owner` at some time and
            // not active now ⇒ the owner is not k's principal. A node the
            // owner never bound as an occurrence (KEM-less) keeps its owner:
            // ownership is then the only fact, and it is a live one.
            let ever_bound = dir
                .list_identity_occurrences_by_occurrence_key(k)
                .await?
                .iter()
                .any(|o| o.identity_key_id == owner);
            if !ever_bound || out.contains(&owner) {
                out.push(owner);
            }
        }
        Ok(None) | Err(Error::AmbiguousNodeOwner { .. }) => {}
        Err(e) => return Err(e),
    }
    if let Some(rec) = dir.lookup_public_key(k).await? {
        if super::types::identity_type::set_contains(
            &rec.identity_type,
            super::types::identity_type::USER,
        ) {
            out.push(k.to_owned());
        }
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// **The nodes of a human** — [`nodes_owned_by`](super::admission::nodes_owned_by):
/// every node whose live owner binding names `p`. NODES, not occurrences
/// (edge `FSD/CONTENT_TRANSFER.md` §6.1, CC 4.4.3.2.4.1(b)): an occurrence is
/// a content-KEM target (CC 3.3.6.1), not a replication endpoint — a
/// device-class occurrence has no destination, and under
/// `use_node_identity` (CIRISEdge#541) an actor occurrence's key is not the
/// key peers see. The send set is homogeneous in node key ids, as the consent
/// half already is.
pub(crate) async fn nodes_of<D>(dir: &D, p: &str) -> Result<Vec<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    super::admission::nodes_owned_by(dir, p).await
}

/// **The active occurrences of a human** — the KEM targets of the
/// self-collective (CC 3.3.6). Read by the read-side `self` gate
/// (`scope::build_caller_admission_from_directory`, v46.3.1 / #888) beside
/// [`nodes_of`]: a row targeted at any of them is the caller's own.
pub(crate) async fn occurrences_of<D>(dir: &D, identity: &str) -> Result<Vec<String>, Error>
where
    D: FederationDirectory + ?Sized,
{
    Ok(dir
        .list_identity_occurrences_active(identity)
        .await?
        .into_iter()
        .map(|o| o.occurrence_key_id)
        .collect())
}

/// **Does `signer` speak for `author` on the key plane?** (FSD §4.1) —
/// `signer` is `author`, or the two share a principal
/// ([`principals_of`]): the same human owns the node that signed and
/// authored the row (CC 3.3.6 — the self-collective IS the person). The
/// hold path's self/family arm asks the same question of `(our_key, author)`.
///
/// A content-axis `key_grant` set is signed by the node that SEALED the
/// bytes (`Engine::emit_key_grant` → `emit_attestation_self`, the node's
/// derived key); a chat row is authored by a PERSON or their actor
/// occurrence. v46.0.0 split author from sealer on the epoch axis
/// (`FSD/EPOCH_MINTER.md`) and the content axis kept comparing the signer
/// to the author, so a person-authored self blob's set was retired as "not
/// the author" on every second device — silently, at the adopt's pending
/// projection (#884). A REVOKED occurrence with no live owner binding shares
/// no principal: a lost device that still knows a DEK cannot grant an
/// outsider (I65); a family member's node shares none either.
pub async fn speaks_for<D>(dir: &D, signer: &str, author: &str) -> Result<bool, Error>
where
    D: FederationDirectory + ?Sized,
{
    if signer == author {
        return Ok(true);
    }
    let of_author = principals_of(dir, author).await?;
    if of_author.is_empty() {
        return Ok(false);
    }
    let of_signer = principals_of(dir, signer).await?;
    Ok(of_signer.iter().any(|p| of_author.contains(p)))
}

/// **The send set of key `k` for a record at `cohort_scope`** (FSD §4).
///
/// - every scope: [`consent_peers_by_principals`](super::consent_by_humans::consent_peers_by_principals)`(k)`;
/// - `self` / `family`: ∪ the NODES owned by every principal of `k`
///   ([`nodes_of`]; never occurrence keys);
/// - `family`: ∪ the nodes owned by every active member of every family a
///   principal of `k` is an active member of;
/// - never `k` itself. Sorted, deduped.
///
/// `community` / `affiliations` / the commons return the consent set
/// unchanged: those planes are `Cohort` / `Global` projected and their
/// audience is the roster, not the collective.
pub async fn send_set_for(
    dir: &dyn FederationDirectory,
    k: &str,
    cohort_scope: &str,
) -> Result<Vec<String>, Error> {
    let mut set: BTreeSet<String> = super::consent_by_humans::consent_peers_by_principals(dir, k)
        .await?
        .into_iter()
        .collect();
    if matches!(cohort_scope, cohort_scope::SELF | cohort_scope::FAMILY) {
        let principals = principals_of(dir, k).await?;
        for p in &principals {
            set.extend(nodes_of(dir, p).await?);
        }
        if cohort_scope == cohort_scope::FAMILY {
            for p in &principals {
                for fam in dir.list_families_for_member_active(p).await? {
                    for m in dir.active_family_members(&fam.family_key_id).await? {
                        set.extend(nodes_of(dir, &m.key_id).await?);
                    }
                }
            }
        }
    }
    set.remove(k);
    Ok(set.into_iter().collect())
}
