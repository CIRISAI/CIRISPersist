//! v52.0.0 (CIRISPersist#946; CC 3.3.1 `consent:community_trust`, the capture
//! gate of the three-artifact trace-sharing chain) — **a node owner's
//! standing grant that the node's sealed reasoning traces may be captured**
//! for the community-trust plane, and the ONE fold that decides whether it
//! stands.
//!
//! The row is the node's own (`attesting_key_id == attested_key_id == node`),
//! and it MUST list, in `subject_key_ids`, the key that was the node's owner
//! **at the grant's own `asserted_at`** — `owner_of(node)` resolved at that
//! instant over the replicated owner-binding rows, never the receiver's
//! current view — so the owner can always revoke it (their `withdraws` admits
//! on the CC 2.4.1.1 third-party path, rule 2) whatever ownership later
//! becomes, and every peer reaches the same verdict.
//!
//! **The fold (normative):** rows are grouped by `attested_key_id`. A
//! `withdraws` / `recants` is a BOUNDARY, not a deletion: the latest admitted
//! revocation's `asserted_at` is `R`, and every grant with `asserted_at ≤ R`
//! is out, whichever row the revocation named — so revoking the newest grant
//! never resurrects an older one. Among the grants after `R` (all of them, if
//! there is no revocation) the latest `asserted_at` wins, ties on the
//! smallest attestation id; no grant means no consent. Capture resumes only
//! on a FRESH grant asserted after `R`.

use super::precedence::{references_attestation_id_from_envelope, retraction_entitled};
use super::types::attestation_type;
use super::{Attestation, Error, FederationDirectory};

/// The canonical leaf (CC 3.1.7 R1 catalogue row).
pub const COMMUNITY_TRUST_DIMENSION: &str = "consent:community_trust:v1";
/// The family stem every version of the leaf shares.
pub const COMMUNITY_TRUST_PREFIX: &str = "consent:community_trust";

fn is_community_trust(row: &Attestation) -> bool {
    super::admission::envelope_dimension(&row.attestation_envelope)
        .is_some_and(|d| d == COMMUNITY_TRUST_PREFIX || d.starts_with("consent:community_trust:"))
}

/// **The admission gate** (CC 3.3.1 "Revocation authority", normative), run
/// by `put_attestation` on every backend. A no-op off the family. On it:
///
/// 1. the row is the NODE's own — `attesting_key_id == attested_key_id`
///    (a third party cannot grant capture of someone else's node);
/// 2. `subject_key_ids` lists the node's owner **as of the grant's
///    `asserted_at`** ([`owner_granters_in_force_at`]). With no owner binding
///    in force at that instant the grant is refused and NOT stored — persist
///    holds no queue for it; the binding rows replicate first and the grant is
///    re-put (first-write-wins on its id, so nothing is lost).
///
/// [`owner_granters_in_force_at`]: super::admission::owner_granters_in_force_at
pub async fn check_community_trust_grant_admission(
    directory: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<(), Error> {
    if row.attestation_type != attestation_type::SCORES || !is_community_trust(row) {
        return Ok(());
    }
    if row.attesting_key_id != row.attested_key_id {
        return Err(Error::InvalidArgument(format!(
            "{COMMUNITY_TRUST_PREFIX}: a capture grant is the NODE's own row (CC 3.3.1) — \
             attesting_key_id {:?} must be the attested node {:?}",
            row.attesting_key_id, row.attested_key_id
        )));
    }
    let owners = super::admission::owner_granters_in_force_at(
        directory,
        &row.attested_key_id,
        row.asserted_at,
    )
    .await?;
    if owners.is_empty() {
        return Err(Error::InvalidArgument(format!(
            "{COMMUNITY_TRUST_PREFIX}: no owner binding over {:?} is in force at the grant's \
             instant {} — the owner-binding rows must be held before the grant is admitted \
             (CC 3.3.1: the listed owner must be able to revoke)",
            row.attested_key_id, row.asserted_at
        )));
    }
    if !row.subject_key_ids.iter().any(|s| owners.contains(s)) {
        return Err(Error::InvalidArgument(format!(
            "{COMMUNITY_TRUST_PREFIX}: subject_key_ids {:?} does not list the node's owner at \
             the grant's instant ({:?}) — the owner MUST always be able to revoke (CC 3.3.1)",
            row.subject_key_ids,
            owners.iter().collect::<Vec<_>>()
        )));
    }
    Ok(())
}

/// **The fold** (CC 3.3.1, normative) over the rows ABOUT `node`
/// (`attested_key_id == node`): the standing grant, or `None`.
#[must_use]
pub fn fold_community_trust(rows: &[Attestation], node: &str) -> Option<Attestation> {
    let grants: Vec<&Attestation> = rows
        .iter()
        .filter(|r| {
            r.attested_key_id == node
                && r.attesting_key_id == node
                && r.attestation_type == attestation_type::SCORES
                && is_community_trust(r)
        })
        .collect();
    if grants.is_empty() {
        return None;
    }
    // The boundary: the latest ADMITTED revocation naming any grant of the
    // node (entitled against the grant it names — the node's own, the listed
    // owner's under rule 2, or one the write door stamped).
    let boundary = rows
        .iter()
        .filter(|r| {
            r.attestation_type == attestation_type::WITHDRAWS
                || r.attestation_type == attestation_type::RECANTS
        })
        .filter_map(|r| {
            let target = references_attestation_id_from_envelope(&r.attestation_envelope)?;
            let g = grants.iter().find(|g| g.attestation_id == target)?;
            retraction_entitled(r, g).then_some(r.asserted_at)
        })
        .max();
    let mut live: Vec<&Attestation> = grants
        .into_iter()
        .filter(|g| boundary.is_none_or(|r| g.asserted_at > r))
        .collect();
    live.sort_by(|a, b| {
        b.asserted_at
            .cmp(&a.asserted_at)
            .then_with(|| a.attestation_id.cmp(&b.attestation_id))
    });
    live.into_iter().next().cloned()
}

/// **The read door** — `Engine::community_trust_consent_for`, pyo3
/// `community_trust_consent_json`: the standing capture grant for `node`, if
/// any. Reads the rows about the node and folds them; never a stored verdict.
pub async fn community_trust_consent_for(
    directory: &dyn FederationDirectory,
    node: &str,
) -> Result<Option<Attestation>, Error> {
    let rows = directory.list_attestations_for(node).await?;
    Ok(fold_community_trust(&rows, node))
}
