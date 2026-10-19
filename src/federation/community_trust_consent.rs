//! v52.0.0 (CIRISPersist#946; CC 3.3.1 `consent:community_trust`, the capture
//! gate of the three-artifact trace-sharing chain) — **a node owner's
//! standing grant that the node's sealed reasoning traces may be captured**
//! for the community-trust plane, and the ONE fold that decides whether it
//! stands.
//!
//! The row is about the node (`attested_key_id == node`) and is the node's own
//! (`attesting_key_id == node`) or — v59.0.0 (CIRISPersist#1096, CC 3.3.1 rc9
//! `1a46e03`) — its owner's: a live roster key of the owner's fedID at the
//! grant's `asserted_at`. In both forms `subject_key_ids` names the node, the
//! agent key that acts on it and the key that was the node's owner
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

use super::attestation_query::{AttestationQuery, FOLD_PAGE};
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

/// v59.0.0 (CIRISPersist#1096) — the refusal token for a grant authored by a
/// key that is neither the node nor a live roster key of the node's owner at
/// the grant's `asserted_at` (`Error::InvalidArgument`, Python `ValueError`,
/// the type this gate's refusals always had).
pub const ATTESTER_NOT_OWNER: &str = "community_trust_attester_not_owner";
/// v59.0.0 (CIRISPersist#1096) — the refusal token for a NEW grant whose
/// `subject_key_ids` does not name all three parties: the node, its owner at
/// the grant's `asserted_at`, and the agent key that acts on the node.
pub const SUBJECTS_INCOMPLETE: &str = "community_trust_subjects_incomplete";

/// Does `subjects` name all three parties (CC 3.3.1 rc9 `1a46e03`): `node`,
/// one of `owners` (the owner at the grant's instant), and an agent key — a
/// held key of the `agent` role that is neither?
async fn names_three_parties(
    directory: &dyn FederationDirectory,
    subjects: &[String],
    node: &str,
    owners: &std::collections::BTreeSet<String>,
) -> Result<bool, Error> {
    if !subjects.iter().any(|s| s == node) {
        return Ok(false);
    }
    for s in subjects {
        if s == node || owners.contains(s) {
            continue;
        }
        if directory.lookup_public_key(s).await?.is_some_and(|k| {
            super::types::identity_type::set_contains(
                &k.identity_type,
                super::types::identity_type::AGENT,
            )
        }) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The owners in force over `node` at `at`, as granters and as the selves
/// they signed as ([`self_of_at`](super::self_roster::self_of_at)): a second
/// device restating its self's binding names the same owner.
async fn owners_at(
    directory: &dyn FederationDirectory,
    node: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<std::collections::BTreeSet<String>, Error> {
    let granters = super::admission::owner_granters_in_force_at(directory, node, at).await?;
    let mut owners = granters.clone();
    for g in &granters {
        owners.insert(super::self_roster::self_of_at(directory, g, at).await?);
    }
    Ok(owners)
}

/// **The admission gate** (CC 3.3.1 "Revocation authority", normative; the
/// owner-authored form, rc9 `1a46e03`, CIRISPersist#1096), run by
/// `put_attestation` on every backend. A no-op off the family. On it:
///
/// 1. the row is about the NODE (`attested_key_id`), whose owner binding is
///    in force at the grant's `asserted_at`
///    ([`owner_granters_in_force_at`]); with none the grant is refused and
///    NOT stored — the binding rows replicate first and the grant is re-put;
/// 2. its author is the node itself, or — the owner-authored form — a live
///    roster key of the owner's fedID at the grant's `asserted_at`
///    ([`acts_as_steward_at`](super::self_roster::acts_as_steward_at), with
///    its W bound [`check_roster_act_fresh`](super::self_roster::check_roster_act_fresh));
///    anyone else is refused [`ATTESTER_NOT_OWNER`];
/// 3. `subject_key_ids` lists the owner as of the grant's `asserted_at`, and —
///    in BOTH forms — the node and the agent key that acts on it, so each
///    party can withdraw (CC 2.4.1.1 rule 2); only the attester recants. A
///    new grant missing the node or the agent key is refused
///    [`SUBJECTS_INCOMPLETE`]; a node-authored grant already HELD that lists
///    only its owner (the v52 shape) is grandfathered — its byte-identical
///    re-offer is admitted as held, and the fold keeps counting it (the open
///    logs how many, [`is_legacy_node_authored_grant`]).
///
/// [`owner_granters_in_force_at`]: super::admission::owner_granters_in_force_at
///
/// v56.0.0 (CIRISPersist#934 step 1) — `fold_at` is the instant the owner
/// bindings are folded at, an INPUT of the shared attestation plan
/// (`attestation_admit::PlanInstants`). The live door passes the grant's own
/// `asserted_at`, which is what this gate read before; a replay of
/// `V(rows, t)` passes `t`.
pub async fn check_community_trust_grant_admission(
    directory: &dyn FederationDirectory,
    row: &Attestation,
    fold_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error> {
    if row.attestation_type != attestation_type::SCORES || !is_community_trust(row) {
        return Ok(());
    }
    let node = &row.attested_key_id;
    let owners = owners_at(directory, node, fold_at).await?;
    if owners.is_empty() {
        return Err(Error::InvalidArgument(format!(
            "{COMMUNITY_TRUST_PREFIX}: no owner binding over {:?} is in force at the grant's \
             instant {} — the owner-binding rows must be held before the grant is admitted \
             (CC 3.3.1: the listed owner must be able to revoke)",
            row.attested_key_id, row.asserted_at
        )));
    }
    if row.attesting_key_id != *node {
        let mut stands = None;
        for owner in &owners {
            if super::self_roster::acts_as_steward_at(
                directory,
                owner,
                &row.attesting_key_id,
                row.asserted_at,
            )
            .await?
            {
                stands = Some(owner.clone());
                break;
            }
        }
        let Some(owner) = stands else {
            return Err(Error::InvalidArgument(format!(
                "{ATTESTER_NOT_OWNER}: {:?} authored a capture grant over {node:?} but is neither \
                 the node nor a live roster key of its owner at the grant's instant {} (CC 3.3.1)",
                row.attesting_key_id, row.asserted_at
            )));
        };
        super::self_roster::check_roster_act_fresh(
            directory,
            &[owner],
            &row.attesting_key_id,
            row.asserted_at,
        )
        .await?;
    }
    if !row.subject_key_ids.iter().any(|s| owners.contains(s)) {
        return Err(Error::InvalidArgument(format!(
            "{COMMUNITY_TRUST_PREFIX}: subject_key_ids {:?} does not list the node's owner at \
             the grant's instant ({:?}) — the owner MUST always be able to revoke (CC 3.3.1)",
            row.subject_key_ids,
            owners.iter().collect::<Vec<_>>()
        )));
    }
    #[cfg(test)]
    if test_support::v52_shape(node) {
        return Ok(());
    }
    // Grandfathered at the door: a grant this node already HOLDS, offered
    // again byte for byte, is admitted as held (it keeps counting); only a
    // new row must name all three parties.
    if let Some(held) = directory.get_attestation(&row.attestation_id).await? {
        if held.persist_row_hash == super::types::compute_persist_row_hash(row)? {
            return Ok(());
        }
    }
    if !names_three_parties(directory, &row.subject_key_ids, node, &owners).await? {
        return Err(Error::InvalidArgument(format!(
            "{SUBJECTS_INCOMPLETE}: subject_key_ids {:?} must name the node {node:?}, its owner \
             at the grant's instant and the agent key that acts on it — each may withdraw (CC \
             3.3.1, CLM-consent-community-trust-owner-authored)",
            row.subject_key_ids
        )));
    }
    Ok(())
}

/// v59.0.0 (CIRISPersist#1096) — is `row` a HELD node-authored capture grant
/// in the v52 shape (it names its owner but not the node or an agent key)?
/// Such a row is grandfathered: it keeps counting in the fold; a new one is
/// refused [`SUBJECTS_INCOMPLETE`]. The sqlite / postgres opens count them in
/// one log line.
pub async fn is_legacy_node_authored_grant(
    directory: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<bool, Error> {
    if row.attestation_type != attestation_type::SCORES
        || !is_community_trust(row)
        || row.attesting_key_id != row.attested_key_id
    {
        return Ok(false);
    }
    let owners = owners_at(directory, &row.attested_key_id, row.asserted_at).await?;
    Ok(!names_three_parties(
        directory,
        &row.subject_key_ids,
        &row.attested_key_id,
        &owners,
    )
    .await?)
}

/// v59.0.0 (CIRISPersist#1096) — the open's count of
/// [`is_legacy_node_authored_grant`] rows among `candidate_ids` (the backend
/// selects the node-authored rows of the family), logged once.
pub async fn log_legacy_node_authored_grants(
    directory: &dyn FederationDirectory,
    candidate_ids: &[String],
    backend: &'static str,
) -> Result<u64, Error> {
    let mut n = 0u64;
    for id in candidate_ids {
        if let Some(row) = directory.get_attestation(id).await? {
            if is_legacy_node_authored_grant(directory, &row).await? {
                n += 1;
            }
        }
    }
    if n > 0 {
        tracing::info!(
            backend,
            legacy_node_authored_grants = n,
            "consent:community_trust: {n} held node-authored grant(s) name only the owner (the v52 \
             shape); grandfathered — they keep counting, a new grant must name the node, the \
             owner and the agent key (CIRISPersist#1096)"
        );
    }
    Ok(n)
}

/// **The fold** (CC 3.3.1, normative) over the rows ABOUT `node`
/// (`attested_key_id == node`): the standing grant, or `None`. Both forms —
/// the node's own grant and its owner's (v59.0.0, CIRISPersist#1096) — are
/// grants of the node; the admission gate decided who may author one, so
/// every admitted capture grant about the node is folded. A revocation of ANY
/// of them is the boundary `R` for all: an owner's recant of its own grant
/// also ends a node-authored grant at or before `R`. What a boundary excludes
/// is grants only, never traces already captured.
#[must_use]
pub fn fold_community_trust(rows: &[Attestation], node: &str) -> Option<Attestation> {
    let grants: Vec<&Attestation> = rows
        .iter()
        .filter(|r| {
            r.attested_key_id == node
                && r.attestation_type == attestation_type::SCORES
                && is_community_trust(r)
        })
        .collect();
    if grants.is_empty() {
        return None;
    }
    // The boundary: the latest ADMITTED revocation naming any grant of the
    // node (entitled against the grant it names — its attester, a listed
    // party under rule 2, or one the write door stamped).
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
    // The community-trust grants about the node and the composers about the
    // node naming them: the fold reads nothing else.
    let mut rows = Vec::new();
    // v59.0.0 (CIRISPersist#1096) — the owner-authored form too: every
    // capture grant about the node, whoever (admittedly) authored it.
    let mut pages = AttestationQuery::to(node, FOLD_PAGE)
        .types(&[attestation_type::SCORES])
        .dimension_prefix(COMMUNITY_TRUST_PREFIX)
        .pages();
    while let Some(page) = pages.next(directory).await? {
        rows.extend(page);
    }
    if !rows.is_empty() {
        let ids: Vec<String> = rows.iter().map(|r| r.attestation_id.clone()).collect();
        rows.extend(
            directory
                .list_composers_referencing_any(&ids, Some(node), None)
                .await?,
        );
    }
    Ok(fold_community_trust(&rows, node))
}

/// Test seam: the v52 gate (the owner alone in `subject_key_ids`) for the
/// grants about one node, to store the grandfathered shape a v58 node held.
/// Keyed by node, so no other test's grants see it.
#[cfg(test)]
pub(crate) mod test_support {
    static V52_NODES: std::sync::Mutex<std::collections::BTreeSet<String>> =
        std::sync::Mutex::new(std::collections::BTreeSet::new());

    /// Is the v52 shape admitted for grants about `node`?
    pub(crate) fn v52_shape(node: &str) -> bool {
        V52_NODES.lock().expect("v52 seam").contains(node)
    }

    /// Admit (or stop admitting) the v52 shape for grants about `node`.
    pub(crate) fn set_v52_shape(node: &str, on: bool) {
        let mut nodes = V52_NODES.lock().expect("v52 seam");
        if on {
            nodes.insert(node.to_owned());
        } else {
            nodes.remove(node);
        }
    }
}
