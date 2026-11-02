//! v61 (CIRISPersist#934, S4b) — **the group supersede, decided once.**
//!
//! `supersede_group_row` (#249 Cut G2) was written twice, in
//! `store/{sqlite,postgres}.rs`, with the same gates in the same order. The
//! door is now one function here; a backend implements
//! [`GroupSupersedeStore`]: the transaction that reads the held head, snapshots
//! it into `federation_group_versions` and rewrites the live row at a fresh
//! serve position (V130). The verdict against the held head
//! ([`held_head_verdict`]) is shared: the executor asks it inside its
//! transaction, on the row it read (FOR UPDATE on postgres), so two
//! concurrent supersedes cannot both pass against the same prior.
//!
//! # Which instant each plan reads
//!
//! None: the supersede is judged on the offered head's proof and
//! `prev_head_digest` against the held head's `persist_row_hash`.

use super::cohort::Cohort;
use super::group_plane::{self, GroupKind, GroupRowLink, GroupSigned};
use super::types::{GroupSupersedeProof, SignedCommunity, SignedFamily};
use super::{Error, FederationDirectory};

/// The new head, decoded from the signed wrapper (#651), its record's
/// `persist_row_hash` stamped.
#[derive(Debug, Clone)]
pub(crate) enum PlannedHead {
    /// A family's new head.
    Family(SignedFamily),
    /// A community's (or an affiliations cohort's) new head.
    Community(SignedCommunity),
}

impl PlannedHead {
    /// The group the head supersedes.
    pub(crate) fn group_key_id(&self) -> &str {
        match self {
            Self::Family(f) => &f.family.family_key_id,
            Self::Community(c) => &c.community.community_key_id,
        }
    }

    fn supersede_proof(&self) -> Option<&GroupSupersedeProof> {
        match self {
            Self::Family(f) => f.supersede_proof.as_ref(),
            Self::Community(c) => c.supersede_proof.as_ref(),
        }
    }

    fn prev_head_digest(&self) -> &str {
        match self {
            Self::Family(f) => &f.family.prev_head_digest,
            Self::Community(c) => &c.community.prev_head_digest,
        }
    }
}

/// A supersede the plan admitted, for the executor's transaction.
#[derive(Debug, Clone)]
pub(crate) struct PlannedSupersede {
    /// The version-history discriminator (`cohort.as_str()`): `affiliations`
    /// keeps its own chain while sharing the community live row (CC
    /// 4.4.3.2.8 / #308).
    pub(crate) cohort_str: &'static str,
    /// The new head.
    pub(crate) head: PlannedHead,
    /// The membership-change justification recorded on the superseded prior.
    pub(crate) authorization: Option<serde_json::Value>,
}

/// **The supersede's verdict against the held head**, asked by the executor
/// inside the transaction that replaces it. `held_row_hash` is the held live
/// row's `persist_row_hash`, `None` when no row is held.
///
/// - an unheld group has nothing to supersede;
/// - v49.0.0 (#910.5) — a proof names the version it replaces;
/// - v53.0.0 (CC 3.2 T6) — the version names the head it succeeds.
pub(crate) fn held_head_verdict(
    planned: &PlannedSupersede,
    held_row_hash: Option<&str>,
) -> Result<(), Error> {
    let key = planned.head.group_key_id();
    let Some(held) = held_row_hash else {
        return Err(Error::InvalidArgument(format!(
            "supersede: unknown {} group {key:?} (nothing to supersede)",
            planned.cohort_str
        )));
    };
    let proof = planned.head.supersede_proof();
    if let Some(p) = proof {
        super::group_amendment::check_proof_names_prior(planned.cohort_str, key, p, held)?;
    }
    super::group_amendment::check_prev_head_names_held(
        planned.cohort_str,
        key,
        planned.head.prev_head_digest(),
        held,
        planned.authorization.as_ref(),
    )
}

/// The versioned cohorts: `self` is not versioned (occurrences are managed
/// individually). Returns the version-history discriminator.
pub(crate) fn check_supersede_cohort(cohort: Cohort) -> Result<&'static str, Error> {
    match cohort {
        Cohort::SelfId => Err(Error::InvalidArgument(
            "supersede: the `self` cohort is not versioned (manage occurrences via \
             put_identity_occurrence / put_identity_occurrence_revocation)"
                .to_string(),
        )),
        Cohort::Family | Cohort::Community | Cohort::Affiliations => Ok(cohort.as_str()),
    }
}

/// v31.0.0 (CIRISPersist#651) — the snapshot is the SIGNED wrapper: decoding
/// the bare record is what silently stranded the caller's signature while
/// every field `signing_envelope()` covers was replaced. Refuses a snapshot
/// that is not one; stamps the record's `persist_row_hash`.
pub(crate) fn decode_planned_head(
    cohort: Cohort,
    new_snapshot: serde_json::Value,
) -> Result<PlannedHead, Error> {
    Ok(match cohort {
        Cohort::Family => {
            let mut f: SignedFamily = serde_json::from_value(new_snapshot).map_err(|e| {
                Error::InvalidArgument(format!("supersede family snapshot decode: {e}"))
            })?;
            f.family.persist_row_hash = super::types::compute_persist_row_hash(&f.family)?;
            PlannedHead::Family(f)
        }
        _ => {
            let mut c: SignedCommunity = serde_json::from_value(new_snapshot).map_err(|e| {
                Error::InvalidArgument(format!("supersede community snapshot decode: {e}"))
            })?;
            c.community.persist_row_hash = super::types::compute_persist_row_hash(&c.community)?;
            PlannedHead::Community(c)
        }
    })
}

/// The supersede executor. Storage only.
#[async_trait::async_trait]
pub(crate) trait GroupSupersedeStore:
    FederationDirectory + group_plane::GroupPlaneStore + super::community_admit::CommunityStore + Sized
{
    /// In ONE transaction: read the held head, ask [`held_head_verdict`],
    /// snapshot the prior into `federation_group_versions`, rewrite the live
    /// row (the signature with the record it authorizes, #651) at a fresh
    /// serve position, bump `version`. Returns the new version.
    async fn store_planned_supersede(&self, planned: PlannedSupersede) -> Result<u32, Error>;
}

/// The door: every backend's `supersede_group_row`.
pub(crate) async fn supersede_group_row_planned<D: GroupSupersedeStore>(
    dir: &D,
    cohort: Cohort,
    new_snapshot: serde_json::Value,
    authorization: Option<serde_json::Value>,
) -> Result<u32, Error> {
    // v61 (CIRISPersist#991) — the new head as its signer signed it, for its
    // `group:roster:v1` row.
    let offered_head = match cohort {
        Cohort::Family => serde_json::from_value::<SignedFamily>(new_snapshot.clone())
            .ok()
            .map(GroupSigned::Family),
        Cohort::Community | Cohort::Affiliations => {
            serde_json::from_value::<SignedCommunity>(new_snapshot.clone())
                .ok()
                .map(GroupSigned::Community)
        }
        Cohort::SelfId => None,
    };
    // Test-only (PR #921 review, F3): a rival supersede of the same community
    // lands here, before this one re-checks its prior.
    #[cfg(test)]
    if matches!(cohort, Cohort::Community) {
        dir.rival_community_write_at(crate::store::test_hooks::RivalPoint::BeforeSupersede)
            .await?;
    }
    let cohort_str = check_supersede_cohort(cohort)?;
    let group_key_id = super::group_amendment::snapshot_group_key_id(cohort, &new_snapshot);
    let head = decode_planned_head(cohort, new_snapshot)?;
    let version = dir
        .store_planned_supersede(PlannedSupersede {
            cohort_str,
            head,
            authorization,
        })
        .await?;
    // v61 (CIRISPersist#991) — the new head's `group:roster:v1` row replaces
    // the prior head's.
    group_plane::sync_group_row_offered(
        dir,
        GroupRowLink::record(
            match cohort {
                Cohort::Family => GroupKind::Family,
                _ => GroupKind::Community,
            },
            &group_key_id,
        ),
        offered_head.as_ref(),
    )
    .await?;
    Ok(version)
}
