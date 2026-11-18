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
//!
//! # A fork is held as a tip (v62.0.0, kernel pass 2)
//!
//! CC 2.7.8: "Two versions of one head wait as tips." A version whose
//! `prev_head_digest` does not name the held head (a sibling of it, a
//! successor of a version not yet held, a second founding version) is no
//! longer refused: the kernel reads it as a tip
//! ([`crate::kernel::head::head_answer`]) and the executor holds it in
//! `federation_group_tips` beside the head, which stays where it is
//! ([`HeadVerdict::Tip`]). A version naming the held head becomes the head
//! ([`HeadVerdict::Extends`]) and leaves the tips: re-offered once the head
//! it names is held, a held tip runs the whole door again and extends.
//! An unheld group (nothing to supersede yet) WAITS (v62.0.0, CC 2.7:
//! [`unheld_group`], `federation_link_not_held`). What stays refused is a
//! `supersede_proof` that contradicts the version it rides on (a
//! matter of one row's shape, before the kernel; CIRISKernel
//! `DIFFERENCES.md` row 8).

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

/// v62.0.0 (kernel pass 2, I2811) — **what the held-head verdict decided**
/// for an offered version of a held group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeadVerdict {
    /// The version names the held head (or is an accord birth recorded as
    /// replacing exactly the held row): it becomes the head.
    Extends,
    /// The version names another version, or none: held as a tip beside
    /// the head, which does not move (CC 2.7.8, "Two versions of one head
    /// wait as tips").
    Tip,
}

/// What the executor wrote for a supersede.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SupersedeWritten {
    /// The head's version after the write: the new version for
    /// [`HeadVerdict::Extends`], the held head's unchanged version for
    /// [`HeadVerdict::Tip`].
    pub(crate) version: u32,
    /// What the verdict decided.
    pub(crate) verdict: HeadVerdict,
}

/// v62.0.0 (CC 2.7) — the supersede names a group this node does not hold
/// (yet, or no longer: a plan/commit race on postgres): a link not held, the
/// WAIT [`Error::LinkNotHeld`] under the cohort as its plane, never a
/// terminal refusal or a substrate error. Before v62 the verdict answered
/// `federation_invalid_argument`, and postgres's executor carried a
/// `federation_backend` arm for the row vanishing under the write. Both
/// backends answer this one value: the verdict and both executors call it.
pub(crate) fn unheld_group(planned: &PlannedSupersede) -> Error {
    Error::link_not_held(
        planned.cohort_str,
        format!(
            "supersede: {} group {:?} is unheld here (nothing to supersede yet)",
            planned.cohort_str,
            planned.head.group_key_id()
        ),
    )
}

/// **The supersede's verdict against the held head**, asked by the executor
/// inside the transaction that replaces it. `held_row_hash` is the held live
/// row's `persist_row_hash`, `None` when no row is held.
///
/// - an unheld group has nothing to supersede yet: the WAIT
///   [`unheld_group`] (v62.0.0, CC 2.7; `InvalidArgument` before);
/// - v49.0.0 (#910.5) — a proof names the version it replaces; v62.0.0
///   (kernel pass 2): the version's own `prev_head_digest` is that version,
///   so a proof naming another is a contradiction inside one row;
/// - v53.0.0 (CC 3.2 T6) — the version names the head it succeeds, and
///   becomes the head; v62.0.0 (kernel pass 2, I2811): a version that names
///   another is held as a tip ([`HeadVerdict::Tip`]), never refused.
pub(crate) fn held_head_verdict(
    planned: &PlannedSupersede,
    held_row_hash: Option<&str>,
) -> Result<HeadVerdict, Error> {
    let key = planned.head.group_key_id();
    let Some(held) = held_row_hash else {
        return Err(unheld_group(planned));
    };
    let proof = planned.head.supersede_proof();
    if let Some(p) = proof {
        super::group_amendment::check_proof_names_versions_prior(
            planned.cohort_str,
            key,
            p,
            planned.head.prev_head_digest(),
            held,
        )?;
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
    /// In ONE transaction: read the held head, ask [`held_head_verdict`];
    /// on [`HeadVerdict::Extends`], snapshot the prior into
    /// `federation_group_versions`, rewrite the live row (the signature with
    /// the record it authorizes, #651) at a fresh serve position, bump
    /// `version`, and drop the new head from `federation_group_tips`; on
    /// [`HeadVerdict::Tip`] (v62.0.0, kernel pass 2), hold the offered
    /// signed version in `federation_group_tips` (idempotent on its
    /// `persist_row_hash`) and leave the live row as it is.
    async fn store_planned_supersede(
        &self,
        planned: PlannedSupersede,
    ) -> Result<SupersedeWritten, Error>;
}

impl PlannedHead {
    /// v62.0.0 (kernel pass 2, K1) — the signed wrapper as JSON, for the tip row.
    pub(crate) fn signed_json(&self) -> Result<serde_json::Value, Error> {
        match self {
            Self::Family(f) => serde_json::to_value(f),
            Self::Community(c) => serde_json::to_value(c),
        }
        .map_err(|e| Error::Backend(format!("tip snapshot serialize: {e}")))
    }
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
    let planned = PlannedSupersede {
        cohort_str,
        head,
        authorization,
    };
    // v62.0.0 (wave GC5; CC 2.7.3) — the head verdict once on THIS task,
    // ahead of the executor's transaction: its fold conditions (a stale
    // proof, a `prev_head_digest` naming no held head) read the held head,
    // and mark the fold attempt here. Inside the executor the verdict runs
    // on the backend's writer (sqlite's blocking connection), where no
    // attempt is in scope, so a mark there would be lost and the two
    // backends would answer differently. The executor still re-asks it
    // under its lock (the race guard).
    let held_hash = match cohort {
        Cohort::Family => dir
            .lookup_family(&group_key_id)
            .await?
            .map(|f| f.persist_row_hash),
        _ => dir
            .lookup_community(&group_key_id)
            .await?
            .map(|c| c.persist_row_hash),
    };
    held_head_verdict(&planned, held_hash.as_deref())?;
    let written = dir.store_planned_supersede(planned).await?;
    let version = written.version;
    // v62.0.0 (kernel pass 2, I2811) — a tip is held beside the head: the
    // head's `group:roster:v1` row stays the head's.
    if written.verdict == HeadVerdict::Tip {
        return Ok(version);
    }
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
