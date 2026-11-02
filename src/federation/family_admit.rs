//! v61 (CIRISPersist#934, S4b) — **the family doors, decided once.**
//!
//! `put_family`, `put_family_local`, `put_family_membership_revocation` and
//! `put_family_membership_widening` were written twice, in
//! `store/{sqlite,postgres}.rs`, with the same gates in the same order (the
//! community plane's twin moved in v57, `community_admit`). Each door is now
//! one function here; a backend implements [`FamilyStore`]: the SQL, the
//! serve position (V130), the dialect's JSON encodings. It decides nothing.
//!
//! # Which instant each plan reads
//!
//! The roster plans judge standing at the row's own `effective_at` (the #908
//! family half); the widening's future-dating bound is the row's
//! `effective_at` against the clock (`reject_future_dated_family_widening`,
//! unchanged).

use super::group_plane::{self, GroupPlaneStore, GroupPlaneTable, GroupRowLink, GroupSigned};
use super::types::{
    Family, FamilyMember, GroupSupersedeProof, RosterCosignature, SignedFamily,
    SignedFamilyMembershipRevocation, SignedFamilyMembershipWidening,
};
use super::{Error, FederationDirectory};

/// The verified authority signature a signed family carries onto its row.
#[derive(Debug, Clone)]
pub(crate) struct PlannedFamilySignature {
    /// The family the row is.
    pub(crate) family_key_id: String,
    /// `authority_key_id`.
    pub(crate) authority_key_id: String,
    /// `scrub_signature_classical`.
    pub(crate) scrub_signature_classical: String,
    /// `scrub_signature_pqc`.
    pub(crate) scrub_signature_pqc: Option<String>,
    /// v49.0.0 (#910.5) — a first copy of an amended version keeps its proof.
    pub(crate) supersede_proof: Option<GroupSupersedeProof>,
    /// v52.0.0 (#955, V162) — the founding members' consent.
    pub(crate) cosignatures: Vec<RosterCosignature>,
}

/// The family executor. Storage only.
#[async_trait::async_trait]
pub(crate) trait FamilyStore: FederationDirectory + GroupPlaneStore + Sized {
    /// Insert the family row (its hash set) at a fresh serve position.
    async fn store_planned_family(&self, row: Family) -> Result<(), Error>;

    /// Attach the verified authority signature, the proof and the
    /// co-signatures to the family row, re-stamping its serve position: the
    /// signed serve cursor admits the row with this statement.
    async fn store_family_signature(&self, planned: PlannedFamilySignature) -> Result<(), Error>;

    /// Insert the revocation row (its hash set), idempotent on its
    /// three-part key. `true`: a new row landed.
    async fn store_planned_family_revocation(
        &self,
        revocation: &SignedFamilyMembershipRevocation,
    ) -> Result<bool, Error>;

    /// Insert the widening row (its hash set), idempotent on its three-part
    /// key.
    async fn store_planned_family_widening(
        &self,
        widening: &SignedFamilyMembershipWidening,
    ) -> Result<(), Error>;
}

/// The door: every backend's `put_family_local` (the genesis-bake path: no
/// authority signature, the signed columns NULL).
pub(crate) async fn put_family_local_planned<D: FamilyStore>(
    dir: &D,
    mut row: Family,
) -> Result<(), Error> {
    super::admission::check_family_consensus_protocol_form(&row.consensus_protocol)?;
    // v13.3.0 (CIRISPersist#386) — every member key_id must be a registered
    // key (the dropped family_key_id FK's real invariant).
    super::admission::validate_family_members(dir, &row).await?;
    row.persist_row_hash = super::types::compute_persist_row_hash(&row)?;
    dir.store_planned_family(row).await
}

/// The door: every backend's `put_family`.
pub(crate) async fn put_family_planned<D: FamilyStore>(
    dir: &D,
    family: SignedFamily,
) -> Result<(), Error> {
    // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship BEFORE any other
    // admission step.
    super::verify_family_admission(dir, &family).await?;
    // v61 (CIRISPersist#991) — the object as signed, for its row.
    let offered = GroupSigned::Family(family.clone());
    // v49.0.0 (CIRISPersist#910.5) — an occupied id: an identical re-put is a
    // no-op, a proof-carrying amendment this node's own state authorizes is
    // applied as a supersede, anything else is refused.
    if let super::group_amendment::OccupiedRoute::Settled(_) =
        super::group_amendment::route_occupied_family(dir, &family).await?
    {
        return Ok(());
    }
    let SignedFamily {
        family: row,
        authority_key_id,
        scrub_signature_classical,
        scrub_signature_pqc,
        supersede_proof,
        cosignatures,
    } = family;
    let family_key_id = row.family_key_id.clone();
    put_family_local_planned(dir, row).await?;
    // v21.0.0 (#502 E4 followup) — the verified authority signature is kept
    // with the row, so the row can prove its own authorship later.
    dir.store_family_signature(PlannedFamilySignature {
        family_key_id,
        authority_key_id,
        scrub_signature_classical,
        scrub_signature_pqc,
        supersede_proof,
        cosignatures,
    })
    .await?;
    // v61 (CIRISPersist#991) — the row follows its object.
    group_plane::sync_group_row_offered(dir, offered.link(), Some(&offered)).await?;
    Ok(())
}

/// The door: every backend's `put_family_membership_revocation`.
pub(crate) async fn put_family_membership_revocation_planned<D: FamilyStore>(
    dir: &D,
    mut revocation: SignedFamilyMembershipRevocation,
) -> Result<(), Error> {
    // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship first.
    super::verify_family_membership_revocation_admission(dir, &revocation).await?;
    let offered = GroupSigned::FamilyRevocation(revocation.clone());
    let row = &revocation.family_membership_revocation;
    // v49.0.0 (CIRISPersist#910.3) — standing, by the family's own
    // `consensus_protocol` at the row's instant (the #908 family half).
    super::check_family_roster_authority(
        dir,
        &row.family_key_id,
        &revocation.authority_key_id,
        &super::roster_row_signer_set(&revocation.authority_key_id, &revocation.cosignatures),
        FamilyMember {
            key_id: row.removed_identity_key_id.clone(),
            joined_at: row.effective_at,
            role: None,
        },
        true,
        row.effective_at,
    )
    .await?;
    let hash = super::types::compute_persist_row_hash(row)?;
    revocation.family_membership_revocation.persist_row_hash = hash;
    let row = &revocation.family_membership_revocation;
    // CEG §7.7 (#161 Ask 5) — the removal-direction membership change.
    let removal_event = super::hard_case::membership_removed_event(
        super::hard_case::kind::FAMILY_MEMBERSHIP_CHANGE,
        &row.family_key_id,
        &row.removed_identity_key_id,
        row.effective_at,
    );
    let link = GroupRowLink::plane(
        GroupPlaneTable::FamilyRevocations,
        &row.family_key_id,
        &row.removed_identity_key_id,
        row.effective_at,
    );
    // v47.1.0 (#861) / v49.0.0 (#910.1) — idempotent on the three-part key.
    if dir.store_planned_family_revocation(&revocation).await? {
        // v57.0.0 (#988 item 2) — an observation: a node with no attester
        // records nothing; the removal already landed.
        super::hard_case::record_observation(dir, removal_event).await?;
    }
    // v61 (CIRISPersist#991) — the row follows its object.
    group_plane::sync_group_row_offered(dir, link, Some(&offered)).await?;
    Ok(())
}

/// The door: every backend's `put_family_membership_widening` (v49.0.0,
/// #910): the primary and every co-signature, no future-dating, standing by
/// the family's own `consensus_protocol` at the row's instant, the family
/// existing, idempotent on the three-part key.
pub(crate) async fn put_family_membership_widening_planned<D: FamilyStore>(
    dir: &D,
    mut widening: SignedFamilyMembershipWidening,
) -> Result<(), Error> {
    super::verify_family_membership_widening_admission(dir, &widening).await?;
    let offered = GroupSigned::FamilyWidening(widening.clone());
    let row = &widening.family_membership_widening;
    super::reject_future_dated_family_widening(row.effective_at)?;
    super::check_family_roster_authority(
        dir,
        &row.family_key_id,
        &widening.authority_key_id,
        &super::roster_row_signer_set(&widening.authority_key_id, &widening.cosignatures),
        row.member(),
        false,
        row.effective_at,
    )
    .await?;
    if dir.lookup_family(&row.family_key_id).await?.is_none() {
        return Err(Error::InvalidArgument(format!(
            "{} does not exist in federation_families",
            row.family_key_id
        )));
    }
    let hash = super::types::compute_persist_row_hash(row)?;
    widening.family_membership_widening.persist_row_hash = hash;
    let row = &widening.family_membership_widening;
    let link = GroupRowLink::plane(
        GroupPlaneTable::FamilyWidenings,
        &row.family_key_id,
        &row.member_key_id,
        row.effective_at,
    );
    dir.store_planned_family_widening(&widening).await?;
    // v61 (CIRISPersist#991) — the row follows its object.
    group_plane::sync_group_row_offered(dir, link, Some(&offered)).await?;
    Ok(())
}
