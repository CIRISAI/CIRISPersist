//! v57.0.0 (CIRISPersist#934 step 2) — **the community and roster doors,
//! decided once.**
//!
//! # What was here before
//!
//! Four doors were written three times, once in each of
//! `store/{memory,sqlite,postgres}.rs`, byte-identical in their gate SEQUENCE
//! by the #670 scan (`store::parity`) and different only in the write:
//!
//! - `put_community` and `apply_replicated_community`, both one per-backend
//!   body (`put_community_at_door`, v50.0.0): settle, authorship, the #926
//!   trust-root door, the protocol form, the #1034 affiliation config, the
//!   geographic admission, the #925/#927 infrastructure conformance, the
//!   steward binding, the occupied-id route, then the insert and its #758
//!   verdict;
//! - `put_community_membership_revocation` and
//!   `put_community_membership_widening`, the roster planes: authorship, the
//!   future-skew bound, the #908 roster authority, the #925 founder gates;
//!
//! # The shape
//!
//! Each door is one shared function here (`*_planned`; the replicated
//! community door is [`apply_replicated_community_planned`] over the same body): the held-row settle,
//! the one clock read, the plan, then the executor. The plans
//! ([`plan_put_community`], [`plan_put_community_membership_revocation`],
//! [`plan_put_community_membership_widening`]) hold every admission gate and
//! read the directory through the trait only. They read no clock: the door
//! passes [`PlanInstants`]. [`CommunityStore`] is what a backend implements:
//! the row mapping, the SQL, the transaction, the wire index. It decides
//! nothing.
//!
//! The occupied-id route of a community record (v49.0.0, #910.5) splits the
//! same way: [`group_amendment::plan_occupied_community`] decides what an
//! occupied id gets (a no-op, a supersede this node's state authorizes, a
//! trust-root chain), and [`group_amendment::apply_occupied_community`]
//! writes it through the shared supersede door after the plan returns.
//!
//! # Which instant each gate reads
//!
//! - community record: `received_at` for the geographic admission (in-force
//!   location proofs) and the #925/#927 conformance (the founders'
//!   node-bearing), both read the clock before #934 and are #1049
//!   candidates; `fold_at` (the record's head instant) is read by no gate.
//! - revocation and widening: `received_at` for the future-skew bound;
//!   `fold_at` (the row's `effective_at`, its signed instant) for the #908
//!   roster authority and both #925 founder gates, which judged at
//!   `effective_at` before #934.
//! - listing: `received_at` for the future-skew bound; nothing reads
//!   `fold_at`.
//!
//! `store::parity`'s `PLAN_INSTANTS` pins this table from the plan bodies.

use super::attestation_admit::PlanInstants;
use super::group_amendment::{
    self, CommunityDoor, CommunityWrite, OccupiedCommunity, OccupiedRoute,
    ReplicatedCommunityOutcome,
};
use super::hard_case::HardCaseEvent;
use super::types::{
    CommunityMember, SignedCommunity, SignedCommunityMembershipRevocation,
    SignedCommunityMembershipWidening,
};
use super::{Error, FederationDirectory};

/// A community record the plan admitted, before the occupied-id route ran.
pub(crate) struct PlannedCommunity {
    community: SignedCommunity,
    occupied: OccupiedCommunity,
}

/// A community record to insert, exactly as the executor stores it.
pub(crate) struct CommunityInsert {
    /// The record, its `persist_row_hash` stamped.
    pub(crate) community: SignedCommunity,
}

/// What the executor's insert found.
pub(crate) enum StoredCommunity {
    /// The row landed, and its wire index.
    Inserted,
    /// The id was taken by the time of the insert; nothing was written.
    /// Carries the STORED row's `persist_row_hash`, read inside the write.
    Occupied {
        /// The stored row's hash, for the #758 verdict.
        stored_persist_row_hash: String,
    },
}

/// An admitted community-membership revocation, exactly as stored.
pub(crate) struct PlannedCommunityRevocation {
    /// The signed row, its `persist_row_hash` stamped.
    pub(crate) revocation: SignedCommunityMembershipRevocation,
    /// The CEG §7.8 removal event, written in the same transaction.
    pub(crate) removal_event: HardCaseEvent,
    /// v61.3.0 (CIRISPersist#1252) — the shortfall refusal when the ONLY
    /// refusal was the consensus count: the door holds the event or returns it.
    pub(crate) short: Option<Error>,
}

/// An admitted community-membership widening, exactly as stored.
pub(crate) struct PlannedCommunityWidening {
    /// The signed row, its `persist_row_hash` stamped.
    pub(crate) widening: SignedCommunityMembershipWidening,
    /// v61.3.0 (CIRISPersist#1252) — as [`PlannedCommunityRevocation::short`].
    pub(crate) short: Option<Error>,
}

/// The community-plane executor: what a backend does for the shared plans.
/// Storage only: every refusal is a plan's. (A missing room or member key on
/// memory is its stand-in for the SQL backends' foreign keys.)
#[async_trait::async_trait]
pub(crate) trait CommunityStore:
    FederationDirectory + super::group_plane::GroupPlaneStore + Sized
{
    /// Insert a planned community record with its authority signature,
    /// supersede proof, co-signatures and lineage, then index it. An id taken
    /// by the time of the insert writes nothing and reports the stored hash.
    async fn store_planned_community(
        &self,
        planned: CommunityInsert,
    ) -> Result<StoredCommunity, Error>;

    /// Store a planned revocation: the row, its removal event and the
    /// rotation-on-removal epoch bump in one transaction, idempotent on the
    /// `(community, removed, effective_at)` key (a repeat commits nothing),
    /// then the wire index.
    async fn store_planned_community_revocation(
        &self,
        planned: PlannedCommunityRevocation,
    ) -> Result<(), Error>;

    /// Store a planned widening, idempotent on its three-part key, then the
    /// wire index.
    async fn store_planned_community_widening(
        &self,
        planned: PlannedCommunityWidening,
    ) -> Result<(), Error>;

    /// Test-only (PR #921 review, F3): apply the rival community write armed
    /// for `at`, if any, through this backend's own replicated door.
    #[cfg(test)]
    async fn rival_community_write_at(
        &self,
        at: crate::store::test_hooks::RivalPoint,
    ) -> Result<(), Error>;
}

/// The door: every backend's `put_community` and `apply_replicated_community`
/// end in this call, with the door they were reached through.
pub(crate) async fn put_community_planned<D>(
    dir: &D,
    community: SignedCommunity,
    door: CommunityDoor,
) -> Result<CommunityWrite, Error>
where
    D: CommunityStore,
{
    // Test-only (PR #921 review, F3): a rival write that won the race lands
    // here, after any read the caller made and before this write's own gates
    // and reads.
    #[cfg(test)]
    dir.rival_community_write_at(crate::store::test_hooks::RivalPoint::DoorStart)
        .await?;
    // v57.0.0 (CIRISPersist#934 step 2) — the ONE clock read of this door,
    // and the record's head instant.
    let instants = PlanInstants {
        fold_at: super::canonical_community::head_instant(&community),
        received_at: chrono::Utc::now(),
    };
    let planned = plan_put_community(dir, community, door, instants).await?;
    // v49.0.0 (CIRISPersist#910.5) — the occupied-id route the plan decided:
    // an identical re-put is a no-op, an authorized amendment is applied as a
    // supersede, an empty id (or a chain apply that found it empty) inserts.
    let PlannedCommunity {
        community,
        occupied,
    } = planned;
    let link = super::group_plane::GroupRowLink::record(
        super::group_plane::GroupKind::Community,
        &community.community.community_key_id,
    );
    let head = super::group_plane::GroupSigned::Community(community.clone());
    if let OccupiedRoute::Settled(written) =
        group_amendment::apply_occupied_community(dir, &community, occupied).await?
    {
        // v61 (CIRISPersist#991) — the head's `group:roster:v1` row.
        super::group_plane::sync_group_row_offered(dir, link, Some(&head)).await?;
        return Ok(written);
    }
    let insert = community_insert(community)?;
    let offered = insert.community.community.persist_row_hash.clone();
    let id = insert.community.community.community_key_id.clone();
    // Test-only (PR #921 review, F3): a rival insert lands after the
    // occupied-id decision said "insert", before this insert.
    #[cfg(test)]
    dir.rival_community_write_at(crate::store::test_hooks::RivalPoint::BeforeInsert)
        .await?;
    match dir.store_planned_community(insert).await? {
        StoredCommunity::Inserted => {
            // v61 (CIRISPersist#991) — the record's `group:roster:v1` row.
            super::group_plane::sync_group_row_offered(dir, link, Some(&head)).await?;
            Ok(CommunityWrite::Inserted)
        }
        // v38.2.0 (#758) — the insert found the id taken: identical content is
        // `Unchanged`, a differing record is refused.
        StoredCommunity::Occupied {
            stored_persist_row_hash,
        } => group_amendment::community_insert_lost_to(&stored_persist_row_hash, &offered, &id),
    }
}

/// The replicated door: every backend's `apply_replicated_community` is this
/// call. v50.0.0 (CIRISPersist#931; PR #921 review, Codex F3) — the typed
/// outcome is what the write did, as the write saw it; no read taken before it.
pub(crate) async fn apply_replicated_community_planned<D>(
    dir: &D,
    community: SignedCommunity,
) -> Result<ReplicatedCommunityOutcome, Error>
where
    D: CommunityStore,
{
    // v61 (CIRISPersist#1148) — the put-time audience precondition, as on the
    // attestation plane: a record this node may not receive is refused by
    // name before any door runs.
    if let Some(me) = dir.node_key_id() {
        if !super::replication_audience::may_receive_community_record(dir, &me, &community)
            .await?
            .allowed()
        {
            return Ok(ReplicatedCommunityOutcome::Refused {
                reason: group_amendment::ReplicatedCommunityRefusal::NotInAudience,
            });
        }
    }
    let stored = put_community_planned(dir, community, CommunityDoor::ReplicatedApply).await;
    group_amendment::replicated_community_outcome(stored)
}

/// The row as inserted: its hash stamped. v61 (CIRISPersist#991): no
/// framed wire-index locator; the record rides as its `group:roster:v1` row.
fn community_insert(mut community: SignedCommunity) -> Result<CommunityInsert, Error> {
    community.community.persist_row_hash =
        super::types::compute_persist_row_hash(&community.community)?;
    Ok(CommunityInsert { community })
}

/// **The decision** for a community record, on both doors (#931: the door,
/// never the signer, decides whether the CC 3.2 infrastructure gate runs).
/// Reads the directory through the trait; reads no clock.
pub(crate) async fn plan_put_community<D>(
    dir: &D,
    community: SignedCommunity,
    door: CommunityDoor,
    instants: PlanInstants,
) -> Result<PlannedCommunity, Error>
where
    D: FederationDirectory,
{
    let received_at = instants.received_at;
    // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship BEFORE any other
    // admission step (mirrors put_family).
    super::verify_community_admission(dir, &community).await?;
    // v50.0.0 (CIRISPersist#926) — the trust-root door, ONE predicate on both
    // doors: the reserved `ciris-canonical` id and any
    // `infrastructure_constraint` row are admitted only as a chain from an
    // accord birth. The replicated door may keep another id's non-conformant
    // record as data (it reads NotRooted); the reserved id never. `true` = an
    // authorized infrastructure room.
    let trust_root = super::canonical_community::check_trust_root_at_door(
        dir,
        &community,
        door == CommunityDoor::ReplicatedApply,
    )
    .await?;
    // v61 S2 (CIRISPersist#1123) — a room stored under founder_only admits
    // one new version, its escape, on both doors.
    super::admission::check_founder_only_escape(dir, &community, received_at).await?;
    let row = &community.community;
    // v4.0 — the consensus_protocol canonical form.
    super::check_consensus_protocol_form(&row.consensus_protocol)?;
    // v54.0.0 (CIRISPersist#1034, CC 4.4.3.2.8) — the declared cohort parses,
    // a config rides only on an affiliation, and an affiliation's config
    // validates against its roster.
    super::affiliation_config::check_community_record(row)?;
    // v61.3.0 (CIRISPersist#1252, CC 4.5.13) — a record that sets its cosign
    // window sets it at or above the floor.
    super::cosign::check_community_record_window(row)?;
    // v4.11.0 (#154 Ask 4) — geographic cohort_subkind admission: every member
    // holds an in-force contained location_proof. No-op for non-geographic
    // communities.
    super::location::check_geographic_community_admission(dir, row, received_at).await?;
    // v50.0.0 (CIRISPersist#925/#927, CC 3.2) — infrastructure conformance on
    // the local door: a quorum:M/N protocol and no node-bearing founder. On
    // the replicated door, a conformant stored room never degrades.
    if door == CommunityDoor::Local {
        super::admission::check_infrastructure_record_admission(dir, row, received_at).await?;
    } else {
        super::admission::check_replicated_supersede_does_not_degrade(dir, row, received_at)
            .await?;
    }
    // v9.0.0 (CC 3.2 / CC 3.4.7.1) — steward-binding precondition for
    // non-infrastructure community membership.
    if !trust_root {
        super::admission::check_community_membership_steward_binding(dir, row).await?;
    }
    // v49.0.0 (CIRISPersist#910.5) — what an occupied id gets.
    let occupied = group_amendment::plan_occupied_community(dir, &community).await?;
    Ok(PlannedCommunity {
        community,
        occupied,
    })
}

/// The door: every backend's `put_community_membership_revocation` is this
/// call.
pub(crate) async fn put_community_membership_revocation_planned<D>(
    dir: &D,
    revocation: SignedCommunityMembershipRevocation,
) -> Result<(), Error>
where
    D: CommunityStore,
{
    // v57.0.0 (CIRISPersist#934 step 2) — the ONE clock read of this door, and
    // the row's signed instant.
    let instants = PlanInstants {
        fold_at: revocation.community_membership_revocation.effective_at,
        received_at: chrono::Utc::now(),
    };
    let planned = plan_put_community_membership_revocation(dir, revocation, instants).await?;
    // v61.3.0 (CIRISPersist#1252) — the sole refusal is the shortfall: held
    // for its cosignatures (or refused as before).
    let planned = match super::cosign::hold_if_short(
        dir,
        planned.short,
        super::group_plane::GroupSigned::CommunityRevocation(planned.revocation),
    )
    .await?
    {
        super::group_plane::GroupSigned::CommunityRevocation(revocation) => {
            PlannedCommunityRevocation {
                revocation,
                removal_event: planned.removal_event,
                short: None,
            }
        }
        _ => unreachable!("hold_if_short returns the event it was handed"),
    };
    // v61 (CIRISPersist#991) — the removal's (or resignation's) row.
    let offered = super::group_plane::GroupSigned::CommunityRevocation(planned.revocation.clone());
    dir.store_planned_community_revocation(planned).await?;
    super::group_plane::sync_group_row_offered(dir, offered.link(), Some(&offered)).await?;
    Ok(())
}

/// **The decision** for a community-membership revocation. Reads the
/// directory through the trait; reads no clock.
pub(crate) async fn plan_put_community_membership_revocation<D>(
    dir: &D,
    revocation: SignedCommunityMembershipRevocation,
    instants: PlanInstants,
) -> Result<PlannedCommunityRevocation, Error>
where
    D: FederationDirectory,
{
    let PlanInstants {
        fold_at,
        received_at,
    } = instants;
    // v21.0.0 (CIRISPersist#502 E4) — mechanistic authorship BEFORE any other
    // admission step. THE worst-case E4 hole: an unverified removal rotates
    // the community DEK epoch — an unauthenticated forward-secrecy DoS.
    super::verify_community_membership_revocation_admission(dir, &revocation).await?;
    let row = &revocation.community_membership_revocation;
    // SecReview F4 — community removal is immediate for forward-secrecy; a
    // future-dated effective_at is refused BEFORE any write.
    super::community_dek::reject_future_dated_community_revocation(row.effective_at, received_at)?;
    // v61 S2 (CIRISPersist#1123) — a room stored under founder_only admits
    // no removal but a member's own resignation.
    {
        let self_leave = revocation.authority_key_id == row.removed_identity_key_id
            || revocation
                .cosignatures
                .iter()
                .any(|c| c.authority_key_id == row.removed_identity_key_id);
        if !self_leave {
            super::admission::refuse_membership_event_under_founder_only(
                dir,
                &row.community_key_id,
                "removal",
            )
            .await?;
        }
    }
    // v61 S2 (CC 4.5.13) — under `open:self_admit`, the removal window, at
    // the local door only.
    if !super::group_plane::applying_replicated_group_row() {
        check_open_self_admit_removal_window(dir, &revocation, received_at).await?;
    }
    // v49.0.0 (CIRISPersist#908) — standing, before the epoch rotates: a
    // stranger's valid signature does not remove a member.
    // v61.3.0 (CIRISPersist#1252) — the shortfall split out: every later
    // check still runs, and a short event one of them refuses keeps the
    // shortfall refusal.
    let mut short = match super::check_community_roster_authority_verdict(
        dir,
        &row.community_key_id,
        &revocation.authority_key_id,
        &super::roster_row_signer_set(&revocation.authority_key_id, &revocation.cosignatures),
        CommunityMember {
            key_id: row.removed_identity_key_id.clone(),
            joined_at: row.effective_at,
            role: None,
        },
        true,
        fold_at,
    )
    .await?
    {
        super::RosterAuthority::Admitted => None,
        super::RosterAuthority::ConsensusShort(e) => Some(e),
    };
    // v50.0.0 (review, M1 loophole) — removing a founder of a conformant
    // infrastructure room would leave its declared N stale.
    if let Some(stored) = dir.lookup_community(&row.community_key_id).await? {
        let self_leave = revocation.authority_key_id == row.removed_identity_key_id
            || revocation
                .cosignatures
                .iter()
                .any(|c| c.authority_key_id == row.removed_identity_key_id);
        super::admission::check_infrastructure_founder_count_unchanged(
            dir,
            &stored,
            &row.removed_identity_key_id,
            None,
            true,
            self_leave,
            fold_at,
        )
        .await
        .map_err(|e| super::cosign::keep_shortfall(&mut short, e))?;
    }
    let mut revocation = revocation;
    let row = &mut revocation.community_membership_revocation;
    row.persist_row_hash = super::types::compute_persist_row_hash(&*row)?;
    // CEG §7.8 (CIRISPersist#161 Ask 5) — the community analog of the §7.7
    // removal emission.
    let removal_event = super::hard_case::membership_removed_event(
        super::hard_case::kind::COMMUNITY_MEMBERSHIP_CHANGE,
        &row.community_key_id,
        &row.removed_identity_key_id,
        row.effective_at,
    );
    Ok(PlannedCommunityRevocation {
        revocation,
        removal_event,
        short,
    })
}

/// v61 S2 (CC 4.5.13; the release lead's ruling) — **the removal window
/// under `open:self_admit`.** Each counted voice of a removal signs within
/// [`OPEN_SELF_ADMIT_REMOVAL_WINDOW_SECS`](super::consensus::OPEN_SELF_ADMIT_REMOVAL_WINDOW_SECS)
/// of the removal's asserted instant (`removed_at`). A
/// [`RosterCosignature`](super::types::RosterCosignature) carries no signed
/// instant of its own (every scrub covers the same `signing_envelope`), so
/// no cosignature can show when it was given. The fallback is the ruling's: a
/// bound on receipt, at the local door only. A removal more than the window
/// from `received_at` is refused [`Error::RosterAuthorityUnauthorized`] /
/// [`ROSTER_REMOVAL_OUTSIDE_WINDOW`](super::ROSTER_REMOVAL_OUTSIDE_WINDOW).
/// The replicated door does not ask: a peer's receipt clock is no witness to
/// when the voices signed, and refusing a removal another node admitted in
/// time would fork the roster.
///
/// A resignation (the removed member among the signers) is a member's own
/// act, not a counted removal, and is not bounded. Any other protocol, and a
/// room this node does not hold, pass.
pub(crate) async fn check_open_self_admit_removal_window<D>(
    dir: &D,
    revocation: &SignedCommunityMembershipRevocation,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<(), Error>
where
    D: FederationDirectory + ?Sized,
{
    let row = &revocation.community_membership_revocation;
    let Some(community) = dir.lookup_community(&row.community_key_id).await? else {
        return Ok(());
    };
    if community.consensus_protocol != super::types::consensus_protocol::OPEN_SELF_ADMIT {
        return Ok(());
    }
    let signers =
        super::roster_row_signer_set(&revocation.authority_key_id, &revocation.cosignatures);
    if signers.contains(&row.removed_identity_key_id) {
        return Ok(());
    }
    let window = chrono::Duration::seconds(super::consensus::OPEN_SELF_ADMIT_REMOVAL_WINDOW_SECS);
    // v61.3.0 (CIRISPersist#1252) — a held removal is bounded on THIS node's
    // first receipt of it (the hold's received_at), not on the instant its
    // executor re-offers the assembled event.
    let received_at = super::cosign::executing_received_at().unwrap_or(received_at);
    let skew = received_at - row.removed_at;
    if skew > window || -skew > window {
        tracing::debug!(
            community_key_id = %row.community_key_id,
            removed_at = %row.removed_at,
            received_at = %received_at,
            "open:self_admit removal outside its window"
        );
        return Err(Error::RosterAuthorityUnauthorized {
            group_key_id: row.community_key_id.clone(),
            offered_authority_key_id: revocation.authority_key_id.clone(),
            rule: super::ROSTER_REMOVAL_OUTSIDE_WINDOW,
        });
    }
    Ok(())
}

/// The door: every backend's `put_community_membership_widening` is this
/// call.
pub(crate) async fn put_community_membership_widening_planned<D>(
    dir: &D,
    widening: SignedCommunityMembershipWidening,
) -> Result<(), Error>
where
    D: CommunityStore,
{
    // v57.0.0 (CIRISPersist#934 step 2) — the ONE clock read of this door, and
    // the row's signed instant.
    let instants = PlanInstants {
        fold_at: widening.community_membership_widening.effective_at,
        received_at: chrono::Utc::now(),
    };
    let planned = plan_put_community_membership_widening(dir, widening, instants).await?;
    // v61.3.0 (CIRISPersist#1252) — the sole refusal is the shortfall: held
    // for its cosignatures (or refused as before).
    let planned = match super::cosign::hold_if_short(
        dir,
        planned.short,
        super::group_plane::GroupSigned::CommunityWidening(planned.widening),
    )
    .await?
    {
        super::group_plane::GroupSigned::CommunityWidening(widening) => PlannedCommunityWidening {
            widening,
            short: None,
        },
        _ => unreachable!("hold_if_short returns the event it was handed"),
    };
    // v61 (CIRISPersist#991) — the widening's row.
    let offered = super::group_plane::GroupSigned::CommunityWidening(planned.widening.clone());
    dir.store_planned_community_widening(planned).await?;
    super::group_plane::sync_group_row_offered(dir, offered.link(), Some(&offered)).await?;
    Ok(())
}

/// **The decision** for a community-membership widening (CIRISPersist#860,
/// FSD §3.2: the mirror of the revocation door, with no DEK rotation). Reads
/// the directory through the trait; reads no clock.
pub(crate) async fn plan_put_community_membership_widening<D>(
    dir: &D,
    widening: SignedCommunityMembershipWidening,
    instants: PlanInstants,
) -> Result<PlannedCommunityWidening, Error>
where
    D: FederationDirectory,
{
    let PlanInstants {
        fold_at,
        received_at,
    } = instants;
    super::verify_community_membership_widening_admission(dir, &widening).await?;
    let row = &widening.community_membership_widening;
    super::community_dek::reject_future_dated_community_widening(row.effective_at, received_at)?;
    // v61 S2 (CIRISPersist#1123) — a room stored under founder_only admits
    // no widening.
    super::admission::refuse_membership_event_under_founder_only(
        dir,
        &row.community_key_id,
        "widening",
    )
    .await?;
    // v49.0.0 (CIRISPersist#908) — whose signature, not just whether: the
    // signer must have standing in the room at the row's instant.
    // v61.3.0 (CIRISPersist#1252) — the shortfall split out, as on removal.
    let mut short = match super::check_community_roster_authority_verdict(
        dir,
        &row.community_key_id,
        &widening.authority_key_id,
        &super::roster_row_signer_set(&widening.authority_key_id, &widening.cosignatures),
        row.member(),
        false,
        fold_at,
    )
    .await?
    {
        super::RosterAuthority::Admitted => None,
        super::RosterAuthority::ConsensusShort(e) => Some(e),
    };
    let community = dir
        .lookup_community(&row.community_key_id)
        .await?
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "{} does not exist in federation_communities",
                row.community_key_id
            ))
        })?;
    let stored_for_count = community.clone();
    let probe = super::types::Community {
        members: vec![row.member()],
        ..community
    };
    // v50.0.0 (CIRISPersist#925) — a widening that seats a node-bearing key as
    // founder of an infrastructure community is refused.
    super::admission::check_infrastructure_founders_not_node(dir, &probe, fold_at)
        .await
        .map_err(|e| super::cosign::keep_shortfall(&mut short, e))?;
    // v50.0.0 (review, M1 loophole) — adding, promoting or demoting a founder
    // of a conformant infrastructure room would leave N stale.
    super::admission::check_infrastructure_founder_count_unchanged(
        dir,
        &stored_for_count,
        &row.member_key_id,
        row.role.as_deref(),
        false,
        false,
        fold_at,
    )
    .await
    .map_err(|e| super::cosign::keep_shortfall(&mut short, e))?;
    super::admission::check_community_membership_steward_binding(dir, &probe)
        .await
        .map_err(|e| super::cosign::keep_shortfall(&mut short, e))?;
    let mut widening = widening;
    let row = &mut widening.community_membership_widening;
    row.persist_row_hash = super::types::compute_persist_row_hash(&*row)?;
    Ok(PlannedCommunityWidening { widening, short })
}
