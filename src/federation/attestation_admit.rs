//! v56.0.0 (CIRISPersist#934 step 1) — **the attestation plane's write door,
//! decided once.**
//!
//! # What was here before
//!
//! `put_attestation_with_origin` — the door under `put_attestation`,
//! `put_attestation_authored` and, for a fresh id,
//! [`apply_planned`](super::attestation_apply::apply_planned) — was written
//! three times: ~1,000 lines in each of `store/{memory,sqlite,postgres}.rs`,
//! 59 gates long, byte-identical in its gate SEQUENCE by the #670 scan
//! (`store::parity`) and different only in the two reads and the one write
//! the substrate does. The scan could DETECT a gate one backend lacked; it
//! could not make the lack impossible, and v21.11–21.17.1 shipped seven
//! "passed on Memory, broke on sqlite/postgres" defects of exactly that shape.
//!
//! # The shape
//!
//! - [`plan_put_attestation`] is the decision: every admission gate, in the
//!   AV-76 tier order, over the row and the directory. It returns an
//!   [`AttestationPlan`] — settled before any write, or a
//!   [`PlannedAttestation`] carrying the row exactly as it will be stored
//!   (canonical envelope, stamped `withdraws_admission_rule`, computed
//!   `persist_row_hash`).
//! - [`AttestationStore`] is the executor each backend implements: two reads
//!   the plan asks ([`AttestationStore::attesting_identity_type`],
//!   [`AttestationStore::composer_replay_held`]) and two writes
//!   ([`AttestationStore::store_planned_attestation`],
//!   [`AttestationStore::repair_withdraws_depth`]). SQL dialect, row mapping,
//!   transactions and locks — no admission decision.
//! - [`put_attestation_planned`] is the body every backend's
//!   `put_attestation_with_origin` is now one call to: plan, execute, and the
//!   two after-steps that were also written three times (the #771 re-put
//!   verdict on an occupied id, the #963 re-wrap after a consent-list change).
//!
//! # The one re-ask an executor makes
//!
//! A cycle-gated `delegates_to` (CIRISPersist#1031) is checked by the plan
//! with the graph unlocked, then checked AGAIN by the executor under its
//! delegation write lock in the same step as the INSERT (Codex on PR #1050):
//! a writer of the reverse edge may have committed between the two. The
//! executor does not decide that either — it calls
//! [`PlannedAttestation::recheck_cycle_under_lock`] with the graph view its
//! lock covers (the backend itself on memory and sqlite, the open transaction
//! on postgres).

use std::sync::Arc;

use super::replication::admission::{PeerWriteQuota, WriteOrigin};
use super::types::Attestation;
use super::{AdmissionGate, AttestationOutcome, Error, FederationDirectory, SchemaResolver};

/// The per-backend-instance state the plan reads: the AV-76 quota, the
/// installed trust gate, this node's identity and the installed schema
/// resolver. Snapshotted once per call by [`AttestationStore::admission_cx`].
pub(crate) struct AdmissionCx<'a> {
    /// The per-peer write quota (AV-76), per backend instance.
    pub(crate) quota: &'a PeerWriteQuota,
    /// The v3.4.0 trust-threshold gate, if a host installed one.
    pub(crate) admission_gate: Option<AdmissionGate>,
    /// This node's own key id, if the host declared one.
    pub(crate) self_key_id: Option<String>,
    /// The v2.5.0 envelope-schema resolver (a no-op by default).
    pub(crate) schema_resolver: Arc<dyn SchemaResolver>,
}

/// v56.0.0 (CIRISPersist#934 step 1; CIRISConstitution review, condition 1)
/// — **the two instants a plan judges at, named.** Nothing inside a plan
/// reads the clock; every time-dependent gate takes one of these.
///
/// - `fold_at` — the row's signed instant. A judgement of OTHER rows (which
///   are live, chain validity, membership, supersession) belongs here, so
///   `V(rows, t)` replays a plan with `fold_at = t`. The live door passes the
///   row's own `asserted_at`.
/// - `received_at` — the receiving node's clock at the door. The receipt
///   bounds read it: the future-skew bound (`check_instant_binding`) and the
///   attach-freshness window W (`check_attach_freshness`, CC 2.6.7).
///
/// #934 changes no behaviour, so each gate reads the instant it read before
/// the plan existed. Four folds read the receipt clock today and still read
/// `received_at` (`check_capacity_consent_admission`,
/// `check_delegation_cycle_admission`, `check_peer_deadmission`,
/// `check_trust_charter_admission`): candidates for #1049. Which gate reads
/// which is pinned by `store::parity`'s `PLAN_INSTANTS`.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PlanInstants {
    /// The row's signed instant: where folds over other rows are judged.
    pub(crate) fold_at: chrono::DateTime<chrono::Utc>,
    /// The receiving node's clock at the door: the receipt bounds only.
    pub(crate) received_at: chrono::DateTime<chrono::Utc>,
}

/// What [`plan_put_attestation`] decided.
pub(crate) enum AttestationPlan {
    /// A byte-identical federation-tier re-offer this node already holds
    /// (CIRISPersist#672): settled ahead of the quota and every verify.
    AlreadyHeld,
    /// A CEG §6.1 structural-composer replay: the `(references_attestation_id,
    /// attestation_type, attesting_key_id)` triple is already held. Nothing is
    /// stored; a held `withdraws` whose admission depth is missing gets it
    /// recorded (`(attestation_id, depth)`, v50.0.0 review H2).
    ComposerReplay {
        /// The depth repair to run, for a `withdraws` replay.
        repair_withdraws_depth: Option<(String, usize)>,
    },
    /// Admitted: store it.
    Insert(Box<PlannedAttestation>),
}

/// An admitted row, exactly as the executor stores it.
pub(crate) struct PlannedAttestation {
    /// The row: canonical envelope (#647), stamped
    /// `withdraws_admission_rule`, computed `persist_row_hash`.
    pub(crate) row: Attestation,
    /// The delegation depth a `withdraws` was admitted under (V157), written
    /// in the same transaction as the row; `None` for every other type.
    pub(crate) withdraws_depth: Option<usize>,
    /// The inbound `trace:*` projection (#501), decomposed from the envelope.
    pub(crate) projected_trace: Option<crate::store::decompose::Decomposed>,
    /// v57.0.0 (CIRISPersist#988 item 3) — the `detection_events` row a
    /// `detection:*` row carrying a detection body projects to, written in the
    /// row's transaction.
    pub(crate) projected_detection: Option<crate::derived::detection_row::DetectionProjection>,
    /// v60.0.0 (CIRISConstitution#170 closed) — the `hard_case_events` row a
    /// `hard_case:*` row carrying a readable event projects to, written in the
    /// row's transaction: a peer's replicated row is in this node's table as
    /// its rebuild has it, the detection precedent.
    pub(crate) projected_hard_case: Option<super::hard_case::HardCaseEvent>,
    /// v60.0.0 (CIRISPersist#988 item 1) — the `credits_ledger` /
    /// `expertise_ledger` row a ledger row signed by this node projects to,
    /// written in the row's transaction when it supersedes the held one
    /// ([`super::ledger_projection::supersedes`]).
    pub(crate) projected_ledger: Option<super::ledger_projection::LedgerProjection>,
    /// The signed-wire-index locator (#507b), federation tier only; the hash
    /// comes from the stored row (#646).
    pub(crate) wire_index_key: Option<String>,
    cycle_gated: bool,
    /// The receipt instant the plan judged the cycle at; the under-lock re-ask
    /// judges at it too.
    received_at: chrono::DateTime<chrono::Utc>,
}

impl PlannedAttestation {
    /// Does the store step hold the delegation write lock (CIRISPersist#1031)?
    pub(crate) fn cycle_gated(&self) -> bool {
        self.cycle_gated
    }

    /// The cycle gate, asked again under the executor's delegation write lock,
    /// in the same step as the INSERT (see the module doc). A no-op for a row
    /// that is not [`Self::cycle_gated`].
    pub(crate) async fn recheck_cycle_under_lock<G>(&self, graph: &G) -> Result<(), Error>
    where
        G: super::attestation_query::AttestationQueryExec + ?Sized,
    {
        if !self.cycle_gated {
            return Ok(());
        }
        super::admission::check_delegation_cycle_admission(graph, &self.row, self.received_at).await
    }
}

/// What the executor's store step found.
pub(crate) enum StoredAttestation {
    /// The row landed, with its projections, depth, trace rows and index.
    Inserted,
    /// The id was already occupied; nothing was written. Carries the STORED
    /// row's `persist_row_hash` (`None`: it vanished before the re-read).
    Occupied {
        /// The stored row's hash, for the #771 verdict.
        stored_persist_row_hash: Option<String>,
    },
}

/// The attestation-plane executor: what a backend does for the shared plan.
/// Storage only — every refusal is [`plan_put_attestation`]'s.
#[async_trait::async_trait]
pub(crate) trait AttestationStore:
    FederationDirectory + super::renditions::HeldBlobScope + Sized
{
    /// Snapshot the per-instance admission state.
    fn admission_cx(&self) -> AdmissionCx<'_>;

    /// The attesting key's `identity_type`, `None` when this node holds no
    /// such key.
    async fn attesting_identity_type(&self, key_id: &str) -> Result<Option<String>, Error>;

    /// Is a structural composer with this `(attestation_type,
    /// attesting_key_id, references_attestation_id)` triple held (any tier)?
    async fn composer_replay_held(
        &self,
        attestation_type: &str,
        attesting_key_id: &str,
        references_attestation_id: &str,
    ) -> Result<bool, Error>;

    /// Record `depth` for `attestation_id` in the V157 depth table when the
    /// id is held and has none (insert-if-absent).
    async fn repair_withdraws_depth(&self, attestation_id: &str, depth: usize)
        -> Result<(), Error>;

    /// Store an admitted row: the row, its projections and its depth in one
    /// transaction (under the delegation write lock when
    /// [`PlannedAttestation::cycle_gated`]), then its trace rows and its wire
    /// index. An occupied id writes nothing and reports the stored hash.
    async fn store_planned_attestation(
        &self,
        planned: PlannedAttestation,
    ) -> Result<StoredAttestation, Error>;

    /// Write a planned hybrid completion: the three columns, guarded on the
    /// row still being incomplete (a concurrent completion is a
    /// [`Error::Conflict`], the guard's storage outcome), the serve position
    /// moved with them, then the wire index re-derived from the row as stored.
    async fn store_pqc_completion(&self, completion: PqcCompletion) -> Result<(), Error>;

    /// Store a planned local-tier row: for an upsert, first delete every local
    /// row of `(attester, dimension)` (and their renditions); then insert the
    /// row if its id is free (a concurrent writer that took it makes this a
    /// no-op), its subject and rendition projections, and its depth.
    async fn store_planned_local_attestation(
        &self,
        planned: PlannedLocalAttestation,
    ) -> Result<(), Error>;

    /// Store a planned re-seal: INSIDE the write step (memory's lock,
    /// sqlite's transaction, postgres's `SELECT … FOR UPDATE`), read the row
    /// as it is now, hand it to [`PlannedReseal::sealed_over`] (the shape gate
    /// re-asked, the sealed row built), write that row, then re-index a
    /// federation-tier row. `false` when the row is gone.
    async fn store_planned_reseal(&self, planned: PlannedReseal) -> Result<bool, Error>;

    /// Delete one attestation row (its subject projection follows: `ON DELETE
    /// CASCADE` on the SQL backends, by hand on memory). With `only_if_hash`,
    /// a compare-and-delete in one step: a row whose `persist_row_hash` moved
    /// is left alone. `false` when nothing was deleted.
    async fn delete_attestation(
        &self,
        attestation_id: &str,
        only_if_hash: Option<&str>,
    ) -> Result<bool, Error>;

    /// v57.0.0 (CIRISPersist#988 item 2) — store a planned `hard_case` row:
    /// the row (insert-if-absent on its id, so a re-recorded event is a no-op)
    /// and, when the row landed, its `hard_case_events` projection, in one
    /// transaction.
    async fn store_planned_hard_case(&self, planned: PlannedHardCase) -> Result<(), Error>;

    /// v57.0.0 (CIRISPersist#988 item 2) — move every pre-v57
    /// `hard_case_events` row that has no backing row onto the plane: plan
    /// each as `attester`'s row ([`plan_hard_case_row`] at `received_at`),
    /// store it, and replace the legacy row with the row's projection, in one
    /// transaction. A no-op when there are none (memory never holds any).
    async fn rehome_legacy_hard_case_events(
        &self,
        attester: &HardCaseAttester,
        received_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error>;

    /// v57.0.0 (CIRISPersist#988; CLM-silo-projection-rebuildable) — the
    /// projection's live rows and its from-rows rebuild through the same
    /// writer, rendered for a byte comparison
    /// ([`super::silo_projection::check_projection_rebuild`]).
    #[cfg_attr(not(any(feature = "sqlite", feature = "postgres")), allow(dead_code))]
    async fn projection_rebuild(
        &self,
        projection: super::silo_projection::SiloProjection,
    ) -> Result<super::silo_projection::ProjectionRebuild, Error>;

    /// v58.0.0 (CIRISPersist#1094 item 2) — the `agent_id_hash` of the trace
    /// `trace_id` as this node holds it (`trace_events`), `None` when no row of
    /// it is held.
    async fn trace_agent_id_hash(&self, trace_id: &str) -> Result<Option<String>, Error>;

    /// v58.0.0 (CIRISPersist#1094 item 2) — the ids of the `detection:*` rows
    /// whose detection names (by its body's `trace_id`) a trace of
    /// `agent_id_hash` this node holds, restricted to traces signed by
    /// `signing_key_id` when given (the key-scoped DSAR door). What a DSAR
    /// erasure of that agent reaches on the attestation plane. Sorted.
    async fn detection_row_ids_for_agent(
        &self,
        agent_id_hash: &str,
        signing_key_id: Option<&str>,
    ) -> Result<Vec<String>, Error>;

    /// v57.0.0 (CIRISPersist#988 item 3) — store a planned detection row and,
    /// when it landed, its `detection_events` projection, in one transaction.
    /// `false` (nothing written) when the row's id is already held.
    async fn store_planned_detection(&self, planned: PlannedDetection) -> Result<bool, Error>;

    /// v57.0.0 (CIRISPersist#988 item 3) — move every pre-v57
    /// `detection_events` row with no backing row onto the plane: plan each as
    /// its detector's row ([`plan_detection_row`] at `received_at`), store it
    /// and replace the legacy row with the row's projection. A legacy row
    /// whose detector key this node does not hold, or whose key the
    /// `detection:` reserved rule refuses, stays as it is (and the rebuild
    /// gate reports it). A no-op when there are none.
    async fn rehome_legacy_detection_events(
        &self,
        received_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Error>;
}

/// v56.0.0 (CIRISPersist#934 step 1) — a planned hybrid completion
/// (`attach_attestation_pqc_signature`): the three columns the write sets.
pub(crate) struct PqcCompletion {
    /// The row being completed.
    pub(crate) attestation_id: String,
    /// The ML-DSA-65 half the caller supplied.
    pub(crate) scrub_signature_pqc: String,
    /// The completion instant: the plan's `received_at`.
    pub(crate) pqc_completed_at: chrono::DateTime<chrono::Utc>,
    /// The row hash over the completed row.
    pub(crate) persist_row_hash: String,
}

/// v56.0.0 (CIRISPersist#934 step 1) — **the hybrid-completion decision**,
/// once for all three backends: the row must be held and not yet
/// PQC-complete; the completed row's hash covers the new signature half and
/// the completion instant `received_at` (the receiving node's clock at the
/// door). Pure: the held row is the directory's read.
pub(crate) fn plan_attach_attestation_pqc_signature(
    held: Option<Attestation>,
    attestation_id: &str,
    scrub_signature_pqc: &str,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<PqcCompletion, Error> {
    let mut row = held.ok_or_else(|| {
        Error::InvalidArgument(format!(
            "federation_attestations row {attestation_id} does not exist"
        ))
    })?;
    if row.is_pqc_complete() {
        return Err(Error::Conflict(format!(
            "federation_attestations row {attestation_id} is already PQC-complete"
        )));
    }
    row.scrub_signature_pqc = Some(scrub_signature_pqc.to_owned());
    row.pqc_completed_at = Some(received_at);
    row.persist_row_hash = String::new();
    let persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
    Ok(PqcCompletion {
        attestation_id: attestation_id.to_owned(),
        scrub_signature_pqc: scrub_signature_pqc.to_owned(),
        pqc_completed_at: received_at,
        persist_row_hash,
    })
}

/// v56.0.0 (CIRISPersist#934 step 1) — the door: every backend's
/// `attach_attestation_pqc_signature` is this call. The one clock read of the
/// door is here; the plan reads the held row through the directory, and the
/// executor writes what the plan decided.
pub(crate) async fn attach_attestation_pqc_planned<D>(
    dir: &D,
    attestation_id: &str,
    scrub_signature_pqc: &str,
) -> Result<(), Error>
where
    D: AttestationStore,
{
    let received_at = chrono::Utc::now();
    // The row as stored, any tier: the same point read the crossing door
    // plans over (`enter_mesh`).
    let held = dir.get_attestation(attestation_id).await?;
    let completion = plan_attach_attestation_pqc_signature(
        held,
        attestation_id,
        scrub_signature_pqc,
        received_at,
    )?;
    dir.store_pqc_completion(completion).await?;
    Ok(())
}

/// The door: every backend's `put_attestation_with_origin` is this call.
pub(crate) async fn put_attestation_planned<D>(
    dir: &D,
    attestation: super::SignedAttestation,
    origin: WriteOrigin,
) -> Result<AttestationOutcome, Error>
where
    D: AttestationStore,
{
    // v58.0.0 (CIRISPersist#991, CC 3.1.3) — a key-plane row goes to its
    // family's door: proof of possession, not resolve-the-attester; the
    // object's own signature, not one over the row's envelope.
    if super::key_plane::is_key_plane_row(&attestation.attestation) {
        use super::key_plane::KeyPlaneApplied;
        return match super::key_plane::apply_key_plane_row(dir, &attestation.attestation).await? {
            KeyPlaneApplied::Changed => Ok(AttestationOutcome::Inserted),
            KeyPlaneApplied::Unchanged => Ok(AttestationOutcome::AlreadyHeld),
            KeyPlaneApplied::Refused(reason) => Err(Error::Conflict(format!(
                "key-plane row {} not applied: {reason}",
                attestation.attestation.attestation_id
            ))),
        };
    }
    // v53.0.0 (#963) — a row that changes an owner's cohort allow list for
    // one of its nodes (a `consent:replication` grant FOR the node, or the
    // owner's retraction of one): read before the row moves, acted on only
    // when the store inserted it.
    let consent_change = super::consent_list_change_of(dir, &attestation.attestation).await;
    let occurrence_withdrawal =
        super::key_plane::occurrence_withdrawal_of(dir, &attestation.attestation).await?;
    // v59.0.0 (CIRISPersist#1104) — an admitted carrier feeds the same
    // projection as a `withdraws` of the occurrence row.
    let carried_revocation =
        super::occurrence_revocation_carrier::carrier_of_row(&attestation.attestation)
            .and_then(|f| f.revocation().ok());
    // v59.0.0 (CIRISPersist#1099, CC 3.3.6.3) — the row as offered, for the
    // self-roster door: an eviction of a live roster key is a proposal. The
    // genesis key's eviction (a `withdraws` of the self pair's occurrence row
    // by another roster key) is one of these.
    let offered_withdrawal = occurrence_withdrawal
        .is_some()
        .then(|| attestation.attestation.clone());
    // v59.0.0 (CIRISPersist#1099) — a proposal or an answer to one, executed
    // after it is stored.
    // v59.0.0 (CIRISPersist#1106) — a quorum re-bind, applied after it is
    // stored.
    let rebind_row = super::transport_rebind::is_rebind_row(&attestation.attestation)
        .then(|| attestation.attestation.clone());
    let roster_row = (super::self_roster::is_proposal_row(&attestation.attestation)
        || super::self_roster::answer_identity(&attestation.attestation).is_some())
    .then(|| attestation.attestation.clone());
    // v56.0.0 (CIRISPersist#934, CC review condition 1) — the ONE clock read
    // of this door, and the row's signed instant: the plan's two inputs. The
    // plan reads no clock of its own and the executor reads none either. A
    // replay of `V(rows, t)` calls the plan with `fold_at = t`.
    let instants = PlanInstants {
        fold_at: attestation.attestation.asserted_at,
        received_at: chrono::Utc::now(),
    };
    let outcome = async {
        let outcome = match plan_put_attestation(dir, attestation, &origin, instants).await? {
            AttestationPlan::AlreadyHeld => AttestationOutcome::AlreadyHeld,
            AttestationPlan::ComposerReplay {
                repair_withdraws_depth,
            } => {
                if let Some((id, depth)) = repair_withdraws_depth {
                    dir.repair_withdraws_depth(&id, depth).await?;
                }
                AttestationOutcome::AlreadyHeld
            }
            AttestationPlan::Insert(planned) => {
                if let (Some(offered), Some(revocation)) =
                    (&offered_withdrawal, &occurrence_withdrawal)
                {
                    super::self_roster::gate_withdrawal(dir, offered, revocation).await?;
                }
                execute_planned(dir, *planned).await?
            }
        };
        Ok(outcome)
    }
    .await;
    if let (Ok(AttestationOutcome::Inserted), Some((owner, node))) = (&outcome, consent_change) {
        super::rewrap_after_admission(dir, &owner, &node).await;
    }
    if let (Ok(AttestationOutcome::Inserted | AttestationOutcome::AlreadyHeld), Some(row)) =
        (&outcome, &roster_row)
    {
        super::self_roster::after_admission(dir, row).await;
    }
    if let (Ok(AttestationOutcome::Inserted | AttestationOutcome::AlreadyHeld), Some(row)) =
        (&outcome, &rebind_row)
    {
        super::transport_rebind::after_admission(dir, row).await?;
    }
    // v58.0.0 (CIRISPersist#991, CC 3.3.6) — an admitted `withdraws` against an
    // `identity:occurrence:v1` row feeds the occurrence-revocation projection
    // (`federation_identity_occurrence_revocations`, this node's local read
    // model: eviction, transport-route retirement).
    //
    // v58.0.0 (compat reads, operator ruling 2026-10-18) — the framed door
    // (`put_identity_occurrence_revocation`) feeds the same projection. A pair
    // already revoked by either route keeps the revocation it holds: the first
    // to land fixes the instants, and neither route rewrites (or un-revokes)
    // the other.
    if let (Ok(AttestationOutcome::Inserted), Some(revocation)) =
        (&outcome, occurrence_withdrawal.or(carried_revocation))
    {
        let held = dir
            .list_identity_occurrence_revocations_for(&revocation.identity_key_id)
            .await?
            .iter()
            .any(|r| r.occurrence_key_id == revocation.occurrence_key_id);
        if !held {
            dir.put_identity_occurrence_revocation_local(revocation)
                .await?;
        }
    }
    outcome
}

/// Store a planned row; an occupied id is decided by the #771 verdict.
async fn execute_planned<D>(
    dir: &D,
    planned: PlannedAttestation,
) -> Result<AttestationOutcome, Error>
where
    D: AttestationStore,
{
    let id = planned.row.attestation_id.clone();
    let offered = planned.row.persist_row_hash.clone();
    let depth = planned.withdraws_depth;
    match dir.store_planned_attestation(planned).await? {
        StoredAttestation::Inserted => Ok(AttestationOutcome::Inserted),
        StoredAttestation::Occupied {
            stored_persist_row_hash,
        } => {
            // v38.5.0 (#771) — RE-READ decides: identical bytes are an
            // idempotent no-op the sender must be able to recognise; different
            // bytes under an occupied id are a real disagreement.
            let Some(stored) = stored_persist_row_hash else {
                // The row vanished between the insert and the re-read (a
                // concurrent purge). Report it as a backend condition rather
                // than inventing an outcome for a row nobody holds.
                return Err(Error::Backend(format!(
                    "attestation {id} was absorbed as a duplicate but is not present on re-read"
                )));
            };
            super::attestation_reput_verdict(&stored, &offered, &id)?;
            // v50.0.0 (review H2, final check) — an identical re-put of a
            // `withdraws` whose admission depth is missing records it now
            // (idempotent repair).
            if let Some(depth) = depth {
                dir.repair_withdraws_depth(&id, depth).await?;
            }
            Ok(AttestationOutcome::AlreadyHeld)
        }
    }
}

/// **The decision.** Every admission gate of the attestation plane's stored
/// write, in the AV-76 tier order, once for all three backends.
///
/// **The two instants are inputs** (CIRISConstitution review on #934,
/// condition 1; see [`PlanInstants`]). Nothing below reads the clock.
pub(crate) async fn plan_put_attestation<D>(
    dir: &D,
    attestation: super::SignedAttestation,
    origin: &WriteOrigin,
    instants: PlanInstants,
) -> Result<AttestationPlan, Error>
where
    D: AttestationStore,
{
    let PlanInstants {
        fold_at,
        received_at,
    } = instants;
    let cx = dir.admission_cx();
    let mut row = attestation.attestation;

    // ── AV-76 TIER 0 — the free prologue ────────────────────────
    // Neither check below reads the row's content or touches the
    // substrate. Before v22.0.0 (CIRISPersist#543 finding 4) the memory
    // backend ran NEITHER — it had no `admission_gate` field at all, so the
    // v3.4.0 trust gate had never run there, and the AV-76 quota would
    // have shipped existing on two backends out of three. That is the
    // defect class this one copy ends (#934).
    // v31.1.0 (CIRISPersist#665) — THE BAKED GENESIS IDS ARE RESERVED, and
    // this gate now runs AHEAD of the quota rather than in tier 1.
    //
    // It is pure (a compare against a 3-element set, then a membership test
    // against the baked roster — no directory read), so it was always free
    // to lead. It has to, now that the quota classifies these ids into the
    // RESERVED budget: were the order reversed, a stranger could spend the
    // budget that keeps constitutional traffic writable simply by claiming
    // a genesis id on a row this gate is about to refuse. Refusing first
    // means only a seated accord holder's row ever reaches that budget.
    //
    // Backend-symmetric across memory / sqlite / postgres.
    // CC 2.3.2.1 (PR #852 review) — the subject gate runs on EVERY ingest,
    // not only the local producer: a remote signer can hybrid-sign a row
    // carrying a malformed subject, and replication would store the same
    // unmatchable revocation authority the emit path refuses.
    // v60.0.0 (CIRISPersist#854) — one gate, the emit gate's rule.
    crate::federation::validate_subject_key_ids(&row.subject_key_ids)?;
    crate::federation::genesis::check_genesis_attestation_reserved(&row)?;
    // v57.0.0 (CIRISPersist#988 item 3) — a `detection:*` row that carries a
    // detection body carries one the projection can read. Pure.
    crate::derived::detection_row::check_detection_body(&row)?;
    // v52.0.0 (CIRISPersist#672) — a re-offer of a held federation-tier row
    // settles here: AHEAD of the per-peer quota (a duplicate did no work
    // and must not spend the sender's budget) and of every verify. Only
    // an index hit that resolves to a byte-identical held row settles; an
    // oversized or otherwise inadmissible row is never held, so it misses
    // and meets the pure gates below exactly as before.
    if row.tier == crate::federation::types::attestation_tier::FEDERATION
        && crate::federation::replication_policy::settle_if_held(
            dir,
            crate::federation::replication_policy::EnvelopeKind::Attestation,
            &row,
        )
        .await?
    {
        return Ok(AttestationPlan::AlreadyHeld);
    }
    // v54.1.0 (CIRISPersist#1046) — a row a steward purge tombstoned is
    // refused (the tombstone outlives the row: it is what keeps a replica
    // from bringing it back); (CIRISPersist#1040) a federation-tier
    // mock-LLM trace is refused. Backend-symmetric across memory / sqlite /
    // postgres, after the settle (a byte-identical held row moves nothing).
    crate::federation::steward_purge::refuse_if_tombstoned_attestation(dir, &row).await?;
    crate::federation::steward_purge::refuse_mock_trace_attestation(&row)?;

    if !row.attesting_key_id.is_empty() {
        // Per-peer write quota. It LEADS the state-consulting checks because
        // it is the only one that consults no shared state, so it also
        // bounds the recursive directory walk the trust scorer runs at
        // any threshold > 0. It answers "you are writing too fast",
        // never "that key exists" — strictly less leaky than the gate
        // it precedes. Per-backend-instance state.
        // v24.3.0 (CIRISPersist#575) — takes the ROW now, not the key:
        // the budget a write is charged against is a pure function of
        // the row (see `PeerWriteQuota::classify`), and that predicate
        // lives in the quota so the three backends cannot hold three
        // opinions of it.
        match origin {
            // v41.0.0 (#804) — this node authored the row; a node is not a
            // peer of itself. The node ceiling only: no peer bucket (which
            // would corrupt `tracked_peers`) and no stranger's tail.
            crate::federation::replication::admission::WriteOrigin::Authored => {
                cx.quota.check_write_authored(&row)?;
            }
            // v41.0.0 (#804) — a bulk sync from an AUTHENTICATED peer. The
            // caller vouches for WHICH identity it authenticated; whether
            // that identity is a cohort-mate is persist's own question,
            // answered from its own rosters and memoized. No shared cohort
            // ⇒ metered exactly as if it had arrived through the wire door.
            crate::federation::replication::admission::WriteOrigin::Sync { peer_key_id } => {
                let shares = match cx.quota.cohort_affinity(peer_key_id) {
                    Some(known) => known,
                    None => {
                        let us = cx.self_key_id.clone().unwrap_or_default();
                        let resolved =
                            crate::federation::replication::admission::shares_cohort_with(
                                dir,
                                &us,
                                peer_key_id,
                            )
                            .await?;
                        cx.quota.remember_cohort_affinity(peer_key_id, resolved);
                        resolved
                    }
                };
                if shares {
                    cx.quota.check_write_synced(&row, peer_key_id)?;
                } else {
                    cx.quota.check_write(&row)?;
                }
            }
            crate::federation::replication::admission::WriteOrigin::Wire => {
                cx.quota.check_write(&row)?;
            }
        }

        // v3.4.0 (CIRISPersist#123) — trust-threshold gate. The
        // cheapest reject that consults state AND the one that leaks
        // the least; an unauthorized writer shouldn't learn about FK /
        // envelope-schema state past it. Free at the default threshold
        // 0 (short-circuits without dispatching to the resolver).
        if let Some(gate) = &cx.admission_gate {
            gate.check_federation(&row.attesting_key_id).await?;
        }
    }

    // ── AV-76 TIER 1 — PURE ENVELOPE GATES ──────────────────────
    // v22.0.0 (CIRISPersist#543 finding 4) — every check in this tier is
    // a pure function of `row`: no state lock, no directory read, no
    // crypto. On this backend they used to be scattered across the stack
    // BEHIND the lock-free authority walks (withdraws / delegated-duty /
    // node-agency / single-owner), so a row that could never be admitted
    // still paid for every one of them — the bootstrap amplification this
    // cut closes.
    //
    // `check_envelope_size_admission` leads deliberately: it BOUNDS the
    // JCS canonicalization that BOTH the hybrid verify (tier 3) and
    // `compute_persist_row_hash` (tier 5) pay.
    //
    // This tier is IDENTICAL to the sqlite + postgres backends', gate for
    // gate and order for order.
    crate::federation::admission::check_envelope_size_admission(&row.attestation_envelope)?;
    // v31.0.0 (CIRISPersist#647) — CANONICAL AT REST. The envelope is
    // replaced by its JCS form HERE, immediately behind the size gate
    // that BOUNDS the canonicalization it pays for, so every gate below
    // and every bind site downstream sees exactly the bytes the
    // producer's signature and `original_content_hash` were taken over.
    // An operator can then `sha256sum` the stored column and compare it
    // to `original_content_hash` with no JCS implementation in hand.
    //
    // Signature-transparent: canonicalization is IDEMPOTENT (proven in
    // `federation::canonical_at_rest`), so the hash cross-check and the
    // hybrid verify further down see byte-identical input to what they
    // would have seen without this line.
    //
    // This tier is IDENTICAL across memory / sqlite / postgres.
    crate::federation::canonical_at_rest::canonicalize_in_place(&mut row.attestation_envelope)?;
    // v31.0.0 (CIRISPersist#660) — the baked genesis ids are RESERVED, and
    // the gate that says so has run at the very top of this function since
    // v31.1.0 (#665), ahead of the write quota — see the comment there for
    // why the order is load-bearing. It used to sit here, behind the
    // canonicalization; it does not read the envelope, so the move costs it
    // nothing.
    //
    // v31.0.0 (CIRISPersist#660) — `original_content_hash` must be hex. The
    // SQL backends refused a non-hex value only as a side effect of binding
    // a BLOB/BYTEA; memory binds nothing and accepted it. Stated on all
    // three so the answer is the same answer, not the same accident.
    crate::federation::admission::check_content_hash_hex(
        "original_content_hash",
        &row.original_content_hash,
    )?;
    // v22.0.0 (CIRISEdge#428) — closed delivery_mode vocabulary; an
    // unknown value is refused HERE instead of being silently demoted
    // to may-drop BestEffort at delivery. Pure predicate, tier 1.
    crate::federation::admission::check_delivery_mode_vocabulary(&row.attestation_envelope)?;
    // v44.8.0 (CIRISPersist#866 C1) — a `consent:state:*` row's scope tokens
    // must parse (`FSD/CONTEXTUAL_INTEGRITY_ENVELOPE.md` §4.4): never admit
    // a token the fold cannot match. Pure; same gate at every door.
    crate::federation::consent_scope::check_consent_scope_tokens(&row.attestation_envelope)?;
    // v45.0.0 (CIRISPersist#871, `FSD/MEDIA_SOURCE.md` §3–§4) — the media
    // Source struct is refused by member name (a holding claim without a
    // positive `size` is the custody parse\'s to refuse, v55) Pure; the same gate at every door.
    crate::federation::media_source::check_media_source(&row.attestation_envelope)?;

    // v31.0.0 (CIRISPersist#598) — THE CONSENT INSTANT BINDING. A
    // `consent:state:*` row is refused unless its signed envelope carries
    // an `asserted_at` (and `expires_at`) equal to the row column the
    // consent fold orders on. `asserted_at` is stored VERBATIM from the
    // caller here and no signature covers it, so without this a replay of
    // a subject's own byte-identical, still-valid grant with a bumped
    // column flipped a revocation back to Granted — and re-opened
    // `check_capacity_consent_admission`, a gate inside persist. Pure
    // function of (row, now) ⇒ AV-76 TIER 1, and a REFUSAL, so an early
    // position is safe. Backend-symmetric across memory / sqlite /
    // postgres, and asked again at the promote door
    // (`check_promotion_admission`) so the local tier is not a way around
    // it (B8).
    crate::federation::admission::check_instant_binding(
        &row,
        received_at,
        crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
    )?;

    // v31.0.0 (CIRISPersist#643) — THE TYPED-COLUMN BINDING. The
    // signature covers `attestation_envelope` and NOTHING ELSE, so
    // `attestation_type` (the VERB), `subject_key_ids` (which grants
    // revocation authority), `attested_key_id`, `cohort_scope` and
    // `weight` were unsigned columns a relay could rewrite with the
    // producer's own signature still verifying — flip `withdraws` to
    // `scores` and a retraction becomes a claim while the thing it
    // retracted stays live. Refused on ABSENCE or DIVERGENCE, no legacy
    // regime. Pure function of the row => AV-76 TIER 1, tier-blind (a
    // tier-scoped binding would be skippable by writing `tier = "local"`
    // and promoting), and backend-symmetric across memory / sqlite /
    // postgres.
    crate::federation::admission::check_row_column_binding(&row)?;
    // v53.0.0 (CIRISPersist#975, CC 2.4) — THE CLOSED ROW-TYPE SLOT, beside
    // the binding that makes the type a signed fact. The five + registered
    // carriers; a carrier of the wrong shape refused; an unregistered type
    // reported (refused once `row_type::ROW_TYPE_ENFORCEMENT` flips). Pure
    // ⇒ AV-76 TIER 1, backend-symmetric.
    crate::federation::row_type::admit_row_type(&row)?;

    // v3.9.1 (CIRISPersist#150 Ask 3, CEG 0.4 §4.2.4) — cohort_scope
    // admission-gate VALUE validation. Rejects out-of-closed-set values
    // (notably `global`, a §8.1.8 feed-name, never a wire value) BEFORE
    // persist_row_hash + insert so rejected rows leave no trace.
    // v22.0.0 (CIRISPersist#543): the memory backend never ran this, and
    // — unlike sqlite/postgres — it has NO V056 CHECK-constraint backstop
    // behind it, so a `global` row the SQL backends refuse at two layers
    // was accepted unconditionally here.
    crate::federation::admission::check_cohort_scope(&row.cohort_scope)?;

    // v26.0.0 (CIRISPersist#589 / AV-83) — `capacity:*` IS NEVER LOCAL.
    // See `src/store/sqlite.rs` put_attestation for the full rationale:
    // the v4.4.0 rule lived only inside `check_local_tier_eligibility`,
    // which this door never calls, while this door accepts
    // `tier = "local"`. Pure predicate ⇒ tier 1; a refusal, never an
    // accept. Backend-symmetric with sqlite + postgres.
    if row.tier == crate::federation::types::attestation_tier::LOCAL {
        crate::federation::admission::check_capacity_never_local(
            &row.attestation_type,
            crate::federation::admission::envelope_dimension(&row.attestation_envelope),
        )?;
    }

    // v18.1.0 (CIRISPersist#473 followup) — the `trace:*`
    // Information-Type validator: self-emission polarity
    // (`attesting_key_id` ∈ `subject_key_ids`) plus the inline-trace /
    // manifest shape. No-op for every non-`trace:` dimension.
    crate::federation::admission::check_trace_dimension_admission(
        crate::federation::admission::envelope_dimension(&row.attestation_envelope),
        &row.attesting_key_id,
        &row.subject_key_ids,
        &row.attestation_envelope,
    )?;

    // v21.3.0 (CIRISPersist#510 P1) — the closed consent-transfer
    // grammar admission chokepoint (parity with sqlite + postgres). A
    // `consent:replication:v1` grant's `payload` MUST parse through
    // `consent_grammar::parse_grant_payload` (closed enums, strict
    // `deny_unknown_fields`) — an unknown restriction op, an
    // unrecognized payload field, a non-consentable `kinds` entry, a
    // bad `grants` token, a bad `audience`, or an empty-string
    // `attestation_prefixes` entry rejects the WHOLE grant. No-op for
    // every other dimension (a `withdraws`/`recants` referencing a grant
    // carries its OWN dimension, never GRANT_DIMENSION). Runs BEFORE
    // persist — a rejected grant leaves no trace.
    if crate::federation::admission::envelope_dimension(&row.attestation_envelope)
        == Some(crate::federation::consent_grammar::GRANT_DIMENSION)
    {
        if let Err(reason) =
            crate::federation::consent_grammar::validate_grant_admission(&row.attestation_envelope)
        {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "consent grant rejected by the closed grammar (#510): {reason}"
            )));
        }
    }

    // ── AV-76 TIER 2 — the one unavoidable directory read ───────
    // v2.4.0 (CIRISPersist#102 Ask 3) — admission gate. Look up the
    // attesting key's `identity_type` through the executor's one read
    // (`AttestationStore::attesting_identity_type`); a missing key is
    // refused HERE, typed, rather than left to the FK violation the SQL
    // backends would raise at the INSERT.
    let attesting_identity_type = dir
        .attesting_identity_type(&row.attesting_key_id)
        .await?
        // v54.1.0 (CIRISPersist#1042) — the ORDERING gap, typed apart from a
        // bad signature (retryable once the Key row lands).
        .ok_or_else(|| {
            crate::federation::Error::unknown_signer(&row.attesting_key_id, "attestation")
        })?;
    // AV-76 D2 — the lookup above is a hard DATA dependency of the
    // dimension policy here (`attesting_identity_type`); the pair moves
    // as a unit and its internal order is fixed. The default policy
    // enforces the `accord:*` × `accord_holder` rule and the four-test
    // operational-language gate on `scores` attestations; structural
    // primitives are exempt. See `src/federation/admission.rs`.
    crate::federation::admission::DimensionAdmissionPolicy::default().check(
        &row.attestation_type,
        crate::federation::admission::envelope_dimension(&row.attestation_envelope),
        &attesting_identity_type,
    )?;

    // v12.6.0 (CIRISPersist#171, §10.1.3 transit-not-rest) — a `revoked`
    // consent_record at local tier MAY *transit* the local write path
    // only if its bound-hybrid signature verifies (accept on VALID crypto
    // only). No-op for non-consent_record rows and durable (granted /
    // federation) ones. Backend-symmetric with SQLite + Postgres.
    //
    // v22.0.0 (AV-76) — deliberately kept AHEAD of the §6.1 dedup. This
    // is the one crypto gate that must NOT move behind it: `withdraws` is
    // a structural composer, so a replayed subject-side revocation would
    // short-circuit at the dedup and never prove its bound-hybrid
    // signature.
    crate::federation::admission::verify_consent_record_transit_ingest(dir, &row).await?;

    // ── AV-76 TIER 3 — CRYPTO ───────────────────────────────────
    // v9.0.0 (CIRISPersist#237, CC 5.3.2.4.3.1) — PQC-mandatory
    // hybrid-verify at the federation-tier bulk store/replicate
    // ingest gate (parity with the postgres + sqlite backends). A
    // no-op for local-tier rows (CC 5.3.2.2 deferred signature); for
    // a federation-tier row it hybrid-verifies the envelope signature
    // (Ed25519 + ML-DSA-65, Strict) against the attester's REGISTERED
    // pubkeys. Composes with — does not replace — the trust-threshold
    // check_federation + the node-agency gate. Runs BEFORE persist — a
    // rejected row leaves no trace (verify-before-mutation, AV-9;
    // store-then-quarantine is non-conformant per CC 5.3.2.4.3.1).
    //
    // v22.0.0 (CIRISPersist#543 finding 4, AV-76) — MOVED here from
    // behind the whole authority walk. The ML-DSA-65 verify is the single
    // most expensive step in the stack, but a row whose signature can
    // never verify must not buy a single directory walk with it — and no
    // authority gate may run on an unverified row. The move is
    // correctness-safe because the verdict is position-independent: the
    // gate reads only attestation_envelope / attesting_key_id /
    // scrub_signature_* / original_content_hash / tier, and NO gate in the
    // stack writes any of them (the sole field-stamping gate,
    // `check_withdraws_admission`, writes `withdraws_admission_rule`,
    // which this never reads).
    crate::federation::verify_federation_tier_ingest(dir, &row).await?;

    // ── AV-76 TIER 4 — the DB-WALK authority gates ──────────────
    // Everything below walks the directory (delegation chains, family /
    // community membership, moderator sets, trust charters) through the
    // directory, never under a backend lock (memory's reads take its state
    // lock themselves). All of it now runs only for a
    // row that has already proven its envelope is admissible in shape AND
    // that its signature verifies.

    // v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — AV-45 write-path
    // cohort_scope admission gate. The writer (`attesting_key_id`) must be
    // a MEMBER of the target cohort they stamp. `self` + broad tiers pass
    // with no read; family/community resolve their target from the
    // producer's SIGNED envelope (v38.2.0, #757 — it was a hardcoded
    // `None` here, which refused every such placement and left an
    // owner-signed community row inexpressible on the whole substrate).
    // Runs AFTER the closed-set value validation in tier 1 and
    // BEFORE persist (verify-then-gate-then-persist, MISSION §1.6).
    // v52.0.0 (CIRISPersist#955) — AV-45 plus the two membership arms (a
    // proposal reaching its invitee, a reply at a group its signer is not in).
    crate::federation::membership_acceptance::check_attestation_write_scope(
        dir,
        &row,
        "put_attestation",
    )
    .await?;

    // v38.2.0 (CIRISPersist#757) — **AV-84 MOVES TO THIS DOOR TOO.**
    // `check_promotion_cohort_standing` refuses a targeted-cohort row
    // that names any party but its producer, and it justified being
    // promote-ONLY with a claim about THIS door: "put_attestation
    // therefore refuses those two placements outright, and that door is
    // SHUT, not leaking". The AV-45 call above just unshut it. Without
    // this line a member could place a row ABOUT A THIRD PARTY into the
    // whole community's plane — the exact claim AV-84 exists to refuse,
    // arriving through the door its own doc said could not be reached.
    // v38.2.0 PR #759 review: the standing comparison RESOLVES
    // occurrence -> identity (a device signing about its own owning
    // identity is not a third party), and a targeted placement is never
    // local-tier (local rows defer signature verification, and an
    // unverified membership claim is mintable by anyone).
    crate::federation::admission::check_attestation_tier_vocabulary(&row.tier)?;
    crate::federation::admission::check_targeted_cohort_requires_federation_tier(
        &row.tier,
        &row.cohort_scope,
    )?;
    crate::federation::admission::check_cohort_standing_resolved(dir, &row).await?;

    // v2.5.0 (CIRISPersist#102 Ask 4) — envelope-schema admission hook.
    // Same shape and same tier position as the sqlite + postgres backends;
    // see `src/store/sqlite.rs` put_attestation for the architectural
    // commentary. Skipped on the default `NoOpSchemaResolver` (which
    // answers `None`), so nothing that passes today starts failing.
    // AV-76 D4 — recomputes the dimension rather than carrying a binding
    // across the reordered stack; `envelope_dimension` is pure.
    //
    // v22.0.0 (CIRISPersist#543) — the memory backend had no resolver field
    // and no call site, so this gate did not exist here. Latent, not live,
    // because the default resolver is a no-op — but a host installing a
    // REAL resolver got enforcement on two backends and silence on the
    // third.
    if row.attestation_type == crate::federation::types::attestation_type::SCORES {
        if let Some(dim_str) =
            crate::federation::admission::envelope_dimension(&row.attestation_envelope)
        {
            let resolver = cx.schema_resolver.clone();
            let resolved = resolver.resolve(dim_str).await.map_err(|e| {
                crate::federation::Error::Backend(format!("schema resolver: {} ({})", e, e.kind()))
            })?;
            if let Some(schema) = resolved {
                if let Err(violations) =
                    crate::federation::schema_resolver::validate_envelope_against_schema(
                        &schema.document,
                        &row.attestation_envelope,
                    )
                {
                    let axis = crate::federation::axis_from_dimension(dim_str)
                        .unwrap_or("")
                        .to_owned();
                    return Err(crate::federation::Error::EnvelopeSchemaViolation {
                        dimension: dim_str.to_string(),
                        axis,
                        violations,
                    });
                }
            }
        }
    }

    // ── AV-76 TIER 4b — the §6.1 idempotent-replay short-circuit ──
    // v3.0.0 (CIRISPersist#116, CEG 0.2 §6.1) — structural-composer
    // dedup on `(references_attestation_id, attestation_type,
    // attesting_key_id)`. Look up the candidate row's references-id
    // from its envelope; if a row with the same triple already exists,
    // the second put is a silent no-op (structural composers are
    // idempotent on replay per §6.1).
    //
    // v22.0.0 (CIRISPersist#543 / AV-76 D3 CORRECTED) — **THIS RAN AT
    // TIER 2b AND THAT WAS A HOLE.** Ahead of crypto, its
    // `return Ok(())` was an early ACCEPT that skipped EVERY gate below
    // it: hybrid verification (tier 3) AND the AV-45 write-scope gate.
    // So a writer who could name an already-referenced
    // `(ref_id, type, attester)` triple got an unverified, unauthorized
    // `Ok`. The substrate state machine shrank it to ONE op with a
    // VALID signature (Withdraw, family=Reserved, cohort_scope=
    // Community: memory refused on write-scope, sqlite returned Ok).
    // The reorder that introduced it was mine.
    //
    // THE RULE, restated: **a dedup short-circuit may return early to
    // REFUSE, never to ACCEPT.** Idempotence is a promise about the
    // EFFECT of a replay (no second row) — never a licence to skip the
    // proof that the replay was admissible at all. So it now runs at
    // tier 4b: after everything that is a property of THIS row's bytes
    // and THIS writer's standing (both of which a replay must still
    // prove), and before the DB-walk authority gates below. That is the
    // property D3 actually wanted, and all it ever wanted — a replayed
    // `withdraws` whose authority has since been revoked stays a silent
    // no-op instead of flipping to a hard reject.
    if crate::federation::precedence::is_structural_composer(&row.attestation_type) {
        if let Some(ref_id) = crate::federation::precedence::references_attestation_id_from_envelope(
            &row.attestation_envelope,
        ) {
            if dir
                .composer_replay_held(&row.attestation_type, &row.attesting_key_id, ref_id)
                .await?
            {
                // v50.0.0 (review H2, final check) — an identical re-put of a
                // held `withdraws` whose admission depth is missing records it
                // now (idempotent repair; the executor writes it only when the
                // id itself is held).
                // v38.5.0 (#771) — the dedup path already returned success;
                // now it can say WHICH success it was.
                return Ok(AttestationPlan::ComposerReplay {
                    repair_withdraws_depth: (row.attestation_type
                        == crate::federation::types::attestation_type::WITHDRAWS)
                        .then(|| (row.attestation_id.clone(), dir.withdraws_delegation_depth())),
                });
            }
        }
    }

    // v6.4.0 (CIRISPersist#146 Ask 2, CEG §3.2.3) — broadened
    // `withdraws` admission gate (parity with sqlite + postgres). A
    // no-op for non-`withdraws` rows; for a `withdraws` it loads the
    // target T (by the envelope's `references_attestation_id`), resolves
    // WHICH of the 4 admission rules authorizes the issuer, and stamps
    // the rule number onto the row for the per-rule audit metadata. Runs
    // AFTER the §6.1 dedup (an idempotent replay short-circuits before
    // the walk) and BEFORE persist_row_hash, so a refused withdraws
    // leaves no trace and the recorded rule is covered by the row hash.
    if let Some(rule) = crate::federation::admission::check_withdraws_admission(dir, &row).await? {
        row.withdraws_admission_rule = Some(rule);
    }

    // v8.7.1 (CIRISPersist#233, CEG §11.10) — FULL moderation gate for
    // the report→`scores` half (moderation:* / reconsideration:*).
    // A no-op for any non-matching row; for a moderation/review report
    // it admits IFF the signer IS a duty-holder over the target (the
    // row's subject_key_ids ∪ the envelope community_id's named
    // moderators) or is reached by an steward-bound duty-holder via a live
    // scoped delegates_to chain. Absence ⇒ REJECT.
    crate::federation::admission::check_delegated_duty_scores_admission(dir, &row).await?;
    // v60.0.0 (CIRISPersist#803, CC 3.1.1 / CC 4.5.5) — a
    // `takedown_notice:{basis}:v1` row: its CC 3.3.2 shape, then the one
    // takedown authority decision for its signer over the content as this
    // node holds it. A no-op for every other row.
    crate::federation::takedown_tombstone::check_takedown_notice_row_admission(dir, &row).await?;
    // v44.6.0 (#857) — a machine author may name only itself in for_key_id.
    crate::federation::admission::check_consent_for_key_admission(dir, &row).await?;

    // v9.0.0 (CIRISPersist#236, CC 4.4.3.4.3 / CC 3.4.7.3) — reject-agency-
    // on-node-key gate. A no-op for non-`delegates_to` rows; for a
    // `delegates_to` whose recipient (`attested_key_id`) resolves to a
    // identity CONTAINING `node` it REJECTS any scope set that is not
    // `infra:*`-only (agency:* / legacy unprefixed agency / empty /
    // other) — "infrastructure must not have agency" made cryptographic.
    crate::federation::admission::check_node_agency_admission(dir, &row).await?;

    // v11.5.0 (CIRISPersist#306, CC 3.2 / CC 1.15.6) — the user-target
    // steward-binding gate: a `delegates_to` onto a `user`-role target is
    // admissible ONLY as minor-guardianship (proven-minor target +
    // proven-adult-user granter). Backend-symmetric with SQLite +
    // Postgres; verify-before-mutation.
    crate::federation::admission::check_user_target_steward_binding_admission(dir, &row).await?;

    // v50.0.0 (CIRISPersist#924, CC 5.4.6 / CC 3.4.13 Q5) — a minor's
    // owner-binding is never ANNOUNCED: refused at `cohort_scope:
    // federation`. Backend-symmetric; verify-before-mutation.
    crate::federation::admission::check_minor_owner_binding_not_announced(dir, &row).await?;

    // v54.0.0 (CIRISPersist#1031, CC 4.1.1) — the cycle-closing `delegates_to`
    // is refused: the recipient must not already reach the granter through live
    // `delegates_to` edges. Backend-symmetric with SQLite + Postgres; verify-before-mutation.
    crate::federation::admission::check_delegation_cycle_admission(dir, &row, received_at).await?;

    // v12.6.0 (CIRISConstitution#23, CC 1.13.3.3 / CC 3.2) — the single-owner
    // gate: a node has AT MOST ONE responsible steward, so a second,
    // distinct-owner owner-binding `delegates_to(U → node)` is rejected. This
    // is what makes the `self` cohort boundary well-defined. Backend-symmetric
    // with SQLite + Postgres; verify-before-mutation.
    crate::federation::admission::check_single_node_owner_admission(dir, &row).await?;

    // v18.2.0 — trust-charter admission (the charter walk). AV-76: a
    // directory walk, so it stays in tier 4.
    crate::federation::trust_root::check_trust_charter_admission(
        dir,
        &row.attestation_type,
        &row.attesting_key_id,
        &row.attested_key_id,
        &row.attestation_envelope,
        received_at,
    )
    .await?;
    // v51.0.0 (CIRISPersist#937, CC 3.2 T4a) — attaching is gated on a
    // witnessed lineage head inside the root's attach window.
    crate::federation::canonical_community::check_attach_freshness(
        dir,
        crate::federation::canonical_community::AttachDoor::of(origin),
        Some(&row.attestation_id),
        &row.attesting_key_id,
        &row.attestation_type,
        &row.attested_key_id,
        &row.attestation_envelope,
        received_at,
    )
    .await?;
    // v24.0.0 (CIRISPersist#557) — a charter naming a constitutional family
    // must be signed by that family's QUORUM. Sits beside the key-charter
    // gate above and refuses the same class of row for the same reason: a
    // root that one seat can declare is not a threshold.
    crate::federation::trust_root::check_family_charter_admission(dir, &row).await?;

    // v10.3.0 (CIRISPersist#288, CC 3.4.1/3.4.3/3.4.5) — reserved-prefix
    // admission on the attestation_TYPE namespace, keyed on the attesting
    // key's identity_type (a directory read), plus the #543 finding-2
    // dimension-keyed `capacity:*` self-emission arm. Backend-symmetric
    // with SQLite + Postgres.
    crate::federation::admission::check_reserved_prefix_admission(dir, &row).await?;
    // v22.0.0 (CIRISConstitution#46) — CONSENT BEFORE SCORING. A
    // federation-tier `capacity:*` claim about subject S from attester P is
    // refused unless a live `analyze` consent from S covering P exists in
    // this node's verified corpus. AV-76 TIER 4: it reads the directory
    // (the scoped consent fold), so it must never run ahead of crypto.
    // Placed IMMEDIATELY after the reserved-prefix gate — which carries
    // AV-62/74's dimension-keyed self-emission arm — so a SELF-attested
    // capacity row is still reported as self-emission rather than shadowed
    // by "no consent". Backend-symmetric across memory / sqlite / postgres.
    crate::federation::admission::check_capacity_consent_admission(dir, &row, received_at).await?;
    // v45.0.0 (CIRISPersist#871, FSD/MEDIA_SOURCE.md §5) — the placement
    // rule: a rendition (`media.derived_from`) whose original THIS node
    // holds must name the original's own `cohort_scope`. AV-76 TIER 4: it
    // reads the blob store, so it sits with the other state-reading gates.
    // Backend-symmetric; memory holds no blobs and answers "not held".
    crate::federation::renditions::check_rendition_placement(
        dir,
        &row.attestation_envelope,
        &row.cohort_scope,
    )
    .await?;

    // v38.7.0 (CIRISPersist#778, CC 3.4.5) — `config:{scope}` IS A
    // SELF-REPORT: `attesting_key_id` must be `attested_key_id` or its
    // live `owner_of`. CC 3.4.7 holds every 3.4.5 emitter rule with three
    // things — substrate admission, consumer re-check, producer obligation
    // — and persist had only the third, so a peer could attest
    // `config:replication` / `config:load` ABOUT A NODE IT DOES NOT OWN
    // and every honest consumer would believe a healthy node was shedding.
    // AV-76 TIER 4: the owner arm walks the directory, so it may not lead
    // the crypto. Placed immediately after the consent gate so the two CC
    // 3.4.5 gates sit together and a reader finds both at one line.
    // Backend-symmetric across memory / sqlite / postgres.
    crate::federation::admission::check_config_self_or_owner_admission(dir, &row).await?;
    // CC 3.1.1 (v42.0.0, CIRISPersist#814 part 1) — a duty rides only a
    // permission its attester issued, and never out-reaches it.
    crate::federation::admission::check_duty_admission(dir, &row).await?;
    // CC 3.4.5.1 — a config renewal must supersede the row it replaces
    // (v42.0.0, CIRISPersist#814 part 3).
    crate::federation::admission::check_config_renewal_supersedes(dir, &row).await?;
    // CC 3.4.3 — `session:*` is a substrate self-report (v42.0.0,
    // CIRISPersist#814 part 5; the rc5 re-vendor exposed the gap).
    crate::federation::admission::check_session_self_report_admission(&row)?;
    // CC 3.3.1 — a `consent:community_trust` grant is the node's own and
    // lists its owner at the grant's instant (v52.0.0, CIRISPersist#946).
    crate::federation::community_trust_consent::check_community_trust_grant_admission(
        dir, &row, fold_at,
    )
    .await?;
    // v59.0.0 (CIRISPersist#1106, CC 5.3.4) — a serve node's transit-pair
    // re-bind is a holder-quorum act.
    crate::federation::transport_rebind::check_rebind_admission(dir, &row).await?;
    // CC 3.1.3.3 — `custody:ack:v1` is a holder self-report, placed within
    // the blob's own cohort (v53.0.0, CIRISPersist#942 part 2).
    crate::federation::custody_ack::check_custody_ack_admission(dir, &row).await?;
    // v55.0.0 (CIRISPersist#989, CC 3.1.3.3 rule 1) — a holding claim about a blob
    // this node holds is placed at that blob's scope (memory holds none).
    crate::federation::holding_claim::check_holding_claim_scope(dir, &row).await?;
    // CC 3.2 — a `community:listing:v1` row is federation-scoped and signed by the
    // room's founder or a current moderate-holder (v55.0.0, CIRISPersist#1053).
    crate::federation::public_room::check_community_listing_admission(dir, &row).await?;
    // CC 3.1 — a lowercase family stem, or the row evades every family gate
    // (v42.0.0, CIRISPersist#814).
    crate::federation::admission::check_dimension_case_rule(&row)?;
    // CC 3.3.9 — a `license`-scoped issuance resolves to the authority it
    // names (v42.0.0, CIRISPersist#814).
    crate::federation::admission::check_licensure_delegator_is_authority(
        dir,
        &row,
        received_at,
        fold_at,
    )
    .await?;

    // v22.0.0 (CIRISPersist#543 / AV-77) — THE DE-ADMISSION GATE. A peer
    // this node has de-admitted gets its writes refused here. No-op when
    // the host installed no `self_key_id`: a node that has declared no
    // identity has authored no de-admissions, so the set is empty.
    //
    // v22.0.0 (CIRISPersist#543): absent on this backend entirely — the
    // gate, its `self_key_id` field and its accessor all shipped on sqlite
    // + postgres only, which made the CHANGELOG's "all five closed on all
    // three backends" false for AV-77. Same tier position as the SQL
    // backends so a refusal is named by the same gate everywhere.
    if let Some(me) = &cx.self_key_id {
        crate::federation::admission::check_peer_deadmission(dir, &row, me, received_at).await?;
    }

    // v12.5.0 (CIRISPersist#238, CC 4.5.4 / §11.11) — no-moderator-no-
    // federate FEDERATION-APPLY re-check (point ii). A federation-tier row
    // keyed on a community is a federation apply step keyed on C; it is
    // refused if C has lost its last live `moderate`-holder (so a
    // moderator-less community cannot continue at moderated capability).
    // #369 broadened the keying: C is referenced via envelope
    // `community_id`/`community_key_id`/`cohort_key_id`, OR a row endpoint
    // / subject_key_ids entry resolving as a stored community (the
    // membership shape). No-op for local-tier rows and rows referencing no
    // locally-known community. Backend-symmetric.
    crate::federation::admission::check_no_moderator_federate_apply(dir, &row).await?;
    // v24.0.0 (CIRISPersist#557) — the attested SUBJECT must resolve as a
    // key this node knows OR as a constitutional family it has stored. V114
    // lifted this rule out of the SQLite schema FK (which cannot express the
    // keyless-family exception a family trust root needs) into ONE predicate
    // every backend runs at this same point. All three DID enforce the rule
    // before (sqlite + postgres by FK, memory by emulation); what none of
    // them could express is the keyless-family exception.
    crate::federation::admission::check_attested_subject_admission(dir, &row.attested_key_id)
        .await?;

    // ── AV-76 TIER 5 — the row as it will be stored ─────────────
    // D1: `check_withdraws_admission` above STAMPS
    // `row.withdraws_admission_rule`, and the row hash covers it — so that
    // gate must precede this line. It does.
    // v21.0.0 (#501) — the inbound trace projection, decomposed while the
    // row is still owned.
    let projected_trace =
        crate::ingest::project_trace_events_from_attestation(&row.attestation_envelope);
    // v57.0.0 (CIRISPersist#988 item 3) — the detection projection, read from
    // the row by the one function the rebuild calls too.
    let projected_detection = crate::derived::detection_row::project_detection_row(&row);
    // v60.0.0 (CIRISConstitution#170 closed) — the hard_case projection, by
    // the one function the hard_case door and the rebuild call too.
    let projected_hard_case = super::hard_case::project_hard_case_row(&row);
    // v60.0.0 (CIRISPersist#988 item 1) — the ledger projection, by the one
    // function the rebuild calls too: this node's own `credits:` /
    // `expertise:` rows only.
    let projected_ledger =
        super::ledger_projection::project_ledger_row(&row, dir.node_key_id().as_deref());
    row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
    // v21.1.0 (CIRISPersist#507b) — wire-index this row (federation tier
    // only, the E5 invariant). v31.0.0 (CIRISPersist#646) — only the
    // LOCATOR is derived here; the hash comes from the stored row, after
    // the write (`index_stored_record`).
    let wire_index_key =
        (row.tier == crate::federation::types::attestation_tier::FEDERATION).then(|| {
            crate::federation::wire_index::record_key(&[("attestation_id", &row.attestation_id)])
        });
    // v50.0.0 (review H2, V157) — the depth this `withdraws` was admitted
    // under, recorded in the SAME write as the row.
    let withdraws_depth = (row.attestation_type
        == crate::federation::types::attestation_type::WITHDRAWS)
        .then(|| dir.withdraws_delegation_depth());
    let cycle_gated = crate::federation::admission::delegation_cycle_gated(&row);
    Ok(AttestationPlan::Insert(Box::new(PlannedAttestation {
        row,
        withdraws_depth,
        projected_trace,
        projected_detection,
        projected_hard_case,
        projected_ledger,
        wire_index_key,
        cycle_gated,
        received_at,
    })))
}

/// v56.0.0 (CIRISPersist#934 step 1, door 2) — what the local door's plan
/// decided.
pub(crate) enum LocalPlan {
    /// An insert (`attestation_insert_local`) whose id is already held: the
    /// held row stands and nothing is written (the #473 replay idempotence of
    /// a deterministic trace-ingest id).
    Held(String),
    /// Write it.
    Write(Box<PlannedLocalAttestation>),
}

/// An admitted local-tier row, exactly as the executor stores it.
pub(crate) struct PlannedLocalAttestation {
    /// The row: stamped mirror and instants, computed `persist_row_hash`.
    pub(crate) row: Attestation,
    /// The `(attester, dimension)` key an upsert replaces.
    pub(crate) dimension: String,
    /// Upsert (`true`) or insert.
    pub(crate) replace: bool,
    /// The delegation depth a local `withdraws` is recorded at (V157).
    pub(crate) withdraws_depth: Option<usize>,
}

/// What a caller-chosen `attestation_id` that is already held means.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LocalIdVerdict {
    /// Nothing holds the id.
    Free,
    /// An upsert, and the held row is one it replaces: the local row of the
    /// same `(attester, dimension)`.
    Replaces,
    /// An insert: the held row stands, nothing is written.
    Held,
}

/// v56.0.0 (CIRISPersist#934 step 1, door 2; lead ruling on I951) — **the
/// occupied-id clause, once.** Before #934 the three backends disagreed (I951):
/// memory returned before the upsert's replace; sqlite and postgres replaced,
/// and on a held row of ANOTHER dimension deleted the upsert's own row and
/// stored nothing. The ruling: an upsert REPLACES its own `(attester,
/// dimension)` local row, whatever id that row holds; an id held by any other
/// row is [`Error::LocalAttestationIdOccupied`], with nothing written and
/// nothing deleted. An insert of a held id writes nothing (unchanged).
pub(crate) fn local_occupied_id_verdict(
    held: Option<&Attestation>,
    row: &Attestation,
    dimension: &str,
    replace: bool,
) -> Result<LocalIdVerdict, Error> {
    let Some(held) = held else {
        return Ok(LocalIdVerdict::Free);
    };
    if !replace {
        return Ok(LocalIdVerdict::Held);
    }
    let held_dimension =
        crate::federation::admission::envelope_dimension(&held.attestation_envelope);
    if held.tier == crate::federation::types::attestation_tier::LOCAL
        && held.attesting_key_id == row.attesting_key_id
        && held_dimension == Some(dimension)
    {
        return Ok(LocalIdVerdict::Replaces);
    }
    Err(Error::LocalAttestationIdOccupied {
        attestation_id: row.attestation_id.clone(),
        held_attesting_key_id: held.attesting_key_id.clone(),
        held_dimension: held_dimension.map(str::to_owned),
        held_tier: held.tier.clone(),
    })
}

/// v56.0.0 (CIRISPersist#934 step 1, door 2) — the door: every backend's
/// `attestation_upsert_local` / `attestation_insert_local` is this call. The
/// one clock read of the door is here.
pub(crate) async fn write_local_attestation_planned<D>(
    dir: &D,
    input: crate::federation::types::LocalAttestationInput,
    replace: bool,
) -> Result<String, Error>
where
    D: AttestationStore,
{
    let received_at = chrono::Utc::now();
    let id = match plan_write_local_attestation(dir, input, replace, received_at).await? {
        LocalPlan::Held(id) => id,
        LocalPlan::Write(planned) => {
            let id = planned.row.attestation_id.clone();
            dir.store_planned_local_attestation(*planned).await?;
            id
        }
    };
    Ok(id)
}

/// v56.0.0 (CIRISPersist#934 step 1, door 2) — **the local door's decision**,
/// once for all three backends: the seventeen gates the three
/// `*_write_local_attestation` helpers each ran, in the same order, then the
/// occupied-id clause. The local door mints the row's instant itself
/// (`local_row_instant`, from the signed envelope when it carries one), so it
/// takes only `received_at`; every gate here read the receipt clock before.
pub(crate) async fn plan_write_local_attestation<D>(
    dir: &D,
    input: crate::federation::types::LocalAttestationInput,
    replace: bool,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<LocalPlan, Error>
where
    D: AttestationStore,
{
    // v17.9.0 (CC#38 interim) — envelope size cap FIRST, before any
    // parsing/lookups (cheapest-most-specific-rejection-first).
    // v20.0.0 (#495): the input envelope is TYPED (EnvelopeCore);
    // serialize once for the Value-based admission checks.
    let envelope_value = input.attestation_envelope.to_value();
    crate::federation::admission::check_envelope_size_admission(&envelope_value)?;
    // v44.8.0 (CIRISPersist#866 C1) — the scope-token gate, at the local
    // door too (`FSD/CONTEXTUAL_INTEGRITY_ENVELOPE.md` §4.4).
    crate::federation::consent_scope::check_consent_scope_tokens(&envelope_value)?;
    // v45.0.0 (CIRISPersist#871) — the media Source struct gate, at the local
    // door too (`FSD/MEDIA_SOURCE.md` §6). A local row never carries a
    // holder claim, so only the struct is checked here.
    crate::federation::media_source::check_media_source(&envelope_value)?;
    crate::federation::admission::check_trace_dimension_admission(
        input.dimension(),
        &input.attesting_key_id,
        &input.subject_key_ids,
        &envelope_value,
    )?;
    crate::federation::trust_root::check_trust_charter_admission(
        dir,
        &input.attestation_type,
        &input.attesting_key_id,
        input
            .attested_key_id
            .as_deref()
            .unwrap_or(&input.attesting_key_id),
        &envelope_value,
        received_at,
    )
    .await?;
    // v51.0.0 (CIRISPersist#937, CC 3.2 T4a) — attaching is gated on a
    // witnessed lineage head inside the root's attach window.
    crate::federation::canonical_community::check_attach_freshness(
        dir,
        crate::federation::canonical_community::AttachDoor::Author,
        input.attestation_id.as_deref(),
        &input.attesting_key_id,
        &input.attestation_type,
        input
            .attested_key_id
            .as_deref()
            .unwrap_or(&input.attesting_key_id),
        &envelope_value,
        received_at,
    )
    .await?;
    // The (occurrence, dimension) key + the gate axis. Required.
    let dimension = input.dimension().map(|s| s.to_string()).ok_or_else(|| {
        Error::InvalidArgument(
            "local attestation envelope must carry a \"dimension\" string".into(),
        )
    })?;
    // v57.0.0 (CIRISPersist#988 item 2) — a `hard_case:*` row is written by
    // the substrate's hard_case door alone (`record_hard_case`, attester = the
    // node key), so the projection holds only what that door decided.
    if super::hard_case::is_hard_case_dimension(&dimension) {
        return Err(Error::InvalidArgument(format!(
            "{dimension}: a hard_case row is written by the substrate's hard_case door \
             (record_hard_case), not the local door"
        )));
    }

    // §4.1 local-tier gate: refuse capacity:*; classify subject-side
    // revocation as TRANSIT (§10.1.3 transit-not-rest).
    let disposition = crate::federation::admission::check_local_tier_eligibility(
        &input.attestation_type,
        Some(dimension.as_str()),
        &input.attesting_key_id,
        &input.subject_key_ids,
        &input.cohort_scope,
    )?;

    // cohort_scope value validation (closed set).
    crate::federation::admission::check_cohort_scope(&input.cohort_scope)?;

    // v12.6.0 (CIRISPersist#171, §10.1.3) — a subject-side revocation MAY
    // *transit* the local write path only if its bound-hybrid signature
    // verifies (accept on VALID crypto only). `None` for a durable
    // producer-authority row. Runs before the DB write.
    let transit =
        crate::federation::admission::verify_caller_signed_local_row(dir, disposition, &input)
            .await?;

    // v24.0.0 (CIRISPersist#557) — the attested SUBJECT rule, shared with the
    // federation write path and with the other two backends. V114 removed
    // the SQLite `attested_key_id` FK that used to catch this at INSERT, so
    // the local writer must run the predicate explicitly or the two write
    // paths would enforce different rules.
    // v31.2.0 (CIRISPersist#670) — it runs HERE, behind the pure gates, not
    // ahead of them. It resolves the subject through the directory; the
    // three gates above are pure functions of `input`. Memory had this
    // order and the two SQL backends did not, which is the AV-76 tier
    // inversion of #660 wearing different clothes: a row that fails a free
    // predicate was paying for a directory walk first, on the two backends
    // production runs.
    crate::federation::admission::check_attested_subject_admission(
        dir,
        input
            .attested_key_id
            .as_deref()
            .unwrap_or(&input.attesting_key_id),
    )
    .await?;
    // v45.0.0 (CIRISPersist#871, FSD/MEDIA_SOURCE.md §5) — the placement
    // rule at the local door: a rendition (`media.derived_from`) whose
    // original THIS node holds must name the original's own
    // `cohort_scope`. Reads the blob store, so it sits with the other
    // directory-reading gates, before the write. Backend-symmetric.
    crate::federation::renditions::check_rendition_placement(
        dir,
        &envelope_value,
        &input.cohort_scope,
    )
    .await?;

    // FK precondition + §7.0.1 emitter gate: the attesting key must
    // exist; its identity_type gates the dimension. Mirrors
    // put_attestation, minus the federation trust-threshold gate
    // (local = producer-only authority, not federation-trust-gated).
    let identity_type = dir
        .attesting_identity_type(&input.attesting_key_id)
        .await?
        .ok_or_else(|| {
            Error::InvalidArgument(format!(
                "attesting_key_id {} does not exist in federation_keys",
                input.attesting_key_id
            ))
        })?;
    let dim = input.dimension();
    crate::federation::admission::DimensionAdmissionPolicy::default().check(
        &input.attestation_type,
        dim,
        &identity_type,
    )?;

    // Build the local row + its persist_row_hash. A durable row defers
    // its signature (empty-sentinel scrub envelope); a TRANSIT revocation
    // carries the caller's verified bound-hybrid signature + computed hash.
    // v18.0.0 (#473) — caller-supplied deterministic id (replay-idempotent
    // trace ingest) or the classic fresh v4.
    let attestation_id = input
        .attestation_id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    // v31.0.0 (CIRISPersist#598) — the row instant comes from the SIGNED
    // envelope when it carries one (see `admission::local_row_instant`), so
    // a `consent:state:*` row staged at the local tier can still satisfy
    // the instant binding at the promote door.
    let now = crate::federation::admission::local_row_instant(&envelope_value, received_at)?;
    let caller_signed = transit.is_some();
    let mut row = match transit {
        Some((hash, sig_classical, sig_pqc)) => {
            input.into_caller_signed_row(attestation_id.clone(), now, hash, sig_classical, sig_pqc)
        }
        None => input.into_local_row(attestation_id.clone(), now),
    };
    // v31.0.0 (CIRISPersist#660) — THE BAKED GENESIS IDS ARE RESERVED AT
    // THIS DOOR TOO. See the memory backend's local door for why this one
    // cannot defer to the promote gate the way `check_reserved_prefix_admission`
    // does: the harm is the PRIMARY KEY, and a local-tier row already holds it.
    crate::federation::genesis::check_genesis_attestation_reserved(&row)?;
    // v31.0.0 (CIRISPersist#649) — STAMP THE MIRROR AT THE LOCAL DOOR.
    // See `crate::federation::envelope::RowMirror::stamp_local_row` for the
    // decision and the transit exclusion. One helper, all three backends.
    crate::federation::envelope::RowMirror::stamp_local_row(&mut row, caller_signed)?;
    // v31.0.0 (CIRISPersist#653) — SIZE THE ROW AS IT WILL BE STORED. The early call above
    // measured the PRODUCER's envelope; this one measures the bytes that
    // actually land, which the #643 mirror and the #598 instants just grew
    // by ~250. Without it a row in that window is admitted here and refused
    // by the SAME function at the federation door on promotion or
    // replication — locally Ok, globally unreplicable. Both calls stay: the
    // early one is the cheap pre-filter that keeps hostile input away from
    // the directory reads below it, this one is authoritative. See
    // `check_envelope_size_admission` for why producers do not reserve
    // headroom instead.
    crate::federation::admission::check_envelope_size_admission(&row.attestation_envelope)?;
    // v31.0.0 (CIRISPersist#598) — the same binding the federation door
    // asks, asked at the local door too: a `consent:state:*` row that
    // cannot state its own signed instant is refused where it is written,
    // not where it is promoted.
    crate::federation::admission::check_instant_binding(
        &row,
        received_at,
        crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
    )?;
    row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
    // The occupied-id clause (lead ruling on I951), over the held row as
    // stored: the same point read the crossing door plans over.
    let held = dir.get_attestation(&row.attestation_id).await?;
    if local_occupied_id_verdict(held.as_ref(), &row, &dimension, replace)? == LocalIdVerdict::Held
    {
        return Ok(LocalPlan::Held(row.attestation_id));
    }
    let withdraws_depth = (row.attestation_type
        == crate::federation::types::attestation_type::WITHDRAWS)
        .then(|| dir.withdraws_delegation_depth());
    Ok(LocalPlan::Write(Box::new(PlannedLocalAttestation {
        row,
        dimension,
        replace,
        withdraws_depth,
    })))
}

/// v56.0.0 (CIRISPersist#934 step 1, door 4) — an admitted re-seal
/// (`reseal_attestation_v31`).
pub(crate) struct PlannedReseal {
    resealed: Attestation,
    received_at: chrono::DateTime<chrono::Utc>,
}

impl PlannedReseal {
    /// The row the re-seal names.
    pub(crate) fn attestation_id(&self) -> &str {
        &self.resealed.attestation_id
    }

    /// **The re-seal against the row the executor holds** in its write step:
    /// the shape gate (`migration::check_reseal_admission`) asked again on
    /// `found`, then `found` with the re-seal's seal fields and its new row
    /// hash. Before v56.0.0 sqlite and postgres judged the row they read
    /// before their transaction and overwrote whatever was there by then
    /// (I953); memory alone re-asked under its lock.
    pub(crate) fn sealed_over(&self, found: &Attestation) -> Result<Attestation, Error> {
        let resealed = &self.resealed;
        crate::federation::migration::check_reseal_admission(found, resealed, self.received_at)?;
        let mut row = found.clone();
        row.attestation_envelope = resealed.attestation_envelope.clone();
        row.original_content_hash = resealed.original_content_hash.clone();
        row.scrub_signature_classical = resealed.scrub_signature_classical.clone();
        row.scrub_signature_pqc = resealed.scrub_signature_pqc.clone();
        row.scrub_key_id = resealed.scrub_key_id.clone();
        row.scrub_timestamp = resealed.scrub_timestamp;
        row.additional_scrubs = resealed.additional_scrubs.clone();
        row.asserted_at = resealed.asserted_at;
        row.expires_at = resealed.expires_at;
        row.pqc_completed_at = resealed
            .scrub_signature_pqc
            .as_ref()
            .map(|_| resealed.scrub_timestamp);
        row.persist_row_hash = String::new();
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
        Ok(row)
    }
}

/// v56.0.0 (CIRISPersist#934 step 1, door 4) — **the re-seal decision**, once
/// for all three backends: the shape gate (AV-76 tier order: the pure gate
/// leads) and the seal gate (#656), over the row as read.
pub(crate) async fn plan_reseal_attestation<D>(
    dir: &D,
    stored: &Attestation,
    resealed: &Attestation,
    received_at: chrono::DateTime<chrono::Utc>,
) -> Result<PlannedReseal, Error>
where
    D: AttestationStore,
{
    crate::federation::migration::check_reseal_admission(stored, resealed, received_at)?;
    crate::federation::admission::check_reseal_seal_admission(dir, stored, resealed).await?;
    Ok(PlannedReseal {
        resealed: resealed.clone(),
        received_at,
    })
}

/// v56.0.0 (CIRISPersist#934 step 1, door 4) — the door: every backend's
/// `reseal_attestation_v31` is this call. The one clock read of the door is
/// here.
pub(crate) async fn reseal_attestation_planned<D>(
    dir: &D,
    resealed: &Attestation,
) -> Result<bool, Error>
where
    D: AttestationStore,
{
    let received_at = chrono::Utc::now();
    let Some(stored) = dir.get_attestation(&resealed.attestation_id).await? else {
        return Ok(false);
    };
    let planned = plan_reseal_attestation(dir, &stored, resealed, received_at).await?;
    let landed = dir.store_planned_reseal(planned).await?;
    Ok(landed)
}

/// v56.0.0 (CIRISPersist#934 step 1, door 5) — `purge_attestation_v31`,
/// decided once: the exclusion gate (`migration::check_purge_admission`) over
/// the row as read, then the delete. The read and the delete are two steps on
/// every backend, as they were before (no backend re-asks under its lock).
pub(crate) async fn purge_attestation_planned<D>(
    dir: &D,
    attestation_id: &str,
) -> Result<bool, Error>
where
    D: AttestationStore,
{
    if let Some(row) = dir.get_attestation(attestation_id).await? {
        crate::federation::migration::check_purge_admission(&row)?;
    }
    let gone = dir.delete_attestation(attestation_id, None).await?;
    Ok(gone)
}

/// v56.0.0 (CIRISPersist#934 step 1, door 6) — `purge_genesis_delegation_row_v31`,
/// decided once: the re-bake gate (the id must be one the compiled-in bundle
/// carries, under the caller's authority), then a compare-and-delete on
/// `expected_persist_row_hash`.
pub(crate) async fn purge_genesis_delegation_row_planned<D>(
    dir: &D,
    attestation_id: &str,
    expected_persist_row_hash: &str,
    authority: &crate::federation::genesis::bundle::GenesisPurgeAuthority<'_>,
) -> Result<bool, Error>
where
    D: AttestationStore,
{
    crate::federation::genesis::check_genesis_rebake_purge_admission_under(
        attestation_id,
        authority,
    )?;
    let gone = dir
        .delete_attestation(attestation_id, Some(expected_persist_row_hash))
        .await?;
    Ok(gone)
}

// ─────────────────────────────────────────────────────────────────────────
//  v57.0.0 (CIRISPersist#988 item 2, CC 3.1.9.4) — the hard_case door
// ─────────────────────────────────────────────────────────────────────────

/// The attester of every `hard_case:*` row (CC 3.1.9.4, CLM-hard-case-on-base:
/// "attester = the node key"): this node's declared key, held in
/// `federation_keys`, with its `identity_type` for the dimension gate.
#[derive(Debug, Clone)]
pub(crate) struct HardCaseAttester {
    /// This node's key id.
    pub(crate) key_id: String,
    /// Its `identity_type`, as held.
    pub(crate) identity_type: String,
}

/// v57.0.0 (CIRISPersist#988 item 2) — **resolve the hard_case attester**,
/// before any mutation. Every emitter calls this first: the hard_case door
/// below, and each backend's in-transaction emitters (the two trace
/// erasures, the membership removal, the peer removal) BEFORE they open
/// their transaction, because the row's attester must exist for the row's
/// foreign key and a refusal must leave the act undone, never done
/// unaudited.
///
/// A directory with no node identity, or one whose declared key it does not
/// hold, refuses with [`Error::HardCaseAttesterUnavailable`] (named
/// [`super::hard_case::refusal::ATTESTER_UNAVAILABLE`]).
///
/// It also rehomes any pre-v57 `hard_case_events` row that has no backing
/// row yet ([`AttestationStore::rehome_legacy_hard_case_events`]): the first
/// emitter after an upgrade, with the node's key in hand, moves the silo onto
/// the plane.
pub(crate) async fn hard_case_attester<D>(dir: &D) -> Result<HardCaseAttester, Error>
where
    D: AttestationStore,
{
    let key_id = dir
        .node_key_id()
        .ok_or(Error::HardCaseAttesterUnavailable {
            reason: super::hard_case::refusal::NODE_KEY_UNSET,
            node_key_id: None,
        })?;
    let identity_type = dir.attesting_identity_type(&key_id).await?.ok_or_else(|| {
        Error::HardCaseAttesterUnavailable {
            reason: super::hard_case::refusal::NODE_KEY_NOT_HELD,
            node_key_id: Some(key_id.clone()),
        }
    })?;
    let attester = HardCaseAttester {
        key_id,
        identity_type,
    };
    dir.rehome_legacy_hard_case_events(&attester, chrono::Utc::now())
        .await?;
    Ok(attester)
}

/// v57.0.0 (CIRISPersist#988 item 2) — what an in-transaction emitter does
/// when this node has no attester for the row ([`hard_case_attester`]
/// refused). Every ACT (an erasure, a peer removal, `record_hard_case`)
/// resolves its attester before it moves anything and refuses typed there,
/// so the only in-transaction emitter left without one is an observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HardCaseEmitter {
    /// An observation riding on a row being admitted (a membership removal
    /// applied from a peer): not recorded, and the admission proceeds. A node
    /// with no identity cannot attest what it saw, and refusing the removal
    /// would leave the removed member keyed.
    Observation,
}

impl HardCaseEmitter {
    /// The outcome without an attester: logged, and the admission proceeds.
    pub(crate) fn without_attester(self, event_id: &str, refusal: &str) -> Result<(), String> {
        match self {
            Self::Observation => {
                tracing::warn!(
                    event_id,
                    refusal,
                    "hard_case observation not recorded: this node has no attester"
                );
                Ok(())
            }
        }
    }
}

/// A planned `hard_case:{kind}:v1` row and the `hard_case_events` row it
/// projects to, written by the executor in one step.
#[derive(Debug, Clone)]
pub(crate) struct PlannedHardCase {
    /// The local-tier row, exactly as stored.
    pub(crate) row: Attestation,
    /// [`super::hard_case::project_hard_case_row`] of `row`.
    pub(crate) projection: super::hard_case::HardCaseEvent,
}

/// v57.0.0 (CIRISPersist#988 item 2, CC 3.1.9.4) — **the hard_case door's
/// decision**, once for all three backends, and PURE: no directory read, no
/// clock. That is what lets each backend call it inside its own transaction,
/// after an erasure has counted what it deleted, so the row commits with the
/// act it records (no erasure without its audit row, no audit row without
/// the erasure).
///
/// The row: `scores`, dimension `hard_case:{kind}:v1`
/// ([`super::hard_case::hard_case_dimension`]), attester = attested = the
/// node key, `cohort_scope = self`, local tier, the event whole under the
/// `hard_case` member, id derived from `event_id`
/// ([`super::hard_case::hard_case_attestation_id`]). Its signature is
/// deferred, as on every local-tier row this node attests (the
/// `trace:complete:v1` precedent): the node signs as the actor at the
/// crossing (`Engine::enter_mesh`), and the crossed row replicates like any
/// attestation row (v60.0.0, CIRISConstitution#170 closed).
///
/// The gates, in order: the envelope size, the dimension gate, the reserved
/// genesis ids, the mirror and instant stamp, the size of the row as stored,
/// the instant binding at `received_at`. A hard_case row judges no other row;
/// its own signed instant is `fold_at` (a live door passes the receipt clock
/// for both; the rehome passes the silo row's recorded `emitted_at`).
///
/// The #570 attribution gate is the `record_hard_case` DOOR's
/// ([`record_hard_case_planned`]), as it was before v57: the in-transaction
/// emitters build their own events, and the peer removal's
/// `admin_action:peer_removal` carries a REQUIRED reason and an optional
/// delegation (#721), which that gate would refuse.
pub(crate) fn plan_hard_case_row(
    event: &super::hard_case::HardCaseEvent,
    attester: &HardCaseAttester,
    instants: PlanInstants,
) -> Result<PlannedHardCase, Error> {
    use crate::federation::types::{attestation_type, cohort_scope, LocalAttestationInput};
    let envelope = super::hard_case::hard_case_envelope(event)
        .map_err(|e| Error::Backend(format!("hard_case envelope: {e}")))?;
    crate::federation::admission::check_envelope_size_admission(&envelope)?;
    let dimension = super::hard_case::hard_case_dimension(&event.kind);
    crate::federation::admission::DimensionAdmissionPolicy::default().check(
        attestation_type::SCORES,
        Some(&dimension),
        &attester.identity_type,
    )?;
    let attestation_id = super::hard_case::hard_case_attestation_id(&event.event_id);
    let input = LocalAttestationInput {
        attestation_id: Some(attestation_id.clone()),
        attesting_key_id: attester.key_id.clone(),
        attested_key_id: None,
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: None,
        expires_at: None,
        attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(envelope)?,
        subject_key_ids: Vec::new(),
        cohort_scope: cohort_scope::SELF.to_owned(),
        scrub_signature_classical: None,
        scrub_signature_pqc: None,
    };
    // The row's signed instant is `fold_at` (PlanInstants: "the row's signed
    // instant"): the receipt clock at a live door, the silo row's own
    // recorded instant when a pre-v57 row is rehomed (never the boot clock).
    let mut row = input.into_local_row(attestation_id, instants.fold_at);
    crate::federation::genesis::check_genesis_attestation_reserved(&row)?;
    crate::federation::envelope::RowMirror::stamp_local_row(&mut row, false)?;
    crate::federation::admission::check_envelope_size_admission(&row.attestation_envelope)?;
    crate::federation::admission::check_instant_binding(
        &row,
        instants.received_at,
        crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
    )?;
    row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
    let projection = super::hard_case::project_hard_case_row(&row).ok_or_else(|| {
        Error::Backend(format!(
            "hard_case row {} does not project: the door built a row its own projection \
             cannot read",
            row.attestation_id
        ))
    })?;
    Ok(PlannedHardCase { row, projection })
}

/// v57.0.0 (CIRISPersist#988 item 2) — the door: every backend's
/// `record_hard_case` is this call. The attribution gate runs first, so an
/// unattributed admin action is refused naming which half is missing on a
/// node with or without an identity (the #570 refusal, unchanged); then the
/// attester, the one clock read, the plan, the write.
pub(crate) async fn record_hard_case_planned<D>(
    dir: &D,
    event: super::hard_case::HardCaseEvent,
) -> Result<(), Error>
where
    D: AttestationStore,
{
    super::hard_case::check_admin_action_attribution(&event)?;
    let attester = hard_case_attester(dir).await?;
    let now = chrono::Utc::now();
    let planned = plan_hard_case_row(
        &event,
        &attester,
        PlanInstants {
            fold_at: now,
            received_at: now,
        },
    )?;
    dir.store_planned_hard_case(planned).await
}

// ─────────────────────────────────────────────────────────────────────────
//  v57.0.0 (CIRISPersist#988 item 3, CC 3.4.8) — the detection door
// ─────────────────────────────────────────────────────────────────────────

/// A planned `detection:{detector}:v1` row and the `detection_events` row it
/// projects to.
#[derive(Debug, Clone)]
pub(crate) struct PlannedDetection {
    /// The local-tier row, exactly as stored.
    pub(crate) row: Attestation,
    /// [`crate::derived::detection_row::project_detection_row`] of `row`.
    pub(crate) projection: crate::derived::detection_row::DetectionProjection,
}

/// v57.0.0 (CIRISPersist#988 item 3, CC 3.4.8) — **the detection door's
/// decision**, once for all three backends, and pure. The row: `scores`,
/// dimension `detection:{detector}:v1`, attester = the detector's key
/// (`signing_key_id`, whose `identity_type` is `attester_identity_type`),
/// `cohort_scope = self`, local tier, the detection whole under the
/// `detection` member, id derived from `detection_id`. Its own signature is
/// deferred (the detector's hybrid signature over `canonical_bytes` rides in
/// the body, verified by the caller); the detector signs the row as the actor
/// at the crossing.
///
/// The gates: V008's shape (the three signature/digest lengths, the
/// canonical-bytes bound, a live body or a whole tombstone), the envelope
/// size, the dimension gate (the `detection:` reserved family:
/// `lenscore_detector` only, CC 3.4.8), the reserved genesis ids, the mirror
/// and instant stamp, the size as stored, the instant binding at
/// `received_at`.
///
/// v58.0.0 (CIRISPersist#1094 item 2, CC 4.5.3) — `subject` is the scored
/// agent's CC 2.3.2.1 canonical hash
/// ([`subject_erasure::agent_subject`](super::subject_erasure::agent_subject)
/// of the trace's `agent_id_hash`, [`detection_subject`]), written into
/// `subject_key_ids`: a detection is a row ABOUT that subject, and naming it
/// makes the rows about a subject discoverable (DSAR export, the erasure
/// door's lookup). It is not an authority path: a detection is adverse, and
/// is erased only by its producer's rule-1 `withdraws` (CC 4.5.3, the 2.4.1.1
/// carve-out). `None` when the door cannot tell whose trace it scored (the
/// trace is not held here): the door never guesses a subject.
pub(crate) fn plan_detection_row(
    body: &crate::derived::detection_row::DetectionProjection,
    attester_identity_type: &str,
    subject: Option<&str>,
    instants: PlanInstants,
) -> Result<PlannedDetection, Error> {
    use crate::derived::detection_row as dr;
    use crate::federation::types::{attestation_type, cohort_scope, LocalAttestationInput};
    if let Some(reason) = dr::detection_shape_refusal(body) {
        return Err(Error::InvalidArgument(reason));
    }
    let envelope = dr::detection_envelope(body)
        .map_err(|e| Error::Backend(format!("detection envelope: {e}")))?;
    crate::federation::admission::check_envelope_size_admission(&envelope)?;
    let dimension = dr::detection_dimension(&body.detector);
    crate::federation::admission::DimensionAdmissionPolicy::default().check(
        attestation_type::SCORES,
        Some(&dimension),
        attester_identity_type,
    )?;
    let attestation_id = dr::detection_attestation_id(&body.detection_id);
    let input = LocalAttestationInput {
        attestation_id: Some(attestation_id.clone()),
        attesting_key_id: body.signing_key_id.clone(),
        attested_key_id: None,
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: None,
        expires_at: None,
        attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(envelope)?,
        subject_key_ids: subject.map(str::to_owned).into_iter().collect(),
        cohort_scope: cohort_scope::SELF.to_owned(),
        scrub_signature_classical: None,
        scrub_signature_pqc: None,
    };
    // The row's signed instant is `fold_at` (PlanInstants: "the row's signed
    // instant"): the receipt clock at a live door, the silo row's own
    // recorded instant when a pre-v57 row is rehomed (never the boot clock).
    let mut row = input.into_local_row(attestation_id, instants.fold_at);
    crate::federation::genesis::check_genesis_attestation_reserved(&row)?;
    crate::federation::envelope::RowMirror::stamp_local_row(&mut row, false)?;
    crate::federation::admission::check_envelope_size_admission(&row.attestation_envelope)?;
    crate::federation::admission::check_instant_binding(
        &row,
        instants.received_at,
        crate::federation::admission::DEFAULT_MAX_TOUCH_SKEW,
    )?;
    row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
    let projection = dr::project_detection_row(&row).ok_or_else(|| {
        Error::Backend(format!(
            "detection row {} does not project: the door built a row its own projection \
             cannot read",
            row.attestation_id
        ))
    })?;
    Ok(PlannedDetection { row, projection })
}

/// v57.0.0 (CIRISPersist#988 item 3) — a re-put of a detection whose row is
/// held: V008's verdict, over the ROW (never the projection): the same
/// `canonical_bytes` is an idempotent no-op, different bytes are a conflict,
/// and an erased detection is not re-attached (no-op, as V080's NULL bytes
/// were). A held row under the id that is not this detection's is a conflict.
pub(crate) fn detection_reput_verdict(
    held: &Attestation,
    offered: &crate::derived::detection_row::DetectionProjection,
) -> Result<(), Error> {
    let Some(stored) = crate::derived::detection_row::project_detection_row(held) else {
        return Err(Error::Conflict(format!(
            "row {} is held and is not a detection",
            held.attestation_id
        )));
    };
    if stored.detection_id != offered.detection_id {
        return Err(Error::Conflict(format!(
            "row {} holds detection {}, not {}",
            held.attestation_id, stored.detection_id, offered.detection_id
        )));
    }
    match (&stored.canonical_bytes, &offered.canonical_bytes) {
        (Some(a), Some(b)) if a != b => Err(Error::Conflict(format!(
            "detection_id {} already exists with different canonical_bytes",
            offered.detection_id
        ))),
        _ => Ok(()),
    }
}

/// v58.0.0 (CIRISPersist#1094 item 2, CC 4.5.3) — **whose detection this
/// is**: the canonical subject
/// ([`subject_erasure::agent_subject`](super::subject_erasure::agent_subject))
/// of the agent whose trace it scored, read from the trace as THIS node holds
/// it. `None` when the trace is not held (or names an agent outside the CC
/// 2.3.2.1 `{id}` production): the door never guesses a subject. One reader
/// for the live door and the legacy rehome.
///
/// # Errors
///
/// Directory reads.
pub(crate) async fn detection_subject<D>(
    dir: &D,
    trace_id: Option<&str>,
) -> Result<Option<String>, Error>
where
    D: AttestationStore,
{
    let Some(trace_id) = trace_id else {
        return Ok(None);
    };
    Ok(dir
        .trace_agent_id_hash(trace_id)
        .await?
        .and_then(|agent| super::subject_erasure::agent_subject(&agent).ok()))
}

/// v57.0.0 (CIRISPersist#988 item 3) — the door: every backend's
/// `put_detection_event` is this call. The detector's hybrid signature over
/// `canonical_bytes` is the caller's to verify (the `DerivedSchema` verify
/// boundary, unchanged); this decides and stores the row.
pub(crate) async fn put_detection_planned<D>(
    dir: &D,
    event: &crate::derived::DetectionEvent,
) -> Result<(), Error>
where
    D: AttestationStore,
{
    let received_at = chrono::Utc::now();
    dir.rehome_legacy_detection_events(received_at).await?;
    let body = crate::derived::detection_row::DetectionProjection::from(event);
    let identity_type = dir
        .attesting_identity_type(&event.signing_key_id)
        .await?
        .ok_or_else(|| Error::AttesterKeyUnknown {
            attesting_key_id: event.signing_key_id.clone(),
            plane: "detection",
        })?;
    let subject = detection_subject(dir, body.trace_id.as_deref()).await?;
    let planned = plan_detection_row(
        &body,
        &identity_type,
        subject.as_deref(),
        PlanInstants {
            fold_at: received_at,
            received_at,
        },
    )?;
    // A detection row a purge or an Art. 17 erasure tombstoned is not
    // re-admitted: the tombstone outlives the row (the purge door's TOMBSTONED
    // gate, the one the put door asks).
    crate::federation::steward_purge::refuse_if_tombstoned_attestation(dir, &planned.row).await?;
    let id = planned.row.attestation_id.clone();
    if !dir.store_planned_detection(planned).await? {
        if let Some(held) = dir.get_attestation(&id).await? {
            detection_reput_verdict(&held, &body)?;
        }
    }
    Ok(())
}
