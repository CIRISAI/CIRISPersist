//! v62.0.0 (WD-fix1; CC 2.4.1.1, CC 6.1.5 "What is unchanged" as ruled
//! 11-21: "Consent is supreme at every tier: N5 forces descent of withdrawn
//! or revoked content regardless of rarity, pin or target") — **an admitted
//! author / subject withdrawal makes the target's content descend.**
//!
//! Before this, an admitted `withdraws` kept everything: the target's
//! envelope and statement, its blob body and chunks, on every holder; the row
//! was only read as retracted (`P/WD-content-PLAN.md`). The ONE shared step,
//! [`descend`], is the subject-erasure tombstone generalized
//! (`subject_erasure::erasure_execution`'s shape, a new notice kind and
//! basis): for a `withdraws` / `recants` this node's door ADMITTED under rules
//! 1–4 ([`rule_descends`], the one table), it tombstones the target row and
//! every blob only that row bound, then finalizes (the row and its
//! projections deleted, the bytes evicted through the host's bytes plane).
//!
//! What SURVIVES, and why verification and convergence still hold:
//!
//! - the withdrawal itself (row and statement): it verifies alone, naming the
//!   target by id, never by its bytes;
//! - the target's id, as a purge tombstone (basis
//!   [`steward_purge::WITHDRAWAL_DESCENT_BASIS`], `derived_from` = the
//!   withdrawal): a late copy, a re-offer, or a blob fetched later is refused
//!   at the door, so two nodes converge on "gone";
//! - the audit leaf (append-only, a hash), and fountain manifests
//!   (`EnvelopeOnly`).
//!
//! What never descends: a COUNTED row (rule 0: one signer's retraction does
//! not undo a group's act), a rule-5 or unstamped withdrawal (held or
//! deferred: its target not held when it was admitted), and anything the
//! delete door still voids (the accountability record).
//!
//! Who runs it: the Engine, after it emits a withdrawal
//! (`Engine::after_emit`), and its sweep over the withdrawals it holds
//! (`Engine::sweep_withdrawn_content_once`) for the ones that arrived by the
//! feed. A peer never descends from a served bundle: it re-derives from the
//! withdrawal it holds itself.

use super::steward_purge::{self as sp, BytesEvictor, PurgePlane};
use super::types::{attestation_type, Attestation};
use super::{Error, FederationDirectory};

/// v62.0.0 (WD-fix1) — **the ONE rule → descends table**: which admitting
/// rule (the door's stamp, `withdraws_admission_rule`) makes the target's
/// content descend. Rules 1–4 (CC 2.4.1.1, Constitution 11-21: "author or
/// named subject → withdraws (rules 1 to 4), and the bytes descend"; "an
/// admitted withdrawal is a withdrawal whoever's hand signed it"). Rule 4,
/// the producer's delegate: per CC's rules 1 to 4; the delegate case is being
/// confirmed with Constitution (a one-line flip here). Rule 5 (the CC 3.2
/// recovery ceremony) does not.
pub const DESCENDING_RULES: &[u8] = &[1, 2, 3, 4];

/// Does a withdrawal admitted under `rule` make its target descend
/// ([`DESCENDING_RULES`])?
#[must_use]
pub fn rule_descends(rule: u8) -> bool {
    DESCENDING_RULES.contains(&rule)
}

/// [`DESCENDING_RULES`] as a SQL list (`1, 2, 3, 4`), for the delete
/// doors' twin of the lift (`steward_purge::withdrawal_descent_sql`).
#[must_use]
pub fn descending_rules_sql() -> String {
    DESCENDING_RULES
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// What [`descend`] did with one withdrawal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descent {
    /// Not a `withdraws` / `recants`, or it names no target.
    NotAWithdrawal,
    /// The withdrawal is not stored as admitted here, or carries no stamp
    /// (held, or deferred because its target was not held at admission):
    /// nothing descends.
    Unadmitted,
    /// Admitted under a rule that does not descend ([`rule_descends`]).
    RuleDoesNotDescend {
        /// The stamp.
        rule: u8,
    },
    /// The target is a counted row (rule 0): one signer's retraction does
    /// not undo a group's act.
    CountedRow,
    /// An admitted accountability record names the target
    /// ([`accountability_citation`]): readers hide it (the withdrawal
    /// retracts it on read), and nothing descends.
    CitedByAccountabilityRecord {
        /// The citing record.
        by: String,
    },
    /// [`disposition`] keeps it at `self` on this node (unreachable while
    /// every relation descends; WD-fix2 builds the keep).
    KeptAtSelf {
        /// The node's relation to the row.
        relation: NodeRelation,
    },
    /// The target's family does not descend ([`family_descends`]): a
    /// structural row (an edge, a grant, a membership) is kept and read
    /// retracted; a shapeless or unknown family is kept.
    KeptByShape {
        /// The shape, `None` for a family the table does not name.
        shape: Option<FamilyShape>,
    },
    /// No row of the target is held here (and none was descended).
    TargetNotHeld,
    /// Already descended (its execution finalized): nothing to do.
    AlreadyDescended,
    /// The target descended now (or its earlier execution was finished).
    Descended {
        /// The descent's notice id.
        notice_id: String,
        /// The finalize report.
        report: sp::FinalizeReport,
        /// The target's held statements deleted (its row statement and
        /// voices).
        statements_deleted: u64,
    },
}

/// The blob shas `row` binds: each sha its `evidence_refs` (either form) or
/// a typed pointer member names, confirmed by the ONE binding predicate the
/// bytes plane asks
/// ([`envelope_binds_content`](super::admission::envelope_binds_content):
/// a custody report binds nothing).
fn bound_shas(row: &Attestation) -> Vec<[u8; 32]> {
    let env = &row.attestation_envelope;
    let mut candidates: Vec<String> = env
        .get("evidence_refs")
        .and_then(serde_json::Value::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(super::admission::evidence_ref_hex)
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default();
    candidates.extend(super::blob_pointer::pointed_shas(env));
    let mut out: Vec<[u8; 32]> = Vec::new();
    for h in candidates {
        let mut sha = [0u8; 32];
        if hex::decode_to_slice(&h, &mut sha).is_ok()
            && !out.contains(&sha)
            && super::admission::envelope_binds_content(env, &h)
        {
            out.push(sha);
        }
    }
    out
}

/// v62.0.0 (WD-fix1) — **the ONE shared step**: make the content of the row
/// `withdraws` withdraws descend, when this node's door admitted that
/// withdrawal under a rule that descends. Idempotent and resumable: a
/// finalized descent is `AlreadyDescended`; an execution recorded but not
/// finalized (a crash, a refused byte eviction) is finished now. `bytes` is
/// the host's bytes plane (the Engine's evictor); a directory with none
/// cannot evict a blob, and its descent of a row that binds one stops at
/// `retraction_inadmissible`, the row kept, as `purge_finalize` refuses.
///
/// # Errors
/// Directory reads and writes; the finalize's refusals.
pub async fn descend<F>(
    dir: &F,
    withdraws: &Attestation,
    executed_by: &str,
    bytes: Option<&dyn BytesEvictor>,
    keep: KeepPolicy,
) -> Result<Descent, Error>
where
    F: FederationDirectory + ?Sized,
{
    if !super::edition2::emit::carries_no_dimension(&withdraws.attestation_type) {
        return Ok(Descent::NotAWithdrawal);
    }
    let Some(target_id) =
        super::precedence::references_attestation_id_from_envelope(&withdraws.attestation_envelope)
            .map(str::to_owned)
    else {
        return Ok(Descent::NotAWithdrawal);
    };
    // The STORED withdrawal and the door's own stamp: never the offered row.
    let Some(stored) = dir.get_attestation(&withdraws.attestation_id).await? else {
        return Ok(Descent::Unadmitted);
    };
    // The one accessor the retraction fold reads the stamp through.
    let Some(rule) = super::precedence::admitting_stamp(&stored) else {
        return Ok(Descent::Unadmitted);
    };
    if !rule_descends(rule) {
        return Ok(Descent::RuleDoesNotDescend { rule });
    }
    let notice_id = super::subject_erasure::descent_notice_id(&stored.attestation_id, &target_id)?;
    if let Some(e) = dir.purge_execution(&notice_id).await? {
        if e.finalized_at.is_some() {
            return Ok(Descent::AlreadyDescended);
        }
        // Resumable: an execution recorded but not finalized (a crash, a
        // refused byte eviction) is finished now, statements included.
        let report = sp::purge_finalize(dir, &notice_id, bytes).await?;
        let statements_deleted = report.statements_deleted;
        return Ok(Descent::Descended {
            notice_id,
            report,
            statements_deleted,
        });
    }
    let Some(target) = dir.get_attestation(&target_id).await? else {
        return Ok(Descent::TargetNotHeld);
    };
    // The withdraws door's own rule-0 test, never a second one.
    if super::admission::is_counted_row(&target) {
        return Ok(Descent::CountedRow);
    }
    // Re-derived against THIS node's state now, as every erasure is: the
    // stamp says the door admitted it; the gate says it still does.
    match super::admission::check_withdraws_admission_as_admitted(dir.as_dyn_directory(), &stored)
        .await
    {
        Ok(Some(r)) if rule_descends(r) => {}
        Ok(Some(r)) => return Ok(Descent::RuleDoesNotDescend { rule: r }),
        // Each refusal the re-derivation raises means "not admitted now";
        // a backend error is an error, and the sweep retries it.
        Ok(None)
        | Err(
            Error::WithdrawsNotAdmitted { .. }
            | Error::WithdrawsTargetUnheld { .. }
            | Error::OwnershipReclaimRefused { .. }
            | Error::InvalidArgument(_),
        ) => return Ok(Descent::Unadmitted),
        Err(e) => return Err(e),
    }
    // The shape decides (the lead's ruling 11-21): content and claims
    // descend; structure is kept, read retracted.
    if !row_descends(&target) {
        return Ok(Descent::KeptByShape {
            shape: shape_of(&target),
        });
    }
    // Descent is never the way an author destroys what a report cites.
    if let Some(by) = accountability_citation(dir, &target).await? {
        return Ok(Descent::CitedByAccountabilityRecord { by });
    }
    // The one switch: this node's relation to the row decides.
    let relation = node_relation(dir, executed_by, &stored, &target).await?;
    if disposition(relation, rule, keep) == Disposition::KeepAtSelf {
        return Ok(Descent::KeptAtSelf { relation });
    }
    // The bytes only this row bound: the bytes-plane fold reads them
    // `Withdrawn` now (every binding row retired). Asked before the row goes:
    // once it is deleted the fold reads them unbound.
    let mut blobs = Vec::new();
    for sha in bound_shas(&target) {
        if matches!(
            super::blob_tombstone::binding_state(dir.as_dyn_directory(), &sha).await?,
            super::blob_tombstone::BindingState::Withdrawn { .. }
        ) {
            blobs.push(hex::encode(sha));
        }
    }
    let mut records: Vec<(PurgePlane, String, Option<String>)> = vec![(
        PurgePlane::Attestation,
        target_id.clone(),
        Some(stored.attestation_id.clone()),
    )];
    for b in blobs {
        records.push((
            PurgePlane::Blob,
            b,
            Some(format!("{}:{target_id}", PurgePlane::Attestation.as_str())),
        ));
    }
    // The erasure's own builder, generalized: one shape, two bases.
    let (execution, tombstones) = super::subject_erasure::withdrawal_execution(
        &super::subject_erasure::ErasureNotice::descent(&stored.attestation_id, &target_id),
        &stored.attesting_key_id,
        sp::WITHDRAWAL_DESCENT_BASIS,
        records,
        executed_by,
        sp::origin::LOCAL,
        sp::purge_clock(),
        None,
    )?;
    dir.purge_put_execution(&execution, &tombstones).await?;
    // The finalize deletes the row, its signed statement bytes (row and
    // voices) and the bytes only it bound.
    let report = sp::purge_finalize(dir, &notice_id, bytes).await?;
    let statements_deleted = report.statements_deleted;
    tracing::info!(
        notice_id = %notice_id,
        withdraws = %stored.attestation_id,
        target = %target_id,
        rule,
        attestations_deleted = report.attestations_deleted,
        blobs_evicted = report.blobs_evicted,
        statements_deleted,
        "an admitted withdrawal's target descended (CC 6.1.5 N5)"
    );
    Ok(Descent::Descended {
        notice_id,
        report,
        statements_deleted,
    })
}

/// v62.0.0 (WD-fix1) — the row id of `statement` when it is a `withdraws` /
/// `recants` row statement, read from its own protected header (the row type,
/// `-70001`) and bytes. `None` for anything else. Nothing a peer states about
/// the row is read.
#[must_use]
pub fn withdrawal_row_id_of_statement(statement: &[u8]) -> Option<String> {
    let (protected, _) = super::edition2::liveness::statement_parts(statement)?;
    let row_type = protected
        .get_int(-70001)
        .and_then(ciris_verify_core::cde::Value::as_text)?;
    if !super::edition2::emit::carries_no_dimension(row_type) {
        return None;
    }
    Some(super::edition2::names::RowId::of_statement(statement)?.hex())
}

/// v62.0.0 (WD-fix1) — **the sweep's in-memory cursor** over this node's
/// held withdrawals, in its own admission order
/// ([`FederationDirectory::list_withdrawals_since`], served by the partial
/// index on `withdraws` / `recants`). No schema for the cursor: a restart
/// starts a fresh one, so the first ticks after a restart make ONE paged pass
/// over the held WITHDRAWALS (the scan bound: linear in the withdrawals held,
/// a page per tick), and [`descend`]'s idempotence ("done" = the target
/// tombstoned, its execution finalized) makes the rescan delete and refuse
/// nothing twice. After the pass it follows the tail: a withdrawal admitted
/// later, by any door (the Engine's or a host's directory), is reached at
/// the next tick.
#[derive(Debug, Clone, Default)]
pub struct SweepCursor {
    position: Option<(chrono::DateTime<chrono::Utc>, String)>,
    last: Option<SweepTick>,
}

/// What [`SweepCursor::state`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SweepState {
    /// No tick has run since this cursor was made (a restart).
    NotYetRun,
    /// The last tick read to the end of the held withdrawals: nothing is
    /// left to examine until more arrive.
    CaughtUp,
    /// The last tick was cut short at its page bound: run another.
    Behind,
}

impl SweepCursor {
    /// A fresh cursor (the state after a restart).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// "Not yet run", "caught up", or "behind": a host tells "nothing to
    /// do" from "not yet run" here.
    #[must_use]
    pub fn state(&self) -> SweepState {
        match &self.last {
            None => SweepState::NotYetRun,
            Some(t) if t.exhausted => SweepState::CaughtUp,
            Some(_) => SweepState::Behind,
        }
    }

    /// The last tick's report, if any ran.
    #[must_use]
    pub fn last_tick(&self) -> Option<&SweepTick> {
        self.last.as_ref()
    }
}

/// One tick of the sweep.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepTick {
    /// Withdrawals read this tick.
    pub examined: u32,
    /// Of them, the ones whose target descended this tick.
    pub descended: u32,
    /// Of them, the ones whose descent a purge refusal stopped (logged; the
    /// recorded execution is finished by a later pass).
    pub refused: u32,
    /// `true` when the tick read to the end of the held withdrawals;
    /// `false` when it was cut short at its page bound.
    pub exhausted: bool,
}

/// The most withdrawals one tick reads.
pub const MAX_SWEEP_PAGE: u32 = 1000;

tokio::task_local! {
    /// v62.0.0 (WD-fix3 rev 2) — the bytes plane a door's caller supplies
    /// for the descent the door runs in its own admission
    /// ([`with_door_bytes`]): the Engine's, which also retracts this node's
    /// holding claims.
    static DOOR_BYTES: std::sync::Arc<dyn BytesEvictor>;
}

/// v62.0.0 (WD-fix3 rev 2) — run a statement door with `bytes` as the bytes
/// plane of the descent it runs in its own admission
/// ([`descend_at_admission`]). A door run outside it uses its directory's
/// own ([`FederationDirectory::withdrawn_bytes_evictor`]).
pub async fn with_door_bytes<T, Fut>(bytes: std::sync::Arc<dyn BytesEvictor>, fut: Fut) -> T
where
    Fut: std::future::Future<Output = T>,
{
    DOOR_BYTES.scope(bytes, fut).await
}

/// v62.0.0 (WD-fix3 rev 2; CC 6.1.5 N5) — **THE descent step of a door's
/// admission**, called from the one place every row admission passes through
/// (`edition2::ingest::put_admitted_row`: the statement door, local or
/// replicated, the capsule's ops on the host's store, the server's ingest,
/// and the fold's re-conclusions). Runs before the door returns:
///
/// - the admitted row is a `withdraws` / `recants`: its target descends
///   ([`descend`]);
/// - any other row: each held `withdraws` / `recants` naming it descends it.
///   This is the withdrawal-first order: a withdrawal whose target is not
///   held waits `link_unheld`, is stamped when the target's arrival re-folds
///   it (that re-conclusion passes here, so the first arm descends it), and
///   a target admitted after a withdrawal already stamped (a re-offer, an
///   alias) descends here.
///
/// The executor is this node (`node_key_id`, empty when the host set none),
/// the bytes plane the door's caller supplied ([`with_door_bytes`]) or the
/// directory's own, the keep policy the default. Never fails the door: the
/// row is admitted; a failure is logged, and an unfinished descent is
/// finished at the next open or `sweep_consent_decay_once`. Isolated from
/// the admission's fold attempt, so its reads mark nothing on the row.
pub async fn descend_at_admission<F>(dir: &F, row_id: &str)
where
    F: FederationDirectory + ?Sized,
{
    let door_bytes = DOOR_BYTES.try_with(std::sync::Arc::clone).ok();
    let bytes: Option<&dyn BytesEvictor> = match &door_bytes {
        Some(b) => Some(b.as_ref()),
        None => dir.withdrawn_bytes_evictor(),
    };
    let executed_by = dir.node_key_id().unwrap_or_default();
    let keep = KeepPolicy::default();
    let result = super::edition2::fold::isolated(async {
        let Some(row) = dir.get_attestation(row_id).await? else {
            return Ok::<u32, Error>(0);
        };
        let mut withdrawals = Vec::new();
        if row.attestation_type == attestation_type::WITHDRAWS
            || row.attestation_type == attestation_type::RECANTS
        {
            withdrawals.push(row);
        } else {
            let named = row.attestation_id.clone();
            for w in dir
                .list_composers_referencing_any(std::slice::from_ref(&named), None, None)
                .await?
            {
                if (w.attestation_type == attestation_type::WITHDRAWS
                    || w.attestation_type == attestation_type::RECANTS)
                    && super::precedence::references_attestation_id_from_envelope(
                        &w.attestation_envelope,
                    ) == Some(named.as_str())
                {
                    withdrawals.push(w);
                }
            }
        }
        let mut descended = 0;
        for w in &withdrawals {
            if let Descent::Descended { .. } = descend(dir, w, &executed_by, bytes, keep).await? {
                descended += 1;
            }
        }
        Ok(descended)
    })
    .await;
    if let Err(e) = result {
        tracing::warn!(
            row_id,
            error = %e,
            "the door's descent step did not finish; the next open or sweep_consent_decay_once \
             finishes it"
        );
    }
}

/// v62.0.0 (WD-fix3 rev 2) — **one full pass** over the held withdrawals
/// from a fresh cursor, each through [`descend`]: what a door left
/// unfinished is finished, a finished one is `AlreadyDescended`. The
/// descents made. A purge refusal is counted by the tick and left for the
/// next pass. Called at open and by the host-called
/// `sweep_consent_decay_once` (`Engine::descend_withdrawn_content_pending`).
///
/// # Errors
/// Directory reads and writes.
pub async fn descend_pending<F>(
    dir: &F,
    executed_by: &str,
    bytes: Option<&dyn BytesEvictor>,
    keep: KeepPolicy,
) -> Result<u64, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut cursor = SweepCursor::new();
    let mut descended = 0u64;
    loop {
        let tick = sweep_tick(dir, &mut cursor, executed_by, bytes, keep, MAX_SWEEP_PAGE).await?;
        descended += u64::from(tick.descended);
        if tick.exhausted {
            return Ok(descended);
        }
    }
}

/// v62.0.0 (WD-fix1) — **one bounded tick of the sweep**: at most `page`
/// held withdrawals after `cursor` (clamped to [`MAX_SWEEP_PAGE`]), each
/// through [`descend`]. The cursor advances past a withdrawal only once it is
/// done; a backend error returns with the cursor at the last one finished,
/// so the next tick resumes there. A purge refusal is not a backend error: it
/// is logged and counted, and the cursor moves on.
///
/// # Errors
/// Directory reads and writes.
pub async fn sweep_tick<F>(
    dir: &F,
    cursor: &mut SweepCursor,
    executed_by: &str,
    bytes: Option<&dyn BytesEvictor>,
    keep: KeepPolicy,
    page: u32,
) -> Result<SweepTick, Error>
where
    F: FederationDirectory + ?Sized,
{
    let page = page.clamp(1, MAX_SWEEP_PAGE);
    let held = dir
        .list_withdrawals_since(cursor.position.clone(), page)
        .await?;
    let mut tick = SweepTick {
        exhausted: (held.len() as u64) < u64::from(page),
        ..SweepTick::default()
    };
    for w in held {
        tick.examined += 1;
        match descend(dir, &w.attestation, executed_by, bytes, keep).await {
            Ok(Descent::Descended { .. }) => tick.descended += 1,
            Ok(_) => {}
            Err(Error::PurgeRefused { token, .. }) => {
                tick.refused += 1;
                tracing::warn!(
                    withdraws = %w.attestation.attestation_id,
                    token,
                    "withdrawn-content sweep: the descent was refused; a later pass finishes it"
                );
            }
            Err(e) => {
                cursor.last = Some(SweepTick {
                    exhausted: false,
                    ..tick
                });
                return Err(e);
            }
        }
        cursor.position = Some((w.admitted_at, w.attestation.attestation_id.clone()));
    }
    cursor.last = Some(tick);
    Ok(tick)
}

// ── the accountability trail's reach (Constitution 11-21, via the lead) ──

/// v62.0.0 (WD-fix1) — **the admitted accountability record that NAMES
/// `target`**, if any: descent must not be the way an author destroys what
/// a report already cites. A held row whose family is on the one
/// accountability list
/// ([`ACCOUNTABILITY_RECORD_PREFIXES`](super::migration::ACCOUNTABILITY_RECORD_PREFIXES):
/// `moderation:*` reports, `hard_case:*` (a `hard_case:legal_hold` among
/// them), `slashing:*` verdicts, `revocation:*`) that names the target by
/// any of the three ways a row names another:
///
/// - its `references_attestation_id` (a composer or filing naming the row);
/// - its `attested_key_id` (what a hard case is against);
/// - the target's bytes, through the bytes plane's own binding read (a
///   report citing the content by `content_sha256` / `evidence_refs`).
///
/// Asked of THIS node's store: a peer holding the report keeps the row too.
///
/// # Errors
/// Directory reads.
pub async fn accountability_citation<F>(
    dir: &F,
    target: &Attestation,
) -> Result<Option<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let cites = |r: &Attestation| {
        r.attestation_id != target.attestation_id && sp::accountability_record_of(r).is_some()
    };
    for r in dir
        .list_attestations_referencing(&target.attestation_id)
        .await?
    {
        if cites(&r) {
            return Ok(Some(r.attestation_id));
        }
    }
    let mut pages = super::attestation_query::AttestationQuery::to(
        &target.attestation_id,
        super::attestation_query::FOLD_PAGE,
    )
    .pages();
    while let Some(page) = pages.next(dir).await? {
        if let Some(r) = page.iter().find(|r| cites(r)) {
            return Ok(Some(r.attestation_id.clone()));
        }
    }
    for sha in bound_shas(target) {
        for r in dir.attestations_binding_content(&hex::encode(sha)).await? {
            if cites(&r) {
                return Ok(Some(r.attestation_id));
            }
        }
    }
    Ok(None)
}

// ── the one switch: does the content descend on THIS node ──────────────

/// v62.0.0 (WD-fix1; FS-step1) — **the SHAPE of a row family**, read from
/// the one family table (`family_model.json` `shape`, CC 6.1.5): claim,
/// content, consent, door, consent+door, or none fits.
pub use crate::federation::namespace::family_table::Shape as FamilyShape;

/// The shape of the family whose family id (header -70002, Verify's
/// [`family_id`](ciris_verify_core::namespace_match::family_id) spelling)
/// is `family_id`; `None` for a family the table does not name.
#[must_use]
pub fn shape_of_family_id(family_id: &str) -> Option<FamilyShape> {
    crate::federation::namespace::family_table::table()
        .by_family_id(family_id)
        .map(|r| r.shape)
}

/// The shape of a held row: its edition-2 statement's family (header
/// -70002). `None` for a row carrying no edition-2 statement or a family
/// the table does not name.
#[must_use]
pub fn shape_of(row: &Attestation) -> Option<FamilyShape> {
    let st = super::edition2::emit::carried_statement(row)?;
    let (family, _) = super::edition2::emit::family_of_statement(&st)?;
    shape_of_family_id(&family)
}

/// v62.0.0 (WD-fix1; FS-step1) — **the ONE family → descends decision**
/// (beside [`rule_descends`]), read from the family table's
/// `descends_on_withdrawal` (CC 6.1.5): a claim descends as its row
/// (`row`), content as its words and the bytes it bound (`bytes_and_words`,
/// when no live row still binds them); structure (consent, door,
/// consent+door) and a shapeless family are kept and read retracted
/// (`nothing`), since acts taken under them are judged as of their own
/// instant against them. A family the table does not name does not descend.
///
/// The mixed case (a structural row carrying free words, `body.note`) keeps
/// the structure whole: persist's producer blinds no member, so no held
/// statement can drop its words and still verify (see the .md).
#[must_use]
pub fn family_descends(family_id: &str) -> bool {
    use crate::federation::namespace::family_table::{table, WithdrawalDescent};
    table()
        .by_family_id(family_id)
        .is_some_and(|r| r.descends_on_withdrawal != WithdrawalDescent::Nothing)
}

/// [`family_descends`] for a held row (its edition-2 statement's family);
/// `false` for a row carrying no statement.
#[must_use]
pub fn row_descends(row: &Attestation) -> bool {
    super::edition2::emit::carried_statement(row)
        .and_then(|st| super::edition2::emit::family_of_statement(&st))
        .is_some_and(|(family, _)| family_descends(&family))
}

/// v62.0.0 (WD-fix1) — this node's relation to a withdrawn row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeRelation {
    /// The node's owner is the withdrawal's signer (the same consenting
    /// party: the key, or another device of the same person).
    SignersOwnNode,
    /// The node's owner is a party the row names (a subject).
    NamedPartysOwnNode,
    /// Any other holder.
    OtherHolder,
}

/// What [`disposition`] decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// The content descends here.
    Descend,
    /// The node keeps the row and its withdrawal together at `self` scope,
    /// served to no one, counting toward nothing, giving way to every duty
    /// to delete (CC 2.4.1.1 "What the signer keeps", "What a named party
    /// keeps"; WD-fix2 builds the copy).
    KeepAtSelf,
}

/// v62.0.0 (WD-fix1) — **the node's keep opt-in**: node configuration the
/// host sets when it opens the Engine, read before any descent. Both
/// `false` (descend) by default; WD-fix2 adds the setter and the copy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KeepPolicy {
    /// The signer's own node keeps what its owner withdrew.
    pub signer_keeps: bool,
    /// A named party's own node keeps a row about its owner that the
    /// SIGNER withdrew.
    pub named_party_keeps: bool,
}

/// v62.0.0 (WD-fix1; CC 2.4.1.1 rc22 d1217ec, "one copy rule for both") —
/// **THE one switchable place**: does the content descend on a node with
/// this relation to the row, this node's opt-in, under a withdrawal
/// admitted by `rule`? The signer's keep and the named party's keep are the
/// same rule with a different test for who may opt in: the named party only
/// where the SIGNER withdrew (rule 1, or a rule-4 delegate acting for the
/// signer); where the party withdrew it themselves (rules 2, 3) they asked
/// for it gone.
#[must_use]
pub fn disposition(relation: NodeRelation, rule: u8, policy: KeepPolicy) -> Disposition {
    let may_keep = match relation {
        NodeRelation::SignersOwnNode => policy.signer_keeps,
        NodeRelation::NamedPartysOwnNode => policy.named_party_keeps && matches!(rule, 1 | 4),
        NodeRelation::OtherHolder => false,
    };
    if may_keep {
        Disposition::KeepAtSelf
    } else {
        Disposition::Descend
    }
}

/// v62.0.0 (WD-fix1) — **how this node knows its relation**: the node's
/// owner by the owner binding ([`owner_of_unmarked`](super::admission::owner_of_unmarked):
/// counted only when the node cosigned it; an ambiguous owner is no owner),
/// then the same test the withdrawal door asks of a signer
/// ([`same_consenting_party`](super::membership_acceptance::same_consenting_party)),
/// against the withdrawal's signer, then against each of the row's subjects.
///
/// # Errors
/// Directory reads.
pub async fn node_relation<F>(
    dir: &F,
    node: &str,
    withdraws: &Attestation,
    target: &Attestation,
) -> Result<NodeRelation, Error>
where
    F: FederationDirectory + ?Sized,
{
    let owner = match super::admission::owner_of_unmarked(dir, node).await {
        Ok(o) => o,
        Err(Error::AmbiguousNodeOwner { .. }) => None,
        Err(e) => return Err(e),
    };
    let Some(owner) = owner else {
        return Ok(NodeRelation::OtherHolder);
    };
    if super::membership_acceptance::same_consenting_party(dir, &owner, &withdraws.attesting_key_id)
        .await?
    {
        return Ok(NodeRelation::SignersOwnNode);
    }
    for subject in sp::attestation_subjects(target) {
        if super::membership_acceptance::same_consenting_party(dir, &owner, &subject).await? {
            return Ok(NodeRelation::NamedPartysOwnNode);
        }
    }
    Ok(NodeRelation::OtherHolder)
}

// ── what a host reads by id ─────────────────────────────────────────────

/// v62.0.0 (WD-fix1) — **a row id as this node holds it**, a NAMED state
/// rather than an ambiguous absence: `get_attestation` answers `None` for a
/// descended row exactly as for one never seen, so a host that reads by id
/// asks this.
#[derive(Debug, Clone, PartialEq)]
pub enum HeldRowState {
    /// The row is held.
    Held(Box<Attestation>),
    /// The row descended under an admitted withdrawal: its id stays as a
    /// tombstone; the withdrawal is held and verifies alone.
    Withdrawn {
        /// The withdrawal.
        withdraws_attestation_id: String,
        /// The descent's notice.
        notice_id: String,
    },
    /// The row was purged under another basis (a steward purge, a takedown,
    /// a producer's erasure).
    Purged {
        /// The notice.
        notice_id: String,
        /// Its `legal_basis`.
        legal_basis: String,
    },
    /// Not held, and no tombstone names it.
    NotHeld,
}

/// [`HeldRowState`] of `id`.
///
/// # Errors
/// Directory reads.
pub async fn held_row_state<F>(dir: &F, id: &str) -> Result<HeldRowState, Error>
where
    F: FederationDirectory + ?Sized,
{
    if let Some(row) = dir.get_attestation(id).await? {
        return Ok(HeldRowState::Held(Box::new(row)));
    }
    let mut purged: Option<HeldRowState> = None;
    for notice_id in dir
        .purge_tombstone_notices(PurgePlane::Attestation.as_str(), id)
        .await?
    {
        let Some(e) = dir.purge_execution(&notice_id).await? else {
            continue;
        };
        if e.legal_basis == sp::WITHDRAWAL_DESCENT_BASIS {
            let withdraws = dir
                .purge_tombstones_of(&notice_id)
                .await?
                .into_iter()
                .find(|t| t.plane == PurgePlane::Attestation && t.record_ref == id)
                .and_then(|t| t.derived_from)
                .unwrap_or_default();
            return Ok(HeldRowState::Withdrawn {
                withdraws_attestation_id: withdraws,
                notice_id,
            });
        }
        purged.get_or_insert(HeldRowState::Purged {
            notice_id,
            legal_basis: e.legal_basis,
        });
    }
    Ok(purged.unwrap_or(HeldRowState::NotHeld))
}
