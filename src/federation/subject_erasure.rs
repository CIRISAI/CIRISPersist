//! v58.0.0 (CIRISPersist#1094 item 2; CC 4.5.3 "Erasure at the subject's
//! request", CLM-erasure-subject-route; CIRISConstitution#174) — **an adverse
//! row about a subject is erased by its PRODUCER, and the replicated fact is
//! the tombstone.**
//!
//! v57.0.0 hard-deleted an erased trace's signed `detection:*` rows under a
//! node-local purge basis (`art17_erasure`) whose notice was the erasure's own
//! `hard_case:trace_erasure:v1` row: a basis outside CIRISConstitution#165, a
//! header never served (so a peer holding a replica kept it), and a hard case
//! naming the erased subject. The steward's ruling (2026-10-15, the
//! controller-only reading of CC 4.5.3; `formal/withdraws_admission`) replaces
//! all three:
//!
//! - **Authority.** A `detection:*` row is ADVERSE (CC 2.4.1.1's carve-out:
//!   `capacity:*`, `detection:*`, `licensure:*`, `revocation:*`): no
//!   subject-authority path (rules 2–4) reaches it, and none is added here.
//!   The subject's Article 17 request is executed by the row's PRODUCER under
//!   rule 1 — the data controller withdrawing its own row. The DSAR door plans
//!   that `withdraws` as the producer's row (attester = the detector key that
//!   signed the detection, held by the host; its signature deferred to the
//!   crossing exactly as the detection row's own is) through the ordinary
//!   local door, and asks the ONE withdraws predicate
//!   (`admission::check_withdraws_admission_at`) to admit it as rule 1
//!   ([`plan_store_erasure`]). Where the host does not hold the producer's key
//!   the row is refused with a reason ([`ErasureRefusal`], CC 4.4
//!   `erasure_policy`'s refused-with-reason shape, GDPR Art. 17(3)) and
//!   reported in the summary — never skipped silently.
//! - **The replicated fact.** Each erased row leaves one tombstone by digest
//!   on the attestation plane, under a header whose notice is
//!   [`ErasureNotice`] — `{withdraws, target}` ids, nothing else — and whose
//!   `legal_basis` column is [`WITHDRAWS_AUTHORITY`]. That header is the
//!   node's informational ledger entry: never a notice of its own, never a
//!   basis; the authority it cites is the producer's withdraws, which a peer
//!   re-derives against ITS OWN state ([`apply_replicated_erasure`]). The
//!   header IS served (`list_purge_bundles_since`).
//! - **The subject is named, not empowered.** A detection row names the
//!   scored agent's canonical subject ([`agent_subject`]) so rows about the
//!   subject are discoverable (DSAR export, the door's own lookup); it is not
//!   an authority path.
//! - **The hard case names nobody** (`hard_case::trace_erasure_event`).
//!
//! The trace corpus (`trace_events`, `trace_llm_calls`) is not on the
//! attestation plane and is hard-deleted by the DSAR door as before. The door
//! touches no ORDINARY row about the subject; such a row is erased by the
//! subject's own withdraws (rule 2, or rule 3 through a consent_revocation
//! proxy chain), unchanged.

use serde::{Deserialize, Serialize};
use sha2::Digest as _;

use super::steward_purge::{self as sp, origin, PurgeExecution, PurgePlane, PurgeTombstone};
use super::types::{attestation_type, Attestation};
use super::{Error, FederationDirectory};

/// The CC 2.3.2.1 `{platform}` of an agent subject: this federation.
pub const AGENT_SUBJECT_PLATFORM: &str = "ciris";
/// The CC 2.3.2.1 `{entity_kind}` of an agent subject.
pub const AGENT_SUBJECT_ENTITY_KIND: &str = "agent";

/// The `legal_basis` column of an erasure's tombstone header. Not a purge
/// basis (CC 4.5.3: "there is no node-local purge basis for erasure"): the
/// column names what authorised the tombstone, and for an erasure that is the
/// subject's `withdraws`, cited by the header's [`ErasureNotice`]. Settles at
/// execution: an erased row is destroyed on receipt, never after a dwell.
pub const WITHDRAWS_AUTHORITY: &str = "withdraws";

/// The `kind` member of an [`ErasureNotice`].
pub const NOTICE_KIND: &str = "subject_erasure";

/// The closed set of refusal tokens the erasure raises, each the
/// [`Error::kind`] of an [`Error::PurgeRefused`] (the one tombstone plane's
/// error).
pub mod token {
    /// A replicated erasure whose withdraws this node does not hold yet: the
    /// authority is the withdraws row, and it has not replicated here.
    /// RETRYABLE. Body: `{notice_id, withdraws_attestation_id, retryable}`.
    pub const WITHDRAWS_UNHELD: &str = "subject_erasure_withdraws_unheld";
    /// A replicated erasure whose cited row is not the target's PRODUCER's
    /// `withdraws` admitted by this node's own gate as rule 1, or whose bundle
    /// names anything but the one target on the attestation plane. Body:
    /// `{notice_id, reason}`.
    pub const UNAUTHORISED: &str = "subject_erasure_unauthorised";
    /// A row's erasure is refused: the host does not hold a live record of
    /// the row's producer key, so the producer cannot withdraw it (CC 4.5.3:
    /// "refused with reason under Article 17(3)"). Carried per row in
    /// [`super::ErasureRefusal::reason`], never raised as an error.
    pub const PRODUCER_KEY_NOT_HELD: &str = "erasure_producer_key_not_held";
    /// Every token.
    pub const ALL: &[&str] = &[WITHDRAWS_UNHELD, UNAUTHORISED, PRODUCER_KEY_NOT_HELD];
}

/// The CC 2.3.2.1 tagged canonical hash naming the agent `agent_id_hash` as a
/// subject: `canonical:sha256:{hex}` over the preimage
/// `ciris:agent:{agent_id_hash}`, hashed exactly (P1: no normalization). The
/// `{id}` production is checked, never repaired.
///
/// # Errors
///
/// [`Error::InvalidArgument`] for an `agent_id_hash` outside the CC 2.3.2.1
/// `{id}` production (empty, a control character, U+FEFF, or leading /
/// trailing whitespace).
pub fn agent_subject(agent_id_hash: &str) -> Result<String, Error> {
    let bad = agent_id_hash.is_empty()
        || agent_id_hash
            .chars()
            .any(|c| c.is_control() || c == '\u{FEFF}' || ('\u{7F}'..='\u{9F}').contains(&c))
        || agent_id_hash.starts_with(char::is_whitespace)
        || agent_id_hash.ends_with(char::is_whitespace);
    if bad {
        return Err(Error::InvalidArgument(format!(
            "agent_id_hash {agent_id_hash:?} is outside the CC 2.3.2.1 {{id}} production; it \
             cannot name a canonical subject"
        )));
    }
    let preimage = format!("{AGENT_SUBJECT_PLATFORM}:{AGENT_SUBJECT_ENTITY_KIND}:{agent_id_hash}");
    Ok(format!(
        "{}{}",
        super::admission::CANONICAL_KEY_ID_PREFIX,
        hex::encode(sha2::Sha256::digest(preimage.as_bytes()))
    ))
}

/// The notice an erasure's tombstone header cites: the subject's `withdraws`
/// and the row it erased, by id. No subject, no content. Its JCS is the
/// header's `notice_jcs`, so `notice_id = sha256(JCS)` is the same on every
/// node that records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErasureNotice {
    /// Always [`NOTICE_KIND`].
    pub kind: String,
    /// The subject's `withdraws` row.
    pub withdraws_attestation_id: String,
    /// The erased row.
    pub target_attestation_id: String,
}

impl ErasureNotice {
    /// The notice for `withdraws` erasing `target`.
    #[must_use]
    pub fn new(withdraws_attestation_id: &str, target_attestation_id: &str) -> Self {
        Self {
            kind: NOTICE_KIND.to_owned(),
            withdraws_attestation_id: withdraws_attestation_id.to_owned(),
            target_attestation_id: target_attestation_id.to_owned(),
        }
    }

    /// `(notice_jcs, notice_id)`.
    ///
    /// # Errors
    ///
    /// The notice does not canonicalize (unreachable for this shape).
    pub fn jcs_and_id(&self) -> Result<(String, String), Error> {
        let value = serde_json::to_value(self)
            .map_err(|e| Error::Backend(format!("erasure notice: {e}")))?;
        let jcs = String::from_utf8(super::attestation_emit::canonicalize(&value)?)
            .map_err(|e| Error::Backend(format!("erasure notice jcs: {e}")))?;
        let id = hex::encode(sha2::Sha256::digest(jcs.as_bytes()));
        Ok((jcs, id))
    }

    /// The notice `envelope` is, when it is one.
    #[must_use]
    pub fn parse(envelope: &serde_json::Value) -> Option<Self> {
        serde_json::from_value::<Self>(envelope.clone())
            .ok()
            .filter(|n| n.kind == NOTICE_KIND)
    }
}

/// Is `envelope` an [`ErasureNotice`]? The Engine's replicated-bundle
/// dispatch asks this before the steward purge's own verification.
#[must_use]
pub fn is_erasure_notice_envelope(envelope: &serde_json::Value) -> bool {
    ErasureNotice::parse(envelope).is_some()
}

/// One erasure the store may execute: `target` erased under `withdraws`.
#[derive(Debug, Clone)]
pub struct ErasureCitation {
    /// The erased row's id.
    pub target: String,
    /// The subject's admitted `withdraws` of it.
    pub withdraws: Attestation,
}

/// The tombstone header and its one tombstone for `citation`, executed by
/// `executed_by` at `at` (`origin`: [`origin::LOCAL`] for this node's erasure,
/// [`origin::REPLICATED`] for a peer's). `finalized_at` is `Some(at)` when the
/// row is deleted in the same transaction.
///
/// # Errors
///
/// The notice does not canonicalize.
pub fn erasure_execution(
    citation: &ErasureCitation,
    executed_by: &str,
    origin: &str,
    at: chrono::DateTime<chrono::Utc>,
    finalized_at: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(PurgeExecution, PurgeTombstone), Error> {
    let (notice_jcs, notice_id) =
        ErasureNotice::new(&citation.withdraws.attestation_id, &citation.target).jcs_and_id()?;
    let record_id = format!("{}:{}", PurgePlane::Attestation.as_str(), citation.target);
    let execution = PurgeExecution {
        notice_id: notice_id.clone(),
        selection_digest: sp::selection_digest(&[record_id]),
        claimant_key_id: citation.withdraws.attesting_key_id.clone(),
        legal_basis: WITHDRAWS_AUTHORITY.to_owned(),
        record_count: 1,
        notice_jcs,
        cosignatures_json: "[]".to_owned(),
        executed_by: executed_by.to_owned(),
        origin: origin.to_owned(),
        executed_at: at,
        admitted_at: at,
        finalized_at,
    };
    let tombstone = PurgeTombstone {
        notice_id,
        ordinal: 0,
        plane: PurgePlane::Attestation,
        record_ref: citation.target.clone(),
        derived_from: None,
    };
    Ok((execution, tombstone))
}

/// **The authority, re-derived**: the first `withdraws` naming `target`
/// that its PRODUCER (`target.attesting_key_id`) issued and THIS node's own
/// `withdraws` gate admits as rule 1 — `check_withdraws_admission_as_admitted`,
/// the read-time form of the one predicate. Rules 2–4 never reach an adverse
/// row (the CC 2.4.1.1 carve-out); the producer's owner lift (also recorded as
/// rule 1) is not the producer. A stored rule is never read.
///
/// # Errors
///
/// Directory reads.
pub async fn erasing_withdraws<F>(
    directory: &F,
    target: &Attestation,
) -> Result<Option<Attestation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut referencing = directory
        .list_attestations_referencing(&target.attestation_id)
        .await?;
    referencing.sort_by(|a, b| a.attestation_id.cmp(&b.attestation_id));
    for w in referencing {
        if w.attestation_type != attestation_type::WITHDRAWS
            || w.attesting_key_id != target.attesting_key_id
            || super::precedence::references_attestation_id_from_envelope(&w.attestation_envelope)
                != Some(target.attestation_id.as_str())
        {
            continue;
        }
        let dir = directory.as_dyn_directory();
        match super::admission::check_withdraws_admission_as_admitted(dir, &w).await {
            Ok(Some(1)) => return Ok(Some(w)),
            Ok(_) | Err(Error::WithdrawsNotAdmitted { .. }) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// One row the erasure refused, and why: CC 4.4 `erasure_policy`'s
/// refused-with-reason shape (GDPR Art. 17(3)). `reason` is a [`token`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErasureRefusal {
    /// `attestation:{id}` — the row, by its plane identifier.
    pub record_id: String,
    /// Why it was not erased.
    pub reason: String,
}

/// The store door's decision: what it erases, the producer `withdraws` rows it
/// writes first, and what it refuses.
#[derive(Debug, Clone, Default)]
pub(crate) struct ErasurePlan {
    /// Rows erased, each under its producer's `withdraws`.
    pub(crate) citations: Vec<ErasureCitation>,
    /// The planned producer `withdraws` rows the door stores in its
    /// transaction (a citation whose withdraws was already held has none).
    pub(crate) new_withdraws: Vec<PlannedErasureWithdraws>,
    /// Rows refused with a reason.
    pub(crate) refused: Vec<ErasureRefusal>,
}

/// v58.0.0 (CIRISPersist#1094 item 2) — **the store door's decision, read
/// before its transaction**, once for all three backends. Every `detection:*`
/// row a DSAR erasure of `agent_id_hash` reaches (one signing key's traces
/// when `signing_key_id` is given) is either:
///
/// - **cited** under its producer's admitted rule-1 `withdraws` — one already
///   held, or one planned now: the producer's local-tier row (attester = the
///   detector key, signature deferred to the crossing as the detection's own
///   is) through the ordinary local door (`plan_write_local_attestation`), and
///   admitted as rule 1 by `check_withdraws_admission_at`, the one predicate;
/// - or **refused** with a reason when the host holds no live record of the
///   producer key ([`token::PRODUCER_KEY_NOT_HELD`]).
///
/// # Errors
///
/// A planned withdraws the gate does not admit as rule 1 (it would be the
/// door forging an authority); directory reads.
pub(crate) async fn plan_store_erasure<D>(
    dir: &D,
    agent_id_hash: &str,
    signing_key_id: Option<&str>,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<ErasurePlan, Error>
where
    D: super::attestation_admit::AttestationStore,
{
    let mut plan = ErasurePlan::default();
    for id in dir
        .detection_row_ids_for_agent(agent_id_hash, signing_key_id)
        .await?
    {
        let Some(target) = dir.get_attestation(&id).await? else {
            continue;
        };
        if let Some(withdraws) = erasing_withdraws(dir, &target).await? {
            plan.citations.push(ErasureCitation {
                target: id,
                withdraws,
            });
            continue;
        }
        if !producer_key_held(dir, &target.attesting_key_id, at).await? {
            plan.refused.push(ErasureRefusal {
                record_id: format!("{}:{id}", PurgePlane::Attestation.as_str()),
                reason: token::PRODUCER_KEY_NOT_HELD.to_owned(),
            });
            continue;
        }
        let planned = plan_producer_withdraws(dir, &target, at).await?;
        plan.citations.push(ErasureCitation {
            target: id,
            withdraws: planned.row.clone(),
        });
        plan.new_withdraws.push(planned);
    }
    if !plan.refused.is_empty() {
        tracing::warn!(
            refused = plan.refused.len(),
            "DSAR erasure: rows refused with reason (the host holds no live producer key; CC \
             4.5.3, GDPR Art. 17(3))"
        );
    }
    Ok(plan)
}

/// Does the host hold a live record of `key` (present, not expired at `at`)?
async fn producer_key_held<F>(
    dir: &F,
    key: &str,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    Ok(dir
        .lookup_public_key(key)
        .await?
        .is_some_and(|k| k.valid_until.is_none_or(|u| u > at)))
}

/// A planned producer `withdraws`: the local-tier row, exactly as stored, and
/// the delegation depth its admission walked (V157).
#[derive(Debug, Clone)]
pub(crate) struct PlannedErasureWithdraws {
    /// The row: attester = the producer, signature deferred, rule 1 stamped.
    pub(crate) row: Attestation,
    /// The depth recorded beside it.
    pub(crate) depth: usize,
}

/// The producer's `withdraws` of `target`, planned the way the detection door
/// plans the detection row itself (`attestation_admit::plan_detection_row`):
/// a local-tier `self` row attested by the producer key the host holds, its
/// signature deferred to the crossing; the reserved-id, mirror, size and
/// instant gates; the attested-subject rule; then admitted as RULE 1 by the
/// one withdraws predicate (`check_withdraws_admission_at`) — anything else is
/// an error, never a row.
async fn plan_producer_withdraws<D>(
    dir: &D,
    target: &Attestation,
    at: chrono::DateTime<chrono::Utc>,
) -> Result<PlannedErasureWithdraws, Error>
where
    D: super::attestation_admit::AttestationStore,
{
    let envelope =
        super::withdraws_attestation_envelope(&target.attestation_id, &target.attestation_type);
    super::admission::check_envelope_size_admission(&envelope)?;
    let attestation_id = uuid::Uuid::new_v4().to_string();
    let input = super::types::LocalAttestationInput {
        attestation_id: Some(attestation_id.clone()),
        attesting_key_id: target.attesting_key_id.clone(),
        attested_key_id: None,
        attestation_type: attestation_type::WITHDRAWS.to_owned(),
        weight: None,
        expires_at: None,
        attestation_envelope: super::envelope::EnvelopeCore::from_value(envelope)?,
        subject_key_ids: Vec::new(),
        cohort_scope: super::types::cohort_scope::SELF.to_owned(),
        scrub_signature_classical: None,
        scrub_signature_pqc: None,
    };
    super::admission::check_local_tier_eligibility(
        &input.attestation_type,
        None,
        &input.attesting_key_id,
        &input.subject_key_ids,
        &input.cohort_scope,
    )?;
    super::admission::check_attested_subject_admission(dir, &target.attesting_key_id).await?;
    let mut row = input.into_local_row(attestation_id, at);
    super::genesis::check_genesis_attestation_reserved(&row)?;
    super::envelope::RowMirror::stamp_local_row(&mut row, false)?;
    super::admission::check_envelope_size_admission(&row.attestation_envelope)?;
    super::admission::check_instant_binding(&row, at, super::admission::DEFAULT_MAX_TOUCH_SKEW)?;
    let depth = dir.withdraws_delegation_depth();
    match super::admission::check_withdraws_admission_at(dir.as_dyn_directory(), &row, depth)
        .await?
    {
        Some(1) => {}
        other => {
            return Err(Error::Backend(format!(
                "the producer's withdraws of {} was admitted as {other:?}, not rule 1",
                target.attestation_id
            )))
        }
    }
    // Like every local row, the stored rule stays unset: authority is
    // re-derived on read (`erasing_withdraws`), never read from the column.
    row.persist_row_hash = super::types::compute_persist_row_hash(&row)?;
    Ok(PlannedErasureWithdraws { row, depth })
}

/// **Apply a peer's erasure tombstone** (a
/// [`PurgeBundle`](super::steward_purge::PurgeBundle) whose notice is an
/// [`ErasureNotice`]). The receiver trusts nothing the sender says: the
/// bundle must name exactly the notice's target on the attestation plane;
/// the cited `withdraws` must be held HERE (it replicates as any row does;
/// until it has, [`token::WITHDRAWS_UNHELD`], retryable), be the target's
/// PRODUCER's, name the target, and be admitted by THIS node's own `withdraws`
/// gate as rule 1 — which needs the target held here too. A node holding no replica of the
/// target has nothing to erase and records nothing. Then the header
/// ([`origin::REPLICATED`]) and its tombstone are recorded and the row is
/// destroyed on receipt (`purge_finalize`, which settles an erasure at its
/// execution).
///
/// # Errors
///
/// [`token::WITHDRAWS_UNHELD`], [`token::UNAUTHORISED`]; directory writes.
pub async fn apply_replicated_erasure<F>(
    directory: &F,
    bundle: &super::steward_purge::PurgeBundle,
    receiver_key_id: &str,
) -> Result<super::steward_purge::ApplyPurgeOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let unauth = |notice_id: &str, reason: String| Error::PurgeRefused {
        token: token::UNAUTHORISED,
        body: serde_json::json!({"notice_id": notice_id, "reason": reason}),
    };
    let notice = ErasureNotice::parse(&bundle.notice.envelope)
        .ok_or_else(|| unauth("", "the bundle's notice is not an erasure notice".into()))?;
    let (_, notice_id) = notice.jcs_and_id()?;
    let record_id = format!(
        "{}:{}",
        PurgePlane::Attestation.as_str(),
        notice.target_attestation_id
    );
    if bundle.record_ids != [record_id] {
        return Err(unauth(
            &notice_id,
            format!(
                "an erasure tombstones exactly its target on the attestation plane; the bundle \
                 names {:?}",
                bundle.record_ids
            ),
        ));
    }
    let Some(target) = directory
        .get_attestation(&notice.target_attestation_id)
        .await?
    else {
        return Ok(super::steward_purge::ApplyPurgeOutcome {
            notice_id,
            tombstoned: 0,
            already_tombstoned: 0,
        });
    };
    let Some(withdraws) = directory
        .get_attestation(&notice.withdraws_attestation_id)
        .await?
    else {
        return Err(Error::PurgeRefused {
            token: token::WITHDRAWS_UNHELD,
            body: serde_json::json!({
                "notice_id": notice_id,
                "withdraws_attestation_id": notice.withdraws_attestation_id,
                "retryable": true,
            }),
        });
    };
    let admitted = erasing_withdraws(directory, &target)
        .await?
        .is_some_and(|w| w.attestation_id == withdraws.attestation_id);
    if !admitted {
        return Err(unauth(
            &notice_id,
            format!(
                "withdraws {} is not the producer's rule-1 withdraws of {} that this node \
                 admits (CC 4.5.3; asked of this node's own state)",
                withdraws.attestation_id, target.attestation_id
            ),
        ));
    }
    let now = sp::purge_clock();
    let citation = ErasureCitation {
        target: target.attestation_id.clone(),
        withdraws,
    };
    let (execution, tombstone) =
        erasure_execution(&citation, receiver_key_id, origin::REPLICATED, now, None)?;
    let put = directory
        .purge_put_execution(&execution, std::slice::from_ref(&tombstone))
        .await?;
    let tombstoned = put.tombstones_inserted.iter().filter(|b| **b).count() as u64;
    sp::purge_finalize(directory, &notice_id, None).await?;
    Ok(super::steward_purge::ApplyPurgeOutcome {
        notice_id,
        tombstoned,
        already_tombstoned: 1 - tombstoned,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The CC 2.3.2.1 vector shape: tag, 64 lowercase hex, the exact preimage.
    #[test]
    fn agent_subject_is_the_tagged_canonical_hash_of_the_preimage() {
        let s = agent_subject("abc").unwrap();
        let hex = s.strip_prefix("canonical:sha256:").unwrap();
        assert_eq!(hex.len(), 64);
        assert_eq!(hex, hex::encode(sha2::Sha256::digest(b"ciris:agent:abc")));
        assert!(agent_subject("").is_err());
        assert!(agent_subject(" abc").is_err());
        assert!(agent_subject("a\nb").is_err());
        // An id MAY contain a colon (CC 2.3.2.1 split-on-first-two-colons).
        assert!(agent_subject("a:b").is_ok());
    }

    #[test]
    fn the_notice_round_trips_and_names_no_subject() {
        let n = ErasureNotice::new("w-1", "t-1");
        let (jcs, id) = n.jcs_and_id().unwrap();
        assert_eq!(
            jcs,
            r#"{"kind":"subject_erasure","target_attestation_id":"t-1","withdraws_attestation_id":"w-1"}"#
        );
        assert_eq!(id, hex::encode(sha2::Sha256::digest(jcs.as_bytes())));
        let v: serde_json::Value = serde_json::from_str(&jcs).unwrap();
        assert_eq!(ErasureNotice::parse(&v), Some(n));
        assert!(!is_erasure_notice_envelope(
            &serde_json::json!({"kind": "other"})
        ));
    }
}
