//! v58.0.0 (CIRISPersist#1094 item 2; CC 4.5.3 "Erasure at the subject's
//! request", CLM-erasure-subject-route; CIRISConstitution#174) — **erasure
//! is the subject's `withdraws`, and the replicated fact is the tombstone.**
//!
//! v57.0.0 hard-deleted an erased trace's signed `detection:*` rows under a
//! node-local purge basis (`art17_erasure`) whose notice was the erasure's own
//! `hard_case:trace_erasure:v1` row: a basis outside CIRISConstitution#165, a
//! header never served (so a peer holding a replica kept it), and a hard case
//! naming the erased subject. The steward's ruling replaces all three:
//!
//! - **Authority.** A row about a subject is erased by the subject's own
//!   `withdraws` (CC 2.4.1.1 rule 2 for an enrolled subject; rule 3 through a
//!   `delegates_to` proxy chain with `scope ⊇ {consent_revocation}` where the
//!   subject proved identity out of band, the NODE acting as that proxy). The
//!   DSAR door's subject is an agent, named on the wire by its CC 2.3.2.1
//!   canonical hash ([`agent_subject`]): the detection door writes it into
//!   every `detection:*` row's `subject_key_ids`, and the erasure writes,
//!   signed by the node key, the proxy grant `delegates_to(node → subject,
//!   scope [consent_revocation])` and one `withdraws` per row
//!   ([`prepare_subject_erasure`]). Each is admitted by the ordinary put door,
//!   whose `withdraws` gate is the ONE predicate
//!   (`admission::resolve_withdraws_admission_rule_at`); the store's erasure
//!   door re-derives it ([`authorised_erasures`]) and erases exactly what a
//!   subject `withdraws` covers.
//! - **The replicated fact.** Each erased row leaves one tombstone by digest
//!   on the attestation plane, under a header whose notice is
//!   [`ErasureNotice`] — `{withdraws, target}` ids, nothing else — and whose
//!   `legal_basis` column is [`WITHDRAWS_AUTHORITY`]. That header is the
//!   node's informational ledger entry: it is never a notice of its own and
//!   never a basis; the authority it cites is the withdraws row, which a peer
//!   verifies against ITS OWN state ([`apply_replicated_erasure`]). The header
//!   IS served (`list_purge_bundles_since`), so a peer holding a replica
//!   receives the tombstone and erases it.
//! - **The hard case names nobody** (`hard_case::trace_erasure_event`).
//!
//! The trace corpus (`trace_events`, `trace_llm_calls`) is not on the
//! attestation plane and is hard-deleted by the DSAR door as before.

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
    /// A replicated erasure whose cited row is not a `withdraws` naming the
    /// target, or that this node's own `withdraws` gate does not admit under
    /// a subject rule (2–4), or whose bundle names anything but the one
    /// target on the attestation plane. Body: `{notice_id, reason}`.
    pub const UNAUTHORISED: &str = "subject_erasure_unauthorised";
    /// Every token.
    pub const ALL: &[&str] = &[WITHDRAWS_UNHELD, UNAUTHORISED];
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

/// **The authority, re-derived**: the first `withdraws` naming `target` that
/// THIS node's own `withdraws` gate admits under a subject rule (2–4) —
/// `check_withdraws_admission_as_admitted`, the read-time form of the one
/// predicate. A producer's own retraction (rule 1) is a retraction, not the
/// subject's erasure, and a stored rule is never read (an out-of-order row
/// carries `None`).
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
            || super::precedence::references_attestation_id_from_envelope(&w.attestation_envelope)
                != Some(target.attestation_id.as_str())
        {
            continue;
        }
        let dir = directory.as_dyn_directory();
        match super::admission::check_withdraws_admission_as_admitted(dir, &w).await {
            Ok(Some(rule)) if (2..=4).contains(&rule) => return Ok(Some(w)),
            Ok(_) | Err(Error::WithdrawsNotAdmitted { .. }) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

/// [`erasing_withdraws`] over `targets` (row ids; one not held is skipped):
/// what the store's erasure door may erase. Run before the door's
/// transaction; the door erases exactly these and leaves every other row.
///
/// # Errors
///
/// Directory reads.
pub async fn authorised_erasures<F>(
    directory: &F,
    targets: &[String],
) -> Result<Vec<ErasureCitation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut out = Vec::new();
    for id in targets {
        let Some(row) = directory.get_attestation(id).await? else {
            continue;
        };
        if let Some(withdraws) = erasing_withdraws(directory, &row).await? {
            out.push(ErasureCitation {
                target: id.clone(),
                withdraws,
            });
        }
    }
    Ok(out)
}

/// v58.0.0 (CIRISPersist#1094 item 2) — **the store door's decision, read
/// before its transaction**, once for all three backends: the `detection:*`
/// rows a DSAR erasure of `agent_id_hash` (one signing key's traces when
/// `signing_key_id` is given) reaches, split into the ones an admitted
/// subject `withdraws` covers ([`authorised_erasures`] — the door erases
/// exactly these) and the count it leaves.
///
/// # Errors
///
/// Directory reads.
pub(crate) async fn plan_store_erasure<D>(
    dir: &D,
    agent_id_hash: &str,
    signing_key_id: Option<&str>,
) -> Result<(Vec<ErasureCitation>, u64), Error>
where
    D: super::attestation_admit::AttestationStore,
{
    let candidates = dir
        .detection_row_ids_for_agent(agent_id_hash, signing_key_id)
        .await?;
    let citations = authorised_erasures(dir, &candidates).await?;
    let retained = (candidates.len() - citations.len()) as u64;
    if retained > 0 {
        tracing::warn!(
            retained,
            "DSAR erasure: row-backed detections no subject withdraws covers are left in place \
             (CC 4.5.3: erasure is the subject's withdraws)"
        );
    }
    Ok((citations, retained))
}

/// What [`prepare_subject_erasure`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreparedErasure {
    /// The canonical subject ([`agent_subject`]).
    pub subject: String,
    /// The proxy grants this call emitted (one per placement it needed).
    pub grants_emitted: Vec<String>,
    /// The `withdraws` rows this call emitted.
    pub withdraws_emitted: Vec<String>,
    /// Rows already covered by an admitted subject `withdraws`.
    pub already_withdrawn: Vec<String>,
    /// Rows that do not name the subject: no subject `withdraws` can reach
    /// them (CC 2.4.1.1 rules 2–3 read the target's `subject_key_ids`), so
    /// the erasure leaves them.
    pub unreachable: Vec<String>,
}

/// The proxy grant's scope: CC 2.4.1.1 rule 3's `consent_revocation`, and
/// nothing else.
fn proxy_grant_input(subject: &str, placement: &Placement) -> super::EmitAttestationInput {
    let envelope = super::delegates_to_envelope(
        subject,
        &[super::admission::DELEGATION_SCOPE_CONSENT_REVOCATION.to_owned()],
        false,
    );
    let mut input = super::EmitAttestationInput::with_envelope(
        attestation_type::DELEGATES_TO,
        super::envelope::EnvelopeCore::from_value(placement.place(envelope))
            .expect("built envelope is a JSON object"),
        &placement.cohort_scope,
    );
    input.attested_key_id = Some(subject.to_owned());
    input
}

/// Where a target row lives, so its erasure's rows go where it went: the same
/// `cohort_scope` and cohort target (the holding-claim retraction's rule).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Placement {
    cohort_scope: String,
    target: Option<(&'static str, String)>,
}

impl Placement {
    fn of(row: &Attestation) -> Result<Self, Error> {
        let target =
            super::admission::envelope_cohort_target(&row.attestation_envelope)?.map(|t| {
                let key = if row.cohort_scope == super::types::cohort_scope::FAMILY {
                    "family_key_id"
                } else {
                    "community_id"
                };
                (key, t.to_owned())
            });
        Ok(Self {
            cohort_scope: row.cohort_scope.clone(),
            target,
        })
    }

    fn place(&self, mut envelope: serde_json::Value) -> serde_json::Value {
        if let (Some((key, t)), Some(obj)) = (&self.target, envelope.as_object_mut()) {
            obj.insert((*key).to_owned(), serde_json::Value::String(t.clone()));
        }
        envelope
    }
}

/// **The DSAR door's half that signs** (Engine-side; the store cannot sign):
/// for each of `targets` that names the subject ([`agent_subject`] of
/// `agent_id_hash`) and is not already covered by an admitted subject
/// `withdraws`, emit — through `emit`, which signs with the node key and puts
/// through the ordinary door — the node's `withdraws` of it. The withdraws
/// gate admits it by CC 2.4.1.1 rule 3 when the node holds the proxy grant
/// `delegates_to(node → subject, scope [consent_revocation])`; when it does
/// not, the grant is emitted once per placement and the withdraws offered
/// again. **The proxy grant is written on the subject's out-of-band proof**:
/// the caller of the DSAR door owns the DSAR-request authority (the identity
/// proof); persist records the proxy it implies, and a withdraws the gate
/// still refuses after the grant is the error returned.
///
/// # Errors
///
/// The `withdraws` gate's refusal; `emit`'s errors; directory reads.
pub async fn prepare_subject_erasure<F, E, Fut>(
    directory: &F,
    node_key_id: &str,
    agent_id_hash: &str,
    targets: &[Attestation],
    emit: E,
) -> Result<PreparedErasure, Error>
where
    F: FederationDirectory + ?Sized,
    E: Fn(super::EmitAttestationInput) -> Fut,
    Fut: std::future::Future<Output = Result<String, Error>>,
{
    let subject = agent_subject(agent_id_hash)?;
    let mut out = PreparedErasure {
        subject: subject.clone(),
        ..PreparedErasure::default()
    };
    let mut granted: std::collections::BTreeSet<Placement> = std::collections::BTreeSet::new();
    for target in targets {
        if !target.subject_key_ids.iter().any(|s| s == &subject) {
            out.unreachable.push(target.attestation_id.clone());
            continue;
        }
        if erasing_withdraws(directory, target).await?.is_some() {
            out.already_withdrawn.push(target.attestation_id.clone());
            continue;
        }
        let placement = Placement::of(target)?;
        let withdraws_input = || {
            let envelope = super::withdraws_attestation_envelope(
                &target.attestation_id,
                &target.attestation_type,
            );
            let mut input = super::EmitAttestationInput::with_envelope(
                attestation_type::WITHDRAWS,
                super::envelope::EnvelopeCore::from_value(placement.place(envelope))
                    .expect("built envelope is a JSON object"),
                &placement.cohort_scope,
            );
            input.attested_key_id = Some(node_key_id.to_owned());
            input
        };
        match emit(withdraws_input()).await {
            Ok(id) => out.withdraws_emitted.push(id),
            Err(Error::WithdrawsNotAdmitted { .. }) if !granted.contains(&placement) => {
                let grant = emit(proxy_grant_input(&subject, &placement)).await?;
                out.grants_emitted.push(grant);
                granted.insert(placement.clone());
                out.withdraws_emitted.push(emit(withdraws_input()).await?);
            }
            Err(e) => return Err(e),
        }
    }
    Ok(out)
}

/// **Apply a peer's erasure tombstone** (a
/// [`PurgeBundle`](super::steward_purge::PurgeBundle) whose notice is an
/// [`ErasureNotice`]). The receiver trusts nothing the sender says: the
/// bundle must name exactly the notice's target on the attestation plane;
/// the cited `withdraws` must be held HERE (it replicates as any row does;
/// until it has, [`token::WITHDRAWS_UNHELD`], retryable), name the target, and
/// be admitted by THIS node's own `withdraws` gate under a subject rule —
/// which needs the target held here too. A node holding no replica of the
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
                "withdraws {} is not a subject withdraws of {} that this node admits (CC 2.4.1.1 \
                 rules 2-4, asked of this node's own state)",
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
