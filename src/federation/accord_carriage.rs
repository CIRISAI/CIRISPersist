//! v31.1.0 (CIRISPersist#655 / CIRISPersist#662) — **the exclusion planes'
//! carriage: replicate EVIDENCE, never verdicts.**
//!
//! # The defect
//!
//! Two exclusion planes could be destroyed and never rebuilt.
//!
//! - `federation_revocations` (#655) had no serve cursor, so a plane that
//!   *excludes* a key could be deleted by a DSAR erasure, an operator repair
//!   or a restored backup and nothing could refill it.
//! - `federation_role_withdrawals` (V104, #662's blocker) had the same gap,
//!   and worse: [`is_infra_attest_effective`](super::admission::is_infra_attest_effective)
//!   folds withdrawals through `lookup_role_withdrawal`, so the *effective*
//!   `infra:attest` set — the build-signing trust root — depended on rows
//!   that could not reach a peer.
//!
//! **The two halves needed opposite remedies, and saying so is the point.**
//!
//! # `federation_revocations` carries its own signature; V104 does not
//!
//! A `federation_revocations` row is self-authenticating: it stores
//! `revocation_envelope` plus `scrub_signature_classical` /
//! `scrub_signature_pqc` / `scrub_key_id`, and
//! [`verify_revocation_admission`](super::verify_revocation_admission) makes
//! the receiving node re-verify that hybrid-Strict signature against the
//! declared revoking key resolved from its OWN `federation_keys` before the
//! row lands. The receive side was therefore already correct; only the SERVE
//! side was missing. A plain cursor
//! ([`FederationDirectory::list_signed_revocations_since`](super::FederationDirectory::list_signed_revocations_since))
//! is the whole fix, and the plane joins the shared `signed_wire_index`
//! alongside the other fourteen.
//!
//! `federation_role_withdrawals` has **no signature columns at all** —
//! `role`, `key_id`, `withdrawn_at`, `authority_decision_digest`,
//! `superseded_by`, `persist_row_hash`. `persist_row_hash` is recomputed
//! locally at write, so it binds nothing across nodes, and the authority
//! lives entirely behind `authority_decision_digest`: a pointer into the
//! accord decision plane (V091 / CIRISPersist#302), which is where the actual
//! signatures are. There is nothing on a V104 row a peer could verify. A
//! cursor there would ship a **derived verdict** and ask the receiver to
//! trust the sender — the forgeable-decision-bool bypass CIRISPersist#377
//! closed, rebuilt on purpose and called replication.
//!
//! # The shape, and why the ordering is load-bearing
//!
//! 1. The **signed evidence** replicates: [`AccordQuorumEvidence`] — the
//!    `AccordProposal` plus the holders' hybrid-signed `AccordParticipation`
//!    set, served by
//!    [`list_signed_accord_quorum_evidence_since`](super::FederationDirectory::list_signed_accord_quorum_evidence_since).
//! 2. The receiver **re-tallies** it ([`admit_replicated_accord_evidence`])
//!    with `tally_live_quorum` against a roster resolved from its OWN
//!    directory, at the same strict-majority threshold the local destructive
//!    ops use. Nothing lands unless that tally passes. *This is the
//!    load-bearing half: a replicated decision that is trusted rather than
//!    re-derived is worse than no replication, because it looks like
//!    evidence.*
//! 3. The receiver then **re-derives its own** V104/V095 projection
//!    ([`project_role_withdrawals_for_proposal`]) by recomputing candidate
//!    payload digests over its OWN key directory and re-running the #377
//!    authority core. V104 becomes a local materialization rather than
//!    something on the wire at all.
//!
//! Step 3 is why step 1 is safe. A node holds a tombstone only because that
//! node re-tallied the quorum itself.
//!
//! # What a hostile carrier can and cannot do
//!
//! It can withhold (the standard partition failure — [`AccordQuorumEvidence`]
//! is a supply set, never proof of absence). It can replay old bundles, which
//! are idempotent. It **cannot** forge one: the participations are hybrid
//! signatures by accord holders whose pinned pubkeys the receiver resolves
//! from its own baked genesis records, and the proposal's `payload_sha256`
//! must equal a digest the receiver computes itself from `(op, target_key_id)`
//! — never one the sender supplies.

use ciris_verify_core::accord_live_quorum::{AccordParticipation, AccordProposal};
use ciris_verify_core::threshold::ThresholdMember;

use super::admission::{
    accord_holder_roster_key_ids, canonical_withdrawal_payload_sha256, op_withdraw_role,
    OP_WITHDRAW_CANONICAL, OP_WITHDRAW_INFRA_ATTEST,
};
use super::types::{identity_type, roles};
use super::{Error, FederationDirectory};

/// v31.1.0 (CIRISPersist#662) — one accord proposal's **signed evidence**, as
/// it crosses the wire: the verify-core proposal, the server-supplied
/// authority-signature envelope, and every stored participation for it.
///
/// # Why a bundle and not two cursors
///
/// A proposal on its own authorizes nothing and a participation cannot be
/// admitted before its proposal exists (`put_accord_participation` verifies
/// against the stored proposal). Two independent cursors would let a peer
/// hold a proposal with no votes — inert, but indistinguishable on the wire
/// from one whose votes have not arrived yet — and would put the re-tally
/// somewhere *after* admission, where it can be forgotten. Bundling makes the
/// re-tally the admission gate itself: there is no ordering in which
/// [`admit_replicated_accord_evidence`] stores a row it has not already
/// re-derived a quorum for.
///
/// `participations` is sorted by `member_id` on the serve side so the bundle
/// serializes deterministically (the roster maps each `member_id` to exactly
/// one pinned pubkey, and M6 dedups by that pubkey, so `member_id` is unique
/// within a bundle).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AccordQuorumEvidence {
    /// The verbatim verify-core proposal. Its `digest()` is content-derived,
    /// so a sender cannot rename a bundle.
    pub proposal: AccordProposal,
    /// The server-supplied authority-signature envelope, if any (stored
    /// verbatim; not itself an authority — the participations are).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_signature: Option<serde_json::Value>,
    /// Every stored participation for `proposal`, sorted by `member_id`.
    /// Each carries the holder's hybrid threshold signature over the
    /// proposal digest + seat + vote, which is what the receiver re-verifies.
    pub participations: Vec<AccordParticipation>,
    /// When THIS node admitted the proposal — the cursor field for
    /// [`FederationDirectory::list_signed_accord_quorum_evidence_since`](super::FederationDirectory::list_signed_accord_quorum_evidence_since),
    /// so a caller can resume from the last element of a page.
    ///
    /// Local admission metadata, deliberately: it is NOT part of the evidence
    /// and nothing verifies against it. A receiver stamps its own on admit
    /// rather than adopting the sender's, so a peer cannot backdate a bundle
    /// past another node's cursor.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// v31.1.0 (CIRISPersist#662) — what an [`admit_replicated_accord_evidence`]
/// call actually did, so a carrier can log a supply decision instead of
/// guessing from `Ok(())`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccordEvidenceAdmission {
    /// The admitted proposal's content-derived digest.
    pub proposal_digest: String,
    /// YES votes the RECEIVER re-tallied (never the sender's count).
    pub yes: usize,
    /// The strict-majority threshold those votes had to clear.
    pub threshold: usize,
    /// The roster size the threshold was derived from.
    pub roster_size: usize,
    /// Participations that landed (a byte-identical re-PUT is idempotent, so
    /// this can be lower than `evidence.participations.len()` on a replay).
    pub participations_admitted: usize,
    /// `(role, key_id)` tombstones this admit re-derived locally — the
    /// [`Projection::RoleWithdrawals`](super::replication_policy::Projection::RoleWithdrawals)
    /// fan-out. Empty is the common case: most proposals are not withdrawals,
    /// and a withdrawal for a key this node does not hold projects nothing.
    pub withdrawals_projected: Vec<(String, String)>,
}

/// The strict-majority destructive threshold for a roster of `n` holders —
/// the SAME derivation
/// [`verify_canonical_authority_over_roster`](super::admission::verify_canonical_withdraw_authority)
/// uses (`QuorumPolicy::new(n / 2 + 1, n)`, CIRISPersist#383), so the receive
/// gate and the local destructive ops cannot drift apart.
fn strict_majority_policy(n: usize) -> ciris_verify_core::threshold::QuorumPolicy {
    ciris_verify_core::threshold::QuorumPolicy::new(n / 2 + 1, n)
}

/// Resolve `roster_key_ids` to their PINNED directory pubkeys — never
/// caller-supplied key material. Mirrors step (3) of the #377 authority core.
async fn roster_from_own_directory(
    directory: &dyn FederationDirectory,
    roster_key_ids: &[String],
) -> Result<Vec<ThresholdMember>, Error> {
    let mut roster: Vec<ThresholdMember> = Vec::with_capacity(roster_key_ids.len());
    for kid in roster_key_ids {
        if let Some(rec) = directory.lookup_public_key(kid).await? {
            roster.push(ThresholdMember {
                member_id: rec.key_id,
                ed25519_public_key_base64: rec.pubkey_ed25519_base64,
                mldsa65_public_key_base64: rec.pubkey_ml_dsa_65_base64,
                role: None,
            });
        }
    }
    Ok(roster)
}

/// v31.1.0 (CIRISPersist#662) — **admit a replicated accord evidence bundle
/// by re-deriving its quorum, against the production accord-holder roster.**
/// See [`admit_replicated_accord_evidence_over_roster`].
pub async fn admit_replicated_accord_evidence(
    directory: &dyn FederationDirectory,
    evidence: &AccordQuorumEvidence,
) -> Result<AccordEvidenceAdmission, Error> {
    admit_replicated_accord_evidence_over_roster(
        directory,
        evidence,
        &accord_holder_roster_key_ids(),
    )
    .await
}

/// v31.1.0 (CIRISPersist#662) — [`admit_replicated_accord_evidence`] with an
/// explicit accord-holder roster keyset (the core primitive; tests supply
/// their own signable holders, mirroring
/// [`withdraw_infra_attest_role_over_roster`](super::admission::withdraw_infra_attest_role_over_roster)).
///
/// # The gate, in order. Every step reads the RECEIVER's own state.
///
/// 0. [`require_seated_accord_roster`](super::genesis::posture::require_seated_accord_roster)
///    — a node with no constitution says so rather than admitting
///    constitutional evidence into a vacuum (CIRISPersist#648).
/// 1. Family scope: only the HUMANITY_ACCORD family, the same scope the
///    withdrawal authority accepts. A bundle for any other family is refused
///    here rather than stored and ignored.
/// 2. Roster resolution: `roster_key_ids` → PINNED pubkeys from OUR
///    `federation_keys`. Sender-supplied key material is unrepresentable.
/// 3. **The re-tally.** `tally_live_quorum(&proposal, &participations,
///    &roster)` re-verifies every participation's hybrid signature, its
///    binding to THIS proposal digest, and its seat in the pinned roster,
///    then dedups by member. `tally.yes` must clear
///    [`strict_majority_policy`]. The sender's `authority_signature` and any
///    `AccordDecision.authorized` bool are NOT consulted — they are not
///    inputs to this function at all.
/// 4. Only now does anything land: the nonce is recorded (so the local M4
///    gate on `put_accord_proposal` is satisfied by evidence this node
///    verified, not by a sender's assertion), then the proposal, then each
///    participation — which `put_accord_participation` re-verifies a SECOND
///    time against the same roster as it stores it.
/// 5. The V104/V095 projection is re-derived locally
///    ([`project_role_withdrawals_for_proposal`]).
///
/// Idempotent: a replayed bundle re-tallies, re-stores nothing new, and
/// re-derives the same tombstones.
///
/// # On step 4's nonce
///
/// M4 (`accord_nonce_issued`) is an ORIGINATION control — it stops a client
/// from proposing arbitrary proposals to a server that never issued a nonce.
/// It is not an authenticity control, and on a receiving node it cannot be
/// satisfied by construction (that node issued nothing). Recording the nonce
/// here is not a bypass because it happens strictly AFTER the strict-majority
/// re-tally: this node is recording that it accepted a bundle carrying real
/// signed votes from its own roster, which is a stronger fact than the one
/// M4 exists to establish.
pub async fn admit_replicated_accord_evidence_over_roster(
    directory: &dyn FederationDirectory,
    evidence: &AccordQuorumEvidence,
    roster_key_ids: &[String],
) -> Result<AccordEvidenceAdmission, Error> {
    use ciris_verify_core::accord_live_quorum::tally_live_quorum;

    let proposal_digest = evidence.proposal.digest();
    let refuse = |reason: String| Error::AccordEvidenceUnverified {
        proposal_digest: proposal_digest.clone(),
        reason,
    };

    // (0) The fail-closed chokepoint: no constitution, no constitutional
    //     evidence. Shares the CANONICAL_WITHDRAW_AUTHORITY operation token
    //     with the destructive ops this evidence authorizes.
    super::genesis::posture::require_seated_accord_roster(
        directory,
        super::genesis::posture::CANONICAL_WITHDRAW_AUTHORITY,
        roster_key_ids,
    )
    .await?;

    // (1) Family scope.
    if evidence.proposal.family_key_id
        != ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID
    {
        return Err(refuse(format!(
            "proposal family_key_id {:?} is not the HUMANITY_ACCORD family {:?}",
            evidence.proposal.family_key_id,
            ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID
        )));
    }

    // (2) Roster from OUR directory.
    let roster = roster_from_own_directory(directory, roster_key_ids).await?;

    // (3) THE RE-TALLY. Not the sender's verdict — ours, over their signatures.
    let tally = tally_live_quorum(&evidence.proposal, &evidence.participations, &roster)
        .map_err(|e| refuse(format!("live-quorum tally failed (fail-closed): {e:?}")))?;
    let policy = strict_majority_policy(roster.len());
    policy.validate().map_err(|e| {
        refuse(format!(
            "accord roster quorum policy invalid ({n} holders): {e:?}",
            n = roster.len()
        ))
    })?;
    if tally.yes < policy.m {
        return Err(refuse(format!(
            "insufficient accord quorum on RE-TALLY: {yes} YES vote(s) among the live set \
             {live:?}, but replicated accord evidence is admitted only at a strict majority \
             of the accord family (>= {m} of {n}) — the sender's own verdict is not consulted",
            yes = tally.yes,
            live = tally.live_set,
            m = policy.m,
            n = policy.n,
        )));
    }

    // (4) Now — and only now — store. See the doc note on M4.
    directory
        .issue_accord_nonce(&evidence.proposal.family_key_id, &evidence.proposal.nonce)
        .await?;
    directory
        .put_accord_proposal(
            evidence.proposal.clone(),
            evidence.authority_signature.clone(),
        )
        .await?;
    let before = directory.list_accord_participations(&proposal_digest).await?.len();
    for participation in &evidence.participations {
        // Re-verified a second time, per row, as it lands: the member must be
        // in the roster and `AccordParticipation::verify` must pass.
        directory
            .put_accord_participation(participation.clone(), &roster)
            .await?;
    }
    let after = directory.list_accord_participations(&proposal_digest).await?.len();

    // (5) Re-derive OUR OWN withdrawal projection. This is why (4) is safe.
    let withdrawals_projected =
        project_role_withdrawals_for_proposal(directory, &evidence.proposal, roster_key_ids)
            .await?;

    Ok(AccordEvidenceAdmission {
        proposal_digest,
        yes: tally.yes,
        threshold: policy.m,
        roster_size: policy.n,
        participations_admitted: after.saturating_sub(before),
        withdrawals_projected,
    })
}

/// The `(op, role)` pairs a withdrawal projection can re-derive for one
/// candidate key. `role` is what the tombstone is recorded under; `op` is the
/// token the proposal's `payload_sha256` must commit to.
///
/// `canonical` and `infra:attest` keep their frozen dedicated tokens; every
/// other accord-conferred role rides
/// [`op_withdraw_role`](super::admission::op_withdraw_role).
fn withdrawal_ops_for(record: &super::KeyRecord) -> Vec<(String, String)> {
    let mut out = vec![
        (
            OP_WITHDRAW_CANONICAL.to_owned(),
            identity_type::CANONICAL.to_owned(),
        ),
        (
            OP_WITHDRAW_INFRA_ATTEST.to_owned(),
            roles::INFRA_ATTEST.to_owned(),
        ),
    ];
    for role in &record.capability_roles {
        if role == roles::INFRA_ATTEST || role == identity_type::CANONICAL {
            continue;
        }
        out.push((op_withdraw_role(role), role.clone()));
    }
    out
}

/// Record the tombstone for one re-derived `(role, key_id)`. `canonical`
/// keeps its dedicated V095 table; every other role lands on V104.
async fn record_projected_withdrawal(
    directory: &dyn FederationDirectory,
    role: &str,
    key_id: &str,
    authority_digest: &str,
) -> Result<(), Error> {
    if role == identity_type::CANONICAL {
        directory
            .record_canonical_withdrawal(key_id, None, authority_digest)
            .await
    } else {
        directory
            .record_role_withdrawal(role, key_id, None, authority_digest)
            .await
    }
}

/// v31.1.0 (CIRISPersist#662) — **re-derive this node's own withdrawal
/// tombstones for ONE proposal.** Returns the `(role, key_id)` pairs
/// projected.
///
/// # Why this is a search over the LOCAL key set, and why that is the point
///
/// `payload_sha256` is a digest, so a receiver cannot read the target key out
/// of a proposal — it can only ASK, for each key it already holds, "does the
/// payload this quorum voted on equal the one I would compute to withdraw
/// THIS key?" That is the correct question, and it has three consequences
/// worth stating:
///
/// - The projection is scoped to what this node knows. A withdrawal naming a
///   key we have never seen materializes nothing, and needs to: there is no
///   role to exclude.
/// - The payload digest is computed HERE, by
///   [`canonical_withdrawal_payload_sha256`], from `(op, target_key_id)`.
///   Nothing about the target crosses the wire, so a decision authorizing one
///   op cannot be replayed against another key or another role.
/// - Each match then runs the full #377 authority core
///   ([`verify_canonical_authority_over_roster`](super::admission::verify_canonical_withdraw_authority)),
///   which re-tallies the stored participations AGAIN and re-checks the
///   payload binding before writing. The projection never shortcuts to
///   "the bundle was admitted, so the tombstone is authorized".
///
/// # Scope: plain WITHDRAW only
///
/// SUPERSEDE (`superseded_by = Some(successor)`) is deliberately NOT
/// re-derived. Its payload commits to a `(target, successor)` PAIR, so the
/// same search would be quadratic in the key set, and a supersede is a
/// rotation link rather than an exclusion — the class #655/#662 are about.
/// A superseding node still records its own link locally through
/// [`supersede_canonical`](super::admission::supersede_canonical); what
/// replicates for the successor is its `SignedKeyRecord` on the `Key` plane.
pub async fn project_role_withdrawals_for_proposal(
    directory: &dyn FederationDirectory,
    proposal: &AccordProposal,
    roster_key_ids: &[String],
) -> Result<Vec<(String, String)>, Error> {
    let candidates = directory.list_signed_key_records_since(None, u32::MAX).await?;
    let proposal_digest = proposal.digest();
    let mut projected: Vec<(String, String)> = Vec::new();
    for candidate in &candidates {
        let key_id = &candidate.record.key_id;
        for (op, role) in withdrawal_ops_for(&candidate.record) {
            let expected = canonical_withdrawal_payload_sha256(&op, key_id, None)?;
            if expected != proposal.payload_sha256 {
                continue;
            }
            // The FULL authority core, re-run: stored proposal, family scope,
            // payload binding, and a fresh `tally_live_quorum` over our own
            // stored participations at the strict-majority threshold.
            let authority_digest = super::admission::verify_withdrawal_authority_over_roster(
                directory,
                &proposal_digest,
                &op,
                key_id,
                roster_key_ids,
            )
            .await?;
            record_projected_withdrawal(directory, &role, key_id, &authority_digest).await?;
            projected.push((role, key_id.clone()));
        }
    }
    projected.sort();
    projected.dedup();
    Ok(projected)
}

/// v31.1.0 (CIRISPersist#662) — **the repair door: re-derive every withdrawal
/// tombstone this node's stored accord evidence supports**, against the
/// production accord-holder roster. See
/// [`rematerialize_role_withdrawals_over_roster`].
pub async fn rematerialize_role_withdrawals(
    directory: &dyn FederationDirectory,
) -> Result<Vec<(String, String)>, Error> {
    rematerialize_role_withdrawals_over_roster(directory, &accord_holder_roster_key_ids()).await
}

/// v31.1.0 (CIRISPersist#662) — [`rematerialize_role_withdrawals`] with an
/// explicit roster keyset.
///
/// This is what makes the exclusion plane genuinely REBUILDABLE, which is the
/// whole of #655/#662: after a purge, a restore from an older backup, or a
/// fresh node catching up through the evidence cursor, this recomputes the
/// V104/V095 tombstones from evidence rather than accepting them from a peer.
/// Idempotent — every underlying `record_*_withdrawal` is.
///
/// O(|proposals| × |keys|) digest computations. That is a repair/backfill
/// cost, not a per-request one, and it is the same shape as
/// [`rebuild_signed_wire_index`](super::FederationDirectory::rebuild_signed_wire_index).
pub async fn rematerialize_role_withdrawals_over_roster(
    directory: &dyn FederationDirectory,
    roster_key_ids: &[String],
) -> Result<Vec<(String, String)>, Error> {
    let bundles = directory
        .list_signed_accord_quorum_evidence_since(None, u32::MAX)
        .await?;
    let mut projected: Vec<(String, String)> = Vec::new();
    for bundle in &bundles {
        projected.extend(
            project_role_withdrawals_for_proposal(directory, &bundle.proposal, roster_key_ids)
                .await?,
        );
    }
    projected.sort();
    projected.dedup();
    Ok(projected)
}

/// v31.1.0 (CIRISPersist#662) — the shared serve-side assembly every backend's
/// [`list_signed_accord_quorum_evidence_since`](super::FederationDirectory::list_signed_accord_quorum_evidence_since)
/// calls once it has selected its page of proposals.
///
/// Written against `&dyn FederationDirectory` so the "sorted by `member_id`"
/// determinism rule lives in ONE place: three backends each sorting their own
/// way is exactly the preserve-set ≢ verified-set shape CIRISPersist#541 paid
/// for, one plane over.
pub async fn assemble_evidence_page(
    directory: &dyn FederationDirectory,
    proposals: Vec<super::accord_quorum::StoredProposal>,
) -> Result<Vec<AccordQuorumEvidence>, Error> {
    let mut out = Vec::with_capacity(proposals.len());
    for stored in proposals {
        let digest = stored.proposal.digest();
        let mut participations: Vec<AccordParticipation> = directory
            .list_accord_participations(&digest)
            .await?
            .into_iter()
            .map(|s| s.participation)
            .collect();
        participations.sort_by(|a, b| a.member_id.cmp(&b.member_id));
        out.push(AccordQuorumEvidence {
            proposal: stored.proposal,
            authority_signature: stored.authority_signature,
            participations,
            created_at: stored.created_at,
        });
    }
    Ok(out)
}
