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
    /// v31.1.0 (CIRISPersist#662, PR review P1) — **the bundle's visibility
    /// instant**: `max(proposal.created_at, max(participation.server_arrival_at))`,
    /// and the cursor field for
    /// [`FederationDirectory::list_signed_accord_quorum_evidence_since`](super::FederationDirectory::list_signed_accord_quorum_evidence_since).
    ///
    /// # Why not the proposal's `created_at`
    ///
    /// A bundle is an AGGREGATE — its content changes every time a holder's
    /// vote lands — so an immutable per-proposal cursor is unsound in both
    /// directions. A peer that read a proposal at one YES and advanced past
    /// its `created_at` would permanently skip the quorum-bearing version that
    /// arrives minutes later; a peer that refused to advance would wedge its
    /// cursor behind a proposal it can never admit. Neither is recoverable
    /// without a full re-scan, on the one plane whose entire purpose is that
    /// exclusion state converges.
    ///
    /// Keying on the latest evidence instead makes a vote's arrival move the
    /// bundle forward in the stream, so it is re-offered exactly when it has
    /// something new to say. This is the same "visibility timestamp" shape
    /// [`list_attestations_since`](super::FederationDirectory::list_attestations_since)
    /// uses (`COALESCE(promoted_at, asserted_at)`) and for the same reason.
    ///
    /// Local metadata, deliberately: nothing verifies against it, and a
    /// receiver stamps its own rather than adopting the sender's, so a peer
    /// cannot backdate a bundle past another node's cursor.
    pub evidence_at: chrono::DateTime<chrono::Utc>,
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
    //
    // NOT the only thing keeping out-of-family evidence out, and the mutation
    // harness proved it: deleting this branch leaves the bundle refused anyway,
    // because `AccordParticipation::verify` binds `family_key_id` inside each
    // holder's signature, so re-pointing a proposal at another family
    // invalidates every vote and the step-(3) tally reaches zero.
    //
    // It stays because the two refusals say different things. Without it an
    // operator reads "insufficient accord quorum: 0 YES votes" for a bundle
    // whose votes are all present and valid — a true statement that sends them
    // hunting a partition. The enumerated check names the actual fault. Kept as
    // the LEGIBLE layer over a safety property enforced one level down, and
    // labelled so, rather than left to look load-bearing.
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
    let before = directory
        .list_accord_participations(&proposal_digest)
        .await?
        .len();
    for participation in &evidence.participations {
        // Re-verified a second time, per row, as it lands: the member must be
        // in the roster and `AccordParticipation::verify` must pass.
        directory
            .put_accord_participation(participation.clone(), &roster)
            .await?;
    }
    let after = directory
        .list_accord_participations(&proposal_digest)
        .await?
        .len();

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
///
/// # BOTH role surfaces, DERIVED rather than re-enumerated (PR #667 review P1)
///
/// A record claims a role through
/// [`claims_role`](super::KeyRecord::claims_role), which is
/// `identity_type ∪ capability_roles` — and this walked `capability_roles`
/// alone. A role claimed through `identity_type` (`registry`, `verify`,
/// `substrate_persist`, `trusted_publisher`, `lenscore_detector` — every
/// accord-co-scrubbed identity type) therefore produced no
/// `withdraw_role:{role}` candidate at all: the withdrawal was authorized,
/// stored as evidence, and silently inert, and `rematerialize_role_withdrawals`
/// could not restore it either.
///
/// **`identity_type` is the only field in this substrate that is
/// simultaneously authority-bearing and shaped like a label**, which is why
/// every hand-written enumeration of "the security-relevant bits" keeps
/// omitting it. `is_canonical` reads standing straight off it and
/// `AUTHORITY_CONFERRING_IDENTITY_TYPES` gates on it, yet it reads as
/// metadata. CIRISPersist#661 was this same field missing from the subject
/// binding one release earlier; this is the fourth occurrence in the v31 line.
///
/// So the remedy is not "add the other list" — it is to **stop keeping a
/// second list**. The candidate set is derived from the same union
/// `claims_role` tests, so the gate and the projection cannot disagree about
/// what a record claims.
fn withdrawal_ops_for(record: &super::KeyRecord) -> Vec<(String, String)> {
    // Considered for EVERY key regardless of what it claims today: a tombstone
    // exists to block a future re-add, and the key that will be re-offered
    // carrying `canonical` may be carrying nothing at all right now.
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
    for role in claimed_roles(record) {
        if role == roles::INFRA_ATTEST || role == identity_type::CANONICAL {
            continue;
        }
        out.push((op_withdraw_role(&role), role));
    }
    out
}

/// Every role `record` claims on EITHER surface — the same union
/// [`claims_role`](super::KeyRecord::claims_role) tests, spelled once here so
/// the projection cannot drift from the gate that reads it.
fn claimed_roles(record: &super::KeyRecord) -> Vec<String> {
    let mut claimed: Vec<String> = identity_type::parse_set(&record.identity_type)
        .into_iter()
        .map(str::to_owned)
        .collect();
    claimed.extend(record.capability_roles.iter().cloned());
    claimed.sort();
    claimed.dedup();
    claimed
}

/// Is `(role, key_id)` already tombstoned on this node?
async fn withdrawal_exists(
    directory: &dyn FederationDirectory,
    role: &str,
    key_id: &str,
) -> Result<bool, Error> {
    Ok(if role == identity_type::CANONICAL {
        directory
            .lookup_canonical_withdrawal(key_id)
            .await?
            .is_some()
    } else {
        directory
            .lookup_role_withdrawal(role, key_id)
            .await?
            .is_some()
    })
}

/// Record the tombstone for one re-derived `(role, key_id)`. `canonical`
/// keeps its dedicated V095 table; every other role lands on V104.
///
/// # An existing tombstone SATISFIES the exclusion (PR #667 review P2)
///
/// The tombstone tables are keyed `(role, key_id)` and
/// `record_*_withdrawal` is idempotent only for a byte-identical re-record —
/// a second row with a DIFFERENT `authority_decision_digest` is a
/// [`Error::Conflict`]. Two distinct quorum-authorized proposals withdrawing
/// the same `(role, key_id)` is not exotic: an operator who retries a ceremony
/// with a fresh nonce produces exactly that. The repair sweep would then hit
/// `Conflict` on the second proposal and propagate it, so
/// [`rematerialize_role_withdrawals`] — the door whose entire purpose is to
/// rebuild an exclusion — would fail permanently, on every retry, over
/// evidence that is entirely valid.
///
/// So an already-materialized tombstone short-circuits: **first authorized
/// withdrawal wins**, deterministically, and the second is satisfied rather
/// than refused. Nothing weakens — a second authority cannot un-withdraw, and
/// a supersede tombstone's exemption names one successor key_id which its own
/// quorum authorized.
async fn record_projected_withdrawal(
    directory: &dyn FederationDirectory,
    role: &str,
    key_id: &str,
    authority_digest: &str,
) -> Result<(), Error> {
    if withdrawal_exists(directory, role, key_id).await? {
        return Ok(());
    }
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
    let candidates = directory
        .list_signed_key_records_since(None, u32::MAX)
        .await?;
    let proposal_digest = proposal.digest();
    let mut projected: Vec<(String, String)> = Vec::new();
    for candidate in &candidates {
        let key_id = &candidate.record.key_id;
        for (op, role) in withdrawal_ops_for(&candidate.record) {
            if canonical_withdrawal_payload_sha256(&op, key_id, None)? != proposal.payload_sha256 {
                continue;
            }
            if try_record_withdrawal(
                directory,
                &proposal_digest,
                &op,
                &role,
                key_id,
                roster_key_ids,
            )
            .await?
            {
                projected.push((role, key_id.clone()));
            }
        }
    }
    projected.sort();
    projected.dedup();
    Ok(projected)
}

/// Re-run the FULL #377 authority core for one `(proposal, op, key_id)` and,
/// if it holds, record the tombstone. `Ok(true)` iff a withdrawal was
/// authorized.
///
/// **A payload MATCH is not authority.** `accord_proposal` also holds
/// proposals this node accepted through its own local server-issued door —
/// including ones that never reached quorum, or have not yet — so the tally
/// runs here even when [`admit_replicated_accord_evidence`] already ran one.
///
/// A `canonical_withdrawal_authority_invalid` refusal means "this proposal
/// does not authorize this withdrawal", which is an ordinary state (a
/// rejected or in-flight proposal), so it returns `Ok(false)` rather than
/// failing the sweep. Any other error propagates: a backend fault must never
/// read as "nothing to project".
async fn try_record_withdrawal(
    directory: &dyn FederationDirectory,
    proposal_digest: &str,
    op: &str,
    role: &str,
    key_id: &str,
    roster_key_ids: &[String],
) -> Result<bool, Error> {
    let authority_digest = match super::admission::verify_withdrawal_authority_over_roster(
        directory,
        proposal_digest,
        op,
        key_id,
        roster_key_ids,
    )
    .await
    {
        Ok(digest) => digest,
        Err(e) if e.kind() == "canonical_withdrawal_authority_invalid" => return Ok(false),
        Err(e) => return Err(e),
    };
    record_projected_withdrawal(directory, role, key_id, &authority_digest).await?;
    Ok(true)
}

/// v31.1.0 (CIRISPersist#662, PR review P1) — **the ordering fix: project the
/// withdrawal for ONE key, from evidence this node already holds.**
///
/// # The gap this closes
///
/// [`project_role_withdrawals_for_proposal`] searches the keys the receiver
/// has *at that moment*. Planes replicate independently, so the accord
/// evidence for a withdrawal can legitimately arrive BEFORE the key it
/// withdraws — a fresh node catching up, or any anti-entropy round that
/// happens to order the `AccordQuorumEvidence` page ahead of the `Key` page.
/// The evidence then projects nothing, and when the key later lands its
/// admission gate consults `lookup_role_withdrawal`, finds nothing, and
/// confers the withdrawn role.
///
/// That is the design's own failure mode arriving through ORDERING rather
/// than through trust: the evidence is present, the derived state is silently
/// missing, and only an operator running
/// [`rematerialize_role_withdrawals`] would ever notice.
///
/// So the role-admission gates call this for the key in front of them, before
/// they consult the tombstone. It is a derivation, not an admission: it writes
/// only a tombstone the node re-tallied itself, from a proposal already in its
/// own state. `Ok(true)` iff a tombstone was materialized by this call.
///
/// # THE INVARIANT, and the closed set that has to keep it
///
/// Eight places read the withdrawal projection. Three are **pure reads** —
/// [`has_accord_conferred_role`](super::admission::has_accord_conferred_role),
/// [`is_infra_attest_effective`](super::admission::is_infra_attest_effective),
/// [`is_canonical_effective`](super::admission::is_canonical_effective) — and
/// they are correct **provided every write gate materializes first**. They can
/// be pure because they take a `key_id` that is already stored, and a stored
/// key reached storage through a gate.
///
/// So the invariant is not a count, it is: *no `federation_keys` row claiming
/// an accord-conferred role is admitted **through a role-admission gate**
/// without this call running for that `(role, key_id)` first.*
///
/// The qualifier is load-bearing and is stated rather than assumed. The
/// genesis-trusted seed paths (`seed_genesis_accord_holders` and the reanchor
/// door) insert directly and run no role gate at all — deliberately, since
/// those rows ARE the baked constitutional root, and the roster they
/// constitute is what authorizes withdrawals in the first place. A withdrawal
/// of a genesis accord holder is therefore not a case this projection covers,
/// and pretending otherwise here would be a doc that reads as a guarantee
/// while the code offers none.
///
/// The write gates that must keep it, in `admission.rs`:
///
/// 1. `check_canonical_role_admission_over_roster` — the production canonical gate.
/// 2. `check_canonical_role_admission_over_roster_with_custody_root` — the
///    `test-anchor` mesh-simulation twin.
/// 3. `check_canonical_role_admission_over_roster_legacy` — the pre-floor test twin.
/// 4. `check_infra_attest_role_admission_over_roster`.
/// 5. `check_accord_role_admission_over_roster` — the role-generic gate, and
///    therefore every CO_STEWARD_ROLE and every accord-co-scrubbed
///    `identity_type` that routes through it.
///
/// A sixth gate added without this call is a silent hole of exactly the shape
/// (5) was: the review found (5) precisely because (1) and (4) had been fixed
/// and it had not. Enumerated here rather than counted, so a new gate is a
/// visible omission.
///
/// Cheap where it runs: the gates fast-path out unless the row actually claims
/// the gated role, so this is on the accord-conferral path only, never on
/// ordinary key registration. The lookup is by payload digest (see
/// [`FederationDirectory::list_accord_proposals_by_payload`](super::FederationDirectory::list_accord_proposals_by_payload))
/// rather than a scan of all evidence, because an attacker chooses when a
/// role-claiming key is offered and must not be able to choose an O(accord
/// history) read with it.
pub async fn project_role_withdrawal_for_key(
    directory: &dyn FederationDirectory,
    role: &str,
    key_id: &str,
    roster_key_ids: &[String],
) -> Result<bool, Error> {
    // Already materialized — the common case, and the cheapest exit. It is
    // also what keeps this off the hot path: after the first admission of a
    // withdrawn key, every later offer costs one indexed point read.
    if withdrawal_exists(directory, role, key_id).await? {
        return Ok(false);
    }

    let op = if role == identity_type::CANONICAL {
        OP_WITHDRAW_CANONICAL.to_owned()
    } else if role == roles::INFRA_ATTEST {
        OP_WITHDRAW_INFRA_ATTEST.to_owned()
    } else {
        op_withdraw_role(role)
    };
    // The digest is computed HERE, from `(op, key_id)`, and then used to LOOK
    // UP rather than to filter a scan. Both properties matter: computing it
    // locally is what stops a sender naming the target, and looking it up is
    // what stops an attacker turning each role-claiming key offer into a read
    // of the whole accord history plus one participation query per proposal.
    let expected = canonical_withdrawal_payload_sha256(&op, key_id, None)?;

    for proposal in directory
        .list_accord_proposals_by_payload(&expected)
        .await?
    {
        if try_record_withdrawal(
            directory,
            &proposal.digest(),
            &op,
            role,
            key_id,
            roster_key_ids,
        )
        .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
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
/// determinism rule AND the [`AccordQuorumEvidence::evidence_at`] derivation
/// live in ONE place: three backends each spelling those their own way is
/// exactly the preserve-set ≢ verified-set shape CIRISPersist#541 paid for,
/// one plane over.
///
/// # The SELECTED instant is returned, never a recomputed one (PR review P1)
///
/// Each backend computes `max(created_at, max(server_arrival_at))` in SQL to
/// filter and order the page, then passes the value it selected on with each
/// proposal. This function must NOT recompute it from the participations it
/// loads a moment later, and the reason is a torn read:
///
/// A vote can land between the page query and this assembly. Recomputing would
/// then return an `evidence_at` LATER than the one the page was selected with
/// — so a consumer resuming from the last bundle's timestamp would skip every
/// proposal whose selected instant fell in the gap and was cut by the page
/// limit. Those proposals are never re-offered, and on this plane that means
/// withdrawal evidence lost to a race.
///
/// Returning the selected instant fails the other way: the bundle may carry a
/// vote that arrived after selection, and will simply be re-offered on the
/// next page because that vote's arrival advanced its visibility instant past
/// the cursor. At-least-once, which is the only safe direction for an
/// exclusion plane.
pub async fn assemble_evidence_page(
    directory: &dyn FederationDirectory,
    proposals: Vec<(
        super::accord_quorum::StoredProposal,
        chrono::DateTime<chrono::Utc>,
    )>,
) -> Result<Vec<AccordQuorumEvidence>, Error> {
    let mut out = Vec::with_capacity(proposals.len());
    for (stored, evidence_at) in proposals {
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
            evidence_at,
        });
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────
// v31.1.0 (CIRISPersist#655 / CIRISPersist#662) — the carriage witnesses.
//
// Run against `&dyn FederationDirectory` on memory, sqlite AND postgres. The
// cross-node legs need TWO directories of the SAME backend: the property under
// test is "a node that never saw the tombstone rebuilds it", and a fixture
// that stood node B up on a different backend would be proving something
// weaker on the one that matters.
// ─────────────────────────────────────────────────────────────────────
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod carriage_tests {
    use super::*;
    use crate::federation::accord_quorum::test_fixtures::signed_participation;
    use crate::federation::admission::{
        is_infra_attest, is_infra_attest_effective, withdraw_infra_attest_role_over_roster,
    };
    use crate::federation::operational::test_support::{
        register_accord_holder, signed_canonical_record_with_roles, Identity,
        PLACEHOLDER_SUBJECT_ED25519_BASE64,
    };
    use crate::federation::SignedKeyRecord;
    use ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    use ciris_verify_core::accord_live_quorum::{AccordAction, Vote};

    /// One node's fixture state. Both nodes in a pair resolve the SAME roster
    /// — the PRODUCTION accord holders (A1/B1/C1), registered under
    /// deterministic test hybrid keys.
    ///
    /// Using the real roster rather than a synthetic one is load-bearing here,
    /// not tidiness: the withdrawal projection that the role-admission gates
    /// invoke resolves its roster from `accord_holder_roster_key_ids()` (as
    /// production does), so a fixture with a side roster would leave the
    /// ordering leg below silently unexercised.
    struct Node {
        holders: Vec<Identity>,
        roster: Vec<ThresholdMember>,
        roster_key_ids: Vec<String>,
    }

    /// Seed the accord family (A1/B1/C1 under test hybrid keys) — one roster
    /// for both the `infra:attest` ADD co-scrub and the destructive quorum,
    /// exactly as production has it.
    async fn seed_node(dir: &dyn FederationDirectory) -> Node {
        let holders: Vec<Identity> = accord_holder_roster_key_ids()
            .iter()
            .map(|k| Identity::new(k))
            .collect();
        for h in &holders {
            register_accord_holder(dir, h)
                .await
                .expect("register accord holder");
        }
        let roster: Vec<ThresholdMember> = holders.iter().map(|h| h.member()).collect();
        Node {
            holders,
            roster,
            roster_key_ids: accord_holder_roster_key_ids(),
        }
    }

    /// A 2-of-3 co-scrubbed pipeline record carrying `infra:attest`.
    fn infra_attest_record(node: &Node, key_id: &str) -> SignedKeyRecord {
        SignedKeyRecord {
            record: signed_canonical_record_with_roles(
                key_id,
                identity_type::NODE,
                PLACEHOLDER_SUBJECT_ED25519_BASE64,
                None,
                vec![roles::INFRA_ATTEST.to_owned()],
                serde_json::json!({ "key_id": key_id }),
                &[&node.holders[0], &node.holders[1]],
            ),
        }
    }

    /// Admit a 2-of-3 co-scrubbed pipeline key carrying `infra:attest`.
    async fn confer_infra_attest(dir: &dyn FederationDirectory, node: &Node, key_id: &str) {
        dir.put_public_key(infra_attest_record(node, key_id))
            .await
            .expect("2-of-3 co-scrubbed infra:attest pipeline must be ADMITTED");
    }

    /// Seed a STORED proposal committing to `(op, target)` plus one signed YES
    /// per holder index in `yes_voters`. Returns the proposal digest.
    async fn seed_quorum(
        dir: &dyn FederationDirectory,
        node: &Node,
        op: &str,
        target: &str,
        yes_voters: &[usize],
        nonce: &str,
    ) -> String {
        let payload_sha256 =
            canonical_withdrawal_payload_sha256(op, target, None).expect("payload sha256");
        let proposal = AccordProposal {
            family_key_id: HUMANITY_ACCORD_FAMILY_KEY_ID.to_owned(),
            action: AccordAction::RosterChange,
            nonce: nonce.to_owned(),
            window_until: "2031-01-01T00:00:00Z".to_owned(),
            prior_family_digest: "prior-family-digest".to_owned(),
            payload_sha256,
        };
        dir.issue_accord_nonce(HUMANITY_ACCORD_FAMILY_KEY_ID, nonce)
            .await
            .expect("issue nonce");
        dir.put_accord_proposal(proposal.clone(), None)
            .await
            .expect("put proposal");
        for &i in yes_voters {
            dir.put_accord_participation(
                signed_participation(&node.holders[i], &proposal, Vote::Yes),
                &node.roster,
            )
            .await
            .expect("put participation");
        }
        proposal.digest()
    }

    /// **THE WITNESS.** A withdrawal that exists on node A reaches node B
    /// without the withdrawal row ever crossing the wire — because B re-tallies
    /// the evidence and re-derives its own tombstone.
    async fn run_carriage_matrix(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        tag: &str,
    ) {
        let na = seed_node(a).await;
        let nb = seed_node(b).await;
        // Both nodes resolve the production roster from their OWN state. If
        // this ever stopped holding, every "B re-derived it" assertion below
        // would be measuring a roster mismatch instead.
        assert_eq!(na.roster_key_ids, nb.roster_key_ids);

        let ci = format!("ci-{tag}");
        confer_infra_attest(a, &na, &ci).await;
        confer_infra_attest(b, &nb, &ci).await;
        assert!(is_infra_attest_effective(a, &ci).await.unwrap());
        assert!(is_infra_attest_effective(b, &ci).await.unwrap());

        // ── A withdraws locally, through the existing #424 destructive op. ──
        let digest = seed_quorum(
            a,
            &na,
            OP_WITHDRAW_INFRA_ATTEST,
            &ci,
            &[0, 1],
            &format!("nw-{tag}"),
        )
        .await;
        withdraw_infra_attest_role_over_roster(a, &ci, &digest, &na.roster_key_ids)
            .await
            .expect("a genuine strict-majority withdraw must succeed on A");
        assert!(!is_infra_attest_effective(a, &ci).await.unwrap());

        // ── (1) THE DEFECT, stated as state: B holds the key, holds the role,
        //        and has no way to learn it was withdrawn. ──
        assert!(
            b.lookup_role_withdrawal(roles::INFRA_ATTEST, &ci)
                .await
                .unwrap()
                .is_none(),
            "(1) B must start with no tombstone — that IS the defect"
        );
        assert!(
            is_infra_attest_effective(b, &ci).await.unwrap(),
            "(1) so B still treats a withdrawn build-signing key as a trust root"
        );

        // ── (2) SERVE the evidence from A. ──
        let page = a
            .list_signed_accord_quorum_evidence_since(None, u32::MAX)
            .await
            .unwrap();
        let bundle = page
            .iter()
            .find(|e| e.proposal.digest() == digest)
            .expect("(2) the withdrawal's evidence must be servable")
            .clone();
        assert_eq!(bundle.participations.len(), 2, "(2) both YES votes ride");
        // The bundle is EVIDENCE. Nothing derived travels with it: no verdict
        // bool, no tombstone columns. A reader that wanted the answer without
        // computing it would find nothing to read.
        let wire = serde_json::to_string(&bundle).expect("bundle serializes");
        for verdict_field in ["withdrawn_at", "authorized", "authority_decision_digest"] {
            assert!(
                !wire.contains(verdict_field),
                "(2) {verdict_field:?} must NOT ride the wire — the receiver derives it: {wire}"
            );
        }
        // Deterministic ordering, so two backends serving the same bundle
        // serialize the same bytes.
        let members: Vec<&str> = bundle
            .participations
            .iter()
            .map(|p| p.member_id.as_str())
            .collect();
        let mut sorted = members.clone();
        sorted.sort_unstable();
        assert_eq!(members, sorted, "(2) participations are member_id-ordered");

        // ── (3) ADMIT on B. The re-tally is the gate. ──
        let admission =
            admit_replicated_accord_evidence_over_roster(b, &bundle, &nb.roster_key_ids)
                .await
                .expect("(3) a strict-majority bundle must be admitted");
        assert_eq!(admission.proposal_digest, digest);
        assert_eq!(admission.yes, 2, "(3) B counted the votes itself");
        assert_eq!(admission.threshold, 2, "(3) strict majority of 3");
        assert_eq!(admission.roster_size, 3);
        assert_eq!(
            admission.withdrawals_projected,
            vec![(roles::INFRA_ATTEST.to_owned(), ci.clone())],
            "(3) the admit re-derived exactly the one tombstone its evidence supports"
        );

        // ── (4) B re-derived its OWN tombstone, and it points at the same
        //        authority A's does. ──
        let w = b
            .lookup_role_withdrawal(roles::INFRA_ATTEST, &ci)
            .await
            .unwrap()
            .expect("(4) B must now hold a locally-derived tombstone");
        assert_eq!(
            w.authority_decision_digest, digest,
            "(4) anchored to the proposal B re-tallied"
        );
        assert!(
            is_infra_attest(b, &ci).await.unwrap(),
            "(4) the stored row is untouched — tombstones never mutate rows"
        );
        assert!(
            !is_infra_attest_effective(b, &ci).await.unwrap(),
            "(4) but the EFFECTIVE read flips false, which is the whole point"
        );

        // ── (5) Idempotent replay: a carrier re-offering the same bundle
        //        changes nothing. ──
        let again = admit_replicated_accord_evidence_over_roster(b, &bundle, &nb.roster_key_ids)
            .await
            .expect("(5) replay must be idempotent");
        assert_eq!(again.participations_admitted, 0, "(5) nothing new landed");
        assert_eq!(again.withdrawals_projected.len(), 1);

        // ── (6) THE REPAIR DOOR. The exclusion is rebuildable from evidence
        //        alone — this is the property #655/#662 are about. ──
        let rebuilt = rematerialize_role_withdrawals_over_roster(b, &nb.roster_key_ids)
            .await
            .expect("(6) the repair sweep must run");
        assert!(
            rebuilt.contains(&(roles::INFRA_ATTEST.to_owned(), ci.clone())),
            "(6) the sweep re-derives the tombstone from stored evidence: {rebuilt:?}"
        );

        // ── (7) BELOW QUORUM IS REFUSED, and nothing lands. ──
        let ci_weak = format!("weak-{tag}");
        confer_infra_attest(a, &na, &ci_weak).await;
        confer_infra_attest(b, &nb, &ci_weak).await;
        let weak_digest = seed_quorum(
            a,
            &na,
            OP_WITHDRAW_INFRA_ATTEST,
            &ci_weak,
            &[0],
            &format!("wk-{tag}"),
        )
        .await;
        let weak = a
            .list_signed_accord_quorum_evidence_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|e| e.proposal.digest() == weak_digest)
            .expect("(7) a 1-of-3 bundle is still servable");
        let err = admit_replicated_accord_evidence_over_roster(b, &weak, &nb.roster_key_ids)
            .await
            .expect_err("(7) one YES is below a strict majority of three");
        assert_eq!(err.kind(), "accord_evidence_unverified", "{err}");
        assert!(
            b.get_accord_proposal(&weak_digest).await.unwrap().is_none(),
            "(7) fail-closed: a refused bundle stores no proposal"
        );
        assert!(
            b.lookup_role_withdrawal(roles::INFRA_ATTEST, &ci_weak)
                .await
                .unwrap()
                .is_none(),
            "(7) and projects no tombstone"
        );
        assert!(is_infra_attest_effective(b, &ci_weak).await.unwrap());

        // ── (8) STRIPPED SIGNATURES ARE NOT A SHORTCUT. A bundle that ASSERTS
        //        authority — `authority_signature: {"authorized": true}` — and
        //        carries no verifiable votes. A receiver that trusted the
        //        sender would see a well-formed accord decision; one that
        //        re-tallies sees zero. ──
        let ci_forge = format!("forge-{tag}");
        confer_infra_attest(b, &nb, &ci_forge).await;
        let forged = AccordQuorumEvidence {
            proposal: AccordProposal {
                family_key_id: HUMANITY_ACCORD_FAMILY_KEY_ID.to_owned(),
                action: AccordAction::RosterChange,
                nonce: format!("fg-{tag}"),
                window_until: "2031-01-01T00:00:00Z".to_owned(),
                prior_family_digest: "prior-family-digest".to_owned(),
                payload_sha256: canonical_withdrawal_payload_sha256(
                    OP_WITHDRAW_INFRA_ATTEST,
                    &ci_forge,
                    None,
                )
                .unwrap(),
            },
            authority_signature: Some(serde_json::json!({ "authorized": true })),
            participations: Vec::new(),
            evidence_at: chrono::Utc::now(),
        };
        let ferr = admit_replicated_accord_evidence_over_roster(b, &forged, &nb.roster_key_ids)
            .await
            .expect_err("(8) an unsigned assertion of authority must be REFUSED");
        assert_eq!(ferr.kind(), "accord_evidence_unverified", "{ferr}");
        assert!(
            is_infra_attest_effective(b, &ci_forge).await.unwrap(),
            "(8) and the forged withdrawal excluded nothing"
        );

        // ── (9) OUT-OF-FAMILY EVIDENCE IS REFUSED, **and says so**.
        //
        //   The refusal alone is not the property. Mutation testing showed that
        //   deleting the family check leaves this bundle refused regardless:
        //   `AccordParticipation::verify` binds `family_key_id` inside each
        //   signature, so re-pointing the proposal invalidates every vote and
        //   the tally reaches zero by another route. An `assert_eq!(kind, ..)`
        //   here passed with the gate removed — a check that could not fail.
        //
        //   So this pins the DIAGNOSIS, which is the only thing the enumerated
        //   gate actually adds: an operator must not be told "0 YES votes"
        //   about a bundle whose votes are all present and valid.
        let mut off_family = bundle.clone();
        off_family.proposal.family_key_id = "not-the-humanity-accord".to_owned();
        let oerr = admit_replicated_accord_evidence_over_roster(b, &off_family, &nb.roster_key_ids)
            .await
            .expect_err("(9) only the HUMANITY_ACCORD family may authorize");
        assert_eq!(oerr.kind(), "accord_evidence_unverified", "{oerr}");
        let omsg = format!("{oerr}");
        assert!(
            omsg.contains("not the HUMANITY_ACCORD family"),
            "(9) the refusal must name the family fault, not report an empty tally: {omsg}"
        );

        // ── (10) A STORED PROPOSAL IS NOT AUTHORITY. A proposal that reached
        //        this node through its own local server-issued door, committing
        //        to a withdrawal but carrying NO votes, must project nothing.
        //        Without the inner re-tally, a payload MATCH alone would write
        //        the tombstone — authority by coincidence of digest. ──
        let ci_bare = format!("bare-{tag}");
        confer_infra_attest(b, &nb, &ci_bare).await;
        seed_quorum(
            b,
            &nb,
            OP_WITHDRAW_INFRA_ATTEST,
            &ci_bare,
            &[],
            &format!("br-{tag}"),
        )
        .await;
        let swept = rematerialize_role_withdrawals_over_roster(b, &nb.roster_key_ids)
            .await
            .expect("(10) the sweep must skip an unauthorized proposal, not fail on it");
        assert!(
            !swept.contains(&(roles::INFRA_ATTEST.to_owned(), ci_bare.clone())),
            "(10) a quorum-less proposal must project NOTHING: {swept:?}"
        );
        assert!(
            is_infra_attest_effective(b, &ci_bare).await.unwrap(),
            "(10) and the key keeps its role"
        );

        // ── (11) THE ORDERING LEG (PR #667 review P1). Evidence can arrive
        //        BEFORE the key it withdraws — the planes replicate
        //        independently. The projection then matches no candidate, and
        //        a design that only projects at admit-time would confer the
        //        withdrawn role when the key finally lands. ──
        let ci_late = format!("late-{tag}");
        let late_digest = seed_quorum(
            a,
            &na,
            OP_WITHDRAW_INFRA_ATTEST,
            &ci_late,
            &[0, 1],
            &format!("lt-{tag}"),
        )
        .await;
        let late_bundle = a
            .list_signed_accord_quorum_evidence_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|e| e.proposal.digest() == late_digest)
            .expect("(11) evidence for a key nobody holds is still servable");
        let late_admission =
            admit_replicated_accord_evidence_over_roster(b, &late_bundle, &nb.roster_key_ids)
                .await
                .expect("(11) the bundle is quorum-bearing regardless of who holds the key");
        assert!(
            late_admission.withdrawals_projected.is_empty(),
            "(11) nothing to project yet — B has never seen this key"
        );
        // ...and NOW the key arrives, fully co-scrubbed, exactly as anti-entropy
        // would deliver it.
        let err_late = b
            .put_public_key(infra_attest_record(&nb, &ci_late))
            .await
            .expect_err("(11) a key whose withdrawal we already hold evidence for must be REFUSED");
        assert_eq!(
            err_late.kind(),
            "infra_attest_role_withdrawn",
            "(11) the gate must materialize the tombstone before consulting it: {err_late}"
        );
        assert!(
            !is_infra_attest_effective(b, &ci_late).await.unwrap(),
            "(11) and the role is not effective by any route"
        );

        // ── (12) THE OTHER ROLE SURFACE (PR #667 round-2 review P1).
        //
        //   `claims_role` is `identity_type ∪ capability_roles`, and the
        //   projection enumerated `capability_roles` alone — so a role claimed
        //   through `identity_type` could be withdrawn by a real quorum and
        //   the tombstone would never materialize. `identity_type` is the only
        //   field here that is authority-bearing while shaped like a label,
        //   which is why it keeps falling out of hand-written enumerations;
        //   this leg exists so the next omission is a red test.
        //
        //   Driven through the ROLE-GENERIC gate, which is also the third
        //   consulting site the same review found unmaterialized. ──
        let ci_idt = format!("idt-{tag}");
        let generic_role = identity_type::REGISTRY;
        let idt_record = SignedKeyRecord {
            record: signed_canonical_record_with_roles(
                &ci_idt,
                generic_role, // claimed via identity_type, NOT capability_roles
                PLACEHOLDER_SUBJECT_ED25519_BASE64,
                None,
                Vec::new(),
                serde_json::json!({ "key_id": ci_idt }),
                &[&nb.holders[0], &nb.holders[1]],
            ),
        };
        assert!(
            idt_record.record.capability_roles.is_empty(),
            "(12) the fixture must claim through identity_type ONLY, or it proves nothing"
        );
        assert!(idt_record.record.claims_role(generic_role));

        // Evidence first, key second — the same ordering as (11).
        let idt_digest = seed_quorum(
            a,
            &na,
            &crate::federation::admission::op_withdraw_role(generic_role),
            &ci_idt,
            &[0, 1],
            &format!("id-{tag}"),
        )
        .await;
        let idt_bundle = a
            .list_signed_accord_quorum_evidence_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|e| e.proposal.digest() == idt_digest)
            .expect("(12) generic-role withdrawal evidence is servable");
        admit_replicated_accord_evidence_over_roster(b, &idt_bundle, &nb.roster_key_ids)
            .await
            .expect("(12) the bundle carries a strict majority");
        let idt_err = b
            .put_public_key(idt_record)
            .await
            .expect_err("(12) an identity_type-claimed withdrawn role must be REFUSED");
        assert_eq!(
            idt_err.kind(),
            "role_withdrawn",
            "(12) the generic gate must materialize before consulting: {idt_err}"
        );

        // The leg above drives the identity_type claim through the GATE, which
        // resolves the op from its `role` argument — so it exercises the
        // ordering fix but NOT `withdrawal_ops_for`, the enumeration that had
        // the bug. Mutation testing caught exactly that: reverting
        // `claimed_roles` to `capability_roles` alone left the leg above green.
        //
        // The enumeration is what the ADMIT-TIME projection and the repair
        // sweep walk, so the case that measures it is the reverse ordering:
        // an identity_type-claiming key ALREADY PRESENT when its withdrawal
        // evidence arrives.
        let ci_idt2 = format!("idt2-{tag}");
        b.put_public_key(SignedKeyRecord {
            record: signed_canonical_record_with_roles(
                &ci_idt2,
                generic_role,
                PLACEHOLDER_SUBJECT_ED25519_BASE64,
                None,
                Vec::new(),
                serde_json::json!({ "key_id": ci_idt2 }),
                &[&nb.holders[0], &nb.holders[1]],
            ),
        })
        .await
        .expect("(12) an identity_type-claimed co-steward key is admissible while un-withdrawn");
        let idt2_digest = seed_quorum(
            a,
            &na,
            &crate::federation::admission::op_withdraw_role(generic_role),
            &ci_idt2,
            &[0, 1],
            &format!("i2-{tag}"),
        )
        .await;
        let idt2_bundle = a
            .list_signed_accord_quorum_evidence_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|e| e.proposal.digest() == idt2_digest)
            .expect("(12) servable");
        let idt2_admission =
            admit_replicated_accord_evidence_over_roster(b, &idt2_bundle, &nb.roster_key_ids)
                .await
                .expect("(12) admitted");
        assert_eq!(
            idt2_admission.withdrawals_projected,
            vec![(generic_role.to_owned(), ci_idt2.clone())],
            "(12) the admit-time projection must enumerate the identity_type surface too"
        );
        assert!(
            b.lookup_role_withdrawal(generic_role, &ci_idt2)
                .await
                .unwrap()
                .is_some(),
            "(12) and the tombstone exists"
        );

        // And the same claim through `capability_roles` on an ALREADY-PRESENT
        // key: the admit-time projection must see it on that surface too.
        let ci_cap = format!("cap-{tag}");
        b.put_public_key(SignedKeyRecord {
            record: signed_canonical_record_with_roles(
                &ci_cap,
                identity_type::NODE,
                PLACEHOLDER_SUBJECT_ED25519_BASE64,
                None,
                vec![generic_role.to_owned()],
                serde_json::json!({ "key_id": ci_cap }),
                &[&nb.holders[0], &nb.holders[1]],
            ),
        })
        .await
        .expect("(12) a capability_roles claim of the same role is admissible");
        let cap_digest = seed_quorum(
            a,
            &na,
            &crate::federation::admission::op_withdraw_role(generic_role),
            &ci_cap,
            &[0, 1],
            &format!("cp-{tag}"),
        )
        .await;
        let cap_bundle = a
            .list_signed_accord_quorum_evidence_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|e| e.proposal.digest() == cap_digest)
            .expect("(12) servable");
        let cap_admission =
            admit_replicated_accord_evidence_over_roster(b, &cap_bundle, &nb.roster_key_ids)
                .await
                .expect("(12) admitted");
        assert_eq!(
            cap_admission.withdrawals_projected,
            vec![(generic_role.to_owned(), ci_cap.clone())],
            "(12) the admit-time projection covers capability_roles as well"
        );

        // ── (13) A SECOND AUTHORIZED WITHDRAWAL DOES NOT BREAK THE REPAIR
        //        DOOR (PR #667 round-2 review P2). An operator who retries a
        //        ceremony with a fresh nonce produces two valid proposals for
        //        one `(role, key_id)`; the tombstone table is keyed on that
        //        pair, so the second `record_*` is a `Conflict`. Propagating it
        //        made `rematerialize_role_withdrawals` — the door whose whole
        //        purpose is rebuilding an exclusion — fail permanently over
        //        evidence that is entirely valid. ──
        let retry_digest = seed_quorum(
            b,
            &nb,
            OP_WITHDRAW_INFRA_ATTEST,
            &ci,
            &[0, 1],
            &format!("rt-{tag}"),
        )
        .await;
        assert_ne!(retry_digest, digest, "(13) a genuinely distinct proposal");
        let swept_again = rematerialize_role_withdrawals_over_roster(b, &nb.roster_key_ids)
            .await
            .expect("(13) the repair sweep must survive a redundant valid withdrawal");
        assert!(
            swept_again.contains(&(roles::INFRA_ATTEST.to_owned(), ci.clone())),
            "(13) and still report the exclusion as in place: {swept_again:?}"
        );
        assert!(!is_infra_attest_effective(b, &ci).await.unwrap());
    }

    /// PR #667 round-3 review P2 — **an `_over_roster` gate projects against
    /// the roster it was GIVEN.**
    ///
    /// The late projection first re-derived against `accord_holder_roster_key_ids()`
    /// — the production roster — inside gates whose whole contract is that the
    /// caller supplies one. With both rosters present that is a live hole:
    /// withdrawal evidence signed by the INJECTED roster projects no tombstone,
    /// and the injected-roster co-scrub then admits the withdrawn role.
    ///
    /// So this uses a roster that is genuinely NOT the production one. A
    /// fixture whose injected roster happens to equal the ambient one cannot
    /// tell the two apart — which is exactly why the first version of the
    /// identity-type witness passed against a broken enumeration.
    async fn run_injected_roster_matrix(dir: &dyn FederationDirectory, tag: &str) {
        let holders: Vec<Identity> = (0..3)
            .map(|i| Identity::new(&format!("ir{i}-{tag}")))
            .collect();
        for h in &holders {
            register_accord_holder(dir, h)
                .await
                .expect("register injected holder");
        }
        let roster: Vec<ThresholdMember> = holders.iter().map(|h| h.member()).collect();
        let roster_key_ids: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();
        // The difference this witness turns on.
        assert_ne!(
            roster_key_ids,
            accord_holder_roster_key_ids(),
            "the injected roster must NOT be the production one, or this proves nothing"
        );

        let node = Node {
            holders,
            roster,
            roster_key_ids: roster_key_ids.clone(),
        };
        let role = identity_type::REGISTRY;
        let subject = format!("ir-sub-{tag}");
        let offer = signed_canonical_record_with_roles(
            &subject,
            role,
            PLACEHOLDER_SUBJECT_ED25519_BASE64,
            None,
            Vec::new(),
            serde_json::json!({ "key_id": subject }),
            &[&node.holders[0], &node.holders[1]],
        );

        // Un-withdrawn: the injected-roster co-scrub admits it.
        crate::federation::admission::check_accord_role_admission_over_roster(
            dir,
            &offer,
            role,
            &roster_key_ids,
        )
        .await
        .expect("a co-scrub by the INJECTED roster must admit while un-withdrawn");

        // Evidence signed by the INJECTED roster withdraws the role.
        seed_quorum(
            dir,
            &node,
            &crate::federation::admission::op_withdraw_role(role),
            &subject,
            &[0, 1],
            &format!("ir-{tag}"),
        )
        .await;

        // The gate must now refuse — which it can only do by having projected
        // against the roster it was handed.
        let err = crate::federation::admission::check_accord_role_admission_over_roster(
            dir,
            &offer,
            role,
            &roster_key_ids,
        )
        .await
        .expect_err("evidence signed by the injected roster must exclude under that roster");
        assert_eq!(err.kind(), "role_withdrawn", "{err}");
        assert!(
            dir.lookup_role_withdrawal(role, &subject)
                .await
                .unwrap()
                .is_some(),
            "and the tombstone was materialized from the injected roster's own quorum"
        );
    }

    /// PR #667 review P1 — **the cursor must advance when a vote lands.**
    ///
    /// A bundle is an aggregate, so a cursor pinned to the proposal's
    /// immutable `created_at` would let a peer that read it pre-quorum skip the
    /// quorum-bearing version forever.
    async fn run_cursor_advance_matrix(dir: &dyn FederationDirectory, tag: &str) {
        let node = seed_node(dir).await;
        let target = format!("adv-{tag}");
        confer_infra_attest(dir, &node, &target).await;

        // One vote — below quorum, but stored and servable.
        let digest = seed_quorum(
            dir,
            &node,
            OP_WITHDRAW_INFRA_ATTEST,
            &target,
            &[0],
            &format!("ad-{tag}"),
        )
        .await;
        let first = dir
            .list_signed_accord_quorum_evidence_since(None, u32::MAX)
            .await
            .unwrap()
            .into_iter()
            .find(|e| e.proposal.digest() == digest)
            .expect("the one-vote bundle is servable");
        assert_eq!(first.participations.len(), 1);

        // A peer reads to here and pins its cursor — the ordinary thing to do.
        let cursor = first.evidence_at;
        assert!(
            !dir.list_signed_accord_quorum_evidence_since(Some(cursor), u32::MAX)
                .await
                .unwrap()
                .iter()
                .any(|e| e.proposal.digest() == digest),
            "a bundle with nothing new must not be re-offered"
        );

        // The second vote lands. The bundle now says something it did not say
        // before, so it must reappear PAST the peer's cursor.
        let proposal = dir
            .get_accord_proposal(&digest)
            .await
            .unwrap()
            .expect("stored")
            .proposal;
        dir.put_accord_participation(
            signed_participation(&node.holders[1], &proposal, Vote::Yes),
            &node.roster,
        )
        .await
        .expect("the second YES lands");

        let resumed = dir
            .list_signed_accord_quorum_evidence_since(Some(cursor), u32::MAX)
            .await
            .unwrap();
        let again = resumed
            .iter()
            .find(|e| e.proposal.digest() == digest)
            .expect("the quorum-bearing version must be re-offered past the old cursor");
        assert_eq!(again.participations.len(), 2, "and it carries both votes");
        assert!(
            again.evidence_at > cursor,
            "the bundle's visibility instant advanced with the vote"
        );
    }

    /// CIRISPersist#655 — the revocation plane's serve cursor and its
    /// wire-index entry, on one directory (the receive side of this plane was
    /// already correct; only serving was missing).
    async fn run_revocation_cursor_matrix(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::tier_ingest::test_support::{hybrid_pubkeys, seal_revocation};

        let subject = format!("rv{tag}-subject");
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(&subject);
        let now = chrono::Utc::now();
        dir.put_public_key(SignedKeyRecord {
            record: crate::federation::KeyRecord {
                key_id: subject.clone(),
                pubkey_ed25519_base64: ed_pk,
                pubkey_ml_dsa_65_base64: mldsa_pk,
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: crate::federation::types::identity_type::USER.to_owned(),
                identity_ref: subject.clone(),
                valid_from: now,
                valid_until: None,
                registration_envelope: serde_json::json!({ "id": subject }),
                original_content_hash: "deadbeef".to_owned(),
                scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
                scrub_signature_pqc: None,
                scrub_key_id: subject.clone(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect("register the revocation subject");

        // A SELF-revocation: `check_revocation_authority` passes it untouched,
        // so this witness measures the carriage rather than the moderation
        // authority plane (which has its own witnesses).
        let revocation_id = uuid::Uuid::new_v4().to_string();
        let row = seal_revocation(crate::federation::types::Revocation {
            revocation_id: revocation_id.clone(),
            revoked_key_id: subject.clone(),
            revoking_key_id: subject.clone(),
            reason: Some("compromise".to_owned()),
            revoked_at: now,
            effective_at: now,
            revocation_envelope: serde_json::json!({ "revoked_key_id": subject }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: subject.clone(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            observed_region: crate::federation::verify_coord::region::US.to_owned(),
            revoked_after: None,
            persist_row_hash: String::new(),
        });
        dir.put_revocation(crate::federation::SignedRevocation { revocation: row })
            .await
            .expect("the self-revocation must be admitted");

        // ── The cursor exists and finds the row. ──
        let all = dir
            .list_signed_revocations_since(None, u32::MAX)
            .await
            .expect("the exclusion plane must be servable");
        let served = all
            .iter()
            .find(|r| r.revocation.revocation_id == revocation_id)
            .expect("the stored revocation must be served");
        assert_eq!(served.revocation.revoked_key_id, subject);

        // ── The cursor is a cursor: `since` at the row's own position excludes
        //    it, so a caller resuming from its last page does not re-read. ──
        let position = served.admitted_at;
        let after = dir
            .list_signed_revocations_since(Some(position), u32::MAX)
            .await
            .unwrap();
        assert!(
            !after
                .iter()
                .any(|r| r.revocation.revocation_id == revocation_id),
            "`since` is exclusive on the admission position"
        );

        // ── PR #667 round-3 P1 — **THE LATE-REPLICATED OLD REVOCATION.**
        //
        //   A revocation SIGNED well before the consumer's cursor, admitted
        //   after it. Keyed on the producer's `scrub_timestamp` this row sorts
        //   behind the cursor and is never served again — stored, and
        //   permanently invisible. That is #655's own defect (an exclusion that
        //   cannot reach a peer) re-entering through the cursor KEY.
        //
        //   Nothing else stops it: `check_revocation_scrub_skew` is a ceiling
        //   only, so an old signed instant is admissible, and the anti-rollback
        //   latch is per-`revoked_key_id`, so it is silent about a first
        //   revocation for a subject this node has not seen. Both are asserted
        //   here, so if either ever grows a floor this witness says so rather
        //   than passing for a new reason. ──
        let late_subject = format!("rv{tag}-late");
        let (late_ed, late_mldsa) = hybrid_pubkeys(&late_subject);
        let old_instant = now - chrono::Duration::days(60);
        dir.put_public_key(SignedKeyRecord {
            record: crate::federation::KeyRecord {
                key_id: late_subject.clone(),
                pubkey_ed25519_base64: late_ed,
                pubkey_ml_dsa_65_base64: late_mldsa,
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: crate::federation::types::identity_type::USER.to_owned(),
                identity_ref: late_subject.clone(),
                valid_from: old_instant,
                valid_until: None,
                registration_envelope: serde_json::json!({ "id": late_subject }),
                original_content_hash: "deadbeef".to_owned(),
                scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
                scrub_signature_pqc: None,
                scrub_key_id: late_subject.clone(),
                scrub_timestamp: old_instant,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                capability_roles: Vec::new(),
                attestation_evidence: None,
                consent_role: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect("register the late subject");

        let late_id = uuid::Uuid::new_v4().to_string();
        let late_row = seal_revocation(crate::federation::types::Revocation {
            revocation_id: late_id.clone(),
            revoked_key_id: late_subject.clone(),
            revoking_key_id: late_subject.clone(),
            reason: Some("compromise".to_owned()),
            revoked_at: old_instant,
            effective_at: old_instant,
            revocation_envelope: serde_json::json!({ "revoked_key_id": late_subject }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: late_subject.clone(),
            // SIGNED 60 days ago — before `position`, which is now.
            scrub_timestamp: old_instant,
            pqc_completed_at: None,
            observed_region: crate::federation::verify_coord::region::US.to_owned(),
            revoked_after: None,
            persist_row_hash: String::new(),
        });
        assert!(
            late_row.scrub_timestamp < position,
            "the fixture must be signed BEFORE the consumer's cursor, or it proves nothing"
        );
        // The instant AS SEALED, not the one this fixture started from: the
        // producer seal floors instants to microseconds (CIRISPersist#646), so
        // comparing the served row against the pre-seal nanoseconds would fail
        // on a difference the cursor change has nothing to do with.
        let late_signed = late_row.scrub_timestamp;
        dir.put_revocation(crate::federation::SignedRevocation {
            revocation: late_row,
        })
        .await
        .expect(
            "an old signed instant is admissible — the skew gate is a ceiling and the \
             anti-rollback latch is per-subject",
        );

        let resumed = dir
            .list_signed_revocations_since(Some(position), u32::MAX)
            .await
            .unwrap();
        let late_served = resumed
            .iter()
            .find(|r| r.revocation.revocation_id == late_id)
            .expect(
                "a revocation admitted AFTER the cursor must be served past it, however old \
                 its signature — keying on the producer's clock hides it forever",
            );
        assert!(
            late_served.admitted_at > position,
            "and its position is THIS node's admission order, not the producer's instant"
        );
        assert_eq!(
            late_served.revocation.scrub_timestamp, late_signed,
            "while the signed instant is untouched — it is still the anti-rollback latch and \
             still envelope-bound"
        );

        // ── And it is point-readable through the shared wire index, which is
        //    what makes it symmetric with the other fourteen kinds.
        //
        //    Hashed as the `SignedRevocation` WRAPPER, not as the
        //    `ServedRevocation` the cursor returns: `admitted_at` is this
        //    node's position on the record, and folding a node-local instant
        //    into a content hash would make one revocation hash differently on
        //    every node holding it. A content hash covers the record; the
        //    cursor covers this node's view of it. ──
        let wrapped = crate::federation::SignedRevocation {
            revocation: served.revocation.clone(),
        };
        let content_hash =
            crate::federation::wire_index::content_hash_of(&wrapped).expect("hash the record");
        let bytes = dir
            .lookup_signed_record_by_content_hash("Revocation", &content_hash)
            .await
            .expect("the point read must be wired for this kind")
            .expect("the put path must have indexed the row");
        assert_eq!(
            bytes,
            serde_json::to_vec(&wrapped).unwrap(),
            "the index resolves to the exact record bytes, cursor position excluded"
        );

        // ── PR #667 review P1 — DISCOVERABLE, not merely fetchable. The
        //    subject-scoped receive-axis pull is how a peer learns which
        //    hashes to ask for; a revocation that is indexed but absent from
        //    that ref set leaves #655 half-closed — rebuildable in principle,
        //    unreachable in practice. A revocation OF a key is squarely "what
        //    is about me", which is the axis this read answers. ──
        let refs = crate::federation::wire_index::wire_refs_for_subject(dir, &subject)
            .await
            .expect("subject-scoped refs");
        let revocation_ref = refs
            .iter()
            .find(|(kind, _, _)| *kind == "Revocation")
            .expect("the subject's revocation must be advertised");
        assert_eq!(
            revocation_ref.1, content_hash,
            "the advertised hash must be the one the point read resolves"
        );
        assert_eq!(
            crate::federation::wire_index::record_key_field(&revocation_ref.2, "revocation_id")
                .unwrap(),
            revocation_id
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn exclusion_carriage_sqlite() {
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;
        let a = SqliteBackend::open_in_memory().await.unwrap();
        a.run_migrations().await.unwrap();
        let b = SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        run_carriage_matrix(&a, &b, "sq").await;
        run_revocation_cursor_matrix(&a, "sq").await;
        let c = SqliteBackend::open_in_memory().await.unwrap();
        c.run_migrations().await.unwrap();
        run_cursor_advance_matrix(&c, "sq").await;
        run_injected_roster_matrix(&c, "sq").await;
    }

    #[tokio::test]
    async fn exclusion_carriage_memory() {
        use crate::store::memory::MemoryBackend;
        let a = MemoryBackend::new();
        let b = MemoryBackend::new();
        run_carriage_matrix(&a, &b, "mem").await;
        run_revocation_cursor_matrix(&a, "mem").await;
        run_cursor_advance_matrix(&MemoryBackend::new(), "mem").await;
        run_injected_roster_matrix(&MemoryBackend::new(), "mem").await;
    }

    /// Two ISOLATED postgres databases — the cross-node property needs two
    /// directories, and the fixture seeds the genesis accord ids (A1/B1/C1)
    /// with test keys, which on the shared test DB would squat the real anchor.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn exclusion_carriage_postgres() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping exclusion_carriage_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let dsn2 = dsn.clone();
        crate::federation::admission::run_in_isolated_pg_db(&dsn, |a| async move {
            crate::federation::admission::run_in_isolated_pg_db(&dsn2, |b| async move {
                run_carriage_matrix(&a, &b, "pg").await;
                run_revocation_cursor_matrix(&a, "pg").await;
                run_cursor_advance_matrix(&b, "pg").await;
                run_injected_roster_matrix(&b, "pg").await;
            })
            .await;
        })
        .await;
    }
}
