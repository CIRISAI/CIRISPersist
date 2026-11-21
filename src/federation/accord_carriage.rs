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
//! ([`FederationDirectory::list_signed_revocations_since`])
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
//!
//!    v62.0.0 (BH-fix2): the re-tally is DELETED (it verified separate
//!    Ed25519 + ML-DSA-65 pairs); every bundle is refused, since the
//!    records it carried are retired (CC rc20).
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

use super::accord_quorum::{AccordParticipation, AccordProposal};

use super::admission::{
    accord_holder_roster, canonical_withdrawal_payload_sha256, op_withdraw_role,
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
///
/// # v36.0.0 (CIRISPersist#675) — `participations_admitted` is REPLACED by [`AccordAdmissionEffect`]
///
/// The struct used to carry "participations that landed", derived by
/// differencing two `list_accord_participations` reads around the put loop.
/// Two carriers admitting overlapping bundles for the same proposal
/// interleave those reads, so each attributes the other's inserts to itself —
/// a caller could read 4 having stored 2, or 0 having stored 2. Differencing
/// cannot be made correct without serialising the whole admission across
/// every writer (including other processes on the same postgres), so the
/// counter is gone; what a consumer actually keyed on it for — "was this
/// admission a duplicate?" (CIRISEdge's replication bridge derives its
/// Admitted-vs-Duplicate supply decision from it) — is carried instead by
/// [`Self::effect`], whose two answers are each exact under concurrency
/// because neither claims physical row insertion. Physical
/// inserted-vs-no-op attribution remains the store's private knowledge; the
/// honest path to exposing it is `put_accord_participation` reporting its
/// outcome per row (each backend already computes that internally and
/// discards it), which is #675's follow-through on the store surface.
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
    /// v36.0.0 (CIRISPersist#675) — whether this admission was a duplicate,
    /// as a fact about (this bundle, this node's state when THIS admission
    /// checked) — see [`AccordAdmissionEffect`] for the exact semantics.
    pub effect: AccordAdmissionEffect,
    /// `(role, key_id)` tombstones this admit re-derived locally — the
    /// [`Projection::RoleWithdrawals`](super::replication_policy::Projection::RoleWithdrawals)
    /// fan-out. Empty is the common case: most proposals are not withdrawals,
    /// and a withdrawal for a key this node does not hold projects nothing.
    pub withdrawals_projected: Vec<(String, String)>,
}

/// v36.0.0 (CIRISPersist#675) — the per-admission Admitted-vs-Duplicate
/// signal, defined as **check-time novelty**: what this node lacked at the
/// instant THIS admission read its state, immediately before its writes.
///
/// # Why this definition, and not "rows I inserted"
///
/// Physical insertion is decided inside each backend's
/// `put_accord_participation` (M6: insert / idempotent no-op / conflict),
/// which returns `()` — so no composition of directory calls can attribute
/// an insert to one of several racing writers, and the differencing counter
/// this replaces was wrong in exactly that window (#675). Check-time novelty
/// is decidable from a pre-write read, and each answer is sound on its own
/// terms:
///
/// * [`Duplicate`](Self::Duplicate) is **deterministically correct**: every
///   row the bundle carried already existed before this admission began, and
///   rows on this plane are append-only (no delete path), so this
///   admission's puts were provably byte-identical no-ops. A true replay —
///   re-offering a bundle a prior admission completed — always reports this.
/// * [`Supplied`](Self::Supplied) claims the node verifiably LACKED some of
///   this bundle's evidence when the admission began — never that this
///   caller's puts physically inserted it. Under a dead-heat race, two
///   carriers offering the same evidence may BOTH report `Supplied`; both
///   statements are true, and which one's put landed first is deliberately
///   unclaimed. What `Supplied` can never do is count another bundle's rows
///   (`novel_participations` is bounded by this bundle's own length) or
///   fire on a completed prior admission's rows — the two lies the
///   differencing counter told.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AccordAdmissionEffect {
    /// The bundle carried evidence this node lacked at check time: the
    /// proposal itself (`novel_proposal`) and/or `novel_participations` of
    /// its votes.
    Supplied {
        /// The proposal was not yet stored when this admission checked.
        novel_proposal: bool,
        /// How many of THIS bundle's participations were not yet stored
        /// (byte-compared against the stored rows; never more than the
        /// bundle carries).
        novel_participations: usize,
    },
    /// Everything the bundle carried — proposal and every participation —
    /// was already stored before this admission began: an idempotent
    /// re-verification that changed nothing.
    Duplicate,
}

/// v31.1.0 (CIRISPersist#662) — **admit a replicated accord evidence bundle
/// by re-deriving its quorum, against the production accord-holder roster.**
/// See [`admit_replicated_accord_evidence_over_roster`].
pub async fn admit_replicated_accord_evidence(
    directory: &dyn FederationDirectory,
    evidence: &AccordQuorumEvidence,
) -> Result<AccordEvidenceAdmission, Error> {
    super::edition2::door::refuse_earlier_form("accord_evidence")?;
    admit_replicated_accord_evidence_over_roster(
        directory,
        evidence,
        &accord_holder_roster(directory).await?,
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
///
///    1b. v36.0.0 (CIRISPersist#674) — the CARRIER bound: a bundle carrying
///    more participations than the declared roster has seats, or two entries
///    for one `member_id`, is refused with the typed
///    [`Error::AccordEvidenceCarrierMalformed`] BEFORE any signature is
///    verified and before the roster is resolved. No legitimate serve side
///    can produce such a bundle, and the refusal names the carrier rather
///    than the evidence.
/// 2. v62.0.0 (BH-fix2; RULINGS "composite signatures only") — the roster
///    resolution and the re-tally (`tally_live_quorum`, which verified each
///    participation's separate Ed25519 + ML-DSA-65 pair) are DELETED. The
///    records they counted are retired, and v62 verifies no separate pair.
/// 3. v62.0.0 (JSON-cut slice F; CC rc20): nothing lands. The proposal,
///    participation and decision records have no write door in this edition,
///    so a bundle that clears steps 0–1b is refused
///    ([`Error::AccordEvidenceUnverified`]) and projects nothing.
///
/// # On step 4's nonce
///
/// v54.1.0 (CIRISPersist#1047) — the proposal's nonce is minted by its
/// PROPOSER (CIRISConstitution#146, verify 20); no node issues one, so there
/// is nothing to record before the proposal lands. `put_accord_proposal`'s
/// single-use dedup applies here as at the local door: a bundle whose
/// proposal reuses a nonce that already names a different proposal in its
/// family is refused `Conflict` and stores nothing past the tally.
pub async fn admit_replicated_accord_evidence_over_roster(
    directory: &dyn FederationDirectory,
    evidence: &AccordQuorumEvidence,
    roster_key_ids: &[String],
) -> Result<AccordEvidenceAdmission, Error> {
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

    // (1b) v36.0.0 (CIRISPersist#674) — THE CARRIER BOUND, decided before any
    // signature is verified, before the roster is resolved, and before
    // anything lands. Both checks are pure functions of the input and the
    // declared seat list: a bundle cannot legitimately carry more votes than
    // the roster has seats, and cannot carry two entries for one seat — the
    // serve side ([`assemble_evidence_page`]) orders by `member_id`, which M6
    // dedup makes unique within a bundle.
    //
    // Like step (1), each rule is ALSO enforced one level down: the step-(3)
    // tally fails closed on an unknown seat and on a duplicate member. The
    // two refusals say different things, though — the tally's collapses into
    // "the receiver's re-tally did not authorize it", which sends an operator
    // hunting a partition or a forgery, when the actual fault is a carrier
    // shipping a bundle no legitimate serve side can produce. And unlike
    // step (1), this layer carries a bound of its own: the hybrid
    // verification work one bundle can demand stays bounded by the seat
    // count even if the tally's error-on-first-anomaly shape ever drifts
    // toward skip-and-continue.
    //
    // The bound is the DECLARED seat count, not the resolved roster: the
    // step-(0) posture gate admits a partially-seated directory (>= 1 seat
    // resolves), and a full bundle offered to such a node is stale-roster
    // evidence for step (3) to refuse honestly — not a malformed carrier.
    let declared_seats = roster_key_ids.len();
    if evidence.participations.len() > declared_seats {
        return Err(Error::AccordEvidenceCarrierMalformed {
            proposal_digest: proposal_digest.clone(),
            participations: evidence.participations.len(),
            roster_seats: declared_seats,
            reason: "a bundle cannot carry more participations than the accord roster has seats"
                .to_owned(),
        });
    }
    let mut seats_seen: Vec<&str> = Vec::with_capacity(evidence.participations.len());
    for p in &evidence.participations {
        if seats_seen.contains(&p.member_id.as_str()) {
            return Err(Error::AccordEvidenceCarrierMalformed {
                proposal_digest: proposal_digest.clone(),
                participations: evidence.participations.len(),
                roster_seats: declared_seats,
                reason: format!(
                    "duplicate participation for seat {member_id:?} — a bundle carries at most \
                     one entry per member_id",
                    member_id = p.member_id
                ),
            });
        }
        seats_seen.push(p.member_id.as_str());
    }

    // (2)–(3) v62.0.0 (BH-fix2; RULINGS "composite signatures only") — the
    // re-tally (`tally_live_quorum`: each participation's SEPARATE Ed25519 +
    // ML-DSA-65 pair verified against the holder's component halves) is
    // deleted: the records it counted are retired, and v62 verifies no
    // separate pair.
    // (4) v62.0.0 (JSON-cut slice F; CC rc20) — nothing lands. The rc20
    // edition has no accord proposal, participation or decision record (a
    // roster change is a later genesis bundle), so their write doors are
    // gone and a bundle that clears every check above is still refused: a
    // node of this edition stores no live-quorum evidence and projects no
    // withdrawal from it.
    Err(refuse(
        "accord live-quorum evidence is retired (CC rc20): the proposal, participation and \
         decision records have no write door in this edition"
            .to_owned(),
    ))
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
///
/// v62.0.0 (CC rc20 4.2.1 / 8.11.27, CIRISPersist#1274) — `canonical` here is
/// the NAME of the conferral a tombstone withdraws (the V095 table), never a
/// read of `identity_type` as standing: it is considered for every key, and
/// the standing itself is read from the conferral (`admission::is_canonical`).
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
    // v58.0.0 (CIRISPersist#991) — the key plane's rows, as a peer pulls them.
    let candidates = super::key_plane::key_records_on_the_plane(directory).await?;
    let proposal_digest = proposal.digest();
    let mut projected: Vec<(String, String)> = Vec::new();
    for candidate in &candidates {
        let key_id = &candidate.key_id;
        for (op, role) in withdrawal_ops_for(candidate) {
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
    rematerialize_role_withdrawals_over_roster(directory, &accord_holder_roster(directory).await?)
        .await
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
// v62.0.0 (JSON cut, wave 3, E5) — **the carriage witnesses are deleted**
// (lead's ruling 1: the accord's proposal, participation, decision and their
// carriage are replaced by genesis bundle/2; covered by C1's I2310–I2320 and
// C2's I2330–I2341). The store suites' `quorum_bundle_survives_backward_clock_*_662`
// runners are deleted by E1 / E2 with the two helpers they called.
