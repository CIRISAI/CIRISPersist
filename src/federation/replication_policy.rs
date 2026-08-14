//! v21.0.0 (CIRISPersist#501/#502) — the Registry-of-Record: the ONE
//! declarative admission policy per replicated `EnvelopeKind`, keyed on a
//! closed enum, exhaustively matched.
//!
//! # The invariant this makes mechanical
//!
//! *State on a node changes ONLY via a hybrid-Strict-verified claim by a
//! signer resolved against our OWN registered directory — never
//! sender-supplied material, a stored flag, a caller-passed roster, or bare
//! FK existence* (FSD `CEG_REPLICATION_MODEL.md` §0). Before this cut six
//! inbound `put_*` planes admitted on FK-existence alone (the classical
//! edges E1/E2/E4/E9), plus a local-tier exemption that poisoned the
//! trust-root walk (E5).
//!
//! The cure is the move proven by v20's `EnvelopeCore` and the
//! `WIRE_VOCABULARY_HASH` gate: the contract lives in ONE typed place, every
//! consumer derives from it, drift is a **compile/test failure**.
//!
//! - Roots of trust are **variants** ([`SignerSource`]) — so "verify against
//!   sender-supplied material" is *unrepresentable*, not merely discouraged.
//! - The policy set is **code on a closed enum**, not a table — a policy
//!   table would itself be unverified mutable state (a fresh classical edge).
//! - Adding an `EnvelopeKind` without a policy is a **compile failure**
//!   ([`policy_for`] is an exhaustive match).
//! - The whole registry is exported as [`replication_policy_manifest`] +
//!   [`REPLICATION_POLICY_HASH`], pinned by a gating witness — exactly like
//!   `ciris_edge::WIRE_VOCABULARY_HASH`. Edge exports its serve/advertise
//!   half; CIRISServer pins both. Two-surface drift → build failure across
//!   the triple.
//!
//! # Ownership
//!
//! Persist is the **admission authority** (APPLY gate; edge does no
//! verification), so persist owns the admission-side [`EnvelopeKind`]. Its
//! correspondence with edge's wire enum (`ciris_edge::replication::protocol`,
//! same 15 names/order) is pinned by [`REPLICATION_POLICY_HASH`], not by a
//! shared crate — resolving the ownership question without a synchronous
//! cross-repo enum move.
//!
//! # v31.1.0 (CIRISPersist#655 / CIRISPersist#662) — the 15th kind
//!
//! [`EnvelopeKind::AccordQuorumEvidence`] is appended (never inserted — the
//! order is hashed), moving [`REPLICATION_POLICY_HASH`]. That re-pin is
//! consumer-visible and deliberate; see the variant's own doc for why the
//! ACCORD EVIDENCE replicates and the withdrawal tombstone it authorizes
//! does not.

use serde::{Deserialize, Serialize};

/// The 15 replicated wire kinds (mirror of edge's
/// `replication::protocol::EnvelopeKind`, pinned by
/// [`REPLICATION_POLICY_HASH`]). Persist owns this as the APPLY authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnvelopeKind {
    /// `federation_keys` — key registrations. Fresh insert needs PoP (E2).
    Key,
    /// `federation_attestations` — the whole 95-family claim namespace
    /// rides here (each family is a claim-dimension, not a wire kind).
    Attestation,
    /// `federation_revocations` — key-level revocation, R1/Q1 quorum (E1).
    Revocation,
    /// `federation_identity_occurrences`.
    IdentityOccurrence,
    /// `federation_families` (E4).
    Family,
    /// `federation_communities` (E4).
    Community,
    /// `federation_identity_occurrence_revocations`.
    IdentityOccurrenceRevocation,
    /// `federation_family_membership_revocations` (E4).
    FamilyMembershipRevocation,
    /// `federation_community_membership_revocations` — insert rotates the
    /// DEK epoch, so a forged removal is a forward-secrecy DoS (E4).
    CommunityMembershipRevocation,
    /// `federation_location_proofs` (E4).
    LocationProof,
    /// `organizations` — role-authority quorum (E9).
    Organization,
    /// `org_memberships` — role-authority quorum (E9).
    OrgMembership,
    /// `partner_records` — M-of-N steward quorum (E9).
    PartnerRecord,
    /// `federation_transport_destinations`.
    TransportDestination,
    /// v31.1.0 (CIRISPersist#662) — `accord_proposal` + its
    /// `accord_participation` set (V091), carried as ONE bundle: the signed
    /// EVIDENCE behind an accord live-quorum decision.
    ///
    /// # Why the evidence and not the verdict
    ///
    /// `federation_role_withdrawals` (V104) — the tombstone plane
    /// [`is_infra_attest_effective`](crate::federation::admission::is_infra_attest_effective)
    /// folds — has **no signature columns at all**: `role`, `key_id`,
    /// `withdrawn_at`, `authority_decision_digest`, `superseded_by`,
    /// `persist_row_hash`. `persist_row_hash` is recomputed locally, so it
    /// binds nothing across nodes, and the authority lives entirely behind
    /// `authority_decision_digest` — a pointer into THIS plane. A cursor on
    /// the tombstone table would therefore ship a derived verdict and ask the
    /// receiver to trust the sender: the forgeable-decision-bool bypass
    /// CIRISPersist#377 closed, rebuilt on purpose and called replication.
    ///
    /// So the wire carries the proposal + the holders' hybrid-signed
    /// participations, and
    /// [`accord_carriage::admit_replicated_accord_evidence`](crate::federation::accord_carriage::admit_replicated_accord_evidence)
    /// **re-tallies** them against a roster resolved from the receiver's OWN
    /// directory before anything lands. Each node then re-derives its own
    /// V104/V095 projection ([`Projection::RoleWithdrawals`]), which is what
    /// makes carrying the evidence safe.
    AccordQuorumEvidence,
}

impl EnvelopeKind {
    /// Every kind, in the canonical (manifest-hashed) order.
    pub const ALL: [EnvelopeKind; 15] = [
        EnvelopeKind::Key,
        EnvelopeKind::Attestation,
        EnvelopeKind::Revocation,
        EnvelopeKind::IdentityOccurrence,
        EnvelopeKind::Family,
        EnvelopeKind::Community,
        EnvelopeKind::IdentityOccurrenceRevocation,
        EnvelopeKind::FamilyMembershipRevocation,
        EnvelopeKind::CommunityMembershipRevocation,
        EnvelopeKind::LocationProof,
        EnvelopeKind::Organization,
        EnvelopeKind::OrgMembership,
        EnvelopeKind::PartnerRecord,
        EnvelopeKind::TransportDestination,
        EnvelopeKind::AccordQuorumEvidence,
    ];

    /// The stable wire token (must match edge's `as_str`; pinned by hash).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            EnvelopeKind::Key => "Key",
            EnvelopeKind::Attestation => "Attestation",
            EnvelopeKind::Revocation => "Revocation",
            EnvelopeKind::IdentityOccurrence => "IdentityOccurrence",
            EnvelopeKind::Family => "Family",
            EnvelopeKind::Community => "Community",
            EnvelopeKind::IdentityOccurrenceRevocation => "IdentityOccurrenceRevocation",
            EnvelopeKind::FamilyMembershipRevocation => "FamilyMembershipRevocation",
            EnvelopeKind::CommunityMembershipRevocation => "CommunityMembershipRevocation",
            EnvelopeKind::LocationProof => "LocationProof",
            EnvelopeKind::Organization => "Organization",
            EnvelopeKind::OrgMembership => "OrgMembership",
            EnvelopeKind::PartnerRecord => "PartnerRecord",
            EnvelopeKind::TransportDestination => "TransportDestination",
            EnvelopeKind::AccordQuorumEvidence => "AccordQuorumEvidence",
        }
    }
}

/// The root of trust a kind's signature is verified against — **variants**,
/// so verifying against sender-supplied material cannot be spelled. Every
/// variant resolves the signer from persist's OWN registered directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerSource {
    /// The record's own declared attester/signer key_id, resolved from our
    /// `federation_keys`.
    RegisteredSigner,
    /// A named signer field (e.g. `revoking_key_id` on a revocation),
    /// resolved from our directory. The `&'static str` is the field name —
    /// part of the hashed manifest.
    RegisteredNamedField(&'static str),
    /// An m-of-n / M-of-N quorum whose roster is resolved from persist's
    /// OWN baked accord/steward directory — never a caller-passed slice.
    QuorumFromOwnDirectory,
}

/// What kind of authorship binding the verified signer must satisfy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerBinding {
    /// The signer IS the subject (self-published).
    SelfOwn,
    /// The signer `owner_of` the subject occurrence.
    OwnerOf,
    /// The signer `signer_acts_for` the subject (identity-occurrence plane).
    SignerActsFor,
    /// The signer holds a steward/role authority resolved from OUR directory.
    StewardRosterFromDirectory,
}

/// Whether a fresh first-sight insert needs a proof-of-possession gate
/// (E2 — the replicated-key TOFU hole).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PopOnInsert {
    /// First-sight insert runs the hybrid PoP registration gate.
    Required,
    /// No first-sight PoP (the record is not a key-registration).
    NotApplicable,
}

/// The tier a wire admit may claim. There is exactly ONE variant on
/// purpose: **a wire admit can never claim `tier=local`** (E5 — the
/// local-tier exemption bypasses `verify_federation_tier_ingest` and
/// silently counts in the trust-root walk). Local tier is producer-only,
/// reachable solely through the local ingest API, never the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireTier {
    /// Wire admits are forced to federation tier.
    FederationOnly,
}

/// A read-projection maintained IN-TX as a feature of admitting a claim
/// (the #501 fan-out; improves on the trust plane's post-commit hook).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Projection {
    /// `trace_events` from a `trace:complete:v1` attestation (#501 — the
    /// corpus leg: replicated traces become scorer-readable).
    TraceEvents,
    /// The consent-peer-set projection (E7 — `withdraws`/`supersedes`
    /// folded, so revocation is honored mechanically).
    ConsentPeerSet,
    /// The V106 `attestation_subjects` subject index (existing).
    AttestationSubjects,
    /// v31.1.0 (CIRISPersist#662) — the V104/V095 role-withdrawal tombstones,
    /// re-derived LOCALLY from admitted accord evidence. This is the
    /// projection that lets the tombstone planes stay off the wire: the
    /// receiver recomputes each candidate `(op, key_id)` payload digest
    /// against its OWN key directory and re-runs the #377 authority core, so
    /// a tombstone exists on a node only because that node re-tallied the
    /// quorum itself.
    RoleWithdrawals,
}

/// The admission policy for one [`EnvelopeKind`] — persist's half of the
/// Registry-of-Record object (edge owns serve/advertise).
#[derive(Debug, Clone, Serialize)]
pub struct KindPolicy {
    /// The kind this policy governs.
    pub kind: EnvelopeKind,
    /// Where the signer of record is resolved from (always OUR directory).
    pub signer: SignerSource,
    /// The authorship binding the verified signer must satisfy.
    pub binding: SignerBinding,
    /// PoP requirement on a fresh insert (E2).
    pub pop_on_insert: PopOnInsert,
    /// The tier a wire admit may claim (always `FederationOnly` — E5).
    pub tier: WireTier,
    /// Read-projections maintained in the same admit transaction.
    pub projections: &'static [Projection],
}

/// The ONE admission policy for a kind. Exhaustive `match`: adding an
/// `EnvelopeKind` without a policy is a **compile failure**.
#[must_use]
pub fn policy_for(kind: EnvelopeKind) -> KindPolicy {
    use EnvelopeKind as K;
    use Projection as P;
    use SignerBinding as B;
    use SignerSource as S;
    let (signer, binding, pop, projections): (S, B, PopOnInsert, &'static [P]) = match kind {
        K::Key => (
            S::RegisteredSigner,
            B::SelfOwn,
            PopOnInsert::Required, // E2: first-sight PoP
            &[],
        ),
        K::Attestation => (
            S::RegisteredSigner,
            B::SignerActsFor,
            PopOnInsert::NotApplicable,
            // #501: trace attestations materialize the corpus; V106 subjects.
            &[P::TraceEvents, P::AttestationSubjects, P::ConsentPeerSet],
        ),
        K::Revocation => (
            // E1: verify vs the REVOKING key, quorum-from-own-directory.
            S::QuorumFromOwnDirectory,
            B::StewardRosterFromDirectory,
            PopOnInsert::NotApplicable,
            &[],
        ),
        K::IdentityOccurrence => (
            S::RegisteredSigner,
            B::SignerActsFor,
            PopOnInsert::NotApplicable,
            &[],
        ),
        K::IdentityOccurrenceRevocation => (
            S::RegisteredSigner,
            B::SignerActsFor,
            PopOnInsert::NotApplicable,
            &[],
        ),
        K::TransportDestination => (
            S::RegisteredSigner,
            B::OwnerOf,
            PopOnInsert::NotApplicable,
            &[],
        ),
        // E4: the roster/proof planes — verify vs the record's declared,
        // registered signer.
        K::Family | K::Community | K::LocationProof => (
            S::RegisteredSigner,
            B::OwnerOf,
            PopOnInsert::NotApplicable,
            &[],
        ),
        K::FamilyMembershipRevocation | K::CommunityMembershipRevocation => (
            S::RegisteredSigner,
            B::OwnerOf,
            PopOnInsert::NotApplicable,
            &[],
        ),
        // E9: operational planes — quorum roster from OUR directory.
        K::Organization | K::OrgMembership | K::PartnerRecord => (
            S::QuorumFromOwnDirectory,
            B::StewardRosterFromDirectory,
            PopOnInsert::NotApplicable,
            &[],
        ),
        // v31.1.0 (#662): the accord evidence bundle. The roster is the
        // accord holders resolved from OUR baked genesis records, and the
        // admit gate IS a `tally_live_quorum` re-tally at the strict-majority
        // threshold — the receiver never reads the sender's verdict. The
        // withdrawal tombstones are re-derived in the same admit.
        K::AccordQuorumEvidence => (
            S::QuorumFromOwnDirectory,
            B::StewardRosterFromDirectory,
            PopOnInsert::NotApplicable,
            &[P::RoleWithdrawals],
        ),
    };
    KindPolicy {
        kind,
        signer,
        binding,
        pop_on_insert: pop,
        tier: WireTier::FederationOnly,
        projections,
    }
}

/// The full registry as canonical JSON (the hashed representation + the
/// public API shape). Serves as edge's / server's cross-repo pin source.
#[must_use]
pub fn replication_policy_manifest() -> serde_json::Value {
    serde_json::json!({
        "contract": "replication_admission_policy",
        "version": 1,
        "policies": EnvelopeKind::ALL
            .iter()
            .map(|k| policy_for(*k))
            .collect::<Vec<_>>(),
    })
}

/// sha256 (lowercase hex) over JCS of [`replication_policy_manifest`].
#[must_use]
pub fn replication_policy_sha256() -> String {
    use sha2::Digest as _;
    let canonical =
        crate::verify::canonical::ceg_produce_canonicalize(&replication_policy_manifest())
            .expect("replication policy manifest canonicalizes");
    hex::encode(sha2::Sha256::digest(&canonical))
}

/// The PINNED registry hash. Edge + CIRISServer assert it in gate tests;
/// the `replication_policy_hash_is_pinned` witness asserts computed ==
/// pinned. Any admission-policy change is a deliberate re-pin, visible to
/// every consumer — cross-repo drift is a build failure.
/// v31.1.0 (CIRISPersist#655/#662) — re-pinned for the 15th kind
/// ([`EnvelopeKind::AccordQuorumEvidence`]) and the
/// [`Projection::RoleWithdrawals`] fan-out it declares. Previous value:
/// `351912ead0aab4847f40d2b54a7a326546c37d43507deb38ea24d6094d29d63b`
/// (v21.0.0 – v31.0.0, the 14-kind era).
pub const REPLICATION_POLICY_HASH: &str =
    "3af30bccf437679ecccba325e2db055824b4721eeac069fc30a38d7a0723bbef";

#[cfg(test)]
mod tests {
    use super::*;

    /// The pin gate (the loud-drift discipline).
    #[test]
    fn replication_policy_hash_is_pinned() {
        assert_eq!(
            replication_policy_sha256(),
            REPLICATION_POLICY_HASH,
            "replication admission policy changed: re-pin REPLICATION_POLICY_HASH \
             deliberately (and notify the edge serve/advertise + CIRISServer pin holders)"
        );
    }

    /// Every kind has a policy (guaranteed by the exhaustive match, pinned
    /// here so the ALL array and the match can't silently diverge).
    #[test]
    fn every_kind_has_a_policy_and_forces_federation_tier() {
        for k in EnvelopeKind::ALL {
            let p = policy_for(k);
            assert_eq!(p.kind, k);
            // E5: NO wire kind may admit at local tier.
            assert_eq!(p.tier, WireTier::FederationOnly);
        }
        assert_eq!(EnvelopeKind::ALL.len(), 15, "the wire-kind count is pinned");
    }
}
