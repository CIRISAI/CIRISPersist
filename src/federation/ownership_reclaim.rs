//! (CIRISPersist#578, CIRISConstitution rc3 CC 3.2) — the `ownership:*`
//! ownerless-lock **reclaim CEREMONY**: petition → WA quorum finding →
//! gated `withdraws` (K becomes **unowned**) → fresh owner-binding
//! co-signed by K.
//!
//! # The gap this closes
//!
//! Ownership is a `delegates_to(U → node)` on the owner-binding dimension
//! ([`super::types::owner_binding::DIMENSION`]). Ownership is single-valued
//! (CC 3.2): a binding counts only when the node cosigned it, and v62.0.0's
//! kernel owner seat ([`super::admission::owner_of`]) reads two counted owners
//! as none. Until v62.0.0 a single-owner gate refused a DIFFERENT granter's
//! binding outright; either way the incumbent's live binding stands until it
//! is withdrawn or lapses. So if the owner dies, loses custody, or *front-ran
//! the legitimate owner*, the live binding never withdraws and the node is
//! locked **forever**. That is CC 3.2's "no permanent ownerless lock"
//! violated by omission.
//!
//! # What rc3 ratified (and what v21.8.0 got wrong)
//!
//! v21.8.0 shipped a mechanism whose authority was the **HUMANITY_ACCORD
//! holder roster** and whose evidence was an m-of-n co-signature carried
//! *directly on the `withdraws`*. CIRISConstitution rc3 rules otherwise, and
//! persist committed to implementing whatever CC ratifies:
//!
//! 1. **Authority is the [CC 4.3](https://github.com/CIRISAI/CIRISConstitution)
//!    Wise-Authority quorum, NOT the accord roster.** `ReclaimPolicy` now
//!    names a **WA body** ([`ReclaimPolicy::wa_family_key_id`]) and
//!    [`ReclaimRefusal::AccordRosterIsNotWaAuthority`] refuses, by name, a
//!    deployment that points the pin back at the accord family.
//! 2. **The gated `withdraws` MUST carry a `wa_adjudication_ref`**
//!    ([`field::WA_ADJUDICATION_REF`]) resolving to the quorum finding. A
//!    direct m-of-n on the `withdraws` carries none and is non-conformant:
//!    *"The substrate records the finding; it never makes it — quorum
//!    adjudicates, the substrate admits."*
//! 3. **Four steps, never collapsed.** Petition (1), finding (2), gated
//!    `withdraws` after which K is **unowned** (3), fresh owner-binding
//!    co-signed by K (4). **Reclaim MUST NOT transfer incumbent → claimant
//!    in one act** — see *the single-act wall* below.
//! 4. The **180-day** [`ReclaimPolicy::DEFAULT_ABANDONMENT_WINDOW`] remains
//!    compliant as a deployment value (CC pins a **90-day floor**, and the
//!    window must be *published* — an unpublished window means no
//!    abandonment finding is admissible, which is why
//!    [`ReclaimPolicy::from_deployment_pin`] returns `None` rather than
//!    guessing).
//! 5. rc3 answers persist's open question 3 in-text: *"the owner-binding
//!    attestation itself establishes the initial floor, so a binding is
//!    never floorless"* — encoded in `initial_freshness_floor`, which
//!    reads the binding's own `asserted_at` as the floor of last resort
//!    instead of bolting on a separate floor.
//!
//! # The single-act wall (structural, not merely refused)
//!
//! CC 3.2: *"Reclaim MUST NOT transfer incumbent → claimant in one act:
//! passing through the unowned state is what keeps the single-owner
//! invariant and the anti-landgrab rule intact."* This module makes the
//! collapse impossible on **three independent levels**, so no single lapse
//! re-opens it:
//!
//! - **Unrepresentable in the type.** [`ReclaimVerdict::Admit`] carries a
//!   [`WaFinding`] and a [`WaQuorum`] and *has no field that could name a
//!   successor owner*. There is no value of this type that says "and give it
//!   to X". The only thing an admitted reclaim can authorize is the
//!   `withdraws`.
//! - **Refused on the wire.** A `withdraws` envelope carrying any
//!   successor-naming field ([`SUCCESSOR_OWNER_FIELDS`]) is refused with
//!   [`ReclaimRefusal::SingleActTransferAttempted`] *before any authority is
//!   even considered* — a producer that tries to express the collapse is
//!   told exactly which rule it broke.
//! - **Not counted by the owner seat.** v62.0.0 (kernel pass 2): a
//!   claimant's binding is held, but counts only with K's cosignature, and
//!   while the incumbent's binding is live a second counted owner leaves the
//!   node unowned, not transferred. Step 4's own refusal
//!   ([`check_post_reclaim_rebinding_admission`]) still demands K's
//!   co-signature on a rebinding after a reclaim, so K really does pass
//!   through the unowned state.
//!
//! # Authority is re-derived from this node's own verified state (#377)
//!
//! Nothing here trusts a caller-supplied roster, threshold, or decision
//! boolean (a caller-supplied `authorized` bool is a forgeable m-of-n
//! bypass, and this repo has been bitten by exactly that). The WA quorum is
//! re-derived at USE:
//!
//! - the **roster** is [`FederationDirectory::active_family_members`] of the
//!   pinned WA body — revocation-folded, this node's own stored state, and
//!   itself only changeable through the family's own m-of-n
//!   ([`FederationDirectory::verify_membership_quorum`]);
//! - the **threshold** is the family's OWN stored `consensus_protocol` read
//!   through [`family_charter_threshold`](super::trust_root), floored at a
//!   strict majority and fail-secure (`unanimous`/unrecognised ⇒ the whole
//!   roster), so a tampered policy string cannot talk the threshold down;
//! - the **count** is [`count_distinct_roster_scrubs`](super::reverse_quorum),
//!   the SAME body the charter plane and the commons' undo door use — each
//!   co-signature re-verified against pubkeys resolved from THIS node's
//!   directory. One predicate, one implementation.
//!
//! CC 4.3's own normative heading is *"The Wise wear the same card"*, so a
//! counted co-signer must additionally carry
//! [`identity_type::WISE_AUTHORITY`]
//! in its registered `identity_type` set. That is a **legibility** filter on
//! the numerator, never a source of authority: the seat is the family
//! membership (which a Sybil cannot grant itself), and the denominator stays
//! the FULL roster — see `wa_quorum_over_body` for why the denominator is
//! deliberately not shrunk to a live set.
//!
//! # What is NOT built here
//!
//! - **WA appointment.** CC 1.16.5 puts appointment, rotation, recusal and
//!   appeals under the Governance Charter, *"external to this system's
//!   control"*. Persist is handed a deployment-published family and
//!   re-derives everything else from its own state.
//! - **Making the finding.** The substrate records it; the quorum makes it.
//! - **Producing** the petition / finding / `withdraws` rows — edge/agent's
//!   job. [`build_reclaim_petition_envelope`],
//!   [`build_wa_finding_envelope`] and [`build_reclaim_withdraws_envelope`]
//!   publish the wire shapes so a producer never hand-rolls the JSON.
//!
//! # Two decisions CC leaves to the substrate — flagged, not buried
//!
//! rc3 pins the ceremony and the authority; it does not pin *how the
//! substrate is told either one*. Both choices below fail CLOSED by
//! default — an unpublished pin refuses everything, and an unrecognised
//! dimension is simply not a finding — so neither can make a seizure
//! easier than CC allows. Both nonetheless want confirmation from the
//! ratification chain and byte-agreement from the producer side, because a
//! wire shape only one repo knows is a shape nobody can use:
//!
//! 1. **How the WA body is named.** CC 1.16.5 puts appointment outside the
//!    wire, so persist takes a deployment-published `family_key_id`
//!    ([`ReclaimPolicy::WA_FAMILY_ENV`]) and re-derives roster + threshold
//!    from its own stored family. This is the load-bearing pin: it decides
//!    whose signatures can take a node.
//! 2. **What the finding and petition look like.** CC says only *"minted as
//!    an attestation"*. Persist mints them on [`NAMESPACE_FAMILY`] — a new
//!    family, because CC 3.4 forecloses the obvious alternative. Ratification
//!    ask tracked like [`objection:{state}`](super::reverse_quorum::NAMESPACE_FAMILY).
//!
//! Note also what the WA seat's strength actually rests on: the family
//! plane's existing write posture. A REMOTE peer cannot seat itself —
//! `put_family` is INSERT-only (an existing `family_key_id` collides on the
//! primary key) and every roster change rides
//! [`verify_membership_quorum`](FederationDirectory::verify_membership_quorum),
//! i.e. the body's own m-of-n. The host-local roster APIs
//! (`put_family_local` / `add_family_member`) are the node operator's own
//! surface, the same trust boundary the accord family already sits behind.
//! This module adds no new gate there, and does not pretend to.

use chrono::{DateTime, Duration, Utc};

use super::admission::is_owner_binding_envelope;
use super::attestation_query::{AttestationQuery, FOLD_PAGE};
use super::edition2::fold::{self, Dep};
use super::envelope::EnvelopeCore;
use super::freshness::merge_floor;
use super::precedence::references_attestation_id_from_envelope;
use super::types::{attestation_type, identity_type};
use super::{Attestation, Error, FederationDirectory};

/// This module's own consumer convention for the freshness floor's
/// open-vocab `target_kind` ([`super::types::SignedTouchClaim::target_kind`])
/// — the freshness floor is generic across families
/// (`ownership:*`/`trust:*`/`consent:*`/...) and resolved by whoever
/// consumes it; this is the literal this module reads/expects a producer
/// to touch under for an `ownership:*` liveness signal.
pub const OWNERSHIP_FRESHNESS_TARGET_KIND: &str = "ownership_binding";

/// The per-row audit value [`super::admission::check_withdraws_admission`]
/// stamps when the CC 3.2 recovery ceremony (not one of the 4 ordinary
/// rules on their own) admits a `withdraws` against a live owner-binding —
/// see [`super::types::Attestation::withdraws_admission_rule`]'s doc for
/// rules 1-4; this is the recovery path's rule 5.
///
/// It is also how [`check_post_reclaim_rebinding_admission`] learns, from
/// this node's own stored rows and nothing else, that K has been through a
/// reclaim and therefore owes K's co-signature on its next binding.
pub const RECLAIM_WITHDRAWS_ADMISSION_RULE: u8 = 5;

/// The CC 3.1 namespace family the petition and the two finding dimensions
/// live under. **Registered** (CIRISPersist#590): CC 1.0-rc3
/// catalogues it at CC 3.1.9.4, owning component `node`. It is on the CC 3.1.7
/// R2(a) mint gate ([`super::admission::MINTED_NAMESPACE_FAMILIES`]).
///
/// **The parameter is `{state}`, not `{finding}`.** #578 filed the ask as
/// `wa_adjudication:{finding}`; CC ratified `wa_adjudication:{state}`, matching
/// its `objection:{state}` / `quarantine:{state}` siblings in the same Part.
/// The stem is identical either way, so nothing on the wire moved — but the
/// declared family must be spelled the way the registry row spells it, or the
/// R2(a) gate is comparing persist's intention against CC's record and calling
/// a mismatch agreement.
///
/// **The row registers the family, NOT an emitter rule** — `reserved: false`,
/// no `reserved_rule`, so
/// [`authority_for`](super::namespace::registry::authority_for) resolves
/// `ProducerSteward` / `reserved: None`. The CC 4.3 WA-quorum authority this
/// plane requires is re-derived from persist's own verified state in
/// [`check_ownership_reclaim_admission`] and asserted nowhere else. Tracked in
/// [`RULES_NOT_ON_THE_ROW`](super::family_rules::RULES_NOT_ON_THE_ROW).
///
/// The finding deliberately does **not** live under `ownership:*`: CC 3.4
/// reserves that family to the live owner and says the recovery path *"rides
/// `withdraws` + `wa_adjudication_ref` and never a fresh `ownership:*`
/// emission"*. A finding minted on `ownership:*` would be a seizure by
/// attestation, which is the thing being adjudicated.
pub const NAMESPACE_FAMILY: &str = "wa_adjudication:{state}";

/// Ceremony **step 1** — the petition naming K and the evidence. A `scores`
/// row; anyone may file one (that is what a petition IS), and persist never
/// reads its grounds.
pub const DIMENSION_PETITION: &str = "wa_adjudication:petition:v1";

/// Ceremony **step 2**, abandonment arm — the CC 4.3 quorum's finding that
/// the incumbent owner is provably gone. Persist additionally re-checks the
/// freshness predicate itself (see [`check_ownership_reclaim_admission`]);
/// the quorum's word and the substrate's own evidence must BOTH hold.
pub const DIMENSION_FINDING_ABANDONMENT: &str = "wa_adjudication:abandonment:v1";

/// Ceremony **step 2**, seizure arm — the CC 4.3 quorum's finding that a
/// **live** owner-binding was admitted by front-run or fraud. Deliberately
/// NOT gated on the abandonment window: rc3 is explicit that the same
/// recovery path *"also reaches a binding found to be a seizure — a live
/// wrongful owner-binding … not only a dead one"*, so a front-run is
/// reversible rather than permanent. The whole weight of this arm rests on
/// the quorum, which is why the quorum is re-derived and never asserted.
pub const DIMENSION_FINDING_SEIZURE: &str = "wa_adjudication:seizure:v1";

/// CC 3.2's named recovery-delegation scope: the token a `delegates_to(K →
/// R)` must carry for `R` to hold rule-(4) standing to file the gated
/// `withdraws` on K's behalf. *"The key that is still being kept running is
/// the subject with standing to say its owner is gone."*
pub const DELEGATION_SCOPE_OWNER_BINDING_RECOVERY: &str = "owner_binding_recovery";

/// Envelope field names shared by the producer side and this gate, so the
/// two cannot disagree about where a reference lives.
pub mod field {
    /// On the gated `withdraws`: the [`attestation_id`] of the CC 4.3 quorum
    /// finding. The manifest already carries this name on `ownership:*`
    /// (`namespace_supersets.json` § `wa_adjudication_ref`, typing
    /// `untyped_extra`) — it rides
    /// [`EnvelopeCore::extra`](crate::federation::envelope::EnvelopeCore::extra), not a
    /// universal envelope path.
    ///
    /// [`attestation_id`]: crate::federation::types::Attestation::attestation_id
    pub const WA_ADJUDICATION_REF: &str = "wa_adjudication_ref";
    /// On the finding: the `attestation_id` of the **petition** (step 1) it
    /// answers. Required — a finding with no petition is a three-step
    /// ceremony wearing a four-step name.
    pub const PETITION_REF: &str = "petition_ref";
    /// On the petition AND the finding: the `attestation_id` of the
    /// owner-binding under adjudication. Binds the whole ceremony to ONE
    /// binding, so a finding cannot be replayed against a different one.
    pub const TARGET_OWNER_BINDING_ID: &str = "target_owner_binding_id";
    /// Free-text evidence. Recorded, never interpreted — persist does not
    /// adjudicate WHY a node is said to be abandoned or seized.
    pub const GROUNDS: &str = "grounds";
}

/// Envelope keys that would name a successor owner on the gated
/// `withdraws`, i.e. that would collapse ceremony steps 3 and 4 into one
/// act. Their mere PRESENCE is refused with
/// [`ReclaimRefusal::SingleActTransferAttempted`].
///
/// Listing the names rather than trusting their absence is the point: the
/// collapse is the specific thing rc3 forbids, so a producer that reaches
/// for it gets a refusal that says so instead of silently having the field
/// ignored. (Ignoring it would be *safe* — persist would never act on it —
/// but silence here trains producers to keep shipping the shape until some
/// future reader honours it.)
pub const SUCCESSOR_OWNER_FIELDS: [&str; 5] = [
    "successor_owner_key_id",
    "successor_owner",
    "claimant_key_id",
    "new_owner_key_id",
    "replaces_owner_with",
];

/// Which CC 4.3 finding a `wa_adjudication_ref` resolved to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaFinding {
    /// The incumbent owner is provably gone (CC 3.2's abandonment
    /// predicate). Persist re-checks the freshness floor itself.
    Abandonment,
    /// A live owner-binding was admitted by front-run or fraud. The
    /// freshness predicate deliberately does NOT apply.
    Seizure,
}

impl WaFinding {
    /// The finding a `scores` dimension names, or `None` for any other
    /// dimension.
    #[must_use]
    pub fn from_dimension(dimension: &str) -> Option<Self> {
        match dimension {
            DIMENSION_FINDING_ABANDONMENT => Some(Self::Abandonment),
            DIMENSION_FINDING_SEIZURE => Some(Self::Seizure),
            _ => None,
        }
    }

    /// The dimension this finding is minted on.
    #[must_use]
    pub const fn dimension(&self) -> &'static str {
        match self {
            Self::Abandonment => DIMENSION_FINDING_ABANDONMENT,
            Self::Seizure => DIMENSION_FINDING_SEIZURE,
        }
    }

    /// The stable program token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Abandonment => "abandonment",
            Self::Seizure => "seizure",
        }
    }
}

impl std::fmt::Display for WaFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// **WHICH ceremony step refused.**
///
/// A bare refusal on a node-seizure path is unacceptable: the operator of a
/// node someone just tried to take must be able to read, from the refusal
/// alone, whether the ceremony was mis-built, under-signed, or aimed at the
/// wrong binding. Same discipline as
/// [`ObjectionRefusalReason`](super::reverse_quorum::ObjectionRefusalReason)
/// (#574), [`KeyRefusalReason`](super::register::KeyRefusalReason) (#565)
/// and [`PeerQuotaRefusal`](super::replication::admission::PeerQuotaRefusal)
/// (#575).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReclaimRefusal {
    // ── step 0: the deployment pin ──────────────────────────────────────
    /// This deployment has published no WA body / abandonment window, so no
    /// finding is admissible here at all (CC 3.2: *"A deployment MUST
    /// publish its window; an unpublished window means no abandonment
    /// finding is admissible there"*). The shipped default — persist does
    /// not invent an authority.
    NoDeploymentPolicy,
    /// The pin names the **HUMANITY_ACCORD family**. rc3 moved reclaim
    /// authority off the accord roster and onto the CC 4.3 WA quorum; a
    /// deployment cannot quietly move it back by calling the accord a WA
    /// body. This is the v21.8.0 non-conformance, named.
    AccordRosterIsNotWaAuthority,
    /// The published window is below CC 3.2's **90-day floor** (or
    /// unparseable). Refused rather than clamped: a deployment that
    /// published 7 days meant something, and quietly running it at 90 would
    /// be a window nobody published.
    AbandonmentWindowBelowFloor,
    /// The pinned WA `family_key_id` resolves to no family this node holds,
    /// so there is no roster to re-derive authority from. Fail-closed.
    WaBodyUnknown,
    /// The WA body resolves but its revocation-folded active roster is
    /// empty — an unmeetable threshold, refused explicitly rather than
    /// through a vacuous `0 >= 0`.
    WaRosterEmpty,

    // ── step 1: the petition ────────────────────────────────────────────
    /// The finding carries no [`field::PETITION_REF`] — steps 1 and 2
    /// collapsed.
    PetitionMissing,
    /// The petition ref resolves to nothing this node holds, to a row that
    /// is not a [`DIMENSION_PETITION`] row, or to a petition against a
    /// DIFFERENT owner-binding.
    PetitionUnresolvable,

    // ── step 2: the WA quorum finding ───────────────────────────────────
    /// The gated `withdraws` carries no [`field::WA_ADJUDICATION_REF`].
    /// This is the CC 3.2 recovery gate: *"Without this gate a compromised
    /// node key withdraws its own owner and the single-owner invariant is
    /// worthless."*
    WaAdjudicationRefMissing,
    /// The ref names an `attestation_id` this node does not hold. Authority
    /// must be resolvable from local verified state, and there is none.
    WaAdjudicationRefUnresolvable,
    /// The referenced row exists but is not a CC 4.3 finding — wrong
    /// `attestation_type` or a dimension outside
    /// [`DIMENSION_FINDING_ABANDONMENT`] / [`DIMENSION_FINDING_SEIZURE`].
    NotAWaFinding,
    /// The finding does not adjudicate THIS binding (its
    /// [`field::TARGET_OWNER_BINDING_ID`] or its `attested_key_id` names
    /// something else) — a finding is not a bearer token for every node.
    FindingNotAgainstThisBinding,
    /// Fewer distinct, verified, card-carrying WA roster co-signatures than
    /// the WA body's own threshold demands. The shortfall's numbers ride on
    /// the accompanying [`WaQuorum`].
    WaQuorumShort,

    // ── step 3: the gated withdraws ─────────────────────────────────────
    /// The issuer holds neither CC 2.4.1.1 rule-(2) standing (it IS the
    /// node K, or a named subject of the binding) nor rule-(4) standing (a
    /// live `delegates_to(K → issuer)` carrying
    /// [`DELEGATION_SCOPE_OWNER_BINDING_RECOVERY`]). rc3's recovery path
    /// rides those two rules and no other.
    IssuerLacksRecoveryStanding,
    /// The `withdraws` envelope names a successor owner
    /// ([`SUCCESSOR_OWNER_FIELDS`]) — an attempt to transfer incumbent →
    /// claimant in ONE act. Refused before authority is even considered.
    SingleActTransferAttempted,
    /// An **abandonment** finding, but the incumbent's freshness floor is
    /// still inside the window — the owner is quiet, not gone. (A
    /// **seizure** finding never reaches this test.)
    NotAbandoned,

    // ── step 4: the fresh owner-binding ─────────────────────────────────
    /// K has been through a reclaim, and the fresh owner-binding is not
    /// co-signed by K. CC 3.2 step 4 is *"a fresh owner-binding under the
    /// genesis rule above, co-signed by K"* — the node's own key is what
    /// makes a rebinding a claim rather than a landgrab.
    FreshBindingNotCosignedByNode,
}

impl ReclaimRefusal {
    /// The **stable program token** — identical to the serde token, so a
    /// consumer reading the wire and a consumer holding the typed value key
    /// on the same constant.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NoDeploymentPolicy => "no_deployment_policy",
            Self::AccordRosterIsNotWaAuthority => "accord_roster_is_not_wa_authority",
            Self::AbandonmentWindowBelowFloor => "abandonment_window_below_floor",
            Self::WaBodyUnknown => "wa_body_unknown",
            Self::WaRosterEmpty => "wa_roster_empty",
            Self::PetitionMissing => "petition_missing",
            Self::PetitionUnresolvable => "petition_unresolvable",
            Self::WaAdjudicationRefMissing => "wa_adjudication_ref_missing",
            Self::WaAdjudicationRefUnresolvable => "wa_adjudication_ref_unresolvable",
            Self::NotAWaFinding => "not_a_wa_finding",
            Self::FindingNotAgainstThisBinding => "finding_not_against_this_binding",
            Self::WaQuorumShort => "wa_quorum_short",
            Self::IssuerLacksRecoveryStanding => "issuer_lacks_recovery_standing",
            Self::SingleActTransferAttempted => "single_act_transfer_attempted",
            Self::NotAbandoned => "not_abandoned",
            Self::FreshBindingNotCosignedByNode => "fresh_binding_not_cosigned_by_node",
        }
    }

    /// Which of the four CC 3.2 ceremony steps this refusal names (`0` for
    /// the deployment pin, which precedes the ceremony).
    #[must_use]
    pub const fn ceremony_step(&self) -> u8 {
        match self {
            Self::NoDeploymentPolicy
            | Self::AccordRosterIsNotWaAuthority
            | Self::AbandonmentWindowBelowFloor
            | Self::WaBodyUnknown
            | Self::WaRosterEmpty => 0,
            Self::PetitionMissing | Self::PetitionUnresolvable => 1,
            Self::WaAdjudicationRefMissing
            | Self::WaAdjudicationRefUnresolvable
            | Self::NotAWaFinding
            | Self::FindingNotAgainstThisBinding
            | Self::WaQuorumShort => 2,
            Self::IssuerLacksRecoveryStanding
            | Self::SingleActTransferAttempted
            | Self::NotAbandoned => 3,
            Self::FreshBindingNotCosignedByNode => 4,
        }
    }

    /// v62.0.0 (wave GC3; CC 2.7.3) — **the fold reason** this refusal
    /// holds a row with, or `None` for a refusal that stays a refusal.
    ///
    /// A refusal that reads OTHER rows (the finding, the petition, the WA
    /// body's roster and cards, the issuer's delegations, the freshness
    /// floors) concludes nothing and waits: the row is held and re-folds when
    /// one of those rows lands or is withdrawn. A short WA quorum and a
    /// rebinding without the node's co-signature are the one shortfall
    /// reason (`count_short`). What stays a refusal: the withdraws' own bytes
    /// (`single_act_transfer_attempted`, `wa_adjudication_ref_missing`) and
    /// this deployment's own pin (`no_deployment_policy`,
    /// `accord_roster_is_not_wa_authority`, `abandonment_window_below_floor`:
    /// LOCAL configuration, not another row).
    #[must_use]
    pub const fn fold_reason(&self) -> Option<&'static str> {
        use super::edition2::fold::reason;
        match self {
            Self::NoDeploymentPolicy
            | Self::AccordRosterIsNotWaAuthority
            | Self::AbandonmentWindowBelowFloor
            | Self::WaAdjudicationRefMissing
            | Self::SingleActTransferAttempted => None,
            Self::WaBodyUnknown => Some(reason::WA_BODY_UNKNOWN),
            Self::WaRosterEmpty => Some(reason::WA_ROSTER_EMPTY),
            Self::PetitionMissing => Some(reason::PETITION_MISSING),
            Self::PetitionUnresolvable => Some(reason::PETITION_UNRESOLVABLE),
            Self::WaAdjudicationRefUnresolvable => Some(reason::WA_ADJUDICATION_REF_UNRESOLVABLE),
            Self::NotAWaFinding => Some(reason::NOT_A_WA_FINDING),
            Self::FindingNotAgainstThisBinding => Some(reason::FINDING_NOT_AGAINST_THIS_BINDING),
            Self::IssuerLacksRecoveryStanding => Some(reason::ISSUER_LACKS_RECOVERY_STANDING),
            Self::NotAbandoned => Some(reason::NOT_ABANDONED),
            Self::WaQuorumShort | Self::FreshBindingNotCosignedByNode => Some(reason::COUNT_SHORT),
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::NoDeploymentPolicy,
        Self::AccordRosterIsNotWaAuthority,
        Self::AbandonmentWindowBelowFloor,
        Self::WaBodyUnknown,
        Self::WaRosterEmpty,
        Self::PetitionMissing,
        Self::PetitionUnresolvable,
        Self::WaAdjudicationRefMissing,
        Self::WaAdjudicationRefUnresolvable,
        Self::NotAWaFinding,
        Self::FindingNotAgainstThisBinding,
        Self::WaQuorumShort,
        Self::IssuerLacksRecoveryStanding,
        Self::SingleActTransferAttempted,
        Self::NotAbandoned,
        Self::FreshBindingNotCosignedByNode,
    ];
}

impl std::fmt::Display for ReclaimRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (ceremony step {})",
            self.as_str(),
            self.ceremony_step()
        )
    }
}

/// The re-derived WA quorum behind a finding: how many distinct, verified,
/// card-carrying roster co-signatures were COUNTED, how many the body's own
/// `consensus_protocol` REQUIRED, and how big the roster is.
///
/// Returned on refusal as well as on admission, so an under-signed finding
/// tells its filer how far short it fell rather than merely that something
/// said no.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WaQuorum {
    /// Distinct roster members whose co-signature over the finding envelope
    /// re-verified against pubkeys resolved from THIS node's directory, and
    /// who carry the `wise_authority` card.
    pub counted: usize,
    /// The WA body's own threshold, floored at a strict majority of
    /// `roster_size`.
    pub required: usize,
    /// The revocation-folded active roster size — the denominator, never
    /// shrunk.
    pub roster_size: usize,
}

impl WaQuorum {
    /// Did the finding meet its body's threshold?
    #[must_use]
    pub const fn met(&self) -> bool {
        self.counted >= self.required && self.required > 0
    }
}

/// The outcome of [`check_ownership_reclaim_admission`].
///
/// **Note what `Admit` cannot say.** It names the finding and the quorum
/// that produced it, and nothing else. There is no successor field, no
/// claimant field, and no constructor that could add one — so a caller
/// holding an admitted verdict has been authorized to admit a `withdraws`
/// and *has been handed no way to express who gets the node next*. That is
/// the single-act wall's first level; see the module doc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReclaimVerdict {
    /// `reclaim_row` is not a recovery `withdraws` against a live
    /// owner-binding at all (wrong `attestation_type`, no resolvable
    /// target, target isn't an owner-binding, or the "third party" is the
    /// incumbent owner itself — ordinary self-revocation, rule 1's
    /// territory, never this mechanism's). A pure no-op: callers fall
    /// through to their normal admission logic exactly as if this function
    /// did not exist.
    NotAReclaim,
    /// The ceremony holds: a petitioned, quorum-found, correctly-aimed
    /// adjudication filed by an issuer with CC rule-(2)/(4) standing.
    Admit {
        /// Which finding admitted it.
        finding: WaFinding,
        /// The re-derived quorum behind that finding.
        quorum: WaQuorum,
    },
    /// Refused — naming WHICH ceremony step failed.
    Refused {
        /// The typed step-naming reason.
        reason: ReclaimRefusal,
        /// A human-readable diagnostic. Never parsed; [`ReclaimRefusal`] is
        /// the stable surface.
        detail: String,
        /// The re-derived quorum, when the ceremony got far enough to
        /// compute one.
        quorum: Option<WaQuorum>,
    },
}

impl ReclaimVerdict {
    /// The refusal reason, if this is a refusal.
    #[must_use]
    pub const fn refusal(&self) -> Option<ReclaimRefusal> {
        match self {
            Self::Refused { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    /// Is this an admission?
    #[must_use]
    pub const fn is_admit(&self) -> bool {
        matches!(self, Self::Admit { .. })
    }

    fn refuse(reason: ReclaimRefusal, detail: impl Into<String>) -> Self {
        Self::Refused {
            reason,
            detail: detail.into(),
            quorum: None,
        }
    }
}

/// The deployment-published reclaim policy: the CC 3.2 abandonment window
/// and the CC 4.3 Wise-Authority body that adjudicates.
///
/// Both halves are **deployment-published**, not invented here. CC 1.16.5
/// puts WA appointment outside this system's control, and CC 3.2 requires a
/// deployment to publish its window — so persist is handed a family
/// `key_id`, re-derives roster and threshold from its OWN stored state, and
/// refuses when handed nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimPolicy {
    /// An owner whose signed freshness floor has not advanced within this
    /// window is provably-abandoned. Deployment value; CC pins the floor.
    pub abandonment_window: Duration,
    /// The `federation_families.family_key_id` of the CC 4.3 Wise-Authority
    /// body. Its roster and its `consensus_protocol` are read from this
    /// node's own stored state at every use.
    pub wa_family_key_id: String,
}

impl ReclaimPolicy {
    /// The shipped default abandonment window: **180 days** — twice CC's
    /// floor. rc3 confirms this is compliant as a deployment value.
    pub const DEFAULT_ABANDONMENT_WINDOW: Duration = Duration::days(180);

    /// CC 3.2's ratified **floor** on `owner_abandonment_window`: 90 days.
    /// A deployment may publish more, never less.
    pub const CC_ABANDONMENT_WINDOW_FLOOR: Duration = Duration::days(90);

    /// Environment variable publishing the CC 4.3 WA body's
    /// `family_key_id`. Unset ⇒ [`from_deployment_pin`](Self::from_deployment_pin)
    /// yields `None` ⇒ every reclaim refused.
    pub const WA_FAMILY_ENV: &'static str = "CIRIS_PERSIST_WA_ADJUDICATION_FAMILY_KEY_ID";

    /// Environment variable publishing `owner_abandonment_window` in whole
    /// days. Unset ⇒ [`DEFAULT_ABANDONMENT_WINDOW`](Self::DEFAULT_ABANDONMENT_WINDOW).
    pub const ABANDONMENT_WINDOW_DAYS_ENV: &'static str =
        "CIRIS_PERSIST_OWNER_ABANDONMENT_WINDOW_DAYS";

    /// A policy naming `wa_family_key_id` as the adjudicating WA body, at
    /// the shipped 180-day window.
    #[must_use]
    pub fn wise_authority(wa_family_key_id: impl Into<String>) -> Self {
        Self {
            abandonment_window: Self::DEFAULT_ABANDONMENT_WINDOW,
            wa_family_key_id: wa_family_key_id.into(),
        }
    }

    /// The deployment's published pin, or `None` when it has published
    /// none.
    ///
    /// `None` is the SHIPPED state and it is the safe one: with no
    /// published WA body every reclaim is refused with
    /// [`ReclaimRefusal::NoDeploymentPolicy`], so no node in the mesh is
    /// seizable until an operator deliberately names an adjudicating body.
    /// A malformed or below-floor window is likewise `None` rather than
    /// clamped — running a window nobody published is exactly what CC 3.2
    /// forbids.
    #[must_use]
    pub fn from_deployment_pin() -> Option<Self> {
        let family = std::env::var(Self::WA_FAMILY_ENV).ok()?;
        let family = family.trim();
        if family.is_empty() {
            return None;
        }
        let window = match std::env::var(Self::ABANDONMENT_WINDOW_DAYS_ENV) {
            Ok(raw) => Duration::days(raw.trim().parse::<i64>().ok()?),
            Err(_) => Self::DEFAULT_ABANDONMENT_WINDOW,
        };
        if window < Self::CC_ABANDONMENT_WINDOW_FLOOR {
            return None;
        }
        Some(Self {
            abandonment_window: window,
            wa_family_key_id: family.to_owned(),
        })
    }

    /// Is the pin structurally admissible at all? Returns the step-0
    /// refusal when not.
    fn pin_refusal(&self) -> Option<ReclaimRefusal> {
        if self.wa_family_key_id.trim().is_empty() {
            return Some(ReclaimRefusal::WaBodyUnknown);
        }
        if self.wa_family_key_id == ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID
        {
            return Some(ReclaimRefusal::AccordRosterIsNotWaAuthority);
        }
        if self.abandonment_window < Self::CC_ABANDONMENT_WINDOW_FLOOR {
            return Some(ReclaimRefusal::AbandonmentWindowBelowFloor);
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Producer-side envelope builders (the wire shapes, published once)
// ─────────────────────────────────────────────────────────────────────────

fn extra_envelope(
    dimension: &str,
    references: Option<&str>,
    pairs: &[(&str, serde_json::Value)],
) -> serde_json::Value {
    let mut extra = serde_json::Map::new();
    extra.insert(
        crate::federation::envelope::paths::DIMENSION.to_owned(),
        serde_json::Value::String(dimension.to_owned()),
    );
    for (k, v) in pairs {
        extra.insert((*k).to_owned(), v.clone());
    }
    EnvelopeCore {
        references_attestation_id: references.map(str::to_owned),
        extra,
        ..Default::default()
    }
    .to_value()
}

/// **Step 1.** Build the petition envelope naming the owner-binding under
/// adjudication and the evidence.
#[must_use]
pub fn build_reclaim_petition_envelope(
    target_owner_binding_id: &str,
    grounds: &str,
) -> serde_json::Value {
    extra_envelope(
        DIMENSION_PETITION,
        None,
        &[
            (
                field::TARGET_OWNER_BINDING_ID,
                serde_json::Value::String(target_owner_binding_id.to_owned()),
            ),
            (
                field::GROUNDS,
                serde_json::Value::String(grounds.to_owned()),
            ),
        ],
    )
}

/// **Step 2.** Build the CC 4.3 quorum-finding envelope. The WA body's
/// members co-sign THIS envelope (base scrub + `additional_scrubs`); the
/// count is re-derived at use.
#[must_use]
pub fn build_wa_finding_envelope(
    finding: WaFinding,
    target_owner_binding_id: &str,
    petition_ref: &str,
    grounds: &str,
) -> serde_json::Value {
    extra_envelope(
        finding.dimension(),
        None,
        &[
            (
                field::TARGET_OWNER_BINDING_ID,
                serde_json::Value::String(target_owner_binding_id.to_owned()),
            ),
            (
                field::PETITION_REF,
                serde_json::Value::String(petition_ref.to_owned()),
            ),
            (
                field::GROUNDS,
                serde_json::Value::String(grounds.to_owned()),
            ),
        ],
    )
}

/// **Step 3.** Build the gated `withdraws` envelope: it references the
/// owner-binding being withdrawn and carries the
/// [`field::WA_ADJUDICATION_REF`] naming the finding.
///
/// There is deliberately **no parameter** here for a successor owner. The
/// builder cannot express the single-act transfer, and a hand-rolled
/// envelope that does is refused by
/// [`ReclaimRefusal::SingleActTransferAttempted`].
#[must_use]
pub fn build_reclaim_withdraws_envelope(
    target_attestation_id: &str,
    wa_adjudication_ref: &str,
) -> serde_json::Value {
    let mut extra = serde_json::Map::new();
    extra.insert(
        field::WA_ADJUDICATION_REF.to_owned(),
        serde_json::Value::String(wa_adjudication_ref.to_owned()),
    );
    EnvelopeCore {
        references_attestation_id: Some(target_attestation_id.to_owned()),
        extra,
        ..Default::default()
    }
    .to_value()
}

// ── v62.0.0 (JSON-cut slice B) — the three steps as edition-2 drafts ──────
//
// The builders above return the earlier JSON envelope a holder signed by its
// JCS bytes. On the clean mesh each step is a row its signer states with its
// own composite key: these return the [`Draft`](super::edition2::emit::Draft)
// (the CBOR payload and the `Sig_structure` bytes to sign) for the signer
// whose kid is `kid` and identity-ref `iss`. The members are the builders',
// so the gates read the same row; the withdraws names the binding by
// (`(kid, iss)` is the signer the draft is for.)
// `refs.target` and carries the binding's family.

/// **Step 1 draft**: the petition (a `scores` row about `node`).
///
/// # Errors
/// `edition2_payload_invalid`.
pub fn draft_reclaim_petition(
    (kid, iss): (&super::edition2::Digest32, &str),
    node: &str,
    target_owner_binding_id: &str,
    grounds: &str,
    asserted_at_ms: u64,
) -> Result<super::edition2::emit::Draft, Error> {
    super::edition2::emit::draft_from_envelope(
        kid,
        iss,
        node,
        super::types::attestation_type::SCORES,
        &build_reclaim_petition_envelope(target_owner_binding_id, grounds),
        asserted_at_ms,
        None,
    )
}

/// **Step 2 draft**: the WA finding; each WA member drafts and signs its own
/// voice over the same payload.
///
/// # Errors
/// `edition2_payload_invalid`.
pub fn draft_wa_finding(
    (kid, iss): (&super::edition2::Digest32, &str),
    node: &str,
    finding: WaFinding,
    target_owner_binding_id: &str,
    petition_ref: &str,
    grounds: &str,
    asserted_at_ms: u64,
) -> Result<super::edition2::emit::Draft, Error> {
    super::edition2::emit::draft_from_envelope(
        kid,
        iss,
        node,
        super::types::attestation_type::SCORES,
        &build_wa_finding_envelope(finding, target_owner_binding_id, petition_ref, grounds),
        asserted_at_ms,
        None,
    )
}

/// **Step 3 draft**: the gated `withdraws` of the owner binding
/// `target_owner_binding_id` (an edition-2 row id), carrying the binding's
/// family `target_family` (`CC-READING(next-edition)`).
///
/// # Errors
/// `edition2_payload_invalid` (a target that is not a row id included).
pub fn draft_reclaim_withdraws(
    (kid, iss): (&super::edition2::Digest32, &str),
    node: &str,
    target_owner_binding_id: &str,
    target_family: &str,
    wa_adjudication_ref: &str,
    asserted_at_ms: u64,
) -> Result<super::edition2::emit::Draft, Error> {
    let target = super::edition2::store::id_of_hex(target_owner_binding_id).ok_or_else(|| {
        Error::InvalidArgument(format!(
            "edition2_payload_invalid: {target_owner_binding_id:?} is not an edition-2 row id"
        ))
    })?;
    // v62.0.0 (HEAD-3; CC 2.4.1.1, "Where one row between two keys is the
    // whole record, as an owner-binding is, that row is the head") — the end
    // names the binding it ends as the head it acts from. It is one
    // signer's (authored) end: its count is the cited WA finding, so it
    // carries no `lifts` (`lifts_on_own_end`).
    super::edition2::emit::draft_from_envelope_naming_head(
        kid,
        iss,
        node,
        super::types::attestation_type::WITHDRAWS,
        &build_reclaim_withdraws_envelope(target_owner_binding_id, wa_adjudication_ref),
        asserted_at_ms,
        Some((&target, target_family)),
        &super::edition2::names::RowId(target),
    )
}

// ─────────────────────────────────────────────────────────────────────────
//  The re-derived WA quorum
// ─────────────────────────────────────────────────────────────────────────

/// Read a non-empty string field. An EMPTY string is read as ABSENT, so a
/// producer that ships `"wa_adjudication_ref": ""` is told the reference is
/// MISSING (which it is) rather than that it failed to resolve — the refusal
/// has to point at the actual mistake or it sends the operator hunting for a
/// finding that was never named.
fn envelope_str<'a>(envelope: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    envelope
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Re-derive the CC 4.3 WA quorum behind `finding` from THIS node's own
/// verified state, and count it.
///
/// - **Roster** — [`FederationDirectory::active_family_members`] of the
///   pinned body (revocation-folded). Membership itself is governed by the
///   family's own m-of-n, so a Sybil cannot seat itself.
/// - **Threshold** — [`family_charter_threshold`](super::trust_root) over
///   the body's own stored `consensus_protocol`, floored at a strict
///   majority and fail-secure on anything it does not recognise.
/// - **Count** — [`count_distinct_roster_scrubs`](super::reverse_quorum),
///   re-verifying every co-signature against pubkeys from this node's
///   directory, restricted to roster members that wear the CC 4.3
///   `wise_authority` card.
///
/// # Why the denominator is the FULL roster
///
/// CC 4.3 rule 1 lets an unresponsive WA lapse out of a live set `L` so an
/// absent WA cannot *block*. Persist deliberately does **not** shrink the
/// denominator here, because on THIS path shrinking `L` lowers the
/// threshold, and the threshold is what stands between an adversary and
/// somebody else's node: an attacker who can silence WAs would otherwise be
/// able to shrink the body down to the few seats it has captured. Counting
/// against the full roster can only ever REFUSE more than CC requires,
/// never admit more — the safe direction on a seizure path. (The blocking
/// concern CC 4.3 addresses is real for *deferrals*, where the cost of
/// absence is a frozen agent; here the cost of absence is that a node stays
/// owned by its incumbent, which is the status quo, not a freeze.)
async fn wa_quorum_over_body(
    directory: &dyn FederationDirectory,
    policy: &ReclaimPolicy,
    finding: &Attestation,
) -> Result<Result<WaQuorum, (ReclaimRefusal, String)>, Error> {
    // A family this node does not hold is `WaBodyUnknown`. v62.0.0 (PX-fix3)
    // — a directory that cannot answer (`Unsupported`) is an error, not an
    // unknown body (I2190).
    // v62.0.0 (wave GC3) — the WA body, its roster, its members' cards and
    // the finding's voices are all OTHER rows: declared for the fold.
    fold::reads(Dep::key(&policy.wa_family_key_id));
    fold::reads(
        Dep::row_hex(&finding.attestation_id).unwrap_or_else(|| Dep::key(&finding.attestation_id)),
    );
    let family = match directory.lookup_family(&policy.wa_family_key_id).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return Ok(Err((
                ReclaimRefusal::WaBodyUnknown,
                format!(
                    "the published WA body {:?} is not a family this node can resolve — \
                     authority must be re-derived from local verified state, and there is none",
                    policy.wa_family_key_id
                ),
            )));
        }
        Err(e) => return Err(e),
    };
    let roster: Vec<String> = match directory
        .active_family_members(&policy.wa_family_key_id)
        .await
    {
        Ok(members) => members.into_iter().map(|m| m.key_id).collect(),
        Err(e) => return Err(e),
    };
    if roster.is_empty() {
        return Ok(Err((
            ReclaimRefusal::WaRosterEmpty,
            format!(
                "the WA body {:?} has an empty active roster — no threshold is meetable",
                policy.wa_family_key_id
            ),
        )));
    }
    // The threshold is the BODY's own, over the FULL roster (see the doc).
    let required = super::trust_root::family_charter_threshold(&family, roster.len());

    // CC 4.3 "The Wise wear the same card": only roster members whose
    // registered identity_type set carries `wise_authority` are counted. A
    // legibility filter on the NUMERATOR — the seat is what confers, so this
    // can only refuse, never admit.
    let mut carded: Vec<String> = Vec::with_capacity(roster.len());
    for key_id in &roster {
        fold::reads(Dep::key(key_id));
        if let Some(rec) = directory.lookup_public_key(key_id).await? {
            if identity_type::set_contains(&rec.identity_type, identity_type::WISE_AUTHORITY) {
                carded.push(rec.key_id);
            }
        }
    }
    // v62.0.0 (wave V1, I3284) — an edition-2 finding's cosigners are its
    // VOICES: each WA member's own statement over the finding's payload,
    // held in `ceg_statements` under the finding's row id
    // (`edition2::voices`), never an `additional_scrubs` set. Distinct `iss`,
    // restricted to the carded roster exactly as before. An earlier-form
    // finding keeps the scrub count behind the earlier-form switch.
    let counted =
        super::edition2::voices::counted_roster_signers(directory, finding, &carded).await?;
    Ok(Ok(WaQuorum {
        counted: counted.len(),
        required,
        roster_size: roster.len(),
    }))
}

/// rc3's answer to persist's open question 3, encoded: *"the owner-binding
/// attestation itself establishes the initial floor, so a binding is never
/// floorless."*
///
/// The floor for the abandonment predicate is therefore the LATER of every
/// signed touch-claim floor this node holds and the binding's own
/// `asserted_at`. Consequence: a binding whose owner never emitted a single
/// touch-claim is still measurable — it simply has to be older than the
/// window — which is what makes the CC 3.2 MUST reachable instead of
/// permanently blocked on a producer that does not exist yet. It is still
/// FAIL-SAFE in the direction that matters: a *recent* binding is never
/// abandoned, and no floor is ever invented from thin air.
fn initial_freshness_floor(
    binding: &Attestation,
    touch_floors: [Option<DateTime<Utc>>; 2],
) -> DateTime<Utc> {
    let mut floor = binding.asserted_at;
    for f in touch_floors.into_iter().flatten() {
        floor = merge_floor(floor, f);
    }
    floor
}

/// Does `issuer` hold CC 2.4.1.1 rule-(4) standing on `node` — a live
/// `delegates_to(node → issuer)` carrying
/// [`DELEGATION_SCOPE_OWNER_BINDING_RECOVERY`]?
async fn holds_recovery_delegation(
    directory: &dyn FederationDirectory,
    node: &str,
    issuer: &str,
    now: DateTime<Utc>,
) -> Result<bool, Error> {
    let mut pages = AttestationQuery::by(node, FOLD_PAGE)
        .view(crate::federation::attestation_query::ContentView::Record)
        .attested_to(issuer)
        .types(&[attestation_type::DELEGATES_TO])
        .pages();
    while let Some(page) = pages.next(directory).await? {
        for r in page {
            if r.expires_at.is_some_and(|exp| exp <= now) {
                continue;
            }
            let scopes = super::admission::delegation_scope_set(&r.attestation_envelope);
            if scopes.contains(DELEGATION_SCOPE_OWNER_BINDING_RECOVERY) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

// ─────────────────────────────────────────────────────────────────────────
//  The gate
// ─────────────────────────────────────────────────────────────────────────

/// **The CC 3.2 recovery gate.** Is `reclaim_row` — a `withdraws` against a
/// LIVE owner-binding issued by someone other than the incumbent owner — an
/// admissible step 3 of the four-step reclaim ceremony?
///
/// Called from [`super::admission::check_withdraws_admission`] in BOTH
/// directions, which is the point:
///
/// - when the ordinary 4-rule gate REFUSES (persist's owner-bindings carry
///   no `subject_key_ids` today, so rule 2 never fires for them), this is
///   the sanctioned exception — recorded as rule
///   [`RECLAIM_WITHDRAWS_ADMISSION_RULE`];
/// - when the ordinary gate ADMITS under rule 2, 3 or 4 against a live
///   owner-binding, this gate must ALSO pass. That is CC 3.2's recovery
///   gate, and without it *"a compromised node key withdraws its own owner
///   and the single-owner invariant is worthless"* — the self-liberation
///   exploit rule 2 opens the moment a conformant producer starts naming K
///   in the binding's `subject_key_ids`, as CC 3.2 says it must.
///
/// `now` is threaded explicitly so tests are deterministic.
///
/// v62.0.0 (wave GC3; CC 2.7.3) — a refusal whose
/// [`ReclaimRefusal::fold_reason`] is `Some` read OTHER rows: inside a fold
/// attempt it marks the row held with that reason (the caller's
/// `OwnershipReclaimRefused` is then the held row's detail), and every row
/// the ceremony read is declared, so the withdraws re-folds when the
/// finding, the petition, a WA card or voice, a delegation or a freshness
/// floor changes. Outside an attempt the verdict is exactly what it was.
pub async fn check_ownership_reclaim_admission(
    directory: &dyn FederationDirectory,
    reclaim_row: &Attestation,
    policy: Option<&ReclaimPolicy>,
    now: DateTime<Utc>,
) -> Result<ReclaimVerdict, Error> {
    let verdict = reclaim_verdict(directory, reclaim_row, policy, now).await?;
    if let Some(reason) = verdict.refusal().and_then(|r| r.fold_reason()) {
        fold::note(reason);
    }
    Ok(verdict)
}

/// The ceremony's verdict ([`check_ownership_reclaim_admission`] marks the
/// fold from it).
async fn reclaim_verdict(
    directory: &dyn FederationDirectory,
    reclaim_row: &Attestation,
    policy: Option<&ReclaimPolicy>,
    now: DateTime<Utc>,
) -> Result<ReclaimVerdict, Error> {
    // (0) Shape check: is this even a candidate? A pure no-op otherwise —
    //     callers fall through to their normal logic unchanged.
    if reclaim_row.attestation_type != attestation_type::WITHDRAWS {
        return Ok(ReclaimVerdict::NotAReclaim);
    }
    let Some(target_id) =
        references_attestation_id_from_envelope(&reclaim_row.attestation_envelope)
    else {
        return Ok(ReclaimVerdict::NotAReclaim);
    };
    // v62.0.0 (wave GC3) — the target binding is read: its arrival (or
    // withdrawal) re-folds this withdraws.
    fold::reads(Dep::row_hex(target_id).unwrap_or_else(|| Dep::key(target_id)));
    let Some(target) = directory.get_attestation(target_id).await? else {
        return Ok(ReclaimVerdict::NotAReclaim);
    };
    if !is_owner_binding_envelope(&target.attestation_envelope) {
        return Ok(ReclaimVerdict::NotAReclaim);
    }
    // Self-withdrawal (the incumbent revoking their OWN binding) is ordinary
    // rule-1 authority — never a reclaim, regardless of policy.
    if reclaim_row.attesting_key_id == target.attesting_key_id {
        return Ok(ReclaimVerdict::NotAReclaim);
    }

    // (1) THE SINGLE-ACT WALL, checked before authority is even considered.
    //     A `withdraws` that names who gets the node next is not step 3 of a
    //     four-step ceremony; it is the collapse rc3 forbids by name.
    for key in SUCCESSOR_OWNER_FIELDS {
        if reclaim_row.attestation_envelope.get(key).is_some() {
            return Ok(ReclaimVerdict::refuse(
                ReclaimRefusal::SingleActTransferAttempted,
                format!(
                    "the gated withdraws names a successor owner ({key:?}); CC 3.2 forbids \
                     transferring incumbent → claimant in one act — K MUST pass through the \
                     unowned state, then take a fresh owner-binding co-signed by K"
                ),
            ));
        }
    }

    // (2) The deployment pin. No published WA body ⇒ nothing is admissible
    //     here (fail-secure, and exactly what CC 3.2 says about an
    //     unpublished window).
    let Some(policy) = policy else {
        return Ok(ReclaimVerdict::refuse(
            ReclaimRefusal::NoDeploymentPolicy,
            format!(
                "this deployment has published no CC 4.3 Wise-Authority body (set {}) and no \
                 owner_abandonment_window — no reclaim is admissible here",
                ReclaimPolicy::WA_FAMILY_ENV
            ),
        ));
    };
    if let Some(reason) = policy.pin_refusal() {
        let detail = match reason {
            ReclaimRefusal::AccordRosterIsNotWaAuthority => format!(
                "the published reclaim authority {:?} is the HUMANITY_ACCORD family; \
                 CIRISConstitution rc3 moved ownerless-reclaim authority to the CC 4.3 \
                 Wise-Authority quorum — the accord holder roster is NOT a WA body",
                policy.wa_family_key_id
            ),
            ReclaimRefusal::AbandonmentWindowBelowFloor => format!(
                "the published owner_abandonment_window ({}s) is below CC 3.2's 90-day floor",
                policy.abandonment_window.num_seconds()
            ),
            _ => "the published WA body key_id is empty".to_owned(),
        };
        return Ok(ReclaimVerdict::refuse(reason, detail));
    }

    // (3) Step 2 — the wa_adjudication_ref MUST be present and MUST resolve
    //     to a real CC 4.3 finding against THIS binding.
    let Some(finding_ref) = envelope_str(
        &reclaim_row.attestation_envelope,
        field::WA_ADJUDICATION_REF,
    ) else {
        return Ok(ReclaimVerdict::refuse(
            ReclaimRefusal::WaAdjudicationRefMissing,
            format!(
                "the withdraws against owner-binding {} carries no {:?}; CC 3.2 REQUIRES the \
                 gated withdraws to name a CC 4.3 Wise-Authority quorum finding of abandonment \
                 or seizure — the substrate records the finding, it never makes it",
                target.attestation_id,
                field::WA_ADJUDICATION_REF
            ),
        ));
    };
    fold::reads(Dep::row_hex(finding_ref).unwrap_or_else(|| Dep::key(finding_ref)));
    let Some(finding_row) = directory.get_attestation(finding_ref).await? else {
        return Ok(ReclaimVerdict::refuse(
            ReclaimRefusal::WaAdjudicationRefUnresolvable,
            format!(
                "{:?} {finding_ref:?} resolves to no attestation this node holds",
                field::WA_ADJUDICATION_REF
            ),
        ));
    };
    let Some(finding) = super::admission::envelope_dimension(&finding_row.attestation_envelope)
        .and_then(WaFinding::from_dimension)
        .filter(|_| finding_row.attestation_type == attestation_type::SCORES)
    else {
        return Ok(ReclaimVerdict::refuse(
            ReclaimRefusal::NotAWaFinding,
            format!(
                "{finding_ref:?} is not a CC 4.3 quorum finding — expected a `scores` row on \
                 {DIMENSION_FINDING_ABANDONMENT:?} or {DIMENSION_FINDING_SEIZURE:?}"
            ),
        ));
    };
    let binds_this = envelope_str(
        &finding_row.attestation_envelope,
        field::TARGET_OWNER_BINDING_ID,
    ) == Some(target.attestation_id.as_str())
        && finding_row.attested_key_id == target.attested_key_id;
    if !binds_this {
        return Ok(ReclaimVerdict::refuse(
            ReclaimRefusal::FindingNotAgainstThisBinding,
            format!(
                "finding {finding_ref:?} does not adjudicate owner-binding {} on node {} — a \
                 finding is scoped to one binding, never a bearer token for every node",
                target.attestation_id, target.attested_key_id
            ),
        ));
    }

    // (4) Step 1 — the petition. A finding with no resolvable petition
    //     against the SAME binding is a collapsed ceremony.
    let Some(petition_ref) = envelope_str(&finding_row.attestation_envelope, field::PETITION_REF)
    else {
        return Ok(ReclaimVerdict::refuse(
            ReclaimRefusal::PetitionMissing,
            format!(
                "finding {finding_ref:?} carries no {:?}; the CC 3.2 ceremony is FOUR steps and \
                 MUST NOT be collapsed — step 1 is a petition naming K and the evidence",
                field::PETITION_REF
            ),
        ));
    };
    fold::reads(Dep::row_hex(petition_ref).unwrap_or_else(|| Dep::key(petition_ref)));
    let petition_ok = match directory.get_attestation(petition_ref).await? {
        Some(p) => {
            super::admission::envelope_dimension(&p.attestation_envelope)
                == Some(DIMENSION_PETITION)
                && envelope_str(&p.attestation_envelope, field::TARGET_OWNER_BINDING_ID)
                    == Some(target.attestation_id.as_str())
                && p.attested_key_id == target.attested_key_id
        }
        None => false,
    };
    if !petition_ok {
        return Ok(ReclaimVerdict::refuse(
            ReclaimRefusal::PetitionUnresolvable,
            format!(
                "{:?} {petition_ref:?} does not resolve to a {DIMENSION_PETITION:?} row against \
                 owner-binding {} on node {}",
                field::PETITION_REF,
                target.attestation_id,
                target.attested_key_id
            ),
        ));
    }

    // (5) Step 2 — re-tally the WA quorum from this node's OWN state.
    let quorum = match wa_quorum_over_body(directory, policy, &finding_row).await? {
        Ok(q) => q,
        Err((reason, detail)) => return Ok(ReclaimVerdict::refuse(reason, detail)),
    };
    if !quorum.met() {
        return Ok(ReclaimVerdict::Refused {
            reason: ReclaimRefusal::WaQuorumShort,
            detail: format!(
                "finding {finding_ref:?} carries {} distinct verified card-carrying co-signature(s) \
                 from the WA body {:?}, but its own consensus_protocol demands {} of {}",
                quorum.counted, policy.wa_family_key_id, quorum.required, quorum.roster_size
            ),
            quorum: Some(quorum),
        });
    }

    // (6) Step 3 — the issuer's standing. rc3's recovery path rides CC
    //     2.4.1.1 rule (2) (the node K itself, or a named subject of the
    //     binding) and rule (4) (a live owner_binding_recovery delegate of
    //     K) — and no other.
    let node = target.attested_key_id.as_str();
    let issuer = reclaim_row.attesting_key_id.as_str();
    // v62.0.0 (wave GC3) — the node's delegations to the issuer, and (below)
    // the incumbent's and the node's freshness floors.
    fold::reads(Dep::key(node));
    fold::reads(Dep::key(issuer));
    let rule2 = issuer == node || target.subject_key_ids.iter().any(|s| s == issuer);
    let standing = rule2 || holds_recovery_delegation(directory, node, issuer, now).await?;
    if !standing {
        return Ok(ReclaimVerdict::Refused {
            reason: ReclaimRefusal::IssuerLacksRecoveryStanding,
            detail: format!(
                "{issuer:?} is neither the node {node:?} nor a named subject of the binding \
                 (CC 2.4.1.1 rule 2), and holds no live delegates_to({node} → {issuer}) carrying \
                 {DELEGATION_SCOPE_OWNER_BINDING_RECOVERY:?} (rule 4)"
            ),
            quorum: Some(quorum),
        });
    }

    // (7) The abandonment predicate — persist's OWN evidence, on top of the
    //     quorum's finding. A SEIZURE finding never reaches this test: rc3
    //     is explicit that the recovery path also reaches a LIVE wrongful
    //     binding, so requiring staleness there would make front-running
    //     permanent, which is the failure this clause exists to prevent.
    if finding == WaFinding::Abandonment {
        let incumbent = target.attesting_key_id.as_str();
        fold::reads(Dep::key(incumbent));
        // v62.0.0 (P5b) — the floor as this node holds it, whichever write
        // set it (a touch claim is node-local).
        let incumbent_floor = directory
            .freshness_floor(incumbent, OWNERSHIP_FRESHNESS_TARGET_KIND)
            .await?
            .map(|f| f.fresh_as_of);
        let node_floor = directory
            .freshness_floor(node, OWNERSHIP_FRESHNESS_TARGET_KIND)
            .await?
            .map(|f| f.fresh_as_of);
        let floor = initial_freshness_floor(&target, [incumbent_floor, node_floor]);
        let cutoff = now - policy.abandonment_window;
        if floor >= cutoff {
            return Ok(ReclaimVerdict::Refused {
                reason: ReclaimRefusal::NotAbandoned,
                detail: format!(
                    "incumbent owner {incumbent} (or node {node}) has a freshness floor of \
                     {floor} — inside the {}s abandonment window; the owner is quiet, not gone",
                    policy.abandonment_window.num_seconds()
                ),
                quorum: Some(quorum),
            });
        }
    }

    Ok(ReclaimVerdict::Admit { finding, quorum })
}

/// **Ceremony step 4** — a fresh owner-binding on a node that has been
/// through a reclaim MUST be co-signed by that node.
///
/// Asked by the shared attestation plan (`plan_put_attestation`) beside
/// [`super::admission::check_owner_binding_roster_fresh`] (v62.0.0: the
/// single-owner gate that called it is deleted), so every backend inherits it
/// from one chokepoint.
///
/// "Has been through a reclaim" is derived from this node's own stored
/// rows and nothing else: a `withdraws` against K stamped with
/// [`RECLAIM_WITHDRAWS_ADMISSION_RULE`] by the gate above. The
/// co-signature is counted with the same
/// [`count_distinct_roster_scrubs`](super::reverse_quorum) body the WA
/// quorum uses — one predicate, one implementation — over the one-member
/// roster `[K]`.
///
/// A no-op for a first (genesis) binding and for a refresh by the incumbent:
/// #578 rules on the RECLAIM rebinding, and widening the co-signature
/// requirement to every binding in the mesh is a separate, producer-visible
/// change.
pub async fn check_post_reclaim_rebinding_admission(
    directory: &dyn FederationDirectory,
    row: &Attestation,
) -> Result<(), Error> {
    if row.attestation_type != attestation_type::DELEGATES_TO
        || !is_owner_binding_envelope(&row.attestation_envelope)
    {
        return Ok(());
    }
    let node = row.attested_key_id.as_str();
    // v62.0.0 (wave GC3; CC 2.7.3) — the reclaim withdraws against the node
    // and the node's co-signature are other rows / voices: declared, and a
    // missing co-signature HOLDS the binding (`count_short`) until the
    // node's voice lands.
    fold::reads(Dep::key(node));
    fold::reads(Dep::row_hex(&row.attestation_id).unwrap_or_else(|| Dep::key(&row.attestation_id)));
    let mut reclaimed = false;
    let mut pages = AttestationQuery::to(node, FOLD_PAGE)
        .view(crate::federation::attestation_query::ContentView::Record)
        .types(&[attestation_type::WITHDRAWS])
        .pages();
    while let Some(page) = pages.next(directory).await? {
        if page
            .iter()
            .any(|r| r.withdraws_admission_rule == Some(RECLAIM_WITHDRAWS_ADMISSION_RULE))
        {
            reclaimed = true;
            break;
        }
    }
    if !reclaimed {
        return Ok(());
    }
    // v62.0.0 (wave V1b, I3285) — an edition-2 binding is judged by the one
    // owner-binding counted rule (`admission::check_owner_binding_counted`),
    // which runs for EVERY owner binding, reclaimed node or not: without the
    // bound key's own voice the door keeps the owner's voice and the binding
    // waits (`Pending`, no typed row); the node's voice over the same row
    // lands it. So this step-4 check has nothing left to add for it. An
    // earlier-form binding keeps the admission check behind the earlier-form
    // switch.
    if super::edition2::voices::carried_row_id(row).is_some() {
        return Ok(());
    }
    let node_roster = [node.to_owned()];
    let cosigned =
        super::edition2::voices::counted_roster_signers(directory, row, &node_roster).await?;
    if cosigned.is_empty() {
        return Err(fold::hold(
            fold::reason::COUNT_SHORT,
            Error::OwnershipReclaimRefused {
                node_key_id: node.to_owned(),
                owner_binding_id: row.attestation_id.clone(),
                reason: ReclaimRefusal::FreshBindingNotCosignedByNode,
                detail: format!(
                    "node {node} has been through a CC 3.2 reclaim, so its fresh owner-binding \
                     MUST be co-signed by {node} itself (ceremony step 4); the row carries no \
                     verifying co-signature from it"
                ),
            },
        ));
    }
    Ok(())
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::test_support as rts;
    use super::*;
    use crate::engine::Engine;
    use crate::signing::LocalSigner;
    use ed25519_dalek::SigningKey;
    use std::sync::Arc;

    fn test_signer() -> Arc<LocalSigner> {
        let signing_key = SigningKey::from_bytes(&[0x9Cu8; 32]);
        Arc::new(LocalSigner::from_parts(
            signing_key,
            "ownership-reclaim-test-steward".to_string(),
            None,
            None,
        ))
    }

    /// Every refusal token is unique and non-empty, and every ceremony step
    /// 0..=4 is named by at least one variant — so no step can be silently
    /// dropped from the enum while the ceremony still claims four steps.
    #[test]
    fn refusal_tokens_are_closed_and_cover_every_ceremony_step() {
        use std::collections::BTreeSet;
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut steps: BTreeSet<u8> = BTreeSet::new();
        for r in ReclaimRefusal::ALL {
            assert!(!r.as_str().is_empty(), "{r:?} has an empty token");
            assert!(seen.insert(r.as_str()), "duplicate token for {r:?}");
            steps.insert(r.ceremony_step());
        }
        assert_eq!(
            seen.len(),
            ReclaimRefusal::ALL.len(),
            "ALL must list every variant exactly once"
        );
        for step in 0u8..=4 {
            assert!(
                steps.contains(&step),
                "no refusal names ceremony step {step} — a step nothing can refuse is a step \
                 nothing enforces"
            );
        }
    }

    /// The shipped default: 180 days, twice CC 3.2's 90-day floor, and the
    /// floor is what the policy gate actually applies.
    #[test]
    fn shipped_window_is_compliant_and_the_floor_bites() {
        assert_eq!(
            ReclaimPolicy::DEFAULT_ABANDONMENT_WINDOW,
            Duration::days(180)
        );
        assert!(
            ReclaimPolicy::DEFAULT_ABANDONMENT_WINDOW >= ReclaimPolicy::CC_ABANDONMENT_WINDOW_FLOOR
        );
        let mut short = ReclaimPolicy::wise_authority("wa-body");
        short.abandonment_window = Duration::days(7);
        assert_eq!(
            short.pin_refusal(),
            Some(ReclaimRefusal::AbandonmentWindowBelowFloor)
        );
        assert_eq!(ReclaimPolicy::wise_authority("wa-body").pin_refusal(), None);
    }

    /// **The rc3 non-conformance, named.** A policy pointing reclaim
    /// authority at the HUMANITY_ACCORD holder roster is REFUSED — that is
    /// what `ReclaimPolicy::humanity_accord_default` shipped in v21.8.0.
    #[test]
    fn accord_roster_is_refused_as_reclaim_authority() {
        let accord = ReclaimPolicy::wise_authority(
            ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID,
        );
        assert_eq!(
            accord.pin_refusal(),
            Some(ReclaimRefusal::AccordRosterIsNotWaAuthority),
            "rc3 moved reclaim authority to the CC 4.3 WA quorum — the accord roster is not a \
             WA body, and a deployment must not be able to point it back"
        );
    }

    /// rc3's answer to question 3: the owner-binding itself establishes the
    /// initial floor, so a binding is never floorless — and a later
    /// touch-claim only ever moves the floor FORWARD.
    #[test]
    fn a_binding_is_never_floorless() {
        let t0: DateTime<Utc> = "2026-01-01T00:00:00Z".parse().unwrap();
        let mut binding = rts::bare_owner_binding("b", "owner", "node");
        binding.asserted_at = t0;
        assert_eq!(
            initial_freshness_floor(&binding, [None, None]),
            t0,
            "with no touch-claims at all the binding's own asserted_at IS the floor"
        );
        let later = t0 + Duration::days(30);
        assert_eq!(
            initial_freshness_floor(&binding, [Some(later), None]),
            later
        );
        let earlier = t0 - Duration::days(30);
        assert_eq!(
            initial_freshness_floor(&binding, [Some(earlier), None]),
            t0,
            "a stale touch-claim never drags the floor BACKWARDS below the binding"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn ownership_reclaim_ceremony_sqlite() {
        let engine = Engine::with_signer(test_signer(), "sqlite::memory:")
            .await
            .expect("construct sqlite engine");
        let dir = engine.federation_directory();
        Box::pin(rts::exercise_reclaim_ceremony(&*dir, "sq")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn ownership_reclaim_ceremony_postgres() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!(
                "skipping ownership_reclaim_ceremony_postgres: CIRIS_PERSIST_TEST_PG_URL unset"
            );
            return;
        };
        let engine = Engine::with_signer(test_signer(), &dsn)
            .await
            .expect("construct postgres engine");
        let dir = engine.federation_directory();
        let tag = format!("pg{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
        Box::pin(rts::exercise_reclaim_ceremony(&*dir, &tag)).await;
    }
}

// The #578 behavioural witness, run by the sqlite / postgres / memory
// suites against `&dyn FederationDirectory` so the three backends cannot
// silently diverge on the plane that decides **who can take a node**.
// `suffix` scopes every fixture key so a run against a shared postgres test
// DB does not collide with a prior one.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod test_support {
    //! v62.0.0 (the JSON cut; V1, P5b, cut B): the ceremony is edition 2.
    //!
    //! - Keys are live by their `key:record` (`e2::put_key`); every id the
    //!   store holds is a kid. The seeds sign; the kids are what reads name.
    //! - The WA body is founded by its voices (`e2::family_voices_naming_held`).
    //! - The petition, the finding and the gated `withdraws` are cut B's drafts
    //!   (`draft_reclaim_petition`, `draft_wa_finding`,
    //!   `draft_reclaim_withdraws`), each signed with its signer's composite.
    //! - A finding's co-signers are COUNTED VOICES: one statement per WA member
    //!   over the finding's payload (`e2::voice_of`), under its row id; the gate
    //!   counts them (`edition2::voices::counted_roster_signers`, V1).
    //! - An owner binding carries the node's voice (CC 3.2): put without it,
    //!   the row is held `Pending` (no typed row; the lead's PENDING model,
    //!   V1b) and the node's voice lands it. RED 8 is that held rebinding.
    //! - A touch claim is node-local (`put_touch_claim_local`, P5b).
    use super::*;
    use crate::federation::edition2::emit::Draft;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_tier, cohort_scope, identity_type, FamilyMember};
    use crate::federation::Family;

    /// An UNSIGNED owner-binding row (used by pure unit tests that never
    /// store it).
    pub(super) fn bare_owner_binding(id: &str, owner: &str, node: &str) -> Attestation {
        ts::owner_binding_attestation(id, owner, node)
    }

    /// Sign cut B's `draft` with `seed`'s composite: the edition-2 statement.
    fn signed(seed: &str, draft: Draft) -> Vec<u8> {
        let sig = e2::signing_key(seed)
            .sign(&draft.sig_structure)
            .expect("sign the draft");
        draft.assemble(sig)
    }

    /// `seed`'s `(kid, iss)` for a cut B draft.
    fn signer(seed: &str) -> (ciris_verify_core::edition2::Digest32, String) {
        (e2::kid_digest(seed), e2::kid(seed))
    }

    /// v62.0.0 (E2-fix3; CC 2.7.3) — **the real put door says NO**: it
    /// refuses `statement`, or HOLDS it on a fold condition (the ceremony
    /// reads the binding, the finding and the petition, other rows), with the
    /// fold's reason recorded (`fold::why_held`). Either way it never lands.
    async fn refused_or_held(dir: &dyn FederationDirectory, statement: &[u8]) -> bool {
        match e2::put_statement(dir, statement).await {
            Err(_) => true,
            Ok(StatementOutcome::Pending { row_id, .. }) => {
                crate::federation::edition2::fold::why_held(dir, &row_id)
                    .await
                    .expect("the fold's record reads")
                    .is_some()
            }
            Ok(_) => false,
        }
    }

    /// **I2631** (v62.0.0, E2-fix9; CC rc21 994b4f5 ruling (c): CC 3.2 "the
    /// recovery gate", CC 8.10 the `ownership:*` card's withdraw guard,
    /// `wa_adjudication_ref` a logical name for `refs.also.cites`) — **the
    /// gated `withdraws` names its WA finding as its ONE `refs.also.cites`
    /// row, beside `refs.target`**, and carries no other refs member. The draft passes the composer rule (no
    /// non-composer member: `wa_adjudication_ref` is never a payload member),
    /// and the mapping reads the finding back as the envelope member the
    /// reclaim gate reads. Kills: stating the reference as a payload member
    /// (the composer rule refuses the row); the target replacing the roles the
    /// envelope stated (the finding is lost, the gate reads it missing).
    #[test]
    fn i2631_the_reclaim_withdraws_names_its_finding_in_refs() {
        use crate::federation::edition2::names::{names_of, single};
        let (binding, finding) = ("11".repeat(32), "22".repeat(32));
        let family = ciris_verify_core::namespace_match::family_id(
            "ownership:{relation}:{target_kind}:{version}",
        );
        let (kid, iss) = signer("i2631-node");
        let draft = draft_reclaim_withdraws(
            (&kid, &iss),
            &e2::kid("i2631-node"),
            &binding,
            &family,
            &finding,
            e2::ms(chrono::Utc::now()),
        )
        .expect("I2631: the reclaim withdraws drafts");
        let payload =
            ciris_verify_core::cde::decode(&draft.payload).expect("I2631: the payload decodes");
        crate::federation::edition2::payloads::check_composer("withdraws", &payload)
            .expect("I2631: the composer rule admits the reclaim withdraws");
        assert!(
            payload.get_text(field::WA_ADJUDICATION_REF).is_none(),
            "I2631: the reference is no payload member"
        );
        let names = names_of(&payload).expect("I2631: refs read");
        assert_eq!(
            single(&names, "target").map(|r| r.hex()),
            Some(binding.clone()),
            "I2631: refs.target names the binding"
        );
        assert_eq!(
            single(&names, "also:cites").map(|r| r.hex()),
            Some(finding.clone()),
            "I2631: refs.also.cites names the finding, exactly one row"
        );
        assert!(
            names
                .iter()
                .all(|n| n.role == "target" || n.role == "also:cites"),
            "I2631: no refs member beyond target and also.cites: {names:?}"
        );
        let row = row_of(&signed("i2631-node", draft));
        assert_eq!(
            row.attestation_envelope
                .get(field::WA_ADJUDICATION_REF)
                .and_then(serde_json::Value::as_str),
            Some(finding.as_str()),
            "I2631: the gate's member reads back from refs"
        );
    }

    /// The row a statement maps to (its row id is `attestation_id`).
    fn row_of(statement: &[u8]) -> Attestation {
        e2::row_of_statement(statement, attestation_tier::FEDERATION)
    }

    /// Put `statement`, then one voice over its payload per `cosigners`.
    async fn put_with_voices(
        dir: &dyn FederationDirectory,
        statement: &[u8],
        cosigners: &[&str],
    ) -> Result<StatementOutcome, Error> {
        let mut out = e2::put_statement(dir, statement).await?;
        for c in cosigners {
            out = e2::put_statement(dir, &e2::voice_of(statement, c)).await?;
        }
        Ok(out)
    }

    /// Step 1: the petition, signed by `filer`.
    fn petition(
        filer: &str,
        node: &str,
        binding: &str,
        grounds: &str,
        at: DateTime<Utc>,
    ) -> Vec<u8> {
        let (kid, iss) = signer(filer);
        signed(
            filer,
            draft_reclaim_petition((&kid, &iss), &e2::kid(node), binding, grounds, e2::ms(at))
                .expect("petition draft"),
        )
    }

    /// Step 2: a WA finding's FIRST voice, signed by `wa`.
    fn finding(
        wa: &str,
        node: &str,
        kind: WaFinding,
        binding: &str,
        petition_ref: &str,
        grounds: &str,
        at: DateTime<Utc>,
    ) -> Vec<u8> {
        let (kid, iss) = signer(wa);
        signed(
            wa,
            draft_wa_finding(
                (&kid, &iss),
                &e2::kid(node),
                kind,
                binding,
                petition_ref,
                grounds,
                e2::ms(at),
            )
            .expect("finding draft"),
        )
    }

    /// Step 3: the gated `withdraws` of `binding` (family `family`), signed
    /// by `by`.
    fn withdraws(
        by: &str,
        node: &str,
        binding: &str,
        family: &str,
        wa_ref: &str,
        at: DateTime<Utc>,
    ) -> Vec<u8> {
        let (kid, iss) = signer(by);
        signed(
            by,
            draft_reclaim_withdraws(
                (&kid, &iss),
                &e2::kid(node),
                binding,
                family,
                wa_ref,
                e2::ms(at),
            )
            .expect("withdraws draft"),
        )
    }

    /// A `withdraws` over a HAND-MADE envelope (the malformed shapes no
    /// draft builds), in `family`, signed by `by`.
    fn withdraws_of_envelope(
        by: &str,
        node: &str,
        envelope: serde_json::Value,
        family: &str,
        at: DateTime<Utc>,
    ) -> Vec<u8> {
        let mut shape = ts::bare_attestation("", by, node, &envelope);
        shape.attestation_type = attestation_type::WITHDRAWS.to_owned();
        shape.asserted_at = at;
        e2::statement_of_family(&shape, by, family)
    }

    /// An owner binding of `node` by `owner`, put with the node's voice.
    /// `edit` adjusts the earlier-form shape before it is sealed.
    async fn bind(
        dir: &dyn FederationDirectory,
        owner: &str,
        node: &str,
        edit: impl FnOnce(&mut Attestation),
    ) -> Result<Attestation, Error> {
        let mut row = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), owner, node);
        edit(&mut row);
        ts::reseal(&mut row);
        let st = e2::carried_statement(&row).expect("a mapped row carries its statement");
        put_with_voices(dir, &st, &[node]).await?;
        Ok(dir
            .get_attestation(&row.attestation_id)
            .await?
            .expect("the binding is stored"))
    }

    /// A WA body `body`: a family of `seated`, founded by its voices, under
    /// `majority` (a strict majority of 3 ⇒ 2).
    async fn seat_body(
        dir: &dyn FederationDirectory,
        body: &str,
        seated: &[&str],
        now: DateTime<Utc>,
    ) {
        let _ = e2::put_key(dir, body, &[identity_type::USER]).await;
        let signed = ts::sign_family(
            body,
            Family {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                family_key_id: body.to_owned(),
                family_name: format!("wise authorities {body}"),
                members: seated
                    .iter()
                    .map(|k| FamilyMember {
                        key_id: (*k).to_owned(),
                        joined_at: now,
                        role: Some("member".to_owned()),
                    })
                    .collect(),
                founded_at: now,
                consensus_protocol: "majority".to_owned(),
                consensus_protocol_entrenched: false,
                dissolved_at: None,
                persist_row_hash: String::new(),
            },
        );
        let voices = e2::family_voices_naming_held(dir, &signed, e2::ms(now)).await;
        e2::put_voices(dir, &voices)
            .await
            .expect("seat the WA body");
    }

    /// **The whole ceremony, both directions.** Run against every backend.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn exercise_reclaim_ceremony(dir: &dyn FederationDirectory, suffix: &str) {
        let now = crate::federation::admission::truncate_to_substrate_resolution(Utc::now());
        let owner = format!("r-owner-{suffix}");
        let node = format!("r-node-{suffix}");
        let claimant = format!("r-claimant-{suffix}");
        let filer = format!("r-filer-{suffix}");
        let wa_body = format!("r-wa-body-{suffix}");
        let wa: [String; 3] = [
            format!("r-wa-a-{suffix}"),
            format!("r-wa-b-{suffix}"),
            format!("r-wa-c-{suffix}"),
        ];

        for k in [&owner, &claimant, &filer] {
            let _ = e2::put_key(dir, k, &[identity_type::USER]).await;
        }
        // The node's record covers the back-dated binding below (a node row is
        // judged at its own instant inside its record's window; CC 2.4.1.1).
        let back = now - Duration::days(200);
        let _ = e2::put_key_with(
            dir,
            &node,
            &[identity_type::NODE],
            &e2::KeyRecordOptions {
                asserted_at_ms: Some(e2::ms(back - Duration::days(10))),
                ..Default::default()
            },
        )
        .await;
        for k in &wa {
            let _ = e2::put_key(
                dir,
                k,
                &[identity_type::USER, identity_type::WISE_AUTHORITY],
            )
            .await;
        }

        // The CC 4.3 WA body: a family whose roster IS the quorum and whose
        // own consensus_protocol IS the threshold.
        seat_body(dir, &wa_body, &[&wa[0], &wa[1], &wa[2]], now).await;
        let policy = ReclaimPolicy::wise_authority(e2::kid(&wa_body));
        let node_k = e2::kid(&node);

        // ── The incumbent binding, admitted through the REAL gate, dated
        //    outside the abandonment window so the abandonment arm is
        //    reachable (rc3: the binding itself IS the initial floor).
        let stored_binding = bind(dir, &owner, &node, |b| {
            b.asserted_at = back;
            b.scrub_timestamp = back;
        })
        .await
        .expect("incumbent binding");
        let binding_id = stored_binding.attestation_id.clone();
        let binding_family = e2::family_of(&stored_binding);
        assert!(
            stored_binding.asserted_at < now - policy.abandonment_window,
            "({suffix}) rc3: the binding itself IS the initial freshness floor, and this fixture \
             needs it OUTSIDE the window for the abandonment arm to be reachable"
        );
        assert_eq!(
            crate::federation::admission::owner_of(dir, &node_k)
                .await
                .expect("owner_of"),
            Some(e2::kid(&owner)),
            "({suffix}) the node starts owned by its incumbent"
        );

        // ── Step 1: the petition.
        let petition_st = petition(
            &filer,
            &node,
            &binding_id,
            "owner unreachable for 13 months",
            now,
        );
        e2::put_statement(dir, &petition_st)
            .await
            .expect("petition");
        let petition_id = row_of(&petition_st).attestation_id;

        // ── Step 2: the CC 4.3 finding, voiced 2-of-3 by the WA body.
        let grounds = "sustained non-response plus out-of-band confirmation";
        let finding_st = finding(
            &wa[0],
            &node,
            WaFinding::Abandonment,
            &binding_id,
            &petition_id,
            grounds,
            now,
        );
        put_with_voices(dir, &finding_st, &[&wa[1]])
            .await
            .expect("finding");
        let finding_id = row_of(&finding_st).attestation_id;
        let check = |st: Vec<u8>, policy: Option<ReclaimPolicy>| async move {
            check_ownership_reclaim_admission(dir, &row_of(&st), policy.as_ref(), now)
                .await
                .expect("gate")
        };

        // ══ RED 1 — a withdraws with NO wa_adjudication_ref is refused,
        //    naming exactly that. This is CC 3.2's recovery gate: without
        //    it, K's own key liberates K from its owner.
        let mut bare_env = EnvelopeCore {
            references_attestation_id: Some(binding_id.clone()),
            ..Default::default()
        }
        .to_value();
        bare_env
            .as_object_mut()
            .expect("object")
            .remove(field::WA_ADJUDICATION_REF);
        let bare = withdraws_of_envelope(&node, &node, bare_env, &binding_family, now);
        assert_eq!(
            check(bare.clone(), Some(policy.clone())).await.refusal(),
            Some(ReclaimRefusal::WaAdjudicationRefMissing),
            "({suffix}) a gated withdraws with no wa_adjudication_ref must be refused BY NAME"
        );
        assert!(
            refused_or_held(dir, &bare).await,
            "({suffix}) and the real put gate must refuse it too — the gate is not advisory"
        );

        // ══ RED 1b (E2-fix9; CC rc21 994b4f5 ruling (c)) — `cites` holds
        //    EXACTLY ONE row, the finding: a withdraws whose `refs.also.cites`
        //    names the finding AND another row names no finding, so it
        //    concludes nothing (the gate reads no `wa_adjudication_ref`).
        let mut two_env = build_reclaim_withdraws_envelope(&binding_id, &finding_id);
        two_env.as_object_mut().expect("object").insert(
            field::WA_ADJUDICATION_REF.to_owned(),
            serde_json::json!([finding_id.clone(), petition_id.clone()]),
        );
        let two = withdraws_of_envelope(&node, &node, two_env, &binding_family, now);
        assert_eq!(
            check(two.clone(), Some(policy.clone())).await.refusal(),
            Some(ReclaimRefusal::WaAdjudicationRefMissing),
            "({suffix}) a cites of two rows names no single finding: it concludes nothing"
        );
        assert!(
            refused_or_held(dir, &two).await,
            "({suffix}) …and the real put gate does not land it"
        );

        // ══ RED 2 — a wa_adjudication_ref that resolves to nothing.
        let unheld = {
            use sha2::Digest as _;
            hex::encode(sha2::Sha256::digest(uuid::Uuid::new_v4().as_bytes()))
        };
        assert_eq!(
            check(
                withdraws(&node, &node, &binding_id, &binding_family, &unheld, now),
                Some(policy.clone())
            )
            .await
            .refusal(),
            Some(ReclaimRefusal::WaAdjudicationRefUnresolvable),
            "({suffix}) a ref naming no held row is refused"
        );
        // I3760 (wave GC3; CC 2.7.3) — under a fold attempt (the edition-2
        // door's tail) the same verdict HOLDS the withdraws: reason
        // `wa_adjudication_ref_unresolvable`, reading the binding it names,
        // so the finding's arrival re-folds it. Not concluded, not refused.
        // X2 pass 2: E2 replaced the `dangling` row this GC3 witness read.
        let dangling = row_of(&withdraws(
            &node,
            &node,
            &binding_id,
            &binding_family,
            &unheld,
            now,
        ));
        let (verdict, att) = crate::federation::edition2::fold::attempt(
            crate::federation::edition2::names::RowId([0x76; 32]),
            None,
            check_ownership_reclaim_admission(dir, &dangling, Some(&policy), now),
        )
        .await;
        assert!(
            verdict.expect("gate").refusal().is_some(),
            "({suffix}) I3760: the verdict itself is unchanged"
        );
        assert_eq!(
            att.held.as_ref().map(|(r, _)| r.as_str()),
            Some(crate::federation::edition2::fold::reason::WA_ADJUDICATION_REF_UNRESOLVABLE),
            "({suffix}) I3760: an unresolvable finding holds the withdraws, by its reason"
        );
        assert!(
            att.reads.contains(
                &crate::federation::edition2::fold::Dep::row_hex(&binding_id)
                    .unwrap_or_else(|| crate::federation::edition2::fold::Dep::key(&binding_id))
                    .read_key()
            ),
            "({suffix}) I3760: the fold read the target binding: {:?}",
            att.reads
        );
        // …and one that resolves to a REAL row that is not a finding.
        assert_eq!(
            check(
                withdraws(
                    &node,
                    &node,
                    &binding_id,
                    &binding_family,
                    &petition_id,
                    now
                ),
                Some(policy.clone())
            )
            .await
            .refusal(),
            Some(ReclaimRefusal::NotAWaFinding),
            "({suffix}) the petition is not the finding — a ref must resolve to a QUORUM finding"
        );

        // ══ RED 3 — an under-voiced finding (1 of the required 2). A
        //    different grounds text, so it is its own row.
        let short_st = finding(
            &wa[0],
            &node,
            WaFinding::Abandonment,
            &binding_id,
            &petition_id,
            "one member's word",
            now,
        );
        e2::put_statement(dir, &short_st)
            .await
            .expect("short finding");
        let short_id = row_of(&short_st).attestation_id;
        match check(
            withdraws(&node, &node, &binding_id, &binding_family, &short_id, now),
            Some(policy.clone()),
        )
        .await
        {
            ReclaimVerdict::Refused {
                reason: ReclaimRefusal::WaQuorumShort,
                quorum: Some(q),
                ..
            } => {
                assert_eq!(
                    (q.counted, q.required, q.roster_size),
                    (1, 2, 3),
                    "({suffix}) the refusal must say how far short: {q:?}"
                );
            }
            other => panic!("({suffix}) a 1-of-3 finding must be WaQuorumShort, got {other:?}"),
        }

        // ══ RED 3b — THE SYBIL. Two keys that SELF-ASSERT the
        //    `wise_authority` card but hold no seat in the WA body voice a
        //    finding. The seat is what confers; the card is only legibility.
        let sybil: [String; 2] = [format!("r-sybil-a-{suffix}"), format!("r-sybil-b-{suffix}")];
        for k in &sybil {
            let _ = e2::put_key(
                dir,
                k,
                &[identity_type::USER, identity_type::WISE_AUTHORITY],
            )
            .await;
        }
        let sybil_st = finding(
            &sybil[0],
            &node,
            WaFinding::Abandonment,
            &binding_id,
            &petition_id,
            grounds,
            now,
        );
        put_with_voices(dir, &sybil_st, &[&sybil[1]])
            .await
            .expect("sybil finding");
        match check(
            withdraws(
                &node,
                &node,
                &binding_id,
                &binding_family,
                &row_of(&sybil_st).attestation_id,
                now,
            ),
            Some(policy.clone()),
        )
        .await
        {
            ReclaimVerdict::Refused {
                reason: ReclaimRefusal::WaQuorumShort,
                quorum: Some(q),
                ..
            } => assert_eq!(
                q.counted, 0,
                "({suffix}) a self-asserted `wise_authority` card with no seat must count for \
                 NOTHING: {q:?}"
            ),
            other => panic!(
                "({suffix}) two self-declared WAs outside the body must not reach quorum, got \
                 {other:?}"
            ),
        }

        // ══ RED 3c — THE CARD. CC 4.3: "The Wise wear the same card": a
        //    SEATED member whose identity set does not carry `wise_authority`
        //    is not legible as a WA and its voice does not COUNT, while still
        //    sitting in the denominator. A second body.
        let uncarded = format!("r-uncarded-{suffix}");
        let _ = e2::put_key(dir, &uncarded, &[identity_type::USER]).await;
        let body2 = format!("r-wa-body2-{suffix}");
        seat_body(dir, &body2, &[&wa[0], &wa[1], &uncarded], now).await;
        let half_st = finding(
            &wa[0],
            &node,
            WaFinding::Abandonment,
            &binding_id,
            &petition_id,
            "half-legible grounds",
            now,
        );
        put_with_voices(dir, &half_st, &[&uncarded])
            .await
            .expect("half-legible finding");
        match check(
            withdraws(
                &node,
                &node,
                &binding_id,
                &binding_family,
                &row_of(&half_st).attestation_id,
                now,
            ),
            Some(ReclaimPolicy::wise_authority(e2::kid(&body2))),
        )
        .await
        {
            ReclaimVerdict::Refused {
                reason: ReclaimRefusal::WaQuorumShort,
                quorum: Some(q),
                ..
            } => assert_eq!(
                (q.counted, q.required, q.roster_size),
                (1, 2, 3),
                "({suffix}) TWO seated members voiced, but only the card-carrying one COUNTS — \
                 and the uncarded seat still sits in the denominator: {q:?}"
            ),
            other => panic!(
                "({suffix}) a seated-but-illegible voice must not carry the quorum, got {other:?}"
            ),
        }

        // ══ RED 4 — the accord roster is not a WA body.
        let good = withdraws(&node, &node, &binding_id, &binding_family, &finding_id, now);
        let accord_policy = ReclaimPolicy::wise_authority(
            ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID,
        );
        assert_eq!(
            check(good.clone(), Some(accord_policy)).await.refusal(),
            Some(ReclaimRefusal::AccordRosterIsNotWaAuthority),
            "({suffix}) v21.8.0's accord-rostered authority is now non-conformant"
        );
        // …and with NO published policy at all, nothing is seizable.
        assert_eq!(
            check(good.clone(), None).await.refusal(),
            Some(ReclaimRefusal::NoDeploymentPolicy),
            "({suffix}) an unpublished WA body means no reclaim is admissible here"
        );

        // ══ RED 5 — THE SINGLE-ACT TRANSFER. Refused before authority is
        //    even considered, and unrepresentable in the admitted verdict.
        let mut collapsed_env = build_reclaim_withdraws_envelope(&binding_id, &finding_id);
        collapsed_env.as_object_mut().expect("object").insert(
            "successor_owner_key_id".to_owned(),
            serde_json::Value::String(e2::kid(&claimant)),
        );
        let collapsed = withdraws_of_envelope(&node, &node, collapsed_env, &binding_family, now);
        assert_eq!(
            check(collapsed.clone(), Some(policy.clone()))
                .await
                .refusal(),
            Some(ReclaimRefusal::SingleActTransferAttempted),
            "({suffix}) a withdraws that names who gets the node next collapses steps 3 and 4"
        );
        assert!(
            refused_or_held(dir, &collapsed).await,
            "({suffix}) …and the real put gate refuses it, so it never lands"
        );

        // ══ RED 6 — an issuer with no CC rule-(2)/(4) standing.
        assert_eq!(
            check(
                withdraws(
                    &filer,
                    &node,
                    &binding_id,
                    &binding_family,
                    &finding_id,
                    now
                ),
                Some(policy.clone())
            )
            .await
            .refusal(),
            Some(ReclaimRefusal::IssuerLacksRecoveryStanding),
            "({suffix}) a quorum finding is not a warrant for an arbitrary third party"
        );

        // ══ I2842 (was RED 7) — a fresh binding while the incumbent is still
        //    live. v62.0.0 (K2): the single-owner refusal is gone; the
        //    claimant's binding (K's voice absent) is HELD and names no owner,
        //    so the claimant still cannot skip step 3: the incumbent stays.
        {
            let mut premature =
                ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &claimant, &node);
            ts::reseal(&mut premature);
            let st = e2::carried_statement(&premature).expect("an edition-2 owner binding");
            let _ = e2::put_statement(dir, &st).await;
        }
        assert_eq!(
            crate::federation::admission::owner_of(dir, &node_k)
                .await
                .expect("owner_of"),
            Some(e2::kid(&owner)),
            "({suffix}) I2842: a binding K never voiced names no owner; the incumbent stays"
        );

        // ══ GREEN — step 3: the full ceremony admits, THROUGH THE REAL GATE.
        assert!(
            check(good.clone(), Some(policy.clone())).await.is_admit(),
            "({suffix}) petition + 2-of-3 finding + rule-(2) issuer + lapsed floor ⇒ admit"
        );
        std::env::set_var(ReclaimPolicy::WA_FAMILY_ENV, e2::kid(&wa_body));
        e2::put_statement(dir, &good)
            .await
            .expect("the gated withdraws lands");
        std::env::remove_var(ReclaimPolicy::WA_FAMILY_ENV);
        let stored_withdraws = dir
            .get_attestation(&row_of(&good).attestation_id)
            .await
            .expect("read")
            .expect("stored");
        assert_eq!(
            stored_withdraws.withdraws_admission_rule,
            Some(RECLAIM_WITHDRAWS_ADMISSION_RULE),
            "({suffix}) the row records WHICH rule admitted it"
        );

        // ══ THE UNOWNED STATE — between steps 3 and 4, K has NO owner.
        assert_eq!(
            crate::federation::admission::owner_of(dir, &node_k)
                .await
                .expect("owner_of"),
            None,
            "({suffix}) after the gated withdraws K is UNOWNED — empty self cohort, fail-secure"
        );

        // ══ RED 8 — step 4 without K's voice does not seat the claimant.
        //    v62.0.0 (the lead's PENDING model, V1b): an owner binding put
        //    without the node's voice is HELD `Pending`: no typed row is
        //    written; the node's voice lands it.
        let rebind =
            ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &claimant, &node);
        let rebind_st = e2::carried_statement(&rebind).expect("a mapped row carries its statement");
        match e2::put_statement(dir, &rebind_st).await {
            Ok(StatementOutcome::Pending { .. }) => {}
            other => panic!(
                "({suffix}) a post-reclaim rebinding without K's voice must be held Pending, got \
                 {other:?}"
            ),
        }
        assert!(
            dir.get_attestation(&rebind.attestation_id)
                .await
                .expect("read")
                .is_none(),
            "({suffix}) a held rebinding writes no typed row"
        );
        assert_eq!(
            crate::federation::admission::owner_of(dir, &node_k)
                .await
                .expect("owner_of"),
            None,
            "({suffix}) a post-reclaim rebinding without K's voice must not seat the claimant"
        );

        // ══ GREEN — step 4: K voices the same row, which lands it.
        match e2::put_statement(dir, &e2::voice_of(&rebind_st, &node)).await {
            Ok(StatementOutcome::Row { .. }) => {}
            other => panic!("({suffix}) K's voice must land the rebinding, got {other:?}"),
        }
        assert_eq!(
            crate::federation::admission::owner_of(dir, &node_k)
                .await
                .expect("owner_of"),
            Some(e2::kid(&claimant)),
            "({suffix}) and only now, after four distinct acts, is K owned again"
        );

        // ══ THE SEIZURE ARM — a LIVE binding, reached by a seizure finding.
        //    A fresh touch proves the incumbent is alive; abandonment would
        //    refuse, seizure must not (rc3: a front-run is reversible).
        let node2 = format!("r-node2-{suffix}");
        let owner2 = format!("r-owner2-{suffix}");
        let _ = e2::put_key(dir, &node2, &[identity_type::NODE]).await;
        let _ = e2::put_key(dir, &owner2, &[identity_type::USER]).await;
        let b2 = bind(dir, &owner2, &node2, |_| {})
            .await
            .expect("live binding");
        let b2_family = e2::family_of(&b2);
        // A touch claim is node-local (P5b): this node records the incumbent
        // alive five minutes ago.
        dir.put_touch_claim_local(
            &e2::kid(&owner2),
            OWNERSHIP_FRESHNESS_TARGET_KIND,
            now - Duration::minutes(5),
            cohort_scope::SELF,
        )
        .await
        .expect("fresh node-local touch");
        let p2_st = petition(
            &filer,
            &node2,
            &b2.attestation_id,
            "front-run at provisioning",
            now,
        );
        e2::put_statement(dir, &p2_st).await.expect("petition 2");
        let p2_id = row_of(&p2_st).attestation_id;
        let mk_finding = |kind: WaFinding| {
            finding(
                &wa[0],
                &node2,
                kind,
                &b2.attestation_id,
                &p2_id,
                "fraudulent binding",
                now,
            )
        };
        let aband2 = mk_finding(WaFinding::Abandonment);
        put_with_voices(dir, &aband2, &[&wa[2]])
            .await
            .expect("abandonment finding 2");
        let seiz2 = mk_finding(WaFinding::Seizure);
        put_with_voices(dir, &seiz2, &[&wa[2]])
            .await
            .expect("seizure finding 2");
        let seiz2_id = row_of(&seiz2).attestation_id;

        // ══ RED 9 — A FINDING IS NOT A BEARER TOKEN. The genuine, fully
        //    quorum-voiced finding minted against node2's binding is replayed
        //    against the FIRST node's binding: refused, because it adjudicates
        //    a different binding.
        assert_eq!(
            check(
                withdraws(&node, &node, &binding_id, &binding_family, &seiz2_id, now),
                Some(policy.clone())
            )
            .await
            .refusal(),
            Some(ReclaimRefusal::FindingNotAgainstThisBinding),
            "({suffix}) a valid finding for ONE binding must not authorize a withdraws against \
             another — a quorum finding is scoped, never a warrant for the mesh"
        );
        assert_eq!(
            check(
                withdraws(
                    &node2,
                    &node2,
                    &b2.attestation_id,
                    &b2_family,
                    &row_of(&aband2).attestation_id,
                    now
                ),
                Some(policy.clone())
            )
            .await
            .refusal(),
            Some(ReclaimRefusal::NotAbandoned),
            "({suffix}) a LIVE owner is quiet-proof: abandonment refuses even with a real quorum"
        );
        match check(
            withdraws(
                &node2,
                &node2,
                &b2.attestation_id,
                &b2_family,
                &seiz2_id,
                now,
            ),
            Some(policy.clone()),
        )
        .await
        {
            ReclaimVerdict::Admit {
                finding: WaFinding::Seizure,
                ..
            } => {}
            other => panic!(
                "({suffix}) rc3: the SAME recovery path reaches a live wrongful binding on a \
                 seizure finding — a front-run must be reversible, got {other:?}"
            ),
        }

        // ══ RED 10 — THE SELF-LIBERATION EXPLOIT, on the rc3-CONFORMANT
        //    producer shape: the owner-binding names K in its
        //    `subject_key_ids`, so CEG rule 2 (subject self-revocation) would
        //    ADMIT a `withdraws` from K against its own owner with no
        //    adjudication at all. The recovery gate must close it.
        let node3 = format!("r-node3-{suffix}");
        let owner3 = format!("r-owner3-{suffix}");
        let _ = e2::put_key(dir, &node3, &[identity_type::NODE]).await;
        let _ = e2::put_key(dir, &owner3, &[identity_type::USER]).await;
        let b3 = bind(dir, &owner3, &node3, |b| {
            b.subject_key_ids = vec![node3.clone()];
        })
        .await
        .expect("conformant binding names K as subject");
        assert_eq!(
            crate::federation::admission::resolve_withdraws_admission_rule(
                dir,
                &e2::kid(&node3),
                &b3
            )
            .await
            .expect("rule"),
            2,
            "({suffix}) the ordinary 4-rule gate really does hand K rule-2 authority over its \
             own owner-binding — this is the exploit the recovery gate exists to close"
        );
        let liberation = withdraws(
            &node3,
            &node3,
            &b3.attestation_id,
            &e2::family_of(&b3),
            "",
            now,
        );
        match e2::put_statement(dir, &liberation).await {
            // No WA body is published in this process, so the refusal lands at
            // ceremony step 0 — the SHIPPED posture and the strongest form of
            // this witness.
            Err(Error::OwnershipReclaimRefused {
                reason: ReclaimRefusal::NoDeploymentPolicy,
                ..
            }) => {}
            other => panic!(
                "({suffix}) a rule-2 withdraws against a LIVE owner-binding MUST be refused \
                 without a resolving wa_adjudication_ref — a compromised node key must not be \
                 able to shed its own owner, got {other:?}"
            ),
        }
        assert_eq!(
            crate::federation::admission::owner_of(dir, &e2::kid(&node3))
                .await
                .expect("owner_of"),
            Some(e2::kid(&owner3)),
            "({suffix}) …and the node is still owned — the refusal wrote nothing"
        );
    }
}

/// v62.0.0 (wave V1) — **I3284: the WA quorum counts the finding's VOICES**,
/// on sqlite and postgres. A 2-of-3 WA body (every member wearing the
/// `wise_authority` card): the finding with its author's voice alone is short;
/// a second member's own statement over the finding's payload meets it; a
/// carded key outside the roster is never counted.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod wa_quorum_voices_v1 {
    use super::{wa_quorum_over_body, ReclaimPolicy, WaQuorum};
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::voices_invariants::{add_voice, counted_row, found_family};
    use crate::federation::types::identity_type;
    use crate::federation::FederationDirectory;

    async fn quorum(
        d: &dyn FederationDirectory,
        policy: &ReclaimPolicy,
        finding: &crate::federation::Attestation,
    ) -> WaQuorum {
        match wa_quorum_over_body(d, policy, finding).await.unwrap() {
            Ok(q) => q,
            Err((_, detail)) => panic!("I3284 the WA body resolves: {detail}"),
        }
    }

    pub(crate) async fn body(d: &dyn FederationDirectory) {
        let (w1, w2, w3, x) = ("v1-wa-1", "v1-wa-2", "v1-wa-3", "v1-wa-x");
        for s in [w1, w2, w3, x] {
            let _ = e2::put_key(d, s, &[identity_type::USER, identity_type::WISE_AUTHORITY]).await;
        }
        let body = found_family(d, "v1-wa-body", &[w1, w2, w3], "majority").await;
        let policy = ReclaimPolicy {
            abandonment_window: ReclaimPolicy::DEFAULT_ABANDONMENT_WINDOW,
            wa_family_key_id: body.family_key_id.clone(),
        };
        let finding = counted_row(d, w1).await;
        let q = quorum(d, &policy, &finding).await;
        assert_eq!((q.counted, q.roster_size), (1, 3), "I3284 one voice: {q:?}");
        assert!(q.counted < q.required, "I3284 one of three is short: {q:?}");

        let _ = add_voice(d, &finding, x).await;
        assert_eq!(
            quorum(d, &policy, &finding).await.counted,
            1,
            "I3284 a carded key outside the roster is not counted"
        );

        add_voice(d, &finding, w2)
            .await
            .expect("I3284 the second WA member's voice");
        let q = quorum(d, &policy, &finding).await;
        assert_eq!(q.counted, 2, "I3284 two voices: {q:?}");
        assert!(q.counted >= q.required, "I3284 2-of-3 met by voices: {q:?}");
    }

    /// I3288: the WA card filter applies AFTER voice counting. A 3-seat body
    /// where one seated member does NOT wear the `wise_authority` card: the
    /// author's voice plus that uncarded member's voice is still 1 counted,
    /// short of 2 (the denominator stays the full roster of 3); a second
    /// CARDED member's voice meets it.
    pub(crate) async fn card_filter_body(d: &dyn FederationDirectory) {
        let (w1, w2, u) = ("v1-wc-1", "v1-wc-2", "v1-wc-u");
        for s in [w1, w2] {
            let _ = e2::put_key(d, s, &[identity_type::USER, identity_type::WISE_AUTHORITY]).await;
        }
        let _ = e2::put_key(d, u, &[identity_type::USER]).await;
        let body = found_family(d, "v1-wc-body", &[w1, w2, u], "majority").await;
        let policy = ReclaimPolicy {
            abandonment_window: ReclaimPolicy::DEFAULT_ABANDONMENT_WINDOW,
            wa_family_key_id: body.family_key_id.clone(),
        };
        let finding = counted_row(d, w1).await;
        add_voice(d, &finding, u)
            .await
            .expect("I3288 the uncarded member's voice is held");
        let q = quorum(d, &policy, &finding).await;
        assert_eq!(
            (q.counted, q.roster_size),
            (1, 3),
            "I3288 a seated member without the card is not counted: {q:?}"
        );
        assert!(q.counted < q.required, "I3288 still short: {q:?}");
        add_voice(d, &finding, w2)
            .await
            .expect("I3288 the second carded member's voice");
        let q = quorum(d, &policy, &finding).await;
        assert_eq!(q.counted, 2, "I3288 two carded voices: {q:?}");
        assert!(q.counted >= q.required, "I3288 met: {q:?}");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i3288_wa_card_filter_after_voices_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(card_filter_body(&b)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3288_wa_card_filter_after_voices_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(card_filter_body(&b)).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i3284_wa_quorum_by_voices_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(body(&b)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3284_wa_quorum_by_voices_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(body(&b)).await;
    }
}
