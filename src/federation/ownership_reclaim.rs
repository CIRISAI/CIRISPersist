//! (CIRISPersist#578, CIRISConstitution rc3 CC 3.2) — the `ownership:*`
//! ownerless-lock **reclaim CEREMONY**: petition → WA quorum finding →
//! gated `withdraws` (K becomes **unowned**) → fresh owner-binding
//! co-signed by K.
//!
//! # The gap this closes
//!
//! Ownership is a `delegates_to(U → node)` on the owner-binding dimension
//! ([`super::types::owner_binding::DIMENSION`]).
//! [`super::admission::check_single_node_owner_admission`] enforces
//! at-most-one live owner (CC 3.2): a node already owned rejects a
//! DIFFERENT granter's binding — the incumbent must `withdraws`/`recants`
//! it, or it must lapse. So if the owner dies, loses custody, or *front-ran
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
//! - **Refused by the ownership gate.** Step 4 still runs through
//!   [`super::admission::check_single_node_owner_admission`], which rejects a
//!   different granter's binding while ANY live binding remains. The reclaim
//!   `withdraws` must therefore have already landed and taken the incumbent
//!   non-live — i.e. K really does pass through the unowned state — before a
//!   claimant can bind.
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
    // A backend that cannot answer the family question (the FFI directory
    // capsule reports `Unsupported` for `lookup_family`) is honestly unable to
    // re-derive the authority, which is `WaBodyUnknown` — never a hard error
    // that a caller might retry into, and never a guess. Same discipline
    // `check_attested_subject_admission` applies to the same call.
    let family = match directory.lookup_family(&policy.wa_family_key_id).await {
        Ok(Some(f)) => f,
        Ok(None) | Err(Error::Unsupported { .. }) => {
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
        Err(Error::Unsupported { .. }) => Vec::new(),
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
        if let Some(rec) = directory.lookup_public_key(key_id).await? {
            if identity_type::set_contains(&rec.identity_type, identity_type::WISE_AUTHORITY) {
                carded.push(rec.key_id);
            }
        }
    }
    let counted = super::reverse_quorum::count_distinct_roster_scrubs(
        directory,
        &finding.attestation_envelope,
        &finding.scrubs(),
        &carded,
    )
    .await;
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
    for r in directory.list_attestations_by(node).await? {
        if r.attestation_type != attestation_type::DELEGATES_TO || r.attested_key_id != issuer {
            continue;
        }
        if let Some(exp) = r.expires_at {
            if exp <= now {
                continue;
            }
        }
        let scopes = super::admission::delegation_scope_set(&r.attestation_envelope);
        if scopes.contains(DELEGATION_SCOPE_OWNER_BINDING_RECOVERY) {
            return Ok(true);
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
pub async fn check_ownership_reclaim_admission(
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
        let incumbent_floor = directory
            .lookup_freshness_floor(incumbent, OWNERSHIP_FRESHNESS_TARGET_KIND)
            .await?
            .map(|f| f.fresh_as_of);
        let node_floor = directory
            .lookup_freshness_floor(node, OWNERSHIP_FRESHNESS_TARGET_KIND)
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
/// Wired into [`super::admission::check_single_node_owner_admission`], so
/// all three backends inherit it from one chokepoint.
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
    let reclaimed = directory
        .list_attestations_for(node)
        .await?
        .iter()
        .any(|r| {
            r.attestation_type == attestation_type::WITHDRAWS
                && r.withdraws_admission_rule == Some(RECLAIM_WITHDRAWS_ADMISSION_RULE)
        });
    if !reclaimed {
        return Ok(());
    }
    let node_roster = [node.to_owned()];
    let cosigned = super::reverse_quorum::count_distinct_roster_scrubs(
        directory,
        &row.attestation_envelope,
        &row.scrubs(),
        &node_roster,
    )
    .await;
    if cosigned.is_empty() {
        return Err(Error::OwnershipReclaimRefused {
            node_key_id: node.to_owned(),
            owner_binding_id: row.attestation_id.clone(),
            reason: ReclaimRefusal::FreshBindingNotCosignedByNode,
            detail: format!(
                "node {node} has been through a CC 3.2 reclaim, so its fresh owner-binding MUST \
                 be co-signed by {node} itself (ceremony step 4); the row carries no verifying \
                 co-signature from it"
            ),
        });
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
        rts::exercise_reclaim_ceremony(&*dir, "sq").await;
    }

    #[tokio::test]
    async fn ownership_reclaim_ceremony_memory() {
        let dir = crate::store::memory::MemoryBackend::new();
        rts::exercise_reclaim_ceremony(&dir, "mem").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn ownership_reclaim_ceremony_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
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
        rts::exercise_reclaim_ceremony(&*dir, &tag).await;
    }
}

/// The #578 behavioural witness, run by the sqlite / postgres / memory
/// suites against `&dyn FederationDirectory` so the three backends cannot
/// silently diverge on the plane that decides **who can take a node**.
/// `suffix` scopes every fixture key so a run against a shared postgres test
/// DB does not collide with a prior one.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod test_support {
    use super::*;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{
        attestation_tier, cohort_scope, identity_type, FamilyMember, SignerForm,
    };
    use crate::federation::{Family, SignedAttestation, SignedTouchClaim};

    /// An UNSIGNED owner-binding row (used by pure unit tests that never
    /// store it).
    pub(super) fn bare_owner_binding(id: &str, owner: &str, node: &str) -> Attestation {
        ts::owner_binding_attestation(id, owner, node)
    }

    /// Register `key_id` carrying its REAL deterministic hybrid pubkeys and
    /// the given `identity_type` set (comma-joined per CC 3.4.7.1).
    async fn register(dir: &dyn FederationDirectory, key_id: &str, types: &[&str]) {
        let (ed_pk, mldsa_pk) = ts::hybrid_pubkeys(key_id);
        let now = Utc::now();
        dir.put_public_key(crate::federation::SignedKeyRecord {
            record: crate::federation::KeyRecord {
                key_id: key_id.to_owned(),
                pubkey_ed25519_base64: ed_pk,
                pubkey_ml_dsa_65_base64: mldsa_pk,
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: identity_type::join_set(types.iter().copied()),
                identity_ref: key_id.to_owned(),
                valid_from: now,
                valid_until: None,
                registration_envelope: serde_json::json!({ "id": key_id }),
                original_content_hash: "deadbeef".to_owned(),
                scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
                scrub_signature_pqc: None,
                scrub_key_id: key_id.to_owned(),
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
        .expect("register key");
    }

    /// Build a federation-tier attestation of `kind` signed by `signer`, with
    /// `cosigners` added as `additional_scrubs` over the SAME envelope.
    fn signed_row(
        signer: &str,
        attested: &str,
        kind: &str,
        envelope: serde_json::Value,
        cosigners: &[&str],
        asserted_at: DateTime<Utc>,
    ) -> Attestation {
        let (och, classical, pqc) = ts::sign_envelope(signer, &envelope);
        let additional_scrubs = cosigners
            .iter()
            .map(|c| {
                let (_h, cl, pq) = ts::sign_envelope(c, &envelope);
                crate::federation::types::ScrubSig {
                    scrub_key_id: (*c).to_owned(),
                    scrub_signature_classical: cl,
                    scrub_signature_pqc: pq,
                }
            })
            .collect();
        Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: signer.to_owned(),
            attested_key_id: attested.to_owned(),
            attestation_type: kind.to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: signer.to_owned(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: cohort_scope::FEDERATION.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs,
        }
    }

    async fn store(dir: &dyn FederationDirectory, row: &Attestation) -> Result<(), Error> {
        dir.put_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
    }

    /// A hybrid-signed `self_touch` freshness claim.
    fn self_touch(target_key_id: &str, fresh_as_of: DateTime<Utc>) -> SignedTouchClaim {
        let unsigned = SignedTouchClaim {
            target_key_id: target_key_id.to_owned(),
            target_kind: OWNERSHIP_FRESHNESS_TARGET_KIND.to_owned(),
            fresh_as_of,
            signer_form: SignerForm::SelfTouch,
            attesting_key_id: target_key_id.to_owned(),
            signed_envelope: serde_json::Value::Null,
            signature: ciris_verify_core::transport_binding::TransportBindingSignature {
                ed25519_signature_base64: String::new(),
                mldsa65_signature_base64: None,
            },
            cohort_scope: cohort_scope::SELF.to_owned(),
        };
        let env = unsigned.signing_envelope();
        let (_hash, classical, pqc) = ts::sign_envelope(target_key_id, &env);
        SignedTouchClaim {
            signed_envelope: env,
            signature: ciris_verify_core::transport_binding::TransportBindingSignature {
                ed25519_signature_base64: classical,
                mldsa65_signature_base64: pqc,
            },
            ..unsigned
        }
    }

    /// **The whole ceremony, both directions.** Run against every backend.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn exercise_reclaim_ceremony(dir: &dyn FederationDirectory, suffix: &str) {
        let now = Utc::now();
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

        register(dir, &owner, &[identity_type::USER]).await;
        register(dir, &claimant, &[identity_type::USER]).await;
        register(dir, &node, &[identity_type::NODE]).await;
        register(dir, &filer, &[identity_type::USER]).await;
        for k in &wa {
            register(
                dir,
                k,
                &[identity_type::USER, identity_type::WISE_AUTHORITY],
            )
            .await;
        }

        // The CC 4.3 WA body: a family whose roster IS the quorum and whose
        // own consensus_protocol IS the threshold. `majority` floors at a
        // strict majority of 3 ⇒ 2.
        dir.put_family_local(Family {
            family_key_id: wa_body.clone(),
            family_name: format!("wise authorities {suffix}"),
            members: wa
                .iter()
                .map(|k| FamilyMember {
                    key_id: k.clone(),
                    joined_at: now,
                    role: Some("member".to_owned()),
                })
                .collect(),
            founded_at: now,
            consensus_protocol: "majority".to_owned(),
            consensus_protocol_entrenched: false,
            persist_row_hash: String::new(),
        })
        .await
        .expect("seat the WA body");

        let policy = ReclaimPolicy::wise_authority(&wa_body);

        // ── The incumbent binding, admitted through the REAL gate, dated
        //    outside the abandonment window so the abandonment arm is
        //    reachable (rc3: the binding itself IS the initial floor).
        let binding_id = uuid::Uuid::new_v4().to_string();
        let mut binding = ts::owner_binding_attestation(&binding_id, &owner, &node);
        binding.asserted_at = now - Duration::days(400);
        binding.scrub_timestamp = binding.asserted_at;
        store(dir, &binding).await.expect("incumbent binding");
        let stored_binding = dir
            .get_attestation(&binding_id)
            .await
            .expect("read")
            .expect("binding stored");
        assert!(
            stored_binding.asserted_at < now - policy.abandonment_window,
            "({suffix}) rc3: the binding itself IS the initial freshness floor, and this fixture \
             needs it OUTSIDE the window for the abandonment arm to be reachable"
        );
        assert_eq!(
            crate::federation::admission::owner_of(dir, &node)
                .await
                .expect("owner_of"),
            Some(owner.clone()),
            "({suffix}) the node starts owned by its incumbent"
        );

        // ── Step 1: the petition.
        let petition = signed_row(
            &filer,
            &node,
            attestation_type::SCORES,
            build_reclaim_petition_envelope(&binding_id, "owner unreachable for 13 months"),
            &[],
            now,
        );
        store(dir, &petition).await.expect("petition");

        // ── Step 2: the CC 4.3 finding, co-signed 2-of-3 by the WA body.
        let finding_env = build_wa_finding_envelope(
            WaFinding::Abandonment,
            &binding_id,
            &petition.attestation_id,
            "sustained non-response plus out-of-band confirmation",
        );
        let finding = signed_row(
            &wa[0],
            &node,
            attestation_type::SCORES,
            finding_env.clone(),
            &[&wa[1]],
            now,
        );
        store(dir, &finding).await.expect("finding");

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
        let bare = signed_row(
            &node,
            &node,
            attestation_type::WITHDRAWS,
            bare_env,
            &[],
            now,
        );
        assert_eq!(
            check_ownership_reclaim_admission(dir, &bare, Some(&policy), now)
                .await
                .expect("gate")
                .refusal(),
            Some(ReclaimRefusal::WaAdjudicationRefMissing),
            "({suffix}) a gated withdraws with no wa_adjudication_ref must be refused BY NAME"
        );
        assert!(
            store(dir, &bare).await.is_err(),
            "({suffix}) and the real put gate must refuse it too — the gate is not advisory"
        );

        // ══ RED 2 — a wa_adjudication_ref that resolves to nothing.
        let dangling = signed_row(
            &node,
            &node,
            attestation_type::WITHDRAWS,
            build_reclaim_withdraws_envelope(&binding_id, &uuid::Uuid::new_v4().to_string()),
            &[],
            now,
        );
        assert_eq!(
            check_ownership_reclaim_admission(dir, &dangling, Some(&policy), now)
                .await
                .expect("gate")
                .refusal(),
            Some(ReclaimRefusal::WaAdjudicationRefUnresolvable),
            "({suffix}) a ref naming no held attestation is refused"
        );
        // …and one that resolves to a REAL row that is not a finding.
        let not_a_finding = signed_row(
            &node,
            &node,
            attestation_type::WITHDRAWS,
            build_reclaim_withdraws_envelope(&binding_id, &petition.attestation_id),
            &[],
            now,
        );
        assert_eq!(
            check_ownership_reclaim_admission(dir, &not_a_finding, Some(&policy), now)
                .await
                .expect("gate")
                .refusal(),
            Some(ReclaimRefusal::NotAWaFinding),
            "({suffix}) the petition is not the finding — a ref must resolve to a QUORUM finding"
        );

        // ══ RED 3 — an under-signed finding (1 of the required 2).
        let short_finding = signed_row(
            &wa[0],
            &node,
            attestation_type::SCORES,
            finding_env.clone(),
            &[],
            now,
        );
        store(dir, &short_finding).await.expect("short finding");
        let short_withdraws = signed_row(
            &node,
            &node,
            attestation_type::WITHDRAWS,
            build_reclaim_withdraws_envelope(&binding_id, &short_finding.attestation_id),
            &[],
            now,
        );
        match check_ownership_reclaim_admission(dir, &short_withdraws, Some(&policy), now)
            .await
            .expect("gate")
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
        //    `wise_authority` card but hold no seat in the WA body co-sign a
        //    finding. `identity_type` is self-declared at registration
        //    (CC 3.4.7.1 / #543 `DerivedFromVerifiedState`), so if the card
        //    alone counted, anyone could register two keys and take any node
        //    in the mesh. The seat is what confers; the card is only
        //    legibility.
        let sybil: [String; 2] = [format!("r-sybil-a-{suffix}"), format!("r-sybil-b-{suffix}")];
        for k in &sybil {
            register(
                dir,
                k,
                &[identity_type::USER, identity_type::WISE_AUTHORITY],
            )
            .await;
        }
        let sybil_finding = signed_row(
            &sybil[0],
            &node,
            attestation_type::SCORES,
            finding_env.clone(),
            &[&sybil[1]],
            now,
        );
        store(dir, &sybil_finding).await.expect("sybil finding");
        let sybil_withdraws = signed_row(
            &node,
            &node,
            attestation_type::WITHDRAWS,
            build_reclaim_withdraws_envelope(&binding_id, &sybil_finding.attestation_id),
            &[],
            now,
        );
        match check_ownership_reclaim_admission(dir, &sybil_withdraws, Some(&policy), now)
            .await
            .expect("gate")
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

        // ══ RED 3c — THE CARD. CC 4.3's normative heading is "The Wise wear
        //    the same card": a SEATED member whose registered identity_type
        //    does not carry `wise_authority` is not legible as a WA and its
        //    co-signature does not COUNT — while still sitting in the
        //    denominator. A second body, so the 2-of-3 green path above keeps
        //    its own roster.
        let uncarded = format!("r-uncarded-{suffix}");
        register(dir, &uncarded, &[identity_type::USER]).await;
        let body2 = format!("r-wa-body2-{suffix}");
        dir.put_family_local(Family {
            family_key_id: body2.clone(),
            family_name: format!("half-legible authorities {suffix}"),
            members: [&wa[0], &wa[1], &uncarded]
                .iter()
                .map(|k| FamilyMember {
                    key_id: (*k).clone(),
                    joined_at: now,
                    role: Some("member".to_owned()),
                })
                .collect(),
            founded_at: now,
            consensus_protocol: "majority".to_owned(),
            consensus_protocol_entrenched: false,
            persist_row_hash: String::new(),
        })
        .await
        .expect("seat the half-legible body");
        let half_legible = signed_row(
            &wa[0],
            &node,
            attestation_type::SCORES,
            finding_env.clone(),
            &[&uncarded],
            now,
        );
        store(dir, &half_legible)
            .await
            .expect("half-legible finding");
        let half_withdraws = signed_row(
            &node,
            &node,
            attestation_type::WITHDRAWS,
            build_reclaim_withdraws_envelope(&binding_id, &half_legible.attestation_id),
            &[],
            now,
        );
        match check_ownership_reclaim_admission(
            dir,
            &half_withdraws,
            Some(&ReclaimPolicy::wise_authority(&body2)),
            now,
        )
        .await
        .expect("gate")
        {
            ReclaimVerdict::Refused {
                reason: ReclaimRefusal::WaQuorumShort,
                quorum: Some(q),
                ..
            } => assert_eq!(
                (q.counted, q.required, q.roster_size),
                (1, 2, 3),
                "({suffix}) TWO seated members signed, but only the card-carrying one COUNTS — \
                 and the uncarded seat still sits in the denominator: {q:?}"
            ),
            other => panic!(
                "({suffix}) a seated-but-illegible co-signer must not carry the quorum, got \
                 {other:?}"
            ),
        }

        // ══ RED 4 — the accord roster is not a WA body.
        let accord_policy = ReclaimPolicy::wise_authority(
            ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID,
        );
        let good_env = build_reclaim_withdraws_envelope(&binding_id, &finding.attestation_id);
        let good = signed_row(
            &node,
            &node,
            attestation_type::WITHDRAWS,
            good_env.clone(),
            &[],
            now,
        );
        assert_eq!(
            check_ownership_reclaim_admission(dir, &good, Some(&accord_policy), now)
                .await
                .expect("gate")
                .refusal(),
            Some(ReclaimRefusal::AccordRosterIsNotWaAuthority),
            "({suffix}) v21.8.0's accord-rostered authority is now non-conformant"
        );
        // …and with NO published policy at all, nothing is seizable.
        assert_eq!(
            check_ownership_reclaim_admission(dir, &good, None, now)
                .await
                .expect("gate")
                .refusal(),
            Some(ReclaimRefusal::NoDeploymentPolicy),
            "({suffix}) an unpublished WA body means no reclaim is admissible here"
        );

        // ══ RED 5 — THE SINGLE-ACT TRANSFER. Refused before authority is
        //    even considered, and unrepresentable in the admitted verdict.
        let mut collapsed_env = good_env.clone();
        collapsed_env.as_object_mut().expect("object").insert(
            "successor_owner_key_id".to_owned(),
            serde_json::Value::String(claimant.clone()),
        );
        let collapsed = signed_row(
            &node,
            &node,
            attestation_type::WITHDRAWS,
            collapsed_env,
            &[],
            now,
        );
        assert_eq!(
            check_ownership_reclaim_admission(dir, &collapsed, Some(&policy), now)
                .await
                .expect("gate")
                .refusal(),
            Some(ReclaimRefusal::SingleActTransferAttempted),
            "({suffix}) a withdraws that names who gets the node next collapses steps 3 and 4"
        );
        assert!(
            store(dir, &collapsed).await.is_err(),
            "({suffix}) …and the real put gate refuses it, so it never lands"
        );

        // ══ RED 6 — an issuer with no CC rule-(2)/(4) standing.
        let outsider = signed_row(
            &filer,
            &node,
            attestation_type::WITHDRAWS,
            good_env.clone(),
            &[],
            now,
        );
        assert_eq!(
            check_ownership_reclaim_admission(dir, &outsider, Some(&policy), now)
                .await
                .expect("gate")
                .refusal(),
            Some(ReclaimRefusal::IssuerLacksRecoveryStanding),
            "({suffix}) a quorum finding is not a warrant for an arbitrary third party"
        );

        // ══ RED 7 — a fresh binding while the incumbent is still live is the
        //    ordinary single-owner refusal (the claimant cannot skip step 3).
        let premature =
            ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &claimant, &node);
        assert!(
            matches!(
                store(dir, &premature).await,
                Err(Error::NodeAlreadyOwned { .. })
            ),
            "({suffix}) the claimant cannot bind while the incumbent is live"
        );

        // ══ GREEN — step 3: the full ceremony admits, THROUGH THE REAL GATE.
        assert!(
            check_ownership_reclaim_admission(dir, &good, Some(&policy), now)
                .await
                .expect("gate")
                .is_admit(),
            "({suffix}) petition + 2-of-3 finding + rule-(2) issuer + lapsed floor ⇒ admit"
        );
        std::env::set_var(ReclaimPolicy::WA_FAMILY_ENV, &wa_body);
        store(dir, &good).await.expect("the gated withdraws lands");
        std::env::remove_var(ReclaimPolicy::WA_FAMILY_ENV);
        let stored_withdraws = dir
            .get_attestation(&good.attestation_id)
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
            crate::federation::admission::owner_of(dir, &node)
                .await
                .expect("owner_of"),
            None,
            "({suffix}) after the gated withdraws K is UNOWNED — empty self cohort, fail-secure. \
             If the incumbent were still resolvable here the ceremony would not pass through the \
             unowned state at all and the single-act wall would be cosmetic."
        );

        // ══ RED 8 — step 4 without K's co-signature is refused.
        let uncosigned =
            ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), &claimant, &node);
        match store(dir, &uncosigned).await {
            Err(Error::OwnershipReclaimRefused {
                reason: ReclaimRefusal::FreshBindingNotCosignedByNode,
                ..
            }) => {}
            other => panic!(
                "({suffix}) a post-reclaim rebinding not co-signed by K must be refused, got \
                 {other:?}"
            ),
        }

        // ══ GREEN — step 4: co-signed by K, the claimant binds.
        let rebind_id = uuid::Uuid::new_v4().to_string();
        let mut rebind = ts::owner_binding_attestation(&rebind_id, &claimant, &node);
        let (_h, cl, pq) = ts::sign_envelope(&node, &rebind.attestation_envelope);
        rebind.additional_scrubs = vec![crate::federation::types::ScrubSig {
            scrub_key_id: node.clone(),
            scrub_signature_classical: cl,
            scrub_signature_pqc: pq,
        }];
        store(dir, &rebind)
            .await
            .expect("co-signed rebinding lands");
        assert_eq!(
            crate::federation::admission::owner_of(dir, &node)
                .await
                .expect("owner_of"),
            Some(claimant.clone()),
            "({suffix}) and only now, after four distinct acts, is K owned again"
        );

        // ══ THE SEIZURE ARM — a LIVE binding, reached by a seizure finding.
        //    A fresh touch-claim proves the incumbent is alive; abandonment
        //    would refuse, seizure must not (rc3: a front-run is reversible).
        let node2 = format!("r-node2-{suffix}");
        let owner2 = format!("r-owner2-{suffix}");
        register(dir, &node2, &[identity_type::NODE]).await;
        register(dir, &owner2, &[identity_type::USER]).await;
        let b2_id = uuid::Uuid::new_v4().to_string();
        store(dir, &ts::owner_binding_attestation(&b2_id, &owner2, &node2))
            .await
            .expect("live binding");
        dir.put_touch_claim(&self_touch(&owner2, now - Duration::minutes(5)))
            .await
            .expect("fresh self-touch");
        let p2 = signed_row(
            &filer,
            &node2,
            attestation_type::SCORES,
            build_reclaim_petition_envelope(&b2_id, "front-run at provisioning"),
            &[],
            now,
        );
        store(dir, &p2).await.expect("petition 2");
        let mk_finding = |kind: WaFinding| {
            signed_row(
                &wa[0],
                &node2,
                attestation_type::SCORES,
                build_wa_finding_envelope(kind, &b2_id, &p2.attestation_id, "fraudulent binding"),
                &[&wa[2]],
                now,
            )
        };
        let aband2 = mk_finding(WaFinding::Abandonment);
        store(dir, &aband2).await.expect("abandonment finding 2");
        let seiz2 = mk_finding(WaFinding::Seizure);
        store(dir, &seiz2).await.expect("seizure finding 2");

        // ══ RED 9 — A FINDING IS NOT A BEARER TOKEN. The genuine, fully
        //    quorum-signed finding minted against node2's binding is replayed
        //    against the FIRST node's binding. Everything about it verifies —
        //    real WAs, real signatures, real quorum — and it must still be
        //    refused, because it adjudicates a different binding.
        let replayed = signed_row(
            &node,
            &node,
            attestation_type::WITHDRAWS,
            build_reclaim_withdraws_envelope(&binding_id, &seiz2.attestation_id),
            &[],
            now,
        );
        assert_eq!(
            check_ownership_reclaim_admission(dir, &replayed, Some(&policy), now)
                .await
                .expect("gate")
                .refusal(),
            Some(ReclaimRefusal::FindingNotAgainstThisBinding),
            "({suffix}) a valid finding for ONE binding must not authorize a withdraws against \
             another — a quorum finding is scoped, never a warrant for the mesh"
        );

        let w_aband = signed_row(
            &node2,
            &node2,
            attestation_type::WITHDRAWS,
            build_reclaim_withdraws_envelope(&b2_id, &aband2.attestation_id),
            &[],
            now,
        );
        assert_eq!(
            check_ownership_reclaim_admission(dir, &w_aband, Some(&policy), now)
                .await
                .expect("gate")
                .refusal(),
            Some(ReclaimRefusal::NotAbandoned),
            "({suffix}) a LIVE owner is quiet-proof: abandonment refuses even with a real quorum"
        );
        let w_seiz = signed_row(
            &node2,
            &node2,
            attestation_type::WITHDRAWS,
            build_reclaim_withdraws_envelope(&b2_id, &seiz2.attestation_id),
            &[],
            now,
        );
        match check_ownership_reclaim_admission(dir, &w_seiz, Some(&policy), now)
            .await
            .expect("gate")
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
        //    producer shape. rc3: *"The owner-binding `delegates_to(owner → K)`
        //    names K in its `subject_key_ids`"* — and the moment a producer
        //    does that, CEG rule 2 (subject self-revocation) ADMITS a
        //    `withdraws` from K against its own owner, with no adjudication at
        //    all. That is precisely what CC 3.2 says makes the single-owner
        //    invariant "worthless".
        //
        //    Persist's owner-bindings carry no subject_key_ids today, so the
        //    other witnesses all travel the rules-1-4-REFUSED branch. This one
        //    travels the rules-ADMIT branch, which is the load-bearing half:
        //    without the gate on that side, the row below simply lands.
        let node3 = format!("r-node3-{suffix}");
        let owner3 = format!("r-owner3-{suffix}");
        register(dir, &node3, &[identity_type::NODE]).await;
        register(dir, &owner3, &[identity_type::USER]).await;
        let b3_id = uuid::Uuid::new_v4().to_string();
        let mut b3 = ts::owner_binding_attestation(&b3_id, &owner3, &node3);
        b3.subject_key_ids = vec![node3.clone()];
        store(dir, &b3)
            .await
            .expect("conformant binding names K as subject");
        assert_eq!(
            crate::federation::admission::resolve_withdraws_admission_rule(
                dir,
                &node3,
                &dir.get_attestation(&b3_id)
                    .await
                    .expect("read")
                    .expect("stored")
            )
            .await
            .expect("rule"),
            2,
            "({suffix}) the ordinary 4-rule gate really does hand K rule-2 authority over its \
             own owner-binding — this is the exploit the recovery gate exists to close"
        );
        let liberation = signed_row(
            &node3,
            &node3,
            attestation_type::WITHDRAWS,
            build_reclaim_withdraws_envelope(&b3_id, ""),
            &[],
            now,
        );
        match store(dir, &liberation).await {
            // No WA body is published in this process, so the refusal lands at
            // ceremony step 0 — which is the SHIPPED posture and the strongest
            // form of this witness: with nothing published, a compromised node
            // key cannot shed its owner no matter what else it carries.
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
            crate::federation::admission::owner_of(dir, &node3)
                .await
                .expect("owner_of"),
            Some(owner3.clone()),
            "({suffix}) …and the node is still owned — the refusal wrote nothing"
        );
    }
}
