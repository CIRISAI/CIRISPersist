//! v24.3.0 (CIRISPersist#574) — **reverse quorum: the commons' brake.**
//!
//! Consent protects the private plane structurally: no signed directed grant,
//! no delivery. The **commons** — federation-scoped, publicly readable rows —
//! gets nothing from consent, because in the commons everyone has already
//! consented to look. Communities are meant to police it themselves, and the
//! only shape that resolves speed against legitimacy at mesh scale is
//! **act-unless-objected**: the action lands on arrival, and it is undone if
//! enough members object inside a window. Approve-first means the response
//! arrives after the harm; no-check means one member governs.
//!
//! # The asymmetry is the design
//!
//! This module implements the repo's recorded accord-ops invariant —
//! ***m-of-n OR reverse quorum, never 1-of-N capability-grant*** — in its
//! reverse-quorum form:
//!
//! > **1-of-N to PROTECT, m-of-n to UNDO.**
//!
//! Concretely, and enforced in exactly two functions so the two directions
//! can never drift:
//!
//! | side | who | threshold |
//! |---|---|---|
//! | raise an objection | any ONE current member | [`OBJECTION_THRESHOLD`] = 1, always, every roster |
//! | reverse the action | `m` distinct in-window objectors | [`ReverseQuorumPolicy::reversal_threshold`] — the declared `m`, **capped** at the roster, never raised |
//! | dismiss an objection | the cohort, m-of-n | [`ReverseQuorumPolicy::dismissal_threshold`] — the declared `m`, **floored at a strict majority**, never lowered |
//!
//! One rule, two directions: *the protective side is never made harder than
//! declared; the undo side is never made easier than a strict majority.*
//!
//! [`tests::the_asymmetry_holds_for_every_roster`] pins the ordering
//! `1 ≤ reversal ≤ dismissal` over every roster/policy pair in range — but the
//! ordering ALONE is not enough, which a mutation run proved: flooring BOTH
//! sides at a strict majority preserves it while quietly making the brake as
//! expensive as the undo, and every test passed. So the protective side is
//! additionally pinned as an exact equality there and in
//! [`tests::the_protective_side_is_never_floored_at_a_strict_majority`], and
//! the backend witness runs a FIVE-member roster under `reverse_quorum:2/5`
//! (at three, `m` and a strict majority coincide and the witness cannot see
//! the difference).
//!
//! # Markers, not commands (the #570 design wall)
//!
//! An objection is a **`scores` attestation**, deliberately NOT a `withdraws`.
//! That is the whole distinction:
//!
//! - a `withdraws` **compels** — the substrate acts on it at admission and the
//!   target row is revoked;
//! - a `scores` row on [`DIMENSION_OBJECTION`] **asserts** — it is durable,
//!   signed, attributable, and replicates on the ordinary attestation plane
//!   because it *is* an ordinary attestation. Nothing is mutated by its
//!   arrival. A reader that folds it may honour what the fold says; a reader
//!   that does not fold it is unaffected.
//!
//! So the objection travels (it is a row on the substrate, not an API call
//! that dies with the objector's node), it can be counted by a peer that was
//! partitioned during the window whenever it finally arrives, and it never
//! instructs anyone.
//!
//! # Evidence, not verdict
//!
//! [`resolve_reverse_quorum`] returns a [`ReverseQuorumFold`] — the count, the
//! threshold, the roster size, the window bounds, and the ids of the
//! objections it counted. Persist **never** deletes, tombstones, or rewrites
//! the objected-to row. [`ReverseQuorumStanding::Reversed`] is a derived
//! state in exactly the sense
//! [`ConsentState::Revoked`](super::hard_case::ConsentState::Revoked) is: a
//! pure function of held rows, recomputed at read time, converging on every
//! node without coordination once the rows have travelled. It is the same
//! `hard_case`-evidence / never-slashing-verdict split v22 shipped.
//!
//! # Authority is re-derived from this node's own verified state (#377)
//!
//! Nothing here trusts a caller-supplied roster, threshold, or decision
//! boolean. The roster comes from
//! [`FederationDirectory::active_members`](super::FederationDirectory::active_members)
//! (revocation-folded), the threshold from the cohort's OWN stored
//! `consensus_protocol`, and every counted signature is re-verified through
//! [`verify_envelope_hybrid_signature`](super::tier_ingest::verify_envelope_hybrid_signature)
//! against pubkeys resolved from this node's directory.
//!
//! # The vocabulary is closed in THREE places
//!
//! `reverse_quorum:{m}/{n}:{window_secs}` had to be admitted by all of:
//! [`consensus_protocol::is_canonical_form`](super::types::consensus_protocol::is_canonical_form)
//! (which routes to [`ReverseQuorumPolicy::parse`], so the shape gate can
//! never admit a string this module cannot read), the sqlite
//! `federation_communities` table CHECK, and its postgres twin — V116 on both
//! backends. The issue named only the Rust gate; the sqlite CHECK raised a
//! constraint violation on the first real `put_community`, which is the useful
//! kind of red. `federation_families.consensus_protocol` carries no CHECK, so
//! there was deliberately nothing to widen there.
//!
//! # What is deliberately out of scope
//!
//! **Objection to the objection.** One level. A second level makes this a
//! governance system instead of a brake — a dismissal is not itself
//! objectionable.
//!
//! A member retracting their OWN objection is not a second level and is not
//! m-of-n: it costs one signature, their own ([`dismissal_required`]). Dropping
//! your own protection is cheap by exactly the construction that makes raising
//! it cheap, and a captured key can retract only what that same key raised, so
//! nobody else's protection is reachable that way.

use chrono::{DateTime, Duration, Utc};

use super::types::Attestation;
use super::{cohort::Cohort, Error, FederationDirectory};

/// The `scores` dimension an objection carries: *"I, a member of this cohort,
/// object to this action in our commons."*
///
/// A **new namespace family** — see [`NAMESPACE_FAMILY`]. Versioned `:v1` per
/// the house style for persist-minted dimensions (`consent:replication:v1`,
/// `trace:complete:v1`).
pub const DIMENSION_OBJECTION: &str = "objection:raised:v1";

/// The `scores` dimension a **dismissal** carries: *"this cohort, at m-of-n,
/// holds that the named objection does not stand."* The m-of-n half of the
/// asymmetry — see [`ReverseQuorumPolicy::dismissal_threshold`].
pub const DIMENSION_DISMISSAL: &str = "objection:dismissed:v1";

/// The CC 3.1 namespace family both dimensions live under. **Registered**
/// (CIRISPersist#590): CC 1.0-rc3 catalogues it at CC 3.1.9.2, owning
/// component `node`, alongside `moderation:{allegation_type}`,
/// `slashing:{outcome}` and `reconsideration:{grounds}`. Between #574 and the
/// re-vendor it was rowless, which is the state CC 3.1.7 R2 exists to make
/// impossible; it is now on the R2(a) mint gate
/// ([`super::admission::MINTED_NAMESPACE_FAMILIES`]), so a future family minted
/// without its row fails persist's own build.
///
/// The cohort-member-only emitter rule the ask named is the gate
/// [`record_objection`] enforces here; CC's row carries the family, and the
/// emitter/composition elaboration rides CIRISConstitution#67.
pub const NAMESPACE_FAMILY: &str = "objection:{state}";

/// Envelope field names shared by the producer side and persist's fold, so
/// the two cannot disagree about where a reference lives.
pub mod field {
    /// The objected-to action's `attestation_id`.
    pub const OBJECTS_TO: &str = "objects_to_attestation_id";
    /// The objection's own `attestation_id` — on a DISMISSAL envelope, which
    /// objection is being dismissed.
    pub const DISMISSES: &str = "dismisses_objection_id";
    /// Which rostered tier's commons this is (`family` / `community` /
    /// `affiliations`).
    pub const COHORT: &str = "cohort";
    /// The cohort's `federation_keys.key_id` — whose roster and whose
    /// `consensus_protocol` govern the count.
    ///
    /// NOTE this is one of the three fields
    /// [`check_no_moderator_federate_apply`](super::admission::check_no_moderator_federate_apply)
    /// scans, so an objection naming a community re-checks that community's
    /// §11.11 moderator existence on its way in. That is correct and
    /// deliberate: an unmoderated community does not get to run a policing
    /// plane either.
    pub const COHORT_KEY_ID: &str = "cohort_key_id";
    /// Free-text grounds. Recorded, never interpreted — persist does not
    /// adjudicate WHY somebody objected.
    pub const GROUNDS: &str = "grounds";
}

// ─────────────────────────────────────────────────────────────────────────
//  The policy
// ─────────────────────────────────────────────────────────────────────────

/// A parsed `reverse_quorum:{m}/{n}:{window_secs}`
/// ([`consensus_protocol::REVERSE_QUORUM_PREFIX`](super::types::consensus_protocol::REVERSE_QUORUM_PREFIX)).
///
/// `n` is the roster size the protocol was WRITTEN against; the live roster is
/// what actually counts (a cohort that grew or shrank without re-baselining
/// its protocol string does not get to keep the stale denominator). `n` is
/// therefore validated (`0 < m ≤ n`) and then never used as an authority —
/// exactly the discipline
/// [`family_charter_threshold`](super::trust_root) applies to a carried
/// `quorum:M/N`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReverseQuorumPolicy {
    /// Objectors required to reverse the action.
    pub m: u32,
    /// The roster size the protocol was written against.
    pub n: u32,
    /// How long after the action's `asserted_at` objections still count.
    pub window_secs: u64,
}

impl ReverseQuorumPolicy {
    /// Parse `reverse_quorum:{m}/{n}:{window_secs}`. `None` for any other
    /// string, and for the degenerate shapes:
    ///
    /// - `m == 0` — an action reversed by ZERO objections is an action that
    ///   never lands; that is approve-to-act wearing this prefix, and it would
    ///   make the "acts immediately" half a lie.
    /// - `m > n` or `n == 0` — unsatisfiable.
    /// - a window that does not parse as seconds. A window of `0` IS accepted:
    ///   it means "no reverse-quorum grace", which is a coherent (if severe)
    ///   declaration, and the fold reports it honestly as an already-closed
    ///   window rather than guessing a default.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let tail = s.strip_prefix(super::types::consensus_protocol::REVERSE_QUORUM_PREFIX)?;
        let (quorum, window) = tail.split_once(':')?;
        let (m_s, n_s) = quorum.split_once('/')?;
        let m: u32 = m_s.parse().ok()?;
        let n: u32 = n_s.parse().ok()?;
        let window_secs: u64 = window.parse().ok()?;
        if m == 0 || n == 0 || m > n {
            return None;
        }
        Some(Self { m, n, window_secs })
    }

    /// Render back to the canonical `consensus_protocol` string.
    #[must_use]
    pub fn to_protocol_string(&self) -> String {
        format!(
            "{}{}/{}:{}",
            super::types::consensus_protocol::REVERSE_QUORUM_PREFIX,
            self.m,
            self.n,
            self.window_secs
        )
    }

    /// The objection window for an action asserted at `asserted_at`:
    /// `[asserted_at, asserted_at + window_secs]`, inclusive at both ends.
    ///
    /// Pinned to the ACTION, not to the objection and not to `now` — that is
    /// what makes the fold a pure function of held rows, so a node that was
    /// partitioned for the whole window still computes the same answer the
    /// moment the rows arrive.
    #[must_use]
    pub fn window(&self, asserted_at: DateTime<Utc>) -> (DateTime<Utc>, DateTime<Utc>) {
        // `window_secs` is bounded by i64 seconds; a value beyond that
        // saturates to the far future, which is the fail-SAFE direction for a
        // protective window (longer protection, never shorter).
        let secs = i64::try_from(self.window_secs).unwrap_or(i64::MAX);
        let close = asserted_at
            .checked_add_signed(Duration::try_seconds(secs).unwrap_or(Duration::MAX))
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        (asserted_at, close)
    }

    /// **The protective side.** How many DISTINCT in-window objectors reverse
    /// the action: the declared `m`, **capped** at the live roster — never
    /// raised.
    ///
    /// The cap exists because a roster that shrank below `m` would otherwise
    /// make reversal unreachable, i.e. would silently disarm the brake. The
    /// absence of a strict-majority FLOOR here is the load-bearing asymmetry:
    /// flooring the protective side is exactly the mistake this module exists
    /// to not make. Contrast [`Self::dismissal_threshold`].
    #[must_use]
    pub fn reversal_threshold(&self, roster_size: usize) -> usize {
        (self.m as usize).min(roster_size.max(1))
    }

    /// **The undo side.** How many DISTINCT roster members must co-sign to
    /// DISMISS an objection: the declared `m`, **floored at a strict
    /// majority** of the live roster — never lowered.
    ///
    /// Undoing protection is expensive and collective. The floor is the same
    /// defence [`family_charter_threshold`](super::trust_root) applies: a
    /// tampered (or merely optimistic) policy string cannot talk the threshold
    /// down, because the number the node acts on is re-derived from the
    /// node's OWN roster.
    #[must_use]
    pub fn dismissal_threshold(&self, roster_size: usize) -> usize {
        let floor = ciris_verify_core::accord_genesis::strict_majority(roster_size);
        (self.m as usize).max(floor).max(1)
    }
}

/// **The protective threshold, in full.** One member. Every roster, every
/// cohort, every action — the constant exists so the 1 is a named commitment
/// rather than an implicit absence of a check.
///
/// Protection is cheap and unilateral by construction: an adversary who has
/// captured keys still cannot stop one honest surviving member from raising
/// the brake, and raising it confers no capability on the objector (a marker
/// grants nothing). Undoing SOMEBODY ELSE'S costs
/// [`ReverseQuorumPolicy::dismissal_threshold`]; undoing your own costs this
/// same 1 — see [`dismissal_required`].
pub const OBJECTION_THRESHOLD: usize = 1;

/// How many distinct verified roster co-signatures THIS dismissal needs — the
/// ONE place that number is decided, read by both the admission door
/// ([`record_objection_dismissal`]) and the read-time re-derivation
/// ([`resolve_reverse_quorum`]) so the two can never disagree about whether a
/// stored dismissal still stands.
///
/// `self_dismissal` — the dismissal's author IS the author of the objection it
/// names. Then **one**: dropping your own protection is cheap by exactly the
/// construction that makes raising it cheap, and it is not an undo of anybody
/// else's. A captured key can retract only what that same key raised, so the
/// m-of-n property over every OTHER member's objection is untouched — which is
/// what makes this the correct reading of "1-of-N to protect" rather than a
/// hole in it.
///
/// This is also the only retraction path a member has. The ordinary
/// `withdraws` grammar names a KEY (`attested_key_id`), not a specific
/// attestation, so it cannot single out one objection among several against
/// the same actor.
#[must_use]
pub fn dismissal_required(
    policy: &ReverseQuorumPolicy,
    roster_size: usize,
    self_dismissal: bool,
) -> usize {
    if self_dismissal {
        OBJECTION_THRESHOLD
    } else {
        policy.dismissal_threshold(roster_size)
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Typed refusals (#565 style)
// ─────────────────────────────────────────────────────────────────────────

/// **WHICH branch refused** an objection or a dismissal.
///
/// Closed, snake_case serde tokens, [`Self::as_str`] returning the SAME token,
/// and deliberately no `Other`/`Unspecified` catch-all — the
/// [`KeyRefusalReason`](super::register::KeyRefusalReason) discipline #565
/// shipped, for the same reason: a refusal is a verdict, and a verdict without
/// its branch sends the reader to the wrong layer.
///
/// **The token set is the downstream contract and this mapping is
/// APPEND-ONLY.** Add variants; never re-spell one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectionRefusalReason {
    /// The envelope's `cohort` / `cohort_key_id` does not resolve to a group
    /// this node holds. Authority must come from local verified state, and
    /// there is none — fail-closed.
    CohortUnknown,
    /// The cohort's stored `consensus_protocol` is not a `reverse_quorum:*`
    /// form, so this cohort has not adopted the objection plane. Refused
    /// rather than defaulted: inventing a window and a threshold for a group
    /// that declared neither is exactly the "stored label nobody consumes"
    /// failure #574 was filed about, one layer deeper.
    NotGoverned,
    /// The signer is not on the cohort's revocation-folded active roster. The
    /// ONLY test the 1-of-N protective gate applies — and the reason a
    /// non-member's objection never becomes a marker others might honour.
    NotACohortMember,
    /// The objected-to `attestation_id` is not held by this node. Nothing can
    /// object to a row that is not here; the objection would be uncountable
    /// and its window unresolvable.
    TargetActionUnknown,
    /// The row's envelope `dimension` is not the one this door admits
    /// ([`DIMENSION_OBJECTION`] / [`DIMENSION_DISMISSAL`]). Wrong door.
    DimensionMismatch,
    /// The envelope is missing a field the fold needs — [`field::OBJECTS_TO`]
    /// on an objection, [`field::DISMISSES`] on a dismissal, or the cohort
    /// pair on either.
    MalformedEnvelope,
    /// The row's own scrub signature did not verify against the signer's
    /// pubkeys as registered on THIS node.
    UnverifiableSignature,
    /// This member already holds a live objection against this action. One
    /// member is one objection: without this, a single member could raise `m`
    /// of them and reach the reversal threshold alone. (The fold counts
    /// DISTINCT objectors regardless — this refusal keeps the corpus clean;
    /// the distinctness in [`fold_reverse_quorum`] is what makes it safe.)
    DuplicateObjection,
    /// The row's `attested_key_id` is not the objected-to action's AUTHOR.
    ///
    /// Objections and dismissals are found by
    /// [`list_attestations_for`](super::FederationDirectory::list_attestations_for)`(action.attesting_key_id)`,
    /// so a row filed against any other key would be stored and then never
    /// counted by anything — admitted, durable, and permanently inert. Refused
    /// instead: the preserve set must equal the verified set, and a marker
    /// nobody can find is not a marker.
    NotFiledAgainstActor,
    /// A dismissal's [`field::DISMISSES`] does not resolve to an objection
    /// this node holds against the SAME action — the row is absent, is not an
    /// [`DIMENSION_OBJECTION`] row, or objects to something else. Tested here
    /// exactly as [`resolve_reverse_quorum`] tests it at read time, so a
    /// dismissal cannot be admitted under one rule and re-priced under another.
    ObjectionUnknown,
    /// A dismissal carried fewer distinct verified roster co-signatures than
    /// [`ReverseQuorumPolicy::dismissal_threshold`] demands. The shortfall's
    /// numbers ride on the accompanying [`DismissalQuorum`].
    DismissalQuorumShort,
}

impl ObjectionRefusalReason {
    /// The **stable program token** — identical to the serde token, so a
    /// consumer reading the wire and a consumer holding the typed value key on
    /// the same constant.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CohortUnknown => "cohort_unknown",
            Self::NotGoverned => "not_governed",
            Self::NotACohortMember => "not_a_cohort_member",
            Self::TargetActionUnknown => "target_action_unknown",
            Self::DimensionMismatch => "dimension_mismatch",
            Self::MalformedEnvelope => "malformed_envelope",
            Self::UnverifiableSignature => "unverifiable_signature",
            Self::DuplicateObjection => "duplicate_objection",
            Self::NotFiledAgainstActor => "not_filed_against_actor",
            Self::ObjectionUnknown => "objection_unknown",
            Self::DismissalQuorumShort => "dismissal_quorum_short",
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::CohortUnknown,
        Self::NotGoverned,
        Self::NotACohortMember,
        Self::TargetActionUnknown,
        Self::DimensionMismatch,
        Self::MalformedEnvelope,
        Self::UnverifiableSignature,
        Self::DuplicateObjection,
        Self::NotFiledAgainstActor,
        Self::ObjectionUnknown,
        Self::DismissalQuorumShort,
    ];
}

impl std::fmt::Display for ObjectionRefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of an admission attempt. `Refused` is a **policy** outcome, not an
/// error: an objection arrives unsolicited on a replication plane, so every
/// gate failure resolves deterministically and safe-to-re-offer rather than
/// aborting a loop. Backend/IO failures still surface as `Err`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectionOutcome {
    /// Admitted and stored.
    Admitted,
    /// Not admitted; nothing was written.
    Refused {
        /// WHICH policy branch refused.
        reason: ObjectionRefusalReason,
    },
}

impl ObjectionOutcome {
    /// The refusal reason, if this is a refusal.
    #[must_use]
    pub const fn refusal(&self) -> Option<ObjectionRefusalReason> {
        match self {
            Self::Admitted => None,
            Self::Refused { reason } => Some(*reason),
        }
    }
}

/// The m-of-n evidence behind a dismissal decision — carried on BOTH arms, so
/// a refusal names its shortfall and an admission names what it cleared.
/// Structural twin of `CharterQuorum` on the trust-root plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DismissalQuorum {
    /// DISTINCT roster members whose signature over this dismissal's canonical
    /// envelope verified against pubkeys resolved from this node's directory.
    pub counted: usize,
    /// [`ReverseQuorumPolicy::dismissal_threshold`] for the live roster.
    pub required: usize,
    /// The live (revocation-folded) roster size the threshold was derived
    /// from.
    pub roster_size: usize,
}

/// A dismissal admission decision: the outcome plus the count it rests on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DismissalDecision {
    /// Admitted, or refused naming the branch.
    pub outcome: ObjectionOutcome,
    /// The m-of-n evidence — always present, on both arms.
    pub quorum: DismissalQuorum,
}

// ─────────────────────────────────────────────────────────────────────────
//  The fold
// ─────────────────────────────────────────────────────────────────────────

/// What the reverse quorum says about one action, right now, on this node.
///
/// A derived STATE, not a sentence — see the module doc. Persist never mutates
/// the objected-to row on any of these arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReverseQuorumStanding {
    /// The cohort declares no `reverse_quorum:*` protocol — this plane does
    /// not apply to its commons at all.
    NotGoverned,
    /// The window is still open and the live in-window objector count is below
    /// the reversal threshold. The action stands FOR NOW.
    WindowOpen,
    /// The window closed below the threshold. The action stands.
    Stood,
    /// `m` distinct current members objected in-window and their objections
    /// are live. Every node holding these rows folds to this same answer.
    Reversed,
}

/// The full read-time answer, with the evidence that produced it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReverseQuorumFold {
    /// The derived state.
    pub standing: ReverseQuorumStanding,
    /// The cohort's parsed protocol, or `None` when
    /// [`ReverseQuorumStanding::NotGoverned`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// DISTINCT in-window, live, roster-member objectors.
    pub distinct_objectors: usize,
    /// [`ReverseQuorumPolicy::reversal_threshold`] for the live roster (`0`
    /// when not governed).
    pub required: usize,
    /// The live roster size the threshold was derived from.
    pub roster_size: usize,
    /// The action's `asserted_at` — the window's start.
    pub window_opens_at: DateTime<Utc>,
    /// `window_opens_at + window_secs` — the last instant an objection counts.
    pub window_closes_at: DateTime<Utc>,
    /// Whether `now` is inside the window.
    pub window_open: bool,
    /// The `attestation_id`s of the objections that COUNTED, sorted. The fold
    /// names its evidence.
    pub counted_objection_ids: Vec<String>,
    /// The `attestation_id`s of objections excluded because a quorum-verified
    /// dismissal named them, sorted.
    pub dismissed_objection_ids: Vec<String>,
}

/// The **pure fold**: a function of `(action, objections, dismissals, roster,
/// policy, now)` and nothing else.
///
/// Evaluated at READ time rather than advanced at write time, for the reason
/// the issue gives: a node partitioned during the window sees the action but
/// not the objections, and must converge on the same answer when they arrive
/// late. A state machine advanced at write time cannot do that; a fold over
/// held rows does it for free — the same shape `resolve_scoped_consent` has.
///
/// # The `dismissals` contract
///
/// This function CANNOT verify a dismissal's m-of-n: counting signatures needs
/// a directory. It therefore trusts `dismissals` to be **already
/// quorum-verified**, and [`resolve_reverse_quorum`] is the only supported way
/// to build that list. Passing unverified rows here would let one member
/// dismiss another's objection, which is precisely the asymmetry this module
/// exists to hold — so the async resolver, not this core, is the public entry
/// point for hosts.
///
/// # Counting rules
///
/// An objection counts iff ALL of: it carries [`DIMENSION_OBJECTION`]; its
/// [`field::OBJECTS_TO`] names `action`; its `attesting_key_id` is on the LIVE
/// roster (a member who left stops counting — the threshold is re-derived at
/// read time, so a reversal can lapse exactly as a charter quorum can); its
/// `asserted_at` is inside the window; and no supplied dismissal names it.
/// Objectors are counted **distinct** by `attesting_key_id`.
#[must_use]
pub fn fold_reverse_quorum(
    action: &Attestation,
    objections: &[Attestation],
    dismissals: &[Attestation],
    roster: &[String],
    policy: Option<ReverseQuorumPolicy>,
    now: DateTime<Utc>,
) -> ReverseQuorumFold {
    let Some(policy) = policy else {
        return ReverseQuorumFold {
            standing: ReverseQuorumStanding::NotGoverned,
            policy: None,
            distinct_objectors: 0,
            required: 0,
            roster_size: roster.len(),
            window_opens_at: action.asserted_at,
            window_closes_at: action.asserted_at,
            window_open: false,
            counted_objection_ids: Vec::new(),
            dismissed_objection_ids: Vec::new(),
        };
    };

    let (opens, closes) = policy.window(action.asserted_at);
    let required = policy.reversal_threshold(roster.len());

    // Which objections has a (pre-verified) dismissal named?
    let mut dismissed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for d in dismissals {
        if envelope_str(d, "dimension") != Some(DIMENSION_DISMISSAL) {
            continue;
        }
        if let Some(id) = envelope_str(d, field::DISMISSES) {
            dismissed.insert(id.to_owned());
        }
    }

    let mut counted_ids: Vec<String> = Vec::new();
    let mut objectors: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    let mut dismissed_ids: Vec<String> = Vec::new();
    for o in objections {
        if envelope_str(o, "dimension") != Some(DIMENSION_OBJECTION) {
            continue;
        }
        if envelope_str(o, field::OBJECTS_TO) != Some(action.attestation_id.as_str()) {
            continue;
        }
        if !roster.iter().any(|k| k == &o.attesting_key_id) {
            continue;
        }
        if o.asserted_at < opens || o.asserted_at > closes {
            continue;
        }
        if dismissed.contains(&o.attestation_id) {
            dismissed_ids.push(o.attestation_id.clone());
            continue;
        }
        // DISTINCT objectors — one member is one objection, however many rows
        // that member authored.
        if objectors.insert(o.attesting_key_id.as_str()) {
            counted_ids.push(o.attestation_id.clone());
        }
    }
    counted_ids.sort();
    dismissed_ids.sort();

    let window_open = now >= opens && now <= closes;
    let standing = if objectors.len() >= required {
        ReverseQuorumStanding::Reversed
    } else if window_open {
        ReverseQuorumStanding::WindowOpen
    } else {
        ReverseQuorumStanding::Stood
    };

    ReverseQuorumFold {
        standing,
        policy: Some(policy.to_protocol_string()),
        distinct_objectors: objectors.len(),
        required,
        roster_size: roster.len(),
        window_opens_at: opens,
        window_closes_at: closes,
        window_open,
        counted_objection_ids: counted_ids,
        dismissed_objection_ids: dismissed_ids,
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Envelope builders — one shape, producer side and persist side
// ─────────────────────────────────────────────────────────────────────────

/// Build the canonical envelope of an **objection**. Defined here so a
/// producer and this node's fold agree byte-for-byte about where the
/// references live.
#[must_use]
pub fn objection_envelope(
    cohort: Cohort,
    cohort_key_id: &str,
    action_attestation_id: &str,
    grounds: &str,
) -> serde_json::Value {
    serde_json::json!({
        "dimension": DIMENSION_OBJECTION,
        field::COHORT: cohort.as_str(),
        field::COHORT_KEY_ID: cohort_key_id,
        field::OBJECTS_TO: action_attestation_id,
        field::GROUNDS: grounds,
    })
}

/// Build the canonical envelope of a **dismissal**. Every co-signer signs
/// THESE bytes; [`record_objection_dismissal`] counts distinct roster members
/// whose signature over them verifies.
#[must_use]
pub fn dismissal_envelope(
    cohort: Cohort,
    cohort_key_id: &str,
    action_attestation_id: &str,
    objection_attestation_id: &str,
    grounds: &str,
) -> serde_json::Value {
    serde_json::json!({
        "dimension": DIMENSION_DISMISSAL,
        field::COHORT: cohort.as_str(),
        field::COHORT_KEY_ID: cohort_key_id,
        field::OBJECTS_TO: action_attestation_id,
        field::DISMISSES: objection_attestation_id,
        field::GROUNDS: grounds,
    })
}

/// Read a string field off a row's envelope.
fn envelope_str<'a>(row: &'a Attestation, key: &str) -> Option<&'a str> {
    row.attestation_envelope.get(key)?.as_str()
}

/// Parse a cohort token back to [`Cohort`]. `self` is rejected: the `self`
/// cohort has no roster to be a quorum over (its "members" are one identity's
/// own devices), so it has no commons to police.
fn parse_cohort(token: &str) -> Option<Cohort> {
    match token {
        "family" => Some(Cohort::Family),
        "community" => Some(Cohort::Community),
        "affiliations" => Some(Cohort::Affiliations),
        _ => None,
    }
}

/// The `(cohort, cohort_key_id)` an objection/dismissal names, from its own
/// envelope.
fn envelope_cohort(row: &Attestation) -> Option<(Cohort, String)> {
    let cohort = parse_cohort(envelope_str(row, field::COHORT)?)?;
    let key = envelope_str(row, field::COHORT_KEY_ID)?;
    if key.is_empty() {
        return None;
    }
    Some((cohort, key.to_owned()))
}

// ─────────────────────────────────────────────────────────────────────────
//  Shared primitives
// ─────────────────────────────────────────────────────────────────────────

/// The cohort's live (revocation-folded) roster and its parsed reverse-quorum
/// policy, BOTH re-derived from this node's own stored state (#377).
///
/// `Ok(None)` when the group does not resolve here.
async fn cohort_state<F>(
    directory: &F,
    cohort: Cohort,
    cohort_key_id: &str,
) -> Result<Option<(Vec<String>, Option<ReverseQuorumPolicy>)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let group = match directory.lookup_group(cohort, cohort_key_id).await {
        Ok(Some(g)) => g,
        Ok(None) => return Ok(None),
        Err(Error::Unsupported { .. }) => return Ok(None),
        Err(e) => return Err(e),
    };
    let policy = group
        .consensus_protocol
        .as_deref()
        .and_then(ReverseQuorumPolicy::parse);
    let roster: Vec<String> = match directory.active_members(cohort, cohort_key_id).await {
        Ok(members) => members.into_iter().map(|m| m.key_id).collect(),
        Err(Error::Unsupported { .. }) => Vec::new(),
        Err(e) => return Err(e),
    };
    Ok(Some((roster, policy)))
}

/// v24.3.0 (CIRISPersist#574) — how many DISTINCT members of `roster` really
/// signed `row`?
///
/// The row's FULL scrub set ([`Attestation::scrubs`] — the base
/// `scrub_key_id`/`scrub_signature_*` plus every `additional_scrubs` entry,
/// all over the SAME canonical envelope) intersected with `roster`, each
/// survivor hybrid-verified through
/// [`verify_envelope_hybrid_signature`](super::tier_ingest::verify_envelope_hybrid_signature)
/// against pubkeys resolved from THIS node's directory. Never the roster a
/// caller passed on the row, never pubkeys carried on the row.
///
/// A scrub that is not a roster member, or that does not verify, simply does
/// not COUNT — it is not an error. That is the m-of-n discipline the key plane
/// already uses, and it means a stray co-signature degrades the evidence
/// rather than destroying the row.
///
/// **One predicate, one implementation.** This is the body
/// [`trust_root`](super::trust_root)'s `family_quorum_over` runs for the
/// charter plane; it was lifted here rather than copied so the two planes
/// cannot drift on what "a distinct verified co-signature" means.
pub(crate) async fn count_distinct_roster_scrubs<F>(
    directory: &F,
    envelope: &serde_json::Value,
    scrubs: &[super::types::ScrubSig],
    roster: &[String],
) -> std::collections::BTreeSet<String>
where
    F: FederationDirectory + ?Sized,
{
    let mut counted: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for scrub in scrubs {
        if counted.contains(&scrub.scrub_key_id) || !roster.iter().any(|k| k == &scrub.scrub_key_id)
        {
            continue;
        }
        if super::verify_envelope_hybrid_signature(
            directory,
            &scrub.scrub_key_id,
            envelope,
            &scrub.scrub_signature_classical,
            scrub.scrub_signature_pqc.as_deref(),
        )
        .await
        .is_ok()
        {
            counted.insert(scrub.scrub_key_id.clone());
        }
    }
    counted
}

// ─────────────────────────────────────────────────────────────────────────
//  The two admission doors
// ─────────────────────────────────────────────────────────────────────────

/// **The protective door — 1-of-N.** Admit and store one member's objection.
///
/// Verify-before-mutation: every gate below runs BEFORE any row is written, and
/// a refusal writes nothing.
///
/// The threshold applied here is [`OBJECTION_THRESHOLD`] — one. There is no
/// count, no quorum, and no co-signature requirement, on purpose: protection
/// must be cheap and unilateral or it is not protection. What IS checked is
/// that the objector is genuinely a member of the cohort whose commons this
/// is, that the action objected to is a row this node actually holds, and that
/// the objection's own signature verifies. Everything else about it —
/// including whether the grounds are any good — is the reader's business, not
/// the substrate's.
///
/// # A LATE objection is stored, not refused
///
/// There is deliberately no `WindowClosed` refusal. A node cannot distinguish
/// an objection authored late from one delivered late after a partition, and
/// throwing away the second kind is how a partitioned member loses their voice
/// entirely. The row is stored either way and
/// [`fold_reverse_quorum`] — the one place counting happens — excludes it from
/// the count by its `asserted_at`. Store everything, count carefully.
pub async fn record_objection<F>(
    directory: &F,
    objection: &Attestation,
) -> Result<ObjectionOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let refused = |reason: ObjectionRefusalReason| Ok(ObjectionOutcome::Refused { reason });

    if envelope_str(objection, "dimension") != Some(DIMENSION_OBJECTION) {
        return refused(ObjectionRefusalReason::DimensionMismatch);
    }
    let Some((cohort, cohort_key_id)) = envelope_cohort(objection) else {
        return refused(ObjectionRefusalReason::MalformedEnvelope);
    };
    let Some(action_id) = envelope_str(objection, field::OBJECTS_TO).map(str::to_owned) else {
        return refused(ObjectionRefusalReason::MalformedEnvelope);
    };
    if action_id.is_empty() {
        return refused(ObjectionRefusalReason::MalformedEnvelope);
    }

    let Some((roster, policy)) = cohort_state(directory, cohort, &cohort_key_id).await? else {
        return refused(ObjectionRefusalReason::CohortUnknown);
    };
    if policy.is_none() {
        return refused(ObjectionRefusalReason::NotGoverned);
    }

    // ── THE 1-of-N GATE, in full. One member is enough; a non-member is not.
    if !roster.iter().any(|k| k == &objection.attesting_key_id) {
        return refused(ObjectionRefusalReason::NotACohortMember);
    }

    // The objected-to row must be held here, or the objection names nothing
    // this node can fold.
    let Some(action) = directory.get_attestation(&action_id).await? else {
        return refused(ObjectionRefusalReason::TargetActionUnknown);
    };
    // The row must be FILED where the fold looks for it (see
    // `objections_against`), or it would be stored and never counted.
    if objection.attested_key_id != action.attesting_key_id {
        return refused(ObjectionRefusalReason::NotFiledAgainstActor);
    }

    // The objector's own signature, re-verified against pubkeys resolved from
    // this node's directory.
    if super::verify_envelope_hybrid_signature(
        directory,
        &objection.attesting_key_id,
        &objection.attestation_envelope,
        &objection.scrub_signature_classical,
        objection.scrub_signature_pqc.as_deref(),
    )
    .await
    .is_err()
    {
        return refused(ObjectionRefusalReason::UnverifiableSignature);
    }

    // One member, one objection (the fold counts distinct objectors anyway —
    // this keeps the corpus honest rather than being the safety property).
    //
    // Scoped to OBJECTION rows specifically. `objections_against` returns both
    // dimensions, and matching on the author alone would refuse an objection
    // from anyone who had previously authored a DISMISSAL against this action —
    // i.e. it would silently take the brake away from a member for having once
    // helped lift it. That is the wrong direction on the one axis this module
    // may not get wrong.
    for held in objections_against(directory, &action).await? {
        if envelope_str(&held, "dimension") == Some(DIMENSION_OBJECTION)
            && held.attesting_key_id == objection.attesting_key_id
            && held.attestation_id != objection.attestation_id
        {
            return refused(ObjectionRefusalReason::DuplicateObjection);
        }
    }

    directory
        .put_attestation(super::SignedAttestation {
            attestation: objection.clone(),
        })
        .await?;
    Ok(ObjectionOutcome::Admitted)
}

/// **The undo door — m-of-n.** Admit and store a dismissal of one objection.
///
/// A dismissal removes protection, so it costs
/// [`ReverseQuorumPolicy::dismissal_threshold`] distinct roster members
/// co-signing the SAME canonical [`dismissal_envelope`] — counted through
/// [`count_distinct_roster_scrubs`], i.e. re-verified against this node's
/// registered pubkeys. A quorum-short dismissal is REFUSED with
/// [`ObjectionRefusalReason::DismissalQuorumShort`] and the returned
/// [`DismissalQuorum`] names the shortfall (`counted` / `required` /
/// `roster_size`), so the caller learns how far short they were rather than
/// merely that something said no.
///
/// This is NOT "objecting to the objection" — deliberately out of scope, one
/// level only.
///
/// # Self-retraction is free
///
/// When the dismissal's author IS the objection's author, the threshold is
/// [`OBJECTION_THRESHOLD`] — one, their own signature. Dropping your own
/// protection is cheap by exactly the construction that makes raising it cheap,
/// and it takes nothing away from anyone else. See [`dismissal_required`],
/// which both this door and [`resolve_reverse_quorum`] read.
pub async fn record_objection_dismissal<F>(
    directory: &F,
    dismissal: &Attestation,
) -> Result<DismissalDecision, Error>
where
    F: FederationDirectory + ?Sized,
{
    let empty = DismissalQuorum {
        counted: 0,
        required: 0,
        roster_size: 0,
    };
    let refuse = |reason: ObjectionRefusalReason, quorum: DismissalQuorum| DismissalDecision {
        outcome: ObjectionOutcome::Refused { reason },
        quorum,
    };

    if envelope_str(dismissal, "dimension") != Some(DIMENSION_DISMISSAL) {
        return Ok(refuse(ObjectionRefusalReason::DimensionMismatch, empty));
    }
    let Some((cohort, cohort_key_id)) = envelope_cohort(dismissal) else {
        return Ok(refuse(ObjectionRefusalReason::MalformedEnvelope, empty));
    };
    let Some(objection_id) = envelope_str(dismissal, field::DISMISSES).map(str::to_owned) else {
        return Ok(refuse(ObjectionRefusalReason::MalformedEnvelope, empty));
    };

    let Some((roster, policy)) = cohort_state(directory, cohort, &cohort_key_id).await? else {
        return Ok(refuse(ObjectionRefusalReason::CohortUnknown, empty));
    };
    let Some(policy) = policy else {
        return Ok(refuse(
            ObjectionRefusalReason::NotGoverned,
            DismissalQuorum {
                counted: 0,
                required: 0,
                roster_size: roster.len(),
            },
        ));
    };
    // Resolve the objection FIRST — whether this is a self-retraction (cheap)
    // or an undo of somebody else's protection (m-of-n) is a property of the
    // objection's author, not of anything the dismissal claims about itself.
    //
    // It must be an OBJECTION row, not merely some row this node holds: the
    // read-time re-derivation resolves `self_dismissal` against the objection
    // set, so admitting on a laxer test than the one the fold applies would let
    // a dismissal be admitted at 1 and then silently re-priced at m-of-n on
    // every subsequent read. Same test both sides, or the two disagree.
    let named = directory.get_attestation(&objection_id).await?;
    let Some(objection) = named.filter(|row| {
        envelope_str(row, "dimension") == Some(DIMENSION_OBJECTION)
            && envelope_str(row, field::OBJECTS_TO) == envelope_str(dismissal, field::OBJECTS_TO)
    }) else {
        return Ok(refuse(
            ObjectionRefusalReason::ObjectionUnknown,
            DismissalQuorum {
                counted: 0,
                required: policy.dismissal_threshold(roster.len()),
                roster_size: roster.len(),
            },
        ));
    };
    if dismissal.attested_key_id != objection.attested_key_id {
        return Ok(refuse(
            ObjectionRefusalReason::NotFiledAgainstActor,
            DismissalQuorum {
                counted: 0,
                required: policy.dismissal_threshold(roster.len()),
                roster_size: roster.len(),
            },
        ));
    }
    let self_dismissal = objection.attesting_key_id == dismissal.attesting_key_id;
    let required = dismissal_required(&policy, roster.len(), self_dismissal);

    // ── THE m-of-n GATE. Distinct roster members, each signature re-verified
    //    against pubkeys resolved from this node's own directory.
    let counted = count_distinct_roster_scrubs(
        directory,
        &dismissal.attestation_envelope,
        &dismissal.scrubs(),
        &roster,
    )
    .await;
    let quorum = DismissalQuorum {
        counted: counted.len(),
        required,
        roster_size: roster.len(),
    };
    if quorum.counted < quorum.required {
        return Ok(refuse(ObjectionRefusalReason::DismissalQuorumShort, quorum));
    }

    directory
        .put_attestation(super::SignedAttestation {
            attestation: dismissal.clone(),
        })
        .await?;
    Ok(DismissalDecision {
        outcome: ObjectionOutcome::Admitted,
        quorum,
    })
}

// ─────────────────────────────────────────────────────────────────────────
//  The read-time answer
// ─────────────────────────────────────────────────────────────────────────

/// Every objection/dismissal row this node holds that is keyed on `action`'s
/// author. Objections and dismissals both carry
/// `attested_key_id = action.attesting_key_id` (the actor whose action is
/// under objection), so ONE existing read serves both.
async fn objections_against<F>(
    directory: &F,
    action: &Attestation,
) -> Result<Vec<Attestation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let rows = match directory
        .list_attestations_for(&action.attesting_key_id)
        .await
    {
        Ok(rows) => rows,
        Err(Error::Unsupported { .. }) => Vec::new(),
        Err(e) => return Err(e),
    };
    Ok(rows
        .into_iter()
        .filter(|r| {
            matches!(
                envelope_str(r, "dimension"),
                Some(DIMENSION_OBJECTION) | Some(DIMENSION_DISMISSAL)
            ) && envelope_str(r, field::OBJECTS_TO) == Some(action.attestation_id.as_str())
        })
        .collect())
}

/// **The read-time answer** — what `cohort`'s reverse quorum says about
/// `action`, folded from the rows this node holds right now.
///
/// The only supported public entry point, because it is the one that supplies
/// [`fold_reverse_quorum`] with a QUORUM-VERIFIED dismissal list: each held
/// dismissal is re-counted through [`count_distinct_roster_scrubs`] here and
/// dropped if it no longer clears
/// [`ReverseQuorumPolicy::dismissal_threshold`]. That re-check is not
/// redundant with [`record_objection_dismissal`]'s — a dismissal admitted
/// against a five-member roster STOPS clearing a grown roster's strict
/// majority, and the protection it removed comes back. Authority is re-derived
/// at read time on every plane in this repo, and the undo side is exactly
/// where that matters most.
///
/// Persist mutates nothing here.
pub async fn resolve_reverse_quorum<F>(
    directory: &F,
    cohort: Cohort,
    cohort_key_id: &str,
    action: &Attestation,
    now: DateTime<Utc>,
) -> Result<ReverseQuorumFold, Error>
where
    F: FederationDirectory + ?Sized,
{
    let (roster, policy) = cohort_state(directory, cohort, cohort_key_id)
        .await?
        .unwrap_or_else(|| (Vec::new(), None));
    let rows = objections_against(directory, action).await?;

    let (dismissal_rows, objection_rows): (Vec<Attestation>, Vec<Attestation>) = rows
        .into_iter()
        .partition(|r| envelope_str(r, "dimension") == Some(DIMENSION_DISMISSAL));

    // Re-derive each dismissal's threshold against the LIVE roster before it is
    // allowed to suppress an objection. The self-retraction case is resolved
    // the same way the admission door resolves it — from the OBJECTION's
    // author, through the shared `dismissal_required` — so a stored dismissal
    // means the same thing at read time as it did when it was admitted.
    let mut verified_dismissals: Vec<Attestation> = Vec::new();
    if let Some(policy) = policy {
        for d in dismissal_rows {
            let self_dismissal = envelope_str(&d, field::DISMISSES).is_some_and(|oid| {
                objection_rows
                    .iter()
                    .any(|o| o.attestation_id == oid && o.attesting_key_id == d.attesting_key_id)
            });
            let required = dismissal_required(&policy, roster.len(), self_dismissal);
            let counted = count_distinct_roster_scrubs(
                directory,
                &d.attestation_envelope,
                &d.scrubs(),
                &roster,
            )
            .await;
            if counted.len() >= required {
                verified_dismissals.push(d);
            }
        }
    }

    Ok(fold_reverse_quorum(
        action,
        &objection_rows,
        &verified_dismissals,
        &roster,
        policy,
        now,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(m: u32, n: u32, w: u64) -> ReverseQuorumPolicy {
        ReverseQuorumPolicy {
            m,
            n,
            window_secs: w,
        }
    }

    #[test]
    fn the_objection_form_parses_and_round_trips() {
        let p = ReverseQuorumPolicy::parse("reverse_quorum:2/5:86400").expect("parses");
        assert_eq!((p.m, p.n, p.window_secs), (2, 5, 86400));
        assert_eq!(p.to_protocol_string(), "reverse_quorum:2/5:86400");
        // And the vocabulary gate admits exactly what the fold can evaluate.
        assert!(super::super::types::consensus_protocol::is_canonical_form(
            "reverse_quorum:2/5:86400"
        ));
    }

    #[test]
    fn degenerate_reverse_quorum_forms_are_refused_by_the_one_parse_door() {
        use super::super::types::consensus_protocol::is_canonical_form;
        for bad in [
            // m == 0 — "reversed by zero objections" is approve-to-act in
            // disguise; the action would never really land.
            "reverse_quorum:0/3:60",
            "reverse_quorum:4/3:60",  // m > n
            "reverse_quorum:2/0:60",  // n == 0
            "reverse_quorum:2/3",     // no window
            "reverse_quorum:2/3:",    // empty window
            "reverse_quorum:2/3:abc", // non-numeric window
            "reverse_quorum:x/3:60",
            "reverse_quorum:",
        ] {
            assert!(
                ReverseQuorumPolicy::parse(bad).is_none(),
                "{bad} must not parse"
            );
            assert!(
                !is_canonical_form(bad),
                "{bad} must not pass the consensus_protocol shape gate either — one \
                 parse door, so the gate can never admit a string the fold cannot read"
            );
        }
        // A window of 0 IS legal: "no grace" is a coherent declaration.
        assert!(ReverseQuorumPolicy::parse("reverse_quorum:1/1:0").is_some());
    }

    /// THE property this module exists to hold. Over every roster size and
    /// every declared `m`, protection must never cost more than undoing it.
    #[test]
    fn the_asymmetry_holds_for_every_roster() {
        for roster in 0usize..=12 {
            for m in 1u32..=12 {
                let p = policy(m, m.max(1), 3600);
                let reversal = p.reversal_threshold(roster);
                let dismissal = p.dismissal_threshold(roster);
                assert!(
                    OBJECTION_THRESHOLD <= reversal,
                    "raising the brake (1) must never cost more than reversing \
                     (roster={roster}, m={m}, reversal={reversal})"
                );
                assert!(
                    reversal <= dismissal,
                    "undoing protection must never be cheaper than applying it \
                     (roster={roster}, m={m}, reversal={reversal}, dismissal={dismissal})"
                );
                // The ordering alone is NOT enough — flooring BOTH sides at a
                // strict majority preserves it while quietly making the brake
                // as expensive as the undo. Caught in a mutation run; pinned
                // here as an exact equality so the protective side can only be
                // the declared `m`, capped.
                assert_eq!(
                    reversal,
                    (m as usize).min(roster.max(1)),
                    "the protective side is the DECLARED m, capped at the roster \
                     and floored at nothing (roster={roster}, m={m})"
                );
                // The undo side is floored at a strict majority — a policy
                // string can never talk it down.
                assert!(
                    dismissal >= ciris_verify_core::accord_genesis::strict_majority(roster).max(1),
                    "dismissal must never fall below a strict majority \
                     (roster={roster}, m={m}, dismissal={dismissal})"
                );
            }
        }
    }

    /// The single most dangerous edit this module can suffer: flooring the
    /// PROTECTIVE side at a strict majority "for symmetry".
    ///
    /// A community declaring `reverse_quorum:2/9` means TWO. Flooring reversal
    /// at a strict majority would make the brake five times harder to pull
    /// than the community declared, which at mesh scale is indistinguishable
    /// from having no brake — the response would land after the harm, which is
    /// the exact failure #574 exists to close. A mutation run proved the
    /// ordering assertion alone does not catch it (floor both sides and
    /// `reversal <= dismissal` still holds), so it is pinned separately.
    #[test]
    fn the_protective_side_is_never_floored_at_a_strict_majority() {
        let p = policy(2, 9, 3600);
        let majority = ciris_verify_core::accord_genesis::strict_majority(9);
        assert_eq!(p.reversal_threshold(9), 2, "two means two");
        assert!(
            p.reversal_threshold(9) < majority,
            "the protective side must be allowed BELOW a strict majority"
        );
        // …while the undo side is floored at exactly that majority.
        assert_eq!(p.dismissal_threshold(9), majority);
        assert_eq!(majority, 5);
    }

    /// Self-retraction is ONE; dismissing somebody else's is the floored
    /// m-of-n. The two prices come from one function so the admission door and
    /// the read-time re-derivation can never disagree about whether a stored
    /// dismissal still stands.
    #[test]
    fn dropping_your_own_protection_costs_one_and_nobody_elses_does() {
        let p = policy(2, 9, 3600);
        assert_eq!(dismissal_required(&p, 9, true), OBJECTION_THRESHOLD);
        assert_eq!(dismissal_required(&p, 9, true), 1);
        assert_eq!(dismissal_required(&p, 9, false), 5);
        // And the cheap price does not leak into the expensive one at any
        // roster size — the ONLY thing that buys 1 is being the objection's
        // own author.
        for roster in 1usize..=12 {
            assert_eq!(dismissal_required(&p, roster, true), 1);
            assert_eq!(
                dismissal_required(&p, roster, false),
                p.dismissal_threshold(roster)
            );
        }
    }

    #[test]
    fn a_shrunken_roster_caps_reversal_but_never_floors_it() {
        // Declared 4-of-7; three members left. Reversal must stay REACHABLE
        // (capped at 3), or the brake would silently disarm itself.
        let p = policy(4, 7, 3600);
        assert_eq!(p.reversal_threshold(3), 3);
        // And the undo side still demands a strict majority of what is left,
        // floored by the declared m: max(4, 2) = 4 — unreachable on a roster
        // of 3, which is the FAIL-SECURE direction (protection sticks).
        assert_eq!(p.dismissal_threshold(3), 4);
    }

    #[test]
    fn refusal_reason_tokens_match_serde_and_are_unique() {
        for reason in ObjectionRefusalReason::ALL {
            let json = serde_json::to_string(reason).expect("serialize");
            assert_eq!(
                json,
                format!("\"{}\"", reason.as_str()),
                "the serde token and the program token are ONE spelling"
            );
            let back: ObjectionRefusalReason = serde_json::from_str(&json).expect("round-trip");
            assert_eq!(back, *reason);
            assert_eq!(reason.to_string(), reason.as_str());
        }
        let tokens: std::collections::BTreeSet<&str> = ObjectionRefusalReason::ALL
            .iter()
            .map(|r| r.as_str())
            .collect();
        assert_eq!(
            tokens.len(),
            ObjectionRefusalReason::ALL.len(),
            "every refusal branch has its OWN token — a shared token is the \
             disjunction #565 was filed to end, one name deeper"
        );
    }

    /// A NEW vocabulary form must not weaken an EXISTING threshold reader.
    /// `family_charter_threshold` reads `consensus_protocol` for the v24.0.0
    /// trust-root charter; a `reverse_quorum:*` string is not a forward
    /// threshold, so it must read as unanimity there, never as `m`.
    #[test]
    fn the_new_form_reads_fail_secure_on_the_forward_threshold_plane() {
        // `family_charter_threshold` is private; its rule is
        // "unrecognised policy ⇒ roster_size" via `genesis::bundle::parse_quorum`,
        // which is the function that decides recognition. Assert THAT: the new
        // form is not a `quorum:M/N`, so the charter plane cannot read a 2 out
        // of `reverse_quorum:2/9:86400` and admit a 2-of-9 charter.
        assert!(
            super::super::genesis::bundle::parse_quorum("reverse_quorum:2/9:86400").is_none(),
            "the forward-threshold parser must NOT read the reverse form — it \
             would turn a 2-of-9 BRAKE into a 2-of-9 charter quorum"
        );
    }

    fn row(
        id: &str,
        author: &str,
        envelope: serde_json::Value,
        asserted_at: DateTime<Utc>,
    ) -> Attestation {
        Attestation {
            attestation_id: id.into(),
            attesting_key_id: author.into(),
            attested_key_id: "actor".into(),
            attestation_type: super::super::types::attestation_type::SCORES.into(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: author.into(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".into(),
            tier: super::super::types::attestation_tier::FEDERATION.into(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    fn action_row(at: DateTime<Utc>) -> Attestation {
        row(
            "action-1",
            "actor",
            serde_json::json!({"dimension": "testimonial_witness:commons_act:v1"}),
            at,
        )
    }

    fn objection(id: &str, author: &str, at: DateTime<Utc>) -> Attestation {
        row(
            id,
            author,
            objection_envelope(Cohort::Community, "c1", "action-1", "grounds"),
            at,
        )
    }

    #[test]
    fn one_member_cannot_reach_the_reversal_threshold_alone() {
        let t0: DateTime<Utc> = "2026-08-02T00:00:00Z".parse().unwrap();
        let action = action_row(t0);
        let roster: Vec<String> = ["a", "b", "c"].iter().map(|s| (*s).to_string()).collect();
        // `a` files THREE objections. The fold counts DISTINCT objectors, so
        // this is one — otherwise a single member would hold the whole
        // reverse quorum, which is the 1-of-N capability grant the doctrine
        // forbids.
        let objections = vec![
            objection("o1", "a", t0),
            objection("o2", "a", t0),
            objection("o3", "a", t0),
        ];
        let f = fold_reverse_quorum(
            &action,
            &objections,
            &[],
            &roster,
            Some(policy(2, 3, 3600)),
            t0,
        );
        assert_eq!(f.distinct_objectors, 1);
        assert_eq!(f.required, 2);
        assert_eq!(f.standing, ReverseQuorumStanding::WindowOpen);
        assert_eq!(f.counted_objection_ids, vec!["o1".to_string()]);
    }

    #[test]
    fn m_distinct_members_reverse_and_the_fold_names_its_evidence() {
        let t0: DateTime<Utc> = "2026-08-02T00:00:00Z".parse().unwrap();
        let action = action_row(t0);
        let roster: Vec<String> = ["a", "b", "c"].iter().map(|s| (*s).to_string()).collect();
        let objections = vec![objection("o1", "a", t0), objection("o2", "b", t0)];
        let f = fold_reverse_quorum(
            &action,
            &objections,
            &[],
            &roster,
            Some(policy(2, 3, 3600)),
            t0,
        );
        assert_eq!(f.standing, ReverseQuorumStanding::Reversed);
        assert_eq!(f.counted_objection_ids, vec!["o1".to_string(), "o2".into()]);
    }

    #[test]
    fn a_non_member_objection_is_never_counted_and_late_ones_miss_the_window() {
        let t0: DateTime<Utc> = "2026-08-02T00:00:00Z".parse().unwrap();
        let action = action_row(t0);
        let roster: Vec<String> = ["a", "b", "c"].iter().map(|s| (*s).to_string()).collect();
        let late = t0 + Duration::seconds(3601);
        let objections = vec![
            objection("o1", "a", t0),
            objection("o2", "stranger", t0), // not on the roster
            objection("o3", "b", late),      // after the window closed
        ];
        let f = fold_reverse_quorum(
            &action,
            &objections,
            &[],
            &roster,
            Some(policy(2, 3, 3600)),
            late,
        );
        assert_eq!(f.distinct_objectors, 1);
        assert!(!f.window_open);
        assert_eq!(f.standing, ReverseQuorumStanding::Stood);
    }

    #[test]
    fn a_verified_dismissal_removes_protection_and_the_fold_says_which() {
        let t0: DateTime<Utc> = "2026-08-02T00:00:00Z".parse().unwrap();
        let action = action_row(t0);
        let roster: Vec<String> = ["a", "b", "c"].iter().map(|s| (*s).to_string()).collect();
        let objections = vec![objection("o1", "a", t0), objection("o2", "b", t0)];
        let dismissal = row(
            "d1",
            "a",
            dismissal_envelope(Cohort::Community, "c1", "action-1", "o1", "resolved"),
            t0,
        );
        let f = fold_reverse_quorum(
            &action,
            &objections,
            &[dismissal],
            &roster,
            Some(policy(2, 3, 3600)),
            t0,
        );
        assert_eq!(f.distinct_objectors, 1);
        assert_eq!(f.standing, ReverseQuorumStanding::WindowOpen);
        assert_eq!(f.dismissed_objection_ids, vec!["o1".to_string()]);
    }

    #[test]
    fn an_ungoverned_cohort_folds_to_not_governed_rather_than_a_guessed_window() {
        let t0: DateTime<Utc> = "2026-08-02T00:00:00Z".parse().unwrap();
        let action = action_row(t0);
        let roster: Vec<String> = ["a", "b"].iter().map(|s| (*s).to_string()).collect();
        let f = fold_reverse_quorum(&action, &[objection("o1", "a", t0)], &[], &roster, None, t0);
        assert_eq!(f.standing, ReverseQuorumStanding::NotGoverned);
        assert_eq!(f.required, 0);
        assert!(f.policy.is_none());
    }

    /// A partitioned node sees the action but not the objections. It must
    /// converge on the SAME answer once they arrive — even long after the
    /// window closed. That is why the window is pinned to the ACTION and the
    /// fold is evaluated at read time.
    #[test]
    fn objections_arriving_after_the_window_still_reverse_the_action() {
        let t0: DateTime<Utc> = "2026-08-02T00:00:00Z".parse().unwrap();
        let action = action_row(t0);
        let roster: Vec<String> = ["a", "b", "c"].iter().map(|s| (*s).to_string()).collect();
        let p = Some(policy(2, 3, 3600));
        // In-window objections, folded a WEEK later on a node that only just
        // received them.
        let objections = vec![
            objection("o1", "a", t0 + Duration::seconds(10)),
            objection("o2", "b", t0 + Duration::seconds(20)),
        ];
        let much_later = t0 + Duration::days(7);
        let f = fold_reverse_quorum(&action, &objections, &[], &roster, p, much_later);
        assert!(!f.window_open, "the window is long closed");
        assert_eq!(
            f.standing,
            ReverseQuorumStanding::Reversed,
            "a late-arriving in-window objection set still reverses — the fold \
             is a function of the rows, never of when this node saw them"
        );
    }
}

/// The #574 behavioural witness, run by the sqlite / postgres / memory suites
/// against `&dyn FederationDirectory` so the three backends cannot silently
/// diverge on the reverse-quorum plane (the same discipline
/// [`super::load_bearing::test_support::exercise_load_bearing_predicate`]
/// runs). `suffix` scopes every fixture key so a run against a shared postgres
/// test DB does not collide with a prior one.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod test_support {
    use super::*;
    use crate::federation::tier_ingest::test_support::{hybrid_pubkeys, sign_envelope};
    use crate::federation::types::{attestation_tier, attestation_type, CommunityMember};
    use crate::federation::{Community, SignedAttestation};

    /// Register `key_id` as a **`user`**-role identity carrying its real
    /// deterministic hybrid pubkeys.
    ///
    /// `user` rather than the usual `agent` for a load-bearing reason, not a
    /// cosmetic one: a community's roster members must be steward-bound
    /// (CC 3.2) and the community must have a live named moderator (§11.11)
    /// before `put_community` / a federation-tier apply keyed on it will
    /// admit. A `user`-role key satisfies both structurally, so the witness
    /// exercises the reverse-quorum gates rather than fighting the community
    /// gates that guard them.
    async fn register_user_key<D: FederationDirectory + ?Sized>(dir: &D, key_id: &str) {
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        let now = Utc::now();
        dir.put_public_key(crate::federation::SignedKeyRecord {
            record: crate::federation::KeyRecord {
                key_id: key_id.to_owned(),
                pubkey_ed25519_base64: ed_pk,
                pubkey_ml_dsa_65_base64: mldsa_pk,
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: crate::federation::types::identity_type::USER.to_owned(),
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
        .expect("register user key");
    }

    /// A federation-tier row carrying `envelope`, authored + scrubbed by
    /// `author`, about `subject`. `co_signers` add REAL additional scrubs over
    /// the SAME canonical envelope — the m-of-n input.
    fn signed_row(
        id: &str,
        author: &str,
        subject: &str,
        envelope: serde_json::Value,
        asserted_at: DateTime<Utc>,
        co_signers: &[&str],
    ) -> Attestation {
        let (och, ed_sig, pqc_sig) = sign_envelope(author, &envelope);
        let additional_scrubs = co_signers
            .iter()
            .map(|k| {
                let (_h, c, p) = sign_envelope(k, &envelope);
                crate::federation::types::ScrubSig {
                    scrub_key_id: (*k).to_owned(),
                    scrub_signature_classical: c,
                    scrub_signature_pqc: p,
                }
            })
            .collect();
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: author.to_owned(),
            attested_key_id: subject.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: author.to_owned(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs,
        }
    }

    /// Seed a `reverse_quorum:2/3:3600` community over `members`, plus a
    /// commons action authored by `actor`. Returns the action row.
    async fn seed<D: FederationDirectory + ?Sized>(
        dir: &D,
        community_key_id: &str,
        actor: &str,
        members: &[String],
        action_id: &str,
        protocol: &str,
    ) -> Attestation {
        let now = Utc::now();
        let community = Community {
            community_key_id: community_key_id.to_owned(),
            community_name: format!("commons {community_key_id}"),
            members: members
                .iter()
                .enumerate()
                .map(|(i, k)| CommunityMember {
                    key_id: k.clone(),
                    joined_at: now,
                    role: Some(if i == 0 { "founder" } else { "member" }.to_owned()),
                })
                .collect(),
            founded_at: now,
            consensus_protocol: protocol.to_owned(),
            policy_blob: None,
            persist_row_hash: String::new(),
        };
        dir.put_community(
            crate::federation::tier_ingest::test_support::sign_community(&members[0], community),
        )
        .await
        .expect("put_community");

        // The commons action: a plain federation-tier row by the actor. It
        // takes effect on arrival — there is no approve-to-act gate, which is
        // the whole premise reverse quorum is the answer to.
        let action = signed_row(
            action_id,
            actor,
            actor,
            serde_json::json!({
                "dimension": "testimonial_witness:commons_act:v1",
                "payload": {"action": "the commons act under objection"},
            }),
            now,
            &[],
        );
        dir.put_attestation(SignedAttestation {
            attestation: action.clone(),
        })
        .await
        .expect("the commons action lands immediately — act-unless-objected");
        action
    }

    /// The #574 witness:
    ///
    /// 1. a SINGLE member's objection is admitted and visible (1-of-N);
    /// 2. a non-member's objection is REFUSED naming `not_a_cohort_member`;
    /// 3. a quorum-SHORT dismissal is REFUSED naming the shortfall;
    /// 4. a quorum-MET dismissal succeeds and the fold drops the objection;
    /// 5. `m` distinct members reverse the action, and persist mutated nothing;
    /// 6. the objection SURVIVES REPLICATION — the same signed row, applied to
    ///    a peer directory that never saw the objector's node, folds to the
    ///    same standing;
    /// 7. a dismissal STOPS counting when the roster it cleared grows past it,
    ///    and the protection it had lifted returns by itself;
    /// 8. a cohort that declared no `reverse_quorum:*` is refused, never
    ///    silently defaulted;
    /// 9. a member retracts their OWN objection with one signature on a roster
    ///    of nine, and every other member's objection is untouched.
    ///
    /// # Why the roster is FIVE and the policy is `2/5`
    ///
    /// A 3-member roster cannot witness the load-bearing asymmetry: strict
    /// majority of 3 is 2, so a `2/3` policy makes the protective and undo
    /// thresholds numerically identical and an edit that floors the PROTECTIVE
    /// side passes anyway (it did, in a mutation run). At five, `reverse_quorum
    /// :2/5` separates them — reversal 2, dismissal 3 — so the witness itself
    /// fails if reversal is ever floored at a strict majority.
    pub(crate) async fn exercise_reverse_quorum(dir: &dyn FederationDirectory, suffix: &str) {
        let alice = format!("rq-alice-{suffix}");
        let bob = format!("rq-bob-{suffix}");
        let carol = format!("rq-carol-{suffix}");
        let dave = format!("rq-dave-{suffix}");
        let erin = format!("rq-erin-{suffix}");
        let stranger = format!("rq-stranger-{suffix}");
        let actor = format!("rq-actor-{suffix}");
        let community = format!("rq-commons-{suffix}");
        let action_id = uuid::Uuid::new_v4().to_string();

        for k in [
            &alice, &bob, &carol, &dave, &erin, &stranger, &actor, &community,
        ] {
            register_user_key(dir, k).await;
        }
        let roster = vec![
            alice.clone(),
            bob.clone(),
            carol.clone(),
            dave.clone(),
            erin.clone(),
        ];
        let action = seed(
            dir,
            &community,
            &actor,
            &roster,
            &action_id,
            "reverse_quorum:2/5:3600",
        )
        .await;
        let now = Utc::now();
        let fold = |a: &Attestation| {
            let a = a.clone();
            let community = community.clone();
            async move {
                resolve_reverse_quorum(dir, Cohort::Community, &community, &a, Utc::now())
                    .await
                    .expect("resolve")
            }
        };

        // Nothing objected yet: the action stands, inside an open window.
        let f0 = fold(&action).await;
        assert_eq!(f0.standing, ReverseQuorumStanding::WindowOpen, "({suffix})");
        assert_eq!(f0.roster_size, 5, "({suffix})");
        assert_eq!(
            f0.required, 2,
            "({suffix}) TWO — the declared m, NOT the strict majority of 5. \
             The protective side is never floored; that is the whole doctrine."
        );

        // ── (1) ONE member objects. No quorum, no co-signature, no ceremony.
        let o1_id = uuid::Uuid::new_v4().to_string();
        let o1 = signed_row(
            &o1_id,
            &alice,
            &actor,
            objection_envelope(
                Cohort::Community,
                &community,
                &action_id,
                "harms the commons",
            ),
            now,
            &[],
        );
        assert_eq!(
            record_objection(dir, &o1).await.expect("record"),
            ObjectionOutcome::Admitted,
            "({suffix}) ONE member is the whole protective threshold"
        );
        let f1 = fold(&action).await;
        assert_eq!(f1.distinct_objectors, 1, "({suffix}) and it is VISIBLE");
        assert_eq!(f1.counted_objection_ids, vec![o1_id.clone()]);
        assert_eq!(f1.standing, ReverseQuorumStanding::WindowOpen);
        // The objected-to row is UNTOUCHED — evidence, never verdict.
        let held = dir
            .get_attestation(&action_id)
            .await
            .expect("read back")
            .expect("the action is still here");
        assert_eq!(
            held.original_content_hash, action.original_content_hash,
            "({suffix}) persist records an objection; it does not sentence the row"
        );

        // ── (2) A NON-member's objection is refused, naming the branch.
        let outsider = signed_row(
            &uuid::Uuid::new_v4().to_string(),
            &stranger,
            &actor,
            objection_envelope(Cohort::Community, &community, &action_id, "not my commons"),
            now,
            &[],
        );
        assert_eq!(
            record_objection(dir, &outsider)
                .await
                .expect("record")
                .refusal(),
            Some(ObjectionRefusalReason::NotACohortMember),
            "({suffix}) 1-of-N means one MEMBER, not one anybody"
        );

        // ── (2b) …and an objection filed against the WRONG key is refused
        //    rather than stored-and-never-counted. The fold finds objections
        //    through the action's author; a row filed anywhere else is inert
        //    forever, which is the failure mode that looks most like success.
        let misfiled = signed_row(
            &uuid::Uuid::new_v4().to_string(),
            &bob,
            &bob, // should be `actor`
            objection_envelope(Cohort::Community, &community, &action_id, "misfiled"),
            now,
            &[],
        );
        assert_eq!(
            record_objection(dir, &misfiled)
                .await
                .expect("record")
                .refusal(),
            Some(ObjectionRefusalReason::NotFiledAgainstActor),
            "({suffix}) a marker nobody can find is not a marker"
        );

        // ── (3) A quorum-SHORT dismissal of SOMEBODY ELSE'S objection. bob +
        //    carol try to lift alice's — which is ENOUGH to have reversed the
        //    action (m = 2) and NOT enough to lift one objection (strict
        //    majority of 5 = 3). That gap IS the asymmetry, priced in
        //    signatures. Refused, naming the shortfall.
        //
        //    Authored by BOB deliberately: alice lifting her OWN objection is
        //    free (step 9), and an earlier draft of this witness accidentally
        //    tested that instead — the numbers looked right and the property
        //    under test was absent.
        let d_short_id = uuid::Uuid::new_v4().to_string();
        let dismissal_env = dismissal_envelope(
            Cohort::Community,
            &community,
            &action_id,
            &o1_id,
            "reviewed",
        );
        let d_short = signed_row(
            &d_short_id,
            &bob,
            &actor,
            dismissal_env.clone(),
            now,
            &[carol.as_str()],
        );
        let short = record_objection_dismissal(dir, &d_short)
            .await
            .expect("dismissal decision");
        assert_eq!(
            short.outcome.refusal(),
            Some(ObjectionRefusalReason::DismissalQuorumShort),
            "({suffix}) undoing protection costs strictly more than applying it"
        );
        assert_eq!(
            (
                short.quorum.counted,
                short.quorum.required,
                short.quorum.roster_size
            ),
            (2, 3, 5),
            "({suffix}) the refusal names the shortfall, not merely that it refused"
        );
        assert!(
            dir.get_attestation(&d_short_id)
                .await
                .expect("read")
                .is_none(),
            "({suffix}) a refused dismissal writes NOTHING (verify-before-mutation)"
        );

        // ── (3b) …and a NON-MEMBER co-signature buys nothing. bob + carol +
        //    the stranger is still two, because the count intersects the scrub
        //    set with the cohort's OWN roster before verifying anything. A
        //    stray co-signature degrades the evidence; it never manufactures a
        //    quorum.
        let d_padded = signed_row(
            &uuid::Uuid::new_v4().to_string(),
            &bob,
            &actor,
            dismissal_env.clone(),
            now,
            &[carol.as_str(), stranger.as_str()],
        );
        let padded = record_objection_dismissal(dir, &d_padded)
            .await
            .expect("dismissal decision");
        assert_eq!(
            padded.outcome.refusal(),
            Some(ObjectionRefusalReason::DismissalQuorumShort),
            "({suffix}) padding the scrub set with an outsider is not a quorum"
        );
        assert_eq!(
            (padded.quorum.counted, padded.quorum.required),
            (2, 3),
            "({suffix}) the outsider's signature verified fine and STILL did not count"
        );

        // ── (4) The SAME dismissal, now carrying three roster signatures:
        //    quorum met. Authored by DAVE deliberately, for two reasons: dave is
        //    not alice, so this is a genuine m-of-n undo of somebody ELSE'S
        //    protection and not the free self-retraction of step (9); and dave
        //    goes on to raise his own objection in step (5), witnessing that
        //    helping lift the brake once does not cost a member the right to
        //    pull it again. alice CO-SIGNS — a co-signature from the objector
        //    does not make it a self-retraction, which keys on the AUTHOR.
        let d_ok_id = uuid::Uuid::new_v4().to_string();
        let d_ok = signed_row(
            &d_ok_id,
            &dave,
            &actor,
            dismissal_env,
            now,
            &[alice.as_str(), bob.as_str()],
        );
        let ok = record_objection_dismissal(dir, &d_ok)
            .await
            .expect("dismissal decision");
        assert_eq!(
            ok.outcome,
            ObjectionOutcome::Admitted,
            "({suffix}) m-of-n undoes"
        );
        assert_eq!((ok.quorum.counted, ok.quorum.required), (3, 3));
        let f2 = fold(&action).await;
        assert_eq!(
            f2.distinct_objectors, 0,
            "({suffix}) the objection is lifted"
        );
        assert_eq!(f2.dismissed_objection_ids, vec![o1_id.clone()]);

        // ── (5) TWO distinct members object: the action is reversed — on a
        //    roster of FIVE, i.e. BELOW a strict majority, because that is what
        //    this community declared. dave and erin, so the dismissed alice
        //    objection plays no part.
        let mut late_objections: Vec<(String, String)> = Vec::new();
        for member in [&dave, &erin] {
            let oid = uuid::Uuid::new_v4().to_string();
            let o = signed_row(
                &oid,
                member,
                &actor,
                objection_envelope(
                    Cohort::Community,
                    &community,
                    &action_id,
                    "still harms the commons",
                ),
                Utc::now(),
                &[],
            );
            late_objections.push((member.clone(), oid));
            assert_eq!(
                record_objection(dir, &o).await.expect("record"),
                ObjectionOutcome::Admitted,
                "({suffix}) each member raises the brake alone — including dave, \
                 who authored the step-4 dismissal: one-member-one-objection is \
                 scoped to OBJECTIONS, never to \"has this member touched this \
                 action before\""
            );
        }
        let f3 = fold(&action).await;
        assert_eq!(
            f3.standing,
            ReverseQuorumStanding::Reversed,
            "({suffix}) m distinct in-window objectors reverse: {f3:?}"
        );
        assert_eq!(f3.distinct_objectors, 2);
        assert_eq!(f3.counted_objection_ids.len(), 2);
        assert!(
            f3.distinct_objectors
                < ciris_verify_core::accord_genesis::strict_majority(f3.roster_size),
            "({suffix}) TWO of five reversed it — the protective side really is \
             reachable below a strict majority, on a live backend and not only \
             in the threshold unit test"
        );
        assert!(
            dir.get_attestation(&action_id)
                .await
                .expect("read")
                .is_some(),
            "({suffix}) REVERSED is a derived state — the row itself is untouched"
        );

        // ── (6) THE MARKER TRAVELS. A peer that never saw any of this gets
        //    the same signed rows and folds to the SAME standing. An objection
        //    that only lived as an API call could not do this.
        let peer = crate::store::memory::MemoryBackend::new();
        for k in [&alice, &bob, &carol, &dave, &erin, &actor, &community] {
            register_user_key(&peer, k).await;
        }
        let peer_community = Community {
            community_key_id: community.clone(),
            community_name: format!("commons {community}"),
            members: roster
                .iter()
                .enumerate()
                .map(|(i, k)| CommunityMember {
                    key_id: k.clone(),
                    joined_at: now,
                    role: Some(if i == 0 { "founder" } else { "member" }.to_owned()),
                })
                .collect(),
            founded_at: now,
            consensus_protocol: "reverse_quorum:2/3:3600".to_owned(),
            policy_blob: None,
            persist_row_hash: String::new(),
        };
        peer.put_community(
            crate::federation::tier_ingest::test_support::sign_community(&alice, peer_community),
        )
        .await
        .expect("peer community");
        // Replicate the action + every objection/dismissal row VERBATIM.
        peer.put_attestation(SignedAttestation {
            attestation: action.clone(),
        })
        .await
        .expect("peer action");
        let mut replicated = 0usize;
        for r in dir
            .list_attestations_for(&actor)
            .await
            .expect("origin rows")
        {
            if r.attestation_id == action_id {
                continue;
            }
            peer.put_attestation(SignedAttestation {
                attestation: r.clone(),
            })
            .await
            .expect("replicate marker");
            replicated += 1;
        }
        assert!(
            replicated >= 3,
            "({suffix}) the markers must actually have travelled, got {replicated}"
        );
        let peer_fold =
            resolve_reverse_quorum(&peer, Cohort::Community, &community, &action, Utc::now())
                .await
                .expect("peer resolve");
        assert_eq!(
            peer_fold.standing,
            ReverseQuorumStanding::Reversed,
            "({suffix}) a peer folds the replicated markers to the SAME answer: {peer_fold:?}"
        );
        assert_eq!(peer_fold.counted_objection_ids, f3.counted_objection_ids);
        assert_eq!(
            peer_fold.dismissed_objection_ids,
            f3.dismissed_objection_ids
        );

        // ── (7) THE UNDO EXPIRES WITH THE ROSTER IT WAS COUNTED AGAINST.
        //    The step-4 dismissal cleared 3-of-5. Grow the commons to nine and
        //    a strict majority is FIVE: those same three signatures no longer
        //    buy a dismissal, so alice's objection comes back on its own. This
        //    is why `resolve_reverse_quorum` re-derives every dismissal's
        //    m-of-n at READ time instead of trusting that it was admitted once
        //    — a mutation run showed that skipping the re-check is otherwise
        //    invisible. Protection returning by itself is the fail-SAFE
        //    direction, and it is the same read-time re-derivation the charter
        //    plane does (a quorum that stops reaching stops counting).
        for i in 0..4 {
            let newcomer = format!("rq-newcomer{i}-{suffix}");
            register_user_key(dir, &newcomer).await;
            dir.add_community_member(
                &community,
                CommunityMember {
                    key_id: newcomer,
                    joined_at: Utc::now(),
                    role: Some("member".to_owned()),
                },
            )
            .await
            .expect("grow the commons");
        }
        let f_grown = fold(&action).await;
        assert_eq!(f_grown.roster_size, 9, "({suffix})");
        assert!(
            f_grown.dismissed_objection_ids.is_empty(),
            "({suffix}) a 3-signature dismissal does not survive a roster of 9: {f_grown:?}"
        );
        assert!(
            f_grown.counted_objection_ids.contains(&o1_id),
            "({suffix}) the objection it had lifted is LIVE again"
        );
        assert_eq!(
            f_grown.distinct_objectors, 3,
            "({suffix}) alice is counted once more, beside dave and erin"
        );

        // ── (8) A cohort that never adopted the protocol is NOT GOVERNED —
        //    persist refuses rather than inventing a window and a threshold.
        let plain = format!("rq-plain-{suffix}");
        register_user_key(dir, &plain).await;
        let plain_action_id = uuid::Uuid::new_v4().to_string();
        let plain_action = seed(dir, &plain, &actor, &roster, &plain_action_id, "quorum:2/3").await;
        let o = signed_row(
            &uuid::Uuid::new_v4().to_string(),
            &alice,
            &actor,
            objection_envelope(Cohort::Community, &plain, &plain_action_id, "no"),
            Utc::now(),
            &[],
        );
        assert_eq!(
            record_objection(dir, &o).await.expect("record").refusal(),
            Some(ObjectionRefusalReason::NotGoverned),
            "({suffix}) a stored label nobody adopted must not become a silent default"
        );
        let plain_fold =
            resolve_reverse_quorum(dir, Cohort::Community, &plain, &plain_action, Utc::now())
                .await
                .expect("resolve");
        assert_eq!(plain_fold.standing, ReverseQuorumStanding::NotGoverned);

        // ── (9) SELF-RETRACTION IS FREE. erin raised the brake alone; she may
        //    lower her own alone, on a roster of NINE where dismissing anyone
        //    else's would take five. It takes nothing from alice or dave —
        //    their objections are untouched — which is why one signature is the
        //    right price and why a captured key gains nothing by it.
        let (_erin_key, erin_objection_id) = late_objections
            .last()
            .cloned()
            .expect("erin's objection id was captured");
        let self_retraction = signed_row(
            &uuid::Uuid::new_v4().to_string(),
            &erin,
            &actor,
            dismissal_envelope(
                Cohort::Community,
                &community,
                &action_id,
                &erin_objection_id,
                "withdrawn on reflection",
            ),
            Utc::now(),
            &[],
        );
        let retracted = record_objection_dismissal(dir, &self_retraction)
            .await
            .expect("self-retraction decision");
        assert_eq!(
            retracted.outcome,
            ObjectionOutcome::Admitted,
            "({suffix}) a member drops their OWN protection with their own \
             signature: {retracted:?}"
        );
        assert_eq!(
            (retracted.quorum.counted, retracted.quorum.required),
            (1, 1),
            "({suffix}) one, on a roster of nine — and dismissing anyone ELSE's \
             here still costs five"
        );
        let f_retracted = fold(&action).await;
        assert!(
            !f_retracted
                .counted_objection_ids
                .contains(&erin_objection_id),
            "({suffix}) erin's objection is lifted"
        );
        assert_eq!(
            f_retracted.distinct_objectors, 2,
            "({suffix}) alice and dave are UNTOUCHED — a self-retraction is not \
             an undo of anybody else's protection: {f_retracted:?}"
        );
    }
}
