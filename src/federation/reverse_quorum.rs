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
//! # The protective side
//!
//! | side | who | threshold |
//! |---|---|---|
//! | raise an objection | any ONE current member | [`OBJECTION_THRESHOLD`] = 1, always, every roster |
//! | reverse the action | `m` distinct in-window objectors | [`ReverseQuorumPolicy::reversal_threshold`] — the declared `m`, **capped** at the roster, never raised |
//! | retract your own objection | its author (any key of the same person) | a `withdraws` / `recants` naming it |
//!
//! The protective side is never made harder than declared:
//! [`tests::the_protective_side_is_never_floored_at_a_strict_majority`] pins
//! the reversal threshold as the declared `m`, capped, and floored at
//! nothing. The undo side's price, [`ReverseQuorumPolicy::dismissal_threshold`]
//! (the declared `m` floored at a strict majority), survives KR-fix35 as the
//! forward price of a capability grant under this protocol (`consensus.rs`).
//!
//! # v62.0.0 (KR-fix35) — dismissal, ballots and the steward tier are gone
//!
//! Constitution ruled `objection:{state}` CLOSED at `assent | raised` (the
//! pre4 registry: `{state}` is a closed vocabulary of those two). The earlier
//! escalation machinery — the m-of-n `objection:dismissed:v1` that lifted an
//! objection, the `objection:upheld:v1` / `objection:overruled:v1` ballots,
//! the appointed moderators' steward tier and the escalated respondent pool
//! (CIRISPersist#591) — is not in that form and is DELETED: its builders, its
//! tally arms, its fold fields and its types. A row of one of those states
//! that a node still holds is read by nothing here; the door refuses a new
//! one once the pre4 registry is vendored (`namespace_vocab_value_unregistered`).
//! A held dismissal therefore no longer suppresses an objection: protection
//! sticks, the fail-secure direction.
//!
//! **A steward-tier string is still READ.** A `consensus_protocol` of the form
//! `reverse_quorum:{m}/{n}:{window}+escalate:{steward_secs}:{floor}` parses
//! exactly as it did (the suffix's shape is still checked, so no string the
//! shape gate admitted is refused now and none it refused is admitted), and
//! folds exactly as `reverse_quorum:{m}/{n}:{window}`: the suffix is read and
//! has no effect. [`ReverseQuorumPolicy::to_protocol_string`] names the
//! base form, which is what is in force.
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
//! (revocation-folded) and the threshold from the cohort's OWN stored
//! `consensus_protocol`.
//!
//! # The vocabulary is closed in THREE places
//!
//! `reverse_quorum:{m}/{n}:{window_secs}` had to be admitted by all of:
//! [`consensus_protocol::is_canonical_form`](super::types::consensus_protocol::is_canonical_form)
//! (which routes to [`ReverseQuorumPolicy::parse`], so the shape gate can
//! never admit a string this module cannot read), the sqlite
//! `federation_communities` table CHECK, and its postgres twin — V116 on both
//! backends. `federation_families.consensus_protocol` carries no CHECK, so
//! there was deliberately nothing to widen there.
//!
//! # What is deliberately out of scope
//!
//! **Objection to the objection**, and any escalation of one: a v62
//! escalation feature would be new design (Constitution's ruling, for Eric).

use chrono::{DateTime, Duration, Utc};

use super::attestation_query::{AttestationQuery, FOLD_PAGE};
use super::key_person::{KeySelves, PersonsAt, NO_KEY_SELVES};
use super::types::{attestation_type, Attestation};
use super::{cohort::Cohort, Error, FederationDirectory};

/// The `scores` dimension an objection carries: *"I, a member of this cohort,
/// object to this action in our commons."*
///
/// A **new namespace family** — see [`NAMESPACE_FAMILY`]. Versioned `:v1` per
/// the house style for persist-minted dimensions (`consent:replication:v1`,
/// `trace:complete:v1`).
pub const DIMENSION_OBJECTION: &str = "objection:raised:v1";

/// The CC 3.1 namespace family the objection dimension lives under.
/// **Registered** (CIRISPersist#590): CC 1.0-rc3 catalogues it at CC 3.1.9.2,
/// owning component `node`, alongside `moderation:{allegation_type}`,
/// `slashing:{outcome}` and `reconsideration:{grounds}`. It is on the R2(a)
/// mint gate ([`super::admission::MINTED_NAMESPACE_FAMILIES`]), so a future
/// family minted without its row fails persist's own build.
///
/// **The row registers the family, NOT the emitter rule.** CC's row carries
/// `reserved: false` and **no** `reserved_rule`. So
/// [`authority_for`](super::namespace::registry::authority_for)`("objection:…")`
/// returns `ProducerSteward` / `reserved: None`; the cohort-member-only rule
/// is the read fold's (a non-member's objection counts for nothing). Tracked
/// in [`RULES_NOT_ON_THE_ROW`](super::family_rules::RULES_NOT_ON_THE_ROW).
pub const NAMESPACE_FAMILY: &str = "objection:{state}";

/// The smallest respondent floor the earlier steward-tier suffix could
/// declare. v62.0.0 (KR-fix35): the tier is gone, and the suffix is only READ;
/// [`ReverseQuorumPolicy::parse`] still checks its shape against this number,
/// so the set of strings the shape gate admits does not move.
const STEWARD_SUFFIX_FLOOR_MIN: usize = 3;

/// The infix that opens the earlier steward-tier suffix in a
/// `consensus_protocol` string:
/// `reverse_quorum:{m}/{n}:{window}+escalate:{steward_secs}:{floor}`.
///
/// v62.0.0 (KR-fix35): READ, with no effect. A string carrying it folds as
/// the same string without it. The sqlite `federation_communities` CHECK
/// admits it unchanged (`GLOB 'reverse_quorum:*/*:*'`); the postgres CHECK
/// (widened by V120) admits it too. Nothing new writes it.
pub const ESCALATE_INFIX: &str = "+escalate:";

/// v62.0.0 (KR-fix35c; Constitution: the protocol vocabulary has no
/// `+escalate:` suffix, and persist never WRITES one) — does `protocol`
/// carry the earlier steward-tier suffix?
#[must_use]
pub fn carries_escalate_suffix(protocol: &str) -> bool {
    protocol.starts_with(super::types::consensus_protocol::REVERSE_QUORUM_PREFIX)
        && protocol.contains(ESCALATE_INFIX)
}

/// v62.0.0 (KR-fix35c) — **the base form of a `consensus_protocol`**: a
/// `reverse_quorum:*` string carrying a well-formed `+escalate:` suffix reads
/// as [`ReverseQuorumPolicy::to_protocol_string`] (the suffix is read and has
/// no effect); every other string is itself. The ONE comparison form for
/// "did the protocol change": a successor persist writes from a held suffix
/// record states the base form, and that is no change.
#[must_use]
pub fn base_protocol(protocol: &str) -> std::borrow::Cow<'_, str> {
    if carries_escalate_suffix(protocol) {
        if let Some(p) = ReverseQuorumPolicy::parse(protocol) {
            return std::borrow::Cow::Owned(p.to_protocol_string());
        }
    }
    std::borrow::Cow::Borrowed(protocol)
}

/// v62.0.0 (KR-fix35c) — are `a` and `b` the same protocol, compared on
/// their [`base_protocol`] forms?
#[must_use]
pub fn same_protocol(a: &str, b: &str) -> bool {
    base_protocol(a) == base_protocol(b)
}

/// Envelope field names shared by the producer side and persist's fold, so
/// the two cannot disagree about where a reference lives.
pub mod field {
    /// v62.0.0 (KR-fix34a; CC 2.6.1.3, the Constitution's ruling (a)) — the
    /// row an `objection:assent` / `objection:raised` vote ANSWERS: stated as
    /// `refs.answers` (`edition2::payloads::REF_MEMBERS`), read back by the
    /// earlier gates under this envelope member, as a membership reply's is.
    /// A roster event is named by its record's row id (KR-fix34b). The
    /// earlier member `objects_to_attestation_id` is refused on a vote
    /// (`malformed:objects_to_attestation_id`) and, since KR-fix35, named by
    /// nothing here.
    pub const ANSWERS: &str = "references_attestation_id";
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
    ///
    /// v62.0.0 (KR-fix35) — the earlier steward-tier suffix
    /// ([`ESCALATE_INFIX`]`{steward_secs}:{floor}`) is still READ: its shape
    /// is checked exactly as before (two numbers, the floor at least three;
    /// a malformed suffix is `None`, as it was),
    /// and then DISCARDED. A string carrying a well-formed suffix is the
    /// policy of its base form.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let tail = s.strip_prefix(super::types::consensus_protocol::REVERSE_QUORUM_PREFIX)?;
        // The suffix is split off FIRST: `{window}` would otherwise swallow
        // it and fail to parse as seconds.
        let (base, escalate) = match tail.split_once(ESCALATE_INFIX) {
            Some((base, rest)) => (base, Some(rest)),
            None => (tail, None),
        };
        let (quorum, window) = base.split_once(':')?;
        let (m_s, n_s) = quorum.split_once('/')?;
        let m: u32 = m_s.parse().ok()?;
        let n: u32 = n_s.parse().ok()?;
        let window_secs: u64 = window.parse().ok()?;
        if m == 0 || n == 0 || m > n {
            return None;
        }
        if let Some(rest) = escalate {
            let (secs, floor) = rest.split_once(':')?;
            let _steward_window: u64 = secs.parse().ok()?;
            let respondent_floor: usize = floor.parse().ok()?;
            if respondent_floor < STEWARD_SUFFIX_FLOOR_MIN {
                return None;
            }
        }
        Some(Self { m, n, window_secs })
    }

    /// Render back to the canonical `consensus_protocol` string: the base
    /// form, which is what is in force (v62.0.0, KR-fix35: a steward-tier
    /// suffix is read and has no effect, so it is not rendered).
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
    /// absence of a strict-majority FLOOR here is load-bearing: flooring the
    /// protective side is exactly the mistake this module exists to not make.
    #[must_use]
    pub fn reversal_threshold(&self, roster_size: usize) -> usize {
        (self.m as usize).min(roster_size.max(1))
    }

    /// **The undo side's price**: the declared `m`, **floored at a strict
    /// majority** of the live roster — never lowered. A tampered (or merely
    /// optimistic) policy string cannot talk it down, because the number the
    /// node acts on is re-derived from the node's OWN roster.
    ///
    /// v62.0.0 (KR-fix35) — the dismissal it priced is deleted; this stays as
    /// the FORWARD price of a capability grant under a `reverse_quorum:*`
    /// protocol (`consensus::required_signatures_at`, and `evaluate`'s Add
    /// arm): a grant is never 1-of-N.
    #[must_use]
    pub fn dismissal_threshold(&self, roster_size: usize) -> usize {
        let floor = crate::federation::admission::strict_majority(roster_size);
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
/// grants nothing).
pub const OBJECTION_THRESHOLD: usize = 1;

// ─────────────────────────────────────────────────────────────────────────
//  Typed refusals (#565 style)
// ─────────────────────────────────────────────────────────────────────────

/// **WHICH branch refused** an objection.
///
/// Closed, snake_case serde tokens, [`Self::as_str`] returning the SAME token,
/// and deliberately no `Other`/`Unspecified` catch-all — the
/// [`KeyRefusalReason`](super::register::KeyRefusalReason) discipline #565
/// shipped, for the same reason: a refusal is a verdict, and a verdict without
/// its branch sends the reader to the wrong layer.
///
/// v62.0.0 (KR-fix35) — the three ballot branches
/// (`steward_tier_not_adopted`, `actor_recused`, `ballot_predates_action`)
/// are deleted with the ballots.
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
    /// The row's envelope `dimension` is not [`DIMENSION_OBJECTION`]. Wrong
    /// door.
    DimensionMismatch,
    /// The envelope is missing a field the fold needs — [`field::ANSWERS`]
    /// or the cohort pair.
    MalformedEnvelope,
    /// The row's own scrub signature did not verify against the signer's
    /// pubkeys as registered on THIS node.
    UnverifiableSignature,
    /// The row's `attested_key_id` is not the objected-to action's AUTHOR.
    ///
    /// Objections are found by
    /// [`list_attestations_for`](crate::federation::attestation_query::AttestationQuery::to)`(action.attesting_key_id)`,
    /// so a row filed against any other key would be stored and then never
    /// counted by anything — admitted, durable, and permanently inert. Refused
    /// instead: the preserve set must equal the verified set, and a marker
    /// nobody can find is not a marker.
    NotFiledAgainstActor,
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
            Self::DimensionMismatch => "dimension_mismatch",
            Self::MalformedEnvelope => "malformed_envelope",
            Self::UnverifiableSignature => "unverifiable_signature",
            Self::NotFiledAgainstActor => "not_filed_against_actor",
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::CohortUnknown,
        Self::NotGoverned,
        Self::DimensionMismatch,
        Self::MalformedEnvelope,
        Self::UnverifiableSignature,
        Self::NotFiledAgainstActor,
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
///
/// v62.0.0 (KR-fix35) — a CLEAN BREAK: `dismissed_objection_ids`,
/// `steward_deadline`, `escalation` and `escalated_dismissed_objection_ids`
/// are deleted with the dismissal, the ballots and the steward tier.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReverseQuorumFold {
    /// The derived state.
    pub standing: ReverseQuorumStanding,
    /// The cohort's parsed protocol (its base form), or `None` when
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
}

/// v49.0.0 — **what the fold reads from an action**, and nothing else.
///
/// The fold reads exactly three things from the action under objection: who
/// did it ([`Self::actor_key_id`] — objections are filed against, and found
/// through, that key), what it is called ([`Self::action_id`] — matched
/// byte-for-byte against the row an objection answers, [`field::ANSWERS`]),
/// and when it happened ([`Self::asserted_at`] — the window opens there).
/// Naming that as a type lets an action that is NOT an [`Attestation`] be
/// folded by the same code: a roster event in a `reverse_quorum:*` room is
/// identified by its record's row id (KR-fix34b), and its actor is the member
/// whose signature it landed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActionRef<'a> {
    /// The key whose single signature the action landed on — the actor.
    pub actor_key_id: &'a str,
    /// The action's identifier, exactly as objections name it in
    /// [`field::ANSWERS`].
    pub action_id: &'a str,
    /// The action's own instant — the objection window opens here.
    pub asserted_at: DateTime<Utc>,
}

impl<'a> From<&'a Attestation> for ActionRef<'a> {
    fn from(a: &'a Attestation) -> Self {
        Self {
            actor_key_id: a.attesting_key_id.as_str(),
            action_id: a.attestation_id.as_str(),
            asserted_at: a.asserted_at,
        }
    }
}

/// **The fold's whole input**, as a type.
///
/// #574's invariant, made structural: the standing of an action is a pure
/// function of `(action, objections, roster, policy, now)` and of nothing
/// else — no clock of its own, no timer, no control loop, no state advanced at
/// write time.
#[derive(Debug, Clone, Copy)]
pub struct ReverseQuorumInputs<'a> {
    /// The commons action under objection (v49.0.0: an [`ActionRef`], so an
    /// action that is not an attestation folds by the same rules).
    pub action: ActionRef<'a>,
    /// Every standing objection row this node holds against it.
    pub objections: &'a [Attestation],
    /// The cohort's live, revocation-folded roster.
    pub roster: &'a [String],
    /// The cohort's parsed `consensus_protocol`.
    pub policy: Option<ReverseQuorumPolicy>,
    /// The read-time instant every window is compared against.
    pub now: DateTime<Utc>,
    /// CIRISPersist#1198 (CC 4.5.13) — the persons behind the keys, at the
    /// count. A tally counts fedIDs, so `roster` is read as the persons it
    /// seats. [`PersonsAt::each_key`] is the per-key count.
    pub persons: PersonsAt<'a>,
}

/// The **pure fold** over `(action, objections, roster, policy, now)`, one
/// key per person.
///
/// Evaluated at READ time rather than advanced at write time: a node
/// partitioned during the window sees the action but not the objections, and
/// must converge on the same answer when they arrive late. A state machine
/// advanced at write time cannot do that; a fold over held rows does it for
/// free — the same shape `resolve_scoped_consent` has.
///
/// # Counting rules
///
/// An objection counts iff ALL of: it carries [`DIMENSION_OBJECTION`]; the row
/// it answers ([`objected_object`]) is `action`; its `attesting_key_id` is on
/// the LIVE roster (a member who left stops counting — the threshold is
/// re-derived at read time, so a reversal can lapse exactly as a charter
/// quorum can); and its `asserted_at` is inside the window. Objectors are
/// counted **distinct** by `attesting_key_id`.
#[must_use]
pub fn fold_reverse_quorum(
    action: &Attestation,
    objections: &[Attestation],
    roster: &[String],
    policy: Option<ReverseQuorumPolicy>,
    now: DateTime<Utc>,
) -> ReverseQuorumFold {
    fold_reverse_quorum_over(&ReverseQuorumInputs {
        action: action.into(),
        objections,
        roster,
        policy,
        now,
        persons: PersonsAt::each_key(),
    })
}

/// **The pure fold, in full**: the one implementation of every counting rule
/// on this plane, over [`ReverseQuorumInputs`] and nothing else. Objectors are
/// counted **one voice per person** (CC 4.5.13): one person is one objection,
/// however many rows that person authored, on however many devices.
#[must_use]
pub fn fold_reverse_quorum_over(inputs: &ReverseQuorumInputs<'_>) -> ReverseQuorumFold {
    let &ReverseQuorumInputs {
        action,
        objections,
        roster,
        policy,
        now,
        persons,
    } = inputs;
    let seated = persons.seated(roster);
    let Some(policy) = policy else {
        return ReverseQuorumFold {
            standing: ReverseQuorumStanding::NotGoverned,
            policy: None,
            distinct_objectors: 0,
            required: 0,
            roster_size: seated.len(),
            window_opens_at: action.asserted_at,
            window_closes_at: action.asserted_at,
            window_open: false,
            counted_objection_ids: Vec::new(),
        };
    };

    let (opens, closes) = policy.window(action.asserted_at);
    let required = policy.reversal_threshold(seated.len());

    // One person, one objection, however many rows: the lowest id stands for
    // the voice, so the report does not depend on row order.
    let mut objectors: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for o in objections {
        if envelope_str(o, "dimension") != Some(DIMENSION_OBJECTION) {
            continue;
        }
        if objected_object(o) != Some(action.action_id) {
            continue;
        }
        let Some(person) = persons
            .voice(&o.attesting_key_id)
            .filter(|person| seated.contains(person))
        else {
            continue;
        };
        if o.asserted_at < opens || o.asserted_at > closes {
            continue;
        }
        objectors
            .entry(person)
            .and_modify(|id| *id = (*id).min(o.attestation_id.as_str()))
            .or_insert(o.attestation_id.as_str());
    }
    let mut counted_ids: Vec<String> = objectors.values().map(|id| (*id).to_owned()).collect();
    counted_ids.sort();

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
        roster_size: seated.len(),
        window_opens_at: opens,
        window_closes_at: closes,
        window_open,
        counted_objection_ids: counted_ids,
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Envelope builders — one shape, producer side and persist side
// ─────────────────────────────────────────────────────────────────────────

/// Build the canonical envelope of an **objection**. Defined here so a
/// producer and this node's fold agree byte-for-byte about where the
/// references live.
///
/// v62.0.0 (KR-fix34a; KR-fix34b) — the action is a ROW, by its row id: an
/// attestation's, or a ROSTER EVENT's (the counted change its typed record
/// projects, `record_row_id`). Named under [`field::ANSWERS`], stated as
/// `refs.answers`.
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
        field::ANSWERS: action_attestation_id,
        field::GROUNDS: grounds,
    })
}

/// v62.0.0 (KR-fix34a; KR-fix34b) — **the object an assent / raised vote
/// names**: the row it answers ([`field::ANSWERS`], from `refs.answers`). An
/// attestation and a roster event alike are named by their ROW ID (a roster
/// event's is its record's `record_row_id`). The one reader every fold asks.
#[must_use]
pub fn objected_object(row: &Attestation) -> Option<&str> {
    envelope_str(row, field::ANSWERS)
}

/// Read a string field off a row's envelope.
fn envelope_str<'a>(row: &'a Attestation, key: &str) -> Option<&'a str> {
    row.attestation_envelope.get(key)?.as_str()
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
        Err(e) => return Err(e),
    };
    let policy = group
        .consensus_protocol
        .as_deref()
        .and_then(ReverseQuorumPolicy::parse);
    let roster: Vec<String> = match directory.active_members(cohort, cohort_key_id).await {
        Ok(members) => members.into_iter().map(|m| m.key_id).collect(),
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
/// survivor admitted only as a voice the edition-2 door vouches for
/// ([`vouched_envelope`](crate::federation::edition2::group::vouched_envelope);
/// v62.0.0, F0-cp8: the earlier envelope verify against the directory's
/// registered component halves is deleted, so `_directory` reads nothing).
/// Never the roster a caller passed on the row, never pubkeys carried on the
/// row.
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
    _directory: &F,
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
        if crate::federation::edition2::group::vouched_envelope(
            &scrub.scrub_key_id,
            envelope,
            &scrub.scrub_signature_classical,
            "roster_scrub",
        )
        .is_ok()
        {
            counted.insert(scrub.scrub_key_id.clone());
        }
    }
    counted
}

/// The action a cohort objection names: the row that opens a vote window. The
/// attestation plan writes the window in the row's transaction (V213).
#[must_use]
pub(crate) fn objection_action(row: &Attestation) -> Option<String> {
    (envelope_str(row, "dimension") == Some(DIMENSION_OBJECTION) && is_vote_row(row))
        .then(|| objected_object(row).map(str::to_owned))
        .flatten()
}

/// Is this row a vote of a cohort: an objection? A retraction of one is
/// admitted from any verifiable signer and judged by the fold (CC's ruling on
/// #1198, item 2). The self roster's objections are not: there the keys are
/// the voters and the write gate stands.
///
/// v61.1.0 (D12) — the family is the row's claim token
/// ([`row_type::claim_token`](super::row_type::claim_token): a `scores` row's
/// `dimension`, any other row's type), the one classifier every family gate
/// asks (CIRISPersist#1174), not the envelope `dimension` of whatever type.
/// v62.0.0 (KR-fix35) — the two ballot dimensions are no votes any more.
#[must_use]
pub fn is_vote_row(row: &Attestation) -> bool {
    super::row_type::claim_token(row) == Some(DIMENSION_OBJECTION)
        && envelope_str(row, field::COHORT) != Some(Cohort::SelfId.as_str())
}

// ─────────────────────────────────────────────────────────────────────────
//  The read-time answer
// ─────────────────────────────────────────────────────────────────────────

/// Every objection row this node holds that is keyed on `action`'s author and
/// answers `action`. An objection carries `attested_key_id =
/// action.attesting_key_id` (the actor whose action is under objection), so
/// ONE existing read serves it. v62.0.0 (KR-fix35): objections only; a held
/// dismissal or ballot row is read by nothing.
async fn objections_against<F>(
    directory: &F,
    action: ActionRef<'_>,
) -> Result<Vec<Attestation>, Error>
where
    F: FederationDirectory + ?Sized,
{
    // The `objection:` family: the prefix seek carries it, the exact match
    // below picks the objection.
    let mut rows = Vec::new();
    let mut pages = AttestationQuery::to(action.actor_key_id, FOLD_PAGE)
        .dimension_prefix("objection:")
        .pages();
    let read: Result<(), Error> = async {
        while let Some(page) = pages.next(directory).await? {
            rows.extend(page);
        }
        Ok(())
    }
    .await;
    read?;
    Ok(rows
        .into_iter()
        .filter(|r| {
            envelope_str(r, "dimension") == Some(DIMENSION_OBJECTION)
                && objected_object(r) == Some(action.action_id)
        })
        .collect())
}

/// **The read-time answer** — what `cohort`'s reverse quorum says about
/// `action`, folded from the rows this node holds right now: the roster and
/// the policy re-derived from this node's own stored state, the objections
/// that still stand (a retracted one does not).
///
/// Persist mutates nothing here.
///
/// The receiver is `&dyn FederationDirectory` (CIRISPersist#591's reason, the
/// steward tier's moderation walk, is gone with the tier; the signature is
/// kept so no caller changes).
pub async fn resolve_reverse_quorum(
    directory: &dyn FederationDirectory,
    cohort: Cohort,
    cohort_key_id: &str,
    action: &Attestation,
    now: DateTime<Utc>,
) -> Result<ReverseQuorumFold, Error> {
    resolve_reverse_quorum_for(directory, cohort, cohort_key_id, action.into(), now).await
}

/// v49.0.0 — [`resolve_reverse_quorum`] over an [`ActionRef`]: the same
/// read-time answer for an action that is not an [`Attestation`] (a roster
/// event named by its record's row id, whose actor is the one member whose
/// signature it landed on).
///
/// ONE implementation: [`resolve_reverse_quorum`] is a thin wrapper over this,
/// so the two cannot disagree about a single counting rule. The caller vouches
/// for nothing but the action's identity — the roster and the policy are
/// re-derived here from this node's own verified state, exactly as for an
/// attestation. A caller that names the wrong actor or instant only
/// mis-locates the objections filed against the action; it cannot mint one.
pub async fn resolve_reverse_quorum_for(
    directory: &dyn FederationDirectory,
    cohort: Cohort,
    cohort_key_id: &str,
    action: ActionRef<'_>,
    now: DateTime<Utc>,
) -> Result<ReverseQuorumFold, Error> {
    let (roster, policy) = cohort_state(directory, cohort, cohort_key_id)
        .await?
        .unwrap_or_else(|| (Vec::new(), None));
    resolve_reverse_quorum_with(directory, roster, policy, &NO_KEY_SELVES, action, now).await
}

/// v49.0.0 (CIRISPersist#908) — [`resolve_reverse_quorum_for`] over a roster
/// and policy the CALLER supplies. The roster fold uses it: it cannot let this
/// fold read the roster, because that read IS the roster fold (whose
/// reversed-removal leg is this fold) — an unbounded recursion. The caller
/// passes the roster with no reversals applied (the members who could
/// object). Everything else is identical. `known` is what the caller already
/// read about the keys, so a fold over many events reads each key once.
///
/// v62.0.0 (KR-fix35) — the cohort and its duty-holder set are no inputs any
/// more (they served the steward tier only).
pub(crate) async fn resolve_reverse_quorum_with(
    directory: &dyn FederationDirectory,
    roster: Vec<String>,
    policy: Option<ReverseQuorumPolicy>,
    known: &KeySelves,
    action: ActionRef<'_>,
    now: DateTime<Utc>,
) -> Result<ReverseQuorumFold, Error> {
    let objection_rows = objections_against(directory, action).await?;

    // CIRISPersist#1198 (CC 4.5.13) — who these keys are, and which objections
    // still stand: a retracted row is not live, whoever of the same fedID
    // signed the retraction. Over every held row, with no clock (CC's ruling,
    // item 1).
    let retractions = vote_retractions(directory, &objection_rows).await?;
    let mut selves = KeySelves::default();
    let keys = roster
        .iter()
        .chain(objection_rows.iter().map(|r| &r.attesting_key_id))
        .chain(retractions.iter().map(|(_, issuer)| issuer))
        .map(String::as_str)
        .chain([action.actor_key_id])
        .filter(|k| !known.holds(k))
        .map(str::to_owned)
        .collect::<Vec<String>>();
    selves.add(directory, keys).await?;
    let persons = known.held_with(&selves);
    let objection_rows = standing_votes(objection_rows, &retractions, persons);

    Ok(fold_reverse_quorum_over(&ReverseQuorumInputs {
        action,
        objections: &objection_rows,
        roster: &roster,
        policy,
        now,
        persons,
    }))
}

/// Every retraction held against each objection, as `(row id, issuer)`.
async fn vote_retractions<F>(
    directory: &F,
    objections: &[Attestation],
) -> Result<Vec<(String, String)>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut out = Vec::new();
    for b in objections {
        for w in directory
            .list_attestations_referencing(&b.attestation_id)
            .await?
        {
            if matches!(
                w.attestation_type.as_str(),
                attestation_type::WITHDRAWS | attestation_type::RECANTS
            ) {
                out.push((b.attestation_id.clone(), w.attesting_key_id));
            }
        }
    }
    Ok(out)
}

/// The vote rows no retraction reaches. A retraction counts when its signer
/// is the row's author or any key with the voice of the same person (CC
/// 4.5.13, CC 2.4.1.1 rule 1); its instant plays no part. CC's ruling on #1198,
/// item 5: a `recants` retracts as a `withdraws` does.
fn standing_votes(
    votes: Vec<Attestation>,
    retractions: &[(String, String)],
    persons: PersonsAt<'_>,
) -> Vec<Attestation> {
    votes
        .into_iter()
        .filter(|b| {
            !retractions.iter().any(|(id, issuer)| {
                *id == b.attestation_id
                    && (*issuer == b.attesting_key_id
                        || persons.voice(issuer) == Some(persons.seat_person(&b.attesting_key_id)))
            })
        })
        .collect()
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

    /// v62.0.0 (KR-fix35) — **a steward-tier string is still READ**, and
    /// folds as its base form: the parse is the base policy, the rendering is
    /// the base form, and the shape gate still admits the string.
    #[test]
    fn a_steward_tier_string_is_read_and_has_no_effect() {
        let with = "reverse_quorum:2/9:86400+escalate:172800:4";
        let p = ReverseQuorumPolicy::parse(with).expect("a steward-tier string still parses");
        assert_eq!(
            Some(p),
            ReverseQuorumPolicy::parse("reverse_quorum:2/9:86400"),
            "the suffix is read and has no effect"
        );
        assert_eq!(p.to_protocol_string(), "reverse_quorum:2/9:86400");
        assert!(
            super::super::types::consensus_protocol::is_canonical_form(with),
            "no string the shape gate admitted is refused now"
        );
        // And it folds exactly as the base form does.
        let t0: DateTime<Utc> = "2026-08-02T00:00:00Z".parse().unwrap();
        let action = action_row(t0);
        let roster: Vec<String> = (0..9).map(|i| format!("m{i}")).collect();
        let objections = vec![objection("o1", "m1", t0), objection("o2", "m2", t0)];
        let a = fold_reverse_quorum(&action, &objections, &roster, Some(p), t0);
        let b = fold_reverse_quorum(
            &action,
            &objections,
            &roster,
            ReverseQuorumPolicy::parse("reverse_quorum:2/9:86400"),
            t0,
        );
        assert_eq!(a, b);
        assert_eq!(a.standing, ReverseQuorumStanding::Reversed);
    }

    /// v62.0.0 (KR-fix35c) — the base form: a suffix string compares equal to
    /// its base, other strings are themselves, and a malformed suffix is not
    /// rewritten (it does not parse, so it is no protocol at all).
    #[test]
    fn the_base_form_is_the_one_comparison() {
        let with = "reverse_quorum:2/9:86400+escalate:172800:4";
        assert!(carries_escalate_suffix(with));
        assert!(!carries_escalate_suffix("reverse_quorum:2/9:86400"));
        assert_eq!(base_protocol(with), "reverse_quorum:2/9:86400");
        assert!(same_protocol(with, "reverse_quorum:2/9:86400"));
        assert!(!same_protocol(with, "reverse_quorum:3/9:86400"));
        assert_eq!(base_protocol("quorum:2/3"), "quorum:2/3");
        let bad = "reverse_quorum:2/9:600+escalate:60:1";
        assert_eq!(base_protocol(bad), bad);
    }

    /// The earlier suffix's SHAPE is still checked: a string the shape gate
    /// refused before KR-fix35 is refused now (the set of admitted strings
    /// does not move in either direction).
    #[test]
    fn degenerate_steward_tiers_are_refused_by_the_one_parse_door() {
        use super::super::types::consensus_protocol::is_canonical_form;
        for bad in [
            "reverse_quorum:2/9:600+escalate:60:2",
            "reverse_quorum:2/9:600+escalate:60:1",
            "reverse_quorum:2/9:600+escalate:60:0",
            "reverse_quorum:2/9:600+escalate:60",   // no floor
            "reverse_quorum:2/9:600+escalate:60:",  // empty floor
            "reverse_quorum:2/9:600+escalate::3",   // empty window
            "reverse_quorum:2/9:600+escalate:",     // nothing at all
            "reverse_quorum:2/9:600+escalate:x:3",  // non-numeric window
            "reverse_quorum:2/9:600+escalate:60:x", // non-numeric floor
            // …and the #574 degenerates stay refused THROUGH the suffix.
            "reverse_quorum:0/9:600+escalate:60:3",
            "reverse_quorum:9/2:600+escalate:60:3",
        ] {
            assert!(
                ReverseQuorumPolicy::parse(bad).is_none(),
                "{bad} must not parse"
            );
            assert!(
                !is_canonical_form(bad),
                "{bad} must not pass the consensus_protocol shape gate either"
            );
        }
        assert_eq!(
            ReverseQuorumPolicy::parse("reverse_quorum:1/1:0+escalate:0:3"),
            ReverseQuorumPolicy::parse("reverse_quorum:1/1:0"),
            "a steward window of 0 was legal, and still reads as the base form"
        );
    }

    /// THE property this module exists to hold. Over every roster size and
    /// every declared `m`, protection must never cost more than the undo
    /// side's price (which, since KR-fix35, prices a capability grant under a
    /// `reverse_quorum:*` protocol, `consensus.rs`).
    #[test]
    fn the_asymmetry_holds_for_every_roster() {
        for roster in 0usize..=12 {
            for m in 1u32..=12 {
                let p = policy(m, m.max(1), 3600);
                let reversal = p.reversal_threshold(roster);
                let undo = p.dismissal_threshold(roster);
                assert!(
                    OBJECTION_THRESHOLD <= reversal,
                    "raising the brake (1) must never cost more than reversing \
                     (roster={roster}, m={m}, reversal={reversal})"
                );
                assert!(
                    reversal <= undo,
                    "the undo side is never cheaper than protection \
                     (roster={roster}, m={m}, reversal={reversal}, undo={undo})"
                );
                // The ordering alone is NOT enough — flooring BOTH sides at a
                // strict majority preserves it while quietly making the brake
                // as expensive as the undo. Pinned as an exact equality.
                assert_eq!(
                    reversal,
                    (m as usize).min(roster.max(1)),
                    "the protective side is the DECLARED m, capped at the roster \
                     and floored at nothing (roster={roster}, m={m})"
                );
                assert!(
                    undo >= crate::federation::admission::strict_majority(roster).max(1),
                    "the undo side never falls below a strict majority \
                     (roster={roster}, m={m}, undo={undo})"
                );
            }
        }
    }

    /// The single most dangerous edit this module can suffer: flooring the
    /// PROTECTIVE side at a strict majority "for symmetry".
    ///
    /// A community declaring `reverse_quorum:2/9` means TWO. Flooring reversal
    /// at a strict majority would make the brake far harder to pull than the
    /// community declared, which at mesh scale is indistinguishable from
    /// having no brake.
    #[test]
    fn the_protective_side_is_never_floored_at_a_strict_majority() {
        let p = policy(2, 9, 3600);
        let majority = crate::federation::admission::strict_majority(9);
        assert_eq!(p.reversal_threshold(9), 2, "two means two");
        assert!(
            p.reversal_threshold(9) < majority,
            "the protective side must be allowed BELOW a strict majority"
        );
        // …while the undo side is floored at exactly that majority.
        assert_eq!(p.dismissal_threshold(9), majority);
        assert_eq!(majority, 5);
    }

    // DELETED (KR-fix35): `dropping_your_own_protection_costs_one_and_nobody_elses_does`
    // priced a DISMISSAL (`dismissal_required`), which is gone. Retracting
    // your own objection is a `withdraws` / `recants` by any key of the same
    // person (`standing_votes`). GAP (READ): its backend witnesses (I1527,
    // I1536) were deleted in wave 3 slice E6 (vote_by_person_invariants.rs);
    // nothing witnesses `standing_votes` on a backend today.

    #[test]
    fn a_shrunken_roster_caps_reversal_but_never_floors_it() {
        // Declared 4-of-7; three members left. Reversal must stay REACHABLE
        // (capped at 3), or the brake would silently disarm itself.
        let p = policy(4, 7, 3600);
        assert_eq!(p.reversal_threshold(3), 3);
        // And the undo side still demands a strict majority of what is left,
        // floored by the declared m: max(4, 2) = 4.
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
        assert!(
            super::super::canonical_community::parse_quorum("reverse_quorum:2/9:86400").is_none(),
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

    fn t0() -> DateTime<Utc> {
        "2026-08-02T00:00:00Z".parse().unwrap()
    }

    #[test]
    fn one_member_cannot_reach_the_reversal_threshold_alone() {
        let t0 = t0();
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
        let f = fold_reverse_quorum(&action, &objections, &roster, Some(policy(2, 3, 3600)), t0);
        assert_eq!(f.distinct_objectors, 1);
        assert_eq!(f.required, 2);
        assert_eq!(f.standing, ReverseQuorumStanding::WindowOpen);
        assert_eq!(f.counted_objection_ids, vec!["o1".to_string()]);
    }

    #[test]
    fn m_distinct_members_reverse_and_the_fold_names_its_evidence() {
        let t0 = t0();
        let action = action_row(t0);
        let roster: Vec<String> = ["a", "b", "c"].iter().map(|s| (*s).to_string()).collect();
        let objections = vec![objection("o1", "a", t0), objection("o2", "b", t0)];
        let f = fold_reverse_quorum(&action, &objections, &roster, Some(policy(2, 3, 3600)), t0);
        assert_eq!(f.standing, ReverseQuorumStanding::Reversed);
        assert_eq!(f.counted_objection_ids, vec!["o1".to_string(), "o2".into()]);
    }

    #[test]
    fn a_non_member_objection_is_never_counted_and_late_ones_miss_the_window() {
        let t0 = t0();
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
            &roster,
            Some(policy(2, 3, 3600)),
            late,
        );
        assert_eq!(f.distinct_objectors, 1);
        assert!(!f.window_open);
        assert_eq!(f.standing, ReverseQuorumStanding::Stood);
    }

    /// v62.0.0 (KR-fix35) — **a held row of a retired state is read by
    /// nothing**: an `objection:dismissed:v1` that names an objection no
    /// longer lifts it (protection sticks, the fail-secure direction), and an
    /// `objection:overruled:v1` / `objection:upheld:v1` ballot is no vote and
    /// counts as no objection.
    #[test]
    fn a_held_dismissal_or_ballot_lifts_nothing() {
        let t0 = t0();
        let action = action_row(t0);
        let roster: Vec<String> = ["a", "b", "c"].iter().map(|s| (*s).to_string()).collect();
        let retired = |id: &str, dimension: &str| {
            row(
                id,
                "a",
                serde_json::json!({
                    "dimension": dimension,
                    "cohort": "community",
                    "cohort_key_id": "c1",
                    "objects_to_attestation_id": "action-1",
                    "references_attestation_id": "action-1",
                    "dismisses_objection_id": "o1",
                    "ballot_on_objection_id": "o1",
                    "grounds": "earlier form",
                }),
                t0,
            )
        };
        let rows = vec![
            objection("o1", "a", t0),
            objection("o2", "b", t0),
            retired("d1", "objection:dismissed:v1"),
            retired("b1", "objection:overruled:v1"),
            retired("b2", "objection:upheld:v1"),
        ];
        let f = fold_reverse_quorum(&action, &rows, &roster, Some(policy(2, 3, 3600)), t0);
        assert_eq!(
            f.standing,
            ReverseQuorumStanding::Reversed,
            "the dismissal lifts nothing: {f:?}"
        );
        assert_eq!(f.counted_objection_ids, vec!["o1".to_string(), "o2".into()]);
        for r in &rows[2..] {
            assert!(!is_vote_row(r), "{} is no vote", r.attestation_id);
        }
        // The serialized fold carries none of the deleted members.
        let json = serde_json::to_value(&f).unwrap();
        for gone in [
            "dismissed_objection_ids",
            "steward_deadline",
            "escalation",
            "escalated_dismissed_objection_ids",
        ] {
            assert!(json.get(gone).is_none(), "{gone} is gone: {json}");
        }
    }

    #[test]
    fn an_ungoverned_cohort_folds_to_not_governed_rather_than_a_guessed_window() {
        let t0 = t0();
        let action = action_row(t0);
        let roster: Vec<String> = ["a", "b"].iter().map(|s| (*s).to_string()).collect();
        let f = fold_reverse_quorum(&action, &[objection("o1", "a", t0)], &roster, None, t0);
        assert_eq!(f.standing, ReverseQuorumStanding::NotGoverned);
        assert_eq!(f.required, 0);
        assert!(f.policy.is_none());
    }

    // DELETED (KR-fix35; Constitution: `objection:{state}` is CLOSED at
    // assent | raised, dismissed / upheld / overruled are not in this form):
    // the steward-tier and escalation tests of CIRISPersist#591 —
    // `the_steward_tier_parses_and_round_trips` (now
    // `a_steward_tier_string_is_read_and_has_no_effect`),
    // `a_574_string_still_declares_no_steward_tier_at_all`,
    // `the_escalated_undo_can_never_become_a_one_of_n`,
    // `a_declared_floor_only_ever_raises_the_escalated_price`,
    // `an_empty_duty_holder_set_can_never_rule`,
    // `steward_and_escalation_tokens_match_serde_and_are_unique`,
    // `only_the_three_zeroes_escalate`,
    // `silence_is_its_own_outcome_and_suppresses_nothing`,
    // `awaiting_is_not_silence`, `an_upholding_ruling_closes_escalation`,
    // `an_overruling_ruling_does_not_close_escalation`,
    // `the_escalated_quorum_counts_respondents_and_not_the_roster`,
    // `a_pool_below_the_floor_resolves_nothing`,
    // `upholders_dilute_the_pool_they_join`,
    // `the_commons_can_uphold_and_it_confers_nothing`,
    // `the_actor_is_recused_from_the_pool_and_from_the_duty_bench`,
    // `a_moderator_cannot_rule_on_their_own_objection`,
    // `a_persons_rows_are_one_voice_or_none_and_no_instant_decides`,
    // `recusal_and_the_bench_are_persons`,
    // `a_ballot_dated_before_the_action_never_counts_and_now_is_no_input`,
    // `a_non_member_is_not_a_respondent`,
    // `an_already_dismissed_objection_is_not_escalated`,
    // `a_partitioned_node_converges_on_the_escalated_answer`, and
    // `a_verified_dismissal_removes_protection_and_the_fold_says_which`.
    // Each witnessed the deleted machinery itself; what covers the remaining
    // property: `a_held_dismissal_or_ballot_lifts_nothing` (a retired-state
    // row lifts nothing), `no_permutation_of_the_rows_changes_the_count`
    // (one voice per person, over objections), and the pre4 registry pin (a
    // new row of a retired state refused `namespace_vocab_value_unregistered`).

    /// A self roster's objection stays outside the cohort-vote rule.
    #[test]
    fn a_self_roster_objection_is_no_cohort_vote() {
        let mut env = objection_envelope(Cohort::SelfId, "f", "p", "no");
        let row_of = |env: serde_json::Value| row("x", "k", env, t0());
        assert!(
            !is_vote_row(&row_of(env.clone())),
            "the keys are the voters"
        );
        env[field::COHORT] = serde_json::json!(Cohort::Community.as_str());
        assert!(is_vote_row(&row_of(env)));
    }

    /// Who a persons fixture says the keys are: `m1b` is a live device of
    /// `m1`, `e1` a device that left `m1`, `a1` a device of the actor `m4`,
    /// and `m5b` a device of `m5`.
    fn fixture_selves() -> KeySelves {
        KeySelves::of_devices(&[
            ("m1", "m1b", false),
            ("m1", "e1", true),
            ("m4", "a1", false),
            ("m5", "m5b", false),
        ])
    }

    /// **I1531 (the fold).** Every order of six objection rows folds to one
    /// answer: two devices of one person, two of another, one seated member,
    /// a device that left its person. v62.0.0 (KR-fix35): over objections
    /// (the ballots it permuted before are deleted).
    #[test]
    fn no_permutation_of_the_rows_changes_the_count() {
        let selves = fixture_selves();
        let action = action_row(t0());
        let t = t0() + Duration::seconds(10);
        let roster: Vec<String> = (0..9).map(|i| format!("m{i}")).collect();
        let rows = [
            objection("o0", "m1", t),
            objection("o1", "m1b", t + Duration::seconds(1)),
            objection("o2", "m5", t + Duration::seconds(2)),
            objection("o3", "m5b", t + Duration::seconds(3)),
            objection("o4", "m2", t + Duration::seconds(4)),
            objection("o5", "e1", t + Duration::seconds(5)),
        ];
        let mut indices: Vec<usize> = (0..rows.len()).collect();
        let mut seen = std::collections::BTreeSet::new();
        permute(&mut indices, 0, &mut |order| {
            let objections: Vec<Attestation> = order.iter().map(|i| rows[*i].clone()).collect();
            let f = fold_reverse_quorum_over(&ReverseQuorumInputs {
                action: (&action).into(),
                objections: &objections,
                roster: &roster,
                policy: Some(policy(2, 9, 3600)),
                now: t0() + Duration::seconds(100),
                persons: selves.at(t0() + Duration::seconds(100)),
            });
            seen.insert((f.distinct_objectors, f.counted_objection_ids.clone()));
        });
        assert_eq!(seen.len(), 1, "720 orders, one answer: {seen:?}");
        let (objectors, _) = seen.iter().next().unwrap();
        assert!(
            *objectors <= 4,
            "two devices of one person are one objector: {seen:?}"
        );
    }

    fn permute(items: &mut Vec<usize>, from: usize, visit: &mut impl FnMut(&[usize])) {
        if from == items.len() {
            visit(items);
            return;
        }
        for i in from..items.len() {
            items.swap(from, i);
            permute(items, from + 1, visit);
            items.swap(from, i);
        }
    }

    /// A partitioned node sees the action but not the objections. It must
    /// converge on the SAME answer once they arrive — even long after the
    /// window closed. That is why the window is pinned to the ACTION and the
    /// fold is evaluated at read time.
    #[test]
    fn objections_arriving_after_the_window_still_reverse_the_action() {
        let t0 = t0();
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
        let f = fold_reverse_quorum(&action, &objections, &roster, p, much_later);
        assert!(!f.window_open, "the window is long closed");
        assert_eq!(
            f.standing,
            ReverseQuorumStanding::Reversed,
            "a late-arriving in-window objection set still reverses — the fold \
             is a function of the rows, never of when this node saw them"
        );
    }
}
