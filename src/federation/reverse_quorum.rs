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
//! # CIRISPersist#591 — silence is its own outcome
//!
//! #574 shipped the brake and left one case undecided: **the duty-holders do
//! not answer.** Then the outcome falls out of whichever default the window
//! resolves to — the brake stands indefinitely on one member's word, or it
//! lapses with nobody having judged it. Both are decisions; neither was made by
//! anybody. Non-response is the *normal* failure mode (moderator burnout is the
//! fediverse's dominant cause of instance death), and the adversarial case is a
//! duty-holder unreachable precisely because the objection concerns them.
//!
//! The cohort may now declare a **steward tier** —
//! `reverse_quorum:{m}/{n}:{window}+escalate:{steward_secs}:{floor}` — which
//! adds one deadline and one escalated path:
//!
//! ```text
//! t0 = the action's asserted_at
//! ├─ objection window ──────┤                     objections count here
//!                           ├─ steward window ────┤  appointed moderators rule here
//!                                                 └─ escalation opens, if no upholding
//!                                                    ruling was reached, to a quorum
//!                                                    of RESPONDENTS
//! ```
//!
//! Three properties, each load-bearing:
//!
//! **1. Silence is its own arm, on its own axis.** [`StewardTierStanding`] is a
//! SEPARATE enum from [`ReverseQuorumStanding`], because they answer two
//! questions — *does the action stand?* and *did the people carrying the duty
//! answer?* — and this repo's recurring defect class is one name carrying two
//! axes. Within that enum, [`StewardTierStanding::Silent`],
//! [`StewardTierStanding::Overruled`] and
//! [`StewardTierStanding::NoDutyHolders`] are three DIFFERENT zeroes and each
//! gets its own value: nobody answered / somebody answered but their answer was
//! an undo (and undos are never unilateral) / there was nobody to answer. The
//! same discipline as #565's typed refusals and
//! [`QuarantineState::Released`](super::quarantine::QuarantineState::Released)
//! being distinct from `NotQuarantined`. Silence is deliberately NOT an arm of
//! [`ObjectionRefusalReason`] or of [`DismissalDecision`] (which the issue
//! suggested): a refusal is a verdict on ONE admission attempt, and silence is a
//! property of an objection over TIME that refuses nothing and is nobody's act.
//!
//! **2. The escalated threshold counts RESPONDENTS, not the roster** —
//! [`escalated_dismissal_required`]. m-of-n over the full roster means an
//! inactive community can never resolve anything: the more absent members, the
//! more impossible the decision, which inverts exactly when it is needed.
//!
//! > **This is the OPPOSITE of the rule
//! > [`ownership_reclaim`](super::ownership_reclaim)'s `wa_quorum_over_body`
//! > applies (#578), and both are correct.** There, the denominator is the FULL
//! > seated WA roster and never the live subset, because on THAT path shrinking
//! > the denominator LOWERS the threshold, and the threshold is what stands
//! > between an adversary and somebody else's node — an attacker who can
//! > silence seats would otherwise shrink the body down to the seats they have
//! > captured. **Silence is a lever there and the condition being escalated
//! > past here.** The two rules protect against different attacks, so read the
//! > direction each one fails in, not the shape: #578's rule can only ever
//! > REFUSE more than CC requires (a node stays with its incumbent — the status
//! > quo); this one can only ever make an UNDO reachable that the roster's own
//! > absence had made unreachable — and it is bounded below by
//! > [`ESCALATION_RESPONDENT_FLOOR`] precisely so "reachable" never degrades to
//! > "one person decides".
//!
//! **3. It must not become a griefing lever.** The mitigations, and the ones
//! deliberately NOT taken, are on [`escalated_dismissal_required`] and
//! [`ESCALATION_RESPONDENT_FLOOR`]. The short version: escalation is not an
//! ACT — nobody performs it, it is derived from the passage of time over held
//! rows — so it cannot be farmed by acting more; the escalation instant is a
//! function of the ACTION's `asserted_at` and the cohort's declared windows
//! alone, so no objector can advance the clock; and the escalated undo is
//! floored at an absolute respondent count that no policy string can lower.
//!
//! # Which kind of op is escalation? (the standing accord-ops invariant)
//!
//! *Every governance operation is m-of-n or a reverse quorum, **never** a
//! 1-of-N capability grant.* Escalation classifies as follows, and every arm
//! stays inside the invariant:
//!
//! | act | who | threshold | direction |
//! |---|---|---|---|
//! | raise an objection | any ONE member | [`OBJECTION_THRESHOLD`] = 1 | protective |
//! | duty-holders uphold (escalation never opens) | the appointed moderators | [`ReverseQuorumPolicy::steward_ruling_threshold`] — a strict majority of the LIVE duty-holder set | protective |
//! | dismiss, ordinary | the roster | [`ReverseQuorumPolicy::dismissal_threshold`] | **undo** |
//! | dismiss, escalated (only on silence) | the respondents | [`escalated_dismissal_required`] — the SAME ratio, a smaller denominator, floored absolutely | **undo** |
//! | retract your own objection | its author | 1 | drops own protection |
//!
//! **Escalation itself is not an op**: no signature performs it, it grants
//! nobody anything, and the only thing it changes is which denominator the
//! *undo* is priced against. Every `1` in that table buys protection (the
//! fail-secure direction) and every undo is m-of-n — including the escalated
//! one, which is exactly what [`ESCALATION_RESPONDENT_FLOOR`] exists to
//! guarantee: without it, `strict_majority(1) == 1` and a respondent pool of one
//! would make the escalated undo a literal 1-of-N capability grant.
//!
//! # What is deliberately out of scope
//!
//! **Objection to the objection.** One level. A second level makes this a
//! governance system instead of a brake — a dismissal is not itself
//! objectionable. (The escalated ballot is not a second level: it does not
//! object to anything, it answers a question the duty-holders left unanswered,
//! and it can only ever suppress an objection or decline to.)
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
/// **The row registers the family, NOT the emitter rule.** CC's row carries
/// `reserved: false` and **no** `reserved_rule`; its description ends
/// *"Registered per CC 3.1.7 R2(a); emitter/composition elaboration rides #67."*
/// So [`authority_for`](super::namespace::registry::authority_for)`("objection:…")`
/// returns `ProducerSteward` / `reserved: None`, before and after the re-vendor
/// alike — contrast `accord:*`, whose row does carry `accord_holder-only`.
///
/// The cohort-member-only rule is therefore enforced by [`record_objection`] and
/// by nothing else. Nothing on this plane reads `.reserved`, and nothing should
/// start until the rule is on the row. Tracked in
/// [`MINTED_FAMILY_RULES_NOT_ON_THE_ROW`](super::admission::MINTED_FAMILY_RULES_NOT_ON_THE_ROW);
/// getting it onto the row rides CIRISConstitution#67.
pub const NAMESPACE_FAMILY: &str = "objection:{state}";

/// CIRISPersist#591 — the `scores` dimension an **upholding ballot**
/// carries: *"I hold that this objection stands."*
///
/// ONE proposition, read by two predicates — which is deliberately not the axis
/// fusion this repo gates against, because the proposition does not change with
/// the reader:
///
/// - authored by an **appointed moderator** at or before the steward deadline,
///   it is a duty-holder's ruling, and a strict majority of the live
///   duty-holder set means the matter was judged in time — escalation never
///   opens ([`StewardTierStanding::Upheld`]);
/// - authored by any roster member, it is a **respondent ballot** in the
///   escalated pool ([`EscalationOutcome::Upheld`]).
///
/// Both readings say the same thing about the objection; only *who signed* and
/// *when* differ, and each reading names its own denominator.
///
/// Lives under the existing [`NAMESPACE_FAMILY`] — a new dimension inside a
/// registered family, never a new family.
pub const DIMENSION_UPHELD: &str = "objection:upheld:v1";

/// CIRISPersist#591 — the `scores` dimension an **overruling ballot**
/// carries: *"I hold that this objection does not stand."*
///
/// Deliberately spelled `overruled` and **not** `dismissed`. A
/// [`DIMENSION_DISMISSAL`] row is the m-of-n act that lifts an objection by
/// itself and is priced at [`ReverseQuorumPolicy::dismissal_threshold`]; this
/// is one member's ballot, costs one signature, and has NO force on its own. A
/// single token meaning two prices is precisely the fusion #565 was filed to
/// end, so the two prices get two spellings.
pub const DIMENSION_OVERRULED: &str = "objection:overruled:v1";

/// **The absolute floor on the escalated undo — the mitigation that keeps it an
/// m-of-n instead of a capability grant.**
///
/// [`escalated_dismissal_required`] never returns less than this many distinct
/// respondents, whatever the ratio says and whatever the cohort declared. A
/// cohort may raise its own floor in the policy string; nothing can lower it,
/// and a policy string that tries is REFUSED at
/// [`ReverseQuorumPolicy::parse`] rather than silently clamped — the loud kind
/// of red, at the one parse door.
///
/// # Why THREE, and why a floor at all
///
/// The escalated threshold is a strict majority of the respondents, and
/// `strict_majority(1) == 1`. Without a floor, a respondent pool of one makes
/// the escalated undo a **literal 1-of-N capability grant** — the one shape the
/// repo's standing accord-ops invariant forbids outright — and a pool of two
/// makes it a 2-of-2 that two captured keys satisfy by themselves. Three is the
/// smallest count at which "a quorum of those who showed up" is a quorum of
/// anybody at all, and it is the same number CC's own m-of-n bodies bottom out
/// at. The floor is not a tuning knob; it is what makes the op classification
/// in the module doc TRUE.
///
/// # What this does and does not buy
///
/// Stated honestly, because an unmitigated escalation is worse than none: an
/// adversary holding three roster keys can lift an objection after the steward
/// window that would have cost a strict majority of the whole roster before it.
/// On a roster of nine that is three signatures instead of five. That is the
/// trade #591 asks for — the alternative is a commons whose undo is
/// unreachable in exactly the inactive community that needs it — and it is
/// bounded on all four sides:
///
/// 1. **The floor**, here, which no declaration can lower.
/// 2. **The ratio is not re-priced.** [`escalated_dismissal_required`] reuses
///    [`ReverseQuorumPolicy::dismissal_threshold`] verbatim and only swaps the
///    denominator, so a cohort that declared "it takes seven to lift a brake"
///    still needs seven; escalation buys a smaller denominator, never a weaker
///    rule.
/// 3. **Upholders dilute the pool.** A respondent is anyone who answered, in
///    EITHER direction, so honest members who show up to defend the objection
///    raise the denominator the attacker's strict majority is measured against.
/// 4. **It is all in the record.** Every ballot is an ordinary signed
///    `scores` row on the replication plane, attributable to its author, and
///    [`ReverseQuorumFold::escalation`] names every ballot it counted — so the
///    pattern "objections raised while the moderators were away, dismissed by
///    the same three keys" is visible to anyone holding the rows, on every node,
///    without a control loop.
///
/// # A mitigation deliberately REJECTED: rate-limiting the objector
///
/// #591 suggests "a rate limit on objections per objector per window". Refused,
/// for two reasons.
///
/// It does not fit the threat. **Escalation is not an act** — it is derived
/// from the passage of time over held rows, so an objector cannot cause it,
/// cannot advance it (the deadline is a function of the ACTION's `asserted_at`
/// and the cohort's declared windows, never of anything an objector writes),
/// and gains nothing by raising more objections: the escalated undo needs
/// respondents, and objections are not respondents. Objection SPAM is real, but
/// it is a load problem, and persist already meters load on the capacity plane
/// ([`capacity`](super::capacity)) where it belongs.
///
/// And it would break the one rule this module may not break. A per-objector
/// rate limit makes the PROTECTIVE side conditional on the objector's unrelated
/// history — a member's brake refused because of what they did about some other
/// action. In a burning-out community the last member still paying attention is
/// exactly the member who has objected most recently, and rate-limiting is a
/// gate that bites hardest on them. Protection is 1-of-N unconditionally or it
/// is not protection.
pub const ESCALATION_RESPONDENT_FLOOR: usize = 3;

/// The infix that opens the optional steward-tier declaration in a
/// `consensus_protocol` string:
/// `reverse_quorum:{m}/{n}:{window}+escalate:{steward_secs}:{floor}`.
///
/// A SUFFIX rather than a new prefix, so every #574 string keeps parsing to
/// exactly what it meant (no steward tier, no escalation) and adopting the
/// tier is a visible, deliberate edit to the cohort's own declaration. The
/// sqlite `federation_communities` CHECK admits it unchanged
/// (`GLOB 'reverse_quorum:*/*:*'` is coarse by V116's design — `*` spans `:`
/// and `+`); the postgres CHECK is an anchored regex and is widened by V120.
pub const ESCALATE_INFIX: &str = "+escalate:";

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
    /// CIRISPersist#591 — on a BALLOT envelope
    /// ([`DIMENSION_UPHELD`](super::DIMENSION_UPHELD) /
    /// [`DIMENSION_OVERRULED`](super::DIMENSION_OVERRULED)): which objection
    /// this ballot is cast on.
    ///
    /// A distinct name from [`DISMISSES`], deliberately: `dismisses_objection_id`
    /// rides a row that lifts an objection by itself, and reusing it on a row
    /// that does not would be one field name carrying two forces.
    pub const BALLOT_ON: &str = "ballot_on_objection_id";
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
    /// CIRISPersist#591 — the optional steward tier. `None` is every
    /// #574 string, and means exactly what it meant then: no deadline, no
    /// duty-holder ruling, no escalation. A cohort that declared none does not
    /// get one invented for it — the same refusal-over-default discipline
    /// [`ObjectionRefusalReason::NotGoverned`] applies one layer out.
    pub steward: Option<StewardTier>,
}

/// CIRISPersist#591 — the parsed `+escalate:{steward_secs}:{floor}`
/// half of a policy string: the duty-holders' deadline and the cohort's own
/// respondent floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StewardTier {
    /// How long AFTER the objection window closes the appointed moderators have
    /// to reach an upholding ruling.
    ///
    /// Measured from the objection window's close, not from the objection —
    /// which is what makes the escalation instant a pure function of the
    /// ACTION's `asserted_at` and the cohort's declaration. An objector signs
    /// their own `asserted_at`, so a deadline keyed on the objection would let
    /// an attacker back-date one and open escalation on arrival; keyed here,
    /// nothing an objector writes can move the clock by a second. It also means
    /// the duty-holders rule on a COMPLETE objection set rather than a moving
    /// one, and that the whole cohort shares ONE deadline per action instead of
    /// one per objection.
    pub window_secs: u64,
    /// The cohort's declared floor on the escalated respondent count. Validated
    /// at [`ReverseQuorumPolicy::parse`] to be at least
    /// [`ESCALATION_RESPONDENT_FLOOR`]: a cohort may demand MORE participation
    /// before its commons may act on silence, never less.
    pub respondent_floor: usize,
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
    /// CIRISPersist#591 additionally parses the optional
    /// [`ESCALATE_INFIX`] suffix, and refuses two more degenerate shapes:
    ///
    /// - a declared floor **below** [`ESCALATION_RESPONDENT_FLOOR`] — a
    ///   declaration that tries to talk the escalated undo down toward a 1-of-N
    ///   is refused at the door rather than silently clamped at use, so the
    ///   cohort learns its string is wrong instead of quietly getting a
    ///   different policy than it wrote. (The clamp is applied at use as well —
    ///   see [`escalated_dismissal_required`] — because a `ReverseQuorumPolicy`
    ///   built in code never passed this door.)
    /// - a malformed suffix (missing floor, non-numeric parts, or the infix
    ///   present with nothing after it).
    ///
    /// A steward window of `0` IS accepted, on the same reasoning a `0`
    /// objection window is: "the duty-holders get no grace" is a coherent, if
    /// severe, declaration, and the fold reports it honestly.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let tail = s.strip_prefix(super::types::consensus_protocol::REVERSE_QUORUM_PREFIX)?;
        // The steward tier is split off FIRST: `{window}` would otherwise
        // swallow the whole suffix and fail to parse as seconds, which would
        // refuse the string — safe, but for the wrong reason and with the wrong
        // message.
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
        let steward = match escalate {
            None => None,
            Some(rest) => {
                let (secs, floor) = rest.split_once(':')?;
                let steward_window: u64 = secs.parse().ok()?;
                let respondent_floor: usize = floor.parse().ok()?;
                if respondent_floor < ESCALATION_RESPONDENT_FLOOR {
                    return None;
                }
                Some(StewardTier {
                    window_secs: steward_window,
                    respondent_floor,
                })
            }
        };
        Some(Self {
            m,
            n,
            window_secs,
            steward,
        })
    }

    /// Render back to the canonical `consensus_protocol` string, steward tier
    /// included when one was declared.
    #[must_use]
    pub fn to_protocol_string(&self) -> String {
        let base = format!(
            "{}{}/{}:{}",
            super::types::consensus_protocol::REVERSE_QUORUM_PREFIX,
            self.m,
            self.n,
            self.window_secs
        );
        match self.steward {
            None => base,
            Some(tier) => format!(
                "{base}{ESCALATE_INFIX}{}:{}",
                tier.window_secs, tier.respondent_floor
            ),
        }
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

    /// CIRISPersist#591 — the instant the appointed moderators' answer
    /// is due for an action asserted at `asserted_at`: the objection window's
    /// close plus [`StewardTier::window_secs`]. `None` when the cohort declared
    /// no steward tier.
    ///
    /// Pinned to the ACTION and the DECLARATION, and to nothing else — see
    /// [`StewardTier::window_secs`] for why that is the anti-griefing property
    /// and not merely a simplification.
    #[must_use]
    pub fn steward_deadline(&self, asserted_at: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let tier = self.steward?;
        let (_, window_closes) = self.window(asserted_at);
        // Saturating, in the same fail-SAFE direction `window` saturates: a
        // deadline beyond representable time never arrives, so escalation never
        // opens, so the undo stays at the full-roster price.
        let secs = i64::try_from(tier.window_secs).unwrap_or(i64::MAX);
        Some(
            window_closes
                .checked_add_signed(Duration::try_seconds(secs).unwrap_or(Duration::MAX))
                .unwrap_or(DateTime::<Utc>::MAX_UTC),
        )
    }

    /// CIRISPersist#591 — how many distinct appointed moderators must
    /// rule the same way for the duty-holders to have ANSWERED: a strict
    /// majority of the live duty-holder set, never fewer than one.
    ///
    /// A strict majority rather than "any one steward", because an
    /// upholding ruling closes the commons' escalated undo, and a single
    /// duty-holder able to close it alone would be a 1-of-N grant on the
    /// escalation plane. `n = 1` (the §11.11 minimum, one appointed moderator)
    /// makes this `1-of-1`, which is an m-of-n with `n = 1` and not a 1-of-N —
    /// the community appointed exactly one person to the duty and that person
    /// did it.
    ///
    /// The `.max(1)` is a **pin, not the guard** — stated precisely, because a
    /// comment claiming a clamp is load-bearing when it is not is worse than no
    /// comment. `strict_majority` is `n / 2 + 1` in the pinned verify, so
    /// `strict_majority(0)` is already 1 and a mutation run deleting the
    /// `.max(1)` turns nothing red. What actually stops an EMPTY duty-holder set
    /// from "ruling" with zero ballots (and thereby blocking escalation forever
    /// on the community that has no moderators at all — the precise inversion
    /// #591 exists to close) is a threshold of at least one, whoever provides
    /// it. The clamp holds that true if verify's definition ever changes, and
    /// [`tests::an_empty_duty_holder_set_can_never_rule`] pins the dependency's
    /// behaviour so a re-pin that changed it would be caught here rather than
    /// in a commons.
    #[must_use]
    pub fn steward_ruling_threshold(&self, duty_holders: usize) -> usize {
        ciris_verify_core::accord_genesis::strict_majority(duty_holders).max(1)
    }
}

/// CIRISPersist#591 — **the escalated undo's price**: how many
/// distinct respondents must overrule an objection once the duty-holders have
/// let the deadline pass.
///
/// ```text
/// max( dismissal_threshold(RESPONDENTS) , declared floor , ESCALATION_RESPONDENT_FLOOR )
/// ```
///
/// # One ratio, two denominators
///
/// The ONLY thing escalation changes is the denominator. The ratio is
/// [`ReverseQuorumPolicy::dismissal_threshold`] itself — the same function the
/// ordinary undo door and the read-time re-derivation run, called with the
/// respondent count in place of the roster count. So a cohort that declared
/// `reverse_quorum:7/9` still needs seven signatures on the escalated path
/// (`max(7, …)`); what it does NOT need is seven out of a roster where six
/// members have stopped reading their mail. A policy string can no more talk
/// the escalated threshold down than the ordinary one, because it is the same
/// number derived from the same declaration — which is also why this is a
/// wrapper and not a second threshold function. (#574's note on
/// [`dismissal_required`] is the same rule: one place decides, or a row is
/// admitted under one price and re-priced under another on the next read.)
///
/// # Why respondents and not the roster (and why that is not #578's bug)
///
/// Counting an escalated m-of-n against the FULL roster means the more members
/// have gone quiet, the more impossible any decision becomes — the threshold
/// inverts exactly when it is needed, and a burned-out commons seizes with a
/// brake on. Counting against those who actually answered lets the commons act
/// at the participation it really has.
///
/// [`ownership_reclaim`](super::ownership_reclaim) does the OPPOSITE on the WA
/// reclaim path (#578) and is right to: there, shrinking the denominator LOWERS
/// the bar to take somebody's node, so an adversary who can silence seats could
/// shrink the body to the seats they hold. The distinction is what silence
/// *is* on each path — a lever the attacker pulls there, the condition being
/// escalated past here — and which way each rule fails: #578's can only refuse
/// more than CC requires (the node stays with its incumbent), and this one can
/// only make reachable an undo that absence had made unreachable, bounded below
/// by [`ESCALATION_RESPONDENT_FLOOR`]. Two rules, two attacks; neither is the
/// other's bug.
#[must_use]
pub fn escalated_dismissal_required(policy: &ReverseQuorumPolicy, respondents: usize) -> usize {
    let declared_floor = policy
        .steward
        .map_or(ESCALATION_RESPONDENT_FLOOR, |t| t.respondent_floor);
    policy
        .dismissal_threshold(respondents)
        .max(declared_floor)
        .max(ESCALATION_RESPONDENT_FLOOR)
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
    /// CIRISPersist#591 — a BALLOT ([`DIMENSION_UPHELD`] /
    /// [`DIMENSION_OVERRULED`]) named a cohort whose `consensus_protocol`
    /// declares a `reverse_quorum:*` but no `+escalate:` steward tier. There is
    /// no deadline to be silent past and no escalated pool to count, so the row
    /// would be stored and never read by anything — the admitted-but-inert
    /// shape [`Self::NotFiledAgainstActor`] exists to refuse, one declaration
    /// out.
    StewardTierNotAdopted,
    /// CIRISPersist#591 — the ballot's author IS the author of the
    /// objected-to action. **Recusal**: the one participant with a guaranteed
    /// conflict of interest does not get to vote on the objection to their own
    /// act, and on the escalated path — thin by construction — a single
    /// self-interested ballot is a third of [`ESCALATION_RESPONDENT_FLOOR`].
    ///
    /// Refused at the door rather than merely ignored by the fold, on the
    /// [`Self::NotFiledAgainstActor`] principle: a row that will never be
    /// counted should say so on arrival instead of sitting in the corpus
    /// looking like participation.
    ActorRecused,
    /// CIRISPersist#591 — the ballot's `asserted_at` predates the
    /// action it judges. A judgement cannot be older than its subject, and the
    /// escalated pool is the one place a back-dated row would be worth
    /// forging.
    BallotPredatesAction,
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
            Self::StewardTierNotAdopted => "steward_tier_not_adopted",
            Self::ActorRecused => "actor_recused",
            Self::BallotPredatesAction => "ballot_predates_action",
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
        Self::StewardTierNotAdopted,
        Self::ActorRecused,
        Self::BallotPredatesAction,
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

/// CIRISPersist#591 — **did the people carrying the duty answer?**
///
/// A SEPARATE axis from [`ReverseQuorumStanding`], which answers *does the
/// action stand?* Fusing them would put "the action stands" and "nobody looked"
/// in one value, and the entire point of #591 is that those are different
/// facts. Resolved per OBJECTION (a ruling names one objection), against the
/// LIVE duty-holder set, at read time — like every other authority in this repo.
///
/// **Three of these arms are zeroes and none of them share a value**, because
/// a failing commons and a healthy one must not read identically:
/// [`Self::Silent`] (nobody answered), [`Self::Overruled`] (somebody answered,
/// but their answer was an undo, and undos are never unilateral), and
/// [`Self::NoDutyHolders`] (there was nobody to answer). All three open
/// escalation; they are three different diagnoses of why.
///
/// Closed, snake_case serde tokens with no catch-all, and **APPEND-ONLY** —
/// the [`ObjectionRefusalReason`] discipline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StewardTierStanding {
    /// The cohort's `consensus_protocol` declares no `+escalate:` tier. There is
    /// no deadline, no ruling and no escalation — #574 semantics exactly, which
    /// is what every string written before v25.2.0 keeps meaning.
    NotAdopted,
    /// A tier IS declared, and this node resolves ZERO appointed moderators for
    /// the cohort — including the case where the only one is
    /// [recused](ObjectionRefusalReason::ActorRecused) because the objection is
    /// about their own action. A strictly more informative [`Self::Silent`]:
    /// nobody was silent, because nobody was there. Escalation opens at the
    /// deadline.
    NoDutyHolders,
    /// The deadline has not passed on this node's clock and no ruling has been
    /// reached yet. The duty-holders may still answer; escalation has not
    /// opened. **Not a zero** — this is the healthy in-progress state, and
    /// conflating it with [`Self::Silent`] would escalate every objection the
    /// moment it was raised.
    Awaiting,
    /// A strict majority of the live duty-holder set
    /// ([`ReverseQuorumPolicy::steward_ruling_threshold`]) upheld the objection
    /// at or before the deadline. The matter WAS judged, by named people, on the
    /// record — so escalation does not open. Nothing is granted by this: an
    /// upholding ruling cannot reverse the action (it adds no objectors), it
    /// only declines to open a cheaper undo.
    Upheld,
    /// A strict majority of the live duty-holder set OVERRULED the objection at
    /// or before the deadline — and escalation opens anyway.
    ///
    /// Overruling is an UNDO, and an undo priced at a majority of a small
    /// appointed body would be cheaper than the roster's own
    /// [`ReverseQuorumPolicy::dismissal_threshold`] — on a nine-member commons
    /// with one moderator it would be a literal 1-of-N lift. So the duty-holders
    /// get no undo power the roster does not have: their overruling ballots are
    /// recorded, count as respondent ballots once escalation opens, and lift
    /// nothing by themselves. This arm exists so that "the stewards said it was
    /// groundless" never reads as "the stewards said nothing".
    Overruled,
    /// The deadline passed with no ruling either way. **Silence.** Escalation
    /// opens.
    Silent,
}

impl StewardTierStanding {
    /// The **stable program token** — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotAdopted => "not_adopted",
            Self::NoDutyHolders => "no_duty_holders",
            Self::Awaiting => "awaiting",
            Self::Upheld => "upheld",
            Self::Overruled => "overruled",
            Self::Silent => "silent",
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::NotAdopted,
        Self::NoDutyHolders,
        Self::Awaiting,
        Self::Upheld,
        Self::Overruled,
        Self::Silent,
    ];

    /// **The one predicate that decides whether the commons may act on
    /// silence.** Read by the fold and by nothing else, so "escalation is open"
    /// has exactly one definition.
    ///
    /// True for the three zeroes ([`Self::Silent`], [`Self::Overruled`],
    /// [`Self::NoDutyHolders`]); false while the duty-holders may still answer
    /// ([`Self::Awaiting`]), once they have upheld ([`Self::Upheld`]), and where
    /// no tier was declared at all ([`Self::NotAdopted`]).
    #[must_use]
    pub const fn escalates(&self) -> bool {
        matches!(self, Self::Silent | Self::Overruled | Self::NoDutyHolders)
    }
}

impl std::fmt::Display for StewardTierStanding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CIRISPersist#591 — **what the commons said, once it was asked.**
///
/// The second half of the split: [`StewardTierStanding`] says whether the
/// question reached the commons at all, this says what came back. Two enums
/// because they are two questions — a single fused enum would have to spell
/// "the duty-holders were silent AND the respondents have not reached the
/// floor" as one token, and the next reader would have to guess which half of
/// it was the problem.
///
/// Closed, snake_case, no catch-all, APPEND-ONLY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscalationOutcome {
    /// Escalation did not open for this objection — see the accompanying
    /// [`StewardTierStanding`] for which of the five reasons.
    NotEscalated,
    /// Open, and undecided: the respondents are below
    /// [`ESCALATION_RESPONDENT_FLOOR`], or neither side reached
    /// [`escalated_dismissal_required`].
    ///
    /// **The fail-secure arm.** An unresolved escalation changes nothing: the
    /// objection stands exactly as it did, protection sticks, and the ordinary
    /// full-roster undo remains available. `respondents == 0` and
    /// `respondents == 4-but-split` are both this arm, and that is not two
    /// zeroes sharing a value — the counts are on the face of
    /// [`ObjectionEscalation`], so the two read differently without needing two
    /// tokens.
    Unresolved,
    /// The respondents ruled that the objection STANDS. Confers nothing: it
    /// cannot reverse the action (an upholding ballot is not an objection and
    /// never becomes one), it defeats a competing overruling pool, and it makes
    /// "this brake was judged" distinguishable from "this brake was never
    /// looked at" — which is the whole of what #591 asks the record to be able
    /// to say.
    Upheld,
    /// The respondents ruled that the objection does NOT stand. **The only arm
    /// with force**: the objection is suppressed for the count exactly as a
    /// quorum-verified [`DIMENSION_DISMISSAL`] suppresses it, and its id is
    /// reported separately in
    /// [`ReverseQuorumFold::escalated_dismissed_objection_ids`] so the two
    /// prices are never confused in the evidence.
    Dismissed,
}

impl EscalationOutcome {
    /// The **stable program token** — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::NotEscalated => "not_escalated",
            Self::Unresolved => "unresolved",
            Self::Upheld => "upheld",
            Self::Dismissed => "dismissed",
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::NotEscalated,
        Self::Unresolved,
        Self::Upheld,
        Self::Dismissed,
    ];
}

impl std::fmt::Display for EscalationOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CIRISPersist#591 — the steward-tier and escalation record for ONE
/// objection, with the numbers behind both verdicts. The fold names its
/// evidence here exactly as [`ReverseQuorumFold`] does for the objection count.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObjectionEscalation {
    /// The objection this record is about.
    pub objection_id: String,
    /// Did the duty-holders answer, and if not, why not.
    pub steward: StewardTierStanding,
    /// What the commons said, if it was asked.
    pub outcome: EscalationOutcome,
    /// The live appointed-moderator count the ruling threshold was derived from,
    /// AFTER recusal.
    pub duty_holders: usize,
    /// [`ReverseQuorumPolicy::steward_ruling_threshold`] for that set.
    pub steward_ruling_required: usize,
    /// Distinct roster members (recused actor excluded) whose ballot on this
    /// objection this node holds — the escalated DENOMINATOR.
    pub respondents: usize,
    /// [`escalated_dismissal_required`] for that respondent count.
    pub required: usize,
    /// Distinct respondents whose governing ballot upholds.
    pub uphold_ballots: usize,
    /// Distinct respondents whose governing ballot overrules.
    pub overrule_ballots: usize,
    /// The `attestation_id`s of the GOVERNING ballots — one per respondent,
    /// sorted. A member who balloted twice contributes only the ballot that
    /// counted, so this list is the evidence for the counts above and not
    /// merely everything that arrived.
    pub counted_ballot_ids: Vec<String>,
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
    /// CIRISPersist#591 — the instant the appointed moderators' answer
    /// was due (`window_closes_at + steward_window`), or `None` when the cohort
    /// declared no steward tier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steward_deadline: Option<DateTime<Utc>>,
    /// CIRISPersist#591 — the per-objection steward/escalation record,
    /// sorted by `objection_id`. Empty when no tier is declared, and empty on
    /// the [`ReverseQuorumStanding::NotGoverned`] arm.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalation: Vec<ObjectionEscalation>,
    /// CIRISPersist#591 — the `attestation_id`s of objections excluded
    /// because the ESCALATED respondent pool overruled them, sorted.
    ///
    /// Deliberately its own list rather than merged into
    /// [`Self::dismissed_objection_ids`]: the two suppressions were bought at
    /// two different prices against two different denominators, and an auditor
    /// asking "what did this commons decide while its moderators were away"
    /// must be able to see it without re-deriving anything.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub escalated_dismissed_objection_ids: Vec<String>,
}

/// CIRISPersist#591 — **the fold's whole input**, as a type.
///
/// #574's invariant, made structural: the standing of an action is a pure
/// function of `(action, objections, dismissals, ballots, roster, duty-holders,
/// policy, now)` and of nothing else — no clock of its own, no timer, no
/// control loop, no state advanced at write time. A node partitioned for the
/// whole steward window computes the same answer as everyone else the moment
/// the rows arrive, which is the property that makes escalation safe to derive
/// instead of announce.
///
/// If a future arm needs something that is not in this struct, that is the
/// signal it belongs in a different layer.
#[derive(Debug, Clone, Copy)]
pub struct ReverseQuorumInputs<'a> {
    /// The commons action under objection.
    pub action: &'a Attestation,
    /// Every objection row this node holds against it.
    pub objections: &'a [Attestation],
    /// **Already quorum-verified** dismissals — see
    /// [`fold_reverse_quorum_over`]'s contract.
    pub dismissals: &'a [Attestation],
    /// Ballot rows ([`DIMENSION_UPHELD`] / [`DIMENSION_OVERRULED`]).
    pub ballots: &'a [Attestation],
    /// The cohort's live, revocation-folded roster.
    pub roster: &'a [String],
    /// The cohort's live appointed moderators
    /// ([`appointed_moderators_of`](super::admission::appointed_moderators_of)).
    /// Empty is a legible state, not an error — see
    /// [`StewardTierStanding::NoDutyHolders`].
    pub duty_holders: &'a [String],
    /// The cohort's parsed `consensus_protocol`.
    pub policy: Option<ReverseQuorumPolicy>,
    /// The read-time instant every window is compared against.
    pub now: DateTime<Utc>,
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
/// # CIRISPersist#591
///
/// This six-argument form is the **no-steward-tier instantiation** of
/// [`fold_reverse_quorum_over`] — one implementation, one set of counting
/// rules, called with an empty ballot list and an empty duty-holder set. Its
/// #574 behaviour is unchanged and its signature is untouched.
///
/// Passing a policy that DOES declare a steward tier through this form is safe
/// but blunt: with no duty-holders and no ballots every objection folds to
/// [`StewardTierStanding::NoDutyHolders`] +
/// [`EscalationOutcome::Unresolved`], which suppresses nothing — the
/// fail-secure direction. Hosts should use
/// [`resolve_reverse_quorum`], which is the only entry point that derives the
/// duty-holder set from this node's own verified state.
#[must_use]
pub fn fold_reverse_quorum(
    action: &Attestation,
    objections: &[Attestation],
    dismissals: &[Attestation],
    roster: &[String],
    policy: Option<ReverseQuorumPolicy>,
    now: DateTime<Utc>,
) -> ReverseQuorumFold {
    fold_reverse_quorum_over(&ReverseQuorumInputs {
        action,
        objections,
        dismissals,
        ballots: &[],
        roster,
        duty_holders: &[],
        policy,
        now,
    })
}

/// CIRISPersist#591 — **the pure fold, in full**: the one
/// implementation of every counting rule on this plane, over
/// [`ReverseQuorumInputs`] and nothing else.
///
/// See [`fold_reverse_quorum`] for the counting rules of the #574 half and the
/// `dismissals` contract (this function cannot verify an m-of-n either — it has
/// no directory — so [`resolve_reverse_quorum`] remains the only supported way
/// to build that list).
///
/// # The escalation pass
///
/// For each objection that survives the ordinary filters AND was not suppressed
/// by a quorum-verified dismissal, in this order:
///
/// 1. **Recusal.** The action's author is struck from both the duty-holder set
///    and the respondent pool; the objection's own author is additionally
///    struck from the duty-holder set for THAT objection. Recusal removes the
///    seat, numerator and denominator both — so a commons whose only appointed
///    moderator is the actor folds to
///    [`StewardTierStanding::NoDutyHolders`] and escalates, rather than letting
///    that moderator rule on the objection to their own act.
/// 2. **The duty-holders' ruling**, over ballots asserted at or before the
///    deadline. An upholding ruling at
///    [`ReverseQuorumPolicy::steward_ruling_threshold`] closes escalation; an
///    overruling one is recorded and does not, because it is an undo.
/// 3. **The respondent pool**, over every ballot from a roster member, with no
///    deadline — a bounded ballot window would recreate the exact
///    lapse-without-a-judgement failure #591 is about, one layer down. A
///    duty-holder who turns up after the deadline participates here as an
///    ordinary member; silence at the deadline is a fact of the record and is
///    not undone by arriving late.
///
/// Ballots are counted **one per author**, by the same `(asserted_at,
/// protective-side-wins, attestation_id)` ordering
/// [`fold_quarantine`](super::quarantine::fold_quarantine) uses — so a member
/// may change their mind (the latest ballot governs) and a same-instant
/// contradiction resolves fail-secure to UPHELD, deterministically, on every
/// node.
///
/// A ballot must be dated at or after the action it judges and at or before
/// `now`. The `now` bound is the one asymmetry with the objection count, and it
/// is deliberate: an objection's `asserted_at` is already bounded above by the
/// objection window, so a future-dated one cannot count, while a ballot has no
/// upper window — without this bound three ballots dated 2099 would resolve an
/// escalation today.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn fold_reverse_quorum_over(inputs: &ReverseQuorumInputs<'_>) -> ReverseQuorumFold {
    let &ReverseQuorumInputs {
        action,
        objections,
        dismissals,
        ballots,
        roster,
        duty_holders,
        policy,
        now,
    } = inputs;
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
            steward_deadline: None,
            escalation: Vec::new(),
            escalated_dismissed_objection_ids: Vec::new(),
        };
    };

    let (opens, closes) = policy.window(action.asserted_at);
    let required = policy.reversal_threshold(roster.len());
    let steward_deadline = policy.steward_deadline(action.asserted_at);

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
    let mut escalated_ids: Vec<String> = Vec::new();
    let mut escalation: Vec<ObjectionEscalation> = Vec::new();
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
            // Already lifted at the full-roster price. Escalating a suppressed
            // objection would be asking the commons a question that has an
            // answer, so no record is produced for it.
            dismissed_ids.push(o.attestation_id.clone());
            continue;
        }
        if policy.steward.is_some() {
            let record = escalate_objection(action, o, ballots, roster, duty_holders, &policy, now);
            let overruled = record.outcome == EscalationOutcome::Dismissed;
            escalation.push(record);
            if overruled {
                escalated_ids.push(o.attestation_id.clone());
                continue;
            }
        }
        // DISTINCT objectors — one member is one objection, however many rows
        // that member authored.
        if objectors.insert(o.attesting_key_id.as_str()) {
            counted_ids.push(o.attestation_id.clone());
        }
    }
    counted_ids.sort();
    dismissed_ids.sort();
    escalated_ids.sort();
    escalation.sort_by(|a, b| a.objection_id.cmp(&b.objection_id));

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
        steward_deadline,
        escalation,
        escalated_dismissed_objection_ids: escalated_ids,
    }
}

/// Is this row a ballot on `objection`, cast about `action`, dated sanely
/// relative to both the action and `now`?
fn is_ballot_on(
    row: &Attestation,
    action: &Attestation,
    objection: &Attestation,
    now: DateTime<Utc>,
) -> bool {
    matches!(
        envelope_str(row, "dimension"),
        Some(DIMENSION_UPHELD | DIMENSION_OVERRULED)
    ) && envelope_str(row, field::BALLOT_ON) == Some(objection.attestation_id.as_str())
        && envelope_str(row, field::OBJECTS_TO) == Some(action.attestation_id.as_str())
        && row.asserted_at >= action.asserted_at
        && row.asserted_at <= now
}

/// One ballot per author — the GOVERNING one, by the `(asserted_at,
/// protective-side-wins, attestation_id)` ordering
/// [`fold_quarantine`](super::quarantine::fold_quarantine) uses.
///
/// Sorts ASCENDING and the last write per author wins, so `uphold_rank` is 1
/// for an upholding ballot and 0 for an overruling one: the protective side
/// sorts LAST, i.e. a member whose two ballots share an instant is counted as
/// having upheld. Fail-secure, deterministic, and identical on every node.
fn governing_ballots<'a>(
    candidates: &[&'a Attestation],
    eligible: &[String],
    not_after: Option<DateTime<Utc>>,
) -> std::collections::BTreeMap<&'a str, &'a Attestation> {
    let mut rows: Vec<&'a Attestation> = candidates
        .iter()
        .copied()
        .filter(|b| eligible.iter().any(|k| k == &b.attesting_key_id))
        .filter(|b| not_after.is_none_or(|t| b.asserted_at <= t))
        .collect();
    let uphold_rank =
        |b: &Attestation| u8::from(envelope_str(b, "dimension") == Some(DIMENSION_UPHELD));
    rows.sort_by(|a, b| {
        a.asserted_at
            .cmp(&b.asserted_at)
            .then_with(|| uphold_rank(a).cmp(&uphold_rank(b)))
            .then_with(|| a.attestation_id.cmp(&b.attestation_id))
    });
    let mut out: std::collections::BTreeMap<&'a str, &'a Attestation> =
        std::collections::BTreeMap::new();
    for b in rows {
        out.insert(b.attesting_key_id.as_str(), b);
    }
    out
}

/// How many of these governing ballots uphold, and how many overrule.
fn tally(governing: &std::collections::BTreeMap<&str, &Attestation>) -> (usize, usize) {
    let mut uphold = 0usize;
    let mut overrule = 0usize;
    for b in governing.values() {
        match envelope_str(b, "dimension") {
            Some(DIMENSION_UPHELD) => uphold += 1,
            Some(DIMENSION_OVERRULED) => overrule += 1,
            _ => {}
        }
    }
    (uphold, overrule)
}

/// The steward-tier and escalation record for ONE objection — see
/// [`fold_reverse_quorum_over`] for the ordering and the reasoning.
fn escalate_objection(
    action: &Attestation,
    objection: &Attestation,
    ballots: &[Attestation],
    roster: &[String],
    duty_holders: &[String],
    policy: &ReverseQuorumPolicy,
    now: DateTime<Utc>,
) -> ObjectionEscalation {
    // Re-derived here rather than passed in: the deadline is a function of the
    // action and the declaration, so there is no version of it a caller could
    // supply that this could not compute — and one that disagreed would be a
    // silent escalation-clock bypass.
    let steward_deadline = policy.steward_deadline(action.asserted_at);
    // ── RECUSAL. The actor has a guaranteed conflict on their own action; the
    //    objector has one on their own objection. A recusal removes the seat
    //    from BOTH sides of the fraction, which is what makes it a recusal and
    //    not a veto.
    let actor = action.attesting_key_id.as_str();
    let objector = objection.attesting_key_id.as_str();
    let seated_duty: Vec<String> = duty_holders
        .iter()
        .filter(|k| k.as_str() != actor && k.as_str() != objector)
        .cloned()
        .collect();
    let seated_roster: Vec<String> = roster
        .iter()
        .filter(|k| k.as_str() != actor)
        .cloned()
        .collect();

    let relevant: Vec<&Attestation> = ballots
        .iter()
        .filter(|b| is_ballot_on(b, action, objection, now))
        .collect();

    // ── (2) THE DUTY-HOLDERS' RULING, in time.
    let ruling_required = policy.steward_ruling_threshold(seated_duty.len());
    let ruling = governing_ballots(&relevant, &seated_duty, steward_deadline);
    let (ruled_uphold, ruled_overrule) = tally(&ruling);
    let deadline_passed = steward_deadline.is_some_and(|d| now >= d);
    let steward = if ruled_uphold >= ruling_required {
        StewardTierStanding::Upheld
    } else if ruled_overrule >= ruling_required {
        StewardTierStanding::Overruled
    } else if !deadline_passed {
        StewardTierStanding::Awaiting
    } else if seated_duty.is_empty() {
        StewardTierStanding::NoDutyHolders
    } else {
        StewardTierStanding::Silent
    };

    // ── (3) THE RESPONDENT POOL. Counted (and reported) whether or not
    //    escalation opened — the ballots are held rows and the numbers are
    //    facts about them; only the OUTCOME is conditional.
    let pool = governing_ballots(&relevant, &seated_roster, None);
    let (uphold_ballots, overrule_ballots) = tally(&pool);
    let respondents = pool.len();
    let required = escalated_dismissal_required(policy, respondents);
    let mut counted_ballot_ids: Vec<String> = pool
        .values()
        .map(|b| b.attestation_id.clone())
        .collect::<Vec<_>>();
    counted_ballot_ids.sort();

    // ── THE VERDICT. Upheld is tested FIRST: with `required` at a strict
    //    majority of the pool both sides cannot reach it (2·required >
    //    respondents), so this is a defensive branch — and it defends in the
    //    protective direction, which is the only direction a tie may fall.
    let outcome = if !steward.escalates() {
        EscalationOutcome::NotEscalated
    } else if uphold_ballots >= required {
        EscalationOutcome::Upheld
    } else if overrule_ballots >= required {
        EscalationOutcome::Dismissed
    } else {
        EscalationOutcome::Unresolved
    };

    ObjectionEscalation {
        objection_id: objection.attestation_id.clone(),
        steward,
        outcome,
        duty_holders: seated_duty.len(),
        steward_ruling_required: ruling_required,
        respondents,
        required,
        uphold_ballots,
        overrule_ballots,
        counted_ballot_ids,
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

/// CIRISPersist#591 — build the canonical envelope of a **ballot**.
///
/// `upholds` selects [`DIMENSION_UPHELD`] (*"this objection stands"*) or
/// [`DIMENSION_OVERRULED`] (*"it does not"*). One row, one signature, its
/// author's own — a ballot is never co-signed, because the whole point of
/// counting respondents is that the DENOMINATOR is the set of people who
/// answered. A pool folded into one co-signed row would make the numerator and
/// the denominator the same number, which is the thin-pool attack in its purest
/// form: three signatures on one row would always be a strict majority of
/// themselves.
#[must_use]
pub fn ballot_envelope(
    cohort: Cohort,
    cohort_key_id: &str,
    action_attestation_id: &str,
    objection_attestation_id: &str,
    upholds: bool,
    grounds: &str,
) -> serde_json::Value {
    serde_json::json!({
        "dimension": if upholds { DIMENSION_UPHELD } else { DIMENSION_OVERRULED },
        field::COHORT: cohort.as_str(),
        field::COHORT_KEY_ID: cohort_key_id,
        field::OBJECTS_TO: action_attestation_id,
        field::BALLOT_ON: objection_attestation_id,
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

/// CIRISPersist#591 — **the ballot door.** Admit and store one
/// member's answer on one objection: [`DIMENSION_UPHELD`] (*it stands*) or
/// [`DIMENSION_OVERRULED`] (*it does not*).
///
/// One signature, the author's own — and, unlike
/// [`record_objection_dismissal`], no threshold is applied here at all, because
/// a ballot has no force on its own. Its price is paid at READ time against a
/// denominator that does not exist yet when it is cast: whether the pool ever
/// reaches [`escalated_dismissal_required`] depends on who else answers. That
/// is not a second door around [`fold_reverse_quorum_over`]'s counting rules —
/// it is the same rule, applied where the evidence is complete.
///
/// # What IS checked
///
/// The same membership and filing gates [`record_objection`] applies, plus
/// three of this plane's own:
///
/// - [`ObjectionRefusalReason::StewardTierNotAdopted`] — the cohort declared no
///   `+escalate:` tier, so nothing will ever read this row;
/// - [`ObjectionRefusalReason::ActorRecused`] — the ballot's author is the
///   author of the objected-to action;
/// - [`ObjectionRefusalReason::BallotPredatesAction`] — the ballot is dated
///   before the thing it judges.
///
/// # A member may change their mind
///
/// There is deliberately NO duplicate-ballot refusal (contrast
/// [`ObjectionRefusalReason::DuplicateObjection`]). Reconsidering is legitimate
/// — it is most of what deliberation IS — and the fold already counts one
/// ballot per author, the latest one governing. Refusing the second row would
/// freeze a member's first reaction as their final answer, which on a plane
/// built to make judgement possible would be the wrong direction.
pub async fn record_objection_ballot<F>(
    directory: &F,
    ballot: &Attestation,
) -> Result<ObjectionOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    let refused = |reason: ObjectionRefusalReason| Ok(ObjectionOutcome::Refused { reason });

    if !matches!(
        envelope_str(ballot, "dimension"),
        Some(DIMENSION_UPHELD | DIMENSION_OVERRULED)
    ) {
        return refused(ObjectionRefusalReason::DimensionMismatch);
    }
    let Some((cohort, cohort_key_id)) = envelope_cohort(ballot) else {
        return refused(ObjectionRefusalReason::MalformedEnvelope);
    };
    let Some(action_id) = envelope_str(ballot, field::OBJECTS_TO).map(str::to_owned) else {
        return refused(ObjectionRefusalReason::MalformedEnvelope);
    };
    let Some(objection_id) = envelope_str(ballot, field::BALLOT_ON).map(str::to_owned) else {
        return refused(ObjectionRefusalReason::MalformedEnvelope);
    };
    if action_id.is_empty() || objection_id.is_empty() {
        return refused(ObjectionRefusalReason::MalformedEnvelope);
    }

    let Some((roster, policy)) = cohort_state(directory, cohort, &cohort_key_id).await? else {
        return refused(ObjectionRefusalReason::CohortUnknown);
    };
    let Some(policy) = policy else {
        return refused(ObjectionRefusalReason::NotGoverned);
    };
    // A ballot on a cohort with no steward tier could never be counted by
    // anything: no deadline, no silence, no escalated pool.
    if policy.steward.is_none() {
        return refused(ObjectionRefusalReason::StewardTierNotAdopted);
    }

    // The respondent pool is a SUBSET of the roster and never a widening of it
    // — the same gate `record_objection` applies.
    //
    // **THIS DOOR IS THE ONLY ENFORCEMENT, and the manifest confers nothing
    // here.** CC registered [`NAMESPACE_FAMILY`] per CC 3.1.7 R2(a) and
    // DEFERRED the emitter rule: the row carries no `reserved_rule`, and
    // [`registry`](super::namespace::registry) reads only that key (the
    // manifest's `reserved` bool is explicitly ignored by its serde shape), so
    // `authority_for("objection:upheld:v1")` resolves to
    // `ProducerSteward` with `reserved: None` — before AND after the rc3
    // re-vendor. Persist enforcing cohort-member-only on a family the manifest
    // calls open is a divergence to close in CC (the elaboration rides
    // CIRISConstitution#67), not a second belt to lean on. Nothing on this
    // plane reads `.reserved`, and nothing should start until the rule is on
    // the row — a hand-written gate that believes it is backed by a manifest
    // entry that does not exist is the split-truth shape #590 was filed about.
    if !roster.iter().any(|k| k == &ballot.attesting_key_id) {
        return refused(ObjectionRefusalReason::NotACohortMember);
    }

    let Some(action) = directory.get_attestation(&action_id).await? else {
        return refused(ObjectionRefusalReason::TargetActionUnknown);
    };
    // Filed where the fold looks (see `objections_against`), or stored and
    // never counted.
    if ballot.attested_key_id != action.attesting_key_id {
        return refused(ObjectionRefusalReason::NotFiledAgainstActor);
    }
    // RECUSAL, at the door: the actor does not vote on the objection to their
    // own act. Refused rather than silently dropped by the fold, so a producer
    // learns it instead of believing it participated.
    if ballot.attesting_key_id == action.attesting_key_id {
        return refused(ObjectionRefusalReason::ActorRecused);
    }
    if ballot.asserted_at < action.asserted_at {
        return refused(ObjectionRefusalReason::BallotPredatesAction);
    }

    if super::verify_envelope_hybrid_signature(
        directory,
        &ballot.attesting_key_id,
        &ballot.attestation_envelope,
        &ballot.scrub_signature_classical,
        ballot.scrub_signature_pqc.as_deref(),
    )
    .await
    .is_err()
    {
        return refused(ObjectionRefusalReason::UnverifiableSignature);
    }

    // The named objection must be an OBJECTION row against the SAME action —
    // the identical test `record_objection_dismissal` applies, and the identical
    // one the fold applies at read time, so a ballot cannot be admitted under
    // one reading of "which objection" and counted under another.
    let named = directory.get_attestation(&objection_id).await?;
    if named
        .filter(|row| {
            envelope_str(row, "dimension") == Some(DIMENSION_OBJECTION)
                && envelope_str(row, field::OBJECTS_TO) == Some(action_id.as_str())
        })
        .is_none()
    {
        return refused(ObjectionRefusalReason::ObjectionUnknown);
    }

    directory
        .put_attestation(super::SignedAttestation {
            attestation: ballot.clone(),
        })
        .await?;
    Ok(ObjectionOutcome::Admitted)
}

// ─────────────────────────────────────────────────────────────────────────
//  The read-time answer
// ─────────────────────────────────────────────────────────────────────────

/// Every objection / dismissal / **ballot** row this node holds that is keyed
/// on `action`'s author. All four dimensions carry
/// `attested_key_id = action.attesting_key_id` (the actor whose action is
/// under objection), so ONE existing read serves them all.
///
/// CIRISPersist#591 widened this filter to the two ballot dimensions.
/// It had to be widened here and nowhere else: a dimension missing from this
/// list stores fine, replicates fine, verifies fine — and is never read by
/// anything, which is the failure mode that looks most like success.
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
                Some(
                    DIMENSION_OBJECTION
                        | DIMENSION_DISMISSAL
                        | DIMENSION_UPHELD
                        | DIMENSION_OVERRULED
                )
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
///
/// # Why this one public fn takes `&dyn` rather than a generic
///
/// CIRISPersist#591 changed the receiver from
/// `F: FederationDirectory + ?Sized` to `&dyn FederationDirectory`, and it is a
/// necessity rather than a preference. The steward tier's duty-holder set must
/// be re-derived from this node's own verified state (#377 — a caller-supplied
/// steward set would be a forgeable escalation bypass), and that derivation is
/// the §11.10/§11.11 moderation walk, which is `&dyn` the whole way down:
/// [`appointed_moderators_of`](super::admission::appointed_moderators_of) →
/// [`is_steward_bound`](super::admission::is_steward_bound) →
/// [`age_band`](super::age::age_band), plus the scoped-delegation BFS. `&F`
/// where `F: ?Sized` cannot be unsize-coerced to `&dyn`, and adding `F: Sized`
/// would break the callers that instantiate `F` AS `dyn FederationDirectory`.
///
/// So the choice was one public signature or a generic rewrite of a recursive
/// moderation walk that has been `&dyn` since v8.7.1 — this fn was the outlier
/// on an otherwise uniformly `&dyn` surface. **If that walk is ever made
/// generic, this can go back to a generic in the same cut with no semantic
/// change**; it is not laziness, and it is not worth "fixing" on its own.
pub async fn resolve_reverse_quorum(
    directory: &dyn FederationDirectory,
    cohort: Cohort,
    cohort_key_id: &str,
    action: &Attestation,
    now: DateTime<Utc>,
) -> Result<ReverseQuorumFold, Error> {
    let (roster, policy) = cohort_state(directory, cohort, cohort_key_id)
        .await?
        .unwrap_or_else(|| (Vec::new(), None));
    let rows = objections_against(directory, action).await?;

    let (ballot_rows, rows): (Vec<Attestation>, Vec<Attestation>) =
        rows.into_iter().partition(|r| {
            matches!(
                envelope_str(r, "dimension"),
                Some(DIMENSION_UPHELD | DIMENSION_OVERRULED)
            )
        });
    let (dismissal_rows, objection_rows): (Vec<Attestation>, Vec<Attestation>) = rows
        .into_iter()
        .partition(|r| envelope_str(r, "dimension") == Some(DIMENSION_DISMISSAL));

    // The APPOINTED duty-holders, re-derived here and never taken from a
    // caller. Only the `community`/`affiliations` tiers have a §11.11
    // moderation plane at all (both resolve through `federation_communities`);
    // a family or `self` cohort has no duty-holders to be silent, which folds
    // to `NoDutyHolders` and escalates on schedule — the honest answer for a
    // tier that never appointed anybody. Skipped entirely when no steward tier
    // is declared, so #574 cohorts pay nothing for this.
    //
    // ⚠ DO NOT swap this for `moderators_of` / `duty_holders_for_community`.
    // They resolve `community_authority_set`, which is
    // `if is_founder || !founder_only { insert }` — so for EVERY protocol other
    // than the literal `founder_only`, and `reverse_quorum:*` is one by
    // construction, the authority set is the entire roster. The steward tier
    // would silently become "every member reviews", a member could rule on
    // their own objection, and the escalated undo would be vetoable by anyone.
    // It looks like an independent reviewer set and is the objectors. See the
    // three-way table on `appointed_moderators_of`.
    let duty_holders: Vec<String> = match (policy.and_then(|p| p.steward), cohort) {
        (Some(_), Cohort::Community | Cohort::Affiliations) => {
            super::admission::appointed_moderators_of(
                directory,
                cohort_key_id,
                super::admission::DELEGATION_SCOPE_MODERATE,
            )
            .await?
        }
        _ => Vec::new(),
    };

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

    Ok(fold_reverse_quorum_over(&ReverseQuorumInputs {
        action,
        objections: &objection_rows,
        dismissals: &verified_dismissals,
        ballots: &ballot_rows,
        roster: &roster,
        duty_holders: &duty_holders,
        policy,
        now,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(m: u32, n: u32, w: u64) -> ReverseQuorumPolicy {
        ReverseQuorumPolicy {
            m,
            n,
            window_secs: w,
            steward: None,
        }
    }

    /// The same policy WITH a steward tier: `+escalate:{secs}:{floor}`.
    fn escalating(m: u32, n: u32, w: u64, secs: u64, floor: usize) -> ReverseQuorumPolicy {
        ReverseQuorumPolicy {
            m,
            n,
            window_secs: w,
            steward: Some(StewardTier {
                window_secs: secs,
                respondent_floor: floor,
            }),
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

    // ─────────────────────────────────────────────────────────────────────
    //  CIRISPersist#591 — the steward tier and escalation
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn the_steward_tier_parses_and_round_trips() {
        let p = ReverseQuorumPolicy::parse("reverse_quorum:2/9:86400+escalate:172800:4")
            .expect("parses");
        assert_eq!((p.m, p.n, p.window_secs), (2, 9, 86400));
        let tier = p.steward.expect("a steward tier was declared");
        assert_eq!((tier.window_secs, tier.respondent_floor), (172_800, 4));
        assert_eq!(
            p.to_protocol_string(),
            "reverse_quorum:2/9:86400+escalate:172800:4"
        );
        // The shape gate admits exactly what the fold can evaluate — ONE parse
        // door, so the vocabulary cannot be widened in one layer only.
        assert!(super::super::types::consensus_protocol::is_canonical_form(
            "reverse_quorum:2/9:86400+escalate:172800:4"
        ));
    }

    /// Every #574 string keeps meaning EXACTLY what it meant: no tier, no
    /// deadline, no escalation, and a fold whose new fields are all empty.
    #[test]
    fn a_574_string_still_declares_no_steward_tier_at_all() {
        let p = ReverseQuorumPolicy::parse("reverse_quorum:2/5:86400").expect("parses");
        assert!(p.steward.is_none());
        assert!(p.steward_deadline(Utc::now()).is_none());
        assert_eq!(p.to_protocol_string(), "reverse_quorum:2/5:86400");

        let t0: DateTime<Utc> = "2026-08-02T00:00:00Z".parse().unwrap();
        let action = action_row(t0);
        let roster: Vec<String> = ["a", "b", "c"].iter().map(|s| (*s).to_string()).collect();
        let f = fold_reverse_quorum(
            &action,
            &[objection("o1", "a", t0)],
            &[],
            &roster,
            Some(p),
            t0 + Duration::days(30),
        );
        assert!(f.steward_deadline.is_none());
        assert!(f.escalation.is_empty(), "no tier ⇒ no escalation records");
        assert!(f.escalated_dismissed_objection_ids.is_empty());
        assert_eq!(
            f.standing,
            ReverseQuorumStanding::Stood,
            "and the #574 answer is byte-identical to what it was"
        );
    }

    #[test]
    fn degenerate_steward_tiers_are_refused_by_the_one_parse_door() {
        use super::super::types::consensus_protocol::is_canonical_form;
        for bad in [
            // A floor BELOW the substrate's — refused LOUDLY rather than
            // clamped, so a cohort learns its declaration is wrong instead of
            // quietly running a policy it did not write.
            "reverse_quorum:2/9:600+escalate:60:2",
            "reverse_quorum:2/9:600+escalate:60:1",
            "reverse_quorum:2/9:600+escalate:60:0",
            "reverse_quorum:2/9:600+escalate:60",   // no floor
            "reverse_quorum:2/9:600+escalate:60:",  // empty floor
            "reverse_quorum:2/9:600+escalate::3",   // empty window
            "reverse_quorum:2/9:600+escalate:",     // nothing at all
            "reverse_quorum:2/9:600+escalate:x:3",  // non-numeric window
            "reverse_quorum:2/9:600+escalate:60:x", // non-numeric floor
            // …and the #574 degenerates stay refused THROUGH the new suffix.
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
        // A steward window of 0 IS legal — "the duty-holders get no grace" is a
        // coherent declaration, exactly as a 0 objection window is.
        let p = ReverseQuorumPolicy::parse("reverse_quorum:1/1:0+escalate:0:3").expect("legal");
        assert_eq!(p.steward.expect("tier").window_secs, 0);
    }

    /// **The escalated undo is an m-of-n, never a 1-of-N** — the property the
    /// module's op classification rests on. Over every respondent count and
    /// every declared `m`.
    #[test]
    fn the_escalated_undo_can_never_become_a_one_of_n() {
        // The floor is asserted as the LITERAL 3, not as
        // `ESCALATION_RESPONDENT_FLOOR` — an assertion written in terms of the
        // constant it is guarding moves with it and pins nothing. A mutation
        // run that lowers the constant must redden this.
        assert_eq!(
            ESCALATION_RESPONDENT_FLOOR, 3,
            "changing this number is a governance decision, not a refactor — \
             see the constant's doc and the CC ratification ask"
        );
        for respondents in 0usize..=14 {
            for m in 1u32..=12 {
                // The cohort declares the substrate minimum, so the CONSTANT is
                // the binding term wherever the ratio does not exceed it.
                let p = escalating(m, m.max(1), 3600, 600, 3);
                let required = escalated_dismissal_required(&p, respondents);
                assert!(
                    required >= 3,
                    "the absolute floor is what keeps this an m-of-n \
                     (respondents={respondents}, m={m}, required={required})"
                );
                assert!(
                    required >= m as usize,
                    "escalation may shrink the DENOMINATOR and must never \
                     re-price the ratio — a cohort that declared {m} still \
                     needs {m} (respondents={respondents}, required={required})"
                );
                assert!(
                    required >= ciris_verify_core::accord_genesis::strict_majority(respondents),
                    "…and never below a strict majority of those who answered"
                );
                // BOTH sides can never reach the threshold at once, so the
                // fail-secure tie-break in `escalate_objection` is defence in
                // depth rather than a live branch.
                assert!(
                    required * 2 > respondents,
                    "uphold and overrule must be mutually exclusive \
                     (respondents={respondents}, required={required})"
                );
            }
        }
    }

    /// A cohort may RAISE its own floor and may never lower it — in the parse
    /// door and again at use, because a `ReverseQuorumPolicy` built in code
    /// never passed the door.
    #[test]
    fn a_declared_floor_only_ever_raises_the_escalated_price() {
        let strict = escalating(2, 9, 3600, 600, 6);
        assert_eq!(escalated_dismissal_required(&strict, 5), 6);
        assert_eq!(escalated_dismissal_required(&strict, 11), 6);
        assert_eq!(
            escalated_dismissal_required(&strict, 12),
            7,
            "…until the ratio overtakes it"
        );
        // A hand-built policy carrying an illegal floor is clamped at USE, not
        // trusted: the parse door refuses this string, but nothing stops code
        // from constructing the struct.
        let smuggled = escalating(1, 9, 3600, 600, 1);
        assert_eq!(
            escalated_dismissal_required(&smuggled, 1),
            3,
            "strict_majority(1) == 1, and 1 is a capability grant — pinned as \
             the literal, because an assertion written in terms of the constant \
             it guards moves with it and pins nothing"
        );
    }

    /// An EMPTY duty-holder set must never "rule" with zero ballots — that
    /// would block escalation forever on exactly the community that has no
    /// moderators, the precise inversion #591 exists to close.
    ///
    /// The FIRST assertion is the one that earns its keep. The property holds
    /// because `strict_majority` is `n / 2 + 1`, i.e. it already returns 1 at
    /// zero; persist's `.max(1)` is a pin against that changing and deleting it
    /// turns nothing red (a mutation run proved exactly that). So the guard is a
    /// DEPENDENCY's behaviour, and the honest test is the one that pins the
    /// dependency — a verify re-pin that redefined `strict_majority(0)` would
    /// otherwise silently hand every moderator-less commons a permanent block.
    #[test]
    fn an_empty_duty_holder_set_can_never_rule() {
        assert_eq!(
            ciris_verify_core::accord_genesis::strict_majority(0),
            1,
            "the property this module relies on lives in verify — if a re-pin \
             ever makes this 0, `steward_ruling_threshold`'s clamp becomes the \
             only thing standing between a moderator-less commons and a \
             permanent escalation block"
        );
        let p = escalating(2, 9, 3600, 600, 3);
        assert_eq!(p.steward_ruling_threshold(0), 1);
        assert_eq!(p.steward_ruling_threshold(1), 1);
        assert_eq!(p.steward_ruling_threshold(3), 2);
        assert_eq!(p.steward_ruling_threshold(9), 5);
    }

    #[test]
    fn steward_and_escalation_tokens_match_serde_and_are_unique() {
        for s in StewardTierStanding::ALL {
            let json = serde_json::to_string(s).expect("serialize");
            assert_eq!(json, format!("\"{}\"", s.as_str()));
            let back: StewardTierStanding = serde_json::from_str(&json).expect("round-trip");
            assert_eq!(back, *s);
            assert_eq!(s.to_string(), s.as_str());
        }
        for o in EscalationOutcome::ALL {
            let json = serde_json::to_string(o).expect("serialize");
            assert_eq!(json, format!("\"{}\"", o.as_str()));
            let back: EscalationOutcome = serde_json::from_str(&json).expect("round-trip");
            assert_eq!(back, *o);
            assert_eq!(o.to_string(), o.as_str());
        }
        let steward: std::collections::BTreeSet<&str> = StewardTierStanding::ALL
            .iter()
            .map(StewardTierStanding::as_str)
            .collect();
        assert_eq!(
            steward.len(),
            StewardTierStanding::ALL.len(),
            "the three zeroes — silent / overruled / no_duty_holders — must not \
             share a token, or the failing commons and the healthy one read the \
             same"
        );
        let outcomes: std::collections::BTreeSet<&str> = EscalationOutcome::ALL
            .iter()
            .map(EscalationOutcome::as_str)
            .collect();
        assert_eq!(outcomes.len(), EscalationOutcome::ALL.len());
        // And the two axes are genuinely two: `upheld` is a legal token on
        // BOTH, meaning two different things, which is exactly why they may
        // not be one enum.
        assert!(steward.contains("upheld") && outcomes.contains("upheld"));
    }

    /// Which of the three zeroes opens the escalated path — the ONE predicate.
    #[test]
    fn only_the_three_zeroes_escalate() {
        for s in StewardTierStanding::ALL {
            let expected = matches!(
                s,
                StewardTierStanding::Silent
                    | StewardTierStanding::Overruled
                    | StewardTierStanding::NoDutyHolders
            );
            assert_eq!(s.escalates(), expected, "{s}");
        }
        assert!(!StewardTierStanding::Awaiting.escalates());
        assert!(!StewardTierStanding::Upheld.escalates());
        assert!(!StewardTierStanding::NotAdopted.escalates());
    }

    fn ballot(
        id: &str,
        author: &str,
        objection_id: &str,
        upholds: bool,
        at: DateTime<Utc>,
    ) -> Attestation {
        row(
            id,
            author,
            ballot_envelope(
                Cohort::Community,
                "c1",
                "action-1",
                objection_id,
                upholds,
                "g",
            ),
            at,
        )
    }

    fn names(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("m{i}")).collect()
    }

    /// Fold a roster of nine under `reverse_quorum:2/9:3600+escalate:600:3`,
    /// with `m0` the sole appointed moderator and `actor` NOT a member unless
    /// the test says so.
    fn fold_nine(
        objections: &[Attestation],
        ballots: &[Attestation],
        duty: &[String],
        now: DateTime<Utc>,
        action: &Attestation,
    ) -> ReverseQuorumFold {
        let roster = names(9);
        fold_reverse_quorum_over(&ReverseQuorumInputs {
            action,
            objections,
            dismissals: &[],
            ballots,
            roster: &roster,
            duty_holders: duty,
            policy: Some(escalating(2, 9, 3600, 600, 3)),
            now,
        })
    }

    fn t0() -> DateTime<Utc> {
        "2026-08-02T00:00:00Z".parse().unwrap()
    }

    /// Comfortably past the objection window (3600) and the steward window
    /// (600), i.e. past the `t0 + 4200` deadline — and past the `t0 + 5000` the
    /// post-escalation ballots below are dated at, since a ballot after `now`
    /// does not count yet.
    fn after_deadline() -> DateTime<Utc> {
        t0() + Duration::seconds(9000)
    }

    /// **Silence is its own outcome.** The duty-holder said nothing; the fold
    /// says SO, distinctly from "judged and dismissed" and from "judged and
    /// upheld" — and nothing has been suppressed.
    #[test]
    fn silence_is_its_own_outcome_and_suppresses_nothing() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        let f = fold_nine(
            &[objection("o1", "m1", t0())],
            &[],
            &duty,
            after_deadline(),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!(e.steward, StewardTierStanding::Silent);
        assert_eq!(e.outcome, EscalationOutcome::Unresolved);
        assert_eq!((e.respondents, e.required), (0, 3));
        assert_eq!(
            f.counted_objection_ids,
            vec!["o1".to_string()],
            "an unresolved escalation changes NOTHING — protection sticks"
        );
        assert!(f.escalated_dismissed_objection_ids.is_empty());
        assert_eq!(
            f.steward_deadline,
            Some(t0() + Duration::seconds(4200)),
            "the deadline is a function of the ACTION and the declaration alone"
        );
    }

    /// Before the deadline the duty-holders may still answer. `Awaiting` is not
    /// a zero, and conflating it with `Silent` would escalate every objection
    /// the instant it was raised.
    #[test]
    fn awaiting_is_not_silence() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        // Three overruling ballots are already in — and buy nothing yet.
        let ballots: Vec<Attestation> = ["m1", "m2", "m3"]
            .iter()
            .enumerate()
            .map(|(i, k)| ballot(&format!("b{i}"), k, "o1", false, t0()))
            .collect();
        let f = fold_nine(
            &[objection("o1", "m4", t0())],
            &ballots,
            &duty,
            t0() + Duration::seconds(10),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!(e.steward, StewardTierStanding::Awaiting);
        assert_eq!(e.outcome, EscalationOutcome::NotEscalated);
        assert_eq!(
            (e.respondents, e.overrule_ballots),
            (3, 3),
            "the ballots are COUNTED and reported — only the outcome waits"
        );
        assert_eq!(f.counted_objection_ids, vec!["o1".to_string()]);
    }

    /// **The tier is real**: a duty-holders' upholding ruling, in time, closes
    /// the escalated path — and three overruling ballots do not reopen it.
    #[test]
    fn an_upholding_ruling_closes_escalation() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        let mut ballots = vec![ballot("r0", "m0", "o1", true, t0() + Duration::seconds(60))];
        for (i, k) in ["m1", "m2", "m3"].iter().enumerate() {
            ballots.push(ballot(
                &format!("b{i}"),
                k,
                "o1",
                false,
                t0() + Duration::seconds(5000),
            ));
        }
        let f = fold_nine(
            &[objection("o1", "m4", t0())],
            &ballots,
            &duty,
            after_deadline(),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!(e.steward, StewardTierStanding::Upheld);
        assert_eq!(e.outcome, EscalationOutcome::NotEscalated);
        assert_eq!(e.overrule_ballots, 3, "the pool exists and is recorded");
        assert_eq!(
            f.counted_objection_ids,
            vec!["o1".to_string()],
            "a judged brake is not re-litigated by the commons"
        );
    }

    /// …and an OVERRULING ruling does not, because overruling is an undo and
    /// the duty-holders get no undo power the roster does not have. On a
    /// nine-member commons with one moderator, the alternative would be a
    /// literal 1-of-N lift.
    #[test]
    fn an_overruling_ruling_does_not_close_escalation() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        let f = fold_nine(
            &[objection("o1", "m4", t0())],
            &[ballot(
                "r0",
                "m0",
                "o1",
                false,
                t0() + Duration::seconds(60),
            )],
            &duty,
            after_deadline(),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!(e.steward, StewardTierStanding::Overruled);
        assert!(e.steward.escalates());
        assert_eq!(
            e.outcome,
            EscalationOutcome::Unresolved,
            "one moderator's word is not a quorum of respondents either"
        );
        assert_eq!(
            (e.respondents, e.overrule_ballots),
            (1, 1),
            "…and their ballot counts as an ordinary member's, which it is"
        );
        assert_eq!(f.counted_objection_ids, vec!["o1".to_string()]);
    }

    /// **The key move.** Three respondents out of nine lift an objection that
    /// the full-roster undo would have priced at five — which is unreachable in
    /// a commons where six members have stopped reading their mail.
    #[test]
    fn the_escalated_quorum_counts_respondents_and_not_the_roster() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        let ballots: Vec<Attestation> = ["m1", "m2", "m3"]
            .iter()
            .enumerate()
            .map(|(i, k)| {
                ballot(
                    &format!("b{i}"),
                    k,
                    "o1",
                    false,
                    t0() + Duration::seconds(5000),
                )
            })
            .collect();
        let f = fold_nine(
            &[objection("o1", "m4", t0())],
            &ballots,
            &duty,
            after_deadline(),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!(e.steward, StewardTierStanding::Silent);
        assert_eq!(e.outcome, EscalationOutcome::Dismissed);
        assert_eq!((e.respondents, e.required, e.overrule_ballots), (3, 3, 3));
        assert_eq!(
            e.counted_ballot_ids,
            vec!["b0".to_string(), "b1".into(), "b2".into()],
            "the fold NAMES the ballots it counted"
        );
        assert_eq!(f.escalated_dismissed_objection_ids, vec!["o1".to_string()]);
        assert!(
            f.counted_objection_ids.is_empty(),
            "the objection is lifted by the escalated pool"
        );
        // The ordinary price, for contrast — and it is not reachable here.
        assert_eq!(escalating(2, 9, 3600, 600, 3).dismissal_threshold(9), 5);
        assert!(
            f.dismissed_objection_ids.is_empty(),
            "…and the two suppressions are never confused in the evidence"
        );
    }

    /// Two respondents cannot, however many of them agree: the absolute floor
    /// is what stops the escalated undo from degrading into "whoever is awake".
    #[test]
    fn a_pool_below_the_floor_resolves_nothing() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        let ballots: Vec<Attestation> = ["m1", "m2"]
            .iter()
            .enumerate()
            .map(|(i, k)| {
                ballot(
                    &format!("b{i}"),
                    k,
                    "o1",
                    false,
                    t0() + Duration::seconds(5000),
                )
            })
            .collect();
        let f = fold_nine(
            &[objection("o1", "m4", t0())],
            &ballots,
            &duty,
            after_deadline(),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!((e.respondents, e.required, e.overrule_ballots), (2, 3, 2));
        assert_eq!(e.outcome, EscalationOutcome::Unresolved);
        assert_eq!(f.counted_objection_ids, vec!["o1".to_string()]);
    }

    /// Members who show up to DEFEND the objection raise the denominator the
    /// attacker's strict majority is measured against. Three overrulers who
    /// would have carried an unattended pool carry nothing once three members
    /// answer the other way.
    #[test]
    fn upholders_dilute_the_pool_they_join() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        let mut ballots: Vec<Attestation> = ["m1", "m2", "m3"]
            .iter()
            .enumerate()
            .map(|(i, k)| {
                ballot(
                    &format!("b{i}"),
                    k,
                    "o1",
                    false,
                    t0() + Duration::seconds(5000),
                )
            })
            .collect();
        for (i, k) in ["m5", "m6", "m7"].iter().enumerate() {
            ballots.push(ballot(
                &format!("u{i}"),
                k,
                "o1",
                true,
                t0() + Duration::seconds(5100),
            ));
        }
        let f = fold_nine(
            &[objection("o1", "m4", t0())],
            &ballots,
            &duty,
            after_deadline(),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!(
            (
                e.respondents,
                e.required,
                e.overrule_ballots,
                e.uphold_ballots
            ),
            (6, 4, 3, 3)
        );
        assert_eq!(e.outcome, EscalationOutcome::Unresolved);
        assert_eq!(f.counted_objection_ids, vec!["o1".to_string()]);
    }

    /// A respondent pool that UPHOLDS produces a judged brake — distinguishable
    /// in the record from one nobody ever looked at, which is the whole of what
    /// #591 asks the record to be able to say.
    #[test]
    fn the_commons_can_uphold_and_it_confers_nothing() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        let ballots: Vec<Attestation> = ["m1", "m2", "m3"]
            .iter()
            .enumerate()
            .map(|(i, k)| {
                ballot(
                    &format!("u{i}"),
                    k,
                    "o1",
                    true,
                    t0() + Duration::seconds(5000),
                )
            })
            .collect();
        let f = fold_nine(
            &[objection("o1", "m4", t0())],
            &ballots,
            &duty,
            after_deadline(),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!(e.outcome, EscalationOutcome::Upheld);
        assert_eq!(
            f.distinct_objectors, 1,
            "an upholding ballot is not an objection and never becomes one — \
             three upholders did NOT reverse a 2-of-9 action"
        );
        assert_eq!(f.standing, ReverseQuorumStanding::Stood);
    }

    /// **Recusal.** The actor does not vote on the objection to their own act,
    /// on either side — and when the actor IS the commons' only appointed
    /// moderator, that seat is empty rather than decisive.
    #[test]
    fn the_actor_is_recused_from_the_pool_and_from_the_duty_bench() {
        // `m0` is both the actor and the sole moderator.
        let action = row(
            "action-1",
            "m0",
            serde_json::json!({"dimension": "testimonial_witness:commons_act:v1"}),
            t0(),
        );
        let duty = vec!["m0".to_string()];
        let ballots = vec![
            // The actor votes to lift the objection to their own action…
            ballot("b0", "m0", "o1", false, t0() + Duration::seconds(5000)),
            ballot("b1", "m1", "o1", false, t0() + Duration::seconds(5000)),
            ballot("b2", "m2", "o1", false, t0() + Duration::seconds(5000)),
        ];
        let f = fold_nine(
            &[objection("o1", "m4", t0())],
            &ballots,
            &duty,
            after_deadline(),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!(
            e.steward,
            StewardTierStanding::NoDutyHolders,
            "the only moderator is the actor, so the bench is EMPTY — not \
             occupied by someone judging their own act"
        );
        assert_eq!(e.duty_holders, 0);
        assert_eq!(
            (e.respondents, e.overrule_ballots),
            (2, 2),
            "…and their ballot is not in the pool either: recusal removes the \
             seat from BOTH sides of the fraction"
        );
        assert_eq!(
            e.outcome,
            EscalationOutcome::Unresolved,
            "two is below the floor — the actor's own vote would have been a \
             third of it"
        );
        assert_eq!(f.counted_objection_ids, vec!["o1".to_string()]);
    }

    /// A moderator who OBJECTS does not then get to rule on their own
    /// objection. Without this, the steward tier would hand any duty-holder a
    /// permanent unilateral brake: object, uphold, escalation never opens.
    #[test]
    fn a_moderator_cannot_rule_on_their_own_objection() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        let f = fold_nine(
            // m0, the moderator, is also the objector.
            &[objection("o1", "m0", t0())],
            &[ballot("r0", "m0", "o1", true, t0() + Duration::seconds(60))],
            &duty,
            after_deadline(),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!(
            e.steward,
            StewardTierStanding::NoDutyHolders,
            "recused from their own objection, the bench is empty and the \
             commons is asked"
        );
        assert_eq!(
            (e.respondents, e.uphold_ballots),
            (1, 1),
            "their ballot still counts as an ordinary member's — they are \
             recused from the BENCH, not silenced"
        );
    }

    /// A member may change their mind; the latest ballot governs, and a
    /// same-instant contradiction resolves fail-secure to UPHELD — the
    /// `fold_quarantine` ordering, verbatim.
    #[test]
    fn the_latest_ballot_governs_and_a_tied_instant_upholds() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        let t = t0() + Duration::seconds(5000);
        let ballots = vec![
            // m1 overrules, then thinks better of it a second later.
            ballot("b0", "m1", "o1", false, t),
            ballot("b1", "m1", "o1", true, t + Duration::seconds(1)),
            // m2 signs both in the SAME instant — protection wins.
            ballot("b2", "m2", "o1", false, t),
            ballot("b3", "m2", "o1", true, t),
            ballot("b4", "m3", "o1", false, t),
        ];
        let f = fold_nine(
            &[objection("o1", "m4", t0())],
            &ballots,
            &duty,
            after_deadline(),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!(
            (e.respondents, e.uphold_ballots, e.overrule_ballots),
            (3, 2, 1),
            "three members, three ballots counted — one each: {e:?}"
        );
        assert_eq!(
            e.counted_ballot_ids,
            vec!["b1".to_string(), "b3".into(), "b4".into()]
        );
        assert_eq!(e.outcome, EscalationOutcome::Unresolved);
    }

    /// The two bounds a ballot's date must satisfy. The `now` bound is the one
    /// asymmetry with the objection count and it is load-bearing: an
    /// objection's date is bounded above by its window, a ballot's is not, so
    /// without it three ballots dated 2099 would resolve an escalation today.
    #[test]
    fn a_ballot_dated_in_the_future_or_before_the_action_never_counts() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        let ballots = vec![
            ballot(
                "b0",
                "m1",
                "o1",
                false,
                after_deadline() + Duration::days(365),
            ),
            ballot(
                "b1",
                "m2",
                "o1",
                false,
                after_deadline() + Duration::days(365),
            ),
            ballot(
                "b2",
                "m3",
                "o1",
                false,
                after_deadline() + Duration::days(365),
            ),
            ballot("b3", "m5", "o1", false, t0() - Duration::seconds(1)),
        ];
        let f = fold_nine(
            &[objection("o1", "m4", t0())],
            &ballots,
            &duty,
            after_deadline(),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!((e.respondents, e.overrule_ballots), (0, 0));
        assert_eq!(e.outcome, EscalationOutcome::Unresolved);
        assert_eq!(f.counted_objection_ids, vec!["o1".to_string()]);
        // …and once `now` catches up, the SAME rows resolve. Nothing was
        // discarded; the fold simply did not count them yet.
        let later = fold_nine(
            &[objection("o1", "m4", t0())],
            &ballots,
            &duty,
            after_deadline() + Duration::days(400),
            &action,
        );
        assert_eq!(later.escalation[0].respondents, 3);
        assert_eq!(later.escalation[0].outcome, EscalationOutcome::Dismissed);
    }

    /// **The respondent pool is a SUBSET of the roster, never a widening of
    /// it.** A non-member's ballot is not merely outvoted — it is not in the
    /// denominator at all.
    ///
    /// This test and [`record_objection_ballot`]'s roster gate ARE the
    /// enforcement of that property. The manifest does not supply it: CC
    /// registered the family and deferred its emitter rule, so
    /// `authority_for` resolves these dimensions to `ProducerSteward` with no
    /// reserved rule. See the note on the door.
    #[test]
    fn a_non_member_is_not_a_respondent() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        let t = t0() + Duration::seconds(5000);
        let ballots = vec![
            ballot("b0", "m1", "o1", false, t),
            ballot("b1", "m2", "o1", false, t),
            ballot("b2", "stranger", "o1", false, t),
            ballot("b3", "another-stranger", "o1", false, t),
        ];
        let f = fold_nine(
            &[objection("o1", "m4", t0())],
            &ballots,
            &duty,
            after_deadline(),
            &action,
        );
        let e = &f.escalation[0];
        assert_eq!(
            (e.respondents, e.overrule_ballots),
            (2, 2),
            "two members answered; the outsiders are not in the pool: {e:?}"
        );
        assert_eq!(
            e.counted_ballot_ids,
            vec!["b0".to_string(), "b1".into()],
            "and the named evidence contains no outsider row"
        );
        assert_eq!(e.outcome, EscalationOutcome::Unresolved);
    }

    /// An objection already lifted at the full-roster price is not escalated —
    /// the commons is not asked a question that has an answer.
    #[test]
    fn an_already_dismissed_objection_is_not_escalated() {
        let action = action_row(t0());
        let dismissal = row(
            "d1",
            "m1",
            dismissal_envelope(Cohort::Community, "c1", "action-1", "o1", "resolved"),
            t0(),
        );
        let roster = names(9);
        let f = fold_reverse_quorum_over(&ReverseQuorumInputs {
            action: &action,
            objections: &[objection("o1", "m4", t0())],
            dismissals: &[dismissal],
            ballots: &[],
            roster: &roster,
            duty_holders: &["m0".to_string()],
            policy: Some(escalating(2, 9, 3600, 600, 3)),
            now: after_deadline(),
        });
        assert!(f.escalation.is_empty());
        assert_eq!(f.dismissed_objection_ids, vec!["o1".to_string()]);
    }

    /// The escalation arm is a pure function of held rows, so a node that was
    /// partitioned through the whole steward window converges the moment the
    /// evidence arrives — a year late, at a different `now`, with no timer
    /// having run anywhere.
    #[test]
    fn a_partitioned_node_converges_on_the_escalated_answer() {
        let action = action_row(t0());
        let duty = vec!["m0".to_string()];
        let ballots: Vec<Attestation> = ["m1", "m2", "m3"]
            .iter()
            .enumerate()
            .map(|(i, k)| {
                ballot(
                    &format!("b{i}"),
                    k,
                    "o1",
                    false,
                    t0() + Duration::seconds(5000),
                )
            })
            .collect();
        let objections = [objection("o1", "m4", t0())];
        let prompt = fold_nine(&objections, &ballots, &duty, after_deadline(), &action);
        let a_year_later = fold_nine(
            &objections,
            &ballots,
            &duty,
            after_deadline() + Duration::days(365),
            &action,
        );
        assert_eq!(prompt.escalation, a_year_later.escalation);
        assert_eq!(
            prompt.escalated_dismissed_objection_ids,
            a_year_later.escalated_dismissed_objection_ids
        );
        assert_eq!(prompt.standing, a_year_later.standing);
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

    /// The #591 witness — **escalation on steward silence**, run by the
    /// sqlite / postgres / memory suites against `&dyn FederationDirectory`.
    ///
    /// 1. a community really can DECLARE the steward tier through the host API
    ///    — `put_community` with `+escalate:` lands on this backend, which is
    ///    the only thing that proves the widened `consensus_protocol` vocabulary
    ///    is reachable here (V116's sqlite `GLOB` already admits the suffix;
    ///    V120 widens the postgres regex);
    /// 2. before the deadline the fold says `awaiting`, not silence;
    /// 3. the ballot door refuses a non-member, the recused actor, a ballot on
    ///    an unknown objection, a misfiled ballot, and a ballot on a cohort that
    ///    declared no tier — each naming its own branch, each writing nothing;
    /// 4. past the deadline with no ruling: `silent` + `unresolved`, and NOTHING
    ///    is suppressed;
    /// 5. three respondents out of nine lift the objection — where the ordinary
    ///    undo would have cost five, which this commons cannot reach;
    /// 6. three upholders joining the pool take it back, by themselves;
    /// 7. a duty-holder who rules IN TIME closes the escalated path, and three
    ///    overruling ballots do not reopen it;
    /// 8. the whole thing SURVIVES REPLICATION — a peer that never saw any of it
    ///    folds the same rows to the same record;
    /// 9. a non-member ballot written straight into a peer's store, bypassing
    ///    the door entirely, is still not a respondent.
    ///
    /// # Why the roster is NINE and the moderator is ONE
    ///
    /// At five, `dismissal_threshold` is 3 and
    /// [`ESCALATION_RESPONDENT_FLOOR`] is 3, so the escalated path and the
    /// ordinary one cost the same and the whole point is invisible — the same
    /// trap the #574 witness documents at three. At nine the ordinary undo is
    /// five and the escalated one is three, so an edit that quietly re-prices
    /// the escalated path against the ROSTER instead of the respondents fails
    /// here. One appointed moderator is the §11.11 minimum and the case the
    /// issue is actually about: the community that has exactly one person
    /// carrying the duty, and that person is asleep.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn exercise_escalation_on_silence(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        let founder = format!("esc-founder-{suffix}");
        let members: Vec<String> = (0..7).map(|i| format!("esc-m{i}-{suffix}")).collect();
        // The actor is a MEMBER — the recusal cases only exist when the person
        // whose action is under objection sits on the roster.
        let actor = format!("esc-actor-{suffix}");
        let stranger = format!("esc-stranger-{suffix}");
        let community = format!("esc-commons-{suffix}");
        let plain = format!("esc-plain-{suffix}");

        let mut roster = vec![founder.clone()];
        roster.extend(members.iter().cloned());
        roster.push(actor.clone());
        assert_eq!(roster.len(), 9);

        for k in roster.iter().chain([&stranger, &community, &plain]) {
            register_user_key(dir, k).await;
        }

        // ── (1) THE DECLARATION LANDS. `reverse_quorum:2/9:3600+escalate:600:3`
        //    through the ordinary host door — the vocabulary is closed in the
        //    Rust shape gate AND in this backend's CHECK, and only a real
        //    `put_community` proves both agree.
        let protocol = "reverse_quorum:2/9:3600+escalate:600:3";
        let action_id = uuid::Uuid::new_v4().to_string();
        let action = seed(dir, &community, &actor, &roster, &action_id, protocol).await;
        let t0 = action.asserted_at;
        let deadline = t0 + Duration::seconds(4200);
        let after = deadline + Duration::seconds(3600);

        let fold = |a: Attestation, when: DateTime<Utc>| {
            let community = community.clone();
            async move {
                resolve_reverse_quorum(dir, Cohort::Community, &community, &a, when)
                    .await
                    .expect("resolve")
            }
        };

        // ── (2) ONE member objects, and before the deadline the duty-holder may
        //    still answer. `awaiting` is not a zero.
        let o1_id = uuid::Uuid::new_v4().to_string();
        let o1 = signed_row(
            &o1_id,
            &members[0],
            &actor,
            objection_envelope(
                Cohort::Community,
                &community,
                &action_id,
                "harms the commons",
            ),
            Utc::now(),
            &[],
        );
        assert_eq!(
            record_objection(dir, &o1).await.expect("record"),
            ObjectionOutcome::Admitted,
            "({suffix}) the 1-of-N protective door is untouched by #591"
        );
        let early = fold(action.clone(), t0 + Duration::seconds(1)).await;
        assert_eq!(
            early.steward_deadline,
            Some(deadline),
            "({suffix}) the deadline is the action's asserted_at + both declared \
             windows and nothing else — no objector can move it"
        );
        let e_early = &early.escalation[0];
        assert_eq!(e_early.steward, StewardTierStanding::Awaiting, "({suffix})");
        assert_eq!(e_early.outcome, EscalationOutcome::NotEscalated);
        assert_eq!(
            (e_early.duty_holders, e_early.steward_ruling_required),
            (1, 1),
            "({suffix}) one appointed moderator — the founder; the other eight \
             members are appointment-ELIGIBLE and not appointed: {e_early:?}"
        );

        let ballot_row = |author: &str, upholds: bool, objection: &str| {
            signed_row(
                &uuid::Uuid::new_v4().to_string(),
                author,
                &actor,
                ballot_envelope(
                    Cohort::Community,
                    &community,
                    &action_id,
                    objection,
                    upholds,
                    "on reflection",
                ),
                Utc::now(),
                &[],
            )
        };

        // ── (3) THE DOOR. Five refusals, each naming its own branch, each
        //    writing nothing.
        let outsider = ballot_row(&stranger, false, &o1_id);
        assert_eq!(
            record_objection_ballot(dir, &outsider)
                .await
                .expect("ballot")
                .refusal(),
            Some(ObjectionRefusalReason::NotACohortMember),
            "({suffix}) the respondent pool is a SUBSET of the roster and never \
             a widening of it. This door is the ONLY thing enforcing that — the \
             manifest registers objection:{{state}} and defers its emitter rule, \
             so nothing upstream refuses an outsider's ballot on persist's behalf"
        );
        assert!(
            dir.get_attestation(&outsider.attestation_id)
                .await
                .expect("read")
                .is_none(),
            "({suffix}) a refused ballot writes NOTHING"
        );

        let self_dealing = ballot_row(&actor, false, &o1_id);
        assert_eq!(
            record_objection_ballot(dir, &self_dealing)
                .await
                .expect("ballot")
                .refusal(),
            Some(ObjectionRefusalReason::ActorRecused),
            "({suffix}) the one participant with a guaranteed conflict does not \
             vote on the objection to their own act"
        );

        let phantom = ballot_row(&members[1], false, &uuid::Uuid::new_v4().to_string());
        assert_eq!(
            record_objection_ballot(dir, &phantom)
                .await
                .expect("ballot")
                .refusal(),
            Some(ObjectionRefusalReason::ObjectionUnknown),
            "({suffix}) a ballot must name an objection this node holds against \
             this action — the SAME test the fold applies at read time"
        );

        let mut misfiled = ballot_row(&members[1], false, &o1_id);
        misfiled.attested_key_id.clone_from(&members[1]);
        assert_eq!(
            record_objection_ballot(dir, &misfiled)
                .await
                .expect("ballot")
                .refusal(),
            Some(ObjectionRefusalReason::NotFiledAgainstActor),
            "({suffix}) a ballot nobody can find is not a ballot"
        );

        // A community on the #574 form: governed, but with no steward tier.
        let plain_action_id = uuid::Uuid::new_v4().to_string();
        let plain_action = seed(
            dir,
            &plain,
            &actor,
            &roster,
            &plain_action_id,
            "reverse_quorum:2/9:3600",
        )
        .await;
        let plain_objection_id = uuid::Uuid::new_v4().to_string();
        let plain_objection = signed_row(
            &plain_objection_id,
            &members[0],
            &actor,
            objection_envelope(Cohort::Community, &plain, &plain_action_id, "no"),
            Utc::now(),
            &[],
        );
        assert_eq!(
            record_objection(dir, &plain_objection)
                .await
                .expect("record"),
            ObjectionOutcome::Admitted
        );
        let tierless = signed_row(
            &uuid::Uuid::new_v4().to_string(),
            &members[1],
            &actor,
            ballot_envelope(
                Cohort::Community,
                &plain,
                &plain_action_id,
                &plain_objection_id,
                false,
                "no tier here",
            ),
            Utc::now(),
            &[],
        );
        assert_eq!(
            record_objection_ballot(dir, &tierless)
                .await
                .expect("ballot")
                .refusal(),
            Some(ObjectionRefusalReason::StewardTierNotAdopted),
            "({suffix}) a cohort that declared no tier does not get one invented \
             for it, and a row nothing will read is refused rather than stored"
        );
        let plain_fold = resolve_reverse_quorum(
            dir,
            Cohort::Community,
            &plain,
            &plain_action,
            Utc::now() + Duration::days(30),
        )
        .await
        .expect("resolve");
        assert!(
            plain_fold.steward_deadline.is_none() && plain_fold.escalation.is_empty(),
            "({suffix}) every #574 string still means exactly what it meant: \
             {plain_fold:?}"
        );

        // ── (4) SILENCE. The deadline passes and the duty-holder has said
        //    nothing. It is its own outcome, and it suppresses nothing.
        let silent = fold(action.clone(), after).await;
        let e_silent = &silent.escalation[0];
        assert_eq!(
            e_silent.steward,
            StewardTierStanding::Silent,
            "({suffix}) NOT `stood`, NOT a refusal, NOT `no_duty_holders` — the \
             moderator existed and did not answer: {e_silent:?}"
        );
        assert_eq!(e_silent.outcome, EscalationOutcome::Unresolved);
        assert_eq!((e_silent.respondents, e_silent.required), (0, 3));
        assert_eq!(
            silent.counted_objection_ids,
            vec![o1_id.clone()],
            "({suffix}) an unresolved escalation changes nothing"
        );

        // ── (5) THREE RESPONDENTS OUT OF NINE. The ordinary undo here is FIVE
        //    (a strict majority of the roster) and this commons cannot reach it
        //    — that is the whole inversion #591 closes.
        assert_eq!(
            ReverseQuorumPolicy::parse(protocol)
                .expect("parses")
                .dismissal_threshold(9),
            5,
            "({suffix}) the price the absent roster cannot pay"
        );
        let mut ballot_ids: Vec<String> = Vec::new();
        for member in &members[1..4] {
            let b = ballot_row(member, false, &o1_id);
            ballot_ids.push(b.attestation_id.clone());
            assert_eq!(
                record_objection_ballot(dir, &b).await.expect("ballot"),
                ObjectionOutcome::Admitted,
                "({suffix}) one member, one signature, no co-scrub — a ballot has \
                 no force by itself"
            );
        }
        ballot_ids.sort();
        let lifted = fold(action.clone(), after).await;
        let e_lifted = &lifted.escalation[0];
        assert_eq!(
            (
                e_lifted.respondents,
                e_lifted.required,
                e_lifted.overrule_ballots
            ),
            (3, 3, 3),
            "({suffix}) counted against those who ANSWERED, not against the nine: \
             {e_lifted:?}"
        );
        assert_eq!(e_lifted.outcome, EscalationOutcome::Dismissed);
        assert_eq!(
            e_lifted.counted_ballot_ids, ballot_ids,
            "({suffix}) the fold names every ballot it counted"
        );
        assert_eq!(
            lifted.escalated_dismissed_objection_ids,
            vec![o1_id.clone()],
            "({suffix}) …and reports the escalated suppression SEPARATELY from \
             the full-roster one, because they cost different things"
        );
        assert!(lifted.dismissed_objection_ids.is_empty(), "({suffix})");
        assert!(
            lifted.counted_objection_ids.is_empty(),
            "({suffix}) the brake is lifted — by a decision somebody actually made"
        );
        assert!(
            dir.get_attestation(&action_id)
                .await
                .expect("read")
                .is_some(),
            "({suffix}) and persist mutated NOTHING — evidence, never verdict"
        );

        // ── (6) DILUTION. Three members turn up to defend the objection. The
        //    pool is six, a strict majority of six is four, and the three
        //    overrulers no longer carry it — protection returns by itself.
        for member in &members[4..7] {
            let b = ballot_row(member, true, &o1_id);
            assert_eq!(
                record_objection_ballot(dir, &b).await.expect("ballot"),
                ObjectionOutcome::Admitted
            );
        }
        let diluted = fold(action.clone(), after).await;
        let e_diluted = &diluted.escalation[0];
        assert_eq!(
            (
                e_diluted.respondents,
                e_diluted.required,
                e_diluted.overrule_ballots,
                e_diluted.uphold_ballots
            ),
            (6, 4, 3, 3),
            "({suffix}) upholders raise the denominator the attacker's majority \
             is measured against: {e_diluted:?}"
        );
        assert_eq!(e_diluted.outcome, EscalationOutcome::Unresolved);
        assert_eq!(
            diluted.counted_objection_ids,
            vec![o1_id.clone()],
            "({suffix}) the objection is LIVE again, with nobody having written \
             a retraction"
        );

        // ── (7) A DUTY-HOLDER WHO ANSWERS. On a second action the founder
        //    upholds in time, and three overruling ballots do not reopen the
        //    escalated path: a judged brake is not re-litigated by whoever is
        //    awake.
        let a2_id = uuid::Uuid::new_v4().to_string();
        let a2 = signed_row(
            &a2_id,
            &actor,
            &actor,
            serde_json::json!({
                "dimension": "testimonial_witness:commons_act:v1",
                "payload": {"action": "a second act, judged in time"},
            }),
            Utc::now(),
            &[],
        );
        dir.put_attestation(SignedAttestation {
            attestation: a2.clone(),
        })
        .await
        .expect("second action");
        let o2_id = uuid::Uuid::new_v4().to_string();
        let o2 = signed_row(
            &o2_id,
            &members[0],
            &actor,
            objection_envelope(Cohort::Community, &community, &a2_id, "and this too"),
            Utc::now(),
            &[],
        );
        assert_eq!(
            record_objection(dir, &o2).await.expect("record"),
            ObjectionOutcome::Admitted
        );
        let ruling = signed_row(
            &uuid::Uuid::new_v4().to_string(),
            &founder,
            &actor,
            ballot_envelope(
                Cohort::Community,
                &community,
                &a2_id,
                &o2_id,
                true,
                "reviewed: it stands",
            ),
            Utc::now(),
            &[],
        );
        assert_eq!(
            record_objection_ballot(dir, &ruling).await.expect("ballot"),
            ObjectionOutcome::Admitted
        );
        for member in &members[1..4] {
            let b = signed_row(
                &uuid::Uuid::new_v4().to_string(),
                member,
                &actor,
                ballot_envelope(
                    Cohort::Community,
                    &community,
                    &a2_id,
                    &o2_id,
                    false,
                    "disagree",
                ),
                Utc::now(),
                &[],
            );
            assert_eq!(
                record_objection_ballot(dir, &b).await.expect("ballot"),
                ObjectionOutcome::Admitted
            );
        }
        let judged = fold(a2.clone(), a2.asserted_at + Duration::seconds(9000)).await;
        let e_judged = &judged.escalation[0];
        assert_eq!(
            e_judged.steward,
            StewardTierStanding::Upheld,
            "({suffix}) the duty-holder answered, in time, on the record"
        );
        assert_eq!(e_judged.outcome, EscalationOutcome::NotEscalated);
        assert_eq!(
            (
                e_judged.respondents,
                e_judged.overrule_ballots,
                e_judged.uphold_ballots
            ),
            (4, 3, 1),
            "({suffix}) three members overruled and it bought them nothing — the \
             escalated door never opened. FOUR respondents, not three: the \
             founder's ruling is also their ballot, counted ONCE, read by two \
             predicates against two denominators — one person, one vote, on \
             whichever question is being asked: {e_judged:?}"
        );
        assert_eq!(judged.counted_objection_ids, vec![o2_id.clone()]);

        // ── (8) THE RECORD TRAVELS. A peer that never saw any of this receives
        //    the same signed rows and folds to the same escalation record. An
        //    escalation that lived in a control loop could not do this.
        let peer = crate::store::memory::MemoryBackend::new();
        for k in roster.iter().chain([&stranger, &community]) {
            register_user_key(&peer, k).await;
        }
        let now = Utc::now();
        peer.put_community(
            crate::federation::tier_ingest::test_support::sign_community(
                &founder,
                Community {
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
                    consensus_protocol: protocol.to_owned(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            ),
        )
        .await
        .expect("peer community");
        let mut replicated = 0usize;
        for r in dir
            .list_attestations_for(&actor)
            .await
            .expect("origin rows")
        {
            peer.put_attestation(SignedAttestation {
                attestation: r.clone(),
            })
            .await
            .expect("replicate");
            replicated += 1;
        }
        assert!(
            replicated >= 10,
            "({suffix}) the markers must actually have travelled, got {replicated}"
        );
        let peer_fold =
            resolve_reverse_quorum(&peer, Cohort::Community, &community, &action, after)
                .await
                .expect("peer resolve");
        assert_eq!(
            peer_fold.escalation, diluted.escalation,
            "({suffix}) a peer folds the replicated rows to the SAME record — \
             steward standing, respondent count, threshold and named ballots all"
        );
        assert_eq!(
            peer_fold.counted_objection_ids,
            diluted.counted_objection_ids
        );

        // ── (9) THE READ PATH HOLDS ITS OWN. A hostile peer can write a row
        //    straight into a store, bypassing the door entirely — the stranger's
        //    ballot is signed, verifiable and perfectly well-formed, and it is
        //    still not a respondent, because the COUNT intersects with the
        //    cohort's own roster before it counts anything.
        let smuggled = signed_row(
            &uuid::Uuid::new_v4().to_string(),
            &stranger,
            &actor,
            ballot_envelope(
                Cohort::Community,
                &community,
                &action_id,
                &o1_id,
                false,
                "not my commons",
            ),
            Utc::now(),
            &[],
        );
        peer.put_attestation(SignedAttestation {
            attestation: smuggled.clone(),
        })
        .await
        .expect("a peer can write what it likes into its own store");
        let smuggled_fold =
            resolve_reverse_quorum(&peer, Cohort::Community, &community, &action, after)
                .await
                .expect("peer resolve");
        assert_eq!(
            smuggled_fold.escalation, diluted.escalation,
            "({suffix}) the outsider's ballot is in the store and NOT in the \
             pool — neither in the numerator nor in the denominator"
        );
        assert!(
            !smuggled_fold.escalation[0]
                .counted_ballot_ids
                .contains(&smuggled.attestation_id),
            "({suffix}) …and the named evidence contains no outsider row"
        );
    }
}
