//! v18.2.0 (CIRISPersist#481) — the pluggable-trust-root graph predicate.
//!
//! Substrate half of CIRISServer's `FSD/TRUST_ROOT_CAPABILITY_GATE.md`
//! (CC ratification: CIRISConstitution#40). Trust is a layered graph of
//! plain `attestation` / `delegates_to` objects — **no new object kind**:
//!
//! - **Self-root base**: `attestation(user → user)` — the immutable
//!   identity floor. Ordinary self-attestation; nothing here touches it.
//! - **Root self-declaration**: `delegates_to(root → root,
//!   scope:[infra:attest, infra:serve])` — a root roots to itself; the
//!   self-loop IS what makes it a root.
//! - **The trust edge**: `delegates_to(user → root)` — the user's chosen,
//!   consensual delegation. Un-trust is the `withdraws` composer on that
//!   edge (the CEG tombstone; the walk folds it as ABSENT).
//!
//! [`trust_root_valid`] is the **pure graph predicate** the FSD demands —
//! "never a client assertion, never a cached flag". It lives in persist so
//! server / edge / agent share ONE implementation (the single-authority
//! discipline; edge reaches it via the directory capsule op).
//!
//! # The two trust planes (do not conflate)
//!
//! # v24.0.0 (CIRISPersist#557) — the root is a THRESHOLD, not a seat
//!
//! Until this cut a trust root was always exactly one key: `trust_root_valid`
//! took a `root_key_id`, a charter was a key's self-loop, and a node's
//! `trust:accepts` edge named whichever holder happened to sign. The accord is a
//! trio under `quorum:2/3` and its KILL SWITCH is deliberately 2-of-3 — so we
//! required two humans to halt the mesh and one to legitimize all of it. That
//! asymmetry was never decided; it was inherited from the portable root's
//! self-charter shape.
//!
//! [`trust_root_valid`] now also accepts a **keyless constitutional family** as
//! the root ([`RootKind::Family`]): the trust edge names the accord, and the
//! charter leg demands signatures from ≥m distinct SEATED holders, with m
//! re-derived from the node's own stored `consensus_protocol` and floored at a
//! strict majority of its own roster. Single-key roots are untouched and remain
//! fully valid — 1-of-1 is a legitimate quorum for a root you alone own, and
//! portability is the reason that arm exists.
//!
//! `infra:attest` here is a **delegation SCOPE token inside a
//! `delegates_to` envelope** — the user's consensual choice of what a root
//! may do for them. It is NOT the accord-conferred `infra:attest` **role**
//! on a `federation_keys` row (the v15.0.0 build-manifest trust root),
//! which remains gated by the accord co-scrub at every key-admission
//! chokepoint. A self-declared root confers capability only over users who
//! signed an edge to it; it gains NO standing in the accord role plane.

use super::precedence;
use super::types::{attestation_type, Attestation};
use super::{Error, FederationDirectory};

/// Upper bound (days) of the **green** drill band — a root drilled within
/// this window is currently governed. FSD `TRUST_ROOT_CAPABILITY_GATE.md` §2
/// item 2 pins "≤90-day refresh" per CC; the exact number is
/// CC#40-ratification-tracked — re-pin on ruling.
///
/// v23.0.0 (CIRISPersist#551 item 4) — replaces
/// `ACCORD_LIFECYCLE_FRESHNESS_DAYS`, which was a single number because it
/// was a GATE threshold. It is a band edge now; see [`DrillFreshness`].
pub const DRILL_GREEN_MAX_DAYS: i64 = 90;

/// Upper bound (days) of the **yellow** drill band. At or beyond this the
/// signal reads [`DrillFreshness::Red`]. See [`DrillFreshness`].
pub const DRILL_YELLOW_MAX_DAYS: i64 = 180;

/// v23.0.0 (CIRISPersist#551 item 4) — how recently the root was drilled,
/// as a **band**: the same band-not-float discipline every other score in
/// this substrate follows (FSD-005 App C).
///
/// # This is a signal, not a gate
///
/// It does NOT appear in [`TrustRootVerdict::valid`]. A root with a red
/// drill signal serves normally; its trust card just says so. The operator
/// decision behind this (#551 item 4 / CIRISPersist#550): **the drills ARE
/// the liveness signal, and liveness is a thing to REPORT, not a thing to
/// withhold service over.**
///
/// Before this cut the drill was a deadman inside `valid`, which gave a
/// genesis root a *shelf life*: a baked witness ages out, so ~90 days after
/// a mint every node depending on that root would darken together, with no
/// error at the point of use. That is the wrong failure mode for the wrong
/// question. A root is valid until **revoked, halted, or un-trusted** —
/// tombstones, the accord halt latch, and the user's own edge are the
/// revocation mechanisms, and they are all still hard gates. What a stale
/// drill actually distinguishes is *governed* from *abandoned*, which a
/// consumer should surface to a human, not enforce against a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DrillFreshness {
    /// Drilled less than [`DRILL_GREEN_MAX_DAYS`] ago.
    Green,
    /// Drilled at least [`DRILL_GREEN_MAX_DAYS`] but less than
    /// [`DRILL_YELLOW_MAX_DAYS`] ago.
    Yellow,
    /// Drilled [`DRILL_YELLOW_MAX_DAYS`] or longer ago — **or never**.
    ///
    /// Never-drilled deliberately shares this band rather than getting a
    /// fourth `Never` variant: an undrilled root and a long-abandoned one
    /// warrant the same skepticism, so they should read the same. The
    /// distinction is not lost — it is carried, unambiguously and in exactly
    /// one place, by [`TrustRootVerdict::last_drill_at`] being `None`. A
    /// `Never` variant would encode the same fact a second time, in a
    /// second field that could disagree with the first, which is the class
    /// of bug this whole cut exists to remove.
    Red,
}

impl DrillFreshness {
    /// Band `age`. `None` (never drilled) is [`Red`](Self::Red).
    fn of(age: Option<chrono::Duration>) -> Self {
        match age {
            Some(d) if d < chrono::Duration::days(DRILL_GREEN_MAX_DAYS) => Self::Green,
            Some(d) if d < chrono::Duration::days(DRILL_YELLOW_MAX_DAYS) => Self::Yellow,
            _ => Self::Red,
        }
    }
}

/// Dimension a root's **heartbeat** (liveness witness) carries. Versioned per
/// the mechanism-descriptive dimension rule (the #102 four-test gate requires
/// a version segment).
///
/// # The full contract (state it, do not infer it)
///
/// This row is **not** durable state and — as of v23.0.0 — **not a gate**.
/// It is a periodic drill, and what it reports is whether the root is
/// GOVERNED or ABANDONED:
///
/// - the newest live drill about a root surfaces as
///   [`TrustRootVerdict::last_drill_at`], banded into
///   [`TrustRootVerdict::drill_freshness`]: green < [`DRILL_GREEN_MAX_DAYS`],
///   yellow < [`DRILL_YELLOW_MAX_DAYS`], red at or beyond (and red when
///   never drilled);
/// - [`TrustRootVerdict::valid`] **does not consult it**. A root with a red
///   drill signal serves normally.
///
/// **A genesis root is valid until revoked, halted, or un-trusted.**
/// Tombstones (`withdraws` / `recants`), the accord halt latch, and the
/// user's own `trust:accepts:v1` edge are the revocation mechanisms, and all
/// three remain hard gates. Requiring liveness ON TOP of them gave the
/// artifact a shelf life instead: a BAKED witness ages out, so ~90 days
/// after a mint every node depending on that root darkened **together**,
/// with no error at the point of use. Shelf life is gone
/// (CIRISPersist#550 / #551 item 4).
///
/// v23.0.0 (CIRISPersist#551 item 4) — renamed from
/// `ACCORD_LIFECYCLE_DIMENSION` because "lifecycle" reads durable, as if a
/// state machine held a value; the mechanism is a drill, and reading it as
/// durable is how a mesh-wide shelf life went unnoticed in the first place.
///
/// **The wire token is FROZEN at `accord:lifecycle:v1`.** Prose says
/// heartbeat / drill; the bytes say `accord:lifecycle:v1`, because every
/// stored row carries that dimension inside a signed envelope — changing the
/// token would desync stored rows from the signatures over them (the #541
/// preserve-set≢verified-set class) and silently invalidate every existing
/// witness. A name in Rust is free to be honest; a name on the wire is not.
pub const ACCORD_HEARTBEAT_DIMENSION: &str = "accord:lifecycle:v1";

/// v23.0.0 (CIRISPersist#551 item 2) — the envelope `dimension` that NAMES
/// which of the three `delegates_to` jobs a row does.
///
/// One wire type carries three opposite jobs, and before this cut the ONLY
/// thing telling them apart was direction:
///
/// | job | shape | read by |
/// |---|---|---|
/// | charter | `delegates_to(R → R)` | [`TrustRootVerdict::root_self_declares`] |
/// | conferral | `delegates_to(R → subject, scope)` | the candidate loop in [`capability_roots_to_trusted_root_over_roster`] |
/// | trust edge | `delegates_to(node → R)` | [`TrustRootVerdict::edge_exists`] |
///
/// The middle two point OPPOSITE ways. #551 reports that this cost a session
/// with full source access four wrong statements about what the trust root
/// contains and who must sign what — every one a "which `delegates_to` is
/// this?" failure. Naming the job lets each predicate read English instead of
/// doing direction-arithmetic.
///
/// **Additive, no wire break.** The `attestation_type` stays `delegates_to`;
/// this is one more envelope member, and every pre-v23 row — which carries no
/// job dimension — still walks by direction inference exactly as before (see
/// [`job_dimension_admits`]). Stored rows and signed envelopes are untouched.
///
/// Registry status: `trust:*` is a NEW dimension family, not yet in the
/// vendored CC 3.1 namespace registry (that registration is filed separately —
/// #551 disposition item 2). Persist records its own manifest rows in
/// [`crate::federation::namespace::supersets::PERSIST_AUTHORED_TRUST_JOB_DIMENSIONS`]
/// rather than hand-editing the generated Registry-of-Record.
pub const TRUST_CHARTER_DIMENSION: &str = "trust:charter:v1";
/// The capability grant, `delegates_to(root → subject, scope)`. See
/// [`TRUST_CHARTER_DIMENSION`].
pub const TRUST_CONFERS_DIMENSION: &str = "trust:confers:v1";
/// The user's own trust edge, `delegates_to(node → root)` — the deletable
/// un-trust lever. See [`TRUST_CHARTER_DIMENSION`].
pub const TRUST_ACCEPTS_DIMENSION: &str = "trust:accepts:v1";

/// The closed set of job labels [`job_dimension_admits`] arbitrates. A
/// `delegates_to` carrying some OTHER dimension (or none) is making no claim
/// about its job, so direction inference decides — only these three tokens
/// are a claim that can be contradicted.
const TRUST_JOB_DIMENSIONS: &[&str] = &[
    TRUST_CHARTER_DIMENSION,
    TRUST_CONFERS_DIMENSION,
    TRUST_ACCEPTS_DIMENSION,
];

/// v23.0.0 (CIRISPersist#551 item 2) — may a row be read as doing `expected`?
///
/// **Prefer the label; refuse a contradiction; infer when silent.**
///
/// - carries `expected` → yes, and the reader never consults direction alone;
/// - carries a DIFFERENT job label → **no**, unconditionally. The caller has
///   already established the direction matches its job, so a row reaching
///   here with another label is one whose two self-descriptions disagree.
///   Refusing is the strictly safer read: a MISLABELED lever is worse than an
///   unlabeled one, because the label invites a reader (human or code) to
///   trust it instead of checking. Two answers that disagree is the #541
///   preserve-set≢verified-set class, and the fix is the same — refuse rather
///   than pick a winner.
/// - carries no job label → yes; direction inference stands, which is what
///   keeps this additive for every row written before v23.0.0.
fn job_dimension_admits(envelope: &serde_json::Value, expected: &str) -> bool {
    match super::admission::envelope_dimension(envelope) {
        Some(d) if TRUST_JOB_DIMENSIONS.contains(&d) => d == expected,
        _ => true,
    }
}

/// The delegation scope tokens a root self-declaration (its **charter**)
/// must carry. v19.0.0 (#488, RC3): the validity minimum is **BOTH**
/// `[infra:serve, infra:attest]` — "a root serves and vouches, or it is
/// inert" (a vouch-only or serve-only self-loop is not a trust root).
/// Extra charter scopes (`infra:store`, `infra:transport` — the accord's
/// full charter) are tolerated; `infra:network_presence` and
/// `infra:hold_*_membership` are owner-granted, never charter scopes.
pub const INFRA_ATTEST_SCOPE: &str = "infra:attest";
/// See [`INFRA_ATTEST_SCOPE`].
pub const INFRA_SERVE_SCOPE: &str = "infra:serve";

/// v19.0.0 (#488 delta 1, CRITICAL — the KERI lesson) — the envelope field
/// a root charter (`delegates_to(root → root)`) MUST carry: the
/// **pre-rotation commitment**, `lowercase_hex(sha256(JCS(successor_keys)))`
/// over the sorted JSON array of successor key_ids — the hash of the next
/// key set, published BEFORE it is ever needed. Tombstone-revocation
/// assumes the revoker's key is honest: compromise the charter key and the
/// attacker owns the tombstoning pen, and a self-referential root has no
/// superior to appeal to. Without the commitment (+ the m-of-n recovery
/// ceremony it enables), root-key compromise is unrecoverable BY
/// CONSTRUCTION (Parity: powers not pre-committed don't exist when
/// needed). Exact byte layout CC#40-ratification-tracked.
pub const CHARTER_PRE_ROTATION_FIELD: &str = super::envelope::paths::PRE_ROTATION_COMMITMENT;

/// v19.0.0 (#488 delta 1) — the recovery-declaration envelope fields: a
/// successor charter carries `recovers: <old_root_key_id>` plus
/// `successor_keys: [key_id, …]` whose JCS-sha256 must equal the
/// predecessor charter's [`CHARTER_PRE_ROTATION_FIELD`], and its attesting
/// key MUST be a member of that pre-committed set. (The holder-quorum
/// co-signature half of the ceremony rides the server propose+cosign flow;
/// its record shape is CC#40-tracked — persist verifies the pre-commitment
/// binding, the ceremony supplies the quorum.)
pub const CHARTER_RECOVERS_FIELD: &str = super::envelope::paths::RECOVERS;
/// See [`CHARTER_RECOVERS_FIELD`].
pub const CHARTER_SUCCESSOR_KEYS_FIELD: &str = super::envelope::paths::SUCCESSOR_KEYS;

/// Compute the pinned pre-rotation commitment over a successor key set:
/// `lowercase_hex(sha256(JCS(sorted keys as JSON array)))`. The ONE
/// construction both the charter producer and the recovery verifier use.
pub fn pre_rotation_commitment(successor_keys: &[String]) -> Result<String, Error> {
    use sha2::Digest as _;
    let mut sorted: Vec<&str> = successor_keys.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let value = serde_json::json!(sorted);
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(&value)
        .map_err(|e| Error::InvalidArgument(format!("successor_keys canonicalize: {e}")))?;
    Ok(hex::encode(sha2::Sha256::digest(&canonical)))
}

/// v24.0.0 (CIRISPersist#557) — WHAT KIND of thing the root reference names.
///
/// The two arms of [`trust_root_valid`] answer the same question about
/// structurally different objects, and naming the axis is what keeps this from
/// becoming one verdict with two silent value spaces (the #532 fusion class —
/// compare [`ConferralPlane`], added for the same reason).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RootKind {
    /// A single `federation_keys` key id — the root that chartered itself.
    /// **Still fully valid**: 1-of-1 is a legitimate quorum for a root you
    /// alone own, and a solo operator's personal mesh has exactly one seat.
    /// Portability is unchanged by #557; the family arm is *additional*
    /// expressiveness, not a replacement.
    #[default]
    Key,
    /// A KEYLESS constitutional family id (`humanity-accord` in the bake). The
    /// family holds no key — which is the point: there is no seat to
    /// compromise, so the identifier can be the durable name of the root while
    /// the AUTHORITY is re-derived from the family's roster and threshold.
    Family,
}

/// v24.0.0 (CIRISPersist#557) — the charter-quorum accounting for a
/// [`RootKind::Family`] root: how many DISTINCT seated holders actually
/// hybrid-verified over the charter, against how many this node's OWN stored
/// policy requires.
///
/// Reported whether the quorum held or not, because the interesting case is the
/// shortfall: "1 of 2 required distinct holders" is the whole finding of
/// CIRISPersist#557 rendered as a number a human can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CharterQuorum {
    /// Distinct seated holders whose scrub over the charter envelope verified
    /// against this node's DIRECTORY-pinned pubkeys.
    pub distinct_holders: usize,
    /// The threshold, re-derived from the node's OWN state: the family row's
    /// `consensus_protocol`, floored at a strict majority of the node's OWN
    /// active roster so a tampered policy string cannot talk it down.
    pub required: usize,
    /// The node's OWN active roster size (revocation-folded), for context.
    pub roster_size: usize,
}

impl CharterQuorum {
    /// Did the charter reach the threshold?
    #[must_use]
    pub fn met(&self) -> bool {
        self.distinct_holders >= self.required
    }

    /// One line naming the shortfall — the phrasing a refusal quotes.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{} of {} required distinct holders (roster of {})",
            self.distinct_holders, self.required, self.roster_size
        )
    }
}

/// The typed, per-check verdict of [`trust_root_valid`].
///
/// Open accounting, not a bare bool (the derivation-trace discipline): a
/// consumer gates on [`Self::valid`] but can SEE which leg failed and
/// surface the right remediation ("attach a root" vs "root heartbeat
/// stale" vs "halt latched").
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustRootVerdict {
    /// A live (non-tombstoned, non-expired) `delegates_to(user → root)`
    /// edge exists with `root != user` — the FSD's "NOT the base
    /// self-root" rule.
    pub edge_exists: bool,
    /// `root` carries a live self-referential `delegates_to(root → root)`
    /// charter whose envelope `scope` includes **BOTH** `infra:serve` AND
    /// `infra:attest` (v19.0.0 #488: the RC3 validity minimum — a root
    /// serves and vouches, or it is inert).
    pub root_self_declares: bool,
    /// v19.0.0 (#488, CRITICAL) — the live charter carries a well-formed
    /// [`CHARTER_PRE_ROTATION_FIELD`] (64 lowercase hex), so root-key
    /// compromise is recoverable by the pre-committed m-of-n ceremony.
    pub charter_has_recovery: bool,
    /// v23.0.0 (CIRISPersist#551 item 4) — when the root was last drilled:
    /// the `asserted_at` of the newest LIVE drill about it (non-tombstoned,
    /// non-expired, federation-tier), or `None` if it has never been
    /// drilled. Reported so a consumer can render "last drill performed X
    /// days ago"; banded by [`Self::drill_freshness`].
    ///
    /// This REPLACES the pre-v23 `lifecycle_active: bool`. Clean break, no
    /// alias field: the boolean's whole meaning was "does this leg let the
    /// root serve", and that question no longer exists.
    pub last_drill_at: Option<chrono::DateTime<chrono::Utc>>,
    /// v23.0.0 (CIRISPersist#551 item 4) — [`Self::last_drill_at`] as a
    /// band. **A signal, never a gate** — deliberately absent from
    /// [`Self::valid`]; see [`DrillFreshness`] for why.
    pub drill_freshness: DrillFreshness,
    /// The accord halt latch for `root` (keyed as the halt-table family
    /// id): `Some(true)` = a halt is latched (brake pulled); `Some(false)`
    /// = present-and-clear; `None` = this backend cannot answer
    /// (halt storage unsupported) — reported honestly, never guessed.
    pub halt_latched: Option<bool>,
    /// The gate: every leg holds (including charter recovery) and no halt
    /// is latched.
    pub valid: bool,
    /// v24.0.0 (CIRISPersist#557) — which arm produced this verdict. `#[serde(default)]`
    /// = [`RootKind::Key`], so payloads from pre-v24 producers deserialize unchanged.
    #[serde(default)]
    pub root_kind: RootKind,
    /// v24.0.0 (CIRISPersist#557) — the charter-quorum accounting, present only
    /// for a [`RootKind::Family`] root. `Some` with
    /// [`CharterQuorum::met`] false is the #557 refusal: a charter signed by
    /// fewer distinct seated holders than this node's own policy requires, which
    /// is why [`Self::root_self_declares`] is false beside it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charter_quorum: Option<CharterQuorum>,
    /// v24.1.0 (CIRISPersist#561) — **the instant this verdict can first stop
    /// holding on time alone**, or `None` when nothing it counted is
    /// time-bounded.
    ///
    /// The earliest moment at which some leg of [`Self::valid`] expires: the
    /// user's trust edge and the root's live recovery-carrying charter(s) each
    /// survive while ANY of their rows is live, so each leg contributes its
    /// LATEST expiry (`None` = never, and never dominates), and the verdict
    /// contributes the EARLIEST of those legs.
    ///
    /// It exists because [`resolve_transit_eligibility`] must return an
    /// authoritative cache TTL, and the only code that knows WHICH rows counted
    /// is the walk that counted them. Re-deriving the charter set at the caller
    /// would fork [`job_dimension_admits`], the tombstone fold, the tier filter
    /// and the family-quorum count — four predicates whose whole design rule is
    /// that they exist once (#483). Reported here so the consumer's TTL cannot
    /// drift from the authority that produced the verdict.
    ///
    /// **Not a gate.** A verdict is `valid` or it is not; this says when to ask
    /// again. `#[serde(default)]` = `None`, so payloads from pre-v24.1
    /// producers deserialize unchanged, and an unbounded verdict serializes
    /// byte-identically to before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bounded_until: Option<chrono::DateTime<chrono::Utc>>,
}

/// v24.1.0 (CIRISPersist#561) — the EARLIER of two expiry bounds, treating
/// `None` as "never expires".
///
/// The min-fold behind every TTL in this module: a conjunction dies when its
/// first conjunct dies, and a conjunct with no expiry cannot be the one that
/// kills it. Folding from `None` therefore yields `None` only when nothing
/// walked was time-bounded, which is exactly the contract
/// [`TransitEligibility::valid_until`] documents.
fn earlier_bound(
    a: Option<chrono::DateTime<chrono::Utc>>,
    b: Option<chrono::DateTime<chrono::Utc>>,
) -> Option<chrono::DateTime<chrono::Utc>> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (Some(x), None) => Some(x),
        (None, other) => other,
    }
}

/// v24.1.0 (CIRISPersist#561) — the LATEST expiry across a set of
/// INTERCHANGEABLE live rows, treating `None` as "never expires".
///
/// A leg backed by several rows (two live trust edges, two live charters)
/// survives while ANY one of them does, so the leg's bound is the latest — and
/// a single never-expiring row makes the whole leg unbounded. An EMPTY set
/// returns `None`, which is safe because an empty set means the leg did not
/// hold at all and no TTL is being reported for it.
fn latest_bound<'a, I>(rows: I) -> Option<chrono::DateTime<chrono::Utc>>
where
    I: IntoIterator<Item = &'a Attestation>,
{
    let mut best: Option<chrono::DateTime<chrono::Utc>> = None;
    for row in rows {
        // One unbounded row makes the leg unbounded, whatever else is here —
        // so a `None` short-circuits the whole fold to `None`.
        let t = row.expires_at?;
        best = Some(best.map_or(t, |b: chrono::DateTime<chrono::Utc>| b.max(t)));
    }
    best
}

/// v19.0.0 (#488 delta 3, the OCSP/CRLite lesson) — a row is LIVE only if
/// it is neither tombstoned nor **expired**: an expired `delegates_to` must
/// be as dead to the walk as a withdrawn one (stale grants die of age;
/// grants outliving purpose are the dominant real-world breach class —
/// Ronin's stale allowlist).
fn is_expired(a: &Attestation, now: chrono::DateTime<chrono::Utc>) -> bool {
    a.expires_at.is_some_and(|e| e <= now)
}

/// v21.0.0 (CIRISPersist#502 E5) — does this row COUNT in a capability
/// decision? Only FEDERATION-tier rows do. A local-tier attestation is
/// producer-only (deferred signature, visible solely to the producing
/// occurrence); before this it silently counted in `trust_root_valid` /
/// `capability_roots_to_trusted_root`, so a local-tier `delegates_to(user
/// → root)` or root self-charter could forge the capability gate the
/// instant any local-tier row reached `put_attestation` from the wire.
/// The walk now ignores every non-federation-tier row — the exploit is
/// closed at the READ side regardless of how the row was admitted.
fn counts_in_capability_walk(a: &Attestation) -> bool {
    a.tier == super::types::attestation_tier::FEDERATION
}

/// v28.3.0 (CIRISPersist#570 ask 1) — **every trust root `node_key_id` has a
/// live edge to**, sorted and deduped. The node's own subscription set.
///
/// A "root" here is the `attested_key_id` of a live (non-tombstoned,
/// non-expired, federation-tier) `delegates_to(node → R)` that is not
/// self-referential and does not claim some OTHER `trust:*` job. That is
/// exactly leg 1 of [`trust_root_valid`], evaluated with the SAME four
/// predicates — `tombstoned_ids`, `is_expired`, `counts_in_capability_walk`,
/// `job_dimension_admits` — rather than a second filter free to disagree with
/// the first. It lives here for that reason: those four are private to this
/// module, and a caller reimplementing "live trust edge" over
/// `list_attestations_by` is precisely the two-lists class.
///
/// # What this deliberately does NOT check
///
/// It does not run the full [`trust_root_valid`] predicate. A root whose
/// charter has lapsed, whose pre-rotation commitment is missing, or whose halt
/// latch is pulled is **still returned**, and
/// [`crate::federation::mesh_config`] — the caller this exists for — still
/// folds its rows.
///
/// That is the fail-secure direction for a plane where every value is a
/// RESTRICTION. Dropping a lapsed root from the mesh-config fold would silently
/// RELAX whatever that root had tightened, on a schedule nobody chose, and a
/// restriction that evaporates when its author's paperwork ages is not a
/// restriction. The un-trust lever is the node's own edge — one row, deletable,
/// and the only thing that should end a subscription.
///
/// A caller making a CAPABILITY decision must keep calling
/// [`trust_root_valid`]; this is a subscription enumeration, not a validity
/// verdict, and the two are named differently on purpose.
pub async fn trusted_roots_of<F>(
    directory: &F,
    node_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let by_node = match directory.list_attestations_by(node_key_id).await {
        Ok(rows) => rows,
        Err(Error::Unsupported { .. }) => Vec::new(),
        Err(e) => return Err(e),
    };
    let refs: Vec<&Attestation> = by_node.iter().collect();
    let dead = tombstoned_ids(&refs);
    let mut roots: Vec<String> = by_node
        .iter()
        .filter(|a| {
            a.attestation_type == attestation_type::DELEGATES_TO
                && a.attested_key_id != node_key_id
                && !dead.contains(&a.attestation_id)
                && !is_expired(a, now)
                && counts_in_capability_walk(a)
                && job_dimension_admits(&a.attestation_envelope, TRUST_ACCEPTS_DIMENSION)
        })
        .map(|a| a.attested_key_id.clone())
        .collect();
    roots.sort();
    roots.dedup();
    Ok(roots)
}

/// Is this envelope's [`CHARTER_PRE_ROTATION_FIELD`] present and
/// well-formed (64 lowercase hex — a sha256)?
fn charter_commitment_well_formed(envelope: &serde_json::Value) -> bool {
    envelope
        .get(CHARTER_PRE_ROTATION_FIELD)
        .and_then(|v| v.as_str())
        .is_some_and(|h| {
            h.len() == 64
                && h.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
}

/// Does `token` appear in the envelope's `scope` field? Accepts the two
/// established wire shapes (`topology.rs` convention): a bare string or an
/// array of tokens. `pub(crate)` so the composed [`capability_roots_to_trusted_root`]
/// walk shares the ONE scope-parse (never forked).
pub(crate) fn scope_contains(envelope: &serde_json::Value, token: &str) -> bool {
    envelope
        .get(super::envelope::paths::SCOPE)
        .cloned()
        .and_then(|v| serde_json::from_value::<super::envelope::ScopeSet>(v).ok())
        .is_some_and(|s| s.contains(token))
}

/// Fold the CEG tombstones over `rows`: an attestation is DEAD when a
/// `withdraws` / `recants` composer (precedence-winning, same-attester
/// authority is enforced at composer admission) references its id.
/// Returns the set of dead `attestation_id`s. `pub(crate)` so the composed
/// [`capability_roots_to_trusted_root`] walk shares the ONE tombstone fold
/// (the module's single-authority discipline — never forked, per #483).
pub(crate) fn tombstoned_ids(rows: &[&Attestation]) -> std::collections::HashSet<String> {
    use std::collections::HashMap;
    let mut by_target: HashMap<&str, Vec<&Attestation>> = HashMap::new();
    for row in rows {
        if precedence::is_structural_composer(&row.attestation_type) {
            if let Some(target) =
                precedence::references_attestation_id_from_envelope(&row.attestation_envelope)
            {
                by_target.entry(target).or_default().push(row);
            }
        }
    }
    let mut dead = std::collections::HashSet::new();
    for (target, composers) in by_target {
        if let Some(winner) = precedence::precedence_winner(&composers) {
            if winner.attestation_type == attestation_type::WITHDRAWS
                || winner.attestation_type == attestation_type::RECANTS
            {
                dead.insert(target.to_owned());
            }
        }
    }
    dead
}

/// v24.0.0 (CIRISPersist#557) — does `root_ref` name a constitutional family
/// this node has stored?
///
/// The ONE place the two arms of [`trust_root_valid`] are chosen between, so
/// they can never be selected by two different rules. A backend that cannot
/// answer (the FFI directory capsule reports [`Error::Unsupported`] for
/// `lookup_family`) reads as "no family" — the pre-v24 key-only behaviour —
/// rather than guessing, exactly as the halt leg already does.
/// `pub(crate)` since v25.2.0 — [`crate::federation::mesh_config`] asks the
/// same question (KEY root or FAMILY root?) to decide what "the root's own
/// quorum" means for a durable config row, and asking it a second way is how
/// two call sites come to disagree about which arm a root is on.
pub(crate) async fn resolve_family_root<F>(
    directory: &F,
    root_ref: &str,
) -> Result<Option<super::types::Family>, Error>
where
    F: FederationDirectory + ?Sized,
{
    match directory.lookup_family(root_ref).await {
        Ok(found) => Ok(found),
        Err(Error::Unsupported { .. }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// v24.0.0 (CIRISPersist#557) — the threshold this node's OWN state demands of
/// a family, given its stored `consensus_protocol` and its OWN active roster.
///
/// **Floored at a strict majority of the node's own roster**, the identical
/// defense [`super::genesis::bundle::verify_bundle_quorum`] applies to a carried
/// `consensus_protocol`: a tampered policy string cannot talk the threshold
/// down. Reused rather than re-derived — one rule, two call sites.
///
/// The non-`quorum:M/N` members of the closed
/// [`consensus_protocol`](super::types::consensus_protocol) vocabulary are read
/// FAIL-SECURE: `unanimous` (and any form this function does not recognise)
/// demands the whole roster rather than a guess, because under-counting a
/// threshold is the failure mode #557 exists to close.
pub(crate) fn family_charter_threshold(family: &super::types::Family, roster_size: usize) -> usize {
    let floor = ciris_verify_core::accord_genesis::strict_majority(roster_size);
    let policy = match family.consensus_protocol.as_str() {
        "founder_only" | "majority" => floor,
        "unanimous" => roster_size,
        other => super::genesis::bundle::parse_quorum(other).map_or(
            // Unrecognised policy ⇒ unanimity, never a guessed-low number.
            roster_size,
            |(m, _)| m,
        ),
    };
    policy.max(floor)
}

/// v24.0.0 (CIRISPersist#557) — how many DISTINCT seated holders of `family`
/// really signed `row`?
///
/// The row's FULL scrub set ([`Attestation::scrubs`] — the base
/// `scrub_key_id`/`scrub_signature_*` plus every `additional_scrubs` entry, all
/// over the SAME canonical envelope) is intersected with the family's OWN active
/// roster, and each survivor is hybrid-verified through
/// [`verify_envelope_hybrid_signature`](super::verify_envelope_hybrid_signature)
/// — the same primitive federation-tier ingest runs, against pubkeys resolved
/// from THIS node's directory. Never the roster a caller passed, never pubkeys
/// carried on the row: authority is re-derived from the node's own verified
/// state (the #377 rule).
///
/// A scrub that is not a seated holder, or that does not verify, simply does not
/// COUNT — it is not an error. That is the m-of-n discipline the key plane
/// already uses (`verify_quorum_policy` counts valid founder signatures and
/// ignores the rest), and it means a stray co-signature degrades the evidence
/// rather than destroying the row.
/// `pub(crate)` since v25.2.0 — [`crate::federation::mesh_config`] uses this
/// EXACT accounting for "the root's own quorum ratifying" (CC 4.2.1 rule 3) on
/// a durable config row. One implementation of m-of-n-over-a-row, two callers;
/// a second one written for the config plane would be free to count differently
/// from the one that charters roots.
pub(crate) async fn family_quorum_over<F>(
    directory: &F,
    row: &Attestation,
    family: &super::types::Family,
) -> Result<CharterQuorum, Error>
where
    F: FederationDirectory + ?Sized,
{
    // The roster is the REVOCATION-FOLDED active seat set, not the raw member
    // list: a holder removed from the family stops counting toward its quorum
    // immediately, and a charter that once reached the threshold stops reaching
    // it — which is exactly why the count is re-derived at READ time instead of
    // being frozen at admission.
    let roster: Vec<String> = match directory.active_family_members(&family.family_key_id).await {
        Ok(members) => members.into_iter().map(|m| m.key_id).collect(),
        Err(Error::Unsupported { .. }) => Vec::new(),
        Err(e) => return Err(e),
    };
    let required = family_charter_threshold(family, roster.len());

    // v24.3.0 (CIRISPersist#574) — the count itself lives in
    // [`super::reverse_quorum::count_distinct_roster_scrubs`]. It was lifted
    // out of this function so the charter plane and the commons' m-of-n undo
    // door run the SAME body: "a distinct verified co-signature" must mean one
    // thing in this repo, and two copies of it is the two-lists-that-disagree
    // class (rule #9 — one predicate, one implementation).
    let counted = super::reverse_quorum::count_distinct_roster_scrubs(
        directory,
        &row.attestation_envelope,
        &row.scrubs(),
        &roster,
    )
    .await;
    Ok(CharterQuorum {
        distinct_holders: counted.len(),
        required,
        roster_size: roster.len(),
    })
}

/// v18.2.0 (CIRISPersist#481) — the trust-root graph predicate.
///
/// Evaluates, purely from graph state (FSD `TRUST_ROOT_CAPABILITY_GATE.md`
/// §2):
/// 1. a live `delegates_to(user → root)` edge exists, `root != user`;
/// 2. `root` self-declares (`delegates_to(root → root)` with an
///    `infra:attest` / `infra:serve` scope), live, carrying a recovery
///    pre-commitment;
/// 3. no accord halt is latched for `root`.
///
/// # v24.0.0 (CIRISPersist#557) — `root_ref` may name a FAMILY
///
/// The mesh's root authority is a THRESHOLD, not a seat. When `root_ref`
/// resolves to a constitutional family this node has stored, the same three
/// legs are evaluated against the family instead of a key:
///
/// | leg | key root | family root |
/// |---|---|---|
/// | edge | `delegates_to(user → root_key)` | `delegates_to(user → family_id)` |
/// | charter | `delegates_to(root → root)`, self-signed | `delegates_to(holder → family)` whose FULL scrub set reaches the family's own threshold |
/// | halt | `get_active_halt(root_key)` (always misses — the table is family-keyed) | `get_active_halt(family_id)` — the accord's real 2-of-3 kill switch |
///
/// The threshold is re-derived from the node's OWN stored state — the family
/// row's `consensus_protocol`, floored at a strict majority of its OWN
/// revocation-folded roster — never from anything the caller or the row says
/// (the #377 rule). Because it is re-derived at READ time, revoking a seat from
/// the family retroactively un-charters a root that only reached the threshold
/// with that seat's signature, with no write anywhere.
///
/// **The key arm is unchanged and stays fully valid.** 1-of-1 is a legitimate
/// quorum for a root you alone own; a solo operator's portable mesh keeps
/// working exactly as before, and the currently-baked single-key genesis root
/// remains valid under it. See [`RootKind`].
///
/// It ALSO reports, without gating on it, when `root` was last drilled
/// ([`TrustRootVerdict::last_drill_at`] /
/// [`TrustRootVerdict::drill_freshness`]). v23.0.0 (CIRISPersist#551 item
/// 4) removed the drill from the conjunction: a root is valid until
/// revoked, halted, or un-trusted, and a deadman on top of those gave the
/// artifact a shelf life. See [`DrillFreshness`].
///
/// The rooting-chain leg (FSD §2 item 2's "chain from this node's records
/// roots to it") stays with the existing [`super::rooting`] /
/// `has_accord_conferred_role` walks — this predicate composes beside them, it
/// does not re-derive them.
pub async fn trust_root_valid<F>(
    directory: &F,
    user_key_id: &str,
    root_ref: &str,
) -> Result<TrustRootVerdict, Error>
where
    F: FederationDirectory + ?Sized,
{
    // A self-root is the immutable BASE, never a valid EXTERNAL root (the
    // FSD's gate demands a SHARED external root).
    if user_key_id == root_ref {
        return Ok(TrustRootVerdict {
            edge_exists: false,
            root_self_declares: false,
            charter_has_recovery: false,
            // Nothing was read on this path, so nothing is claimed: no
            // drill found, banded Red. Consistent with every other leg
            // reporting "not established" here.
            last_drill_at: None,
            drill_freshness: DrillFreshness::Red,
            halt_latched: None,
            valid: false,
            root_kind: RootKind::Key,
            charter_quorum: None,
            bounded_until: None,
        });
    }

    // v24.0.0 (CIRISPersist#557) — WHICH ARM. Resolved once, from the node's own
    // stored state, before any leg is evaluated.
    let family = resolve_family_root(directory, root_ref).await?;
    let root_kind = if family.is_some() {
        RootKind::Family
    } else {
        RootKind::Key
    };

    // One read per authority: everything the user attested (edges + their
    // tombstones — a withdraws on your own edge is attested by YOU), and
    // everything attested about/by the root (self-declaration + its
    // tombstones + lifecycle rows).
    let by_user = directory.list_attestations_by(user_key_id).await?;
    let by_root = directory.list_attestations_by(root_ref).await?;
    let about_root = directory.list_attestations_for(root_ref).await?;

    let now = chrono::Utc::now();

    // 1. Edge: live (non-tombstoned, non-expired) delegates_to(user → root).
    // v23.0.0 (#551 item 2): the row may NAME itself `trust:accepts:v1`; one
    // claiming a different job is refused here (see `job_dimension_admits`).
    let user_refs: Vec<&Attestation> = by_user.iter().collect();
    let user_dead = tombstoned_ids(&user_refs);
    // v24.1.0 (CIRISPersist#561) — collected rather than `.any()`-ed, so the
    // SAME predicate that decides `edge_exists` also supplies the edge leg's
    // expiry bound. One predicate, one pass; a second filter written to compute
    // the TTL is a second answer free to disagree with the first.
    let live_edges: Vec<&Attestation> = by_user
        .iter()
        .filter(|a| {
            a.attestation_type == attestation_type::DELEGATES_TO
                && a.attested_key_id == root_ref
                && !user_dead.contains(&a.attestation_id)
                && !is_expired(a, now)
                && counts_in_capability_walk(a)
                && job_dimension_admits(&a.attestation_envelope, TRUST_ACCEPTS_DIMENSION)
        })
        .collect();
    let edge_exists = !live_edges.is_empty();

    // 2. Charter.
    //
    // KEY ROOT — live delegates_to(root → root) carrying BOTH infra:serve AND
    // infra:attest (v19.0.0 #488 — the RC3 AND-minimum; extra charter scopes
    // tolerated). The self-loop IS what makes a key a root.
    //
    // FAMILY ROOT (v24.0.0, CIRISPersist#557) — a family is KEYLESS, so it
    // cannot sign a self-loop and the self-loop shape is structurally
    // unavailable. Its analogue is `delegates_to(holder → family)` labelled
    // `trust:charter:v1`, carried in the ABOUT set rather than the BY set, and
    // it counts as a charter only when its FULL scrub set reaches the family's
    // own threshold. That is the whole of #557: *the roster charters the
    // family*, so no single seat can declare itself the mesh's root.
    //
    // The recovery leg (#488 delta 1) reads the SAME live charter rows on both
    // arms: any live charter with a well-formed pre-rotation commitment
    // satisfies it. Pre-rotation still protects individual SEATS; the family
    // root additionally survives losing one without any ceremony at all.
    let root_refs: Vec<&Attestation> = by_root.iter().collect();
    let root_dead = tombstoned_ids(&root_refs);
    let about_refs: Vec<&Attestation> = about_root.iter().collect();
    let about_dead = tombstoned_ids(&about_refs);

    let charter_shaped = |a: &&Attestation, dead: &std::collections::HashSet<String>| {
        a.attestation_type == attestation_type::DELEGATES_TO
            && a.attested_key_id == root_ref
            && !dead.contains(&a.attestation_id)
            && !is_expired(a, now)
            && counts_in_capability_walk(a)
            && job_dimension_admits(&a.attestation_envelope, TRUST_CHARTER_DIMENSION)
            && scope_contains(&a.attestation_envelope, INFRA_SERVE_SCOPE)
            && scope_contains(&a.attestation_envelope, INFRA_ATTEST_SCOPE)
    };

    let (live_charters, charter_quorum): (Vec<&Attestation>, Option<CharterQuorum>) =
        match family.as_ref() {
            None => (
                by_root
                    .iter()
                    .filter(|a| charter_shaped(a, &root_dead) && a.attesting_key_id == root_ref)
                    .collect(),
                None,
            ),
            Some(fam) => {
                let mut quorate: Vec<&Attestation> = Vec::new();
                // Reported even when nothing reaches the bar: the SHORTFALL is
                // the finding a human acts on ("1 of 2 required distinct
                // holders"), so the best candidate's count is carried out.
                let mut best: Option<CharterQuorum> = None;
                for candidate in about_root.iter().filter(|a| charter_shaped(a, &about_dead)) {
                    let q = family_quorum_over(directory, candidate, fam).await?;
                    if q.met() {
                        quorate.push(candidate);
                    }
                    if best.is_none_or(|b| q.distinct_holders > b.distinct_holders) {
                        best = Some(q);
                    }
                }
                // No charter-shaped row at all still deserves an honest number:
                // 0 of whatever this node requires.
                let reported = match best {
                    Some(q) => q,
                    None => {
                        let roster_size =
                            match directory.active_family_members(&fam.family_key_id).await {
                                Ok(m) => m.len(),
                                Err(Error::Unsupported { .. }) => 0,
                                Err(e) => return Err(e),
                            };
                        CharterQuorum {
                            distinct_holders: 0,
                            required: family_charter_threshold(fam, roster_size),
                            roster_size,
                        }
                    }
                };
                (quorate, Some(reported))
            }
        };
    let root_self_declares = !live_charters.is_empty();
    // v24.1.0 (CIRISPersist#561) — the recovery-carrying subset, collected for
    // the same reason `live_edges` is: `valid` needs BOTH charter legs, so the
    // set that actually holds the conjunction up is this one, and it is the one
    // whose expiry bounds the verdict.
    let recovery_charters: Vec<&Attestation> = live_charters
        .iter()
        .copied()
        .filter(|a| charter_commitment_well_formed(&a.attestation_envelope))
        .collect();
    let charter_has_recovery = !recovery_charters.is_empty();

    // 3. Drill SIGNAL (v23.0.0, #551 item 4 — no longer a gate): the NEWEST
    // live drill about the root, reported with its age banded. No freshness
    // filter in the fold any more — an old drill is still a drill, and
    // "when was it" is exactly the fact being reported. Tombstones for
    // rows-about-root can come from their own attesters; fold over the
    // about-set (composers reference the target id and carry the same
    // attested key). A tombstoned / expired / local-tier row is still not a
    // drill: those legs are unchanged.
    //
    // v24.0.0 (CIRISPersist#557) — unchanged for a FAMILY root too, and
    // deliberately so: `list_attestations_for(family_id)` is already "drills
    // about the family", which is the only shape the drill can take once the
    // root is the family rather than a seat. A drill naming an individual
    // holder is a drill about that holder, not about the accord.
    let last_drill_at = about_root
        .iter()
        .filter(|a| {
            a.attestation_type == attestation_type::SCORES
                && super::admission::envelope_dimension(&a.attestation_envelope)
                    == Some(ACCORD_HEARTBEAT_DIMENSION)
                && !about_dead.contains(&a.attestation_id)
                && !is_expired(a, now)
                && counts_in_capability_walk(a)
        })
        .map(|a| a.asserted_at)
        .max();
    let drill_freshness = DrillFreshness::of(last_drill_at.map(|t| now.signed_duration_since(t)));

    // 4. Halt latch (kill-switch state). Unsupported backends report None
    // — honestly unknown, never guessed.
    // v24.0.0 (CIRISPersist#557) — on the FAMILY arm this argument is finally
    // the kind of id the halt table is keyed by (`accord_active_halt` has
    // `family_key_id` as its PRIMARY KEY), so the accord's 2-of-3 kill switch
    // now latches against the root it was always meant to stop. On the key arm
    // it stays a key id and, as before, resolves to "no halt".
    let halt_latched = match directory.get_active_halt(root_ref).await {
        Ok(v) => Some(v.is_some()),
        Err(Error::Unsupported { .. }) => None,
        Err(e) => return Err(e),
    };

    // v23.0.0 (#551 item 4) — `drill_freshness` is DELIBERATELY absent from
    // this conjunction. The hard gates are the ones that answer "may this
    // root act": a consensual edge, a real charter, a recovery commitment,
    // and no halt latched. The drill answers "is anyone still minding it",
    // which is reported beside the verdict, not enforced inside it.
    let valid =
        edge_exists && root_self_declares && charter_has_recovery && halt_latched != Some(true);

    // v24.1.0 (CIRISPersist#561) — when this verdict can first lapse on time.
    // Each leg survives while ANY of its rows is live (latest expiry wins,
    // `None` = never); the VERDICT lapses when its first leg does (earliest
    // wins). Reported only for a verdict that currently holds: "when does this
    // stop being true" is not a question about something already false, and a
    // TTL attached to a refusal would invite a caller to cache it.
    let bounded_until = valid.then(|| {
        earlier_bound(
            latest_bound(live_edges.iter().copied()),
            latest_bound(recovery_charters.iter().copied()),
        )
    });

    Ok(TrustRootVerdict {
        edge_exists,
        root_self_declares,
        charter_has_recovery,
        last_drill_at,
        drill_freshness,
        halt_latched,
        valid,
        root_kind,
        charter_quorum,
        bounded_until: bounded_until.flatten(),
    })
}

/// The winning grant returned by [`capability_roots_to_trusted_root`]: the
/// root that confers the scope AND that the asking user trusts, plus that
/// root's full [`TrustRootVerdict`] (the derivation-trace discipline — the
/// consumer sees WHICH root and WHY it counted, never a bare bool).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustedGrant {
    /// The root that both (a) conferred `scope` on the subject (see
    /// [`Self::conferral_plane`] for HOW) and (b) passes
    /// [`trust_root_valid`] from the asking user's records.
    ///
    /// v24.0.0 (CIRISPersist#557) — for a [`ConferralPlane::FamilyQuorum`] grant
    /// this carries the FAMILY id, which is not a key. The wire name is kept
    /// (renaming it would break every downstream deserializer for a cosmetic
    /// gain); what disambiguates it is [`TrustRootVerdict::root_kind`] on
    /// [`Self::verdict`], which NAMES the axis rather than leaving one field
    /// with two silent value spaces.
    pub root_key_id: String,
    /// Which row carried the conferral. Its meaning is keyed by
    /// [`Self::conferral_plane`] — the two planes confer through different
    /// objects, and naming the axis explicitly is what keeps this from
    /// being one field with two silent value spaces (the #532 fusion class):
    /// - [`ConferralPlane::Delegation`]: the `delegates_to(root → subject)`
    ///   grant's `attestation_id`.
    /// - [`ConferralPlane::AccordCoScrub`]: the subject's `key_id` — the
    ///   conferral lives ON the co-scrubbed `KeyRecord`, which has no
    ///   attestation id.
    pub grant_attestation_id: String,
    /// The winning root's trust verdict (all legs green — it is the reason
    /// `valid` held).
    pub verdict: TrustRootVerdict,
    /// v22.1.0 (CIRISPersist#548) — WHICH conferral plane produced the
    /// candidate. `#[serde(default)]` = `Delegation`, so payloads from
    /// pre-#548 producers deserialize unchanged.
    #[serde(default)]
    pub conferral_plane: ConferralPlane,
}

/// v22.1.0 (CIRISPersist#548) — the two planes a capability conferral can
/// travel on. The portable-trust-root doctrine names them: CEREMONY (an
/// accord 2-of-3 co-scrub on the key record — root identity) and DELEGATION
/// (`delegates_to` rows — operational capability). The baked genesis seed
/// carries its `infra:serve` conferral in the ceremony encoding ONLY, which
/// is what #548 found: the walk read one plane while the admission-side
/// effective-role read (`has_accord_conferred_role`) read the other, and a fully
/// accord-blessed canonical could not receive traces.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ConferralPlane {
    /// A live `delegates_to(root → subject)` grant carried the scope.
    #[default]
    Delegation,
    /// The subject's own key record carries the scope as a role INSIDE its
    /// accord-co-scrubbed `registration_envelope`, verified 2-of-3 against
    /// THIS node's effective accord roster. The candidate root is the
    /// subject itself — the ceremony is what MAKES it a root — and the
    /// asking user's own trust chain to it (edge, charter, heartbeat, halt)
    /// is still required in full via [`trust_root_valid`].
    AccordCoScrub,
    /// v24.0.0 (CIRISPersist#557) — a live `delegates_to(holder → subject)`
    /// grant carried the scope AND its own scrub set reached the QUORUM of a
    /// constitutional family the granter sits in. The candidate root is that
    /// FAMILY, not the holder who signed.
    ///
    /// # The granter semantic, chosen and written down
    ///
    /// #557 asks whether the walk should accept a grant whose granter is the
    /// family id itself, or one from a quorum-covered holder acting for it.
    /// **It is the second, and the code leaves no real choice**: a
    /// constitutional family is KEYLESS by doctrine, so a row with
    /// `attesting_key_id = <family id>` could never be signed and could never
    /// pass federation-tier ingest, which verifies the attester's REGISTERED
    /// pubkeys. A grant that merely *named* the family in its envelope while
    /// carrying one seat's signature would be worse than the status quo — it
    /// would let A1 alone re-grant under the accord's name, which is exactly
    /// the authority #557 exists to take away from any single seat.
    ///
    /// So the family a grant acts for is **derived, never asserted**: from the
    /// grant's own verified signer set, intersected with the node's OWN family
    /// rosters. There is no `on_behalf_of` field to forge, and adding one seat's
    /// signature to a grant buys nothing until the threshold is met.
    FamilyQuorum,
}

/// v18.3.0 (CIRISPersist#483) — the composed capability walk: does
/// `subject_key_id` hold delegation `scope`, granted by a root that
/// `user_key_id` trusts?
///
/// The `ConferralPlane::Delegation` half of CIRISEdge#386's trace serve
/// gate: it must confirm the recipient's
/// `infra:serve` roots to a root **the sending node itself trusts** — so
/// two nodes serve each other only under a COMMON valid root, and un-trust
/// stops serving immediately. Kept in persist (not re-derived in edge)
/// because it reuses the module's ONE scope-parse + ONE CEG-tombstone fold;
/// forking those into a consumer would double the policy the FSD demands
/// live in a single authority.
///
/// Walk: enumerate live (non-tombstoned) `delegates_to(candidate_root →
/// subject)` edges carrying `scope`, and for each candidate evaluate
/// [`trust_root_valid`] from the user's records. Returns the FIRST valid
/// root as a [`TrustedGrant`] (`None` if the subject holds the scope from
/// no root the user trusts — or from no root at all). Self-granted scope
/// (`root == subject`) is skipped: a subject cannot confer capability on
/// itself here, mirroring the self-root-is-not-an-external-root rule.
pub async fn capability_roots_to_trusted_root(
    directory: &dyn FederationDirectory,
    user_key_id: &str,
    subject_key_id: &str,
    scope: &str,
) -> Result<Option<TrustedGrant>, Error> {
    capability_roots_to_trusted_root_over_roster(
        directory,
        user_key_id,
        subject_key_id,
        scope,
        &super::admission::accord_holder_roster_key_ids(),
    )
    .await
}

/// v22.1.0 (CIRISPersist#548) — the roster-parameterized core of
/// [`capability_roots_to_trusted_root`], mirroring the
/// [`has_accord_conferred_role`](super::admission::has_accord_conferred_role) /
/// [`has_accord_conferred_role_over_roster`](super::admission::has_accord_conferred_role_over_roster)
/// split and for the same reason: the production roster is the node's OWN
/// genesis-derived accord holders (whose private halves live in the #268
/// hardware ceremony), so an explicit-roster variant is the only way a test
/// or a downstream conformance run can drive the ceremony arm with keys it
/// actually holds.
pub async fn capability_roots_to_trusted_root_over_roster(
    directory: &dyn FederationDirectory,
    user_key_id: &str,
    subject_key_id: &str,
    scope: &str,
    accord_roster_key_ids: &[String],
) -> Result<Option<TrustedGrant>, Error> {
    // Every grant ABOUT the subject (delegates_to(* → subject)) plus its
    // tombstones — a withdraws/recants on a grant is attested about the
    // same subject, so the one about-read carries both.
    let about_subject = directory.list_attestations_for(subject_key_id).await?;
    let about_refs: Vec<&Attestation> = about_subject.iter().collect();
    let dead = tombstoned_ids(&about_refs);
    let now = chrono::Utc::now();

    // Candidate roots: distinct granters of a live (non-tombstoned,
    // non-expired — #488 delta 3) scoped delegates_to edge to the subject
    // (excluding a self-grant). Dedup so a root that granted twice is
    // walked once.
    let conferral_shaped = |a: &&Attestation| {
        a.attestation_type == attestation_type::DELEGATES_TO
            && a.attested_key_id == subject_key_id
            && a.attesting_key_id != subject_key_id
            && !dead.contains(&a.attestation_id)
            && !is_expired(a, now)
            && counts_in_capability_walk(a)
            // v23.0.0 (#551 item 2) — this loop reads CONFERRALS
            // (R → subject); a row here labeled charter or trust-edge is
            // pointing the other way and does not confer.
            && job_dimension_admits(&a.attestation_envelope, TRUST_CONFERS_DIMENSION)
            && scope_contains(&a.attestation_envelope, scope)
    };

    let mut seen = std::collections::HashSet::new();
    let candidates: Vec<(&str, &str)> = about_subject
        .iter()
        .filter(conferral_shaped)
        .filter(|a| seen.insert(a.attesting_key_id.clone()))
        .map(|a| (a.attesting_key_id.as_str(), a.attestation_id.as_str()))
        .collect();

    // First candidate root the user actually trusts wins.
    for (root_key_id, grant_id) in candidates {
        let verdict = trust_root_valid(directory, user_key_id, root_key_id).await?;
        if verdict.valid {
            return Ok(Some(TrustedGrant {
                root_key_id: root_key_id.to_owned(),
                grant_attestation_id: grant_id.to_owned(),
                verdict,
                conferral_plane: ConferralPlane::Delegation,
            }));
        }
    }

    // ── FAMILY-QUORUM plane (v24.0.0 / CIRISPersist#557) ─────────────────
    // The same conferral rows, read for a different root: a grant signed by
    // ENOUGH distinct seated holders of a family is a grant BY THAT FAMILY, and
    // the candidate root is the family id.
    //
    // The family is DERIVED from the grant's own verified signer set against
    // this node's OWN rosters — see [`ConferralPlane::FamilyQuorum`] for why
    // that, and not a granter field naming the family, is the only safe reading.
    // Runs AFTER the plain delegation loop (a single-key root costs no quorum
    // crypto) and BEFORE the ceremony arm, matching the cheapest-first ordering
    // this walk has always used.
    let mut family_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for grant in about_subject.iter().filter(conferral_shaped) {
        let families = match directory
            .list_families_for_member(&grant.attesting_key_id)
            .await
        {
            Ok(f) => f,
            // Honestly unknown, never guessed — same treatment the halt leg
            // gives a backend that cannot answer.
            Err(Error::Unsupported { .. }) => Vec::new(),
            Err(e) => return Err(e),
        };
        for family in families {
            if !family_seen.insert(format!(
                "{}\u{1f}{}",
                family.family_key_id, grant.attestation_id
            )) {
                continue;
            }
            let quorum = family_quorum_over(directory, grant, &family).await?;
            if !quorum.met() {
                continue;
            }
            let verdict = trust_root_valid(directory, user_key_id, &family.family_key_id).await?;
            if verdict.valid {
                return Ok(Some(TrustedGrant {
                    root_key_id: family.family_key_id,
                    grant_attestation_id: grant.attestation_id.clone(),
                    verdict,
                    conferral_plane: ConferralPlane::FamilyQuorum,
                }));
            }
        }
    }
    // ── CEREMONY-PLANE fallback (v22.1.0 / CIRISPersist#548) ─────────────
    // The baked genesis seed carries its conferral as a 2-of-3 accord
    // co-scrub on the subject's OWN key record — roles inside the
    // scrub-signed registration_envelope, zero `delegates_to` rows. That is
    // the ceremony encoding: the accord blesses the identity, and the
    // blessing is what MAKES the subject a root. Before this arm, the
    // `AccordCoScrub` read (`has_accord_conferred_role`) consulted that plane
    // while this walk read only `Delegation` — so a fully accord-blessed
    // canonical rooted to nothing and the trace plane stayed dark on a
    // production-seeded node. (v23.0.0 / CIRISPersist#551 item 3: this used
    // to be written "leg A" and "leg B", names that recorded the ORDER two
    // checks run in and not the PLANE each consults — which is why #548's
    // first proposed remedy would have deleted the operator's un-trust
    // lever. The planes have names; use them.)
    //
    // The check IS the `AccordCoScrub` plane, by call —
    // `has_accord_conferred_role_over_roster`
    // (claims_role + verify_accord_family_coscrub against THIS node's
    // effective roster), never a re-implementation: one predicate, one impl.
    // A portable root minted by a DIFFERENT trio does not verify against our
    // roster and does not need to — its mint already carries the delegation
    // plane (charter + grant), which the loop above serves.
    //
    // HALF 2 IS UNTOUCHED, deliberately (the corrected #548 ask): the
    // candidate still walks `trust_root_valid(user, subject-as-root)` in
    // full — the user's OWN `delegates_to(user → subject)` edge, the
    // subject's self-charter with a recovery commitment, a fresh
    // heartbeat witness, no halt latched. So the operator's un-trust
    // lever survives exactly as designed: delete the one edge row and the
    // verdict goes false, the walk returns None, the serve gate withholds,
    // agent capabilities gate off, manifests stop — all emergent, nothing
    // special-cased. A ceremony arm that skipped half 2 would have deleted
    // that lever, which is strictly worse than the bug it fixes.
    //
    // Runs AFTER the delegation loop: delegation grants are the specific,
    // cheap path (no quorum crypto); the ceremony check costs a 2-of-3
    // hybrid verification, so cheapest-first ordering holds here too.
    if super::admission::has_accord_conferred_role_over_roster(
        directory,
        subject_key_id,
        scope,
        accord_roster_key_ids,
    )
    .await?
    {
        let verdict = trust_root_valid(directory, user_key_id, subject_key_id).await?;
        if verdict.valid {
            return Ok(Some(TrustedGrant {
                root_key_id: subject_key_id.to_owned(),
                // Keyed by `conferral_plane`: the conferral lives ON the
                // co-scrubbed KeyRecord, which has no attestation id.
                grant_attestation_id: subject_key_id.to_owned(),
                verdict,
                conferral_plane: ConferralPlane::AccordCoScrub,
            }));
        }
    }
    Ok(None)
}

/// v24.1.0 (CIRISPersist#561) — the verdict of
/// [`resolve_transit_eligibility`]: may this peer carry our relay traffic, and
/// for how long may the answer be cached?
///
/// Shaped for a hot path. CIRISEdge#430 gates A/V relay HOP SELECTION on this,
/// and selection happens on peer churn and per-substream in MDC — so edge
/// resolves trust ONCE per candidate, caches `(eligible, valid_until)`, and
/// keeps `AlmJoinPlanner::plan` crypto-free. Everything expensive is on this
/// side of the call.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TransitEligibility {
    /// The gate. All four conjuncts held — see
    /// [`resolve_transit_eligibility`].
    pub eligible: bool,
    /// Min expiry across every attestation the walk COUNTED: the peer's
    /// `KeyRecord::valid_until`, and each side's satisfying trust edge and
    /// root charter (via [`TrustRootVerdict::bounded_until`], so the bound is
    /// computed by the walk that chose the rows, at persist's own
    /// [`is_expired`] reference time — the caller's TTL cannot drift from the
    /// authority).
    ///
    /// `None` = nothing walked is time-bounded ⇒ cache until a withdrawal
    /// event. A denied verdict carries `None`: "when does this stop being
    /// true" is not a question about something already false, and a TTL on a
    /// refusal would invite a caller to cache the refusal.
    pub valid_until: Option<chrono::DateTime<chrono::Utc>>,
    /// The shared root that satisfied conjunct (D) — observability, and the
    /// cache-invalidation key. A tombstone naming this root (or the peer)
    /// drops the cached verdict on the caller's replication apply path;
    /// [`Self::valid_until`] is the backstop if such an event is ever missed.
    ///
    /// May name a KEY root or a keyless constitutional FAMILY — a shared
    /// family root satisfies (D) exactly as a key root does, and which kind it
    /// is falls out of [`trust_root_valid`]'s own arm selection rather than
    /// being decided again here.
    pub via_root: Option<String>,
}

impl TransitEligibility {
    /// The fail-closed verdict: not eligible, no TTL, no root.
    ///
    /// The ONE value every refusal path returns, so "what does a denied
    /// transport gate look like" has a single answer rather than one per
    /// early exit.
    #[must_use]
    fn denied() -> Self {
        Self {
            eligible: false,
            valid_until: None,
            via_root: None,
        }
    }
}

/// v24.1.0 (CIRISPersist#561) — one candidate shared root, drawn from the
/// USER's own live `trust:accepts` edges.
///
/// A named type rather than a bare `String` because the candidate SET is the
/// thing the anti-inflation property is about: its size is bounded by the
/// asking node's own record count, and [`transit_candidate_roots`] is where
/// that is enforced and can be asserted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransitCandidateRoot {
    /// The root the user's edge names (a key id or a family id).
    pub root_ref: String,
}

/// v24.1.0 (CIRISPersist#561) — the candidate shared roots for conjunct (D):
/// the distinct targets of the USER's own live `delegates_to(user → R)`
/// accepts-edges.
///
/// # This is the anti-inflation boundary
///
/// The candidate set is drawn from the ASKING NODE's records and never from
/// the peer's. A hostile peer can author fifty `delegates_to` rows naming
/// fifty roots; none of them lands here, so neither the set nor the work grows
/// — the walk runs `trust_root_valid` at most once per root the user itself
/// chose to trust. Enumerating from the peer instead (or from the union) would
/// let any peer set the cost of evaluating it, on a hot path, for free.
///
/// The same liveness rules as [`trust_root_valid`]'s edge leg, by construction:
/// non-tombstoned, non-expired at `now`, federation-tier, and not claiming a
/// different `delegates_to` job. Self-edges are excluded — a self-root is the
/// immutable base, never a SHARED external root.
///
/// `pub(crate)` so the parity harness can assert the bound directly rather
/// than inferring it from timings.
pub(crate) fn transit_candidate_roots(
    by_user: &[Attestation],
    user_key_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<TransitCandidateRoot> {
    let refs: Vec<&Attestation> = by_user.iter().collect();
    let dead = tombstoned_ids(&refs);
    let mut seen = std::collections::HashSet::new();
    by_user
        .iter()
        .filter(|a| {
            a.attestation_type == attestation_type::DELEGATES_TO
                && a.attested_key_id != user_key_id
                && !dead.contains(&a.attestation_id)
                && !is_expired(a, now)
                && counts_in_capability_walk(a)
                && job_dimension_admits(&a.attestation_envelope, TRUST_ACCEPTS_DIMENSION)
        })
        .filter(|a| seen.insert(a.attested_key_id.clone()))
        .map(|a| TransitCandidateRoot {
            root_ref: a.attested_key_id.clone(),
        })
        .collect()
}

/// v24.1.0 (CIRISPersist#561) — **may `peer_key_id` carry our relay traffic?**
///
/// The substrate half of CIRISEdge#430's A/V hop-selection gate. Persist owns
/// the whole resolution — the shared-root composition AND the expiry — so edge
/// holds zero trust logic: call once per candidate, cache
/// `(eligible, valid_until)`, drop the entry on a withdrawal event.
///
/// # `eligible` = all four
///
/// | | conjunct | why |
/// |---|---|---|
/// | A | present in the federation directory | we have a record of it at all |
/// | B | its `identity_type` set contains `node` | the verifiable recast of "proxy/server mode", which is not remotely attestable |
/// | C | it self-offers `infra:transport` | the peer says it relays |
/// | D | it validly trusts a root WE validly trust | the actual bar |
///
/// # Deliberately weaker than the `infra:serve` conferral walk
///
/// A relay carries only ciphertext — no `EpochDek` is reachable from a hop —
/// so what a bad hop gets is POSITION, not content. Shared-root anchoring is
/// the proportionate bar for that, and it is what keeps relaying
/// DECENTRALIZED: any trust-anchored node offering transport can serve as a
/// hop, not only the ones our own root has blessed. Requiring
/// [`capability_roots_to_trusted_root`] here would have made the mesh's relay
/// topology a function of one root's grants.
///
/// (A)–(C) are self-claims and are meant to be. The AV-75 property holds
/// because (D) is not: registering the string `infra:transport` buys nothing
/// without a shared root, which is a property this function has a test for.
///
/// # Fail-closed, always
///
/// Any directory error, an unregistered `user_key_id`, an unresolvable read —
/// every one returns [`TransitEligibility::denied`]. A transport gate never
/// fails open, so the failure of a read is never the reason a peer becomes
/// usable. The `Result` is retained for API stability and because a future leg
/// may need to distinguish an infrastructure fault from a refusal; today every
/// resolution path returns `Ok`.
///
/// # Withdrawal
///
/// No new API. A revocation or tombstone for the peer or for
/// [`TransitEligibility::via_root`] invalidates the cached verdict — the
/// caller drops the entry on its replication apply path, and
/// [`TransitEligibility::valid_until`] is the backstop if an event is missed.
/// The substrate half is emergent: withdraw the edge and the very next
/// resolution reads `false`, because (D) re-derives from live graph state
/// every time.
pub async fn resolve_transit_eligibility(
    directory: &dyn FederationDirectory,
    user_key_id: &str,
    peer_key_id: &str,
) -> Result<TransitEligibility, Error> {
    resolve_transit_eligibility_over_roster(
        directory,
        user_key_id,
        peer_key_id,
        &super::admission::accord_holder_roster_key_ids(),
    )
    .await
}

/// v24.1.0 (CIRISPersist#561) — the roster-parameterized
/// [`resolve_transit_eligibility`], mirroring the
/// [`capability_roots_to_trusted_root`] /
/// [`capability_roots_to_trusted_root_over_roster`] split.
///
/// # What the roster does here, stated plainly
///
/// **Nothing, today, and that is a fact about the RULE rather than about this
/// function.** The sibling walks take a roster because they end in a CEREMONY
/// arm — `has_accord_conferred_role_over_roster` verifies a 2-of-3 accord
/// co-scrub, and the production roster's private halves live in the #268
/// hardware ceremony, so a test can only drive that arm with an injected
/// roster. Transit eligibility has no such arm: conjuncts (A)–(C) read the
/// peer's own `KeyRecord`, and (D) is `trust_root_valid` on both sides, whose
/// family arm re-derives its threshold from `active_family_members` — the
/// FAMILY's roster, resolved from this node's own state, not the accord-holder
/// constant.
///
/// It is kept, and kept honest by this paragraph rather than by being quietly
/// threaded somewhere it would not matter, for two reasons. The transport gate
/// should carry the same signature as the two walks a reader will compare it
/// to; and if a ceremony leg is ever added — a peer whose relationship to the
/// shared root is carried by an accord co-scrub rather than a `trust:accepts`
/// edge, which is the #548 shape one plane over — it must be addable without a
/// breaking signature change, because the version where that leg exists and
/// cannot be tested is the version that ships fail-closed-dead (CIRISEdge#379).
///
/// **Widening (D) to accept that ceremony encoding was considered and NOT
/// done**: it would make more peers eligible than the rule as written, and a
/// transport gate is not the place to widen on inference.
pub async fn resolve_transit_eligibility_over_roster(
    directory: &dyn FederationDirectory,
    user_key_id: &str,
    peer_key_id: &str,
    accord_roster_key_ids: &[String],
) -> Result<TransitEligibility, Error> {
    // See the doc above: the roster reaches no verifier in this walk, because
    // none of the four conjuncts reads the ceremony plane.
    let _ = accord_roster_key_ids;
    match transit_eligibility_walk(directory, user_key_id, peer_key_id).await {
        Ok((verdict, _roots_walked)) => Ok(verdict),
        Err(e) => {
            // The fail-closed clause, and the only place it fires. A read that
            // failed tells us nothing about the peer, and "nothing" is not a
            // reason to route traffic through it.
            tracing::warn!(
                user_key_id,
                peer_key_id,
                error = %e,
                "resolve_transit_eligibility: read failed — DENYING (a transport gate \
                 never fails open)"
            );
            Ok(TransitEligibility::denied())
        }
    }
}

/// v24.1.0 (CIRISPersist#561) — [`resolve_transit_eligibility`], plus **how
/// many candidate roots the walk actually evaluated**.
///
/// The anti-inflation property is about COST, not just about the verdict: a
/// hostile peer authoring fifty `delegates_to` rows must not be able to make
/// this walk do fifty times the crypto on a hot path. That is only assertable
/// if the work is observable, and the honest way to observe the REAL walk's
/// work is to have the real walk report it — not a process-global counter (racy
/// under a threaded runner, and a second thing to keep in sync) and not a test
/// re-derivation of the candidate set (which would pass even if the walk
/// ignored the boundary entirely — the first draft of this witness did exactly
/// that and stayed green under a deliberately inflated walk).
///
/// `pub(crate)` and returning the count is why the parity harness can assert
/// `roots_walked` is unchanged across a 50-row flood. Gated exactly like
/// [`super::operational::test_support`], its only consumer — the count is an
/// observability hook for the witness, not surface a production caller needs.
#[cfg(any(test, feature = "test-anchor"))]
pub(crate) async fn resolve_transit_eligibility_counting_roots(
    directory: &dyn FederationDirectory,
    user_key_id: &str,
    peer_key_id: &str,
) -> Result<(TransitEligibility, usize), Error> {
    match transit_eligibility_walk(directory, user_key_id, peer_key_id).await {
        Ok(out) => Ok(out),
        // Same fail-closed clause as the public entry point; a denied verdict
        // walked nothing.
        Err(_) => Ok((TransitEligibility::denied(), 0)),
    }
}

/// The fallible core of [`resolve_transit_eligibility`]. Every `?` here becomes
/// a DENY at the boundary above; nothing in this body may return a permissive
/// value on an error path.
///
/// Returns the verdict and the number of candidate roots evaluated — see
/// [`resolve_transit_eligibility_counting_roots`].
async fn transit_eligibility_walk(
    directory: &dyn FederationDirectory,
    user_key_id: &str,
    peer_key_id: &str,
) -> Result<(TransitEligibility, usize), Error> {
    use super::types::{delegation_scope, identity_type};

    // A node is not its own hop. Short-circuited before any read: the
    // shared-root rule needs two parties, and `trust_root_valid` already
    // refuses a self-root as the immutable base rather than an external root.
    if user_key_id == peer_key_id {
        return Ok((TransitEligibility::denied(), 0));
    }

    // (A) directory presence.
    let Some(peer) = directory.lookup_public_key(peer_key_id).await? else {
        return Ok((TransitEligibility::denied(), 0));
    };

    // (B) it is a NODE.
    //
    // Read as SET MEMBERSHIP, not string equality. `identity_type` is a
    // scalar-or-comma-joined set (#441 — `claims_role` reads it the same way),
    // and the canonical serve node in the genesis bake carries
    // `identity_type = "canonical,node"`. `== "node"` would deny exactly the
    // production nodes most likely to be asked to relay, which is a denial
    // with no security content: (B) is a self-claim either way, and the bar
    // that does the work is (D).
    if !identity_type::set_contains(&peer.identity_type, identity_type::NODE) {
        return Ok((TransitEligibility::denied(), 0));
    }

    // (C) it self-offers transport.
    if !peer.claims_role(delegation_scope::INFRA_TRANSPORT) {
        return Ok((TransitEligibility::denied(), 0));
    }

    // (D) shared root. Candidates come from the USER's own edges — see
    // `transit_candidate_roots` for why that boundary is the anti-inflation
    // property and not merely an optimization.
    let now = chrono::Utc::now();
    let by_user = directory.list_attestations_by(user_key_id).await?;
    let mut roots_walked = 0usize;
    for candidate in transit_candidate_roots(&by_user, user_key_id, now) {
        roots_walked += 1;
        let ours = trust_root_valid(directory, user_key_id, &candidate.root_ref).await?;
        if !ours.valid {
            continue;
        }
        // Only now is the peer's side worth reading: a root WE do not validly
        // trust cannot be a SHARED root however the peer feels about it, and
        // checking us first keeps the per-candidate cost on our own records.
        let theirs = trust_root_valid(directory, peer_key_id, &candidate.root_ref).await?;
        if !theirs.valid {
            continue;
        }

        // The TTL: the earliest bound across everything the walk counted. Each
        // verdict's `bounded_until` already folds that side's trust edge and
        // charter at persist's own `is_expired` reference time; the peer's key
        // record contributes its own validity window.
        let valid_until = earlier_bound(
            earlier_bound(peer.valid_until, ours.bounded_until),
            theirs.bounded_until,
        );
        // A bound already in the past means the walk counted something whose
        // window has closed — in practice the peer's own `valid_until`, since
        // every graph row the legs counted was liveness-filtered at `now`. An
        // expired key is not an eligible hop, and reporting `eligible: true`
        // beside an elapsed TTL would be a fail-OPEN dressed as a fresh answer.
        if valid_until.is_some_and(|t| t <= now) {
            return Ok((TransitEligibility::denied(), roots_walked));
        }
        return Ok((
            TransitEligibility {
                eligible: true,
                valid_until,
                via_root: Some(candidate.root_ref),
            },
            roots_walked,
        ));
    }
    Ok((TransitEligibility::denied(), roots_walked))
}

/// v24.0.0 (CIRISPersist#557) — the FAMILY-charter admission gate: a charter
/// that names a constitutional family must be signed by that family's QUORUM,
/// and it is refused at the write chokepoint if it is not.
///
/// # Why a second gate rather than a wider first one
///
/// [`check_trust_charter_admission`] is handed an envelope, not a row, because
/// the local-tier writers call it before any row exists. A family charter's
/// authority lives in its SCRUB SET, which only a row carries — so this gate
/// takes the row and runs at `put_attestation` only. That is not a hole: a
/// local-tier row defers its signature and is ignored by
/// [`counts_in_capability_walk`], and a promote re-signs with the promoting
/// node's single key, so neither path can manufacture a quorum.
///
/// # What it refuses, and what it deliberately does not
///
/// Fires only on a `delegates_to` carrying [`TRUST_CHARTER_DIMENSION`] whose
/// attester is not its own subject AND whose subject resolves as a family this
/// node knows — the shape a family charter has and a key self-charter never has.
/// Then:
///
/// 1. the pre-rotation commitment rule applies unchanged (#488 delta 1) — the
///    family root survives losing a seat, but the SEATS still rotate;
/// 2. the row's full scrub set must reach the family's own threshold, re-derived
///    from this node's stored roster and `consensus_protocol`. The refusal NAMES
///    the shortfall ("1 of 2 required distinct holders"), because "quorum not
///    met" without the numbers tells a ceremony operator nothing about whether
///    they are one signature short or looking at the wrong family.
///
/// A `trust:charter:v1` row whose subject is somebody else's KEY is deliberately
/// NOT refused here. It is mislabeled — on the key arm a root charters ITSELF —
/// but #551 item 2 settled where that gets caught: **a mislabeled row still
/// writes, and the WALK refuses it** ([`job_dimension_admits`] returns false for
/// a row whose two self-descriptions disagree). Refusing it at ingest as well
/// would move a deliberate read-side decision to the write side and break the
/// contract that cut pinned. What is judged here is the one thing only the
/// writer can be judged for: a charter that names a real family and does not
/// carry that family's quorum.
///
/// A backend that cannot answer the family question degrades to a no-op, the
/// pre-v24 behaviour, rather than refusing rows it cannot judge.
pub async fn check_family_charter_admission<F>(
    directory: &F,
    row: &Attestation,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    if row.attestation_type != attestation_type::DELEGATES_TO
        || row.attesting_key_id == row.attested_key_id
        || super::admission::envelope_dimension(&row.attestation_envelope)
            != Some(TRUST_CHARTER_DIMENSION)
    {
        return Ok(());
    }
    let refuse = |detail: String| Err(Error::CharterInvalid { detail });

    // Not a family ⇒ a MISLABELED key-plane row. Stored and inert, per #551
    // item 2 — see the type-level doc.
    let Some(family) = resolve_family_root(directory, &row.attested_key_id).await? else {
        return Ok(());
    };

    if !charter_commitment_well_formed(&row.attestation_envelope) {
        return refuse(format!(
            "family charter for {} must carry a well-formed \
             \"{CHARTER_PRE_ROTATION_FIELD}\" (64 lowercase hex — sha256 of the \
             pre-committed successor key set); a quorum-rooted family survives losing \
             a seat, but the seats themselves still rotate",
            family.family_key_id
        ));
    }

    let quorum = family_quorum_over(directory, row, &family).await?;
    if !quorum.met() {
        return refuse(format!(
            "family charter for {} is signed by {} — the accord's own \
             consensus_protocol {:?} makes this root a threshold, not a seat, and a \
             charter below it would hand one holder the authority that grants \
             everything",
            family.family_key_id,
            quorum.describe(),
            family.consensus_protocol
        ));
    }
    Ok(())
}

/// v19.0.0 (CIRISPersist#488 delta 1, CRITICAL — the KERI lesson) — the
/// charter admission gate, run at every attestation write chokepoint.
///
/// A **root charter** is a self-referential `delegates_to(root → root)`
/// whose envelope `scope` carries any `infra:*` token. From this cut, a
/// charter MUST be born recoverable:
///
/// 1. The envelope MUST carry a well-formed
///    [`CHARTER_PRE_ROTATION_FIELD`] (64 lowercase hex — the sha256 of the
///    pre-committed successor key set, published BEFORE ever needed).
///    Without it, compromise of the charter key is unrecoverable by
///    construction — the attacker owns the tombstoning pen and a
///    self-referential root has no superior to appeal to.
/// 2. A **recovery declaration** (envelope carries
///    [`CHARTER_RECOVERS_FIELD`] + [`CHARTER_SUCCESSOR_KEYS_FIELD`]) is
///    verified against the predecessor: the successor key set must hash
///    (via [`pre_rotation_commitment`] — the ONE pinned construction) to
///    the predecessor's live charter commitment, and the attesting new
///    root MUST be a member of that pre-committed set. The holder-quorum
///    co-signature half of the ceremony rides the server propose+cosign
///    flow (record shape CC#40-tracked); persist verifies the
///    pre-commitment binding — the part that makes forging a recovery
///    cryptographically impossible without the pre-committed keys.
///
/// Non-charter rows (any non-`delegates_to`, any non-self-loop, any
/// self-loop without an `infra:*` scope) fast-exit untouched.
pub async fn check_trust_charter_admission<F>(
    directory: &F,
    attestation_type_str: &str,
    attesting_key_id: &str,
    attested_key_id: &str,
    envelope: &serde_json::Value,
) -> Result<(), Error>
where
    F: FederationDirectory + ?Sized,
{
    // Charter shape: self-loop delegates_to with an infra:* scope.
    if attestation_type_str != attestation_type::DELEGATES_TO || attesting_key_id != attested_key_id
    {
        return Ok(());
    }
    let has_infra_scope = match envelope.get(super::envelope::paths::SCOPE) {
        Some(serde_json::Value::String(s)) => s.starts_with("infra:"),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .any(|v| v.as_str().is_some_and(|s| s.starts_with("infra:"))),
        _ => false,
    };
    if !has_infra_scope {
        return Ok(());
    }
    let refuse = |detail: String| Err(Error::CharterInvalid { detail });

    // 1. Pre-rotation commitment: present + well-formed, always.
    if !charter_commitment_well_formed(envelope) {
        return refuse(format!(
            "root charter must carry a well-formed \"{CHARTER_PRE_ROTATION_FIELD}\" \
             (64 lowercase hex — sha256 of the pre-committed successor key set); \
             without it root-key compromise is unrecoverable by construction"
        ));
    }

    // 2. Recovery declaration (if present): verify the pre-commitment binding.
    let recovers = envelope
        .get(CHARTER_RECOVERS_FIELD)
        .and_then(|v| v.as_str());
    let successors: Option<Vec<String>> = envelope
        .get(CHARTER_SUCCESSOR_KEYS_FIELD)
        .and_then(|v| serde_json::from_value(v.clone()).ok());
    match (recovers, successors) {
        (None, None) => Ok(()),
        (Some(old_root), Some(successor_keys)) => {
            if old_root.is_empty() || successor_keys.is_empty() {
                return refuse(
                    "recovery declaration must name a predecessor and a non-empty \
                     successor key set"
                        .into(),
                );
            }
            if !successor_keys.iter().any(|k| k == attesting_key_id) {
                return refuse(format!(
                    "recovery charter attester {attesting_key_id} is not a member of \
                     its own successor key set — only a pre-committed key may rotate \
                     the charter"
                ));
            }
            // The predecessor's live charter commitment must equal the hash
            // of THIS successor set (the pre-commitment binding).
            let claimed = pre_rotation_commitment(&successor_keys)?;
            let by_old = directory.list_attestations_by(old_root).await?;
            let old_refs: Vec<&Attestation> = by_old.iter().collect();
            let old_dead = tombstoned_ids(&old_refs);
            let now = chrono::Utc::now();
            let bound = by_old.iter().any(|a| {
                a.attestation_type == attestation_type::DELEGATES_TO
                    && a.attested_key_id == old_root
                    && !old_dead.contains(&a.attestation_id)
                    && !is_expired(a, now)
                    && counts_in_capability_walk(a)
                    && a.attestation_envelope
                        .get(CHARTER_PRE_ROTATION_FIELD)
                        .and_then(|v| v.as_str())
                        == Some(claimed.as_str())
            });
            if !bound {
                return refuse(format!(
                    "recovery declaration does not bind: no live charter of {old_root} \
                     pre-committed to this successor key set \
                     (computed commitment {claimed})"
                ));
            }
            Ok(())
        }
        _ => refuse(format!(
            "recovery declaration must carry BOTH \"{CHARTER_RECOVERS_FIELD}\" and \
             \"{CHARTER_SUCCESSOR_KEYS_FIELD}\", or neither"
        )),
    }
}
