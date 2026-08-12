//! CIRISServer#356 — **the operator read surface: what this node IS.**
//!
//! A node's refusals have been legible for a long time; every gate in this
//! substrate carries a typed reason with a stable token. Its *state* was not.
//! Ten typed signals were computed at read time and discarded, so an operator
//! who did not build the mesh had no way to answer *"is this node healthy,
//! trusted, and doing its job?"* without reading Rust.
//!
//! This module is persist's half: the node-scoped signals, folded once, into
//! one value a consumer can render.
//!
//! # A gauge, not a gate
//!
//! **Nothing here may be gated on.** Every band below is a rendering of an
//! authority that lives somewhere else, and the authority is what a decision
//! must consult:
//! [`trust_root_valid`](super::trust_root::trust_root_valid) decides whether a
//! root serves, [`QuarantineFold::withholds`](super::quarantine::QuarantineFold::withholds)
//! decides whether a key is served, and so on. A [`NodeState`] is a summary
//! taken at an instant, and summaries lose information on purpose. It is
//! reported so a human can look at it.
//!
//! Drill freshness is the sharpest instance and it was decided deliberately
//! (CIRISPersist#550/#551 item 4): the drills ARE the liveness signal, and
//! liveness is a thing to REPORT, not a thing to withhold service over. A root
//! with a red drill band serves normally. See [`DrillFreshness`].
//!
//! # Bands, never floats
//!
//! Every signal renders as a [`StateBand`], the same discipline FSD-005 App C
//! puts on scores. A band is four-valued because three would not be enough:
//! see [`StateBand::Unknown`].
//!
//! # The bands are lossy, and the tokens beside them are not
//!
//! Every signal carries its band AND the underlying typed token — never the
//! band alone. That is the whole of what #356 asks for when it says *distinguish
//! the zeroes*. v26.0.0 shipped
//! [`StewardTierStanding`](super::reverse_quorum::StewardTierStanding) with
//! three separate zeroes (`silent` / `overruled` / `no_duty_holders`) precisely
//! because "nobody answered" and "answered no" are different facts, and a fold
//! that mapped both to one red would have re-introduced the defect that type
//! exists to prevent. So the rule this module follows is: **a band never
//! replaces a token, it only accompanies one.** When two states share a band,
//! their tokens still differ, and a consumer that needs the difference has it
//! without a second call.
//!
//! # Clock-dependence, stated rather than discovered
//!
//! Several of these bands transition **with no state change and no new row** —
//! drill freshness crosses green→yellow→red on elapsed time alone, a consent
//! SLA goes overdue on elapsed time alone, a future-dated revocation or
//! quarantine marker takes effect on elapsed time alone. A consumer diffing two
//! reads will see a transition nothing caused.
//!
//! Rather than leave that to be discovered, every [`NodeState`] names the
//! affected fields in [`NodeState::clock_dependent`] and reports the instant it
//! was taken in [`NodeState::as_of`]. Server is building a gauge, not a ledger,
//! and the surface says so.
//!
//! # What is deliberately NOT here
//!
//! Four of #356's ten signals are not node facts at all — they are answers
//! about a *target*: a peer, an object, an objection. Folding them into a
//! node-level view would require inventing a target, and the invented answer
//! would be indistinguishable from a real one. They are named in
//! [`NodeState::targeted`], each with the binding that answers it, so the
//! omission is legible rather than silent.

use super::replication::admission::PeerQuotaObservation;
use super::trust_root::{DrillFreshness, TrustRootVerdict};
use super::{Error, FederationDirectory};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// CIRISServer#356 — the four-valued band vocabulary for the operator surface.
///
/// Green / Yellow / Red mirror [`DrillFreshness`], which already shipped those
/// three names; the fourth exists because three cannot express the most common
/// failure mode on this plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateBand {
    /// The signal was computed and reads healthy.
    Green,
    /// Computed, and warrants attention but not action.
    Yellow,
    /// Computed, and reads unhealthy.
    Red,
    /// **The node cannot currently compute this signal.**
    ///
    /// Not a fourth severity — a statement about the reader rather than about
    /// the node. It is a distinct token, and never `Green`, because most of the
    /// failure modes on this plane are silent ones: a host that never declared
    /// its own key id, a backend that does not implement a read, a counter that
    /// has never been exercised. Every one of those produces "no bad news",
    /// and "no bad news" rendered green is how an unmonitored node looks
    /// healthy right up until it does not.
    ///
    /// It sorts *worse than yellow and better than red* in
    /// [`NodeState::band`] — a known red is more actionable than an unknown —
    /// but the roll-up is a headline only. [`NodeState::unknown`] names every
    /// unknown signal individually, so an unknown can never hide behind a red.
    Unknown,
}

impl StateBand {
    /// The stable program token — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Green => "green",
            Self::Yellow => "yellow",
            Self::Red => "red",
            Self::Unknown => "unknown",
        }
    }

    /// Every variant, in severity order — the closed set.
    pub const ALL: &'static [Self] = &[Self::Green, Self::Yellow, Self::Unknown, Self::Red];

    /// Severity rank for the roll-up. See [`Self::Unknown`] for why unknown
    /// sits between yellow and red rather than at either end.
    #[must_use]
    const fn rank(self) -> u8 {
        match self {
            Self::Green => 0,
            Self::Yellow => 1,
            Self::Unknown => 2,
            Self::Red => 3,
        }
    }

    /// The worse of two bands.
    #[must_use]
    pub const fn worse(self, other: Self) -> Self {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }

    /// Is this band anything other than [`Green`](Self::Green)? The one
    /// predicate a consumer should use to decide whether to draw attention,
    /// so "needs a look" has exactly one definition.
    #[must_use]
    pub const fn needs_attention(&self) -> bool {
        !matches!(self, Self::Green)
    }
}

impl std::fmt::Display for StateBand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CIRISServer#356 — why this node's trust-root signal reads the way it does.
///
/// **Five arms, and four of them are ways of having no valid root.** They do
/// not share a token, because "the host never told me who I am", "I trust
/// nobody", "I trust somebody who does not check out" and "I could not read"
/// call for four different actions, and a surface that answered *red* to all
/// four would send an operator hunting in the wrong place.
///
/// Closed, snake_case, no catch-all, APPEND-ONLY.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustRootStanding {
    /// A root this node's own edges name checks out in full — live trust edge,
    /// self-declaring charter with a recovery commitment, no halt latched.
    Valid,
    /// **The host never declared this node's own key id.** Nothing was walked,
    /// because there is no "this node" to walk from. Call
    /// `Engine.set_self_key_id(...)` at startup; until then this and every
    /// other self-scoped signal is [`StateBand::Unknown`], which is the honest
    /// answer and not a fault of the mesh.
    NoSelfKey,
    /// The node declared itself and holds **no live `trust:accepts` edge to
    /// any external root**. A real, known state: this node roots to nothing.
    NoTrustEdges,
    /// The node trusts one or more roots and **none of them validates**. The
    /// first candidate's full [`TrustRootVerdict`] rides along on
    /// [`TrustRootSignal::verdict`] so the failing leg is visible without a
    /// second call.
    NoValidRoot,
    /// A backend read failed. Reported rather than guessed — an unreadable
    /// directory is not an untrusted one.
    Unreadable,
}

impl TrustRootStanding {
    /// The stable program token — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::NoSelfKey => "no_self_key",
            Self::NoTrustEdges => "no_trust_edges",
            Self::NoValidRoot => "no_valid_root",
            Self::Unreadable => "unreadable",
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::Valid,
        Self::NoSelfKey,
        Self::NoTrustEdges,
        Self::NoValidRoot,
        Self::Unreadable,
    ];

    /// The band this standing renders as.
    #[must_use]
    const fn band(self) -> StateBand {
        match self {
            Self::Valid => StateBand::Green,
            Self::NoSelfKey | Self::Unreadable => StateBand::Unknown,
            Self::NoTrustEdges | Self::NoValidRoot => StateBand::Red,
        }
    }
}

/// CIRISServer#356 — **`trust_root_valid` and `DrillFreshness` on one verdict**,
/// which is where they belong: the drill is a property OF a root, and reporting
/// a drill band with no root to attach it to would be reporting the shelf life
/// of nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRootSignal {
    /// The roll-up band. Lossy — [`Self::standing`] is the authority.
    pub band: StateBand,
    /// Which of the five states this is. Never collapsed into `band`.
    pub standing: TrustRootStanding,
    /// The root the verdict is about: the first VALID candidate, else the first
    /// candidate walked, else `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_ref: Option<String>,
    /// How many distinct roots this node's own edges named. The anti-inflation
    /// boundary of
    /// [`transit_candidate_roots`](super::trust_root::transit_candidate_roots)
    /// applies: candidates come from THIS node's records, never a peer's.
    pub roots_considered: usize,
    /// The full per-leg verdict for [`Self::root_ref`] — `edge_exists`,
    /// `root_self_declares`, `charter_has_recovery`, `halt_latched`,
    /// `charter_quorum`, `bounded_until`. Present whenever a candidate was
    /// walked, on the failing arm as well as the passing one, so an operator
    /// sees WHICH leg failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verdict: Option<TrustRootVerdict>,
    /// **Clock-dependent.** When [`Self::root_ref`] was last drilled, or `None`
    /// if never (or if nothing was walked).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_drill_at: Option<DateTime<Utc>>,
    /// **Clock-dependent, and a SIGNAL rather than a gate.**
    /// [`DrillFreshness`] verbatim, so its meaning cannot drift from the
    /// verdict's. A red drill does not make a root invalid and never has —
    /// [`TrustRootVerdict::valid`] does not consult it.
    ///
    /// # Token case
    ///
    /// `DrillFreshness` predates this module and serializes **PascalCase**
    /// (`"Green"` / `"Yellow"` / `"Red"`), which is its wire contract and is
    /// not changed here. [`Self::drill_band`] carries the same three states in
    /// this module's snake_case band vocabulary. They cannot disagree — the
    /// band is derived from this field — and a consumer should read
    /// `drill_band`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drill_freshness: Option<DrillFreshness>,
    /// [`Self::drill_freshness`] as a [`StateBand`]. `Unknown` when no
    /// candidate root was walked — an undrilled root reads `Red`, but a node
    /// with no root at all has nothing to be undrilled.
    pub drill_band: StateBand,
}

/// CIRISServer#356 — do this node's OWN past statements still stand, given the
/// revocations it holds?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStatementSignal {
    /// The roll-up band. Lossy — [`Self::standing`] is the authority.
    pub band: StateBand,
    /// [`KeyStatementStanding`](super::register::KeyStatementStanding) verbatim
    /// (`stands` / `suspect_after_bound` / `suspect_unbounded`), or `None` when
    /// the node could not be asked (no declared self key, or an unreadable
    /// backend). `None` is NOT `stands`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub standing: Option<super::register::KeyStatementStanding>,
    /// **Clock-dependent.** The instant asked about — [`NodeState::as_of`],
    /// i.e. *would a statement made right now stand?* For any other instant
    /// call the dedicated read; a node gauge cannot pick one for you.
    pub statement_at: DateTime<Utc>,
    /// `revocation_id`s that cover the statement, sorted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub covered_by: Vec<String>,
    /// Revocations against this key that had taken effect at `as_of`, covering
    /// or not. `covered_by.len() < considered` is the case a bounded revocation
    /// makes expressible.
    pub considered: usize,
}

/// CIRISServer#356 — is this node's own key withheld from serving?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineSignal {
    /// The roll-up band. Lossy — [`Self::state`] is the authority.
    pub band: StateBand,
    /// [`QuarantineState`](super::quarantine::QuarantineState) verbatim, or
    /// `None` when the node could not be asked. `None` is NOT
    /// `not_quarantined`.
    ///
    /// Note that `not_quarantined` and `released` both mean "serving right
    /// now" and are nonetheless **different tokens on different bands** —
    /// green and yellow. "Never withheld" and "withheld and released" are
    /// different facts and an operator reviewing this node deserves the second
    /// one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<super::quarantine::QuarantineState>,
    /// The governing marker's `attestation_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub marker_id: Option<String>,
    /// WHO withheld (or released).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    /// The grounds the author recorded. Never interpreted by persist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grounds: Option<String>,
}

/// CIRISServer#356 — **are we late on a deletion we promised?**
///
/// #356 calls this the sharpest of the ten: persist already knows when the node
/// is failing a consent SLA it committed to, and nothing told anyone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentSlaSignal {
    /// The roll-up band. `green` = nothing overdue; `red` = at least one
    /// promise is late; `unknown` = the read failed, which is NOT "nothing
    /// overdue".
    pub band: StateBand,
    /// **Clock-dependent.** How many subject-side revocations are resting
    /// local-tier past the SLA at [`NodeState::as_of`], or `None` when the read
    /// failed. `Some(0)` and `None` are different facts and do not share a
    /// band.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overdue: Option<usize>,
    /// The SLA window the count was taken against, in seconds.
    pub sla_seconds: u64,
    /// The `attestation_id`s of the overdue rows (the `attestation_promote`
    /// handles that clear the condition), capped at
    /// [`OVERDUE_SAMPLE_CAP`] so one bad day cannot make this value unbounded.
    /// [`Self::overdue`] is the true count.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sample_attestation_ids: Vec<String>,
    /// Always `true`. This fold uses
    /// [`list_consent_revocation_promotion_overdue_readonly`](FederationDirectory::list_consent_revocation_promotion_overdue_readonly)
    /// and therefore writes NOTHING — a dashboard may poll a
    /// [`NodeState`] at any rate without driving `hard_case` writes. The
    /// emitting sibling exists for the watcher tick that is supposed to put the
    /// breach on the record.
    pub read_only: bool,
}

/// How many overdue `attestation_id`s [`ConsentSlaSignal`] carries.
pub const OVERDUE_SAMPLE_CAP: usize = 16;

/// CIRISServer#356 — the #583 tail-squeeze tripwire, **as a band that can say
/// "not tested"**.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerQuotaSignal {
    /// `unknown` when this backend holds no quota, and also when the quota
    /// holds no peers — see [`Self::note`]. `green` when the tripwire has been
    /// exercised and reads clean. `red` when it fired.
    pub band: StateBand,
    /// The raw reading, or `None` when this backend exposes none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<PeerQuotaObservation>,
    /// **The volatility, in the payload and not only in the docs.** A fixed
    /// sentence naming what these numbers are not, so a consumer that renders
    /// the struct without reading the stub still shows it.
    pub note: String,
}

/// The sentence [`PeerQuotaSignal::note`] always carries.
pub const PEER_QUOTA_NOTE: &str =
    "process-local gauge, not node state: resets on restart, differs \
                                   between processes serving one node, and is stored nowhere. \
                                   slot_denials must be 0 by the tracked-peers cap derivation; a \
                                   non-zero reading means that arithmetic no longer holds in this \
                                   build. Not a throttling metric — ordinary quota refusals are \
                                   not counted here.";

/// CIRISServer#356 — one of the signals that is **not a node fact**, named
/// together with the target it needs and the binding that answers it.
///
/// Carried as data rather than left to prose so a consumer composing a node
/// view cannot mistake an omission for a healthy zero, and does not have to
/// re-derive which read to call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetedSignal {
    /// The signal's name.
    pub signal: String,
    /// The target it must be asked about.
    pub requires: String,
    /// The FFI binding that answers it.
    pub binding: String,
}

/// The closed list behind [`NodeState::targeted`], as `(signal, requires,
/// binding)`. A `const` table rather than a `LazyLock<Vec<_>>` so it is
/// reviewable in one place and cannot be mutated at runtime.
pub const TARGETED_SIGNALS: &[(&str, &str, &str)] = &[
    (
        "transit_eligibility",
        "a peer key id",
        "resolve_transit_eligibility_json",
    ),
    (
        "load_bearing",
        "a CEG object (kind + id)",
        "is_load_bearing_json",
    ),
    (
        "reverse_quorum_standing",
        "a cohort and an action attestation id",
        "resolve_reverse_quorum_json",
    ),
    (
        "steward_tier_standing",
        "a cohort and an action attestation id (per-objection)",
        "resolve_reverse_quorum_json",
    ),
];

/// [`TARGETED_SIGNALS`] as the owned rows [`NodeState::targeted`] carries.
#[must_use]
pub fn targeted_signals() -> Vec<TargetedSignal> {
    TARGETED_SIGNALS
        .iter()
        .map(|(signal, requires, binding)| TargetedSignal {
            signal: (*signal).to_owned(),
            requires: (*requires).to_owned(),
            binding: (*binding).to_owned(),
        })
        .collect()
}

/// The fields of [`NodeState`] whose band moves with [`NodeState::as_of`]
/// alone — **no state change, no new row**.
pub const CLOCK_DEPENDENT_FIELDS: &[&str] = &[
    "trust_root.drill_band",
    "trust_root.standing",
    "key_statements.standing",
    "quarantine.state",
    "consent_sla.overdue",
];

/// CIRISServer#356 — **how is this node?**, folded once.
///
/// See the [module doc](self) for the four rules this shape obeys: a gauge
/// never a gate, bands never floats, a band never replaces a token, and unknown
/// is neither green nor absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeState {
    /// The instant every band below was computed against. Each field named in
    /// [`Self::clock_dependent`] is a function of it.
    pub as_of: DateTime<Utc>,
    /// The node's own declared key id
    /// (`Engine.set_self_key_id`), or `None` — in which case every self-scoped
    /// signal reads [`StateBand::Unknown`] and says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_key_id: Option<String>,
    /// The worst band across the signals below. **A headline only** — it is a
    /// deliberate collapse, and [`Self::unknown`] is what keeps the collapse
    /// from hiding anything.
    ///
    /// # A red headline does not mean an invalid root
    ///
    /// [`TrustRootSignal::drill_band`] is folded in, because "last drill
    /// performed 200 days ago" is precisely what #356 asks an operator surface
    /// to show. It remains a SIGNAL: a red drill does not make a root invalid
    /// and [`TrustRootVerdict::valid`] does not consult it. So a node can read
    /// `band: "red"` here and serve perfectly, and a consumer that turned this
    /// headline into a gate would re-create the deadman #551 item 4 removed.
    /// The per-signal bands and tokens are the authority; this is the thing you
    /// colour the tile with.
    pub band: StateBand,
    /// Every signal reading [`StateBand::Unknown`], by field name.
    ///
    /// This list is why the [`Self::band`] roll-up is safe: an unknown ranked
    /// below a red would otherwise vanish behind it, and "we could not compute
    /// three of these" is not something a summary may swallow. Empty means
    /// every signal was computed.
    ///
    /// Entries are signal names (`trust_root`, `key_statements`, `quarantine`,
    /// `consent_sla`, `peer_quota`) plus `trust_root.drill_band`, which is
    /// listed separately because a root can be known-bad while its drill band
    /// is genuinely unknowable — a node with no root at all has nothing to be
    /// undrilled about.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unknown: Vec<String>,
    /// `trust_root_valid` + `DrillFreshness`, on one verdict.
    pub trust_root: TrustRootSignal,
    /// `KeyStatementStanding` for this node's own key at [`Self::as_of`].
    pub key_statements: KeyStatementSignal,
    /// `QuarantineState` for this node's own key at [`Self::as_of`].
    pub quarantine: QuarantineSignal,
    /// The consent-SLA promotion backlog. Computed **read-only**.
    pub consent_sla: ConsentSlaSignal,
    /// The peer-write-quota tripwire. Process-local; see [`PeerQuotaSignal`].
    pub peer_quota: PeerQuotaSignal,
    /// The fields above whose band moves on elapsed time alone —
    /// [`CLOCK_DEPENDENT_FIELDS`]. A consumer diffing two reads will see these
    /// transition with nothing having caused them.
    pub clock_dependent: Vec<String>,
    /// The #356 signals that are NOT node facts, with the binding that answers
    /// each — [`TARGETED_SIGNALS`]. Present so their absence here is legible.
    pub targeted: Vec<TargetedSignal>,
}

/// Options for [`resolve_node_state`]. A struct rather than four positional
/// arguments because three of the four are optional and two are instants.
#[derive(Debug, Clone, Copy)]
pub struct NodeStateOptions<'a> {
    /// This node's own federation key id. `None` renders every self-scoped
    /// signal [`TrustRootStanding::NoSelfKey`] / [`StateBand::Unknown`].
    pub self_key_id: Option<&'a str>,
    /// Pin the trust-root walk to ONE root instead of enumerating this node's
    /// own `trust:accepts` edges. `None` enumerates.
    pub root_key_id: Option<&'a str>,
    /// The read-time instant. Every clock-dependent band is a function of it.
    pub now: DateTime<Utc>,
    /// The consent-promotion SLA window.
    pub sla: std::time::Duration,
}

impl NodeStateOptions<'_> {
    /// Defaults: no pinned root, `Utc::now()`, the 24 h never-rest-local
    /// tripwire.
    #[must_use]
    pub fn new(self_key_id: Option<&str>) -> NodeStateOptions<'_> {
        NodeStateOptions {
            self_key_id,
            root_key_id: None,
            now: Utc::now(),
            sla: std::time::Duration::from_secs(86_400),
        }
    }
}

/// CIRISServer#356 — **the read-time answer.** Persist mutates nothing here,
/// on any arm, including the consent-SLA one (that is the whole reason
/// [`FederationDirectory::list_consent_revocation_promotion_overdue_readonly`]
/// exists).
///
/// Every leg degrades to [`StateBand::Unknown`] independently: an unreadable
/// quarantine plane does not take the trust-root signal down with it, because a
/// partial answer that says which part is missing is worth more than an error.
pub async fn resolve_node_state(
    directory: &dyn FederationDirectory,
    opts: NodeStateOptions<'_>,
) -> Result<NodeState, Error> {
    let now = opts.now;
    let self_key_id = opts.self_key_id.filter(|s| !s.is_empty());

    let trust_root = resolve_trust_root_signal(directory, self_key_id, opts.root_key_id, now).await;
    let key_statements = resolve_key_statement_signal(directory, self_key_id, now).await;
    let quarantine = resolve_quarantine_signal(directory, self_key_id, now).await;
    let consent_sla = resolve_consent_sla_signal(directory, now, opts.sla).await;
    let peer_quota = resolve_peer_quota_signal(directory);

    let mut unknown: Vec<String> = Vec::new();
    let mut band = StateBand::Green;
    for (name, b) in [
        ("trust_root", trust_root.band),
        ("trust_root.drill_band", trust_root.drill_band),
        ("key_statements", key_statements.band),
        ("quarantine", quarantine.band),
        ("consent_sla", consent_sla.band),
        ("peer_quota", peer_quota.band),
    ] {
        band = band.worse(b);
        if b == StateBand::Unknown {
            unknown.push(name.to_owned());
        }
    }

    Ok(NodeState {
        as_of: now,
        self_key_id: self_key_id.map(ToOwned::to_owned),
        band,
        unknown,
        trust_root,
        key_statements,
        quarantine,
        consent_sla,
        peer_quota,
        clock_dependent: CLOCK_DEPENDENT_FIELDS
            .iter()
            .map(|s| (*s).to_owned())
            .collect(),
        targeted: targeted_signals(),
    })
}

/// The trust-root leg. Candidate roots come from THIS node's own live
/// `trust:accepts` edges via
/// [`transit_candidate_roots`](super::trust_root::transit_candidate_roots) —
/// the same enumeration `resolve_transit_eligibility` uses, reused rather than
/// re-derived, so the two cannot disagree about what root this node trusts.
async fn resolve_trust_root_signal(
    directory: &dyn FederationDirectory,
    self_key_id: Option<&str>,
    pinned_root: Option<&str>,
    now: DateTime<Utc>,
) -> TrustRootSignal {
    let Some(user) = self_key_id else {
        return trust_root_signal(TrustRootStanding::NoSelfKey, None, 0, None);
    };

    // Candidates: the pinned root if the caller named one, else the distinct
    // targets of the node's own live accepts-edges.
    let candidates: Vec<String> = match pinned_root {
        Some(r) => vec![r.to_owned()],
        None => match directory.list_attestations_by(user).await {
            Ok(rows) => super::trust_root::transit_candidate_roots(&rows, user, now)
                .into_iter()
                .map(|c| c.root_ref)
                .collect(),
            Err(_) => return trust_root_signal(TrustRootStanding::Unreadable, None, 0, None),
        },
    };
    let considered = candidates.len();
    if considered == 0 {
        return trust_root_signal(TrustRootStanding::NoTrustEdges, None, 0, None);
    }

    let mut first: Option<(String, TrustRootVerdict)> = None;
    for root in candidates {
        match super::trust_root::trust_root_valid(directory, user, &root).await {
            Ok(v) if v.valid => {
                return trust_root_signal(
                    TrustRootStanding::Valid,
                    Some(root),
                    considered,
                    Some(v),
                );
            }
            Ok(v) => {
                if first.is_none() {
                    first = Some((root, v));
                }
            }
            // One unreadable candidate does not condemn the rest; only an
            // all-unreadable walk reports `Unreadable`.
            Err(_) => continue,
        }
    }
    match first {
        Some((root, v)) => trust_root_signal(
            TrustRootStanding::NoValidRoot,
            Some(root),
            considered,
            Some(v),
        ),
        None => trust_root_signal(TrustRootStanding::Unreadable, None, considered, None),
    }
}

/// Assemble a [`TrustRootSignal`], deriving both bands from the standing and
/// the verdict so they cannot be set inconsistently at a call site.
fn trust_root_signal(
    standing: TrustRootStanding,
    root_ref: Option<String>,
    roots_considered: usize,
    verdict: Option<TrustRootVerdict>,
) -> TrustRootSignal {
    let drill_freshness = verdict.as_ref().map(|v| v.drill_freshness);
    let drill_band = match drill_freshness {
        Some(DrillFreshness::Green) => StateBand::Green,
        Some(DrillFreshness::Yellow) => StateBand::Yellow,
        Some(DrillFreshness::Red) => StateBand::Red,
        // No root walked — nothing to be undrilled ABOUT. Not red.
        None => StateBand::Unknown,
    };
    TrustRootSignal {
        band: standing.band(),
        standing,
        root_ref,
        roots_considered,
        last_drill_at: verdict.as_ref().and_then(|v| v.last_drill_at),
        drill_freshness,
        drill_band,
        verdict,
    }
}

/// CIRISServer#356 — **the one place a key-statement standing becomes a band.**
///
/// Extracted for the same reason as [`peer_quota_band`]: a rule stated twice is
/// a rule that drifts, and a unit test over a copy proves nothing about the
/// path that runs.
#[must_use]
pub const fn key_statement_band(standing: super::register::KeyStatementStanding) -> StateBand {
    match standing {
        super::register::KeyStatementStanding::Stands => StateBand::Green,
        // Bounded: this key is de-admitted as of now, but its honest past
        // still stands. A materially better position than an unbounded
        // revocation, and the two must not read alike — that distinction is
        // the whole of what the bound bought.
        super::register::KeyStatementStanding::SuspectAfterBound => StateBand::Yellow,
        super::register::KeyStatementStanding::SuspectUnbounded => StateBand::Red,
    }
}

/// CIRISServer#356 — **the one place a quarantine state becomes a band.**
#[must_use]
pub const fn quarantine_band(state: super::quarantine::QuarantineState) -> StateBand {
    match state {
        super::quarantine::QuarantineState::NotQuarantined => StateBand::Green,
        // Serving, and it was not always. A different fact from never having
        // been withheld, so a different band as well as a different token.
        super::quarantine::QuarantineState::Released => StateBand::Yellow,
        super::quarantine::QuarantineState::Withheld => StateBand::Red,
    }
}

/// The key-statement leg.
async fn resolve_key_statement_signal(
    directory: &dyn FederationDirectory,
    self_key_id: Option<&str>,
    now: DateTime<Utc>,
) -> KeyStatementSignal {
    let empty = |band| KeyStatementSignal {
        band,
        standing: None,
        statement_at: now,
        covered_by: Vec::new(),
        considered: 0,
    };
    let Some(key) = self_key_id else {
        return empty(StateBand::Unknown);
    };
    match super::register::resolve_key_statement_standing(directory, key, now, now).await {
        Ok(fold) => KeyStatementSignal {
            band: key_statement_band(fold.standing),
            standing: Some(fold.standing),
            statement_at: fold.statement_at,
            covered_by: fold.covered_by,
            considered: fold.considered,
        },
        Err(_) => empty(StateBand::Unknown),
    }
}

/// The quarantine leg.
async fn resolve_quarantine_signal(
    directory: &dyn FederationDirectory,
    self_key_id: Option<&str>,
    now: DateTime<Utc>,
) -> QuarantineSignal {
    let unknown = QuarantineSignal {
        band: StateBand::Unknown,
        state: None,
        marker_id: None,
        decided_by: None,
        grounds: None,
    };
    let Some(key) = self_key_id else {
        return unknown;
    };
    match super::quarantine::resolve_quarantine(directory, key, now).await {
        Ok(fold) => QuarantineSignal {
            band: quarantine_band(fold.state),
            state: Some(fold.state),
            marker_id: fold.marker_id,
            decided_by: fold.decided_by,
            grounds: fold.grounds,
        },
        Err(_) => unknown,
    }
}

/// The consent-SLA leg — **read-only**, by construction.
async fn resolve_consent_sla_signal(
    directory: &dyn FederationDirectory,
    now: DateTime<Utc>,
    sla: std::time::Duration,
) -> ConsentSlaSignal {
    let sla_seconds = sla.as_secs();
    match directory
        .list_consent_revocation_promotion_overdue_readonly(now, sla)
        .await
    {
        Ok(rows) => ConsentSlaSignal {
            band: if rows.is_empty() {
                StateBand::Green
            } else {
                StateBand::Red
            },
            overdue: Some(rows.len()),
            sla_seconds,
            sample_attestation_ids: rows
                .iter()
                .take(OVERDUE_SAMPLE_CAP)
                .map(|r| r.attestation_id.clone())
                .collect(),
            read_only: true,
        },
        Err(_) => ConsentSlaSignal {
            band: StateBand::Unknown,
            overdue: None,
            sla_seconds,
            sample_attestation_ids: Vec::new(),
            read_only: true,
        },
    }
}

/// CIRISServer#356 — **the one place the peer-quota reading becomes a band.**
///
/// Its own function so the rule is testable without a backend and cannot be
/// stated twice: a unit test that re-implemented this match would go on passing
/// after the real path changed, which is the shape of a test that proves
/// nothing.
#[must_use]
pub const fn peer_quota_band(observation: Option<PeerQuotaObservation>) -> StateBand {
    match observation {
        // The derivation no longer holds in this build. See
        // `PER_PEER_QUOTA_TRACKED_PEERS_CAP`.
        Some(o) if o.slot_denials > 0 => StateBand::Red,
        // Clean AND exercised: at least one peer write has been charged
        // against this quota, so the zero means something.
        Some(o) if o.tracked_peers > 0 => StateBand::Green,
        // Clean and NOT exercised (a fresh process), or no quota at all.
        // Both are "I have not tested this", which is not "it passed".
        _ => StateBand::Unknown,
    }
}

/// The peer-quota leg. Synchronous — the quota is a mutex, not a table.
fn resolve_peer_quota_signal(directory: &dyn FederationDirectory) -> PeerQuotaSignal {
    let observation = directory.peer_quota_observation();
    PeerQuotaSignal {
        band: peer_quota_band(observation),
        observation,
        note: PEER_QUOTA_NOTE.to_owned(),
    }
}

/// CIRISServer#356 — the shared assertion bodies for the operator surface,
/// run **identically against every backend**.
///
/// The bodies live here, once, and each backend's test module calls them.
/// #541 is the standing reminder of what happens when two backends' paths
/// drift: memory tolerates what postgres refuses, so a fold proven only on
/// memory is a fold proven nowhere. A divergence here is a compile-or-fail,
/// never a silent asymmetry.
#[cfg(test)]
pub mod parity_test_support {
    use super::*;
    use crate::federation::hard_case::HardCaseFilter;
    use crate::federation::tier_ingest::test_support::{hybrid_pubkeys, sign_envelope};
    use crate::federation::types::{
        attestation_type, cohort_scope, identity_type, KeyRecord, LocalAttestationInput,
        SignedKeyRecord,
    };

    /// A registerable key with REAL deterministic hybrid pubkeys, so the
    /// consent fixture's local-tier admission resolves the attester.
    fn key(key_id: &str) -> KeyRecord {
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: identity_type::PRIMITIVE.into(),
            identity_ref: key_id.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": key_id }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    async fn hard_case_count(dir: &dyn FederationDirectory) -> usize {
        dir.list_hard_case_events(HardCaseFilter::default())
            .await
            .expect("hard_case read")
            .len()
    }

    /// **The #356 unknown rule, on a live backend.** A host that never declared
    /// its own key id gets `unknown` on every self-scoped signal — never green,
    /// never absent — and the four ways of having no valid trust root do not
    /// share a token.
    pub async fn assert_unknown_without_self_key(dir: &dyn FederationDirectory, tag: &str) {
        // Through the convenience constructor, so its defaults are covered by
        // the same body that pins the unknown rule rather than only claimed.
        let opts = NodeStateOptions::new(None);
        assert_eq!(opts.sla.as_secs(), 86_400, "({tag}) the 24 h SLA default");
        assert!(opts.root_key_id.is_none(), "({tag})");
        let s = resolve_node_state(dir, opts).await.expect("fold");

        assert_eq!(
            s.trust_root.standing,
            TrustRootStanding::NoSelfKey,
            "({tag}) no declared self key is `no_self_key`, NOT `no_trust_edges` \
             — 'I was never told who I am' is not 'I root to nothing'"
        );
        assert_eq!(s.trust_root.band, StateBand::Unknown, "({tag})");
        assert_eq!(
            s.trust_root.drill_band,
            StateBand::Unknown,
            "({tag}) no root walked means nothing to be undrilled ABOUT — not Red"
        );
        assert!(s.trust_root.drill_freshness.is_none(), "({tag})");
        assert_eq!(s.key_statements.band, StateBand::Unknown, "({tag})");
        assert!(
            s.key_statements.standing.is_none(),
            "({tag}) an uncomputable standing is ABSENT, never `stands`"
        );
        assert_eq!(s.quarantine.band, StateBand::Unknown, "({tag})");
        assert!(
            s.quarantine.state.is_none(),
            "({tag}) an uncomputable state is ABSENT, never `not_quarantined`"
        );
        assert_eq!(
            s.band,
            StateBand::Unknown,
            "({tag}) the headline must not read green when four signals are unknown"
        );
        for expected in [
            "trust_root",
            "trust_root.drill_band",
            "key_statements",
            "quarantine",
            "peer_quota",
        ] {
            assert!(
                s.unknown.iter().any(|u| u == expected),
                "({tag}) unknown[] must name {expected}; got {:?}",
                s.unknown
            );
        }
        assert!(!s.clock_dependent.is_empty(), "({tag})");
        assert_eq!(s.targeted.len(), TARGETED_SIGNALS.len(), "({tag})");
        assert!(s.consent_sla.read_only, "({tag})");
        // The peer-quota zero on a fresh engine is UNTESTED, not clean.
        assert_eq!(
            s.peer_quota.band,
            StateBand::Unknown,
            "({tag}) slot_denials==0 with tracked_peers==0 is not health"
        );
        assert!(
            s.peer_quota
                .observation
                .is_some_and(|o| o.process_local && o.slot_denials == 0),
            "({tag}) every backend that charges peer writes reports the gauge"
        );
    }

    /// **The zeroes, distinguished.** A declared self key with no trust edges
    /// is a RED with its own token — materially different from the UNKNOWN
    /// above, and the two must not be reachable from one another by accident.
    pub async fn assert_declared_but_rootless(dir: &dyn FederationDirectory, tag: &str) {
        let me = format!("{tag}-ns-self");
        dir.put_public_key(SignedKeyRecord { record: key(&me) })
            .await
            .expect("register self key");
        let opts = NodeStateOptions {
            self_key_id: Some(&me),
            root_key_id: None,
            now: Utc::now(),
            sla: std::time::Duration::from_secs(86_400),
        };
        let s = resolve_node_state(dir, opts).await.expect("fold");

        assert_eq!(
            s.trust_root.standing,
            TrustRootStanding::NoTrustEdges,
            "({tag})"
        );
        assert_eq!(
            s.trust_root.band,
            StateBand::Red,
            "({tag}) a node that roots to nothing is a KNOWN bad, not an unknown"
        );
        assert_eq!(s.trust_root.roots_considered, 0, "({tag})");
        assert_eq!(
            s.key_statements.standing,
            Some(crate::federation::register::KeyStatementStanding::Stands),
            "({tag})"
        );
        assert_eq!(s.key_statements.band, StateBand::Green, "({tag})");
        assert_eq!(
            s.quarantine.state,
            Some(crate::federation::quarantine::QuarantineState::NotQuarantined),
            "({tag})"
        );
        assert_eq!(s.quarantine.band, StateBand::Green, "({tag})");
        assert!(
            !s.unknown
                .iter()
                .any(|u| u == "key_statements" || u == "quarantine"),
            "({tag}) a computable signal must leave unknown[]; got {:?}",
            s.unknown
        );
        assert_eq!(s.self_key_id.as_deref(), Some(me.as_str()), "({tag})");
        // Serialization: the two rootless states are distinguishable on the wire.
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"no_trust_edges\""), "({tag}) {json}");
        assert!(!json.contains("\"no_self_key\""), "({tag})");
    }

    /// **The no-write proof.** The read-only overdue query answers the same
    /// question as its emitting sibling and leaves the `hard_case` row count at
    /// ZERO across N calls — then one call to the emitting sibling raises it,
    /// and a second call does not.
    ///
    /// Asserting only "the count is unchanged across N calls" would pass for
    /// BOTH methods, because the emitting one is idempotent. The zero is what
    /// separates them.
    pub async fn assert_overdue_readonly_writes_nothing(dir: &dyn FederationDirectory, tag: &str) {
        let subject = format!("{tag}-ns-subj");
        let target = format!("{tag}-ns-tgt");
        for k in [&subject, &target] {
            dir.put_public_key(SignedKeyRecord { record: key(k) })
                .await
                .expect("register");
        }
        // v30.13.0 (CIRISPersist#598) — the signed instant; the local write
        // door stamps the `asserted_at` column FROM it.
        let env = serde_json::json!({
            "id": format!("{tag}-ns-rev"),
            "dimension": "consent:state:revoked:v1",
            "score": 1.0,
            "confidence": 0.9,
            crate::federation::envelope::paths::ASSERTED_AT:
                crate::federation::admission::truncate_to_substrate_resolution(chrono::Utc::now())
                    .to_rfc3339(),
        });
        let (_h, sig_classical, sig_pqc) = sign_envelope(&subject, &env);
        dir.attestation_upsert_local(LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: subject.clone(),
            attested_key_id: Some(target.clone()),
            attestation_type: attestation_type::SCORES.into(),
            weight: None,
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(env)
                .unwrap(),
            subject_key_ids: vec![subject.clone()],
            cohort_scope: cohort_scope::SELF.to_string(),
            scrub_signature_classical: Some(sig_classical),
            scrub_signature_pqc: sig_pqc,
        })
        .await
        .expect("transit local-tier revocation admits");

        let revoked_at = dir
            .list_consent_revocations(None)
            .await
            .expect("revocations")
            .iter()
            .find(|r| r.attesting_key_id == subject)
            .expect("our revocation")
            .asserted_at;
        let sla = std::time::Duration::from_secs(86_400);
        let past_sla = revoked_at + chrono::Duration::seconds(86_401);

        let baseline = hard_case_count(dir).await;

        // N calls to the READ-ONLY reader: the same answer every time, and not
        // one row written.
        for i in 0..5 {
            let rows = dir
                .list_consent_revocation_promotion_overdue_readonly(past_sla, sla)
                .await
                .expect("readonly reader");
            assert!(
                rows.iter().any(|r| r.subject_key_id == subject),
                "({tag}) call {i}: the read-only reader must answer the same \
                 question as its emitting sibling"
            );
            assert_eq!(
                hard_case_count(dir).await,
                baseline,
                "({tag}) call {i}: the read-only reader wrote to the audit plane"
            );
        }

        // ...and the AGGREGATE, which routes through it. A dashboard refresh
        // must not be an attestation.
        for i in 0..5 {
            let s = resolve_node_state(
                dir,
                NodeStateOptions {
                    self_key_id: None,
                    root_key_id: None,
                    now: past_sla,
                    sla,
                },
            )
            .await
            .expect("fold");
            assert_eq!(s.consent_sla.band, StateBand::Red, "({tag}) refresh {i}");
            assert!(s.consent_sla.overdue.is_some_and(|n| n >= 1), "({tag})");
            assert!(s.consent_sla.read_only, "({tag})");
            assert_eq!(
                hard_case_count(dir).await,
                baseline,
                "({tag}) refresh {i}: node_state_json wrote to the audit plane"
            );
        }

        // The emitting sibling DOES write — one row, then idempotently none.
        // This is what makes "unchanged across N calls" too weak a test on its
        // own: it holds for both methods, and only one of them is read-only.
        let emitted = dir
            .list_consent_revocation_promotion_overdue(past_sla, sla)
            .await
            .expect("emitting reader");
        assert!(!emitted.is_empty(), "({tag})");
        let after_one = hard_case_count(dir).await;
        assert!(
            after_one > baseline,
            "({tag}) the emitting sibling is the one that records; if this ever \
             stops writing, the read-only twin has stopped being a distinction"
        );
        dir.list_consent_revocation_promotion_overdue(past_sla, sla)
            .await
            .expect("emitting reader again");
        assert_eq!(
            hard_case_count(dir).await,
            after_one,
            "({tag}) the emitting sibling stays idempotent — no duplicate rows"
        );

        // Both readers agree, byte-for-byte, on the same (now, sla).
        let ro = dir
            .list_consent_revocation_promotion_overdue_readonly(past_sla, sla)
            .await
            .expect("readonly");
        assert_eq!(
            serde_json::to_string(&ro).unwrap(),
            serde_json::to_string(&emitted).unwrap(),
            "({tag}) one predicate, one answer — the twins must not drift"
        );
    }

    /// The composition the `resolve_reverse_quorum_json` binding performs —
    /// `get_attestation(id)` then fold — proven to reach a FOLD on a real
    /// stored row, not only the two refusal arms the wheel-level test pins.
    ///
    /// `not_governed` is the correct answer here: the cohort declares no
    /// `reverse_quorum:*` protocol, so this plane does not apply to it. What
    /// matters is that it is a fold with a token, arrived at through the same
    /// two steps the FFI takes.
    pub async fn assert_reverse_quorum_folds_a_stored_action(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        let rows = dir
            .list_consent_revocations(None)
            .await
            .expect("revocations");
        let Some(action_id) = rows
            .iter()
            .find(|r| r.attesting_key_id == format!("{tag}-ns-subj"))
            .map(|r| r.attestation_id.clone())
        else {
            panic!("({tag}) the overdue fixture must have left a row to fold over");
        };
        let action = dir
            .get_attestation(&action_id)
            .await
            .expect("get_attestation")
            .expect("the row this node just wrote");
        let fold = crate::federation::reverse_quorum::resolve_reverse_quorum(
            dir,
            crate::federation::cohort::Cohort::Community,
            &format!("{tag}-ns-cohort"),
            &action,
            Utc::now(),
        )
        .await
        .expect("fold");
        assert_eq!(
            fold.standing,
            crate::federation::reverse_quorum::ReverseQuorumStanding::NotGoverned,
            "({tag}) a cohort declaring no reverse-quorum protocol is NOT_GOVERNED \
             — a distinct token from 'stood', not a silent empty answer"
        );
        // The steward tier's three zeroes ride on `escalation[]`, and an
        // ungoverned action has none — the arm that must not be confused with
        // `silent`.
        assert!(fold.escalation.is_empty(), "({tag})");
        let json = serde_json::to_string(&fold).unwrap();
        assert!(json.contains("\"not_governed\""), "({tag}) {json}");
    }

    /// Run every #356 body against one backend, in order.
    pub async fn assert_node_state_surface(dir: &dyn FederationDirectory, tag: &str) {
        assert_unknown_without_self_key(dir, tag).await;
        assert_declared_but_rootless(dir, tag).await;
        assert_overdue_readonly_writes_nothing(dir, tag).await;
        assert_reverse_quorum_folds_a_stored_action(dir, tag).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn band_tokens_are_stable_and_closed() {
        assert_eq!(StateBand::Green.as_str(), "green");
        assert_eq!(StateBand::Yellow.as_str(), "yellow");
        assert_eq!(StateBand::Red.as_str(), "red");
        assert_eq!(StateBand::Unknown.as_str(), "unknown");
        assert_eq!(StateBand::ALL.len(), 4);
        for b in StateBand::ALL {
            assert_eq!(
                serde_json::to_string(b).unwrap(),
                format!("\"{}\"", b.as_str())
            );
        }
    }

    #[test]
    fn unknown_never_reads_as_healthy() {
        // The #356 rule, as an assertion rather than a doc claim.
        assert_ne!(StateBand::Unknown, StateBand::Green);
        assert!(StateBand::Unknown.needs_attention());
        assert_eq!(
            StateBand::Green.worse(StateBand::Unknown),
            StateBand::Unknown
        );
        assert_eq!(
            StateBand::Yellow.worse(StateBand::Unknown),
            StateBand::Unknown
        );
        // ...and a known red still outranks it for the headline, which is why
        // `NodeState::unknown` enumerates unknowns separately.
        assert_eq!(StateBand::Unknown.worse(StateBand::Red), StateBand::Red);
    }

    #[test]
    fn trust_root_zeroes_do_not_share_a_token() {
        let tokens: std::collections::HashSet<&str> =
            TrustRootStanding::ALL.iter().map(|s| s.as_str()).collect();
        assert_eq!(tokens.len(), TrustRootStanding::ALL.len());
        // The four ways of having no valid root are four tokens, and two of
        // them are UNKNOWN rather than RED — "I was never told who I am" is
        // not "I root to nothing".
        assert_eq!(TrustRootStanding::NoSelfKey.band(), StateBand::Unknown);
        assert_eq!(TrustRootStanding::Unreadable.band(), StateBand::Unknown);
        assert_eq!(TrustRootStanding::NoTrustEdges.band(), StateBand::Red);
        assert_eq!(TrustRootStanding::NoValidRoot.band(), StateBand::Red);
        assert_eq!(TrustRootStanding::Valid.band(), StateBand::Green);
    }

    #[test]
    fn peer_quota_zero_is_unknown_until_the_tripwire_is_exercised() {
        // The distinction slot_denials alone cannot make.
        let fresh = PeerQuotaObservation {
            process_local: true,
            tracked_peers: 0,
            slot_denials: 0,
        };
        let exercised = PeerQuotaObservation {
            process_local: true,
            tracked_peers: 3,
            slot_denials: 0,
        };
        let fired = PeerQuotaObservation {
            process_local: true,
            tracked_peers: 3,
            slot_denials: 1,
        };
        // The REAL predicate the fold runs — not a copy of it.
        assert_eq!(peer_quota_band(Some(fresh)), StateBand::Unknown);
        assert_eq!(peer_quota_band(Some(exercised)), StateBand::Green);
        assert_eq!(peer_quota_band(Some(fired)), StateBand::Red);
        assert_eq!(
            peer_quota_band(None),
            StateBand::Unknown,
            "a backend with no quota reports unknown, never green"
        );
        // Both zeroes serialize, and they are distinguishable.
        assert_ne!(
            serde_json::to_string(&fresh).unwrap(),
            serde_json::to_string(&exercised).unwrap()
        );
    }

    #[test]
    fn a_band_never_collapses_two_different_facts() {
        use crate::federation::quarantine::QuarantineState;
        use crate::federation::register::KeyStatementStanding;

        // "Never withheld" and "withheld and released" both mean SERVING right
        // now. They are different facts, so they get different bands as well as
        // different tokens — collapsing them is the #356 defect exactly.
        assert_eq!(
            quarantine_band(QuarantineState::NotQuarantined),
            StateBand::Green
        );
        assert_eq!(
            quarantine_band(QuarantineState::Released),
            StateBand::Yellow
        );
        assert_eq!(quarantine_band(QuarantineState::Withheld), StateBand::Red);
        assert_ne!(
            quarantine_band(QuarantineState::NotQuarantined),
            quarantine_band(QuarantineState::Released),
        );

        // A bounded revocation and an unbounded one are likewise not the same
        // fact: the bound is precisely what stops a Tuesday compromise costing
        // every honest signature the key ever made.
        assert_eq!(
            key_statement_band(KeyStatementStanding::Stands),
            StateBand::Green
        );
        assert_eq!(
            key_statement_band(KeyStatementStanding::SuspectAfterBound),
            StateBand::Yellow
        );
        assert_eq!(
            key_statement_band(KeyStatementStanding::SuspectUnbounded),
            StateBand::Red
        );
        assert_ne!(
            key_statement_band(KeyStatementStanding::SuspectAfterBound),
            key_statement_band(KeyStatementStanding::SuspectUnbounded),
        );

        // Every mapping above lands inside the closed band set.
        for b in [
            quarantine_band(QuarantineState::Released),
            key_statement_band(KeyStatementStanding::SuspectAfterBound),
            peer_quota_band(None),
        ] {
            assert!(StateBand::ALL.contains(&b));
        }
    }

    #[test]
    fn targeted_signals_name_a_real_binding() {
        assert!(!TARGETED_SIGNALS.is_empty());
        for t in targeted_signals() {
            assert!(t.binding.ends_with("_json"), "{}", t.binding);
            assert!(!t.requires.is_empty());
            assert!(!t.signal.is_empty());
        }
        assert!(!CLOCK_DEPENDENT_FIELDS.is_empty());
    }
}
