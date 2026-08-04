//! v28.3.0 (CIRISPersist#570 **ask 1**) — **the `mesh_config:{key}` plane.**
//!
//! A trust root turns a knob on the nodes that subscribe to it, and the
//! Constitution bounds what a knob can do. From CIRISServer's
//! `FSD/MESH_CONFIG_AND_ADMIN_OPS.md`: twenty copies to ten while a mesh is
//! congested, anti-entropy rounds stretched, a feature quiesced — the graded
//! response set's *relief* tier, as opposed to the halt.
//!
//! Ask 1 was filed with asks 2–5 and was the only one **not** built in v25.1.0.
//! It was held deliberately, on the issue's own strongest argument: *"shipping
//! the plane before the authority is named means the authority gets retrofitted
//! from whatever the code did."* CIRISConstitution#57 ratified the authority,
//! so this module is written against text rather than against itself.
//!
//! # What CC 4.2.1 actually says, and where it contradicts the issue
//!
//! The issue asked for rows *"authored by an accord holder or quorum"*. **CC
//! says the opposite, in terms**, and CC wins:
//!
//! > *"This enumeration's silence confers no authority; the mesh-config author
//! > is **the trust root, acting on the CC 3.2 delegation plane**
//! > (`trust:confers:v1`), **never the accord's ceremony plane** — this scope
//! > isolation stands verbatim, and the trust edge is the subscription,
//! > inheriting the T3 one-row un-trust lever."*
//!
//! That is not a detail. Widening `HUMANITY_ACCORD` signature scope past
//! `EmergencyShutdown` was the thing #57 was opened to avoid, and the halt's
//! isolation is what makes the halt trustworthy. So **no accord-holder check
//! appears anywhere in this module**, and [`MeshConfigRefusalReason`] has no
//! variant for one. Authority is a trust-root question, re-derived from this
//! node's own stored edges ([`trust_root`](super::trust_root)).
//!
//! Four rules bind, all four from CC 4.2.1:
//!
//! 1. **relieve-never-expand** — a `mesh_config` action MAY relieve or restrict
//!    and MUST NOT expand what flows; no key may cause a node to share more
//!    than its owner consented to.
//! 2. **most-restrictive-across-roots** — *forced, not preferred*. Restrictions
//!    compose safely under plural authority; grants do not.
//! 3. **Closed key registry** — a key naming no consumer processor MUST be
//!    refused at admission.
//! 4. **Emergency relief is TTL-bounded** — TTL ≤ 72 h, not renewable
//!    back-to-back by the same holder; durable settings need the root's own
//!    quorum ratifying the emergency's `payload_sha256`.
//!
//! # One axis carries both of the load-bearing rules
//!
//! Rules 1 and 2 look like two rules and are one question asked twice: **does
//! this value mean MORE flows, or less?** [`FlowPolarity`] answers it per key,
//! and every comparison in this module goes through
//! [`MeshConfigKey::more_restrictive_of`] and
//! [`MeshConfigKey::expands_beyond`], which are the same predicate read in two
//! directions. Writing "take the min" would have been correct for five of the
//! nine keys and silently inverted for four — `antientropy.round_secs` LARGER
//! is less traffic, `backpressure.summary_only` TRUE is less traffic. A fold
//! that minimises is not most-restrictive; it is most-restrictive on the keys
//! where the two coincide, which is the kind of bug that ships.
//!
//! # A MARKER, not a command (the #570 design wall, inherited)
//!
//! A mesh-config row is a `scores` attestation, exactly like #574's objection
//! and #570 ask 5's quarantine marker. Nothing is changed by its arrival;
//! `put_attestation` stores one row and touches nothing else. The effect is
//! entirely a read-time fold ([`fold_mesh_config`]) that a reader may honour.
//! Usenet shipped `cancel` and got the cancel wars; every durable system
//! re-derives NoCeM.
//!
//! # Why the fold clamps as well as the door refusing
//!
//! [`record_mesh_config_row`] refuses an expanding value at the door
//! ([`MeshConfigRefusalReason::ExpandsBeyondConsent`]) — and
//! [`fold_mesh_config`] clamps it anyway, unconditionally, at read time. That
//! is not belt-and-braces for its own sake:
//!
//! - the door is reachable only for rows that come through it. A row that
//!   arrives on the **replication plane** never sees it;
//! - and CC's guarantee is about what a NODE does, not about what a node
//!   accepted. A row already on disk from before a baseline changed, or one
//!   admitted by a node running an older cut, must still not expand this
//!   node's behaviour.
//!
//! So the fold is the load-bearing enforcement and the door is the loud one.
//! The property [`fold_mesh_config`] guarantees is total: **for every key, over
//! any row set from any roots, `effective` never means more flow than
//! `baseline`.** That is what makes trust-edge-as-subscription safe — the worst
//! a hostile root does to a subscriber through this plane is slow it down.
//!
//! # Evidence, not verdict
//!
//! [`MeshConfigSetting::per_root`] carries **every** root's own answer, not
//! only the winner, so the disagreeing-roots case is auditable rather than
//! merely resolved; [`MeshConfigSetting::clamped_roots`] names every root whose
//! value was refused for expanding. Persist never says a root was wrong. It
//! says *these roots asked for these values, this one bound, and here are the
//! rows.*
//!
//! # What persist does NOT claim here
//!
//! **Persist consumes none of these keys itself.** The registry names each
//! key's consumer processor ([`MeshConfigKey::consumer`]) and every one of them
//! is a downstream loop — the anti-entropy scheduler, the repair planner, the
//! offer filter — living in CIRISServer or CIRISEdge, reached through
//! [`Engine::resolve_mesh_config`](crate::Engine::resolve_mesh_config) and its
//! `_json` FFI twin. Persist owns the plane, the registry, the authority
//! derivation and the fold; it does not own the loops.
//!
//! That is stated rather than implied because #333's lesson cuts both ways: a
//! conferral nothing gates on is decoration, and so is a claim that a substrate
//! "supports" a knob it never reads. What persist can honestly guarantee is
//! that the fold is correct and reachable, and
//! [`tests::every_registered_key_is_reachable_through_the_public_fold`] holds
//! that.

use chrono::{DateTime, Duration, Utc};

use super::types::Attestation;
use super::{Error, FederationDirectory};

// ─────────────────────────────────────────────────────────────────────────
//  The family + the wire
// ─────────────────────────────────────────────────────────────────────────

/// The CC 3.1 namespace family this plane lives on. **Registered** — CC
/// 1.0-rc3 catalogues `mesh_config:{key}` at CC 3.1.9.2 (owning component
/// `node`), landed by CIRISConstitution#57 and carried in by the v28.3.0
/// re-vendor. It is on the CC 3.1.7 R2(a) mint gate
/// ([`MINTED_NAMESPACE_FAMILIES`](super::admission::MINTED_NAMESPACE_FAMILIES)).
///
/// **The row registers the family, NOT the emitter rule** — the same shape
/// `quarantine::NAMESPACE_FAMILY` documents on its own row. CC's row says
/// *"trust-root-emitted on the delegation plane"* in `description` prose, and
/// its machine-readable `reserved_rule` is **absent** with `reserved: false`,
/// so [`authority_for`](super::namespace::registry::authority_for)`("mesh_config:…")`
/// returns `ProducerSteward` / `reserved: None`.
///
/// **This module therefore does not consult `authority_for` at all**, and that
/// is deliberate rather than an oversight: the authority it would report is
/// weaker than the one CC 4.2.1 states in text, and reading prose as a
/// registered rule is how two validators come to share a predicate that exists
/// in neither of their sources. [`root_authorizes_author`] re-derives authority
/// from this node's own trust-edge and conferral rows instead. The
/// field/prose divergence is pinned by
/// [`tests::the_mesh_config_row_states_its_rule_in_prose_only`]; the generator
/// ask (CC 3.1.9.2's table carries neither a `Reserved?` column nor CC-3.4
/// cross-references, so `build_cc_namespace.py` cannot emit a rule for ANY row
/// in that section) rides CIRISConstitution#67.
pub const NAMESPACE_FAMILY: &str = "mesh_config:{key}";

/// The dimension stem every row on this plane carries:
/// `mesh_config:{key}:v1`. Matched by
/// [`MESH_CONFIG_DIMENSION_PREFIX`](super::admission::MESH_CONFIG_DIMENSION_PREFIX).
pub const DIMENSION_PREFIX: &str = "mesh_config:";

/// The version suffix persist's house style puts on a minted dimension
/// (`consent:replication:v1`, `objection:raised:v1`, `quarantine:withheld:v1`).
pub const DIMENSION_SUFFIX: &str = ":v1";

/// **CC 4.2.1 rule 3** — the maximum life of an emergency relief row. *"TTL ≤
/// 72 h, not renewable back-to-back by the same holder."*
///
/// The asymmetry with the halt is deliberate and CC states it: *"relief expires
/// because it is unilateral; the halt carries no TTL because its exit is the
/// named resumption."* A single holder may buy the mesh three days; making that
/// permanent takes the root's own quorum.
pub const EMERGENCY_MAX_TTL_HOURS: i64 = 72;

/// Envelope field names, shared by the producer side and persist's fold so the
/// two cannot disagree about where a value lives.
pub mod field {
    /// The registered key this row sets, spelled as
    /// [`MeshConfigKey::wire_name`] spells it (`"antientropy.round_secs"`).
    pub const KEY: &str = "mesh_config_key";
    /// The value, as a JSON integer. **Integers only** — the band-not-float
    /// discipline every other number in this substrate follows (FSD-005 App C).
    /// A ratio key carries centi-units; see
    /// [`MeshConfigKey::unit`](super::MeshConfigKey::unit).
    pub const VALUE: &str = "value";
    /// The trust root this row is issued UNDER — a `federation_keys.key_id` or
    /// a constitutional family id. Also the row's `attested_key_id`, so one
    /// existing read
    /// ([`list_attestations_for`](crate::federation::FederationDirectory::list_attestations_for))
    /// finds every row a root has issued.
    pub const ROOT_REF: &str = "root_ref";
    /// `"emergency"` or `"durable"` — see
    /// [`MeshConfigForm`](super::MeshConfigForm).
    pub const FORM: &str = "form";
    /// RFC 3339. The TTL. **Mandatory on the emergency form**; a row whose
    /// `valid_until` has passed is dropped by the fold at READ time, so an
    /// expired relief needs no revocation and no reachable author.
    ///
    /// The same field name the capacity-binding plane uses
    /// ([`capacity::binding_field::VALID_UNTIL`](crate::federation::capacity::binding_field::VALID_UNTIL))
    /// — one spelling of "this row stops counting then" across the crate.
    pub const VALID_UNTIL: &str = crate::federation::capacity::binding_field::VALID_UNTIL;
    /// The `delegates_to` attestation id the author acted UNDER. Required at
    /// admission, per #570 ask 3's rule applied to this plane: an act that does
    /// not carry its own authority is indistinguishable from an unauthorized
    /// one once the actor is gone.
    pub const DELEGATION_ID: &str = "delegation_id";
    /// On a [`Durable`](super::MeshConfigForm::Durable) row: the
    /// `attestation_id` of the emergency row this makes permanent. CC 4.2.1
    /// rule 3 — *"durable settings require the root's own quorum ratifying the
    /// emergency's `payload_sha256`."*
    pub const RATIFIES: &str = "ratifies_row_id";
    /// Free text: WHY. Recorded, never interpreted.
    pub const GROUNDS: &str = "grounds";
}

// ─────────────────────────────────────────────────────────────────────────
//  The axis both ratified rules are computed on
// ─────────────────────────────────────────────────────────────────────────

/// **Which direction of a key's value means MORE flows.** The single axis
/// [`relieve-never-expand`](MeshConfigKey::expands_beyond) and
/// [`most-restrictive-across-roots`](MeshConfigKey::more_restrictive_of) are
/// both computed on.
///
/// "What flows" is CC 4.2.1's own phrasing — *"MUST NOT expand what flows"*,
/// *"no key may cause a node to share more than its owner consented to"*. It
/// unifies the clause's two permitted directions: *relieving* a constraint (do
/// less work) and *restricting* (share less) both reduce flow, and only
/// expansion is forbidden. So there is one order per key, not two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowPolarity {
    /// A LARGER value means more flows. `redundancy.k_repair_target` (more
    /// copies pushed), `antientropy.page_limit` (bigger pages),
    /// `admission.rate_per_key` (more rows admitted).
    HigherMeansMoreFlow,
    /// A SMALLER value means more flows. `antientropy.round_secs` (rounds more
    /// often), `backpressure.summary_only` (0 = full rows, not summaries),
    /// `descent.pressure_multiplier` (less descent pressure).
    ///
    /// **Four of the nine keys are on this arm**, which is why the fold cannot
    /// be a `min()`.
    LowerMeansMoreFlow,
}

impl FlowPolarity {
    /// The stable program token — identical to the serde token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HigherMeansMoreFlow => "higher_means_more_flow",
            Self::LowerMeansMoreFlow => "lower_means_more_flow",
        }
    }
}

/// The unit a key's integer value is expressed in. Carried so a consumer
/// rendering the value, and a producer composing one, cannot disagree about
/// scale — the `descent.pressure_multiplier` centi-unit is exactly the kind of
/// fact that lives in a comment and then does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshConfigUnit {
    /// A plain count (copies, rows, symbols).
    Count,
    /// Whole seconds.
    Seconds,
    /// A boolean, carried as `0` / `1`. **Not a JSON bool**: one integer domain
    /// for every key is what lets [`FlowPolarity`] be a total order over all of
    /// them, and a two-valued integer orders exactly as well as a bool.
    Flag,
    /// A ratio in **centi-units**: `100` = 1.00×, `250` = 2.50×. Integer, per
    /// the band-not-float discipline.
    CentiRatio,
}

impl MeshConfigUnit {
    /// The stable program token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Count => "count",
            Self::Seconds => "seconds",
            Self::Flag => "flag",
            Self::CentiRatio => "centi_ratio",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The CLOSED key registry (CC 4.2.1 rule 2)
// ─────────────────────────────────────────────────────────────────────────

/// **The closed key registry.** CC 4.2.1 rule 2: *"a config key naming no
/// consumer processor MUST be refused at admission."*
///
/// Closed **by construction**, not by a string list: an unregistered key cannot
/// be named because there is no variant to name it with, and a wire row
/// carrying an unknown key resolves to `None` from [`Self::from_wire`] and is
/// refused with [`MeshConfigRefusalReason::UnknownKey`]. That is the #333
/// lesson — a conferral nothing gates on is decoration — enforced by the type
/// system rather than by a lookup someone can forget to call.
///
/// The nine are #570's own initial registry, verbatim. Each carries the four
/// facts the plane needs and nothing else: its wire spelling, its
/// [`FlowPolarity`], its domain, and its consumer processor.
///
/// # About `consumer`
///
/// Every consumer is a **downstream loop**, and none of them is in persist —
/// see the module doc. The rule CC states is that a key must name one, not that
/// the substrate must run it; a mesh-config plane whose keys could only address
/// the substrate's own knobs would be able to express almost nothing the
/// taxonomy asks for. What persist owes, and
/// [`tests::every_registered_key_names_a_distinct_consumer_knob`] enforces, is
/// that the naming is real: every key names a consumer AND a knob, and no two
/// keys name the same `(consumer, knob)` pair — two keys driving one knob is a
/// disagreement waiting to be resolved by whichever fold ran last.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(into = "String")]
pub enum MeshConfigKey {
    /// Target repair-symbol count the repair planner aims for. #570's headline:
    /// *"20 copies → 10"*. Higher = more copies pushed = more flow.
    RedundancyKRepairTarget,
    /// Floor below which a corpus is not considered viable. Higher = more
    /// copies must be held and served = more flow.
    RedundancyMinViableFloor,
    /// Seconds between anti-entropy rounds. **Higher = rounds less often = LESS
    /// flow.**
    AntientropyRoundSecs,
    /// Rows per anti-entropy page. Higher = bigger pages = more flow.
    AntientropyPageLimit,
    /// Serve trace summaries instead of full rows. **1 = summaries only = LESS
    /// flow.**
    BackpressureSummaryOnly,
    /// Whether AV stream replication runs at all. 1 = on = more flow.
    FeatureAvStreams,
    /// Whether trace rows replicate. 1 = on = more flow.
    FeatureTraceReplication,
    /// Descent pressure multiplier (CC 6.1.2), in centi-units. **Higher = more
    /// descent = LESS flow.**
    DescentPressureMultiplier,
    /// Admission rate ceiling per attesting key, rows per burst window. Higher
    /// = more admitted = more flow.
    AdmissionRatePerKey,
}

/// One registered key's full specification. Returned by
/// [`MeshConfigKey::spec`] so a consumer reads one struct instead of calling
/// five accessors and hoping they agree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MeshConfigKeySpec {
    /// The wire spelling.
    pub wire_name: &'static str,
    /// Which direction means more flow.
    pub polarity: FlowPolarity,
    /// The unit the integer is in.
    pub unit: MeshConfigUnit,
    /// Inclusive lower bound of the admissible domain.
    pub min: i64,
    /// Inclusive upper bound of the admissible domain.
    pub max: i64,
    /// The value a node runs when no root has spoken and the host supplies no
    /// baseline of its own — *"what its owner consented to"* by default.
    pub owner_default: i64,
    /// The processor that reads this key.
    pub consumer: &'static str,
    /// The specific knob within that processor.
    pub knob: &'static str,
}

impl MeshConfigKey {
    /// Every registered key, in declaration order. **The closed set.**
    pub const ALL: &'static [Self] = &[
        Self::RedundancyKRepairTarget,
        Self::RedundancyMinViableFloor,
        Self::AntientropyRoundSecs,
        Self::AntientropyPageLimit,
        Self::BackpressureSummaryOnly,
        Self::FeatureAvStreams,
        Self::FeatureTraceReplication,
        Self::DescentPressureMultiplier,
        Self::AdmissionRatePerKey,
    ];

    /// This key's full specification — the ONE place its five facts live.
    #[must_use]
    pub const fn spec(self) -> MeshConfigKeySpec {
        use FlowPolarity::{HigherMeansMoreFlow, LowerMeansMoreFlow};
        use MeshConfigUnit::{CentiRatio, Count, Flag, Seconds};
        match self {
            Self::RedundancyKRepairTarget => MeshConfigKeySpec {
                wire_name: "redundancy.k_repair_target",
                polarity: HigherMeansMoreFlow,
                unit: Count,
                min: 0,
                max: 4096,
                owner_default: 20,
                consumer: "repair_planner",
                knob: "target_repair_symbols",
            },
            Self::RedundancyMinViableFloor => MeshConfigKeySpec {
                wire_name: "redundancy.min_viable_floor",
                polarity: HigherMeansMoreFlow,
                unit: Count,
                min: 1,
                max: 4096,
                owner_default: 3,
                consumer: "repair_planner",
                knob: "min_viable_floor",
            },
            Self::AntientropyRoundSecs => MeshConfigKeySpec {
                wire_name: "antientropy.round_secs",
                // Longer between rounds is LESS gossip.
                polarity: LowerMeansMoreFlow,
                unit: Seconds,
                min: 1,
                max: 86_400,
                owner_default: 60,
                consumer: "antientropy_scheduler",
                knob: "round_interval",
            },
            Self::AntientropyPageLimit => MeshConfigKeySpec {
                wire_name: "antientropy.page_limit",
                polarity: HigherMeansMoreFlow,
                unit: Count,
                min: 1,
                max: 10_000,
                owner_default: 500,
                consumer: "antientropy_scheduler",
                knob: "page_limit",
            },
            Self::BackpressureSummaryOnly => MeshConfigKeySpec {
                wire_name: "backpressure.summary_only",
                // 1 = summaries instead of rows = LESS out.
                polarity: LowerMeansMoreFlow,
                unit: Flag,
                min: 0,
                max: 1,
                owner_default: 0,
                consumer: "serve_path",
                knob: "summary_only",
            },
            Self::FeatureAvStreams => MeshConfigKeySpec {
                wire_name: "feature.av_streams",
                polarity: HigherMeansMoreFlow,
                unit: Flag,
                min: 0,
                max: 1,
                owner_default: 1,
                consumer: "stream_replicator",
                knob: "av_streams_enabled",
            },
            Self::FeatureTraceReplication => MeshConfigKeySpec {
                wire_name: "feature.trace_replication",
                polarity: HigherMeansMoreFlow,
                unit: Flag,
                min: 0,
                max: 1,
                owner_default: 1,
                consumer: "trace_replicator",
                knob: "trace_replication_enabled",
            },
            Self::DescentPressureMultiplier => MeshConfigKeySpec {
                wire_name: "descent.pressure_multiplier",
                // More descent pressure = the node does LESS.
                polarity: LowerMeansMoreFlow,
                unit: CentiRatio,
                min: 100,
                max: 10_000,
                owner_default: 100,
                consumer: "descent_controller",
                knob: "pressure_multiplier",
            },
            Self::AdmissionRatePerKey => MeshConfigKeySpec {
                wire_name: "admission.rate_per_key",
                polarity: HigherMeansMoreFlow,
                unit: Count,
                min: 0,
                max: 1_000_000,
                owner_default: 600,
                consumer: "peer_write_quota",
                knob: "per_key_rows_per_window",
            },
        }
    }

    /// The wire spelling.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        self.spec().wire_name
    }

    /// Which direction means more flow.
    #[must_use]
    pub const fn polarity(self) -> FlowPolarity {
        self.spec().polarity
    }

    /// The unit the value is in.
    #[must_use]
    pub const fn unit(self) -> MeshConfigUnit {
        self.spec().unit
    }

    /// The processor that reads this key.
    #[must_use]
    pub const fn consumer(self) -> &'static str {
        self.spec().consumer
    }

    /// The default owner-consented value.
    #[must_use]
    pub const fn owner_default(self) -> i64 {
        self.spec().owner_default
    }

    /// Resolve a wire key name to its registered key. `None` for anything
    /// outside the closed set — the whole of CC 4.2.1 rule 2 in one function.
    #[must_use]
    pub fn from_wire(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.wire_name() == name)
    }

    /// The full `scores` dimension for this key: `mesh_config:{key}:v1`.
    #[must_use]
    pub fn dimension(self) -> String {
        format!("{DIMENSION_PREFIX}{}{DIMENSION_SUFFIX}", self.wire_name())
    }

    /// Resolve a wire dimension back to its key, or `None`.
    #[must_use]
    pub fn from_dimension(dimension: &str) -> Option<Self> {
        let rest = dimension.strip_prefix(DIMENSION_PREFIX)?;
        let name = rest.strip_suffix(DIMENSION_SUFFIX)?;
        Self::from_wire(name)
    }

    /// Is `value` inside this key's declared domain?
    #[must_use]
    pub const fn in_domain(self, value: i64) -> bool {
        let s = self.spec();
        value >= s.min && value <= s.max
    }

    /// **`most-restrictive-across-roots`, as a binary operator.** The one of
    /// `a` / `b` that means LESS flow, per this key's [`FlowPolarity`].
    ///
    /// Commutative, associative and idempotent — a min or a max over a total
    /// order — which is precisely why a fold built from it cannot depend on
    /// root ORDER. CC calls most-restrictive *forced, not preferred*; an
    /// order-sensitive combiner would make it preferred, and
    /// [`tests::the_fold_is_invariant_under_every_permutation_of_the_roots`]
    /// is the executed proof it is not.
    #[must_use]
    pub const fn more_restrictive_of(self, a: i64, b: i64) -> i64 {
        match self.polarity() {
            // Less flow = smaller.
            FlowPolarity::HigherMeansMoreFlow => {
                if a <= b {
                    a
                } else {
                    b
                }
            }
            // Less flow = larger.
            FlowPolarity::LowerMeansMoreFlow => {
                if a >= b {
                    a
                } else {
                    b
                }
            }
        }
    }

    /// **`relieve-never-expand`, as a predicate.** Does `candidate` mean MORE
    /// flow than `baseline`?
    ///
    /// The exact complement of [`Self::more_restrictive_of`]: `candidate`
    /// expands iff the more-restrictive of the two is `baseline` and they
    /// differ. Written that way rather than as a second comparison so the two
    /// ratified rules cannot come to disagree about which way a key points —
    /// rule #9, one predicate one implementation.
    #[must_use]
    pub const fn expands_beyond(self, candidate: i64, baseline: i64) -> bool {
        candidate != baseline && self.more_restrictive_of(candidate, baseline) == baseline
    }

    /// `candidate` clamped so it never expands past `baseline`. The fold's
    /// enforcement of rule 1.
    #[must_use]
    pub const fn clamp_to_consent(self, candidate: i64, baseline: i64) -> i64 {
        if self.expands_beyond(candidate, baseline) {
            baseline
        } else {
            candidate
        }
    }
}

impl std::fmt::Display for MeshConfigKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.wire_name())
    }
}

impl From<MeshConfigKey> for String {
    fn from(k: MeshConfigKey) -> Self {
        k.wire_name().to_owned()
    }
}

impl<'de> serde::Deserialize<'de> for MeshConfigKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_wire(&s).ok_or_else(|| {
            serde::de::Error::custom(format!(
                "{s:?} is not a registered mesh_config key (CC 4.2.1 rule 2: the registry is \
                 closed — a key naming no consumer processor is refused)"
            ))
        })
    }
}

/// **What the node's owner consented to**, per key. The ceiling
/// `relieve-never-expand` is measured against.
///
/// Node config is SELF (#324) — so the baseline is the node's OWN value,
/// supplied by the host, never carried on an incoming row. A baseline read off
/// the row being judged would let the row authorise itself, which is the
/// caller-supplied-decision-bool class this repo closed in #377.
///
/// Sparse: any key the host does not pin falls back to
/// [`MeshConfigKey::owner_default`].
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MeshConfigBaseline {
    /// `(key, owner-consented value)`, sparse.
    pub pinned: Vec<(MeshConfigKey, i64)>,
}

impl MeshConfigBaseline {
    /// The node's default posture: every key at its `owner_default`.
    #[must_use]
    pub fn owner_defaults() -> Self {
        Self { pinned: Vec::new() }
    }

    /// Pin one key. Out-of-domain values are clamped into the key's domain
    /// rather than rejected — this is the OWNER's own number, and a host that
    /// asks for something unrepresentable should get the nearest representable
    /// thing, not a plane that silently stops folding.
    #[must_use]
    pub fn with(mut self, key: MeshConfigKey, value: i64) -> Self {
        let s = key.spec();
        let clamped = value.clamp(s.min, s.max);
        self.pinned.retain(|(k, _)| *k != key);
        self.pinned.push((key, clamped));
        self
    }

    /// The consented value for `key`.
    #[must_use]
    pub fn get(&self, key: MeshConfigKey) -> i64 {
        self.pinned
            .iter()
            .find(|(k, _)| *k == key)
            .map_or_else(|| key.owner_default(), |(_, v)| *v)
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Form (CC 4.2.1 rule 3)
// ─────────────────────────────────────────────────────────────────────────

/// Emergency relief or a durable setting. CC 4.2.1 rule 3 gives them different
/// authority and different lifetimes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshConfigForm {
    /// **Threshold-1.** One holder, acting alone, may relieve — and it expires:
    /// [`field::VALID_UNTIL`] is mandatory and bounded by
    /// [`EMERGENCY_MAX_TTL_HOURS`], and the same holder may not chain one
    /// window straight onto the last
    /// ([`MeshConfigRefusalReason::BackToBackRenewal`]).
    ///
    /// The bound is the whole safety argument: *"the emergency path must not
    /// become the government"* (#570's fourth design wall). Single-holder
    /// changes expire **by construction**, so the government is a thing you
    /// have to keep being, not a thing you become by acting once.
    Emergency,
    /// Permanent until superseded, and correspondingly harder to get. CC:
    /// *"durable settings require **the root's own quorum** ratifying the
    /// emergency's `payload_sha256`."*
    ///
    /// **Two doors, and which two is a reading of an ambiguous clause.** Both
    /// are pinned by
    /// [`tests::cc_421_rule_3_is_read_as_unilateral_not_unexercised`], which
    /// quotes the sentence, so if CC disambiguates in either direction it fails
    /// loudly rather than sitting here looking settled:
    ///
    /// 1. **Conversion.** The row names the emergency it makes durable
    ///    ([`field::RATIFIES`]); that emergency must be one this node holds, on
    ///    the same key and root, agreeing about the value.
    /// 2. **Cold durable, under the root's own quorum.** No prior emergency —
    ///    admitted iff the act is not UNILATERAL. For a
    ///    [`RootKind::Family`](super::trust_root::RootKind::Family) root that
    ///    means ≥m distinct seated holders scrubbed this row, counted by the
    ///    same [`family_quorum_over`](super::trust_root::family_quorum_over)
    ///    that charters roots. For a
    ///    [`RootKind::Key`](super::trust_root::RootKind::Key) root it means the
    ///    root ITSELF signed — *"1-of-1 is a legitimate quorum for a root you
    ///    alone own"*, which is
    ///    [`trust_root`](super::trust_root)'s own doctrine, not a hole opened
    ///    here. A CONFERRED delegate is refused on both arms: a delegation is
    ///    not a quorum, and that is where this door actually bites.
    ///
    /// # The reading, and the one it replaced
    ///
    /// This module first shipped the STRICT reading — cold durable refused
    /// outright, so a setting became durable only by having been *exercised*.
    /// It was overturned on **CC 4.2.1 rule (4)**, which states the reason the
    /// TTL exists: *"relief expires because it is **unilateral**; the halt
    /// carries no TTL because its exit is the named resumption."* The bound
    /// attaches to `threshold-1`, not to emergency-ness — so what earns
    /// durability is **quorum**, not history. Under the strict reading a full
    /// quorum act was still barred from durability unless it happened to
    /// ratify some prior *unilateral* one, which makes quorum weaker than rule
    /// (4)'s own logic and makes a single holder the agenda-setter for every
    /// durable setting the mesh can hold.
    ///
    /// Two consequences settled it. Strict made a durable restriction that was
    /// never an emergency **unreachable forever** — a fresh mesh could hold no
    /// durable `mesh_config` until someone fired a 72-hour emergency to
    /// bootstrap one, which is the circular-at-genesis class. And it forced
    /// *every* durable change through the emergency channel, which is the most
    /// direct available route to "the emergency path becomes the government" —
    /// the property it was meant to protect. Compare CC 3.4.14 R4 on another
    /// plane: *"marking everything is the same failure as marking nothing."*
    ///
    /// The honest counter, kept because it is not nothing: *"**the**
    /// emergency's `payload_sha256`"* is a definite article and does
    /// presuppose an emergency. But rule 3 is titled *"Emergency relief is
    /// TTL-bounded"* — its subject is the emergency path, so it specifies the
    /// CONVERSION case rather than enumerating every door to durability, and
    /// reading its silence as prohibition is the fail-closed-and-wrong trade
    /// CIRISPersist#590 exists to prevent.
    ///
    /// What makes this safe either way is rule 1: a cold durable row can only
    /// ever RESTRICT, because [`fold_mesh_config`] clamps it. The dangerous
    /// direction was already closed by construction, so "must have been
    /// exercised" bought little and cost reachability.
    ///
    /// Argued out with CIRISPersist#571's agent; the reasoning above is
    /// substantially theirs.
    Durable,
}

impl MeshConfigForm {
    /// The stable program token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Emergency => "emergency",
            Self::Durable => "durable",
        }
    }

    /// Parse the wire token.
    #[must_use]
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "emergency" => Some(Self::Emergency),
            "durable" => Some(Self::Durable),
            _ => None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Typed refusals (#565 style)
// ─────────────────────────────────────────────────────────────────────────

/// **WHICH branch refused** a mesh-config row.
///
/// Closed, snake_case serde tokens, [`Self::as_str`] returning the SAME token,
/// no `Other`/`Unspecified` catch-all — the
/// [`KeyRefusalReason`](super::register::KeyRefusalReason) discipline #565
/// shipped and #570 asks 2–5 already ship to this consumer. **The token set is
/// the downstream contract and this mapping is APPEND-ONLY.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshConfigRefusalReason {
    /// The envelope `dimension` is not `mesh_config:{key}:v1`. Wrong door.
    DimensionMismatch,
    /// **CC 4.2.1 rule 2, the closed registry.** The row names a key outside
    /// [`MeshConfigKey::ALL`], or its dimension and its [`field::KEY`]
    /// disagree about which key it sets. A key naming no consumer processor
    /// cannot be set — and a row whose two self-descriptions disagree is
    /// refused rather than resolved toward either, the same call
    /// `trust_root::job_dimension_admits` makes.
    UnknownKey,
    /// A field the fold needs is missing or the wrong JSON type —
    /// [`field::VALUE`] not an integer, [`field::ROOT_REF`] absent,
    /// [`field::FORM`] not one of the two tokens, [`field::VALID_UNTIL`]
    /// unparseable.
    MalformedEnvelope,
    /// The value is outside the key's declared `[min, max]`.
    ValueOutOfDomain,
    /// No [`field::DELEGATION_ID`]. #570 ask 3's rule: an act that does not
    /// carry its own authority is indistinguishable from an unauthorized one
    /// once the actor is gone.
    Unattributed,
    /// The row is not filed against the root it names, so the fold's
    /// `list_attestations_for(root)` read would never see it. A row stored and
    /// permanently uncounted is the preserve-set ≠ verified-set class (#541).
    NotFiledAgainstRoot,
    /// This node holds no live `trust:accepts:v1` edge to the named root. **The
    /// subscription is the trust edge** (CC 4.2.1), so a root this node has not
    /// subscribed to has nothing to say to it — and un-trusting is one row,
    /// which is the T3 lever CC names.
    RootNotTrusted,
    /// The author is neither the root itself nor a key the root has conferred
    /// to by a live `trust:confers:v1` `delegates_to`. CC 4.2.1 puts the
    /// authority *on the delegation plane*; this is that sentence as a gate.
    AuthorNotRootAuthorized,
    /// The author's own scrub signature did not verify against pubkeys resolved
    /// from THIS node's directory (#377 — never pubkeys carried on the row).
    UnverifiableSignature,
    /// **CC 4.2.1 rule 3.** An [`Emergency`](MeshConfigForm::Emergency) row
    /// carries no [`field::VALID_UNTIL`]. Relief that does not expire is not
    /// relief, it is government.
    TtlMissing,
    /// **CC 4.2.1 rule 3.** The emergency window exceeds
    /// [`EMERGENCY_MAX_TTL_HOURS`], or ends before it starts.
    TtlTooLong,
    /// **CC 4.2.1 rule 3.** *"not renewable back-to-back by the same holder"* —
    /// this author already holds an emergency row on this `(root, key)` whose
    /// window has not closed before the new one opens. Chaining 72-hour
    /// windows is how a unilateral lever becomes a permanent one.
    BackToBackRenewal,
    /// A [`Durable`](MeshConfigForm::Durable) row NAMES a
    /// [`field::RATIFIES`] that does not resolve to an emergency this node
    /// holds on the same root and key with the same value. Ratification of
    /// nothing is not ratification.
    ///
    /// Note what this is NOT: a durable row naming no emergency at all is the
    /// cold-durable door, judged by
    /// [`DurableWithoutRootQuorum`](Self::DurableWithoutRootQuorum).
    DurableUnratified,
    /// A **cold** [`Durable`](MeshConfigForm::Durable) row — one naming no
    /// prior emergency — that did not reach **the root's own quorum**.
    ///
    /// CC 4.2.1 rule 3 gives durability to quorum, and rule 4 says why:
    /// *"relief expires because it is unilateral."* So a durable setting with
    /// no emergency behind it must not be a unilateral act. A conferred
    /// delegate is refused here on both root arms — a delegation is not a
    /// quorum — as is a family-root row that fewer than m distinct seated
    /// holders scrubbed.
    ///
    /// The one act this does NOT refuse is a single-key root signing for
    /// itself: 1-of-1 is that root's whole quorum, which is
    /// [`trust_root`](super::trust_root)'s own doctrine and not a carve-out
    /// invented here.
    DurableWithoutRootQuorum,
    /// **CC 4.2.1 rule 1, at the door.** The value means MORE flow than this
    /// node's own baseline. *"No key may cause a node to share more than its
    /// owner consented to."*
    ///
    /// Refusing here is the LOUD half; [`fold_mesh_config`] clamps
    /// unconditionally at read time, which is the half that holds for rows this
    /// door never saw.
    ExpandsBeyondConsent,
}

impl MeshConfigRefusalReason {
    /// The stable program token — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::DimensionMismatch => "dimension_mismatch",
            Self::UnknownKey => "unknown_key",
            Self::MalformedEnvelope => "malformed_envelope",
            Self::ValueOutOfDomain => "value_out_of_domain",
            Self::Unattributed => "unattributed",
            Self::NotFiledAgainstRoot => "not_filed_against_root",
            Self::RootNotTrusted => "root_not_trusted",
            Self::AuthorNotRootAuthorized => "author_not_root_authorized",
            Self::UnverifiableSignature => "unverifiable_signature",
            Self::TtlMissing => "ttl_missing",
            Self::TtlTooLong => "ttl_too_long",
            Self::BackToBackRenewal => "back_to_back_renewal",
            Self::DurableUnratified => "durable_unratified",
            Self::DurableWithoutRootQuorum => "durable_without_root_quorum",
            Self::ExpandsBeyondConsent => "expands_beyond_consent",
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[
        Self::DimensionMismatch,
        Self::UnknownKey,
        Self::MalformedEnvelope,
        Self::ValueOutOfDomain,
        Self::Unattributed,
        Self::NotFiledAgainstRoot,
        Self::RootNotTrusted,
        Self::AuthorNotRootAuthorized,
        Self::UnverifiableSignature,
        Self::TtlMissing,
        Self::TtlTooLong,
        Self::BackToBackRenewal,
        Self::DurableUnratified,
        Self::DurableWithoutRootQuorum,
        Self::ExpandsBeyondConsent,
    ];
}

impl std::fmt::Display for MeshConfigRefusalReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of a mesh-config admission attempt. `Refused` is a **policy**
/// outcome, not an error: rows arrive unsolicited on a replication plane, so
/// every gate failure resolves deterministically and safe-to-re-offer rather
/// than aborting a loop. Backend/IO failures still surface as `Err`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshConfigOutcome {
    /// Admitted and stored.
    Admitted,
    /// Not admitted; nothing was written.
    Refused {
        /// WHICH policy branch refused.
        reason: MeshConfigRefusalReason,
    },
}

impl MeshConfigOutcome {
    /// The refusal reason, if this is a refusal.
    #[must_use]
    pub const fn refusal(&self) -> Option<MeshConfigRefusalReason> {
        match self {
            Self::Admitted => None,
            Self::Refused { reason } => Some(*reason),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Envelope builder
// ─────────────────────────────────────────────────────────────────────────

/// Build the canonical envelope of a mesh-config row. Defined here so a
/// producer and this node's fold agree byte-for-byte about where each value
/// lives.
///
/// `valid_until` is `Option` because only [`MeshConfigForm::Emergency`]
/// requires it — but a durable row MAY still carry one, and the fold honours it
/// either way. `ratifies` is `Option` for the mirror reason.
///
/// Eight positional arguments, and a builder struct would be nicer. It is
/// deliberately NOT one: every argument here is a field the fold and the
/// admission door both read by name, and the whole value of this function is
/// that there is exactly one place the envelope's shape is written. A builder
/// with defaults would let a producer omit `root_ref` or `delegation_id` and
/// get a row that parses, stores, and is then refused or silently uncounted —
/// which is the failure this function exists to make impossible at the call
/// site.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn mesh_config_envelope(
    key: MeshConfigKey,
    value: i64,
    root_ref: &str,
    form: MeshConfigForm,
    valid_until: Option<DateTime<Utc>>,
    delegation_id: &str,
    ratifies: Option<&str>,
    grounds: &str,
) -> serde_json::Value {
    let mut env = serde_json::json!({
        "dimension": key.dimension(),
        field::KEY: key.wire_name(),
        field::VALUE: value,
        field::ROOT_REF: root_ref,
        field::FORM: form.as_str(),
        field::DELEGATION_ID: delegation_id,
        field::GROUNDS: grounds,
    });
    if let Some(vu) = valid_until {
        env[field::VALID_UNTIL] = serde_json::Value::String(vu.to_rfc3339());
    }
    if let Some(r) = ratifies {
        env[field::RATIFIES] = serde_json::Value::String(r.to_owned());
    }
    env
}

// ─────────────────────────────────────────────────────────────────────────
//  Envelope readers
// ─────────────────────────────────────────────────────────────────────────

fn env_str<'a>(row: &'a Attestation, key: &str) -> Option<&'a str> {
    row.attestation_envelope.get(key)?.as_str()
}

fn env_nonempty<'a>(row: &'a Attestation, key: &str) -> Option<&'a str> {
    env_str(row, key).filter(|s| !s.is_empty())
}

fn env_i64(row: &Attestation, key: &str) -> Option<i64> {
    row.attestation_envelope.get(key)?.as_i64()
}

fn env_time(row: &Attestation, key: &str) -> Option<DateTime<Utc>> {
    env_str(row, key)?.parse::<DateTime<Utc>>().ok()
}

/// Is `dimension` on this plane at all?
#[must_use]
pub fn is_mesh_config_dimension(dimension: &str) -> bool {
    MeshConfigKey::from_dimension(dimension).is_some()
}

/// **One row, parsed into the four facts the fold needs**, or `None` if it is
/// not a well-formed mesh-config row.
///
/// Deliberately the SAME parse the admission door runs, so a row cannot be
/// admitted under one reading and folded under another. Note in particular that
/// the `dimension` and the [`field::KEY`] must AGREE — a row claiming
/// `mesh_config:feature.av_streams:v1` while setting
/// `admission.rate_per_key` is refused rather than resolved toward either.
#[must_use]
fn parse_row(row: &Attestation) -> Option<ParsedRow> {
    let dimension = env_str(row, "dimension")?;
    let key = MeshConfigKey::from_dimension(dimension)?;
    if env_str(row, field::KEY)? != key.wire_name() {
        return None;
    }
    let value = env_i64(row, field::VALUE)?;
    if !key.in_domain(value) {
        return None;
    }
    let root_ref = env_nonempty(row, field::ROOT_REF)?.to_owned();
    let form = MeshConfigForm::from_wire(env_str(row, field::FORM)?)?;
    // Present-but-unparseable is a REFUSAL, not "no TTL": treating a garbled
    // expiry as absent would make a malformed emergency row immortal.
    let valid_until = match row.attestation_envelope.get(field::VALID_UNTIL) {
        None => None,
        Some(serde_json::Value::Null) => None,
        Some(_) => Some(env_time(row, field::VALID_UNTIL)?),
    };
    Some(ParsedRow {
        key,
        value,
        root_ref,
        form,
        valid_until,
    })
}

/// The parsed shape of one mesh-config row.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedRow {
    key: MeshConfigKey,
    value: i64,
    root_ref: String,
    form: MeshConfigForm,
    valid_until: Option<DateTime<Utc>>,
}

// ─────────────────────────────────────────────────────────────────────────
//  The fold
// ─────────────────────────────────────────────────────────────────────────

/// One root's own answer for one key — carried whether it won or not, so the
/// disagreement between roots is auditable rather than merely resolved.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RootValue {
    /// The root that said it.
    pub root_ref: String,
    /// What that root's newest live row asks for, **before** the
    /// relieve-never-expand clamp. Reported raw on purpose: a reader auditing a
    /// hostile root needs to see what it ASKED for, not only what it got.
    pub asked: i64,
    /// The same value after clamping to the node's baseline — what this root
    /// actually contributes to the cross-root fold.
    pub effective: i64,
    /// `true` iff the clamp bit: this root tried to expand past consent.
    pub clamped: bool,
    /// The governing row's `attestation_id`.
    pub row_id: String,
    /// Emergency or durable.
    pub form: MeshConfigForm,
    /// The governing row's TTL, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

/// The resolved setting for one key: what the node runs, and every root's
/// answer that produced it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MeshConfigSetting {
    /// The registered key.
    pub key: MeshConfigKey,
    /// Which direction means more flow — carried so a consumer can check the
    /// fold's arithmetic without re-deriving the registry.
    pub polarity: FlowPolarity,
    /// The unit `baseline` and `effective` are in.
    pub unit: MeshConfigUnit,
    /// What the node's owner consented to.
    pub baseline: i64,
    /// **What the node runs.** Never means more flow than `baseline`.
    pub effective: i64,
    /// `true` iff some root moved this key off the baseline.
    pub relieved: bool,
    /// The root whose value bound, when one did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by_root: Option<String>,
    /// That root's governing row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_id: Option<String>,
    /// Its author — WHO turned the knob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    /// The `delegates_to` id they acted under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_id: Option<String>,
    /// Emergency or durable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form: Option<MeshConfigForm>,
    /// When the binding value stops applying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// The grounds recorded. Never interpreted by persist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grounds: Option<String>,
    /// **Every** root's answer, sorted by `root_ref` — including the ones that
    /// lost and the ones that were clamped.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub per_root: Vec<RootValue>,
    /// Roots whose value was clamped for expanding past consent, sorted. The
    /// enumeration a compromised-root review reads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clamped_roots: Vec<String>,
}

/// What this node's held mesh-config rows say, right now.
///
/// A derived STATE, not a sentence — a pure function of held rows and the
/// node's own baseline, recomputed at read time, converging on every node
/// without coordination once the rows have travelled.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MeshConfigFold {
    /// The node the fold is about.
    pub node_key_id: String,
    /// Every trust root folded, sorted. A node with two roots folds both and
    /// takes the tightest per key.
    pub roots: Vec<String>,
    /// One entry per registered key — **all nine, always**, even when no root
    /// has spoken about it. A consumer reading a config plane should never have
    /// to distinguish "not set" from "not returned"; an absent key is exactly
    /// how a knob silently keeps a stale value.
    pub settings: Vec<MeshConfigSetting>,
}

impl MeshConfigFold {
    /// The effective value for `key`. Infallible: every key is always present.
    #[must_use]
    pub fn effective(&self, key: MeshConfigKey) -> i64 {
        self.settings
            .iter()
            .find(|s| s.key == key)
            .map_or_else(|| key.owner_default(), |s| s.effective)
    }

    /// The resolved setting for `key`.
    #[must_use]
    pub fn setting(&self, key: MeshConfigKey) -> Option<&MeshConfigSetting> {
        self.settings.iter().find(|s| s.key == key)
    }

    /// A flag key as a bool. `Flag` keys carry `0`/`1`; this is the ONE place
    /// that mapping happens, so a consumer cannot invent a second one.
    #[must_use]
    pub fn flag(&self, key: MeshConfigKey) -> bool {
        self.effective(key) != 0
    }
}

/// **The pure fold** — a function of `(node_key_id, baseline, rows, now)` and
/// nothing else.
///
/// # Per root, then across roots
///
/// 1. **Drop what does not count.** A row counts for `(root, key)` iff it
///    parses ([`parse_row`]), its `root_ref` is that root, the root is in
///    `roots`, `asserted_at <= now`, and its `valid_until` (if any) is strictly
///    after `now`. **TTL-expired rows drop at read time** — #570's own wording,
///    and the reason an expired relief needs no revocation and no reachable
///    author.
/// 2. **Newest wins within a root**, ordered by
///    `(asserted_at, more-restrictive, attestation_id)`.
///    - `asserted_at` alone is not a total order, and two rows at one instant
///      is exactly what an author constructs to let each node pick its own
///      answer;
///    - **at a tie, the MORE RESTRICTIVE value wins** — the only safe
///      direction, and the same call `quarantine::fold_quarantine` makes when
///      it lets withhold beat release at equal timestamps. A relaxation lost to
///      a tie-break is recoverable by another row; a relaxation WON by a
///      tie-break is not recoverable by anything;
///    - `attestation_id` breaks the remainder, so the fold is a function of the
///      row set and never of arrival order.
/// 3. **Clamp to consent** (CC 4.2.1 rule 1). Each root's winning value is
///    clamped so it cannot mean more flow than `baseline`. A root that tried to
///    expand contributes exactly `baseline` and is named in `clamped_roots`.
/// 4. **Most restrictive across roots** (CC 4.2.1 rule 2), by
///    [`MeshConfigKey::more_restrictive_of`] — a min-or-max over a total order,
///    so the result cannot depend on the order the roots are visited.
///
/// Step 3 before step 4 is load-bearing. Clamping AFTER the cross-root fold
/// would let an expanding root's value participate in the comparison, where it
/// can only ever lose (it means more flow than the baseline every other root is
/// bounded by) — so the two orders agree on the effective VALUE. What they do
/// not agree on is attribution: fold-then-clamp would let a hostile root's
/// number appear in `per_root[].effective` as though the node had considered
/// running it. Clamping first means every number this fold reports as effective
/// is one the node would actually run.
#[must_use]
pub fn fold_mesh_config(
    node_key_id: &str,
    baseline: &MeshConfigBaseline,
    roots: &[String],
    rows: &[Attestation],
    now: DateTime<Utc>,
) -> MeshConfigFold {
    let mut sorted_roots: Vec<String> = roots.to_vec();
    sorted_roots.sort();
    sorted_roots.dedup();

    let mut settings: Vec<MeshConfigSetting> = Vec::with_capacity(MeshConfigKey::ALL.len());

    for &key in MeshConfigKey::ALL {
        let base = baseline.get(key);
        let mut per_root: Vec<RootValue> = Vec::new();

        for root in &sorted_roots {
            // Step 1 — the counting rules.
            let mut live: Vec<(&Attestation, ParsedRow)> = rows
                .iter()
                .filter_map(|r| parse_row(r).map(|p| (r, p)))
                .filter(|(r, p)| {
                    p.key == key
                        && &p.root_ref == root
                        && r.asserted_at <= now
                        && p.valid_until.is_none_or(|vu| vu > now)
                })
                .collect();
            if live.is_empty() {
                continue;
            }
            // Step 2 — newest wins; at a tie, restriction wins. Sorts
            // ASCENDING and the LAST element governs, so the comparator ranks
            // the more-restrictive value HIGHER.
            live.sort_by(|(ra, pa), (rb, pb)| {
                ra.asserted_at
                    .cmp(&rb.asserted_at)
                    .then_with(|| {
                        let winner = key.more_restrictive_of(pa.value, pb.value);
                        if pa.value == pb.value {
                            std::cmp::Ordering::Equal
                        } else if winner == pa.value {
                            // `a` is tighter — it must sort LAST.
                            std::cmp::Ordering::Greater
                        } else {
                            std::cmp::Ordering::Less
                        }
                    })
                    .then_with(|| ra.attestation_id.cmp(&rb.attestation_id))
            });
            let (row, parsed) = &live[live.len() - 1];
            // Step 3 — clamp to consent.
            let effective = key.clamp_to_consent(parsed.value, base);
            per_root.push(RootValue {
                root_ref: root.clone(),
                asked: parsed.value,
                effective,
                clamped: effective != parsed.value,
                row_id: row.attestation_id.clone(),
                form: parsed.form,
                expires_at: parsed.valid_until,
            });
        }

        // Step 4 — most restrictive across roots.
        let mut effective = base;
        for rv in &per_root {
            effective = key.more_restrictive_of(effective, rv.effective);
        }

        // Attribution: the tightest root that actually moved the value. Ties
        // resolve to the lowest `root_ref` (per_root is already root-sorted),
        // so a two-root tie names a root deterministically on every node.
        let winner = per_root
            .iter()
            .find(|rv| rv.effective == effective && effective != base);
        let clamped_roots: Vec<String> = per_root
            .iter()
            .filter(|rv| rv.clamped)
            .map(|rv| rv.root_ref.clone())
            .collect();
        let winning_row = winner.and_then(|w| rows.iter().find(|r| r.attestation_id == w.row_id));

        settings.push(MeshConfigSetting {
            key,
            polarity: key.polarity(),
            unit: key.unit(),
            baseline: base,
            effective,
            relieved: effective != base,
            decided_by_root: winner.map(|w| w.root_ref.clone()),
            row_id: winner.map(|w| w.row_id.clone()),
            decided_by: winning_row.map(|r| r.attesting_key_id.clone()),
            delegation_id: winning_row
                .and_then(|r| env_nonempty(r, field::DELEGATION_ID))
                .map(str::to_owned),
            form: winner.map(|w| w.form),
            expires_at: winner.and_then(|w| w.expires_at),
            grounds: winning_row
                .and_then(|r| env_nonempty(r, field::GROUNDS))
                .map(str::to_owned),
            per_root,
            clamped_roots,
        });
    }

    MeshConfigFold {
        node_key_id: node_key_id.to_owned(),
        roots: sorted_roots,
        settings,
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Authority — re-derived from this node's own verified state (#377)
// ─────────────────────────────────────────────────────────────────────────

/// **CC 4.2.1's authority sentence, as a predicate.** May `author` set config
/// under `root_ref`?
///
/// Two ways, and only two:
///
/// - `author == root_ref` — the root speaking for itself;
/// - a live `delegates_to(root → author)` labelled `trust:confers:v1` — the
///   conferral leg, which is the plane CC names verbatim (*"the trust root,
///   acting on the CC 3.2 delegation plane (`trust:confers:v1`)"*).
///
/// Read from the node's OWN stored rows, never from anything the incoming row
/// carries (#377: a caller-supplied decision is a forgeable bypass). Live means
/// non-tombstoned, non-expired, federation-tier — the same four predicates
/// [`trust_root_valid`](super::trust_root::trust_root_valid) applies, reached
/// through [`trusted_roots_of`](super::trust_root::trusted_roots_of)'s module
/// rather than re-implemented here.
///
/// **No accord-holder arm exists**, deliberately: CC 4.2.1 confines
/// `HUMANITY_ACCORD` signatures to `EmergencyShutdown` and its named siblings
/// and says the mesh-config author is *"never the accord's ceremony plane"*.
/// Widening that scope is the thing CIRISConstitution#57 was opened to avoid.
async fn root_authorizes_author<F>(
    directory: &F,
    root_ref: &str,
    author: &str,
    now: DateTime<Utc>,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    if root_ref == author {
        return Ok(true);
    }
    let by_root = match directory.list_attestations_by(root_ref).await {
        Ok(rows) => rows,
        Err(Error::Unsupported { .. }) => Vec::new(),
        Err(e) => return Err(e),
    };
    let refs: Vec<&Attestation> = by_root.iter().collect();
    let dead = super::trust_root::tombstoned_ids(&refs);
    Ok(by_root.iter().any(|a| {
        a.attestation_type == super::types::attestation_type::DELEGATES_TO
            && a.attested_key_id == author
            && a.tier == super::types::attestation_tier::FEDERATION
            && !dead.contains(&a.attestation_id)
            && !a.expires_at.is_some_and(|e| e <= now)
            && env_str(a, "dimension") == Some(super::trust_root::TRUST_CONFERS_DIMENSION)
    }))
}

/// **"The root's own quorum" (CC 4.2.1 rule 3), as a predicate over one row.**
///
/// What counts depends on what kind of thing the root is, resolved once through
/// [`resolve_family_root`](super::trust_root::resolve_family_root) — the same
/// function [`trust_root_valid`](super::trust_root::trust_root_valid) uses to
/// pick its arm, so the two can never disagree about which arm a root is on:
///
/// - **Family root** — ≥m distinct SEATED holders must have scrubbed this row,
///   counted by [`family_quorum_over`](super::trust_root::family_quorum_over):
///   the row's full scrub set intersected with the family's own
///   revocation-folded roster, each survivor hybrid-verified against pubkeys
///   from THIS node's directory, against a threshold floored at a strict
///   majority of that roster. Not a second m-of-n implementation — the one
///   that charters roots.
/// - **Key root** — the root itself must be the author. *"1-of-1 is a
///   legitimate quorum for a root you alone own"* is
///   [`trust_root`](super::trust_root)'s stated doctrine, and this is where it
///   is being relied on rather than quietly assumed.
///
/// **A conferred delegate fails on both arms.** That is the whole bite of this
/// gate: a `trust:confers:v1` grant lets a key act for the root at
/// threshold-1 — which is exactly what CC 4.2.1 rule 4 says must expire — so
/// it can raise a bounded emergency and it cannot make anything permanent
/// alone.
async fn root_quorum_reached<F>(
    directory: &F,
    root_ref: &str,
    row: &Attestation,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    match super::trust_root::resolve_family_root(directory, root_ref).await? {
        Some(family) => Ok(
            super::trust_root::family_quorum_over(directory, row, &family)
                .await?
                .met(),
        ),
        None => Ok(row.attesting_key_id == root_ref),
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  The admission door
// ─────────────────────────────────────────────────────────────────────────

/// **The config door.** Admit and store one mesh-config row.
///
/// Verify-before-mutation (AV-9): every gate below runs BEFORE any row is
/// written, and a refusal writes nothing.
///
/// `node_key_id` is the node whose subscription and consent are being judged —
/// its live trust edges decide [`RootNotTrusted`](MeshConfigRefusalReason::RootNotTrusted),
/// and its `baseline` decides
/// [`ExpandsBeyondConsent`](MeshConfigRefusalReason::ExpandsBeyondConsent).
///
/// A row that clears every gate is stored through the ordinary
/// `put_attestation` path, which re-runs the shared namespace/reserved-prefix
/// admission. A row that arrives on the **replication plane** instead never
/// reaches this door at all — which is exactly why [`fold_mesh_config`] clamps
/// unconditionally rather than trusting that this ran.
pub async fn record_mesh_config_row<F>(
    directory: &F,
    node_key_id: &str,
    baseline: &MeshConfigBaseline,
    row: &Attestation,
    now: DateTime<Utc>,
) -> Result<MeshConfigOutcome, Error>
where
    F: FederationDirectory + ?Sized,
{
    use MeshConfigRefusalReason as R;
    let refused = |reason: R| Ok(MeshConfigOutcome::Refused { reason });

    // ── Shape. Split so the refusal names the branch rather than collapsing
    // every malformed row into one token a consumer cannot act on.
    let Some(dimension) = env_str(row, "dimension") else {
        return refused(R::DimensionMismatch);
    };
    if !dimension.starts_with(DIMENSION_PREFIX) {
        return refused(R::DimensionMismatch);
    }
    // On-plane but not a registered key — CC 4.2.1 rule 2.
    let Some(key) = MeshConfigKey::from_dimension(dimension) else {
        return refused(R::UnknownKey);
    };
    // The dimension and the key field must AGREE.
    match env_str(row, field::KEY) {
        None => return refused(R::MalformedEnvelope),
        Some(named) if named != key.wire_name() => return refused(R::UnknownKey),
        Some(_) => {}
    }
    let Some(value) = env_i64(row, field::VALUE) else {
        return refused(R::MalformedEnvelope);
    };
    if !key.in_domain(value) {
        return refused(R::ValueOutOfDomain);
    }
    let Some(root_ref) = env_nonempty(row, field::ROOT_REF).map(str::to_owned) else {
        return refused(R::MalformedEnvelope);
    };
    let Some(form) = env_str(row, field::FORM).and_then(MeshConfigForm::from_wire) else {
        return refused(R::MalformedEnvelope);
    };
    let valid_until = match row.attestation_envelope.get(field::VALID_UNTIL) {
        None | Some(serde_json::Value::Null) => None,
        Some(_) => match env_time(row, field::VALID_UNTIL) {
            Some(t) => Some(t),
            None => return refused(R::MalformedEnvelope),
        },
    };

    // ── #570 ask 3 on the wire: the act carries its own authority.
    if env_nonempty(row, field::DELEGATION_ID).is_none() {
        return refused(R::Unattributed);
    }

    // ── Filed where the fold looks, or stored and never counted.
    if row.attested_key_id != root_ref {
        return refused(R::NotFiledAgainstRoot);
    }

    // ── CC 4.2.1 rule 3 — the TTL bound on emergency relief.
    if form == MeshConfigForm::Emergency {
        let Some(vu) = valid_until else {
            return refused(R::TtlMissing);
        };
        let window = vu - row.asserted_at;
        if window <= Duration::zero() || window > Duration::hours(EMERGENCY_MAX_TTL_HOURS) {
            return refused(R::TtlTooLong);
        }
    }

    // ── CC 4.2.1 rule 1 at the door — relieve-never-expand.
    if key.expands_beyond(value, baseline.get(key)) {
        return refused(R::ExpandsBeyondConsent);
    }

    // ── The subscription. CC: "the trust edge is the subscription."
    let roots = super::trust_root::trusted_roots_of(directory, node_key_id, now).await?;
    if !roots.iter().any(|r| r == &root_ref) {
        return refused(R::RootNotTrusted);
    }

    // ── The authority, re-derived from this node's own state.
    if !root_authorizes_author(directory, &root_ref, &row.attesting_key_id, now).await? {
        return refused(R::AuthorNotRootAuthorized);
    }

    // ── The author's own signature, against pubkeys from THIS node's
    // directory (#377 — never pubkeys carried on the row).
    if super::verify_envelope_hybrid_signature(
        directory,
        &row.attesting_key_id,
        &row.attestation_envelope,
        &row.scrub_signature_classical,
        row.scrub_signature_pqc.as_deref(),
    )
    .await
    .is_err()
    {
        return refused(R::UnverifiableSignature);
    }

    // ── Rows this root already holds on this key — the two history gates.
    let held = match directory.list_attestations_for(&root_ref).await {
        Ok(rows) => rows,
        Err(Error::Unsupported { .. }) => Vec::new(),
        Err(e) => return Err(e),
    };
    let same_key: Vec<(&Attestation, ParsedRow)> = held
        .iter()
        .filter_map(|r| parse_row(r).map(|p| (r, p)))
        .filter(|(_, p)| p.key == key && p.root_ref == root_ref)
        .collect();

    match form {
        // CC 4.2.1 rule 3 — "not renewable back-to-back by the same holder."
        MeshConfigForm::Emergency => {
            let chains = same_key.iter().any(|(prior, p)| {
                p.form == MeshConfigForm::Emergency
                    && prior.attesting_key_id == row.attesting_key_id
                    && prior.attestation_id != row.attestation_id
                    // The prior window has not closed before this one opens.
                    && p.valid_until.is_none_or(|vu| vu > row.asserted_at)
            });
            if chains {
                return refused(R::BackToBackRenewal);
            }
        }
        // CC 4.2.1 rule 3 — durability belongs to QUORUM, not to history.
        // Two doors; see `MeshConfigForm::Durable` for the reading and the
        // argument that overturned the stricter one.
        MeshConfigForm::Durable => match env_nonempty(row, field::RATIFIES) {
            // Door 1 — CONVERSION. The row names the emergency it makes
            // permanent, and that emergency must be one this node holds, on
            // this root and key, agreeing about the value.
            Some(ratifies) => {
                let ratifies_a_real_emergency = same_key.iter().any(|(prior, p)| {
                    prior.attestation_id == ratifies
                        && p.form == MeshConfigForm::Emergency
                        && p.value == value
                });
                if !ratifies_a_real_emergency {
                    return refused(R::DurableUnratified);
                }
            }
            // Door 2 — COLD DURABLE, under the root's OWN quorum. What is
            // refused here is a UNILATERAL durable act (rule 4: "relief
            // expires because it is unilateral"), not an unexercised one.
            None => {
                if !root_quorum_reached(directory, &root_ref, row).await? {
                    return refused(R::DurableWithoutRootQuorum);
                }
            }
        },
    }

    directory
        .put_attestation(super::SignedAttestation {
            attestation: row.clone(),
        })
        .await?;
    Ok(MeshConfigOutcome::Admitted)
}

// ─────────────────────────────────────────────────────────────────────────
//  The read-time answer
// ─────────────────────────────────────────────────────────────────────────

/// **The read-time answer** — what this node's held rows say, as of `now`,
/// given what its owner consented to. Persist mutates nothing here.
///
/// Two reads per root plus one: [`trusted_roots_of`](super::trust_root::trusted_roots_of)
/// enumerates the subscription from the node's own edges, then one
/// `list_attestations_for(root)` per root collects that root's rows (they are
/// filed against the root, which is what
/// [`NotFiledAgainstRoot`](MeshConfigRefusalReason::NotFiledAgainstRoot)
/// guarantees). No index, no new table.
pub async fn resolve_mesh_config<F>(
    directory: &F,
    node_key_id: &str,
    baseline: &MeshConfigBaseline,
    now: DateTime<Utc>,
) -> Result<MeshConfigFold, Error>
where
    F: FederationDirectory + ?Sized,
{
    let roots = super::trust_root::trusted_roots_of(directory, node_key_id, now).await?;
    let mut rows: Vec<Attestation> = Vec::new();
    for root in &roots {
        match directory.list_attestations_for(root).await {
            Ok(found) => rows.extend(
                found
                    .into_iter()
                    .filter(|r| env_str(r, "dimension").is_some_and(is_mesh_config_dimension)),
            ),
            Err(Error::Unsupported { .. }) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(fold_mesh_config(node_key_id, baseline, &roots, &rows, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::types::{attestation_tier, attestation_type};

    fn ts(s: &str) -> DateTime<Utc> {
        s.parse().expect("rfc3339")
    }

    /// A mesh-config row. No signature, no directory — the fold is pure and
    /// these tests are about the fold.
    fn row(
        id: &str,
        author: &str,
        root: &str,
        key: MeshConfigKey,
        value: i64,
        at: &str,
        valid_until: Option<&str>,
    ) -> Attestation {
        let envelope = mesh_config_envelope(
            key,
            value,
            root,
            if valid_until.is_some() {
                MeshConfigForm::Emergency
            } else {
                MeshConfigForm::Durable
            },
            valid_until.map(ts),
            "att-deleg",
            None,
            "congestion",
        );
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: author.to_owned(),
            attested_key_id: root.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: ts(at),
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: "00".to_owned(),
            scrub_signature_classical: "c2ln".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: author.to_owned(),
            scrub_timestamp: ts(at),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    const NOW: &str = "2026-08-03T12:00:00Z";

    // ══════════════════════════════════════════════════════════════════
    // The closed registry (CC 4.2.1 rule 2)
    // ══════════════════════════════════════════════════════════════════

    /// The registry is closed BY CONSTRUCTION and round-trips through both
    /// wire surfaces.
    #[test]
    fn the_key_registry_is_closed_and_round_trips() {
        assert_eq!(MeshConfigKey::ALL.len(), 9, "#570's initial registry");
        for &k in MeshConfigKey::ALL {
            assert_eq!(MeshConfigKey::from_wire(k.wire_name()), Some(k));
            assert_eq!(MeshConfigKey::from_dimension(&k.dimension()), Some(k));
            assert!(k.dimension().starts_with(DIMENSION_PREFIX));
            assert!(k.dimension().ends_with(DIMENSION_SUFFIX));
            assert!(
                k.in_domain(k.owner_default()),
                "{k}'s owner_default is outside its own domain"
            );
        }
        // Not registered ⇒ not nameable. The whole of rule 2.
        for unknown in [
            "totally.made.up",
            "",
            "redundancy",
            "redundancy.k_repair_target ",
        ] {
            assert!(MeshConfigKey::from_wire(unknown).is_none(), "{unknown:?}");
        }
        assert!(MeshConfigKey::from_dimension("mesh_config:nope:v1").is_none());
        assert!(MeshConfigKey::from_dimension("quarantine:withheld:v1").is_none());
        // Serde honours the closure in BOTH directions.
        let json = serde_json::to_string(&MeshConfigKey::AntientropyRoundSecs).unwrap();
        assert_eq!(json, "\"antientropy.round_secs\"");
        assert!(serde_json::from_str::<MeshConfigKey>("\"nope\"").is_err());
    }

    /// Every registered key names a consumer AND a knob, and no two keys drive
    /// the same knob — two keys on one knob is a disagreement waiting for
    /// whichever fold ran last.
    #[test]
    fn every_registered_key_names_a_distinct_consumer_knob() {
        use std::collections::BTreeSet;
        let mut pairs: BTreeSet<(&str, &str)> = BTreeSet::new();
        let mut names: BTreeSet<&str> = BTreeSet::new();
        for &k in MeshConfigKey::ALL {
            let s = k.spec();
            assert!(!s.consumer.is_empty(), "{k} names no consumer processor");
            assert!(!s.knob.is_empty(), "{k} names no knob");
            assert!(
                pairs.insert((s.consumer, s.knob)),
                "{k} shares consumer knob ({}, {}) with another key",
                s.consumer,
                s.knob
            );
            assert!(names.insert(s.wire_name), "duplicate wire name for {k}");
            assert!(s.min <= s.max, "{k} has an empty domain");
        }
    }

    /// Every key is reachable through the PUBLIC fold surface. Guards the
    /// "code-path-exists ≠ host-reachable" class: a registered key a consumer
    /// cannot read is a key that does not exist.
    #[test]
    fn every_registered_key_is_reachable_through_the_public_fold() {
        let fold = fold_mesh_config(
            "n",
            &MeshConfigBaseline::owner_defaults(),
            &[],
            &[],
            ts(NOW),
        );
        assert_eq!(fold.settings.len(), MeshConfigKey::ALL.len());
        for &k in MeshConfigKey::ALL {
            let s = fold.setting(k).unwrap_or_else(|| panic!("{k} absent"));
            assert_eq!(s.effective, k.owner_default());
            assert_eq!(fold.effective(k), k.owner_default());
            assert!(!s.relieved);
        }
    }

    /// **The reading of CC 4.2.1 rule 3, pinned in one place with the clause
    /// quoted.**
    ///
    /// > **(3) Emergency relief is TTL-bounded** — threshold-1 on the announce
    /// > carrier, TTL ≤ 72 h, not renewable back-to-back by the same holder;
    /// > **durable** settings require the root's own quorum ratifying the
    /// > emergency's `payload_sha256`.
    /// >
    /// > **(4)** The halt asymmetry is deliberate: relief expires **because it
    /// > is unilateral**; the halt carries no TTL because its exit is the named
    /// > resumption.
    ///
    /// The clause is genuinely ambiguous and this module takes a side: the TTL
    /// attaches to **threshold-1**, per rule 4's own stated reason, so what
    /// earns durability is QUORUM and not having-been-exercised. The full
    /// argument — including the honest counter, that *"**the** emergency's
    /// `payload_sha256`"* presupposes an emergency — is on
    /// [`MeshConfigForm::Durable`].
    ///
    /// This test exists so that reading is a **named artifact** rather than a
    /// property scattered across the door's branches. It asserts the shape in
    /// both directions and cites the sentence, so if CC ever disambiguates —
    /// either way — there is one place to come and one thing to change. A
    /// reading of ambiguous text should never sit in a doc comment looking
    /// settled.
    ///
    /// The three-backend executed witness is
    /// `mesh_config_door_and_fold_*` step 2b; this is the statement of what
    /// that step is testing and why.
    #[test]
    fn cc_421_rule_3_is_read_as_unilateral_not_unexercised() {
        // The reading, as three claims about the refusal taxonomy that only
        // hold under it.
        //
        // 1. There is a refusal for a UNILATERAL durable act…
        assert_eq!(
            MeshConfigRefusalReason::DurableWithoutRootQuorum.as_str(),
            "durable_without_root_quorum",
            "the cold-durable refusal is named for the ABSENCE OF QUORUM. Under the strict \
             reading it would be named for the absence of a prior emergency, and there would be \
             no cold-durable door at all."
        );
        // 2. …and it is DISTINCT from the conversion-path refusal, because the
        //    two doors judge different things. One token for both would make a
        //    consumer unable to tell "you acted alone" from "the emergency you
        //    named does not exist".
        assert_ne!(
            MeshConfigRefusalReason::DurableWithoutRootQuorum.as_str(),
            MeshConfigRefusalReason::DurableUnratified.as_str()
        );
        // 3. The emergency form still carries the TTL, and the durable form
        //    still does not — which is the half of rule 3 that is NOT in
        //    dispute, and the half the reading has to preserve.
        assert_eq!(EMERGENCY_MAX_TTL_HOURS, 72, "CC 4.2.1 rule 3 states 72h");
        assert_eq!(MeshConfigForm::Emergency.as_str(), "emergency");
        assert_eq!(MeshConfigForm::Durable.as_str(), "durable");
    }

    /// The refusal tokens are the downstream contract: stable, unique, and
    /// identical to their serde spelling.
    #[test]
    fn refusal_tokens_match_serde_and_are_unique() {
        let mut tokens: Vec<&str> = MeshConfigRefusalReason::ALL
            .iter()
            .map(MeshConfigRefusalReason::as_str)
            .collect();
        for reason in MeshConfigRefusalReason::ALL {
            let json = serde_json::to_string(reason).expect("serialize");
            assert_eq!(json, format!("\"{}\"", reason.as_str()));
            assert_eq!(reason.to_string(), reason.as_str());
        }
        tokens.sort_unstable();
        let n = tokens.len();
        tokens.dedup();
        assert_eq!(tokens.len(), n, "duplicate refusal token");
    }

    // ══════════════════════════════════════════════════════════════════
    // relieve-never-expand (CC 4.2.1 rule 1)
    // ══════════════════════════════════════════════════════════════════

    /// **The polarity table is right**, key by key, in both directions. This is
    /// the fact both ratified rules are computed from, so it is asserted
    /// against the ENGLISH meaning of each key rather than against itself.
    #[test]
    fn flow_polarity_matches_what_each_knob_actually_does() {
        use MeshConfigKey as K;
        // Higher = more flow.
        for (k, more, less) in [
            (K::RedundancyKRepairTarget, 20, 10),
            (K::RedundancyMinViableFloor, 6, 3),
            (K::AntientropyPageLimit, 500, 100),
            (K::FeatureAvStreams, 1, 0),
            (K::FeatureTraceReplication, 1, 0),
            (K::AdmissionRatePerKey, 600, 60),
        ] {
            assert_eq!(k.polarity(), FlowPolarity::HigherMeansMoreFlow, "{k}");
            assert_eq!(k.more_restrictive_of(more, less), less, "{k}");
            assert!(
                k.expands_beyond(more, less),
                "{k}: {more} expands past {less}"
            );
            assert!(!k.expands_beyond(less, more), "{k}");
        }
        // LOWER = more flow. These four are why the fold cannot be a min().
        for (k, more, less) in [
            (K::AntientropyRoundSecs, 30, 300),
            (K::BackpressureSummaryOnly, 0, 1),
            (K::DescentPressureMultiplier, 100, 400),
        ] {
            assert_eq!(k.polarity(), FlowPolarity::LowerMeansMoreFlow, "{k}");
            assert_eq!(k.more_restrictive_of(more, less), less, "{k}");
            assert!(
                k.expands_beyond(more, less),
                "{k}: {more} expands past {less}"
            );
            assert!(!k.expands_beyond(less, more), "{k}");
        }
    }

    /// **`more_restrictive_of` and `expands_beyond` are ONE predicate.** Rule
    /// #9. Checked exhaustively over every key and a dense value grid, so the
    /// two ratified rules cannot come to disagree about which way a key points.
    #[test]
    fn the_two_rules_are_computed_from_one_predicate() {
        for &k in MeshConfigKey::ALL {
            let s = k.spec();
            let step = ((s.max - s.min) / 17).max(1);
            let mut a = s.min;
            while a <= s.max {
                let mut b = s.min;
                while b <= s.max {
                    let tight = k.more_restrictive_of(a, b);
                    // The definitional relationship.
                    assert_eq!(
                        k.expands_beyond(a, b),
                        a != b && tight == b,
                        "{k}: expands_beyond({a},{b}) disagrees with more_restrictive_of"
                    );
                    // Commutative + idempotent — the properties order-independence rests on.
                    assert_eq!(tight, k.more_restrictive_of(b, a), "{k}: not commutative");
                    assert_eq!(k.more_restrictive_of(a, a), a, "{k}: not idempotent");
                    // Exactly one of the two can expand past the other.
                    assert!(
                        !(k.expands_beyond(a, b) && k.expands_beyond(b, a)),
                        "{k}: {a} and {b} each expand past the other"
                    );
                    // The clamp is the predicate's own consequence.
                    assert_eq!(
                        k.clamp_to_consent(a, b),
                        if k.expands_beyond(a, b) { b } else { a },
                        "{k}"
                    );
                    b = b.saturating_add(step);
                }
                a = a.saturating_add(step);
            }
        }
    }

    /// **The witness.** A root asks for MORE than the node consented to, on
    /// each polarity arm, and the fold clamps — never returning a value that
    /// means more flow than the baseline, and naming the root that tried.
    #[test]
    fn a_root_cannot_expand_past_what_the_node_consented_to() {
        use MeshConfigKey as K;
        let base = MeshConfigBaseline::owner_defaults()
            .with(K::RedundancyKRepairTarget, 10)
            .with(K::AntientropyRoundSecs, 300);
        let roots = vec!["root-a".to_owned()];
        let rows = vec![
            // HigherMeansMoreFlow: 40 copies is MORE than the 10 consented.
            row(
                "m-expand-hi",
                "root-a",
                "root-a",
                K::RedundancyKRepairTarget,
                40,
                "2026-08-03T10:00:00Z",
                None,
            ),
            // LowerMeansMoreFlow: a 5-second round is MORE gossip than 300.
            row(
                "m-expand-lo",
                "root-a",
                "root-a",
                K::AntientropyRoundSecs,
                5,
                "2026-08-03T10:00:00Z",
                None,
            ),
        ];
        let fold = fold_mesh_config("node-1", &base, &roots, &rows, ts(NOW));

        let hi = fold.setting(K::RedundancyKRepairTarget).unwrap();
        assert_eq!(hi.effective, 10, "clamped to consent, not raised to 40");
        assert!(!hi.relieved);
        assert_eq!(hi.clamped_roots, vec!["root-a".to_owned()]);
        // The ASK is still visible — evidence, not erasure.
        assert_eq!(hi.per_root[0].asked, 40);
        assert!(hi.per_root[0].clamped);

        let lo = fold.setting(K::AntientropyRoundSecs).unwrap();
        assert_eq!(lo.effective, 300, "clamped; 5s would be MORE gossip");
        assert_eq!(lo.clamped_roots, vec!["root-a".to_owned()]);
        assert_eq!(lo.per_root[0].asked, 5);
    }

    /// The relief direction is NOT blocked — a plane that refused everything
    /// would pass the invariant and be useless. #570's headline case: 20 → 10.
    #[test]
    fn relief_is_admitted_and_binds() {
        use MeshConfigKey as K;
        let base = MeshConfigBaseline::owner_defaults(); // k_repair_target = 20
        let roots = vec!["root-a".to_owned()];
        let rows = vec![row(
            "m-relief",
            "root-a",
            "root-a",
            K::RedundancyKRepairTarget,
            10,
            "2026-08-03T10:00:00Z",
            None,
        )];
        let fold = fold_mesh_config("node-1", &base, &roots, &rows, ts(NOW));
        let s = fold.setting(K::RedundancyKRepairTarget).unwrap();
        assert_eq!(s.baseline, 20);
        assert_eq!(s.effective, 10, "#570's headline: 20 copies to 10");
        assert!(s.relieved);
        assert_eq!(s.decided_by_root.as_deref(), Some("root-a"));
        assert_eq!(s.decided_by.as_deref(), Some("root-a"));
        assert_eq!(s.delegation_id.as_deref(), Some("att-deleg"));
        assert!(s.clamped_roots.is_empty());
    }

    /// The most-flow end of a key's domain — the value a hostile root asks for.
    fn most_flow_value(k: MeshConfigKey) -> i64 {
        let s = k.spec();
        match k.polarity() {
            FlowPolarity::HigherMeansMoreFlow => s.max,
            FlowPolarity::LowerMeansMoreFlow => s.min,
        }
    }

    /// The least-flow end — the baseline this adversarial test pins, so that
    /// EVERY other value in the domain expands past it on every key.
    ///
    /// A midpoint would have been more realistic and is wrong here: the four
    /// `Flag` keys have domain `[0, 1]`, whose midpoint is `0`, which is
    /// already the most-flow end for `backpressure.summary_only`. A baseline a
    /// root cannot expand past makes the clamp unreachable for that key — the
    /// test would pass by having nothing to test, which is how a property test
    /// quietly stops being one.
    fn least_flow_value(k: MeshConfigKey) -> i64 {
        let s = k.spec();
        match k.polarity() {
            FlowPolarity::HigherMeansMoreFlow => s.min,
            FlowPolarity::LowerMeansMoreFlow => s.max,
        }
    }

    /// **The total property, against an adversary that is actually trying.**
    ///
    /// Every key, three roots, values swept across each whole domain — and, per
    /// `(root, key)`, the **newest** row is pinned to the most-flow extreme of
    /// the domain, so every root's winning value expands past the baseline. The
    /// fold's `effective` must still never mean more flow than the baseline,
    /// and neither must any per-root contribution.
    ///
    /// The "newest row is the worst row" construction is not decoration. An
    /// earlier version of this test swept values at uniform timestamps and
    /// **passed with the relieve-never-expand clamp deleted**, because step 4
    /// seeds the cross-root fold from `baseline` and therefore bounds
    /// `effective` on its own. That made the test a witness for a property the
    /// fold had two reasons to satisfy, which is a witness for neither. It now
    /// forces the clamp to be the thing that holds — see
    /// `clamped_roots` below, which is the half step 4 cannot supply.
    #[test]
    fn no_row_set_from_any_roots_can_ever_expand_the_effective_value() {
        let roots: Vec<String> = vec!["r-a".into(), "r-b".into(), "r-c".into()];
        let mut rows: Vec<Attestation> = Vec::new();
        let mut base = MeshConfigBaseline::owner_defaults();
        let mut n = 0usize;
        for &k in MeshConfigKey::ALL {
            let s = k.spec();
            // The node consents to the LEAST flow the key can express, so every
            // other value in the domain expands past it — see
            // `least_flow_value` for why a midpoint would silently disarm the
            // four Flag keys.
            base = base.with(k, least_flow_value(k));
            for (ri, root) in roots.iter().enumerate() {
                for step in 0..5i64 {
                    let v = s.min + (s.max - s.min) * step / 4;
                    n += 1;
                    rows.push(row(
                        &format!("m{n}"),
                        root,
                        root,
                        k,
                        v,
                        // Deliberately colliding timestamps across roots and
                        // rows: the tie-break must be exercised, not avoided.
                        if (ri + step as usize) % 2 == 0 {
                            "2026-08-03T10:00:00Z"
                        } else {
                            "2026-08-03T11:00:00Z"
                        },
                        None,
                    ));
                }
                // …and the NEWEST row this root holds asks for the most flow
                // the domain allows. Every root's winner therefore expands.
                n += 1;
                rows.push(row(
                    &format!("m{n}-greedy"),
                    root,
                    root,
                    k,
                    most_flow_value(k),
                    "2026-08-03T11:30:00Z",
                    None,
                ));
            }
        }
        let fold = fold_mesh_config("node-1", &base, &roots, &rows, ts(NOW));
        for s in &fold.settings {
            assert!(
                !s.key.expands_beyond(s.effective, s.baseline),
                "CC 4.2.1 rule 1 VIOLATED for {}: effective {} expands past baseline {} \
                 (polarity {:?})",
                s.key,
                s.effective,
                s.baseline,
                s.polarity
            );
            // Every per-root contribution is likewise bounded. This is the
            // assertion the clamp is load-bearing for: step 4 bounds
            // `effective`, but nothing but the clamp bounds what a single root
            // contributes or what the fold REPORTS that root as contributing.
            for rv in &s.per_root {
                assert!(
                    !s.key.expands_beyond(rv.effective, s.baseline),
                    "{} root {} contributed an expanding value ({} asked, {} effective, baseline \
                     {})",
                    s.key,
                    rv.root_ref,
                    rv.asked,
                    rv.effective,
                    s.baseline
                );
            }
            // Every root here is greedy by construction, so every root must be
            // NAMED as clamped. A fold that quietly dropped the expanding rows
            // instead of clamping them would satisfy the bounds above and lose
            // the evidence a compromised-root review reads.
            assert_eq!(
                s.clamped_roots, roots,
                "{}: every root's newest row asks for the most-flow extreme, so every root must \
                 be reported clamped",
                s.key
            );
            assert_eq!(
                s.effective, s.baseline,
                "{}: with every root expanding, nothing may move the node off its own baseline",
                s.key
            );
            assert!(!s.relieved, "{}", s.key);
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // most-restrictive-across-roots (CC 4.2.1 rule 2)
    // ══════════════════════════════════════════════════════════════════

    /// **The disagreeing-roots case, on BOTH polarity arms.** Two roots ask for
    /// different values; the tighter binds. A fold taking the last root, the
    /// first root, or the min would each fail at least one of these four.
    #[test]
    fn when_roots_disagree_the_tightest_binding_wins() {
        use MeshConfigKey as K;
        let base = MeshConfigBaseline::owner_defaults();
        let roots = vec!["root-a".to_owned(), "root-b".to_owned()];

        // HigherMeansMoreFlow — tighter is SMALLER. `root-b` (the LATER root
        // alphabetically, and the later row) asks for the LOOSER value, so a
        // "last root wins" fold answers 15 here.
        // LowerMeansMoreFlow — tighter is LARGER. `root-a` asks for the looser
        // value, so a "first root wins" fold answers 30 here, and a fold that
        // took the min over every key answers 30 too.
        let rows = vec![
            row(
                "m1",
                "root-a",
                "root-a",
                K::RedundancyKRepairTarget,
                8,
                "2026-08-03T10:00:00Z",
                None,
            ),
            row(
                "m2",
                "root-b",
                "root-b",
                K::RedundancyKRepairTarget,
                15,
                "2026-08-03T11:00:00Z",
                None,
            ),
            row(
                "m3",
                "root-a",
                "root-a",
                K::AntientropyRoundSecs,
                30,
                "2026-08-03T11:00:00Z",
                None,
            ),
            row(
                "m4",
                "root-b",
                "root-b",
                K::AntientropyRoundSecs,
                600,
                "2026-08-03T10:00:00Z",
                None,
            ),
        ];
        let fold = fold_mesh_config("node-1", &base, &roots, &rows, ts(NOW));

        let hi = fold.setting(K::RedundancyKRepairTarget).unwrap();
        assert_eq!(
            hi.effective, 8,
            "most-restrictive: 8 copies is tighter than 15. Answering 15 means the fold took the \
             LAST root (m2 is newer) or the last-seen root."
        );
        assert_eq!(hi.decided_by_root.as_deref(), Some("root-a"));
        assert_eq!(hi.per_root.len(), 2, "both roots' answers are carried");

        let lo = fold.setting(K::AntientropyRoundSecs).unwrap();
        assert_eq!(
            lo.effective, 600,
            "most-restrictive on a LowerMeansMoreFlow key is the LARGER value: 600s between \
             rounds is less gossip than 30s. Answering 30 means the fold took the first root, the \
             newest row across roots, or a blanket min()."
        );
        assert_eq!(lo.decided_by_root.as_deref(), Some("root-b"));
        // Both roots' asks survive for audit.
        let asked: Vec<i64> = lo.per_root.iter().map(|r| r.asked).collect();
        assert_eq!(asked, vec![30, 600]);
    }

    /// **Most-restrictive is FORCED, not preferred** (CC 4.2.1's own emphasis):
    /// there is no baseline, no key spec and no local option that selects the
    /// permissive branch. The node cannot opt into the looser root even by
    /// pinning its baseline there.
    #[test]
    fn a_node_cannot_choose_the_permissive_root_even_deliberately() {
        use MeshConfigKey as K;
        // The node pins its OWN baseline at the loose root's value.
        let base = MeshConfigBaseline::owner_defaults().with(K::RedundancyKRepairTarget, 15);
        let roots = vec!["root-loose".to_owned(), "root-tight".to_owned()];
        let rows = vec![
            row(
                "m1",
                "root-loose",
                "root-loose",
                K::RedundancyKRepairTarget,
                15,
                "2026-08-03T11:00:00Z",
                None,
            ),
            row(
                "m2",
                "root-tight",
                "root-tight",
                K::RedundancyKRepairTarget,
                4,
                "2026-08-03T10:00:00Z",
                None,
            ),
        ];
        let fold = fold_mesh_config("node-1", &base, &roots, &rows, ts(NOW));
        let s = fold.setting(K::RedundancyKRepairTarget).unwrap();
        assert_eq!(
            s.effective, 4,
            "the tight root binds regardless of the node's own preference — CC 4.2.1: \
             most-restrictive-across-roots is forced, not advisory"
        );
        assert_eq!(s.decided_by_root.as_deref(), Some("root-tight"));
    }

    /// **The order-independence proof.** Every permutation of the roots, and a
    /// reversed row vector, must produce the byte-identical fold. This is the
    /// executed form of "a fold that takes the LAST root, or the FIRST, is the
    /// defect".
    #[test]
    fn the_fold_is_invariant_under_every_permutation_of_the_roots() {
        use MeshConfigKey as K;
        let base = MeshConfigBaseline::owner_defaults();
        let roots = ["r1".to_owned(), "r2".to_owned(), "r3".to_owned()];
        let rows = vec![
            row(
                "a",
                "r1",
                "r1",
                K::RedundancyKRepairTarget,
                12,
                "2026-08-03T10:00:00Z",
                None,
            ),
            row(
                "b",
                "r2",
                "r2",
                K::RedundancyKRepairTarget,
                6,
                "2026-08-03T11:00:00Z",
                None,
            ),
            row(
                "c",
                "r3",
                "r3",
                K::RedundancyKRepairTarget,
                18,
                "2026-08-03T09:00:00Z",
                None,
            ),
            row(
                "d",
                "r1",
                "r1",
                K::AntientropyRoundSecs,
                120,
                "2026-08-03T09:00:00Z",
                None,
            ),
            row(
                "e",
                "r2",
                "r2",
                K::AntientropyRoundSecs,
                900,
                "2026-08-03T10:00:00Z",
                None,
            ),
            row(
                "f",
                "r3",
                "r3",
                K::BackpressureSummaryOnly,
                1,
                "2026-08-03T10:00:00Z",
                None,
            ),
        ];
        let expected = fold_mesh_config("n", &base, &roots, &rows, ts(NOW));
        assert_eq!(expected.effective(K::RedundancyKRepairTarget), 6);
        assert_eq!(expected.effective(K::AntientropyRoundSecs), 900);
        assert!(expected.flag(K::BackpressureSummaryOnly));

        // All 6 permutations of the roots × forward/reversed rows.
        let perms: [[usize; 3]; 6] = [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ];
        let mut reversed = rows.clone();
        reversed.reverse();
        for p in perms {
            let permuted: Vec<String> = p.iter().map(|&i| roots[i].clone()).collect();
            for row_order in [&rows, &reversed] {
                let got = fold_mesh_config("n", &base, &permuted, row_order, ts(NOW));
                assert_eq!(
                    got, expected,
                    "the fold depends on ROOT ORDER (permutation {p:?}) or on ROW ORDER — \
                     most-restrictive must be a commutative combine, not a scan that keeps the \
                     last or first answer"
                );
            }
        }
    }

    /// At a tie WITHIN a root — same instant, two values — the more restrictive
    /// wins. The only recoverable direction: a relaxation lost to a tie-break
    /// can be re-asserted; a relaxation WON by one cannot be taken back.
    #[test]
    fn a_same_instant_collision_resolves_toward_restriction() {
        use MeshConfigKey as K;
        let base = MeshConfigBaseline::owner_defaults();
        let roots = vec!["r".to_owned()];
        // Same author, same root, same instant, opposite intents — the shape a
        // hostile author constructs to let each node pick its own answer.
        let rows = vec![
            row(
                "zzz-loose",
                "r",
                "r",
                K::RedundancyKRepairTarget,
                20,
                "2026-08-03T10:00:00Z",
                None,
            ),
            row(
                "aaa-tight",
                "r",
                "r",
                K::RedundancyKRepairTarget,
                5,
                "2026-08-03T10:00:00Z",
                None,
            ),
        ];
        let fold = fold_mesh_config("n", &base, &roots, &rows, ts(NOW));
        assert_eq!(
            fold.effective(K::RedundancyKRepairTarget),
            5,
            "restriction must win a same-instant tie; picking by attestation_id would answer 20 \
             for `aaa-tight` < `zzz-loose`"
        );
        // Reversed input order: same answer.
        let mut rev = rows.clone();
        rev.reverse();
        assert_eq!(
            fold_mesh_config("n", &base, &roots, &rev, ts(NOW))
                .effective(K::RedundancyKRepairTarget),
            5
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // TTL — "TTL-expired rows drop at read time"
    // ══════════════════════════════════════════════════════════════════

    /// An expired relief stops applying **at read time**, with no revocation,
    /// no author and no write. And a future-dated row has not started.
    #[test]
    fn ttl_expired_rows_drop_at_read_time_and_future_rows_have_not_started() {
        use MeshConfigKey as K;
        let base = MeshConfigBaseline::owner_defaults();
        let roots = vec!["r".to_owned()];
        let rows = vec![
            // Emergency relief that expired an hour ago.
            row(
                "m-expired",
                "r",
                "r",
                K::RedundancyKRepairTarget,
                4,
                "2026-08-03T09:00:00Z",
                Some("2026-08-03T11:00:00Z"),
            ),
            // Relief that has not been asserted yet.
            row(
                "m-future",
                "r",
                "r",
                K::AntientropyRoundSecs,
                3600,
                "2026-08-04T00:00:00Z",
                None,
            ),
        ];
        let fold = fold_mesh_config("n", &base, &roots, &rows, ts(NOW));
        assert_eq!(
            fold.effective(K::RedundancyKRepairTarget),
            K::RedundancyKRepairTarget.owner_default(),
            "an expired emergency must stop binding without anyone revoking it"
        );
        assert_eq!(
            fold.effective(K::AntientropyRoundSecs),
            K::AntientropyRoundSecs.owner_default(),
            "a future-dated row has not taken effect"
        );
        assert!(fold
            .setting(K::RedundancyKRepairTarget)
            .unwrap()
            .per_root
            .is_empty());

        // Wound back one hour, the SAME row set binds — proving the drop is
        // the TTL and not a parse failure.
        let earlier = fold_mesh_config("n", &base, &roots, &rows, ts("2026-08-03T10:00:00Z"));
        assert_eq!(earlier.effective(K::RedundancyKRepairTarget), 4);
        assert_eq!(
            earlier
                .setting(K::RedundancyKRepairTarget)
                .unwrap()
                .form
                .unwrap(),
            MeshConfigForm::Emergency
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // Shape parsing
    // ══════════════════════════════════════════════════════════════════

    /// A row whose dimension and `mesh_config_key` disagree is refused rather
    /// than resolved toward either — the same call
    /// `trust_root::job_dimension_admits` makes about a mislabelled row.
    #[test]
    fn a_row_whose_two_self_descriptions_disagree_does_not_fold() {
        use MeshConfigKey as K;
        let mut r = row(
            "m",
            "r",
            "r",
            K::RedundancyKRepairTarget,
            5,
            "2026-08-03T10:00:00Z",
            None,
        );
        r.attestation_envelope[field::KEY] =
            serde_json::Value::String(K::AdmissionRatePerKey.wire_name().to_owned());
        let fold = fold_mesh_config(
            "n",
            &MeshConfigBaseline::owner_defaults(),
            &["r".to_owned()],
            std::slice::from_ref(&r),
            ts(NOW),
        );
        assert_eq!(
            fold.effective(K::RedundancyKRepairTarget),
            K::RedundancyKRepairTarget.owner_default()
        );
        assert_eq!(
            fold.effective(K::AdmissionRatePerKey),
            K::AdmissionRatePerKey.owner_default()
        );
    }

    /// Out-of-domain values do not fold, and a row from a root the node does
    /// not subscribe to is not folded at all.
    #[test]
    fn out_of_domain_values_and_unsubscribed_roots_do_not_fold() {
        use MeshConfigKey as K;
        let base = MeshConfigBaseline::owner_defaults();
        let rows = vec![
            row(
                "m-oob",
                "r",
                "r",
                K::AntientropyRoundSecs,
                0,
                "2026-08-03T10:00:00Z",
                None,
            ),
            row(
                "m-stranger",
                "x",
                "x",
                K::RedundancyKRepairTarget,
                1,
                "2026-08-03T10:00:00Z",
                None,
            ),
        ];
        // `min` for round_secs is 1, so 0 is out of domain.
        assert!(!K::AntientropyRoundSecs.in_domain(0));
        let fold = fold_mesh_config("n", &base, &["r".to_owned()], &rows, ts(NOW));
        assert_eq!(
            fold.effective(K::AntientropyRoundSecs),
            K::AntientropyRoundSecs.owner_default()
        );
        assert_eq!(
            fold.effective(K::RedundancyKRepairTarget),
            K::RedundancyKRepairTarget.owner_default(),
            "root `x` is not in the node's subscription set, so it says nothing to this node"
        );
        assert_eq!(fold.roots, vec!["r".to_owned()]);
    }

    /// A present-but-garbled `valid_until` must not read as "no TTL" — that
    /// would make a malformed emergency row immortal.
    #[test]
    fn an_unparseable_ttl_is_a_refusal_not_an_absent_one() {
        use MeshConfigKey as K;
        let mut r = row(
            "m",
            "r",
            "r",
            K::RedundancyKRepairTarget,
            5,
            "2026-08-03T10:00:00Z",
            Some("2026-08-03T20:00:00Z"),
        );
        r.attestation_envelope[field::VALID_UNTIL] =
            serde_json::Value::String("not-a-timestamp".to_owned());
        let fold = fold_mesh_config(
            "n",
            &MeshConfigBaseline::owner_defaults(),
            &["r".to_owned()],
            std::slice::from_ref(&r),
            ts(NOW),
        );
        assert_eq!(
            fold.effective(K::RedundancyKRepairTarget),
            K::RedundancyKRepairTarget.owner_default(),
            "a garbled TTL must drop the row, not grant it eternal life"
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // The executed door — every backend persist ships
    // ══════════════════════════════════════════════════════════════════

    /// Register a key with its REAL deterministic hybrid pubkeys.
    async fn register(dir: &dyn FederationDirectory, key_id: &str) {
        crate::federation::tier_ingest::test_support::register_hybrid_key(dir, key_id).await;
    }

    /// A really-hybrid-signed `delegates_to` carrying a `trust:*` job label.
    fn trust_edge(id: &str, from: &str, to: &str, job: &str) -> Attestation {
        let envelope = serde_json::json!({
            "dimension": job,
            "scope": ["infra:attest", "infra:serve"],
        });
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(from, &envelope);
        let now = Utc::now();
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: from.to_owned(),
            attested_key_id: to.to_owned(),
            attestation_type: attestation_type::DELEGATES_TO.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: sc,
            scrub_signature_pqc: sp,
            scrub_key_id: from.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// A really-hybrid-signed mesh-config row, ready for the real door.
    #[allow(clippy::too_many_arguments)]
    fn signed_config_row(
        author: &str,
        root: &str,
        key: MeshConfigKey,
        value: i64,
        form: MeshConfigForm,
        asserted_at: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        ratifies: Option<&str>,
        delegation_id: &str,
    ) -> Attestation {
        let envelope = mesh_config_envelope(
            key,
            value,
            root,
            form,
            valid_until,
            delegation_id,
            ratifies,
            "congestion",
        );
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(author, &envelope);
        Attestation {
            // UUID, not a slug: postgres types `attestation_id` as `uuid` and
            // rejects anything else at the driver.
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: author.to_owned(),
            attested_key_id: root.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: sc,
            scrub_signature_pqc: sp,
            scrub_key_id: author.to_owned(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// **The whole plane, driven through the REAL doors, on one backend.**
    ///
    /// Every gate below runs against rows that were actually stored by
    /// `put_attestation` and read back by `list_attestations_*` — never against
    /// a hand-built `Error`. The "code-path-exists ≠ host-reachable" class this
    /// repo has been bitten by repeatedly is what this exists to close.
    ///
    /// The shape: one node, TWO trust roots it has live edges to, one key each
    /// root has conferred to, and one root the node has NOT subscribed to.
    async fn mesh_config_door_body(dir: &dyn FederationDirectory, tag: &str) {
        use MeshConfigKey as K;
        let node = format!("mc-node-{tag}");
        let root_a = format!("mc-root-a-{tag}");
        let root_b = format!("mc-root-b-{tag}");
        let delegate = format!("mc-deleg-{tag}");
        let stranger = format!("mc-stranger-{tag}");
        let outsider = format!("mc-outsider-{tag}");
        for k in [&node, &root_a, &root_b, &delegate, &stranger, &outsider] {
            register(dir, k).await;
        }

        // The node's SUBSCRIPTION: live trust edges to two roots, and none to
        // `stranger`. CC 4.2.1: "the trust edge is the subscription."
        for (i, root) in [&root_a, &root_b].iter().enumerate() {
            dir.put_attestation(super::super::SignedAttestation {
                attestation: trust_edge(
                    &uuid::Uuid::new_v4().to_string(),
                    &node,
                    root,
                    crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
                ),
            })
            .await
            .unwrap_or_else(|e| panic!("[{tag}] trust edge {i} must admit: {e}"));
        }
        // root_a confers config authority on `delegate` — the CC 3.2
        // delegation plane CC 4.2.1 names verbatim.
        dir.put_attestation(super::super::SignedAttestation {
            attestation: trust_edge(
                &uuid::Uuid::new_v4().to_string(),
                &root_a,
                &delegate,
                crate::federation::trust_root::TRUST_CONFERS_DIMENSION,
            ),
        })
        .await
        .unwrap_or_else(|e| panic!("[{tag}] conferral must admit: {e}"));

        let now = Utc::now();
        let base = MeshConfigBaseline::owner_defaults();
        /// The REAL door. A policy refusal comes back as `Refused`; anything
        /// else is a bug in the test's fixture, so it panics rather than being
        /// silently read as a refusal.
        async fn door(
            dir: &dyn FederationDirectory,
            node: &str,
            base: &MeshConfigBaseline,
            row: Attestation,
            now: DateTime<Utc>,
            tag: &str,
        ) -> MeshConfigOutcome {
            record_mesh_config_row(dir, node, base, &row, now)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] door errored rather than refusing: {e}"))
        }
        macro_rules! door {
            ($row:expr) => {
                door(dir, &node, &base, $row, now, tag).await
            };
        }

        // ── 1. THE HAPPY PATH: the root itself relieves. #570's headline,
        //       "20 copies -> 10", in the form CC 4.2.1 gives a single holder:
        //       bounded emergency relief.
        let relief = signed_config_row(
            &root_a,
            &root_a,
            K::RedundancyKRepairTarget,
            10,
            MeshConfigForm::Emergency,
            now - Duration::hours(1),
            Some(now + Duration::hours(24)),
            None,
            "att-deleg",
        );
        assert_eq!(
            door!(relief.clone()),
            MeshConfigOutcome::Admitted,
            "[{tag}] 20 copies -> 10 is relief and must admit"
        );

        // ── 2. THE CONFERRED AUTHOR: a key the root delegated to.
        let by_delegate = signed_config_row(
            &delegate,
            &root_a,
            K::AntientropyRoundSecs,
            600,
            MeshConfigForm::Emergency,
            now - Duration::hours(1),
            Some(now + Duration::hours(24)),
            None,
            "att-deleg",
        );
        assert_eq!(
            door!(by_delegate),
            MeshConfigOutcome::Admitted,
            "[{tag}] a live trust:confers:v1 grant is the CC 3.2 delegation plane CC 4.2.1 names"
        );

        // ── 2b. **CC 4.2.1 RULE 3, THE READ THAT MATTERS.** A COLD durable
        //        row — no prior emergency — turns on whether the act is
        //        UNILATERAL, not on whether it was exercised. `root_a` is a
        //        single-key root, so signing for itself IS its whole quorum
        //        and this admits; the conferred delegate is refused, because a
        //        delegation is threshold-1 and rule 4 says threshold-1
        //        expires. See `MeshConfigForm::Durable` for the argument that
        //        overturned the stricter reading.
        let cold_durable_by_root = signed_config_row(
            &root_a,
            &root_a,
            K::FeatureAvStreams,
            0,
            MeshConfigForm::Durable,
            now - Duration::hours(1),
            None,
            None,
            "att-deleg",
        );
        assert_eq!(
            door!(cold_durable_by_root),
            MeshConfigOutcome::Admitted,
            "[{tag}] a single-key root IS its own quorum (1-of-1), so a cold durable RESTRICTION \
             it signs for itself must admit. Refusing here makes a durable setting unreachable on \
             a fresh mesh until someone fires a 72h emergency to bootstrap one — the \
             circular-at-genesis class."
        );
        let cold_durable_by_delegate = signed_config_row(
            &delegate,
            &root_a,
            K::FeatureTraceReplication,
            0,
            MeshConfigForm::Durable,
            now - Duration::hours(1),
            None,
            None,
            "att-deleg",
        );
        assert_eq!(
            door!(cold_durable_by_delegate),
            MeshConfigOutcome::Refused {
                reason: MeshConfigRefusalReason::DurableWithoutRootQuorum
            },
            "[{tag}] a CONFERRED delegate acts at threshold-1, and CC 4.2.1 rule 4 says \
             threshold-1 expires. It may raise a bounded emergency; it may not make anything \
             permanent alone. That asymmetry is the whole bite of the cold-durable door."
        );

        // ── 3. Every refusal branch, on the real door. Each differs from an
        //       ADMITTED row in exactly one input.
        let refusals: Vec<(&str, Attestation, MeshConfigRefusalReason)> =
            vec![
            (
                "an unsubscribed root has nothing to say to this node",
                signed_config_row(&stranger, &stranger, K::AntientropyPageLimit, 50,
                    MeshConfigForm::Durable, now - Duration::hours(1), None, None, "att-deleg"),
                MeshConfigRefusalReason::RootNotTrusted,
            ),
            (
                "an author the root never conferred to",
                signed_config_row(&outsider, &root_a, K::AntientropyPageLimit, 50,
                    MeshConfigForm::Durable, now - Duration::hours(1), None, None, "att-deleg"),
                MeshConfigRefusalReason::AuthorNotRootAuthorized,
            ),
            (
                "relieve-never-expand at the door: 40 copies is MORE than the 20 consented",
                signed_config_row(&root_a, &root_a, K::RedundancyKRepairTarget, 40,
                    MeshConfigForm::Durable, now - Duration::hours(1), None, None, "att-deleg"),
                MeshConfigRefusalReason::ExpandsBeyondConsent,
            ),
            (
                "relieve-never-expand on the LowerMeansMoreFlow arm: 5s is MORE gossip than 60s",
                signed_config_row(&root_a, &root_a, K::AntientropyRoundSecs, 5,
                    MeshConfigForm::Durable, now - Duration::hours(1), None, None, "att-deleg"),
                MeshConfigRefusalReason::ExpandsBeyondConsent,
            ),
            (
                "emergency relief with no TTL is not relief, it is government",
                signed_config_row(&root_a, &root_a, K::AntientropyPageLimit, 50,
                    MeshConfigForm::Emergency, now - Duration::hours(1), None, None, "att-deleg"),
                MeshConfigRefusalReason::TtlMissing,
            ),
            (
                "an emergency window beyond 72h",
                signed_config_row(&root_a, &root_a, K::AntientropyPageLimit, 50,
                    MeshConfigForm::Emergency, now - Duration::hours(1),
                    Some(now + Duration::hours(100)), None, "att-deleg"),
                MeshConfigRefusalReason::TtlTooLong,
            ),
            (
                "an act that does not carry its own authority (#570 ask 3)",
                signed_config_row(&root_a, &root_a, K::AntientropyPageLimit, 50,
                    MeshConfigForm::Durable, now - Duration::hours(1), None, None, ""),
                MeshConfigRefusalReason::Unattributed,
            ),
            (
                "a durable row NAMING a ratification that resolves to nothing (distinct from a \
                 cold durable, which names none and is judged on quorum)",
                signed_config_row(&root_a, &root_a, K::AntientropyPageLimit, 50,
                    MeshConfigForm::Durable, now - Duration::hours(1), None,
                    Some("00000000-0000-0000-0000-000000000000"), "att-deleg"),
                MeshConfigRefusalReason::DurableUnratified,
            ),
            (
                "a value outside the key's declared domain",
                signed_config_row(&root_a, &root_a, K::AntientropyRoundSecs, 999_999,
                    MeshConfigForm::Durable, now - Duration::hours(1), None, None, "att-deleg"),
                MeshConfigRefusalReason::ValueOutOfDomain,
            ),
        ];
        for (why, row, expected) in refusals {
            let got = door!(row);
            assert_eq!(
                got,
                MeshConfigOutcome::Refused { reason: expected },
                "[{tag}] {why}"
            );
        }

        // ── 3b. The CLOSED REGISTRY (CC 4.2.1 rule 2). Hand-built envelope,
        //        because the typed builder cannot express an unregistered key —
        //        which is itself the point, but a wire row can, so the door
        //        must refuse it.
        let mut unknown = signed_config_row(
            &root_a,
            &root_a,
            K::AntientropyPageLimit,
            50,
            MeshConfigForm::Durable,
            now - Duration::hours(1),
            None,
            None,
            "att-deleg",
        );
        unknown.attestation_envelope["dimension"] =
            serde_json::Value::String("mesh_config:cluster.secret_knob:v1".to_owned());
        unknown.attestation_envelope[field::KEY] =
            serde_json::Value::String("cluster.secret_knob".to_owned());
        assert_eq!(
            door!(unknown),
            MeshConfigOutcome::Refused {
                reason: MeshConfigRefusalReason::UnknownKey
            },
            "[{tag}] CC 4.2.1 rule 2: a key naming no consumer processor cannot be set"
        );

        // ── 3c. Filed against something other than the root it names — the
        //        row the fold would never find.
        let mut misfiled = signed_config_row(
            &root_a,
            &root_a,
            K::AntientropyPageLimit,
            50,
            MeshConfigForm::Durable,
            now - Duration::hours(1),
            None,
            None,
            "att-deleg",
        );
        misfiled.attested_key_id = node.clone();
        assert_eq!(
            door!(misfiled),
            MeshConfigOutcome::Refused {
                reason: MeshConfigRefusalReason::NotFiledAgainstRoot
            },
            "[{tag}] a row the fold cannot find is not a row"
        );

        // ── 4. THE BACK-TO-BACK RENEWAL BAN (CC 4.2.1 rule 3). One emergency
        //       admits; a second from the SAME holder whose window opens before
        //       the first closes does not. "The emergency path must not become
        //       the government."
        let em1 = signed_config_row(
            &root_a,
            &root_a,
            K::AntientropyPageLimit,
            50,
            MeshConfigForm::Emergency,
            now - Duration::hours(2),
            Some(now + Duration::hours(24)),
            None,
            "att-deleg",
        );
        assert_eq!(
            door!(em1.clone()),
            MeshConfigOutcome::Admitted,
            "[{tag}] a bounded emergency relief must admit"
        );
        let em2 = signed_config_row(
            &root_a,
            &root_a,
            K::AntientropyPageLimit,
            40,
            MeshConfigForm::Emergency,
            now - Duration::hours(1),
            Some(now + Duration::hours(48)),
            None,
            "att-deleg",
        );
        assert_eq!(
            door!(em2),
            MeshConfigOutcome::Refused {
                reason: MeshConfigRefusalReason::BackToBackRenewal
            },
            "[{tag}] CC 4.2.1 rule 3: not renewable back-to-back by the same holder"
        );
        // The same holder CAN act again once the first window has closed —
        // the ban is on CHAINING, not on ever acting twice.
        let em3 = signed_config_row(
            &root_a,
            &root_a,
            K::AntientropyPageLimit,
            40,
            MeshConfigForm::Emergency,
            now + Duration::hours(25),
            Some(now + Duration::hours(48)),
            None,
            "att-deleg",
        );
        assert_eq!(
            door!(em3),
            MeshConfigOutcome::Admitted,
            "[{tag}] a fresh window after the last one closed is not a renewal"
        );

        // ── 5. THE DURABLE RATIFICATION (CC 4.2.1 rule 3). A durable row
        //       naming the emergency it makes permanent, at the same value.
        let durable = signed_config_row(
            &root_a,
            &root_a,
            K::AntientropyPageLimit,
            50,
            MeshConfigForm::Durable,
            now - Duration::hours(1),
            None,
            Some(&em1.attestation_id),
            "att-deleg",
        );
        assert_eq!(
            door!(durable),
            MeshConfigOutcome::Admitted,
            "[{tag}] a durable row ratifying a held emergency at the same value must admit"
        );

        // ── 6. THE READ SIDE, through the real reads. root_b now disagrees
        //       with root_a about k_repair_target, more tightly.
        dir.put_attestation(super::super::SignedAttestation {
            attestation: signed_config_row(
                &root_b,
                &root_b,
                K::RedundancyKRepairTarget,
                4,
                MeshConfigForm::Durable,
                now - Duration::hours(1),
                None,
                None,
                "att-deleg",
            ),
        })
        .await
        .unwrap_or_else(|e| panic!("[{tag}] root_b's row must store: {e}"));

        let fold = resolve_mesh_config(dir, &node, &base, now)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] resolve: {e}"));
        assert_eq!(
            fold.roots,
            vec![root_a.clone(), root_b.clone()],
            "[{tag}] both subscriptions are folded, and only those"
        );
        let s = fold
            .setting(K::RedundancyKRepairTarget)
            .unwrap_or_else(|| panic!("[{tag}] key present"));
        assert_eq!(
            s.effective, 4,
            "[{tag}] MOST-RESTRICTIVE-ACROSS-ROOTS on the real read path: root_b's 4 binds over \
             root_a's 10"
        );
        assert_eq!(s.decided_by_root.as_deref(), Some(root_b.as_str()));
        assert_eq!(
            s.per_root.len(),
            2,
            "[{tag}] the disagreement is carried, not merely resolved"
        );
        assert_eq!(
            fold.effective(K::AntientropyRoundSecs),
            600,
            "[{tag}] the conferred delegate's row binds too"
        );
        assert_eq!(
            fold.effective(K::AntientropyPageLimit),
            50,
            "[{tag}] the live rows for this key are the emergency at 50 and the durable that \
             ratified it, also 50. The tighter emergency at 40 was admitted with an \
             `asserted_at` 25 hours in the FUTURE, so it has not started — answering 40 means a \
             future-dated row is being counted as live, which would let an author pre-schedule \
             the mesh's configuration"
        );
        // Nothing the stranger root said reaches this node.
        assert!(
            !fold.roots.contains(&stranger),
            "[{tag}] an unsubscribed root must not appear in the fold"
        );
        // And the whole plane still honours rule 1 on the real path.
        for setting in &fold.settings {
            assert!(
                !setting
                    .key
                    .expands_beyond(setting.effective, setting.baseline),
                "[{tag}] CC 4.2.1 rule 1 violated for {} on the real read path",
                setting.key
            );
        }
    }

    #[tokio::test]
    async fn mesh_config_door_and_fold_memory() {
        let dir = crate::store::MemoryBackend::new();
        mesh_config_door_body(&dir, "mem").await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn mesh_config_door_and_fold_sqlite() {
        use crate::store::Backend;
        let dir = crate::store::SqliteBackend::open_in_memory()
            .await
            .expect("sqlite");
        dir.run_migrations().await.expect("migrations");
        mesh_config_door_body(&dir, "sq").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn mesh_config_door_and_fold_postgres() {
        use crate::store::Backend;
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let dir = crate::store::PostgresBackend::connect(&dsn)
            .await
            .expect("pg");
        dir.run_migrations().await.expect("migrations");
        // Invocation-unique so the key ids and the row set cannot collide with
        // an earlier run against the same database.
        let tag = format!("pg{}", uuid::Uuid::new_v4().simple());
        mesh_config_door_body(&dir, &tag).await;
    }

    // ══════════════════════════════════════════════════════════════════
    // The registry row itself
    // ══════════════════════════════════════════════════════════════════

    /// The family is registered (CC 3.1.7 R2(a)), and its row states its
    /// emitter rule in PROSE ONLY — so this module's refusal to consult
    /// `authority_for` is a decision with a fact behind it, not a habit.
    ///
    /// Fails the day CC lands a machine-readable rule on the row, which is the
    /// day this module's authority derivation can be checked against CC's own
    /// artifact instead of against CC 4.2.1's paragraph.
    #[test]
    fn the_mesh_config_row_states_its_rule_in_prose_only() {
        use crate::federation::namespace::registry;
        assert!(
            registry::is_family_registered(&MeshConfigKey::ALL[0].dimension()),
            "CC 3.1.7 R2(a): the family persist mints must have its registry row"
        );
        let entry = registry::entries()
            .iter()
            .find(|e| e.prefix == NAMESPACE_FAMILY)
            .expect("mesh_config:{key} is in the vendored manifest");
        assert_eq!(entry.cc_section, "3.1.9.2");
        assert!(
            entry.authority.reserved.is_none(),
            "CC has landed a machine-readable rule on {NAMESPACE_FAMILY} — this module can now \
             check its authority derivation against the manifest instead of against CC 4.2.1's \
             prose. Do that, and delete this pin."
        );
        // The prose half, read from the raw artifact — the divergence is the
        // point, so both halves are read.
        let root: serde_json::Value =
            serde_json::from_str(include_str!("namespace/namespace_registry.json"))
                .expect("vendored manifest parses");
        let description = root["families"]
            .as_array()
            .expect("families")
            .iter()
            .find(|r| r["prefix"].as_str() == Some(NAMESPACE_FAMILY))
            .expect("the mesh_config row")["description"]
            .as_str()
            .unwrap_or_default();
        for phrase in [
            "trust-root-emitted",
            "relieve-never-expand",
            "most-restrictive-across-roots",
        ] {
            assert!(
                description.contains(phrase),
                "the row's description no longer states {phrase:?}; re-read the row before \
                 trusting this module's reading of CC 4.2.1"
            );
        }
    }
}
