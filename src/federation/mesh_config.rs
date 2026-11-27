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
//! **v62.0.0 (R2-rest-b2; CC 4.2.1 "Mesh-config authorship" at pre4,
//! Constitution 11-24 "MESH-CONFIG HAS NO DELEGATE").** The quoted
//! delegation-plane wording is the earlier text. Now: *"The author of mesh
//! configuration is **the root**: the lineage of the bundle a node's owner
//! accepted"*; a durable setting is *"a row counted over a strict majority of
//! the holders of the bundle in force"*; emergency relief is *"one holder's
//! row"*; *"A node MUST NOT author a `mesh_config` value"* (CC 4.2.1.4). No
//! grant and no scope word confers the authority, so persist has no delegate
//! leg and no keyed root here (`root_authorizes_author`, `config_roots`).
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
//! directions. Writing "take the min" would have been correct for nine of the
//! twelve keys and silently inverted for three — `antientropy.round_secs`
//! LARGER is less traffic, `backpressure.summary_only` TRUE is less traffic. A
//! fold that minimises is not most-restrictive; it is most-restrictive on the
//! keys where the two coincide, which is the kind of bug that ships.
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

use super::attestation_query::{AttestationQuery, FOLD_PAGE};
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
    /// ([`list_attestations_for`](crate::federation::attestation_query::AttestationQuery::to))
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
    // v62.0.0 (R2-rest-b3; Constitution 11-24, the lead's ruling 2) —
    // `DELEGATION_ID` ("delegation_id") is DELETED: mesh config has no
    // delegate, and pre4's payload names no such member. Clean break.
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
    /// A LARGER value means more flows. `redundancy.k_repair_symbols` (more
    /// copies pushed), `antientropy.page_limit` (bigger pages),
    /// `admission.rate_per_key` (more rows admitted), `load.ceiling` (more
    /// background work carried at once — *"do less work"* is the clause's own
    /// first permitted direction, so work is on this axis exactly as traffic
    /// is).
    HigherMeansMoreFlow,
    /// A SMALLER value means more flows. `antientropy.round_secs` (rounds more
    /// often), `backpressure.summary_only` (0 = full rows, not summaries),
    /// `descent.pressure_multiplier` (less descent pressure).
    ///
    /// **Three of the twelve keys are on this arm**, which is why the fold
    /// cannot be a `min()`.
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
    /// A plain count of things with no redundancy axis — rows, pages,
    /// admissions, concurrent background tasks. **No longer "copies, rows,
    /// symbols"**: that gloss is what
    /// let [`MeshConfigKey`] carry a symbol quantity and a holder quantity
    /// under one unit, so the manifest could not express the difference
    /// (CIRISPersist#602, the same gap #532 closed with `ci_axis`).
    Count,
    /// v30.0.0 (CIRISPersist#602) — a count of **fountain symbols**: source or
    /// repair blocks of one content. Distinct from [`Holders`](Self::Holders)
    /// because a holder does not hold exactly one symbol, so the two are not
    /// interconvertible and a knob typed for one silently misconfigures the
    /// other.
    Symbols,
    /// v30.0.0 (CIRISPersist#602) — a count of **distinct peers** holding
    /// symbols for one content. Edge's `target_holders` (`H`) is this axis; its
    /// repair planner counts peers, not blocks.
    Holders,
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
            Self::Symbols => "symbols",
            Self::Holders => "holders",
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
/// #570's own initial registry, verbatim, plus the two axes CIRISPersist#602
/// split out of its fused redundancy pair and CIRISPersist#777's load ceiling.
/// Each carries the four facts the plane needs and nothing else: its wire
/// spelling, its [`FlowPolarity`], its domain, and its consumer processor.
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
    RedundancyKRepairSymbols,
    /// v30.0.0 (CIRISPersist#602) — the symbol floor below which content is
    /// unreconstructable. Edge's `min_viable_symbols` (`N/4`).
    RedundancyMinViableSymbols,
    /// v30.0.0 (CIRISPersist#602) — the target number of distinct PEERS holding
    /// symbols. Edge's `target_holders` (`H`) — a different axis from
    /// [`RedundancyKRepairSymbols`](Self::RedundancyKRepairSymbols).
    RedundancyTargetHolders,
    /// v30.0.0 (CIRISPersist#602) — the holder floor below which the converger
    /// emits `RepairNeeded`. Edge's `min_viable`.
    RedundancyMinViableHolders,
    /// Floor below which a corpus is not considered viable. Higher = more
    /// copies must be held and served = more flow.

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
    /// CIRISPersist#777 — the upper bound on the **concurrent background
    /// work** a node carries: reconcile rounds, scorer passes, holonomic
    /// publish. Higher = the node does more at once = more flow.
    ///
    /// # A ceiling, not a switch
    ///
    /// CIRISServer#501 was a 2-vCPU canonical that measured its own CPU stall,
    /// raised `resource.cpu_stall` correctly, and went dark anyway — detection
    /// with no consequence. What relieves that node is *less of its own
    /// housekeeping at once*, and that is a QUANTITY. A flag could only take
    /// the work to zero, and a node that never reconciles never converges: it
    /// would stop being a mesh member rather than be relieved as one. So the
    /// domain floors at `1` — a ceiling of `0` is a halt, and the halt is a
    /// different plane with different authority and no TTL (CC 4.2.1 rule 4's
    /// asymmetry, which this module quotes on
    /// [`MeshConfigForm::Emergency`]). Relief that can reach zero is not the
    /// relief tier.
    ///
    /// # It can only ever LOWER what the node does
    ///
    /// `owner_default` is the consent CEILING, so
    /// [`MeshConfigKey::expands_beyond`] refuses a bigger number at the door
    /// and [`fold_mesh_config`] clamps one that arrives by any other route.
    /// The worst a subscribed root can do to a node through this key is make
    /// it slower — never busier — which is what lets it compose under PLURAL
    /// roots with no coordination between them: two roots asking 24 and 6 fold
    /// to **6** through [`MeshConfigKey::more_restrictive_of`], on every node,
    /// in any order. Restrictions compose; grants do not, and a key that could
    /// raise the ceiling would need the roots to agree before it was safe.
    ///
    /// # Why a node cannot author it
    ///
    /// The node DETECTS, the owner RELIEVES, the node CONSUMES. Self-measured
    /// stall needs no authority — it declares nothing, is invisible to peers
    /// and binds nobody — but a *value the node then runs under* is a
    /// governance act, and CIRISServer#503 tried the node-local form and was
    /// withdrawn on the constitution rather than on engineering: CC 4.2.1 puts
    /// the mesh-config author on the CC 3.2 delegation plane, and a node holds
    /// no delegation to itself.
    ///
    /// That refusal needs no new vocabulary, which is the point.
    /// [`trusted_roots_of`](super::trust_root::trusted_roots_of) excludes
    /// self-edges by construction (`attested_key_id != node_key_id`), so a
    /// node naming itself as its own root is refused
    /// [`RootNotTrusted`](MeshConfigRefusalReason::RootNotTrusted) even when it
    /// charters ITSELF as one, and a node signing under a root that never
    /// conferred on it is refused
    /// [`AuthorNotRootAuthorized`](MeshConfigRefusalReason::AuthorNotRootAuthorized).
    /// Both are witnessed on every backend by
    /// [`tests::a_node_cannot_author_its_own_load_ceiling_memory`] and its
    /// siblings. The TTL that makes unilateral relief safe attaches to a root
    /// HOLDER's standing (rule 3); a node has none, so there would be nothing
    /// for a TTL to bound.
    LoadCeiling,
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

/// v30.0.0 (CIRISPersist#602) — **the consumer's own pinned values, recorded
/// once so a ceiling below them fails the build.**
///
/// `MeshConfigKeySpec::owner_default` is a **consent CEILING**: roots may only
/// tighten beneath it ([`FlowPolarity`], CC 4.2.1 rule 1). So a ceiling ABOVE
/// the consumer's operating value merely permits, while a ceiling BELOW it makes
/// the knob **unsatisfiable** — no root can ever configure the consumer to a
/// value the consumer itself considers viable. `redundancy.min_viable_floor`
/// shipped that way: ceiling 3 against a consumer floor of 5.
///
/// **This table is a placeholder for a vendored manifest, and is the weakest
/// thing in this module.** These numbers are hand-recorded from CIRISEdge's
/// `pub const`s, which is the same transcription that produced the defect —
/// `redundancy.k_repair_target` carried `n_source`'s 20 under `k_repair`'s
/// name, and nothing could notice. Recording them *as a gate input* is
/// different from using them *as values*: the gate's only job is to fail when
/// our ceiling sinks below them. It cannot detect edge moving a floor UP, which
/// is exactly what the manifest is for.
///
/// The right shape is `namespace_registry.json`'s: generated upstream, vendored,
/// gated, failing in EITHER direction. Filed on edge; until it lands this is a
/// ratchet, not a reconciliation.
///
/// `(wire_name, consumer's pinned value, where it lives)`
/// Test-only: this table's whole job is to fail a gate, so it is not compiled
/// into the shipped library. It is deliberately NOT `pub` — a consumer reading
/// these numbers from persist would be taking the transcription as authority,
/// which is the defect, not the fix.
#[cfg(test)]
const CONSUMER_FLOORS: &[(&str, i64, &str)] = &[
    (
        "redundancy.k_repair_symbols",
        6,
        "CIRISEdge DEFAULT_K_REPAIR (knee pinned by repair_headroom_knee_at_k_6)",
    ),
    (
        "redundancy.min_viable_symbols",
        5,
        "CIRISEdge DEFAULT_MIN_VIABLE_SYMBOLS (N/4)",
    ),
    (
        "redundancy.target_holders",
        30,
        "CIRISEdge DEFAULT_TARGET_HOLDERS (H = max(26,7,10) x 1.15)",
    ),
    (
        "redundancy.min_viable_holders",
        5,
        "CIRISEdge DEFAULT_MIN_VIABLE",
    ),
];

impl MeshConfigKey {
    /// Every registered key, in declaration order. **The closed set.**
    pub const ALL: &'static [Self] = &[
        Self::RedundancyKRepairSymbols,
        Self::RedundancyMinViableSymbols,
        Self::RedundancyTargetHolders,
        Self::RedundancyMinViableHolders,
        Self::AntientropyRoundSecs,
        Self::AntientropyPageLimit,
        Self::BackpressureSummaryOnly,
        Self::FeatureAvStreams,
        Self::FeatureTraceReplication,
        Self::DescentPressureMultiplier,
        Self::AdmissionRatePerKey,
        Self::LoadCeiling,
    ];

    /// This key's full specification — the ONE place its five facts live.
    #[must_use]
    pub const fn spec(self) -> MeshConfigKeySpec {
        use FlowPolarity::{HigherMeansMoreFlow, LowerMeansMoreFlow};
        use MeshConfigUnit::{CentiRatio, Count, Flag, Holders, Seconds, Symbols};
        match self {
            Self::RedundancyKRepairSymbols => MeshConfigKeySpec {
                wire_name: "redundancy.k_repair_symbols",
                polarity: HigherMeansMoreFlow,
                unit: Symbols,
                min: 0,
                max: 4096,
                // A CEILING, not a recommendation. Roots may only tighten
                // beneath it, so a generous ceiling merely permits; a tight one
                // makes the consumer's own operating value unreachable. See
                // CONSUMER_FLOORS.
                owner_default: 20,
                consumer: "repair_planner",
                knob: "k_repair",
            },
            Self::RedundancyMinViableSymbols => MeshConfigKeySpec {
                wire_name: "redundancy.min_viable_symbols",
                polarity: HigherMeansMoreFlow,
                unit: Symbols,
                min: 1,
                max: 4096,
                // RAISED from 3 (CIRISPersist#602). The old ceiling sat BELOW
                // the consumer's own viability floor, so no root could ever
                // configure the planner to a value it considers viable — an
                // unsatisfiable knob, not merely a mismatched one.
                owner_default: 20,
                consumer: "repair_planner",
                knob: "min_viable_symbols",
            },
            Self::RedundancyTargetHolders => MeshConfigKeySpec {
                wire_name: "redundancy.target_holders",
                polarity: HigherMeansMoreFlow,
                unit: Holders,
                min: 1,
                max: 4096,
                owner_default: 64,
                consumer: "repair_planner",
                knob: "target_holders",
            },
            Self::RedundancyMinViableHolders => MeshConfigKeySpec {
                wire_name: "redundancy.min_viable_holders",
                polarity: HigherMeansMoreFlow,
                unit: Holders,
                min: 1,
                max: 4096,
                owner_default: 64,
                consumer: "repair_planner",
                knob: "min_viable",
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
            Self::LoadCeiling => MeshConfigKeySpec {
                wire_name: "load.ceiling",
                // More work carried at once is more flow. CC 4.2.1's "what
                // flows" covers work as well as traffic — *"relieving a
                // constraint (do less work)"* is the clause's own first
                // permitted direction.
                polarity: HigherMeansMoreFlow,
                unit: Count,
                // FLOORED AT 1, not 0. Relief that reaches zero is a halt, and
                // the halt is the other tier of the graded response — different
                // authority, no TTL. A node held at 1 still converges, slowly,
                // and recovers on its own when the relief expires; a node at 0
                // converges never and would sit there until a TTL nobody is
                // watching runs out.
                min: 1,
                max: 4096,
                // A CEILING, not a recommendation — the same reading every
                // other key's default carries. Deliberately generous: roots may
                // only tighten beneath it, so a high ceiling merely permits,
                // while one below the consumer's own operating concurrency
                // would make the knob unsatisfiable by any root (#602, and the
                // reason CONSUMER_FLOORS exists). No entry there for this key
                // yet: the consumer is being filed against CIRISServer as the
                // key lands, and a floor transcribed before it exists would be
                // a number invented here and then gated against.
                owner_default: 64,
                consumer: "background_scheduler",
                knob: "max_concurrent_tasks",
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
    ///    admitted iff the act is not UNILATERAL: v62.0.0 (R2-rest) the row's
    ///    voices reach the accord's threshold over the holders of the bundle
    ///    in force (`root_quorum_reached`; the earlier family and key arms are
    ///    deleted). v62.0.0 (R2-rest-b2): a delegate does not reach this
    ///    door at all (mesh config has no delegate), and door 1's conversion
    ///    is counted the same way: one holder converts nothing alone.
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
    /// No `delegation_id`. #570 ask 3's rule: an act that does not carry its
    /// own authority is indistinguishable from an unauthorized one once the
    /// actor is gone. v62.0.0 (R2-rest-b3) — **produced by nothing since
    /// R2-rest-b3**: the member is deleted (mesh config has no delegate); kept
    /// because this mapping is append-only.
    Unattributed,
    /// v30.0.0 (CIRISPersist#601) — `delegation_id` is present, but it
    /// does **not** name any of the live `trust:confers:v1` edges by which the
    /// root authorises this author.
    ///
    /// [`Unattributed`](Self::Unattributed) catches an act that names NO
    /// authority. This catches one that names a **different** authority than
    /// the one it actually has — which is worse, because it reads as attributed
    /// and gets stored in a signed row that anything downstream will report as
    /// verified provenance.
    ///
    /// v62.0.0 (R2-rest-b2) — **produced by nothing since R2-rest-b2**: mesh
    /// config has no delegate, so no conferral exists for `delegation_id` to
    /// name. Kept because this mapping is append-only.
    DelegationIdNotConferring,
    /// The row is not filed against the root it names, so the fold's
    /// `list_attestations_for(root)` read would never see it. A row stored and
    /// permanently uncounted is the preserve-set ≠ verified-set class (#541).
    NotFiledAgainstRoot,
    /// This node holds no live `trust:accepts:v1` edge to the named root. **The
    /// subscription is the trust edge** (CC 4.2.1), so a root this node has not
    /// subscribed to has nothing to say to it — and un-trusting is one row,
    /// which is the T3 lever CC names. v62.0.0 (R2-rest-b2): the root is the
    /// lineage of the bundle in force; an edge to anything else (a key)
    /// subscribes to no config.
    RootNotTrusted,
    /// v62.0.0 (R2-rest-b2; Constitution 11-24 "MESH-CONFIG HAS NO
    /// DELEGATE") — the author is not a holder of the bundle in force. No
    /// grant and no scope word confers mesh-config authority: a grantee of
    /// the root, a delegate and a node (CC 4.2.1.4) are all refused here.
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
    /// no emergency behind it must not be a unilateral act.
    ///
    /// v62.0.0 (R2-rest-b2; CC 4.2.1 rule 3 at pre4, "two routes to one
    /// authority") — the quorum is a strict majority of the holders of the
    /// bundle in force, on BOTH durable routes: a durable row that names a
    /// held emergency is refused here too when one holder signs it alone.
    /// The earlier single-key "1-of-1" root and the family-record arm are
    /// gone with the keyed root.
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
            Self::DelegationIdNotConferring => "delegation_id_not_conferring",
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
        Self::DelegationIdNotConferring,
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
    /// v62.0.0 (wave GC7; CC rc21 item 14, CC 2.7.3) — **kept and
    /// concluding nothing**: the row is stored, and the fold
    /// ([`fold_mesh_config`]) does not count it, for the reason named. It is
    /// not a refusal: the same row set folds the same way whichever row
    /// arrived first.
    Kept {
        /// Why it concludes nothing (a [`MeshConfigRefusalReason`] token).
        reason: MeshConfigRefusalReason,
    },
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
            Self::Admitted | Self::Kept { .. } => None,
            Self::Refused { reason } => Some(*reason),
        }
    }

    /// v62.0.0 (wave GC7) — the reason a kept row concludes nothing, if it
    /// was kept so.
    #[must_use]
    pub const fn kept_reason(&self) -> Option<MeshConfigRefusalReason> {
        match self {
            Self::Kept { reason } => Some(*reason),
            Self::Admitted | Self::Refused { .. } => None,
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
/// with defaults would let a producer omit `root_ref` and
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
    ratifies: Option<&str>,
    grounds: &str,
) -> serde_json::Value {
    let mut env = serde_json::json!({
        "dimension": key.dimension(),
        field::KEY: key.wire_name(),
        field::VALUE: value,
        field::ROOT_REF: root_ref,
        field::FORM: form.as_str(),
        field::GROUNDS: grounds,
    });
    if let Some(vu) = valid_until {
        // CC 2.6.2: a signed instant is `.sssZ` (v61 S3).
        env[field::VALID_UNTIL] =
            serde_json::Value::String(crate::federation::admission::render_signed_instant(vu));
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

/// v62.0.0 (wave GC7; CC rc21 item 14) — **CC 4.2.1 rule (3) as a fold.**
/// "A holder's relief on a key whose own earlier relief there was in force
/// at the new one's `asserted_at` concludes nothing." Of `rows` (one key and
/// root's held rows, parsed), the ids of the emergency reliefs that conclude
/// nothing for that reason.
///
/// "In force" is read as *concluding*: the reliefs are walked in
/// `(asserted_at, attestation_id)` order, and a relief is back-to-back when
/// an EARLIER relief of the same holder that itself concluded was in force
/// at its `asserted_at`. So a relief that concludes nothing never makes a
/// later one back-to-back, and a fresh window after the last concluding one
/// closed is not a renewal. Strictly earlier: two reliefs at one instant are
/// neither's renewal. A function of the row set, never of arrival order.
fn back_to_back_reliefs(rows: &[(&Attestation, ParsedRow)]) -> std::collections::BTreeSet<String> {
    let mut reliefs: Vec<&(&Attestation, ParsedRow)> = rows
        .iter()
        .filter(|(_, p)| p.form == MeshConfigForm::Emergency)
        .collect();
    reliefs.sort_by(|(a, _), (b, _)| {
        a.asserted_at
            .cmp(&b.asserted_at)
            .then_with(|| a.attestation_id.cmp(&b.attestation_id))
    });
    let mut concluding: Vec<&(&Attestation, ParsedRow)> = Vec::new();
    let mut out = std::collections::BTreeSet::new();
    for relief in reliefs {
        let (r, p) = relief;
        let chained = concluding.iter().any(|(q, pq)| {
            pq.key == p.key
                && pq.root_ref == p.root_ref
                && q.attesting_key_id == r.attesting_key_id
                && q.asserted_at < r.asserted_at
                && pq.valid_until.is_none_or(|vu| vu > r.asserted_at)
        });
        if chained {
            out.insert(r.attestation_id.clone());
        } else {
            concluding.push(relief);
        }
    }
    out
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
    /// One entry per registered key — **all twelve, always**, even when no root
    /// has spoken about it. A consumer reading a config plane should never have
    /// to distinguish "not set" from "not returned"; an absent key is exactly
    /// how a knob silently keeps a stale value.
    pub settings: Vec<MeshConfigSetting>,
    /// v30.0.0 (CIRISPersist#601) — roots this node is subscribed to whose rows
    /// **could not be read**, sorted. Empty on every backend that can answer.
    ///
    /// **The field above states the rule this one was breaking.** `settings`
    /// returns all twelve keys always, because *"a consumer should never have to
    /// distinguish 'not set' from 'not returned'"*. [`resolve_mesh_config`] then
    /// swallowed `Error::Unsupported` per root, so **"this backend cannot answer
    /// for root R" and "root R said nothing" were the same answer** — the
    /// identical defect one level up, for roots instead of keys.
    ///
    /// The direction matters on this plane specifically. `mesh_config` only ever
    /// *restricts*, so a root that silently contributes nothing renders as a
    /// node under **fewer** restrictions than it consented to. A broken backend
    /// read as an unconstrained node is the wrong way to fail here.
    ///
    /// Reported by CIRISServer, who worked around it by gathering per-root and
    /// reporting `unreadable_roots` separately — the same shape, one layer out,
    /// which is where it belongs but not where it should have been necessary.
    /// They record it as the fifth independent instance of this class in the
    /// project (`ScoreOutcome`, `RetentionOutcome`, edge's withhold ledger,
    /// their operator surface, and this).
    ///
    /// **NOT COVERED BY AN AUTOMATED WITNESS, stated rather than implied.** All
    /// three shipped backends implement `list_attestations_for`, so none of
    /// them can produce `Unsupported` and no test in this repo reaches the arm
    /// that fills this field. Exercising it needs a `FederationDirectory`
    /// double, and that trait has **78 required methods** — disproportionate to
    /// build for one arm, and the second time this cycle a testing gap has come
    /// from the trait's size. A composable test-support directory is filed
    /// separately. Until it exists, treat this field as reasoned-correct and
    /// unwitnessed; the consumer that reported the defect is the one exercising
    /// it, through their own directory implementation.
    ///
    /// v62.0.0 (PX-fix3) — ALWAYS EMPTY now: a root whose read cannot be
    /// answered (`Unsupported`) fails `resolve_mesh_config` instead of being
    /// folded as fewer restrictions and reported here (I2190). The field
    /// stays for the wire shape adopters read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unreadable_roots: Vec<String>,
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
            let on_key: Vec<(&Attestation, ParsedRow)> = rows
                .iter()
                .filter_map(|r| parse_row(r).map(|p| (r, p)))
                .filter(|(_, p)| p.key == key && &p.root_ref == root)
                .collect();
            // v62.0.0 (wave GC7; CC rc21 item 14) — a back-to-back relief is
            // kept and concludes nothing.
            let back_to_back = back_to_back_reliefs(&on_key);
            let mut live: Vec<(&Attestation, ParsedRow)> = on_key
                .iter()
                .filter(|(r, p)| {
                    r.asserted_at <= now
                        && p.valid_until.is_none_or(|vu| vu > now)
                        && !back_to_back.contains(&r.attestation_id)
                })
                .cloned()
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
        // The pure fold reads rows; it cannot know a root was unreadable,
        // because an unreadable root contributes no row to observe.
        // [`resolve_mesh_config`] fills this after the read.
        unreadable_roots: Vec::new(),
    }
}

// ─────────────────────────────────────────────────────────────────────────
//  Authority — re-derived from this node's own verified state (#377)
// ─────────────────────────────────────────────────────────────────────────

/// **CC 4.2.1's authority sentence, as a predicate.** May `author` set config
/// under `root_ref`?
///
/// v62.0.0 (R2-rest-b2; CC 4.2.1 "Mesh-config authorship" at pre4,
/// Constitution 11-24 "MESH-CONFIG HAS NO DELEGATE") — **one way only: the
/// author is a HOLDER of the bundle in force, and `root_ref` is that bundle's
/// lineage** ([`bundle_root_holders`](super::trust_root::bundle_root_holders)).
/// One holder may raise emergency relief (rule 3); a durable setting is
/// counted over a strict majority of the holders ([`root_quorum_reached`]).
/// No scope word and no grant confers mesh-config authority, so the
/// delegate leg (a live `trust:confers:v1` to the author, read by key) is
/// deleted, and with it the KEYED arm (`root_ref == author`, a key speaking
/// as its own root): the root is the bundle's lineage and has no key. Every
/// other author, a node's own key included (CC 4.2.1.4 "A node MUST NOT
/// author a `mesh_config` value"), is [`AuthorAuthority::None`].
///
/// Read from the node's OWN stored state, never from anything the incoming
/// row carries (#377: a caller-supplied decision is a forgeable bypass).
///
/// **No accord-holder arm exists**, deliberately: a holder signs here as the
/// root's conferring roster, never as an accord invocation; the accord's
/// powers stay exactly those CC 4.2.1 enumerates (CIRISConstitution#57).
pub(crate) async fn root_authorizes_author<F>(
    directory: &F,
    root_ref: &str,
    author: &str,
) -> Result<AuthorAuthority, Error>
where
    F: FederationDirectory + ?Sized,
{
    let Some(holders) = super::trust_root::bundle_root_holders(directory, root_ref).await? else {
        return Ok(AuthorAuthority::None);
    };
    Ok(if holders.iter().any(|h| h == author) {
        AuthorAuthority::Holder
    } else {
        AuthorAuthority::None
    })
}

/// v30.0.0 (CIRISPersist#601) — **what authorises this author.**
///
/// v62.0.0 (R2-rest-b2) — the `Conferred` arm (a delegate named by its
/// `trust:confers:v1` edge, which `delegation_id` had to name) is deleted:
/// mesh config has no delegate (Constitution 11-24). `Inherent` (the root
/// itself, a key) became [`Holder`](Self::Holder): the root is the bundle's
/// lineage and acts through its holders in force.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AuthorAuthority {
    /// The author is a holder of the bundle in force, and the row's root is
    /// that bundle's lineage. One holder's row is emergency relief at most;
    /// durability is counted ([`root_quorum_reached`]).
    Holder,
    /// Nothing authorises this author.
    None,
}

/// **"The root's own quorum" (CC 4.2.1 rule 3), as a predicate over one row.**
///
/// v62.0.0 (R2-rest; CC 3.2 T5, CC 4.2.1 rule 3; lead's ruling 1) — **what it
/// counts:** the row's distinct voices (`edition2::voices::counted_roster_signers`)
/// among the HOLDERS OF THE BUNDLE IN FORCE, against the accord's threshold
/// (`admission::accord_threshold`, the one strict-majority seam), when
/// `root_ref` is that bundle's lineage (`trust_root::bundle_root_holders`).
/// Any other `root_ref` has no quorum and the answer is `false`: the root is
/// the bundle's lineage, and there is no other kind of root. The earlier
/// FAMILY-record arm (`resolve_family_root`, a family's m-of-n over the row's
/// scrubs) and the KEY arm ("the root itself is the author": 1-of-1) are
/// deleted.
///
/// **One holder is not a quorum.** That is the whole bite of this gate: one
/// holder acts for the root at threshold-1, which is exactly what CC 4.2.1
/// rule 4 says must expire, so it can raise a bounded emergency and it cannot
/// make anything permanent alone, by either durable route.
async fn root_quorum_reached<F>(
    directory: &F,
    root_ref: &str,
    row: &Attestation,
) -> Result<bool, Error>
where
    F: FederationDirectory + ?Sized,
{
    // v62.0.0 (R2-rest-b3; CC 4.2.1 as ruled 11-24: "a durable setting IS A
    // GRANT") — the ONE count a root grant is read by
    // (`admission::root_grant_reading`, R2-gaps-1a's reading): over the
    // holders of the bundle the row's OWN `refs.head` names, by the voices
    // dated before that bundle's successor. A setting counted under an
    // earlier bundle of the lineage keeps its standing under a later one; a
    // row arriving under an already-superseded bundle whose voices postdate
    // the successor is not counted, and is held.
    Ok(named_bundle(directory, root_ref, row)
        .await?
        .is_some_and(|r| r.count.met()))
}

/// v62.0.0 (R2-rest-b3) — **INTERIM pending Constitution** (the model's
/// mesh_config row vs CC 4.2.1's text; Constitution types the payload in
/// pre5). The bundle a mesh-config row names in `refs.head`, read as a root
/// grant's is ([`crate::federation::admission::root_grant_reading`]), when it
/// is a bundle of `root_ref`'s lineage this node holds. `Ok(None)`: the named
/// bundle is not held, or is of another lineage (the row is HELD
/// `durable_without_root_quorum` by the caller). A row naming NO head is
/// refused `act_names_no_head` (`Err`), the token the head rule types.
///
/// # Errors
/// `act_names_no_head`; directory reads.
async fn named_bundle<F>(
    directory: &F,
    root_ref: &str,
    row: &Attestation,
) -> Result<Option<crate::federation::admission::RootGrantReading>, Error>
where
    F: FederationDirectory + ?Sized,
{
    if crate::federation::admission::edition2_named_head(row).is_none() {
        return Err(Error::malformed_row(
            "mesh_config",
            crate::federation::malformed_row::ACT_NAMES_NO_HEAD,
            format!(
                "{}: mesh_config row {} names no `refs.head`: a mesh-config row names the \
                 bundle of its root (CC 4.2.1)",
                crate::federation::malformed_row::ACT_NAMES_NO_HEAD,
                row.attestation_id
            ),
        ));
    }
    Ok(
        crate::federation::admission::root_grant_reading(directory.as_dyn_directory(), row)
            .await?
            .filter(|r| r.family_key_id == root_ref),
    )
}

/// v62.0.0 (R2-rest-b2; CC 4.2.1 "The author of mesh configuration is the
/// root: the lineage of the bundle a node's owner accepted") — **the roots a
/// node's mesh config is read under**: the ids its acceptance edges name
/// ([`trusted_roots_of`](super::trust_root::trusted_roots_of), the
/// subscription) that are the lineage of the bundle in force
/// ([`bundle_root_holders`](super::trust_root::bundle_root_holders)). An edge
/// to any other id (a key, a room: an acceptance of kind C) subscribes to no
/// config: the keyed root is gone, and a key's rows filed against itself are
/// refused [`RootNotTrusted`](MeshConfigRefusalReason::RootNotTrusted) at
/// the door and never folded. A ROOTLESS node (no accepted lineage) reads
/// none: its effective config is its own baseline.
async fn config_roots<F>(
    directory: &F,
    node_key_id: &str,
    now: DateTime<Utc>,
) -> Result<Vec<String>, Error>
where
    F: FederationDirectory + ?Sized,
{
    let mut roots = Vec::new();
    for root in super::trust_root::trusted_roots_of(directory, node_key_id, now).await? {
        if super::trust_root::bundle_root_holders(directory, &root)
            .await?
            .is_some()
        {
            roots.push(root);
        }
    }
    Ok(roots)
}

// ─────────────────────────────────────────────────────────────────────────
//  The admission door
// ─────────────────────────────────────────────────────────────────────────

/// **The config door.** Admit and store one mesh-config row.
///
/// Verify-before-mutation (AV-9): every gate below runs BEFORE any row is
/// written, and a refusal writes nothing.
///
/// v62.0.0 (WD-fix6) — a HOLD is not a refusal: when the final put's
/// statement door HOLDS the row (a fold condition not yet met; WD-fix4 routes
/// a statement-carrying row through the statement funnel), the answer is the
/// gate's error, as before, but the statement is KEPT and concludes when what
/// it waits for arrives. Told apart structurally by
/// [`kept_waiting`](super::attestation_admit::kept_waiting) (the fold's held
/// state, `fold::why_held`), never by the error's text; a re-offer is a no-op
/// on the statement id.
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
    // v62.0.0 (wave GC7; CC 2.7.3) — a gate below that reads OTHER rows
    // (the node's trust edges, the root's conferrals, the root's held rows,
    // the root's roster) is a fold condition: under a fold attempt the
    // answer marks the row HELD with the refusal's own token, and the inputs
    // are declared so it re-folds when they change. Outside an attempt (this
    // node's own config door, today) the answer is the `Refused` it was. The
    // shape, bounds and signature gates read only the row and stay refusals.
    let held_as = |reason: R| {
        super::edition2::fold::hold_detail(
            reason.as_str(),
            format!("mesh_config: {}", reason.as_str()),
        );
        Ok(MeshConfigOutcome::Refused { reason })
    };

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

    // v62.0.0 (R2-rest-b3) — the `delegation_id` requirement (#570 ask 3's
    // `Unattributed`) is deleted with the member: mesh config has no
    // delegate, and the row's own statement attributes it.

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
    {
        use super::edition2::fold::{reads, Dep};
        reads(Dep::key(node_key_id));
        reads(Dep::key(&root_ref));
        reads(Dep::key(&row.attesting_key_id));
    }
    let roots = config_roots(directory, node_key_id, now).await?;
    if !roots.iter().any(|r| r == &root_ref) {
        return held_as(R::RootNotTrusted);
    }

    // ── The authority, re-derived from this node's own state.
    // v62.0.0 (R2-rest-b2) — a holder of the bundle in force, or nothing:
    // mesh config has no delegate (`DelegationIdNotConferring` is produced by
    // nothing; kept because the token mapping is append-only).
    match root_authorizes_author(directory, &root_ref, &row.attesting_key_id).await? {
        AuthorAuthority::None => return held_as(R::AuthorNotRootAuthorized),
        AuthorAuthority::Holder => {}
    }

    // ── The author's own signature, against pubkeys from THIS node's
    // directory (#377 — never pubkeys carried on the row).
    //
    // v62.0.0 (E6-fix8; CC 2.6.1.7) — the ROW's verify, not the envelope's: a
    // v62 config row is the projection of the edition-2 statement it carries,
    // proven by that statement's composite under the author's live key
    // (`tier_ingest::verify_row_hybrid_signature` → `ingest::verify_carried`).
    // The envelope-only earlier-form verify could never pass one (its scrub
    // is not a bound-hybrid pair), so the root's own relief was refused
    // `unverifiable_signature`. A row carrying no statement still meets the
    // earlier-form arms, which refuse it by name.
    if super::tier_ingest::verify_row_hybrid_signature(directory, row)
        .await
        .is_err()
    {
        return refused(R::UnverifiableSignature);
    }

    // ── Rows this root already holds on this key — the two history gates.
    // The root's `mesh_config:*` rows: the only rows `parse_row` accepts.
    let mut held = Vec::new();
    let mut pages = AttestationQuery::to(&root_ref, FOLD_PAGE)
        .dimension_prefix(DIMENSION_PREFIX)
        .pages();
    let read: Result<(), Error> = async {
        while let Some(page) = pages.next(directory).await? {
            held.extend(page);
        }
        Ok(())
    }
    .await;
    read?;
    let same_key: Vec<(&Attestation, ParsedRow)> = held
        .iter()
        .filter_map(|r| parse_row(r).map(|p| (r, p)))
        .filter(|(_, p)| p.key == key && p.root_ref == root_ref)
        .collect();

    match form {
        // CC 4.2.1 rule 3 — "not renewable back-to-back by the same holder."
        // v62.0.0 (wave GC7; CC rc21 item 14) — no longer refused: the row
        // is KEPT and concludes nothing (`fold_mesh_config` does not count a
        // relief the holder's own earlier one was in force at). Only an
        // EARLIER relief makes this one back-to-back, so a later-arriving
        // earlier relief does not flip a row already held.
        MeshConfigForm::Emergency => {
            // v62.0.0 (R2-rest-b3; CC 4.2.1 as ruled 11-24) — relief NAMES the
            // bundle in force in `refs.head`; one naming another bundle is
            // held the same way a durable row is (interim, `named_bundle`).
            if !named_bundle(directory, &root_ref, row)
                .await?
                .is_some_and(|r| r.in_force)
            {
                return held_as(R::DurableWithoutRootQuorum);
            }
            let parsed = ParsedRow {
                key,
                value,
                root_ref: root_ref.clone(),
                form,
                valid_until,
            };
            let mut with_row: Vec<(&Attestation, ParsedRow)> = same_key
                .iter()
                .filter(|(prior, _)| prior.attestation_id != row.attestation_id)
                .cloned()
                .collect();
            with_row.push((row, parsed));
            if back_to_back_reliefs(&with_row).contains(&row.attestation_id) {
                directory
                    .put_attestation(super::SignedAttestation {
                        attestation: row.clone(),
                    })
                    .await?;
                return Ok(MeshConfigOutcome::Kept {
                    reason: R::BackToBackRenewal,
                });
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
                super::edition2::fold::reads(
                    super::edition2::fold::Dep::row_hex(ratifies)
                        .unwrap_or_else(|| super::edition2::fold::Dep::key(ratifies)),
                );
                if !ratifies_a_real_emergency {
                    return held_as(R::DurableUnratified);
                }
                // v62.0.0 (R2-rest-b2; CC 4.2.1 rule 3 at pre4, "The root's
                // own quorum MAY establish a durable setting directly (cold),
                // or MAY ratify a held emergency's `payload_sha256` …: two
                // routes to one authority") — the ratification is the
                // QUORUM's act too. Before, any author the root authorised
                // converted a held emergency alone, so ONE holder made its
                // own 72-hour relief permanent.
                if !root_quorum_reached(directory, &root_ref, row).await? {
                    return held_as(R::DurableWithoutRootQuorum);
                }
            }
            // Door 2 — COLD DURABLE, under the root's OWN quorum. What is
            // refused here is a UNILATERAL durable act (rule 4: "relief
            // expires because it is unilateral"), not an unexercised one.
            None => {
                if !root_quorum_reached(directory, &root_ref, row).await? {
                    return held_as(R::DurableWithoutRootQuorum);
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
    // v62.0.0 (R2-rest-b2) — the accepted lineage only (`config_roots`).
    let roots = config_roots(directory, node_key_id, now).await?;
    let mut rows: Vec<Attestation> = Vec::new();
    for root in &roots {
        // The root's `mesh_config:*` rows, every page.
        let mut found = Vec::new();
        let mut pages = AttestationQuery::to(root, FOLD_PAGE)
            .dimension_prefix(DIMENSION_PREFIX)
            .pages();
        let read: Result<(), Error> = async {
            while let Some(page) = pages.next(directory).await? {
                found.extend(page);
            }
            Ok(())
        }
        .await;
        match read.map(|()| found) {
            Ok(found) => rows.extend(
                found
                    .into_iter()
                    .filter(|r| env_str(r, "dimension").is_some_and(is_mesh_config_dimension)),
            ),
            // v62.0.0 (PX-fix3) — an `Unsupported` read is an ERROR, as every
            // other could-not-ask is. v30.0.0 (#601) recorded it in
            // `unreadable_roots` and folded on: on a restrict-only plane that
            // root then read as fewer restrictions than the node consented to,
            // and through the capsule proxy that is the fail-open (I2190). On
            // v62 both backends answer this read and the proxy routes it.
            Err(e) => return Err(e),
        }
    }
    // v62.0.0 (PX-fix3) — `unreadable_roots` stays empty: a root this node
    // cannot read fails the resolution instead (I2190).
    Ok(fold_mesh_config(node_key_id, baseline, &roots, &rows, now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::types::{attestation_tier, attestation_type};

    fn ts(s: &str) -> DateTime<Utc> {
        s.parse().expect("rfc3339")
    }

    /// v30.0.0 (CIRISPersist#602) — **this module's prose count is checked
    /// against the registry.**
    ///
    /// Three doc comments state how many keys exist. #602's split moved the
    /// number and every one of them would have gone quietly stale — the class
    /// this repo spent v28.3.0 and v29.0.0 fixing twice (30 references to a
    /// version that never shipped; "53 testimonial rows" that were always 49).
    /// A count a reader ACTS on is not allowed to be hand-maintained here.
    #[test]
    fn the_doc_counts_match_the_registry() {
        const SRC: &str = include_str!("mesh_config.rs");
        let n = MeshConfigKey::ALL.len();
        let words = [
            (0, "zero"),
            (1, "one"),
            (2, "two"),
            (3, "three"),
            (4, "four"),
            (5, "five"),
            (6, "six"),
            (7, "seven"),
            (8, "eight"),
            (9, "nine"),
            (10, "ten"),
            (11, "eleven"),
            (12, "twelve"),
        ];
        let word = words
            .iter()
            .find(|(v, _)| *v == n)
            .map(|(_, w)| *w)
            .expect("registry outgrew the spelled-number table; extend it");
        let mut checked = 0usize;
        // Only phrases that denote the WHOLE registry — "all N keys", "the N
        // keys". Bare "<word> keys" would also match legitimate prose about a
        // subset ("no TWO keys drive the same knob"), and a gate that fires on
        // correct text gets deleted by the next person who hits it.
        for (v, w) in words {
            let whole = [format!("all {w} keys"), format!("the {w} keys")];
            if whole.iter().any(|ph| SRC.contains(ph.as_str())) {
                let phrase = whole
                    .iter()
                    .find(|ph| SRC.contains(ph.as_str()))
                    .unwrap()
                    .clone();
                checked += 1;
                assert_eq!(
                    v, n,
                    "a doc comment says \"{phrase}\" but the registry holds {n}. Say \
                     \"{word} keys\", or this module joins the phantom-count class it \
                     already carries two gates for."
                );
            }
        }
        // Non-vacuity. If every doc were reworded to avoid the phrases, this
        // test would pass by checking nothing — the exact shape it exists to
        // prevent, one level up.
        assert!(
            checked > 0,
            "no doc comment states the registry size in a form this gate reads. Say \
             \"all {word} keys\" or \"the {word} keys\" somewhere, or delete this test \
             rather than leaving a check that cannot fail."
        );
    }

    /// v30.0.0 (CIRISPersist#602) — **no consent ceiling may sit below the
    /// consumer's own operating value.**
    ///
    /// `owner_default` is a ceiling and roots only tighten, so a ceiling under
    /// the consumer's floor is not a mismatch — it is a knob that **cannot be
    /// satisfied by any root**, which is strictly worse than a wrong default
    /// because no operator action can reach the intended state.
    ///
    /// `redundancy.min_viable_floor` shipped at 3 against a consumer floor of 5
    /// and nothing said so. This is the check that would have.
    #[test]
    fn no_consent_ceiling_sits_below_its_consumers_floor() {
        for (wire, floor, source) in CONSUMER_FLOORS {
            let key = MeshConfigKey::ALL
                .iter()
                .find(|k| k.spec().wire_name == *wire)
                .unwrap_or_else(|| {
                    panic!(
                        "CONSUMER_FLOORS names `{wire}`, which is not a registered key. Either \
                         the key was renamed and this table was not, or the table is stale — \
                         both are the drift this table exists to catch."
                    )
                });
            let spec = key.spec();
            assert!(
                spec.owner_default >= *floor,
                "`{wire}` ceiling is {} but its consumer's own value is {floor} ({source}). \
                 owner_default is a CEILING and roots may only tighten beneath it, so no root \
                 can ever configure the consumer to a value it considers viable. Raise the \
                 ceiling — a generous ceiling only permits; a tight one forbids.",
                spec.owner_default
            );
            assert!(
                spec.max >= *floor,
                "`{wire}` domain max is {} but its consumer's value is {floor} ({source}) — \
                 the value is not even expressible on the wire.",
                spec.max
            );
        }
    }

    /// v30.0.0 (CIRISPersist#602) — **the two redundancy axes stay two.**
    ///
    /// A holder does not hold exactly one symbol, so a knob typed for one
    /// silently misconfigures the other. Both were `Count` until this cut,
    /// which is precisely why the manifest could not express the difference —
    /// the same gap #532 closed with `ci_axis`.
    #[test]
    fn redundancy_keys_declare_which_quantity_they_count() {
        use MeshConfigUnit::{Holders, Symbols};
        for key in MeshConfigKey::ALL {
            let spec = key.spec();
            if !spec.wire_name.starts_with("redundancy.") {
                continue;
            }
            assert!(
                matches!(spec.unit, Symbols | Holders),
                "`{}` is a redundancy knob typed `{}`. Every redundancy key counts EITHER \
                 fountain symbols OR distinct holders, and `count` is the fusion that let \
                 `target_repair_symbols` be read by a planner counting holders.",
                spec.wire_name,
                spec.unit.as_str()
            );
            // The name must agree with the type, so a reader cannot be misled
            // by either one alone.
            let says_symbols = spec.wire_name.contains("symbols");
            let says_holders = spec.wire_name.contains("holders");
            assert!(
                says_symbols ^ says_holders,
                "`{}` names neither or both axes; a redundancy wire name must say which.",
                spec.wire_name
            );
            assert_eq!(
                says_symbols,
                spec.unit == Symbols,
                "`{}` is typed `{}` but its NAME says otherwise. The name and the unit are two \
                 statements of one fact and must not be able to disagree — that disagreement \
                 is how `k_repair_target` came to carry `n_source`'s value.",
                spec.wire_name,
                spec.unit.as_str()
            );
        }
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
        // 9 at #570; 11 after CIRISPersist#602 split the two redundancy knobs
        // into their symbol and holder axes; 12 after CIRISPersist#777 added
        // `load.ceiling`. Update BOTH this number and the prose above when the
        // registry moves — the doc counts are checked by
        // `the_doc_counts_match_the_registry` for exactly that reason.
        assert_eq!(
            MeshConfigKey::ALL.len(),
            12,
            "#570's registry + #602's axis split + #777's load ceiling"
        );
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
            (K::RedundancyKRepairSymbols, 20, 10),
            (K::RedundancyMinViableSymbols, 6, 3),
            (K::AntientropyPageLimit, 500, 100),
            (K::FeatureAvStreams, 1, 0),
            (K::FeatureTraceReplication, 1, 0),
            (K::AdmissionRatePerKey, 600, 60),
            // #777 — a HIGHER ceiling is more concurrent background work, so
            // relieving a stalled node means moving this DOWN.
            (K::LoadCeiling, 64, 8),
        ] {
            assert_eq!(k.polarity(), FlowPolarity::HigherMeansMoreFlow, "{k}");
            assert_eq!(k.more_restrictive_of(more, less), less, "{k}");
            assert!(
                k.expands_beyond(more, less),
                "{k}: {more} expands past {less}"
            );
            assert!(!k.expands_beyond(less, more), "{k}");
        }
        // LOWER = more flow. These three are why the fold cannot be a min().
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
            .with(K::RedundancyKRepairSymbols, 10)
            .with(K::AntientropyRoundSecs, 300);
        let roots = vec!["root-a".to_owned()];
        let rows = vec![
            // HigherMeansMoreFlow: 40 copies is MORE than the 10 consented.
            row(
                "m-expand-hi",
                "root-a",
                "root-a",
                K::RedundancyKRepairSymbols,
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

        let hi = fold.setting(K::RedundancyKRepairSymbols).unwrap();
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

    /// **I3918** (wave GC7; CC rc21 item 14): a back-to-back emergency relief
    /// is KEPT and concludes nothing. The fold never counts a relief whose
    /// holder's own EARLIER concluding relief was in force at its
    /// `asserted_at`; a relief that concluded nothing makes no later one
    /// back-to-back; and the answer is the same for either order of the rows.
    #[test]
    fn i3918_back_to_back_relief_concludes_nothing_in_either_order() {
        use MeshConfigKey as K;
        let base = MeshConfigBaseline::owner_defaults(); // k_repair_target = 20
        let roots = vec!["root-a".to_owned()];
        let r = |id: &str, v: i64, at: &str, until: &str| {
            row(
                id,
                "root-a",
                "root-a",
                K::RedundancyKRepairSymbols,
                v,
                at,
                Some(until),
            )
        };
        let fold_of = |rows: &[Attestation]| {
            let f = fold_mesh_config("node-1", &base, &roots, rows, ts(NOW));
            let s = f.setting(K::RedundancyKRepairSymbols).unwrap().clone();
            (s.effective, s.row_id)
        };
        // e1 in force 10:00–13:00; e2 at 11:00 is its holder's renewal.
        let e1 = r("e1", 10, "2026-08-03T10:00:00Z", "2026-08-03T13:00:00Z");
        let e2 = r("e2", 8, "2026-08-03T11:00:00Z", "2026-08-03T14:00:00Z");
        let fwd = fold_of(&[e1.clone(), e2.clone()]);
        let rev = fold_of(&[e2, e1]);
        assert_eq!(
            fwd,
            (10, Some("e1".to_owned())),
            "I3918: the renewal concludes nothing; the first relief governs"
        );
        assert_eq!(fwd, rev, "I3918: the same answer for either order");
        // A relief that concluded nothing makes no later one back-to-back:
        // f1 closes at 11:30, f2 (11:00) is its renewal, f3 (11:45) opens
        // after the last CONCLUDING relief closed.
        let f1 = r("f1", 10, "2026-08-03T10:00:00Z", "2026-08-03T11:30:00Z");
        let f2 = r("f2", 8, "2026-08-03T11:00:00Z", "2026-08-03T14:00:00Z");
        let f3 = r("f3", 9, "2026-08-03T11:45:00Z", "2026-08-03T15:00:00Z");
        let fwd = fold_of(&[f1.clone(), f2.clone(), f3.clone()]);
        let rev = fold_of(&[f3, f2, f1]);
        assert_eq!(fwd, (9, Some("f3".to_owned())), "I3918: f3 concludes");
        assert_eq!(fwd, rev, "I3918: either order");
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
            K::RedundancyKRepairSymbols,
            10,
            "2026-08-03T10:00:00Z",
            None,
        )];
        let fold = fold_mesh_config("node-1", &base, &roots, &rows, ts(NOW));
        let s = fold.setting(K::RedundancyKRepairSymbols).unwrap();
        assert_eq!(s.baseline, 20);
        assert_eq!(s.effective, 10, "#570's headline: 20 copies to 10");
        assert!(s.relieved);
        assert_eq!(s.decided_by_root.as_deref(), Some("root-a"));
        assert_eq!(s.decided_by.as_deref(), Some("root-a"));
        assert!(s.clamped_roots.is_empty());
    }

    // ══════════════════════════════════════════════════════════════════
    // `load.ceiling` (CIRISPersist#777)
    // ══════════════════════════════════════════════════════════════════

    /// **The key exists on the wire and points the way its English does.**
    ///
    /// Asserted against the MEANING of a ceiling rather than against the
    /// registry's own answer: a bigger ceiling is more concurrent background
    /// work, so `8` relieves a node that `64` was stalling. Every other
    /// assertion in this section is downstream of that one fact.
    #[test]
    fn the_load_ceiling_key_round_trips_and_points_the_way_its_english_does() {
        use MeshConfigKey as K;
        let spec = K::LoadCeiling.spec();

        assert_eq!(spec.wire_name, "load.ceiling");
        assert_eq!(K::from_wire("load.ceiling"), Some(K::LoadCeiling));
        assert_eq!(K::LoadCeiling.dimension(), "mesh_config:load.ceiling:v1");
        assert_eq!(
            K::from_dimension("mesh_config:load.ceiling:v1"),
            Some(K::LoadCeiling)
        );
        assert_eq!(
            serde_json::to_string(&K::LoadCeiling).expect("serialize"),
            "\"load.ceiling\""
        );
        assert_eq!(
            serde_json::from_str::<K>("\"load.ceiling\"").expect("deserialize"),
            K::LoadCeiling
        );

        // Typed to the ONE field it names (#602's discipline): a count of
        // concurrent background tasks, on neither redundancy axis.
        assert_eq!(spec.unit, MeshConfigUnit::Count);
        assert_eq!(
            spec.polarity,
            FlowPolarity::HigherMeansMoreFlow,
            "a HIGHER ceiling lets the node carry MORE background work at once. On the other \
             arm the fold would relieve a stalled node by raising its ceiling."
        );
        // A ceiling of 0 is a halt, not relief — the halt is the other tier of
        // the graded response, with different authority and no TTL.
        assert_eq!(
            spec.min, 1,
            "`load.ceiling` must not be able to express 0: a node that does no background work \
             never converges, and stopping a node is the halt plane's act, not this one's"
        );
        assert!(
            K::LoadCeiling.in_domain(spec.owner_default),
            "the consent ceiling must itself be settable"
        );
        assert!(!K::LoadCeiling.in_domain(0), "0 is out of domain");

        // relieve-never-expand, in this key's own terms.
        assert!(
            K::LoadCeiling.expands_beyond(64, 8),
            "raising a node's ceiling is EXPANSION and no root may do it"
        );
        assert!(
            !K::LoadCeiling.expands_beyond(8, 64),
            "lowering it is relief, which is the whole point of the key"
        );
        assert_eq!(K::LoadCeiling.more_restrictive_of(64, 8), 8);
        assert_eq!(K::LoadCeiling.clamp_to_consent(64, 8), 8);
    }

    /// **Plural roots, and the LOWER ceiling binds.**
    ///
    /// The safety argument for letting several trust roots turn one knob is
    /// that this key can only ever lower it, so their answers compose without
    /// their agreement. That is only true if the fold takes the tighter one —
    /// and "tighter" is a per-key fact, not `min` (three of the twelve keys
    /// invert it), so it is asserted here rather than assumed from arithmetic.
    ///
    /// Constructed so the wrong answers are distinguishable: `root-b` is the
    /// LATER root alphabetically, files the LATER row, and asks for the TIGHTER
    /// value — so a fold that took the last root, the newest row, the first
    /// root, or the higher value would each answer something other than 6.
    #[test]
    fn the_lower_load_ceiling_binds_when_two_roots_disagree() {
        use MeshConfigKey as K;
        let base = MeshConfigBaseline::owner_defaults().with(K::LoadCeiling, 32);
        let roots = vec!["root-a".to_owned(), "root-b".to_owned()];
        let rows = vec![
            row(
                "m-lc-a",
                "root-a",
                "root-a",
                K::LoadCeiling,
                24,
                "2026-08-03T10:00:00Z",
                None,
            ),
            row(
                "m-lc-b",
                "root-b",
                "root-b",
                K::LoadCeiling,
                6,
                "2026-08-03T11:00:00Z",
                None,
            ),
        ];
        let fold = fold_mesh_config("node-1", &base, &roots, &rows, ts(NOW));
        let s = fold.setting(K::LoadCeiling).expect("registered key");

        assert_eq!(s.baseline, 32, "what this node's owner consented to");
        assert_eq!(
            s.effective, 6,
            "most-restrictive-across-roots: the LOWER ceiling binds. 24 would be the answer of \
             every wrong fold — last root, newest row, or the looser value"
        );
        assert_eq!(fold.effective(K::LoadCeiling), 6);
        assert!(s.relieved);
        assert_eq!(s.decided_by_root.as_deref(), Some("root-b"));
        assert_eq!(s.row_id.as_deref(), Some("m-lc-b"));

        // Evidence, not verdict: the root that LOST is still carried, so an
        // operator can see the two roots disagreed rather than only the answer.
        assert_eq!(s.per_root.len(), 2);
        assert_eq!(s.per_root[0].root_ref, "root-a");
        assert_eq!(s.per_root[0].asked, 24);
        assert_eq!(s.per_root[1].asked, 6);
        // Neither root expanded, so neither is named as clamped — 24 and 6 are
        // both beneath the node's own 32.
        assert!(s.clamped_roots.is_empty());

        // And the direction is the only thing holding: a root asking to RAISE
        // the ceiling contributes the baseline and is named for it.
        let greedy = vec![row(
            "m-lc-greedy",
            "root-a",
            "root-a",
            K::LoadCeiling,
            4096,
            "2026-08-03T12:00:00Z",
            None,
        )];
        let fold = fold_mesh_config("node-1", &base, &roots[..1], &greedy, ts(NOW));
        let s = fold.setting(K::LoadCeiling).expect("registered key");
        assert_eq!(
            s.effective, 32,
            "a root may not make a node busier than its owner consented to"
        );
        assert!(!s.relieved);
        assert_eq!(s.clamped_roots, vec!["root-a".to_owned()]);
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
    /// A midpoint would have been more realistic and is wrong here: the three
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
            // three Flag keys.
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
                        if (ri + step as usize).is_multiple_of(2) {
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
                K::RedundancyKRepairSymbols,
                8,
                "2026-08-03T10:00:00Z",
                None,
            ),
            row(
                "m2",
                "root-b",
                "root-b",
                K::RedundancyKRepairSymbols,
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

        let hi = fold.setting(K::RedundancyKRepairSymbols).unwrap();
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
        let base = MeshConfigBaseline::owner_defaults().with(K::RedundancyKRepairSymbols, 15);
        let roots = vec!["root-loose".to_owned(), "root-tight".to_owned()];
        let rows = vec![
            row(
                "m1",
                "root-loose",
                "root-loose",
                K::RedundancyKRepairSymbols,
                15,
                "2026-08-03T11:00:00Z",
                None,
            ),
            row(
                "m2",
                "root-tight",
                "root-tight",
                K::RedundancyKRepairSymbols,
                4,
                "2026-08-03T10:00:00Z",
                None,
            ),
        ];
        let fold = fold_mesh_config("node-1", &base, &roots, &rows, ts(NOW));
        let s = fold.setting(K::RedundancyKRepairSymbols).unwrap();
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
                K::RedundancyKRepairSymbols,
                12,
                "2026-08-03T10:00:00Z",
                None,
            ),
            row(
                "b",
                "r2",
                "r2",
                K::RedundancyKRepairSymbols,
                6,
                "2026-08-03T11:00:00Z",
                None,
            ),
            row(
                "c",
                "r3",
                "r3",
                K::RedundancyKRepairSymbols,
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
        assert_eq!(expected.effective(K::RedundancyKRepairSymbols), 6);
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
                K::RedundancyKRepairSymbols,
                20,
                "2026-08-03T10:00:00Z",
                None,
            ),
            row(
                "aaa-tight",
                "r",
                "r",
                K::RedundancyKRepairSymbols,
                5,
                "2026-08-03T10:00:00Z",
                None,
            ),
        ];
        let fold = fold_mesh_config("n", &base, &roots, &rows, ts(NOW));
        assert_eq!(
            fold.effective(K::RedundancyKRepairSymbols),
            5,
            "restriction must win a same-instant tie; picking by attestation_id would answer 20 \
             for `aaa-tight` < `zzz-loose`"
        );
        // Reversed input order: same answer.
        let mut rev = rows.clone();
        rev.reverse();
        assert_eq!(
            fold_mesh_config("n", &base, &roots, &rev, ts(NOW))
                .effective(K::RedundancyKRepairSymbols),
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
                K::RedundancyKRepairSymbols,
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
            fold.effective(K::RedundancyKRepairSymbols),
            K::RedundancyKRepairSymbols.owner_default(),
            "an expired emergency must stop binding without anyone revoking it"
        );
        assert_eq!(
            fold.effective(K::AntientropyRoundSecs),
            K::AntientropyRoundSecs.owner_default(),
            "a future-dated row has not taken effect"
        );
        assert!(fold
            .setting(K::RedundancyKRepairSymbols)
            .unwrap()
            .per_root
            .is_empty());

        // Wound back one hour, the SAME row set binds — proving the drop is
        // the TTL and not a parse failure.
        let earlier = fold_mesh_config("n", &base, &roots, &rows, ts("2026-08-03T10:00:00Z"));
        assert_eq!(earlier.effective(K::RedundancyKRepairSymbols), 4);
        assert_eq!(
            earlier
                .setting(K::RedundancyKRepairSymbols)
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
            K::RedundancyKRepairSymbols,
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
            fold.effective(K::RedundancyKRepairSymbols),
            K::RedundancyKRepairSymbols.owner_default()
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
                K::RedundancyKRepairSymbols,
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
            fold.effective(K::RedundancyKRepairSymbols),
            K::RedundancyKRepairSymbols.owner_default(),
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
            K::RedundancyKRepairSymbols,
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
            fold.effective(K::RedundancyKRepairSymbols),
            K::RedundancyKRepairSymbols.owner_default(),
            "a garbled TTL must drop the row, not grant it eternal life"
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // The executed door — every backend persist ships
    // ══════════════════════════════════════════════════════════════════

    /// v62.0.0 (slice E6) — the seed each registered kid was put from, so a
    /// fixture handed a kid signs with its key.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn seeds() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
        static SEEDS: std::sync::OnceLock<
            std::sync::Mutex<std::collections::HashMap<String, String>>,
        > = std::sync::OnceLock::new();
        SEEDS.get_or_init(Default::default)
    }

    /// The seed of a registered kid (any other text is its own seed).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn seed_of(key: &str) -> String {
        seeds()
            .lock()
            .expect("seed map")
            .get(key)
            .cloned()
            .unwrap_or_else(|| key.to_owned())
    }

    /// Register the key of `seed`: v62.0.0, its edition-2 `key:record`
    /// (`fixture_switch::put_key`). Returns its kid; the bodies name every
    /// key by kid after registering it.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn register(dir: &dyn FederationDirectory, seed: &str) -> String {
        let k = crate::federation::edition2::fixture_switch::put_key(
            dir,
            seed,
            &[crate::federation::types::identity_type::AGENT],
        )
        .await;
        seeds()
            .lock()
            .expect("seed map")
            .insert(k.clone(), seed.to_owned());
        k
    }

    /// A really-hybrid-signed `delegates_to` carrying a `trust:*` job label.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn trust_edge(id: &str, from: &str, to: &str, job: &str) -> Attestation {
        let envelope = serde_json::json!({
            "dimension": job,
            "scope": ["infra:attest", "infra:serve"],
        });
        let now = Utc::now();
        let sealed_row_ = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: from.to_owned(),
            attested_key_id: to.to_owned(),
            attestation_type: attestation_type::DELEGATES_TO.to_owned(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
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
        };
        // v62.0.0 — signed once, as an edition-2 statement; its id computed.
        crate::federation::edition2::fixture_switch::row_of(&sealed_row_, &seed_of(from))
    }

    /// A really-hybrid-signed mesh-config row, ready for the real door.
    #[allow(clippy::too_many_arguments)]
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn signed_config_row(
        author: &str,
        root: &str,
        key: MeshConfigKey,
        value: i64,
        form: MeshConfigForm,
        asserted_at: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        ratifies: Option<&str>,
    ) -> Attestation {
        let envelope =
            mesh_config_envelope(key, value, root, form, valid_until, ratifies, "congestion");
        let sealed_row_ = Attestation {
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
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
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
        };
        // v62.0.0 — signed once, as an edition-2 statement; its id computed.
        crate::federation::edition2::fixture_switch::row_of(&sealed_row_, &seed_of(author))
    }

    /// v62.0.0 (R2-rest-b3) — `st` re-signed by holder seed `seed` with
    /// `refs.head` naming the bundle in force (its first tip), as a
    /// mesh-config row must (CC 4.2.1; interim pending Constitution).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn with_bundle_head(dir: &dyn FederationDirectory, st: &[u8], seed: u8) -> Vec<u8> {
        use crate::federation::edition2::fixture_genesis as fg;
        use ciris_verify_core::cde::Value;
        let tip = crate::federation::edition2::genesis::genesis_in_force(dir)
            .await
            .expect("the bundle reads")
            .tips()
            .first()
            .expect("a bundle in force")
            .object_id;
        let (protected, payload) =
            crate::federation::edition2::liveness::statement_parts(st).expect("a statement");
        let text = |k: i64| {
            protected
                .get_int(k)
                .and_then(Value::as_text)
                .expect("a header member")
                .to_owned()
        };
        let sub = protected
            .get_int(15)
            .and_then(|c| c.get_int(2))
            .and_then(Value::as_text)
            .expect("sub")
            .to_owned();
        let Value::Map(mut m) = payload else {
            panic!("a map payload");
        };
        m.retain(|(k, _)| k.as_text() != Some("refs"));
        m.push((
            Value::Text("refs".into()),
            Value::Map(vec![(
                Value::Text("head".into()),
                ciris_verify_core::edition2::row_ref(&tip),
            )]),
        ));
        m.sort_by_key(|(k, _)| ciris_verify_core::cde::encode(k));
        ciris_verify_core::edition2::sign_row_statement(
            &fg::test_key(seed),
            &fg::identity_ref_of(seed),
            &sub,
            &text(-70001),
            &text(-70002),
            &Value::Map(m),
            vec![],
        )
        .expect("the headed row signs")
    }

    /// v62.0.0 (R2-rest-b2) — holder `i`'s (of `fixture_genesis::HOLDER_SEEDS`)
    /// mesh-config statement filed against the lineage `root`, and the row
    /// this node admits it as: over the keys it HOLDS (the bundle places a
    /// holder's key; RL-fix10), never a fixture seed map.
    #[allow(clippy::too_many_arguments)]
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn holder_config_row(
        dir: &dyn FederationDirectory,
        i: usize,
        root: &str,
        key: MeshConfigKey,
        value: i64,
        form: MeshConfigForm,
        asserted_at: DateTime<Utc>,
        valid_until: Option<DateTime<Utc>>,
        ratifies: Option<&str>,
    ) -> (Vec<u8>, Attestation) {
        use crate::federation::edition2::fixture_genesis as fg;
        use crate::federation::edition2::fixture_switch as e2;
        use crate::federation::edition2::ingest;
        let seed = fg::HOLDER_SEEDS[i];
        let author = fg::identity_ref_of(seed);
        let a = Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: author.clone(),
            attested_key_id: root.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: mesh_config_envelope(
                key,
                value,
                root,
                form,
                valid_until,
                ratifies,
                "congestion",
            ),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: author,
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        let st = e2::statement_of_with_key(&a, &fg::test_key(seed), &e2::family_of(&a));
        // v62.0.0 (R2-rest-b3) — a mesh-config row names its root's bundle.
        let st = with_bundle_head(dir, &st, seed).await;
        let keys = ingest::held_keys_for(dir, &st)
            .await
            .unwrap_or_else(|e| panic!("holder {i}'s key reads: {e}"));
        let admitted = crate::federation::edition2::door::admit_row(
            &st,
            &keys,
            None,
            ciris_verify_core::edition2::family::SelectContext::default(),
        )
        .unwrap_or_else(|e| panic!("holder {i}'s row admits: {e}"));
        let row = ingest::attestation_of(&admitted, ingest::INGEST_TIER)
            .unwrap_or_else(|e| panic!("holder {i}'s row maps: {e}"));
        (st, row)
    }

    /// v62.0.0 (R2-rest-b2) — holder `i`'s voice over the payload of the
    /// statement `st` (the same header and payload, its own `iss` and key):
    /// how a second holder joins a counted row.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    fn holder_voice(st: &[u8], i: usize) -> Vec<u8> {
        use crate::federation::edition2::fixture_genesis as fg;
        use ciris_verify_core::cde::Value;
        let (protected, payload) =
            crate::federation::edition2::liveness::statement_parts(st).expect("a statement");
        let text = |k: i64| {
            protected
                .get_int(k)
                .and_then(Value::as_text)
                .expect("a header member")
                .to_owned()
        };
        let sub = protected
            .get_int(15)
            .and_then(|c| c.get_int(2))
            .and_then(Value::as_text)
            .expect("sub")
            .to_owned();
        let seed = fg::HOLDER_SEEDS[i];
        ciris_verify_core::edition2::sign_row_statement(
            &fg::test_key(seed),
            &fg::identity_ref_of(seed),
            &sub,
            &text(-70001),
            &text(-70002),
            &payload,
            vec![],
        )
        .expect("the holder's voice signs")
    }

    /// v62.0.0 (R2-rest-b2) — stand `dir`'s node up under the test bundle's
    /// lineage (`fixture_trust_root::rooted_trust_root`: the bundle installed
    /// when none is held, the node's acceptance edge landed). Returns what it
    /// stood up and the node's kid. Precondition: the runner set
    /// `dir.node_key_id()`.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn rooted(
        dir: &dyn FederationDirectory,
    ) -> (
        crate::federation::edition2::fixture_trust_root::RootedTrustRoot,
        String,
    ) {
        use crate::federation::edition2::fixture_genesis as fg;
        let r = crate::federation::edition2::fixture_trust_root::rooted_trust_root(
            dir,
            &fg::HOLDER_SEEDS,
            "quorum:2/3",
        )
        .await;
        let node = dir.node_key_id().expect("the runner set the node key");
        (r, node)
    }

    /// **The whole plane, driven through the REAL doors, on one backend.**
    ///
    /// Every gate below runs against rows that were actually stored by
    /// `put_attestation` and read back by `list_attestations_*` — never against
    /// a hand-built `Error`. The "code-path-exists ≠ host-reachable" class this
    /// repo has been bitten by repeatedly is what this exists to close.
    ///
    /// v62.0.0 (R2-rest-b2; CC 4.2.1 "Mesh-config authorship" at pre4,
    /// Constitution 11-24 "MESH-CONFIG HAS NO DELEGATE") — **the shape**: one
    /// node ROOTED under the test bundle's lineage (its owner accepted it);
    /// the bundle's three holders author; a KEY the node also holds an edge
    /// to; a user key holding the root's accepted COUNTED grant; a stranger.
    /// The earlier shape (two KEY roots, each authoring as itself, and a
    /// delegate conferred by one signature) witnessed the keyed root and the
    /// delegate leg, both deleted.
    ///
    /// - **I6413** a key holding the root's accepted counted grant (it
    ///   confers, `root_grants_for`) is refused `author_not_root_authorized`
    ///   for emergency relief and for a durable setting, naming the grant as
    ///   its `delegation_id`: no grant confers mesh-config authority; nothing
    ///   it filed binds at the read.
    /// - **I6414** a durable row RATIFYING a held emergency, signed by one
    ///   holder alone, is refused `durable_without_root_quorum`; a second
    ///   holder's voice admits it (CC 4.2.1 rule 3: "two routes to one
    ///   authority"). Before, one holder made its own relief permanent.
    /// - **I6407** (rewritten) a KEY is no config root: its own durable row
    ///   filed against itself is refused `root_not_trusted` although this
    ///   node holds an acceptance edge to it, and the fold reads the lineage
    ///   alone (`config_roots`).
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn mesh_config_door_body(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::edition2::fixture_genesis as fg;
        use MeshConfigKey as K;
        let (r, node) = rooted(dir).await;
        let root = r.lineage.clone();
        let holder = |i: usize| fg::identity_ref_of(fg::HOLDER_SEEDS[i]);
        let key_root = register(dir, &format!("mc-keyroot-{tag}")).await;
        let stranger = register(dir, &format!("mc-stranger-{tag}")).await;
        let outsider = register(dir, &format!("mc-outsider-{tag}")).await;

        // The node ALSO holds an acceptance edge to a KEY (an acceptance of
        // kind C): before R2-rest-b2 that key was a config root that authored
        // as itself.
        dir.put_attestation(super::super::SignedAttestation {
            attestation: trust_edge(
                &uuid::Uuid::new_v4().to_string(),
                &node,
                &key_root,
                crate::federation::trust_root::TRUST_ACCEPTS_DIMENSION,
            ),
        })
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the edge to the key must admit: {e}"));
        let now = crate::federation::admission::truncate_to_substrate_resolution(Utc::now());
        let subscribed = crate::federation::trust_root::trusted_roots_of(dir, &node, now)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] trusted_roots_of: {e}"));
        assert!(
            subscribed.contains(&root) && subscribed.contains(&key_root),
            "[{tag}] precondition: the node's edges name the lineage and the key: {subscribed:?}"
        );

        // The root's accepted COUNTED grant to a user key: it confers.
        let deleg_seed = format!("mc-deleg-{tag}");
        let grant = crate::federation::edition2::fixture_trust_root::put_conferral(
            dir,
            &r,
            &deleg_seed,
            &[crate::federation::trust_root::INFRA_SERVE_SCOPE],
        )
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the root's counted grant lands: {e}"));
        let delegate = crate::federation::edition2::fixture_switch::kid(&deleg_seed);
        seeds()
            .lock()
            .expect("seed map")
            .insert(delegate.clone(), deleg_seed.clone());
        assert!(
            crate::federation::admission::root_grants_for(
                dir,
                &delegate,
                crate::host::clock::now() + Duration::seconds(1)
            )
            .await
            .unwrap_or_else(|e| panic!("[{tag}] root_grants_for: {e}"))
            .iter()
            .any(|g| g.row_id == grant.hex() && g.confers),
            "[{tag}] I6413 precondition: the counted grant is accepted and confers"
        );

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
        macro_rules! by_holder {
            ($i:expr, $key:expr, $value:expr, $form:expr, $at:expr, $until:expr, $ratifies:expr) => {
                holder_config_row(dir, $i, &root, $key, $value, $form, $at, $until, $ratifies).await
            };
        }

        // ── 1. THE HAPPY PATH: one holder relieves. #570's headline, "20
        //       copies -> 10", in the form CC 4.2.1 gives one holder: bounded
        //       emergency relief.
        let (_, relief) = by_holder!(
            0,
            K::RedundancyKRepairSymbols,
            10,
            MeshConfigForm::Emergency,
            now - Duration::hours(1),
            Some(now + Duration::hours(24)),
            None
        );
        assert_eq!(
            door!(relief),
            MeshConfigOutcome::Admitted,
            "[{tag}] 20 copies -> 10 is relief and must admit"
        );

        // ── 2. I6413 — NO DELEGATE. The root's grantee, naming the grant.
        for (what, form, until) in [
            (
                "emergency relief",
                MeshConfigForm::Emergency,
                Some(now + Duration::hours(24)),
            ),
            ("a durable setting", MeshConfigForm::Durable, None),
        ] {
            let row = signed_config_row(
                &delegate,
                &root,
                K::AntientropyRoundSecs,
                600,
                form,
                now - Duration::hours(1),
                until,
                None,
            );
            assert_eq!(
                door!(row),
                MeshConfigOutcome::Refused {
                    reason: MeshConfigRefusalReason::AuthorNotRootAuthorized
                },
                "[{tag}] I6413: the root's grantee may not author {what}: no grant and no scope \
                 word confers mesh-config authority (Constitution 11-24)"
            );
        }

        // ── 3. I6407 (rewritten) — a KEY is no config root, the node's edge to
        //       it notwithstanding.
        let by_key = signed_config_row(
            &key_root,
            &key_root,
            K::FeatureAvStreams,
            0,
            MeshConfigForm::Durable,
            now - Duration::hours(1),
            None,
            None,
        );
        assert_eq!(
            door!(by_key),
            MeshConfigOutcome::Refused {
                reason: MeshConfigRefusalReason::RootNotTrusted
            },
            "[{tag}] I6407: a key is no root: its own row filed against itself subscribes to \
             nothing at this node"
        );

        // ── 4. Every refusal branch, on the real door. Each differs from an
        //       ADMITTED row in exactly one input.
        let ago = now - Duration::hours(1);
        let mut refusals: Vec<(&str, Attestation, MeshConfigRefusalReason)> = vec![
            (
                "an unsubscribed root has nothing to say to this node",
                signed_config_row(
                    &stranger,
                    &stranger,
                    K::AntientropyPageLimit,
                    50,
                    MeshConfigForm::Durable,
                    ago,
                    None,
                    None,
                ),
                MeshConfigRefusalReason::RootNotTrusted,
            ),
            (
                "an author who holds no seat of the bundle in force",
                signed_config_row(
                    &outsider,
                    &root,
                    K::AntientropyPageLimit,
                    50,
                    MeshConfigForm::Emergency,
                    ago,
                    Some(now + Duration::hours(24)),
                    None,
                ),
                MeshConfigRefusalReason::AuthorNotRootAuthorized,
            ),
        ];
        for (why, key, value, form, until, ratifies, expected) in [
            (
                "relieve-never-expand at the door: 40 copies is MORE than the 20 consented",
                K::RedundancyKRepairSymbols,
                40,
                MeshConfigForm::Durable,
                None,
                None,
                MeshConfigRefusalReason::ExpandsBeyondConsent,
            ),
            (
                "relieve-never-expand on the LowerMeansMoreFlow arm: 5s is MORE gossip than 60s",
                K::AntientropyRoundSecs,
                5,
                MeshConfigForm::Durable,
                None,
                None,
                MeshConfigRefusalReason::ExpandsBeyondConsent,
            ),
            (
                "emergency relief with no TTL is not relief, it is government",
                K::AntientropyPageLimit,
                50,
                MeshConfigForm::Emergency,
                None,
                None,
                MeshConfigRefusalReason::TtlMissing,
            ),
            (
                "an emergency window beyond 72h",
                K::AntientropyPageLimit,
                50,
                MeshConfigForm::Emergency,
                Some(now + Duration::hours(100)),
                None,
                MeshConfigRefusalReason::TtlTooLong,
            ),
            (
                "a durable row NAMING a ratification that resolves to nothing (distinct from a \
              cold durable, which names none and is judged on quorum)",
                K::AntientropyPageLimit,
                50,
                MeshConfigForm::Durable,
                None,
                Some("00000000-0000-0000-0000-000000000000"),
                MeshConfigRefusalReason::DurableUnratified,
            ),
            (
                "a value outside the key's declared domain",
                K::AntientropyRoundSecs,
                999_999,
                MeshConfigForm::Durable,
                None,
                None,
                MeshConfigRefusalReason::ValueOutOfDomain,
            ),
        ] {
            let (_, row) = by_holder!(0, key, value, form, ago, until, ratifies);
            refusals.push((why, row, expected));
        }
        for (why, row, expected) in refusals {
            assert_eq!(
                door!(row),
                MeshConfigOutcome::Refused { reason: expected },
                "[{tag}] {why}"
            );
        }

        // ── 4b. The CLOSED REGISTRY (CC 4.2.1 rule 2) and a misfiled row. The three
        //        gates read the row alone, ahead of the signature; each is the
        //        holder's admitted row edited after admission, which only those
        //        gates see.
        // v62.0.0 (R2-rest-b3) — the `unattributed` leg (#570 ask 3) is DELETED
        // with the `delegation_id` member: the refusal is produced by nothing.
        let (_, mut unknown) = by_holder!(
            0,
            K::AntientropyPageLimit,
            50,
            MeshConfigForm::Durable,
            ago,
            None,
            None
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
        let (_, mut misfiled) = by_holder!(
            0,
            K::AntientropyPageLimit,
            50,
            MeshConfigForm::Durable,
            ago,
            None,
            None
        );
        misfiled.attested_key_id = node.clone();
        assert_eq!(
            door!(misfiled),
            MeshConfigOutcome::Refused {
                reason: MeshConfigRefusalReason::NotFiledAgainstRoot
            },
            "[{tag}] a row the fold cannot find is not a row"
        );

        // ── 5. THE BACK-TO-BACK RENEWAL BAN (CC 4.2.1 rule 3). One emergency
        //       admits; a second from the SAME holder whose window opens before
        //       the first closes is kept and concludes nothing. The window
        //       closes two minutes from `now` and em3 opens four minutes ahead:
        //       inside #598's five-minute skew guard (see the earlier note on
        //       this chronology; the rule is a relative comparison).
        let (_, em1) = by_holder!(
            0,
            K::AntientropyPageLimit,
            50,
            MeshConfigForm::Emergency,
            now - Duration::hours(2),
            Some(now + Duration::minutes(2)),
            None
        );
        assert_eq!(
            door!(em1.clone()),
            MeshConfigOutcome::Admitted,
            "[{tag}] a bounded emergency relief must admit"
        );
        let (_, em2) = by_holder!(
            0,
            K::AntientropyPageLimit,
            40,
            MeshConfigForm::Emergency,
            now - Duration::hours(1),
            Some(now + Duration::hours(48)),
            None
        );
        let em2_id = em2.attestation_id.clone();
        assert_eq!(
            door!(em2),
            MeshConfigOutcome::Kept {
                reason: MeshConfigRefusalReason::BackToBackRenewal
            },
            "[{tag}] CC 4.2.1 rule 3: a back-to-back renewal is kept and concludes nothing"
        );
        assert!(
            dir.get_attestation(&em2_id).await.unwrap().is_some(),
            "[{tag}] I3918: the kept renewal is stored (the fold does not count it)"
        );
        let (_, em3) = by_holder!(
            0,
            K::AntientropyPageLimit,
            40,
            MeshConfigForm::Emergency,
            now + Duration::minutes(4),
            Some(now + Duration::hours(48)),
            None
        );
        assert_eq!(
            door!(em3),
            MeshConfigOutcome::Admitted,
            "[{tag}] a fresh window after the last one closed is not a renewal"
        );

        // ── 6. I6414 — THE DURABLE RATIFICATION is the QUORUM's act. One
        //       holder ratifying its own held emergency is short; a second
        //       holder's voice over the same row admits it.
        let (st, durable) = by_holder!(
            0,
            K::AntientropyPageLimit,
            50,
            MeshConfigForm::Durable,
            now - Duration::hours(1),
            None,
            Some(em1.attestation_id.as_str())
        );
        let _held =
            crate::federation::edition2::fixture_switch::put_held(dir, &st, "I6414: holder 0's")
                .await;
        assert_eq!(
            door!(durable.clone()),
            MeshConfigOutcome::Refused {
                reason: MeshConfigRefusalReason::DurableWithoutRootQuorum
            },
            "[{tag}] I6414: one holder does not make its own relief permanent"
        );
        let _ =
            crate::federation::edition2::fixture_switch::put_statement(dir, &holder_voice(&st, 1))
                .await;
        assert_eq!(
            door!(durable),
            MeshConfigOutcome::Admitted,
            "[{tag}] I6414: two of three holders ratify the held emergency"
        );

        // ── 7. THE READ SIDE, through the real reads. Holder 1 relieves the
        //       same key more tightly than holder 0 did.
        let (_, tighter) = by_holder!(
            1,
            K::RedundancyKRepairSymbols,
            4,
            MeshConfigForm::Emergency,
            now - Duration::hours(1),
            Some(now + Duration::hours(24)),
            None
        );
        assert_eq!(
            door!(tighter),
            MeshConfigOutcome::Admitted,
            "[{tag}] another holder's relief is not holder 0's renewal"
        );
        let fold = resolve_mesh_config(dir, &node, &base, now)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] resolve: {e}"));
        assert_eq!(
            fold.roots,
            vec![root.clone()],
            "[{tag}] I6407: the lineage is the one config root; the key the node also \
             accepted is none"
        );
        let s = fold
            .setting(K::RedundancyKRepairSymbols)
            .unwrap_or_else(|| panic!("[{tag}] key present"));
        assert_eq!(
            s.effective, 4,
            "[{tag}] the tighter relief binds over the looser on the real read path"
        );
        assert_eq!(s.decided_by.as_deref(), Some(holder(1).as_str()));
        assert_eq!(s.decided_by_root.as_deref(), Some(root.as_str()));
        assert_eq!(
            fold.effective(K::AntientropyRoundSecs),
            base.get(K::AntientropyRoundSecs),
            "[{tag}] I6413: the grantee's rows bind nothing"
        );
        assert_eq!(
            fold.effective(K::AntientropyPageLimit),
            50,
            "[{tag}] the live rows for this key are the emergency at 50 and the durable that \
             ratified it, also 50. The tighter emergency at 40 was admitted with an \
             `asserted_at` FOUR MINUTES in the future, so it has not started (the unbounded \
             claim is pinned on the pure fold by \
             `ttl_expired_rows_drop_at_read_time_and_future_rows_have_not_started`)"
        );
        assert!(
            !fold.roots.contains(&stranger),
            "[{tag}] an unsubscribed root must not appear in the fold"
        );
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

    /// v62.0.0 (R2-rest-b2; Lead, after the rootless READ: "ROOTLESS is a
    /// supported state", the mesh runs) — **I6415: a ROOTLESS node runs its own
    /// baseline.** The bundle is held (its holders' keys are placed), the node
    /// has accepted no lineage:
    ///
    /// - `resolve_mesh_config` folds NO root and every key's effective value
    ///   is the owner's baseline;
    /// - a holder's well-formed emergency relief, filed against the lineage,
    ///   is refused `root_not_trusted` (held under a fold attempt) and binds
    ///   nothing;
    /// - once the node accepts the lineage, the same row is admitted and
    ///   binds: the refusal was the subscription's, not the row's.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn rootless_baseline_body(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::edition2::fixture_genesis as fg;
        use MeshConfigKey as K;
        fg::install_ceremony_v2(dir, fg::bundle_v2_wide())
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the bundle installs: {e}"));
        let root = crate::federation::edition2::genesis::genesis_in_force(dir)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the bundle reads: {e}"))
            .family_key_id()
            .expect("a bundle in force")
            .to_owned();
        let node = dir.node_key_id().expect("the runner set the node key");
        let now = crate::federation::admission::truncate_to_substrate_resolution(Utc::now());
        let base = MeshConfigBaseline::owner_defaults();
        let baseline_only = |fold: &MeshConfigFold, when: &str| {
            assert!(
                fold.roots.is_empty(),
                "[{tag}] I6415 {when}: no root: {:?}",
                fold.roots
            );
            for k in MeshConfigKey::ALL {
                assert_eq!(
                    fold.effective(*k),
                    base.get(*k),
                    "[{tag}] I6415 {when}: {k} runs at the owner's baseline"
                );
            }
        };
        let fold = resolve_mesh_config(dir, &node, &base, now)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] resolve: {e}"));
        baseline_only(&fold, "before any row");
        let (_, relief) = holder_config_row(
            dir,
            0,
            &root,
            K::LoadCeiling,
            8,
            MeshConfigForm::Emergency,
            now - Duration::hours(1),
            Some(now + Duration::hours(24)),
            None,
        )
        .await;
        assert_eq!(
            record_mesh_config_row(dir, &node, &base, &relief, now)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] door errored rather than refusing: {e}")),
            MeshConfigOutcome::Refused {
                reason: MeshConfigRefusalReason::RootNotTrusted
            },
            "[{tag}] I6415: a rootless node subscribes to no root"
        );
        let fold = resolve_mesh_config(dir, &node, &base, now)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] resolve: {e}"));
        baseline_only(&fold, "after the holder's relief");

        // CONTROL — the node's owner accepts the lineage: the same row binds.
        let (accepted, _) = rooted(dir).await;
        assert_eq!(accepted.lineage, root, "[{tag}] one lineage");
        assert_eq!(
            record_mesh_config_row(dir, &node, &base, &relief, now)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] door errored rather than refusing: {e}")),
            MeshConfigOutcome::Admitted,
            "[{tag}] I6415 CONTROL: rooted, the holder's relief is admitted"
        );
        let fold = resolve_mesh_config(dir, &node, &base, now)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] resolve: {e}"));
        assert_eq!(fold.roots, vec![root.clone()], "[{tag}] I6415 CONTROL");
        assert_eq!(
            fold.effective(K::LoadCeiling),
            8,
            "[{tag}] I6415 CONTROL: the relief binds once the lineage is accepted"
        );
    }

    /// v62.0.0 (KB-fix1; CC 3.2 at rc22 `87abd2d`, CC 4.2.1 rule 3) —
    /// **I2410–I2411: a durable setting rooted at the BUNDLE root lands at
    /// the accord's threshold over the holders in force.** The node accepts
    /// the bundle root (its `family_key_id`); a holder authors a COLD durable
    /// restriction (no ratified emergency):
    ///
    /// - **I2410** one holder's voice of three is short:
    ///   `durable_without_root_quorum` (`root_quorum_reached`'s bundle arm);
    /// - **I2411** a second holder's voice of the same row: two of three is
    ///   the strict majority, and the row is admitted.
    ///
    /// BELIEVED (unbuilt): that the second holder's voice is stored by the
    /// statement door as a voice of the row; the precondition is asserted, so
    /// a red names the voice store, not the count.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn bundle_root_durable_body(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::edition2::fixture_genesis as fg;
        use crate::federation::edition2::fixture_switch as e2;
        use ciris_verify_core::cde::Value;
        use MeshConfigKey as K;
        fg::install_v2(dir)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the ceremony installs: {e}"));
        let root = fg::FAMILY_KEY_ID;
        let in_force = crate::federation::edition2::genesis::genesis_in_force(dir)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the genesis reads: {e}"));
        let tip = hex::encode(in_force.tips().first().expect("a tip").object_id);
        let node_seed = format!("kb1-mc-node-{}", &tag[..tag.len().min(8)]);
        let node = e2::put_key(dir, &node_seed, &["node"]).await;
        let edge = crate::federation::edition2::fixture_trust_root::bundle_acceptance_statement(
            dir,
            &e2::signing_key(&node_seed),
            &node,
            &tip,
        )
        .await
        .unwrap_or_else(|e| panic!("[{tag}] the acceptance edge signs: {e}"));
        e2::put_statement(dir, &edge)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the node accepts the bundle root: {e}"));

        let now = Utc::now();
        let base = MeshConfigBaseline::owner_defaults();
        let author = fg::identity_ref_of(fg::HOLDER_SEEDS[0]);
        let a = Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: author.clone(),
            attested_key_id: root.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: now - Duration::hours(1),
            expires_at: None,
            attestation_envelope: mesh_config_envelope(
                K::FeatureAvStreams,
                0,
                root,
                MeshConfigForm::Durable,
                None,
                None,
                "congestion",
            ),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: author.clone(),
            scrub_timestamp: now - Duration::hours(1),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        let st =
            e2::statement_of_with_key(&a, &fg::test_key(fg::HOLDER_SEEDS[0]), &e2::family_of(&a));
        // v62.0.0 (R2-rest-b3) — the durable row names the bundle it is counted over.
        let unheaded = st.clone();
        let st = with_bundle_head(dir, &st, fg::HOLDER_SEEDS[0]).await;
        // v62.0.0 (FX-fix2) — the fixture codec keeps the literal root as
        // the row's `sub` (`RESERVED_LITERAL_SUBJECTS`); RL-fix21's re-sign
        // is no longer needed.
        // v62.0.0 (RL-fix24) — holder 0's statement through the door first:
        // one holder of three is short, so it is HELD (kept, waiting for a
        // second holder's voice), and holder 1's voice below is a voice of a
        // row this node holds (before this the row was only admitted
        // locally, so the voice had no row to join).
        let _reason = e2::put_held(dir, &st, &format!("[{tag}] I2410: holder 0's row")).await;
        // RL-fix10 — the holder's key is placed by the bundle, not by a
        // fixture seed, so the row is admitted over THIS node's held keys
        // (`ingest::held_keys_for`), never the fixture's seed map.
        let row = {
            let keys = crate::federation::edition2::ingest::held_keys_for(dir, &st)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] the holder's key reads: {e}"));
            let admitted = crate::federation::edition2::door::admit_row(
                &st,
                &keys,
                None,
                ciris_verify_core::edition2::family::SelectContext::default(),
            )
            .unwrap_or_else(|e| panic!("[{tag}] the holder's row admits: {e}"));
            crate::federation::edition2::ingest::attestation_of(
                &admitted,
                crate::federation::edition2::ingest::INGEST_TIER,
            )
            .unwrap_or_else(|e| panic!("[{tag}] the row maps: {e}"))
        };
        let door = |row: &Attestation| {
            let row = row.clone();
            let node = node.clone();
            let base = base.clone();
            async move {
                record_mesh_config_row(dir, &node, &base, &row, now)
                    .await
                    .unwrap_or_else(|e| panic!("[{tag}] the door errored: {e}"))
            }
        };
        assert_eq!(
            door(&row).await,
            MeshConfigOutcome::Refused {
                reason: MeshConfigRefusalReason::DurableWithoutRootQuorum
            },
            "[{tag}] I2410: one holder of three is short of the strict majority"
        );

        // A second holder's voice over the same payload.
        let voice = {
            let (protected, payload) =
                crate::federation::edition2::liveness::statement_parts(&st).expect("a statement");
            let text = |k: i64| {
                protected
                    .get_int(k)
                    .and_then(Value::as_text)
                    .expect("a header member")
                    .to_owned()
            };
            let sub = protected
                .get_int(15)
                .and_then(|c| c.get_int(2))
                .and_then(Value::as_text)
                .expect("sub")
                .to_owned();
            let key = fg::test_key(fg::HOLDER_SEEDS[1]);
            ciris_verify_core::edition2::sign_row_statement(
                &key,
                &fg::identity_ref_of(fg::HOLDER_SEEDS[1]),
                &sub,
                &text(-70001),
                &text(-70002),
                &payload,
                vec![],
            )
            .expect("the second voice signs")
        };
        let _ = e2::put_statement(dir, &voice).await;
        let row_id = crate::federation::edition2::voices::carried_row_id(&row).expect("a row id");
        let holders = crate::federation::admission::accord_holder_roster(dir)
            .await
            .expect("the holders read");
        assert!(
            crate::federation::edition2::voices::roster_voices(dir, &row_id, &holders)
                .await
                .expect("voices read")
                .contains(&fg::identity_ref_of(fg::HOLDER_SEEDS[1])),
            "[{tag}] precondition: the second holder's voice is held for the row"
        );
        assert_eq!(
            door(&row).await,
            MeshConfigOutcome::Admitted,
            "[{tag}] I2411: two of three holders in force is the accord's threshold"
        );

        // v62.0.0 (R2-rest-b3; CC 4.2.1 as ruled 11-24) — I6434: the same
        // durable row naming NO head is refused act_names_no_head.
        let unheaded_row = {
            let keys = crate::federation::edition2::ingest::held_keys_for(dir, &unheaded)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] keys read: {e}"));
            let admitted = crate::federation::edition2::door::admit_row(
                &unheaded,
                &keys,
                None,
                ciris_verify_core::edition2::family::SelectContext::default(),
            )
            .unwrap_or_else(|e| panic!("[{tag}] the unheaded row admits at the reader: {e}"));
            crate::federation::edition2::ingest::attestation_of(
                &admitted,
                crate::federation::edition2::ingest::INGEST_TIER,
            )
            .unwrap_or_else(|e| panic!("[{tag}] the row maps: {e}"))
        };
        assert!(
            matches!(
                record_mesh_config_row(dir, &node, &base, &unheaded_row, now).await,
                Err(Error::MalformedRow { reason, .. })
                    if reason == crate::federation::malformed_row::ACT_NAMES_NO_HEAD
            ),
            "[{tag}] I6434: a durable mesh-config row naming no head is refused act_names_no_head"
        );

        // A holder's relief naming THIS bundle, kept to offer after the
        // later bundle (I6436).
        let (_, old_relief) = holder_config_row(
            dir,
            0,
            root,
            K::LoadCeiling,
            8,
            MeshConfigForm::Emergency,
            now - Duration::hours(1),
            Some(now + Duration::hours(24)),
            None,
        )
        .await;

        // I6435 — a later bundle of the lineage (holders 1, 2, 4): the durable
        // setting counted under the first bundle KEEPS its standing.
        let later = fg::later_v2(
            fg::bundle_v2(),
            &[1, 2, 4],
            &fg::SERVE_NODE_SEEDS,
            &[1, 2, 4],
        );
        fg::install_ceremony_v2(dir, &later)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the later bundle installs: {e}"));
        let fold = resolve_mesh_config(dir, &node, &base, now)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] resolve: {e}"));
        assert_eq!(
            fold.effective(K::FeatureAvStreams),
            0,
            "[{tag}] I6435: a durable setting counted under an earlier bundle still stands \
             (a durable setting IS a grant)"
        );

        // I6436 — relief naming a bundle no longer in force is HELD
        // durable_without_root_quorum (interim pending Constitution).
        assert_eq!(
            record_mesh_config_row(dir, &node, &base, &old_relief, now)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] door errored: {e}")),
            MeshConfigOutcome::Refused {
                reason: MeshConfigRefusalReason::DurableWithoutRootQuorum
            },
            "[{tag}] I6436: relief names the bundle in force"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2410_bundle_root_durable_sqlite() {
        use crate::store::Backend;
        let dir = crate::store::SqliteBackend::open_in_memory()
            .await
            .expect("sqlite");
        dir.run_migrations().await.expect("migrations");
        Box::pin(bundle_root_durable_body(&dir, "sq")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2410_bundle_root_durable_postgres() {
        use crate::store::Backend;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let dir = crate::store::PostgresBackend::connect(&dsn)
            .await
            .expect("pg");
        dir.run_migrations().await.expect("migrations");
        Box::pin(bundle_root_durable_body(&dir, "pg")).await;
    }

    /// v62.0.0 (R2-rest-b2) — a fresh sqlite store whose node key is set
    /// (`seed`'s node key), as `fixture_trust_root::rooted_trust_root` needs.
    #[cfg(feature = "sqlite")]
    async fn sqlite_with_node(seed: &str) -> crate::store::SqliteBackend {
        use crate::store::Backend;
        let dir = crate::store::SqliteBackend::open_in_memory()
            .await
            .expect("sqlite");
        dir.run_migrations().await.expect("migrations");
        let node =
            crate::federation::edition2::fixture_switch::put_key(&dir, seed, &["node"]).await;
        dir.set_node_key_id(node);
        dir
    }

    /// The postgres twin of [`sqlite_with_node`], on a fresh database
    /// (`test_pg::empty_dsn`: the bundle is installed per store). `None`
    /// without a DSN.
    #[cfg(feature = "postgres")]
    async fn postgres_with_node(seed: &str) -> Option<crate::store::PostgresBackend> {
        use crate::store::Backend;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return None;
        };
        let dir = crate::store::PostgresBackend::connect(&dsn)
            .await
            .expect("pg");
        dir.run_migrations().await.expect("migrations");
        let node =
            crate::federation::edition2::fixture_switch::put_key(&dir, seed, &["node"]).await;
        dir.set_node_key_id(node);
        Some(dir)
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn mesh_config_door_and_fold_sqlite() {
        let dir = sqlite_with_node("mc-node-sq").await;
        Box::pin(mesh_config_door_body(&dir, "sq")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn mesh_config_door_and_fold_postgres() {
        let Some(dir) = postgres_with_node("mc-node-pg").await else {
            return;
        };
        Box::pin(mesh_config_door_body(&dir, "pg")).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i6415_a_rootless_node_runs_its_baseline_sqlite() {
        let dir = sqlite_with_node("mc-rootless-sq").await;
        Box::pin(rootless_baseline_body(&dir, "sq")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i6415_a_rootless_node_runs_its_baseline_postgres() {
        let Some(dir) = postgres_with_node("mc-rootless-pg").await else {
            return;
        };
        Box::pin(rootless_baseline_body(&dir, "pg")).await;
    }

    /// **CIRISPersist#777 — the node detects, the OWNER relieves.**
    ///
    /// `load.ceiling` is the key a stalling node has the most reason to want to
    /// set for itself, and the one it may least do so: CC 4.2.1.4 *"A node
    /// MUST NOT author a `mesh_config` value: that plane is the root's"*.
    /// CIRISServer#503 proposed the node-local form and was withdrawn on
    /// exactly that.
    ///
    /// v62.0.0 (R2-rest-b2) — on the lineage: the root is the bundle the
    /// node's owner accepted, and its author is a holder. Three claims, in
    /// the order that makes the refusals mean something:
    ///
    /// 1. a HOLDER's relief is **admitted** and binds — without this the other
    ///    two would pass on a key nothing can set at all, which is a witness
    ///    for nothing;
    /// 2. the same row, signed by the NODE under the lineage it accepted, is
    ///    refused `author_not_root_authorized`;
    /// 3. the node naming ITSELF as the root is refused `root_not_trusted`:
    ///    a node is no lineage. (The earlier leg first stored a self-charter
    ///    edge, `trust:accepts:v1` node → node, to show `trusted_roots_of`
    ///    drops self-edges; with the keyed root gone no edge to a key makes a
    ///    config root, `config_roots`, so that premise is deleted.)
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn node_authored_load_ceiling_body(dir: &dyn FederationDirectory, tag: &str) {
        use crate::federation::edition2::fixture_genesis as fg;
        use MeshConfigKey as K;
        let (r, node) = rooted(dir).await;
        let root = r.lineage;
        let seed = format!("lc-node-{tag}");
        seeds()
            .lock()
            .expect("seed map")
            .insert(node.clone(), seed.clone());

        let now = crate::federation::admission::truncate_to_substrate_resolution(Utc::now());
        let base = MeshConfigBaseline::owner_defaults();
        let relief_at = now - Duration::hours(1);
        // v61 (CC 2.6.2) — the signed expiry carries milliseconds.
        let expires = crate::federation::admission::truncate_to_substrate_resolution(
            now + Duration::hours(24),
        );

        // ── 1. A HOLDER relieves the node. Bounded emergency relief, which is
        //       what CC 4.2.1 gives one holder.
        let (_, by_holder) = holder_config_row(
            dir,
            0,
            &root,
            K::LoadCeiling,
            8,
            MeshConfigForm::Emergency,
            relief_at,
            Some(expires),
            None,
        )
        .await;
        assert_eq!(
            record_mesh_config_row(dir, &node, &base, &by_holder, now)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] door errored rather than refusing: {e}")),
            MeshConfigOutcome::Admitted,
            "[{tag}] the holder's relief must be admitted, or the refusals below prove only              that nothing can set this key"
        );

        // ── 2. The NODE signs the identical relief, under the lineage it
        //       accepted. The value is the same and the direction is relief;
        //       what is refused is the AUTHOR.
        let by_node = signed_config_row(
            &node,
            &root,
            K::LoadCeiling,
            8,
            MeshConfigForm::Emergency,
            relief_at,
            Some(expires),
            None,
        );
        assert_eq!(
            record_mesh_config_row(dir, &node, &base, &by_node, now)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] door errored rather than refusing: {e}"))
                .refusal(),
            Some(MeshConfigRefusalReason::AuthorNotRootAuthorized),
            "[{tag}] CC 4.2.1.4: a node MUST NOT author a mesh_config value"
        );

        // ── 3. The NODE names ITSELF as the root.
        let self_rooted = signed_config_row(
            &node,
            &node,
            K::LoadCeiling,
            8,
            MeshConfigForm::Emergency,
            relief_at,
            Some(expires),
            None,
        );
        assert_eq!(
            record_mesh_config_row(dir, &node, &base, &self_rooted, now)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] door errored rather than refusing: {e}"))
                .refusal(),
            Some(MeshConfigRefusalReason::RootNotTrusted),
            "[{tag}] a node is no root of itself"
        );

        // ── 4. And the node runs the HOLDER's number, from the real read path.
        let fold = resolve_mesh_config(dir, &node, &base, now)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] resolve: {e}"));
        let s = fold.setting(K::LoadCeiling).expect("registered key");
        assert_eq!(
            s.effective, 8,
            "[{tag}] the relief the holder filed is the ceiling the node runs"
        );
        assert_eq!(
            s.decided_by.as_deref(),
            Some(fg::identity_ref_of(fg::HOLDER_SEEDS[0]).as_str())
        );
        assert_eq!(s.decided_by_root.as_deref(), Some(root.as_str()));
        assert_eq!(s.form, Some(MeshConfigForm::Emergency));
        assert_eq!(
            s.expires_at,
            Some(expires),
            "[{tag}] relief that does not expire is government"
        );
        assert!(
            !fold.roots.contains(&node),
            "[{tag}] the node must not appear among its own trust roots"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn a_node_cannot_author_its_own_load_ceiling_sqlite() {
        let dir = sqlite_with_node("lc-node-sq").await;
        Box::pin(node_authored_load_ceiling_body(&dir, "sq")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn a_node_cannot_author_its_own_load_ceiling_postgres() {
        let Some(dir) = postgres_with_node("lc-node-pg").await else {
            return;
        };
        Box::pin(node_authored_load_ceiling_body(&dir, "pg")).await;
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
            // v61.3.0 (CIRISPersist#1252, rc18 registry, re-read): the row now
            // also names the delegation plane, and the generator's 200-char
            // description cut falls inside this phrase ("most-restrictiv").
            // The rule it states is unchanged.
            "most-restrictiv",
        ] {
            assert!(
                description.contains(phrase),
                "the row's description no longer states {phrase:?}; re-read the row before \
                 trusting this module's reading of CC 4.2.1"
            );
        }
    }
}
