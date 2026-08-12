//! Wire-enforced admission gate on `scores`-attestation dimensions
//! (CIRISPersist#102 Ask 3, v2.4.0; extended for CEG 0.2 §7.0 +
//! transition-window dual-acceptance at v3.0.0, CIRISPersist#116).
//!
//! # Fractal-self framing (CEG §0.5)
//!
//! Persist is **relational fabric**, not a Cartesian gate. The
//! admission policy here enforces **wire-format invariants** —
//! shapes that consumers downstream cannot recover from on the read
//! path — NOT relational arbitration. Concretely:
//!
//! - **Cartesian-OK gates** (kept): the constitutional
//!   `accord:*` × `accord_holder` asymmetry (CEG §7.1), the
//!   reserved-prefix emitter rule (CEG §7.0 — `system:*`,
//!   `audit_chain:*`, `transparency_log:cosigned:*`, `capacity:*`
//!   self-emission, …), the four-test operational-language gate
//!   (T1/T2/T3/T4 — names must describe machine-checkable
//!   mechanisms, not subjective qualities).
//!
//! - **Cartesian-misread (DON'T add)**: a gate that rejects
//!   `witness_relation: self` rows, or a gate that demands every row
//!   carry N cross-attestations before admission, or a gate that
//!   re-checks whether a self-attestation's emitter "really is" the
//!   identity it claims. Cross-attestation already happened upstream
//!   (in NodeCore / Verify / Registry) — persist's job is to record
//!   the relational fabric the federation produces, not to gate
//!   admission on whether the self is "real."
//!
//! The wire-format gates above are admitted because a misformed
//! prefix string or a wrong-emitter-class row cannot be repaired by
//! any read-path policy — the row is structurally invalid. The
//! self/relational gates are refused because consumer composition
//! IS where relational arbitration belongs; persist's substrate role
//! is to keep the audit chain complete enough that composition can
//! happen.
//!
//! # What this module is
//!
//! `put_attestation` calls [`DimensionAdmissionPolicy::check`] at
//! the start of the write path. The gate rejects malformed or
//! reserved-prefix `scores` attestations *before* they hit the DB.
//! Three layers compose:
//!
//! 1. **The `accord:*` × `accord_holder` constitutional rule**
//!    (FSD-002 §4.1 + §7.1) — only keys whose `identity_type` is
//!    `accord_holder` may emit `dimension` starting with `accord:`.
//!    This is the federation's *one* constitutional asymmetry; the
//!    schema's CHECK cannot enforce it (the constraint crosses
//!    tables — `federation_attestations` row vs `federation_keys`
//!    row), so the admission hook is the load-bearing point.
//!
//! 2. **The four-test operational-language gate** (FSD-002
//!    §1.10.1, added v1.2) — every accepted `scores` dimension
//!    must:
//!    - **T1 Rules/verdicts separation**: name a measurable
//!      mechanism, not a verdict. Enforced as a deny-list of
//!      morally-charged stems (`deception`, `lies`, `evil`, …).
//!    - **T2 Mechanism-descriptive-not-judgment-descriptive
//!      naming**: same enforcement as T1 (heuristic — the two
//!      tests catch the same class of slip from different angles).
//!    - **T3 Version-pinning**: the dimension MUST include a
//!      `:v[0-9]+` segment. Versionless prefixes are rejected.
//!    - **T4 Adjudication separation**: the dimension is a
//!      measurement, not a verdict. Same enforcement as T1.
//!
//! # Scope: `scores` attestations only
//!
//! The four-test gate applies **only** to the unified workhorse
//! primitive (`attestation_type == "scores"`). The four structural
//! primitives (`delegates_to` / `supersedes` / `withdraws` /
//! `recants`) are exempt — they don't carry epistemic content,
//! they carry structural metadata about the attestation graph
//! itself (FSD-002 §2.2). A `delegates_to` row that references a
//! now-banned legacy dimension in its scope (e.g.,
//! `delegates_to:correlated_action_v2:from:emergent_deception_v1`)
//! is still admitted — the rename chain in the federation's own
//! mechanism is how legacy-name consumers discover the rename
//! (FSD-002 v1.2 Ask 5 delta).
//!
//! The `accord:*` rule also applies only to `scores` attestations
//! — the four structural primitives carry no dimension field on
//! the wire surface persist enforces.
//!
//! # Why a configurable policy struct
//!
//! The deny-list of morally-charged stems + the required version
//! segment is the v2.4.0 default. Future v1.3+ FSD revisions may
//! tighten or relax the rule (e.g., adding new T2-failing stems
//! as RATCHET calibration packages rename). Persist's admission
//! point reads its policy from a struct so operators can override
//! per deployment without forking the substrate.
//!
//! [`DimensionAdmissionPolicy::default()`] is the canonical v2.4.0
//! policy; persist's backends instantiate it once and consult it
//! on every `put_attestation`.

use ciris_verify_core::classification::{Classification, Gating};
use serde::{Deserialize, Serialize};

use super::types::{attestation_type, identity_type};
use super::Error;

/// v3.0.0 (CEG 0.2 §5.2 / §8.1.9) — the canonical mechanism-only
/// vocabulary for `attestation:{mechanism}` dimensions. CEG 0.2
/// renamed the L1-L5 ladder prefixes from `attestation:l{N}:*` to
/// mechanism-only form per [§1.3.1](https://github.com/CIRISAI/CIRISRegistry/blob/main/FSD/CEG/01_foundation.md)
/// T2 (L-numbers name a ladder-position, not a mechanism; only
/// mechanism belongs in the wire prefix). The five canonical
/// mechanism leaves below are the post-rename target shapes.
///
/// Order matches the consumer-side §8.1.9 Policy I ladder
/// (L1=self_verify, L2=hardware_rooted, L3=registry_consensus,
/// L4=license_validity, L5=agent_integrity).
pub const ATTESTATION_LADDER_MECHANISMS: &[&str] = &[
    "attestation:self_verify",
    "attestation:hardware_rooted",
    "attestation:registry_consensus",
    "attestation:license_validity",
    "attestation:agent_integrity",
];

/// v3.0.0 (CEG 0.1 → 0.2 transition window) — policy for the L1-L5
/// attestation-ladder rename. CEG 0.2 renamed `attestation:l{N}:*` →
/// `attestation:{mechanism}`; the deprecated form is admitted during
/// the transition window so producers still emitting the 0.1 wire
/// shape don't have their rows rejected.
///
/// The `dimension` field on `federation_attestations` is TEXT — no
/// schema migration is required by the rename. The transition policy
/// here is purely string-level admission behavior.
///
/// # Flip target
///
/// Post-CEG 0.3 (separate future PR; tracked at CIRISPersist#117
/// when CEG 0.3 lands), persist's policy flips to
/// [`AttestationLadderTransitionPolicy::RejectDeprecated`] — the
/// deprecated `attestation:l{N}:*` form is rejected at admission per
/// CEG §13.1 deprecation table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationLadderTransitionPolicy {
    /// CEG 0.1 → 0.2 transition (v3.0.0 default). Both
    /// `attestation:l{N}:*` and `attestation:{mechanism}` are admitted
    /// on write. Producers SHOULD migrate to the mechanism form;
    /// consumers SHOULD treat both as equivalent during the window.
    DualAccept,
    /// Post-CEG 0.3 target (NOT the default at v3.0.0). The
    /// deprecated `attestation:l{N}:*` form is rejected at admission;
    /// only the mechanism-only form is admitted.
    RejectDeprecated,
}

impl AttestationLadderTransitionPolicy {
    /// True iff the policy admits the deprecated `attestation:l{N}:*`
    /// wire shape. The current v3.0.0 default returns true.
    pub fn admits_deprecated_form(self) -> bool {
        matches!(self, Self::DualAccept)
    }
}

/// v3.0.0 (CIRISPersist#116, CEG 0.2 §7.0) — a reserved-prefix
/// admission rule. The substrate rejects a `scores` attestation whose
/// `dimension` matches the prefix pattern AND whose attesting key's
/// `identity_type` is not in the rule's `required_identity_types`.
///
/// # Why a list, not a single value
///
/// Some reserved prefixes accept multiple identity types (e.g.,
/// `licensure:*` per CEG §7.3 is co-owned between CIRISRegistry and
/// CIRISVerify). The vocabulary is a set, not a singleton.
///
/// # Why a Vec, not a fixed array
///
/// Operator policy may extend the set per deployment (e.g., a
/// sovereign deployment may admit a fourth steward identity).
/// [`DimensionAdmissionPolicy::default()`] ships the CEG 0.2 §5.3 +
/// §7.x base set; extensions ride the policy struct.
///
/// # Match semantics
///
/// `pattern_prefix` is a literal byte-string prefix match against the
/// `dimension`. No regex; no wildcards; the rule fires iff
/// `dimension.starts_with(&self.pattern_prefix)`. Reserved prefixes
/// in CEG §7.x are all literal prefixes — e.g., `system:*` matches
/// any `dimension` beginning with `system:`. The `:` separator is
/// included in `pattern_prefix` to avoid accidental sub-token matches
/// (`system:foo` matches `system:`; `systematic` does NOT — the
/// prefix string is `"system:"` with the trailing colon).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedPrefixRule {
    /// Literal prefix the rule fires on (e.g., `"system:"`,
    /// `"audit_chain:"`, `"transparency_log:cosigned:"`).
    pub pattern_prefix: String,
    /// Identity types whose keys may emit under this prefix. A
    /// `scores` attestation whose attesting key's `identity_type` is
    /// NOT in this list is rejected with
    /// [`super::Error::ReservedPrefixEmitterMismatch`].
    pub required_identity_types: Vec<String>,
    /// v30.2.0 (CIRISPersist#607) — the delegation scope the emitter must hold
    /// from a trust root this node trusts, resolved at the door.
    ///
    /// `Some(scope)` makes the identity-type check a **precondition rather than
    /// the whole test**: the claim must be present AND a live
    /// `trust:confers:v1` edge must confer `scope` on the attester. `None`
    /// keeps membership-only, which is correct for claims that are gated at
    /// REGISTRATION by a ceremony (`HardwareAttested`, `AnchorScrubbed`,
    /// `AccordCoScrubbed`) — for those the stored string is already a fact
    /// somebody proved.
    ///
    /// # Why this exists
    ///
    /// `identity_type` is self-asserted at registration for every claim whose
    /// [`ConferralMode`](crate::federation::types::identity_type::ConferralMode)
    /// defers enforcement to use. Those modes promise the authority is
    /// "re-derived at each use" — and a `required_identity_types` membership
    /// test re-derives NOTHING; it reads the string off the registration row a
    /// stranger wrote. #607 measured the consequence: a self-registered
    /// `witness` could assert an age-assurance LEVEL about any third party, the
    /// rung CC 3.4.11 reserves to a witness *precisely because a subject must
    /// not reach it*.
    ///
    /// The resolver is [`trust_root::capability_roots_to_trusted_root`], which
    /// is the one the mode table already named and which nothing was calling.
    pub required_delegation_scope: Option<String>,
}

/// Machine-readable reason tokens emitted alongside
/// [`super::Error::DimensionRejected`]. The string form is the stable
/// telemetry / log token; consumer code should match on the enum
/// variant or the `as_str()` constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionRejectionReason {
    /// T1 / T2 / T4 — the dimension contains a morally-charged
    /// stem (`deception`, `harm`, `evil`, …) that fails the
    /// rules/verdicts separation + mechanism-descriptive naming +
    /// adjudication-separation tests jointly. FSD-002 §1.10.1
    /// anti-pattern catalogue.
    MorallyChargedStem,
    /// T3 — the dimension lacks a version segment (`:v[0-9]+`).
    /// Versionless dimensions admit silent rule drift; rejected.
    MissingVersionSegment,
    /// The dimension is empty or whitespace-only. The wire format
    /// requires a `<namespace-prefix>:<scoped-leaf>` value;
    /// emptiness is malformed.
    EmptyOrMissingDimension,
    /// CC 3.4.11 — the self-declared age rung carries a `{band}`
    /// (`age_self_declared:band:*`), never a `{level}`. The `{level}`
    /// token is reserved to the witness-attested `age_assurance:` rung,
    /// so a `level` discriminator on the self-declared prefix is a
    /// subject claiming the witness rung's authority on its own
    /// signature. Refused structurally, independent of emitter.
    SelfDeclaredLevelReserved,
}

impl DimensionRejectionReason {
    /// Stable machine-readable token (snake_case). Matches the
    /// `serde(rename_all)` output for parity with structured logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MorallyChargedStem => "morally_charged_stem",
            Self::MissingVersionSegment => "missing_version_segment",
            Self::EmptyOrMissingDimension => "empty_or_missing_dimension",
            Self::SelfDeclaredLevelReserved => "self_declared_level_reserved",
        }
    }
}

/// The configurable per-deployment policy. Default-deny on the
/// four-test gate; the `accord:*` × `accord_holder` rule is
/// constitutionally fixed (not policy-tunable — it's enforced
/// independently of the deny-list).
///
/// # Default contents (v3.0.0)
///
/// - `morally_charged_stems`: the FSD-002 §1.10.1 anti-pattern
///   list (`deception`, `harm`, `evil`, `bad_actor`,
///   `trustworthiness`, `malicious`, `lies`). The
///   v1.2 rename `emergent_deception` → `correlated_action` is
///   what `deception` blocks: any future contributor proposing
///   `detection:emergent_deception:*` gets rejected at admission.
/// - `require_version_segment`: `true`. Every accepted `scores`
///   dimension must contain `:v[0-9]+`.
/// - `reserved_prefix_rules`: the CEG 0.2 §5.3 + §7.x base set
///   (`system:*`, `audit_chain:*`, `corpus_health:*`,
///   `identity_continuity:*`, `federation_directory:*` →
///   `substrate_persist`; `transparency_log:cosigned:*` →
///   `witness`). See [`ReservedPrefixRule`] for the match shape.
///   v3.0.0 ships a minimal allowlist; sovereign deployments extend
///   per CEG §7.6 (e.g., adding the `witness` identity type once
///   their federation directory has registered witnesses).
/// - `attestation_ladder_transition`: CEG 0.1 → 0.2 transition window
///   policy. Default is [`AttestationLadderTransitionPolicy::DualAccept`]
///   — both `attestation:l{N}:*` (deprecated) and
///   `attestation:{mechanism}` (canonical) admit. Flips to
///   `RejectDeprecated` post-CEG 0.3.
///
/// Customize via the explicit constructor for tests / sovereign
/// deployments that need a different stem list. The default is
/// what production persist deployments use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DimensionAdmissionPolicy {
    /// Lowercase substrings whose presence in the dimension
    /// triggers [`DimensionRejectionReason::MorallyChargedStem`].
    /// The match is substring (case-insensitive), not whole-token
    /// — `emergent_deception_v1` and `deception_alleged_v2` both
    /// trip on `deception`.
    pub morally_charged_stems: Vec<String>,
    /// When `true`, every accepted `scores` dimension MUST contain
    /// at least one `:v[0-9]+` segment. Versionless rejection
    /// emits [`DimensionRejectionReason::MissingVersionSegment`].
    pub require_version_segment: bool,
    /// v3.0.0 (CEG 0.2 §7.0) — reserved-prefix admission rules.
    /// Each rule names a prefix pattern + the identity-type set
    /// whose keys are allowed to emit under that prefix. A `scores`
    /// dimension matching `rule.pattern_prefix` requires the
    /// attesting key's `identity_type` to be in
    /// `rule.required_identity_types`; otherwise the gate emits
    /// [`super::Error::ReservedPrefixEmitterMismatch`].
    ///
    /// Rules are evaluated in declaration order; the first matching
    /// rule's identity-type set is checked. Disjoint prefixes are
    /// expected; an overlapping rule shadow is a configuration bug
    /// the operator owns (the policy struct doesn't normalize).
    pub reserved_prefix_rules: Vec<ReservedPrefixRule>,
    /// v3.0.0 (CEG 0.1 → 0.2 transition). Default
    /// [`AttestationLadderTransitionPolicy::DualAccept`] — both
    /// `attestation:l{N}:*` and `attestation:{mechanism}` admit.
    /// See the policy enum docs for the post-CEG-0.3 flip target.
    pub attestation_ladder_transition: AttestationLadderTransitionPolicy,
}

impl Default for DimensionAdmissionPolicy {
    fn default() -> Self {
        Self {
            morally_charged_stems: vec![
                "deception".into(),
                "harm".into(),
                "evil".into(),
                "bad_actor".into(),
                "trustworthiness".into(),
                "malicious".into(),
                "lies".into(),
            ],
            require_version_segment: true,
            reserved_prefix_rules: default_reserved_prefix_rules(),
            attestation_ladder_transition: AttestationLadderTransitionPolicy::DualAccept,
        }
    }
}

/// v3.0.0 (CIRISPersist#116, CEG 0.2 §5.3 + §7.x) — the base set of
/// reserved-prefix rules persist ships out of the box. Sovereign
/// operators extend per deployment (e.g., adding witness keys once
/// their federation directory has them registered).
///
/// # Coverage
///
/// | Prefix | Required emitter | CEG section |
/// |---|---|---|
/// | `system:` | `substrate_persist` | §5.3 + §7.2 |
/// | `audit_chain:` | `substrate_persist` | §5.3 |
/// | `corpus_health:` | `substrate_persist` | §5.3 |
/// | `identity_continuity:` | `substrate_persist` | §5.3 |
/// | `federation_directory:` | `substrate_persist` | §5.3 |
/// | `transparency_log:cosigned:` | `witness` | §7.6 |
///
/// # What's deliberately NOT here
///
/// - `accord:*` is handled separately by the constitutional-asymmetry
///   layer (see [`DimensionAdmissionPolicy::check`] Layer 1) so its
///   typed error variant stays distinct
///   ([`super::Error::AccordDimensionRequiresAccordHolder`]).
/// - `capacity:*` self-emission rejection (CEG §7.5 / CC 3.4.5) is NOT in
///   this *dimension* table — it's an attester==attested check, not an
///   identity-type check. As of v10.3.0 (CIRISPersist#288) it IS
///   substrate-enforced, on the `attestation_type` namespace at the
///   `put_attestation` chokepoint by
///   [`check_reserved_prefix_admission`] (which sees the row-level
///   `attesting_key_id` == `attested_key_id` distinction the
///   identity-type-only `DimensionAdmissionPolicy::check` cannot).
/// - `licensure:*` (CEG §7.3) is co-owned — the admission gate
///   doesn't reject single-source emissions; per §7.3, consumers
///   mark them `confidence ≤ 0.5` until the second co-owner attests.
/// - `detection:correlated_action:*` / `detection:distributive:access:*`
///   (CC 3.4.8) ARE gated here (v13.0.0, CIRISPersist#366): they are
///   LensCore-only emission — emitter rule `lenscore_detector ∈
///   attesting_key.identity_type`. Per CC 3.4.8 a cross-attestation by a
///   non-LensCore peer MUST use the DISTINCT `truth_grounding:detection:*`
///   prefix (which does not start with `detection:` and so stays ungated),
///   so anything landing on `detection:*` is a **primary detector
///   emission** — gate-able with NO envelope field, resolving the earlier
///   "which shape is this?" ambiguity. As of CIRISPersist#379 the bare
///   `detection:` prefix is ALSO gated (see below) — the two leaves are
///   kept as the more-specific, first-matched entries so their mismatch
///   errors keep reporting the narrower prefix.
/// - `detection:*` (CC 3.4.8, the prefix-WILDCARD) is gated here
///   (CIRISPersist#379): every `detection:{anything}` — including subkinds
///   not yet enumerated as their own leaf — requires `lenscore_detector`
///   by construction. This closes the gap where a NOVEL
///   `detection:{newkind}:*` subkind from an ordinary agent key was
///   wrongly admitted until someone added its leaf rule. It is declared
///   AFTER the two leaves above so first-match-wins precedence keeps
///   their narrower `prefix` value in the emitted error; this wildcard is
///   a pure fallback net over anything else under `detection:`. It does
///   NOT catch `truth_grounding:detection:*`, which is a distinct prefix
///   (doesn't start with `detection:`) and stays ungated per CC 3.4.8.
pub fn default_reserved_prefix_rules() -> Vec<ReservedPrefixRule> {
    use super::types::identity_type;
    let substrate_persist = identity_type::SUBSTRATE_PERSIST.to_owned();
    let witness = identity_type::WITNESS.to_owned();
    // NB: no `trusted_publisher` binding — CC 3.3.12 leaves `content_rating:`
    // open vocabulary, so the write door carries no publisher rule. The
    // publisher discrimination lives on the READ door
    // (`lookup_trusted_publisher_chain`), which is where CC puts it.
    let lenscore_detector = identity_type::LENSCORE_DETECTOR.to_owned();
    vec![
        ReservedPrefixRule {
            pattern_prefix: "system:".into(),
            required_identity_types: vec![substrate_persist.clone()],
            required_delegation_scope: None,
        },
        ReservedPrefixRule {
            pattern_prefix: "audit_chain:".into(),
            required_identity_types: vec![substrate_persist.clone()],
            required_delegation_scope: None,
        },
        ReservedPrefixRule {
            pattern_prefix: "corpus_health:".into(),
            required_identity_types: vec![substrate_persist.clone()],
            required_delegation_scope: None,
        },
        ReservedPrefixRule {
            pattern_prefix: "identity_continuity:".into(),
            required_identity_types: vec![substrate_persist.clone()],
            required_delegation_scope: None,
        },
        ReservedPrefixRule {
            pattern_prefix: "federation_directory:".into(),
            required_identity_types: vec![substrate_persist.clone()],
            required_delegation_scope: None,
        },
        ReservedPrefixRule {
            pattern_prefix: "transparency_log:cosigned:".into(),
            required_identity_types: vec![witness.clone()],
            required_delegation_scope: Some(
                crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE.to_owned(),
            ),
        },
        // CEG 0.3 §5.6.8.3 + §11.5.3 added FOUR reserved-prefix families for
        // media-sharing admission. **Three of them are gone as of the rc3
        // re-vendor (CIRISPersist#571), and their removal is a fix, not a
        // relaxation** — see [`MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN`].
        //
        // CC 3.3.12 catalogues `content_rating:` / `content_class:` /
        // `cw_class:` and opens its own table with *"All four families are open
        // vocabulary"*, naming NO emitter role for any of the three; the one
        // family in that table CC does reserve (`age_assurance:`) it marks
        // "witness-reserved" in as many words, and that row carries a
        // machine-readable `reserved_rule` while the other three carry none.
        // Persist's CEG-sourced gates therefore demanded an emitter role the
        // Constitution does not, which CC 3.1.7 R2 names as refusing traffic
        // the Constitution leaves open.
        //
        // `content_class:` was the sharp end: CC 3.4.14 R1 — *"Class marking is
        // universal (every attester)"* — makes `content_class:generated` /
        // `content_class:generated_modified` MANDATORY on any Contribution
        // carrying generated content, and R2 requires an agent's to be attested
        // under a key whose `identity_type` contains `agent`. Gating the family
        // to `substrate_persist` refused exactly that row, so the disclosure
        // path CC 3.4.14 makes normative (EU AI Act Art. 50(2), applicable
        // 2026-08-02, discharged in CIRISAgent 2.9.8 / CIRISServer 0.6) was
        // blocked at the substrate. Witnessed on every backend by
        // `tests::cc_3414_r1_class_marking_admits_from_any_attester`.
        //
        // What did NOT change: `lookup_trusted_publisher_chain` still reads
        // `content_rating:` rows through `trusted_publisher` keys ONLY. CC puts
        // the discrimination on the READ side for these families — *"polarity
        // carries certifier confidence; not a slashing input"* — so an open
        // write door and a publisher-filtered read door is the shape CC
        // describes, not a hole.
        //
        // - age_assurance:{level} → emitted by witness (a registered
        //   age-assurance provider). CC 3.3.12 + CC 3.4.11; STAYS.
        ReservedPrefixRule {
            pattern_prefix: "age_assurance:".into(),
            required_identity_types: vec![witness.clone()],
            required_delegation_scope: Some(
                crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE.to_owned(),
            ),
        },
        // v11.9.0 (CIRISPersist#309, CC 3.4.12) — the capacity-assurance
        // ladder, the witness-reserved sibling of `age_assurance:`. A
        // registered qualified assessor (identity_type ⊇ {witness}) attests;
        // this covers both the `capacity_assurance:{level}:{domain}:{band}`
        // verdicts AND the `reversible_excluded` / `reversible_pending`
        // companions (same prefix). The SUBJECT-must-not-emit rule (attester
        // == attested) is enforced separately in
        // `check_reserved_prefix_admission` (an identity-independent check).
        ReservedPrefixRule {
            pattern_prefix: crate::federation::capacity::CAPACITY_ASSURANCE_PREFIX.into(),
            required_identity_types: vec![witness],
            required_delegation_scope: Some(
                crate::federation::types::delegation_scope::INFRA_ATTEST_ASSURANCE.to_owned(),
            ),
        },
        // v13.0.0 (CIRISPersist#366, CC 3.4.8) — the detector-only
        // prefixes. `detection:correlated_action:*` and
        // `detection:distributive:access:*` are LensCore-only emission:
        // emitter rule `lenscore_detector ∈ attesting_key.identity_type`.
        // Set-membership (not scalar equality) is the load-bearing test
        // (CC 3.4.7.1) so a folded `{agent, lenscore_detector}` key passes.
        // A non-detector peer wishing to cross-check the detector's verdict
        // emits under the DISTINCT `truth_grounding:detection:*` prefix
        // (ungated — it does not start with `detection:`), so every row on
        // these two families is a primary detector emission.
        ReservedPrefixRule {
            pattern_prefix: "detection:correlated_action:".into(),
            required_identity_types: vec![lenscore_detector.clone()],
            required_delegation_scope: Some(
                crate::federation::types::delegation_scope::INFRA_DETECT.to_owned(),
            ),
        },
        ReservedPrefixRule {
            pattern_prefix: "detection:distributive:access:".into(),
            required_identity_types: vec![lenscore_detector.clone()],
            required_delegation_scope: Some(
                crate::federation::types::delegation_scope::INFRA_DETECT.to_owned(),
            ),
        },
        // CIRISPersist#379 (CC 3.4.8) — the `detection:*` prefix-WILDCARD.
        // The two leaves above enumerate the known detector families;
        // this blanket rule closes the conformance gap (CIRISConformance
        // `test_550_detection_discriminator`) where a NOVEL
        // `detection:{newkind}:*` subkind from an ordinary agent key was
        // wrongly admitted until someone hand-added its own leaf. Every
        // `detection:{anything}` now requires `lenscore_detector` by
        // construction — no envelope parsing, a pure prefix rule.
        //
        // Declared AFTER the two leaves: `default_reserved_prefix_rules()`
        // consumers scan in declaration order and stop at the first match
        // (`DimensionAdmissionPolicy::check`'s `for … { break }` loop and
        // `check_reserved_prefix_admission`'s `.find()`), so the two
        // leaves still win their own lookup and keep reporting the
        // narrower `detection:correlated_action:` /
        // `detection:distributive:access:` prefix in
        // `Error::ReservedPrefixEmitterMismatch`. This rule only ever
        // fires as the fallback net for everything else under
        // `detection:` — same required role either way, so it is
        // behavior-preserving for the two enumerated leaves.
        //
        // `truth_grounding:detection:*` cross-attestations (CC 3.4.8)
        // remain ungated: that string does NOT start with `detection:`
        // (it starts with `truth_grounding:`), so `str::starts_with`
        // never matches this rule for it.
        ReservedPrefixRule {
            pattern_prefix: "detection:".into(),
            required_identity_types: vec![lenscore_detector],
            required_delegation_scope: Some(
                crate::federation::types::delegation_scope::INFRA_DETECT.to_owned(),
            ),
        },
    ]
}

// ══════════════════════════════════════════════════════════════════════════
// (CIRISPersist#590) — CC 3.1.7 R2: the namespace-registration gate
// ══════════════════════════════════════════════════════════════════════════

/// Why a namespace conformance check refused. One variant today; typed and
/// `as_str`-tokenised from the start because CC named the token, downstream
/// keys on it, and this repo's rule is that a refusal names its branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamespaceConformanceReason {
    /// **CC 3.1.7 R2(b)** — emission observed on a family persist governs that
    /// carries no row (provisional or ratified) in the vendored registry.
    ///
    /// Renamed explicitly rather than left to `rename_all`: CC spells the token
    /// `namespace_family_unregistered`, and the enum is already namespaced by
    /// its type name, so the derive's `family_unregistered` would have been a
    /// second spelling of a word the Constitution already chose.
    #[serde(rename = "namespace_family_unregistered")]
    FamilyUnregistered,

    /// **CC 3.1.7 R2, Private Use** (CIRISPersist#571) — a row on the
    /// `x_private:{anything}` range was offered at **federation tier**, which
    /// the clause forbids *under any authority*.
    ///
    /// A distinct variant rather than a second use of [`Self::FamilyUnregistered`]
    /// because the two say opposite things about the same missing row. R2(b)
    /// means "nobody registered this and somebody should"; Private Use means
    /// "nobody will ever register this, and that is correct" — the refusal is
    /// about the row's TIER, never its registration. One name, one reading.
    ///
    /// Unlike its sibling, this token is **persist's coinage**: the clause
    /// states the MUST without naming a refusal token, where R2(b) names
    /// `namespace_family_unregistered` explicitly. Spelled in the clause's own
    /// vocabulary ("private use", "federatable") so a CC ruling that later names
    /// one has an obvious candidate; if CC chooses differently, this appends a
    /// variant rather than re-spelling one.
    #[serde(rename = "namespace_private_use_not_federatable")]
    PrivateUseNotFederatable,
}

impl NamespaceConformanceReason {
    /// The stable program token. `FamilyUnregistered` spells
    /// `"namespace_family_unregistered"` — **CC 3.1.7 R2(b)'s own word**, not a
    /// persist coinage, so a conformance harness reading CC and a consumer
    /// reading persist's error key on the same string.
    ///
    /// **APPEND-ONLY.** Add variants; never re-spell one.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FamilyUnregistered => "namespace_family_unregistered",
            Self::PrivateUseNotFederatable => "namespace_private_use_not_federatable",
        }
    }
}

/// **CC 3.1.7 R2's Private Use range** — the one family prefix the Constitution
/// reserves for private use, which carries no registry row by design.
///
/// > *"One family prefix is reserved for Private Use (`x_private:{anything}`)
/// > and carries no registry row: private-use families MUST NOT admit at
/// > federation tier under any authority and MUST NOT be promoted to a
/// > registered family without minting a fresh name — the legitimate
/// > unregistered range whose absence is what mints `X-`-convention squatting
/// > (RFC 6648's lesson)."*
///
/// A **range**, not a family: it is checked with `starts_with` against this
/// stem and it is deliberately absent from the manifest, so
/// [`is_family_registered`](crate::federation::namespace::registry::is_family_registered)
/// answers `false` for it forever. That is why it needs its own arm — every
/// other R2 answer is derived from the manifest, and this one cannot be.
///
/// **And that is a residual worth naming, because it is R2's own failure mode
/// turned on R2.** R2's enforcement-surface clause requires a substrate to
/// consume the manifest rather than walk prose — but the Private Use range is
/// stated ONLY in the CC 3.1.7 prose, and CC's generator reaches only the
/// CC 3.1 tables. So every substrate enforcing this clause must hard-code the
/// literal `"x_private:"` from prose, and nothing can detect two of them
/// disagreeing. Persist cannot fix that from here: inventing a manifest row for
/// a range CC says carries none would be worse. The ask on CC is a
/// machine-readable range field in the generated manifest (a `_meta` key, not a
/// family row, since it is not a family); until then this const is a prose
/// transcription and is marked as one.
pub const PRIVATE_USE_FAMILY_STEM: &str = "x_private:";

/// **CC 3.1.7 R2, Private Use** — refuse an `x_private:*` namespace at
/// federation tier; admit it everywhere else.
///
/// The asymmetry is the whole rule. Local tier ADMITS, because the range exists
/// precisely so that unregistered work has somewhere legitimate to live: RFC
/// 6648's lesson is that when there is no legitimate unregistered range, people
/// mint squatted prefixes and those calcify into de-facto standards. Refusing
/// `x_private:*` locally would recreate exactly the pressure the clause
/// relieves. Federation tier REFUSES, unconditionally on the signer — *"under
/// any authority"* leaves no identity, role, or co-scrub that buys a private-use
/// row a wire.
///
/// `tier` is the tier the row **will be stored at**, so one call site covers
/// both the direct federation-tier write and the promotion (which gates on the
/// row as-it-will-be-stored). Pure — no directory lookup — so it sits in the
/// cheap tier alongside R2(b).
///
/// The clause's second MUST — *"MUST NOT be promoted to a registered family
/// without minting a fresh name"* — is a rule about **naming**, addressed to
/// whoever mints the registered family; there is no row persist could refuse to
/// express it, and refusing `x_private:` at federation tier is what makes the
/// rename unavoidable in practice.
///
/// **The executed witness lives in
/// [`crate::federation::regime`]** — three doors (local admits, promotion
/// refused, direct federation-tier write refused) plus the consent-edge arm, on
/// every backend. It sits there rather than here because that module is where
/// the Private Use range was weighed as a home for `regime:*` and rejected; the
/// ban is what makes that rejection consequential, so the judgement and its
/// enforcement are read together.
pub fn check_private_use_not_federatable(namespace: &str, tier: &str) -> Result<(), Error> {
    if tier != crate::federation::types::attestation_tier::FEDERATION
        || !namespace.starts_with(PRIVATE_USE_FAMILY_STEM)
    {
        return Ok(());
    }
    Err(Error::NamespacePrivateUseNotFederatable {
        namespace: namespace.to_owned(),
        family_stem: PRIVATE_USE_FAMILY_STEM,
        reason: NamespaceConformanceReason::PrivateUseNotFederatable.as_str(),
    })
}

/// **The R2(a) mint declaration** — every namespace family *persist itself
/// mints*, spelled exactly as the registry row spells it.
///
/// CC 3.1.7 R2(a): *"a producer minting a new family MUST land a registry row
/// carrying its intended emitter/reserved rule in the same change."* This const
/// is how persist states which families it is the producer of, and
/// [`tests::r2a_every_minted_family_has_a_registry_row`] turns that statement
/// into a build failure when the row is missing. Three consecutive cuts
/// (#574 / #578 / #570) each shipped a family with no row and each was noticed
/// only afterwards; this is what makes the fourth impossible rather than merely
/// noticed.
///
/// Each entry is cross-checked against the module const that declares it, so
/// the list cannot quietly diverge from the code that mints on it.
pub const MINTED_NAMESPACE_FAMILIES: &[&str] = &[
    // src/federation/reverse_quorum.rs (#574) — CC 3.1.9.2.
    "objection:{state}",
    // src/federation/quarantine.rs (#570) — CC 3.1.9.2.
    "quarantine:{state}",
    // src/federation/ownership_reclaim.rs (#578) — CC 3.1.9.4.
    "wa_adjudication:{state}",
    // src/federation/mesh_config.rs (#570 ask 1) — CC 3.1.9.2 / CC 4.2.1.
    "mesh_config:{key}",
];

/// v28.3.0 (CIRISPersist#570 ask 1) — the dimension stem of the mesh-config
/// plane, re-exported here so the admission surface names it at the same place
/// it names [`QUARANTINE_DIMENSION_PREFIX`] and friends.
///
/// **There is no `ReservedPrefixRule` for it, deliberately.** The prefix table
/// gates on `identity_type`, and CC 4.2.1's rule is not about identity type at
/// all — the author must be *this node's own trust root, or a key that root has
/// conferred to on the `trust:confers:v1` delegation plane*, which is a
/// per-node graph question no static table can answer. The gate is
/// [`mesh_config::record_mesh_config_row`](crate::federation::mesh_config::record_mesh_config_row),
/// and the read-time clamp in
/// [`fold_mesh_config`](crate::federation::mesh_config::fold_mesh_config) is
/// what holds for rows that arrive on the replication plane instead.
pub const MESH_CONFIG_DIMENSION_PREFIX: &str = crate::federation::mesh_config::DIMENSION_PREFIX;

/// Family stems persist gates with **hand-written arms** rather than a
/// [`ReservedPrefixRule`] row — the gates [`check_reserved_prefix_admission`]
/// and [`DimensionAdmissionPolicy::check`] apply directly.
///
/// Listed here for one reason: they are governed families, so R2 owes them a
/// registry row exactly as much as the table-driven ones do. Deriving the
/// governed set from ONLY `default_reserved_prefix_rules()` would have quietly
/// excused `accord:` / `hard_case:` / `capacity:` — the most reserved families
/// in the Part.
///
/// `pub` since v26 (#519): [`crate::federation::family_rules`] derives the
/// family-rule inventory from this list at ITS source rather than re-listing
/// the same four stems a fifth time.
pub const HARD_CODED_RESERVED_STEMS: &[&str] = &[
    // CC 3.4.1 — the one constitutional asymmetry (accord_holder-only).
    "accord:",
    // substrate-emitted; `hard_case:` → substrate_persist.
    "hard_case:",
    // CC 3.4.5 — no-self-emit (attester != attested).
    "capacity:",
    // CC 3.4.11 — the self rung's `{band}`-not-`{level}` shape rule.
    "age_self_declared:",
];

/// **The declared exceptions.** Family stems persist governs that CC's Part 3
/// does **not** catalogue — so R2 has nothing to check them against, and
/// refusing them under R2(b) would reject traffic the Constitution never spoke
/// about (the exact "refuse conformant traffic and blame the producer" failure
/// CIRISPersist#590 was opened to prevent).
///
/// # EMPTY as of the rc3 re-vendor (CIRISPersist#571) — and that is the pin working
///
/// It carried exactly three: `content_rating:`, `content_class:`, `cw_class:` —
/// CEG-0.3 media-plane families persist had gated since v3.0.0 that CC Part 3
/// had never catalogued. CIRISConstitution#77 landed all three (CC 3.1.9.2,
/// deferring their semantics to CC 3.3.12), the re-vendor brought them in, and
/// [`tests::declared_exceptions_are_still_unregistered`] failed by name — which
/// is precisely what it was written to do. The lines were deleted rather than
/// the gate suppressed.
///
/// Reading the rows CC actually landed then removed their *gates* too: CC 3.3.12
/// opens with *"All four families are open vocabulary"* and reserves only
/// `age_assurance:`. See [`MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN`] — the three are
/// no longer exceptions to R2 because they are no longer governed at all.
///
/// The const stays (rather than being deleted) because the mechanism is the
/// point, and it is still CLOSED and still self-deleting:
///
/// - a NEW gated-but-unregistered family fails
///   [`tests::r2_governed_families_are_registered_or_declared`] until someone
///   states why, so the loudness R2(b) asks for lands in the build rather than
///   nowhere;
/// - any line added here must stay TRUE —
///   [`tests::declared_exceptions_are_still_unregistered`] fails once CC
///   registers it, forcing removal instead of letting a stale excuse outlive
///   its reason. It has now done that once, for real.
pub const UNREGISTERED_GATED_FAMILIES: &[&str] = &[];

/// **CIRISPersist#571 — the three media-plane families persist STOPPED gating,
/// and why that is a fix rather than a relaxation.**
///
/// Named in source because "persist deleted three admission gates" is exactly
/// the sentence a future reader must be able to audit without re-deriving the
/// argument from two Constitution sections.
///
/// `(family_stem, the CC clause that leaves it open, what still discriminates)`.
///
/// The rules came from CEG 0.3 §5.6.8.3 / §11.5.3 and predate any CC row. When
/// CIRISConstitution#77 finally catalogued the families, CC did not ratify the
/// CEG emitter rules — it contradicted them: CC 3.3.12's table opens *"All four
/// families are open vocabulary per CC 4.5.1.1 axis-vocabulary discipline"* and
/// marks only its fourth row (`age_assurance:`) reserved. Keeping the gates
/// would have been persist demanding an emitter role CC declines to demand,
/// which CC 3.1.7 R2 names as the failure mode.
///
/// `content_class:` is the one that was actively breaking: CC 3.4.14 R1 makes
/// the `generated` / `generated_modified` marking **universal — every attester**
/// — and R2 requires an agent's to ride a key whose `identity_type` contains
/// `agent`. The `substrate_persist` gate refused precisely that row, on every
/// backend, blocking the Art. 50(2) disclosure path CC 3.4.14 makes normative
/// (applicable 2026-08-02; discharged in CIRISAgent 2.9.8 / CIRISServer 0.6).
///
/// [`tests::media_plane_families_cc_leaves_open_are_ungated_and_uncatalogued_by_persist`]
/// keeps this from rotting in either direction: it fails if a rule for one of
/// these reappears, AND if CC ever lands a `reserved_rule` on the row (at which
/// point the gate should come back, matching CC's rule rather than CEG's).
pub const MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN: &[(&str, &str, &str)] = &[
    (
        "content_rating:",
        "CC 3.3.12 — open vocabulary; `{scheme}` explicitly admits \
         `operator:{operator_id}` operator-defined rubrics, and polarity carries \
         certifier confidence rather than admission authority",
        "the READ door: `lookup_trusted_publisher_chain` surfaces only rows \
         attested by `trusted_publisher` keys",
    ),
    (
        "content_class:",
        "CC 3.3.12 — open vocabulary, producer-declared; and CC 3.4.14 R1 makes \
         the `generated`/`generated_modified` marking mandatory for EVERY \
         attester, which a `substrate_persist` gate refuses outright",
        "the READ door (v30.13.0, CIRISPersist#612): \
         `FederationDirectory::resolve_content_class_flag` folds the flag plane \
         with a deliberate asymmetry — any emitter may RAISE (withholding is the \
         safe error), but a withdrawal clears a flag its emitter did not raise \
         only when a root THIS NODE trusts has conferred \
         `infra:classify_content`. Plus CC 3.4.14 R2 (an agent's marking must \
         ride an `agent`-typed key, which is a property of the signed envelope, \
         not an admission rule) and R5 (a false or stripped marking is a false \
         attestation adjudicated by WA quorum on the `hard_case:*` evidence \
         floor — the substrate observes, it does not adjudicate)",
    ),
    (
        "cw_class:",
        "CC 3.3.12 — open vocabulary, community-applied and cohort-attestable \
         per CC 4.4.1 Frickerian discipline (low-density cohort CWs are \
         explicitly NOT downweighted)",
        "cohort composition on the read side; a community warning that only a \
         substrate could emit would not be a community warning",
    ),
];

/// Every family stem persist **governs**: the ones it gates
/// ([`default_reserved_prefix_rules`] + [`HARD_CODED_RESERVED_STEMS`] +
/// [`RESERVED_CLASS_DIMENSION_PREFIXES`](crate::federation::replication::admission::RESERVED_CLASS_DIMENSION_PREFIXES))
/// and the ones it mints ([`MINTED_NAMESPACE_FAMILIES`]). Sorted, deduped.
///
/// **Derived, never re-listed.** Every source is read at ITS source, so adding a
/// `ReservedPrefixRule` — or a prefix to the #575 quota reserve — automatically
/// puts that family under the R2 gate. There is no fourth list to keep in step,
/// which is the only version of this that survives contact.
///
/// The quota reserve is included for a reason worth stating: a family that
/// carries reserved admission BUDGET is a family this node has decided is
/// special, and R2 asks who said so. Today it adds no stem the other sources
/// lack (`accord:` and `objection:` are already governed) — the point is that
/// the next prefix added there cannot arrive unregistered and unnoticed.
#[must_use]
pub fn governed_family_stems() -> Vec<String> {
    use crate::federation::namespace::registry::family_stem;
    let mut stems: Vec<String> = default_reserved_prefix_rules()
        .iter()
        .map(|r| family_stem(&r.pattern_prefix).to_owned())
        .chain(HARD_CODED_RESERVED_STEMS.iter().map(|s| (*s).to_owned()))
        .chain(
            crate::federation::replication::admission::RESERVED_CLASS_DIMENSION_PREFIXES
                .iter()
                .map(|s| family_stem(s).to_owned()),
        )
        .chain(
            MINTED_NAMESPACE_FAMILIES
                .iter()
                .map(|f| family_stem(f).to_owned()),
        )
        .filter(|s| !s.is_empty())
        .collect();
    stems.sort();
    stems.dedup();
    stems
}

/// A family stem that is **governed but deliberately never registered**,
/// compiled only under `cfg(test)`.
///
/// It exists because the R2(b) refusal is, by construction, unreachable in a
/// conformant tree: the R2(a) build gate
/// ([`tests::r2_governed_families_are_registered_or_declared`]) guarantees every
/// governed family has a row or a declared reason, so no real dimension can
/// trigger the refusal. Without a probe the runtime half would be asserted only
/// on a hand-built `Error` value — the "code-path-exists ≠ host-reachable" class
/// this repo has been bitten by before.
///
/// What it does NOT do is fork the gate. The probe only widens the GOVERNED set
/// by one stem; the refusal decision, the error, and the whole call chain
/// (`put_attestation` → [`check_reserved_prefix_admission`] →
/// [`check_namespace_family_registered`]) are the production ones, on all three
/// backends. `cfg(test)`, never `feature = "test-anchor"`: a published feature
/// flag would ship a governed family to real deployments.
#[cfg(test)]
pub(crate) const R2_PROBE_UNREGISTERED_STEM: &str = "r2probe_unregistered:";

/// Is `namespace` (an `attestation_type` or an envelope `dimension`) on a family
/// persist governs?
fn is_governed_family(namespace: &str) -> bool {
    use crate::federation::namespace::registry::family_stem;
    let stem = family_stem(namespace);
    if stem.is_empty() {
        return false;
    }
    #[cfg(test)]
    if stem == R2_PROBE_UNREGISTERED_STEM {
        return true;
    }
    // Cheap and allocation-free on the hot path: the governed set is ~17 short
    // stems, so a scan beats building the sorted Vec per row.
    default_reserved_prefix_rules()
        .iter()
        .any(|r| family_stem(&r.pattern_prefix) == stem)
        || HARD_CODED_RESERVED_STEMS.contains(&stem)
        || crate::federation::replication::admission::RESERVED_CLASS_DIMENSION_PREFIXES
            .iter()
            .any(|s| family_stem(s) == stem)
        || MINTED_NAMESPACE_FAMILIES
            .iter()
            .any(|f| family_stem(f) == stem)
}

/// **CC 3.1.7 R2(b)** — refuse emission on a governed family with no registry
/// row, rather than admitting it under the `ProducerSteward` fallback.
///
/// Consumes the **manifest** ([`crate::federation::namespace::registry`]), which
/// is R2's normative enforcement surface: *"A generator or substrate enforcing
/// R2 MUST consume the manifest, never a section-walk heuristic — a walker that
/// reads only `### 3.1.N` refuses traffic this Part reserves."*
///
/// # What it refuses, and what it deliberately does not
///
/// Refusal needs all three: the namespace is on a **governed** family
/// ([`governed_family_stems`]), that family is **absent** from the vendored
/// registry, and it is not a **declared exception**
/// ([`UNREGISTERED_GATED_FAMILIES`]).
///
/// Everything else admits, on purpose. CC preserves *"the open-vocabulary space
/// this Part deliberately leaves open"* and says the fallback is wrong only as
/// *"the interim state of a family on its way to reservation"*. A family persist
/// gates or mints is exactly a family on its way to reservation; a dimension
/// persist has no opinion about is exactly the open vocabulary. Enforcing wider
/// than that — refusing every unregistered dimension — is the fail-closed trap
/// CIRISPersist#590 named: it fails loud and wrong, which is worse than the
/// silent default R2 was written to kill.
///
/// Stem-granular ([`family_stem`](crate::federation::namespace::registry::family_stem)):
/// R2 registers *families*, so `credits:rust:en:alice` is registered because
/// `credits:{domain}:{language}:{subject}` is, and the `{param}` vocabulary
/// inside a registered family is never the thing refused.
pub fn check_namespace_family_registered(namespace: &str) -> Result<(), Error> {
    use crate::federation::namespace::registry;
    let stem = registry::family_stem(namespace);
    if stem.is_empty()
        || !is_governed_family(namespace)
        || registry::is_family_registered(namespace)
        || UNREGISTERED_GATED_FAMILIES.contains(&stem)
    {
        return Ok(());
    }
    Err(Error::NamespaceFamilyUnregistered {
        namespace: namespace.to_owned(),
        family_stem: stem.to_owned(),
        reason: NamespaceConformanceReason::FamilyUnregistered.as_str(),
    })
}

impl DimensionAdmissionPolicy {
    /// Run both layers (the `accord:*` × `accord_holder` rule and
    /// the four-test gate) against an incoming attestation.
    ///
    /// # Arguments
    ///
    /// * `attn_type` — the wire-shape `attestation_type` token
    ///   (one of `"scores"` / `"delegates_to"` / `"supersedes"` /
    ///   `"withdraws"` / `"recants"`). Structural primitives are
    ///   exempt; only `"scores"` passes through the dimension
    ///   tests.
    /// * `dimension` — `attestation_envelope["dimension"]` as a
    ///   string. Pass `None` for structural primitives that have
    ///   no dimension. For `scores`, `None` is treated as an empty
    ///   dimension and rejected.
    /// * `attesting_identity_type` — the `identity_type` field on
    ///   the row referenced by `attesting_key_id`. The caller
    ///   resolves this via `federation_keys` lookup before calling
    ///   the gate.
    pub fn check(
        &self,
        attn_type: &str,
        dimension: Option<&str>,
        attesting_identity_type: &str,
    ) -> Result<(), Error> {
        // Structural primitives exempt — see module docs §"Scope".
        if attn_type != attestation_type::SCORES {
            return Ok(());
        }

        let dim = dimension.unwrap_or("").trim();
        if dim.is_empty() {
            return Err(Error::DimensionRejected {
                dimension: String::new(),
                reason: DimensionRejectionReason::EmptyOrMissingDimension.as_str(),
            });
        }

        // Layer 1 — the `accord:*` × `accord_holder` constitutional
        // rule. FSD-002 §4.1 + §7.1. Checked first because it
        // produces a distinct error variant downstream consumers
        // pattern-match on for the constitutional asymmetry case.
        if dim.starts_with("accord:") && attesting_identity_type != identity_type::ACCORD_HOLDER {
            return Err(Error::AccordDimensionRequiresAccordHolder {
                dimension: dim.to_string(),
                identity_type: attesting_identity_type.to_string(),
            });
        }

        // Layer 1b — CEG 0.2 §7.0 reserved-prefix emitter rule.
        // Checked after the `accord:*` constitutional rule so that
        // layer's distinct error variant stays the canonical signal
        // for the constitutional asymmetry. Reserved-prefix rules
        // produce [`Error::ReservedPrefixEmitterMismatch`] which is
        // a separate machine-readable signal.
        //
        // Rules fire on `dim.starts_with(rule.pattern_prefix)`; the
        // first matching rule's identity-type set is checked. A
        // single matching prefix per dimension is the expected shape
        // — overlapping prefix rules are a configuration bug the
        // operator owns.
        for rule in &self.reserved_prefix_rules {
            if dim.starts_with(rule.pattern_prefix.as_str()) {
                // CC 3.4.7.1 — `identity_type` is a SET; the gate is
                // satisfied iff a required role is a MEMBER of the
                // attester's role-set (not scalar equality). For a
                // single-role key `X ∈ {X}` ≡ `X == X`, so this is
                // behavior-preserving for every legacy single-role key;
                // it only newly-admits conformant folded keys (e.g. a
                // `{agent, lenscore_detector}` LensCore fold — CC 3.4.8).
                if !rule
                    .required_identity_types
                    .iter()
                    .any(|t| identity_type::set_contains(attesting_identity_type, t))
                {
                    let mut required = rule.required_identity_types.clone();
                    required.sort();
                    return Err(Error::ReservedPrefixEmitterMismatch {
                        dimension: dim.to_string(),
                        prefix: rule.pattern_prefix.clone(),
                        required,
                        got_identity_type: attesting_identity_type.to_string(),
                    });
                }
                // Match satisfied — stop scanning further rules.
                break;
            }
        }

        // Layer 1c — CC 3.4.11 token-structure rule for the self-declared
        // age rung. The self rung carries a `{band}`
        // (`age_self_declared:band:adult`), NEVER a `{level}`; the `{level}`
        // discriminator is reserved to the witness-attested `age_assurance:`
        // rung (`age_assurance:level:adult`). A subject self-asserting a
        // `level` is claiming the witness rung's authority on its own
        // signature, so the shape is refused structurally — independent of
        // emitter (even a witness must use the `age_assurance:` prefix to
        // carry a level). Mirrors the witness-rung positive gate in
        // `default_reserved_prefix_rules` (`age_assurance:` → witness).
        if dim == "age_self_declared:level" || dim.starts_with("age_self_declared:level:") {
            return Err(Error::DimensionRejected {
                dimension: dim.to_string(),
                reason: DimensionRejectionReason::SelfDeclaredLevelReserved.as_str(),
            });
        }

        // Layer 2a — the morally-charged-stem deny-list.
        // T1 (rules/verdicts) + T2 (mechanism-vs-judgment) + T4
        // (adjudication separation) are all caught by the same
        // heuristic; an axis named `deception` collapses all three
        // tests at once. Case-insensitive substring match keeps
        // the policy minimal — operators can extend the list per
        // deployment.
        let dim_lc = dim.to_ascii_lowercase();
        for stem in &self.morally_charged_stems {
            if dim_lc.contains(stem.as_str()) {
                return Err(Error::DimensionRejected {
                    dimension: dim.to_string(),
                    reason: DimensionRejectionReason::MorallyChargedStem.as_str(),
                });
            }
        }

        // Layer 2b — T3 version-pinning. Every accepted dimension
        // must contain at least one `:v[0-9]+` segment so any
        // past verdict can be re-checked against the rule version
        // it ran against. Implementation is a manual scan rather
        // than a regex compile per call — keeps the hot path zero-
        // alloc and avoids pulling `regex` into a dep tree that
        // doesn't have it.
        //
        // CEG 0.2 §5.2 + §8.1.9 carve-out: the attestation-ladder
        // dimensions (canonical `attestation:{mechanism}` and the
        // deprecated `attestation:l{N}:*` shape during the 0.1→0.2
        // transition) are mechanism-naming rather than versioned-
        // mechanism-naming. The wire shape names the verification
        // mechanism the producer ran (`self_verify`,
        // `hardware_rooted`, `registry_consensus`, `license_validity`,
        // `agent_integrity`); the L1-L5 ladder ordering happens
        // consumer-side per §8.1.9 Policy I. Version-pinning of
        // these mechanisms lives in the attesting binary's commit
        // (CIRISVerify's own SLSA-stamped build) and the
        // calibration package's version, not the wire prefix.
        //
        // CEG 1.0-RC5 §5.6.8.14 carve-out: the canonical-binding dimension
        // `identity:canonical_binding:{H}` is a structural identity claim
        // (K asserts it is the federation identity behind canonical hash H)
        // — the suffix is the bound hash, not a versioned mechanism, so it
        // carries no `:vN`. Like the attestation ladder it is exempt from
        // T3 version-pinning.
        if self.require_version_segment
            && !contains_version_segment(dim)
            && !self.is_attestation_ladder_dimension(dim)
            && parse_canonical_binding_hash(dim).is_none()
        {
            return Err(Error::DimensionRejected {
                dimension: dim.to_string(),
                reason: DimensionRejectionReason::MissingVersionSegment.as_str(),
            });
        }

        Ok(())
    }

    /// v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — AV-45 closure.
    /// The write-side cohort_scope admission gate, symmetric to the
    /// read-gate ([`crate::scope::cohort_scope_sql_predicate`], §4.3).
    ///
    /// The read-gate asks "is the *reader* in this row's target cohort?";
    /// the write-gate asks "is the *writer* in the target cohort they're
    /// trying to stamp?". Both directions consume the same
    /// [`CallerAdmission`](crate::scope::CallerAdmission) primitive — one
    /// builder, no emitter-resolution, pure set-membership.
    ///
    /// Called from `put_attestation`, the trace-ingest pipeline
    /// (`IngestPipeline::receive_and_persist_with`, after the
    /// verify-before-persist gate, MISSION §4), and every write path that
    /// stores a row carrying `(cohort_scope, cohort_target_id)`. A
    /// refusal means the row is NOT persisted (zero writes, mirroring the
    /// verify-rejection discipline).
    ///
    /// `claimed_target_id` is `None` for the broad belonging-tiers and
    /// for `self` (where the target IS the writer's identity, resolved
    /// and stamped by the substrate at ingest, not caller-supplied — see
    /// `IngestPipeline` D2 self-target resolution and FSD §4.4 / §12.0).
    ///
    /// # Arms (FSD §4.6)
    ///
    /// - `self` — always permitted; the substrate already stamps
    ///   `cohort_target_id = writer identity` from the verified signer.
    /// - `family` — `Ok` iff `claimed_target_id ∈
    ///   writer_admission.family_key_ids`, else
    ///   [`ScopeRefusalReason::NoFamilyMembership`]. A `None` target
    ///   (claiming family visibility without naming a family) cannot be
    ///   membership-validated and is refused.
    /// - `community` — `Ok` iff `claimed_target_id ∈
    ///   writer_admission.community_key_ids`, else
    ///   [`ScopeRefusalReason::NoCommunityMembership`].
    /// - `affiliations` / `species` / `biosphere` / `federation` —
    ///   broad belonging-tiers; no per-row target; any authenticated
    ///   writer may emit. The federation layer counter-signs (hybrid
    ///   sigs).
    /// - anything else — [`ScopeRefusalReason::InvalidCohortScope`]
    ///   carrying the offending label (closed-set fall-through).
    ///
    /// Returns `Err(...)` on a downgrade attempt — e.g. stamping
    /// `cohort_scope: community` for a community the writer is not a
    /// member of, to broaden visibility.
    pub fn check_write_cohort_scope(
        writer_admission: &crate::scope::CallerAdmission,
        claimed_cohort_scope: &str,
        claimed_target_id: Option<&str>,
    ) -> Result<(), crate::scope::ScopeRefusalReason> {
        use crate::federation::types::cohort_scope as cs;
        use crate::scope::ScopeRefusalReason;

        match claimed_cohort_scope {
            // Self — target IS the writer's identity, resolved + stamped
            // by the substrate from the verified signer (D2 ingest /
            // FSD §4.4). Any caller-supplied self-target is ignored.
            // Always permitted for the writer.
            cs::SELF => Ok(()),

            // Family — the writer must be a member of the claimed family.
            cs::FAMILY => match claimed_target_id {
                Some(fid) if writer_admission.family_key_ids.contains(fid) => Ok(()),
                _ => Err(ScopeRefusalReason::NoFamilyMembership),
            },

            // Community — the writer must be a member of the claimed
            // community.
            cs::COMMUNITY => match claimed_target_id {
                Some(cid) if writer_admission.community_key_ids.contains(cid) => Ok(()),
                _ => Err(ScopeRefusalReason::NoCommunityMembership),
            },

            // Broad belonging-tiers — no per-row target; any
            // authenticated writer may emit.
            cs::AFFILIATIONS | cs::SPECIES | cs::BIOSPHERE | cs::FEDERATION => Ok(()),

            other => Err(ScopeRefusalReason::InvalidCohortScope(other.to_string())),
        }
    }

    /// True iff `dim` is one of the CEG 0.2 §5.2 attestation-ladder
    /// dimensions — either the canonical mechanism form
    /// ([`ATTESTATION_LADDER_MECHANISMS`]) or the deprecated
    /// `attestation:l{N}:*` form when
    /// [`AttestationLadderTransitionPolicy::DualAccept`] is in effect.
    ///
    /// # Transition window
    ///
    /// During the 0.1 → 0.2 transition window (default policy
    /// [`AttestationLadderTransitionPolicy::DualAccept`]):
    ///
    /// - Both `attestation:l1:self_verify` (deprecated 0.1 wire shape)
    ///   AND `attestation:self_verify` (canonical 0.2 mechanism form)
    ///   return `true`.
    /// - The `dimension` field on `federation_attestations` is TEXT
    ///   so no schema migration is required; the transition is purely
    ///   admission-layer behavior.
    ///
    /// Post-CEG-0.3 (policy flipped to
    /// [`AttestationLadderTransitionPolicy::RejectDeprecated`]), only
    /// the canonical mechanism form returns `true`; the deprecated
    /// form falls through to the version-segment check and is
    /// rejected with `missing_version_segment`. The CEG §13.1
    /// deprecation table records the timing.
    fn is_attestation_ladder_dimension(&self, dim: &str) -> bool {
        // Canonical mechanism form is always admitted.
        if ATTESTATION_LADDER_MECHANISMS.contains(&dim) {
            return true;
        }
        // Deprecated `attestation:l{N}:*` form — only during the
        // transition window.
        if self.attestation_ladder_transition.admits_deprecated_form()
            && is_deprecated_attestation_ladder_prefix(dim)
        {
            return true;
        }
        false
    }
}

/// The DEPRECATED CEG 0.1 attestation-ladder prefix (`attestation:l<N>:…`).
///
/// Hoisted to a const in v26 (#519): this is a shape rule persist applies to
/// the whole `attestation:` family, and CC's five catalogued rows state no rule
/// at all — so [`crate::federation::family_rules`] has to be able to read the
/// prefix at the site that branches on it rather than re-spelling the literal.
/// The source scan found this one; nobody remembered it.
pub const ATTESTATION_LADDER_DEPRECATED_PREFIX: &str = "attestation:l";

/// True iff `dim` matches the deprecated CEG 0.1 attestation-ladder
/// shape `attestation:l<N>:<mechanism>`, where `<N>` is one or more
/// ASCII digits and `<mechanism>` is any non-empty suffix. CEG 0.2
/// §13.1 records this as a deprecated wire shape; persist admits it
/// during the 0.1 → 0.2 transition window (see
/// [`AttestationLadderTransitionPolicy`]).
fn is_deprecated_attestation_ladder_prefix(dim: &str) -> bool {
    let Some(rest) = dim.strip_prefix(ATTESTATION_LADDER_DEPRECATED_PREFIX) else {
        return false;
    };
    let Some((digits, mech)) = rest.split_once(':') else {
        return false;
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if mech.is_empty() {
        return false;
    }
    true
}

/// Returns true iff `dim` contains at least one segment of the
/// form `:v` followed by one-or-more ASCII digits, terminated by a
/// `:` or end-of-string. Equivalent to the regex
/// `:v[0-9]+(:|$)`, hand-rolled to avoid pulling the `regex` crate.
fn contains_version_segment(dim: &str) -> bool {
    let bytes = dim.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        // Look for `:v` prefix.
        if bytes[i] == b':' && bytes[i + 1] == b'v' && bytes[i + 2].is_ascii_digit() {
            // Consume the digits.
            let mut j = i + 2;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            // Terminator must be `:` or end-of-string.
            if j == bytes.len() || bytes[j] == b':' {
                return true;
            }
        }
        i += 1;
    }
    // Tail case: the dimension may end with `:v[0-9]+` exactly
    // (no trailing `:`). The loop above handles that via the
    // `j == bytes.len()` check; nothing additional needed.
    false
}

/// Pull the `dimension` field out of an attestation envelope as a
/// `&str`. Returns `None` if the envelope is not an object, lacks
/// a `dimension` key, or the value is not a string. The four
/// structural primitives have no `dimension` field — `None` is
/// the expected shape for them.
pub fn envelope_dimension(envelope: &serde_json::Value) -> Option<&str> {
    envelope
        .get(crate::federation::envelope::paths::DIMENSION)
        .and_then(|v| v.as_str())
}

/// v30.8.0 (CIRISConstitution#87) — **can `key_id` accept for itself?**
///
/// This is THE predicate behind CC 3.2 rc3's ruling, written once because both
/// halves of the custody rule read it and they must never disagree:
/// `check_user_target_steward_binding_admission` (the write gate) and
/// `steward_bindings_of` clause (3) (the read fold).
///
/// The ruling's sentence is *an act the target must accept for itself cannot be
/// custody of the target*. So custody is possible exactly where acceptance is
/// not. The substrate encodes "cannot accept for itself" in three separate
/// places, which is why an earlier implementation of this rule took four
/// successive corrections — each fix found the next encoding:
///
///  * **a node has no agency** (`identity_type` contains `node`). This is why
///    node stewardship is a distinct act from agent partnership: the targets
///    differ in agency, not in wire shape.
///  * **a minor cannot accept for itself** (`user` whose [`age_band`] is
///    `Minor`) — guardianship.
///  * everything else CAN: an adult, an agent, a primitive. For those, custody
///    exists only where the envelope DECLARES it
///    ([`is_custody_claim_envelope`]).
///
/// An **unverified** age counts as able to accept — CC 3.2's own presumption of
/// sovereignty. Failing the other way would let anyone claim custody over any
/// unaged key.
///
/// An unresolved key also counts as able: inventing custody over a key this node
/// has never seen is the worse error.
pub async fn can_accept_for_itself(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
) -> Result<bool, Error> {
    use super::age::{age_band, AgeBand};
    let Some(rec) = directory.lookup_public_key(key_id).await? else {
        return Ok(true);
    };
    if identity_type::set_contains(&rec.identity_type, identity_type::NODE) {
        return Ok(false);
    }
    if identity_type::set_contains(&rec.identity_type, identity_type::USER)
        && age_band(directory, key_id).await? == AgeBand::Minor
    {
        return Ok(false);
    }
    Ok(true)
}

/// v30.8.0 (CIRISConstitution#87) — is this envelope a **claim of CUSTODY** over
/// its target, as opposed to a capability conferral?
///
/// This is the predicate the CC 3.2 gate and the steward fold share, and it is
/// deliberately WIDER than [`is_owner_binding_envelope`]:
///
///  * the CC 2.4.1.2 owner-binding marker (or the internal owner-binding
///    dimension) — an explicit custody claim; and
///  * **any envelope carrying `binding_legitimacy_source`** — a guardianship or
///    adult-incapacity binding. That field exists to JUSTIFY custody, so its
///    presence is a custody claim by construction, and such bindings do not
///    carry the owner-binding marker.
///
/// Missing the second clause is a hole, not a narrowing: keying the gate on
/// `is_owner_binding_envelope` alone left the entire adult-incapacity aperture
/// UNGATED, because those bindings are marked by their legitimacy source rather
/// than by `delegation_purpose`. Caught by the incapacity decision tables.
///
/// Kept separate from [`is_owner_binding_envelope`] rather than widening it: that
/// one drives the OWNERSHIP projection (`nodes_stewarded_by`), and silently
/// changing what counts as ownership is a different decision from what counts as
/// custody for CC 3.2.
#[must_use]
pub fn is_custody_claim_envelope(envelope: &serde_json::Value) -> bool {
    is_owner_binding_envelope(envelope)
        || envelope
            .get(super::capacity::binding_field::LEGITIMACY_SOURCE)
            .is_some()
}

/// v13.3.0 (CIRISPersist#378) — is this `delegates_to` envelope an
/// **owner-binding** (CC 3.2 single-owner sub-relation)? True iff EITHER
/// the internal versioned [`owner_binding::DIMENSION`](super::types::owner_binding::DIMENSION)
/// is set (the `steward_bind`/`grant_delegation(Some(purpose))` path) OR the
/// **CC 2.4.1.2 canonical** `delegation_purpose == "owner_binding"`
/// ([`owner_binding::CC_DELEGATION_PURPOSE`](super::types::owner_binding::CC_DELEGATION_PURPOSE))
/// is carried — the marker a raw `emit_attestation_self` `delegates_to` uses
/// (the only expressible owner-binding path per CC 2.4.1.2, and what
/// CIRISConformance `test_551` probes). Keying on the dimension ALONE let the
/// raw-emit path bypass the single-owner admission gate + resolver, admitting
/// a second distinct owner.
pub fn is_owner_binding_envelope(envelope: &serde_json::Value) -> bool {
    envelope_dimension(envelope) == Some(super::types::owner_binding::DIMENSION)
        || envelope.get("delegation_purpose").and_then(|v| v.as_str())
            == Some(super::types::owner_binding::CC_DELEGATION_PURPOSE)
}

/// v8.7.2 (CIRISPersist#233 follow-on, CEG RC27 §11.10) — does an
/// attestation `envelope` bind `content_sha256`? True iff the envelope's
/// `evidence_refs` array contains the hex string. This is the exact
/// set-membership the [`FederationDirectory::attestations_binding_content`]
/// backends confirm against the parsed envelope (the SQLite LIKE / PG
/// `@>` prefilters narrow the scan; this is the authoritative check).
///
/// [`FederationDirectory::attestations_binding_content`]: super::FederationDirectory::attestations_binding_content
#[must_use]
pub fn envelope_binds_content(envelope: &serde_json::Value, content_sha256: &str) -> bool {
    envelope
        .get("evidence_refs")
        .and_then(|v| v.as_array())
        .is_some_and(|arr| arr.iter().any(|r| r.as_str() == Some(content_sha256)))
}

/// v3.9.1 (CIRISPersist#150 Ask 3, CEG 0.4 §4.2.4) — admission-gate
/// validation of the producer-side `cohort_scope` field.
///
/// Rejects any value outside the closed set
/// `{self, family, community, affiliations, species, biosphere,
/// federation}` ([`crate::federation::types::cohort_scope::is_valid`])
/// BEFORE the row is hashed and inserted, so a malformed envelope —
/// notably `global`, which is a §8.1.8 *feed-name* aggregating
/// `{species, biosphere, federation}` and **never** a wire value —
/// leaves no trace. Returns [`Error::CohortScopeRejected`] on a bad
/// value; the row is not stored.
///
/// This is the trust-graph-free first layer of #150 Ask 3 (the
/// caller-vs-scope admission rules that need `federation_keys` /
/// trust-graph walks are deferred to the v3.10+ enforcement cut). It
/// is the application-layer companion to the V056 `CHECK
/// (cohort_scope IN (...))` constraint: the constraint is
/// defense-in-depth for rows that bypass this hook (direct SQL); this
/// hook produces the machine-readable typed rejection consumers
/// pattern-match on (`kind() == "federation_cohort_scope_rejected"`).
///
/// `self`-tier locality enforcement (a `cohort_scope: self`
/// attestation MUST NOT emit `holds_bytes` to peers — the
/// FEDERATION_SCALING_MODEL §9.5 locality dividend) is a separate,
/// emission-side concern tracked by #153 Ask 5 and is not part of this
/// value-validation layer.
pub fn check_cohort_scope(cohort_scope: &str) -> Result<(), Error> {
    if crate::federation::types::cohort_scope::is_valid(cohort_scope) {
        Ok(())
    } else {
        Err(Error::CohortScopeRejected {
            cohort_scope: cohort_scope.to_string(),
        })
    }
}

/// Pull the `subject_kind` discriminator out of an attestation envelope
/// as a `&str` (the §5.6.8.7 ceremony discriminator on a `scores` row).
/// `None` if absent / not a string — the common case (a bare `scores`
/// on a free `dimension` carries no `subject_kind`).
#[must_use]
pub fn envelope_subject_kind(envelope: &serde_json::Value) -> Option<&str> {
    envelope.get("subject_kind").and_then(|v| v.as_str())
}

/// v6.7.0 (CIRISPersist#146 Ask 5, CEG 1.0-RC5 §5.6.8.7) — admission
/// gate for a `consent_record` ceremony Contribution. A `consent_record`
/// rides the [`attestation_type::SCORES`] primitive with a
/// `subject_kind = "consent_record"` envelope discriminator (NO new
/// attestation_type; the 1+4 lockdown holds). This gate is a **no-op**
/// (`Ok(())`) for any row that is not a `scores` carrying that
/// discriminator — bare `scores` on `consent:state:*` and the four
/// structural primitives flow through untouched.
///
/// For a `consent_record` the §5.6.8.7 admission rules are enforced:
///
///   1. **Required fields present** (rule 1): `subject_key_id`, `stance`,
///      `asserted_at` (all string-valued in the envelope). All other
///      envelope members are optional (`scope` / `valid_until` /
///      `deletion_sla_days` / … ride the §0.9.2 omit rule).
///   2. **Closed-set `stance`** (rule 2): one of `granted` / `revoked` /
///      `expired`; and **`expired` is substrate-emitted only** — a
///      producer/subject-submitted `expired` is rejected (it is the
///      substrate's `valid_until`-passed emission, never a wire input).
///   3. **Tier eligibility** (rule 3, §10.1.3): a `stance: revoked`
///      `consent_record` carries subject revocation authority over
///      another party's content. It is federation-tier by classification
///      but MAY **transit** the local tier (v12.6.0, resolving AV-61): a
///      `revoked` consent_record at `tier = "local"` returns
///      [`LocalTierDisposition::TransitRevocation`] so the caller
///      (`put_attestation`) hybrid-verifies its signature before storing
///      (accept on VALID crypto only) and never lets it rest durable. A
///      `stance: granted` self-consent MAY be local durable (the
///      §10.1.5.2 self-tier eligibility is enforced by
///      [`check_local_tier_eligibility`]).
///
/// Rule 4 (composition with the §3.2.3 `withdraws` gate / no quorum) is
/// not a *field* check — it is the single-subject authority already baked
/// into [`resolve_withdraws_admission_rule`]; a `revoked` consent_record
/// needs no producer co-signature. The signature obligation is the
/// ordinary hybrid signature every federation-tier `scores` row carries
/// (RC5: consent_record is a signature-only obligation on the existing
/// verify path) — this gate adds no separate crypto step.
///
/// `tier` is the row's [`crate::federation::types::Attestation::tier`]
/// (`"local"` / `"federation"`). Returns [`Error::InvalidArgument`] on
/// any rule violation (the row is not stored); otherwise the
/// [`LocalTierDisposition`] — [`LocalTierDisposition::TransitRevocation`]
/// for a `revoked` consent_record at local tier (caller MUST hybrid-verify
/// before storing), else [`LocalTierDisposition::Durable`].
pub fn check_consent_record_admission(
    attestation_type: &str,
    envelope: &serde_json::Value,
    tier: &str,
) -> Result<LocalTierDisposition, Error> {
    use crate::federation::types::consent_record;
    // No-op unless this is a `scores` carrying the consent_record
    // discriminator. (A `consent_record` MUST ride `scores` — §5.6.8.7
    // "Rides existing scores attestation_type"; a non-scores row bearing
    // the discriminator is malformed.)
    if envelope_subject_kind(envelope) != Some(consent_record::SUBJECT_KIND) {
        return Ok(LocalTierDisposition::Durable);
    }
    if attestation_type != attestation_type::SCORES {
        return Err(Error::InvalidArgument(format!(
            "consent_record subject_kind must ride attestation_type='scores' \
             (CEG §5.6.8.7), got '{attestation_type}'"
        )));
    }
    // Rule 1 — required fields present + string-valued.
    let require_str = |field: &str| -> Result<&str, Error> {
        envelope
            .get(field)
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "consent_record requires a non-empty string '{field}' \
                     (CEG §5.6.8.7 admission rule 1)"
                ))
            })
    };
    let _subject_key_id = require_str("subject_key_id")?;
    let stance = require_str("stance")?;
    let _asserted_at = require_str("asserted_at")?;
    // Rule 2 — closed-set stance; reject a producer-submitted `expired`.
    if !consent_record::stance::is_valid(stance) {
        return Err(Error::InvalidArgument(format!(
            "consent_record stance '{stance}' is not in the closed set \
             {{granted, revoked, expired}} (CEG §5.6.8.7 admission rule 2)"
        )));
    }
    if stance == consent_record::stance::EXPIRED {
        return Err(Error::InvalidArgument(
            "consent_record stance 'expired' is substrate-emitted only — a \
             producer/subject MUST NOT assert it (CEG §5.6.8.7 admission rule 2)"
                .to_string(),
        ));
    }
    // Rule 3 — tier eligibility (§10.1.3): a `revoked` consent_record is
    // subject revocation authority. It is federation-tier by classification
    // but MAY *transit* the local tier — the caller (`put_attestation`)
    // hybrid-verifies the signature before storing (accept on VALID crypto
    // only; transit-not-rest). Pre-v12.6.0 this was a hard `Err`.
    if stance == consent_record::stance::REVOKED
        && tier == crate::federation::types::attestation_tier::LOCAL
    {
        return Ok(LocalTierDisposition::TransitRevocation);
    }
    Ok(LocalTierDisposition::Durable)
}

/// v12.6.0 (CIRISPersist#171, §10.1.3 transit-not-rest) — the
/// `put_attestation` ingest gate for subject-side consent revocations at
/// local tier. Two classifiers feed it:
///
/// 1. [`check_consent_record_admission`] (field / stance / substrate-only
///    `expired` checks) — a `revoked` consent_record ceremony at
///    `tier = local`;
/// 2. [`is_subject_side_revocation`] — a *bare* subject-side revocation
///    (`withdraws`, or a `consent:state:revoked` dimension with writer ∈
///    `subject_key_ids`) at `tier = local`. Without this arm,
///    `put_attestation(tier = local)` would be a trivial bypass of the
///    crypto gate the local-write path
///    ([`verify_local_transit_revocation`]) enforces.
///
/// Either way the row MAY transit the local tier only on VALID crypto: its
/// bound-hybrid signature is verified via
/// [`verify_row_hybrid_signature`](crate::federation::verify_row_hybrid_signature)
/// against the attester's REGISTERED pubkeys **before** any store
/// (Ed25519 + ML-DSA-65, Strict, PQC-mandatory). An unsigned /
/// classical-only / forged one is rejected
/// [`Error::FederationTierUnverified`], fail-secure. A no-op (`Ok(())`) for
/// every other row (durable consent_records; federation-tier rows are gated
/// by `verify_federation_tier_ingest`; non-revocations). Must run BEFORE the
/// backend acquires its write lock (it resolves pubkeys via the directory,
/// which locks itself).
pub async fn verify_consent_record_transit_ingest<F>(
    directory: &F,
    row: &crate::federation::types::Attestation,
) -> Result<(), Error>
where
    F: super::FederationDirectory + ?Sized,
{
    let ceremony_disposition = check_consent_record_admission(
        &row.attestation_type,
        &row.attestation_envelope,
        &row.tier,
    )?;
    let bare_transit = row.tier == crate::federation::types::attestation_tier::LOCAL
        && is_subject_side_revocation(
            &row.attestation_type,
            envelope_dimension(&row.attestation_envelope),
            &row.attesting_key_id,
            &row.subject_key_ids,
        );
    if ceremony_disposition == LocalTierDisposition::TransitRevocation || bare_transit {
        crate::federation::verify_row_hybrid_signature(directory, row).await
    } else {
        Ok(())
    }
}

/// v12.6.0 (CIRISPersist#171, §10.1.3 transit-not-rest) — the local-write
/// path's transit gate, shared by all three backends. Given the
/// [`LocalTierDisposition`] from [`check_local_tier_eligibility`] and the
/// caller's [`LocalAttestationInput`](crate::federation::types::LocalAttestationInput):
///
/// - [`LocalTierDisposition::Durable`] ⇒ `Ok(None)` (ordinary
///   producer-authority row; signature deferred — written as the
///   empty-sentinel scrub envelope).
/// - [`LocalTierDisposition::TransitRevocation`] ⇒ the subject-side
///   revocation MUST carry a bound-hybrid signature that verifies against
///   the attester's REGISTERED pubkeys (Ed25519 + ML-DSA-65, Strict,
///   PQC-mandatory). On success returns `Ok(Some((original_content_hash,
///   scrub_signature_classical, scrub_signature_pqc)))` so the backend
///   builds the signed transit row
///   ([`LocalAttestationInput::into_transit_revocation_row`](crate::federation::types::LocalAttestationInput::into_transit_revocation_row)).
///   A missing signature ⇒ [`Error::InvalidArgument`]; an invalid one ⇒
///   [`Error::FederationTierUnverified`]. Either way the row is NOT stored —
///   persist accepts the transit write ONLY on VALID crypto (never an
///   unsigned/forged revocation), and never rests it as a durable local row.
///
/// MUST run BEFORE the backend acquires its write lock (it resolves pubkeys
/// via the directory, which locks itself).
#[allow(clippy::type_complexity)]
pub async fn verify_local_transit_revocation<F>(
    directory: &F,
    disposition: LocalTierDisposition,
    input: &crate::federation::types::LocalAttestationInput,
) -> Result<Option<(String, String, Option<String>)>, Error>
where
    F: super::FederationDirectory + ?Sized,
{
    match disposition {
        LocalTierDisposition::Durable => Ok(None),
        LocalTierDisposition::TransitRevocation => {
            let sig_classical = input.scrub_signature_classical.as_deref().ok_or_else(|| {
                Error::InvalidArgument(
                    "a subject-side revocation transiting the local tier requires a bound-hybrid \
                     signature (§10.1.3, AV-61): scrub_signature_classical + scrub_signature_pqc \
                     must be present and verify against the attester's registered pubkeys"
                        .to_string(),
                )
            })?;
            let sig_pqc = input.scrub_signature_pqc.as_deref();
            let hash = crate::federation::verify_envelope_hybrid_signature(
                directory,
                &input.attesting_key_id,
                &input.attestation_envelope.to_value(),
                sig_classical,
                sig_pqc,
            )
            .await?;
            Ok(Some((
                hash,
                sig_classical.to_string(),
                sig_pqc.map(str::to_string),
            )))
        }
    }
}

/// v12.6.0 (CIRISPersist#171, CEG §10.1.3 transit-not-rest) — how a
/// local-tier write is admitted. The subject-side revocation resolution of
/// AV-61: a subject revocation is federation-tier *by classification* but
/// MAY **transit** the local write path (never *rest* as a durable local
/// row). [`check_local_tier_eligibility`] /
/// [`check_consent_record_admission`] classify the row; the backend then
/// acts on the disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalTierDisposition {
    /// Ordinary producer-only-authority local row — signature deferred
    /// (CC 5.3.2.2), written as an empty-sentinel scrub envelope.
    Durable,
    /// A subject-side consent revocation **transiting** the local tier
    /// (§10.1.3). The backend MUST verify its bound-hybrid signature
    /// (Ed25519 + ML-DSA-65, Strict, PQC-mandatory) against the attester's
    /// REGISTERED pubkeys before storing; a signature that does not verify
    /// (or is absent) is rejected. The accepted row carries the REAL
    /// signature at `tier = local`, `promoted_at = None` — never a durable
    /// unsigned local row: the consent-SLA watcher drives it to promotion
    /// (federation-tier) or flags it overdue within the bounded window.
    TransitRevocation,
}

/// True iff `(attestation_type, dimension, writer, subjects)` is a
/// **subject-side** consent revocation (CEG §10.1.3, AV-61): a `withdraws`
/// (structural) or a `consent:state:revoked` dimension whose writer
/// (`attesting_key_id`) is a member of `subject_key_ids` — the subject
/// exercising its own revocation right. The transit-not-rest classifier.
#[must_use]
pub fn is_subject_side_revocation(
    attestation_type: &str,
    dimension: Option<&str>,
    attesting_key_id: &str,
    subject_key_ids: &[String],
) -> bool {
    let is_revocation = attestation_type == crate::federation::types::attestation_type::WITHDRAWS
        || dimension.is_some_and(|d| {
            d.starts_with(crate::federation::consent::consent_dimension::STATE_REVOKED_PREFIX)
        });
    is_revocation && subject_key_ids.iter().any(|s| s == attesting_key_id)
}

/// v4.4.0 (CIRISPersist#171, CEG §10.1.3/§10.1.5/§7.5) — gate a row's
/// eligibility for the **local tier** (signature-deferred,
/// producer-only-authority). Local-tier eligibility is producer
/// authority — NOT empty `subject_key_ids` (CEG §4.2.6: producer-
/// authority rows legitimately name subjects).
///
/// One class is **hard-refused** at local tier:
///
///   1. **`capacity:*` (CEG §7.5 anti-Goodhart, AV-62).** A `capacity:*`
///      dimension rejects self-emission; the local tier's self-write →
///      self-read → deferred-sig shape is precisely the §7.5 forbidden
///      loop. Capacity is inherently third-party-attested.
///
/// A second class is **admitted as transit, not durable** (v12.6.0,
/// resolving AV-61 per the §10.1.3 transit-not-rest ratification):
///
///   2. **Subject-side revocation (CEG §10.1.3, AV-61).** A `withdraws`
///      (structural) or a `consent:state:revoked` dimension whose
///      **writer (`attesting_key_id`) is a member of `subject_key_ids`**
///      — the subject exercising its own revocation right. It is
///      federation-tier by classification but MAY *transit* the local
///      write path: this returns [`LocalTierDisposition::TransitRevocation`]
///      so the backend verifies the bound-hybrid signature before storing
///      (accept on VALID crypto only) and marks the row transit (signed,
///      `tier = local`, promotable/flaggable — never a durable local row).
///      Pre-v12.6.0 this was a hard `Err`, which left the consent-SLA
///      watcher firing on nothing (persist refused to originate any row for
///      it to observe).
///
/// `dimension` is the envelope dimension ([`envelope_dimension`]);
/// `attestation_type` is the §3 structural primitive. Returns
/// [`Error::InvalidArgument`] on an ineligible row (bad cohort_scope /
/// capacity:*); otherwise the [`LocalTierDisposition`].
pub fn check_local_tier_eligibility(
    attestation_type: &str,
    dimension: Option<&str>,
    attesting_key_id: &str,
    subject_key_ids: &[String],
    cohort_scope: &str,
) -> Result<LocalTierDisposition, Error> {
    // (0) local rows are `self`-scoped (private to the producing
    // occurrence). The v4.0 `self`-cohort read-gate then IS the tier
    // read-gate (FSD §3 / CEG §10.1.5, AV-59); promotion widens scope.
    if cohort_scope != crate::federation::types::cohort_scope::SELF {
        return Err(Error::InvalidArgument(format!(
            "local-tier attestations must be cohort_scope='self' (private to the \
             producing occurrence until promotion; CEG §10.1.5 tier read-gate, AV-59) \
             — got '{cohort_scope}'"
        )));
    }
    // (1) capacity:* — never local (anti-Goodhart §7.5 / AV-62). The rule
    // itself lives in [`check_capacity_never_local`] so that `put_attestation`
    // — the OTHER door onto the local tier — asks the identical predicate
    // rather than a second copy of it (CIRISPersist#589 / AV-83).
    check_capacity_never_local(attestation_type, dimension)?;
    // (2) subject-side revocation — admitted as TRANSIT (§10.1.3, AV-61):
    // the backend hybrid-verifies before storing, marks it transit, and the
    // consent-SLA watcher drives it to promotion / overdue-flag.
    if is_subject_side_revocation(
        attestation_type,
        dimension,
        attesting_key_id,
        subject_key_ids,
    ) {
        return Ok(LocalTierDisposition::TransitRevocation);
    }
    Ok(LocalTierDisposition::Durable)
}

/// v26.0.0 (CIRISPersist#589, AV-83) — **`capacity:*` IS NEVER LOCAL**, stated
/// once and asked at BOTH doors onto the local tier.
///
/// # Why this is its own function
///
/// The rule is v4.4.0's (CEG §7.5 anti-Goodhart / AV-62) and it was already
/// written, tested and shipped — inside [`check_local_tier_eligibility`], which
/// runs on `attestation_insert_local` / `attestation_upsert_local` and **only**
/// there. `put_attestation` accepts a `tier = "local"` row on every backend and
/// never consulted it, so the correct rule sat behind a door the attack does
/// not use: CIRISPersist#589, the third occurrence of the
/// [SHIPPED-means-host-reachable class](https://github.com/CIRISAI/CIRISPersist/issues/444)
/// after AV-77 and #444's route table.
///
/// Lifting the arm out (rather than copy-pasting the condition into
/// `put_attestation`) is the one-predicate-one-implementation rule: two
/// validators for one artifact MUST share one predicate, or they drift and the
/// weaker one becomes the real policy.
///
/// # Both wire shapes
///
/// Reputation rides `attestation_type = scores` with the family in
/// `dimension`, but the type-keyed shape (`attestation_type = capacity:*`)
/// exists too, and #543 finding 2 was exactly a guard that saw one of them.
/// This asks both, in the same precedence [`consent_gated_claim`] uses
/// (dimension first — it is the axis the emit path actually writes).
///
/// # Why the refusal says "never local" and not "no consent"
///
/// A local-tier row is not an emission, so the CC 3.4.5 consent gate has
/// nothing to bind to yet and deliberately no-ops there. Widening THAT gate to
/// cover local rows would refuse this row with a "no consent" message, which is
/// a true statement about the wrong rule: the row would be inadmissible even
/// with a live `analyze` grant, because capacity is third-party-attested and
/// the local tier's self-write → self-read → deferred-signature shape is the
/// §7.5 forbidden loop. A refusal that names the wrong rule sends the reader to
/// the wrong layer (#575).
pub fn check_capacity_never_local(
    attestation_type: &str,
    dimension: Option<&str>,
) -> Result<(), Error> {
    let claimed = dimension
        .filter(|d| d.starts_with(CAPACITY_FAMILY_PREFIX))
        .or(Some(attestation_type).filter(|t| t.starts_with(CAPACITY_FAMILY_PREFIX)));
    let Some(claimed) = claimed else {
        return Ok(());
    };
    Err(Error::InvalidArgument(format!(
        "capacity:* attestations are ineligible for the local tier (CEG §7.5 \
         anti-Goodhart, AV-62): capacity is third-party-attested — federation-tier, \
         signed, attesting_key_id != attested_key_id — got '{claimed}'"
    )))
}

/// CIRISPersist#592 (AV-84) — **WHICH party** made a targeted-cohort
/// placement something other than a producer self-declaration.
///
/// Closed, snake_case serde tokens, [`Self::as_str`] returning the SAME token,
/// no `Other` catch-all — the #565 `KeyRefusalReason` discipline. "The
/// placement was refused" is not an answer an operator can act on;
/// "`attested_party`" points at the field to fix.
///
/// **The token set is the downstream contract and this mapping is
/// APPEND-ONLY.** Add variants; never re-spell one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortStandingRefusal {
    /// `attested_key_id` is not the row's own producer: the row is a claim
    /// ABOUT somebody else, and placing it into a cohort plane publishes that
    /// claim to a cohort the producer cannot be shown to stand in.
    AttestedParty,
    /// `subject_key_ids` names a key other than the producer. Subject-naming is
    /// the revocability-authority surface (CEG 0.6 §4.2), so a row that names
    /// a foreign subject is a row a foreign party has standing over — not a
    /// self-declaration about the producer's own content's visibility.
    NamedSubject,
}

impl CohortStandingRefusal {
    /// The **stable program token** — identical to the serde token.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AttestedParty => "attested_party",
            Self::NamedSubject => "named_subject",
        }
    }

    /// The row field the refusal is about.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        match self {
            Self::AttestedParty => "attested_key_id",
            Self::NamedSubject => "subject_key_ids",
        }
    }

    /// Every variant, in declaration order — the closed set.
    pub const ALL: &'static [Self] = &[Self::AttestedParty, Self::NamedSubject];
}

impl std::fmt::Display for CohortStandingRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// CIRISPersist#592 (AV-84) — **THE TARGETED-COHORT STANDING GATE**:
/// a row reaches the `family` / `community` plane only as a self-declaration by
/// its own producer.
///
/// # Why this is not AV-45, and must not be
///
/// AV-45 ([`DimensionAdmissionPolicy::check_write_cohort_scope`]) asks *"is the
/// writer a member of the target cohort it names?"* On `federation_attestations`
/// that question is **unaskable**: the row carries a `cohort_scope` and no
/// `cohort_target_id`, so the predicate's `family` / `community` arms refuse on
/// a `None` target — which, on this table, is every row. `put_attestation`
/// therefore refuses those two placements outright, and that door is SHUT, not
/// leaking.
///
/// The promote door cannot copy that answer. Promotion is the ONLY door those
/// placements have ever had, so refusing them there deletes the #519/#510
/// audience plane — a product amputation wearing a security fix's clothes, and
/// the reason CIRISPersist#589 left AV-45 out of
/// [`check_promotion_admission`]. **This is a different predicate for a
/// different question, deliberately: one implementation forced onto two
/// questions is the axis-fusion defect this repo gates against.**
///
/// # The question this one CAN ask
///
/// #589 wrote down why the promote door's exemption is defensible:
///
/// > A promotion re-publishes a row this node itself authored (local tier IS
/// > producer authority) at an audience taken from this node's OWN signed
/// > consent grant — a self-declaration about its own content's visibility, not
/// > a claim about someone else's cohort.
///
/// **Nothing enforced that sentence.** `attestation_promote` is a raw primitive
/// that places ANY local-tier row, including one authored by — and about — a
/// peer; and `promote_consented_backlog` pages
/// `list_local_tier_attestations` (`WHERE tier = 'local'`, no author
/// predicate), so a peer's local row is promoted under THIS node's grant and
/// re-signed with THIS node's key. The excuse for AV-45's absence was itself
/// unchecked, which is the [SHIPPED-means-host-reachable](https://github.com/CIRISAI/CIRISPersist/issues/444)
/// class read in the mirror: not a rule written behind a door nothing uses, but
/// a *precondition asserted in prose that no door ever tests*.
///
/// So this gate makes it testable, and tests it: for `family` / `community`,
/// the row must name **no party but its own producer** —
/// `attested_key_id == attesting_key_id`, and every `subject_key_ids` entry is
/// the producer. Anything else is a claim about a third party being published
/// into a cohort plane, which is exactly the unverifiable cohort claim AV-45
/// refuses at the put door, arriving through the one door AV-45 cannot stand at.
///
/// # Scope, stated as a limit rather than implied
///
/// The broad belonging-tiers (`affiliations` / `species` / `biosphere` /
/// `federation`) are untouched: AV-45's own rule for them is *"no per-row
/// target; any authenticated writer may emit"*, so there is no cohort to have
/// standing in and this gate has nothing to ask. `self` is refused earlier by
/// the placement-validity arm (#315/#519). Widening this to a general ban on
/// promoting third-party rows would be a DIFFERENT gate shipped silently under
/// this one's name.
///
/// What this does **not** close, stated plainly so it does not quietly become
/// untrue: a producer that belongs to no community can still place its OWN
/// content at `community`. That placement names no cohort — the row has no
/// field to name one — so it is unprovable in the same way for everybody, and
/// closing it means naming the target end-to-end (grant grammar, promotion
/// signature, and a stored column if it is ever to be read back). See
/// [`tests::promotion_does_not_prove_cohort_membership_589`], which still
/// holds and still pins that residual.
///
/// Pure: no directory read, no configuration, no `self_key_id`. It cannot
/// fail open on an unset node identity, and it is free — which is why it leads
/// [`check_promotion_admission`]'s cheapest-refusal-first ordering.
pub fn check_promotion_cohort_standing(row: &super::Attestation) -> Result<(), Error> {
    use crate::federation::types::cohort_scope as cs;

    // Only the TARGETED cohorts. The broad belonging-tiers have no cohort to
    // stand in; `self` is already refused by the placement-validity arm.
    if row.cohort_scope != cs::FAMILY && row.cohort_scope != cs::COMMUNITY {
        return Ok(());
    }

    let producer = row.attesting_key_id.as_str();
    let refuse = |reason: CohortStandingRefusal, foreign: &str| {
        Err(Error::CohortStandingRefused {
            cohort_scope: row.cohort_scope.clone(),
            producer_key_id: producer.to_owned(),
            foreign_key_id: foreign.to_owned(),
            reason,
        })
    };

    if row.attested_key_id != producer {
        return refuse(CohortStandingRefusal::AttestedParty, &row.attested_key_id);
    }
    if let Some(foreign) = row.subject_key_ids.iter().find(|s| s.as_str() != producer) {
        return refuse(CohortStandingRefusal::NamedSubject, foreign);
    }
    Ok(())
}

/// v26.0.0 (CIRISPersist#589, AV-83) — **THE PROMOTION ADMISSION GATE**: the
/// tier-4 authority stack, re-run against the row a promotion is about to
/// store.
///
/// # The hole this closes
///
/// `Engine::attestation_promote` and the backends' `promote_attestation` /
/// `promote_attestation_transformed` re-sign a row and flip `tier`
/// local→federation. Before this gate they ran **no** put-gate at all: the
/// promote path validated `cohort_scope`, refused `(federation, self)`, and was
/// idempotent on an already-federation row, and that was the whole of it.
///
/// So every tier-4 gate that is a no-op at the local tier had never been asked
/// about a promoted row — and promotion is the moment those rows become
/// federation-tier. The consent gate is the sharpest instance and the reason
/// this is a **MUST** violation rather than a gap: CC 3.4.5's reciprocity
/// clause says a subject that declines analysis *"cannot be scored; its
/// `capacity:composite` is undefined and MUST NOT be emitted"*, and promote
/// could mint exactly that row. Because `capacity:composite` is `min` over five
/// factors ([CC 3.1.8.1](https://github.com/CIRISAI/CIRISConstitution)), one
/// leaked row certifies five.
///
/// # The rule for what belongs here
///
/// > A promotion re-runs every tier-4 gate whose verdict is a function of state
/// > that can have changed since the local write, and that neither mutates the
/// > row nor assumes the row is not yet stored.
///
/// Both halves of that sentence are load-bearing. The first admits the gates a
/// promotion is genuinely the FIRST (or a fresh) opportunity to face. The
/// second excludes three gates whose preconditions are false here — see
/// "Deliberately not re-run" below — because re-running a gate outside its
/// stated precondition is how a fix becomes the next defect.
///
/// # What it re-runs
///
/// **Pure** — no directory read, so it leads (CIRISPersist#592):
///
/// 0. [`check_promotion_cohort_standing`] — AV-84. A `family` / `community`
///    placement is a producer self-declaration or it is refused. Not AV-45
///    finally wired in — a DIFFERENT predicate for a question AV-45 cannot ask
///    on this table; see "AV-45 is deliberately NOT here" below.
///
/// **Tier-sensitive** — these no-op at `tier = "local"`, so the promotion is
/// the first time they are ever asked:
///
/// 1. [`check_capacity_consent_admission`] — CC 3.4.5 consent-before-scoring.
/// 2. [`check_no_moderator_federate_apply`] — CC 4.5.4 / §11.11: a
///    federation-tier row keyed on a community whose last live `moderate`
///    holder is gone.
///
/// **Time-varying authority** — the verdict at the local write does not bind at
/// promotion, and all of these are read-only:
///
/// 3. [`check_peer_deadmission`] — AV-77. The node may have de-admitted the
///    row's author in between; a promotion that ignores that would republish
///    the author's claims out of a sanction the node has already declared.
/// 4. [`check_delegated_duty_scores_admission`] — the moderation / review /
///    quarantine duty delegation may have expired or been withdrawn.
/// 5. [`check_reserved_prefix_admission`] — carries AV-62/74's dimension-keyed
///    self-emission arm, and keys on the attester's `identity_type`, which a
///    role withdrawal can change.
/// 6. [`check_node_agency_admission`] /
///    [`check_user_target_steward_binding_admission`] — the recipient's
///    identity type and the minor/adult proofs behind them are directory state
///    that moves.
///
/// # Ordering
///
/// Ordered cheapest-refusal-first within the constraint that nothing here may
/// return early to ACCEPT — every arm either refuses or falls through to the
/// next. That is the AV-76 tier-4b lesson stated as a precondition rather than
/// re-learned: *a short-circuit may return early to refuse, never to accept.*
/// There is no dedup arm here for exactly that reason.
///
/// # AV-45 is deliberately NOT here, and this is the residual
///
/// **CIRISPersist#592 (AV-84) update:** everything below still holds
/// verbatim — AV-45's predicate is still unaskable on this table and running it
/// here would still delete the audience plane. What changed is the last
/// paragraph's *"what remains true"*: the provenance argument that justifies
/// the asymmetry (a promotion republishes a row THIS NODE ITSELF AUTHORED) was
/// asserted and never enforced, and [`check_promotion_cohort_standing`] now
/// enforces it. The SCHEMA question — persist cannot PROVE a family/community
/// placement, because the row has nowhere to name the family or community it
/// means — is unchanged and still tracked separately.
///
/// A promotion stamps a `cohort_scope`, which looks like the fresh membership
/// claim [`check_write_cohort_scope_for`](super::FederationDirectory::check_write_cohort_scope_for)
/// exists to police — and #589 named AV-45 as part of the bypassed class. It is
/// left out on purpose, and the reasoning is recorded here rather than in a
/// commit message because the next reader will ask.
///
/// Attestations carry a `cohort_scope` label but **no** `cohort_target_id`, so
/// [`DimensionAdmissionPolicy::check_write_cohort_scope`] refuses `family` /
/// `community` whenever the target is `None` — which, on this table, is always.
/// Running AV-45 here would therefore not *check* a promotion's placement, it
/// would make `family` / `community` placements **unreachable**: every
/// `attestation_promote(id, "community")` and every #510
/// `consent:replication:v1` grant naming `audience: community | family` would
/// refuse. Promotion is the only door those placements have ever had, so
/// "enforce AV-45 here" reduces to "delete the #519/#510 audience plane". That
/// is a product amputation wearing a security fix's clothes, and it is not
/// this issue's defect.
///
/// The provenance also differs, which is why the asymmetry is defensible rather
/// than merely convenient. AV-45 at `put_attestation` polices an INBOUND row
/// from a peer asserting a cohort label persist cannot verify. A promotion
/// re-publishes a row this node itself authored (local tier IS producer
/// authority) at an audience taken from this node's OWN signed consent grant —
/// a self-declaration about its own content's visibility, not a claim about
/// someone else's cohort.
///
/// What remains true, and is the residual: persist cannot *prove* a
/// family/community placement on any path, because the row has nowhere to name
/// the family or community it means. Closing that is a SCHEMA question — give
/// the row a `cohort_target_id` and AV-45 becomes answerable at both doors —
/// not a gate question, and it is tracked as its own defect rather than
/// smuggled in here. [`tests::promotion_does_not_prove_cohort_membership_589`]
/// is the executed witness that the residual is real, so it cannot quietly
/// become untrue in either direction.
///
/// CIRISPersist#592 took the ANSWERABLE half of that residual and left the
/// schema half exactly where it was: a producer that belongs to no community
/// can still place its OWN content at `community`, because the row still cannot
/// name a community for anybody. What it can no longer do is place someone
/// ELSE's content there — see [`check_promotion_cohort_standing`].
///
/// # Deliberately NOT re-run, and why
///
/// - **The §6.1 dedup short-circuit (tier 4b).** It is an early ACCEPT, and a
///   promotion is not a new row; running it here would skip everything after
///   it. This is the AV-76 hole in its original shape.
/// - **[`check_withdraws_admission`].** It STAMPS `withdraws_admission_rule`,
///   a hash-covered field, and the promoted `persist_row_hash` already covers
///   the value the local write resolved. Re-running it would let a
///   later-changing delegation silently rewrite a stored row's audit metadata.
/// - **[`check_single_node_owner_admission`].** Its own doc pins the
///   precondition: *"The incoming row is NOT yet stored (this runs
///   pre-insert)"*. At promotion the row IS stored, so the incumbent set it
///   walks is no longer the set it was written to reason about.
/// - **The trust-charter gates.** Same class: they classify a row entering the
///   corpus, and a promoted row is already in it.
///
/// # Where it is called
///
/// Every backend's `promote_attestation` AND `promote_attestation_transformed`,
/// **before any mutation** (verify-before-mutation, AV-9) and — on the memory
/// backend — before the state lock is taken, since every gate here reads the
/// directory through the same lock. One chokepoint per backend means
/// `Engine::attestation_promote`, `Engine::promote_attestation_with_transforms`,
/// `promote_consented_backlog`, the pyo3 wrapper and the FFI capsule all
/// inherit it without a call site of their own.
///
/// `row` MUST be the row **as it will be stored** — `tier = "federation"`, the
/// post-promotion `cohort_scope`, and (for the transformed path) the
/// TRANSFORMED envelope. Gating the pre-promotion shape would ask every
/// tier-sensitive gate the question it already no-ops on.
pub async fn check_promotion_admission(
    directory: &dyn super::FederationDirectory,
    row: &super::Attestation,
    self_key_id: Option<&str>,
) -> Result<(), Error> {
    // The placement itself must be a legal, federation-visible value. Pure,
    // free, and a REFUSAL — so it leads. `(federation, self)` is the #315
    // incoherent state (substrate-local-only scope on a replicate-me tier; the
    // offer filter drops it), refused here so every caller of the primitive
    // inherits the rule, not just `Engine::attestation_promote`.
    if !crate::federation::types::cohort_scope::is_valid(&row.cohort_scope)
        || row.cohort_scope == crate::federation::types::cohort_scope::SELF
    {
        return Err(Error::InvalidArgument(format!(
            "promotion placement {:?} is not a valid federation-visible cohort_scope \
             (self / invalid rejected — CIRISPersist#519/#315)",
            row.cohort_scope
        )));
    }

    // AV-84 — a TARGETED cohort placement (`family` / `community`) is a
    // producer self-declaration or it is refused. Pure and free, so it leads
    // the walks; and #589's justification for AV-45's absence from this stack
    // is precisely the sentence this arm turns into a check.
    check_promotion_cohort_standing(row)?;

    // v30.13.0 (CIRISPersist#598) — the consent instant BINDING, asked at the
    // promote door for the B8 reason: a row must not escape a put-gate by
    // entering at the local tier and being PROMOTED. Only federation-tier rows
    // reach the consent folds (`list_attestations_for` filters on tier), so
    // promotion is the OTHER way a `consent:state:*` row arrives there — and
    // the local door mints `asserted_at` from this node's own clock, which is
    // exactly the bumped ordering key the replay wants. Pure, so it leads.
    check_consent_state_instant_binding(row, chrono::Utc::now(), DEFAULT_MAX_TOUCH_SKEW)?;

    // AV-77 — a de-admitted author's rows are refused before any walk runs, so
    // a sanctioned peer also sheds the amplification cost (same posture as
    // `put_attestation`'s tier-4 placement).
    if let Some(me) = self_key_id {
        check_peer_deadmission(directory, row, me).await?;
    }

    // AV-62/74 — reserved-prefix + the dimension-keyed capacity self-emission
    // arm. Kept IMMEDIATELY ahead of the consent gate for the same reason
    // `put_attestation` does: a SELF-attested capacity row must be reported as
    // self-emission, not shadowed by "no consent".
    check_reserved_prefix_admission(directory, row).await?;

    // CC 3.4.5 — CONSENT BEFORE SCORING. The MUST this issue is rated on.
    check_capacity_consent_admission(directory, row).await?;

    // §11.10 moderation / reconsideration / quarantine duty.
    check_delegated_duty_scores_admission(directory, row).await?;

    // CC 4.4.3.4.3 — infrastructure must not have agency.
    check_node_agency_admission(directory, row).await?;

    // CC 3.2 / CC 1.15.6 — a `delegates_to` onto a `user` target is admissible
    // only as minor-guardianship.
    check_user_target_steward_binding_admission(directory, row).await?;

    // CC 4.5.4 / §11.11 — a federation apply step keyed on a moderator-less
    // community. Tier-sensitive, and now reached for the first time.
    check_no_moderator_federate_apply(directory, row).await?;

    Ok(())
}

/// v19.0.0 (CIRISPersist#486) — lift the **envelope-attested** roles into
/// `KeyRecord.roles` at admission.
///
/// Verify's ceremony DOES attest roles: `produce_scrubbed_key_record`
/// materializes `ScrubTarget.roles` into the scrub-signed
/// `registration_envelope` (`"roles"`), and `roles_in_envelope()` exposes
/// them — but persist never read that surface, so an accord co-scrub could
/// attest `infra:serve` and every `claims_role` / `has_accord_conferred_role`
/// consumer still saw `[]`. The attestation was made and dropped on the
/// floor (the actual root cause behind #480's dark trace plane).
///
/// Semantics — **union, then gate**:
/// - The envelope set (mirroring verify's `roles_in_envelope()` codec
///   byte-for-byte: `envelope["roles"]` as `Vec<String>`, absent → empty) is
///   unioned into the top-level `roles` claim surface.
/// - Runs BEFORE the role write-gates in `put_public_key`, so a lifted
///   gated role (`canonical` / `infra:attest` / co-steward) still faces its
///   co-scrub admission gate — lifting creates VISIBILITY, never conferral.
///   Tampering the envelope's `roles` breaks the scrub signatures (the
///   envelope is the signed bytes), and effectiveness is ALWAYS re-derived
///   (`has_accord_conferred_role` re-verifies the co-scrub against the live
///   roster) — so wire-supplied top-level roles stay exactly as untrusted
///   as before: a claim, not a capability.
pub fn lift_envelope_attested_roles(row: &mut super::KeyRecord) {
    let envelope_roles: Vec<String> = row
        .registration_envelope
        .get("roles")
        .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
        .unwrap_or_default();
    for role in envelope_roles {
        if !row.capability_roles.contains(&role) {
            row.capability_roles.push(role);
        }
    }
}

/// v18.1.0 (CIRISPersist#473 followup) — the `trace:` namespace prefix. The
/// dimension is the CEG's Information-Type parameter; `trace:*` is the
/// envelope-native trace family (`trace:complete:v1` = the v18.0.0 ingest
/// mint's member). Registry entry + validator pending CC ratification
/// (namespace catalog + `trace_manifest:v1` schema + the self-emission rule);
/// this const + [`check_trace_dimension_admission`] are persist's
/// machine-checkable interim, the same posture as the CC#38 size cap.
pub const TRACE_DIMENSION_PREFIX: &str = "trace:";

/// CIRISPersist#579 (CC 3.1.5 → CC 2.6.3) — is `s` a well-formed sha256 digest
/// token: the literal `"sha256:"` followed by **exactly 64 lowercase hex
/// digits**?
///
/// CC 2.6.3 is the encoding rule every digest on the wire follows, and CC 3.1.5
/// binds `trace_manifest:v1.content_hash` to it. Checking the prefix and "there
/// is something after it" admits `sha256:` + a sentence, `sha256:DEADBEEF`
/// (uppercase — a DIFFERENT byte string that hashes differently downstream),
/// and a truncated digest: shapes a consumer will fail on, admitted here as
/// conformant. A shape check that admits a malformed value is not a shape
/// check.
fn is_sha256_digest_token(s: &str) -> bool {
    const PREFIX: &str = "sha256:";
    const HEX_LEN: usize = 64;
    s.strip_prefix(PREFIX).is_some_and(|hex| {
        hex.len() == HEX_LEN
            && hex
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}

/// v18.1.0 (CIRISPersist#473 followup) — the `trace:*` Information-Type
/// validator. No-op for non-`trace:` dimensions. For `trace:*`:
///
/// 1. **Self-emission** (the inverse polarity of `capacity:*`'s anti-self
///    rule): a trace records its own producer's reasoning, so
///    `attesting_key_id` MUST appear in `subject_key_ids`. Third-party
///    emission on the namespace is refused.
/// 2. **Shape**: the envelope MUST carry `trace_id` + `agent_id_hash`
///    (strings) and EXACTLY ONE of:
///    - `trace` (object) — the inline post-scrub CompleteTrace, or
///    - `manifest` (object) — `schema == "trace_manifest:v1"`,
///      `content_hash` a CC 2.6.3 digest token (`"sha256:"` + 64 lowercase
///      hex — [`is_sha256_digest_token`], CIRISPersist#579), positive integer
///      `byte_len`, integer `component_count` (the CC#38 oversize form).
///
/// Admission validates SHAPE, machine-checkably — a `trace:*` row that
/// admits is guaranteed parseable by every consumer. PROVENANCE rides the
/// producer signature inside the envelope (verified at promotion/read);
/// neither half substitutes for the other.
pub fn check_trace_dimension_admission(
    dimension: Option<&str>,
    attesting_key_id: &str,
    subject_key_ids: &[String],
    envelope: &serde_json::Value,
) -> Result<(), Error> {
    let Some(dim) = dimension else {
        return Ok(());
    };
    if !dim.starts_with(TRACE_DIMENSION_PREFIX) {
        return Ok(());
    }
    let refuse = |detail: String| Err(Error::TraceDimensionInvalid { detail });

    // 1. Self-emission.
    if !subject_key_ids.iter().any(|s| s == attesting_key_id) {
        return refuse(format!(
            "trace:* is self-emitted: attesting_key_id {attesting_key_id} must appear in \
             subject_key_ids (a trace records its own producer's reasoning)"
        ));
    }

    // 2. Required identity fields.
    for field in ["trace_id", "agent_id_hash"] {
        match envelope.get(field) {
            Some(serde_json::Value::String(v)) if !v.is_empty() => {}
            _ => {
                return refuse(format!(
                    "trace:* envelope must carry non-empty string \"{field}\""
                ))
            }
        }
    }

    // 3. Exactly one of inline `trace` / `manifest`.
    let inline = envelope.get("trace");
    let manifest = envelope.get("manifest");
    match (inline, manifest) {
        (Some(t), None) => {
            if !t.is_object() {
                return refuse("trace:* inline form: \"trace\" must be an object".into());
            }
        }
        (None, Some(m)) => {
            let Some(m) = m.as_object() else {
                return refuse("trace:* manifest form: \"manifest\" must be an object".into());
            };
            if m.get("schema").and_then(|v| v.as_str()) != Some("trace_manifest:v1") {
                return refuse(
                    "trace:* manifest form: \"schema\" must be \"trace_manifest:v1\"".into(),
                );
            }
            match m.get("content_hash").and_then(|v| v.as_str()) {
                Some(h) if is_sha256_digest_token(h) => {}
                _ => {
                    return refuse(
                        "trace:* manifest form: \"content_hash\" must be \
                         \"sha256:\" + 64 lowercase hex (CC 3.1.5 / CC 2.6.3)"
                            .into(),
                    )
                }
            }
            match m.get("byte_len").and_then(|v| v.as_u64()) {
                Some(n) if n > 0 => {}
                _ => {
                    return refuse(
                        "trace:* manifest form: \"byte_len\" must be a positive integer".into(),
                    )
                }
            }
            if m.get("component_count").and_then(|v| v.as_u64()).is_none() {
                return refuse(
                    "trace:* manifest form: \"component_count\" must be an integer".into(),
                );
            }
        }
        (Some(_), Some(_)) => {
            return refuse(
                "trace:* envelope must carry EXACTLY ONE of \"trace\" / \"manifest\", not both"
                    .into(),
            )
        }
        (None, None) => {
            return refuse(
                "trace:* envelope must carry one of \"trace\" (inline) / \"manifest\"".into(),
            )
        }
    }
    Ok(())
}

/// v4.4.0 (CIRISPersist#171, CEG §7.5 / AV-62) — the federation-path
/// mirror of the `capacity:*` anti-Goodhart rule: a `capacity:*` row
/// MUST have `attesting_key_id != attested_key_id` (no self-scoring).
/// Enforced on `put_attestation` / `attestation_promote`. `Ok(())` for
/// non-capacity rows.
pub fn check_capacity_not_self_attested(
    dimension: Option<&str>,
    attesting_key_id: &str,
    attested_key_id: &str,
) -> Result<(), Error> {
    if dimension.is_some_and(|d| d.starts_with("capacity:")) && attesting_key_id == attested_key_id
    {
        return Err(Error::InvalidArgument(
            "capacity:* attestation must not be self-attested (attesting_key_id == \
             attested_key_id) — CEG §7.5 anti-Goodhart, AV-62"
                .to_string(),
        ));
    }
    Ok(())
}

/// v25.1.0 (CIRISPersist#569) — the `capacity:*` prefix, named once. The
/// substrate's own open-sender reputation family; verify's namespace does not
/// contain it, so it is the one member of the consent-gated set persist owns.
///
/// `capacity_assurance:*` is a DIFFERENT family (it does not start with
/// `capacity:` — the next byte is `_`) and is deliberately NOT matched: it is
/// role-gated (a registered `witness` assessor), not open-sender.
pub const CAPACITY_FAMILY_PREFIX: &str = "capacity:";

/// v25.1.0 (CIRISPersist#569) — **WHICH consent rule** a dimension falls under.
///
/// Closed, and every variant corresponds to exactly one classification source.
/// Deliberately no `Other` — a catch-all would reintroduce the "which rule
/// refused me?" disjunction one name deeper (the #565 / #575 lesson). Serde
/// tokens are snake_case and [`Self::as_str`] returns the SAME token, so a
/// consumer keys on a program constant and never on a message string. The
/// token set is the downstream contract and this mapping is **APPEND-ONLY**.
///
/// **One variant today, and that is the ruling — not an oversight.** #569
/// briefly added a `VerifyConsensualReputation` variant covering every family
/// CIRISVerify's registry classifies `ConsensualReputation`; CC 3.4.5's
/// per-family disposition put all four of them OUTSIDE the gate (see
/// [`consent_gated_family`]) and the variant was removed before merge. The
/// type stays because a refusal must still name its rule as a program
/// constant, and because the boundary it draws is the one CC 3.4.5 drew:
/// *"consent-before-scoring binds the family that judges agents —
/// `capacity:*` — never the families that verify artifacts."* If a future CC
/// amendment moves a family across that line, it arrives here as a new
/// variant and as a deliberate edit to
/// [`tests::verify_dimension_registry_is_the_only_enumeration`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentGatedFamily {
    /// [`CAPACITY_FAMILY_PREFIX`] — CC 3.4.5's open-sender reputation family,
    /// consent-gated since v22.0.0 (CIRISConstitution#46 / AV-79). The family
    /// that judges an AGENT, which is what makes it the gated one.
    Capacity,
}

impl ConsentGatedFamily {
    /// The **stable program token** for this classification — identical to the
    /// serde token, so a consumer that reads the wire and a consumer that
    /// holds the typed value key on the same constant.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Capacity => "capacity",
        }
    }

    /// Every variant, in declaration order — the closed set, for exhaustive
    /// gates and for a consumer enumerating the taxonomy it must handle.
    pub const ALL: &'static [Self] = &[Self::Capacity];
}

impl std::fmt::Display for ConsentGatedFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// v25.1.0 (CIRISPersist#569) — is `dimension` consent-gated, and under which
/// rule? `None` for every family outside the gated set.
///
/// # The gated set is `capacity:*`, and CC 3.4.5 is why
///
/// CIRISPersist#569 widened this predicate to every family CIRISVerify's
/// registry then classified `ConsensualReputation` (deliberately plain text,
/// not an intra-doc link: verify's classification type is the one surface that
/// moves under a re-pin, and it is named in exactly one place — see
/// [`tests::verify_dimension_registry_is_the_only_enumeration`])
/// — `attestation:registry_consensus`, `attestation:license_validity`,
/// `cert_validity:{authority}`, `rollback_detected:{revision_field}`. **CC
/// 3.4.5's per-family disposition paragraph put every one of them outside the
/// gate**, and the widening was held before merge:
///
/// - the first three, with `provenance:*` and the rest, are **artifact-integrity
///   verification** — they *"score builds, manifests, licenses and certificates
///   — not a subject's conduct or capacity; integrity checking is the trust
///   precondition, and a forger never consents to verification"*;
/// - `rollback_detected:{revision_field}` is *"an adversarial detector (−1-only
///   polarity), on the abuse-response side of the line by construction"* —
///   gating it would let an adversary opt out of its own rollback detection,
///   which is the very thing #569 said it would never do when it left
///   `detection:*` / `moderation:*` / `slashing:*` alone;
/// - and the rule itself: *"Consent-before-scoring binds the family that judges
///   **agents** — `capacity:*` — never the families that verify **artifacts**."*
///
/// # Where #569 was right, and where it was wrong
///
/// #569 refused to hold a hand-copied list and derived its set from
/// [`dim::lookup`](ciris_verify_core::federation_provenance::dim::lookup) —
/// the correct instinct, and the #541 / #532 / #574 lesson applied. Its error
/// was one layer up: it treated verify's classification as a *ruling*, when
/// verify itself called the split **"a proposal from the measuring side, not a
/// ruling"** — in prose, in a document persist's reader never opened. Verify
/// knows what each dimension IS; the Constitution decides what the substrate
/// does about it. So this predicate reads the floor, not the measuring side —
/// and [`tests::verify_dimension_registry_is_the_only_enumeration`] is the
/// adjudication record that keeps the two visible to each other, going red if
/// EITHER moves.
///
/// # (#568): the answer now lives in the type
///
/// CIRISVerify v12.1.0's `classification::{Gating, Classification}` — asked
/// for by persist (CIRISVerify#238) precisely because of the above — makes
/// each shipped classification state whether a consumer may gate on it, and
/// on whose authority. `ConsentDisposition` declares
/// `Normative { authority: "CC 3.4.5" }`: **the same document this predicate
/// reads.** The adjudication record now asks
/// [`standing_of`]`::<ConsentDisposition>()` rather than asking a human to
/// remember which side was measuring, and — because both sides now cite one
/// ratified rule — it requires them to AGREE family-by-family instead of
/// asserting one side alone.
///
/// # Not a weakening (CC 3.4.5, reciprocity clause)
///
/// *"A subject that declines analysis cannot be scored; its
/// `capacity:composite` is undefined and MUST NOT be emitted; and every gate
/// that requires a capacity verdict therefore **fails closed** for that
/// subject."* Consent-before-scoring is reciprocal: a declining subject is not
/// scored at all, which is a stronger outcome than being scored without
/// consent — while the planes that verify artifacts and report abuse, which
/// never judged that subject's conduct, keep working.
#[must_use]
pub fn consent_gated_family(dimension: &str) -> Option<ConsentGatedFamily> {
    if dimension.starts_with(CAPACITY_FAMILY_PREFIX) {
        return Some(ConsentGatedFamily::Capacity);
    }
    // Everything else, deliberately: verify's whole namespace (artifact
    // integrity, log infrastructure, self-reports, and the `rollback_detected:`
    // adversarial detector) per CC 3.4.5's per-family disposition, plus every
    // role-gated abuse-response family outside it (`detection:*` /
    // `moderation:*` / `slashing:*`, `revocation:peer_admission:v1`).
    None
}

/// (CIRISPersist#568) — the ratifying documents **persist's own floor
/// reads**, and therefore the only authorities a CIRISVerify classification
/// may cite and still bind a persist gate.
///
/// A classification that is [`Gating::Normative`] is gate-able *somewhere* —
/// but "normative" is meaningless without asking *on whose authority*. Verify
/// may legitimately track a document persist does not: `Purpose` cites
/// `draft-ietf-rats-concise-ta-stores-02`, an IETF draft, which is the right
/// authority for a trust-anchor-store vocabulary and NOT a rule about what
/// this substrate admits. Importing that as a persist gate would be the #569
/// mistake wearing a citation.
///
/// So the list is short and every entry is a document persist can be held to.
/// Adding one is a claim that persist's behaviour is answerable to it.
pub const PERSIST_RATIFYING_AUTHORITIES: &[&str] = &["CC 3.4.5"];

/// (CIRISPersist#568 / CIRISVerify#238) — what standing a
/// CIRISVerify classification has **here**, in persist.
///
/// Three-valued because "may I gate on this?" has three honest answers, and
/// #569 shipped because only two were ever considered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassificationStanding {
    /// Verify declares it [`Gating::Normative`] **and** names an authority in
    /// [`PERSIST_RATIFYING_AUTHORITIES`]. Verify's reading and persist's
    /// reading are then two readings of ONE ratified document: they must
    /// agree, and a divergence is a misreading to settle on the document —
    /// not a disagreement to hold open.
    Binding {
        /// The ratifying document both sides are reading.
        authority: &'static str,
    },
    /// Verify declares it [`Gating::Normative`], but on an authority persist's
    /// floor does not read. Gate-able in verify's world; evidence in ours.
    /// Adopting it means first deciding that persist is answerable to that
    /// document — a deliberate edit to [`PERSIST_RATIFYING_AUTHORITIES`].
    ForeignAuthority {
        /// The document verify cites, which persist's floor does not.
        authority: &'static str,
    },
    /// v29.0.0 (CIRISVerify 13.0.0, CIRISOntology#3) — verify declares it
    /// [`Gating::Structural`]: it **cannot vary**, and no authority ratifies
    /// it because none *can* waive it. Deviating breaks parsing or dispatch.
    ///
    /// **Binding on persist without appearing in
    /// [`PERSIST_RATIFYING_AUTHORITIES`]**, and that is not an exception to
    /// that list — it is outside its subject. The list answers "is persist
    /// answerable to this document?", and a structural constraint cites no
    /// document. Persist honours it for the same reason verify does: the
    /// machine breaks otherwise, and no ruling can make it not break.
    ///
    /// **Why this is a fourth variant rather than a reuse.** Both available
    /// arms encode something false. [`Binding`](Self::Binding) would have to
    /// name an authority that does not exist, inviting someone to petition CC
    /// to amend a wire format. [`NoStanding`](Self::NoStanding) would discard
    /// a constraint that is *more* inescapable than a ruling, not less. The
    /// verify split exists precisely because a consumer that cannot tell
    /// *this would break* from *this is disallowed* petitions the wrong body —
    /// so flattening it here would reproduce, one layer down, the confusion
    /// the split was made to end.
    ///
    /// The doc above still says three answers were considered where two were
    /// honest ([#569](https://github.com/CIRISAI/CIRISPersist/issues/569)).
    /// This is the same lesson one turn further: the count was never the
    /// point, the *type answering instead of the reader* was.
    Structural {
        /// What breaks if it varies — verify's own words, carried rather than
        /// paraphrased, so a persist-side reader can act on it without
        /// re-deriving it from a variant name.
        breaks: &'static str,
    },
    /// [`Gating::may_gate`] is false — a measurement or an unratified
    /// proposal. Verify's own type says a consumer MUST NOT gate on it.
    /// Persist may compose policy *over* it; persist may never take it AS
    /// policy. This is the arm `ConsentDisposition` occupied at v11.0.0, when
    /// nothing in the type said so and CIRISPersist#569 read it as a ruling.
    NoStanding,
}

/// (CIRISPersist#568 / CIRISVerify#238) — the rule, applied to one
/// [`Gating`].
///
/// Fail-closed in both directions that matter: anything verify does not mark
/// gate-able is [`ClassificationStanding::NoStanding`], and any future
/// gate-able status verify invents that is not `Normative` also lands there
/// rather than being silently honoured.
#[must_use]
pub fn classification_standing(gating: Gating) -> ClassificationStanding {
    // The type answers the first half. Persist does not re-derive it from
    // variant names — re-deriving policy from a name is exactly what #569 did.
    if !gating.may_gate() {
        return ClassificationStanding::NoStanding;
    }
    match gating {
        Gating::Normative { authority } if PERSIST_RATIFYING_AUTHORITIES.contains(&authority) => {
            ClassificationStanding::Binding { authority }
        }
        Gating::Normative { authority } => ClassificationStanding::ForeignAuthority { authority },
        // v29.0.0 (CIRISVerify 13.0.0) — the second gate-able disposition. No
        // authority check, because there is no authority: `amendable_by()`
        // returns None and the constraint is mechanical. The comment below
        // used to say `may_gate()` is true only for `Normative`; verify
        // widened it exactly as that comment anticipated, and the arm arrived
        // here as a COMPILE ERROR rather than as a silent reclassification —
        // which is the whole reason this match is exhaustive over verify's
        // type instead of ending in a wildcard.
        Gating::Structural { breaks } => ClassificationStanding::Structural { breaks },
        // Unreachable while `may_gate()` is true only for `Normative` and
        // `Structural`. Kept so that if verify widens it again, the new status
        // arrives here as NoStanding rather than as an unhandled ruling.
        Gating::Measurement | Gating::Proposal { .. } => ClassificationStanding::NoStanding,
    }
}

/// (CIRISPersist#568 / CIRISVerify#238) — **ask the type, not the
/// prose**: what standing does the classification `C` have in persist?
///
/// The whole point of `ciris_verify_core::classification`. The call site names
/// the verify TYPE and gets back persist's verdict; nobody has to find the
/// sentence in another repo's document that said whether it was a ruling.
///
/// ```ignore
/// use ciris_verify_core::federation_provenance::dim::ConsentDisposition;
/// assert_eq!(
///     standing_of::<ConsentDisposition>(),
///     ClassificationStanding::Binding { authority: "CC 3.4.5" },
/// );
/// ```
#[must_use]
pub fn standing_of<C: Classification>() -> ClassificationStanding {
    classification_standing(C::gating())
}

/// v25.1.0 (CIRISPersist#569) — the consent-gated claim a row makes, on
/// EITHER wire shape, or `None` when the row is in no gated family.
///
/// Reputation rides `attestation_type = scores` with the family in
/// `dimension`; the type-keyed shape (`attestation_type = capacity:composite`)
/// also exists. #543 finding 2 was
/// exactly a gate keyed to one of the two shapes and therefore reaching zero
/// real callers (the AV-74 lesson) — so every consent rule reads the family
/// through this one helper, which asks BOTH. The DIMENSION wins when both
/// carry a gated family: it is the axis the emit path actually uses.
#[must_use]
pub fn consent_gated_claim(row: &super::Attestation) -> Option<ConsentGatedClaim<'_>> {
    if let Some(d) = envelope_dimension(&row.attestation_envelope) {
        if let Some(family) = consent_gated_family(d) {
            return Some(ConsentGatedClaim {
                family,
                dimension: d,
            });
        }
    }
    consent_gated_family(&row.attestation_type).map(|family| ConsentGatedClaim {
        family,
        dimension: row.attestation_type.as_str(),
    })
}

/// v25.1.0 (CIRISPersist#569) — what [`consent_gated_claim`] resolved: the
/// exact dimension string the row claimed, and WHICH rule puts it behind
/// consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentGatedClaim<'a> {
    /// Which consent rule covers the claim.
    pub family: ConsentGatedFamily,
    /// The dimension string the row actually carried, on whichever wire
    /// shape carried it.
    pub dimension: &'a str,
}

/// v25.1.0 (CIRISPersist#569) — the typed refusal
/// [`check_capacity_consent_admission`] returns: WHICH rule, WHICH dimension,
/// WHO was claimed about by WHOM, and the stance the fold actually resolved.
///
/// A refusal is a verdict, and a verdict without its evidence sends the reader
/// to the wrong layer (#575). String-matching a message to learn "was this the
/// consent gate?" is what this type makes unnecessary rather than merely
/// discouraged: it survives the conversion into
/// [`Error::ConsentGateRefused`](crate::federation::Error::ConsentGateRefused)
/// intact, so a consumer branches on `family` and reads `dimension` /
/// `stance` as data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentGateRefused {
    /// WHICH rule refused. A closed enum, not a message string.
    pub family: ConsentGatedFamily,
    /// The dimension the refused row claimed, verbatim.
    pub dimension: String,
    /// S — the subject the claim is ABOUT, and the only party who can
    /// authorize it.
    pub subject_key_id: String,
    /// P — the attester who tried to publish the claim.
    pub attester_key_id: String,
    /// What [`resolve_scoped_consent`](super::FederationDirectory::resolve_scoped_consent)
    /// resolved for (S → P, [`ANALYZE_CONSENT_SCOPE`]). Never `Granted` —
    /// that is the admit path.
    pub stance: super::hard_case::ConsentState,
}

impl std::fmt::Display for ConsentGateRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no live consent covers this {dimension} emission ({family} rule): subject \
             {subject} has not granted attester {attester} the \"{scope}\" scope (resolved \
             stance: {stance:?}) — a party MUST NOT emit a score that judges a subject unless a \
             live consent:scope:{scope} from that subject covers the attester \
             (CIRISConstitution#46, ratified at CC 3.4.5). The subject authorizes it with a \
             `{granted}:v1` row whose attested_key_id is the attester and whose envelope names \
             scope \"{scope}\".",
            dimension = self.dimension,
            family = self.family,
            subject = self.subject_key_id,
            attester = self.attester_key_id,
            scope = ANALYZE_CONSENT_SCOPE,
            stance = self.stance,
            granted = super::consent::consent_dimension::STATE_GRANTED_PREFIX,
        )
    }
}

impl From<ConsentGateRefused> for Error {
    fn from(refused: ConsentGateRefused) -> Self {
        Error::ConsentGateRefused(refused)
    }
}

/// v22.0.0 (CIRISConstitution#46), ratified and bounded at CC 3.4.5 —
/// **CONSENT BEFORE SCORING**: a federation-tier claim in a
/// [`ConsentGatedFamily`] about subject S from attester P is REFUSED unless a
/// live [`ANALYZE_CONSENT_SCOPE`] consent from S covering P exists in this
/// node's verified corpus.
///
/// # The gated set is `capacity:*`
///
/// CIRISPersist#569 widened this gate to every family verify classifies
/// `ConsensualReputation` and CC 3.4.5 disposed of all four of those families
/// the other way, so the widening was held before merge and the gate is
/// `capacity:*` — the family that judges an AGENT. The per-family reasoning,
/// and why the narrowing is the STRONGER outcome rather than the weaker one,
/// is on [`consent_gated_family`], which is the one predicate every arm of
/// this rule classifies through.
///
/// # The default this inverts
///
/// RC2's position is post-hoc revocation, optional by default. CC 3.4.5 is the
/// *entire* emitter rule for `capacity:*` — `attesting_key_id MUST NOT equal
/// attested_key_id`, no witness requirement, no role gate, no consent
/// requirement — so **any registered key may score any third party**, and CC
/// 3.3.7 says so outright ("admission is by key registration; consent is the
/// governance record … `consent:replication` does not add a substrate
/// admission check — by design"). Persist's own bootstrap is deliberately
/// cheap (a self-signed hybrid PoP and nothing else), so "any registered key"
/// means "anyone". CC#46 inverts the default for this one family.
///
/// This is the contextual-integrity transmission-principle question in its
/// purest form: *were you permitted to compute and publish this about me?*
/// It keeps persist mechanical rather than adjudicating — the substrate reads
/// a consent edge, it never forms a verdict about who has earned the right to
/// score (MISSION §1.10, "the substrate stores; it never adjudicates").
///
/// # The edge it reads (NOT a new shape)
///
/// The claim is the edge P → S; the consent is the REVERSE edge S → P, in the
/// consent representation the substrate already maintains and folds:
/// `attesting_key_id` = S, `attested_key_id` = P, envelope `dimension` =
/// `consent:state:granted|revoked|expired:*`, envelope `scope` naming
/// [`ANALYZE_CONSENT_SCOPE`]. It is resolved through
/// [`resolve_scoped_consent`](super::FederationDirectory::resolve_scoped_consent)
/// — the ONE canonical scoped fold (a default trait method, so all three
/// backends answer from identical code): latest-wins by `asserted_at`,
/// expiry-aware, a grant must name its scope exactly, a scope-less
/// revocation is blanket. A bespoke parallel lookup here would be the
/// two-lists-that-disagree class (#541); there is one list.
///
/// # Scope — what it deliberately does NOT catch
///
/// - **Families outside [`consent_gated_family`].** CC#46's own scope
///   boundary. An abuser never consents to `detection:*` / `moderation:*` /
///   `slashing:*`, and a uniform application of this rule would delete the
///   abuse-response plane. `revocation:peer_admission:v1` (AV-77) is likewise
///   untouched.
/// - **CIRISVerify's entire namespace**, per CC 3.4.5's per-family
///   disposition: the self-reports and log-infrastructure families have no
///   third-party subject at all; the artifact-integrity families score builds,
///   manifests, licenses and certificates rather than a subject's conduct, and
///   *"a forger never consents to verification"*; and
///   `rollback_detected:{revision_field}` is an adversarial detector on the
///   abuse-response side of the line — gating it would hand the adversary the
///   off switch for its own detection. Witnessed by B7
///   ([`super::bootstrap_admission::test_support::exercise_verify_families_are_not_consent_gated`])
///   on all three backends, not merely asserted here.
/// - **Local-tier rows.** A local-tier row is not an EMISSION — it is this
///   node's own working state, un-replicated, so consent-to-publish has
///   nothing to bind to yet. This arm is LOAD-BEARING, not redundant, and it
///   is safe to keep **because a `capacity:*` row can no longer be local at
///   all**: [`check_capacity_never_local`] is now asked at BOTH doors onto the
///   local tier — [`check_local_tier_eligibility`] (as before) and, since
///   v26.0.0, `put_attestation`, which accepts a `tier = "local"` row on every
///   backend and used to skip the rule entirely.
///
///   That was **CIRISPersist#589 / AV-83**, and it was rated a MUST violation
///   rather than a gap: a local-tier `capacity:*` row written via
///   `put_attestation` and then `attestation_promote`d became a federation-tier
///   `capacity:*` row that never faced this gate — CC 3.4.5's reciprocity
///   clause forbids exactly that artifact. It is closed at two chokepoints, on
///   purpose, because they close different things:
///
///   - `put_attestation` asking [`check_capacity_never_local`] closes the
///     SYMPTOM at the door where the row is born, with the accurate refusal
///     ("capacity is never local", not "no consent");
///   - [`check_promotion_admission`] re-running the tier-4 stack closes the
///     CLASS — promote equally bypassed AV-45, AV-77 and the moderation gates
///     for every other family, and the capacity arm alone would have left all
///     of that open.
///
///   Note the asymmetry this gate's own sibling still carries, and it is
///   deliberate: [`check_capacity_not_self_attested`] is NOT tier-gated, so
///   self-emission was caught on a local row when missing consent was not.
///   Two halves of one anti-Goodhart wall, enforced at different tiers,
///   because they answer different questions.
/// - **Self-attestation.** `attesting_key_id == attested_key_id` is AV-62/74's
///   rule and is refused UPSTREAM, by
///   [`check_capacity_not_self_attested`] inside
///   [`check_reserved_prefix_admission`], which every backend calls
///   immediately before this gate. Skipping it here is not a hole — it keeps
///   the self-emission refusal reporting as self-emission instead of being
///   shadowed by "no consent" (a subject who never granted itself `analyze`
///   would otherwise fail this gate first and get the wrong message).
///
/// # Genesis goes dark, deliberately
///
/// With no consent edges anywhere — a fresh mesh — third-party `capacity:*`
/// scoring is refused everywhere. That IS CC#46's semantics: consent BEFORE
/// scoring means the plane opens when subjects open it, not before. There is
/// no bootstrap bypass on purpose; a bypass keyed to "the mesh is young" would
/// be a permanent hole with a temporary name. CC 3.4.5's reciprocity clause
/// names the same posture from the subject's side: a subject that declines
/// analysis *"cannot be scored; its `capacity:composite` is undefined and MUST
/// NOT be emitted; and every gate that requires a capacity verdict therefore
/// fails closed for that subject."*
///
/// # It bites this node's OWN emit surface
///
/// [`Engine::emit_attestation`](crate::Engine::emit_attestation) and
/// [`emit_attestation_self`](crate::Engine::emit_attestation_self) store
/// through `put_attestation`, so they face this gate like any peer — no local
/// bypass. `engine::tests::emit_attestation_consent_gate_bites_own_surface_569`
/// witnesses it: the node's own `capacity:*` emit about a third party is
/// refused until that subject grants and admits after, while its
/// `rollback_detected:*` emit about the same silent subject admits throughout.
pub async fn check_capacity_consent_admission(
    directory: &dyn super::FederationDirectory,
    row: &super::Attestation,
) -> Result<(), Error> {
    let Some(claim) = consent_gated_claim(row) else {
        return Ok(());
    };
    if row.tier != crate::federation::types::attestation_tier::FEDERATION {
        return Ok(());
    }
    if row.attesting_key_id == row.attested_key_id {
        return Ok(());
    }

    let stance = directory
        .resolve_scoped_consent(
            &row.attesting_key_id, // the consent edge points AT the attester P
            &row.attested_key_id,  // and is authored BY the subject S
            ANALYZE_CONSENT_SCOPE,
            None,
            chrono::Utc::now(),
        )
        .await?;
    if stance == super::hard_case::ConsentState::Granted {
        return Ok(());
    }
    Err(ConsentGateRefused {
        family: claim.family,
        dimension: claim.dimension.to_owned(),
        subject_key_id: row.attested_key_id.clone(),
        attester_key_id: row.attesting_key_id.clone(),
        stance,
    }
    .into())
}

/// v22.0.0 (CIRISConstitution#46) — the CC 3.3.1 consent-grant KIND that
/// authorizes deriving scores about a subject: *"`analyze` (derive features
/// / scores / classifications)"*. Named here rather than re-spelled at each
/// call site, and pinned by `analyze_consent_scope_is_the_grammar_analyze_kind`
/// to the wire token of
/// [`consent_grammar::TransmissionPrinciple::Analyze`](crate::federation::consent_grammar::TransmissionPrinciple::Analyze)
/// — persist has ONE `analyze` vocabulary, not two that can drift apart.
///
/// v25.1.0 (CIRISPersist#569) — renamed from `ANALYZE_CONSENT_SCOPE`: the
/// scope was never capacity-specific (it is CC 3.3.1's `analyze` kind), and
/// the gate that reads it no longer is either. Clean break, no alias.
pub const ANALYZE_CONSENT_SCOPE: &str = "analyze";

/// v4.13.0 (CIRISPersist#192, CEG 0.18 §5.6.8.8) — validate an
/// occurrence's optional content-encryption pubkeys on admit: each half
/// MUST base64-decode to its exact raw length (x25519 = 32 bytes,
/// ML-KEM-768 = 1184 bytes, FIPS 203). `Ok(())` when absent. A
/// malformed-length key would silently break `wrap_algorithm: v2`, so it
/// is refused at the boundary.
pub fn check_encryption_pubkeys(
    keys: Option<&crate::federation::types::EncryptionPubkeys>,
) -> Result<(), Error> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let Some(k) = keys else { return Ok(()) };
    let check = |label: &str, b64: &str, want: usize| -> Result<(), Error> {
        let raw = B64.decode(b64).map_err(|e| {
            Error::InvalidArgument(format!("encryption_pubkeys.{label} not valid base64: {e}"))
        })?;
        if raw.len() != want {
            return Err(Error::InvalidArgument(format!(
                "encryption_pubkeys.{label} must be {want} raw bytes, got {}",
                raw.len()
            )));
        }
        Ok(())
    };
    check("x25519_base64", &k.x25519_base64, 32)?;
    check("ml_kem_768_base64", &k.ml_kem_768_base64, 1184)?;
    Ok(())
}

/// v14.0.0 (CIRISPersist#418, occurrence-KEX arc 2/4) — the SIGNED-occurrence
/// admission gate: cryptographically prove the content-tier KEX pubkeys (+
/// transport binding) belong to the identity BEFORE any write, closing the
/// silent content-MITM where a consented replication peer could fabricate a
/// victim's occurrence. Fail-secure; called by every `put_identity_occurrence`
/// (HTTP + wire — one gate).
///
/// **Authority is `signed_envelope`, never the sender's typed projection.** The
/// hybrid signature covers `JCS(signed_envelope)` only; persist therefore parses
/// the authoritative `transport_destination` / `encryption_pubkeys` / ids FROM
/// that envelope and REJECTS if the typed `identity_occurrence` diverges — else
/// an attacker sends an envelope carrying the victim's keys but a typed
/// projection carrying its own, and the MITM reopens.
///
/// Verifies, each fail-closed:
/// 1. `signed_envelope` carries a `transport_destination` (REQUIRED — every
///    signed occurrence binds transport, #418) + optional `encryption_pubkeys`;
/// 2. the typed projection's transport/enc keys + ids EQUAL the envelope's;
/// 3. [`verify_transport_binding`] is authentic against the PINNED federation
///    signing key of `attesting_key_id` (hybrid sig, §5.6.8.8.2 C4, dest_hash
///    recompute) — `UnknownSigner` / bad sig / C4 / `Malformed` ⇒ reject;
/// 4. `signer_acts_for`: `attesting_key_id` is the occurrence's own
///    `identity_key_id` OR an already-active occurrence key of the same identity.
///
/// NOT feature-gated: backend-agnostic (verify-core only), and the MemoryBackend
/// (compiled without postgres/sqlite) calls it — a `cfg(any(postgres,sqlite))`
/// gate here breaks reduced-feature builds (darwin no-postgres, the default-
/// feature manifest bin) with E0425.
pub async fn verify_signed_identity_occurrence(
    directory: &dyn super::FederationDirectory,
    signed: &crate::federation::types::SignedIdentityOccurrence,
) -> Result<(), Error> {
    use ciris_verify_core::threshold::ThresholdMember;
    use ciris_verify_core::transport_binding::{
        verify_transport_binding, EncryptionPubkeys as VEnc, TransportBinding, TransportDestination,
    };

    let row = &signed.identity_occurrence;
    let env = &signed.signed_envelope;

    // (1) Parse the AUTHORITATIVE transport_destination from the signed envelope.
    let str_field = |obj: &serde_json::Value, k: &str| -> Result<String, Error> {
        obj.get(k)
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "signed identity_occurrence envelope missing string field `{k}`"
                ))
            })
    };
    let td_env = env.get("transport_destination").ok_or_else(|| {
        Error::InvalidArgument(
            "signed identity_occurrence must carry a transport_destination (occurrence-KEX #418)"
                .into(),
        )
    })?;
    let transport_destination = TransportDestination {
        reticulum_x25519_pubkey_base64: str_field(td_env, "reticulum_x25519_pubkey")?,
        reticulum_ed25519_pubkey_base64: str_field(td_env, "reticulum_ed25519_pubkey")?,
        destination_hash_base64: str_field(td_env, "destination_hash")?,
        app_name: str_field(td_env, "app_name")?,
        aspects: td_env
            .get("aspects")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    };
    // Optional content-KEM half, from the envelope.
    let encryption_pubkeys = match env.get("encryption_pubkeys") {
        Some(e) if !e.is_null() => Some(VEnc {
            x25519_base64: str_field(e, "x25519_base64")?,
            ml_kem_768_base64: str_field(e, "ml_kem_768_base64")?,
        }),
        _ => None,
    };

    // (2) The typed projection persist will STORE must equal the envelope — the
    // signature only covers the envelope, so a divergent projection is a MITM.
    let diverges = |what: &str| {
        Error::InvalidArgument(format!(
            "signed identity_occurrence: typed {what} diverges from the signed envelope (rejected)"
        ))
    };
    if str_field(env, "identity_key_id")? != row.identity_key_id {
        return Err(diverges("identity_key_id"));
    }
    if str_field(env, "occurrence_key_id")? != row.occurrence_key_id {
        return Err(diverges("occurrence_key_id"));
    }
    match row.transport_binding.as_ref() {
        Some(tb)
            if tb.reticulum_x25519_pubkey_base64
                == transport_destination.reticulum_x25519_pubkey_base64
                && tb.reticulum_ed25519_pubkey_base64
                    == transport_destination.reticulum_ed25519_pubkey_base64
                && tb.destination_hash_base64 == transport_destination.destination_hash_base64 => {}
        _ => return Err(diverges("transport_destination")),
    }
    // v21.17.1 (CIRISPersist#541) — compare BOTH content-KEM halves. The
    // envelope carries `x25519_base64` AND `ml_kem_768_base64`; comparing only
    // x25519 was a FAIL-OPEN gap — a diverged post-quantum KEM key on the typed
    // row (e.g. rewritten by an unsigned `put_identity_occurrence_local`) was
    // silently ACCEPTED, unlike every other divergence in this class which
    // fails closed. Both halves must equal the signed envelope, as a pair.
    let env_enc = encryption_pubkeys
        .as_ref()
        .map(|e| (e.x25519_base64.clone(), e.ml_kem_768_base64.clone()));
    let row_enc = row
        .encryption_pubkeys
        .as_ref()
        .map(|e| (e.x25519_base64.clone(), e.ml_kem_768_base64.clone()));
    if env_enc != row_enc {
        return Err(diverges("encryption_pubkeys"));
    }

    // (3) Verify the hybrid signature against the signer's PINNED federation key.
    let Some(signer_key) = directory
        .lookup_public_key(&signed.attesting_key_id)
        .await?
    else {
        return Err(Error::SignatureInvalid(format!(
            "signed identity_occurrence: attesting_key_id {} is not a registered federation key",
            signed.attesting_key_id
        )));
    };
    let key_directory = vec![ThresholdMember {
        member_id: signer_key.key_id.clone(),
        ed25519_public_key_base64: signer_key.pubkey_ed25519_base64.clone(),
        mldsa65_public_key_base64: signer_key.pubkey_ml_dsa_65_base64.clone(),
        role: None,
    }];
    let binding = TransportBinding {
        attesting_key_id: signed.attesting_key_id.clone(),
        signed_envelope: env.clone(),
        transport_destination,
        encryption_pubkeys,
        signature: signed.signature.clone(),
    };
    let verdict = verify_transport_binding(&binding, &key_directory).map_err(|e| {
        Error::InvalidArgument(format!("signed identity_occurrence canonicalize: {e}"))
    })?;
    if !verdict.authentic {
        return Err(Error::SignatureInvalid(format!(
            "signed identity_occurrence for {} not authentic: {:?}",
            row.occurrence_key_id, verdict.reason
        )));
    }

    // (4) signer_acts_for — the signer is the identity itself, or an already-
    // active occurrence of the same identity (a peer can't sign a victim's
    // occurrence with its own unrelated key).
    check_signer_acts_for(
        directory,
        &signed.attesting_key_id,
        &row.identity_key_id,
        "identity_occurrence",
    )
    .await
}

/// v16.0.0 (#421) — **THE `signer_acts_for` check**, shared by the signed
/// occurrence AND signed revocation gates (one authorization rule, one place):
/// `attesting_key_id` may act for `identity_key_id` iff it IS that identity's
/// own key, or it is bound as an occurrence of that identity (the §11.7.4
/// single-vouch-for-self). Anything else — including another *registered* but
/// unrelated key — is refused: a peer cannot sign (or revoke) a victim's
/// occurrence with its own key.
async fn check_signer_acts_for(
    directory: &dyn super::FederationDirectory,
    attesting_key_id: &str,
    identity_key_id: &str,
    what: &str,
) -> Result<(), Error> {
    if attesting_key_id == identity_key_id {
        return Ok(());
    }
    let acts_for = matches!(
        directory
            .lookup_identity_for_occurrence(attesting_key_id)
            .await?,
        Some(sig_occ) if sig_occ.identity_key_id == identity_key_id
    );
    if !acts_for {
        return Err(Error::SignatureInvalid(format!(
            "signed {what}: signer {attesting_key_id} is neither identity {identity_key_id} \
             nor an active occurrence of it"
        )));
    }
    Ok(())
}

/// v16.0.0 (CIRISPersist#421) — the SIGNED-revocation admission gate: the
/// revocation-plane mirror of [`verify_signed_identity_occurrence`], closing the
/// **permanent-DoS forgery** the #418 cut deferred. An unsigned revocation on
/// the replication plane would let any consented peer fabricate
/// `{identity: victim, occurrence: victim}` and brick the victim's sealability
/// (`resolve_encryption_keys → None`) — worse than the occurrence MITM because
/// it was terminal. Fail-secure; called by every
/// `put_identity_occurrence_revocation` (HTTP + wire — one gate; edge's
/// replication apply delegates to `put`, exactly like the occurrence).
///
/// **Authority is `signed_envelope`, never the sender's typed projection** —
/// the #418 discipline verbatim. Verifies, each fail-closed:
/// 1. the envelope carries `identity_key_id` / `occurrence_key_id` /
///    `revoked_at` / `effective_at`, and the typed projection persist will
///    store EQUALS them (a divergent projection is the MITM reopening);
/// 2. the detached hybrid signature over `JCS(signed_envelope)` verifies at
///    threshold **1-of-1** against the PINNED federation pubkeys of
///    `attesting_key_id` ([`verify_threshold_signatures`] — the same bound-sig
///    rule `verify_transport_binding` composes; that fn itself is NOT reusable
///    here because it hard-requires a `transport_destination`, which a
///    revocation envelope rightly lacks);
/// 3. `signer_acts_for`: the signer is the identity's own key OR an
///    already-active occurrence of the same identity — the §11.7.4
///    single-vouch-for-self, ENFORCED (the `witness_set` only shaped it).
///
/// NOT feature-gated: backend-agnostic, and the MemoryBackend calls it (the
/// #418 cfg lesson).
///
/// [`verify_threshold_signatures`]: ciris_verify_core::threshold::verify_threshold_signatures
pub async fn verify_signed_identity_occurrence_revocation(
    directory: &dyn super::FederationDirectory,
    signed: &crate::federation::types::SignedIdentityOccurrenceRevocation,
) -> Result<(), Error> {
    use ciris_verify_core::threshold::{
        verify_threshold_signatures, ThresholdMember, ThresholdSignature,
    };

    let row = &signed.identity_occurrence_revocation;
    let env = &signed.signed_envelope;

    // (1) Authoritative fields FROM the signed envelope; the typed projection
    // must equal them (the signature covers only the envelope).
    let str_field = |k: &str| -> Result<String, Error> {
        env.get(k)
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "signed identity_occurrence_revocation envelope missing string field `{k}`"
                ))
            })
    };
    let ts_field = |k: &str| -> Result<chrono::DateTime<chrono::Utc>, Error> {
        let s = str_field(k)?;
        chrono::DateTime::parse_from_rfc3339(&s)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|e| {
                Error::InvalidArgument(format!(
                    "signed identity_occurrence_revocation envelope `{k}` not RFC-3339: {e}"
                ))
            })
    };
    let diverges = |what: &str| {
        Error::InvalidArgument(format!(
            "signed identity_occurrence_revocation: typed {what} diverges from the signed \
             envelope (rejected)"
        ))
    };
    if str_field("identity_key_id")? != row.identity_key_id {
        return Err(diverges("identity_key_id"));
    }
    if str_field("occurrence_key_id")? != row.occurrence_key_id {
        return Err(diverges("occurrence_key_id"));
    }
    if ts_field("revoked_at")? != row.revoked_at {
        return Err(diverges("revoked_at"));
    }
    // `effective_at` is the terminality clock (the re-establish comparator
    // reads it), so a divergence here is the whole attack.
    if ts_field("effective_at")? != row.effective_at {
        return Err(diverges("effective_at"));
    }

    // (2) Hybrid signature over JCS(signed_envelope) against the PINNED
    // federation pubkeys of the claimed signer, threshold 1-of-1 (RequireHybrid
    // — a classical-only revocation does not count, RC7 §10.1.5.1.1).
    let Some(signer_key) = directory
        .lookup_public_key(&signed.attesting_key_id)
        .await?
    else {
        return Err(Error::SignatureInvalid(format!(
            "signed identity_occurrence_revocation: attesting_key_id {} is not a registered \
             federation key",
            signed.attesting_key_id
        )));
    };
    let bytes = crate::verify::canonical::ceg_produce_canonicalize(env).map_err(|e| {
        Error::InvalidArgument(format!(
            "signed identity_occurrence_revocation canonicalize: {e}"
        ))
    })?;
    let members = [ThresholdMember {
        member_id: signer_key.key_id.clone(),
        ed25519_public_key_base64: signer_key.pubkey_ed25519_base64.clone(),
        mldsa65_public_key_base64: signer_key.pubkey_ml_dsa_65_base64.clone(),
        role: None,
    }];
    let sigs = [ThresholdSignature {
        member_id: signed.attesting_key_id.clone(),
        ed25519_signature_base64: signed.signature.ed25519_signature_base64.clone(),
        mldsa65_signature_base64: signed.signature.mldsa65_signature_base64.clone(),
    }];
    if verify_threshold_signatures(&bytes, &members, &sigs, 1).is_err() {
        return Err(Error::SignatureInvalid(format!(
            "signed identity_occurrence_revocation for {} not authentic (hybrid 1-of-1 over \
             JCS(envelope) failed against the pinned key of {})",
            row.occurrence_key_id, signed.attesting_key_id
        )));
    }

    // (3) signer_acts_for — THE shared check ([`check_signer_acts_for`]): a
    // peer cannot revoke a victim's occurrence with its own unrelated key.
    check_signer_acts_for(
        directory,
        &signed.attesting_key_id,
        &row.identity_key_id,
        "identity_occurrence_revocation",
    )
    .await
}

/// v17.0.0 (CIRISPersist#443) — the SIGNED transport-destination admission
/// gate: the route-plane mirror of
/// [`verify_signed_identity_occurrence_revocation`], closing the
/// **route-hijack confused deputy** (CIRISEdge#336): before this the
/// replication plane applied a bare unsigned `TransportDestination` through
/// the plain local upsert, so any cohort node could overwrite the durable
/// route — with an attacker-chosen `binding_provenance: Rooted` — for any
/// key_id. Fail-secure; called by every `put_signed_transport_destination`
/// (all three backends — one gate) BEFORE any write.
///
/// **Authority is `signed_envelope`, never the sender's typed projection** —
/// the #418 discipline verbatim. `binding_provenance` in particular is read
/// ONLY from the verified envelope. Verifies, each fail-closed:
/// 1. the envelope carries `occurrence_key_id` / `transport_kind` /
///    `destination` / `asserted_at` / `epoch` (+ optional `retired_at`,
///    transport pubkeys, `binding_provenance`), and the typed projection
///    persist will store EQUALS them (a divergent projection is the hijack
///    reopening). `last_seen_at` is advisory liveness, not signed material.
/// 2. the detached hybrid signature over `JCS(signed_envelope)` verifies at
///    threshold **1-of-1** against the PINNED federation pubkeys of
///    `attesting_key_id` ([`verify_threshold_signatures`] — RequireHybrid; a
///    classical-only route assertion does not count);
/// 3. `signer_acts_for`: the signer IS the route's `occurrence_key_id` or a
///    key bound as an occurrence of it ([`check_signer_acts_for`]) — a peer
///    cannot assert (or retire) a victim's route with its own unrelated key.
///
/// NOT feature-gated: backend-agnostic, and the MemoryBackend calls it (the
/// #418 cfg lesson).
///
/// [`verify_threshold_signatures`]: ciris_verify_core::threshold::verify_threshold_signatures
pub async fn verify_signed_transport_destination(
    directory: &dyn super::FederationDirectory,
    signed: &crate::federation::self_at_login::SignedTransportDestination,
) -> Result<(), Error> {
    use ciris_verify_core::threshold::{
        verify_threshold_signatures, ThresholdMember, ThresholdSignature,
    };

    let row = &signed.transport_destination;
    let env = &signed.signed_envelope;

    // (1) Authoritative fields FROM the signed envelope; the typed projection
    // must equal them (the signature covers only the envelope).
    let str_field = |k: &str| -> Result<String, Error> {
        env.get(k)
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "signed transport_destination envelope missing string field `{k}`"
                ))
            })
    };
    let parse_ts = |k: &str, s: &str| -> Result<chrono::DateTime<chrono::Utc>, Error> {
        chrono::DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|e| {
                Error::InvalidArgument(format!(
                    "signed transport_destination envelope `{k}` not RFC-3339: {e}"
                ))
            })
    };
    // Optional string field: absent/null ⇒ None; a non-string is malformed.
    let opt_str_field = |k: &str| -> Result<Option<String>, Error> {
        match env.get(k) {
            None | Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(s)) => Ok(Some(s.clone())),
            Some(_) => Err(Error::InvalidArgument(format!(
                "signed transport_destination envelope `{k}` must be a string"
            ))),
        }
    };
    let diverges = |what: &str| {
        Error::InvalidArgument(format!(
            "signed transport_destination: typed {what} diverges from the signed envelope \
             (rejected)"
        ))
    };
    if str_field("occurrence_key_id")? != row.occurrence_key_id {
        return Err(diverges("occurrence_key_id"));
    }
    if str_field("transport_kind")? != row.transport_kind {
        return Err(diverges("transport_kind"));
    }
    if str_field("destination")? != row.destination {
        return Err(diverges("destination"));
    }
    if parse_ts("asserted_at", &str_field("asserted_at")?)? != row.asserted_at {
        return Err(diverges("asserted_at"));
    }
    // `epoch` is the anti-rollback clock — REQUIRED in the envelope (a
    // serde-default 0 in the typed projection must not be silently trusted).
    let env_epoch = env.get("epoch").and_then(|v| v.as_u64()).ok_or_else(|| {
        Error::InvalidArgument(
            "signed transport_destination envelope missing unsigned-integer field `epoch`".into(),
        )
    })?;
    if env_epoch != row.epoch {
        return Err(diverges("epoch"));
    }
    // `retired_at` is the tombstone — a divergence here is a resurrection
    // (or fabricated retirement) attack.
    let env_retired = match opt_str_field("retired_at")? {
        Some(s) => Some(parse_ts("retired_at", &s)?),
        None => None,
    };
    if env_retired != row.retired_at {
        return Err(diverges("retired_at"));
    }
    if opt_str_field("transport_ed25519_pubkey_base64")? != row.transport_ed25519_pubkey_base64 {
        return Err(diverges("transport_ed25519_pubkey_base64"));
    }
    if opt_str_field("transport_x25519_pubkey_base64")? != row.transport_x25519_pubkey_base64 {
        return Err(diverges("transport_x25519_pubkey_base64"));
    }
    // `binding_provenance` comes ONLY from the verified envelope (the AV-42 /
    // #336 hijack asserted `Rooted` on an unauthenticated wire field). An
    // absent/unknown token reads `Rooted` per the V100 back-compat rule, so a
    // typed `Advisory` with an envelope that omits the field DIVERGES —
    // fail-closed either way.
    let env_provenance = crate::federation::self_at_login::BindingProvenance::from_token(
        opt_str_field("binding_provenance")?.as_deref(),
    );
    if env_provenance != row.binding_provenance {
        return Err(diverges("binding_provenance"));
    }

    // (2) Hybrid signature over JCS(signed_envelope) against the PINNED
    // federation pubkeys of the claimed signer, threshold 1-of-1.
    let Some(signer_key) = directory
        .lookup_public_key(&signed.attesting_key_id)
        .await?
    else {
        return Err(Error::SignatureInvalid(format!(
            "signed transport_destination: attesting_key_id {} is not a registered federation key",
            signed.attesting_key_id
        )));
    };
    let bytes = crate::verify::canonical::ceg_produce_canonicalize(env).map_err(|e| {
        Error::InvalidArgument(format!("signed transport_destination canonicalize: {e}"))
    })?;
    let members = [ThresholdMember {
        member_id: signer_key.key_id.clone(),
        ed25519_public_key_base64: signer_key.pubkey_ed25519_base64.clone(),
        mldsa65_public_key_base64: signer_key.pubkey_ml_dsa_65_base64.clone(),
        role: None,
    }];
    let sigs = [ThresholdSignature {
        member_id: signed.attesting_key_id.clone(),
        ed25519_signature_base64: signed.signature.ed25519_signature_base64.clone(),
        mldsa65_signature_base64: signed.signature.mldsa65_signature_base64.clone(),
    }];
    if verify_threshold_signatures(&bytes, &members, &sigs, 1).is_err() {
        return Err(Error::SignatureInvalid(format!(
            "signed transport_destination for ({}, {}) not authentic (hybrid 1-of-1 over \
             JCS(envelope) failed against the pinned key of {})",
            row.occurrence_key_id, row.transport_kind, signed.attesting_key_id
        )));
    }

    // (3) signer_acts_for — THE shared check ([`check_signer_acts_for`]),
    // with the route's `occurrence_key_id` as the subject: the signer is the
    // route's own key, or a key bound as an occurrence of it.
    check_signer_acts_for(
        directory,
        &signed.attesting_key_id,
        &row.occurrence_key_id,
        "transport_destination",
    )
    .await
}

/// v21.6.0 (CIRISPersist#519 item 2a-iii, CEG `namespace_supersets.json` §
/// `freshness_floor.admission_guard`) — clock-skew tolerance for the signed
/// `fresh_as_of` freshness floor
/// ([`crate::federation::types::SignedTouchClaim`]). Mirrors
/// [`crate::verify::canonical_validation::MAX_SIGNED_AT_FUTURE_SKEW`] (same
/// 5-minute CEG §0.7 window) — persist exposes the constant so a producer
/// or a sovereign deployment's own validation uses the same tolerance the
/// substrate enforces.
pub const DEFAULT_MAX_TOUCH_SKEW: chrono::Duration = chrono::Duration::minutes(5);

/// v21.6.0 (CIRISPersist#519 item 2a-iii) — the freshness-floor SKEW guard:
/// **reject `fresh_as_of > now + max_skew`**.
///
/// Monotonic-max ([`crate::federation::freshness`]) is the anti-ROLLBACK
/// property — it stops a touch from ever moving the floor backward. This
/// is the dual: nothing about a pure max-fold stops a lying clock from
/// asserting a `fresh_as_of` far in the future and jumping the floor
/// forward past the point any real touch could have occurred. Mirrors
/// [`crate::verify::canonical_validation::validate_signed_at_not_future`]'s
/// shape exactly.
///
/// Called by every backend's `put_touch_claim` BEFORE the merge
/// (verify-before-mutation), ALONGSIDE — never instead of —
/// [`verify_signed_touch_claim`] (the full hybrid-signature gate). A
/// touch-claim is admitted only when BOTH pass.
pub fn verify_touch_claim_admission(
    claim: &crate::federation::types::SignedTouchClaim,
    now: chrono::DateTime<chrono::Utc>,
    max_skew: chrono::Duration,
) -> Result<(), Error> {
    let skew = claim.fresh_as_of - now;
    if skew > max_skew {
        return Err(Error::InvalidArgument(format!(
            "signed touch_claim: fresh_as_of {} is {}s ahead of now ({}), beyond the {}s skew \
             tolerance — a lying clock cannot jump the freshness floor into the future",
            claim.fresh_as_of.to_rfc3339(),
            skew.num_seconds(),
            now.to_rfc3339(),
            max_skew.num_seconds(),
        )));
    }
    Ok(())
}

/// v30.13.0 (CIRISPersist#598) — **the substrate's instant RESOLUTION**: one
/// microsecond, expressed as the nanosecond quantum every bound consent
/// instant must be a whole multiple of.
///
/// The three backends do not agree about sub-microsecond time and cannot be
/// made to. sqlite stores RFC-3339 TEXT and memory holds a `chrono`
/// `DateTime` — both keep the full nanosecond — while postgres `TIMESTAMPTZ`
/// is microsecond precision and TRUNCATES. So a grant and a revoke 500ns
/// apart are a strict order on two backends and a TIE on the third, and the
/// tie was resolved by whatever row order the backend happened to present.
/// That is a fold whose verdict depends on which database you asked, on the
/// plane where the wrong answer is "processing may proceed".
///
/// The decision is to **REFUSE, not truncate**. Truncating at the write
/// chokepoint is the other honest option and was rejected because the
/// instant is now BOUND to a signature: silently rewriting `asserted_at` to
/// a coarser value would leave the stored column no longer equal to the
/// signed envelope it was admitted for, so the row would fail its own
/// binding on re-check — trading a cross-backend divergence for a
/// self-inconsistent row. Refusing keeps the property total: **the stored
/// column, the signed envelope, and every backend's round-trip of it are the
/// same instant, byte for byte.**
///
/// The cost lands on producers, and persist pays it first:
/// [`crate::federation::attestation_emit::stamp_and_canonicalize`] truncates
/// `Utc::now()` before it stamps, so nothing this node mints can trip the
/// rule. Same fix, same reason, as `1f93785` one plane over on the Key wire
/// index.
pub const CONSENT_INSTANT_RESOLUTION_NANOS: u32 = 1_000;

/// v30.13.0 (CIRISPersist#598) — truncate an instant to the substrate's
/// [`CONSENT_INSTANT_RESOLUTION_NANOS`] floor, i.e. to what postgres
/// `TIMESTAMPTZ` can actually hold. Every persist-minted instant that will be
/// bound to a signature goes through here.
#[must_use]
pub fn truncate_to_substrate_resolution(
    t: chrono::DateTime<chrono::Utc>,
) -> chrono::DateTime<chrono::Utc> {
    use chrono::Timelike as _;
    let nanos = t.nanosecond();
    // `nanosecond()` reports ≥ 1_000_000_000 inside a leap second; `with_nanosecond`
    // then refuses the truncated value, so fall back to the input unchanged
    // rather than silently mangling it (the caller's binding check still runs).
    t.with_nanosecond(nanos / CONSENT_INSTANT_RESOLUTION_NANOS * CONSENT_INSTANT_RESOLUTION_NANOS)
        .unwrap_or(t)
}

/// v30.13.0 (CIRISPersist#598) — the instant a LOCAL-tier write stamps on
/// its row: the envelope's own signed `asserted_at` when it carries one, else
/// this node's clock truncated to the substrate resolution.
///
/// The local door mints `asserted_at` itself, which is fine while the row
/// stays local (`list_attestations_for` filters to `tier = 'federation'`, so a
/// local row reaches no consent fold) and NOT fine at promotion, where
/// [`check_promotion_admission`] asks for the binding. A subject-side
/// `consent:state:revoked` transiting the local tier (§10.1.3) must therefore
/// be able to state its own instant, or the consent-SLA watcher could never
/// promote it and every revocation would strand at local tier — fail-closed in
/// the direction that loses the revocation.
///
/// Deriving the column from the signed envelope is also the same answer
/// [`crate::federation::attestation_emit::assemble`] gives on the emit path:
/// one instant, sampled once, carried by the object.
pub fn local_row_instant(
    envelope: &serde_json::Value,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<chrono::DateTime<chrono::Utc>, Error> {
    match envelope.get(crate::federation::envelope::paths::ASSERTED_AT) {
        None | Some(serde_json::Value::Null) => Ok(truncate_to_substrate_resolution(now)),
        Some(serde_json::Value::String(s)) => chrono::DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|e| {
                Error::InvalidArgument(format!(
                    "local attestation envelope `asserted_at` is not RFC-3339: {e} \
                     (CIRISPersist#598)"
                ))
            }),
        Some(_) => Err(Error::InvalidArgument(
            "local attestation envelope `asserted_at` must be an RFC-3339 string or absent \
             (CIRISPersist#598)"
                .into(),
        )),
    }
}

/// v30.13.0 (CIRISPersist#598) — **THE CONSENT INSTANT BINDING GATE.**
///
/// # What was open
///
/// `federation_attestations.asserted_at` is a ROW COLUMN, stored VERBATIM
/// from the caller on all three backends (`sqlite.rs` / `postgres.rs` /
/// `memory.rs` `put_attestation`), and it is NOT covered by any signature:
/// `verify_row_hybrid_signature` canonicalizes `attestation_envelope`, checks
/// `SHA-256(canonical) == original_content_hash` and hybrid-verifies — the
/// column never enters the preimage. `persist_row_hash` does cover it, but is
/// recomputed locally at write, so it binds nothing across nodes.
///
/// Both consent folds order on that column. So the attack needed no forgery
/// and no broken signature — it is a **REPLAY**:
///
/// 1. subject `S` grants `analyze` at `t1`, then revokes at `t2 > t1`; the
///    fold reads `Revoked`.
/// 2. anyone resubmits `S`'s **byte-identical, still-validly-signed** `t1`
///    grant with a fresh `attestation_id` and `asserted_at = t3 > t2`.
/// 3. nothing refused it — `attestation_id` is the only PK, there is no
///    UNIQUE on the envelope or the content hash, the §6.1 dedup
///    ([`crate::federation::precedence`]) covers only the four structural
///    composers and returns `false` for a `scores` row, and the future-skew
///    guards that exist (`fresh_as_of`, trace `signed_at`) do not reach this
///    field.
/// 4. the fold reads `Granted` again — and
///    [`check_capacity_consent_admission`], a gate INSIDE persist, re-opens
///    third-party `capacity:*` scoring about `S`.
///
/// # What this refuses
///
/// A `consent:state:*` row is admitted only when, all fail-closed:
///
/// 1. its signed envelope carries `asserted_at` as an RFC-3339 string, and
///    that instant EQUALS the row column;
/// 2. its `expires_at` agrees in BOTH directions — envelope absent ⇔ column
///    `None`, envelope present ⇔ column present and equal (an unsigned
///    `expires_at` is an unsigned mute button: the fold drops an expired
///    row, so a writer who can set it alone can silence a revocation);
/// 3. both bound instants sit on the substrate resolution floor
///    ([`CONSENT_INSTANT_RESOLUTION_NANOS`] — see there for why REFUSE and
///    not truncate);
/// 4. `asserted_at` is not more than `max_skew` in the future — the
///    anti-rollback dual, reusing [`DEFAULT_MAX_TOUCH_SKEW`] rather than
///    minting a second tolerance constant. Without it the replay above still
///    works with a signed instant, just one the attacker's clock invented.
///
/// **No grandfathering.** A `consent:state:*` row whose envelope lacks the
/// instant is refused, not tolerated and not flagged (operator decision on
/// #598: "we need to break NOW … consent needs to be the final shape").
/// There is no legacy regime and no compatibility flag to find later.
///
/// # Why a gate and not a re-keyed fold
///
/// See [`crate::federation::consent::fold_ordering_key`]. Ordering stays on
/// the column; this gate is what makes the column trustworthy. Security comes
/// from the gate, not from the ordering.
///
/// # Shape
///
/// This is the [`verify_signed_transport_destination`] discipline one plane
/// over — that gate already refuses exactly this divergence for the transport
/// route table ("typed {what} diverges from the signed envelope") — minus the
/// signature verification, which the surrounding write path already performs
/// on the same envelope bytes. Pure function of `(row, now)`: no directory
/// read, no crypto, no lock ⇒ AV-76 TIER 1 on every door.
pub fn check_consent_state_instant_binding(
    row: &super::Attestation,
    now: chrono::DateTime<chrono::Utc>,
    max_skew: chrono::Duration,
) -> Result<(), Error> {
    use crate::federation::envelope::paths;
    let Some(dimension) = envelope_dimension(&row.attestation_envelope) else {
        return Ok(());
    };
    if !dimension.starts_with(crate::federation::consent::consent_dimension::STATE_PREFIX) {
        return Ok(());
    }
    let env = &row.attestation_envelope;

    let parse = |key: &str, s: &str| -> Result<chrono::DateTime<chrono::Utc>, Error> {
        chrono::DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&chrono::Utc))
            .map_err(|e| {
                Error::InvalidArgument(format!(
                    "consent:state row {}: signed envelope `{key}` is not RFC-3339: {e} \
                     (CIRISPersist#598)",
                    row.attestation_id
                ))
            })
    };
    let on_resolution = |key: &str, t: chrono::DateTime<chrono::Utc>| -> Result<(), Error> {
        use chrono::Timelike as _;
        if t.nanosecond() % CONSENT_INSTANT_RESOLUTION_NANOS == 0 {
            return Ok(());
        }
        Err(Error::InvalidArgument(format!(
            "consent:state row {}: `{key}` = {} carries sub-microsecond precision, which \
             postgres TIMESTAMPTZ cannot store — the same op sequence would be a strict order \
             on sqlite/memory and a TIE on postgres. Truncate to microseconds at the producer \
             (CIRISPersist#598)",
            row.attestation_id,
            t.to_rfc3339(),
        )))
    };

    // (1) asserted_at — REQUIRED, and the row column must equal it.
    let Some(serde_json::Value::String(env_asserted)) = env.get(paths::ASSERTED_AT) else {
        return Err(Error::InvalidArgument(format!(
            "consent:state row {} carries no signed `{}` string in its envelope. The consent \
             fold orders on the `asserted_at` COLUMN, which no signature covers — an unbound \
             row is a replay waiting to happen, so it is REFUSED (no legacy regime; \
             CIRISPersist#598)",
            row.attestation_id,
            paths::ASSERTED_AT,
        )));
    };
    let env_asserted = parse(paths::ASSERTED_AT, env_asserted)?;
    if env_asserted != row.asserted_at {
        return Err(Error::InvalidArgument(format!(
            "consent:state row {}: typed `asserted_at` {} diverges from the signed envelope's \
             {} (rejected — the column decides which consent claim wins, so it may not differ \
             from the signed instant; CIRISPersist#598)",
            row.attestation_id,
            row.asserted_at.to_rfc3339(),
            env_asserted.to_rfc3339(),
        )));
    }
    on_resolution(paths::ASSERTED_AT, row.asserted_at)?;

    // (2) expires_at — bound in BOTH directions (absent ⇔ None).
    let env_expires = match env.get(paths::EXPIRES_AT) {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(s)) => Some(parse(paths::EXPIRES_AT, s)?),
        Some(_) => {
            return Err(Error::InvalidArgument(format!(
                "consent:state row {}: signed envelope `{}` must be an RFC-3339 string or absent \
                 (CIRISPersist#598)",
                row.attestation_id,
                paths::EXPIRES_AT,
            )))
        }
    };
    if env_expires != row.expires_at {
        return Err(Error::InvalidArgument(format!(
            "consent:state row {}: typed `expires_at` {:?} diverges from the signed envelope's \
             {:?} (rejected — the fold DROPS an expired row, so an unsigned expiry is an \
             unsigned mute button on a revocation; CIRISPersist#598)",
            row.attestation_id,
            row.expires_at.map(|t| t.to_rfc3339()),
            env_expires.map(|t| t.to_rfc3339()),
        )));
    }
    if let Some(exp) = row.expires_at {
        on_resolution(paths::EXPIRES_AT, exp)?;
    }

    // (3) the future-skew dual. Binding alone stops a REPLAY of someone
    // else's instant; it does not stop the claimant's own clock asserting a
    // grant far enough forward that no later revocation can ever out-sort it.
    let skew = row.asserted_at - now;
    if skew > max_skew {
        return Err(Error::InvalidArgument(format!(
            "consent:state row {}: asserted_at {} is {}s ahead of now ({}), beyond the {}s skew \
             tolerance — a lying clock cannot mint a consent claim no later revocation can \
             out-sort (CIRISPersist#598)",
            row.attestation_id,
            row.asserted_at.to_rfc3339(),
            skew.num_seconds(),
            now.to_rfc3339(),
            max_skew.num_seconds(),
        )));
    }
    Ok(())
}

/// v21.6.0 (CIRISPersist#519 item 2a-iii) — the SIGNED touch-claim
/// admission gate: the freshness-floor mirror of
/// [`verify_signed_transport_destination`], closing the same class of hole
/// (an unsigned/forged touch could otherwise jump anyone's liveness floor
/// forward at will). Fail-secure; called by every `put_touch_claim` (all
/// three backends — one gate) BEFORE any write, ALONGSIDE — never instead
/// of — [`verify_touch_claim_admission`] (the future-skew guard): a
/// touch-claim admits ONLY when the hybrid signature verifies AND the skew
/// guard passes.
///
/// **Authority is `signed_envelope`, never the sender's typed projection**
/// — the #418 discipline verbatim. Verifies, each fail-closed:
/// 1. the envelope carries `target_key_id` / `target_kind` / `fresh_as_of`
///    / `signer_form` / `attesting_key_id` / `cohort_scope`, and the typed
///    projection persist will store EQUALS them (a divergent projection is
///    the MITM reopening);
/// 2. `cohort_scope` is one of the closed-set values
///    ([`check_cohort_scope`]) — touch-claims are cohort-scoped and
///    consent-gated by construction (the MANDATORY privacy row: an
///    unrestricted read-receipt trail is an access-pattern surveillance
///    surface, worst-case `trace:*` leaking who reads whose reasoning);
/// 3. the detached hybrid signature over `JCS(signed_envelope)` verifies at
///    threshold **1-of-1** against the PINNED federation pubkeys of
///    `attesting_key_id` ([`verify_threshold_signatures`] — RequireHybrid;
///    a classical-only touch does not count);
/// 4. the **signer-form relationship**
///    ([`crate::federation::types::SignerForm`]):
///    [`SelfTouch`](crate::federation::types::SignerForm::SelfTouch)
///    requires the signer to BE the touched `target_key_id` or a
///    registered occurrence of it — the same "own clock / dead-man's-
///    switch" bar [`check_signer_acts_for`] already draws elsewhere;
///    [`WitnessTouch`](crate::federation::types::SignerForm::WitnessTouch) /
///    [`NOfMCosigned`](crate::federation::types::SignerForm::NOfMCosigned)
///    require an attester INDEPENDENT of the target — the OPPOSITE bar (a
///    witness cannot be the thing it is witnessing).
///
/// **Known limitation (deliberate, documented, not built here):**
/// `NOfMCosigned` verifies IDENTICALLY to `WitnessTouch` (a single
/// independent attester, 1-of-1). The wire shape this cut ships — one
/// `attesting_key_id` + one
/// [`ciris_verify_core::transport_binding::TransportBindingSignature`],
/// mirroring [`crate::federation::self_at_login::SignedTransportDestination`]
/// exactly per the #519 item 2a-iii brief — has no multi-signer envelope to
/// tally an actual m-of-n quorum over. Real collusion-resistant n-of-m
/// aggregation needs a wire-shape change (a signer set + threshold, like
/// [`ciris_verify_core::threshold::ThresholdSignature`] used as a LIST
/// rather than a single value) and is a follow-up.
///
/// NOT feature-gated: backend-agnostic, and the MemoryBackend calls it (the
/// #418 cfg lesson).
///
/// [`verify_threshold_signatures`]: ciris_verify_core::threshold::verify_threshold_signatures
pub async fn verify_signed_touch_claim(
    directory: &dyn super::FederationDirectory,
    claim: &crate::federation::types::SignedTouchClaim,
) -> Result<(), Error> {
    use ciris_verify_core::threshold::{
        verify_threshold_signatures, ThresholdMember, ThresholdSignature,
    };

    let env = &claim.signed_envelope;

    // (1) Authoritative fields FROM the signed envelope; the typed
    // projection must equal them (the signature covers only the envelope).
    let str_field = |k: &str| -> Result<String, Error> {
        env.get(k)
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned())
            .ok_or_else(|| {
                Error::InvalidArgument(format!(
                    "signed touch_claim envelope missing string field `{k}`"
                ))
            })
    };
    let diverges = |what: &str| {
        Error::InvalidArgument(format!(
            "signed touch_claim: typed {what} diverges from the signed envelope (rejected)"
        ))
    };
    if str_field("target_key_id")? != claim.target_key_id {
        return Err(diverges("target_key_id"));
    }
    if str_field("target_kind")? != claim.target_kind {
        return Err(diverges("target_kind"));
    }
    let env_fresh_str = str_field("fresh_as_of")?;
    let env_fresh_as_of = chrono::DateTime::parse_from_rfc3339(&env_fresh_str)
        .map(|t| t.with_timezone(&chrono::Utc))
        .map_err(|e| {
            Error::InvalidArgument(format!(
                "signed touch_claim envelope `fresh_as_of` not RFC-3339: {e}"
            ))
        })?;
    if env_fresh_as_of != claim.fresh_as_of {
        return Err(diverges("fresh_as_of"));
    }
    if str_field("signer_form")? != claim.signer_form.as_str() {
        return Err(diverges("signer_form"));
    }
    if str_field("attesting_key_id")? != claim.attesting_key_id {
        return Err(diverges("attesting_key_id"));
    }
    if str_field("cohort_scope")? != claim.cohort_scope {
        return Err(diverges("cohort_scope"));
    }

    // (2) MANDATORY privacy row: cohort_scope must be a closed-set value.
    check_cohort_scope(&claim.cohort_scope)?;

    // (3) Hybrid signature over JCS(signed_envelope) against the PINNED
    // federation pubkeys of the claimed signer, threshold 1-of-1.
    let Some(signer_key) = directory.lookup_public_key(&claim.attesting_key_id).await? else {
        return Err(Error::SignatureInvalid(format!(
            "signed touch_claim: attesting_key_id {} is not a registered federation key",
            claim.attesting_key_id
        )));
    };
    // v21.10.0 (#519 b2) — the signature bytes are over the envelope WITHOUT
    // the `touch_cosignatures` set: co-signatures cannot be inside the bytes
    // they sign (the fixed-point the reclaim quorum solves the same way). For
    // SelfTouch/WitnessTouch the field is absent, so this is a no-op clone.
    let sig_env = {
        let mut e = env.clone();
        if let Some(obj) = e.as_object_mut() {
            obj.remove(crate::federation::freshness::TOUCH_COSIGNATURES_FIELD);
        }
        e
    };
    let bytes = crate::verify::canonical::ceg_produce_canonicalize(&sig_env)
        .map_err(|e| Error::InvalidArgument(format!("signed touch_claim canonicalize: {e}")))?;
    let members = [ThresholdMember {
        member_id: signer_key.key_id.clone(),
        ed25519_public_key_base64: signer_key.pubkey_ed25519_base64.clone(),
        mldsa65_public_key_base64: signer_key.pubkey_ml_dsa_65_base64.clone(),
        role: None,
    }];
    let sigs = [ThresholdSignature {
        member_id: claim.attesting_key_id.clone(),
        ed25519_signature_base64: claim.signature.ed25519_signature_base64.clone(),
        mldsa65_signature_base64: claim.signature.mldsa65_signature_base64.clone(),
    }];
    if verify_threshold_signatures(&bytes, &members, &sigs, 1).is_err() {
        return Err(Error::SignatureInvalid(format!(
            "signed touch_claim for ({}, {}) not authentic (hybrid 1-of-1 over JCS(envelope) \
             failed against the pinned key of {})",
            claim.target_key_id, claim.target_kind, claim.attesting_key_id
        )));
    }

    // (4) signer-form relationship — the opposite bars `SelfTouch` and
    // `WitnessTouch`/`NOfMCosigned` draw.
    use crate::federation::types::SignerForm;
    match claim.signer_form {
        SignerForm::SelfTouch => {
            check_signer_acts_for(
                directory,
                &claim.attesting_key_id,
                &claim.target_key_id,
                "touch_claim",
            )
            .await?;
        }
        SignerForm::WitnessTouch | SignerForm::NOfMCosigned => {
            if claim.attesting_key_id == claim.target_key_id {
                return Err(Error::SignatureInvalid(format!(
                    "signed touch_claim: signer_form {:?} requires an attester independent of \
                     the touched target {} — a witness cannot be the thing it witnesses",
                    claim.signer_form, claim.target_key_id
                )));
            }
        }
    }

    // (5) v21.10.0 (CIRISPersist#519 b2) — NOfMCosigned is a real m-of-n
    // TALLY, not the 1-of-1 above. The primary attester (verified in step 3)
    // counts as one signer; the envelope's `touch_cosignatures` extra carries
    // the rest. Each co-signature must verify (hybrid, over the SAME
    // JCS(envelope) bytes) against the co-signer's OWN pinned federation key,
    // and every signer must be DISTINCT and INDEPENDENT of the target — so a
    // forged "death finding" needs to corrupt >= NOFM_MIN_COSIGNERS+1 distinct
    // real keys, not one. (SelfTouch / WitnessTouch ignore this field.)
    if claim.signer_form == SignerForm::NOfMCosigned {
        use crate::federation::freshness::{NOFM_MIN_COSIGNERS, TOUCH_COSIGNATURES_FIELD};
        let cosigs_val = env.get(TOUCH_COSIGNATURES_FIELD).ok_or_else(|| {
            Error::SignatureInvalid(format!(
                "signed touch_claim: signer_form NOfMCosigned requires a `{TOUCH_COSIGNATURES_FIELD}` \
                 co-signature set in the signed envelope"
            ))
        })?;
        let cosigs: Vec<ThresholdSignature> = serde_json::from_value(cosigs_val.clone())
            .map_err(|e| {
                Error::InvalidArgument(format!(
                    "signed touch_claim: `{TOUCH_COSIGNATURES_FIELD}` is not a threshold-signature array: {e}"
                ))
            })?;
        // Distinct + independent-of-target signer set, primary included.
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        seen.insert(claim.attesting_key_id.clone());
        let mut distinct_cosigners = 0usize;
        for cs in &cosigs {
            if cs.member_id == claim.target_key_id {
                return Err(Error::SignatureInvalid(format!(
                    "signed touch_claim: NOfMCosigned co-signer {} is the touched target — \
                     independence required",
                    cs.member_id
                )));
            }
            if !seen.insert(cs.member_id.clone()) {
                // duplicate (or equals the primary) — does not add to the tally.
                continue;
            }
            let Some(cs_key) = directory.lookup_public_key(&cs.member_id).await? else {
                return Err(Error::SignatureInvalid(format!(
                    "signed touch_claim: NOfMCosigner {} is not a registered federation key",
                    cs.member_id
                )));
            };
            let cs_member = [ThresholdMember {
                member_id: cs_key.key_id.clone(),
                ed25519_public_key_base64: cs_key.pubkey_ed25519_base64.clone(),
                mldsa65_public_key_base64: cs_key.pubkey_ml_dsa_65_base64.clone(),
                role: None,
            }];
            let cs_sig = [cs.clone()];
            if verify_threshold_signatures(&bytes, &cs_member, &cs_sig, 1).is_err() {
                return Err(Error::SignatureInvalid(format!(
                    "signed touch_claim: NOfMCosigner {}'s signature is not authentic over the \
                     touch envelope",
                    cs.member_id
                )));
            }
            distinct_cosigners += 1;
        }
        if distinct_cosigners < NOFM_MIN_COSIGNERS {
            return Err(Error::SignatureInvalid(format!(
                "signed touch_claim: NOfMCosigned needs >= {NOFM_MIN_COSIGNERS} distinct valid \
                 co-signer(s) beyond the primary attester; got {distinct_cosigners}"
            )));
        }
    }
    Ok(())
}

/// v3.11.0 (CIRISPersist#143, CIRISVerify FEDERATION_THREAT_MODEL
/// §3.3.2 R1) — admission-gate validation of the producer-side
/// `observed_region` field on a revocation.
///
/// Rejects any value outside the closed set
/// `{us, eu, apac}` ([`crate::federation::verify_coord::region::is_valid`])
/// BEFORE the row is hashed and inserted, so a malformed envelope
/// leaves no trace. Returns [`Error::RegionRejected`] on a bad value
/// (stable `kind()` token `federation_region_rejected`).
///
/// Application-layer companion to the V058 `CHECK (observed_region IN
/// (...))` constraint: the constraint is the defense-in-depth backstop
/// for direct-SQL bypass; this hook produces the typed rejection
/// consumers pattern-match on.
pub fn check_observed_region(observed_region: &str) -> Result<(), Error> {
    if crate::federation::verify_coord::region::is_valid(observed_region) {
        Ok(())
    } else {
        Err(Error::RegionRejected {
            observed_region: observed_region.to_string(),
        })
    }
}

/// v3.12.0 (CIRISPersist#153 Ask 1, CEG 0.7 §5.6.8.8) — admission-gate
/// validation of the producer-side `device_class` field on an
/// `identity_occurrence` Contribution.
///
/// Rejects any value outside the closed set `{phone, laptop, server,
/// embedded, agent, service}`
/// ([`crate::federation::types::device_class::is_valid`]) BEFORE the
/// row is hashed and inserted. Returns [`Error::DeviceClassRejected`]
/// on a bad value (stable `kind()` token
/// `federation_device_class_rejected`).
///
/// Application-layer companion to the V059 `CHECK (device_class IN
/// (...))` constraint: the constraint is defense-in-depth for direct-
/// SQL bypass; this hook produces the typed rejection consumers
/// pattern-match on.
pub fn check_device_class(device_class: &str) -> Result<(), Error> {
    if crate::federation::types::device_class::is_valid(device_class) {
        Ok(())
    } else {
        Err(Error::DeviceClassRejected {
            device_class: device_class.to_string(),
        })
    }
}

/// v3.12.0 (CIRISPersist#153 Ask 2, CEG 0.7 §5.6.8.9) — admission-gate
/// validation of the producer-side `consensus_protocol` field on a
/// `family` Contribution.
///
/// `consensus_protocol` is OPEN vocabulary per the spec — operators
/// MAY extend with their own protocol names. This gate verifies the
/// string parses into one of the canonical shapes
/// ([`crate::federation::types::consensus_protocol::is_canonical_form`]):
/// the three bare forms (`founder_only`, `unanimous`, `majority`), or
/// one of the three prefixed forms with a non-empty tail
/// (`quorum:m/n`, `weighted:rubric`, `custom:id`). Returns
/// [`Error::ConsensusProtocolMalformed`] on a malformed string
/// (stable `kind()` token `federation_consensus_protocol_malformed`).
///
/// **Not** the consensus-protocol enforcement gate — full signature
/// counting against the named protocol is the v3.13+ admission gate
/// (#153 Ask 3). This is the value-validation floor that enforcement
/// composes on top of.
pub fn check_consensus_protocol_form(consensus_protocol: &str) -> Result<(), Error> {
    if crate::federation::types::consensus_protocol::is_canonical_form(consensus_protocol) {
        Ok(())
    } else {
        Err(Error::ConsensusProtocolMalformed {
            consensus_protocol: consensus_protocol.to_string(),
        })
    }
}

/// v13.3.0 (CIRISPersist#386) — the REAL family invariant, enforced at
/// `put_family` write time on every backend: **every member `key_id` MUST be a
/// registered `federation_keys` row**. This replaces the dropped
/// `family_key_id REFERENCES federation_keys` FK (V097) — a constitutional
/// family is *keyless* (constituted by its founder quorum, NOT by owning a
/// key), so the family's OWN key was never the meaningful constraint; the
/// members being real keys always was. Applies uniformly to constitutional and
/// ordinary families. Fail-secure: an unregistered member ⇒ `InvalidArgument`,
/// verify-before-mutation.
pub async fn validate_family_members<D>(
    directory: &D,
    family: &crate::federation::types::Family,
) -> Result<(), Error>
where
    D: super::FederationDirectory + ?Sized,
{
    for m in &family.members {
        if directory.lookup_public_key(&m.key_id).await?.is_none() {
            return Err(Error::InvalidArgument(format!(
                "family {} member {} is not a registered federation_keys row \
                 (members MUST be registered keys)",
                family.family_key_id, m.key_id
            )));
        }
    }
    Ok(())
}

// ─── v6.4.0 — broadened `withdraws` admission gate (CEG §3.2.3) ────

/// The delegation-scope token a `delegates_to` edge MUST carry for it
/// to confer proxy revocation authority under rule 3 / rule 4 (CEG
/// §3.2.3: `scope ⊇ {consent_revocation}`). Matched against the
/// `delegates_to` envelope's `scope` field, which persist admits as
/// either a bare string OR a JSON array of strings (set-containment).
pub const DELEGATION_SCOPE_CONSENT_REVOCATION: &str = "consent_revocation";

/// v8.7.0 (CIRISPersist#232, CEG 1.0-RC19 §11.10 / §3.2.3 rule-(3);
/// CIRISRegistry#90) — the `moderate` delegated-duty scope. A
/// `delegates_to` chain bearing this token authorizes the delegate to
/// emit a [`ModerationEvent`](crate::cirisnode::ModerationEvent) on the
/// delegator's behalf, and ONLY then. Same wire-shape acceptance as
/// [`DELEGATION_SCOPE_CONSENT_REVOCATION`] (bare string OR array-set).
pub const DELEGATION_SCOPE_MODERATE: &str = "moderate";

/// v8.7.0 (CIRISPersist#232, CEG §11.10 / §11.4; CIRISRegistry#90) — the
/// `takedown` delegated-duty scope. A `delegates_to` chain bearing this
/// token authorizes the delegate to emit a `takedown_notice` Contribution
/// on the delegator's behalf, and ONLY then.
pub const DELEGATION_SCOPE_TAKEDOWN: &str = "takedown";

/// v8.7.0 (CIRISPersist#232, CEG §11.10; CIRISRegistry#90) — the `review`
/// delegated-duty scope. A `delegates_to` chain bearing this token
/// authorizes the delegate to emit a report → `scores` (reconsideration)
/// attestation on the delegator's behalf, and ONLY then.
pub const DELEGATION_SCOPE_REVIEW: &str = "review";

/// v25.1.0 (CIRISPersist#570 ask 2; CIRISServer `FSD/ADMIN_OPS_TAXONOMY.md`,
/// CC 6.1.2) — the `slash` delegated-duty scope: **the authority to take
/// something AWAY.**
///
/// The four scopes above it are all authorities to **emit** — write a note,
/// file a report, publish a takedown notice. Between "write a note" and the
/// node-wide kill switch there was nothing, so every graded response either
/// under-reached (a note nobody has to read) or over-reached (halt the node).
/// `slash` is the middle rung: it authorizes the tier-3/4 ops that REMOVE —
/// today [`quarantine`](crate::federation::quarantine) (ask 5, withhold from
/// serving) and time-bounded de-admission
/// ([`Revocation::revoked_after`](crate::federation::Revocation::revoked_after),
/// ask 4).
///
/// Identical wire acceptance and identical walk to the other four: a bare
/// string OR a JSON array-set on a `delegates_to` envelope, traversed under
/// [`DelegationWalkPolicy::MODERATION_DUTY`] (⊆-parent attenuation,
/// `sub_delegation`-gated deputization, `withdraws`-retracted edges skipped,
/// depth ≤ [`MAX_MODERATION_DELEGATION_DEPTH`]), rooted at a
/// [`is_steward_bound`] duty holder. There is deliberately no laxer path for
/// the scope that takes things away.
///
/// # It is not a decoration
///
/// The #333 lesson this repo keeps re-learning is that a conferral nothing
/// gates on is a stored label. `slash` gates a real door from the moment it
/// exists: [`check_delegated_duty_scores_admission`] routes every
/// [`QUARANTINE_DIMENSION_PREFIX`] row through it, so a quarantine marker
/// authored by a key with no live `slash` chain is refused and never stored —
/// which in turn is what lets the serve path treat "held" as "authorized"
/// without re-walking the graph on every page.
pub const DELEGATION_SCOPE_SLASH: &str = "slash";

/// v30.11.0 (CIRISPersist#637) — **the delegated-duty ladder, as an array.**
/// Import this; do not hand-pick the `DELEGATION_SCOPE_*` constants above.
///
/// | scope | grants |
/// |---|---|
/// | [`DELEGATION_SCOPE_CONSENT_REVOCATION`] | proxy revocation authority (CEG §3.2.3 rule 3/4) |
/// | [`DELEGATION_SCOPE_MODERATE`] | emit a `ModerationEvent` on the delegator's behalf |
/// | [`DELEGATION_SCOPE_TAKEDOWN`] | emit a `takedown_notice` Contribution |
/// | [`DELEGATION_SCOPE_REVIEW`] | emit a report → `scores` reconsideration |
/// | [`DELEGATION_SCOPE_SLASH`] | take something AWAY — quarantine, time-bounded de-admission |
///
/// # Why this exists — five `pub const`s and no array cost a shipped defect
///
/// CIRISServer's duty-conferral card shipped able to confer **three of five**;
/// `takedown` and `consent_revocation` were simply absent. The constants were
/// imported, not retyped — spelling was never the problem. **There was nothing
/// to import for MEMBERSHIP**, so every consumer hand-picked the subset it knew
/// about, and a hand-picked mirror of another crate's vocabulary drifts the
/// moment that vocabulary grows.
///
/// A missing option is uniquely hard to notice: the dropdown looked complete,
/// and nobody scans a menu wondering what is *not* on it. It surfaced only
/// because an operator asked whether the verbs had come from an authoritative
/// list — and they had not, because there wasn't one.
///
/// # `owner_binding_recovery` is excluded, deliberately
///
/// [`crate::federation::ownership_reclaim::DELEGATION_SCOPE_OWNER_BINDING_RECOVERY`]
/// carries the same `DELEGATION_SCOPE_` prefix and is **not** a delegated duty:
/// it is CC 3.2 succession standing, traversed on a different plane by a
/// different walk. It answers "who speaks for this key now", not "what may be
/// done about this party". Excluded by decision, not by the accident of living
/// in another file — see [`crate::federation::types::delegation_scope::RECOVERY`].
///
/// # Single definition
///
/// [`crate::federation::types::delegation_scope::MODERATION`] IS this array, not
/// a copy of it. Two arrays over one vocabulary would be the defect this
/// constant exists to remove.
pub const DELEGATED_DUTY_SCOPES: &[&str] = &[
    DELEGATION_SCOPE_CONSENT_REVOCATION,
    DELEGATION_SCOPE_MODERATE,
    DELEGATION_SCOPE_TAKEDOWN,
    DELEGATION_SCOPE_REVIEW,
    DELEGATION_SCOPE_SLASH,
];

/// v6.7.0 (CIRISPersist#146 Ask 6, CEG 1.0-RC5 §5.6.8.14) — the reserved
/// `scores` dimension prefix for a **canonical-binding** claim. A bare
/// `scores` on `identity:canonical_binding:{H}` with `attesting_key_id =
/// K` is K's self-assertion "I am the federation identity behind the
/// canonical hash H". `{H}` is the suffix after this prefix. NOT a new
/// primitive — a reserved `scores` dimension (1+4 preserved).
pub const IDENTITY_CANONICAL_BINDING_PREFIX: &str = "identity:canonical_binding:";

/// Parse the bound canonical hash `H` out of an
/// `identity:canonical_binding:{H}` dimension. `None` if the dimension
/// is not a canonical-binding or carries an empty suffix.
#[must_use]
pub fn parse_canonical_binding_hash(dimension: &str) -> Option<&str> {
    dimension
        .strip_prefix(IDENTITY_CANONICAL_BINDING_PREFIX)
        .filter(|h| !h.is_empty())
}

/// v6.7.0 (CIRISPersist#146 Ask 6, CEG §5.6.8.14) — the set of canonical
/// hashes `K` has an admitted `identity:canonical_binding` claim to. Each
/// admitted binding widens K's `withdraws` authority: K is treated as
/// authorized wherever one of these hashes appears in a target's
/// `subject_key_ids` (§3.2.3 rule 2/3). A binding is a `scores` row with
/// `attesting_key_id = K` on the reserved `identity:canonical_binding:{H}`
/// dimension; we read K's out-rows via
/// [`FederationDirectory::list_attestations_by`] and collect every `H`.
///
/// Authorization is consumer-policy (§5.6.8.14: proof-of-control of H is
/// out-of-band, NOT a wire obligation) — persist admits the self-assertion
/// and exposes it here; it does not adjudicate whether K legitimately
/// controls H.
async fn canonical_binding_hashes_for(
    directory: &dyn super::FederationDirectory,
    issuer: &str,
) -> Result<std::collections::HashSet<String>, Error> {
    let mut out = std::collections::HashSet::new();
    for r in directory.list_attestations_by(issuer).await? {
        if r.attestation_type != attestation_type::SCORES {
            continue;
        }
        if let Some(h) =
            envelope_dimension(&r.attestation_envelope).and_then(parse_canonical_binding_hash)
        {
            out.insert(h.to_owned());
        }
    }
    Ok(out)
}

/// Depth bound + cycle guard for the rule-3/rule-4 delegation walk.
/// Mirrors [`crate::federation::topology::MAX_DELEGATION_DEPTH`] (16);
/// a `delegates_to` graph deeper than this cannot confer revocation
/// authority (a pathological chain is refused, not silently admitted).
pub const MAX_WITHDRAWS_DELEGATION_DEPTH: usize = 16;

/// v8.7.0 (CIRISPersist#232) — true iff a `delegates_to` envelope's
/// `scope` field contains `scope_token`. Accepts both wire shapes:
///
/// - `"scope": "consent_revocation"` (bare string), and
/// - `"scope": ["retain", "consent_revocation"]` (array — set).
///
/// A delegation with no `scope`, or a `scope` that omits the token,
/// does NOT confer the duty (returns `false`). This is the single
/// scope-containment predicate behind every delegated-duty walk
/// (`consent_revocation` / `moderate` / `takedown` / `review`); the
/// scope token is the only thing that varies — the bare-string-OR-set
/// acceptance is identical for all four (§11.10 mirrors §3.2.3 rule-3).
fn delegation_scope_grants(envelope: &serde_json::Value, scope_token: &str) -> bool {
    match envelope.get("scope") {
        Some(serde_json::Value::String(s)) => s == scope_token,
        Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(scope_token)),
        _ => false,
    }
}

/// v8.7.1 (CIRISPersist#233, CEG RC24 §11.10 deputization + attenuation)
/// — the set of scope tokens a `delegates_to` envelope's `scope` field
/// declares, as a `HashSet`. Accepts both wire shapes (bare string OR
/// array-of-strings) exactly as [`delegation_scope_grants`]. The §11.10
/// `⊆`-parent attenuation check (`child.scope ⊆ parent.scope`) compares
/// these sets along the chain. A `scope` that is neither string nor array
/// (or absent) yields the empty set.
/// v11.9.0 (CIRISPersist#309, CC 3.4.12 fail-to-liberty) — has a
/// `delegates_to` row's envelope `valid_until` lapsed as of `now`? An
/// adult-incapacity binding carries a mandatory `valid_until`; on lapse it
/// goes non-live and the adult auto-re-sovereigns with NO steward assent. A
/// minor-guardianship row carries no `valid_until`, so this returns `false`
/// for it (unaffected). An unparseable `valid_until` is treated as
/// NOT-lapsed (fail-open at read is wrong here — but a malformed binding is
/// rejected at admission, so this branch is unreachable for admitted rows;
/// we do not silently un-live a row on a parse quirk).
fn delegation_valid_until_lapsed(
    envelope: &serde_json::Value,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    envelope
        .get(crate::federation::capacity::binding_field::VALID_UNTIL)
        .and_then(serde_json::Value::as_str)
        .and_then(|s| s.parse::<chrono::DateTime<chrono::Utc>>().ok())
        .map(|vu| vu <= now)
        .unwrap_or(false)
}

/// v30.0.0 (CIRISPersist#596 item 3) — **the scopes a `delegates_to` envelope
/// actually confers**, exported so consumers stop re-implementing it.
///
/// `pub(crate)` until now, which left the only public authority predicate as
/// [`reachable_under_scope`] — true the moment the issuer granted `S` by **any**
/// edge. CIRISServer's mutation testing caught what that permits: without a
/// per-row scope check their route **recorded a `review` delegation as the
/// authority for a `slash` de-admission**. They mirrored this parse on their
/// side to close it, and marked the copy for deletion the day this is exported.
///
/// That copy is the thing worth avoiding. A second implementation of an
/// authority rule is the split-truth shape this repo has spent the cycle
/// closing — the same defect persist filed CIRISConstitution#81 about, where a
/// rule stated in one place is re-derived in another and nothing detects the
/// two disagreeing.
///
/// Tolerant of both wire shapes a `scope` field takes (a bare string, or an
/// array), because refusing a legitimate single-scope envelope on a parse
/// quirk would fail CLOSED on the authority plane — and an authority predicate
/// that silently returns an empty set is indistinguishable from "confers
/// nothing".
#[must_use]
pub fn delegation_scope_set(envelope: &serde_json::Value) -> std::collections::HashSet<String> {
    match envelope.get("scope") {
        Some(serde_json::Value::String(s)) => std::iter::once(s.clone()).collect(),
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => std::collections::HashSet::new(),
    }
}

/// v9.0.0 (CIRISPersist#236, CC 4.4.3.4.3 / CC 1.13.5) — the CC 1.13.5
/// verifier: is `scopes` a delegation scope set a pure `node`-role
/// delegate is allowed to carry?
///
/// Returns `true` **iff** the set is **non-empty** AND **every** token
/// begins with [`super::types::delegation_scope::INFRA_PREFIX`]
/// (`infra:`). Returns `false` for any set that:
///
/// - is **empty** (a node delegation must positively name infra scopes;
///   a scope-less delegation grants nothing checkable), OR
/// - contains any `agency:*` token, OR
/// - contains any **legacy unprefixed** agency kind
///   ([`super::types::delegation_scope::is_legacy_agency_scope`] —
///   `act_on_behalf` / `message_io` / `reason` / `decide` /
///   `sub_delegation`), OR
/// - contains any other non-`infra:` token (unknown prefix, etc.).
///
/// **CIRISServer parity.** This mirrors CIRISServer
/// `src/auth/ownership.rs::scopes_are_infra_only(&[String])` semantics
/// EXACTLY (accepts `infra:*`, rejects `agency:*` + legacy agency kinds +
/// empty + other). The legacy-agency and other-prefix cases are
/// subsumed by the single "every token starts with `infra:`" predicate
/// (a legacy kind like `act_on_behalf` does not start with `infra:`), so
/// the predicate is the whole rule; the legacy-agency recognizer exists
/// for the explicit reject-message / test clarity, not as a separate
/// admission branch. Exposed `pub` for downstream reuse (the gate below
/// + CIRISServer's server-side wrapper).
pub fn scopes_are_infra_only(scopes: &std::collections::HashSet<String>) -> bool {
    !scopes.is_empty()
        && scopes
            .iter()
            .all(|s| s.starts_with(super::types::delegation_scope::INFRA_PREFIX))
}

/// v8.7.1 (CIRISPersist#233, CEG RC24 §11.10) — does a `delegates_to`
/// envelope grant `sub_delegation` (the right of the recipient to
/// further-delegate the duty)? `true` only when the envelope carries
/// `"sub_delegation": true`; absent / false / non-bool ⇒ `false`. A
/// delegate WITHOUT `sub_delegation` is a leaf — it may exercise the duty
/// but MUST NOT deputize anyone further (UCAN-style; §13.3 deputization
/// gate). The root duty-holder is NOT subject to this gate (it holds the
/// duty natively, not by delegation).
/// v30.8.0 (CIRISPersist#628) — the **re-delegation BUDGET**: how many further
/// hops the recipient's own chain may run.
///
/// # This EXTENDS `sub_delegation`; it does not sit beside it
///
/// #628 asked for a separate `redelegation_depth` with `absent ⇒ 0`. That would
/// be a second answer to the question `sub_delegation` already answers — *may
/// this recipient pass the duty on?* — and two fields that can disagree about
/// one property is the class this substrate keeps paying for (#532's
/// one-name-two-axes, #541's two-lists-that-disagree). The boolean stays the
/// gate; this is only the BOUND on a gate already open:
///
/// | envelope | meaning |
/// |---|---|
/// | `sub_delegation` absent / `false` | leaf — may exercise, may not pass on (**unchanged**, still the default) |
/// | `sub_delegation: true`, no depth | may pass on, bounded only by the global rail (**unchanged** — every already-issued grant keeps its exact meaning) |
/// | `sub_delegation: true, sub_delegation_depth: N` | may pass on; the chain below may run `N` further hops |
///
/// `redelegation_depth: 0` from the issue is spelled `sub_delegation: false`,
/// which is what every envelope without the field already says. The new field
/// can only ever TIGHTEN.
fn delegation_sub_delegation_depth(envelope: &serde_json::Value) -> Option<usize> {
    envelope
        .get("sub_delegation_depth")
        .and_then(serde_json::Value::as_u64)
        .map(|n| usize::try_from(n).unwrap_or(usize::MAX))
}

fn delegation_grants_sub_delegation(envelope: &serde_json::Value) -> bool {
    envelope
        .get("sub_delegation")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// v8.7.1 (CIRISPersist#233) — per-walk policy distinguishing the two
/// `delegates_to`-chain consumers that share
/// [`issuer_reaches_target_via_scoped_delegation`]:
///
/// - **`consent_revocation`** (CEG §3.2.3) — the proxy revocation walk
///   (rule 3, and the proxy half of rule 4).
///   `enforce_attenuation_and_sub_delegation = false`: its delegations do
///   not carry `⊆`-parent attenuation or a `sub_delegation` deputization
///   gate, so those constraints do not apply to it.
/// - **§11.10 `moderate` / `takedown` / `review`** (CEG RC24) — the
///   moderation-enforcement walk. `enforce_attenuation_and_sub_delegation
///   = true`: each edge's scope must be `⊆` its parent edge's scope
///   (restate-or-attenuate) and a non-root node may only be reached
///   through a parent edge that granted `sub_delegation`.
///
/// # Retraction is NOT a policy axis (CIRISPersist#594)
///
/// This struct used to carry a second flag, `skip_withdrawn_edges`, which
/// the consent-revocation policy set to `false` — so that walk consulted
/// **no retraction at all**, not even one the granter issued against its own
/// edge. It was introduced in v8.7.1 to add per-edge revocation for the
/// moderation walk *without* changing the consent walk, and documented as
/// keeping that walk "BYTE-IDENTICAL to the v6.4.0 behaviour".
///
/// That was true, and it was the defect: byte-identical-to-v6.4.0 preserved a
/// v6.4.0 **gap** rather than a v6.4.0 **decision**. Nothing anywhere recorded
/// that a plane should ignore retractions; it read as compatibility, and
/// compatibility with an unexamined default is not a policy.
///
/// So the flag is **gone** rather than flipped. Both retraction gates now run
/// on every walk, unconditionally, and there is no way to spell a walk that
/// skips them — which is the point: a flag that only ever had one correct
/// value is a way for the wrong value to come back.
#[derive(Debug, Clone, Copy)]
struct DelegationWalkPolicy {
    /// Enforce `child.scope ⊆ parent.scope` along the chain AND require
    /// `sub_delegation` on the parent edge before traversing past depth 1.
    enforce_attenuation_and_sub_delegation: bool,
}

impl DelegationWalkPolicy {
    /// Consent_revocation proxy reachability (CEG §3.2.3 rules 3 / 4).
    const CONSENT_REVOCATION: Self = Self {
        enforce_attenuation_and_sub_delegation: false,
    };
    /// The §11.10 moderation-duty walk — attenuation + sub_delegation.
    const MODERATION_DUTY: Self = Self {
        enforce_attenuation_and_sub_delegation: true,
    };
}

/// (CIRISPersist#593) — the **admitted-retraction fold**: which
/// `attestation_id`s does this row slice retract by NAME?
///
/// One predicate, one impl (the standing rule). A `withdraws` / `recants` that
/// carries `references_attestation_id` names the exact edge it kills; that is
/// the shape CEG §3.2.3 rules 2/3/4 produce (subject self-revocation, a
/// canonical-bound claimant, a consent-revocation proxy) and it is the shape
/// the GRANTER-scoped fold structurally cannot see — the granter never issued
/// it, so it is not among the granter's out-rows.
///
/// Deliberately takes a row SLICE rather than doing its own read.
/// [`live_delegation_granters`] already holds `subject`'s incoming rows; the
/// scoped-delegation BFS memoizes one read per distinct recipient. Extracting
/// the FOLD and not the READ is what lets both planes share one definition of
/// "retracted by name" without either inheriting the other's access pattern.
fn retracted_edge_ids(rows: &[super::Attestation]) -> std::collections::HashSet<String> {
    rows.iter()
        .filter(|g| {
            g.attestation_type == attestation_type::WITHDRAWS
                || g.attestation_type == attestation_type::RECANTS
        })
        .filter_map(|g| {
            crate::federation::precedence::references_attestation_id_from_envelope(
                &g.attestation_envelope,
            )
            .map(str::to_owned)
        })
        .collect()
}

/// (CIRISPersist#593) — everything the ONE scoped-delegation BFS observes.
///
/// The three former copies of that BFS each needed a different projection of
/// the same walk: a `bool` (did we reach a target?), a set (which keys did we
/// reach?), and a classified refusal. They are all here, so the walk can be
/// written once.
#[derive(Debug, Default)]
struct ScopedReach {
    /// Every recipient of a traversable edge — the enumerating projection.
    /// Truncated when the walk short-circuits on `hit_target`, which is sound
    /// because the only caller that reads it passes an EMPTY `targets` and so
    /// never short-circuits.
    ///
    /// Filled on every walk, including the two that discard it. It ranges over
    /// the same key space as the `visited` cycle-guard the walk already
    /// allocates, so recording it costs at most one more set of that size —
    /// never a second traversal.
    reached: std::collections::HashSet<String>,
    /// Did a traversable edge land on a key in `targets`?
    hit_target: bool,
    /// Did the issuer emit ANY `delegates_to` at all (pre-gate)?
    issuer_emitted_delegation: bool,
    /// Was an edge TO a target skipped because it is retracted — by its
    /// granter, or by an admitted `withdraws` naming it?
    target_edge_retracted: bool,
    /// Was an edge TO a target skipped because it does not carry `scope_token`?
    target_edge_missing_scope: bool,
}

/// **THE §11.10 scoped-`delegates_to` walk — one BFS, three callers**
/// (CIRISPersist#593).
///
/// Does a `delegates_to` chain from `issuer` reach a key in `targets` where
/// every edge on the path carries `scope_token`, under `policy`? And, in the
/// same pass, which keys does it reach and — when it does not reach a target —
/// why not?
///
/// # Why one body and not three
///
/// This BFS used to exist three times: as
/// [`issuer_reaches_target_via_scoped_delegation`] (the predicate), as
/// [`reachable_under_scope_with_reasons`] (the classified refusal) and as
/// [`enumerate_scoped_delegation_reach`] (the enumeration). admission.rs states
/// in prose, at five sites, that they agree:
///
///   1. `reachable_under_scope_with_reasons` returns `Reachable` "in exactly
///      the cases the `bool` form returns `true`";
///   2. `enumerate_scoped_delegation_reach` is the "identical BFS to the
///      predicate … so the two never diverge on reachability";
///   3. [`reachable_under_scope`] is a "thin wrapper … no change to the
///      attenuation/depth/withdraws semantics";
///   4. **`is_named_moderator(k, …)` ⟺ `k ∈ moderators_of(…)`** "because both
///      compose … the SAME scoped-reach walk" — and they did not: the predicate
///      composed copy 1, the enumerator copy 3;
///   5. [`appointed_moderators_of`] — "one reachability predicate, two root
///      sets — never two walks that could drift".
///
/// Not one of those five is checked by the build. Repairing the #593 fold at
/// one copy and not the others would have made every one of them FALSE while
/// the tree stayed green — the same reason CIRISPersist#584 extracted
/// [`live_delegation_granters`] before repairing it. Now they hold
/// structurally: same body, same gates, same order.
///
/// # The short-circuit is preserved, not traded away
///
/// The predicate returns at the FIRST edge into `targets`. So does this. The
/// enumerating caller gets a full walk out of the same body by passing an
/// **empty** `targets`, which no edge can ever be in — so `hit_target` never
/// fires and the walk runs to exhaustion. (#584 had to give its up-walk's
/// short-circuit away to make its four readers agree; this one does not.)
///
/// # The retraction gates — two of them, reading two different row sets
///
/// An edge is skipped — on EVERY walk, unconditionally since
/// CIRISPersist#594 — when EITHER:
///
///   * its granter retracted it — a `withdraws`/`recants` among the granter's
///     OUTGOING rows naming the recipient (the §11.10 edge-retraction model,
///     which carries no `references_attestation_id`); OR
///   * **(CIRISPersist#593)** an admitted `withdraws`/`recants` among the
///     RECIPIENT's incoming rows names this edge by
///     `references_attestation_id` — CEG §3.2.3 rules 2/3/4, which the granter
///     by definition never issued.
///
/// The second clause is the whole point of the #593 cut: without it a
/// subject-revoked `delegates_to` kept conferring `moderate` / `takedown` /
/// `review`. The two clauses read DIFFERENT rows, so neither subsumes the
/// other and neither may be deleted as redundant.
///
/// Neither clause re-litigates AUTHORITY. A stored `withdraws` already passed
/// [`check_withdraws_admission`], which is where CEG §3.2.3 rules 1-4 decided
/// whether its issuer had standing.
///
/// # Why the consent-revocation plane needed this too (CIRISPersist#594)
///
/// On that plane the delegation confers **rule-(3) proxy revocation
/// authority**: the right to file an admitted `withdraws` on behalf of a
/// subject who cannot hold a federation key — a Discord user-id, a
/// content-sha256-bound entity. Skipping the retraction gates there meant a
/// proxy whose delegation had been withdrawn *by its own granter* kept
/// speaking for exactly the party CC 1.13.2 names as least able to object.
///
/// Honouring retractions here raises a question the moderation plane does not
/// have, because rule-3 authority is **itself a revocation mechanism**: can a
/// proxy defend its own edge, or attack a rival's? It cannot, and the reason
/// is structural rather than a rule bolted on:
///
///   * the walk is DIRECTED, and a `delegates_to` names its RECIPIENT in
///     `subject_key_ids` — so retracting the edge that empowers you is
///     resignation, which is exactly what rule 2 is for;
///   * SIBLING proxies under one root never reach each other, so neither can
///     obtain rule-3 standing against the other's edge and become the sole
///     proxy for a subject who cannot object.
///
/// Both are pinned by the witness rather than left as reasoning, because the
/// sibling case is the one that would be a privilege escalation and it is
/// currently prevented by a topology property, not by a check.
///
/// # Reach — the honest bound
///
/// A retraction is visible only where the substrate INDEXES it: among the
/// recipient's INCOMING rows (`attested_key_id == recipient`) or the granter's
/// OUTGOING rows. A retraction filed against some third key entirely is
/// invisible to this walk — as it was to CIRISPersist#578 and #584. Widening
/// that means a per-granter fan-out read on every hop, which is a separate
/// decision with its own cost.
///
/// # Cost
///
/// One `list_attestations_by` per dequeued node (unchanged), plus one
/// `list_attestations_for` per DISTINCT recipient of an edge that survived the
/// type, scope, granter-retraction and `⊆`-attenuation gates. Memoized for the
/// whole walk, so a root with twenty `moderate` edges to one deputy costs ONE
/// extra read, and placed LAST so pruned edges pay nothing.
/// CIRISPersist#584's trick — skip the read when the granter is not
/// `user`-role — does NOT transfer: any recipient's incoming edge can be
/// revoked, so there is no analogous precondition. The bound is therefore
/// ≤ 2× the reads of the pre-#593 walk, never a per-edge fan-out.
///
/// CIRISPersist#594 extends that same bound to the consent-revocation plane,
/// which previously paid neither gate. Its walks are shallow (rule 3 probes a
/// subject set; `MAX_WITHDRAWS_DELEGATION_DEPTH` caps the chain), so the
/// absolute cost is small — but it is a real increase from 1× to ≤2×, and is
/// measured by the witness rather than asserted here.
async fn scoped_delegation_reach(
    directory: &dyn super::FederationDirectory,
    issuer: &str,
    targets: &std::collections::HashSet<String>,
    scope_token: &str,
    max_depth: usize,
    policy: DelegationWalkPolicy,
) -> Result<ScopedReach, Error> {
    use std::collections::{HashMap, HashSet, VecDeque};
    let mut out = ScopedReach::default();
    let effective_depth = max_depth.min(MAX_WITHDRAWS_DELEGATION_DEPTH);
    if effective_depth == 0 {
        return Ok(out);
    }
    // Per-node walk state. `parent_scope` is the scope-set of the edge that
    // reached `key` (the root `issuer` has `None` — no incoming edge);
    // `parent_sub_delegation` is whether that incoming edge granted
    // deputization. Under §11.10 (`enforce_attenuation_and_sub_delegation`)
    // these gate traversal; under consent_revocation they are inert.
    struct Node {
        key: String,
        depth: usize,
        parent_scope: Option<HashSet<String>>,
        parent_sub_delegation: bool,
        /// v30.8.0 (CIRISPersist#628) — hops this node's OWN chain may still
        /// run, granted by its incoming edge. `None` = no bound declared
        /// (legacy), so only the global rail applies.
        budget: Option<usize>,
    }
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<Node> = VecDeque::new();
    // Per-walk memo for the #593 clause: recipient key_id → the set of
    // attestation_ids retracted BY NAME among that recipient's incoming rows.
    // Keyed on the RECIPIENT, not the granter — the retraction is indexed
    // against the key the edge is about.
    let mut incoming_retracted: HashMap<String, HashSet<String>> = HashMap::new();
    queue.push_back(Node {
        key: issuer.to_owned(),
        depth: 0,
        parent_scope: None,
        parent_sub_delegation: false,
        // The root duty-holder holds the duty natively; no issuer bounded it.
        budget: None,
    });
    visited.insert(issuer.to_owned());

    while let Some(node) = queue.pop_front() {
        if node.depth >= effective_depth {
            continue;
        }
        // §11.10 deputization gate: a NON-root granter (one reached via an
        // incoming edge) may only further-delegate if that incoming edge
        // granted `sub_delegation`. The root duty-holder holds the duty
        // natively and is exempt (`parent_scope == None`).
        if policy.enforce_attenuation_and_sub_delegation
            && node.parent_scope.is_some()
            && !node.parent_sub_delegation
        {
            continue;
        }
        // v30.8.0 (CIRISPersist#628) — the granted budget is SPENT. This node
        // may still EXERCISE the duty (it was reached and counted) but may not
        // pass it on: its issuer said how far the chain could run and it has run
        // that far. Distinct from the guard above — that one is "you were never
        // deputized", this one is "you were, and the allowance is gone".
        if policy.enforce_attenuation_and_sub_delegation && node.budget == Some(0) {
            continue;
        }
        let rows = directory.list_attestations_by(&node.key).await?;
        // §11.10: bucket this granter's `withdraws`/`recants` retractions by
        // recipient so a revoked edge invalidates the downstream chain
        // (UCAN-style; topology's edge-retraction model). Unconditional since
        // CIRISPersist#594 — a granter's retraction of its own edge means the
        // same thing on every plane.
        let mut retracted: HashSet<String> = HashSet::new();
        for r in &rows {
            if r.attestation_type == attestation_type::WITHDRAWS
                || r.attestation_type == attestation_type::RECANTS
            {
                retracted.insert(r.attested_key_id.clone());
            }
        }
        let is_issuer = node.depth == 0;
        for r in rows {
            if r.attestation_type != attestation_type::DELEGATES_TO {
                continue;
            }
            if is_issuer {
                out.issuer_emitted_delegation = true;
            }
            let to_target = targets.contains(&r.attested_key_id);
            // Scope gate (first — a `consent_revocation`-only edge probed for
            // `takedown` is not traversable at all; the load-bearing
            // scope-isolation property).
            if !delegation_scope_grants(&r.attestation_envelope, scope_token) {
                if to_target {
                    out.target_edge_missing_scope = true;
                }
                continue;
            }
            // Retraction gate (a): the granter retracted its own edge.
            if retracted.contains(&r.attested_key_id) {
                if to_target {
                    out.target_edge_retracted = true;
                }
                continue;
            }
            // §11.10 `⊆`-parent attenuation: the child edge's scope-set must be
            // a subset of the parent edge's scope-set (restate-or-attenuate,
            // never expand). The root's first out-edge has no parent edge to
            // attenuate against. A pruned edge here is neither a clean
            // missing-scope nor a retraction — the duty simply cannot validly
            // flow down this path; it contributes only to a `SignerUnreached`.
            if policy.enforce_attenuation_and_sub_delegation {
                if let Some(parent_scope) = &node.parent_scope {
                    let child_scope = delegation_scope_set(&r.attestation_envelope);
                    if !child_scope.is_subset(parent_scope) {
                        continue;
                    }
                }
            }
            // Retraction gate (b) — THE CIRISPersist#593 CLAUSE. An admitted
            // `withdraws`/`recants` among the RECIPIENT's incoming rows that
            // names THIS edge kills it, whoever issued it. Placed LAST so only
            // edges that survived every cheaper gate pay a read, and memoized
            // per recipient so the fan-out is bounded by distinct recipients
            // rather than by edges.
            if !incoming_retracted.contains_key(&r.attested_key_id) {
                let incoming = directory.list_attestations_for(&r.attested_key_id).await?;
                incoming_retracted.insert(r.attested_key_id.clone(), retracted_edge_ids(&incoming));
            }
            if incoming_retracted[&r.attested_key_id].contains(&r.attestation_id) {
                if to_target {
                    out.target_edge_retracted = true;
                }
                continue;
            }
            // The edge is traversable. Record the recipient (the enumerating
            // projection) BEFORE the short-circuit, so the two never disagree
            // about what a reached key is.
            out.reached.insert(r.attested_key_id.clone());
            // A scope-bearing delegation edge to a target key is sufficient —
            // delegated duty established along the path.
            if to_target {
                out.hit_target = true;
                return Ok(out);
            }
            if !visited.contains(&r.attested_key_id) && node.depth + 1 < effective_depth {
                visited.insert(r.attested_key_id.clone());
                // v30.8.0 (CIRISPersist#628) — the budget ATTENUATES, exactly as
                // scope does: the child gets the smaller of what this edge
                // declares and what remains of the parent's allowance. Without
                // this the field is advisory — any holder could restore an
                // unbounded chain by declaring a bigger number than it was given.
                let declared = delegation_sub_delegation_depth(&r.attestation_envelope);
                let inherited = node.budget.map(|b| b.saturating_sub(1));
                let budget = match (declared, inherited) {
                    (Some(d), Some(i)) => Some(d.min(i)),
                    (Some(d), None) => Some(d),
                    (None, Some(i)) => Some(i),
                    (None, None) => None,
                };
                queue.push_back(Node {
                    key: r.attested_key_id,
                    depth: node.depth + 1,
                    parent_scope: Some(delegation_scope_set(&r.attestation_envelope)),
                    parent_sub_delegation: delegation_grants_sub_delegation(
                        &r.attestation_envelope,
                    ),
                    budget,
                });
            }
        }
    }
    Ok(out)
}

/// v6.4.0 (CIRISPersist#146 Ask 2, CEG §3.2.3) — does `issuer` reach
/// any key in `targets` via a `delegates_to` chain where **every edge
/// on the path carries `consent_revocation` scope**? This is the
/// reachability primitive behind rule 3 (chain to a canonical-hash
/// subject) and the proxy half of rule 4.
///
/// # Why a purpose-built walk (not [`build_delegation_graph`])
///
/// [`crate::federation::topology::build_delegation_graph`] walks ALL
/// `delegates_to` out-edges regardless of scope and flattens each
/// edge's scope to a single string for display. Proxy *revocation*
/// authority is narrower: the §3.2.3 contract requires the
/// `consent_revocation` scope to hold along the delegated path, so a
/// `delegates_to` granting only `retain`/`share` MUST NOT confer it.
/// We therefore re-use the BFS shape (queue + visited cycle-guard +
/// depth cap) but filter edges by scope-containment.
///
/// # Algorithm
///
/// BFS from `issuer`. At each granter, pull its `delegates_to`
/// out-edges via [`FederationDirectory::list_attestations_by`]; an
/// edge is *traversable* only if its envelope `scope ⊇
/// {consent_revocation}`. If a traversable edge's recipient is in
/// `targets`, return `true`. Cycle-guarded on the granter key and
/// bounded by [`MAX_WITHDRAWS_DELEGATION_DEPTH`].
async fn issuer_reaches_target_via_consent_revocation_delegation(
    directory: &dyn super::FederationDirectory,
    issuer: &str,
    targets: &std::collections::HashSet<String>,
    max_depth: usize,
) -> Result<bool, Error> {
    issuer_reaches_target_via_scoped_delegation(
        directory,
        issuer,
        targets,
        DELEGATION_SCOPE_CONSENT_REVOCATION,
        max_depth,
        DelegationWalkPolicy::CONSENT_REVOCATION,
    )
    .await
}

/// v8.7.0 (CIRISPersist#232, CEG §11.10 / §3.2.3 rule-(3)) — the
/// scope-parameterized generalization of
/// [`issuer_reaches_target_via_consent_revocation_delegation`]. Does
/// `issuer` reach any key in `targets` via a `delegates_to` chain where
/// **every edge on the path carries `scope_token`**?
///
/// This is the single reachability primitive behind ALL delegated-duty
/// admission: `consent_revocation` (the §3.2.3 proxy revocation half) AND
/// the §11.10 `moderate` / `takedown` / `review` duties. It re-uses the
/// `build_delegation_graph` BFS shape (queue + visited cycle-guard +
/// depth cap) but filters edges by scope-containment for the requested
/// `scope_token`, so a `delegates_to` granting only a DIFFERENT scope
/// (e.g. a `consent_revocation`-only edge probed for `takedown`) is NOT
/// traversable — this is the load-bearing scope-isolation property
/// (CIRISRegistry#90: "and only then"). Cycle-guarded on the granter key
/// and bounded by [`MAX_WITHDRAWS_DELEGATION_DEPTH`].
///
/// (CIRISPersist#593) A thin projection of [`scoped_delegation_reach`] — the
/// ONE body all three scoped-delegation walks share. It still returns at the
/// FIRST edge into `targets`; the short-circuit was preserved by the
/// extraction, not traded for it.
async fn issuer_reaches_target_via_scoped_delegation(
    directory: &dyn super::FederationDirectory,
    issuer: &str,
    targets: &std::collections::HashSet<String>,
    scope_token: &str,
    max_depth: usize,
    policy: DelegationWalkPolicy,
) -> Result<bool, Error> {
    Ok(
        scoped_delegation_reach(directory, issuer, targets, scope_token, max_depth, policy)
            .await?
            .hit_target,
    )
}

/// #249 Cut B — the **public** scoped-delegation reachability primitive
/// (CIRISPersist#249, the by-construction "#13 `reachable_under_scope`"
/// load-bearing walk). Does `issuer_key_id` reach `target_key_id` via a
/// `delegates_to` chain where **every edge carries `scope`** under the
/// §11.10 [`MODERATION_DUTY`] walk policy: `⊆`-parent attenuation +
/// `sub_delegation`-gated deputization past depth 1 + per-edge
/// `withdraws`/`recants` revocation + depth cap (`max_depth`, itself
/// clamped to [`MAX_WITHDRAWS_DELEGATION_DEPTH`]).
///
/// This is the general primitive every delegated-duty reader specializes:
/// [`moderators_of`] / [`is_named_moderator`] root it at a community
/// authority set, [`steward_bindings_of`] / [`steward_binding_chain`] read the
/// human anchor, and `duty_holders_*` compose it per target. It is a thin
/// `pub` wrapper over the private predicate walk
/// [`issuer_reaches_target_via_scoped_delegation`] with a singleton target
/// set and the `MODERATION_DUTY` policy — **no change** to the
/// attenuation/depth/withdraws semantics. A zero-hop `issuer == target` is
/// NOT a reach (no edge carries the scope to the self); callers wanting the
/// reflexive case test it separately (as `is_named_moderator` does for the
/// authority root).
///
/// [`MODERATION_DUTY`]: DelegationWalkPolicy::MODERATION_DUTY
pub async fn reachable_under_scope(
    directory: &dyn super::FederationDirectory,
    issuer_key_id: &str,
    target_key_id: &str,
    scope: &str,
    max_depth: usize,
) -> Result<bool, Error> {
    let target: std::collections::HashSet<String> =
        std::iter::once(target_key_id.to_owned()).collect();
    issuer_reaches_target_via_scoped_delegation(
        directory,
        issuer_key_id,
        &target,
        scope,
        max_depth,
        DelegationWalkPolicy::MODERATION_DUTY,
    )
    .await
}

/// v10.0.0 (CIRISPersist#272) — the typed verdict returned by
/// [`reachable_under_scope_with_reasons`]. Where
/// [`reachable_under_scope`] collapses every "no" into `false`, this
/// discriminates WHY, so a consumer (CIRISEdge's
/// `verify_self_at_login_delegation`) can route a distinct forensic
/// audit-trail entry per refusal reason instead of hand-rolling its own
/// scope-discriminating walk.
///
/// `#[non_exhaustive]` — future walk refinements may add reasons (or
/// attach payloads to the existing ones) without a further major bump.
///
/// `Serialize`/`Deserialize` (CIRISPersist#320) so the verdict rides
/// back across the ABI-stable directory dispatch capsule
/// ([`crate::ffi::directory_capsule`]) as the
/// `DirectoryOpResult::Reachability` payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ReachabilityVerdict {
    /// A `delegates_to` chain from the issuer reaches the target where
    /// every edge carries `scope` (§11.10 attenuation/deputization
    /// satisfied) and no edge on the path is withdrawn/recanted.
    Reachable,
    /// A scope-bearing `delegates_to` edge to the target exists, but it has
    /// been `withdraws`/`recants`-retracted (UCAN-style edge retraction).
    /// Named for the depth-1 login case where the issuer (root) retracts its
    /// own edge to the target.
    ///
    /// (CIRISPersist#593) It is NOT limited to that case, and it is no longer
    /// limited to a retraction the GRANTER issued: it also covers an admitted
    /// `withdraws`/`recants` among the target's incoming rows naming the edge
    /// by `references_attestation_id` — CEG §3.2.3 rules 2/3/4, which the
    /// granter by definition never issued. The name is historical; the verdict
    /// means *the edge to the target is retracted*, by whoever had standing.
    RetractedAtRoot,
    /// A `delegates_to` edge to the target exists but does NOT grant the
    /// required `scope`.
    MissingScope,
    /// The issuer emitted delegation edges, but none — after the scope,
    /// retraction, ⊆-attenuation, deputization, and depth gates — reach
    /// the target. The target was never established as a scoped delegate.
    SignerUnreached,
    /// A substrate read failed mid-walk. Unlike [`reachable_under_scope`]
    /// (which propagates substrate failures as `Err`), the with-reasons
    /// walk classifies them so the consumer's `match` over the verdict
    /// stays total and can emit an "unavailable" audit entry. This is the
    /// one contract difference between the two walks.
    SubstrateUnavailable,
    /// The issuer emitted no `delegates_to` edges at all — there is no
    /// trust root to seed the walk from.
    NoTrustRoots,
}

/// v10.0.0 (CIRISPersist#272) — the **refusal-reason** companion of
/// [`reachable_under_scope`]. Runs the identical §11.10
/// [`MODERATION_DUTY`] scope-bearing `delegates_to` walk (⊆-parent
/// attenuation + `sub_delegation`-gated deputization past depth 1 +
/// per-edge `withdraws`/`recants` skipping + depth cap), but returns a
/// typed [`ReachabilityVerdict`] instead of `bool`.
///
/// # Refusal precedence (when not [`Reachable`](ReachabilityVerdict::Reachable))
///
/// The walk records, across every edge-to-target it encounters, whether
/// that edge was *scope-bearing-but-retracted* or *present-but-unscoped*,
/// plus whether the issuer emitted any delegation at all. On a "no" it
/// returns the most specific signal, in order:
///
/// 1. [`RetractedAtRoot`](ReachabilityVerdict::RetractedAtRoot) — a
///    scope-bearing edge to the target was explicitly retracted.
/// 2. [`MissingScope`](ReachabilityVerdict::MissingScope) — an edge to
///    the target exists but does not carry `scope`.
/// 3. [`NoTrustRoots`](ReachabilityVerdict::NoTrustRoots) — the issuer
///    emitted no delegation edges whatsoever.
/// 4. [`SignerUnreached`](ReachabilityVerdict::SignerUnreached) — edges
///    exist but no scoped path reaches the target.
///
/// A substrate read failure short-circuits to
/// [`SubstrateUnavailable`](ReachabilityVerdict::SubstrateUnavailable).
///
/// The reachability decision is byte-identical to
/// [`reachable_under_scope`]: this returns
/// [`Reachable`](ReachabilityVerdict::Reachable) in exactly the cases the
/// `bool` form returns `true`. Only the classification of the "no" is new.
/// (CIRISPersist#593) That is now STRUCTURAL — both run
/// [`scoped_delegation_reach`], the one shared body — rather than a claim about
/// two hard-mirrored copies.
///
/// # NOT a diagnostic for the consent-revocation plane (CIRISPersist#594)
///
/// This walks under [`MODERATION_DUTY`], **always** — the policy is hard-coded
/// below, not a parameter. Passing
/// [`DELEGATION_SCOPE_CONSENT_REVOCATION`] as `scope` therefore does NOT
/// explain a rule-(3) proxy refusal: it answers under `⊆`-parent attenuation
/// and the `sub_delegation` deputization gate, neither of which the consent
/// plane applies. It can report `SignerUnreached` for a chain the consent walk
/// would happily traverse.
///
/// This matters more since CIRISPersist#594 made that plane honour retractions:
/// a proxy chain that used to work can now be refused, and the refusal arrives
/// as a bare [`Error::WithdrawsNotAdmitted`](super::Error::WithdrawsNotAdmitted)
/// carrying only `issuer` + `target_attestation_id`. So an operator cannot
/// currently distinguish *"the delegation was retracted — appoint a new proxy"*
/// from *"this issuer never had standing"*, and the obvious surface to reach
/// for is this one, which will mislead them.
///
/// Deliberately NOT fixed in #594: a classified consent-plane verdict is a new
/// public/FFI surface on the `deontic` tier, which is a separate cut with its
/// own stub and taxonomy obligations. Closing the authority hole should not
/// wait on it. Recorded here so the gap is a known one rather than a surprise.
///
/// [`MODERATION_DUTY`]: DelegationWalkPolicy::MODERATION_DUTY
pub async fn reachable_under_scope_with_reasons(
    directory: &dyn super::FederationDirectory,
    issuer_key_id: &str,
    target_key_id: &str,
    scope: &str,
    max_depth: usize,
) -> Result<ReachabilityVerdict, Error> {
    // A zero effective depth is `SignerUnreached`, NOT `NoTrustRoots` — the
    // walk never got far enough to learn whether the issuer emitted anything.
    // Kept explicit here because the shared walk cannot distinguish the two
    // from its (all-false) zero-depth result.
    if max_depth.min(MAX_WITHDRAWS_DELEGATION_DEPTH) == 0 {
        return Ok(ReachabilityVerdict::SignerUnreached);
    }
    let targets: std::collections::HashSet<String> =
        std::iter::once(target_key_id.to_owned()).collect();
    // (CIRISPersist#593) The SAME body the `bool` walk runs — which is what
    // makes the byte-identical claim above structural rather than aspirational.
    // A substrate read failure is the one contract difference: the predicate
    // propagates it, this classifies it.
    let reach = match scoped_delegation_reach(
        directory,
        issuer_key_id,
        &targets,
        scope,
        max_depth,
        DelegationWalkPolicy::MODERATION_DUTY,
    )
    .await
    {
        Ok(reach) => reach,
        Err(_) => return Ok(ReachabilityVerdict::SubstrateUnavailable),
    };
    if reach.hit_target {
        return Ok(ReachabilityVerdict::Reachable);
    }
    if reach.target_edge_retracted {
        return Ok(ReachabilityVerdict::RetractedAtRoot);
    }
    if reach.target_edge_missing_scope {
        return Ok(ReachabilityVerdict::MissingScope);
    }
    if !reach.issuer_emitted_delegation {
        return Ok(ReachabilityVerdict::NoTrustRoots);
    }
    Ok(ReachabilityVerdict::SignerUnreached)
}

/// #249 Cut B — the **enumeration** companion of
/// [`issuer_reaches_target_via_scoped_delegation`]. Where the predicate
/// answers "does `issuer` reach SOME target?", this collects EVERY key
/// `issuer` reaches via a `delegates_to` chain whose every edge carries
/// `scope_token`, under the same [`DelegationWalkPolicy`] (attenuation +
/// `sub_delegation`-gated deputization + withdrawn-edge skipping + depth
/// cap). The returned set EXCLUDES `issuer` itself (the caller adds the
/// steward-bound roots separately) — it is exactly the set of delegates the
/// `issuer` root empowers under `scope_token`.
///
/// Identical BFS to the predicate (same edge filters, same per-node
/// `parent_scope` / `parent_sub_delegation` walk state), so the two never
/// diverge on reachability — this one simply records the visited recipients
/// instead of short-circuiting on a target match.
///
/// (CIRISPersist#593) "Identical" is now literal: this is
/// [`scoped_delegation_reach`] with an **empty** `targets` set. No edge can be
/// in the empty set, so the shared short-circuit never fires and the walk runs
/// to exhaustion — full enumeration out of the very body the predicate uses.
async fn enumerate_scoped_delegation_reach(
    directory: &dyn super::FederationDirectory,
    issuer: &str,
    scope_token: &str,
    max_depth: usize,
    policy: DelegationWalkPolicy,
) -> Result<std::collections::HashSet<String>, Error> {
    Ok(scoped_delegation_reach(
        directory,
        issuer,
        &std::collections::HashSet::new(),
        scope_token,
        max_depth,
        policy,
    )
    .await?
    .reached)
}

/// v6.4.0 (CIRISPersist#146 Ask 2, CEG §3.2.3 / §8.1.11.2) — the
/// broadened `withdraws` admission gate. Resolves WHICH of the four
/// admission rules (if any) authorizes `issuer` to withdraw target
/// `T`, and returns that rule number for the per-row audit metadata
/// ([`Attestation::withdraws_admission_rule`]).
///
/// Pre-v6.4.0 the substrate admitted a `withdraws` from any
/// federation-trusted key (no producer/subject check beyond the
/// trust-threshold gate). CEG 0.6 §3.2.3 narrows + broadens that in
/// one move: a `withdraws` against `T` is admitted iff `issuer.key_id`
/// satisfies **any** of —
///
///   1. `issuer == T.attesting_key_id` (producer self-revocation; the
///      pre-CEG-0.6 shape, unchanged).
///   2. `issuer ∈ T.subject_key_ids` (subject self-revocation; NEW).
///      **v6.7.0 / CEG §5.6.8.14 widening:** ALSO satisfied when `issuer`
///      K holds an admitted `identity:canonical_binding` to a canonical
///      hash `H ∈ T.subject_key_ids` — the binding promotes the
///      canonical-hash subject to K's real key, so K inherits H's DIRECT
///      revocation authority (recorded as rule 2). This is the
///      never-rebound-canonical-subject closure: H acquires a real
///      revoker without H ever holding a key.
///   3. ∃ `delegates_to` chain `issuer →* H` where `H ∈
///      T.subject_key_ids` AND `scope ⊇ {consent_revocation}` (proxy
///      authority for canonical-hash subjects; NEW). Persist admits a
///      `delegates_to` edge to a canonical-hash `attested_key_id` (no FK),
///      so the BFS already reaches a canonical-hash subject directly; the
///      §5.6.8.14 binding is the *direct*-authority complement (rule 2)
///      for the case where the real key K, not a delegate, revokes.
///   4. `issuer` holds a valid `delegates_to` (consent_revocation
///      scope) → any key satisfying 1–3 (existing delegation as a new
///      admission path).
///
/// # §8.1.11.2 multi-subject independent authority
///
/// When `len(T.subject_key_ids) > 1`, each subject is an INDEPENDENT
/// revocation authority. The gate reflects this structurally: rule 2
/// is satisfied by membership in the *set* (`any` over
/// `subject_key_ids`), and rule 3 by reaching *any one* element of the
/// subject set. There is no quorum / majority softening — a single
/// subject's `withdraws` is admitted. The eviction semantics (any
/// admitted subject `withdraws` evicts the Contribution from
/// propagation) compose on the read side over the admitted rows.
///
/// # Rule ordering
///
/// Rules are checked cheapest-first (1, 2, then the delegation walks
/// 3, 4) and the FIRST satisfied rule's number is recorded. Rule 1/2
/// are field comparisons (no DB walk); 3/4 each cost a bounded BFS
/// over `delegates_to` edges (depth ≤
/// [`MAX_WITHDRAWS_DELEGATION_DEPTH`], cycle-guarded).
///
/// # Errors
///
/// - [`Error::WithdrawsNotAdmitted`] when none of the four rules hold
///   (stable `kind()` token `federation_withdraws_not_admitted`).
/// - [`Error::InvalidArgument`] when the `withdraws` envelope omits
///   the required `references_attestation_id`, or names a target that
///   does not exist (a `withdraws` against a non-existent `T` cannot
///   be authority-checked).
///
/// `target_id` is the `withdraws` envelope's `references_attestation_id`
/// (the attestation `T` being withdrawn).
pub async fn resolve_withdraws_admission_rule(
    directory: &dyn super::FederationDirectory,
    issuer: &str,
    target: &super::Attestation,
) -> Result<u8, Error> {
    // Rule 1 — producer self-revocation (no DB walk).
    if issuer == target.attesting_key_id {
        return Ok(1);
    }

    // v21.11.0 (CIRISPersist#528), RATIFIED at **CC 2.4.1.1** as the
    // anti-Goodhart retraction dual — for the scored families whose
    // SELF-EMISSION is banned (`capacity:*` /
    // `detection:*`: `attesting_key_id` MUST NOT equal `attested_key_id`), the
    // subject-derived revocation rules (2/3/4) are DENIED. The scored agent is
    // legitimately named in `subject_key_ids` (it is who the claim is about —
    // that field does real data-subject naming work the read path depends on),
    // but `subject_key_ids` must NOT ALSO be spent as revocation AUTHORITY here:
    // an agent that cannot score itself UP must not be able to score itself
    // UN-DOWN by retracting its own unflattering rows (which reaches the same
    // place by subtraction). The anti-Goodhart wall was enforced on assertion
    // and forgotten on retraction — this closes the dual. Rule 1 (the attester
    // who MADE the claim — the scorer / a canonical) still retracts/corrects;
    // only the subject-self path is cut. `subject_key_ids` carries
    // naming-but-not-revocation for these families (the manifest's rubric keeps
    // `data_subject` and `recipient_revoke` distinct precisely for this).
    //
    // **Ratification history — read this before touching the citation.**
    // v21.11.0 shipped this behaviour citing "CC 3.4.5 — the anti-Goodhart
    // DUAL". **No such rule existed at CC 3.4.5**, and CC 2.4.1.1 said the
    // substrate MUST admit under ANY of rules 1-4 with no carve-out. So for
    // four minor versions this gate refused writes the Constitution required
    // us to accept, on the authority of a clause nobody had written
    // (CIRISPersist#587). The behaviour was right and only the citation was
    // invented — but a comment asserting a rule that does not exist is how a
    // reader concludes a question is settled when it is open.
    //
    // CC has since ratified the dual **in the MUST sentence itself** at CC
    // 2.4.1.1, stated inline rather than by forward reference, and it is
    // admissible only because CC 4.5.5 simultaneously grants the subject
    // standing on `reconsideration:{grounds}` — contestation at zero
    // disclosure, where the subject files band-blind and a duty-holder who CAN
    // see the composition performs the valence-sensitive step. CC 4.5.5 says
    // so explicitly: "the withdraws path closes only because a real contest
    // path exists." **The two are one ruling.** If a future cut weakens the
    // `reconsideration:{grounds}` standing, this gate must be revisited in the
    // same change — otherwise it goes back to closing a door with nothing
    // behind it, which is what #587 actually objected to.
    let target_denies_subject_revocation = envelope_dimension(&target.attestation_envelope)
        .is_some_and(|d| d.starts_with("capacity:") || d.starts_with("detection:"));
    if target_denies_subject_revocation {
        return Err(Error::WithdrawsNotAdmitted {
            issuer: issuer.to_string(),
            target_attestation_id: target.attestation_id.clone(),
        });
    }

    // Rule 2 — subject self-revocation. §8.1.11.2: membership in the
    // subject SET, any single element suffices (no quorum).
    if target.subject_key_ids.iter().any(|s| s == issuer) {
        return Ok(2);
    }
    // Rule 2 (canonical-binding widening, CEG §5.6.8.14 / §4.2.2.2) —
    // `issuer` K holds an admitted `identity:canonical_binding` to a
    // canonical hash H that appears in `T.subject_key_ids`. The binding
    // promotes the canonical-hash subject to K's real key_id, so K
    // inherits H's DIRECT subject-revocation authority — rule 2. This is
    // what lets a real key revoke against a never-rebound canonical
    // subject it has since claimed. (Authorization that K==H is
    // consumer-policy; persist admits the binding and resolves authority
    // structurally — §5.6.8.14 normative-honesty clause.)
    if !target.subject_key_ids.is_empty() {
        let subjects: std::collections::HashSet<&str> =
            target.subject_key_ids.iter().map(String::as_str).collect();
        let bound = canonical_binding_hashes_for(directory, issuer).await?;
        if bound.iter().any(|h| subjects.contains(h.as_str())) {
            return Ok(2);
        }
    }
    // Rule 3 — proxy authority: a consent_revocation-scoped
    // `delegates_to` chain from `issuer` reaching ANY subject in
    // `T.subject_key_ids` (§8.1.11.2: any single subject is enough).
    if !target.subject_key_ids.is_empty() {
        let subjects: std::collections::HashSet<String> =
            target.subject_key_ids.iter().cloned().collect();
        if issuer_reaches_target_via_consent_revocation_delegation(
            directory,
            issuer,
            &subjects,
            MAX_WITHDRAWS_DELEGATION_DEPTH,
        )
        .await?
        {
            return Ok(3);
        }
    }
    // Rule 4 — `issuer` holds a valid consent_revocation-scoped
    // `delegates_to` reaching a key that itself satisfies rule 1
    // (the producer) or rule 2 (a subject). Rule 3 is already the
    // subject-set reach; rule 4 closes the producer case + the
    // "delegation to a subject who could self-revoke" case as an
    // explicit admission path. We reach the producer key OR any
    // subject key; reaching a subject collapses into rule 3's target
    // set, so rule 4 is the producer-reaching arm.
    {
        let mut rule4_targets: std::collections::HashSet<String> = std::collections::HashSet::new();
        rule4_targets.insert(target.attesting_key_id.clone());
        for s in &target.subject_key_ids {
            rule4_targets.insert(s.clone());
        }
        if issuer_reaches_target_via_consent_revocation_delegation(
            directory,
            issuer,
            &rule4_targets,
            MAX_WITHDRAWS_DELEGATION_DEPTH,
        )
        .await?
        {
            return Ok(4);
        }
    }
    Err(Error::WithdrawsNotAdmitted {
        issuer: issuer.to_string(),
        target_attestation_id: target.attestation_id.clone(),
    })
}

/// v6.4.0 (CIRISPersist#146 Ask 2) — the `put_attestation` entry point
/// for the broadened gate. A no-op (`Ok(None)`) for any
/// non-`withdraws` row; for a `withdraws` it loads target `T`
/// (referenced by the envelope's `references_attestation_id`), runs
/// [`resolve_withdraws_admission_rule`], and returns the admitting
/// rule number for the caller to stamp onto
/// [`Attestation::withdraws_admission_rule`].
///
/// Returns [`Error::WithdrawsNotAdmitted`] when target `T` IS locally
/// known but no rule authorizes the issuer.
///
/// # Deferred resolution — out-of-order federation delivery
///
/// Authority rules 1–4 all read fields of the target `T`
/// (`attesting_key_id` / `subject_key_ids`). When `T` is **not locally
/// present** — the common federation case where a `withdraws`
/// replicates before its target, or a malformed envelope omits
/// `references_attestation_id` — persist CANNOT authority-check the
/// revocation against a row it has not seen. Rather than reject (which
/// would break out-of-order replication and silently drop legitimate
/// subject revocations), the gate **admits the row with
/// `withdraws_admission_rule = None`** (the documented "unresolved /
/// pre-gate" sentinel on [`Attestation::withdraws_admission_rule`]).
/// Authority is then a read-side concern: composition recomputes the
/// rule once `T` is present (or treats an unresolved withdraws per the
/// consumer's policy). The 4-rule gate is fully enforced whenever `T`
/// IS local. **Design note flagged in the v6.4.0 cut report.**
///
/// # Scope — CONSENT-revocation withdraws ONLY (v6.4.0 regression fix)
///
/// CEG §3.2.3 broadens the authority basis for **consent**-revocation.
/// It is NOT the only authority basis for a `withdraws`. The substrate
/// emits `withdraws` on several SEPARATELY-authorized paths whose target
/// `T` is a `holds_bytes:sha256:*` **content-location directory entry**,
/// not a consent-bearing Contribution:
///
/// - **takedown** ([`crate::cirisnode::takedown_handler`]) — a
///   moderation/operator key (already authorized by the takedown path)
///   withdraws each holder's `holds_bytes` row.
/// - **Policy-J age-gate** — same handler, age-assurance composition.
/// - **`evict_actor` / sweeper** ([`crate::federation::blobs`],
///   `engine.rs`) — a host self-attests it no longer holds the bytes.
///
/// These are content-location retractions, not consent revocations;
/// their authority is established upstream of persist (the moderation
/// path / the host's own self-attestation). The consent gate would
/// wrongly reject a moderation key withdrawing a third-party holder's
/// `holds_bytes` row (issuer ≠ holder, no subjects, no delegation), so
/// the gate is **scoped to NON-`holds_bytes` targets**: a `withdraws`
/// whose target `T.attestation_type` begins with
/// [`crate::federation::blobs::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX`]
/// bypasses the consent rules entirely (`Ok(None)`). Genuine consent
/// withdraws target a consent-bearing Contribution (a `scores` /
/// content attestation that may carry `subject_key_ids`), never a
/// `holds_bytes` directory row — so the 4-rule gate still fully applies
/// to them.
pub async fn check_withdraws_admission(
    directory: &dyn super::FederationDirectory,
    row: &super::Attestation,
) -> Result<Option<u8>, Error> {
    if row.attestation_type != attestation_type::WITHDRAWS {
        return Ok(None);
    }
    let Some(target_id) = crate::federation::precedence::references_attestation_id_from_envelope(
        &row.attestation_envelope,
    ) else {
        // Malformed withdraws (no target ref) — unresolvable authority.
        return Ok(None);
    };
    let Some(target) = directory.get_attestation(target_id).await? else {
        // Target not locally present — defer authority to read side.
        return Ok(None);
    };
    // Scope discriminator: a `holds_bytes:sha256:*` target is a
    // content-location directory entry whose `withdraws` is emitted by a
    // separately-authorized moderation / host self-attestation path
    // (takedown / age-gate / evict_actor / sweeper). The §3.2.3 consent
    // gate does NOT apply — admit with rule `None` (the moderation path
    // owns its own authorization).
    if target
        .attestation_type
        .starts_with(crate::federation::blobs::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX)
    {
        return Ok(None);
    }
    // v25.x (CIRISPersist#578, CIRISConstitution rc3 CC 3.2) — **the recovery
    // gate, in BOTH directions.**
    //
    // rc3: *"A substrate MUST reject a rule-(2) or rule-(4) `withdraws`
    // targeting a live owner-binding unless it carries a `wa_adjudication_ref`
    // naming a CC 4.3 Wise-Authority quorum finding of abandonment or
    // seizure. Without this gate a compromised node key withdraws its own
    // owner and the single-owner invariant is worthless."*
    //
    // So the ceremony gate is consulted on BOTH branches below, and this is
    // the load-bearing half: rules 2/3/4 ADMIT such a `withdraws` today, and
    // the only reason that is not already a live self-liberation exploit is
    // that persist's own owner-bindings carry no `subject_key_ids`. rc3 says a
    // conformant binding MUST name K there — at which point rule 2 would hand
    // K's key the power to shed its owner unilaterally. Gating the admitting
    // branch closes that before the producer change lands, not after.
    match resolve_withdraws_admission_rule(directory, &row.attesting_key_id, &target).await {
        Ok(rule) => {
            // Rule 1 is the producer's own retraction and is never a reclaim.
            // Rules 2/3/4 against a LIVE owner-binding are exactly what rc3
            // gates.
            if matches!(rule, 2..=4) && is_owner_binding_envelope(&target.attestation_envelope) {
                if let Some(outcome) = run_recovery_ceremony_gate(directory, row, &target).await? {
                    return outcome.map(Some);
                }
            }
            Ok(Some(rule))
        }
        Err(err) => {
            // None of rules 1-4 gave this issuer authority over a LIVE
            // owner-binding — correct, and it MUST stay the default (a node
            // whose owner is merely quiet is not up for grabs). CC 3.2 also
            // forbids a PERMANENT ownerless lock, and the four-step ceremony
            // is the sanctioned exception: recorded as rule 5.
            match run_recovery_ceremony_gate(directory, row, &target).await? {
                Some(outcome) => outcome.map(Some),
                None => Err(err),
            }
        }
    }
}

/// v25.x (CIRISPersist#578) — run the CC 3.2 four-step recovery ceremony gate
/// against `row` (a `withdraws`) and `target` (its referenced attestation),
/// translating the typed [`ReclaimVerdict`](super::ownership_reclaim::ReclaimVerdict)
/// into the `withdraws`-admission shape.
///
/// `Ok(None)` means "not a reclaim candidate at all" — the caller's ordinary
/// rule stands. `Ok(Some(Ok(5)))` admits under the recovery rule.
/// `Ok(Some(Err(..)))` is a refusal that NAMES the failing ceremony step.
async fn run_recovery_ceremony_gate(
    directory: &dyn super::FederationDirectory,
    row: &super::Attestation,
    target: &super::Attestation,
) -> Result<Option<Result<u8, Error>>, Error> {
    let policy = super::ownership_reclaim::ReclaimPolicy::from_deployment_pin();
    match super::ownership_reclaim::check_ownership_reclaim_admission(
        directory,
        row,
        policy.as_ref(),
        chrono::Utc::now(),
    )
    .await?
    {
        super::ownership_reclaim::ReclaimVerdict::Admit { .. } => Ok(Some(Ok(
            super::ownership_reclaim::RECLAIM_WITHDRAWS_ADMISSION_RULE,
        ))),
        super::ownership_reclaim::ReclaimVerdict::Refused { reason, detail, .. } => {
            Ok(Some(Err(Error::OwnershipReclaimRefused {
                node_key_id: target.attested_key_id.clone(),
                owner_binding_id: target.attestation_id.clone(),
                reason,
                detail,
            })))
        }
        // Not a candidate (self-revocation by the incumbent, or a
        // non-owner-binding target) — the ordinary rule stands.
        super::ownership_reclaim::ReclaimVerdict::NotAReclaim => Ok(None),
    }
}

// ─── v8.7.1 — §11.10 FULL moderation enforcement (CEG RC24/RC25/RC26) ───
//
// v8.7.1 (CIRISPersist#233) REPLACES the v8.7.0 `on_behalf_of`-field model
// entirely. RC24 §11.10 pins the principal as the chain ROOT discovered by
// walking UP from `attesting_key_id` to an steward-bound scoped duty-holder —
// NOT a payload field. The v8.7.0 absent/empty/self ⇒ admit path WAS the
// bypass: CIRISServer#15 never emits `on_behalf_of` (not a spec field), so
// every emission hit the as-self admit path and the authority check never
// fired. The `on_behalf_of` const / `payload_on_behalf_of` /
// `check_delegated_duty_admission(.., on_behalf_of, ..)` shape is DELETED.
//
// New admission (per primitive `takedown_notice` / `moderation:*` /
// `reconsideration:*`): admit IFF
//   (a) as-self — `attesting_key_id ∈ duty_holders(target)`, OR
//   (b) delegated — ∃ `root ∈ duty_holders(target)` with a live
//       scope-bearing `delegates_to` chain `root →* attesting_key_id`
//       (every edge `scope ⊇ {duty}`, `⊆`-parent attenuation,
//       `sub_delegation`-gated deputization, depth ≤ 5, no `withdraws`-
//       revoked edge) AND `is_steward_bound(root)`.
//   else REJECT. Absence is NEVER an admit condition.

/// v8.7.0 (CIRISPersist#232, CEG §11.10) — reserved `scores` dimension
/// prefix for a **moderation** report attestation. A `scores` row on a
/// `moderation:*` dimension is the federation-attestation image of a
/// moderation report; its emission is gated by the [`moderate`]
/// delegated-duty scope.
///
/// [`moderate`]: DELEGATION_SCOPE_MODERATE
pub const MODERATION_DIMENSION_PREFIX: &str = "moderation:";

/// v8.7.0 (CIRISPersist#232, CEG §11.10) — reserved `scores` dimension
/// prefix for a **reconsideration / review** report attestation. A
/// `scores` row on a `reconsideration:*` dimension is the report→`scores`
/// path named by CIRISRegistry#90; its emission is gated by the
/// [`review`] delegated-duty scope.
///
/// [`review`]: DELEGATION_SCOPE_REVIEW
pub const RECONSIDERATION_DIMENSION_PREFIX: &str = "reconsideration:";

/// v25.1.0 (CIRISPersist#570 ask 2 + ask 5) — reserved `scores` dimension
/// prefix for a **quarantine marker** (see
/// [`quarantine`](crate::federation::quarantine) for the two dimensions and
/// the fold). A `scores` row under this prefix asserts *"withhold this key's
/// rows from serving"* / *"stop withholding them"*; its emission is gated by
/// the [`slash`] delegated-duty scope.
///
/// This prefix is the reason [`DELEGATION_SCOPE_SLASH`] is load-bearing rather
/// than declarative: it is the third arm of the dimension→duty map below.
///
/// [`slash`]: DELEGATION_SCOPE_SLASH
pub const QUARANTINE_DIMENSION_PREFIX: &str = "quarantine:";

/// v8.7.1 (CIRISPersist#233, CEG RC24 §11.10) — the §11.10 delegated-duty
/// depth bound (§13.3: depth ≤ 5). Distinct from the
/// [`MAX_WITHDRAWS_DELEGATION_DEPTH`] (16) used by the consent_revocation
/// proxy walk — moderation chains are short by spec. The walk's
/// `effective_depth` is `min(this, MAX_WITHDRAWS_DELEGATION_DEPTH)`, so a
/// chain longer than 5 cannot confer a moderation duty.
pub const MAX_MODERATION_DELEGATION_DEPTH: usize = 5;

/// v30.8.0 (CIRISPersist#596 item 1 / CIRISServer#383) — **revoking SOMEONE
/// ELSE'S key is a moderation act and needs moderation authority.**
///
/// # What was there before
///
/// `put_revocation`'s only gate was `check_federation`, which is a **trust-score
/// threshold** — it asks whether the revoker is trusted enough to write at all,
/// never whether it has any standing over the key it is revoking. So any
/// sufficiently-trusted key could revoke any other key in the mesh. That was
/// recorded as CIRISPersist#596 item 1 and deliberately deferred; a live
/// key-rotation drill (CIRISServer#383) turned it from backlog into the thing
/// standing between an operator and a clean slash.
///
/// # The split, and why it is exactly #620's
///
/// **Self-revocation is always allowed.** A holder must be able to retire its
/// own key — that is the whole remedy for a compromised one, and gating it
/// would mean a leaked key can only be retired by someone else, which is
/// backwards. This is the same attester-vs-attested discriminator the
/// `hard_case:` door uses (v30.5.0), for the same reason.
///
/// **Third-party revocation requires [`DELEGATION_SCOPE_SLASH`]** conferred by a
/// root THIS NODE trusts, re-derived at use through
/// [`super::trust_root::capability_roots_to_trusted_root`] — never a flag on the
/// row, never the revoker vouching for itself. `slash` is the scope the
/// substrate already documents as *"the authority to take something away"*, and
/// removing a key from the mesh is the sharpest form of that.
///
/// # Deliberately NOT gated here
///
/// The trust-score threshold stays where it is. It answers a different question
/// (may this peer write at all) and removing it would widen a different door
/// while narrowing this one.
pub async fn check_revocation_authority(
    directory: &dyn super::FederationDirectory,
    row: &super::Revocation,
) -> Result<(), Error> {
    // Self-revocation: always. See the doc above — this is the remedy path.
    if row.revoking_key_id == row.revoked_key_id {
        return Ok(());
    }
    // An unattributed revocation cannot be authorised against anything. The
    // existing `revoking_key_id.is_empty()` paths predate attribution and are
    // left alone rather than silently re-classified as self-revocation.
    if row.revoking_key_id.is_empty() {
        return Ok(());
    }
    let Some(node) = directory.node_key_id() else {
        return Err(Error::NodeIdentityUnset {
            method: "check_revocation_authority",
            needed_for: "resolving the revoker's slash conferral against this node's own trust \
                         root",
        });
    };
    let conferred = super::trust_root::capability_roots_to_trusted_root(
        directory,
        &node,
        &row.revoking_key_id,
        DELEGATION_SCOPE_SLASH,
    )
    .await?;
    if conferred.is_none() {
        return Err(Error::DelegatedScopeUnauthorized {
            signer: row.revoking_key_id.clone(),
            on_behalf_of: row.revoked_key_id.clone(),
            scope: DELEGATION_SCOPE_SLASH.to_owned(),
        });
    }
    Ok(())
}

/// Which incoming `delegates_to` edges [`live_delegation_granters`] admits.
/// The ONLY axis on which its four consumers differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DelegationEdgeFilter {
    /// Every `delegates_to` — the §11.10 steward-binding clause (3).
    AnyDelegation,
    /// Only CC 1.13.3.3 / CC 3.2 owner-binding edges
    /// ([`is_owner_binding_envelope`]) — the ownership projection.
    OwnerBindingOnly,
}

/// **THE live incoming-`delegates_to` walk — one predicate, one impl**
/// (CIRISPersist#584).
///
/// Returns the distinct `user`-role granters `U` of a **live**
/// `delegates_to(U → subject)`. "Live" is the conjunction of five clauses, and
/// the whole point of this function is that there is exactly one place where
/// that conjunction is written down:
///
///   1. the row is a `delegates_to` matching `filter`;
///   2. it has not been **retracted by anyone the write gate admitted** — an
///      admitted `withdraws`/`recants` among `subject`'s incoming rows whose
///      `references_attestation_id` names this edge;
///   3. it has not been retracted by its own **granter** (a
///      `withdraws`/`recants` among the granter's OUTGOING rows naming
///      `subject` — the §11.10 edge-retraction model, which carries no
///      `references_attestation_id`);
///   4. its `expires_at` has not passed (SecReview F3); and
///   5. its adult-incapacity `valid_until` has not lapsed (CC 3.4.12
///      fail-to-liberty — a no-op for every other row shape).
///
/// # Why clause (2) is here and not only in the ownership projection
///
/// v25.x (CIRISPersist#578) added clause (2) to the ownership walk alone,
/// because a CC 3.2 recovery `withdraws` is issued by the node K — never by
/// the incumbent — so the granter-scoped clause (3) could not see it. The same
/// blindness applied verbatim to the three STEWARD-binding walks
/// ([`is_steward_bound`], [`steward_bindings_of`], [`steward_binding_chain`]):
/// a `delegates_to` retracted under CEG §3.2.3 rule 2/3/4 — by its subject, by
/// a canonical-bound claimant, or by a consent-revocation proxy — kept
/// conferring stewardship (CIRISPersist#584).
///
/// Repairing that at ONE of those three sites is not an option: admission.rs
/// states the invariant `is_steward_bound(k) ⟺ !steward_bindings_of(k).is_empty()`
/// in prose (and the same for `steward_binding_chain`), and a per-site repair
/// makes it FALSE — one side says *bound*, the other returns *empty*. Hence
/// one walk, four thin callers. `nodes_stewarded_by` inherits it for free: it
/// is defined by re-asking [`steward_bindings_of`].
///
/// # What clause (2) does NOT re-litigate
///
/// Authority. A stored `withdraws` has already passed
/// [`check_withdraws_admission`] — which is where CEG §3.2.3 rules 1-4 and the
/// CC 3.2 recovery ceremony decided whether its issuer had standing. Reading it
/// back here and asking again would be a second, divergent copy of exactly the
/// gate this function exists to stop duplicating.
///
/// # Reach — the honest bound
///
/// Clause (2) sees a retraction only where the substrate already indexes it:
/// among `subject`'s INCOMING rows (`attested_key_id == subject`). A
/// third-party retraction filed against some other key entirely is invisible
/// to both clause (2) and clause (3) — and was equally invisible to #578. That
/// is a reach limit of the row index, not of this fold; widening it means a
/// per-granter fan-out read on every steward-binding check, which is a
/// separate decision with its own cost.
async fn live_delegation_granters(
    directory: &dyn super::FederationDirectory,
    subject: &str,
    filter: DelegationEdgeFilter,
) -> Result<std::collections::BTreeSet<String>, Error> {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // Per-walk memo: granter key_id → "is a live `user`-role anchor for
    // `subject`" (resolves + carries `user` + has not retracted against
    // `subject`). Bounds the granter-scoped reads by DISTINCT granters.
    let mut granter_live: std::collections::HashMap<String, bool> =
        std::collections::HashMap::new();
    let now = chrono::Utc::now();
    let rows = directory.list_attestations_for(subject).await?;

    // (2) — a binding withdrawn BY ANYONE the gate admitted is non-live, not
    // only one retracted by its own granter. Two lists that disagree about
    // what "live" means; one list now. (CIRISPersist#593 lifted the fold itself
    // into [`retracted_edge_ids`], which the scoped-delegation BFS shares — the
    // same defect, one plane over, so the same predicate.)
    let withdrawn = retracted_edge_ids(&rows);

    for r in rows {
        // (1) shape.
        if r.attestation_type != attestation_type::DELEGATES_TO {
            continue;
        }
        // Only OWNER-BINDING edges for the ownership projection — the internal
        // dimension OR the CC 2.4.1.2 `delegation_purpose: owner_binding`
        // marker (v13.3.0 #378). This is what keeps ownership single-valued
        // WITHOUT constraining act-on-behalf / hierarchy delegations (multi-
        // parent per CC 4.5.13). Must match `check_single_node_owner_admission`
        // exactly so the gate and the `owner_of` resolver agree on what an
        // owner-binding IS.
        if filter == DelegationEdgeFilter::OwnerBindingOnly
            && !is_owner_binding_envelope(&r.attestation_envelope)
        {
            continue;
        }
        // (2) admitted retraction naming this edge.
        if withdrawn.contains(r.attestation_id.as_str()) {
            continue;
        }
        // (4) expiry — a lapsed delegation is not live.
        if let Some(exp) = r.expires_at {
            if exp <= now {
                continue;
            }
        }
        // (5) fail-to-liberty (CC 3.4.12): a lapsed adult-incapacity
        // `valid_until` is not live; the adult auto-re-sovereigns. No-op for
        // minor rows.
        if delegation_valid_until_lapsed(&r.attestation_envelope, now) {
            continue;
        }
        // Already established live for this granter — the remaining checks are
        // granter-scoped, not edge-scoped, so a second edge from the same
        // human costs no reads.
        if out.contains(&r.attesting_key_id) {
            continue;
        }
        // The two granter-scoped reads are memoized per walk: several edges
        // from one human resolve its key + retraction history ONCE. That keeps
        // the fan-out bounded by DISTINCT granters rather than by edges, which
        // is what pays for `is_steward_bound` no longer short-circuiting on the
        // first live edge (it must now agree with the enumerating readers, and
        // agreement is the property CIRISPersist#584 is about).
        if let Some(live) = granter_live.get(r.attesting_key_id.as_str()) {
            if *live {
                out.insert(r.attesting_key_id);
            }
            continue;
        }
        // A non-`user` granter cannot steward.
        let is_user = directory
            .lookup_public_key(&r.attesting_key_id)
            .await?
            .is_some_and(|g| identity_type::set_contains(&g.identity_type, identity_type::USER));
        // (3) granter-scoped edge-retraction — the granter `withdraws`/
        // `recants` a delegation against this recipient. The retraction is one
        // of the granter's OUTGOING attestations whose `attested_key_id ==
        // subject`.
        let granter_retracted = is_user
            && directory
                .list_attestations_by(&r.attesting_key_id)
                .await?
                .into_iter()
                .any(|g| {
                    (g.attestation_type == attestation_type::WITHDRAWS
                        || g.attestation_type == attestation_type::RECANTS)
                        && g.attested_key_id == subject
                });
        let live = is_user && !granter_retracted;
        granter_live.insert(r.attesting_key_id.clone(), live);
        if live {
            out.insert(r.attesting_key_id);
        }
    }
    Ok(out)
}

/// v8.7.1 (CIRISPersist#233, CEG RC25/RC26 §5.6.8.10) — is key `k`
/// **steward-bound**? A moderation chain ROOT must terminate in a real human
/// (a `user`-role identity), never a free-floating agent/service key — the
/// §11.10 "takedown isn't a coup" anchor. True iff ANY of:
///
///   1. `k`'s OWN `federation_keys.identity_type` set ⊇ `{user}`
///      ([`identity_type::USER`]); OR
///   2. [`FederationDirectory::lookup_identity_for_occurrence`]`(k)`
///      resolves `k` to an identity whose key is `user`-role (k is a
///      device/occurrence of a human identity); OR
///   3. ∃ a **live** `delegates_to(U → k)` with `U` a `user`-role key (a
///      human delegated to k) — [`live_delegation_granters`], the ONE walk
///      that owns what "live" means: not retracted by the granter (the §11.10
///      edge-retraction model), not retracted by ANY admitted
///      `withdraws`/`recants` naming the edge (CEG §3.2.3 rules 1-4 /
///      CIRISPersist#584), not expired (SecReview F3), not adult-incapacity-
///      lapsed (CC 3.4.12). A revoked or lapsed edge confers no
///      steward-binding.
///
/// A key whose chain to a `user` identity cannot be shown is NOT
/// steward-bound and cannot root a moderation duty (fail-closed). Authority
/// that the `user`-role key genuinely is a human is consumer/registry
/// policy (§5.6.8.10 normative-honesty); persist resolves it structurally
/// over the `federation_keys` `identity_type` set + occurrence + delegation
/// graph that are already present.
pub async fn is_steward_bound(
    directory: &dyn super::FederationDirectory,
    k: &str,
) -> Result<bool, Error> {
    // v11.5.0 (CIRISPersist#306, CC 3.2 / CC 1.15.6) — minor-stewardship
    // liveness fix. A PROVEN minor user does NOT self-anchor via clauses
    // (1)/(2): a minor MUST rely on a LIVE adult-steward edge (clause 3), so
    // when that edge is withdrawn `is_steward_bound(minor)` fails secure
    // (false). An adult/unknown user (self-sovereign — its own steward) still
    // self-anchors. Node/agent keys are never `user`-role, so (1)/(2) never
    // fired for them regardless and this gate cannot change their result.
    let k_band = super::age::age_band(directory, k).await?;
    let k_self_anchors = k_band != super::age::AgeBand::Minor;
    // (1) k's own identity_type set contains `user`.
    if k_self_anchors {
        if let Some(rec) = directory.lookup_public_key(k).await? {
            if identity_type::set_contains(&rec.identity_type, identity_type::USER) {
                return Ok(true);
            }
        }
        // (2) k is an occurrence of a human identity — resolve the identity
        //     key and check ITS identity_type set for `user`.
        if let Some(occ) = directory.lookup_identity_for_occurrence(k).await? {
            if let Some(id_rec) = directory.lookup_public_key(&occ.identity_key_id).await? {
                if identity_type::set_contains(&id_rec.identity_type, identity_type::USER) {
                    return Ok(true);
                }
            }
        }
    }
    // (3) a LIVE `delegates_to(U → k)` with U user-role — resolved by the ONE
    //     live-delegation walk ([`live_delegation_granters`]), which owns every
    //     liveness clause (retraction by the granter OR by any admitted
    //     `withdraws` naming the edge, expiry, adult-incapacity lapse).
    Ok(
        !live_delegation_granters(directory, k, DelegationEdgeFilter::AnyDelegation)
            .await?
            .is_empty(),
    )
}

/// #249 Cut B — the **enumeration** of [`is_steward_bound`]: the `user`-role
/// key(s) that steward-bind `k` (who `k` is steward-bound TO). Collects every
/// human anchor across the same three clauses the predicate tests:
///
///   1. `k`'s OWN key is `user`-role → `k` steward-binds itself (`k` is in the
///      set); AND/OR
///   2. `k` is an occurrence of a `user`-role identity → that identity key;
///      AND/OR
///   3. each granter `U` of a **live** `delegates_to(U → k)` with `U`
///      `user`-role → `U`. Liveness is [`live_delegation_granters`]'s, not a
///      copy of it (CIRISPersist#584).
///
/// Consistency: `is_steward_bound(k)` ⟺ `!steward_bindings_of(k).is_empty()` —
/// the predicate returns true iff ANY clause holds, and this returns the
/// union of all satisfying anchors (deduped, sorted). An unbound `k` yields
/// the empty set. Clause (3) is now literally the same call in both, so the
/// biconditional cannot drift; the memory / sqlite / postgres legs of
/// `steward_liveness_test_support` assert it at every state transition.
pub async fn steward_bindings_of(
    directory: &dyn super::FederationDirectory,
    k: &str,
) -> Result<Vec<String>, Error> {
    let mut out: std::collections::HashSet<String> = std::collections::HashSet::new();
    // v11.5.0 (CIRISPersist#306) — mirror `is_steward_bound`'s minor gate so
    // the invariant `is_steward_bound(k) ⟺ !steward_bindings_of(k).is_empty()`
    // holds: a PROVEN minor user does NOT self-anchor (clauses 1/2 are
    // suppressed); it must be carried by a live adult-steward edge (clause 3).
    let k_self_anchors = super::age::age_band(directory, k).await? != super::age::AgeBand::Minor;
    if k_self_anchors {
        // (1) k's own key is user-role.
        if let Some(rec) = directory.lookup_public_key(k).await? {
            if identity_type::set_contains(&rec.identity_type, identity_type::USER) {
                out.insert(k.to_owned());
            }
        }
        // (2) k is an occurrence of a user-role identity.
        if let Some(occ) = directory.lookup_identity_for_occurrence(k).await? {
            if let Some(id_rec) = directory.lookup_public_key(&occ.identity_key_id).await? {
                if identity_type::set_contains(&id_rec.identity_type, identity_type::USER) {
                    out.insert(occ.identity_key_id);
                }
            }
        }
    }
    // (3) each user-role granter U of a LIVE delegates_to(U → k) — with the
    // filter chosen by **whether `k` has agency**.
    //
    // v30.8.0 (CIRISConstitution#87). CC 3.2 rc3's discriminator is consent
    // structure: an act the target must accept for itself cannot be custody of
    // the target. So the question is never "what does the edge look like" but
    // "can this target accept for itself?"
    //
    //  * **A node has no agency.** It cannot accept anything for itself, so a
    //    person's delegation to it IS custody — every such edge is a steward
    //    binding, marker or not. This is why node stewardship is a separate act
    //    from agent partnership: the two targets differ in agency, not in wire
    //    shape.
    //  * **A key that CAN accept for itself** (a person) is stewarded only by an
    //    explicit owner-binding — the CC 2.4.1.2 marker. An unmarked delegation
    //    to a person is a capability conferral: giving them a job, not owning
    //    them.
    //
    // An earlier draft of this narrowed BOTH cases to the marker, which dropped
    // real node-stewardship relations from deployed data — inverting what CC 3.2
    // protects. 26 tests caught it.
    //
    // PAIRED with `check_user_target_steward_binding_admission`, which fires only
    // on USER targets and now only on marker-bearing edges: the two halves agree
    // on "a person is stewarded only by an explicit custody claim", and neither
    // touches the node case.
    // ONE predicate, shared with `check_user_target_steward_binding_admission`.
    // A target that cannot accept for itself (a node, or a minor) is stewarded by
    // ANY delegation naming it; one that can is stewarded only where the envelope
    // declares custody.
    let filter = if can_accept_for_itself(directory, k).await? {
        DelegationEdgeFilter::OwnerBindingOnly
    } else {
        DelegationEdgeFilter::AnyDelegation
    };
    out.extend(live_delegation_granters(directory, k, filter).await?);
    let mut out: Vec<String> = out.into_iter().collect();
    out.sort();
    Ok(out)
}

/// CIRISPersist#299 — the **outbound** steward-binding projection: the nodes a
/// `user`-role key owns. The exact inverse of [`steward_bindings_of`]:
///
/// ```text
/// n ∈ nodes_stewarded_by(U)  ⟺  U ∈ steward_bindings_of(n)
/// ```
///
/// Consumers (CIRISServer's `auth::ownership::nodes_stewarded_by`, driving the
/// client node-switcher `GET /v1/setup/owned-nodes`) used to hand-roll this:
/// scan `U`'s outgoing `delegates_to` edges, then confirm each candidate back
/// through `steward_bindings_of` — re-deriving liveness/retraction/role
/// semantics at the consumer and missing the occurrence half. This folds it
/// into one substrate reader, with **read-after-write correctness owned where
/// the objects live**.
///
/// Implementation enumerates the candidate nodes `U` could steward-bind, then
/// **confirms each via [`steward_bindings_of`]** (the single source of truth) —
/// so the inverse property holds by construction and the
/// liveness/`withdraws`/`recants`-retraction/live-`user`-role-anchor logic is
/// inherited verbatim, never re-implemented. Candidates:
///
///   * **clause (3)** — `U`'s OUTGOING `delegates_to` edges → each recipient
///     (`list_attestations_by(U)`);
///   * **clause (2)** — occurrences that speak for identity `U`
///     (`list_identity_occurrences_for(U)`);
///   * **clause (1)** — `U` itself (so the invariant holds exactly: `U` is
///     returned iff `U` is `user`-role, i.e. `U` steward-binds itself). A
///     consumer wanting "nodes OTHER than me" filters `== U` — that's a
///     presentation choice, not substrate policy.
///
/// Returns the deduped, sorted set; empty when `U` owns nothing (or isn't a
/// live `user`-role anchor — `steward_bindings_of` fails each candidate closed).
pub async fn nodes_stewarded_by(
    directory: &dyn super::FederationDirectory,
    steward_user_key_id: &str,
) -> Result<Vec<String>, Error> {
    // Enumerate candidate nodes (cheap, indexed reads) — NOT a full scan.
    let mut candidates: std::collections::HashSet<String> = std::collections::HashSet::new();
    // (3) U's outgoing delegates_to edges → recipients.
    for r in directory.list_attestations_by(steward_user_key_id).await? {
        if r.attestation_type == attestation_type::DELEGATES_TO {
            candidates.insert(r.attested_key_id);
        }
    }
    // (2) occurrences speaking for identity U.
    for occ in directory
        .list_identity_occurrences_for(steward_user_key_id)
        .await?
    {
        candidates.insert(occ.occurrence_key_id);
    }
    // (1) U itself (exact-inverse: U owns U iff U is user-role).
    candidates.insert(steward_user_key_id.to_owned());

    // Confirm each candidate through steward_bindings_of — the inverse is exact
    // because membership is decided by the SAME predicate, never a re-derived
    // copy of its liveness/retraction/role rules.
    let mut out: Vec<String> = Vec::new();
    for cand in candidates {
        if steward_bindings_of(directory, &cand)
            .await?
            .iter()
            .any(|anchor| anchor == steward_user_key_id)
        {
            out.push(cand);
        }
    }
    out.sort();
    Ok(out)
}

/// The distinct set of **live owner-binding granters** of `node` — the users
/// `U` with a live `delegates_to(U → node)` carrying the CC 1.13.3.3 / CC 3.2
/// owner-binding dimension ([`super::types::owner_binding::DIMENSION`]). The raw
/// set behind [`owner_of`] + [`check_single_node_owner_admission`].
///
/// Exactly [`live_delegation_granters`] restricted to the ownership dimension —
/// not a parallel implementation of it. v25.x (CIRISPersist#578) wrote the
/// admitted-`withdraws` clause HERE, and CIRISPersist#584 found the same fold
/// unrepaired at the three steward-binding sites; the walk now lives in one
/// place, so `owner_of(node) ⊆ steward_bindings_of(node)` holds by construction
/// rather than by two functions being edited in step.
async fn live_owner_binding_granters(
    directory: &dyn super::FederationDirectory,
    node: &str,
) -> Result<std::collections::BTreeSet<String>, Error> {
    live_delegation_granters(directory, node, DelegationEdgeFilter::OwnerBindingOnly).await
}

/// **CIRISConstitution#23 (CC 1.13.3.3 / CC 3.2) — the single responsible owner
/// of `node`, or `None` when the node is unowned.** The dimension-precise
/// ownership projection (a subset of [`steward_bindings_of`] restricted to
/// owner-binding edges), and the reader consumers MUST use to resolve "the owner
/// of a node" for the `self` cohort boundary.
///
/// Returns [`Error::AmbiguousNodeOwner`] when the node carries **more than one**
/// distinct live owner — a pre-gate anomaly the single-owner admission gate
/// [`check_single_node_owner_admission`] prevents going forward. Consumers
/// (CIRISEdge's `SelfOnly` widening, CIRISServer's node switcher) MUST treat the
/// error as **fail-closed**: an ambiguous owner is not a resolvable `self`
/// boundary. NEVER silently pick one (unlike the historical
/// `is_steward_bound(..).next()` on a sorted set).
pub async fn owner_of(
    directory: &dyn super::FederationDirectory,
    node: &str,
) -> Result<Option<String>, Error> {
    let owners = live_owner_binding_granters(directory, node).await?;
    match owners.len() {
        0 => Ok(None),
        1 => Ok(owners.into_iter().next()),
        _ => Err(Error::AmbiguousNodeOwner {
            node_key_id: node.to_owned(),
            owners: owners.into_iter().collect(),
        }),
    }
}

/// **CIRISConstitution#23 (CC 1.13.3.3 / CC 3.2) — the single-owner admission
/// gate.** The node-target companion to [`check_node_agency_admission`]: a node
/// has **at most one** responsible steward (the `self` cohort boundary is
/// undefined otherwise). Rejects a `delegates_to(U → node)` owner-binding when
/// the node already carries a LIVE owner-binding from a DIFFERENT granter `U'`
/// ([`Error::NodeAlreadyOwned`]) — the incumbent must first `withdraws` /
/// `recants` it (or it must lapse). A refresh by the SAME owner is idempotently
/// admitted; a first owner is admitted.
///
/// Keyed on the versioned owner-binding dimension
/// ([`super::types::owner_binding::DIMENSION`]) so it constrains ONLY the
/// ownership relation; act-on-behalf / hierarchy `delegates_to` (multi-parent
/// per CC 4.5.13) are untouched. A no-op for any non-`delegates_to` row or any
/// `delegates_to` lacking the ownership dimension.
///
/// v24.0.0 (CIRISPersist#557) — **the attested subject must be something this
/// node already knows**: either a registered `federation_keys` row, or a
/// CONSTITUTIONAL FAMILY it has stored.
///
/// # What moved, and why this is not a loosening
///
/// **All three backends enforced this rule** and none could express the
/// exception: sqlite declared
/// `attested_key_id TEXT NOT NULL REFERENCES federation_keys(key_id)` (V004),
/// postgres declared the same FK (its V004 puts the `REFERENCES` clause on the
/// following line), and the memory backend emulated it in code.
///
/// The rule is right and is KEPT. What a schema FK cannot express is the one
/// legitimate exception: a constitutional family is **keyless by doctrine**
/// (v13.3.0 dropped `families.family_key_id`'s FK for exactly this reason — the
/// family id is an identifier, not a key, and having no seat is precisely what
/// makes it a durable name for a trust root). CIRISPersist#557's whole ask is
/// that a node's `trust:accepts` edge NAME THE ACCORD rather than whichever
/// holder happened to sign the charter — `delegates_to(node → humanity-accord)`,
/// plus that family's charter and drill rows. Under the FK those rows were not
/// merely unimplemented, they were **unstorable**.
///
/// So V114 lifts the constraint out of BOTH SQL schemas and into this predicate,
/// which runs at the same point in `put_attestation` on **memory, sqlite and
/// postgres**. Net effect: every backend keeps the rule and gains the exception,
/// and the rule now lives somewhere it can be read, tested and reasoned about
/// instead of in three separate places. One predicate, one impl.
///
/// The FKs on `attesting_key_id` and `scrub_key_id` are deliberately untouched:
/// those identify SIGNERS, and a signer with no key record could not have signed.
///
/// A backend that cannot answer the family question (the FFI directory capsule
/// reports [`Error::Unsupported`] for `lookup_family`) degrades to the
/// key-only rule — the pre-v24 behaviour — rather than guessing.
pub async fn check_attested_subject_admission<F>(
    directory: &F,
    attested_key_id: &str,
) -> Result<(), Error>
where
    F: super::FederationDirectory + ?Sized,
{
    if directory
        .lookup_public_key(attested_key_id)
        .await?
        .is_some()
    {
        return Ok(());
    }
    match directory.lookup_family(attested_key_id).await {
        Ok(Some(_)) => return Ok(()),
        Ok(None) => {}
        // Honestly unknown, never guessed — mirrors how `trust_root_valid`
        // treats a backend that cannot answer the halt question.
        Err(Error::Unsupported { .. }) => {}
        Err(e) => return Err(e),
    }
    Err(Error::InvalidArgument(format!(
        "attested_key_id {attested_key_id} resolves as neither a registered \
         federation_keys row nor a constitutional family known to this node"
    )))
}

/// Verify-before-mutation (AV-9): wired into every backend's `put_attestation`
/// immediately AFTER [`check_user_target_steward_binding_admission`], so a
/// rejected second-owner emission leaves no trace. Backend-agnostic.
pub async fn check_single_node_owner_admission(
    directory: &dyn super::FederationDirectory,
    row: &super::Attestation,
) -> Result<(), Error> {
    if row.attestation_type != attestation_type::DELEGATES_TO {
        return Ok(());
    }
    // v13.3.0 (#378): recognize the owner-binding by EITHER the internal
    // dimension OR the CC 2.4.1.2 `delegation_purpose: owner_binding` marker —
    // the raw `emit_attestation_self` path carries only the latter, and gating
    // on the dimension alone let it bypass the single-owner gate.
    if !is_owner_binding_envelope(&row.attestation_envelope) {
        return Ok(());
    }
    // The incoming row is NOT yet stored (this runs pre-insert), so every
    // granter here is a pre-existing incumbent. Any incumbent that is NOT the
    // attesting owner blocks admission — a node cannot accrue a second steward.
    let incumbents = live_owner_binding_granters(directory, &row.attested_key_id).await?;
    for incumbent in incumbents {
        if incumbent != row.attesting_key_id {
            return Err(Error::NodeAlreadyOwned {
                node_key_id: row.attested_key_id.clone(),
                incumbent_owner: incumbent,
                attempted_owner: row.attesting_key_id.clone(),
            });
        }
    }
    // v25.x (CIRISPersist#578, CC 3.2 ceremony step 4) — a node that has been
    // through a reclaim owes its OWN co-signature on the fresh owner-binding.
    // Hooked here so all three backends inherit it from one chokepoint.
    super::ownership_reclaim::check_post_reclaim_rebinding_admission(directory, row).await?;
    Ok(())
}

/// **CIRISPersist#372 (CC 3.4.7.1 set-membership) — the `canonical`-role
/// admission gate.** A `federation_keys` row may carry the
/// [`super::types::identity_type::CANONICAL`] role (founding / canonical
/// bootstrap server) in its `identity_type` **set** IFF the record is
/// **anchor-scrub-signed**: `scrub_key_id != key_id` AND `scrub_key_id`'s
/// Ed25519 pubkey ∈ the pinned HUMANITY_ACCORD anchor. That role is
/// accord-CONFERRED, never self-claimed — a node cannot bootstrap itself into
/// the founding set.
///
/// This wrapper pins the trusted anchor to the HUMANITY_ACCORD holder keyset
/// (A1/B1/C1) via
/// [`ciris_verify_core::accord_genesis::accord_holder_bootstrap_anchor`] — the
/// SAME terminus [`super::rooting::root_binding`] and
/// [`super::register::verify_key_registration`] verify against. Use
/// [`check_canonical_role_admission_over_roster`] to inject a different accord
/// roster (tests).
///
/// Behaviour:
/// - The row's `identity_type` set does NOT contain `canonical` → `Ok(())`
///   (no-op; the vast majority of rows).
/// - It contains `canonical` AND the record is anchor-scrub-signed → `Ok(())`.
/// - It contains `canonical` but the record is **self-signed**
///   (`scrub_key_id == key_id`), scrubbed by an **unknown** key, or scrubbed
///   by a key whose ed25519 is **not** in the anchor → refused with
///   [`Error::CanonicalRoleNotAccordConferred`] (fail-closed; the caller must
///   NOT store the row).
///
/// **Monotonicity.** Because this runs at every `federation_keys` write
/// chokepoint (`put_public_key` on both backends + memory, plus the
/// `adopt_scrub_upgrade` self→anchored path), `canonical` can never be added
/// by a later self-registration or by replication of a self-signed row: those
/// records are all self-signed (or non-anchor-scrubbed) and are refused here
/// before any INSERT/UPDATE. The only way `canonical` enters the directory is
/// an accord holder scrub-signing the node with the role (the Trust Root
/// add-canonical op). Verify-before-mutation (AV-9); backend-agnostic.
pub async fn check_canonical_role_admission(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
) -> Result<(), Error> {
    check_canonical_role_admission_over_roster(directory, row, &accord_holder_roster_key_ids())
        .await
}

/// [`check_canonical_role_admission`] with an explicit accord-holder roster
/// keyset — the core primitive. Production callers use the
/// [`check_canonical_role_admission`] wrapper (genesis A1/B1/C1 roster); this
/// form exists so tests can supply their own signable holders, mirroring
/// [`super::withdraw_canonical_role_over_roster`].
///
/// # v13.2.0 (CIRISPersist#383) — 2-of-3 multi-scrub add (the security crux)
///
/// The `canonical` role is conferred ONLY if the record carries **≥ a strict
/// majority of the live accord family, each a cryptographically VERIFIED
/// hybrid scrub signature** over the record's canonical `registration_envelope`
/// — the m-of-n add gate (2-of-3 today; 3-of-4 if the family grows). This
/// retires the v13.0.0 (#372) **1-of-N** add path, where a single anchor-scrub
/// (`scrub_key_id ∈ anchor`, membership only, no sig verified) conferred the
/// role — the ASI first-strike hole (one captured accord key mints a rogue
/// founding anchor). CC 3.4.7.1 / CIRISVerify#174.
///
/// The gate routes through verify-core's **`verify_quorum_policy`** — the SAME
/// m-of-n primitive `ciris-canonical` registry-consensus, the HUMANITY_ACCORD,
/// and every entrenched `quorum:M/N` community use — so the count is DYNAMIC
/// (strict-majority of the roster, never a frozen `2`), non-forgeable (each
/// hybrid sig is cryptographically verified; only DISTINCT founders count; a
/// forged / garbage scrub silently does not count), and deadlock-safe
/// (`2·M > N`, no `M==1` escape, declared `N` must equal the live founder
/// roster size).
///
/// Steps:
/// 1. Fast path — the row's `identity_type` set lacks `canonical` → `Ok(())`.
/// 2. **Withdrawal consult (revocation-wins, #377).** A `key_id` the accord
///    quorum WITHDREW (V095 tombstone) cannot be re-conferred `canonical`, EVEN
///    with a valid 2-of-3 scrub set — the add-gate is monotonic and the
///    anti-entropy path ([`apply_replicated_key_record`](super::register),
///    #375) re-runs it, so without this a peer still holding the old scrubbed
///    record would silently RE-ADD the role on the next round. A SUPERSEDE
///    successor (`superseded_by == this key_id`) is exempt.
/// 3. **Roster** — resolve `roster_key_ids` to their PINNED directory pubkeys
///    as `Founder`-role [`ThresholdMember`](ciris_verify_core::threshold::ThresholdMember)s
///    (skip any that don't resolve). `n = roster.len()`; never caller keys.
/// 4. **Policy** — strict majority over the LIVE roster,
///    [`QuorumPolicy::new`](ciris_verify_core::threshold::QuorumPolicy::new)`(n/2 + 1, n)`.
/// 5. **Signatures** — the record's full scrub set ([`KeyRecord::scrubs`], scrub
///    #1 + `additional_scrubs`) mapped to
///    [`ThresholdSignature`](ciris_verify_core::threshold::ThresholdSignature)s.
/// 6. **bytes** — `ceg_produce_canonicalize(registration_envelope)` (JCS RFC
///    8785), the IDENTICAL canonical form the single-scrub verify
///    ([`super::register::verify_key_registration`] / [`super::rooting`]) uses,
///    so the multi-scrub bytes line up with the base-field scrub.
/// 7. [`verify_quorum_policy`](ciris_verify_core::threshold::verify_quorum_policy)`(bytes,
///    &roster, &sigs, policy)` — `Ok` ⇒ confer; any
///    [`ThresholdError`](ciris_verify_core::threshold::ThresholdError) ⇒
///    [`Error::CanonicalRoleNotAccordConferred`] (fail-closed).
///
/// **Monotonicity.** This runs at every `federation_keys` write chokepoint
/// (`put_public_key` on all three backends + the `adopt_scrub_upgrade`
/// self→anchored path), so `canonical` can never be added by a later
/// self-registration or by replication of an under-quorum record. The only way
/// `canonical` enters the directory is a fully-assembled ≥2-of-3 accord co-scrub
/// (the Trust Root add-canonical op). `root_binding` is unchanged (still roots
/// via ANY one scrub — rooting is recognition, not conferral). Verify-before-
/// mutation (AV-9); backend-agnostic.
pub async fn check_canonical_role_admission_over_roster(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
    roster_key_ids: &[String],
) -> Result<(), Error> {
    // (1) Fast path: no `canonical` role on EITHER surface → nothing to gate.
    // #441: evaluated over identity_type ∪ roles — `roles=["canonical"]` is
    // the same claim as `identity_type="canonical"` and hits the same gate.
    if !row.claims_role(identity_type::CANONICAL) {
        return Ok(());
    }

    // (2) Revocation-wins (#377): a quorum-withdrawn key stays refused, even
    // with a valid 2-of-3 scrub set. Runs BEFORE the quorum verify. A SUPERSEDE
    // successor whose tombstone names THIS key_id is exempt (rotate-in).
    if let Some(w) = directory.lookup_canonical_withdrawal(&row.key_id).await? {
        if w.superseded_by.as_deref() != Some(row.key_id.as_str()) {
            return Err(Error::CanonicalRoleWithdrawn {
                key_id: row.key_id.clone(),
                superseded_by: w.superseded_by.clone(),
            });
        }
    }

    // (3)-(7) the shared accord-family m-of-n co-scrub quorum core.
    //
    // v21.3.0 (CIRISPersist#513) — the hardware anti-Sybil floor: a NEW
    // canonical requires `max(strict_majority, 3)` DISTINCT co-scrubbers,
    // each with a verified FIPS-140-3 Yubico custody attestation chained to
    // the pinned [`YUBICO_ATTESTATION_ROOT_1_DER`]. Minting a trust root is
    // thereby costly-but-possible: three hardware-bound, touch-required
    // humans — non-virtualizable. Two declared exemptions, both honest:
    //
    // - **The compiled-in genesis canonical** (grandfather): the baked
    //   ceremony record predates the floor with 2 scrubbers; it is matched
    //   BYTE-EXACT on (key_id, registration_envelope, base scrub signature)
    //   against OUR OWN embedded seed — an attacker cannot ride this
    //   exemption without presenting the exact already-trusted artifact.
    //   The NEXT canonical rotation meets the full floor (the gate runs at
    //   every write chokepoint, so a rotated-in successor is gated too).
    // - **The test anchor** (feature-gated + runtime-armed): its rosters
    //   are explicitly declared software keys; the floor would make every
    //   test-anchor mint impossible. Prod builds compile the override to
    //   const-false.
    let legacy = is_baked_genesis_canonical(row)
        || crate::federation::genesis::test_anchor_override_active();
    let verify_result = if legacy {
        verify_accord_family_coscrub(directory, row, roster_key_ids).await
    } else {
        verify_accord_family_coscrub_with(
            directory,
            row,
            roster_key_ids,
            CANONICAL_MIN_COSCRUBBERS,
            true,
            YUBICO_ATTESTATION_ROOT_1_DER,
        )
        .await
    };
    verify_result.map_err(|reason| Error::CanonicalRoleNotAccordConferred {
        key_id: row.key_id.clone(),
        scrub_key_id: row.scrub_key_id.clone(),
        reason,
    })
}

/// v21.4.0 (CIRISPersist#513 / CIRISVerify#219) — the STRICT canonical
/// gate with an INJECTED custody root: withdrawal-wins + the full #513
/// floor (`max(strict_majority, 3)` FIPS-verified co-scrubbers), verified
/// against `custody_root` instead of the pinned production Yubico root.
///
/// **The mesh-simulation surface.** CIRISVerify v10.6.2's
/// `accord_custody_attestation::test_support::MockYubicoCa` mints members
/// whose custody chains verify only against the mock CA's own root — pass
/// `ca.root_der()` here to exercise REAL floor semantics over fabricated
/// hardware. Gated `any(test, feature = "test-anchor")`: production builds
/// never expose a caller-supplied custody trust root (Registry-of-Record);
/// simulation harnesses (CIRISServer / CIRISAgent mesh sims) compile with
/// `test-anchor` — the same declared-test-context feature that arms the
/// software trust-root override.
#[cfg(any(test, feature = "test-anchor"))]
pub async fn check_canonical_role_admission_over_roster_with_custody_root(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
    roster_key_ids: &[String],
    custody_root: &[u8],
) -> Result<(), Error> {
    if !row.claims_role(identity_type::CANONICAL) {
        return Ok(());
    }
    if let Some(w) = directory.lookup_canonical_withdrawal(&row.key_id).await? {
        if w.superseded_by.as_deref() != Some(row.key_id.as_str()) {
            return Err(Error::CanonicalRoleWithdrawn {
                key_id: row.key_id.clone(),
                superseded_by: w.superseded_by.clone(),
            });
        }
    }
    verify_accord_family_coscrub_with(
        directory,
        row,
        roster_key_ids,
        CANONICAL_MIN_COSCRUBBERS,
        true,
        custody_root,
    )
    .await
    .map_err(|reason| Error::CanonicalRoleNotAccordConferred {
        key_id: row.key_id.clone(),
        scrub_key_id: row.scrub_key_id.clone(),
        reason,
    })
}

/// v21.3.0 (CIRISPersist#513) — the LEGACY (pre-floor) canonical admission
/// over an injected roster: withdrawal-wins + the strict-majority quorum
/// core WITHOUT the FIPS-custody floor. **Test-only** — the quorum-core
/// semantics surface (distinct-founder counting, self-scrub exclusion,
/// forged-scrub rejection, m-of-n arithmetic) for rosters of software test
/// identities, which by design can never carry a genuine Yubico custody
/// attestation. The production gate
/// ([`check_canonical_role_admission_over_roster`]) is strict; its floor is
/// exercised by the `*_513` witnesses and the run-the-real-artifact boot
/// tests (the grandfathered genesis canonical through the real gate).
#[cfg(test)]
pub(crate) async fn check_canonical_role_admission_over_roster_legacy(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
    roster_key_ids: &[String],
) -> Result<(), Error> {
    if !row.claims_role(identity_type::CANONICAL) {
        return Ok(());
    }
    if let Some(w) = directory.lookup_canonical_withdrawal(&row.key_id).await? {
        if w.superseded_by.as_deref() != Some(row.key_id.as_str()) {
            return Err(Error::CanonicalRoleWithdrawn {
                key_id: row.key_id.clone(),
                superseded_by: w.superseded_by.clone(),
            });
        }
    }
    verify_accord_family_coscrub(directory, row, roster_key_ids)
        .await
        .map_err(|reason| Error::CanonicalRoleNotAccordConferred {
            key_id: row.key_id.clone(),
            scrub_key_id: row.scrub_key_id.clone(),
            reason,
        })
}

/// v21.3.0 (CIRISPersist#513) — does `row` belong to the compiled-in
/// genesis canonical LINEAGE (same `key_id` as an embedded
/// `canonical_seed.json` record)?
///
/// #513 is a Sybil floor on trust-root **minting** — scarcity for NEW
/// roots. The genesis lineage id predates the floor (its real history
/// includes 2-scrub artifacts: the pre-ceremony anchor, the re-blessed
/// v2 record), so records for THAT id keep exactly today's bar: the
/// legacy strict-majority accord quorum + withdrawal-wins — real A1/B1/C1
/// signatures, no regression, nothing an attacker gains that they don't
/// already need. Every NEW canonical `key_id` — including a rotation
/// successor, which is how an unattested root would otherwise launder in —
/// meets the full floor (this gate runs at every write chokepoint).
fn is_baked_genesis_canonical(row: &super::KeyRecord) -> bool {
    crate::federation::genesis::canonical_genesis_bundle()
        .serve_nodes
        .iter()
        .any(|baked| baked.record.key_id == row.key_id)
}

/// The accord-family **m-of-n co-scrub quorum core** — the shared enforcement
/// primitive behind the `canonical` ([`identity_type`]) and `infra:attest`
/// ([`super::types::roles`]) conferral gates. Both roles fold onto the SAME
/// ceremony (CIRISPersist#422, "same ceremony, different CEG object"), so the
/// quorum math lives in exactly ONE place and cannot drift between them.
///
/// Verifies the record's full scrub set ([`KeyRecord::scrubs`]) meets a **strict
/// majority of the LIVE accord roster** over `JCS(registration_envelope)`, via
/// verify-core's [`verify_quorum_policy`](ciris_verify_core::threshold::verify_quorum_policy)
/// — the SAME m-of-n primitive `ciris-canonical` registry-consensus, the
/// HUMANITY_ACCORD, and every entrenched `quorum:M/N` community use. The count
/// is DYNAMIC (strict-majority of the resolved roster, never a frozen `2`),
/// non-forgeable (each hybrid sig is cryptographically verified; only DISTINCT
/// founders count; a forged / garbage scrub silently does not count), and
/// deadlock-safe (`2·M > N`, no `M==1` escape, declared `N` == live founder
/// roster size).
///
/// Steps: (3) resolve `roster_key_ids` to their PINNED directory pubkeys as
/// `Founder` members (skip unresolvable; `n = roster.len()`, never caller keys);
/// (4) strict-majority policy `QuorumPolicy::new(n/2 + 1, n)`; (6) canonical
/// bytes `ceg_produce_canonicalize(registration_envelope)` (JCS RFC 8785, the
/// IDENTICAL form the single-scrub verify uses); (5) the scrub set →
/// threshold signatures (a self-scrub's `member_id` is not in the founder
/// roster, so it is silently not counted — self can never confer); (7)
/// `verify_quorum_policy`. Returns `Ok(())` iff quorum met, else the failure
/// reason (each caller maps it to its role-specific error variant).
// v30.3.0 (CIRISPersist#611) — `?Sized`-generic; see
// `has_accord_conferred_role_over_roster`. Source-compatible for `&dyn` callers.
async fn verify_accord_family_coscrub<F>(
    directory: &F,
    row: &super::KeyRecord,
    roster_key_ids: &[String],
) -> Result<(), String>
where
    F: super::FederationDirectory + ?Sized,
{
    verify_accord_family_coscrub_with(
        directory,
        row,
        roster_key_ids,
        0,
        false,
        YUBICO_ATTESTATION_ROOT_1_DER,
    )
    .await
}

/// v21.3.0 (CIRISPersist#513) — the PINNED durable accord-custody trust
/// anchor: **Yubico Attestation Root 1**
/// (`developers.yubico.com/PKI/yubico-ca-1.pem`, CN="Yubico Attestation
/// Root 1", DER) — byte-identical to CIRISServer's
/// `YUBICO_ATTESTATION_ROOT_1_DER` pin (one trust anchor across the
/// federation, drift caught by the sha256 pin witness). The durable ROOT is
/// pinned, never the rotating "Yubico PIV Attestation B 1" intermediate; the
/// f9 device cert + intermediates ride in each holder's custody-attestation
/// chain, which `verify_accord_custody_attestation` walks up to this anchor.
pub const YUBICO_ATTESTATION_ROOT_1_DER: &[u8] =
    include_bytes!("accord_pki/yubico_attestation_root_1.der");

/// v21.3.0 (CIRISPersist#513) — the canonical-admission hardware anti-Sybil
/// floor: a NEW canonical (trust root) requires at least this many DISTINCT
/// FIPS-custody-verified accord co-scrubbers, regardless of roster size
/// (`quorum = max(strict_majority, 3)`). Scoped to canonicals ONLY — never
/// ordinary node/agent admission.
pub const CANONICAL_MIN_COSCRUBBERS: usize = 3;

/// v21.3.0 (CIRISPersist#513) — verify one accord member's **FIPS-140-3
/// Yubico custody attestation**, the per-member half of the canonical
/// anti-Sybil floor.
///
/// The member's `KeyRecord.attestation_evidence` must deserialize as the
/// signed custody-attestation CEG object
/// ([`ciris_verify_core::accord_custody_attestation::ACCORD_CUSTODY_ATTESTATION_KIND`],
/// the sibling artifact the accord ceremony produces), and
/// [`verify_accord_custody_attestation`](ciris_verify_core::accord_custody_attestation::verify_accord_custody_attestation)
/// must confirm: the bundle is holder-authored (bound-hybrid against the
/// member's PINNED directory pubkeys), the 9c cert chains to the pinned
/// [`YUBICO_ATTESTATION_ROOT_1_DER`] (every link a real signature verify),
/// the attested key IS the member's federation Ed25519 key, and the Yubico
/// extensions mark **FIPS-certified + touch=always**. Fail-closed: absent/
/// malformed/unverifiable evidence ⇒ `Err` ⇒ the member does not count.
///
/// # The authority is #513, not a sibling's behaviour (corrected #568)
///
/// This note used to end *"— the same predicate CIRISServer's holder-admission
/// gate applies."* That is a claim about a repo persist does not compile, it
/// was never checked by anything here, and nothing would fail if it stopped
/// being true — the exact shape #545/#554 turned into a live ceremony and the
/// shape [`super::hardware_attestation`]'s custody note was rewritten to
/// remove. Deleted rather than re-verified: **the floor is persist's own**
/// (CIRISPersist#513), the pinned root is persist's own
/// ([`YUBICO_ATTESTATION_ROOT_1_DER`]), and the walk runs here. Whether a
/// sibling happens to agree is not this gate's warrant.
///
/// Noted under CIRISPersist#568's classification sweep: the two booleans
/// gated here are verify **measurements** of a certificate's extensions, and
/// the decision to refuse on them is persist's. `ciris-keyring` /
/// `accord_custody_attestation` ship no
/// [`Classification`] impl, so [`standing_of`] cannot be asked about them —
/// the discipline is held by this comment, which is strictly weaker than the
/// typed answer `ConsentDisposition` now gives.
///
/// **Honest scope (encode, don't paper over — #513):** the FIPS attestation
/// covers the **Ed25519 (classical) half** of the hybrid identity; the
/// ML-DSA-65 half is software sealed-media custody the harness does not
/// check. This is a Sybil/identity anchor on the classical key — it does
/// not imply PQ hardware custody. Pre-rotation successors are NOT verified
/// here against their commitments (hashes reveal nothing to attest); they
/// are gated at ROTATION time instead — this gate runs at every
/// `federation_keys` write chokepoint, so a rotated-in successor passes the
/// same floor before it can carry `canonical`.
pub fn verify_member_fips_custody(
    rec: &super::KeyRecord,
) -> Result<ciris_verify_core::accord_custody_attestation::CustodyVerdict, String> {
    verify_member_fips_custody_against(rec, YUBICO_ATTESTATION_ROOT_1_DER)
}

/// The root-parameterized core of [`verify_member_fips_custody`] — the
/// attestation-verify surface downstream composes for MESH SIMULATION
/// (CIRISVerify v10.6.2 `test_support::MockYubicoCa` mints members whose
/// chains verify only against the mock CA's own root; pass `ca.root_der()`
/// here). Production gates use the pinned wrapper above — a caller-supplied
/// custody root never reaches the admission path (Registry-of-Record).
pub fn verify_member_fips_custody_against(
    rec: &super::KeyRecord,
    yubico_root_der: &[u8],
) -> Result<ciris_verify_core::accord_custody_attestation::CustodyVerdict, String> {
    use ciris_verify_core::accord_custody_attestation::verify_accord_custody_attestation;
    use ciris_verify_core::ceg_outbox::SignedCegObject;
    use ciris_verify_core::threshold::{Role, ThresholdMember};

    let ev = rec
        .attestation_evidence
        .as_ref()
        .ok_or_else(|| "no attestation_evidence on the record".to_string())?;
    let obj: SignedCegObject = serde_json::from_value(ev.clone()).map_err(|e| {
        format!("attestation_evidence is not a signed custody-attestation object: {e}")
    })?;
    let member = ThresholdMember {
        member_id: rec.key_id.clone(),
        ed25519_public_key_base64: rec.pubkey_ed25519_base64.clone(),
        mldsa65_public_key_base64: rec.pubkey_ml_dsa_65_base64.clone(),
        role: Some(Role::Founder),
    };
    let verdict = verify_accord_custody_attestation(&obj, &member, yubico_root_der)
        .map_err(|e| format!("custody attestation verify failed: {e}"))?;
    if !verdict.fips_certified {
        return Err("custody attestation is not FIPS-certified (Yubico ext …3.10 absent)".into());
    }
    if !verdict.touch_always {
        return Err("custody attestation touch policy is not 'always' (Yubico ext …3.8)".into());
    }
    Ok(verdict)
}

/// The parameterized body of [`verify_accord_family_coscrub`].
///
/// v21.3.0 (CIRISPersist#513) — two strictness knobs, BOTH engaged only by
/// the canonical gate (`min_quorum = `[`CANONICAL_MIN_COSCRUBBERS`]`,
/// require_fips_custody = true`); every other caller (infra:attest, the
/// supersede-tombstone probe) passes `(0, false)` = the legacy
/// strict-majority behavior, unchanged:
///
/// - `require_fips_custody` — a roster member counts toward `n` ONLY with a
///   verified FIPS-140-3 Yubico custody attestation
///   ([`verify_member_fips_custody`]). Fail-closed: an unattested member
///   silently doesn't count (recorded in the error on quorum failure).
/// - `min_quorum` — `m = max(n/2 + 1, min_quorum)`; when `m > n` the quorum
///   is honestly unreachable and the verify fails with the full accounting.
// v30.3.0 (CIRISPersist#611) — `?Sized`-generic; see
// `has_accord_conferred_role_over_roster`. Source-compatible for `&dyn` callers.
async fn verify_accord_family_coscrub_with<F>(
    directory: &F,
    row: &super::KeyRecord,
    roster_key_ids: &[String],
    min_quorum: usize,
    require_fips_custody: bool,
    custody_root: &[u8],
) -> Result<(), String>
where
    F: super::FederationDirectory + ?Sized,
{
    use ciris_verify_core::threshold::{
        verify_quorum_policy, QuorumPolicy, Role, ThresholdMember, ThresholdSignature,
    };

    // (3) Standing founder roster = the accord family resolved to their PINNED
    // directory pubkeys (never caller-supplied keys). Skip any that don't
    // resolve; `n` tracks the LIVE roster so the policy is dynamic.
    // #513: under `require_fips_custody`, membership additionally requires a
    // verified FIPS custody attestation — the hardware anti-Sybil floor.
    let mut roster: Vec<ThresholdMember> = Vec::with_capacity(roster_key_ids.len());
    let mut custody_rejected: Vec<String> = Vec::new();
    for kid in roster_key_ids {
        if let Some(rec) = directory
            .lookup_public_key(kid)
            .await
            .map_err(|e| format!("roster resolve failed for {kid}: {e}"))?
        {
            if require_fips_custody {
                if let Err(why) = verify_member_fips_custody_against(&rec, custody_root) {
                    custody_rejected.push(format!("{kid}: {why}"));
                    continue;
                }
            }
            roster.push(ThresholdMember {
                member_id: rec.key_id,
                ed25519_public_key_base64: rec.pubkey_ed25519_base64,
                mldsa65_public_key_base64: rec.pubkey_ml_dsa_65_base64,
                role: Some(Role::Founder),
            });
        }
    }
    let n = roster.len();

    // (4) Strict-majority policy over the live roster (2-of-3 today; 3-of-4 if
    // the family grows), floored at `min_quorum` (#513: 3 for canonicals — a
    // hardware-bound, touch-required, distinct-human scarcity mechanism).
    // `verify_quorum_policy` re-validates `2·M > N` and `N == founder_count`,
    // so this is NOT a frozen constant.
    let m = std::cmp::max(n / 2 + 1, min_quorum);
    if m > n {
        return Err(format!(
            "accord quorum unreachable: floor {m} exceeds the {n} qualifying roster \
             member(s){}",
            if custody_rejected.is_empty() {
                String::new()
            } else {
                format!(
                    " (FIPS-custody-rejected: [{}])",
                    custody_rejected.join("; ")
                )
            }
        ));
    }
    let policy = QuorumPolicy::new(m, n);

    // (6) The exact canonical bytes the scrubs signed = JCS(registration_envelope)
    // — the IDENTICAL function the single-scrub verify uses, so a base-field
    // scrub and an `additional_scrubs` entry are over byte-identical content.
    let bytes = crate::verify::canonical::ceg_produce_canonicalize(&row.registration_envelope)
        .map_err(|e| format!("registration_envelope canonicalize failed: {e}"))?;

    // (5) The record's full scrub set → threshold signatures (member_id =
    // scrub_key_id; a self-scrub's member_id is not in the founder roster, so it
    // is silently not counted — self can never confer).
    let sigs: Vec<ThresholdSignature> = row
        .scrubs()
        .into_iter()
        .map(|s| ThresholdSignature {
            member_id: s.scrub_key_id,
            ed25519_signature_base64: s.scrub_signature_classical,
            mldsa65_signature_base64: s.scrub_signature_pqc,
        })
        .collect();

    // (7) m-of-n over the accord family. Non-forgeable: verify_quorum_policy
    // cryptographically verifies each hybrid sig and counts ONLY distinct
    // founders — a claimed-but-unsigned / garbage scrub does not count.
    verify_quorum_policy(&bytes, &roster, &sigs, policy).map_err(|e| {
        format!(
            "accord family m-of-n not met ({m}-of-{n}): {e}",
            m = policy.m,
            n = policy.n
        )
    })?;

    Ok(())
}

/// **CIRISPersist#422 (CIRISVerify#185) — the `infra:attest`-role admission
/// gate.** The `roles`-vector mirror of [`check_canonical_role_admission`]: a
/// `federation_keys` row may carry [`super::types::roles::INFRA_ATTEST`] in its
/// V020 `roles` set IFF the record is accord-co-scrubbed to the family m-of-n —
/// the SAME ceremony that confers `canonical`, differing only in which CEG
/// object the role names (a build-signing / CI pipeline key vs a founding
/// server). Pins the trusted anchor to the HUMANITY_ACCORD holder keyset
/// (A1/B1/C1); use [`check_infra_attest_role_admission_over_roster`] to inject a
/// test roster.
///
/// - The row's `roles` does NOT contain `infra:attest` → `Ok(())` (no-op).
/// - It contains `infra:attest` AND the scrub set meets the accord m-of-n →
///   `Ok(())`.
/// - It contains `infra:attest` but is self-signed / sub-quorum / scrubbed by
///   non-anchor keys → [`Error::InfraAttestRoleNotAccordConferred`]
///   (fail-closed; the caller must NOT store the row).
///
/// **Monotonicity.** Runs at every `federation_keys` write chokepoint
/// (`put_public_key` on all three backends + the `adopt_scrub_upgrade`
/// self→anchored path), so `infra:attest` can never be added by a later
/// self-registration or by replication of an under-quorum row. Verify-before-
/// mutation (AV-9); backend-agnostic.
pub async fn check_infra_attest_role_admission(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
) -> Result<(), Error> {
    check_infra_attest_role_admission_over_roster(directory, row, &accord_holder_roster_key_ids())
        .await
}

/// [`check_infra_attest_role_admission`] with an explicit accord-holder roster —
/// the core primitive (tests inject their own signable holders). Shares the
/// [`verify_accord_family_coscrub`] quorum core with the `canonical` gate.
pub async fn check_infra_attest_role_admission_over_roster(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
    roster_key_ids: &[String],
) -> Result<(), Error> {
    // (1) Fast path: no `infra:attest` role on EITHER surface → nothing to
    // gate. (Plain authorization scopes in `roles` are untouched; only this
    // token is gated.) #441: evaluated over identity_type ∪ roles so an
    // `identity_type` self-claim cannot slip the roles-vector gate.
    if !row.claims_role(super::types::roles::INFRA_ATTEST) {
        return Ok(());
    }

    // (2) Revocation-wins (#424, the #377 rule generalized): a quorum-withdrawn
    // key stays refused EVEN with a valid co-scrub set — the ADD gate is
    // monotonic and anti-entropy re-runs it, so without this consult a peer
    // still holding the old co-scrubbed record silently re-adds the role. A
    // SUPERSEDE successor whose tombstone names THIS key_id is exempt.
    if let Some(w) = directory
        .lookup_role_withdrawal(super::types::roles::INFRA_ATTEST, &row.key_id)
        .await?
    {
        if w.superseded_by.as_deref() != Some(row.key_id.as_str()) {
            return Err(Error::InfraAttestRoleWithdrawn {
                key_id: row.key_id.clone(),
                superseded_by: w.superseded_by.clone(),
            });
        }
    }

    // (3) The shared accord-family m-of-n co-scrub quorum core.
    verify_accord_family_coscrub(directory, row, roster_key_ids)
        .await
        .map_err(|reason| Error::InfraAttestRoleNotAccordConferred {
            key_id: row.key_id.clone(),
            scrub_key_id: row.scrub_key_id.clone(),
            reason,
        })
}

/// v17.0.0 (CIRISPersist#440, CC 3.4.9) — the **CC 3.4.9 co-steward role
/// admission gate**: a `federation_keys` row may claim
/// [`identity_type::REGISTRY`] or [`identity_type::VERIFY`] (on either role
/// surface, [`super::KeyRecord::claims_role`]) IFF the record carries the
/// accord family m-of-n co-scrub — the SAME ceremony that confers `canonical`
/// and `infra:attest` ("same ceremony, different CEG object"). The co-steward
/// relation is capability-granting (a consumer lifts the CC 3.4.9
/// `confidence <= 0.5` single-source licensure cap on its say-so), so per the
/// accord-ops invariant it is m-of-n conferred, never self-claimed.
///
/// Runs at every `federation_keys` write chokepoint (`put_public_key` on all
/// three backends + `adopt_scrub_upgrade`); rides the role-generic core
/// [`check_accord_role_admission_over_roster`]. Fail-closed
/// ([`Error::RoleNotAccordConferred`], kind `role_not_accord_conferred`);
/// withdrawal-aware via the V104 generic tombstone
/// ([`Error::RoleWithdrawn`], kind `role_withdrawn`).
pub async fn check_co_steward_role_admission(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
) -> Result<(), Error> {
    check_co_steward_role_admission_over_roster(directory, row, &accord_holder_roster_key_ids())
        .await
}

/// v22.0.0 (CIRISPersist#543 finding 5 / AV-77) — the CEG dimension a node
/// emits to **de-admit a peer from its own corpus**.
///
/// Shape: a `scores` row, `attesting_key_id` = the de-admitting node,
/// `attested_key_id` = the de-admitted key, `score < 0` (the denial), live
/// unless the node `withdraws` it.
pub const PEER_DEADMISSION_DIMENSION: &str = "revocation:peer_admission:v1";

/// v22.0.0 (CIRISPersist#543 / AV-77) — **THE DE-ADMISSION GATE**: refuse
/// inbound writes authored by a key this node has de-admitted.
///
/// # The gap this closes
///
/// #543's audit found that persist's put-gates are the *entire* defence on the
/// mesh receive path, and then that there was **no CEG-encoded way to respond to
/// an abuser at all** — "the only thing that stops a bootstrap abuser today is
/// the whole-node accord kill-switch, a sledgehammer requiring hardware-attested
/// accord holders, with nothing between 'ignore it' and 'halt the node'."
/// `moderation:*` records an *event*, not a sanction; `slashing:*` has a verdict
/// shape but **no emit and no act**; `consent:*` withdrawal is SEND-side and so
/// cannot stop inbound injection. This is the missing act.
///
/// # Why it is LOCAL, and why that is the safe design
///
/// De-admission is scoped to the **emitting node's own corpus**. Node N refusing
/// K's writes is N exercising sovereignty over what N stores — it is not a
/// federation-wide ban, and no node can decree another's admission set. That
/// matters: a globally-effective de-admission primitive would itself be a
/// censorship weapon, and a 1-of-N global capability-removal is exactly the
/// shape the accord-ops invariant refuses.
///
/// Isolation of a genuine abuser is therefore **emergent, not decreed** — it
/// arises when many nodes independently reach the same conclusion, which is the
/// same shape as CC 3.2's re-rooting sovereignty ("untrust the canonical group…
/// a forced root is a walled garden; a default-plus-re-root is a federation").
///
/// Note this is NOT a capability grant, so the m-of-n floor does not bind: the
/// invariant governs granting authority, and this only ever *removes* what this
/// node accepts. The reverse-quorum reading also holds — protection is cheap to
/// invoke (the node alone), and the node alone can lift it by `withdraws`.
///
/// # Distinct from the blackhole substrate
///
/// [`crate::federation::blackhole`] denies **Reticulum transport addresses** —
/// operator-driven, out-of-band, about *where bytes go*. This denies **authors**
/// — a signed, replicable, revocable CEG attestation about *whose claims this
/// node accepts*, which is what "responses to abuse are themselves CEG
/// attestations, not out-of-band state" requires.
///
/// Fail-secure: a de-admitted author's rows are refused before any DB-walking
/// gate runs, so de-admission also sheds the AV-76 amplification cost.
pub async fn check_peer_deadmission(
    directory: &dyn super::FederationDirectory,
    row: &super::Attestation,
    self_key_id: &str,
) -> Result<(), Error> {
    // A node never de-admits itself.
    //
    // v30.13.0 (CIRISPersist#608) — this used to be a DISJUNCTION, exempting
    // any row carrying `PEER_DEADMISSION_DIMENSION` regardless of who wrote it.
    // A peer this node had already de-admitted could therefore keep authoring
    // de-admission rows ABOUT THIRD PARTIES: the sanction did not cover the
    // sanctioning dimension itself. Live since v22.0.0, on all three backends,
    // at both chokepoints that call this (`put_attestation` and
    // `check_promotion_admission`).
    //
    // The reason the dimension arm cannot be repaired — only removed — is that
    // **the exemption must mirror the consumption fold.** The fold below asks
    // `list_attestations_by(self_key_id)`: WHO AUTHORED. The old second arm
    // asked WHAT DIMENSION. Any exemption wider than the fold admits rows the
    // fold will never read, which is the "accepted but not projected" class
    // (v17.0.0's route table) wearing a different hat.
    //
    // The stated worry — "a node could not lift its own denial" — is answered
    // by the FIRST arm, not the second: every lift path forces the attester to
    // this node (`OpKind::Deadmit` and `OpKind::Withdraw` both pin
    // `SELF_PRINCIPAL`), so self-authored rows are already exempt. The second
    // arm only ever extended that to OTHER people's de-admission rows.
    //
    // Deliberately NOT widened to delegates: `is_steward_bound` /
    // `can_accept_for_itself` / the delegation walk answer custody about a
    // SUBJECT, not authorship of THIS ROW. Wiring one in here would re-open the
    // same gap one layer up, because the fold would still ignore the delegate.
    // Delegated de-admission means changing the FOLD first, and that is a
    // capability grant subject to the accord-ops m-of-n invariant.
    if row.attesting_key_id == self_key_id {
        return Ok(());
    }
    // Live de-admissions THIS node authored about the row's author. The
    // tombstone fold is the shared one — a `withdraws` against the de-admission
    // lifts it, so re-admitting is a first-class, auditable act.
    let mine = directory.list_attestations_by(self_key_id).await?;
    let refs: Vec<&super::Attestation> = mine.iter().collect();
    let dead = super::trust_root::tombstoned_ids(&refs);
    let now = chrono::Utc::now();
    let de_admitted = mine.iter().any(|a| {
        a.attestation_type == attestation_type::SCORES
            && a.attested_key_id == row.attesting_key_id
            && envelope_dimension(&a.attestation_envelope) == Some(PEER_DEADMISSION_DIMENSION)
            && !dead.contains(&a.attestation_id)
            && a.expires_at.is_none_or(|e| e > now)
    });
    if de_admitted {
        return Err(Error::InvalidArgument(format!(
            "peer {} is de-admitted from this node's corpus \
             ({PEER_DEADMISSION_DIMENSION}) — inbound writes refused (CIRISPersist#543 / AV-77). \
             Lift with a `withdraws` against the de-admission row.",
            row.attesting_key_id
        )));
    }
    Ok(())
}

/// v22.0.0 (CIRISPersist#543 finding 3) — **THE CLOSED AUTHORITY-CLAIM GATE**:
/// no [`identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES`] member may be
/// SELF-ASSERTED at registration.
///
/// # The hole this closes
///
/// `register_federation_key` proves key CUSTODY (a self-signed hybrid PoP) and
/// nothing more — deliberately, so canonical servers can bootstrap strangers.
/// Key material is free, so the threat model assumes unlimited admitted
/// identities. Four privileged claims were gated (each after its own incident);
/// the rest of the privileged set was self-assertable, so a Sybil could
/// register as `substrate_persist` / `witness` / `trusted_publisher` /
/// `lenscore_detector` and emit under the reserved dimension families those
/// types unlock (`system:`, `audit_chain:`, `age_assurance:`,
/// `capacity_assurance:`, `content_rating:`, `detection:*`) — asserting system,
/// age, capacity or detection authority **about a third party**.
///
/// # The rule
///
/// A privileged claim must be **CONFERRED, never self-declared**. Conferral is
/// the accord m-of-n co-scrub the whole substrate already uses
/// ([`check_accord_role_admission_over_roster`] — written to be parameterized
/// so "every FUTURE accord-conferred role rides it with zero new gate code";
/// this is that future). [`identity_type::ACCORD_HOLDER`] and
/// [`identity_type::CANONICAL`] keep their dedicated gates for their CC-pinned
/// error kinds and stronger ceremonies (hardware attestation / anchor-scrub)
/// and are skipped here — gating them twice would demand a co-scrub the
/// bootstrap anchor cannot produce.
///
/// Self-registration of a DESCRIPTIVE type (`agent` / `user` / `node` /
/// `primitive`) is untouched: those unlock nothing, which is why they are
/// absent from the closed set.
///
/// Fail-closed: [`Error::RoleNotAccordConferred`]. Runs at every
/// `federation_keys` write chokepoint, backend-symmetric.
pub async fn check_privileged_identity_type_admission(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
) -> Result<(), Error> {
    check_privileged_identity_type_admission_over_roster(
        directory,
        row,
        &accord_holder_roster_key_ids(),
    )
    .await
}

/// [`check_privileged_identity_type_admission`] with an explicit accord-holder
/// roster (tests inject their own signable holders).
pub async fn check_privileged_identity_type_admission_over_roster(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
    roster_key_ids: &[String],
) -> Result<(), Error> {
    for claim in identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES {
        // Enforce ONLY the claims whose conferral root IS the accord co-scrub.
        // The others are not ungated — they are gated by a DIFFERENT, stronger
        // or differently-shaped ceremony at this same chokepoint:
        //
        // - HardwareAttested (`accord_holder`) → hardware_attestation_policy
        // - AnchorScrubbed  (`canonical`)      → check_canonical_role_admission
        // - DerivedFromVerifiedState (`witness`/`steward`/`partner`/
        //   `wise_authority`) → the claim is DESCRIPTIVE; every use site
        //   re-derives the authority from persist's own verified state (the
        //   steward-binding walk, licensure quorum, WA adjudication edge), so a
        //   self-asserted claim buys nothing. Demanding a co-scrub for these
        //   would fail CLOSED on legitimate operators — a witness has no accord
        //   family to co-scrub it, and at bootstrap there is no roster at all.
        //
        // Getting this distinction wrong in either direction is a real bug:
        // too loose and a Sybil self-asserts authority; too strict and honest
        // operators cannot register. The mode table makes the choice explicit
        // and reviewable per claim rather than assumed uniformly.
        if identity_type::conferral_mode(claim)
            != Some(identity_type::ConferralMode::AccordCoScrubbed)
        {
            continue;
        }
        check_accord_role_admission_over_roster(directory, row, claim, roster_key_ids).await?;
    }
    Ok(())
}

/// [`check_co_steward_role_admission`] with an explicit accord-holder roster
/// (tests inject their own signable holders).
pub async fn check_co_steward_role_admission_over_roster(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
    roster_key_ids: &[String],
) -> Result<(), Error> {
    for role in identity_type::CO_STEWARD_ROLES {
        check_accord_role_admission_over_roster(directory, row, role, roster_key_ids).await?;
    }
    Ok(())
}

/// v17.0.0 (CIRISPersist#440/#441) — the **role-generic accord-conferral
/// admission gate**: `role` may be claimed (on either role surface,
/// [`super::KeyRecord::claims_role`]) only by a record carrying the accord
/// family m-of-n co-scrub, and only while no un-superseded V104 withdrawal
/// tombstone names `(role, key_id)`. This is the third instantiation of the
/// `canonical` / `infra:attest` gate shape, parameterized so every FUTURE
/// accord-conferred role rides it with zero new gate code (`canonical` and
/// `infra:attest` keep their dedicated functions for their CC-pinned error
/// kinds).
///
/// - `row` does not claim `role` → `Ok(())` (no-op; the vast majority of rows).
/// - `(role, key_id)` is quorum-withdrawn and not this key's own SUPERSEDE
///   rotate-in → [`Error::RoleWithdrawn`] (revocation-wins, the #377 rule:
///   anti-entropy re-runs this gate, so a peer re-offering the old co-scrubbed
///   record cannot silently re-add the role).
/// - Claim present, scrub set meets the live-roster strict majority
///   ([`verify_accord_family_coscrub`], the ONE shared quorum core) → `Ok(())`.
/// - Otherwise → [`Error::RoleNotAccordConferred`] (fail-closed; the caller
///   must NOT store the row).
pub async fn check_accord_role_admission_over_roster(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
    role: &str,
    roster_key_ids: &[String],
) -> Result<(), Error> {
    // (1) Fast path: no claim on either role surface → nothing to gate.
    if !row.claims_role(role) {
        return Ok(());
    }

    // (2) Revocation-wins (#377/#424): a quorum-withdrawn (role, key_id) stays
    // refused EVEN with a valid co-scrub set; a SUPERSEDE successor whose
    // tombstone names THIS key_id is exempt (rotate-in).
    if let Some(w) = directory.lookup_role_withdrawal(role, &row.key_id).await? {
        if w.superseded_by.as_deref() != Some(row.key_id.as_str()) {
            return Err(Error::RoleWithdrawn {
                role: role.to_owned(),
                key_id: row.key_id.clone(),
                superseded_by: w.superseded_by.clone(),
            });
        }
    }

    // (3) The shared accord-family m-of-n co-scrub quorum core.
    verify_accord_family_coscrub(directory, row, roster_key_ids)
        .await
        .map_err(|reason| Error::RoleNotAccordConferred {
            role: role.to_owned(),
            key_id: row.key_id.clone(),
            scrub_key_id: row.scrub_key_id.clone(),
            reason,
        })
}

/// v17.0.0 (CIRISPersist#440) — the **self-authenticating effective-role
/// read** a consumer resolves trust from: `key_id`'s stored row claims `role`
/// (either role surface), the row's scrub set STILL VERIFIES to the accord
/// family m-of-n ([`verify_accord_family_coscrub`], re-run against the live
/// roster), and no un-superseded V104 tombstone names `(role, key_id)`.
///
/// The co-scrub is re-verified rather than trusted from claim-presence
/// because the `roles` vector accepted arbitrary self-asserted tokens before
/// v17.0.0 gated these roles — a row stored under ≤16.1.1 may carry a
/// decorative self-claimed `registry`/`verify` that the write gate never saw.
/// Re-deriving conferral from the row's own cryptography (never from write-
/// gate history) means such a legacy row reads `false` here, by construction.
///
/// CIRISServer's CC 3.4.9 `licensure_cap` resolves "which co-steward is this
/// attesting key" through this (dropping its by-pin fallback):
/// `has_accord_conferred_role(dir, kid, identity_type::REGISTRY)` /
/// `identity_type::VERIFY`. Role-generic on purpose; the `canonical` /
/// `infra:attest` dedicated effective-reads stay as-is.
pub async fn has_accord_conferred_role(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
    role: &str,
) -> Result<bool, Error> {
    has_accord_conferred_role_over_roster(directory, key_id, role, &accord_holder_roster_key_ids())
        .await
}

/// v22.0.0 (CIRISPersist#543 / AV-75) — the **delegation-plane** effective-role
/// read: does `key_id` hold `role` as a capability DELEGATED by a trust root
/// that `user_key_id` itself trusts?
///
/// This is the counterpart to [`has_accord_conferred_role`] for roles whose
/// [`ConferralMode`](super::types::identity_type::ConferralMode) is
/// `DelegatedFromTrustRoot` — `trusted_publisher` and `lenscore_detector`.
/// Where the co-scrub read asks "did the accord bless this key's identity",
/// this asks "did a root I trust grant this key this capability", which is the
/// plane the portable trust root already uses for `infra:*`.
///
/// Two conditions, both required:
/// 1. the key CLAIMS the role (either surface — [`KeyRecord::claims_role`]);
/// 2. the claim is BACKED by a live `delegates_to(root → key, [role])` whose
///    root passes [`trust_root_valid`](super::trust_root) from `user_key_id`'s
///    own records — i.e. `capability_roots_to_trusted_root`.
///
/// A self-asserted claim with no delegation therefore reads `false`, which is
/// the AV-75 property: registering the string buys nothing.
///
/// v22.1.0 (CIRISPersist#548): the walk it delegates to also accepts the
/// CEREMONY plane — a 2-of-3 accord co-scrub conferring the role inside the
/// subject's own registration_envelope (the baked-seed encoding), still
/// subject to the user's full trust chain to the subject-as-root. Strictly
/// stronger evidence than one root's `delegates_to`; the AV-75 property is
/// unchanged (a bare self-registered string still buys nothing).
///
/// Fail-closed: any resolution error reads `false`.
pub async fn has_root_delegated_role(
    directory: &dyn super::FederationDirectory,
    user_key_id: &str,
    key_id: &str,
    role: &str,
) -> Result<bool, Error> {
    let Some(row) = directory.lookup_public_key(key_id).await? else {
        return Ok(false);
    };
    if !row.claims_role(role) {
        return Ok(false);
    }
    Ok(
        super::trust_root::capability_roots_to_trusted_root(directory, user_key_id, key_id, role)
            .await?
            .is_some(),
    )
}

/// [`has_accord_conferred_role`] with an explicit accord-holder roster (tests inject
/// their own signable holders).
// v30.3.0 (CIRISPersist#611) — `?Sized`-generic for the same reason
// `capability_roots_to_trusted_root_over_roster` is: it sits on that resolver's
// ceremony arm, so the whole walk has to be reachable from a default trait
// method. Source-compatible for every existing `&dyn` caller.
pub async fn has_accord_conferred_role_over_roster<F>(
    directory: &F,
    key_id: &str,
    role: &str,
    roster_key_ids: &[String],
) -> Result<bool, Error>
where
    F: super::FederationDirectory + ?Sized,
{
    let Some(row) = directory.lookup_public_key(key_id).await? else {
        return Ok(false);
    };
    if !row.claims_role(role) {
        return Ok(false);
    }
    if verify_accord_family_coscrub(directory, &row, roster_key_ids)
        .await
        .is_err()
    {
        return Ok(false);
    }
    Ok(
        match directory.lookup_role_withdrawal(role, key_id).await? {
            // A supersede tombstone naming THIS key as its own successor is a
            // rotate-in; anything else withdrawn ⇒ not effective.
            Some(w) => w.superseded_by.as_deref() == Some(key_id),
            None => true,
        },
    )
}

/// **CIRISPersist#422 — is `key_id` an accord-blessed build-signing pipeline?**
/// True iff `key_id` resolves to a `federation_keys` row whose `roles` set
/// contains [`super::types::roles::INFRA_ATTEST`]. Because
/// [`check_infra_attest_role_admission`] gates every write path, a stored row
/// can carry `infra:attest` only if it earned it via the accord co-scrub — so
/// this simple membership read is sufficient (the admission gate is the
/// enforcement point). The manifest verifier + CIRISServer call this to ask "is
/// this build-signing key trust-root-blessed?" `false` for an unknown `key_id`
/// or a row without the role.
pub async fn is_infra_attest(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
) -> Result<bool, Error> {
    Ok(directory.lookup_public_key(key_id).await?.is_some_and(|r| {
        r.capability_roles
            .iter()
            .any(|role| role == super::types::roles::INFRA_ATTEST)
    }))
}

/// v16.0.0 (CIRISPersist#424) — the WITHDRAWAL-AWARE trust-root read:
/// [`is_infra_attest`] AND no un-superseded V104 tombstone. The mirror of
/// [`is_canonical_effective`]: a stored row may still carry `infra:attest`
/// (the tombstone never mutates rows) but a quorum-withdrawn key is NOT an
/// effective build-signing trust root. Consumers deciding whether to TRUST a
/// pipeline key call THIS; the bare read is the storage-state accessor.
pub async fn is_infra_attest_effective(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
) -> Result<bool, Error> {
    if !is_infra_attest(directory, key_id).await? {
        return Ok(false);
    }
    Ok(
        match directory
            .lookup_role_withdrawal(super::types::roles::INFRA_ATTEST, key_id)
            .await?
        {
            // A supersede tombstone naming THIS key as its own successor is a
            // rotate-in; anything else withdrawn ⇒ not effective.
            Some(w) => w.superseded_by.as_deref() == Some(key_id),
            None => true,
        },
    )
}

/// **CIRISPersist#372 — is `key_id` a canonical / founding bootstrap server?**
/// True iff `key_id` resolves to a `federation_keys` row whose `identity_type`
/// **set** contains [`super::types::identity_type::CANONICAL`]. Because
/// [`check_canonical_role_admission`] gates every write path, a stored row can
/// carry `canonical` only if it earned it via anchor-scrub — so this simple
/// set-membership read is sufficient (the admission gate is the enforcement
/// point). `false` for an unknown `key_id` or a non-canonical row.
pub async fn is_canonical(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
) -> Result<bool, Error> {
    Ok(directory
        .lookup_public_key(key_id)
        .await?
        .is_some_and(|r| identity_type::set_contains(&r.identity_type, identity_type::CANONICAL)))
}

// ─────────────────────────────────────────────────────────────────────
// v13.1.0 (CIRISPersist#377) — canonical-role WITHDRAW / SUPERSEDE.
//
// The two DESTRUCTIVE Trust Root ops on top of #372's monotonic add-canonical.
// Withdrawal is a durable, quorum-verified TOMBSTONE (V095) — NOT a hard
// un-set — because the add-gate above is monotonic and anti-entropy re-runs
// it, so a hard drop would be silently re-added on the next replication round.
// The gate ([`check_canonical_role_admission_over_roster`]) consults the
// tombstone so the effective rule is "2-of-3-scrubbed AND not
// withdrawn-by-quorum".
// ─────────────────────────────────────────────────────────────────────

/// The canonical `op` token committed by a plain-WITHDRAW authority payload
/// (bound into `AccordProposal::payload_sha256`).
pub const OP_WITHDRAW_CANONICAL: &str = "withdraw_canonical";
/// v16.0.0 (#424) — the `op` token committed by an `infra:attest`-WITHDRAW
/// authority payload. Rides the same op-parameterized #377 authority machinery
/// ([`verify_canonical_authority_over_roster`]) — same ceremony, different role.
pub const OP_WITHDRAW_INFRA_ATTEST: &str = "withdraw_infra_attest";
/// The canonical `op` token committed by a SUPERSEDE authority payload.
pub const OP_SUPERSEDE_CANONICAL: &str = "supersede_canonical";

/// v13.1.0 (CIRISPersist#377) — a stored canonical-role WITHDRAW/SUPERSEDE
/// tombstone (V095 `canonical_role_withdrawal`). One row per withdrawn
/// canonical `key_id`. The gate consults it (revocation-wins); a
/// [`superseded_by`](Self::superseded_by)`= Some(new)` row is the old→new audit
/// link of a supersede (a plain withdraw leaves it `None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalWithdrawal {
    /// The withdrawn canonical node (the `federation_keys.key_id` whose
    /// `canonical` role is tombstoned).
    pub key_id: String,
    /// When the withdrawal was recorded.
    pub withdrawn_at: chrono::DateTime<chrono::Utc>,
    /// The authorizing accord **proposal digest** (V091 / #302) — the audit
    /// anchor for the m-of-n quorum whose stored, verified participations
    /// persist re-tallied to authorize this withdrawal.
    pub authority_decision_digest: String,
    /// The successor key_id for a SUPERSEDE (old→new link); `None` for a plain
    /// WITHDRAW.
    pub superseded_by: Option<String>,
    /// Substrate row hash (canonical SHA-256 of the stored row).
    pub persist_row_hash: String,
}

/// v16.0.0 (CIRISPersist#424) — a GENERIC accord-conferred-role withdrawal
/// tombstone (V104 `federation_role_withdrawals`) — [`CanonicalWithdrawal`]
/// generalized with a `role` discriminant. `canonical` stays on its V095
/// table; every later accord-conferred role tombstones HERE, starting with
/// [`roles::INFRA_ATTEST`](crate::federation::types::roles::INFRA_ATTEST).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoleWithdrawal {
    /// The withdrawn role token (e.g. `"infra:attest"`).
    pub role: String,
    /// The `federation_keys.key_id` whose role is tombstoned.
    pub key_id: String,
    /// When the withdrawal was recorded.
    pub withdrawn_at: chrono::DateTime<chrono::Utc>,
    /// The authorizing accord **proposal digest** (V091 / #302).
    pub authority_decision_digest: String,
    /// The successor key_id for a SUPERSEDE (old→new link); `None` for a plain
    /// WITHDRAW.
    pub superseded_by: Option<String>,
    /// Substrate row hash (canonical SHA-256 of the stored row).
    pub persist_row_hash: String,
}

/// v13.1.0 (CIRISPersist#377) — the canonical persist-computed authority
/// payload digest a withdraw/supersede accord **proposal** MUST commit to (its
/// `payload_sha256`). Lowercase-hex SHA-256 of the JCS (RFC 8785)
/// canonicalization of `{"op": <op>, "target_key_id": <target>[,
/// "successor_key_id": <successor>]}`. `op` is [`OP_WITHDRAW_CANONICAL`] or
/// [`OP_SUPERSEDE_CANONICAL`]; `successor_key_id` is present iff `successor` is
/// `Some` (a supersede). Persist DEFINES this payload — it never trusts a
/// caller-supplied digest — so a decision authorizing some OTHER payload cannot
/// be replayed to withdraw a different key.
pub fn canonical_withdrawal_payload_sha256(
    op: &str,
    target_key_id: &str,
    successor_key_id: Option<&str>,
) -> Result<String, Error> {
    use sha2::{Digest, Sha256};
    let mut payload = serde_json::Map::new();
    payload.insert("op".to_owned(), serde_json::Value::String(op.to_owned()));
    payload.insert(
        "target_key_id".to_owned(),
        serde_json::Value::String(target_key_id.to_owned()),
    );
    if let Some(succ) = successor_key_id {
        payload.insert(
            "successor_key_id".to_owned(),
            serde_json::Value::String(succ.to_owned()),
        );
    }
    let bytes = ciris_verify_core::jcs::canonicalize(&serde_json::Value::Object(payload))
        .map_err(|e| Error::Backend(format!("canonicalize canonical-withdrawal payload: {e}")))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

// v13.1.0 #377 destructive threshold: was a frozen `CANONICAL_WITHDRAW_QUORUM_M/N
// = 2/3`. v13.2.0 (#383 follow-up) derives it as the **strict majority of the
// LIVE accord roster** via `QuorumPolicy::new(n/2+1, n)` inside
// `verify_canonical_authority_over_roster` — symmetric with the #383 canonical
// ADD gate, so every capability-granting canonical op is m-of-n on the family
// (no hardcoded constant, no 1-of-N first-strike hole). The threshold is
// absolute (a strict majority of distinct real accord holders whose YES
// participations verify) — inflating `|L|` with captured keys cannot lower it.

/// The accord-holder standing-roster `key_id`s (A1/B1/C1) — the FIXED identities
/// whose PINNED directory pubkeys form the canonical-withdraw quorum roster.
/// Sourced from the EFFECTIVE genesis records, never caller input: the baked
/// trio in production, and — only on a `test-anchor` build with the runtime
/// gate armed (#449) — the synthesized SW test-root holders, so the whole
/// accord quorum machinery follows the same anchor verify roots against.
pub(crate) fn accord_holder_roster_key_ids() -> Vec<String> {
    super::genesis::effective_accord_holder_records()
        .iter()
        .map(|r| r.record.key_id.clone())
        .collect()
}

/// v13.1.0 (CIRISPersist#377) — verify a withdraw/supersede authority by
/// **re-tallying persist's OWN cryptographically-verified state**, never a
/// caller-supplied `AccordDecision` (whose `authorized` bool is an
/// unauthenticated assertion an attacker could fabricate — the #377 security
/// fix). Fail-closed with [`Error::CanonicalWithdrawalAuthorityInvalid`].
///
/// Steps, against the live directory:
/// 1. [`get_accord_proposal`](super::FederationDirectory::get_accord_proposal)`(proposal_digest)`
///    MUST resolve to a stored proposal (#302 / V091).
/// 2. The proposal MUST be over the HUMANITY_ACCORD family
///    ([`HUMANITY_ACCORD_FAMILY_KEY_ID`](ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID))
///    and its `payload_sha256` MUST equal the persist-computed
///    [`canonical_withdrawal_payload_sha256`] for `(op, target[, successor])` —
///    so the quorum voted on EXACTLY this op + target, no replay.
/// 3. The standing roster is the accord holders (`roster_key_ids`) resolved to
///    their PINNED directory pubkeys ([`ThresholdMember`](ciris_verify_core::threshold::ThresholdMember)).
/// 4. [`list_accord_participations`](super::FederationDirectory::list_accord_participations)`(proposal_digest)`
///    are the STORED, per-write-verified votes; re-tally them with verify-core
///    [`tally_live_quorum`](ciris_verify_core::accord_live_quorum::tally_live_quorum)
///    (each participation's hybrid signature + proposal-digest + seat binding is
///    re-checked; signers resolve ONLY in the pinned roster; deduped by member).
/// 5. Require `tally.yes` ≥ a **strict majority of the live accord roster**
///    (`QuorumPolicy::new(n/2+1, n)` — 2-of-3 today, tracks the family). A caller
///    cannot forge YES votes: only real, signed participations the roster holders
///    produced (and persist already verified at store time) count.
///
/// Returns the stored proposal's digest (the tombstone's `authority_decision_digest`).
async fn verify_canonical_authority_over_roster(
    directory: &dyn super::FederationDirectory,
    proposal_digest: &str,
    op: &str,
    target_key_id: &str,
    successor_key_id: Option<&str>,
    roster_key_ids: &[String],
) -> Result<String, Error> {
    use ciris_verify_core::accord_live_quorum::tally_live_quorum;
    use ciris_verify_core::threshold::ThresholdMember;

    let invalid = |reason: String| Error::CanonicalWithdrawalAuthorityInvalid {
        key_id: target_key_id.to_owned(),
        reason,
    };

    // (1) The proposal MUST be stored (a caller cannot invent one).
    let stored = directory
        .get_accord_proposal(proposal_digest)
        .await?
        .ok_or_else(|| {
            invalid(format!(
                "no stored accord proposal for digest {proposal_digest:?} — the quorum \
                 evidence does not exist in persist's own state"
            ))
        })?;
    let proposal = stored.proposal;

    // (2a) Family scope: only the HUMANITY_ACCORD family may authorize a
    //      canonical withdraw/supersede (parity with the kill-switch path).
    if proposal.family_key_id != ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID {
        return Err(invalid(format!(
            "proposal family_key_id {:?} is not the HUMANITY_ACCORD family {:?}",
            proposal.family_key_id,
            ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID
        )));
    }

    // (2b) Payload binding: the quorum voted on EXACTLY this op + target.
    let expected = canonical_withdrawal_payload_sha256(op, target_key_id, successor_key_id)?;
    if proposal.payload_sha256 != expected {
        return Err(invalid(format!(
            "proposal payload_sha256 ({got:?}) does not commit to the canonical `{op}` payload \
             for target {target_key_id:?} (expected {expected:?}) — the quorum did not authorize \
             THIS operation",
            got = proposal.payload_sha256,
        )));
    }

    // (3) Standing roster = accord holders resolved to their PINNED directory
    //     pubkeys (never caller-supplied keys).
    let mut roster: Vec<ThresholdMember> = Vec::with_capacity(roster_key_ids.len());
    for kid in roster_key_ids {
        if let Some(rec) = directory.lookup_public_key(kid).await? {
            roster.push(ThresholdMember {
                member_id: rec.key_id,
                ed25519_public_key_base64: rec.pubkey_ed25519_base64,
                mldsa65_public_key_base64: rec.pubkey_ml_dsa_65_base64,
                role: None,
            });
        }
    }

    // (4) Re-tally persist's own stored, per-write-verified participations. Each
    //     is re-verified (sig + proposal-digest + seat) against the pinned roster.
    let participations: Vec<_> = directory
        .list_accord_participations(proposal_digest)
        .await?
        .into_iter()
        .map(|s| s.participation)
        .collect();
    let tally = tally_live_quorum(&proposal, &participations, &roster)
        .map_err(|e| invalid(format!("live-quorum tally failed (fail-closed): {e:?}")))?;

    // (5) Destructive threshold = **strict majority of the LIVE accord roster**
    // (CIRISPersist#383 follow-up — was a frozen 2/3). Derived via verify's
    // `QuorumPolicy` (`2·M > N`, no M==1 escape), so withdraw/supersede tracks
    // the family the same way canonical *add* does (2-of-3 today, 3-of-4 if the
    // family grows) — never a hardcoded constant.
    let n = roster.len();
    let policy = ciris_verify_core::threshold::QuorumPolicy::new(n / 2 + 1, n);
    policy.validate().map_err(|e| {
        invalid(format!(
            "accord roster quorum policy invalid ({n} holders): {e:?}"
        ))
    })?;
    if tally.yes < policy.m {
        return Err(invalid(format!(
            "insufficient accord quorum: {yes} YES vote(s) among the live set {live:?}, but a \
             canonical withdraw/supersede requires a strict majority of the accord family \
             (>= {m} of {n})",
            yes = tally.yes,
            live = tally.live_set,
            m = policy.m,
            n = policy.n,
        )));
    }

    Ok(proposal.digest())
}

/// v13.1.0 (CIRISPersist#377) — verify a PLAIN-WITHDRAW authority binds a
/// withdraw of `key_id`, against the production accord-holder roster (A1/B1/C1).
/// Returns the authorizing proposal digest. See
/// [`verify_canonical_authority_over_roster`].
pub async fn verify_canonical_withdraw_authority(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
    proposal_digest: &str,
) -> Result<String, Error> {
    verify_canonical_authority_over_roster(
        directory,
        proposal_digest,
        OP_WITHDRAW_CANONICAL,
        key_id,
        None,
        &accord_holder_roster_key_ids(),
    )
    .await
}

/// v13.1.0 (CIRISPersist#377) — verify a SUPERSEDE authority binds
/// `old_key_id → new_key_id`, against the production accord-holder roster.
/// Returns the authorizing proposal digest. See
/// [`verify_canonical_authority_over_roster`].
pub async fn verify_canonical_supersede_authority(
    directory: &dyn super::FederationDirectory,
    old_key_id: &str,
    new_key_id: &str,
    proposal_digest: &str,
) -> Result<String, Error> {
    verify_canonical_authority_over_roster(
        directory,
        proposal_digest,
        OP_SUPERSEDE_CANONICAL,
        old_key_id,
        Some(new_key_id),
        &accord_holder_roster_key_ids(),
    )
    .await
}

/// v13.1.0 (CIRISPersist#377) — **withdraw** the `canonical` role from `key_id`.
/// `proposal_digest` names a STORED accord proposal (#302) whose payload commits
/// to `(withdraw, key_id)`; persist re-tallies its own cryptographically-verified
/// participations against the accord-holder roster at the 2-of-3 destructive
/// threshold (verify-before-mutation, AV-9 — never a caller-supplied
/// `AccordDecision.authorized` bool), then records the durable tombstone (V095).
/// Because [`check_canonical_role_admission`] consults it, a replicated re-offer
/// of the old anchor-scrubbed `canonical` record for `key_id` is Refused, and
/// [`is_canonical_effective`] reads `false`. Idempotent.
pub async fn withdraw_canonical_role(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
    proposal_digest: &str,
) -> Result<(), Error> {
    withdraw_canonical_role_over_roster(
        directory,
        key_id,
        proposal_digest,
        &accord_holder_roster_key_ids(),
    )
    .await
}

/// [`withdraw_canonical_role`] with an explicit accord-holder roster keyset — the
/// core primitive. Production callers use the [`withdraw_canonical_role`] wrapper
/// (genesis A1/B1/C1 roster); this form exists so tests can supply their own
/// signable holders, mirroring [`check_canonical_role_admission_over_roster`].
pub async fn withdraw_canonical_role_over_roster(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
    proposal_digest: &str,
    roster_key_ids: &[String],
) -> Result<(), Error> {
    let authority_digest = verify_canonical_authority_over_roster(
        directory,
        proposal_digest,
        OP_WITHDRAW_CANONICAL,
        key_id,
        None,
        roster_key_ids,
    )
    .await?;
    directory
        .record_canonical_withdrawal(key_id, None, &authority_digest)
        .await
}

/// v16.0.0 (CIRISPersist#424) — **withdraw** the `infra:attest` role from
/// `key_id` (a compromised/retired build-signing pipeline). The #377 canonical
/// withdraw, re-used for the roles-vector role: `proposal_digest` names a
/// STORED accord proposal whose payload commits to
/// `(withdraw_infra_attest, key_id)`; persist re-tallies its OWN
/// cryptographically-verified participations against the accord-holder roster
/// at the strict-majority destructive threshold (verify-before-mutation, AV-9 —
/// never a caller `AccordDecision.authorized` bool), then records the durable
/// V104 tombstone. Because [`check_infra_attest_role_admission`] consults it, a
/// replicated re-offer of the old co-scrubbed record is Refused, and
/// [`is_infra_attest_effective`] reads `false`. Reverse quorum per the accord-
/// ops invariant: the ADD needed m-of-n; the WITHDRAW (protective) needs m-of-n
/// too. Idempotent.
pub async fn withdraw_infra_attest_role(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
    proposal_digest: &str,
) -> Result<(), Error> {
    withdraw_infra_attest_role_over_roster(
        directory,
        key_id,
        proposal_digest,
        &accord_holder_roster_key_ids(),
    )
    .await
}

/// [`withdraw_infra_attest_role`] with an explicit accord-holder roster keyset
/// (tests). Shares [`verify_canonical_authority_over_roster`] — the
/// op-parameterized #377 authority core — with the canonical withdraw, so the
/// quorum math lives in ONE place.
pub async fn withdraw_infra_attest_role_over_roster(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
    proposal_digest: &str,
    roster_key_ids: &[String],
) -> Result<(), Error> {
    let authority_digest = verify_canonical_authority_over_roster(
        directory,
        proposal_digest,
        OP_WITHDRAW_INFRA_ATTEST,
        key_id,
        None,
        roster_key_ids,
    )
    .await?;
    directory
        .record_role_withdrawal(
            crate::federation::types::roles::INFRA_ATTEST,
            key_id,
            None,
            &authority_digest,
        )
        .await
}

/// v17.0.0 (CIRISPersist#440) — the canonical `op` token a role-generic
/// WITHDRAW authority payload commits to: `withdraw_role:{role}`. The role
/// token is INSIDE the op string (and therefore inside the JCS payload
/// digest), so a decision authorizing withdrawal of one role can never be
/// replayed to withdraw a different role from the same key. `canonical` and
/// `infra:attest` keep their frozen dedicated tokens
/// ([`OP_WITHDRAW_CANONICAL`] / [`OP_WITHDRAW_INFRA_ATTEST`]).
pub fn op_withdraw_role(role: &str) -> String {
    format!("withdraw_role:{role}")
}

/// v17.0.0 (CIRISPersist#440) — **withdraw** an accord-conferred role (the
/// CC 3.4.9 co-stewards `registry`/`verify`, and every future
/// [`check_accord_role_admission_over_roster`]-gated role) from `key_id`.
/// The #377 op-parameterized authority core, role-generically: the stored
/// accord proposal's payload must commit to
/// `(`[`op_withdraw_role`]`(role), key_id)`; persist re-tallies its OWN
/// cryptographically-verified participations against the accord-holder
/// roster at the strict-majority destructive threshold (never a caller
/// `AccordDecision.authorized` bool), then records the durable V104
/// tombstone. Reverse-quorum per the accord-ops invariant; idempotent.
///
/// Refuses `canonical` and `infra:attest` — those roles have dedicated
/// withdraw ops with frozen tokens and (for `canonical`) a dedicated V095
/// tombstone table; routing them here would fork their audit surface.
pub async fn withdraw_accord_role(
    directory: &dyn super::FederationDirectory,
    role: &str,
    key_id: &str,
    proposal_digest: &str,
) -> Result<(), Error> {
    withdraw_accord_role_over_roster(
        directory,
        role,
        key_id,
        proposal_digest,
        &accord_holder_roster_key_ids(),
    )
    .await
}

/// [`withdraw_accord_role`] with an explicit accord-holder roster keyset
/// (tests). Shares [`verify_canonical_authority_over_roster`] — the
/// op-parameterized #377 authority core — so the quorum math lives in ONE
/// place.
pub async fn withdraw_accord_role_over_roster(
    directory: &dyn super::FederationDirectory,
    role: &str,
    key_id: &str,
    proposal_digest: &str,
    roster_key_ids: &[String],
) -> Result<(), Error> {
    if role == identity_type::CANONICAL || role == crate::federation::types::roles::INFRA_ATTEST {
        return Err(Error::InvalidArgument(format!(
            "withdraw_accord_role: role {role:?} has a dedicated withdraw op \
             (withdraw_canonical_role / withdraw_infra_attest_role) — use it"
        )));
    }
    let authority_digest = verify_canonical_authority_over_roster(
        directory,
        proposal_digest,
        &op_withdraw_role(role),
        key_id,
        None,
        roster_key_ids,
    )
    .await?;
    directory
        .record_role_withdrawal(role, key_id, None, &authority_digest)
        .await
}

/// v13.1.0 (CIRISPersist#377) — **supersede** (rotate) a canonical server:
/// re-tally the stored quorum for `proposal_digest` (payload committing to
/// `old_key_id → new_record`'s key_id) at the 2-of-3 destructive threshold
/// (AV-9), then admit the successor (the normal anchor-scrub add-gate runs inside
/// [`put_public_key`](super::FederationDirectory::put_public_key)) AND record
/// `old_key_id`'s withdrawal with `superseded_by = new_key_id` (the old→new audit
/// link). The authority is verified FIRST, so if the successor is refused no
/// tombstone is written; the successor is admitted before the predecessor is
/// tombstoned so the canonical set is never momentarily empty. Backend-agnostic
/// (all three backends run identical steps — the ordering IS the atomicity
/// guarantee and a re-record is idempotent).
pub async fn supersede_canonical(
    directory: &dyn super::FederationDirectory,
    old_key_id: &str,
    new_record: super::SignedKeyRecord,
    proposal_digest: &str,
) -> Result<(), Error> {
    supersede_canonical_over_roster(
        directory,
        old_key_id,
        new_record,
        proposal_digest,
        &accord_holder_roster_key_ids(),
    )
    .await
}

/// [`supersede_canonical`] with an explicit accord-holder roster keyset (tests).
/// See [`withdraw_canonical_role_over_roster`].
pub async fn supersede_canonical_over_roster(
    directory: &dyn super::FederationDirectory,
    old_key_id: &str,
    new_record: super::SignedKeyRecord,
    proposal_digest: &str,
    roster_key_ids: &[String],
) -> Result<(), Error> {
    let new_key_id = new_record.record.key_id.clone();
    let authority_digest = verify_canonical_authority_over_roster(
        directory,
        proposal_digest,
        OP_SUPERSEDE_CANONICAL,
        old_key_id,
        Some(&new_key_id),
        roster_key_ids,
    )
    .await?;
    // Admit the successor first — the anchor-scrub add-gate + (for a key-id-
    // preserving rotation) the `superseded_by == key_id` withdrawal exemption
    // are enforced inside `put_public_key`.
    directory.put_public_key(new_record).await?;
    directory
        .record_canonical_withdrawal(old_key_id, Some(&new_key_id), &authority_digest)
        .await
}

/// v13.1.0 (CIRISPersist#377) — the **tombstone-aware** `canonical`-membership
/// read: `true` iff `key_id` carries the `canonical` role AND has NO withdrawal
/// tombstone (a superseded successor whose tombstone names itself is treated as
/// withdrawn for its OWN key — the successor is a distinct key). Where
/// [`is_canonical`] is the raw set-membership read (sufficient pre-#377 because
/// the add-gate was the only enforcement point), this is the read consumers
/// (and `list_canonical_servers` filtering) should use once withdrawals exist.
pub async fn is_canonical_effective(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
) -> Result<bool, Error> {
    if !is_canonical(directory, key_id).await? {
        return Ok(false);
    }
    Ok(directory
        .lookup_canonical_withdrawal(key_id)
        .await?
        .is_none())
}

/// #249 Cut B — the steward-binding **PATH** for audit: the actual delegation
/// chain `user → … → key_id` that steward-binds `key_id`, anchor-first (the
/// human `user`-role key at index 0, `key_id` last). Where
/// [`steward_bindings_of`] returns just the human ENDPOINTS, this returns the
/// resolving path so a consumer can show WHY a key is steward-bound.
///
/// Resolves the FIRST satisfying clause in [`is_steward_bound`]'s precedence
/// order (so `!steward_binding_chain(k).is_empty()` ⟺ `is_steward_bound(k)`):
///   1. `k` is itself `user`-role → `[k]` (the key IS the human anchor).
///   2. `k` is an occurrence of a `user`-role identity → `[identity, k]`.
///   3. a **live** `delegates_to(U → k)` with `U` `user`-role →
///      `[U, k]`, liveness decided by [`live_delegation_granters`] — the same
///      call [`is_steward_bound`] and [`steward_bindings_of`] make, so
///      `!steward_binding_chain(k).is_empty() ⟺ is_steward_bound(k)` holds by
///      construction (CIRISPersist#584). The §11.10 steward-binding clause (3)
///      is a DIRECT incoming edge (same as the predicate), so the delegated
///      path is one hop; a multi-hop human→…→k steward-binding is not part of
///      the predicate and is not synthesized here.
///
/// Returns the empty vec when `k` is not steward-bound (fail-closed, mirrors
/// the predicate).
pub async fn steward_binding_chain(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
) -> Result<Vec<String>, Error> {
    // v11.5.0 (CIRISPersist#306) — mirror `is_steward_bound`'s minor gate so
    // `!steward_binding_chain(k).is_empty() ⟺ is_steward_bound(k)` holds: a
    // PROVEN minor user does NOT self-anchor (clauses 1/2 suppressed); its
    // chain must root in a live adult-steward edge (clause 3).
    let k_self_anchors =
        super::age::age_band(directory, key_id).await? != super::age::AgeBand::Minor;
    if k_self_anchors {
        // (1) k's own key is user-role — k is the anchor.
        if let Some(rec) = directory.lookup_public_key(key_id).await? {
            if identity_type::set_contains(&rec.identity_type, identity_type::USER) {
                return Ok(vec![key_id.to_owned()]);
            }
        }
        // (2) k is an occurrence of a user-role identity — identity → k.
        if let Some(occ) = directory.lookup_identity_for_occurrence(key_id).await? {
            if let Some(id_rec) = directory.lookup_public_key(&occ.identity_key_id).await? {
                if identity_type::set_contains(&id_rec.identity_type, identity_type::USER) {
                    return Ok(vec![occ.identity_key_id, key_id.to_owned()]);
                }
            }
        }
    }
    // (3) a LIVE delegates_to(U → k) with U user-role — U → k. Lowest
    //     granter key_id first for a deterministic path when several humans
    //     delegate to k (consistent with the sorted `steward_bindings_of`);
    //     the ONE live-delegation walk returns a BTreeSet, so `.first()` IS
    //     that minimum. Liveness is NOT re-derived here — that is the whole
    //     point of CIRISPersist#584.
    let anchors =
        live_delegation_granters(directory, key_id, DelegationEdgeFilter::AnyDelegation).await?;
    if let Some(anchor) = anchors.into_iter().next() {
        return Ok(vec![anchor, key_id.to_owned()]);
    }
    Ok(Vec::new())
}

/// v9.0.0 SecReview F2 (CC 3.2 / CC 4.4.3.2.1) — is `community` an
/// **authorized** infrastructure community whose carve-outs (steward-binding
/// exemption + Commons-plaintext opt-out) may be honored?
///
/// A `cohort_subkind: infrastructure` label is honored ONLY IF the
/// community's OWN key ([`Community::community_key_id`]) resolves in
/// `federation_keys` to a record whose `identity_type` set contains
/// [`identity_type::SUBSTRATE_PERSIST`] — the §5.3/§7.2 reserved
/// governance/substrate authority that already owns the `system:` /
/// `audit_chain:` / `corpus_health:` reserved prefixes
/// ([`default_reserved_prefix_rules`]). CC 3.2 reserves the infrastructure
/// carve-out for genuine governance / trust roots (`ciris-canonical`);
/// without this check ANY caller could self-label a community
/// `infrastructure` to (a) skip the steward-binding gate and (b) force its
/// content to Commons-plaintext (no DEK).
///
/// **Fail-secure:** a community labeled `infrastructure` whose key does
/// NOT resolve to `substrate_persist` (or does not resolve at all) returns
/// `false` — the label is NOT honored, so the caller falls through to the
/// STRICTER non-infra path (steward-binding REQUIRED + DEK cascade applies).
/// An unauthorized infra label can only ever get the stricter treatment,
/// never the weaker one.
pub async fn is_authorized_infrastructure_community<F>(
    directory: &F,
    community: &super::Community,
) -> Result<bool, Error>
where
    F: super::FederationDirectory + ?Sized,
{
    let labeled_infra = community
        .policy_blob
        .as_ref()
        .and_then(|b| b.get("cohort_subkind"))
        .and_then(|v| v.as_str())
        == Some("infrastructure");
    if !labeled_infra {
        return Ok(false);
    }
    // Honor the carve-out ONLY if the community's own key is the reserved
    // governance/substrate authority.
    match directory
        .lookup_public_key(&community.community_key_id)
        .await?
    {
        Some(rec) => Ok(identity_type::set_contains(
            &rec.identity_type,
            identity_type::SUBSTRATE_PERSIST,
        )),
        None => Ok(false),
    }
}

/// v9.0.0 (CC 3.2 "steward-binding gate for non-infrastructure membership"
/// / CC 3.4.7.1) — the community-admission precondition: a `node`- or
/// `agent`-role roster member of a **non-infrastructure** community MUST
/// be steward-bound ([`is_steward_bound`]) before admission. Non-infra
/// membership is an *authority act* (standing to speak AS the group),
/// and CC 1.13.2 requires authority to root in an accountable human — a
/// fresh, unstewarded node/agent is **canonical-trust-and-serve only** until
/// owned. This is a **precondition**, not a substitute for the community's
/// own `consensus_protocol` vote (which still governs *whether* an owned
/// key is admitted).
///
/// # Scope and the infrastructure carve-out
///
/// `cohort_subkind: infrastructure` communities (`ciris-canonical` /
/// operator governance roots) are **EXEMPT** — a node MAY trust + serve
/// an infrastructure community with no steward (CC 3.2 "Trust ≠
/// membership"). The label is honored ONLY when
/// [`is_authorized_infrastructure_community`] holds (the community's own
/// key resolves to the `substrate_persist` governance authority, SecReview
/// F2); a self-labeled infra community whose key is not `substrate_persist`
/// gets the strict steward-binding treatment. For every other community this
/// gate runs per roster member.
///
/// A member key that does NOT resolve in `federation_keys`, or whose
/// `identity_type` set contains NEITHER `node` NOR `agent` (e.g. a pure
/// `user`/`org` member, or an unrecognized future role), is **out of
/// scope** — the gate constrains only node/agent standing. A `user`-role
/// member trivially satisfies `is_steward_bound` (clause 1) and is never
/// rejected here.
///
/// Fail-secure: the FIRST node/agent member lacking a live steward-binding
/// rejects the whole `put_community` with [`Error::UnstewardedCommunityMember`]
/// BEFORE any row is stored (verify-before-mutation, AV-9).
pub async fn check_community_membership_steward_binding(
    directory: &dyn super::FederationDirectory,
    community: &super::Community,
) -> Result<(), Error> {
    // Infrastructure carve-out: trust + serve needs no steward (CC 3.2) —
    // honored ONLY for an AUTHORIZED infrastructure community (its own key
    // is the `substrate_persist` governance authority). A self-labeled
    // infra community whose key is NOT substrate_persist falls through to
    // the strict steward-binding path below (SecReview F2, fail-secure).
    if is_authorized_infrastructure_community(directory, community).await? {
        return Ok(());
    }
    for member in &community.members {
        // Resolve the member's identity_type set. An unresolved member has
        // no node/agent standing this gate can prove — out of scope (and
        // FK-orthogonal: put_community does not FK roster members).
        let Some(rec) = directory.lookup_public_key(&member.key_id).await? else {
            continue;
        };
        // Only node/agent members are an authority-act constraint. Report
        // `node` first when both are present (it is the stricter framing).
        let member_role = if identity_type::set_contains(&rec.identity_type, identity_type::NODE) {
            identity_type::NODE
        } else if identity_type::set_contains(&rec.identity_type, identity_type::AGENT) {
            identity_type::AGENT
        } else {
            continue;
        };
        if !is_steward_bound(directory, &member.key_id).await? {
            return Err(Error::UnstewardedCommunityMember {
                community_key_id: community.community_key_id.clone(),
                member_key_id: member.key_id.clone(),
                member_role,
            });
        }
    }
    Ok(())
}

/// v12.5.0 (CIRISPersist#238, CC 4.5.4 / §11.11 — the no-moderator-no-federate
/// existence invariant) — the **substrate** federate-gate: a `community`
/// federates (is admitted to, and continues at, moderated capability) ONLY
/// while ≥1 live holder of its `moderate` duty exists. This is the moderation
/// analogue of the CC 3.2 steward-binding gate, and — like it — lives in the
/// substrate where the write lands, NOT in a governance / consumer-policy
/// layer (§11.11 "the gate lives where the write lands"; resolving the
/// CIRISPersist#238 / CIRISRegistry#110(a) ownership ambiguity to SUBSTRATE).
///
/// Takes the [`Community`](crate::federation::types::Community) record
/// **directly** (not via `lookup_community`) — the reusable admission-decision
/// primitive over a record in hand (in-flight or stored). For the
/// federation-apply re-check keyed on a stored community's id, see
/// [`check_no_moderator_federate_admission_by_id`]; both are the load-bearing
/// enforcement point [`check_no_moderator_federate_apply`] consumes.
///
/// # Enforcement point (design note — CIRISPersist#238)
///
/// The §11.11 gate is enforced at the **federation-apply chokepoint**: every
/// federation-tier attestation apply step keyed on `C`
/// ([`check_no_moderator_federate_apply`], wired into every backend's
/// `put_attestation`). This point subsumes BOTH spec evaluation points — a
/// community's **first** federation-tier apply keyed on `C` IS its
/// admission-to-federate (i), and every subsequent one is the continue-to-
/// federate re-check (ii). It is deliberately NOT wired into `put_community`:
/// storing a community *record* is not itself "federating" (a local-only
/// community that never emits federation-tier content keyed on `C` causes no
/// unmoderated-federation harm), and hard-failing record storage would also
/// fail-secure communities that §11.11 rule-2 merit auto-promotion / the CC
/// 4.5.13 recovery could still rescue — ceremonies persist cannot itself
/// perform (it cannot forge the authority's appointment signature). The gate
/// thus "lives where the [federation] write lands." This function remains the
/// admission-decision primitive a consumer/governance layer MAY call to decide
/// admission ahead of federation.
///
/// # The existence check
///
/// A named moderator exists IFF the community has ≥1 **steward-bound authority
/// root**. This is exact, not an approximation: [`is_named_moderator`] admits
/// `k` only via a chain rooted at some `root ∈ authority_set(C)` with
/// [`is_steward_bound(root)`](is_steward_bound) — and that steward-bound root
/// is itself a **zero-hop** named moderator. So `moderators_of(C, moderate)`
/// is non-empty IFF such a root exists; we test that directly (the authority
/// set computed from the in-flight record's roster, per
/// [`community_authority_set`]'s `founder_only`-vs-open rule), avoiding the
/// per-delegate walk.
///
/// # Carve-out + fail-secure
///
/// `cohort_subkind: infrastructure` communities
/// ([`is_authorized_infrastructure_community`]) are EXEMPT — a node MAY trust +
/// serve an infrastructure community (`ciris-canonical` / governance roots)
/// with no moderator, mirroring the CC 3.2 steward-binding carve-out. Every
/// other community with no steward-bound authority root is REFUSED with
/// [`Error::CommunityHasNoModerator`] BEFORE any row is stored
/// (verify-before-mutation, AV-9) — §11.11 rule 3 fail-secure, "better no
/// group than an unmoderated one".
///
/// Merit auto-promotion (§11.11 rule 2) + the CC 4.5.13 48-hour recovery are
/// signed appointment *ceremonies* (a `delegates_to(moderate)` emitted by the
/// community authority); persist cannot forge that authority signature, so
/// they live one layer up. This gate is the fail-secure floor the ceremony
/// recovers the community out of — the substrate never *fabricates* a
/// moderator, it only refuses to federate one that does not exist.
pub async fn check_no_moderator_federate_admission(
    directory: &dyn super::FederationDirectory,
    community: &super::Community,
) -> Result<(), Error> {
    // Infrastructure carve-out (authorized only — SecReview F2 fail-secure):
    // trust + serve needs no moderator.
    if is_authorized_infrastructure_community(directory, community).await? {
        return Ok(());
    }
    // Authority set from the in-flight roster (mirrors community_authority_set:
    // founders always; every member too under a non-`founder_only` protocol).
    let founder_only =
        community.consensus_protocol == crate::federation::types::consensus_protocol::FOUNDER_ONLY;
    for m in &community.members {
        let is_authority = m.role.as_deref() == Some(MEMBER_ROLE_FOUNDER) || !founder_only;
        if is_authority && is_steward_bound(directory, &m.key_id).await? {
            // ≥1 steward-bound authority root ⇒ a live (zero-hop) named
            // moderator exists ⇒ the community may federate.
            return Ok(());
        }
    }
    Err(Error::CommunityHasNoModerator {
        community_key_id: community.community_key_id.clone(),
    })
}

/// v12.5.0 (CIRISPersist#238, CC 4.5.4 / §11.11) — the **federation-apply**
/// re-check of [`check_no_moderator_federate_admission`], keyed on a stored
/// community's `community_id`. §11.11 requires the moderator-existence gate at
/// **two** points: (i) at admission (`put_community` — the record-in-flight
/// form above) AND (ii) **on the federation path** — "every cross-region
/// propagation / federation apply step keyed on C MUST re-check live
/// `moderate`-holder existence at apply time, so a community that *loses* its
/// moderator (lapse / `withdraws`-revocation / freshness expiry) cannot
/// continue at moderated capability." Mid-life moderator loss happens via
/// `delegates_to` retraction / steward-binding lapse — NOT via a community
/// re-write — so the community-record admission gate alone cannot catch it;
/// this apply-time re-check does.
///
/// Resolves the community via [`FederationDirectory::lookup_community`]. A
/// community **not locally known** is out of scope — `Ok(())` (fail-open): the
/// substrate cannot resolve an absent record's moderators, and a
/// federation-tier row keyed on it is governed by that peer's own admission
/// gate; the known-community record admission gate is the authoritative point.
/// A known community runs the full existence + infrastructure-carve-out check.
pub async fn check_no_moderator_federate_admission_by_id(
    directory: &dyn super::FederationDirectory,
    community_id: &str,
) -> Result<(), Error> {
    if community_id.is_empty() {
        return Ok(());
    }
    let Some(community) = directory.lookup_community(community_id).await? else {
        return Ok(());
    };
    check_no_moderator_federate_admission(directory, &community).await
}

/// v12.5.0 (CIRISPersist#238, CC 4.5.4 / §11.11) — the `put_attestation` entry
/// point for the §11.11 federation-apply re-check (point ii). A
/// **federation-tier** attestation keyed on a community `C` is a "federation
/// apply step keyed on C"; it is refused if `C` has no live `moderate`-holder
/// ([`check_no_moderator_federate_admission_by_id`]).
///
/// # Keying — what "keyed on C" means for an attestation row (v13.0.0, #369)
///
/// §11.11 requires the re-check on **every** federation apply step keyed on
/// `C`, not only rows that ride one envelope convention. A federation-tier
/// row is keyed on `C` when it references `C` under ANY of the substrate's
/// own community-reference shapes:
///
/// 1. **Envelope fields** — `community_id` (the CEG §11.10 moderation-gate
///    shape, [`check_delegated_duty_scores_admission`]'s keying),
///    `community_key_id` (the [`Community`](crate::federation::types::Community)
///    record / CC 3.2 steward-binding-gate field name), and `cohort_key_id`
///    (the #249 Cut G4 membership-change event field name). Each is honored
///    when present as a string.
/// 2. **Row endpoints** — `attesting_key_id` / `attested_key_id` resolving as
///    a stored community (`lookup_community` hit). This is how
///    community-MEMBERSHIP attestations reference their community with no
///    literal envelope field: a community's own key IS a `federation_keys`
///    row, and the scope read-gate already treats the attestation *subject*
///    as the membership target ("`federation_attestations` carries
///    `cohort_scope` but no separate `cohort_target_id`, so the subject
///    doubles as the membership target" — `list_attestations_for`). A row
///    attested TO `C` (membership / scores-on-community) or emitted BY `C`
///    (community-signed roster claims) is a federation apply step keyed on
///    `C`.
/// 3. **`subject_key_ids` entries** resolving as stored communities — the
///    CEG 0.6 §4.2 consent-subject shape (the same subject set the §11.10
///    duty-holder composition folds community moderators into).
///
/// A no-op (`Ok(())`) for:
/// - **local-tier** rows — a local-tier write is private to the producing
///   occurrence and not a federation apply step (CC 5.3.2.2), and
/// - rows referencing **no** community under any shape above (not keyed on a
///   community: every candidate either absent or **not locally known** —
///   out of scope, fail-open, per
///   [`check_no_moderator_federate_admission_by_id`]; an ordinary
///   key-to-key attestation costs two `lookup_community` misses and passes
///   untouched).
///
/// A founder appointment (`delegates_to(moderate)` keyed on C) is NOT
/// chicken-and-egg-blocked: a steward-bound founder is already a zero-hop named
/// moderator, so `C` is not moderator-less at that point; and a non-steward-
/// bound founder could not root a moderator via the appointment anyway (the
/// walk requires a steward-bound root). Verify-before-mutation (AV-9) — wired
/// alongside the other shared admission gates on every backend's
/// `put_attestation`, before the row is hashed + INSERTed.
pub async fn check_no_moderator_federate_apply(
    directory: &dyn super::FederationDirectory,
    row: &super::Attestation,
) -> Result<(), Error> {
    // Only federation-tier rows are a federation apply step.
    if row.tier != crate::federation::types::attestation_tier::FEDERATION {
        return Ok(());
    }
    // Collect every community reference the row carries (deduplicated —
    // a row naming C under several shapes re-checks it once).
    let mut candidates: Vec<&str> = Vec::new();
    for field in ["community_id", "community_key_id", "cohort_key_id"] {
        if let Some(cid) = row.attestation_envelope.get(field).and_then(|v| v.as_str()) {
            if !cid.is_empty() && !candidates.contains(&cid) {
                candidates.push(cid);
            }
        }
    }
    for endpoint in [row.attesting_key_id.as_str(), row.attested_key_id.as_str()] {
        if !endpoint.is_empty() && !candidates.contains(&endpoint) {
            candidates.push(endpoint);
        }
    }
    for sid in &row.subject_key_ids {
        if !sid.is_empty() && !candidates.contains(&sid.as_str()) {
            candidates.push(sid);
        }
    }
    for cid in candidates {
        check_no_moderator_federate_admission_by_id(directory, cid).await?;
    }
    Ok(())
}

/// v13.0.0 (CIRISPersist#369, CC 4.5.4 / §11.11) — the directly drivable
/// federate-admission **verdict** over one community id: exactly the decision
/// [`check_no_moderator_federate_apply`] takes for a federation apply step
/// keyed on `community_id`, returned as data instead of an error so a
/// conformance/consumer layer can stage the gate without constructing a full
/// federation flow. Verdict JSON:
///
/// - `{"admitted": true, "community_known": false}` — not locally known ⇒
///   out of scope, fail-open (the peer's own admission gate governs it);
/// - `{"admitted": true, "community_known": true}` — a live `moderate`-holder
///   resolves (or the authorized-infrastructure carve-out applies) ⇒ `C` may
///   federate at moderated capability;
/// - `{"admitted": false, "community_known": true, "reason":
///   "federation_community_no_moderator"}` — §11.11 rule-3 fail-secure: no
///   live steward-bound authority root ⇒ MUST NOT federate at moderated
///   capability.
///
/// Read-only — never mutates; substrate read errors propagate as `Err`.
pub async fn no_moderator_federate_verdict(
    directory: &dyn super::FederationDirectory,
    community_id: &str,
) -> Result<serde_json::Value, Error> {
    let Some(community) = directory.lookup_community(community_id).await? else {
        return Ok(serde_json::json!({ "admitted": true, "community_known": false }));
    };
    match check_no_moderator_federate_admission(directory, &community).await {
        Ok(()) => Ok(serde_json::json!({ "admitted": true, "community_known": true })),
        Err(err @ Error::CommunityHasNoModerator { .. }) => Ok(serde_json::json!({
            "admitted": false,
            "community_known": true,
            "reason": err.kind(),
        })),
        Err(other) => Err(other),
    }
}

/// v8.7.1 (CIRISPersist#233, CEG RC25/RC26 §11.11) — is key `k` a **named
/// moderator** of community `community_id` for `duty` (`moderate` /
/// `takedown` / `review`)? True iff a live scope-bearing `delegates_to`
/// chain `root →* k` exists where:
///   - every edge bears `duty` scope (the [`MODERATION_DUTY`] walk:
///     `⊆`-parent attenuation + `sub_delegation`-gated deputization +
///     depth ≤ 5 + no `withdraws`-revoked edge), AND
///   - `root ∈ authority_set(community_id)` — the community's founders /
///     `consensus_protocol` signers (resolved from the
///     [`Community`](crate::federation::types::Community) record via
///     [`FederationDirectory::lookup_community`]), AND
///   - `is_steward_bound(root)`.
///
/// A zero-hop appointment (`root == k`, root directly in the authority set)
/// is admitted — a founder IS a named moderator of their own community. The
/// §11.11 merit auto-promotion emits the SAME appointment shape (a
/// `delegates_to` from a community authority), so this one predicate covers
/// both the explicit-appointment and merit-promotion cases.
///
/// `community_id` is the community's `community_key_id`. Returns `false`
/// (never errors) when the community is unknown, declares no authority set,
/// or no steward-bound authority reaches `k` — fail-closed.
///
/// [`MODERATION_DUTY`]: DelegationWalkPolicy::MODERATION_DUTY
pub async fn is_named_moderator(
    directory: &dyn super::FederationDirectory,
    k: &str,
    community_id: &str,
    duty: &str,
) -> Result<bool, Error> {
    let authority = community_authority_set(directory, community_id).await?;
    let target: std::collections::HashSet<String> = std::iter::once(k.to_owned()).collect();
    for root in authority {
        // Steward-binding of the root is REQUIRED (§11.11 → §5.6.8.10).
        if !is_steward_bound(directory, &root).await? {
            continue;
        }
        // Zero-hop: the steward-bound authority IS the named moderator.
        if root == k {
            return Ok(true);
        }
        // Walk-down from the authority root to k under the §11.10 policy.
        if issuer_reaches_target_via_scoped_delegation(
            directory,
            &root,
            &target,
            duty,
            MAX_MODERATION_DELEGATION_DEPTH,
            DelegationWalkPolicy::MODERATION_DUTY,
        )
        .await?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// #249 Cut B — the **enumeration** of [`is_named_moderator`]: the FULL
/// named-moderator set of community `community_id` for `duty` — the
/// steward-bound authority roots ∪ every delegate they reach via a live
/// `duty`-scoped `delegates_to` chain (the same [`MODERATION_DUTY`] walk
/// `is_named_moderator` probes, but accumulated instead of target-tested).
///
/// For each root in the community authority set
/// ([`community_authority_set`]) that [`is_steward_bound`], the root itself is
/// a named moderator (zero-hop founder) AND every key it reaches under the
/// §11.10 scoped walk
/// ([`enumerate_scoped_delegation_reach`]) is one too. Returns the deduped
/// key_id set (sorted for a deterministic surface). Consistency with the
/// predicate: `is_named_moderator(k, …)` ⟺ `k ∈ moderators_of(…)`, because
/// both compose the SAME authority set, the SAME steward-binding gate, and the
/// SAME scoped-reach walk.
///
/// (CIRISPersist#593) The last of those three was a claim about two hand-mirrored
/// BFS copies until #593 collapsed them into [`scoped_delegation_reach`] — a fold
/// repaired in the predicate and not the enumerator falsified this `⟺` while the
/// build stayed green. `moderation_walk_liveness_parity_*_593` asserts it at
/// every state transition, so it cannot silently become false again.
///
/// Fail-closed: an unknown community / no steward-bound authority yields the
/// empty set (no named moderators), never an error.
pub async fn moderators_of(
    directory: &dyn super::FederationDirectory,
    community_id: &str,
    duty: &str,
) -> Result<Vec<String>, Error> {
    let authority = community_authority_set(directory, community_id).await?;
    let mut out: std::collections::HashSet<String> = std::collections::HashSet::new();
    for root in authority {
        // Steward-binding of the root is REQUIRED (§11.11 → §5.6.8.10) — a
        // non-steward-bound authority roots no moderation duty.
        if !is_steward_bound(directory, &root).await? {
            continue;
        }
        // Zero-hop: the steward-bound authority IS a named moderator.
        // Then every delegate it reaches under the duty-scoped walk.
        let reach = enumerate_scoped_delegation_reach(
            directory,
            &root,
            duty,
            MAX_MODERATION_DELEGATION_DEPTH,
            DelegationWalkPolicy::MODERATION_DUTY,
        )
        .await?;
        out.insert(root);
        out.extend(reach);
    }
    let mut out: Vec<String> = out.into_iter().collect();
    out.sort();
    Ok(out)
}

/// CIRISPersist#591 — the **APPOINTED** moderator set of community
/// `community_id` for `duty`: the steward-bound **founders** and every key they
/// reach under the same §11.10 `duty`-scoped `delegates_to` walk.
///
/// # Three functions, three questions — read the table before adding a fourth
///
/// | question | function | set |
/// |---|---|---|
/// | who may **appoint** a moderator? | [`duty_holders_for_community`] | the steward-bound authority set — founders, **plus every current member for any non-`founder_only` protocol** |
/// | who **counts as** a named moderator (§11.11 existence)? | [`moderators_of`] | that same widened authority set ∪ its `duty`-scoped delegates |
/// | who has **been appointed** to the duty? | **this function** | founders ∪ their `duty`-scoped delegates |
///
/// For a `founder_only` community all three coincide, which is why the widening
/// was invisible for as long as §11.11's only consumer was the
/// moderator-EXISTENCE gate ([`check_no_moderator_federate_admission`]). There
/// the widened reading is correct and deliberate: a community with any
/// steward-bound member *can* appoint, so it is not moderator-less.
///
/// It is NOT correct for a **duty** question. Every cohort that adopts
/// `reverse_quorum:*` is by construction non-`founder_only`, so `moderators_of`
/// on that plane returns the ENTIRE steward-bound roster — and a "steward tier"
/// whose membership equals the roster is not a tier. Worse than useless:
/// [`reverse_quorum`](super::reverse_quorum)'s escalation is blocked by a
/// duty-holder ruling, so a roster-wide steward set would let any member rule
/// on any objection and freeze the commons' escalated undo forever — the exact
/// 1-of-N capability grant the accord-ops invariant forbids. Reading an
/// appointment-ELIGIBILITY set as an appointed-duty set is axis fusion; this is
/// the split.
///
/// Fail-closed, exactly like [`moderators_of`]: an unknown community, a
/// community with no founder-tagged member, or a founder that is not
/// [`is_steward_bound`] yields the empty set (no appointed moderators), never
/// an error. An empty result is a legible fact, not an error — see
/// [`StewardTierStanding::NoDutyHolders`](super::reverse_quorum::StewardTierStanding::NoDutyHolders).
pub async fn appointed_moderators_of(
    directory: &dyn super::FederationDirectory,
    community_id: &str,
    duty: &str,
) -> Result<Vec<String>, Error> {
    let Some(community) = directory.lookup_community(community_id).await? else {
        return Ok(Vec::new());
    };
    let mut out: std::collections::HashSet<String> = std::collections::HashSet::new();
    for member in &community.members {
        if member.role.as_deref() != Some(MEMBER_ROLE_FOUNDER) {
            continue;
        }
        // The SAME steward-binding gate `moderators_of` applies to its roots
        // (§11.11 → §5.6.8.10) — a non-steward-bound founder roots no duty.
        if !is_steward_bound(directory, &member.key_id).await? {
            continue;
        }
        // …and the SAME duty-scoped walk. One reachability predicate, two root
        // sets — never two walks that could drift on what a delegated duty is.
        let reach = enumerate_scoped_delegation_reach(
            directory,
            &member.key_id,
            duty,
            MAX_MODERATION_DELEGATION_DEPTH,
            DelegationWalkPolicy::MODERATION_DUTY,
        )
        .await?;
        out.insert(member.key_id.clone());
        out.extend(reach);
    }
    let mut out: Vec<String> = out.into_iter().collect();
    out.sort();
    Ok(out)
}

/// v8.7.1 (CIRISPersist#233, CEG RC25/RC26 §11.11) — the **authority set**
/// of community `community_id`: the keys empowered to appoint moderators.
/// Per §8.1.13.3 + §5.6.8.9 the community record carries a member roster
/// (`role`-tagged) and a `consensus_protocol`; the authority set is the
/// roster members whose `role` marks them a founder / consensus signer:
///
///   - For `founder_only` (the default-strict protocol): members tagged
///     [`MEMBER_ROLE_FOUNDER`].
///   - For any OTHER `consensus_protocol` (`unanimous` / `majority` /
///     `quorum:*` / `weighted:*` / `custom:*`): every current member is a
///     consensus signer — the whole roster is the authority set (persist
///     does not adjudicate the signature-count threshold here; that is the
///     appointment ceremony's job — §5.6.8.9 normative-honesty).
///
/// Founders are always included regardless of protocol. Returns an empty
/// set when the community is unknown — fail-closed (no authority ⇒ no named
/// moderators).
async fn community_authority_set(
    directory: &dyn super::FederationDirectory,
    community_id: &str,
) -> Result<std::collections::HashSet<String>, Error> {
    let Some(community) = directory.lookup_community(community_id).await? else {
        return Ok(std::collections::HashSet::new());
    };
    let founder_only =
        community.consensus_protocol == crate::federation::types::consensus_protocol::FOUNDER_ONLY;
    let mut out = std::collections::HashSet::new();
    for m in &community.members {
        let is_founder = m.role.as_deref() == Some(MEMBER_ROLE_FOUNDER);
        if is_founder || !founder_only {
            out.insert(m.key_id.clone());
        }
    }
    Ok(out)
}

/// v8.7.1 (CIRISPersist#233, CEG §5.6.8.9) — the `role` tag marking a
/// community/family member as a founder (the §5.6.8.9 open-vocab
/// `founder` value). Founders are always in the community authority set
/// regardless of `consensus_protocol`.
pub const MEMBER_ROLE_FOUNDER: &str = "founder";

/// v8.7.1 (CIRISPersist#233, CEG RC24/RC25 §11.10) — the FULL §11.10
/// admit-iff gate. Admit the moderation action IFF the `signer`
/// (`attesting_key_id`) is authorized over the `duty_holders` of the
/// target:
///
///   (a) **as-self** — `signer ∈ duty_holders` (it itself holds the duty
///       over the target), OR
///   (b) **delegated** — ∃ `root ∈ duty_holders` that `is_steward_bound`
///       AND reaches `signer` via a live `duty`-scoped chain under the
///       [`MODERATION_DUTY`] walk policy (every edge `scope ⊇ {duty}`,
///       `⊆`-parent attenuation, `sub_delegation`-gated deputization,
///       depth ≤ 5, no `withdraws`-revoked edge).
///   else REJECT with [`Error::DelegatedScopeUnauthorized`] (stable
///   `kind()` token `federation_delegated_scope_unauthorized`).
///
/// **Absence is never an admit condition** — `duty_holders` empty ⇒ no
/// principal holds the duty ⇒ REJECT (the v8.7.0 bypass, closed). The
/// per-edge scope filter gives the load-bearing scope-isolation property
/// (a `consent_revocation`-only chain cannot drive a `takedown`).
///
/// `duty_holders` is the set of keys that natively hold `duty` over the
/// specific target (resolved per-primitive by the caller —
/// [`duty_holders_for_content`] / [`duty_holders_for_community`]). The
/// error's `on_behalf_of` field carries the target descriptor for audit
/// (the model no longer has a principal field).
///
/// [`MODERATION_DUTY`]: DelegationWalkPolicy::MODERATION_DUTY
pub async fn check_moderation_admission(
    directory: &dyn super::FederationDirectory,
    signer: &str,
    duty_holders: &std::collections::HashSet<String>,
    duty: &str,
    target_descriptor: &str,
) -> Result<(), Error> {
    // (a) as-self: signer itself holds the duty over the target.
    if duty_holders.contains(signer) {
        return Ok(());
    }
    // (b) delegated: an steward-bound duty-holder root reaches signer via a
    //     live duty-scoped chain (§11.10 attenuation + sub_delegation).
    let target: std::collections::HashSet<String> = std::iter::once(signer.to_owned()).collect();
    for root in duty_holders {
        if !is_steward_bound(directory, root).await? {
            continue;
        }
        if issuer_reaches_target_via_scoped_delegation(
            directory,
            root,
            &target,
            duty,
            MAX_MODERATION_DELEGATION_DEPTH,
            DelegationWalkPolicy::MODERATION_DUTY,
        )
        .await?
        {
            return Ok(());
        }
    }
    Err(Error::DelegatedScopeUnauthorized {
        signer: signer.to_string(),
        on_behalf_of: target_descriptor.to_string(),
        scope: duty.to_string(),
    })
}

/// v8.7.2 (CIRISPersist#233 follow-on, CEG RC27 §11.10; CIRISRegistry#96)
/// — `subject_of(content_sha256)`: the SIGNED subject set behind a content
/// hash. The §11.10 pin:
///
///   `subject_of(content_sha256)` ≔ the union of the `subject_key_ids`
///   signed INSIDE the content-establishing `scores` Contribution(s) whose
///   envelope binds `content_sha256` (via `evidence_refs`).
///
/// The subject set is the producer's signed assertion of who the content is
/// ABOUT — it is NOT a value a later third party (a takedown/moderation
/// payload) can self-declare. This is the load-bearing distinction that
/// closes the self-declaration spoof: a signer claiming
/// `subject_key_ids = [self]` in a takedown payload gains NO subject-self
/// authority unless `self` appears in the content's own signed subjects.
///
/// # Fail-secure
///
/// Returns the **empty set** when no establishing attestation is locally
/// resolvable (`subject_of` undetermined). An empty set means the
/// subject-self admission clause `attesting_key_id ∈ subject_of(...)`
/// cannot hold — subject-self FAILS. Absence never admits; the named-mod
/// path (b) still applies independently
/// ([`duty_holders_for_content`] unions the two).
///
/// `content_sha256` is hex-validated (lowercase hex-64) before the lookup;
/// a malformed hash yields the empty set (it can bind no establishing
/// attestation). The resolution is the
/// [`FederationDirectory::attestations_binding_content`] `evidence_refs`
/// scan — see that method for the per-backend query.
///
/// [`FederationDirectory::attestations_binding_content`]: super::FederationDirectory::attestations_binding_content
pub async fn subject_of_content(
    directory: &dyn super::FederationDirectory,
    content_sha256: &str,
) -> Result<std::collections::HashSet<String>, Error> {
    // Hex-validate (lowercase hex-64) — a malformed hash can bind no
    // establishing attestation; the empty set is the fail-secure answer.
    if content_sha256.len() != 64
        || !content_sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Ok(std::collections::HashSet::new());
    }
    let mut subjects = std::collections::HashSet::new();
    for att in directory
        .attestations_binding_content(content_sha256)
        .await?
    {
        subjects.extend(att.subject_key_ids.iter().cloned());
    }
    Ok(subjects)
}

/// v8.7.2 (CIRISPersist#233 follow-on, CEG RC27 §11.10; CIRISRegistry#96)
/// — the duty-holders of a **content target**
/// (`takedown_notice{content_sha256}` / `moderation:*` /
/// `reconsideration:*` over content): the content's SIGNED subjects ∪ the
/// named moderators of the content's community.
///
///   `duty_holders(content_sha256) =
///        subject_of(content_sha256)
///      ∪ { K : is_named_moderator(K, community_id, duty) }`
///
/// **v8.7.2 spoof closure.** The subject half is now
/// [`subject_of_content`] — the `subject_key_ids` signed INSIDE the
/// content-establishing `scores` attestation, resolved from
/// `content_sha256`. It is NO LONGER the takedown/moderation payload's
/// self-declared `subject_key_ids` (which a signer could set to
/// `[self]` to spoof subject-self authority; that field is now
/// advisory/routing-only). Fail-secure: when no establishing attestation
/// is locally held, `subject_of` is empty and only the named-mod path can
/// admit.
///
/// `community_id` is the content's declared community (empty ⇒ no
/// community moderators, only subjects). The named-moderator half resolves
/// only the AUTHORITY ROOTS into the holder set — the per-signer walk-down
/// is then done by [`check_moderation_admission`]; here we materialize the
/// roots (the community authority set, steward-bound) so a signer who IS a
/// named moderator is admitted as-self.
pub async fn duty_holders_for_content(
    directory: &dyn super::FederationDirectory,
    content_sha256: &str,
    community_id: &str,
    duty: &str,
) -> Result<std::collections::HashSet<String>, Error> {
    let mut holders = subject_of_content(directory, content_sha256).await?;
    holders.extend(named_moderator_holders(directory, community_id, duty).await?);
    Ok(holders)
}

// v22.0.0 (CIRISPersist#543 finding 2b) — `duty_holders_from_signed_subjects`
// was DELETED here, not merely un-cited.
//
// It unioned the row's OWN `subject_key_ids` into the duty-holder (authority)
// set on the report→`scores` path. v21.11.0 (#517) established that this is
// unsound — the §11.10 "already signed-state" argument proves the SIGNER is not
// spoofed, it does NOT prove the SUBJECT claim is genuine (**integrity is not
// authority**), so any Rooted producer could name THEMSELVES subject and self-
// authorize a `moderation:*` / `reconsideration:*` action. #517 replaced the
// call site with `duty_holders_for_community` (named moderators ONLY, CC 4.5.5)
// but left this function `pub` "for a future referenced-action resolver".
//
// #543's citation-liveness gate then found the manifest still citing it as a
// live processor — labelled, in the manifest's own words, "the drift site".
// A `pub` helper that computes an authority set from caller-declared data,
// retained with no caller, is a loaded gun: the next caller re-introduces the
// vulnerability, and the citation made it look enforced. If a referenced-action
// resolver is ever built, it must derive authority from persist's OWN verified
// state (see `feedback_authority_from_own_verified_state`) — not from a set
// handed in by the row being admitted.

/// v30.10.0 (CIRISPersist#632) — the **federation-scope** duty-holder resolver:
/// who may act on a key admitted to the FEDERATION, as opposed to one inside a
/// community.
///
/// # The gap this closes
///
/// De-admitting a federation directory key is neither content moderation nor
/// community moderation, so neither existing resolver applies and
/// `duty_holders` came back empty for the whole class — meaning the emission
/// could never be admitted, as-self or by delegation. That is not a policy
/// refusal, it is an unreachable surface: 61 exposed keys with no expressible
/// act (CIRISServer#383).
///
/// # NO steward-bound filter, and the asymmetry is deliberate
///
/// [`duty_holders_for_community`] intersects its authority set with
/// [`is_steward_bound`], because a community member may be a node or an agent
/// and CC 3.2 requires authority to trace to an accountable human.
///
/// Copying that here returns the EMPTY SET and reproduces the bug one level up.
/// Accord holders are `identity_type: accord_holder`, not `user` — verified
/// against the baked seed, where A1/B1/C1 are all accord-holder-only — and
/// `steward_bindings_of` clause (1) self-anchors only a `user`-role key. Nothing
/// steward-binds an accord holder, so the filter would erase the roster.
///
/// It should not be there regardless: `accord_holder` is
/// [`ConferralMode::HardwareAttested`](super::types::identity_type::ConferralMode)
/// — established by ceremony at registration behind a co-scrub quorum, which is
/// STRICTLY STRONGER than the steward-bound heuristic. Asking the constitutional
/// root to prove it has a root is a category error.
///
/// # The LIVE roster, not the pinned anchor
///
/// Read through [`FederationDirectory::active_family_members`], so the set is
/// revocation-folded: a holder removed from the accord stops being a duty-holder
/// immediately. Same reasoning `family_quorum_over` documents for charter
/// quorum — a roster that once reached a threshold must stop reaching it.
///
/// # An unresolvable roster is a REFUSAL, not an empty set
///
/// If the accord family cannot be resolved this returns
/// [`Error::InvalidArgument`], never `Ok(empty)`. Empty-set-as-refusal is the
/// exact shape that let `tier_4_deadmit` pass for years while reading absence of
/// evidence as evidence of authority — the bypass v30.8.0 closed. A node that
/// cannot see the accord must say so, not silently conclude nobody may act.
pub async fn duty_holders_for_federation(
    directory: &dyn super::FederationDirectory,
    _duty: &str,
) -> Result<std::collections::HashSet<String>, Error> {
    let family = ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    let members = directory.active_family_members(family).await.map_err(|e| {
        Error::InvalidArgument(format!(
            "federation-scope duty-holders are the live accord roster, and this node cannot \
                 resolve family {family:?}: {e}. Returning an empty holder set here would read \
                 as \"nobody may act\" — the absent-⇒-admit shape inverted (CIRISPersist#632)."
        ))
    })?;
    Ok(members.into_iter().map(|m| m.key_id).collect())
}

/// v8.7.1 (CIRISPersist#233, CEG §11.10) — the duty-holders of a
/// **community-scoped action** with no content subject (a bare
/// `moderation:*` / `reconsideration:*` over a community): the named
/// moderators of that community for `duty`.
pub async fn duty_holders_for_community(
    directory: &dyn super::FederationDirectory,
    community_id: &str,
    duty: &str,
) -> Result<std::collections::HashSet<String>, Error> {
    named_moderator_holders(directory, community_id, duty).await
}

/// Materialize the named-moderator AUTHORITY ROOTS for `community_id` /
/// `duty` into the duty-holder set: each steward-bound member of the
/// community authority set. (The full `is_named_moderator` relation —
/// including delegates reached from these roots — is then enforced by
/// [`check_moderation_admission`]'s per-signer walk-down rooted at these
/// holders.) Empty community / no steward-bound authority ⇒ empty set.
async fn named_moderator_holders(
    directory: &dyn super::FederationDirectory,
    community_id: &str,
    _duty: &str,
) -> Result<std::collections::HashSet<String>, Error> {
    if community_id.is_empty() {
        return Ok(std::collections::HashSet::new());
    }
    let authority = community_authority_set(directory, community_id).await?;
    let mut holders = std::collections::HashSet::new();
    for root in authority {
        if is_steward_bound(directory, &root).await? {
            holders.insert(root);
        }
    }
    Ok(holders)
}

/// v8.7.1 (CIRISPersist#233, CEG RC24/RC25 §11.10) — `put_attestation`
/// entry point for the **report → `scores`** half of the moderation gate.
/// A no-op (`Ok(())`) for any attestation that is not a `scores` row on a
/// `moderation:*` or `reconsideration:*` dimension; for those it resolves
/// the governing duty (`moderate` / `review`), computes the target's
/// duty-holders from the row's `subject_key_ids` + the envelope
/// `community_id`, and runs [`check_moderation_admission`] with the row's
/// `attesting_key_id` as the signer.
///
/// Verify-before-mutation (AV-9): runs alongside `check_withdraws_admission`
/// BEFORE the row is hashed + INSERTed — a rejected emission leaves no
/// trace. Mirrors exactly how/where the consent_revocation gate is wired
/// into the put_attestation path on every backend.
pub async fn check_delegated_duty_scores_admission(
    directory: &dyn super::FederationDirectory,
    row: &super::Attestation,
) -> Result<(), Error> {
    if row.attestation_type != attestation_type::SCORES {
        return Ok(());
    }
    let Some(dimension) = envelope_dimension(&row.attestation_envelope) else {
        return Ok(());
    };
    let duty = if dimension.starts_with(MODERATION_DIMENSION_PREFIX) {
        DELEGATION_SCOPE_MODERATE
    } else if dimension.starts_with(RECONSIDERATION_DIMENSION_PREFIX) {
        DELEGATION_SCOPE_REVIEW
    } else if dimension.starts_with(QUARANTINE_DIMENSION_PREFIX) {
        // v25.1.0 (CIRISPersist#570 ask 2/5) — the third arm. A quarantine
        // marker takes something away, so it is gated on the ONE scope that
        // authorizes removal, walked under exactly the same policy as the two
        // emit duties above (there is no laxer path for the harsher op).
        DELEGATION_SCOPE_SLASH
    } else {
        return Ok(());
    };
    let community_id = row
        .attestation_envelope
        .get("community_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // v21.11.0 (CIRISPersist#517, CC 4.5.5) — resolve duty-holders from the
    // community's NAMED MODERATORS ONLY. The prior code seeded the admissible
    // set from the row's OWN `subject_key_ids`, so any Rooted producer could
    // file an admissible `reconsideration:*` / `moderation:*` over any
    // community action by naming THEMSELVES as subject — CC 4.5.5's
    // target→duty-holder table authorizes NO subject-self clause for these two
    // dimensions (only `takedown_notice`, on a DIFFERENT content path, gets
    // `subject_of(content_sha256) ∪ is_named_moderator`). The §11.10 "already
    // signed-state, leave it" note proves the SIGNER isn't spoofed; it does NOT
    // prove the SUBJECT claim is genuine — integrity ≠ authority. If a
    // subject-self carve-out is ever intended it must resolve against the
    // REFERENCED prior action's signed subjects (a `subject_of`-style
    // fail-secure resolver keyed on `references_attestation_id`), never from
    // the row's own envelope. (`duty_holders_from_signed_subjects` is retained
    // for that future referenced-action resolver; it is no longer reachable
    // from this self-declared path.)
    // v30.10.0 (CIRISPersist#632) — SCOPE SELECTS THE RESOLVER.
    //
    // An act naming a `community_id` is community-scoped and resolves its
    // duty-holders from that community's authority set. An act naming NO
    // community is FEDERATION-scoped — de-admitting a key admitted to the
    // federation is neither content nor community moderation — and resolves
    // from the live accord roster instead.
    //
    // Before this, the community resolver was hardcoded, so a federation-scope
    // act got `community_id == ""` ⇒ empty holder set ⇒ never admissible, as-self
    // or by delegation. That is an unreachable surface, not a policy: 61 exposed
    // keys with no expressible act (CIRISServer#383).
    //
    // GATED ON THE QUARANTINE ARM, not merely on an empty `community_id`.
    //
    // `moderation:*` and `reconsideration:*` are community acts. One of those
    // arriving without a community is MALFORMED, and its existing refusal
    // (`DelegatedScopeUnauthorized`, via an empty community authority set) is
    // correct. Routing them to the federation resolver changed that refusal into
    // `InvalidArgument` on any node without the accord seeded — five moderation
    // tests caught it, and they were right to.
    //
    // `quarantine:*` is the removal arm — `slash` — and a de-admission with no
    // community IS the federation scope. That is the only class that had no
    // resolver.
    //
    // Note what does NOT change: an act that names a community it is not
    // authorised in still fails through the community resolver. This adds a
    // resolver for a scope that had none; it does not give anyone a second try
    // at a scope that refused them.
    let duty_holders =
        if community_id.is_empty() && dimension.starts_with(QUARANTINE_DIMENSION_PREFIX) {
            duty_holders_for_federation(directory, duty).await?
        } else {
            duty_holders_for_community(directory, community_id, duty).await?
        };
    check_moderation_admission(
        directory,
        &row.attesting_key_id,
        &duty_holders,
        duty,
        dimension,
    )
    .await
}

/// v9.0.0 (CIRISPersist#236, CC 4.4.3.4.3 / CC 1.13.5) — the
/// reject-agency-on-node-key gate: the `put_attestation` entry point that
/// makes "infrastructure must not have agency" cryptographically enforced.
///
/// A no-op (`Ok(())`) for any row that is NOT a
/// [`attestation_type::DELEGATES_TO`]. For a `delegates_to` it resolves the
/// recipient's (`attested_key_id`'s) `identity_type` via
/// [`FederationDirectory::lookup_public_key`]; the gate **only constrains a
/// recipient that resolves to a `node`-ONLY identity** (the resolved
/// `identity_type` set contains `node` and NOTHING else — a `{node}` key,
/// not a `{node,agent}` hybrid). For such a node-only recipient the
/// delegation's [`delegation_scope_set`] MUST satisfy
/// [`scopes_are_infra_only`]; otherwise the row is REJECTED with
/// [`Error::NodeAgencyForbidden`] (CC 4.4.3.4.3) and never stored.
///
/// # Unresolved / non-node recipients (design decision)
///
/// - **Recipient does not resolve** (`lookup_public_key` ⇒ `None`): the
///   gate **passes** — an unregistered recipient is out of scope for THIS
///   gate (it only constrains a *known* node key). This cannot be used to
///   bypass the property: every backend's `put_attestation` independently
///   FK-rejects a `delegates_to` whose `attested_key_id` does not exist in
///   `federation_keys`, so an unresolved recipient can never be persisted
///   at all — and once a key IS registered as `node` it resolves here and
///   the gate fires. A node key can therefore never receive an agency
///   delegation.
/// - **Recipient resolves to a non-node identity** (`agent`, `user`, a
///   `{node,agent}` hybrid, …): the gate **passes** (returns `Ok(())`).
///   The gate ONLY constrains pure-node recipients — it does not
///   over-reject `agency:*` on a brain/agent key, which legitimately
///   carries agency (CC 1.13.5 is about *infrastructure*, not all keys).
///
/// Verify-before-mutation (AV-9): runs alongside the withdraws /
/// delegated-duty gates BEFORE the row is hashed + INSERTed — a rejected
/// emission leaves no trace. Mirrors exactly how the other shared
/// admission gates are wired into the `put_attestation` path on every
/// backend (memory / sqlite / postgres). Resolution uses the trait's own
/// `lookup_public_key`, which all three backends implement, so this is
/// backend-agnostic admission logic (no Backend-trait surface added).
pub async fn check_node_agency_admission(
    directory: &dyn super::FederationDirectory,
    row: &super::Attestation,
) -> Result<(), Error> {
    if row.attestation_type != attestation_type::DELEGATES_TO {
        return Ok(());
    }
    // Resolve the recipient's identity_type set. Only a recipient that
    // resolves to a *node-only* identity is constrained here.
    let Some(recipient) = directory.lookup_public_key(&row.attested_key_id).await? else {
        // Unresolved recipient: out of scope for this gate (and FK-rejected
        // downstream — it can never be persisted). See doc note.
        return Ok(());
    };
    // Test the identity_type *set*, robust to duplicate/whitespace/order
    // tokens (`"node,node"`, `"node, node"`). `parse_set` does NOT dedup,
    // so an equality check against `[NODE]` is bypassable by a repeated
    // token; collect into a `HashSet` and assert it is exactly `{node}`.
    let member_set: std::collections::HashSet<&str> =
        identity_type::parse_set(&recipient.identity_type)
            .into_iter()
            .collect();
    let is_node_only = member_set.len() == 1 && member_set.contains(identity_type::NODE);
    if !is_node_only {
        return Ok(());
    }
    let scopes = delegation_scope_set(&row.attestation_envelope);
    if scopes_are_infra_only(&scopes) {
        return Ok(());
    }
    // Reject: a node-only key may carry ONLY infra:* scopes. Report the
    // offending (non-infra) tokens, sorted for a stable error string.
    let mut offending_scopes: Vec<String> = scopes
        .into_iter()
        .filter(|s| !s.starts_with(super::types::delegation_scope::INFRA_PREFIX))
        .collect();
    offending_scopes.sort();
    Err(Error::NodeAgencyForbidden {
        attested_key_id: row.attested_key_id.clone(),
        offending_scopes,
    })
}

/// v11.5.0 (CIRISPersist#306, CC 3.2 / CC 1.15.6) — the **user-target
/// steward-binding gate**: the companion to [`check_node_agency_admission`]
/// for `delegates_to` rows whose TARGET resolves to a `user`-role identity.
///
/// The node/agency gate constrains node-targets; user-targets ("stewarding a
/// person") were otherwise unguarded. CC 3.2 narrows the admissible
/// user-target set to exactly **minor-guardianship**:
///
/// ```text
/// admit_user_steward_binding(delegates_to S -> T):
///   require  age_band(T) == minor                # ward is a proven minor
///   require  user ∈ S.identity_type              # steward is a user
///   require  age_band(S) == adult                # steward is a proven adult
///   require  S == delegates_to.attesting_key_id  # steward signed it
///   otherwise REJECT
/// ```
///
/// A no-op (`Ok(())`) for any row that is NOT a
/// [`attestation_type::DELEGATES_TO`], for an unresolved target (FK-rejected
/// downstream), or for a target that is NOT a `user`-role identity
/// (node/agent targets are governed by [`check_node_agency_admission`]). For
/// a user target:
///
/// - target age band `!= Minor` ⇒ REJECT (`target_is_self_sovereign` when
///   Adult — an adult is un-stewardable, CC 1.15.6; `target_age_unverified`
///   when Unknown — the presumption of sovereignty: no stewardship over
///   someone not PROVEN a minor);
/// - target is a proven Minor but the granter does not resolve ⇒ REJECT
///   (`granter_unresolved`);
/// - granter is not a `user` OR not a proven adult ⇒ REJECT
///   (`granter_not_adult_user` — a minor cannot be a guardian, a non-user
///   cannot be a guardian);
/// - else ADMIT (the legal minor-guardianship binding). `S ==
///   attesting_key_id` is structural on the emit path, so no separate signer
///   check is needed.
///
/// v11.9.0 (CIRISPersist#309, CC 3.4.12): an ADULT user target is no longer
/// rejected unconditionally — it is dispatched to
/// [`check_adult_incapacity_binding`], the single narrow aperture that admits
/// an attested-incapacitated adult under a scoped, bounded, independently-
/// attested fiduciary binding (and re-asserts `target_is_self_sovereign` when
/// no live incapacity is attested — the presumption of capacity).
///
/// Verify-before-mutation (AV-9): wired into every backend's
/// `put_attestation` immediately AFTER [`check_node_agency_admission`], so a
/// rejected emission leaves no trace. Backend-agnostic — resolution uses the
/// trait's own `lookup_public_key` + [`super::age::age_band`].
pub async fn check_user_target_steward_binding_admission(
    directory: &dyn super::FederationDirectory,
    row: &super::Attestation,
) -> Result<(), Error> {
    use super::age::{age_band, AgeBand};
    if row.attestation_type != attestation_type::DELEGATES_TO {
        return Ok(());
    }
    // v30.8.0 (CIRISConstitution#87) — **CONFERRAL IS NOT STEWARDSHIP.**
    //
    // This gate fired on EVERY `delegates_to` targeting a `user`, so a quorum
    // could not confer a moderation duty (`slash`, `moderate`, `takedown`,
    // `review`) on a named human: the grant was refused `target_age_unverified`
    // unless that human was a proven minor. The only way through was to register
    // moderators as `agent`/`primitive`/`accord_holder` — dressing a person as
    // infrastructure to get past a rule about persons, which CC 3.2 rc3 now
    // names as the ontological misclassification it was.
    //
    // The ruling's discriminator is CONSENT STRUCTURE, and it was already
    // ratified: T3's own-acceptance rule says no conferral, however strong its
    // ceremony, substitutes for the target's own acceptance. So **an act the
    // target must accept for itself cannot be custody of the target.**
    // Stewardship is custody over a key that CANNOT accept for itself (a node
    // or agent rooted in an accountable human, an adult under adjudicated
    // incapacity, a minor under guardianship); a capability conferral is a
    // consensual grant. Different acts, by their consent shape.
    //
    // PAIRED, not optional (CIRISPersist#541's two-lists discipline): this gate
    // and `steward_bindings_of` clause (3) key on the SAME predicate. Narrowing
    // one alone would let a conferral silently establish a stewardship relation
    // the other would have refused — a state the substrate can create but not
    // describe.
    //
    // WHAT THIS DELIBERATELY GIVES UP: the conflation was silently doing a
    // second job — for conferrals, this was an accidental AGE gate. Per the
    // ruling that duty is now explicit: a duty scope needing an age or
    // assurance floor declares it on its own CC 4.5.5 row via the CC 3.4.11
    // ladders, never inherits it from a custody rule. **Today no duty scope
    // declares one**, which is now a visible choice rather than an accident.
    // Resolve the target. An unresolved target is out of scope here (and
    // FK-rejected downstream — it can never be persisted).
    let Some(target) = directory.lookup_public_key(&row.attested_key_id).await? else {
        return Ok(());
    };
    let target_set: std::collections::HashSet<&str> =
        identity_type::parse_set(&target.identity_type)
            .into_iter()
            .collect();
    // Only USER-role targets are governed by THIS rule; node/agent targets go
    // through the node-agency gate.
    if !target_set.contains(identity_type::USER) {
        return Ok(());
    }
    // The target is a user. The default CC 3.2 rule admits ONLY a proven
    // minor (guardianship). An ADULT target is un-stewardable by default —
    // EXCEPT the single narrow CC 3.4.12 adult-incapacity aperture, which
    // this dispatches to. An unverified age is neither (presumption of
    // sovereignty).
    let target_band = age_band(directory, &row.attested_key_id).await?;
    // v30.8.0 (CIRISConstitution#87) — the discriminator applies PER AGE BAND,
    // because it is about who can accept for themselves.
    //
    // A **minor** cannot, so a delegation naming one is custody whether or not it
    // says so — guardianship is checked below exactly as before. Only an **adult**
    // can accept for itself, so for an adult an undeclared edge is a capability
    // conferral (giving a person a job) and not this gate's business.
    //
    // An earlier draft returned early on any non-custody envelope BEFORE resolving
    // age. That let an unmarked delegation to a MINOR through as a conferral —
    // the guardianship gate never ran. Caught by
    // `minor_guardianship_grant_and_withdraw_end_to_end`.
    if can_accept_for_itself(directory, &row.attested_key_id).await?
        && !is_custody_claim_envelope(&row.attestation_envelope)
    {
        return Ok(());
    }
    match target_band {
        AgeBand::Minor => { /* fall through to minor-guardianship checks */ }
        AgeBand::Adult => {
            // The adult-incapacity path is the ONLY way to steward-bind an
            // adult. It reasserts `target_is_self_sovereign` when no live
            // incapacity is attested (presumption of capacity).
            return check_adult_incapacity_binding(directory, row).await;
        }
        AgeBand::Unknown => {
            return Err(Error::UserTargetStewardBindingForbidden {
                target_key_id: row.attested_key_id.clone(),
                // Presumption of sovereignty (age axis): not PROVEN a minor,
                // and not PROVEN an adult (so not eligible for the incapacity
                // aperture either — that predicate requires age_band == adult).
                reason: "target_age_unverified",
            });
        }
    }
    // Target is a proven minor — require the granter is a proven adult user.
    let Some(granter) = directory.lookup_public_key(&row.attesting_key_id).await? else {
        return Err(Error::UserTargetStewardBindingForbidden {
            target_key_id: row.attested_key_id.clone(),
            reason: "granter_unresolved",
        });
    };
    let granter_is_adult_user =
        identity_type::set_contains(&granter.identity_type, identity_type::USER)
            && age_band(directory, &row.attesting_key_id).await? == AgeBand::Adult;
    if !granter_is_adult_user {
        return Err(Error::UserTargetStewardBindingForbidden {
            target_key_id: row.attested_key_id.clone(),
            reason: "granter_not_adult_user",
        });
    }
    // Admit the minor-guardianship binding (S == attesting_key_id structural).
    Ok(())
}

/// v11.9.0 (CIRISPersist#309, CC 3.4.12) — the **adult-incapacity
/// steward-binding** admission predicate: the third — and final — admissible
/// user-target case, and the single narrow aperture in the CC 3.2
/// un-stewardable-adult wall. Called by
/// [`check_user_target_steward_binding_admission`] only when the target `T`
/// resolves to a `user`-role identity with `age_band(T) == Adult`.
///
/// Admits `delegates_to(S -> T)` **only** when ALL hold (CC 3.4.12 admission
/// predicate); otherwise REJECTS with a stable reason token on
/// [`Error::UserTargetStewardBindingForbidden`]:
///
/// - **`target_is_self_sovereign`** — no LIVE `capacity_assurance:*:{d}:
///   incapacitated` for any domain (the **presumption of capacity**: absence
///   ⇒ full capacity ⇒ the un-stewardable default reasserts).
/// - **`scope_missing`** — the binding declares no scope (a scope-less adult
///   binding grants nothing checkable and cannot be `⊆` the attested loss).
/// - **`scope_exceeds_attested_domains`** — a scoped domain has no live
///   `:incapacitated` verdict (scope MUST be `⊆` the attested loss).
/// - **`capacity_reversible_not_excluded`** — a scoped incapacitated domain
///   lacks its mandatory `reversible_excluded` companion, and the acute T1
///   `reversible_pending` path does not apply (wrong tier / missing pending /
///   wrong legitimacy source).
/// - **`scope_touches_protected_domain`** — scope intersects
///   [`crate::federation::capacity::PROTECTED_NON_TRANSFERABLE`] (the
///   apophatic floor: contact / relational / voting / marriage / reproduction
///   are never delegable).
/// - **`attester_conflicted`** — a capacity assessor for a covered domain is
///   the steward `S` or the `petitioner` (assessor-independence; no one mints
///   the incapacity of a person they propose to steward).
/// - **`missing_legitimacy_source`** — `binding_legitimacy_source` is absent
///   or not one of {`prior_will_proxy`, `wa_due_process_quorum`,
///   `emergency_necessity_expedited`} (NEVER the steward's signature alone).
/// - **`missing_valid_until`** — no `valid_until` (mandatory expiry ⇒
///   fail-to-liberty).
/// - **`valid_until_unparseable`** — `valid_until` is not an ISO-8601 instant.
/// - **`valid_until_exceeds_review_cadence`** — the window exceeds
///   [`crate::federation::capacity::T2_REVIEW_CADENCE_DAYS`] (no window may
///   outrun periodic review).
///
/// **Fail-to-liberty** is enforced at READ time, not here: a binding whose
/// `valid_until` has lapsed is treated as non-live by
/// [`steward_bindings_of`], so the adult auto-re-sovereigns with no steward
/// assent (see that function). This gate only guarantees a mandatory,
/// bounded `valid_until` is present so the lapse mechanism can fire.
///
/// **Deliberately scoped down (CIRISPersist#309), tracked for follow-up:**
/// the `panel`-rung M-of-N independent-quorum requirement for continuing /
/// asset-bearing domains, the T1 retrospective-WA-audit HARD_DEADLINE + the
/// irreversible-acts prohibition, the ward's-champion / inalienable-channel
/// roles, and the supported-vs-substituted distinct-wire-shape check are
/// governance/temporal concerns above this admission chokepoint. This gate
/// enforces the structural core (per-domain incapacity + reversible exclusion,
/// scope containment, protected-domain exclusion, assessor independence vs
/// steward/petitioner, a mandatory bounded legitimacy source, and the
/// fail-to-liberty `valid_until`).
pub async fn check_adult_incapacity_binding(
    directory: &dyn super::FederationDirectory,
    row: &super::Attestation,
) -> Result<(), Error> {
    use super::age::{age_band, AgeBand};
    use crate::federation::capacity::{
        binding_field, is_protected_domain, legitimacy_source, tier, T2_REVIEW_CADENCE_DAYS,
    };
    let reject = |reason: &'static str| {
        Err(Error::UserTargetStewardBindingForbidden {
            target_key_id: row.attested_key_id.clone(),
            reason,
        })
    };
    let env = &row.attestation_envelope;

    // Gather the ward's live incapacity facts in a single pass.
    let facts =
        crate::federation::capacity::incapacity_facts(directory, &row.attested_key_id).await?;

    // (1) presumption of capacity: NO live incapacity attested anywhere ⇒ the
    // adult is sovereign, the CC 3.2 default reasserts. (Checked FIRST so a
    // capacitated adult target always reports `target_is_self_sovereign`.)
    if facts.incapacitated_domains.is_empty() {
        return reject("target_is_self_sovereign");
    }

    // The steward S must itself be an adult `user` (CC 3.4.12 "steward is a
    // user identity (adult)"). A minor / non-user cannot be a fiduciary.
    let steward_is_adult_user = match directory.lookup_public_key(&row.attesting_key_id).await? {
        Some(rec) => {
            identity_type::set_contains(&rec.identity_type, identity_type::USER)
                && age_band(directory, &row.attesting_key_id).await? == AgeBand::Adult
        }
        None => false,
    };
    if !steward_is_adult_user {
        return reject("granter_not_adult_user");
    }

    // (2) the delegated scope — the domains the steward may act in. Reuse the
    // shared `scope` reader (bare-string OR array-set). For an adult-incapacity
    // binding the scope tokens are decision-domains.
    let scope = delegation_scope_set(env);
    if scope.is_empty() {
        return reject("scope_missing");
    }

    // Whether the T1 acute path (reversible_pending in lieu of _excluded) is
    // available for this binding: tier == T1 AND legitimacy == emergency.
    let legit = env
        .get(binding_field::LEGITIMACY_SOURCE)
        .and_then(serde_json::Value::as_str);
    let binding_tier = env
        .get(binding_field::TIER)
        .and_then(serde_json::Value::as_str);
    let t1_path = binding_tier == Some(tier::T1_EMERGENCY_NECESSITY)
        && legit == Some(legitimacy_source::EMERGENCY_NECESSITY_EXPEDITED);

    // (3) scope ⊆ attested-incapacitated domains, each with reversible
    // exclusion (or the T1 pending path), and none protected.
    for d in &scope {
        if is_protected_domain(d) {
            return reject("scope_touches_protected_domain");
        }
        if !facts.incapacitated_domains.contains(d) {
            return reject("scope_exceeds_attested_domains");
        }
        let excluded = facts.reversible_excluded_domains.contains(d);
        let pending_ok = t1_path && facts.reversible_pending_domains.contains(d);
        if !excluded && !pending_ok {
            return reject("capacity_reversible_not_excluded");
        }
    }

    // (4) assessor independence: no capacity attester for the covered domains
    // may be the steward S or the petitioner (anti-capture). `S` is the
    // granter = attesting_key_id of the delegates_to.
    let steward = row.attesting_key_id.as_str();
    let petitioner = env
        .get(binding_field::PETITIONER_KEY_ID)
        .and_then(serde_json::Value::as_str);
    if facts.incapacity_attesters.contains(steward)
        || petitioner
            .map(|p| facts.incapacity_attesters.contains(p))
            .unwrap_or(false)
    {
        return reject("attester_conflicted");
    }

    // (5) mandatory legitimacy source ∈ the closed set — NEVER the steward's
    // signature alone (naked self-appointment).
    match legit {
        Some(s) if legitimacy_source::is_valid(s) => {}
        _ => return reject("missing_legitimacy_source"),
    }

    // (6) mandatory bounded valid_until (fail-to-liberty).
    let Some(vu_raw) = env
        .get(binding_field::VALID_UNTIL)
        .and_then(serde_json::Value::as_str)
    else {
        return reject("missing_valid_until");
    };
    let Ok(valid_until) = vu_raw.parse::<chrono::DateTime<chrono::Utc>>() else {
        return reject("valid_until_unparseable");
    };
    // No window may outrun the T2 periodic-review cadence.
    let ceiling = chrono::Utc::now() + chrono::Duration::days(T2_REVIEW_CADENCE_DAYS);
    if valid_until > ceiling {
        return reject("valid_until_exceeds_review_cadence");
    }

    // ADMIT the scoped, bounded, independently-attested adult-incapacity
    // fiduciary binding (CC 3.4.12).
    Ok(())
}

/// v17.9.0 (CIRISConstitution#38 interim) — the attestation-plane envelope
/// size cap, in **canonical (JCS) bytes**. 1 MiB, deliberately aligned with
/// the blob plane's [`crate::federation::blobs::DEFAULT_INLINE_BYTES_CAP`]:
/// the substrate-wide discipline is *inline below 1 MiB; above it, the
/// envelope carries a manifest (content hash + degradable-plane reference)
/// and the payload rides the fountain-content primitive*. Until this cut the
/// CEG had NO size bound at any layer — the 8 MiB HTTP ingest body cap
/// (AV-7) never covered capsule/FFI writes, so an unchecked write could park
/// a multi-hundred-MB row on the anti-entropy plane. Interim persist value;
/// re-pin to the ratified number when CC#38 lands.
pub const MAX_ATTESTATION_ENVELOPE_BYTES: usize = 1024 * 1024;

/// v22.0.0 (CIRISEdge#428) — the closed `delivery_mode` vocabulary. Absent is
/// legal (BestEffort); `"mandatory"` is legal. Nothing else is.
pub const DELIVERY_MODE_VOCABULARY: [&str; 1] = ["mandatory"];

/// v22.0.0 (CIRISEdge#428) — **REFUSE unknown `delivery_mode` values at the
/// wire.** Pure envelope predicate (AV-76 tier 1): no directory read, no
/// crypto.
///
/// # The hazard this closes
///
/// `delivery_mode` is the contextual-integrity recipient-RECEIVE axis, typed
/// since v21.9.0 and byte-faithfully carried — and its VALUE was never
/// validated anywhere. Edge's processor (`delivery_mode.rs`, CIRISEdge#411)
/// recognizes exactly one value and degrades everything else to BestEffort:
///
/// ```text
/// Some(DELIVERY_MODE_MANDATORY) => Mandatory,
/// _ => BestEffort,   // <- everything else, INCLUDING TYPOS, may DROP
/// ```
///
/// So `"manditory"` was admitted here, carried faithfully, and silently
/// demoted at delivery — the producer believed they demanded delivery; the
/// network quietly stopped promising it. That is the "accepted but not
/// projected" class (v17.0.0/#444, AV-77's reachability finding) in delivery
/// flavor. Refusing the typo at WRITE time turns a silent drop months later
/// into a loud error now.
///
/// Absent stays legal and means BestEffort — the field is optional, not
/// required. A present-but-non-string shape (number, null, object) is refused
/// too: edge's typed reader resolves those to `None` ⇒ BestEffort, which is
/// the same silent demotion wearing a different type error.
///
/// Vocabulary ratification: CIRISEdge#428 (assumed `{absent, "mandatory"}`,
/// matching edge's implemented semantics exactly; future values are an
/// additive contract change on both sides, not a silent semantics change).
pub fn check_delivery_mode_vocabulary(envelope: &serde_json::Value) -> Result<(), Error> {
    match envelope.get(crate::federation::envelope::paths::DELIVERY_MODE) {
        None => Ok(()),
        Some(serde_json::Value::String(s)) if DELIVERY_MODE_VOCABULARY.contains(&s.as_str()) => {
            Ok(())
        }
        Some(other) => Err(Error::InvalidArgument(format!(
            "delivery_mode {other} is not in the ratified vocabulary (legal: absent, or one of \
             {DELIVERY_MODE_VOCABULARY:?}) — an unknown value would be silently demoted to \
             may-drop BestEffort at delivery (CIRISEdge#428); refused at the wire instead"
        ))),
    }
}

/// v17.9.0 (CIRISConstitution#38 interim) — refuse an attestation whose
/// envelope's canonical bytes exceed [`MAX_ATTESTATION_ENVELOPE_BYTES`].
///
/// Runs FIRST at every attestation write chokepoint (all three backends'
/// `put_attestation` + the three local-tier write funnels) — the
/// cheapest-most-specific-rejection-first discipline: no signature
/// verification or directory lookups are spent on an envelope that can never
/// be admitted. Measures the REAL canonical bytes (the same JCS the producer
/// signed, via [`crate::verify::canonical::ceg_produce_canonicalize`]) — the
/// signed thing is the sized thing (CC#38's proposed rule).
pub fn check_envelope_size_admission(envelope: &serde_json::Value) -> Result<(), Error> {
    let canonical = crate::verify::canonical::ceg_produce_canonicalize(envelope)
        .map_err(|e| Error::InvalidArgument(format!("envelope canonicalize: {e}")))?;
    if canonical.len() > MAX_ATTESTATION_ENVELOPE_BYTES {
        return Err(Error::EnvelopeTooLarge {
            bytes: canonical.len(),
            cap: MAX_ATTESTATION_ENVELOPE_BYTES,
        });
    }
    Ok(())
}

/// v10.3.0 (CIRISPersist#288, CC 3.4.1 / 3.4.3 / 3.4.5) — reserved-prefix
/// admission on the **`attestation_type`** namespace, keyed on the attesting
/// key's `identity_type`.
///
/// The Constitution reserves whole `attestation_type` prefixes to specific
/// emitter classes. The pre-existing [`DimensionAdmissionPolicy::check`] only
/// gates the **`dimension`** field of `scores` rows — so an attestation whose
/// **type** is `accord:invoke:*` / `system:audit_chain:*` / `capacity:*`
/// slipped through unchecked (any `identity_type` could emit it). This gate
/// closes that, at the `put_attestation` chokepoint (so it covers
/// `emit_attestation` / `emit_attestation_self` / direct writes / replicated
/// rows alike — keyed on the *attesting* key's identity_type, which is
/// node-independent):
///
/// - `accord:*` → `accord_holder` only (CC 3.4.1 — the one constitutional
///   asymmetry).
/// - `system:*` / `audit_chain:*` / `corpus_health:*` / … → per the
///   [`default_reserved_prefix_rules`] table (CC 3.4.3 — substrate-self-report).
/// - `hard_case:*` → `substrate_persist` only (substrate-emitted).
/// - `capacity:*` → MUST NOT be self-emitted (`attesting_key_id ==
///   attested_key_id`) — CC 3.4.5's "Critical enforcement" anti-Goodhart rule
///   (an `identity_type`-independent attester==attested check).
/// - `age_assurance:*` → MUST NOT be self-emitted either (v13.0.0,
///   CIRISPersist#368) — CC 3.4.11 "A subject MUST NOT emit on
///   `age_assurance:`". The witness-RESERVED half rides the rule table; this
///   attester==attested half stops a `witness`-typed key from graduating
///   ITSELF. A witness graduates a DIFFERENT subject by naming it as
///   `attested_key_id` (the cross-subject edge
///   [`crate::Engine::emit_attestation`] carries via
///   [`EmitAttestationInput::attested_key_id`](crate::federation::EmitAttestationInput::attested_key_id)),
///   which [`super::age::age_band`] then resolves for that subject.
///
/// Structural primitives (`scores` / `delegates_to` / `supersedes` /
/// `withdraws` / `recants`) and any non-reserved type fast-exit with no
/// directory lookup.
pub async fn check_reserved_prefix_admission(
    directory: &dyn super::FederationDirectory,
    row: &super::Attestation,
) -> Result<(), Error> {
    use super::types::identity_type;
    let at = row.attestation_type.as_str();

    // CC 3.4.5 — capacity:* self-emission. Cheapest check (no lookup); an
    // attester==attested rule independent of identity_type.
    if at.starts_with("capacity:") && row.attesting_key_id == row.attested_key_id {
        return Err(Error::CapacitySelfEmissionRejected {
            key_id: row.attesting_key_id.clone(),
            attestation_type: at.to_owned(),
        });
    }

    // CC 3.4.12 — capacity_assurance:* the SUBJECT must not self-mint their
    // own (in)capacity ("the subject MUST NOT emit it"). An attester==attested
    // check independent of identity_type; the witness-RESERVED half (only a
    // registered `witness` assessor may emit) rides the reserved-prefix rule
    // table below. (`capacity_assurance:` does not start with `capacity:`, so
    // the CC 3.4.5 check above never fires for it.)
    if at.starts_with(crate::federation::capacity::CAPACITY_ASSURANCE_PREFIX)
        && row.attesting_key_id == row.attested_key_id
    {
        return Err(Error::CapacitySelfEmissionRejected {
            key_id: row.attesting_key_id.clone(),
            attestation_type: at.to_owned(),
        });
    }

    // v13.0.0 (CIRISPersist#368) — CC 3.4.11: "A subject MUST NOT emit on
    // `age_assurance:`". The witness rung is an attestation ABOUT a subject
    // (`attested_key_id` = the subject, the same cross-subject edge shape
    // `delegates_to` uses); the SUBJECT-must-not-emit half is an
    // attester==attested check independent of identity_type — without it a
    // key carrying the `witness` identity_type could self-mint its own
    // `adult` graduation. The witness-RESERVED half (only `identity_type ⊇
    // {witness}` may emit) rides the reserved-prefix rule table below,
    // unchanged. Exact sibling of the CC 3.4.12 `capacity_assurance:` check
    // above. NB: the self rung stays on the distinct NON-reserved
    // `age_self_declared:` prefix (subject-signed by design), which this
    // check never touches.
    if at.starts_with("age_assurance:") && row.attesting_key_id == row.attested_key_id {
        return Err(Error::AgeAssuranceSelfEmissionRejected {
            key_id: row.attesting_key_id.clone(),
            attestation_type: at.to_owned(),
        });
    }

    // CC 3.4.11 (CIRISPersist#307) — the self-declared age rung carries a
    // `{band}`, NEVER a `{level}`; a `{level}` token belongs to the
    // witness `age_assurance:` rung. Age tokens travel as the
    // `attestation_type` string (NOT the `scores` envelope `dimension`), so
    // the v11.3.0 rule placed only in `DimensionAdmissionPolicy::check`
    // (which fast-exits for any `attestation_type != scores`) was a no-op on
    // the real emit path. Gate it HERE, on the `attestation_type` namespace,
    // independent of emitter (no identity_type rescues the shape). The
    // dimension-side rule is kept too (defense-in-depth for the
    // scores+dimension shape).
    if at == "age_self_declared:level" || at.starts_with("age_self_declared:level:") {
        return Err(Error::DimensionRejected {
            dimension: at.to_owned(),
            reason: DimensionRejectionReason::SelfDeclaredLevelReserved.as_str(),
        });
    }

    // v22.0.0 (CIRISPersist#543 finding 2) — THE DIMENSION-KEYED CAPACITY
    // SELF-EMISSION GATE, wired at last. The CC 3.4.5 arm above keys on the
    // `attestation_type` namespace (`capacity:*` as a TYPE), but reputation
    // actually rides `attestation_type = scores` with `dimension = capacity:*`
    // — so on the real emit shape that arm never fired, and
    // `check_capacity_not_self_attested` (the dimension-keyed guard written for
    // exactly this, v4.4.0 / AV-62) had ZERO callers: capacity self-inflation
    // was open. Two things were wrong and both are fixed here: the live hole,
    // and the EVIDENCE-REGISTRY UNSOUNDNESS — `namespace_supersets.json` cites
    // this function as a live processor, and a citation that names code which
    // never runs breaks the #519 premise that a cited processor is executed
    // code (see `tests::every_cited_processor_has_a_non_test_caller`, the gate
    // that now makes that mechanically true).
    //
    // Kept as a SEPARATE call rather than folded into the arm above: the two
    // guards cover two different wire shapes (type-keyed and dimension-keyed)
    // and must both hold — a row is self-attested capacity if EITHER says so.
    // Pure (no directory lookup), so it stays in the cheap tier.
    check_capacity_not_self_attested(
        envelope_dimension(&row.attestation_envelope),
        &row.attesting_key_id,
        &row.attested_key_id,
    )?;

    // (CIRISPersist#519 item 3) — the invariant-registry-driven admission
    // gate: applies the ADMISSION-ENFORCEABLE invariants for this row's
    // family that no OTHER gate in this function (or elsewhere) already
    // covers — see `crate::federation::invariant`'s module doc for the full
    // cross-reference against `default_reserved_prefix_rules`. Cheap (no
    // directory lookup) and placed alongside the other attester==attested
    // arms above for the same "cheapest-most-specific-rejection-first"
    // reason. Today this closes exactly one manifest-documented gap
    // (`health:liveness:*` self-emission); every identity-type-reserved
    // invariant the manifest declares is already enforced by the rest of
    // this function, per the module's consistency witness.
    crate::federation::invariant::enforce_admission_invariants(
        at,
        &row.attesting_key_id,
        &row.attested_key_id,
        "",
    )?;

    // (CIRISPersist#590) — CC 3.1.7 R2(b): a governed family with no
    // registry row is a CONFORMANCE FAILURE, never an admit-and-wait.
    //
    // Placed HERE, inside the reserved-prefix chokepoint, on purpose. R2(b)
    // and the reserved-prefix rule ask the same question from two directions —
    // "who may emit on this family?" and "did anyone ever say?" — and the
    // answer to the second is the vendored manifest the first's rule table is
    // supposed to mirror. Two lists that disagree is this repo's most-scarred
    // class (#541, #532, #588); running both off the SAME
    // `default_reserved_prefix_rules()` call site, in the same function, at the
    // same instant, is what makes drifting apart impossible rather than
    // unlikely. Every backend reaches this function through `put_attestation`,
    // so memory / sqlite / postgres refuse identically.
    //
    // Both namespaces are checked because both carry families: the reserved
    // rules below key on `attestation_type`, while persist's own minted
    // families (`objection:`, `quarantine:`, `wa_adjudication:`) ride the
    // `scores` envelope's `dimension`. Checking only one would leave exactly
    // the three families #590 was opened about unenforced.
    //
    // Pure (no directory lookup), so it stays in the cheap tier alongside the
    // attester==attested arms.
    check_namespace_family_registered(at)?;
    if let Some(dim) = envelope_dimension(&row.attestation_envelope) {
        check_namespace_family_registered(dim)?;
    }

    // (CIRISPersist#571) — CC 3.1.7 R2's Private Use range: `x_private:*` MUST
    // NOT admit at federation tier under any authority. The clause's sibling,
    // and placed with it for the same reason: both answer "what does R2 say
    // about a family with no row?", and the answers differ only in whether the
    // absence is a gap (R2(b)) or the point (Private Use). Split across two
    // call sites they would drift; here they are read together.
    //
    // `row.tier` is the tier the row WILL be stored at — `check_promotion_admission`
    // passes the row as-it-will-be-stored — so this one placement covers the
    // direct federation-tier write and the local→federation promotion both,
    // on every backend, without a second gate.
    check_private_use_not_federatable(at, &row.tier)?;
    if let Some(dim) = envelope_dimension(&row.attestation_envelope) {
        check_private_use_not_federatable(dim, &row.tier)?;
    }

    // Which (if any) identity-gated reserved prefix does the TYPE carry?
    let is_accord = at.starts_with("accord:");
    let is_hard_case = at.starts_with("hard_case:");
    let matched_rule = default_reserved_prefix_rules()
        .into_iter()
        .find(|r| at.starts_with(r.pattern_prefix.as_str()));
    if !is_accord && !is_hard_case && matched_rule.is_none() {
        return Ok(()); // not a reserved type — no lookup needed.
    }

    // Resolve the attester's identity_type (an unregistered/unknown attester
    // resolves to "" — fail-secure: it satisfies no reserved-prefix rule).
    let got = directory
        .lookup_public_key(&row.attesting_key_id)
        .await?
        .map(|k| k.identity_type)
        .unwrap_or_default();

    if is_accord && got != identity_type::ACCORD_HOLDER {
        return Err(Error::AccordDimensionRequiresAccordHolder {
            dimension: at.to_owned(),
            identity_type: got,
        });
    }
    if is_hard_case {
        if got != identity_type::SUBSTRATE_PERSIST {
            return Err(Error::ReservedPrefixEmitterMismatch {
                dimension: at.to_owned(),
                prefix: "hard_case:".to_owned(),
                required: vec![identity_type::SUBSTRATE_PERSIST.to_owned()],
                got_identity_type: got,
            });
        }
        // v30.3.0 (CIRISPersist#607) — **a hard_case row ABOUT ANOTHER PARTY
        // needs a conferral; one about YOURSELF does not.**
        //
        // `substrate_persist` is self-assertable, and until now this was a bare
        // membership test — so a stranger claiming it could author tombstones
        // about anyone. `hard_case:` is where CIRISServer's graded admin ladder
        // records every action taken about someone else, carrying the
        // authorizing delegation id and a mandatory reason: an accountability
        // plane resting on a claim anybody could make.
        //
        // The split is attester==attested, and it is taken STRAIGHT from the
        // retirement condition `substrate_persist`'s own mode note states:
        // *"if a `system:*` row ever becomes an input to a decision ABOUT
        // ANOTHER PARTY, this must move"*. A third-party `hard_case:` row meets
        // that condition by construction; a self-attested one does not, and
        // tightening past what the condition names would be scope creep with a
        // fail-closed edge — a node unable to enter its own incident on the
        // attestation plane.
        //
        // Note what this door does NOT govern: persist's own `hard_case:*`
        // telemetry (the at-rest cascade, the community-DEK recipient
        // exclusions, the consent-SLA watcher) is written through
        // `FederationDirectory::record_hard_case` into `hard_case_events`, a
        // different table on a different surface. Persist emits no `hard_case:`
        // ATTESTATION at all. The traffic here is a host's — CIRISServer's
        // graded admin ladder — which is exactly the third-party case.
        if row.attested_key_id != row.attesting_key_id {
            let Some(node) = directory.node_key_id() else {
                return Err(Error::ReservedPrefixEmitterMismatch {
                    dimension: at.to_owned(),
                    prefix: "hard_case:".to_owned(),
                    required: vec![format!(
                        "delegated scope {} — but this directory has no node identity, so \
                         conferral cannot be verified. Call set_node_key_id().",
                        super::types::delegation_scope::INFRA_RECORD_HARD_CASE
                    )],
                    got_identity_type: got,
                });
            };
            let conferred = super::trust_root::capability_roots_to_trusted_root(
                directory,
                &node,
                &row.attesting_key_id,
                super::types::delegation_scope::INFRA_RECORD_HARD_CASE,
            )
            .await?;
            if conferred.is_none() {
                return Err(Error::ReservedPrefixEmitterMismatch {
                    dimension: at.to_owned(),
                    prefix: "hard_case:".to_owned(),
                    required: vec![format!(
                        "delegated scope {} from a root this node trusts (this row is ABOUT \
                         another party)",
                        super::types::delegation_scope::INFRA_RECORD_HARD_CASE
                    )],
                    got_identity_type: got,
                });
            }
        }
    }
    if let Some(rule) = matched_rule {
        // CC 3.4.7.1 — set membership, not scalar equality: `got` is the
        // stored (possibly comma-joined) `identity_type` set; the rule is
        // satisfied iff a required role is one of its members. Single-role
        // keys encode identically to scalar (`X ∈ {X}` ≡ `X == X`), so this
        // is behavior-preserving for every existing reserved prefix and
        // only newly-admits conformant folded keys (CC 3.4.8 detector fold).
        // v30.2.0 (CIRISPersist#607) — RESOLVE, don't just membership-test.
        //
        // For a rule carrying a delegation scope the identity check below is a
        // PRECONDITION, not the whole test: the emitter must ALSO hold that
        // scope from a trust root THIS NODE trusts, re-derived from this node's
        // own state — which is what the claim's ConferralMode always promised
        // and nothing ever did.
        //
        // The node identity is load-bearing and must come from the host. An
        // earlier draft of this passed `row.attesting_key_id` as the trusting
        // party, which asks "does the attester trust the root that vouches for
        // the attester" — answered by two rows the attester signs itself. That
        // is forgery wearing the shape of verification, and it would have
        // reported the hole as closed.
        //
        // No identity ⇒ cannot verify ⇒ REFUSE. Admitting here would restore
        // the self-assertable state #607 measured, silently.
        if let Some(scope) = rule.required_delegation_scope.as_deref() {
            let Some(node) = directory.node_key_id() else {
                return Err(Error::ReservedPrefixEmitterMismatch {
                    dimension: at.to_owned(),
                    prefix: rule.pattern_prefix.clone(),
                    required: vec![format!(
                        "delegated scope {scope} — but this directory has no node identity,                          so conferral cannot be verified. Call set_node_key_id()."
                    )],
                    got_identity_type: got.clone(),
                });
            };
            let conferred = super::trust_root::capability_roots_to_trusted_root(
                directory,
                &node,
                &row.attesting_key_id,
                scope,
            )
            .await?;
            if conferred.is_none() {
                return Err(Error::ReservedPrefixEmitterMismatch {
                    dimension: at.to_owned(),
                    prefix: rule.pattern_prefix.clone(),
                    required: vec![format!(
                        "delegated scope {scope} from a root this node trusts"
                    )],
                    got_identity_type: got.clone(),
                });
            }
        }
        if !rule
            .required_identity_types
            .iter()
            .any(|t| identity_type::set_contains(&got, t))
        {
            let mut required = rule.required_identity_types.clone();
            required.sort();
            return Err(Error::ReservedPrefixEmitterMismatch {
                dimension: at.to_owned(),
                prefix: rule.pattern_prefix.clone(),
                required,
                got_identity_type: got,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> DimensionAdmissionPolicy {
        DimensionAdmissionPolicy::default()
    }

    /// v26.0.0 (CIRISPersist#589 / AV-83) — **THE RESIDUAL, EXECUTED.**
    ///
    /// [`check_promotion_admission`] deliberately does NOT run AV-45, and its
    /// doc says why: on this table AV-45 cannot ASK the question (an
    /// attestation carries a `cohort_scope` with no `cohort_target_id`), so
    /// running it would not check a promotion's placement, it would make
    /// `family` / `community` placements unreachable and delete the #519/#510
    /// audience plane.
    ///
    /// A residual recorded only in prose is a residual that quietly becomes
    /// untrue in one direction or the other — either someone "fixes" it by
    /// wiring AV-45 in and silently amputates the audience plane, or the
    /// underlying predicate changes and the prose keeps claiming a hole that
    /// closed. This asserts the exact shape of what is and is not proven, so
    /// BOTH drifts land as a red test with this comment attached.
    ///
    /// The two halves:
    ///
    /// 1. AV-45's predicate refuses `family` / `community` **whenever the
    ///    target is `None`**, which on an attestation is always — so it is a
    ///    predicate about a field this row does not have. That is why closing
    ///    the residual is a SCHEMA change (give the row a `cohort_target_id`),
    ///    not a gate change.
    /// 2. It admits `self` and every broad belonging-tier with no membership
    ///    read at all — so for the placements a promotion overwhelmingly uses,
    ///    there is nothing AV-45 would have added.
    #[test]
    fn promotion_does_not_prove_cohort_membership_589() {
        use crate::federation::types::cohort_scope as cs;
        use crate::scope::CallerAdmission;

        // A writer belonging to NOTHING — the honest state of a promoting node
        // as far as this table can express it.
        let unaffiliated = CallerAdmission::from_resolved(
            "occ-589".to_owned(),
            "id-589".to_owned(),
            Vec::<String>::new(),
            Vec::<String>::new(),
        );

        // (1) The two targeted scopes are refused for want of a TARGET, not for
        // want of membership — pass a real family id and it is still refused,
        // because the row has no field to carry it.
        for scope in [cs::FAMILY, cs::COMMUNITY] {
            assert!(
                DimensionAdmissionPolicy::check_write_cohort_scope(&unaffiliated, scope, None)
                    .is_err(),
                "#589 residual: {scope} is refused with no target — the row cannot name one"
            );
        }

        // (2) …and the placements a promotion actually lands at are admitted
        // unconditionally, so AV-45 would contribute no check there.
        for scope in [
            cs::SELF,
            cs::AFFILIATIONS,
            cs::SPECIES,
            cs::BIOSPHERE,
            cs::FEDERATION,
        ] {
            assert!(
                DimensionAdmissionPolicy::check_write_cohort_scope(&unaffiliated, scope, None)
                    .is_ok(),
                "#589 residual: {scope} passes with no membership read"
            );
        }
    }

    /// CIRISPersist#592 (AV-84) — **AV-84 IS NOT AV-45, AND THE
    /// SEPARATION IS THE POINT.**
    ///
    /// The witness above pins what AV-45 cannot ask on this table. This pins
    /// what AV-84 does ask instead, and — more importantly — the two ways a
    /// well-meaning later reader could collapse them into one gate:
    ///
    /// 1. **Widening it into a general third-party ban.** AV-45's own rule for
    ///    the broad belonging-tiers is *"no per-row target; any authenticated
    ///    writer may emit"*. A third-party row promoted to `federation` must
    ///    still pass, or AV-84 has silently become a different gate under this
    ///    one's name.
    /// 2. **Reporting it as a membership failure.** The refusal names the FIELD
    ///    that carried the foreign party (`attested_key_id` /
    ///    `subject_key_ids`), never "no family membership" — that would send an
    ///    operator hunting a membership record that was never the problem, on a
    ///    table with nowhere to record one.
    ///
    /// Pure: same verdict on every backend because there is no backend in it.
    #[test]
    fn promotion_cohort_standing_is_not_av45_592() {
        use crate::federation::types::{attestation_tier, attestation_type, cohort_scope as cs};

        let row = |attested: &str, subjects: &[&str], scope: &str| super::super::Attestation {
            attestation_id: "att-592".to_owned(),
            attesting_key_id: "producer-592".to_owned(),
            attested_key_id: attested.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: serde_json::json!({"dimension": "trust:demo:v1"}),
            original_content_hash: "ab".to_owned(),
            scrub_signature_classical: "c2ln".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: "producer-592".to_owned(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: subjects.iter().map(|s| (*s).to_owned()).collect(),
            withdraws_admission_rule: None,
            cohort_scope: scope.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };

        // (1) The gate is the TARGETED-cohort arm and nothing else. A row about
        // a stranger still reaches every broad belonging-tier.
        for scope in [cs::AFFILIATIONS, cs::SPECIES, cs::BIOSPHERE, cs::FEDERATION] {
            check_promotion_cohort_standing(&row("stranger-592", &["stranger-592"], scope))
                .expect("AV-84 is the targeted-cohort arm — broad tiers keep AV-45's own rule");
        }

        // (2) …and on the two targeted cohorts it refuses, naming its branch.
        for scope in [cs::FAMILY, cs::COMMUNITY] {
            let err = check_promotion_cohort_standing(&row("stranger-592", &[], scope))
                .expect_err("a row ABOUT a stranger is not a producer self-declaration");
            assert!(
                matches!(&err, Error::CohortStandingRefused { reason, foreign_key_id, .. }
                    if *reason == CohortStandingRefusal::AttestedParty
                        && foreign_key_id == "stranger-592"),
                "the refusal names the FIELD, not a membership: {err:?}"
            );

            // The subject surface is the other way a foreign party rides in —
            // checking only `attested_key_id` would be a one-shape answer.
            let err =
                check_promotion_cohort_standing(&row("producer-592", &["stranger-592"], scope))
                    .expect_err("a foreign SUBJECT is a foreign party too");
            assert!(
                matches!(&err, Error::CohortStandingRefused { reason, .. }
                    if *reason == CohortStandingRefusal::NamedSubject),
                "the subject arm names its own branch: {err:?}"
            );

            // The producer's own row — the #519/#510 audience plane — passes.
            check_promotion_cohort_standing(&row("producer-592", &["producer-592"], scope))
                .expect("a producer's own row still reaches its own audience");
        }

        // The refusal token set is closed and each variant names a real field.
        for r in CohortStandingRefusal::ALL {
            assert!(!r.as_str().is_empty() && !r.field().is_empty());
        }
    }

    /// v26.0.0 (CIRISPersist#589 / AV-83) — the "capacity is never local" rule
    /// is ONE predicate, asked on BOTH wire shapes, and
    /// [`check_local_tier_eligibility`] routes through it rather than holding a
    /// second copy. Two validators for one artifact MUST share one predicate.
    #[test]
    fn capacity_never_local_is_one_predicate_both_shapes_589() {
        use crate::federation::types::{attestation_type::SCORES, cohort_scope::SELF};

        // Dimension-keyed (the shape reputation actually travels in).
        assert!(check_capacity_never_local(SCORES, Some("capacity:composite:v1")).is_err());
        // Type-keyed (the other real shape — #543 finding 2's lesson).
        assert!(check_capacity_never_local("capacity:composite", None).is_err());
        // `capacity_assurance:*` is a DIFFERENT, role-gated family: the next
        // byte after `capacity` is `_`, so the prefix must not match it.
        assert!(check_capacity_never_local(SCORES, Some("capacity_assurance:x:v1")).is_ok());
        assert!(check_capacity_never_local(SCORES, Some("trust:demo:v1")).is_ok());

        // The local-tier gate reaches the SAME verdict through the SAME
        // function — not a copy of the condition.
        let err =
            check_local_tier_eligibility(SCORES, Some("capacity:composite:v1"), "a", &[], SELF)
                .expect_err("capacity is never local");
        assert!(
            format!("{err}").contains("local tier"),
            "both doors give the same refusal: {err}"
        );
    }

    /// v22.0.0 (CIRISPersist#543 finding 3) — **THE DRIFT-PROOF COVERAGE
    /// GATE**: every `identity_type` that any reserved-prefix rule requires
    /// MUST appear in
    /// [`identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES`].
    ///
    /// This is what makes the fix closed-set rather than incident-driven. The
    /// pre-#543 state gated four claims, each noticed as its own incident,
    /// while `substrate_persist` / `witness` / `trusted_publisher` /
    /// `lenscore_detector` — every one of which reserves a dimension family —
    /// stayed self-assertable. Adding a rule that reserves a family to a NEW
    /// identity type without adding that type to the closed set now fails the
    /// build, so the enumeration cannot silently fall behind the rule table
    /// again.
    ///
    /// (Direction matters: the closed set may be a strict SUPERSET — `steward`
    /// / `partner` / `wise_authority` confer authority through paths other than
    /// the reserved-prefix table, e.g. steward-binding and licensure.)
    #[test]
    fn authority_conferring_set_covers_every_reserved_prefix_rule() {
        use std::collections::BTreeSet;
        let closed: BTreeSet<&str> = identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES
            .iter()
            .copied()
            .collect();
        let mut required: BTreeSet<String> = BTreeSet::new();
        for rule in default_reserved_prefix_rules() {
            for t in rule.required_identity_types {
                required.insert(t);
            }
        }
        assert!(
            !required.is_empty(),
            "the reserved-prefix rule table is empty — this gate would pass vacuously"
        );
        let missing: Vec<&String> = required
            .iter()
            .filter(|t| !closed.contains(t.as_str()))
            .collect();
        assert!(
            missing.is_empty(),
            "SELF-ASSERTABLE AUTHORITY (CIRISPersist#543): identity_type(s) {missing:?} reserve a \
             dimension family in `default_reserved_prefix_rules` but are NOT in \
             `identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES`, so a peer can self-assert them \
             at registration and emit under the family they reserve. Add them to the closed set \
             (they will then require accord conferral), or drop the reserved-prefix rule."
        );
    }

    /// Every authority-conferring claim declares a conferral mode — the table
    /// is exhaustive over the closed set, so a claim can never be added
    /// without a reviewer stating HOW it is conferred. (`None` here would mean
    /// a privileged claim silently falls through every gate.)
    #[test]
    fn every_authority_claim_declares_a_conferral_mode() {
        for claim in identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES {
            assert!(
                identity_type::conferral_mode(claim).is_some(),
                "{claim:?} is authority-conferring but declares no ConferralMode — state how it \
                 is conferred (CIRISPersist#543)"
            );
        }
        // And a descriptive type must NOT declare one (it would imply a gate
        // that does not exist).
        for t in [
            identity_type::AGENT,
            identity_type::USER,
            identity_type::NODE,
            identity_type::PRIMITIVE,
        ] {
            assert!(
                identity_type::conferral_mode(t).is_none(),
                "{t:?} is descriptive — it must not declare a ConferralMode"
            );
        }
    }

    /// The closed set names only REAL identity types (a typo would silently
    /// gate nothing, since `claims_role` would never match it).
    #[test]
    fn authority_conferring_set_members_are_real_identity_types() {
        let known = [
            identity_type::AGENT,
            identity_type::PRIMITIVE,
            identity_type::STEWARD,
            identity_type::PARTNER,
            identity_type::ACCORD_HOLDER,
            identity_type::SUBSTRATE_PERSIST,
            identity_type::WITNESS,
            identity_type::TRUSTED_PUBLISHER,
            identity_type::USER,
            identity_type::WISE_AUTHORITY,
            identity_type::NODE,
            identity_type::LENSCORE_DETECTOR,
            identity_type::CANONICAL,
        ];
        for claim in identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES {
            assert!(
                known.contains(&claim),
                "{claim:?} is in AUTHORITY_CONFERRING_IDENTITY_TYPES but is not a known \
                 identity_type constant — a typo here gates nothing"
            );
        }
    }

    // ── Ask 3a: `accord:*` × `accord_holder` constitutional rule ───

    #[test]
    fn admission_rejects_accord_dimension_from_steward() {
        let p = default_policy();
        let err = p
            .check(
                attestation_type::SCORES,
                Some("accord:human_dignity:v1"),
                identity_type::STEWARD,
            )
            .unwrap_err();
        match err {
            Error::AccordDimensionRequiresAccordHolder {
                dimension,
                identity_type,
            } => {
                assert_eq!(dimension, "accord:human_dignity:v1");
                assert_eq!(identity_type, "steward");
            }
            other => panic!("expected AccordDimensionRequiresAccordHolder, got {other:?}"),
        }
    }

    #[test]
    fn admission_rejects_accord_dimension_from_agent() {
        let p = default_policy();
        let err = p
            .check(
                attestation_type::SCORES,
                Some("accord:invoke:CONSTITUTIONAL:halt_id_42:v1"),
                identity_type::AGENT,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            Error::AccordDimensionRequiresAccordHolder { .. }
        ));
    }

    #[test]
    fn admission_accepts_accord_dimension_from_accord_holder() {
        let p = default_policy();
        p.check(
            attestation_type::SCORES,
            Some("accord:human_dignity:v1"),
            identity_type::ACCORD_HOLDER,
        )
        .unwrap();
    }

    // ── Ask 3b: the four-test operational-language gate ────────────

    #[test]
    fn admission_rejects_morally_charged_emergent_deception() {
        // FSD-002 §1.10.1's canonical anti-pattern: the v1.2
        // rename target. `deception` is in the deny-list; the
        // dimension contains it; reject.
        let p = default_policy();
        let err = p
            .check(
                attestation_type::SCORES,
                Some("emergent_deception:v1"),
                identity_type::STEWARD,
            )
            .unwrap_err();
        match err {
            Error::DimensionRejected { dimension, reason } => {
                assert_eq!(dimension, "emergent_deception:v1");
                assert_eq!(reason, "morally_charged_stem");
            }
            other => panic!("expected DimensionRejected, got {other:?}"),
        }
    }

    #[test]
    fn admission_rejects_dimension_missing_version_segment() {
        // T3 — `rights_asymmetry` is mechanism-descriptive (no
        // morally-charged stem) but lacks `:v[0-9]+`. Reject.
        let p = default_policy();
        let err = p
            .check(
                attestation_type::SCORES,
                Some("rights_asymmetry"),
                identity_type::STEWARD,
            )
            .unwrap_err();
        match err {
            Error::DimensionRejected { dimension, reason } => {
                assert_eq!(dimension, "rights_asymmetry");
                assert_eq!(reason, "missing_version_segment");
            }
            other => panic!("expected DimensionRejected, got {other:?}"),
        }
    }

    #[test]
    fn admission_accepts_correlated_action_rights_asymmetry_v1() {
        // The v1.2 rename target itself — mechanism-descriptive
        // + version-pinned. As of CC 3.4.8 (CIRISPersist#366) this is a
        // detector-only prefix, so the emitter must hold `lenscore_detector`.
        let p = default_policy();
        p.check(
            attestation_type::SCORES,
            Some("detection:correlated_action:rights_asymmetry:v1"),
            identity_type::LENSCORE_DETECTOR,
        )
        .unwrap();
    }

    // ── CC 3.4.8 (CIRISPersist#366) — detector-only prefix decision table
    //    (dimension side; `DimensionAdmissionPolicy::check`) ────────────

    #[test]
    fn detector_prefix_decision_table_dimension_side() {
        let p = default_policy();
        let detector_dims = [
            "detection:correlated_action:rights_asymmetry:v1",
            "detection:distributive:access:disparity:v1",
        ];

        // 1. A plain `lenscore_detector` key is ADMITTED.
        for dim in detector_dims {
            p.check(
                attestation_type::SCORES,
                Some(dim),
                identity_type::LENSCORE_DETECTOR,
            )
            .unwrap_or_else(|e| panic!("detector must admit {dim}: {e:?}"));
        }

        // 2. A folded `{agent, lenscore_detector}` key is ADMITTED by set
        //    membership (CC 3.4.8 LensCore-fold worked example). Encode the
        //    set as the canonical sorted comma-joined form.
        let folded =
            identity_type::join_set([identity_type::AGENT, identity_type::LENSCORE_DETECTOR]);
        for dim in detector_dims {
            p.check(attestation_type::SCORES, Some(dim), &folded)
                .unwrap_or_else(|e| panic!("folded detector must admit {dim}: {e:?}"));
        }

        // 3. A plain `agent`/`steward` key is REJECTED — the cohabiting
        //    non-detector role neither grants nor blocks; only the held
        //    `lenscore_detector` role does.
        for role in [identity_type::AGENT, identity_type::STEWARD] {
            for dim in detector_dims {
                let err = p
                    .check(attestation_type::SCORES, Some(dim), role)
                    .unwrap_err();
                match err {
                    Error::ReservedPrefixEmitterMismatch {
                        required,
                        got_identity_type,
                        ..
                    } => {
                        assert_eq!(required, vec![identity_type::LENSCORE_DETECTOR.to_owned()]);
                        assert_eq!(got_identity_type, role);
                    }
                    other => panic!("expected ReservedPrefixEmitterMismatch, got {other:?}"),
                }
            }
        }

        // 4. A `truth_grounding:detection:*` cross-attestation from ANY key
        //    is ADMITTED (ungated — a DIFFERENT prefix, shadowing-free).
        for role in [
            identity_type::AGENT,
            identity_type::STEWARD,
            identity_type::LENSCORE_DETECTOR,
        ] {
            p.check(
                attestation_type::SCORES,
                Some("truth_grounding:detection:correlated_action:rights_asymmetry:v1"),
                role,
            )
            .unwrap_or_else(|e| panic!("cross-attestation must be ungated for {role}: {e:?}"));
        }
    }

    // ── CIRISPersist#379 (CC 3.4.8) — the `detection:*` prefix-WILDCARD ──

    #[test]
    fn detection_wildcard_refuses_novel_subkind_from_agent_key() {
        // A NOVEL `detection:{newkind}:*` subkind that has no dedicated
        // leaf rule (nothing named `emergent_pattern` exists among the
        // enumerated leaves) must STILL be refused for a plain `agent`
        // key — the blanket `detection:` wildcard rule closes this gap
        // (the conformance sweep's `test_550_detection_discriminator`
        // strict-xfail).
        let p = default_policy();
        let err = p
            .check(
                attestation_type::SCORES,
                Some("detection:emergent_pattern:novel_signal:v1"),
                identity_type::AGENT,
            )
            .unwrap_err();
        match err {
            Error::ReservedPrefixEmitterMismatch {
                dimension,
                prefix,
                required,
                got_identity_type,
            } => {
                assert_eq!(dimension, "detection:emergent_pattern:novel_signal:v1");
                assert_eq!(prefix, "detection:");
                assert_eq!(required, vec![identity_type::LENSCORE_DETECTOR.to_owned()]);
                assert_eq!(got_identity_type, identity_type::AGENT);
            }
            other => panic!("expected ReservedPrefixEmitterMismatch, got {other:?}"),
        }
    }

    #[test]
    fn detection_wildcard_admits_novel_subkind_from_lenscore_detector_key() {
        // The same novel subkind IS admitted for a `lenscore_detector`
        // key — the wildcard grants exactly the role the two enumerated
        // leaves already require, just without needing its own leaf.
        let p = default_policy();
        p.check(
            attestation_type::SCORES,
            Some("detection:emergent_pattern:novel_signal:v1"),
            identity_type::LENSCORE_DETECTOR,
        )
        .unwrap_or_else(|e| panic!("lenscore_detector must admit novel detection subkind: {e:?}"));

        // And a folded `{agent, lenscore_detector}` key, by set membership
        // (CC 3.4.7.1), same as the two enumerated leaves.
        let folded =
            identity_type::join_set([identity_type::AGENT, identity_type::LENSCORE_DETECTOR]);
        p.check(
            attestation_type::SCORES,
            Some("detection:emergent_pattern:novel_signal:v1"),
            &folded,
        )
        .unwrap_or_else(|e| panic!("folded detector key must admit novel subkind: {e:?}"));
    }

    #[test]
    fn detection_wildcard_does_not_shadow_the_two_enumerated_leaves() {
        // The wildcard is declared AFTER the two leaves, so the leaves'
        // own (narrower) `prefix` still surfaces in the mismatch error —
        // precedence must not regress to the blanket `detection:` prefix
        // for these two already-enumerated families.
        let p = default_policy();
        let cases = [
            (
                "detection:correlated_action:rights_asymmetry:v1",
                "detection:correlated_action:",
            ),
            (
                "detection:distributive:access:disparity:v1",
                "detection:distributive:access:",
            ),
        ];
        for (dim, expected_prefix) in cases {
            let err = p
                .check(attestation_type::SCORES, Some(dim), identity_type::AGENT)
                .unwrap_err();
            match err {
                Error::ReservedPrefixEmitterMismatch { prefix, .. } => {
                    assert_eq!(
                        prefix, expected_prefix,
                        "{dim} should report its own leaf prefix, not the blanket wildcard"
                    );
                }
                other => panic!("expected ReservedPrefixEmitterMismatch, got {other:?}"),
            }
        }
    }

    #[test]
    fn detection_wildcard_does_not_catch_truth_grounding_cross_attestation() {
        // CRITICAL: `truth_grounding:detection:*` is a DISTINCT prefix
        // (it does not start with `detection:`) and MUST remain ungated
        // for cross-attestations by any key, including a plain `agent`
        // key with no detector role at all — the wildcard must not
        // accidentally widen its net to catch it.
        let p = default_policy();
        for role in [
            identity_type::AGENT,
            identity_type::STEWARD,
            identity_type::LENSCORE_DETECTOR,
        ] {
            p.check(
                attestation_type::SCORES,
                Some("truth_grounding:detection:novel_kind:foo:v1"),
                role,
            )
            .unwrap_or_else(|e| {
                panic!("truth_grounding:detection:* cross-attestation must stay free for {role}: {e:?}")
            });
        }
    }

    // ── Ask 3 exemption: structural primitives bypass the gate ─────

    #[test]
    fn admission_exempts_delegates_to_with_legacy_rename_chain() {
        // FSD-002 v1.2 Ask 5 delta — the rename chain
        // `delegates_to:correlated_action_v2:from:emergent_deception_v1`
        // is one of §2.2's four structural primitives doing
        // federation work. Even though the envelope's content
        // references a now-banned dimension prefix
        // (`emergent_deception`), the structural primitive itself
        // is exempt from the dimension gate — it carries metadata
        // about the attestation graph, not epistemic content.
        let p = default_policy();
        p.check(
            attestation_type::DELEGATES_TO,
            Some("delegates_to:correlated_action_v2:from:emergent_deception_v1"),
            identity_type::STEWARD,
        )
        .unwrap();
    }

    #[test]
    fn admission_exempts_supersedes_withdraws_recants() {
        let p = default_policy();
        for ty in [
            attestation_type::SUPERSEDES,
            attestation_type::WITHDRAWS,
            attestation_type::RECANTS,
        ] {
            // Pass a dimension that would fail every test under
            // `scores`. Confirm the structural primitives skip it.
            p.check(ty, Some("evil_deception_no_version"), identity_type::AGENT)
                .unwrap();
            // And with no dimension at all.
            p.check(ty, None, identity_type::AGENT).unwrap();
        }
    }

    #[test]
    fn admission_rejects_empty_scores_dimension() {
        let p = default_policy();
        for d in [Some(""), Some("   "), None] {
            let err = p
                .check(attestation_type::SCORES, d, identity_type::STEWARD)
                .unwrap_err();
            match err {
                Error::DimensionRejected { reason, .. } => {
                    assert_eq!(reason, "empty_or_missing_dimension");
                }
                other => panic!("expected DimensionRejected, got {other:?}"),
            }
        }
    }

    // ── Helper: contains_version_segment edge cases ────────────────

    #[test]
    fn version_segment_terminal_and_middle() {
        // Terminal `:v1`.
        assert!(contains_version_segment("accord:human_dignity:v1"));
        // Middle `:v2:`.
        assert!(contains_version_segment(
            "detection:correlated_action:v2:rights_asymmetry"
        ));
        // Multi-digit version.
        assert!(contains_version_segment("a:v123"));
        // No version segment at all.
        assert!(!contains_version_segment("rights_asymmetry"));
        // `:v` followed by a non-digit (`:variant:`) does NOT
        // count — we're looking for `:v[0-9]+`.
        assert!(!contains_version_segment("a:variant:b"));
        // `v1` without leading colon doesn't count.
        assert!(!contains_version_segment("v1_only"));
    }

    // ── Error::kind() stability ────────────────────────────────────

    #[test]
    fn admission_errors_carry_stable_kind_tokens() {
        let e1 = Error::AccordDimensionRequiresAccordHolder {
            dimension: "accord:x:v1".into(),
            identity_type: "steward".into(),
        };
        assert_eq!(
            e1.kind(),
            "federation_accord_dimension_requires_accord_holder"
        );
        let e2 = Error::DimensionRejected {
            dimension: "x".into(),
            reason: DimensionRejectionReason::MorallyChargedStem.as_str(),
        };
        assert_eq!(e2.kind(), "federation_dimension_rejected");
    }

    // ── envelope_dimension helper ──────────────────────────────────

    #[test]
    fn envelope_dimension_extracts_string_or_returns_none() {
        let v = serde_json::json!({ "dimension": "a:v1", "score": 1.0 });
        assert_eq!(envelope_dimension(&v), Some("a:v1"));
        let v2 = serde_json::json!({ "score": 1.0 });
        assert_eq!(envelope_dimension(&v2), None);
        let v3 = serde_json::json!({ "dimension": 123 });
        assert_eq!(envelope_dimension(&v3), None);
        let v4 = serde_json::json!(null);
        assert_eq!(envelope_dimension(&v4), None);
    }

    // ── CIRISConstitution#46 — consent-before-scoring vocabulary ────

    /// The `analyze` verb persist gates on MUST be the same `analyze` the
    /// closed #510 consent grammar already publishes (and pins into
    /// `CONSENT_GRAMMAR_HASH`'s `principles` list). Two independently-spelled
    /// `analyze`s would be the axis-fusion mistake in reverse — one concept,
    /// two strings that can drift.
    #[test]
    fn analyze_consent_scope_is_the_grammar_analyze_kind() {
        use crate::federation::consent_grammar::TransmissionPrinciple;
        assert_eq!(
            serde_json::to_value(TransmissionPrinciple::Analyze).unwrap(),
            serde_json::Value::String(ANALYZE_CONSENT_SCOPE.to_string()),
            "the gate's scope token and the grammar's transmission principle are one vocabulary"
        );
        assert!(
            crate::federation::consent_grammar::consent_grammar_manifest()["principles"]
                .as_array()
                .expect("principles is an array")
                .contains(&serde_json::Value::String(
                    ANALYZE_CONSENT_SCOPE.to_string()
                )),
            "and it is a published grammar principle, not a private string"
        );
    }

    /// Build a minimal deserialized [`crate::federation::Attestation`] with the
    /// given `attestation_type` + envelope — enough for the pure classifiers.
    #[cfg(test)]
    fn minimal_row(at: &str, envelope: serde_json::Value) -> crate::federation::Attestation {
        serde_json::from_value(serde_json::json!({
            "attestation_id": "a-1",
            "attesting_key_id": "p",
            "attested_key_id": "s",
            "attestation_type": at,
            "asserted_at": "2026-06-01T00:00:00Z",
            "attestation_envelope": envelope,
            "original_content_hash": "00",
            "scrub_signature_classical": "AA",
            "scrub_key_id": "p",
            "scrub_timestamp": "2026-06-01T00:00:00Z",
            "persist_row_hash": "",
            "cohort_scope": "federation",
        }))
        .expect("minimal attestation deserializes")
    }

    /// The claim reader sees BOTH wire shapes and neither neighbour.
    /// (`capacity_assurance:` is a role-gated family — matching it here would
    /// consent-gate the abuse-response plane, which CC#46 explicitly excludes.)
    #[test]
    fn consent_gated_claim_reads_both_wire_shapes() {
        let mk = minimal_row;
        let claim = |row: crate::federation::Attestation| {
            consent_gated_claim(&row).map(|c| (c.family, c.dimension.to_owned()))
        };
        // The dimension shape — how reputation actually travels.
        assert_eq!(
            claim(mk(
                "scores",
                serde_json::json!({"dimension": "capacity:core_identity:v1"})
            )),
            Some((
                ConsentGatedFamily::Capacity,
                "capacity:core_identity:v1".to_owned()
            ))
        );
        // The legacy type shape.
        assert_eq!(
            claim(mk("capacity:composite", serde_json::json!({}))),
            Some((
                ConsentGatedFamily::Capacity,
                "capacity:composite".to_owned()
            ))
        );
        // The dimension wins when both are present.
        assert_eq!(
            claim(mk(
                "capacity:composite",
                serde_json::json!({"dimension": "capacity:core_identity:v1"})
            )),
            Some((
                ConsentGatedFamily::Capacity,
                "capacity:core_identity:v1".to_owned()
            ))
        );
        // Neighbours that must NOT be caught. `capacity_assurance:*` is a
        // role-gated family (a registered `witness` assessor), and the last
        // five are CIRISVerify's namespace, which CC 3.4.5 dispositions
        // family-by-family OUTSIDE this gate: self-reports and log
        // infrastructure have no third-party subject; artifact-integrity
        // verification scores builds, manifests, licenses and certificates
        // rather than a subject's conduct; and `rollback_detected:*` is an
        // adversarial detector, gating which would let an adversary opt out of
        // its own detection.
        for (at, dim) in [
            ("scores", "capacity_assurance:v1"),
            ("capacity_assurance:v1", "trust:demo:v1"),
            ("scores", "detection:probe:v1"),
            ("scores", PEER_DEADMISSION_DIMENSION),
            ("scores", "trust:demo:v1"),
            ("scores", "attestation:self_verify"),
            ("scores", "hardware_custody:tpm"),
            ("scores", "provenance:build_manifest:aarch64"),
            ("scores", "attestation:registry_consensus"),
            ("scores", "attestation:license_validity"),
            ("scores", "rollback_detected:agent_version:v1"),
            ("cert_validity:acme", "trust:demo:v1"),
            ("scores", "cert_validity:acme"),
        ] {
            assert_eq!(
                claim(mk(at, serde_json::json!({"dimension": dim}))),
                None,
                "({at}, {dim}) is not a consent-gated claim"
            );
        }
    }

    /// v25.1.0 (CIRISPersist#569, adjudicated by CC 3.4.5) — **THE
    /// ADJUDICATION RECORD between the measuring side and the floor, and the
    /// ONLY place in this crate that reads verify's consent classification.**
    ///
    /// This test does not defend a gate. It holds a **disagreement** open so
    /// nobody has to rediscover it — and it is deliberately the single site
    /// that touches the version-dependent surface of
    /// `ciris_verify_core::federation_provenance::dim`, so whoever re-pins
    /// verify has one function to edit rather than a scatter (see the
    /// **v12.1.0** block below).
    ///
    /// # (#568): the disagreement RESOLVED, and it resolved in the type
    ///
    /// At v11.x this record held two sides apart. At **v12.1.0 they cite the
    /// same document.** `ConsentDisposition` now implements
    /// `ciris_verify_core::classification::Classification` and declares
    /// `Normative { authority: "CC 3.4.5" }` — the very paragraph persist's
    /// [`consent_gated_family`] reads. So the question this test used to
    /// answer by prose ("is verify ruling or measuring here?") is answered by
    /// the type, via [`standing_of`]`::<ConsentDisposition>()`, and the shape
    /// of the assertion changes with the answer:
    ///
    /// - [`ClassificationStanding::Binding`] — one ratified rule, two readers.
    ///   They must **AGREE family-by-family**, in both directions. A
    ///   divergence is no longer "two sides doing their own jobs"; it is one
    ///   of them misreading CC 3.4.5, and it gets settled on the document.
    /// - [`ClassificationStanding::NoStanding`] / `ForeignAuthority` — verify
    ///   is measuring, proposing, or citing a document persist's floor does
    ///   not read. Persist's gate stands alone and nothing here is imported.
    ///
    /// The standing itself is pinned, so a demotion back to `Proposal` — or a
    /// re-citation to some other authority — reopens the adjudication instead
    /// of quietly relaxing this record into the weaker one-sided form it had.
    ///
    /// # The disagreement, as it stood at v11.x
    ///
    /// CIRISVerify's registry classified four families
    /// `ConsentClass::ConsensualReputation` and its own doc said they
    /// *"belong behind the subject's `analyze` consent"*. **CIRISPersist does
    /// not gate them.** CC 3.4.5's per-family disposition paragraph —
    /// *"Disposition of the CC 2.3.2 verification families under this rule
    /// (per family)"* — dispositions all four individually and puts every one
    /// outside the gate: `attestation:registry_consensus`,
    /// `attestation:license_validity` and `cert_validity:{authority}` are
    /// **artifact-integrity verification** (*"a forger never consents to
    /// verification"*), and `rollback_detected:{revision_field}` is *"an
    /// adversarial detector (−1-only polarity), on the abuse-response side of
    /// the line by construction"*. The rule: *"Consent-before-scoring binds
    /// the family that judges **agents** — `capacity:*` — never the families
    /// that verify **artifacts**."*
    ///
    /// That was never persist overruling verify. It is the two sides doing
    /// their own jobs: **verify knows what each dimension IS**; the
    /// Constitution decides what the substrate does about it. Verify said so
    /// itself — the split is *"a proposal from the measuring side, not a
    /// ruling"* — and CIRISPersist#569 is what happens when a consumer reads
    /// the proposal as the ruling. It shipped the widened gate at 18:17; CC
    /// 3.4.5 was ratified at 19:56; the widening was held before merge.
    ///
    /// # It must go red if EITHER side moves
    ///
    /// - **Verify moves** (a family added, dropped, or reclassified): the
    ///   `dim::ALL` size pin, the recognition-only pin and the classification
    ///   assertion read verify's registry directly.
    /// - **The floor moves** (a CC amendment carrying a family across the
    ///   line): the ruling block asserts persist gates NONE of `dim::ALL`, so
    ///   a widening — deliberate or accidental — cannot land quietly, and a
    ///   deliberate one has to edit this record and say why.
    ///
    /// Neither direction may arrive as a side-effect of a dependency bump.
    #[test]
    fn verify_dimension_registry_is_the_only_enumeration() {
        use ciris_verify_core::federation_provenance::dim::{self, ConsentDisposition};

        // The dimension shape the gate actually sees, for a registry entry.
        let probe_for = |spec: &dim::DimensionSpec| {
            if spec.parameterized {
                format!("{}probe:v1", spec.prefix)
            } else {
                spec.prefix.to_owned()
            }
        };

        // CC part_3's 15 rows; 14 verify FAMILIES (the locale leaf is a
        // sub-form of `provenance:build_manifest:`, not its own family), of
        // which 13 are verify-emitted — `transparency_log:cosigned:` is
        // witness-emitted and recognized only.
        assert_eq!(
            dim::ALL.len(),
            14,
            "verify's dimension registry changed size — a family was added or removed upstream. \
             ADJUDICATE, do not just re-pin: read CC 3.4.5's paragraph headed \"Disposition of \
             the CC 2.3.2 verification families under this rule (per family)\" and decide which \
             side of the artifact/agent line the new family falls on. The Constitution settles \
             it; verify's classification is evidence, not the verdict."
        );
        assert_eq!(
            dim::ALL.iter().filter(|d| !d.verify_emits).count(),
            1,
            "exactly one registry entry is recognition-only (transparency_log:cosigned:)"
        );

        // ─────────────────────────────────────────────────────────────────
        // MAY PERSIST GATE ON THIS AT ALL? **ASK THE TYPE** (#568).
        //
        // This is the question #569 got wrong, and it got it wrong honestly:
        // at v11.x nothing in `ConsentClass` said whether it was a ruling or a
        // proposal — the sentence that said so lived in another repo's prose.
        // CIRISVerify#238 (which persist filed) fixed the class, and v12.1.0
        // ships `classification::{Gating, Classification}`. Persist is its
        // first consumer, and this is the call site.
        //
        // `Normative { authority: "CC 3.4.5" }` is the answer we pin: verify's
        // classification tracks the SAME ratified paragraph `consent_gated_
        // family` reads. Not "verify agrees with us" — one document, two
        // readers. That is what makes the two-sided assertion below correct.
        // ─────────────────────────────────────────────────────────────────
        assert_eq!(
            standing_of::<ConsentDisposition>(),
            ClassificationStanding::Binding {
                authority: "CC 3.4.5"
            },
            "verify's `ConsentDisposition` no longer declares itself NORMATIVE on CC 3.4.5 \
             (it now says {:?}). The adjudication basis of this record changed, so re-open \
             it rather than re-pinning through: if verify demoted it to Measurement or \
             Proposal, persist's gate stands ALONE on CC 3.4.5 and the agreement assertion \
             below must go back to the one-sided v11 form; if verify re-cited some OTHER \
             authority, decide whether persist's floor is answerable to that document \
             before adding it to PERSIST_RATIFYING_AUTHORITIES. Gating on an unratified \
             proposal is the defect CIRISPersist#569 shipped and CIRISVerify#238 corrected.",
            <ConsentDisposition as Classification>::gating()
        );

        // ── ONE RULE, TWO READERS — so they must AGREE, both directions ──
        // The ONLY version-dependent read of verify's registry in this crate.
        // Everything else here and in B7 uses `dim::ALL` / `dim::lookup` /
        // `prefix` / `parameterized`, which were stable across the re-pin.
        //
        // Pinned against ciris-verify-core v12.1.0, which agrees with CC 3.4.5
        // on all fourteen families:
        //
        //   * `ConsentClass`         -> `ConsentDisposition`
        //   * `ConsensualReputation` -> `ArtifactVerification` / `AbuseResponse`
        //   * the predicate is a METHOD, `spec.is_consent_gated()`, deliberately
        //     not an implicit property of a variant name, "so the wrong gate
        //     cannot be re-derived from variant names" — exactly #569's mistake.
        //
        // The v11 form pinned four prefixes BY NAME and asserted only that
        // verify gated none. This sweeps the whole registry and asserts the two
        // readings MATCH — so a divergence in EITHER direction (verify gates
        // what persist does not, or persist gates what verify does not) is a
        // misreading of one document, and gets settled there.
        for spec in dim::ALL {
            let probe = probe_for(spec);
            assert_eq!(
                spec.consent_disposition.is_consent_gated(),
                consent_gated_family(&probe).is_some(),
                "verify and persist read CC 3.4.5 differently on `{}`: verify says gated={}, \
                 persist says gated={}. Both now cite the SAME ratified paragraph (verify's \
                 ConsentDisposition declares Normative(\"CC 3.4.5\")), so this is not a \
                 disagreement to hold open — one of the two is misreading the document. \
                 Re-read CC 3.4.5's paragraph headed \"Disposition of the CC 2.3.2 \
                 verification families under this rule (per family)\" and settle it THERE. \
                 The rule: consent-before-scoring binds the family that judges agents \
                 (`capacity:*`), never the families that verify artifacts.",
                spec.prefix,
                spec.consent_disposition.is_consent_gated(),
                consent_gated_family(&probe).is_some()
            );
        }

        // ── THE FLOOR'S RULING — persist gates NONE of verify's namespace ──
        // Over the WHOLE registry: a CC amendment moving any family across the
        // line, or a re-widening of the gate, lands here. Probed through the
        // one predicate the gate itself calls, on the real dimension shape, so
        // this asserts shipped behaviour and not a restatement of the source.
        //
        // NOT redundant with the agreement sweep above: that one would stay
        // green if BOTH sides moved together, which is precisely how a
        // dependency bump could carry a widening in. This one is anchored to
        // the floor alone.
        for spec in dim::ALL {
            let probe = probe_for(spec);
            assert_eq!(
                consent_gated_family(&probe),
                None,
                "{probe} is consent-gated by persist, but CC 3.4.5 puts every verify-owned \
                 family OUTSIDE the gate: the artifact-integrity families verify builds, \
                 manifests, licenses and certificates rather than a subject's conduct (\"a forger \
                 never consents to verification\"), and rollback_detected:* is an adversarial \
                 detector on the abuse-response side of the line — gating it would let an \
                 adversary opt out of its own rollback detection. If a CC amendment has moved \
                 this family across the line, add the ConsentGatedFamily variant and change this \
                 assertion; do not widen the gate quietly. Settled by: CIRISConstitution \
                 constitution/part_3_the_namespace.md, CC 3.4.5, the paragraph headed \
                 \"Disposition of the CC 2.3.2 verification families under this rule (per \
                 family)\"."
            );
        }

        // Every probe B7 drives through the real put path is a family verify
        // actually declares — so the two witnesses cannot drift apart, and B7
        // cannot end up probing a name that no longer exists.
        for probe in crate::federation::bootstrap_admission::test_support::CC_345_UNGATED_PROBES {
            assert!(
                dim::lookup(probe).is_some(),
                "B7 probes {probe}, which verify's registry does not resolve"
            );
        }

        // And the converse: the ONE family that is gated is the one CC 3.4.5
        // names — the family that judges agents.
        assert_eq!(
            consent_gated_family("capacity:core_identity:v1"),
            Some(ConsentGatedFamily::Capacity),
            "capacity:* is the family CC 3.4.5 binds: \"consent-before-scoring binds the family \
             that judges agents — capacity:* — never the families that verify artifacts\""
        );
        assert!(
            dim::lookup("capacity:core_identity:v1").is_none(),
            "capacity:* is persist-owned and outside verify's namespace — which is why the gated \
             set cannot be read off verify's registry at all"
        );

        // And persist's OWN pre-existing hand-list of ladder mechanisms is not
        // a rival registry: every entry resolves in verify's, unparameterized.
        for m in ATTESTATION_LADDER_MECHANISMS {
            let spec = dim::lookup(m).unwrap_or_else(|| {
                panic!("{m} is in persist's ladder list but not in verify's registry")
            });
            assert!(
                !spec.parameterized && spec.prefix == *m,
                "{m} resolves to a DIFFERENT registry family ({}) — the two lists have drifted",
                spec.prefix
            );
        }
    }

    /// v30.0.1 (CIRISPersist#607) — **a claim whose conferral mode defers
    /// enforcement to USE must never be consumed by a pure membership test.**
    ///
    /// GateSpec (CIRISOntology/GATES.md), stated here because a gate that does
    /// not say what it catches is a hypothesis about a gate:
    ///
    /// - **family** — `deontic`. Varying it changes what the mesh permits: a
    ///   stranger reaches a door reserved to a conferred role.
    /// - **headwaters** — `identity_type::conferral_mode` (the declared mode
    ///   table) × [`default_reserved_prefix_rules`] (the actual consumers).
    ///   Both already existed; nothing compared them.
    /// - **references** — CIRISPersist#543 (AV-75, the gate this extends),
    ///   #607, CC 3.4.11 (`age_assurance:` is witness-reserved *precisely
    ///   because a subject must not reach it*), CC 3.4.12.
    /// - **dye test** — `a_deferred_mode_claim_in_a_membership_rule_is_caught`
    ///   below plants the contradiction and watches this fire.
    /// - **depth** — **registration-time shape only.** This proves no
    ///   *declaration* contradicts its *consumer*. It says nothing about a
    ///   conferral revoked AFTER registration, nothing about claims outside
    ///   `AUTHORITY_CONFERRING_IDENTITY_TYPES`, and nothing about doors that
    ///   gate on identity by a route other than `required_identity_types`.
    ///   Those are separate gates and this one must not be read as covering
    ///   them.
    ///
    ///   In particular it reads the RULES TABLE only. The two prefixes handled
    ///   by inline branches in [`check_reserved_prefix_admission`] — `accord:`
    ///   and `hard_case:` — are invisible to it, because a `ReservedPrefixRule`
    ///   cannot express their conditions (`accord:` keys off a co-scrub quorum,
    ///   `hard_case:` off whether the row is about a third party). `accord:` is
    ///   fine on its own terms — `accord_holder` is `HardwareAttested`, a
    ///   registration-time mode, so its membership test reads a fact a ceremony
    ///   established. But this gate is not what establishes that. That is not
    ///   hypothetical scoping: #607's THIRD claim was exactly such a branch, so
    ///   this gate stayed green while `substrate_persist` — self-assertable —
    ///   membership-tested its way into every `hard_case:` row about anyone.
    ///   v30.3.0 fixed the branch; nothing yet gates the shape of new ones.
    ///
    ///   It also reads WRITE doors only. #607's fourth claim,
    ///   `trusted_publisher`, had no write door at all — CC 3.3.12 leaves
    ///   `content_rating:` open vocabulary — and put its whole discrimination on
    ///   a READ door, `lookup_trusted_publisher_chain`, which membership-tested
    ///   the same self-written string. Closed in v30.3.0 (CIRISPersist#611) by
    ///   resolving `infra:publish_rating` there. So this gate has now been shown
    ///   blind to the same contradiction twice, in two different places, and
    ///   both were found by reading the issue rather than by the build. A gate
    ///   over read-side membership tests on
    ///   `AUTHORITY_CONFERRING_IDENTITY_TYPES` is the missing third one.
    /// - **owner** — persist.
    ///
    /// # The invariant
    ///
    /// `ConferralMode` is a promise about *where* a claim is enforced.
    /// `DerivedFromVerifiedState` says the authority *"is re-derived from
    /// persist's own verified state at each use, so a self-asserted claim buys
    /// nothing"*. `DelegatedFromTrustRoot` says it is *"resolved at USE by
    /// `capability_roots_to_trusted_root`"*.
    ///
    /// A `required_identity_types` membership test **re-derives nothing**. It
    /// reads the `identity_type` string off the stored registration row. So a
    /// claim on either deferred mode appearing in such a rule is a **flat
    /// contradiction between the mode table and the door**: the mode says the
    /// claim buys nothing, and the door hands it everything.
    ///
    /// Only the three modes gated AT REGISTRATION — `HardwareAttested`,
    /// `AnchorScrubbed`, `AccordCoScrubbed` — may back a membership test,
    /// because for those the stored string is a fact some ceremony already
    /// established.
    ///
    /// # Why this is a gate and not a fix
    ///
    /// The contradiction is mechanically derivable from two tables that were
    /// both already in the tree. Nothing compared them, so it survived #543,
    /// which introduced one of them. That is the class: **a declaration naming
    /// where it is enforced, with nothing checking the where exists.** Same
    /// shape as CIRISConstitution#81 (a rule in prose no enforcer reaches) and
    /// #602 (`consumer: "repair_planner"`, a component nothing resolves).
    #[test]
    fn a_deferred_conferral_mode_never_backs_a_membership_test_607() {
        use crate::federation::types::identity_type::{self, ConferralMode};
        // ── THE RATCHET, and it is NOT the fix ────────────────────────────
        // Eleven pairs when this gate was written; five now. The six that left
        // are #607's first two claims — `witness` × `age_assurance:` and
        // `lenscore_detector` × `detection:` — repaired in v30.2.0 by giving
        // their rules a `required_delegation_scope`, which the loop below
        // recognises as no longer a membership test. The ratchet SHRANK, which
        // is the only direction it is allowed to move.
        //
        // What remains is persist's own self-telemetry: five prefixes a node
        // writes ABOUT ITSELF. They are the weakest case for a stranger's
        // benefit and the strongest case for fail-closed harm if gated wrong,
        // and the fix is a POLICY choice (gate at registration vs resolve at
        // use, per claim) with real operator consequences.
        //
        // What this buys today: a SIXTH cannot be added silently. Every new
        // deferred-mode membership rule fails the build.
        //
        // Shrink this list; never extend it. A list that grows is a suppression
        // file, and this one is load-bearing on an exploitable surface.
        const GRANDFATHERED_607: &[(&str, &str)] = &[
            ("substrate_persist", "system:"),
            ("substrate_persist", "audit_chain:"),
            ("substrate_persist", "corpus_health:"),
            ("substrate_persist", "identity_continuity:"),
            ("substrate_persist", "federation_directory:"),
        ];
        let rules = default_reserved_prefix_rules();
        let mut violations: Vec<String> = Vec::new();
        let mut still_open = 0usize;
        let mut checked = 0usize;

        for claim in identity_type::AUTHORITY_CONFERRING_IDENTITY_TYPES {
            let Some(mode) = identity_type::conferral_mode(claim) else {
                continue;
            };
            let deferred = matches!(
                mode,
                ConferralMode::DerivedFromVerifiedState | ConferralMode::DelegatedFromTrustRoot
            );
            if !deferred {
                continue;
            }
            checked += 1;
            for rule in &rules {
                // v30.2.0 (#607) — a rule that RESOLVES a delegation at the
                // door is not a membership test, so a deferred-mode claim
                // backing it is exactly right. Recognising the fix is what lets
                // this ratchet SHRINK rather than be suppressed.
                if rule.required_delegation_scope.is_some() {
                    continue;
                }
                if rule.required_identity_types.iter().any(|t| t == claim) {
                    if GRANDFATHERED_607
                        .iter()
                        .any(|(c, p)| *c == claim && *p == rule.pattern_prefix)
                    {
                        still_open += 1;
                        continue;
                    }
                    violations.push(format!(
                        "  `{}` (mode {:?}) backs the membership rule `{}`",
                        claim, mode, rule.pattern_prefix
                    ));
                }
            }
        }

        assert!(
            checked >= 4,
            "expected at least 4 deferred-mode claims to examine, examined {checked} — a \
             change to the mode table just emptied this gate"
        );
        // A grandfathered pair that has been FIXED must leave the list, or the
        // ratchet quietly re-permits it the day someone reintroduces the rule.
        assert_eq!(
            still_open,
            GRANDFATHERED_607.len(),
            "the ratchet lists {} pair(s) but only {still_open} are still present. Delete the \
             fixed entr(ies) from GRANDFATHERED_607 — a stale grandfather is how a closed hole \
             gets silently reopened.",
            GRANDFATHERED_607.len()
        );
        assert!(
            violations.is_empty(),
            "{} NEW deferred-mode claim(s) back a pure membership test:\n{}\n\n\
             A `required_identity_types` check re-derives NOTHING — it reads the \
             identity_type off the stored registration row. Either gate the claim at \
             registration (and move it to a registration-time mode), or make the door ask \
             the resolver its mode names. The mode table and the door must not disagree \
             about where a claim is enforced.",
            violations.len(),
            violations.join("\n")
        );
    }

    /// The **dye test** for
    /// [`a_deferred_conferral_mode_never_backs_a_membership_test_607`]: plant
    /// the contradiction and confirm the detector fires.
    ///
    /// Without this, that gate is a hypothesis — it has never been shown to
    /// catch anything, and a refactor that silently emptied its loop would look
    /// identical to a clean pass.
    #[test]
    fn a_deferred_mode_claim_in_a_membership_rule_is_caught() {
        use crate::federation::types::identity_type::{self, ConferralMode};
        // A claim on a deferred mode, exactly as the real table declares it.
        let planted = identity_type::WITNESS;
        assert!(
            matches!(
                identity_type::conferral_mode(planted),
                Some(ConferralMode::DerivedFromVerifiedState)
                    | Some(ConferralMode::DelegatedFromTrustRoot)
            ),
            "the dye depends on `{planted}` being a deferred-mode claim; if its mode moved, \
             re-aim the dye rather than deleting it"
        );
        let planted_rule = ReservedPrefixRule {
            pattern_prefix: "dye_test_planted:".into(),
            required_identity_types: vec![planted.to_owned()],
            required_delegation_scope: None,
        };
        // The same predicate the gate applies, over a table containing the
        // planted rule.
        let caught = [planted_rule]
            .iter()
            .any(|r| r.required_identity_types.iter().any(|t| t == planted));
        assert!(
            caught,
            "the gate's predicate did not catch a planted deferred-mode membership rule — \
             the gate cannot fire, and a passing run means nothing"
        );
    }

    /// (CIRISPersist#568 / CIRISVerify#238) — the rule that decides
    /// whether ANY verify classification may bind a persist gate, exercised on
    /// all three statuses plus the case the statuses alone do not cover.
    ///
    /// [`verify_dimension_registry_is_the_only_enumeration`] only ever sees one
    /// status at a time; without this, the other arms would be shipped and
    /// never run. Each case is a real failure mode:
    ///
    /// - `Measurement` — device-attestation verdicts. A consumer that gates
    ///   admission on `AndroidSecurityLevel` has made hardware a REQUIREMENT,
    ///   the exact inversion verify's own docs warn against, and the inversion
    ///   persist's `hardware_attestation` module deliberately refuses.
    /// - `Proposal` — the arm `ConsentDisposition` occupied at v11.0.0. #569.
    /// - `Normative` on a **foreign** authority — the case `may_gate()` alone
    ///   cannot answer. `Purpose` is genuinely normative on an IETF draft; that
    ///   makes it gate-able for a trust-anchor store, not a rule about what
    ///   this substrate admits. "Normative" without "on whose authority" is
    ///   the same ambiguity one level up.
    #[test]
    fn only_a_ratified_authority_persist_reads_may_bind_a_gate() {
        use ciris_verify_core::device_attestation::{AndroidSecurityLevel, AppAttestEnvironment};
        use ciris_verify_core::trust_anchor_store::Purpose;

        assert_eq!(
            classification_standing(Gating::Normative {
                authority: "CC 3.4.5"
            }),
            ClassificationStanding::Binding {
                authority: "CC 3.4.5"
            }
        );
        assert_eq!(
            classification_standing(Gating::Measurement),
            ClassificationStanding::NoStanding,
            "a measurement is an INPUT to policy, never policy"
        );
        assert_eq!(
            classification_standing(Gating::Proposal {
                tracking: "CIRISVerify#238"
            }),
            ClassificationStanding::NoStanding,
            "an unratified proposal has no standing at all — this is the #569 arm"
        );
        assert_eq!(
            classification_standing(Gating::Normative {
                authority: "some-other-repos-charter"
            }),
            ClassificationStanding::ForeignAuthority {
                authority: "some-other-repos-charter"
            },
            "normative elsewhere is not normative here: persist's floor must be answerable \
             to a document before a classification citing it can bind a persist gate"
        );
        // v29.0.0 — the second gate-able disposition. It binds WITHOUT
        // appearing in PERSIST_RATIFYING_AUTHORITIES, and that is not a hole
        // in that list: the list asks "is persist answerable to this
        // document?", and a structural constraint cites no document. The
        // string below is deliberately not a real authority — if the
        // implementation ever routed Structural through the authority check,
        // this would come back ForeignAuthority and fail.
        assert_eq!(
            classification_standing(Gating::Structural {
                breaks: "CBOR dispatch against every other implementation"
            }),
            ClassificationStanding::Structural {
                breaks: "CBOR dispatch against every other implementation"
            },
            "a structural constraint binds because the MACHINE breaks, not because a body \
             ruled — so it must not be filtered by the ratifying-authority list, and \
             disagreement with it is a bug report rather than an amendment"
        );

        // Against the classifications verify actually ships, so this cannot
        // drift into testing only hand-built `Gating` values.
        assert_eq!(
            standing_of::<AndroidSecurityLevel>(),
            ClassificationStanding::NoStanding,
            "where the chain says a key lives is a MEASUREMENT — gating admission on it \
             would make hardware a requirement, which persist's hardware_attestation module \
             refuses by design (the SoftwareOnly floor is the one structural line)"
        );
        assert_eq!(
            standing_of::<AppAttestEnvironment>(),
            ClassificationStanding::NoStanding,
            "production-vs-development is reported, never enforced"
        );
        // v29.0.0 (CIRISVerify 13.0.0, CIRISOntology#3) — this assertion used
        // to read `ForeignAuthority { "draft-ietf-rats-concise-ta-stores-02" }`
        // and the reasoning under it was subtly wrong in a way worth keeping
        // visible. Persist read "cites an IETF draft" as "normative on an
        // authority persist does not read", i.e. as a RULING held by a body
        // persist is not answerable to. Verify's arity ruling says it was
        // never a ruling: `Purpose`'s values are pinned CDDL wire indices, so
        // deviating breaks CBOR dispatch against every other CoTS
        // implementation — and no body, including the IETF, can waive that.
        //
        // The distinction is exactly the one CIRISOntology#3 forced: persist
        // could not tell *this would break* from *this is disallowed*, so it
        // filed a mechanical constraint under a document. Had persist ever
        // wanted to deviate, the old standing pointed it at the wrong
        // remedy — petition (or adopt) the draft — when the real answer is
        // that deviating is a bug and interop breaks.
        assert_eq!(
            standing_of::<Purpose>(),
            ClassificationStanding::Structural {
                breaks: "CBOR wire interop with other draft-ietf-rats-concise-ta-stores \
                         implementations"
            },
            "the CoTS purpose vocabulary CANNOT VARY — its values are wire indices, not a \
             rule some body ratified and could re-ratify. Structural standing is NOT persist \
             adopting constrained anchor resolution: it describes what the classification IS, \
             not whether persist consumes that vocabulary. Persist still does not, and the \
             day it does is still a deliberate change."
        );

        // And the rule is exactly `may_gate()` plus the authority question —
        // no persist-side re-derivation from variant names (#569's method).
        for g in [
            Gating::Measurement,
            Gating::Proposal {
                tracking: "CIRISVerify#238",
            },
        ] {
            assert!(!g.may_gate());
            assert_eq!(
                classification_standing(g),
                ClassificationStanding::NoStanding
            );
        }
    }

    /// The typed refusal is a program contract, not a message: the serde token
    /// and [`ConsentGatedFamily::as_str`] are the SAME string, and
    /// [`ConsentGatedFamily::ALL`] is complete.
    #[test]
    fn consent_gated_family_tokens_match_serde() {
        for family in ConsentGatedFamily::ALL {
            let json = serde_json::to_string(family).expect("serialize");
            assert_eq!(
                json,
                format!("\"{}\"", family.as_str()),
                "serde token and as_str must be one spelling"
            );
            let back: ConsentGatedFamily = serde_json::from_str(&json).expect("round-trip");
            assert_eq!(back, *family);
        }
        assert_eq!(
            ConsentGatedFamily::ALL.len(),
            1,
            "ALL must list every variant — it is what a consumer enumerates. ONE today because \
             CC 3.4.5 binds consent-before-scoring to the family that judges agents and to \
             nothing else; a second variant is a Constitutional amendment moving a family across \
             that line, never a convenience."
        );
        // The refusal renders its evidence: rule, dimension, both parties.
        let refused = ConsentGateRefused {
            family: ConsentGatedFamily::Capacity,
            dimension: "capacity:core_identity:v1".to_owned(),
            subject_key_id: "s".to_owned(),
            attester_key_id: "p".to_owned(),
            stance: crate::federation::hard_case::ConsentState::Unspecified,
        };
        let rendered = refused.to_string();
        for needle in [
            "capacity:core_identity:v1",
            "capacity",
            ANALYZE_CONSENT_SCOPE,
            "Unspecified",
        ] {
            assert!(
                rendered.contains(needle),
                "the refusal must name {needle}: {rendered}"
            );
        }
        assert_eq!(
            Error::from(refused).kind(),
            "federation_consent_gate_refused",
            "and it reaches the wire as its own kind, not a generic argument complaint"
        );
    }

    // ── v3.0.0 (CIRISPersist#116, CEG 0.2 §7.0) — reserved-prefix ──

    #[test]
    fn admission_rejects_system_prefix_from_non_substrate_persist() {
        // CEG §7.2 — `system:*` is reserved to substrate_persist.
        // An agent (or steward, or any other identity_type) emitting
        // under `system:*` is a category error per §7.2.
        let p = default_policy();
        let err = p
            .check(
                attestation_type::SCORES,
                Some("system:health:n_eff_measurable:v1"),
                identity_type::STEWARD,
            )
            .unwrap_err();
        match err {
            Error::ReservedPrefixEmitterMismatch {
                dimension,
                prefix,
                required,
                got_identity_type,
            } => {
                assert_eq!(dimension, "system:health:n_eff_measurable:v1");
                assert_eq!(prefix, "system:");
                assert_eq!(required, vec!["substrate_persist".to_string()]);
                assert_eq!(got_identity_type, "steward");
            }
            other => panic!("expected ReservedPrefixEmitterMismatch, got {other:?}"),
        }
    }

    #[test]
    fn admission_accepts_system_prefix_from_substrate_persist() {
        let p = default_policy();
        p.check(
            attestation_type::SCORES,
            Some("system:health:n_eff_measurable:v1"),
            identity_type::SUBSTRATE_PERSIST,
        )
        .unwrap();
    }

    #[test]
    fn admission_rejects_audit_chain_prefix_from_agent() {
        // §5.3 — audit_chain:* is a substrate-self-report prefix.
        let p = default_policy();
        let err = p
            .check(
                attestation_type::SCORES,
                Some("audit_chain:hash_continuity:v1"),
                identity_type::AGENT,
            )
            .unwrap_err();
        assert!(matches!(err, Error::ReservedPrefixEmitterMismatch { .. }));
    }

    #[test]
    fn admission_rejects_transparency_log_cosigned_from_non_witness() {
        // §7.6 — transparency_log:cosigned:* is witness-only.
        let p = default_policy();
        let err = p
            .check(
                attestation_type::SCORES,
                Some("transparency_log:cosigned:42:v1"),
                identity_type::STEWARD,
            )
            .unwrap_err();
        match err {
            Error::ReservedPrefixEmitterMismatch {
                prefix, required, ..
            } => {
                assert_eq!(prefix, "transparency_log:cosigned:");
                assert_eq!(required, vec!["witness".to_string()]);
            }
            other => panic!("expected ReservedPrefixEmitterMismatch, got {other:?}"),
        }
    }

    #[test]
    fn admission_accepts_transparency_log_cosigned_from_witness() {
        let p = default_policy();
        p.check(
            attestation_type::SCORES,
            Some("transparency_log:cosigned:42:v1"),
            identity_type::WITNESS,
        )
        .unwrap();
    }

    #[test]
    fn admission_reserved_prefix_emitter_mismatch_kind_token_stable() {
        let e = Error::ReservedPrefixEmitterMismatch {
            dimension: "system:foo:v1".into(),
            prefix: "system:".into(),
            required: vec!["substrate_persist".into()],
            got_identity_type: "agent".into(),
        };
        assert_eq!(e.kind(), "federation_reserved_prefix_emitter_mismatch");
    }

    // ── CEG 0.1 → 0.2 attestation-ladder transition window ──

    #[test]
    fn admission_accepts_deprecated_attestation_ladder_in_dual_accept() {
        // CEG 0.2 transition: persist admits BOTH
        // `attestation:l1:self_verify` (deprecated 0.1 shape) AND
        // `attestation:self_verify` (canonical 0.2 shape) on write.
        // The dimension lacks a `:v[0-9]+` segment but is exempt via
        // the attestation-ladder carve-out.
        let p = default_policy();
        for dim in [
            "attestation:l1:self_verify",
            "attestation:l2:hardware",
            "attestation:l5:agent_integrity",
        ] {
            p.check(attestation_type::SCORES, Some(dim), identity_type::AGENT)
                .unwrap_or_else(|e| panic!("transition admit failed for {dim}: {e:?}"));
        }
    }

    #[test]
    fn admission_accepts_canonical_attestation_mechanism_form() {
        let p = default_policy();
        for dim in ATTESTATION_LADDER_MECHANISMS {
            p.check(attestation_type::SCORES, Some(dim), identity_type::AGENT)
                .unwrap_or_else(|e| panic!("canonical admit failed for {dim}: {e:?}"));
        }
    }

    #[test]
    fn admission_rejects_deprecated_form_post_ceg_0_3_flip() {
        // Post-CEG-0.3 flip target — operator sets the policy to
        // RejectDeprecated. The deprecated wire shape no longer
        // benefits from the version-segment carve-out and falls
        // through to the standard missing_version_segment check.
        let mut p = default_policy();
        p.attestation_ladder_transition = AttestationLadderTransitionPolicy::RejectDeprecated;
        let err = p
            .check(
                attestation_type::SCORES,
                Some("attestation:l1:self_verify"),
                identity_type::AGENT,
            )
            .unwrap_err();
        match err {
            Error::DimensionRejected { reason, .. } => {
                assert_eq!(reason, "missing_version_segment");
            }
            other => panic!("expected DimensionRejected, got {other:?}"),
        }
    }

    #[test]
    fn deprecated_ladder_prefix_parser_rejects_malformed() {
        // Sanity checks on the deprecated-shape parser.
        assert!(super::is_deprecated_attestation_ladder_prefix(
            "attestation:l1:self_verify"
        ));
        assert!(super::is_deprecated_attestation_ladder_prefix(
            "attestation:l42:agent_integrity"
        ));
        // Missing digit set.
        assert!(!super::is_deprecated_attestation_ladder_prefix(
            "attestation:l:foo"
        ));
        // Non-digit after l.
        assert!(!super::is_deprecated_attestation_ladder_prefix(
            "attestation:lxa:foo"
        ));
        // Missing mechanism.
        assert!(!super::is_deprecated_attestation_ladder_prefix(
            "attestation:l1:"
        ));
        // Not the attestation:l prefix at all.
        assert!(!super::is_deprecated_attestation_ladder_prefix(
            "attestation:self_verify"
        ));
        assert!(!super::is_deprecated_attestation_ladder_prefix(
            "system:l1:foo"
        ));
    }

    #[test]
    fn default_reserved_prefix_rules_cover_ceg_persist_slice() {
        // Sanity: the default rules cover the CEG §5.3 substrate-
        // self-report set + §7.6 witness rule. Regression-guards the table
        // doc-comment.
        let rules = default_reserved_prefix_rules();
        let prefixes: Vec<&str> = rules.iter().map(|r| r.pattern_prefix.as_str()).collect();
        for expected in &[
            "system:",
            "audit_chain:",
            "corpus_health:",
            "identity_continuity:",
            "federation_directory:",
            "transparency_log:cosigned:",
            // CEG 0.3 §5.6.8.3 landed FOUR media-sharing families here; only
            // this one survives. CC 3.3.12 leaves the other three open
            // vocabulary — see MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN.
            "age_assurance:",
        ] {
            assert!(
                prefixes.contains(expected),
                "default rules missing {expected}; got {prefixes:?}"
            );
        }
        // The removal direction, asserted rather than left to the absence of a
        // line: a re-added gate on a family CC leaves open is the regression
        // CIRISPersist#571 fixed.
        for gone in MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN {
            assert!(
                !prefixes.contains(&gone.0),
                "{:?} is gated again — CC 3.3.12 leaves it open vocabulary ({}). If CC has since \
                 landed a reserved rule on the row, restore the gate to match CC's rule and delete \
                 the MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN line; do not restore the CEG-0.3 one.",
                gone.0,
                gone.1
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // (CIRISPersist#590) — the CC 3.1.7 R2 gate suite
    // ══════════════════════════════════════════════════════════════════

    /// Manifest-reserved families persist does **not** carry a
    /// [`ReservedPrefixRule`] for, each with the reason it is not persist's to
    /// gate. Pinned like `KNOWN_AXIS_FUSIONS`: a NEW reserved family arriving in
    /// a re-vendor fails
    /// [`authority_lists_agree_on_every_manifest_family`] until a reviewer
    /// either writes its gate or states here why persist is not the enforcer.
    ///
    /// Two honest reasons appear:
    ///
    /// - **another substrate's self-report.** CC 3.4.3 reserves
    ///   `transport:` / `delivery:` / `delivery_receipt:` / `key_boundary:` /
    ///   `peer_reachability:` to the substrate the claim is ABOUT — which is
    ///   the transport-delivery component, not persist. Gating them to
    ///   `substrate_persist` would be a wrong answer, not a missing one.
    /// - **the rule is not identity-type-shaped.** `licensure:` is co-stewarded
    ///   (CEG §7.3: consumers mark single-source rows `confidence ≤ 0.5`, the
    ///   admission gate deliberately does not reject them); `config:` /
    ///   `consent:` / `ownership:` / `trace:` / `trace_summary:` / `trust:`
    ///   carry CC's opaque `"reserved (see table)"`, whose enforcement lives in
    ///   purpose-built gates elsewhere in this file, not in a prefix→role table.
    const RESERVED_BUT_NOT_GATED_BY_PREFIX_RULE: &[&str] = &[
        "config:",
        "consent:",
        "delivery:",
        "delivery_receipt:",
        "key_boundary:",
        "licensure:",
        "ownership:",
        "peer_reachability:",
        "trace:",
        "trace_summary:",
        "transport:",
        "trust:",
    ];

    /// **CC 3.1.7 R2(a) — the mint gate.** Every family persist declares itself
    /// the producer of must carry a registry row. This is the build failure that
    /// makes a fourth rowless-family cut impossible rather than merely noticed
    /// on the third.
    #[test]
    fn r2a_every_minted_family_has_a_registry_row() {
        use crate::federation::namespace::registry;
        assert!(
            !MINTED_NAMESPACE_FAMILIES.is_empty(),
            "the minted-family list is empty — this gate would pass vacuously"
        );
        for fam in MINTED_NAMESPACE_FAMILIES {
            assert!(
                registry::entries().iter().any(|e| &e.prefix == fam),
                "CC 3.1.7 R2(a) VIOLATION: persist mints {fam:?} but the vendored CC namespace \
                 registry has no row for it. R2(a): a producer minting a new family MUST land its \
                 registry row, carrying the intended emitter/reserved rule, IN THE SAME CHANGE — \
                 otherwise the family admits under the ProducerSteward fallback, an authority \
                 nobody chose for it. Land the CC row and re-vendor, or do not mint the family. \
                 (Spelling counts: the entry must match the registry row's prefix exactly.)"
            );
        }
    }

    /// **The population the inventory does NOT cover, measured rather than
    /// asserted.**
    ///
    /// [`family_rules::RULES_NOT_ON_THE_ROW`](crate::federation::family_rules::RULES_NOT_ON_THE_ROW)
    /// pins the families PERSIST rules on whose row states nothing. That is not
    /// the whole population, and a reader could take a const called "rules not
    /// on the row" for it: most of the manifest carries no machine-readable
    /// rule for anyone. This records the real shape so the scope limit is a
    /// measured fact in the build rather than a caveat in a doc comment, and so
    /// a re-vendor that materially changes rule coverage is visible.
    ///
    /// Deliberately a floor-check, not an equality: CC adding rules is the
    /// desired direction and must not fail the build.
    #[test]
    fn most_of_the_manifest_carries_no_machine_readable_rule() {
        use crate::federation::namespace::registry;
        let total = registry::entries().len();
        let with_rule = registry::entries()
            .iter()
            .filter(|e| e.authority.reserved.is_some())
            .count();
        assert!(
            with_rule < total / 2,
            "rule coverage is now {with_rule}/{total} — over half. That is a GOOD change, but it \
             means the 'the manifest mostly does not state emitter rules' premise behind \
             family_rules::RULES_NOT_ON_THE_ROW's scope note is stale; re-measure it."
        );
        // The specific claim the #67 / #76 asks rest on: persist's own minted
        // section is rule-free — and so are many others, which is why the ask
        // is about the generator's coverage and not about three rows.
        let s3192: Vec<&str> = registry::entries()
            .iter()
            .filter(|e| e.cc_section == "3.1.9.2")
            .map(|e| e.prefix.as_str())
            .collect();
        assert!(
            !s3192.is_empty(),
            "CC 3.1.9.2 vanished from the manifest — the section persist mints into"
        );
        assert!(
            registry::entries()
                .iter()
                .filter(|e| e.cc_section == "3.1.9.2")
                .all(|e| e.authority.reserved.is_none()),
            "a CC 3.1.9.2 family now carries a machine-readable rule ({s3192:?}) — check whether \
             it is one of persist's three, and if so delete its \
             family_rules::RULES_NOT_ON_THE_ROW line"
        );
    }

    /// The mint list is not a hand-kept parallel copy: every entry is the
    /// `NAMESPACE_FAMILY` const of the module that actually mints on it, so the
    /// declaration and the minting code cannot diverge.
    #[test]
    fn minted_family_list_matches_the_modules_that_mint() {
        use std::collections::BTreeSet;
        let declared: BTreeSet<&str> = [
            crate::federation::reverse_quorum::NAMESPACE_FAMILY,
            crate::federation::quarantine::NAMESPACE_FAMILY,
            crate::federation::ownership_reclaim::NAMESPACE_FAMILY,
            crate::federation::mesh_config::NAMESPACE_FAMILY,
        ]
        .into_iter()
        .collect();
        let listed: BTreeSet<&str> = MINTED_NAMESPACE_FAMILIES.iter().copied().collect();
        assert_eq!(
            listed, declared,
            "MINTED_NAMESPACE_FAMILIES must be exactly the NAMESPACE_FAMILY consts of the modules \
             that mint — a family minted by a module missing from this set is a family the R2(a) \
             gate never checks"
        );
    }

    /// **CC 3.1.7 R2 closed-set gate.** Every family persist governs is either
    /// registered or a declared exception. A new `ReservedPrefixRule` for a
    /// family CC has no row for fails here — which is where R2(b)'s loudness
    /// lands for the families persist ships gates for.
    #[test]
    fn r2_governed_families_are_registered_or_declared() {
        use crate::federation::namespace::registry;
        let stems = governed_family_stems();
        assert!(!stems.is_empty(), "governed set empty — vacuous gate");
        let undeclared: Vec<&String> = stems
            .iter()
            .filter(|s| {
                !registry::is_family_registered(s) && !UNREGISTERED_GATED_FAMILIES.contains(&&***s)
            })
            .collect();
        assert!(
            undeclared.is_empty(),
            "CC 3.1.7 R2: persist governs famil(ies) {undeclared:?} that the vendored CC namespace \
             registry does not register and UNREGISTERED_GATED_FAMILIES does not declare. Either \
             land the CC row and re-vendor, or add the stem to UNREGISTERED_GATED_FAMILIES with \
             the reason CC has nothing to say about it — silence is the one option R2 removes."
        );
    }

    /// The declared exceptions must stay TRUE. Once CC registers one, the line
    /// is a stale excuse that would keep an admitted-by-exception family out of
    /// the real gate; this fails until it is deleted.
    #[test]
    fn declared_exceptions_are_still_unregistered() {
        use crate::federation::namespace::registry;
        for stem in UNREGISTERED_GATED_FAMILIES {
            assert!(
                !registry::is_family_registered(stem),
                "{stem:?} is declared in UNREGISTERED_GATED_FAMILIES but CC now REGISTERS it — \
                 delete the line so the family goes through the real R2 gate"
            );
            assert!(
                stem.ends_with(':'),
                "{stem:?} must be a family stem (ending in ':'), not a leaf prefix"
            );
            assert!(
                governed_family_stems().iter().any(|g| g == stem),
                "{stem:?} is declared an exception to a gate it is not subject to — persist does \
                 not govern that family, so the line excuses nothing"
            );
        }
    }

    /// **THE DIFFERENTIAL WITNESS** (CIRISPersist#590, the #541/#532/#588
    /// class): `namespace/registry.rs#authority_for` — resolved over the
    /// vendored manifest — and `admission.rs#default_reserved_prefix_rules` —
    /// hand-maintained here — must agree about every family in the manifest.
    ///
    /// The two disagreed for real before this cut: the rule table knew
    /// `capacity_assurance:` was witness-reserved while `authority_for` returned
    /// `ProducerSteward`/`reserved: None`, because the generator walked only
    /// `### 3.1.N` and never saw the CC-3.4.12 block. Compose that with R2(b)
    /// and it is a fail-closed trap. Both directions are checked:
    ///
    /// - **persist must not over-refuse** — a family persist gates must be one
    ///   CC actually reserves, or persist is demanding an emitter role for
    ///   traffic the Constitution leaves open;
    /// - **persist must not silently under-enforce** — a family CC reserves must
    ///   be gated here, or appear in
    ///   [`RESERVED_BUT_NOT_GATED_BY_PREFIX_RULE`] with its reason.
    #[test]
    fn authority_lists_agree_on_every_manifest_family() {
        use crate::federation::namespace::registry;
        let rules = default_reserved_prefix_rules();
        let mut over_refused: Vec<String> = Vec::new();
        let mut under_enforced: Vec<String> = Vec::new();

        for entry in registry::entries() {
            // A concrete dimension on this family: the literal stem the
            // manifest's `{param}`/`*` prefix truncates to, which is exactly
            // what `authority_for` and the rule table both match against.
            let dim = &entry.match_prefix;
            let manifest_reserved = registry::authority_for(dim).reserved.is_some();
            let gated_by_rule = rules.iter().any(|r| dim.starts_with(&r.pattern_prefix));
            let gated_by_arm = HARD_CODED_RESERVED_STEMS.iter().any(|s| dim.starts_with(s));

            if gated_by_rule && !manifest_reserved {
                over_refused.push(format!(
                    "{} (persist demands an emitter role; the manifest says the family is open)",
                    entry.prefix
                ));
            }
            if manifest_reserved
                && !gated_by_rule
                && !gated_by_arm
                && !RESERVED_BUT_NOT_GATED_BY_PREFIX_RULE
                    .iter()
                    .any(|s| dim.starts_with(s))
            {
                under_enforced.push(format!(
                    "{} (CC reserves it: {:?}; persist has no gate and no declared reason)",
                    entry.prefix,
                    registry::authority_for(dim).reserved.map(|r| r.rule)
                ));
            }
        }

        assert!(
            over_refused.is_empty(),
            "SPLIT TRUTH — persist OVER-REFUSES (CIRISPersist#590): {over_refused:?}. \
             `default_reserved_prefix_rules` gates famil(ies) the vendored manifest marks \
             unreserved. Under CC 3.1.7 R2 that is persist refusing traffic the Constitution \
             leaves open. Fix the rule table or re-vendor a manifest that carries the reservation."
        );
        assert!(
            under_enforced.is_empty(),
            "SPLIT TRUTH — persist UNDER-ENFORCES (CIRISPersist#590): {under_enforced:?}. The \
             manifest reserves these famil(ies) and no gate in this file enforces it, so they \
             admit from any emitter. Add the ReservedPrefixRule, or record the family in \
             RESERVED_BUT_NOT_GATED_BY_PREFIX_RULE with the reason persist is not its enforcer."
        );
    }

    /// R2(b) refuses a governed family whose row went missing — the runtime
    /// half. Exercised against the real predicate; the mutation is "pretend
    /// `objection:` were never registered", which is precisely the state
    /// v24.3.0 shipped in.
    #[test]
    fn r2b_refuses_a_governed_family_with_no_registry_row() {
        // A governed, unregistered, undeclared family: constructed rather than
        // taken from the live set, because the live set is (correctly) empty.
        // `is_governed_family` reads MINTED_NAMESPACE_FAMILIES and the rule
        // table, so this asserts the refusal SHAPE on a stem that is governed
        // by construction — see the backend witnesses for the wired path.
        let err = Error::NamespaceFamilyUnregistered {
            namespace: "objection:raised:v1".into(),
            family_stem: "objection:".into(),
            reason: NamespaceConformanceReason::FamilyUnregistered.as_str(),
        };
        assert_eq!(err.kind(), "federation_namespace_family_unregistered");
        assert!(err.to_string().contains("CC 3.1.7 R2(b)"));

        // And the live predicate admits every governed family today, because
        // every one of them is registered or declared — the state R2(a)'s build
        // gate maintains.
        for fam in MINTED_NAMESPACE_FAMILIES {
            let dim = format!(
                "{}probe:v1",
                crate::federation::namespace::registry::family_stem(fam)
            );
            assert!(
                check_namespace_family_registered(&dim).is_ok(),
                "{dim} is minted by persist and registered by CC; it must admit"
            );
        }
    }

    /// **The conformant-traffic guard** — the failure CIRISPersist#590 named.
    /// R2(b) must never refuse the open vocabulary: dimensions persist has no
    /// opinion about, and `{param}` values inside registered families.
    #[test]
    fn r2b_never_refuses_open_vocabulary() {
        for dim in [
            // ungoverned, unregistered — the open space CC preserves
            "trust:demo:v1",
            "identity_binding:v1",
            "totally:made:up:v1",
            "regex:github_pat_v1",
            "",
            // structural primitives carry no family at all
            "scores",
            "delegates_to",
            "withdraws",
            // open vocabulary INSIDE registered families
            "credits:rust:en:alice",
            "detection:emergent_pattern:novel_signal:v1",
            "capacity:core_identity:v1",
            "hard_case:moderation_filed:v1",
            "accord:human_dignity:v1",
            // the declared CEG-0.3 exceptions
            "content_rating:mpa:pg13:v1",
            "content_class:violence:v1",
            "cw_class:flashing_lights:v1",
        ] {
            assert!(
                check_namespace_family_registered(dim).is_ok(),
                "R2(b) must not refuse {dim:?} — refusing conformant traffic and blaming the \
                 producer is the failure mode CIRISPersist#590 was opened to prevent"
            );
        }
    }

    /// The refusal token is CC's own word, and the typed spelling matches the
    /// serde spelling so a consumer reading the wire and one holding the value
    /// key on the same constant.
    #[test]
    fn namespace_conformance_reason_token_is_ccs_own_word() {
        assert_eq!(
            NamespaceConformanceReason::FamilyUnregistered.as_str(),
            "namespace_family_unregistered"
        );
        let json = serde_json::to_string(&NamespaceConformanceReason::FamilyUnregistered).unwrap();
        assert_eq!(
            json,
            format!(
                "\"{}\"",
                NamespaceConformanceReason::FamilyUnregistered.as_str()
            ),
            "the serde token and as_str must not drift"
        );
    }

    /// The governed set is DERIVED from its sources, not re-listed beside them:
    /// every `pattern_prefix`'s stem, every hard-coded arm and every quota-
    /// reserve prefix is governed by construction, so adding one anywhere puts
    /// its family under R2 automatically.
    #[test]
    fn governed_set_is_derived_from_the_rule_table() {
        use crate::federation::namespace::registry::family_stem;
        let stems = governed_family_stems();
        for rule in default_reserved_prefix_rules() {
            let stem = family_stem(&rule.pattern_prefix).to_owned();
            assert!(
                stems.contains(&stem),
                "{stem:?} carries a ReservedPrefixRule but is not in the governed set — the R2 \
                 gate and the reserved-prefix table have drifted apart"
            );
        }
        for arm in HARD_CODED_RESERVED_STEMS {
            assert!(stems.contains(&(*arm).to_owned()), "{arm:?} not governed");
        }
        for p in crate::federation::replication::admission::RESERVED_CLASS_DIMENSION_PREFIXES {
            assert!(
                stems.contains(&family_stem(p).to_owned()),
                "{p:?} carries reserved admission budget but is not governed — a family this node \
                 treats as special that R2 never asks about"
            );
        }
        // sorted + deduped, so `is_governed_family`'s scan and this list agree
        assert!(stems.windows(2).all(|w| w[0] < w[1]));
    }

    /// **The #575 copy-debt, retired** (CIRISPersist#590).
    ///
    /// `RESERVED_CLASS_DIMENSION_PREFIXES` carries the string `"objection:"` as
    /// a deliberate copy of a family `reverse_quorum` owns, and its own doc
    /// names the retirement condition: *"When #574 and #575 land in one tree,
    /// replace `"objection:"` with a reference to
    /// `reverse_quorum::NAMESPACE_FAMILY` so the prefix and the dimensions that
    /// ride it cannot drift apart."*
    ///
    /// They HAVE landed in one tree. The const's type (`&[&str]`, matched with
    /// `starts_with` on a hot admission path) can't hold a runtime-derived stem
    /// without becoming a function, so the binding is made here instead: the
    /// literal must equal `family_stem` of the const that owns the family.
    /// Same guarantee — the two cannot drift — without changing a public type
    /// or paying an allocation per admitted row.
    #[test]
    fn quota_reserve_objection_prefix_is_bound_to_the_family_that_owns_it() {
        use crate::federation::namespace::registry::family_stem;
        let owned = family_stem(crate::federation::reverse_quorum::NAMESPACE_FAMILY);
        assert!(
            crate::federation::replication::admission::RESERVED_CLASS_DIMENSION_PREFIXES
                .contains(&owned),
            "the #575 quota reserve must protect exactly the stem \
             reverse_quorum::NAMESPACE_FAMILY declares ({owned:?}) — a reserve that names a \
             different string protects rows nobody emits and leaves the real ones to be crowded \
             out"
        );
        // And the accord half names the family CC reserves, not a near-miss.
        assert!(
            crate::federation::replication::admission::RESERVED_CLASS_DIMENSION_PREFIXES
                .contains(&family_stem("accord:*")),
            "the accord kill-switch stem must be in the reserve"
        );
    }

    // ── CEG 0.3 §5.6.8.3 + §11.5.3 landed FOUR reserved-prefix families here.
    //    CC 3.3.12 later catalogued them and left three OPEN; only
    //    `age_assurance:` survives as a reserved prefix. See
    //    MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN. ──

    /// **CIRISPersist#571 — the policy-layer twin of the removal.**
    ///
    /// Replaces three v3.0.0 tests that asserted the CEG-0.3 emitter rules
    /// (`content_rating:` → `trusted_publisher`, `content_class:` /
    /// `cw_class:` → `substrate_persist`). CC 3.3.12 catalogued all three as
    /// **open vocabulary** and CC 3.4.14 R1 makes the `content_class` marking
    /// mandatory for *every* attester, so those assertions encoded a rule the
    /// Constitution declines to make. They are inverted rather than deleted:
    /// the families must now admit from identities that were previously
    /// refused, which is the property the removal exists to deliver.
    ///
    /// Pure-policy layer only. The executed three-backend witness through the
    /// real `put_attestation` door is
    /// `crate::federation::regime::tests::cc_3414_r1_class_marking_admits_from_any_attester`.
    #[test]
    fn media_plane_families_cc_leaves_open_admit_from_any_emitter() {
        let p = default_policy();
        // Every identity_type that used to be refused on at least one of these.
        for identity in [
            identity_type::AGENT,
            identity_type::WITNESS,
            identity_type::SUBSTRATE_PERSIST,
            identity_type::TRUSTED_PUBLISHER,
        ] {
            for dim in [
                // CC 3.4.14 R1's mandatory markings — the sharp case.
                "content_class:generated:v1",
                "content_class:generated_modified:v1",
                "content_class:violence:v1",
                "content_rating:mpa:pg13:v1",
                // CC 3.3.12 names `operator:{operator_id}` rubrics explicitly.
                "content_rating:operator:acme:strong:v1",
                "cw_class:flashing_lights:v1",
            ] {
                p.check(attestation_type::SCORES, Some(dim), identity)
                    .unwrap_or_else(|e| {
                        panic!(
                            "CC 3.3.12 leaves {dim} open vocabulary, but the policy refused it \
                             from identity_type={identity:?}: {e}"
                        )
                    });
            }
        }
        // The reasoning const must describe exactly the families that were
        // freed — not a stem that is still gated, and not a stale line.
        let rules = default_reserved_prefix_rules();
        for (stem, why, still_discriminates) in MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN {
            assert!(
                !rules.iter().any(|r| r.pattern_prefix == *stem),
                "{stem:?} is recorded as CC-leaves-open but is gated again"
            );
            assert!(
                why.contains("CC 3.3.12"),
                "{stem:?} must cite the clause that leaves it open, got {why:?}"
            );
            assert!(
                still_discriminates.len() > 30,
                "{stem:?} must name what DOES discriminate now — an open write door with nothing \
                 said about the read door reads as a hole rather than a decision"
            );
        }
    }

    #[test]
    fn reserved_prefix_age_assurance_requires_witness_emitter() {
        // CEG 0.3 §5.6.8.3: age_assurance:* is witness-only (registered
        // age-assurance provider).
        let p = default_policy();
        let err = p
            .check(
                attestation_type::SCORES,
                Some("age_assurance:thirteen_plus:v1"),
                identity_type::SUBSTRATE_PERSIST,
            )
            .unwrap_err();
        match err {
            Error::ReservedPrefixEmitterMismatch {
                prefix, required, ..
            } => {
                assert_eq!(prefix, "age_assurance:");
                assert_eq!(required, vec!["witness".to_string()]);
            }
            other => panic!("expected ReservedPrefixEmitterMismatch, got {other:?}"),
        }
        // witness passes.
        p.check(
            attestation_type::SCORES,
            Some("age_assurance:thirteen_plus:v1"),
            identity_type::WITNESS,
        )
        .unwrap();
    }

    #[test]
    fn self_declared_age_rung_refuses_level_token() {
        // CC 3.4.11 (CIRISPersist#307): the self-declared rung carries a
        // `{band}`, never a `{level}`. `age_self_declared:level:*` is reserved
        // to the witness `age_assurance:` rung and must be refused structurally
        // — independent of emitter (no identity_type rescues the shape).
        let p = default_policy();
        for emitter in [
            identity_type::AGENT,
            identity_type::WITNESS,
            identity_type::SUBSTRATE_PERSIST,
        ] {
            for dim in ["age_self_declared:level:adult", "age_self_declared:level"] {
                let err = p
                    .check(attestation_type::SCORES, Some(dim), emitter)
                    .expect_err(&format!("{dim:?} must be refused for emitter {emitter:?}"));
                match err {
                    Error::DimensionRejected { reason, .. } => assert_eq!(
                        reason,
                        DimensionRejectionReason::SelfDeclaredLevelReserved.as_str(),
                        "{dim:?} should refuse with self_declared_level_reserved",
                    ),
                    other => panic!("expected DimensionRejected, got {other:?}"),
                }
            }
        }
        // The `{band}` shape is NOT caught by the level rule — a versioned
        // band self-assertion admits (subject-signed). (The bare
        // `age_self_declared:band:adult` form the conformance suite uses is
        // admitted on the production path; here it would trip the orthogonal
        // version-segment rule, so the versioned form isolates the level gate.)
        p.check(
            attestation_type::SCORES,
            Some("age_self_declared:band:adult:v1"),
            identity_type::AGENT,
        )
        .unwrap();
    }

    // ── #150 Ask 3: cohort_scope admission-gate validation ─────────

    #[test]
    fn cohort_scope_admits_every_closed_set_value() {
        use crate::federation::types::cohort_scope as cs;
        for scope in [
            cs::SELF,
            cs::FAMILY,
            cs::COMMUNITY,
            cs::AFFILIATIONS,
            cs::SPECIES,
            cs::BIOSPHERE,
            cs::FEDERATION,
        ] {
            check_cohort_scope(scope)
                .unwrap_or_else(|e| panic!("closed-set value {scope:?} must admit, got {e:?}"));
        }
    }

    #[test]
    fn cohort_scope_rejects_global_feed_name() {
        // `global` is a §8.1.8 feed-name (aggregates species/biosphere/
        // federation), NEVER a wire value — it must be rejected.
        let err = check_cohort_scope("global").unwrap_err();
        match err {
            Error::CohortScopeRejected { ref cohort_scope } => {
                assert_eq!(cohort_scope, "global");
                assert_eq!(err.kind(), "federation_cohort_scope_rejected");
            }
            other => panic!("expected CohortScopeRejected, got {other:?}"),
        }
    }

    #[test]
    fn cohort_scope_rejects_garbage_and_empty() {
        assert!(matches!(
            check_cohort_scope("").unwrap_err(),
            Error::CohortScopeRejected { .. }
        ));
        assert!(matches!(
            check_cohort_scope("Self").unwrap_err(),
            Error::CohortScopeRejected { .. }
        ));
        assert!(matches!(
            check_cohort_scope("partnered").unwrap_err(),
            Error::CohortScopeRejected { .. }
        ));
    }

    // ── #153 Ask 5: structural-invisibility classification ─────────

    #[test]
    fn cohort_scope_suppresses_holds_bytes_only_for_self_and_family() {
        use crate::federation::types::cohort_scope as cs;
        // self + family are structurally invisible — no holds_bytes.
        assert!(cs::suppresses_holds_bytes(cs::SELF));
        assert!(cs::suppresses_holds_bytes(cs::FAMILY));
        // everything else federates and emits holds_bytes per status quo
        // (CEG 0.8 §8.1.13.3 is explicit that community is NOT suppressed).
        for scope in [
            cs::COMMUNITY,
            cs::AFFILIATIONS,
            cs::SPECIES,
            cs::BIOSPHERE,
            cs::FEDERATION,
        ] {
            assert!(
                !cs::suppresses_holds_bytes(scope),
                "{scope:?} must federate (emit holds_bytes)"
            );
        }
        // unknown values are not suppressors (they're rejected upstream
        // by is_valid / the admission gate).
        assert!(!cs::suppresses_holds_bytes("global"));
    }

    // ── AV-45 (FSD §4.6): write-path cohort_scope admission gate ────

    use crate::scope::{CallerAdmission, ScopeRefusalReason};

    /// A writer in family F1 + community C1 (and identity == occurrence).
    fn writer_in_f1_c1() -> CallerAdmission {
        CallerAdmission::for_test(
            "writer-occ",
            "writer-identity",
            ["family-key:f1".to_string()],
            ["community-key:c1".to_string()],
        )
    }

    #[test]
    fn write_self_always_permitted() {
        // `self` is a no-op pass — the substrate stamps the target from
        // the verified signer; any caller-supplied target is ignored.
        let w = writer_in_f1_c1();
        DimensionAdmissionPolicy::check_write_cohort_scope(&w, "self", None).unwrap();
        // A bogus self-target is still permitted at the gate (it's
        // overwritten by D2's self-target resolution, not trusted here).
        DimensionAdmissionPolicy::check_write_cohort_scope(&w, "self", Some("victim-id")).unwrap();
    }

    #[test]
    fn write_family_member_permitted() {
        let w = writer_in_f1_c1();
        DimensionAdmissionPolicy::check_write_cohort_scope(&w, "family", Some("family-key:f1"))
            .unwrap();
    }

    #[test]
    fn write_family_non_member_refused() {
        // Downgrade attempt: claim a family the writer is NOT in.
        let w = writer_in_f1_c1();
        let err =
            DimensionAdmissionPolicy::check_write_cohort_scope(&w, "family", Some("family-key:f9"))
                .unwrap_err();
        assert_eq!(err, ScopeRefusalReason::NoFamilyMembership);
        assert_eq!(err.kind(), "scope_no_family_membership");
    }

    #[test]
    fn write_family_missing_target_refused() {
        // Claiming family visibility without naming a family cannot be
        // membership-validated — refused.
        let w = writer_in_f1_c1();
        let err =
            DimensionAdmissionPolicy::check_write_cohort_scope(&w, "family", None).unwrap_err();
        assert_eq!(err, ScopeRefusalReason::NoFamilyMembership);
    }

    #[test]
    fn write_community_member_permitted() {
        let w = writer_in_f1_c1();
        DimensionAdmissionPolicy::check_write_cohort_scope(
            &w,
            "community",
            Some("community-key:c1"),
        )
        .unwrap();
    }

    #[test]
    fn write_community_non_member_refused() {
        // The §4.6 named downgrade-refusal: writer claims community C2
        // they are NOT a member of → NoCommunityMembership.
        let w = writer_in_f1_c1();
        let err = DimensionAdmissionPolicy::check_write_cohort_scope(
            &w,
            "community",
            Some("community-key:c2"),
        )
        .unwrap_err();
        assert_eq!(err, ScopeRefusalReason::NoCommunityMembership);
        assert_eq!(err.kind(), "scope_no_community_membership");
    }

    #[test]
    fn write_community_missing_target_refused() {
        let w = writer_in_f1_c1();
        let err =
            DimensionAdmissionPolicy::check_write_cohort_scope(&w, "community", None).unwrap_err();
        assert_eq!(err, ScopeRefusalReason::NoCommunityMembership);
    }

    #[test]
    fn write_broad_tiers_permitted_for_any_authenticated_writer() {
        // Broad belonging-tiers carry no per-row target; any
        // authenticated writer may emit. A writer with empty admission
        // sets passes all four.
        let w = CallerAdmission::for_test("sovereign-occ", "sovereign-occ", [], []);
        for scope in ["affiliations", "species", "biosphere", "federation"] {
            DimensionAdmissionPolicy::check_write_cohort_scope(&w, scope, None)
                .unwrap_or_else(|e| panic!("broad tier {scope} must admit, got {e:?}"));
            // A spurious target on a broad tier is ignored (no target
            // semantics) — still admitted.
            DimensionAdmissionPolicy::check_write_cohort_scope(&w, scope, Some("ignored")).unwrap();
        }
    }

    #[test]
    fn write_unknown_cohort_scope_refused_invalid() {
        let w = writer_in_f1_c1();
        // `global` is a feed-name, never a wire value; garbage too.
        for bad in ["global", "", "Self", "partnered"] {
            let err =
                DimensionAdmissionPolicy::check_write_cohort_scope(&w, bad, None).unwrap_err();
            match err {
                ScopeRefusalReason::InvalidCohortScope(ref label) => {
                    assert_eq!(label, bad);
                    assert_eq!(err.kind(), "scope_invalid_cohort_scope");
                }
                other => panic!("expected InvalidCohortScope({bad:?}), got {other:?}"),
            }
        }
    }

    #[test]
    fn write_family_target_membership_is_exact_not_substring() {
        // Set-membership is exact-match, not prefix/substring — a writer
        // in `family-key:f1` cannot stamp `family-key:f10`.
        let w = writer_in_f1_c1();
        assert_eq!(
            DimensionAdmissionPolicy::check_write_cohort_scope(
                &w,
                "family",
                Some("family-key:f10")
            )
            .unwrap_err(),
            ScopeRefusalReason::NoFamilyMembership
        );
    }

    // ── #236 CC 1.13.5 — scopes_are_infra_only verifier unit table ─────

    /// Build a `HashSet<String>` from string slices for the table tests.
    fn scope_set(items: &[&str]) -> std::collections::HashSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// v19.1.1 (verify 10.6.1 re-pin) — the DIFFERENTIAL VOCABULARY GUARD:
    /// persist's `delegation_scope` infra tokens and verify-core's
    /// `INFRA_SCOPES` must be the SAME SET, and every persist token must
    /// pass verify's exact-membership fail-closed gate
    /// (`verify_delegation_scope_split`). This pins the drift class 10.6.1
    /// fixed: the RC3 vocab cut (#487) landed in server+persist while
    /// verify still enumerated the retired `infra:join_communities` — one
    /// fact, two gate verdicts (delegations passed persist's prefix
    /// admission but read UnknownScope on the verify/FFI surface). Any
    /// future one-sided vocabulary change now fails THIS test instead of
    /// fail-closing real delegations in the field.
    #[test]
    fn persist_and_verify_infra_scope_vocabularies_are_identical() {
        use super::super::types::delegation_scope as ds;
        let persist_infra = [
            ds::INFRA_NETWORK_PRESENCE,
            ds::INFRA_HOLD_COMMUNITY_MEMBERSHIP,
            ds::INFRA_HOLD_FAMILY_MEMBERSHIP,
            ds::INFRA_SERVE,
            ds::INFRA_STORE,
            ds::INFRA_TRANSPORT,
            ds::INFRA_ATTEST,
        ];
        // Same SET (order-independent), both directions.
        let mut ours: Vec<&str> = persist_infra.to_vec();
        let mut theirs: Vec<&str> = ciris_verify_core::operational_admit::INFRA_SCOPES.to_vec();
        ours.sort_unstable();
        theirs.sort_unstable();
        assert_eq!(
            ours, theirs,
            "persist delegation_scope infra set != verify INFRA_SCOPES — \
             a one-sided vocabulary change (the 10.6.1 drift class)"
        );
        // And every token passes verify's fail-closed gate on a node.
        let scopes: Vec<String> = persist_infra.iter().map(|s| s.to_string()).collect();
        ciris_verify_core::operational_admit::verify_delegation_scope_split("node", &scopes)
            .expect("every persist infra token must be verify-admissible on a node");
        // The retired token stays dead on BOTH sides.
        let retired = vec!["infra:join_communities".to_owned()];
        assert!(
            ciris_verify_core::operational_admit::verify_delegation_scope_split("node", &retired)
                .is_err(),
            "retired infra:join_communities must fail-close on the verify gate"
        );
    }

    #[test]
    fn scopes_are_infra_only_table() {
        use super::super::types::delegation_scope as ds;

        // infra-only set → true (single + multiple).
        assert!(scopes_are_infra_only(&scope_set(&[ds::INFRA_SERVE])));
        assert!(scopes_are_infra_only(&scope_set(&[
            ds::INFRA_NETWORK_PRESENCE,
            ds::INFRA_HOLD_COMMUNITY_MEMBERSHIP,
            ds::INFRA_HOLD_FAMILY_MEMBERSHIP,
            ds::INFRA_SERVE,
            ds::INFRA_STORE,
            ds::INFRA_TRANSPORT,
            ds::INFRA_ATTEST,
        ])));

        // mixed infra + agency → false.
        assert!(!scopes_are_infra_only(&scope_set(&[
            ds::INFRA_SERVE,
            ds::AGENCY_ACT_ON_BEHALF
        ])));

        // agency-only → false.
        assert!(!scopes_are_infra_only(&scope_set(&[ds::AGENCY_DECIDE])));
        assert!(!scopes_are_infra_only(&scope_set(&[
            ds::AGENCY_ACT_ON_BEHALF,
            ds::AGENCY_MESSAGE_IO,
            ds::AGENCY_REASON,
            ds::AGENCY_DECIDE,
        ])));

        // legacy unprefixed agency kind → false.
        for legacy in ds::LEGACY_AGENCY_KINDS {
            assert!(
                !scopes_are_infra_only(&scope_set(&[legacy])),
                "legacy agency kind {legacy:?} must not be infra-only"
            );
            assert!(ds::is_legacy_agency_scope(legacy));
        }

        // empty set → false.
        assert!(!scopes_are_infra_only(&scope_set(&[])));

        // unknown / other prefix → false.
        assert!(!scopes_are_infra_only(&scope_set(&["consent_revocation"])));
        assert!(!scopes_are_infra_only(&scope_set(&["moderate"])));
        // `network_presence` (unprefixed) is NOT infra:* and NOT a legacy
        // agency kind — it just isn't an admissible node scope unprefixed.
        assert!(!scopes_are_infra_only(&scope_set(&["network_presence"])));
        assert!(!ds::is_legacy_agency_scope("network_presence"));
    }
}

/// v13.2.0 (CIRISPersist#383) — run `body` against an **isolated, freshly-created
/// postgres database** derived from `base_dsn`, then drop it. The v13.2.0
/// canonical tests seed the accord family (A1/B1/C1) under their real key_ids
/// with TEST hybrid keys to satisfy the 2-of-3 ADD gate; on the SHARED test db
/// that squats the real anchor and breaks concurrent Engine-constructing pg
/// tests. A throwaway db (`ciris_isol_<uuid>`) gives full pg coverage with zero
/// shared-anchor pollution. `CREATE`/`DROP DATABASE` run over a bare admin
/// connection (they cannot execute inside the pool's transactioned session);
/// `DROP … WITH (FORCE)` terminates any lingering pool session.
#[cfg(all(test, feature = "postgres"))]
async fn run_in_isolated_pg_db<F, Fut>(base_dsn: &str, body: F)
where
    F: FnOnce(crate::store::postgres::PostgresBackend) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    use crate::store::backend::Backend as _;
    use crate::store::postgres::PostgresBackend;
    use tokio_postgres::NoTls;

    let (base, _cur_db) = base_dsn.rsplit_once('/').expect("dsn has a db path");
    let db = format!("ciris_isol_{}", uuid::Uuid::new_v4().simple());
    let admin_dsn = format!("{base}/postgres");
    let temp_dsn = format!("{base}/{db}");

    let (admin, conn) = tokio_postgres::connect(&admin_dsn, NoTls)
        .await
        .expect("admin connect");
    let admin_task = tokio::spawn(conn);
    admin
        .execute(&format!("CREATE DATABASE {db}"), &[])
        .await
        .expect("create throwaway db");
    drop(admin);
    let _ = admin_task.await;

    {
        let backend = PostgresBackend::connect(&temp_dsn)
            .await
            .expect("connect throwaway db");
        backend
            .run_migrations()
            .await
            .expect("migrate throwaway db");
        body(backend).await;
    } // backend (pool) dropped → connections released

    let (admin, conn) = tokio_postgres::connect(&admin_dsn, NoTls)
        .await
        .expect("admin reconnect");
    let admin_task = tokio::spawn(conn);
    let _ = admin
        .execute(&format!("DROP DATABASE IF EXISTS {db} WITH (FORCE)"), &[])
        .await;
    drop(admin);
    let _ = admin_task.await;
}

/// v13.0.0 (CIRISPersist#372, CC 3.4.7.1) — the accord-conferred `canonical`
/// admission decision table, run identically against SQLite and (when
/// `CIRIS_PERSIST_TEST_PG_URL` is set) Postgres. Exercises the PRODUCTION gate
/// (`check_canonical_role_admission`) end-to-end through `put_public_key` +
/// `adopt_scrub_upgrade`.
///
/// v13.2.0 (CIRISPersist#383) — the gate is now the **2-of-3 multi-scrub** add:
/// `canonical` is conferred only on a record with ≥ a strict majority of the
/// accord family, each a cryptographically VERIFIED hybrid scrub over the SAME
/// canonical `registration_envelope` (`verify_quorum_policy`). Because the real
/// A1/B1/C1 ceremony private keys are not in the test tree, these tests seed the
/// three accord holders under their REAL key_ids (`accord_holder_roster_key_ids`
/// = A1/B1/C1) with **test hybrid keypairs** (as `node` rows, skipping the HW
/// attestation gate), so the production gate resolves the roster to signable
/// keys and a genuine 2-of-3 co-scrub can be produced + verified end-to-end.
/// Proves: 2 distinct valid anchor scrubs ADMIT; 1 scrub, a FORGED 2nd scrub,
/// two scrubs by the SAME holder, and a self-scrub + 1 anchor are all REFUSED;
/// `canonical` cannot be self-claimed via ANY path.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod canonical_gate_tests {
    use super::super::operational::test_support::{signed_canonical_record, Identity};
    use super::super::types::{algorithm, identity_type, ScrubSig};
    use super::super::{is_canonical, FederationDirectory, KeyRecord, SignedKeyRecord};
    use super::accord_holder_roster_key_ids;
    use crate::verify::canonical::ceg_produce_canonicalize;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};

    /// v21.3.0 (CIRISPersist#513) — the pinned Yubico Attestation Root 1 DER
    /// is byte-identical to CIRISServer's pin (one trust anchor across the
    /// federation). A silent swap of the anchor is a build failure here
    /// first, a behavior change second.
    #[test]
    fn yubico_root_pin_sha256_513() {
        assert_eq!(
            hex::encode(Sha256::digest(super::YUBICO_ATTESTATION_ROOT_1_DER)),
            "62760c6a6ef91679f454c8902b80fd009825b3f25da90f1fbace2ec6586cd5a8",
            "the pinned Yubico attestation root changed — re-pin DELIBERATELY \
             and in lockstep with CIRISServer"
        );
    }

    /// v21.3.0 (CIRISPersist#513) — the REAL baked accord holders (A1/B1/C1,
    /// the actual ceremony artifacts embedded as the genesis seed) each carry
    /// a custody attestation that GENUINELY verifies: holder-authored
    /// bound-hybrid signature, 9c cert chained link-by-link to the pinned
    /// Yubico root, attested key == the holder's federation Ed25519 key,
    /// FIPS-certified + touch=always extensions. Real hardware, real chain —
    /// the positive half of the anti-Sybil floor, no mocks.
    #[test]
    fn baked_accord_holders_fips_custody_verifies_513() {
        let holders = crate::federation::genesis::accord_holder_genesis_records();
        assert_eq!(holders.len(), 3, "A1/B1/C1");
        for h in holders {
            let verdict = super::verify_member_fips_custody(&h.record).unwrap_or_else(|e| {
                panic!(
                    "baked holder {} custody attestation must verify: {e}",
                    h.record.key_id
                )
            });
            assert!(verdict.fips_certified, "{}: FIPS ext", h.record.key_id);
            assert!(verdict.touch_always, "{}: touch ext", h.record.key_id);
        }
    }

    /// v21.3.0 (CIRISPersist#513) — the floor refuses a canonical minted by
    /// an accord roster WITHOUT verified FIPS custody: software members
    /// silently don't count, the 3-floor is unreachable, and the refusal
    /// names both facts. This is the anti-Sybil property end-to-end at the
    /// strict over-roster gate.
    #[tokio::test]
    async fn canonical_floor_refuses_unattested_roster_513() {
        let backend = crate::store::memory::MemoryBackend::new();
        let holders = [
            Identity::new("f513-0"),
            Identity::new("f513-1"),
            Identity::new("f513-2"),
        ];
        for h in &holders {
            super::super::operational::test_support::register_accord_holder(&backend, h)
                .await
                .unwrap();
        }
        let roster: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();
        let rec = signed_canonical_record(
            "canon-floor-513",
            "canonical,node",
            serde_json::json!({ "key_id": "canon-floor-513" }),
            &[&holders[0], &holders[1], &holders[2]],
        );
        let err = super::check_canonical_role_admission_over_roster(&backend, &rec, &roster)
            .await
            .expect_err("3 genuine software scrubs must still be refused by the FIPS floor");
        let msg = format!("{err}");
        assert!(
            msg.contains("floor 3") || msg.contains("unreachable"),
            "refusal must cite the floor: {msg}"
        );
        assert!(
            msg.contains("attestation_evidence") || msg.contains("custody"),
            "refusal must cite the custody rejections: {msg}"
        );
    }

    /// v21.4.0 (CIRISVerify#219 / v10.6.2) — MOCK custody attestations:
    /// a `MockYubicoCa` member verifies against ITS OWN root, is
    /// structurally INERT against the pinned production root, and a
    /// non-FIPS mock is rejected even against its own root. The
    /// per-member half of mesh simulation.
    #[tokio::test]
    async fn mock_member_custody_verifies_against_mock_root_only_513() {
        use ciris_verify_core::accord_custody_attestation::test_support::MockYubicoCa;

        let ca = MockYubicoCa::new();
        let a1 = ca
            .attest_member([0x61u8; 32], "mockA1", "2026-07-26T00:00:00Z")
            .await;
        let mut rec = record("mockA1", identity_type::NODE, "mockA1");
        rec.pubkey_ed25519_base64 = a1.member.ed25519_public_key_base64.clone();
        rec.pubkey_ml_dsa_65_base64 = a1.member.mldsa65_public_key_base64.clone();
        rec.attestation_evidence = Some(serde_json::to_value(&a1.attestation).unwrap());

        let verdict = super::verify_member_fips_custody_against(&rec, ca.root_der())
            .expect("mock member must verify against the mock root");
        assert!(verdict.fips_certified && verdict.touch_always);

        // INERT against the pinned production root — the safety property
        // that makes exporting the mock acceptable at all.
        super::verify_member_fips_custody(&rec)
            .expect_err("a mock member must NEVER verify against the real pinned root");

        // A non-FIPS mock is rejected even against its own root.
        let weak = ca
            .attest_member_with(
                [0x62u8; 32],
                "mockWeak",
                "2026-07-26T00:00:00Z",
                false,
                0x02, // TOUCH_POLICY_ALWAYS (private const in verify-core)
            )
            .await;
        let mut wrec = record("mockWeak", identity_type::NODE, "mockWeak");
        wrec.pubkey_ed25519_base64 = weak.member.ed25519_public_key_base64.clone();
        wrec.pubkey_ml_dsa_65_base64 = weak.member.mldsa65_public_key_base64.clone();
        wrec.attestation_evidence = Some(serde_json::to_value(&weak.attestation).unwrap());
        let err = super::verify_member_fips_custody_against(&wrec, ca.root_der())
            .expect_err("non-FIPS mock must be rejected");
        assert!(err.contains("FIPS"), "{err}");
    }

    /// v21.4.0 (CIRISVerify#219) — the floor DISCRIMINATOR: with 3
    /// mock-FIPS-attested roster members and the mock root injected, the
    /// gate's failure moves PAST the custody floor ("floor 3 exceeds the 0
    /// qualifying") to the signature tally ("insufficient distinct valid
    /// signatures") — proving the FIPS filter genuinely counted all three
    /// fabricated members. (A full positive mint additionally needs the
    /// members' ML-DSA private halves, which the mock deliberately does not
    /// expose yet — tracked verify-side; the real-artifact witnesses cover
    /// the full positive path.)
    #[tokio::test]
    async fn mock_quorum_qualifies_the_floor_513() {
        use ciris_verify_core::accord_custody_attestation::test_support::MockYubicoCa;

        let backend = crate::store::memory::MemoryBackend::new();
        let ca = MockYubicoCa::new();
        let mut roster = Vec::new();
        for (i, kid) in ["mq0", "mq1", "mq2"].iter().enumerate() {
            let m = ca
                .attest_member([0x70 + i as u8; 32], kid, "2026-07-26T00:00:00Z")
                .await;
            let mut rec = record(kid, identity_type::NODE, kid);
            rec.pubkey_ed25519_base64 = m.member.ed25519_public_key_base64.clone();
            rec.pubkey_ml_dsa_65_base64 = m.member.mldsa65_public_key_base64.clone();
            rec.attestation_evidence = Some(serde_json::to_value(&m.attestation).unwrap());
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
            roster.push((*kid).to_string());
        }
        let rec = record("canon-mock-513", "canonical,node", "mq0");
        let err = super::check_canonical_role_admission_over_roster_with_custody_root(
            &backend,
            &rec,
            &roster,
            ca.root_der(),
        )
        .await
        .expect_err("garbage scrubs cannot mint even with a qualified roster");
        let msg = format!("{err}");
        assert!(
            msg.contains("insufficient distinct valid signatures"),
            "failure must be at the signature tally, not the custody floor: {msg}"
        );
        assert!(
            !msg.contains("floor 3 exceeds"),
            "all 3 mock members must have QUALIFIED past the FIPS filter: {msg}"
        );
    }

    /// v21.4.0 (CIRISVerify#221 / v10.6.3) — the FULL POSITIVE MINT with
    /// fabricated hardware: three `MockYubicoCa` members (FIPS-shaped
    /// custody artifacts + the deterministic hybrid `.holder` signer)
    /// co-scrub a NEW canonical, and the strict gate — withdrawal-wins +
    /// the ≥3-FIPS floor + the real quorum crypto — ADMITS it against the
    /// injected mock root. No hardware, no ceremony, inert against any
    /// real gate. The anti-Sybil floor's complete positive path.
    #[tokio::test]
    async fn mock_full_quorum_mints_canonical_513() {
        use ciris_verify_core::accord_custody_attestation::test_support::MockYubicoCa;
        use ciris_verify_core::transport_binding::produce_signed_identity_occurrence;

        let backend = crate::store::memory::MemoryBackend::new();
        let ca = MockYubicoCa::new();
        let envelope = serde_json::json!({ "key_id": "canon-mockmint-513" });

        let mut roster = Vec::new();
        let mut scrubs: Vec<super::super::types::ScrubSig> = Vec::new();
        for (i, kid) in ["mm0", "mm1", "mm2"].iter().enumerate() {
            let m = ca
                .attest_member([0x80 + i as u8; 32], kid, "2026-07-26T00:00:00Z")
                .await;
            let mut rec = record(kid, identity_type::NODE, kid);
            rec.pubkey_ed25519_base64 = m.member.ed25519_public_key_base64.clone();
            rec.pubkey_ml_dsa_65_base64 = m.member.mldsa65_public_key_base64.clone();
            rec.attestation_evidence = Some(serde_json::to_value(&m.attestation).unwrap());
            backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .unwrap();
            roster.push((*kid).to_string());
            // Sign the canonical's registration envelope as this member —
            // bound-hybrid over JCS(envelope), the exact scrub contract.
            let (_, sig) = produce_signed_identity_occurrence(&m.holder, envelope.clone())
                .await
                .unwrap();
            scrubs.push(super::super::types::ScrubSig {
                scrub_key_id: (*kid).to_string(),
                scrub_signature_classical: sig.ed25519_signature_base64,
                scrub_signature_pqc: sig.mldsa65_signature_base64,
            });
        }

        let mut rec = record("canon-mockmint-513", "canonical,node", "mm0");
        rec.registration_envelope = envelope.clone();
        rec.original_content_hash = {
            use sha2::{Digest, Sha256};
            let bytes = ceg_produce_canonicalize(&envelope).unwrap();
            hex::encode(Sha256::digest(&bytes))
        };
        rec.scrub_key_id = scrubs[0].scrub_key_id.clone();
        rec.scrub_signature_classical = scrubs[0].scrub_signature_classical.clone();
        rec.scrub_signature_pqc = scrubs[0].scrub_signature_pqc.clone();
        rec.additional_scrubs = scrubs[1..].to_vec();

        super::check_canonical_role_admission_over_roster_with_custody_root(
            &backend,
            &rec,
            &roster,
            ca.root_der(),
        )
        .await
        .expect("3 mock-FIPS members with real hybrid scrubs must mint through the strict floor");
    }

    /// v21.3.0 (CIRISPersist#513) — the grandfather matcher covers exactly
    /// the embedded genesis LINEAGE (by key_id: today's quorum bar, real
    /// accord signatures still required); any NEW canonical key_id — the
    /// trust-root MINTING the floor exists for — is not lineage.
    #[test]
    fn baked_genesis_canonical_matcher_is_lineage_scoped_513() {
        let baked = &crate::federation::genesis::canonical_genesis_bundle().serve_nodes[0];
        assert!(super::is_baked_genesis_canonical(&baked.record));
        // The lineage id with a different envelope is STILL lineage — it
        // faces the same real-accord-quorum bar as today (no floor, no
        // regression; the pre-ceremony → re-blessed history is exactly
        // this shape).
        let mut lineage_variant = baked.record.clone();
        lineage_variant.registration_envelope =
            serde_json::json!({ "key_id": lineage_variant.key_id });
        assert!(super::is_baked_genesis_canonical(&lineage_variant));
        // A NEW key_id is a NEW trust root → the full #513 floor.
        let mut new_root = baked.record.clone();
        new_root.key_id = "ciris-canonical-2-newroot".into();
        assert!(!super::is_baked_genesis_canonical(&new_root));
    }

    /// Build a `federation_keys` `KeyRecord` for `key_id` carrying
    /// `identity_type`, scrubbed by `scrub_key_id` (set `== key_id` for a
    /// self-signed row). The scrub-signature is NOT verified at the
    /// `put_public_key` chokepoint (that is `verify_key_registration`'s job on
    /// `register_federation_key`), so a syntactically-valid record suffices to
    /// exercise the canonical admission gate. Deterministic per-key pubkey.
    fn record(key_id: &str, identity_type: &str, scrub_key_id: &str) -> KeyRecord {
        let mut seed = [0x11u8; 32];
        for (i, b) in key_id.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        let ed = SigningKey::from_bytes(&seed);
        let envelope = serde_json::json!({ "key_id": key_id });
        let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize");
        let now = chrono::Utc::now();
        KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: B64.encode(ed.verifying_key().to_bytes()),
            pubkey_ml_dsa_65_base64: None,
            algorithm: algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(Sha256::digest(&canonical)),
            scrub_signature_classical: "AA".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    async fn put(dir: &dyn FederationDirectory, rec: KeyRecord) -> Result<(), super::Error> {
        dir.put_public_key(SignedKeyRecord { record: rec }).await
    }

    /// Register `id` as a `node` `federation_keys` row under its key_id with the
    /// Identity's PINNED hybrid pubkeys (so a founder roster resolves to keys
    /// the test can sign with). `node` (not `accord_holder`) skips the HW gate.
    async fn register_founder(dir: &dyn FederationDirectory, id: &Identity) {
        let m = id.member();
        let mut rec = record(&id.key_id, identity_type::NODE, &id.key_id);
        rec.pubkey_ed25519_base64 = m.ed25519_public_key_base64;
        rec.pubkey_ml_dsa_65_base64 = m.mldsa65_public_key_base64;
        put(dir, rec).await.expect("register founder");
    }

    /// The full 2-of-3 multi-scrub admission decision table, exercised on the
    /// CORE gate [`super::check_canonical_role_admission_over_roster`] with a
    /// DISTINCT test roster (`cah{0,1,2}-{tag}`) — so it runs on every backend
    /// (incl. the SHARED postgres) WITHOUT touching the real A1/B1/C1 anchor.
    /// The real accord ceremony private keys are not in-tree, so a genuine
    /// co-scrub can only be produced against a test roster; the production
    /// `check_canonical_role_admission` wrapper is identical modulo the roster
    /// key_ids and is exercised end-to-end on the isolated backends
    /// ([`run_endtoend`]).
    async fn run_gate_matrix(dir: &dyn FederationDirectory, tag: &str) {
        let founders = [
            Identity::new(&format!("cah0-{tag}")),
            Identity::new(&format!("cah1-{tag}")),
            Identity::new(&format!("cah2-{tag}")),
        ];
        for f in &founders {
            register_founder(dir, f).await;
        }
        let roster: Vec<String> = founders.iter().map(|f| f.key_id.clone()).collect();
        let env = |kid: &str| serde_json::json!({ "key_id": kid });
        let gate = |rec: KeyRecord, roster: Vec<String>| async move {
            super::check_canonical_role_admission_over_roster_legacy(dir, &rec, &roster).await
        };

        // (1) ADMITTED: 2 DISTINCT valid founder scrubs (strict majority of 3).
        gate(
            signed_canonical_record(
                "g1",
                "canonical,node",
                env("g1"),
                &[&founders[0], &founders[1]],
            ),
            roster.clone(),
        )
        .await
        .expect("(1) 2-of-3 distinct valid scrubs must confer canonical");

        // (2) REFUSED: exactly ONE scrub (1-of-N is retired). Error cites m-of-n.
        let err = gate(
            signed_canonical_record("g2", "canonical,node", env("g2"), &[&founders[0]]),
            roster.clone(),
        )
        .await
        .expect_err("(2) a single scrub must be REFUSED");
        assert_eq!(err.kind(), "canonical_role_not_accord_conferred");
        assert!(
            format!("{err}").contains("2-of-3") || format!("{err}").contains("m-of-n"),
            "(2) error must cite the m-of-n shortfall, got: {err}"
        );

        // (3) FORGERY (load-bearing): scrub #1 is a REAL cah0 scrub; the 2nd
        //     claims member_id = cah1 with a GARBAGE signature. The quorum
        //     primitive cryptographically verifies each sig, so the forged one
        //     does NOT count → 1 < 2 → REFUSED. Counting claimed scrub_key_ids
        //     without verifying would WRONGLY admit this.
        let mut forged =
            signed_canonical_record("g3", "canonical,node", env("g3"), &[&founders[0]]);
        forged.additional_scrubs = vec![ScrubSig {
            scrub_key_id: founders[1].key_id.clone(),
            scrub_signature_classical: B64.encode([0u8; 64]),
            scrub_signature_pqc: Some(B64.encode([0u8; 64])),
        }];
        let err = gate(forged, roster.clone())
            .await
            .expect_err("(3) a forged 2nd scrub must be REFUSED");
        assert_eq!(err.kind(), "canonical_role_not_accord_conferred");

        // (4) NOT DISTINCT: two scrubs by the SAME founder (cah0 twice) → the
        //     primitive dedups by member → 1 distinct < 2 → REFUSED.
        let err = gate(
            signed_canonical_record(
                "g4",
                "canonical,node",
                env("g4"),
                &[&founders[0], &founders[0]],
            ),
            roster.clone(),
        )
        .await
        .expect_err("(4) two scrubs by the same holder must be REFUSED");
        assert_eq!(err.kind(), "canonical_role_not_accord_conferred");

        // (5) SELF-SCRUB + 1 founder: scrub #1 is a self-scrub (member_id =
        //     key_id, NOT a founder → not counted); only the 1 founder scrub
        //     counts → REFUSED. A node cannot bootstrap itself into the set.
        let me_self = Identity::new("g5");
        let err = gate(
            signed_canonical_record("g5", "canonical,node", env("g5"), &[&me_self, &founders[0]]),
            roster.clone(),
        )
        .await
        .expect_err("(5) self-scrub + 1 founder must be REFUSED");
        assert_eq!(err.kind(), "canonical_role_not_accord_conferred");

        // (6) A non-canonical record fast-paths to Ok regardless of scrubs.
        gate(
            record("g6", identity_type::NODE, &founders[0].key_id),
            roster.clone(),
        )
        .await
        .expect("(6) a non-canonical record is not gated");

        // (7) WITHDRAWN-still-refused (#377 composition): record a withdrawal
        //     tombstone for a key, then EVEN a valid 2-of-3 scrub set is refused
        //     — the revocation-wins consult runs before the quorum verify.
        dir.record_canonical_withdrawal("g7", None, "digest-g7")
            .await
            .expect("record withdrawal");
        let err = gate(
            signed_canonical_record(
                "g7",
                "canonical,node",
                env("g7"),
                &[&founders[0], &founders[1]],
            ),
            roster.clone(),
        )
        .await
        .expect_err("(7) a withdrawn key stays refused even with a valid 2-of-3");
        assert_eq!(err.kind(), "canonical_role_withdrawn");

        // (8) ROSTER-DERIVED POLICY (the threshold tracks the LIVE roster, is
        //     NOT a frozen `2`): over a 4-FOUNDER roster the strict majority is
        //     3, so the SAME 2 valid scrubs that pass at n=3 are REFUSED at n=4.
        let f3 = Identity::new(&format!("cah3-{tag}"));
        register_founder(dir, &f3).await;
        let roster4: Vec<String> = founders
            .iter()
            .map(|f| f.key_id.clone())
            .chain(std::iter::once(f3.key_id.clone()))
            .collect();
        let err = gate(
            signed_canonical_record(
                "g8",
                "canonical,node",
                env("g8"),
                &[&founders[0], &founders[1]],
            ),
            roster4.clone(),
        )
        .await
        .expect_err("(8) 2 scrubs over a 4-founder roster (needs 3) must be REFUSED");
        assert_eq!(err.kind(), "canonical_role_not_accord_conferred");
        // 3 distinct valid scrubs over the 4-founder roster DO confer.
        gate(
            signed_canonical_record(
                "g8b",
                "canonical,node",
                env("g8b"),
                &[&founders[0], &founders[1], &f3],
            ),
            roster4,
        )
        .await
        .expect("(8) 3-of-4 over the live roster confers canonical");

        // (9) STORAGE round-trip of `additional_scrubs` on the write path
        //     (writer + decoder) — a NON-canonical node record carrying a 2nd
        //     scrub fast-paths the gate, stores, and reads back with the scrub
        //     set intact. Covers the V096 column + serde on every backend.
        let store = format!("gstore-{tag}");
        dir.put_public_key(SignedKeyRecord {
            record: signed_canonical_record(
                &store,
                identity_type::NODE,
                env(&store),
                &[&founders[0], &founders[1]],
            ),
        })
        .await
        .expect("(9) non-canonical 2-scrub node stores");
        let read = dir.lookup_public_key(&store).await.unwrap().unwrap();
        assert_eq!(read.additional_scrubs.len(), 1, "(9) 2nd scrub round-trips");
        assert_eq!(read.distinct_scrub_count(), 2);
        assert_eq!(
            read.additional_scrubs[0].scrub_key_id, founders[1].key_id,
            "(9) the additional scrub's key_id survives store→read"
        );
    }

    /// End-to-end through the PRODUCTION gate + storage on an ISOLATED backend:
    /// seed the accord family (A1/B1/C1) under their real key_ids with TEST
    /// hybrid keys (safe only on a per-test-isolated backend — NEVER the shared
    /// pg), admit a 2-of-3 canonical via `put_public_key`, and confirm
    /// `is_canonical` / `list_canonical_servers` / round-trip
    /// `additional_scrubs` / accord-attested bootstrap-hint surfacing.
    async fn run_endtoend(dir: &dyn FederationDirectory, tag: &str) {
        let accord: Vec<Identity> = accord_holder_roster_key_ids()
            .iter()
            .map(|k| Identity::new(k))
            .collect();
        for a in &accord {
            register_founder(dir, a).await;
        }
        // v21.3.0 (#513) — the GENESIS-LINEAGE id keeps today's bar (legacy
        // 2-of-3 accord quorum, no floor): the full positive prod-path
        // round-trip rides it. A NEW key_id (a fresh trust root) meets the
        // FIPS floor — asserted below.
        let good = "ciris-canonical-1-d7bdeu223k".to_string();
        let good_env = serde_json::json!({
            "key_id": good,
            "transport_hints": [{ "kind": "ip", "destination": "108.61.242.236:4242" }],
        });
        dir.put_public_key(SignedKeyRecord {
            record: signed_canonical_record(
                &good,
                "canonical,node",
                good_env,
                &[&accord[0], &accord[1]],
            ),
        })
        .await
        .expect("2-of-3 lineage canonical admits through the production gate");
        assert!(is_canonical(dir, &good).await.expect("is_canonical"));

        // #513 e2e: a NEW canonical key_id minted by the same (software,
        // unattested) accord roster is REFUSED by the hardware anti-Sybil
        // floor at the SAME production chokepoint.
        let fresh = format!("canon-new-root-{tag}");
        let floor_err = dir
            .put_public_key(SignedKeyRecord {
                record: signed_canonical_record(
                    &fresh,
                    "canonical,node",
                    serde_json::json!({ "key_id": fresh }),
                    &[&accord[0], &accord[1]],
                ),
            })
            .await
            .expect_err("a NEW trust root without FIPS custody must be refused (floor)");
        let floor_msg = format!("{floor_err}");
        assert!(
            floor_msg.contains("floor 3") || floor_msg.contains("custody"),
            "refusal must cite the #513 floor: {floor_msg}"
        );
        assert!(dir.lookup_public_key(&fresh).await.unwrap().is_none());

        // Round-trip: the 2nd scrub survives store→read.
        let read = dir.lookup_public_key(&good).await.unwrap().unwrap();
        assert_eq!(
            read.additional_scrubs.len(),
            1,
            "2nd scrub preserved on read-back"
        );
        assert_eq!(read.distinct_scrub_count(), 2);

        // #381 bootstrap-hint surfacing from the signed envelope.
        let hints = read.transport_hints();
        assert!(
            hints
                .iter()
                .any(|h| h.kind == "ip" && h.destination == "108.61.242.236:4242"),
            "the accord-attested transport hint must surface"
        );

        // A single-scrub re-offer of a DIFFERENT key is refused end-to-end.
        let one = format!("canon-one-{tag}");
        let err = dir
            .put_public_key(SignedKeyRecord {
                record: signed_canonical_record(
                    &one,
                    "canonical,node",
                    serde_json::json!({"key_id": one}),
                    &[&accord[0]],
                ),
            })
            .await
            .expect_err("a single-scrub canonical must be REFUSED end-to-end");
        assert_eq!(err.kind(), "canonical_role_not_accord_conferred");
        assert!(dir.lookup_public_key(&one).await.unwrap().is_none());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn canonical_gate_sqlite() {
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        run_gate_matrix(&backend, "sq").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn canonical_gate_postgres() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping canonical_gate_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        // Isolated throwaway db → zero shared-anchor pollution (the matrix seeds
        // no A1/B1/C1 here, but the isolated db also keeps its stray gate rows
        // out of the shared suite entirely).
        super::run_in_isolated_pg_db(&dsn, |backend| async move {
            run_gate_matrix(&backend, "pg").await;
        })
        .await;
    }

    #[tokio::test]
    async fn canonical_gate_memory() {
        use crate::store::memory::MemoryBackend;
        let backend = MemoryBackend::new();
        run_gate_matrix(&backend, "mem").await;
    }

    /// v13.7.0 (CIRISPersist#405) — the CANONICAL SUPERSEDE policy end-to-end
    /// over a DISTINCT test roster, with REAL co-scrubs: proves the monotonic +
    /// m-of-n composition of
    /// [`verify_canonical_supersede_over_roster`](super::super::register::verify_canonical_supersede_over_roster).
    /// A newer, validly 2-of-3-scrubbed canonical supersedes; an OLDER validly
    /// scrubbed record does NOT (monotonicity beats a fresh quorum — the
    /// downgrade guard); a newer 1-scrub does NOT (m-of-n shortfall); a newer
    /// NON-canonical re-scrub does NOT (canonical-scope). All records share the
    /// fixed test pubkey, so the same-pubkey precondition holds.
    #[tokio::test]
    async fn canonical_supersede_over_roster_matrix() {
        use super::super::register::verify_canonical_supersede_over_roster;
        use crate::store::memory::MemoryBackend;
        let dir = MemoryBackend::new();
        let founders = [
            Identity::new("scah0"),
            Identity::new("scah1"),
            Identity::new("scah2"),
        ];
        for f in &founders {
            register_founder(&dir, f).await;
        }
        let roster: Vec<String> = founders.iter().map(|f| f.key_id.clone()).collect();
        let env_at = |kid: &str, vf: &str| serde_json::json!({ "key_id": kid, "valid_from": vf });
        let (t_minus, t0, t1) = (
            "2026-07-09T00:00:00+00:00",
            "2026-07-10T00:00:00+00:00",
            "2026-07-11T00:00:00+00:00",
        );
        let two = [&founders[0], &founders[1]];
        let existing =
            signed_canonical_record("canon-1", "canonical,node", env_at("canon-1", t0), &two);

        let check = |record| {
            let dir = &dir;
            let existing = &existing;
            let roster = roster.clone();
            async move {
                verify_canonical_supersede_over_roster(dir, existing, &record, &roster)
                    .await
                    .expect("no infra error")
            }
        };

        // (a) newer + 2 distinct valid scrubs → SUPERSEDE.
        assert!(
            check(signed_canonical_record(
                "canon-1",
                "canonical,node",
                env_at("canon-1", t1),
                &two
            ))
            .await,
            "newer 2-of-3 canonical must supersede"
        );
        // (b) OLDER envelope valid_from, still validly 2-scrubbed → REFUSED
        //     (monotonicity beats a fresh quorum — the downgrade guard).
        assert!(
            !check(signed_canonical_record(
                "canon-1",
                "canonical,node",
                env_at("canon-1", t_minus),
                &two
            ))
            .await,
            "an older validly-scrubbed record must NOT supersede"
        );
        // (c) newer but only ONE scrub → REFUSED (m-of-n shortfall).
        assert!(
            !check(signed_canonical_record(
                "canon-1",
                "canonical,node",
                env_at("canon-1", t1),
                &[&founders[0]]
            ))
            .await,
            "a newer 1-scrub record must NOT supersede"
        );
        // (d) newer + 2 scrubs but NON-canonical → REFUSED (canonical-scope).
        assert!(
            !check(signed_canonical_record(
                "canon-1",
                "node",
                env_at("canon-1", t1),
                &two
            ))
            .await,
            "a non-canonical re-scrub must NOT reach supersede"
        );
    }

    /// End-to-end via the PRODUCTION `check_canonical_role_admission` on the
    /// ISOLATED sqlite-in-memory backend (safe to seed test A1/B1/C1).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn canonical_endtoend_sqlite() {
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        run_endtoend(&backend, "e2e-sq").await;

        // adopt_scrub_upgrade path is ALSO gated: a self-signed node cannot be
        // upgraded to canonical by an under-quorum (single/non-roster) scrub.
        let up = "mono-adopt-sq";
        backend
            .put_public_key(SignedKeyRecord {
                record: record(up, identity_type::NODE, up),
            })
            .await
            .expect("seed self-signed node for adopt");
        let mut adopted = record(up, "canonical,node", "notanchor-sq");
        adopted.pubkey_ed25519_base64 = record(up, identity_type::NODE, up).pubkey_ed25519_base64;
        let err = backend
            .adopt_scrub_upgrade(SignedKeyRecord { record: adopted })
            .await
            .expect_err("adopt adding canonical without quorum must be REFUSED");
        assert_eq!(err.kind(), "canonical_role_not_accord_conferred");
        assert!(!is_canonical(&backend, up).await.unwrap());

        let canon = backend.list_canonical_servers().await.expect("list");
        assert_eq!(canon.len(), 1, "exactly the one admitted canonical row");
        assert!(identity_type::set_contains(
            &canon[0].identity_type,
            identity_type::CANONICAL
        ));
    }

    /// End-to-end via the PRODUCTION gate on the ISOLATED memory backend.
    #[tokio::test]
    async fn canonical_endtoend_memory() {
        use crate::store::memory::MemoryBackend;
        let backend = MemoryBackend::new();
        run_endtoend(&backend, "e2e-mem").await;
    }

    // ─────────────────────────────────────────────────────────────────
    // CIRISPersist#422 — the `infra:attest` (build-manifest trust root)
    // adopt-gate. Same accord m-of-n co-scrub as `canonical`, in the
    // `roles` vector. Shares the `verify_accord_family_coscrub` core, so
    // this matrix is the `canonical` matrix in the `roles`-field mirror.
    // ─────────────────────────────────────────────────────────────────

    /// Stamp `infra:attest` into a co-scrubbed record's `roles`. The scrubs sign
    /// the `registration_envelope` (independent of `roles`), so a genuine 2-of-3
    /// co-scrub is valid exactly as for `canonical` — the role token differs, the
    /// ceremony does not.
    fn with_infra_role(mut rec: KeyRecord) -> KeyRecord {
        rec.capability_roles = vec![super::super::types::roles::INFRA_ATTEST.to_owned()];
        rec
    }

    /// The `infra:attest` core-gate decision table over a DISTINCT test roster
    /// (runs on every backend without touching the real A1/B1/C1 anchor).
    async fn run_infra_gate_matrix(dir: &dyn FederationDirectory, tag: &str) {
        let founders = [
            Identity::new(&format!("iah0-{tag}")),
            Identity::new(&format!("iah1-{tag}")),
            Identity::new(&format!("iah2-{tag}")),
        ];
        for f in &founders {
            register_founder(dir, f).await;
        }
        let roster: Vec<String> = founders.iter().map(|f| f.key_id.clone()).collect();
        let env = |kid: &str| serde_json::json!({ "key_id": kid });
        let gate = |rec: KeyRecord, roster: Vec<String>| async move {
            super::check_infra_attest_role_admission_over_roster(dir, &rec, &roster).await
        };

        // (1) ADMITTED: 2 distinct valid founder scrubs + `infra:attest`.
        gate(
            with_infra_role(signed_canonical_record(
                "i1",
                identity_type::NODE,
                env("i1"),
                &[&founders[0], &founders[1]],
            )),
            roster.clone(),
        )
        .await
        .expect("(1) 2-of-3 distinct scrubs must confer infra:attest");

        // (2) REFUSED: exactly ONE scrub; error cites the m-of-n shortfall.
        let err = gate(
            with_infra_role(signed_canonical_record(
                "i2",
                identity_type::NODE,
                env("i2"),
                &[&founders[0]],
            )),
            roster.clone(),
        )
        .await
        .expect_err("(2) a single scrub must be REFUSED");
        assert_eq!(err.kind(), "infra_attest_role_not_accord_conferred");
        assert!(
            format!("{err}").contains("2-of-3") || format!("{err}").contains("m-of-n"),
            "(2) error must cite the m-of-n shortfall, got: {err}"
        );

        // (3) FORGERY: real cah0 scrub + a garbage-sig 2nd claiming cah1 → the
        //     quorum primitive verifies each sig, so the forged one doesn't count.
        let mut forged = with_infra_role(signed_canonical_record(
            "i3",
            identity_type::NODE,
            env("i3"),
            &[&founders[0]],
        ));
        forged.additional_scrubs = vec![ScrubSig {
            scrub_key_id: founders[1].key_id.clone(),
            scrub_signature_classical: B64.encode([0u8; 64]),
            scrub_signature_pqc: Some(B64.encode([0u8; 64])),
        }];
        let err = gate(forged, roster.clone())
            .await
            .expect_err("(3) a forged 2nd scrub must be REFUSED");
        assert_eq!(err.kind(), "infra_attest_role_not_accord_conferred");

        // (4) NOT DISTINCT: two scrubs by the SAME founder → dedup → 1 < 2.
        let err = gate(
            with_infra_role(signed_canonical_record(
                "i4",
                identity_type::NODE,
                env("i4"),
                &[&founders[0], &founders[0]],
            )),
            roster.clone(),
        )
        .await
        .expect_err("(4) two scrubs by the same holder must be REFUSED");
        assert_eq!(err.kind(), "infra_attest_role_not_accord_conferred");

        // (5) SELF-SCRUB + 1 founder: the self-scrub is not a founder → not
        //     counted; a pipeline cannot bootstrap ITSELF into the blessed set.
        let me_self = Identity::new(&format!("i5-{tag}"));
        let err = gate(
            with_infra_role(signed_canonical_record(
                "i5",
                identity_type::NODE,
                env("i5"),
                &[&me_self, &founders[0]],
            )),
            roster.clone(),
        )
        .await
        .expect_err("(5) self-scrub + 1 founder must be REFUSED");
        assert_eq!(err.kind(), "infra_attest_role_not_accord_conferred");

        // (6) A record WITHOUT `infra:attest` fast-paths to Ok regardless of
        //     scrubs (plain authorization scopes in `roles` are untouched).
        let mut plain = record("i6", identity_type::NODE, &founders[0].key_id);
        plain.capability_roles = vec!["cirislens_pipeline_writer".to_owned()];
        gate(plain, roster.clone())
            .await
            .expect("(6) a non-infra:attest record is not gated");

        // (7) ROSTER-DERIVED policy: over a 4-founder roster the majority is 3,
        //     so the SAME 2 scrubs that pass at n=3 are REFUSED at n=4.
        let f3 = Identity::new(&format!("iah3-{tag}"));
        register_founder(dir, &f3).await;
        let roster4: Vec<String> = founders
            .iter()
            .map(|f| f.key_id.clone())
            .chain(std::iter::once(f3.key_id.clone()))
            .collect();
        let err = gate(
            with_infra_role(signed_canonical_record(
                "i7",
                identity_type::NODE,
                env("i7"),
                &[&founders[0], &founders[1]],
            )),
            roster4.clone(),
        )
        .await
        .expect_err("(7) 2 scrubs over a 4-founder roster (needs 3) must be REFUSED");
        assert_eq!(err.kind(), "infra_attest_role_not_accord_conferred");
        gate(
            with_infra_role(signed_canonical_record(
                "i7b",
                identity_type::NODE,
                env("i7b"),
                &[&founders[0], &founders[1], &f3],
            )),
            roster4,
        )
        .await
        .expect("(7) 3-of-4 over the live roster confers infra:attest");
    }

    /// End-to-end through the PRODUCTION gate (real A1/B1/C1 roster) + storage +
    /// the `is_infra_attest` resolver + the `adopt_scrub_upgrade` path, on an
    /// ISOLATED backend (safe to seed test A1/B1/C1).
    async fn run_infra_endtoend(dir: &dyn FederationDirectory, tag: &str) {
        let accord: Vec<Identity> = accord_holder_roster_key_ids()
            .iter()
            .map(|k| Identity::new(k))
            .collect();
        for a in &accord {
            register_founder(dir, a).await;
        }

        // 2-of-3 co-scrubbed pipeline key with `infra:attest` → admitted + blessed.
        let good = format!("ci-good-{tag}");
        dir.put_public_key(SignedKeyRecord {
            record: with_infra_role(signed_canonical_record(
                &good,
                identity_type::NODE,
                serde_json::json!({ "key_id": good }),
                &[&accord[0], &accord[1]],
            )),
        })
        .await
        .expect("2-of-3 infra:attest admits through the production gate");
        assert!(
            super::is_infra_attest(dir, &good)
                .await
                .expect("is_infra_attest"),
            "an accord-co-scrubbed pipeline key is blessed"
        );
        assert!(
            !is_canonical(dir, &good).await.unwrap(),
            "infra:attest is NOT canonical (distinct CEG object, same ceremony)"
        );

        // 1-scrub `infra:attest` → REFUSED end-to-end; not stored, not blessed.
        let one = format!("ci-one-{tag}");
        let err = dir
            .put_public_key(SignedKeyRecord {
                record: with_infra_role(signed_canonical_record(
                    &one,
                    identity_type::NODE,
                    serde_json::json!({ "key_id": one }),
                    &[&accord[0]],
                )),
            })
            .await
            .expect_err("a single-scrub infra:attest must be REFUSED end-to-end");
        assert_eq!(err.kind(), "infra_attest_role_not_accord_conferred");
        assert!(dir.lookup_public_key(&one).await.unwrap().is_none());
        assert!(!super::is_infra_attest(dir, &one).await.unwrap());

        // A self-signed record self-asserting `infra:attest` → REFUSED (no
        // self-conferral, exactly like a self-asserted `canonical`).
        let selfp = format!("ci-self-{tag}");
        let err = dir
            .put_public_key(SignedKeyRecord {
                record: with_infra_role(record(&selfp, identity_type::NODE, &selfp)),
            })
            .await
            .expect_err("a self-asserted infra:attest must be REFUSED");
        assert_eq!(err.kind(), "infra_attest_role_not_accord_conferred");
        assert!(!super::is_infra_attest(dir, &selfp).await.unwrap());
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn infra_attest_gate_sqlite() {
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        run_infra_gate_matrix(&backend, "sq").await;
        run_infra_endtoend(&backend, "e2e-sq").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn infra_attest_gate_postgres() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping infra_attest_gate_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        super::run_in_isolated_pg_db(&dsn, |backend| async move {
            run_infra_gate_matrix(&backend, "pg").await;
            run_infra_endtoend(&backend, "e2e-pg").await;
        })
        .await;
    }

    #[tokio::test]
    async fn infra_attest_gate_memory() {
        use crate::store::memory::MemoryBackend;
        let backend = MemoryBackend::new();
        run_infra_gate_matrix(&backend, "mem").await;
        run_infra_endtoend(&backend, "e2e-mem").await;
    }

    // ─────────────────────────────────────────────────────────────────
    // CIRISPersist#441 — the `roles=[...]` set path runs the SAME
    // accord-conferral admission gates as the scalar `identity_type`
    // path (CC 4.5.8.1: cohabitation must not become a self-claim
    // backdoor). Before #441 `roles=["agent","canonical"]` was ADMITTED
    // where `identity_type="canonical"` was refused.
    // ─────────────────────────────────────────────────────────────────

    /// End-to-end via `put_public_key` (production wrappers, isolated
    /// backend): every constitutional role self-claim is refused with the
    /// SAME error kind regardless of which role surface carries it.
    async fn run_set_path_parity(dir: &dyn FederationDirectory, tag: &str) {
        // (a) `canonical` in the roles VECTOR — the #441 probe case.
        let kid = format!("sp-canon-roles-{tag}");
        let mut rec = record(&kid, identity_type::NODE, &kid);
        rec.capability_roles = vec!["agent".to_owned(), identity_type::CANONICAL.to_owned()];
        let err = put(dir, rec)
            .await
            .expect_err("(a) roles=[..,canonical] self-claim must be REFUSED");
        assert_eq!(
            err.kind(),
            "canonical_role_not_accord_conferred",
            "(a) set path must fire the SAME kind as the scalar path"
        );
        assert!(dir.lookup_public_key(&kid).await.unwrap().is_none());

        // (b) `infra:attest` smuggled through the identity_type SET — the
        // mirror-direction hole closed by the same claims_role predicate.
        let kid = format!("sp-infra-set-{tag}");
        let rec = record(&kid, "infra:attest,node", &kid);
        let err = put(dir, rec)
            .await
            .expect_err("(b) identity_type set infra:attest self-claim must be REFUSED");
        assert_eq!(err.kind(), "infra_attest_role_not_accord_conferred");

        // (c) A plain self-assertable scope in `roles` stays admissible —
        // the gate touches ONLY the accord-conferred tokens.
        let kid = format!("sp-plain-{tag}");
        let mut rec = record(&kid, identity_type::NODE, &kid);
        rec.capability_roles = vec!["cirislens_pipeline_writer".to_owned()];
        put(dir, rec)
            .await
            .expect("(c) plain authorization scopes must remain self-assertable");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn set_path_parity_sqlite() {
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        run_set_path_parity(&backend, "sq").await;

        // (d) `accord_holder` — hardware-attestation gate parity across all
        // three claim shapes (scalar was already gated; set + vector are the
        // #441 closures). Backend-specific: the HW policy lives on the SQL
        // backends.
        for (kid, ident, roles) in [
            ("sp-ah-set-sq", "agent,accord_holder".to_owned(), Vec::new()),
            (
                "sp-ah-roles-sq",
                identity_type::NODE.to_owned(),
                vec![identity_type::ACCORD_HOLDER.to_owned()],
            ),
        ] {
            let mut rec = record(kid, &ident, kid);
            rec.capability_roles = roles;
            let err = backend
                .put_public_key(SignedKeyRecord { record: rec })
                .await
                .expect_err("(d) accord_holder claim without evidence must be REFUSED");
            assert_eq!(
                err.kind(),
                "federation_accord_holder_requires_attestation_evidence",
                "(d) {kid}: every claim shape hits the HW gate"
            );
        }
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn set_path_parity_postgres() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping set_path_parity_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        super::run_in_isolated_pg_db(&dsn, |backend| async move {
            run_set_path_parity(&backend, "pg").await;
        })
        .await;
    }

    #[tokio::test]
    async fn set_path_parity_memory() {
        use crate::store::memory::MemoryBackend;
        let backend = MemoryBackend::new();
        run_set_path_parity(&backend, "mem").await;
    }

    // ─────────────────────────────────────────────────────────────────
    // CIRISPersist#469 — the seeder bridge: announced/advisory LAN-peer
    // bookmarks. Backend-parity harness over the #469 contract:
    // record→list roundtrip, idempotent liveness refresh + enrichment,
    // Conflict on pubkey change, and promotion supersede (an ADMITTED
    // key_id's bookmark disappears from the read — invariant 4).
    // ─────────────────────────────────────────────────────────────────
    async fn run_announced_peer_parity(dir: &dyn FederationDirectory, tag: &str) {
        // Whole-second timestamps: pg TIMESTAMPTZ truncates to MICROseconds,
        // so nanosecond-carrying `Utc::now()` round-trips unequal on pg only.
        let t0 = chrono::DateTime::from_timestamp(1_752_600_000, 0).expect("fixture ts");
        let t1 = t0 + chrono::Duration::seconds(60);

        // (a) record → list roundtrip, fields intact.
        let kid = format!("ap-roundtrip-{tag}");
        dir.record_announced_peer(&kid, "ed-pub-a", None, Some("node"), t0)
            .await
            .expect("(a) first announce records");
        let peers = dir.list_announced_peers().await.expect("(a) list");
        let p = peers
            .iter()
            .find(|p| p.key_id == kid)
            .expect("(a) bookmark visible");
        assert_eq!(p.pubkey_ed25519_base64, "ed-pub-a");
        assert_eq!(p.claimed_identity_type.as_deref(), Some("node"));
        assert_eq!(p.announce_count, 1);
        assert_eq!(p.first_seen_at, p.last_seen_at);

        // (b) idempotent refresh: same key+pubkey → one row, count bumps,
        // last_seen advances, PQC half ENRICHES (never blanks).
        dir.record_announced_peer(&kid, "ed-pub-a", Some("pqc-pub-a"), None, t1)
            .await
            .expect("(b) repeat announce refreshes");
        let peers = dir.list_announced_peers().await.expect("(b) list");
        let matches: Vec<_> = peers.iter().filter(|p| p.key_id == kid).collect();
        assert_eq!(matches.len(), 1, "(b) no duplicate bookmark");
        let p = matches[0];
        assert_eq!(p.announce_count, 2);
        assert_eq!(p.last_seen_at, t1, "(b) liveness refreshed");
        assert_eq!(p.first_seen_at, t0, "(b) first_seen preserved");
        assert_eq!(
            p.pubkey_ml_dsa_65_base64.as_deref(),
            Some("pqc-pub-a"),
            "(b) PQC half enriched"
        );
        assert_eq!(
            p.claimed_identity_type.as_deref(),
            Some("node"),
            "(b) claimed type not blanked by a None refresh"
        );

        // (c) pubkey change for the same key_id → Conflict (identity
        // conflict, not a refresh), and the stored row is untouched.
        let err = dir
            .record_announced_peer(&kid, "ed-pub-DIFFERENT", None, None, t1)
            .await
            .expect_err("(c) pubkey change must be refused");
        assert_eq!(err.kind(), "federation_conflict", "(c) typed Conflict");
        let peers = dir.list_announced_peers().await.expect("(c) list");
        let p = peers.iter().find(|p| p.key_id == kid).expect("(c) intact");
        assert_eq!(p.pubkey_ed25519_base64, "ed-pub-a", "(c) row untouched");

        // (d) promotion supersede (invariant 4): once the same key_id is
        // ADMITTED for real (put_public_key through the actual gate), the
        // bookmark vanishes from the read — the rooted row wins, with no
        // hook in the admission gate.
        let kid_promoted = format!("ap-promoted-{tag}");
        dir.record_announced_peer(&kid_promoted, "ed-pub-b", None, None, t0)
            .await
            .expect("(d) bookmark records");
        let rec = record(&kid_promoted, identity_type::NODE, &kid_promoted);
        put(dir, rec).await.expect("(d) real admission succeeds");
        let peers = dir.list_announced_peers().await.expect("(d) list");
        assert!(
            !peers.iter().any(|p| p.key_id == kid_promoted),
            "(d) admitted key_id's bookmark must be superseded by the rooted row"
        );

        // (e) empty args → typed InvalidArgument, fail-honest.
        let err = dir
            .record_announced_peer("", "ed", None, None, t0)
            .await
            .expect_err("(e) empty key_id refused");
        assert_eq!(err.kind(), "federation_invalid_argument");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn announced_peer_parity_sqlite() {
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        run_announced_peer_parity(&backend, "sq").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn announced_peer_parity_postgres() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping announced_peer_parity_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        super::run_in_isolated_pg_db(&dsn, |backend| async move {
            run_announced_peer_parity(&backend, "pg").await;
        })
        .await;
    }

    #[tokio::test]
    async fn announced_peer_parity_memory() {
        use crate::store::memory::MemoryBackend;
        let backend = MemoryBackend::new();
        run_announced_peer_parity(&backend, "mem").await;
    }

    // ─────────────────────────────────────────────────────────────────
    // CIRISPersist#440 — the CC 3.4.9 co-steward roles (`registry` /
    // `verify`). Same accord m-of-n co-scrub ceremony as `canonical` /
    // `infra:attest`, via the role-generic gate; withdrawal rides the
    // V104 generic tombstone; `has_accord_conferred_role` is the consumer read.
    // ─────────────────────────────────────────────────────────────────

    /// The co-steward decision table, end-to-end through the PRODUCTION
    /// wrappers (real A1/B1/C1 roster key_ids seeded with test-signable
    /// identities, the [`run_infra_endtoend`] pattern) — so it must run only
    /// on ISOLATED backends.
    async fn run_costeward_gate_matrix(dir: &dyn FederationDirectory, tag: &str) {
        let accord: Vec<Identity> = accord_holder_roster_key_ids()
            .iter()
            .map(|k| Identity::new(k))
            .collect();
        for a in &accord {
            register_founder(dir, a).await;
        }
        let env = |kid: &str| serde_json::json!({ "key_id": kid });

        // (1) ADMITTED: 2-of-3 co-scrub carrying `registry` in the
        // identity_type set (the CC 3.4.9 shape — a key may be {node,registry});
        // stored through the production put_public_key gate, then resolvable
        // from the key record alone via the effective read.
        let reg_kid = format!("cs1-{tag}");
        let reg = signed_canonical_record(
            &reg_kid,
            "node,registry",
            env(&reg_kid),
            &[&accord[0], &accord[1]],
        );
        dir.put_public_key(SignedKeyRecord { record: reg })
            .await
            .expect("(1) a 2-of-3 co-scrubbed registry co-steward admits");
        assert!(
            super::has_accord_conferred_role(dir, &reg_kid, identity_type::REGISTRY)
                .await
                .unwrap(),
            "(1) the stored co-scrubbed row reads effective"
        );
        assert!(
            !super::has_accord_conferred_role(dir, &reg_kid, identity_type::VERIFY)
                .await
                .unwrap(),
            "(1) registry is NOT the verify co-steward"
        );

        // (2) REFUSED end-to-end: self-signed `verify` claim, on EITHER
        // surface; nothing stored.
        let kid = format!("cs2-{tag}");
        let err = put(dir, record(&kid, "node,verify", &kid))
            .await
            .expect_err("(2) a self-signed verify claim must be REFUSED");
        assert_eq!(err.kind(), "role_not_accord_conferred");
        assert!(dir.lookup_public_key(&kid).await.unwrap().is_none());
        let kid = format!("cs2b-{tag}");
        let mut vec_claim = record(&kid, identity_type::NODE, &kid);
        vec_claim.capability_roles = vec![identity_type::VERIFY.to_owned()];
        let err = put(dir, vec_claim)
            .await
            .expect_err("(2) a roles-vector verify claim must be REFUSED");
        assert_eq!(err.kind(), "role_not_accord_conferred");

        // (3) REFUSED: single scrub (sub-quorum).
        let kid = format!("cs3-{tag}");
        let err = put(
            dir,
            signed_canonical_record(&kid, "node,registry", env(&kid), &[&accord[0]]),
        )
        .await
        .expect_err("(3) a single-scrub registry claim must be REFUSED");
        assert_eq!(err.kind(), "role_not_accord_conferred");

        // (4) Revocation-wins: after a V104 tombstone for (registry, cs1),
        // the SAME valid co-scrubbed record is refused re-admission and the
        // effective read flips false.
        dir.record_role_withdrawal(identity_type::REGISTRY, &reg_kid, None, "digest-cs1")
            .await
            .expect("(4) record the registry withdrawal tombstone");
        let re_offer = signed_canonical_record(
            &reg_kid,
            "node,registry",
            env(&reg_kid),
            &[&accord[0], &accord[1]],
        );
        let err = put(dir, re_offer)
            .await
            .expect_err("(4) a withdrawn co-steward cannot be re-conferred");
        assert_eq!(err.kind(), "role_withdrawn");
        assert!(
            !super::has_accord_conferred_role(dir, &reg_kid, identity_type::REGISTRY)
                .await
                .unwrap(),
            "(4) a withdrawn co-steward is not effective"
        );

        // (5) The effective read is self-authenticating: a row with NO claim
        // reads false by claim-absence (and the ≤16.1.1 legacy-row shapes —
        // self-claimed / sub-quorum — are exactly the rows (2)/(3) prove the
        // co-scrub re-verification refuses).
        assert!(
            !super::has_accord_conferred_role(dir, &accord[0].key_id, identity_type::REGISTRY)
                .await
                .unwrap()
        );

        // (6) The generic withdraw op refuses the dedicated-op roles.
        for role in [identity_type::CANONICAL, "infra:attest"] {
            let err = super::withdraw_accord_role(dir, role, "whoever", "digest")
                .await
                .expect_err("(6) canonical/infra:attest must use their dedicated ops");
            assert!(
                format!("{err}").contains("dedicated withdraw op"),
                "(6) got: {err}"
            );
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn costeward_gate_sqlite() {
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        run_costeward_gate_matrix(&backend, "sq").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn costeward_gate_postgres() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping costeward_gate_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        super::run_in_isolated_pg_db(&dsn, |backend| async move {
            run_costeward_gate_matrix(&backend, "pg").await;
        })
        .await;
    }

    #[tokio::test]
    async fn costeward_gate_memory() {
        use crate::store::memory::MemoryBackend;
        let backend = MemoryBackend::new();
        run_costeward_gate_matrix(&backend, "mem").await;
    }
}

/// v13.1.0 (CIRISPersist#377, CC 3.4.7.1 / FSD Trust Root) — the canonical-role
/// WITHDRAW / SUPERSEDE decision table, run identically against SQLite and (when
/// `CIRIS_PERSIST_TEST_PG_URL` is set) Postgres, plus a memory-backend gate
/// consult. Authority is re-tallied from persist's OWN stored,
/// cryptographically-verified `accord_participation` rows (never a
/// caller-supplied `AccordDecision.authorized` bool) at the 2-of-3 destructive
/// threshold. Exercises: tombstone recording; **forged-authority rejection** (a
/// stored proposal with < 2 valid YES participations cannot withdraw); the
/// revocation-wins gate consult; the #375 anti-entropy composition
/// (`apply_replicated_key_record` refuses a re-add of a withdrawn canonical);
/// atomic supersede; and payload-binding fail-closed. No pg/sqlite/memory
/// asymmetry.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod canonical_withdrawal_tests {
    use super::super::accord_quorum::test_fixtures::signed_participation;
    use super::super::operational::test_support::{signed_canonical_record, Identity};
    use super::super::types::{algorithm, identity_type};
    use super::super::{FederationDirectory, KeyRecord, SignedKeyRecord};
    use super::{
        accord_holder_roster_key_ids, canonical_withdrawal_payload_sha256, is_canonical_effective,
        supersede_canonical_over_roster, withdraw_canonical_role_over_roster,
        OP_SUPERSEDE_CANONICAL, OP_WITHDRAW_CANONICAL,
    };
    use crate::verify::canonical::ceg_produce_canonicalize;
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use ciris_verify_core::accord_genesis::HUMANITY_ACCORD_FAMILY_KEY_ID;
    use ciris_verify_core::accord_live_quorum::{AccordAction, AccordProposal, Vote};
    use ciris_verify_core::threshold::ThresholdMember;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};

    /// A syntactically-valid `federation_keys` `KeyRecord` for `key_id` (the
    /// scrub-signature is not verified at the `put_public_key` chokepoint, so a
    /// well-formed record suffices to exercise the gate). Deterministic pubkey.
    fn record(key_id: &str, identity_type: &str, scrub_key_id: &str) -> KeyRecord {
        let mut seed = [0x22u8; 32];
        for (i, b) in key_id.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        let ed = SigningKey::from_bytes(&seed);
        let envelope = serde_json::json!({ "key_id": key_id });
        let canonical = ceg_produce_canonicalize(&envelope).expect("canonicalize");
        let now = chrono::Utc::now();
        KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: B64.encode(ed.verifying_key().to_bytes()),
            pubkey_ml_dsa_65_base64: None,
            algorithm: algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(Sha256::digest(&canonical)),
            scrub_signature_classical: "AA".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    async fn put(dir: &dyn FederationDirectory, rec: KeyRecord) -> Result<(), super::Error> {
        dir.put_public_key(SignedKeyRecord { record: rec }).await
    }

    /// Register a signable roster holder as a `node`-role `federation_keys` row
    /// whose PINNED pubkeys equal the `Identity`'s (so the authority tally
    /// resolves the roster to the SAME keys the participations were signed with).
    /// `node` (not `accord_holder`) avoids the hardware-attestation gate.
    async fn register_holder(dir: &dyn FederationDirectory, id: &Identity) {
        let m = id.member();
        let mut rec = record(&id.key_id, identity_type::NODE, &id.key_id);
        rec.pubkey_ed25519_base64 = m.ed25519_public_key_base64;
        rec.pubkey_ml_dsa_65_base64 = m.mldsa65_public_key_base64;
        put(dir, rec).await.expect("register roster holder");
    }

    /// Seed a STORED accord proposal (family = HUMANITY_ACCORD) committing to the
    /// canonical `op`/`target`/`successor` payload, plus one signed YES
    /// participation per holder index in `yes_voters`. Returns the proposal
    /// digest. This is persist's OWN verified evidence — the authority re-tally
    /// reads it back.
    #[allow(clippy::too_many_arguments)]
    async fn seed_quorum(
        dir: &dyn FederationDirectory,
        holders: &[Identity],
        roster: &[ThresholdMember],
        op: &str,
        target: &str,
        successor: Option<&str>,
        yes_voters: &[usize],
        nonce: &str,
    ) -> String {
        let payload_sha256 =
            canonical_withdrawal_payload_sha256(op, target, successor).expect("payload sha256");
        let proposal = AccordProposal {
            family_key_id: HUMANITY_ACCORD_FAMILY_KEY_ID.to_owned(),
            action: AccordAction::RosterChange,
            nonce: nonce.to_owned(),
            window_until: "2031-01-01T00:00:00Z".to_owned(),
            prior_family_digest: "prior-family-digest".to_owned(),
            payload_sha256,
        };
        dir.issue_accord_nonce(HUMANITY_ACCORD_FAMILY_KEY_ID, nonce)
            .await
            .expect("issue nonce");
        dir.put_accord_proposal(proposal.clone(), None)
            .await
            .expect("put proposal");
        for &i in yes_voters {
            let part = signed_participation(&holders[i], &proposal, Vote::Yes);
            dir.put_accord_participation(part, roster)
                .await
                .expect("put participation");
        }
        proposal.digest()
    }

    /// The full withdraw/supersede decision table over an anchor-seeded directory
    /// (genesis A1/B1/C1 present for the anchor-scrub ADD gate) with a signable
    /// 3-holder quorum roster (H0/H1/H2) for the destructive-op authority.
    async fn run_withdrawal_matrix(dir: &dyn FederationDirectory, tag: &str) {
        // Seed the accord family (A1/B1/C1) under their REAL key_ids with TEST
        // hybrid keypairs so the v13.2.0 2-of-3 ADD gate can be satisfied
        // end-to-end (the real ceremony keys are not in-tree). `env` builds the
        // per-key envelope; a canonical `good`/`old`/`new` is admitted with a
        // valid A1+B1 co-scrub over it.
        let accord: Vec<Identity> = accord_holder_roster_key_ids()
            .iter()
            .map(|k| Identity::new(k))
            .collect();
        assert_eq!(accord[0].key_id, "A1");
        for a in &accord {
            register_holder(dir, a).await;
        }
        let env = |kid: &str| serde_json::json!({ "key_id": kid });

        // Signable DESTRUCTIVE-quorum roster (3 holders) — distinct from the
        // ADD roster; resolved from directory pinned keys.
        let holders = [
            Identity::new(&format!("H0-{tag}")),
            Identity::new(&format!("H1-{tag}")),
            Identity::new(&format!("H2-{tag}")),
        ];
        for h in &holders {
            register_holder(dir, h).await;
        }
        let roster: Vec<ThresholdMember> = holders.iter().map(|h| h.member()).collect();
        let roster_key_ids: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();

        // ── Admit a 2-of-3 anchor-scrubbed canonical, then withdraw it. ─────
        // v21.3.0 (#513): the stored canonical rides the GENESIS-LINEAGE id
        // (legacy quorum bar — the withdrawal machinery under test is
        // orthogonal to the new-root FIPS floor, which has its own e2e
        // witnesses in `canonical_gate_tests`). The lineage id is the ONE
        // storable canonical for software fixtures, so the supersede legs
        // that need a live predecessor run FIRST, against this same row,
        // before it is withdrawn below.
        let good = "ciris-canonical-1-d7bdeu223k".to_string();
        put(
            dir,
            signed_canonical_record(
                &good,
                "canonical,node",
                env(&good),
                &[&accord[0], &accord[1]],
            ),
        )
        .await
        .expect("2-of-3 anchor-scrubbed canonical must be ADMITTED");
        assert!(is_canonical_effective(dir, &good).await.unwrap());

        // ── (H, moved pre-withdrawal) SUPERSEDE against the live lineage. ──
        let new = format!("cw-new-{tag}");
        // Fail-closed: a proposal committing to good→WRONG cannot supersede
        // good→new (payload mismatch); neither mutation happens.
        let d_wrong = seed_quorum(
            dir,
            &holders,
            &roster,
            OP_SUPERSEDE_CANONICAL,
            &good,
            Some(&format!("wrong-{tag}")),
            &[0, 1],
            &format!("n-wrong-{tag}"),
        )
        .await;
        let err = supersede_canonical_over_roster(
            dir,
            &good,
            SignedKeyRecord {
                record: signed_canonical_record(
                    &new,
                    "canonical,node",
                    env(&new),
                    &[&accord[0], &accord[1]],
                ),
            },
            &d_wrong,
            &roster_key_ids,
        )
        .await
        .expect_err("supersede with wrong-successor payload must be REFUSED");
        assert_eq!(err.kind(), "canonical_withdrawal_authority_invalid");
        assert!(dir.lookup_public_key(&new).await.unwrap().is_none());
        assert!(dir
            .lookup_canonical_withdrawal(&good)
            .await
            .unwrap()
            .is_none());

        // v21.3.0 (#513) — the ANTI-LAUNDERING witness: a fully-authorized
        // supersede (correct payload, real 2-of-3 authority) whose SUCCESSOR
        // is a NEW, FIPS-unattested root is REFUSED at the successor's own
        // admission (the floor runs inside `put_public_key`, which the op
        // calls BEFORE recording the tombstone) — a rotation cannot launder
        // an unattested trust root in, and the failed op leaves NO partial
        // state: predecessor still effective, no tombstone, successor absent.
        let d_sup = seed_quorum(
            dir,
            &holders,
            &roster,
            OP_SUPERSEDE_CANONICAL,
            &good,
            Some(&new),
            &[0, 1],
            &format!("n-sup-{tag}"),
        )
        .await;
        let floor_err = supersede_canonical_over_roster(
            dir,
            &good,
            SignedKeyRecord {
                record: signed_canonical_record(
                    &new,
                    "canonical,node",
                    env(&new),
                    &[&accord[0], &accord[1]],
                ),
            },
            &d_sup,
            &roster_key_ids,
        )
        .await
        .expect_err("an unattested successor root must be refused by the #513 floor");
        let floor_msg = format!("{floor_err}");
        assert!(
            floor_msg.contains("floor 3") || floor_msg.contains("custody"),
            "supersede refusal must cite the floor: {floor_msg}"
        );
        assert!(is_canonical_effective(dir, &good).await.unwrap());
        assert!(dir.lookup_public_key(&new).await.unwrap().is_none());
        assert!(dir
            .lookup_canonical_withdrawal(&good)
            .await
            .unwrap()
            .is_none());

        // (A) FORGED-AUTHORITY REJECTION: a stored proposal committing to
        //     (withdraw, good) but with ZERO participations → the re-tally
        //     yields 0 YES < 2 → REFUSED, role NOT withdrawn. A caller cannot
        //     fabricate a quorum: only real signed participations count.
        let d_zero = seed_quorum(
            dir,
            &holders,
            &roster,
            OP_WITHDRAW_CANONICAL,
            &good,
            None,
            &[],
            &format!("n-zero-{tag}"),
        )
        .await;
        let err = withdraw_canonical_role_over_roster(dir, &good, &d_zero, &roster_key_ids)
            .await
            .expect_err("zero-participation authority must be REFUSED");
        assert_eq!(err.kind(), "canonical_withdrawal_authority_invalid");
        assert!(dir
            .lookup_canonical_withdrawal(&good)
            .await
            .unwrap()
            .is_none());
        assert!(is_canonical_effective(dir, &good).await.unwrap());

        // (B) FEWER-THAN-2: a proposal with exactly ONE valid YES participation
        //     → 1 < 2 destructive threshold → REFUSED.
        let d_one = seed_quorum(
            dir,
            &holders,
            &roster,
            OP_WITHDRAW_CANONICAL,
            &good,
            None,
            &[0],
            &format!("n-one-{tag}"),
        )
        .await;
        let err = withdraw_canonical_role_over_roster(dir, &good, &d_one, &roster_key_ids)
            .await
            .expect_err("single-vote authority must be REFUSED");
        assert_eq!(err.kind(), "canonical_withdrawal_authority_invalid");
        assert!(dir
            .lookup_canonical_withdrawal(&good)
            .await
            .unwrap()
            .is_none());

        // (C) NO STORED PROPOSAL: a digest persist never stored → REFUSED (the
        //     quorum evidence does not exist).
        let err = withdraw_canonical_role_over_roster(
            dir,
            &good,
            &format!("deadbeef-no-such-proposal-{tag}"),
            &roster_key_ids,
        )
        .await
        .expect_err("nonexistent proposal must be REFUSED");
        assert_eq!(err.kind(), "canonical_withdrawal_authority_invalid");

        // (D) PAYLOAD REPLAY: a genuinely-quorumed proposal for a DIFFERENT
        //     target cannot be replayed to withdraw `good`.
        let decoy = format!("cw-decoy-{tag}");
        let d_decoy = seed_quorum(
            dir,
            &holders,
            &roster,
            OP_WITHDRAW_CANONICAL,
            &decoy,
            None,
            &[0, 1],
            &format!("n-decoy-{tag}"),
        )
        .await;
        let err = withdraw_canonical_role_over_roster(dir, &good, &d_decoy, &roster_key_ids)
            .await
            .expect_err("payload-mismatch (wrong target) must be REFUSED");
        assert_eq!(err.kind(), "canonical_withdrawal_authority_invalid");
        assert!(dir
            .lookup_canonical_withdrawal(&good)
            .await
            .unwrap()
            .is_none());

        // (E) POSITIVE: a proposal committing to (withdraw, good) with 2 distinct
        //     valid YES votes → WITHDRAWS: tombstone recorded, is_canonical false.
        let d_good = seed_quorum(
            dir,
            &holders,
            &roster,
            OP_WITHDRAW_CANONICAL,
            &good,
            None,
            &[0, 1],
            &format!("n-good-{tag}"),
        )
        .await;
        withdraw_canonical_role_over_roster(dir, &good, &d_good, &roster_key_ids)
            .await
            .expect("2-of-3 quorum must withdraw");
        let w = dir
            .lookup_canonical_withdrawal(&good)
            .await
            .unwrap()
            .expect("tombstone recorded");
        assert_eq!(w.key_id, good);
        assert_eq!(w.superseded_by, None);
        assert_eq!(w.authority_decision_digest, d_good);
        assert!(!is_canonical_effective(dir, &good).await.unwrap());
        // Idempotent re-withdraw (same quorum) is a no-op.
        withdraw_canonical_role_over_roster(dir, &good, &d_good, &roster_key_ids)
            .await
            .expect("idempotent re-withdraw");
        assert!(dir
            .list_canonical_withdrawals()
            .await
            .unwrap()
            .iter()
            .any(|x| x.key_id == good));

        // (F) Revocation-wins gate consult: re-offering the anchor-scrubbed
        //     canonical record for `good` via put_public_key is REFUSED.
        // The withdrawal consult runs BEFORE the quorum verify, so a re-offer of
        // the WITHDRAWN key is refused regardless of scrub validity — a plain
        // (even under-quorum) canonical record suffices to prove the consult wins.
        let err = put(dir, record(&good, "canonical,node", &accord[0].key_id))
            .await
            .expect_err("re-confer of a withdrawn canonical must be REFUSED");
        assert_eq!(err.kind(), "canonical_role_withdrawn");

        // (G) #375 anti-entropy composition: withdraw a not-yet-admitted key,
        //     then a peer replicates the anchor-scrubbed canonical record →
        //     NOT re-conferred.
        let repl = format!("cw-repl-{tag}");
        let d_repl = seed_quorum(
            dir,
            &holders,
            &roster,
            OP_WITHDRAW_CANONICAL,
            &repl,
            None,
            &[0, 1],
            &format!("n-repl-{tag}"),
        )
        .await;
        withdraw_canonical_role_over_roster(dir, &repl, &d_repl, &roster_key_ids)
            .await
            .expect("withdraw the (future) key");
        let outcome = dir
            .apply_replicated_key_record(SignedKeyRecord {
                record: record(&repl, "canonical,node", &accord[0].key_id),
            })
            .await;
        match outcome {
            Err(e) => assert_eq!(e.kind(), "canonical_role_withdrawn"),
            // The assertion here is "not admitted", whichever way the store
            // says so — this corpus has no row for `repl`, so the withdrawal
            // normally surfaces as the typed `Err`. Left deliberately
            // reason-agnostic (v24.2.0, CIRISPersist#565): pinning a
            // [`KeyRefusalReason`] on a branch this test does not actually
            // drive would assert a fact it has not established.
            Ok(o) => assert!(
                matches!(
                    o,
                    super::super::register::ReplicatedKeyOutcome::Refused { .. }
                ),
                "a withdrawn canonical must not be re-conferred over anti-entropy, got {o:?}"
            ),
        }
        assert!(!is_canonical_effective(dir, &repl).await.unwrap());
        assert!(dir.lookup_public_key(&repl).await.unwrap().is_none());

        // ── (H2) Successor-exemption + withdrawn-wins VERDICTS (legacy
        // gate — the exemption logic is identical in the strict path; the
        // completing old→new supersede itself now requires FIPS-attested
        // successors, witnessed above as the floor refusal). ──
        let ex_old = format!("cw-ex-{tag}");
        let ex_succ = format!("cw-exsucc-{tag}");
        dir.record_canonical_withdrawal(&ex_old, Some(&ex_succ), "digest-h2")
            .await
            .expect("record exemption tombstone");
        // The named SUCCESSOR is exempt from withdrawal-wins and admits
        // under the (legacy) quorum.
        super::check_canonical_role_admission_over_roster_legacy(
            dir,
            &signed_canonical_record(
                &ex_succ,
                "canonical,node",
                env(&ex_succ),
                &[&accord[0], &accord[1]],
            ),
            &accord.iter().map(|a| a.key_id.clone()).collect::<Vec<_>>(),
        )
        .await
        .expect("the tombstone-named successor is exempt from withdrawal-wins");
        // The WITHDRAWN key itself stays refused even with valid scrubs.
        let werr = super::check_canonical_role_admission_over_roster_legacy(
            dir,
            &signed_canonical_record(
                &ex_old,
                "canonical,node",
                env(&ex_old),
                &[&accord[0], &accord[1]],
            ),
            &accord.iter().map(|a| a.key_id.clone()).collect::<Vec<_>>(),
        )
        .await
        .expect_err("a withdrawn key must stay refused (withdrawal-wins)");
        assert_eq!(werr.kind(), "canonical_role_withdrawn");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn canonical_withdrawal_sqlite() {
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;

        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // The matrix seeds the accord family (A1/B1/C1) with test hybrid keys
        // itself (2-of-3 ADD gate); no real-genesis seed here.
        run_withdrawal_matrix(&backend, "sq").await;
    }

    /// v13.2.0 (CIRISPersist#383) — run the withdraw/supersede matrix against an
    /// **ISOLATED, freshly-created postgres database**. The matrix seeds the
    /// accord family (A1/B1/C1) with TEST hybrid keys to satisfy the 2-of-3 ADD
    /// gate for its `good`/`old`/`new` setup rows; on the SHARED test db that
    /// would squat the real anchor and break concurrent Engine-constructing pg
    /// tests, so we spin up a throwaway db (`cw_isol_<uuid>`), migrate it, run,
    /// and drop it — full pg coverage with zero shared-anchor pollution.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn canonical_withdrawal_postgres() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping canonical_withdrawal_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        super::run_in_isolated_pg_db(&dsn, |backend| async move {
            run_withdrawal_matrix(&backend, "pg").await;
        })
        .await;
    }

    /// Memory-backend symmetry: the withdrawal store (record/lookup/list,
    /// idempotency) + the revocation-wins gate consult
    /// ([`check_canonical_role_admission_over_roster`](super::check_canonical_role_admission_over_roster))
    /// behave identically to the SQL backends. Seeds the accord family (A1/B1/C1)
    /// with test hybrid keys so the 2-of-3 ADD gate can be satisfied, then proves
    /// the withdrawal consult runs BEFORE the quorum verify (a withdrawn key is
    /// refused EVEN with a valid 2-of-3 scrub set), while a superseded-to-self
    /// key is exempt.
    #[tokio::test]
    async fn canonical_withdrawal_memory() {
        use crate::store::memory::MemoryBackend;

        let backend = MemoryBackend::new();
        let dir: &dyn FederationDirectory = &backend;

        // Record a tombstone for a key + idempotency + conflict on differing.
        dir.record_canonical_withdrawal("K", None, "digest-1")
            .await
            .expect("record");
        dir.record_canonical_withdrawal("K", None, "digest-1")
            .await
            .expect("idempotent");
        let err = dir
            .record_canonical_withdrawal("K", Some("K2"), "digest-1")
            .await
            .expect_err("conflicting re-record");
        assert!(matches!(err, super::Error::Conflict(_)));

        let w = dir.lookup_canonical_withdrawal("K").await.unwrap().unwrap();
        assert_eq!(w.key_id, "K");
        assert_eq!(w.superseded_by, None);
        assert_eq!(dir.list_canonical_withdrawals().await.unwrap().len(), 1);
        assert!(dir
            .lookup_canonical_withdrawal("nope")
            .await
            .unwrap()
            .is_none());

        // Seed the signable accord family (A1/B1/C1 with test hybrid keys) so a
        // GENUINE 2-of-3 co-scrub can be produced + verified by the gate.
        let accord: Vec<Identity> = accord_holder_roster_key_ids()
            .iter()
            .map(|k| Identity::new(k))
            .collect();
        for a in &accord {
            register_holder(dir, a).await;
        }
        let roster = accord_holder_roster_key_ids();
        let env = |kid: &str| serde_json::json!({ "key_id": kid });

        // The gate consult rejects re-conferring canonical on the withdrawn key
        // K EVEN with a valid 2-of-3 scrub set — the consult runs FIRST
        // (revocation-wins), so the withdrawal (not a quorum shortfall) is the
        // rejection cause.
        let rec =
            signed_canonical_record("K", "canonical,node", env("K"), &[&accord[0], &accord[1]]);
        let err = super::check_canonical_role_admission_over_roster_legacy(dir, &rec, &roster)
            .await
            .expect_err("withdrawn key cannot be re-conferred canonical");
        assert_eq!(err.kind(), "canonical_role_withdrawn");

        // A NON-withdrawn key with a valid 2-of-3 scrub set passes the gate.
        let ok =
            signed_canonical_record("J", "canonical,node", env("J"), &[&accord[0], &accord[1]]);
        super::check_canonical_role_admission_over_roster_legacy(dir, &ok, &roster)
            .await
            .expect("non-withdrawn 2-of-3 canonical passes the gate");

        // Supersede exemption: a tombstone whose superseded_by names THIS key
        // does NOT block re-confer (key-id-preserving rotation) — the valid
        // 2-of-3 then confers.
        dir.record_canonical_withdrawal("S", Some("S"), "digest-2")
            .await
            .expect("self-superseded tombstone");
        let rec_s =
            signed_canonical_record("S", "canonical,node", env("S"), &[&accord[0], &accord[1]]);
        super::check_canonical_role_admission_over_roster_legacy(dir, &rec_s, &roster)
            .await
            .expect("a superseded-to-self key is exempt from the withdrawal block");
    }

    // ─────────────────────────────────────────────────────────────────
    // CIRISPersist#424 — the `infra:attest` WITHDRAW decision table: the
    // #377 canonical machinery re-used for the roles-vector role (same
    // op-parameterized authority core, the generic V104 tombstone). Lives
    // in this module to share record/register_holder/seed_quorum verbatim.
    // ─────────────────────────────────────────────────────────────────

    /// Stamp `infra:attest` into a co-scrubbed record's `roles` (the #422
    /// conferral shape; the co-scrub signs the envelope, not the role field).
    fn with_infra(mut rec: KeyRecord) -> KeyRecord {
        rec.capability_roles = vec![super::super::types::roles::INFRA_ATTEST.to_owned()];
        rec
    }

    async fn run_infra_withdrawal_matrix(dir: &dyn FederationDirectory, tag: &str) {
        use super::{
            is_infra_attest, is_infra_attest_effective, withdraw_infra_attest_role_over_roster,
            OP_WITHDRAW_INFRA_ATTEST,
        };
        // Accord family (test keys) for the ADD co-scrub + signable H roster
        // for the destructive quorum — same fixture shape as canonical.
        let accord: Vec<Identity> = accord_holder_roster_key_ids()
            .iter()
            .map(|k| Identity::new(k))
            .collect();
        for a in &accord {
            register_holder(dir, a).await;
        }
        let holders = [
            Identity::new(&format!("IH0-{tag}")),
            Identity::new(&format!("IH1-{tag}")),
            Identity::new(&format!("IH2-{tag}")),
        ];
        for h in &holders {
            register_holder(dir, h).await;
        }
        let roster: Vec<ThresholdMember> = holders.iter().map(|h| h.member()).collect();
        let roster_key_ids: Vec<String> = holders.iter().map(|h| h.key_id.clone()).collect();
        let env = |kid: &str| serde_json::json!({ "key_id": kid });

        // Admit a 2-of-3 co-scrubbed pipeline key carrying `infra:attest`.
        let ci = format!("ci-key-{tag}");
        put(
            dir,
            with_infra(signed_canonical_record(
                &ci,
                identity_type::NODE,
                env(&ci),
                &[&accord[0], &accord[1]],
            )),
        )
        .await
        .expect("2-of-3 co-scrubbed infra:attest pipeline must be ADMITTED");
        assert!(is_infra_attest_effective(dir, &ci).await.unwrap());

        // (A) FORGED AUTHORITY: a stored proposal with ZERO participations →
        //     re-tally 0 YES < majority → REFUSED; still effective.
        let d_zero = seed_quorum(
            dir,
            &holders,
            &roster,
            OP_WITHDRAW_INFRA_ATTEST,
            &ci,
            None,
            &[],
            &format!("iw-zero-{tag}"),
        )
        .await;
        withdraw_infra_attest_role_over_roster(dir, &ci, &d_zero, &roster_key_ids)
            .await
            .expect_err("(A) zero-participation authority must be REFUSED");
        assert!(is_infra_attest_effective(dir, &ci).await.unwrap());

        // (B) GENUINE strict-majority quorum → withdrawn. The stored row still
        //     carries the role (tombstones never mutate rows); the EFFECTIVE
        //     read flips false; a replicated re-offer of the co-scrubbed
        //     record is refused by the gate consult (revocation-wins).
        let d_yes = seed_quorum(
            dir,
            &holders,
            &roster,
            OP_WITHDRAW_INFRA_ATTEST,
            &ci,
            None,
            &[0, 1],
            &format!("iw-yes-{tag}"),
        )
        .await;
        withdraw_infra_attest_role_over_roster(dir, &ci, &d_yes, &roster_key_ids)
            .await
            .expect("(B) a genuine strict-majority withdraw must succeed");
        assert!(
            is_infra_attest(dir, &ci).await.unwrap(),
            "(B) row untouched"
        );
        assert!(
            !is_infra_attest_effective(dir, &ci).await.unwrap(),
            "(B) effective read flips false"
        );
        let re_offer = with_infra(signed_canonical_record(
            &ci,
            identity_type::NODE,
            env(&ci),
            &[&accord[0], &accord[1]],
        ));
        let err = super::check_infra_attest_role_admission_over_roster(
            dir,
            &re_offer,
            &accord_holder_roster_key_ids(),
        )
        .await
        .expect_err("(B) a withdrawn key cannot be re-conferred, even validly co-scrubbed");
        assert_eq!(err.kind(), "infra_attest_role_withdrawn");

        // (C) Idempotent re-withdraw (same digest) is a no-op.
        withdraw_infra_attest_role_over_roster(dir, &ci, &d_yes, &roster_key_ids)
            .await
            .expect("(C) idempotent re-withdraw");

        // (D) CROSS-OP replay: the infra-withdraw digest CANNOT authorize a
        //     CANONICAL withdraw of the same key — the payload op-token binding
        //     refuses (same ceremony, different CEG object, non-fungible).
        let err = super::withdraw_canonical_role_over_roster(dir, &ci, &d_yes, &roster_key_ids)
            .await
            .expect_err("(D) an infra-withdraw authority must not withdraw canonical");
        assert_eq!(err.kind(), "canonical_withdrawal_authority_invalid");

        // (E) Supersede-to-self exemption (key-id-preserving rotate-in): a
        //     tombstone whose superseded_by names THIS key does not block the
        //     gate; a valid co-scrub then re-confers.
        let rot = format!("ci-rot-{tag}");
        put(
            dir,
            record(&rot, identity_type::NODE, &rot), // plain row first (no role)
        )
        .await
        .expect("seed rotation key row");
        dir.record_role_withdrawal(
            super::super::types::roles::INFRA_ATTEST,
            &rot,
            Some(&rot),
            "digest-rot",
        )
        .await
        .expect("self-superseded tombstone");
        let rot_offer = with_infra(signed_canonical_record(
            &rot,
            identity_type::NODE,
            env(&rot),
            &[&accord[0], &accord[1]],
        ));
        super::check_infra_attest_role_admission_over_roster(
            dir,
            &rot_offer,
            &accord_holder_roster_key_ids(),
        )
        .await
        .expect("(E) a superseded-to-self key is exempt from the withdrawal block");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn infra_attest_withdrawal_sqlite() {
        use crate::store::backend::Backend as _;
        use crate::store::sqlite::SqliteBackend;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        run_infra_withdrawal_matrix(&backend, "sq").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn infra_attest_withdrawal_postgres() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping infra_attest_withdrawal_postgres: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        super::run_in_isolated_pg_db(&dsn, |backend| async move {
            run_infra_withdrawal_matrix(&backend, "pg").await;
        })
        .await;
    }

    #[tokio::test]
    async fn infra_attest_withdrawal_memory() {
        use crate::store::memory::MemoryBackend;
        let backend = MemoryBackend::new();
        run_infra_withdrawal_matrix(&backend, "mem").await;
    }
}

// ─────────────────────────────────────────────────────────────────────
// v17.9.0 (CIRISConstitution#38 interim) — envelope size cap witnesses.
// The check is SINGLE-SOURCED (`check_envelope_size_admission`) and called
// identically at all six write chokepoints, so the boundary is unit-pinned
// here and one backend integration (memory, below in store tests) proves the
// wiring; per-backend duplication would re-test the same fn.
// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod envelope_size_tests {
    use super::{check_envelope_size_admission, MAX_ATTESTATION_ENVELOPE_BYTES};

    /// Build an envelope whose CANONICAL bytes are exactly `n` long:
    /// `{"d":"<pad>"}` canonicalizes to 8 framing bytes + pad.
    fn envelope_of_canonical_len(n: usize) -> serde_json::Value {
        assert!(n > 8);
        serde_json::json!({ "d": "x".repeat(n - 8) })
    }

    #[test]
    fn at_cap_admits_over_cap_refuses_exact_boundary() {
        // Exactly AT the cap — admitted.
        let at = envelope_of_canonical_len(MAX_ATTESTATION_ENVELOPE_BYTES);
        let canonical = crate::verify::canonical::ceg_produce_canonicalize(&at).unwrap();
        assert_eq!(
            canonical.len(),
            MAX_ATTESTATION_ENVELOPE_BYTES,
            "fixture sanity"
        );
        check_envelope_size_admission(&at).expect("exactly-at-cap envelope must admit");

        // One byte OVER — refused with the typed kind.
        let over = envelope_of_canonical_len(MAX_ATTESTATION_ENVELOPE_BYTES + 1);
        let err = check_envelope_size_admission(&over).expect_err("cap+1 envelope must be refused");
        assert_eq!(err.kind(), "federation_envelope_too_large");
        match err {
            crate::federation::Error::EnvelopeTooLarge { bytes, cap } => {
                assert_eq!(bytes, MAX_ATTESTATION_ENVELOPE_BYTES + 1);
                assert_eq!(cap, MAX_ATTESTATION_ENVELOPE_BYTES);
            }
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn cap_is_canonical_bytes_not_pretty_bytes() {
        // The measured thing is the JCS canonical form — whitespace in any
        // non-canonical serialization is irrelevant. A value whose PRETTY
        // form exceeds the cap but whose canonical form fits must admit.
        let v = envelope_of_canonical_len(MAX_ATTESTATION_ENVELOPE_BYTES);
        let pretty = serde_json::to_string_pretty(&v).unwrap();
        assert!(pretty.len() > MAX_ATTESTATION_ENVELOPE_BYTES - 8);
        check_envelope_size_admission(&v).expect("canonical-bytes rule");
    }
}

// ─────────────────────────────────────────────────────────────────────
// v18.1.0 — trace:* Information-Type validator witnesses.
// ─────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod trace_dimension_tests {
    use super::check_trace_dimension_admission;

    fn subjects(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn inline_env() -> serde_json::Value {
        serde_json::json!({
            "dimension": "trace:complete:v1",
            "trace_id": "t-1", "agent_id_hash": "ah-1",
            "trace": {"components": []}
        })
    }

    /// A CC 2.6.3 digest token, the shape both live emitters produce
    /// (`format!("sha256:{}", hex::encode(sha256))` — `ingest.rs` and the
    /// `engine.rs` backfill).
    const DIGEST: &str = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn manifest_env() -> serde_json::Value {
        serde_json::json!({
            "dimension": "trace:complete:v1",
            "trace_id": "t-1", "agent_id_hash": "ah-1",
            "manifest": {"schema": "trace_manifest:v1",
                          "content_hash": DIGEST,
                          "byte_len": 2_000_000, "component_count": 16}
        })
    }

    #[test]
    fn non_trace_dimension_is_a_no_op() {
        check_trace_dimension_admission(
            Some("consent:community_trust:v1"),
            "k",
            &[],
            &serde_json::json!({}),
        )
        .expect("non-trace dimensions bypass");
        check_trace_dimension_admission(None, "k", &[], &serde_json::json!({})).expect("no dim");
    }

    #[test]
    fn valid_inline_and_manifest_forms_admit() {
        check_trace_dimension_admission(
            Some("trace:complete:v1"),
            "prod",
            &subjects(&["prod"]),
            &inline_env(),
        )
        .expect("inline form");
        check_trace_dimension_admission(
            Some("trace:complete:v1"),
            "prod",
            &subjects(&["prod", "other"]),
            &manifest_env(),
        )
        .expect("manifest form");
    }

    #[test]
    fn third_party_emission_refused_self_rule() {
        let err = check_trace_dimension_admission(
            Some("trace:complete:v1"),
            "third-party",
            &subjects(&["prod"]),
            &inline_env(),
        )
        .expect_err("attester not in subjects must refuse");
        assert_eq!(err.kind(), "federation_trace_dimension_invalid");
    }

    #[test]
    fn shape_violations_each_refuse_with_the_typed_kind() {
        let cases: Vec<serde_json::Value> = vec![
            // missing trace_id
            serde_json::json!({"dimension":"trace:x:v1","agent_id_hash":"a","trace":{}}),
            // empty agent_id_hash
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"","trace":{}}),
            // neither form
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"a"}),
            // both forms
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"a",
                               "trace":{}, "manifest":{"schema":"trace_manifest:v1",
                               "content_hash":DIGEST,"byte_len":1,"component_count":1}}),
            // inline not an object
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"a","trace":"str"}),
            // manifest wrong schema
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"a",
                               "manifest":{"schema":"nope","content_hash":DIGEST,"byte_len":1,"component_count":1}}),
            // manifest un-prefixed hash
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"a",
                               "manifest":{"schema":"trace_manifest:v1","content_hash":"abc","byte_len":1,"component_count":1}}),
            // manifest zero byte_len
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"a",
                               "manifest":{"schema":"trace_manifest:v1","content_hash":DIGEST,"byte_len":0,"component_count":1}}),
            // manifest missing component_count
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"a",
                               "manifest":{"schema":"trace_manifest:v1","content_hash":DIGEST,"byte_len":1}}),
        ];
        for (i, env) in cases.iter().enumerate() {
            let err = check_trace_dimension_admission(
                Some("trace:x:v1"),
                "prod",
                &subjects(&["prod"]),
                env,
            )
            .expect_err("shape case must refuse");
            assert_eq!(
                err.kind(),
                "federation_trace_dimension_invalid",
                "case {i} typed kind"
            );
        }
    }

    /// CIRISPersist#579 (CC 3.1.5 → CC 2.6.3) — `content_hash` is a DIGEST,
    /// not a string that starts with `"sha256:"`.
    ///
    /// The old check was `starts_with("sha256:") && len > 7`, so every value
    /// below admitted as a conformant trace manifest: a truncated digest, an
    /// UPPERCASE one (a different byte string — CC 2.6.3 fixes the encoding
    /// precisely so two spellings of one digest cannot both be canonical), a
    /// digest with a stray character, and `"sha256:"` + prose. Admission
    /// validates SHAPE machine-checkably; a shape gate that admits a malformed
    /// value is a gate that cannot fail.
    #[test]
    fn manifest_content_hash_must_be_lowercase_hex_cc_263() {
        let with_hash = |h: &str| {
            serde_json::json!({
                "dimension": "trace:complete:v1",
                "trace_id": "t-1", "agent_id_hash": "ah-1",
                "manifest": {"schema": "trace_manifest:v1", "content_hash": h,
                             "byte_len": 2_000_000, "component_count": 16}
            })
        };
        let hex64 = &DIGEST["sha256:".len()..];
        let bad = [
            "sha256:abc123",                             // truncated
            &format!("sha256:{}", hex64.to_uppercase()), // uppercase hex
            &format!("sha256:{}g", &hex64[..63]),        // non-hex digit
            &format!("sha256:{hex64}0"),                 // 65 nibbles
            &format!("sha256:{}", &hex64[..63]),         // 63 nibbles
            "sha256:not a hash at all, just some prose here that is long enough",
            "sha256:",
        ];
        for h in bad {
            let err = check_trace_dimension_admission(
                Some("trace:complete:v1"),
                "prod",
                &subjects(&["prod"]),
                &with_hash(h),
            )
            .expect_err(&format!("malformed digest {h:?} must refuse"));
            assert_eq!(err.kind(), "federation_trace_dimension_invalid");
        }
        // The live emitters' shape still admits.
        check_trace_dimension_admission(
            Some("trace:complete:v1"),
            "prod",
            &subjects(&["prod"]),
            &with_hash(DIGEST),
        )
        .expect("a real sha256 digest token admits");
    }
}

/// **The CC 3.1.7 R2(b) three-backend witness** (CIRISPersist#590).
///
/// One body, run by the memory / sqlite / postgres suites against
/// `&dyn FederationDirectory`, so the three cannot diverge on whether an
/// unregistered governed family reaches the wire. It goes through the REAL
/// `put_attestation` — not [`check_namespace_family_registered`] directly —
/// because "the gate exists" and "the gate is on the host's write path" are
/// different claims, and this repo has shipped the first while believing the
/// second.
///
/// `suffix` scopes every fixture key so a run against a shared postgres test DB
/// does not collide with a prior one.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod r2_test_support {
    use super::*;
    use crate::federation::tier_ingest::test_support::{hybrid_pubkeys, sign_envelope};
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation, SignedKeyRecord};
    use chrono::Utc;

    async fn register_agent_key(dir: &dyn FederationDirectory, key_id: &str) {
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        let now = Utc::now();
        dir.put_public_key(SignedKeyRecord {
            record: crate::federation::KeyRecord {
                key_id: key_id.to_owned(),
                pubkey_ed25519_base64: ed_pk,
                pubkey_ml_dsa_65_base64: mldsa_pk,
                algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
                identity_type: crate::federation::types::identity_type::AGENT.to_owned(),
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
        .expect("register agent key");
    }

    fn scores_row(id: &str, author: &str, dimension: &str) -> SignedAttestation {
        let now = Utc::now();
        let envelope = serde_json::json!({ "dimension": dimension, "score": 0.5 });
        let (och, ed_sig, pqc_sig) = sign_envelope(author, &envelope);
        SignedAttestation {
            attestation: Attestation {
                attestation_id: id.to_owned(),
                attesting_key_id: author.to_owned(),
                attested_key_id: author.to_owned(),
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: och,
                scrub_signature_classical: ed_sig,
                scrub_signature_pqc: pqc_sig,
                scrub_key_id: author.to_owned(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: crate::federation::types::cohort_scope::SELF.to_owned(),
                tier: attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            },
        }
    }

    /// v30.1.0 (CIRISPersist#610) — **a re-scoped attestation stays SERVABLE.**
    ///
    /// GateSpec:
    ///
    /// - **family** — `testimonial`, frame `upstream_attestation`: the wire index
    ///   is this node's record of what it can serve, and a row missing from it is
    ///   unservable in a way no re-read of the row itself reveals.
    /// - **headwaters** — `set_attestation_cohort_scope` (writes the table) ×
    ///   `lookup_signed_record_by_content_hash` (reads the index).
    /// - **references** — #610, #547 (the same class on five Key-plane mutators),
    ///   #541 (preserve set ≠ verified set).
    /// - **dye test** — this IS the dye test: it fails on the unfixed code.
    /// - **depth** — proves the index resolves the NEW hash. Says nothing about
    ///   the stale entry under the OLD hash, which is left to self-heal via the
    ///   defensive re-hash on read.
    /// - **owner** — persist.
    ///
    /// The defect: this mutator recomputes `persist_row_hash` and used to write
    /// only the table. The offer path reads the table and offers the new hash; the
    /// pack path reads the index and cannot serve it. Downstream that appears as
    /// `wanted=6 packed=5 dropped=1` — a peer asking for a row this node just
    /// advertised, and getting silence.
    /// v30.2.0 (CIRISPersist#607) — build the HONEST conferral path a
    /// reserved-prefix rule now resolves, and return the node key id the caller
    /// must give the backend.
    ///
    /// Three rows, and each is required for a different reason:
    ///
    /// 1. the root **charters itself** — `trust:charter:v1` (declaring yourself is
    ///    a different job from conferring on someone else), carrying BOTH
    ///    `infra:serve` and `infra:attest` (the RC3 AND-minimum, #488) and a
    ///    `pre_rotation_commitment`, without which root-key compromise is
    ///    unrecoverable by construction;
    /// 2. **this node accepts** that root — `trust:accepts:v1`; this is the leg
    ///    that makes the check non-circular, because it is signed by the NODE, not
    ///    by the emitter;
    /// 3. the root **confers** `scope` on the emitter — `trust:confers:v1`.
    ///
    /// Shared rather than copied per backend: a fixture that builds this graph
    /// slightly differently on one backend would prove the gate works there and
    /// silently not test it elsewhere, which is this repo's recurring class.
    pub(crate) async fn confer_scope_from_trusted_root(
        dir: &dyn FederationDirectory,
        node: &str,
        root: &str,
        subject: &str,
        scope: &str,
    ) {
        use crate::federation::trust_root::{
            pre_rotation_commitment, TRUST_ACCEPTS_DIMENSION, TRUST_CHARTER_DIMENSION,
            TRUST_CONFERS_DIMENSION,
        };
        // The FK on attesting_key_id is real: every signer of the three rows must
        // already exist in federation_keys. Seeding them here rather than at each
        // call site keeps the helper self-sufficient — a fixture that has to
        // remember two extra keys is a fixture that gets copied wrong.
        for k in [node, root] {
            // Only register what is missing. A caller may legitimately pass a key
            // that already exists — in the Engine-level age fixtures the node's own
            // signer IS the witness — and re-registering it with helper-derived
            // pubkeys is a content conflict, not a fixture error.
            if dir.lookup_public_key(k).await.ok().flatten().is_none() {
                crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
            }
        }
        // Postgres stores attestation_id as a UUID column, so readable ids are
        // refused at the driver. v5 (name-based) keeps them DETERMINISTIC,
        // which is what makes re-asserting the shared charter / accept row
        // idempotent instead of a fresh duplicate on every call.
        let uid = |name: &str| {
            uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, name.as_bytes()).to_string()
        };
        let now = chrono::Utc::now();
        let rows: [(String, &str, &str, &str, serde_json::Value); 3] = [
            (
                uid(&format!("conf-charter-{root}")),
                root,
                root,
                TRUST_CHARTER_DIMENSION,
                serde_json::json!({
                    "dimension": TRUST_CHARTER_DIMENSION,
                    "scope": ["infra:serve", "infra:attest"],
                    "pre_rotation_commitment":
                        pre_rotation_commitment(&[format!("{root}-successor")]).expect("commitment"),
                }),
            ),
            (
                uid(&format!("conf-accept-{node}-{root}")),
                node,
                root,
                TRUST_ACCEPTS_DIMENSION,
                serde_json::json!({"dimension": TRUST_ACCEPTS_DIMENSION, "scope": ["infra:serve"]}),
            ),
            (
                uid(&format!("conf-grant-{subject}-{scope}")),
                root,
                subject,
                TRUST_CONFERS_DIMENSION,
                serde_json::json!({"dimension": TRUST_CONFERS_DIMENSION, "scope": [scope]}),
            ),
        ];
        for (id, from, to, _dim, envelope) in rows {
            let (och, sc, sp) =
                crate::federation::tier_ingest::test_support::sign_envelope(from, &envelope);
            let att = Attestation {
                attestation_id: id,
                attesting_key_id: from.to_owned(),
                attested_key_id: to.to_owned(),
                attestation_type: crate::federation::types::attestation_type::DELEGATES_TO
                    .to_owned(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: och,
                scrub_signature_classical: sc,
                scrub_signature_pqc: sp,
                scrub_key_id: from.to_owned(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
                tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            };
            match dir
                .put_attestation(crate::federation::SignedAttestation { attestation: att })
                .await
            {
                Ok(()) => {}
                // Re-asserting the shared charter / accept row is idempotence when
                // a test confers on several subjects, not a failure.
                Err(e) if e.to_string().contains("UNIQUE constraint failed") => {}
                Err(e) if e.to_string().contains("duplicate key") => {}
                Err(e) => panic!("conferral row must admit: {e}"),
            }
        }
    }

    /// v30.12.0 (CIRISPersist#634) — every ref
    /// [`wire_refs_for_subject`](crate::federation::wire_index::wire_refs_for_subject)
    /// returns for a subject MUST resolve through
    /// `lookup_signed_record_by_content_hash`.
    ///
    /// That is the whole guarantee edge is buying. Edge previously composed the
    /// per-kind subject reads and hashed the structs itself, which held only
    /// while each backend's `_for` read serialized byte-identically to what its
    /// `_since` read hashed into the index. **That is a per-backend property**,
    /// which is why this runs on all three rather than on memory alone — memory
    /// reserializes from the same in-process struct and would agree with itself
    /// no matter what sqlite and postgres did.
    ///
    /// A ref that does not resolve is the #634 skew, caught here instead of as
    /// a `None` on a peer's fetch.
    pub(crate) async fn exercise_wire_refs_for_subject_resolve(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        use chrono::Timelike as _;

        let subject = format!("wireref-subject-{tag}");
        let author = format!("wireref-author-{tag}");
        crate::federation::tier_ingest::test_support::register_hybrid_key(dir, &subject).await;
        crate::federation::tier_ingest::test_support::register_hybrid_key(dir, &author).await;

        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id, "dimension": "trust:wireref:v1", "score": 1.0, "confidence": 0.9,
        });
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(&author, &envelope);
        // Microsecond truncation for the same reason the rescope witness does
        // it: postgres TIMESTAMPTZ drops nanoseconds, so a nanosecond-bearing
        // fixture re-serializes to a different hash than the one indexed at
        // write — a property of the FIXTURE, not the backend.
        let now = chrono::Utc::now().with_nanosecond(0).expect("truncate");

        let att = crate::federation::types::SignedAttestation {
            attestation: crate::federation::Attestation {
                attestation_id: id.clone(),
                attesting_key_id: author.clone(),
                attested_key_id: subject.clone(),
                attestation_type: "scores".to_owned(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: och,
                scrub_signature_classical: sc,
                scrub_signature_pqc: sp,
                scrub_key_id: author.clone(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
                tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            },
        };
        dir.put_attestation(att)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] seed attestation must admit: {e}"));

        let refs = crate::federation::wire_index::wire_refs_for_subject(dir, &subject)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] wire_refs_for_subject: {e}"));

        // NON-VACUITY FIRST. An empty result resolves every ref it returns, so
        // without this the assertion below passes on a function that does
        // nothing — the exact shape of a check that cannot fail.
        assert!(
            refs.iter().any(|(k, _, _)| *k == "Attestation"),
            "[{tag}] no Attestation ref for the seeded subject; got {refs:?}"
        );
        assert!(
            refs.iter().any(|(k, _, _)| *k == "Key"),
            "[{tag}] no Key ref for the subject's own key record; got {refs:?}"
        );

        for (kind, content_hash, record_key) in &refs {
            let served = dir
                .lookup_signed_record_by_content_hash(kind, content_hash)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] lookup {kind}/{content_hash}: {e}"));
            assert!(
                served.is_some(),
                "[{tag}] ref ({kind}, {content_hash}) does not resolve — the subject read and \
                 the wire index disagree about this row's bytes (record_key {record_key}). \
                 That is the #634 skew, and a peer asking for this exact ref would get None."
            );
        }
    }

    /// v30.13.0 (CIRISPersist#640) — a key whose timestamps carry
    /// SUB-MICROSECOND precision, and a `consent_role` submitted in its STORED
    /// form, must still resolve through the ref this node advertises for it.
    ///
    /// # Why this exists separately from the #634 witness
    ///
    /// #634's witness seeds keys through
    /// [`register_hybrid_key`](crate::federation::tier_ingest::test_support::register_hybrid_key),
    /// which truncates to microseconds. That truncation was added because the
    /// postgres leg went red, and it was read as a fixture defect. It was not:
    /// the write paths hashed the row the WRITER held while every read
    /// re-serializes the row the BACKEND reloaded, and those differ whenever
    /// storage normalizes anything. Truncating the fixture hid the mechanism
    /// instead of closing it, and a witness that only fails when the fixture
    /// cooperates is not a witness.
    ///
    /// So this one supplies the divergence ITSELF, deterministically, and does
    /// not depend on the shared fixture's precision policy:
    ///
    /// * **789 nanoseconds** of sub-microsecond tail on `valid_from` /
    ///   `scrub_timestamp`. Postgres `TIMESTAMPTZ` drops it; sqlite (RFC-3339
    ///   TEXT) and memory keep it. Deterministic rather than clock-dependent —
    ///   `Utc::now()` *usually* carries nanoseconds, and a probe that fires
    ///   "usually" is a flake, not a gate. Kept under 1µs so `valid_from` is
    ///   never meaningfully in the future.
    /// * **`consent_role: Some("unregistered")`** — the STORED token, which
    ///   both SQL backends normalize to wire `None` on read. That instance has
    ///   nothing to do with clocks, and it is why the remedy is "hash the
    ///   stored row" rather than "truncate the timestamps": a fix aimed at
    ///   precision leaves this one live.
    ///
    /// Runs on all three backends. Memory normalizes nothing and rounds
    /// nothing, so it is the CONTROL — it must pass before and after; a change
    /// that reds memory has broken the derivation, not caught the skew.
    pub(crate) async fn exercise_nanosecond_key_wire_ref_resolves(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        use chrono::Timelike as _;

        let subject = format!("nanokey-subject-{tag}");
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(&subject);
        // A DETERMINISTIC sub-microsecond tail: keep the current microsecond
        // and append 789ns. Postgres truncates it away on the way in.
        let now = {
            let dt = chrono::Utc::now();
            dt.with_nanosecond(dt.nanosecond() / 1_000 * 1_000 + 789)
                .expect("789ns tail is a valid nanosecond field")
        };
        assert_ne!(
            now.nanosecond() % 1_000,
            0,
            "[{tag}] the fixture must actually carry sub-microsecond precision, \
             or this witness cannot fail"
        );

        let rec = crate::federation::KeyRecord {
            key_id: subject.clone(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: crate::federation::types::identity_type::AGENT.to_owned(),
            identity_ref: subject.clone(),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({ "id": subject }),
            original_content_hash: "deadbeef".to_owned(),
            scrub_signature_classical: "c2lnbmF0dXJl".to_owned(),
            scrub_signature_pqc: None,
            scrub_key_id: subject.clone(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            // The STORED form on the wire — reads back as `None` on both SQL
            // backends. See the doc above.
            consent_role: Some(crate::federation::types::consent_role::UNREGISTERED.to_owned()),
            additional_scrubs: Vec::new(),
        };
        dir.put_public_key(crate::federation::SignedKeyRecord { record: rec })
            .await
            .unwrap_or_else(|e| panic!("[{tag}] nanosecond-bearing key must register: {e}"));

        let refs = crate::federation::wire_index::wire_refs_for_subject(dir, &subject)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] wire_refs_for_subject: {e}"));

        // NON-VACUITY. An empty ref set resolves every ref it returns.
        assert!(
            refs.iter().any(|(k, _, _)| *k == "Key"),
            "[{tag}] no Key ref for the registered subject; got {refs:?}"
        );

        for (kind, content_hash, record_key) in &refs {
            let served = dir
                .lookup_signed_record_by_content_hash(kind, content_hash)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] lookup {kind}/{content_hash}: {e}"));
            assert!(
                served.is_some(),
                "[{tag}] ref ({kind}, {content_hash}) does not resolve (record_key \
                 {record_key}). The wire index was written from the row this node HELD, \
                 not the row it STORED — CIRISPersist#640. A peer asking for the ref \
                 this node just advertised would get None."
            );
        }
    }

    /// v30.13.0 (CIRISPersist#643) — a DETERMINISTIC sub-microsecond tail on
    /// every seeded row of four MORE kinds, each written through a different
    /// put chokepoint, all of which must still resolve through the ref this
    /// node advertises for them.
    ///
    /// # Why this exists beyond the #640 Key witness
    ///
    /// #640's witness covers the `Key` plane, which is where the defect was
    /// FOUND. The derivation it fixed — index the row as stored, never the
    /// struct the writer holds — was applied only there, while twelve other
    /// kinds went on hashing the in-memory value at fifteen sites per backend.
    /// A witness on the one plane that was fixed cannot tell you the rule
    /// holds; it can only tell you the exception does.
    ///
    /// So this drives one row through each of four DIFFERENT chokepoints, with
    /// the same 789ns tail postgres `TIMESTAMPTZ` rounds away:
    ///
    /// * `put_attestation` — `asserted_at` / `scrub_timestamp` /
    ///   `pqc_completed_at`;
    /// * `put_location_proof` — `asserted_at`, which is ALSO half the
    ///   `record_key`, so this row exercises the locator floor
    ///   ([`wire_index::locator_instant`](crate::federation::wire_index::locator_instant))
    ///   as well as the hash. Before #643 a nanosecond-bearing location proof
    ///   was unresolvable on postgres for two independent reasons;
    /// * `put_family` and `put_community` — `founded_at`, and each member's
    ///   `joined_at`.
    ///
    /// The check is the strongest available: for every entry
    /// [`wire_index::all_kind_hash_keys`](crate::federation::wire_index::all_kind_hash_keys)
    /// derives for these rows — the same list `rebuild_signed_wire_index`
    /// writes, computed from the reloaded rows — the INCREMENTALLY written
    /// index must already resolve it. A write path that indexed a different
    /// hash leaves the correct one absent, and the point-read returns `None`
    /// exactly as a peer's fetch would.
    ///
    /// Memory rounds nothing, so it is the CONTROL: it must pass before and
    /// after, and a change that reds memory has broken the derivation rather
    /// than caught the skew.
    pub(crate) async fn exercise_nanosecond_wire_refs_resolve_every_kind(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::tier_ingest::test_support as ts;
        use chrono::Timelike as _;

        // A DETERMINISTIC sub-microsecond tail — 789ns — not `Utc::now()`'s
        // luck. A probe that fires "usually" is a flake, not a gate.
        let now = {
            let dt = chrono::Utc::now();
            dt.with_nanosecond(dt.nanosecond() / 1_000 * 1_000 + 789)
                .expect("789ns tail is a valid nanosecond field")
        };
        assert_ne!(
            now.nanosecond() % 1_000,
            0,
            "[{tag}] the fixture must actually carry sub-microsecond precision, \
             or this witness cannot fail"
        );

        let author = format!("nskinds-author-{tag}");
        let member = format!("nskinds-member-{tag}");
        let fam = format!("nskinds-fam-{tag}");
        let comm = format!("nskinds-comm-{tag}");
        ts::register_hybrid_key(dir, &author).await;
        // A `user`-role member: CC 3.2's steward-binding gate refuses a bare
        // `node`/`agent` key into a non-infrastructure community, and that gate
        // is not what this witness is about.
        ts::register_identity_key(dir, &member, crate::federation::types::identity_type::USER)
            .await;
        ts::register_hybrid_key(dir, &fam).await;
        ts::register_hybrid_key(dir, &comm).await;

        // ── Attestation ───────────────────────────────────────────────
        let att_id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": att_id, "dimension": "trust:nskinds:v1", "score": 1.0, "confidence": 0.9,
        });
        let (och, sc, sp) = ts::sign_envelope(&author, &envelope);
        dir.put_attestation(crate::federation::SignedAttestation {
            attestation: crate::federation::Attestation {
                attestation_id: att_id.clone(),
                attesting_key_id: author.clone(),
                attested_key_id: author.clone(),
                attestation_type: crate::federation::types::attestation_type::SCORES.to_owned(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: och,
                scrub_signature_classical: sc,
                scrub_signature_pqc: sp,
                scrub_key_id: author.clone(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
                tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .unwrap_or_else(|e| panic!("[{tag}] nanosecond attestation must admit: {e}"));

        // ── LocationProof (hash AND locator) ──────────────────────────
        let cell = h3o::LatLng::new(37.0, -122.0)
            .expect("valid latlng")
            .to_cell(h3o::Resolution::Seven)
            .to_string();
        dir.put_location_proof(ts::sign_location_proof(
            &author,
            crate::federation::types::LocationProof {
                subject_key_id: author.clone(),
                cell_id: cell,
                cell_resolution: 7,
                asserted_at: now,
                valid_until: None,
                attestation_evidence: None,
                withdrawn_at: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] nanosecond location proof must admit: {e}"));

        // ── Family ────────────────────────────────────────────────────
        dir.put_family(ts::sign_family(
            &author,
            crate::federation::types::Family {
                family_key_id: fam.clone(),
                family_name: format!("nskinds-family-{tag}"),
                members: vec![crate::federation::types::FamilyMember {
                    key_id: member.clone(),
                    joined_at: now,
                    role: Some("founder".to_owned()),
                }],
                founded_at: now,
                consensus_protocol: "founder_only".to_owned(),
                consensus_protocol_entrenched: false,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] nanosecond family must admit: {e}"));

        // ── Community ─────────────────────────────────────────────────
        dir.put_community(ts::sign_community(
            &author,
            crate::federation::types::Community {
                community_key_id: comm.clone(),
                community_name: format!("nskinds-community-{tag}"),
                members: vec![crate::federation::types::CommunityMember {
                    key_id: member.clone(),
                    joined_at: now,
                    role: Some("founder".to_owned()),
                }],
                founded_at: now,
                consensus_protocol: "founder_only".to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap_or_else(|e| panic!("[{tag}] nanosecond community must admit: {e}"));

        // The rebuild-side derivation, computed from the RELOADED rows. Scoped
        // to this fixture's own ids so a shared/genesis-seeded directory cannot
        // make the assertion about someone else's rows.
        let all = crate::federation::wire_index::all_kind_hash_keys(dir)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] all_kind_hash_keys: {e}"));
        let mine: Vec<_> = all
            .into_iter()
            .filter(|(_, _, rk)| {
                rk.contains(&author)
                    || rk.contains(&member)
                    || rk.contains(&fam)
                    || rk.contains(&comm)
                    || rk.contains(&att_id)
            })
            .collect();

        // NON-VACUITY FIRST. An empty set resolves every ref it contains, so
        // without this the loop below passes on a fixture that seeded nothing.
        for kind in ["Key", "Attestation", "LocationProof", "Family", "Community"] {
            assert!(
                mine.iter().any(|(k, _, _)| *k == kind),
                "[{tag}] no {kind} ref for the seeded fixture; got {mine:?}"
            );
        }

        for (kind, content_hash, record_key) in &mine {
            let served = dir
                .lookup_signed_record_by_content_hash(kind, content_hash)
                .await
                .unwrap_or_else(|e| panic!("[{tag}] lookup {kind}/{content_hash}: {e}"));
            assert!(
                served.is_some(),
                "[{tag}] ref ({kind}, {content_hash}) does not resolve (record_key \
                 {record_key}). The {kind} write path indexed the row this node HELD, \
                 not the row it STORED — CIRISPersist#643, the #640 defect at the \
                 twelve kinds #640 did not reach. A peer asking for this exact ref \
                 gets None."
            );
        }
    }

    pub(crate) async fn exercise_rescope_keeps_row_servable(
        dir: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::types::cohort_scope;
        use chrono::Timelike as _;

        let author = format!("rescope-author-{tag}");
        crate::federation::tier_ingest::test_support::register_hybrid_key(dir, &author).await;

        let id = uuid::Uuid::new_v4().to_string();
        let envelope = serde_json::json!({
            "id": id, "dimension": "trust:rescope:v1", "score": 1.0, "confidence": 0.9,
        });
        let (och, sc, sp) =
            crate::federation::tier_ingest::test_support::sign_envelope(&author, &envelope);
        // v30.13.0 (CIRISPersist#643) — NANOSECOND-BEARING, deliberately.
        //
        // This fixture used to truncate to microseconds, with a comment calling
        // the skew "a property of the FIXTURE, not of the backend". That was
        // wrong in the same way #634's truncation was wrong: `postgres`
        // `TIMESTAMPTZ` rounds a sub-microsecond instant on the way in, and the
        // re-scope path then hashed the row it HELD while every read
        // re-serializes the row it STORED. The truncation was not keeping the
        // test honest, it was hiding the mechanism the test is named for.
        //
        // Now that `set_attestation_cohort_scope` indexes the stored row on all
        // three backends, the tail can stay — and removing it is what makes
        // this a regression net rather than a description. 789ns, deterministic:
        // `Utc::now()` only *usually* carries a sub-microsecond tail, and a
        // probe that fires usually is a flake.
        let now = {
            let dt = chrono::Utc::now();
            dt.with_nanosecond(dt.nanosecond() / 1_000 * 1_000 + 789)
                .expect("789ns tail is a valid nanosecond field")
        };
        assert_ne!(
            now.nanosecond() % 1_000,
            0,
            "[{tag}] the fixture must actually carry sub-microsecond precision, \
             or this witness cannot fail"
        );
        let att = crate::federation::SignedAttestation {
            attestation: crate::federation::Attestation {
                attestation_id: id.clone(),
                attesting_key_id: author.clone(),
                attested_key_id: author.clone(),
                attestation_type: crate::federation::types::attestation_type::SCORES.to_owned(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: och,
                scrub_signature_classical: sc,
                scrub_signature_pqc: sp,
                scrub_key_id: author.clone(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
                tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            },
        };
        dir.put_attestation(att)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] seed row must admit: {e}"));

        // Servable BEFORE the re-scope — the control. Without this, a fix that
        // never indexed anything would look identical to a fix that works.
        let before = dir
            .get_attestation(&id)
            .await
            .expect("get")
            .expect("row exists");
        // The index is keyed by `content_hash_of(row)` — the RE-SERIALIZED row,
        // which is exactly what the offer path advertises. NOT `persist_row_hash`;
        // asking for that returns None even on a healthy row, which is how the
        // first version of this test failed its own precondition.
        let before_wire = crate::federation::wire_index::content_hash_of(&before).expect("hash");
        let served = dir
            .lookup_signed_record_by_content_hash("Attestation", &before_wire)
            .await
            .expect("lookup");
        assert!(
            served.is_some(),
            "[{tag}] precondition: a freshly put federation row must be servable by its own hash"
        );

        dir.set_attestation_cohort_scope(&id, cohort_scope::COMMUNITY)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] re-scope must succeed: {e}"));

        let after = dir
            .get_attestation(&id)
            .await
            .expect("get")
            .expect("row exists");
        assert_ne!(
            after.persist_row_hash, before.persist_row_hash,
            "[{tag}] the re-scope must change persist_row_hash, or this test proves nothing"
        );
        let after_wire = crate::federation::wire_index::content_hash_of(&after).expect("hash");
        assert_ne!(
            after_wire, before_wire,
            "[{tag}] the re-scope must change the SERIALIZED row hash, or the index could not go \
         stale and this test proves nothing"
        );
        let served_after = dir
            .lookup_signed_record_by_content_hash("Attestation", &after_wire)
            .await
            .expect("lookup");
        assert!(
            served_after.is_some(),
            "[{tag}] CIRISPersist#610: the row re-serializes to {after_wire} — the hash the offer \
         path advertises — but the signed_wire_index cannot serve it. The peer asks for exactly \
         the ref this node just advertised and gets nothing: `wanted=N packed=N-1`. The wire \
         index must move WITH the row."
        );
    }

    /// R2(b) on the write path, both directions, on whichever backend `dir` is.
    /// v30.3.0 (CIRISPersist#611) — **a self-asserted `trusted_publisher`
    /// does not get into the publisher-vouch chain.**
    ///
    /// GateSpec:
    ///
    /// - **family** — `deontic`. Varying it changes what the mesh treats as a
    ///   vouched rating: a stranger's self-issued `content_rating:` row is
    ///   returned to callers as a trusted publisher's vouch.
    /// - **headwaters** — `lookup_trusted_publisher_chain` (the READ door) ×
    ///   `capability_roots_to_trusted_root` (the resolver its declared mode
    ///   names). Both already existed; nothing connected them.
    /// - **references** — #611, #607 (the same contradiction on three write
    ///   doors), #571 (why the WRITE door is deliberately open here), CC 3.3.12.
    /// - **dye test** — this IS the dye test. On the pre-#611 code the
    ///   unconferred publisher's row comes back in the chain.
    /// - **depth** — proves the filter resolves a conferral, both directions.
    ///   Says nothing about the CONTENT of a rating, nor about whether the root
    ///   should have conferred. It is also the only `?Sized` consumer of that
    ///   resolver, so it doubles as the witness that the generic conversion did
    ///   not change the walk's answer.
    /// - **owner** — persist.
    ///
    /// Both legs are load-bearing: without the CONFERRED leg, a door that
    /// returns an empty chain for everyone passes, and the whole
    /// `content_rating:` plane goes dark; without the UNCONFERRED leg, the
    /// pre-#611 code passes.
    pub(crate) async fn exercise_publisher_vouch_conferral(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::types::{delegation_scope, identity_type};

        let node = dir
            .node_key_id()
            .expect("this leg must give the backend a node identity before calling");
        let publisher = format!("tp-pub-{suffix}");
        let root = format!("tp-root-{suffix}");
        super::steward_liveness_test_support::register(
            dir,
            &publisher,
            &[identity_type::TRUSTED_PUBLISHER],
        )
        .await;

        // A content hash this rating vouches for. Real hex-64: the door
        // validates the shape early and returns an empty vector for anything
        // else, which would make both legs pass for the wrong reason.
        let sha: String = suffix
            .bytes()
            .cycle()
            .take(64)
            .map(|b| char::from_digit((b % 16) as u32, 16).unwrap())
            .collect();

        let rating_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();
        let envelope = serde_json::json!({
            "dimension": "content_rating:mpa:pg13:v1",
            "score": 0.5,
            "evidence_refs": [sha],
        });
        let (och, ed_sig, pqc_sig) = sign_envelope(&publisher, &envelope);
        dir.put_attestation(SignedAttestation {
            attestation: Attestation {
                attestation_id: rating_id.clone(),
                attesting_key_id: publisher.clone(),
                attested_key_id: publisher.clone(),
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: envelope,
                original_content_hash: och,
                scrub_signature_classical: ed_sig,
                scrub_signature_pqc: pqc_sig,
                scrub_key_id: publisher.clone(),
                scrub_timestamp: now,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: crate::federation::types::cohort_scope::SELF.to_owned(),
                tier: attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            },
        })
        .await
        .expect(
            "the WRITE door for content_rating: is deliberately open (CC 3.3.12 leaves the \
             family open vocabulary; CIRISPersist#571 removed persist's stricter gate) — if this \
             refuses, the discrimination moved and this witness is testing the wrong door",
        );

        // ── (1) SELF-ASSERTED publisher — NOT in the chain ────────────────
        let chain = dir
            .lookup_trusted_publisher_chain(&sha)
            .await
            .expect("the read itself must succeed; the filter is on membership, not on the call");
        assert!(
            chain.is_empty(),
            "a self-asserted trusted_publisher must not vouch — that is CIRISPersist#611. Got \
             {} row(s)",
            chain.len()
        );

        // ── (2) CONFERRED publisher — IS in the chain ─────────────────────
        confer_scope_from_trusted_root(
            dir,
            &node,
            &root,
            &publisher,
            delegation_scope::INFRA_PUBLISH_RATING,
        )
        .await;
        let chain = dir
            .lookup_trusted_publisher_chain(&sha)
            .await
            .expect("read after conferral");
        assert_eq!(
            chain.len(),
            1,
            "a publisher CONFERRED infra:publish_rating by this node's own trust root must vouch \
             — otherwise the content_rating: plane is dark and leg (1) passes vacuously"
        );
        assert_eq!(
            chain[0].attestation_id, rating_id,
            "the chain must carry the rating row itself, not some other row"
        );
    }

    /// v30.3.0 (CIRISPersist#607) — **a self-asserted `substrate_persist`
    /// cannot file a `hard_case:` record ABOUT ANOTHER PARTY.**
    ///
    /// GateSpec:
    ///
    /// - **family** — `testimonial`, frame `repairable_does_not_factor`: a
    ///   `hard_case:` row is the artifact CIRISServer's graded admin ladder
    ///   leaves behind when it acts on someone. Forged, it is an accusation on
    ///   the record that the accused cannot unmake by behaving differently.
    /// - **headwaters** — `put_attestation` (every backend) ×
    ///   `check_reserved_prefix_admission` (the shared chokepoint).
    /// - **references** — CIRISPersist#607; CIRISServer's `abuse_surface`
    ///   reproduction; #565 (typed refusals name the missing thing).
    /// - **dye test** — this IS the dye test. On the pre-#607 code the third-party
    ///   leg ADMITS, because the gate was a membership test on
    ///   `substrate_persist`, and `substrate_persist` is a claim any key can make
    ///   about itself at registration.
    /// - **depth** — proves the gate is a CONFERRAL resolved against this node's
    ///   own trust root, in both directions: refused without one, admitted with
    ///   one. Says nothing about whether the root SHOULD have conferred it; that
    ///   is the conferral plane's business, not this door's.
    /// - **owner** — persist.
    ///
    /// Three legs, and all three are load-bearing. Without the SELF leg, a gate
    /// that refuses every `hard_case:` row would pass — and that gate tightens
    /// past what `substrate_persist`'s retirement condition names, leaving a node
    /// unable to enter its own incident on this plane. Without the CONFERRED leg,
    /// a gate that refuses every third-party row would pass, and the whole admin
    /// ladder would be unreachable. Without the REFUSAL leg, the pre-#607 code
    /// passes.
    pub(crate) async fn exercise_hard_case_third_party_conferral(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::types::{delegation_scope, identity_type};

        // The gate resolves the conferral against THIS NODE's trust root, so a
        // directory with no identity of its own refuses for a different reason.
        // Asserting it here means a leg that forgets `set_node_key_id` fails
        // loudly instead of passing for the wrong reason.
        let node = dir
            .node_key_id()
            .expect("this leg must give the backend a node identity before calling");

        let author = format!("hc-persist-{suffix}");
        let victim = format!("hc-victim-{suffix}");
        let root = format!("hc-root-{suffix}");
        super::steward_liveness_test_support::register(
            dir,
            &author,
            &[identity_type::SUBSTRATE_PERSIST],
        )
        .await;
        super::steward_liveness_test_support::register(dir, &victim, &[identity_type::USER]).await;

        let row = |id: &str, about: &str| {
            let now = Utc::now();
            let dimension = "hard_case:consent_sla_breach:v1";
            let envelope = serde_json::json!({ "dimension": dimension });
            let (och, ed_sig, pqc_sig) = sign_envelope(&author, &envelope);
            SignedAttestation {
                attestation: Attestation {
                    attestation_id: id.to_owned(),
                    attesting_key_id: author.clone(),
                    attested_key_id: about.to_owned(),
                    attestation_type: dimension.to_owned(),
                    weight: None,
                    asserted_at: now,
                    expires_at: None,
                    attestation_envelope: envelope,
                    original_content_hash: och,
                    scrub_signature_classical: ed_sig,
                    scrub_signature_pqc: pqc_sig,
                    scrub_key_id: author.clone(),
                    scrub_timestamp: now,
                    pqc_completed_at: None,
                    persist_row_hash: String::new(),
                    subject_key_ids: Vec::new(),
                    withdraws_admission_rule: None,
                    cohort_scope: crate::federation::types::cohort_scope::SELF.to_owned(),
                    tier: attestation_tier::FEDERATION.to_owned(),
                    promoted_at: None,
                    additional_scrubs: Vec::new(),
                },
            }
        };

        // ── (1) ABOUT ANOTHER PARTY, no conferral — REFUSED ───────────────
        let forged = uuid::Uuid::new_v4().to_string();
        let err = dir.put_attestation(row(&forged, &victim)).await.expect_err(
            "a self-asserted substrate_persist must NOT file a hard_case record about a \
                 third party — that is CIRISPersist#607",
        );
        assert_eq!(
            err.kind(),
            "federation_reserved_prefix_emitter_mismatch",
            "must refuse at the reserved-prefix door, not incidentally elsewhere: {err}"
        );
        assert!(
            err.to_string()
                .contains(delegation_scope::INFRA_RECORD_HARD_CASE),
            "the refusal must NAME the missing conferral (#565) — an is_err() check alone would \
             pass on an unregistered key or a bad signature. Got: {err}"
        );
        assert!(
            dir.get_attestation(&forged).await.expect("get").is_none(),
            "a row refused by the #607 gate must not be persisted"
        );

        // ── (2) ABOUT ITSELF, no conferral — ADMITTED ─────────────────────
        // The retirement condition in `substrate_persist`'s mode note is scoped
        // to rows that are an input to a decision ABOUT ANOTHER PARTY; a
        // self-attested row is not one, and refusing it would tighten past what
        // #607 asks.
        let own = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(row(&own, &author))
            .await
            .expect("a SELF-attested hard_case row must still admit — see the doc comment");
        assert!(
            dir.get_attestation(&own).await.expect("get").is_some(),
            "the self-attested row must be stored"
        );

        // ── (3) ABOUT ANOTHER PARTY, WITH a conferral — ADMITTED ──────────
        confer_scope_from_trusted_root(
            dir,
            &node,
            &root,
            &author,
            delegation_scope::INFRA_RECORD_HARD_CASE,
        )
        .await;
        let conferred = uuid::Uuid::new_v4().to_string();
        dir.put_attestation(row(&conferred, &victim)).await.expect(
            "a substrate_persist CONFERRED infra:record_hard_case by this node's own trust \
                 root must be able to file the record — otherwise the admin ladder is \
                 unreachable and leg (1) passes vacuously",
        );
        assert!(
            dir.get_attestation(&conferred)
                .await
                .expect("get")
                .is_some(),
            "the conferred third-party row must be stored"
        );
    }

    pub(crate) async fn exercise_r2b_refusal(dir: &dyn FederationDirectory, suffix: &str) {
        let author = format!("r2-author-{suffix}");
        register_agent_key(dir, &author).await;

        // ── the refusal ──────────────────────────────────────────────────
        // A dimension on a GOVERNED family with no registry row. Admitting it
        // would file the row under the ProducerSteward fallback — the exact
        // "silently and cumulatively" state CC 3.1.7 R2 names.
        let probe = format!("{R2_PROBE_UNREGISTERED_STEM}probe:v1");
        // A REAL uuid, not a readable slug: postgres types `attestation_id` as
        // `uuid` and refuses anything else at the driver, so a slug would make
        // the postgres leg fail on the fixture instead of on the property —
        // which is the "memory tolerates what postgres rejects" trap this
        // three-backend witness exists to catch. (It caught it: the first run
        // of this body was green on memory + sqlite and red on postgres with
        // `attestation_id is not a valid UUID`.)
        let bad_id = uuid::Uuid::new_v4().to_string();
        let err = dir
            .put_attestation(scores_row(&bad_id, &author, &probe))
            .await
            .expect_err("R2(b): an unregistered governed family must never admit");
        assert_eq!(
            err.kind(),
            "federation_namespace_family_unregistered",
            "R2(b) must refuse with its own typed error, not some other gate's: got {err}"
        );
        match &err {
            Error::NamespaceFamilyUnregistered {
                namespace,
                family_stem,
                reason,
            } => {
                assert_eq!(namespace, &probe);
                assert_eq!(family_stem, R2_PROBE_UNREGISTERED_STEM);
                assert_eq!(*reason, "namespace_family_unregistered");
            }
            other => panic!("wrong variant: {other:?}"),
        }
        // Verify-before-mutation: the refused row was not stored.
        assert!(
            dir.get_attestation(&bad_id).await.expect("get").is_none(),
            "a row refused by R2(b) must not be persisted"
        );

        // ── the conformant traffic that must still pass ──────────────────
        // Three shapes R2(b) is forbidden to touch: a REGISTERED governed
        // family (persist's own #574 mint), open vocabulary INSIDE a
        // registered family, and a family CC never speaks to at all.
        for dim in [
            "objection:raised:v1",
            "credits:rust:en:someone:v1",
            "identity_binding:v1",
        ] {
            let id = uuid::Uuid::new_v4().to_string();
            dir.put_attestation(scores_row(&id, &author, dim))
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "R2(b) must not refuse conformant traffic {dim:?} — refusing it and \
                         blaming the producer is the failure CIRISPersist#590 was opened to \
                         prevent: {e}"
                    )
                });
            assert!(
                dir.get_attestation(&id).await.expect("get").is_some(),
                "conformant row {dim:?} must be stored"
            );
        }
    }
}

/// (CIRISPersist#584) — the **steward-binding liveness** witness, run by the
/// memory / sqlite / postgres suites against `&dyn FederationDirectory` so no
/// backend can silently disagree about which `delegates_to` edges still confer
/// stewardship. `suffix` scopes every fixture key so a run against a shared
/// postgres test DB does not collide with a prior one.
///
/// Two properties, deliberately in ONE body because they constrain each other:
///
///  * **the biconditional** — `is_steward_bound(k)` ⟺
///    `!steward_bindings_of(k).is_empty()` ⟺
///    `!steward_binding_chain(k).is_empty()`. The repo asserts this in prose at
///    three sites; here it is asserted at every state transition. A fold
///    repaired at one site and not the others fails HERE — which is why the
///    shared-predicate extraction is a correctness requirement, not hygiene.
///  * **subject-revocation liveness** — a `delegates_to(U → K)` retracted by an
///    admitted `withdraws` that its own granter `U` never issued (CEG §3.2.3
///    rules 2/3/4) is NOT live, and confers no stewardship.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod steward_liveness_test_support {
    use super::*;
    use crate::federation::tier_ingest::test_support::{hybrid_pubkeys, sign_envelope};
    use crate::federation::types::{
        attestation_tier, attestation_type, cohort_scope, delegation_scope as ds, identity_type,
    };
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation, SignedKeyRecord};
    use chrono::Utc;

    /// Register `key_id` carrying its REAL deterministic hybrid pubkeys and the
    /// given `identity_type` set, so federation-tier ingest verifies rows it
    /// signs.
    pub(crate) async fn register(dir: &dyn FederationDirectory, key_id: &str, types: &[&str]) {
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        let now = Utc::now();
        dir.put_public_key(SignedKeyRecord {
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

    /// A federation-tier row of `kind`, hybrid-signed by `signer` over
    /// `envelope`. `attestation_id` is a real UUID — postgres types the column
    /// as `uuid` and refuses anything else at the driver.
    pub(crate) fn signed_row(
        signer: &str,
        attested: &str,
        kind: &str,
        envelope: serde_json::Value,
    ) -> Attestation {
        let (och, classical, pqc) = sign_envelope(signer, &envelope);
        let ts = Utc::now();
        Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: signer.to_owned(),
            attested_key_id: attested.to_owned(),
            attestation_type: kind.to_owned(),
            weight: None,
            asserted_at: ts,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: classical,
            scrub_signature_pqc: pqc,
            scrub_key_id: signer.to_owned(),
            scrub_timestamp: ts,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: cohort_scope::FEDERATION.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// A `delegates_to(granter → recipient)`. `subjects` fills
    /// `subject_key_ids` — the CIRISConstitution rc3-conformant shape in which
    /// a binding NAMES the key it is about, and the field CEG §3.2.3 rule 2
    /// reads for subject self-revocation.
    fn delegates_to(
        granter: &str,
        recipient: &str,
        scope: &[&str],
        subjects: &[&str],
    ) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut row = signed_row(
            granter,
            recipient,
            attestation_type::DELEGATES_TO,
            serde_json::json!({
                "id": id,
                "scope": scope.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            }),
        );
        row.subject_key_ids = subjects.iter().map(|s| (*s).to_owned()).collect();
        row
    }

    pub(crate) fn withdraws_of(
        issuer: &str,
        attested: &str,
        target_attestation_id: &str,
    ) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        signed_row(
            issuer,
            attested,
            attestation_type::WITHDRAWS,
            serde_json::json!({
                "id": id,
                "references_attestation_id": target_attestation_id,
            }),
        )
    }

    /// The §11.10 **edge-retraction** shape: a granter's `withdraws` naming
    /// only the recipient, with NO `references_attestation_id`. This is the
    /// row only the granter-scoped clause can see — it is what keeps that
    /// clause load-bearing after the admitted-`withdraws` clause lands, and a
    /// witness that used the referencing shape here would let clause (3) be
    /// deleted silently.
    pub(crate) fn bare_edge_retraction(granter: &str, recipient: &str) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        signed_row(
            granter,
            recipient,
            attestation_type::WITHDRAWS,
            serde_json::json!({ "id": id }),
        )
    }

    pub(crate) async fn store(
        dir: &dyn FederationDirectory,
        row: &Attestation,
    ) -> Result<(), Error> {
        dir.put_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
    }

    /// **THE BICONDITIONAL.** The three steward-binding readers are three
    /// projections of ONE relation; asserting them together is what makes a
    /// per-site fold repair impossible to land silently.
    async fn assert_biconditional(
        dir: &dyn FederationDirectory,
        k: &str,
        expect_bound: bool,
        at: &str,
    ) {
        let bound = is_steward_bound(dir, k).await.expect("is_steward_bound");
        let anchors = steward_bindings_of(dir, k)
            .await
            .expect("steward_bindings_of");
        let chain = steward_binding_chain(dir, k)
            .await
            .expect("steward_binding_chain");
        assert_eq!(
            bound,
            !anchors.is_empty(),
            "[{at}] is_steward_bound({k}) <=> !steward_bindings_of({k}).is_empty() — the \
             invariant admission.rs states in prose. bound={bound} anchors={anchors:?}"
        );
        assert_eq!(
            bound,
            !chain.is_empty(),
            "[{at}] is_steward_bound({k}) <=> !steward_binding_chain({k}).is_empty(). \
             bound={bound} chain={chain:?}"
        );
        assert_eq!(
            bound, expect_bound,
            "[{at}] {k} should be steward-bound={expect_bound}; anchors={anchors:?}"
        );
    }

    /// The #584 behavioural witness. Run against every backend.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn exercise_steward_binding_liveness(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        let granter = format!("sb-granter-{suffix}");
        let node = format!("sb-node-{suffix}");

        register(dir, &granter, &[identity_type::USER]).await;
        register(dir, &node, &[identity_type::NODE]).await;

        // A node with no incoming edge is not steward-bound (clauses 1/2 never
        // fire for a node key).
        assert_biconditional(dir, &node, false, "no edges").await;

        // ── the live delegation ──────────────────────────────────────────
        // rc3-conformant: the binding NAMES the key it is about in
        // `subject_key_ids`. That is the field CEG §3.2.3 rule 2 reads, and it
        // is precisely what CIRISPersist#578's own comment says a conformant
        // binding MUST carry.
        let edge = delegates_to(
            &granter,
            &node,
            &[ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
            &[&node],
        );
        store(dir, &edge).await.expect("delegates_to admitted");
        assert_biconditional(dir, &node, true, "live edge").await;
        assert_eq!(
            steward_bindings_of(dir, &node).await.expect("anchors"),
            vec![granter.clone()],
            "the live edge's granter is the node's steward anchor"
        );

        // ── the subject-side revocation ──────────────────────────────────
        // The SUBJECT of the delegation retracts it: CEG §3.2.3 rule 2
        // (subject self-revocation), admitted by the real `withdraws` gate.
        // The edge's own GRANTER never issued this — exactly the shape the
        // granter-scoped fold cannot see.
        let revocation = withdraws_of(&node, &node, &edge.attestation_id);
        store(dir, &revocation)
            .await
            .expect("a rule-2 withdraws against the delegation must be ADMITTED");
        let stored = dir
            .get_attestation(&revocation.attestation_id)
            .await
            .expect("read")
            .expect("the withdraws is stored");
        assert_eq!(
            stored.withdraws_admission_rule,
            Some(2),
            "the fixture must exercise the rule-2 (non-granter) arm — if this is None the \
             withdraws was admitted unresolved and the witness proves nothing about authority"
        );

        // THE DEFECT (#584): the edge is dead, so nothing it conferred survives.
        assert_biconditional(dir, &node, false, "subject-revoked edge").await;
        assert!(
            steward_bindings_of(dir, &node)
                .await
                .expect("anchors")
                .is_empty(),
            "a delegates_to retracted by an admitted withdraws its granter never issued must NOT \
             confer stewardship — CIRISPersist#584, the second site of the fold CIRISPersist#578 \
             repaired in live_owner_binding_granters"
        );
        // …and the outbound projection agrees, since it is defined by the same
        // predicate (`n ∈ nodes_stewarded_by(U)` ⟺ `U ∈ steward_bindings_of(n)`).
        assert!(
            !nodes_stewarded_by(dir, &granter)
                .await
                .expect("nodes_stewarded_by")
                .contains(&node),
            "the inverse projection must not keep listing a node whose only edge is dead"
        );

        // ── the granter-scoped arm still works (no regression) ───────────
        // Deliberately the BARE §11.10 edge-retraction, with no
        // `references_attestation_id`: the new clause cannot see it, so this
        // step fails if the granter-scoped clause is ever dropped as
        // "subsumed". (It is not subsumed — the two clauses read different
        // rows.)
        let node2 = format!("sb-node2-{suffix}");
        register(dir, &node2, &[identity_type::NODE]).await;
        let edge2 = delegates_to(&granter, &node2, &[ds::INFRA_SERVE], &[]);
        store(dir, &edge2).await.expect("second edge admitted");
        assert_biconditional(dir, &node2, true, "second live edge").await;
        store(dir, &bare_edge_retraction(&granter, &node2))
            .await
            .expect("the granter's own edge-retraction lands");
        assert_biconditional(dir, &node2, false, "granter-retracted edge").await;

        // ── an unrelated withdraws does not kill a live edge ─────────────
        let node3 = format!("sb-node3-{suffix}");
        register(dir, &node3, &[identity_type::NODE]).await;
        let edge3 = delegates_to(&granter, &node3, &[ds::INFRA_SERVE], &[&node3]);
        store(dir, &edge3).await.expect("third edge admitted");
        let decoy = withdraws_of(&node3, &node3, &uuid::Uuid::new_v4().to_string());
        store(dir, &decoy)
            .await
            .expect("a withdraws naming an absent target admits unresolved");
        assert_biconditional(dir, &node3, true, "unrelated withdraws").await;
        assert_eq!(
            steward_bindings_of(dir, &node3).await.expect("anchors"),
            vec![granter.clone()],
            "a withdraws that references some OTHER attestation must not fold this edge away"
        );
    }

    /// **THE BLAST RADIUS, witnessed rather than reasoned about**
    /// (CIRISPersist#584).
    ///
    /// `check_no_moderator_federate_apply` scans `community_id` /
    /// `community_key_id` / `cohort_key_id`, and #574 objection envelopes carry
    /// `cohort_key_id` by design. It reaches [`is_steward_bound`]. So the
    /// question the pre-flight scoping left open — *does the stricter fold
    /// actually flip a live binding on the objection plane?* — has a concrete
    /// answer, and this body is it:
    ///
    /// **Yes.** A community whose only authority root is a NODE key is
    /// moderator-bearing solely by clause (3), and a subject-revoked
    /// `delegates_to` takes its moderator away. Every subsequent
    /// federation-tier row keyed on it — including the objection that is the
    /// #574 brake and the ballot #591 escalates to — is refused
    /// [`Error::CommunityHasNoModerator`].
    ///
    /// That is CC 4.5.4 / §11.11 rule 3 working as written ("better no group
    /// than an unmoderated one"), and it is a REAL behaviour change: before
    /// this cut the dead edge kept the community federating. It is asserted
    /// here so it is a decision on the record, not a surprise in a deployment.
    ///
    /// Note the shape it does NOT touch: the existing #574 / #591 witnesses
    /// roster `user`-role members, which self-anchor under clause (1) and never
    /// consult the fold at all. The exposure is exactly node/agent-rostered
    /// commons.
    pub(crate) async fn exercise_objection_plane_blast_radius(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::cohort::Cohort;
        use crate::federation::reverse_quorum::{
            objection_envelope, record_objection, ObjectionOutcome,
        };
        use crate::federation::types::CommunityMember;
        use crate::federation::Community;

        let steward = format!("op-steward-{suffix}");
        let n1 = format!("op-n1-{suffix}");
        let n2 = format!("op-n2-{suffix}");
        let actor = format!("op-actor-{suffix}");
        let community = format!("op-commons-{suffix}");

        register(dir, &steward, &[identity_type::USER]).await;
        register(dir, &n1, &[identity_type::NODE]).await;
        register(dir, &n2, &[identity_type::NODE]).await;
        register(dir, &actor, &[identity_type::USER]).await;
        register(dir, &community, &[identity_type::USER]).await;

        // The commons is rostered by NODE keys — legal (CC 3.2 requires each to
        // be steward-bound, and each is) and the only shape where the fold is
        // load-bearing.
        let edges: Vec<Attestation> = [&n1, &n2]
            .iter()
            .map(|n| {
                delegates_to(
                    &steward,
                    n,
                    &[ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
                    &[n],
                )
            })
            .collect();
        for e in &edges {
            store(dir, e).await.expect("steward binds the node member");
        }

        let now = Utc::now();
        dir.put_community(
            crate::federation::tier_ingest::test_support::sign_community(
                &n1,
                Community {
                    community_key_id: community.clone(),
                    community_name: format!("node commons {suffix}"),
                    members: [&n1, &n2]
                        .iter()
                        .enumerate()
                        .map(|(i, k)| CommunityMember {
                            key_id: (*k).clone(),
                            joined_at: now,
                            role: Some(if i == 0 { "founder" } else { "member" }.to_owned()),
                        })
                        .collect(),
                    founded_at: now,
                    consensus_protocol: "reverse_quorum:1/2:3600".to_owned(),
                    policy_blob: None,
                    persist_row_hash: String::new(),
                },
            ),
        )
        .await
        .expect("a node-rostered commons is admissible while its members are steward-bound");

        // The commons act, taking effect on arrival (act-unless-objected).
        let action = signed_row(
            &actor,
            &actor,
            attestation_type::SCORES,
            serde_json::json!({
                "dimension": "testimonial_witness:commons_act:v1",
                "payload": {"action": "the commons act under objection"},
            }),
        );
        store(dir, &action).await.expect("the commons act lands");

        assert_eq!(
            no_moderator_federate_verdict(dir, &community)
                .await
                .expect("verdict")["admitted"],
            serde_json::json!(true),
            "while the bindings are live the commons has a moderator"
        );

        // ── the objection lands ──────────────────────────────────────────
        let o1 = signed_row(
            &n1,
            &actor,
            attestation_type::SCORES,
            objection_envelope(
                Cohort::Community,
                &community,
                &action.attestation_id,
                "harms the commons",
            ),
        );
        assert_eq!(
            record_objection(dir, &o1).await.expect("record"),
            ObjectionOutcome::Admitted,
            "one member is the whole protective threshold"
        );

        // ── the subject revokes both bindings ────────────────────────────
        for (n, e) in [(&n1, &edges[0]), (&n2, &edges[1])] {
            store(dir, &withdraws_of(n, n, &e.attestation_id))
                .await
                .expect("the subject's rule-2 withdraws lands");
            assert!(
                !is_steward_bound(dir, n).await.expect("is_steward_bound"),
                "the member's only binding is dead"
            );
        }

        // ── and the objection plane goes dark for this commons ───────────
        assert_eq!(
            no_moderator_federate_verdict(dir, &community)
                .await
                .expect("verdict"),
            serde_json::json!({
                "admitted": false,
                "community_known": true,
                "reason": "federation_community_no_moderator",
            }),
            "§11.11 rule 3: a commons whose every authority root lost its binding must not \
             continue at moderated capability"
        );
        let o2 = signed_row(
            &n2,
            &actor,
            attestation_type::SCORES,
            objection_envelope(
                Cohort::Community,
                &community,
                &action.attestation_id,
                "still harms the commons",
            ),
        );
        let err = record_objection(dir, &o2)
            .await
            .expect_err("the apply-time moderator re-check must refuse it");
        assert_eq!(
            err.kind(),
            "federation_community_no_moderator",
            "the refusal must be the §11.11 gate NAMING itself, not some incidental error: {err}"
        );
        assert!(
            dir.get_attestation(&o2.attestation_id)
                .await
                .expect("get")
                .is_none(),
            "verify-before-mutation: the refused objection left no row"
        );
        // The objection already recorded is EVIDENCE and is untouched — persist
        // records an objection, it never sentences a row.
        assert!(
            dir.get_attestation(&o1.attestation_id)
                .await
                .expect("get")
                .is_some(),
            "the already-admitted objection survives its commons losing its moderator"
        );

        // ── THE STATE IS EXITABLE ────────────────────────────────────────
        // The fail-secure floor must not be a one-way door — that is the
        // permanent-lock failure CIRISPersist#578 exists to prevent, one plane
        // over. The recovery act is a FRESH steward binding, a row about the
        // NODE and not about the commons, so the §11.11 apply gate does not
        // refuse the very act that lifts it.
        store(
            dir,
            &delegates_to(
                &steward,
                &n1,
                &[ds::INFRA_SERVE, ds::INFRA_NETWORK_PRESENCE],
                &[&n1],
            ),
        )
        .await
        .expect("re-binding the node member is not itself keyed on the commons");
        assert!(
            is_steward_bound(dir, &n1).await.expect("is_steward_bound"),
            "a fresh edge is live — the subject's withdraws named the OLD attestation_id, not the \
             granter"
        );
        let o3 = signed_row(
            &n2,
            &actor,
            attestation_type::SCORES,
            objection_envelope(
                Cohort::Community,
                &community,
                &action.attestation_id,
                "the commons speaks again",
            ),
        );
        assert_eq!(
            record_objection(dir, &o3).await.expect("record"),
            ObjectionOutcome::Admitted,
            "with one authority root re-bound the commons federates again — the stricter fold is \
             a gate, never a tombstone"
        );
    }
}

/// (CIRISPersist#593) — the **moderation-duty walk liveness** witness, run by
/// the memory / sqlite / postgres suites against `&dyn FederationDirectory`.
///
/// The property: a `delegates_to` on a moderation chain that has been retracted
/// by an admitted `withdraws` its own GRANTER never issued (CEG §3.2.3 rules
/// 2/3/4 — subject self-revocation, canonical-bound claimant, consent-revocation
/// proxy) confers no `moderate` / `takedown` / `review` duty. Before this cut it
/// did, through all five readers: [`reachable_under_scope`],
/// [`reachable_under_scope_with_reasons`], [`is_named_moderator`],
/// [`moderators_of`] / [`appointed_moderators_of`], and the write chokepoint
/// [`check_moderation_admission`].
///
/// The witness asserts TWO biconditionals at every state transition, not because
/// they are interesting on their own but because they are what makes a per-site
/// repair impossible to land silently — each spans a DIFFERENT pair of the three
/// walks that were three copies before [`scoped_delegation_reach`]:
///
///   * `is_named_moderator(k, …)` ⟺ `k ∈ moderators_of(…)` — the predicate
///     projection against the enumerating projection.
///   * `reachable_under_scope(…)` ⟺ `reachable_under_scope_with_reasons(…) ==
///     Reachable` — the predicate projection against the classifying one.
///
/// Together they pin all three former copies against each other. Repair one and
/// not the others and one of the two goes red; both failures are exercised as
/// mutations and recorded in the CHANGELOG.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod moderation_walk_liveness_test_support {
    use super::steward_liveness_test_support::{
        bare_edge_retraction, register, signed_row, store, withdraws_of,
    };
    use super::*;
    use crate::federation::tier_ingest::test_support::sign_community;
    use crate::federation::types::{attestation_type, consensus_protocol, identity_type};
    use crate::federation::types::{Community, CommunityMember};
    use crate::federation::{Attestation, FederationDirectory};
    use chrono::Utc;

    /// A `delegates_to(granter → recipient)` on the §11.10 moderation plane.
    /// Distinct from the steward witness's helper only in carrying an explicit
    /// `sub_delegation` flag — the §13.3 deputization gate the moderation walk
    /// enforces and the steward walk does not.
    fn moderation_edge(
        granter: &str,
        recipient: &str,
        scope: &[&str],
        subjects: &[&str],
        sub_delegation: bool,
    ) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut row = signed_row(
            granter,
            recipient,
            attestation_type::DELEGATES_TO,
            serde_json::json!({
                "id": id,
                "scope": scope.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
                "sub_delegation": sub_delegation,
            }),
        );
        row.subject_key_ids = subjects.iter().map(|s| (*s).to_owned()).collect();
        row
    }

    /// A `founder_only` commons rooted at a single steward-bound founder. The
    /// strict protocol is deliberate: under `founder_only` the community
    /// authority set and the founder set COINCIDE, so [`moderators_of`] and
    /// [`appointed_moderators_of`] must return the same list — the cheapest
    /// available pin on the "two root sets, one walk" invariant.
    async fn commons(dir: &dyn FederationDirectory, community: &str, founder: &str, suffix: &str) {
        let now = Utc::now();
        dir.put_community(sign_community(
            founder,
            Community {
                community_key_id: community.to_owned(),
                community_name: format!("moderation commons {suffix}"),
                members: vec![CommunityMember {
                    key_id: founder.to_owned(),
                    joined_at: now,
                    role: Some(MEMBER_ROLE_FOUNDER.to_owned()),
                }],
                founded_at: now,
                consensus_protocol: consensus_protocol::FOUNDER_ONLY.to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .expect("a founder-rooted commons is admissible");
    }

    /// **BICONDITIONAL 1** — the predicate walk against the enumerating walk.
    /// Returns the roster so the caller can assert membership directly.
    async fn assert_moderator_agreement(
        dir: &dyn FederationDirectory,
        community: &str,
        duty: &str,
        keys: &[&str],
        at: &str,
    ) -> Vec<String> {
        let roster = moderators_of(dir, community, duty)
            .await
            .expect("moderators_of");
        let appointed = appointed_moderators_of(dir, community, duty)
            .await
            .expect("appointed_moderators_of");
        assert_eq!(
            roster, appointed,
            "[{at}] under `founder_only` the authority set IS the founder set, so \
             moderators_of == appointed_moderators_of — the invariant `appointed_moderators_of` \
             states in prose (one reachability predicate, two root sets)"
        );
        for k in keys {
            let named = is_named_moderator(dir, k, community, duty)
                .await
                .expect("is_named_moderator");
            assert_eq!(
                named,
                roster.iter().any(|m| m == k),
                "[{at}] is_named_moderator({k}) <=> {k} ∈ moderators_of() — THE biconditional \
                 admission.rs states in prose over TWO different walks. named={named} \
                 roster={roster:?}"
            );
        }
        roster
    }

    /// **BICONDITIONAL 2** — the `bool` walk against the with-reasons walk.
    /// Returns the typed verdict so the caller can assert the classification.
    async fn assert_reach_agreement(
        dir: &dyn FederationDirectory,
        issuer: &str,
        target: &str,
        scope: &str,
        at: &str,
    ) -> ReachabilityVerdict {
        let flag =
            reachable_under_scope(dir, issuer, target, scope, MAX_MODERATION_DELEGATION_DEPTH)
                .await
                .expect("reachable_under_scope");
        let verdict = reachable_under_scope_with_reasons(
            dir,
            issuer,
            target,
            scope,
            MAX_MODERATION_DELEGATION_DEPTH,
        )
        .await
        .expect("reachable_under_scope_with_reasons");
        assert_eq!(
            flag,
            verdict == ReachabilityVerdict::Reachable,
            "[{at}] reachable_under_scope({issuer} -> {target}, {scope}) <=> \
             reachable_under_scope_with_reasons(..) == Reachable — the byte-identical claim \
             admission.rs makes over TWO different walks. flag={flag} verdict={verdict:?}"
        );
        verdict
    }

    /// The #593 behavioural witness. Run against every backend.
    #[allow(clippy::too_many_lines)]
    pub(crate) async fn exercise_moderation_walk_liveness(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        let duty = DELEGATION_SCOPE_MODERATE;
        let founder = format!("mw-founder-{suffix}");
        let deputy = format!("mw-deputy-{suffix}");
        let leaf = format!("mw-leaf-{suffix}");
        let community = format!("mw-commons-{suffix}");

        // The identity types are forced by the two `delegates_to` gates that
        // bracket the moderation plane, and getting them wrong makes the
        // fixture unstoreable rather than merely unrealistic:
        //   * the RECIPIENT of a duty edge may not be `user`-role — a
        //     `user → user` delegation is a steward-binding and CC 3.2 admits
        //     it only for a proven minor or an attested-incapacitated adult
        //     (`check_user_target_steward_binding_admission`);
        //   * nor `node`-only — CC 4.4.3.4.3 confines a node delegate to
        //     `infra:*` scopes, so a `moderate` edge to one is refused
        //     (`check_node_agency_admission`).
        // `primitive` is the shape the existing §11.11 fixtures use, and the
        // ROOT must be `user` because §11.11 requires a steward-bound authority.
        register(dir, &founder, &[identity_type::USER]).await;
        register(dir, &community, &[identity_type::USER]).await;
        for k in [&deputy, &leaf] {
            register(dir, k, &[identity_type::PRIMITIVE]).await;
        }
        commons(dir, &community, &founder, suffix).await;
        assert!(
            is_steward_bound(dir, &founder)
                .await
                .expect("is_steward_bound"),
            "the `user`-role founder self-anchors — §11.11 requires a steward-bound authority root"
        );

        // ── the live moderation chain ────────────────────────────────────
        // founder →(moderate, sub_delegation) deputy →(moderate) leaf.
        let e_fd = moderation_edge(&founder, &deputy, &[duty], &[&deputy], true);
        let e_dl = moderation_edge(&deputy, &leaf, &[duty], &[&leaf], false);
        store(dir, &e_fd).await.expect("founder -> deputy admitted");
        store(dir, &e_dl).await.expect("deputy -> leaf admitted");

        let roster = assert_moderator_agreement(
            dir,
            &community,
            duty,
            &[&founder, &deputy, &leaf],
            "live chain",
        )
        .await;
        assert_eq!(
            roster,
            {
                let mut want = vec![founder.clone(), deputy.clone(), leaf.clone()];
                want.sort();
                want
            },
            "the whole live chain is the named-moderator set"
        );
        assert_eq!(
            assert_reach_agreement(dir, &founder, &deputy, duty, "live chain").await,
            ReachabilityVerdict::Reachable
        );
        assert_eq!(
            assert_reach_agreement(dir, &founder, &leaf, duty, "live chain").await,
            ReachabilityVerdict::Reachable
        );
        for k in [&deputy, &leaf] {
            check_moderation_admission(
                dir,
                k,
                &std::iter::once(founder.clone()).collect(),
                duty,
                "content:deadbeef",
            )
            .await
            .expect("the write chokepoint admits a live delegated moderator");
        }

        // ── the SUBJECT revokes the founder → deputy edge ────────────────
        // CEG §3.2.3 rule 2. The edge's own granter never issued it — exactly
        // the row the granter-scoped fold cannot see.
        let revocation = withdraws_of(&deputy, &deputy, &e_fd.attestation_id);
        store(dir, &revocation)
            .await
            .expect("a rule-2 withdraws against the delegation must be ADMITTED");
        let stored = dir
            .get_attestation(&revocation.attestation_id)
            .await
            .expect("read")
            .expect("the withdraws is stored");
        assert_eq!(
            stored.withdraws_admission_rule,
            Some(2),
            "the fixture must exercise the rule-2 (non-granter) arm — if this is None the \
             withdraws was admitted unresolved and the witness proves nothing about authority"
        );

        // ── THE DEFECT (#593): everything downstream of a dead edge is dead ──
        let roster = assert_moderator_agreement(
            dir,
            &community,
            duty,
            &[&founder, &deputy, &leaf],
            "subject-revoked hop",
        )
        .await;
        assert_eq!(
            roster,
            vec![founder.clone()],
            "a delegates_to retracted by an admitted withdraws its granter never issued must NOT \
             confer a moderation duty — CIRISPersist#593, the third site of the fold #578 and \
             #584 each closed on their own plane. roster={roster:?}"
        );
        assert_eq!(
            assert_reach_agreement(dir, &founder, &deputy, duty, "subject-revoked hop").await,
            ReachabilityVerdict::RetractedAtRoot,
            "the retracted edge IS the edge to this target, so the with-reasons walk must name \
             the retraction — including the retraction the granter never issued"
        );
        assert_eq!(
            assert_reach_agreement(dir, &founder, &leaf, duty, "subject-revoked hop").await,
            ReachabilityVerdict::SignerUnreached,
            "the retracted edge is NOT the edge to `leaf`, so the classification is \
             SignerUnreached — the founder emitted delegation, and no live scoped path reaches"
        );
        for k in [&deputy, &leaf] {
            let err = check_moderation_admission(
                dir,
                k,
                &std::iter::once(founder.clone()).collect(),
                duty,
                "content:deadbeef",
            )
            .await
            .expect_err("the write chokepoint must refuse a dead delegated chain");
            assert_eq!(
                err.kind(),
                "federation_delegated_scope_unauthorized",
                "the refusal must be the §11.10 gate NAMING itself: {err}"
            );
        }

        // ── the granter-scoped arm is NOT subsumed ───────────────────────
        // A BARE §11.10 edge-retraction carries no `references_attestation_id`,
        // so the new incoming clause cannot see it. This step goes red if the
        // granter-scoped clause is ever deleted as redundant.
        let d2 = format!("mw-deputy2-{suffix}");
        let c2 = format!("mw-commons2-{suffix}");
        let f2 = format!("mw-founder2-{suffix}");
        for k in [&f2, &c2] {
            register(dir, k, &[identity_type::USER]).await;
        }
        register(dir, &d2, &[identity_type::PRIMITIVE]).await;
        commons(dir, &c2, &f2, suffix).await;
        store(dir, &moderation_edge(&f2, &d2, &[duty], &[], true))
            .await
            .expect("second chain admitted");
        assert_moderator_agreement(dir, &c2, duty, &[&f2, &d2], "second live chain").await;
        assert_eq!(
            assert_reach_agreement(dir, &f2, &d2, duty, "second live chain").await,
            ReachabilityVerdict::Reachable
        );
        store(dir, &bare_edge_retraction(&f2, &d2))
            .await
            .expect("the granter's own edge-retraction lands");
        assert_eq!(
            moderators_of(dir, &c2, duty).await.expect("moderators_of"),
            vec![f2.clone()],
            "the granter-scoped clause reads rows the incoming clause cannot see — it is not \
             subsumed and must not be deleted"
        );
        assert_eq!(
            assert_reach_agreement(dir, &f2, &d2, duty, "granter-retracted").await,
            ReachabilityVerdict::RetractedAtRoot
        );

        // ── a withdraws naming an ABSENT attestation is a decoy ──────────
        let d3 = format!("mw-deputy3-{suffix}");
        let c3 = format!("mw-commons3-{suffix}");
        let f3 = format!("mw-founder3-{suffix}");
        for k in [&f3, &c3] {
            register(dir, k, &[identity_type::USER]).await;
        }
        register(dir, &d3, &[identity_type::PRIMITIVE]).await;
        commons(dir, &c3, &f3, suffix).await;
        store(dir, &moderation_edge(&f3, &d3, &[duty], &[&d3], true))
            .await
            .expect("third chain admitted");
        store(
            dir,
            &withdraws_of(&d3, &d3, &uuid::Uuid::new_v4().to_string()),
        )
        .await
        .expect("a withdraws naming an absent target admits unresolved");
        assert_eq!(
            assert_moderator_agreement(dir, &c3, duty, &[&f3, &d3], "unrelated withdraws").await,
            {
                let mut want = vec![f3.clone(), d3.clone()];
                want.sort();
                want
            },
            "a withdraws that references some OTHER attestation must not fold this edge away"
        );

        // ── scope isolation is untouched ─────────────────────────────────
        assert_eq!(
            assert_reach_agreement(dir, &f3, &d3, DELEGATION_SCOPE_REVIEW, "scope isolation").await,
            ReachabilityVerdict::MissingScope,
            "a `moderate`-only chain still confers no `review` — the load-bearing scope-isolation \
             property (CIRISRegistry#90 'and only then')"
        );

        // ── THE CONSENT-REVOCATION PLANE — CIRISPersist#593's tripwire,
        //    RETARGETED by CIRISPersist#594 ───────────────────────────────
        //
        // #593 left this block asserting the DEFECT (the walk consulted no
        // retraction at all) with instructions to flip it rather than delete
        // it when #594 landed. This is that flip. It is still the tripwire:
        // narrow the retraction gates on this plane again and it goes red.
        //
        // **Each clause gets its OWN edge.** #593's version reused one edge
        // for both, which meant the granter-retraction assertion ran with the
        // subject's retraction already in place — so once the first clause
        // worked, the second would pass whether or not it was implemented.
        // Two clauses that read DIFFERENT rows need two fixtures, or the
        // weaker one is never actually under test.
        let cr_targets_of = |k: &String| -> std::collections::HashSet<String> {
            std::iter::once(k.clone()).collect()
        };

        // ── clause (a): the GRANTER retracts its own edge ────────────────
        // The #594 core. `bare_edge_retraction` carries NO
        // `references_attestation_id` — it is the §11.10 edge-retraction
        // shape, granter-against-recipient — so ONLY the granter-scoped gate
        // can see it. If that gate is dropped this goes red.
        let cr_from = format!("mw-cr-from-{suffix}");
        let cr_to = format!("mw-cr-to-{suffix}");
        register(dir, &cr_from, &[identity_type::USER]).await;
        register(dir, &cr_to, &[identity_type::PRIMITIVE]).await;
        let cr_edge = moderation_edge(
            &cr_from,
            &cr_to,
            &[DELEGATION_SCOPE_CONSENT_REVOCATION],
            &[&cr_to],
            true,
        );
        store(dir, &cr_edge).await.expect("cr edge admitted");
        let cr_targets = cr_targets_of(&cr_to);
        assert!(
            issuer_reaches_target_via_consent_revocation_delegation(
                dir,
                &cr_from,
                &cr_targets,
                MAX_WITHDRAWS_DELEGATION_DEPTH,
            )
            .await
            .expect("consent-revocation walk"),
            "the live consent-revocation edge confers proxy authority"
        );
        store(dir, &bare_edge_retraction(&cr_from, &cr_to))
            .await
            .expect("the granter's own edge-retraction lands");
        assert!(
            !issuer_reaches_target_via_consent_revocation_delegation(
                dir,
                &cr_from,
                &cr_targets,
                MAX_WITHDRAWS_DELEGATION_DEPTH,
            )
            .await
            .expect("consent-revocation walk"),
            "CIRISPersist#594: a `delegates_to` the GRANTER itself withdrew must stop conferring \
             rule-(3) proxy authority. Before #594 this plane consulted no retraction at all, so a \
             revoked proxy could still revoke consent on behalf of a subject who cannot hold a key \
             to object (CC 1.13.2). This is the assertion #593 asked to have flipped, not deleted"
        );

        // ── clause (b): the SUBJECT names the edge (CEG §3.2.3 rules 2/3/4)
        // A FRESH edge, so this is not satisfied by clause (a)'s retraction.
        // `withdraws_of` carries `references_attestation_id`, which the
        // granter-scoped gate structurally cannot see — the granter never
        // issued it. Only the #593 incoming-rows clause catches this one.
        let cr2_from = format!("mw-cr2-from-{suffix}");
        let cr2_to = format!("mw-cr2-to-{suffix}");
        register(dir, &cr2_from, &[identity_type::USER]).await;
        register(dir, &cr2_to, &[identity_type::PRIMITIVE]).await;
        let cr2_edge = moderation_edge(
            &cr2_from,
            &cr2_to,
            &[DELEGATION_SCOPE_CONSENT_REVOCATION],
            &[&cr2_to],
            true,
        );
        store(dir, &cr2_edge).await.expect("cr2 edge admitted");
        let cr2_targets = cr_targets_of(&cr2_to);
        assert!(
            issuer_reaches_target_via_consent_revocation_delegation(
                dir,
                &cr2_from,
                &cr2_targets,
                MAX_WITHDRAWS_DELEGATION_DEPTH,
            )
            .await
            .expect("consent-revocation walk"),
            "the live consent-revocation edge confers proxy authority"
        );
        store(
            dir,
            &withdraws_of(&cr2_to, &cr2_to, &cr2_edge.attestation_id),
        )
        .await
        .expect("the subject's rule-2 withdraws lands");
        assert!(
            !issuer_reaches_target_via_consent_revocation_delegation(
                dir,
                &cr2_from,
                &cr2_targets,
                MAX_WITHDRAWS_DELEGATION_DEPTH,
            )
            .await
            .expect("consent-revocation walk"),
            "CIRISPersist#594: the subject's own rule-2 retraction of the delegation naming it \
             must also stop conferring proxy authority. This is the #593 clause, now reaching this \
             plane too — the two gates read DIFFERENT rows, so neither subsumes the other"
        );

        // ── the answer to \"can the proxy path revoke itself?\", asserted
        //    rather than argued (CIRISPersist#594) ──────────────────────────
        // Rule-3 proxy authority IS a revocation mechanism, so honouring
        // retractions here raises a question the moderation plane never had:
        // can a proxy defend its own edge, or attack a rival's? The walk is
        // DIRECTED and an edge names its RECIPIENT as subject, so:
        //   * self-retraction is resignation — already covered by clause (b);
        //   * SIBLING proxies never reach each other, so one cannot revoke the
        //     other's edge by this path at all.
        // The sibling case is the one that would be a privilege escalation,
        // and it is structurally unreachable. Pinned so a future widening of
        // the walk (an up-walk, a fan-out read) cannot quietly create it.
        let sib_root = format!("mw-cr-sib-root-{suffix}");
        let sib_a = format!("mw-cr-sib-a-{suffix}");
        let sib_b = format!("mw-cr-sib-b-{suffix}");
        register(dir, &sib_root, &[identity_type::USER]).await;
        register(dir, &sib_a, &[identity_type::PRIMITIVE]).await;
        register(dir, &sib_b, &[identity_type::PRIMITIVE]).await;
        for peer in [&sib_a, &sib_b] {
            store(
                dir,
                &moderation_edge(
                    &sib_root,
                    peer,
                    &[DELEGATION_SCOPE_CONSENT_REVOCATION],
                    &[peer],
                    true,
                ),
            )
            .await
            .expect("sibling proxy edge admitted");
        }
        assert!(
            !issuer_reaches_target_via_consent_revocation_delegation(
                dir,
                &sib_a,
                &cr_targets_of(&sib_b),
                MAX_WITHDRAWS_DELEGATION_DEPTH,
            )
            .await
            .expect("consent-revocation walk"),
            "CIRISPersist#594: two proxies under one root must NOT reach each other. If they did, \
             either could file an admitted rule-(3) `withdraws` against the other's delegation and \
             become the sole proxy for a subject who cannot object — a privilege escalation the \
             directed walk is what prevents"
        );

        // ── GATE (a) IS RECIPIENT-SCOPED, NOT EDGE-SCOPED (CIRISPersist#594)
        //
        // A precision property that existed before this cut but only BOUND the
        // moderation plane; #594 makes it bind the consent plane too, so it is
        // pinned here rather than left to be discovered by an adopter.
        //
        // Gate (a) buckets a granter's retractions by `attested_key_id` alone.
        // It does NOT read `references_attestation_id`. So a granter who
        // retracts ONE scoped delegation to a recipient retracts EVERY edge to
        // that recipient, on every scope — even when the retraction names a
        // different edge by id.
        //
        // That is the §11.10 edge-retraction model ("the granter has retracted
        // this recipient"), and the over-broad direction is the SAFE one: it
        // withdraws more authority than named, never less. Narrowing it to be
        // edge-precise would LOOSEN the moderation plane as a side effect of a
        // consent-plane fix, which is not a trade this cut may make silently.
        // Recorded as behaviour + flagged as a follow-up, not changed here.
        let broad_g = format!("mw-cr-broad-g-{suffix}");
        let broad_p = format!("mw-cr-broad-p-{suffix}");
        register(dir, &broad_g, &[identity_type::USER]).await;
        register(dir, &broad_p, &[identity_type::PRIMITIVE]).await;
        let keep_edge = moderation_edge(
            &broad_g,
            &broad_p,
            &[DELEGATION_SCOPE_CONSENT_REVOCATION],
            &[&broad_p],
            true,
        );
        let other_edge = moderation_edge(
            &broad_g,
            &broad_p,
            &[DELEGATION_SCOPE_REVIEW],
            &[&broad_p],
            true,
        );
        store(dir, &keep_edge).await.expect("cr edge admitted");
        store(dir, &other_edge).await.expect("review edge admitted");
        let broad_targets = cr_targets_of(&broad_p);
        assert!(
            issuer_reaches_target_via_consent_revocation_delegation(
                dir,
                &broad_g,
                &broad_targets,
                MAX_WITHDRAWS_DELEGATION_DEPTH,
            )
            .await
            .expect("consent-revocation walk"),
            "both edges live — the consent_revocation one confers proxy authority"
        );
        // Retract ONLY the `review` edge, BY ID.
        store(
            dir,
            &withdraws_of(&broad_g, &broad_p, &other_edge.attestation_id),
        )
        .await
        .expect("the granter's targeted retraction lands");
        assert!(
            !issuer_reaches_target_via_consent_revocation_delegation(
                dir,
                &broad_g,
                &broad_targets,
                MAX_WITHDRAWS_DELEGATION_DEPTH,
            )
            .await
            .expect("consent-revocation walk"),
            "CIRISPersist#594, recorded rather than desired: gate (a) is keyed on the RECIPIENT, \
             so a granter's retraction naming ONE edge by id withdraws every edge to that \
             recipient — here a `review` retraction also killed the `consent_revocation` proxy. \
             Over-broad in the SAFE direction (less authority, never more). Narrowing it would \
             loosen the §11.10 moderation plane too, which #594 may not do as a side effect"
        );
    }

    /// **THE READ COST, MEASURED** (CIRISPersist#593) — and the short-circuit,
    /// proven rather than asserted.
    ///
    /// The new incoming-retraction clause costs a directory read the walk did
    /// not make before, and "≈2× reads, memoized per recipient" is a claim that
    /// has to be checked against a counter, not against an argument. This body
    /// pins four numbers on a `founder → deputy → leaf → tail` chain, using the
    /// memory backend's [`attestation_read_counts`] — a count of what the
    /// SUBSTRATE was asked for, external to the walk. The counts are properties
    /// of the shared walk, not of the backend: all three backends run this exact
    /// body and issue this exact sequence of calls.
    ///
    /// [`attestation_read_counts`]: crate::store::memory::MemoryBackend::attestation_read_counts
    pub(crate) async fn exercise_moderation_walk_read_cost(
        backend: &crate::store::memory::MemoryBackend,
        suffix: &str,
    ) {
        let duty = DELEGATION_SCOPE_MODERATE;
        let founder = format!("mc-founder-{suffix}");
        let deputy = format!("mc-deputy-{suffix}");
        let leaf = format!("mc-leaf-{suffix}");
        let tail = format!("mc-tail-{suffix}");
        register(backend, &founder, &[identity_type::USER]).await;
        for k in [&deputy, &leaf, &tail] {
            register(backend, k, &[identity_type::PRIMITIVE]).await;
        }
        for (g, r) in [(&founder, &deputy), (&deputy, &leaf), (&leaf, &tail)] {
            store(backend, &moderation_edge(g, r, &[duty], &[r], true))
                .await
                .expect("chain edge admitted");
        }

        // (1) THE COST. A three-hop probe reads the two granters on the path
        //     (as it always did) plus the two recipients whose edges survived
        //     every cheaper gate. Two reads became four: exactly the 2× ceiling
        //     the walk's doc claims, and NOT a per-hop fan-out.
        //
        //     The design this cut was built from estimated "3 reads → 5" for
        //     this chain. Measured, it is 2 → 4: the predicate stops at the
        //     edge INTO the target and never dequeues the target itself, so the
        //     pre-#593 walk read one fewer node than the estimate assumed.
        backend.reset_attestation_read_counts();
        assert!(
            reachable_under_scope(
                backend,
                &founder,
                &leaf,
                duty,
                MAX_MODERATION_DELEGATION_DEPTH
            )
            .await
            .expect("reachable_under_scope"),
            "the live chain reaches the leaf"
        );
        assert_eq!(
            backend.attestation_read_counts(),
            (2, 2),
            "(list_attestations_by, list_attestations_for) for a founder -> deputy -> leaf probe. \
             `by` is unchanged from before CIRISPersist#593 (one per DEQUEUED node: founder, \
             deputy); `for` is the new clause, one per DISTINCT SURVIVING RECIPIENT (deputy, \
             leaf). If `for` ever exceeds `by` on a simple chain the memo has stopped working"
        );

        // (2) THE SHORT-CIRCUIT SURVIVED THE EXTRACTION. A depth-1 target ends
        //     the walk at the first hit: the founder's out-rows are read, the
        //     deputy's are NOT, and neither leaf nor tail is ever touched.
        backend.reset_attestation_read_counts();
        assert!(
            reachable_under_scope(
                backend,
                &founder,
                &deputy,
                duty,
                MAX_MODERATION_DELEGATION_DEPTH
            )
            .await
            .expect("reachable_under_scope"),
            "the founder reaches the deputy directly"
        );
        assert_eq!(
            backend.attestation_read_counts(),
            (1, 1),
            "the predicate must RETURN at the first edge into `targets` — one granter read, one \
             recipient read, and no traversal past the hit. CIRISPersist#584 had to give its \
             up-walk's short-circuit away to make its readers agree; this extraction did not, \
             and this is the number that proves it"
        );

        // (3) …and the SAME body still enumerates exhaustively, because the
        //     enumerating caller passes an EMPTY `targets` that no edge can be
        //     in. Four granter reads (every node), three recipient reads.
        backend.reset_attestation_read_counts();
        let reach = enumerate_scoped_delegation_reach(
            backend,
            &founder,
            duty,
            MAX_MODERATION_DELEGATION_DEPTH,
            DelegationWalkPolicy::MODERATION_DUTY,
        )
        .await
        .expect("enumerate_scoped_delegation_reach");
        let mut reach: Vec<String> = reach.into_iter().collect();
        reach.sort();
        assert_eq!(
            reach,
            {
                let mut want = vec![deputy.clone(), leaf.clone(), tail.clone()];
                want.sort();
                want
            },
            "empty targets ⇒ no short-circuit ⇒ full enumeration from the predicate's own body"
        );
        assert_eq!(
            backend.attestation_read_counts(),
            (4, 3),
            "the enumerating projection walks the whole chain — 4 dequeued nodes, 3 distinct \
             recipients. The contrast with (2) IS the short-circuit"
        );

        // (4) THE MEMO IS KEYED ON THE RECIPIENT, NOT THE EDGE. Five parallel
        //     `moderate` edges from one granter to one deputy cost ONE incoming
        //     read, so the fan-out is bounded by distinct recipients and can
        //     never be bounded by edges.
        let f4 = format!("mc-fan-founder-{suffix}");
        let d4 = format!("mc-fan-deputy-{suffix}");
        register(backend, &f4, &[identity_type::USER]).await;
        register(backend, &d4, &[identity_type::PRIMITIVE]).await;
        for _ in 0..5 {
            store(backend, &moderation_edge(&f4, &d4, &[duty], &[&d4], true))
                .await
                .expect("parallel edge admitted");
        }
        backend.reset_attestation_read_counts();
        assert!(
            !reachable_under_scope(
                backend,
                &f4,
                &format!("mc-absent-{suffix}"),
                duty,
                MAX_MODERATION_DELEGATION_DEPTH
            )
            .await
            .expect("reachable_under_scope"),
            "the probe target is not in the graph, so the walk runs to exhaustion"
        );
        assert_eq!(
            backend.attestation_read_counts(),
            (2, 1),
            "5 edges, ONE distinct recipient, ONE incoming read — memoized per recipient for the \
             whole walk. Key the memo on the granter instead and this becomes 5"
        );

        // (5) THE CIRISPersist#594 COST — the consent-revocation plane, which
        //     paid NEITHER gate before this cut.
        //
        //     #593 measured the moderation plane, where the granter-scoped gate
        //     already ran and only the incoming clause was new. On this plane
        //     BOTH gates are new, so the honest before/after is 1× → 2×, not
        //     the moderation plane's already-1.5×. Measured rather than
        //     reasoned, because "the walk is shallow so it does not matter" is
        //     exactly the kind of claim that is true until a deployment makes
        //     it false.
        //
        //     The shape is a rule-(3) probe: a proxy chain from an issuer to a
        //     keyless subject. Same numbers as (1) — which is the point. The
        //     consent plane now costs precisely what the moderation plane
        //     costs, because it now runs precisely the same gates.
        let cr_iss = format!("mc-cr-issuer-{suffix}");
        let cr_mid = format!("mc-cr-mid-{suffix}");
        let cr_sub = format!("mc-cr-subject-{suffix}");
        register(backend, &cr_iss, &[identity_type::USER]).await;
        for k in [&cr_mid, &cr_sub] {
            register(backend, k, &[identity_type::PRIMITIVE]).await;
        }
        for (g, r) in [(&cr_iss, &cr_mid), (&cr_mid, &cr_sub)] {
            store(
                backend,
                &moderation_edge(g, r, &[DELEGATION_SCOPE_CONSENT_REVOCATION], &[r], true),
            )
            .await
            .expect("proxy chain edge admitted");
        }
        backend.reset_attestation_read_counts();
        let cr_targets: std::collections::HashSet<String> =
            std::iter::once(cr_sub.clone()).collect();
        assert!(
            issuer_reaches_target_via_consent_revocation_delegation(
                backend,
                &cr_iss,
                &cr_targets,
                MAX_WITHDRAWS_DELEGATION_DEPTH,
            )
            .await
            .expect("consent-revocation walk"),
            "the live proxy chain reaches the keyless subject"
        );
        assert_eq!(
            backend.attestation_read_counts(),
            (2, 2),
            "CIRISPersist#594's measured cost on the consent-revocation plane: a two-hop rule-(3) \
             probe reads 2 granters (unchanged — one per dequeued node) and 2 recipients (BOTH \
             new; this plane previously read none). So 2 reads became 4 — the same 2× ceiling the \
             walk's doc claims, and identical to the moderation plane's (1) because the two planes \
             now run the same gates. A `for` count above `by` here means the memo is not shared \
             across the walk"
        );
    }

    /// v30.8.0 (CIRISPersist#628) — the same edge, carrying a re-delegation
    /// BUDGET: how many further hops the recipient's chain may run.
    fn moderation_edge_bounded(
        granter: &str,
        recipient: &str,
        scope: &[&str],
        subjects: &[&str],
        sub_delegation: bool,
        depth: usize,
    ) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut row = signed_row(
            granter,
            recipient,
            attestation_type::DELEGATES_TO,
            serde_json::json!({
                "id": id,
                "scope": scope.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
                "sub_delegation": sub_delegation,
                "sub_delegation_depth": depth,
            }),
        );
        row.subject_key_ids = subjects.iter().map(|s| (*s).to_owned()).collect();
        row
    }

    /// v30.8.0 (CIRISPersist#628) — **a re-delegation budget bounds the chain,
    /// and it attenuates.**
    ///
    /// The governance need (CIRISServer#383): an accord quorum delegating a
    /// moderation duty to a named human must be able to say *"you, and one
    /// deputy"* rather than only "you, and anyone, sixteen deep".
    ///
    /// # The semantics, stated because I got them wrong first
    ///
    /// `sub_delegation_depth: N` on edge A→B means **B's chain may run N
    /// further hops**, matching #628's wording (*"1 = may pass it on once; that
    /// holder may not"*). So on `founder →(depth 1) deputy → leaf → tail`, the
    /// LEAF is reachable — the deputy spent its one hop — and the TAIL is not.
    /// My first witness asserted the leaf was unreachable, which would have made
    /// `depth: 1` mean the same as `sub_delegation: false` and left the field
    /// unable to express the one case the issue actually asked for.
    ///
    /// Four legs, each killing a different wrong implementation:
    ///  1. the deputy is reached — else the field breaks delegation outright;
    ///  2. the leaf is reached — `depth 1` really does buy one hop;
    ///  3. the tail is NOT — the bound bites. **The dye test**;
    ///  4. attenuation — a holder with no allowance left cannot declare 5 and
    ///     resurrect the chain. Without it the field is advisory.
    pub(crate) async fn exercise_sub_delegation_budget(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        let duty = DELEGATION_SCOPE_MODERATE;
        let founder = format!("bud-founder-{suffix}");
        let deputy = format!("bud-deputy-{suffix}");
        let leaf = format!("bud-leaf-{suffix}");
        let tail = format!("bud-tail-{suffix}");
        // Chain members are `primitive`, not `user`: a `user` target needs an
        // age-verified steward binding, a different gate than this is about.
        register(dir, &founder, &[identity_type::USER]).await;
        for k in [&deputy, &leaf, &tail] {
            register(dir, k, &[identity_type::PRIMITIVE]).await;
        }

        store(
            dir,
            &moderation_edge_bounded(&founder, &deputy, &[duty], &[&deputy], true, 1),
        )
        .await
        .expect("founder -> deputy admitted");
        store(
            dir,
            &moderation_edge(&deputy, &leaf, &[duty], &[&leaf], true),
        )
        .await
        .expect("deputy -> leaf admitted");
        store(dir, &moderation_edge(&leaf, &tail, &[duty], &[&tail], true))
            .await
            .expect("leaf -> tail admitted");

        let reach = async |t: &str| -> bool {
            reachable_under_scope(dir, &founder, t, duty, MAX_MODERATION_DELEGATION_DEPTH)
                .await
                .expect("walk")
        };

        assert!(
            reach(&deputy).await,
            "the direct recipient must be reached — otherwise the field is not a bound, it is a \
             break"
        );
        assert!(
            reach(&leaf).await,
            "depth 1 means the deputy MAY pass it on once, so the leaf is reachable. If this \
             fails, `depth: 1` collapses into `sub_delegation: false` and cannot express the one \
             case CIRISPersist#628 asked for"
        );
        assert!(
            !reach(&tail).await,
            "budget 1 must NOT reach three hops out. This is CIRISPersist#628: without it, \
             granting a scope grants the right to pass it on, sixteen deep, with no way to say \
             otherwise"
        );
        // ── (4) ATTENUATION, on a SEPARATE chain ─────────────────────────
        //
        // This needs its own chain, and the reason is worth recording: my first
        // version hung the attenuation leg off the chain above, where the
        // over-declaring holder's allowance was ALREADY 0. The budget-spent
        // guard refused it before the attenuation arithmetic ever ran, so the
        // leg passed for the wrong reason — a mutation that deleted attenuation
        // entirely left all four legs green. Caught by mutation testing, not by
        // reading it.
        //
        // Here the over-declaring holder still HAS allowance, so the guard does
        // not fire and only attenuation can produce the refusal:
        //   f2 →(depth 2) d2 →(declares 9!) l2 → t2 → x2
        // With attenuation  d2=2, l2=min(9,1)=1, t2=min(-,0)=0 → x2 UNREACHABLE.
        // Without it        d2=2, l2=9,         t2=min(-,8)=8 → x2 reachable.
        let f2 = format!("att-f-{suffix}");
        let d2 = format!("att-d-{suffix}");
        let l2 = format!("att-l-{suffix}");
        let t2 = format!("att-t-{suffix}");
        let x2 = format!("att-x-{suffix}");
        register(dir, &f2, &[identity_type::USER]).await;
        for k in [&d2, &l2, &t2, &x2] {
            register(dir, k, &[identity_type::PRIMITIVE]).await;
        }
        store(
            dir,
            &moderation_edge_bounded(&f2, &d2, &[duty], &[&d2], true, 2),
        )
        .await
        .expect("f2 -> d2 admitted");
        // d2 declares NINE, far beyond the 1 it has left to give.
        store(
            dir,
            &moderation_edge_bounded(&d2, &l2, &[duty], &[&l2], true, 9),
        )
        .await
        .expect("d2 -> l2 admitted (the WRITE is not gated; the WALK is)");
        store(dir, &moderation_edge(&l2, &t2, &[duty], &[&t2], true))
            .await
            .expect("l2 -> t2 admitted");
        store(dir, &moderation_edge(&t2, &x2, &[duty], &[&x2], true))
            .await
            .expect("t2 -> x2 admitted");

        let reach2 = async |t: &str| -> bool {
            reachable_under_scope(dir, &f2, t, duty, MAX_MODERATION_DELEGATION_DEPTH)
                .await
                .expect("walk")
        };
        assert!(
            reach2(&t2).await,
            "depth 2 must reach two hops past the deputy — otherwise this chain proves nothing \
             about attenuation, only that it is short"
        );
        assert!(
            !reach2(&x2).await,
            "a holder given 2 hops declared 9 and must not get them: the budget attenuates \
             exactly as scope does. Without this the field is advisory — any holder could restore \
             an unbounded chain by writing a bigger number than its issuer allowed"
        );
    }

    /// v30.8.0 — **the CHARTER SCOPE does not bound what a root may confer**
    /// (CIRISServer#383 / CIRISPersist#628).
    ///
    /// # Why this witness exists, and what it corrected
    ///
    /// I advised the operator that `humanity-accord`'s charter had to be
    /// re-minted carrying the four moderation scopes, on the reasoning that
    /// `⊆`-parent attenuation means a family can only delegate what it holds —
    /// so no charter scope ⇒ no quorum could ever confer `slash`, and that would
    /// need a **new genesis ceremony**.
    ///
    /// **That was wrong**, and this witness is what proved it. `⊆`-parent
    /// attenuation belongs to the MODERATION walk
    /// (`enforce_attenuation_and_sub_delegation` in `scoped_delegation_reach`).
    /// The CAPABILITY plane — `capability_roots_to_trusted_root` — is
    /// single-hop: it finds a `trust:confers:v1` edge about the subject, then
    /// asks only whether this node trusts the granter as a ROOT. `trust_root_valid`
    /// checks the charter's AND-minimum (`infra:serve` + `infra:attest`) and
    /// nothing about the conferred scope.
    ///
    /// So the charter answers *"is this a root at all"*, never *"what may it
    /// confer"* — which is why `trust_root.rs` calls extra charter scopes merely
    /// *"tolerated"*. The node's lever is whether to accept the root, not a
    /// per-scope allowlist.
    ///
    /// The operational consequence is the whole point: **an existing accord can
    /// confer `slash` with the charter it already has.** No re-mint, no ceremony.
    ///
    /// Four legs. Note the charter here carries the BARE minimum on purpose:
    ///
    ///  1. a bare-minimum charter is a valid trust root;
    ///  2. that root confers `slash` — a scope its charter never mentions;
    ///  3. the walk resolves it, so the human really holds the duty;
    ///  4. a scope with NO conferral row does not resolve — the discriminator is
    ///     the conferral, not the charter, and without this leg 2 could be read
    ///     as "everything resolves".
    pub(crate) async fn exercise_moderation_charter_rehearsal(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::trust_root::{
            capability_roots_to_trusted_root, pre_rotation_commitment, trust_root_valid,
            TRUST_ACCEPTS_DIMENSION, TRUST_CHARTER_DIMENSION, TRUST_CONFERS_DIMENSION,
        };
        let node = format!("reh-node-{suffix}");
        let root = format!("reh-root-{suffix}");
        let human = format!("reh-human-{suffix}");
        for k in [&node, &root, &human] {
            crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
        }

        // The charter the ceremony will actually mint: the RC3 AND-minimum plus
        // the full moderation vocabulary.
        // DELIBERATELY the bare AND-minimum, NOT the moderation scopes. See the
        // doc above: this witness exists to prove the charter's scope does not
        // bound what the root may confer.
        let charter_scope = vec!["infra:serve".to_owned(), "infra:attest".to_owned()];
        let uid =
            |n: &str| uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, n.as_bytes()).to_string();
        let now = chrono::Utc::now();
        let rows: [(String, &str, &str, &str, serde_json::Value); 3] = [
            (
                uid(&format!("reh-charter-{root}")),
                &root,
                &root,
                TRUST_CHARTER_DIMENSION,
                serde_json::json!({
                    "dimension": TRUST_CHARTER_DIMENSION,
                    "scope": charter_scope,
                    "pre_rotation_commitment":
                        pre_rotation_commitment(&[format!("{root}-successor")]).expect("commitment"),
                }),
            ),
            (
                uid(&format!("reh-accept-{node}-{root}")),
                &node,
                &root,
                TRUST_ACCEPTS_DIMENSION,
                serde_json::json!({ "dimension": TRUST_ACCEPTS_DIMENSION }),
            ),
            (
                uid(&format!("reh-confer-{root}-{human}")),
                &root,
                &human,
                TRUST_CONFERS_DIMENSION,
                serde_json::json!({
                    "dimension": TRUST_CONFERS_DIMENSION,
                    "scope": [DELEGATION_SCOPE_SLASH],
                }),
            ),
        ];
        for (id, by, about, dim, env) in rows {
            let (och, sc, sp) =
                crate::federation::tier_ingest::test_support::sign_envelope(by, &env);
            let att = Attestation {
                attestation_id: id,
                attesting_key_id: by.to_owned(),
                attested_key_id: about.to_owned(),
                attestation_type: crate::federation::types::attestation_type::DELEGATES_TO
                    .to_owned(),
                weight: None,
                asserted_at: now,
                expires_at: None,
                attestation_envelope: env,
                original_content_hash: och,
                scrub_signature_classical: sc,
                scrub_signature_pqc: sp,
                scrub_key_id: by.to_owned(),
                scrub_timestamp: now,
                pqc_completed_at: Some(now),
                persist_row_hash: String::new(),
                subject_key_ids: Vec::new(),
                withdraws_admission_rule: None,
                cohort_scope: crate::federation::types::cohort_scope::FEDERATION.to_owned(),
                tier: crate::federation::types::attestation_tier::FEDERATION.to_owned(),
                promoted_at: None,
                additional_scrubs: Vec::new(),
            };
            dir.put_attestation(crate::federation::SignedAttestation { attestation: att })
                .await
                .unwrap_or_else(|e| panic!("{dim} row must admit: {e}"));
        }

        // (1) the charter is a valid trust root DESPITE carrying moderation scopes.
        let verdict = trust_root_valid(dir, &node, &root).await.expect("walk");
        assert!(
            verdict.valid,
            "the bare AND-minimum charter must be a valid trust root"
        );

        // (2) + (3) the root can confer `slash`, and the walk resolves it.
        let granted = capability_roots_to_trusted_root(dir, &node, &human, DELEGATION_SCOPE_SLASH)
            .await
            .expect("resolve");
        assert!(
            granted.is_some(),
            "a trusted root must be able to confer `slash` even though its charter never mentions \
             it — the charter's AND-minimum answers 'is this a root', not 'what may it confer'. \
             If this ever fails, an existing accord can no longer delegate moderation duties \
             without a NEW GENESIS CEREMONY, which is exactly the cost this witness exists to \
             keep from being paid by surprise"
        );

        // (4) a scope the charter does NOT carry is still refused.
        let ungranted = capability_roots_to_trusted_root(
            dir,
            &node,
            &human,
            crate::federation::types::delegation_scope::INFRA_DETECT,
        )
        .await
        .expect("resolve");
        assert!(
            ungranted.is_none(),
            "a scope neither chartered nor conferred must NOT resolve — otherwise leg 1 proves \
             tolerance of anything, not tolerance of extra CHARTER scopes"
        );
    }

    /// v30.8.0 (CIRISConstitution#87) — **conferral is not stewardship, and the
    /// gate and the fold say so together.**
    ///
    /// CC 3.2 rc3 ruled on the discriminator: an act the target must accept for
    /// itself cannot be custody of the target. Stewardship is custody over a key
    /// that cannot accept for itself; a capability conferral is a consensual
    /// grant.
    ///
    /// Four legs, and the two REFUSAL legs are what keep this from being a hole:
    ///
    ///  1. a capability conferral on an age-UNVERIFIED adult human is ADMITTED —
    ///     the case that was refused `target_age_unverified` and blocked
    ///     delegating moderation duties to people;
    ///  2. an OWNER-BINDING on that same human is still REFUSED — CC 3.2 /
    ///     CC 1.15.6 survive untouched; steward-binding an adult stays forbidden;
    ///  3. the fold does NOT count the conferral as stewardship;
    ///  4. the fold DOES still count an owner-binding.
    ///
    /// Legs 3 and 4 are the paired half. Without them the gate could narrow while
    /// the fold kept counting conferrals, and a grant would silently establish a
    /// stewardship relation the gate had just refused — CIRISPersist#541's
    /// two-lists-that-disagree, on a constitutional rule.
    pub(crate) async fn exercise_conferral_is_not_stewardship(
        dir: &dyn FederationDirectory,
        suffix: &str,
    ) {
        use crate::federation::types::owner_binding;
        let root = format!("cns-root-{suffix}");
        let human = format!("cns-human-{suffix}");
        let owner = format!("cns-owner-{suffix}");
        // A `user` with NO age attestation — the exact band (`Unknown`) that was
        // refused, and the ordinary state of a human moderator.
        register(dir, &human, &[identity_type::USER]).await;
        register(dir, &owner, &[identity_type::USER]).await;
        // The conferral granter is USER-role ON PURPOSE. `live_delegation_granters`
        // only ever returns user-role granters, so a non-user granter makes leg 3
        // vacuous — it would pass whatever filter the fold used. Mutation testing
        // caught exactly that: reverting the fold to `AnyDelegation` left all four
        // legs green until this key became a `user`.
        register(dir, &root, &[identity_type::USER]).await;

        // ── (1) the CONFERRAL is admitted ────────────────────────────────
        let conferral = moderation_edge(&root, &human, &[DELEGATION_SCOPE_SLASH], &[&human], true);
        store(dir, &conferral).await.unwrap_or_else(|e| {
            panic!(
                "a capability conferral on an age-unverified human must be ADMITTED — this is \
                 CIRISConstitution#87: giving a person a job is not owning them. Got: {e}"
            )
        });

        // ── (2) the OWNER-BINDING is still refused ───────────────────────
        let binding = signed_row(
            &owner,
            &human,
            attestation_type::DELEGATES_TO,
            serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "scope": [DELEGATION_SCOPE_SLASH],
                "delegation_purpose": owner_binding::CC_DELEGATION_PURPOSE,
            }),
        );
        let err = store(dir, &binding).await.expect_err(
            "steward-binding an age-unverified adult must STILL be refused — CC 3.2 / CC 1.15.6 \
             are untouched by CIRISConstitution#87, and if this ever admits the ruling has been \
             read as a licence rather than a distinction",
        );
        assert_eq!(
            err.kind(),
            "federation_user_target_steward_binding_forbidden",
            "must be refused by the CC 3.2 gate specifically, not incidentally elsewhere: {err}"
        );

        // ── (3) the FOLD does not count the conferral ────────────────────
        let bound = steward_bindings_of(dir, &human).await.expect("fold");
        assert!(
            !bound.contains(&root),
            "the conferral granter must NOT appear as a steward of the human — the fold half of \
             the paired narrowing. If it does, a conferral silently establishes the custody the \
             gate just refused"
        );

        // ── (4) the FOLD still counts a real owner-binding ───────────────
        let target = format!("cns-node-{suffix}");
        register(dir, &target, &[identity_type::NODE]).await;
        let real = signed_row(
            &owner,
            &target,
            attestation_type::DELEGATES_TO,
            serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "scope": [crate::federation::types::delegation_scope::INFRA_SERVE],
                "delegation_purpose": owner_binding::CC_DELEGATION_PURPOSE,
            }),
        );
        store(dir, &real)
            .await
            .expect("owner-binding a node admits");
        let bound = steward_bindings_of(dir, &target).await.expect("fold");
        assert!(
            bound.contains(&owner),
            "a real owner-binding MUST still register as stewardship — otherwise the narrowing \
             emptied the fold instead of focusing it, and leg 3 proves nothing"
        );
    }

    /// v30.10.0 (CIRISPersist#632) — **a federation-scope act resolves its
    /// duty-holders from the accord roster.**
    ///
    /// De-admitting a key admitted to the FEDERATION is neither content nor
    /// community moderation, so before this the caller got an empty holder set
    /// and the emission could never be admitted — an unreachable surface, not a
    /// policy refusal (CIRISServer#383: 61 exposed keys, no expressible act).
    ///
    /// Three legs:
    ///
    ///  1. an unresolvable accord family is a typed REFUSAL, not `Ok(empty)`.
    ///     This is the leg that matters most: empty-set-as-refusal is the exact
    ///     shape that let `tier_4_deadmit` pass for years while reading absence
    ///     of evidence as evidence of authority. A node that cannot see the
    ///     accord must SAY so, not silently conclude nobody may act.
    ///  2. with the accord seeded, the roster resolves and is NON-EMPTY —
    ///     without this, leg 1 passes for a resolver that always errors.
    ///  3. the holders are the accord's own members, and are NOT filtered by
    ///     `is_steward_bound`. Copying the community resolver's filter would
    ///     return empty, because accord holders are `accord_holder`-role and
    ///     `steward_bindings_of` clause (1) self-anchors only `user`-role keys.
    ///     `accord_holder` is HardwareAttested — strictly stronger than the
    ///     steward-bound heuristic, so the filter is a category error here.
    pub(crate) async fn exercise_federation_duty_holders(
        dir: &dyn FederationDirectory,
        _suffix: &str,
    ) {
        use crate::federation::admission::duty_holders_for_federation;
        use crate::federation::admission::DELEGATION_SCOPE_SLASH;

        // (1) no accord seeded yet ⇒ typed refusal, never an empty set.
        let err = duty_holders_for_federation(dir, DELEGATION_SCOPE_SLASH)
            .await
            .expect_err(
                "an unresolvable accord roster MUST refuse, not return an empty holder set — \
                 empty-set-as-refusal is the absent-⇒-admit shape inverted, and it is what let \
                 tier_4_deadmit pass while reading absence of evidence as evidence of authority",
            );
        assert_eq!(
            err.kind(),
            "federation_invalid_argument",
            "the refusal must be typed and name what could not be resolved: {err}"
        );

        // Seed the accord FAMILY. Holders are seeded by each backend leg before
        // calling (it is a concrete method, not a trait one), which is also what
        // keeps leg 1 honest: holders present, family absent, so the refusal is
        // about the roster and not about an empty directory.
        crate::federation::genesis::seed_accord_family(dir)
            .await
            .expect("accord family seeds");

        // (2) + (3) the roster resolves, is non-empty, and is the accord's own
        // members — unfiltered by steward-binding.
        let got = duty_holders_for_federation(dir, DELEGATION_SCOPE_SLASH)
            .await
            .expect("the accord roster resolves once seeded");
        assert!(
            !got.is_empty(),
            "the seeded accord roster must be NON-EMPTY — otherwise leg 1 proves only that this \
             resolver always errors, and the federation scope stays unreachable"
        );
        // ── (4) THE GATE reaches the resolver ────────────────────────────
        //
        // Legs 1-3 prove the resolver works. They do NOT prove anything CALLS it:
        // a mutation disabling the scope selection in
        // `check_quarantine_admission` left all three green. That is the leg
        // CIRISServer actually depends on — their tier-4 deadmit names no
        // community, so it is the empty-`community_id` branch or nothing.
        //
        // An accord holder emitting a federation-scope `quarantine:*` row must
        // now be admitted as-self. Before #632 this was unreachable: the gate
        // hardcoded the community resolver, `community_id == ""` yielded an empty
        // holder set, and no signer could ever satisfy it.
        let holder = got.iter().next().expect("roster is non-empty").clone();
        let row = signed_row(
            &holder,
            &holder,
            attestation_type::SCORES,
            serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "dimension": "quarantine:deadmit:v1",
                // NO community_id — this is the federation scope.
            }),
        );
        check_delegated_duty_scores_admission(dir, &row)
            .await
            .unwrap_or_else(|e| {
                panic!(
                    "an accord holder must be able to emit a FEDERATION-scope quarantine row \
                     as-self. If this refuses, the gate is not reaching \
                     duty_holders_for_federation and CIRISServer#383's 61 keys stay \
                     unactionable: {e}"
                )
            });

        for h in &got {
            assert!(
                !is_steward_bound(dir, h).await.expect("steward check"),
                "accord holder {h:?} is steward-bound, which means this witness can no longer \
                 tell whether the resolver filters. The whole point is that it must NOT: holders \
                 are accord_holder-role, HardwareAttested, and filtering them returns empty"
            );
        }
    }
}
