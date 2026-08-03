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
///   (CC 3.4.8) ARE gated here (v12.7.0, CIRISPersist#366): they are
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
    let trusted_publisher = identity_type::TRUSTED_PUBLISHER.to_owned();
    let lenscore_detector = identity_type::LENSCORE_DETECTOR.to_owned();
    vec![
        ReservedPrefixRule {
            pattern_prefix: "system:".into(),
            required_identity_types: vec![substrate_persist.clone()],
        },
        ReservedPrefixRule {
            pattern_prefix: "audit_chain:".into(),
            required_identity_types: vec![substrate_persist.clone()],
        },
        ReservedPrefixRule {
            pattern_prefix: "corpus_health:".into(),
            required_identity_types: vec![substrate_persist.clone()],
        },
        ReservedPrefixRule {
            pattern_prefix: "identity_continuity:".into(),
            required_identity_types: vec![substrate_persist.clone()],
        },
        ReservedPrefixRule {
            pattern_prefix: "federation_directory:".into(),
            required_identity_types: vec![substrate_persist.clone()],
        },
        ReservedPrefixRule {
            pattern_prefix: "transparency_log:cosigned:".into(),
            required_identity_types: vec![witness.clone()],
        },
        // CEG 0.3 §5.6.8.3 + §11.5.3 — four new reserved-prefix
        // families added for media-sharing admission.
        //
        // - content_rating:{scheme}:{rating} → emitted by trusted_publisher
        //   (publisher-curated content ratings per Policy J).
        // - content_class:{class} → emitted by substrate_persist.
        // - cw_class:{class} → emitted by substrate_persist
        //   (content-warning class).
        // - age_assurance:{level} → emitted by witness (a registered
        //   age-assurance provider).
        ReservedPrefixRule {
            pattern_prefix: "content_rating:".into(),
            required_identity_types: vec![trusted_publisher],
        },
        ReservedPrefixRule {
            pattern_prefix: "content_class:".into(),
            required_identity_types: vec![substrate_persist.clone()],
        },
        ReservedPrefixRule {
            pattern_prefix: "cw_class:".into(),
            required_identity_types: vec![substrate_persist],
        },
        ReservedPrefixRule {
            pattern_prefix: "age_assurance:".into(),
            required_identity_types: vec![witness.clone()],
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
        },
        // v12.7.0 (CIRISPersist#366, CC 3.4.8) — the detector-only
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
        },
        ReservedPrefixRule {
            pattern_prefix: "detection:distributive:access:".into(),
            required_identity_types: vec![lenscore_detector.clone()],
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
        },
    ]
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

/// True iff `dim` matches the deprecated CEG 0.1 attestation-ladder
/// shape `attestation:l<N>:<mechanism>`, where `<N>` is one or more
/// ASCII digits and `<mechanism>` is any non-empty suffix. CEG 0.2
/// §13.1 records this as a deprecated wire shape; persist admits it
/// during the 0.1 → 0.2 transition window (see
/// [`AttestationLadderTransitionPolicy`]).
fn is_deprecated_attestation_ladder_prefix(dim: &str) -> bool {
    let Some(rest) = dim.strip_prefix("attestation:l") else {
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

/// v13.2.1 (CIRISPersist#378) — is this `delegates_to` envelope an
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
    // (1) capacity:* — never local (anti-Goodhart §7.5 / AV-62).
    if dimension.is_some_and(|d| d.starts_with("capacity:")) {
        return Err(Error::InvalidArgument(
            "capacity:* attestations are ineligible for the local tier (CEG §7.5 \
             anti-Goodhart, AV-62): capacity is third-party-attested — federation-tier, \
             signed, attesting_key_id != attested_key_id"
                .to_string(),
        ));
    }
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
///      `content_hash` a `"sha256:"`-prefixed string, positive integer
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
                Some(h) if h.starts_with("sha256:") && h.len() > "sha256:".len() => {}
                _ => {
                    return refuse(
                        "trace:* manifest form: \"content_hash\" must be a \
                         \"sha256:\"-prefixed string"
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
/// verify itself calls the split **"a proposal from the measuring side, not a
/// ruling"**. Verify knows what each dimension IS; the Constitution decides
/// what the substrate does about it. So this predicate reads the floor, not
/// the measuring side — and [`tests::verify_dimension_registry_is_the_only_enumeration`]
/// is the adjudication record that keeps the two visible to each other, going
/// red if EITHER moves.
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
///   nothing to bind to yet. This arm is LOAD-BEARING, not redundant, and the
///   distinction matters: [`check_local_tier_eligibility`] does declare
///   `capacity:*` ineligible for the local tier, but it runs ONLY on
///   `attestation_insert_local` / `attestation_upsert_local` — **not on
///   `put_attestation`**, which accepts a `tier = "local"` row on every
///   backend (the `substrate_machine` alphabet draws `Tier::Local` against
///   every family and those rows admit). So the local-tier `capacity:*` row
///   is reachable here, and this arm is what lets it through.
///
///   The residual is therefore real and named rather than papered over, and it
///   is tracked as **CIRISPersist#589**: a local-tier `capacity:*` row written
///   via `put_attestation` and then `attestation_promote`d becomes a
///   federation-tier `capacity:*` row that never faced this gate. That is the
///   PROMOTE path's pre-existing shape —
///   it re-signs and flips `tier` without re-running ANY tier-4 put-gate, so
///   it equally bypasses AV-45, AV-77 and the moderation gates — but note the
///   asymmetry with this gate's own sibling: [`check_capacity_not_self_attested`]
///   is NOT tier-gated, so self-emission is caught on a local row and missing
///   consent is not. Closing it belongs at the chokepoint (either
///   `put_attestation` enforcing [`check_local_tier_eligibility`], or promote
///   re-running the tier-4 stack), not by widening this gate to refuse
///   local-tier rows with a "no consent" message when the accurate refusal is
///   "capacity is never local".
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
    if row.tier != super::types::attestation_tier::FEDERATION {
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

pub(crate) fn delegation_scope_set(
    envelope: &serde_json::Value,
) -> std::collections::HashSet<String> {
    match envelope.get("scope") {
        Some(serde_json::Value::String(s)) => std::iter::once(s.clone()).collect(),
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => std::collections::HashSet::new(),
    }
}

/// v8.9.0 (CIRISPersist#236, CC 4.4.3.4.3 / CC 1.13.5) — the CC 1.13.5
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
/// - **`consent_revocation`** (CEG §3.2.3) — the pre-existing proxy
///   revocation walk. `enforce_attenuation_and_sub_delegation = false`
///   and `skip_withdrawn_edges = false`: BYTE-IDENTICAL to the v6.4.0
///   behavior (no `⊆`-parent attenuation, no `sub_delegation`
///   deputization gate, no per-edge `withdraws` skip). Its delegations
///   simply do not set those constraints, so adding the machinery behind
///   a `false` flag cannot regress it.
/// - **§11.10 `moderate` / `takedown` / `review`** (CEG RC24) — the new
///   moderation-enforcement walk. Both flags `true`: each edge's scope
///   must be `⊆` its parent edge's scope (restate-or-attenuate), a
///   non-root node may only be reached through a parent edge that granted
///   `sub_delegation`, and a `withdraws`-revoked edge (issuer-against-
///   recipient, UCAN-style) invalidates everything downstream.
#[derive(Debug, Clone, Copy)]
struct DelegationWalkPolicy {
    /// Enforce `child.scope ⊆ parent.scope` along the chain AND require
    /// `sub_delegation` on the parent edge before traversing past depth 1.
    enforce_attenuation_and_sub_delegation: bool,
    /// Skip any `delegates_to` edge the granter has `withdraws`/`recants`-
    /// revoked against the recipient (topology's edge-retraction model).
    skip_withdrawn_edges: bool,
}

impl DelegationWalkPolicy {
    /// The pre-v8.7.1 behavior — consent_revocation proxy reachability.
    const CONSENT_REVOCATION: Self = Self {
        enforce_attenuation_and_sub_delegation: false,
        skip_withdrawn_edges: false,
    };
    /// The §11.10 moderation-duty walk — attenuation + sub_delegation +
    /// per-edge revocation all enforced.
    const MODERATION_DUTY: Self = Self {
        enforce_attenuation_and_sub_delegation: true,
        skip_withdrawn_edges: true,
    };
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
async fn issuer_reaches_target_via_scoped_delegation(
    directory: &dyn super::FederationDirectory,
    issuer: &str,
    targets: &std::collections::HashSet<String>,
    scope_token: &str,
    max_depth: usize,
    policy: DelegationWalkPolicy,
) -> Result<bool, Error> {
    use std::collections::{HashSet, VecDeque};
    let effective_depth = max_depth.min(MAX_WITHDRAWS_DELEGATION_DEPTH);
    if effective_depth == 0 {
        return Ok(false);
    }
    // Per-node walk state. `parent_scope` is the scope-set of the edge
    // that reached `key` (the root `issuer` has `None` — no incoming
    // edge); `parent_sub_delegation` is whether that incoming edge granted
    // deputization. Under §11.10 (`enforce_attenuation_and_sub_delegation`)
    // these gate traversal; under consent_revocation they are inert.
    struct Node {
        key: String,
        depth: usize,
        parent_scope: Option<HashSet<String>>,
        parent_sub_delegation: bool,
    }
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<Node> = VecDeque::new();
    queue.push_back(Node {
        key: issuer.to_owned(),
        depth: 0,
        parent_scope: None,
        parent_sub_delegation: false,
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
        let rows = directory.list_attestations_by(&node.key).await?;
        // §11.10: bucket this granter's `withdraws`/`recants` retractions
        // by recipient so a revoked edge invalidates the downstream chain
        // (UCAN-style; topology's edge-retraction model). Inert for
        // consent_revocation (`skip_withdrawn_edges == false`).
        let mut retracted: HashSet<String> = HashSet::new();
        if policy.skip_withdrawn_edges {
            for r in &rows {
                if r.attestation_type == attestation_type::WITHDRAWS
                    || r.attestation_type == attestation_type::RECANTS
                {
                    retracted.insert(r.attested_key_id.clone());
                }
            }
        }
        for r in rows {
            if r.attestation_type != attestation_type::DELEGATES_TO {
                continue;
            }
            if !delegation_scope_grants(&r.attestation_envelope, scope_token) {
                continue;
            }
            if policy.skip_withdrawn_edges && retracted.contains(&r.attested_key_id) {
                continue;
            }
            // §11.10 `⊆`-parent attenuation: the child edge's scope-set
            // must be a subset of the parent edge's scope-set
            // (restate-or-attenuate, never expand). The root's first
            // out-edge has no parent edge to attenuate against.
            if policy.enforce_attenuation_and_sub_delegation {
                if let Some(parent_scope) = &node.parent_scope {
                    let child_scope = delegation_scope_set(&r.attestation_envelope);
                    if !child_scope.is_subset(parent_scope) {
                        continue;
                    }
                }
            }
            // A scope-bearing delegation edge to a target key is
            // sufficient — delegated duty established along the path.
            if targets.contains(&r.attested_key_id) {
                return Ok(true);
            }
            if !visited.contains(&r.attested_key_id) && node.depth + 1 < effective_depth {
                visited.insert(r.attested_key_id.clone());
                queue.push_back(Node {
                    key: r.attested_key_id,
                    depth: node.depth + 1,
                    parent_scope: Some(delegation_scope_set(&r.attestation_envelope)),
                    parent_sub_delegation: delegation_grants_sub_delegation(
                        &r.attestation_envelope,
                    ),
                });
            }
        }
    }
    Ok(false)
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
    /// A scope-bearing `delegates_to` edge to the target exists, but its
    /// granter has `withdraws`/`recants`-retracted it (UCAN-style edge
    /// retraction). Named for the depth-1 login case where the issuer
    /// (root) retracts its own edge to the target.
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
///
/// [`MODERATION_DUTY`]: DelegationWalkPolicy::MODERATION_DUTY
pub async fn reachable_under_scope_with_reasons(
    directory: &dyn super::FederationDirectory,
    issuer_key_id: &str,
    target_key_id: &str,
    scope: &str,
    max_depth: usize,
) -> Result<ReachabilityVerdict, Error> {
    use std::collections::{HashSet, VecDeque};
    let policy = DelegationWalkPolicy::MODERATION_DUTY;
    let effective_depth = max_depth.min(MAX_WITHDRAWS_DELEGATION_DEPTH);
    if effective_depth == 0 {
        return Ok(ReachabilityVerdict::SignerUnreached);
    }
    // Same per-node walk state as the predicate walk; see
    // `issuer_reaches_target_via_scoped_delegation`.
    struct Node {
        key: String,
        depth: usize,
        parent_scope: Option<HashSet<String>>,
        parent_sub_delegation: bool,
    }
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<Node> = VecDeque::new();
    queue.push_back(Node {
        key: issuer_key_id.to_owned(),
        depth: 0,
        parent_scope: None,
        parent_sub_delegation: false,
    });
    visited.insert(issuer_key_id.to_owned());

    // Observations that classify a "no" — see the precedence in the
    // doc comment. None of these influence the reachability decision
    // itself (that stays identical to the predicate walk).
    let mut issuer_emitted_delegation = false;
    let mut saw_target_edge_retracted = false;
    let mut saw_target_edge_missing_scope = false;

    while let Some(node) = queue.pop_front() {
        if node.depth >= effective_depth {
            continue;
        }
        if policy.enforce_attenuation_and_sub_delegation
            && node.parent_scope.is_some()
            && !node.parent_sub_delegation
        {
            continue;
        }
        let rows = match directory.list_attestations_by(&node.key).await {
            Ok(rows) => rows,
            Err(_) => return Ok(ReachabilityVerdict::SubstrateUnavailable),
        };
        let mut retracted: HashSet<String> = HashSet::new();
        if policy.skip_withdrawn_edges {
            for r in &rows {
                if r.attestation_type == attestation_type::WITHDRAWS
                    || r.attestation_type == attestation_type::RECANTS
                {
                    retracted.insert(r.attested_key_id.clone());
                }
            }
        }
        let is_issuer = node.depth == 0;
        for r in rows {
            if r.attestation_type != attestation_type::DELEGATES_TO {
                continue;
            }
            if is_issuer {
                issuer_emitted_delegation = true;
            }
            let to_target = r.attested_key_id == target_key_id;
            // Scope gate (checked first, mirroring the predicate walk).
            if !delegation_scope_grants(&r.attestation_envelope, scope) {
                if to_target {
                    saw_target_edge_missing_scope = true;
                }
                continue;
            }
            // Retraction gate.
            if policy.skip_withdrawn_edges && retracted.contains(&r.attested_key_id) {
                if to_target {
                    saw_target_edge_retracted = true;
                }
                continue;
            }
            // ⊆-parent attenuation gate. A pruned edge here is neither a
            // clean missing-scope nor a retraction — the duty just cannot
            // validly flow down this path; it contributes only to a
            // SignerUnreached "no".
            if policy.enforce_attenuation_and_sub_delegation {
                if let Some(parent_scope) = &node.parent_scope {
                    let child_scope = delegation_scope_set(&r.attestation_envelope);
                    if !child_scope.is_subset(parent_scope) {
                        continue;
                    }
                }
            }
            if to_target {
                return Ok(ReachabilityVerdict::Reachable);
            }
            if !visited.contains(&r.attested_key_id) && node.depth + 1 < effective_depth {
                visited.insert(r.attested_key_id.clone());
                queue.push_back(Node {
                    key: r.attested_key_id,
                    depth: node.depth + 1,
                    parent_scope: Some(delegation_scope_set(&r.attestation_envelope)),
                    parent_sub_delegation: delegation_grants_sub_delegation(
                        &r.attestation_envelope,
                    ),
                });
            }
        }
    }

    if saw_target_edge_retracted {
        return Ok(ReachabilityVerdict::RetractedAtRoot);
    }
    if saw_target_edge_missing_scope {
        return Ok(ReachabilityVerdict::MissingScope);
    }
    if !issuer_emitted_delegation {
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
async fn enumerate_scoped_delegation_reach(
    directory: &dyn super::FederationDirectory,
    issuer: &str,
    scope_token: &str,
    max_depth: usize,
    policy: DelegationWalkPolicy,
) -> Result<std::collections::HashSet<String>, Error> {
    use std::collections::{HashSet, VecDeque};
    let effective_depth = max_depth.min(MAX_WITHDRAWS_DELEGATION_DEPTH);
    let mut reached: HashSet<String> = HashSet::new();
    if effective_depth == 0 {
        return Ok(reached);
    }
    struct Node {
        key: String,
        depth: usize,
        parent_scope: Option<HashSet<String>>,
        parent_sub_delegation: bool,
    }
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<Node> = VecDeque::new();
    queue.push_back(Node {
        key: issuer.to_owned(),
        depth: 0,
        parent_scope: None,
        parent_sub_delegation: false,
    });
    visited.insert(issuer.to_owned());

    while let Some(node) = queue.pop_front() {
        if node.depth >= effective_depth {
            continue;
        }
        // §11.10 deputization gate (identical to the predicate walk): a
        // non-root granter may only further-delegate if its incoming edge
        // granted `sub_delegation`.
        if policy.enforce_attenuation_and_sub_delegation
            && node.parent_scope.is_some()
            && !node.parent_sub_delegation
        {
            continue;
        }
        let rows = directory.list_attestations_by(&node.key).await?;
        let mut retracted: HashSet<String> = HashSet::new();
        if policy.skip_withdrawn_edges {
            for r in &rows {
                if r.attestation_type == attestation_type::WITHDRAWS
                    || r.attestation_type == attestation_type::RECANTS
                {
                    retracted.insert(r.attested_key_id.clone());
                }
            }
        }
        for r in rows {
            if r.attestation_type != attestation_type::DELEGATES_TO {
                continue;
            }
            if !delegation_scope_grants(&r.attestation_envelope, scope_token) {
                continue;
            }
            if policy.skip_withdrawn_edges && retracted.contains(&r.attested_key_id) {
                continue;
            }
            if policy.enforce_attenuation_and_sub_delegation {
                if let Some(parent_scope) = &node.parent_scope {
                    let child_scope = delegation_scope_set(&r.attestation_envelope);
                    if !child_scope.is_subset(parent_scope) {
                        continue;
                    }
                }
            }
            // Record the reached recipient. The cycle guard (`visited`)
            // ensures we never enqueue a key twice; `reached` accumulates
            // every recipient regardless of further traversal.
            reached.insert(r.attested_key_id.clone());
            if !visited.contains(&r.attested_key_id) && node.depth + 1 < effective_depth {
                visited.insert(r.attested_key_id.clone());
                queue.push_back(Node {
                    key: r.attested_key_id,
                    depth: node.depth + 1,
                    parent_scope: Some(delegation_scope_set(&r.attestation_envelope)),
                    parent_sub_delegation: delegation_grants_sub_delegation(
                        &r.attestation_envelope,
                    ),
                });
            }
        }
    }
    Ok(reached)
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

    // v21.11.0 (CIRISPersist#528, CC 3.4.5 — the anti-Goodhart DUAL) — for the
    // scored families whose SELF-EMISSION is banned (`capacity:*` /
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
///      human delegated to k) — checked over k's INCOMING attestations
///      ([`FederationDirectory::list_attestations_for`]). "Live" excludes a
///      delegation the granter has `withdraws`/`recants`-retracted against
///      `k` (the §11.10 edge-retraction model) AND one whose `expires_at`
///      has passed (SecReview F3) — a revoked or lapsed edge confers no
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
    // (3) a LIVE `delegates_to(U → k)` with U user-role. k's INCOMING
    //     attestations name the granter as `attesting_key_id`. A delegation
    //     edge confers steward-binding ONLY while genuinely live (SecReview
    //     F3): skip it if (a) the granter has `withdraws`/`recants`-retracted
    //     it (reusing the §11.10 edge-retraction bucketing the MODERATION_DUTY
    //     walk uses — a retraction names the recipient `k` as
    //     `attested_key_id`), or (b) the edge has expired (`expires_at <=
    //     now`). A revoked/expired delegation must not confer standing.
    let now = chrono::Utc::now();
    for r in directory.list_attestations_for(k).await? {
        if r.attestation_type != attestation_type::DELEGATES_TO {
            continue;
        }
        // (b) expiry — a lapsed delegation is not live.
        if let Some(exp) = r.expires_at {
            if exp <= now {
                continue;
            }
        }
        // (b') fail-to-liberty — a lapsed adult-incapacity `valid_until` is
        //      not live (CC 3.4.12; no-op for minor rows).
        if delegation_valid_until_lapsed(&r.attestation_envelope, now) {
            continue;
        }
        let Some(granter) = directory.lookup_public_key(&r.attesting_key_id).await? else {
            continue;
        };
        if !identity_type::set_contains(&granter.identity_type, identity_type::USER) {
            continue;
        }
        // (a) edge-retraction — skip if the granter `withdraws`/`recants` a
        //     delegation against this recipient `k`. The retraction is one of
        //     the granter's OUTGOING attestations whose `attested_key_id == k`.
        let granter_retracted_k = directory
            .list_attestations_by(&r.attesting_key_id)
            .await?
            .into_iter()
            .any(|g| {
                (g.attestation_type == attestation_type::WITHDRAWS
                    || g.attestation_type == attestation_type::RECANTS)
                    && g.attested_key_id == k
            });
        if granter_retracted_k {
            continue;
        }
        return Ok(true);
    }
    Ok(false)
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
///      `user`-role (live = not `withdraws`/`recants`-retracted against `k`
///      by `U`, and not expired) → `U`.
///
/// Consistency: `is_steward_bound(k)` ⟺ `!steward_bindings_of(k).is_empty()` —
/// the predicate returns true iff ANY clause holds, and this returns the
/// union of all satisfying anchors (deduped, sorted). An unbound `k` yields
/// the empty set.
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
    // (3) each granter U of a LIVE delegates_to(U → k) with U user-role.
    let now = chrono::Utc::now();
    for r in directory.list_attestations_for(k).await? {
        if r.attestation_type != attestation_type::DELEGATES_TO {
            continue;
        }
        if let Some(exp) = r.expires_at {
            if exp <= now {
                continue;
            }
        }
        // Fail-to-liberty (CC 3.4.12): a lapsed adult-incapacity `valid_until`
        // is non-live; the adult auto-re-sovereigns. No-op for minor rows.
        if delegation_valid_until_lapsed(&r.attestation_envelope, now) {
            continue;
        }
        let Some(granter) = directory.lookup_public_key(&r.attesting_key_id).await? else {
            continue;
        };
        if !identity_type::set_contains(&granter.identity_type, identity_type::USER) {
            continue;
        }
        let granter_retracted_k = directory
            .list_attestations_by(&r.attesting_key_id)
            .await?
            .into_iter()
            .any(|g| {
                (g.attestation_type == attestation_type::WITHDRAWS
                    || g.attestation_type == attestation_type::RECANTS)
                    && g.attested_key_id == k
            });
        if granter_retracted_k {
            continue;
        }
        out.insert(r.attesting_key_id);
    }
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
/// set behind [`owner_of`] + [`check_single_node_owner_admission`]; it applies
/// the SAME liveness/retraction predicate as [`steward_bindings_of`]'s clause
/// (3) — not-expired, not adult-incapacity-lapsed, live `user`-role granter, not
/// `withdraws`/`recants`-retracted — restricted to the ownership dimension, so
/// `owner_of(node)` is always a subset of `steward_bindings_of(node)`.
async fn live_owner_binding_granters(
    directory: &dyn super::FederationDirectory,
    node: &str,
) -> Result<std::collections::BTreeSet<String>, Error> {
    let mut out: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let now = chrono::Utc::now();
    let rows = directory.list_attestations_for(node).await?;

    // v25.x (CIRISPersist#578) — **a binding withdrawn BY ANYONE the gate
    // admitted is non-live**, not only one retracted by its own granter.
    //
    // The granter-scoped clause below cannot see the CC 3.2 recovery
    // `withdraws`: it is issued by the node K (or K's recovery delegate),
    // never by the incumbent owner. So without this set the ceremony's step 3
    // would admit a `withdraws`, store it, and leave `owner_of(K)` STILL
    // resolving to the incumbent — K would never pass through the unowned
    // state, the "empty self cohort, fail-secure" clause would be prose, and
    // step 4's single-owner gate would refuse the rightful claimant forever.
    // Two lists that disagree about what "live" means; one list now.
    //
    // Authority is not re-litigated here: a stored `withdraws` has already
    // been through `check_withdraws_admission`, which is where the recovery
    // ceremony (or rules 1-4) authorized it.
    let withdrawn: std::collections::HashSet<String> = rows
        .iter()
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
        .collect();

    for r in rows {
        if r.attestation_type != attestation_type::DELEGATES_TO {
            continue;
        }
        if withdrawn.contains(r.attestation_id.as_str()) {
            continue;
        }
        // Only OWNER-BINDING edges — the internal dimension OR the CC 2.4.1.2
        // `delegation_purpose: owner_binding` marker (v13.2.1 #378). This is
        // what keeps ownership single-valued WITHOUT constraining act-on-behalf
        // / hierarchy delegations (multi-parent per CC 4.5.13). Must match
        // `check_single_node_owner_admission` exactly so the gate and the
        // `owner_of` resolver agree on what an owner-binding IS.
        if !is_owner_binding_envelope(&r.attestation_envelope) {
            continue;
        }
        if let Some(exp) = r.expires_at {
            if exp <= now {
                continue;
            }
        }
        // Fail-to-liberty (CC 3.4.12): a lapsed adult-incapacity `valid_until`
        // is non-live.
        if delegation_valid_until_lapsed(&r.attestation_envelope, now) {
            continue;
        }
        // A non-`user` granter cannot steward — mirror steward_bindings_of.
        let Some(granter) = directory.lookup_public_key(&r.attesting_key_id).await? else {
            continue;
        };
        if !identity_type::set_contains(&granter.identity_type, identity_type::USER) {
            continue;
        }
        let granter_retracted = directory
            .list_attestations_by(&r.attesting_key_id)
            .await?
            .into_iter()
            .any(|g| {
                (g.attestation_type == attestation_type::WITHDRAWS
                    || g.attestation_type == attestation_type::RECANTS)
                    && g.attested_key_id == node
            });
        if granter_retracted {
            continue;
        }
        out.insert(r.attesting_key_id);
    }
    Ok(out)
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
    // v13.2.1 (#378): recognize the owner-binding by EITHER the internal
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
async fn verify_accord_family_coscrub(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
    roster_key_ids: &[String],
) -> Result<(), String> {
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
/// extensions mark **FIPS-certified + touch=always** — the same predicate
/// CIRISServer's holder-admission gate applies. Fail-closed: absent/
/// malformed/unverifiable evidence ⇒ `Err` ⇒ the member does not count.
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
async fn verify_accord_family_coscrub_with(
    directory: &dyn super::FederationDirectory,
    row: &super::KeyRecord,
    roster_key_ids: &[String],
    min_quorum: usize,
    require_fips_custody: bool,
    custody_root: &[u8],
) -> Result<(), String> {
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
    // A node never de-admits itself, and a de-admission row itself must always
    // be admissible (else a node could not lift its own denial).
    if row.attesting_key_id == self_key_id
        || envelope_dimension(&row.attestation_envelope) == Some(PEER_DEADMISSION_DIMENSION)
    {
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
pub async fn has_accord_conferred_role_over_roster(
    directory: &dyn super::FederationDirectory,
    key_id: &str,
    role: &str,
    roster_key_ids: &[String],
) -> Result<bool, Error> {
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
///   3. a **live** `delegates_to(U → k)` with `U` `user`-role (not
///      `withdraws`/`recants`-retracted against `k`, not expired) →
///      `[U, k]`. The §11.10 steward-binding clause (3) is a DIRECT incoming
///      edge (same as the predicate), so the delegated path is one hop; a
///      multi-hop human→…→k steward-binding is not part of the predicate and
///      is not synthesized here.
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
    //     delegate to k (consistent with the sorted `steward_bindings_of`).
    let now = chrono::Utc::now();
    let mut anchors: Vec<String> = Vec::new();
    for r in directory.list_attestations_for(key_id).await? {
        if r.attestation_type != attestation_type::DELEGATES_TO {
            continue;
        }
        if let Some(exp) = r.expires_at {
            if exp <= now {
                continue;
            }
        }
        // Fail-to-liberty (CC 3.4.12): a lapsed adult-incapacity `valid_until`
        // is non-live; the adult auto-re-sovereigns. No-op for minor rows.
        if delegation_valid_until_lapsed(&r.attestation_envelope, now) {
            continue;
        }
        let Some(granter) = directory.lookup_public_key(&r.attesting_key_id).await? else {
            continue;
        };
        if !identity_type::set_contains(&granter.identity_type, identity_type::USER) {
            continue;
        }
        let granter_retracted_k = directory
            .list_attestations_by(&r.attesting_key_id)
            .await?
            .into_iter()
            .any(|g| {
                (g.attestation_type == attestation_type::WITHDRAWS
                    || g.attestation_type == attestation_type::RECANTS)
                    && g.attested_key_id == key_id
            });
        if granter_retracted_k {
            continue;
        }
        anchors.push(r.attesting_key_id);
    }
    if let Some(anchor) = anchors.into_iter().min() {
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
/// # Keying — what "keyed on C" means for an attestation row (v12.7.0, #369)
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

/// v12.7.0 (CIRISPersist#369, CC 4.5.4 / §11.11) — the directly drivable
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
    let duty_holders = duty_holders_for_community(directory, community_id, duty).await?;
    check_moderation_admission(
        directory,
        &row.attesting_key_id,
        &duty_holders,
        duty,
        dimension,
    )
    .await
}

/// v8.9.0 (CIRISPersist#236, CC 4.4.3.4.3 / CC 1.13.5) — the
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
/// - `age_assurance:*` → MUST NOT be self-emitted either (v12.7.0,
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

    // v12.7.0 (CIRISPersist#368) — CC 3.4.11: "A subject MUST NOT emit on
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
    if is_hard_case && got != identity_type::SUBSTRATE_PERSIST {
        return Err(Error::ReservedPrefixEmitterMismatch {
            dimension: at.to_owned(),
            prefix: "hard_case:".to_owned(),
            required: vec![identity_type::SUBSTRATE_PERSIST.to_owned()],
            got_identity_type: got,
        });
    }
    if let Some(rule) = matched_rule {
        // CC 3.4.7.1 — set membership, not scalar equality: `got` is the
        // stored (possibly comma-joined) `identity_type` set; the rule is
        // satisfied iff a required role is one of its members. Single-role
        // keys encode identically to scalar (`X ∈ {X}` ≡ `X == X`), so this
        // is behavior-preserving for every existing reserved prefix and
        // only newly-admits conformant folded keys (CC 3.4.8 detector fold).
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
    /// **v12.0.0** block below).
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
        use ciris_verify_core::federation_provenance::dim;

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
        // THE MEASURING SIDE'S CLASSIFICATION — the ONLY version-dependent
        // read of verify's registry in this crate. Everything else here and
        // in B7 uses `dim::ALL` / `dim::lookup` / `prefix` / `parameterized`,
        // which were stable across the re-pin.
        //
        // **Now pinned against ciris-verify-core v12.0.0**, which verify
        // shipped in response to this rework (CIRISVerify#238) and which
        // agrees with CC 3.4.5 on all fourteen families:
        //
        //   * `ConsentClass`         -> `ConsentDisposition`
        //   * `ConsensualReputation` -> `ArtifactVerification` / `AbuseResponse`
        //   * the predicate is now a METHOD, `spec.is_consent_gated()`,
        //     deliberately not an implicit property of a variant name, "so the
        //     wrong gate cannot be re-derived from variant names" — which is
        //     exactly the mistake #569 made.
        //
        // The v11 form pinned four prefixes BY NAME. This one sweeps the whole
        // registry, so it fires if verify ever re-gates ANY family rather than
        // only if one of four named prefixes moves. Strictly stronger, and it
        // was verify's own proposal.
        // ─────────────────────────────────────────────────────────────────
        for spec in dim::ALL {
            assert!(
                !spec.consent_disposition.is_consent_gated(),
                "verify now consent-gates `{}`, but CC 3.4.5 gates NO verify-owned family — \
                 consent-before-scoring binds the family that judges agents (`capacity:*`), \
                 never the families that verify artifacts. Do NOT follow the measuring side \
                 here: re-read CC 3.4.5's per-family disposition and adjudicate. Following \
                 verify's classification over the floor's ruling is precisely the defect \
                 CIRISPersist#569 shipped and CIRISVerify#238 corrected.",
                spec.prefix
            );
        }

        // ── THE FLOOR'S RULING — persist gates NONE of verify's namespace ──
        // Over the WHOLE registry, not just the four above: a CC amendment
        // moving any family across the line, or a re-widening of the gate,
        // lands here. Probed through the one predicate the gate itself calls,
        // on the real dimension shape, so this asserts shipped behaviour and
        // not a restatement of the source.
        for spec in dim::ALL {
            let probe = if spec.parameterized {
                format!("{}probe:v1", spec.prefix)
            } else {
                spec.prefix.to_owned()
            };
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
        // self-report set + §7.6 witness rule + CEG 0.3 §5.6.8.3
        // four-family media-sharing set. Regression-guards the table
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
            // CEG 0.3 §5.6.8.3 — four new families.
            "content_rating:",
            "content_class:",
            "cw_class:",
            "age_assurance:",
        ] {
            assert!(
                prefixes.contains(expected),
                "default rules missing {expected}; got {prefixes:?}"
            );
        }
    }

    // ── CEG 0.3 §5.6.8.3 + §11.5.3 — four new reserved-prefix tests ──

    #[test]
    fn reserved_prefix_content_rating_requires_trusted_publisher_emitter() {
        // CEG 0.3 §11.5.3: only trusted_publisher may emit
        // content_rating:* attestations.
        let p = default_policy();
        let err = p
            .check(
                attestation_type::SCORES,
                Some("content_rating:mpa:pg13:v1"),
                identity_type::AGENT,
            )
            .unwrap_err();
        match err {
            Error::ReservedPrefixEmitterMismatch {
                prefix, required, ..
            } => {
                assert_eq!(prefix, "content_rating:");
                assert_eq!(required, vec!["trusted_publisher".to_string()]);
            }
            other => panic!("expected ReservedPrefixEmitterMismatch, got {other:?}"),
        }
        // trusted_publisher passes.
        p.check(
            attestation_type::SCORES,
            Some("content_rating:mpa:pg13:v1"),
            identity_type::TRUSTED_PUBLISHER,
        )
        .unwrap();
    }

    #[test]
    fn reserved_prefix_content_class_requires_substrate_persist_emitter() {
        let p = default_policy();
        let err = p
            .check(
                attestation_type::SCORES,
                Some("content_class:violence:v1"),
                identity_type::AGENT,
            )
            .unwrap_err();
        assert!(matches!(err, Error::ReservedPrefixEmitterMismatch { .. }));
        p.check(
            attestation_type::SCORES,
            Some("content_class:violence:v1"),
            identity_type::SUBSTRATE_PERSIST,
        )
        .unwrap();
    }

    #[test]
    fn reserved_prefix_cw_class_requires_substrate_persist_emitter() {
        let p = default_policy();
        let err = p
            .check(
                attestation_type::SCORES,
                Some("cw_class:flashing_lights:v1"),
                identity_type::WITNESS,
            )
            .unwrap_err();
        assert!(matches!(err, Error::ReservedPrefixEmitterMismatch { .. }));
        p.check(
            attestation_type::SCORES,
            Some("cw_class:flashing_lights:v1"),
            identity_type::SUBSTRATE_PERSIST,
        )
        .unwrap();
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

/// v12.7.0 (CIRISPersist#372, CC 3.4.7.1) — the accord-conferred `canonical`
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
    async fn canonical_gate_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
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
    async fn infra_attest_gate_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
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
    async fn set_path_parity_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
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
    async fn announced_peer_parity_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
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
    async fn costeward_gate_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
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
    async fn canonical_withdrawal_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
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
    async fn infra_attest_withdrawal_postgres() {
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
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

    fn manifest_env() -> serde_json::Value {
        serde_json::json!({
            "dimension": "trace:complete:v1",
            "trace_id": "t-1", "agent_id_hash": "ah-1",
            "manifest": {"schema": "trace_manifest:v1",
                          "content_hash": "sha256:abc123",
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
                               "content_hash":"sha256:x","byte_len":1,"component_count":1}}),
            // inline not an object
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"a","trace":"str"}),
            // manifest wrong schema
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"a",
                               "manifest":{"schema":"nope","content_hash":"sha256:x","byte_len":1,"component_count":1}}),
            // manifest un-prefixed hash
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"a",
                               "manifest":{"schema":"trace_manifest:v1","content_hash":"abc","byte_len":1,"component_count":1}}),
            // manifest zero byte_len
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"a",
                               "manifest":{"schema":"trace_manifest:v1","content_hash":"sha256:x","byte_len":0,"component_count":1}}),
            // manifest missing component_count
            serde_json::json!({"dimension":"trace:x:v1","trace_id":"t","agent_id_hash":"a",
                               "manifest":{"schema":"trace_manifest:v1","content_hash":"sha256:x","byte_len":1}}),
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
}
