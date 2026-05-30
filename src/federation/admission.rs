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
}

impl DimensionRejectionReason {
    /// Stable machine-readable token (snake_case). Matches the
    /// `serde(rename_all)` output for parity with structured logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MorallyChargedStem => "morally_charged_stem",
            Self::MissingVersionSegment => "missing_version_segment",
            Self::EmptyOrMissingDimension => "empty_or_missing_dimension",
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
/// - `capacity:*` self-emission rejection (CEG §7.5) is NOT in this
///   table — it's an attester==attested check, not an identity-type
///   check, and lives at the consumer composition layer per §7.5's
///   anti-Goodhart commentary. The substrate's reserved-prefix gate
///   doesn't enforce it because the substrate doesn't see the
///   attester==attested distinction except at the row level (the
///   `Attestation` row carries `attesting_key_id` + `attested_key_id`;
///   the admission gate only knows the attester's identity-type, not
///   whether the two keys are the same row).
/// - `licensure:*` (CEG §7.3) is co-owned — the admission gate
///   doesn't reject single-source emissions; per §7.3, consumers
///   mark them `confidence ≤ 0.5` until the second co-owner attests.
/// - `detection:correlated_action:*` / `detection:distributive:*`
///   (CEG §7.4) are LensCore-only emission but the substrate accepts
///   cross-attestations under a different prefix per §7.4's last
///   sentence; mapping this to a substrate-admission rule requires
///   knowing whether the row is a primary detection-emission vs a
///   cross-attestation, which lives in the envelope shape. Deferred
///   to consumer-side check pending CEG-side rule clarification.
pub fn default_reserved_prefix_rules() -> Vec<ReservedPrefixRule> {
    use super::types::identity_type;
    let substrate_persist = identity_type::SUBSTRATE_PERSIST.to_owned();
    let witness = identity_type::WITNESS.to_owned();
    let trusted_publisher = identity_type::TRUSTED_PUBLISHER.to_owned();
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
            required_identity_types: vec![witness],
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
                if !rule
                    .required_identity_types
                    .iter()
                    .any(|t| t == attesting_identity_type)
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
        if self.require_version_segment
            && !contains_version_segment(dim)
            && !self.is_attestation_ladder_dimension(dim)
        {
            return Err(Error::DimensionRejected {
                dimension: dim.to_string(),
                reason: DimensionRejectionReason::MissingVersionSegment.as_str(),
            });
        }

        Ok(())
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
    envelope.get("dimension").and_then(|v| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_policy() -> DimensionAdmissionPolicy {
        DimensionAdmissionPolicy::default()
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
        // + version-pinned. Should pass.
        let p = default_policy();
        p.check(
            attestation_type::SCORES,
            Some("detection:correlated_action:rights_asymmetry:v1"),
            identity_type::STEWARD,
        )
        .unwrap();
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
}
