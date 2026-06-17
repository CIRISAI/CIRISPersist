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
    envelope.get("dimension").and_then(|v| v.as_str())
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
///      another party's content → it is **NOT local-tier-eligible** and
///      is rejected at `tier = "local"`. A `stance: granted` self-consent
///      MAY be local (no tier restriction here; the §10.1.5.2 self-tier
///      eligibility is enforced by [`check_local_tier_eligibility`]).
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
/// any rule violation; the row is not stored.
pub fn check_consent_record_admission(
    attestation_type: &str,
    envelope: &serde_json::Value,
    tier: &str,
) -> Result<(), Error> {
    use crate::federation::types::consent_record;
    // No-op unless this is a `scores` carrying the consent_record
    // discriminator. (A `consent_record` MUST ride `scores` — §5.6.8.7
    // "Rides existing scores attestation_type"; a non-scores row bearing
    // the discriminator is malformed.)
    if envelope_subject_kind(envelope) != Some(consent_record::SUBJECT_KIND) {
        return Ok(());
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
    // subject revocation authority → never local-tier-eligible.
    if stance == consent_record::stance::REVOKED
        && tier == crate::federation::types::attestation_tier::LOCAL
    {
        return Err(Error::InvalidArgument(
            "a consent_record with stance 'revoked' is NOT local-tier-eligible \
             (CEG §10.1.3 / §5.6.8.7 admission rule 3): it carries subject \
             revocation authority — it must be federation-tier (hybrid-signed) \
             or promoted within the §10.1.3 bounded window"
                .to_string(),
        ));
    }
    Ok(())
}

/// v4.4.0 (CIRISPersist#171, CEG §10.1.3/§10.1.5/§7.5) — gate a row's
/// eligibility for the **local tier** (signature-deferred,
/// producer-only-authority). Local-tier eligibility is producer
/// authority — NOT empty `subject_key_ids` (CEG §4.2.6: producer-
/// authority rows legitimately name subjects). Exactly two classes are
/// **refused** at local tier (they MUST be federation-tier, signed):
///
///   1. **`capacity:*` (CEG §7.5 anti-Goodhart, AV-62).** A `capacity:*`
///      dimension rejects self-emission; the local tier's self-write →
///      self-read → deferred-sig shape is precisely the §7.5 forbidden
///      loop. Capacity is inherently third-party-attested.
///   2. **Subject-side revocation (CEG §10.1.3, AV-61).** A `withdraws`
///      (structural) or a `consent:state:revoked` dimension whose
///      **writer (`attesting_key_id`) is a member of `subject_key_ids`**
///      — the subject exercising its own revocation right. Subject-side
///      revocation is the federation-observability primitive peers
///      depend on; it cannot ride the deferral path.
///
/// `dimension` is the envelope dimension ([`envelope_dimension`]);
/// `attestation_type` is the §3 structural primitive. Returns
/// [`Error::InvalidArgument`] on an ineligible row; `Ok(())` otherwise.
pub fn check_local_tier_eligibility(
    attestation_type: &str,
    dimension: Option<&str>,
    attesting_key_id: &str,
    subject_key_ids: &[String],
    cohort_scope: &str,
) -> Result<(), Error> {
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
    // (2) subject-side revocation — never local (§10.1.3 / AV-61).
    let is_revocation = attestation_type == crate::federation::types::attestation_type::WITHDRAWS
        || dimension.is_some_and(|d| d.starts_with("consent:state:revoked"));
    if is_revocation && subject_key_ids.iter().any(|s| s == attesting_key_id) {
        return Err(Error::InvalidArgument(
            "a subject-side revocation (the writer is a member of subject_key_ids) is NOT \
             local-tier-eligible (CEG §10.1.3, AV-61): it must be federation-tier signed / \
             promoted within the bounded window"
                .to_string(),
        ));
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
fn delegation_scope_set(envelope: &serde_json::Value) -> std::collections::HashSet<String> {
    match envelope.get("scope") {
        Some(serde_json::Value::String(s)) => std::iter::once(s.clone()).collect(),
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        _ => std::collections::HashSet::new(),
    }
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
    let rule = resolve_withdraws_admission_rule(directory, &row.attesting_key_id, &target).await?;
    Ok(Some(rule))
}

// ─── v8.7.1 — §11.10 FULL moderation enforcement (CEG RC24/RC25/RC26) ───
//
// v8.7.1 (CIRISPersist#233) REPLACES the v8.7.0 `on_behalf_of`-field model
// entirely. RC24 §11.10 pins the principal as the chain ROOT discovered by
// walking UP from `attesting_key_id` to an owner-bound scoped duty-holder —
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
//       revoked edge) AND `is_owner_bound(root)`.
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

/// v8.7.1 (CIRISPersist#233, CEG RC24 §11.10) — the §11.10 delegated-duty
/// depth bound (§13.3: depth ≤ 5). Distinct from the
/// [`MAX_WITHDRAWS_DELEGATION_DEPTH`] (16) used by the consent_revocation
/// proxy walk — moderation chains are short by spec. The walk's
/// `effective_depth` is `min(this, MAX_WITHDRAWS_DELEGATION_DEPTH)`, so a
/// chain longer than 5 cannot confer a moderation duty.
pub const MAX_MODERATION_DELEGATION_DEPTH: usize = 5;

/// v8.7.1 (CIRISPersist#233, CEG RC25/RC26 §5.6.8.10) — is key `k`
/// **owner-bound**? A moderation chain ROOT must terminate in a real human
/// (a `user`-role identity), never a free-floating agent/service key — the
/// §11.10 "takedown isn't a coup" anchor. True iff ANY of:
///
///   1. `k`'s OWN `federation_keys.identity_type` set ⊇ `{user}`
///      ([`identity_type::USER`]); OR
///   2. [`FederationDirectory::lookup_identity_for_occurrence`]`(k)`
///      resolves `k` to an identity whose key is `user`-role (k is a
///      device/occurrence of a human identity); OR
///   3. ∃ a live `delegates_to(U → k)` with `U` a `user`-role key (a human
///      delegated to k) — checked over k's INCOMING attestations
///      ([`FederationDirectory::list_attestations_for`]).
///
/// A key whose chain to a `user` identity cannot be shown is NOT
/// owner-bound and cannot root a moderation duty (fail-closed). Authority
/// that the `user`-role key genuinely is a human is consumer/registry
/// policy (§5.6.8.10 normative-honesty); persist resolves it structurally
/// over the `federation_keys` `identity_type` set + occurrence + delegation
/// graph that are already present.
pub async fn is_owner_bound(
    directory: &dyn super::FederationDirectory,
    k: &str,
) -> Result<bool, Error> {
    // (1) k's own identity_type set contains `user`.
    if let Some(rec) = directory.lookup_public_key(k).await? {
        if identity_type::set_contains(&rec.identity_type, identity_type::USER) {
            return Ok(true);
        }
    }
    // (2) k is an occurrence of a human identity — resolve the identity key
    //     and check ITS identity_type set for `user`.
    if let Some(occ) = directory.lookup_identity_for_occurrence(k).await? {
        if let Some(id_rec) = directory.lookup_public_key(&occ.identity_key_id).await? {
            if identity_type::set_contains(&id_rec.identity_type, identity_type::USER) {
                return Ok(true);
            }
        }
    }
    // (3) a live `delegates_to(U → k)` with U user-role. k's INCOMING
    //     attestations name the granter as `attesting_key_id`.
    for r in directory.list_attestations_for(k).await? {
        if r.attestation_type != attestation_type::DELEGATES_TO {
            continue;
        }
        if let Some(granter) = directory.lookup_public_key(&r.attesting_key_id).await? {
            if identity_type::set_contains(&granter.identity_type, identity_type::USER) {
                return Ok(true);
            }
        }
    }
    Ok(false)
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
///   - `is_owner_bound(root)`.
///
/// A zero-hop appointment (`root == k`, root directly in the authority set)
/// is admitted — a founder IS a named moderator of their own community. The
/// §11.11 merit auto-promotion emits the SAME appointment shape (a
/// `delegates_to` from a community authority), so this one predicate covers
/// both the explicit-appointment and merit-promotion cases.
///
/// `community_id` is the community's `community_key_id`. Returns `false`
/// (never errors) when the community is unknown, declares no authority set,
/// or no owner-bound authority reaches `k` — fail-closed.
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
        // Owner-binding of the root is REQUIRED (§11.11 → §5.6.8.10).
        if !is_owner_bound(directory, &root).await? {
            continue;
        }
        // Zero-hop: the owner-bound authority IS the named moderator.
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
///   (b) **delegated** — ∃ `root ∈ duty_holders` that `is_owner_bound`
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
    // (b) delegated: an owner-bound duty-holder root reaches signer via a
    //     live duty-scoped chain (§11.10 attenuation + sub_delegation).
    let target: std::collections::HashSet<String> = std::iter::once(signer.to_owned()).collect();
    for root in duty_holders {
        if !is_owner_bound(directory, root).await? {
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
/// roots (the community authority set, owner-bound) so a signer who IS a
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

/// v8.7.2 (CIRISPersist#233 follow-on, CEG RC27 §11.10) — the duty-holders
/// of a content target whose subject set is ALREADY signed state in hand
/// (the report→`scores` path: the row's own `subject_key_ids`, signed by
/// the producer INSIDE the attestation being admitted). Unlike
/// [`duty_holders_for_content`], no `subject_of_content` resolution is
/// needed — the signed subjects are the attestation's own field, not a
/// hash to resolve, and not a third-party payload declaration. Holders =
/// `signed_subjects ∪ named_moderators(community_id, duty)`.
///
/// This is the §11.10 "already signed-state, fine" case: the scores row's
/// `subject_key_ids` are part of the signed envelope, so feeding them is
/// NOT the payload-self-declaration spoof the cirisnode path closes.
pub async fn duty_holders_from_signed_subjects(
    directory: &dyn super::FederationDirectory,
    signed_subjects: &[String],
    community_id: &str,
    duty: &str,
) -> Result<std::collections::HashSet<String>, Error> {
    let mut holders: std::collections::HashSet<String> = signed_subjects.iter().cloned().collect();
    holders.extend(named_moderator_holders(directory, community_id, duty).await?);
    Ok(holders)
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
/// `duty` into the duty-holder set: each owner-bound member of the
/// community authority set. (The full `is_named_moderator` relation —
/// including delegates reached from these roots — is then enforced by
/// [`check_moderation_admission`]'s per-signer walk-down rooted at these
/// holders.) Empty community / no owner-bound authority ⇒ empty set.
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
        if is_owner_bound(directory, &root).await? {
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
    } else {
        return Ok(());
    };
    let community_id = row
        .attestation_envelope
        .get("community_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // v8.7.2: this is the SCORES path — the row's OWN `subject_key_ids` are
    // signed state (the producer signed THIS attestation, subjects
    // included), not a later third party's self-declaration. So we feed the
    // row's signed subjects directly (NOT via `subject_of_content`, which is
    // the cirisnode-payload path where the subjects are NOT yet signed
    // state). This is the "already signed-state, leave it" case
    // (CIRISRegistry#96 follow-on note).
    let duty_holders =
        duty_holders_from_signed_subjects(directory, &row.subject_key_ids, community_id, duty)
            .await?;
    check_moderation_admission(
        directory,
        &row.attesting_key_id,
        &duty_holders,
        duty,
        dimension,
    )
    .await
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
}
