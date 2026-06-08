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
) -> Result<(), Error> {
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
