//! (CIRISPersist#519 item 3) — the **invariant-registry admission
//! enforcement + consistency witness**.
//!
//! The vendored manifest (`namespace_supersets.json`, see
//! [`super::namespace::supersets`]) carries an `invariant_registry`: 104
//! CC-3.1 families → 571 constitutional invariants, each a
//! `{rule, cc_ref, quote, primitive_constraint}` tuple produced by a
//! constitution-grounded semantic walk. **Most of these invariants are
//! consumer-applied** — scorer aggregation rules (median-not-mean,
//! never-sole-evidence, aggregate-forbidden), witness-diversity math,
//! consumer re-checks. Persist's admission gate never sees a composer's
//! aggregation step, so it cannot enforce those, and this module does not
//! pretend to.
//!
//! This module's job is narrower and two-part:
//!
//! 1. **The typed reader** ([`invariants_for`]) + a heuristic classifier
//!    ([`admission_enforceable`]) that surfaces the CANDIDATE subset of
//!    invariants shaped like something persist's admission gate — not a
//!    downstream composer — could plausibly check: a reserved-identity-type
//!    emitter rule, an attester-must-not-equal-attested self-emission ban, a
//!    closed/exhaustive vocabulary check.
//! 2. **The consistency witness**
//!    ([`tests::manifest_reserved_invariants_match_persist_admission`]) — the
//!    highest-value deliverable here. Persist already hardcodes a
//!    substantial reserved-prefix admission surface
//!    ([`super::admission::default_reserved_prefix_rules`] +
//!    the `accord:`/`hard_case:` special cases inside
//!    [`super::admission::check_reserved_prefix_admission`]). This witness
//!    *executes* that real gate against every family the manifest declares
//!    reserved-to-an-identity-type and asserts the code enforces the SAME
//!    reservation — so the vendored governance record and the hardcoded
//!    admission code cannot silently drift apart, in EITHER direction (a
//!    manifest reservation with no matching code, or code that reserves a
//!    family the manifest says is open, both fail the build).
//!
//! # What this cut newly enforces (honest accounting)
//!
//! Cross-referencing all 104 families against persist's existing admission
//! surface found that **every identity-type-reserved family the manifest
//! declares is already enforced** — `accord:*` (accord_holder), the four
//! `substrate-self-report` families (`audit_chain:` / `corpus_health:` /
//! `identity_continuity:` / `federation_directory:` → substrate_persist),
//! `hard_case:{kind}` (substrate_persist), `capacity_assurance:*` and
//! `transparency_log:cosigned:*` (witness), and all six
//! `detection:*` leaves (lenscore_detector) — see
//! [`tests::manifest_reserved_invariants_match_persist_admission`] for the
//! executed proof. **That witness is this cut's primary value**: no new
//! identity-type gate was invented, because none was missing.
//!
//! One genuine, narrowly-scoped gap DID surface: the manifest's own
//! `health:liveness:{version}` family walk names an unenforced self-emission
//! ban — *"witness_relation MUST be external - a service never attests its
//! own liveness under this family"* (CC 3.1.9.4 / CC 3.4.3) — and its
//! `placement_fields_required` entry literally proposes the fix: *"admission.rs
//! #check_reserved_prefix_admission - add a health:liveness: arm rejecting
//! attester==attested (mirrors existing capacity/age arms; absent today)"*.
//! [`enforce_admission_invariants`] adds exactly that one arm, mirroring
//! [`super::admission::Error::CapacitySelfEmissionRejected`] /
//! [`super::admission::Error::AgeAssuranceSelfEmissionRejected`]'s existing
//! attester==attested shape (reusing [`super::admission::Error::DimensionRejected`]
//! with a new reason token rather than a new `Error` variant — the
//! `pyo3.rs` FFI boundary matches `Error::DimensionRejected { .. }` by
//! shape, so a new *reason* token needs no FFI-side change; a new `Error`
//! variant would).
//!
//! # Explicitly consumer-owned (documented, NOT built here)
//!
//! - **`testimonial_witness:{kind}`'s "never sole evidence for slashing"** —
//!   the exemplar CIRISPersist#519 item 3 names as consumer-side: persist's
//!   admission gate stores one row at a time and never sees the aggregation
//!   step a `slashing:*` composer runs across many attestations, so it
//!   cannot enforce a NEVER-ALONE property. Same reasoning excludes
//!   `ratchet:flag:*` / `hard_case:*`'s "never sole input to slashing"
//!   invariants, and every median-vs-mean / aggregate-forbidden /
//!   aggregate-required composition rule across the 104 families.
//! - **Witness-diversity / corroboration math** (`witness_diversity:*`,
//!   `moderation_track_record:*`) — a fold over MULTIPLE rows a composer
//!   reads back, not a single-row admission predicate.
//! - **`capacity_assurance:*`'s panel-M-of-N / reversible-exclusion /
//!   apophatic-floor / auto-lapse invariants** — real admission-shaped rules,
//!   but already substrate-enforced by a DIFFERENT, pre-existing gate
//!   ([`super::admission::check_adult_incapacity_binding`]'s
//!   `attester_conflicted` / `capacity_reversible_not_excluded` checks), not
//!   this module — see the consistency witness for how the identity-type
//!   HALF of that family's reservation (witness-only emission) cross-checks
//!   against [`super::admission::default_reserved_prefix_rules`].
//! - **`delivery:{class}` / `peer_reachability:{network}`** — the manifest
//!   marks these `identity_type=substrate_edge`-reserved, but `substrate_edge`
//!   is not a registered [`super::types::identity_type`] constant anywhere in
//!   persist (these are CIRISEdge-owned families per the manifest's
//!   `owning_repo`, and the manifest's own text flags the gate as
//!   "currently UNIMPLEMENTED... verified" / "gate absent in code" — a
//!   known, already-declared gap, not something this cut invents a fake
//!   enforcement for).
//! - **`system:*` / `content_rating:*` / `content_class:*` / `cw_class:*` /
//!   `age_assurance:*`** — persist DOES reserve these (CEG 0.2/0.3 §7.x,
//!   [`super::admission::default_reserved_prefix_rules`]), but they are
//!   CEG-defined, not CC-Constitution-defined, so they are absent from this
//!   CC-grounded `invariant_registry` entirely (confirmed: neither the 104
//!   `invariant_registry` families nor the 95
//!   [`super::namespace::registry`] families name them). Nothing to
//!   cross-check — the manifest is silent about them by construction, not by
//!   omission.

use super::namespace::supersets;
use super::Error;
use serde::Deserialize;

/// One family's invariant entry — the typed mirror of an
/// `invariant_registry[family][i]` element.
#[derive(Debug, Clone, Deserialize)]
pub struct FamilyInvariant {
    /// The constitutional rule, in prose.
    pub rule: String,
    /// The CC section(s) grounding the rule (e.g. `"CC 3.4.1 / CC 4.2.1.3"`).
    pub cc_ref: String,
    /// A verbatim quote from the Constitution, when the walk recorded one.
    /// Empty string when absent (the manifest omits the key entirely for
    /// many entries; `#[serde(default)]` normalizes that to `""`).
    #[serde(default)]
    pub quote: String,
    /// The machine-checkable shape the rule reduces to — the field this
    /// module's classifier and the consistency witness both read.
    pub primitive_constraint: String,
}

/// The [`FamilyInvariant`]s the manifest records for `family_prefix` (the
/// literal `invariant_registry` key, e.g. `"accord:*"`,
/// `"capacity:composite"`, `"health:liveness:{version}"`) — an exact-key
/// lookup into [`supersets::invariant_registry`]. Returns `[]` for a family
/// not in the vendored cut (unknown family, or a typo — the same "absent
/// means empty, not an error" convention
/// [`supersets::field_processor_matrix`] readers use).
pub fn invariants_for(family_prefix: &str) -> Vec<FamilyInvariant> {
    supersets::invariant_registry()
        .get(family_prefix)
        .and_then(|v| serde_json::from_value::<Vec<FamilyInvariant>>(v.clone()).ok())
        .unwrap_or_default()
}

/// Keyword vocabulary [`admission_enforceable`] scans `primitive_constraint`
/// for, case-insensitively. Chosen because each keyword is how the manifest's
/// semantic walk phrases an admission-SHAPED constraint: `"reserved"` /
/// `"identity_type"` (a reserved-prefix emitter rule), `"attester"` / `"self"`
/// (an attester==attested self-emission ban), `"closed"` / `"exhaustive"` (a
/// closed-vocabulary / exhaustive-match structural check).
const ADMISSION_ENFORCEABLE_KEYWORDS: &[&str] = &[
    "reserved",
    "identity_type",
    "attester",
    "self",
    "closed",
    "exhaustive",
];

/// Does `inv`'s `primitive_constraint` look admission-time
/// persist-enforceable?
///
/// **This is a deliberately OVER-INCLUSIVE candidate heuristic, not a final
/// enforcement decision.** A plain keyword OR-match cannot tell
/// *"self-emission FORBIDDEN"* (an admission-time ban) apart from
/// *"self-emission ALLOWED; never apply attesting!=attested enforcement"*
/// (an explicit DO-NOT-ENFORCE signal that also contains "self") — both hit
/// the `"self"` keyword. Real families in the vendored manifest exhibit both
/// phrasings (contrast `capacity:core_identity`'s "FORBIDDEN self-attestation"
/// with `conscience:coherence`'s "self-emission ALLOWED/expected; never
/// apply attesting!=attested enforcement" — the classifier flags BOTH as
/// candidates). Turning a candidate flag into an actual admission gate
/// requires reading the invariant's prose and cross-checking persist's
/// existing gates by hand — exactly what the module doc's "what this cut
/// newly enforces" section and the consistency witness below do for the
/// families that turned out to matter. Use this function to FIND invariants
/// worth that manual read, never to auto-wire enforcement from the boolean
/// alone.
pub fn admission_enforceable(inv: &FamilyInvariant) -> bool {
    let pc = inv.primitive_constraint.to_ascii_lowercase();
    ADMISSION_ENFORCEABLE_KEYWORDS
        .iter()
        .any(|kw| pc.contains(kw))
}

/// Family-prefixes whose `invariant_registry` entry demands an
/// attester-must-not-equal-attested admission rule that, as of this cut, NO
/// EXISTING persist gate enforces (verified by direct read of
/// [`super::admission::check_reserved_prefix_admission`] /
/// [`super::admission::default_reserved_prefix_rules`] — see the module doc's
/// "what this cut newly enforces"). Each entry is a literal `attestation_type`
/// prefix (matched via `starts_with`, mirroring
/// [`super::admission::ReservedPrefixRule::pattern_prefix`]'s match
/// semantics).
///
/// Exactly one entry today: `health:liveness:{version}`'s "witness_relation
/// MUST be external - a service never attests its own liveness under this
/// family" (CC 3.1.9.4 / CC 3.4.3), which the manifest's own
/// `placement_fields_required` names as the proposed fix for a documented,
/// currently-unenforced gap. Extending this list is a deliberate per-family
/// decision (add the prefix here, add a fail-closed witness in
/// [`tests`] mirroring [`tests::health_liveness_self_emission_rejected`]) —
/// never something [`admission_enforceable`]'s heuristic drives
/// automatically.
const NEWLY_ENFORCED_SELF_EMISSION_PREFIXES: &[&str] = &["health:liveness:"];

/// The reason token [`enforce_admission_invariants`] rejects under, carried
/// on [`Error::DimensionRejected`]'s `reason` field. Not a
/// [`super::admission::DimensionRejectionReason`] variant — that enum's
/// `as_str()` values are for gate-shape rejections `DimensionAdmissionPolicy`
/// itself defines; this is a distinct, invariant-registry-attributed reason
/// so a caller inspecting the string can tell the two provenances apart.
const INVARIANT_SELF_EMISSION_REASON: &str = "invariant_registry_self_emission_forbidden";

/// The admission-time enforcement half of this cut: apply the
/// [`NEWLY_ENFORCED_SELF_EMISSION_PREFIXES`] self-emission ban(s) for the
/// row's family. Called from
/// [`super::admission::check_reserved_prefix_admission`] — the SAME
/// chokepoint every backend's `put_attestation` already runs
/// (`check_reserved_prefix_admission` is backend-symmetric across memory /
/// sqlite / postgres), so this rides that existing wiring rather than adding
/// a second call site.
///
/// `dimension` is the row's `attestation_type` (the same value
/// `check_reserved_prefix_admission` calls `at` internally — see that
/// function's own `Error::DimensionRejected { dimension: at.to_owned(), .. }`
/// use for precedent that this codebase's `dimension` field names the
/// attestation_type axis at this chokepoint, not the nested `scores`
/// envelope `dimension`). `identity_types` is reserved for a FUTURE
/// identity-type-based invariant enforced at this same call site; today's
/// one newly-enforced invariant is a pure attester==attested check and does
/// not consult it (no directory lookup is spent — the "cheapest-most-
/// specific-rejection-first" discipline the sibling capacity/age arms in
/// `check_reserved_prefix_admission` already follow).
pub fn enforce_admission_invariants(
    dimension: &str,
    attesting_key_id: &str,
    attested_key_id: &str,
    _identity_types: &str,
) -> Result<(), Error> {
    for prefix in NEWLY_ENFORCED_SELF_EMISSION_PREFIXES {
        if dimension.starts_with(prefix) && attesting_key_id == attested_key_id {
            return Err(Error::DimensionRejected {
                dimension: dimension.to_owned(),
                reason: INVARIANT_SELF_EMISSION_REASON,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::types::{attestation_tier, identity_type};
    use crate::federation::{Attestation, FederationDirectory, KeyRecord, SignedKeyRecord};
    use crate::store::memory::MemoryBackend;

    // ── shared test fixtures ────────────────────────────────────────────

    fn fix_key(key_id: &str, identity_type_value: &str) -> KeyRecord {
        let (ed_pk, mldsa_pk) =
            crate::federation::tier_ingest::test_support::hybrid_pubkeys(key_id);
        let mut row = KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: identity_type_value.into(),
            identity_ref: key_id.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
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
        };
        // v22.0.0 (CIRISPersist#543) — an `accord_holder` claim is
        // `ConferralMode::HardwareAttested`, so it needs real evidence on
        // EVERY backend (memory included, as of #543). Satisfy the gate, do
        // not bypass it.
        crate::federation::hardware_attestation::test_support::attach_accord_holder_evidence(
            &mut row,
        );
        row
    }

    fn fix_attestation(id: &str, attn_type: &str, attesting: &str, attested: &str) -> Attestation {
        Attestation {
            attestation_id: id.into(),
            attesting_key_id: attesting.into(),
            attested_key_id: attested.into(),
            attestation_type: attn_type.into(),
            weight: Some(1.0),
            asserted_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "id": id,
                "dimension": "identity_binding:v1",
                "score": 1.0,
                "confidence": 0.9,
            }),
            original_content_hash: "abc123".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: attesting.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
        }
    }

    /// Register `key_id` carrying `identity_type_value`.
    ///
    /// v22.0.0 (CIRISPersist#543) — an `identity_type` whose `ConferralMode` is
    /// `AccordCoScrubbed` (`trusted_publisher` / `lenscore_detector`: claims
    /// ABOUT A THIRD PARTY) may not be self-asserted at any `federation_keys`
    /// write chokepoint, so the fixture confers it for real — a genesis accord
    /// roster standing in the test directory co-scrubs the record to the family
    /// m-of-n. Every other type still registers self-scrubbed, which is what
    /// the gate permits.
    async fn register(backend: &MemoryBackend, key_id: &str, identity_type_value: &str) {
        let record = fix_key(key_id, identity_type_value);
        let accord_conferred = identity_type::parse_set(identity_type_value)
            .iter()
            .any(|t| {
                identity_type::conferral_mode(t)
                    == Some(identity_type::ConferralMode::AccordCoScrubbed)
            });
        if accord_conferred {
            crate::federation::operational::test_support::put_accord_conferred_key(backend, record)
                .await
                .unwrap();
        } else {
            backend
                .put_public_key(SignedKeyRecord { record })
                .await
                .unwrap();
        }
    }

    // ── §1 typed reader + classifier ────────────────────────────────────

    /// `invariants_for` reads a known family's invariants straight out of
    /// the vendored manifest — `accord:*` (7 invariants; see the module's
    /// own accounting of the 571-invariant / 104-family cut).
    #[test]
    fn invariants_for_reads_the_family() {
        let invs = invariants_for("accord:*");
        assert!(!invs.is_empty(), "accord:* must carry known invariants");
        assert!(
            invs.iter()
                .any(|i| i.primitive_constraint.contains("accord_holder")),
            "accord:* invariants must name its accord_holder reservation: {invs:?}"
        );
        // Unknown family → empty, not a panic/error.
        assert!(invariants_for("totally:made:up:family").is_empty());
    }

    /// The classifier is intentionally an OR of keyword hits — a couple of
    /// representative positive/negative cases.
    #[test]
    fn admission_enforceable_classifier() {
        // Positive: accord:*'s first invariant literally says "reserved
        // identity_type=... exhaustive compile-time match".
        let accord = &invariants_for("accord:*")[0];
        assert!(
            accord.primitive_constraint.contains("reserved")
                && accord.primitive_constraint.contains("exhaustive")
        );
        assert!(admission_enforceable(accord));

        // Negative: bond_posted:{currency} carries invariants with none of
        // the 6 keywords (pure aggregation-composer / compile-time-shape
        // prose, nothing self/attester/reserved-shaped).
        let bond = invariants_for("bond_posted:{currency}");
        let clean = bond
            .iter()
            .find(|i| {
                i.primitive_constraint
                    .contains("no un-forfeit primitive exists")
            })
            .expect("bond_posted:{currency} carries the expected forfeiture invariant");
        assert!(
            !admission_enforceable(clean),
            "{:?}",
            clean.primitive_constraint
        );
    }

    // ── §1 the consistency witness (the load-bearing deliverable) ───────

    /// One manifest-declared reserved-identity-type fact: a family, a
    /// concrete `attestation_type` sample under it, and the identity_type
    /// persist's admission gate must require. Hand-verified against BOTH
    /// the manifest text (asserted in this test) AND persist's actual
    /// `check_reserved_prefix_admission` behavior (executed in this test) —
    /// every family the manifest marks reserved-to-an-identity-type that
    /// persist can plausibly enforce (CC-catalogued, not a CIRISEdge/CEG-only
    /// family — see the module doc).
    struct ReservedFact {
        family: &'static str,
        sample_attestation_type: &'static str,
        required_identity_type: &'static str,
        /// The literal substring corroborating this reservation in the
        /// family's `rule` / `primitive_constraint` text. Usually equal to
        /// `required_identity_type`; a couple of `detection:*` leaves state
        /// the reservation via the generalized wildcard ("LensCore-only" /
        /// "reserved-emitter gate REQUIRED... for ANY detection:* dimension")
        /// rather than repeating the literal role token per leaf, so those
        /// use the phrase actually present instead.
        manifest_marker: &'static str,
    }

    const RESERVED_FACTS: &[ReservedFact] = &[
        ReservedFact {
            family: "accord:*",
            sample_attestation_type: "accord:invoke:notify:halt",
            required_identity_type: identity_type::ACCORD_HOLDER,
            manifest_marker: identity_type::ACCORD_HOLDER,
        },
        ReservedFact {
            family: "hard_case:{kind}",
            sample_attestation_type: "hard_case:community_lapse",
            required_identity_type: identity_type::SUBSTRATE_PERSIST,
            manifest_marker: identity_type::SUBSTRATE_PERSIST,
        },
        ReservedFact {
            family: "audit_chain:hash_continuity",
            sample_attestation_type: "audit_chain:hash_continuity",
            required_identity_type: identity_type::SUBSTRATE_PERSIST,
            manifest_marker: identity_type::SUBSTRATE_PERSIST,
        },
        ReservedFact {
            family: "corpus_health:n_eff_measurable",
            sample_attestation_type: "corpus_health:n_eff_measurable",
            required_identity_type: identity_type::SUBSTRATE_PERSIST,
            manifest_marker: identity_type::SUBSTRATE_PERSIST,
        },
        ReservedFact {
            family: "identity_continuity:relational_anchor",
            sample_attestation_type: "identity_continuity:relational_anchor",
            required_identity_type: identity_type::SUBSTRATE_PERSIST,
            manifest_marker: identity_type::SUBSTRATE_PERSIST,
        },
        ReservedFact {
            family: "federation_directory:replication_lag",
            sample_attestation_type: "federation_directory:replication_lag",
            required_identity_type: identity_type::SUBSTRATE_PERSIST,
            manifest_marker: identity_type::SUBSTRATE_PERSIST,
        },
        ReservedFact {
            family: "transparency_log:cosigned:{tree_size}",
            sample_attestation_type: "transparency_log:cosigned:100",
            required_identity_type: identity_type::WITNESS,
            manifest_marker: identity_type::WITNESS,
        },
        ReservedFact {
            family: "capacity_assurance:*",
            sample_attestation_type: "capacity_assurance:financial:v1",
            required_identity_type: identity_type::WITNESS,
            manifest_marker: identity_type::WITNESS,
        },
        ReservedFact {
            family: "detection:correlated_action:{axis}",
            sample_attestation_type: "detection:correlated_action:voting",
            required_identity_type: identity_type::LENSCORE_DETECTOR,
            manifest_marker: identity_type::LENSCORE_DETECTOR,
        },
        ReservedFact {
            family: "detection:distributive:access:{resource_type}",
            sample_attestation_type: "detection:distributive:access:compute",
            required_identity_type: identity_type::LENSCORE_DETECTOR,
            manifest_marker: identity_type::LENSCORE_DETECTOR,
        },
        ReservedFact {
            family: "detection:conscience_override_rate",
            sample_attestation_type: "detection:conscience_override_rate",
            required_identity_type: identity_type::LENSCORE_DETECTOR,
            // This leaf's own text states the reservation via the
            // generalized wildcard, not the literal role token.
            manifest_marker: "reserved-emitter gate REQUIRED",
        },
        ReservedFact {
            family: "detection:cross_agent_divergence",
            sample_attestation_type: "detection:cross_agent_divergence",
            required_identity_type: identity_type::LENSCORE_DETECTOR,
            manifest_marker: identity_type::LENSCORE_DETECTOR,
        },
        ReservedFact {
            family: "detection:hash_chain_integrity",
            sample_attestation_type: "detection:hash_chain_integrity",
            required_identity_type: identity_type::LENSCORE_DETECTOR,
            manifest_marker: identity_type::LENSCORE_DETECTOR,
        },
        ReservedFact {
            family: "detection:intra_agent_consistency",
            sample_attestation_type: "detection:intra_agent_consistency",
            required_identity_type: identity_type::LENSCORE_DETECTOR,
            manifest_marker: identity_type::LENSCORE_DETECTOR,
        },
        ReservedFact {
            family: "detection:temporal_drift",
            sample_attestation_type: "detection:temporal_drift",
            required_identity_type: identity_type::LENSCORE_DETECTOR,
            // States the reservation as "LensCore-only", not the literal
            // `lenscore_detector` token.
            manifest_marker: "LensCore-only",
        },
    ];

    /// THE load-bearing witness. For every [`RESERVED_FACTS`] entry: (a) the
    /// manifest text itself must name the required identity_type token
    /// (guards the curated fixture against silently drifting from the
    /// vendored manifest — if a re-vendor stops saying "witness" for
    /// `capacity_assurance:*`, this fails FIRST); (b) persist's REAL
    /// `check_reserved_prefix_admission` gate — executed here, not
    /// re-implemented — must reject a non-required-identity emitter and
    /// admit (past the identity check) the required-identity emitter.
    /// A manifest reservation with no matching persist rule, or a persist
    /// rule the manifest doesn't corroborate, fails this test.
    #[tokio::test]
    async fn manifest_reserved_invariants_match_persist_admission() {
        use crate::federation::admission::check_reserved_prefix_admission;

        let backend = MemoryBackend::new();
        register(&backend, "wia-wrong-agent", identity_type::AGENT).await;
        register(&backend, "wia-target", identity_type::AGENT).await;
        for it in [
            identity_type::ACCORD_HOLDER,
            identity_type::SUBSTRATE_PERSIST,
            identity_type::WITNESS,
            identity_type::LENSCORE_DETECTOR,
        ] {
            register(&backend, &format!("wia-right-{it}"), it).await;
        }

        for fact in RESERVED_FACTS {
            // (a) manifest corroboration — the required identity_type token
            // is actually named somewhere in this family's invariant text.
            let invs = invariants_for(fact.family);
            assert!(
                !invs.is_empty(),
                "manifest carries no invariants for {:?} — RESERVED_FACTS is stale",
                fact.family
            );
            assert!(
                invs.iter()
                    .any(|i| i.primitive_constraint.contains(fact.manifest_marker)
                        || i.rule.contains(fact.manifest_marker)),
                "{:?}'s manifest text no longer contains {:?} — re-verify RESERVED_FACTS \
                 against the re-vendored manifest",
                fact.family,
                fact.manifest_marker
            );

            // (b) persist's REAL gate rejects the wrong identity...
            let wrong = fix_attestation(
                "wia-att",
                fact.sample_attestation_type,
                "wia-wrong-agent",
                "wia-target",
            );
            check_reserved_prefix_admission(&backend, &wrong)
                .await
                .expect_err(&format!(
                    "{:?} (attestation_type={:?}) must reject a non-{:?} emitter — \
                     manifest reservation with no matching persist rule",
                    fact.family, fact.sample_attestation_type, fact.required_identity_type
                ));

            // ...and admits (past the identity check) the required identity.
            let right_key = format!("wia-right-{}", fact.required_identity_type);
            let right = fix_attestation(
                "wia-att",
                fact.sample_attestation_type,
                &right_key,
                "wia-target",
            );
            check_reserved_prefix_admission(&backend, &right)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "{:?} (attestation_type={:?}) rejected its OWN required identity \
                         {:?}: {e} — persist rule diverged from the manifest reservation",
                        fact.family, fact.sample_attestation_type, fact.required_identity_type
                    )
                });
        }
    }

    /// The "vice versa" direction on a concrete, manifest-named case: the
    /// manifest explicitly says `transparency_log:inclusion` is NOT
    /// witness-reserved ("admission MUST NOT require witness in
    /// identity_type for inclusion/consistency; that gate applies solely to
    /// cosigned:*"). Confirms persist agrees — an ordinary `agent` key's
    /// `transparency_log:inclusion` attestation must NOT be rejected for
    /// identity reasons (an over-restrictive persist rule here would be
    /// drift the other direction: code more restrictive than the governance
    /// record permits).
    #[tokio::test]
    async fn transparency_log_inclusion_is_not_witness_reserved() {
        use crate::federation::admission::check_reserved_prefix_admission;
        let invs = invariants_for("transparency_log:inclusion");
        assert!(
            invs.iter()
                .any(|i| i.primitive_constraint.contains("MUST NOT require witness")),
            "manifest text for transparency_log:inclusion changed — re-verify this witness"
        );

        let backend = MemoryBackend::new();
        register(&backend, "tli-agent", identity_type::AGENT).await;
        register(&backend, "tli-target", identity_type::AGENT).await;
        let row = fix_attestation(
            "tli-att",
            "transparency_log:inclusion",
            "tli-agent",
            "tli-target",
        );
        check_reserved_prefix_admission(&backend, &row)
            .await
            .expect(
                "transparency_log:inclusion must NOT be identity-reserved — \
                 the manifest is explicit that only cosigned:* is",
            );
    }

    // ── §2 the one newly-enforced invariant ──────────────────────────────

    /// Fail-closed: `health:liveness:*` self-emission (attester==attested)
    /// is now rejected at the real chokepoint — the one gap this cut closes
    /// (see the module doc + the manifest's own proposed-fix citation).
    /// Mirrors [`super::super::admission::tests`]'s existing
    /// capacity/age self-emission witnesses in shape (real fixtures, no
    /// hand-faked signatures — the gate under test never inspects the row's
    /// own signature).
    #[tokio::test]
    async fn health_liveness_self_emission_rejected() {
        use crate::federation::admission::check_reserved_prefix_admission;
        let backend = MemoryBackend::new();
        register(&backend, "hl-self", identity_type::AGENT).await;
        let row = fix_attestation("hl-att", "health:liveness:v1", "hl-self", "hl-self");
        let err = check_reserved_prefix_admission(&backend, &row)
            .await
            .expect_err("health:liveness:* self-emission must be rejected");
        assert_eq!(err.kind(), "federation_dimension_rejected");
        assert!(format!("{err}").contains(INVARIANT_SELF_EMISSION_REASON));
    }

    /// Positive control: a legitimate cross-subject `health:liveness:*`
    /// observation (an external monitor attesting about a DIFFERENT keyed
    /// service) is NOT caught by the new arm — only genuine self-emission
    /// is rejected, exactly as CC 3.1.9.4 requires ("a service never
    /// attests its OWN liveness"; a third party observing it is the normal,
    /// expected case).
    #[tokio::test]
    async fn health_liveness_cross_subject_still_admitted() {
        use crate::federation::admission::check_reserved_prefix_admission;
        let backend = MemoryBackend::new();
        register(&backend, "hl-monitor", identity_type::AGENT).await;
        register(&backend, "hl-observed", identity_type::AGENT).await;
        let row = fix_attestation("hl-att", "health:liveness:v1", "hl-monitor", "hl-observed");
        check_reserved_prefix_admission(&backend, &row)
            .await
            .expect("a third-party health:liveness observation must still admit");
    }

    /// Direct unit coverage of [`enforce_admission_invariants`] itself
    /// (no directory needed — the check is a pure string/equality test).
    #[test]
    fn enforce_admission_invariants_self_emission_gate() {
        assert!(enforce_admission_invariants("health:liveness:v1", "k", "k", "").is_err());
        assert!(enforce_admission_invariants("health:liveness:v1", "k1", "k2", "").is_ok());
        // Unrelated families are untouched (no-op today — see module doc).
        assert!(enforce_admission_invariants("capacity:composite", "k", "k", "").is_ok());
    }
}
