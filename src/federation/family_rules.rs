//! (CIRISPersist#519 / #520) — **the family-rule inventory**: every namespace
//! family persist states an emitter/composition rule about in its own code, and
//! whether the vendored registry states that rule too.
//!
//! # The question this module answers
//!
//! [`super::namespace::registry`] answers *which families exist and what rule CC
//! states for them*. [`super::admission`] answers *is this row admissible*.
//! Neither answers the question that keeps going wrong:
//!
//! > **Which families does persist rule on that nothing else can see?**
//!
//! A family in that set has two validators — persist's gate and
//! [`authority_for`](registry::authority_for) — that disagree about whether it
//! is governed, and only one of them is written where a consumer can read it.
//! `authority_for` answers `reserved: None`, so a downstream reading the
//! classifier concludes the family is open while persist refuses non-conformant
//! emissions on it. That is the two-lists-that-quietly-disagree class (#541 /
//! #532 / #588 / #590), and the reason it survived is that **the left-hand list
//! never existed**: there were enumerations of the particular tables persist
//! rules *from*, and no enumeration of what persist rules *on*.
//!
//! CIRISPersist#590 built the first slice of it — [`RULES_NOT_ON_THE_ROW`]'s
//! `minted_by_persist` entries — scoped to the three families persist is the
//! PRODUCER of, because CC 3.1.7 R2(a) is a producer obligation. R2(a) is not
//! the whole exposure. Measured on the vendored rc3 cut, the minted set is **4
//! of 19** (three from #590, plus `mesh_config:` — CIRISPersist#570 ask 1).
//!
//! # What is derived and what is pinned
//!
//! The left side is **derived**, never re-listed —
//! [`persist_ruled_prefixes`] reads every ruling surface at its own source:
//!
//! - [`super::admission::default_reserved_prefix_rules`] — the identity-type
//!   prefix table;
//! - [`super::admission::HARD_CODED_RESERVED_STEMS`] — the families gated by
//!   hand-written arms rather than a table row;
//! - [`super::admission::MINTED_NAMESPACE_FAMILIES`] — persist's producer
//!   declaration (itself cross-checked against the minting modules' consts);
//! - [`super::replication::admission::RESERVED_CLASS_DIMENSION_PREFIXES`] — the
//!   #575 quota reserve;
//! - the **purpose-built gates**, each read at the const its own gate branches
//!   on: [`super::admission::MODERATION_DIMENSION_PREFIX`],
//!   [`super::admission::RECONSIDERATION_DIMENSION_PREFIX`],
//!   [`super::admission::QUARANTINE_DIMENSION_PREFIX`],
//!   [`super::admission::PEER_DEADMISSION_DIMENSION`],
//!   [`super::admission::ATTESTATION_LADDER_DEPRECATED_PREFIX`],
//!   [`super::invariant::NEWLY_ENFORCED_SELF_EMISSION_PREFIXES`] and
//!   [`registry::ACCORD_CO_SCRUB_MATCH_PREFIX`].
//!
//! Only the **gap** is pinned. [`RULES_NOT_ON_THE_ROW`] carries one entry per
//! ruled prefix the registry is silent about, with the rule persist applies,
//! the code site(s) that apply it, and the CC ask that would land it.
//! [`tests::every_ruled_prefix_states_its_rule_somewhere`] fails when a ruled
//! prefix is neither registry-ruled nor pinned;
//! [`tests::pinned_rules_are_still_missing_from_the_registry`] fails when a pin
//! outlives the gap it names.
//!
//! # Why a source scan closes the loop
//!
//! The derivation above still contains one hand-maintained fact: *which consts
//! to read*. A new purpose-built gate keyed on a literal nobody added here
//! would be invisible to it — the same failure one level up.
//!
//! [`tests::every_admission_shaped_prefix_literal_is_classified`] removes that
//! degree of freedom. It scans persist's non-test source for family-shaped
//! string literals in admission-shaped positions (`starts_with` / `strip_prefix`
//! arguments, and `PREFIX` / `DIMENSION` / `FAMILY` / `NAMESPACE` consts) and
//! requires every family stem it finds to be one of three things: **ruled** by
//! persist per the derivation, **ruled** by the vendored registry, or
//! **declared not a family rule** ([`NOT_A_FAMILY_RULE`], with the reason).
//! Over-reporting is the safe direction — a scan hit costs one classified line;
//! a missed gate costs the class this module exists to close. It has already
//! paid: `attestation:`'s CEG-0.1 ladder rule was found by the scan, not by
//! anyone remembering it.
//!
//! # The wider population this inventory does NOT cover
//!
//! [`RULES_NOT_ON_THE_ROW`] is the set persist *rules on* and CC does not. It is
//! a small corner of a much larger silence: on the vendored rc3 cut **34 of 109**
//! families carry a machine-readable rule, so **75 do not**, spread across **14
//! CC sections with none at all** (3.1.5.1-4, 3.1.6, 3.1.8.3, 3.1.9.1-7,
//! 3.1.10). Most of those 75 are nobody's gate — persist has no opinion about
//! them and this module correctly says nothing. The measurement is kept as a
//! floor-check in
//! [`admission::tests::most_of_the_manifest_carries_no_machine_readable_rule`]
//! so the scope limit stays a fact in the build, and the general ask is
//! CIRISConstitution#67 (the generator's rule coverage), not 17 rows.
//!
//! Persist named one instance of this class before anyone named the class:
//! [`super::invariant`]'s module doc records that the supersets walk asserts a
//! `health:liveness:{version}` self-emission ban CC never put in a
//! machine-readable field, and that the manifest's own
//! `placement_fields_required` entry proposed the remedy verbatim — which #519
//! implemented as a single arm. One instance, seen and fixed; the class,
//! enumerated here.
//!
//! # Two prose claims that were wrong, checked
//!
//! - #590's scope note asserted persist hand-gates *"`moderation:` and
//!   `slashing:` through
//!   [`check_moderation_admission`](super::admission::check_moderation_admission)'s
//!   duty-holder walk"*. Executed:
//!   [`super::admission::check_delegated_duty_scores_admission`] routes
//!   `moderation:` → `moderate`, `reconsideration:` → `review` and
//!   `quarantine:` → `slash`. **`slashing:` is not gated at admission by
//!   persist at all** — the only `slashing` surface in the crate is the
//!   `cirisnode`-feature-gated typed table, a different plane. The two families
//!   persist gates there and had never enumerated are `moderation:` and
//!   `reconsideration:`. Pinned by
//!   [`tests::slashing_is_not_a_persist_ruled_family`] so the correction cannot
//!   rot back.
//! - The sharpest entry in the inventory is
//!   `provenance:build_manifest`: `registry::class_for` hardcodes
//!   `AuthorityClass::AccordCoScrub` for it, so **the manifest-derived
//!   classifier returns an authority the manifest never stated**. A hand-written
//!   rule inside the artifact whose entire job is to be derived is the class
//!   this program exists to close, at its own source.

use super::admission;
use super::namespace::registry;

/// **Why the registry does not state the rule persist applies.** Three
/// branches, because they carry different asks and different risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowRuleGap {
    /// The family's registry row exists and carries **no** machine-readable
    /// `reserved_rule` at all — [`authority_for`](registry::authority_for)
    /// resolves `reserved: None` for every dimension in the family. The rule
    /// may well be written in the row's `description` prose; prose is not a
    /// registered rule, because nothing parses prose.
    NoRuleOnTheRow,
    /// The registry states rules only for **individually catalogued leaf
    /// dimensions**, while persist's gate covers the whole family prefix. The
    /// catalogued dimensions resolve correctly; anything else in the family
    /// persist gates resolves to nothing.
    ///
    /// The direction here is *safe* — persist is stricter than the classifier,
    /// never laxer — but it is still two validators with different predicates
    /// over one artifact, and it is precisely the shape CIRISPersist#379 fixed
    /// from the other side (a novel `detection:{newkind}` was wrongly ADMITTED
    /// until someone hand-added its leaf rule). The ask is a family-level rule,
    /// not another leaf.
    RuleOnCataloguedLeavesOnly,
    /// The registry row states no rule, and persist's **classifier** —
    /// `registry::class_for`, the function whose whole job is to derive
    /// authority FROM the manifest — hardcodes an [`AuthorityClass`] for the
    /// family anyway.
    ///
    /// The inverse hazard of the other two: a consumer asking `authority_for`
    /// gets a non-default answer and has no way to learn it came from persist's
    /// source rather than from CC. Nothing downstream can audit it against the
    /// Constitution, because it is not in the Constitution's artifact.
    ///
    /// [`AuthorityClass`]: super::namespace::AuthorityClass
    ClassAssertedByPersistNotTheRow,
}

impl RowRuleGap {
    /// The stable program token. **APPEND-ONLY** — add variants, never
    /// re-spell one.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoRuleOnTheRow => "no_rule_on_the_row",
            Self::RuleOnCataloguedLeavesOnly => "rule_on_catalogued_leaves_only",
            Self::ClassAssertedByPersistNotTheRow => "class_asserted_by_persist_not_the_row",
        }
    }
}

/// One family prefix persist rules on that the vendored registry does not
/// state a rule for.
#[derive(Debug, Clone, Copy)]
pub struct PersistFamilyRule {
    /// The prefix persist's code matches on, spelled exactly as it spells it
    /// (`"moderation:"`, `"health:liveness:"`, `"provenance:build_manifest"`).
    /// Cross-checked against the derived ruled set
    /// ([`tests::pinned_prefixes_are_all_really_ruled`]), so a pin cannot name
    /// a prefix nothing rules on.
    pub prefix: &'static str,
    /// The rule persist applies, in one line.
    pub rule: &'static str,
    /// Every code site that applies it, by `module::path::symbol`.
    ///
    /// A **list**: one family can have several admission doors, and a registry
    /// of enforcement sites that names one of two is the exact thing it exists
    /// to prevent. Each entry must resolve to a real definition in persist's
    /// source ([`tests::pinned_sites_resolve_to_a_definition_in_source`]) —
    /// #590's pin named its gates as free text nothing checked.
    pub enforced_at: &'static [&'static str],
    /// Which shape of gap this is.
    pub gap: RowRuleGap,
    /// True iff persist is the family's PRODUCER
    /// ([`admission::MINTED_NAMESPACE_FAMILIES`]) — the CC 3.1.7 R2(a) subset,
    /// where the obligation to land the rule is persist's own.
    pub minted_by_persist: bool,
    /// The CC ask that would land the rule on the row and delete this entry.
    pub cc_ask: &'static str,
}

/// **The gap inventory.** Every prefix persist rules on for which
/// [`authority_for`](registry::authority_for) states no rule.
///
/// Ordered by gap kind then prefix, so the three populations read as the three
/// different asks they are.
pub const RULES_NOT_ON_THE_ROW: &[PersistFamilyRule] = &[
    // ── NoRuleOnTheRow: the row is silent, so the classifier is too. ───────
    PersistFamilyRule {
        prefix: "x_private:",
        rule: "the CC 3.1.7 Private Use range MUST NOT admit at federation tier under ANY \
               authority, and MUST NOT be promoted to a registered family without minting a \
               fresh name. Local tier admits; promotion and direct federation writes refuse",
        enforced_at: &[
            "federation::admission::check_private_use_not_federatable",
            "federation::admission::check_promotion_admission",
        ],
        gap: RowRuleGap::NoRuleOnTheRow,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 + CIRISPersist#571 Asks 2/3 — R2 states the Private Use \
                 MUST in 3.1.7 PROSE ONLY, names no refusal token where R2(b) names \
                 `namespace_family_unregistered`, and the generator reaches only 3.1 tables. So \
                 every substrate must hard-code the literal and nothing detects two disagreeing: \
                 persist coined `namespace_private_use_not_federatable`. It is not a family, so \
                 the ask is a `_meta` key, not a row",
    },
    PersistFamilyRule {
        prefix: "age_self_declared:",
        rule: "the self rung is a `{band}` — an `age_self_declared:level*` spelling is refused \
               outright, on both the dimension and the attestation_type surface",
        enforced_at: &[
            "federation::admission::check_reserved_prefix_admission",
            "federation::admission::DimensionAdmissionPolicy::check",
        ],
        gap: RowRuleGap::NoRuleOnTheRow,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 (CC 3.4.11's band-not-level rule is stated in prose, not in \
                 the row's reserved_rule)",
    },
    PersistFamilyRule {
        prefix: "attestation:",
        rule: "the canonical wire shape is `attestation:{mechanism}`; the CEG 0.1 ladder form \
               `attestation:l{N}:{mechanism}` is DEPRECATED and admits only while the transition \
               policy says DualAccept",
        enforced_at: &[
            "federation::admission::is_deprecated_attestation_ladder_prefix",
            "federation::admission::DimensionAdmissionPolicy::check",
        ],
        gap: RowRuleGap::NoRuleOnTheRow,
        minted_by_persist: false,
        cc_ask:
            "CIRISConstitution#67 (CC catalogues the five mechanisms and states no shape rule; \
                 the deprecation window lives only in CEG 0.2 §13.1 and in persist)",
    },
    PersistFamilyRule {
        prefix: "mesh_config:",
        rule: "the author is the node's OWN trust root, or a key that root has conferred to by a \
               live `trust:confers:v1` `delegates_to` — never the accord's ceremony plane. Plus \
               the three bounds CC 4.2.1 states on the ACT rather than the emitter: a value may \
               relieve or restrict and never expand what flows; a key naming no consumer \
               processor is refused; emergency relief carries a mandatory TTL of at most 72 h and \
               is not renewable back-to-back by the same holder",
        enforced_at: &[
            "federation::mesh_config::record_mesh_config_row",
            "federation::mesh_config::fold_mesh_config",
        ],
        gap: RowRuleGap::NoRuleOnTheRow,
        minted_by_persist: true,
        cc_ask: "CIRISConstitution#67 — CC 4.2.1 states this rule NORMATIVELY and at length \
                 (CIRISConstitution#57, ratified), and CC 3.1.9.2's row for the family carries \
                 `reserved: false` with no `reserved_rule`, so `authority_for` reports it open. \
                 The root cause is the generator, not the drafting: \
                 `build_cc_namespace.py` derives `reserved_rule` from CC 3.4 cross-references \
                 plus a `Reserved?` table column, and CC 3.1.9.2's table has NEITHER — which is \
                 why `admission::tests::most_of_the_manifest_carries_no_machine_readable_rule` \
                 can assert that EVERY 3.1.9.2 family resolves `reserved: None`. The ask is one \
                 generator predicate covering the whole section, not a reworded row. NOTE the \
                 emitter rule here is a per-node GRAPH question (which root does THIS node \
                 subscribe to), so a `reserved_rule` naming an identity_type could not express \
                 it either; what the row could carry is the trust-root-emitter CLASS",
    },
    PersistFamilyRule {
        prefix: "hard_case:",
        rule: "substrate-emitted — substrate_persist only",
        enforced_at: &["federation::admission::check_reserved_prefix_admission"],
        gap: RowRuleGap::NoRuleOnTheRow,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 (the row states no emitter; persist's substrate-emitter arm \
                 is the only statement of it)",
    },
    PersistFamilyRule {
        prefix: "health:liveness:",
        rule: "witness_relation MUST be external — a service never attests its own liveness \
               (attester != attested)",
        enforced_at: &["federation::invariant::enforce_admission_invariants"],
        gap: RowRuleGap::NoRuleOnTheRow,
        minted_by_persist: false,
        cc_ask:
            "CIRISConstitution#67 (CC 3.1.9.4 / CC 3.4.3; the rule reached persist through the \
                 namespace_supersets walk, never through a reserved_rule)",
    },
    PersistFamilyRule {
        prefix: "moderation:",
        rule: "cohort duty-holder only — the community's NAMED moderators, never the row's own \
               self-declared subjects",
        enforced_at: &[
            "federation::admission::check_delegated_duty_scores_admission",
            "federation::admission::check_moderation_admission",
        ],
        gap: RowRuleGap::NoRuleOnTheRow,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 (CC 4.5.5's target→duty-holder table is normative and \
                 machine-shaped; the row carries none of it)",
    },
    PersistFamilyRule {
        prefix: "objection:",
        rule: "cohort-member-only",
        enforced_at: &["federation::reverse_quorum::record_objection"],
        gap: RowRuleGap::NoRuleOnTheRow,
        minted_by_persist: true,
        cc_ask: "CIRISConstitution#67 (the row itself defers: \"emitter/composition elaboration \
                 rides #67\")",
    },
    PersistFamilyRule {
        prefix: "quarantine:",
        rule: "slash-duty-holder-only",
        enforced_at: &["federation::admission::check_delegated_duty_scores_admission"],
        gap: RowRuleGap::NoRuleOnTheRow,
        minted_by_persist: true,
        cc_ask: "CIRISConstitution#76 (the rule is in the row's description prose, not its \
                 reserved_rule)",
    },
    PersistFamilyRule {
        prefix: "reconsideration:",
        rule: "review duty-holder only — the community's named moderators (CC 4.5.5), never the \
               filer's own self-declared subjects",
        enforced_at: &["federation::admission::check_delegated_duty_scores_admission"],
        gap: RowRuleGap::NoRuleOnTheRow,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 (same CC 4.5.5 table as `moderation:`; the row states \
                 nothing)",
    },
    PersistFamilyRule {
        prefix: "revocation:peer_admission:",
        rule: "self-authored only AT CONSUMPTION — a de-admission is honoured on this node only \
               if THIS node authored it, so a peer cannot de-admit a third party here (AV-77)",
        enforced_at: &["federation::admission::check_peer_deadmission"],
        gap: RowRuleGap::NoRuleOnTheRow,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 (the `revocation:{entity_type}:{reason}` row states no \
                 emitter or whose-copy-counts rule)",
    },
    PersistFamilyRule {
        prefix: "wa_adjudication:",
        rule: "CC 4.3 WA-quorum finding, re-derived from persist's own verified state",
        enforced_at: &["federation::ownership_reclaim::check_ownership_reclaim_admission"],
        gap: RowRuleGap::NoRuleOnTheRow,
        minted_by_persist: true,
        cc_ask: "CIRISConstitution#73",
    },
    // ── RuleOnCataloguedLeavesOnly: the rule exists per leaf; persist's gate
    //    covers the family. Safe direction, still two predicates. ───────────
    PersistFamilyRule {
        prefix: "audit_chain:",
        rule: "substrate_persist-only emitter, for the WHOLE family (CC 3.4.3 \
               substrate-self-report)",
        enforced_at: &["federation::admission::check_reserved_prefix_admission"],
        gap: RowRuleGap::RuleOnCataloguedLeavesOnly,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 (catalogue the rule at the family, not on \
                 `audit_chain:hash_continuity` alone)",
    },
    PersistFamilyRule {
        prefix: "capacity:",
        rule: "no self-emission — attester != attested, for the WHOLE family (CC 3.4.5)",
        enforced_at: &["federation::admission::check_reserved_prefix_admission"],
        gap: RowRuleGap::RuleOnCataloguedLeavesOnly,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 (CC 3.4.5 is written about the family; the manifest states \
                 it only on the catalogued factors, so a novel capacity factor resolves to no \
                 rule)",
    },
    PersistFamilyRule {
        prefix: "corpus_health:",
        rule: "substrate_persist-only emitter, for the WHOLE family (CC 3.4.3 \
               substrate-self-report)",
        enforced_at: &["federation::admission::check_reserved_prefix_admission"],
        gap: RowRuleGap::RuleOnCataloguedLeavesOnly,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 (family-level rule)",
    },
    PersistFamilyRule {
        prefix: "detection:",
        rule: "detector-only (identity_type contains lenscore_detector) for EVERY subkind, \
               including ones CC has not catalogued yet",
        enforced_at: &["federation::admission::check_reserved_prefix_admission"],
        gap: RowRuleGap::RuleOnCataloguedLeavesOnly,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 (CIRISPersist#379 already fixed this from the enforcement \
                 side; the manifest still enumerates leaves, so a novel subkind classifies as \
                 open)",
    },
    PersistFamilyRule {
        prefix: "federation_directory:",
        rule: "substrate_persist-only emitter, for the WHOLE family (CC 3.4.3 \
               substrate-self-report)",
        enforced_at: &["federation::admission::check_reserved_prefix_admission"],
        gap: RowRuleGap::RuleOnCataloguedLeavesOnly,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 (family-level rule)",
    },
    PersistFamilyRule {
        prefix: "identity_continuity:",
        rule: "substrate_persist-only emitter, for the WHOLE family (CC 3.4.3 \
               substrate-self-report)",
        enforced_at: &["federation::admission::check_reserved_prefix_admission"],
        gap: RowRuleGap::RuleOnCataloguedLeavesOnly,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 (family-level rule)",
    },
    // ── ClassAssertedByPersistNotTheRow: the classifier answers from persist's
    //    source, not from the manifest it derives from. ──────────────────────
    PersistFamilyRule {
        prefix: "provenance:build_manifest",
        rule: "accord co-scrub — a build manifest carries the same authority as a canonical seed \
               (the infra:attest gate), so authority_for() answers AccordCoScrub",
        enforced_at: &["federation::namespace::registry::class_for"],
        gap: RowRuleGap::ClassAssertedByPersistNotTheRow,
        minted_by_persist: false,
        cc_ask: "CIRISConstitution#67 (the manifest-derived classifier returns an authority the \
                 manifest never stated — land `accord-co-scrub` as the row's reserved_rule and \
                 delete the hardcoded arm)",
    },
];

/// Family stems the discovery scan finds in persist's source that are **not**
/// governed-family rules, each with the reason. `(stem, why)`.
///
/// The scan cannot tell a dimension family from a role namespace, a corpus-kind
/// prefix or a decision-rule token — and it must not try, because inferring a
/// rule from a string's shape is the section-walk heuristic CC 3.1.7 R2
/// explicitly forbids, pointed at a different input. So every stem it surfaces
/// is classified once, here, with its reason; that is the cost, and it is the
/// whole cost.
///
/// A stem here that LATER acquires a persist rule fails
/// [`tests::not_a_family_rule_entries_are_not_secretly_ruled`], so the
/// declaration cannot outlive its truth.
pub const NOT_A_FAMILY_RULE: &[(&str, &str)] = &[
    (
        "regime:",
        "NOT persist-ruled, and still deliberately so (CIRISPersist#571) — but the \
         REASON changed at the rc3 re-vendor and the old one is dead. It used to \
         be that CC catalogued no `regime:` family, so governing the stem would \
         make R2(b) refuse every emission and kill the local-tier path CIRISAgent \
         uses. CIRISConstitution#81 landed `regime:{artifact}:{version}`, so R2(b) \
         is satisfied and governing it would no longer refuse it \
         (`governing_regime_would_now_admit_but_the_row_states_no_rule` executes \
         that falsification rather than deleting the claim). What persist still \
         has is NOTHING TO ENFORCE: the generated row carries `reserved: false` \
         and no `reserved_rule`, because CC's generator cross-references rules \
         from CC 3.4 plus a `Reserved?` table column and the row sits in CC \
         3.1.9.2, which has neither — so the row's own prose (\"reserved — \
         substrate-steward-emitted\") reaches no machine-readable field, and \
         `substrate-steward` names no identity_type persist has. Gating on the \
         prose would be refused by \
         `admission::tests::authority_lists_agree_on_every_manifest_family` by \
         construction. The literal appears in `regime.rs` only as the family the \
         replication DECISION is about, never as a gate. It becomes persist-ruled \
         the day CC lands the rule where the generator can reach it — and \
         `regime::tests::the_regime_row_still_states_no_machine_readable_rule` \
         fires then.",
    ),
    (
        "content_rating:",
        "a READ-side filter, not an admission rule (CIRISPersist#571). Persist \
         gated this family to `trusted_publisher` from v3.0.0 under CEG 0.3 \
         §11.5.3 until CC catalogued it: CC 3.3.12 declares it OPEN VOCABULARY \
         (its `{scheme}` explicitly admits `operator:{operator_id}` \
         operator-defined rubrics), so the write gate was persist demanding an \
         emitter role the Constitution declines to demand and it was removed — see \
         `admission::MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN`. The surviving literal \
         is in `FederationDirectory::lookup_trusted_publisher_chain`, which \
         SELECTS rows attested by `trusted_publisher` keys when serving a rating \
         chain. That is CC's own placement of the discrimination — the row admits, \
         and the reader weighs it (\"polarity carries certifier confidence; not a \
         slashing input\") — so an open write door with a publisher-filtered read \
         door is the shape CC describes, not a gap.",
    ),
    (
        "admin_action:",
        "a `hard_case` event-KIND token (`hard_case::kind::ADMIN_ACTION_PREFIX`), carried in the \
         `kind` column of an observed admin action — not a scored dimension",
    ),
    (
        "agency:",
        "a capability-ROLE namespace (`types::capability_role::AGENCY_PREFIX`), matched against \
         conferred roles, never against a dimension",
    ),
    (
        "aggregate:",
        "a fountain `corpus_kind` prefix (`fountain::aggregation::AGGREGATE_CORPUS_PREFIX`) \
         naming a composite's folded source kind",
    ),
    (
        "custom:",
        "a decision-RULE token in the governance vocabulary (`types::decision_rule`), parsed off \
         a rule string, not a dimension",
    ),
    (
        "holds_bytes:",
        "an `attestation_type` prefix for blob-holding receipts \
         (`blobs::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX`), a structural primitive rather than a \
         `scores` family",
    ),
    (
        "identity:",
        "`identity:canonical_binding:{H}` is consumed as an authority-WIDENING input on the \
         withdraws path, not gated at emit; CC Part 3 catalogues no `identity:` family",
    ),
    (
        "infra:",
        "a capability-ROLE namespace (`types::capability_role`): `infra:attest` / `infra:serve` / \
         `infra:hold_*` are conferred roles, not dimensions",
    ),
    (
        "postgres:",
        "a DSN/URI scheme, not a namespace: `Engine::open` dispatches the backend on the \
         connection string's scheme",
    ),
    (
        "postgresql:",
        "the long spelling of the same DSN scheme — both forms are accepted, so both appear at \
         the dispatch site",
    ),
    (
        "proposed:",
        "the vendored manifest's design-note marker — a `field_processor_matrix` processor cell \
         prefixed `proposed:` is a proposal, not a live processor",
    ),
    (
        "quorum:",
        "a decision-RULE token (`types::decision_rule::QUORUM_PREFIX`, `quorum:{m}of{n}`)",
    ),
    (
        "reverse_quorum:",
        "a decision-RULE token (`types::decision_rule::REVERSE_QUORUM_PREFIX`)",
    ),
    (
        "s3:",
        "a blob-reference URI scheme (`blobs::BlobRef`), naming where bytes live",
    ),
    (
        "self:",
        "`self:delegates_to*` are `delegates_to` STRUCTURAL-PRIMITIVE envelope dimensions, \
         explicitly exempt from the `scores` dimension gate and documented as advisory/routing",
    ),
    (
        "sha256:",
        "a hash-encoding prefix (`sha256:<hex>`), the digest spelling used in content references",
    ),
    (
        "sqlite:",
        "a DSN/URI scheme (see `postgres:`), not a namespace",
    ),
    (
        "stream:",
        "a transparency-log `log_id` prefix (`stream_sth::STREAM_LOG_ID_PREFIX`), the sibling of \
         `tenant:<id>`",
    ),
    (
        "weighted:",
        "a decision-RULE token (`types::decision_rule::WEIGHTED_PREFIX`)",
    ),
    (
        "witness_diversity:",
        "READ-side only: `scores::compose_verdict` folds live rows on this family into the \
         `witness_diversity` input. Persist rules on nobody's right to emit it — deliberately, \
         since CC 3.4.7.1 wants diversity attested rather than substrate-derived",
    ),
];

/// Every family prefix persist states an emitter/composition rule about,
/// **derived** from each ruling surface at its own source. Sorted, deduped.
///
/// There is no parallel list to keep in step: adding a
/// [`ReservedPrefixRule`](admission::ReservedPrefixRule) row, a hard-coded
/// stem, a minted family or a quota-reserved prefix puts that family under this
/// inventory automatically, and a NEW purpose-built gate is caught by the
/// source scan ([`tests::every_admission_shaped_prefix_literal_is_classified`])
/// rather than by anyone remembering.
#[must_use]
pub fn persist_ruled_prefixes() -> Vec<String> {
    let mut out: Vec<String> = admission::default_reserved_prefix_rules()
        .iter()
        .map(|r| r.pattern_prefix.clone())
        .chain(
            admission::HARD_CODED_RESERVED_STEMS
                .iter()
                .map(|s| (*s).to_owned()),
        )
        .chain(
            admission::MINTED_NAMESPACE_FAMILIES
                .iter()
                .map(|f| registry::family_stem(f).to_owned()),
        )
        .chain(
            crate::federation::replication::admission::RESERVED_CLASS_DIMENSION_PREFIXES
                .iter()
                .map(|s| (*s).to_owned()),
        )
        // The purpose-built gates + the classifier arm, each read at the const
        // its own site branches on rather than re-spelled here.
        .chain(
            [
                admission::MODERATION_DIMENSION_PREFIX,
                admission::RECONSIDERATION_DIMENSION_PREFIX,
                admission::QUARANTINE_DIMENSION_PREFIX,
                registry::ACCORD_CO_SCRUB_MATCH_PREFIX,
            ]
            .into_iter()
            .map(str::to_owned),
        )
        // `attestation:l{N}:` is a SHAPE rule over the `attestation:` family;
        // record it at family granularity, which is the granularity the
        // registry and the classifier both speak.
        .chain(std::iter::once(
            registry::family_stem(admission::ATTESTATION_LADDER_DEPRECATED_PREFIX).to_owned(),
        ))
        // v27.0.0 (CIRISPersist#571) — persist rules on the CC 3.1.7 Private
        // Use range: `x_private:` MUST NOT admit at federation tier under any
        // authority (`check_private_use_not_federatable`, all three doors).
        // Read at the const the gate itself branches on, never re-spelled —
        // this arrived from a sibling branch and the scan caught it at merge,
        // which is the whole reason the scan exists.
        .chain(std::iter::once(
            admission::PRIVATE_USE_FAMILY_STEM.to_owned(),
        ))
        // `revocation:peer_admission:v1` is a whole dimension, not a prefix —
        // the gate compares it for EQUALITY. Recorded as the family prefix so
        // the inventory reads uniformly.
        .chain(std::iter::once(
            admission::PEER_DEADMISSION_DIMENSION
                .rsplit_once(':')
                .map_or_else(
                    || admission::PEER_DEADMISSION_DIMENSION.to_owned(),
                    |(head, _)| format!("{head}:"),
                ),
        ))
        .chain(
            crate::federation::invariant::NEWLY_ENFORCED_SELF_EMISSION_PREFIXES
                .iter()
                .map(|s| (*s).to_owned()),
        )
        .filter(|s| !s.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Does the vendored registry state a machine-readable emitter rule that
/// applies to `dimension`?
///
/// [`authority_for`](registry::authority_for)'s answer, asked as a yes/no: a
/// consumer resolving `dimension` through the classifier either learns a rule
/// or learns nothing.
#[must_use]
pub fn registry_states_a_rule_for(dimension: &str) -> bool {
    registry::authority_for(dimension).reserved.is_some()
}

/// The pinned entry covering `dimension`, if persist rules on it and the
/// registry does not state that rule. Longest matching
/// [`prefix`](PersistFamilyRule::prefix) wins.
///
/// This is the accessor a downstream (server / edge / a cross-repo conformance
/// harness) uses to ask *"is `authority_for`'s silence here real, or is persist
/// ruling on something the manifest never said?"* — #519 item 2b's question,
/// answered from persist's own inventory instead of by re-reading persist's
/// source.
#[must_use]
pub fn rule_not_on_the_row_for(dimension: &str) -> Option<&'static PersistFamilyRule> {
    RULES_NOT_ON_THE_ROW
        .iter()
        .filter(|e| dimension.starts_with(e.prefix))
        .max_by_key(|e| e.prefix.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// A probe dimension inside `prefix`'s space that is NOT one of CC's
    /// catalogued leaves — the question a consumer asks about an ordinary
    /// member of the family, not about the one row someone remembered to
    /// catalogue.
    fn probe(prefix: &str) -> String {
        let sep = if prefix.ends_with(':') { "" } else { ":" };
        format!("{prefix}{sep}zz_probe_dimension:v1")
    }

    /// Read every `.rs` file under `src/`.
    fn persist_sources() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            let Ok(rd) = std::fs::read_dir(dir) else {
                return;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.extension().is_some_and(|x| x == "rs") {
                    if let Ok(t) = std::fs::read_to_string(&p) {
                        out.push((p.display().to_string(), t));
                    }
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut out,
        );
        assert!(
            out.len() > 20,
            "source walk collapsed ({} files) — every gate keyed on it would pass vacuously",
            out.len()
        );
        out
    }

    /// **The gate.** Every prefix persist rules on either has a rule a consumer
    /// can resolve, or is pinned in [`RULES_NOT_ON_THE_ROW`] with the rule, the
    /// sites and the ask.
    ///
    /// The three families with NO registry row at all
    /// ([`admission::UNREGISTERED_GATED_FAMILIES`]) are a different failure,
    /// already gated by #590's R2 suite; skipping them keeps each question in
    /// one place.
    #[test]
    fn every_ruled_prefix_states_its_rule_somewhere() {
        let prefixes = persist_ruled_prefixes();
        assert!(
            prefixes.len() >= 20,
            "the derived ruled set collapsed to {} entries — this gate would pass vacuously. \
             Check that every ruling surface is still being read.",
            prefixes.len()
        );
        let pinned: BTreeSet<&str> = RULES_NOT_ON_THE_ROW.iter().map(|e| e.prefix).collect();
        let mut unstated: Vec<String> = Vec::new();
        for p in &prefixes {
            let stem = registry::family_stem(p);
            if admission::UNREGISTERED_GATED_FAMILIES.contains(&stem) {
                continue; // no row at all — #590's R2(b) question, not this one
            }
            if registry_states_a_rule_for(&probe(p)) || pinned.contains(p.as_str()) {
                continue;
            }
            unstated.push(p.clone());
        }
        assert!(
            unstated.is_empty(),
            "persist states an emitter/composition rule about {unstated:?}, and `authority_for` \
             resolves NO rule for an ordinary dimension in that space. A downstream reading the \
             classifier concludes the family is open while persist refuses emissions on it — two \
             validators, one artifact, different predicates. Land the rule on the CC row and \
             re-vendor, or pin it in RULES_NOT_ON_THE_ROW with the rule persist applies, the \
             site(s) that apply it, and the CC ask."
        );
    }

    /// The stale-pin bite. A pin whose rule HAS landed is an excuse that would
    /// keep a now-classified family out of the real classifier.
    #[test]
    fn pinned_rules_are_still_missing_from_the_registry() {
        assert!(
            !RULES_NOT_ON_THE_ROW.is_empty(),
            "the gap inventory is empty — this gate would pass vacuously"
        );
        for e in RULES_NOT_ON_THE_ROW {
            assert!(
                !registry_states_a_rule_for(&probe(e.prefix)),
                "{:?} is pinned as a rule the registry does not state, but `authority_for` now \
                 resolves one — delete the line so the family goes through the real classifier",
                e.prefix
            );
            let ruled_rows: Vec<&str> = registry::entries()
                .iter()
                .filter(|x| x.prefix.starts_with(e.prefix) && x.authority.reserved.is_some())
                .map(|x| x.prefix.as_str())
                .collect();
            match e.gap {
                RowRuleGap::NoRuleOnTheRow => assert!(
                    ruled_rows.is_empty(),
                    "{:?} is pinned NoRuleOnTheRow but {ruled_rows:?} now carry a reserved_rule — \
                     re-classify as RuleOnCataloguedLeavesOnly or delete the line",
                    e.prefix
                ),
                RowRuleGap::RuleOnCataloguedLeavesOnly => assert!(
                    !ruled_rows.is_empty(),
                    "{:?} is pinned RuleOnCataloguedLeavesOnly but NO row under it carries a \
                     reserved_rule — it is a NoRuleOnTheRow gap, and the softer classification \
                     understates it",
                    e.prefix
                ),
                RowRuleGap::ClassAssertedByPersistNotTheRow => {
                    assert!(
                        ruled_rows.is_empty(),
                        "{:?} is pinned as classifier-asserted but {ruled_rows:?} now carry a \
                         reserved_rule — the hardcoded arm can go, and so can this line",
                        e.prefix
                    );
                    // The claim is that the CLASSIFIER answers anyway. Execute it.
                    assert_ne!(
                        registry::authority_for(&probe(e.prefix)).class,
                        crate::federation::namespace::AuthorityClass::ProducerSteward,
                        "{:?} is pinned as classifier-asserted, but `authority_for` returns the \
                         DEFAULT class — persist asserts nothing, so the pin is wrong",
                        e.prefix
                    );
                }
            }
            assert!(!e.rule.is_empty(), "{:?} must name the rule", e.prefix);
            assert!(
                !e.enforced_at.is_empty(),
                "{:?} names no site — a rule the manifest does not state and no code claims is a \
                 rule nothing applies",
                e.prefix
            );
            for site in e.enforced_at {
                assert!(
                    site.starts_with("federation::"),
                    "{:?} must name each site by module path, got {site:?}",
                    e.prefix
                );
            }
            assert!(
                e.cc_ask.contains("CIRISConstitution#"),
                "{:?} must name the CC ask that lands the rule, got {:?}",
                e.prefix,
                e.cc_ask
            );
        }
    }

    /// Every pinned prefix is one persist actually rules on — the pin cannot
    /// name a family nothing touches.
    #[test]
    fn pinned_prefixes_are_all_really_ruled() {
        let ruled: BTreeSet<String> = persist_ruled_prefixes().into_iter().collect();
        for e in RULES_NOT_ON_THE_ROW {
            assert!(
                ruled.contains(e.prefix),
                "{:?} is pinned as a persist rule the registry omits, but the derived ruled set \
                 does not contain it. Either the site was deleted (delete the pin) or it is keyed \
                 on a literal `persist_ruled_prefixes()` does not read (add the const to the \
                 derivation). Derived set: {ruled:?}",
                e.prefix
            );
        }
    }

    /// The R2(a) subset must agree with persist's producer declaration in both
    /// directions — the #590 pin's guarantee, preserved by the generalization
    /// rather than dropped by it.
    #[test]
    fn minted_flag_matches_the_producer_declaration() {
        let minted_stems: BTreeSet<&str> = admission::MINTED_NAMESPACE_FAMILIES
            .iter()
            .map(|f| registry::family_stem(f))
            .collect();
        for e in RULES_NOT_ON_THE_ROW {
            assert_eq!(
                e.minted_by_persist,
                minted_stems.contains(e.prefix),
                "{:?}: minted_by_persist={} disagrees with MINTED_NAMESPACE_FAMILIES",
                e.prefix,
                e.minted_by_persist
            );
        }
        // Every minted family with no rule must be pinned: R2(a) one level
        // deeper, the property #590 shipped and this list inherits.
        let pinned: BTreeSet<&str> = RULES_NOT_ON_THE_ROW.iter().map(|e| e.prefix).collect();
        for fam in admission::MINTED_NAMESPACE_FAMILIES {
            let stem = registry::family_stem(fam);
            assert!(
                registry_states_a_rule_for(&probe(stem)) || pinned.contains(stem),
                "{fam:?} is minted by persist, carries no machine-readable rule, and is not \
                 pinned. The family is registered but the AUTHORITY is not."
            );
        }
        assert_eq!(
            RULES_NOT_ON_THE_ROW
                .iter()
                .filter(|e| e.minted_by_persist)
                .count(),
            admission::MINTED_NAMESPACE_FAMILIES.len(),
            "every minted family is rule-free on its row today; if CC lands one, delete its line \
             AND re-measure the \"N of M\" claim in this module's doc"
        );
        // The other half of that claim, measured rather than asserted. Growing
        // the inventory is the expected direction and must not be hard to do —
        // but a doc number a reader ACTS on ("R2(a) covered a fifth of the
        // exposure") is exactly the hand-maintained truth this module exists to
        // stop, so it is checked here rather than trusted.
        assert_eq!(
            RULES_NOT_ON_THE_ROW.len(),
            19,
            "the inventory now has {} entries; this module's doc says the minted set is \"4 of \
             19\". Update BOTH numbers so the claim a reader acts on is the claim the build \
             checked.",
            RULES_NOT_ON_THE_ROW.len()
        );
    }

    /// A cited site must resolve to a real definition in persist's source.
    ///
    /// #590's pin named its gates as free text nothing checked, so a rename
    /// would have left the inventory pointing at a symbol that no longer
    /// existed — the failure `evidence_cc_impl_pointers_resolve` was tightened
    /// for in v24.3.0 (a `contains()` check that matched doc comments kept a
    /// deleted symbol "resolving" for a whole release).
    #[test]
    fn pinned_sites_resolve_to_a_definition_in_source() {
        let sources = persist_sources();
        for e in RULES_NOT_ON_THE_ROW {
            for site in e.enforced_at {
                let mut parts: Vec<&str> = site.split("::").collect();
                let bare = parts.pop().expect("non-empty path");
                // `Type::method` — the definition must sit in a file that also
                // declares the type, so a generic `fn check` elsewhere cannot
                // satisfy the citation.
                let owner = parts
                    .last()
                    .filter(|p| p.starts_with(|c: char| c.is_ascii_uppercase()))
                    .copied();
                let needle = format!("fn {bare}");
                let defined = sources.iter().any(|(_, t)| {
                    let hit = t.lines().map(str::trim_start).any(|l| {
                        !l.starts_with("//") && !l.starts_with("///") && l.contains(&needle)
                    });
                    hit && owner.is_none_or(|o| t.contains(&format!("impl {o}")))
                });
                assert!(
                    defined,
                    "{:?} cites {site:?}, but no `fn {bare}`{} is DEFINED anywhere in persist's \
                     source. A citation that resolves against a doc comment is a spell-checker, \
                     not evidence.",
                    e.prefix,
                    owner.map_or(String::new(), |o| format!(" inside `impl {o}`")),
                );
            }
        }
    }

    /// A `NOT_A_FAMILY_RULE` declaration cannot outlive its truth: if persist
    /// later starts ruling on that stem, the excuse must go.
    #[test]
    fn not_a_family_rule_entries_are_not_secretly_ruled() {
        let ruled_stems: BTreeSet<String> = persist_ruled_prefixes()
            .iter()
            .map(|p| registry::family_stem(p).to_owned())
            .collect();
        assert!(
            !NOT_A_FAMILY_RULE.is_empty(),
            "the declaration list is empty — vacuous gate"
        );
        for (stem, why) in NOT_A_FAMILY_RULE {
            assert!(
                stem.ends_with(':'),
                "{stem:?} must be a family stem ending in ':'"
            );
            assert!(!why.is_empty(), "{stem:?} must state why it is not a rule");
            assert!(
                !ruled_stems.contains(*stem),
                "{stem:?} is declared NOT a family rule, but persist now rules on it — delete the \
                 line and pin the rule instead"
            );
        }
    }

    // ── the discovery witness ────────────────────────────────────────────

    /// Line ranges of `#[cfg(test)]` modules, so a fixture's dimension literal
    /// is not mistaken for a production gate.
    fn test_regions(lines: &[&str]) -> Vec<(usize, usize)> {
        let mut regions = Vec::new();
        let mut i = 0usize;
        while i < lines.len() {
            let s = lines[i].trim_start();
            if s.starts_with("#[cfg(test)]") || s.starts_with("#[cfg(any(test") {
                let mut j = i;
                while j < lines.len() && !lines[j].contains('{') {
                    j += 1;
                }
                if j < lines.len() {
                    let mut depth = 0i32;
                    let mut k = j;
                    while k < lines.len() {
                        depth += i32::try_from(lines[k].matches('{').count()).unwrap_or(0);
                        depth -= i32::try_from(lines[k].matches('}').count()).unwrap_or(0);
                        if depth <= 0 {
                            break;
                        }
                        k += 1;
                    }
                    regions.push((i, k));
                    i = k;
                }
            }
            i += 1;
        }
        regions
    }

    /// Is `lit` shaped like a namespace family prefix — `head:` with a
    /// lowercase `[a-z0-9_]` head and no whitespace?
    fn is_family_shaped(lit: &str) -> bool {
        let Some((head, _)) = lit.split_once(':') else {
            return false;
        };
        !head.is_empty()
            && head.starts_with(|c: char| c.is_ascii_lowercase())
            && head
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            && !lit.contains(char::is_whitespace)
    }

    /// The double-quoted literal opening at `open`, plus the index of its
    /// closing quote.
    fn literal_at(line: &str, open: usize) -> Option<(&str, usize)> {
        let rest = line.get(open + 1..)?;
        let close = rest.find('"')? + open + 1;
        Some((line.get(open + 1..close)?, close))
    }

    /// Family-shaped literals in `line` at the two admission-shaped positions:
    /// a `starts_with` / `strip_prefix` argument, and a `PREFIX` / `DIMENSION`
    /// / `FAMILY` / `NAMESPACE` const's value(s).
    fn family_literals_in(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        for call in ["starts_with(", "strip_prefix("] {
            let mut from = 0usize;
            while let Some(rel) = line[from..].find(call) {
                let at = from + rel + call.len();
                let lead = line[at..].len() - line[at..].trim_start().len();
                if line.as_bytes().get(at + lead) == Some(&b'"') {
                    if let Some((lit, _)) = literal_at(line, at + lead) {
                        if is_family_shaped(lit) {
                            out.push(lit.to_owned());
                        }
                    }
                }
                from = at;
            }
        }
        let declares_a_prefix_const = (line.contains("const ") || line.contains("static "))
            && ["PREFIX", "DIMENSION", "FAMILY", "NAMESPACE"]
                .iter()
                .any(|k| line.contains(k));
        if declares_a_prefix_const {
            let mut i = 0usize;
            while let Some(rel) = line[i..].find('"') {
                let open = i + rel;
                let Some((lit, close)) = literal_at(line, open) else {
                    break;
                };
                if is_family_shaped(lit) {
                    out.push(lit.to_owned());
                }
                i = close + 1;
            }
        }
        out
    }

    /// **The closure.** Every family-shaped literal persist branches on in
    /// production code is either ruled by persist, ruled by the registry, or
    /// declared not a rule. A new purpose-built gate keyed on a literal nobody
    /// wired into [`persist_ruled_prefixes`] fails HERE.
    #[test]
    fn every_admission_shaped_prefix_literal_is_classified() {
        let mut found: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for (path, text) in persist_sources() {
            let lines: Vec<&str> = text.lines().collect();
            let regions = test_regions(&lines);
            for (i, line) in lines.iter().enumerate() {
                if regions.iter().any(|(a, b)| i >= *a && i <= *b) {
                    continue;
                }
                if line.trim_start().starts_with("//") {
                    continue;
                }
                for lit in family_literals_in(line) {
                    let stem = registry::family_stem(&lit).to_owned();
                    if !stem.is_empty() {
                        found.entry(stem).or_default().insert(path.clone());
                    }
                }
            }
        }
        assert!(
            found.len() >= 25,
            "the discovery scan found only {} family stems — it has stopped seeing persist's \
             admission surface and would pass vacuously. Check `family_literals_in`.",
            found.len()
        );

        let ruled_stems: BTreeSet<String> = persist_ruled_prefixes()
            .iter()
            .map(|p| registry::family_stem(p).to_owned())
            .collect();
        let declared: BTreeSet<&str> = NOT_A_FAMILY_RULE.iter().map(|(s, _)| *s).collect();

        let mut unclassified: Vec<String> = Vec::new();
        for (stem, seen_in) in &found {
            if ruled_stems.contains(stem) || declared.contains(stem.as_str()) {
                continue;
            }
            // The registry stating a rule ANYWHERE in the family means CC has
            // spoken about it and persist is not the only statement of it —
            // the condition this module exists to detect the absence of.
            if registry::entries()
                .iter()
                .any(|e| e.prefix.starts_with(stem.as_str()) && e.authority.reserved.is_some())
            {
                continue;
            }
            let files: Vec<&str> = seen_in.iter().map(String::as_str).collect();
            unclassified.push(format!("{stem} (seen in {files:?})"));
        }
        assert!(
            unclassified.is_empty(),
            "unclassified family-shaped prefix literal(s) in persist's production source: \
             {unclassified:#?}\n\nEach must become one of three things: (1) a prefix \
             `persist_ruled_prefixes()` derives, if persist rules on it — wire the site's const \
             into the derivation and pin the gap; (2) a family CC states a rule for — nothing to \
             do; or (3) a line in NOT_A_FAMILY_RULE with the reason it is not a governed \
             dimension family. Silence is the option this gate removes."
        );
    }

    /// The accessor a downstream uses: longest matching prefix wins, and a
    /// dimension outside every gap answers `None`.
    #[test]
    fn rule_lookup_is_longest_prefix() {
        let hit = rule_not_on_the_row_for("moderation:harassment:v1")
            .expect("moderation: is a pinned gap");
        assert_eq!(hit.prefix, "moderation:");
        assert!(!hit.minted_by_persist);

        let minted =
            rule_not_on_the_row_for("quarantine:withheld:v1").expect("quarantine: is a pinned gap");
        assert!(minted.minted_by_persist);

        // `health:liveness:` must beat a hypothetical bare `health:` entry.
        let health = rule_not_on_the_row_for("health:liveness:v1").expect("pinned");
        assert_eq!(health.prefix, "health:liveness:");

        // `accord:*` carries a real reserved_rule — not a gap.
        assert!(rule_not_on_the_row_for("accord:invoke:halt").is_none());
        // Open vocabulary persist has no opinion about.
        assert!(rule_not_on_the_row_for("credits:rust:en:alice").is_none());
    }

    /// The gap kinds are three genuinely different populations, and none is
    /// empty — if one were, the distinction would be decoration.
    #[test]
    fn every_gap_kind_is_populated_and_tokenised() {
        for kind in [
            RowRuleGap::NoRuleOnTheRow,
            RowRuleGap::RuleOnCataloguedLeavesOnly,
            RowRuleGap::ClassAssertedByPersistNotTheRow,
        ] {
            assert!(
                RULES_NOT_ON_THE_ROW.iter().any(|e| e.gap == kind),
                "{kind:?} has no entries — either delete the variant or the pin that needed it \
                 was dropped"
            );
            assert!(!kind.as_str().is_empty());
        }
        assert_eq!(RowRuleGap::NoRuleOnTheRow.as_str(), "no_rule_on_the_row");
        assert_eq!(
            RowRuleGap::RuleOnCataloguedLeavesOnly.as_str(),
            "rule_on_catalogued_leaves_only"
        );
        assert_eq!(
            RowRuleGap::ClassAssertedByPersistNotTheRow.as_str(),
            "class_asserted_by_persist_not_the_row"
        );
    }

    /// The correction recorded in this module's doc, executed rather than
    /// asserted: `slashing:` is NOT ruled on by persist.
    #[test]
    fn slashing_is_not_a_persist_ruled_family() {
        let ruled: BTreeSet<String> = persist_ruled_prefixes().into_iter().collect();
        assert!(
            !ruled.contains("slashing:"),
            "persist now rules on `slashing:` — add it to the inventory (its row carries no \
             reserved_rule) and delete this test's premise from the module doc"
        );
        assert!(rule_not_on_the_row_for("slashing:suspension:v1").is_none());
        // …while the two it DOES gate through that walk are both inventoried.
        assert!(rule_not_on_the_row_for("moderation:x:v1").is_some());
        assert!(rule_not_on_the_row_for("reconsideration:x:v1").is_some());
    }
}
