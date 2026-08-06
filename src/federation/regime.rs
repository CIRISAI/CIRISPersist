//! **CIRISPersist#571 — `regime:*`, the experimental-regime research
//! artifacts: the admission finding and the replication decision.**
//!
//! CIRISAgent's manifest-driven experimental regimes (FSD
//! `RESEARCH_PROMPT_OVERRIDES.md` §13) emit four signed CEG artifacts —
//! [`REGIME_DIMENSIONS`] — so a reviewer holding a result can walk back to the
//! exact composed prompt and verify the signature over it. #571 asked persist
//! for two things: **registry rows** for the four families, and an **explicit
//! replication decision** for the prefix.
//!
//! Exactly one of those was persist's to give.
//!
//! # The registry half LANDED — and it did not carry the rule
//!
//! Persist does not author namespace rows. [`registry`](super::namespace::registry)
//! is GENERATED from CC Part 3 by the Constitution's own
//! `tools/build_cc_namespace.py` and vendored here byte-for-byte, pinned by
//! [`VENDORED_SOURCE_SHA256`](super::namespace::registry::VENDORED_SOURCE_SHA256).
//! At v27.0.0 CC carried no `regime:` family and this module said so, with a
//! self-deleting pin. **CIRISConstitution#81 landed the row**, the rc3
//! re-vendor (109 → 114 families) brought it in, the pin failed by name as
//! designed, and #571's registry half is closed.
//!
//! **What arrived is narrower than the row's prose, and the difference is the
//! whole remaining story.** The catalogue row reads:
//!
//! > `regime:{artifact}:{version}` — … **reserved — substrate-steward-emitted**,
//! > the emitter rule pinned at mint per R2(a); registered to end the
//! > ProducerSteward default.
//!
//! The GENERATED row that prose produces is `"reserved": false` with **no
//! `reserved_rule` key at all**. So:
//!
//! - [`is_family_registered`](super::namespace::registry::is_family_registered)
//!   flips to `true` — real, and it is what unblocks R2(b);
//! - [`authority_for`](super::namespace::registry::authority_for) returns
//!   `ProducerSteward` / `reserved: None` — **byte-identical to what it returned
//!   before the row existed.** The "ProducerSteward default" the row says it
//!   ends is not ended by the artifact the row generates.
//!
//! This is not a CC drafting slip so much as a generator reach limit, and it is
//! structural rather than incidental: `build_cc_namespace.py` cross-references
//! reserved rules from CC **3.4** onto families, plus a `Reserved?` table column
//! where one exists. The `regime:` row sits in CC **3.1.9.2**, whose table has
//! three columns and no `Reserved?`, and its rule is stated in prose that names
//! no CC 3.4 clause. Persist already measured exactly this and pinned it:
//! `admission::tests::most_of_the_manifest_carries_no_machine_readable_rule`
//! asserts that **every** CC 3.1.9.2 family resolves `reserved.is_none()`. The
//! `regime:` row landed in the one section of the Part that cannot currently
//! carry a machine-readable emitter rule.
//!
//! **So persist does not gate the family, and the reason has changed.** It is no
//! longer "R2(b) would refuse it" (there is a row now — that reason is dead and
//! [`tests::governing_regime_would_now_admit_but_the_row_states_no_rule`] proves
//! it dead rather than quietly dropping it). It is that there is **no rule on
//! the row to enforce**, and enforcing the prose instead would be persist
//! re-deriving an emitter rule from CC's sentences — the generated-vs-hand-
//! maintained split truth CC 3.1.7 R2 exists to end, and the exact defect
//! `admission::tests::authority_lists_agree_on_every_manifest_family` fails the
//! build for. That gate would refuse a hand-written `regime:` rule immediately,
//! by construction. `substrate-steward-emitted` also names no
//! `identity_type` persist has: there is no `substrate_steward`.
//!
//! **The ask on CC**, which is the last thing standing between this module and
//! deletion: land the rule where the generator can reach it — a `Reserved?`
//! column on the CC 3.1.9.2 row, or a `regime:` predicate in
//! `build_cc_namespace.py`'s `RESERVED_RULES` naming the CC 3.4 clause that
//! rules it. [`tests::the_regime_row_still_states_no_machine_readable_rule`]
//! fails the day that lands, which is the day persist writes the gate.
//!
//! The same defect shipped on four other rc3 rows and persist is not
//! speculating about that either: `content_rating:` / `content_class:` /
//! `cw_class:` arrived in the same re-vendor with their emitter rules deferred
//! to CC 3.3.12 prose, and `mesh_config:{key}` says "trust-root-emitted" with
//! `reserved: false`. For the media three the resolution went the other way —
//! CC 3.3.12 turned out to *declare them open*, so the fix was to delete
//! persist's CEG-era gates
//! ([`MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN`](super::admission::MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN)).
//! `regime:`'s prose says the opposite, which is why it waits for a rule rather
//! than being declared open.
//!
//! **The exception pin does not fit this family and was deliberately not used.**
//! [`UNREGISTERED_GATED_FAMILIES`](super::admission::UNREGISTERED_GATED_FAMILIES)
//! grandfathers families persist *already gates* that CC has *not* catalogued —
//! enforcement predating R2, named in source rather than implied by silence.
//! `regime:` is the exact opposite on both axes: catalogued by CC, gated by
//! nobody. Putting it there would convert a named residual into a
//! general-purpose bypass — the mechanism for "we govern this and CC hasn't
//! caught up" becoming the mechanism for "CC hasn't ruled, so we ruled."
//!
//! As of this cut the list is **empty**: it held exactly the three CEG-0.3
//! families, CC catalogued all three, and the lines were deleted rather than the
//! gate suppressed. So the pin has now been exercised end to end, which is worth
//! more than the three lines were.
//!
//! # Why not the Private Use range?
//!
//! R2 now reserves `x_private:{anything}` as the legitimate unregistered range
//! (RFC 6648's lesson: with nowhere legitimate to put an unregistered family,
//! people mint squatted prefixes and those calcify). An "experimental" artifact
//! class is exactly the shape that range is for, so the question is fair — and
//! the answer is no, on the clause's own terms.
//!
//! Private Use carries two hard properties: private-use families **MUST NOT
//! admit at federation tier under any authority**, and **MUST NOT be promoted
//! to a registered family without minting a fresh name**. The first forecloses
//! the only thing #571 asks for. CIRISAgent already HAS a signed local-tier
//! path — the issue says so in as many words — and states that this ask "gates
//! the *federation* of regime evidence"; the reviewability property is a
//! reviewer on ANOTHER node walking back to the composed prompt. Shipping
//! `x_private:regime:*` would deliver what already exists and make the thing
//! that was asked for constitutionally unreachable.
//!
//! The second property is a **one-way door worth naming**: adopting the range
//! now guarantees a rename later — for the producer, for every artifact already
//! emitted, and for any reviewer's stored corpus, none of which can be
//! re-pointed by a registry row. It converts "waiting for a CC row" into
//! "shipping a name we have already committed to abandoning."
//!
//! And "experimental" here describes the artifacts' CONTENT (ablation and
//! replacement studies), not the family's lifecycle. The TORQUE series runs
//! across releases and the FSD calls the federation ask the longest-lead item
//! of the whole design — a family the mesh is expected to converge on, which is
//! the case Private Use explicitly is not for.
//!
//! What DID come out of that clause is a defect: the federation-tier ban was
//! unenforced here, so an `x_private:*` row promoted cleanly on every backend.
//! [`check_private_use_not_federatable`](super::admission::check_private_use_not_federatable)
//! closes it, and
//! [`tests::private_use_is_banned_from_federation_tier`] holds all three doors.
//!
//! # The replication half — the decision
//!
//! **`regime:*` replicates: as ordinary consented egress, with no persist-side
//! carve-out, and never by default.** Five clauses, each mechanical:
//!
//! 1. **There is no allowlist to be added to.** #571 records that "the default
//!    replication grant covers `["capacity:","trace:"]`" — that is a fact about
//!    a *deployment's* grant payload, not about persist. Persist ships no
//!    family allowlist for egress at all: what a node replicates is entirely a
//!    function of its own live, self-signed `consent:replication:v1` grants,
//!    whose `attestation_prefixes` are free-form strings matched by
//!    [`consent_grammar::covers`](super::consent_grammar::covers). Naming
//!    [`REGIME_FAMILY_STEM`] in that grant is sufficient, and it is the whole
//!    mechanism — witnessed end to end in
//!    [`tests::a_consent_grant_naming_regime_federates_a_regime_row`].
//!
//! 2. **Opt-in per deployment; the default stays local.** The default grant set
//!    is empty, so the default posture is local-only — and that is the right
//!    default here rather than an accident worth fixing. `regime:composition:v1`
//!    carries the composed prompt per arm × locale and `regime:onwire:v1`
//!    carries a wire-divergence report; those are the two artifacts most likely
//!    to carry deployment-specific or user-derived text. A research campaign
//!    starting is not consent for them to leave the node.
//!
//! 3. **"Replicates" always means "to a named cohort".** The covering grant's
//!    `audience` is carried by the promotion primitive itself, and both
//!    [`Engine::attestation_promote`](crate::engine::Engine::attestation_promote)
//!    and [`check_promotion_admission`](super::admission::check_promotion_admission)
//!    refuse the `(federation, self)` placement. There is no path on which a
//!    `regime:*` row becomes federation-visible without a placement someone
//!    signed for.
//!
//! 4. **Authority is still `ProducerSteward` — self-attested and un-reserved,
//!    now WITH a registry row rather than for lack of one.** Before the
//!    re-vendor this was
//!    [`authority_for`](super::namespace::registry::authority_for)'s fallback
//!    for an uncatalogued family. After it, the family is catalogued and the
//!    answer is unchanged — because the row states no rule. The reading is the
//!    honest one either way: a `regime:gate:v1` from peer X is evidence about
//!    X's own run, signed by X, and persist confers no warrant on it. What
//!    changed is that "un-reserved" is now a fact *about a row someone wrote*
//!    instead of an artifact of silence, and
//!    [`tests::regime_authority_is_unreserved_producer_steward`] asserts both
//!    halves together so the pair cannot drift apart unnoticed.
//!
//! 5. **Not gating it is still the decision — for a different reason than in
//!    v27.0.0.** The old reason was mechanical and is now DEAD: adding `regime:`
//!    to any source [`governed_family_stems`](super::admission::governed_family_stems)
//!    reads used to make CC 3.1.7 R2(b) refuse the family outright, because
//!    there was no row to satisfy R2(b) with, taking out the local-tier path
//!    CIRISAgent depends on. There is a row now, so R2(b) is satisfied and
//!    governing the family would no longer refuse it.
//!
//!    The reason persist still does not gate it is the one in the header: the
//!    row carries no machine-readable rule, so there is nothing to enforce, and
//!    a hand-written rule would be refused by persist's own split-truth gate.
//!    [`tests::governing_regime_would_now_admit_but_the_row_states_no_rule`]
//!    retires the old claim by EXECUTING its falsification — it asserts the
//!    R2(b) refusal no longer reaches `regime:*`, on the same predicate that
//!    still refuses the governed-and-unregistered probe.
//!
//! # What is NOT here, on purpose
//!
//! No shape validator. `check_trace_dimension_admission` is the tempting
//! precedent — persist shipped a machine-checkable interim for `trace:*` before
//! CC ratified it, and CC then adopted persist's framing nearly verbatim. It
//! does not transfer. The `trace:complete:v1` shape was settled and shipping;
//! the regime artifacts' shapes are still moving in an unmerged CIRISAgent FSD
//! branch ("the block table per arm × locale, including annotator ids, κ, and
//! the adjudication log"), and the producing path has since moved to detached
//! object signatures that never enter the graph at all. A gate written against
//! a spec that is not merged is a gate written against a fixture — it certifies
//! nothing and it refuses real traffic the moment the spec moves.

/// The four leaves CIRISAgent's regime campaign emits (FSD
/// `RESEARCH_PROMPT_OVERRIDES.md` §13), spelled exactly as #571 asked for them.
///
/// Exported so a consumer composing the `consent:replication:v1` grant that
/// carries them, or a reviewer filtering a corpus for them, has ONE spelling to
/// key on rather than four string literals per repo. Persist attaches **no**
/// admission meaning to membership in this list — that is the whole finding
/// above, and [`tests::the_four_leaves_all_sit_on_one_family_stem`] pins that
/// the list is a naming aid and not a second, local registry.
pub const REGIME_DIMENSIONS: [&str; 4] = [
    "regime:manifest:v1",
    "regime:composition:v1",
    "regime:gate:v1",
    "regime:onwire:v1",
];

/// The family stem the four [`REGIME_DIMENSIONS`] share — the granularity CC
/// 3.1.7 R2 speaks at, and the string a `consent:replication:v1` grant names to
/// cover all four at once.
pub const REGIME_FAMILY_STEM: &str = "regime:";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::admission::{
        check_namespace_family_registered, governed_family_stems, UNREGISTERED_GATED_FAMILIES,
    };
    use crate::federation::namespace::registry::{
        authority_for, family_stem, is_family_registered,
    };
    use crate::federation::namespace::AuthorityClass;

    // ══════════════════════════════════════════════════════════════════
    // The finding: CC has not catalogued the family
    // ══════════════════════════════════════════════════════════════════

    /// **The self-deleting pin, DELETED — by its own failure.**
    ///
    /// v27.0.0 shipped `regime_families_are_still_absent_from_the_vendored_manifest`,
    /// asserting CC carried no `regime:` row. CIRISConstitution#81 landed one,
    /// the rc3 re-vendor brought it in, and that test failed by name with the
    /// instruction it was written to deliver. This is its replacement: the same
    /// question, asked of the new state.
    ///
    /// Deliberately keyed on the vendored MANIFEST, never on a section-walk or a
    /// local list: R2's normative enforcement surface is the manifest, and a
    /// second source of truth about what CC catalogues is the defect this whole
    /// area exists to prevent.
    #[test]
    fn regime_families_are_registered_by_the_vendored_manifest() {
        for dim in REGIME_DIMENSIONS {
            assert!(
                is_family_registered(dim),
                "CIRISPersist#571: {dim} is no longer registered. CIRISConstitution#81 landed \
                 `regime:{{artifact}}:{{version}}` and this crate vendors that cut — if the family \
                 has vanished, the re-vendor dropped it (see \
                 `registry::tests::no_vendored_family_silently_disappears`), it did not become \
                 open vocabulary again."
            );
        }
        assert!(
            is_family_registered(REGIME_FAMILY_STEM),
            "the stem itself must be registered — R2 speaks at family-stem granularity"
        );
        // The row is spelled the way CC spells it. #571 asked for four leaf
        // rows; CC landed ONE parameterised family covering all four, which is
        // the R2 granularity and the better answer — pin the spelling so a
        // re-vendor that re-spells it is visible.
        assert!(
            crate::federation::namespace::registry::entries()
                .iter()
                .any(|e| e.prefix == "regime:{artifact}:{version}"),
            "the CC row must be the parameterised family `regime:{{artifact}}:{{version}}`"
        );
    }

    /// **The remaining half of #571, as a failing-when-fixed pin.**
    ///
    /// The row's PROSE says *"reserved — substrate-steward-emitted"*. The row's
    /// generated STRUCTURE says `"reserved": false` with no `reserved_rule`, so
    /// [`authority_for`] has no rule to report and persist has none to enforce.
    ///
    /// The cause is structural, not a typo: CC's generator cross-references
    /// reserved rules from CC 3.4 (plus a `Reserved?` table column where one
    /// exists), and the `regime:` row sits in CC 3.1.9.2 — a three-column table
    /// with no such column, whose prose names no CC 3.4 clause.
    ///
    /// This FAILS the day CC lands the rule where the generator can reach it,
    /// which is the day persist writes the `regime:` gate. Until then persist
    /// gates nothing on this family, and that is a decision with a stated
    /// reason rather than an oversight.
    #[test]
    fn the_regime_row_still_states_no_machine_readable_rule() {
        for dim in REGIME_DIMENSIONS {
            let authority = authority_for(dim);
            assert!(
                authority.reserved.is_none(),
                "CIRISPersist#571 IS NOW FINISHABLE: the vendored `regime:` row carries a \
                 machine-readable rule ({:?}). CC has landed what the row's prose always claimed \
                 (\"reserved — substrate-steward-emitted\"). Write the persist gate to match THAT \
                 rule — not the prose — add the stem to the governed set, delete this pin, and \
                 delete the ask in this module's header.",
                authority.reserved
            );
        }
        // The prose half, quoted from the vendored bytes rather than from
        // memory, so "the row says one thing and generates another" is a
        // checked claim and not a comment. If CC rewords the description, this
        // fails and a human re-reads the row — which is the correct outcome:
        // the whole finding is about the gap between these two fields.
        let row = crate::federation::namespace::registry::entries()
            .iter()
            .find(|e| e.prefix == "regime:{artifact}:{version}")
            .expect("the regime row is registered");
        assert_eq!(
            row.cc_section, "3.1.9.2",
            "the row moved sections — re-check whether the generator can now reach its rule"
        );
        assert_eq!(
            row.authority.class,
            AuthorityClass::ProducerSteward,
            "an unreserved row must classify ProducerSteward"
        );
        assert!(
            row.description.contains("substrate-steward-emitted"),
            "the row's prose no longer claims an emitter rule (got {:?}) — if CC has WITHDRAWN the \
             reservation rather than landed it, `regime:*` is settled open vocabulary: say so here \
             and in the header, and stop waiting for a rule that is not coming",
            row.description
        );
        // The gap, stated as one assertion so a reader sees both halves at
        // once: the row claims a reservation in prose and generates none.
        assert!(
            row.description.contains("reserved") && row.authority.reserved.is_none(),
            "prose and structure have converged — one of the two branches above should have fired"
        );
    }

    /// The four leaves are ONE family, so one CC row and one grant prefix cover
    /// all four. Also pins that this const is a naming aid, not a local
    /// registry: nothing in the admission path consults it.
    #[test]
    fn the_four_leaves_all_sit_on_one_family_stem() {
        for dim in REGIME_DIMENSIONS {
            assert_eq!(
                family_stem(dim),
                REGIME_FAMILY_STEM,
                "{dim} must sit on the one stem a single CC row and a single grant prefix cover"
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // The decision, clause by clause
    // ══════════════════════════════════════════════════════════════════

    /// **Clause 5 — the old reason RETIRED by executing its falsification.**
    ///
    /// v27.0.0's `governing_regime_today_would_refuse_it` claimed: governing
    /// `regime:` would make CC 3.1.7 R2(b) refuse every `regime:*` emission,
    /// because there was no registry row to satisfy R2(b) with. That claim was
    /// TRUE and is now FALSE — CIRISConstitution#81 landed the row.
    ///
    /// Retiring it by deletion would leave "persist does not gate `regime:`"
    /// resting on a reason nobody could find again. So the claim is retired the
    /// only honest way: by asserting its negation on the same predicate that
    /// once produced it. R2(b) no longer reaches `regime:*` **even if the family
    /// were governed** — proven by driving the gate at the registered stem — and
    /// the probe stem, governed-and-unregistered by construction, still refuses.
    /// One differing input, opposite verdicts.
    ///
    /// What still holds is the DECISION, on its new footing: persist does not
    /// gate the family because the row states no rule to enforce (see
    /// [`the_regime_row_still_states_no_machine_readable_rule`]).
    #[test]
    fn governing_regime_would_now_admit_but_the_row_states_no_rule() {
        let governed = governed_family_stems();
        assert!(
            !governed.contains(&REGIME_FAMILY_STEM.to_owned()),
            "CIRISPersist#571 clause 5: `regime:` is now in a source `governed_family_stems()` \
             reads. That is no longer FATAL — the CC row satisfies R2(b), so emissions would still \
             admit — but persist has no rule to enforce on this family: the row carries no \
             `reserved_rule` and `substrate-steward-emitted` names no identity_type persist has. A \
             gate here would be persist enforcing CC's PROSE, which \
             `admission::tests::authority_lists_agree_on_every_manifest_family` fails the build \
             for. Land the rule on the CC row first."
        );
        assert!(
            !UNREGISTERED_GATED_FAMILIES.contains(&REGIME_FAMILY_STEM),
            "`regime:` must never ride the declared-exception list: that list grandfathers \
             families persist ALREADY gates that CC has NOT catalogued, and `regime:` is now the \
             exact opposite — catalogued by CC, gated by nobody"
        );

        // R2(b) admits — as it did before, but for the opposite reason. Then it
        // was ungoverned; now the family is REGISTERED, which is the condition
        // that would hold even under governance.
        for dim in REGIME_DIMENSIONS {
            check_namespace_family_registered(dim)
                .unwrap_or_else(|e| panic!("{dim} must admit under R2(b): {e}"));
            assert!(
                is_family_registered(dim),
                "{dim} must admit because it is REGISTERED — if it admits only because it is \
                 ungoverned, the old reason is still the live one and this test is lying"
            );
        }

        // The SAME predicate still refuses a governed-and-unregistered family,
        // so the admit above is a decision and not a dead gate.
        let probe = format!(
            "{}manifest:v1",
            crate::federation::admission::R2_PROBE_UNREGISTERED_STEM
        );
        let err = check_namespace_family_registered(&probe)
            .expect_err("a governed-but-unregistered family must refuse");
        assert_eq!(err.kind(), "federation_namespace_family_unregistered");
    }

    /// **Clause 4.** The family resolves to a self-attested producer claim with
    /// no reserved rule — the honest reading of a research artifact: evidence
    /// about its own producer's run, signed by that producer, carrying no
    /// warrant persist conferred.
    ///
    /// Both halves are asserted TOGETHER on purpose. Before the re-vendor this
    /// answer came from `authority_for`'s uncatalogued-family fallback; after
    /// it, the family IS catalogued and the answer is unchanged — which is the
    /// finding, not a coincidence. A future re-vendor that lands the rule flips
    /// the second assertion while the first still passes, and the pair is what
    /// makes that legible.
    #[test]
    fn regime_authority_is_unreserved_producer_steward() {
        for dim in REGIME_DIMENSIONS {
            let authority = authority_for(dim);
            assert_eq!(
                authority.class,
                AuthorityClass::ProducerSteward,
                "{dim} must classify as a producer claim"
            );
            assert!(
                authority.reserved.is_none(),
                "{dim} must carry no reserved rule — persist has not been given one to enforce"
            );
            assert!(
                is_family_registered(dim),
                "{dim} must be REGISTERED while resolving ProducerSteward — that pairing is \
                 CIRISPersist#571's remaining finding (a row that ends the ProducerSteward default \
                 in prose and not in structure). If registration has gone away, the re-vendor \
                 regressed."
            );
        }
    }

    // ══════════════════════════════════════════════════════════════════
    // The executed replication witness — every backend persist ships
    // ══════════════════════════════════════════════════════════════════

    /// Register `attester` + `subject` and land a **local-tier** `regime:*`
    /// `scores` row through the REAL `put_attestation` door, then promote it
    /// through the REAL `promote_attestation` door. Both doors run
    /// `check_reserved_prefix_admission` → `check_namespace_family_registered`,
    /// so this is the R2 gate on the production path, not a hand-built `Error`.
    ///
    /// Returns `Ok(())` when both doors admitted.
    #[cfg(any(test, feature = "test-anchor"))]
    async fn regime_row_survives_both_doors(
        dir: &dyn crate::federation::FederationDirectory,
        suffix: &str,
        dimension: &str,
    ) -> Result<(), crate::federation::Error> {
        let (id, attester) = land_local(dir, suffix, dimension).await?;
        promote_to_federation(dir, &id, &attester).await
    }

    /// **Door 1** — the local-tier write, through the real `put_attestation`.
    /// Returns `(attestation_id, attester_key_id)`.
    #[cfg(any(test, feature = "test-anchor"))]
    async fn land_local(
        dir: &dyn crate::federation::FederationDirectory,
        suffix: &str,
        dimension: &str,
    ) -> Result<(String, String), crate::federation::Error> {
        use crate::federation::types::{attestation_tier, cohort_scope};
        use crate::federation::SignedAttestation;

        let (id, attester, mut row) = build_row(dir, suffix, dimension).await;
        row.tier = attestation_tier::LOCAL.to_owned();
        row.cohort_scope = cohort_scope::SELF.to_owned();
        dir.put_attestation(SignedAttestation { attestation: row })
            .await?;
        Ok((id, attester))
    }

    /// **Door 2** — the promotion, carrying a federation-visible placement.
    #[cfg(any(test, feature = "test-anchor"))]
    async fn promote_to_federation(
        dir: &dyn crate::federation::FederationDirectory,
        id: &str,
        attester: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::types::{attestation_tier, cohort_scope};

        dir.promote_attestation(
            id,
            cohort_scope::FEDERATION,
            "c2ln",
            Some("cHFj"),
            "deadbeef",
            attester,
            chrono::Utc::now(),
        )
        .await?;
        let stored = dir
            .get_attestation(id)
            .await?
            .expect("the promoted row exists");
        assert_eq!(stored.tier, attestation_tier::FEDERATION);
        assert_eq!(stored.cohort_scope, cohort_scope::FEDERATION);
        Ok(())
    }

    /// **Door 3** — the DIRECT federation-tier write. A promotion ban that only
    /// covers the promote path is not a ban; an inbound peer row arrives here.
    #[cfg(any(test, feature = "test-anchor"))]
    async fn write_at_federation_tier(
        dir: &dyn crate::federation::FederationDirectory,
        suffix: &str,
        dimension: &str,
    ) -> Result<(), crate::federation::Error> {
        use crate::federation::SignedAttestation;
        let (_, _, row) = build_row(dir, suffix, dimension).await;
        dir.put_attestation(SignedAttestation { attestation: row })
            .await
            .map(|_| ())
    }

    /// Register `attester`/`subject` and build a really-hybrid-signed `scores`
    /// row on `dimension` (federation tier, federation scope — callers
    /// downgrade). Returns `(id, attester, row)`.
    #[cfg(any(test, feature = "test-anchor"))]
    async fn build_row(
        dir: &dyn crate::federation::FederationDirectory,
        suffix: &str,
        dimension: &str,
    ) -> (String, String, crate::federation::Attestation) {
        let attester = format!("regime571-attester-{suffix}");
        let subject = format!("regime571-subject-{suffix}");
        for k in [&attester, &subject] {
            crate::federation::tier_ingest::test_support::register_hybrid_key(dir, k).await;
        }
        // UUID, not a readable slug: postgres types `attestation_id` as `uuid`
        // and rejects anything else at the driver.
        let id = uuid::Uuid::new_v4().to_string();
        let row = crate::federation::bootstrap_admission::test_support::scores_row(
            &id, &attester, &subject, dimension,
        );
        (id, attester, row)
    }

    /// **The backend-uniform half of the decision.** On every backend persist
    /// ships: all four `regime:*` leaves clear the local write AND the
    /// promotion, and the R2 probe — governed, unregistered, otherwise
    /// identical — is refused at the first door. One differing input, opposite
    /// verdicts, same production path.
    #[cfg(any(test, feature = "test-anchor"))]
    async fn regime_replication_body(dir: &dyn crate::federation::FederationDirectory, tag: &str) {
        for (i, dim) in REGIME_DIMENSIONS.iter().enumerate() {
            regime_row_survives_both_doors(dir, &format!("{tag}-{i}"), dim)
                .await
                .unwrap_or_else(|e| {
                    panic!("{dim} must federate on {tag} (CIRISPersist#571 decision): {e}")
                });
        }

        let probe = format!(
            "{}manifest:v1",
            crate::federation::admission::R2_PROBE_UNREGISTERED_STEM
        );
        let err = regime_row_survives_both_doors(dir, &format!("{tag}-probe"), &probe)
            .await
            .expect_err("a governed-but-unregistered family must be refused on the same path");
        assert_eq!(
            err.kind(),
            "federation_namespace_family_unregistered",
            "the R2 door must be the thing refusing on {tag}, not some unrelated gate"
        );

        // ── CC 3.1.7 R2 Private Use, the contrast that makes the decision
        //    legible: `x_private:*` is the range `regime:*` was considered for
        //    and rejected for, and it is BANNED from federation tier on every
        //    door. Asserted right next to the admit so the two verdicts are
        //    read together.
        private_use_is_banned_from_federation_tier(dir, tag).await;

        // ── The other family the same re-vendor unblocked. Rides this body so
        //    it inherits the three-backend trio rather than growing a fourth.
        cc_3414_r1_class_marking_admits_from_any_attester(dir, tag).await;
    }

    /// **CC 3.4.14 R1 — "Class marking is universal (every attester)"**, the
    /// regression witness for the gate this cut REMOVED.
    ///
    /// Until the rc3 re-vendor, persist carried a CEG-0.3 `ReservedPrefixRule`
    /// pinning `content_class:` to `identity_type = substrate_persist`. CC then
    /// catalogued the family (CIRISConstitution#77) and its semantics section,
    /// CC 3.3.12, opens *"All four families are open vocabulary"* — while
    /// CC 3.4.14 R1 makes `content_class:generated` / `generated_modified`
    /// MANDATORY on any Contribution carrying generated content, and R2 requires
    /// an agent's marking to ride a key whose `identity_type` contains `agent`.
    ///
    /// So persist's gate refused, on every backend, precisely the row CC makes
    /// mandatory — blocking the Art. 50(2) disclosure path (applicable
    /// 2026-08-02; discharged in CIRISAgent 2.9.8 / CIRISServer 0.6) at the
    /// substrate. Measured before it was fixed:
    /// `ReservedPrefixEmitterMismatch { required: ["substrate_persist"],
    /// got_identity_type: "agent" }`.
    ///
    /// The test keys on an `agent`-typed key deliberately — that is R2's
    /// required shape and was the exact identity the old rule refused. A
    /// negative control rides alongside: `age_assurance:` is the ONE family in
    /// CC 3.3.12 that IS reserved (witness-only, and it carries a real
    /// `reserved_rule` in the manifest), and it must still refuse an `agent`
    /// key. Without it this test would pass just as happily if every
    /// reserved-prefix rule had been deleted.
    #[cfg(any(test, feature = "test-anchor"))]
    async fn cc_3414_r1_class_marking_admits_from_any_attester(
        dir: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) {
        // `register_hybrid_key` registers `identity_type = agent` — CC 3.4.14
        // R2's required shape, and what the removed rule rejected.
        //
        // The `:v1` leaf is the pre-existing T3 version-pinning convention
        // (CEG §13.1, `require_version_segment`) that every `scores` dimension
        // in persist carries; it is orthogonal to this cut and applies to the
        // `{class}` token as open vocabulary. Worth knowing rather than
        // discovering: CC 3.4.14 R1 spells the marking `content_class:generated`
        // unversioned, so a producer emitting CC's literal spelling is refused
        // by T3, not by any emitter rule. That is a separate question from this
        // one and is NOT what #571 changed.
        for (i, dim) in [
            "content_class:generated:v1",
            "content_class:generated_modified:v1",
        ]
        .iter()
        .enumerate()
        {
            land_local(dir, &format!("{tag}-cc3414-{i}"), dim)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "CC 3.4.14 R1 — class marking is universal (EVERY attester): {dim} was \
                         refused from an `agent`-typed key on {tag} ({e}). A gate on \
                         `content_class:` refuses the marking CC makes mandatory and blocks the \
                         Art. 50(2) disclosure path; CC 3.3.12 leaves the family open vocabulary. \
                         See admission::MEDIA_PLANE_FAMILIES_CC_LEAVES_OPEN."
                    )
                });
        }
        // The sibling families CC 3.3.12 also leaves open.
        for (i, dim) in ["content_rating:mpaa:pg13:v1", "cw_class:horror:v1"]
            .iter()
            .enumerate()
        {
            land_local(dir, &format!("{tag}-open-{i}"), dim)
                .await
                .unwrap_or_else(|e| {
                    panic!("CC 3.3.12 leaves {dim} open vocabulary; refused on {tag}: {e}")
                });
        }
        // NEGATIVE CONTROL — the one row in that CC 3.3.12 table that IS
        // reserved must still refuse the same key. Proves the three admits
        // above are a scoped decision, not a deleted gate.
        let err = land_local(
            dir,
            &format!("{tag}-agegate"),
            "age_assurance:provider:adult:v1",
        )
        .await
        .expect_err(
            "CC 3.3.12 + CC 3.4.11: `age_assurance:` is witness-reserved and must still \
                 refuse an `agent`-typed emitter — if this admits, the media-plane fix deleted \
                 more than CC leaves open",
        );
        assert_eq!(
            err.kind(),
            "federation_reserved_prefix_emitter_mismatch",
            "the reserved-prefix gate must be what refuses `age_assurance:` on {tag}"
        );
    }

    /// **CC 3.1.7 R2, the Private Use range** (landed on rc3 after v26.0.0
    /// shipped #590): *"private-use families MUST NOT admit at federation tier
    /// under any authority."*
    ///
    /// Three doors, because a ban that covers one is not a ban:
    ///
    /// 1. the **local** write still ADMITS — Private Use is a legitimate range,
    ///    not a forbidden one, and refusing it locally would delete the thing
    ///    CC created it for (RFC 6648: no legitimate unregistered range is how
    ///    `X-` squatting gets minted);
    /// 2. the **promotion** local→federation is REFUSED;
    /// 3. the **direct federation-tier write** — the shape an inbound peer row
    ///    arrives in — is REFUSED.
    ///
    /// "Under any authority" is why the refusal is unconditional on the
    /// attester rather than resolved through `authority_for`: there is no
    /// identity, role, or co-scrub that buys a private-use row a federation
    /// tier.
    #[cfg(any(test, feature = "test-anchor"))]
    async fn private_use_is_banned_from_federation_tier(
        dir: &dyn crate::federation::FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::admission::PRIVATE_USE_FAMILY_STEM;

        let dim = format!("{PRIVATE_USE_FAMILY_STEM}regime:composition:v1");

        // (1) local ADMITS — the range exists to be usable.
        let (id, attester) = land_local(dir, &format!("{tag}-xp"), &dim)
            .await
            .unwrap_or_else(|e| panic!("{dim} must admit at LOCAL tier on {tag}: {e}"));

        // (2) promotion REFUSED.
        let err = promote_to_federation(dir, &id, &attester)
            .await
            .expect_err("CC 3.1.7 R2: a private-use row must not be promotable to federation tier");
        assert_eq!(
            err.kind(),
            "federation_namespace_private_use_not_federatable",
            "the private-use ban must be what refuses the promotion on {tag}"
        );

        // The refused promotion left the row untouched (verify-before-mutation).
        let after = dir
            .get_attestation(&id)
            .await
            .expect("read back")
            .expect("row survives a refused promotion");
        assert_eq!(
            after.tier,
            crate::federation::types::attestation_tier::LOCAL
        );

        // (3) the DIRECT federation-tier write REFUSED — the inbound-peer shape.
        let err = write_at_federation_tier(dir, &format!("{tag}-xpdirect"), &dim)
            .await
            .expect_err("CC 3.1.7 R2: a private-use row must not admit at federation tier");
        assert_eq!(
            err.kind(),
            "federation_namespace_private_use_not_federatable",
            "the private-use ban must be what refuses the direct write on {tag}"
        );
    }

    #[tokio::test]
    async fn regime_replicates_memory() {
        let dir = crate::store::MemoryBackend::new();
        regime_replication_body(&dir, "mem").await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn regime_replicates_sqlite() {
        use crate::store::Backend;
        let dir = crate::store::SqliteBackend::open_in_memory()
            .await
            .expect("sqlite");
        dir.run_migrations().await.expect("migrations");
        regime_replication_body(&dir, "sq").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn regime_replicates_postgres() {
        use crate::store::Backend;
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let dir = crate::store::PostgresBackend::connect(&dsn)
            .await
            .expect("pg");
        dir.run_migrations().await.expect("migrations");
        let tag = format!("pg{}", uuid::Uuid::new_v4().simple());
        regime_replication_body(&dir, &tag).await;
    }

    // ══════════════════════════════════════════════════════════════════
    // Clause 1: the grant IS the whole mechanism
    // ══════════════════════════════════════════════════════════════════

    /// **The falsification of #571's second premise.** A `regime:*` artifact
    /// does not "never leave the producing node" because persist keeps an
    /// allowlist — persist keeps none. It leaves the moment this node's own
    /// signed `consent:replication:v1` grant names [`REGIME_FAMILY_STEM`], and
    /// stays put when the grant names something else.
    ///
    /// Both arms in one test on purpose: a promotion witness with no
    /// negative control proves only that *something* promoted the row.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn consent_grant_body(
        engine: &crate::engine::Engine,
        dir: &dyn crate::federation::FederationDirectory,
        derived: &str,
        tag: &str,
    ) {
        use crate::federation::types::{attestation_tier, cohort_scope};

        let local_row = |dimension: &str| crate::federation::types::LocalAttestationInput {
            // UUID: postgres types `attestation_id` as `uuid`.
            attestation_id: Some(uuid::Uuid::new_v4().to_string()),
            attesting_key_id: derived.to_owned(),
            attested_key_id: None,
            attestation_type: crate::federation::types::attestation_type::SCORES.to_owned(),
            weight: None,
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                serde_json::json!({
                    "dimension": dimension,
                    "campaign_id": "torque-17",
                }),
            )
            .expect("envelope"),
            subject_key_ids: vec![derived.to_owned()],
            cohort_scope: cohort_scope::SELF.to_owned(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };

        let first = dir
            .attestation_insert_local(local_row("regime:manifest:v1"))
            .await
            .expect("insert local regime row");
        let second = dir
            .attestation_insert_local(local_row("regime:manifest:v1"))
            .await
            .expect("insert local regime row");
        // A private-use row alongside them, to prove the consent edge cannot
        // buy what CC forbids (CC 3.1.7 R2, "under any authority").
        let private = dir
            .attestation_insert_local(local_row(&format!(
                "{}regime:manifest:v1",
                crate::federation::admission::PRIVATE_USE_FAMILY_STEM
            )))
            .await
            .expect("insert local private-use row");

        // NEGATIVE CONTROL — a grant covering only `capacity:` (#571's quoted
        // deployment posture) leaves the regime rows exactly where they are.
        emit_replication_grant(engine, &format!("peer-571-capacity-{tag}"), &["capacity:"]).await;
        engine.promote_consented_backlog().await.expect("sweep");
        for id in [&first, &second] {
            let row = dir.get_attestation(id).await.unwrap().expect("row");
            assert_eq!(
                row.tier,
                attestation_tier::LOCAL,
                "a capacity:-only grant must not federate a regime:* row"
            );
        }

        // THE DECISION — naming the stem is the entire mechanism. The grant's
        // (c) hook fires the promote sweep, so no explicit call is needed.
        emit_replication_grant(
            engine,
            &format!("peer-571-regime-{tag}"),
            &[REGIME_FAMILY_STEM],
        )
        .await;
        let after = dir.get_attestation(&first).await.unwrap().expect("row");
        assert_eq!(
            after.tier,
            attestation_tier::FEDERATION,
            "a grant naming `regime:` federates the regime row — there is no allowlist to add to"
        );
        assert_eq!(
            after.cohort_scope,
            cohort_scope::FEDERATION,
            "clause 3: the placement is carried from the covering grant's audience, never `self`"
        );
        // The second row rides the same grant — the coverage is the FAMILY, not
        // the row (clause 1: one prefix covers all four leaves).
        let sibling = dir.get_attestation(&second).await.unwrap().expect("row");
        assert_eq!(sibling.tier, attestation_tier::FEDERATION);

        // ── CC 3.1.7 R2 Private Use vs the consent edge. A grant naming
        //    `x_private:` is a mistake an operator can absolutely make, and the
        //    grant is this node's OWN signed authority — the strongest one the
        //    sweep ever sees. "Under any authority" means it still does not
        //    move the row. The sweep skips it (a refused promotion is logged
        //    and counted, never fatal), so the rest of the backlog is
        //    unaffected — a poisoned row must not wedge the walk.
        emit_replication_grant(
            engine,
            &format!("peer-571-private-{tag}"),
            &[crate::federation::admission::PRIVATE_USE_FAMILY_STEM],
        )
        .await;
        engine.promote_consented_backlog().await.expect("sweep");
        let stayed = dir.get_attestation(&private).await.unwrap().expect("row");
        assert_eq!(
            stayed.tier,
            attestation_tier::LOCAL,
            "a consent grant cannot federate an x_private:* row — CC 3.1.7 R2 forbids it under \
             ANY authority, and this node's own signed grant is an authority"
        );
        assert_eq!(
            stayed.cohort_scope,
            cohort_scope::SELF,
            "the refused promotion left the row byte-identical (verify-before-mutation)"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn a_consent_grant_naming_regime_federates_a_regime_row() {
        let alias = "node-571-sq";
        let signer = crate::federation::tier_ingest::test_support::local_signer(alias);
        let derived = signer.derived_key_id();
        let engine = crate::engine::Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        let sq = engine.sqlite_backend().expect("sqlite").clone();
        // The signer's keypair is seeded from its ALIAS, while the rows it
        // signs are keyed by its DERIVED id — register the derived id carrying
        // the alias's pubkeys, else the federation-tier ingest gate refuses
        // this node's own grant.
        crate::federation::tier_ingest::test_support::register_hybrid_key_aliased(
            &*sq, &derived, alias,
        )
        .await;
        consent_grant_body(&engine, &*sq, &derived, "sq").await;
    }

    /// The postgres twin. Not a formality: the `uuid` typing of
    /// `attestation_id` and the real SQL write-back are exactly the class
    /// sqlite/memory tolerate and pg refuses.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn a_consent_grant_naming_regime_federates_a_regime_row_postgres() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let tag = uuid::Uuid::new_v4().simple().to_string();
        let alias = format!("node-571-pg-{tag}");
        let signer = crate::federation::tier_ingest::test_support::local_signer(&alias);
        let derived = signer.derived_key_id();
        let engine = crate::engine::Engine::with_signer(signer, &dsn)
            .await
            .expect("pg engine");
        let pg = engine.postgres_backend().expect("pg").clone();
        crate::federation::tier_ingest::test_support::register_hybrid_key_aliased(
            &*pg, &derived, &alias,
        )
        .await;
        consent_grant_body(&engine, &*pg, &derived, &tag).await;
    }

    /// Emit a self-authored `consent:replication:v1` grant naming `peer` as the
    /// consented recipient and `prefixes` as the covered families — the same
    /// shape a real node's operator lands, through `emit_attestation_self` so it
    /// is federation-tier and hybrid-signed.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    async fn emit_replication_grant(
        engine: &crate::engine::Engine,
        peer: &str,
        prefixes: &[&str],
    ) -> String {
        let envelope = crate::federation::envelope::EnvelopeCore::from_value(serde_json::json!({
            "dimension": crate::federation::consent_peer_set::DIMENSION,
            "subject_key_ids": [peer],
            "payload": {"grants": "replication", "attestation_prefixes": prefixes},
            "subject_kind": "consent_replication",
        }))
        .expect("grant envelope");
        let mut input = crate::federation::EmitAttestationInput::with_envelope(
            crate::federation::types::attestation_type::SCORES,
            envelope,
            crate::federation::types::cohort_scope::FEDERATION,
        );
        input.subject_key_ids = vec![peer.to_owned()];
        engine
            .emit_attestation_self(input)
            .await
            .expect("replication grant emits")
    }
}
