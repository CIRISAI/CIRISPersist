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
//! # The registry half is the Constitution's, and it is not landed
//!
//! Persist does not author namespace rows. [`registry`](super::namespace::registry)
//! is GENERATED from CC Part 3 by the Constitution's own
//! `tools/build_cc_namespace.py` and vendored here byte-for-byte, pinned by
//! [`VENDORED_SOURCE_SHA256`](super::namespace::registry::VENDORED_SOURCE_SHA256).
//! **CC carries no `regime:` family** — checked against `rc3` HEAD, not merely
//! against the vendored copy, precisely so the finding cannot be an artifact of
//! a stale vendor. It is absent from the cut this crate vendors (109 families)
//! AND from the newer cut on `rc3` (112 families, which added the CEG-0.3
//! catalogue rows). There is no version of "pull the newer manifest" that
//! produces a `regime:` row, so re-vendoring — which this module deliberately
//! does not do, it is #519/#586's surface — would not unblock the ask either.
//!
//! A row hand-added *here* would be exactly the generated-vs-hand-maintained
//! split truth CC 3.1.7 R2 exists to end, so this module adds none. What it
//! adds instead is a finding that cannot be forgotten:
//! [`tests::regime_families_are_still_absent_from_the_vendored_manifest`] fails
//! the day CC lands the rows — which is the day #571 can be finished — the same
//! shape as
//! [`UNREGISTERED_GATED_FAMILIES`](super::admission::UNREGISTERED_GATED_FAMILIES)'s
//! "the excuse deletes itself" pin, without granting persist the governance
//! carve-out that pin grants.
//!
//! **The exception pin does not fit this family and was deliberately not used.**
//! `UNREGISTERED_GATED_FAMILIES` grandfathers three CEG-0.3 families persist has
//! *already gated* since v3.0.0 and CC never catalogued — enforcement that
//! predates R2, named in source rather than implied by silence. `regime:*` is a
//! family being introduced today, which persist does not gate and has no rule
//! for. Putting it on that list would convert a named residual into a
//! general-purpose bypass: the mechanism for "we govern this and CC hasn't
//! caught up" would become the mechanism for "CC hasn't ruled, so we ruled."
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
//! 4. **Authority is `ProducerSteward` — self-attested and un-reserved.** This
//!    is what [`authority_for`](super::namespace::registry::authority_for)
//!    already returns for an uncatalogued family, and for this one it is also
//!    the honest answer: a `regime:gate:v1` from peer X is evidence about X's
//!    own run, signed by X. Persist confers no warrant on it and no reader
//!    should read one. Whether CC eventually reserves the family (as it did
//!    `trace:{form}:{version}` — CC 3.1.5 / 3.4.5, catalogued after persist
//!    shipped the interim validator) is CC's call, not this module's.
//!
//! 5. **Letting it federate IS the decision not to gate it — today those are
//!    the same decision.** Adding `regime:` to any source
//!    [`governed_family_stems`](super::admission::governed_family_stems) reads
//!    would make CC 3.1.7 R2(b) refuse the family outright, because there is no
//!    row to satisfy R2(b) with: every `regime:*` emission would fail with
//!    `namespace_family_unregistered`, taking out the local-tier path
//!    CIRISAgent depends on today. So "govern it" and "let it replicate" are
//!    presently mutually exclusive, and this is a footgun #571's own existence
//!    creates. [`tests::governing_regime_today_would_refuse_it`] states it as an
//!    executed witness rather than a hope.
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

    /// **The self-deleting pin.** #571's registry half is blocked on a CC Part-3
    /// row; this asserts the block is still real. It FAILS the moment CC lands
    /// `regime:*` and persist re-vendors — which is the signal to finish #571
    /// (resolve the emitter rule, decide whether persist gates it, and delete
    /// this test), not a signal to relax the assertion.
    ///
    /// Deliberately keyed on the vendored MANIFEST, never on a section-walk or a
    /// local list: R2's normative enforcement surface is the manifest, and a
    /// second source of truth about what CC catalogues is the defect this whole
    /// area exists to prevent.
    #[test]
    fn regime_families_are_still_absent_from_the_vendored_manifest() {
        for dim in REGIME_DIMENSIONS {
            assert!(
                !is_family_registered(dim),
                "CIRISPersist#571: CC has catalogued {dim} — the registry half is no longer \
                 blocked. Finish #571: resolve the emitter rule from the new row, re-decide \
                 whether persist governs the family (see \
                 `governing_regime_today_would_refuse_it`), and delete this pin."
            );
        }
        assert!(
            !is_family_registered(REGIME_FAMILY_STEM),
            "the stem itself must be unregistered too — a row on any leaf registers the family"
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

    /// **Clause 5, and the footgun guard.** `regime:*` must NOT be a governed
    /// family while CC carries no row for it: R2(b) refuses a governed family
    /// with no row, so governing it would refuse every `regime:*` emission —
    /// including the local-tier path CIRISAgent uses today.
    ///
    /// The refusal half is proven on the SAME predicate, not asserted: the
    /// `cfg(test)` R2 probe stem is governed-and-unregistered by construction,
    /// so the two calls below differ in exactly one input.
    #[test]
    fn governing_regime_today_would_refuse_it() {
        let governed = governed_family_stems();
        assert!(
            !governed.contains(&REGIME_FAMILY_STEM.to_owned()),
            "CIRISPersist#571 clause 5: `regime:` was added to a source \
             `governed_family_stems()` reads while CC still carries no row for it. That makes CC \
             3.1.7 R2(b) refuse EVERY regime:* emission with `namespace_family_unregistered`, \
             taking out the local-tier artifact path CIRISAgent depends on. Governing this \
             family requires the CC row first — not the other way round."
        );
        assert!(
            !UNREGISTERED_GATED_FAMILIES.contains(&REGIME_FAMILY_STEM),
            "the declared-exception pin grandfathers families persist ALREADY gates and CC never \
             catalogued; `regime:` is neither, and using it here would turn a named residual into \
             a general-purpose bypass"
        );

        // Ungoverned ⇒ R2(b) admits (the open vocabulary CC preserves).
        for dim in REGIME_DIMENSIONS {
            check_namespace_family_registered(dim)
                .unwrap_or_else(|e| panic!("{dim} must admit under R2(b) while ungoverned: {e}"));
        }

        // The SAME predicate refuses when the family IS governed and
        // unregistered — so the admit above is a decision, not a dead gate.
        let probe = format!(
            "{}manifest:v1",
            crate::federation::admission::R2_PROBE_UNREGISTERED_STEM
        );
        let err = check_namespace_family_registered(&probe)
            .expect_err("a governed-but-unregistered family must refuse");
        assert_eq!(err.kind(), "federation_namespace_family_unregistered");
    }

    /// **Clause 4.** The uncatalogued family resolves to a self-attested
    /// producer claim with no reserved rule — which is both what the classifier
    /// already does and the honest reading of a research artifact: evidence
    /// about its own producer's run, signed by that producer, carrying no
    /// warrant persist conferred.
    #[test]
    fn regime_authority_is_unreserved_producer_steward() {
        for dim in REGIME_DIMENSIONS {
            let authority = authority_for(dim);
            assert_eq!(
                authority.class,
                AuthorityClass::ProducerSteward,
                "{dim} must classify as a producer claim while CC is silent"
            );
            assert!(
                authority.reserved.is_none(),
                "{dim} must carry no reserved rule — persist has not been given one to enforce"
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
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
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
        let Ok(dsn) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
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
