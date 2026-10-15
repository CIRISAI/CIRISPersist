//! v58.0.0 (slice V) — I1100–I1110, the CC v1.0-rc8 re-vendor.
//!
//! - **I1100** (pure, `namespace::matcher`) — CC's ten `polarity_vectors`
//!   replay through the admission gate, refusal token included.
//! - **I1101** (pure) — every family's catalogue polarity resolves to a
//!   `_meta.polarity_classes` class, and the classes are CC 3.1.7 R4's sets:
//!   points are points (`-0.7` is outside `-1 / -0.5 only`), `positive-only`
//!   excludes zero, `signed` is the closed interval.
//! - **I1102** (pure) — the five Retirement Standard families (CC 3.1.5)
//!   parse and match: each resolves to its own row, a closed `{basis}` refuses
//!   a value outside it.
//! - **I1103** (pure) — `takedown_notice:{basis}:v1` (CC 3.1.1) admits every
//!   one of its eleven bases as the only family under the gated
//!   `takedown_notice:` stem; any other leaf is unregistered and a basis off
//!   the closed list is refused.
//! - **I1104** (pure) — `prohibited:{category}` is closed to 22 values: each
//!   passes the case gate AND the morally-charged-stem deny-list (three carry
//!   a listed stem), and a value outside the list is refused
//!   `namespace_vocab_value_unregistered`.
//! - **I1105** (pure) — `settlement:*` is no longer reserved and the three
//!   `ledger:*` rows carry CC 3.3.10.1's owner rule, so neither resolves to
//!   the substrate-self-report class any more.
//! - **I1106** a `scores` row outside its family's polarity class is refused
//!   `score_outside_declared_polarity` at the put door and the authored door,
//!   on a point class, a range class and the signed interval; in-class rows
//!   admit; nothing refused is stored.
//! - **I1107** the six rc8 families persist builds no door for are held shut
//!   at the put door; nothing is stored.
//! - **I1108** the `ledger:*` owner rule (CC 3.3.10.1): the owner's row
//!   admits, a live occurrence of the owner admits, a `delegates_to` delegate
//!   of the owner is refused (persist stores no serialization discipline to
//!   read), a stranger is refused.
//! - **I1109** a registered closed `prohibited` value carrying a deny-listed
//!   stem admits at the put door with an in-class score; an unregistered
//!   category is refused; nothing refused is stored.
//!
//! Each door witness runs on memory, sqlite and postgres (postgres through
//! `CIRIS_PERSIST_TEST_PG_URL`; without it the leg returns at once).

#[cfg(test)]
mod pure {
    use crate::federation::admission::{
        check_dimension_case_rule, check_score_within_declared_polarity, DimensionAdmissionPolicy,
    };
    use crate::federation::namespace::matcher::{match_family, placeholder_values, Refusal};
    use crate::federation::namespace::registry::{
        self, family_polarities, family_polarity_class, polarity_classes, PolarityClass,
    };
    use crate::federation::namespace::AuthorityClass;
    use crate::federation::types::identity_type::USER;

    fn row(dim: &str, score: Option<f64>) -> crate::federation::Attestation {
        let mut env = serde_json::json!({ "dimension": dim });
        if let Some(s) = score {
            env["score"] = serde_json::json!(s);
        }
        crate::federation::namespace::matcher::tests_support::scores_row(env)
    }

    fn polarity_refused(r: Result<(), crate::federation::Error>) -> bool {
        matches!(
            r,
            Err(crate::federation::Error::DimensionRejected { reason, .. })
                if reason == "score_outside_declared_polarity"
        )
    }

    /// **I1101** — every label resolves; the classes are R4's sets.
    #[test]
    fn i1101_every_family_polarity_resolves_to_an_r4_class() {
        let pc = polarity_classes().expect("rc8 carries _meta.polarity_classes");
        assert_eq!(pc.refusal, "score_outside_declared_polarity");
        let labels = family_polarities();
        assert_eq!(
            labels.len(),
            registry::VENDORED_N_FAMILIES,
            "I1101 every rc8 row declares a polarity"
        );
        for (fam, label) in labels {
            assert!(
                family_polarity_class(fam).is_some(),
                "I1101 {fam}: polarity {label:?} names no class in _meta.polarity_classes"
            );
        }
        let class = |n: &str| pc.classes.get(n).unwrap_or_else(|| panic!("{n}"));
        // Points are points, never intervals.
        let apophatic = class("-1 / -0.5 only");
        assert!(apophatic.admits(-1.0) && apophatic.admits(-0.5));
        for s in [-0.7, -0.75, 0.0, 1.0, -1.0000001] {
            assert!(!apophatic.admits(s), "I1101 -1 / -0.5 only admits {s}");
        }
        let halt = class("+1.0 only");
        assert!(halt.admits(1.0) && !halt.admits(0.999) && !halt.admits(-1.0));
        let revoked = class("-1 only");
        assert!(revoked.admits(-1.0) && !revoked.admits(-0.5));
        let boolean = class("boolean-via-score");
        assert!(boolean.admits(-1.0) && boolean.admits(1.0));
        assert!(!boolean.admits(0.0) && !boolean.admits(0.5));
        // positive-only is (0, 1]; signed and enumerated are [-1, 1].
        let pos = class("positive-only");
        assert!(!pos.admits(0.0) && pos.admits(1e-6) && pos.admits(1.0) && !pos.admits(1.01));
        for n in ["signed", "enumerated"] {
            let c = class(n);
            assert!(c.admits(-1.0) && c.admits(0.0) && c.admits(1.0), "{n}");
            assert!(
                !c.admits(1.5) && !c.admits(-1.5) && !c.admits(f64::NAN),
                "{n}"
            );
        }
        assert_eq!(class("per-leaf"), &PolarityClass::PerLeaf);
        // The aliases fold the three prose labels onto a class.
        assert_eq!(pc.class_name("see CC 3.4.1"), "+1.0 only");
        assert_eq!(pc.class_name("per-leaf (CC 3.3.1)"), "per-leaf");
        assert_eq!(
            pc.class_name("boolean-via-score; Indeterminate allowed → RESTRICTED"),
            "boolean-via-score"
        );
        // A per-leaf parent constrains nothing itself.
        assert_eq!(
            family_polarity_class("consent:{kind}").map(|(n, _)| n),
            Some("per-leaf")
        );
    }

    /// **I1101 (gate)** — the admission gate reads the class, never the
    /// label text, and judges a PRESENT `score`.
    ///
    /// A row with no `score` member is not judged. CC 2.1 marks `score`
    /// required; persist's own emitters omit it on positive-only and point
    /// families (genesis `trust:charter:v1`, `membership:proposal:v1`,
    /// `consent:partnership_grant:v1`, `trust:accepts:v1`), so the absence
    /// is a CC 2.1 conformance gap of persist's emitters, pinned here as one:
    /// the day the gate starts judging absence, persist's genesis must
    /// already carry its scores.
    #[test]
    fn i1101_gate_judges_a_present_score() {
        assert!(polarity_refused(check_score_within_declared_polarity(
            &row("prohibited:medical:v1", Some(0.0))
        )));
        // A present non-number is outside every class.
        let mut r = row("prohibited:medical:v1", None);
        r.attestation_envelope["score"] = serde_json::json!("-1");
        assert!(polarity_refused(check_score_within_declared_polarity(&r)));
        // Absence is not judged (the CC 2.1 gap above).
        check_score_within_declared_polarity(&row("prohibited:medical:v1", None)).unwrap();
        check_score_within_declared_polarity(&row("trust:charter:v1", None)).unwrap();
        // Signed: the whole closed interval.
        check_score_within_declared_polarity(&row("ledger:head:usd:v1", Some(-1.0))).unwrap();
        assert!(polarity_refused(check_score_within_declared_polarity(
            &row("ledger:head:usd:v1", Some(1.0001))
        )));
        // Open vocabulary and refused grammar are not this gate's question.
        check_score_within_declared_polarity(&row("no_such_family:thing:v1", Some(9.0))).unwrap();
        check_score_within_declared_polarity(&row("prohibited:gambling:v1", Some(9.0))).unwrap();
        // A composer is not a scores row.
        let mut r = row("prohibited:medical:v1", Some(0.3));
        r.attestation_type = "delegates_to".to_owned();
        check_score_within_declared_polarity(&r).unwrap();
    }

    /// **I1102** — the Retirement Standard rows parse and match, exactly as
    /// CC's reference matcher answers them.
    ///
    /// **CC rc8 defect, pinned as the reference states it.** All six rc8
    /// families spell their version as a LITERAL segment (`…:v1`) rather than
    /// a `{version}` placeholder, so the R3 trailing-version rule demands a
    /// second tail: the prose wire form `retirement:retired:v1` is refused
    /// `missing_version_segment`, and only `retirement:retired:v1:v1`
    /// resolves cleanly (the published vectors say the same:
    /// `retirement:sample:v1` → `missing_version_segment`). Persist's matcher
    /// is a port and must agree with the reference, so the fix is CC's
    /// generator; this witness reds when a re-vendor fixes it.
    #[test]
    fn i1102_retirement_families_parse_and_match() {
        for (dim, fam) in [
            ("retirement:retired:v1:v1", "retirement:{state}:v1"),
            ("retirement:retiring:v1:v1", "retirement:{state}:v1"),
            ("preserve_request:v1:v1", "preserve_request:v1"),
            ("preserve_response:v1:v1", "preserve_response:v1"),
            (
                "archive_release:wa_approval:v1:v1",
                "archive_release:{basis}:v1",
            ),
            (
                "archive_release:lawful_order:v1:v1",
                "archive_release:{basis}:v1",
            ),
            ("lawful_order:release:v1:v1", "lawful_order:release:v1"),
        ] {
            let m = match_family(dim);
            assert_eq!((m.family, m.refusal), (Some(fam), None), "I1102 {dim}");
            assert!(
                registry::VENDORED_FAMILY_PREFIXES.contains(&fam),
                "I1102 {fam} is pinned against silent removal"
            );
            // The single-tail prose form: the CC defect above.
            let single = dim.strip_suffix(":v1").unwrap();
            assert_eq!(
                (match_family(single).family, match_family(single).refusal),
                (Some(fam), Some(Refusal::MissingVersionSegment)),
                "I1102 {single}: CC rc8's literal-v1 prefixes still demand a second tail"
            );
        }
        for dim in [
            "archive_release:self_approval:v1:v1",
            "archive_release:self_approval:v1",
        ] {
            assert_eq!(
                match_family(dim).refusal,
                Some(Refusal::VocabValueUnregistered),
                "I1102 archive_release's basis is closed: {dim}"
            );
        }
        assert_eq!(
            placeholder_values("archive_release:{basis}:v1", "{basis}"),
            Some((
                &["wa_approval".to_owned(), "lawful_order".to_owned()][..],
                false
            ))
        );
    }

    /// The eleven `takedown_notice` bases, as CC 3.3.2 spells them on the wire.
    pub(super) const TAKEDOWN_BASES: [&str; 11] = [
        "dmca512",
        "dsa_article16",
        "tvec_terrorist",
        "ncmec_csam",
        "gifct_cip",
        "community_standards",
        "perceptual_hash_csam",
        "osa_illegal_content",
        "avmsd_age_inappropriate",
        "court_order",
        "steward_purge",
    ];

    /// **I1103** — the only family under the gated stem.
    #[test]
    fn i1103_takedown_notice_is_the_only_family_under_its_stem() {
        let (values, open) =
            placeholder_values("takedown_notice:{basis}:v1", "{basis}").expect("closed basis");
        assert!(!open);
        assert_eq!(values, TAKEDOWN_BASES, "I1103 the registry's basis list");
        // The doubled tail: the CC rc8 literal-`v1` defect pinned at I1102.
        for basis in TAKEDOWN_BASES {
            let dim = format!("takedown_notice:{basis}:v1:v1");
            let m = match_family(&dim);
            assert_eq!(
                (m.family, m.refusal),
                (Some("takedown_notice:{basis}:v1"), None),
                "I1103 {dim}"
            );
            assert_eq!(
                match_family(&format!("takedown_notice:{basis}:v1")).refusal,
                Some(Refusal::MissingVersionSegment)
            );
        }
        assert!(
            crate::federation::namespace::matcher::reserved_stems()
                .any(|s| s == "takedown_notice:"),
            "I1103 the stem is gated"
        );
        // Expectations are the CC reference matcher's own answers.
        for (dim, want) in [
            ("takedown_notice:other", Refusal::FamilyUnregistered),
            ("takedown_notice:dmca512:v2", Refusal::FamilyUnregistered),
            (
                "takedown_notice:dmca512:extra:v1",
                Refusal::FamilyUnregistered,
            ),
            ("takedown_notice:other:v1", Refusal::VocabValueUnregistered),
            (
                "takedown_notice:other:v1:v1",
                Refusal::VocabValueUnregistered,
            ),
            (
                "takedown_notice:dmca_512:v1:v1",
                Refusal::VocabValueUnregistered,
            ),
        ] {
            assert_eq!(match_family(dim).refusal, Some(want), "I1103 {dim}");
        }
    }

    /// **I1104** — the closed apophatic vocabulary.
    #[test]
    fn i1104_prohibited_is_closed_to_22_values() {
        let (values, open) =
            placeholder_values("prohibited:{category}", "{category}").expect("closed category");
        assert!(!open, "I1104 rc8 closes the vocabulary");
        assert_eq!(values.len(), 22);
        let policy = DimensionAdmissionPolicy::default();
        for v in values {
            let dim = format!("prohibited:{v}:v1");
            let r = row(&dim, Some(-1.0));
            check_dimension_case_rule(&r).unwrap_or_else(|e| panic!("I1104 {dim}: {e}"));
            policy
                .check("scores", Some(dim.as_str()), USER)
                .unwrap_or_else(|e| panic!("I1104 the deny-list refuses CC's own {dim}: {e}"));
            check_score_within_declared_polarity(&r).unwrap();
        }
        for dim in ["prohibited:gambling:v1", "prohibited:Medical:v1"] {
            assert!(
                check_dimension_case_rule(&row(dim, Some(-1.0))).is_err(),
                "I1104 {dim}"
            );
        }
        assert_eq!(
            match_family("prohibited:gambling:v1").refusal,
            Some(Refusal::VocabValueUnregistered)
        );
        // The deny-list still reads emitter-chosen text: an open-vocabulary
        // dimension carrying a listed stem is refused as before.
        assert!(policy
            .check("scores", Some("detection:emergent_deception:v1"), USER)
            .is_err());
        assert!(policy
            .check("scores", Some("chat:weapons_harmful:v1"), USER)
            .is_err());
    }

    /// **I1105** — `settlement:*` unreserved; `ledger:*` on the owner rule.
    #[test]
    fn i1105_settlement_unreserved_and_ledger_owner_rule() {
        let a = registry::authority_for("settlement:paid:v1");
        assert!(
            a.reserved.is_none(),
            "I1105 settlement:* is not reserved at rc8"
        );
        assert_eq!(a.class, AuthorityClass::ProducerSteward);
        assert!(
            crate::federation::namespace::matcher::reserved_stem_rule("settlement:paid:v1")
                .is_none()
        );
        for dim in [
            "ledger:head:usd:v1",
            "ledger:checkpoint:usd:v1",
            "ledger:promotion:v1",
        ] {
            let a = registry::authority_for(dim);
            let r = a.reserved.expect("I1105 ledger rows are reserved");
            assert_eq!(r.cc_ref, "CC 3.3.10.1", "{dim}");
            assert!(r.rule.starts_with("the ledger's single owner"), "{dim}");
            assert_eq!(a.class, AuthorityClass::ProducerSteward, "{dim}");
        }
    }
}

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::types::SignedAttestation;
    use crate::federation::{Attestation, FederationDirectory};

    /// A `scores` row about `attested`, sealed by `signer` (registered with
    /// its deterministic fixture keys).
    fn scores(signer: &str, attested: &str, env: serde_json::Value) -> Attestation {
        let id = uuid::Uuid::new_v4().to_string();
        let mut r = ts::bare_attestation(&id, signer, attested, &env);
        r.attestation_type = crate::federation::types::attestation_type::SCORES.to_owned();
        ts::seal_row_in_place(signer, &mut r);
        r
    }

    async fn key<B: FederationDirectory + Sync>(b: &B, name: &str) -> String {
        ts::register_hybrid_key_as(b, name, name, USER).await;
        name.to_owned()
    }

    /// Put through the replicated door and the authored door.
    async fn both_doors<B: FederationDirectory + Sync>(
        b: &B,
        r: &Attestation,
    ) -> [Result<(), crate::federation::Error>; 2] {
        let put = b
            .put_attestation(SignedAttestation {
                attestation: r.clone(),
            })
            .await
            .map(|_| ());
        let authored = b
            .put_attestation_authored(SignedAttestation {
                attestation: r.clone(),
            })
            .await
            .map(|_| ());
        [put, authored]
    }

    fn reason_of(e: &crate::federation::Error) -> Option<&'static str> {
        match e {
            crate::federation::Error::DimensionRejected { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    async fn refused_everywhere<B: FederationDirectory + Sync>(
        b: &B,
        r: &Attestation,
        reason: &str,
        why: &str,
    ) {
        for (door, got) in ["put", "authored"].iter().zip(both_doors(b, r).await) {
            let e = got.expect_err(why);
            assert_eq!(reason_of(&e), Some(reason), "{why} ({door}): {e}");
        }
        assert!(
            b.get_attestation(&r.attestation_id)
                .await
                .unwrap()
                .is_none(),
            "{why}: a refused row is not stored"
        );
    }

    /// **I1106** — the polarity gate at the doors.
    pub async fn i1106_polarity_refused_at_the_doors<B: FederationDirectory + Sync>(
        b: &B,
        s: &str,
    ) {
        let w = key(b, &format!("i1106-{s}")).await;
        const OUT: &str = "score_outside_declared_polarity";
        for (dim, score, why) in [
            (
                "prohibited:medical:v1",
                -0.7,
                "I1106 a point class refuses -0.7",
            ),
            (
                "prohibited:medical:v1",
                1.0,
                "I1106 the apophatic class refuses +1",
            ),
            (
                "need:food:shelter:v1",
                0.0,
                "I1106 positive-only refuses zero",
            ),
            (
                "need:food:shelter:v1",
                -0.5,
                "I1106 positive-only refuses a negative",
            ),
            (
                "no_such_family:thing:v1",
                1.5,
                "I1106 an uncatalogued dim is open vocabulary",
            ),
            ("chat:leaf:v1", 1.5, "I1106 signed refuses a score above 1"),
            (
                "activity_tier:daily:v1",
                0.5,
                "I1106 boolean-via-score refuses 0.5",
            ),
        ] {
            let r = scores(
                &w,
                &w,
                serde_json::json!({"dimension": dim, "score": score}),
            );
            if dim.starts_with("no_such_family:") {
                // Open vocabulary: the gate has nothing to say.
                for got in both_doors(b, &r).await {
                    got.unwrap_or_else(|e| panic!("{why}: {e}"));
                }
                continue;
            }
            refused_everywhere(b, &r, OUT, why).await;
        }
        for (dim, score) in [
            ("prohibited:medical:v1", -1.0),
            ("prohibited:medical:v1", -0.5),
            ("need:food:shelter:v1", 0.25),
            ("activity_tier:daily:v1", -1.0),
        ] {
            let r = scores(
                &w,
                &w,
                serde_json::json!({"dimension": dim, "score": score}),
            );
            b.put_attestation(SignedAttestation {
                attestation: r.clone(),
            })
            .await
            .unwrap_or_else(|e| panic!("I1106 {dim} {score} is in class: {e}"));
            assert!(b
                .get_attestation(&r.attestation_id)
                .await
                .unwrap()
                .is_some());
        }
    }

    /// **I1107** — the rc8 families with no door are held shut.
    pub async fn i1107_rc8_families_held_shut<B: FederationDirectory + Sync>(b: &B, s: &str) {
        let w = key(b, &format!("i1107-{s}")).await;
        for (dim, score) in [
            // Both spellings: the prose single tail and the doubled tail the
            // CC reference resolves cleanly (I1102).
            ("retirement:retired:v1", 1.0),
            ("retirement:retired:v1:v1", 1.0),
            ("preserve_request:v1:v1", 1.0),
            ("preserve_response:v1:v1", 1.0),
            ("archive_release:wa_approval:v1:v1", 1.0),
            ("lawful_order:release:v1:v1", 1.0),
            ("takedown_notice:dmca512:v1", -1.0),
            ("takedown_notice:dmca512:v1:v1", -1.0),
            ("takedown_notice:steward_purge:v1:v1", -1.0),
        ] {
            let r = scores(
                &w,
                &w,
                serde_json::json!({"dimension": dim, "score": score}),
            );
            refused_everywhere(
                b,
                &r,
                crate::federation::admission::REGISTERED_FAMILY_HELD_SHUT_REASON,
                &format!("I1107 {dim} is held shut"),
            )
            .await;
        }
    }

    /// **I1108** — the ledger owner rule.
    pub async fn i1108_ledger_owner_rule<B: FederationDirectory + Sync>(b: &B, s: &str) {
        let owner = key(b, &format!("i1108-owner-{s}")).await;
        let occ = key(b, &format!("i1108-occ-{s}")).await;
        let delegate = key(b, &format!("i1108-delegate-{s}")).await;
        let stranger = key(b, &format!("i1108-stranger-{s}")).await;
        let lid = crate::ledgers::standard::derive_ledger_id(&owner, "usd", "1").unwrap();
        let head = |seq: u64| {
            serde_json::json!({
                "dimension": "ledger:head:usd:v1",
                "score": 1, "confidence": 1,
                "ledger_id": lid, "sequence": seq,
            })
        };
        // The owner's own row admits.
        let r = scores(&owner, &owner, head(1));
        b.put_attestation(SignedAttestation {
            attestation: r.clone(),
        })
        .await
        .unwrap_or_else(|e| panic!("I1108 the owner's row admits: {e}"));
        assert!(b
            .get_attestation(&r.attestation_id)
            .await
            .unwrap()
            .is_some());

        // A live occurrence of the owner admits.
        b.put_identity_occurrence(
            ts::signed_content_only_occurrence(
                &owner,
                &owner,
                &occ,
                chrono::Utc::now() - chrono::Duration::seconds(60),
            )
            .await,
        )
        .await
        .unwrap_or_else(|e| panic!("I1108 the occurrence binding: {e}"));
        let r = scores(&occ, &owner, head(2));
        b.put_attestation(SignedAttestation {
            attestation: r.clone(),
        })
        .await
        .unwrap_or_else(|e| panic!("I1108 a live occurrence of the owner admits: {e}"));

        // A `delegates_to` delegate is refused: no declared discipline.
        ts::put_delegates_to(b, &owner, &delegate, None)
            .await
            .unwrap_or_else(|e| panic!("I1108 the delegation: {e}"));
        for (signer, why) in [
            (
                &delegate,
                "I1108 a delegate under no declared discipline is refused",
            ),
            (&stranger, "I1108 a stranger is refused"),
        ] {
            let r = scores(signer, &owner, head(3));
            let e = b
                .put_attestation(SignedAttestation {
                    attestation: r.clone(),
                })
                .await
                .expect_err(why);
            assert_eq!(e.kind(), "federation_signer_not_acting_for", "{why}: {e}");
            assert!(b
                .get_attestation(&r.attestation_id)
                .await
                .unwrap()
                .is_none());
        }
    }

    /// **I1109** — the closed apophatic vocabulary at the door.
    pub async fn i1109_prohibited_closed_vocab_at_the_door<B: FederationDirectory + Sync>(
        b: &B,
        s: &str,
    ) {
        let w = key(b, &format!("i1109-{s}")).await;
        for dim in [
            "prohibited:weapons_harmful:v1",
            "prohibited:deception_fraud:v1",
            "prohibited:autonomous_deception:v1",
            "prohibited:research:v1",
        ] {
            let r = scores(&w, &w, serde_json::json!({"dimension": dim, "score": -1.0}));
            b.put_attestation(SignedAttestation {
                attestation: r.clone(),
            })
            .await
            .unwrap_or_else(|e| panic!("I1109 CC's closed value {dim} admits: {e}"));
        }
        let r = scores(
            &w,
            &w,
            serde_json::json!({"dimension": "prohibited:gambling:v1", "score": -1.0}),
        );
        let e = b
            .put_attestation(SignedAttestation {
                attestation: r.clone(),
            })
            .await
            .expect_err("I1109 a category outside the closed list");
        assert!(
            e.to_string().contains("namespace_vocab_value_unregistered"),
            "I1109: {e}"
        );
        assert!(b
            .get_attestation(&r.attestation_id)
            .await
            .unwrap()
            .is_none());
    }

    #[cfg(test)]
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                fn suffix() -> String {
                    uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
                }
                #[tokio::test]
                async fn i1106() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i1106_polarity_refused_at_the_doors(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i1107() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i1107_rc8_families_held_shut(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i1108() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i1108_ledger_owner_rule(&b, &suffix()).await
                }
                #[tokio::test]
                async fn i1109() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i1109_prohibited_closed_vocab_at_the_door(&b, &suffix()).await
                }
            }
        };
    }
    runners!(memory, async { Some(crate::store::MemoryBackend::new()) });
    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
}
