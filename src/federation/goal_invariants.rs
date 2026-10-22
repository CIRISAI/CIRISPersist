//! v60.0.0 (CIRISPersist#988 item 4; CC 3.1.9.7, CC 2.4.2,
//! CLM-silo-projection-rebuildable) — **a Goal is its declarer's signed
//! `goal:{scale}:v1` row; `goals` is the projection of the goal rows held.**
//!
//! - **I1178** (memory, sqlite, postgres) — through the plane's put door: a
//!   declaration projects (goal_id = its id, its body, its score); an
//!   amendment chain moves the head and the body, never the id; a foreign
//!   `supersedes` of the goal and a body-less one are refused; a
//!   `withdraws` retires it at its signed instant and `list_goals` hides it
//!   unless asked; a `recants` removes it; the filters (declarer, M-1
//!   dimension, scale, cohort) select; and `goals` is byte-equal to its
//!   from-rows rebuild after every step. Rows arriving out of order (the
//!   amendment and the retirement before their declaration) project the same
//!   goal.
//! - **I1179** (memory, sqlite, postgres) — the M-1 admission gate at the put
//!   door: a goal row without a well-formed `meta_goal_alignment` is
//!   `federation_malformed_row` / `goal_meta_alignment_malformed` and stores
//!   nothing; a body defect is `goal_body_malformed`; the three v59 scopes
//!   admit as `self` / `cohort` / `federation`; an empty scale is refused; a
//!   negative stance is a declaration.
//! - **I1180** (sqlite, postgres engines) — the Engine's goal doors
//!   (`put_goal`, `amend_goal`, `retire_goal`, `recant_goal`) sign the four
//!   rows; only the declarer amends, retires or recants; a pre-V204 typed
//!   goal is red in the rebuild until `rehome_legacy_goals` moves it (this
//!   node's re-signed, its retirement re-signed; another declarer's
//!   dropped).
//! - **I1181** (sqlite, postgres) — V204 over an upgrading store: the typed
//!   goals stay as legacy rows (`attestation_id` NULL), `single_declarer`
//!   reads `self`, `inserted_at` is gone.
//! - **I1182** (memory, sqlite, postgres) — `approach:{goal_id}` keys on the
//!   goal's `attestation_id`: the matcher binds it, and an approach row
//!   naming a held goal is admitted.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::attestation_admit::AttestationStore;
    use crate::federation::envelope::EnvelopeCore;
    use crate::federation::goal::{self, GoalsFilter, M1Dimension};
    use crate::federation::ledger_projection_invariants::bodies::{signer, Signer};
    use crate::federation::silo_projection::{check_projection_rebuild, SiloProjection};
    use crate::federation::types::{cohort_scope, identity_type, Attestation};
    use crate::federation::{EmitAttestationInput, Error, FederationDirectory, SignedAttestation};

    /// A goal body, as an envelope: `scale`, the cohort for `cohort`, an
    /// M-1 alignment unless `alignment` says otherwise.
    pub(crate) fn body(scale: &str, text: &str, score: f64) -> serde_json::Value {
        let mut env = serde_json::json!({
            "dimension": format!("goal:{scale}:v1"),
            "score": score,
            "confidence": 1.0,
            "goal_text": text,
            "meta_goal_alignment": {"dimension": "plurality", "rationale": "keeps it plural"},
        });
        if scale == goal::SCALE_COHORT {
            env["cohort_id"] = serde_json::json!("stewards");
        }
        env
    }

    fn input(ty: &str, env: serde_json::Value) -> EmitAttestationInput {
        EmitAttestationInput::with_envelope(
            ty,
            EnvelopeCore::from_value(env).unwrap(),
            cohort_scope::FEDERATION,
        )
    }

    /// Sign `env` as a `ty` row by `s`, WITHOUT putting it.
    pub(crate) async fn sign(s: &Signer, ty: &str, env: serde_json::Value) -> Attestation {
        let mut i = input(ty, env);
        let key = s.signer.derived_key_id();
        let canonical = crate::federation::attestation_emit::stamp_and_canonicalize(
            &mut i,
            &key,
            chrono::Utc::now(),
        )
        .unwrap();
        let sig = s.signer.sign_hybrid(&canonical).await.unwrap();
        crate::federation::attestation_emit::assemble(key, &canonical, sig, i)
            .unwrap()
            .0
    }

    pub(crate) async fn put<B>(b: &B, row: &Attestation) -> Result<(), Error>
    where
        B: FederationDirectory + Sync,
    {
        b.put_attestation(SignedAttestation {
            attestation: row.clone(),
        })
        .await
        .map(|_| ())
    }

    fn naming(target: &str, ty: &str, mut env: serde_json::Value) -> serde_json::Value {
        env["references_attestation_id"] = serde_json::json!(target);
        env["references_attestation_type"] = serde_json::json!(ty);
        env
    }

    fn retraction(verb: &str, target: &str) -> serde_json::Value {
        serde_json::json!({
            "kind": verb,
            "references_attestation_id": target,
            "references_attestation_type": "scores",
        })
    }

    /// The live rows, after asserting the rebuild is byte-equal.
    async fn live<B>(b: &B) -> Vec<String>
    where
        B: AttestationStore + Sync,
    {
        check_projection_rebuild(b, SiloProjection::Goals)
            .await
            .unwrap_or_else(|e| panic!("goals is its from-rows rebuild: {e}"))
            .live
    }

    async fn all<B>(b: &B, f: GoalsFilter) -> Vec<String>
    where
        B: FederationDirectory + Sync,
    {
        b.list_goals(f)
            .await
            .unwrap()
            .into_iter()
            .map(|g| g.goal_id)
            .collect()
    }

    // ── I1178 ─────────────────────────────────────────────────────────────
    pub(crate) async fn i1178_goals_are_the_projection_of_goal_rows<B>(b: &B, tag: &str)
    where
        B: AttestationStore + Sync,
    {
        let alice = signer(b, &format!("i1178-alice-{tag}"), identity_type::USER).await;
        let mallory = signer(b, &format!("i1178-mallory-{tag}"), identity_type::USER).await;

        // A declaration projects.
        let d = sign(&alice, "scores", body("cohort", "v0", -0.25)).await;
        put(b, &d)
            .await
            .expect("I1178: the declaration is admitted");
        let g = b
            .get_goal(&d.attestation_id)
            .await
            .unwrap()
            .expect("projected");
        assert_eq!(g.goal_id, d.attestation_id);
        assert_eq!(g.attestation_id, d.attestation_id);
        assert_eq!(g.declared_by_key_id, alice.id);
        assert_eq!(g.declared_at, d.asserted_at);
        assert_eq!(g.goal_text, "v0");
        assert_eq!(g.score, -0.25, "a negative stance is projected as signed");
        assert_eq!(
            (g.scope.scale(), g.scope.cohort_id()),
            ("cohort", Some("stewards"))
        );
        assert_eq!(live(b).await.len(), 1);

        // An amendment chain: the head and the body move, the id does not.
        let s1 = sign(
            &alice,
            "supersedes",
            naming(&d.attestation_id, "scores", body("self", "v1", 1.0)),
        )
        .await;
        put(b, &s1).await.expect("I1178: the declarer amends");
        let s2 = sign(
            &alice,
            "supersedes",
            naming(
                &s1.attestation_id,
                "supersedes",
                body("federation", "v2", 0.5),
            ),
        )
        .await;
        put(b, &s2)
            .await
            .expect("I1178: the declarer amends the amendment");
        let g = b.get_goal(&d.attestation_id).await.unwrap().unwrap();
        assert_eq!(
            (
                g.goal_text.as_str(),
                g.attestation_id.as_str(),
                g.scope.scale()
            ),
            ("v2", s2.attestation_id.as_str(), "federation"),
            "I1178: the head is the chain's end"
        );
        assert_eq!(
            g.declared_at, d.asserted_at,
            "the declaration's instant stays"
        );
        assert!(b.get_goal(&s1.attestation_id).await.unwrap().is_none());
        assert_eq!(live(b).await.len(), 1);

        // A foreign amendment and a body-less one are refused.
        let foreign = sign(
            &mallory,
            "supersedes",
            naming(
                &s2.attestation_id,
                "supersedes",
                body("self", "mine now", 1.0),
            ),
        )
        .await;
        let e = put(b, &foreign).await.expect_err("a foreign amendment");
        assert!(matches!(e, Error::InvalidArgument(_)), "I1178: {e}");
        let bodyless = sign(
            &alice,
            "supersedes",
            naming(
                &s2.attestation_id,
                "supersedes",
                serde_json::json!({"kind": "supersedes"}),
            ),
        )
        .await;
        let e = put(b, &bodyless).await.expect_err("a body-less amendment");
        assert!(matches!(e, Error::InvalidArgument(_)), "I1178: {e}");
        assert!(b
            .get_attestation(&bodyless.attestation_id)
            .await
            .unwrap()
            .is_none());
        assert_eq!(
            b.get_goal(&d.attestation_id)
                .await
                .unwrap()
                .unwrap()
                .goal_text,
            "v2"
        );

        // The filters.
        let other = sign(&mallory, "scores", body("self", "theirs", 1.0)).await;
        put(b, &other).await.unwrap();
        let mut both = vec![d.attestation_id.clone(), other.attestation_id.clone()];
        both.sort();
        let mut listed = all(b, GoalsFilter::default()).await;
        listed.sort();
        assert_eq!(listed, both);
        let by = |k: &str| GoalsFilter {
            declared_by_key_id: Some(k.to_owned()),
            ..GoalsFilter::default()
        };
        assert_eq!(all(b, by(&alice.id)).await, vec![d.attestation_id.clone()]);
        let scale = |s: &str| GoalsFilter {
            scale: Some(s.to_owned()),
            ..GoalsFilter::default()
        };
        assert_eq!(
            all(b, scale("self")).await,
            vec![other.attestation_id.clone()]
        );
        assert_eq!(
            all(b, scale("federation")).await,
            vec![d.attestation_id.clone()]
        );
        assert!(all(b, scale("cohort")).await.is_empty());
        let dim = |d: M1Dimension| GoalsFilter {
            m1_dimension: Some(d),
            ..GoalsFilter::default()
        };
        assert_eq!(all(b, dim(M1Dimension::Plurality)).await.len(), 2);
        assert!(all(b, dim(M1Dimension::Justice)).await.is_empty());
        let coh = sign(&mallory, "scores", body("cohort", "cohort goal", 1.0)).await;
        put(b, &coh).await.unwrap();
        let cohort = |c: &str| GoalsFilter {
            cohort_id: Some(c.to_owned()),
            ..GoalsFilter::default()
        };
        assert_eq!(
            all(b, cohort("stewards")).await,
            vec![coh.attestation_id.clone()]
        );
        assert!(all(b, cohort("other")).await.is_empty());

        // A stranger's retraction is refused; the declarer's retires at its
        // instant.
        let stranger_w = sign(
            &mallory,
            "withdraws",
            retraction("withdraws", &d.attestation_id),
        )
        .await;
        put(b, &stranger_w)
            .await
            .expect_err("I1178: a stranger's withdraws of a held goal is refused at the door");
        assert!(b
            .get_goal(&d.attestation_id)
            .await
            .unwrap()
            .unwrap()
            .retired_at
            .is_none());
        let w = sign(
            &alice,
            "withdraws",
            retraction("withdraws", &d.attestation_id),
        )
        .await;
        put(b, &w).await.expect("I1178: the declarer retires");
        let g = b.get_goal(&d.attestation_id).await.unwrap().unwrap();
        assert_eq!(
            g.retired_at,
            Some(w.asserted_at),
            "retired at the withdraws' instant"
        );
        assert_eq!(g.goal_text, "v2", "retirement keeps the amended body");
        assert!(!all(b, GoalsFilter::default())
            .await
            .contains(&d.attestation_id));
        assert!(all(
            b,
            GoalsFilter {
                include_retired: true,
                ..GoalsFilter::default()
            }
        )
        .await
        .contains(&d.attestation_id));
        assert_eq!(live(b).await.len(), 3);

        // "Never mine": a recants removes it.
        let r = sign(&alice, "recants", retraction("recants", &d.attestation_id)).await;
        put(b, &r).await.expect("I1178: the declarer recants");
        assert!(b.get_goal(&d.attestation_id).await.unwrap().is_none());
        assert_eq!(live(b).await.len(), 2);

        // Out of order: the amendment and the retirement land before their
        // declaration; the declaration's put folds them.
        let d2 = sign(&alice, "scores", body("self", "late v0", 1.0)).await;
        let a2 = sign(
            &alice,
            "supersedes",
            naming(&d2.attestation_id, "scores", body("self", "late v1", 1.0)),
        )
        .await;
        let w2 = sign(
            &alice,
            "withdraws",
            retraction("withdraws", &d2.attestation_id),
        )
        .await;
        put(b, &a2)
            .await
            .expect("I1178: an amendment ahead of its goal");
        assert!(b.get_goal(&d2.attestation_id).await.unwrap().is_none());
        put(b, &w2)
            .await
            .expect("I1178: the declarer's retirement ahead of its goal (an absent target)");
        put(b, &d2).await.expect("I1178: the late declaration");
        let g = b
            .get_goal(&d2.attestation_id)
            .await
            .unwrap()
            .expect("late goal");
        assert_eq!(
            g.goal_text, "late v1",
            "I1178: the earlier amendment is folded"
        );
        assert_eq!(g.attestation_id, a2.attestation_id);
        assert_eq!(
            g.retired_at,
            Some(w2.asserted_at),
            "I1178: the earlier retirement is folded"
        );
        assert_eq!(live(b).await.len(), 3);

        // Each goal folds only the rows naming ITS chain: goal E is amended,
        // then goal F is amended later; a refold of E (its retirement) keeps
        // E's own head, never F's later amendment.
        let ge = sign(&alice, "scores", body("self", "e v0", 1.0)).await;
        put(b, &ge).await.unwrap();
        let e1 = sign(
            &alice,
            "supersedes",
            naming(&ge.attestation_id, "scores", body("self", "e v1", 1.0)),
        )
        .await;
        put(b, &e1).await.unwrap();
        let gf = sign(&alice, "scores", body("self", "f v0", 1.0)).await;
        put(b, &gf).await.unwrap();
        let f1 = sign(
            &alice,
            "supersedes",
            naming(&gf.attestation_id, "scores", body("self", "f v1", 1.0)),
        )
        .await;
        put(b, &f1).await.unwrap();
        let we = sign(
            &alice,
            "withdraws",
            retraction("withdraws", &ge.attestation_id),
        )
        .await;
        put(b, &we).await.unwrap();
        let g = b.get_goal(&ge.attestation_id).await.unwrap().unwrap();
        assert_eq!(
            (g.goal_text.as_str(), g.attestation_id.as_str()),
            ("e v1", e1.attestation_id.as_str()),
            "I1178: a goal's head is the end of ITS chain"
        );
        assert_eq!(g.retired_at, Some(we.asserted_at));

        // A LOCAL-tier retraction is not a federation retraction: a node's
        // local scratch row naming F never retires it, whatever later row
        // refolds F.
        let local = crate::federation::types::LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: alice.id.clone(),
            attested_key_id: Some(alice.id.clone()),
            attestation_type: "withdraws".into(),
            weight: None,
            expires_at: None,
            attestation_envelope: EnvelopeCore::from_value(retraction(
                "withdraws",
                &gf.attestation_id,
            ))
            .unwrap(),
            subject_key_ids: Vec::new(),
            cohort_scope: cohort_scope::SELF.into(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        };
        let local_admitted = b.attestation_insert_local(local).await.is_ok();
        let f2 = sign(
            &alice,
            "supersedes",
            naming(&f1.attestation_id, "supersedes", body("self", "f v2", 1.0)),
        )
        .await;
        put(b, &f2).await.unwrap();
        let g = b.get_goal(&gf.attestation_id).await.unwrap().unwrap();
        assert_eq!(g.goal_text, "f v2");
        assert_eq!(
            g.retired_at, None,
            "I1178: a local-tier withdraws (admitted: {local_admitted}) retires nothing"
        );
        assert_eq!(live(b).await.len(), 5);
    }

    // ── I1179 ─────────────────────────────────────────────────────────────
    pub(crate) async fn i1179_m1_is_the_admission_gate<B>(b: &B, tag: &str)
    where
        B: AttestationStore + Sync,
    {
        use crate::federation::malformed_row::{GOAL_BODY, GOAL_META_ALIGNMENT};
        let alice = signer(b, &format!("i1179-alice-{tag}"), identity_type::USER).await;
        let reason = |e: &Error| match e {
            Error::MalformedRow { plane, reason, .. } => {
                assert_eq!(*plane, goal::PLANE, "{e}");
                *reason
            }
            other => panic!("I1179: expected a malformed-row refusal, got {other}"),
        };
        for scale in ["self", "cohort", "federation"] {
            let row = sign(&alice, "scores", body(scale, scale, 1.0)).await;
            put(b, &row)
                .await
                .unwrap_or_else(|e| panic!("I1179: scale {scale} admits: {e}"));
            assert!(b.get_goal(&row.attestation_id).await.unwrap().is_some());
        }
        let neg = sign(&alice, "scores", body("self", "avoid it", -1.0)).await;
        put(b, &neg)
            .await
            .expect("I1179: a negative stance is a declaration");
        assert_eq!(
            b.get_goal(&neg.attestation_id)
                .await
                .unwrap()
                .unwrap()
                .score,
            -1.0
        );

        let mut no_m1 = body("self", "t", 1.0);
        no_m1.as_object_mut().unwrap().remove("meta_goal_alignment");
        let mut bad_dim = body("self", "t", 1.0);
        bad_dim["meta_goal_alignment"]["dimension"] = serde_json::json!("greed");
        let mut empty_rationale = body("self", "t", 1.0);
        empty_rationale["meta_goal_alignment"]["rationale"] = serde_json::json!("");
        for (what, env) in [
            ("no M-1", no_m1.clone()),
            ("a dimension outside the seven", bad_dim),
            ("an empty rationale", empty_rationale),
        ] {
            let row = sign(&alice, "scores", env).await;
            let e = put(b, &row).await.expect_err(what);
            assert_eq!(reason(&e), GOAL_META_ALIGNMENT, "I1179 {what}: {e}");
            assert!(
                b.get_attestation(&row.attestation_id)
                    .await
                    .unwrap()
                    .is_none(),
                "I1179 {what}: a refused goal row stores nothing"
            );
        }
        // An amendment carries M-1 too.
        let d = sign(&alice, "scores", body("self", "t", 1.0)).await;
        put(b, &d).await.unwrap();
        let am = sign(
            &alice,
            "supersedes",
            naming(&d.attestation_id, "scores", no_m1),
        )
        .await;
        let e = put(b, &am).await.expect_err("an amendment without M-1");
        assert_eq!(reason(&e), GOAL_META_ALIGNMENT, "I1179: {e}");

        let mut no_cohort = body("cohort", "t", 1.0);
        no_cohort.as_object_mut().unwrap().remove("cohort_id");
        let mut empty_text = body("self", "t", 1.0);
        empty_text["goal_text"] = serde_json::json!(" ");
        for (what, env) in [
            ("a cohort with no cohort_id", no_cohort),
            ("an empty goal", empty_text),
        ] {
            let row = sign(&alice, "scores", env).await;
            let e = put(b, &row).await.expect_err(what);
            assert_eq!(reason(&e), GOAL_BODY, "I1179 {what}: {e}");
        }
        // An empty scale never lands, whichever gate names it first.
        let mut empty_scale = body("self", "t", 1.0);
        empty_scale["dimension"] = serde_json::json!("goal::v1");
        let row = sign(&alice, "scores", empty_scale).await;
        put(b, &row).await.expect_err("I1179: an empty scale");
        assert!(b
            .get_attestation(&row.attestation_id)
            .await
            .unwrap()
            .is_none());
        check_projection_rebuild(b, SiloProjection::Goals)
            .await
            .expect("I1179: goals is its rebuild");
    }

    // ── I1182 ─────────────────────────────────────────────────────────────
    pub(crate) async fn i1182_an_approach_keys_on_the_goal_row<B>(b: &B, tag: &str)
    where
        B: AttestationStore + Sync,
    {
        let alice = signer(b, &format!("i1182-alice-{tag}"), identity_type::USER).await;
        let d = sign(&alice, "scores", body("self", "the goal", 1.0)).await;
        put(b, &d).await.unwrap();
        let goal_id = b
            .get_goal(&d.attestation_id)
            .await
            .unwrap()
            .expect("projected")
            .goal_id;
        let dimension = format!("approach:{goal_id}:v1");
        let m = crate::federation::namespace::matcher::match_family(&dimension);
        assert_eq!(m.family, Some("approach:{goal_id}"), "I1182: {m:?}");
        assert_eq!(m.refusal, None, "I1182: {m:?}");
        assert_eq!(m.binds.get("goal_id"), Some(&goal_id), "I1182: {m:?}");
        let approach = sign(
            &alice,
            "scores",
            serde_json::json!({"dimension": dimension, "score": 1.0, "confidence": 1.0}),
        )
        .await;
        put(b, &approach)
            .await
            .expect("I1182: an approach naming a held goal is admitted");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod engine_bodies {
    use crate::federation::goal::{GoalInput, M1Dimension, MetaGoalAlignment};
    use crate::federation::silo_projection::SiloProjection;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::USER;
    use crate::federation::Error;
    use crate::Engine;

    pub(crate) async fn engine(dsn: &str, alias: &str) -> Engine {
        let mut alias = alias.to_owned();
        while alias.len() < 32 {
            alias.push('0');
        }
        let alias = alias.as_str();
        let e = Engine::with_signer_pre_genesis(ts::local_signer(alias), dsn)
            .await
            .unwrap();
        e.register_self_federation_key(USER, alias, None, serde_json::json!({}), vec![])
            .await
            .expect("register the engine's own key");
        e
    }

    fn input(text: &str) -> GoalInput {
        GoalInput {
            goal_text: text.into(),
            scale: "self".into(),
            cohort_id: None,
            meta_goal_alignment: MetaGoalAlignment::new(M1Dimension::Wonder, "r".into(), None),
            score: 1.0,
        }
    }

    // ── I1180 ─────────────────────────────────────────────────────────────
    pub(crate) async fn i1180_the_engine_doors_sign_the_four_verbs(
        e: &Engine,
        insert_legacy: impl Fn(
            String,
        )
            -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    ) {
        let dir = e.federation_directory();
        let me = e.local_derived_key_id().await.unwrap();
        let id = e.put_goal(&input("v0")).await.expect("I1180: declare");
        let g = dir.get_goal(&id).await.unwrap().expect("projected");
        assert_eq!(
            (g.goal_id.as_str(), g.declared_by_key_id.as_str()),
            (id.as_str(), me.as_str())
        );
        let a1 = e.amend_goal(&id, &input("v1")).await.expect("I1180: amend");
        let a2 = e
            .amend_goal(&id, &input("v2"))
            .await
            .expect("I1180: amend again");
        let g = dir.get_goal(&id).await.unwrap().unwrap();
        assert_eq!(
            (g.goal_text.as_str(), g.attestation_id.as_str()),
            ("v2", a2.as_str())
        );
        assert_ne!(a1, a2);
        let a1_row = dir.get_attestation(&a1).await.unwrap().unwrap();
        assert_eq!(
            a1_row.attestation_envelope["references_attestation_type"], "scores",
            "I1180: the first amendment names the declaration"
        );
        let a2_row = dir.get_attestation(&a2).await.unwrap().unwrap();
        assert!(a2_row.attestation_type == crate::federation::types::attestation_type::SUPERSEDES);
        assert_eq!(
            a2_row.attestation_envelope["references_attestation_type"], "supersedes",
            "I1180: a later amendment names the amendment it replaces"
        );
        assert_eq!(
            crate::federation::precedence::references_attestation_id_from_envelope(
                &a2_row.attestation_envelope
            ),
            Some(a1.as_str()),
            "I1180: an amendment names the current head"
        );
        let w = e.retire_goal(&id).await.expect("I1180: retire");
        let w_row = dir.get_attestation(&w).await.unwrap().unwrap();
        assert_eq!(w_row.attestation_type, "withdraws");
        assert_eq!(
            dir.get_goal(&id).await.unwrap().unwrap().retired_at,
            Some(w_row.asserted_at)
        );
        e.recant_goal(&id).await.expect("I1180: recant");
        assert!(dir.get_goal(&id).await.unwrap().is_none());
        for r in [
            e.amend_goal(&id, &input("x")).await,
            e.retire_goal(&id).await,
            e.recant_goal("no-such-goal").await,
        ] {
            assert!(matches!(r, Err(Error::InvalidArgument(_))), "I1180: {r:?}");
        }
        let mut bad = input("t");
        bad.meta_goal_alignment.rationale = " ".into();
        assert!(matches!(
            e.put_goal(&bad).await,
            Err(Error::MalformedRow { .. })
        ));

        // Another declarer's goal: the engine neither amends nor retires it.
        let other = ts::local_signer("i1180-other-000000000000000000000");
        let other_id = other.derived_key_id();
        ts::register_hybrid_key_as(&*dir, &other_id, "i1180-other-000000000000000000000", USER)
            .await;
        let inp = crate::federation::goal::plan_goal_row(&input("theirs")).unwrap();
        let theirs =
            crate::federation::attestation_emit::emit_with_local_signer(&*dir, &other, inp)
                .await
                .unwrap()
                .attestation_id;
        for r in [
            e.amend_goal(&theirs, &input("x")).await,
            e.retire_goal(&theirs).await,
            e.recant_goal(&theirs).await,
        ] {
            let err = r.expect_err("I1180: not the declarer");
            assert!(
                err.to_string().contains("only its declarer"),
                "I1180: {err}"
            );
        }

        // The rehome: a legacy goal of this node's (retired), and one of
        // another declarer's.
        insert_legacy(me.clone()).await;
        insert_legacy(other_id.clone()).await;
        let err = e
            .check_silo_projection(SiloProjection::Goals)
            .await
            .expect_err("I1180: a typed goal with no row is not its rebuild");
        assert!(err.to_string().contains("goals"), "I1180: {err}");
        let n = e.rehome_legacy_goals().await.expect("I1180: rehome");
        assert_eq!((n.rehomed, n.dropped), (1, 1), "I1180: {n:?}");
        e.check_silo_projection(SiloProjection::Goals)
            .await
            .expect("I1180: green after the rehome");
        assert!(dir.legacy_goals().await.unwrap().is_empty());
        let mine = dir
            .list_goals(crate::federation::GoalsFilter {
                declared_by_key_id: Some(me.clone()),
                include_retired: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let rehomed = mine
            .iter()
            .find(|g| g.goal_text == format!("legacy goal of {me}"))
            .expect("I1180: the node's legacy goal is a row");
        let every = dir
            .list_goals(crate::federation::GoalsFilter {
                include_retired: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(
            every
                .iter()
                .all(|g| g.goal_text != format!("legacy goal of {other_id}")),
            "I1180: another declarer's legacy goal is never re-signed as this node's"
        );
        assert!(
            rehomed.retired_at.is_some(),
            "I1180: its retirement is re-signed"
        );
        assert_eq!(rehomed.scope.scale(), "cohort");
        assert_eq!(
            e.rehome_legacy_goals().await.unwrap(),
            crate::federation::GoalRehome::default(),
            "I1180: a second rehome has nothing to move"
        );
        // put_goal rehomes first.
        insert_legacy(other_id).await;
        e.put_goal(&input("after")).await.unwrap();
        assert!(dir.legacy_goals().await.unwrap().is_empty());
    }
}

#[cfg(test)]
mod run {
    use super::bodies as b;

    fn tag() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite() -> crate::store::sqlite::SqliteBackend {
        use crate::store::Backend as _;
        let s = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        s.run_migrations().await.unwrap();
        s
    }

    #[cfg(feature = "postgres")]
    async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::isolated_dsn()?;
        let p = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        p.run_migrations().await.unwrap();
        Some(p)
    }

    #[tokio::test]
    async fn i1178_memory() {
        let m = crate::store::memory::MemoryBackend::new();
        b::i1178_goals_are_the_projection_of_goal_rows(&m, &tag()).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1178_sqlite() {
        b::i1178_goals_are_the_projection_of_goal_rows(&sqlite().await, &tag()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1178_postgres() {
        let Some(p) = postgres().await else { return };
        b::i1178_goals_are_the_projection_of_goal_rows(&p, &tag()).await;
    }

    #[tokio::test]
    async fn i1179_memory() {
        let m = crate::store::memory::MemoryBackend::new();
        b::i1179_m1_is_the_admission_gate(&m, &tag()).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1179_sqlite() {
        b::i1179_m1_is_the_admission_gate(&sqlite().await, &tag()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1179_postgres() {
        let Some(p) = postgres().await else { return };
        b::i1179_m1_is_the_admission_gate(&p, &tag()).await;
    }

    #[tokio::test]
    async fn i1182_memory() {
        let m = crate::store::memory::MemoryBackend::new();
        b::i1182_an_approach_keys_on_the_goal_row(&m, &tag()).await;
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1182_sqlite() {
        b::i1182_an_approach_keys_on_the_goal_row(&sqlite().await, &tag()).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1182_postgres() {
        let Some(p) = postgres().await else { return };
        b::i1182_an_approach_keys_on_the_goal_row(&p, &tag()).await;
    }

    /// The legacy goal both engines seed: `declarer`'s, scale `cohort`,
    /// retired.
    fn legacy_sql(table: &str, declarer: &str, retired: &str) -> String {
        format!(
            "INSERT INTO {table} (goal_id, declared_by_key_id, declared_at, goal_text, \
             goal_text_canonical, scale, scope_cohort_id, meta_dimension, meta_rationale, \
             meta_deliberation, retired_at, persist_row_hash) VALUES ('legacy-{}', '{declarer}', \
             '2026-01-01T00:00:00Z', 'legacy goal of {declarer}', 'legacy goal of {declarer}', \
             'cohort', 'c1', 'justice', \
             'r', NULL, {retired}, 'h')",
            uuid::Uuid::new_v4().simple()
        )
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1180_sqlite_engine() {
        let e = super::engine_bodies::engine("sqlite::memory:", &format!("i1180-{}", tag())).await;
        let sq = e.sqlite_backend().expect("sqlite").clone();
        super::engine_bodies::i1180_the_engine_doors_sign_the_four_verbs(&e, move |who| {
            let sq = sq.clone();
            Box::pin(async move {
                sq.test_execute(&legacy_sql("goals", &who, "'2026-02-01T00:00:00Z'"))
                    .await
            })
        })
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1180_postgres_engine() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let e = super::engine_bodies::engine(&dsn, &format!("i1180-{}", tag())).await;
        let pg = e.postgres_backend().expect("postgres").clone();
        super::engine_bodies::i1180_the_engine_doors_sign_the_four_verbs(&e, move |who| {
            let pg = pg.clone();
            Box::pin(async move {
                pg.test_execute(&legacy_sql(
                    "cirislens.goals",
                    &who,
                    "'2026-02-01T00:00:00Z'",
                ))
                .await
            })
        })
        .await;
    }

    // ── I1181 — V204 over an upgrading node ───────────────────────────────

    /// The declarer every V203 goal names: registered through the key door at
    /// the V203 schema (V204 touches only `goals`).
    const K1: &str = "i1181-k1";

    fn v203_goal(table: &str, id: &str, scope: &str, cohort: &str) -> String {
        format!(
            "INSERT INTO {table} (goal_id, declared_by_key_id, declared_at, goal_text, \
             goal_text_canonical, scope_kind, scope_cohort_id, meta_dimension, meta_rationale, \
             persist_row_hash) VALUES ('{id}', '{K1}', '2026-01-06T00:00:00Z', 't', 't', \
             '{scope}', {cohort}, 'coherence', 'r', 'h')"
        )
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i1181_sqlite() {
        use crate::store::Backend as _;
        let s = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        s.run_migrations_through(203).await.unwrap();
        crate::federation::tier_ingest::test_support::register_hybrid_key(&s, K1).await;
        let a = "11111111-1111-4111-8111-111111111111";
        let c = "22222222-2222-4222-8222-222222222222";
        s.test_execute(&v203_goal("goals", a, "single_declarer", "NULL"))
            .await;
        s.test_execute(&v203_goal("goals", c, "cohort", "'stewards'"))
            .await;
        s.run_migrations()
            .await
            .expect("I1181: V204 runs over a populated store");
        let one = |sql: &str| {
            let conn = s.conn_handle();
            let sql = sql.to_owned();
            move || -> String {
                conn.lock()
                    .query_row(&sql, [], |r| r.get::<_, String>(0))
                    .unwrap()
            }
        };
        assert_eq!(
            one("SELECT group_concat(goal_id || '|' || scale || '|' || \
                 COALESCE(scope_cohort_id, '-') || '|' || COALESCE(attestation_id, 'NULL') || \
                 '|' || COALESCE(score, 'NULL'), ',') FROM (SELECT * FROM goals ORDER BY goal_id)")(
            ),
            format!("{a}|self|-|NULL|NULL,{c}|cohort|stewards|NULL|NULL"),
            "I1181: the typed goals are legacy rows, single_declarer is self"
        );
        assert_eq!(
            one(
                "SELECT CAST(COUNT(*) AS TEXT) FROM pragma_table_info('goals') \
                 WHERE name IN ('inserted_at', 'scope_kind')"
            )(),
            "0"
        );
        assert_eq!(
            one("SELECT CAST(COUNT(*) AS TEXT) FROM pragma_foreign_key_check")(),
            "0"
        );
        let legacy = crate::federation::FederationDirectory::legacy_goals(&s)
            .await
            .unwrap();
        assert_eq!(legacy.len(), 2);
        assert!(
            crate::federation::FederationDirectory::list_goals(&s, Default::default())
                .await
                .unwrap()
                .is_empty(),
            "I1181: a legacy goal is not a goal"
        );
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i1181_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let p = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        p.run_migrations_through(203).await.unwrap();
        crate::federation::tier_ingest::test_support::register_hybrid_key(&p, K1).await;
        let a = "11111111-1111-4111-8111-111111111111";
        let c = "22222222-2222-4222-8222-222222222222";
        p.test_execute(&v203_goal("cirislens.goals", a, "single_declarer", "NULL"))
            .await;
        p.test_execute(&v203_goal("cirislens.goals", c, "cohort", "'stewards'"))
            .await;
        p.run_migrations()
            .await
            .expect("I1181: V204 runs over a populated store");
        let client = p.get_client().await.unwrap();
        let one = |sql: &'static str| {
            let c = &client;
            async move { c.query_one(sql, &[]).await.unwrap().get::<_, String>(0) }
        };
        assert_eq!(
            one("SELECT string_agg(goal_id || '|' || scale || '|' || \
                 COALESCE(scope_cohort_id, '-') || '|' || COALESCE(attestation_id, 'NULL') || \
                 '|' || COALESCE(score::text, 'NULL'), ',' ORDER BY goal_id) \
                 FROM cirislens.goals")
            .await,
            format!("{a}|self|-|NULL|NULL,{c}|cohort|stewards|NULL|NULL"),
        );
        assert_eq!(
            one(
                "SELECT COUNT(*)::text FROM information_schema.columns WHERE table_schema = \
                 'cirislens' AND table_name = 'goals' AND column_name IN ('inserted_at', \
                 'scope_kind')"
            )
            .await,
            "0"
        );
        assert_eq!(
            crate::federation::FederationDirectory::legacy_goals(&p)
                .await
                .unwrap()
                .len(),
            2
        );
    }
}
