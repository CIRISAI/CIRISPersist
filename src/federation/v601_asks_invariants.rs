//! v60.1.0 (docs/V61_TASK_PLAN.md §2 slice B) — **the consumer asks**, each
//! witnessed on every backend through the doors a consumer calls.
//!
//! - **I1360 (CIRISPersist#1117; CC 4.2.6 / CC 4.5.1.2)** — the accord
//!   threshold is ONE function: `accord_threshold(n) = ⌊n/2⌋ + 1`. (v62, E3:
//!   the co-scrub store legs are deleted with the earlier-form key record's
//!   roles and scrubs.)
//! - **I1361** (deleted in v62, E3: `infra:relay` conferred by a holder
//!   co-scrub on a key record is earlier form; edition-2 standing is the
//!   bundle in force.)
//! - **I1362 (CIRISPersist#1064, CIRISEdge)** — the reason a door raises on
//!   `federation_dimension_rejected` classifies through persist's own
//!   predicate (`dimension_rejected_reason::is_retryable`): a self-report on a
//!   morally-charged stem is refused at `put_attestation`, its token is in the
//!   closed set and terminal, and a re-offer of the same bytes is refused the
//!   same way. (The key-grant twin rides I742's doors: `signer_not_minter`
//!   terminal, `recipient_not_in_audience` retryable.)
//! - **I1363 (CIRISPersist#1095, CIRISEdge; CC rc9)** — an A/V call record is
//!   one self-subject `chat:call:v1` row per attendee (attester = subject =
//!   the attendee), placed at the ROOM's scope like a chat row: (a) each
//!   member's row admits and a non-member's is refused; (b) a member reads the
//!   rows by subject, and the call's attendees are the union of subjects over
//!   the rows sharing a `call_id`, while a non-member reads none; (c) an
//!   attendee's own `withdraws` retracts their row and the other attendee's
//!   stands; nothing is superseded.
//! - **I1365 (CIRISPersist#1120; CC 3.1.5 rc10)** — `identity_amendment:v1`
//!   admits only citing an admitted `deferral:response:approved:v1` about the
//!   same agent, signed by a seated WA (the agent node's owner, compared self
//!   to self at the response's instant). Refused
//!   `identity_amendment_unauthorized`, each with its condition: a response
//!   not held, a rejected response, a response by a stranger, a response about
//!   another agent, evidence that does not cite the response, an amendment
//!   signed by a key that is not the agent's; an unowned agent has no seated
//!   WA. Ill-shaped `amendment_digest` / `authorized_by` are malformed rows.
//! - **I1368** (deleted in v62, E3: the split home binds an AGENT key as a
//!   person's occurrence, which O1 refuses `occurrence_mixes_person_and_machine`
//!   by the CC rc21 ruling, witnessed by O1 I3030; an agent's occurrence binds
//!   the agent's own identity, O1 I3023.)

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::admission::accord_threshold;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::FederationDirectory;

    /// **I1360** — see the module doc.
    pub(crate) async fn i1360_accord_threshold_is_the_gates_threshold(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        // The rule, by value: a strict majority, and an empty roster is
        // unreachable.
        for (n, m) in [
            (0, 1),
            (1, 1),
            (2, 2),
            (3, 2),
            (4, 3),
            (5, 3),
            (6, 4),
            (7, 4),
        ] {
            assert_eq!(accord_threshold(n), m, "I1360: accord_threshold({n})");
            assert!(2 * accord_threshold(n) > n, "I1360: strict majority of {n}");
        }

        // v62 (E3): the store legs (a key record co-scrubbed by two of three
        // holders, read through `has_accord_conferred_role_over_roster`) are
        // deleted: they ride the earlier-form key record's roles and scrubs,
        // and an edition-2 `key:record` carries neither (standing is the
        // bundle in force, RULINGS "Canonical standing"). The rule stays.
        //
        // v62.0.0 (TR-fix2; Eric's rule, CC 4.2.6) — the store leg, re-stated:
        // `accord_threshold_now` counts over the STANDING roster, the holders
        // of the genesis bundle in force. Pre-genesis it is the empty roster's
        // fail-closed 1-of-0; with the three-holder bundle, 2 of 3.
        let _ = tag;
        let t = crate::federation::admission::accord_threshold_now(d)
            .await
            .expect("I1360: read");
        if t.n == 0 {
            assert_eq!(t.m, 1, "I1360: an empty roster is never met");
            crate::federation::edition2::fixture_genesis::install_v2(d)
                .await
                .expect("I1360: the bundle installs");
        }
        let t = crate::federation::admission::accord_threshold_now(d)
            .await
            .expect("I1360: read");
        assert_eq!(
            (t.m, t.n),
            (2, 3),
            "I1360: two of the three holders of the bundle in force"
        );
    }

    /// **I1362** — see the module doc.
    pub(crate) async fn i1362_a_dimension_refusal_classifies_terminal(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::admission::dimension_rejected_reason;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::attestation_type;
        use crate::federation::{Error, SignedAttestation};

        let who = format!("i1362-{tag}");
        ts::register_hybrid_key(d, &who).await;
        let nonce = uuid::Uuid::new_v4().to_string();
        // v62 (E3): a registered family (`need:{domain}:{kind}`), so the
        // edition-2 door admits the statement and persist's own deny-list is
        // what refuses it; the stem is in an open-vocabulary bind.
        let env = serde_json::json!({ "id": nonce, "dimension": "need:i1362x:deception_rate:v1" });
        let mut row = ts::bare_attestation(&nonce, &who, &who, &env);
        row.attestation_type = attestation_type::SCORES.into();
        row.subject_key_ids = vec![who.clone()];
        ts::seal_row_in_place(&who, &mut row);
        let id = row.attestation_id.clone();
        for attempt in ["first offer", "re-offer"] {
            let err = d
                .put_attestation(SignedAttestation {
                    attestation: crate::federation::edition2::fixture_switch::headed_row(
                        &*d,
                        &row.clone(),
                    )
                    .await
                    .expect("HEAD-fix1: the row names its head"),
                })
                .await
                .expect_err("I1362: a morally-charged stem is refused");
            let Error::DimensionRejected { reason, .. } = err else {
                panic!("I1362 ({attempt}): expected DimensionRejected, got {err:?}");
            };
            assert_eq!(reason, "morally_charged_stem", "I1362 ({attempt})");
            assert_eq!(
                dimension_rejected_reason::is_retryable(reason),
                Some(false),
                "I1362 ({attempt}): the raised token is in the closed set and terminal"
            );
        }
        assert!(d.get_attestation(&id).await.unwrap().is_none());
    }

    /// **I1363** — see the module doc.
    pub(crate) async fn i1363_a_call_record_is_one_self_row_per_attendee(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{attestation_type, cohort_scope, Attestation};
        use crate::federation::SignedAttestation;
        use crate::read::{AttestationFilter, LifecycleView};

        let room = format!("chat:room:v1:i1363-{tag}");
        let (alice, bob, carol) = (
            format!("i1363-alice-{tag}"),
            format!("i1363-bob-{tag}"),
            format!("i1363-carol-{tag}"),
        );
        ts::register_hybrid_key(d, &room).await;
        for k in [&alice, &bob, &carol] {
            ts::register_user_role_key(d, k).await;
        }
        ts::seed_two_member_community(d, &room, &alice, &bob).await;
        let call_id = uuid::Uuid::new_v4().to_string();

        let call_row = |who: &str| -> Attestation {
            let id = uuid::Uuid::new_v4().to_string();
            let mut r = ts::bare_attestation(
                &id,
                who,
                who,
                &serde_json::json!({
                    "id": id,
                    "dimension": "chat:call:v1",
                    "call_id": call_id,
                    "community_key_id": e2::kid(&room),
                    "started_at": "2026-10-26T12:00:00Z",
                }),
            );
            r.attestation_type = attestation_type::SCORES.to_owned();
            r.weight = None;
            r.cohort_scope = cohort_scope::COMMUNITY.to_owned();
            r.subject_key_ids = vec![who.to_owned()];
            ts::seal_row_in_place(who, &mut r);
            r
        };

        // (a) Each member's own row admits; a non-member's is refused.
        let (a_row, b_row) = (call_row(&alice), call_row(&bob));
        let (a_id, b_id) = (a_row.attestation_id.clone(), b_row.attestation_id.clone());
        let a_copy = a_row.clone();
        for r in [a_row, b_row] {
            crate::federation::edition2::fixture_switch::put_signed(d, &r)
                .await
                .unwrap_or_else(|e| panic!("I1363 (a): a member's chat:call:v1 row admits: {e}"));
        }
        let c_row = call_row(&carol);
        let c_id = c_row.attestation_id.clone();
        assert!(
            d.put_attestation(SignedAttestation {
                attestation: crate::federation::edition2::fixture_switch::headed_row(&*d, &c_row)
                    .await
                    .expect("HEAD-fix1: the row names its head")
            })
            .await
            .is_err(),
            "I1363 (a): a non-member cannot place a call row in the room"
        );
        assert!(d.get_attestation(&c_id).await.unwrap().is_none());

        // (b) Read by subject, as a member and as a non-member.
        // v62 (E3): the stored subject and caller ids are identity-refs.
        let by_subject = |subject: &str, lifecycle: LifecycleView| AttestationFilter {
            subject_key_id: Some(e2::kid(subject)),
            dimension_prefixes: vec!["chat:call:".to_owned()],
            lifecycle,
            ..Default::default()
        };
        let read = |caller: String, subject: String, lifecycle: LifecycleView| {
            let filter = by_subject(&subject, lifecycle);
            async move {
                d.list_scores(&e2::kid(&caller), filter, None, 50)
                    .await
                    .unwrap()
                    .items
                    .into_iter()
                    .map(|r| r.attestation_id)
                    .collect::<Vec<_>>()
            }
        };
        assert_eq!(
            read(bob.clone(), alice.clone(), LifecycleView::Live).await,
            vec![a_id.clone()],
            "I1363 (b): a member reads the other attendee's row by subject"
        );
        assert_eq!(
            read(alice.clone(), bob.clone(), LifecycleView::Live).await,
            vec![b_id.clone()],
            "I1363 (b): per attendee"
        );
        assert!(
            read(carol.clone(), alice.clone(), LifecycleView::Live)
                .await
                .is_empty(),
            "I1363 (b): a non-member reads no row of the room"
        );
        let mut attendees = std::collections::BTreeSet::new();
        for who in [&alice, &bob, &carol] {
            for id in read(alice.clone(), who.clone(), LifecycleView::Live).await {
                let row = d.get_attestation(&id).await.unwrap().unwrap();
                if row.attestation_envelope["call_id"] == serde_json::json!(call_id) {
                    attendees.extend(row.subject_key_ids);
                }
            }
        }
        assert_eq!(
            attendees,
            [e2::kid(&alice), e2::kid(&bob)].into_iter().collect(),
            "I1363 (b): the attendees are the union of subjects over the call's rows"
        );

        // (c) Alice withdraws her own row; Bob's stands.
        ts::put_retraction(d, &alice, &alice, &a_id, attestation_type::WITHDRAWS)
            .await
            .unwrap_or_else(|e| panic!("I1363 (c): the attendee withdraws their own row: {e}"));
        assert!(
            read(bob.clone(), alice.clone(), LifecycleView::Live)
                .await
                .is_empty(),
            "I1363 (c): the withdrawn row is no longer live"
        );
        // v62.0.0 (WD-fix5; CC 6.1.5 N5, the lead's ruling) — an admitted
        // author withdrawal of CONTENT (`chat:*`) descends it at the door: the
        // row is gone, its id a tombstone, a later copy refused.
        assert!(
            read(bob.clone(), alice.clone(), LifecycleView::IncludeWithdrawn)
                .await
                .is_empty(),
            "I1363 (c): the withdrawn call row descended: no lifecycle lists it"
        );
        assert!(
            d.get_attestation(&a_id).await.unwrap().is_none(),
            "I1363 (c): the row is gone"
        );
        assert!(
            matches!(
                crate::federation::withdrawn_content::held_row_state(d, &a_id)
                    .await
                    .unwrap(),
                crate::federation::withdrawn_content::HeldRowState::Withdrawn { .. }
            ),
            "I1363 (c): its id reads Withdrawn"
        );
        let late = d
            .put_attestation(SignedAttestation {
                attestation: crate::federation::edition2::fixture_switch::headed_row(&*d, &a_copy)
                    .await
                    .expect("HEAD-fix1: the row names its head"),
            })
            .await
            .expect_err("I1363 (c): a later copy is refused");
        assert!(
            late.to_string()
                .contains(crate::federation::steward_purge::token::TOMBSTONED),
            "I1363 (c): by the tombstone: {late}"
        );
        assert_eq!(
            read(alice.clone(), bob.clone(), LifecycleView::Live).await,
            vec![b_id.clone()],
            "I1363 (c): the other attendee's row stands"
        );
        // A non-subject cannot withdraw it.
        assert!(
            ts::put_retraction(d, &alice, &bob, &b_id, attestation_type::WITHDRAWS)
                .await
                .is_err(),
            "I1363 (c): nobody withdraws another attendee's row"
        );
    }

    /// **I1365** — see the module doc.
    pub(crate) async fn i1365_an_identity_amendment_needs_a_seated_was_approval(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        use crate::federation::identity_amendment as ia;
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::{attestation_type, cohort_scope, Attestation};
        use crate::federation::{Error, SignedAttestation};

        let owner = format!("i1365-owner-{tag}");
        let stranger = format!("i1365-stranger-{tag}");
        let agent = format!("i1365-agent-{tag}");
        let other_agent = format!("i1365-other-{tag}");
        let unowned = format!("i1365-unowned-{tag}");
        for k in [&owner, &stranger] {
            ts::register_user_role_key(d, k).await;
        }
        for k in [&agent, &other_agent, &unowned] {
            ts::register_hybrid_key(d, k).await;
        }
        ts::put_owner_binding(d, &owner, &agent).await;
        ts::put_owner_binding(d, &owner, &other_agent).await;

        let put = |r: Attestation| async move {
            d.put_attestation(SignedAttestation {
                attestation: crate::federation::edition2::fixture_switch::headed_row(&*d, &r)
                    .await
                    .expect("HEAD-fix1: the row names its head"),
            })
            .await
            .map(|_| ())
        };
        // A row by `by` on `dimension`, attested to `about`; `self_subject`
        // makes `about` its subject too (the agent's own rows).
        let row = |by: &str, about: &str, dimension: &str, extra: serde_json::Value| {
            let id = uuid::Uuid::new_v4().to_string();
            let mut env = serde_json::json!({ "id": id, "dimension": dimension });
            for (k, v) in extra.as_object().unwrap() {
                env[k] = v.clone();
            }
            let mut r = ts::bare_attestation(&id, by, about, &env);
            r.attestation_type = attestation_type::SCORES.to_owned();
            r.cohort_scope = cohort_scope::SELF.to_owned();
            if by == about {
                r.subject_key_ids = vec![about.to_owned()];
            }
            ts::seal_row_in_place(by, &mut r);
            r
        };
        let request = row(
            &agent,
            &agent,
            ia::DEFERRAL_REQUEST_DIMENSION,
            serde_json::json!({ "deferral_id": "d-1", "reason_digest": "ab".repeat(32) }),
        );
        let request_id = request.attestation_id.clone();
        put(request).await.expect("I1365: the deferral request");
        let response = |by: &str, about: &str, dimension: &str| {
            row(
                by,
                about,
                dimension,
                // v62 (CC 3.1.5 rc21) — the approval names the text it
                // approves; every amendment below carries this digest.
                serde_json::json!({
                    "references_attestation_id": request_id,
                    "amendment_digest": "cd".repeat(32),
                    // v62.0.0 (E0 fix 9; CC rc21 ruling) — a response
                    // correlates on the deferral it answers, by its id.
                    "deferral_id": "d-1",
                }),
            )
        };
        let amendment = |by: &str, about: &str, authorized_by: &str, cite: bool| {
            let refs = if cite {
                serde_json::json!([authorized_by])
            } else {
                serde_json::json!([])
            };
            row(
                by,
                about,
                ia::IDENTITY_AMENDMENT_DIMENSION,
                serde_json::json!({
                    "amendment_digest": "cd".repeat(32),
                    "authorized_by": authorized_by,
                    "evidence_refs": refs,
                }),
            )
        };
        let refused = |e: Error, reason: &str, what: &str| {
            let text = e.to_string();
            assert!(
                matches!(e, Error::InvalidArgument(_))
                    && text.contains(&format!(
                        "{}: {reason}",
                        ia::IDENTITY_AMENDMENT_UNAUTHORIZED
                    )),
                "I1365 ({what}): expected {reason}, got {text}"
            );
        };
        // v62 (CC 2.7) — a condition the CITED RESPONSE decides never refuses
        // the amendment: it is admitted and held, not in force, reporting
        // the token.
        let held = |s: Option<ia::AmendmentStanding>, reason: &str, what: &str| {
            let s = s.unwrap_or_else(|| panic!("I1365 ({what}): not an amendment"));
            assert!(!s.is_in_force(), "I1365 ({what}): held, not in force");
            assert_eq!(
                s.token(),
                Some(ia::IDENTITY_AMENDMENT_UNAUTHORIZED),
                "I1365 ({what}): {s:?}"
            );
            assert_eq!(s.reason(), Some(reason), "I1365 ({what}): {s:?}");
        };
        // Admitted (CC 2.7), then its standing read now.
        let admitted_standing = |r: Attestation, what: &'static str| async move {
            put(r.clone())
                .await
                .unwrap_or_else(|e| panic!("I1365 ({what}): admitted and held: {e}"));
            assert!(d
                .get_attestation(&r.attestation_id)
                .await
                .unwrap()
                .is_some());
            crate::federation::identity_amendment::amendment_standing(d, &r)
                .await
                .unwrap()
        };

        // The owner (the seated WA) approves: the amendment admits.
        let approved = response(&owner, &agent, ia::DEFERRAL_APPROVED_DIMENSION);
        let approved_id = approved.attestation_id.clone();
        put(approved).await.expect("I1365: the owner's approval");
        let ok = amendment(&agent, &agent, &approved_id, true);
        let ok_id = ok.attestation_id.clone();
        put(ok.clone())
            .await
            .unwrap_or_else(|e| panic!("I1365: the authorised amendment admits: {e}"));
        assert!(d.get_attestation(&ok_id).await.unwrap().is_some());
        assert_eq!(
            ia::amendment_standing(d, &ok).await.unwrap(),
            Some(ia::AmendmentStanding::InForce),
            "I1365: the authorised amendment is in force"
        );

        // A response this node does not hold.
        let missing = uuid::Uuid::new_v4().to_string();
        held(
            admitted_standing(amendment(&agent, &agent, &missing, true), "not held").await,
            ia::unauthorized_reason::RESPONSE_NOT_HELD,
            "not held",
        );
        // A rejected response.
        let rejected = response(&owner, &agent, ia::DEFERRAL_REJECTED_DIMENSION);
        let rejected_id = rejected.attestation_id.clone();
        put(rejected).await.expect("I1365: the owner's rejection");
        held(
            admitted_standing(amendment(&agent, &agent, &rejected_id, true), "rejected").await,
            ia::unauthorized_reason::NOT_APPROVED,
            "rejected",
        );
        // An approval by a stranger, who holds no seat over this agent.
        let by_stranger = response(&stranger, &agent, ia::DEFERRAL_APPROVED_DIMENSION);
        let by_stranger_id = by_stranger.attestation_id.clone();
        put(by_stranger)
            .await
            .expect("I1365: a stranger's row stores");
        held(
            admitted_standing(amendment(&agent, &agent, &by_stranger_id, true), "stranger").await,
            ia::unauthorized_reason::NOT_A_SEATED_WA,
            "stranger",
        );
        // An approval about another agent.
        let elsewhere = response(&owner, &other_agent, ia::DEFERRAL_APPROVED_DIMENSION);
        let elsewhere_id = elsewhere.attestation_id.clone();
        put(elsewhere)
            .await
            .expect("I1365: the other agent's approval");
        held(
            admitted_standing(
                amendment(&agent, &agent, &elsewhere_id, true),
                "another agent",
            )
            .await,
            ia::unauthorized_reason::ABOUT_ANOTHER_AGENT,
            "another agent",
        );
        // Evidence that does not cite the response.
        refused(
            put(amendment(&agent, &agent, &approved_id, false))
                .await
                .unwrap_err(),
            ia::unauthorized_reason::EVIDENCE_DOES_NOT_CITE,
            "no citation",
        );
        // Signed by a key that is not the agent's.
        let mut forged = amendment(&other_agent, &agent, &approved_id, true);
        forged.subject_key_ids = vec![agent.clone()];
        ts::seal_row_in_place(&other_agent, &mut forged);
        assert!(
            put(forged).await.is_err(),
            "I1365: another key cannot amend this agent"
        );
        // An unowned agent has no seated WA: its own approval-shaped row by a
        // stranger authorises nothing.
        let for_unowned = row(
            &stranger,
            &unowned,
            ia::DEFERRAL_APPROVED_DIMENSION,
            serde_json::json!({ "amendment_digest": "cd".repeat(32) }),
        );
        let for_unowned_id = for_unowned.attestation_id.clone();
        put(for_unowned).await.expect("I1365: stores");
        held(
            admitted_standing(
                amendment(&unowned, &unowned, &for_unowned_id, true),
                "unowned",
            )
            .await,
            ia::unauthorized_reason::NOT_A_SEATED_WA,
            "unowned",
        );

        // A multi-occurrence agent: an occurrence key signs about its agent
        // identity. The seat is the owner of the signing occurrence's node
        // or, when that key has no owner binding, of the agent.
        let occurrence_of = |identity: String, occ: String| async move {
            // v62 (E3): a trusted-local bind keyed by identity-refs.
            d.test_seam_put_identity_occurrence(crate::federation::types::IdentityOccurrence {
                identity_key_id: e2::kid(&identity),
                occurrence_key_id: e2::kid(&occ),
                device_class: crate::federation::types::device_class::LAPTOP.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now() - chrono::Duration::seconds(5),
                valid_until: None,
                encryption_pubkeys: None,
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap_or_else(|e| panic!("I1365: occurrence record: {e}"));
        };
        let about = |by: &str, agent: &str, authorized_by: &str| {
            let id = uuid::Uuid::new_v4().to_string();
            let mut r = ts::bare_attestation(
                &id,
                by,
                agent,
                &serde_json::json!({
                    "id": id,
                    "dimension": ia::IDENTITY_AMENDMENT_DIMENSION,
                    "amendment_digest": "cd".repeat(32),
                    "authorized_by": authorized_by,
                    "evidence_refs": [authorized_by],
                }),
            );
            r.attestation_type = attestation_type::SCORES.to_owned();
            r.cohort_scope = cohort_scope::SELF.to_owned();
            r.subject_key_ids = vec![agent.to_owned()];
            ts::seal_row_in_place(by, &mut r);
            r
        };
        for (n, owner_on_occurrence) in [(1, true), (2, false)] {
            let multi = format!("i1365-multi{n}-{tag}");
            let occ = format!("i1365-occ{n}-{tag}");
            for k in [&multi, &occ] {
                ts::register_hybrid_key(d, k).await;
            }
            occurrence_of(multi.clone(), occ.clone()).await;
            if owner_on_occurrence {
                ts::put_owner_binding(d, &owner, &occ).await;
            } else {
                ts::put_owner_binding(d, &owner, &multi).await;
            }
            let ok = response(&owner, &multi, ia::DEFERRAL_APPROVED_DIMENSION);
            let ok_id = ok.attestation_id.clone();
            put(ok)
                .await
                .expect("I1365: the owner approves for the agent");
            let amended = about(&occ, &multi, &ok_id);
            assert_eq!(
                ia::amendment_standing(d, &amended).await.unwrap(),
                Some(ia::AmendmentStanding::InForce),
                "I1365: an occurrence's amendment under the owner's approval is in force"
            );
            put(amended).await.unwrap_or_else(|e| {
                panic!(
                    "I1365: an occurrence of the agent amends it (owner on the {}): {e}",
                    if owner_on_occurrence {
                        "occurrence"
                    } else {
                        "agent"
                    }
                )
            });
        }

        // Ill-shaped members are malformed rows, not authority questions.
        for (member, value, reason) in [
            (
                "amendment_digest",
                serde_json::json!("CD".repeat(32)),
                crate::federation::malformed_row::ENVELOPE_MEMBER_INVALID,
            ),
            (
                "authorized_by",
                serde_json::json!("not-a-uuid"),
                crate::federation::malformed_row::ENVELOPE_MEMBER_INVALID,
            ),
        ] {
            let mut bad = amendment(&agent, &agent, &approved_id, true);
            bad.attestation_envelope[member] = value;
            if member == "authorized_by" {
                bad.attestation_envelope["evidence_refs"] = serde_json::json!(["not-a-uuid"]);
            }
            ts::seal_row_in_place(&agent, &mut bad);
            match put(bad).await.unwrap_err() {
                Error::MalformedRow { reason: r, .. } => assert_eq!(r, reason, "I1365 {member}"),
                other => panic!("I1365 {member}: expected a malformed row, got {other:?}"),
            }
        }
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::bodies;

    fn tag(n: &str) -> String {
        format!("{n}{}", &uuid::Uuid::new_v4().simple().to_string()[..8])
    }

    macro_rules! on_every_backend {
        ($name:ident, $body:path) => {
            mod $name {
                use super::*;

                #[cfg(feature = "sqlite")]
                #[tokio::test(flavor = "multi_thread")]
                async fn sqlite() {
                    use crate::store::Backend as _;
                    let b = crate::store::sqlite::SqliteBackend::open_in_memory()
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("s")).await;
                }

                #[cfg(feature = "postgres")]
                #[tokio::test(flavor = "multi_thread")]
                async fn postgres() {
                    use crate::store::Backend as _;
                    let Some(dsn) = crate::test_pg::empty_dsn() else {
                        eprintln!("v601 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
                        return;
                    };
                    let b = crate::store::postgres::PostgresBackend::connect(&dsn)
                        .await
                        .unwrap();
                    b.run_migrations().await.unwrap();
                    $body(&b, &tag("p")).await;
                    eprintln!("{}: RAN", stringify!($name));
                }
            }
        };
    }

    on_every_backend!(i1360, bodies::i1360_accord_threshold_is_the_gates_threshold);
    on_every_backend!(i1362, bodies::i1362_a_dimension_refusal_classifies_terminal);
    on_every_backend!(
        i1363,
        bodies::i1363_a_call_record_is_one_self_row_per_attendee
    );
    on_every_backend!(
        i1365,
        bodies::i1365_an_identity_amendment_needs_a_seated_was_approval
    );

    /// v60.1.0 (CIRISPersist#1064) — **every `DimensionRejected` reason is
    /// classified exactly once.** The closed set holds each token once, the
    /// retryable set is inside it, an unknown token answers `None`, and every
    /// construction site in `src/` (comments stripped) raises a token
    /// expression this census names — a new token at a new site fails here.
    #[test]
    fn every_dimension_rejected_reason_is_classified_once() {
        use crate::federation::admission::{
            dimension_rejected_reason as dr, DimensionRejectionReason,
        };
        let mut seen = std::collections::BTreeSet::new();
        for t in dr::ALL {
            assert!(seen.insert(*t), "{t:?} listed twice");
            assert!(dr::is_retryable(t).is_some(), "{t:?}");
        }
        for t in dr::RETRYABLE {
            assert!(dr::ALL.contains(t), "{t:?} retryable but not in ALL");
        }
        for r in DimensionRejectionReason::ALL {
            assert!(dr::ALL.contains(&r.as_str()), "{r:?} unclassified");
        }
        assert_eq!(dr::ALL.len(), DimensionRejectionReason::ALL.len() + 6);
        assert_eq!(dr::is_retryable("partnership_shape_retired"), Some(false));
        assert_eq!(dr::is_retryable("registered_family_held_shut"), Some(false));
        assert_eq!(dr::is_retryable("group_plane_row_shape"), Some(false));
        assert_eq!(
            dr::is_retryable("substrate_self_report_names_another_party"),
            Some(false)
        );
        assert_eq!(dr::is_retryable("not_a_reason"), None);

        // The construction sites, from disk.
        let known_exprs = [
            "LEDGER_BINDING_REASON",
            "REGISTERED_FAMILY_HELD_SHUT_REASON",
            "INVARIANT_SELF_EMISSION_REASON",
            "GROUP_PLANE_ROW_SHAPE_REASON",
            "PARTNERSHIP_SHAPE_RETIRED_REASON",
            "SUBSTRATE_SELF_REPORT_SUBJECT_REASON",
        ];
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![root];
        let mut sites = 0usize;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text: String = std::fs::read_to_string(&path)
                    .unwrap()
                    .lines()
                    .map(|l| l.split("//").next().unwrap_or(""))
                    .collect::<Vec<_>>()
                    .join("\n");
                for (at, _) in text.match_indices("DimensionRejected {") {
                    let window = &text[at..(at + 400).min(text.len())];
                    let window = &window[..window.find('}').unwrap_or(window.len())];
                    let Some(r) = window.find("reason:") else {
                        continue; // a pattern, not a construction
                    };
                    let expr = window[r + "reason:".len()..]
                        .split(',')
                        .next()
                        .unwrap()
                        .trim();
                    if expr == "&'static str" {
                        continue; // the arm's declaration in `federation::Error`
                    }
                    sites += 1;
                    let named = known_exprs.contains(&expr)
                        || (expr.starts_with("DimensionRejectionReason::")
                            && expr.ends_with(".as_str()"));
                    assert!(
                        named,
                        "{}: DimensionRejected raises reason `{expr}`, which \
                         dimension_rejected_reason::ALL does not classify",
                        path.display()
                    );
                }
            }
        }
        assert!(
            sites >= 8,
            "the scan found {sites} construction sites — it is broken"
        );
    }
}

/// **I2235** (VA-genesis-fns; Eric's rule) — persist's ONE majority pair: for
/// every roster size, `strict_majority(n)` is the least count that is more
/// than half (`2·m > n ≥ 2·(m − 1)`), `is_strict_majority(yes, n)` holds
/// exactly from it, `accord_threshold` is it, and the local
/// `accord_consensus_protocol` reads `quorum:{m}/{n}` (Verify 23.3.2's text).
#[test]
fn i2235_the_majority_helpers_agree() {
    use crate::federation::admission::{accord_threshold, is_strict_majority, strict_majority};
    for n in 0..64usize {
        let m = strict_majority(n);
        assert!(
            2 * m > n && 2 * (m - 1) <= n,
            "I2235: strict_majority({n}) = {m}"
        );
        assert_eq!(accord_threshold(n), m, "I2235: accord_threshold({n})");
        for yes in 0..=n + 1 {
            assert_eq!(
                is_strict_majority(yes, n),
                yes >= m,
                "I2235: is_strict_majority({yes}, {n})"
            );
        }
    }
    assert_eq!(
        crate::federation::group_membership_change::accord_consensus_protocol(3),
        "quorum:2/3",
        "I2235: the local accord_consensus_protocol"
    );
}
