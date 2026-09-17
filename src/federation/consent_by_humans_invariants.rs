//! CIRISPersist#857 — witnesses for `FSD/CONSENT_BY_HUMANS.md` §5. One body
//! per invariant, generic over the directory, run by every backend that folds
//! consent (memory, sqlite, postgres), so the three cannot diverge.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::hard_case::ConsentState;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{
        admission, consent_by_humans as cbh, Attestation, FederationDirectory, IdentityOccurrence,
        SignedAttestation,
    };

    /// A federation-tier row signed by `signer` over `envelope`, targeting
    /// `target`, with `subject_key_ids` — sign → seal → reseal, the crate's
    /// fixture shape.
    fn row(
        id: &str,
        signer: &str,
        target: &str,
        envelope: serde_json::Value,
        subject_key_ids: Vec<String>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Attestation {
        let (och, ed_sig, pqc_sig) = ts::sign_envelope(signer, &envelope);
        let mut r = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: signer.to_owned(),
            attested_key_id: target.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: ed_sig,
            scrub_signature_pqc: pqc_sig,
            scrub_key_id: signer.to_owned(),
            scrub_timestamp: at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids,
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        ts::seal_row_in_place(signer, &mut r);
        ts::reseal(&mut r);
        r
    }

    /// `consent:state:<stance>:v1` by `subject` about `target`, naming `scope`,
    /// optionally FOR `for_key`.
    fn state(
        id: &str,
        subject: &str,
        target: &str,
        stance: &str,
        scope: &str,
        for_key: Option<&str>,
        at: &str,
    ) -> Attestation {
        let at: chrono::DateTime<chrono::Utc> = at.parse().unwrap();
        let at = admission::truncate_to_substrate_resolution(at);
        let mut env = serde_json::json!({
            "id": id,
            "dimension": format!("consent:state:{stance}:v1"),
            "scope": scope,
            crate::federation::envelope::paths::ASSERTED_AT: at.to_rfc3339(),
        });
        if let Some(f) = for_key {
            env[cbh::FOR_KEY_ID] = serde_json::Value::String(f.to_owned());
        }
        row(id, subject, target, env, Vec::new(), at)
    }

    /// A `consent:replication:v1` grant by `author` to `peer`, optionally FOR `for_key`.
    fn grant(id: &str, author: &str, peer: &str, for_key: Option<&str>) -> Attestation {
        let mut payload =
            serde_json::json!({"grants": "replication", "attestation_prefixes": ["i96-fixture:"]});
        if let Some(f) = for_key {
            payload[cbh::FOR_KEY_ID] = serde_json::Value::String(f.to_owned());
        }
        row(
            id,
            author,
            author,
            serde_json::json!({"dimension": crate::federation::consent_peer_set::DIMENSION, "payload": payload}),
            vec![peer.to_owned()],
            chrono::Utc::now(),
        )
    }

    /// A PLAIN conferral `delegates_to(user → agent)` — the `self_at_login`
    /// delegation shape, no custody marker: a job, not stewardship.
    fn conferral(id: &str, user: &str, agent: &str) -> Attestation {
        let mut r = row(
            id,
            user,
            agent,
            serde_json::json!({"id": id, "kind": "delegates_to", "delegate_key_id": agent, "scope": ["act_on_behalf", "message_io"], "sub_delegation": false}),
            Vec::new(),
            "2026-05-01T00:00:00Z".parse().unwrap(),
        );
        r.attestation_type = attestation_type::DELEGATES_TO.to_owned();
        ts::reseal(&mut r);
        r
    }

    async fn put(
        d: &dyn FederationDirectory,
        a: Attestation,
    ) -> Result<(), crate::federation::Error> {
        d.put_attestation(SignedAttestation { attestation: a })
            .await
            .map(|_| ())
    }

    /// The trusted-local occurrence row: `occurrence` as an occurrence of `identity`.
    async fn occurrence(
        d: &dyn FederationDirectory,
        identity: &str,
        occurrence_key: &str,
        class: &str,
        valid_until: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        d.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence_key.to_owned(),
            device_class: class.to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until,
            encryption_pubkeys: None,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .expect("occurrence row");
    }

    /// **I94** — the occurrence anchor: an agent bound as an occurrence of a
    /// `user` identity has that human in every steward fold — WHILE the
    /// agent's transport self-row exists beside it. A conferral does not
    /// steward. A revoked occurrence stops anchoring.
    pub async fn i94_occurrence_anchor_with_the_self_row_present(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let (alice, agent) = (format!("i94-alice-{s}"), format!("i94-agent-{s}"));
        ts::register_identity_key(d, &alice, USER).await;
        ts::register_identity_key(d, &agent, AGENT).await;
        // Server compose's transport self-occurrence: identity = the agent itself.
        occurrence(d, &agent, &agent, "agent", None).await;
        assert!(
            admission::steward_bindings_of(d, &agent)
                .await
                .unwrap()
                .is_empty(),
            "I94: the self-row anchors nobody"
        );
        assert!(!admission::is_steward_bound(d, &agent).await.unwrap());
        assert_eq!(
            cbh::consent_principals_of(d, &agent).await.unwrap(),
            vec![agent.clone()],
            "I94: {{k}} only"
        );

        // A conferral (the login delegation's shape) is a job, not stewardship.
        put(d, conferral(&format!("i94-conf-{s}"), &alice, &agent))
            .await
            .expect("I94: a conferral admits");
        assert!(
            admission::steward_bindings_of(d, &agent)
                .await
                .unwrap()
                .is_empty(),
            "I94: a conferral does not steward (Clause D)"
        );

        // The login shape: the agent as an occurrence of the HUMAN — beside
        // the self-row. This is the row `LIMIT 1` could miss.
        occurrence(d, &alice, &agent, "agent", None).await;
        let rows = d
            .list_identity_occurrences_by_occurrence_key(&agent)
            .await
            .unwrap();
        assert_eq!(
            rows.len(),
            2,
            "I94 precondition: two identity rows for one occurrence key"
        );
        assert_eq!(
            admission::steward_bindings_of(d, &agent).await.unwrap(),
            vec![alice.clone()],
            "I94: the human anchors the agent"
        );
        assert!(
            admission::is_steward_bound(d, &agent).await.unwrap(),
            "I94: is_steward_bound agrees"
        );
        assert_eq!(
            admission::steward_binding_chain(d, &agent).await.unwrap(),
            vec![alice.clone(), agent.clone()],
            "I94: the chain is human → agent"
        );
        let mut p = cbh::consent_principals_of(d, &agent).await.unwrap();
        p.sort();
        let mut want = vec![agent.clone(), alice.clone()];
        want.sort();
        assert_eq!(p, want, "I94: {{k}} ∪ stewards");

        // REVOKED under the human (active = admitted AND no effective
        // revocation; expiry plays no part — v4.8.0's contract): the anchor is
        // gone, the self-row still anchors nobody.
        d.put_identity_occurrence_revocation_local(
            crate::federation::IdentityOccurrenceRevocation {
                identity_key_id: alice.clone(),
                occurrence_key_id: agent.clone(),
                // #421 re-assert semantics: an occurrence asserted AFTER the
                // revocation's instants is re-established, so both instants sit
                // strictly after the row's `asserted_at`.
                revoked_at: chrono::Utc::now() + chrono::Duration::milliseconds(5),
                effective_at: chrono::Utc::now() + chrono::Duration::milliseconds(5),
                reason: None,
                witness_set: Vec::new(),
                persist_row_hash: String::new(),
            },
        )
        .await
        .expect("I94: the revocation lands");
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(
            admission::steward_bindings_of(d, &agent)
                .await
                .unwrap()
                .is_empty(),
            "I94: a revoked device is not co-self with its former identity"
        );
    }

    /// **I95** — the scoped fold keyed by the machine walks to the human ON
    /// ROWS THAT NAME THE MACHINE, and combines principals as a reverse quorum.
    pub async fn i95_scoped_consent_by_principals(d: &dyn FederationDirectory, s: &str) {
        use ConsentState::*;
        let now = chrono::Utc::now();
        let (canonical, alice, node, sibling) = (
            format!("i95-canon-{s}"),
            format!("i95-alice-{s}"),
            format!("i95-node-{s}"),
            format!("i95-sib-{s}"),
        );
        for (k, t) in [
            (&canonical, NODE),
            (&alice, USER),
            (&node, NODE),
            (&sibling, AGENT),
        ] {
            ts::register_identity_key(d, k, t).await;
        }
        put(
            d,
            ts::owner_binding_attestation(&format!("i95-ob-{s}"), &alice, &node),
        )
        .await
        .unwrap();
        occurrence(d, &alice, &sibling, "agent", None).await;
        let by = |subject: String, target: String| async move {
            cbh::resolve_scoped_consent_by_principals(d, &target, &subject, "analyze", None, now)
                .await
                .unwrap()
        };
        assert_eq!(
            by(node.clone(), canonical.clone()).await,
            Unspecified,
            "I95: no human stance, no consent"
        );

        // alice grants FOR the sibling agent: nothing for the node.
        put(
            d,
            state(
                &format!("i95-gs-{s}"),
                &alice,
                &canonical,
                "granted",
                "analyze",
                Some(&sibling),
                "2026-06-01T00:00:00Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            by(node.clone(), canonical.clone()).await,
            Unspecified,
            "I95: a row naming ANOTHER agent is Unspecified for this one"
        );
        assert_eq!(
            by(sibling.clone(), canonical.clone()).await,
            Granted,
            "I95: …and Granted for the one it names"
        );
        // alice grants naming nobody: nothing for the node either.
        put(
            d,
            state(
                &format!("i95-gn-{s}"),
                &alice,
                &canonical,
                "granted",
                "analyze",
                None,
                "2026-06-01T00:00:01Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            by(node.clone(), canonical.clone()).await,
            Unspecified,
            "I95: a row naming no machine is Unspecified for a machine"
        );
        assert_eq!(
            by(alice.clone(), canonical.clone()).await,
            Granted,
            "I95: keyed by the human, the human's own stance, whatever it names"
        );

        // alice grants FOR the node: the node's consent is its owner's — and
        // the strict fold keyed by the node still answers nothing (the defect).
        put(
            d,
            state(
                &format!("i95-g-{s}"),
                &alice,
                &canonical,
                "granted",
                "analyze",
                Some(&node),
                "2026-06-01T00:00:02Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            by(node.clone(), canonical.clone()).await,
            Granted,
            "I95: the row naming the node governs it"
        );
        assert_eq!(
            d.resolve_scoped_consent(&canonical, &node, "analyze", None, now)
                .await
                .unwrap(),
            Unspecified,
            "I95: the strict fold keyed by the node is the defect, kept visible"
        );

        // Legacy: a MACHINE-authored grant still counts — {k} is in the set.
        let (legacy, t2) = (format!("i95-legacy-{s}"), format!("i95-t2-{s}"));
        ts::register_identity_key(d, &legacy, AGENT).await;
        ts::register_identity_key(d, &t2, NODE).await;
        put(
            d,
            state(
                &format!("i95-lg-{s}"),
                &legacy,
                &t2,
                "granted",
                "analyze",
                None,
                "2026-06-01T00:00:00Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            by(legacy.clone(), t2.clone()).await,
            Granted,
            "I95: a legacy machine-authored grant keeps counting"
        );

        // Two principals: the agent's own legacy row + its steward's row naming it.
        let (agent, t3) = (format!("i95-agent-{s}"), format!("i95-t3-{s}"));
        ts::register_identity_key(d, &agent, AGENT).await;
        ts::register_identity_key(d, &t3, NODE).await;
        occurrence(d, &alice, &agent, "agent", None).await;
        put(
            d,
            state(
                &format!("i95-g3-{s}"),
                &alice,
                &t3,
                "granted",
                "analyze",
                Some(&agent),
                "2026-06-01T00:00:00Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            by(agent.clone(), t3.clone()).await,
            Granted,
            "I95: steward grant + agent silent → Granted"
        );
        put(
            d,
            state(
                &format!("i95-ag-{s}"),
                &agent,
                &t3,
                "granted",
                "analyze",
                None,
                "2026-06-01T12:00:00Z",
            ),
        )
        .await
        .unwrap();
        put(
            d,
            state(
                &format!("i95-r3-{s}"),
                &alice,
                &t3,
                "revoked",
                "analyze",
                Some(&agent),
                "2026-06-02T00:00:00Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            by(agent.clone(), t3.clone()).await,
            Revoked,
            "I95: agent's own grant + steward revoke → Revoked (reverse quorum on the stop)"
        );
        put(
            d,
            state(
                &format!("i95-g3b-{s}"),
                &alice,
                &t3,
                "granted",
                "analyze",
                Some(&agent),
                "2026-06-03T00:00:00Z",
            ),
        )
        .await
        .unwrap();
        assert_eq!(by(agent.clone(), t3.clone()).await, Granted, "I95: the SAME steward re-granting newer than its own revoke → Granted (latest-wins within one principal)");
    }

    /// **I96** — the peer set by principals: own peers ∪ the steward's grants
    /// that NAME the machine; a grant for a sibling contributes nothing.
    pub async fn i96_consent_peers_by_principals(d: &dyn FederationDirectory, s: &str) {
        let (alice, node, sibling, p1, p2, p3, p4) = (
            format!("i96-alice-{s}"),
            format!("i96-node-{s}"),
            format!("i96-sib-{s}"),
            format!("i96-p1-{s}"),
            format!("i96-p2-{s}"),
            format!("i96-p3-{s}"),
            format!("i96-p4-{s}"),
        );
        ts::register_identity_key(d, &alice, USER).await;
        ts::register_identity_key(d, &node, NODE).await;
        ts::register_identity_key(d, &sibling, AGENT).await;
        put(
            d,
            ts::owner_binding_attestation(&format!("i96-ob-{s}"), &alice, &node),
        )
        .await
        .unwrap();
        occurrence(d, &alice, &sibling, "agent", None).await;
        // The owner grants replication FOR the node to p1 and p2, FOR the
        // sibling to p4; the node itself to nobody — the split-key home.
        put(d, grant(&format!("i96-g1-{s}"), &alice, &p1, Some(&node)))
            .await
            .unwrap();
        put(d, grant(&format!("i96-g2-{s}"), &alice, &p2, Some(&node)))
            .await
            .unwrap();
        put(
            d,
            grant(&format!("i96-g4-{s}"), &alice, &p4, Some(&sibling)),
        )
        .await
        .unwrap();
        assert!(d.list_consent_peers(&node).await.unwrap().is_empty(), "I96 precondition: the strict projection keyed by the node is EMPTY — the zero-traces defect");
        let mut want = vec![p1.clone(), p2.clone()];
        want.sort();
        assert_eq!(
            cbh::consent_peers_by_principals(d, &node).await.unwrap(),
            want,
            "I96: keyed by the node, the owner's grants naming it — and NOT the sibling's"
        );
        assert_eq!(
            cbh::consent_peers_by_principals(d, &sibling).await.unwrap(),
            vec![p4.clone()],
            "I96: the sibling gets only its own"
        );
        // A legacy node-authored grant is unioned in, not lost.
        put(d, grant(&format!("i96-g3-{s}"), &node, &p3, None))
            .await
            .unwrap();
        let mut want3 = vec![p1, p2, p3];
        want3.sort();
        assert_eq!(
            cbh::consent_peers_by_principals(d, &node).await.unwrap(),
            want3,
            "I96: {{k}} ∪ stewards-naming-k, deduped, sorted"
        );
        // A stranger's grant naming the node contributes nothing: not a steward.
        let mallory = format!("i96-mallory-{s}");
        ts::register_identity_key(d, &mallory, USER).await;
        put(
            d,
            grant(
                &format!("i96-gm-{s}"),
                &mallory,
                &format!("i96-px-{s}"),
                Some(&node),
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            cbh::consent_peers_by_principals(d, &node).await.unwrap(),
            want3,
            "I96: a non-steward naming the machine consents for nothing"
        );
    }

    /// **I96 (b)** — a MACHINE author naming another key is refused at
    /// admission; a human may name any key; an unknown member still rejects.
    pub async fn i96b_for_key_id_admission(d: &dyn FederationDirectory, s: &str) {
        let (alice, node, other) = (
            format!("i96b-alice-{s}"),
            format!("i96b-node-{s}"),
            format!("i96b-other-{s}"),
        );
        ts::register_identity_key(d, &alice, USER).await;
        ts::register_identity_key(d, &node, NODE).await;
        ts::register_identity_key(d, &other, AGENT).await;
        put(d, grant(&format!("i96b-self-{s}"), &node, "p", Some(&node)))
            .await
            .expect("I96 (b): a machine naming ITSELF admits");
        let err = put(d, grant(&format!("i96b-x-{s}"), &node, "p", Some(&other)))
            .await
            .expect_err("I96 (b): a machine naming ANOTHER key is refused");
        assert!(
            err.to_string().contains("for_key_id"),
            "I96 (b): the refusal names the member: {err}"
        );
        put(d, grant(&format!("i96b-h-{s}"), &alice, "p", Some(&other)))
            .await
            .expect("I96 (b): a human may name any key");
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i94() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i94_occurrence_anchor_with_the_self_row_present(&b, &super::suffix())
                        .await
                }
                #[tokio::test]
                async fn i95() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i95_scoped_consent_by_principals(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i96() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i96_consent_peers_by_principals(&b, &super::suffix()).await
                }
                #[tokio::test]
                async fn i96b() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i96b_for_key_id_admission(&b, &super::suffix()).await
                }
            }
        };
    }
    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });
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

    /// **I97 — two nodes: the login ceremony's occurrence anchor crosses.**
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i97_login_anchor_crosses_and_the_far_node_walks_to_the_human() {
        use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::identity_type::{AGENT, USER};
        use crate::federation::FederationDirectory;
        let run = super::run::suffix();
        let mk = |alias: String| async move {
            let e =
                crate::Engine::with_signer_pre_genesis(ts::local_signer(&alias), "sqlite::memory:")
                    .await
                    .unwrap();
            e.register_self_federation_key(
                crate::federation::types::identity_type::NODE,
                &alias,
                None,
                serde_json::json!({}),
                vec![],
            )
            .await
            .unwrap();
            e
        };
        let (a, b) = (
            mk(format!("i97-a-{run}")).await,
            mk(format!("i97-b-{run}")).await,
        );
        let (sa, sb) = (
            a.sqlite_backend().unwrap().clone(),
            b.sqlite_backend().unwrap().clone(),
        );
        let alice_label = format!("i97-alice-{run}");
        let alice_signer = ts::local_signer(&alice_label);
        let alice = alice_signer.derived_key_id();
        let (app, agent) = (format!("i97-app-{run}"), format!("i97-agent-{run}"));
        for s in [&sa, &sb] {
            ts::register_hybrid_key_as(s.as_ref(), &alice, &alice_label, USER).await;
            ts::register_hybrid_key_as(s.as_ref(), &app, &app, USER).await;
            ts::register_hybrid_key_as(s.as_ref(), &agent, &agent, AGENT).await;
        }
        let keys = || {
            use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
            let (_x, xp, _m, mp) =
                crate::federation::identity_aggregate::mint_content_kem_keypair().unwrap();
            crate::federation::EncryptionPubkeys {
                x25519_base64: B64.encode(xp),
                ml_kem_768_base64: B64.encode(mp),
            }
        };
        a.self_at_login(SelfAtLoginInput {
            identity_key_id: alice.clone(),
            identity_signer: Some(alice_signer),
            app: SelfAtLoginOccurrence {
                occurrence_key_id: app.clone(),
                device_class: "phone".into(),
                hardware_attestation: None,
                encryption_pubkeys: Some(keys()),
                transport_destinations: vec![],
            },
            agent: SelfAtLoginOccurrence {
                occurrence_key_id: agent.clone(),
                device_class: "agent".into(),
                hardware_attestation: None,
                encryption_pubkeys: Some(keys()),
                transport_destinations: vec![],
            },
            bilateral_pair_id: uuid::Uuid::new_v4().to_string(),
            delegation_scope: None,
        })
        .await
        .expect("I97: the login ceremony on A");
        assert_eq!(
            crate::federation::admission::steward_bindings_of(sa.as_ref(), &agent)
                .await
                .unwrap(),
            vec![alice.clone()],
            "I97: on A the human stewards the agent"
        );
        let mut crossed = 0;
        for served in sa
            .list_signed_identity_occurrences_since(None, 1_000)
            .await
            .unwrap()
        {
            if served.occurrence.identity_occurrence.occurrence_key_id == agent {
                sb.put_identity_occurrence(served.occurrence)
                    .await
                    .expect("I97: B admits the agent's occurrence through the gated door");
                crossed += 1;
            }
        }
        assert_eq!(crossed, 1, "I97: the anchor was on the plane");
        assert_eq!(
            crate::federation::admission::steward_bindings_of(sb.as_ref(), &agent)
                .await
                .unwrap(),
            vec![alice.clone()],
            "I97: on B the same human stewards the agent"
        );
        let mut p =
            crate::federation::consent_by_humans::consent_principals_of(sb.as_ref(), &agent)
                .await
                .unwrap();
        p.sort();
        let mut want = vec![agent.clone(), alice];
        want.sort();
        assert_eq!(p, want, "I97: {{agent, human}} on the far node");
    }

    /// **I94 (b) + I98 — from disk.** The three clause-(2) sites use the one
    /// helper; the combine rule is one function every door reaches.
    #[test]
    fn i94b_i98_one_helper_one_rule_every_door() {
        const ADM: &str = include_str!("admission.rs");
        const MODULE: &str = include_str!("consent_by_humans.rs");
        const PYO3: &str = include_str!("../ffi/pyo3.rs");
        for f in [
            "pub async fn is_steward_bound(",
            "pub async fn steward_bindings_of(",
            "pub async fn steward_binding_chain(",
        ] {
            let body = ADM.split(f).nth(1).expect(f);
            let body = &body[..body.find("\n}\n").expect("fn end")];
            assert!(
                body.contains("user_identity_anchors_of("),
                "I94 (b): {f} resolves the occurrence half through the one helper"
            );
            assert!(
                !body.contains("lookup_identity_for_occurrence("),
                "I94 (b): {f} still reads LIMIT 1"
            );
        }
        assert_eq!(
            MODULE.matches("pub fn combine_principal_stances(").count(),
            1
        );
        for (name, text) in [("pyo3.rs", PYO3), ("admission.rs", ADM)] {
            assert!(
                !text.contains("fn combine_principal_stances("),
                "I98: {name} re-defines the combine rule"
            );
        }
        let door = MODULE
            .split("pub async fn resolve_scoped_consent_by_principals")
            .nth(1)
            .unwrap();
        assert!(
            door.contains("combine_principal_stances("),
            "I98: the scoped door calls the rule"
        );
        const ENGINE: &str = include_str!("../engine.rs");
        for f in [
            "consent_peers_by_principals",
            "resolve_scoped_consent_by_principals",
        ] {
            let d = ENGINE.split(&format!("pub async fn {f}(")).nth(1).expect(f);
            let body = &d[..d.find("\n    }\n").expect("end")];
            assert!(
                body.contains(&format!("consent_by_humans::{f}(")),
                "I98: the Engine door `{f}` delegates to the module"
            );
        }
        for f in [
            "consent_peers_by_principals",
            "resolve_scoped_consent_by_principals",
        ] {
            let d = PYO3.split(&format!("    fn {f}(")).nth(1).expect(f);
            let body = &d[..d.find("\n    }\n").expect("end")];
            assert!(
                body.contains(&format!("engine.{f}(")),
                "I98: the PyO3 mirror `{f}` delegates to the Engine"
            );
        }
    }
}
