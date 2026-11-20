//! v48.0.0 (CIRISPersist#905) — **the promotion sweep sees a claimed
//! machine's consent.** Since v44.6.0 the grants that cover a machine are
//! authored by its HUMAN and name it in `for_key_id`; a sweep that loaded
//! only self-authored grants saw zero on every claimed node, and an owned
//! agent's sealed traces stayed `(self, local)` forever with no refusal and
//! no line. I168 is the production shape on an `Engine`; I169 is the
//! `consent_peer_set` key on every backend.

/// The backend-agnostic bodies; `run` instantiates them per backend.
#[cfg(test)]
pub mod bodies {
    use crate::federation::consent_by_humans as cbh;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{Attestation, FederationDirectory};

    /// The unsigned literal [`row`] states (the payload of its statement).
    fn literal(
        signer: &str,
        target: &str,
        envelope: serde_json::Value,
        subject_key_ids: Vec<String>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Attestation {
        Attestation {
            attestation_id: String::new(),
            attesting_key_id: signer.to_owned(),
            attested_key_id: target.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at: at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
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
        }
    }

    /// A federation-tier row signed by `signer`: the door's mapping of the
    /// signer's edition-2 statement. `id` is kept for the callers' shape and
    /// is NOT the row's id: an edition-2 row id is node-computed, so a caller
    /// reads `attestation_id` off the returned row.
    pub(crate) fn row(
        id: &str,
        signer: &str,
        target: &str,
        envelope: serde_json::Value,
        subject_key_ids: Vec<String>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Attestation {
        let _ = id;
        e2::row_of(
            &literal(signer, target, envelope, subject_key_ids, at),
            signer,
        )
    }

    /// A `consent:replication:v1` grant by `author` toward `peer`, naming
    /// `for_key` as the machine it is for (None = a self-grant), covering
    /// `prefixes` for egress.
    pub fn grant(
        id: &str,
        author: &str,
        peer: &str,
        for_key: Option<&str>,
        prefixes: &[&str],
    ) -> Attestation {
        let mut payload =
            serde_json::json!({"grants": "replication", "attestation_prefixes": prefixes});
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

    /// `author` withdraws its own row `target` (a row id) — the structural
    /// composer the peer-set projection folds on (`revocation_fold_target`).
    /// Edition 2: the composer carries its target's family (a consent grant)
    /// and names the target in `refs.target`. `id` is ignored (see [`row`]).
    pub(crate) fn withdraws(id: &str, author: &str, target: &str) -> Attestation {
        let _ = id;
        let family = e2::family_of(&literal(
            author,
            author,
            serde_json::json!({"dimension": crate::federation::consent_peer_set::DIMENSION}),
            Vec::new(),
            chrono::Utc::now(),
        ));
        let mut r = literal(
            author,
            author,
            serde_json::json!({"references_attestation_id": target}),
            Vec::new(),
            chrono::Utc::now(),
        );
        r.attestation_type = attestation_type::WITHDRAWS.to_owned();
        e2::row_of_statement(&e2::statement_of_family(&r, author, &family), &r.tier)
    }

    /// An owner binding `owner → node`, put with the node's own voice
    /// (edition 2, C557: a binding counts only with the node's statement).
    async fn put_owner_binding(d: &dyn FederationDirectory, owner: &str, node: &str) {
        // K2.api: the shared landing (owner's statement, then the node's
        // voice, C557; asserts Row).
        let b = ts::owner_binding_attestation("", owner, node);
        ts::put_sealed_owner_binding(d, &b, node)
            .await
            .unwrap_or_else(|e| panic!("the owner binding {owner} → {node}: {e}"));
    }

    pub(crate) async fn put(d: &dyn FederationDirectory, a: Attestation) {
        crate::federation::edition2::fixture_switch::put_signed(d, &a)
            .await
            .unwrap_or_else(|e| panic!("put {}: {e}", "attestation"));
    }

    /// **I169 — a human's two per-key grants toward one peer are both live.**
    pub async fn i169_two_per_key_grants_are_both_live(d: &dyn FederationDirectory, s: &str) {
        let alice = format!("i169-alice-{s}");
        let node = format!("i169-node-{s}");
        let actor = format!("i169-actor-{s}");
        let peer = format!("i169-peer-{s}");
        let other = format!("i169-other-{s}");
        ts::register_identity_key(d, &alice, USER).await;
        for k in [&node, &actor, &peer, &other] {
            ts::register_identity_key(d, k, NODE).await;
        }
        for machine in [&node, &actor] {
            put_owner_binding(d, &alice, machine).await;
        }
        // Edition 2: every key is named by its identity-ref, and a row by
        // its node-computed id (read off the row).
        let (alice_k, node_k, actor_k) = (e2::kid(&alice), e2::kid(&node), e2::kid(&actor));
        let g_node_row = grant("", &alice, &peer, Some(&node), &["trace:"]);
        let g_actor_row = grant("", &alice, &peer, Some(&actor), &["trace:"]);
        let (g_node, g_actor) = (
            g_node_row.attestation_id.clone(),
            g_actor_row.attestation_id.clone(),
        );
        put(d, g_node_row).await;
        put(d, g_actor_row).await;
        // The attester-keyed reader holds BOTH (the V152 key), and the
        // peer set has the peer once.
        let live: Vec<String> = d
            .list_live_consent_grants_by(&alice_k)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert!(
            live.contains(&g_node) && live.contains(&g_actor),
            "I169: both per-key grants are live for the author: {live:?}"
        );
        assert_eq!(
            d.list_consent_peers(&alice_k).await.unwrap(),
            vec![e2::kid(&peer)]
        );
        // By principals: each machine sees exactly the grant that names it.
        let for_node: Vec<String> = cbh::live_egress_grants_by_principals(d, &node_k)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(
            for_node,
            vec![g_node.clone()],
            "I169: the node's grant, not the actor's"
        );
        let for_actor: Vec<String> = cbh::live_egress_grants_by_principals(d, &actor_k)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(for_actor, vec![g_actor.clone()]);
        // The READ alone is keyed by the machine (the V147 projection): the
        // actor's grant is not a candidate for the node even before the
        // predicate looks (a reader that ignored `for_key_id` would hide
        // behind the predicate, and the predicate behind the reader).
        let read_for_node: Vec<String> = d
            .list_live_consent_grants_for(&node_k)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(
            read_for_node,
            vec![g_node.clone()],
            "I169: the read is keyed by for_key_id"
        );
        // The PREDICATE alone: alice is bound to BOTH machines, so only
        // `for_key_id` tells the node's grant from the actor's.
        let g_node_row = d.get_attestation(&g_node).await.unwrap().unwrap();
        let g_actor_row = d.get_attestation(&g_actor).await.unwrap().unwrap();
        assert!(cbh::grant_is_authored_for(d, &g_node_row, &node_k)
            .await
            .unwrap());
        assert!(
            !cbh::grant_is_authored_for(d, &g_actor_row, &node_k)
                .await
                .unwrap(),
            "I169: a bound steward's grant for a SIBLING machine is not the node's"
        );
        // And the crossing's covering check — the door a replicated row
        // reaches — refuses the sibling's grant and accepts the node's.
        let sent_by_node = row(
            "",
            &node,
            &node,
            serde_json::json!({"dimension": "trace:demo:v1", "trace": {}}),
            vec![node.clone()],
            chrono::Utc::now(),
        );
        let now = chrono::Utc::now();
        crate::federation::crossing::check_grant_covers(
            d,
            &sent_by_node,
            &g_node,
            "trace:demo:v1",
            None,
            now,
        )
        .await
        .unwrap_or_else(|e| panic!("I169: the node's own steward-authored grant covers it: {e}"));
        let err = crate::federation::crossing::check_grant_covers(
            d,
            &sent_by_node,
            &g_actor,
            "trace:demo:v1",
            None,
            now,
        )
        .await
        .expect_err("I169: the steward's grant for the sibling does not cover the node");
        assert!(
            err.to_string().contains("neither the sender nor a steward"),
            "I169: refused for the principal, not something else: {err}"
        );
        // A stranger's grant naming the node is NOT the node's (no binding).
        let mallory = format!("i169-mallory-{s}");
        ts::register_identity_key(d, &mallory, USER).await;
        put(d, grant("", &mallory, &other, Some(&node), &["trace:"])).await;
        let for_node_again: Vec<String> = cbh::live_egress_grants_by_principals(d, &node_k)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(
            for_node_again,
            vec![g_node.clone()],
            "I169: an unbound author's grant is not the machine's"
        );
        // Withdrawing the actor's grant leaves the node's grant live and the
        // peer still a peer of the author (the V109 key used to drop it).
        put(d, withdraws("", &alice, &g_actor)).await;
        let live: Vec<String> = d
            .list_live_consent_grants_by(&alice_k)
            .await
            .unwrap()
            .into_iter()
            .map(|a| a.attestation_id)
            .collect();
        assert_eq!(
            live,
            vec![g_node.clone()],
            "I169: the node's grant survives the actor's withdrawal"
        );
        assert_eq!(
            d.list_consent_peers(&alice_k).await.unwrap(),
            vec![e2::kid(&peer)]
        );
        assert!(cbh::live_egress_grants_by_principals(d, &actor_k)
            .await
            .unwrap()
            .is_empty());
    }

    /// **I168 — an owned agent's sealed traces are promoted by its human's
    /// consent.** The production shape: the machine's consent is authored
    /// by its owner and names it in `for_key_id`; the machine authored no
    /// grant of its own. Before #905 the sweep loaded zero grants here.
    ///
    /// v62.0.0 (v62 P8-fix6, CP2) — edition 2 throughout:
    /// - the machine's key is its engine's own edition-2 `key:record`
    ///   (`register_self_federation_key`), the key `kid(node)` its signer
    ///   signs as;
    /// - the owner binding is the owner's statement plus the machine's own
    ///   voice ([`put_owner_binding`], C557);
    /// - the sealed local row is the machine's OWN edition-2 statement put at
    ///   the `local` tier (`attestation_emit::produce_row` →
    ///   `put_statement_with_origin(.., LOCAL, Authored)`), so the sweep's
    ///   crossing is the statement custody: the same row id flips to
    ///   `federation` (P8, CC 2.6.1.9);
    /// - the owner's grant is [`grant`] (edition 2), naming the machine.
    ///
    /// The row's dimension is `observation:reachability:v1` (a family the
    /// producer states without a blob; a `trace:complete:v1` row needs its
    /// trace blob's `evidence_refs`), and the grant covers `observation:`.
    #[cfg(any(feature = "sqlite", feature = "postgres"))]
    pub async fn i168_the_sweep_promotes_an_owned_agents_rows(dsn: &str, s: &str) {
        use crate::federation::types::cohort_scope;
        let node = format!("i168-node-{s}");
        let engine = crate::Engine::with_signer_pre_genesis(ts::local_signer(&node), dsn)
            .await
            .expect("engine");
        // The machine registers its own key (the row every attestation ABOUT
        // it resolves against) — the production boot shape.
        let registered = engine
            .register_self_federation_key(NODE, None, None)
            .await
            .expect("register self");
        let derived = engine.local_derived_key_id().await.expect("derived key");
        assert_eq!(registered, derived, "I168: the self row IS the derived key");
        assert_eq!(
            derived,
            e2::kid(&node),
            "I168: the engine signs as its seed's identity-ref"
        );
        let dir = engine.federation_directory();
        let alice = format!("i168-alice-{s}");
        let peer = format!("i168-peer-{s}");
        ts::register_identity_key(&*dir, &alice, USER).await;
        ts::register_identity_key(&*dir, &peer, NODE).await;
        // The human is bound to the machine (her statement and its voice);
        // the machine is claimed.
        put_owner_binding(&*dir, &alice, &node).await;
        // A sealed local row authored by the machine: its own statement at
        // the local tier.
        let signer = engine
            .composite_signer("i168")
            .expect("I168: the engine's composite signer");
        let input = crate::federation::EmitAttestationInput::with_envelope(
            attestation_type::SCORES,
            crate::federation::envelope::EnvelopeCore::from_value(serde_json::json!({
                "dimension": "observation:reachability:v1",
                "score": 0.5,
            }))
            .expect("an envelope"),
            cohort_scope::SELF,
        );
        let produced = crate::federation::attestation_emit::produce_row(&*dir, signer, input, None)
            .await
            .expect("I168: the machine states its row");
        crate::federation::edition2::ingest::put_statement_with_origin(
            &*dir,
            &produced.statement,
            None,
            attestation_tier::LOCAL,
            crate::federation::replication::admission::WriteOrigin::Authored,
        )
        .await
        .expect("I168: the local put");
        let before_id =
            crate::federation::edition2::names::RowId::of_statement(&produced.statement)
                .expect("a row statement")
                .hex();
        let before = dir.get_attestation(&before_id).await.unwrap().expect("row");
        assert_eq!(before.tier, attestation_tier::LOCAL);
        assert_eq!(
            before.attesting_key_id, derived,
            "I168: authored by the machine"
        );
        // Control: no grant → the sweep promotes nothing, and says so.
        let none = engine.promote_consented_backlog().await.expect("sweep");
        assert_eq!(none.promoted, 0, "I168 control: nothing covers the row yet");
        // The OWNER's grant, naming the machine — the machine authored none.
        put(
            &*dir,
            grant("", &alice, &peer, Some(&node), &["observation:"]),
        )
        .await;
        assert!(
            dir.list_live_consent_grants_by(&derived)
                .await
                .unwrap()
                .is_empty(),
            "I168 precondition: the machine has NO self-authored grant — the v47 sweep saw zero"
        );
        // Capture what the sweep says while it runs: a skip is logged, not
        // returned, and the line is the diagnosis.
        let lines = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let report = {
            struct Cap(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
            struct V(String);
            impl tracing::field::Visit for V {
                fn record_debug(&mut self, f: &tracing::field::Field, v: &dyn std::fmt::Debug) {
                    self.0.push_str(&format!("{}={:?} ", f.name(), v));
                }
            }
            impl tracing::Subscriber for Cap {
                fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
                    true
                }
                fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
                    tracing::span::Id::from_u64(1)
                }
                fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
                fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
                fn event(&self, e: &tracing::Event<'_>) {
                    let mut v = V(format!("[{}] ", e.metadata().level()));
                    e.record(&mut v);
                    self.0.lock().unwrap().push(v.0);
                }
                fn enter(&self, _: &tracing::span::Id) {}
                fn exit(&self, _: &tracing::span::Id) {}
            }
            let _g = tracing::subscriber::set_default(Cap(std::sync::Arc::clone(&lines)));
            engine.promote_consented_backlog().await.expect("sweep")
        };
        let said = lines.lock().unwrap().join("\n");
        assert_eq!(
            report.promoted, 1,
            "I168: the human's grant lifts the owned agent's row: {report:?}\n--- the sweep said ---\n{said}"
        );
        // The statement custody: the SAME row id crossed (a row id does not
        // depend on the tier).
        let after = dir
            .get_attestation(&before.attestation_id)
            .await
            .unwrap()
            .expect("row");
        assert_eq!(
            after.tier,
            attestation_tier::FEDERATION,
            "I168: promoted to the federation tier"
        );
        // Idempotent: a second sweep has nothing left.
        let again = engine.promote_consented_backlog().await.expect("sweep");
        assert_eq!(again.promoted, 0);
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i169() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i169_two_per_key_grants_are_both_live(
                        &d as &dyn FederationDirectory,
                        &super::suffix(),
                    )
                    .await
                }
            }
        };
    }

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

    /// **I168** (sqlite, postgres) — see [`super::bodies::i168_the_sweep_promotes_an_owned_agents_rows`].
    /// v62.0.0 (v62 P8-fix6, CP2) — edition 2 on both backends, no
    /// earlier-form scope.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i168_sqlite() {
        let d = tempfile::tempdir().unwrap();
        let dsn = format!("sqlite:///{}", d.path().join("i168.db").display());
        Box::pin(super::bodies::i168_the_sweep_promotes_an_owned_agents_rows(
            &dsn,
            &suffix(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i168_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("i168 postgres: no CIRIS_PERSIST_TEST_PG base DSN — SKIPPED");
            return;
        };
        Box::pin(super::bodies::i168_the_sweep_promotes_an_owned_agents_rows(
            &dsn,
            &suffix(),
        ))
        .await;
        eprintln!("i168 postgres: RAN");
    }
}
