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
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{NODE, USER};
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{Attestation, FederationDirectory, SignedAttestation};

    /// A federation-tier row signed by `signer` — the consent-by-humans
    /// fixture shape (sign → seal → reseal).
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
        ts::reseal(&mut r);
        r
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

    /// `author` withdraws its own row `target` — the structural composer the
    /// peer-set projection folds on (`revocation_fold_target`).
    fn withdraws(id: &str, author: &str, target: &str) -> Attestation {
        let mut r = row(
            id,
            author,
            author,
            serde_json::json!({"references_attestation_id": target}),
            Vec::new(),
            chrono::Utc::now(),
        );
        r.attestation_type = attestation_type::WITHDRAWS.to_owned();
        ts::reseal(&mut r);
        r
    }

    async fn put(d: &dyn FederationDirectory, a: Attestation) {
        d.put_attestation(SignedAttestation { attestation: a })
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
            put(
                d,
                ts::owner_binding_attestation(&format!("i169-ob-{machine}"), &alice, machine),
            )
            .await;
        }
        let g_node = format!("i169-g-node-{s}");
        let g_actor = format!("i169-g-actor-{s}");
        put(d, grant(&g_node, &alice, &peer, Some(&node), &["trace:"])).await;
        put(d, grant(&g_actor, &alice, &peer, Some(&actor), &["trace:"])).await;
        // The attester-keyed reader holds BOTH (the V152 key), and the
        // peer set has the peer once.
        let live: Vec<String> = d
            .list_live_consent_grants_by(&alice)
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
            d.list_consent_peers(&alice).await.unwrap(),
            vec![peer.clone()]
        );
        // By principals: each machine sees exactly the grant that names it.
        let for_node: Vec<String> = cbh::live_egress_grants_by_principals(d, &node)
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
        let for_actor: Vec<String> = cbh::live_egress_grants_by_principals(d, &actor)
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
            .list_live_consent_grants_for(&node)
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
        assert!(cbh::grant_is_authored_for(d, &g_node_row, &node)
            .await
            .unwrap());
        assert!(
            !cbh::grant_is_authored_for(d, &g_actor_row, &node)
                .await
                .unwrap(),
            "I169: a bound steward's grant for a SIBLING machine is not the node's"
        );
        // And the crossing's covering check — the door a replicated row
        // reaches — refuses the sibling's grant and accepts the node's.
        let sent_by_node = row(
            &format!("i169-row-{s}"),
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
        put(
            d,
            grant(
                &format!("i169-g-mallory-{s}"),
                &mallory,
                &other,
                Some(&node),
                &["trace:"],
            ),
        )
        .await;
        let for_node_again: Vec<String> = cbh::live_egress_grants_by_principals(d, &node)
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
        put(d, withdraws(&format!("i169-w-{s}"), &alice, &g_actor)).await;
        let live: Vec<String> = d
            .list_live_consent_grants_by(&alice)
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
            d.list_consent_peers(&alice).await.unwrap(),
            vec![peer.clone()]
        );
        assert!(cbh::live_egress_grants_by_principals(d, &actor)
            .await
            .unwrap()
            .is_empty());
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

    /// **I168 — an owned agent's sealed traces are promoted by its human's
    /// consent.** The production shape: the machine's consent is authored
    /// by its owner and names it in `for_key_id`; the machine authored no
    /// grant of its own. Before #905 the sweep loaded zero grants here.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i168_the_sweep_promotes_an_owned_agents_rows() {
        use crate::federation::tier_ingest::test_support as ts;
        use crate::federation::types::attestation_tier;
        use crate::federation::types::identity_type::{NODE, USER};
        let s = super::run::suffix();
        let signer = ts::local_signer(&format!("i168-node-{s}"));
        let engine = crate::Engine::with_signer(signer, "sqlite::memory:")
            .await
            .expect("engine");
        // The machine registers its own key (the row every attestation ABOUT
        // it resolves against) — the production boot shape.
        let registered = engine
            .register_self_federation_key("node", "ref", None, serde_json::json!({}), Vec::new())
            .await
            .expect("register self");
        let derived = engine.local_derived_key_id().await.expect("derived key");
        assert_eq!(registered, derived, "I168: the self row IS the derived key");
        let dir = engine.federation_directory();
        let alice = format!("i168-alice-{s}");
        let peer = format!("i168-peer-{s}");
        ts::register_identity_key(&*dir, &alice, USER).await;
        ts::register_identity_key(&*dir, &peer, NODE).await;
        // The human is bound to the machine; the machine is claimed.
        super::bodies_put(
            &*dir,
            ts::owner_binding_attestation(&format!("i168-ob-{s}"), &alice, &derived),
        )
        .await;
        // A sealed local trace authored by the machine.
        let before_id = dir
            .attestation_insert_local(crate::federation::types::LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: derived.clone(),
                attested_key_id: None,
                attestation_type: crate::federation::types::attestation_type::SCORES.to_owned(),
                weight: None,
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    serde_json::json!({
                        "dimension": "trace:complete:v1",
                        "trace_id": format!("i168-trace-{s}"),
                        "agent_id_hash": "agent-hash-905",
                        "trace": {},
                    }),
                )
                .unwrap(),
                subject_key_ids: vec![derived.clone()],
                cohort_scope: crate::federation::types::cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await
            .expect("insert local trace");
        let before = dir.get_attestation(&before_id).await.unwrap().expect("row");
        assert_eq!(before.tier, attestation_tier::LOCAL);
        // Control: no grant → the sweep promotes nothing, and says so.
        let none = engine.promote_consented_backlog().await.expect("sweep");
        assert_eq!(none.promoted, 0, "I168 control: nothing covers the row yet");
        // The OWNER's grant, naming the machine — the machine authored none.
        super::bodies_put(
            &*dir,
            super::bodies::grant(
                &format!("i168-g-{s}"),
                &alice,
                &peer,
                Some(&derived),
                &["trace:"],
            ),
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

// Only I168 (sqlite) drives the engine through this; keep the server-only
// axis (`-D warnings`) free of a dead helper.
#[cfg(all(test, feature = "sqlite"))]
async fn bodies_put(
    d: &dyn crate::federation::FederationDirectory,
    a: crate::federation::Attestation,
) {
    d.put_attestation(crate::federation::SignedAttestation { attestation: a })
        .await
        .unwrap_or_else(|e| panic!("put attestation: {e}"));
}
