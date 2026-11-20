//! v52.0.0 (CIRISPersist#946; CC 3.3.1) — **I148: the capture grant is the
//! node's own, names its owner at the grant's instant, and the fold treats a
//! revocation as a boundary.** Memory, sqlite, postgres.
//!
//! v59.0.0 (CIRISPersist#1096; CC 3.3.1 rc9 `1a46e03`,
//! `CLM-consent-community-trust-owner-authored`) — **I1154: the owner may
//! author it.** A live roster key of the owner's fedID authors a grant about
//! the node naming the node, the owner and the agent key; it admits and
//! counts. A key that is not the owner's roster key is refused
//! `community_trust_attester_not_owner`. Both forms present: the later
//! governs. The owner's recant of its own grant ends a node-authored grant
//! at or before it. The agent key's withdrawal ends consent and leaves the
//! traces already captured. A held node-authored grant in the v52 shape (the
//! owner alone) keeps counting and is counted at open; a new one missing a
//! party is refused `community_trust_subjects_incomplete`.
//!
//! v62.0.0 (the JSON cut): every row is an edition-2 statement
//! (`edition2::fixture_switch`); keys are live by their `key:record` and
//! named by `kid(label)`; the owner binding carries the node's voice; a
//! retraction names its target by `refs.target`. The v52-shape grandfather
//! legs (I1154's held owner-only grant, its open-time count) are deleted:
//! nothing of the earlier form carries into a v62 store.

pub(crate) mod bodies {
    use crate::federation::community_trust_consent::{
        community_trust_consent_for, COMMUNITY_TRUST_DIMENSION,
    };
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it};
    use crate::federation::{Attestation, Error, FederationDirectory};

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    /// `key` is live by its edition-2 `key:record` carrying `types`.
    async fn register(d: &dyn FederationDirectory, key: &str, types: &[&str]) {
        let _ = e2::put_key(d, key, types).await;
    }

    /// A community-trust grant about `node` listing `subjects`, signed by
    /// `attester` (its edition-2 statement's mapped row).
    fn grant(node: &str, subjects: &[&str], attester: &str) -> Attestation {
        let mut r = {
            ts::bare_attestation(
                "",
                attester,
                node,
                &serde_json::json!({
                    "dimension": COMMUNITY_TRUST_DIMENSION,
                    "score": 1.0,
                }),
            )
        };
        r.attestation_type = attestation_type::SCORES.to_owned();
        r.subject_key_ids = subjects.iter().map(|s| (*s).to_owned()).collect();
        e2::row_of(&r, attester)
    }

    /// `owner` binds `node`: the owner's row, then the node's voice over it.
    async fn bind(d: &dyn FederationDirectory, id: &str, owner: &str, node: &str) {
        let row = ts::owner_binding_attestation(id, owner, node);
        // v62.0.0 (E2-fix3; K2.api) — the owner's statement, then the node's
        // voice, through K2's shared helper (no hand-rolled voice).
        ts::put_sealed_owner_binding(d, &row, node)
            .await
            .expect("the owner binds the node");
    }

    /// **I1154** (see the module header).
    pub(crate) async fn i1154_the_owner_may_author_the_grant<B>(b: &B)
    where
        B: FederationDirectory + crate::store::Backend,
    {
        use crate::federation::community_trust_consent as ctc;
        let d: &dyn FederationDirectory = b;
        let s = suffix();
        let (owner, dev, node, agent, stranger) = (
            format!("ct4-owner-{s}"),
            format!("ct4-dev-{s}"),
            format!("ct4-node-{s}"),
            format!("ct4-agent-{s}"),
            format!("ct4-stranger-{s}"),
        );
        register(d, &owner, &[it::USER]).await;
        register(d, &dev, &[it::USER]).await;
        register(d, &node, &[it::NODE]).await;
        register(d, &agent, &[it::AGENT]).await;
        register(d, &stranger, &[it::USER]).await;
        // v62.0.0 (E2-fix3; O1) — the owner's second device is an edition-2
        // `identity:occurrence` bind (the device's own voice and the owner's),
        // naming the owner's roster head; the earlier signed occurrence
        // (`self_roster_invariants::bodies::add`) is not an edition-2 row.
        assert!(
            matches!(
                e2::put_bind(
                    d,
                    &owner,
                    &owner,
                    &dev,
                    crate::federation::types::device_class::PHONE,
                    &e2::BindOptions::default(),
                )
                .await
                .expect("the owner's second device"),
                StatementOutcome::Row { .. }
            ),
            "I1154: the owner's second device binds"
        );
        let put = |a: Attestation| async move { e2::put_signed(d, &a).await };
        bind(d, &format!("ct4-ob-{s}"), &owner, &node).await;
        let node_kid = e2::kid(&node);
        let consent = || async { community_trust_consent_for(d, &node_kid).await.unwrap() };
        let three = [node.as_str(), owner.as_str(), agent.as_str()];
        let tick = || tokio::time::sleep(std::time::Duration::from_millis(20));

        // A non-roster key is refused.
        let e = put(grant(&node, &three, &stranger))
            .await
            .expect_err("I1154: a stranger's grant");
        assert!(
            matches!(&e, Error::InvalidArgument(m) if m.starts_with(ctc::ATTESTER_NOT_OWNER)),
            "I1154: {e:?}"
        );

        // A node-authored grant, then the owner's (by its second device): the
        // later governs.
        let gn = grant(&node, &three, &node);
        let gn_id = gn.attestation_id.clone();
        put(gn).await.expect("I1154: the node's grant");
        tick().await;
        let go = grant(&node, &three, &dev);
        let go_id = go.attestation_id.clone();
        let go_row = go.clone();
        assert!(matches!(
            put(go)
                .await
                .expect("I1154: the owner's roster key authors a grant"),
            StatementOutcome::Row { new: true, .. }
        ));
        assert_eq!(
            consent().await.map(|a| a.attestation_id),
            Some(go_id.clone()),
            "I1154: the owner-authored grant counts, and the later governs"
        );
        tick().await;
        let gn2 = grant(&node, &three, &node);
        let gn2_id = gn2.attestation_id.clone();
        put(gn2).await.unwrap();
        assert_eq!(
            consent().await.map(|a| a.attestation_id),
            Some(gn2_id.clone()),
            "I1154: a later node-authored grant governs in turn"
        );

        // The owner recants its grant: the boundary ends every grant at or
        // before it, the node-authored ones included.
        tick().await;
        let recant = e2::composer_of(attestation_type::RECANTS, &go_row, &dev);
        put(recant).await.expect("I1154: the attester recants");
        assert!(
            consent().await.is_none(),
            "I1154: the owner's recant ends the node-authored grants at or before it"
        );
        let _ = (gn_id, gn2_id);

        // A fresh grant, a captured trace, then the agent key withdraws.
        tick().await;
        let g = grant(&node, &three, &dev);
        let g_id = g.attestation_id.clone();
        put(g.clone()).await.unwrap();
        assert_eq!(
            consent().await.map(|a| a.attestation_id),
            Some(g_id.clone())
        );
        let trace = format!("ct4-trace-{s}");
        b.insert_trace_events_batch(&[
            crate::federation::silo_projection_invariants::bodies::trace_row(&trace, &agent),
        ])
        .await
        .expect("I1154: a trace captured under the grant");
        tick().await;
        put(e2::composer_of(attestation_type::WITHDRAWS, &g, &agent))
            .await
            .expect("I1154: the agent key withdraws (rule 2)");
        assert!(
            consent().await.is_none(),
            "I1154: the agent key's withdrawal is a boundary"
        );
        let held = b
            .fetch_trace_events_page(0, 100, Some(&agent))
            .await
            .unwrap();
        assert!(
            held.iter().any(|(_, r)| r.trace_id == trace),
            "I1154: the boundary is over grants only — the captured trace stands"
        );

        // A NEW grant missing a party is refused, in both forms.
        for (attester, subjects) in [
            (&node, vec![owner.as_str()]),
            (&node, vec![node.as_str(), owner.as_str()]),
            (&dev, vec![owner.as_str(), agent.as_str()]),
        ] {
            let e = put(grant(&node, &subjects, attester))
                .await
                .expect_err("I1154: a grant missing a party");
            assert!(
                matches!(&e, Error::InvalidArgument(m) if m.starts_with(ctc::SUBJECTS_INCOMPLETE)),
                "I1154: {subjects:?}: {e:?}"
            );
        }
    }

    pub(crate) async fn i148_the_capture_grant_names_its_owner_and_folds_by_boundary(
        d: &dyn FederationDirectory,
    ) {
        let s = suffix();
        let (owner, node, stranger, unbound, agent) = (
            format!("ct-owner-{s}"),
            format!("ct-node-{s}"),
            format!("ct-stranger-{s}"),
            format!("ct-unbound-{s}"),
            format!("ct-agent-{s}"),
        );
        // v59.0.0 (CIRISPersist#1096) — a grant names the node, its owner and
        // the agent key.
        register(d, &agent, &[it::AGENT]).await;
        register(d, &owner, &[it::USER]).await;
        register(d, &node, &[it::NODE]).await;
        register(d, &stranger, &[it::USER]).await;
        register(d, &unbound, &[it::NODE]).await;
        let put = |a: Attestation| async move { e2::put_signed(d, &a).await };
        bind(d, &format!("ct-ob-{s}"), &owner, &node).await;
        let node_kid = e2::kid(&node);
        assert!(
            community_trust_consent_for(d, &node_kid)
                .await
                .unwrap()
                .is_none(),
            "no grant, no consent"
        );
        // a grant that does not list the owner is refused, not stored
        let bad = grant(&node, &[&stranger], &node);
        let bad_id = bad.attestation_id.clone();
        let e = put(bad).await.expect_err("owner not listed");
        assert!(
            matches!(&e, Error::InvalidArgument(m) if m.contains("does not list the node's owner")),
            "{e:?}"
        );
        assert!(d.get_attestation(&bad_id).await.unwrap().is_none());
        // a third party's grant about the node is refused
        let e = put(grant(&node, &[&node, &owner, &agent], &stranger))
            .await
            .expect_err("neither the node nor its owner's roster key");
        assert!(
            matches!(&e, Error::InvalidArgument(m)
                if m.starts_with(crate::federation::community_trust_consent::ATTESTER_NOT_OWNER)),
            "{e:?}"
        );
        // a node with no owner binding in force cannot grant
        let e = put(grant(&unbound, &[&owner], &unbound))
            .await
            .expect_err("no binding in force");
        assert!(
            matches!(&e, Error::InvalidArgument(m) if m.contains("no owner binding")),
            "{e:?}"
        );
        // the node's own grant listing its owner admits and stands
        let g1 = grant(&node, &[&node, &owner, &agent], &node);
        let g1_id = g1.attestation_id.clone();
        assert!(matches!(
            put(g1).await.unwrap(),
            StatementOutcome::Row { new: true, .. }
        ));
        assert_eq!(
            community_trust_consent_for(d, &node_kid)
                .await
                .unwrap()
                .map(|a| a.attestation_id),
            Some(g1_id.clone())
        );
        // a later grant wins
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let g2 = grant(&node, &[&node, &owner, &agent], &node);
        let g2_id = g2.attestation_id.clone();
        put(g2.clone()).await.unwrap();
        assert_eq!(
            community_trust_consent_for(d, &node_kid)
                .await
                .unwrap()
                .map(|a| a.attestation_id),
            Some(g2_id.clone()),
            "the latest grant stands"
        );
        // the OWNER revokes the newest (rule 2, listed in subject_key_ids): a
        // boundary — the older grant is NOT resurrected
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let w = e2::composer_of(attestation_type::WITHDRAWS, &g2, &owner);
        let w_id = w.attestation_id.clone();
        put(w).await.expect("the listed owner revokes");
        // admitted on the third-party path: rule 2 (listed subject), or rule 1
        // lifted to the node's owner (#941) — whichever the door reaches first
        let rule = d
            .get_attestation(&w_id)
            .await
            .unwrap()
            .unwrap()
            .withdraws_admission_rule;
        assert!(matches!(rule, Some(1) | Some(2)), "{rule:?}");
        assert!(
            community_trust_consent_for(d, &node_kid)
                .await
                .unwrap()
                .is_none(),
            "I148: revoking the newest grant never resurrects an older one"
        );
        // capture resumes only on a FRESH grant after the boundary
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let g3 = grant(&node, &[&node, &owner, &agent], &node);
        let g3_id = g3.attestation_id.clone();
        put(g3).await.unwrap();
        assert_eq!(
            community_trust_consent_for(d, &node_kid)
                .await
                .unwrap()
                .map(|a| a.attestation_id),
            Some(g3_id),
            "a fresh grant after R stands"
        );
        let _ = g1_id;
    }
}

#[cfg(test)]
mod runners {
    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                #[tokio::test]
                async fn i1154() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i1154_the_owner_may_author_the_grant(&d).await
                }

                #[tokio::test]
                async fn i148() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i148_the_capture_grant_names_its_owner_and_folds_by_boundary(
                        &d as &dyn crate::federation::FederationDirectory,
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
}
