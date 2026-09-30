//! v52.0.0 (CIRISPersist#946; CC 3.3.1) — **I148: the capture grant is the
//! node's own, names its owner at the grant's instant, and the fold treats a
//! revocation as a boundary.** Memory, sqlite, postgres.

pub(crate) mod bodies {
    use crate::federation::admission::steward_liveness_test_support::{
        register, signed_row, withdraws_of,
    };
    use crate::federation::community_trust_consent::{
        community_trust_consent_for, COMMUNITY_TRUST_DIMENSION,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{attestation_type, identity_type as it, SignedAttestation};
    use crate::federation::{Attestation, AttestationOutcome, Error, FederationDirectory};

    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    fn grant(node: &str, subjects: &[&str], attester: &str) -> Attestation {
        let mut r = signed_row(
            attester,
            node,
            attestation_type::SCORES,
            serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "dimension": COMMUNITY_TRUST_DIMENSION,
                "score": 1.0,
            }),
        );
        r.subject_key_ids = subjects.iter().map(|s| (*s).to_owned()).collect();
        ts::reseal(&mut r);
        r
    }

    pub(crate) async fn i148_the_capture_grant_names_its_owner_and_folds_by_boundary(
        d: &dyn FederationDirectory,
    ) {
        let s = suffix();
        let (owner, node, stranger, unbound) = (
            format!("ct-owner-{s}"),
            format!("ct-node-{s}"),
            format!("ct-stranger-{s}"),
            format!("ct-unbound-{s}"),
        );
        register(d, &owner, &[it::USER]).await;
        register(d, &node, &[it::NODE]).await;
        register(d, &stranger, &[it::USER]).await;
        register(d, &unbound, &[it::NODE]).await;
        let put = |a: Attestation| async move {
            d.put_attestation(SignedAttestation { attestation: a })
                .await
        };
        put(ts::owner_binding_attestation(
            &format!("ct-ob-{s}"),
            &owner,
            &node,
        ))
        .await
        .expect("the owner binds the node");
        assert!(
            community_trust_consent_for(d, &node)
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
        let e = put(grant(&node, &[&owner], &stranger))
            .await
            .expect_err("not the node's own row");
        assert!(
            matches!(&e, Error::InvalidArgument(m) if m.contains("NODE's own row")),
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
        let g1 = grant(&node, &[&owner], &node);
        let g1_id = g1.attestation_id.clone();
        assert_eq!(put(g1).await.unwrap(), AttestationOutcome::Inserted);
        assert_eq!(
            community_trust_consent_for(d, &node)
                .await
                .unwrap()
                .map(|a| a.attestation_id),
            Some(g1_id.clone())
        );
        // a later grant wins
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let g2 = grant(&node, &[&owner], &node);
        let g2_id = g2.attestation_id.clone();
        put(g2).await.unwrap();
        assert_eq!(
            community_trust_consent_for(d, &node)
                .await
                .unwrap()
                .map(|a| a.attestation_id),
            Some(g2_id.clone()),
            "the latest grant stands"
        );
        // the OWNER revokes the newest (rule 2, listed in subject_key_ids): a
        // boundary — the older grant is NOT resurrected
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let w = withdraws_of(&owner, &node, &g2_id);
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
            community_trust_consent_for(d, &node)
                .await
                .unwrap()
                .is_none(),
            "I148: revoking the newest grant never resurrects an older one"
        );
        // capture resumes only on a FRESH grant after the boundary
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let g3 = grant(&node, &[&owner], &node);
        let g3_id = g3.attestation_id.clone();
        put(g3).await.unwrap();
        assert_eq!(
            community_trust_consent_for(d, &node)
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
}
