//! CIRISPersist#884 — witnesses for `FSD/SELF_COLLECTIVE_TRANSFER.md` §5
//! (I137–I140): self/family bytes are DELIVERED, not discovered. The send set
//! includes the self-collective without a consent row; the retroactive
//! re-grant reaches a device admitted after the write; the puller asks the
//! MINTER, never `list_holders`.

#![cfg(any(feature = "sqlite", feature = "postgres"))]

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::key_grant::SignedKeyGrantSet;
    use crate::federation::key_grant_invariants::two_node::{introduce, Node};
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::{self, CryptoTier};
    use crate::federation::types::identity_type::USER;
    use crate::federation::{
        AdoptDisposition, BlobBody, BlobProvenance, BlobStorage, EncryptionPubkeys,
        FederationDirectory, IdentityOccurrence,
    };
    use crate::Engine;
    use std::sync::Arc;

    pub(crate) type Pick<B> = fn(&Engine) -> Arc<B>;

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().unwrap()
    }

    /// Bind `occurrence` (a node key) as an active occurrence of `identity`
    /// on `d`, with `kem` as its content-KEM keys.
    async fn bind(d: &dyn FederationDirectory, identity: &str, occurrence: &str, kem: Option<EncryptionPubkeys>) {
        d.put_identity_occurrence_local(IdentityOccurrence {
            identity_key_id: identity.to_owned(),
            occurrence_key_id: occurrence.to_owned(),
            device_class: crate::federation::types::device_class::SERVER.to_owned(),
            hardware_attestation: None,
            asserted_at: chrono::Utc::now(),
            valid_until: None,
            encryption_pubkeys: kem,
            transport_binding: None,
            persist_row_hash: String::new(),
        })
        .await
        .unwrap_or_else(|e| panic!("bind {identity} through {occurrence}: {e}"));
    }

    /// **I137 — the send set includes the self-collective, without a
    /// consent row; and only where the plane is `SelfOwn`.**
    pub(crate) async fn i137_the_send_set_is_the_self_collective(d: &dyn FederationDirectory, s: &str) {
        let (owner, node_a, node_b, peer) = (
            format!("i137-owner-{s}"),
            format!("i137-node-a-{s}"),
            format!("i137-node-b-{s}"),
            format!("i137-peer-{s}"),
        );
        for k in [&owner, &peer] {
            ts::register_identity_key(d, k, USER).await;
        }
        for k in [&node_a, &node_b] {
            ts::register_identity_key(d, k, crate::federation::types::identity_type::NODE).await;
        }
        bind(d, &node_a, &node_a, None).await;
        bind(d, &owner, &node_a, None).await;
        bind(d, &owner, &node_b, None).await;
        let consent = crate::federation::consent_by_humans::consent_peers_by_principals(d, &node_a)
            .await
            .unwrap();
        assert!(
            !consent.contains(&node_b),
            "I137: there is NO consent row between an owner's own nodes (CC 3.2)"
        );
        let self_set = crate::federation::self_collective::send_set_for(d, &node_a, cohort_scope::SELF)
            .await
            .unwrap();
        assert!(self_set.contains(&node_b), "I137: the owner's other occurrence is in the self send set: {self_set:?}");
        assert!(!self_set.contains(&node_a), "I137: a node does not send to itself");
        for c in &consent {
            assert!(self_set.contains(c), "I137: the consent peers are still in it");
        }
        let community_set = crate::federation::self_collective::send_set_for(d, &node_a, cohort_scope::COMMUNITY)
            .await
            .unwrap();
        assert_eq!(community_set, consent, "I137: a community plane's set is the consent set, unchanged");
        // family: a family member's device is in the FAMILY set and not in the SELF set.
        let (member, member_node, fam) = (
            format!("i137-member-{s}"),
            format!("i137-member-node-{s}"),
            format!("i137-fam-{s}"),
        );
        ts::register_identity_key(d, &member, USER).await;
        ts::register_identity_key(d, &member_node, crate::federation::types::identity_type::NODE).await;
        bind(d, &member, &member_node, None).await;
        ts::register_identity_key(d, &fam, USER).await;
        d.put_family(ts::sign_family(
            &fam,
            crate::federation::Family {
                family_key_id: fam.clone(),
                family_name: "Fam".into(),
                members: vec![
                    crate::federation::FamilyMember { key_id: owner.clone(), joined_at: at("2026-06-01T00:00:00Z"), role: None },
                    crate::federation::FamilyMember { key_id: member.clone(), joined_at: at("2026-06-01T00:00:00Z"), role: None },
                ],
                founded_at: at("2026-06-01T00:00:00Z"),
                consensus_protocol: "unanimous".into(),
                consensus_protocol_entrenched: false,
                persist_row_hash: String::new(),
            },
        ))
        .await
        .unwrap();
        let family_set = crate::federation::self_collective::send_set_for(d, &node_a, cohort_scope::FAMILY)
            .await
            .unwrap();
        assert!(family_set.contains(&member_node), "I137: a family member's device is in the family set: {family_set:?}");
        assert!(family_set.contains(&node_b), "I137: and so is the owner's other device");
        let self_set = crate::federation::self_collective::send_set_for(d, &node_a, cohort_scope::SELF)
            .await
            .unwrap();
        assert!(!self_set.contains(&member_node), "I137: a family member's device is NOT in the self set");
    }

    /// **I139 — `minter_of_blob`: the community binding's minter, and the
    /// content set's attester for self; `None` for an unknown sha.**
    pub(crate) async fn i139_minter_of_blob<B>(dsn_a: &str, dsn_b: &str, run: &str, pick: Pick<B>)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let l = crate::federation::epoch_minter_invariants::bodies::ladder(dsn_a, dsn_b, run, pick).await;
        let r = l.engine_a
            .put_blob_scoped(cohort_scope::COMMUNITY, Some(&l.comm), b"community minter", None, None)
            .await
            .unwrap();
        assert_eq!(
            l.ba.minter_of_blob(&r.at_rest_sha256).await.unwrap().as_deref(),
            Some(l.node_a.as_str()),
            "I139: a community blob's minter is the epoch binding's"
        );
        let unknown = [7u8; 32];
        assert_eq!(l.ba.minter_of_blob(&unknown).await.unwrap(), None, "I139: unknown sha → None");
        // self: seal on A, carry the content set to B, ask B.
        let rs = l.engine_a
            .put_blob_scoped(cohort_scope::SELF, None, b"self minter", None, None)
            .await
            .unwrap();
        assert_eq!(rs.tier, CryptoTier::InvisibleEncrypted);
        let sets: Vec<_> = l.ba
            .list_attestations_by(&l.node_a)
            .await
            .unwrap()
            .into_iter()
            .filter(|x| x.attestation_type == crate::federation::key_grant::KEY_GRANT_CONTENT_ATTESTATION_TYPE)
            .collect();
        assert!(!sets.is_empty(), "I139: the self write emitted a content set");
        for a in &sets {
            let _ = l.engine_b.apply_replicated_key_grant(SignedKeyGrantSet { attestation: a.clone() }).await;
        }
        assert_eq!(
            l.bb.minter_of_blob(&rs.at_rest_sha256).await.unwrap().as_deref(),
            Some(l.node_a.as_str()),
            "I139: on the peer, a self blob's minter is the content set's attester"
        );
    }

    /// **I138 — a device admitted after the write opens the write.** Seal a
    /// self blob on A while A is the only occurrence; then B becomes an
    /// occurrence of A's owner; the retroactive re-key on A emits the content
    /// set naming B; carried to B, the bytes adopted `LocalOnly`, B opens.
    pub(crate) async fn i138_a_device_admitted_after_the_write_opens_it<B>(dsn_a: &str, dsn_b: &str, run: &str, pick: Pick<B>)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let (alias_a, alias_b) = (format!("sc-a-{run}"), format!("sc-b-{run}"));
        let engine_a = Engine::with_signer_pre_genesis(ts::local_signer(&alias_a), dsn_a).await.unwrap();
        let engine_b = Engine::with_signer_pre_genesis(ts::local_signer(&alias_b), dsn_b).await.unwrap();
        for (e, alias) in [(&engine_a, &alias_a), (&engine_b, &alias_b)] {
            e.register_self_federation_key(USER, alias, None, serde_json::json!({}), vec![]).await.unwrap();
        }
        let (sa, sb) = (pick(&engine_a), pick(&engine_b));
        let kem = |id: crate::federation::identity_aggregate::ContentKemIdentity| EncryptionPubkeys {
            x25519_base64: id.x25519_pubkey_b64,
            ml_kem_768_base64: id.ml_kem_768_pubkey_b64,
        };
        let a = Node { backend: sa.as_ref(), signer: ts::local_signer(&alias_a), key: engine_a.local_derived_key_id().await.unwrap(), kem: kem(sa.load_or_init_content_kem_identity().await.unwrap()) };
        let b = Node { backend: sb.as_ref(), signer: ts::local_signer(&alias_b), key: engine_b.local_derived_key_id().await.unwrap(), kem: kem(sb.load_or_init_content_kem_identity().await.unwrap()) };
        introduce(&[&a, &b], &[&alias_a, &alias_b]).await;
        // The owner, with A as the only occurrence, on both nodes.
        let owner = format!("sc-owner-{run}");
        for n in [&a, &b] {
            ts::register_hybrid_key_as(n.backend, &owner, &owner, USER).await;
            bind(n.backend, &owner, &a.key, Some(a.kem.clone())).await;
        }
        let r = engine_a
            .put_blob_scoped(cohort_scope::SELF, None, b"before the second device existed", None, None)
            .await
            .expect("A seals a self blob");
        let sha = r.at_rest_sha256;
        // Now B becomes an occurrence of the owner (on both nodes), AFTER the write.
        for n in [&a, &b] {
            bind(n.backend, &owner, &b.key, Some(b.kem.clone())).await;
        }
        assert!(
            crate::federation::self_collective::send_set_for(sa.as_ref(), &a.key, cohort_scope::SELF)
                .await
                .unwrap()
                .contains(&b.key),
            "I138: B is in A's self send set with no grant (R2)"
        );
        let rk = engine_a
            .rekey_self_occurrence_add(&owner, &[b.key.clone()])
            .await
            .expect("I138: the retroactive re-key runs on A");
        assert!(rk.wraps_added >= 1, "I138: a wrap for B was added: {rk:?}");
        // The sets A emitted travel to B (the R2 send set now names B).
        let sets: Vec<_> = sa
            .list_attestations_by(&a.key)
            .await
            .unwrap()
            .into_iter()
            .filter(|x| x.attestation_type == crate::federation::key_grant::KEY_GRANT_CONTENT_ATTESTATION_TYPE)
            .collect();
        let mut written = 0;
        for s in &sets {
            written += engine_b
                .apply_replicated_key_grant(SignedKeyGrantSet { attestation: s.clone() })
                .await
                .map(|adm| adm.wraps_written)
                .unwrap_or(0);
        }
        assert!(written >= 1, "I138: B admitted a wrap addressed to it");
        // The bytes: B asks the MINTER (A), which holds them by construction.
        assert_eq!(sb.minter_of_blob(&sha).await.unwrap().as_deref(), Some(a.key.as_str()), "I138/R4");
        let Some(BlobBody::Inline(bytes)) = sa.get_blob(&sha).await.unwrap() else { panic!("inline") };
        engine_b
            .adopt_sealed_blob(
                &bytes,
                BlobProvenance {
                    author_key_id: owner.clone(),
                    cohort_scope: cohort_scope::SELF.to_owned(),
                    community_key_id: None,
                    epoch: None,
                    tier: CryptoTier::InvisibleEncrypted,
                    minter_key_id: Some(a.key.clone()),
                },
                None,
                AdoptDisposition::LocalOnly,
            )
            .await
            .expect("I138: B adopts its owner's bytes LocalOnly (self arm: principal equality)");
        assert_eq!(
            engine_b.read_blob_as(&sha, &b.key, None).await.expect("I138: B OPENS what A wrote before B existed"),
            b"before the second device existed"
        );
    }

    /// **I140 — from disk: the three doors reach Python, and no claim was added.**
    #[test]
    fn i140_the_doors_reach_python_and_no_claim_was_added() {
        const PY: &str = include_str!("../ffi/pyo3.rs");
        for door in ["fn send_set_for_json(", "fn minter_of_blob_json(", "fn rekey_self_occurrence_add_json(", "fn rekey_family_member_add_json("] {
            assert!(PY.contains(door), "I140: {door} is on the PyO3 surface");
        }
        const TYPES: &str = include_str!("types.rs");
        assert!(
            TYPES.contains("matches!(s, SELF | FAMILY)"),
            "I140: suppresses_holds_bytes still says self | family — no claim at any scope (CC 5.2)"
        );
    }
}

#[cfg(test)]
mod run {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()
    }
    macro_rules! dir_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i137() {
                    let Some(b) = $fresh.await else { return };
                    bodies::i137_the_send_set_is_the_self_collective(&b, &super::suffix()).await
                }
            }
        };
    }
    macro_rules! engine_runners {
        ($modname:ident, $dsns:expr, $pick:expr) => {
            mod $modname {
                use super::super::bodies;
                #[tokio::test]
                async fn i138() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i138_a_device_admitted_after_the_write_opens_it(&a, &b, &super::suffix(), $pick).await
                }
                #[tokio::test]
                async fn i139() {
                    let Some((a, b)) = $dsns else { return };
                    bodies::i139_minter_of_blob(&a, &b, &super::suffix(), $pick).await
                }
            }
        };
    }
    dir_runners!(memory, async { Some(crate::store::memory::MemoryBackend::new()) });
    #[cfg(feature = "sqlite")]
    dir_runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "postgres")]
    dir_runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn).await.unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });
    #[cfg(feature = "sqlite")]
    engine_runners!(sqlite_engine, Some(("sqlite::memory:".to_owned(), "sqlite::memory:".to_owned())),
        (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone()) as bodies::Pick<crate::store::sqlite::SqliteBackend>);
    #[cfg(feature = "postgres")]
    engine_runners!(postgres_engine, (|| Some((crate::test_pg::empty_dsn()?, crate::test_pg::empty_dsn()?)))(),
        (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone()) as bodies::Pick<crate::store::postgres::PostgresBackend>);
}
