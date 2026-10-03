//! v53.0.0 (CIRISPersist#965) — **an occurrence's consent is not erased by
//! the identity re-signing the pair.**
//!
//! `federation_identity_occurrences` is keyed `(identity_key_id,
//! occurrence_key_id)` and last-signed-wins, and the #932 resolver read the
//! occurrence's agreement off that CURRENT row. So a newer identity-signed row
//! over the row the occurrence itself signed (`self_at_login` naming a node's
//! own engine occurrence as `app`) made the binding resolve nothing: the node
//! stopped being party to its owner's rooms, which surfaced far away as
//! `NotPartyTo` on unrelated content (CIRISEdge#768). The V161 history (#930)
//! already held the agreement, and I271 already said the re-signing does not
//! erase it; the resolver now reads it from there.
//!
//! - **I381** (every backend) — after the identity re-signs a consented pair,
//!   `active_identities_for_occurrence` still names the owner; an identity's
//!   claim the occurrence never agreed to still resolves nothing (#932).
//! - **I382** (sqlite, postgres) — the issue's shape end to end: provision the
//!   engine occurrence, run `self_at_login` with `app` = the engine key, and
//!   the owner is still the node's principal.

#[cfg(test)]
pub(crate) mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type as it;
    use crate::federation::FederationDirectory;

    fn ago(secs: i64) -> chrono::DateTime<chrono::Utc> {
        let t = chrono::Utc::now() - chrono::Duration::seconds(secs);
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(t.timestamp_millis()).expect("ms")
    }

    /// **I381** — the identity re-signing does not demote the binding.
    pub(crate) async fn i381_re_signing_keeps_the_principal(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let owner = format!("owner-{tag}");
        let node = format!("node-{tag}");
        ts::register_hybrid_key_as(d, &owner, &owner, it::USER).await;
        ts::register_hybrid_key_as(d, &node, &node, it::NODE).await;
        // The provisioning shape: the owner binds the node, claims it, and the
        // occurrence agrees (a node signs its own occurrence through the lift).
        d.put_attestation(crate::federation::SignedAttestation {
            attestation: ts::owner_binding_attestation(&format!("bind-{tag}"), &owner, &node),
        })
        .await
        .expect("I381 the owner-binding is admitted");
        d.put_identity_occurrence(
            ts::signed_content_only_occurrence(&owner, &owner, &node, ago(30)).await,
        )
        .await
        .expect("I381 the identity's claim is admitted");
        d.put_identity_occurrence(
            ts::signed_content_only_occurrence(&node, &owner, &node, ago(20)).await,
        )
        .await
        .expect("I381 the occurrence's agreement is admitted");
        assert_eq!(
            d.active_identities_for_occurrence(&node).await.unwrap(),
            vec![owner.clone()],
            "I381 precondition — the occurrence's consent resolves the owner"
        );

        // The identity re-signs the pair: the current row is now its own, the
        // occurrence's row is history.
        d.put_identity_occurrence(
            ts::signed_content_only_occurrence(&owner, &owner, &node, ago(10)).await,
        )
        .await
        .expect("I381 the identity's re-signing is admitted (I271)");
        let current = d
            .list_signed_identity_occurrences_for(&owner)
            .await
            .unwrap()
            .into_iter()
            .find(|r| r.identity_occurrence.occurrence_key_id == node)
            .expect("I381 the pair's current row");
        assert_eq!(
            current.attesting_key_id, owner,
            "I381 precondition — the current row is the identity's"
        );
        assert_eq!(
            d.active_identities_for_occurrence(&node).await.unwrap(),
            vec![owner.clone()],
            "I381 the occurrence's agreement survives the identity's re-signing"
        );
    }

    /// The control (#932 kept): an identity's claims the occurrence never
    /// agreed to resolve nothing, however many times the identity re-signs.
    pub(crate) async fn i381_an_unagreed_claim_still_resolves_nothing(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let owner = format!("owner-{tag}");
        let phone = format!("phone-{tag}");
        ts::register_hybrid_key_as(d, &owner, &owner, it::USER).await;
        ts::register_hybrid_key_as(d, &phone, &phone, it::USER).await;
        for t in [ago(20), ago(10)] {
            d.put_identity_occurrence(
                ts::signed_content_only_occurrence(&owner, &owner, &phone, t).await,
            )
            .await
            .expect("I381 control — the identity's claim is admitted");
        }
        assert!(
            d.active_identities_for_occurrence(&phone)
                .await
                .unwrap()
                .is_empty(),
            "I381 control — #932: a claim never agreed to is not a principal"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod engine_bodies {
    use crate::engine::{SelfAtLoginInput, SelfAtLoginOccurrence};
    use crate::federation::epoch_minter_invariants::bodies::Pick;
    use crate::federation::key_grant::publish_signed_content_only_occurrence;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{device_class, identity_type as it};
    use crate::federation::{BlobStorage, EncryptionPubkeys, FederationDirectory};
    use crate::Engine;

    fn fresh_keys() -> EncryptionPubkeys {
        use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
        let (_xp, x_pub, _mp, ml_pub) =
            crate::federation::identity_aggregate::mint_content_kem_keypair().expect("kem");
        EncryptionPubkeys {
            x25519_base64: B64.encode(x_pub),
            ml_kem_768_base64: B64.encode(ml_pub),
        }
    }

    /// **I382** — the issue's shape (CIRISEdge#768), end to end.
    pub(crate) async fn i382_self_at_login_keeps_the_engine_occurrence<B>(
        dsn: &str,
        tag: &str,
        pick: Pick<B>,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let alias_n = format!("n382-the-engine-occurrence-node-{tag}");
        let n_signer = ts::local_signer(&alias_n);
        let engine = Engine::with_signer_pre_genesis(n_signer.clone(), dsn)
            .await
            .unwrap();
        engine
            .register_self_federation_key(it::NODE, &alias_n, None, serde_json::json!({}), vec![])
            .await
            .expect("register the engine key");
        let n = engine.local_derived_key_id().await.unwrap();
        let b = pick(&engine);
        let o_signer = ts::local_signer(&format!("o382-the-owner-of-the-engine-node-{tag}"));
        let o = o_signer.derived_key_id();
        ts::register_hybrid_key_as(
            b.as_ref(),
            &o,
            &format!("o382-the-owner-of-the-engine-node-{tag}"),
            it::USER,
        )
        .await;
        let agent =
            ts::local_signer(&format!("ag382-the-agent-occurrence-key-{tag}")).derived_key_id();
        ts::register_hybrid_key_as(
            b.as_ref(),
            &agent,
            &format!("ag382-the-agent-occurrence-key-{tag}"),
            it::AGENT,
        )
        .await;

        // provision_engine_occurrence: the owner binds N, claims it, N agrees.
        b.put_attestation(crate::federation::SignedAttestation {
            attestation: ts::owner_binding_attestation(&format!("bind382-{tag}"), &o, &n),
        })
        .await
        .expect("I382 the owner-binding is admitted");
        let kem = b.load_or_init_content_kem_identity().await.unwrap();
        let enc = EncryptionPubkeys {
            x25519_base64: kem.x25519_pubkey_b64,
            ml_kem_768_base64: kem.ml_kem_768_pubkey_b64,
        };
        for signer in [&o_signer, &n_signer] {
            publish_signed_content_only_occurrence(
                b.as_ref(),
                signer,
                &o,
                &n,
                device_class::SERVER,
                None,
                enc.clone(),
                None,
            )
            .await
            .unwrap_or_else(|e| panic!("I382 provision ({}): {e}", signer.derived_key_id()));
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            b.active_identities_for_occurrence(&n).await.unwrap(),
            vec![o.clone()],
            "I382 precondition — N's own consent resolves O"
        );

        let input = |app_keys: EncryptionPubkeys, pair: &str| SelfAtLoginInput {
            identity_key_id: o.clone(),
            identity_signer: Some(o_signer.clone()),
            app: SelfAtLoginOccurrence {
                occurrence_key_id: n.clone(),
                device_class: device_class::SERVER.to_owned(),
                hardware_attestation: None,
                encryption_pubkeys: Some(app_keys),
                transport_destinations: vec![],
            },
            agent: SelfAtLoginOccurrence {
                occurrence_key_id: agent.clone(),
                device_class: device_class::AGENT.to_owned(),
                hardware_attestation: None,
                encryption_pubkeys: Some(fresh_keys()),
                transport_destinations: vec![],
            },
            bilateral_pair_id: pair.to_owned(),
            delegation_scope: None,
        };
        let outcome = engine
            .self_at_login(input(enc.clone(), &format!("p1-{tag}")))
            .await
            .expect("I382 self_at_login over the engine occurrence");
        assert!(
            b.active_identities_for_occurrence(&n)
                .await
                .unwrap()
                .contains(&o),
            "I382 the owner is still the node's principal after self_at_login"
        );
        assert!(
            outcome.occurrences_published.contains(&n),
            "I382 the ceremony published the app occurrence: {outcome:?}"
        );
        let stored = b
            .list_signed_identity_occurrences_for(&o)
            .await
            .unwrap()
            .into_iter()
            .find(|s| s.identity_occurrence.occurrence_key_id == n)
            .expect("I382 the (O, N) row");
        assert_eq!(
            stored.attesting_key_id, o,
            "I382 the mechanism — the current row is now the identity's; the \
             agreement lives in the history"
        );
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! dyn_runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                macro_rules! case {
                    ($name:ident) => {
                        #[tokio::test]
                        async fn $name() {
                            let Some(d) = $fresh.await else { return };
                            super::super::bodies::$name(
                                &d as &dyn FederationDirectory,
                                &format!("{}-{}", stringify!($name), suffix()),
                            )
                            .await
                        }
                    };
                }
                case!(i381_re_signing_keeps_the_principal);
                case!(i381_an_unagreed_claim_still_resolves_nothing);
            }
        };
    }

    dyn_runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    dyn_runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    dyn_runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i382_self_at_login_sqlite() {
        super::engine_bodies::i382_self_at_login_keeps_the_engine_occurrence(
            "sqlite::memory:",
            &suffix(),
            (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
                as crate::federation::epoch_minter_invariants::bodies::Pick<
                    crate::store::sqlite::SqliteBackend,
                >,
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i382_self_at_login_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        super::engine_bodies::i382_self_at_login_keeps_the_engine_occurrence(
            &dsn,
            &suffix(),
            (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
                as crate::federation::epoch_minter_invariants::bodies::Pick<
                    crate::store::postgres::PostgresBackend,
                >,
        )
        .await;
    }
}
