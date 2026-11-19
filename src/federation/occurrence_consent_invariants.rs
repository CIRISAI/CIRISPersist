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
//!
//! v62.0.0 (flip wave 2, slice E6) — I381 runs on O1's edition-2
//! `identity:occurrence` door (two voices per bind); I382 runs the Engine's
//! own producers (`publish_signed_content_only_occurrence`, `self_at_login`),
//! edition 2 since cut B.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    //! v62.0.0 (flip wave 2, slice E6; O1's `identity:occurrence` door) — an
    //! occurrence bind is two voices over one payload: the occurrence key's
    //! OWN statement first, then the identity's (the author's). Keys are
    //! edition-2 `key:record`s named by kid; rows are now-relative.
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::types::identity_type as it;
    use crate::federation::FederationDirectory;

    fn now_ms() -> u64 {
        u64::try_from(chrono::Utc::now().timestamp_millis()).expect("after the epoch")
    }

    /// The two voices of an `identity:occurrence` bind of the key of
    /// `occurrence_seed` to the identity of `identity_seed` (O1, CC 3.3.6):
    /// `[the occurrence key's own statement, the identity's statement]`, in
    /// the order a node admits them, naming the identity's current roster
    /// head by `refs.head` (required, CC 3.3.6.4). Delegates to O1's
    /// `fixture_occurrence::occurrence_bind_voices`.
    pub(crate) async fn bind_voices(
        d: &dyn FederationDirectory,
        identity_seed: &str,
        occurrence_seed: &str,
        device_class: &str,
        asserted_at_ms: u64,
    ) -> Vec<Vec<u8>> {
        let (head, further_heads) = crate::federation::edition2::occurrence::current_roster_heads(
            d,
            &e2::kid(identity_seed),
        )
        .await
        .expect("the identity's roster heads read")
        .map_or((None, Vec::new()), |(h, f)| (Some(h), f));
        e2::occurrence_bind_voices(
            identity_seed,
            identity_seed,
            occurrence_seed,
            device_class,
            &e2::BindOptions {
                asserted_at_ms,
                head,
                further_heads,
                ..Default::default()
            },
        )
    }

    /// Put both voices of a bind, in order: O1's `put_bind` (the identity
    /// authors; `refs.head` = the identity's current roster head).
    pub(crate) async fn put_bind(
        d: &dyn FederationDirectory,
        identity_seed: &str,
        occurrence_seed: &str,
        device_class: &str,
        asserted_at_ms: u64,
    ) {
        Box::pin(e2::put_bind(
            d,
            identity_seed,
            identity_seed,
            occurrence_seed,
            device_class,
            &e2::BindOptions {
                asserted_at_ms,
                ..Default::default()
            },
        ))
        .await
        .expect("an occurrence bind voice is admitted");
    }

    /// **I381** — re-asserting the occurrence does not demote the binding:
    /// the node's principal stands. v62.0.0 (CC rc21 3.3.6, way (d); the
    /// door refuses `occurrence_binds_machine_to_person`): a NODE key is never
    /// an occurrence of a person. The user OWNS the node through an owner
    /// binding (the owner's statement plus the node's voice), and the node
    /// carries its OWN self-occurrence `(node, node)` (O1 `put_bind`, naming
    /// its roster head). The node re-asserts that self-occurrence; the owner,
    /// read through the owner relation, stays the node's principal.
    pub(crate) async fn i381_re_signing_keeps_the_principal(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (owner_s, node_s) = (format!("owner-{tag}"), format!("node-{tag}"));
        let owner = e2::put_key(d, &owner_s, &[it::USER]).await;
        let node = e2::put_key(d, &node_s, &[it::NODE]).await;
        // The provisioning shape: the owner binds the node (with the node's
        // own voice, `ownership:*`'s second signer).
        let ob = crate::federation::tier_ingest::test_support::owner_binding_attestation(
            &format!("bind-{tag}"),
            &owner_s,
            &node_s,
        );
        let ob_st = e2::carried_statement(&ob).expect("an edition-2 owner binding");
        e2::put_signed(d, &ob)
            .await
            .expect("I381 the owner-binding is admitted");
        e2::put_statement(d, &e2::voice_of(&ob_st, &node_s))
            .await
            .expect("I381 the node's voice on its owner binding");
        // The node's own self-occurrence: it says WHAT KIND it is; its owner
        // says WHO.
        let self_bind = |at: u64| e2::BindOptions {
            asserted_at_ms: at,
            ..Default::default()
        };
        let t = now_ms();
        Box::pin(e2::put_bind(
            d,
            &node_s,
            &node_s,
            &node_s,
            "server",
            &self_bind(t - 30_000),
        ))
        .await
        .expect("I381 the node's self-occurrence lands");
        assert_eq!(
            crate::federation::admission::owner_of(d, &node)
                .await
                .unwrap(),
            Some(owner.clone()),
            "I381 precondition — the owner binding names the node's human"
        );
        assert!(
            crate::federation::self_collective::principals_of(d, &node)
                .await
                .unwrap()
                .contains(&owner),
            "I381 precondition — the owner is the node's principal"
        );

        // The node re-asserts its self-occurrence.
        Box::pin(e2::put_bind(
            d,
            &node_s,
            &node_s,
            &node_s,
            "server",
            &self_bind(t - 10_000),
        ))
        .await
        .expect("I381 the re-asserted self-occurrence lands");
        assert!(
            d.list_identity_occurrences_for(&node)
                .await
                .unwrap()
                .iter()
                .any(|o| o.occurrence_key_id == node),
            "I381 the self-occurrence is held"
        );
        assert_eq!(
            crate::federation::admission::owner_of(d, &node)
                .await
                .unwrap(),
            Some(owner.clone()),
            "I381 the re-assertion keeps the owner"
        );
        assert!(
            crate::federation::self_collective::principals_of(d, &node)
                .await
                .unwrap()
                .contains(&owner),
            "I381 the re-assertion keeps the principal"
        );
    }

    /// The control (#932 kept): an identity's claim the occurrence never
    /// agreed to resolves nothing. v62.0.0: the identity's statement with no
    /// statement of the occurrence key's own is refused (retryable, O1 I3022)
    /// and binds nothing, however many times it is offered.
    pub(crate) async fn i381_an_unagreed_claim_still_resolves_nothing(
        d: &dyn FederationDirectory,
        tag: &str,
    ) {
        let (owner_s, phone_s) = (format!("owner-{tag}"), format!("phone-{tag}"));
        e2::put_key(d, &owner_s, &[it::USER]).await;
        let phone = e2::put_key(d, &phone_s, &[it::USER]).await;
        let t = now_ms();
        for at in [t - 20_000, t - 10_000] {
            let voices = bind_voices(d, &owner_s, &phone_s, "phone", at).await;
            let by_owner = voices.last().expect("the owner's voice").clone();
            let e = Box::pin(e2::put_statement(d, &by_owner))
                .await
                .expect_err("I381 control — the identity's claim alone binds nothing");
            assert_eq!(
                e.kind(),
                "federation_attester_key_unknown",
                "I381 control — retryable, waiting on the occurrence's own voice: {e}"
            );
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
            .register_self_federation_key(it::NODE, None, None)
            .await
            .expect("register the engine key");
        let n = engine.local_derived_key_id().await.unwrap();
        let b = pick(&engine);
        // v62.0.0 — edition-2 keys (`kid(seed)`); each LocalSigner signs as
        // the kid of its alias.
        let o_alias = format!("o382-the-owner-of-the-engine-node-{tag}");
        let o_signer = ts::local_signer(&o_alias);
        let o =
            crate::federation::edition2::fixture_switch::put_key(b.as_ref(), &o_alias, &[it::USER])
                .await;
        let agent = crate::federation::edition2::fixture_switch::put_key(
            b.as_ref(),
            &format!("ag382-the-agent-occurrence-key-{tag}"),
            &[it::AGENT],
        )
        .await;

        // provision_engine_occurrence: the owner binds N, claims it, N agrees.
        {
            use crate::federation::edition2::fixture_switch as e2;
            let ob = ts::owner_binding_attestation(&format!("bind382-{tag}"), &o_alias, &n);
            let st = e2::carried_statement(&ob).expect("an edition-2 owner binding");
            e2::put_signed(b.as_ref(), &ob)
                .await
                .expect("I382 the owner-binding is admitted");
            e2::put_statement(b.as_ref(), &e2::voice_of(&st, &alias_n))
                .await
                .expect("I382 the node's voice on its owner binding");
        }
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
                identity_key_id: None,
                occurrence_signer: None,
                transport: None,
                device_class: device_class::SERVER.to_owned(),
                hardware_attestation: None,
                encryption_pubkeys: Some(app_keys),
                transport_destinations: vec![],
            },
            agent: SelfAtLoginOccurrence {
                occurrence_key_id: agent.clone(),
                identity_key_id: None,
                occurrence_signer: None,
                transport: None,
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
        // v62.0.0 — O1's signed listing serves edition-2 binds (carrying
        // their statements; O1 I3034): the pair's current row is the
        // identity's, and the occurrence's agreement lives in the history.
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

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
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
        Box::pin(
            super::engine_bodies::i382_self_at_login_keeps_the_engine_occurrence(
                "sqlite::memory:",
                &suffix(),
                (|e: &crate::Engine| e.sqlite_backend().expect("sqlite").clone())
                    as crate::federation::epoch_minter_invariants::bodies::Pick<
                        crate::store::sqlite::SqliteBackend,
                    >,
            ),
        )
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i382_self_at_login_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        Box::pin(
            super::engine_bodies::i382_self_at_login_keeps_the_engine_occurrence(
                &dsn,
                &suffix(),
                (|e: &crate::Engine| e.postgres_backend().expect("postgres").clone())
                    as crate::federation::epoch_minter_invariants::bodies::Pick<
                        crate::store::postgres::PostgresBackend,
                    >,
            ),
        )
        .await;
    }
}
