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
//! `identity:occurrence` door. **I382 is deleted** (round 3): its premise is a
//! node's ENGINE key provisioned as an occurrence of its owner (a person) and
//! named as `self_at_login`'s `app`. CC rc21 3.3.6 (way (d)) refuses a machine
//! key under a person (`occurrence_mixes_person_and_machine`): a node's human
//! is its owner binding, which I381 witnesses.

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
    /// door refuses `occurrence_mixes_person_and_machine`): a NODE key is never
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
        // v62.0.0 (round 3) — K2's shared helper lands the node's voice too.
        crate::federation::tier_ingest::test_support::put_owner_binding(d, &owner_s, &node_s).await;
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
}
