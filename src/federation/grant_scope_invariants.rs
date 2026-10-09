//! v54.0.0 (CIRISPersist#1033, CC 2.4.1.2.1 / CC 4.4.3.4.3) — **the `grant`
//! scope admits its holder.**
//!
//! CC 2.4.1.2.1: an onward grant is "a new grant issued by the asset's owner or
//! steward, or by a holder of a `grant`-scoped delegation from them", and a
//! substrate MUST refuse one whose issuer is neither. Persist shipped the
//! refusal and not the positive arm: `DELEGATION_SCOPE_GRANT` was declared and
//! no gate read it, so a legitimate `grant` delegate was refused.
//!
//! - **I561** (memory, sqlite, postgres) — consent. A machine naming a person
//!   in `for_key_id` is refused `consent_for_key_not_delegated`, still refused
//!   under a non-`grant` delegation, ADMITTED under a live `grant` chain from
//!   that person (a `consent:replication` grant and a `consent:state` row),
//!   refused again once the edge is withdrawn, refused under an expired edge,
//!   and refused when the chain is rooted at a machine.
//! - **I561b** (sqlite, postgres) — `key_grant`, content axis: a key that is
//!   neither the author nor an occurrence of them is `signer_not_author`;
//!   still so under a `moderate` delegation; admitted and PROJECTED under the
//!   author's `grant` delegation; refused again once it is withdrawn.
//! - **I561c** (sqlite, postgres) — `key_grant`, epoch axis on a two-node
//!   pair: a member signing the minter's counter is `signer_not_minter`;
//!   admitted and projected under the minter's `grant` delegation; refused
//!   again once it is withdrawn. Memory has no blob store, so it cannot host
//!   the `key_grant` door.

/// The consent body, generic over the directory.
#[cfg(test)]
pub mod bodies {
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::identity_type::{AGENT, NODE, USER};
    use crate::federation::types::{attestation_tier, attestation_type};
    use crate::federation::{
        admission, consent_by_humans as cbh, Attestation, Error, FederationDirectory,
        SignedAttestation,
    };

    /// A federation-tier row by `signer` (sealed with `seed`'s deterministic
    /// keys) — the crate's fixture shape.
    #[allow(clippy::too_many_arguments)]
    pub fn row(
        id: &str,
        signer: &str,
        seed: &str,
        target: &str,
        verb: &str,
        envelope: serde_json::Value,
        subject_key_ids: Vec<String>,
        at: chrono::DateTime<chrono::Utc>,
    ) -> Attestation {
        let mut r = Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: signer.to_owned(),
            attested_key_id: target.to_owned(),
            attestation_type: verb.to_owned(),
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
        };
        ts::seal_row_in_place(seed, &mut r);
        r
    }

    /// `delegates_to(granter → grantee)` carrying `scope`, sealed with
    /// `seed`'s keys; `expires_at` = `at + ttl` when `ttl` is set.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_delegation(
        d: &dyn FederationDirectory,
        granter: &str,
        seed: &str,
        grantee: &str,
        scope: &str,
        at: chrono::DateTime<chrono::Utc>,
        ttl: Option<chrono::Duration>,
    ) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut r = row(
            &id,
            granter,
            seed,
            grantee,
            attestation_type::DELEGATES_TO,
            serde_json::json!({ "id": id, "kind": "delegates_to", "scope": [scope], "sub_delegation": false }),
            Vec::new(),
            admission::truncate_to_substrate_resolution(at),
        );
        r.expires_at = ttl.map(|t| r.asserted_at + t);
        ts::seal_row_in_place(seed, &mut r);
        d.put_attestation(SignedAttestation { attestation: r })
            .await
            .unwrap_or_else(|e| panic!("delegates_to({granter} → {grantee}, {scope}): {e}"));
        id
    }

    /// The granter withdraws the edge `target` by name.
    pub async fn withdraw(
        d: &dyn FederationDirectory,
        granter: &str,
        seed: &str,
        grantee: &str,
        target: &str,
    ) {
        let id = uuid::Uuid::new_v4().to_string();
        let r = row(
            &id,
            granter,
            seed,
            grantee,
            attestation_type::WITHDRAWS,
            serde_json::json!({ "id": id, "references_attestation_id": target }),
            Vec::new(),
            admission::truncate_to_substrate_resolution(chrono::Utc::now()),
        );
        d.put_attestation(SignedAttestation { attestation: r })
            .await
            .unwrap_or_else(|e| panic!("withdraws {target}: {e}"));
    }

    /// A `consent:replication:v1` grant by `author` FOR `for_key` — #857's
    /// shape.
    fn replication_grant(id: &str, author: &str, for_key: &str) -> Attestation {
        let payload = serde_json::json!({
            "grants": "replication",
            "attestation_prefixes": ["i561-fixture:"],
            cbh::FOR_KEY_ID: for_key,
        });
        row(
            id,
            author,
            author,
            author,
            attestation_type::SCORES,
            serde_json::json!({ "dimension": crate::federation::consent_peer_set::DIMENSION, "payload": payload }),
            vec!["i561-peer".to_owned()],
            chrono::Utc::now(),
        )
    }

    /// A `consent:state:granted:v1` row by `author` about `target`, FOR
    /// `for_key`, scope `analyze` — the scoped consent shape.
    fn state_grant(id: &str, author: &str, target: &str, for_key: &str) -> Attestation {
        let at = admission::truncate_to_substrate_resolution(chrono::Utc::now());
        row(
            id,
            author,
            author,
            target,
            attestation_type::SCORES,
            serde_json::json!({
                "id": id,
                "dimension": "consent:state:granted:v1",
                "scope": "analyze",
                crate::federation::envelope::paths::ASSERTED_AT: at.to_rfc3339(),
                cbh::FOR_KEY_ID: for_key,
            }),
            Vec::new(),
            at,
        )
    }

    async fn put(d: &dyn FederationDirectory, a: Attestation) -> Result<(), Error> {
        d.put_attestation(SignedAttestation { attestation: a })
            .await
            .map(|_| ())
    }

    fn assert_not_delegated(r: Result<(), Error>, what: &str) {
        match r {
            Err(Error::InvalidArgument(m))
                if m.starts_with(admission::CONSENT_FOR_KEY_NOT_DELEGATED) => {}
            other => panic!(
                "{what}: expected {}, got {other:?}",
                admission::CONSENT_FOR_KEY_NOT_DELEGATED
            ),
        }
    }

    /// **I561** — see the module doc.
    pub async fn i561_consent_grant_scope(d: &dyn FederationDirectory, s: &str) {
        let k = |n: &str| format!("i561-{n}-{s}");
        let (alice, m, o, n) = (k("alice"), k("m"), k("o"), k("n"));
        ts::register_identity_key(d, &alice, USER).await;
        ts::register_identity_key(d, &m, AGENT).await;
        ts::register_identity_key(d, &o, AGENT).await;
        ts::register_identity_key(d, &n, NODE).await;
        let now = chrono::Utc::now();

        // (1) no delegation: the existing refusal, now by name.
        assert_not_delegated(
            put(d, replication_grant(&k("g1"), &m, &alice)).await,
            "(1) a machine naming a person with no delegation",
        );
        // (2) a non-`grant` scope confers nothing here.
        put_delegation(
            d,
            &alice,
            &alice,
            &m,
            admission::DELEGATION_SCOPE_MODERATE,
            now,
            None,
        )
        .await;
        assert_not_delegated(
            put(d, replication_grant(&k("g2"), &m, &alice)).await,
            "(2) a `moderate` delegation is not a `grant` delegation",
        );
        // (3) THE POSITIVE ARM: alice delegates `grant` to m.
        let edge = put_delegation(
            d,
            &alice,
            &alice,
            &m,
            admission::DELEGATION_SCOPE_GRANT,
            now,
            None,
        )
        .await;
        put(d, replication_grant(&k("g3"), &m, &alice))
            .await
            .expect("(3) a `grant` delegate may issue a consent grant over the person's data");
        put(d, state_grant(&k("s3"), &m, &o, &alice))
            .await
            .expect("(3) …and a scoped consent:state row");
        // (4) withdrawn: the chain is no longer live.
        withdraw(d, &alice, &alice, &m, &edge).await;
        assert_not_delegated(
            put(d, replication_grant(&k("g4"), &m, &alice)).await,
            "(4) a withdrawn `grant` delegation confers nothing",
        );
        // (5) expired an hour ago.
        put_delegation(
            d,
            &alice,
            &alice,
            &o,
            admission::DELEGATION_SCOPE_GRANT,
            now - chrono::Duration::hours(2),
            Some(chrono::Duration::hours(1)),
        )
        .await;
        assert_not_delegated(
            put(d, replication_grant(&k("g5"), &o, &alice)).await,
            "(5) an expired `grant` delegation confers nothing",
        );
        // (6) a chain rooted at a MACHINE: consent stays by humans.
        put_delegation(d, &n, &n, &m, admission::DELEGATION_SCOPE_GRANT, now, None).await;
        assert_not_delegated(
            put(d, replication_grant(&k("g6"), &m, &n)).await,
            "(6) a `grant` chain from a node is one machine consenting for another",
        );
    }
}

/// The `key_grant` exercises, generic over a blob-capable backend.
#[cfg(all(test, any(feature = "postgres", feature = "sqlite")))]
pub mod key_grant_arms {
    use super::bodies::{put_delegation, withdraw};
    use crate::federation::admission::{DELEGATION_SCOPE_GRANT, DELEGATION_SCOPE_MODERATE};
    use crate::federation::at_rest_cascade::blob_invariants::node_signer;
    use crate::federation::community_dek::orchestrate::encrypt_and_cascade_community;
    use crate::federation::key_grant::{admit_replicated_key_grant, KeyGrantAxis, KeyGrantSet};
    use crate::federation::key_grant_invariants::two_node::{
        seed_community_everywhere, sign_set_unstored, Node,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::cohort_scope::SELF;
    use crate::federation::types::identity_type::USER;
    use crate::federation::{BlobStorage, Error, FederationDirectory, GrantWrap};

    fn reason(r: &Result<crate::federation::key_grant::KeyGrantAdmission, Error>) -> &'static str {
        match r {
            Err(Error::KeyGrantRefused { reason, .. }) => reason,
            Err(e) => panic!("expected a typed KeyGrantRefused, got {e:?}"),
            Ok(a) => panic!("expected a refusal, the set was admitted: {a:?}"),
        }
    }

    fn wrap(recipient: &str) -> GrantWrap {
        GrantWrap {
            recipient_key_id: recipient.to_owned(),
            wrap_algorithm: crate::federation::at_rest_cascade::WRAP_ALGORITHM_V2.into(),
            wrapped_dek: "{}".into(),
        }
    }

    /// **I561b** — the content axis, one node.
    pub async fn exercise_i561b_content_axis<B>(a: &Node<'_, B>, tag: &str)
    where
        B: BlobStorage + FederationDirectory + Sync,
    {
        use crate::federation::at_rest_cascade::orchestrate::encrypt_and_cascade;
        let run = uuid::Uuid::new_v4().simple().to_string();
        let owner = format!("{tag}-owner-{run}");
        ts::register_hybrid_key_as(a.backend, &owner, &owner, USER).await;
        a.backend
            .put_identity_occurrence_local(crate::federation::types::IdentityOccurrence {
                identity_key_id: owner.clone(),
                occurrence_key_id: a.key.clone(),
                device_class: crate::federation::types::device_class::LAPTOP.into(),
                hardware_attestation: None,
                asserted_at: chrono::Utc::now(),
                valid_until: None,
                encryption_pubkeys: Some(a.kem.clone()),
                transport_binding: None,
                persist_row_hash: String::new(),
            })
            .await
            .unwrap();
        let sealed = encrypt_and_cascade(
            a.backend,
            SELF,
            &owner,
            b"the ledger",
            None,
            None,
            Some(&a.key),
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I561b: A seals self: {e}"));
        let sha = sealed.at_rest_sha256;
        // The delegate: a registered key that is neither the author nor one
        // of the author's occurrences.
        let d_alias = format!("{tag}-delegate-{run}");
        let delegate = node_signer(a.backend, &d_alias).await;
        let d_key = delegate.derived_key_id();
        let set_for = |recipient: &str| KeyGrantSet {
            axis: KeyGrantAxis::Content {
                at_rest_sha256: hex::encode(sha),
                cohort_scope: SELF.into(),
                owner_key_id: owner.clone(),
            },
            wraps: vec![wrap(recipient)],
        };
        let r1 = format!("{tag}-r1-{run}");
        let r = admit_replicated_key_grant(
            a.backend,
            sign_set_unstored(&delegate, &set_for(&r1)).await,
        )
        .await;
        assert_eq!(
            reason(&r),
            "signer_not_author",
            "{tag} I561b (1): no delegation"
        );

        let dir = a.backend.as_dyn_directory();
        let now = chrono::Utc::now();
        put_delegation(
            dir,
            &owner,
            &owner,
            &d_key,
            DELEGATION_SCOPE_MODERATE,
            now,
            None,
        )
        .await;
        let r = admit_replicated_key_grant(
            a.backend,
            sign_set_unstored(&delegate, &set_for(&r1)).await,
        )
        .await;
        assert_eq!(
            reason(&r),
            "signer_not_author",
            "{tag} I561b (2): `moderate` is not `grant`"
        );

        let edge = put_delegation(
            dir,
            &owner,
            &owner,
            &d_key,
            DELEGATION_SCOPE_GRANT,
            now,
            None,
        )
        .await;
        let admitted = admit_replicated_key_grant(
            a.backend,
            sign_set_unstored(&delegate, &set_for(&r1)).await,
        )
        .await
        .unwrap_or_else(|e| panic!("{tag} I561b (3): the author's `grant` delegate: {e}"));
        assert!(
            !admitted.pending && admitted.wraps_written == 1,
            "{tag} I561b (3): admitted AND projected: {admitted:?}"
        );
        assert!(
            a.backend
                .get_at_rest_grant(&sha, &r1)
                .await
                .unwrap()
                .is_some(),
            "{tag} I561b (3): the onward recipient holds a grant row"
        );

        withdraw(dir, &owner, &owner, &d_key, &edge).await;
        let r2 = format!("{tag}-r2-{run}");
        let r = admit_replicated_key_grant(
            a.backend,
            sign_set_unstored(&delegate, &set_for(&r2)).await,
        )
        .await;
        assert_eq!(
            reason(&r),
            "signer_not_author",
            "{tag} I561b (4): withdrawn"
        );
        assert!(
            a.backend
                .get_at_rest_grant(&sha, &r2)
                .await
                .unwrap()
                .is_none(),
            "{tag} I561b (4): a refused set projects nothing"
        );
    }

    /// **I561c** — the epoch axis, two nodes: B admits sets for A's counter.
    pub async fn exercise_i561c_epoch_axis<B>(
        a: &Node<'_, B>,
        a_alias: &str,
        b: &Node<'_, B>,
        tag: &str,
    ) where
        B: BlobStorage + FederationDirectory + Sync,
    {
        let run = uuid::Uuid::new_v4().simple().to_string();
        let comm = format!("{tag}-comm-{run}");
        let alice = format!("{tag}-alice-{run}");
        let bob = format!("{tag}-bob-{run}");
        seed_community_everywhere(&[a, b], &comm, &[(&alice, Some(a)), (&bob, Some(b))]).await;
        encrypt_and_cascade_community(a.backend, &comm, b"minutes", None, Some(&a.key))
            .await
            .unwrap_or_else(|e| panic!("{tag} I561c: A seals: {e}"));
        let honest = crate::federation::key_grant::build_epoch_set(a.backend, &comm, &a.key, 0)
            .await
            .unwrap()
            .expect("A holds wraps for (C, A, 0)");
        let set_for = |recipient: &str| KeyGrantSet {
            axis: honest.axis.clone(),
            wraps: vec![wrap(recipient)],
        };
        let r1 = format!("{tag}-r1-{run}");
        // (1) B's own member occurrence signs A's counter: not the minter.
        let r = admit_replicated_key_grant(
            b.backend,
            sign_set_unstored(&b.signer, &set_for(&r1)).await,
        )
        .await;
        assert_eq!(
            reason(&r),
            "signer_not_minter",
            "{tag} I561c (1): no delegation"
        );

        let dir = b.backend.as_dyn_directory();
        let now = chrono::Utc::now();
        put_delegation(
            dir,
            &a.key,
            a_alias,
            &b.key,
            DELEGATION_SCOPE_MODERATE,
            now,
            None,
        )
        .await;
        let r = admit_replicated_key_grant(
            b.backend,
            sign_set_unstored(&b.signer, &set_for(&r1)).await,
        )
        .await;
        assert_eq!(
            reason(&r),
            "signer_not_minter",
            "{tag} I561c (2): `moderate` is not `grant`"
        );

        let edge = put_delegation(
            dir,
            &a.key,
            a_alias,
            &b.key,
            DELEGATION_SCOPE_GRANT,
            now,
            None,
        )
        .await;
        admit_replicated_key_grant(b.backend, sign_set_unstored(&b.signer, &set_for(&r1)).await)
            .await
            .unwrap_or_else(|e| panic!("{tag} I561c (3): the minter's `grant` delegate: {e}"));
        assert!(
            b.backend
                .community_dek_has_member_grant(&comm, &a.key, 0, &r1)
                .await
                .unwrap(),
            "{tag} I561c (3): the onward recipient holds a grant on (C, A, 0)"
        );

        withdraw(dir, &a.key, a_alias, &b.key, &edge).await;
        let r2 = format!("{tag}-r2-{run}");
        let r = admit_replicated_key_grant(
            b.backend,
            sign_set_unstored(&b.signer, &set_for(&r2)).await,
        )
        .await;
        assert_eq!(
            reason(&r),
            "signer_not_minter",
            "{tag} I561c (4): withdrawn"
        );
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
                #[tokio::test(flavor = "multi_thread")]
                async fn i561() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i561_consent_grant_scope(
                        &d as &dyn FederationDirectory,
                        &super::suffix(),
                    )
                    .await
                }
            }
        };
    }

    runners!(memory_dyn, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    runners!(sqlite_dyn, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    runners!(postgres_dyn, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "sqlite")]
    mod sqlite_key_grant {
        use super::super::key_grant_arms::*;
        use crate::federation::key_grant_invariants::two_node::{introduce, node};
        use crate::store::sqlite::SqliteBackend;
        use crate::store::Backend as _;

        async fn fresh() -> SqliteBackend {
            let b = SqliteBackend::open_in_memory().await.unwrap();
            b.run_migrations().await.unwrap();
            b
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn i561b() {
            let ba = fresh().await;
            let a = node(&ba, "i561b-a").await;
            exercise_i561b_content_axis(&a, "sqlite").await;
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn i561c() {
            let (ba, bb) = (fresh().await, fresh().await);
            let a = node(&ba, "i561c-a").await;
            let b = node(&bb, "i561c-b").await;
            introduce(&[&a, &b], &["i561c-a", "i561c-b"]).await;
            exercise_i561c_epoch_axis(&a, "i561c-a", &b, "sqlite").await;
        }
    }

    #[cfg(feature = "postgres")]
    mod postgres_key_grant {
        use super::super::key_grant_arms::*;
        use crate::federation::key_grant_invariants::two_node::{introduce, node};
        use crate::store::postgres::PostgresBackend;
        use crate::store::Backend as _;

        async fn fresh() -> Option<PostgresBackend> {
            let dsn = crate::test_pg::empty_dsn()?;
            let b = PostgresBackend::connect(&dsn).await.unwrap();
            b.run_migrations().await.unwrap();
            Some(b)
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn i561b() {
            let Some(ba) = fresh().await else { return };
            let a = node(&ba, "i561b-a").await;
            exercise_i561b_content_axis(&a, "postgres").await;
        }

        #[tokio::test(flavor = "multi_thread")]
        async fn i561c() {
            let (Some(ba), Some(bb)) = (fresh().await, fresh().await) else {
                return;
            };
            let a = node(&ba, "i561c-a").await;
            let b = node(&bb, "i561c-b").await;
            introduce(&[&a, &b], &["i561c-a", "i561c-b"]).await;
            exercise_i561c_epoch_axis(&a, "i561c-a", &b, "postgres").await;
        }
    }
}
