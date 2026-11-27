//! v62.0.0 (GID-tips; CC 2.7.8 "two versions of one head wait as tips", the
//! convergent minimum the lead ruled for v62.0) — **a contested founding
//! concludes nothing.** sqlite and postgres, through the statement door.
//!
//! - **I5717** — two DISTINCT first versions under one derived id (the same
//!   founder, `founded_at` and nonce, two names: the founder signed two
//!   foundings): node A receives A then B, node B receives B then A. On both
//!   the group concludes nothing (`lookup_community` is `None`) and the later
//!   arrival is held `group_founding_contested`: the first un-concluded when
//!   the second arrived. The two nodes converge.
//! - **I5718** — a single founding lands (`Row`, a typed community under the
//!   derived id); re-delivering the SAME first version is idempotent (the
//!   same row id is no rival): the room stays concluded.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::fold;
    use crate::federation::edition2::group::{founding_payload, GroupRecord, GROUP_ROSTER_PREFIX};
    use crate::federation::edition2::ingest::StatementOutcome;
    use crate::federation::edition2::names::RowId;
    use crate::federation::types::{identity_type, Community, CommunityMember};
    use crate::federation::FederationDirectory;

    /// A first version of a one-founder community named `name`, founded at
    /// `at` (whole milliseconds) under `nonce`: its derived id and its
    /// statement, signed by `founder`'s seed.
    fn founding(
        founder: &str,
        name: &str,
        nonce: [u8; 32],
        at: chrono::DateTime<chrono::Utc>,
    ) -> (String, Vec<u8>) {
        let mut record = GroupRecord::Community(Community {
            prev_head_digest: String::new(),
            charter_digest: String::new(),
            community_key_id: String::new(),
            community_name: name.to_owned(),
            members: vec![CommunityMember {
                key_id: e2::kid(founder),
                joined_at: at,
                role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.into()),
            }],
            founded_at: at,
            consensus_protocol: "majority".into(),
            policy_blob: None,
            persist_row_hash: String::new(),
        });
        // The row's own instant is the test's clock seam; `founded_at` (an
        // input of the derived id) is the fixture base, never the clock.
        let asserted = e2::ms(instant());
        let (id, payload) =
            founding_payload(&mut record, &nonce, asserted).expect("the founding payload");
        let family = ciris_verify_core::namespace_match::family_id(GROUP_ROSTER_PREFIX);
        let st = ciris_verify_core::edition2::sign_row_statement(
            &e2::signing_key(founder),
            &e2::kid(founder),
            &id,
            "scores",
            &family,
            &payload,
            vec![],
        )
        .expect("sign the founding");
        (id, st)
    }

    /// GID-fixtures-mech.rev3 — the founding instant: the process's fixture
    /// base (`fixture_switch::fixture_founding_base_ms`, read once per
    /// process), never the clock: it is an input of the derived id.
    fn founded() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            i64::try_from(e2::fixture_founding_base_ms()).expect("ms"),
        )
        .expect("an instant")
    }

    /// An hour ago, in whole milliseconds: the founding ROW's `asserted_at`.
    fn instant() -> chrono::DateTime<chrono::Utc> {
        let ms = (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp_millis();
        chrono::DateTime::<chrono::Utc>::from_timestamp_millis(ms).expect("an instant")
    }

    async fn put(d: &dyn FederationDirectory, st: &[u8]) -> StatementOutcome {
        e2::put_statement(d, st)
            .await
            .unwrap_or_else(|e| panic!("a founding is kept or lands, never refused: {e}"))
    }

    async fn reason(d: &dyn FederationDirectory, st: &[u8]) -> Option<String> {
        let rid = RowId::of_statement(st).expect("a row id");
        fold::why_held(d, &rid)
            .await
            .expect("why_held")
            .map(|h| h.reason)
    }

    /// **I5717** — `a` and `b` are two nodes (fresh stores).
    pub(crate) async fn i5717_a_contested_founding_concludes_nothing(
        a: &dyn FederationDirectory,
        b: &dyn FederationDirectory,
        s: &str,
    ) {
        let founder = format!("i5717-founder-{s}");
        for d in [a, b] {
            e2::put_key(d, &founder, &[identity_type::USER]).await;
        }
        let nonce = [0x57; 32];
        let at = founded();
        let (id, first) = founding(&founder, "the first", nonce, at);
        let (id2, second) = founding(&founder, "the second", nonce, at);
        assert_eq!(
            id, id2,
            "I5717 premise: one derived id, two distinct foundings"
        );
        assert_ne!(first, second, "I5717 premise: two different statements");

        // Node A: first then second.
        assert!(
            matches!(put(a, &first).await, StatementOutcome::Row { .. }),
            "I5717 A: the first founding lands alone"
        );
        assert!(a.lookup_community(&id).await.unwrap().is_some());
        let _ = put(a, &second).await;
        assert!(
            a.lookup_community(&id).await.unwrap().is_none(),
            "I5717 A: the second founding un-concludes the first: the group concludes nothing"
        );
        assert_eq!(
            reason(a, &second).await.as_deref(),
            Some(fold::reason::GROUP_FOUNDING_CONTESTED),
            "I5717 A: the rival is held by name"
        );
        assert_eq!(
            reason(a, &first).await.as_deref(),
            Some(fold::reason::GROUP_FOUNDING_CONTESTED),
            "I5717 A: and so is the first, once contested"
        );

        // Node B: second then first.
        let _ = put(b, &second).await;
        let _ = put(b, &first).await;
        assert!(
            b.lookup_community(&id).await.unwrap().is_none(),
            "I5717 B: the other order also concludes nothing"
        );
        for st in [&first, &second] {
            assert_eq!(
                reason(b, st).await.as_deref(),
                Some(fold::reason::GROUP_FOUNDING_CONTESTED),
                "I5717 B: both foundings held by name"
            );
        }
    }

    /// **I5718** — a single founding, and its re-delivery.
    pub(crate) async fn i5718_a_single_founding_and_its_redelivery(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let founder = format!("i5718-founder-{s}");
        e2::put_key(d, &founder, &[identity_type::USER]).await;
        let (id, st) = founding(&founder, "alone", [0x58; 32], founded());
        assert!(
            matches!(put(d, &st).await, StatementOutcome::Row { .. }),
            "I5718: a single founding lands"
        );
        assert!(d.lookup_community(&id).await.unwrap().is_some());
        let _ = put(d, &st).await;
        assert!(
            d.lookup_community(&id).await.unwrap().is_some(),
            "I5718: re-delivering the same first version is no rival"
        );
        assert_eq!(reason(d, &st).await, None, "I5718: not held");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    #[cfg(feature = "sqlite")]
    async fn sqlite() -> crate::store::sqlite::SqliteBackend {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        b
    }

    #[cfg(feature = "postgres")]
    async fn postgres() -> Option<crate::store::postgres::PostgresBackend> {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i5717_a_contested_founding_concludes_nothing_sqlite() {
        let (a, b) = (sqlite().await, sqlite().await);
        Box::pin(super::bodies::i5717_a_contested_founding_concludes_nothing(
            &a,
            &b,
            &suffix(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i5717_a_contested_founding_concludes_nothing_postgres() {
        let (Some(a), Some(b)) = (postgres().await, postgres().await) else {
            return;
        };
        Box::pin(super::bodies::i5717_a_contested_founding_concludes_nothing(
            &a,
            &b,
            &suffix(),
        ))
        .await;
        eprintln!("i5717 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i5718_a_single_founding_and_its_redelivery_sqlite() {
        let d = sqlite().await;
        Box::pin(super::bodies::i5718_a_single_founding_and_its_redelivery(
            &d,
            &suffix(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i5718_a_single_founding_and_its_redelivery_postgres() {
        let Some(d) = postgres().await else {
            return;
        };
        Box::pin(super::bodies::i5718_a_single_founding_and_its_redelivery(
            &d,
            &suffix(),
        ))
        .await;
        eprintln!("i5718 postgres: RAN");
    }
}
