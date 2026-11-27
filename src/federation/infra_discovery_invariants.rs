//! v62.0.0 (R2-rooms-b2; Constitution 11-24: an infrastructure room has NO
//! listing. "Its birth row and roster rows, served by any node that holds the
//! room and itself reaches it, ARE the discovery") — **how a fresh node
//! learns an infrastructure room**. Two stores per run, every body on sqlite
//! and postgres.
//!
//! - **I6417** node A founds an infrastructure room whose founders are the
//!   holders of the bundle in force, and A reaches it. Node B is FRESH: its
//!   own node key, the bundle installed, the lineage accepted, and no row of
//!   the room. B pulls A's feed for B and takes it through its statement door
//!   (`ingest::put_statement`, the wire door). Everything but the room's
//!   roster voices is delivered first in A's order, then the roster voices in
//!   A's order (one store) and reversed (another). In both arrival orders B
//!   holds the room, and `admission::is_authorized_infrastructure_community`
//!   is true at B.
//! - **I6418** a founding that lists a NON-holder founder (a `user` key B
//!   holds), delivered to B in both orders, does not land. It is HELD
//!   `founder_not_conferred` (the one founder predicate, R2-rooms-b), and it
//!   is not reached.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod bodies {
    use crate::federation::canonical_community_invariants::bodies::{
        rooted_infrastructure_room_e2, SetNodeKey,
    };
    use crate::federation::edition2::fixture_genesis as fg;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::group::roster_view_of_statement;
    use crate::federation::types::identity_type;
    use crate::federation::FederationDirectory;

    /// The statements `from` serves to `requester`, every page.
    async fn served<B: FederationDirectory + Sync>(from: &B, requester: &str) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let page = crate::federation::edition2::serve::statements_served_to(
                from,
                cursor.as_ref(),
                256,
                Some(requester),
            )
            .await
            .expect("the serve feed reads");
            out.extend(page.statements.into_iter().map(|st| st.bytes));
            let Some(next) = page.next else { break };
            cursor = Some(next);
        }
        out
    }

    /// A fresh node B: its node key (`seed`), the bundle in force, its
    /// acceptance of the lineage (`rooted_trust_root`). No row of any room.
    async fn fresh_rooted<B>(b: &B, seed: &str)
    where
        B: FederationDirectory + SetNodeKey + Sync,
    {
        let node = e2::put_key(b, seed, &[identity_type::NODE]).await;
        b.set_node_key(node);
        let _ = crate::federation::edition2::fixture_trust_root::rooted_trust_root(
            b,
            &fg::HOLDER_SEEDS,
            "quorum:2/3",
        )
        .await;
    }

    /// Deliver `feed` to `to` through its wire door: every statement that is
    /// no roster voice first, in feed order, then the roster voices, in feed
    /// order or reversed. A statement `to` refuses is left, as a peer leaves
    /// it.
    async fn deliver<B: FederationDirectory + Sync>(to: &B, feed: &[Vec<u8>], reverse: bool) {
        let (mut roster, rest): (Vec<&Vec<u8>>, Vec<&Vec<u8>>) = feed
            .iter()
            .partition(|st| roster_view_of_statement(st).is_ok());
        if reverse {
            roster.reverse();
        }
        for st in rest.into_iter().chain(roster) {
            let _ = e2::put_statement(to, st).await;
        }
    }

    /// I6417.
    pub(crate) async fn served_birth_is_the_discovery<B>(a: &B, b1: &B, b2: &B, tag: &str)
    where
        B: FederationDirectory + SetNodeKey + Sync,
    {
        let room = rooted_infrastructure_room_e2(a, &format!("i6417-room-{tag}"), &[], tag).await;
        let held_a = a
            .lookup_community(&room)
            .await
            .expect("A reads")
            .expect("I6417 precondition: A holds the room");
        assert!(
            crate::federation::admission::is_authorized_infrastructure_community(a, &held_a)
                .await
                .expect("A reads"),
            "I6417 precondition: A reaches the room it serves"
        );
        for (b, reverse, which) in [(b1, false, "A's order"), (b2, true, "reversed")] {
            fresh_rooted(b, &format!("i6417-node-b-{tag}-{reverse}")).await;
            assert!(
                b.lookup_community(&room).await.expect("B reads").is_none(),
                "[{tag} {which}] I6417 precondition: B holds no row of the room"
            );
            let me = b.node_key_id().expect("B's node key");
            let feed = served(a, &me).await;
            assert!(
                feed.iter().any(|st| roster_view_of_statement(st).is_ok()),
                "[{tag} {which}] I6417: A serves the room's roster voices to a non-member"
            );
            deliver(b, &feed, reverse).await;
            let held = b
                .lookup_community(&room)
                .await
                .expect("B reads")
                .unwrap_or_else(|| panic!("[{tag} {which}] I6417: B admits the served birth"));
            assert!(
                crate::federation::admission::is_authorized_infrastructure_community(b, &held)
                    .await
                    .expect("B reads"),
                "[{tag} {which}] I6417: B reaches the room (its founders are holders of the \
                 bundle B holds, and B accepts the lineage)"
            );
        }
    }

    /// I6418.
    pub(crate) async fn non_holder_founder_is_held<B>(b1: &B, b2: &B, tag: &str)
    where
        B: FederationDirectory + SetNodeKey + Sync,
    {
        use crate::federation::edition2::group::GroupRecord;
        use crate::federation::edition2::group_fixtures as gf;
        use crate::federation::types::{Community, CommunityMember};
        for (b, reverse, which) in [(b1, false, "in order"), (b2, true, "reversed")] {
            fresh_rooted(b, &format!("i6418-node-b-{tag}-{reverse}")).await;
            let outsider_seed = format!("i6418-outsider-{tag}");
            let outsider = e2::put_key(b, &outsider_seed, &[identity_type::USER]).await;
            let room = e2::put_key(b, &format!("i6418-room-{tag}"), &[identity_type::USER]).await;
            let at = e2::ms(crate::host::clock::now());
            let joined = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
                i64::try_from(at).expect("ms") - 60_000,
            )
            .expect("an instant");
            let founder = |key_id: String| CommunityMember {
                key_id,
                joined_at: joined,
                role: Some(crate::federation::admission::MEMBER_ROLE_FOUNDER.to_owned()),
            };
            let record = Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: room.clone(),
                community_name: format!("infrastructure {tag}"),
                members: vec![
                    founder(fg::identity_ref_of(fg::HOLDER_SEEDS[0])),
                    founder(fg::identity_ref_of(fg::HOLDER_SEEDS[1])),
                    founder(outsider.clone()),
                ],
                founded_at: joined,
                consensus_protocol: "quorum:2/3".to_owned(),
                policy_blob: Some(serde_json::json!({
                    "cohort_subkind": crate::federation::canonical_community::COHORT_SUBKIND_INFRASTRUCTURE,
                    "cohort_subkind_payload": {
                        "infrastructure_constraint": {
                            "admission_quorum_basis":
                                crate::federation::canonical_community::ADMISSION_QUORUM_BASIS_FOUNDERS,
                        },
                    },
                    "consensus_protocol_entrenched": true,
                })),
                persist_row_hash: String::new(),
            };
            let (k0, k1) = (
                fg::test_key(fg::HOLDER_SEEDS[0]),
                fg::test_key(fg::HOLDER_SEEDS[1]),
            );
            let k2 = e2::signing_key(&outsider_seed);
            let mut voices = gf::roster_voices(
                &GroupRecord::Community(record),
                1,
                None,
                at,
                &[&k0, &k1, &k2],
            );
            if reverse {
                voices.reverse();
            }
            for v in &voices {
                let _ = e2::put_statement(b, v).await;
            }
            assert!(
                b.lookup_community(&room).await.expect("B reads").is_none(),
                "[{tag} {which}] I6418: a founding with a non-holder founder does not land"
            );
            let row = gf::row_id_of(&voices[0]);
            assert_eq!(
                crate::federation::edition2::fold::why_held(b, &row)
                    .await
                    .expect("why_held reads")
                    .map(|h| h.reason),
                Some(
                    crate::federation::edition2::fold::reason::gc8::FOUNDER_NOT_CONFERRED
                        .to_owned()
                ),
                "[{tag} {which}] I6418: HELD by the one founder predicate"
            );
        }
    }
}

#[cfg(feature = "sqlite")]
mod sqlite_runners {
    use crate::store::Backend as _;

    async fn fresh() -> crate::store::sqlite::SqliteBackend {
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .expect("sqlite");
        b.run_migrations().await.expect("migrations");
        b
    }

    #[tokio::test]
    async fn i6417_a_served_birth_is_the_discovery_sqlite() {
        let (a, b1, b2) = (fresh().await, fresh().await, fresh().await);
        Box::pin(super::bodies::served_birth_is_the_discovery(
            &a, &b1, &b2, "sq",
        ))
        .await;
    }

    #[tokio::test]
    async fn i6418_a_non_holder_founder_is_held_sqlite() {
        let (b1, b2) = (fresh().await, fresh().await);
        Box::pin(super::bodies::non_holder_founder_is_held(&b1, &b2, "sq")).await;
    }
}

#[cfg(feature = "postgres")]
mod postgres_runners {
    use crate::store::Backend as _;

    async fn fresh() -> Option<crate::store::postgres::PostgresBackend> {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return None;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .expect("pg");
        b.run_migrations().await.expect("migrations");
        Some(b)
    }

    #[tokio::test]
    async fn i6417_a_served_birth_is_the_discovery_postgres() {
        let (Some(a), Some(b1), Some(b2)) = (fresh().await, fresh().await, fresh().await) else {
            return;
        };
        Box::pin(super::bodies::served_birth_is_the_discovery(
            &a, &b1, &b2, "pg",
        ))
        .await;
    }

    #[tokio::test]
    async fn i6418_a_non_holder_founder_is_held_postgres() {
        let (Some(b1), Some(b2)) = (fresh().await, fresh().await) else {
            return;
        };
        Box::pin(super::bodies::non_holder_founder_is_held(&b1, &b2, "pg")).await;
    }
}
