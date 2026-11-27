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

/// v62.0.0 (R2-rooms-b3; Constitution 11-24, "the reach TENSION is RULED") —
/// **I6419: a later bundle that drops a founder-holder does not un-reach the
/// room.**
///
/// The room's three founders are holders 1, 2, 3 at `quorum:2/3`. A later
/// bundle of the lineage seats holders 1, 2, 4. Then:
/// - the room is STILL reached (`is_authorized_infrastructure_community`);
/// - the active founder set shrinks to two (holder 3 no longer meets the
///   predicate), so T7 reads the room STALLED (M + 1 = 3);
/// - a founder-seat version that names holders 1, 2 and 4 (each meets the
///   predicate against the bundle in force), voiced by them, lands, and the
///   room is live (Rooted) again, still reached.
///
/// Mutation: reading "every founder eligible NOW" in
/// `trust_root::infrastructure_reached_here` turns the first leg red.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod b3 {
    use crate::federation::canonical_community::{chain_standing_at, StoredStanding};
    use crate::federation::canonical_community_invariants::bodies::{
        rooted_infrastructure_room_e2, SetNodeKey,
    };
    use crate::federation::edition2::fixture_genesis as fg;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::federation::edition2::group::GroupRecord;
    use crate::federation::edition2::group_fixtures as gf;
    use crate::federation::FederationDirectory;

    async fn reached<B: FederationDirectory + Sync>(b: &B, room: &str, what: &str) -> bool {
        let row = b
            .lookup_community(room)
            .await
            .expect("reads")
            .unwrap_or_else(|| panic!("{what}: the room is held"));
        crate::federation::admission::is_authorized_infrastructure_community(b, &row)
            .await
            .expect("reads")
    }

    async fn standing<B: FederationDirectory + Sync>(b: &B, room: &str) -> StoredStanding {
        chain_standing_at(b, room, crate::host::clock::now())
            .await
            .expect("the chain reads")
    }

    pub(crate) async fn later_bundle_keeps_reach<B>(b: &B, tag: &str)
    where
        B: FederationDirectory + SetNodeKey + Sync,
    {
        let room = rooted_infrastructure_room_e2(b, &format!("i6419-room-{tag}"), &[], tag).await;
        assert!(
            reached(b, &room, "I6419 before").await,
            "[{tag}] I6419 CONTROL: reached"
        );
        assert!(
            matches!(standing(b, &room).await, StoredStanding::Rooted(_)),
            "[{tag}] I6419 CONTROL: live"
        );

        // The later bundle: holder 3 is dropped, holder 4 joins.
        let later = fg::later_v2(
            fg::bundle_v2_wide(),
            &[1, 2, 4],
            &fg::SERVE_NODE_SEEDS,
            &[1, 2, 4],
        );
        fg::install_ceremony_v2(b, &later)
            .await
            .unwrap_or_else(|e| panic!("[{tag}] the later bundle installs: {e}"));
        assert!(
            reached(b, &room, "I6419 after").await,
            "[{tag}] I6419: a later bundle dropping a founder-holder does NOT un-reach the room"
        );
        assert!(
            matches!(standing(b, &room).await, StoredStanding::Stalled { .. }),
            "[{tag}] I6419: the active founder set is two of three at quorum:2/3: STALLED (T7)"
        );

        // The founder-seat version: holder 3's seat moves to holder 4.
        let mut record = b
            .lookup_community(&room)
            .await
            .expect("reads")
            .expect("the room is held");
        let (three, four) = (fg::identity_ref_of(3), fg::identity_ref_of(4));
        for m in &mut record.members {
            if m.key_id == three {
                m.key_id = four.clone();
            }
        }
        let head = gf::held_head(b, &room).await.expect("the room's head").0;
        let at = e2::ms(crate::host::clock::now());
        let keys = [fg::test_key(1), fg::test_key(2), fg::test_key(4)];
        let refs: Vec<_> = keys.iter().collect();
        for v in gf::roster_voices(&GroupRecord::Community(record), 2, Some(&head), at, &refs) {
            let _ = e2::put_statement(b, &v).await;
        }
        assert!(
            matches!(standing(b, &room).await, StoredStanding::Rooted(_)),
            "[{tag}] I6419: the founder-seat version (each named founder a holder in force) lands: \
             live again"
        );
        assert!(
            reached(b, &room, "I6419 recovered").await,
            "[{tag}] I6419: still reached"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i6419_a_later_bundle_keeps_the_reach_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .expect("sqlite");
        b.run_migrations().await.expect("migrations");
        Box::pin(later_bundle_keeps_reach(&b, "sq")).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i6419_a_later_bundle_keeps_the_reach_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .expect("pg");
        b.run_migrations().await.expect("migrations");
        Box::pin(later_bundle_keeps_reach(&b, "pg")).await;
    }
}
