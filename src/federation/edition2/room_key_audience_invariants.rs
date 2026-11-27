//! v62.0.0 (ROOMKEY-4; CC 3.1.3.2) — **a node is party to a room by a room key
//! it holds there.**
//!
//! - **I7011** (sqlite + postgres) — `hold::seated_room_key_rooms`, and through
//!   it `audience_memberships` / `is_audience`, on one node's store. A room is
//!   founded seating a room key R, whose own key record names the room:
//!   - before the node holds any room key, the room is not in its audience
//!     (the control: the person's other device, holding none);
//!   - a held key whose record names ANOTHER room is not counted, whatever
//!     the local row says;
//!   - a held room key of the room that holds no seat is not counted;
//!   - once the node holds R (not retired), the room is in its audience, and
//!     `is_audience` admits a community row placed there;
//!   - retired locally, R counts no more.

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod bodies {
    use std::collections::HashSet;

    use ciris_verify_core::cde::Value;

    use super::super::fixture_switch::{self as e2, KeyRecordOptions};
    use super::super::group_id::derive_group_id;
    use super::super::room_key_record::{KEM_XWING_PUBKEY, ROOM, SEAT_COMMITMENT};
    use super::super::room_keys::RoomKeyHeld;
    use crate::federation::replication::hold::{
        audience_memberships, is_audience, seated_room_key_rooms,
    };
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::{consensus_protocol, Community, CommunityMember};
    use crate::federation::FederationDirectory;

    const COMMUNITY: &str = "community";

    fn at(s: &str) -> chrono::DateTime<chrono::Utc> {
        s.parse().expect("rfc3339")
    }

    async fn room_key(d: &dyn FederationDirectory, seed: &str, room: &str) {
        e2::put_key_with(
            d,
            seed,
            &["user"],
            &KeyRecordOptions {
                asserted_at_ms: Some(0),
                // ROOMKEY-5b: a room key's record carries all three members.
                extra: vec![
                    (ROOM.to_owned(), Value::Text(room.to_owned())),
                    (KEM_XWING_PUBKEY.to_owned(), Value::Bytes(vec![0x71; 1216])),
                    (
                        SEAT_COMMITMENT.to_owned(),
                        Value::Array(vec![Value::Nint(15), Value::Bytes(vec![0x72; 32])]),
                    ),
                ],
                ..KeyRecordOptions::default()
            },
        )
        .await;
    }

    fn held(seed: &str, room: &str, created_at_us: i64) -> RoomKeyHeld {
        RoomKeyHeld {
            room_key_kid: e2::kid_digest(seed),
            room_id: room.to_owned(),
            acts_for: e2::kid("i7011-person"),
            created_at_us,
            retired_at_us: None,
        }
    }

    async fn audience(d: &dyn FederationDirectory, node: &str) -> HashSet<String> {
        audience_memberships(d, node, COMMUNITY)
            .await
            .expect("I7011 audience")
    }

    /// I7011 — the seated room-key arm on one node.
    pub(super) async fn i7011_seated_room_key_audience(d: &dyn FederationDirectory) {
        let (alias, rk) = ("i7011-room", "i7011-rk");
        let gid = derive_group_id(
            COMMUNITY,
            &[&e2::kid(rk)],
            e2::fixture_founded_at_ms(alias),
            &e2::fixture_group_nonce(alias),
        );
        room_key(d, rk, &gid).await;
        let founded = at("2026-01-01T00:00:00Z");
        let community = ts::sign_community(
            rk,
            Community {
                prev_head_digest: String::new(),
                charter_digest: String::new(),
                community_key_id: alias.to_owned(),
                community_name: "i7011 room".into(),
                members: vec![CommunityMember {
                    key_id: rk.to_owned(),
                    joined_at: founded,
                    role: Some("founder".to_owned()),
                }],
                founded_at: founded,
                consensus_protocol: consensus_protocol::MAJORITY.to_owned(),
                policy_blob: None,
                persist_row_hash: String::new(),
            },
        );
        let founded_ms = u64::try_from(founded.timestamp_millis()).expect("ms");
        e2::put_voices(d, &e2::community_voices(&community, 1, None, founded_ms))
            .await
            .expect("I7011 premise: the room is founded");
        assert_eq!(
            e2::room_id(alias),
            gid,
            "I7011 premise: the room key's record names the id the founding derived"
        );
        assert!(
            d.list_communities_for_member_active(&e2::kid(rk))
                .await
                .unwrap()
                .iter()
                .any(|c| c.community_key_id == gid),
            "I7011 premise: the room key holds a seat"
        );

        let node = e2::kid("i7011-node");
        assert!(
            !audience(d, &node).await.contains(&gid),
            "I7011 no room key held: not party"
        );

        // A key whose own record names another room: the local row does not
        // make it this room's.
        let other = derive_group_id(COMMUNITY, &[&e2::kid("i7011-x")], 0, &[9; 32]);
        room_key(d, "i7011-rk-other", &other).await;
        d.edition2_put_room_key_local(&held("i7011-rk-other", &gid, 1))
            .await
            .unwrap();
        // A room key of this room that holds no seat.
        room_key(d, "i7011-rk-unseated", &gid).await;
        d.edition2_put_room_key_local(&held("i7011-rk-unseated", &gid, 1))
            .await
            .unwrap();
        assert!(
            seated_room_key_rooms(d).await.unwrap().is_empty(),
            "I7011 a key of another room, and an unseated key, give no room"
        );
        assert!(!audience(d, &node).await.contains(&gid));

        d.edition2_put_room_key_local(&held(rk, &gid, 1))
            .await
            .unwrap();
        assert_eq!(
            seated_room_key_rooms(d).await.unwrap(),
            HashSet::from([gid.clone()]),
            "I7011 the seated room key gives its room"
        );
        assert!(
            audience(d, &node).await.contains(&gid),
            "I7011 party by the held room key"
        );
        assert!(
            is_audience(
                d,
                COMMUNITY,
                Some(gid.as_str()),
                &e2::kid("i7011-author"),
                |_| false,
                &node
            )
            .await
            .unwrap(),
            "I7011 a community row placed in the room reaches this node"
        );

        assert!(d
            .edition2_retire_room_key_local(&e2::kid_digest(rk), 2)
            .await
            .unwrap());
        assert!(
            !audience(d, &node).await.contains(&gid),
            "I7011 a retired room key counts no more"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i7011_seated_room_key_audience_sqlite() {
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(i7011_seated_room_key_audience(&d)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i7011_seated_room_key_audience_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(i7011_seated_room_key_audience(&d)).await;
        eprintln!("i7011 postgres: RAN");
    }
}
