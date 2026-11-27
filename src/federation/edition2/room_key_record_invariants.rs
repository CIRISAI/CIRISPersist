//! v62.0.0 (ROOMKEY-5; CC 3.1.3.2) — **the room-key members of a key record.**
//!
//! - **I7006** (pure) — one record's payload: no `room` is no room key; a
//!   well-typed `room` / `kem_xwing_pubkey` / `seat_commitment` read back; an
//!   ill-typed one of the three is refused BY NAME (`room` not a group-ref,
//!   `kem_xwing_pubkey` not 1216 bytes, `seat_commitment` not a hash digest),
//!   never read as absent.
//! - **I7007** (pure, over held statements) — a key's VALID records: a room
//!   key reads its room, KEM half and commitment; a plain key is no room key;
//!   renewals naming two rooms, or marked in one and not the other, are
//!   `Conflicting`; the KEM half is the latest record's, and at an instant the
//!   latest record covering it; a record only another key signed, or no
//!   record, is `Unresolved`; a malformed `room` is `Malformed { "room" }`.
//! - **I7008** (sqlite + postgres) — `is_room_key` through the store's key
//!   plane: the room of a room key put through the door; `None` for a plain
//!   key and for a key not held.
//!
//! v62.0.0 (ROOMKEY-5b; Constitution 11-24 ruling (3)) — the three members come
//! together: I7006 refuses `room` without either of the other two, and either
//! of them without `room`, by the member's name.
//! - **I7015** (sqlite + postgres, through the statement door) — four cases:
//!   - a record with all three lands;
//!   - `kem_xwing_pubkey` without `room` is refused `edition2_payload_invalid`;
//!   - `seat_commitment` without `room` is refused the same;
//!   - `room` without `seat_commitment` is refused the same, and nothing is held.

#[cfg(test)]
mod pure {
    use ciris_verify_core::cde::Value;

    use super::super::fixture_switch::{self as e2, KeyRecordOptions};
    use super::super::liveness::HeldKeys;
    use super::super::room_key_record::{
        members_of_payload, room_key_reading, RoomKeyMembers, RoomKeyReading, KEM_XWING_PUBKEY,
        ROOM, SEAT_COMMITMENT,
    };
    use crate::federation::self_at_login::XWingPublicKey;

    pub(super) fn room(n: u8) -> String {
        super::super::group_id::derive_group_id(
            "community",
            &[&e2::kid("i7007-founder")],
            0,
            &[n; 32],
        )
    }

    pub(super) fn kem(n: u8) -> Value {
        Value::Bytes(vec![n; 1216])
    }

    pub(super) fn seat(n: u8) -> Value {
        Value::Array(vec![Value::Nint(15), Value::Bytes(vec![n; 32])])
    }

    pub(super) fn opts(at: u64, extra: Vec<(&str, Value)>) -> KeyRecordOptions {
        KeyRecordOptions {
            asserted_at_ms: Some(at),
            extra: extra.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
            ..KeyRecordOptions::default()
        }
    }

    fn map(m: Vec<(&str, Value)>) -> Value {
        Value::Map(
            m.into_iter()
                .map(|(k, v)| (Value::Text(k.into()), v))
                .collect(),
        )
    }

    fn held(records: &[Vec<u8>]) -> HeldKeys {
        let mut h = HeldKeys::new();
        for r in records {
            h.insert_record(r.clone());
        }
        h
    }

    /// I7006 — one payload.
    #[test]
    fn i7006_one_record_s_room_key_members() {
        assert_eq!(
            members_of_payload(&map(vec![("asserted_at", Value::Uint(0))])),
            Ok(None)
        );
        let r = room(1);
        assert_eq!(
            members_of_payload(&map(vec![
                (ROOM, Value::Text(r.clone())),
                (KEM_XWING_PUBKEY, kem(0x5a)),
                (SEAT_COMMITMENT, seat(7)),
            ])),
            Ok(Some(RoomKeyMembers {
                room: r.clone(),
                kem_xwing_pubkey: XWingPublicKey::from_bytes(&[0x5a; 1216]).unwrap(),
                seat_commitment: [7; 32],
            }))
        );
        for (bad, member) in [
            // ROOMKEY-5b: the three come together.
            (map(vec![(ROOM, Value::Text(r.clone()))]), KEM_XWING_PUBKEY),
            (
                map(vec![
                    (ROOM, Value::Text(r.clone())),
                    (KEM_XWING_PUBKEY, kem(1)),
                ]),
                SEAT_COMMITMENT,
            ),
            (
                map(vec![
                    (ROOM, Value::Text(r.clone())),
                    (SEAT_COMMITMENT, seat(1)),
                ]),
                KEM_XWING_PUBKEY,
            ),
            (map(vec![(KEM_XWING_PUBKEY, kem(1))]), KEM_XWING_PUBKEY),
            (map(vec![(SEAT_COMMITMENT, seat(1))]), SEAT_COMMITMENT),
            (
                map(vec![(KEM_XWING_PUBKEY, kem(1)), (SEAT_COMMITMENT, seat(1))]),
                KEM_XWING_PUBKEY,
            ),
            (
                map(vec![(ROOM, Value::Text("chat:room:v1:abc".into()))]),
                ROOM,
            ),
            (map(vec![(ROOM, Value::Bytes(vec![1; 32]))]), ROOM),
            (
                map(vec![
                    (ROOM, Value::Text(r.clone())),
                    (KEM_XWING_PUBKEY, Value::Bytes(vec![1; 1215])),
                ]),
                KEM_XWING_PUBKEY,
            ),
            (
                map(vec![
                    (ROOM, Value::Text(r.clone())),
                    (KEM_XWING_PUBKEY, Value::Text("x".into())),
                ]),
                KEM_XWING_PUBKEY,
            ),
            (
                map(vec![
                    (ROOM, Value::Text(r.clone())),
                    (KEM_XWING_PUBKEY, kem(1)),
                    (SEAT_COMMITMENT, Value::Bytes(vec![7; 32])),
                ]),
                SEAT_COMMITMENT,
            ),
            (
                map(vec![
                    (ROOM, Value::Text(r.clone())),
                    (KEM_XWING_PUBKEY, kem(1)),
                    (
                        SEAT_COMMITMENT,
                        Value::Array(vec![Value::Nint(15), Value::Bytes(vec![7; 31])]),
                    ),
                ]),
                SEAT_COMMITMENT,
            ),
        ] {
            assert_eq!(
                members_of_payload(&bad),
                Err(member),
                "I7006 {member} breaking the rule is refused by name"
            );
        }
    }

    /// I7007 — a key's valid records.
    #[test]
    fn i7007_the_reading_over_a_key_s_valid_records() {
        let (r1, r2) = (room(1), room(2));
        let k = "i7007-rk";
        let kid = e2::kid_digest(k);
        let first = e2::key_record_with(
            k,
            &["user"],
            &opts(
                10,
                vec![
                    (ROOM, Value::Text(r1.clone())),
                    (KEM_XWING_PUBKEY, kem(1)),
                    (SEAT_COMMITMENT, seat(1)),
                ],
            ),
        );
        let one = held(std::slice::from_ref(&first));
        assert_eq!(
            room_key_reading(&one, &kid, None),
            RoomKeyReading::Room(RoomKeyMembers {
                room: r1.clone(),
                kem_xwing_pubkey: XWingPublicKey::from_bytes(&[1; 1216]).unwrap(),
                seat_commitment: [1; 32],
            }),
            "I7007 a room key reads its room, KEM half and commitment"
        );
        assert_eq!(
            room_key_reading(&one, &kid, Some(5)),
            RoomKeyReading::Unresolved,
            "I7007 not live before its record"
        );

        let renewal = e2::key_record_with(
            k,
            &["user"],
            &opts(
                20,
                vec![
                    (ROOM, Value::Text(r1.clone())),
                    (KEM_XWING_PUBKEY, kem(2)),
                    (SEAT_COMMITMENT, seat(1)),
                ],
            ),
        );
        let both = held(&[first.clone(), renewal]);
        let kem_of = |r: RoomKeyReading| match r {
            RoomKeyReading::Room(m) => m.kem_xwing_pubkey,
            other => panic!("I7007 expected a room key, got {other:?}"),
        };
        assert_eq!(
            kem_of(room_key_reading(&both, &kid, None)),
            XWingPublicKey::from_bytes(&[2; 1216]).unwrap(),
            "I7007 the KEM half is the latest record's"
        );
        assert_eq!(
            kem_of(room_key_reading(&both, &kid, Some(15))),
            XWingPublicKey::from_bytes(&[1; 1216]).unwrap(),
            "I7007 at an instant, the latest record covering it"
        );

        let elsewhere = e2::key_record_with(
            k,
            &["user"],
            &opts(
                30,
                vec![
                    (ROOM, Value::Text(r2.clone())),
                    (KEM_XWING_PUBKEY, kem(3)),
                    (SEAT_COMMITMENT, seat(3)),
                ],
            ),
        );
        assert_eq!(
            room_key_reading(&held(&[first.clone(), elsewhere]), &kid, None),
            RoomKeyReading::Conflicting,
            "I7007 renewals naming two rooms conclude no room"
        );
        let unmarked = e2::key_record_with(k, &["user"], &opts(30, vec![]));
        assert_eq!(
            room_key_reading(&held(&[first.clone(), unmarked]), &kid, None),
            RoomKeyReading::Conflicting,
            "I7007 a record marked and a renewal not marked conclude no room"
        );

        let plain = "i7007-plain";
        assert_eq!(
            room_key_reading(
                &held(&[e2::key_record_with(plain, &["user"], &opts(10, vec![]))]),
                &e2::kid_digest(plain),
                None
            ),
            RoomKeyReading::NotARoomKey,
            "I7007 a record without `room` is no room key"
        );
        let bad = "i7007-bad";
        assert_eq!(
            room_key_reading(
                &held(&[e2::key_record_with(
                    bad,
                    &["user"],
                    &opts(10, vec![(ROOM, Value::Text("chat:room:v1:x".into()))])
                )]),
                &e2::kid_digest(bad),
                None
            ),
            RoomKeyReading::Malformed { member: ROOM },
            "I7007 a malformed `room` is a refusal, never an absence"
        );

        assert_eq!(
            room_key_reading(&HeldKeys::new(), &kid, None),
            RoomKeyReading::Unresolved,
            "I7007 no record held"
        );
        let other = "i7007-other";
        let by_other = e2::key_record_with(
            other,
            &["user"],
            &KeyRecordOptions {
                signer: Some("i7007-signer".into()),
                ..opts(
                    10,
                    vec![
                        (ROOM, Value::Text(r1)),
                        (KEM_XWING_PUBKEY, kem(1)),
                        (SEAT_COMMITMENT, seat(1)),
                    ],
                )
            },
        );
        assert_eq!(
            room_key_reading(&held(&[by_other]), &e2::kid_digest(other), None),
            RoomKeyReading::Unresolved,
            "I7007 a record only another key signed makes no room key"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod bodies {
    use ciris_verify_core::cde::Value;

    use super::super::fixture_switch as e2;
    use super::super::room_key_record::{is_room_key, KEM_XWING_PUBKEY, ROOM, SEAT_COMMITMENT};
    use super::pure::{kem, opts, room, seat};
    use crate::federation::FederationDirectory;

    /// I7008 — `is_room_key` through the store.
    pub(super) async fn i7008_is_room_key_through_the_store(d: &dyn FederationDirectory) {
        let r = room(8);
        let rk = "i7008-rk";
        e2::put_key_with(
            d,
            rk,
            &["user"],
            &opts(
                10,
                vec![
                    (ROOM, Value::Text(r.clone())),
                    (KEM_XWING_PUBKEY, kem(8)),
                    (SEAT_COMMITMENT, seat(8)),
                ],
            ),
        )
        .await;
        assert_eq!(
            is_room_key(d, &e2::kid_digest(rk))
                .await
                .expect("I7008 read"),
            Some(r),
            "I7008 the room key put through the door reads its room"
        );
        let plain = "i7008-plain";
        e2::put_key_with(d, plain, &["user"], &opts(10, vec![])).await;
        assert_eq!(
            is_room_key(d, &e2::kid_digest(plain))
                .await
                .expect("I7008 plain"),
            None,
            "I7008 a plain key is no room key"
        );
        assert_eq!(
            is_room_key(d, &e2::kid_digest("i7008-never-held"))
                .await
                .expect("I7008 none"),
            None,
            "I7008 a key not held is no room key"
        );
    }

    /// I7015 — the door refuses a record whose room-key members do not come
    /// together.
    pub(super) async fn i7015_the_three_members_come_together(d: &dyn FederationDirectory) {
        use crate::federation::{malformed_row, Error};
        let r = room(15);
        let refused = |out: &Result<_, Error>| {
            matches!(out, Err(Error::MalformedRow { reason, .. })
                if *reason == malformed_row::EDITION2_PAYLOAD_INVALID)
        };
        let all = e2::key_record_with(
            "i7015-all",
            &["user"],
            &opts(
                10,
                vec![
                    (ROOM, Value::Text(r.clone())),
                    (KEM_XWING_PUBKEY, kem(15)),
                    (SEAT_COMMITMENT, seat(15)),
                ],
            ),
        );
        let out = e2::put_statement(d, &all).await;
        assert!(out.is_ok(), "I7015 a record with all three lands: {out:?}");
        for (seed, extra, what) in [
            (
                "i7015-kem-only",
                vec![(KEM_XWING_PUBKEY, kem(16))],
                "kem_xwing_pubkey without room",
            ),
            (
                "i7015-seat-only",
                vec![(SEAT_COMMITMENT, seat(17))],
                "seat_commitment without room",
            ),
            (
                "i7015-no-seat",
                vec![(ROOM, Value::Text(r.clone())), (KEM_XWING_PUBKEY, kem(18))],
                "room without seat_commitment",
            ),
        ] {
            let st = e2::key_record_with(seed, &["user"], &opts(10, extra));
            let out = e2::put_statement(d, &st).await;
            assert!(
                refused(&out),
                "I7015 {what} is refused edition2_payload_invalid: {out:?}"
            );
            assert!(
                d.edition2_statements_about(
                    ciris_verify_core::edition2::keys::KEY_RECORD_FAMILY,
                    &e2::kid(seed)
                )
                .await
                .unwrap()
                .is_empty(),
                "I7015 {what}: nothing of it is held"
            );
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i7015_the_three_members_come_together_sqlite() {
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(i7015_the_three_members_come_together(&d)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i7015_the_three_members_come_together_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(i7015_the_three_members_come_together(&d)).await;
        eprintln!("i7015 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i7008_is_room_key_through_the_store_sqlite() {
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(i7008_is_room_key_through_the_store(&d)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i7008_is_room_key_through_the_store_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(i7008_is_room_key_through_the_store(&d)).await;
        eprintln!("i7008 postgres: RAN");
    }
}
