//! v62.0.0 (ROOMKEY-6; CC 3.1.3.2, Constitution Q-C3) — **an identity's room
//! binding key on `identity:occurrence`.**
//!
//! - **I7009** (pure) — `reused_half` answers the reused half, the ML-KEM-768
//!   half first, and `None` when neither is reused. `check_xwing_halves` keeps
//!   its four refusals over it. T9's token for the room binding key is the
//!   held name: `None` while `roomkey_names` holds it unnamed, the name once
//!   given.
//! - **I7010** (sqlite + postgres) — through the statement door:
//!   - a bind carrying a 1216-byte `room_binding_xwing_pubkey` lands. Before
//!     ROOMKEY-6 the closed map refused it `edition2_payload_invalid`;
//!   - one of 1215 bytes is refused `xwing_pubkey_wrong_length`;
//!   - one whose ML-KEM half is the row's content-KEM `ml_kem_768` lands while
//!     T9 is unnamed (the check runs and refuses nothing), and is refused by
//!     T9's name once it is given.

#[cfg(test)]
mod pure {
    use super::super::roomkey_names::{ROOM_BINDING_ML_KEM_768_REUSE, ROOM_BINDING_X25519_REUSE};
    use crate::federation::self_at_login::{
        check_xwing_halves, reused_half, XWingHalf, XWingKeyRole, XWingPublicKey, XWingReuseRefusal,
    };

    fn key(m: u8, x: u8) -> XWingPublicKey {
        let mut b = vec![m; 1184];
        b.extend(vec![x; 32]);
        XWingPublicKey::from_bytes(&b).expect("1216 bytes")
    }

    /// I7009 — the shared half test, and T9's held names.
    #[test]
    fn i7009_the_reused_half_and_the_held_names() {
        let k = key(1, 2);
        let (ml, x, other) = (vec![1u8; 1184], vec![2u8; 32], vec![9u8; 32]);
        assert_eq!(
            reused_half(&k, [other.as_slice()]),
            None,
            "I7009 nothing reused"
        );
        assert_eq!(reused_half(&k, [x.as_slice()]), Some(XWingHalf::X25519));
        assert_eq!(reused_half(&k, [ml.as_slice()]), Some(XWingHalf::MlKem768));
        assert_eq!(
            reused_half(&k, [x.as_slice(), ml.as_slice()]),
            Some(XWingHalf::MlKem768),
            "I7009 the ML-KEM half is checked first"
        );
        assert_eq!(
            check_xwing_halves(XWingKeyRole::Transit, &k, [ml.as_slice()]),
            Err(XWingReuseRefusal::TransitMlKem768Reuse)
        );
        assert_eq!(
            check_xwing_halves(XWingKeyRole::OnionHop, &k, [x.as_slice()]),
            Err(XWingReuseRefusal::OnionHopX25519Reuse)
        );
        assert_eq!(
            check_xwing_halves(XWingKeyRole::OnionHop, &k, [other.as_slice()]),
            Ok(())
        );

        for (half, name) in [
            (XWingHalf::MlKem768, ROOM_BINDING_ML_KEM_768_REUSE),
            (XWingHalf::X25519, ROOM_BINDING_X25519_REUSE),
        ] {
            assert_eq!(
                super::super::occurrence::room_binding_reuse_token(Some(half)),
                name,
                "I7009 T9's token is the held name: None while unnamed"
            );
        }
        assert_eq!(
            super::super::occurrence::room_binding_reuse_token(None),
            None,
            "I7009 no half reused, no token"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod bodies {
    use ciris_verify_core::cde::Value;

    use super::super::door_invariants::fixture::map;
    use super::super::fixture_occurrence::{put_bind, BindOptions};
    use super::super::fixture_switch as e2;
    use super::super::ingest::StatementOutcome;
    use super::super::roomkey_names::ROOM_BINDING_ML_KEM_768_REUSE;
    use crate::federation::self_at_login::ROOM_BINDING_XWING_PUBKEY_MEMBER;
    use crate::federation::{malformed_row, Error, FederationDirectory};

    fn now_ms() -> u64 {
        u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap()
    }

    async fn bind(
        d: &dyn FederationDirectory,
        tag: &str,
        extra: Vec<(&'static str, Value)>,
    ) -> Result<StatementOutcome, Error> {
        let (u, dev) = (format!("i7010-{tag}-u"), format!("i7010-{tag}-d"));
        for s in [&u, &dev] {
            e2::put_key(d, s, &["user"]).await;
        }
        let opts = BindOptions {
            asserted_at_ms: now_ms() - 60_000,
            extra,
            ..BindOptions::default()
        };
        Box::pin(put_bind(d, &u, &u, &dev, "laptop", &opts)).await
    }

    fn landed(out: &Result<StatementOutcome, Error>) -> bool {
        matches!(out, Ok(StatementOutcome::Row { .. }))
    }

    fn refused(out: &Result<StatementOutcome, Error>, token: &str) -> bool {
        matches!(out, Err(Error::MalformedRow { reason, .. }) if *reason == token)
    }

    /// I7010 — the member through the door.
    pub(super) async fn i7010_the_room_binding_key_through_the_door(d: &dyn FederationDirectory) {
        let mut good = vec![0x41u8; 1184];
        good.extend([0x42u8; 32]);
        let out = bind(
            d,
            "good",
            vec![(ROOM_BINDING_XWING_PUBKEY_MEMBER, Value::Bytes(good))],
        )
        .await;
        assert!(
            landed(&out),
            "I7010 a 1216-byte room binding key lands: {out:?}"
        );

        let out = bind(
            d,
            "short",
            vec![(
                ROOM_BINDING_XWING_PUBKEY_MEMBER,
                Value::Bytes(vec![0x43; 1215]),
            )],
        )
        .await;
        assert!(
            refused(&out, malformed_row::XWING_PUBKEY_WRONG_LENGTH),
            "I7010 a 1215-byte room binding key is refused by length: {out:?}"
        );

        let content_ml = vec![0x51u8; 1184];
        let mut reusing = content_ml.clone();
        reusing.extend([0x52u8; 32]);
        let out = bind(
            d,
            "reuse",
            vec![
                (
                    "encryption_pubkeys",
                    map(vec![
                        ("x25519", Value::Bytes(vec![0x53; 32])),
                        ("ml_kem_768", Value::Bytes(content_ml)),
                    ]),
                ),
                (ROOM_BINDING_XWING_PUBKEY_MEMBER, Value::Bytes(reusing)),
            ],
        )
        .await;
        match ROOM_BINDING_ML_KEM_768_REUSE {
            None => assert!(
                landed(&out),
                "I7010 T9 unnamed: a reusing row is admitted (the check refuses nothing): {out:?}"
            ),
            Some(name) => assert!(
                refused(&out, name),
                "I7010 T9 named: refused by name: {out:?}"
            ),
        }
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i7010_the_room_binding_key_through_the_door_sqlite() {
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(i7010_the_room_binding_key_through_the_door(&d)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i7010_the_room_binding_key_through_the_door_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(i7010_the_room_binding_key_through_the_door(&d)).await;
        eprintln!("i7010 postgres: RAN");
    }
}
