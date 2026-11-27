//! v62.0.0 (ROOMKEY-7, the parts that touch no door) — **a voice of a private
//! room.**
//!
//! - **I7018** (pure):
//!   - the adapter's decision: a row counts as its voice's only when it names
//!     a voice-roster head, its `iss` is a voice of the row's room, and its
//!     signer is a key of the voice at that head; otherwise it concludes
//!     nothing, by reason;
//!   - `bind_draft_signed_by` puts the SIGNER's kid in the protected header
//!     (`iss` = the voice, `kid` = the room key), where `bind_draft` would put
//!     the genesis key of `iss`.
//! - **I7019** (sqlite + postgres, over held rows; no row carries `voice`, so
//!   nothing here waits for Verify 23.7.0) — `voice_keys_at_head`:
//!   - a person's voice is its first key at the first head, and both keys
//!     after a further key is bound;
//!   - a bound key whose own record names another room is no key of the
//!     voice;
//!   - an agent's voice is its one key;
//!   - a first key that is no room key names no voice.

#[cfg(test)]
mod pure {
    use std::collections::BTreeSet;

    use ciris_verify_core::cde::Value;

    use super::super::fixture_switch as e2;
    use super::super::occurrence::{bind_draft, bind_draft_signed_by, BindTerms};
    use super::super::voice::{voice_of_room_row, VoiceKeys, VoiceOfRow, VoiceRoster};

    /// I7018 — the adapter's decision.
    #[test]
    fn i7018_the_adapter_counts_a_row_as_its_voice_s_or_nothing() {
        let (room, other) = ("group-room", "group-other");
        let (voice, k2, stranger) = ("v", "k2", "x");
        let roster = VoiceRoster::Keys(VoiceKeys {
            room: room.into(),
            keys: BTreeSet::from([voice.to_owned(), k2.to_owned()]),
        });
        assert_eq!(
            voice_of_room_row(room, voice, k2, true, &roster),
            VoiceOfRow::Voice(voice.into()),
            "I7018 a further key of the voice signs as the voice"
        );
        assert_eq!(
            voice_of_room_row(room, voice, voice, true, &roster),
            VoiceOfRow::Voice(voice.into()),
            "I7018 the first key signs as the voice"
        );
        assert_eq!(
            voice_of_room_row(room, voice, k2, false, &roster),
            VoiceOfRow::NoVoiceHead,
            "I7018 a row naming no voice-roster head concludes nothing"
        );
        assert_eq!(
            voice_of_room_row(room, voice, stranger, true, &roster),
            VoiceOfRow::NotAKeyOfTheVoice,
            "I7018 a key not of the voice at the head concludes nothing"
        );
        assert_eq!(
            voice_of_room_row(other, voice, k2, true, &roster),
            VoiceOfRow::OtherRoom,
            "I7018 a voice of another room"
        );
        assert_eq!(
            voice_of_room_row(room, voice, k2, true, &VoiceRoster::NotAVoice),
            VoiceOfRow::NotAVoice
        );
    }

    /// I7018 — the producer takes the signer's own kid.
    #[test]
    fn i7018_the_bind_producer_takes_the_signer_s_kid() {
        let voice = e2::kid("i7018-voice");
        let t = BindTerms {
            author: voice.clone(),
            identity_key_id: voice.clone(),
            occurrence_key_id: e2::kid("i7018-k2"),
            device_class: "laptop".into(),
            asserted_at_ms: 1_000,
            ..BindTerms::default()
        };
        let kid_of = |d: &super::super::emit::Draft| -> Vec<u8> {
            let protected = ciris_verify_core::cde::decode(&d.protected).expect("protected");
            protected
                .get_int(4)
                .and_then(Value::as_bytes)
                .expect("kid")
                .to_vec()
        };
        let signer = e2::kid_digest("i7018-k2");
        let by = bind_draft_signed_by(&t, &voice, &signer).expect("drafted");
        assert_eq!(
            kid_of(&by),
            signer.to_vec(),
            "I7018 kid = the signing room key"
        );
        let plain = bind_draft(&t, &voice).expect("drafted");
        assert_eq!(
            kid_of(&plain),
            e2::kid_digest("i7018-voice").to_vec(),
            "I7018 bind_draft keeps the genesis key of iss"
        );
        assert_eq!(by.payload, plain.payload, "I7018 one payload, two signers");
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod bodies {
    use std::collections::BTreeSet;

    use ciris_verify_core::cde::Value;

    use super::super::fixture_occurrence::{put_bind, BindOptions};
    use super::super::fixture_switch::{self as e2, KeyRecordOptions};
    use super::super::group_id::derive_group_id;
    use super::super::ingest::StatementOutcome;
    use super::super::occurrence::current_roster_head;
    use super::super::room_key_record::{KEM_XWING_PUBKEY, ROOM, SEAT_COMMITMENT};
    use super::super::voice::{voice_keys_at_head, VoiceKeys, VoiceRoster};
    use crate::federation::FederationDirectory;

    fn now_ms() -> u64 {
        u64::try_from(crate::host::clock::now().timestamp_millis()).unwrap()
    }

    fn room(n: u8) -> String {
        derive_group_id("community", &[&e2::kid("i7019-founder")], 0, &[n; 32])
    }

    async fn room_key(
        d: &dyn FederationDirectory,
        seed: &str,
        room: &str,
        roles: &[&str],
    ) -> String {
        let user = roles == ["user"];
        e2::put_key_with(
            d,
            seed,
            roles,
            &KeyRecordOptions {
                asserted_at_ms: user.then_some(0),
                extra: vec![
                    (ROOM.to_owned(), Value::Text(room.to_owned())),
                    (KEM_XWING_PUBKEY.to_owned(), Value::Bytes(vec![0x61; 1216])),
                    (
                        SEAT_COMMITMENT.to_owned(),
                        Value::Array(vec![Value::Nint(15), Value::Bytes(vec![0x62; 32])]),
                    ),
                ],
                ..KeyRecordOptions::default()
            },
        )
        .await
    }

    async fn bind(d: &dyn FederationDirectory, voice: &str, key: &str) {
        let out = Box::pin(put_bind(
            d,
            voice,
            voice,
            key,
            "laptop",
            &BindOptions {
                asserted_at_ms: now_ms() - 60_000,
                ..BindOptions::default()
            },
        ))
        .await;
        assert!(
            matches!(out, Ok(StatementOutcome::Row { .. })),
            "I7019 premise: the bind lands: {out:?}"
        );
    }

    async fn head(d: &dyn FederationDirectory, voice: &str) -> super::super::names::RowId {
        current_roster_head(d, voice)
            .await
            .unwrap()
            .expect("I7019 premise: a head")
    }

    /// I7019 — the voice's keys at a named head.
    pub(super) async fn i7019_the_voice_s_keys_at_a_named_head(d: &dyn FederationDirectory) {
        let (r, elsewhere) = (room(1), room(2));
        let v = room_key(d, "i7019-v1", &r, &["user"]).await;
        let k2 = room_key(d, "i7019-v2", &r, &["user"]).await;
        let first_head = head(d, &v).await;
        bind(d, &v, &k2).await;
        let after = head(d, &v).await;
        assert_eq!(
            voice_keys_at_head(d, &v, &first_head).await.unwrap(),
            VoiceRoster::Keys(VoiceKeys {
                room: r.clone(),
                keys: BTreeSet::from([v.clone()]),
            }),
            "I7019 at its first head a voice is its first key"
        );
        assert_eq!(
            voice_keys_at_head(d, &v, &after).await.unwrap(),
            VoiceRoster::Keys(VoiceKeys {
                room: r.clone(),
                keys: BTreeSet::from([v.clone(), k2.clone()]),
            }),
            "I7019 after the bind, both keys speak for the voice"
        );

        let w = room_key(d, "i7019-w1", &r, &["user"]).await;
        let w2 = room_key(d, "i7019-w2", &elsewhere, &["user"]).await;
        bind(d, &w, &w2).await;
        assert_eq!(
            voice_keys_at_head(d, &w, &head(d, &w).await).await.unwrap(),
            VoiceRoster::Keys(VoiceKeys {
                room: r.clone(),
                keys: BTreeSet::from([w.clone()]),
            }),
            "I7019 a bound key of another room is no key of the voice"
        );

        let a = room_key(d, "i7019-agent", &r, &["agent"]).await;
        let a_head = super::super::names::RowId([0x19; 32]);
        assert_eq!(
            voice_keys_at_head(d, &a, &a_head).await.unwrap(),
            VoiceRoster::Keys(VoiceKeys {
                room: r.clone(),
                keys: BTreeSet::from([a.clone()]),
            }),
            "I7019 an agent's voice is its one room key"
        );

        let plain = e2::put_key(d, "i7019-plain", &["user"]).await;
        assert_eq!(
            voice_keys_at_head(d, &plain, &first_head).await.unwrap(),
            VoiceRoster::NotAVoice,
            "I7019 a first key that is no room key names no voice"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i7019_the_voice_s_keys_at_a_named_head_sqlite() {
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(i7019_the_voice_s_keys_at_a_named_head(&d)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i7019_the_voice_s_keys_at_a_named_head_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(i7019_the_voice_s_keys_at_a_named_head(&d)).await;
        eprintln!("i7019 postgres: RAN");
    }
}
