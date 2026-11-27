//! v62.0.0 (ROOMKEY-3; CC 3.1.3.2) — **the node-local room keys and bindings.**
//!
//! - **I7004** (sqlite + postgres) — `ceg_room_keys_local` and
//!   `ceg_room_bindings` through the directory:
//!   - a held room key reads back, by its room and in the whole list;
//!   - the same key for the same room again is a no-op (`false`);
//!   - for ANOTHER room it is refused `Conflict` ("A room key MUST NOT be used
//!     in a second room", p3:365) and the first room stays;
//!   - retiring marks it once, keeps the row, and never before it was recorded;
//!   - a binding reads back by its room;
//!   - a second binding for the same `(room key, made for)` keeps the first.
//! - **I7005** (pure, from disk) — **nothing outside `edition2::room_keys`
//!   reads or writes the two tables**: no serve, replication, purge,
//!   tombstone or erasure path can reach a node-local room key or binding
//!   without naming the table, and only `room_keys.rs` (and the V300 table
//!   list, `store/edition_baseline.rs`) names it in code. Comment lines are
//!   stripped first, so a doc mention neither passes nor fails the check.

#[cfg(test)]
mod from_disk {
    use super::super::room_keys::{ROOM_BINDINGS_TABLE, ROOM_KEYS_TABLE};

    fn rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for e in std::fs::read_dir(dir).expect("I7005: read src") {
            let p = e.expect("I7005: a dir entry").path();
            if p.is_dir() {
                rs_files(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }

    /// I7005 — only `room_keys.rs` (and the V300 table list) names the two
    /// node-local tables in code.
    #[test]
    fn i7005_nothing_outside_room_keys_reaches_the_local_tables() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut files = Vec::new();
        rs_files(&root.join("src"), &mut files);
        assert!(files.len() > 100, "I7005 premise: the source tree is read");
        let allowed = [
            "src/federation/edition2/room_keys.rs",
            "src/federation/edition2/room_keys_invariants.rs",
            "src/store/edition_baseline.rs",
        ];
        let mut named_in_room_keys = 0usize;
        let mut strays = Vec::new();
        for f in files {
            let rel = f
                .strip_prefix(root)
                .expect("I7005: under the root")
                .to_string_lossy()
                .replace('\\', "/");
            let text = std::fs::read_to_string(&f).expect("I7005: read a file");
            for (n, line) in text.lines().enumerate() {
                if line.trim_start().starts_with("//") {
                    continue;
                }
                if line.contains(ROOM_KEYS_TABLE) || line.contains(ROOM_BINDINGS_TABLE) {
                    if rel == allowed[0] {
                        named_in_room_keys += 1;
                    } else if !allowed.contains(&rel.as_str()) {
                        strays.push(format!("{rel}:{}", n + 1));
                    }
                }
            }
        }
        assert!(
            named_in_room_keys >= 10,
            "I7005 premise: room_keys.rs's SQL names the tables ({named_in_room_keys} lines)"
        );
        assert!(
            strays.is_empty(),
            "I7005: code outside edition2::room_keys names a node-local room-key table: {strays:?}"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies {
    use crate::federation::edition2::room_keys::{RoomBinding, RoomKeyHeld};
    use crate::federation::{Error, FederationDirectory};

    fn iref(n: u8) -> String {
        ciris_verify_core::edition2::identity_ref(&[n; 32])
    }

    fn room(s: &str, n: u8) -> String {
        // a group-ref spelling the table's CHECK admits; never parsed here
        format!("group-i7004{s}{n:02}")
    }

    /// **I7004** — the two tables on one store.
    pub(crate) async fn i7004_the_local_room_key_tables(d: &dyn FederationDirectory, s: &str) {
        let r1 = room(s, 1);
        let r2 = room(s, 2);
        let k = RoomKeyHeld {
            room_key_kid: [0x74; 32],
            room_id: r1.clone(),
            acts_for: iref(0x41),
            created_at_us: 1_000,
            retired_at_us: None,
        };
        assert!(
            d.edition2_put_room_key_local(&k).await.expect("I7004 put"),
            "I7004 a new room key is recorded"
        );
        assert!(
            !d.edition2_put_room_key_local(&k)
                .await
                .expect("I7004 again"),
            "I7004 the same key for the same room again is a no-op"
        );
        let elsewhere = RoomKeyHeld {
            room_id: r2.clone(),
            ..k.clone()
        };
        assert!(
            matches!(
                d.edition2_put_room_key_local(&elsewhere).await,
                Err(Error::Conflict(_))
            ),
            "I7004 a room key is never recorded for a second room"
        );
        assert_eq!(
            d.edition2_room_keys_held(Some(&r1))
                .await
                .expect("I7004 by room"),
            vec![k.clone()],
            "I7004 the key reads back in its room"
        );
        assert!(
            d.edition2_room_keys_held(Some(&r2))
                .await
                .expect("I7004 the other room")
                .is_empty(),
            "I7004 and in no other"
        );
        assert!(
            d.edition2_room_keys_held(None)
                .await
                .expect("I7004 all")
                .contains(&k),
            "I7004 the whole list holds it"
        );

        assert!(
            !d.edition2_retire_room_key_local(&k.room_key_kid, 999)
                .await
                .expect("I7004 retire early"),
            "I7004 a key is never retired before it was recorded"
        );
        assert!(
            d.edition2_retire_room_key_local(&k.room_key_kid, 2_000)
                .await
                .expect("I7004 retire"),
            "I7004 retiring marks it"
        );
        assert!(
            !d.edition2_retire_room_key_local(&k.room_key_kid, 3_000)
                .await
                .expect("I7004 retire again"),
            "I7004 once"
        );
        assert_eq!(
            d.edition2_room_keys_held(Some(&r1))
                .await
                .expect("I7004 after"),
            vec![RoomKeyHeld {
                retired_at_us: Some(2_000),
                ..k.clone()
            }],
            "I7004 the retired row is kept, with its first retirement"
        );

        let b = RoomBinding {
            room_key_kid: [0x75; 32],
            made_for: iref(0x42),
            room_id: r1.clone(),
            person: iref(0x43),
            nonce: [0x76; 32],
            received_at_us: 4_000,
        };
        assert!(
            d.edition2_put_room_binding(&b)
                .await
                .expect("I7004 binding"),
            "I7004 a binding is recorded"
        );
        let second = RoomBinding {
            person: iref(0x44),
            nonce: [0x77; 32],
            received_at_us: 5_000,
            ..b.clone()
        };
        assert!(
            !d.edition2_put_room_binding(&second)
                .await
                .expect("I7004 a second"),
            "I7004 a second binding for the same key and addressee is a no-op"
        );
        assert_eq!(
            d.edition2_room_bindings(&r1).await.expect("I7004 bindings"),
            vec![b],
            "I7004 the first binding is kept and reads back by its room"
        );
        assert!(
            d.edition2_room_bindings(&r2)
                .await
                .expect("I7004 none")
                .is_empty(),
            "I7004 no binding in another room"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..8].to_owned()
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i7004_the_local_room_key_tables_sqlite() {
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(super::bodies::i7004_the_local_room_key_tables(
            &d,
            &suffix(),
        ))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i7004_the_local_room_key_tables_postgres() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        Box::pin(super::bodies::i7004_the_local_room_key_tables(
            &d,
            &suffix(),
        ))
        .await;
        eprintln!("i7004 postgres: RAN");
    }
}
