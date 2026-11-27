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
//!
//! v62.0.0 (ROOMKEY-3b; PRE4-V300-h; the lead's item 11) — the voice ↔ person
//! tie SEALED at rest:
//! - **I7120** (pure) — `person_tag` is deterministic per (master, room,
//!   person) and differs across rooms and masters; a tie opens back to its
//!   person and nonce; it does not open under another master, and a sealed
//!   blob that is no tie is refused, never read.
//! - **I7121** (sqlite + postgres):
//!   - a binding reads back in the clear through the directory, but its row
//!     holds neither the person nor the nonce;
//!   - "a person already seated" is found by the person's tag, in its room
//!     only;
//!   - a row whose `tie_key_kind` names a master this node does not hold, or
//!     whose seal does not open, is a REFUSAL to read (`Err`), never a row
//!     left out;
//!   - the lookup's SQL filters by `person_tag` (no scan that opens every
//!     row: I7005's from-disk leg).
//!
//! v62.0.0 (ROOMKEY-E1; the lead's item 12) — erasure, three cases, node-local:
//! - **I7122** (sqlite + postgres) — over seeded rows of all four tables:
//!   - (a) dropping a room removes that room's bindings and pending exchanges
//!     and nothing else;
//!   - (b) a person's erasure on their own device removes that person's room
//!     keys, their KEM secrets, the exchanges addressed to them and the
//!     person's binding secret, and keeps the bindings held of others;
//!   - (c) device retirement empties every table, and a second (c) removes
//!     nothing.
//! - **I7123** (from disk) — case (c), on both backends, names every node-local
//!   table that names a person or holds a secret (`ceg_room_keys_local`,
//!   `ceg_room_kem_secrets`, `ceg_room_binding_exchanges`, `ceg_room_bindings`).

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

    /// I7121 (from disk) — the person lookup filters by the keyed tag through
    /// the index, on both backends: never by the clear value, never a scan.
    #[test]
    fn i7121_the_person_lookup_is_by_the_keyed_tag() {
        let src = include_str!("room_keys.rs");
        for c in [
            "SELECT_BINDINGS_OF_PERSON_SQLITE",
            "SELECT_BINDINGS_OF_PERSON_POSTGRES",
        ] {
            let at = src
                .find(&format!("const {c}"))
                .unwrap_or_else(|| panic!("I7121: {c}"));
            let sql = &src[at..at + src[at..].find("\";").expect("I7121: the literal ends")];
            assert!(
                sql.contains("AND person_tag = "),
                "I7121: {c} filters by person_tag"
            );
            assert!(
                !sql.contains(" person ="),
                "I7121: {c} never by a clear person"
            );
        }
    }
}

#[cfg(test)]
mod from_disk_e1 {
    /// I7123 — case (c) reaches every node-local table, on both backends.
    #[test]
    fn i7123_device_retirement_reaches_every_room_table() {
        use super::super::room_keys::{
            ROOM_BINDINGS_TABLE, ROOM_EXCHANGES_TABLE, ROOM_KEM_SECRETS_TABLE as ROOM_KEMS,
            ROOM_KEYS_TABLE,
        };
        let src = include_str!("room_keys.rs");
        for f in [
            "pub fn erase_room_device_state_sqlite(",
            "pub async fn erase_room_device_state_postgres(",
        ] {
            let at = src.find(f).unwrap_or_else(|| panic!("I7123: {f}"));
            let body = &src[at..at + src[at..].find("\n}\n").expect("I7123: the body ends")];
            for t in [
                ROOM_KEYS_TABLE,
                ROOM_KEMS,
                ROOM_EXCHANGES_TABLE,
                ROOM_BINDINGS_TABLE,
            ] {
                assert!(
                    body.contains(&format!("DELETE FROM {t}"))
                        || body.contains(&format!("DELETE FROM cirislens.{t}")),
                    "I7123: {f} empties {t}"
                );
            }
        }
    }
}

#[cfg(test)]
mod pure_3b {
    use super::super::room_keys::{open_tie, person_tag, seal_tie};

    /// I7120 — the tag and the seal.
    #[test]
    fn i7120_the_tag_and_the_sealed_tie() {
        let (m1, m2) = ([0x31u8; 32], [0x32u8; 32]);
        let p = "urn:ietf:params:oauth:ckt:sha-256:person";
        let t = person_tag(&m1, "group-a", p).unwrap();
        assert_eq!(
            t,
            person_tag(&m1, "group-a", p).unwrap(),
            "I7120 deterministic"
        );
        assert_ne!(
            t,
            person_tag(&m1, "group-b", p).unwrap(),
            "I7120 keyed per room"
        );
        assert_ne!(
            t,
            person_tag(&m2, "group-a", p).unwrap(),
            "I7120 keyed by the master"
        );
        assert_ne!(
            t,
            person_tag(&m1, "group-a", "urn:ietf:params:oauth:ckt:sha-256:other").unwrap()
        );
        let sealed = seal_tie(&m1, p, &[0x07; 32]).unwrap();
        assert!(
            !sealed.contains("person"),
            "I7120 the sealed text names no one"
        );
        assert_eq!(open_tie(&m1, &sealed).unwrap(), (p.to_owned(), [0x07; 32]));
        assert!(
            open_tie(&m2, &sealed).is_err(),
            "I7120 another master opens nothing"
        );
        let not_a_tie =
            crate::federation::identity_aggregate::seal_content_kem_private(&m1, &[1u8; 40])
                .unwrap();
        assert!(
            open_tie(&m1, &not_a_tie).is_err(),
            "I7120 a blob that is no tie is refused"
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
pub(crate) mod bodies_3b {
    use crate::federation::edition2::room_keys::RoomBinding;
    use crate::federation::FederationDirectory;

    pub(crate) fn binding(s: &str, person: &str) -> RoomBinding {
        RoomBinding {
            room_key_kid: [0x81; 32],
            made_for: ciris_verify_core::edition2::identity_ref(&[0x82; 32]),
            room_id: format!("group-i7121{s}"),
            person: person.to_owned(),
            nonce: [0x83; 32],
            received_at_us: 7_000,
        }
    }

    /// I7121, the directory half: read back in the clear; found by person.
    pub(crate) async fn i7121_through_the_directory(d: &dyn FederationDirectory, s: &str) {
        let p1 = ciris_verify_core::edition2::identity_ref(&[0x84; 32]);
        let p2 = ciris_verify_core::edition2::identity_ref(&[0x85; 32]);
        let b = binding(s, &p1);
        assert!(d.edition2_put_room_binding(&b).await.expect("I7121 put"));
        assert_eq!(
            d.edition2_room_bindings(&b.room_id)
                .await
                .expect("I7121 read"),
            vec![b.clone()],
            "I7121 the binding reads back in the clear"
        );
        assert_eq!(
            d.edition2_room_bindings_of_person(&b.room_id, &p1)
                .await
                .expect("I7121 lookup"),
            vec![b.clone()],
            "I7121 the person is found seated by their tag"
        );
        assert!(
            d.edition2_room_bindings_of_person(&b.room_id, &p2)
                .await
                .expect("I7121 another")
                .is_empty(),
            "I7121 another person is not"
        );
        assert!(
            d.edition2_room_bindings_of_person(&format!("group-i7121x{s}"), &p1)
                .await
                .expect("I7121 another room")
                .is_empty(),
            "I7121 nor the same person in another room"
        );
    }

    /// The raw row holds neither the person nor the nonce.
    pub(crate) fn assert_nothing_clear(tag: &[u8], sealed: &str, person: &str) {
        use base64::Engine as _;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(sealed)
            .expect("I7121 sealed is base64");
        for hay in [raw.as_slice(), sealed.as_bytes(), tag] {
            assert!(
                !hay.windows(person.len()).any(|w| w == person.as_bytes()),
                "I7121 the row holds no clear person"
            );
            assert!(
                !hay.windows(32).any(|w| w == [0x83; 32]),
                "I7121 the row holds no clear nonce"
            );
        }
    }

    /// The refusal leg: `room_bindings` answers Err, never a shorter list.
    pub(crate) async fn assert_refused(d: &dyn FederationDirectory, room: &str, what: &str) {
        assert!(
            d.edition2_room_bindings(room).await.is_err(),
            "I7121 {what}: a refusal to read, never a row left out"
        );
    }
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
pub(crate) mod bodies_e1 {
    use crate::federation::edition2::room_keys::{RoomBinding, RoomErasure, RoomKeyHeld};
    use crate::federation::FederationDirectory;

    pub(crate) fn iref(n: u8) -> String {
        ciris_verify_core::edition2::identity_ref(&[n; 32])
    }
    pub(crate) fn room(s: &str, n: u8) -> String {
        format!("group-i7122{s}{n}")
    }
    /// The seeded rows the raw SQL of each runner writes:
    /// `(purpose, digest byte, room_key_kid byte or None, identity_ref or None)`
    /// for the KEM secrets, and `(room_key_kid byte, made_for, room)` for the
    /// exchanges.
    pub(crate) fn kem_rows() -> Vec<(&'static str, u8, Option<u8>, Option<String>)> {
        vec![
            ("room_key", 0xa1, Some(0x91), None),
            ("room_key", 0xa2, Some(0x92), None),
            ("room_key", 0xa3, Some(0x93), None),
            ("room_binding", 0xa4, None, Some(iref(0x51))),
            ("room_binding", 0xa5, None, Some(iref(0x52))),
        ]
    }
    pub(crate) fn exchange_rows(s: &str) -> Vec<(u8, String, String)> {
        vec![
            (0xb1, iref(0x91), room(s, 1)),
            (0xb2, iref(0x93), room(s, 1)),
            (0xb3, iref(0x92), room(s, 2)),
        ]
    }

    /// Keys and bindings through the directory (before the raw seeds).
    pub(crate) async fn seed(d: &dyn FederationDirectory, s: &str) {
        for (k, who, r) in [(0x91, 0x51, 1), (0x92, 0x51, 2), (0x93, 0x52, 1)] {
            d.edition2_put_room_key_local(&RoomKeyHeld {
                room_key_kid: [k; 32],
                room_id: room(s, r),
                acts_for: iref(who),
                created_at_us: 1,
                retired_at_us: None,
            })
            .await
            .unwrap();
        }
        for (made_for, r, who) in [(0x91, 1, 0x61), (0x92, 2, 0x62), (0x93, 1, 0x63)] {
            d.edition2_put_room_binding(&RoomBinding {
                room_key_kid: [0x71; 32],
                made_for: iref(made_for),
                room_id: room(s, r),
                person: iref(who),
                nonce: [0x72; 32],
                received_at_us: 2,
            })
            .await
            .unwrap();
        }
    }

    /// I7122 — the three cases, after `seed` and the runner's raw rows.
    pub(crate) async fn i7122_the_three_erasure_cases(d: &dyn FederationDirectory, s: &str) {
        let (r1, r2) = (room(s, 1), room(s, 2));
        assert_eq!(
            d.edition2_drop_room_bindings(&r1).await.unwrap(),
            RoomErasure {
                exchanges: 2,
                bindings: 2,
                ..RoomErasure::default()
            },
            "I7122 (a) the room's bindings and exchanges go"
        );
        assert_eq!(
            d.edition2_room_keys_held(None).await.unwrap().len(),
            3,
            "I7122 (a) keys stay"
        );
        assert_eq!(
            d.edition2_room_bindings(&r2).await.unwrap().len(),
            1,
            "I7122 (a) other rooms stay"
        );

        assert_eq!(
            d.edition2_erase_person_room_keys(&iref(0x51))
                .await
                .unwrap(),
            RoomErasure {
                room_keys: 2,
                kem_secrets: 3,
                exchanges: 1,
                bindings: 0,
            },
            "I7122 (b) the person's keys, secrets and exchanges go"
        );
        let held = d.edition2_room_keys_held(None).await.unwrap();
        assert_eq!(held.len(), 1, "I7122 (b) another person's key stays");
        assert_eq!(held[0].acts_for, iref(0x52));
        assert_eq!(
            d.edition2_room_bindings(&r2).await.unwrap().len(),
            1,
            "I7122 (b) the bindings held of others are kept"
        );

        assert_eq!(
            d.edition2_erase_room_device_state().await.unwrap(),
            RoomErasure {
                room_keys: 1,
                kem_secrets: 2,
                exchanges: 0,
                bindings: 1,
            },
            "I7122 (c) every table is emptied"
        );
        assert_eq!(
            d.edition2_erase_room_device_state().await.unwrap(),
            RoomErasure::default(),
            "I7122 (c) nothing is left"
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

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i7121_the_sealed_tie_sqlite() {
        use super::bodies_3b as b;
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        let s = suffix();
        Box::pin(b::i7121_through_the_directory(&d, &s)).await;
        let room = b::binding(&s, "").room_id;
        let person = ciris_verify_core::edition2::identity_ref(&[0x84; 32]);
        let r = room.clone();
        let (tag, sealed): (Vec<u8>, String) = d
            .read(move |c| {
                c.query_row(
                    "SELECT person_tag, tie_sealed_b64 FROM ceg_room_bindings WHERE room_id = ?1",
                    [&r],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
            })
            .await
            .unwrap();
        b::assert_nothing_clear(&tag, &sealed, &person);
        let r = room.clone();
        d.write(move |c| {
            c.execute(
                "UPDATE ceg_room_bindings SET tie_key_kind = CASE tie_key_kind \
                 WHEN 'software' THEN 'hardware' ELSE 'software' END WHERE room_id = ?1",
                [&r],
            )
        })
        .await
        .unwrap();
        b::assert_refused(&d, &room, "a master this node does not hold").await;
        let r = room.clone();
        d.write(move |c| {
            c.execute(
                "UPDATE ceg_room_bindings SET tie_key_kind = CASE tie_key_kind \
                 WHEN 'software' THEN 'hardware' ELSE 'software' END, \
                 tie_sealed_b64 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE room_id = ?1",
                [&r],
            )
        })
        .await
        .unwrap();
        b::assert_refused(&d, &room, "a seal that does not open").await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i7121_the_sealed_tie_postgres() {
        use super::bodies_3b as b;
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        let s = suffix();
        Box::pin(b::i7121_through_the_directory(&d, &s)).await;
        let room = b::binding(&s, "").room_id;
        let person = ciris_verify_core::edition2::identity_ref(&[0x84; 32]);
        let c = d.get_client().await.unwrap();
        let row = c
            .query_one(
                "SELECT person_tag, tie_sealed_b64 FROM cirislens.ceg_room_bindings \
                 WHERE room_id = $1",
                &[&room],
            )
            .await
            .unwrap();
        let (tag, sealed): (Vec<u8>, String) = (row.get(0), row.get(1));
        b::assert_nothing_clear(&tag, &sealed, &person);
        c.execute(
            "UPDATE cirislens.ceg_room_bindings SET tie_key_kind = CASE tie_key_kind \
             WHEN 'software' THEN 'hardware' ELSE 'software' END WHERE room_id = $1",
            &[&room],
        )
        .await
        .unwrap();
        b::assert_refused(&d, &room, "a master this node does not hold").await;
        c.execute(
            "UPDATE cirislens.ceg_room_bindings SET tie_key_kind = CASE tie_key_kind \
             WHEN 'software' THEN 'hardware' ELSE 'software' END, \
             tie_sealed_b64 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAA' WHERE room_id = $1",
            &[&room],
        )
        .await
        .unwrap();
        b::assert_refused(&d, &room, "a seal that does not open").await;
        eprintln!("i7121 postgres: RAN");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i7122_the_three_erasure_cases_sqlite() {
        use super::bodies_e1 as b;
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        let s = suffix();
        Box::pin(b::seed(&d, &s)).await;
        let (kems, ex) = (b::kem_rows(), b::exchange_rows(&s));
        d.write(move |c| -> rusqlite::Result<()> {
            for (purpose, dg, kid, who) in kems {
                c.execute(
                    "INSERT INTO ceg_room_kem_secrets (xwing_pubkey_digest, purpose, room_key_kid, \
                     identity_ref, xwing_pubkey, key_kind, secret_sealed_b64, created_at_us) \
                     VALUES (?1, ?2, ?3, ?4, ?5, 'software', 'c2VhbGVk', 1)",
                    rusqlite::params![
                        vec![dg; 32],
                        purpose,
                        kid.map(|k| vec![k; 32]),
                        who,
                        vec![0x5a; 1216]
                    ],
                )?;
            }
            for (tag, made_for, room) in ex {
                c.execute(
                    "INSERT INTO ceg_room_binding_exchanges (room_key_kid, made_for, room_id, \
                     person_tag, claim_key_kind, claim_sealed_b64, state, claimed_at_us) \
                     VALUES (?1, ?2, ?3, ?4, 'software', 'c2VhbGVk', 'claimed', 1)",
                    rusqlite::params![vec![tag; 32], made_for, room, vec![tag; 32]],
                )?;
            }
            Ok(())
        })
        .await
        .unwrap();
        Box::pin(b::i7122_the_three_erasure_cases(&d, &s)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i7122_the_three_erasure_cases_postgres() {
        use super::bodies_e1 as b;
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        let s = suffix();
        Box::pin(b::seed(&d, &s)).await;
        let c = d.get_client().await.unwrap();
        for (purpose, dg, kid, who) in b::kem_rows() {
            let (dg, kid, pk) = (vec![dg; 32], kid.map(|k| vec![k; 32]), vec![0x5a_u8; 1216]);
            c.execute(
                "INSERT INTO cirislens.ceg_room_kem_secrets (xwing_pubkey_digest, purpose, \
                 room_key_kid, identity_ref, xwing_pubkey, key_kind, secret_sealed_b64, \
                 created_at_us) VALUES ($1, $2, $3, $4, $5, 'software', 'c2VhbGVk', 1)",
                &[&dg, &purpose, &kid, &who, &pk],
            )
            .await
            .unwrap();
        }
        for (tag, made_for, room) in b::exchange_rows(&s) {
            let tag = vec![tag; 32];
            c.execute(
                "INSERT INTO cirislens.ceg_room_binding_exchanges (room_key_kid, made_for, \
                 room_id, person_tag, claim_key_kind, claim_sealed_b64, state, claimed_at_us) \
                 VALUES ($1, $2, $3, $4, 'software', 'c2VhbGVk', 'claimed', 1)",
                &[&tag, &made_for, &room, &tag],
            )
            .await
            .unwrap();
        }
        drop(c);
        Box::pin(b::i7122_the_three_erasure_cases(&d, &s)).await;
        eprintln!("i7122 postgres: RAN");
    }
}
