//! v62.0.0 (CC 2.7, wave P9) — **a foreign-key refusal is the one wait,
//! on both backends.**
//!
//! A store step whose foreign key refuses the insert means a row the write
//! names is not held here yet. Under CC 2.7 that answers WAITING:
//! [`Error::LinkNotHeld`] (`federation_link_not_held`, [`Error::is_wait`]).
//! Before v62 sqlite answered the terminal `federation_invalid_argument`, and
//! five postgres arms tested `e.to_string().contains("foreign key")`, which
//! never fires: tokio-postgres renders a database error as the bare
//! `db error`, so the same fact reached a pg host as `federation_backend`.
//!
//! - **I3604 (sqlite).** A real `FOREIGN KEY constraint failed` from rusqlite,
//!   through the store's mapper, is `LinkNotHeld` under the mapper's plane,
//!   `federation_link_not_held`, a wait; a UNIQUE violation through the same
//!   mapper is NOT a wait (`federation_backend`).
//! - **I3605 (postgres).** A real SQLSTATE 23503 from tokio-postgres is read
//!   by its CODE: the error's `Display` carries no "foreign key" (the reason
//!   the five string arms were dead), and both the revocation mapper and the
//!   shared insert mapper answer `LinkNotHeld` under the same plane sqlite
//!   answers, the same kind, a wait; a 23505 is `pg_is_unique_violation` and
//!   not a wait.
//!
//! The parent/child tables are the witness's own (sqlite in-memory; postgres
//! `TEMP` tables, session-local), so the witness reads the DRIVERS' errors,
//! not a schema that a planner pre-check may keep the store from reaching.

use crate::federation::Error;

/// The plane both legs map under (one of the store's real revocation planes).
const PLANE: &str = "family_membership_revocation";

/// The shared reading of a mapped FK refusal.
fn assert_link_not_held(e: &Error, leg: &str) {
    assert_eq!(e.kind(), "federation_link_not_held", "{leg}: the kind: {e}");
    assert!(e.is_wait(), "{leg}: a wait: {e}");
    match e {
        Error::LinkNotHeld { plane, .. } => assert_eq!(*plane, PLANE, "{leg}: the plane"),
        other => panic!("{leg}: expected LinkNotHeld, got {other:?}"),
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;

    fn conn() -> rusqlite::Connection {
        let c = rusqlite::Connection::open_in_memory().expect("open");
        c.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE p9_parent (id TEXT PRIMARY KEY);
             CREATE TABLE p9_child (id TEXT PRIMARY KEY,
                                    parent TEXT NOT NULL REFERENCES p9_parent(id));
             INSERT INTO p9_parent (id) VALUES ('held');",
        )
        .expect("schema");
        c
    }

    /// I3604 — sqlite: the driver's FK refusal is the wait; a UNIQUE
    /// refusal is not.
    #[test]
    fn i3604_sqlite_fk_refusal_is_link_not_held() {
        let c = conn();
        let fk = c
            .execute(
                "INSERT INTO p9_child (id, parent) VALUES ('c1', 'not-held')",
                [],
            )
            .expect_err("I3604: the FK refuses");
        let e =
            crate::store::sqlite::map_revocation_sqlite_err(PLANE, vec!["not-held".to_owned()])(fk);
        assert_link_not_held(&e, "I3604 sqlite");

        c.execute(
            "INSERT INTO p9_child (id, parent) VALUES ('c2', 'held')",
            [],
        )
        .expect("I3604: a held parent admits");
        let dup = c
            .execute(
                "INSERT INTO p9_child (id, parent) VALUES ('c2', 'held')",
                [],
            )
            .expect_err("I3604: the PK refuses");
        let e = crate::store::sqlite::map_revocation_sqlite_err(PLANE, vec!["not-held".to_owned()])(
            dup,
        );
        assert!(!e.is_wait(), "I3604: a UNIQUE refusal is not a wait: {e}");
        assert_eq!(e.kind(), "federation_backend", "I3604: {e}");
    }
}

#[cfg(feature = "postgres")]
mod pg {
    use super::*;

    /// I3605 — postgres: SQLSTATE 23503 read by its code is the wait, under
    /// the same plane and kind as sqlite; 23505 is not.
    #[tokio::test]
    async fn i3605_postgres_fk_refusal_is_link_not_held_by_sqlstate() {
        let Some(dsn) = crate::test_pg::dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let (client, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
            .await
            .expect("connect");
        tokio::spawn(conn);
        client
            .batch_execute(
                "CREATE TEMP TABLE p9_parent (id TEXT PRIMARY KEY);
                 CREATE TEMP TABLE p9_child (id TEXT PRIMARY KEY,
                                             parent TEXT NOT NULL REFERENCES p9_parent(id));
                 INSERT INTO p9_parent (id) VALUES ('held');",
            )
            .await
            .expect("schema");

        let insert = "INSERT INTO p9_child (id, parent) VALUES ($1, $2)";
        let fk = client
            .execute(insert, &[&"c1", &"not-held"])
            .await
            .expect_err("I3605: the FK refuses");
        assert!(
            crate::store::postgres::pg_is_fk_violation(&fk),
            "I3605: SQLSTATE 23503"
        );
        assert!(
            !fk.to_string().to_lowercase().contains("foreign key"),
            "I3605: the Display carries no 'foreign key' ({fk}) — a text test never fires"
        );
        let e = crate::store::postgres::pg_federation_insert_err(PLANE, "insert p9_child", &fk);
        assert_link_not_held(&e, "I3605 shared mapper");
        let fk_again = client
            .execute(insert, &[&"c1", &"not-held"])
            .await
            .expect_err("I3605: the FK refuses again");
        let e = crate::store::postgres::map_revocation_pg_err(PLANE, &["not-held"])(fk_again);
        assert_link_not_held(&e, "I3605 revocation mapper");

        client
            .execute(insert, &[&"c2", &"held"])
            .await
            .expect("I3605: a held parent admits");
        let dup = client
            .execute(insert, &[&"c2", &"held"])
            .await
            .expect_err("I3605: the PK refuses");
        assert!(
            crate::store::postgres::pg_is_unique_violation(&dup),
            "I3605: SQLSTATE 23505"
        );
        assert!(
            !crate::store::postgres::pg_is_fk_violation(&dup),
            "I3605: a UNIQUE refusal is not a FK refusal"
        );
        let e = crate::store::postgres::pg_federation_insert_err(PLANE, "insert p9_child", &dup);
        assert!(!e.is_wait(), "I3605: a UNIQUE refusal is not a wait: {e}");
        assert_eq!(e.kind(), "federation_backend", "I3605: {e}");
        assert!(
            e.is_duplicate_key(),
            "I3605: the detail now carries SQLSTATE 23505, which is_duplicate_key reads: {e}"
        );
    }
}
