//! SQLite impl of [`KeyEscrowService`] (CIRISPersist#752).
//!
//! Dialect translations per the V034 conventions: TIMESTAMPTZ → TEXT
//! (RFC 3339). Threading: inline-sync closures over `conn.lock()`.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};

use super::service::KeyEscrowService;
use super::types::{EscrowStatus, EscrowType, KeyEscrowRow};
use super::Error;

/// SQLite-backed [`KeyEscrowService`] impl.
pub struct SqliteKeyEscrowBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteKeyEscrowBackend {
    /// Construct from a shared connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if err.code == ErrorCode::ConstraintViolation {
            let extended = err.extended_code;
            if extended == 787 {
                return Error::Conflict(format!("{op} FK: {e}"));
            }
            if extended == 1555 || extended == 2067 {
                return Error::Conflict(format!("{op} UNIQUE: {e}"));
            }
            return Error::InvalidArgument(format!("{op}: {e}"));
        }
    }
    Error::Backend(format!("{op}: {e}"))
}

fn parse_datetime(s: &str) -> Result<DateTime<Utc>, Error> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::Backend(format!("datetime parse: {e} (raw={s})")))
}

fn fmt_datetime(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn validate_row(r: &KeyEscrowRow) -> Result<(), Error> {
    for (v, what) in [
        (&r.escrow_id, "escrow_id"),
        (&r.key_id, "key_id"),
        (&r.org_id, "org_id"),
        (&r.custodian, "custodian"),
    ] {
        if v.is_empty() {
            return Err(Error::InvalidArgument(format!("{what} required")));
        }
    }
    if r.status != EscrowStatus::Active {
        return Err(Error::InvalidArgument(
            "an escrow is born active; terminal states are reached only through \
             set_escrow_status — one door for the lifecycle"
                .into(),
        ));
    }
    Ok(())
}

fn decode_row(row: &rusqlite::Row<'_>) -> Result<KeyEscrowRow, Error> {
    let ty: String = row
        .get("escrow_type")
        .map_err(|e| Error::Backend(format!("decode escrow_type: {e}")))?;
    let status: String = row
        .get("status")
        .map_err(|e| Error::Backend(format!("decode status: {e}")))?;
    let created: String = row
        .get("created_at")
        .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?;
    let expires: Option<String> = row
        .get("expires_at")
        .map_err(|e| Error::Backend(format!("decode expires_at: {e}")))?;
    let get = |k: &str| -> Result<String, Error> {
        row.get(k)
            .map_err(|e| Error::Backend(format!("decode {k}: {e}")))
    };
    Ok(KeyEscrowRow {
        escrow_id: get("escrow_id")?,
        key_id: get("key_id")?,
        org_id: get("org_id")?,
        escrow_type: EscrowType::parse_str(&ty)
            .ok_or_else(|| Error::Backend(format!("unknown escrow_type `{ty}`")))?,
        custodian: get("custodian")?,
        status: EscrowStatus::parse_str(&status)
            .ok_or_else(|| Error::Backend(format!("unknown status `{status}`")))?,
        created_at: parse_datetime(&created)?,
        expires_at: expires.map(|s| parse_datetime(&s)).transpose()?,
    })
}

const COLUMNS: &str = "escrow_id, key_id, org_id, escrow_type, custodian, status, created_at, \
                       expires_at";

impl KeyEscrowService for SqliteKeyEscrowBackend {
    async fn create_escrow(&self, row: &KeyEscrowRow) -> Result<bool, Error> {
        validate_row(row)?;
        let r = row.clone();
        let created = fmt_datetime(r.created_at);
        let expires = r.expires_at.map(fmt_datetime);
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let mut guard = conn.lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "create_escrow begin"))?;
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO cirislens_key_escrows (\
                        escrow_id, key_id, org_id, escrow_type, custodian, status, \
                        created_at, expires_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        r.escrow_id,
                        r.key_id,
                        r.org_id,
                        r.escrow_type.as_sql_str(),
                        r.custodian,
                        r.status.as_sql_str(),
                        created,
                        expires
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "create_escrow insert"))?;
            if inserted == 1 {
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "create_escrow commit"))?;
                return Ok(true);
            }
            // Occupied id: identical (modulo lifecycle status — a re-offered
            // create must not resurrect a terminal escrow, so only the
            // IMMUTABLE identity columns decide) ⇒ idempotent no-op;
            // differing ⇒ refusal.
            let stored: (String, String, String, String, Option<String>) = tx
                .query_row(
                    "SELECT key_id, org_id, escrow_type, custodian, expires_at \
                     FROM cirislens_key_escrows WHERE escrow_id = ?1",
                    params![r.escrow_id],
                    |x| Ok((x.get(0)?, x.get(1)?, x.get(2)?, x.get(3)?, x.get(4)?)),
                )
                .map_err(|e| map_sqlite_error(e, "create_escrow re-read"))?;
            if stored.0 == r.key_id
                && stored.1 == r.org_id
                && stored.2 == r.escrow_type.as_sql_str()
                && stored.3 == r.custodian
                && stored.4 == expires
            {
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "create_escrow commit"))?;
                return Ok(false);
            }
            Err(Error::Conflict(format!(
                "escrow_id {} exists with different content",
                r.escrow_id
            )))
        })()
    }

    async fn get_escrow(&self, escrow_id: &str) -> Result<Option<KeyEscrowRow>, Error> {
        if escrow_id.is_empty() {
            return Err(Error::InvalidArgument("escrow_id required".into()));
        }
        let eid = escrow_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Option<KeyEscrowRow>, Error> {
            let guard = conn.lock();
            let row = guard
                .query_row(
                    &format!("SELECT {COLUMNS} FROM cirislens_key_escrows WHERE escrow_id = ?1"),
                    params![eid],
                    |r| Ok(decode_row(r)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_escrow"))?;
            row.transpose()
        })()
    }

    async fn list_escrows_for_org(&self, org_id: &str) -> Result<Vec<KeyEscrowRow>, Error> {
        list_by(&self.conn, "org_id", org_id)
    }

    async fn list_escrows_for_key(&self, key_id: &str) -> Result<Vec<KeyEscrowRow>, Error> {
        list_by(&self.conn, "key_id", key_id)
    }

    async fn set_escrow_status(
        &self,
        escrow_id: &str,
        status: EscrowStatus,
    ) -> Result<bool, Error> {
        if escrow_id.is_empty() {
            return Err(Error::InvalidArgument("escrow_id required".into()));
        }
        let eid = escrow_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let mut guard = conn.lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "set_escrow_status begin"))?;
            let current: Option<String> = tx
                .query_row(
                    "SELECT status FROM cirislens_key_escrows WHERE escrow_id = ?1",
                    params![eid],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "set_escrow_status read"))?;
            let Some(current) = current else {
                return Err(Error::NotFound(format!("escrow {eid} does not exist")));
            };
            let current = EscrowStatus::parse_str(&current)
                .ok_or_else(|| Error::Backend(format!("unknown stored status `{current}`")))?;
            if current == status {
                return Ok(false); // idempotent re-assertion
            }
            if current.is_terminal() {
                return Err(Error::Conflict(format!(
                    "escrow {eid} is {} — a custody outcome pins, it never flips",
                    current.as_sql_str()
                )));
            }
            tx.execute(
                "UPDATE cirislens_key_escrows SET status = ?2 WHERE escrow_id = ?1",
                params![eid, status.as_sql_str()],
            )
            .map_err(|e| map_sqlite_error(e, "set_escrow_status update"))?;
            tx.commit()
                .map_err(|e| map_sqlite_error(e, "set_escrow_status commit"))?;
            Ok(true)
        })()
    }
}

fn list_by(
    conn: &Arc<Mutex<Connection>>,
    column: &'static str,
    value: &str,
) -> Result<Vec<KeyEscrowRow>, Error> {
    if value.is_empty() {
        return Err(Error::InvalidArgument(format!("{column} required")));
    }
    let value = value.to_owned();
    let guard = conn.lock();
    let mut stmt = guard
        .prepare(&format!(
            "SELECT {COLUMNS} FROM cirislens_key_escrows WHERE {column} = ?1 ORDER BY escrow_id"
        ))
        .map_err(|e| map_sqlite_error(e, "list_escrows prepare"))?;
    let rows = stmt
        .query_map(params![value], |r| Ok(decode_row(r)))
        .map_err(|e| map_sqlite_error(e, "list_escrows query"))?;
    let mut out = Vec::new();
    for r in rows {
        out.push(r.map_err(|e| map_sqlite_error(e, "list_escrows row"))??);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::backend::Backend as _;
    use crate::store::sqlite::SqliteBackend;

    async fn fresh() -> (SqliteBackend, SqliteKeyEscrowBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteKeyEscrowBackend::new(backend.conn_handle());
        (backend, svc)
    }

    fn row(id: &str) -> KeyEscrowRow {
        KeyEscrowRow {
            escrow_id: id.into(),
            key_id: "key-1".into(),
            org_id: "org-1".into(),
            escrow_type: EscrowType::DualCustody,
            custodian: "steward-a+steward-b".into(),
            status: EscrowStatus::Active,
            created_at: Utc::now(),
            expires_at: None,
        }
    }

    #[tokio::test]
    async fn create_is_idempotent_and_conflicts_on_difference() {
        let (_b, svc) = fresh().await;
        assert!(svc.create_escrow(&row("e1")).await.unwrap());
        assert!(!svc.create_escrow(&row("e1")).await.unwrap());
        let mut differing = row("e1");
        differing.custodian = "attorney-x".into();
        assert_eq!(
            svc.create_escrow(&differing).await.unwrap_err().kind(),
            "key_escrows_conflict"
        );
        // Born active, one lifecycle door: a non-active create refuses.
        let mut born_dead = row("e2");
        born_dead.status = EscrowStatus::Revoked;
        assert_eq!(
            svc.create_escrow(&born_dead).await.unwrap_err().kind(),
            "key_escrows_invalid_argument"
        );
        let got = svc.get_escrow("e1").await.unwrap().unwrap();
        assert_eq!(got.escrow_type, EscrowType::DualCustody);
    }

    #[tokio::test]
    async fn lifecycle_pins_terminal_states() {
        let (_b, svc) = fresh().await;
        svc.create_escrow(&row("e1")).await.unwrap();
        // Same-state no-op.
        assert!(!svc
            .set_escrow_status("e1", EscrowStatus::Active)
            .await
            .unwrap());
        assert!(svc
            .set_escrow_status("e1", EscrowStatus::Recovered)
            .await
            .unwrap());
        // Idempotent terminal re-assertion.
        assert!(!svc
            .set_escrow_status("e1", EscrowStatus::Recovered)
            .await
            .unwrap());
        // A custody outcome pins — every way out of terminal refuses.
        for next in [
            EscrowStatus::Active,
            EscrowStatus::Revoked,
            EscrowStatus::Expired,
        ] {
            assert_eq!(
                svc.set_escrow_status("e1", next).await.unwrap_err().kind(),
                "key_escrows_conflict"
            );
        }
        assert_eq!(
            svc.set_escrow_status("nope", EscrowStatus::Revoked)
                .await
                .unwrap_err()
                .kind(),
            "key_escrows_not_found"
        );
        // And a re-offered create must not resurrect it (the RPC's retry
        // path): identical identity columns ⇒ no-op, status untouched.
        assert!(!svc.create_escrow(&row("e1")).await.unwrap());
        assert_eq!(
            svc.get_escrow("e1").await.unwrap().unwrap().status,
            EscrowStatus::Recovered
        );
    }

    #[tokio::test]
    async fn the_two_indexes_answer_the_two_recovery_questions() {
        let (_b, svc) = fresh().await;
        svc.create_escrow(&row("e1")).await.unwrap();
        let mut other_key = row("e2");
        other_key.key_id = "key-2".into();
        svc.create_escrow(&other_key).await.unwrap();
        let mut other_org = row("e3");
        other_org.org_id = "org-2".into();
        svc.create_escrow(&other_org).await.unwrap();

        let by_org = svc.list_escrows_for_org("org-1").await.unwrap();
        assert_eq!(
            by_org
                .iter()
                .map(|r| r.escrow_id.as_str())
                .collect::<Vec<_>>(),
            ["e1", "e2"]
        );
        let by_key = svc.list_escrows_for_key("key-1").await.unwrap();
        assert_eq!(
            by_key
                .iter()
                .map(|r| r.escrow_id.as_str())
                .collect::<Vec<_>>(),
            ["e1", "e3"]
        );
    }
}
