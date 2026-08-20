//! PostgreSQL impl of [`KeyEscrowService`] (CIRISPersist#752).
//!
//! Timestamps cross as `chrono::DateTime<Utc>` (TIMESTAMPTZ). No mutex
//! serializes writers here, so the #719 absorb-then-re-read discipline is
//! load-bearing on `create_escrow`, and `set_escrow_status` guards its
//! transition in the UPDATE's own WHERE clause so a concurrent terminal
//! transition cannot be overwritten.

use super::service::KeyEscrowService;
use super::types::{EscrowStatus, EscrowType, KeyEscrowRow};
use super::Error;
use crate::store::postgres::PostgresBackend;

fn map_pg_error(e: tokio_postgres::Error, op: &str) -> Error {
    use tokio_postgres::error::SqlState;
    let code = e.as_db_error().map(|d| d.code().clone());
    let detail = e
        .as_db_error()
        .map(|d| d.message().to_owned())
        .unwrap_or_else(|| e.to_string());
    match code {
        Some(c) if c == SqlState::CHECK_VIOLATION => {
            Error::InvalidArgument(format!("{op} CHECK: {detail}"))
        }
        Some(c) if c == SqlState::UNIQUE_VIOLATION => {
            Error::Conflict(format!("{op} UNIQUE: {detail}"))
        }
        Some(c) if c == SqlState::NOT_NULL_VIOLATION => {
            Error::InvalidArgument(format!("{op} NOT NULL: {detail}"))
        }
        Some(c) if c == SqlState::FOREIGN_KEY_VIOLATION => {
            Error::Conflict(format!("{op} FK: {detail}"))
        }
        _ => Error::Backend(format!("{op}: {detail}")),
    }
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

fn decode_row(row: &tokio_postgres::Row) -> Result<KeyEscrowRow, Error> {
    let get = |k: &str| -> Result<String, Error> {
        row.try_get(k)
            .map_err(|e| Error::Backend(format!("decode {k}: {e}")))
    };
    let ty = get("escrow_type")?;
    let status = get("status")?;
    Ok(KeyEscrowRow {
        escrow_id: get("escrow_id")?,
        key_id: get("key_id")?,
        org_id: get("org_id")?,
        escrow_type: EscrowType::parse_str(&ty)
            .ok_or_else(|| Error::Backend(format!("unknown escrow_type `{ty}`")))?,
        custodian: get("custodian")?,
        status: EscrowStatus::parse_str(&status)
            .ok_or_else(|| Error::Backend(format!("unknown status `{status}`")))?,
        created_at: row
            .try_get("created_at")
            .map_err(|e| Error::Backend(format!("decode created_at: {e}")))?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|e| Error::Backend(format!("decode expires_at: {e}")))?,
    })
}

const COLUMNS: &str = "escrow_id, key_id, org_id, escrow_type, custodian, status, created_at, \
                       expires_at";

impl KeyEscrowService for PostgresBackend {
    async fn create_escrow(&self, row: &KeyEscrowRow) -> Result<bool, Error> {
        validate_row(row)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let inserted = client
            .execute(
                "INSERT INTO cirislens.key_escrows (\
                    escrow_id, key_id, org_id, escrow_type, custodian, status, \
                    created_at, expires_at\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
                 ON CONFLICT DO NOTHING",
                &[
                    &row.escrow_id,
                    &row.key_id,
                    &row.org_id,
                    &row.escrow_type.as_sql_str(),
                    &row.custodian,
                    &row.status.as_sql_str(),
                    &row.created_at,
                    &row.expires_at,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "create_escrow insert"))?;
        if inserted == 1 {
            return Ok(true);
        }
        // Occupied id: only the IMMUTABLE identity columns decide, so a
        // re-offered create cannot resurrect a terminal escrow.
        let stored = client
            .query_one(
                "SELECT key_id, org_id, escrow_type, custodian, expires_at \
                 FROM cirislens.key_escrows WHERE escrow_id = $1",
                &[&row.escrow_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "create_escrow re-read"))?;
        let (k, o, t, c, x): (
            String,
            String,
            String,
            String,
            Option<chrono::DateTime<chrono::Utc>>,
        ) = (
            stored
                .try_get(0)
                .map_err(|e| Error::Backend(e.to_string()))?,
            stored
                .try_get(1)
                .map_err(|e| Error::Backend(e.to_string()))?,
            stored
                .try_get(2)
                .map_err(|e| Error::Backend(e.to_string()))?,
            stored
                .try_get(3)
                .map_err(|e| Error::Backend(e.to_string()))?,
            stored
                .try_get(4)
                .map_err(|e| Error::Backend(e.to_string()))?,
        );
        if k == row.key_id
            && o == row.org_id
            && t == row.escrow_type.as_sql_str()
            && c == row.custodian
            && x == row.expires_at
        {
            return Ok(false);
        }
        Err(Error::Conflict(format!(
            "escrow_id {} exists with different content",
            row.escrow_id
        )))
    }

    async fn get_escrow(&self, escrow_id: &str) -> Result<Option<KeyEscrowRow>, Error> {
        if escrow_id.is_empty() {
            return Err(Error::InvalidArgument("escrow_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row = client
            .query_opt(
                &format!("SELECT {COLUMNS} FROM cirislens.key_escrows WHERE escrow_id = $1"),
                &[&escrow_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_escrow"))?;
        row.map(|r| decode_row(&r)).transpose()
    }

    async fn list_escrows_for_org(&self, org_id: &str) -> Result<Vec<KeyEscrowRow>, Error> {
        self.list_by("org_id", org_id).await
    }

    async fn list_escrows_for_key(&self, key_id: &str) -> Result<Vec<KeyEscrowRow>, Error> {
        self.list_by("key_id", key_id).await
    }

    async fn set_escrow_status(
        &self,
        escrow_id: &str,
        status: EscrowStatus,
    ) -> Result<bool, Error> {
        if escrow_id.is_empty() {
            return Err(Error::InvalidArgument("escrow_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // Guarded transition: only an ACTIVE row moves. Zero rows re-reads
        // to classify (missing / same-state no-op / terminal refusal) — a
        // concurrent terminal transition loses no information.
        let moved = client
            .execute(
                "UPDATE cirislens.key_escrows SET status = $2 \
                 WHERE escrow_id = $1 AND status = 'active'",
                &[&escrow_id, &status.as_sql_str()],
            )
            .await
            .map_err(|e| map_pg_error(e, "set_escrow_status update"))?;
        if moved == 1 {
            return Ok(status != EscrowStatus::Active);
        }
        let current = client
            .query_opt(
                "SELECT status FROM cirislens.key_escrows WHERE escrow_id = $1",
                &[&escrow_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "set_escrow_status re-read"))?;
        let Some(current) = current else {
            return Err(Error::NotFound(format!(
                "escrow {escrow_id} does not exist"
            )));
        };
        let current: String = current
            .try_get(0)
            .map_err(|e| Error::Backend(e.to_string()))?;
        let current = EscrowStatus::parse_str(&current)
            .ok_or_else(|| Error::Backend(format!("unknown stored status `{current}`")))?;
        if current == status {
            return Ok(false);
        }
        Err(Error::Conflict(format!(
            "escrow {escrow_id} is {} — a custody outcome pins, it never flips",
            current.as_sql_str()
        )))
    }
}

impl PostgresBackend {
    async fn list_by(&self, column: &'static str, value: &str) -> Result<Vec<KeyEscrowRow>, Error> {
        if value.is_empty() {
            return Err(Error::InvalidArgument(format!("{column} required")));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM cirislens.key_escrows \
                     WHERE {column} = $1 ORDER BY escrow_id"
                ),
                &[&value],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_escrows"))?;
        rows.iter().map(decode_row).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::backend::Backend as _;

    fn unique(prefix: &str) -> String {
        format!("{prefix}-{}", uuid::Uuid::new_v4())
    }

    async fn svc() -> Option<PostgresBackend> {
        let dsn = crate::test_pg::dsn()?;
        let backend = PostgresBackend::connect(&dsn).await.expect("pg connect");
        backend.run_migrations().await.expect("pg migrations");
        Some(backend)
    }

    #[tokio::test]
    async fn pg_escrow_lifecycle_and_the_idempotent_create() {
        let Some(svc) = svc().await else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let eid = unique("escrow");
        let row = KeyEscrowRow {
            escrow_id: eid.clone(),
            key_id: unique("key"),
            org_id: unique("org"),
            escrow_type: EscrowType::Steward,
            custodian: "steward-a".into(),
            status: EscrowStatus::Active,
            created_at: chrono::Utc::now(),
            expires_at: None,
        };
        assert!(svc.create_escrow(&row).await.unwrap());
        assert!(!svc.create_escrow(&row).await.unwrap());
        let mut differing = row.clone();
        differing.custodian = "attorney-x".into();
        assert_eq!(
            svc.create_escrow(&differing).await.unwrap_err().kind(),
            "key_escrows_conflict"
        );
        assert!(svc
            .set_escrow_status(&eid, EscrowStatus::Revoked)
            .await
            .unwrap());
        assert!(!svc
            .set_escrow_status(&eid, EscrowStatus::Revoked)
            .await
            .unwrap());
        assert_eq!(
            svc.set_escrow_status(&eid, EscrowStatus::Active)
                .await
                .unwrap_err()
                .kind(),
            "key_escrows_conflict"
        );
        // The re-offered create does not resurrect the terminal escrow.
        assert!(!svc.create_escrow(&row).await.unwrap());
        assert_eq!(
            svc.get_escrow(&eid).await.unwrap().unwrap().status,
            EscrowStatus::Revoked
        );
        let by_org = svc.list_escrows_for_org(&row.org_id).await.unwrap();
        assert_eq!(by_org.len(), 1);
    }
}
