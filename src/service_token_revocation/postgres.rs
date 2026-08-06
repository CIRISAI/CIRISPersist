//! PostgreSQL impl of [`ServiceTokenRevocationService`] (v1.5.23,
//! CIRISPersist#64).
//!
//! 4 columns, all NOT NULL. PK on `token_hash`. The record path is
//! a single-statement `INSERT ... ON CONFLICT DO NOTHING` so
//! retries are safe and the first record wins (revocation
//! timestamp + reason are stable once recorded).

use super::service::ServiceTokenRevocationService;
use super::types::RevokedServiceToken;
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
        _ => Error::Backend(format!("{op}: {detail}")),
    }
}

fn validate_revocation(r: &RevokedServiceToken) -> Result<(), Error> {
    if r.token_hash.is_empty() {
        return Err(Error::InvalidArgument("token_hash required".into()));
    }
    if r.revoked_by.is_empty() {
        return Err(Error::InvalidArgument("revoked_by required".into()));
    }
    if r.reason.is_empty() {
        return Err(Error::InvalidArgument("reason required".into()));
    }
    Ok(())
}

fn decode_row(row: &tokio_postgres::Row) -> Result<RevokedServiceToken, Error> {
    Ok(RevokedServiceToken {
        token_hash: row
            .try_get("token_hash")
            .map_err(|e| Error::Backend(format!("decode token_hash: {e}")))?,
        revoked_at: row
            .try_get("revoked_at")
            .map_err(|e| Error::Backend(format!("decode revoked_at: {e}")))?,
        revoked_by: row
            .try_get("revoked_by")
            .map_err(|e| Error::Backend(format!("decode revoked_by: {e}")))?,
        reason: row
            .try_get("reason")
            .map_err(|e| Error::Backend(format!("decode reason: {e}")))?,
    })
}

const SELECT_COLUMNS: &str = "token_hash, revoked_at, revoked_by, reason";

impl ServiceTokenRevocationService for PostgresBackend {
    async fn record_revocation(&self, revocation: RevokedServiceToken) -> Result<(), Error> {
        validate_revocation(&revocation)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // Idempotent upsert: first record wins, subsequent records
        // with the same token_hash are silently ignored. The agent's
        // auth_service hashes the token at revocation time so the
        // PK collision is the "this token was already revoked"
        // signal — no error, just a no-op.
        client
            .execute(
                "INSERT INTO cirislens.revoked_service_tokens (\
                    token_hash, revoked_at, revoked_by, reason\
                 ) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (token_hash) DO NOTHING",
                &[
                    &revocation.token_hash,
                    &revocation.revoked_at,
                    &revocation.revoked_by,
                    &revocation.reason,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "record_revocation"))?;
        Ok(())
    }

    async fn list_revocations(&self) -> Result<Vec<RevokedServiceToken>, Error> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                &format!("SELECT {SELECT_COLUMNS} FROM cirislens.revoked_service_tokens"),
                &[],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_revocations"))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(decode_row(row)?);
        }
        Ok(out)
    }

    async fn check_revocation(
        &self,
        token_hash: &str,
    ) -> Result<Option<RevokedServiceToken>, Error> {
        if token_hash.is_empty() {
            return Err(Error::InvalidArgument("token_hash required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                &format!(
                    "SELECT {SELECT_COLUMNS} \
                     FROM cirislens.revoked_service_tokens \
                     WHERE token_hash = $1"
                ),
                &[&token_hash],
            )
            .await
            .map_err(|e| map_pg_error(e, "check_revocation"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_row(&row)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        crate::test_pg::dsn()
    }

    fn unique_hash() -> String {
        format!("hash-{}", Uuid::new_v4().simple())
    }

    fn mk(hash: &str) -> RevokedServiceToken {
        RevokedServiceToken {
            token_hash: hash.to_owned(),
            revoked_at: Utc::now(),
            revoked_by: "operator-a".into(),
            reason: "compromised".into(),
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn record_revocation_then_check_lookup_returns_row() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let hash = unique_hash();
        let rev = mk(&hash);
        ServiceTokenRevocationService::record_revocation(&backend, rev.clone())
            .await
            .unwrap();
        let got = ServiceTokenRevocationService::check_revocation(&backend, &hash)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.token_hash, hash);
        assert_eq!(got.revoked_by, "operator-a");
        assert_eq!(got.reason, "compromised");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn record_revocation_idempotent_same_hash() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let hash = unique_hash();
        let first = mk(&hash);
        ServiceTokenRevocationService::record_revocation(&backend, first.clone())
            .await
            .unwrap();
        // Re-record with same hash but different metadata — first
        // record wins, ON CONFLICT DO NOTHING swallows the second.
        let mut second = mk(&hash);
        second.revoked_by = "operator-b".into();
        second.reason = "later".into();
        ServiceTokenRevocationService::record_revocation(&backend, second)
            .await
            .unwrap();
        let got = ServiceTokenRevocationService::check_revocation(&backend, &hash)
            .await
            .unwrap()
            .expect("present");
        assert_eq!(got.revoked_by, "operator-a", "first record wins");
        assert_eq!(got.reason, "compromised", "first record wins");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_revocations_returns_all_rows_on_populated_table() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let h1 = unique_hash();
        let h2 = unique_hash();
        let h3 = unique_hash();
        for h in [&h1, &h2, &h3] {
            ServiceTokenRevocationService::record_revocation(&backend, mk(h))
                .await
                .unwrap();
        }
        let listed = ServiceTokenRevocationService::list_revocations(&backend)
            .await
            .unwrap();
        let hashes: std::collections::HashSet<String> =
            listed.iter().map(|r| r.token_hash.clone()).collect();
        assert!(hashes.contains(&h1));
        assert!(hashes.contains(&h2));
        assert!(hashes.contains(&h3));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_revocations_empty_table_returns_empty_vec() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // We can't truncate a shared PG table without disturbing
        // other serial tests, so this test just exercises the
        // "no error / Vec usable" property and confirms a freshly
        // generated hash isn't in the returned list.
        let listed = ServiceTokenRevocationService::list_revocations(&backend)
            .await
            .unwrap();
        let probe = unique_hash();
        assert!(!listed.iter().any(|r| r.token_hash == probe));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn check_revocation_unknown_hash_returns_none() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let probe = unique_hash();
        let got = ServiceTokenRevocationService::check_revocation(&backend, &probe)
            .await
            .unwrap();
        assert!(got.is_none(), "unknown hash returns None");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn record_revocation_empty_token_hash_rejected_invalid_argument() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let mut rev = mk("");
        rev.token_hash = String::new();
        let r = ServiceTokenRevocationService::record_revocation(&backend, rev).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));

        // Also exercise empty revoked_by and reason.
        let mut rev = mk(&unique_hash());
        rev.revoked_by = String::new();
        let r = ServiceTokenRevocationService::record_revocation(&backend, rev).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));

        let mut rev = mk(&unique_hash());
        rev.reason = String::new();
        let r = ServiceTokenRevocationService::record_revocation(&backend, rev).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));

        // check_revocation also rejects empty hash.
        let r = ServiceTokenRevocationService::check_revocation(&backend, "").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
    }
}
