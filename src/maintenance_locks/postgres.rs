//! PostgreSQL impl of [`MaintenanceLockService`] (v1.5.15,
//! CIRISPersist#59 #7).
//!
//! 5 columns. JSON column `metadata` rides as `serde_json::Value`
//! (JSONB on the PG side); timestamps cross as
//! `chrono::DateTime<Utc>` (TIMESTAMPTZ).
//!
//! The acquire path is a single-statement UPSERT with a guarded
//! WHERE clause. The WHERE filters for "not held OR expired" so a
//! losing caller against an actively-held lock doesn't overwrite
//! the holder; in that case the UPSERT updates ZERO rows and the
//! `RETURNING` clause is empty.

use super::service::MaintenanceLockService;
use super::types::MaintenanceLock;
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
        _ => Error::Backend(format!("{op}: {detail}")),
    }
}

fn validate_acquire_args(
    lock_key: &str,
    locked_by: &str,
    timeout_seconds: i32,
) -> Result<(), Error> {
    if lock_key.is_empty() {
        return Err(Error::InvalidArgument("lock_key required".into()));
    }
    if locked_by.is_empty() {
        return Err(Error::InvalidArgument("locked_by required".into()));
    }
    if timeout_seconds <= 0 {
        return Err(Error::InvalidArgument(format!(
            "timeout_seconds must be > 0, got {timeout_seconds}"
        )));
    }
    Ok(())
}

fn decode_lock_row(row: &tokio_postgres::Row) -> Result<MaintenanceLock, Error> {
    Ok(MaintenanceLock {
        lock_key: row
            .try_get("lock_key")
            .map_err(|e| Error::Backend(format!("decode lock_key: {e}")))?,
        locked_by: row
            .try_get("locked_by")
            .map_err(|e| Error::Backend(format!("decode locked_by: {e}")))?,
        locked_at: row
            .try_get("locked_at")
            .map_err(|e| Error::Backend(format!("decode locked_at: {e}")))?,
        lock_timeout_seconds: row
            .try_get("lock_timeout_seconds")
            .map_err(|e| Error::Backend(format!("decode lock_timeout_seconds: {e}")))?,
        metadata: row
            .try_get("metadata")
            .map_err(|e| Error::Backend(format!("decode metadata: {e}")))?,
    })
}

impl MaintenanceLockService for PostgresBackend {
    async fn try_acquire_lock(
        &self,
        lock_key: &str,
        locked_by: &str,
        timeout_seconds: i32,
        metadata: Option<serde_json::Value>,
    ) -> Result<Option<MaintenanceLock>, Error> {
        validate_acquire_args(lock_key, locked_by, timeout_seconds)?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // Single-statement race-safe acquire. The WHERE clause on
        // the UPDATE arm gates on (not-held OR same-holder OR
        // expired); when none of those match (active lock held by a
        // different caller) the UPDATE skips and RETURNING is empty.
        //
        // Same-holder is included so a caller re-acquiring its own
        // lock for refresh purposes succeeds. This is symmetric with
        // the SQLite arm.
        let row_opt = client
            .query_opt(
                "INSERT INTO cirislens.maintenance_locks (\
                    lock_key, locked_by, locked_at, \
                    lock_timeout_seconds, metadata\
                 ) VALUES ($1, $2, NOW(), $3, $4) \
                 ON CONFLICT (lock_key) DO UPDATE SET \
                    locked_by            = EXCLUDED.locked_by, \
                    locked_at            = EXCLUDED.locked_at, \
                    lock_timeout_seconds = EXCLUDED.lock_timeout_seconds, \
                    metadata             = EXCLUDED.metadata \
                 WHERE cirislens.maintenance_locks.locked_by IS NULL \
                    OR cirislens.maintenance_locks.locked_at IS NULL \
                    OR cirislens.maintenance_locks.locked_by = EXCLUDED.locked_by \
                    OR cirislens.maintenance_locks.locked_at \
                        + (cirislens.maintenance_locks.lock_timeout_seconds \
                           * interval '1 second') < NOW() \
                 RETURNING lock_key, locked_by, locked_at, \
                           lock_timeout_seconds, metadata",
                &[&lock_key, &locked_by, &timeout_seconds, &metadata],
            )
            .await
            .map_err(|e| map_pg_error(e, "try_acquire_lock"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_lock_row(&row)?)),
        }
    }

    async fn release_lock(&self, lock_key: &str, locked_by: &str) -> Result<bool, Error> {
        if lock_key.is_empty() {
            return Err(Error::InvalidArgument("lock_key required".into()));
        }
        if locked_by.is_empty() {
            return Err(Error::InvalidArgument("locked_by required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let changed = client
            .execute(
                "UPDATE cirislens.maintenance_locks SET \
                    locked_by = NULL, \
                    locked_at = NULL \
                 WHERE lock_key = $1 AND locked_by = $2",
                &[&lock_key, &locked_by],
            )
            .await
            .map_err(|e| map_pg_error(e, "release_lock"))?;
        Ok(changed > 0)
    }

    async fn get_lock(&self, lock_key: &str) -> Result<Option<MaintenanceLock>, Error> {
        if lock_key.is_empty() {
            return Err(Error::InvalidArgument("lock_key required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT lock_key, locked_by, locked_at, \
                        lock_timeout_seconds, metadata \
                 FROM cirislens.maintenance_locks WHERE lock_key = $1",
                &[&lock_key],
            )
            .await
            .map_err(|e| map_pg_error(e, "get_lock"))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(decode_lock_row(&row)?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    fn unique_lock_key() -> String {
        format!("lock-{}", Uuid::new_v4().simple())
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn mlock_pg_try_acquire_clean_returns_some() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = unique_lock_key();
        let got = MaintenanceLockService::try_acquire_lock(
            &backend,
            &key,
            "worker-a",
            300,
            Some(serde_json::json!({"pid": 1})),
        )
        .await
        .unwrap();
        let lock = got.expect("clean acquire returns Some");
        assert_eq!(lock.lock_key, key);
        assert_eq!(lock.locked_by.as_deref(), Some("worker-a"));
        assert!(lock.locked_at.is_some());
        assert_eq!(lock.lock_timeout_seconds, 300);
        assert_eq!(lock.metadata, Some(serde_json::json!({"pid": 1})));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn mlock_pg_try_acquire_same_holder_refresh_returns_some() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = unique_lock_key();
        let first = MaintenanceLockService::try_acquire_lock(&backend, &key, "worker-a", 300, None)
            .await
            .unwrap()
            .expect("first acquire returns Some");
        // Same-holder re-acquire (refresh).
        let second =
            MaintenanceLockService::try_acquire_lock(&backend, &key, "worker-a", 600, None)
                .await
                .unwrap()
                .expect("same-holder re-acquire returns Some (refresh)");
        assert_eq!(second.lock_timeout_seconds, 600);
        // locked_at should advance.
        assert!(
            second.locked_at.unwrap() >= first.locked_at.unwrap(),
            "refresh advances locked_at"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn mlock_pg_try_acquire_held_by_other_returns_none() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = unique_lock_key();
        let _ = MaintenanceLockService::try_acquire_lock(&backend, &key, "worker-a", 300, None)
            .await
            .unwrap()
            .expect("acquire by A");
        // B tries to steal but A's lock is fresh — should return None.
        let got = MaintenanceLockService::try_acquire_lock(&backend, &key, "worker-b", 300, None)
            .await
            .unwrap();
        assert!(got.is_none(), "active lock held by other returns None");

        // A still holds it.
        let state = backend.get_lock(&key).await.unwrap().expect("present");
        assert_eq!(state.locked_by.as_deref(), Some("worker-a"));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn mlock_pg_try_acquire_steals_expired_lock() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = unique_lock_key();
        // A acquires with timeout=1s.
        let _ = MaintenanceLockService::try_acquire_lock(&backend, &key, "worker-a", 1, None)
            .await
            .unwrap()
            .expect("A acquires");
        // Wait past the 1s window so the row's locked_at + 1s < NOW().
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        // B should now be able to steal.
        let got = MaintenanceLockService::try_acquire_lock(&backend, &key, "worker-b", 300, None)
            .await
            .unwrap();
        let lock = got.expect("expired-lock steal returns Some");
        assert_eq!(lock.locked_by.as_deref(), Some("worker-b"));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn mlock_pg_release_caller_matches_returns_true() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = unique_lock_key();
        let _ = MaintenanceLockService::try_acquire_lock(&backend, &key, "worker-a", 300, None)
            .await
            .unwrap()
            .expect("acquire");
        let ok = backend.release_lock(&key, "worker-a").await.unwrap();
        assert!(ok);
        // After release, row's locked_by/at should be NULL.
        let state = backend.get_lock(&key).await.unwrap().expect("row persists");
        assert!(state.locked_by.is_none());
        assert!(state.locked_at.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn mlock_pg_release_caller_mismatches_returns_false_no_op() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = unique_lock_key();
        let _ = MaintenanceLockService::try_acquire_lock(&backend, &key, "worker-a", 300, None)
            .await
            .unwrap()
            .expect("acquire by A");
        let ok = backend.release_lock(&key, "worker-b").await.unwrap();
        assert!(!ok, "B's release of A's lock is a no-op");
        // A still holds it.
        let state = backend.get_lock(&key).await.unwrap().expect("present");
        assert_eq!(state.locked_by.as_deref(), Some("worker-a"));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn mlock_pg_get_lock_returns_current_state() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = unique_lock_key();
        // get_lock on non-existent row.
        let absent = backend.get_lock(&key).await.unwrap();
        assert!(absent.is_none());
        // Acquire then get.
        let _ = MaintenanceLockService::try_acquire_lock(
            &backend,
            &key,
            "worker-a",
            42,
            Some(serde_json::json!({"k": "v"})),
        )
        .await
        .unwrap()
        .expect("acquire");
        let got = backend.get_lock(&key).await.unwrap().expect("present");
        assert_eq!(got.lock_key, key);
        assert_eq!(got.locked_by.as_deref(), Some("worker-a"));
        assert_eq!(got.lock_timeout_seconds, 42);
        assert_eq!(got.metadata, Some(serde_json::json!({"k": "v"})));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn mlock_pg_invalid_argument_validation() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        // Empty lock_key.
        let r = MaintenanceLockService::try_acquire_lock(&backend, "", "w", 300, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        // Empty locked_by.
        let r = MaintenanceLockService::try_acquire_lock(&backend, "k", "", 300, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        // Non-positive timeout.
        let r = MaintenanceLockService::try_acquire_lock(&backend, "k", "w", 0, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = MaintenanceLockService::try_acquire_lock(&backend, "k", "w", -1, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
    }

    /// Lock-expiry semantics consistency check. Borrowed shape from
    /// `MaintenanceLock::is_expired` — for any wall-clock moment
    /// chosen as "now", the PG server-clock comparison
    /// (`locked_at + timeout < NOW()`) and the client-side
    /// `is_expired(now)` should agree.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn mlock_pg_expiry_semantics_match_client_helper() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = unique_lock_key();
        // Acquire with 1s timeout, wait 1.5s, then ask via get_lock
        // and is_expired with `now = Utc::now()` — should agree
        // with the server's view (steal succeeds).
        let _ = MaintenanceLockService::try_acquire_lock(&backend, &key, "worker-a", 1, None)
            .await
            .unwrap()
            .expect("acquire");
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let now = Utc::now();
        let state = backend.get_lock(&key).await.unwrap().expect("present");
        assert!(state.is_expired(now), "client-side is_expired says expired");
        // And the server agrees — B can steal.
        let stolen =
            MaintenanceLockService::try_acquire_lock(&backend, &key, "worker-b", 300, None)
                .await
                .unwrap();
        assert!(
            stolen.is_some(),
            "server-side WHERE agrees: expired → steal"
        );
    }
}
