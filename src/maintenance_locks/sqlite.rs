//! SQLite impl of [`MaintenanceLockService`] (v1.5.15,
//! CIRISPersist#59 #7).
//!
//! Mirrors the v1.5.15 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ                         → TEXT (RFC 3339 +
//!                                          `datetime('now', 'subsec')`)
//!   JSONB                               → TEXT (raw JSON string)
//!   NOW()                               → `datetime('now', 'subsec')` (the
//!                                          stored format) or
//!                                          `julianday('now')` (for
//!                                          interval arithmetic)
//!   `locked_at + N*interval 1 second`   → `julianday(locked_at) +
//!                                          (lock_timeout_seconds /
//!                                          86400.0)`
//!   ON CONFLICT DO UPDATE WHERE         → SQLite 3.24+ syntax (same
//!                                          shape as PG)
//!
//! Both arms server-stamp `locked_at` against the same clock (PG:
//! `NOW()`; SQLite: `datetime('now', 'subsec')`) and gate the
//! steal-the-stale-lock decision server-side in the same statement
//! that does the acquire. This guarantees lock-expiry semantics
//! match on both backends for any wall-clock moment.
//!
//! Threading: `tokio::task::spawn_blocking` + `conn.lock()`
//! per the existing pattern.
#![allow(clippy::redundant_closure_call)]
// v3.14.0 (CIRISPersist#158) — inline-sync rewrite of all
// tokio::task::spawn_blocking sites uses (closure)() to invoke
// the closure inline. Clippy's redundant_closure_call lint flags
// this; we allow it because the mechanical transformation kept
// each closure's typed return signature load-bearing for error
// propagation and any other refactor would be a much larger diff.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};

use super::service::MaintenanceLockService;
use super::types::MaintenanceLock;
use super::Error;

/// SQLite-backed [`MaintenanceLockService`] impl.
pub struct SqliteMaintenanceLockBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteMaintenanceLockBackend {
    /// Construct from a shared connection handle.
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }
}

fn map_sqlite_error(e: rusqlite::Error, op: &str) -> Error {
    use rusqlite::ErrorCode;
    if let rusqlite::Error::SqliteFailure(err, _) = &e {
        if err.code == ErrorCode::ConstraintViolation {
            return Error::InvalidArgument(format!("{op}: {e}"));
        }
    }
    Error::Backend(format!("{op}: {e}"))
}

fn parse_datetime(s: &str) -> Result<DateTime<Utc>, Error> {
    // `datetime('now', 'subsec')` emits the `YYYY-MM-DD HH:MM:SS.SSS`
    // shape without a trailing `Z` — same `' '`-separated form used
    // by other substrates. Normalize to RFC 3339 before parsing.
    let normalized = if s.contains('T') {
        s.to_owned()
    } else {
        format!("{}+00:00", s.replacen(' ', "T", 1))
    };
    chrono::DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::Backend(format!("datetime parse: {e} (raw={s})")))
}

fn parse_datetime_opt(s: Option<String>) -> Result<Option<DateTime<Utc>>, Error> {
    match s {
        None => Ok(None),
        Some(raw) => parse_datetime(&raw).map(Some),
    }
}

fn encode_json_opt(v: Option<&serde_json::Value>) -> Result<Option<String>, Error> {
    match v {
        None => Ok(None),
        Some(value) => serde_json::to_string(value)
            .map(Some)
            .map_err(|e| Error::Internal(format!("json encode: {e}"))),
    }
}

fn decode_json_opt(s: Option<String>) -> Result<Option<serde_json::Value>, Error> {
    match s {
        None => Ok(None),
        Some(raw) => serde_json::from_str(&raw)
            .map(Some)
            .map_err(|e| Error::Backend(format!("json decode: {e} (raw={raw})"))),
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

fn decode_lock_row(row: &rusqlite::Row<'_>) -> Result<MaintenanceLock, Error> {
    let lock_key: String = row
        .get("lock_key")
        .map_err(|e| Error::Backend(format!("decode lock_key: {e}")))?;
    let locked_by: Option<String> = row
        .get("locked_by")
        .map_err(|e| Error::Backend(format!("decode locked_by: {e}")))?;
    let locked_at_str: Option<String> = row
        .get("locked_at")
        .map_err(|e| Error::Backend(format!("decode locked_at: {e}")))?;
    let lock_timeout_seconds: i32 = row
        .get("lock_timeout_seconds")
        .map_err(|e| Error::Backend(format!("decode lock_timeout_seconds: {e}")))?;
    let metadata_raw: Option<String> = row
        .get("metadata")
        .map_err(|e| Error::Backend(format!("decode metadata: {e}")))?;
    Ok(MaintenanceLock {
        lock_key,
        locked_by,
        locked_at: parse_datetime_opt(locked_at_str)?,
        lock_timeout_seconds,
        metadata: decode_json_opt(metadata_raw)?,
    })
}

impl MaintenanceLockService for SqliteMaintenanceLockBackend {
    async fn try_acquire_lock(
        &self,
        lock_key: &str,
        locked_by: &str,
        timeout_seconds: i32,
        metadata: Option<serde_json::Value>,
    ) -> Result<Option<MaintenanceLock>, Error> {
        validate_acquire_args(lock_key, locked_by, timeout_seconds)?;
        let lock_key = lock_key.to_owned();
        let locked_by = locked_by.to_owned();
        let metadata_str = encode_json_opt(metadata.as_ref())?;
        let conn = self.conn.clone();
        (move || -> Result<Option<MaintenanceLock>, Error> {
            let mut guard = conn.lock();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|e| map_sqlite_error(e, "try_acquire_lock begin"))?;
            // Race-safe UPSERT mirroring the PG arm. Both backends
            // server-stamp locked_at via the same clock used to
            // evaluate expiry — keeps acquire-vs-expiry consistent.
            //
            // The WHERE clause includes "same holder" so refresh by
            // the current owner succeeds — symmetric with the PG arm.
            let changed = tx
                .execute(
                    "INSERT INTO cirislens_maintenance_locks (\
                        lock_key, locked_by, locked_at, \
                        lock_timeout_seconds, metadata\
                     ) VALUES (?1, ?2, datetime('now', 'subsec'), ?3, ?4) \
                     ON CONFLICT (lock_key) DO UPDATE SET \
                        locked_by            = excluded.locked_by, \
                        locked_at            = excluded.locked_at, \
                        lock_timeout_seconds = excluded.lock_timeout_seconds, \
                        metadata             = excluded.metadata \
                     WHERE cirislens_maintenance_locks.locked_by IS NULL \
                        OR cirislens_maintenance_locks.locked_at IS NULL \
                        OR cirislens_maintenance_locks.locked_by = excluded.locked_by \
                        OR julianday('now') > julianday(cirislens_maintenance_locks.locked_at) \
                           + (cirislens_maintenance_locks.lock_timeout_seconds / 86400.0)",
                    params![lock_key, locked_by, timeout_seconds, metadata_str],
                )
                .map_err(|e| map_sqlite_error(e, "try_acquire_lock upsert"))?;
            if changed == 0 {
                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "try_acquire_lock commit-noop"))?;
                return Ok(None);
            }
            // Win — read back the row so the caller sees the
            // server-stamped locked_at.
            let row = tx
                .query_row(
                    "SELECT lock_key, locked_by, locked_at, \
                            lock_timeout_seconds, metadata \
                     FROM cirislens_maintenance_locks WHERE lock_key = ?1",
                    params![lock_key],
                    |row| Ok(decode_lock_row(row)),
                )
                .map_err(|e| map_sqlite_error(e, "try_acquire_lock readback"))??;
            tx.commit()
                .map_err(|e| map_sqlite_error(e, "try_acquire_lock commit"))?;
            Ok(Some(row))
        })()
    }

    async fn release_lock(&self, lock_key: &str, locked_by: &str) -> Result<bool, Error> {
        if lock_key.is_empty() {
            return Err(Error::InvalidArgument("lock_key required".into()));
        }
        if locked_by.is_empty() {
            return Err(Error::InvalidArgument("locked_by required".into()));
        }
        let lock_key = lock_key.to_owned();
        let locked_by = locked_by.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let guard = conn.lock();
            let changed = guard
                .execute(
                    "UPDATE cirislens_maintenance_locks SET \
                        locked_by = NULL, \
                        locked_at = NULL \
                     WHERE lock_key = ?1 AND locked_by = ?2",
                    params![lock_key, locked_by],
                )
                .map_err(|e| map_sqlite_error(e, "release_lock exec"))?;
            Ok(changed > 0)
        })()
    }

    async fn get_lock(&self, lock_key: &str) -> Result<Option<MaintenanceLock>, Error> {
        if lock_key.is_empty() {
            return Err(Error::InvalidArgument("lock_key required".into()));
        }
        let lock_key = lock_key.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Option<MaintenanceLock>, Error> {
            let guard = conn.lock();
            let row_opt = guard
                .query_row(
                    "SELECT lock_key, locked_by, locked_at, \
                            lock_timeout_seconds, metadata \
                     FROM cirislens_maintenance_locks WHERE lock_key = ?1",
                    params![lock_key],
                    |row| Ok(decode_lock_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "get_lock query"))?;
            match row_opt {
                None => Ok(None),
                Some(r) => Ok(Some(r?)),
            }
        })()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteMaintenanceLockBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteMaintenanceLockBackend::new(backend.conn_handle());
        (backend, svc)
    }

    fn unique_lock_key() -> String {
        format!("lock-{}", Uuid::new_v4().simple())
    }

    #[tokio::test]
    async fn try_acquire_clean_returns_some() {
        let (_b, svc) = fresh_backend().await;
        let key = unique_lock_key();
        let got = svc
            .try_acquire_lock(&key, "worker-a", 300, Some(serde_json::json!({"pid": 1})))
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
    async fn try_acquire_same_holder_refresh_returns_some() {
        let (_b, svc) = fresh_backend().await;
        let key = unique_lock_key();
        let first = svc
            .try_acquire_lock(&key, "worker-a", 300, None)
            .await
            .unwrap()
            .expect("first acquire");
        // Wait a tick so locked_at advances measurably.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let second = svc
            .try_acquire_lock(&key, "worker-a", 600, None)
            .await
            .unwrap()
            .expect("same-holder re-acquire returns Some (refresh)");
        assert_eq!(second.lock_timeout_seconds, 600);
        assert!(
            second.locked_at.unwrap() >= first.locked_at.unwrap(),
            "refresh advances locked_at"
        );
    }

    #[tokio::test]
    async fn try_acquire_held_by_other_returns_none() {
        let (_b, svc) = fresh_backend().await;
        let key = unique_lock_key();
        let _ = svc
            .try_acquire_lock(&key, "worker-a", 300, None)
            .await
            .unwrap()
            .expect("A acquires");
        let got = svc
            .try_acquire_lock(&key, "worker-b", 300, None)
            .await
            .unwrap();
        assert!(got.is_none(), "active lock held by other returns None");
        let state = svc.get_lock(&key).await.unwrap().expect("present");
        assert_eq!(state.locked_by.as_deref(), Some("worker-a"));
    }

    #[tokio::test]
    async fn try_acquire_steals_expired_lock() {
        let (_b, svc) = fresh_backend().await;
        let key = unique_lock_key();
        let _ = svc
            .try_acquire_lock(&key, "worker-a", 1, None)
            .await
            .unwrap()
            .expect("A acquires");
        // Wait past the 1s window so julianday('now') > julianday(locked_at) + 1/86400.0
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let got = svc
            .try_acquire_lock(&key, "worker-b", 300, None)
            .await
            .unwrap();
        let lock = got.expect("expired-lock steal returns Some");
        assert_eq!(lock.locked_by.as_deref(), Some("worker-b"));
        assert_eq!(lock.lock_timeout_seconds, 300);
    }

    #[tokio::test]
    async fn release_caller_matches_returns_true() {
        let (_b, svc) = fresh_backend().await;
        let key = unique_lock_key();
        let _ = svc
            .try_acquire_lock(&key, "worker-a", 300, None)
            .await
            .unwrap()
            .expect("acquire");
        let ok = svc.release_lock(&key, "worker-a").await.unwrap();
        assert!(ok);
        let state = svc.get_lock(&key).await.unwrap().expect("row persists");
        assert!(state.locked_by.is_none());
        assert!(state.locked_at.is_none());
    }

    #[tokio::test]
    async fn release_caller_mismatches_returns_false_no_op() {
        let (_b, svc) = fresh_backend().await;
        let key = unique_lock_key();
        let _ = svc
            .try_acquire_lock(&key, "worker-a", 300, None)
            .await
            .unwrap()
            .expect("A acquires");
        let ok = svc.release_lock(&key, "worker-b").await.unwrap();
        assert!(!ok, "B's release of A's lock is a no-op");
        let state = svc.get_lock(&key).await.unwrap().expect("present");
        assert_eq!(state.locked_by.as_deref(), Some("worker-a"));
    }

    #[tokio::test]
    async fn get_lock_returns_current_state() {
        let (_b, svc) = fresh_backend().await;
        let key = unique_lock_key();
        let absent = svc.get_lock(&key).await.unwrap();
        assert!(absent.is_none());
        let _ = svc
            .try_acquire_lock(&key, "worker-a", 42, Some(serde_json::json!({"k": "v"})))
            .await
            .unwrap()
            .expect("acquire");
        let got = svc.get_lock(&key).await.unwrap().expect("present");
        assert_eq!(got.lock_key, key);
        assert_eq!(got.locked_by.as_deref(), Some("worker-a"));
        assert_eq!(got.lock_timeout_seconds, 42);
        assert_eq!(got.metadata, Some(serde_json::json!({"k": "v"})));
    }

    #[tokio::test]
    async fn invalid_argument_validation() {
        let (_b, svc) = fresh_backend().await;
        let r = svc.try_acquire_lock("", "w", 300, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.try_acquire_lock("k", "", 300, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.try_acquire_lock("k", "w", 0, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.try_acquire_lock("k", "w", -1, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
    }

    /// Lock-expiry semantics consistency check on SQLite. Mirrors
    /// the PG test of the same shape: the server's
    /// `julianday('now') > julianday(locked_at) + (timeout/86400.0)`
    /// comparison should agree with `MaintenanceLock::is_expired(now)`
    /// for any wall-clock moment chosen as "now".
    #[tokio::test]
    async fn expiry_semantics_match_client_helper() {
        let (_b, svc) = fresh_backend().await;
        let key = unique_lock_key();
        let _ = svc
            .try_acquire_lock(&key, "worker-a", 1, None)
            .await
            .unwrap()
            .expect("acquire");
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let now = Utc::now();
        let state = svc.get_lock(&key).await.unwrap().expect("present");
        assert!(state.is_expired(now), "client-side is_expired says expired");
        let stolen = svc
            .try_acquire_lock(&key, "worker-b", 300, None)
            .await
            .unwrap();
        assert!(
            stolen.is_some(),
            "server-side WHERE agrees: expired → steal"
        );
    }
}
