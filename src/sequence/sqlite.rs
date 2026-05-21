//! SQLite impl of [`SequenceService`] (v1.7.1, CIRISPersist#83).
//!
//! Mirrors the v1.7.1 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ                  → TEXT (RFC 3339 microseconds, Z)
//!   BIGINT                       → INTEGER
//!   ON CONFLICT DO UPDATE ...    → identical syntax
//!   RETURNING                    → identical (SQLite 3.35+)
//!
//! The `next_sequence` bump-and-return is a single atomic UPSERT
//! statement; SQLite serializes writes per-connection, and the
//! shared `Arc<Mutex<Connection>>` serializes across the
//! occurrences + in-process consumers sharing one Ed25519 identity.
//!
//! Threading: `tokio::task::spawn_blocking` + `conn.blocking_lock()`
//! per the existing pattern.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use tokio::sync::Mutex;

use super::service::SequenceService;
use super::Error;

/// SQLite-backed [`SequenceService`] impl.
pub struct SqliteSequenceBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteSequenceBackend {
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
            // 787  = SQLITE_CONSTRAINT_FOREIGNKEY
            // 1555 = SQLITE_CONSTRAINT_PRIMARYKEY
            // 2067 = SQLITE_CONSTRAINT_UNIQUE
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

fn fmt_datetime(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

fn validate_key(identity: &str, stream: &str) -> Result<(), Error> {
    if identity.is_empty() {
        return Err(Error::InvalidArgument("identity required".into()));
    }
    if stream.is_empty() {
        return Err(Error::InvalidArgument("stream required".into()));
    }
    Ok(())
}

impl SequenceService for SqliteSequenceBackend {
    async fn next_sequence(&self, identity: &str, stream: &str) -> Result<u64, Error> {
        validate_key(identity, stream)?;
        let identity = identity.to_owned();
        let stream = stream.to_owned();
        let updated_at = fmt_datetime(Utc::now());
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<u64, Error> {
            let guard = conn.blocking_lock();
            // Atomic bump-and-return: a single UPSERT increments the
            // counter and RETURNs the new value. SQLite serializes
            // the write per-connection.
            let value: i64 = guard
                .query_row(
                    "INSERT INTO cirislens_identity_sequences (\
                        identity, stream, next_value, updated_at\
                     ) VALUES (?1, ?2, 1, ?3) \
                     ON CONFLICT (identity, stream) DO UPDATE \
                       SET next_value = next_value + 1, \
                           updated_at = ?3 \
                     RETURNING next_value",
                    params![identity, stream, updated_at],
                    |row| row.get(0),
                )
                .map_err(|e| map_sqlite_error(e, "next_sequence"))?;
            super::decode_sequence_value(value)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn peek_sequence(&self, identity: &str, stream: &str) -> Result<u64, Error> {
        validate_key(identity, stream)?;
        let identity = identity.to_owned();
        let stream = stream.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<u64, Error> {
            let guard = conn.blocking_lock();
            let value_opt: Option<i64> = guard
                .query_row(
                    "SELECT next_value FROM cirislens_identity_sequences \
                     WHERE identity = ?1 AND stream = ?2",
                    params![identity, stream],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "peek_sequence"))?;
            value_opt.map_or(Ok(0), super::decode_sequence_value)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteSequenceBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteSequenceBackend::new(backend.conn_handle());
        (backend, svc)
    }

    fn unique_id() -> String {
        format!("id-{}", Uuid::new_v4().simple())
    }

    #[tokio::test]
    async fn next_sequence_increments_1_2_3() {
        let (_b, svc) = fresh_backend().await;
        let identity = unique_id();
        assert_eq!(svc.next_sequence(&identity, "s").await.unwrap(), 1);
        assert_eq!(svc.next_sequence(&identity, "s").await.unwrap(), 2);
        assert_eq!(svc.next_sequence(&identity, "s").await.unwrap(), 3);
    }

    #[tokio::test]
    async fn streams_under_same_identity_are_independent() {
        let (_b, svc) = fresh_backend().await;
        let identity = unique_id();
        assert_eq!(svc.next_sequence(&identity, "stream-a").await.unwrap(), 1);
        assert_eq!(svc.next_sequence(&identity, "stream-a").await.unwrap(), 2);
        // Different stream — fresh counter.
        assert_eq!(svc.next_sequence(&identity, "stream-b").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn identities_are_independent() {
        let (_b, svc) = fresh_backend().await;
        let id_a = unique_id();
        let id_b = unique_id();
        assert_eq!(svc.next_sequence(&id_a, "s").await.unwrap(), 1);
        assert_eq!(svc.next_sequence(&id_a, "s").await.unwrap(), 2);
        // Different identity — fresh counter.
        assert_eq!(svc.next_sequence(&id_b, "s").await.unwrap(), 1);
    }

    #[tokio::test]
    async fn peek_sequence_does_not_bump() {
        let (_b, svc) = fresh_backend().await;
        let identity = unique_id();
        // Cold pair — peek returns 0.
        assert_eq!(svc.peek_sequence(&identity, "s").await.unwrap(), 0);
        svc.next_sequence(&identity, "s").await.unwrap();
        svc.next_sequence(&identity, "s").await.unwrap();
        // Peek returns last-issued without bumping — repeated.
        assert_eq!(svc.peek_sequence(&identity, "s").await.unwrap(), 2);
        assert_eq!(svc.peek_sequence(&identity, "s").await.unwrap(), 2);
        // Next issue continues from 3 — peek did not consume.
        assert_eq!(svc.next_sequence(&identity, "s").await.unwrap(), 3);
    }

    #[tokio::test]
    async fn empty_identity_or_stream_rejected_invalid_argument() {
        let (_b, svc) = fresh_backend().await;
        let r = svc.next_sequence("", "s").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.next_sequence("id", "").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.peek_sequence("", "s").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.peek_sequence("id", "").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
    }

    #[tokio::test]
    async fn concurrent_next_sequence_yields_distinct_set() {
        // Two SqliteSequenceBackend instances sharing one
        // Arc<Mutex<Connection>> — models two in-process consumers
        // (e.g. agent + NodeCore) issuing against one identity.
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let conn = backend.conn_handle();
        let svc_a = Arc::new(SqliteSequenceBackend::new(conn.clone()));
        let svc_b = Arc::new(SqliteSequenceBackend::new(conn.clone()));

        let identity = unique_id();
        let stream = "concurrent";
        let mut handles = Vec::new();
        for i in 0..20 {
            let svc = if i % 2 == 0 {
                svc_a.clone()
            } else {
                svc_b.clone()
            };
            let id = identity.clone();
            handles.push(tokio::spawn(async move {
                svc.next_sequence(&id, stream).await.unwrap()
            }));
        }
        let mut got = std::collections::HashSet::new();
        for h in handles {
            got.insert(h.await.unwrap());
        }
        // Atomicity proof: 20 concurrent callers across two backend
        // instances, exactly {1..=20}, no duplicates.
        let expected: std::collections::HashSet<u64> = (1..=20).collect();
        assert_eq!(got, expected);
    }
}
