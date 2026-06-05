//! SQLite impl of [`ServiceTokenRevocationService`] (v1.5.23,
//! CIRISPersist#64).
//!
//! Mirrors the v1.5.23 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ                  → TEXT (RFC 3339 microseconds, Z)
//!   ON CONFLICT DO NOTHING       → identical syntax
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

use super::service::ServiceTokenRevocationService;
use super::types::RevokedServiceToken;
use super::Error;

/// SQLite-backed [`ServiceTokenRevocationService`] impl.
pub struct SqliteServiceTokenRevocationBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteServiceTokenRevocationBackend {
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

fn parse_datetime(s: &str) -> Result<DateTime<Utc>, Error> {
    let normalized = if s.contains('T') {
        s.to_owned()
    } else {
        format!("{}+00:00", s.replacen(' ', "T", 1))
    };
    chrono::DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::Backend(format!("datetime parse: {e} (raw={s})")))
}

fn fmt_datetime(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
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

fn decode_row(row: &rusqlite::Row<'_>) -> Result<RevokedServiceToken, Error> {
    let token_hash: String = row
        .get("token_hash")
        .map_err(|e| Error::Backend(format!("decode token_hash: {e}")))?;
    let revoked_at_str: String = row
        .get("revoked_at")
        .map_err(|e| Error::Backend(format!("decode revoked_at: {e}")))?;
    let revoked_by: String = row
        .get("revoked_by")
        .map_err(|e| Error::Backend(format!("decode revoked_by: {e}")))?;
    let reason: String = row
        .get("reason")
        .map_err(|e| Error::Backend(format!("decode reason: {e}")))?;
    Ok(RevokedServiceToken {
        token_hash,
        revoked_at: parse_datetime(&revoked_at_str)?,
        revoked_by,
        reason,
    })
}

impl ServiceTokenRevocationService for SqliteServiceTokenRevocationBackend {
    async fn record_revocation(&self, revocation: RevokedServiceToken) -> Result<(), Error> {
        validate_revocation(&revocation)?;
        let revoked_at_str = fmt_datetime(revocation.revoked_at);
        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT INTO cirislens_revoked_service_tokens (\
                        token_hash, revoked_at, revoked_by, reason\
                     ) VALUES (?1, ?2, ?3, ?4) \
                     ON CONFLICT (token_hash) DO NOTHING",
                    params![
                        revocation.token_hash,
                        revoked_at_str,
                        revocation.revoked_by,
                        revocation.reason
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "record_revocation"))?;
            Ok(())
        })()
    }

    async fn list_revocations(&self) -> Result<Vec<RevokedServiceToken>, Error> {
        let conn = self.conn.clone();
        (move || -> Result<Vec<RevokedServiceToken>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(
                    "SELECT token_hash, revoked_at, revoked_by, reason \
                     FROM cirislens_revoked_service_tokens",
                )
                .map_err(|e| map_sqlite_error(e, "list_revocations prepare"))?;
            let rows = stmt
                .query_map([], |row| Ok(decode_row(row)))
                .map_err(|e| map_sqlite_error(e, "list_revocations query"))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(|e| map_sqlite_error(e, "list_revocations row"))??);
            }
            Ok(out)
        })()
    }

    async fn check_revocation(
        &self,
        token_hash: &str,
    ) -> Result<Option<RevokedServiceToken>, Error> {
        if token_hash.is_empty() {
            return Err(Error::InvalidArgument("token_hash required".into()));
        }
        let token_hash = token_hash.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<Option<RevokedServiceToken>, Error> {
            let guard = conn.lock();
            let row_opt = guard
                .query_row(
                    "SELECT token_hash, revoked_at, revoked_by, reason \
                     FROM cirislens_revoked_service_tokens WHERE token_hash = ?1",
                    params![token_hash],
                    |row| Ok(decode_row(row)),
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "check_revocation query"))?;
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

    async fn fresh_backend() -> (SqliteBackend, SqliteServiceTokenRevocationBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteServiceTokenRevocationBackend::new(backend.conn_handle());
        (backend, svc)
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
    async fn record_revocation_then_check_lookup_returns_row() {
        let (_b, svc) = fresh_backend().await;
        let hash = unique_hash();
        let rev = mk(&hash);
        svc.record_revocation(rev.clone()).await.unwrap();
        let got = svc.check_revocation(&hash).await.unwrap().expect("present");
        assert_eq!(got.token_hash, hash);
        assert_eq!(got.revoked_by, "operator-a");
        assert_eq!(got.reason, "compromised");
    }

    #[tokio::test]
    async fn record_revocation_idempotent_same_hash() {
        let (_b, svc) = fresh_backend().await;
        let hash = unique_hash();
        let first = mk(&hash);
        svc.record_revocation(first.clone()).await.unwrap();
        // Second record with same hash but different metadata —
        // first record wins (ON CONFLICT DO NOTHING).
        let mut second = mk(&hash);
        second.revoked_by = "operator-b".into();
        second.reason = "later".into();
        svc.record_revocation(second).await.unwrap();
        let got = svc.check_revocation(&hash).await.unwrap().expect("present");
        assert_eq!(got.revoked_by, "operator-a", "first record wins");
        assert_eq!(got.reason, "compromised", "first record wins");
    }

    #[tokio::test]
    async fn list_revocations_returns_all_rows_on_populated_table() {
        let (_b, svc) = fresh_backend().await;
        let h1 = unique_hash();
        let h2 = unique_hash();
        let h3 = unique_hash();
        for h in [&h1, &h2, &h3] {
            svc.record_revocation(mk(h)).await.unwrap();
        }
        let listed = svc.list_revocations().await.unwrap();
        let hashes: std::collections::HashSet<String> =
            listed.iter().map(|r| r.token_hash.clone()).collect();
        assert_eq!(hashes.len(), 3);
        assert!(hashes.contains(&h1));
        assert!(hashes.contains(&h2));
        assert!(hashes.contains(&h3));
    }

    #[tokio::test]
    async fn list_revocations_empty_table_returns_empty_vec() {
        let (_b, svc) = fresh_backend().await;
        let listed = svc.list_revocations().await.unwrap();
        assert!(listed.is_empty(), "cold table → empty Vec");
    }

    #[tokio::test]
    async fn check_revocation_unknown_hash_returns_none() {
        let (_b, svc) = fresh_backend().await;
        let probe = unique_hash();
        let got = svc.check_revocation(&probe).await.unwrap();
        assert!(got.is_none(), "unknown hash returns None");
    }

    #[tokio::test]
    async fn record_revocation_empty_token_hash_rejected_invalid_argument() {
        let (_b, svc) = fresh_backend().await;
        let mut rev = mk("placeholder");
        rev.token_hash = String::new();
        let r = svc.record_revocation(rev).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));

        let mut rev = mk(&unique_hash());
        rev.revoked_by = String::new();
        let r = svc.record_revocation(rev).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));

        let mut rev = mk(&unique_hash());
        rev.reason = String::new();
        let r = svc.record_revocation(rev).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));

        // check_revocation also rejects empty hash.
        let r = svc.check_revocation("").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
    }
}
