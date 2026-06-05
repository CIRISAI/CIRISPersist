//! SQLite impl of [`OccurrenceService`] (v1.7.3, CIRISPersist#81).
//!
//! Mirrors the v1.7.3 Postgres impl. Dialect translations:
//!
//!   TIMESTAMPTZ                  → TEXT (RFC 3339 microseconds, Z)
//!   JSONB                        → TEXT (serde_json encoded)
//!   ON CONFLICT DO UPDATE ...    → identical syntax
//!
//! RFC 3339 micros strings sort lexicographically === chronologically
//! as long as the format is consistent, so the `expires_at > now`
//! liveness filter is a plain string comparison against
//! `fmt_datetime(now)`.
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

use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use rusqlite::{params, Connection};

use super::service::OccurrenceService;
use super::types::OccurrenceRecord;
use super::Error;

/// SQLite-backed [`OccurrenceService`] impl.
pub struct SqliteOccurrenceBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteOccurrenceBackend {
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

fn encode_optional_json(v: &Option<serde_json::Value>) -> Result<Option<String>, Error> {
    match v {
        None => Ok(None),
        Some(j) => serde_json::to_string(j)
            .map(Some)
            .map_err(|e| Error::Internal(format!("encode metadata: {e}"))),
    }
}

fn decode_optional_json(s: Option<String>) -> Result<Option<serde_json::Value>, Error> {
    match s {
        None => Ok(None),
        Some(s) => serde_json::from_str(&s)
            .map(Some)
            .map_err(|e| Error::Backend(format!("decode metadata: {e}"))),
    }
}

fn validate_register(occurrence_id: &str, identity: &str, ttl_seconds: i64) -> Result<(), Error> {
    if occurrence_id.is_empty() {
        return Err(Error::InvalidArgument("occurrence_id required".into()));
    }
    if identity.is_empty() {
        return Err(Error::InvalidArgument("identity required".into()));
    }
    if ttl_seconds <= 0 {
        return Err(Error::InvalidArgument("ttl_seconds must be > 0".into()));
    }
    Ok(())
}

fn decode_row(row: &rusqlite::Row<'_>) -> Result<OccurrenceRecord, Error> {
    let occurrence_id: String = row
        .get("occurrence_id")
        .map_err(|e| Error::Backend(format!("decode occurrence_id: {e}")))?;
    let identity: String = row
        .get("identity")
        .map_err(|e| Error::Backend(format!("decode identity: {e}")))?;
    let registered_at: String = row
        .get("registered_at")
        .map_err(|e| Error::Backend(format!("decode registered_at: {e}")))?;
    let last_heartbeat: String = row
        .get("last_heartbeat")
        .map_err(|e| Error::Backend(format!("decode last_heartbeat: {e}")))?;
    let expires_at: String = row
        .get("expires_at")
        .map_err(|e| Error::Backend(format!("decode expires_at: {e}")))?;
    let metadata: Option<String> = row
        .get("metadata")
        .map_err(|e| Error::Backend(format!("decode metadata: {e}")))?;
    Ok(OccurrenceRecord {
        occurrence_id,
        identity,
        registered_at: parse_datetime(&registered_at)?,
        last_heartbeat: parse_datetime(&last_heartbeat)?,
        expires_at: parse_datetime(&expires_at)?,
        metadata: decode_optional_json(metadata)?,
    })
}

impl OccurrenceService for SqliteOccurrenceBackend {
    async fn register_occurrence(
        &self,
        occurrence_id: &str,
        identity: &str,
        ttl_seconds: i64,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        validate_register(occurrence_id, identity, ttl_seconds)?;
        let occurrence_id = occurrence_id.to_owned();
        let identity = identity.to_owned();
        let now = Utc::now();
        let now_str = fmt_datetime(now);
        let expires_str = fmt_datetime(now + Duration::seconds(ttl_seconds));
        let metadata_str = encode_optional_json(&metadata)?;
        let conn = self.conn.clone();
        (move || -> Result<(), Error> {
            let guard = conn.lock();
            // Idempotent upsert: re-registering refreshes every
            // column; the TTL clock restarts from `now`.
            guard
                .execute(
                    "INSERT INTO cirislens_occurrence_registry (\
                        occurrence_id, identity, registered_at, last_heartbeat, \
                        expires_at, metadata\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                     ON CONFLICT (occurrence_id) DO UPDATE \
                       SET identity = excluded.identity, \
                           registered_at = excluded.registered_at, \
                           last_heartbeat = excluded.last_heartbeat, \
                           expires_at = excluded.expires_at, \
                           metadata = excluded.metadata",
                    params![
                        occurrence_id,
                        identity,
                        now_str,
                        now_str,
                        expires_str,
                        metadata_str
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "register_occurrence"))?;
            Ok(())
        })()
    }

    async fn heartbeat_occurrence(
        &self,
        occurrence_id: &str,
        ttl_seconds: i64,
    ) -> Result<bool, Error> {
        if occurrence_id.is_empty() {
            return Err(Error::InvalidArgument("occurrence_id required".into()));
        }
        if ttl_seconds <= 0 {
            return Err(Error::InvalidArgument("ttl_seconds must be > 0".into()));
        }
        let occurrence_id = occurrence_id.to_owned();
        let now = Utc::now();
        let now_str = fmt_datetime(now);
        let expires_str = fmt_datetime(now + Duration::seconds(ttl_seconds));
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let guard = conn.lock();
            let affected = guard
                .execute(
                    "UPDATE cirislens_occurrence_registry \
                     SET last_heartbeat = ?2, expires_at = ?3 \
                     WHERE occurrence_id = ?1",
                    params![occurrence_id, now_str, expires_str],
                )
                .map_err(|e| map_sqlite_error(e, "heartbeat_occurrence"))?;
            Ok(affected > 0)
        })()
    }

    async fn deregister_occurrence(&self, occurrence_id: &str) -> Result<bool, Error> {
        if occurrence_id.is_empty() {
            return Err(Error::InvalidArgument("occurrence_id required".into()));
        }
        let occurrence_id = occurrence_id.to_owned();
        let conn = self.conn.clone();
        (move || -> Result<bool, Error> {
            let guard = conn.lock();
            let affected = guard
                .execute(
                    "DELETE FROM cirislens_occurrence_registry WHERE occurrence_id = ?1",
                    params![occurrence_id],
                )
                .map_err(|e| map_sqlite_error(e, "deregister_occurrence"))?;
            Ok(affected > 0)
        })()
    }

    async fn list_live_occurrences(&self, identity: &str) -> Result<Vec<OccurrenceRecord>, Error> {
        if identity.is_empty() {
            return Err(Error::InvalidArgument("identity required".into()));
        }
        let identity = identity.to_owned();
        let now_str = fmt_datetime(Utc::now());
        let conn = self.conn.clone();
        (move || -> Result<Vec<OccurrenceRecord>, Error> {
            let guard = conn.lock();
            let mut stmt = guard
                .prepare(
                    "SELECT occurrence_id, identity, registered_at, last_heartbeat, \
                            expires_at, metadata \
                     FROM cirislens_occurrence_registry \
                     WHERE identity = ?1 AND expires_at > ?2 \
                     ORDER BY occurrence_id",
                )
                .map_err(|e| map_sqlite_error(e, "list_live_occurrences prepare"))?;
            let rows = stmt
                .query_map(params![identity, now_str], |row| Ok(decode_row(row)))
                .map_err(|e| map_sqlite_error(e, "list_live_occurrences query"))?;
            let mut out = Vec::new();
            for r in rows {
                out.push(r.map_err(|e| map_sqlite_error(e, "list_live_occurrences row"))??);
            }
            Ok(out)
        })()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;
    use uuid::Uuid;

    async fn fresh_backend() -> (SqliteBackend, SqliteOccurrenceBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let svc = SqliteOccurrenceBackend::new(backend.conn_handle());
        (backend, svc)
    }

    fn unique_id(prefix: &str) -> String {
        format!("{prefix}-{}", Uuid::new_v4().simple())
    }

    #[tokio::test]
    async fn register_then_list_live_shows_it_fields_round_trip() {
        let (_b, svc) = fresh_backend().await;
        let identity = unique_id("id");
        let occ = unique_id("occ");
        let meta = serde_json::json!({"endpoint": "10.0.0.1:9000"});
        svc.register_occurrence(&occ, &identity, 3600, Some(meta.clone()))
            .await
            .unwrap();
        let live = svc.list_live_occurrences(&identity).await.unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].occurrence_id, occ);
        assert_eq!(live[0].identity, identity);
        assert_eq!(live[0].metadata, Some(meta));
    }

    #[tokio::test]
    async fn re_register_updates_row_still_one_row() {
        let (_b, svc) = fresh_backend().await;
        let id_a = unique_id("id");
        let id_b = unique_id("id");
        let occ = unique_id("occ");
        svc.register_occurrence(&occ, &id_a, 3600, None)
            .await
            .unwrap();
        let first = svc.list_live_occurrences(&id_a).await.unwrap();
        let first_expires = first[0].expires_at;
        let meta = serde_json::json!({"v": 2});
        svc.register_occurrence(&occ, &id_b, 7200, Some(meta.clone()))
            .await
            .unwrap();
        assert!(svc.list_live_occurrences(&id_a).await.unwrap().is_empty());
        let now = svc.list_live_occurrences(&id_b).await.unwrap();
        assert_eq!(now.len(), 1, "still one row");
        assert_eq!(now[0].identity, id_b);
        assert_eq!(now[0].metadata, Some(meta));
        assert!(now[0].expires_at > first_expires, "expires refreshed");
    }

    #[tokio::test]
    async fn heartbeat_bumps_expires_unknown_returns_false() {
        let (_b, svc) = fresh_backend().await;
        let identity = unique_id("id");
        let occ = unique_id("occ");
        svc.register_occurrence(&occ, &identity, 10, None)
            .await
            .unwrap();
        let before = svc.list_live_occurrences(&identity).await.unwrap()[0].expires_at;
        let bumped = svc.heartbeat_occurrence(&occ, 3600).await.unwrap();
        assert!(bumped);
        let after = svc.list_live_occurrences(&identity).await.unwrap()[0].expires_at;
        assert!(after > before, "heartbeat bumps expires_at");
        let unknown = svc
            .heartbeat_occurrence(&unique_id("occ"), 60)
            .await
            .unwrap();
        assert!(!unknown);
    }

    #[tokio::test]
    async fn deregister_removes_row_absent_returns_false() {
        let (_b, svc) = fresh_backend().await;
        let identity = unique_id("id");
        let occ = unique_id("occ");
        svc.register_occurrence(&occ, &identity, 3600, None)
            .await
            .unwrap();
        let removed = svc.deregister_occurrence(&occ).await.unwrap();
        assert!(removed);
        assert!(svc
            .list_live_occurrences(&identity)
            .await
            .unwrap()
            .is_empty());
        let again = svc.deregister_occurrence(&occ).await.unwrap();
        assert!(!again);
    }

    #[tokio::test]
    async fn ttl_expiry_filters_expired_rows() {
        let (b, svc) = fresh_backend().await;
        let identity = unique_id("id");
        let occ_a = unique_id("occ");
        let occ_b = unique_id("occ");
        svc.register_occurrence(&occ_a, &identity, 3600, None)
            .await
            .unwrap();
        svc.register_occurrence(&occ_b, &identity, 3600, None)
            .await
            .unwrap();
        // Force occ_b's expires_at into the past via raw SQL — proves
        // the `expires_at > now` filter without a real sleep.
        let past = fmt_datetime(Utc::now() - Duration::hours(1));
        {
            let conn = b.conn_handle();
            let guard = conn.lock();
            guard
                .execute(
                    "UPDATE cirislens_occurrence_registry \
                     SET expires_at = ?2 WHERE occurrence_id = ?1",
                    params![occ_b, past],
                )
                .unwrap();
        }
        let live = svc.list_live_occurrences(&identity).await.unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].occurrence_id, occ_a);
    }

    #[tokio::test]
    async fn identities_are_isolated() {
        let (_b, svc) = fresh_backend().await;
        let id_a = unique_id("id");
        let id_b = unique_id("id");
        let occ_a = unique_id("occ");
        let occ_b = unique_id("occ");
        svc.register_occurrence(&occ_a, &id_a, 3600, None)
            .await
            .unwrap();
        svc.register_occurrence(&occ_b, &id_b, 3600, None)
            .await
            .unwrap();
        let live_a = svc.list_live_occurrences(&id_a).await.unwrap();
        assert_eq!(live_a.len(), 1);
        assert_eq!(live_a[0].occurrence_id, occ_a);
    }

    #[tokio::test]
    async fn invalid_arguments_rejected() {
        let (_b, svc) = fresh_backend().await;
        let r = svc.register_occurrence("", "id", 60, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.register_occurrence("occ", "", 60, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.register_occurrence("occ", "id", 0, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.register_occurrence("occ", "id", -5, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.heartbeat_occurrence("", 60).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.heartbeat_occurrence("occ", 0).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.deregister_occurrence("").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = svc.list_live_occurrences("").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
    }
}
