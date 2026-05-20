//! PostgreSQL impl of [`OccurrenceService`] (v1.7.3,
//! CIRISPersist#81).
//!
//! 6 columns, PK on `occurrence_id`. `metadata` rides as
//! `Option<serde_json::Value>` (JSONB on the wire). Timestamps ride
//! as `chrono::DateTime<Utc>` (TIMESTAMPTZ).
//!
//! `registered_at` / `last_heartbeat` / `expires_at` are computed in
//! Rust (chrono) and bound — not via SQL `NOW()` — so the three
//! values are mutually consistent within one call and the TTL math
//! is testable.

use chrono::{Duration, Utc};

use super::service::OccurrenceService;
use super::types::OccurrenceRecord;
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

fn decode_row(row: &tokio_postgres::Row) -> Result<OccurrenceRecord, Error> {
    Ok(OccurrenceRecord {
        occurrence_id: row
            .try_get("occurrence_id")
            .map_err(|e| Error::Backend(format!("decode occurrence_id: {e}")))?,
        identity: row
            .try_get("identity")
            .map_err(|e| Error::Backend(format!("decode identity: {e}")))?,
        registered_at: row
            .try_get("registered_at")
            .map_err(|e| Error::Backend(format!("decode registered_at: {e}")))?,
        last_heartbeat: row
            .try_get("last_heartbeat")
            .map_err(|e| Error::Backend(format!("decode last_heartbeat: {e}")))?,
        expires_at: row
            .try_get("expires_at")
            .map_err(|e| Error::Backend(format!("decode expires_at: {e}")))?,
        metadata: row
            .try_get("metadata")
            .map_err(|e| Error::Backend(format!("decode metadata: {e}")))?,
    })
}

const SELECT_COLUMNS: &str =
    "occurrence_id, identity, registered_at, last_heartbeat, expires_at, metadata";

impl OccurrenceService for PostgresBackend {
    async fn register_occurrence(
        &self,
        occurrence_id: &str,
        identity: &str,
        ttl_seconds: i64,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), Error> {
        validate_register(occurrence_id, identity, ttl_seconds)?;
        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_seconds);
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        // Idempotent upsert: re-registering an occurrence refreshes
        // every column. The TTL clock restarts from `now`.
        client
            .execute(
                "INSERT INTO cirislens.occurrence_registry (\
                    occurrence_id, identity, registered_at, last_heartbeat, \
                    expires_at, metadata\
                 ) VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (occurrence_id) DO UPDATE \
                   SET identity = EXCLUDED.identity, \
                       registered_at = EXCLUDED.registered_at, \
                       last_heartbeat = EXCLUDED.last_heartbeat, \
                       expires_at = EXCLUDED.expires_at, \
                       metadata = EXCLUDED.metadata",
                &[
                    &occurrence_id,
                    &identity,
                    &now,
                    &now,
                    &expires_at,
                    &metadata,
                ],
            )
            .await
            .map_err(|e| map_pg_error(e, "register_occurrence"))?;
        Ok(())
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
        let now = Utc::now();
        let expires_at = now + Duration::seconds(ttl_seconds);
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let affected = client
            .execute(
                "UPDATE cirislens.occurrence_registry \
                 SET last_heartbeat = $2, expires_at = $3 \
                 WHERE occurrence_id = $1",
                &[&occurrence_id, &now, &expires_at],
            )
            .await
            .map_err(|e| map_pg_error(e, "heartbeat_occurrence"))?;
        Ok(affected > 0)
    }

    async fn deregister_occurrence(&self, occurrence_id: &str) -> Result<bool, Error> {
        if occurrence_id.is_empty() {
            return Err(Error::InvalidArgument("occurrence_id required".into()));
        }
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let affected = client
            .execute(
                "DELETE FROM cirislens.occurrence_registry WHERE occurrence_id = $1",
                &[&occurrence_id],
            )
            .await
            .map_err(|e| map_pg_error(e, "deregister_occurrence"))?;
        Ok(affected > 0)
    }

    async fn list_live_occurrences(&self, identity: &str) -> Result<Vec<OccurrenceRecord>, Error> {
        if identity.is_empty() {
            return Err(Error::InvalidArgument("identity required".into()));
        }
        let now = Utc::now();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                &format!(
                    "SELECT {SELECT_COLUMNS} FROM cirislens.occurrence_registry \
                     WHERE identity = $1 AND expires_at > $2 \
                     ORDER BY occurrence_id"
                ),
                &[&identity, &now],
            )
            .await
            .map_err(|e| map_pg_error(e, "list_live_occurrences"))?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push(decode_row(row)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    fn unique_id(prefix: &str) -> String {
        format!("{prefix}-{}", Uuid::new_v4().simple())
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn register_then_list_live_shows_it_fields_round_trip() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let identity = unique_id("id");
        let occ = unique_id("occ");
        let meta = serde_json::json!({"endpoint": "10.0.0.1:9000"});
        OccurrenceService::register_occurrence(&backend, &occ, &identity, 3600, Some(meta.clone()))
            .await
            .unwrap();
        let live = OccurrenceService::list_live_occurrences(&backend, &identity)
            .await
            .unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].occurrence_id, occ);
        assert_eq!(live[0].identity, identity);
        assert_eq!(live[0].metadata, Some(meta));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn re_register_updates_row_still_one_row() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id_a = unique_id("id");
        let id_b = unique_id("id");
        let occ = unique_id("occ");
        OccurrenceService::register_occurrence(&backend, &occ, &id_a, 3600, None)
            .await
            .unwrap();
        let first = OccurrenceService::list_live_occurrences(&backend, &id_a)
            .await
            .unwrap();
        let first_expires = first[0].expires_at;
        // Re-register under a different identity + metadata + ttl.
        let meta = serde_json::json!({"v": 2});
        OccurrenceService::register_occurrence(&backend, &occ, &id_b, 7200, Some(meta.clone()))
            .await
            .unwrap();
        // Old identity no longer lists it.
        assert!(OccurrenceService::list_live_occurrences(&backend, &id_a)
            .await
            .unwrap()
            .is_empty());
        let now = OccurrenceService::list_live_occurrences(&backend, &id_b)
            .await
            .unwrap();
        assert_eq!(now.len(), 1, "still one row");
        assert_eq!(now[0].identity, id_b);
        assert_eq!(now[0].metadata, Some(meta));
        assert!(now[0].expires_at > first_expires, "expires refreshed");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn heartbeat_bumps_expires_unknown_returns_false() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let identity = unique_id("id");
        let occ = unique_id("occ");
        OccurrenceService::register_occurrence(&backend, &occ, &identity, 10, None)
            .await
            .unwrap();
        let before = OccurrenceService::list_live_occurrences(&backend, &identity)
            .await
            .unwrap()[0]
            .expires_at;
        let bumped = OccurrenceService::heartbeat_occurrence(&backend, &occ, 3600)
            .await
            .unwrap();
        assert!(bumped);
        let after = OccurrenceService::list_live_occurrences(&backend, &identity)
            .await
            .unwrap()[0]
            .expires_at;
        assert!(after > before, "heartbeat bumps expires_at");
        // Heartbeat of an unregistered occurrence → false, no error.
        let unknown = OccurrenceService::heartbeat_occurrence(&backend, &unique_id("occ"), 60)
            .await
            .unwrap();
        assert!(!unknown);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn deregister_removes_row_absent_returns_false() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let identity = unique_id("id");
        let occ = unique_id("occ");
        OccurrenceService::register_occurrence(&backend, &occ, &identity, 3600, None)
            .await
            .unwrap();
        let removed = OccurrenceService::deregister_occurrence(&backend, &occ)
            .await
            .unwrap();
        assert!(removed);
        assert!(
            OccurrenceService::list_live_occurrences(&backend, &identity)
                .await
                .unwrap()
                .is_empty()
        );
        // Deregister of an absent occurrence → false, idempotent.
        let again = OccurrenceService::deregister_occurrence(&backend, &occ)
            .await
            .unwrap();
        assert!(!again);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn ttl_expiry_filters_expired_rows() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let identity = unique_id("id");
        let occ_a = unique_id("occ");
        let occ_b = unique_id("occ");
        OccurrenceService::register_occurrence(&backend, &occ_a, &identity, 3600, None)
            .await
            .unwrap();
        OccurrenceService::register_occurrence(&backend, &occ_b, &identity, 3600, None)
            .await
            .unwrap();
        // Force occ_b's expires_at into the past via raw SQL — proves
        // the `expires_at > now` filter without a real sleep.
        let client = backend.pool().get().await.unwrap();
        let past = Utc::now() - Duration::hours(1);
        client
            .execute(
                "UPDATE cirislens.occurrence_registry \
                 SET expires_at = $2 WHERE occurrence_id = $1",
                &[&occ_b, &past],
            )
            .await
            .unwrap();
        let live = OccurrenceService::list_live_occurrences(&backend, &identity)
            .await
            .unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].occurrence_id, occ_a);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn identities_are_isolated() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let id_a = unique_id("id");
        let id_b = unique_id("id");
        let occ_a = unique_id("occ");
        let occ_b = unique_id("occ");
        OccurrenceService::register_occurrence(&backend, &occ_a, &id_a, 3600, None)
            .await
            .unwrap();
        OccurrenceService::register_occurrence(&backend, &occ_b, &id_b, 3600, None)
            .await
            .unwrap();
        let live_a = OccurrenceService::list_live_occurrences(&backend, &id_a)
            .await
            .unwrap();
        assert_eq!(live_a.len(), 1);
        assert_eq!(live_a[0].occurrence_id, occ_a);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn invalid_arguments_rejected() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let r = OccurrenceService::register_occurrence(&backend, "", "id", 60, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = OccurrenceService::register_occurrence(&backend, "occ", "", 60, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = OccurrenceService::register_occurrence(&backend, "occ", "id", 0, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = OccurrenceService::register_occurrence(&backend, "occ", "id", -5, None).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = OccurrenceService::heartbeat_occurrence(&backend, "", 60).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = OccurrenceService::heartbeat_occurrence(&backend, "occ", 0).await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = OccurrenceService::deregister_occurrence(&backend, "").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
        let r = OccurrenceService::list_live_occurrences(&backend, "").await;
        assert!(matches!(r, Err(Error::InvalidArgument(_))));
    }
}
