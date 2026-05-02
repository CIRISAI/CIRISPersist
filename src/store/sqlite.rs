//! SQLite backend (Phase 1 parity, v0.1.21+).
//!
//! # Mission alignment (MISSION.md §2 — `store/`)
//!
//! Same Backend trait surface as the in-memory and Postgres backends.
//! The SQLite-specific bits — synchronous `rusqlite::Connection`
//! wrapped in `tokio::task::spawn_blocking`, ISO-8601 TEXT timestamps,
//! TEXT-as-JSON payload column, single-file or `:memory:` storage —
//! live behind the trait, not through it.
//!
//! # Why SQLite (FSD §7 #7)
//!
//! Sovereign-mode lens deployments don't need Postgres + TimescaleDB.
//! A single agent + lens running on a Pi-class node can land traces
//! directly into SQLite with the same `Backend` trait the multi-tenant
//! lens uses against Postgres. The SQL writer adapts row → SQL the
//! same way; the only difference is the substrate.
//!
//! # Implementation notes
//!
//! - **Connection model**: a single `rusqlite::Connection` wrapped in
//!   `Arc<Mutex<…>>`. Phase 1 has one ingest writer per process
//!   (FSD §3.4 robustness primitive #1: bounded queue, single
//!   persister consumer); contention on the mutex is structurally
//!   negligible. A future Phase 2 multi-reader workload would benefit
//!   from `r2d2-sqlite` pooling.
//! - **Async adapter**: `tokio::task::spawn_blocking` wraps every SQL
//!   call. rusqlite is synchronous; spawn_blocking moves the work to
//!   a tokio worker thread so the main runtime keeps spinning.
//! - **Migrations**: `refinery` against the `migrations/sqlite/lens/`
//!   directory. Same migration file naming as postgres
//!   (`V001__trace_events.sql`, `V003__scrub_envelope.sql`) so refinery
//!   tracks them in a parallel `__refinery_schema_history` table.
//! - **Batch insert**: parameterized
//!   `INSERT INTO … VALUES (…), (…), … ON CONFLICT DO NOTHING`. SQLite
//!   3.24+ supports `ON CONFLICT` clauses; the bundled rusqlite ships a
//!   recent-enough libsqlite3.
//! - **Idempotency**: the `trace_events_dedup` UNIQUE index in
//!   `V001__trace_events.sql` is the conflict target — same shape as
//!   the postgres index (THREAT_MODEL.md AV-9, includes
//!   `agent_id_hash`).

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ed25519_dalek::VerifyingKey;
use rusqlite::{params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use tokio::sync::Mutex;

use super::backend::{Backend, InsertReport, PublicKeySample};
use super::types::{TraceEventRow, TraceLlmCallRow};
use super::Error;
use crate::schema::ReasoningEventType;

mod embedded {
    refinery::embed_migrations!("migrations/sqlite/lens");
}

/// SQLite-backed [`Backend`] impl.
///
/// Construct via [`SqliteBackend::open`] for a file-backed database
/// or [`SqliteBackend::open_in_memory`] for tests. Run migrations once
/// after construction via [`Backend::run_migrations`].
pub struct SqliteBackend {
    /// Owning handle. `Arc<Mutex<…>>` so spawn_blocking closures can
    /// take ownership of a clone without moving `&self`.
    conn: Arc<Mutex<Connection>>,
}

impl SqliteBackend {
    /// Open (or create) a file-backed SQLite database.
    ///
    /// Path is passed verbatim to `rusqlite::Connection::open`. Use
    /// [`SqliteBackend::open_in_memory`] for ephemeral tests.
    pub async fn open(path: impl Into<String>) -> Result<Self, Error> {
        let path = path.into();
        let conn = tokio::task::spawn_blocking(move || Connection::open(path))
            .await
            .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
            .map_err(|e| Error::Backend(format!("sqlite open: {e}")))?;
        Self::with_connection_settings(conn).await
    }

    /// Open an in-memory SQLite database (for tests + sovereign-mode
    /// dev scratch).
    pub async fn open_in_memory() -> Result<Self, Error> {
        let conn = tokio::task::spawn_blocking(Connection::open_in_memory)
            .await
            .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
            .map_err(|e| Error::Backend(format!("sqlite open in-memory: {e}")))?;
        Self::with_connection_settings(conn).await
    }

    /// Apply the pragmas every SqliteBackend connection runs at boot.
    /// Centralized so file-backed and in-memory share the same shape.
    async fn with_connection_settings(conn: Connection) -> Result<Self, Error> {
        let conn = tokio::task::spawn_blocking(move || -> Result<Connection, rusqlite::Error> {
            // Foreign keys are off by default in SQLite for backwards
            // compat — turn them on so any future FK constraints we
            // declare actually fire. None today, but good hygiene.
            conn.execute_batch(
                "PRAGMA foreign_keys = ON;\n\
                 PRAGMA journal_mode = WAL;\n\
                 PRAGMA synchronous = NORMAL;",
            )?;
            Ok(conn)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| Error::Backend(format!("sqlite pragmas: {e}")))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }
}

impl Backend for SqliteBackend {
    async fn insert_trace_events_batch(
        &self,
        rows: &[TraceEventRow],
    ) -> Result<InsertReport, Error> {
        if rows.is_empty() {
            return Ok(InsertReport::default());
        }
        // Materialize the parameter vector before crossing the
        // spawn_blocking boundary so the closure is `'static`.
        let owned: Vec<TraceEventRow> = rows.to_vec();
        let total = owned.len();

        let conn = self.conn.clone();
        let inserted = tokio::task::spawn_blocking(move || -> Result<usize, rusqlite::Error> {
            let mut conn = conn.blocking_lock();
            let tx = conn.transaction()?;
            let mut inserted = 0usize;

            // Single-row prepared INSERT inside a transaction. SQLite
            // optimizes this case well (parsed once, executed N times)
            // and the per-row branching for audit-anchor extraction
            // is simpler than building a multi-row VALUES list with
            // varying NULLs.
            const SQL: &str = "INSERT INTO trace_events (\
                trace_id, thought_id, task_id, step_point, event_type, \
                attempt_index, ts, agent_name, agent_id_hash, cognitive_state, \
                trace_level, payload, cost_llm_calls, cost_tokens, cost_usd, \
                signature, signing_key_id, signature_verified, schema_version, \
                pii_scrubbed, audit_sequence_number, audit_entry_hash, audit_signature, \
                original_content_hash, scrub_signature, scrub_key_id, scrub_timestamp\
                ) VALUES (\
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27\
                ) ON CONFLICT (agent_id_hash, trace_id, thought_id, event_type, \
                attempt_index, ts) DO NOTHING";

            {
                let mut stmt = tx.prepare(SQL)?;
                for row in &owned {
                    let (audit_seq, audit_hash, audit_sig): (
                        Option<i64>,
                        Option<String>,
                        Option<String>,
                    ) = if row.event_type == ReasoningEventType::ActionResult {
                        let seq = row
                            .payload
                            .get("audit_sequence_number")
                            .and_then(|v| v.as_i64());
                        let hash = row
                            .payload
                            .get("audit_entry_hash")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned);
                        let sig = row
                            .payload
                            .get("audit_signature")
                            .and_then(|v| v.as_str())
                            .map(str::to_owned);
                        (seq, hash, sig)
                    } else {
                        (None, None, None)
                    };

                    let payload_text =
                        serde_json::to_string(&serde_json::Value::Object(row.payload.clone()))
                            .map_err(|e| {
                                rusqlite::Error::ToSqlConversionFailure(Box::new(
                                    std::io::Error::new(std::io::ErrorKind::InvalidData, e),
                                ))
                            })?;

                    let attempt_index_i64 = i64::from(row.attempt_index);

                    let params: [SqlValue; 27] = [
                        SqlValue::Text(row.trace_id.clone()),
                        SqlValue::Text(row.thought_id.clone()),
                        opt_text(row.task_id.as_deref()),
                        opt_text(row.step_point.as_deref()),
                        SqlValue::Text(row.event_type.as_str().to_owned()),
                        SqlValue::Integer(attempt_index_i64),
                        SqlValue::Text(row.ts.to_rfc3339()),
                        opt_text(row.agent_name.as_deref()),
                        SqlValue::Text(row.agent_id_hash.clone()),
                        opt_text(row.cognitive_state.as_deref()),
                        SqlValue::Text(trace_level_str(row.trace_level).to_owned()),
                        SqlValue::Text(payload_text),
                        opt_int(row.cost_llm_calls),
                        opt_int(row.cost_tokens),
                        opt_real(row.cost_usd),
                        SqlValue::Text(row.signature.clone()),
                        SqlValue::Text(row.signing_key_id.clone()),
                        SqlValue::Integer(i64::from(row.signature_verified)),
                        SqlValue::Text(row.schema_version.clone()),
                        SqlValue::Integer(i64::from(row.pii_scrubbed)),
                        opt_i64(audit_seq),
                        opt_text(audit_hash.as_deref()),
                        opt_text(audit_sig.as_deref()),
                        opt_text(row.original_content_hash.as_deref()),
                        opt_text(row.scrub_signature.as_deref()),
                        opt_text(row.scrub_key_id.as_deref()),
                        opt_text(
                            row.scrub_timestamp
                                .as_ref()
                                .map(|t| t.to_rfc3339())
                                .as_deref(),
                        ),
                    ];

                    let n = stmt.execute(params_from_iter(params.iter()))?;
                    inserted += n;
                }
            }

            tx.commit()?;
            Ok(inserted)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| Error::Backend(format!("insert trace_events: {e}")))?;

        Ok(InsertReport {
            inserted,
            conflicted: total.saturating_sub(inserted),
        })
    }

    async fn insert_trace_llm_calls_batch(&self, rows: &[TraceLlmCallRow]) -> Result<usize, Error> {
        if rows.is_empty() {
            return Ok(0);
        }
        let owned: Vec<TraceLlmCallRow> = rows.to_vec();
        let conn = self.conn.clone();
        let inserted = tokio::task::spawn_blocking(move || -> Result<usize, rusqlite::Error> {
            let mut conn = conn.blocking_lock();
            let tx = conn.transaction()?;
            let mut inserted = 0usize;

            const SQL: &str = "INSERT INTO trace_llm_calls (\
                trace_id, thought_id, task_id, parent_event_id, parent_event_type, \
                parent_attempt_index, attempt_index, ts, duration_ms, handler_name, \
                service_name, model, base_url, response_model, prompt_tokens, \
                completion_tokens, prompt_bytes, completion_bytes, cost_usd, status, \
                error_class, attempt_count, retry_count, prompt_hash, prompt, \
                response_text\
                ) VALUES (\
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26\
                )";

            {
                let mut stmt = tx.prepare(SQL)?;
                for r in &owned {
                    let params: [SqlValue; 26] = [
                        SqlValue::Text(r.trace_id.clone()),
                        SqlValue::Text(r.thought_id.clone()),
                        opt_text(r.task_id.as_deref()),
                        opt_i64(r.parent_event_id),
                        SqlValue::Text(r.parent_event_type.as_str().to_owned()),
                        SqlValue::Integer(i64::from(r.parent_attempt_index)),
                        SqlValue::Integer(i64::from(r.attempt_index)),
                        SqlValue::Text(r.ts.to_rfc3339()),
                        SqlValue::Real(r.duration_ms),
                        SqlValue::Text(r.handler_name.clone()),
                        SqlValue::Text(r.service_name.clone()),
                        opt_text(r.model.as_deref()),
                        opt_text(r.base_url.as_deref()),
                        opt_text(r.response_model.as_deref()),
                        opt_int(r.prompt_tokens),
                        opt_int(r.completion_tokens),
                        opt_int(r.prompt_bytes),
                        opt_int(r.completion_bytes),
                        opt_real(r.cost_usd),
                        SqlValue::Text(llm_status_str(r.status).to_owned()),
                        opt_text(r.error_class.as_deref()),
                        opt_int(r.attempt_count),
                        opt_int(r.retry_count),
                        opt_text(r.prompt_hash.as_deref()),
                        opt_text(r.prompt.as_deref()),
                        opt_text(r.response_text.as_deref()),
                    ];
                    let n = stmt.execute(params_from_iter(params.iter()))?;
                    inserted += n;
                }
            }

            tx.commit()?;
            Ok(inserted)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| Error::Backend(format!("insert trace_llm_calls: {e}")))?;
        Ok(inserted)
    }

    async fn lookup_public_key(&self, key_id: &str) -> Result<Option<VerifyingKey>, Error> {
        let key_id = key_id.to_owned();
        let conn = self.conn.clone();
        let row_opt =
            tokio::task::spawn_blocking(move || -> Result<Option<String>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                // Filter matches postgres lookup_public_key: unrevoked,
                // unexpired. SQLite uses CURRENT_TIMESTAMP which emits
                // ISO-8601 UTC; since we store TIMESTAMPTZ as TEXT in
                // RFC 3339, lexical comparison on the strings produces
                // the right ordering for UTC timestamps.
                conn.query_row(
                    "SELECT public_key_base64 FROM accord_public_keys \
                 WHERE key_id = ?1 \
                   AND revoked_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
                    [&key_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
            .map_err(|e| Error::Backend(format!("lookup_public_key: {e}")))?;

        let Some(b64) = row_opt else {
            return Ok(None);
        };
        let bytes = BASE64
            .decode(&b64)
            .map_err(|e| Error::Backend(format!("public_key_base64 decode: {e}")))?;
        if bytes.len() != 32 {
            return Err(Error::Backend(format!(
                "public_key_base64 wrong length: got {}, expected 32",
                bytes.len()
            )));
        }
        let arr: [u8; 32] = bytes.as_slice().try_into().expect("length-checked");
        let key = VerifyingKey::from_bytes(&arr)
            .map_err(|e| Error::Backend(format!("public_key parse: {e}")))?;
        Ok(Some(key))
    }

    async fn sample_public_keys(&self, limit: usize) -> Result<PublicKeySample, Error> {
        // Same filter as `lookup_public_key`, ORDER BY key_id LIMIT N.
        // Diagnostic-only path; mirrors the postgres impl so the
        // verify-unknown-key breadcrumb (CIRISPersist#6, v0.1.17) sees
        // identical shape regardless of backend.
        let conn = self.conn.clone();
        let lim = i64::try_from(limit).unwrap_or(i64::MAX);

        let (size, sample) = tokio::task::spawn_blocking(
            move || -> Result<(usize, Vec<String>), rusqlite::Error> {
                let conn = conn.blocking_lock();
                let total: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM accord_public_keys \
                     WHERE revoked_at IS NULL \
                       AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)",
                    [],
                    |r| r.get(0),
                )?;
                let mut stmt = conn.prepare(
                    "SELECT key_id FROM accord_public_keys \
                     WHERE revoked_at IS NULL \
                       AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) \
                     ORDER BY key_id LIMIT ?1",
                )?;
                let rows = stmt.query_map([lim], |r| r.get::<_, String>(0))?;
                let mut sample = Vec::new();
                for r in rows {
                    sample.push(r?);
                }
                Ok((usize::try_from(total.max(0)).unwrap_or(0), sample))
            },
        )
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| Error::Backend(format!("sample_public_keys: {e}")))?;

        Ok(PublicKeySample { size, sample })
    }

    async fn run_migrations(&self) -> Result<(), Error> {
        // refinery's `runner().run(&mut Connection)` is sync; we wrap
        // it in spawn_blocking. SQLite has no advisory-lock equivalent
        // to postgres's `pg_advisory_lock`, but the Phase 1 sovereign-
        // mode use case is single-process / single-writer (one ingest
        // per Pi-class node), so the multi-worker boot race v0.1.5
        // closed for postgres doesn't surface here. If multi-process
        // SQLite ever lands (unusual; SQLite's WAL handles
        // concurrent readers but writers serialize on the database
        // file lock anyway), refinery's idempotent IF NOT EXISTS
        // semantics on its schema_history table cover the race.
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), refinery::Error> {
            let mut conn = conn.blocking_lock();
            embedded::migrations::runner().run(&mut *conn)?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| Error::Migration {
            sqlstate: None,
            detail: format!("sqlite migrations: {e}"),
        })?;
        Ok(())
    }
}

// ─── Helpers ───────────────────────────────────────────────────────

fn opt_text(v: Option<&str>) -> SqlValue {
    match v {
        Some(s) => SqlValue::Text(s.to_owned()),
        None => SqlValue::Null,
    }
}

fn opt_int(v: Option<i32>) -> SqlValue {
    match v {
        Some(i) => SqlValue::Integer(i64::from(i)),
        None => SqlValue::Null,
    }
}

fn opt_i64(v: Option<i64>) -> SqlValue {
    match v {
        Some(i) => SqlValue::Integer(i),
        None => SqlValue::Null,
    }
}

fn opt_real(v: Option<f64>) -> SqlValue {
    match v {
        Some(f) => SqlValue::Real(f),
        None => SqlValue::Null,
    }
}

fn trace_level_str(t: crate::schema::TraceLevel) -> &'static str {
    match t {
        crate::schema::TraceLevel::Generic => "generic",
        crate::schema::TraceLevel::Detailed => "detailed",
        crate::schema::TraceLevel::FullTraces => "full_traces",
    }
}

fn llm_status_str(s: crate::schema::LlmCallStatus) -> &'static str {
    match s {
        crate::schema::LlmCallStatus::Ok => "ok",
        crate::schema::LlmCallStatus::Timeout => "timeout",
        crate::schema::LlmCallStatus::RateLimited => "rate_limited",
        crate::schema::LlmCallStatus::ModelNotAvailable => "model_not_available",
        crate::schema::LlmCallStatus::InstructorRetry => "instructor_retry",
        crate::schema::LlmCallStatus::OtherError => "other_error",
    }
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{LlmCallStatus, ReasoningEventType, TraceLevel};
    use chrono::{TimeZone, Utc};

    fn fixture_event_row(trace_id: &str, attempt: u32) -> TraceEventRow {
        TraceEventRow {
            trace_id: trace_id.to_owned(),
            thought_id: "th-1".to_owned(),
            task_id: Some("task-1".to_owned()),
            step_point: Some("OBSERVE".to_owned()),
            event_type: ReasoningEventType::ThoughtStart,
            attempt_index: attempt,
            ts: Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap(),
            agent_name: Some("agent-test".to_owned()),
            agent_id_hash: "deadbeef".to_owned(),
            cognitive_state: Some("WORK".to_owned()),
            trace_level: TraceLevel::Generic,
            payload: serde_json::Map::new(),
            cost_llm_calls: None,
            cost_tokens: None,
            cost_usd: None,
            signature: "sig-test".to_owned(),
            signing_key_id: "key-test".to_owned(),
            signature_verified: true,
            schema_version: "2.7.0".to_owned(),
            pii_scrubbed: true,
            original_content_hash: Some("aabbcc".to_owned()),
            scrub_signature: Some("sig-scrub".to_owned()),
            scrub_key_id: Some("scrub-key-1".to_owned()),
            scrub_timestamp: Some(Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 1).unwrap()),
        }
    }

    fn fixture_llm_row(trace_id: &str, attempt: u32) -> TraceLlmCallRow {
        TraceLlmCallRow {
            trace_id: trace_id.to_owned(),
            thought_id: "th-1".to_owned(),
            task_id: None,
            parent_event_id: Some(1),
            parent_event_type: ReasoningEventType::ThoughtStart,
            parent_attempt_index: 0,
            attempt_index: attempt,
            ts: Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap(),
            duration_ms: 1433.2029819488525,
            handler_name: "handler-test".to_owned(),
            service_name: "openai".to_owned(),
            model: Some("gpt-4".to_owned()),
            base_url: None,
            response_model: None,
            prompt_tokens: Some(100),
            completion_tokens: Some(50),
            prompt_bytes: Some(400),
            completion_bytes: Some(200),
            cost_usd: Some(0.0031992000000000006),
            status: LlmCallStatus::Ok,
            error_class: None,
            attempt_count: Some(1),
            retry_count: Some(0),
            prompt_hash: Some("ph-1".to_owned()),
            prompt: None,
            response_text: None,
        }
    }

    /// Smoke: open in-memory, run migrations, both lens tables exist.
    #[tokio::test]
    async fn migrations_run_clean_in_memory() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();

        // Re-running is a no-op (refinery tracks applied versions).
        backend.run_migrations().await.unwrap();
    }

    /// Idempotency: insert the same event twice; second insert reports
    /// `conflicted`. Mirrors postgres test `insert_idempotent`.
    #[tokio::test]
    async fn insert_idempotent() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();

        let row = fixture_event_row("trace-x-1", 0);
        let r1 = backend
            .insert_trace_events_batch(std::slice::from_ref(&row))
            .await
            .unwrap();
        assert_eq!(r1.inserted, 1);
        assert_eq!(r1.conflicted, 0);

        let r2 = backend
            .insert_trace_events_batch(std::slice::from_ref(&row))
            .await
            .unwrap();
        assert_eq!(r2.inserted, 0, "second insert hits ON CONFLICT DO NOTHING");
        assert_eq!(r2.conflicted, 1);
    }

    /// Two events with different attempt_index are separate rows
    /// (FSD §3.4 #4 — per-attempt dedup tuple).
    #[tokio::test]
    async fn distinct_attempts_both_land() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let row0 = fixture_event_row("trace-x-2", 0);
        let row1 = fixture_event_row("trace-x-2", 1);
        let r = backend
            .insert_trace_events_batch(&[row0, row1])
            .await
            .unwrap();
        assert_eq!(r.inserted, 2);
        assert_eq!(r.conflicted, 0);
    }

    /// llm_calls batch insert + non-empty rows.
    #[tokio::test]
    async fn llm_calls_batch_insert() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let rows = vec![
            fixture_llm_row("trace-x-3", 0),
            fixture_llm_row("trace-x-3", 1),
        ];
        let n = backend.insert_trace_llm_calls_batch(&rows).await.unwrap();
        assert_eq!(n, 2);
    }

    /// Empty batch returns zero without touching the DB.
    #[tokio::test]
    async fn empty_batches_are_noops() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let r = backend.insert_trace_events_batch(&[]).await.unwrap();
        assert_eq!(r.inserted, 0);
        assert_eq!(r.conflicted, 0);
        let n = backend.insert_trace_llm_calls_batch(&[]).await.unwrap();
        assert_eq!(n, 0);
    }

    fn fixture_pubkey() -> ed25519_dalek::VerifyingKey {
        // Deterministic 32-byte seed → SigningKey → VerifyingKey, so
        // we don't pull `rand` into the dev-deps just for tests.
        let seed: [u8; 32] = [7u8; 32];
        ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key()
    }

    /// public_key lookup hits round-trip through base64 → 32-byte
    /// VerifyingKey. Insert a known key directly into accord_public_keys
    /// (test fixture) and look it up.
    #[tokio::test]
    async fn lookup_public_key_round_trip() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();

        let verifying = fixture_pubkey();
        let pk_b64 = BASE64.encode(verifying.to_bytes());

        // Insert the row directly via the connection (the federation
        // directory ingest path is v0.3.0 work).
        {
            let conn = backend.conn.clone();
            tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
                let conn = conn.blocking_lock();
                conn.execute(
                    "INSERT INTO accord_public_keys (key_id, public_key_base64, algorithm) \
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params!["key-test", pk_b64, "ed25519"],
                )?;
                Ok(())
            })
            .await
            .unwrap()
            .unwrap();
        }

        let got = backend.lookup_public_key("key-test").await.unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().to_bytes(), verifying.to_bytes());

        // Unknown key returns None.
        let none = backend.lookup_public_key("key-missing").await.unwrap();
        assert!(none.is_none());
    }

    /// Revoked keys are filtered out of lookup AND sample.
    #[tokio::test]
    async fn revoked_keys_filtered() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();

        let pk_b64 = BASE64.encode(fixture_pubkey().to_bytes());

        // Insert two rows: one valid, one revoked.
        {
            let conn = backend.conn.clone();
            let pk_b64 = pk_b64.clone();
            tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
                let conn = conn.blocking_lock();
                conn.execute(
                    "INSERT INTO accord_public_keys (key_id, public_key_base64) VALUES (?1, ?2)",
                    rusqlite::params!["key-active", pk_b64],
                )?;
                conn.execute(
                    "INSERT INTO accord_public_keys (key_id, public_key_base64, revoked_at) \
                     VALUES (?1, ?2, ?3)",
                    rusqlite::params!["key-revoked", pk_b64, "2026-04-30T00:00:00+00:00"],
                )?;
                Ok(())
            })
            .await
            .unwrap()
            .unwrap();
        }

        assert!(backend
            .lookup_public_key("key-active")
            .await
            .unwrap()
            .is_some());
        assert!(backend
            .lookup_public_key("key-revoked")
            .await
            .unwrap()
            .is_none());

        let sample = backend.sample_public_keys(10).await.unwrap();
        assert_eq!(sample.size, 1);
        assert_eq!(sample.sample, vec!["key-active".to_owned()]);
    }
}
