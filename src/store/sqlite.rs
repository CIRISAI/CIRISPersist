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
    /// Shared connection handle. Used by sibling modules
    /// (cirisgraph SQLite impl in v0.8.4+) that ride on the same
    /// underlying SQLite file/in-memory connection.
    pub fn conn_handle(&self) -> std::sync::Arc<tokio::sync::Mutex<Connection>> {
        self.conn.clone()
    }

    /// v2.1 (CIRISPersist#101) — construct a `SqliteBackend` from an
    /// existing connection handle (e.g. one shared with the cirisnode
    /// substrate). Used internally by `cirisnode::sqlite` to compose
    /// a `FederationDirectory` view over the same connection without
    /// reopening the file. NO pragmas are applied — the caller has
    /// already initialized the connection via
    /// [`SqliteBackend::open`] / [`SqliteBackend::open_in_memory`].
    pub fn from_conn_handle(conn: std::sync::Arc<tokio::sync::Mutex<Connection>>) -> Self {
        Self { conn }
    }

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
            //
            // v0.8.4: `busy_timeout = 30000` (ms) matches the
            // CIRISAgent iOS connection-open default. Per the
            // hard-won-victory lesson in
            // `ciris_engine/logic/persistence/db/core.py` —
            // contended SQLite operations should wait up to 30s
            // for the lock rather than fail-fast with SQLITE_BUSY.
            // Applies universally (not iOS-specific) — good
            // hygiene on Pi-class deployments + dev laptops with
            // background indexers touching the WAL.
            conn.execute_batch(
                "PRAGMA foreign_keys = ON;\n\
                 PRAGMA journal_mode = WAL;\n\
                 PRAGMA synchronous = NORMAL;\n\
                 PRAGMA busy_timeout = 30000;",
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
                original_content_hash, scrub_signature, scrub_key_id, scrub_timestamp, \
                agent_role, agent_template, deployment_domain, \
                deployment_type, deployment_region, deployment_trust_mode, \
                verification_source\
                ) VALUES (\
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, \
                ?28, ?29, ?30, ?31, ?32, ?33, ?34\
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

                    let params: [SqlValue; 34] = [
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
                        // v0.3.4 deployment_profile (V006).
                        opt_text(row.agent_role.as_deref()),
                        opt_text(row.agent_template.as_deref()),
                        opt_text(row.deployment_domain.as_deref()),
                        opt_text(row.deployment_type.as_deref()),
                        opt_text(row.deployment_region.as_deref()),
                        opt_text(row.deployment_trust_mode.as_deref()),
                        // v2.0 verification_source (V044, #91).
                        SqlValue::Text(row.verification_source.as_wire_str().to_owned()),
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
        // v0.4.0 (lens#8 ASK 2) — federation_keys is the canonical
        // pubkey directory. accord_public_keys fallback retired this
        // release. Same shape as PostgresBackend post-cutover.
        let key_id = key_id.to_owned();
        let conn = self.conn.clone();
        let b64_opt =
            tokio::task::spawn_blocking(move || -> Result<Option<String>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                conn.query_row(
                    "SELECT pubkey_ed25519_base64 FROM federation_keys \
                     WHERE key_id = ?1 \
                       AND (valid_until IS NULL OR valid_until > CURRENT_TIMESTAMP)",
                    [&key_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
            .map_err(|e| Error::Backend(format!("lookup_public_key: {e}")))?;

        let Some(b64) = b64_opt else {
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
        // v0.4.0 — diagnostic queries federation_keys (canonical
        // post-lens#8 ASK 2) so the verify-unknown-key breadcrumb
        // sample matches what `lookup_public_key` actually queries.
        let conn = self.conn.clone();
        let lim = i64::try_from(limit).unwrap_or(i64::MAX);

        let (size, sample) = tokio::task::spawn_blocking(
            move || -> Result<(usize, Vec<String>), rusqlite::Error> {
                let conn = conn.blocking_lock();
                let total: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM federation_keys \
                     WHERE valid_until IS NULL OR valid_until > CURRENT_TIMESTAMP",
                    [],
                    |r| r.get(0),
                )?;
                let mut stmt = conn.prepare(
                    "SELECT key_id FROM federation_keys \
                     WHERE valid_until IS NULL OR valid_until > CURRENT_TIMESTAMP \
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

    async fn delete_traces_for_agent(
        &self,
        agent_id_hash: &str,
        signature_key_id: &str,
        include_federation_key: bool,
    ) -> Result<super::types::DeleteSummary, Error> {
        let agent = agent_id_hash.to_owned();
        let key = signature_key_id.to_owned();
        let conn = self.conn.clone();
        let summary = tokio::task::spawn_blocking(
            move || -> Result<super::types::DeleteSummary, rusqlite::Error> {
                let mut conn = conn.blocking_lock();
                let tx = conn.transaction()?;
                // Per-key DSAR scope: both agent_id_hash AND
                // signing_key_id must match. Same shape as postgres.
                // Step 1: collect matching trace_ids.
                let trace_ids: Vec<String> = {
                    let mut stmt = tx.prepare(
                        "SELECT DISTINCT trace_id FROM trace_events \
                         WHERE agent_id_hash = ?1 AND signing_key_id = ?2",
                    )?;
                    let rows = stmt.query_map([&agent, &key], |r| r.get::<_, String>(0))?;
                    rows.collect::<Result<Vec<_>, _>>()?
                };

                // Step 2: delete LLM call rows joined by trace_id.
                let mut trace_llm_calls_deleted = 0u64;
                if !trace_ids.is_empty() {
                    let mut stmt = tx.prepare("DELETE FROM trace_llm_calls WHERE trace_id = ?1")?;
                    for tid in &trace_ids {
                        trace_llm_calls_deleted += stmt.execute([tid])? as u64;
                    }
                }

                // Step 3: delete trace_events rows. Same key-scope
                // filter as step 1.
                let trace_events_deleted = tx.execute(
                    "DELETE FROM trace_events \
                     WHERE agent_id_hash = ?1 AND signing_key_id = ?2",
                    [&agent, &key],
                )? as u64;

                let mut federation_keys_deleted = 0u64;
                let mut federation_attestations_deleted = 0u64;
                let mut federation_revocations_deleted = 0u64;

                if include_federation_key {
                    // Per-key federation_keys cascade: the single
                    // key_id matching (agent_id_hash, signature_key_id).
                    let target_key_ids: Vec<String> = {
                        let mut stmt = tx.prepare(
                            "SELECT key_id FROM federation_keys \
                             WHERE identity_type = 'agent' \
                               AND identity_ref = ?1 \
                               AND key_id = ?2",
                        )?;
                        let rows = stmt.query_map([&agent, &key], |r| r.get::<_, String>(0))?;
                        rows.collect::<Result<Vec<_>, _>>()?
                    };

                    if !target_key_ids.is_empty() {
                        // Per-key DELETE (sqlite doesn't have ANY/array
                        // params; iterate). Same row-count-summing
                        // shape as the trace_llm_calls loop above.
                        let mut rev_stmt = tx.prepare(
                            "DELETE FROM federation_revocations \
                             WHERE revoked_key_id = ?1 \
                                OR revoking_key_id = ?1 \
                                OR scrub_key_id    = ?1",
                        )?;
                        let mut att_stmt = tx.prepare(
                            "DELETE FROM federation_attestations \
                             WHERE attesting_key_id = ?1 \
                                OR attested_key_id  = ?1 \
                                OR scrub_key_id     = ?1",
                        )?;
                        let mut key_stmt =
                            tx.prepare("DELETE FROM federation_keys WHERE key_id = ?1")?;
                        for kid in &target_key_ids {
                            federation_revocations_deleted += rev_stmt.execute([kid])? as u64;
                            federation_attestations_deleted += att_stmt.execute([kid])? as u64;
                            federation_keys_deleted += key_stmt.execute([kid])? as u64;
                        }
                    }
                }

                tx.commit()?;
                Ok(super::types::DeleteSummary {
                    trace_events_deleted,
                    trace_llm_calls_deleted,
                    federation_keys_deleted,
                    federation_attestations_deleted,
                    federation_revocations_deleted,
                    deleted_at: chrono::Utc::now(),
                })
            },
        )
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| Error::Backend(format!("dsar tx: {e}")))?;
        Ok(summary)
    }

    async fn fetch_trace_events_page(
        &self,
        after_event_id: i64,
        limit: i64,
        agent_id_hash: Option<&str>,
    ) -> Result<Vec<(i64, TraceEventRow)>, Error> {
        let agent = agent_id_hash.map(str::to_owned);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<(i64, TraceEventRow)>, Error> {
            let conn = conn.blocking_lock();
            let cols = "event_id, trace_id, thought_id, task_id, step_point, event_type, \
                        attempt_index, ts, agent_name, agent_id_hash, cognitive_state, \
                        trace_level, payload, cost_llm_calls, cost_tokens, cost_usd, \
                        signature, signing_key_id, signature_verified, schema_version, \
                        pii_scrubbed, audit_sequence_number, audit_entry_hash, \
                        audit_signature, original_content_hash, scrub_signature, \
                        scrub_key_id, scrub_timestamp, agent_role, agent_template, \
                        deployment_domain, deployment_type, deployment_region, \
                        deployment_trust_mode, verification_source";
            let (sql, rows) = match agent {
                Some(h) => {
                    let sql = format!(
                        "SELECT {cols} FROM trace_events \
                         WHERE event_id > ?1 AND agent_id_hash = ?2 \
                         ORDER BY event_id ASC LIMIT ?3"
                    );
                    let mut stmt = conn
                        .prepare(&sql)
                        .map_err(|e| Error::Backend(format!("prepare: {e}")))?;
                    let rows = stmt
                        .query_map(
                            rusqlite::params![after_event_id, h, limit],
                            sqlite_row_to_event_row,
                        )
                        .map_err(|e| Error::Backend(format!("query_map: {e}")))?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| Error::Backend(format!("row map: {e}")))?;
                    (sql, rows)
                }
                None => {
                    let sql = format!(
                        "SELECT {cols} FROM trace_events \
                         WHERE event_id > ?1 \
                         ORDER BY event_id ASC LIMIT ?2"
                    );
                    let mut stmt = conn
                        .prepare(&sql)
                        .map_err(|e| Error::Backend(format!("prepare: {e}")))?;
                    let rows = stmt
                        .query_map(
                            rusqlite::params![after_event_id, limit],
                            sqlite_row_to_event_row,
                        )
                        .map_err(|e| Error::Backend(format!("query_map: {e}")))?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| Error::Backend(format!("row map: {e}")))?;
                    (sql, rows)
                }
            };
            let _ = sql; // hold for diagnostics if needed
            Ok(rows)
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
    }
}

// ─── Pipeline read+write surface (v1.5.8, CIRISPersist#57) ─────────
//
// Inherent methods on `SqliteBackend` for reading + writing the V023
// pipeline TEXT-as-JSON columns (`extracted_features`,
// `classifications`). Mirrors `PostgresBackend`'s v0.6.0-α5 read
// surface (postgres.rs read_features / read_classifications) and adds
// public write methods so the agent's AdaptiveFilter output can
// round-trip through persist without leaning on the internal pipeline
// classify-stage UPDATE.
//
// V023 stores all three columns as nullable TEXT (vs. PG JSONB). The
// json1 extension reads TEXT as JSON natively; on decode we go
// through `serde_json::from_str` rather than tokio-postgres'
// JSONB→serde_json::Value decode. Wire shape matches PG byte-for-byte.

impl SqliteBackend {
    /// v1.5.8 (CIRISPersist#57) — SQLite parity for `read_features`.
    /// Read typed [`Features`] for a `(trace_id, thought_id)` pair from
    /// `trace_events.extracted_features` (V023 column).
    ///
    /// Returns `Ok(None)` when:
    /// - The trace/thought pair has no rows, OR
    /// - The pipeline hasn't yet run on those rows
    ///   (`extracted_features IS NULL` — pre-V023 or pipeline-skipped
    ///   ingest paths).
    ///
    /// Wire format mirrors PG V009 / SQLite V023: the TEXT column
    /// stores the serde-encoded `Features` shape. Additive wire-shape
    /// changes only within v1.5.x.
    #[cfg(feature = "extract")]
    pub async fn read_features(
        &self,
        trace_id: &str,
        thought_id: &str,
    ) -> Result<Option<crate::pipeline::extract::Features>, Error> {
        let trace_id = trace_id.to_owned();
        let thought_id = thought_id.to_owned();
        let conn = self.conn.clone();
        let row_opt =
            tokio::task::spawn_blocking(move || -> Result<Option<String>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                conn.query_row(
                    "SELECT extracted_features \
                     FROM trace_events \
                     WHERE trace_id = ?1 AND thought_id = ?2 \
                       AND extracted_features IS NOT NULL \
                     LIMIT 1",
                    rusqlite::params![trace_id, thought_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
            .map_err(|e| Error::Backend(format!("read_features: {e}")))?;
        match row_opt {
            None => Ok(None),
            Some(text) => {
                let features: crate::pipeline::extract::Features = serde_json::from_str(&text)
                    .map_err(|e| Error::Backend(format!("extracted_features TEXT decode: {e}")))?;
                Ok(Some(features))
            }
        }
    }

    /// v1.5.8 (CIRISPersist#57) — SQLite parity for
    /// `read_classifications`. Read per-component classification matches
    /// for a `(trace_id, thought_id)` pair from
    /// `trace_events.classifications` (V023 column).
    ///
    /// Returns an empty vec when:
    /// - The trace/thought pair has no rows, OR
    /// - The pipeline hasn't yet run (`classifications IS NULL`).
    ///
    /// Outer vec is per-component (in the order the pipeline classify
    /// stage emitted); inner vec is per-match within that component.
    #[cfg(feature = "classify")]
    pub async fn read_classifications(
        &self,
        trace_id: &str,
        thought_id: &str,
    ) -> Result<Vec<Vec<crate::pipeline::classify::ContentClassMatch>>, Error> {
        let trace_id = trace_id.to_owned();
        let thought_id = thought_id.to_owned();
        let conn = self.conn.clone();
        let row_opt =
            tokio::task::spawn_blocking(move || -> Result<Option<String>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                conn.query_row(
                    "SELECT classifications \
                     FROM trace_events \
                     WHERE trace_id = ?1 AND thought_id = ?2 \
                       AND classifications IS NOT NULL \
                     LIMIT 1",
                    rusqlite::params![trace_id, thought_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
            .map_err(|e| Error::Backend(format!("read_classifications: {e}")))?;
        match row_opt {
            None => Ok(Vec::new()),
            Some(text) => {
                let parsed: Vec<Vec<crate::pipeline::classify::ContentClassMatch>> =
                    serde_json::from_str(&text)
                        .map_err(|e| Error::Backend(format!("classifications TEXT decode: {e}")))?;
                Ok(parsed)
            }
        }
    }

    /// v1.5.8 (CIRISPersist#57) — write the V023 `extracted_features`
    /// column for a `(trace_id, thought_id)` pair. Public write path
    /// for the agent's AdaptiveFilter output → persist round-trip.
    ///
    /// Caller contract: "set this if the row exists." If no
    /// `trace_events` row matches `(trace_id, thought_id)`, the UPDATE
    /// affects 0 rows and we return `Ok(())` (matches the canonical
    /// pipeline classify-stage UPDATE semantics on PG — the row must
    /// already be in the table; this method does not insert).
    #[cfg(feature = "extract")]
    pub async fn write_features(
        &self,
        trace_id: &str,
        thought_id: &str,
        features: &crate::pipeline::extract::Features,
    ) -> Result<(), Error> {
        let features_json = serde_json::to_string(features)
            .map_err(|e| Error::Backend(format!("write_features encode: {e}")))?;
        let trace_id = trace_id.to_owned();
        let thought_id = thought_id.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE trace_events \
                 SET extracted_features = ?1 \
                 WHERE trace_id = ?2 AND thought_id = ?3",
                rusqlite::params![features_json, trace_id, thought_id],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| Error::Backend(format!("write_features: {e}")))?;
        Ok(())
    }

    /// v1.5.8 (CIRISPersist#57) — write the V023 `classifications`
    /// column for a `(trace_id, thought_id)` pair. Public write path
    /// for the agent's AdaptiveFilter output → persist round-trip.
    ///
    /// Caller contract: "set this if the row exists." If no
    /// `trace_events` row matches `(trace_id, thought_id)`, the UPDATE
    /// affects 0 rows and we return `Ok(())` (matches the canonical
    /// pipeline classify-stage UPDATE semantics on PG — the row must
    /// already be in the table; this method does not insert).
    #[cfg(feature = "classify")]
    pub async fn write_classifications(
        &self,
        trace_id: &str,
        thought_id: &str,
        classifications: &Vec<Vec<crate::pipeline::classify::ContentClassMatch>>,
    ) -> Result<(), Error> {
        let cls_json = serde_json::to_string(classifications)
            .map_err(|e| Error::Backend(format!("write_classifications encode: {e}")))?;
        let trace_id = trace_id.to_owned();
        let thought_id = thought_id.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE trace_events \
                 SET classifications = ?1 \
                 WHERE trace_id = ?2 AND thought_id = ?3",
                rusqlite::params![cls_json, trace_id, thought_id],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| Error::Backend(format!("write_classifications: {e}")))?;
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

// ─── FederationDirectory impl (v0.2.0) ─────────────────────────────
//
// SQLite-backed federation directory. Same logical surface as the
// memory + postgres backends; differences are sqlite-isms:
//   - Timestamps are TEXT (RFC 3339) — chrono's ToSql/FromSql via the
//     rusqlite chrono feature handles this transparently.
//   - JSONB → TEXT — we serialize the Value before INSERT and parse
//     on read.
//   - BLOB columns for original_content_hash + scrub_signature take
//     raw bytes; the wire shape uses hex/base64 strings, decoded at
//     the persist boundary.
//   - UUID columns are TEXT — rusqlite passes UUID strings as TEXT.

impl crate::federation::FederationDirectory for SqliteBackend {
    async fn put_public_key(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<(), crate::federation::Error> {
        let mut row = record.record;
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;

        let original_content_hash = hex::decode(&row.original_content_hash).map_err(|e| {
            crate::federation::Error::InvalidArgument(format!(
                "original_content_hash hex decode: {e}"
            ))
        })?;
        if row.algorithm != crate::federation::types::algorithm::HYBRID {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "algorithm must be 'hybrid' (got '{}')",
                row.algorithm
            )));
        }

        let registration_envelope_text = serde_json::to_string(&row.registration_envelope)
            .map_err(|e| crate::federation::Error::Backend(format!("envelope serialize: {e}")))?;

        let conn = self.conn.clone();
        let key_id = row.key_id.clone();
        let row_hash = row.persist_row_hash.clone();
        let conflict_check =
            tokio::task::spawn_blocking(move || -> Result<Option<String>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                conn.query_row(
                    "SELECT persist_row_hash FROM federation_keys WHERE key_id = ?1",
                    [&key_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
            .map_err(|e| crate::federation::Error::Backend(format!("conflict check: {e}")))?;

        if let Some(existing_hash) = conflict_check {
            if existing_hash == row_hash {
                return Ok(()); // exact duplicate — idempotent no-op
            }
            return Err(crate::federation::Error::Conflict(format!(
                "key_id {} already exists with different content",
                row.key_id
            )));
        }

        // v1.3.0 (CIRISPersist#46): serialize the roles list to a
        // JSON-array TEXT for the column. Empty Vec → NULL so the
        // column matches the pre-V020 "no roles declared" semantics.
        let roles_text: Option<String> =
            if row.roles.is_empty() {
                None
            } else {
                Some(serde_json::to_string(&row.roles).map_err(|e| {
                    crate::federation::Error::Backend(format!("roles serialize: {e}"))
                })?)
            };
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO federation_keys (\
                    key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                    identity_type, identity_ref, valid_from, valid_until, registration_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
                rusqlite::params![
                    row.key_id,
                    row.pubkey_ed25519_base64,
                    row.pubkey_ml_dsa_65_base64,
                    row.algorithm,
                    row.identity_type,
                    row.identity_ref,
                    row.valid_from.to_rfc3339(),
                    row.valid_until.map(|t| t.to_rfc3339()),
                    registration_envelope_text,
                    original_content_hash,
                    row.scrub_signature_classical,
                    row.scrub_signature_pqc,
                    row.scrub_key_id,
                    row.scrub_timestamp.to_rfc3339(),
                    row.pqc_completed_at.map(|t| t.to_rfc3339()),
                    row.persist_row_hash,
                    roles_text,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("insert federation_keys: {e}")))?;
        Ok(())
    }

    async fn lookup_public_key(
        &self,
        key_id: &str,
    ) -> Result<Option<crate::federation::KeyRecord>, crate::federation::Error> {
        let conn = self.conn.clone();
        let key_id = key_id.to_owned();
        tokio::task::spawn_blocking(
            move || -> Result<Option<crate::federation::KeyRecord>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                conn.query_row(
                    "SELECT key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                        identity_type, identity_ref, valid_from, valid_until, registration_envelope, \
                        original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles \
                     FROM federation_keys WHERE key_id = ?1",
                    [&key_id],
                    sqlite_row_to_key_record,
                )
                .optional()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("lookup federation_keys: {e}")))
    }

    async fn lookup_keys_for_identity(
        &self,
        identity_ref: &str,
    ) -> Result<Vec<crate::federation::KeyRecord>, crate::federation::Error> {
        let conn = self.conn.clone();
        let identity_ref = identity_ref.to_owned();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::federation::KeyRecord>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(
                    "SELECT key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                        identity_type, identity_ref, valid_from, valid_until, registration_envelope, \
                        original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles \
                     FROM federation_keys WHERE identity_ref = ?1",
                )?;
                let rows = stmt.query_map([&identity_ref], sqlite_row_to_key_record)?;
                rows.collect()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("lookup_keys_for_identity: {e}")))
    }

    async fn put_attestation(
        &self,
        attestation: crate::federation::SignedAttestation,
    ) -> Result<(), crate::federation::Error> {
        let mut row = attestation.attestation;
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;

        let original_content_hash = hex::decode(&row.original_content_hash).map_err(|e| {
            crate::federation::Error::InvalidArgument(format!(
                "original_content_hash hex decode: {e}"
            ))
        })?;
        let attestation_envelope_text = serde_json::to_string(&row.attestation_envelope)
            .map_err(|e| crate::federation::Error::Backend(format!("envelope serialize: {e}")))?;

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO federation_attestations (\
                    attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                    weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                rusqlite::params![
                    row.attestation_id,
                    row.attesting_key_id,
                    row.attested_key_id,
                    row.attestation_type,
                    row.weight,
                    row.asserted_at.to_rfc3339(),
                    row.expires_at.map(|t| t.to_rfc3339()),
                    attestation_envelope_text,
                    original_content_hash,
                    row.scrub_signature_classical,
                    row.scrub_signature_pqc,
                    row.scrub_key_id,
                    row.scrub_timestamp.to_rfc3339(),
                    row.pqc_completed_at.map(|t| t.to_rfc3339()),
                    row.persist_row_hash,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("FOREIGN KEY") {
                crate::federation::Error::InvalidArgument(format!(
                    "FK constraint violated on attestation insert: {msg}"
                ))
            } else {
                crate::federation::Error::Backend(format!("insert attestation: {msg}"))
            }
        })?;
        Ok(())
    }

    async fn list_attestations_for(
        &self,
        attested_key_id: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let conn = self.conn.clone();
        let key = attested_key_id.to_owned();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::federation::Attestation>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(
                    "SELECT attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                        weight, asserted_at, expires_at, attestation_envelope, \
                        original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
                     FROM federation_attestations \
                     WHERE attested_key_id = ?1 \
                     ORDER BY asserted_at DESC",
                )?;
                let rows = stmt.query_map([&key], sqlite_row_to_attestation)?;
                rows.collect()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("list_attestations_for: {e}")))
    }

    async fn list_attestations_by(
        &self,
        attesting_key_id: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let conn = self.conn.clone();
        let key = attesting_key_id.to_owned();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::federation::Attestation>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(
                    "SELECT attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                        weight, asserted_at, expires_at, attestation_envelope, \
                        original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
                     FROM federation_attestations \
                     WHERE attesting_key_id = ?1 \
                     ORDER BY asserted_at DESC",
                )?;
                let rows = stmt.query_map([&key], sqlite_row_to_attestation)?;
                rows.collect()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("list_attestations_by: {e}")))
    }

    async fn put_revocation(
        &self,
        revocation: crate::federation::SignedRevocation,
    ) -> Result<(), crate::federation::Error> {
        let mut row = revocation.revocation;
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;

        let original_content_hash = hex::decode(&row.original_content_hash).map_err(|e| {
            crate::federation::Error::InvalidArgument(format!(
                "original_content_hash hex decode: {e}"
            ))
        })?;
        let revocation_envelope_text = serde_json::to_string(&row.revocation_envelope)
            .map_err(|e| crate::federation::Error::Backend(format!("envelope serialize: {e}")))?;

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO federation_revocations (\
                    revocation_id, revoked_key_id, revoking_key_id, reason, \
                    revoked_at, effective_at, revocation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
                rusqlite::params![
                    row.revocation_id,
                    row.revoked_key_id,
                    row.revoking_key_id,
                    row.reason,
                    row.revoked_at.to_rfc3339(),
                    row.effective_at.to_rfc3339(),
                    revocation_envelope_text,
                    original_content_hash,
                    row.scrub_signature_classical,
                    row.scrub_signature_pqc,
                    row.scrub_key_id,
                    row.scrub_timestamp.to_rfc3339(),
                    row.pqc_completed_at.map(|t| t.to_rfc3339()),
                    row.persist_row_hash,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("FOREIGN KEY") {
                crate::federation::Error::InvalidArgument(format!(
                    "FK constraint violated on revocation insert: {msg}"
                ))
            } else {
                crate::federation::Error::Backend(format!("insert revocation: {msg}"))
            }
        })?;
        Ok(())
    }

    async fn revocations_for(
        &self,
        revoked_key_id: &str,
    ) -> Result<Vec<crate::federation::Revocation>, crate::federation::Error> {
        let conn = self.conn.clone();
        let key = revoked_key_id.to_owned();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::federation::Revocation>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(
                    "SELECT revocation_id, revoked_key_id, revoking_key_id, reason, \
                        revoked_at, effective_at, revocation_envelope, \
                        original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
                     FROM federation_revocations \
                     WHERE revoked_key_id = ?1 \
                     ORDER BY effective_at DESC",
                )?;
                let rows = stmt.query_map([&key], sqlite_row_to_revocation)?;
                rows.collect()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("revocations_for: {e}")))
    }

    async fn attach_key_pqc_signature(
        &self,
        key_id: &str,
        pubkey_ml_dsa_65_base64: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), crate::federation::Error> {
        let mut row =
            <Self as crate::federation::FederationDirectory>::lookup_public_key(self, key_id)
                .await?
                .ok_or_else(|| {
                    crate::federation::Error::InvalidArgument(format!(
                        "federation_keys row {key_id} does not exist"
                    ))
                })?;
        if row.is_pqc_complete() {
            return Err(crate::federation::Error::Conflict(format!(
                "federation_keys row {key_id} is already PQC-complete"
            )));
        }
        row.pubkey_ml_dsa_65_base64 = Some(pubkey_ml_dsa_65_base64.to_owned());
        row.scrub_signature_pqc = Some(scrub_signature_pqc.to_owned());
        let now = chrono::Utc::now();
        row.pqc_completed_at = Some(now);
        let mut for_hash = row.clone();
        for_hash.persist_row_hash = String::new();
        let new_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;

        let conn = self.conn.clone();
        let key_id = key_id.to_owned();
        let mldsa = pubkey_ml_dsa_65_base64.to_owned();
        let pqc_sig = scrub_signature_pqc.to_owned();
        let now_str = now.to_rfc3339();
        let n = tokio::task::spawn_blocking(move || -> Result<usize, rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE federation_keys \
                 SET pubkey_ml_dsa_65_base64 = ?1, scrub_signature_pqc = ?2, \
                     pqc_completed_at = ?3, persist_row_hash = ?4 \
                 WHERE key_id = ?5 AND pqc_completed_at IS NULL",
                rusqlite::params![mldsa, pqc_sig, now_str, new_hash, key_id],
            )
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("attach_key_pqc_signature: {e}")))?;
        if n == 0 {
            return Err(crate::federation::Error::Conflict(
                "federation_keys row was concurrently completed".to_string(),
            ));
        }
        Ok(())
    }

    async fn attach_attestation_pqc_signature(
        &self,
        attestation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), crate::federation::Error> {
        // Read existing row to recompute hash + check pending state.
        let conn_for_read = self.conn.clone();
        let id = attestation_id.to_owned();
        let row_opt = tokio::task::spawn_blocking(
            move || -> Result<Option<crate::federation::Attestation>, rusqlite::Error> {
                let conn = conn_for_read.blocking_lock();
                conn.query_row(
                    "SELECT attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                        weight, asserted_at, expires_at, attestation_envelope, \
                        original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
                     FROM federation_attestations WHERE attestation_id = ?1",
                    [&id],
                    sqlite_row_to_attestation,
                )
                .optional()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("attach lookup: {e}")))?;
        let mut row = row_opt.ok_or_else(|| {
            crate::federation::Error::InvalidArgument(format!(
                "federation_attestations row {attestation_id} does not exist"
            ))
        })?;
        if row.is_pqc_complete() {
            return Err(crate::federation::Error::Conflict(format!(
                "federation_attestations row {attestation_id} is already PQC-complete"
            )));
        }
        row.scrub_signature_pqc = Some(scrub_signature_pqc.to_owned());
        let now = chrono::Utc::now();
        row.pqc_completed_at = Some(now);
        let mut for_hash = row.clone();
        for_hash.persist_row_hash = String::new();
        let new_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;

        let conn = self.conn.clone();
        let attestation_id = attestation_id.to_owned();
        let pqc_sig = scrub_signature_pqc.to_owned();
        let now_str = now.to_rfc3339();
        let n = tokio::task::spawn_blocking(move || -> Result<usize, rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE federation_attestations \
                 SET scrub_signature_pqc = ?1, pqc_completed_at = ?2, persist_row_hash = ?3 \
                 WHERE attestation_id = ?4 AND pqc_completed_at IS NULL",
                rusqlite::params![pqc_sig, now_str, new_hash, attestation_id],
            )
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            crate::federation::Error::Backend(format!("attach_attestation_pqc_signature: {e}"))
        })?;
        if n == 0 {
            return Err(crate::federation::Error::Conflict(
                "federation_attestations row was concurrently completed".to_string(),
            ));
        }
        Ok(())
    }

    async fn attach_revocation_pqc_signature(
        &self,
        revocation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), crate::federation::Error> {
        let conn_for_read = self.conn.clone();
        let id = revocation_id.to_owned();
        let row_opt = tokio::task::spawn_blocking(
            move || -> Result<Option<crate::federation::Revocation>, rusqlite::Error> {
                let conn = conn_for_read.blocking_lock();
                conn.query_row(
                    "SELECT revocation_id, revoked_key_id, revoking_key_id, reason, \
                        revoked_at, effective_at, revocation_envelope, \
                        original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
                     FROM federation_revocations WHERE revocation_id = ?1",
                    [&id],
                    sqlite_row_to_revocation,
                )
                .optional()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("attach lookup: {e}")))?;
        let mut row = row_opt.ok_or_else(|| {
            crate::federation::Error::InvalidArgument(format!(
                "federation_revocations row {revocation_id} does not exist"
            ))
        })?;
        if row.is_pqc_complete() {
            return Err(crate::federation::Error::Conflict(format!(
                "federation_revocations row {revocation_id} is already PQC-complete"
            )));
        }
        row.scrub_signature_pqc = Some(scrub_signature_pqc.to_owned());
        let now = chrono::Utc::now();
        row.pqc_completed_at = Some(now);
        let mut for_hash = row.clone();
        for_hash.persist_row_hash = String::new();
        let new_hash = crate::federation::types::compute_persist_row_hash(&for_hash)?;

        let conn = self.conn.clone();
        let revocation_id = revocation_id.to_owned();
        let pqc_sig = scrub_signature_pqc.to_owned();
        let now_str = now.to_rfc3339();
        let n = tokio::task::spawn_blocking(move || -> Result<usize, rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE federation_revocations \
                 SET scrub_signature_pqc = ?1, pqc_completed_at = ?2, persist_row_hash = ?3 \
                 WHERE revocation_id = ?4 AND pqc_completed_at IS NULL",
                rusqlite::params![pqc_sig, now_str, new_hash, revocation_id],
            )
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            crate::federation::Error::Backend(format!("attach_revocation_pqc_signature: {e}"))
        })?;
        if n == 0 {
            return Err(crate::federation::Error::Conflict(
                "federation_revocations row was concurrently completed".to_string(),
            ));
        }
        Ok(())
    }

    async fn list_hybrid_pending_keys(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::federation::HybridPendingRow>, crate::federation::Error> {
        let conn = self.conn.clone();
        let rows = tokio::task::spawn_blocking(
            move || -> Result<Vec<(String, String, String)>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(
                    "SELECT key_id, registration_envelope, scrub_signature_classical \
                     FROM federation_keys \
                     WHERE pqc_completed_at IS NULL \
                     ORDER BY valid_from ASC \
                     LIMIT ?1",
                )?;
                let iter = stmt.query_map([limit], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?;
                iter.collect()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("list_hybrid_pending_keys: {e}")))?;
        rows.into_iter()
            .map(|(id, envelope_text, classical_sig_b64)| {
                let envelope: serde_json::Value =
                    serde_json::from_str(&envelope_text).map_err(|e| {
                        crate::federation::Error::Backend(format!(
                            "registration_envelope decode: {e}"
                        ))
                    })?;
                Ok(crate::federation::HybridPendingRow {
                    id,
                    envelope,
                    classical_sig_b64,
                })
            })
            .collect()
    }

    async fn list_hybrid_pending_attestations(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::federation::HybridPendingRow>, crate::federation::Error> {
        let conn = self.conn.clone();
        let rows = tokio::task::spawn_blocking(
            move || -> Result<Vec<(String, String, String)>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(
                    "SELECT attestation_id, attestation_envelope, scrub_signature_classical \
                     FROM federation_attestations \
                     WHERE pqc_completed_at IS NULL \
                     ORDER BY asserted_at ASC \
                     LIMIT ?1",
                )?;
                let iter = stmt.query_map([limit], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?;
                iter.collect()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            crate::federation::Error::Backend(format!("list_hybrid_pending_attestations: {e}"))
        })?;
        rows.into_iter()
            .map(|(id, envelope_text, classical_sig_b64)| {
                let envelope: serde_json::Value =
                    serde_json::from_str(&envelope_text).map_err(|e| {
                        crate::federation::Error::Backend(format!(
                            "attestation_envelope decode: {e}"
                        ))
                    })?;
                Ok(crate::federation::HybridPendingRow {
                    id,
                    envelope,
                    classical_sig_b64,
                })
            })
            .collect()
    }

    async fn list_hybrid_pending_revocations(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::federation::HybridPendingRow>, crate::federation::Error> {
        let conn = self.conn.clone();
        let rows = tokio::task::spawn_blocking(
            move || -> Result<Vec<(String, String, String)>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(
                    "SELECT revocation_id, revocation_envelope, scrub_signature_classical \
                     FROM federation_revocations \
                     WHERE pqc_completed_at IS NULL \
                     ORDER BY revoked_at ASC \
                     LIMIT ?1",
                )?;
                let iter = stmt.query_map([limit], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?;
                iter.collect()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            crate::federation::Error::Backend(format!("list_hybrid_pending_revocations: {e}"))
        })?;
        rows.into_iter()
            .map(|(id, envelope_text, classical_sig_b64)| {
                let envelope: serde_json::Value =
                    serde_json::from_str(&envelope_text).map_err(|e| {
                        crate::federation::Error::Backend(format!(
                            "revocation_envelope decode: {e}"
                        ))
                    })?;
                Ok(crate::federation::HybridPendingRow {
                    id,
                    envelope,
                    classical_sig_b64,
                })
            })
            .collect()
    }

    // ── Trust grants (v1.3.0, CIRISPersist#46 + #47) ───────────────

    async fn grant_trust(
        &self,
        grant: crate::federation::TrustGrant,
    ) -> Result<(), crate::federation::Error> {
        crate::store::memory::validate_trust_grant(&grant)?;
        // Serialize the trust_domains list to a JSON-array string for
        // the TEXT column (SQLite has no array type).
        let trust_domains_text: Option<String> = match &grant.trust_domains {
            Some(d) => Some(serde_json::to_string(d).map_err(|e| {
                crate::federation::Error::Backend(format!("trust_domains serialize: {e}"))
            })?),
            None => None,
        };
        let trust_type_str = grant.trust_type.as_str().to_owned();
        let trust_relationship_str = grant.trust_relationship.as_str().to_owned();
        let key = grant.key.clone();
        let trusted_by = grant.trusted_by.clone();
        let expires_at_text = grant.expires_at.map(|t| t.to_rfc3339());
        let now_text = chrono::Utc::now().to_rfc3339();

        let conn = self.conn.clone();
        let n = tokio::task::spawn_blocking(move || -> Result<usize, rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE federation_keys \
                 SET trust_type = ?2, \
                     trust_relationship = ?3, \
                     trust_domains = ?4, \
                     trusted_by = ?5, \
                     trusted_at = ?6, \
                     expires_at = ?7 \
                 WHERE key_id = ?1",
                rusqlite::params![
                    key,
                    trust_type_str,
                    trust_relationship_str,
                    trust_domains_text,
                    trusted_by,
                    now_text,
                    expires_at_text,
                ],
            )
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("grant_trust UPDATE: {e}")))?;
        if n == 0 {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "federation_keys row {} does not exist — call put_public_key first",
                grant.key
            )));
        }
        Ok(())
    }

    async fn revoke_trust(
        &self,
        key: &str,
        revoked_by: &str,
    ) -> Result<(), crate::federation::Error> {
        if key.is_empty() {
            return Err(crate::federation::Error::InvalidArgument(
                "key must be non-empty".into(),
            ));
        }
        if revoked_by.is_empty() {
            return Err(crate::federation::Error::InvalidArgument(
                "revoked_by must be non-empty".into(),
            ));
        }
        // RFC 3339 comparisons via julianday() so the SQLite-native
        // CURRENT_TIMESTAMP shape ("YYYY-MM-DD HH:MM:SS") and the
        // chrono RFC-3339 ("YYYY-MM-DDTHH:MM:SS.fff+00:00") shape
        // both compare correctly.
        let key_owned = key.to_owned();
        let now_text = chrono::Utc::now().to_rfc3339();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<usize, rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE federation_keys \
                 SET expires_at = ?2 \
                 WHERE key_id = ?1 \
                   AND trusted_by IS NOT NULL \
                   AND (expires_at IS NULL OR julianday(expires_at) > julianday(?2))",
                rusqlite::params![key_owned, now_text],
            )
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("revoke_trust: {e}")))?;
        let _ = revoked_by;
        Ok(())
    }

    async fn lookup_trust(
        &self,
        key: &str,
    ) -> Result<Option<crate::federation::TrustRow>, crate::federation::Error> {
        let key_owned = key.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Option<crate::federation::TrustRow>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                conn.query_row(
                    "SELECT key_id, trust_type, trust_relationship, trust_domains, \
                            trusted_by, trusted_at, expires_at \
                     FROM federation_keys \
                     WHERE key_id = ?1 AND trusted_by IS NOT NULL",
                    [&key_owned],
                    sqlite_row_to_trust_row,
                )
                .optional()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("lookup_trust: {e}")))
    }

    async fn list_trusted_keys(
        &self,
        filter: crate::federation::TrustFilter,
    ) -> Result<Vec<crate::federation::TrustRow>, crate::federation::Error> {
        // Build the parametric WHERE clause. We materialize all rows
        // and apply the domain filter in-memory because SQLite has
        // no native ARRAY/JSON-membership operator on the bound side;
        // `json_each` works but composes awkwardly with the rest of
        // the filter. For the row counts persist sees on the SQLite
        // arm (sovereign-mode agents, single-tenant) this is fine.
        let now_text = chrono::Utc::now().to_rfc3339();
        let mut where_parts: Vec<String> = vec!["trusted_by IS NOT NULL".to_owned()];
        let mut params: Vec<String> = Vec::new();
        if !filter.include_expired {
            params.push(now_text);
            where_parts.push(format!(
                "(expires_at IS NULL OR julianday(expires_at) > julianday(?{}))",
                params.len()
            ));
        }
        if let Some(t) = filter.trust_type {
            params.push(t.as_str().to_owned());
            where_parts.push(format!("trust_type = ?{}", params.len()));
        }
        if let Some(rel) = filter.trust_relationship {
            params.push(rel.as_str().to_owned());
            where_parts.push(format!("trust_relationship = ?{}", params.len()));
        }
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT key_id, trust_type, trust_relationship, trust_domains, \
                    trusted_by, trusted_at, expires_at \
             FROM federation_keys \
             WHERE {where_sql} \
             ORDER BY trusted_at DESC, key_id DESC"
        );
        let domain_filter = filter.domain;
        let conn = self.conn.clone();
        let rows = tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::federation::TrustRow>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(&sql)?;
                let params_dyn: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
                let rows = stmt
                    .query_map(params_dyn.as_slice(), sqlite_row_to_trust_row)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("list_trusted_keys: {e}")))?;
        let filtered: Vec<crate::federation::TrustRow> = match domain_filter {
            Some(domain) => rows
                .into_iter()
                .filter(|r| {
                    r.trust_domains
                        .as_ref()
                        .map(|d| d.iter().any(|x| x == &domain))
                        .unwrap_or(false)
                })
                .collect(),
            None => rows,
        };
        Ok(filtered)
    }
}

/// Convert a SQLite row from the trust columns of `federation_keys`
/// into a [`crate::federation::TrustRow`]. SELECT clause MUST include
/// exactly the 7 trust columns (read by name).
fn sqlite_row_to_trust_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::federation::TrustRow> {
    let trust_type_str: String = row.get("trust_type")?;
    let trust_relationship_str: String = row.get("trust_relationship")?;
    let trust_type =
        crate::federation::TrustType::from_wire_str(&trust_type_str).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown trust_type: {trust_type_str}"),
                )),
            )
        })?;
    let trust_relationship = crate::federation::TrustRelationship::from_wire_str(
        &trust_relationship_str,
    )
    .ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            2,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown trust_relationship: {trust_relationship_str}"),
            )),
        )
    })?;
    let trust_domains_text: Option<String> = row.get("trust_domains")?;
    let trust_domains: Option<Vec<String>> = match trust_domains_text.as_deref() {
        Some("") | None => None,
        Some(s) => Some(serde_json::from_str(s).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            )
        })?),
    };
    let trusted_by: String = row.get("trusted_by")?;
    let trusted_at_text: String = row.get("trusted_at")?;
    let expires_at_text: Option<String> = row.get("expires_at")?;
    Ok(crate::federation::TrustRow {
        key: row.get("key_id")?,
        trust_type,
        trust_relationship,
        trust_domains,
        trusted_by,
        trusted_at: parse_rfc3339(&trusted_at_text),
        expires_at: expires_at_text.as_deref().map(parse_rfc3339),
    })
}

// ─── OutboundQueue impl (v0.4.0, CIRISPersist#16) ──────────────────
//
// SQLite-backed durable substrate. Same logical surface as the
// postgres impl; differences are sqlite-isms:
//
//   - No UUID type; queue_id is TEXT.
//   - No FOR UPDATE SKIP LOCKED; WAL mode + writer-serialization
//     on file lock means single-writer dispatch is correct without
//     row-level locks. Multi-instance dispatch on sqlite is rare
//     (sovereign-mode is typically single-process).
//   - No interval arithmetic in SQL; per-row TTL/timeout checks
//     happen in Rust after row read.
//   - All ops wrapped in spawn_blocking + Mutex like other sqlite
//     impls in this file.

impl crate::outbound::OutboundQueue for SqliteBackend {
    async fn enqueue_outbound(
        &self,
        sender_key_id: &str,
        destination_key_id: &str,
        message_type: &str,
        edge_schema_version: &str,
        envelope_bytes: &[u8],
        body_sha256: &[u8; 32],
        body_size_bytes: i32,
        requires_ack: bool,
        ack_timeout_seconds: Option<i64>,
        max_attempts: i32,
        ttl_seconds: i64,
        initial_next_attempt_after: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::outbound::QueueId, crate::outbound::Error> {
        if max_attempts <= 0 || ttl_seconds <= 0 {
            return Err(crate::outbound::Error::InvalidArgument(
                "max_attempts + ttl_seconds must be > 0".into(),
            ));
        }
        if !(1..=8 * 1024 * 1024).contains(&body_size_bytes) {
            return Err(crate::outbound::Error::InvalidArgument(format!(
                "body_size_bytes out of range: {body_size_bytes}"
            )));
        }
        if requires_ack && ack_timeout_seconds.unwrap_or(0) <= 0 {
            return Err(crate::outbound::Error::InvalidArgument(
                "ack_timeout_seconds required when requires_ack=true".into(),
            ));
        }
        let queue_id = format!(
            "{:x}-{:x}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
            std::process::id()
        );
        let conn = self.conn.clone();
        let qid = queue_id.clone();
        let sender = sender_key_id.to_owned();
        let dest = destination_key_id.to_owned();
        let mt = message_type.to_owned();
        let esv = edge_schema_version.to_owned();
        let env_bytes = envelope_bytes.to_vec();
        let hash_vec = body_sha256.to_vec();
        let now = chrono::Utc::now();
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO edge_outbound_queue (\
                    queue_id, sender_key_id, destination_key_id, message_type, \
                    edge_schema_version, envelope_bytes, body_sha256, \
                    body_size_bytes, status, enqueued_at, next_attempt_after, \
                    max_attempts, ttl_seconds, requires_ack, ack_timeout_seconds\
                 ) VALUES (\
                    ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'pending', ?9, ?10, ?11, ?12, ?13, ?14\
                 )",
                rusqlite::params![
                    qid,
                    sender,
                    dest,
                    mt,
                    esv,
                    env_bytes,
                    hash_vec,
                    body_size_bytes,
                    now.to_rfc3339(),
                    initial_next_attempt_after.to_rfc3339(),
                    max_attempts,
                    ttl_seconds,
                    if requires_ack { 1i64 } else { 0i64 },
                    ack_timeout_seconds,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("enqueue_outbound: {e}")))?;
        Ok(queue_id)
    }

    async fn claim_pending_outbound(
        &self,
        batch_size: i64,
        claim_duration_seconds: i64,
        claimed_by: &str,
    ) -> Result<Vec<crate::outbound::OutboundRow>, crate::outbound::Error> {
        let conn = self.conn.clone();
        let now = chrono::Utc::now();
        let claim_until = now + chrono::Duration::seconds(claim_duration_seconds);
        let claimed_by = claimed_by.to_owned();
        let rows = tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::outbound::OutboundRow>, rusqlite::Error> {
                let mut conn = conn.blocking_lock();
                let tx = conn.transaction()?;
                let queue_ids: Vec<String> = {
                    let mut stmt = tx.prepare(
                        "SELECT queue_id FROM edge_outbound_queue \
                     WHERE status = 'pending' AND next_attempt_after <= ?1 \
                     ORDER BY next_attempt_after ASC LIMIT ?2",
                    )?;
                    let rows = stmt
                        .query_map(rusqlite::params![now.to_rfc3339(), batch_size], |r| {
                            r.get::<_, String>(0)
                        })?;
                    rows.collect::<Result<Vec<_>, _>>()?
                };
                let now_str = now.to_rfc3339();
                let claim_until_str = claim_until.to_rfc3339();
                for qid in &queue_ids {
                    tx.execute(
                        "UPDATE edge_outbound_queue \
                     SET status = 'sending', last_attempt_at = ?1, \
                         attempt_count = attempt_count + 1, \
                         claimed_until = ?2, claimed_by = ?3 \
                     WHERE queue_id = ?4",
                        rusqlite::params![now_str, claim_until_str, claimed_by, qid],
                    )?;
                }
                let claimed: Vec<crate::outbound::OutboundRow> = {
                    let mut out = Vec::with_capacity(queue_ids.len());
                    let mut stmt = tx.prepare(SQLITE_OUTBOUND_SELECT_BY_ID)?;
                    for qid in &queue_ids {
                        let row = stmt.query_row([qid], sqlite_row_to_outbound_row)?;
                        out.push(row);
                    }
                    out
                };
                tx.commit()?;
                Ok(claimed)
            },
        )
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("claim_pending_outbound: {e}")))?;
        Ok(rows)
    }

    async fn mark_transport_delivered(
        &self,
        queue_id: &crate::outbound::QueueId,
        transport: &str,
    ) -> Result<(), crate::outbound::Error> {
        let conn = self.conn.clone();
        let qid = queue_id.clone();
        let transport = transport.to_owned();
        let now_str = chrono::Utc::now().to_rfc3339();
        let n = tokio::task::spawn_blocking(move || -> rusqlite::Result<usize> {
            let conn = conn.blocking_lock();
            // CASE branch on requires_ack: !requires_ack → delivered;
            // requires_ack → awaiting_ack.
            conn.execute(
                "UPDATE edge_outbound_queue \
                 SET status = CASE WHEN requires_ack THEN 'awaiting_ack' ELSE 'delivered' END, \
                     transport_delivered_at = ?1, \
                     delivered_at = CASE WHEN requires_ack THEN NULL ELSE ?1 END, \
                     last_transport = ?2, claimed_until = NULL, claimed_by = NULL \
                 WHERE queue_id = ?3 AND status = 'sending'",
                rusqlite::params![now_str, transport, qid],
            )
        })
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("mark_transport_delivered: {e}")))?;
        if n == 0 {
            return Err(crate::outbound::Error::InvalidTransition(format!(
                "queue_id {queue_id} not in 'sending'"
            )));
        }
        Ok(())
    }

    async fn mark_transport_failed(
        &self,
        queue_id: &crate::outbound::QueueId,
        error_class: &str,
        error_detail: &str,
        transport: &str,
        next_attempt_after: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::outbound::OutboundFailureOutcome, crate::outbound::Error> {
        let conn = self.conn.clone();
        let qid = queue_id.clone();
        let error_class = error_class.to_owned();
        let error_detail = error_detail.to_owned();
        let transport = transport.to_owned();
        let now = chrono::Utc::now();
        let next_str = next_attempt_after.to_rfc3339();
        let outcome = tokio::task::spawn_blocking(
            move || -> Result<crate::outbound::OutboundFailureOutcome, rusqlite::Error> {
                let mut conn = conn.blocking_lock();
                let tx = conn.transaction()?;
                let (attempt_count, max_attempts, enqueued_at_str, ttl_seconds): (
                    i32,
                    i32,
                    String,
                    i64,
                ) = tx
                    .query_row(
                        "SELECT attempt_count, max_attempts, enqueued_at, ttl_seconds \
                     FROM edge_outbound_queue \
                     WHERE queue_id = ?1 AND status = 'sending'",
                        [&qid],
                        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                    )
                    .map_err(|e| {
                        if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                            // surface a sentinel error so the caller can map to InvalidTransition
                            rusqlite::Error::QueryReturnedNoRows
                        } else {
                            e
                        }
                    })?;
                let enqueued_at = parse_rfc3339(&enqueued_at_str);
                let ttl_expired = (now - enqueued_at) > chrono::Duration::seconds(ttl_seconds);
                let attempts_exhausted = attempt_count >= max_attempts;
                let outcome = if ttl_expired || attempts_exhausted {
                    let reason = if ttl_expired {
                        "ttl_expired"
                    } else {
                        "max_attempts"
                    };
                    tx.execute(
                        "UPDATE edge_outbound_queue \
                     SET status = 'abandoned', abandoned_at = ?1, abandoned_reason = ?2, \
                         last_error_class = ?3, last_error_detail = ?4, last_transport = ?5, \
                         claimed_until = NULL, claimed_by = NULL \
                     WHERE queue_id = ?6",
                        rusqlite::params![
                            now.to_rfc3339(),
                            reason,
                            error_class,
                            error_detail,
                            transport,
                            qid
                        ],
                    )?;
                    crate::outbound::OutboundFailureOutcome::Abandoned
                } else {
                    tx.execute(
                        "UPDATE edge_outbound_queue \
                     SET status = 'pending', next_attempt_after = ?1, \
                         last_error_class = ?2, last_error_detail = ?3, last_transport = ?4, \
                         claimed_until = NULL, claimed_by = NULL \
                     WHERE queue_id = ?5",
                        rusqlite::params![next_str, error_class, error_detail, transport, qid],
                    )?;
                    crate::outbound::OutboundFailureOutcome::Retrying {
                        attempt: attempt_count,
                    }
                };
                tx.commit()?;
                Ok(outcome)
            },
        )
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => crate::outbound::Error::InvalidTransition(
                format!("queue_id {queue_id} not in 'sending'"),
            ),
            other => crate::outbound::Error::Backend(format!("mark_transport_failed: {other}")),
        })?;
        Ok(outcome)
    }

    async fn mark_replay_resolved(
        &self,
        queue_id: &crate::outbound::QueueId,
    ) -> Result<(), crate::outbound::Error> {
        let conn = self.conn.clone();
        let qid = queue_id.clone();
        let now_str = chrono::Utc::now().to_rfc3339();
        tokio::task::spawn_blocking(move || -> rusqlite::Result<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE edge_outbound_queue \
                 SET status = 'delivered', delivered_at = ?1, \
                     claimed_until = NULL, claimed_by = NULL \
                 WHERE queue_id = ?2 AND status NOT IN ('delivered', 'abandoned')",
                rusqlite::params![now_str, qid],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("mark_replay_resolved: {e}")))?;
        Ok(())
    }

    async fn match_ack_to_outbound(
        &self,
        in_reply_to_sha256: &[u8; 32],
    ) -> Result<Option<crate::outbound::OutboundRow>, crate::outbound::Error> {
        let conn = self.conn.clone();
        let hash_vec = in_reply_to_sha256.to_vec();
        tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<crate::outbound::OutboundRow>> {
            let conn = conn.blocking_lock();
            let sql = format!(
                "{SQLITE_OUTBOUND_SELECT_PREFIX} WHERE body_sha256 = ?1 AND status = 'awaiting_ack' LIMIT 1"
            );
            let mut stmt = conn.prepare(&sql)?;
            stmt.query_row([&hash_vec as &dyn rusqlite::ToSql], sqlite_row_to_outbound_row)
                .optional()
        })
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("match_ack_to_outbound: {e}")))
    }

    async fn mark_ack_received(
        &self,
        queue_id: &crate::outbound::QueueId,
        ack_envelope_bytes: &[u8],
    ) -> Result<(), crate::outbound::Error> {
        let conn = self.conn.clone();
        let qid = queue_id.clone();
        let ack_bytes = ack_envelope_bytes.to_vec();
        let now_str = chrono::Utc::now().to_rfc3339();
        let n = tokio::task::spawn_blocking(move || -> rusqlite::Result<usize> {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE edge_outbound_queue \
                 SET status = 'delivered', \
                     ack_envelope_bytes = ?1, ack_received_at = ?2, delivered_at = ?2 \
                 WHERE queue_id = ?3 AND status = 'awaiting_ack'",
                rusqlite::params![ack_bytes, now_str, qid],
            )
        })
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("mark_ack_received: {e}")))?;
        if n == 0 {
            return Err(crate::outbound::Error::InvalidTransition(format!(
                "queue_id {queue_id} not in 'awaiting_ack'"
            )));
        }
        Ok(())
    }

    async fn sweep_ack_timeouts(&self) -> Result<i64, crate::outbound::Error> {
        let conn = self.conn.clone();
        let now = chrono::Utc::now();
        tokio::task::spawn_blocking(move || -> rusqlite::Result<i64> {
            let mut conn = conn.blocking_lock();
            let tx = conn.transaction()?;
            // Walk awaiting_ack rows; per-row TTL/timeout checks in Rust
            // (sqlite has no interval arithmetic).
            // (queue_id, transport_delivered_at, ack_timeout_seconds,
            //  attempt_count, max_attempts, enqueued_at, ttl_seconds)
            type AckCandidate = (String, String, Option<i64>, i32, i32, String, i64);
            let candidates: Vec<AckCandidate> = {
                let mut stmt = tx.prepare(
                    "SELECT queue_id, transport_delivered_at, ack_timeout_seconds, \
                            attempt_count, max_attempts, enqueued_at, ttl_seconds \
                     FROM edge_outbound_queue WHERE status = 'awaiting_ack'",
                )?;
                let rows = stmt.query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                })?;
                rows.collect::<Result<Vec<_>, _>>()?
            };
            let mut count = 0i64;
            for (
                qid,
                transport_delivered_str,
                ack_timeout,
                attempt,
                max_attempts,
                enqueued_str,
                ttl,
            ) in candidates
            {
                let transport_delivered = parse_rfc3339(&transport_delivered_str);
                let Some(timeout) = ack_timeout else { continue };
                if (now - transport_delivered) <= chrono::Duration::seconds(timeout) {
                    continue;
                }
                let enqueued = parse_rfc3339(&enqueued_str);
                let ttl_expired = (now - enqueued) > chrono::Duration::seconds(ttl);
                let attempts_exhausted = attempt >= max_attempts;
                if ttl_expired || attempts_exhausted {
                    let reason = if ttl_expired {
                        "ttl_expired"
                    } else {
                        "max_attempts"
                    };
                    tx.execute(
                        "UPDATE edge_outbound_queue \
                         SET status = 'abandoned', abandoned_at = ?1, abandoned_reason = ?2, \
                             last_error_class = 'ack_timeout', \
                             last_error_detail = 'no ACK before ack_timeout_seconds expired' \
                         WHERE queue_id = ?3",
                        rusqlite::params![now.to_rfc3339(), reason, qid],
                    )?;
                } else {
                    let next = (now + chrono::Duration::seconds(60)).to_rfc3339();
                    tx.execute(
                        "UPDATE edge_outbound_queue \
                         SET status = 'pending', next_attempt_after = ?1, \
                             last_error_class = 'ack_timeout', \
                             last_error_detail = 'no ACK before ack_timeout_seconds expired' \
                         WHERE queue_id = ?2",
                        rusqlite::params![next, qid],
                    )?;
                }
                count += 1;
            }
            tx.commit()?;
            Ok(count)
        })
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("sweep_ack_timeouts: {e}")))
    }

    async fn sweep_ttl_expired(&self) -> Result<i64, crate::outbound::Error> {
        let conn = self.conn.clone();
        let now = chrono::Utc::now();
        tokio::task::spawn_blocking(move || -> rusqlite::Result<i64> {
            let mut conn = conn.blocking_lock();
            let tx = conn.transaction()?;
            // Pull non-terminal rows; check ttl in Rust.
            let candidates: Vec<(String, String, i64)> = {
                let mut stmt = tx.prepare(
                    "SELECT queue_id, enqueued_at, ttl_seconds \
                     FROM edge_outbound_queue \
                     WHERE status NOT IN ('delivered', 'abandoned')",
                )?;
                let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
                rows.collect::<Result<Vec<_>, _>>()?
            };
            let mut count = 0i64;
            for (qid, enqueued_str, ttl) in candidates {
                let enqueued = parse_rfc3339(&enqueued_str);
                if (now - enqueued) > chrono::Duration::seconds(ttl) {
                    tx.execute(
                        "UPDATE edge_outbound_queue \
                         SET status = 'abandoned', abandoned_at = ?1, \
                             abandoned_reason = 'ttl_expired', \
                             claimed_until = NULL, claimed_by = NULL \
                         WHERE queue_id = ?2",
                        rusqlite::params![now.to_rfc3339(), qid],
                    )?;
                    count += 1;
                }
            }
            tx.commit()?;
            Ok(count)
        })
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("sweep_ttl_expired: {e}")))
    }

    async fn sweep_expired_claims(&self) -> Result<i64, crate::outbound::Error> {
        let conn = self.conn.clone();
        let now_str = chrono::Utc::now().to_rfc3339();
        tokio::task::spawn_blocking(move || -> rusqlite::Result<i64> {
            let conn = conn.blocking_lock();
            let n = conn.execute(
                "UPDATE edge_outbound_queue \
                 SET status = 'pending', claimed_until = NULL, claimed_by = NULL \
                 WHERE status = 'sending' AND claimed_until < ?1",
                rusqlite::params![now_str],
            )?;
            Ok(n as i64)
        })
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("sweep_expired_claims: {e}")))
    }

    async fn outbound_status(
        &self,
        queue_id: &crate::outbound::QueueId,
    ) -> Result<Option<crate::outbound::OutboundRow>, crate::outbound::Error> {
        let conn = self.conn.clone();
        let qid = queue_id.clone();
        tokio::task::spawn_blocking(
            move || -> rusqlite::Result<Option<crate::outbound::OutboundRow>> {
                let conn = conn.blocking_lock();
                let sql = format!("{SQLITE_OUTBOUND_SELECT_PREFIX} WHERE queue_id = ?1");
                let mut stmt = conn.prepare(&sql)?;
                stmt.query_row([&qid], sqlite_row_to_outbound_row)
                    .optional()
            },
        )
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("outbound_status: {e}")))
    }

    async fn list_outbound(
        &self,
        filter: crate::outbound::OutboundFilter,
        limit: i64,
    ) -> Result<Vec<crate::outbound::OutboundRow>, crate::outbound::Error> {
        let conn = self.conn.clone();
        // Pre-compute filter conditions + bind values. SQLite has
        // params_from_iter for dynamic argument lists.
        let mut where_clauses: Vec<String> = vec!["1=1".into()];
        let mut binds: Vec<rusqlite::types::Value> = Vec::new();
        if let Some(s) = filter.status {
            where_clauses.push(format!("status = ?{}", binds.len() + 1));
            binds.push(s.as_str().to_string().into());
        }
        if let Some(d) = filter.destination_key_id.clone() {
            where_clauses.push(format!("destination_key_id = ?{}", binds.len() + 1));
            binds.push(d.into());
        }
        if let Some(s) = filter.sender_key_id.clone() {
            where_clauses.push(format!("sender_key_id = ?{}", binds.len() + 1));
            binds.push(s.into());
        }
        if let Some(m) = filter.message_type.clone() {
            where_clauses.push(format!("message_type = ?{}", binds.len() + 1));
            binds.push(m.into());
        }
        if let Some(t) = filter.enqueued_after {
            where_clauses.push(format!("enqueued_at >= ?{}", binds.len() + 1));
            binds.push(t.to_rfc3339().into());
        }
        binds.push(limit.into());
        let limit_idx = binds.len();
        let sql = format!(
            "{SQLITE_OUTBOUND_SELECT_PREFIX} WHERE {} ORDER BY enqueued_at ASC LIMIT ?{}",
            where_clauses.join(" AND "),
            limit_idx,
        );
        tokio::task::spawn_blocking(
            move || -> rusqlite::Result<Vec<crate::outbound::OutboundRow>> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(&sql)?;
                let rows = stmt
                    .query_map(
                        rusqlite::params_from_iter(binds.iter()),
                        sqlite_row_to_outbound_row,
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            },
        )
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("list_outbound: {e}")))
    }

    async fn cancel_outbound(
        &self,
        queue_id: &crate::outbound::QueueId,
    ) -> Result<(), crate::outbound::Error> {
        let conn = self.conn.clone();
        let qid = queue_id.clone();
        let now_str = chrono::Utc::now().to_rfc3339();
        tokio::task::spawn_blocking(move || -> rusqlite::Result<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE edge_outbound_queue \
                 SET status = 'abandoned', abandoned_at = ?1, \
                     abandoned_reason = 'operator_cancel', \
                     claimed_until = NULL, claimed_by = NULL \
                 WHERE queue_id = ?2 AND status NOT IN ('delivered', 'abandoned')",
                rusqlite::params![now_str, qid],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("cancel_outbound: {e}")))?;
        Ok(())
    }

    async fn replay_abandoned(
        &self,
        queue_id: &crate::outbound::QueueId,
    ) -> Result<(), crate::outbound::Error> {
        let conn = self.conn.clone();
        let qid = queue_id.clone();
        let now_str = chrono::Utc::now().to_rfc3339();
        let n = tokio::task::spawn_blocking(move || -> rusqlite::Result<usize> {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE edge_outbound_queue \
                 SET status = 'pending', attempt_count = 0, \
                     next_attempt_after = ?1, \
                     abandoned_at = NULL, abandoned_reason = NULL, \
                     last_error_class = NULL, last_error_detail = NULL \
                 WHERE queue_id = ?2 AND status = 'abandoned'",
                rusqlite::params![now_str, qid],
            )
        })
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| crate::outbound::Error::Backend(format!("replay_abandoned: {e}")))?;
        if n == 0 {
            return Err(crate::outbound::Error::InvalidTransition(format!(
                "queue_id {queue_id} not in 'abandoned'"
            )));
        }
        Ok(())
    }
}

const SQLITE_OUTBOUND_SELECT_PREFIX: &str =
    "SELECT queue_id, sender_key_id, destination_key_id, message_type, \
            edge_schema_version, envelope_bytes, body_sha256, body_size_bytes, \
            status, enqueued_at, next_attempt_after, last_attempt_at, \
            transport_delivered_at, delivered_at, abandoned_at, abandoned_reason, \
            attempt_count, max_attempts, ttl_seconds, last_error_class, \
            last_error_detail, last_transport, requires_ack, ack_timeout_seconds, \
            ack_envelope_bytes, ack_received_at, claimed_until, claimed_by \
     FROM edge_outbound_queue";

const SQLITE_OUTBOUND_SELECT_BY_ID: &str =
    "SELECT queue_id, sender_key_id, destination_key_id, message_type, \
            edge_schema_version, envelope_bytes, body_sha256, body_size_bytes, \
            status, enqueued_at, next_attempt_after, last_attempt_at, \
            transport_delivered_at, delivered_at, abandoned_at, abandoned_reason, \
            attempt_count, max_attempts, ttl_seconds, last_error_class, \
            last_error_detail, last_transport, requires_ack, ack_timeout_seconds, \
            ack_envelope_bytes, ack_received_at, claimed_until, claimed_by \
     FROM edge_outbound_queue WHERE queue_id = ?1";

/// v0.4.0 (CIRISPersist#16) — sqlite row → OutboundRow. Mirrors the
/// postgres `pg_row_to_outbound_row` field set + ordering. Unknown
/// status / abandoned_reason / wrong-length body_sha256 surface as
/// `rusqlite::Error::FromSqlConversionFailure` so the rusqlite
/// `query_row` / `query_map` `?` operator handles them naturally;
/// the OutboundQueue impl maps the outer Backend variant at the
/// async boundary.
fn sqlite_row_to_outbound_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::outbound::OutboundRow> {
    use crate::outbound::{AbandonedReason, OutboundStatus};
    let status_str: String = row.get("status")?;
    let status = OutboundStatus::from_wire_str(&status_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            8,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(format!(
                "unknown status: {status_str}"
            ))),
        )
    })?;
    let abandoned_reason_str: Option<String> = row.get("abandoned_reason")?;
    let abandoned_reason = match abandoned_reason_str.as_deref() {
        Some(s) => Some(AbandonedReason::from_wire_str(s).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                15,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(format!(
                    "unknown abandoned_reason: {s}"
                ))),
            )
        })?),
        None => None,
    };
    let body_sha256_vec: Vec<u8> = row.get("body_sha256")?;
    if body_sha256_vec.len() != 32 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::other(format!(
                "body_sha256 wrong length: {}",
                body_sha256_vec.len()
            ))),
        ));
    }
    let mut body_sha256 = [0u8; 32];
    body_sha256.copy_from_slice(&body_sha256_vec);

    let enqueued_at_str: String = row.get("enqueued_at")?;
    let next_attempt_after_str: String = row.get("next_attempt_after")?;
    let last_attempt_at_str: Option<String> = row.get("last_attempt_at")?;
    let transport_delivered_at_str: Option<String> = row.get("transport_delivered_at")?;
    let delivered_at_str: Option<String> = row.get("delivered_at")?;
    let abandoned_at_str: Option<String> = row.get("abandoned_at")?;
    let ack_received_at_str: Option<String> = row.get("ack_received_at")?;
    let claimed_until_str: Option<String> = row.get("claimed_until")?;
    let requires_ack_i: i64 = row.get("requires_ack")?;

    Ok(crate::outbound::OutboundRow {
        queue_id: row.get("queue_id")?,
        sender_key_id: row.get("sender_key_id")?,
        destination_key_id: row.get("destination_key_id")?,
        message_type: row.get("message_type")?,
        edge_schema_version: row.get("edge_schema_version")?,
        envelope_bytes: row.get("envelope_bytes")?,
        body_sha256,
        body_size_bytes: row.get("body_size_bytes")?,
        status,
        enqueued_at: parse_rfc3339(&enqueued_at_str),
        next_attempt_after: parse_rfc3339(&next_attempt_after_str),
        last_attempt_at: last_attempt_at_str.as_deref().map(parse_rfc3339),
        transport_delivered_at: transport_delivered_at_str.as_deref().map(parse_rfc3339),
        delivered_at: delivered_at_str.as_deref().map(parse_rfc3339),
        abandoned_at: abandoned_at_str.as_deref().map(parse_rfc3339),
        abandoned_reason,
        attempt_count: row.get("attempt_count")?,
        max_attempts: row.get("max_attempts")?,
        ttl_seconds: row.get("ttl_seconds")?,
        last_error_class: row.get("last_error_class")?,
        last_error_detail: row.get("last_error_detail")?,
        last_transport: row.get("last_transport")?,
        requires_ack: requires_ack_i != 0,
        ack_timeout_seconds: row.get("ack_timeout_seconds")?,
        ack_envelope_bytes: row.get("ack_envelope_bytes")?,
        ack_received_at: ack_received_at_str.as_deref().map(parse_rfc3339),
        claimed_until: claimed_until_str.as_deref().map(parse_rfc3339),
        claimed_by: row.get("claimed_by")?,
    })
}

fn parse_rfc3339(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|t| t.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now())
}

/// v0.3.5 (CIRISLens#8 ASK 3) — sqlite row → (event_id, TraceEventRow).
/// Used by `Backend::fetch_trace_events_page`. Mirrors the postgres
/// counterpart `pg_row_to_event_row` field set + ordering.
fn sqlite_row_to_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<(i64, TraceEventRow)> {
    use crate::schema::{ReasoningEventType, TraceLevel};
    let event_id: i64 = row.get("event_id")?;
    let event_type_str: String = row.get("event_type")?;
    let event_type = ReasoningEventType::from_wire_str(&event_type_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(format!(
                "unknown event_type: {event_type_str}"
            ))),
        )
    })?;
    let trace_level_str: String = row.get("trace_level")?;
    let trace_level = match trace_level_str.as_str() {
        "generic" => TraceLevel::Generic,
        "detailed" => TraceLevel::Detailed,
        "full_traces" => TraceLevel::FullTraces,
        other => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                11,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(format!(
                    "unknown trace_level: {other}"
                ))),
            ));
        }
    };
    let attempt_index_i64: i64 = row.get("attempt_index")?;
    let attempt_index = u32::try_from(attempt_index_i64).map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Integer,
            Box::new(std::io::Error::other(format!(
                "attempt_index out of range: {attempt_index_i64}"
            ))),
        )
    })?;
    let payload_text: String = row.get("payload")?;
    let payload_value: serde_json::Value = serde_json::from_str(&payload_text).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            12,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(e)),
        )
    })?;
    let payload = match payload_value {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    let ts_str: String = row.get("ts")?;
    let ts = parse_rfc3339(&ts_str);
    let scrub_ts: Option<String> = row.get("scrub_timestamp")?;
    let scrub_timestamp = scrub_ts.as_deref().map(parse_rfc3339);
    let signature_verified_i: i64 = row.get("signature_verified")?;
    let pii_scrubbed_i: i64 = row.get("pii_scrubbed")?;
    let verification_source_str: String = row.get("verification_source")?;
    let verification_source = crate::store::VerificationSource::from_wire_str(
        &verification_source_str,
    )
    .ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(format!(
                "unknown verification_source: {verification_source_str}"
            ))),
        )
    })?;
    Ok((
        event_id,
        TraceEventRow {
            trace_id: row.get("trace_id")?,
            thought_id: row.get("thought_id")?,
            task_id: row.get("task_id")?,
            step_point: row.get("step_point")?,
            event_type,
            attempt_index,
            ts,
            agent_name: row.get("agent_name")?,
            agent_id_hash: row.get("agent_id_hash")?,
            cognitive_state: row.get("cognitive_state")?,
            trace_level,
            payload,
            cost_llm_calls: row.get("cost_llm_calls")?,
            cost_tokens: row.get("cost_tokens")?,
            cost_usd: row.get("cost_usd")?,
            signature: row.get("signature")?,
            signing_key_id: row.get("signing_key_id")?,
            signature_verified: signature_verified_i != 0,
            verification_source,
            schema_version: row.get("schema_version")?,
            pii_scrubbed: pii_scrubbed_i != 0,
            original_content_hash: row.get("original_content_hash")?,
            scrub_signature: row.get("scrub_signature")?,
            scrub_key_id: row.get("scrub_key_id")?,
            scrub_timestamp,
            agent_role: row.get("agent_role")?,
            agent_template: row.get("agent_template")?,
            deployment_domain: row.get("deployment_domain")?,
            deployment_type: row.get("deployment_type")?,
            deployment_region: row.get("deployment_region")?,
            deployment_trust_mode: row.get("deployment_trust_mode")?,
        },
    ))
}

fn sqlite_row_to_key_record(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::federation::KeyRecord> {
    let envelope_text: String = row.get("registration_envelope")?;
    let envelope: serde_json::Value = serde_json::from_str(&envelope_text).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            7,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        )
    })?;
    let original_content_hash: Vec<u8> = row.get("original_content_hash")?;
    let valid_from: String = row.get("valid_from")?;
    let valid_until: Option<String> = row.get("valid_until")?;
    let scrub_timestamp: String = row.get("scrub_timestamp")?;
    let pqc_completed_at: Option<String> = row.get("pqc_completed_at")?;
    // v1.3.0 (CIRISPersist#46): `roles` is stored as a JSON-array
    // TEXT column. NULL or absent → empty Vec.
    let roles_text: Option<String> = row.get("roles").ok();
    let roles: Vec<String> = roles_text
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();
    Ok(crate::federation::KeyRecord {
        key_id: row.get("key_id")?,
        pubkey_ed25519_base64: row.get("pubkey_ed25519_base64")?,
        pubkey_ml_dsa_65_base64: row.get("pubkey_ml_dsa_65_base64")?,
        algorithm: row.get("algorithm")?,
        identity_type: row.get("identity_type")?,
        identity_ref: row.get("identity_ref")?,
        valid_from: parse_rfc3339(&valid_from),
        valid_until: valid_until.as_deref().map(parse_rfc3339),
        registration_envelope: envelope,
        original_content_hash: hex::encode(&original_content_hash),
        scrub_signature_classical: row.get("scrub_signature_classical")?,
        scrub_signature_pqc: row.get("scrub_signature_pqc")?,
        scrub_key_id: row.get("scrub_key_id")?,
        scrub_timestamp: parse_rfc3339(&scrub_timestamp),
        pqc_completed_at: pqc_completed_at.as_deref().map(parse_rfc3339),
        persist_row_hash: row.get("persist_row_hash")?,
        roles,
    })
}

fn sqlite_row_to_attestation(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::federation::Attestation> {
    let envelope_text: String = row.get("attestation_envelope")?;
    let envelope: serde_json::Value = serde_json::from_str(&envelope_text).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            7,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        )
    })?;
    let original_content_hash: Vec<u8> = row.get("original_content_hash")?;
    let asserted_at: String = row.get("asserted_at")?;
    let expires_at: Option<String> = row.get("expires_at")?;
    let scrub_timestamp: String = row.get("scrub_timestamp")?;
    let pqc_completed_at: Option<String> = row.get("pqc_completed_at")?;
    Ok(crate::federation::Attestation {
        attestation_id: row.get("attestation_id")?,
        attesting_key_id: row.get("attesting_key_id")?,
        attested_key_id: row.get("attested_key_id")?,
        attestation_type: row.get("attestation_type")?,
        weight: row.get("weight")?,
        asserted_at: parse_rfc3339(&asserted_at),
        expires_at: expires_at.as_deref().map(parse_rfc3339),
        attestation_envelope: envelope,
        original_content_hash: hex::encode(&original_content_hash),
        scrub_signature_classical: row.get("scrub_signature_classical")?,
        scrub_signature_pqc: row.get("scrub_signature_pqc")?,
        scrub_key_id: row.get("scrub_key_id")?,
        scrub_timestamp: parse_rfc3339(&scrub_timestamp),
        pqc_completed_at: pqc_completed_at.as_deref().map(parse_rfc3339),
        persist_row_hash: row.get("persist_row_hash")?,
    })
}

fn sqlite_row_to_revocation(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::federation::Revocation> {
    let envelope_text: String = row.get("revocation_envelope")?;
    let envelope: serde_json::Value = serde_json::from_str(&envelope_text).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            6,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        )
    })?;
    let original_content_hash: Vec<u8> = row.get("original_content_hash")?;
    let revoked_at: String = row.get("revoked_at")?;
    let effective_at: String = row.get("effective_at")?;
    let scrub_timestamp: String = row.get("scrub_timestamp")?;
    let pqc_completed_at: Option<String> = row.get("pqc_completed_at")?;
    Ok(crate::federation::Revocation {
        revocation_id: row.get("revocation_id")?,
        revoked_key_id: row.get("revoked_key_id")?,
        revoking_key_id: row.get("revoking_key_id")?,
        reason: row.get("reason")?,
        revoked_at: parse_rfc3339(&revoked_at),
        effective_at: parse_rfc3339(&effective_at),
        revocation_envelope: envelope,
        original_content_hash: hex::encode(&original_content_hash),
        scrub_signature_classical: row.get("scrub_signature_classical")?,
        scrub_signature_pqc: row.get("scrub_signature_pqc")?,
        scrub_key_id: row.get("scrub_key_id")?,
        scrub_timestamp: parse_rfc3339(&scrub_timestamp),
        pqc_completed_at: pqc_completed_at.as_deref().map(parse_rfc3339),
        persist_row_hash: row.get("persist_row_hash")?,
    })
}

// ─── ReadEngine impl (v1.x sovereign-mode parity, CIRISPersist#23) ──
//
// SQLite backend — full parity with the Postgres `ReadEngine` impl so
// sovereign-mode deployments (Raspberry Pi, iOS) get the observability
// read API. The Postgres impl leans on TimescaleDB continuous
// aggregates for the §E/§F analytics; SQLite has no continuous-
// aggregate machinery, so those primitives run as raw-window queries
// over `trace_events` — the same logical computation, expressed
// in single-statement SQL plus Rust-side statistics where SQLite
// lacks an aggregate (it has no `STDDEV` / `VAR_SAMP`, so divergence
// / temporal-drift variance is computed in Rust from per-group
// means).
//
// Dialect translations vs. the Postgres impl:
//   * `cirislens.<table>`     → flat `<table>` (SQLite has no schemas).
//   * `payload->>'k'`         → `json_extract(payload, '$.k')`.
//   * `payload ? 'k'`         → `json_extract(payload,'$.k') IS NOT NULL`.
//   * `col = ANY($1::text[])` → `IN (?,?,…)` with one bind per element.
//   * `BOOL_OR` / `BOOL_AND`  → `MAX` / `MIN` over 0/1 integers.
//   * `STDDEV_SAMP`/`VAR_SAMP`→ computed in Rust.
//   * `::bigint` / `::float8` casts → dropped (dynamic typing).
//   * Timestamps               → RFC3339 TEXT (`to_rfc3339`); lexical
//     comparison is order-correct because every writer normalizes to
//     a fixed `+00:00` offset. Decoded via `parse_rfc3339`.
//
// Cursor wire format is byte-identical to the Postgres impl — same
// `*Cursor::from_trailing` calls, same `"v1"` version gate.

/// JSONB-extraction SELECT clause shared by SQLite's `get_trace_summary`
/// and `list_trace_summaries`. SQLite has no `BOOL_AND` / `BOOL_OR`, so
/// boolean folds use `MIN`/`MAX` over the 0/1 the json predicate yields
/// (`json_extract` on a JSON boolean returns integer 0/1). Postgres'
/// `TRACE_SUMMARY_SELECT` is the reference; the column aliases match
/// 1:1 so `sqlite_row_to_trace_summary` reads by name.
const SQLITE_TRACE_SUMMARY_SELECT: &str = "\
    MIN(trace_id) AS trace_id, \
    MIN(thought_id) AS thought_id, \
    MIN(task_id) AS task_id, \
    MIN(agent_id_hash) AS agent_id_hash, \
    MIN(agent_name) AS agent_name, \
    MIN(agent_role) AS agent_role, \
    MIN(deployment_domain) AS deployment_domain, \
    MIN(deployment_type) AS deployment_type, \
    MIN(ts) AS started_at, \
    MAX(ts) AS completed_at, \
    MIN(trace_level) AS trace_level, \
    MIN(schema_version) AS schema_version, \
    MIN(signature_verified) AS signature_verified, \
    MIN(cognitive_state) AS cognitive_state, \
    MAX(CASE WHEN event_type = 'THOUGHT_START' \
        THEN json_extract(payload, '$.thought_type') END) AS thought_type, \
    MAX(CASE WHEN event_type = 'THOUGHT_START' \
        THEN json_extract(payload, '$.thought_depth') END) AS thought_depth, \
    AVG(CASE WHEN event_type = 'DMA_RESULTS' \
        THEN json_extract(payload, '$.csdma_plausibility_score') END) \
        AS csdma_plausibility_score, \
    AVG(CASE WHEN event_type = 'DMA_RESULTS' \
        THEN json_extract(payload, '$.dsdma_domain_alignment') END) \
        AS dsdma_domain_alignment, \
    MAX(CASE WHEN event_type = 'DMA_RESULTS' \
        THEN json_extract(payload, '$.dsdma_domain') END) AS dsdma_domain, \
    AVG(CASE WHEN event_type = 'IDMA_RESULT' \
        THEN json_extract(payload, '$.idma_k_eff') END) AS idma_k_eff, \
    AVG(CASE WHEN event_type = 'IDMA_RESULT' \
        THEN json_extract(payload, '$.idma_correlation_risk') END) \
        AS idma_correlation_risk, \
    MAX(CASE WHEN event_type = 'IDMA_RESULT' \
        THEN json_extract(payload, '$.idma_fragility_flag') END) AS idma_fragility_flag, \
    MAX(CASE WHEN event_type = 'IDMA_RESULT' \
        THEN json_extract(payload, '$.idma_phase') END) AS idma_phase, \
    MIN(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
        THEN json_extract(payload, '$.conscience_passed') END) AS conscience_passed, \
    MAX(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
        THEN json_extract(payload, '$.action_was_overridden') END) AS action_was_overridden, \
    MIN(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
        THEN json_extract(payload, '$.entropy_passed') END) AS entropy_passed, \
    MIN(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
        THEN json_extract(payload, '$.coherence_passed') END) AS coherence_passed, \
    MIN(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
        THEN json_extract(payload, '$.optimization_veto_passed') END) \
        AS optimization_veto_passed, \
    MIN(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
        THEN json_extract(payload, '$.epistemic_humility_passed') END) \
        AS epistemic_humility_passed, \
    MAX(CASE WHEN event_type = 'ACTION_RESULT' \
        THEN json_extract(payload, '$.action_executed') END) AS selected_action, \
    MIN(CASE WHEN event_type = 'ACTION_RESULT' \
        THEN json_extract(payload, '$.success') END) AS action_success, \
    MAX(cost_llm_calls) AS llm_calls, \
    MAX(cost_tokens) AS tokens_total, \
    MAX(cost_usd) AS cost_usd";

/// Decode an integer-or-NULL column carrying a JSON boolean into
/// `Option<bool>`. `json_extract` on a JSON `true`/`false` yields the
/// SQLite integers 1/0; absent paths yield NULL.
fn sqlite_opt_bool(row: &rusqlite::Row<'_>, col: &str) -> rusqlite::Result<Option<bool>> {
    Ok(row.get::<_, Option<i64>>(col)?.map(|v| v != 0))
}

/// Convert a row produced by [`SQLITE_TRACE_SUMMARY_SELECT`] into a
/// [`crate::read::TraceSummary`]. Mirrors `pg_row_to_trace_summary`.
fn sqlite_row_to_trace_summary(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<crate::read::TraceSummary> {
    use crate::schema::TraceLevel;
    let trace_level_str: String = row.get("trace_level")?;
    let trace_level = match trace_level_str.as_str() {
        "generic" => TraceLevel::Generic,
        "detailed" => TraceLevel::Detailed,
        "full_traces" => TraceLevel::FullTraces,
        other => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(format!(
                    "unknown trace_level: {other}"
                ))),
            ));
        }
    };
    let started_at: String = row.get("started_at")?;
    let completed_at: String = row.get("completed_at")?;
    let signature_verified_i: Option<i64> = row.get("signature_verified")?;
    let thought_depth: Option<i64> = row.get("thought_depth")?;
    Ok(crate::read::TraceSummary {
        trace_id: row.get("trace_id")?,
        thought_id: row.get("thought_id")?,
        task_id: row.get("task_id")?,
        agent_id_hash: row.get("agent_id_hash")?,
        agent_name: row.get("agent_name")?,
        agent_role: row.get("agent_role")?,
        deployment_domain: row.get("deployment_domain")?,
        deployment_type: row.get("deployment_type")?,
        started_at: parse_rfc3339(&started_at),
        completed_at: parse_rfc3339(&completed_at),
        trace_level,
        schema_version: row.get("schema_version")?,
        signature_verified: signature_verified_i.unwrap_or(0) != 0,
        cognitive_state: row.get("cognitive_state")?,
        thought_type: row.get("thought_type")?,
        thought_depth: thought_depth.and_then(|d| i32::try_from(d).ok()),
        csdma_plausibility_score: row.get("csdma_plausibility_score")?,
        dsdma_domain_alignment: row.get("dsdma_domain_alignment")?,
        dsdma_domain: row.get("dsdma_domain")?,
        idma_k_eff: row.get("idma_k_eff")?,
        idma_correlation_risk: row.get("idma_correlation_risk")?,
        idma_fragility_flag: sqlite_opt_bool(row, "idma_fragility_flag")?,
        idma_phase: row.get("idma_phase")?,
        conscience_passed: sqlite_opt_bool(row, "conscience_passed")?,
        action_was_overridden: sqlite_opt_bool(row, "action_was_overridden")?,
        entropy_passed: sqlite_opt_bool(row, "entropy_passed")?,
        coherence_passed: sqlite_opt_bool(row, "coherence_passed")?,
        optimization_veto_passed: sqlite_opt_bool(row, "optimization_veto_passed")?,
        epistemic_humility_passed: sqlite_opt_bool(row, "epistemic_humility_passed")?,
        selected_action: row.get("selected_action")?,
        action_success: sqlite_opt_bool(row, "action_success")?,
        llm_calls: row.get("llm_calls")?,
        tokens_total: row.get("tokens_total")?,
        cost_usd: row.get("cost_usd")?,
    })
}

/// Decode a `trace_llm_calls` row into a typed [`TraceLlmCallRow`].
/// Mirrors `pg_row_to_llm_call_row`; the SELECT must alias every
/// column read here.
fn sqlite_row_to_llm_call_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TraceLlmCallRow> {
    use crate::schema::{LlmCallStatus, ReasoningEventType};
    let parent_event_type_str: String = row.get("parent_event_type")?;
    let parent_event_type = ReasoningEventType::from_wire_str(&parent_event_type_str)
        .unwrap_or(ReasoningEventType::Unknown);
    let status_str: String = row.get("status")?;
    let status = match status_str.as_str() {
        "ok" => LlmCallStatus::Ok,
        "timeout" => LlmCallStatus::Timeout,
        "rate_limited" => LlmCallStatus::RateLimited,
        "model_not_available" => LlmCallStatus::ModelNotAvailable,
        "instructor_retry" => LlmCallStatus::InstructorRetry,
        "other_error" => LlmCallStatus::OtherError,
        other => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(format!(
                    "unknown llm_call status: {other}"
                ))),
            ));
        }
    };
    let parent_attempt_index_i64: i64 = row.get("parent_attempt_index")?;
    let attempt_index_i64: i64 = row.get("attempt_index")?;
    let ts_str: String = row.get("ts")?;
    Ok(TraceLlmCallRow {
        trace_id: row.get("trace_id")?,
        thought_id: row.get("thought_id")?,
        task_id: row.get("task_id")?,
        parent_event_id: row.get("parent_event_id")?,
        parent_event_type,
        parent_attempt_index: u32::try_from(parent_attempt_index_i64).unwrap_or(0),
        attempt_index: u32::try_from(attempt_index_i64).unwrap_or(0),
        ts: parse_rfc3339(&ts_str),
        duration_ms: row.get("duration_ms")?,
        handler_name: row.get("handler_name")?,
        service_name: row.get("service_name")?,
        model: row.get("model")?,
        base_url: row.get("base_url")?,
        response_model: row.get("response_model")?,
        prompt_tokens: row.get("prompt_tokens")?,
        completion_tokens: row.get("completion_tokens")?,
        prompt_bytes: row.get("prompt_bytes")?,
        completion_bytes: row.get("completion_bytes")?,
        cost_usd: row.get("cost_usd")?,
        status,
        error_class: row.get("error_class")?,
        attempt_count: row.get("attempt_count")?,
        retry_count: row.get("retry_count")?,
        prompt_hash: row.get("prompt_hash")?,
        prompt: row.get("prompt")?,
        response_text: row.get("response_text")?,
    })
}

/// Build a parameterized WHERE fragment from a [`crate::read::TraceFilter`].
/// Returns the SQL (`"WHERE …"` or empty) and the positional bind vec.
/// `?N` placeholders count from 1; callers that append more binds
/// continue from `binds.len()`.
fn sqlite_filter_where(
    filter: &crate::read::TraceFilter,
) -> Result<(String, Vec<SqlValue>), crate::read::Error> {
    let mut parts: Vec<String> = Vec::new();
    let mut binds: Vec<SqlValue> = Vec::new();
    if let Some(w) = filter.time_window {
        binds.push(SqlValue::Text(w.since.to_rfc3339()));
        parts.push(format!("ts >= ?{}", binds.len()));
        binds.push(SqlValue::Text(w.until.to_rfc3339()));
        parts.push(format!("ts < ?{}", binds.len()));
    }
    if let Some(h) = &filter.agent_id_hash {
        binds.push(SqlValue::Text(h.clone()));
        parts.push(format!("agent_id_hash = ?{}", binds.len()));
    }
    if let Some(n) = &filter.agent_name {
        binds.push(SqlValue::Text(n.clone()));
        parts.push(format!("agent_name = ?{}", binds.len()));
    }
    if let Some(d) = &filter.deployment_domain {
        binds.push(SqlValue::Text(d.clone()));
        parts.push(format!("deployment_domain = ?{}", binds.len()));
    }
    if let Some(d) = &filter.deployment_type {
        binds.push(SqlValue::Text(d.clone()));
        parts.push(format!("deployment_type = ?{}", binds.len()));
    }
    if let Some(level) = filter.trace_level {
        binds.push(SqlValue::Text(trace_level_str(level).to_owned()));
        parts.push(format!("trace_level = ?{}", binds.len()));
    }
    if let Some(verified) = filter.signature_verified {
        binds.push(SqlValue::Integer(i64::from(verified)));
        parts.push(format!("signature_verified = ?{}", binds.len()));
    }
    if let Some(v) = &filter.schema_version {
        binds.push(SqlValue::Text(v.clone()));
        parts.push(format!("schema_version = ?{}", binds.len()));
    }
    if let Some(s) = &filter.cognitive_state {
        binds.push(SqlValue::Text(s.clone()));
        parts.push(format!("cognitive_state = ?{}", binds.len()));
    }
    let sql = if parts.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", parts.join(" AND "))
    };
    Ok((sql, binds))
}

/// SQL predicate matching a [`crate::read::TaskClass`] against the
/// `task_id` column — mirrors `TaskClass::from_task_id`. SQLite
/// supports `LIKE … ESCAPE` and `instr()` (arg order
/// `instr(haystack, needle)`).
fn sqlite_task_class_predicate(tc: crate::read::TaskClass) -> &'static str {
    use crate::read::TaskClass;
    match tc {
        TaskClass::QaEval => "(task_id LIKE 'qa\\_%' ESCAPE '\\' OR task_id LIKE 'qa-eval%')",
        TaskClass::Discord => "task_id LIKE 'discord\\_%' ESCAPE '\\'",
        TaskClass::RealUserDiscord => "task_id LIKE 'real\\_user\\_discord\\_%' ESCAPE '\\'",
        TaskClass::RealUserCli => "task_id LIKE 'real\\_user\\_cli\\_%' ESCAPE '\\'",
        TaskClass::RealUserApi => "task_id LIKE 'real\\_user\\_api\\_%' ESCAPE '\\'",
        TaskClass::WakeupRitual => "instr(task_id, 'wakeup') > 0",
        TaskClass::Other => {
            "(task_id NOT LIKE 'qa\\_%' ESCAPE '\\' \
               AND task_id NOT LIKE 'qa-eval%' \
               AND task_id NOT LIKE 'discord\\_%' ESCAPE '\\' \
               AND task_id NOT LIKE 'real\\_user\\_discord\\_%' ESCAPE '\\' \
               AND task_id NOT LIKE 'real\\_user\\_cli\\_%' ESCAPE '\\' \
               AND task_id NOT LIKE 'real\\_user\\_api\\_%' ESCAPE '\\' \
               AND instr(task_id, 'wakeup') = 0)"
        }
    }
}

/// Build the JOIN + WHERE + binds for an [`crate::read::LlmCallFilter`].
/// Filters that need parent `trace_events` columns force the join.
/// Returns `(join_sql, where_sql, binds)`; `where_sql` is empty or
/// starts with `"WHERE "`.
fn sqlite_llm_filter_sql(
    filter: &crate::read::LlmCallFilter,
) -> Result<(String, String, Vec<SqlValue>), crate::read::Error> {
    let mut parts: Vec<String> = Vec::new();
    let mut binds: Vec<SqlValue> = Vec::new();
    let needs_join = filter.agent_id_hash.is_some()
        || filter.agent_name.is_some()
        || filter.deployment_domain.is_some();
    if let Some(w) = filter.time_window {
        binds.push(SqlValue::Text(w.since.to_rfc3339()));
        parts.push(format!("lc.ts >= ?{}", binds.len()));
        binds.push(SqlValue::Text(w.until.to_rfc3339()));
        parts.push(format!("lc.ts < ?{}", binds.len()));
    }
    if let Some(h) = &filter.agent_id_hash {
        binds.push(SqlValue::Text(h.clone()));
        parts.push(format!("e.agent_id_hash = ?{}", binds.len()));
    }
    if let Some(n) = &filter.agent_name {
        binds.push(SqlValue::Text(n.clone()));
        parts.push(format!("e.agent_name = ?{}", binds.len()));
    }
    if let Some(d) = &filter.deployment_domain {
        binds.push(SqlValue::Text(d.clone()));
        parts.push(format!("e.deployment_domain = ?{}", binds.len()));
    }
    if let Some(m) = &filter.model {
        binds.push(SqlValue::Text(m.clone()));
        parts.push(format!("lc.model = ?{}", binds.len()));
    }
    if let Some(s) = filter.status {
        binds.push(SqlValue::Text(llm_status_str(s).to_owned()));
        parts.push(format!("lc.status = ?{}", binds.len()));
    }
    if let Some(t) = &filter.trace_id {
        binds.push(SqlValue::Text(t.clone()));
        parts.push(format!("lc.trace_id = ?{}", binds.len()));
    }
    if let Some(t) = &filter.thought_id {
        binds.push(SqlValue::Text(t.clone()));
        parts.push(format!("lc.thought_id = ?{}", binds.len()));
    }
    let join_sql = if needs_join {
        "JOIN trace_events e \
           ON e.trace_id = lc.trace_id AND e.event_id = lc.parent_event_id"
            .to_owned()
    } else {
        String::new()
    };
    let where_sql = if parts.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", parts.join(" AND "))
    };
    Ok((join_sql, where_sql, binds))
}

/// Map a `rusqlite::Error` to a `read::Error::Backend`, tagged with the
/// calling primitive's name.
fn sqlite_read_err(ctx: &str) -> impl Fn(rusqlite::Error) -> crate::read::Error + '_ {
    move |e| crate::read::Error::Backend(format!("{ctx}: {e}"))
}

impl crate::read::ReadEngine for SqliteBackend {
    async fn list_trace_summaries(
        &self,
        filter: crate::read::TraceFilter,
        cursor: Option<crate::read::TraceCursor>,
        limit: i64,
    ) -> Result<crate::read::TraceListPage, crate::read::Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(crate::read::Error::InvalidArgument(format!(
                "limit must be in 1..=10000, got {limit}"
            )));
        }
        if let Some(c) = &cursor {
            if c.version != "v1" {
                return Err(crate::read::Error::InvalidCursor(format!(
                    "cursor version {} not supported (expected v1)",
                    c.version
                )));
            }
        }
        let (where_sql, mut binds) = sqlite_filter_where(&filter)?;
        // HAVING gates the cursor on the GROUPED row's started_at /
        // trace_id (aggregates can't go in WHERE). SQLite supports
        // row-value comparison.
        let having_sql = match &cursor {
            None => String::new(),
            Some(c) => {
                binds.push(SqlValue::Text(c.last_started_at.to_rfc3339()));
                let p1 = binds.len();
                binds.push(SqlValue::Text(c.last_trace_id.clone()));
                let p2 = binds.len();
                format!("HAVING (MIN(ts), MIN(trace_id)) < (?{p1}, ?{p2})")
            }
        };
        binds.push(SqlValue::Integer(limit));
        let p_limit = binds.len();
        let sql = format!(
            "SELECT {select} FROM trace_events \
             {where_sql} GROUP BY trace_id {having_sql} \
             ORDER BY started_at DESC, trace_id DESC LIMIT ?{p_limit}",
            select = SQLITE_TRACE_SUMMARY_SELECT,
        );
        let conn = self.conn.clone();
        let items = tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::read::TraceSummary>, crate::read::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(sqlite_read_err("list_trace_summaries prepare"))?;
                let rows = stmt
                    .query_map(params_from_iter(binds.iter()), |r| {
                        sqlite_row_to_trace_summary(r)
                    })
                    .map_err(sqlite_read_err("list_trace_summaries query"))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sqlite_read_err("list_trace_summaries row"))?;
                Ok(rows)
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))??;

        let next_cursor = if items.len() as i64 == limit {
            items
                .last()
                .map(|s| crate::read::TraceCursor::from_trailing(s.started_at, s.trace_id.clone()))
        } else {
            None
        };
        Ok(crate::read::TraceListPage { items, next_cursor })
    }

    async fn get_trace_summary(
        &self,
        trace_id: &str,
    ) -> Result<Option<crate::read::TraceSummary>, crate::read::Error> {
        let trace_id = trace_id.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Option<crate::read::TraceSummary>, crate::read::Error> {
                let conn = conn.blocking_lock();
                let sql = format!(
                    "SELECT {select} FROM trace_events \
                     WHERE trace_id = ?1 GROUP BY trace_id",
                    select = SQLITE_TRACE_SUMMARY_SELECT,
                );
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(sqlite_read_err("get_trace_summary prepare"))?;
                stmt.query_row([&trace_id], sqlite_row_to_trace_summary)
                    .optional()
                    .map_err(sqlite_read_err("get_trace_summary query"))
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn get_trace_detail(
        &self,
        trace_id: &str,
    ) -> Result<Option<crate::read::TraceDetail>, crate::read::Error> {
        let trace_id = trace_id.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Option<crate::read::TraceDetail>, crate::read::Error> {
                let conn = conn.blocking_lock();

                // Summary first — early-out on absent trace.
                let summary_sql = format!(
                    "SELECT {select} FROM trace_events \
                     WHERE trace_id = ?1 GROUP BY trace_id",
                    select = SQLITE_TRACE_SUMMARY_SELECT,
                );
                let summary = {
                    let mut stmt = conn
                        .prepare(&summary_sql)
                        .map_err(sqlite_read_err("get_trace_detail summary prepare"))?;
                    stmt.query_row([&trace_id], sqlite_row_to_trace_summary)
                        .optional()
                        .map_err(sqlite_read_err("get_trace_detail summary"))?
                };
                let summary = match summary {
                    Some(s) => s,
                    None => return Ok(None),
                };

                // Components — full event-row spread, chronological.
                let cols = "event_id, trace_id, thought_id, task_id, step_point, \
                            event_type, attempt_index, ts, agent_name, agent_id_hash, \
                            cognitive_state, trace_level, payload, cost_llm_calls, \
                            cost_tokens, cost_usd, signature, signing_key_id, \
                            signature_verified, schema_version, pii_scrubbed, \
                            audit_sequence_number, audit_entry_hash, audit_signature, \
                            original_content_hash, scrub_signature, scrub_key_id, \
                            scrub_timestamp, agent_role, agent_template, \
                            deployment_domain, deployment_type, deployment_region, \
                            deployment_trust_mode, verification_source";
                let event_rows: Vec<(i64, TraceEventRow)> = {
                    let sql = format!(
                        "SELECT {cols} FROM trace_events \
                         WHERE trace_id = ?1 ORDER BY ts ASC"
                    );
                    let mut stmt = conn
                        .prepare(&sql)
                        .map_err(sqlite_read_err("get_trace_detail components prepare"))?;
                    let collected = stmt
                        .query_map([&trace_id], sqlite_row_to_event_row)
                        .map_err(sqlite_read_err("get_trace_detail components query"))?
                        .collect::<Result<Vec<_>, _>>();
                    collected.map_err(sqlite_read_err("get_trace_detail components row"))?
                };
                if event_rows.is_empty() {
                    // Concurrent delete between the two reads — caller retries.
                    return Ok(None);
                }

                // Envelope refs — per-trace constants from the first row.
                let first = &event_rows[0].1;
                let envelope = crate::read::TraceEnvelopeRefs {
                    signature: first.signature.clone(),
                    signature_key_id: first.signing_key_id.clone(),
                    original_content_hash: first.original_content_hash.clone(),
                    scrub_signature: first.scrub_signature.clone(),
                    scrub_key_id: first.scrub_key_id.clone(),
                    scrub_timestamp: first.scrub_timestamp,
                    pii_scrubbed: first.pii_scrubbed,
                };
                let components: Vec<crate::read::TraceComponentRow> = event_rows
                    .into_iter()
                    .map(|(_id, full)| crate::read::TraceComponentRow {
                        step_point: full.step_point,
                        event_type: full.event_type,
                        attempt_index: full.attempt_index,
                        ts: full.ts,
                        payload: full.payload,
                    })
                    .collect();

                // LLM calls — chronological.
                let llm_cols = "trace_id, thought_id, task_id, parent_event_id, \
                                parent_event_type, parent_attempt_index, attempt_index, \
                                ts, duration_ms, handler_name, service_name, model, \
                                base_url, response_model, prompt_tokens, completion_tokens, \
                                prompt_bytes, completion_bytes, cost_usd, status, \
                                error_class, attempt_count, retry_count, prompt_hash, \
                                prompt, response_text";
                let llm_calls: Vec<TraceLlmCallRow> = {
                    let sql = format!(
                        "SELECT {llm_cols} FROM trace_llm_calls \
                         WHERE trace_id = ?1 ORDER BY ts ASC"
                    );
                    let mut stmt = conn
                        .prepare(&sql)
                        .map_err(sqlite_read_err("get_trace_detail llm prepare"))?;
                    let collected = stmt
                        .query_map([&trace_id], sqlite_row_to_llm_call_row)
                        .map_err(sqlite_read_err("get_trace_detail llm query"))?
                        .collect::<Result<Vec<_>, _>>();
                    collected.map_err(sqlite_read_err("get_trace_detail llm row"))?
                };

                Ok(Some(crate::read::TraceDetail {
                    summary,
                    components,
                    llm_calls,
                    envelope,
                }))
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn list_tasks(
        &self,
        filter: crate::read::TaskFilter,
        cursor: Option<crate::read::TaskCursor>,
        limit: i64,
    ) -> Result<crate::read::TaskListPage, crate::read::Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(crate::read::Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        if let Some(c) = &cursor {
            if c.version != "v1" {
                return Err(crate::read::Error::InvalidCursor(format!(
                    "TaskCursor version {} unsupported; v1 only",
                    c.version
                )));
            }
        }
        // WHERE on the trace rows. task_id IS NOT NULL excludes
        // task-less traces from the task-axis listing.
        let mut parts: Vec<String> = vec!["task_id IS NOT NULL".to_owned()];
        let mut binds: Vec<SqlValue> = Vec::new();
        if let Some(w) = filter.time_window {
            binds.push(SqlValue::Text(w.since.to_rfc3339()));
            parts.push(format!("ts >= ?{}", binds.len()));
            binds.push(SqlValue::Text(w.until.to_rfc3339()));
            parts.push(format!("ts < ?{}", binds.len()));
        }
        if let Some(h) = &filter.agent_id_hash {
            binds.push(SqlValue::Text(h.clone()));
            parts.push(format!("agent_id_hash = ?{}", binds.len()));
        }
        if let Some(n) = &filter.agent_name {
            binds.push(SqlValue::Text(n.clone()));
            parts.push(format!("agent_name = ?{}", binds.len()));
        }
        if let Some(d) = &filter.deployment_domain {
            binds.push(SqlValue::Text(d.clone()));
            parts.push(format!("deployment_domain = ?{}", binds.len()));
        }
        if let Some(tc) = filter.task_class {
            parts.push(sqlite_task_class_predicate(tc).to_owned());
        }
        let where_sql = format!("WHERE {}", parts.join(" AND "));
        let having_sql = match &cursor {
            None => String::new(),
            Some(c) => {
                binds.push(SqlValue::Text(c.last_earliest_at.to_rfc3339()));
                let p_at = binds.len();
                binds.push(SqlValue::Text(c.last_task_id.clone()));
                let p_id = binds.len();
                format!("HAVING (MIN(ts), task_id) < (?{p_at}, ?{p_id})")
            }
        };
        binds.push(SqlValue::Integer(limit));
        let p_limit = binds.len();
        let task_page_sql = format!(
            "SELECT task_id, MIN(ts) AS earliest_at, MAX(ts) AS latest_at, \
                    MAX(CASE WHEN event_type = 'THOUGHT_START' \
                        THEN json_extract(payload, '$.task_description') END) \
                        AS initial_observation \
             FROM trace_events {where_sql} \
             GROUP BY task_id {having_sql} \
             ORDER BY earliest_at DESC, task_id DESC LIMIT ?{p_limit}"
        );
        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        tokio::task::spawn_blocking(
            move || -> Result<crate::read::TaskListPage, crate::read::Error> {
                let conn = conn.blocking_lock();
                struct TaskHeader {
                    task_id: String,
                    earliest_at: chrono::DateTime<chrono::Utc>,
                    latest_at: chrono::DateTime<chrono::Utc>,
                    initial_observation: Option<String>,
                }
                let headers: Vec<TaskHeader> = {
                    let mut stmt = conn
                        .prepare(&task_page_sql)
                        .map_err(sqlite_read_err("list_tasks page prepare"))?;
                    let collected = stmt
                        .query_map(params_from_iter(binds.iter()), |r| {
                            let earliest: String = r.get("earliest_at")?;
                            let latest: String = r.get("latest_at")?;
                            Ok(TaskHeader {
                                task_id: r.get("task_id")?,
                                earliest_at: parse_rfc3339(&earliest),
                                latest_at: parse_rfc3339(&latest),
                                initial_observation: r.get("initial_observation")?,
                            })
                        })
                        .map_err(sqlite_read_err("list_tasks page query"))?
                        .collect::<Result<Vec<_>, _>>();
                    collected.map_err(sqlite_read_err("list_tasks page row"))?
                };
                if headers.is_empty() {
                    return Ok(crate::read::TaskListPage {
                        items: Vec::new(),
                        next_cursor: None,
                    });
                }

                // Trace summaries for every task on the page. SQLite has
                // no array binding — build an IN (?,?,…) list.
                let task_ids: Vec<String> = headers.iter().map(|h| h.task_id.clone()).collect();
                let placeholders: String = (1..=task_ids.len())
                    .map(|i| format!("?{i}"))
                    .collect::<Vec<_>>()
                    .join(",");
                let traces_sql = format!(
                    "SELECT MAX(task_id) AS _tg_task_id, {select}, \
                            MAX(CASE WHEN event_type = 'THOUGHT_START' \
                                THEN json_extract(payload, '$.thought_depth') END) \
                                AS _tg_depth \
                     FROM trace_events WHERE task_id IN ({placeholders}) \
                     GROUP BY trace_id \
                     ORDER BY _tg_task_id ASC, \
                              _tg_depth IS NULL, _tg_depth ASC, started_at ASC",
                    select = SQLITE_TRACE_SUMMARY_SELECT,
                );
                let trace_binds: Vec<SqlValue> =
                    task_ids.iter().map(|t| SqlValue::Text(t.clone())).collect();
                let mut bucket: std::collections::HashMap<String, Vec<crate::read::TraceSummary>> =
                    std::collections::HashMap::new();
                {
                    let mut stmt = conn
                        .prepare(&traces_sql)
                        .map_err(sqlite_read_err("list_tasks traces prepare"))?;
                    let mut rows = stmt
                        .query(params_from_iter(trace_binds.iter()))
                        .map_err(sqlite_read_err("list_tasks traces query"))?;
                    while let Some(row) = rows
                        .next()
                        .map_err(sqlite_read_err("list_tasks traces row"))?
                    {
                        let tg_task_id: String = row
                            .get("_tg_task_id")
                            .map_err(sqlite_read_err("list_tasks _tg_task_id"))?;
                        let summary = sqlite_row_to_trace_summary(row)
                            .map_err(sqlite_read_err("list_tasks trace decode"))?;
                        bucket.entry(tg_task_id).or_default().push(summary);
                    }
                }

                let items: Vec<crate::read::TaskGroup> = headers
                    .into_iter()
                    .map(|h| {
                        let traces = bucket.remove(&h.task_id).unwrap_or_default();
                        let task_class = crate::read::TaskClass::from_task_id(&h.task_id);
                        crate::read::TaskGroup {
                            task_id: h.task_id,
                            initial_observation: h.initial_observation,
                            task_class,
                            earliest_at: h.earliest_at,
                            latest_at: h.latest_at,
                            traces,
                        }
                    })
                    .collect();
                let next_cursor = if items.len() == limit_usize {
                    let last = &items[items.len() - 1];
                    Some(crate::read::TaskCursor::from_trailing(
                        last.earliest_at,
                        last.task_id.clone(),
                    ))
                } else {
                    None
                };
                Ok(crate::read::TaskListPage { items, next_cursor })
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn list_llm_calls(
        &self,
        filter: crate::read::LlmCallFilter,
        cursor: Option<crate::read::LlmCallCursor>,
        limit: i64,
    ) -> Result<crate::read::LlmCallListPage, crate::read::Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(crate::read::Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let (join_sql, where_sql, mut binds) = sqlite_llm_filter_sql(&filter)?;
        let cursor_clause = match &cursor {
            None => String::new(),
            Some(c) => {
                if c.version != "v1" {
                    return Err(crate::read::Error::InvalidCursor(format!(
                        "LlmCallCursor version {} unsupported; v1 only",
                        c.version
                    )));
                }
                binds.push(SqlValue::Text(c.last_ts.to_rfc3339()));
                let p_ts = binds.len();
                binds.push(SqlValue::Text(c.last_trace_id.clone()));
                let p_tid = binds.len();
                let ai = i64::from(c.last_attempt_index);
                binds.push(SqlValue::Integer(ai));
                let p_ai = binds.len();
                let prefix = if where_sql.is_empty() { "WHERE" } else { "AND" };
                format!(
                    "{prefix} (lc.ts, lc.trace_id, lc.attempt_index) < (?{p_ts}, ?{p_tid}, ?{p_ai})"
                )
            }
        };
        binds.push(SqlValue::Integer(limit));
        let p_limit = binds.len();
        let sql = format!(
            "SELECT lc.trace_id, lc.thought_id, lc.task_id, lc.parent_event_id, \
                    lc.parent_event_type, lc.parent_attempt_index, lc.attempt_index, \
                    lc.ts, lc.duration_ms, lc.handler_name, lc.service_name, lc.model, \
                    lc.base_url, lc.response_model, lc.prompt_tokens, lc.completion_tokens, \
                    lc.prompt_bytes, lc.completion_bytes, lc.cost_usd, lc.status, \
                    lc.error_class, lc.attempt_count, lc.retry_count, lc.prompt_hash, \
                    lc.prompt, lc.response_text \
             FROM trace_llm_calls lc {join_sql} {where_sql} {cursor_clause} \
             ORDER BY lc.ts DESC, lc.trace_id DESC, lc.attempt_index DESC \
             LIMIT ?{p_limit}"
        );
        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        tokio::task::spawn_blocking(
            move || -> Result<crate::read::LlmCallListPage, crate::read::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(sqlite_read_err("list_llm_calls prepare"))?;
                let items: Vec<TraceLlmCallRow> = stmt
                    .query_map(params_from_iter(binds.iter()), sqlite_row_to_llm_call_row)
                    .map_err(sqlite_read_err("list_llm_calls query"))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sqlite_read_err("list_llm_calls row"))?;
                let next_cursor = if items.len() == limit_usize {
                    let last = &items[items.len() - 1];
                    Some(crate::read::LlmCallCursor::from_trailing(
                        last.ts,
                        last.trace_id.clone(),
                        last.attempt_index,
                    ))
                } else {
                    None
                };
                Ok(crate::read::LlmCallListPage { items, next_cursor })
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn aggregate_llm_costs(
        &self,
        filter: crate::read::LlmCallFilter,
    ) -> Result<crate::read::LlmCostAggregate, crate::read::Error> {
        let (join_sql, where_sql, binds) = sqlite_llm_filter_sql(&filter)?;
        // by_agent / by_domain need the parent join even when the
        // filter didn't already force it.
        let join_for_agg = if join_sql.is_empty() {
            "JOIN trace_events e \
               ON e.trace_id = lc.trace_id AND e.event_id = lc.parent_event_id"
                .to_owned()
        } else {
            join_sql.clone()
        };
        let time_window = filter.time_window;
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<crate::read::LlmCostAggregate, crate::read::Error> {
                let conn = conn.blocking_lock();

                // Per-model rollup.
                let sql_model = format!(
                    "SELECT COALESCE(lc.model, '<unknown>') AS k, \
                            COUNT(*) AS call_count, \
                            COALESCE(SUM(lc.prompt_tokens), 0) AS prompt_tokens, \
                            COALESCE(SUM(lc.completion_tokens), 0) AS completion_tokens, \
                            COALESCE(SUM(lc.cost_usd), 0.0) AS cost_usd, \
                            COUNT(*) FILTER (WHERE lc.status != 'ok') AS error_count \
                     FROM trace_llm_calls lc {join_sql} {where_sql} GROUP BY k"
                );
                let mut by_model: std::collections::HashMap<String, crate::read::ModelCostStats> =
                    std::collections::HashMap::new();
                {
                    let mut stmt = conn
                        .prepare(&sql_model)
                        .map_err(sqlite_read_err("agg_llm_costs by_model prepare"))?;
                    let mut rows = stmt
                        .query(params_from_iter(binds.iter()))
                        .map_err(sqlite_read_err("agg_llm_costs by_model query"))?;
                    while let Some(row) = rows
                        .next()
                        .map_err(sqlite_read_err("agg_llm_costs by_model row"))?
                    {
                        let k: String = row.get("k").map_err(sqlite_read_err("by_model k"))?;
                        by_model.insert(
                            k.clone(),
                            crate::read::ModelCostStats {
                                model: k,
                                call_count: row
                                    .get("call_count")
                                    .map_err(sqlite_read_err("by_model call_count"))?,
                                prompt_tokens: row
                                    .get("prompt_tokens")
                                    .map_err(sqlite_read_err("by_model prompt_tokens"))?,
                                completion_tokens: row
                                    .get("completion_tokens")
                                    .map_err(sqlite_read_err("by_model completion_tokens"))?,
                                cost_usd: row
                                    .get("cost_usd")
                                    .map_err(sqlite_read_err("by_model cost_usd"))?,
                                error_count: row
                                    .get("error_count")
                                    .map_err(sqlite_read_err("by_model error_count"))?,
                            },
                        );
                    }
                }

                // Per-agent rollup.
                let sql_agent = format!(
                    "SELECT e.agent_id_hash AS k, MAX(e.agent_name) AS agent_name, \
                            COUNT(*) AS call_count, \
                            COALESCE(SUM(lc.prompt_tokens), 0) AS prompt_tokens, \
                            COALESCE(SUM(lc.completion_tokens), 0) AS completion_tokens, \
                            COALESCE(SUM(lc.cost_usd), 0.0) AS cost_usd \
                     FROM trace_llm_calls lc {join_for_agg} {where_sql} GROUP BY k"
                );
                let mut by_agent: std::collections::HashMap<String, crate::read::AgentCostStats> =
                    std::collections::HashMap::new();
                {
                    let mut stmt = conn
                        .prepare(&sql_agent)
                        .map_err(sqlite_read_err("agg_llm_costs by_agent prepare"))?;
                    let mut rows = stmt
                        .query(params_from_iter(binds.iter()))
                        .map_err(sqlite_read_err("agg_llm_costs by_agent query"))?;
                    while let Some(row) = rows
                        .next()
                        .map_err(sqlite_read_err("agg_llm_costs by_agent row"))?
                    {
                        let k: Option<String> =
                            row.get("k").map_err(sqlite_read_err("by_agent k"))?;
                        let Some(k) = k else { continue };
                        by_agent.insert(
                            k.clone(),
                            crate::read::AgentCostStats {
                                agent_id_hash: k,
                                agent_name: row
                                    .get("agent_name")
                                    .map_err(sqlite_read_err("by_agent agent_name"))?,
                                call_count: row
                                    .get("call_count")
                                    .map_err(sqlite_read_err("by_agent call_count"))?,
                                prompt_tokens: row
                                    .get("prompt_tokens")
                                    .map_err(sqlite_read_err("by_agent prompt_tokens"))?,
                                completion_tokens: row
                                    .get("completion_tokens")
                                    .map_err(sqlite_read_err("by_agent completion_tokens"))?,
                                cost_usd: row
                                    .get("cost_usd")
                                    .map_err(sqlite_read_err("by_agent cost_usd"))?,
                            },
                        );
                    }
                }

                // Per-domain rollup.
                let sql_domain = format!(
                    "SELECT COALESCE(e.deployment_domain, '<unknown>') AS k, \
                            COUNT(*) AS call_count, \
                            COALESCE(SUM(lc.cost_usd), 0.0) AS cost_usd \
                     FROM trace_llm_calls lc {join_for_agg} {where_sql} GROUP BY k"
                );
                let mut by_domain: std::collections::HashMap<String, crate::read::DomainCostStats> =
                    std::collections::HashMap::new();
                {
                    let mut stmt = conn
                        .prepare(&sql_domain)
                        .map_err(sqlite_read_err("agg_llm_costs by_domain prepare"))?;
                    let mut rows = stmt
                        .query(params_from_iter(binds.iter()))
                        .map_err(sqlite_read_err("agg_llm_costs by_domain query"))?;
                    while let Some(row) = rows
                        .next()
                        .map_err(sqlite_read_err("agg_llm_costs by_domain row"))?
                    {
                        let k: String = row.get("k").map_err(sqlite_read_err("by_domain k"))?;
                        by_domain.insert(
                            k.clone(),
                            crate::read::DomainCostStats {
                                deployment_domain: k,
                                call_count: row
                                    .get("call_count")
                                    .map_err(sqlite_read_err("by_domain call_count"))?,
                                cost_usd: row
                                    .get("cost_usd")
                                    .map_err(sqlite_read_err("by_domain cost_usd"))?,
                            },
                        );
                    }
                }

                // Window totals.
                let sql_totals = format!(
                    "SELECT COUNT(*) AS call_count, \
                            COALESCE(SUM(lc.prompt_tokens), 0) AS prompt_tokens, \
                            COALESCE(SUM(lc.completion_tokens), 0) AS completion_tokens, \
                            COALESCE(SUM(lc.cost_usd), 0.0) AS cost_usd, \
                            COUNT(*) FILTER (WHERE lc.status != 'ok') AS error_count \
                     FROM trace_llm_calls lc {join_sql} {where_sql}"
                );
                let totals = {
                    let mut stmt = conn
                        .prepare(&sql_totals)
                        .map_err(sqlite_read_err("agg_llm_costs totals prepare"))?;
                    stmt.query_row(params_from_iter(binds.iter()), |row| {
                        Ok(crate::read::TotalCostStats {
                            call_count: row.get("call_count")?,
                            prompt_tokens: row.get("prompt_tokens")?,
                            completion_tokens: row.get("completion_tokens")?,
                            cost_usd: row.get("cost_usd")?,
                            error_count: row.get("error_count")?,
                        })
                    })
                    .map_err(sqlite_read_err("agg_llm_costs totals"))?
                };

                Ok(crate::read::LlmCostAggregate {
                    time_window,
                    by_model,
                    by_agent,
                    by_domain,
                    totals,
                })
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn corpus_shape(
        &self,
        filter: crate::read::CorpusShapeFilter,
    ) -> Result<crate::read::CorpusShape, crate::read::Error> {
        let window = filter.time_window;
        let mut parts: Vec<String> = Vec::new();
        let mut binds: Vec<SqlValue> = Vec::new();
        binds.push(SqlValue::Text(window.since.to_rfc3339()));
        parts.push(format!("ts >= ?{}", binds.len()));
        binds.push(SqlValue::Text(window.until.to_rfc3339()));
        parts.push(format!("ts < ?{}", binds.len()));
        if let Some(h) = &filter.agent_id_hash {
            binds.push(SqlValue::Text(h.clone()));
            parts.push(format!("agent_id_hash = ?{}", binds.len()));
        }
        if let Some(n) = &filter.agent_name {
            binds.push(SqlValue::Text(n.clone()));
            parts.push(format!("agent_name = ?{}", binds.len()));
        }
        if let Some(d) = &filter.deployment_domain {
            binds.push(SqlValue::Text(d.clone()));
            parts.push(format!("deployment_domain = ?{}", binds.len()));
        }
        let where_sql = format!("WHERE {}", parts.join(" AND "));
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<crate::read::CorpusShape, crate::read::Error> {
                let conn = conn.blocking_lock();

                // Totals + by_task_class. One distinct row per trace.
                let sql_totals = format!(
                    "WITH traces AS ( \
                         SELECT trace_id, MAX(task_id) AS task_id \
                         FROM trace_events {where_sql} GROUP BY trace_id \
                     ) \
                     SELECT COUNT(*) AS total_traces, \
                            COUNT(*) FILTER ( \
                                WHERE task_id LIKE 'qa\\_%' ESCAPE '\\' \
                                   OR task_id LIKE 'qa-eval%') AS c_qa, \
                            COUNT(*) FILTER ( \
                                WHERE task_id LIKE 'real\\_user\\_discord\\_%' ESCAPE '\\') \
                                AS c_rud, \
                            COUNT(*) FILTER ( \
                                WHERE task_id LIKE 'real\\_user\\_cli\\_%' ESCAPE '\\') \
                                AS c_ruc, \
                            COUNT(*) FILTER ( \
                                WHERE task_id LIKE 'real\\_user\\_api\\_%' ESCAPE '\\') \
                                AS c_rua, \
                            COUNT(*) FILTER ( \
                                WHERE instr(task_id, 'wakeup') > 0 \
                                  AND task_id NOT LIKE 'real\\_user\\_%' ESCAPE '\\') \
                                AS c_wakeup, \
                            COUNT(*) FILTER ( \
                                WHERE task_id LIKE 'discord\\_%' ESCAPE '\\') AS c_discord, \
                            COUNT(*) FILTER ( \
                                WHERE task_id IS NOT NULL \
                                  AND task_id NOT LIKE 'qa\\_%' ESCAPE '\\' \
                                  AND task_id NOT LIKE 'qa-eval%' \
                                  AND task_id NOT LIKE 'discord\\_%' ESCAPE '\\' \
                                  AND task_id NOT LIKE 'real\\_user\\_discord\\_%' ESCAPE '\\' \
                                  AND task_id NOT LIKE 'real\\_user\\_cli\\_%' ESCAPE '\\' \
                                  AND task_id NOT LIKE 'real\\_user\\_api\\_%' ESCAPE '\\' \
                                  AND instr(task_id, 'wakeup') = 0) AS c_other \
                     FROM traces"
                );
                let (total_traces, by_task_class): (
                    i64,
                    std::collections::HashMap<crate::read::TaskClass, i64>,
                ) = {
                    let mut stmt = conn
                        .prepare(&sql_totals)
                        .map_err(sqlite_read_err("corpus_shape totals prepare"))?;
                    stmt.query_row(params_from_iter(binds.iter()), |row| {
                        let total: i64 = row.get("total_traces")?;
                        let mut map = std::collections::HashMap::new();
                        for (tc, col) in [
                            (crate::read::TaskClass::QaEval, "c_qa"),
                            (crate::read::TaskClass::RealUserDiscord, "c_rud"),
                            (crate::read::TaskClass::RealUserCli, "c_ruc"),
                            (crate::read::TaskClass::RealUserApi, "c_rua"),
                            (crate::read::TaskClass::WakeupRitual, "c_wakeup"),
                            (crate::read::TaskClass::Discord, "c_discord"),
                            (crate::read::TaskClass::Other, "c_other"),
                        ] {
                            let n: i64 = row.get(col)?;
                            if n > 0 {
                                map.insert(tc, n);
                            }
                        }
                        Ok((total, map))
                    })
                    .map_err(sqlite_read_err("corpus_shape totals"))?
                };

                // QA language + question-num breakdown. SQLite has no
                // regex-capture; extract in Rust from the task_id.
                let mut by_qa_language: std::collections::HashMap<String, i64> =
                    std::collections::HashMap::new();
                let mut by_qa_question_num: std::collections::HashMap<i32, i64> =
                    std::collections::HashMap::new();
                {
                    let sql_qa = format!(
                        "WITH traces AS ( \
                             SELECT trace_id, MAX(task_id) AS task_id \
                             FROM trace_events {where_sql} GROUP BY trace_id \
                         ) \
                         SELECT task_id FROM traces \
                         WHERE task_id LIKE 'qa\\_%' ESCAPE '\\' \
                            OR task_id LIKE 'qa-eval%'"
                    );
                    let mut stmt = conn
                        .prepare(&sql_qa)
                        .map_err(sqlite_read_err("corpus_shape qa prepare"))?;
                    let mut rows = stmt
                        .query(params_from_iter(binds.iter()))
                        .map_err(sqlite_read_err("corpus_shape qa query"))?;
                    while let Some(row) = rows
                        .next()
                        .map_err(sqlite_read_err("corpus_shape qa row"))?
                    {
                        let task_id: String = row
                            .get(0)
                            .map_err(sqlite_read_err("corpus_shape qa task_id"))?;
                        if let Some((lang, qnum)) = parse_qa_task_id(&task_id) {
                            *by_qa_language.entry(lang).or_insert(0) += 1;
                            if let Some(q) = qnum {
                                *by_qa_question_num.entry(q).or_insert(0) += 1;
                            }
                        }
                    }
                }

                // by_agent_name + by_agent_version + by_deployment_region.
                let sql_agent = format!(
                    "WITH traces AS ( \
                         SELECT trace_id, MAX(agent_name) AS agent_name, \
                                MAX(agent_template) AS agent_template, \
                                MAX(deployment_region) AS deployment_region \
                         FROM trace_events {where_sql} GROUP BY trace_id \
                     ) \
                     SELECT 'an' AS k, agent_name AS v, COUNT(*) AS n FROM traces \
                         WHERE agent_name IS NOT NULL GROUP BY agent_name \
                     UNION ALL \
                     SELECT 'av', agent_template, COUNT(*) FROM traces \
                         WHERE agent_template IS NOT NULL GROUP BY agent_template \
                     UNION ALL \
                     SELECT 'dr', deployment_region, COUNT(*) FROM traces \
                         WHERE deployment_region IS NOT NULL GROUP BY deployment_region"
                );
                let mut by_agent_name: std::collections::HashMap<String, i64> =
                    std::collections::HashMap::new();
                let mut by_agent_version: std::collections::HashMap<String, i64> =
                    std::collections::HashMap::new();
                let mut by_deployment_region: std::collections::HashMap<String, i64> =
                    std::collections::HashMap::new();
                {
                    let mut stmt = conn
                        .prepare(&sql_agent)
                        .map_err(sqlite_read_err("corpus_shape agent prepare"))?;
                    let mut rows = stmt
                        .query(params_from_iter(binds.iter()))
                        .map_err(sqlite_read_err("corpus_shape agent query"))?;
                    while let Some(row) = rows
                        .next()
                        .map_err(sqlite_read_err("corpus_shape agent row"))?
                    {
                        let k: String = row.get("k").map_err(sqlite_read_err("corpus_shape k"))?;
                        let v: String = row.get("v").map_err(sqlite_read_err("corpus_shape v"))?;
                        let n: i64 = row.get("n").map_err(sqlite_read_err("corpus_shape n"))?;
                        match k.as_str() {
                            "an" => {
                                by_agent_name.insert(v, n);
                            }
                            "av" => {
                                by_agent_version.insert(v, n);
                            }
                            "dr" => {
                                by_deployment_region.insert(v, n);
                            }
                            _ => {}
                        }
                    }
                }

                // by_primary_model: the model with the most LLM calls
                // per trace, ties broken alphabetically.
                let sql_model = format!(
                    "WITH traces AS ( \
                         SELECT DISTINCT trace_id FROM trace_events {where_sql} \
                     ), \
                     tm AS ( \
                         SELECT lc.trace_id, lc.model, COUNT(*) AS n_calls \
                         FROM trace_llm_calls lc \
                         JOIN traces t ON lc.trace_id = t.trace_id \
                         WHERE lc.model IS NOT NULL \
                         GROUP BY lc.trace_id, lc.model \
                     ), \
                     ranked AS ( \
                         SELECT trace_id, model, \
                                ROW_NUMBER() OVER ( \
                                    PARTITION BY trace_id \
                                    ORDER BY n_calls DESC, model ASC) AS rn \
                         FROM tm \
                     ) \
                     SELECT model AS k, COUNT(*) AS n FROM ranked \
                     WHERE rn = 1 GROUP BY model"
                );
                let mut by_primary_model: std::collections::HashMap<String, i64> =
                    std::collections::HashMap::new();
                {
                    let mut stmt = conn
                        .prepare(&sql_model)
                        .map_err(sqlite_read_err("corpus_shape model prepare"))?;
                    let mut rows = stmt
                        .query(params_from_iter(binds.iter()))
                        .map_err(sqlite_read_err("corpus_shape model query"))?;
                    while let Some(row) = rows
                        .next()
                        .map_err(sqlite_read_err("corpus_shape model row"))?
                    {
                        let k: String = row
                            .get("k")
                            .map_err(sqlite_read_err("corpus_shape model k"))?;
                        let n: i64 = row
                            .get("n")
                            .map_err(sqlite_read_err("corpus_shape model n"))?;
                        by_primary_model.insert(k, n);
                    }
                }

                Ok(crate::read::CorpusShape {
                    window,
                    total_traces,
                    by_task_class,
                    by_qa_language,
                    by_qa_question_num,
                    by_agent_name,
                    by_agent_version,
                    by_primary_model,
                    by_deployment_region,
                    stationarity_z_score: None,
                })
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn aggregate_scrub_stats(
        &self,
        window: crate::read::TimeWindow,
    ) -> Result<crate::read::ScrubAggregate, crate::read::Error> {
        let since = window.since.to_rfc3339();
        let until = window.until.to_rfc3339();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<crate::read::ScrubAggregate, crate::read::Error> {
                let conn = conn.blocking_lock();
                // Per-trace collapse: MAX(pii_scrubbed) is BOOL_OR;
                // MAX(trace_level) is the §H reference's MAX().
                let sql = "WITH traces AS ( \
                               SELECT trace_id, MAX(pii_scrubbed) AS scrubbed, \
                                      MAX(trace_level) AS trace_level \
                               FROM trace_events WHERE ts >= ?1 AND ts < ?2 \
                               GROUP BY trace_id \
                           ) \
                           SELECT COUNT(*) FILTER (WHERE scrubbed = 1) AS total_scrubbed, \
                                  COUNT(*) FILTER ( \
                                      WHERE scrubbed = 1 AND trace_level = 'generic') \
                                      AS c_generic, \
                                  COUNT(*) FILTER ( \
                                      WHERE scrubbed = 1 AND trace_level = 'detailed') \
                                      AS c_detailed, \
                                  COUNT(*) FILTER ( \
                                      WHERE scrubbed = 1 AND trace_level = 'full_traces') \
                                      AS c_full \
                           FROM traces";
                let (envelopes_scrubbed, by_trace_level) = {
                    let mut stmt = conn
                        .prepare(sql)
                        .map_err(sqlite_read_err("aggregate_scrub_stats prepare"))?;
                    stmt.query_row([&since, &until], |row| {
                        let total: i64 = row.get("total_scrubbed")?;
                        let mut map = std::collections::HashMap::new();
                        for (lvl, col) in [
                            (crate::schema::TraceLevel::Generic, "c_generic"),
                            (crate::schema::TraceLevel::Detailed, "c_detailed"),
                            (crate::schema::TraceLevel::FullTraces, "c_full"),
                        ] {
                            let n: i64 = row.get(col)?;
                            if n > 0 {
                                map.insert(lvl, n);
                            }
                        }
                        Ok((total, map))
                    })
                    .map_err(sqlite_read_err("aggregate_scrub_stats query"))?
                };
                Ok(crate::read::ScrubAggregate {
                    window,
                    envelopes_scrubbed,
                    // Same v0.6.0-pipeline gating as the Postgres impl.
                    fields_scrubbed_total: 0,
                    by_entity_type: std::collections::HashMap::new(),
                    by_trace_level,
                })
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn list_federation_keys(
        &self,
        filter: crate::read::FederationKeyFilter,
        cursor: Option<crate::read::FederationKeyCursor>,
        limit: i64,
    ) -> Result<crate::read::FederationKeyListPage, crate::read::Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(crate::read::Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let mut parts: Vec<String> = Vec::new();
        let mut binds: Vec<SqlValue> = Vec::new();
        if let Some(h) = &filter.agent_id_hash {
            binds.push(SqlValue::Text(h.clone()));
            parts.push(format!(
                "(identity_type = 'agent' AND identity_ref = ?{})",
                binds.len()
            ));
        }
        if let Some(a) = &filter.algorithm {
            binds.push(SqlValue::Text(a.clone()));
            parts.push(format!("algorithm = ?{}", binds.len()));
        }
        if let Some(revoked) = filter.revoked {
            let op = if revoked { "EXISTS" } else { "NOT EXISTS" };
            parts.push(format!(
                "{op} (SELECT 1 FROM federation_revocations r \
                     WHERE r.revoked_key_id = federation_keys.key_id)"
            ));
        }
        if let Some(pqc) = filter.pqc_completed {
            parts.push(if pqc {
                "pqc_completed_at IS NOT NULL".to_owned()
            } else {
                "pqc_completed_at IS NULL".to_owned()
            });
        }
        if let Some(c) = &cursor {
            if c.version != "v1" {
                return Err(crate::read::Error::InvalidCursor(format!(
                    "FederationKeyCursor version {} unsupported; v1 only",
                    c.version
                )));
            }
            binds.push(SqlValue::Text(c.last_valid_from.to_rfc3339()));
            let p_at = binds.len();
            binds.push(SqlValue::Text(c.last_key_id.clone()));
            let p_id = binds.len();
            parts.push(format!("(valid_from, key_id) < (?{p_at}, ?{p_id})"));
        }
        let where_sql = if parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", parts.join(" AND "))
        };
        binds.push(SqlValue::Integer(limit));
        let p_limit = binds.len();
        let sql = format!(
            "SELECT key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                    identity_type, identity_ref, valid_from, valid_until, \
                    registration_envelope, original_content_hash, \
                    scrub_signature_classical, scrub_signature_pqc, scrub_key_id, \
                    scrub_timestamp, pqc_completed_at, persist_row_hash, roles \
             FROM federation_keys {where_sql} \
             ORDER BY valid_from DESC, key_id DESC LIMIT ?{p_limit}"
        );
        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        tokio::task::spawn_blocking(
            move || -> Result<crate::read::FederationKeyListPage, crate::read::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(sqlite_read_err("list_federation_keys prepare"))?;
                let items: Vec<crate::federation::KeyRecord> = stmt
                    .query_map(params_from_iter(binds.iter()), sqlite_row_to_key_record)
                    .map_err(sqlite_read_err("list_federation_keys query"))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sqlite_read_err("list_federation_keys row"))?;
                let next_cursor = if items.len() == limit_usize {
                    let last = &items[items.len() - 1];
                    Some(crate::read::FederationKeyCursor::from_trailing(
                        last.valid_from,
                        last.key_id.clone(),
                    ))
                } else {
                    None
                };
                Ok(crate::read::FederationKeyListPage { items, next_cursor })
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn list_attestations(
        &self,
        filter: crate::read::AttestationFilter,
        cursor: Option<crate::read::AttestationCursor>,
        limit: i64,
    ) -> Result<crate::read::AttestationListPage, crate::read::Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(crate::read::Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let mut parts: Vec<String> = Vec::new();
        let mut binds: Vec<SqlValue> = Vec::new();
        if let Some(k) = &filter.attesting_key_id {
            binds.push(SqlValue::Text(k.clone()));
            parts.push(format!("attesting_key_id = ?{}", binds.len()));
        }
        if let Some(k) = &filter.attested_key_id {
            binds.push(SqlValue::Text(k.clone()));
            parts.push(format!("attested_key_id = ?{}", binds.len()));
        }
        if let Some(t) = &filter.attestation_type {
            binds.push(SqlValue::Text(t.clone()));
            parts.push(format!("attestation_type = ?{}", binds.len()));
        }
        if let Some(pqc) = filter.pqc_completed {
            parts.push(if pqc {
                "pqc_completed_at IS NOT NULL".to_owned()
            } else {
                "pqc_completed_at IS NULL".to_owned()
            });
        }
        if let Some(c) = &cursor {
            if c.version != "v1" {
                return Err(crate::read::Error::InvalidCursor(format!(
                    "AttestationCursor version {} unsupported; v1 only",
                    c.version
                )));
            }
            binds.push(SqlValue::Text(c.last_asserted_at.to_rfc3339()));
            let p_at = binds.len();
            binds.push(SqlValue::Text(c.last_attestation_id.clone()));
            let p_id = binds.len();
            parts.push(format!(
                "(asserted_at, attestation_id) < (?{p_at}, ?{p_id})"
            ));
        }
        let where_sql = if parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", parts.join(" AND "))
        };
        binds.push(SqlValue::Integer(limit));
        let p_limit = binds.len();
        let sql = format!(
            "SELECT attestation_id, attesting_key_id, attested_key_id, \
                    attestation_type, weight, asserted_at, expires_at, \
                    attestation_envelope, original_content_hash, \
                    scrub_signature_classical, scrub_signature_pqc, scrub_key_id, \
                    scrub_timestamp, pqc_completed_at, persist_row_hash \
             FROM federation_attestations {where_sql} \
             ORDER BY asserted_at DESC, attestation_id DESC LIMIT ?{p_limit}"
        );
        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        tokio::task::spawn_blocking(
            move || -> Result<crate::read::AttestationListPage, crate::read::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(sqlite_read_err("list_attestations prepare"))?;
                let items: Vec<crate::federation::Attestation> = stmt
                    .query_map(params_from_iter(binds.iter()), sqlite_row_to_attestation)
                    .map_err(sqlite_read_err("list_attestations query"))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sqlite_read_err("list_attestations row"))?;
                let next_cursor = if items.len() == limit_usize {
                    let last = &items[items.len() - 1];
                    Some(crate::read::AttestationCursor::from_trailing(
                        last.asserted_at,
                        last.attestation_id.clone(),
                    ))
                } else {
                    None
                };
                Ok(crate::read::AttestationListPage { items, next_cursor })
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn list_revocations(
        &self,
        filter: crate::read::RevocationFilter,
        cursor: Option<crate::read::RevocationCursor>,
        limit: i64,
    ) -> Result<crate::read::RevocationListPage, crate::read::Error> {
        if !(1..=10_000).contains(&limit) {
            return Err(crate::read::Error::InvalidArgument(format!(
                "limit must be in [1, 10000], got {limit}"
            )));
        }
        let mut parts: Vec<String> = Vec::new();
        let mut binds: Vec<SqlValue> = Vec::new();
        if let Some(k) = &filter.revoked_key_id {
            binds.push(SqlValue::Text(k.clone()));
            parts.push(format!("revoked_key_id = ?{}", binds.len()));
        }
        if let Some(k) = &filter.revoking_key_id {
            binds.push(SqlValue::Text(k.clone()));
            parts.push(format!("revoking_key_id = ?{}", binds.len()));
        }
        if let Some(pqc) = filter.pqc_completed {
            parts.push(if pqc {
                "pqc_completed_at IS NOT NULL".to_owned()
            } else {
                "pqc_completed_at IS NULL".to_owned()
            });
        }
        if let Some(c) = &cursor {
            if c.version != "v1" {
                return Err(crate::read::Error::InvalidCursor(format!(
                    "RevocationCursor version {} unsupported; v1 only",
                    c.version
                )));
            }
            binds.push(SqlValue::Text(c.last_revoked_at.to_rfc3339()));
            let p_at = binds.len();
            binds.push(SqlValue::Text(c.last_revocation_id.clone()));
            let p_id = binds.len();
            parts.push(format!("(revoked_at, revocation_id) < (?{p_at}, ?{p_id})"));
        }
        let where_sql = if parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", parts.join(" AND "))
        };
        binds.push(SqlValue::Integer(limit));
        let p_limit = binds.len();
        let sql = format!(
            "SELECT revocation_id, revoked_key_id, revoking_key_id, reason, \
                    revoked_at, effective_at, revocation_envelope, \
                    original_content_hash, scrub_signature_classical, \
                    scrub_signature_pqc, scrub_key_id, scrub_timestamp, \
                    pqc_completed_at, persist_row_hash \
             FROM federation_revocations {where_sql} \
             ORDER BY revoked_at DESC, revocation_id DESC LIMIT ?{p_limit}"
        );
        let conn = self.conn.clone();
        let limit_usize = limit as usize;
        tokio::task::spawn_blocking(
            move || -> Result<crate::read::RevocationListPage, crate::read::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(sqlite_read_err("list_revocations prepare"))?;
                let items: Vec<crate::federation::Revocation> = stmt
                    .query_map(params_from_iter(binds.iter()), sqlite_row_to_revocation)
                    .map_err(sqlite_read_err("list_revocations query"))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sqlite_read_err("list_revocations row"))?;
                let next_cursor = if items.len() == limit_usize {
                    let last = &items[items.len() - 1];
                    Some(crate::read::RevocationCursor::from_trailing(
                        last.revoked_at,
                        last.revocation_id.clone(),
                    ))
                } else {
                    None
                };
                Ok(crate::read::RevocationListPage { items, next_cursor })
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn cross_agent_divergence(
        &self,
        deployment_domain: &str,
        window: crate::read::TimeWindow,
        metric: crate::read::DeviationMetric,
    ) -> Result<Vec<crate::read::DivergenceRow>, crate::read::Error> {
        use crate::read::DeviationMetric;
        let domain = deployment_domain.to_owned();
        let since = window.since.to_rfc3339();
        let until = window.until.to_rfc3339();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::read::DivergenceRow>, crate::read::Error> {
                let conn = conn.blocking_lock();
                // Per-agent (mean, sample_count) pairs. SQLite has no
                // STDDEV; the domain mean+stddev of the per-agent means
                // is computed in Rust.
                struct PerAgent {
                    agent_id_hash: String,
                    agent_name: Option<String>,
                    mean: f64,
                    sample_count: i64,
                }
                let per_agent: Vec<PerAgent> =
                    if matches!(metric, DeviationMetric::ConscienceOverrideRate) {
                        // Per-trace MAX collapses recursive CONSCIENCE_RESULT
                        // retries; per-agent rate over distinct traces.
                        let sql = "WITH per_trace AS ( \
                                       SELECT agent_id_hash, MIN(agent_name) AS agent_name, \
                                              trace_id, \
                                              MAX(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
                                                  AND json_extract( \
                                                      payload, '$.action_was_overridden') = 1 \
                                                  THEN 1 ELSE 0 END) AS was_overridden \
                                       FROM trace_events \
                                       WHERE deployment_domain = ?1 \
                                             AND ts >= ?2 AND ts < ?3 \
                                       GROUP BY agent_id_hash, trace_id \
                                   ) \
                                   SELECT agent_id_hash, MIN(agent_name) AS agent_name, \
                                          COUNT(*) AS sample_count, \
                                          CAST(SUM(was_overridden) AS REAL) \
                                            / COUNT(*) AS mean \
                                   FROM per_trace GROUP BY agent_id_hash \
                                   HAVING COUNT(*) > 0";
                        let mut stmt = conn
                            .prepare(sql)
                            .map_err(sqlite_read_err("cross_agent_divergence override prepare"))?;
                        let collected = stmt
                            .query_map([&domain, &since, &until], |row| {
                                Ok(PerAgent {
                                    agent_id_hash: row.get("agent_id_hash")?,
                                    agent_name: row.get("agent_name")?,
                                    mean: row.get("mean")?,
                                    sample_count: row.get("sample_count")?,
                                })
                            })
                            .map_err(sqlite_read_err("cross_agent_divergence override query"))?
                            .collect::<Result<Vec<_>, _>>();
                        collected.map_err(sqlite_read_err("cross_agent_divergence override row"))?
                    } else {
                        let (event_type_filter, field): (&str, &str) = match metric {
                            DeviationMetric::CsdmaPlausibility => {
                                ("DMA_RESULTS", "csdma_plausibility_score")
                            }
                            DeviationMetric::DsdmaDomainAlignment => {
                                ("DMA_RESULTS", "dsdma_domain_alignment")
                            }
                            DeviationMetric::IdmaKEff => ("IDMA_RESULT", "idma_k_eff"),
                            DeviationMetric::IdmaCorrelationRisk => {
                                ("IDMA_RESULT", "idma_correlation_risk")
                            }
                            DeviationMetric::ConscienceOverrideRate => unreachable!(),
                        };
                        let sql = format!(
                            "SELECT agent_id_hash, MIN(agent_name) AS agent_name, \
                                    AVG(json_extract(payload, '$.{field}')) AS mean, \
                                    COUNT(*) AS sample_count \
                             FROM trace_events \
                             WHERE deployment_domain = ?1 AND ts >= ?2 AND ts < ?3 \
                                   AND event_type = '{event_type_filter}' \
                                   AND json_extract(payload, '$.{field}') IS NOT NULL \
                             GROUP BY agent_id_hash HAVING COUNT(*) > 0"
                        );
                        let mut stmt = conn
                            .prepare(&sql)
                            .map_err(sqlite_read_err("cross_agent_divergence prepare"))?;
                        let collected = stmt
                            .query_map([&domain, &since, &until], |row| {
                                Ok(PerAgent {
                                    agent_id_hash: row.get("agent_id_hash")?,
                                    agent_name: row.get("agent_name")?,
                                    mean: row.get::<_, Option<f64>>("mean")?.unwrap_or(0.0),
                                    sample_count: row.get("sample_count")?,
                                })
                            })
                            .map_err(sqlite_read_err("cross_agent_divergence query"))?
                            .collect::<Result<Vec<_>, _>>();
                        collected.map_err(sqlite_read_err("cross_agent_divergence row"))?
                    };

                // Domain mean + sample stddev of the per-agent means.
                let n = per_agent.len() as f64;
                let (domain_mean, domain_std) = if per_agent.len() >= 2 {
                    let m = per_agent.iter().map(|a| a.mean).sum::<f64>() / n;
                    let var =
                        per_agent.iter().map(|a| (a.mean - m).powi(2)).sum::<f64>() / (n - 1.0);
                    (m, var.sqrt())
                } else if per_agent.len() == 1 {
                    (per_agent[0].mean, 0.0)
                } else {
                    (0.0, 0.0)
                };

                let mut out: Vec<crate::read::DivergenceRow> = per_agent
                    .into_iter()
                    .map(|a| {
                        let z = if domain_std > 0.0 {
                            (a.mean - domain_mean) / domain_std
                        } else {
                            0.0
                        };
                        crate::read::DivergenceRow {
                            agent_id_hash: a.agent_id_hash,
                            agent_name: a.agent_name,
                            z_score: z,
                            deviation_metric: metric,
                            sample_count: a.sample_count,
                        }
                    })
                    .collect();
                // Most-divergent first; agent_id_hash ASC tiebreak.
                out.sort_by(|a, b| {
                    b.z_score
                        .abs()
                        .partial_cmp(&a.z_score.abs())
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.agent_id_hash.cmp(&b.agent_id_hash))
                });
                Ok(out)
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn temporal_drift(
        &self,
        agent_id_hash: &str,
        baseline: crate::read::TimeWindow,
        comparison: crate::read::TimeWindow,
    ) -> Result<Vec<crate::read::TemporalDriftRow>, crate::read::Error> {
        use crate::read::DeviationMetric;
        let agent = agent_id_hash.to_owned();
        let b_since = baseline.since.to_rfc3339();
        let b_until = baseline.until.to_rfc3339();
        let c_since = comparison.since.to_rfc3339();
        let c_until = comparison.until.to_rfc3339();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::read::TemporalDriftRow>, crate::read::Error> {
                let conn = conn.blocking_lock();
                let metrics = [
                    (
                        DeviationMetric::CsdmaPlausibility,
                        "DMA_RESULTS",
                        "csdma_plausibility_score",
                    ),
                    (
                        DeviationMetric::DsdmaDomainAlignment,
                        "DMA_RESULTS",
                        "dsdma_domain_alignment",
                    ),
                    (DeviationMetric::IdmaKEff, "IDMA_RESULT", "idma_k_eff"),
                    (
                        DeviationMetric::IdmaCorrelationRisk,
                        "IDMA_RESULT",
                        "idma_correlation_risk",
                    ),
                ];
                let mut out = Vec::new();
                for (metric, et, field) in metrics {
                    // Pull raw values for each window; compute mean +
                    // sample variance in Rust (no SQLite VAR_SAMP).
                    let sql = format!(
                        "SELECT \
                           CASE WHEN ts >= ?2 AND ts < ?3 THEN 0 ELSE 1 END AS win, \
                           json_extract(payload, '$.{field}') AS v \
                         FROM trace_events \
                         WHERE agent_id_hash = ?1 AND event_type = '{et}' \
                               AND json_extract(payload, '$.{field}') IS NOT NULL \
                               AND ((ts >= ?2 AND ts < ?3) OR (ts >= ?4 AND ts < ?5))"
                    );
                    let mut base: Vec<f64> = Vec::new();
                    let mut comp: Vec<f64> = Vec::new();
                    {
                        let mut stmt = conn
                            .prepare(&sql)
                            .map_err(sqlite_read_err("temporal_drift prepare"))?;
                        let mut rows = stmt
                            .query([&agent, &b_since, &b_until, &c_since, &c_until])
                            .map_err(sqlite_read_err("temporal_drift query"))?;
                        while let Some(row) =
                            rows.next().map_err(sqlite_read_err("temporal_drift row"))?
                        {
                            let win: i64 = row
                                .get("win")
                                .map_err(sqlite_read_err("temporal_drift win"))?;
                            let v: f64 =
                                row.get("v").map_err(sqlite_read_err("temporal_drift v"))?;
                            if win == 0 {
                                base.push(v);
                            } else {
                                comp.push(v);
                            }
                        }
                    }
                    if base.is_empty() || comp.is_empty() {
                        continue;
                    }
                    let (bm, bv) = mean_and_sample_var(&base);
                    let (cm, cv) = mean_and_sample_var(&comp);
                    let pooled_se = ((bv / (base.len() as f64).max(1.0))
                        + (cv / (comp.len() as f64).max(1.0)))
                    .sqrt();
                    let significance = if pooled_se > 0.0 {
                        (cm - bm) / pooled_se
                    } else {
                        0.0
                    };
                    let variance_ratio = if bv > 0.0 { cv / bv } else { 0.0 };
                    out.push(crate::read::TemporalDriftRow {
                        deviation_metric: metric,
                        baseline_window: baseline,
                        comparison_window: comparison,
                        mean_shift: cm - bm,
                        variance_ratio,
                        significance,
                    });
                }
                Ok(out)
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn hash_chain_gaps(
        &self,
        agent_id_hash: &str,
        window: crate::read::TimeWindow,
    ) -> Result<Vec<crate::read::HashChainGap>, crate::read::Error> {
        let agent = agent_id_hash.to_owned();
        let since = window.since.to_rfc3339();
        let until = window.until.to_rfc3339();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::read::HashChainGap>, crate::read::Error> {
                let conn = conn.blocking_lock();
                // LAG window over audit_sequence_number — SQLite
                // supports window functions since 3.25.
                let sql = "WITH ordered AS ( \
                               SELECT audit_sequence_number AS seq, ts, \
                                      LAG(audit_sequence_number) OVER w AS prev_seq, \
                                      LAG(ts) OVER w AS prev_ts \
                               FROM trace_events \
                               WHERE agent_id_hash = ?1 AND ts >= ?2 AND ts < ?3 \
                                     AND audit_sequence_number IS NOT NULL \
                               WINDOW w AS (ORDER BY audit_sequence_number) \
                           ) \
                           SELECT prev_seq, seq, prev_ts, ts FROM ordered \
                           WHERE prev_seq IS NOT NULL AND seq > prev_seq + 1 \
                           ORDER BY seq ASC";
                let mut stmt = conn
                    .prepare(sql)
                    .map_err(sqlite_read_err("hash_chain_gaps prepare"))?;
                let agent_for_row = agent.clone();
                let rows = stmt
                    .query_map([&agent, &since, &until], |row| {
                        let prev_ts: String = row.get("prev_ts")?;
                        let ts: String = row.get("ts")?;
                        Ok(crate::read::HashChainGap {
                            agent_id_hash: agent_for_row.clone(),
                            gap_start_seq: row.get("prev_seq")?,
                            gap_end_seq: row.get("seq")?,
                            gap_start_ts: parse_rfc3339(&prev_ts),
                            gap_end_ts: parse_rfc3339(&ts),
                        })
                    })
                    .map_err(sqlite_read_err("hash_chain_gaps query"))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sqlite_read_err("hash_chain_gaps row"))?;
                Ok(rows)
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn conscience_override_rates(
        &self,
        deployment_domain: &str,
        window: crate::read::TimeWindow,
    ) -> Result<Vec<crate::read::OverrideRateRow>, crate::read::Error> {
        let domain = deployment_domain.to_owned();
        let since = window.since.to_rfc3339();
        let until = window.until.to_rfc3339();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::read::OverrideRateRow>, crate::read::Error> {
                let conn = conn.blocking_lock();
                // Per-trace MAX collapse → per-agent counts. Domain
                // average computed in Rust from the per-agent rows.
                let sql = "WITH per_trace AS ( \
                               SELECT agent_id_hash, MIN(agent_name) AS agent_name, \
                                      MIN(deployment_domain) AS deployment_domain, \
                                      trace_id, \
                                      MAX(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
                                          AND json_extract( \
                                              payload, '$.action_was_overridden') = 1 \
                                          THEN 1 ELSE 0 END) AS was_overridden \
                               FROM trace_events \
                               WHERE deployment_domain = ?1 AND ts >= ?2 AND ts < ?3 \
                               GROUP BY agent_id_hash, trace_id \
                           ) \
                           SELECT agent_id_hash, MIN(agent_name) AS agent_name, \
                                  MIN(deployment_domain) AS deployment_domain, \
                                  SUM(was_overridden) AS override_count, \
                                  COUNT(*) AS trace_count \
                           FROM per_trace GROUP BY agent_id_hash";
                struct Raw {
                    agent_id_hash: String,
                    agent_name: Option<String>,
                    deployment_domain: Option<String>,
                    override_count: i64,
                    trace_count: i64,
                }
                let raws: Vec<Raw> = {
                    let mut stmt = conn
                        .prepare(sql)
                        .map_err(sqlite_read_err("conscience_override_rates prepare"))?;
                    let collected = stmt
                        .query_map([&domain, &since, &until], |row| {
                            Ok(Raw {
                                agent_id_hash: row.get("agent_id_hash")?,
                                agent_name: row.get("agent_name")?,
                                deployment_domain: row.get("deployment_domain")?,
                                override_count: row.get("override_count")?,
                                trace_count: row.get("trace_count")?,
                            })
                        })
                        .map_err(sqlite_read_err("conscience_override_rates query"))?
                        .collect::<Result<Vec<_>, _>>();
                    collected.map_err(sqlite_read_err("conscience_override_rates row"))?
                };
                // domain_avg_rate = SUM(overrides) / SUM(traces) — the
                // call-weighted reference (matches the Postgres CTE).
                let total_over: i64 = raws.iter().map(|r| r.override_count).sum();
                let total_trace: i64 = raws.iter().map(|r| r.trace_count).sum();
                let domain_avg_rate = if total_trace > 0 {
                    total_over as f64 / total_trace as f64
                } else {
                    0.0
                };
                let mut out: Vec<crate::read::OverrideRateRow> = raws
                    .into_iter()
                    .map(|r| {
                        let override_rate = if r.trace_count > 0 {
                            r.override_count as f64 / r.trace_count as f64
                        } else {
                            0.0
                        };
                        let multiple = if domain_avg_rate > 0.0 {
                            override_rate / domain_avg_rate
                        } else {
                            0.0
                        };
                        crate::read::OverrideRateRow {
                            agent_id_hash: r.agent_id_hash,
                            agent_name: r.agent_name,
                            deployment_domain: r.deployment_domain,
                            override_count: r.override_count,
                            trace_count: r.trace_count,
                            override_rate,
                            domain_avg_rate,
                            multiple_of_domain_avg: multiple,
                        }
                    })
                    .collect();
                out.sort_by(|a, b| {
                    b.override_rate
                        .partial_cmp(&a.override_rate)
                        .unwrap_or(std::cmp::Ordering::Equal)
                        .then_with(|| a.agent_id_hash.cmp(&b.agent_id_hash))
                });
                Ok(out)
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn aggregate_scoring_factors(
        &self,
        agent_id_hash: &str,
        window: crate::read::TimeWindow,
        baseline_window: Option<crate::read::TimeWindow>,
    ) -> Result<crate::read::ScoringFactorAggregate, crate::read::Error> {
        let agent = agent_id_hash.to_owned();
        let since = window.since.to_rfc3339();
        let until = window.until.to_rfc3339();
        let window_secs = (window.until - window.since).num_seconds().max(1);
        let bucket_secs = (window_secs / 24).max(60);
        let conn = self.conn.clone();
        let agg = tokio::task::spawn_blocking(
            move || -> Result<crate::read::ScoringFactorAggregate, crate::read::Error> {
                let conn = conn.blocking_lock();

                // Main per-trace collapse + window-wide counts.
                let main_sql = "WITH per_trace AS ( \
                       SELECT trace_id, MIN(agent_name) AS agent_name, \
                              MAX(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
                                  AND json_extract(payload, '$.action_was_overridden') = 1 \
                                  THEN 1 ELSE 0 END) AS was_overridden, \
                              MAX(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
                                  AND json_extract(payload, '$.conscience_passed') = 0 \
                                  THEN 1 ELSE 0 END) AS conscience_failed, \
                              MAX(CASE WHEN event_type = 'ACTION_RESULT' \
                                  AND json_extract(payload, '$.success') = 1 \
                                  THEN 1 ELSE 0 END) AS action_succeeded, \
                              MAX(CASE WHEN audit_sequence_number IS NOT NULL \
                                  THEN 1 ELSE 0 END) AS has_audit_seq, \
                              MAX(CASE WHEN audit_signature IS NOT NULL \
                                  THEN 1 ELSE 0 END) AS has_audit_sig \
                       FROM trace_events \
                       WHERE agent_id_hash = ?1 AND ts >= ?2 AND ts < ?3 \
                       GROUP BY trace_id \
                   ) \
                   SELECT COUNT(*) AS trace_count, \
                          MAX(COUNT(DISTINCT agent_name) - 1, 0) AS identity_changes, \
                          COALESCE(SUM(was_overridden), 0) AS conscience_overrides, \
                          COALESCE(SUM(has_audit_seq), 0) AS audit_chain_total, \
                          COALESCE(SUM(has_audit_sig), 0) AS audit_signed_total, \
                          COALESCE(SUM(CASE WHEN conscience_failed = 1 \
                              AND action_succeeded = 1 THEN 1 ELSE 0 END), 0) \
                              AS unsafe_action_count \
                   FROM per_trace";
                struct Main {
                    trace_count: i64,
                    identity_changes: i64,
                    conscience_overrides: i64,
                    audit_chain_total: i64,
                    audit_signed_total: i64,
                    unsafe_action_count: i64,
                }
                let main = {
                    let mut stmt = conn
                        .prepare(main_sql)
                        .map_err(sqlite_read_err("aggregate_scoring_factors main prepare"))?;
                    stmt.query_row([&agent, &since, &until], |row| {
                        Ok(Main {
                            trace_count: row.get("trace_count")?,
                            identity_changes: row.get("identity_changes")?,
                            conscience_overrides: row.get("conscience_overrides")?,
                            audit_chain_total: row.get("audit_chain_total")?,
                            audit_signed_total: row.get("audit_signed_total")?,
                            unsafe_action_count: row.get("unsafe_action_count")?,
                        })
                    })
                    .map_err(sqlite_read_err("aggregate_scoring_factors main"))?
                };
                let unsafe_action_rate = if main.trace_count > 0 {
                    main.unsafe_action_count as f64 / main.trace_count as f64
                } else {
                    0.0
                };

                // Audit-chain gap count via LAG window.
                let gaps_sql = "WITH ordered AS ( \
                                    SELECT audit_sequence_number AS seq, \
                                           LAG(audit_sequence_number) OVER w AS prev_seq \
                                    FROM trace_events \
                                    WHERE agent_id_hash = ?1 AND ts >= ?2 AND ts < ?3 \
                                          AND audit_sequence_number IS NOT NULL \
                                    WINDOW w AS (ORDER BY audit_sequence_number) \
                                ) \
                                SELECT COUNT(*) AS gap_count FROM ordered \
                                WHERE prev_seq IS NOT NULL AND seq > prev_seq + 1";
                let audit_chain_gaps: i64 = {
                    let mut stmt = conn
                        .prepare(gaps_sql)
                        .map_err(sqlite_read_err("aggregate_scoring_factors gaps prepare"))?;
                    stmt.query_row([&agent, &since, &until], |r| r.get("gap_count"))
                        .map_err(sqlite_read_err("aggregate_scoring_factors gaps"))?
                };

                // Recovery events: top-50 most recent override→pass pairs.
                let recovery_sql = "WITH per_trace AS ( \
                       SELECT trace_id, MIN(ts) AS started_at, MAX(ts) AS completed_at, \
                              MAX(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
                                  AND json_extract(payload, '$.action_was_overridden') = 1 \
                                  THEN 1 ELSE 0 END) AS was_overridden, \
                              MIN(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
                                  THEN json_extract(payload, '$.coherence_passed') \
                                  ELSE 1 END) AS coherence_passed \
                       FROM trace_events \
                       WHERE agent_id_hash = ?1 AND ts >= ?2 AND ts < ?3 \
                       GROUP BY trace_id \
                   ), \
                   ordered AS ( \
                       SELECT trace_id, started_at, completed_at, was_overridden, \
                              LEAD(trace_id) OVER w AS next_trace_id, \
                              LEAD(started_at) OVER w AS next_started_at, \
                              LEAD(coherence_passed) OVER w AS next_coherence_passed \
                       FROM per_trace WINDOW w AS (ORDER BY started_at) \
                   ) \
                   SELECT trace_id AS override_trace_id, completed_at AS override_at, \
                          next_trace_id AS recovery_trace_id, \
                          next_started_at AS recovery_at \
                   FROM ordered \
                   WHERE was_overridden = 1 AND next_trace_id IS NOT NULL \
                         AND next_coherence_passed = 1 \
                   ORDER BY override_at DESC LIMIT 50";
                let recovery_events: Vec<crate::read::RecoveryEvent> = {
                    let mut stmt = conn.prepare(recovery_sql).map_err(sqlite_read_err(
                        "aggregate_scoring_factors recovery prepare",
                    ))?;
                    let collected = stmt
                        .query_map([&agent, &since, &until], |row| {
                            let override_at: String = row.get("override_at")?;
                            let recovery_at: String = row.get("recovery_at")?;
                            let o = parse_rfc3339(&override_at);
                            let r = parse_rfc3339(&recovery_at);
                            Ok(crate::read::RecoveryEvent {
                                override_trace_id: row.get("override_trace_id")?,
                                override_at: o,
                                recovery_trace_id: row.get("recovery_trace_id")?,
                                recovery_at: r,
                                recovery_latency_seconds: (r - o).num_milliseconds() as f64
                                    / 1000.0,
                            })
                        })
                        .map_err(sqlite_read_err("aggregate_scoring_factors recovery query"))?
                        .collect::<Result<Vec<_>, _>>();
                    collected.map_err(sqlite_read_err("aggregate_scoring_factors recovery row"))?
                };

                // Coherence decay series — bucketed pass-rate. Bucket on
                // floor(epoch / bucket_secs) * bucket_secs.
                let decay_sql = format!(
                    "WITH per_trace AS ( \
                         SELECT trace_id, MIN(ts) AS started_at, \
                                MIN(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
                                    THEN json_extract(payload, '$.coherence_passed') \
                                    ELSE 1 END) AS coherence_passed \
                         FROM trace_events \
                         WHERE agent_id_hash = ?1 AND ts >= ?2 AND ts < ?3 \
                         GROUP BY trace_id \
                     ) \
                     SELECT (CAST(strftime('%s', started_at) AS INTEGER) / {bucket_secs}) \
                                * {bucket_secs} AS bucket_epoch, \
                            COUNT(*) AS trace_count, \
                            SUM(CASE WHEN coherence_passed = 1 THEN 1 ELSE 0 END) \
                                AS coherence_passed_count \
                     FROM per_trace GROUP BY bucket_epoch ORDER BY bucket_epoch ASC"
                );
                let coherence_decay_series: Vec<crate::read::CoherencePoint> = {
                    let mut stmt = conn
                        .prepare(&decay_sql)
                        .map_err(sqlite_read_err("aggregate_scoring_factors decay prepare"))?;
                    let collected = stmt
                        .query_map([&agent, &since, &until], |row| {
                            let bucket_epoch: i64 = row.get("bucket_epoch")?;
                            let tc: i64 = row.get("trace_count")?;
                            let pc: i64 = row.get("coherence_passed_count")?;
                            let at =
                                chrono::DateTime::<chrono::Utc>::from_timestamp(bucket_epoch, 0)
                                    .unwrap_or_else(chrono::Utc::now);
                            Ok(crate::read::CoherencePoint {
                                at,
                                coherence_passed_count: pc,
                                trace_count: tc,
                                coherence_pass_rate: if tc > 0 {
                                    pc as f64 / tc as f64
                                } else {
                                    0.0
                                },
                            })
                        })
                        .map_err(sqlite_read_err("aggregate_scoring_factors decay query"))?
                        .collect::<Result<Vec<_>, _>>();
                    collected.map_err(sqlite_read_err("aggregate_scoring_factors decay row"))?
                };

                Ok(crate::read::ScoringFactorAggregate {
                    agent_id_hash: agent,
                    window,
                    trace_count: main.trace_count,
                    identity_changes: main.identity_changes,
                    conscience_overrides: main.conscience_overrides,
                    audit_chain_total: main.audit_chain_total,
                    audit_chain_gaps,
                    audit_signed_total: main.audit_signed_total,
                    recovery_events,
                    // drift_z_score filled in by the caller below.
                    drift_z_score: None,
                    calibration_error: None,
                    unsafe_action_rate,
                    coherence_decay_series,
                })
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))??;

        // Drift z-score: when a baseline window is supplied, surface the
        // CSDMA significance from temporal_drift (matches Postgres).
        let mut agg = agg;
        if let Some(base) = baseline_window {
            let drift_rows = self.temporal_drift(agent_id_hash, base, window).await?;
            agg.drift_z_score = drift_rows
                .iter()
                .find(|r| r.deviation_metric == crate::read::DeviationMetric::CsdmaPlausibility)
                .map(|r| r.significance);
        }
        Ok(agg)
    }

    async fn aggregate_scoring_factors_batch(
        &self,
        agent_id_hashes: &[String],
        window: crate::read::TimeWindow,
        baseline_window: Option<crate::read::TimeWindow>,
    ) -> Result<Vec<crate::read::ScoringFactorAggregate>, crate::read::Error> {
        if agent_id_hashes.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(agent_id_hashes.len());
        for aid in agent_id_hashes {
            out.push(
                self.aggregate_scoring_factors(aid, window, baseline_window)
                    .await?,
            );
        }
        Ok(out)
    }

    async fn count_traces(
        &self,
        filter: crate::read::TraceFilter,
    ) -> Result<i64, crate::read::Error> {
        let (where_sql, binds) = sqlite_filter_where(&filter)?;
        let sql = format!("SELECT COUNT(DISTINCT trace_id) AS n FROM trace_events {where_sql}");
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<i64, crate::read::Error> {
            let conn = conn.blocking_lock();
            let mut stmt = conn
                .prepare(&sql)
                .map_err(sqlite_read_err("count_traces prepare"))?;
            stmt.query_row(params_from_iter(binds.iter()), |r| r.get("n"))
                .map_err(sqlite_read_err("count_traces query"))
        })
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn count_overrides(
        &self,
        filter: crate::read::TraceFilter,
    ) -> Result<i64, crate::read::Error> {
        let (where_sql, binds) = sqlite_filter_where(&filter)?;
        let sql = format!(
            "SELECT COUNT(*) AS n FROM ( \
                SELECT trace_id FROM trace_events {where_sql} GROUP BY trace_id \
                HAVING MAX(CASE WHEN event_type = 'CONSCIENCE_RESULT' \
                    AND json_extract(payload, '$.action_was_overridden') = 1 \
                    THEN 1 ELSE 0 END) = 1 \
             ) sub"
        );
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<i64, crate::read::Error> {
            let conn = conn.blocking_lock();
            let mut stmt = conn
                .prepare(&sql)
                .map_err(sqlite_read_err("count_overrides prepare"))?;
            stmt.query_row(params_from_iter(binds.iter()), |r| r.get("n"))
                .map_err(sqlite_read_err("count_overrides query"))
        })
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn count_identity_changes(
        &self,
        filter: crate::read::TraceFilter,
    ) -> Result<i64, crate::read::Error> {
        let (where_sql, binds) = sqlite_filter_where(&filter)?;
        let sql = format!(
            "SELECT MAX(COUNT(DISTINCT agent_name) - 1, 0) AS n \
             FROM trace_events {where_sql}"
        );
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<i64, crate::read::Error> {
            let conn = conn.blocking_lock();
            let mut stmt = conn
                .prepare(&sql)
                .map_err(sqlite_read_err("count_identity_changes prepare"))?;
            stmt.query_row(params_from_iter(binds.iter()), |r| r.get("n"))
                .map_err(sqlite_read_err("count_identity_changes query"))
        })
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn aggregate_audit_chain(
        &self,
        filter: crate::read::TraceFilter,
    ) -> Result<crate::read::AuditChainAggregate, crate::read::Error> {
        let (where_sql, binds) = sqlite_filter_where(&filter)?;
        let has_agent = filter.agent_id_hash.is_some();
        let totals_sql = format!(
            "SELECT \
                COUNT(*) FILTER (WHERE audit_sequence_number IS NOT NULL) AS audit_total, \
                COUNT(*) FILTER (WHERE audit_signature IS NOT NULL) AS audit_signed, \
                COUNT(*) FILTER (WHERE audit_entry_hash IS NOT NULL) AS audit_hashed \
             FROM trace_events {where_sql}"
        );
        // The gap query needs to AND audit_sequence_number IS NOT NULL
        // onto the WHERE — appended only when filter narrows to one
        // agent (cross-agent sequences interleave; matches Postgres).
        let gaps_sql = if has_agent {
            let conj = if where_sql.is_empty() {
                "WHERE audit_sequence_number IS NOT NULL".to_owned()
            } else {
                format!("{where_sql} AND audit_sequence_number IS NOT NULL")
            };
            Some(format!(
                "WITH ordered AS ( \
                    SELECT audit_sequence_number AS seq, \
                           LAG(audit_sequence_number) OVER w AS prev_seq \
                    FROM trace_events {conj} \
                    WINDOW w AS (ORDER BY audit_sequence_number) \
                 ) \
                 SELECT COUNT(*) AS gap_count FROM ordered \
                 WHERE prev_seq IS NOT NULL AND seq > prev_seq + 1"
            ))
        } else {
            None
        };
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<crate::read::AuditChainAggregate, crate::read::Error> {
                let conn = conn.blocking_lock();
                let (audit_total, audit_signed, audit_hashed) = {
                    let mut stmt = conn
                        .prepare(&totals_sql)
                        .map_err(sqlite_read_err("aggregate_audit_chain totals prepare"))?;
                    stmt.query_row(params_from_iter(binds.iter()), |row| {
                        Ok((
                            row.get::<_, i64>("audit_total")?,
                            row.get::<_, i64>("audit_signed")?,
                            row.get::<_, i64>("audit_hashed")?,
                        ))
                    })
                    .map_err(sqlite_read_err("aggregate_audit_chain totals"))?
                };
                let gap_count = match gaps_sql {
                    None => 0,
                    Some(sql) => {
                        let mut stmt = conn
                            .prepare(&sql)
                            .map_err(sqlite_read_err("aggregate_audit_chain gaps prepare"))?;
                        stmt.query_row(params_from_iter(binds.iter()), |r| {
                            r.get::<_, i64>("gap_count")
                        })
                        .map_err(sqlite_read_err("aggregate_audit_chain gaps"))?
                    }
                };
                Ok(crate::read::AuditChainAggregate {
                    audit_total,
                    audit_signed,
                    audit_hashed,
                    gap_count,
                })
            },
        )
        .await
        .map_err(|e| crate::read::Error::Backend(format!("spawn_blocking join: {e}")))?
    }
}

/// Mean + sample variance (Bessel-corrected, `n-1`) of a slice.
/// Returns `(mean, variance)`; variance is `0.0` for fewer than 2
/// samples. Used by `temporal_drift` (SQLite has no `VAR_SAMP`).
fn mean_and_sample_var(xs: &[f64]) -> (f64, f64) {
    let n = xs.len();
    if n == 0 {
        return (0.0, 0.0);
    }
    let mean = xs.iter().sum::<f64>() / n as f64;
    if n < 2 {
        return (mean, 0.0);
    }
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0);
    (mean, var)
}

/// Parse the canonical `qa_<lang>_<num>` / `qa-eval-<lang>-<num>`
/// task-id shape into `(language, Option<question_num>)`. Returns
/// `None` when the task-id doesn't match the QA shape. SQLite has no
/// regex-capture, so the corpus-shape QA breakdown extracts in Rust
/// (the Postgres impl does it with `substring(... from '<regex>')`).
fn parse_qa_task_id(task_id: &str) -> Option<(String, Option<i32>)> {
    // Strip the `qa_` / `qa-eval_` / `qa-eval-` prefix, normalizing
    // both `_` and `-` separators.
    let rest = if let Some(r) = task_id.strip_prefix("qa-eval") {
        r.strip_prefix(['_', '-'])?
    } else if let Some(r) = task_id.strip_prefix("qa") {
        r.strip_prefix(['_', '-'])?
    } else {
        return None;
    };
    // First token = language (lowercase alpha); second = question num.
    let mut segments = rest.split(['_', '-']);
    let lang = segments.next()?;
    if lang.is_empty() || !lang.chars().all(|c| c.is_ascii_lowercase()) {
        return None;
    }
    let qnum = segments.next().and_then(|s| s.parse::<i32>().ok());
    Some((lang.to_owned(), qnum))
}

// ─── DerivedSchema impl — SQLite parity (CIRISPersist#82 review) ───
//
// Real implementations of the cirislens_derived substrate for the
// SQLite backend, backed by the V040 migration tables
// `cirislens_derived_detection_events` /
// `cirislens_derived_calibration_bundles`. Sovereign-mode (Pi / iOS)
// deployments run SQLite and now get the same lens-derived evidence
// surface as Postgres. Idempotency + conflict semantics match the
// Postgres impl exactly: a PK collision (detection_id /
// ratchet_calibration_version) is idempotent; a collision with
// different `canonical_bytes` raises `Conflict`.

/// Build a `derived::Error::Backend` mapper carrying call context.
fn sqlite_derived_err(ctx: &str) -> impl Fn(rusqlite::Error) -> crate::derived::Error {
    let ctx = ctx.to_owned();
    move |e| crate::derived::Error::Backend(format!("{ctx}: {e}"))
}

/// Raw column values for one `cirislens_derived_detection_events`
/// row — all rusqlite-native types, decoded inside the `query_map`
/// closure; the serde / enum / uuid parsing happens in
/// [`raw_to_detection_event`] where a typed error can be returned.
struct RawSqliteDetection {
    detection_id: String,
    trace_id: String,
    body_sha256: Vec<u8>,
    detector: String,
    severity: String,
    cohort_cell: String,
    conformity_variant: String,
    conformity_payload: String,
    lens_core_version: String,
    ratchet_calibration_version: i64,
    canonical_bytes: Vec<u8>,
    ed25519_sig: Vec<u8>,
    ml_dsa_65_sig: Vec<u8>,
    signing_key_id: String,
    ts: String,
}

fn sqlite_detection_from_row(row: &rusqlite::Row) -> rusqlite::Result<RawSqliteDetection> {
    Ok(RawSqliteDetection {
        detection_id: row.get("detection_id")?,
        trace_id: row.get("trace_id")?,
        body_sha256: row.get("body_sha256")?,
        detector: row.get("detector")?,
        severity: row.get("severity")?,
        cohort_cell: row.get("cohort_cell")?,
        conformity_variant: row.get("conformity_variant")?,
        conformity_payload: row.get("conformity_payload")?,
        lens_core_version: row.get("lens_core_version")?,
        ratchet_calibration_version: row.get("ratchet_calibration_version")?,
        canonical_bytes: row.get("canonical_bytes")?,
        ed25519_sig: row.get("ed25519_sig")?,
        ml_dsa_65_sig: row.get("ml_dsa_65_sig")?,
        signing_key_id: row.get("signing_key_id")?,
        ts: row.get("ts")?,
    })
}

fn raw_to_detection_event(
    r: RawSqliteDetection,
) -> Result<crate::derived::DetectionEvent, crate::derived::Error> {
    let detection_id = uuid::Uuid::parse_str(&r.detection_id)
        .map_err(|e| crate::derived::Error::Backend(format!("detection_id not a UUID: {e}")))?;
    let severity =
        crate::derived::DetectionSeverity::from_db_str(&r.severity).ok_or_else(|| {
            crate::derived::Error::Backend(format!("unknown severity in DB: {}", r.severity))
        })?;
    let conformity_variant = crate::derived::ConformityVariant::from_db_str(&r.conformity_variant)
        .ok_or_else(|| {
            crate::derived::Error::Backend(format!(
                "unknown conformity_variant in DB: {}",
                r.conformity_variant
            ))
        })?;
    let cohort_cell: serde_json::Value = serde_json::from_str(&r.cohort_cell)
        .map_err(|e| crate::derived::Error::Backend(format!("cohort_cell decode: {e}")))?;
    let conformity_payload: serde_json::Value = serde_json::from_str(&r.conformity_payload)
        .map_err(|e| crate::derived::Error::Backend(format!("conformity_payload decode: {e}")))?;
    Ok(crate::derived::DetectionEvent {
        detection_id,
        trace_id: r.trace_id,
        body_sha256: r.body_sha256,
        detector: r.detector,
        severity,
        cohort_cell,
        conformity_variant,
        conformity_payload,
        lens_core_version: r.lens_core_version,
        ratchet_calibration_version: r.ratchet_calibration_version as i32,
        canonical_bytes: r.canonical_bytes,
        ed25519_sig: r.ed25519_sig,
        ml_dsa_65_sig: r.ml_dsa_65_sig,
        signing_key_id: r.signing_key_id,
        ts: parse_rfc3339(&r.ts),
    })
}

/// Raw column values for one `cirislens_derived_calibration_bundles`
/// row. See [`RawSqliteDetection`] for the two-step decode rationale.
struct RawSqliteBundle {
    ratchet_calibration_version: i64,
    projection_version: String,
    calibrated_at: String,
    calibration_corpus_sha256: String,
    calibration_corpus_n: i64,
    sample_size_gate: i64,
    manifold_threshold_global: f64,
    projection_metadata: String,
    cohort_centroids: String,
    is_current: i64,
    canonical_bytes: Vec<u8>,
    ed25519_sig: Vec<u8>,
    ml_dsa_65_sig: Vec<u8>,
    signing_key_id: String,
    inserted_at: String,
}

fn sqlite_bundle_from_row(row: &rusqlite::Row) -> rusqlite::Result<RawSqliteBundle> {
    Ok(RawSqliteBundle {
        ratchet_calibration_version: row.get("ratchet_calibration_version")?,
        projection_version: row.get("projection_version")?,
        calibrated_at: row.get("calibrated_at")?,
        calibration_corpus_sha256: row.get("calibration_corpus_sha256")?,
        calibration_corpus_n: row.get("calibration_corpus_n")?,
        sample_size_gate: row.get("sample_size_gate")?,
        manifold_threshold_global: row.get("manifold_threshold_global")?,
        projection_metadata: row.get("projection_metadata")?,
        cohort_centroids: row.get("cohort_centroids")?,
        is_current: row.get("is_current")?,
        canonical_bytes: row.get("canonical_bytes")?,
        ed25519_sig: row.get("ed25519_sig")?,
        ml_dsa_65_sig: row.get("ml_dsa_65_sig")?,
        signing_key_id: row.get("signing_key_id")?,
        inserted_at: row.get("inserted_at")?,
    })
}

fn raw_to_calibration_bundle(
    r: RawSqliteBundle,
) -> Result<crate::derived::CalibrationBundle, crate::derived::Error> {
    let projection_metadata: serde_json::Value = serde_json::from_str(&r.projection_metadata)
        .map_err(|e| crate::derived::Error::Backend(format!("projection_metadata decode: {e}")))?;
    let cohort_centroids: serde_json::Value = serde_json::from_str(&r.cohort_centroids)
        .map_err(|e| crate::derived::Error::Backend(format!("cohort_centroids decode: {e}")))?;
    Ok(crate::derived::CalibrationBundle {
        ratchet_calibration_version: r.ratchet_calibration_version as i32,
        projection_version: r.projection_version,
        calibrated_at: parse_rfc3339(&r.calibrated_at),
        calibration_corpus_sha256: r.calibration_corpus_sha256,
        calibration_corpus_n: r.calibration_corpus_n as i32,
        sample_size_gate: r.sample_size_gate as i32,
        manifold_threshold_global: r.manifold_threshold_global as f32,
        projection_metadata,
        cohort_centroids,
        is_current: r.is_current != 0,
        canonical_bytes: r.canonical_bytes,
        ed25519_sig: r.ed25519_sig,
        ml_dsa_65_sig: r.ml_dsa_65_sig,
        signing_key_id: r.signing_key_id,
        inserted_at: parse_rfc3339(&r.inserted_at),
    })
}

const SQLITE_BUNDLE_SELECT: &str = "SELECT \
    ratchet_calibration_version, projection_version, calibrated_at, \
    calibration_corpus_sha256, calibration_corpus_n, sample_size_gate, \
    manifold_threshold_global, projection_metadata, cohort_centroids, \
    is_current, canonical_bytes, ed25519_sig, ml_dsa_65_sig, \
    signing_key_id, inserted_at \
    FROM cirislens_derived_calibration_bundles";

impl crate::derived::DerivedSchema for SqliteBackend {
    async fn put_detection_event(
        &self,
        event: crate::derived::DetectionEvent,
    ) -> Result<(), crate::derived::Error> {
        // Fixed-length signature shape gates — surface a typed
        // InvalidArgument rather than letting the table CHECK fire as
        // an opaque backend SQL error. Matches the Postgres impl.
        if event.body_sha256.len() != 32 {
            return Err(crate::derived::Error::InvalidArgument(format!(
                "body_sha256 must be 32 bytes (got {})",
                event.body_sha256.len()
            )));
        }
        if event.ed25519_sig.len() != 64 {
            return Err(crate::derived::Error::InvalidArgument(format!(
                "ed25519_sig must be 64 bytes (got {})",
                event.ed25519_sig.len()
            )));
        }
        if event.ml_dsa_65_sig.len() != 3309 {
            return Err(crate::derived::Error::InvalidArgument(format!(
                "ml_dsa_65_sig must be 3309 bytes (got {})",
                event.ml_dsa_65_sig.len()
            )));
        }

        let cohort_cell = serde_json::to_string(&event.cohort_cell)
            .map_err(|e| crate::derived::Error::Backend(format!("cohort_cell encode: {e}")))?;
        let conformity_payload = serde_json::to_string(&event.conformity_payload).map_err(|e| {
            crate::derived::Error::Backend(format!("conformity_payload encode: {e}"))
        })?;
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), crate::derived::Error> {
            let conn = conn.blocking_lock();
            // Idempotent on detection_id; raise Conflict on collision
            // with different canonical_bytes.
            let changed = conn
                .execute(
                    "INSERT INTO cirislens_derived_detection_events (\
                        detection_id, trace_id, body_sha256, detector, severity, \
                        cohort_cell, conformity_variant, conformity_payload, \
                        lens_core_version, ratchet_calibration_version, \
                        canonical_bytes, ed25519_sig, ml_dsa_65_sig, signing_key_id, ts\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
                     ON CONFLICT (detection_id) DO NOTHING",
                    rusqlite::params![
                        event.detection_id.to_string(),
                        event.trace_id,
                        event.body_sha256,
                        event.detector,
                        event.severity.as_db_str(),
                        cohort_cell,
                        event.conformity_variant.as_db_str(),
                        conformity_payload,
                        event.lens_core_version,
                        event.ratchet_calibration_version as i64,
                        event.canonical_bytes,
                        event.ed25519_sig,
                        event.ml_dsa_65_sig,
                        event.signing_key_id,
                        event.ts.to_rfc3339(),
                    ],
                )
                .map_err(sqlite_derived_err("insert detection_events"))?;
            if changed == 0 {
                let existing: Option<Vec<u8>> = conn
                    .query_row(
                        "SELECT canonical_bytes FROM cirislens_derived_detection_events \
                         WHERE detection_id = ?1",
                        [event.detection_id.to_string()],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sqlite_derived_err("detection conflict check"))?;
                if let Some(existing_bytes) = existing {
                    if existing_bytes != event.canonical_bytes {
                        return Err(crate::derived::Error::Conflict(format!(
                            "detection_id {} already exists with different canonical_bytes",
                            event.detection_id
                        )));
                    }
                }
            }
            Ok(())
        })
        .await
        .map_err(|e| crate::derived::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn get_detection_events(
        &self,
        filter: crate::derived::EventFilter,
    ) -> Result<Vec<crate::derived::DetectionEvent>, crate::derived::Error> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::derived::DetectionEvent>, crate::derived::Error> {
                let conn = conn.blocking_lock();
                // Conditional filters; ts DESC for newest-first triage,
                // matching the Postgres path (default LIMIT 1000).
                let mut sql = String::from(
                    "SELECT detection_id, trace_id, body_sha256, detector, severity, \
                        cohort_cell, conformity_variant, conformity_payload, \
                        lens_core_version, ratchet_calibration_version, \
                        canonical_bytes, ed25519_sig, ml_dsa_65_sig, signing_key_id, ts \
                     FROM cirislens_derived_detection_events WHERE 1 = 1",
                );
                let mut binds: Vec<String> = Vec::new();
                if let Some(t) = filter.trace_id {
                    binds.push(t);
                    sql.push_str(&format!(" AND trace_id = ?{}", binds.len()));
                }
                if let Some(d) = filter.detector {
                    binds.push(d);
                    sql.push_str(&format!(" AND detector = ?{}", binds.len()));
                }
                if let Some(s) = filter.since {
                    binds.push(s.to_rfc3339());
                    sql.push_str(&format!(" AND ts >= ?{}", binds.len()));
                }
                sql.push_str(" ORDER BY ts DESC LIMIT 1000");

                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(sqlite_derived_err("get_detection_events prepare"))?;
                let collected = stmt
                    .query_map(rusqlite::params_from_iter(binds.iter()), |row| {
                        sqlite_detection_from_row(row)
                    })
                    .map_err(sqlite_derived_err("get_detection_events query"))?
                    .collect::<Result<Vec<_>, _>>();
                let raw = collected.map_err(sqlite_derived_err("get_detection_events row"))?;
                raw.into_iter().map(raw_to_detection_event).collect()
            },
        )
        .await
        .map_err(|e| crate::derived::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn put_calibration_bundle(
        &self,
        bundle: crate::derived::CalibrationBundle,
    ) -> Result<(), crate::derived::Error> {
        if bundle.ed25519_sig.len() != 64 {
            return Err(crate::derived::Error::InvalidArgument(format!(
                "ed25519_sig must be 64 bytes (got {})",
                bundle.ed25519_sig.len()
            )));
        }
        if bundle.ml_dsa_65_sig.len() != 3309 {
            return Err(crate::derived::Error::InvalidArgument(format!(
                "ml_dsa_65_sig must be 3309 bytes (got {})",
                bundle.ml_dsa_65_sig.len()
            )));
        }

        let projection_metadata =
            serde_json::to_string(&bundle.projection_metadata).map_err(|e| {
                crate::derived::Error::Backend(format!("projection_metadata encode: {e}"))
            })?;
        let cohort_centroids = serde_json::to_string(&bundle.cohort_centroids)
            .map_err(|e| crate::derived::Error::Backend(format!("cohort_centroids encode: {e}")))?;
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), crate::derived::Error> {
            let mut conn = conn.blocking_lock();
            // Atomic flip: clear the prior is_current row + insert the
            // new row in one transaction. The partial-unique index
            // calibration_bundles_one_current makes "at most one
            // current bundle" DB-enforced; the transaction makes the
            // transition race-free.
            let tx = conn.transaction().map_err(sqlite_derived_err("begin tx"))?;
            if bundle.is_current {
                tx.execute(
                    "UPDATE cirislens_derived_calibration_bundles \
                     SET is_current = 0 WHERE is_current = 1",
                    [],
                )
                .map_err(sqlite_derived_err("clear prior current"))?;
            }
            let changed = tx
                .execute(
                    "INSERT INTO cirislens_derived_calibration_bundles (\
                        ratchet_calibration_version, projection_version, calibrated_at, \
                        calibration_corpus_sha256, calibration_corpus_n, sample_size_gate, \
                        manifold_threshold_global, projection_metadata, cohort_centroids, \
                        is_current, canonical_bytes, ed25519_sig, ml_dsa_65_sig, \
                        signing_key_id, inserted_at\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15) \
                     ON CONFLICT (ratchet_calibration_version) DO NOTHING",
                    rusqlite::params![
                        bundle.ratchet_calibration_version as i64,
                        bundle.projection_version,
                        bundle.calibrated_at.to_rfc3339(),
                        bundle.calibration_corpus_sha256,
                        bundle.calibration_corpus_n as i64,
                        bundle.sample_size_gate as i64,
                        bundle.manifold_threshold_global as f64,
                        projection_metadata,
                        cohort_centroids,
                        i64::from(bundle.is_current),
                        bundle.canonical_bytes,
                        bundle.ed25519_sig,
                        bundle.ml_dsa_65_sig,
                        bundle.signing_key_id,
                        bundle.inserted_at.to_rfc3339(),
                    ],
                )
                .map_err(sqlite_derived_err("insert calibration_bundles"))?;
            if changed == 0 {
                let existing: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT canonical_bytes FROM cirislens_derived_calibration_bundles \
                         WHERE ratchet_calibration_version = ?1",
                        [bundle.ratchet_calibration_version as i64],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sqlite_derived_err("bundle conflict check"))?;
                if let Some(existing_bytes) = existing {
                    if existing_bytes != bundle.canonical_bytes {
                        return Err(crate::derived::Error::Conflict(format!(
                            "ratchet_calibration_version {} already exists with \
                             different canonical_bytes",
                            bundle.ratchet_calibration_version
                        )));
                    }
                }
            }
            tx.commit().map_err(sqlite_derived_err("commit tx"))?;
            Ok(())
        })
        .await
        .map_err(|e| crate::derived::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn get_current_calibration_bundle(
        &self,
    ) -> Result<Option<crate::derived::CalibrationBundle>, crate::derived::Error> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Option<crate::derived::CalibrationBundle>, crate::derived::Error> {
                let conn = conn.blocking_lock();
                let raw = conn
                    .query_row(
                        &format!("{SQLITE_BUNDLE_SELECT} WHERE is_current = 1"),
                        [],
                        sqlite_bundle_from_row,
                    )
                    .optional()
                    .map_err(sqlite_derived_err("get_current_calibration_bundle"))?;
                raw.map(raw_to_calibration_bundle).transpose()
            },
        )
        .await
        .map_err(|e| crate::derived::Error::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn get_calibration_bundle_by_version(
        &self,
        version: i32,
    ) -> Result<Option<crate::derived::CalibrationBundle>, crate::derived::Error> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Option<crate::derived::CalibrationBundle>, crate::derived::Error> {
                let conn = conn.blocking_lock();
                let raw = conn
                    .query_row(
                        &format!("{SQLITE_BUNDLE_SELECT} WHERE ratchet_calibration_version = ?1"),
                        [i64::from(version)],
                        sqlite_bundle_from_row,
                    )
                    .optional()
                    .map_err(sqlite_derived_err("get_calibration_bundle_by_version"))?;
                raw.map(raw_to_calibration_bundle).transpose()
            },
        )
        .await
        .map_err(|e| crate::derived::Error::Backend(format!("spawn_blocking join: {e}")))?
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
            verification_source: crate::store::VerificationSource::Persist,
            schema_version: "2.7.0".to_owned(),
            pii_scrubbed: true,
            original_content_hash: Some("aabbcc".to_owned()),
            scrub_signature: Some("sig-scrub".to_owned()),
            scrub_key_id: Some("scrub-key-1".to_owned()),
            scrub_timestamp: Some(Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 1).unwrap()),
            agent_role: None,
            agent_template: None,
            deployment_domain: None,
            deployment_type: None,
            deployment_region: None,
            deployment_trust_mode: None,
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
                // v0.4.0 — write directly to federation_keys (the
                // canonical pubkey directory post-lens#8 ASK 2). The
                // pre-v0.4.0 dual-read fallback to accord_public_keys
                // was retired.
                conn.execute(
                    "INSERT INTO federation_keys (\
                        key_id, pubkey_ed25519_base64, algorithm, \
                        identity_type, identity_ref, valid_from, \
                        registration_envelope, original_content_hash, \
                        scrub_signature_classical, scrub_key_id, \
                        scrub_timestamp, persist_row_hash\
                     ) VALUES (?1, ?2, 'hybrid', 'agent', ?1, ?3, '{}', \
                              x'00', '', ?1, ?3, '0')",
                    rusqlite::params!["key-test", pk_b64, "2026-04-30T00:00:00+00:00"],
                )?;
                Ok(())
            })
            .await
            .unwrap()
            .unwrap();
        }

        // Disambiguate: both Backend and FederationDirectory traits
        // expose `lookup_public_key` post-v0.2.0. This test exercises
        // the legacy Backend (VerifyingKey) shape used by the trace
        // verify path. Source-of-truth is federation_keys (v0.4.0).
        let got = Backend::lookup_public_key(&backend, "key-test")
            .await
            .unwrap();
        assert!(got.is_some());
        assert_eq!(got.unwrap().to_bytes(), verifying.to_bytes());

        // Unknown key returns None.
        let none = Backend::lookup_public_key(&backend, "key-missing")
            .await
            .unwrap();
        assert!(none.is_none());
    }

    /// v0.4.0 — Expired federation_keys rows are filtered from
    /// lookup AND sample. Replaces the v0.1.x revoked_at filter
    /// against accord_public_keys (retired in this release).
    /// Federation revocations now live in federation_revocations,
    /// a separate concern (consumers walk that graph for revocation
    /// policy).
    #[tokio::test]
    async fn expired_keys_filtered() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();

        let pk_b64 = BASE64.encode(fixture_pubkey().to_bytes());

        {
            let conn = backend.conn.clone();
            let pk_b64 = pk_b64.clone();
            tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
                let conn = conn.blocking_lock();
                conn.execute(
                    "INSERT INTO federation_keys (\
                        key_id, pubkey_ed25519_base64, algorithm, \
                        identity_type, identity_ref, valid_from, \
                        registration_envelope, original_content_hash, \
                        scrub_signature_classical, scrub_key_id, \
                        scrub_timestamp, persist_row_hash\
                     ) VALUES (?1, ?2, 'hybrid', 'agent', ?1, ?3, '{}', \
                              x'00', '', ?1, ?3, '0')",
                    rusqlite::params!["key-active", pk_b64, "2026-04-30T00:00:00+00:00"],
                )?;
                conn.execute(
                    "INSERT INTO federation_keys (\
                        key_id, pubkey_ed25519_base64, algorithm, \
                        identity_type, identity_ref, valid_from, valid_until, \
                        registration_envelope, original_content_hash, \
                        scrub_signature_classical, scrub_key_id, \
                        scrub_timestamp, persist_row_hash\
                     ) VALUES (?1, ?2, 'hybrid', 'agent', ?1, ?3, ?4, '{}', \
                              x'00', '', ?1, ?3, '0')",
                    rusqlite::params![
                        "key-expired",
                        pk_b64,
                        "2026-04-29T00:00:00+00:00",
                        "2026-04-30T00:00:00+00:00",
                    ],
                )?;
                Ok(())
            })
            .await
            .unwrap()
            .unwrap();
        }

        assert!(Backend::lookup_public_key(&backend, "key-active")
            .await
            .unwrap()
            .is_some());
        assert!(Backend::lookup_public_key(&backend, "key-expired")
            .await
            .unwrap()
            .is_none());

        let sample = backend.sample_public_keys(10).await.unwrap();
        assert_eq!(sample.size, 1);
        assert_eq!(sample.sample, vec!["key-active".to_owned()]);
    }

    // ─── FederationDirectory tests ─────────────────────────────────

    use crate::federation::{
        Attestation, FederationDirectory, KeyRecord, Revocation, SignedAttestation,
        SignedKeyRecord, SignedRevocation,
    };

    fn fed_key(key_id: &str, identity_ref: &str, scrub_key_id: &str) -> KeyRecord {
        KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::PRIMITIVE.into(),
            identity_ref: identity_ref.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
        }
    }

    fn fed_attestation(
        id: &str,
        attesting: &str,
        attested: &str,
        scrub_key_id: &str,
    ) -> Attestation {
        Attestation {
            attestation_id: id.into(),
            attesting_key_id: attesting.into(),
            attested_key_id: attested.into(),
            attestation_type: crate::federation::types::attestation_type::VOUCHES_FOR.into(),
            weight: Some(1.0),
            asserted_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            expires_at: None,
            attestation_envelope: serde_json::json!({"id": id}),
            original_content_hash: "abc123".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
        }
    }

    fn fed_revocation(id: &str, revoked: &str, revoking: &str, scrub_key_id: &str) -> Revocation {
        Revocation {
            revocation_id: id.into(),
            revoked_key_id: revoked.into(),
            revoking_key_id: revoking.into(),
            reason: Some("test".into()),
            revoked_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            effective_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            revocation_envelope: serde_json::json!({"id": id}),
            original_content_hash: "abc123".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
        }
    }

    #[tokio::test]
    async fn federation_put_and_lookup_round_trip() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();

        let key = fed_key("persist-steward", "persist", "persist-steward");
        backend
            .put_public_key(SignedKeyRecord {
                record: key.clone(),
            })
            .await
            .unwrap();

        let got = FederationDirectory::lookup_public_key(&backend, "persist-steward")
            .await
            .unwrap();
        assert!(got.is_some());
        let got = got.unwrap();
        assert_eq!(got.key_id, "persist-steward");
        assert_eq!(got.identity_ref, "persist");
        assert_eq!(got.persist_row_hash.len(), 64);
        // Server-computed hash matches what compute_persist_row_hash
        // gives — round-trip via SQLite did not corrupt the field.
        let mut for_hash = got.clone();
        for_hash.persist_row_hash = String::new();
        let recomputed = crate::federation::types::compute_persist_row_hash(&for_hash).unwrap();
        assert_eq!(got.persist_row_hash, recomputed);
    }

    #[tokio::test]
    async fn federation_idempotent_put() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let key = fed_key("k1", "primitive-a", "k1");
        backend
            .put_public_key(SignedKeyRecord {
                record: key.clone(),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord { record: key })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn federation_conflict_on_different_content() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let key1 = fed_key("k1", "primitive-a", "k1");
        let key2 = fed_key("k1", "primitive-b", "k1");
        backend
            .put_public_key(SignedKeyRecord { record: key1 })
            .await
            .unwrap();
        let err = backend
            .put_public_key(SignedKeyRecord { record: key2 })
            .await
            .unwrap_err();
        assert!(matches!(err, crate::federation::Error::Conflict(_)));
    }

    #[tokio::test]
    async fn federation_lookup_by_identity_filters() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-1", "persist", "k-1"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-2", "persist", "k-2"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-3", "lens", "k-3"),
            })
            .await
            .unwrap();
        let persist_keys = backend.lookup_keys_for_identity("persist").await.unwrap();
        assert_eq!(persist_keys.len(), 2);
        let lens_keys = backend.lookup_keys_for_identity("lens").await.unwrap();
        assert_eq!(lens_keys.len(), 1);
    }

    #[tokio::test]
    async fn federation_attestation_round_trip() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // Bootstrap two keys first (FK requirement).
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fed_attestation(
                    "att-1",
                    "registry-steward",
                    "k-a",
                    "registry-steward",
                ),
            })
            .await
            .unwrap();

        let by = backend
            .list_attestations_by("registry-steward")
            .await
            .unwrap();
        assert_eq!(by.len(), 1);
        let for_a = backend.list_attestations_for("k-a").await.unwrap();
        assert_eq!(for_a.len(), 1);
        assert_eq!(for_a[0].attestation_id, "att-1");
        assert_eq!(for_a[0].persist_row_hash.len(), 64);
    }

    #[tokio::test]
    async fn federation_attestation_fk_enforcement() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // Insert an attestation referencing a non-existent key — FK
        // violation surfaces as InvalidArgument (matches memory shape).
        let att = fed_attestation("att-1", "ghost-steward", "ghost-key", "ghost-steward");
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        assert!(matches!(err, crate::federation::Error::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn federation_revocation_round_trip() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-bad", "primitive-bad", "registry-steward"),
            })
            .await
            .unwrap();
        backend
            .put_revocation(SignedRevocation {
                revocation: fed_revocation(
                    "rev-1",
                    "k-bad",
                    "registry-steward",
                    "registry-steward",
                ),
            })
            .await
            .unwrap();
        let revs = backend.revocations_for("k-bad").await.unwrap();
        assert_eq!(revs.len(), 1);
        assert_eq!(revs[0].revocation_id, "rev-1");
        assert_eq!(revs[0].persist_row_hash.len(), 64);
    }

    // ─── Trust hierarchy tests (v1.3.0, CIRISPersist#46+#47) ───────
    //
    // Shapes 1–7 cover the seven invariants in the M2 cut spec; shape 8
    // smokes the edge_detection_events table V020 ships alongside.

    use crate::federation::{TrustFilter, TrustGrant, TrustRelationship, TrustType};

    async fn trust_test_backend() -> SqliteBackend {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // Bootstrap a registry steward so the FK contract on
        // federation_keys is satisfied.
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("registry-steward", "registry", "registry-steward"),
            })
            .await
            .unwrap();
        backend
    }

    fn trust_grant_for(key: &str) -> TrustGrant {
        TrustGrant {
            key: key.to_owned(),
            trust_type: TrustType::Temporary,
            trust_relationship: TrustRelationship::Direct,
            trust_domains: None,
            trusted_by: "registry-steward".to_owned(),
            expires_at: None,
        }
    }

    /// Shape 1 (M1): grant_trust → lookup_trust round-trip.
    #[tokio::test]
    async fn trust_grant_then_lookup_round_trip() {
        let backend = trust_test_backend().await;
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        backend.grant_trust(trust_grant_for("k-a")).await.unwrap();
        let got = backend.lookup_trust("k-a").await.unwrap();
        let row = got.expect("trust row present");
        assert_eq!(row.key, "k-a");
        assert_eq!(row.trust_type, TrustType::Temporary);
        assert_eq!(row.trust_relationship, TrustRelationship::Direct);
        assert_eq!(row.trusted_by, "registry-steward");
        assert!(row.expires_at.is_none());
    }

    /// Shape 2 (M1): self-trust → InvalidArgument.
    #[tokio::test]
    async fn trust_grant_rejects_self_trust() {
        let backend = trust_test_backend().await;
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-self", "primitive-self", "registry-steward"),
            })
            .await
            .unwrap();
        let mut grant = trust_grant_for("k-self");
        grant.trusted_by = "k-self".to_owned();
        let err = backend.grant_trust(grant).await.unwrap_err();
        assert!(matches!(err, crate::federation::Error::InvalidArgument(_)));
    }

    /// Shape 3 (M1): Registry without domains → InvalidArgument.
    /// SQLite enforces at the API surface via `validate_trust_grant`;
    /// PG also enforces via the V020 CHECK constraint.
    #[tokio::test]
    async fn trust_grant_rejects_registry_without_domains() {
        let backend = trust_test_backend().await;
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-reg", "primitive-reg", "registry-steward"),
            })
            .await
            .unwrap();
        let mut grant = trust_grant_for("k-reg");
        grant.trust_relationship = TrustRelationship::Registry;
        grant.trust_domains = None;
        let err = backend.grant_trust(grant).await.unwrap_err();
        assert!(matches!(err, crate::federation::Error::InvalidArgument(_)));
    }

    /// Shape 4 (M1): revoke_trust is idempotent — second revoke is a
    /// no-op.
    #[tokio::test]
    async fn trust_revoke_is_idempotent() {
        let backend = trust_test_backend().await;
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-rev", "primitive-rev", "registry-steward"),
            })
            .await
            .unwrap();
        backend.grant_trust(trust_grant_for("k-rev")).await.unwrap();
        backend
            .revoke_trust("k-rev", "registry-steward")
            .await
            .unwrap();
        // Second call must succeed without error.
        backend
            .revoke_trust("k-rev", "registry-steward")
            .await
            .unwrap();
        let row = backend.lookup_trust("k-rev").await.unwrap().unwrap();
        // expires_at populated by revoke; the second revoke didn't
        // change the row.
        assert!(row.expires_at.is_some());
    }

    /// Shape 5 (M1): list_trusted_keys filter narrows by relationship.
    #[tokio::test]
    async fn trust_list_filter_by_relationship() {
        let backend = trust_test_backend().await;
        // Two Direct + one Registry; filter Registry returns 1.
        for (kid, rel, domains) in [
            ("k-d1", TrustRelationship::Direct, None),
            ("k-d2", TrustRelationship::Direct, None),
            (
                "k-r1",
                TrustRelationship::Registry,
                Some(vec!["alpha".into()]),
            ),
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fed_key(kid, kid, "registry-steward"),
                })
                .await
                .unwrap();
            let mut grant = trust_grant_for(kid);
            grant.trust_relationship = rel;
            grant.trust_domains = domains;
            backend.grant_trust(grant).await.unwrap();
        }
        let registry_only = backend
            .list_trusted_keys(TrustFilter {
                trust_relationship: Some(TrustRelationship::Registry),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(registry_only.len(), 1);
        assert_eq!(registry_only[0].key, "k-r1");
    }

    /// Shape 6 (M1): include_expired filter.
    #[tokio::test]
    async fn trust_list_include_expired() {
        let backend = trust_test_backend().await;
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-exp", "primitive-exp", "registry-steward"),
            })
            .await
            .unwrap();
        let mut grant = trust_grant_for("k-exp");
        grant.expires_at = Some(chrono::Utc::now() - chrono::Duration::hours(1));
        backend.grant_trust(grant).await.unwrap();

        // include_expired=false → excludes.
        let active = backend
            .list_trusted_keys(TrustFilter::default())
            .await
            .unwrap();
        assert!(active.iter().all(|r| r.key != "k-exp"));

        // include_expired=true → includes.
        let all = backend
            .list_trusted_keys(TrustFilter {
                include_expired: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(all.iter().any(|r| r.key == "k-exp"));
    }

    /// Shape 7 (M1): audit chain integration — a trust grant + a
    /// caller-composed `trust_granted` audit entry round-trip. Per
    /// the trait doc, persist's `grant_trust` does NOT auto-sign the
    /// audit entry (the audit chain is self-signed by the caller's
    /// Ed25519 key per AV-49). The vocabulary is the integration
    /// point: V020 extends the V018 CHECK to accept `trust_granted` +
    /// `trust_revoked`. This test exercises the vocabulary by parsing
    /// the wire string through `AuditEventType::from_wire_str`.
    #[cfg(feature = "cirisaudit")]
    #[tokio::test]
    async fn trust_grant_vocab_round_trips_via_audit_event_type() {
        use crate::audit::AuditEventType;
        assert_eq!(AuditEventType::TrustGranted.as_str(), "trust_granted");
        assert_eq!(AuditEventType::TrustRevoked.as_str(), "trust_revoked");
        assert_eq!(
            AuditEventType::from_wire_str("trust_granted"),
            Some(AuditEventType::TrustGranted)
        );
        assert_eq!(
            AuditEventType::from_wire_str("trust_revoked"),
            Some(AuditEventType::TrustRevoked)
        );
    }

    /// Shape 8: edge_detection_events table is usable (smoke test —
    /// no service trait wraps it yet, just confirms the V020 table
    /// schema works for INSERT + SELECT).
    #[tokio::test]
    async fn edge_detection_events_insert_and_select() {
        let backend = trust_test_backend().await;
        // FK-target key
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-suspect", "primitive-suspect", "registry-steward"),
            })
            .await
            .unwrap();

        let conn = backend.conn.clone();
        let detection_id = uuid::Uuid::new_v4().to_string();
        let did = detection_id.clone();
        tokio::task::spawn_blocking(move || -> rusqlite::Result<()> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO edge_detection_events (\
                    detection_id, tenant_id, detector_kind, subject_key_id, \
                    observed_at, evidence, severity, \
                    signature, signing_key_id, signature_verified, persist_row_hash\
                 ) VALUES (?1, ?2, 'unconsented_external_probe', ?3, ?4, ?5, 'warn', \
                          'sig', 'registry-steward', 1, 'hash')",
                rusqlite::params![
                    did,
                    "tnt-test",
                    "k-suspect",
                    "2026-05-15T00:00:00+00:00",
                    "{\"probed\":\"x\"}",
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap()
        .unwrap();

        let conn = backend.conn.clone();
        let did = detection_id.clone();
        let row_exists = tokio::task::spawn_blocking(move || -> rusqlite::Result<bool> {
            let conn = conn.blocking_lock();
            let n: i64 = conn.query_row(
                "SELECT COUNT(*) FROM edge_detection_events WHERE detection_id = ?1",
                [&did],
                |r| r.get(0),
            )?;
            Ok(n == 1)
        })
        .await
        .unwrap()
        .unwrap();
        assert!(row_exists);
    }

    /// v1.3.0 (CIRISPersist#46): roles round-trip via put_public_key
    /// → lookup_public_key. Confirms the wire-shape + storage path
    /// for the per-row role tag column.
    #[tokio::test]
    async fn roles_round_trip_via_put_lookup() {
        let backend = trust_test_backend().await;
        let mut key = fed_key("k-roles", "primitive-roles", "registry-steward");
        key.roles = vec![
            "cirislens_pipeline_writer".to_owned(),
            "cirislens_secrets_reader".to_owned(),
        ];
        backend
            .put_public_key(SignedKeyRecord { record: key })
            .await
            .unwrap();
        let got = FederationDirectory::lookup_public_key(&backend, "k-roles")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.roles.len(), 2);
        assert!(got.roles.contains(&"cirislens_pipeline_writer".to_owned()));
        assert!(got.roles.contains(&"cirislens_secrets_reader".to_owned()));
    }

    // ─── Pipeline read+write tests (v1.5.8, CIRISPersist#57) ────────
    //
    // V023 parity sweep: mirrors postgres.rs::pipeline_read_features_and_
    // classifications_round_trip but on the SQLite substrate. Tests
    // cover (a) write→read round-trip, (b) NULL column → empty/None,
    // (c) UPDATE on missing-row → Ok(()) no-op.

    /// Helper: insert a trace_events row directly via raw SQL — the
    /// minimum shape needed to give the V023 UPDATEs something to
    /// land on. No-op-friendly fixture (no audit fields, no pipeline
    /// columns set; those are what the tests UPDATE).
    #[cfg(any(feature = "extract", feature = "classify"))]
    async fn insert_minimal_trace_row(backend: &SqliteBackend, trace_id: &str, thought_id: &str) {
        let conn = backend.conn.clone();
        let trace_id = trace_id.to_owned();
        let thought_id = thought_id.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO trace_events (\
                    trace_id, thought_id, event_type, attempt_index, ts, \
                    agent_id_hash, trace_level, payload, signature, \
                    signing_key_id, signature_verified, schema_version, \
                    pii_scrubbed\
                 ) VALUES (?1, ?2, 'thought_start', 0, ?3, 'deadbeef', \
                    'generic', '{}', 'sig', 'k', 1, '2.7.0', 0)",
                rusqlite::params![trace_id, thought_id, "2026-05-16T00:00:00+00:00"],
            )?;
            Ok(())
        })
        .await
        .unwrap()
        .unwrap();
    }

    #[cfg(feature = "classify")]
    fn fixture_classifications() -> Vec<Vec<crate::pipeline::classify::ContentClassMatch>> {
        vec![vec![crate::pipeline::classify::ContentClassMatch {
            class: crate::pipeline::classify::ContentClass::EmailAddress,
            method: crate::pipeline::classify::DetectionMethod::Regex,
            sensitivity: crate::pipeline::classify::Sensitivity::Medium,
            action: crate::pipeline::classify::Action::ScrubReplace,
            matcher_id: "regex:email_v1".into(),
            address: crate::pipeline::classify::MatchAddress::BatchComponent {
                index: 0,
                json_path: Some("$.task_description".into()),
            },
            span: Some((0, 16)),
            confidence: 1.0,
            learning: None,
            secret_uuid: None,
        }]]
    }

    #[cfg(feature = "extract")]
    fn fixture_features() -> crate::pipeline::extract::Features {
        let declared = crate::pipeline::extract::DeclaredCohortAxes {
            agent_role: Some("ally".into()),
            agent_template: Some("ally-v3-default".into()),
            deployment_domain: Some("moderation".into()),
            deployment_type: Some("production".into()),
            deployment_region: Some("US".into()),
            deployment_trust_mode: Some("federated_peer".into()),
        };
        crate::pipeline::extract::extract_features(&serde_json::json!({"components": []}), declared)
    }

    /// Write → read round-trip for classifications. Confirms the V023
    /// TEXT-as-JSON wire shape decodes byte-identically to the input.
    #[cfg(feature = "classify")]
    #[tokio::test]
    async fn write_then_read_classifications_round_trip() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();

        let tid = "tr-pipe-rd-cls";
        let thid = "th-pipe-rd-cls";
        insert_minimal_trace_row(&backend, tid, thid).await;

        let cls = fixture_classifications();
        backend
            .write_classifications(tid, thid, &cls)
            .await
            .unwrap();

        let got = backend.read_classifications(tid, thid).await.unwrap();
        assert_eq!(got.len(), 1, "one component classified");
        assert_eq!(got[0].len(), 1, "one match in that component");
        assert_eq!(
            got[0][0].class,
            crate::pipeline::classify::ContentClass::EmailAddress
        );
        assert_eq!(got[0][0].matcher_id, "regex:email_v1");
    }

    /// Read against a row with NULL classifications returns an empty
    /// vec (matches PG `read_classifications` contract — "no pipeline
    /// ran" is empty, not an error).
    #[cfg(feature = "classify")]
    #[tokio::test]
    async fn read_classifications_returns_empty_when_null() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();

        let tid = "tr-pipe-null-cls";
        let thid = "th-pipe-null-cls";
        insert_minimal_trace_row(&backend, tid, thid).await;
        // Note: no write_classifications call — column stays NULL.

        let got = backend.read_classifications(tid, thid).await.unwrap();
        assert!(got.is_empty(), "NULL classifications → empty vec");
    }

    /// UPDATE on a (trace_id, thought_id) that has no row affects 0
    /// rows and returns Ok(()). Documented caller contract: "set this
    /// if the row exists."
    #[cfg(feature = "classify")]
    #[tokio::test]
    async fn write_classifications_on_missing_row_is_noop() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();

        let cls = fixture_classifications();
        // No insert_minimal_trace_row — the (trace_id, thought_id)
        // pair has zero rows. UPDATE matches nothing, returns Ok(()).
        backend
            .write_classifications("tr-missing", "th-missing", &cls)
            .await
            .unwrap();

        // Confirm read still returns empty (no row at all).
        let got = backend
            .read_classifications("tr-missing", "th-missing")
            .await
            .unwrap();
        assert!(got.is_empty());
    }

    /// Write → read round-trip for features.
    #[cfg(feature = "extract")]
    #[tokio::test]
    async fn write_then_read_features_round_trip() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();

        let tid = "tr-pipe-rd-feat";
        let thid = "th-pipe-rd-feat";
        insert_minimal_trace_row(&backend, tid, thid).await;

        let features = fixture_features();
        backend.write_features(tid, thid, &features).await.unwrap();

        let got = backend
            .read_features(tid, thid)
            .await
            .unwrap()
            .expect("features present");
        assert_eq!(
            got.declared.deployment_domain.as_deref(),
            Some("moderation")
        );
        assert_eq!(got.declared.agent_role.as_deref(), Some("ally"));
    }

    /// Read against a row with NULL extracted_features returns None
    /// (matches PG `read_features` contract).
    #[cfg(feature = "extract")]
    #[tokio::test]
    async fn read_features_returns_none_when_null() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();

        let tid = "tr-pipe-null-feat";
        let thid = "th-pipe-null-feat";
        insert_minimal_trace_row(&backend, tid, thid).await;

        let got = backend.read_features(tid, thid).await.unwrap();
        assert!(got.is_none(), "NULL extracted_features → None");
    }

    /// UPDATE on a missing row is a no-op.
    #[cfg(feature = "extract")]
    #[tokio::test]
    async fn write_features_on_missing_row_is_noop() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();

        let features = fixture_features();
        backend
            .write_features("tr-missing-f", "th-missing-f", &features)
            .await
            .unwrap();

        let got = backend
            .read_features("tr-missing-f", "th-missing-f")
            .await
            .unwrap();
        assert!(got.is_none());
    }

    // ─── ReadEngine tests (sovereign-mode parity, CIRISPersist#23) ─────
    //
    // Real-data round-trips: insert trace_events / trace_llm_calls /
    // federation rows through the public Backend / FederationDirectory
    // surfaces, then call the ReadEngine primitives and assert on
    // counts, ordering, cursor paging, and aggregates.

    use crate::read::{
        AttestationFilter, CorpusShapeFilter, DeviationMetric, FederationKeyFilter, LlmCallFilter,
        ReadEngine, RevocationFilter, TaskFilter, TimeWindow, TraceFilter,
    };

    /// Flexible trace-event builder for ReadEngine tests. One event row
    /// at `ts_offset` minutes past 2026-05-01T12:00:00Z.
    #[allow(clippy::too_many_arguments)]
    fn re_event(
        trace_id: &str,
        thought_id: &str,
        task_id: Option<&str>,
        event_type: ReasoningEventType,
        ts_offset_min: i64,
        agent_id_hash: &str,
        agent_name: Option<&str>,
        deployment_domain: Option<&str>,
        payload: serde_json::Value,
    ) -> TraceEventRow {
        let base = Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap();
        let payload = match payload {
            serde_json::Value::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        TraceEventRow {
            trace_id: trace_id.to_owned(),
            thought_id: thought_id.to_owned(),
            task_id: task_id.map(str::to_owned),
            step_point: None,
            event_type,
            attempt_index: 0,
            ts: base + chrono::Duration::minutes(ts_offset_min),
            agent_name: agent_name.map(str::to_owned),
            agent_id_hash: agent_id_hash.to_owned(),
            cognitive_state: Some("WORK".to_owned()),
            trace_level: TraceLevel::Generic,
            payload,
            cost_llm_calls: Some(2),
            cost_tokens: Some(150),
            cost_usd: Some(0.01),
            signature: "sig".to_owned(),
            signing_key_id: "key-1".to_owned(),
            signature_verified: true,
            verification_source: crate::store::VerificationSource::Persist,
            schema_version: "2.7.0".to_owned(),
            pii_scrubbed: true,
            original_content_hash: Some("hash".to_owned()),
            scrub_signature: Some("scrub-sig".to_owned()),
            scrub_key_id: Some("scrub-key".to_owned()),
            scrub_timestamp: Some(base),
            agent_role: Some("ally".to_owned()),
            agent_template: Some("ally-v3".to_owned()),
            deployment_domain: deployment_domain.map(str::to_owned),
            deployment_type: Some("production".to_owned()),
            deployment_region: Some("us-east".to_owned()),
            deployment_trust_mode: None,
        }
    }

    /// Insert a 3-event trace (THOUGHT_START + CONSCIENCE_RESULT +
    /// ACTION_RESULT) with given DMA/conscience/action signal payloads.
    #[allow(clippy::too_many_arguments)]
    async fn insert_trace(
        backend: &SqliteBackend,
        trace_id: &str,
        task_id: Option<&str>,
        ts_offset_min: i64,
        agent_id_hash: &str,
        agent_name: &str,
        domain: &str,
        overridden: bool,
        csdma: f64,
        audit_seq: Option<i64>,
    ) {
        let thought_id = format!("{trace_id}-th");
        let mut rows = vec![
            re_event(
                trace_id,
                &thought_id,
                task_id,
                ReasoningEventType::ThoughtStart,
                ts_offset_min,
                agent_id_hash,
                Some(agent_name),
                Some(domain),
                serde_json::json!({
                    "thought_type": "standard",
                    "thought_depth": 0,
                    "task_description": format!("desc for {trace_id}"),
                }),
            ),
            re_event(
                trace_id,
                &thought_id,
                task_id,
                ReasoningEventType::DmaResults,
                ts_offset_min,
                agent_id_hash,
                Some(agent_name),
                Some(domain),
                serde_json::json!({ "csdma_plausibility_score": csdma }),
            ),
            re_event(
                trace_id,
                &thought_id,
                task_id,
                ReasoningEventType::ConscienceResult,
                ts_offset_min + 1,
                agent_id_hash,
                Some(agent_name),
                Some(domain),
                serde_json::json!({
                    "conscience_passed": !overridden,
                    "action_was_overridden": overridden,
                    "coherence_passed": !overridden,
                }),
            ),
        ];
        let mut action_payload = serde_json::Map::new();
        action_payload.insert("action_executed".to_owned(), serde_json::json!("speak"));
        action_payload.insert("success".to_owned(), serde_json::json!(true));
        if let Some(seq) = audit_seq {
            action_payload.insert("audit_sequence_number".to_owned(), serde_json::json!(seq));
            action_payload.insert(
                "audit_entry_hash".to_owned(),
                serde_json::json!("entry-hash"),
            );
            action_payload.insert("audit_signature".to_owned(), serde_json::json!("audit-sig"));
        }
        rows.push(re_event(
            trace_id,
            &thought_id,
            task_id,
            ReasoningEventType::ActionResult,
            ts_offset_min + 2,
            agent_id_hash,
            Some(agent_name),
            Some(domain),
            serde_json::Value::Object(action_payload),
        ));
        let report = backend.insert_trace_events_batch(&rows).await.unwrap();
        assert_eq!(report.inserted, 4, "all 4 component rows land");
    }

    #[tokio::test]
    async fn re_trace_summary_and_detail_round_trip() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        insert_trace(
            &backend,
            "tr-A",
            Some("qa_en_3"),
            0,
            "agent-h",
            "Scout",
            "legal",
            true,
            0.82,
            Some(1),
        )
        .await;

        let summary = backend.get_trace_summary("tr-A").await.unwrap().unwrap();
        assert_eq!(summary.trace_id, "tr-A");
        assert_eq!(summary.agent_id_hash, "agent-h");
        assert_eq!(summary.agent_name.as_deref(), Some("Scout"));
        assert_eq!(summary.task_id.as_deref(), Some("qa_en_3"));
        assert_eq!(summary.thought_depth, Some(0));
        assert!(summary.signature_verified);
        assert_eq!(summary.action_was_overridden, Some(true));
        assert_eq!(summary.conscience_passed, Some(false));
        assert_eq!(summary.selected_action.as_deref(), Some("speak"));
        assert!((summary.csdma_plausibility_score.unwrap() - 0.82).abs() < 1e-9);

        // Missing trace → None.
        assert!(backend
            .get_trace_summary("tr-missing")
            .await
            .unwrap()
            .is_none());

        let detail = backend.get_trace_detail("tr-A").await.unwrap().unwrap();
        assert_eq!(detail.components.len(), 4, "4 component rows");
        assert_eq!(detail.summary.trace_id, "tr-A");
        // Components are chronological.
        let ts: Vec<_> = detail.components.iter().map(|c| c.ts).collect();
        let mut sorted = ts.clone();
        sorted.sort();
        assert_eq!(ts, sorted);
        assert!(detail.envelope.pii_scrubbed);
        assert!(backend.get_trace_detail("tr-none").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn re_list_trace_summaries_pagination() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        for i in 0..5 {
            insert_trace(
                &backend,
                &format!("tr-{i}"),
                Some("qa_en_1"),
                i,
                "agent-h",
                "Scout",
                "legal",
                false,
                0.5,
                Some(i + 1),
            )
            .await;
        }
        // Page 1: limit 2 → newest-first (tr-4, tr-3).
        let page1 = backend
            .list_trace_summaries(TraceFilter::default(), None, 2)
            .await
            .unwrap();
        assert_eq!(page1.items.len(), 2);
        assert_eq!(page1.items[0].trace_id, "tr-4");
        assert_eq!(page1.items[1].trace_id, "tr-3");
        assert!(page1.next_cursor.is_some());

        // Page 2 via cursor.
        let page2 = backend
            .list_trace_summaries(TraceFilter::default(), page1.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(page2.items.len(), 2);
        assert_eq!(page2.items[0].trace_id, "tr-2");
        assert_eq!(page2.items[1].trace_id, "tr-1");

        // Page 3: last item, no further cursor.
        let page3 = backend
            .list_trace_summaries(TraceFilter::default(), page2.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(page3.items.len(), 1);
        assert_eq!(page3.items[0].trace_id, "tr-0");
        assert!(page3.next_cursor.is_none());

        // Invalid limit + bad cursor version are typed errors.
        assert!(backend
            .list_trace_summaries(TraceFilter::default(), None, 0)
            .await
            .is_err());
        let bad = crate::read::TraceCursor {
            version: "v9".to_owned(),
            last_started_at: Utc::now(),
            last_trace_id: "x".to_owned(),
        };
        assert!(backend
            .list_trace_summaries(TraceFilter::default(), Some(bad), 10)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn re_list_trace_summaries_filter() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        insert_trace(
            &backend, "tr-a", None, 0, "agent-1", "Scout", "legal", false, 0.5, None,
        )
        .await;
        insert_trace(
            &backend,
            "tr-b",
            None,
            1,
            "agent-2",
            "Echo",
            "healthcare",
            false,
            0.5,
            None,
        )
        .await;
        let filter = TraceFilter {
            agent_id_hash: Some("agent-2".to_owned()),
            ..Default::default()
        };
        let page = backend
            .list_trace_summaries(filter, None, 100)
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].trace_id, "tr-b");
    }

    #[tokio::test]
    async fn re_list_tasks_grouping() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // Task qa_en_1 has two traces; discord_x has one.
        insert_trace(
            &backend,
            "tr-1",
            Some("qa_en_1"),
            0,
            "agent-h",
            "Scout",
            "legal",
            false,
            0.5,
            None,
        )
        .await;
        insert_trace(
            &backend,
            "tr-2",
            Some("qa_en_1"),
            1,
            "agent-h",
            "Scout",
            "legal",
            false,
            0.5,
            None,
        )
        .await;
        insert_trace(
            &backend,
            "tr-3",
            Some("discord_x"),
            5,
            "agent-h",
            "Scout",
            "legal",
            false,
            0.5,
            None,
        )
        .await;
        let page = backend
            .list_tasks(TaskFilter::default(), None, 100)
            .await
            .unwrap();
        assert_eq!(page.items.len(), 2, "two distinct tasks");
        // Newest-first: discord_x (offset 5) before qa_en_1 (offset 0).
        assert_eq!(page.items[0].task_id, "discord_x");
        assert_eq!(page.items[0].task_class, crate::read::TaskClass::Discord);
        assert_eq!(page.items[1].task_id, "qa_en_1");
        assert_eq!(page.items[1].task_class, crate::read::TaskClass::QaEval);
        assert_eq!(page.items[1].traces.len(), 2, "qa_en_1 has 2 traces");
        assert!(page.items[1].initial_observation.is_some());

        // task_class filter.
        let filtered = backend
            .list_tasks(
                TaskFilter {
                    task_class: Some(crate::read::TaskClass::Discord),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(filtered.items.len(), 1);
        assert_eq!(filtered.items[0].task_id, "discord_x");
    }

    /// Insert one LLM call linked to a trace.
    async fn insert_llm(
        backend: &SqliteBackend,
        trace_id: &str,
        attempt: u32,
        model: &str,
        cost: f64,
        status: LlmCallStatus,
    ) {
        let row = TraceLlmCallRow {
            trace_id: trace_id.to_owned(),
            thought_id: format!("{trace_id}-th"),
            task_id: None,
            parent_event_id: None,
            parent_event_type: ReasoningEventType::ActionResult,
            parent_attempt_index: 0,
            attempt_index: attempt,
            ts: Utc.with_ymd_and_hms(2026, 5, 1, 12, 0, 0).unwrap()
                + chrono::Duration::seconds(i64::from(attempt)),
            duration_ms: 100.0,
            handler_name: "h".to_owned(),
            service_name: "openai".to_owned(),
            model: Some(model.to_owned()),
            base_url: None,
            response_model: None,
            prompt_tokens: Some(10),
            completion_tokens: Some(20),
            prompt_bytes: Some(40),
            completion_bytes: Some(80),
            cost_usd: Some(cost),
            status,
            error_class: None,
            attempt_count: Some(1),
            retry_count: Some(0),
            prompt_hash: Some("ph".to_owned()),
            prompt: None,
            response_text: None,
        };
        let n = backend
            .insert_trace_llm_calls_batch(std::slice::from_ref(&row))
            .await
            .unwrap();
        assert_eq!(n, 1);
    }

    #[tokio::test]
    async fn re_llm_calls_list_and_aggregate() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        insert_llm(&backend, "tr-1", 0, "gpt-4", 0.10, LlmCallStatus::Ok).await;
        insert_llm(&backend, "tr-1", 1, "gpt-4", 0.20, LlmCallStatus::Timeout).await;
        insert_llm(&backend, "tr-2", 0, "claude", 0.05, LlmCallStatus::Ok).await;

        // List newest-first; paginate.
        let page1 = backend
            .list_llm_calls(LlmCallFilter::default(), None, 2)
            .await
            .unwrap();
        assert_eq!(page1.items.len(), 2);
        assert!(page1.next_cursor.is_some());
        let page2 = backend
            .list_llm_calls(LlmCallFilter::default(), page1.next_cursor, 2)
            .await
            .unwrap();
        assert_eq!(page2.items.len(), 1);
        assert!(page2.next_cursor.is_none());

        // Filter by model.
        let claude = backend
            .list_llm_calls(
                LlmCallFilter {
                    model: Some("claude".to_owned()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(claude.items.len(), 1);

        // Aggregate.
        let agg = backend
            .aggregate_llm_costs(LlmCallFilter::default())
            .await
            .unwrap();
        assert_eq!(agg.totals.call_count, 3);
        assert_eq!(agg.totals.error_count, 1, "one timeout");
        assert!((agg.totals.cost_usd - 0.35).abs() < 1e-9);
        let gpt = agg.by_model.get("gpt-4").unwrap();
        assert_eq!(gpt.call_count, 2);
        assert_eq!(gpt.error_count, 1);
        assert!((gpt.cost_usd - 0.30).abs() < 1e-9);
        let claude_model = agg.by_model.get("claude").unwrap();
        assert_eq!(claude_model.call_count, 1);
    }

    #[tokio::test]
    async fn re_corpus_shape() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        insert_trace(
            &backend,
            "tr-1",
            Some("qa_en_1"),
            0,
            "agent-h",
            "Scout",
            "legal",
            false,
            0.5,
            None,
        )
        .await;
        insert_trace(
            &backend,
            "tr-2",
            Some("qa_fr_2"),
            1,
            "agent-h",
            "Scout",
            "legal",
            false,
            0.5,
            None,
        )
        .await;
        insert_trace(
            &backend,
            "tr-3",
            Some("discord_x"),
            2,
            "agent-h",
            "Scout",
            "legal",
            false,
            0.5,
            None,
        )
        .await;
        insert_llm(&backend, "tr-1", 0, "gpt-4", 0.1, LlmCallStatus::Ok).await;
        let window = TimeWindow::new(
            Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 5, 2, 0, 0, 0).unwrap(),
        )
        .unwrap();
        let shape = backend
            .corpus_shape(CorpusShapeFilter {
                time_window: window,
                agent_id_hash: None,
                agent_name: None,
                deployment_domain: None,
            })
            .await
            .unwrap();
        assert_eq!(shape.total_traces, 3);
        assert_eq!(
            *shape
                .by_task_class
                .get(&crate::read::TaskClass::QaEval)
                .unwrap(),
            2
        );
        assert_eq!(
            *shape
                .by_task_class
                .get(&crate::read::TaskClass::Discord)
                .unwrap(),
            1
        );
        assert_eq!(*shape.by_qa_language.get("en").unwrap(), 1);
        assert_eq!(*shape.by_qa_language.get("fr").unwrap(), 1);
        assert_eq!(*shape.by_qa_question_num.get(&1).unwrap(), 1);
        assert_eq!(*shape.by_agent_name.get("Scout").unwrap(), 3);
        assert_eq!(*shape.by_agent_version.get("ally-v3").unwrap(), 3);
        assert_eq!(*shape.by_deployment_region.get("us-east").unwrap(), 3);
        assert_eq!(*shape.by_primary_model.get("gpt-4").unwrap(), 1);
    }

    #[tokio::test]
    async fn re_scrub_stats() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        insert_trace(
            &backend, "tr-1", None, 0, "agent-h", "Scout", "legal", false, 0.5, None,
        )
        .await;
        let window = TimeWindow::new(
            Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 5, 2, 0, 0, 0).unwrap(),
        )
        .unwrap();
        let scrub = backend.aggregate_scrub_stats(window).await.unwrap();
        assert_eq!(scrub.envelopes_scrubbed, 1);
        assert_eq!(
            *scrub
                .by_trace_level
                .get(&crate::schema::TraceLevel::Generic)
                .unwrap(),
            1
        );
        assert_eq!(scrub.fields_scrubbed_total, 0);
    }

    #[tokio::test]
    async fn re_federation_lists() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-a", "agent-a", "k-a"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-b", "agent-b", "k-a"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fed_attestation("att-1", "k-a", "k-b", "k-a"),
            })
            .await
            .unwrap();
        backend
            .put_revocation(SignedRevocation {
                revocation: fed_revocation("rev-1", "k-b", "k-a", "k-a"),
            })
            .await
            .unwrap();

        let keys = backend
            .list_federation_keys(FederationKeyFilter::default(), None, 100)
            .await
            .unwrap();
        assert_eq!(keys.items.len(), 2);

        // revoked filter: k-b appears in federation_revocations.
        let revoked = backend
            .list_federation_keys(
                FederationKeyFilter {
                    revoked: Some(true),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(revoked.items.len(), 1);
        assert_eq!(revoked.items[0].key_id, "k-b");

        let atts = backend
            .list_attestations(AttestationFilter::default(), None, 100)
            .await
            .unwrap();
        assert_eq!(atts.items.len(), 1);
        assert_eq!(atts.items[0].attestation_id, "att-1");

        let revs = backend
            .list_revocations(RevocationFilter::default(), None, 100)
            .await
            .unwrap();
        assert_eq!(revs.items.len(), 1);
        assert_eq!(revs.items[0].revocation_id, "rev-1");
    }

    #[tokio::test]
    async fn re_cross_agent_divergence() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // Three agents in one domain; agent-3 is an outlier.
        insert_trace(
            &backend, "t1", None, 0, "agent-1", "A1", "legal", false, 0.50, None,
        )
        .await;
        insert_trace(
            &backend, "t2", None, 1, "agent-2", "A2", "legal", false, 0.52, None,
        )
        .await;
        insert_trace(
            &backend, "t3", None, 2, "agent-3", "A3", "legal", false, 0.99, None,
        )
        .await;
        let window = TimeWindow::new(
            Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 5, 2, 0, 0, 0).unwrap(),
        )
        .unwrap();
        let rows = backend
            .cross_agent_divergence("legal", window, DeviationMetric::CsdmaPlausibility)
            .await
            .unwrap();
        assert_eq!(rows.len(), 3);
        // Most-divergent first — agent-3.
        assert_eq!(rows[0].agent_id_hash, "agent-3");
        assert!(rows[0].z_score.abs() > rows[1].z_score.abs());
    }

    #[tokio::test]
    async fn re_temporal_drift() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // Baseline window: low csdma. Comparison window: high csdma.
        insert_trace(
            &backend, "b1", None, 0, "agent-h", "Scout", "legal", false, 0.30, None,
        )
        .await;
        insert_trace(
            &backend, "b2", None, 5, "agent-h", "Scout", "legal", false, 0.32, None,
        )
        .await;
        insert_trace(
            &backend, "c1", None, 120, "agent-h", "Scout", "legal", false, 0.80, None,
        )
        .await;
        insert_trace(
            &backend, "c2", None, 125, "agent-h", "Scout", "legal", false, 0.82, None,
        )
        .await;
        let base = TimeWindow::new(
            Utc.with_ymd_and_hms(2026, 5, 1, 11, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 5, 1, 13, 0, 0).unwrap(),
        )
        .unwrap();
        let comp = TimeWindow::new(
            Utc.with_ymd_and_hms(2026, 5, 1, 13, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 5, 1, 15, 0, 0).unwrap(),
        )
        .unwrap();
        let drift = backend.temporal_drift("agent-h", base, comp).await.unwrap();
        let csdma = drift
            .iter()
            .find(|r| r.deviation_metric == DeviationMetric::CsdmaPlausibility)
            .unwrap();
        assert!(csdma.mean_shift > 0.4, "csdma rose ~0.5");
        assert!(csdma.significance > 0.0);
    }

    #[tokio::test]
    async fn re_hash_chain_gaps() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // audit_sequence_number 1, 2, then 5 — a gap (2 → 5).
        insert_trace(
            &backend,
            "t1",
            None,
            0,
            "agent-h",
            "Scout",
            "legal",
            false,
            0.5,
            Some(1),
        )
        .await;
        insert_trace(
            &backend,
            "t2",
            None,
            1,
            "agent-h",
            "Scout",
            "legal",
            false,
            0.5,
            Some(2),
        )
        .await;
        insert_trace(
            &backend,
            "t3",
            None,
            2,
            "agent-h",
            "Scout",
            "legal",
            false,
            0.5,
            Some(5),
        )
        .await;
        let window = TimeWindow::new(
            Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 5, 2, 0, 0, 0).unwrap(),
        )
        .unwrap();
        let gaps = backend.hash_chain_gaps("agent-h", window).await.unwrap();
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].gap_start_seq, 2);
        assert_eq!(gaps[0].gap_end_seq, 5);
    }

    #[tokio::test]
    async fn re_conscience_override_rates() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // agent-1: 1 of 2 overridden. agent-2: 0 of 1.
        insert_trace(
            &backend, "t1", None, 0, "agent-1", "A1", "legal", true, 0.5, None,
        )
        .await;
        insert_trace(
            &backend, "t2", None, 1, "agent-1", "A1", "legal", false, 0.5, None,
        )
        .await;
        insert_trace(
            &backend, "t3", None, 2, "agent-2", "A2", "legal", false, 0.5, None,
        )
        .await;
        let window = TimeWindow::new(
            Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 5, 2, 0, 0, 0).unwrap(),
        )
        .unwrap();
        let rates = backend
            .conscience_override_rates("legal", window)
            .await
            .unwrap();
        assert_eq!(rates.len(), 2);
        let a1 = rates.iter().find(|r| r.agent_id_hash == "agent-1").unwrap();
        assert_eq!(a1.override_count, 1);
        assert_eq!(a1.trace_count, 2);
        assert!((a1.override_rate - 0.5).abs() < 1e-9);
        let a2 = rates.iter().find(|r| r.agent_id_hash == "agent-2").unwrap();
        assert_eq!(a2.override_count, 0);
        // Domain avg = 1 override / 3 traces.
        assert!((a1.domain_avg_rate - (1.0 / 3.0)).abs() < 1e-9);
    }

    #[tokio::test]
    async fn re_scoring_factors_and_counts() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        insert_trace(
            &backend,
            "t1",
            None,
            0,
            "agent-h",
            "Scout",
            "legal",
            true,
            0.30,
            Some(1),
        )
        .await;
        insert_trace(
            &backend,
            "t2",
            None,
            10,
            "agent-h",
            "Scout",
            "legal",
            false,
            0.40,
            Some(2),
        )
        .await;
        insert_trace(
            &backend,
            "t3",
            None,
            20,
            "agent-h",
            "Scout",
            "legal",
            false,
            0.50,
            Some(4),
        )
        .await;
        let window = TimeWindow::new(
            Utc.with_ymd_and_hms(2026, 5, 1, 0, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 5, 2, 0, 0, 0).unwrap(),
        )
        .unwrap();
        let agg = backend
            .aggregate_scoring_factors("agent-h", window, None)
            .await
            .unwrap();
        assert_eq!(agg.trace_count, 3);
        assert_eq!(agg.conscience_overrides, 1);
        assert_eq!(agg.audit_chain_total, 3);
        assert_eq!(agg.audit_signed_total, 3);
        assert_eq!(agg.audit_chain_gaps, 1, "seq 2 → 4 is a gap");
        // t1 overridden then t2 passes coherence → one recovery event.
        assert_eq!(agg.recovery_events.len(), 1);
        assert_eq!(agg.recovery_events[0].override_trace_id, "t1");
        assert_eq!(agg.recovery_events[0].recovery_trace_id, "t2");
        assert!(agg.drift_z_score.is_none());
        assert!(!agg.coherence_decay_series.is_empty());

        // Batch variant.
        let batch = backend
            .aggregate_scoring_factors_batch(
                &["agent-h".to_owned(), "agent-x".to_owned()],
                window,
                None,
            )
            .await
            .unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].trace_count, 3);
        assert_eq!(batch[1].trace_count, 0, "unknown agent → empty");

        // Granular counts.
        assert_eq!(
            backend.count_traces(TraceFilter::default()).await.unwrap(),
            3
        );
        assert_eq!(
            backend
                .count_overrides(TraceFilter::default())
                .await
                .unwrap(),
            1
        );
        let id_changes = backend
            .count_identity_changes(TraceFilter::default())
            .await
            .unwrap();
        assert_eq!(id_changes, 0, "single agent_name → 0 changes");

        // Audit chain aggregate (agent-pinned → gap detected).
        let chain = backend
            .aggregate_audit_chain(TraceFilter {
                agent_id_hash: Some("agent-h".to_owned()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(chain.audit_total, 3);
        assert_eq!(chain.audit_signed, 3);
        assert_eq!(chain.audit_hashed, 3);
        assert_eq!(chain.gap_count, 1);

        // Without agent pin → gap_count documented as 0.
        let chain_unpinned = backend
            .aggregate_audit_chain(TraceFilter::default())
            .await
            .unwrap();
        assert_eq!(chain_unpinned.audit_total, 3);
        assert_eq!(chain_unpinned.gap_count, 0);
    }

    #[tokio::test]
    async fn re_scoring_factors_drift_with_baseline() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        insert_trace(
            &backend, "b1", None, 0, "agent-h", "Scout", "legal", false, 0.30, None,
        )
        .await;
        insert_trace(
            &backend, "b2", None, 5, "agent-h", "Scout", "legal", false, 0.32, None,
        )
        .await;
        insert_trace(
            &backend, "c1", None, 120, "agent-h", "Scout", "legal", false, 0.80, None,
        )
        .await;
        insert_trace(
            &backend, "c2", None, 125, "agent-h", "Scout", "legal", false, 0.82, None,
        )
        .await;
        let baseline = TimeWindow::new(
            Utc.with_ymd_and_hms(2026, 5, 1, 11, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 5, 1, 13, 0, 0).unwrap(),
        )
        .unwrap();
        let window = TimeWindow::new(
            Utc.with_ymd_and_hms(2026, 5, 1, 13, 0, 0).unwrap(),
            Utc.with_ymd_and_hms(2026, 5, 1, 15, 0, 0).unwrap(),
        )
        .unwrap();
        let agg = backend
            .aggregate_scoring_factors("agent-h", window, Some(baseline))
            .await
            .unwrap();
        assert_eq!(agg.trace_count, 2);
        assert!(
            agg.drift_z_score.is_some(),
            "baseline supplied → drift z-score computed"
        );
    }

    // ─── DerivedSchema (cirislens_derived) round-trips ─────────────

    use crate::derived::{
        CalibrationBundle, ConformityVariant, DerivedSchema, DetectionEvent, DetectionSeverity,
        EventFilter,
    };

    fn de_fixture(detection_id: uuid::Uuid, trace_id: &str, canonical: &[u8]) -> DetectionEvent {
        DetectionEvent {
            detection_id,
            trace_id: trace_id.to_owned(),
            body_sha256: vec![7u8; 32],
            detector: "manifold_conformity_outlier".to_owned(),
            severity: DetectionSeverity::Warning,
            cohort_cell: serde_json::json!({"deployment_domain": "legal"}),
            conformity_variant: ConformityVariant::Numeric,
            conformity_payload: serde_json::json!({"score": 3.1}),
            lens_core_version: "lc-1.0.0".to_owned(),
            ratchet_calibration_version: 4,
            canonical_bytes: canonical.to_vec(),
            ed25519_sig: vec![1u8; 64],
            ml_dsa_65_sig: vec![2u8; 3309],
            signing_key_id: "key-lens".to_owned(),
            ts: Utc.with_ymd_and_hms(2026, 5, 10, 12, 0, 0).unwrap(),
        }
    }

    fn cb_fixture(version: i32, is_current: bool, canonical: &[u8]) -> CalibrationBundle {
        CalibrationBundle {
            ratchet_calibration_version: version,
            projection_version: "crc-v1".to_owned(),
            calibrated_at: Utc.with_ymd_and_hms(2026, 5, 9, 9, 0, 0).unwrap(),
            calibration_corpus_sha256: "abc123".to_owned(),
            calibration_corpus_n: 5000,
            sample_size_gate: 30,
            manifold_threshold_global: 2.5,
            projection_metadata: serde_json::json!({"field_order": ["a", "b"]}),
            cohort_centroids: serde_json::json!([{"cohort": "legal"}]),
            is_current,
            canonical_bytes: canonical.to_vec(),
            ed25519_sig: vec![3u8; 64],
            ml_dsa_65_sig: vec![4u8; 3309],
            signing_key_id: "key-ratchet".to_owned(),
            inserted_at: Utc.with_ymd_and_hms(2026, 5, 9, 9, 5, 0).unwrap(),
        }
    }

    #[tokio::test]
    async fn de_detection_event_round_trip_and_filter() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let id_a = uuid::Uuid::new_v4();
        let id_b = uuid::Uuid::new_v4();
        backend
            .put_detection_event(de_fixture(id_a, "tr-A", b"canon-A"))
            .await
            .unwrap();
        backend
            .put_detection_event(de_fixture(id_b, "tr-B", b"canon-B"))
            .await
            .unwrap();

        let all = backend
            .get_detection_events(EventFilter::default())
            .await
            .unwrap();
        assert_eq!(all.len(), 2);
        let got = all.iter().find(|e| e.detection_id == id_a).unwrap();
        assert_eq!(got.trace_id, "tr-A");
        assert_eq!(got.severity, DetectionSeverity::Warning);
        assert_eq!(got.conformity_variant, ConformityVariant::Numeric);
        assert_eq!(got.canonical_bytes, b"canon-A");
        assert_eq!(got.ml_dsa_65_sig.len(), 3309);

        let filtered = backend
            .get_detection_events(EventFilter {
                trace_id: Some("tr-B".to_owned()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].detection_id, id_b);
    }

    #[tokio::test]
    async fn de_detection_event_idempotent_then_conflict() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = uuid::Uuid::new_v4();
        backend
            .put_detection_event(de_fixture(id, "tr-A", b"canon-A"))
            .await
            .unwrap();
        // Same id, same canonical_bytes → idempotent no-op.
        backend
            .put_detection_event(de_fixture(id, "tr-A", b"canon-A"))
            .await
            .unwrap();
        assert_eq!(
            backend
                .get_detection_events(EventFilter::default())
                .await
                .unwrap()
                .len(),
            1
        );
        // Same id, different canonical_bytes → Conflict.
        let err = backend
            .put_detection_event(de_fixture(id, "tr-A", b"canon-DIFFERENT"))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::derived::Error::Conflict(_)));
    }

    #[tokio::test]
    async fn de_detection_event_rejects_bad_signature_length() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let mut ev = de_fixture(uuid::Uuid::new_v4(), "tr-A", b"canon-A");
        ev.ed25519_sig = vec![0u8; 63];
        let err = backend.put_detection_event(ev).await.unwrap_err();
        assert!(matches!(err, crate::derived::Error::InvalidArgument(_)));
    }

    #[tokio::test]
    async fn de_calibration_bundle_atomic_current_flip() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_calibration_bundle(cb_fixture(1, true, b"bundle-1"))
            .await
            .unwrap();
        assert_eq!(
            backend
                .get_current_calibration_bundle()
                .await
                .unwrap()
                .unwrap()
                .ratchet_calibration_version,
            1
        );
        // New current bundle: prior current must flip off atomically.
        backend
            .put_calibration_bundle(cb_fixture(2, true, b"bundle-2"))
            .await
            .unwrap();
        let current = backend
            .get_current_calibration_bundle()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(current.ratchet_calibration_version, 2);
        assert!(current.is_current);

        let v1 = backend
            .get_calibration_bundle_by_version(1)
            .await
            .unwrap()
            .unwrap();
        assert!(!v1.is_current, "v1 flipped off when v2 became current");
        assert_eq!(v1.projection_version, "crc-v1");
        assert_eq!(v1.manifold_threshold_global, 2.5);

        assert!(backend
            .get_calibration_bundle_by_version(99)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn de_calibration_bundle_conflict_on_different_canonical() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_calibration_bundle(cb_fixture(1, true, b"bundle-1"))
            .await
            .unwrap();
        // Same version, same canonical → idempotent.
        backend
            .put_calibration_bundle(cb_fixture(1, true, b"bundle-1"))
            .await
            .unwrap();
        // Same version, different canonical → Conflict.
        let err = backend
            .put_calibration_bundle(cb_fixture(1, true, b"bundle-CHANGED"))
            .await
            .unwrap_err();
        assert!(matches!(err, crate::derived::Error::Conflict(_)));
    }
}
