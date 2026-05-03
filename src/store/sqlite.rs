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
                original_content_hash, scrub_signature, scrub_key_id, scrub_timestamp, \
                agent_role, agent_template, deployment_domain, \
                deployment_type, deployment_region, deployment_trust_mode\
                ) VALUES (\
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, \
                ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27, \
                ?28, ?29, ?30, ?31, ?32, ?33\
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

                    let params: [SqlValue; 33] = [
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
        // v0.2.1 — dual-read migration. Try federation_keys first
        // (v0.2.0 federation directory), fall back to
        // accord_public_keys (legacy). Same pattern as PostgresBackend.
        let key_id = key_id.to_owned();
        let conn = self.conn.clone();
        let b64_opt =
            tokio::task::spawn_blocking(move || -> Result<Option<String>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                // federation_keys first.
                let fed = conn
                    .query_row(
                        "SELECT pubkey_ed25519_base64 FROM federation_keys \
                         WHERE key_id = ?1 \
                           AND (valid_until IS NULL OR valid_until > CURRENT_TIMESTAMP)",
                        [&key_id],
                        |r| r.get::<_, String>(0),
                    )
                    .optional()?;
                if fed.is_some() {
                    return Ok(fed);
                }
                // Fall back to accord_public_keys (legacy).
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
                        deployment_trust_mode";
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

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO federation_keys (\
                    key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                    identity_type, identity_ref, valid_from, valid_until, registration_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
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
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
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
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
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
        let rows = tokio::task::spawn_blocking(move || -> Result<Vec<crate::outbound::OutboundRow>, rusqlite::Error> {
            let mut conn = conn.blocking_lock();
            let tx = conn.transaction()?;
            let queue_ids: Vec<String> = {
                let mut stmt = tx.prepare(
                    "SELECT queue_id FROM edge_outbound_queue \
                     WHERE status = 'pending' AND next_attempt_after <= ?1 \
                     ORDER BY next_attempt_after ASC LIMIT ?2",
                )?;
                let rows = stmt.query_map(
                    rusqlite::params![now.to_rfc3339(), batch_size],
                    |r| r.get::<_, String>(0),
                )?;
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
        })
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
        let outcome = tokio::task::spawn_blocking(move || -> Result<crate::outbound::OutboundFailureOutcome, rusqlite::Error> {
            let mut conn = conn.blocking_lock();
            let tx = conn.transaction()?;
            let (attempt_count, max_attempts, enqueued_at_str, ttl_seconds): (i32, i32, String, i64) = tx
                .query_row(
                    "SELECT attempt_count, max_attempts, enqueued_at, ttl_seconds \
                     FROM edge_outbound_queue \
                     WHERE queue_id = ?1 AND status = 'sending'",
                    [&qid],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                ).map_err(|e| {
                    if matches!(e, rusqlite::Error::QueryReturnedNoRows) {
                        // surface a sentinel error so the caller can map to InvalidTransition
                        rusqlite::Error::QueryReturnedNoRows
                    } else { e }
                })?;
            let enqueued_at = parse_rfc3339(&enqueued_at_str);
            let ttl_expired = (now - enqueued_at) > chrono::Duration::seconds(ttl_seconds);
            let attempts_exhausted = attempt_count >= max_attempts;
            let outcome = if ttl_expired || attempts_exhausted {
                let reason = if ttl_expired { "ttl_expired" } else { "max_attempts" };
                tx.execute(
                    "UPDATE edge_outbound_queue \
                     SET status = 'abandoned', abandoned_at = ?1, abandoned_reason = ?2, \
                         last_error_class = ?3, last_error_detail = ?4, last_transport = ?5, \
                         claimed_until = NULL, claimed_by = NULL \
                     WHERE queue_id = ?6",
                    rusqlite::params![now.to_rfc3339(), reason, error_class, error_detail, transport, qid],
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
                crate::outbound::OutboundFailureOutcome::Retrying { attempt: attempt_count }
            };
            tx.commit()?;
            Ok(outcome)
        })
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("spawn_blocking: {e}")))?
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                crate::outbound::Error::InvalidTransition(format!(
                    "queue_id {queue_id} not in 'sending'"
                ))
            }
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
            let candidates: Vec<(String, String, Option<i64>, i32, i32, String, i64)> = {
                let mut stmt = tx.prepare(
                    "SELECT queue_id, transport_delivered_at, ack_timeout_seconds, \
                            attempt_count, max_attempts, enqueued_at, ttl_seconds \
                     FROM edge_outbound_queue WHERE status = 'awaiting_ack'",
                )?;
                let rows = stmt.query_map([], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
                })?;
                rows.collect::<Result<Vec<_>, _>>()?
            };
            let mut count = 0i64;
            for (qid, transport_delivered_str, ack_timeout, attempt, max_attempts, enqueued_str, ttl) in candidates {
                let transport_delivered = parse_rfc3339(&transport_delivered_str);
                let Some(timeout) = ack_timeout else { continue };
                if (now - transport_delivered) <= chrono::Duration::seconds(timeout) {
                    continue;
                }
                let enqueued = parse_rfc3339(&enqueued_str);
                let ttl_expired = (now - enqueued) > chrono::Duration::seconds(ttl);
                let attempts_exhausted = attempt >= max_attempts;
                if ttl_expired || attempts_exhausted {
                    let reason = if ttl_expired { "ttl_expired" } else { "max_attempts" };
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
        tokio::task::spawn_blocking(move || -> rusqlite::Result<Option<crate::outbound::OutboundRow>> {
            let conn = conn.blocking_lock();
            let sql = format!("{SQLITE_OUTBOUND_SELECT_PREFIX} WHERE queue_id = ?1");
            let mut stmt = conn.prepare(&sql)?;
            stmt.query_row([&qid], sqlite_row_to_outbound_row)
                .optional()
        })
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
        tokio::task::spawn_blocking(move || -> rusqlite::Result<Vec<crate::outbound::OutboundRow>> {
            let conn = conn.blocking_lock();
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(binds.iter()), sqlite_row_to_outbound_row)?
                .collect::<Result<Vec<_>, _>>()?;
            Ok(rows)
        })
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
    let status = OutboundStatus::from_str(&status_str).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            8,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::other(format!("unknown status: {status_str}"))),
        )
    })?;
    let abandoned_reason_str: Option<String> = row.get("abandoned_reason")?;
    let abandoned_reason = match abandoned_reason_str.as_deref() {
        Some(s) => Some(AbandonedReason::from_str(s).ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                15,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::other(format!("unknown abandoned_reason: {s}"))),
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

        // Disambiguate: both Backend and FederationDirectory traits
        // expose `lookup_public_key` post-v0.2.0. This test exercises
        // the legacy Backend (VerifyingKey) shape used by the trace
        // verify path.
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

        assert!(Backend::lookup_public_key(&backend, "key-active")
            .await
            .unwrap()
            .is_some());
        assert!(Backend::lookup_public_key(&backend, "key-revoked")
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
}
