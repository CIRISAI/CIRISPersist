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
    /// v2.3 (CIRISPersist#103) — inline-byte cap for the BlobStorage
    /// trait's `put_blob`. Defaults to
    /// [`crate::federation::DEFAULT_INLINE_BYTES_CAP`]; an Engine
    /// builder may override via [`SqliteBackend::with_inline_bytes_cap`].
    inline_bytes_cap: std::sync::atomic::AtomicUsize,
    /// v2.5.0 (CIRISPersist#102 Ask 4) — per-axis envelope-schema
    /// resolver. The default is
    /// [`crate::federation::NoOpSchemaResolver`], which makes the
    /// admission hook a no-op (existing `put_attestation` callers
    /// don't break). Override via [`SqliteBackend::set_schema_resolver`].
    schema_resolver: std::sync::RwLock<std::sync::Arc<dyn crate::federation::SchemaResolver>>,
    /// v2.5.0 (CIRISPersist#102 Ask 8) — hardware-attestation policy
    /// for accord-holder `put_public_key` admission.
    hardware_attestation_policy:
        std::sync::RwLock<std::sync::Arc<crate::federation::HardwareAttestationPolicy>>,
    /// v3.4.0 (CIRISPersist#123) — trust-weighted admission gate.
    /// `None` = no gate (bootstrap-permissive). See
    /// [`SqliteBackend::set_admission_gate`].
    admission_gate: std::sync::RwLock<Option<crate::federation::AdmissionGate>>,
    /// v3.6.0 (CIRISPersist#134) — perceptual-hash matcher for the
    /// `put_blob_signing` admission hook. `None` = no hook (default).
    perceptual_hash_matcher: std::sync::RwLock<Option<crate::federation::SharedMatcher>>,
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
        Self {
            conn,
            inline_bytes_cap: std::sync::atomic::AtomicUsize::new(
                crate::federation::DEFAULT_INLINE_BYTES_CAP,
            ),
            schema_resolver: std::sync::RwLock::new(std::sync::Arc::new(
                crate::federation::NoOpSchemaResolver,
            )),
            hardware_attestation_policy: std::sync::RwLock::new(std::sync::Arc::new(
                crate::federation::HardwareAttestationPolicy::default(),
            )),
            admission_gate: std::sync::RwLock::new(None),
            perceptual_hash_matcher: std::sync::RwLock::new(None),
        }
    }

    /// v3.4.0 (CIRISPersist#123) — install the trust-weighted
    /// [`AdmissionGate`](crate::federation::AdmissionGate). Passing
    /// `None` clears the gate (bootstrap-permissive).
    pub fn set_admission_gate(&self, gate: Option<crate::federation::AdmissionGate>) {
        *self
            .admission_gate
            .write()
            .unwrap_or_else(|p| p.into_inner()) = gate;
    }

    /// Snapshot of the currently-installed admission gate, if any.
    pub fn admission_gate(&self) -> Option<crate::federation::AdmissionGate> {
        self.admission_gate
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// v3.6.0 (CIRISPersist#134) — install the perceptual-hash matcher
    /// consulted by `put_blob_signing` for inline-body writes. `None`
    /// removes the hook (the default state).
    pub fn set_perceptual_hash_matcher(&self, matcher: Option<crate::federation::SharedMatcher>) {
        *self
            .perceptual_hash_matcher
            .write()
            .unwrap_or_else(|p| p.into_inner()) = matcher;
    }

    /// v2.5.0 (CIRISPersist#102 Ask 4) — install a per-axis
    /// envelope-schema resolver for the `put_attestation` admission
    /// hook.
    pub fn set_schema_resolver(
        &self,
        resolver: std::sync::Arc<dyn crate::federation::SchemaResolver>,
    ) {
        *self
            .schema_resolver
            .write()
            .unwrap_or_else(|p| p.into_inner()) = resolver;
    }

    /// Snapshot the currently-installed schema resolver.
    pub fn schema_resolver(&self) -> std::sync::Arc<dyn crate::federation::SchemaResolver> {
        self.schema_resolver
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// v2.5.0 (CIRISPersist#102 Ask 8) — install a custom
    /// hardware-attestation policy.
    pub fn set_hardware_attestation_policy(
        &self,
        policy: std::sync::Arc<crate::federation::HardwareAttestationPolicy>,
    ) {
        *self
            .hardware_attestation_policy
            .write()
            .unwrap_or_else(|p| p.into_inner()) = policy;
    }

    /// Snapshot the currently-installed hardware-attestation policy.
    pub fn hardware_attestation_policy(
        &self,
    ) -> std::sync::Arc<crate::federation::HardwareAttestationPolicy> {
        self.hardware_attestation_policy
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// v2.3 (CIRISPersist#103) — override the default inline-byte cap
    /// for the [`crate::federation::BlobStorage`] trait's `put_blob`.
    /// Callers larger than the cap on the `Inline` arm receive
    /// [`crate::federation::BlobError::InlineSizeExceeded`].
    pub fn with_inline_bytes_cap(self, cap: usize) -> Self {
        self.inline_bytes_cap
            .store(cap, std::sync::atomic::Ordering::Relaxed);
        self
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
            inline_bytes_cap: std::sync::atomic::AtomicUsize::new(
                crate::federation::DEFAULT_INLINE_BYTES_CAP,
            ),
            schema_resolver: std::sync::RwLock::new(std::sync::Arc::new(
                crate::federation::NoOpSchemaResolver,
            )),
            hardware_attestation_policy: std::sync::RwLock::new(std::sync::Arc::new(
                crate::federation::HardwareAttestationPolicy::default(),
            )),
            admission_gate: std::sync::RwLock::new(None),
            perceptual_hash_matcher: std::sync::RwLock::new(None),
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

#[async_trait::async_trait]
impl crate::federation::FederationDirectory for SqliteBackend {
    async fn put_public_key(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<(), crate::federation::Error> {
        let mut row = record.record;

        // v2.5.0 (CIRISPersist#102 Ask 8) — hardware-attestation
        // admission gate for accord_holder rows. Runs BEFORE
        // persist_row_hash + INSERT so rejected rows leave no trace.
        if row.identity_type == crate::federation::types::identity_type::ACCORD_HOLDER {
            self.hardware_attestation_policy().check(
                &row.key_id,
                row.attestation_evidence.as_ref(),
                chrono::Utc::now(),
            )?;
        }

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
        // v2.5.0 (CIRISPersist#102 Ask 8) — attestation_evidence
        // serialized to TEXT for the JSON-on-SQLite convention.
        // Non-accord-holder rows + accord-holder rows with no
        // evidence (rejected above) both serialize to None.
        let attestation_evidence_text: Option<String> = match &row.attestation_evidence {
            Some(v) => Some(serde_json::to_string(v).map_err(|e| {
                crate::federation::Error::Backend(format!("attestation_evidence serialize: {e}"))
            })?),
            None => None,
        };

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
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles, \
                    attestation_evidence\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
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
                    attestation_evidence_text,
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
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles, \
                        attestation_evidence \
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
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles, \
                        attestation_evidence \
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

    /// v2.6.0 (CIRISPersist#105) — enumerate `federation_keys` rows
    /// by `identity_type` column. `ORDER BY key_id` for stable lex
    /// order; V004's composite index `(identity_type, identity_ref)`
    /// already covers the `WHERE identity_type = ?` lookup.
    async fn list_keys_by_identity_type(
        &self,
        identity_type: &str,
    ) -> Result<Vec<crate::federation::KeyRecord>, crate::federation::Error> {
        let conn = self.conn.clone();
        let identity_type = identity_type.to_owned();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::federation::KeyRecord>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(
                    "SELECT key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                        identity_type, identity_ref, valid_from, valid_until, registration_envelope, \
                        original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles, \
                        attestation_evidence \
                     FROM federation_keys WHERE identity_type = ?1 \
                     ORDER BY key_id",
                )?;
                let rows = stmt.query_map([&identity_type], sqlite_row_to_key_record)?;
                rows.collect()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            crate::federation::Error::Backend(format!("list_keys_by_identity_type: {e}"))
        })
    }

    async fn put_attestation(
        &self,
        attestation: crate::federation::SignedAttestation,
    ) -> Result<(), crate::federation::Error> {
        let mut row = attestation.attestation;

        // v3.4.0 (CIRISPersist#123) — trust-threshold gate runs FIRST.
        // Trust is the cheapest reject AND the one that leaks the
        // least information; an unauthorized writer shouldn't learn
        // about FK / envelope-schema state past the gate.
        if !row.attesting_key_id.is_empty() {
            if let Some(gate) = self.admission_gate() {
                gate.check_federation(&row.attesting_key_id).await?;
            }
        }

        // v2.4.0 (CIRISPersist#102 Ask 3) — admission gate. Look up
        // the attesting key's `identity_type` before insert; let
        // the FK violation surface as a clearer-typed
        // `InvalidArgument` if the key is missing. The gate runs
        // BEFORE persist_row_hash + INSERT so rejected rows leave
        // no trace.
        let attesting_identity_type = {
            let conn = self.conn.clone();
            let attesting = row.attesting_key_id.clone();
            tokio::task::spawn_blocking(move || -> Result<Option<String>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                conn.query_row(
                    "SELECT identity_type FROM federation_keys WHERE key_id = ?1",
                    [&attesting],
                    |r| r.get::<_, String>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
            .map_err(|e| {
                crate::federation::Error::Backend(format!("lookup attesting identity_type: {e}"))
            })?
        };
        let attesting_identity_type = attesting_identity_type.ok_or_else(|| {
            crate::federation::Error::InvalidArgument(format!(
                "attesting_key_id {} does not exist in federation_keys",
                row.attesting_key_id
            ))
        })?;
        let dim = crate::federation::admission::envelope_dimension(&row.attestation_envelope);
        crate::federation::admission::DimensionAdmissionPolicy::default().check(
            &row.attestation_type,
            dim,
            &attesting_identity_type,
        )?;

        // v3.0.0 (CIRISPersist#116, CEG 0.2 §6.1) — structural-composer
        // dedup on `(references_attestation_id, attestation_type,
        // attesting_key_id)`. Look up the candidate row's
        // references-id from its envelope; if a row with the same
        // triple already exists, the second put is a silent no-op
        // (structural composers are idempotent on replay per §6.1).
        if crate::federation::precedence::is_structural_composer(&row.attestation_type) {
            if let Some(ref_id) =
                crate::federation::precedence::references_attestation_id_from_envelope(
                    &row.attestation_envelope,
                )
            {
                let conn = self.conn.clone();
                let attestation_type_owned = row.attestation_type.clone();
                let attesting_owned = row.attesting_key_id.clone();
                let ref_id_owned = ref_id.to_owned();
                let dup_exists =
                    tokio::task::spawn_blocking(move || -> Result<bool, rusqlite::Error> {
                        let conn = conn.blocking_lock();
                        let mut stmt = conn.prepare(
                            "SELECT attestation_envelope FROM federation_attestations \
                         WHERE attestation_type = ?1 AND attesting_key_id = ?2",
                        )?;
                        let rows = stmt.query_map(
                            rusqlite::params![attestation_type_owned, attesting_owned],
                            |r| r.get::<_, String>(0),
                        )?;
                        for env_text in rows {
                            let env_text = env_text?;
                            let env: serde_json::Value = match serde_json::from_str(&env_text) {
                                Ok(v) => v,
                                Err(_) => continue,
                            };
                            let existing_ref =
                            crate::federation::precedence::references_attestation_id_from_envelope(
                                &env,
                            );
                            if existing_ref == Some(ref_id_owned.as_str()) {
                                return Ok(true);
                            }
                        }
                        Ok(false)
                    })
                    .await
                    .map_err(|e| {
                        crate::federation::Error::Backend(format!("spawn_blocking join: {e}"))
                    })?
                    .map_err(|e| {
                        crate::federation::Error::Backend(format!(
                            "dedup lookup structural composer: {e}"
                        ))
                    })?;
                if dup_exists {
                    return Ok(());
                }
            }
        }

        // v2.5.0 (CIRISPersist#102 Ask 4) — envelope-schema admission
        // hook. Same shape as the postgres backend; see
        // `src/store/postgres.rs` put_attestation for the
        // architectural commentary. Skipped on the default
        // `NoOpSchemaResolver`.
        if row.attestation_type == crate::federation::types::attestation_type::SCORES {
            if let Some(dim_str) = dim {
                let resolver = self.schema_resolver();
                let resolved = resolver.resolve(dim_str).await.map_err(|e| {
                    crate::federation::Error::Backend(format!(
                        "schema resolver: {} ({})",
                        e,
                        e.kind()
                    ))
                })?;
                if let Some(schema) = resolved {
                    if let Err(violations) =
                        crate::federation::schema_resolver::validate_envelope_against_schema(
                            &schema.document,
                            &row.attestation_envelope,
                        )
                    {
                        let axis = crate::federation::axis_from_dimension(dim_str)
                            .unwrap_or("")
                            .to_owned();
                        return Err(crate::federation::Error::EnvelopeSchemaViolation {
                            dimension: dim_str.to_string(),
                            axis,
                            violations,
                        });
                    }
                }
            }
        }

        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;

        let original_content_hash = hex::decode(&row.original_content_hash).map_err(|e| {
            crate::federation::Error::InvalidArgument(format!(
                "original_content_hash hex decode: {e}"
            ))
        })?;
        let attestation_envelope_text = serde_json::to_string(&row.attestation_envelope)
            .map_err(|e| crate::federation::Error::Backend(format!("envelope serialize: {e}")))?;

        // v3.7.0 (CIRISPersist#146, CEG 0.6) — serialize subject_key_ids
        // to canonical JSON TEXT; sqlite stores JSON-as-TEXT validated
        // by the json1 CHECK on the column.
        let subject_key_ids_json = serde_json::to_string(&row.subject_key_ids).map_err(|e| {
            crate::federation::Error::Backend(format!("subject_key_ids serialize: {e}"))
        })?;
        let withdraws_admission_rule: Option<i64> = row.withdraws_admission_rule.map(|v| v as i64);
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO federation_attestations (\
                    attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                    weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, \
                    subject_key_ids, withdraws_admission_rule, cohort_scope\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
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
                    subject_key_ids_json,
                    withdraws_admission_rule,
                    row.cohort_scope,
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
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope \
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
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope \
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

        // v3.4.0 (CIRISPersist#123) — trust gate first; the revoking
        // key is the attester.
        if !row.revoking_key_id.is_empty() {
            if let Some(gate) = self.admission_gate() {
                gate.check_federation(&row.revoking_key_id).await?;
            }
        }

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
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope \
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

    // ── Goals (v2.10.0, CIRISPersist#114) ──────────────────────────

    async fn put_goal(
        &self,
        goal: crate::federation::Goal,
    ) -> Result<(), crate::federation::Error> {
        let new_hash = crate::federation::types::compute_persist_row_hash(&goal)?;
        let canonical_text = crate::federation::canonicalize_goal_text(&goal.goal_text);
        let scope_kind = goal.scope.scope_kind_str().to_owned();
        let scope_cohort_id = goal.scope.cohort_id().map(|s| s.to_owned());
        let meta_dimension = goal.meta_goal_alignment.dimension.as_str().to_owned();
        let meta_deliberation_text: Option<String> =
            match &goal.meta_goal_alignment.deliberation_ref {
                Some(d) => Some(serde_json::to_string(d).map_err(|e| {
                    crate::federation::Error::Backend(format!("deliberation_ref serialize: {e}"))
                })?),
                None => None,
            };

        let goal_id_text = goal.goal_id.to_string();
        let conn = self.conn.clone();
        let goal_for_conflict = goal.clone();
        let conflict_check =
            tokio::task::spawn_blocking(move || -> Result<Option<String>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                conn.query_row(
                    "SELECT persist_row_hash FROM goals WHERE goal_id = ?1",
                    [&goal_for_conflict.goal_id.to_string()],
                    |r| r.get::<_, String>(0),
                )
                .optional()
            })
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
            .map_err(|e| crate::federation::Error::Backend(format!("conflict check: {e}")))?;

        if let Some(existing_hash) = conflict_check {
            if existing_hash == new_hash {
                return Ok(()); // exact duplicate — idempotent no-op
            }
            return Err(crate::federation::Error::Conflict(format!(
                "goal_id {} already exists with different content",
                goal.goal_id
            )));
        }

        let declared_by = goal.declared_by_key_id.clone();
        let declared_at_text = goal.declared_at.to_rfc3339();
        let goal_text = goal.goal_text.clone();
        let meta_rationale = goal.meta_goal_alignment.rationale.clone();
        let retired_at_text = goal.retired_at.map(|t| t.to_rfc3339());
        let new_hash_owned = new_hash;
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO goals (\
                    goal_id, declared_by_key_id, declared_at, goal_text, \
                    goal_text_canonical, scope_kind, scope_cohort_id, \
                    meta_dimension, meta_rationale, meta_deliberation, \
                    retired_at, persist_row_hash\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                rusqlite::params![
                    goal_id_text,
                    declared_by,
                    declared_at_text,
                    goal_text,
                    canonical_text,
                    scope_kind,
                    scope_cohort_id,
                    meta_dimension,
                    meta_rationale,
                    meta_deliberation_text,
                    retired_at_text,
                    new_hash_owned,
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            let msg = e.to_string();
            // FK violation → InvalidArgument (matches memory shape).
            if msg.contains("FOREIGN KEY") || msg.contains("foreign key") {
                crate::federation::Error::InvalidArgument(format!(
                    "FK constraint violated on put_goal: {msg}"
                ))
            } else {
                crate::federation::Error::Backend(format!("insert goal: {msg}"))
            }
        })?;
        Ok(())
    }

    async fn get_goal(
        &self,
        goal_id: uuid::Uuid,
    ) -> Result<Option<crate::federation::Goal>, crate::federation::Error> {
        let conn = self.conn.clone();
        let goal_id_text = goal_id.to_string();
        tokio::task::spawn_blocking(
            move || -> Result<Option<crate::federation::Goal>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                conn.query_row(
                    "SELECT goal_id, declared_by_key_id, declared_at, goal_text, \
                            scope_kind, scope_cohort_id, meta_dimension, meta_rationale, \
                            meta_deliberation, retired_at \
                     FROM goals WHERE goal_id = ?1",
                    [&goal_id_text],
                    sqlite_row_to_goal,
                )
                .optional()
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("get_goal: {e}")))
    }

    async fn list_goals(
        &self,
        filter: crate::federation::GoalsFilter,
    ) -> Result<Vec<crate::federation::Goal>, crate::federation::Error> {
        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<String> = Vec::new();
        if !filter.include_retired {
            where_parts.push("retired_at IS NULL".to_owned());
        }
        if let Some(key) = filter.declared_by_key_id {
            params.push(key);
            where_parts.push(format!("declared_by_key_id = ?{}", params.len()));
        }
        if let Some(dim) = filter.m1_dimension {
            params.push(dim.as_str().to_owned());
            where_parts.push(format!("meta_dimension = ?{}", params.len()));
        }
        if let Some(kind) = filter.scope_kind {
            params.push(kind);
            where_parts.push(format!("scope_kind = ?{}", params.len()));
        }
        if let Some(cohort) = filter.cohort_id {
            params.push(cohort);
            where_parts.push(format!("scope_cohort_id = ?{}", params.len()));
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };
        let sql = format!(
            "SELECT goal_id, declared_by_key_id, declared_at, goal_text, \
                    scope_kind, scope_cohort_id, meta_dimension, meta_rationale, \
                    meta_deliberation, retired_at \
             FROM goals \
             {where_sql} \
             ORDER BY declared_at, goal_id"
        );
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::federation::Goal>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(&sql)?;
                let params_dyn: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|p| p as &dyn rusqlite::ToSql).collect();
                let rows = stmt
                    .query_map(params_dyn.as_slice(), sqlite_row_to_goal)?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("list_goals: {e}")))
    }

    async fn retire_goal(
        &self,
        goal_id: uuid::Uuid,
        retired_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), crate::federation::Error> {
        // Idempotent: UPDATE ... WHERE retired_at IS NULL only flips
        // the live row; a follow-up SELECT proves existence so a
        // missing row surfaces as InvalidArgument and not a silent
        // no-op.
        let goal_id_text = goal_id.to_string();
        let retired_at_text = retired_at.to_rfc3339();
        let conn = self.conn.clone();
        let existed = tokio::task::spawn_blocking(move || -> Result<bool, rusqlite::Error> {
            let conn = conn.blocking_lock();
            // First check existence so a missing row returns
            // InvalidArgument rather than silently no-opping.
            let exists: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM goals WHERE goal_id = ?1",
                    [&goal_id_text],
                    |r| r.get(0),
                )
                .optional()?;
            if exists.is_none() {
                return Ok(false);
            }
            conn.execute(
                "UPDATE goals SET retired_at = ?2 WHERE goal_id = ?1 AND retired_at IS NULL",
                rusqlite::params![goal_id_text, retired_at_text],
            )?;
            Ok(true)
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("retire_goal: {e}")))?;
        if !existed {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "goal_id {goal_id} does not exist"
            )));
        }
        Ok(())
    }

    // ── Peer-mutation surface (v3.1.0, CIRISPersist#117) ───────────

    async fn add_peer_record(
        &self,
        key_id: &str,
        pubkey_ed25519_base64: &str,
        identity_type: &str,
        transport_identity: Option<String>,
    ) -> Result<(), crate::federation::Error> {
        if key_id.is_empty() {
            return Err(crate::federation::Error::InvalidArgument(
                "key_id must be non-empty".into(),
            ));
        }
        if pubkey_ed25519_base64.is_empty() {
            return Err(crate::federation::Error::InvalidArgument(
                "pubkey_ed25519_base64 must be non-empty".into(),
            ));
        }
        if identity_type.is_empty() {
            return Err(crate::federation::Error::InvalidArgument(
                "identity_type must be non-empty".into(),
            ));
        }

        let now = chrono::Utc::now();
        // Build the federation_keys row with its persist_row_hash.
        let mut key = crate::federation::KeyRecord {
            key_id: key_id.to_owned(),
            pubkey_ed25519_base64: pubkey_ed25519_base64.to_owned(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.to_owned(),
            identity_type: identity_type.to_owned(),
            identity_ref: key_id.to_owned(),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({"peer_added_by_operator": true}),
            original_content_hash: "00".repeat(32),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
        };
        key.persist_row_hash = crate::federation::types::compute_persist_row_hash(&key)?;

        let mut meta = crate::federation::PeerMetadataRow {
            key_id: key_id.to_owned(),
            alias: None,
            trust: crate::federation::TrustClass::Untrusted,
            notes: None,
            policy_blob: None,
            transport_identity: transport_identity.clone(),
            removed_at: None,
            inserted_at: now,
            updated_at: now,
            persist_row_hash: String::new(),
        };
        meta.persist_row_hash = crate::federation::types::compute_persist_row_hash(&meta)?;

        // Stringify fields ahead of the spawn_blocking boundary.
        let original_content_hash = hex::decode(&key.original_content_hash).map_err(|e| {
            crate::federation::Error::InvalidArgument(format!(
                "original_content_hash hex decode: {e}"
            ))
        })?;
        let registration_envelope_text = serde_json::to_string(&key.registration_envelope)
            .map_err(|e| crate::federation::Error::Backend(format!("envelope serialize: {e}")))?;
        let valid_from_str = key.valid_from.to_rfc3339();
        let scrub_timestamp_str = key.scrub_timestamp.to_rfc3339();
        let now_str = now.to_rfc3339();
        let meta_hash = meta.persist_row_hash.clone();
        let key_hash = key.persist_row_hash.clone();
        let key_id_owned = key.key_id.clone();
        let pubkey_owned = key.pubkey_ed25519_base64.clone();
        let algorithm_owned = key.algorithm.clone();
        let identity_type_owned = key.identity_type.clone();
        let identity_ref_owned = key.identity_ref.clone();
        let scrub_key_id_owned = key.scrub_key_id.clone();
        let scrub_classical_owned = key.scrub_signature_classical.clone();
        let transport_owned = meta.transport_identity.clone();

        let conn = self.conn.clone();
        let outcome = tokio::task::spawn_blocking(
            move || -> Result<Result<(), crate::federation::Error>, rusqlite::Error> {
                let mut conn = conn.blocking_lock();
                let tx = conn.transaction()?;

                // federation_keys ON CONFLICT DO NOTHING.
                tx.execute(
                    "INSERT INTO federation_keys (\
                        key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                        identity_type, identity_ref, valid_from, valid_until, registration_envelope, \
                        original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                        scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles, \
                        attestation_evidence\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18) \
                     ON CONFLICT(key_id) DO NOTHING",
                    rusqlite::params![
                        key_id_owned,
                        pubkey_owned,
                        Option::<String>::None,
                        algorithm_owned,
                        identity_type_owned,
                        identity_ref_owned,
                        valid_from_str,
                        Option::<String>::None,
                        registration_envelope_text,
                        original_content_hash,
                        scrub_classical_owned,
                        Option::<String>::None,
                        scrub_key_id_owned,
                        scrub_timestamp_str,
                        Option::<String>::None,
                        key_hash,
                        Option::<String>::None,
                        Option::<String>::None,
                    ],
                )?;

                // Verify pubkey conflict (existing key with different pubkey
                // → Conflict).
                let existing_pubkey: Option<String> = tx
                    .query_row(
                        "SELECT pubkey_ed25519_base64 FROM federation_keys WHERE key_id = ?1",
                        [&key_id_owned],
                        |r| r.get(0),
                    )
                    .optional()?;
                if let Some(existing) = existing_pubkey {
                    if existing != pubkey_owned {
                        return Ok(Err(crate::federation::Error::Conflict(format!(
                            "key_id {key_id_owned} already exists with different pubkey"
                        ))));
                    }
                }

                // federation_peer_metadata — handle soft-removed re-add,
                // idempotent matching transport, or conflict.
                let existing: Option<(Option<String>, Option<String>)> = tx
                    .query_row(
                        "SELECT transport_identity, removed_at \
                         FROM federation_peer_metadata WHERE key_id = ?1",
                        [&key_id_owned],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                match existing {
                    Some((_existing_transport, Some(_removed_at_text))) => {
                        // Re-add.
                        tx.execute(
                            "UPDATE federation_peer_metadata SET \
                                alias = NULL, trust = 'untrusted', notes = NULL, \
                                policy_blob = NULL, transport_identity = ?2, \
                                removed_at = NULL, inserted_at = ?3, updated_at = ?3, \
                                persist_row_hash = ?4 \
                             WHERE key_id = ?1",
                            rusqlite::params![
                                key_id_owned,
                                transport_owned,
                                now_str,
                                meta_hash,
                            ],
                        )?;
                    }
                    Some((existing_transport, None)) => {
                        if existing_transport == transport_owned {
                            // idempotent no-op
                        } else {
                            return Ok(Err(crate::federation::Error::Conflict(format!(
                                "peer_metadata row for key_id {key_id_owned} already exists with different transport_identity"
                            ))));
                        }
                    }
                    None => {
                        tx.execute(
                            "INSERT INTO federation_peer_metadata (\
                                key_id, alias, trust, notes, policy_blob, \
                                transport_identity, removed_at, inserted_at, updated_at, persist_row_hash\
                             ) VALUES (?1, NULL, 'untrusted', NULL, NULL, ?2, NULL, ?3, ?3, ?4)",
                            rusqlite::params![
                                key_id_owned,
                                transport_owned,
                                now_str,
                                meta_hash,
                            ],
                        )?;
                    }
                }

                tx.commit()?;
                Ok(Ok(()))
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            crate::federation::Error::Backend(format!("add_peer_record sqlite: {e}"))
        })?;
        outcome
    }

    async fn remove_peer_record(
        &self,
        key_id: &str,
        hard: bool,
    ) -> Result<(), crate::federation::Error> {
        let key_id_owned = key_id.to_owned();
        let now = chrono::Utc::now();
        let now_str = now.to_rfc3339();
        let conn = self.conn.clone();

        let outcome = tokio::task::spawn_blocking(
            move || -> Result<Result<(), crate::federation::Error>, rusqlite::Error> {
                let mut conn = conn.blocking_lock();
                let tx = conn.transaction()?;

                // Live-row gate. removed_at TEXT — IS NULL means live.
                let live: Option<i64> = tx
                    .query_row(
                        "SELECT 1 FROM federation_peer_metadata \
                         WHERE key_id = ?1 AND removed_at IS NULL",
                        [&key_id_owned],
                        |r| r.get(0),
                    )
                    .optional()?;
                if live.is_none() {
                    return Ok(Err(crate::federation::Error::PeerNotFound {
                        key_id: key_id_owned.clone(),
                    }));
                }

                if hard {
                    let count: i64 = tx.query_row(
                        "SELECT COUNT(*) FROM federation_attestations \
                         WHERE attesting_key_id = ?1 OR attested_key_id = ?1 OR scrub_key_id = ?1",
                        [&key_id_owned],
                        |r| r.get(0),
                    )?;
                    if count > 0 {
                        return Ok(Err(
                            crate::federation::Error::HardRemoveWithActiveAttestations {
                                key_id: key_id_owned.clone(),
                                attestation_count: count as usize,
                            },
                        ));
                    }
                    // DELETE federation_keys — FK ON DELETE CASCADE on
                    // federation_peer_metadata cleans up the sibling.
                    tx.execute(
                        "DELETE FROM federation_keys WHERE key_id = ?1",
                        [&key_id_owned],
                    )?;
                } else {
                    // Soft-remove: bump removed_at + updated_at +
                    // recompute persist_row_hash from the mutated row.
                    let row = tx.query_row(
                        "SELECT key_id, alias, trust, notes, policy_blob, \
                                transport_identity, inserted_at \
                         FROM federation_peer_metadata WHERE key_id = ?1",
                        [&key_id_owned],
                        |r| {
                            Ok((
                                r.get::<_, String>(0)?,
                                r.get::<_, Option<String>>(1)?,
                                r.get::<_, String>(2)?,
                                r.get::<_, Option<String>>(3)?,
                                r.get::<_, Option<String>>(4)?,
                                r.get::<_, Option<String>>(5)?,
                                r.get::<_, String>(6)?,
                            ))
                        },
                    )?;
                    let new_row = sqlite_row_tuple_to_peer_metadata(row, Some(now), now)
                        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                    let new_hash = crate::federation::types::compute_persist_row_hash(&new_row)
                        .map_err(|e| {
                            rusqlite::Error::ToSqlConversionFailure(Box::new(
                                std::io::Error::other(format!("hash: {e}")),
                            ))
                        })?;
                    tx.execute(
                        "UPDATE federation_peer_metadata SET \
                            removed_at = ?2, updated_at = ?2, persist_row_hash = ?3 \
                         WHERE key_id = ?1",
                        rusqlite::params![key_id_owned, now_str, new_hash],
                    )?;
                }
                tx.commit()?;
                Ok(Ok(()))
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            crate::federation::Error::Backend(format!("remove_peer_record sqlite: {e}"))
        })?;
        outcome
    }

    async fn update_peer_alias(
        &self,
        key_id: &str,
        alias: Option<String>,
    ) -> Result<(), crate::federation::Error> {
        sqlite_update_peer_field(self, key_id, SqlitePeerUpdate::Alias(alias)).await
    }

    async fn update_peer_trust(
        &self,
        key_id: &str,
        trust: crate::federation::TrustClass,
    ) -> Result<(), crate::federation::Error> {
        sqlite_update_peer_field(self, key_id, SqlitePeerUpdate::Trust(trust)).await
    }

    async fn update_peer_notes(
        &self,
        key_id: &str,
        notes: Option<String>,
    ) -> Result<(), crate::federation::Error> {
        sqlite_update_peer_field(self, key_id, SqlitePeerUpdate::Notes(notes)).await
    }

    async fn update_peer_policy(
        &self,
        key_id: &str,
        policy: crate::federation::PeerPolicyBlob,
    ) -> Result<(), crate::federation::Error> {
        sqlite_update_peer_field(self, key_id, SqlitePeerUpdate::Policy(policy)).await
    }

    // v3.4.1 (CIRISPersist#127) — read accessor; returns `None` for
    // non-existent or soft-removed peers.
    async fn peer_metadata_for(
        &self,
        key_id: &str,
    ) -> Result<Option<crate::federation::PeerMetadataRow>, crate::federation::Error> {
        let conn = self.conn.clone();
        let key_id_owned = key_id.to_owned();
        tokio::task::spawn_blocking(
            move || -> Result<Option<crate::federation::PeerMetadataRow>, crate::federation::Error> {
                let conn = conn.blocking_lock();
                type Row = (
                    String,         // key_id
                    Option<String>, // alias
                    String,         // trust
                    Option<String>, // notes
                    Option<String>, // policy_blob (TEXT-as-JSON)
                    Option<String>, // transport_identity
                    Option<String>, // removed_at
                    String,         // inserted_at
                    String,         // updated_at
                    String,         // persist_row_hash
                );
                let row_opt: Option<Row> = conn
                    .query_row(
                        "SELECT key_id, alias, trust, notes, policy_blob, transport_identity, \
                                removed_at, inserted_at, updated_at, persist_row_hash \
                         FROM federation_peer_metadata WHERE key_id = ?1",
                        rusqlite::params![key_id_owned],
                        |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                                row.get(5)?,
                                row.get(6)?,
                                row.get(7)?,
                                row.get(8)?,
                                row.get(9)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|e| {
                        crate::federation::Error::Backend(format!(
                            "peer_metadata_for query: {e}"
                        ))
                    })?;
                let Some((
                    key_id,
                    alias,
                    trust_str,
                    notes,
                    policy_text,
                    transport_identity,
                    removed_at_text,
                    inserted_at_text,
                    updated_at_text,
                    persist_row_hash,
                )) = row_opt
                else {
                    return Ok(None);
                };
                if removed_at_text.is_some() {
                    return Ok(None);
                }
                let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at_text)
                    .map_err(|e| {
                        crate::federation::Error::Backend(format!(
                            "updated_at parse: {e}"
                        ))
                    })?
                    .with_timezone(&chrono::Utc);
                let tuple: PeerMetadataRowTuple = (
                    key_id,
                    alias,
                    trust_str,
                    notes,
                    policy_text,
                    transport_identity,
                    inserted_at_text,
                );
                let mut meta = sqlite_row_tuple_to_peer_metadata(tuple, None, updated_at)?;
                meta.persist_row_hash = persist_row_hash;
                Ok(Some(meta))
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
    }
}

// ─── Peer-metadata update helpers (v3.1.0, CIRISPersist#117) ───────

/// Row-tuple shape read from `federation_peer_metadata` for the
/// canonical-hash hydrator. Order: `key_id, alias, trust, notes,
/// policy_blob, transport_identity, inserted_at`.
type PeerMetadataRowTuple = (
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
);

/// Row-tuple shape that adds `removed_at` for the update path.
type PeerMetadataRowTupleWithRemoved = (
    String,
    Option<String>,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    Option<String>,
);

enum SqlitePeerUpdate {
    Alias(Option<String>),
    Trust(crate::federation::TrustClass),
    Notes(Option<String>),
    Policy(crate::federation::PeerPolicyBlob),
}

/// Hydrate a row-tuple read from federation_peer_metadata into a
/// [`crate::federation::PeerMetadataRow`] suitable for canonical-bytes
/// hashing. `removed_at_override` lets the soft-remove path stamp the
/// new `removed_at` without a second SELECT after UPDATE.
fn sqlite_row_tuple_to_peer_metadata(
    row: PeerMetadataRowTuple,
    removed_at_override: Option<chrono::DateTime<chrono::Utc>>,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> Result<crate::federation::PeerMetadataRow, crate::federation::Error> {
    let (key_id, alias, trust_str, notes, policy_text, transport_identity, inserted_at_text) = row;
    let trust = crate::federation::TrustClass::from_wire_str(&trust_str).ok_or_else(|| {
        crate::federation::Error::Backend(format!(
            "federation_peer_metadata.trust has unrecognized value {trust_str:?} \
             (CHECK constraint bypass — direct SQL write?)"
        ))
    })?;
    let policy_blob = match policy_text {
        Some(text) => Some(crate::federation::PeerPolicyBlob(
            serde_json::from_str(&text).map_err(|e| {
                crate::federation::Error::Backend(format!("policy_blob JSON decode: {e}"))
            })?,
        )),
        None => None,
    };
    let inserted_at = chrono::DateTime::parse_from_rfc3339(&inserted_at_text)
        .map_err(|e| crate::federation::Error::Backend(format!("inserted_at parse: {e}")))?
        .with_timezone(&chrono::Utc);
    Ok(crate::federation::PeerMetadataRow {
        key_id,
        alias,
        trust,
        notes,
        policy_blob,
        transport_identity,
        removed_at: removed_at_override,
        inserted_at,
        updated_at,
        persist_row_hash: String::new(),
    })
}

async fn sqlite_update_peer_field(
    backend: &SqliteBackend,
    key_id: &str,
    update: SqlitePeerUpdate,
) -> Result<(), crate::federation::Error> {
    let key_id_owned = key_id.to_owned();
    let now = chrono::Utc::now();
    let now_str = now.to_rfc3339();
    let conn = backend.conn.clone();
    let outcome = tokio::task::spawn_blocking(
        move || -> Result<Result<(), crate::federation::Error>, rusqlite::Error> {
            let mut conn = conn.blocking_lock();
            let tx = conn.transaction()?;

            // Fetch live-row tuple; PeerNotFound on missing or
            // soft-removed.
            let row_opt: Option<PeerMetadataRowTupleWithRemoved> = tx
                .query_row(
                    "SELECT key_id, alias, trust, notes, policy_blob, \
                            transport_identity, inserted_at, removed_at \
                     FROM federation_peer_metadata WHERE key_id = ?1",
                    [&key_id_owned],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                            r.get(6)?,
                            r.get(7)?,
                        ))
                    },
                )
                .optional()?;
            let row = match row_opt {
                None => {
                    return Ok(Err(crate::federation::Error::PeerNotFound {
                        key_id: key_id_owned.clone(),
                    }));
                }
                Some(r) => r,
            };
            if row.7.is_some() {
                return Ok(Err(crate::federation::Error::PeerNotFound {
                    key_id: key_id_owned.clone(),
                }));
            }

            let mut mut_row = match sqlite_row_tuple_to_peer_metadata(
                (
                    row.0.clone(),
                    row.1.clone(),
                    row.2.clone(),
                    row.3.clone(),
                    row.4.clone(),
                    row.5.clone(),
                    row.6.clone(),
                ),
                None,
                now,
            ) {
                Ok(r) => r,
                Err(e) => return Ok(Err(e)),
            };
            mut_row.updated_at = now;

            match &update {
                SqlitePeerUpdate::Alias(v) => mut_row.alias = v.clone(),
                SqlitePeerUpdate::Trust(v) => mut_row.trust = *v,
                SqlitePeerUpdate::Notes(v) => mut_row.notes = v.clone(),
                SqlitePeerUpdate::Policy(v) => mut_row.policy_blob = Some(v.clone()),
            }
            let new_hash = match crate::federation::types::compute_persist_row_hash(&mut_row) {
                Ok(h) => h,
                Err(e) => return Ok(Err(e)),
            };

            match update {
                SqlitePeerUpdate::Alias(_) => {
                    tx.execute(
                        "UPDATE federation_peer_metadata SET \
                            alias = ?2, updated_at = ?3, persist_row_hash = ?4 \
                         WHERE key_id = ?1",
                        rusqlite::params![key_id_owned, mut_row.alias, now_str, new_hash],
                    )?;
                }
                SqlitePeerUpdate::Trust(_) => {
                    let wire = mut_row.trust.as_wire_str().to_owned();
                    tx.execute(
                        "UPDATE federation_peer_metadata SET \
                            trust = ?2, updated_at = ?3, persist_row_hash = ?4 \
                         WHERE key_id = ?1",
                        rusqlite::params![key_id_owned, wire, now_str, new_hash],
                    )?;
                }
                SqlitePeerUpdate::Notes(_) => {
                    tx.execute(
                        "UPDATE federation_peer_metadata SET \
                            notes = ?2, updated_at = ?3, persist_row_hash = ?4 \
                         WHERE key_id = ?1",
                        rusqlite::params![key_id_owned, mut_row.notes, now_str, new_hash],
                    )?;
                }
                SqlitePeerUpdate::Policy(_) => {
                    let policy_text: Option<String> =
                        match &mut_row.policy_blob {
                            Some(p) => Some(serde_json::to_string(p.as_value()).map_err(|e| {
                                rusqlite::Error::ToSqlConversionFailure(Box::new(e))
                            })?),
                            None => None,
                        };
                    tx.execute(
                        "UPDATE federation_peer_metadata SET \
                            policy_blob = ?2, updated_at = ?3, persist_row_hash = ?4 \
                         WHERE key_id = ?1",
                        rusqlite::params![key_id_owned, policy_text, now_str, new_hash],
                    )?;
                }
            }
            tx.commit()?;
            Ok(Ok(()))
        },
    )
    .await
    .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
    .map_err(|e| crate::federation::Error::Backend(format!("update_peer_* sqlite: {e}")))?;
    outcome
}

// ─── BlobStorage impl (v2.3, CIRISPersist#103) ─────────────────────
//
// Content-addressable byte storage. See `crate::federation::blobs` for
// the trait + types. SQLite uses BLOB for sha256/bytes_inline and TEXT
// JSON-string for the attestation envelope. The holder attestation is
// emitted inside the same transaction as the blob INSERT so a holder-
// attestation FK violation rolls back the blob row too (atomic
// put_blob semantic).

impl crate::federation::BlobStorage for SqliteBackend {
    fn inline_bytes_cap(&self) -> usize {
        self.inline_bytes_cap
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    fn perceptual_hash_matcher(&self) -> Option<crate::federation::SharedMatcher> {
        self.perceptual_hash_matcher
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    async fn put_blob(
        &self,
        sha256: &[u8; 32],
        body: crate::federation::BlobBody,
        media_type: Option<&str>,
        attestation: crate::federation::PutBlobAttestation,
    ) -> Result<(), crate::federation::BlobError> {
        // v3.4.0 (CIRISPersist#123) — admission ordering:
        //   1. empty-string → InvalidArgument
        //   2. trust-threshold → TrustBelowThreshold
        //   3. inline-size → InlineSizeExceeded
        //   4. hash-mismatch → HashMismatch
        //   5. DB FK → AttestationEmissionFailed
        if attestation.attesting_key_id.is_empty() {
            return Err(crate::federation::BlobError::InvalidArgument(
                "attesting_key_id is empty".into(),
            ));
        }
        if let Some(gate) = self.admission_gate() {
            gate.check_blob(&attestation.attesting_key_id).await?;
        }
        let cap = self.inline_bytes_cap();
        if let crate::federation::BlobBody::Inline(ref bytes) = body {
            if bytes.len() > cap {
                return Err(crate::federation::BlobError::InlineSizeExceeded {
                    size: bytes.len(),
                    cap,
                });
            }
            crate::federation::blobs::verify_inline_hash(sha256, bytes)?;
        }

        let original_content_hash =
            hex::decode(&attestation.original_content_hash_hex).map_err(|e| {
                crate::federation::BlobError::InvalidArgument(format!(
                    "original_content_hash hex decode: {e}"
                ))
            })?;

        let storage_kind = body.storage_kind().to_owned();
        let size_bytes_i64 = i64::try_from(body.size_bytes()).map_err(|_| {
            crate::federation::BlobError::InvalidArgument(
                "size_bytes exceeds i64 — federation_blobs.size_bytes is INTEGER".into(),
            )
        })?;
        let (bytes_inline_opt, external_ref_opt) = match &body {
            crate::federation::BlobBody::Inline(b) => (Some(b.clone()), None),
            crate::federation::BlobBody::External(e) => (None, Some(e.uri.clone())),
        };

        // 2. Compose the holder attestation envelope.
        let attestation_type = crate::federation::holds_bytes_attestation_type(sha256);
        let attestation_envelope_value =
            crate::federation::holds_bytes_attestation_envelope(sha256);
        let attestation_row = crate::federation::Attestation {
            attestation_id: attestation.attestation_id.clone(),
            attesting_key_id: attestation.attesting_key_id.clone(),
            attested_key_id: attestation.attesting_key_id.clone(),
            attestation_type: attestation_type.clone(),
            weight: None,
            asserted_at: attestation.scrub_timestamp,
            expires_at: None,
            attestation_envelope: attestation_envelope_value.clone(),
            original_content_hash: attestation.original_content_hash_hex.clone(),
            scrub_signature_classical: attestation.scrub_signature_classical.clone(),
            scrub_signature_pqc: attestation.scrub_signature_pqc.clone(),
            scrub_key_id: attestation.scrub_key_id.clone(),
            scrub_timestamp: attestation.scrub_timestamp,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            // v3.7.0 (CIRISPersist#146, CEG 0.6) — holds_bytes is a
            // self-attestation; subject-side authority does not apply.
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
        };
        let persist_row_hash = crate::federation::types::compute_persist_row_hash(&attestation_row)
            .map_err(|e| crate::federation::BlobError::Backend(format!("persist_row_hash: {e}")))?;
        let attestation_envelope_text = serde_json::to_string(&attestation_envelope_value)
            .map_err(|e| {
                crate::federation::BlobError::Backend(format!("envelope serialize: {e}"))
            })?;

        let sha_vec = sha256.to_vec();
        let conn = self.conn.clone();
        let asserted_at_str = attestation.scrub_timestamp.to_rfc3339();
        let scrub_timestamp_str = attestation.scrub_timestamp.to_rfc3339();
        let attestation_id_owned = attestation.attestation_id.clone();
        let attesting_key_id_owned = attestation.attesting_key_id.clone();
        let scrub_signature_classical_owned = attestation.scrub_signature_classical.clone();
        let scrub_signature_pqc_owned = attestation.scrub_signature_pqc.clone();
        let scrub_key_id_owned = attestation.scrub_key_id.clone();
        let media_type_owned = media_type.map(str::to_owned);
        // v3.4.0 (CIRISPersist#123) — V053 last_accessed_at column has
        // a literal-default sentinel on SQLite (datetime functions are
        // not allowed in ALTER … ADD COLUMN DEFAULT). Write the real
        // wall-clock here so a fresh blob's last_accessed_at matches
        // its first_seen_at instead of the 1970 epoch placeholder.
        let now_iso = chrono::Utc::now().to_rfc3339();

        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let mut conn = conn.blocking_lock();
            let tx = conn.transaction()?;
            tx.execute(
                "INSERT INTO federation_blobs (\
                    sha256, storage_kind, bytes_inline, external_ref, size_bytes, media_type, \
                    last_accessed_at, access_count\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0) \
                 ON CONFLICT (sha256) DO NOTHING",
                rusqlite::params![
                    sha_vec,
                    storage_kind,
                    bytes_inline_opt,
                    external_ref_opt,
                    size_bytes_i64,
                    media_type_owned,
                    now_iso,
                ],
            )?;
            tx.execute(
                "INSERT INTO federation_attestations (\
                    attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                    weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash\
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
                rusqlite::params![
                    attestation_id_owned,
                    attesting_key_id_owned,
                    attesting_key_id_owned,
                    attestation_type,
                    Option::<f64>::None,
                    asserted_at_str,
                    Option::<String>::None,
                    attestation_envelope_text,
                    original_content_hash,
                    scrub_signature_classical_owned,
                    scrub_signature_pqc_owned,
                    scrub_key_id_owned,
                    scrub_timestamp_str,
                    Option::<String>::None,
                    persist_row_hash,
                ],
            )?;
            tx.commit()?;
            Ok(())
        })
        .await
        .map_err(|e| crate::federation::BlobError::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("FOREIGN KEY") {
                crate::federation::BlobError::AttestationEmissionFailed(format!(
                    "FK violation on holds_bytes attestation: {msg}"
                ))
            } else if msg.contains("UNIQUE constraint failed") {
                crate::federation::BlobError::AttestationEmissionFailed(format!(
                    "attestation_id collision: {msg}"
                ))
            } else {
                crate::federation::BlobError::Backend(format!("put_blob tx: {msg}"))
            }
        })?;

        Ok(())
    }

    async fn get_blob(
        &self,
        sha256: &[u8; 32],
    ) -> Result<Option<crate::federation::BlobBody>, crate::federation::BlobError> {
        let sha_vec = sha256.to_vec();
        let conn = self.conn.clone();
        // v3.4.0 (CIRISPersist#123) — bump access-tracking columns on
        // every read hit. SQLite has no UPDATE … RETURNING for our row
        // shape; we do SELECT first, then bump in the same transaction
        // so the counter survives a concurrent get_blob.
        let now_iso = chrono::Utc::now().to_rfc3339();
        tokio::task::spawn_blocking(
            move || -> Result<Option<crate::federation::BlobBody>, rusqlite::Error> {
                let mut conn = conn.blocking_lock();
                let tx = conn.transaction()?;
                let row_opt = tx
                    .query_row(
                        "SELECT storage_kind, bytes_inline, external_ref, size_bytes, media_type \
                         FROM federation_blobs WHERE sha256 = ?1",
                        rusqlite::params![sha_vec],
                        |row| {
                            let storage_kind: String = row.get("storage_kind")?;
                            let bytes_inline: Option<Vec<u8>> = row.get("bytes_inline")?;
                            let external_ref: Option<String> = row.get("external_ref")?;
                            let size_bytes: i64 = row.get("size_bytes")?;
                            let media_type: Option<String> = row.get("media_type")?;
                            Ok((
                                storage_kind,
                                bytes_inline,
                                external_ref,
                                size_bytes,
                                media_type,
                            ))
                        },
                    )
                    .optional()?;
                if row_opt.is_some() {
                    tx.execute(
                        "UPDATE federation_blobs SET access_count = access_count + 1, \
                         last_accessed_at = ?2 WHERE sha256 = ?1",
                        rusqlite::params![sha_vec, now_iso],
                    )?;
                }
                tx.commit()?;
                Ok(
                    row_opt.map(|(kind, inline, ext, size, mt)| match kind.as_str() {
                        "inline" => crate::federation::BlobBody::Inline(inline.unwrap_or_default()),
                        _ => {
                            crate::federation::BlobBody::External(crate::federation::ExternalRef {
                                uri: ext.unwrap_or_default(),
                                size_bytes: size.max(0) as u64,
                                media_type: mt,
                            })
                        }
                    }),
                )
            },
        )
        .await
        .map_err(|e| crate::federation::BlobError::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::BlobError::Backend(format!("get_blob: {e}")))
    }

    async fn has_blob(&self, sha256: &[u8; 32]) -> Result<bool, crate::federation::BlobError> {
        let sha_vec = sha256.to_vec();
        let conn = self.conn.clone();
        // v3.4.0 (CIRISPersist#123) — has_blob also bumps the
        // access-tracking columns when the row exists (per the
        // architect's plan §"Per-row access tracking"). Both reads are
        // treated as evidence the blob is still hot.
        let now_iso = chrono::Utc::now().to_rfc3339();
        tokio::task::spawn_blocking(move || -> Result<bool, rusqlite::Error> {
            let mut conn = conn.blocking_lock();
            let tx = conn.transaction()?;
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM federation_blobs WHERE sha256 = ?1",
                rusqlite::params![sha_vec],
                |row| row.get(0),
            )?;
            if count > 0 {
                tx.execute(
                    "UPDATE federation_blobs SET access_count = access_count + 1, \
                     last_accessed_at = ?2 WHERE sha256 = ?1",
                    rusqlite::params![sha_vec, now_iso],
                )?;
            }
            tx.commit()?;
            Ok(count > 0)
        })
        .await
        .map_err(|e| crate::federation::BlobError::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::BlobError::Backend(format!("has_blob: {e}")))
    }

    async fn list_holders(
        &self,
        sha256: &[u8; 32],
    ) -> Result<Vec<String>, crate::federation::BlobError> {
        // v3.0.0 (CIRISPersist#116, CEG 0.2 §10.1.2):
        // 1. Fetch holds_bytes attestation rows matching the SHA prefix.
        // 2. Filter to rows whose envelope evidence_refs contains the
        //    full hex SHA (discriminates 32-bit prefix collisions).
        // 3. Apply the DEFAULT_HOLDS_BYTES_TTL freshness window —
        //    rows whose asserted_at + TTL <= now are treated as stale.
        // 4. Drop rows whose attester emitted a `withdraws` structural
        //    composer against the holds_bytes row's attestation_id
        //    (the ContentMiss feedback loop).
        //
        // v3.6.4 (CIRISPersist#130 reopen): when the blob is present in
        // `federation_blobs` (local-truth: we have the bytes), the TTL
        // filter is bypassed. Federation §10.1.2 TTL is a backstop for
        // peer attestations going silently offline; for locally-held
        // bytes the row's age says nothing about whether we still hold
        // them. The `withdraws` mechanism remains the active eviction
        // signal — ContentMiss feedback loop unchanged. This also
        // closes a child-safety hole in the takedown handler, which
        // queries `list_holders` and would otherwise leave stale-
        // attested local content uneviction-able.
        let attestation_type = crate::federation::holds_bytes_attestation_type(sha256);
        let full_hex = hex::encode(sha256);
        let sha_vec = sha256.to_vec();
        let now = chrono::Utc::now();
        let ttl = chrono::Duration::from_std(crate::federation::blobs::DEFAULT_HOLDS_BYTES_TTL)
            .expect("DEFAULT_HOLDS_BYTES_TTL fits chrono::Duration");
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<String>, rusqlite::Error> {
            let conn = conn.blocking_lock();

            // v3.6.4 local-truth gate.
            let blob_locally_held: bool = conn
                .query_row(
                    "SELECT 1 FROM federation_blobs WHERE sha256 = ?1",
                    rusqlite::params![&sha_vec],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false);

            // Step A: collect candidate holds_bytes rows.
            let mut stmt = conn.prepare(
                "SELECT attestation_id, attesting_key_id, attestation_envelope, asserted_at \
                 FROM federation_attestations \
                 WHERE attestation_type = ?1",
            )?;
            let rows = stmt.query_map(rusqlite::params![&attestation_type], |row| {
                let attestation_id: String = row.get("attestation_id")?;
                let key_id: String = row.get("attesting_key_id")?;
                let env_text: String = row.get("attestation_envelope")?;
                let asserted_at: String = row.get("asserted_at")?;
                Ok((attestation_id, key_id, env_text, asserted_at))
            })?;
            // Pre-collect so we can release the prepared-statement
            // borrow before doing the withdraws lookup (avoids holding
            // two prepared statements on the same connection).
            let candidates: Vec<(String, String, String, String)> =
                rows.collect::<Result<_, _>>()?;
            drop(stmt);

            // Step B: for each candidate, prune (i) full-SHA mismatch
            // on evidence_refs, (ii) expired TTL window, (iii)
            // withdrawn by the attester.
            let mut holders: Vec<String> = Vec::new();
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            for (attestation_id, key_id, env_text, asserted_at_str) in candidates {
                // (i) full-SHA match
                let env: serde_json::Value = match serde_json::from_str(&env_text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let matches = env
                    .get("evidence_refs")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().any(|v| v.as_str() == Some(full_hex.as_str())))
                    .unwrap_or(false);
                if !matches {
                    continue;
                }
                // (ii) TTL window — bypassed when blob is locally held
                // (#130 reopen: federation TTL is a backstop for peer
                // attestations; local-truth has definitive proof).
                let asserted_at = match chrono::DateTime::parse_from_rfc3339(&asserted_at_str) {
                    Ok(t) => t.with_timezone(&chrono::Utc),
                    Err(_) => continue,
                };
                let expires_at = asserted_at + ttl;
                if !blob_locally_held && expires_at <= now {
                    continue;
                }
                // (iii) ContentMiss withdraws — the attester emitted a
                // `withdraws` referencing this row's attestation_id.
                let mut withdraws_stmt = conn.prepare(
                    "SELECT attestation_envelope FROM federation_attestations \
                     WHERE attestation_type = ?1 AND attesting_key_id = ?2",
                )?;
                let withdraws_rows = withdraws_stmt.query_map(
                    rusqlite::params![
                        crate::federation::types::attestation_type::WITHDRAWS,
                        &key_id
                    ],
                    |r| r.get::<_, String>("attestation_envelope"),
                )?;
                let mut withdrawn = false;
                for w in withdraws_rows {
                    let w_text = w?;
                    let w_env: serde_json::Value = match serde_json::from_str(&w_text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if crate::federation::precedence::references_attestation_id_from_envelope(
                        &w_env,
                    ) == Some(attestation_id.as_str())
                    {
                        withdrawn = true;
                        break;
                    }
                }
                if withdrawn {
                    continue;
                }

                if seen.insert(key_id.clone()) {
                    holders.push(key_id);
                }
            }
            Ok(holders)
        })
        .await
        .map_err(|e| crate::federation::BlobError::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::BlobError::Backend(format!("list_holders: {e}")))
    }

    // v3.5.2 (CIRISPersist#130) — local-truth holder query, bypasses
    // CEG §10.1.2 TTL. See trait docstring for the semantic split
    // between this and `list_holders`. Returns empty if blob is not
    // in `federation_blobs` (local-truth premise doesn't apply).
    async fn list_local_holders(
        &self,
        sha256: &[u8; 32],
    ) -> Result<Vec<String>, crate::federation::BlobError> {
        let attestation_type = crate::federation::holds_bytes_attestation_type(sha256);
        let full_hex = hex::encode(sha256);
        let sha_vec = sha256.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<String>, rusqlite::Error> {
            let conn = conn.blocking_lock();

            // Gate: blob must be locally present.
            let blob_present: bool = conn
                .query_row(
                    "SELECT 1 FROM federation_blobs WHERE sha256 = ?1",
                    rusqlite::params![&sha_vec],
                    |_| Ok(true),
                )
                .optional()?
                .unwrap_or(false);
            if !blob_present {
                return Ok(Vec::new());
            }

            // Collect every holds_bytes attestation for this SHA
            // prefix (NO TTL filter).
            let mut stmt = conn.prepare(
                "SELECT attestation_id, attesting_key_id, attestation_envelope \
                 FROM federation_attestations \
                 WHERE attestation_type = ?1",
            )?;
            let rows = stmt.query_map(rusqlite::params![&attestation_type], |row| {
                let attestation_id: String = row.get("attestation_id")?;
                let key_id: String = row.get("attesting_key_id")?;
                let env_text: String = row.get("attestation_envelope")?;
                Ok((attestation_id, key_id, env_text))
            })?;
            let candidates: Vec<(String, String, String)> = rows.collect::<Result<_, _>>()?;
            drop(stmt);

            let mut holders: Vec<String> = Vec::new();
            let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
            for (attestation_id, key_id, env_text) in candidates {
                // (i) full-SHA match on evidence_refs.
                let env: serde_json::Value = match serde_json::from_str(&env_text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let matches = env
                    .get("evidence_refs")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().any(|v| v.as_str() == Some(full_hex.as_str())))
                    .unwrap_or(false);
                if !matches {
                    continue;
                }

                // (ii) withdraws filter — explicit eviction signal.
                let mut withdraws_stmt = conn.prepare(
                    "SELECT attestation_envelope FROM federation_attestations \
                     WHERE attestation_type = ?1 AND attesting_key_id = ?2",
                )?;
                let withdraws_rows = withdraws_stmt.query_map(
                    rusqlite::params![
                        crate::federation::types::attestation_type::WITHDRAWS,
                        &key_id
                    ],
                    |r| r.get::<_, String>("attestation_envelope"),
                )?;
                let mut withdrawn = false;
                for w in withdraws_rows {
                    let w_text = w?;
                    let w_env: serde_json::Value = match serde_json::from_str(&w_text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if w_env
                        .get("references_attestation_id")
                        .and_then(|v| v.as_str())
                        == Some(attestation_id.as_str())
                    {
                        withdrawn = true;
                        break;
                    }
                }
                if withdrawn {
                    continue;
                }

                if seen.insert(key_id.clone()) {
                    holders.push(key_id);
                }
            }
            Ok(holders)
        })
        .await
        .map_err(|e| crate::federation::BlobError::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::BlobError::Backend(format!("list_local_holders: {e}")))
    }

    async fn list_held_by(
        &self,
        attesting_key_id: &str,
    ) -> Result<Vec<[u8; 32]>, crate::federation::BlobError> {
        // v3.5.0 (CIRISPersist#125) — inverse of list_holders:
        //   "whose bytes do I hold for actor X?"
        //
        // 1. Pull every holds_bytes:sha256:* row authored by
        //    `attesting_key_id`. The attestation_type prefix narrows
        //    well below O(table).
        // 2. For each, parse the full hex SHA out of the envelope's
        //    `evidence_refs[0]` and decode to [u8; 32]. Skip rows that
        //    don't have the expected shape (corrupt envelopes — same
        //    defense-in-depth as list_holders).
        // 3. Apply DEFAULT_HOLDS_BYTES_TTL freshness (rows whose
        //    asserted_at + TTL <= now are stale; drop them).
        // 4. Drop rows whose attester has emitted a `withdraws`
        //    against the holds_bytes row's attestation_id (CEG §10.1.2
        //    ContentMiss feedback loop).
        let prefix = crate::federation::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX;
        let now = chrono::Utc::now();
        let ttl = chrono::Duration::from_std(crate::federation::blobs::DEFAULT_HOLDS_BYTES_TTL)
            .expect("DEFAULT_HOLDS_BYTES_TTL fits chrono::Duration");
        let actor = attesting_key_id.to_owned();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<[u8; 32]>, rusqlite::Error> {
            let conn = conn.blocking_lock();
            let like_pattern = format!("{prefix}%");
            let mut stmt = conn.prepare(
                "SELECT attestation_id, attestation_envelope, asserted_at \
                 FROM federation_attestations \
                 WHERE attesting_key_id = ?1 AND attestation_type LIKE ?2",
            )?;
            let rows = stmt.query_map(rusqlite::params![&actor, &like_pattern], |row| {
                let attestation_id: String = row.get("attestation_id")?;
                let env_text: String = row.get("attestation_envelope")?;
                let asserted_at: String = row.get("asserted_at")?;
                Ok((attestation_id, env_text, asserted_at))
            })?;
            let candidates: Vec<(String, String, String)> = rows.collect::<Result<_, _>>()?;
            drop(stmt);

            let mut out: Vec<[u8; 32]> = Vec::new();
            let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
            for (attestation_id, env_text, asserted_at_str) in candidates {
                let env: serde_json::Value = match serde_json::from_str(&env_text) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                // Pull the full hex SHA from evidence_refs[0].
                let sha_hex = match env
                    .get("evidence_refs")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|v| v.as_str())
                {
                    Some(s) => s,
                    None => continue,
                };
                let mut sha = [0u8; 32];
                if hex::decode_to_slice(sha_hex, &mut sha).is_err() {
                    continue;
                }
                // TTL freshness.
                let asserted_at = match chrono::DateTime::parse_from_rfc3339(&asserted_at_str) {
                    Ok(t) => t.with_timezone(&chrono::Utc),
                    Err(_) => continue,
                };
                if asserted_at + ttl <= now {
                    continue;
                }
                // ContentMiss withdraws filter.
                let mut withdraws_stmt = conn.prepare(
                    "SELECT attestation_envelope FROM federation_attestations \
                     WHERE attestation_type = ?1 AND attesting_key_id = ?2",
                )?;
                let withdraws_rows = withdraws_stmt.query_map(
                    rusqlite::params![
                        crate::federation::types::attestation_type::WITHDRAWS,
                        &actor
                    ],
                    |r| r.get::<_, String>("attestation_envelope"),
                )?;
                let mut withdrawn = false;
                for w in withdraws_rows {
                    let w_text = w?;
                    let w_env: serde_json::Value = match serde_json::from_str(&w_text) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if crate::federation::precedence::references_attestation_id_from_envelope(
                        &w_env,
                    ) == Some(attestation_id.as_str())
                    {
                        withdrawn = true;
                        break;
                    }
                }
                if withdrawn {
                    continue;
                }
                if seen.insert(sha) {
                    out.push(sha);
                }
            }
            Ok(out)
        })
        .await
        .map_err(|e| crate::federation::BlobError::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::BlobError::Backend(format!("list_held_by: {e}")))
    }

    async fn evict_actor(
        &self,
        attesting_key_id: &str,
        signer: &dyn ciris_keyring::HardwareSigner,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::federation::EvictActorReport, crate::federation::BlobError> {
        // v3.5.0 (CIRISPersist#125) — per-actor eviction.
        //
        // 1. Pull the actor's live holds_bytes attestations via
        //    FederationDirectory::list_attestations_by + a holds_bytes
        //    type-prefix filter.
        // 2. For each: emit a withdraws via the shared helper, then
        //    delete the corresponding federation_blobs row. The blob
        //    deletion proceeds regardless of withdraws outcome —
        //    orphan withdraws > missing withdraws. Tally per
        //    EvictActorReport.
        use crate::federation::FederationDirectory;

        let all = self
            .list_attestations_by(attesting_key_id)
            .await
            .map_err(|e| {
                crate::federation::BlobError::Backend(format!(
                    "evict_actor: list_attestations_by failed: {e}"
                ))
            })?;

        // Filter to holds_bytes:* attestations only.
        let prefix = crate::federation::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX;
        let holds_bytes_rows: Vec<crate::federation::Attestation> = all
            .into_iter()
            .filter(|a| a.attestation_type.starts_with(prefix))
            .collect();

        let mut report = crate::federation::EvictActorReport::default();
        for prior in holds_bytes_rows {
            // Recover the SHA from evidence_refs[0]; skip if shape's wrong.
            let sha_hex = prior
                .attestation_envelope
                .get("evidence_refs")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let sha = match sha_hex {
                Some(hex_str) => {
                    let mut s = [0u8; 32];
                    if hex::decode_to_slice(&hex_str, &mut s).is_err() {
                        continue;
                    }
                    s
                }
                None => continue,
            };

            // Emit the withdraws (fail-honest: still delete the blob).
            let withdraws_outcome = crate::federation::blobs::emit_withdraws_attestation_helper(
                &prior,
                attesting_key_id,
                signer,
                self,
                now,
            )
            .await;

            // Delete the blob row.
            let deleted = self.delete_blob(&sha).await?;
            if deleted {
                report.blobs_evicted += 1;
            }
            match withdraws_outcome {
                Ok(()) => report.withdraws_emitted += 1,
                Err(e) => {
                    report.withdraws_failed += 1;
                    tracing::warn!(
                        error = %e,
                        actor = %attesting_key_id,
                        sha256_prefix = &hex::encode(sha)[..16],
                        "ciris-persist v3.5.0 evict_actor: withdraws emission failed"
                    );
                }
            }
        }
        Ok(report)
    }
}

// ─── Eviction sweeper helpers (v3.4.0, CIRISPersist#123) ───────────
//
// Inherent methods, not trait methods — the Engine layer owns the
// orchestration (signer + put_attestation lookup), backends just
// expose "give me the next N eviction candidates" + "delete this
// row". Keeping them off the BlobStorage trait preserves the trait's
// "what a consumer needs to read/write a blob" focus.

impl SqliteBackend {
    /// v3.4.0 (CIRISPersist#123) — fetch the next `limit` eviction
    /// candidates ordered by `(last_accessed_at ASC, access_count
    /// ASC)`. SQLite has no `exp()` in its stdlib so we can't apply
    /// the decay-weighted score in SQL; the composite ASC order is a
    /// monotone bound on the full score (older + less-accessed always
    /// scores lower for any positive half-life), so the top-K by this
    /// SQL order is a superset of the top-K by full score. The Engine
    /// re-ranks the returned candidates by
    /// [`crate::federation::EvictionDecay::score`].
    ///
    /// **Postgres asymmetry**: Postgres computes the full score
    /// `access_count * exp(-ln(2) * Δt / half_life)` inline in SQL via
    /// the `exp()` function. SQLite needs the Rust-side re-rank.
    pub async fn sweep_candidates(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::federation::EvictionCandidate>, crate::federation::BlobError> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::federation::EvictionCandidate>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(
                    "SELECT sha256, size_bytes, access_count, last_accessed_at \
                     FROM federation_blobs \
                     ORDER BY last_accessed_at ASC, access_count ASC \
                     LIMIT ?1",
                )?;
                let rows = stmt.query_map([limit], |r| {
                    let sha_vec: Vec<u8> = r.get(0)?;
                    let size_bytes: i64 = r.get(1)?;
                    let access_count: i64 = r.get(2)?;
                    let last_str: String = r.get(3)?;
                    Ok((sha_vec, size_bytes, access_count, last_str))
                })?;
                let mut out = Vec::new();
                for row in rows {
                    let (sha_vec, size_bytes, access_count, last_str) = row?;
                    let mut sha = [0u8; 32];
                    if sha_vec.len() != 32 {
                        // Defense in depth — schema enforces 32-byte
                        // sha256 but a corrupt row shouldn't panic
                        // the sweeper. Skip the row.
                        continue;
                    }
                    sha.copy_from_slice(&sha_vec);
                    let last_accessed_at: chrono::DateTime<chrono::Utc> =
                        chrono::DateTime::parse_from_rfc3339(&last_str)
                            .map(|t| t.with_timezone(&chrono::Utc))
                            .unwrap_or_else(|_| chrono::Utc::now());
                    out.push(crate::federation::EvictionCandidate {
                        sha256: sha,
                        size_bytes: size_bytes.max(0) as u64,
                        access_count: access_count.max(0) as u64,
                        last_accessed_at,
                    });
                }
                Ok(out)
            },
        )
        .await
        .map_err(|e| crate::federation::BlobError::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::BlobError::Backend(format!("sweep_candidates: {e}")))
    }

    /// v3.4.0 (CIRISPersist#123) — delete one `federation_blobs` row
    /// by SHA. Returns `true` iff a row was removed (rows-affected ==
    /// 1). Used by the Engine eviction loop after a successful
    /// withdraws emission.
    pub async fn delete_blob(
        &self,
        sha256: &[u8; 32],
    ) -> Result<bool, crate::federation::BlobError> {
        let sha_vec = sha256.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<usize, rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "DELETE FROM federation_blobs WHERE sha256 = ?1",
                rusqlite::params![sha_vec],
            )
        })
        .await
        .map_err(|e| crate::federation::BlobError::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::BlobError::Backend(format!("delete_blob: {e}")))
        .map(|n| n > 0)
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

// ─── BlackholeRules impl (v3.2.0, CIRISPersist#120) ────────────────
//
// SQLite-backed mirror of the V052 PG impl. Same upsert / remove /
// hit / prune contract; same in-RAM hash discipline (exclude `hits`
// from the canonical bytes so hot-path hit-recording doesn't force a
// re-hash).

#[async_trait::async_trait]
impl crate::federation::BlackholeRules for SqliteBackend {
    async fn blackhole_list(
        &self,
    ) -> Result<Vec<crate::federation::BlackholeRecord>, crate::federation::Error> {
        let conn = self.conn.clone();
        let rows = tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::federation::BlackholeRecord>, rusqlite::Error> {
                let conn = conn.blocking_lock();
                let mut stmt = conn.prepare(
                    "SELECT identity_hash, until, reason, added_at, hits, persist_row_hash \
                     FROM blackhole_rules \
                     ORDER BY added_at ASC",
                )?;
                let iter = stmt.query_map([], |row| {
                    let identity_hash: Vec<u8> = row.get(0)?;
                    let until_text: Option<String> = row.get(1)?;
                    let reason: Option<String> = row.get(2)?;
                    let added_at_text: String = row.get(3)?;
                    let hits: i64 = row.get(4)?;
                    let persist_row_hash: String = row.get(5)?;
                    Ok((
                        identity_hash,
                        until_text,
                        reason,
                        added_at_text,
                        hits,
                        persist_row_hash,
                    ))
                })?;
                let mut out = Vec::new();
                for r in iter {
                    let (identity_hash, until_text, reason, added_at_text, hits, persist_row_hash) =
                        r?;
                    let added_at = parse_rfc3339(&added_at_text);
                    let until = until_text.as_deref().map(parse_rfc3339);
                    out.push(crate::federation::BlackholeRecord {
                        identity_hash,
                        until,
                        reason,
                        added_at,
                        hits,
                        persist_row_hash,
                    });
                }
                Ok(out)
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("blackhole_list sqlite: {e}")))?;
        Ok(rows)
    }

    async fn blackhole_upsert(
        &self,
        identity_hash: &[u8],
        until: Option<chrono::DateTime<chrono::Utc>>,
        reason: Option<&str>,
    ) -> Result<(), crate::federation::Error> {
        crate::federation::blackhole::validate_identity_hash_len(identity_hash)?;
        let now = chrono::Utc::now();
        let identity_owned = identity_hash.to_vec();
        let reason_owned = reason.map(str::to_owned);
        let conn = self.conn.clone();
        let outcome = tokio::task::spawn_blocking(
            move || -> Result<Result<(), crate::federation::Error>, rusqlite::Error> {
                let mut conn = conn.blocking_lock();
                let tx = conn.transaction()?;
                let existing_added_at_text: Option<String> = tx
                    .query_row(
                        "SELECT added_at FROM blackhole_rules WHERE identity_hash = ?1",
                        [&identity_owned],
                        |r| r.get(0),
                    )
                    .optional()?;
                let added_at = match &existing_added_at_text {
                    Some(text) => parse_rfc3339(text),
                    None => now,
                };
                let new_hash = match crate::federation::blackhole::compute_blackhole_row_hash(
                    &identity_owned,
                    &until,
                    &reason_owned,
                    &added_at,
                ) {
                    Ok(h) => h,
                    Err(e) => return Ok(Err(e)),
                };
                let until_text = until.as_ref().map(|t| t.to_rfc3339());
                if existing_added_at_text.is_some() {
                    tx.execute(
                        "UPDATE blackhole_rules SET \
                            until = ?2, reason = ?3, persist_row_hash = ?4 \
                         WHERE identity_hash = ?1",
                        rusqlite::params![identity_owned, until_text, reason_owned, new_hash],
                    )?;
                } else {
                    let added_at_text = added_at.to_rfc3339();
                    tx.execute(
                        "INSERT INTO blackhole_rules \
                            (identity_hash, until, reason, added_at, hits, persist_row_hash) \
                         VALUES (?1, ?2, ?3, ?4, 0, ?5)",
                        rusqlite::params![
                            identity_owned,
                            until_text,
                            reason_owned,
                            added_at_text,
                            new_hash
                        ],
                    )?;
                }
                tx.commit()?;
                Ok(Ok(()))
            },
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("blackhole_upsert sqlite: {e}")))?;
        outcome
    }

    async fn blackhole_remove(&self, identity_hash: &[u8]) -> Result<(), crate::federation::Error> {
        crate::federation::blackhole::validate_identity_hash_len(identity_hash)?;
        let identity_owned = identity_hash.to_vec();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "DELETE FROM blackhole_rules WHERE identity_hash = ?1",
                [&identity_owned],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| crate::federation::Error::Backend(format!("blackhole_remove sqlite: {e}")))?;
        Ok(())
    }

    async fn blackhole_record_hit(
        &self,
        identity_hash: &[u8],
    ) -> Result<(), crate::federation::Error> {
        crate::federation::blackhole::validate_identity_hash_len(identity_hash)?;
        let identity_owned = identity_hash.to_vec();
        let conn = self.conn.clone();
        // Single-statement UPDATE; race-tolerant — silent no-op when
        // no row matches (rows-affected == 0).
        tokio::task::spawn_blocking(move || -> Result<(), rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE blackhole_rules SET hits = hits + 1 WHERE identity_hash = ?1",
                [&identity_owned],
            )?;
            Ok(())
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            crate::federation::Error::Backend(format!("blackhole_record_hit sqlite: {e}"))
        })?;
        Ok(())
    }

    async fn blackhole_prune_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, crate::federation::Error> {
        let now_str = now.to_rfc3339();
        let conn = self.conn.clone();
        let n = tokio::task::spawn_blocking(move || -> Result<u64, rusqlite::Error> {
            let conn = conn.blocking_lock();
            let affected = conn.execute(
                "DELETE FROM blackhole_rules \
                 WHERE until IS NOT NULL AND until < ?1",
                [&now_str],
            )?;
            Ok(affected as u64)
        })
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("spawn_blocking join: {e}")))?
        .map_err(|e| {
            crate::federation::Error::Backend(format!("blackhole_prune_expired sqlite: {e}"))
        })?;
        Ok(n)
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
    // v2.5.0 (CIRISPersist#102 Ask 8): attestation_evidence stored as
    // JSON-as-TEXT. NULL / absent column / empty string → None.
    // Matches the `roles_text` shape above: `.get(column).ok()`
    // swallows both rusqlite's absent-column Err and the NULL case.
    let evidence_text: Option<String> = row.get("attestation_evidence").ok();
    let attestation_evidence: Option<serde_json::Value> = evidence_text
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str(s).ok());
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
        attestation_evidence,
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
    // v3.7.0 (CIRISPersist#146, CEG 0.6) — subject_key_ids is stored
    // as TEXT containing a JSON array; deserialize at read time.
    let subject_key_ids_text: String = row.get("subject_key_ids")?;
    let subject_key_ids: Vec<String> =
        serde_json::from_str(&subject_key_ids_text).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            )
        })?;
    let withdraws_admission_rule: Option<i64> = row.get("withdraws_admission_rule")?;
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
        subject_key_ids,
        withdraws_admission_rule: withdraws_admission_rule.map(|v| v as u8),
        cohort_scope: row.get("cohort_scope")?,
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

/// v2.10.0 (CIRISPersist#114) — SQLite row → `Goal` projection.
/// SELECT statements that consume this MUST include all the columns
/// listed below (the typed converter pulls them by name); the
/// `persist_row_hash` column is not part of the value — persist's
/// `compute_persist_row_hash` recomputes it on demand from the
/// serde-default JSON form.
fn sqlite_row_to_goal(row: &rusqlite::Row<'_>) -> rusqlite::Result<crate::federation::Goal> {
    let goal_id_text: String = row.get("goal_id")?;
    let goal_id = uuid::Uuid::parse_str(&goal_id_text).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        )
    })?;
    let declared_at_text: String = row.get("declared_at")?;
    let scope_kind: String = row.get("scope_kind")?;
    let scope_cohort_id: Option<String> = row.get("scope_cohort_id")?;
    let scope = match scope_kind.as_str() {
        "single_declarer" => crate::federation::GoalScope::SingleDeclarer,
        "federation" => crate::federation::GoalScope::Federation,
        "cohort" => crate::federation::GoalScope::Cohort {
            cohort_id: scope_cohort_id.ok_or_else(|| {
                rusqlite::Error::FromSqlConversionFailure(
                    5,
                    rusqlite::types::Type::Text,
                    Box::new(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "scope_kind=cohort but scope_cohort_id is NULL (schema CHECK bypass?)",
                    )),
                )
            })?,
        },
        other => {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                4,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown scope_kind: {other}"),
                )),
            ));
        }
    };
    let meta_dimension_text: String = row.get("meta_dimension")?;
    let dimension = crate::federation::M1Dimension::from_wire_str(&meta_dimension_text)
        .ok_or_else(|| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("unknown meta_dimension: {meta_dimension_text}"),
                )),
            )
        })?;
    let meta_rationale: String = row.get("meta_rationale")?;
    let meta_deliberation_text: Option<String> = row.get("meta_deliberation")?;
    let deliberation_ref: Option<crate::federation::DeliberationRef> = match meta_deliberation_text
    {
        None => None,
        Some(s) if s.is_empty() => None,
        Some(s) => Some(serde_json::from_str(&s).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                8,
                rusqlite::types::Type::Text,
                Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            )
        })?),
    };
    let retired_at_text: Option<String> = row.get("retired_at")?;
    let alignment =
        crate::federation::MetaGoalAlignment::new(dimension, meta_rationale, deliberation_ref);
    let mut goal = crate::federation::Goal::new(
        goal_id,
        row.get("declared_by_key_id")?,
        parse_rfc3339(&declared_at_text),
        row.get("goal_text")?,
        scope,
        alignment,
    );
    goal.retired_at = retired_at_text.as_deref().map(parse_rfc3339);
    Ok(goal)
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
                    scrub_timestamp, pqc_completed_at, persist_row_hash, roles, \
                    attestation_evidence \
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
                    scrub_timestamp, pqc_completed_at, persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope \
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

    // v3.1.1 (CIRISPersist#118) — admission for
    // `edge_detection_events` (V020). Idempotent on detection_id
    // collision when persist_row_hash matches; raises Conflict on
    // collision with differing hash. detection_id is TEXT (UUID
    // as TEXT) on SQLite; subject_key_id FK to federation_keys
    // enforced via PRAGMA foreign_keys=ON (set at backend boot).
    async fn put_edge_detection_event(
        &self,
        event: crate::derived::EdgeDetectionEvent,
    ) -> Result<(), crate::derived::Error> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<(), crate::derived::Error> {
            let conn = conn.blocking_lock();
            let observed_at_text = event.observed_at.to_rfc3339();
            let evidence_text = serde_json::to_string(&event.evidence)
                .map_err(|e| crate::derived::Error::Backend(format!("evidence encode: {e}")))?;
            let rows = conn
                .execute(
                    "INSERT INTO edge_detection_events (\
                        detection_id, tenant_id, detector_kind, subject_key_id, \
                        observed_at, evidence, severity, signature, signing_key_id, \
                        signature_verified, persist_row_hash\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) \
                     ON CONFLICT (detection_id) DO NOTHING",
                    rusqlite::params![
                        event.detection_id,
                        event.tenant_id,
                        event.detector_kind,
                        event.subject_key_id,
                        observed_at_text,
                        evidence_text,
                        event.severity,
                        event.signature,
                        event.signing_key_id,
                        event.signature_verified as i64,
                        event.persist_row_hash,
                    ],
                )
                .map_err(sqlite_derived_err("insert edge_detection_events"))?;
            if rows == 0 {
                let existing: Option<String> = conn
                    .query_row(
                        "SELECT persist_row_hash FROM edge_detection_events \
                         WHERE detection_id = ?1",
                        rusqlite::params![event.detection_id],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(sqlite_derived_err("conflict check"))?;
                if let Some(existing_hash) = existing {
                    if existing_hash != event.persist_row_hash {
                        return Err(crate::derived::Error::Conflict(format!(
                            "detection_id {} already exists with different persist_row_hash",
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

    // v2.13.0 (CIRISPersist#113) — read facade over
    // `edge_detection_events` (V020). Stable ORDER BY
    // `(tenant_id ASC, observed_at ASC, detection_id ASC)` — the
    // change-feed polling cursor in
    // [`crate::Engine::subscribe_detection_events`] depends on
    // monotone ASC ordering to advance without re-yielding rows.
    async fn get_edge_detection_events(
        &self,
        filter: crate::derived::EdgeEventFilter,
    ) -> Result<Vec<crate::derived::EdgeDetectionEvent>, crate::derived::Error> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(
            move || -> Result<Vec<crate::derived::EdgeDetectionEvent>, crate::derived::Error> {
                let conn = conn.blocking_lock();
                let mut sql = String::from(
                    "SELECT detection_id, tenant_id, detector_kind, subject_key_id, \
                        observed_at, evidence, severity, signature, signing_key_id, \
                        signature_verified, persist_row_hash \
                     FROM edge_detection_events WHERE 1 = 1",
                );
                let mut binds: Vec<String> = Vec::new();
                if let Some(t) = filter.tenant_id {
                    binds.push(t);
                    sql.push_str(&format!(" AND tenant_id = ?{}", binds.len()));
                }
                if let Some(p) = filter.peer_key_id {
                    binds.push(p);
                    sql.push_str(&format!(" AND subject_key_id = ?{}", binds.len()));
                }
                if let Some(k) = filter.event_type {
                    binds.push(k);
                    sql.push_str(&format!(" AND detector_kind = ?{}", binds.len()));
                }
                if let Some(after) = filter.recorded_after {
                    // Strict `>` for the change-feed polling cursor — a
                    // re-poll at the same cursor must NOT yield the row
                    // that advanced the cursor.
                    binds.push(after.to_rfc3339());
                    sql.push_str(&format!(" AND observed_at > ?{}", binds.len()));
                }
                let limit = filter.limit.unwrap_or(1000);
                sql.push_str(&format!(
                    " ORDER BY tenant_id ASC, observed_at ASC, detection_id ASC LIMIT {limit}"
                ));

                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(sqlite_derived_err("get_edge_detection_events prepare"))?;
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(binds.iter()), |row| {
                        let detection_id: String = row.get(0)?;
                        let tenant_id: String = row.get(1)?;
                        let detector_kind: String = row.get(2)?;
                        let subject_key_id: String = row.get(3)?;
                        let observed_at_s: String = row.get(4)?;
                        let evidence_s: String = row.get(5)?;
                        let severity: String = row.get(6)?;
                        let signature: String = row.get(7)?;
                        let signing_key_id: String = row.get(8)?;
                        let signature_verified_i: i64 = row.get(9)?;
                        let persist_row_hash: String = row.get(10)?;
                        Ok((
                            detection_id,
                            tenant_id,
                            detector_kind,
                            subject_key_id,
                            observed_at_s,
                            evidence_s,
                            severity,
                            signature,
                            signing_key_id,
                            signature_verified_i,
                            persist_row_hash,
                        ))
                    })
                    .map_err(sqlite_derived_err("get_edge_detection_events query"))?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(sqlite_derived_err("get_edge_detection_events row"))?;

                let mut out = Vec::with_capacity(rows.len());
                for (
                    detection_id,
                    tenant_id,
                    detector_kind,
                    subject_key_id,
                    observed_at_s,
                    evidence_s,
                    severity,
                    signature,
                    signing_key_id,
                    signature_verified_i,
                    persist_row_hash,
                ) in rows
                {
                    let observed_at = chrono::DateTime::parse_from_rfc3339(&observed_at_s)
                        .map_err(|e| {
                            crate::derived::Error::Backend(format!("edge observed_at parse: {e}"))
                        })?
                        .with_timezone(&chrono::Utc);
                    let evidence: serde_json::Value =
                        serde_json::from_str(&evidence_s).map_err(|e| {
                            crate::derived::Error::Backend(format!(
                                "edge evidence JSON decode: {e}"
                            ))
                        })?;
                    out.push(crate::derived::EdgeDetectionEvent {
                        detection_id,
                        tenant_id,
                        detector_kind,
                        subject_key_id,
                        observed_at,
                        evidence,
                        severity,
                        signature,
                        signing_key_id,
                        signature_verified: signature_verified_i != 0,
                        persist_row_hash,
                    });
                }
                Ok(out)
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
            attestation_evidence: None,
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
            attestation_type: crate::federation::types::attestation_type::SCORES.into(),
            weight: Some(1.0),
            asserted_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            expires_at: None,
            // v2.4.0 admission gate (CIRISPersist#102 Ask 3) — `scores`
            // attestations need a versioned mechanism-descriptive
            // dimension. Test rows use a generic identity-binding
            // shape that passes the four-test gate.
            attestation_envelope: serde_json::json!({
                "id": id,
                "dimension": "identity_binding:v1",
                "score": 1.0,
                "confidence": 0.9,
            }),
            original_content_hash: "abc123".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
        }
    }

    // v3.7.0 (CIRISPersist#146, CEG 0.6) — round-trip a SignedAttestation
    // with non-empty subject_key_ids + a withdraws_admission_rule and
    // confirm the values survive the persist → read cycle.
    #[tokio::test]
    async fn put_attestation_round_trips_ceg06_subject_fields_sqlite() {
        use crate::federation::FederationDirectory;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("host-a", "primitive-a", "host-a"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("subject-1", "primitive-s1", "subject-1"),
            })
            .await
            .unwrap();
        let canonical_hash = format!("sha256:{}", "0".repeat(64));
        let mut row = fed_attestation("att-ceg06", "host-a", "host-a", "host-a");
        row.subject_key_ids = vec!["subject-1".into(), canonical_hash.clone()];
        row.withdraws_admission_rule = None; // scores row; rule only set on withdraws

        backend
            .put_attestation(SignedAttestation {
                attestation: row.clone(),
            })
            .await
            .unwrap();

        let got = backend
            .list_attestations_for("host-a")
            .await
            .unwrap()
            .into_iter()
            .find(|a| a.attestation_id == "att-ceg06")
            .expect("attestation round-tripped");
        assert_eq!(
            got.subject_key_ids,
            vec!["subject-1".to_string(), canonical_hash.clone()],
            "subject_key_ids round-trip (federation-key + canonical-hash entries)"
        );
        assert_eq!(got.withdraws_admission_rule, None);
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

    /// v2.6.0 (CIRISPersist#105) — class-based enumeration via
    /// `list_keys_by_identity_type` on SQLite. Two `steward` rows +
    /// one `primitive` row; verify ORDER BY key_id sort, the
    /// primitive singleton lookup, and the unknown-type empty case.
    /// Composite index `(identity_type, identity_ref)` from V004
    /// covers the WHERE predicate — no new migration required.
    ///
    /// Note: avoids `accord_holder` because V048's hardware-
    /// attestation admission hook + CHECK constraint require a
    /// non-software `PlatformAttestation` that ciris-keyring does
    /// not expose constructor surface for in tests (the existing
    /// trust-grant tests in this file likewise sidestep the
    /// accord-holder identity_type for the same reason). The
    /// contract being tested is class-filtering by the
    /// `identity_type` column; the specific identity_type strings
    /// don't affect the SQL path.
    #[tokio::test]
    async fn federation_list_keys_by_identity_type_round_trip() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // Insert in reverse lex order to confirm ORDER BY key_id sort.
        let mut steward_b = fed_key("steward-bravo", "steward-bravo", "steward-bravo");
        steward_b.identity_type = crate::federation::types::identity_type::STEWARD.into();
        let mut steward_a = fed_key("steward-alpha", "steward-alpha", "steward-alpha");
        steward_a.identity_type = crate::federation::types::identity_type::STEWARD.into();
        let prim = fed_key("prim-1", "prim-1", "prim-1"); // PRIMITIVE by default

        backend
            .put_public_key(SignedKeyRecord { record: steward_b })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord { record: steward_a })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord { record: prim })
            .await
            .unwrap();

        let steward_rows = backend
            .list_keys_by_identity_type(crate::federation::types::identity_type::STEWARD)
            .await
            .unwrap();
        assert_eq!(steward_rows.len(), 2);
        assert_eq!(steward_rows[0].key_id, "steward-alpha");
        assert_eq!(steward_rows[1].key_id, "steward-bravo");

        let prim_rows = backend
            .list_keys_by_identity_type(crate::federation::types::identity_type::PRIMITIVE)
            .await
            .unwrap();
        assert_eq!(prim_rows.len(), 1);
        assert_eq!(prim_rows[0].key_id, "prim-1");

        let empty = backend
            .list_keys_by_identity_type("unknown_type")
            .await
            .unwrap();
        assert!(empty.is_empty());
    }

    /// v2.6.0 (CIRISPersist#108) — confirm `persist_row_hash` is
    /// surfaced on the federation read paths so CIRISVerify v3.2.0+
    /// can populate `FederationProvenance::persist_row_hash`. The
    /// column exists from V001+; this test asserts the row-type
    /// field is non-empty (server-computed on insert) and stable
    /// across reads (idempotency).
    #[tokio::test]
    async fn federation_persist_row_hash_surfaces_on_reads() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("steward-1", "steward-1", "steward-1"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-target", "primitive-a", "steward-1"),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: fed_attestation("att-1", "steward-1", "k-target", "steward-1"),
            })
            .await
            .unwrap();
        backend
            .put_revocation(SignedRevocation {
                revocation: fed_revocation(
                    "11111111-1111-1111-1111-111111111111",
                    "k-target",
                    "steward-1",
                    "steward-1",
                ),
            })
            .await
            .unwrap();

        let key1 = FederationDirectory::lookup_public_key(&backend, "k-target")
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(key1.persist_row_hash.len(), 64, "row hash is 64 hex chars");
        let key2 = FederationDirectory::lookup_public_key(&backend, "k-target")
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(key1.persist_row_hash, key2.persist_row_hash);

        let att1 = backend.list_attestations_for("k-target").await.unwrap();
        assert_eq!(att1.len(), 1);
        assert_eq!(att1[0].persist_row_hash.len(), 64);
        let att2 = backend.list_attestations_for("k-target").await.unwrap();
        assert_eq!(att1[0].persist_row_hash, att2[0].persist_row_hash);

        let rev1 = backend.revocations_for("k-target").await.unwrap();
        assert_eq!(rev1.len(), 1);
        assert_eq!(rev1[0].persist_row_hash.len(), 64);
        let rev2 = backend.revocations_for("k-target").await.unwrap();
        assert_eq!(rev1[0].persist_row_hash, rev2[0].persist_row_hash);
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

    // ─── Admission-gate tests (v2.4.0, CIRISPersist#102 Ask 3) ──────

    /// Build a key with an explicit identity_type — covers the
    /// `accord_holder` vs `steward` distinction the gate switches on.
    /// When `identity_type = accord_holder` the helper auto-fills a
    /// valid hardware-attestation evidence value so the v2.5.0 admission
    /// gate (Ask 8) doesn't reject the fixture.
    fn fed_key_with_identity_type(
        key_id: &str,
        identity_ref: &str,
        scrub_key_id: &str,
        identity_type: &str,
    ) -> KeyRecord {
        let mut k = fed_key(key_id, identity_ref, scrub_key_id);
        k.identity_type = identity_type.into();
        if identity_type == crate::federation::types::identity_type::ACCORD_HOLDER {
            k.attestation_evidence = Some(serde_json::json!({
                "platform_attestation": {
                    "Android": {
                        "key_attestation_chain": [
                            vec![0x30u8, 0x82, 0x01, 0x00],
                            vec![0x30u8, 0x82, 0x02, 0x00],
                        ],
                        "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                        "strongbox_backed": true,
                    }
                },
                "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
            }));
        }
        k
    }

    /// Build a `scores` attestation with an explicit dimension; lets
    /// the test parameterize the field the gate evaluates.
    fn scores_attestation_with_dimension(
        id: &str,
        attesting: &str,
        attested: &str,
        scrub_key_id: &str,
        dimension: &str,
    ) -> Attestation {
        let mut a = fed_attestation(id, attesting, attested, scrub_key_id);
        a.attestation_envelope = serde_json::json!({
            "id": id,
            "dimension": dimension,
            "score": 1.0,
            "confidence": 0.9,
        });
        a
    }

    #[tokio::test]
    async fn sqlite_put_attestation_rejects_accord_dimension_from_steward() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key_with_identity_type(
                    "registry-steward",
                    "registry",
                    "registry-steward",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        let att = scores_attestation_with_dimension(
            "att-accord-1",
            "registry-steward",
            "k-a",
            "registry-steward",
            "accord:human_dignity:v1",
        );
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::federation::Error::AccordDimensionRequiresAccordHolder { .. }
        ));
        // No row leaked through.
        assert!(backend
            .list_attestations_for("k-a")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn sqlite_put_attestation_accepts_accord_dimension_from_accord_holder() {
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
                record: fed_key_with_identity_type(
                    "accord-holder-1",
                    "humanity-accord-1",
                    "registry-steward",
                    crate::federation::types::identity_type::ACCORD_HOLDER,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        let att = scores_attestation_with_dimension(
            "att-accord-2",
            "accord-holder-1",
            "k-a",
            "registry-steward",
            "accord:human_dignity:v1",
        );
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
        let rows = backend.list_attestations_for("k-a").await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn sqlite_put_attestation_rejects_morally_charged_dimension() {
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
                record: fed_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        let att = scores_attestation_with_dimension(
            "att-bad-1",
            "registry-steward",
            "k-a",
            "registry-steward",
            "emergent_deception:v1",
        );
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::DimensionRejected { reason, .. } => {
                assert_eq!(reason, "morally_charged_stem");
            }
            other => panic!("expected DimensionRejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sqlite_put_attestation_rejects_versionless_dimension() {
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
                record: fed_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        let att = scores_attestation_with_dimension(
            "att-bad-2",
            "registry-steward",
            "k-a",
            "registry-steward",
            "rights_asymmetry",
        );
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::DimensionRejected { reason, .. } => {
                assert_eq!(reason, "missing_version_segment");
            }
            other => panic!("expected DimensionRejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sqlite_put_attestation_accepts_correlated_action_v1() {
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
                record: fed_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        let att = scores_attestation_with_dimension(
            "att-good-1",
            "registry-steward",
            "k-a",
            "registry-steward",
            "detection:correlated_action:rights_asymmetry:v1",
        );
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
        let rows = backend.list_attestations_for("k-a").await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    async fn sqlite_put_attestation_exempts_structural_rename_chain() {
        // FSD-002 v1.2 Ask 5 delta — the rename chain
        // `delegates_to:correlated_action_v2:from:emergent_deception_v1`
        // is one of §2.2's four structural primitives. The dimension
        // would fail the morally-charged-stem test under `scores`,
        // but the structural primitive is exempt.
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
                record: fed_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        let mut att = scores_attestation_with_dimension(
            "att-rename-1",
            "registry-steward",
            "k-a",
            "registry-steward",
            "delegates_to:correlated_action_v2:from:emergent_deception_v1",
        );
        att.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
        let rows = backend.list_attestations_for("k-a").await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    // ─── v3.0.0 (CIRISPersist#116, CEG 0.2 §6.1) — structural-composer ──
    //     dedup + precedence tests.

    /// Build a structural-composer attestation with an envelope that
    /// carries the §6.1 `references_attestation_id` field. The
    /// attestation_type can be SUPERSEDES / WITHDRAWS / RECANTS.
    fn structural_composer_attestation(
        id: &str,
        attester: &str,
        ty: &str,
        references_attestation_id: &str,
        asserted_at: &str,
    ) -> Attestation {
        Attestation {
            attestation_id: id.into(),
            attesting_key_id: attester.into(),
            attested_key_id: attester.into(),
            attestation_type: ty.into(),
            weight: None,
            asserted_at: asserted_at.parse().unwrap(),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "references_attestation_id": references_attestation_id,
                "withdrawal_reason": "test",
            }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.into(),
            scrub_timestamp: asserted_at.parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
        }
    }

    #[tokio::test]
    async fn sqlite_put_attestation_structural_dedup_silent_noop_on_replay() {
        // CEG 0.2 §6.1 — a second `withdraws` with the same triple
        // `(references_attestation_id, attestation_type,
        // attesting_key_id)` is a silent no-op. The audit chain has
        // ONE row, not two.
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        for k in ["registry-steward", "k-a"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fed_key(k, k, "registry-steward"),
                })
                .await
                .unwrap();
        }
        let w1 = structural_composer_attestation(
            "w-1",
            "registry-steward",
            crate::federation::types::attestation_type::WITHDRAWS,
            "upstream-1",
            "2026-05-01T00:00:00Z",
        );
        let mut w2 = w1.clone();
        w2.attestation_id = "w-2".into();
        w2.asserted_at = "2026-05-02T00:00:00Z".parse().unwrap();
        backend
            .put_attestation(SignedAttestation { attestation: w1 })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation { attestation: w2 })
            .await
            .unwrap();
        let rows = backend
            .list_attestations_for("registry-steward")
            .await
            .unwrap();
        let withdraws_rows: Vec<_> = rows
            .iter()
            .filter(|r| r.attestation_type == crate::federation::types::attestation_type::WITHDRAWS)
            .collect();
        assert_eq!(
            withdraws_rows.len(),
            1,
            "second withdraws with same triple should be a silent no-op"
        );
        // First write wins on attestation_id (the second was silently
        // discarded).
        assert_eq!(withdraws_rows[0].attestation_id, "w-1");
    }

    #[tokio::test]
    async fn sqlite_put_attestation_structural_dedup_distinguishes_distinct_triples() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        for k in ["registry-steward", "k-a", "agent-2"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fed_key(k, k, "registry-steward"),
                })
                .await
                .unwrap();
        }
        // Same attester, different references → not a dup.
        let w1 = structural_composer_attestation(
            "w-r1",
            "registry-steward",
            crate::federation::types::attestation_type::WITHDRAWS,
            "upstream-1",
            "2026-05-01T00:00:00Z",
        );
        let w2 = structural_composer_attestation(
            "w-r2",
            "registry-steward",
            crate::federation::types::attestation_type::WITHDRAWS,
            "upstream-2",
            "2026-05-02T00:00:00Z",
        );
        // Same attester + references, different type → not a dup.
        let r3 = structural_composer_attestation(
            "r-r1",
            "registry-steward",
            crate::federation::types::attestation_type::RECANTS,
            "upstream-1",
            "2026-05-03T00:00:00Z",
        );
        // Different attester → not a dup.
        let w4 = structural_composer_attestation(
            "w-r3",
            "agent-2",
            crate::federation::types::attestation_type::WITHDRAWS,
            "upstream-1",
            "2026-05-04T00:00:00Z",
        );
        for att in [w1, w2, r3, w4] {
            backend
                .put_attestation(SignedAttestation { attestation: att })
                .await
                .unwrap();
        }
        let by_steward = backend
            .list_attestations_by("registry-steward")
            .await
            .unwrap();
        let composers: Vec<_> = by_steward
            .iter()
            .filter(|r| {
                matches!(
                    r.attestation_type.as_str(),
                    "withdraws" | "recants" | "supersedes"
                )
            })
            .collect();
        assert_eq!(composers.len(), 3, "expected three distinct triples");
        let by_agent = backend.list_attestations_by("agent-2").await.unwrap();
        assert_eq!(by_agent.len(), 1);
    }

    #[tokio::test]
    async fn sqlite_precedence_recants_wins_over_withdraws() {
        // CEG §6.1 — `recants` outranks `withdraws` regardless of
        // signed_at. Verified by composing the precedence_winner
        // helper over the same-attester chain.
        use crate::federation::precedence::{
            is_structural_composer, precedence_winner, references_attestation_id_from_envelope,
        };
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        for k in ["registry-steward", "k-a"] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fed_key(k, k, "registry-steward"),
                })
                .await
                .unwrap();
        }
        // recants earlier, withdraws later.
        let recants = structural_composer_attestation(
            "r-1",
            "registry-steward",
            crate::federation::types::attestation_type::RECANTS,
            "upstream-x",
            "2026-05-01T00:00:00Z",
        );
        let withdraws_later = structural_composer_attestation(
            "w-1",
            "registry-steward",
            crate::federation::types::attestation_type::WITHDRAWS,
            "upstream-x",
            "2026-06-01T00:00:00Z",
        );
        backend
            .put_attestation(SignedAttestation {
                attestation: recants,
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: withdraws_later,
            })
            .await
            .unwrap();
        let all = backend
            .list_attestations_by("registry-steward")
            .await
            .unwrap();
        let group: Vec<_> = all
            .iter()
            .filter(|r| {
                is_structural_composer(&r.attestation_type)
                    && references_attestation_id_from_envelope(&r.attestation_envelope)
                        == Some("upstream-x")
            })
            .collect();
        let winner = precedence_winner(&group).expect("non-empty");
        assert_eq!(winner.attestation_id, "r-1");
        assert_eq!(
            winner.attestation_type,
            crate::federation::types::attestation_type::RECANTS
        );
    }

    // ─── v3.0.0 (CIRISPersist#116, CEG 0.2 §7.0) — reserved-prefix ──

    #[tokio::test]
    async fn sqlite_put_attestation_rejects_system_prefix_from_agent() {
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
                record: fed_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        let att = scores_attestation_with_dimension(
            "att-sys-1",
            "registry-steward",
            "k-a",
            "registry-steward",
            "system:health:n_eff_measurable:v1",
        );
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::federation::Error::ReservedPrefixEmitterMismatch { .. }
            ),
            "expected ReservedPrefixEmitterMismatch, got {err:?}"
        );
    }

    #[tokio::test]
    async fn sqlite_put_attestation_accepts_system_prefix_from_substrate_persist() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key_with_identity_type(
                    "persist-self",
                    "persist",
                    "persist-self",
                    crate::federation::types::identity_type::SUBSTRATE_PERSIST,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-a", "primitive-a", "persist-self"),
            })
            .await
            .unwrap();
        let att = scores_attestation_with_dimension(
            "att-sys-2",
            "persist-self",
            "k-a",
            "persist-self",
            "system:health:n_eff_measurable:v1",
        );
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sqlite_put_attestation_admits_deprecated_attestation_ladder_in_transition() {
        // CEG 0.1 → 0.2 transition: `attestation:l1:self_verify` is
        // the deprecated 0.1 wire shape; persist admits it during the
        // transition window WITHOUT requiring `:v[0-9]+`.
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
                record: fed_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        let att = scores_attestation_with_dimension(
            "att-deprecated",
            "registry-steward",
            "k-a",
            "registry-steward",
            "attestation:l1:self_verify",
        );
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sqlite_put_attestation_admits_canonical_attestation_mechanism() {
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
                record: fed_key("k-a", "primitive-a", "registry-steward"),
            })
            .await
            .unwrap();
        let att = scores_attestation_with_dimension(
            "att-canonical",
            "registry-steward",
            "k-a",
            "registry-steward",
            "attestation:self_verify",
        );
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    // ─── BlobStorage tests (v2.3, CIRISPersist#103) ────────────────

    use crate::federation::{BlobBody, BlobError, BlobStorage, ExternalRef, PutBlobAttestation};

    fn blob_attestation(
        attesting_key_id: &str,
        scrub_key_id: &str,
        attestation_id: &str,
    ) -> PutBlobAttestation {
        // v3.0.0 (CIRISPersist#116, CEG 0.2 §10.1.2): use Utc::now()
        // so the row lands inside the DEFAULT_HOLDS_BYTES_TTL window
        // — `list_holders` now filters TTL-expired rows.
        PutBlobAttestation {
            attesting_key_id: attesting_key_id.into(),
            attestation_id: attestation_id.into(),
            original_content_hash_hex: "abcdef01".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: chrono::Utc::now(),
        }
    }

    async fn blob_test_backend() -> SqliteBackend {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // Bootstrap a federation key so the FK on holds_bytes
        // attestation's attesting_key_id is satisfied.
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("host-a", "primitive-a", "host-a"),
            })
            .await
            .unwrap();
        backend
    }

    fn sha256_of(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    #[tokio::test]
    async fn blob_inline_round_trip() {
        let backend = blob_test_backend().await;
        let bytes = b"hello blob world".to_vec();
        let sha = sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes.clone()),
                Some("application/octet-stream"),
                blob_attestation(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                ),
            )
            .await
            .expect("put inline");
        let got = backend.get_blob(&sha).await.expect("get").expect("present");
        assert_eq!(got, BlobBody::Inline(bytes));
    }

    #[tokio::test]
    async fn blob_external_round_trip() {
        let backend = blob_test_backend().await;
        let ext = ExternalRef {
            uri: "s3://my-bucket/path/to/object".into(),
            size_bytes: 12_345_678,
            media_type: Some("video/mp4".into()),
        };
        let sha = [0x55u8; 32];
        backend
            .put_blob(
                &sha,
                BlobBody::External(ext.clone()),
                Some("video/mp4"),
                blob_attestation(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                ),
            )
            .await
            .expect("put external");
        let got = backend.get_blob(&sha).await.expect("get").expect("present");
        assert_eq!(got, BlobBody::External(ext));
    }

    #[tokio::test]
    async fn blob_hash_mismatch_rejected() {
        let backend = blob_test_backend().await;
        let bytes = b"the bytes".to_vec();
        let wrong_sha = [0x00u8; 32]; // not the sha of `bytes`
        let err = backend
            .put_blob(
                &wrong_sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                ),
            )
            .await
            .expect_err("must reject");
        assert!(matches!(err, BlobError::HashMismatch { .. }));
        assert_eq!(err.kind(), "blob_hash_mismatch");
    }

    #[tokio::test]
    async fn blob_inline_size_cap_rejected() {
        // 2 MiB Inline against the default 1 MiB cap.
        let backend = blob_test_backend().await;
        let bytes = vec![0u8; 2 * 1024 * 1024];
        let sha = sha256_of(&bytes);
        let err = backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                ),
            )
            .await
            .expect_err("must reject");
        match err {
            BlobError::InlineSizeExceeded { size, cap } => {
                assert_eq!(size, 2 * 1024 * 1024);
                assert_eq!(cap, 1024 * 1024);
            }
            other => panic!("expected InlineSizeExceeded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn blob_has_blob_existence_check() {
        let backend = blob_test_backend().await;
        let bytes = b"ping".to_vec();
        let sha = sha256_of(&bytes);
        assert!(!backend.has_blob(&sha).await.unwrap());
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                ),
            )
            .await
            .unwrap();
        assert!(backend.has_blob(&sha).await.unwrap());

        let missing = [0xEEu8; 32];
        assert!(!backend.has_blob(&missing).await.unwrap());
    }

    #[tokio::test]
    async fn blob_list_holders_single_writer() {
        let backend = blob_test_backend().await;
        let bytes = b"a payload".to_vec();
        let sha = sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                ),
            )
            .await
            .unwrap();
        let holders = backend.list_holders(&sha).await.unwrap();
        assert_eq!(holders, vec!["host-a".to_string()]);
    }

    // Regression for CIRISPersist#130 reopen: list_holders must
    // report a locally-held blob's holder even when the holds_bytes
    // attestation was emitted with a stale timestamp (older than the
    // CEG §10.1.2 24h TTL). The bytes-on-disk in federation_blobs
    // are definitive proof of holding; freshness window only applies
    // to peer-discovered attestations where we lack the bytes.
    //
    // Closes the child-safety hole in cirisnode_process_takedown_-
    // admission, which calls list_holders internally — stale-attested
    // local content would otherwise evade NCMEC/CSAM/CourtOrder
    // eviction.
    #[tokio::test]
    async fn blob_list_holders_stale_local_repro_130() {
        use crate::federation::BlobStorage;
        let backend = evict_test_backend_with_actors(&["actor-a"]).await;
        let signer = test_signer_for("actor-a");
        let bytes = b"signed payload".to_vec();
        let sha = sha256_of(&bytes);
        let stale_ts = chrono::Utc::now() - chrono::Duration::hours(48);
        backend
            .put_blob_signing(
                &sha,
                BlobBody::Inline(bytes),
                None,
                "actor-a",
                &*signer,
                stale_ts,
                uuid::Uuid::new_v4(),
            )
            .await
            .unwrap();
        let holders = backend.list_holders(&sha).await.unwrap();
        assert_eq!(
            holders,
            vec!["actor-a".to_string()],
            "list_holders must include local writer even with stale attestation"
        );
    }

    #[tokio::test]
    async fn blob_list_holders_two_writers() {
        // Bootstrap a second host key.
        let backend = blob_test_backend().await;
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("host-b", "primitive-b", "host-b"),
            })
            .await
            .unwrap();

        let bytes = b"shared payload".to_vec();
        let sha = sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes.clone()),
                None,
                blob_attestation(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                ),
            )
            .await
            .unwrap();
        // Host B writes the SAME sha (same bytes) — second insert
        // collapses on PK but holder attestation lands.
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation(
                    "host-b",
                    "host-b",
                    uuid::Uuid::new_v4().to_string().as_str(),
                ),
            )
            .await
            .unwrap();
        let mut holders = backend.list_holders(&sha).await.unwrap();
        holders.sort();
        assert_eq!(holders, vec!["host-a".to_string(), "host-b".to_string()]);
    }

    #[tokio::test]
    async fn blob_idempotent_put_same_writer() {
        let backend = blob_test_backend().await;
        let bytes = b"same bytes twice".to_vec();
        let sha = sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes.clone()),
                None,
                blob_attestation(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                ),
            )
            .await
            .unwrap();
        // Same blob, same writer, fresh attestation_id. No error; the
        // blob row PK collapses, the attestation row lands.
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                ),
            )
            .await
            .unwrap();
        // list_holders dedups by attesting_key_id.
        let holders = backend.list_holders(&sha).await.unwrap();
        assert_eq!(holders, vec!["host-a".to_string()]);

        // get_blob returns the (idempotent) row exactly once.
        let got = backend.get_blob(&sha).await.unwrap().unwrap();
        assert_eq!(got.size_bytes(), 16);
    }

    #[tokio::test]
    async fn blob_conflicting_storage_kind_first_write_wins() {
        // Per the trait contract: first write's storage_kind wins on
        // SHA collision. This test pins the policy: Inline-first then
        // External-second leaves the row as Inline.
        let backend = blob_test_backend().await;
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("host-b", "primitive-b", "host-b"),
            })
            .await
            .unwrap();
        let bytes = b"will-be-inlined".to_vec();
        let sha = sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes.clone()),
                None,
                blob_attestation(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                ),
            )
            .await
            .unwrap();
        // Second writer claims the same SHA via External — trait
        // contract: silently keep the first row. Persist trusts the
        // caller-supplied SHA for External, so this does not error
        // and lands the holder attestation for host-b.
        backend
            .put_blob(
                &sha,
                BlobBody::External(ExternalRef {
                    uri: "s3://mirror/key".into(),
                    size_bytes: bytes.len() as u64,
                    media_type: None,
                }),
                None,
                blob_attestation(
                    "host-b",
                    "host-b",
                    uuid::Uuid::new_v4().to_string().as_str(),
                ),
            )
            .await
            .unwrap();
        let got = backend.get_blob(&sha).await.unwrap().unwrap();
        // First-write-wins: inline body preserved.
        match got {
            BlobBody::Inline(b) => assert_eq!(b, bytes),
            other => panic!("expected Inline, got {other:?}"),
        }
        let mut holders = backend.list_holders(&sha).await.unwrap();
        holders.sort();
        assert_eq!(holders, vec!["host-a".to_string(), "host-b".to_string()]);
    }

    // ─── v3.0.0 (CIRISPersist#116, CEG 0.2 §10.1.2) — holds_bytes ──
    //     24-hour TTL + ContentMiss feedback tests.

    /// Build a holds_bytes attestation with a CALLER-CHOSEN
    /// `scrub_timestamp` so tests can backdate the row to verify the
    /// TTL filter. Matches `blob_attestation()` shape but with the
    /// asserted_at / scrub_timestamp exposed.
    fn blob_attestation_at(
        attesting_key_id: &str,
        scrub_key_id: &str,
        attestation_id: &str,
        scrub_timestamp: chrono::DateTime<chrono::Utc>,
    ) -> PutBlobAttestation {
        PutBlobAttestation {
            attesting_key_id: attesting_key_id.into(),
            attestation_id: attestation_id.into(),
            original_content_hash_hex: "abcdef01".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp,
        }
    }

    // ── v3.5.2 (CIRISPersist#130) — list_local_holders ──────────────

    /// Stale (past-TTL) attestation for a locally-held blob: BOTH
    /// `list_holders` AND `list_local_holders` report the holder
    /// (v3.6.4 / #130 reopen — TTL bypass on local-truth applies to
    /// both query surfaces; `list_local_holders` remains the
    /// explicit-intent local-only path).
    #[tokio::test]
    async fn blob_list_local_holders_includes_stale_local_holding() {
        let backend = blob_test_backend().await;
        let bytes = b"local-truth-stale-blob".to_vec();
        let sha = sha256_of(&bytes);
        let backdated = chrono::Utc::now()
            - chrono::Duration::from_std(crate::federation::blobs::DEFAULT_HOLDS_BYTES_TTL)
                .unwrap()
            - chrono::Duration::hours(1);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation_at(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                    backdated,
                ),
            )
            .await
            .unwrap();
        let federation_holders = backend.list_holders(&sha).await.unwrap();
        assert_eq!(
            federation_holders,
            vec!["host-a".to_string()],
            "list_holders bypasses TTL when bytes are locally held"
        );
        let local_holders = backend.list_local_holders(&sha).await.unwrap();
        assert_eq!(local_holders, vec!["host-a".to_string()]);
    }

    /// `list_local_holders` returns `[]` when the blob is not in
    /// `federation_blobs` — the local-truth premise doesn't apply.
    #[tokio::test]
    async fn blob_list_local_holders_returns_empty_when_blob_absent() {
        let backend = blob_test_backend().await;
        let sha = sha256_of(b"not-locally-held");
        let holders = backend.list_local_holders(&sha).await.unwrap();
        assert!(holders.is_empty());
    }

    /// `list_local_holders` honors `withdraws` — explicit eviction
    /// signals trump TTL bypass.
    #[tokio::test]
    async fn blob_list_local_holders_filters_on_withdraws() {
        use crate::federation::types::{Attestation, SignedAttestation};
        let backend = blob_test_backend().await;
        let bytes = b"local-truth-withdrawn".to_vec();
        let sha = sha256_of(&bytes);
        let holds_id = uuid::Uuid::new_v4().to_string();
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation("host-a", "host-a", holds_id.as_str()),
            )
            .await
            .unwrap();
        // Sanity: present before withdraws.
        assert_eq!(
            backend.list_local_holders(&sha).await.unwrap(),
            vec!["host-a".to_string()]
        );
        // host-a emits the WITHDRAWS pointing at the holds_bytes row.
        let withdraws_envelope = serde_json::json!({
            "kind": "withdraws",
            "references_attestation_id": holds_id,
            "references_attestation_type": crate::federation::holds_bytes_attestation_type(&sha),
        });
        let withdraws_id = uuid::Uuid::new_v4().to_string();
        use crate::federation::FederationDirectory;
        backend
            .put_attestation(SignedAttestation {
                attestation: Attestation {
                    attestation_id: withdraws_id,
                    attesting_key_id: "host-a".into(),
                    attested_key_id: "host-a".into(),
                    attestation_type: crate::federation::types::attestation_type::WITHDRAWS.into(),
                    weight: None,
                    asserted_at: chrono::Utc::now(),
                    expires_at: None,
                    attestation_envelope: withdraws_envelope,
                    original_content_hash: "abcdef02".into(),
                    scrub_signature_classical: "c2ln".into(),
                    scrub_signature_pqc: None,
                    scrub_key_id: "host-a".into(),
                    scrub_timestamp: chrono::Utc::now(),
                    pqc_completed_at: None,
                    persist_row_hash: String::new(),
                    subject_key_ids: Vec::new(),
                    withdraws_admission_rule: None,
                    cohort_scope: "federation".to_string(),
                },
            })
            .await
            .unwrap();
        // Withdraws active: list_local_holders drops the row.
        assert!(backend.list_local_holders(&sha).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn blob_list_holders_locally_held_bypasses_ttl() {
        // v3.6.4 (CIRISPersist#130 reopen): a locally-held blob (row
        // present in federation_blobs) reports its holder regardless
        // of the holds_bytes attestation's age. CEG §10.1.2 TTL is a
        // federation-discovery backstop; for local-truth, the bytes
        // themselves are definitive. Closes the takedown-handler
        // child-safety hole where stale-attested local content
        // evaded eviction.
        let backend = blob_test_backend().await;
        let bytes = b"ttl-expired-blob".to_vec();
        let sha = sha256_of(&bytes);
        let backdated = chrono::Utc::now()
            - chrono::Duration::from_std(crate::federation::blobs::DEFAULT_HOLDS_BYTES_TTL)
                .unwrap()
            - chrono::Duration::hours(1);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation_at(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                    backdated,
                ),
            )
            .await
            .unwrap();
        let holders = backend.list_holders(&sha).await.unwrap();
        assert_eq!(
            holders,
            vec!["host-a".to_string()],
            "locally-held blob reports holder regardless of attestation age, got {holders:?}"
        );
    }

    #[tokio::test]
    async fn blob_list_holders_includes_fresh_ttl() {
        // Same shape as the expired test, but inside the freshness
        // window — the row stays.
        let backend = blob_test_backend().await;
        let bytes = b"ttl-fresh-blob".to_vec();
        let sha = sha256_of(&bytes);
        let fresh = chrono::Utc::now() - chrono::Duration::hours(1);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation_at(
                    "host-a",
                    "host-a",
                    uuid::Uuid::new_v4().to_string().as_str(),
                    fresh,
                ),
            )
            .await
            .unwrap();
        let holders = backend.list_holders(&sha).await.unwrap();
        assert_eq!(holders, vec!["host-a".to_string()]);
    }

    #[tokio::test]
    async fn blob_list_holders_drops_withdrawn_via_content_miss() {
        // CEG §10.1.2 — the consumer that fetched and saw a
        // ContentMiss emits a `withdraws` referencing the stale
        // holds_bytes row's attestation_id. list_holders MUST drop
        // the row.
        let backend = blob_test_backend().await;
        let bytes = b"content-miss-blob".to_vec();
        let sha = sha256_of(&bytes);
        let holds_bytes_attestation_id = uuid::Uuid::new_v4().to_string();
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation("host-a", "host-a", holds_bytes_attestation_id.as_str()),
            )
            .await
            .unwrap();
        // Sanity: present before withdraws.
        let holders = backend.list_holders(&sha).await.unwrap();
        assert_eq!(holders, vec!["host-a".to_string()]);

        // host-a emits the WITHDRAWS pointing at the holds_bytes row.
        let withdraws = structural_composer_attestation(
            "w-content-miss-1",
            "host-a",
            crate::federation::types::attestation_type::WITHDRAWS,
            &holds_bytes_attestation_id,
            "2026-05-27T00:00:00Z",
        );
        backend
            .put_attestation(SignedAttestation {
                attestation: withdraws,
            })
            .await
            .unwrap();

        let holders = backend.list_holders(&sha).await.unwrap();
        assert!(
            holders.is_empty(),
            "expected withdrawn holder to be filtered, got {holders:?}"
        );
    }

    // ─── v3.5.0 (CIRISPersist#125) — list_held_by + evict_actor ────

    /// A signer that always errors on `sign()` — used to exercise
    /// `evict_actor`'s `withdraws_failed` path. Every other
    /// `HardwareSigner` method delegates to a real signer so the FK
    /// shape stays intact.
    struct AlwaysFailingSigner {
        inner: std::sync::Arc<crate::signing::LocalSignerHardwareAdapter>,
    }

    #[async_trait::async_trait]
    impl ciris_keyring::HardwareSigner for AlwaysFailingSigner {
        fn algorithm(&self) -> ciris_keyring::ClassicalAlgorithm {
            self.inner.algorithm()
        }
        fn hardware_type(&self) -> ciris_keyring::HardwareType {
            self.inner.hardware_type()
        }
        async fn public_key(&self) -> Result<Vec<u8>, ciris_keyring::KeyringError> {
            self.inner.public_key().await
        }
        async fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, ciris_keyring::KeyringError> {
            Err(ciris_keyring::KeyringError::SigningFailed {
                reason: "test signer always fails".into(),
            })
        }
        async fn attestation(
            &self,
        ) -> Result<ciris_keyring::PlatformAttestation, ciris_keyring::KeyringError> {
            self.inner.attestation().await
        }
        async fn generate_key(
            &self,
            cfg: &ciris_keyring::KeyGenConfig,
        ) -> Result<(), ciris_keyring::KeyringError> {
            self.inner.generate_key(cfg).await
        }
        async fn key_exists(&self, alias: &str) -> Result<bool, ciris_keyring::KeyringError> {
            self.inner.key_exists(alias).await
        }
        async fn delete_key(&self, alias: &str) -> Result<(), ciris_keyring::KeyringError> {
            self.inner.delete_key(alias).await
        }
        fn current_alias(&self) -> &str {
            self.inner.current_alias()
        }
        fn storage_descriptor(&self) -> ciris_keyring::StorageDescriptor {
            self.inner.storage_descriptor()
        }
        async fn attestation_with_nonce(
            &self,
            nonce: Option<&[u8]>,
        ) -> Result<ciris_keyring::PlatformAttestation, ciris_keyring::KeyringError> {
            self.inner.attestation_with_nonce(nonce).await
        }
    }

    fn test_signer_for(alias: &str) -> std::sync::Arc<crate::signing::LocalSignerHardwareAdapter> {
        use crate::signing::{LocalSigner, LocalSignerHardwareAdapter};
        use ed25519_dalek::SigningKey;
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let local = std::sync::Arc::new(LocalSigner::from_parts(
            signing_key,
            alias.to_owned(),
            None,
            None,
        ));
        std::sync::Arc::new(LocalSignerHardwareAdapter::new(local))
    }

    async fn evict_test_backend_with_actors(actors: &[&str]) -> SqliteBackend {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        for actor in actors {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fed_key(actor, actor, actor),
                })
                .await
                .unwrap();
        }
        backend
    }

    /// Seed `n` blobs from `actor`. Each blob has a unique payload so
    /// the SHAs differ. Returns the SHAs in insert order.
    async fn seed_blobs(
        backend: &SqliteBackend,
        actor: &str,
        signer: &dyn ciris_keyring::HardwareSigner,
        n: usize,
        tag: &str,
    ) -> Vec<[u8; 32]> {
        use crate::federation::{BlobBody, BlobStorage};
        let mut shas = Vec::with_capacity(n);
        for i in 0..n {
            let bytes = format!("{actor}-{tag}-{i}").into_bytes();
            let sha = sha256_of(&bytes);
            backend
                .put_blob_signing(
                    &sha,
                    BlobBody::Inline(bytes),
                    None,
                    actor,
                    signer,
                    chrono::Utc::now(),
                    uuid::Uuid::new_v4(),
                )
                .await
                .unwrap();
            shas.push(sha);
        }
        shas
    }

    #[tokio::test]
    async fn list_held_by_returns_actor_shas_sqlite() {
        let backend = evict_test_backend_with_actors(&["actor-a", "actor-b"]).await;
        let signer = test_signer_for("actor-a");
        let signer_b = test_signer_for("actor-b");
        let shas_a = seed_blobs(&backend, "actor-a", &*signer, 3, "main").await;
        let shas_b = seed_blobs(&backend, "actor-b", &*signer_b, 2, "main").await;

        use crate::federation::BlobStorage;
        let mut held_a = backend.list_held_by("actor-a").await.unwrap();
        held_a.sort();
        let mut expected_a = shas_a.clone();
        expected_a.sort();
        assert_eq!(held_a, expected_a, "A's holdings");

        let mut held_b = backend.list_held_by("actor-b").await.unwrap();
        held_b.sort();
        let mut expected_b = shas_b.clone();
        expected_b.sort();
        assert_eq!(held_b, expected_b, "B's holdings");
    }

    #[tokio::test]
    async fn list_held_by_filters_withdrawn_sqlite() {
        // Seed one blob from actor-a, emit `withdraws` against the
        // holds_bytes attestation, assert list_held_by(A) excludes it.
        let backend = evict_test_backend_with_actors(&["actor-a"]).await;
        let signer = test_signer_for("actor-a");
        let shas = seed_blobs(&backend, "actor-a", &*signer, 1, "withdrawn").await;

        // Look up the holds_bytes attestation_id we just emitted.
        use crate::federation::FederationDirectory;
        let atts = backend.list_attestations_by("actor-a").await.unwrap();
        let holds_bytes = atts
            .into_iter()
            .find(|a| {
                a.attestation_type
                    .starts_with(crate::federation::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX)
            })
            .expect("holds_bytes from actor-a");
        let withdraws = structural_composer_attestation(
            &uuid::Uuid::new_v4().to_string(),
            "actor-a",
            crate::federation::types::attestation_type::WITHDRAWS,
            &holds_bytes.attestation_id,
            "2026-05-27T00:00:00Z",
        );
        backend
            .put_attestation(SignedAttestation {
                attestation: withdraws,
            })
            .await
            .unwrap();

        use crate::federation::BlobStorage;
        let held = backend.list_held_by("actor-a").await.unwrap();
        assert!(
            !held.contains(&shas[0]),
            "withdrawn blob must be excluded, got {held:?}"
        );
    }

    #[tokio::test]
    async fn evict_actor_evicts_blobs_and_emits_withdraws_sqlite() {
        let backend = evict_test_backend_with_actors(&["actor-a", "actor-b"]).await;
        let signer_a = test_signer_for("actor-a");
        let signer_b = test_signer_for("actor-b");
        let shas_a = seed_blobs(&backend, "actor-a", &*signer_a, 3, "evict").await;
        let shas_b = seed_blobs(&backend, "actor-b", &*signer_b, 2, "evict").await;

        use crate::federation::BlobStorage;
        let report = backend
            .evict_actor("actor-a", &*signer_a, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(report.blobs_evicted, 3, "A's 3 blobs evicted");
        assert_eq!(report.withdraws_emitted, 3, "3 withdraws emitted");
        assert_eq!(report.withdraws_failed, 0, "no failures");

        // A's blobs gone.
        for sha in &shas_a {
            assert!(
                !backend.has_blob(sha).await.unwrap(),
                "A's blob {sha:?} should be gone"
            );
        }
        // B's blobs intact.
        for sha in &shas_b {
            assert!(
                backend.has_blob(sha).await.unwrap(),
                "B's blob {sha:?} must remain"
            );
        }
    }

    #[tokio::test]
    async fn evict_actor_no_holdings_returns_zero_report_sqlite() {
        let backend = evict_test_backend_with_actors(&["actor-a"]).await;
        let signer = test_signer_for("actor-a");

        use crate::federation::BlobStorage;
        let report = backend
            .evict_actor("actor-a", &*signer, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(report, crate::federation::EvictActorReport::default());
    }

    #[tokio::test]
    async fn evict_actor_returns_correct_report_under_partial_failure_sqlite() {
        // Seed 1 blob; use a signer that fails sign() so the
        // withdraws emission fails. The blob row MUST still be
        // evicted — fail-honest contract.
        let backend = evict_test_backend_with_actors(&["actor-a"]).await;
        let real_signer = test_signer_for("actor-a");
        let shas = seed_blobs(&backend, "actor-a", &*real_signer, 1, "partial").await;

        let failing = AlwaysFailingSigner {
            inner: real_signer.clone(),
        };
        use crate::federation::BlobStorage;
        let report = backend
            .evict_actor("actor-a", &failing, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(report.blobs_evicted, 1, "blob still evicted");
        assert_eq!(report.withdraws_emitted, 0, "no withdraws emitted");
        assert_eq!(report.withdraws_failed, 1, "1 withdraws failed");
        assert!(
            !backend.has_blob(&shas[0]).await.unwrap(),
            "blob row deletion proceeds despite withdraws failure"
        );
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

    // ─── Ask 4: envelope-schema admission hook (v2.5.0) ─────────────

    /// Build a per-axis JSON Schema requiring score/confidence/
    /// dimension fields + an evidence_refs array that includes the
    /// schema's own SHA (the FSD-002 §4.9.1 "evidence-shape
    /// requirement" rule). The schema body is content-addressed —
    /// the caller passes the SHA so the schema can reference its
    /// own identity in `evidence_refs`.
    fn rights_asymmetry_v1_schema(schema_sha_hex: &str) -> serde_json::Value {
        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["dimension", "score", "confidence", "evidence_refs"],
            "properties": {
                "dimension": {"type": "string"},
                "score": {"type": "number", "minimum": -1.0, "maximum": 1.0},
                "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "evidence_refs": {
                    "type": "array",
                    "items": {"type": "string"},
                    "contains": {"const": schema_sha_hex},
                },
            },
        })
    }

    #[tokio::test]
    async fn sqlite_axis_from_dimension_worked_example() {
        // Smoke-test the helper through the public re-export.
        assert_eq!(
            crate::federation::axis_from_dimension(
                "detection:correlated_action:rights_asymmetry:v1"
            ),
            Some("rights_asymmetry")
        );
    }

    #[tokio::test]
    async fn sqlite_noop_resolver_default_admits_everything() {
        // Smoke: default resolver is NoOp → schema gate is a no-op.
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("rs", "registry", "rs"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-a", "primitive-a", "rs"),
            })
            .await
            .unwrap();
        let att = scores_attestation_with_dimension(
            "att-noop-1",
            "rs",
            "k-a",
            "rs",
            "detection:correlated_action:rights_asymmetry:v1",
        );
        // Schema-resolver wasn't installed; the gate skips.
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sqlite_blob_backed_resolver_round_trip() {
        // Write a schema blob, register the axis → SHA, resolve(dim),
        // confirm the resolver returns Some(schema).
        let backend = std::sync::Arc::new(SqliteBackend::open_in_memory().await.unwrap());
        backend.run_migrations().await.unwrap();
        // Bootstrap a federation key so put_blob's holder attestation
        // can hang off something.
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("rs", "registry", "rs"),
            })
            .await
            .unwrap();

        let schema = serde_json::json!({"type": "object"});
        let bytes = serde_json::to_vec(&schema).unwrap();
        let sha: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&bytes).into()
        };
        use crate::federation::BlobStorage;
        let put_att = crate::federation::PutBlobAttestation {
            attesting_key_id: "rs".into(),
            attestation_id: uuid::Uuid::new_v4().to_string(),
            original_content_hash_hex: hex::encode([0xab; 32]),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: "rs".into(),
            scrub_timestamp: chrono::Utc::now(),
        };
        backend
            .put_blob(
                &sha,
                crate::federation::BlobBody::Inline(bytes.clone()),
                Some("application/schema+json"),
                put_att,
            )
            .await
            .unwrap();

        let mut axis_index = std::collections::HashMap::new();
        axis_index.insert("rights_asymmetry".to_owned(), sha);
        let resolver =
            crate::federation::BlobBackedSchemaResolver::new(axis_index, backend.clone());
        let resolved = crate::federation::SchemaResolver::resolve(
            &resolver,
            "detection:correlated_action:rights_asymmetry:v1",
        )
        .await
        .unwrap()
        .expect("resolver returns Some(schema)");
        assert_eq!(resolved.sha256, sha);
        assert_eq!(resolved.document, schema);
        // Cache hit: second call should land in the cache (don't need
        // to delete the blob to prove this — the BlobBackedSchemaResolver's
        // `cached()` introspection is sufficient).
        assert!(
            resolver.cached(&sha),
            "schema body cached after first resolve"
        );
        // Resolve again — still works.
        let resolved2 = crate::federation::SchemaResolver::resolve(
            &resolver,
            "detection:correlated_action:rights_asymmetry:v1",
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(resolved2.document, schema);
    }

    #[tokio::test]
    async fn sqlite_put_attestation_with_schema_accepts_valid_envelope() {
        let backend = std::sync::Arc::new(SqliteBackend::open_in_memory().await.unwrap());
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("rs", "registry", "rs"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-a", "primitive-a", "rs"),
            })
            .await
            .unwrap();

        // Bootstrap the schema blob.
        let bytes_placeholder = b"placeholder";
        let mut sha = [0u8; 32];
        {
            use sha2::{Digest, Sha256};
            // Compute SHA on the actual schema body once it knows its
            // own SHA — chicken-and-egg avoided by computing on a
            // simpler placeholder and using THAT sha inside the schema.
            sha.copy_from_slice(&Sha256::digest(bytes_placeholder));
        }
        let schema = rights_asymmetry_v1_schema(&hex::encode(sha));
        let schema_bytes = serde_json::to_vec(&schema).unwrap();
        let schema_sha: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&schema_bytes).into()
        };

        use crate::federation::BlobStorage;
        let put_att = crate::federation::PutBlobAttestation {
            attesting_key_id: "rs".into(),
            attestation_id: uuid::Uuid::new_v4().to_string(),
            original_content_hash_hex: hex::encode([0xab; 32]),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: "rs".into(),
            scrub_timestamp: chrono::Utc::now(),
        };
        backend
            .put_blob(
                &schema_sha,
                crate::federation::BlobBody::Inline(schema_bytes),
                Some("application/schema+json"),
                put_att,
            )
            .await
            .unwrap();

        // Install the resolver pointing at the schema_sha (the schema
        // requires evidence_refs to contain the placeholder sha for
        // simplicity — what matters for the test is the validator
        // accepts when the envelope satisfies the schema).
        let mut axis_index = std::collections::HashMap::new();
        axis_index.insert("rights_asymmetry".to_owned(), schema_sha);
        let resolver = std::sync::Arc::new(crate::federation::BlobBackedSchemaResolver::new(
            axis_index,
            backend.clone(),
        ));
        backend.set_schema_resolver(resolver);

        let mut att = scores_attestation_with_dimension(
            "att-valid-1",
            "rs",
            "k-a",
            "rs",
            "detection:correlated_action:rights_asymmetry:v1",
        );
        // Envelope satisfies the schema (has evidence_refs containing
        // the placeholder SHA the schema requires).
        att.attestation_envelope = serde_json::json!({
            "dimension": "detection:correlated_action:rights_asymmetry:v1",
            "score": 0.42,
            "confidence": 0.9,
            "evidence_refs": [hex::encode(sha)],
        });
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn sqlite_put_attestation_rejects_envelope_missing_required_field() {
        let backend = std::sync::Arc::new(SqliteBackend::open_in_memory().await.unwrap());
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("rs", "registry", "rs"),
            })
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-a", "primitive-a", "rs"),
            })
            .await
            .unwrap();

        let schema = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["dimension", "score", "confidence", "evidence_refs"],
            "properties": {
                "evidence_refs": {"type": "array", "minItems": 1},
            },
        });
        let schema_bytes = serde_json::to_vec(&schema).unwrap();
        let schema_sha: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&schema_bytes).into()
        };
        use crate::federation::BlobStorage;
        let put_att = crate::federation::PutBlobAttestation {
            attesting_key_id: "rs".into(),
            attestation_id: uuid::Uuid::new_v4().to_string(),
            original_content_hash_hex: hex::encode([0xab; 32]),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: "rs".into(),
            scrub_timestamp: chrono::Utc::now(),
        };
        backend
            .put_blob(
                &schema_sha,
                crate::federation::BlobBody::Inline(schema_bytes),
                Some("application/schema+json"),
                put_att,
            )
            .await
            .unwrap();

        let mut axis_index = std::collections::HashMap::new();
        axis_index.insert("rights_asymmetry".to_owned(), schema_sha);
        let resolver = std::sync::Arc::new(crate::federation::BlobBackedSchemaResolver::new(
            axis_index,
            backend.clone(),
        ));
        backend.set_schema_resolver(resolver);

        let mut att = scores_attestation_with_dimension(
            "att-bad-1",
            "rs",
            "k-a",
            "rs",
            "detection:correlated_action:rights_asymmetry:v1",
        );
        // Envelope is missing evidence_refs entirely.
        att.attestation_envelope = serde_json::json!({
            "dimension": "detection:correlated_action:rights_asymmetry:v1",
            "score": 0.42,
            "confidence": 0.9,
        });
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::EnvelopeSchemaViolation {
                axis, violations, ..
            } => {
                assert_eq!(axis, "rights_asymmetry");
                assert!(!violations.is_empty());
            }
            other => panic!("expected EnvelopeSchemaViolation, got {other:?}"),
        }
    }

    // ─── Ask 8: hardware-attestation admission gate (v2.5.0) ────────

    /// Build an accord-holder KeyRecord with the given evidence value.
    fn accord_holder_key_with_evidence(
        key_id: &str,
        evidence: Option<serde_json::Value>,
    ) -> KeyRecord {
        let mut k = fed_key(key_id, "humanity-accord-x", key_id);
        k.identity_type = crate::federation::types::identity_type::ACCORD_HOLDER.into();
        k.attestation_evidence = evidence;
        k
    }

    fn android_strongbox_evidence_value(
        captured_at: chrono::DateTime<chrono::Utc>,
    ) -> serde_json::Value {
        serde_json::json!({
            "platform_attestation": {
                "Android": {
                    "key_attestation_chain": [
                        vec![0x30u8, 0x82, 0x01, 0x00],
                        vec![0x30u8, 0x82, 0x02, 0x00],
                    ],
                    "play_integrity_token": "eyJhbGciOiJIUzI1NiJ9.fake.token",
                    "strongbox_backed": true,
                }
            },
            "nonce_captured_at": captured_at.to_rfc3339(),
        })
    }

    #[tokio::test]
    async fn sqlite_put_public_key_rejects_accord_holder_without_evidence() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let key = accord_holder_key_with_evidence("ah-no-ev", None);
        let err = backend
            .put_public_key(SignedKeyRecord { record: key })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::AccordHolderRequiresAttestationEvidence {
                detail, ..
            } => {
                assert_eq!(detail, "missing");
            }
            other => panic!("expected AccordHolderRequiresAttestationEvidence, got {other:?}"),
        }
        // Nothing landed.
        assert!(
            crate::federation::FederationDirectory::lookup_public_key(&backend, "ah-no-ev")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn sqlite_put_public_key_rejects_accord_holder_software_only() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let ev = serde_json::json!({
            "platform_attestation": {
                "Software": {
                    "key_derivation": "random",
                    "storage": "memory",
                    "security_warning": "test"
                }
            },
            "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
        });
        let key = accord_holder_key_with_evidence("ah-sw", Some(ev));
        let err = backend
            .put_public_key(SignedKeyRecord { record: key })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::HardwareTypeNotAccepted { got, .. } => {
                assert_eq!(got, "SoftwareOnly");
            }
            other => panic!("expected HardwareTypeNotAccepted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sqlite_put_public_key_rejects_accord_holder_tpm_missing_pcr() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let ev = serde_json::json!({
            "platform_attestation": {
                "Tpm": {
                    "tpm_version": "2.0",
                    "manufacturer": "Infineon",
                    "discrete": true,
                    "quote": {
                        "quoted": vec![0xffu8; 32],
                        "signature": vec![0xeeu8; 64],
                        "pcr_selection": [0x03],
                        "qualifying_data": vec![0u8; 32],
                        "pcr_values": null,
                        "timestamp": 1_700_000_000u64,
                    },
                    "ek_cert": [0x30, 0x82, 0x01, 0x00],
                    "ak_public_key": [0x04, 0x01, 0x02],
                }
            },
            "nonce_captured_at": chrono::Utc::now().to_rfc3339(),
        });
        let key = accord_holder_key_with_evidence("ah-tpm-nopcr", Some(ev));
        let err = backend
            .put_public_key(SignedKeyRecord { record: key })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::AttestationEvidenceIncomplete {
                hardware_type,
                missing_fields,
            } => {
                assert_eq!(hardware_type, "TpmDiscrete");
                assert!(missing_fields.iter().any(|f| f == "pcr_values"));
            }
            other => panic!("expected AttestationEvidenceIncomplete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sqlite_put_public_key_rejects_accord_holder_stale_nonce() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let captured = chrono::Utc::now() - chrono::Duration::hours(48);
        let ev = android_strongbox_evidence_value(captured);
        let key = accord_holder_key_with_evidence("ah-stale", Some(ev));
        let err = backend
            .put_public_key(SignedKeyRecord { record: key })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::AttestationEvidenceStale { max_age_secs, .. } => {
                assert_eq!(max_age_secs, 86_400);
            }
            other => panic!("expected AttestationEvidenceStale, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sqlite_put_public_key_accepts_accord_holder_android_strongbox() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let ev = android_strongbox_evidence_value(chrono::Utc::now());
        let key = accord_holder_key_with_evidence("ah-ok", Some(ev));
        backend
            .put_public_key(SignedKeyRecord { record: key })
            .await
            .unwrap();
        let read = crate::federation::FederationDirectory::lookup_public_key(&backend, "ah-ok")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.identity_type, "accord_holder");
        assert!(read.attestation_evidence.is_some());
    }

    #[tokio::test]
    async fn sqlite_put_public_key_accepts_non_accord_holder_without_evidence() {
        // Non-accord-holder rows: column is informational; absence is fine.
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let key = fed_key("steward-k", "registry", "steward-k");
        backend
            .put_public_key(SignedKeyRecord { record: key })
            .await
            .unwrap();
        let read = crate::federation::FederationDirectory::lookup_public_key(&backend, "steward-k")
            .await
            .unwrap()
            .unwrap();
        assert!(read.attestation_evidence.is_none());
    }

    #[tokio::test]
    async fn sqlite_schema_check_constraint_catches_direct_sql_bypass() {
        // The SQLite trigger fires when the admission hook is
        // bypassed (e.g., direct INSERT with identity_type=accord_holder
        // and NULL attestation_evidence). Belt-and-suspenders test.
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let conn = backend.conn_handle();
        let result = tokio::task::spawn_blocking(move || {
            let c = conn.blocking_lock();
            c.execute(
                "INSERT INTO federation_keys (key_id, pubkey_ed25519_base64, algorithm, \
                    identity_type, identity_ref, valid_from, registration_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_key_id, \
                    scrub_timestamp, persist_row_hash) \
                 VALUES ('ah-direct', 'AA==', 'hybrid', 'accord_holder', 'x', \
                    '2026-01-01T00:00:00Z', '{}', X'aa', 's', 'ah-direct', \
                    '2026-01-01T00:00:00Z', 'h')",
                [],
            )
        })
        .await
        .unwrap();
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("federation_keys_accord_holder_requires_attestation"),
            "expected trigger to fire, got: {err}"
        );
    }

    // ─── #104 topology aggregate-query tests ────────────────────────

    /// Build an `Attestation` of the given `attestation_type` with a
    /// stable test envelope. The wire-vocabulary tests below use this
    /// to seed `delegates_to` / `withdraws` / `recants` rows alongside
    /// `scores` rows.
    #[allow(clippy::too_many_arguments)]
    fn topo_attestation(
        attesting: &str,
        attested: &str,
        atype: &str,
        dimension: Option<&str>,
        scope: Option<&str>,
        evidence: &[&str],
        weight: Option<f64>,
        asserted_at: chrono::DateTime<chrono::Utc>,
    ) -> Attestation {
        let mut env = serde_json::Map::new();
        if let Some(d) = dimension {
            env.insert("dimension".into(), serde_json::Value::String(d.into()));
        }
        if let Some(sc) = scope {
            env.insert("scope".into(), serde_json::Value::String(sc.into()));
        }
        if !evidence.is_empty() {
            env.insert(
                "evidence_refs".into(),
                serde_json::Value::Array(
                    evidence
                        .iter()
                        .map(|e| serde_json::Value::String((*e).into()))
                        .collect(),
                ),
            );
        }
        // `scores` admission gate requires a versioned dimension —
        // the helper picks `identity_binding:v1` when no dimension is
        // provided for a scores row so tests don't have to spell it.
        if atype == crate::federation::types::attestation_type::SCORES && dimension.is_none() {
            env.insert(
                "dimension".into(),
                serde_json::Value::String("identity_binding:v1".into()),
            );
            env.insert(
                "score".into(),
                serde_json::Value::Number(serde_json::Number::from_f64(1.0).unwrap()),
            );
            env.insert(
                "confidence".into(),
                serde_json::Value::Number(serde_json::Number::from_f64(0.9).unwrap()),
            );
        }
        Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: attesting.into(),
            attested_key_id: attested.into(),
            attestation_type: atype.into(),
            weight,
            asserted_at,
            expires_at: None,
            attestation_envelope: serde_json::Value::Object(env),
            original_content_hash: "abc123".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: attesting.into(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
        }
    }

    /// #104 — federation_directory_query returns a non-empty
    /// TrustTopology with direct edges when only `scores` rows exist.
    #[tokio::test]
    async fn federation_directory_query_topology_direct_sqlite() {
        use crate::federation::types::attestation_type;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // Three keys: granter, grantee, third.
        for (k, ident) in [
            ("topo-granter", "agent-a"),
            ("topo-grantee", "agent-b"),
            ("topo-third", "agent-c"),
        ] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fed_key(k, ident, k),
                })
                .await
                .unwrap();
        }
        let when = chrono::Utc::now();
        backend
            .put_attestation(SignedAttestation {
                attestation: topo_attestation(
                    "topo-granter",
                    "topo-grantee",
                    attestation_type::SCORES,
                    Some("identity_binding:v1"),
                    None,
                    &[],
                    Some(2.5),
                    when,
                ),
            })
            .await
            .unwrap();

        let topo = crate::federation::build_trust_topology(
            &backend,
            &crate::federation::FederationDirectoryFilter {
                granter_key: Some("topo-granter".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(topo.edges.len(), 1, "exactly one direct edge");
        let e = &topo.edges[0];
        assert_eq!(e.edge_type, crate::federation::EdgeType::Direct);
        assert_eq!(e.from_key, "topo-grantee");
        assert_eq!(e.to_key, "topo-granter");
        assert_eq!(e.purpose, "identity_binding:v1");
        assert!((e.weight - 2.5).abs() < 1e-9);
        assert!(e.revoked_at.is_none());
        assert_eq!(topo.nodes.len(), 2);
        let kinds: Vec<&str> = topo.nodes.iter().map(|n| n.key_id.as_str()).collect();
        assert!(kinds.contains(&"topo-granter"));
        assert!(kinds.contains(&"topo-grantee"));
    }

    /// #104 — adversarial edges (a withdraws/recants row by the
    /// granter against the grantee) are filtered out by default but
    /// surface when `include_revoked=true`.
    #[tokio::test]
    async fn federation_directory_query_adversarial_include_revoked_sqlite() {
        use crate::federation::types::attestation_type;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        for (k, ident) in [("adv-granter", "agent-a"), ("adv-grantee", "agent-b")] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fed_key(k, ident, k),
                })
                .await
                .unwrap();
        }
        let when = chrono::Utc::now();
        backend
            .put_attestation(SignedAttestation {
                attestation: topo_attestation(
                    "adv-granter",
                    "adv-grantee",
                    attestation_type::SCORES,
                    Some("identity_binding:v1"),
                    None,
                    &[],
                    Some(1.0),
                    when,
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: topo_attestation(
                    "adv-granter",
                    "adv-grantee",
                    attestation_type::WITHDRAWS,
                    None,
                    None,
                    &[],
                    None,
                    when + chrono::Duration::seconds(1),
                ),
            })
            .await
            .unwrap();

        // Default filter: revoked edges are dropped.
        let topo = crate::federation::build_trust_topology(
            &backend,
            &crate::federation::FederationDirectoryFilter {
                granter_key: Some("adv-granter".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(topo.edges.is_empty(), "revoked edge filtered by default");

        // With include_revoked=true the adversarial edge is surfaced.
        let topo = crate::federation::build_trust_topology(
            &backend,
            &crate::federation::FederationDirectoryFilter {
                granter_key: Some("adv-granter".into()),
                include_revoked: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(topo.edges.len(), 1);
        assert_eq!(
            topo.edges[0].edge_type,
            crate::federation::EdgeType::Adversarial
        );
        assert!(
            topo.edges[0].revoked_at.is_some(),
            "adversarial edge carries revoked_at"
        );
    }

    /// #104 — empty-result test: no attestations matching the filter
    /// → empty edges + empty nodes, no error.
    #[tokio::test]
    async fn federation_directory_query_empty_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let topo = crate::federation::build_trust_topology(
            &backend,
            &crate::federation::FederationDirectoryFilter {
                granter_key: Some("nonexistent-key".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(topo.edges.is_empty());
        assert!(topo.nodes.is_empty());
    }

    /// #104 — filter with neither granter nor grantee set is
    /// InvalidArgument.
    #[tokio::test]
    async fn federation_directory_query_requires_filter_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let err = crate::federation::build_trust_topology(
            &backend,
            &crate::federation::FederationDirectoryFilter::default(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, crate::federation::Error::InvalidArgument(_)));
    }

    /// #104 — delegates_to_graph BFS walks one level + carries
    /// scope + evidence_refs from the envelope.
    #[tokio::test]
    async fn delegates_to_graph_one_level_sqlite() {
        use crate::federation::types::attestation_type;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        for (k, ident) in [("del-root", "agent-a"), ("del-child", "agent-b")] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fed_key(k, ident, k),
                })
                .await
                .unwrap();
        }
        let when = chrono::Utc::now();
        backend
            .put_attestation(SignedAttestation {
                attestation: topo_attestation(
                    "del-root",
                    "del-child",
                    attestation_type::DELEGATES_TO,
                    None,
                    Some("manifest:bundle-x"),
                    &["sha256:abcd1234", "https://example.test/ev/1"],
                    None,
                    when,
                ),
            })
            .await
            .unwrap();
        let graph = crate::federation::build_delegation_graph(&backend, "del-root", 4)
            .await
            .unwrap();
        assert_eq!(graph.root_key, "del-root");
        assert_eq!(graph.edges.len(), 1);
        let e = &graph.edges[0];
        assert_eq!(e.from_key, "del-root");
        assert_eq!(e.to_key, "del-child");
        assert_eq!(e.scope, "manifest:bundle-x");
        assert_eq!(e.depth, 1);
        assert_eq!(e.evidence_refs.len(), 2);
        assert!(e.withdrawn_by.is_none());
    }

    /// #104 — delegates_to_graph BFS respects cycles + depth bound.
    #[tokio::test]
    async fn delegates_to_graph_cycles_and_depth_sqlite() {
        use crate::federation::types::attestation_type;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // Cycle: a → b → a
        for (k, ident) in [("cyc-a", "agent-a"), ("cyc-b", "agent-b")] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fed_key(k, ident, k),
                })
                .await
                .unwrap();
        }
        let when = chrono::Utc::now();
        backend
            .put_attestation(SignedAttestation {
                attestation: topo_attestation(
                    "cyc-a",
                    "cyc-b",
                    attestation_type::DELEGATES_TO,
                    None,
                    Some("*"),
                    &[],
                    None,
                    when,
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: topo_attestation(
                    "cyc-b",
                    "cyc-a",
                    attestation_type::DELEGATES_TO,
                    None,
                    Some("*"),
                    &[],
                    None,
                    when,
                ),
            })
            .await
            .unwrap();
        let graph = crate::federation::build_delegation_graph(&backend, "cyc-a", 8)
            .await
            .unwrap();
        // Both edges discovered; the cycle does NOT cause a second
        // visit (visited set keeps each granter from being expanded twice).
        assert_eq!(graph.edges.len(), 2);
        // Each granter expanded exactly once.
        let from_a: usize = graph.edges.iter().filter(|e| e.from_key == "cyc-a").count();
        let from_b: usize = graph.edges.iter().filter(|e| e.from_key == "cyc-b").count();
        assert_eq!(from_a, 1);
        assert_eq!(from_b, 1);
    }

    /// #104 — delegates_to_graph annotates an edge with `withdrawn_by`
    /// when the granter has issued a retraction.
    #[tokio::test]
    async fn delegates_to_graph_withdraws_annotation_sqlite() {
        use crate::federation::types::attestation_type;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        for (k, ident) in [("w-root", "agent-a"), ("w-child", "agent-b")] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: fed_key(k, ident, k),
                })
                .await
                .unwrap();
        }
        let when = chrono::Utc::now();
        backend
            .put_attestation(SignedAttestation {
                attestation: topo_attestation(
                    "w-root",
                    "w-child",
                    attestation_type::DELEGATES_TO,
                    None,
                    Some("*"),
                    &[],
                    None,
                    when,
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(SignedAttestation {
                attestation: topo_attestation(
                    "w-root",
                    "w-child",
                    attestation_type::RECANTS,
                    None,
                    None,
                    &[],
                    None,
                    when + chrono::Duration::seconds(2),
                ),
            })
            .await
            .unwrap();
        let graph = crate::federation::build_delegation_graph(&backend, "w-root", 4)
            .await
            .unwrap();
        assert_eq!(graph.edges.len(), 1);
        let entry = graph.edges[0].withdrawn_by.as_ref().expect("withdrawn_by");
        assert_eq!(entry.kind, attestation_type::RECANTS);
        assert_eq!(entry.key_id, "w-root");
    }

    /// #104 — empty delegates_to_graph when the root has no
    /// outbound delegations.
    #[tokio::test]
    async fn delegates_to_graph_empty_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("solo-key", "agent-a", "solo-key"),
            })
            .await
            .unwrap();
        let graph = crate::federation::build_delegation_graph(&backend, "solo-key", 4)
            .await
            .unwrap();
        assert!(graph.edges.is_empty());
        assert_eq!(graph.root_key, "solo-key");
    }

    // ── v2.10.0 (CIRISPersist#114) — typed Goal primitive tests ────

    fn fixture_goal(
        backend_key: &str,
        scope: crate::federation::GoalScope,
        dimension: crate::federation::M1Dimension,
        declared_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::federation::Goal {
        crate::federation::Goal::new(
            uuid::Uuid::new_v4(),
            backend_key.into(),
            declared_at,
            format!("goal text for {backend_key}"),
            scope,
            crate::federation::MetaGoalAlignment::new(dimension, "rationale for goal".into(), None),
        )
    }

    /// v2.10.0 (#114) — put + get_goal round-trip is byte-exact.
    #[tokio::test]
    async fn put_get_goal_round_trip_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("declarer-k1", "agent-a", "declarer-k1"),
            })
            .await
            .unwrap();
        let when = "2026-05-28T12:00:00Z".parse().unwrap();
        let goal = fixture_goal(
            "declarer-k1",
            crate::federation::GoalScope::SingleDeclarer,
            crate::federation::M1Dimension::Plurality,
            when,
        );
        backend.put_goal(goal.clone()).await.unwrap();
        let fetched = backend.get_goal(goal.goal_id).await.unwrap();
        assert_eq!(fetched, Some(goal));
    }

    /// v2.10.0 (#114) — list_goals filter combinations preserve
    /// stable lex order by (declared_at, goal_id).
    #[tokio::test]
    async fn list_goals_filters_and_order_sqlite() {
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
                record: fed_key("k-b", "agent-b", "k-b"),
            })
            .await
            .unwrap();
        let t0: chrono::DateTime<chrono::Utc> = "2026-05-28T12:00:00Z".parse().unwrap();
        let t1: chrono::DateTime<chrono::Utc> = "2026-05-28T13:00:00Z".parse().unwrap();
        let g_a_plurality = fixture_goal(
            "k-a",
            crate::federation::GoalScope::SingleDeclarer,
            crate::federation::M1Dimension::Plurality,
            t0,
        );
        let g_a_justice = fixture_goal(
            "k-a",
            crate::federation::GoalScope::Cohort {
                cohort_id: "stewards".into(),
            },
            crate::federation::M1Dimension::Justice,
            t1,
        );
        let g_b_plurality = fixture_goal(
            "k-b",
            crate::federation::GoalScope::Federation,
            crate::federation::M1Dimension::Plurality,
            t0,
        );
        for g in [
            g_a_plurality.clone(),
            g_a_justice.clone(),
            g_b_plurality.clone(),
        ] {
            backend.put_goal(g).await.unwrap();
        }
        // Filter by key — only k-a's two.
        let by_key = backend
            .list_goals(crate::federation::GoalsFilter {
                declared_by_key_id: Some("k-a".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_key.len(), 2);
        assert!(by_key.iter().all(|g| g.declared_by_key_id == "k-a"));
        // Stable order by declared_at, goal_id.
        assert!(by_key[0].declared_at <= by_key[1].declared_at);
        // Filter by dimension — Plurality across all declarers.
        let by_dim = backend
            .list_goals(crate::federation::GoalsFilter {
                m1_dimension: Some(crate::federation::M1Dimension::Plurality),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_dim.len(), 2);
        // Filter by scope_kind cohort + cohort_id.
        let by_cohort = backend
            .list_goals(crate::federation::GoalsFilter {
                scope_kind: Some("cohort".into()),
                cohort_id: Some("stewards".into()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_cohort.len(), 1);
        assert_eq!(by_cohort[0].goal_id, g_a_justice.goal_id);
    }

    /// v2.10.0 (#114) — all 7 M1Dimension variants round-trip.
    #[tokio::test]
    async fn all_m1_dimension_variants_round_trip_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-all", "agent-all", "k-all"),
            })
            .await
            .unwrap();
        let when: chrono::DateTime<chrono::Utc> = "2026-05-28T12:00:00Z".parse().unwrap();
        let all = [
            crate::federation::M1Dimension::Sustainability,
            crate::federation::M1Dimension::Adaptivity,
            crate::federation::M1Dimension::Coherence,
            crate::federation::M1Dimension::Plurality,
            crate::federation::M1Dimension::Flourishing,
            crate::federation::M1Dimension::Justice,
            crate::federation::M1Dimension::Wonder,
        ];
        let mut ids = Vec::new();
        for (i, dim) in all.iter().enumerate() {
            let g = fixture_goal(
                "k-all",
                crate::federation::GoalScope::SingleDeclarer,
                *dim,
                when + chrono::Duration::seconds(i as i64),
            );
            ids.push((g.goal_id, *dim));
            backend.put_goal(g).await.unwrap();
        }
        for (id, expected) in ids {
            let got = backend.get_goal(id).await.unwrap().expect("present");
            assert_eq!(got.meta_goal_alignment.dimension, expected);
        }
    }

    /// v2.10.0 (#114) — Cohort scope round-trips; schema CHECK
    /// rejects direct-SQL bypass (scope_kind = 'cohort' with
    /// scope_cohort_id NULL).
    #[tokio::test]
    async fn cohort_scope_round_trip_and_check_rejects_bypass_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-c", "agent-c", "k-c"),
            })
            .await
            .unwrap();
        let when: chrono::DateTime<chrono::Utc> = "2026-05-28T12:00:00Z".parse().unwrap();
        let g = fixture_goal(
            "k-c",
            crate::federation::GoalScope::Cohort {
                cohort_id: "cohort-1".into(),
            },
            crate::federation::M1Dimension::Plurality,
            when,
        );
        backend.put_goal(g.clone()).await.unwrap();
        let got = backend.get_goal(g.goal_id).await.unwrap().expect("present");
        assert_eq!(got.scope.cohort_id(), Some("cohort-1"));

        // Direct-SQL bypass attempt: scope_kind='cohort' without
        // scope_cohort_id must hit the CHECK constraint.
        let conn = backend.conn.clone();
        let bypass_id = uuid::Uuid::new_v4().to_string();
        let res = tokio::task::spawn_blocking(move || -> Result<usize, rusqlite::Error> {
            let conn = conn.blocking_lock();
            conn.execute(
                "INSERT INTO goals (\
                    goal_id, declared_by_key_id, declared_at, goal_text, \
                    goal_text_canonical, scope_kind, scope_cohort_id, \
                    meta_dimension, meta_rationale, meta_deliberation, \
                    retired_at, persist_row_hash\
                 ) VALUES (?1, 'k-c', '2026-05-28T12:00:00Z', 'x', 'x', \
                          'cohort', NULL, 'plurality', 'r', NULL, NULL, 'h')",
                [bypass_id],
            )
        })
        .await
        .unwrap();
        assert!(
            res.is_err(),
            "schema CHECK must reject scope_kind='cohort' with NULL scope_cohort_id"
        );
    }

    /// v2.10.0 (#114) — retire_goal sets retired_at; list_goals
    /// with include_retired=false hides it; include_retired=true
    /// includes it. Idempotent on second call.
    #[tokio::test]
    async fn retire_goal_hides_from_default_list_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("k-r", "agent-r", "k-r"),
            })
            .await
            .unwrap();
        let when: chrono::DateTime<chrono::Utc> = "2026-05-28T12:00:00Z".parse().unwrap();
        let g = fixture_goal(
            "k-r",
            crate::federation::GoalScope::SingleDeclarer,
            crate::federation::M1Dimension::Wonder,
            when,
        );
        backend.put_goal(g.clone()).await.unwrap();

        let retired_at = when + chrono::Duration::hours(1);
        backend.retire_goal(g.goal_id, retired_at).await.unwrap();

        // Default (include_retired=false) hides it.
        let live = backend
            .list_goals(crate::federation::GoalsFilter::default())
            .await
            .unwrap();
        assert!(live.iter().all(|x| x.goal_id != g.goal_id));

        // include_retired=true includes it.
        let all = backend
            .list_goals(crate::federation::GoalsFilter {
                include_retired: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let found = all.iter().find(|x| x.goal_id == g.goal_id).expect("found");
        assert!(found.retired_at.is_some());

        // Idempotent: second retire is a no-op and does not change
        // retired_at.
        let original_retired_at = found.retired_at.unwrap();
        backend
            .retire_goal(g.goal_id, retired_at + chrono::Duration::hours(1))
            .await
            .unwrap();
        let again = backend.get_goal(g.goal_id).await.unwrap().expect("present");
        assert_eq!(
            again.retired_at,
            Some(original_retired_at),
            "second retire must not change retired_at"
        );
    }

    /// v2.10.0 (#114) — put_goal with unknown declared_by_key_id
    /// rejects on the FK constraint.
    #[tokio::test]
    async fn put_goal_rejects_unknown_declarer_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let when: chrono::DateTime<chrono::Utc> = "2026-05-28T12:00:00Z".parse().unwrap();
        let g = fixture_goal(
            "ghost-key",
            crate::federation::GoalScope::SingleDeclarer,
            crate::federation::M1Dimension::Coherence,
            when,
        );
        let err = backend.put_goal(g).await.expect_err("FK must reject");
        assert!(matches!(err, crate::federation::Error::InvalidArgument(_)));
    }

    /// v2.10.0 (#114) — retire_goal against an unknown goal_id is
    /// InvalidArgument (not a silent no-op).
    #[tokio::test]
    async fn retire_goal_unknown_id_rejects_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let when = chrono::Utc::now();
        let err = backend
            .retire_goal(uuid::Uuid::new_v4(), when)
            .await
            .expect_err("missing goal_id must reject");
        assert!(matches!(err, crate::federation::Error::InvalidArgument(_)));
    }

    // ── v3.1.0 (CIRISPersist#117) — peer-mutation surface ──────────

    /// Read-helper for tests — peek at `federation_peer_metadata`.
    async fn peek_peer_sqlite(
        backend: &SqliteBackend,
        key_id: &str,
    ) -> Option<(
        Option<String>,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    )> {
        let key_id = key_id.to_owned();
        let conn = backend.conn.clone();
        tokio::task::spawn_blocking(move || -> Option<_> {
            let conn = conn.blocking_lock();
            conn.query_row(
                "SELECT alias, trust, notes, policy_blob, transport_identity, removed_at \
                 FROM federation_peer_metadata WHERE key_id = ?1",
                [&key_id],
                |r| {
                    Ok((
                        r.get::<_, Option<String>>(0)?,
                        r.get::<_, String>(1)?,
                        r.get::<_, Option<String>>(2)?,
                        r.get::<_, Option<String>>(3)?,
                        r.get::<_, Option<String>>(4)?,
                        r.get::<_, Option<String>>(5)?,
                    ))
                },
            )
            .optional()
            .ok()
            .flatten()
        })
        .await
        .ok()
        .flatten()
    }

    async fn peek_key_exists_sqlite(backend: &SqliteBackend, key_id: &str) -> bool {
        let key_id = key_id.to_owned();
        let conn = backend.conn.clone();
        tokio::task::spawn_blocking(move || -> bool {
            let conn = conn.blocking_lock();
            conn.query_row(
                "SELECT 1 FROM federation_keys WHERE key_id = ?1",
                [&key_id],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .is_some()
        })
        .await
        .unwrap_or(false)
    }

    #[tokio::test]
    async fn add_peer_record_creates_both_rows_atomically_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("peer-a", "AAAA", "agent", Some("rns://abc".into()))
            .await
            .unwrap();
        assert!(peek_key_exists_sqlite(&backend, "peer-a").await);
        let meta = peek_peer_sqlite(&backend, "peer-a").await.expect("row");
        assert_eq!(meta.1, "untrusted");
        assert_eq!(meta.4.as_deref(), Some("rns://abc"));
        assert!(meta.5.is_none(), "removed_at NULL");
    }

    #[tokio::test]
    async fn add_peer_record_duplicate_key_id_rejects_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("peer-dup", "AAAA", "agent", None)
            .await
            .unwrap();
        let err = backend
            .add_peer_record("peer-dup", "BBBB", "agent", None)
            .await
            .expect_err("must reject pubkey conflict");
        assert!(matches!(err, crate::federation::Error::Conflict(_)));
    }

    #[tokio::test]
    async fn remove_peer_record_soft_marks_removed_at_and_hides_from_reads_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("peer-soft", "AAAA", "agent", None)
            .await
            .unwrap();
        backend
            .remove_peer_record("peer-soft", false)
            .await
            .unwrap();
        let meta = peek_peer_sqlite(&backend, "peer-soft").await.expect("row");
        assert!(meta.5.is_some(), "removed_at set");
        // Updates against a soft-removed peer fail.
        let err = backend
            .update_peer_trust("peer-soft", crate::federation::TrustClass::Trusted)
            .await
            .expect_err("must reject");
        assert!(matches!(err, crate::federation::Error::PeerNotFound { .. }));
    }

    #[tokio::test]
    async fn remove_peer_record_hard_with_active_attestations_rejects_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("peer-att-a", "AAAA", "agent", None)
            .await
            .unwrap();
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key("peer-att-b", "peer-att-b", "peer-att-b"),
            })
            .await
            .unwrap();
        // Attestation: peer-att-a attests peer-att-b. Need to satisfy
        // the admission gate, so use the test fixture's known-good
        // dimension shape.
        let att = fed_attestation("a-1", "peer-att-a", "peer-att-b", "peer-att-a");
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
        let err = backend
            .remove_peer_record("peer-att-a", true)
            .await
            .expect_err("must reject orphaning");
        assert!(matches!(
            err,
            crate::federation::Error::HardRemoveWithActiveAttestations { .. }
        ));
    }

    #[tokio::test]
    async fn remove_peer_record_hard_with_no_attestations_cascades_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("peer-hard", "AAAA", "agent", None)
            .await
            .unwrap();
        backend.remove_peer_record("peer-hard", true).await.unwrap();
        assert!(!peek_key_exists_sqlite(&backend, "peer-hard").await);
        assert!(peek_peer_sqlite(&backend, "peer-hard").await.is_none());
    }

    #[tokio::test]
    async fn update_peer_alias_round_trip_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("peer-alias", "AAAA", "agent", None)
            .await
            .unwrap();
        backend
            .update_peer_alias("peer-alias", Some("home".into()))
            .await
            .unwrap();
        let meta = peek_peer_sqlite(&backend, "peer-alias").await.unwrap();
        assert_eq!(meta.0.as_deref(), Some("home"));
        backend.update_peer_alias("peer-alias", None).await.unwrap();
        let meta = peek_peer_sqlite(&backend, "peer-alias").await.unwrap();
        assert!(meta.0.is_none());
    }

    #[tokio::test]
    async fn update_peer_trust_round_trip_each_variant_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("peer-trust", "AAAA", "agent", None)
            .await
            .unwrap();
        for variant in [
            crate::federation::TrustClass::Trusted,
            crate::federation::TrustClass::Restricted,
            crate::federation::TrustClass::Blocked,
            crate::federation::TrustClass::Untrusted,
        ] {
            backend
                .update_peer_trust("peer-trust", variant)
                .await
                .unwrap();
            let meta = peek_peer_sqlite(&backend, "peer-trust").await.unwrap();
            assert_eq!(meta.1, variant.as_wire_str(), "variant {variant:?}");
        }
    }

    #[tokio::test]
    async fn update_peer_notes_round_trip_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("peer-notes", "AAAA", "agent", None)
            .await
            .unwrap();
        let meta = peek_peer_sqlite(&backend, "peer-notes").await.unwrap();
        assert!(meta.2.is_none());
        backend
            .update_peer_notes("peer-notes", Some("ops".into()))
            .await
            .unwrap();
        let meta = peek_peer_sqlite(&backend, "peer-notes").await.unwrap();
        assert_eq!(meta.2.as_deref(), Some("ops"));
        backend.update_peer_notes("peer-notes", None).await.unwrap();
        let meta = peek_peer_sqlite(&backend, "peer-notes").await.unwrap();
        assert!(meta.2.is_none());
    }

    #[tokio::test]
    async fn update_peer_policy_round_trip_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("peer-policy", "AAAA", "agent", None)
            .await
            .unwrap();
        let blob = crate::federation::PeerPolicyBlob(serde_json::json!({
            "rate": 60, "tags": ["x", "y"],
        }));
        backend
            .update_peer_policy("peer-policy", blob)
            .await
            .unwrap();
        let meta = peek_peer_sqlite(&backend, "peer-policy").await.unwrap();
        let decoded: serde_json::Value =
            serde_json::from_str(meta.3.as_deref().expect("policy_blob set")).unwrap();
        assert_eq!(decoded["rate"], serde_json::json!(60));
        assert_eq!(decoded["tags"], serde_json::json!(["x", "y"]));
    }

    // ── v3.4.1 (CIRISPersist#127) — peer_metadata_for read accessor ──

    #[tokio::test]
    async fn peer_metadata_for_returns_full_row_sqlite() {
        use crate::federation::FederationDirectory;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("peer-read", "AAAA", "agent", Some("rns://abc".into()))
            .await
            .unwrap();
        let blob = crate::federation::PeerPolicyBlob(serde_json::json!({
            "cohort_scope": "federation",
        }));
        backend.update_peer_policy("peer-read", blob).await.unwrap();
        let meta = backend
            .peer_metadata_for("peer-read")
            .await
            .unwrap()
            .expect("active peer must surface");
        assert_eq!(meta.key_id, "peer-read");
        assert!(meta.removed_at.is_none());
        assert_eq!(meta.transport_identity.as_deref(), Some("rns://abc"));
        let policy = meta.policy_blob.expect("policy_blob set");
        assert_eq!(
            policy.as_value()["cohort_scope"],
            serde_json::json!("federation")
        );
        assert!(!meta.persist_row_hash.is_empty());
    }

    #[tokio::test]
    async fn peer_metadata_for_returns_none_unknown_sqlite() {
        use crate::federation::FederationDirectory;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let got = backend.peer_metadata_for("ghost").await.unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    async fn peer_metadata_for_returns_none_soft_removed_sqlite() {
        use crate::federation::FederationDirectory;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("peer-gone", "AAAA", "agent", None)
            .await
            .unwrap();
        backend
            .remove_peer_record("peer-gone", false)
            .await
            .unwrap();
        let got = backend.peer_metadata_for("peer-gone").await.unwrap();
        assert!(got.is_none(), "soft-removed peer must read as None");
    }

    #[tokio::test]
    async fn update_peer_unknown_key_id_rejects_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let err = backend
            .update_peer_alias("ghost", None)
            .await
            .expect_err("must reject");
        assert!(matches!(err, crate::federation::Error::PeerNotFound { .. }));
    }

    // ── v3.1.1 (CIRISPersist#118) — put_edge_detection_event ──────

    fn ed_fixture_sqlite(
        detection_id: &uuid::Uuid,
        key_id: &str,
    ) -> crate::derived::EdgeDetectionEvent {
        crate::derived::EdgeDetectionEvent {
            detection_id: detection_id.to_string(),
            tenant_id: "test-tenant".into(),
            detector_kind: "unconsented_external_probe".into(),
            subject_key_id: key_id.into(),
            observed_at: chrono::Utc::now(),
            evidence: serde_json::json!({"probe_count": 7}),
            severity: "warn".into(),
            signature: "edge-sig-base64".into(),
            signing_key_id: key_id.into(),
            signature_verified: true,
            persist_row_hash: "row-hash-A".into(),
        }
    }

    #[tokio::test]
    async fn put_edge_detection_event_idempotent_sqlite() {
        use crate::derived::DerivedSchema;
        use crate::federation::FederationDirectory;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("edge-sub", "AAAA", "agent", None)
            .await
            .unwrap();
        let did = uuid::Uuid::new_v4();
        let ev = ed_fixture_sqlite(&did, "edge-sub");
        backend.put_edge_detection_event(ev.clone()).await.unwrap();
        backend.put_edge_detection_event(ev).await.unwrap();
    }

    #[tokio::test]
    async fn put_edge_detection_event_conflict_on_differing_row_hash_sqlite() {
        use crate::derived::DerivedSchema;
        use crate::federation::FederationDirectory;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("edge-sub-2", "AAAA", "agent", None)
            .await
            .unwrap();
        let did = uuid::Uuid::new_v4();
        let ev_a = ed_fixture_sqlite(&did, "edge-sub-2");
        let mut ev_b = ev_a.clone();
        ev_b.persist_row_hash = "row-hash-B-different".into();
        backend.put_edge_detection_event(ev_a).await.unwrap();
        let err = backend.put_edge_detection_event(ev_b).await.unwrap_err();
        assert!(
            matches!(err, crate::derived::Error::Conflict(_)),
            "expected Conflict; got: {err:?}"
        );
    }

    /// V051 CHECK constraint catches direct-SQL bypass — a value
    /// outside the closed-set vocabulary must fail at the DB layer.
    #[tokio::test]
    async fn peer_metadata_trust_check_rejects_direct_sql_bypass_sqlite() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend
            .add_peer_record("peer-check", "AAAA", "agent", None)
            .await
            .unwrap();
        let conn = backend.conn.clone();
        let res = tokio::task::spawn_blocking(move || {
            let conn = conn.blocking_lock();
            conn.execute(
                "UPDATE federation_peer_metadata SET trust = 'mystery' WHERE key_id = ?1",
                ["peer-check"],
            )
        })
        .await
        .unwrap();
        assert!(
            res.is_err(),
            "direct-SQL bypass of trust CHECK must fail; got Ok"
        );
    }

    // ── BlackholeRules tests (v3.2.0, CIRISPersist#120) ────────────

    fn id16(byte: u8) -> Vec<u8> {
        vec![byte; 16]
    }

    #[tokio::test]
    async fn blackhole_upsert_then_list_round_trip_sqlite() {
        use crate::federation::BlackholeRules;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = id16(0xAA);
        backend
            .blackhole_upsert(&id, None, Some("noisy"))
            .await
            .unwrap();
        let rows = backend.blackhole_list().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].identity_hash, id);
        assert!(rows[0].until.is_none());
        assert_eq!(rows[0].reason.as_deref(), Some("noisy"));
        assert_eq!(rows[0].hits, 0);
        assert!(!rows[0].persist_row_hash.is_empty());
    }

    #[tokio::test]
    async fn blackhole_upsert_with_until_round_trip_sqlite() {
        use crate::federation::BlackholeRules;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = id16(0xBB);
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        backend
            .blackhole_upsert(&id, Some(future), Some("temp"))
            .await
            .unwrap();
        let rows = backend.blackhole_list().await.unwrap();
        assert_eq!(rows.len(), 1);
        let stored = rows[0].until.expect("until set");
        // RFC3339 round-trip preserves seconds; allow sub-second drift.
        assert!(
            (stored.timestamp_millis() - future.timestamp_millis()).abs() < 1000,
            "stored {stored:?} != expected {future:?}"
        );
    }

    #[tokio::test]
    async fn blackhole_upsert_idempotent_preserves_hits_sqlite() {
        use crate::federation::BlackholeRules;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = id16(0xCC);
        backend
            .blackhole_upsert(&id, None, Some("first"))
            .await
            .unwrap();
        for _ in 0..3 {
            backend.blackhole_record_hit(&id).await.unwrap();
        }
        let before = backend.blackhole_list().await.unwrap();
        assert_eq!(before[0].hits, 3);
        let added_at_before = before[0].added_at;
        backend
            .blackhole_upsert(&id, None, Some("second"))
            .await
            .unwrap();
        let after = backend.blackhole_list().await.unwrap();
        assert_eq!(after[0].hits, 3);
        assert_eq!(after[0].reason.as_deref(), Some("second"));
        assert_eq!(
            after[0].added_at.timestamp_millis(),
            added_at_before.timestamp_millis()
        );
    }

    #[tokio::test]
    async fn blackhole_upsert_invalid_hash_length_rejects_sqlite() {
        use crate::federation::BlackholeRules;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        for bad in [vec![], vec![1u8; 8], vec![1u8; 15], vec![1u8; 17]] {
            let err = backend
                .blackhole_upsert(&bad, None, None)
                .await
                .expect_err("non-16 must reject");
            assert!(
                matches!(err, crate::federation::Error::InvalidArgument(_)),
                "got {err:?} for len {}",
                bad.len()
            );
        }
    }

    #[tokio::test]
    async fn blackhole_remove_unknown_silent_ok_sqlite() {
        use crate::federation::BlackholeRules;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend.blackhole_remove(&id16(0xEE)).await.unwrap();
        assert!(backend.blackhole_list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn blackhole_remove_idempotent_sqlite() {
        use crate::federation::BlackholeRules;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = id16(0xFE);
        backend.blackhole_upsert(&id, None, None).await.unwrap();
        backend.blackhole_remove(&id).await.unwrap();
        backend.blackhole_remove(&id).await.unwrap();
        assert!(backend.blackhole_list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn blackhole_record_hit_increments_sqlite() {
        use crate::federation::BlackholeRules;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = id16(0x42);
        backend.blackhole_upsert(&id, None, None).await.unwrap();
        for _ in 0..5 {
            backend.blackhole_record_hit(&id).await.unwrap();
        }
        let rows = backend.blackhole_list().await.unwrap();
        assert_eq!(rows[0].hits, 5);
    }

    #[tokio::test]
    async fn blackhole_record_hit_unknown_silent_ok_sqlite() {
        use crate::federation::BlackholeRules;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        backend.blackhole_record_hit(&id16(0xAB)).await.unwrap();
        assert!(backend.blackhole_list().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn blackhole_prune_expired_drops_only_expired_sqlite() {
        use crate::federation::BlackholeRules;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let now = chrono::Utc::now();
        let expired = id16(0x11);
        let permanent = id16(0x22);
        backend
            .blackhole_upsert(&expired, Some(now - chrono::Duration::hours(1)), None)
            .await
            .unwrap();
        backend
            .blackhole_upsert(&permanent, None, None)
            .await
            .unwrap();
        let dropped = backend.blackhole_prune_expired(now).await.unwrap();
        assert_eq!(dropped, 1);
        let rows = backend.blackhole_list().await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].identity_hash, permanent);
    }

    #[tokio::test]
    async fn blackhole_prune_expired_with_no_expired_returns_zero_sqlite() {
        use crate::federation::BlackholeRules;
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let now = chrono::Utc::now();
        backend
            .blackhole_upsert(&id16(0x33), None, None)
            .await
            .unwrap();
        backend
            .blackhole_upsert(&id16(0x44), Some(now + chrono::Duration::hours(1)), None)
            .await
            .unwrap();
        let dropped = backend.blackhole_prune_expired(now).await.unwrap();
        assert_eq!(dropped, 0);
        assert_eq!(backend.blackhole_list().await.unwrap().len(), 2);
    }

    // ─── v3.4.0 (CIRISPersist#123) — replication substrate tests ───

    /// Trivial `TrustScoring` impl for tests: a hard-coded map.
    /// Mirrors the architect's plan §"Memory backend" minimal shim.
    struct FixedTrustScoring(std::collections::HashMap<String, f64>);

    #[async_trait::async_trait]
    impl crate::federation::TrustScoring for FixedTrustScoring {
        async fn trust_score(
            &self,
            key_id: &str,
            _recursion_depth: u8,
        ) -> Result<f64, crate::federation::TrustScoringError> {
            match self.0.get(key_id) {
                Some(s) => Ok(*s),
                None => Err(crate::federation::TrustScoringError::KeyNotFound(
                    key_id.into(),
                )),
            }
        }
    }

    fn gate_for(pairs: &[(&str, f64)], threshold: f64) -> crate::federation::AdmissionGate {
        let mut map = std::collections::HashMap::new();
        for (k, v) in pairs {
            map.insert((*k).to_owned(), *v);
        }
        crate::federation::AdmissionGate::new(
            std::sync::Arc::new(FixedTrustScoring(map)),
            threshold,
            0,
        )
    }

    /// Sweeper-batch test #1 — V053 columns exist and default sanely.
    #[tokio::test]
    async fn v053_columns_default_and_index_present() {
        let backend = blob_test_backend().await;
        let bytes = b"v053-defaults".to_vec();
        let sha = sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation("host-a", "host-a", &uuid::Uuid::new_v4().to_string()),
            )
            .await
            .unwrap();
        // Row exists; access_count == 0; last_accessed_at populated.
        let conn = backend.conn_handle();
        let sha_vec = sha.to_vec();
        let (last, count) =
            tokio::task::spawn_blocking(move || -> Result<(String, i64), rusqlite::Error> {
                let c = conn.blocking_lock();
                c.query_row(
                    "SELECT last_accessed_at, access_count \
                     FROM federation_blobs WHERE sha256 = ?1",
                    rusqlite::params![sha_vec],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)),
                )
            })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(count, 0);
        // last_accessed_at must NOT be the V053 sentinel.
        assert_ne!(last, "1970-01-01T00:00:00+00:00");
    }

    /// Access-tracking test — get_blob bumps access_count and
    /// last_accessed_at.
    #[tokio::test]
    async fn get_blob_bumps_access_count() {
        let backend = blob_test_backend().await;
        let bytes = b"access-track".to_vec();
        let sha = sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes.clone()),
                None,
                blob_attestation("host-a", "host-a", &uuid::Uuid::new_v4().to_string()),
            )
            .await
            .unwrap();
        let _ = backend.get_blob(&sha).await.unwrap();
        let _ = backend.get_blob(&sha).await.unwrap();
        // has_blob also bumps the counter.
        assert!(backend.has_blob(&sha).await.unwrap());
        let conn = backend.conn_handle();
        let sha_vec = sha.to_vec();
        let count: i64 = tokio::task::spawn_blocking(move || -> Result<i64, rusqlite::Error> {
            let c = conn.blocking_lock();
            c.query_row(
                "SELECT access_count FROM federation_blobs WHERE sha256 = ?1",
                rusqlite::params![sha_vec],
                |r| r.get(0),
            )
        })
        .await
        .unwrap()
        .unwrap();
        // 2 get_blob hits + 1 has_blob = 3.
        assert_eq!(count, 3);
    }

    /// Admission ordering test — trust rejection beats inline-size
    /// rejection.
    #[tokio::test]
    async fn trust_rejection_short_circuits_inline_size_check() {
        let backend = blob_test_backend().await;
        backend.set_admission_gate(Some(gate_for(&[("host-a", 0.1)], 0.5)));
        let huge = vec![0u8; crate::federation::DEFAULT_INLINE_BYTES_CAP + 1];
        let sha = sha256_of(&huge);
        let err = backend
            .put_blob(
                &sha,
                BlobBody::Inline(huge),
                None,
                blob_attestation("host-a", "host-a", &uuid::Uuid::new_v4().to_string()),
            )
            .await
            .expect_err("must trust-reject before size-reject");
        match err {
            BlobError::TrustBelowThreshold {
                key_id,
                score,
                threshold,
            } => {
                assert_eq!(key_id, "host-a");
                assert!((score - 0.1).abs() < 1e-9);
                assert!((threshold - 0.5).abs() < 1e-9);
            }
            other => panic!("expected TrustBelowThreshold, got {other:?}"),
        }
    }

    /// Admission ordering test — empty-key still beats trust check.
    #[tokio::test]
    async fn empty_key_id_beats_trust_check() {
        let backend = blob_test_backend().await;
        backend.set_admission_gate(Some(gate_for(&[], 0.5)));
        let sha = sha256_of(b"x");
        let err = backend
            .put_blob(
                &sha,
                BlobBody::Inline(b"x".to_vec()),
                None,
                blob_attestation("", "host-a", &uuid::Uuid::new_v4().to_string()),
            )
            .await
            .expect_err("empty key beats trust");
        assert!(matches!(err, BlobError::InvalidArgument(_)));
    }

    /// Admission-gate test — gate above threshold admits write.
    #[tokio::test]
    async fn trust_admit_when_score_meets_threshold() {
        let backend = blob_test_backend().await;
        backend.set_admission_gate(Some(gate_for(&[("host-a", 0.9)], 0.5)));
        let bytes = b"admit-me".to_vec();
        let sha = sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                blob_attestation("host-a", "host-a", &uuid::Uuid::new_v4().to_string()),
            )
            .await
            .expect("trust admits");
    }

    /// Attestation write-path also honors the gate.
    #[tokio::test]
    async fn put_attestation_honors_trust_gate() {
        let backend = blob_test_backend().await;
        backend.set_admission_gate(Some(gate_for(&[("host-a", 0.1)], 0.5)));
        let att =
            signed_attestation_fixture("host-a", "host-a", "host-a", "attestation:self_verify");
        let err = backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .expect_err("trust-reject");
        assert!(
            matches!(err, crate::federation::Error::TrustBelowThreshold { .. }),
            "got: {err:?}"
        );
    }

    fn signed_attestation_fixture(
        attesting_key_id: &str,
        attested_key_id: &str,
        scrub_key_id: &str,
        attestation_type: &str,
    ) -> crate::federation::Attestation {
        crate::federation::Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: attesting_key_id.into(),
            attested_key_id: attested_key_id.into(),
            attestation_type: attestation_type.into(),
            weight: Some(1.0),
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: serde_json::json!({}),
            original_content_hash: "abcdef01".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
        }
    }

    // ── v3.6.0 (CIRISPersist#134, CEG 0.3 §11.5.3) — trusted-publisher chain ──

    /// CEG 0.3 §11.5.3: `lookup_trusted_publisher_chain` returns an
    /// empty vector when no `trusted_publisher`-type key has emitted a
    /// `content_rating:*` attestation referencing the SHA.
    #[tokio::test]
    async fn lookup_trusted_publisher_chain_returns_empty_for_unblessed_content() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let sha_hex = "a".repeat(64);
        let chain = backend
            .lookup_trusted_publisher_chain(&sha_hex)
            .await
            .unwrap();
        assert!(chain.is_empty(), "no publishers seeded → empty chain");
    }

    /// CEG 0.3 §11.5.3: seed a `trusted_publisher`-type key + a
    /// `content_rating:*` attestation referencing the SHA; the chain
    /// includes the attestation.
    #[tokio::test]
    async fn lookup_trusted_publisher_chain_returns_chain_when_trusted_publisher_attests() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let publisher_key = "pub-1";
        let sha_hex = "b".repeat(64);
        let other_sha = "c".repeat(64);
        // Seed the publisher key as trusted_publisher identity_type.
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key_with_identity_type(
                    publisher_key,
                    publisher_key,
                    publisher_key,
                    crate::federation::types::identity_type::TRUSTED_PUBLISHER,
                ),
            })
            .await
            .unwrap();
        // Seed a content_rating attestation referencing the target SHA.
        let mut hit = fed_attestation("att-hit", publisher_key, publisher_key, publisher_key);
        hit.attestation_envelope = serde_json::json!({
            "dimension": "content_rating:mpa:pg13:v1",
            "score": 1.0,
            "confidence": 0.9,
            "evidence_refs": [sha_hex],
        });
        backend
            .put_attestation(SignedAttestation { attestation: hit })
            .await
            .unwrap();
        // Seed a different content_rating referencing a different SHA —
        // must NOT appear in the result.
        let mut miss = fed_attestation("att-miss", publisher_key, publisher_key, publisher_key);
        miss.attestation_envelope = serde_json::json!({
            "dimension": "content_rating:mpa:r:v1",
            "score": 1.0,
            "confidence": 0.9,
            "evidence_refs": [other_sha],
        });
        backend
            .put_attestation(SignedAttestation { attestation: miss })
            .await
            .unwrap();

        let chain = backend
            .lookup_trusted_publisher_chain(&sha_hex)
            .await
            .unwrap();
        assert_eq!(chain.len(), 1, "exactly one matching attestation");
        assert_eq!(chain[0].attestation_id, "att-hit");
        assert_eq!(chain[0].attesting_key_id, publisher_key);
        let dim = chain[0]
            .attestation_envelope
            .get("dimension")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(dim.starts_with("content_rating:"));
    }

    /// CEG 0.3 §11.5.3: non-`trusted_publisher` identities cannot
    /// emit `content_rating:*` attestations (the reserved-prefix
    /// admission gate would reject them on put_attestation). The chain
    /// accessor reads through `trusted_publisher` keys only, so a
    /// rogue agent's bypass attempt would still not surface here.
    #[tokio::test]
    async fn lookup_trusted_publisher_chain_ignores_non_publisher_emitters() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        // Seed a steward (not trusted_publisher).
        let steward_key = "steward-1";
        backend
            .put_public_key(SignedKeyRecord {
                record: fed_key_with_identity_type(
                    steward_key,
                    steward_key,
                    steward_key,
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        // Steward's attestation under content_rating:* would be
        // rejected by the admission gate in production. For this
        // test, we bypass put_attestation's emitter check via a non-
        // content_rating dimension so the row lands, then assert the
        // accessor still returns empty (steward isn't a publisher).
        let sha_hex = "d".repeat(64);
        let mut att = fed_attestation("att-steward", steward_key, steward_key, steward_key);
        att.attestation_envelope = serde_json::json!({
            "dimension": "identity_binding:v1",
            "score": 1.0,
            "confidence": 0.9,
            "evidence_refs": [sha_hex],
        });
        backend
            .put_attestation(SignedAttestation { attestation: att })
            .await
            .unwrap();
        let chain = backend
            .lookup_trusted_publisher_chain(&sha_hex)
            .await
            .unwrap();
        assert!(chain.is_empty(), "steward isn't a trusted_publisher");
    }
}
