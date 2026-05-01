//! Postgres backend (Phase 1 default for the lens).
//!
//! # Mission alignment (MISSION.md §2 — `store/`)
//!
//! Same Backend trait surface as the in-memory and (Phase 2) SQLite
//! backends. Postgres-specific bits — TimescaleDB hypertables,
//! `ON CONFLICT DO NOTHING` on the dedup index, `BIGSERIAL` returns
//! the inserted PK for parent-FK linkage — live behind the trait, not
//! through it.
//!
//! Implementation notes:
//!
//! - **Pool**: `deadpool-postgres`. The lens runs the ingest server on
//!   a multi-threaded tokio runtime; pooled connections per FSD §3.4
//!   robustness primitive #1 (single persister consumer of the bounded
//!   queue, but the queue may dispatch across multiple connection
//!   handles for batch parallelism within one consumer).
//! - **Migrations**: `refinery` against the `migrations/postgres/lens/`
//!   directory.
//! - **Batch insert**: Phase 1 uses parameterized `INSERT ... VALUES
//!   (...), (...), ... ON CONFLICT DO NOTHING`. The FSD §3.3 step 5
//!   names `COPY ... FROM STDIN BINARY` as the long-term shape; for
//!   the agent's default `batch_size=10` (TRACE_WIRE_FORMAT.md §1)
//!   the `INSERT VALUES` path is faster *and* supports `ON CONFLICT`
//!   natively. Pattern (2) — copy-to-temp-then-insert — is the
//!   optimization we'll switch to when batches routinely exceed ~100
//!   rows.
//! - **Idempotency**: the `trace_events_dedup` UNIQUE index in
//!   `V001__trace_events.sql` is the conflict target for
//!   `ON CONFLICT (trace_id, thought_id, event_type, attempt_index, ts)
//!   DO NOTHING` (mission category §4 "Idempotency").

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use deadpool_postgres::{Config, ManagerConfig, Pool, RecyclingMethod, Runtime};
use ed25519_dalek::VerifyingKey;
use postgres_types::ToSql;
#[cfg(not(feature = "tls"))]
use tokio_postgres::NoTls;

use super::backend::{Backend, InsertReport};
use super::types::{TraceEventRow, TraceLlmCallRow};
use super::Error;
use crate::schema::ReasoningEventType;

mod embedded {
    refinery::embed_migrations!("migrations/postgres/lens");
}

/// Postgres-backed [`Backend`] impl.
pub struct PostgresBackend {
    pool: Pool,
}

impl PostgresBackend {
    /// Connect via libpq-style connection string and return a backend
    /// with a configured connection pool.
    ///
    /// `dsn` examples:
    /// - `postgres://user:pass@host:5432/dbname`
    /// - `host=db user=lens password=… dbname=cirislens`
    pub async fn connect(dsn: &str) -> Result<Self, Error> {
        let pg_config: tokio_postgres::Config = dsn
            .parse()
            .map_err(|e: tokio_postgres::Error| Error::Backend(format!("dsn parse: {e}")))?;

        let mgr_config = ManagerConfig {
            recycling_method: RecyclingMethod::Fast,
        };
        let mut cfg = Config::new();
        cfg.host = pg_config.get_hosts().first().map(|h| match h {
            tokio_postgres::config::Host::Tcp(s) => s.clone(),
            tokio_postgres::config::Host::Unix(p) => p.to_string_lossy().into_owned(),
        });
        cfg.port = pg_config.get_ports().first().copied();
        cfg.user = pg_config.get_user().map(str::to_owned);
        cfg.password = pg_config
            .get_password()
            .map(|b| String::from_utf8_lossy(b).into_owned());
        cfg.dbname = pg_config.get_dbname().map(str::to_owned);
        cfg.manager = Some(mgr_config);

        // THREAT_MODEL.md AV-18: TLS for the Postgres connection
        // pool, gated on the `tls` feature. Sovereign-mode
        // deployments with remote DBs (Postgres-over-WAN) MUST
        // enable this; co-located DBs can leave it off.
        #[cfg(feature = "tls")]
        let pool = {
            use rustls::ClientConfig;
            use tokio_postgres_rustls::MakeRustlsConnect;
            let mut roots = rustls::RootCertStore::empty();
            // rustls-native-certs 0.8 returns CertificateResult with
            // .certs Vec and .errors Vec; non-fatal individual
            // failures don't kill the load.
            let cert_result = rustls_native_certs::load_native_certs();
            for cert in cert_result.certs {
                roots
                    .add(cert)
                    .map_err(|e| Error::Backend(format!("native-cert add: {e}")))?;
            }
            if !cert_result.errors.is_empty() {
                tracing::warn!(
                    errors = ?cert_result.errors,
                    "some native certs failed to load (non-fatal)"
                );
            }
            let tls_config = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let connector = MakeRustlsConnect::new(tls_config);
            cfg.create_pool(Some(Runtime::Tokio1), connector)
                .map_err(|e| Error::Backend(format!("pool create (tls): {e}")))?
        };
        #[cfg(not(feature = "tls"))]
        let pool = cfg
            .create_pool(Some(Runtime::Tokio1), NoTls)
            .map_err(|e| Error::Backend(format!("pool create: {e}")))?;

        Ok(Self { pool })
    }

    /// Construct from an already-built deadpool. For tests / advanced
    /// embeddings (e.g. lens binary that wants to share a pool with
    /// other queries).
    pub fn from_pool(pool: Pool) -> Self {
        Self { pool }
    }

    /// Borrow the underlying pool. Phase 2's `peer-replicate` channel
    /// uses this to share connections for `LISTEN`/`NOTIFY`.
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    async fn get_client(&self) -> Result<deadpool_postgres::Object, Error> {
        self.pool
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool get: {e}")))
    }
}

impl Backend for PostgresBackend {
    async fn insert_trace_events_batch(
        &self,
        rows: &[TraceEventRow],
    ) -> Result<InsertReport, Error> {
        if rows.is_empty() {
            return Ok(InsertReport::default());
        }

        let mut client = self.get_client().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin tx: {e}")))?;

        // Build one INSERT ... VALUES (...), (...), ...
        // ON CONFLICT (trace_id, thought_id, event_type, attempt_index, ts)
        // DO NOTHING
        // The conflict target matches the V001 UNIQUE index
        // `trace_events_dedup`.
        const COLS: &str = "trace_id, thought_id, task_id, step_point, event_type, \
                            attempt_index, ts, agent_name, agent_id_hash, cognitive_state, \
                            trace_level, payload, cost_llm_calls, cost_tokens, cost_usd, \
                            signature, signing_key_id, signature_verified, schema_version, \
                            pii_scrubbed, audit_sequence_number, audit_entry_hash, audit_signature, \
                            original_content_hash, scrub_signature, scrub_key_id, scrub_timestamp";
        const N_COLS: usize = 27;

        let mut sql = String::with_capacity(2048);
        sql.push_str("INSERT INTO cirislens.trace_events (");
        sql.push_str(COLS);
        sql.push_str(") VALUES ");

        let mut params: Vec<Box<dyn ToSql + Sync + Send>> = Vec::with_capacity(rows.len() * N_COLS);
        for (i, row) in rows.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            sql.push('(');
            for c in 0..N_COLS {
                if c > 0 {
                    sql.push(',');
                }
                let placeholder_idx = i * N_COLS + c + 1;
                sql.push('$');
                sql.push_str(&placeholder_idx.to_string());
            }
            sql.push(')');

            // Audit anchor extraction — only ACTION_RESULT rows.
            let (audit_seq, audit_hash, audit_sig): (Option<i64>, Option<String>, Option<String>) =
                if row.event_type == ReasoningEventType::ActionResult {
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

            params.push(Box::new(row.trace_id.clone()));
            params.push(Box::new(row.thought_id.clone()));
            params.push(Box::new(row.task_id.clone()));
            params.push(Box::new(row.step_point.clone()));
            params.push(Box::new(row.event_type.as_str().to_owned()));
            // THREAT_MODEL.md AV-17 (v0.1.3): bounded by
            // schema::MAX_ATTEMPT_INDEX at parse time, so this fits in i32.
            // `try_from` rejects out-of-range explicitly instead of
            // silently wrapping.
            params.push(Box::new(i32::try_from(row.attempt_index).map_err(
                |_| {
                    Error::Backend(format!(
                        "attempt_index {} exceeds i32::MAX (postgres INT)",
                        row.attempt_index
                    ))
                },
            )?));
            params.push(Box::new(row.ts));
            params.push(Box::new(row.agent_name.clone()));
            params.push(Box::new(row.agent_id_hash.clone()));
            params.push(Box::new(row.cognitive_state.clone()));
            params.push(Box::new(trace_level_str(row.trace_level).to_owned()));
            params.push(Box::new(serde_json::Value::Object(row.payload.clone())));
            params.push(Box::new(row.cost_llm_calls));
            params.push(Box::new(row.cost_tokens));
            params.push(Box::new(row.cost_usd));
            params.push(Box::new(row.signature.clone()));
            params.push(Box::new(row.signing_key_id.clone()));
            params.push(Box::new(row.signature_verified));
            params.push(Box::new(row.schema_version.clone()));
            params.push(Box::new(row.pii_scrubbed));
            params.push(Box::new(audit_seq));
            params.push(Box::new(audit_hash));
            params.push(Box::new(audit_sig));
            // v0.1.3 scrub envelope columns (V003).
            params.push(Box::new(row.original_content_hash.clone()));
            params.push(Box::new(row.scrub_signature.clone()));
            params.push(Box::new(row.scrub_key_id.clone()));
            params.push(Box::new(row.scrub_timestamp));
        }
        // THREAT_MODEL.md AV-9: dedup-key target now includes
        // agent_id_hash so a malicious agent reusing another agent's
        // trace_id/thought_id shape cannot DOS the victim's traces.
        // Matches the V001 trace_events_dedup UNIQUE index.
        sql.push_str(
            " ON CONFLICT (agent_id_hash, trace_id, thought_id, \
             event_type, attempt_index, ts) DO NOTHING",
        );

        let params_refs: Vec<&(dyn ToSql + Sync)> = params
            .iter()
            .map(|b| b.as_ref() as &(dyn ToSql + Sync))
            .collect();

        let inserted = tx
            .execute(sql.as_str(), &params_refs)
            .await
            .map_err(|e| Error::Backend(format!("insert trace_events: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| Error::Backend(format!("commit: {e}")))?;

        let inserted = inserted as usize;
        Ok(InsertReport {
            inserted,
            conflicted: rows.len().saturating_sub(inserted),
        })
    }

    async fn insert_trace_llm_calls_batch(&self, rows: &[TraceLlmCallRow]) -> Result<usize, Error> {
        if rows.is_empty() {
            return Ok(0);
        }
        let mut client = self.get_client().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin tx: {e}")))?;

        const COLS: &str = "trace_id, thought_id, task_id, parent_event_id, parent_event_type, \
                            parent_attempt_index, attempt_index, ts, duration_ms, handler_name, \
                            service_name, model, base_url, response_model, prompt_tokens, \
                            completion_tokens, prompt_bytes, completion_bytes, cost_usd, status, \
                            error_class, attempt_count, retry_count, prompt_hash, prompt, \
                            response_text";
        const N_COLS: usize = 26;

        let mut sql = String::with_capacity(2048);
        sql.push_str("INSERT INTO cirislens.trace_llm_calls (");
        sql.push_str(COLS);
        sql.push_str(") VALUES ");

        let mut params: Vec<Box<dyn ToSql + Sync + Send>> = Vec::with_capacity(rows.len() * N_COLS);
        for (i, r) in rows.iter().enumerate() {
            if i > 0 {
                sql.push(',');
            }
            sql.push('(');
            for c in 0..N_COLS {
                if c > 0 {
                    sql.push(',');
                }
                let placeholder_idx = i * N_COLS + c + 1;
                sql.push('$');
                sql.push_str(&placeholder_idx.to_string());
            }
            sql.push(')');

            params.push(Box::new(r.trace_id.clone()));
            params.push(Box::new(r.thought_id.clone()));
            params.push(Box::new(r.task_id.clone()));
            params.push(Box::new(r.parent_event_id));
            params.push(Box::new(r.parent_event_type.as_str().to_owned()));
            // THREAT_MODEL.md AV-17 (v0.1.3): same bound on parent_attempt_index.
            params.push(Box::new(i32::try_from(r.parent_attempt_index).map_err(
                |_| {
                    Error::Backend(format!(
                        "parent_attempt_index {} exceeds i32::MAX",
                        r.parent_attempt_index
                    ))
                },
            )?));
            // Same bound for the LLM_CALL row's own attempt_index.
            params.push(Box::new(i32::try_from(r.attempt_index).map_err(|_| {
                Error::Backend(format!(
                    "attempt_index {} exceeds i32::MAX",
                    r.attempt_index
                ))
            })?));
            params.push(Box::new(r.ts));
            params.push(Box::new(r.duration_ms));
            params.push(Box::new(r.handler_name.clone()));
            params.push(Box::new(r.service_name.clone()));
            params.push(Box::new(r.model.clone()));
            params.push(Box::new(r.base_url.clone()));
            params.push(Box::new(r.response_model.clone()));
            params.push(Box::new(r.prompt_tokens));
            params.push(Box::new(r.completion_tokens));
            params.push(Box::new(r.prompt_bytes));
            params.push(Box::new(r.completion_bytes));
            params.push(Box::new(r.cost_usd));
            params.push(Box::new(llm_status_str(r.status).to_owned()));
            params.push(Box::new(r.error_class.clone()));
            params.push(Box::new(r.attempt_count));
            params.push(Box::new(r.retry_count));
            params.push(Box::new(r.prompt_hash.clone()));
            params.push(Box::new(r.prompt.clone()));
            params.push(Box::new(r.response_text.clone()));
        }

        let params_refs: Vec<&(dyn ToSql + Sync)> = params
            .iter()
            .map(|b| b.as_ref() as &(dyn ToSql + Sync))
            .collect();

        let inserted = tx
            .execute(sql.as_str(), &params_refs)
            .await
            .map_err(|e| Error::Backend(format!("insert trace_llm_calls: {e}")))?;

        tx.commit()
            .await
            .map_err(|e| Error::Backend(format!("commit llm_calls: {e}")))?;

        Ok(inserted as usize)
    }

    async fn lookup_public_key(&self, key_id: &str) -> Result<Option<VerifyingKey>, Error> {
        // SQL maps the wire-level `signature_key_id` to the lens-
        // canonical `key_id` column (THREAT_MODEL.md AV-11; v0.1.2
        // Path B reconciliation). Public-key rows are filtered by
        // revocation: revoked_at IS NULL AND (expires_at IS NULL OR
        // expires_at > now()) — both gates the lens already had.
        let client = self.get_client().await?;
        let row_opt = client
            .query_opt(
                "SELECT public_key_base64 FROM cirislens.accord_public_keys \
                 WHERE key_id = $1 \
                   AND revoked_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > NOW())",
                &[&key_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("lookup_public_key: {e}")))?;
        let Some(row) = row_opt else {
            return Ok(None);
        };
        let b64: String = row.get(0);
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

    async fn run_migrations(&self) -> Result<(), Error> {
        let mut client = self.get_client().await?;
        // refinery wraps tokio-postgres directly; we hand off our
        // pooled client.
        embedded::migrations::runner()
            .set_migration_table_name("ciris_persist_schema_history")
            .run_async(&mut **client)
            .await
            .map_err(|e| Error::Backend(format!("migrations: {e}")))?;
        Ok(())
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

// ─── Integration tests, gated on a real Postgres ───────────────────
//
// Mission category §4 "Backend parity": the same row sequence that
// passes against `MemoryBackend` must produce the same observable
// results against Postgres. The conformance test harness lives in
// `tests/postgres_conformance.rs` (gated behind
// `CIRIS_PERSIST_TEST_PG_URL`).

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn pg_dsn() -> Option<String> {
        env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    /// Smoke: connect + run_migrations. Skipped if no test DB is
    /// configured.
    ///
    /// `serial_test::serial` forces postgres tests to run one at a
    /// time so concurrent migration races (`pg_type_typname_nsp_index`)
    /// don't surface as flake.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn migrations_run_clean() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.expect("connect");
        backend.run_migrations().await.expect("migrations run");
        // Idempotent: running again is a no-op.
        backend.run_migrations().await.expect("migrations re-run");
    }

    /// Mission category §4 "Idempotency": ON CONFLICT DO NOTHING.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn insert_idempotent() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let row = TraceEventRow {
            trace_id: format!("trace-pg-{}", uuid_like()),
            thought_id: "th-1".into(),
            task_id: None,
            step_point: None,
            event_type: ReasoningEventType::ThoughtStart,
            attempt_index: 0,
            ts: chrono::Utc::now(),
            agent_name: None,
            agent_id_hash: "deadbeef".into(),
            cognitive_state: None,
            trace_level: crate::schema::TraceLevel::Generic,
            payload: serde_json::Map::new(),
            cost_llm_calls: None,
            cost_tokens: None,
            cost_usd: None,
            signature: "AAAA".into(),
            signing_key_id: "test-key".into(),
            signature_verified: true,
            schema_version: "2.7.0".into(),
            pii_scrubbed: false,
            original_content_hash: None,
            scrub_signature: None,
            scrub_key_id: None,
            scrub_timestamp: None,
        };

        let r1 = backend
            .insert_trace_events_batch(std::slice::from_ref(&row))
            .await
            .unwrap();
        assert_eq!(r1.inserted, 1);
        assert_eq!(r1.conflicted, 0);

        let r2 = backend.insert_trace_events_batch(&[row]).await.unwrap();
        assert_eq!(r2.inserted, 0);
        assert_eq!(r2.conflicted, 1);
    }

    fn uuid_like() -> String {
        // Avoid pulling in the uuid crate for a single test helper.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{nanos:x}")
    }
}
