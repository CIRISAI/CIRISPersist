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

/// Postgres advisory-lock namespace for the migration phase.
///
/// `pg_advisory_lock(bigint)` takes a single int8; the bytes spell
/// `"cirispsr"` in ASCII so the value is greppable in pg_locks /
/// pg_stat_activity. Stable across worker boots so multi-worker
/// boot contention serializes on the *same* lock id (the whole point
/// of the v0.1.5 fix). THREAT_MODEL.md AV-26.
const MIGRATION_LOCK_ID: i64 = 0x6369_7269_7370_7372_i64;

/// Postgres-backed [`Backend`] impl.
pub struct PostgresBackend {
    pool: Pool,
    /// Original DSN, retained for the migration phase's dedicated
    /// connection. The pool can't be used for the advisory-lock
    /// holder: if a session-scoped `pg_advisory_lock` is taken on a
    /// pooled connection and that connection is recycled into the
    /// pool, the next user inherits the lock until the session ends.
    /// The migration path uses a one-shot non-pooled connection so
    /// the lock auto-releases when the connection drops — including
    /// the panic-mid-migration case.
    dsn: String,
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

        Ok(Self {
            pool,
            dsn: dsn.to_owned(),
        })
    }

    /// Construct from an already-built deadpool. For tests / advanced
    /// embeddings (e.g. lens binary that wants to share a pool with
    /// other queries).
    ///
    /// `dsn` is required so the migration phase (v0.1.5+) can spin up
    /// a dedicated single-use connection to hold the advisory lock —
    /// see [`run_migrations`](Backend::run_migrations) and the
    /// `MIGRATION_LOCK_ID` doc.
    pub fn from_pool(pool: Pool, dsn: impl Into<String>) -> Self {
        Self {
            pool,
            dsn: dsn.into(),
        }
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

    /// Open a one-shot non-pooled connection. Used by
    /// [`Backend::run_migrations`] to hold the session-scoped
    /// advisory lock. When the returned client drops, the
    /// connection task observes EOF and the session ends — the lock
    /// auto-releases. Includes the panic-mid-migration case.
    #[cfg(not(feature = "tls"))]
    async fn dedicated_connect(&self) -> Result<tokio_postgres::Client, Error> {
        let (client, connection) =
            tokio_postgres::connect(&self.dsn, NoTls)
                .await
                .map_err(|e| Error::Migration {
                    sqlstate: extract_sqlstate(&e),
                    detail: format!("dedicated connect: {e}"),
                })?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::warn!(error = %e, "migration-lock connection terminated");
            }
        });
        Ok(client)
    }

    #[cfg(feature = "tls")]
    async fn dedicated_connect(&self) -> Result<tokio_postgres::Client, Error> {
        use rustls::ClientConfig;
        use tokio_postgres_rustls::MakeRustlsConnect;
        let mut roots = rustls::RootCertStore::empty();
        let cert_result = rustls_native_certs::load_native_certs();
        for cert in cert_result.certs {
            roots.add(cert).map_err(|e| Error::Migration {
                sqlstate: None,
                detail: format!("native-cert add: {e}"),
            })?;
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
        let (client, connection) = tokio_postgres::connect(&self.dsn, connector)
            .await
            .map_err(|e| Error::Migration {
                sqlstate: extract_sqlstate(&e),
                detail: format!("dedicated connect (tls): {e}"),
            })?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::warn!(error = %e, "migration-lock connection terminated");
            }
        });
        Ok(client)
    }
}

/// Walk the std::error::Error source chain; if a tokio-postgres
/// error is found, return its SQLSTATE class+code as a stable string.
///
/// Used by [`Backend::run_migrations`] to surface 42P07 / 40P01 /
/// 08006 distinctly to the lens. Every fallible Postgres path goes
/// through `tokio_postgres::Error` somewhere in the source chain;
/// refinery wraps it but doesn't strip it.
fn extract_sqlstate(err: &(dyn std::error::Error + 'static)) -> Option<String> {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(pg_err) = e.downcast_ref::<tokio_postgres::Error>() {
            return pg_err.code().map(|c| c.code().to_owned());
        }
        cur = e.source();
    }
    None
}

/// Format a migration-phase error with the SQLSTATE prepended
/// (when available) so the Display string is greppable in lens
/// logs without separate field-extraction.
fn migration_error<E>(stage: &str, err: E) -> Error
where
    E: std::error::Error + 'static,
{
    let sqlstate = extract_sqlstate(&err);
    let detail = match &sqlstate {
        Some(code) => format!("{stage}: [{code}] {err}"),
        None => format!("{stage}: {err}"),
    };
    Error::Migration { sqlstate, detail }
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
                            original_content_hash, scrub_signature, scrub_key_id, scrub_timestamp, \
                            agent_role, agent_template, deployment_domain, \
                            deployment_type, deployment_region, deployment_trust_mode";
        const N_COLS: usize = 33;

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
            // v0.3.4 deployment_profile columns (V006).
            params.push(Box::new(row.agent_role.clone()));
            params.push(Box::new(row.agent_template.clone()));
            params.push(Box::new(row.deployment_domain.clone()));
            params.push(Box::new(row.deployment_type.clone()));
            params.push(Box::new(row.deployment_region.clone()));
            params.push(Box::new(row.deployment_trust_mode.clone()));
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
        // v0.4.0 (lens#8 ASK 2) — federation_keys is the canonical
        // pubkey directory. The v0.2.1 dual-read fallback to
        // accord_public_keys was retired in this release, coordinated
        // with lens dropping its direct INSERT into accord_public_keys
        // the same release. The legacy table stays in the schema for
        // historical reads via cirislens_reader (V005 read-only role)
        // but the verify path no longer touches it.
        //
        // Filter: federation_keys has no direct revocation column
        // (revocations live in federation_revocations); we accept any
        // unexpired row. Strict consumers can layer revocation checks
        // via FederationDirectory::revocations_for().
        let client = self.get_client().await?;
        let fed_row = client
            .query_opt(
                "SELECT pubkey_ed25519_base64 FROM cirislens.federation_keys \
                 WHERE key_id = $1 \
                   AND (valid_until IS NULL OR valid_until > NOW())",
                &[&key_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("lookup_public_key: {e}")))?;
        match fed_row {
            None => Ok(None),
            Some(row) => {
                let b64: String = row.get(0);
                decode_ed25519_b64(&b64).map(Some)
            }
        }
    }

    async fn sample_public_keys(
        &self,
        limit: usize,
    ) -> Result<super::backend::PublicKeySample, Error> {
        // v0.4.0 — diagnostic for the verify-unknown-key breadcrumb,
        // updated to query federation_keys (the canonical directory
        // post-lens#8 ASK 2). Same filter as `lookup_public_key`'s
        // WHERE so the sample reflects exactly what the runtime
        // lookup queries against.
        let client = self.get_client().await?;
        let count_row = client
            .query_one(
                "SELECT COUNT(*)::BIGINT FROM cirislens.federation_keys \
                 WHERE valid_until IS NULL OR valid_until > NOW()",
                &[],
            )
            .await
            .map_err(|e| Error::Backend(format!("count_public_keys: {e}")))?;
        let total: i64 = count_row.get(0);

        let lim = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = client
            .query(
                "SELECT key_id FROM cirislens.federation_keys \
                 WHERE valid_until IS NULL OR valid_until > NOW() \
                 ORDER BY key_id LIMIT $1",
                &[&lim],
            )
            .await
            .map_err(|e| Error::Backend(format!("sample_public_keys: {e}")))?;
        let sample: Vec<String> = rows.iter().map(|r| r.get(0)).collect();

        Ok(super::backend::PublicKeySample {
            size: total.max(0) as usize,
            sample,
        })
    }

    async fn run_migrations(&self) -> Result<(), Error> {
        // v0.1.5 — multi-worker boot race fix. Before this, two
        // workers calling `run_migrations` concurrently against the
        // same DB would race on Postgres's catalog (`pg_type` insert
        // for hypertable types, `IF NOT EXISTS` checks across the
        // V001 + V003 set, refinery's own schema_history table).
        // Pre-v0.1.5 the second worker saw "error asserting
        // migrations table — db error" with no SQLSTATE handle.
        //
        // Fix: take a session-scoped advisory lock on a dedicated
        // single-use connection. The first worker acquires it
        // immediately; subsequent workers block on
        // `pg_advisory_lock` until the first worker drops its
        // connection. Lock auto-releases on connection close — even
        // if the first worker panics mid-migration. THREAT_MODEL.md
        // AV-26.
        let mut lock_client = self.dedicated_connect().await?;

        // Block until the lock is held. First worker through wins
        // immediately; later workers wake up when the first worker's
        // connection closes (after migrations complete or panic).
        // Lens-side readiness probe should be at least the
        // observed migration runtime + a small buffer.
        lock_client
            .execute("SELECT pg_advisory_lock($1)", &[&MIGRATION_LOCK_ID])
            .await
            .map_err(|e| migration_error("acquire advisory lock", e))?;

        tracing::info!(
            lock_id = MIGRATION_LOCK_ID,
            "ciris-persist: migration phase begin (advisory lock acquired)"
        );

        // Run refinery on the same lock-holding connection. refinery
        // wraps each migration in its own transaction; the advisory
        // lock is at session scope, so it persists across all of
        // them. If a single migration fails, refinery rolls back its
        // transaction; we drop the connection below; lock releases.
        let migration_result = embedded::migrations::runner()
            .set_migration_table_name("ciris_persist_schema_history")
            .run_async(&mut lock_client)
            .await
            .map_err(|e| migration_error("migrations", e));

        // Best-effort explicit unlock — graceful path. The drop below
        // is the actual guarantee (session ends → lock releases),
        // but releasing explicitly returns the lock as soon as the
        // last migration commits, shaving wait time off concurrent
        // workers.
        let _ = lock_client
            .execute("SELECT pg_advisory_unlock($1)", &[&MIGRATION_LOCK_ID])
            .await;
        drop(lock_client);

        migration_result?;
        tracing::info!("ciris-persist: migration phase complete");
        Ok(())
    }

    async fn delete_traces_for_agent(
        &self,
        agent_id_hash: &str,
        signature_key_id: &str,
        include_federation_key: bool,
    ) -> Result<super::types::DeleteSummary, Error> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| Error::Backend(format!("begin tx: {e}")))?;

        // Per-key DSAR scope: both agent_id_hash AND signing_key_id
        // must match. trace_llm_calls cascade walks the matching set
        // via the trace_id bridge (V001 schema: LLM call rows have
        // no signing_key_id column).
        // Step 1: collect matching trace_ids.
        let trace_ids: Vec<String> = tx
            .query(
                "SELECT DISTINCT trace_id FROM cirislens.trace_events \
                 WHERE agent_id_hash = $1 AND signing_key_id = $2",
                &[&agent_id_hash, &signature_key_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("collect trace_ids: {e}")))?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect();

        // Step 2: delete LLM call rows joined by the matching
        // trace_ids. Cross-key traces (agent rotated keys, signed
        // under multiple keys) only cascade for this DSAR's key.
        let trace_llm_calls_deleted = if trace_ids.is_empty() {
            0u64
        } else {
            tx.execute(
                "DELETE FROM cirislens.trace_llm_calls \
                 WHERE trace_id = ANY($1::text[])",
                &[&trace_ids],
            )
            .await
            .map_err(|e| Error::Backend(format!("delete trace_llm_calls: {e}")))?
        };

        // Step 3: delete trace_events rows. Same key-scope filter as
        // step 1 — both must agree, else step 2 could cascade
        // delete LLM calls for trace_events rows step 3 leaves alive.
        let trace_events_deleted = tx
            .execute(
                "DELETE FROM cirislens.trace_events \
                 WHERE agent_id_hash = $1 AND signing_key_id = $2",
                &[&agent_id_hash, &signature_key_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("delete trace_events: {e}")))?;

        // Step 4 (optional): federation key cascade. Find target key_ids,
        // delete cascading attestation/revocation rows, then the keys.
        let mut federation_keys_deleted = 0u64;
        let mut federation_attestations_deleted = 0u64;
        let mut federation_revocations_deleted = 0u64;

        if include_federation_key {
            // Per-key federation_keys cascade: the single key_id
            // matching (agent_id_hash, signature_key_id). The agent's
            // other registered keys stay alive.
            let target_key_ids: Vec<String> = tx
                .query(
                    "SELECT key_id FROM cirislens.federation_keys \
                     WHERE identity_type = 'agent' AND identity_ref = $1 AND key_id = $2",
                    &[&agent_id_hash, &signature_key_id],
                )
                .await
                .map_err(|e| Error::Backend(format!("collect target_key_ids: {e}")))?
                .into_iter()
                .map(|row| row.get::<_, String>(0))
                .collect();

            if !target_key_ids.is_empty() {
                federation_revocations_deleted = tx
                    .execute(
                        "DELETE FROM cirislens.federation_revocations \
                         WHERE revoked_key_id = ANY($1::text[]) \
                            OR revoking_key_id = ANY($1::text[]) \
                            OR scrub_key_id    = ANY($1::text[])",
                        &[&target_key_ids],
                    )
                    .await
                    .map_err(|e| Error::Backend(format!("delete federation_revocations: {e}")))?;

                federation_attestations_deleted = tx
                    .execute(
                        "DELETE FROM cirislens.federation_attestations \
                         WHERE attesting_key_id = ANY($1::text[]) \
                            OR attested_key_id  = ANY($1::text[]) \
                            OR scrub_key_id     = ANY($1::text[])",
                        &[&target_key_ids],
                    )
                    .await
                    .map_err(|e| Error::Backend(format!("delete federation_attestations: {e}")))?;

                federation_keys_deleted = tx
                    .execute(
                        "DELETE FROM cirislens.federation_keys \
                         WHERE key_id = ANY($1::text[])",
                        &[&target_key_ids],
                    )
                    .await
                    .map_err(|e| Error::Backend(format!("delete federation_keys: {e}")))?;
            }
        }

        tx.commit()
            .await
            .map_err(|e| Error::Backend(format!("commit dsar tx: {e}")))?;

        Ok(super::types::DeleteSummary {
            trace_events_deleted,
            trace_llm_calls_deleted,
            federation_keys_deleted,
            federation_attestations_deleted,
            federation_revocations_deleted,
            deleted_at: chrono::Utc::now(),
        })
    }

    async fn fetch_trace_events_page(
        &self,
        after_event_id: i64,
        limit: i64,
        agent_id_hash: Option<&str>,
    ) -> Result<Vec<(i64, TraceEventRow)>, Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| Error::Backend(format!("pool: {e}")))?;

        // Branch on filter so the no-filter case skips the optional
        // WHERE-clause bind. Same shape Postgres planners optimize
        // either way; the bind-arity branch is the simplest readable form.
        let rows = match agent_id_hash {
            Some(h) => client
                .query(
                    "SELECT event_id, trace_id, thought_id, task_id, step_point, event_type, \
                            attempt_index, ts, agent_name, agent_id_hash, cognitive_state, \
                            trace_level, payload, cost_llm_calls, cost_tokens, cost_usd, \
                            signature, signing_key_id, signature_verified, schema_version, \
                            pii_scrubbed, audit_sequence_number, audit_entry_hash, \
                            audit_signature, original_content_hash, scrub_signature, \
                            scrub_key_id, scrub_timestamp, agent_role, agent_template, \
                            deployment_domain, deployment_type, deployment_region, \
                            deployment_trust_mode \
                     FROM cirislens.trace_events \
                     WHERE event_id > $1 AND agent_id_hash = $2 \
                     ORDER BY event_id ASC LIMIT $3",
                    &[&after_event_id, &h, &limit],
                )
                .await
                .map_err(|e| Error::Backend(format!("fetch_trace_events_page: {e}")))?,
            None => client
                .query(
                    "SELECT event_id, trace_id, thought_id, task_id, step_point, event_type, \
                            attempt_index, ts, agent_name, agent_id_hash, cognitive_state, \
                            trace_level, payload, cost_llm_calls, cost_tokens, cost_usd, \
                            signature, signing_key_id, signature_verified, schema_version, \
                            pii_scrubbed, audit_sequence_number, audit_entry_hash, \
                            audit_signature, original_content_hash, scrub_signature, \
                            scrub_key_id, scrub_timestamp, agent_role, agent_template, \
                            deployment_domain, deployment_type, deployment_region, \
                            deployment_trust_mode \
                     FROM cirislens.trace_events \
                     WHERE event_id > $1 \
                     ORDER BY event_id ASC LIMIT $2",
                    &[&after_event_id, &limit],
                )
                .await
                .map_err(|e| Error::Backend(format!("fetch_trace_events_page: {e}")))?,
        };

        rows.into_iter().map(pg_row_to_event_row).collect()
    }
}

// ─── FederationDirectory impl (v0.2.0) ─────────────────────────────
//
// Postgres-backed federation directory. Same logical surface as the
// memory backend; differences are postgres-isms:
//   - persist_row_hash is computed in Rust (server-side, before
//     INSERT) — postgres sees it as a TEXT column.
//   - FK constraints (DEFERRABLE INITIALLY DEFERRED for self-signed
//     bootstrap row) enforced at COMMIT time.
//   - JSONB columns serialize Value via postgres-types' built-in
//     ToSql impl.
//   - BYTEA columns for original_content_hash + scrub_signature take
//     hex-decoded raw bytes; the wire shape uses hex/base64 strings,
//     decoded at the persist boundary.

impl crate::federation::FederationDirectory for PostgresBackend {
    async fn put_public_key(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<(), crate::federation::Error> {
        let mut row = record.record;
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;

        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;

        let original_content_hash = hex::decode(&row.original_content_hash).map_err(|e| {
            crate::federation::Error::InvalidArgument(format!(
                "original_content_hash hex decode: {e}"
            ))
        })?;
        // Reject non-hybrid algorithm values; schema CHECK constraint
        // enforces this too, but we want a clean federation::Error
        // shape rather than a backend SQL error string.
        if row.algorithm != crate::federation::types::algorithm::HYBRID {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "algorithm must be 'hybrid' (got '{}')",
                row.algorithm
            )));
        }

        // Idempotent on (key_id, persist_row_hash). DO NOTHING when
        // (key_id, persist_row_hash) match exactly; raise Conflict
        // when key_id matches but content differs.
        let result = client
            .execute(
                "INSERT INTO cirislens.federation_keys (\
                    key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                    identity_type, identity_ref, valid_from, valid_until, registration_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) \
                 ON CONFLICT (key_id) DO NOTHING",
                &[
                    &row.key_id,
                    &row.pubkey_ed25519_base64,
                    &row.pubkey_ml_dsa_65_base64,
                    &row.algorithm,
                    &row.identity_type,
                    &row.identity_ref,
                    &row.valid_from,
                    &row.valid_until,
                    &row.registration_envelope,
                    &original_content_hash,
                    &row.scrub_signature_classical,
                    &row.scrub_signature_pqc,
                    &row.scrub_key_id,
                    &row.scrub_timestamp,
                    &row.pqc_completed_at,
                    &row.persist_row_hash,
                ],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("insert federation_keys: {e}"))
            })?;

        if result == 0 {
            // ON CONFLICT triggered — check if hash matches.
            let existing: Option<String> = client
                .query_opt(
                    "SELECT persist_row_hash FROM cirislens.federation_keys WHERE key_id = $1",
                    &[&row.key_id],
                )
                .await
                .map_err(|e| crate::federation::Error::Backend(format!("conflict check: {e}")))?
                .map(|r| r.get(0));
            if let Some(existing_hash) = existing {
                if existing_hash != row.persist_row_hash {
                    return Err(crate::federation::Error::Conflict(format!(
                        "key_id {} already exists with different content",
                        row.key_id
                    )));
                }
            }
        }
        Ok(())
    }

    async fn lookup_public_key(
        &self,
        key_id: &str,
    ) -> Result<Option<crate::federation::KeyRecord>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let row_opt = client
            .query_opt(
                "SELECT key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                    identity_type, identity_ref, valid_from, valid_until, registration_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
                 FROM cirislens.federation_keys WHERE key_id = $1",
                &[&key_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("lookup federation_keys: {e}"))
            })?;
        Ok(row_opt.map(pg_row_to_key_record))
    }

    async fn lookup_keys_for_identity(
        &self,
        identity_ref: &str,
    ) -> Result<Vec<crate::federation::KeyRecord>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let rows = client
            .query(
                "SELECT key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                    identity_type, identity_ref, valid_from, valid_until, registration_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
                 FROM cirislens.federation_keys WHERE identity_ref = $1",
                &[&identity_ref],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("lookup_keys_for_identity: {e}"))
            })?;
        Ok(rows.into_iter().map(pg_row_to_key_record).collect())
    }

    async fn put_attestation(
        &self,
        attestation: crate::federation::SignedAttestation,
    ) -> Result<(), crate::federation::Error> {
        let mut row = attestation.attestation;
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;

        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;

        let original_content_hash = hex::decode(&row.original_content_hash).map_err(|e| {
            crate::federation::Error::InvalidArgument(format!(
                "original_content_hash hex decode: {e}"
            ))
        })?;

        // postgres-types doesn't have a built-in for f64→NUMERIC; cast
        // weight to f64 and let postgres convert.
        client
            .execute(
                "INSERT INTO cirislens.federation_attestations (\
                    attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                    weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash\
                 ) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
                &[
                    &row.attestation_id,
                    &row.attesting_key_id,
                    &row.attested_key_id,
                    &row.attestation_type,
                    &row.weight,
                    &row.asserted_at,
                    &row.expires_at,
                    &row.attestation_envelope,
                    &original_content_hash,
                    &row.scrub_signature_classical,
                    &row.scrub_signature_pqc,
                    &row.scrub_key_id,
                    &row.scrub_timestamp,
                    &row.pqc_completed_at,
                    &row.persist_row_hash,
                ],
            )
            .await
            .map_err(|e| {
                let msg = e.to_string();
                // FK violation → InvalidArgument (matches memory shape).
                if msg.contains("foreign key") {
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
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let rows = client
            .query(
                "SELECT attestation_id::text, attesting_key_id, attested_key_id, attestation_type, \
                    weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
                 FROM cirislens.federation_attestations \
                 WHERE attested_key_id = $1 \
                 ORDER BY asserted_at DESC",
                &[&attested_key_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("list_attestations_for: {e}"))
            })?;
        Ok(rows.into_iter().map(pg_row_to_attestation).collect())
    }

    async fn list_attestations_by(
        &self,
        attesting_key_id: &str,
    ) -> Result<Vec<crate::federation::Attestation>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let rows = client
            .query(
                "SELECT attestation_id::text, attesting_key_id, attested_key_id, attestation_type, \
                    weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
                 FROM cirislens.federation_attestations \
                 WHERE attesting_key_id = $1 \
                 ORDER BY asserted_at DESC",
                &[&attesting_key_id],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("list_attestations_by: {e}")))?;
        Ok(rows.into_iter().map(pg_row_to_attestation).collect())
    }

    async fn put_revocation(
        &self,
        revocation: crate::federation::SignedRevocation,
    ) -> Result<(), crate::federation::Error> {
        let mut row = revocation.revocation;
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;

        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;

        let original_content_hash = hex::decode(&row.original_content_hash).map_err(|e| {
            crate::federation::Error::InvalidArgument(format!(
                "original_content_hash hex decode: {e}"
            ))
        })?;

        client
            .execute(
                "INSERT INTO cirislens.federation_revocations (\
                    revocation_id, revoked_key_id, revoking_key_id, reason, \
                    revoked_at, effective_at, revocation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash\
                 ) VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
                &[
                    &row.revocation_id,
                    &row.revoked_key_id,
                    &row.revoking_key_id,
                    &row.reason,
                    &row.revoked_at,
                    &row.effective_at,
                    &row.revocation_envelope,
                    &original_content_hash,
                    &row.scrub_signature_classical,
                    &row.scrub_signature_pqc,
                    &row.scrub_key_id,
                    &row.scrub_timestamp,
                    &row.pqc_completed_at,
                    &row.persist_row_hash,
                ],
            )
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("foreign key") {
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
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let rows = client
            .query(
                "SELECT revocation_id::text, revoked_key_id, revoking_key_id, reason, \
                    revoked_at, effective_at, revocation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
                 FROM cirislens.federation_revocations \
                 WHERE revoked_key_id = $1 \
                 ORDER BY effective_at DESC",
                &[&revoked_key_id],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("revocations_for: {e}")))?;
        Ok(rows.into_iter().map(pg_row_to_revocation).collect())
    }

    async fn attach_key_pqc_signature(
        &self,
        key_id: &str,
        pubkey_ml_dsa_65_base64: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), crate::federation::Error> {
        // Read row → check hybrid-pending → update + recompute hash.
        // Single-statement UPDATE with WHERE pqc_completed_at IS NULL
        // gates against double-fill atomically.
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

        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let n = client
            .execute(
                "UPDATE cirislens.federation_keys \
                 SET pubkey_ml_dsa_65_base64 = $1, scrub_signature_pqc = $2, \
                     pqc_completed_at = $3, persist_row_hash = $4 \
                 WHERE key_id = $5 AND pqc_completed_at IS NULL",
                &[
                    &pubkey_ml_dsa_65_base64,
                    &scrub_signature_pqc,
                    &now,
                    &new_hash,
                    &key_id,
                ],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("attach_key_pqc_signature: {e}"))
            })?;
        if n == 0 {
            return Err(crate::federation::Error::Conflict(format!(
                "federation_keys row {key_id} was concurrently completed"
            )));
        }
        Ok(())
    }

    async fn attach_attestation_pqc_signature(
        &self,
        attestation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        // Read existing row to recompute the hash with new fields.
        let row_opt = client
            .query_opt(
                "SELECT attestation_id::text, attesting_key_id, attested_key_id, attestation_type, \
                    weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
                 FROM cirislens.federation_attestations WHERE attestation_id = $1::uuid",
                &[&attestation_id],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("attach lookup: {e}")))?;
        let mut row = row_opt.map(pg_row_to_attestation).ok_or_else(|| {
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
        let n = client
            .execute(
                "UPDATE cirislens.federation_attestations \
                 SET scrub_signature_pqc = $1, pqc_completed_at = $2, persist_row_hash = $3 \
                 WHERE attestation_id = $4::uuid AND pqc_completed_at IS NULL",
                &[&scrub_signature_pqc, &now, &new_hash, &attestation_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("attach_attestation_pqc_signature: {e}"))
            })?;
        if n == 0 {
            return Err(crate::federation::Error::Conflict(format!(
                "federation_attestations row {attestation_id} was concurrently completed"
            )));
        }
        Ok(())
    }

    async fn attach_revocation_pqc_signature(
        &self,
        revocation_id: &str,
        scrub_signature_pqc: &str,
    ) -> Result<(), crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let row_opt = client
            .query_opt(
                "SELECT revocation_id::text, revoked_key_id, revoking_key_id, reason, \
                    revoked_at, effective_at, revocation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash \
                 FROM cirislens.federation_revocations WHERE revocation_id = $1::uuid",
                &[&revocation_id],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("attach lookup: {e}")))?;
        let mut row = row_opt.map(pg_row_to_revocation).ok_or_else(|| {
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
        let n = client
            .execute(
                "UPDATE cirislens.federation_revocations \
                 SET scrub_signature_pqc = $1, pqc_completed_at = $2, persist_row_hash = $3 \
                 WHERE revocation_id = $4::uuid AND pqc_completed_at IS NULL",
                &[&scrub_signature_pqc, &now, &new_hash, &revocation_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("attach_revocation_pqc_signature: {e}"))
            })?;
        if n == 0 {
            return Err(crate::federation::Error::Conflict(format!(
                "federation_revocations row {revocation_id} was concurrently completed"
            )));
        }
        Ok(())
    }

    async fn list_hybrid_pending_keys(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::federation::HybridPendingRow>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let rows = client
            .query(
                "SELECT key_id, registration_envelope, scrub_signature_classical \
                 FROM cirislens.federation_keys \
                 WHERE pqc_completed_at IS NULL \
                 ORDER BY valid_from ASC \
                 LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("list_hybrid_pending_keys: {e}"))
            })?;
        Ok(rows
            .into_iter()
            .map(|row| crate::federation::HybridPendingRow {
                id: row.get("key_id"),
                envelope: row.get("registration_envelope"),
                classical_sig_b64: row.get("scrub_signature_classical"),
            })
            .collect())
    }

    async fn list_hybrid_pending_attestations(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::federation::HybridPendingRow>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let rows = client
            .query(
                "SELECT attestation_id::text AS attestation_id, \
                    attestation_envelope, scrub_signature_classical \
                 FROM cirislens.federation_attestations \
                 WHERE pqc_completed_at IS NULL \
                 ORDER BY asserted_at ASC \
                 LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("list_hybrid_pending_attestations: {e}"))
            })?;
        Ok(rows
            .into_iter()
            .map(|row| crate::federation::HybridPendingRow {
                id: row.get("attestation_id"),
                envelope: row.get("attestation_envelope"),
                classical_sig_b64: row.get("scrub_signature_classical"),
            })
            .collect())
    }

    async fn list_hybrid_pending_revocations(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::federation::HybridPendingRow>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let rows = client
            .query(
                "SELECT revocation_id::text AS revocation_id, \
                    revocation_envelope, scrub_signature_classical \
                 FROM cirislens.federation_revocations \
                 WHERE pqc_completed_at IS NULL \
                 ORDER BY revoked_at ASC \
                 LIMIT $1",
                &[&limit],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("list_hybrid_pending_revocations: {e}"))
            })?;
        Ok(rows
            .into_iter()
            .map(|row| crate::federation::HybridPendingRow {
                id: row.get("revocation_id"),
                envelope: row.get("revocation_envelope"),
                classical_sig_b64: row.get("scrub_signature_classical"),
            })
            .collect())
    }
}

// ─── OutboundQueue impl (v0.4.0, CIRISPersist#16) ──────────────────
//
// Postgres-backed durable substrate for CIRISEdge::send_durable().
// State-machine + ACK-matching + sweep primitives. Same architectural
// shape as FederationDirectory: trait carries the contract, this
// impl provides the postgres-specific queries.

impl crate::outbound::OutboundQueue for PostgresBackend {
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
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let body_sha256_vec: Vec<u8> = body_sha256.to_vec();
        let row = client
            .query_one(
                "INSERT INTO cirislens.edge_outbound_queue (\
                    sender_key_id, destination_key_id, message_type, \
                    edge_schema_version, envelope_bytes, body_sha256, \
                    body_size_bytes, status, next_attempt_after, \
                    max_attempts, ttl_seconds, requires_ack, \
                    ack_timeout_seconds\
                 ) VALUES (\
                    $1, $2, $3, $4, $5, $6, $7, 'pending', $8, $9, $10, $11, $12\
                 ) RETURNING queue_id::text",
                &[
                    &sender_key_id,
                    &destination_key_id,
                    &message_type,
                    &edge_schema_version,
                    &envelope_bytes,
                    &body_sha256_vec,
                    &body_size_bytes,
                    &initial_next_attempt_after,
                    &max_attempts,
                    &ttl_seconds,
                    &requires_ack,
                    &ack_timeout_seconds,
                ],
            )
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("enqueue_outbound: {e}")))?;
        Ok(row.get(0))
    }

    async fn claim_pending_outbound(
        &self,
        batch_size: i64,
        claim_duration_seconds: i64,
        claimed_by: &str,
    ) -> Result<Vec<crate::outbound::OutboundRow>, crate::outbound::Error> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("begin tx: {e}")))?;

        // FOR UPDATE SKIP LOCKED is the multi-instance dispatch
        // primitive — concurrent workers see disjoint batches
        // (CIRISEdge OQ-06). Subquery picks claim candidates;
        // outer UPDATE marks them sending + writes claim metadata.
        let now = chrono::Utc::now();
        let claim_until = now + chrono::Duration::seconds(claim_duration_seconds);
        let rows = tx
            .query(
                "WITH picked AS (\
                    SELECT queue_id FROM cirislens.edge_outbound_queue \
                     WHERE status = 'pending' AND next_attempt_after <= $1 \
                     ORDER BY next_attempt_after ASC \
                     LIMIT $2 \
                     FOR UPDATE SKIP LOCKED\
                 ) \
                 UPDATE cirislens.edge_outbound_queue q \
                 SET status = 'sending', \
                     last_attempt_at = $1, \
                     attempt_count = attempt_count + 1, \
                     claimed_until = $3, claimed_by = $4 \
                 FROM picked \
                 WHERE q.queue_id = picked.queue_id \
                 RETURNING q.queue_id::text, sender_key_id, destination_key_id, \
                          message_type, edge_schema_version, envelope_bytes, \
                          body_sha256, body_size_bytes, status, enqueued_at, \
                          next_attempt_after, last_attempt_at, transport_delivered_at, \
                          delivered_at, abandoned_at, abandoned_reason, attempt_count, \
                          max_attempts, ttl_seconds, last_error_class, last_error_detail, \
                          last_transport, requires_ack, ack_timeout_seconds, \
                          ack_envelope_bytes, ack_received_at, claimed_until, claimed_by",
                &[&now, &batch_size, &claim_until, &claimed_by],
            )
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("claim_pending_outbound: {e}")))?;
        tx.commit()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("commit claim: {e}")))?;

        rows.into_iter().map(pg_row_to_outbound_row).collect()
    }

    async fn mark_transport_delivered(
        &self,
        queue_id: &crate::outbound::QueueId,
        transport: &str,
    ) -> Result<(), crate::outbound::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let now = chrono::Utc::now();
        // Branch on requires_ack within the SQL: 'delivered' immediately
        // when no ACK required; 'awaiting_ack' otherwise. CHECK
        // constraints enforce delivered_at correctness on terminal.
        let n = client
            .execute(
                "UPDATE cirislens.edge_outbound_queue \
                 SET status = CASE WHEN requires_ack THEN 'awaiting_ack' ELSE 'delivered' END, \
                     transport_delivered_at = $1, \
                     delivered_at = CASE WHEN requires_ack THEN NULL ELSE $1 END, \
                     last_transport = $2, \
                     claimed_until = NULL, claimed_by = NULL \
                 WHERE queue_id = $3::uuid AND status = 'sending'",
                &[&now, &transport, &queue_id],
            )
            .await
            .map_err(|e| {
                crate::outbound::Error::Backend(format!("mark_transport_delivered: {e}"))
            })?;
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
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("begin tx: {e}")))?;

        // Read current state to decide retry vs abandon. Lock the
        // row so concurrent dispatcher workers can't race.
        let row = tx
            .query_opt(
                "SELECT attempt_count, max_attempts, enqueued_at, ttl_seconds \
                 FROM cirislens.edge_outbound_queue \
                 WHERE queue_id = $1::uuid AND status = 'sending' \
                 FOR UPDATE",
                &[&queue_id],
            )
            .await
            .map_err(|e| {
                crate::outbound::Error::Backend(format!("mark_transport_failed lookup: {e}"))
            })?
            .ok_or_else(|| {
                crate::outbound::Error::InvalidTransition(format!(
                    "queue_id {queue_id} not in 'sending'"
                ))
            })?;

        let attempt_count: i32 = row.get(0);
        let max_attempts: i32 = row.get(1);
        let enqueued_at: chrono::DateTime<chrono::Utc> = row.get(2);
        let ttl_seconds: i64 = row.get(3);

        let now = chrono::Utc::now();
        let ttl_expired = (now - enqueued_at) > chrono::Duration::seconds(ttl_seconds);
        let attempts_exhausted = attempt_count >= max_attempts;

        let outcome = if ttl_expired || attempts_exhausted {
            let reason = if ttl_expired {
                "ttl_expired"
            } else {
                "max_attempts"
            };
            tx.execute(
                "UPDATE cirislens.edge_outbound_queue \
                 SET status = 'abandoned', \
                     abandoned_at = $1, abandoned_reason = $2, \
                     last_error_class = $3, last_error_detail = $4, \
                     last_transport = $5, \
                     claimed_until = NULL, claimed_by = NULL \
                 WHERE queue_id = $6::uuid",
                &[
                    &now,
                    &reason,
                    &error_class,
                    &error_detail,
                    &transport,
                    &queue_id,
                ],
            )
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("mark abandoned: {e}")))?;
            crate::outbound::OutboundFailureOutcome::Abandoned
        } else {
            tx.execute(
                "UPDATE cirislens.edge_outbound_queue \
                 SET status = 'pending', \
                     next_attempt_after = $1, \
                     last_error_class = $2, last_error_detail = $3, \
                     last_transport = $4, \
                     claimed_until = NULL, claimed_by = NULL \
                 WHERE queue_id = $5::uuid",
                &[
                    &next_attempt_after,
                    &error_class,
                    &error_detail,
                    &transport,
                    &queue_id,
                ],
            )
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("mark retrying: {e}")))?;
            crate::outbound::OutboundFailureOutcome::Retrying {
                attempt: attempt_count,
            }
        };

        tx.commit().await.map_err(|e| {
            crate::outbound::Error::Backend(format!("commit mark_transport_failed: {e}"))
        })?;
        Ok(outcome)
    }

    async fn mark_replay_resolved(
        &self,
        queue_id: &crate::outbound::QueueId,
    ) -> Result<(), crate::outbound::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let now = chrono::Utc::now();
        // Treat as delivered — receiver already accepted the body
        // (replay window expired before our ACK arrived). Idempotent
        // across non-terminal states.
        client
            .execute(
                "UPDATE cirislens.edge_outbound_queue \
                 SET status = 'delivered', delivered_at = $1, \
                     claimed_until = NULL, claimed_by = NULL \
                 WHERE queue_id = $2::uuid AND status NOT IN ('delivered', 'abandoned')",
                &[&now, &queue_id],
            )
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("mark_replay_resolved: {e}")))?;
        Ok(())
    }

    async fn match_ack_to_outbound(
        &self,
        in_reply_to_sha256: &[u8; 32],
    ) -> Result<Option<crate::outbound::OutboundRow>, crate::outbound::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let hash_vec: Vec<u8> = in_reply_to_sha256.to_vec();
        let row_opt = client
            .query_opt(
                "SELECT queue_id::text, sender_key_id, destination_key_id, \
                        message_type, edge_schema_version, envelope_bytes, \
                        body_sha256, body_size_bytes, status, enqueued_at, \
                        next_attempt_after, last_attempt_at, transport_delivered_at, \
                        delivered_at, abandoned_at, abandoned_reason, attempt_count, \
                        max_attempts, ttl_seconds, last_error_class, last_error_detail, \
                        last_transport, requires_ack, ack_timeout_seconds, \
                        ack_envelope_bytes, ack_received_at, claimed_until, claimed_by \
                 FROM cirislens.edge_outbound_queue \
                 WHERE body_sha256 = $1 AND status = 'awaiting_ack' \
                 LIMIT 1",
                &[&hash_vec],
            )
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("match_ack_to_outbound: {e}")))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(pg_row_to_outbound_row(row)?)),
        }
    }

    async fn mark_ack_received(
        &self,
        queue_id: &crate::outbound::QueueId,
        ack_envelope_bytes: &[u8],
    ) -> Result<(), crate::outbound::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let now = chrono::Utc::now();
        let n = client
            .execute(
                "UPDATE cirislens.edge_outbound_queue \
                 SET status = 'delivered', \
                     ack_envelope_bytes = $1, ack_received_at = $2, \
                     delivered_at = $2 \
                 WHERE queue_id = $3::uuid AND status = 'awaiting_ack'",
                &[&ack_envelope_bytes, &now, &queue_id],
            )
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("mark_ack_received: {e}")))?;
        if n == 0 {
            return Err(crate::outbound::Error::InvalidTransition(format!(
                "queue_id {queue_id} not in 'awaiting_ack'"
            )));
        }
        Ok(())
    }

    async fn sweep_ack_timeouts(&self) -> Result<i64, crate::outbound::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let now = chrono::Utc::now();
        // Walk awaiting_ack rows where the ack_timeout has expired.
        // Treat each as a transport failure (attempt_count++,
        // retry-or-abandon). Reschedule next_attempt_after to now +
        // 60s baseline; the retry policy is otherwise driven by
        // attempt_count vs max_attempts and enqueued_at vs ttl.
        let n = client.execute(
            "WITH timed_out AS (\
                SELECT queue_id, attempt_count, max_attempts, enqueued_at, ttl_seconds \
                FROM cirislens.edge_outbound_queue \
                WHERE status = 'awaiting_ack' \
                  AND transport_delivered_at + (ack_timeout_seconds || ' seconds')::interval < $1 \
                FOR UPDATE\
             ), \
             abandoned AS (\
                UPDATE cirislens.edge_outbound_queue q \
                SET status = 'abandoned', \
                    abandoned_at = $1, \
                    abandoned_reason = CASE \
                        WHEN ($1 - q.enqueued_at) > (q.ttl_seconds || ' seconds')::interval THEN 'ttl_expired' \
                        ELSE 'max_attempts' END, \
                    last_error_class = 'ack_timeout', \
                    last_error_detail = 'no ACK before ack_timeout_seconds expired' \
                FROM timed_out t \
                WHERE q.queue_id = t.queue_id \
                  AND (t.attempt_count >= t.max_attempts \
                       OR ($1 - t.enqueued_at) > (t.ttl_seconds || ' seconds')::interval) \
                RETURNING q.queue_id\
             ), \
             retried AS (\
                UPDATE cirislens.edge_outbound_queue q \
                SET status = 'pending', \
                    next_attempt_after = $1 + interval '60 seconds', \
                    last_error_class = 'ack_timeout', \
                    last_error_detail = 'no ACK before ack_timeout_seconds expired' \
                FROM timed_out t \
                WHERE q.queue_id = t.queue_id \
                  AND t.attempt_count < t.max_attempts \
                  AND ($1 - t.enqueued_at) <= (t.ttl_seconds || ' seconds')::interval \
                RETURNING q.queue_id\
             ) \
             SELECT (SELECT COUNT(*) FROM abandoned) + (SELECT COUNT(*) FROM retried)",
            &[&now],
        )
        .await
        .map_err(|e| crate::outbound::Error::Backend(format!("sweep_ack_timeouts: {e}")))?;
        Ok(n as i64)
    }

    async fn sweep_ttl_expired(&self) -> Result<i64, crate::outbound::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let now = chrono::Utc::now();
        let n = client
            .execute(
                "UPDATE cirislens.edge_outbound_queue \
                 SET status = 'abandoned', \
                     abandoned_at = $1, \
                     abandoned_reason = 'ttl_expired', \
                     claimed_until = NULL, claimed_by = NULL \
                 WHERE status NOT IN ('delivered', 'abandoned') \
                   AND ($1 - enqueued_at) > (ttl_seconds || ' seconds')::interval",
                &[&now],
            )
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("sweep_ttl_expired: {e}")))?;
        Ok(n as i64)
    }

    async fn sweep_expired_claims(&self) -> Result<i64, crate::outbound::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let now = chrono::Utc::now();
        let n = client
            .execute(
                "UPDATE cirislens.edge_outbound_queue \
                 SET status = 'pending', \
                     claimed_until = NULL, claimed_by = NULL \
                 WHERE status = 'sending' AND claimed_until < $1",
                &[&now],
            )
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("sweep_expired_claims: {e}")))?;
        Ok(n as i64)
    }

    async fn outbound_status(
        &self,
        queue_id: &crate::outbound::QueueId,
    ) -> Result<Option<crate::outbound::OutboundRow>, crate::outbound::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT queue_id::text, sender_key_id, destination_key_id, \
                        message_type, edge_schema_version, envelope_bytes, \
                        body_sha256, body_size_bytes, status, enqueued_at, \
                        next_attempt_after, last_attempt_at, transport_delivered_at, \
                        delivered_at, abandoned_at, abandoned_reason, attempt_count, \
                        max_attempts, ttl_seconds, last_error_class, last_error_detail, \
                        last_transport, requires_ack, ack_timeout_seconds, \
                        ack_envelope_bytes, ack_received_at, claimed_until, claimed_by \
                 FROM cirislens.edge_outbound_queue \
                 WHERE queue_id = $1::uuid",
                &[&queue_id],
            )
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("outbound_status: {e}")))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(pg_row_to_outbound_row(row)?)),
        }
    }

    async fn list_outbound(
        &self,
        filter: crate::outbound::OutboundFilter,
        limit: i64,
    ) -> Result<Vec<crate::outbound::OutboundRow>, crate::outbound::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        // Build the WHERE clause dynamically. Bind each filter param;
        // skip when None. Order by enqueued_at ASC so oldest pending
        // surfaces first.
        let mut sql = String::from(
            "SELECT queue_id::text, sender_key_id, destination_key_id, \
                    message_type, edge_schema_version, envelope_bytes, \
                    body_sha256, body_size_bytes, status, enqueued_at, \
                    next_attempt_after, last_attempt_at, transport_delivered_at, \
                    delivered_at, abandoned_at, abandoned_reason, attempt_count, \
                    max_attempts, ttl_seconds, last_error_class, last_error_detail, \
                    last_transport, requires_ack, ack_timeout_seconds, \
                    ack_envelope_bytes, ack_received_at, claimed_until, claimed_by \
             FROM cirislens.edge_outbound_queue WHERE 1=1",
        );
        let mut params: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
        let mut idx = 1usize;
        let status_str = filter.status.map(|s| s.as_str().to_string());
        if let Some(s) = status_str.as_ref() {
            sql.push_str(&format!(" AND status = ${idx}"));
            params.push(Box::new(s.clone()));
            idx += 1;
        }
        if let Some(ref dst) = filter.destination_key_id {
            sql.push_str(&format!(" AND destination_key_id = ${idx}"));
            params.push(Box::new(dst.clone()));
            idx += 1;
        }
        if let Some(ref src) = filter.sender_key_id {
            sql.push_str(&format!(" AND sender_key_id = ${idx}"));
            params.push(Box::new(src.clone()));
            idx += 1;
        }
        if let Some(ref mt) = filter.message_type {
            sql.push_str(&format!(" AND message_type = ${idx}"));
            params.push(Box::new(mt.clone()));
            idx += 1;
        }
        if let Some(ts) = filter.enqueued_after {
            sql.push_str(&format!(" AND enqueued_at >= ${idx}"));
            params.push(Box::new(ts));
            idx += 1;
        }
        sql.push_str(&format!(" ORDER BY enqueued_at ASC LIMIT ${idx}"));
        params.push(Box::new(limit));

        let params_refs: Vec<&(dyn ToSql + Sync)> = params
            .iter()
            .map(|b| b.as_ref() as &(dyn ToSql + Sync))
            .collect();
        let rows = client
            .query(&sql, &params_refs)
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("list_outbound: {e}")))?;
        rows.into_iter().map(pg_row_to_outbound_row).collect()
    }

    async fn cancel_outbound(
        &self,
        queue_id: &crate::outbound::QueueId,
    ) -> Result<(), crate::outbound::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let now = chrono::Utc::now();
        client
            .execute(
                "UPDATE cirislens.edge_outbound_queue \
                 SET status = 'abandoned', \
                     abandoned_at = $1, abandoned_reason = 'operator_cancel', \
                     claimed_until = NULL, claimed_by = NULL \
                 WHERE queue_id = $2::uuid AND status NOT IN ('delivered', 'abandoned')",
                &[&now, &queue_id],
            )
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("cancel_outbound: {e}")))?;
        Ok(())
    }

    async fn replay_abandoned(
        &self,
        queue_id: &crate::outbound::QueueId,
    ) -> Result<(), crate::outbound::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("pool: {e}")))?;
        let now = chrono::Utc::now();
        let n = client
            .execute(
                "UPDATE cirislens.edge_outbound_queue \
                 SET status = 'pending', \
                     attempt_count = 0, \
                     next_attempt_after = $1, \
                     abandoned_at = NULL, abandoned_reason = NULL, \
                     last_error_class = NULL, last_error_detail = NULL \
                 WHERE queue_id = $2::uuid AND status = 'abandoned'",
                &[&now, &queue_id],
            )
            .await
            .map_err(|e| crate::outbound::Error::Backend(format!("replay_abandoned: {e}")))?;
        if n == 0 {
            return Err(crate::outbound::Error::InvalidTransition(format!(
                "queue_id {queue_id} not in 'abandoned'"
            )));
        }
        Ok(())
    }
}

/// v0.4.0 (CIRISPersist#16) — Convert a postgres row from
/// `cirislens.edge_outbound_queue` to OutboundRow. Used by every
/// read path (claim, status, list, match_ack).
fn pg_row_to_outbound_row(
    row: tokio_postgres::Row,
) -> Result<crate::outbound::OutboundRow, crate::outbound::Error> {
    use crate::outbound::{AbandonedReason, OutboundStatus};
    let status_str: String = row.get("status");
    let status = OutboundStatus::from_wire_str(&status_str).ok_or_else(|| {
        crate::outbound::Error::Backend(format!(
            "unknown status in edge_outbound_queue: {status_str}"
        ))
    })?;
    let abandoned_reason_str: Option<String> = row.get("abandoned_reason");
    let abandoned_reason = match abandoned_reason_str.as_deref() {
        Some(s) => Some(AbandonedReason::from_wire_str(s).ok_or_else(|| {
            crate::outbound::Error::Backend(format!("unknown abandoned_reason: {s}"))
        })?),
        None => None,
    };
    let body_sha256_vec: Vec<u8> = row.get("body_sha256");
    if body_sha256_vec.len() != 32 {
        return Err(crate::outbound::Error::Backend(format!(
            "body_sha256 wrong length: {} (expected 32)",
            body_sha256_vec.len()
        )));
    }
    let mut body_sha256 = [0u8; 32];
    body_sha256.copy_from_slice(&body_sha256_vec);

    Ok(crate::outbound::OutboundRow {
        queue_id: row.get("queue_id"),
        sender_key_id: row.get("sender_key_id"),
        destination_key_id: row.get("destination_key_id"),
        message_type: row.get("message_type"),
        edge_schema_version: row.get("edge_schema_version"),
        envelope_bytes: row.get("envelope_bytes"),
        body_sha256,
        body_size_bytes: row.get("body_size_bytes"),
        status,
        enqueued_at: row.get("enqueued_at"),
        next_attempt_after: row.get("next_attempt_after"),
        last_attempt_at: row.get("last_attempt_at"),
        transport_delivered_at: row.get("transport_delivered_at"),
        delivered_at: row.get("delivered_at"),
        abandoned_at: row.get("abandoned_at"),
        abandoned_reason,
        attempt_count: row.get("attempt_count"),
        max_attempts: row.get("max_attempts"),
        ttl_seconds: row.get("ttl_seconds"),
        last_error_class: row.get("last_error_class"),
        last_error_detail: row.get("last_error_detail"),
        last_transport: row.get("last_transport"),
        requires_ack: row.get("requires_ack"),
        ack_timeout_seconds: row.get("ack_timeout_seconds"),
        ack_envelope_bytes: row.get("ack_envelope_bytes"),
        ack_received_at: row.get("ack_received_at"),
        claimed_until: row.get("claimed_until"),
        claimed_by: row.get("claimed_by"),
    })
}

/// v0.2.1 — Decode a base64 standard-alphabet Ed25519 public key
/// (32 raw bytes) and parse to VerifyingKey. Shared between the
/// federation_keys and accord_public_keys lookup paths.
fn decode_ed25519_b64(b64: &str) -> Result<VerifyingKey, Error> {
    let bytes = BASE64
        .decode(b64)
        .map_err(|e| Error::Backend(format!("public_key_base64 decode: {e}")))?;
    if bytes.len() != 32 {
        return Err(Error::Backend(format!(
            "public_key_base64 wrong length: got {}, expected 32",
            bytes.len()
        )));
    }
    let arr: [u8; 32] = bytes.as_slice().try_into().expect("length-checked");
    VerifyingKey::from_bytes(&arr).map_err(|e| Error::Backend(format!("public_key parse: {e}")))
}

fn pg_row_to_key_record(row: tokio_postgres::Row) -> crate::federation::KeyRecord {
    let original_content_hash: Vec<u8> = row.get("original_content_hash");
    crate::federation::KeyRecord {
        key_id: row.get("key_id"),
        pubkey_ed25519_base64: row.get("pubkey_ed25519_base64"),
        pubkey_ml_dsa_65_base64: row.get("pubkey_ml_dsa_65_base64"),
        algorithm: row.get("algorithm"),
        identity_type: row.get("identity_type"),
        identity_ref: row.get("identity_ref"),
        valid_from: row.get("valid_from"),
        valid_until: row.get("valid_until"),
        registration_envelope: row.get("registration_envelope"),
        original_content_hash: hex::encode(&original_content_hash),
        scrub_signature_classical: row.get("scrub_signature_classical"),
        scrub_signature_pqc: row.get("scrub_signature_pqc"),
        scrub_key_id: row.get("scrub_key_id"),
        scrub_timestamp: row.get("scrub_timestamp"),
        pqc_completed_at: row.get("pqc_completed_at"),
        persist_row_hash: row.get("persist_row_hash"),
    }
}

fn pg_row_to_attestation(row: tokio_postgres::Row) -> crate::federation::Attestation {
    let original_content_hash: Vec<u8> = row.get("original_content_hash");
    crate::federation::Attestation {
        attestation_id: row.get("attestation_id"),
        attesting_key_id: row.get("attesting_key_id"),
        attested_key_id: row.get("attested_key_id"),
        attestation_type: row.get("attestation_type"),
        weight: row.get("weight"),
        asserted_at: row.get("asserted_at"),
        expires_at: row.get("expires_at"),
        attestation_envelope: row.get("attestation_envelope"),
        original_content_hash: hex::encode(&original_content_hash),
        scrub_signature_classical: row.get("scrub_signature_classical"),
        scrub_signature_pqc: row.get("scrub_signature_pqc"),
        scrub_key_id: row.get("scrub_key_id"),
        scrub_timestamp: row.get("scrub_timestamp"),
        pqc_completed_at: row.get("pqc_completed_at"),
        persist_row_hash: row.get("persist_row_hash"),
    }
}

fn pg_row_to_revocation(row: tokio_postgres::Row) -> crate::federation::Revocation {
    let original_content_hash: Vec<u8> = row.get("original_content_hash");
    crate::federation::Revocation {
        revocation_id: row.get("revocation_id"),
        revoked_key_id: row.get("revoked_key_id"),
        revoking_key_id: row.get("revoking_key_id"),
        reason: row.get("reason"),
        revoked_at: row.get("revoked_at"),
        effective_at: row.get("effective_at"),
        revocation_envelope: row.get("revocation_envelope"),
        original_content_hash: hex::encode(&original_content_hash),
        scrub_signature_classical: row.get("scrub_signature_classical"),
        scrub_signature_pqc: row.get("scrub_signature_pqc"),
        scrub_key_id: row.get("scrub_key_id"),
        scrub_timestamp: row.get("scrub_timestamp"),
        pqc_completed_at: row.get("pqc_completed_at"),
        persist_row_hash: row.get("persist_row_hash"),
    }
}

/// v0.3.5 (CIRISLens#8 ASK 3) — Convert a postgres row from
/// `cirislens.trace_events` to `(event_id, TraceEventRow)`. Used by
/// `Backend::fetch_trace_events_page`. Column order MUST match the
/// SELECT clause; we read by name here to make additions safer.
fn pg_row_to_event_row(row: tokio_postgres::Row) -> Result<(i64, TraceEventRow), Error> {
    use crate::schema::{ReasoningEventType, TraceLevel};
    let event_type_str: String = row.get("event_type");
    let event_type = ReasoningEventType::from_wire_str(&event_type_str).ok_or_else(|| {
        Error::Backend(format!(
            "unknown event_type in trace_events row: {event_type_str}"
        ))
    })?;
    let trace_level_str: String = row.get("trace_level");
    let trace_level = match trace_level_str.as_str() {
        "generic" => TraceLevel::Generic,
        "detailed" => TraceLevel::Detailed,
        "full_traces" => TraceLevel::FullTraces,
        other => {
            return Err(Error::Backend(format!("unknown trace_level: {other}")));
        }
    };
    let attempt_index_i32: i32 = row.get("attempt_index");
    let attempt_index = u32::try_from(attempt_index_i32).map_err(|_| {
        Error::Backend(format!(
            "attempt_index {attempt_index_i32} negative — schema CHECK should have rejected"
        ))
    })?;
    let payload_value: serde_json::Value = row.get("payload");
    let payload = match payload_value {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };

    let event_id: i64 = row.get("event_id");
    Ok((
        event_id,
        TraceEventRow {
            trace_id: row.get("trace_id"),
            thought_id: row.get("thought_id"),
            task_id: row.get("task_id"),
            step_point: row.get("step_point"),
            event_type,
            attempt_index,
            ts: row.get("ts"),
            agent_name: row.get("agent_name"),
            agent_id_hash: row.get("agent_id_hash"),
            cognitive_state: row.get("cognitive_state"),
            trace_level,
            payload,
            cost_llm_calls: row.get("cost_llm_calls"),
            cost_tokens: row.get("cost_tokens"),
            cost_usd: row.get("cost_usd"),
            signature: row.get("signature"),
            signing_key_id: row.get("signing_key_id"),
            signature_verified: row.get("signature_verified"),
            schema_version: row.get("schema_version"),
            pii_scrubbed: row.get("pii_scrubbed"),
            original_content_hash: row.get("original_content_hash"),
            scrub_signature: row.get("scrub_signature"),
            scrub_key_id: row.get("scrub_key_id"),
            scrub_timestamp: row.get("scrub_timestamp"),
            agent_role: row.get("agent_role"),
            agent_template: row.get("agent_template"),
            deployment_domain: row.get("deployment_domain"),
            deployment_type: row.get("deployment_type"),
            deployment_region: row.get("deployment_region"),
            deployment_trust_mode: row.get("deployment_trust_mode"),
        },
    ))
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

/// v0.5.0 (CIRISPersist#23 §B) — Decode a `cirislens.trace_llm_calls`
/// row into a typed [`TraceLlmCallRow`]. Mirrors `pg_row_to_event_row`
/// for the LLM-call table; reads only the columns selected by
/// `get_trace_detail`'s LLM-calls SELECT.
fn pg_row_to_llm_call_row(
    row: &tokio_postgres::Row,
) -> Result<crate::store::types::TraceLlmCallRow, crate::read::Error> {
    use crate::schema::{LlmCallStatus, ReasoningEventType};

    let parent_event_type_str: String = row.safe_get("parent_event_type")?;
    let parent_event_type =
        ReasoningEventType::from_wire_str(&parent_event_type_str).ok_or_else(|| {
            crate::read::Error::Backend(format!(
                "unknown parent_event_type in trace_llm_calls: {parent_event_type_str}"
            ))
        })?;

    let status_str: String = row.safe_get("status")?;
    let status = match status_str.as_str() {
        "ok" => LlmCallStatus::Ok,
        "timeout" => LlmCallStatus::Timeout,
        "rate_limited" => LlmCallStatus::RateLimited,
        "model_not_available" => LlmCallStatus::ModelNotAvailable,
        "instructor_retry" => LlmCallStatus::InstructorRetry,
        "other_error" => LlmCallStatus::OtherError,
        other => {
            return Err(crate::read::Error::Backend(format!(
                "unknown llm_call status: {other}"
            )))
        }
    };

    let parent_attempt_index_i32: i32 = row.safe_get("parent_attempt_index")?;
    let parent_attempt_index = u32::try_from(parent_attempt_index_i32).map_err(|_| {
        crate::read::Error::Backend(format!(
            "parent_attempt_index {parent_attempt_index_i32} negative"
        ))
    })?;
    let attempt_index_i32: i32 = row.safe_get("attempt_index")?;
    let attempt_index = u32::try_from(attempt_index_i32).map_err(|_| {
        crate::read::Error::Backend(format!("attempt_index {attempt_index_i32} negative"))
    })?;

    Ok(crate::store::types::TraceLlmCallRow {
        trace_id: row.safe_get("trace_id")?,
        thought_id: row.safe_get("thought_id")?,
        task_id: row.safe_get("task_id")?,
        parent_event_id: row.safe_get("parent_event_id")?,
        parent_event_type,
        parent_attempt_index,
        attempt_index,
        ts: row.safe_get("ts")?,
        duration_ms: row.safe_get("duration_ms")?,
        handler_name: row.safe_get("handler_name")?,
        service_name: row.safe_get("service_name")?,
        model: row.safe_get("model")?,
        base_url: row.safe_get("base_url")?,
        response_model: row.safe_get("response_model")?,
        prompt_tokens: row.safe_get("prompt_tokens")?,
        completion_tokens: row.safe_get("completion_tokens")?,
        prompt_bytes: row.safe_get("prompt_bytes")?,
        completion_bytes: row.safe_get("completion_bytes")?,
        cost_usd: row.safe_get("cost_usd")?,
        status,
        error_class: row.safe_get("error_class")?,
        attempt_count: row.safe_get("attempt_count")?,
        retry_count: row.safe_get("retry_count")?,
        prompt_hash: row.safe_get("prompt_hash")?,
        prompt: row.safe_get("prompt")?,
        response_text: row.safe_get("response_text")?,
    })
}

// ─── PgRowExt — NULL-safe row decode helper (v0.5.3, CIRISPersist#26)
//
// `tokio_postgres::Row::get::<_, T>` panics when the column is NULL
// and `T: FromSql` doesn't accept NULL (i.e. T is not `Option<_>`).
// Pre-v0.5.3 every `row.get(col)` in this file was a latent panic
// site; CIRISPersist#24 realized one (SUM-on-empty-CTE → NULL → panic
// → SIGABRT cascade across uvicorn workers).
//
// `PgRowExt::safe_get` wraps `try_get` with a typed Backend error
// mapping. Panics become `read::Error::Backend(...)` — lens HTTP 500
// instead of process abort. The error message names the column so
// future operators can triage without source-diving.
//
// Sweep scope (v0.5.3): the v0.5.0 ReadEngine impl + its decode
// helpers (pg_row_to_trace_summary, pg_row_to_llm_call_row). The
// pre-v0.5.0 sites (decompose, federation directory, outbound queue,
// derived put paths) are tracked in CIRISPersist#28 — they've shipped
// stably without a realized panic, but the v0.5.3 catch_unwind layer
// (CIRISPersist#27) catches any future regression defensively until
// the full sweep lands.

trait PgRowExt {
    /// Decode a column with typed-error propagation on failure.
    /// Replaces `Row::get(col)`'s panic-on-NULL behavior with a
    /// `read::Error::Backend` that names the column.
    fn safe_get<'a, T>(&'a self, col: &str) -> Result<T, crate::read::Error>
    where
        T: tokio_postgres::types::FromSql<'a>;
}

impl PgRowExt for tokio_postgres::Row {
    fn safe_get<'a, T>(&'a self, col: &str) -> Result<T, crate::read::Error>
    where
        T: tokio_postgres::types::FromSql<'a>,
    {
        self.try_get(col)
            .map_err(|e| crate::read::Error::Backend(format!("decode column {col}: {e}")))
    }
}

// ─── ReadEngine impl (v0.5.0, CIRISPersist#23) ─────────────────────
//
// Federation read primitives — sections A/B/F/E per the v0.5.0 batch.
// Section A (list + get) shipped; B/F/E land in follow-up commits
// before the v0.5.0 tag.
//
// JSONB-extraction strategy: every TraceSummary field that lives
// inside a per-event-type payload (DMA scores, conscience flags,
// action result, thought metadata) is extracted via PostgreSQL
// FILTER (WHERE event_type = '...') aggregation in one single-pass
// GROUP BY trace_id. Avoids N+1 round-trips and keeps the SQL
// readable. Index coverage: trace_events_dedup
// (agent_id_hash, trace_id, ...) handles the trace_id-bound queries;
// trace_events_agent_ts handles agent-filtered list pagination.

/// JSONB-extraction SELECT clause shared by [`get_trace_summary`] and
/// [`list_trace_summaries`]. The leading `MIN(trace_id)` produces the
/// trace_id column for the GROUP BY result row.
const TRACE_SUMMARY_SELECT: &str = "\
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
    BOOL_AND(signature_verified) AS signature_verified, \
    MIN(cognitive_state) AS cognitive_state, \
    \
    MAX(payload->>'thought_type') FILTER (WHERE event_type = 'THOUGHT_START') AS thought_type, \
    MAX((payload->>'thought_depth')::int) FILTER (WHERE event_type = 'THOUGHT_START') AS thought_depth, \
    \
    AVG((payload->>'csdma_plausibility_score')::float8) FILTER (WHERE event_type = 'DMA_RESULTS') AS csdma_plausibility_score, \
    AVG((payload->>'dsdma_domain_alignment')::float8) FILTER (WHERE event_type = 'DMA_RESULTS') AS dsdma_domain_alignment, \
    MAX(payload->>'dsdma_domain') FILTER (WHERE event_type = 'DMA_RESULTS') AS dsdma_domain, \
    \
    AVG((payload->>'idma_k_eff')::float8) FILTER (WHERE event_type = 'IDMA_RESULT') AS idma_k_eff, \
    AVG((payload->>'idma_correlation_risk')::float8) FILTER (WHERE event_type = 'IDMA_RESULT') AS idma_correlation_risk, \
    BOOL_OR((payload->>'idma_fragility_flag')::bool) FILTER (WHERE event_type = 'IDMA_RESULT') AS idma_fragility_flag, \
    MAX(payload->>'idma_phase') FILTER (WHERE event_type = 'IDMA_RESULT') AS idma_phase, \
    \
    BOOL_AND((payload->>'conscience_passed')::bool) FILTER (WHERE event_type = 'CONSCIENCE_RESULT') AS conscience_passed, \
    BOOL_OR((payload->>'action_was_overridden')::bool) FILTER (WHERE event_type = 'CONSCIENCE_RESULT') AS action_was_overridden, \
    BOOL_AND((payload->>'entropy_passed')::bool) FILTER (WHERE event_type = 'CONSCIENCE_RESULT') AS entropy_passed, \
    BOOL_AND((payload->>'coherence_passed')::bool) FILTER (WHERE event_type = 'CONSCIENCE_RESULT') AS coherence_passed, \
    BOOL_AND((payload->>'optimization_veto_passed')::bool) FILTER (WHERE event_type = 'CONSCIENCE_RESULT') AS optimization_veto_passed, \
    BOOL_AND((payload->>'epistemic_humility_passed')::bool) FILTER (WHERE event_type = 'CONSCIENCE_RESULT') AS epistemic_humility_passed, \
    \
    MAX(payload->>'action_executed') FILTER (WHERE event_type = 'ACTION_RESULT') AS selected_action, \
    BOOL_AND((payload->>'success')::bool) FILTER (WHERE event_type = 'ACTION_RESULT') AS action_success, \
    \
    MAX(cost_llm_calls) AS llm_calls, \
    MAX(cost_tokens) AS tokens_total, \
    MAX(cost_usd) AS cost_usd";

/// Convert a row produced by `TRACE_SUMMARY_SELECT` into a
/// [`crate::read::TraceSummary`]. Trace-level (`trace_level` column
/// is `TEXT` in V001 — converted via `serde_json::from_str` on the
/// quoted token).
///
/// v0.5.3 (CIRISPersist#26) — every column read goes through
/// `PgRowExt::safe_get` so a NULL-on-deserialize becomes a typed
/// `read::Error::Backend` (HTTP 500), not a process-aborting panic.
/// Option-typed fields tolerate NULL natively (Option<T>: FromSql
/// accepts NULL → None); non-Option fields surface the NULL as an
/// error with the offending column name.
fn pg_row_to_trace_summary(
    row: &tokio_postgres::Row,
) -> Result<crate::read::TraceSummary, crate::read::Error> {
    use crate::schema::TraceLevel;
    let trace_level_str: String = row.safe_get("trace_level")?;
    let trace_level: TraceLevel = serde_json::from_str(&format!("\"{trace_level_str}\""))
        .map_err(|e| crate::read::Error::Backend(format!("trace_level decode: {e}")))?;

    Ok(crate::read::TraceSummary {
        trace_id: row.safe_get("trace_id")?,
        thought_id: row.safe_get("thought_id")?,
        task_id: row.safe_get("task_id")?,
        agent_id_hash: row.safe_get("agent_id_hash")?,
        agent_name: row.safe_get("agent_name")?,
        agent_role: row.safe_get("agent_role")?,
        deployment_domain: row.safe_get("deployment_domain")?,
        deployment_type: row.safe_get("deployment_type")?,
        started_at: row.safe_get("started_at")?,
        completed_at: row.safe_get("completed_at")?,
        trace_level,
        schema_version: row.safe_get("schema_version")?,
        // BOOL_AND result may be NULL for an empty group; default to
        // false for the safety property.
        signature_verified: row
            .safe_get::<Option<bool>>("signature_verified")?
            .unwrap_or(false),
        cognitive_state: row.safe_get("cognitive_state")?,
        thought_type: row.safe_get("thought_type")?,
        thought_depth: row.safe_get("thought_depth")?,
        csdma_plausibility_score: row.safe_get("csdma_plausibility_score")?,
        dsdma_domain_alignment: row.safe_get("dsdma_domain_alignment")?,
        dsdma_domain: row.safe_get("dsdma_domain")?,
        idma_k_eff: row.safe_get("idma_k_eff")?,
        idma_correlation_risk: row.safe_get("idma_correlation_risk")?,
        idma_fragility_flag: row.safe_get("idma_fragility_flag")?,
        idma_phase: row.safe_get("idma_phase")?,
        conscience_passed: row.safe_get("conscience_passed")?,
        action_was_overridden: row.safe_get("action_was_overridden")?,
        entropy_passed: row.safe_get("entropy_passed")?,
        coherence_passed: row.safe_get("coherence_passed")?,
        optimization_veto_passed: row.safe_get("optimization_veto_passed")?,
        epistemic_humility_passed: row.safe_get("epistemic_humility_passed")?,
        selected_action: row.safe_get("selected_action")?,
        action_success: row.safe_get("action_success")?,
        llm_calls: row.safe_get("llm_calls")?,
        tokens_total: row.safe_get("tokens_total")?,
        cost_usd: row.safe_get("cost_usd")?,
    })
}

impl crate::read::ReadEngine for PostgresBackend {
    /// Section A: paged trace summary listing.
    ///
    /// Algorithm:
    /// 1. Apply [`TraceFilter`] WHERE clauses on `trace_events`.
    /// 2. GROUP BY trace_id with FILTER aggregation per event_type
    ///    (see [`TRACE_SUMMARY_SELECT`]).
    /// 3. ORDER BY started_at DESC, trace_id DESC.
    /// 4. Cursor: `(started_at, trace_id) < (cursor.last_started_at, cursor.last_trace_id)`
    ///    using row-tuple comparison.
    /// 5. LIMIT $limit.
    ///
    /// Index coverage: `agent_id_hash` filter hits `trace_events_dedup`
    /// (agent_id_hash leading); `agent_name` filter hits
    /// `trace_events_agent_ts`. No-filter listing scans the time
    /// hypertable in newest-first order.
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

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        // Build the WHERE clause. Bind parameters accumulate in order
        // ($1..$N); we collect typed boxes so the slice can outlive
        // the format! closure.
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        let mut where_parts: Vec<String> = Vec::new();

        if let Some(w) = filter.time_window {
            params.push(Box::new(w.since));
            where_parts.push(format!("ts >= ${}", params.len()));
            params.push(Box::new(w.until));
            where_parts.push(format!("ts < ${}", params.len()));
        }
        if let Some(h) = filter.agent_id_hash {
            params.push(Box::new(h));
            where_parts.push(format!("agent_id_hash = ${}", params.len()));
        }
        if let Some(n) = filter.agent_name {
            params.push(Box::new(n));
            where_parts.push(format!("agent_name = ${}", params.len()));
        }
        if let Some(d) = filter.deployment_domain {
            params.push(Box::new(d));
            where_parts.push(format!("deployment_domain = ${}", params.len()));
        }
        if let Some(d) = filter.deployment_type {
            params.push(Box::new(d));
            where_parts.push(format!("deployment_type = ${}", params.len()));
        }
        if let Some(level) = filter.trace_level {
            // TraceLevel serializes as snake_case lowercase; the V001
            // column is plain TEXT.
            let s = match serde_json::to_value(level) {
                Ok(serde_json::Value::String(s)) => s,
                _ => {
                    return Err(crate::read::Error::Backend(
                        "trace_level enum did not serialize to JSON string".into(),
                    ))
                }
            };
            params.push(Box::new(s));
            where_parts.push(format!("trace_level = ${}", params.len()));
        }
        if let Some(verified) = filter.signature_verified {
            params.push(Box::new(verified));
            where_parts.push(format!("signature_verified = ${}", params.len()));
        }
        if let Some(v) = filter.schema_version {
            params.push(Box::new(v));
            where_parts.push(format!("schema_version = ${}", params.len()));
        }
        if let Some(s) = filter.cognitive_state {
            params.push(Box::new(s));
            where_parts.push(format!("cognitive_state = ${}", params.len()));
        }

        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };

        // HAVING gates the cursor on the GROUPED row's started_at /
        // trace_id (cannot use WHERE since started_at = MIN(ts) is an
        // aggregate). Row-tuple comparison gives strict-less-than
        // ordering matching the ORDER BY direction.
        let having_sql = match &cursor {
            Some(_) => {
                params.push(Box::new(cursor.as_ref().unwrap().last_started_at));
                let p1 = params.len();
                params.push(Box::new(cursor.as_ref().unwrap().last_trace_id.clone()));
                let p2 = params.len();
                format!("HAVING (MIN(ts), MIN(trace_id)) < (${p1}, ${p2})")
            }
            None => String::new(),
        };

        params.push(Box::new(limit));
        let limit_p = params.len();

        let sql = format!(
            "SELECT {select} \
             FROM cirislens.trace_events \
             {where_sql} \
             GROUP BY trace_id \
             {having_sql} \
             ORDER BY started_at DESC, trace_id DESC \
             LIMIT ${limit_p}",
            select = TRACE_SUMMARY_SELECT,
        );

        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();

        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("list_trace_summaries: {e}")))?;

        let mut items: Vec<crate::read::TraceSummary> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(pg_row_to_trace_summary(row)?);
        }

        // Cursor for next page: trailing edge of this page.
        let next_cursor = if items.len() as i64 == limit {
            items
                .last()
                .map(|s| crate::read::TraceCursor::from_trailing(s.started_at, s.trace_id.clone()))
        } else {
            None
        };

        Ok(crate::read::TraceListPage { items, next_cursor })
    }

    /// Section A: single-trace summary lookup.
    async fn get_trace_summary(
        &self,
        trace_id: &str,
    ) -> Result<Option<crate::read::TraceSummary>, crate::read::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        let sql = format!(
            "SELECT {select} \
             FROM cirislens.trace_events \
             WHERE trace_id = $1 \
             GROUP BY trace_id",
            select = TRACE_SUMMARY_SELECT,
        );

        let row_opt = client
            .query_opt(&sql, &[&trace_id])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("get_trace_summary: {e}")))?;
        match row_opt {
            None => Ok(None),
            Some(row) => Ok(Some(pg_row_to_trace_summary(&row)?)),
        }
    }

    /// Section B: full trace reconstruction.
    ///
    /// Three queries, one round-trip each:
    /// 1. The summary view (reuses [`Self::get_trace_summary`]).
    /// 2. All `trace_events` rows for the trace_id, ordered by
    ///    `ts ASC` — chronological component sequence. Returned as
    ///    [`crate::read::TraceComponentRow`] (drops the per-row
    ///    signature/scrub fields — those are envelope constants
    ///    folded into [`crate::read::TraceEnvelopeRefs`]).
    /// 3. All `trace_llm_calls` rows for the trace_id, ordered by
    ///    `ts ASC`.
    ///
    /// Envelope refs are read from the first component row (per-trace
    /// constants by construction; AV-24/25 scrub envelope + signature
    /// are agent-emit-time invariants).
    async fn get_trace_detail(
        &self,
        trace_id: &str,
    ) -> Result<Option<crate::read::TraceDetail>, crate::read::Error> {
        // Compose against §A's summary path. Returns early on absent
        // trace — saves the two follow-on round-trips.
        let summary = match self.get_trace_summary(trace_id).await? {
            Some(s) => s,
            None => return Ok(None),
        };

        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        // Components: full event_type spread, chronological. Reuse
        // pg_row_to_event_row to get the typed TraceEventRow then
        // strip down to TraceComponentRow.
        let event_rows = client
            .query(
                "SELECT event_id, trace_id, thought_id, task_id, step_point, event_type, \
                        attempt_index, ts, agent_name, agent_id_hash, cognitive_state, \
                        trace_level, payload, cost_llm_calls, cost_tokens, cost_usd, \
                        signature, signing_key_id, signature_verified, schema_version, \
                        pii_scrubbed, audit_sequence_number, audit_entry_hash, \
                        audit_signature, original_content_hash, scrub_signature, \
                        scrub_key_id, scrub_timestamp, agent_role, agent_template, \
                        deployment_domain, deployment_type, deployment_region, \
                        deployment_trust_mode \
                 FROM cirislens.trace_events \
                 WHERE trace_id = $1 \
                 ORDER BY ts ASC",
                &[&trace_id],
            )
            .await
            .map_err(|e| {
                crate::read::Error::Backend(format!("get_trace_detail components: {e}"))
            })?;

        if event_rows.is_empty() {
            // Summary returned Some but components empty? Concurrent
            // delete between round-trips. Surface as None — callers retry.
            return Ok(None);
        }

        // Envelope refs: read from the first row. AV-24/25 fields
        // are per-trace constants by construction.
        let first = &event_rows[0];
        let envelope = crate::read::TraceEnvelopeRefs {
            signature: first.safe_get("signature")?,
            signature_key_id: first.safe_get("signing_key_id")?,
            original_content_hash: first.safe_get("original_content_hash")?,
            scrub_signature: first.safe_get("scrub_signature")?,
            scrub_key_id: first.safe_get("scrub_key_id")?,
            scrub_timestamp: first.safe_get("scrub_timestamp")?,
            pii_scrubbed: first
                .get::<_, Option<bool>>("pii_scrubbed")
                .unwrap_or(false),
        };

        let mut components: Vec<crate::read::TraceComponentRow> =
            Vec::with_capacity(event_rows.len());
        for row in event_rows {
            let (_event_id, full) = pg_row_to_event_row(row)
                .map_err(|e| crate::read::Error::Backend(format!("event row decode: {e}")))?;
            components.push(crate::read::TraceComponentRow {
                step_point: full.step_point,
                event_type: full.event_type,
                attempt_index: full.attempt_index,
                ts: full.ts,
                payload: full.payload,
            });
        }

        // LLM calls: chronological. Inline decode (no shared helper
        // exists — V001 trace_llm_calls is not in any other read path).
        let llm_rows = client
            .query(
                "SELECT trace_id, thought_id, task_id, parent_event_id, \
                        parent_event_type, parent_attempt_index, attempt_index, ts, \
                        duration_ms, handler_name, service_name, model, base_url, \
                        response_model, prompt_tokens, completion_tokens, prompt_bytes, \
                        completion_bytes, cost_usd, status, error_class, attempt_count, \
                        retry_count, prompt_hash, prompt, response_text \
                 FROM cirislens.trace_llm_calls \
                 WHERE trace_id = $1 \
                 ORDER BY ts ASC",
                &[&trace_id],
            )
            .await
            .map_err(|e| crate::read::Error::Backend(format!("get_trace_detail llm_calls: {e}")))?;

        let mut llm_calls: Vec<crate::store::types::TraceLlmCallRow> =
            Vec::with_capacity(llm_rows.len());
        for row in llm_rows {
            llm_calls.push(pg_row_to_llm_call_row(&row)?);
        }

        Ok(Some(crate::read::TraceDetail {
            summary,
            components,
            llm_calls,
            envelope,
        }))
    }

    /// Section F: cross-agent divergence z-scores within a deployment
    /// domain. Per-agent metric mean compared to the domain population
    /// mean+std (`STDDEV_SAMP`); rows ordered by `|z_score| DESC`
    /// (most-divergent first; lens applies its own clustering).
    ///
    /// Two SQL shapes:
    /// 1. Numerical metrics (CSDMA / DSDMA / IDMA k_eff / IDMA
    ///    correlation_risk) — per-agent AVG of the JSONB field over
    ///    the relevant event_type rows.
    /// 2. ConscienceOverrideRate — per-trace BOOL_OR collapse +
    ///    per-agent rate over distinct traces.
    async fn cross_agent_divergence(
        &self,
        deployment_domain: &str,
        window: crate::read::TimeWindow,
        metric: crate::read::DeviationMetric,
    ) -> Result<Vec<crate::read::DivergenceRow>, crate::read::Error> {
        use crate::read::DeviationMetric;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        let rows = if matches!(metric, DeviationMetric::ConscienceOverrideRate) {
            // CONSCIENCE_RESULT can fire multiple times per trace
            // (recursive retries); BOOL_OR(action_was_overridden)
            // collapses to one bool per (agent_id_hash, trace_id) so
            // the per-agent rate is over distinct traces.
            client
                .query(
                    "WITH per_trace AS ( \
                        SELECT agent_id_hash, MIN(agent_name) AS agent_name, trace_id, \
                               BOOL_OR( \
                                 (event_type = 'CONSCIENCE_RESULT' \
                                   AND (payload->>'action_was_overridden')::bool) \
                               ) AS was_overridden \
                        FROM cirislens.trace_events \
                        WHERE deployment_domain = $1 AND ts >= $2 AND ts < $3 \
                        GROUP BY agent_id_hash, trace_id \
                     ), \
                     per_agent AS ( \
                        SELECT agent_id_hash, MIN(agent_name) AS agent_name, \
                               COUNT(*) AS sample_count, \
                               (SUM(CASE WHEN was_overridden THEN 1 ELSE 0 END)::float8) \
                                 / NULLIF(COUNT(*), 0)::float8 AS rate \
                        FROM per_trace \
                        GROUP BY agent_id_hash \
                        HAVING COUNT(*) > 0 \
                     ), \
                     domain_stats AS ( \
                        SELECT AVG(rate) AS m, STDDEV_SAMP(rate) AS s FROM per_agent \
                     ) \
                     SELECT pa.agent_id_hash, pa.agent_name, \
                            CASE WHEN ds.s IS NULL OR ds.s = 0.0 THEN 0.0::float8 \
                                 ELSE (pa.rate - ds.m) / ds.s \
                            END AS z_score, \
                            pa.sample_count \
                     FROM per_agent pa CROSS JOIN domain_stats ds \
                     ORDER BY ABS( \
                        CASE WHEN ds.s IS NULL OR ds.s = 0.0 THEN 0.0::float8 \
                             ELSE (pa.rate - ds.m) / ds.s \
                        END \
                     ) DESC, pa.agent_id_hash ASC",
                    &[&deployment_domain, &window.since, &window.until],
                )
                .await
                .map_err(|e| {
                    crate::read::Error::Backend(format!("cross_agent_divergence override: {e}"))
                })?
        } else {
            let (event_type_filter, field_path): (&str, &str) = match metric {
                DeviationMetric::CsdmaPlausibility => ("DMA_RESULTS", "csdma_plausibility_score"),
                DeviationMetric::DsdmaDomainAlignment => ("DMA_RESULTS", "dsdma_domain_alignment"),
                DeviationMetric::IdmaKEff => ("IDMA_RESULT", "idma_k_eff"),
                DeviationMetric::IdmaCorrelationRisk => ("IDMA_RESULT", "idma_correlation_risk"),
                DeviationMetric::ConscienceOverrideRate => unreachable!(),
            };
            let sql = format!(
                "WITH per_agent AS ( \
                    SELECT agent_id_hash, MIN(agent_name) AS agent_name, \
                           AVG((payload->>'{field_path}')::float8) AS mean, \
                           COUNT(*) FILTER (WHERE payload ? '{field_path}') AS sample_count \
                    FROM cirislens.trace_events \
                    WHERE deployment_domain = $1 AND ts >= $2 AND ts < $3 \
                          AND event_type = '{event_type_filter}' \
                          AND payload ? '{field_path}' \
                    GROUP BY agent_id_hash \
                    HAVING COUNT(*) > 0 \
                ), \
                domain_stats AS ( \
                    SELECT AVG(mean) AS m, STDDEV_SAMP(mean) AS s FROM per_agent \
                ) \
                SELECT pa.agent_id_hash, pa.agent_name, \
                       CASE WHEN ds.s IS NULL OR ds.s = 0.0 THEN 0.0::float8 \
                            ELSE (pa.mean - ds.m) / ds.s \
                       END AS z_score, \
                       pa.sample_count \
                FROM per_agent pa CROSS JOIN domain_stats ds \
                ORDER BY ABS( \
                    CASE WHEN ds.s IS NULL OR ds.s = 0.0 THEN 0.0::float8 \
                         ELSE (pa.mean - ds.m) / ds.s \
                    END \
                ) DESC, pa.agent_id_hash ASC",
            );
            client
                .query(&sql, &[&deployment_domain, &window.since, &window.until])
                .await
                .map_err(|e| crate::read::Error::Backend(format!("cross_agent_divergence: {e}")))?
        };

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(crate::read::DivergenceRow {
                agent_id_hash: row.safe_get("agent_id_hash")?,
                agent_name: row.safe_get("agent_name")?,
                z_score: row.safe_get::<f64>("z_score")?,
                deviation_metric: metric,
                sample_count: row.safe_get::<i64>("sample_count")?,
            });
        }
        Ok(out)
    }

    /// Section F: temporal drift between two windows for one agent.
    /// Returns one row per metric where BOTH windows had samples
    /// (rows with no samples in either window are omitted —
    /// significance is undefined). Significance is a Welch-style
    /// z-score on the mean shift; lens applies its own p-value
    /// mapping.
    async fn temporal_drift(
        &self,
        agent_id_hash: &str,
        baseline: crate::read::TimeWindow,
        comparison: crate::read::TimeWindow,
    ) -> Result<Vec<crate::read::TemporalDriftRow>, crate::read::Error> {
        use crate::read::DeviationMetric;
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

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
            let sql = format!(
                "SELECT \
                   AVG(CASE WHEN ts >= $2 AND ts < $3 THEN (payload->>'{field}')::float8 END) \
                     AS base_m, \
                   VAR_SAMP(CASE WHEN ts >= $2 AND ts < $3 \
                                 THEN (payload->>'{field}')::float8 END) AS base_v, \
                   COUNT(*) FILTER (WHERE ts >= $2 AND ts < $3 AND payload ? '{field}') \
                     AS base_n, \
                   AVG(CASE WHEN ts >= $4 AND ts < $5 THEN (payload->>'{field}')::float8 END) \
                     AS comp_m, \
                   VAR_SAMP(CASE WHEN ts >= $4 AND ts < $5 \
                                 THEN (payload->>'{field}')::float8 END) AS comp_v, \
                   COUNT(*) FILTER (WHERE ts >= $4 AND ts < $5 AND payload ? '{field}') \
                     AS comp_n \
                 FROM cirislens.trace_events \
                 WHERE agent_id_hash = $1 \
                       AND event_type = '{et}' \
                       AND payload ? '{field}' \
                       AND ((ts >= $2 AND ts < $3) OR (ts >= $4 AND ts < $5))",
            );
            let row = client
                .query_one(
                    &sql,
                    &[
                        &agent_id_hash,
                        &baseline.since,
                        &baseline.until,
                        &comparison.since,
                        &comparison.until,
                    ],
                )
                .await
                .map_err(|e| crate::read::Error::Backend(format!("temporal_drift query: {e}")))?;

            let bn: i64 = row.safe_get("base_n")?;
            let cn: i64 = row.safe_get("comp_n")?;
            if bn == 0 || cn == 0 {
                continue;
            }
            let bm: f64 = row.safe_get::<Option<f64>>("base_m")?.unwrap_or(0.0);
            let cm: f64 = row.safe_get::<Option<f64>>("comp_m")?.unwrap_or(0.0);
            let bv: f64 = row.safe_get::<Option<f64>>("base_v")?.unwrap_or(0.0);
            let cv: f64 = row.safe_get::<Option<f64>>("comp_v")?.unwrap_or(0.0);

            let pooled_se = ((bv / (bn as f64).max(1.0)) + (cv / (cn as f64).max(1.0))).sqrt();
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
    }

    /// Section F: detected gaps in the agent's audit-chain sequence
    /// number timeline. Uses LAG window function over
    /// `audit_sequence_number` to find non-contiguous pairs.
    /// Audit sequence is populated only on `ACTION_RESULT` rows
    /// (per V001 schema); the query naturally limits to
    /// action-sealed traces.
    async fn hash_chain_gaps(
        &self,
        agent_id_hash: &str,
        window: crate::read::TimeWindow,
    ) -> Result<Vec<crate::read::HashChainGap>, crate::read::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        let rows = client
            .query(
                "WITH ordered AS ( \
                    SELECT audit_sequence_number AS seq, ts, \
                           LAG(audit_sequence_number) OVER w AS prev_seq, \
                           LAG(ts) OVER w AS prev_ts \
                    FROM cirislens.trace_events \
                    WHERE agent_id_hash = $1 AND ts >= $2 AND ts < $3 \
                          AND audit_sequence_number IS NOT NULL \
                    WINDOW w AS (ORDER BY audit_sequence_number) \
                 ) \
                 SELECT prev_seq, seq, prev_ts, ts \
                 FROM ordered \
                 WHERE prev_seq IS NOT NULL AND seq > prev_seq + 1 \
                 ORDER BY seq ASC",
                &[&agent_id_hash, &window.since, &window.until],
            )
            .await
            .map_err(|e| crate::read::Error::Backend(format!("hash_chain_gaps: {e}")))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(crate::read::HashChainGap {
                agent_id_hash: agent_id_hash.to_owned(),
                gap_start_seq: row.safe_get("prev_seq")?,
                gap_end_seq: row.safe_get("seq")?,
                gap_start_ts: row.safe_get("prev_ts")?,
                gap_end_ts: row.safe_get("ts")?,
            });
        }
        Ok(out)
    }

    /// Section F: per-agent conscience-override rates within a
    /// deployment domain. Per-trace `was_overridden` collapses
    /// recursive CONSCIENCE_RESULT retries via BOOL_OR before
    /// per-agent aggregation. `multiple_of_domain_avg = override_rate
    /// / domain_avg_rate`; >1.0 means the agent overrides more than
    /// peers.
    async fn conscience_override_rates(
        &self,
        deployment_domain: &str,
        window: crate::read::TimeWindow,
    ) -> Result<Vec<crate::read::OverrideRateRow>, crate::read::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        let rows = client
            .query(
                "WITH per_trace AS ( \
                    SELECT agent_id_hash, MIN(agent_name) AS agent_name, \
                           MIN(deployment_domain) AS deployment_domain, trace_id, \
                           BOOL_OR( \
                             (event_type = 'CONSCIENCE_RESULT' \
                               AND (payload->>'action_was_overridden')::bool) \
                           ) AS was_overridden \
                    FROM cirislens.trace_events \
                    WHERE deployment_domain = $1 AND ts >= $2 AND ts < $3 \
                    GROUP BY agent_id_hash, trace_id \
                 ), \
                 per_agent AS ( \
                    SELECT agent_id_hash, MIN(agent_name) AS agent_name, \
                           MIN(deployment_domain) AS deployment_domain, \
                           SUM(CASE WHEN was_overridden THEN 1 ELSE 0 END)::bigint \
                             AS override_count, \
                           COUNT(*)::bigint AS trace_count \
                    FROM per_trace \
                    GROUP BY agent_id_hash \
                 ), \
                 dom AS ( \
                    SELECT \
                       SUM(override_count)::float8 / NULLIF(SUM(trace_count), 0)::float8 \
                         AS domain_avg_rate \
                    FROM per_agent \
                 ) \
                 SELECT pa.agent_id_hash, pa.agent_name, pa.deployment_domain, \
                        pa.override_count, pa.trace_count, \
                        CASE WHEN pa.trace_count = 0 THEN 0.0::float8 \
                             ELSE pa.override_count::float8 / pa.trace_count::float8 \
                        END AS override_rate, \
                        COALESCE(d.domain_avg_rate, 0.0::float8) AS domain_avg_rate \
                 FROM per_agent pa CROSS JOIN dom d \
                 ORDER BY override_rate DESC, pa.agent_id_hash ASC",
                &[&deployment_domain, &window.since, &window.until],
            )
            .await
            .map_err(|e| crate::read::Error::Backend(format!("conscience_override_rates: {e}")))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let override_rate: f64 = row.safe_get("override_rate")?;
            let domain_avg: f64 = row.safe_get("domain_avg_rate")?;
            let multiple = if domain_avg > 0.0 {
                override_rate / domain_avg
            } else {
                0.0
            };
            out.push(crate::read::OverrideRateRow {
                agent_id_hash: row.safe_get("agent_id_hash")?,
                agent_name: row.safe_get("agent_name")?,
                deployment_domain: row.safe_get("deployment_domain")?,
                override_count: row.safe_get("override_count")?,
                trace_count: row.safe_get("trace_count")?,
                override_rate,
                domain_avg_rate: domain_avg,
                multiple_of_domain_avg: multiple,
            });
        }
        Ok(out)
    }

    /// Section E: bundled scoring factor aggregate. Replaces
    /// `api/scoring.py`'s raw SQL. Composes via 4 round-trips:
    /// 1. Per-trace collapse + window-wide counts (Factor C, I_int,
    ///    I_inc subset).
    /// 2. Audit-chain gap count (LAG window function).
    /// 3. Recovery events (Factor R) — top 50 most recent.
    /// 4. Coherence decay series (Factor S) — bucketed pass-rate.
    /// 5. Drift z-score (when baseline_window provided) — delegates
    ///    to `temporal_drift` for csdma_plausibility_score.
    ///
    /// AV-43: aggregates return computed statistics. Smallest-window
    /// callers apply k-anonymity at their layer based on `trace_count`.
    async fn aggregate_scoring_factors(
        &self,
        agent_id_hash: &str,
        window: crate::read::TimeWindow,
        baseline_window: Option<crate::read::TimeWindow>,
    ) -> Result<crate::read::ScoringFactorAggregate, crate::read::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        // v0.5.1 (CIRISPersist#24) — NULL-safety on the SUM aggregates.
        //
        // This main SELECT runs without GROUP BY, so when the input
        // `per_trace` CTE is empty (the agent has zero rows in
        // [since, until)), Postgres still produces ONE result row but
        // every SUM(CASE WHEN ...) returns NULL (per the SQL spec:
        // SUM over an empty set is NULL; COUNT is 0).
        //
        // Pre-v0.5.1 the Rust read SUM-derived columns as `i64` (not
        // `Option<i64>`), causing `Row::get::<_, i64>` to panic on
        // NULL → PyO3 propagated the panic as `Fatal Python error:
        // Aborted` → SIGABRT killed every uvicorn worker in parallel
        // from concurrent §E baseline calls. Production wedge
        // 2026-05-11 15:09–15:59 UTC. (The SIGABRT-not-PyErr
        // behavior is from `panic = "abort"` in our release profile;
        // v0.5.2 lifts that constraint per the hardening track.)
        //
        // Belt-and-braces: COALESCE at the SQL layer (data-layer fix
        // — future query edits keep the contract co-located with
        // the SUM) AND `try_get<Option<i64>>` at the Rust layer
        // (defense-in-depth — a future SQL edit that drops a
        // COALESCE surfaces as a typed backend error, lens 500, not
        // a Rust panic).
        //
        // COUNT(*) and GREATEST(...)::bigint stay un-COALESCE'd:
        // SQL semantics guarantee non-NULL on empty input (COUNT → 0,
        // GREATEST → 0 by the literal).
        let main = client
            .query_one(
                "WITH per_trace AS ( \
                    SELECT trace_id, MIN(agent_name) AS agent_name, \
                           BOOL_OR( \
                             event_type = 'CONSCIENCE_RESULT' \
                              AND (payload->>'action_was_overridden')::bool \
                           ) AS was_overridden, \
                           BOOL_OR( \
                             event_type = 'CONSCIENCE_RESULT' \
                              AND (payload->>'conscience_passed')::bool = false \
                           ) AS conscience_failed, \
                           BOOL_OR( \
                             event_type = 'ACTION_RESULT' \
                              AND (payload->>'success')::bool = true \
                           ) AS action_succeeded, \
                           BOOL_OR(audit_sequence_number IS NOT NULL) AS has_audit_seq, \
                           BOOL_OR(audit_signature IS NOT NULL) AS has_audit_sig \
                    FROM cirislens.trace_events \
                    WHERE agent_id_hash = $1 AND ts >= $2 AND ts < $3 \
                    GROUP BY trace_id \
                 ) \
                 SELECT \
                    COUNT(*)::bigint AS trace_count, \
                    GREATEST(COUNT(DISTINCT agent_name) - 1, 0)::bigint AS identity_changes, \
                    COALESCE(SUM(CASE WHEN was_overridden THEN 1 ELSE 0 END), 0)::bigint \
                      AS conscience_overrides, \
                    COALESCE(SUM(CASE WHEN has_audit_seq THEN 1 ELSE 0 END), 0)::bigint \
                      AS audit_chain_total, \
                    COALESCE(SUM(CASE WHEN has_audit_sig THEN 1 ELSE 0 END), 0)::bigint \
                      AS audit_signed_total, \
                    COALESCE( \
                      SUM(CASE WHEN conscience_failed AND action_succeeded THEN 1 ELSE 0 END), \
                      0 \
                    )::bigint AS unsafe_action_count \
                 FROM per_trace",
                &[&agent_id_hash, &window.since, &window.until],
            )
            .await
            .map_err(|e| {
                crate::read::Error::Backend(format!("aggregate_scoring_factors main: {e}"))
            })?;

        let trace_count: i64 = main.safe_get("trace_count")?;
        let identity_changes: i64 = main.safe_get("identity_changes")?;
        // Defense-in-depth on the COALESCE'd columns: `try_get<Option<i64>>`
        // so a future SQL edit that drops a COALESCE surfaces as a
        // typed Backend error instead of a Rust panic.
        let conscience_overrides: i64 = main
            .try_get::<_, Option<i64>>("conscience_overrides")
            .map_err(|e| crate::read::Error::Backend(format!("conscience_overrides decode: {e}")))?
            .unwrap_or(0);
        let audit_chain_total: i64 = main
            .try_get::<_, Option<i64>>("audit_chain_total")
            .map_err(|e| crate::read::Error::Backend(format!("audit_chain_total decode: {e}")))?
            .unwrap_or(0);
        let audit_signed_total: i64 = main
            .try_get::<_, Option<i64>>("audit_signed_total")
            .map_err(|e| crate::read::Error::Backend(format!("audit_signed_total decode: {e}")))?
            .unwrap_or(0);
        let unsafe_action_count: i64 = main
            .try_get::<_, Option<i64>>("unsafe_action_count")
            .map_err(|e| crate::read::Error::Backend(format!("unsafe_action_count decode: {e}")))?
            .unwrap_or(0);
        let unsafe_action_rate = if trace_count > 0 {
            unsafe_action_count as f64 / trace_count as f64
        } else {
            0.0
        };

        // Audit-chain gaps via LAG window — cheap, single round-trip.
        let gaps_row = client
            .query_one(
                "WITH ordered AS ( \
                    SELECT audit_sequence_number AS seq, \
                           LAG(audit_sequence_number) OVER w AS prev_seq \
                    FROM cirislens.trace_events \
                    WHERE agent_id_hash = $1 AND ts >= $2 AND ts < $3 \
                          AND audit_sequence_number IS NOT NULL \
                    WINDOW w AS (ORDER BY audit_sequence_number) \
                 ) \
                 SELECT COUNT(*)::bigint AS gap_count \
                 FROM ordered \
                 WHERE prev_seq IS NOT NULL AND seq > prev_seq + 1",
                &[&agent_id_hash, &window.since, &window.until],
            )
            .await
            .map_err(|e| crate::read::Error::Backend(format!("audit_chain_gaps count: {e}")))?;
        let audit_chain_gaps: i64 = gaps_row.safe_get("gap_count")?;

        // Recovery events: top 50 most-recent override → next-pass pairs.
        let recovery_rows = client
            .query(
                "WITH per_trace AS ( \
                    SELECT trace_id, MIN(ts) AS started_at, MAX(ts) AS completed_at, \
                           BOOL_OR( \
                             event_type = 'CONSCIENCE_RESULT' \
                              AND (payload->>'action_was_overridden')::bool \
                           ) AS was_overridden, \
                           BOOL_AND( \
                             CASE WHEN event_type = 'CONSCIENCE_RESULT' \
                                  THEN (payload->>'coherence_passed')::bool \
                                  ELSE TRUE END \
                           ) AS coherence_passed \
                    FROM cirislens.trace_events \
                    WHERE agent_id_hash = $1 AND ts >= $2 AND ts < $3 \
                    GROUP BY trace_id \
                 ), \
                 ordered AS ( \
                    SELECT trace_id, started_at, completed_at, was_overridden, \
                           LEAD(trace_id) OVER w AS next_trace_id, \
                           LEAD(started_at) OVER w AS next_started_at, \
                           LEAD(coherence_passed) OVER w AS next_coherence_passed \
                    FROM per_trace \
                    WINDOW w AS (ORDER BY started_at) \
                 ) \
                 SELECT trace_id AS override_trace_id, completed_at AS override_at, \
                        next_trace_id AS recovery_trace_id, \
                        next_started_at AS recovery_at, \
                        EXTRACT(EPOCH FROM (next_started_at - completed_at))::float8 \
                          AS recovery_latency_seconds \
                 FROM ordered \
                 WHERE was_overridden = TRUE \
                       AND next_trace_id IS NOT NULL \
                       AND next_coherence_passed = TRUE \
                 ORDER BY override_at DESC \
                 LIMIT 50",
                &[&agent_id_hash, &window.since, &window.until],
            )
            .await
            .map_err(|e| crate::read::Error::Backend(format!("recovery_events: {e}")))?;

        let mut recovery_events: Vec<crate::read::RecoveryEvent> =
            Vec::with_capacity(recovery_rows.len());
        for row in recovery_rows {
            recovery_events.push(crate::read::RecoveryEvent {
                override_trace_id: row.safe_get("override_trace_id")?,
                override_at: row.safe_get("override_at")?,
                recovery_trace_id: row.safe_get("recovery_trace_id")?,
                recovery_at: row.safe_get("recovery_at")?,
                recovery_latency_seconds: row.safe_get("recovery_latency_seconds")?,
            });
        }

        // Coherence decay series: bucket the window into ~24 points
        // (or 1-minute buckets for sub-hour windows).
        let window_secs = (window.until - window.since).num_seconds().max(1);
        let bucket_secs = (window_secs / 24).max(60);
        let decay_rows = client
            .query(
                "WITH per_trace AS ( \
                    SELECT trace_id, MIN(ts) AS started_at, \
                           BOOL_AND( \
                             CASE WHEN event_type = 'CONSCIENCE_RESULT' \
                                  THEN (payload->>'coherence_passed')::bool \
                                  ELSE TRUE END \
                           ) AS coherence_passed \
                    FROM cirislens.trace_events \
                    WHERE agent_id_hash = $1 AND ts >= $2 AND ts < $3 \
                    GROUP BY trace_id \
                 ) \
                 SELECT \
                    to_timestamp( \
                        (EXTRACT(EPOCH FROM started_at)::bigint / $4::bigint) * $4::bigint \
                    ) AS bucket_at, \
                    COUNT(*)::bigint AS trace_count, \
                    SUM(CASE WHEN coherence_passed THEN 1 ELSE 0 END)::bigint \
                      AS coherence_passed_count \
                 FROM per_trace \
                 GROUP BY bucket_at \
                 ORDER BY bucket_at ASC",
                &[&agent_id_hash, &window.since, &window.until, &bucket_secs],
            )
            .await
            .map_err(|e| crate::read::Error::Backend(format!("coherence_decay: {e}")))?;

        let mut coherence_decay_series: Vec<crate::read::CoherencePoint> =
            Vec::with_capacity(decay_rows.len());
        for row in decay_rows {
            let tc: i64 = row.safe_get("trace_count")?;
            let pc: i64 = row.safe_get("coherence_passed_count")?;
            let pass_rate = if tc > 0 { pc as f64 / tc as f64 } else { 0.0 };
            coherence_decay_series.push(crate::read::CoherencePoint {
                at: row.safe_get("bucket_at")?,
                coherence_passed_count: pc,
                trace_count: tc,
                coherence_pass_rate: pass_rate,
            });
        }

        // Drift z-score: when baseline_window supplied, surface the
        // CSDMA significance from temporal_drift. Other metrics' drift
        // is in temporal_drift's own primitive surface.
        let drift_z_score = if let Some(base) = baseline_window {
            let drift_rows = self.temporal_drift(agent_id_hash, base, window).await?;
            drift_rows
                .iter()
                .find(|r| r.deviation_metric == crate::read::DeviationMetric::CsdmaPlausibility)
                .map(|r| r.significance)
        } else {
            None
        };

        // Calibration error: persist's wire format doesn't carry
        // epistemic_certainty yet. Placeholder None for v0.5.0; wire
        // up when the field flows through.
        let calibration_error: Option<f64> = None;

        Ok(crate::read::ScoringFactorAggregate {
            agent_id_hash: agent_id_hash.to_owned(),
            window,
            trace_count,
            identity_changes,
            conscience_overrides,
            audit_chain_total,
            audit_chain_gaps,
            audit_signed_total,
            recovery_events,
            drift_z_score,
            calibration_error,
            unsafe_action_rate,
            coherence_decay_series,
        })
    }

    /// Section E: batch variant — fleet-wide score sweep. Loops over
    /// agents calling the single-agent path. Future optimization
    /// (single-query batched aggregation) is a v0.5.x follow-up;
    /// initial impl prioritizes correctness over round-trip
    /// reduction (lens-side batched calls today are <100 agents).
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

    /// Section E granular: count distinct trace_id matching a filter.
    async fn count_traces(
        &self,
        filter: crate::read::TraceFilter,
    ) -> Result<i64, crate::read::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;
        let (where_sql, params) = build_filter_where(&filter)?;
        let sql = format!(
            "SELECT COUNT(DISTINCT trace_id)::bigint AS n \
             FROM cirislens.trace_events {where_sql}",
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let row = client
            .query_one(&sql, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("count_traces: {e}")))?;
        Ok(row.get::<_, i64>("n"))
    }

    /// Section E granular: count traces where conscience overrode the
    /// action. BOOL_OR per-trace dedupes recursive CONSCIENCE_RESULT
    /// retries.
    async fn count_overrides(
        &self,
        filter: crate::read::TraceFilter,
    ) -> Result<i64, crate::read::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;
        let (where_sql, params) = build_filter_where(&filter)?;
        let sql = format!(
            "SELECT COUNT(*)::bigint AS n FROM ( \
                SELECT trace_id \
                FROM cirislens.trace_events \
                {where_sql} \
                GROUP BY trace_id \
                HAVING BOOL_OR( \
                    event_type = 'CONSCIENCE_RESULT' \
                     AND (payload->>'action_was_overridden')::bool \
                ) \
             ) sub",
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let row = client
            .query_one(&sql, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("count_overrides: {e}")))?;
        Ok(row.get::<_, i64>("n"))
    }

    /// Section E granular: count agent_name changes (the meaningful
    /// sense of "identity change" — agent_id_hash IS the identity
    /// fingerprint by construction; renames within a single hash are
    /// what's surfaced).
    async fn count_identity_changes(
        &self,
        filter: crate::read::TraceFilter,
    ) -> Result<i64, crate::read::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;
        let (where_sql, params) = build_filter_where(&filter)?;
        let sql = format!(
            "SELECT GREATEST(COUNT(DISTINCT agent_name) - 1, 0)::bigint AS n \
             FROM cirislens.trace_events {where_sql}",
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let row = client
            .query_one(&sql, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("count_identity_changes: {e}")))?;
        Ok(row.get::<_, i64>("n"))
    }

    /// Section E granular: audit-chain aggregate. Total signed audit
    /// entries + detected sequence-number gaps. Gap count is meaningful
    /// only when filter narrows to one agent (cross-agent sequences
    /// interleave); when filter doesn't pin agent_id_hash, gap_count
    /// returns 0 with a documented limitation.
    async fn aggregate_audit_chain(
        &self,
        filter: crate::read::TraceFilter,
    ) -> Result<crate::read::AuditChainAggregate, crate::read::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;
        let (where_sql, params) = build_filter_where(&filter)?;
        let totals_sql = format!(
            "SELECT \
                COUNT(*) FILTER (WHERE audit_sequence_number IS NOT NULL)::bigint \
                  AS audit_total, \
                COUNT(*) FILTER (WHERE audit_signature IS NOT NULL)::bigint \
                  AS audit_signed, \
                COUNT(*) FILTER (WHERE audit_entry_hash IS NOT NULL)::bigint \
                  AS audit_hashed \
             FROM cirislens.trace_events {where_sql}",
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let row = client
            .query_one(&totals_sql, &params_ref[..])
            .await
            .map_err(|e| {
                crate::read::Error::Backend(format!("aggregate_audit_chain totals: {e}"))
            })?;
        let audit_total: i64 = row.safe_get("audit_total")?;
        let audit_signed: i64 = row.safe_get("audit_signed")?;
        let audit_hashed: i64 = row.safe_get("audit_hashed")?;

        let gap_count = if filter.agent_id_hash.is_some() {
            let gaps_sql = format!(
                "WITH ordered AS ( \
                    SELECT audit_sequence_number AS seq, \
                           LAG(audit_sequence_number) OVER w AS prev_seq \
                    FROM cirislens.trace_events \
                    {where_sql} AND audit_sequence_number IS NOT NULL \
                    WINDOW w AS (ORDER BY audit_sequence_number) \
                 ) \
                 SELECT COUNT(*)::bigint AS gap_count \
                 FROM ordered \
                 WHERE prev_seq IS NOT NULL AND seq > prev_seq + 1",
            );
            let g_row = client
                .query_one(&gaps_sql, &params_ref[..])
                .await
                .map_err(|e| {
                    crate::read::Error::Backend(format!("aggregate_audit_chain gaps: {e}"))
                })?;
            g_row.get::<_, i64>("gap_count")
        } else {
            0
        };

        Ok(crate::read::AuditChainAggregate {
            audit_total,
            audit_signed,
            audit_hashed,
            gap_count,
        })
    }
}

/// v0.5.0 §E helper — build a parameterized WHERE clause from a
/// [`crate::read::TraceFilter`]. Returns the SQL fragment (starts
/// with "WHERE " when non-empty, empty string when no filters set)
/// and the boxed param list.
///
/// Used by the granular `count_*` and `aggregate_audit_chain`
/// primitives. Section A's `list_trace_summaries` builds its own
/// inline because it composes WHERE + HAVING (cursor) + ORDER BY +
/// LIMIT in one place.
fn build_filter_where(
    filter: &crate::read::TraceFilter,
) -> Result<
    (
        String,
        Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>>,
    ),
    crate::read::Error,
> {
    let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
    let mut where_parts: Vec<String> = Vec::new();

    if let Some(w) = filter.time_window {
        params.push(Box::new(w.since));
        where_parts.push(format!("ts >= ${}", params.len()));
        params.push(Box::new(w.until));
        where_parts.push(format!("ts < ${}", params.len()));
    }
    if let Some(h) = &filter.agent_id_hash {
        params.push(Box::new(h.clone()));
        where_parts.push(format!("agent_id_hash = ${}", params.len()));
    }
    if let Some(n) = &filter.agent_name {
        params.push(Box::new(n.clone()));
        where_parts.push(format!("agent_name = ${}", params.len()));
    }
    if let Some(d) = &filter.deployment_domain {
        params.push(Box::new(d.clone()));
        where_parts.push(format!("deployment_domain = ${}", params.len()));
    }
    if let Some(d) = &filter.deployment_type {
        params.push(Box::new(d.clone()));
        where_parts.push(format!("deployment_type = ${}", params.len()));
    }
    if let Some(level) = filter.trace_level {
        let s = match serde_json::to_value(level) {
            Ok(serde_json::Value::String(s)) => s,
            _ => {
                return Err(crate::read::Error::Backend(
                    "trace_level enum did not serialize to JSON string".into(),
                ))
            }
        };
        params.push(Box::new(s));
        where_parts.push(format!("trace_level = ${}", params.len()));
    }
    if let Some(verified) = filter.signature_verified {
        params.push(Box::new(verified));
        where_parts.push(format!("signature_verified = ${}", params.len()));
    }
    if let Some(v) = &filter.schema_version {
        params.push(Box::new(v.clone()));
        where_parts.push(format!("schema_version = ${}", params.len()));
    }
    if let Some(s) = &filter.cognitive_state {
        params.push(Box::new(s.clone()));
        where_parts.push(format!("cognitive_state = ${}", params.len()));
    }

    let where_sql = if where_parts.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_parts.join(" AND "))
    };
    Ok((where_sql, params))
}

// ─── DerivedSchema impl (v0.4.3, CIRISPersist#18) ──────────────────
//
// CRUD over cirislens_derived.{detection_events, calibration_bundles}.
// Caller (Engine PyO3 surface) MUST verify hybrid signatures via
// verify_hybrid_via_directory under HybridPolicy::Strict before
// calling these put paths — this trait impl is storage-only.

impl crate::derived::DerivedSchema for PostgresBackend {
    async fn put_detection_event(
        &self,
        event: crate::derived::DetectionEvent,
    ) -> Result<(), crate::derived::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::derived::Error::Backend(e.to_string()))?;

        // Validate fixed-length signature shapes early so we surface a
        // typed InvalidArgument rather than letting the DB CHECK fire
        // as a backend SQL error string.
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

        // Idempotent on detection_id collision; raise Conflict on
        // collision-with-different-canonical_bytes.
        let result = client
            .execute(
                "INSERT INTO cirislens_derived.detection_events (\
                    detection_id, trace_id, body_sha256, detector, severity, \
                    cohort_cell, conformity_variant, conformity_payload, \
                    lens_core_version, ratchet_calibration_version, \
                    canonical_bytes, ed25519_sig, ml_dsa_65_sig, signing_key_id, ts\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
                 ON CONFLICT (detection_id) DO NOTHING",
                &[
                    &event.detection_id,
                    &event.trace_id,
                    &event.body_sha256,
                    &event.detector,
                    &event.severity.as_db_str(),
                    &event.cohort_cell,
                    &event.conformity_variant.as_db_str(),
                    &event.conformity_payload,
                    &event.lens_core_version,
                    &event.ratchet_calibration_version,
                    &event.canonical_bytes,
                    &event.ed25519_sig,
                    &event.ml_dsa_65_sig,
                    &event.signing_key_id,
                    &event.ts,
                ],
            )
            .await
            .map_err(|e| crate::derived::Error::Backend(format!("insert detection_events: {e}")))?;

        if result == 0 {
            let existing: Option<Vec<u8>> = client
                .query_opt(
                    "SELECT canonical_bytes FROM cirislens_derived.detection_events \
                     WHERE detection_id = $1",
                    &[&event.detection_id],
                )
                .await
                .map_err(|e| crate::derived::Error::Backend(format!("conflict check: {e}")))?
                .map(|r| r.get(0));
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
    }

    async fn get_detection_events(
        &self,
        filter: crate::derived::EventFilter,
    ) -> Result<Vec<crate::derived::DetectionEvent>, crate::derived::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::derived::Error::Backend(e.to_string()))?;

        // Build the query with conditional filters. We collect
        // boxed-ToSql-trait-object refs into a Vec and pass as
        // a slice — same pattern other typed-filter paths use.
        // Ordering: ts DESC for operator-newest-first triage.
        let mut query = String::from(
            "SELECT detection_id, trace_id, body_sha256, detector, severity, \
                cohort_cell, conformity_variant, conformity_payload, \
                lens_core_version, ratchet_calibration_version, \
                canonical_bytes, ed25519_sig, ml_dsa_65_sig, signing_key_id, ts \
             FROM cirislens_derived.detection_events WHERE 1 = 1",
        );
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(t) = filter.trace_id {
            params.push(Box::new(t));
            query.push_str(&format!(" AND trace_id = ${}", params.len()));
        }
        if let Some(d) = filter.detector {
            params.push(Box::new(d));
            query.push_str(&format!(" AND detector = ${}", params.len()));
        }
        if let Some(s) = filter.since {
            params.push(Box::new(s));
            query.push_str(&format!(" AND ts >= ${}", params.len()));
        }
        query.push_str(" ORDER BY ts DESC LIMIT 1000");

        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&query, &params_ref[..])
            .await
            .map_err(|e| crate::derived::Error::Backend(format!("select detection_events: {e}")))?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let severity_db: String = r.get(4);
            let conformity_db: String = r.get(6);
            out.push(crate::derived::DetectionEvent {
                detection_id: r.get(0),
                trace_id: r.get(1),
                body_sha256: r.get(2),
                detector: r.get(3),
                severity: crate::derived::DetectionSeverity::from_db_str(&severity_db).ok_or_else(
                    || {
                        crate::derived::Error::Backend(format!(
                            "unknown severity in DB: {severity_db}"
                        ))
                    },
                )?,
                cohort_cell: r.get(5),
                conformity_variant: crate::derived::ConformityVariant::from_db_str(&conformity_db)
                    .ok_or_else(|| {
                        crate::derived::Error::Backend(format!(
                            "unknown conformity_variant in DB: {conformity_db}"
                        ))
                    })?,
                conformity_payload: r.get(7),
                lens_core_version: r.get(8),
                ratchet_calibration_version: r.get(9),
                canonical_bytes: r.get(10),
                ed25519_sig: r.get(11),
                ml_dsa_65_sig: r.get(12),
                signing_key_id: r.get(13),
                ts: r.get(14),
            });
        }
        Ok(out)
    }

    async fn put_calibration_bundle(
        &self,
        bundle: crate::derived::CalibrationBundle,
    ) -> Result<(), crate::derived::Error> {
        let mut client = self
            .get_client()
            .await
            .map_err(|e| crate::derived::Error::Backend(e.to_string()))?;

        // Same fixed-length signature shape gates as detection events.
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

        // Atomic flip: clear previous current row + insert new row in
        // a single transaction. The partial-unique index
        // calibration_bundles_one_current makes the invariant
        // DB-enforced — this transaction makes the transition
        // race-free.
        let tx = client
            .transaction()
            .await
            .map_err(|e| crate::derived::Error::Backend(format!("begin tx: {e}")))?;

        if bundle.is_current {
            tx.execute(
                "UPDATE cirislens_derived.calibration_bundles \
                 SET is_current = FALSE WHERE is_current = TRUE",
                &[],
            )
            .await
            .map_err(|e| crate::derived::Error::Backend(format!("clear prior current: {e}")))?;
        }

        let result = tx
            .execute(
                "INSERT INTO cirislens_derived.calibration_bundles (\
                    ratchet_calibration_version, projection_version, calibrated_at, \
                    calibration_corpus_sha256, calibration_corpus_n, sample_size_gate, \
                    manifold_threshold_global, projection_metadata, cohort_centroids, \
                    is_current, canonical_bytes, ed25519_sig, ml_dsa_65_sig, \
                    signing_key_id, inserted_at\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
                 ON CONFLICT (ratchet_calibration_version) DO NOTHING",
                &[
                    &bundle.ratchet_calibration_version,
                    &bundle.projection_version,
                    &bundle.calibrated_at,
                    &bundle.calibration_corpus_sha256,
                    &bundle.calibration_corpus_n,
                    &bundle.sample_size_gate,
                    &bundle.manifold_threshold_global,
                    &bundle.projection_metadata,
                    &bundle.cohort_centroids,
                    &bundle.is_current,
                    &bundle.canonical_bytes,
                    &bundle.ed25519_sig,
                    &bundle.ml_dsa_65_sig,
                    &bundle.signing_key_id,
                    &bundle.inserted_at,
                ],
            )
            .await
            .map_err(|e| {
                crate::derived::Error::Backend(format!("insert calibration_bundles: {e}"))
            })?;

        if result == 0 {
            // ON CONFLICT triggered — check if canonical_bytes match.
            let existing: Option<Vec<u8>> = tx
                .query_opt(
                    "SELECT canonical_bytes FROM cirislens_derived.calibration_bundles \
                     WHERE ratchet_calibration_version = $1",
                    &[&bundle.ratchet_calibration_version],
                )
                .await
                .map_err(|e| crate::derived::Error::Backend(format!("conflict check: {e}")))?
                .map(|r| r.get(0));
            if let Some(existing_bytes) = existing {
                if existing_bytes != bundle.canonical_bytes {
                    return Err(crate::derived::Error::Conflict(format!(
                        "ratchet_calibration_version {} already exists with different canonical_bytes",
                        bundle.ratchet_calibration_version
                    )));
                }
            }
        }

        tx.commit()
            .await
            .map_err(|e| crate::derived::Error::Backend(format!("commit tx: {e}")))?;
        Ok(())
    }

    async fn get_current_calibration_bundle(
        &self,
    ) -> Result<Option<crate::derived::CalibrationBundle>, crate::derived::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::derived::Error::Backend(e.to_string()))?;
        let row_opt = client
            .query_opt(
                "SELECT ratchet_calibration_version, projection_version, calibrated_at, \
                    calibration_corpus_sha256, calibration_corpus_n, sample_size_gate, \
                    manifold_threshold_global, projection_metadata, cohort_centroids, \
                    is_current, canonical_bytes, ed25519_sig, ml_dsa_65_sig, \
                    signing_key_id, inserted_at \
                 FROM cirislens_derived.calibration_bundles \
                 WHERE is_current = TRUE",
                &[],
            )
            .await
            .map_err(|e| crate::derived::Error::Backend(format!("select current bundle: {e}")))?;
        Ok(row_opt.map(row_to_calibration_bundle))
    }

    async fn get_calibration_bundle_by_version(
        &self,
        version: i32,
    ) -> Result<Option<crate::derived::CalibrationBundle>, crate::derived::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::derived::Error::Backend(e.to_string()))?;
        let row_opt = client
            .query_opt(
                "SELECT ratchet_calibration_version, projection_version, calibrated_at, \
                    calibration_corpus_sha256, calibration_corpus_n, sample_size_gate, \
                    manifold_threshold_global, projection_metadata, cohort_centroids, \
                    is_current, canonical_bytes, ed25519_sig, ml_dsa_65_sig, \
                    signing_key_id, inserted_at \
                 FROM cirislens_derived.calibration_bundles \
                 WHERE ratchet_calibration_version = $1",
                &[&version],
            )
            .await
            .map_err(|e| {
                crate::derived::Error::Backend(format!("select bundle by version: {e}"))
            })?;
        Ok(row_opt.map(row_to_calibration_bundle))
    }
}

fn row_to_calibration_bundle(r: tokio_postgres::Row) -> crate::derived::CalibrationBundle {
    crate::derived::CalibrationBundle {
        ratchet_calibration_version: r.get(0),
        projection_version: r.get(1),
        calibrated_at: r.get(2),
        calibration_corpus_sha256: r.get(3),
        calibration_corpus_n: r.get(4),
        sample_size_gate: r.get(5),
        manifold_threshold_global: r.get(6),
        projection_metadata: r.get(7),
        cohort_centroids: r.get(8),
        is_current: r.get(9),
        canonical_bytes: r.get(10),
        ed25519_sig: r.get(11),
        ml_dsa_65_sig: r.get(12),
        signing_key_id: r.get(13),
        inserted_at: r.get(14),
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
    use chrono::TimeZone;
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
            agent_role: None,
            agent_template: None,
            deployment_domain: None,
            deployment_type: None,
            deployment_region: None,
            deployment_trust_mode: None,
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

    // ─── Lens-derived schemas (v0.4.3, CIRISPersist#18) ────────────

    /// Smoke: detection event round-trip through put + get.
    /// Note: this test calls the storage trait directly (post-verify
    /// surface). The Engine PyO3 method enforces hybrid verify; this
    /// test does NOT exercise that — see hybrid_verify_strict_*
    /// tests in src/verify/hybrid.rs for the verify enforcement.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn detection_event_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::derived::{
            ConformityVariant, DerivedSchema, DetectionEvent, DetectionSeverity, EventFilter,
        };
        let event = DetectionEvent {
            detection_id: uuid::Uuid::new_v4(),
            trace_id: format!("trace-derived-{}", uuid_like()),
            body_sha256: vec![0xAB; 32],
            detector: "manifold_conformity_outlier".into(),
            severity: DetectionSeverity::Warning,
            cohort_cell: serde_json::json!({
                "agent_role": "ally",
                "agent_template": "ally-v3-default",
                "deployment_domain": "moderation",
                "deployment_type": "production",
                "deployment_region": "US",
                "deployment_trust_mode": "federated_peer"
            }),
            conformity_variant: ConformityVariant::Numeric,
            conformity_payload: serde_json::json!({"score": 3.7}),
            lens_core_version: "0.1.0".into(),
            ratchet_calibration_version: 1,
            canonical_bytes: b"{\"detection_id\":\"x\"}".to_vec(),
            ed25519_sig: vec![0x01; 64],
            ml_dsa_65_sig: vec![0x02; 3309],
            signing_key_id: "lens-core-test:1".into(),
            ts: chrono::Utc::now(),
        };

        backend.put_detection_event(event.clone()).await.unwrap();

        // Idempotent on detection_id collision with same content.
        backend.put_detection_event(event.clone()).await.unwrap();

        // Read back via filter on trace_id.
        let filter = EventFilter {
            trace_id: Some(event.trace_id.clone()),
            ..Default::default()
        };
        let rows = backend.get_detection_events(filter).await.unwrap();
        assert_eq!(rows.len(), 1);
        let got = &rows[0];
        assert_eq!(got.detection_id, event.detection_id);
        assert_eq!(got.detector, event.detector);
        assert_eq!(got.severity, DetectionSeverity::Warning);
        assert_eq!(got.conformity_variant, ConformityVariant::Numeric);
    }

    /// Conflict on same detection_id with DIFFERENT canonical_bytes
    /// surfaces as derived::Error::Conflict.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn detection_event_conflict_on_different_content() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::derived::{ConformityVariant, DerivedSchema, DetectionEvent, DetectionSeverity};
        let did = uuid::Uuid::new_v4();
        let event_a = DetectionEvent {
            detection_id: did,
            trace_id: format!("trace-conflict-{}", uuid_like()),
            body_sha256: vec![0xAB; 32],
            detector: "test".into(),
            severity: DetectionSeverity::Info,
            cohort_cell: serde_json::json!({}),
            conformity_variant: ConformityVariant::Indeterminate,
            conformity_payload: serde_json::json!({"reason": "missing"}),
            lens_core_version: "0.1.0".into(),
            ratchet_calibration_version: 1,
            canonical_bytes: b"original".to_vec(),
            ed25519_sig: vec![0x01; 64],
            ml_dsa_65_sig: vec![0x02; 3309],
            signing_key_id: "test:1".into(),
            ts: chrono::Utc::now(),
        };
        backend.put_detection_event(event_a.clone()).await.unwrap();

        let event_b = DetectionEvent {
            canonical_bytes: b"DIFFERENT".to_vec(),
            ..event_a
        };
        let err = backend.put_detection_event(event_b).await.unwrap_err();
        assert!(matches!(err, crate::derived::Error::Conflict(_)));
    }

    /// Calibration bundle put → get_current → atomic flip on next put.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn calibration_bundle_atomic_current_flip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::derived::{CalibrationBundle, DerivedSchema};

        // Use timestamp-based versions so re-runs don't collide.
        let v1 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i32;
        let v2 = v1 + 1;

        let bundle_v1 = CalibrationBundle {
            ratchet_calibration_version: v1,
            projection_version: "crc-v1".into(),
            calibrated_at: chrono::Utc::now(),
            calibration_corpus_sha256: "abc".into(),
            calibration_corpus_n: 6465,
            sample_size_gate: 30,
            manifold_threshold_global: 3.5,
            projection_metadata: serde_json::json!({}),
            cohort_centroids: serde_json::json!([]),
            is_current: true,
            canonical_bytes: format!("v1-{v1}").into_bytes(),
            ed25519_sig: vec![0x01; 64],
            ml_dsa_65_sig: vec![0x02; 3309],
            signing_key_id: "ratchet-steward:1".into(),
            inserted_at: chrono::Utc::now(),
        };
        backend
            .put_calibration_bundle(bundle_v1.clone())
            .await
            .unwrap();

        let current = backend
            .get_current_calibration_bundle()
            .await
            .unwrap()
            .expect("v1 should be current after put");
        assert_eq!(current.ratchet_calibration_version, v1);
        assert!(current.is_current);

        // Insert v2 with is_current=true; v1 must flip to false atomically.
        let bundle_v2 = CalibrationBundle {
            ratchet_calibration_version: v2,
            canonical_bytes: format!("v2-{v2}").into_bytes(),
            ..bundle_v1.clone()
        };
        backend.put_calibration_bundle(bundle_v2).await.unwrap();

        let current = backend
            .get_current_calibration_bundle()
            .await
            .unwrap()
            .expect("v2 should be current after flip");
        assert_eq!(current.ratchet_calibration_version, v2);
        assert!(current.is_current);

        // v1 must still be readable by version, but is_current=false.
        let v1_row = backend
            .get_calibration_bundle_by_version(v1)
            .await
            .unwrap()
            .expect("v1 should still exist post-flip");
        assert!(!v1_row.is_current, "v1 must be flipped to is_current=false");
    }

    /// Wrong-length signatures rejected as InvalidArgument before
    /// hitting the DB CHECK constraint (typed error surface).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn detection_event_rejects_wrong_signature_lengths() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::derived::{ConformityVariant, DerivedSchema, DetectionEvent, DetectionSeverity};
        let bad = DetectionEvent {
            detection_id: uuid::Uuid::new_v4(),
            trace_id: "t".into(),
            body_sha256: vec![0xAB; 32],
            detector: "test".into(),
            severity: DetectionSeverity::Info,
            cohort_cell: serde_json::json!({}),
            conformity_variant: ConformityVariant::Numeric,
            conformity_payload: serde_json::json!({"score": 1.0}),
            lens_core_version: "0.1.0".into(),
            ratchet_calibration_version: 1,
            canonical_bytes: b"x".to_vec(),
            ed25519_sig: vec![0x01; 32], // WRONG: must be 64
            ml_dsa_65_sig: vec![0x02; 3309],
            signing_key_id: "test:1".into(),
            ts: chrono::Utc::now(),
        };
        let err = backend.put_detection_event(bad).await.unwrap_err();
        assert!(matches!(err, crate::derived::Error::InvalidArgument(_)));
    }

    // ─── ReadEngine §A tests (v0.5.0, CIRISPersist#23) ──────────────

    /// Insert a synthetic 5-component trace into `cirislens.trace_events`
    /// covering THOUGHT_START + DMA_RESULTS + IDMA_RESULT +
    /// CONSCIENCE_RESULT + ACTION_RESULT — the rows the
    /// `TRACE_SUMMARY_SELECT` JSONB-extraction reads from. Returns
    /// the trace_id (caller can supply or auto-generate).
    ///
    /// Caller can pass `agent_id_hash`, `agent_name`,
    /// `deployment_domain` to control the AV-9 / filter test surface.
    #[allow(clippy::too_many_arguments)]
    async fn insert_section_a_fixture_trace(
        backend: &PostgresBackend,
        trace_id: &str,
        agent_id_hash: &str,
        agent_name: Option<&str>,
        deployment_domain: Option<&str>,
        started_at: chrono::DateTime<chrono::Utc>,
        action_was_overridden: bool,
        csdma_score: f64,
        dsdma_alignment: f64,
        idma_k_eff: f64,
    ) -> String {
        let base_payload =
            |extras: serde_json::Value| -> serde_json::Map<String, serde_json::Value> {
                if let serde_json::Value::Object(m) = extras {
                    m.into_iter().collect()
                } else {
                    serde_json::Map::new()
                }
            };
        let mk_row = |event_type: ReasoningEventType,
                      ts_offset_ms: i64,
                      payload: serde_json::Value,
                      cost_llm_calls: Option<i32>,
                      cost_tokens: Option<i32>,
                      cost_usd: Option<f64>|
         -> TraceEventRow {
            TraceEventRow {
                trace_id: trace_id.to_owned(),
                thought_id: format!("th-{trace_id}"),
                task_id: Some(format!("task-{trace_id}")),
                step_point: None,
                event_type,
                attempt_index: 0,
                ts: started_at + chrono::Duration::milliseconds(ts_offset_ms),
                agent_name: agent_name.map(str::to_owned),
                agent_id_hash: agent_id_hash.to_owned(),
                cognitive_state: Some("work".into()),
                trace_level: crate::schema::TraceLevel::Generic,
                payload: base_payload(payload),
                cost_llm_calls,
                cost_tokens,
                cost_usd,
                signature: "AAAA".into(),
                signing_key_id: "test-key".into(),
                signature_verified: true,
                schema_version: "2.7.0".into(),
                pii_scrubbed: false,
                original_content_hash: None,
                scrub_signature: None,
                scrub_key_id: None,
                scrub_timestamp: None,
                agent_role: Some("ally".into()),
                agent_template: Some("ally-v3-default".into()),
                deployment_domain: deployment_domain.map(str::to_owned),
                deployment_type: Some("production".into()),
                deployment_region: Some("US".into()),
                deployment_trust_mode: Some("federated_peer".into()),
            }
        };

        let rows = vec![
            mk_row(
                ReasoningEventType::ThoughtStart,
                0,
                serde_json::json!({
                    "thought_type": "standard",
                    "thought_depth": 1,
                }),
                None,
                None,
                None,
            ),
            mk_row(
                ReasoningEventType::DmaResults,
                10,
                serde_json::json!({
                    "csdma_plausibility_score": csdma_score,
                    "dsdma_domain_alignment": dsdma_alignment,
                    "dsdma_domain": "moderation",
                }),
                None,
                None,
                None,
            ),
            mk_row(
                ReasoningEventType::IdmaResult,
                20,
                serde_json::json!({
                    "idma_k_eff": idma_k_eff,
                    "idma_correlation_risk": 0.05,
                    "idma_fragility_flag": false,
                    "idma_phase": "stable",
                }),
                None,
                None,
                None,
            ),
            mk_row(
                ReasoningEventType::ConscienceResult,
                30,
                serde_json::json!({
                    "conscience_passed": !action_was_overridden,
                    "action_was_overridden": action_was_overridden,
                    "entropy_passed": true,
                    "coherence_passed": true,
                    "optimization_veto_passed": !action_was_overridden,
                    "epistemic_humility_passed": true,
                }),
                None,
                None,
                None,
            ),
            mk_row(
                ReasoningEventType::ActionResult,
                40,
                serde_json::json!({
                    "action_executed": "speak",
                    "success": !action_was_overridden,
                }),
                Some(2),
                Some(1500),
                Some(0.045),
            ),
        ];
        backend.insert_trace_events_batch(&rows).await.unwrap();
        trace_id.to_owned()
    }

    /// §A round-trip: insert a 5-component trace, read its summary,
    /// every JSONB-extracted field matches the fixture.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_a_get_trace_summary_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let tid = format!("trace-§a-rt-{}", uuid_like());
        let started = chrono::Utc::now();
        insert_section_a_fixture_trace(
            &backend,
            &tid,
            "agent-rt",
            Some("Scout"),
            Some("moderation"),
            started,
            false, // not overridden
            0.83,  // csdma
            0.91,  // dsdma
            1.42,  // idma_k_eff
        )
        .await;

        let s = backend
            .get_trace_summary(&tid)
            .await
            .unwrap()
            .expect("summary present");
        assert_eq!(s.trace_id, tid);
        assert_eq!(s.agent_id_hash, "agent-rt");
        assert_eq!(s.agent_name.as_deref(), Some("Scout"));
        assert_eq!(s.deployment_domain.as_deref(), Some("moderation"));
        assert!(s.signature_verified);
        // JSONB extracts:
        assert_eq!(s.thought_type.as_deref(), Some("standard"));
        assert_eq!(s.thought_depth, Some(1));
        assert!((s.csdma_plausibility_score.unwrap() - 0.83).abs() < 1e-9);
        assert!((s.dsdma_domain_alignment.unwrap() - 0.91).abs() < 1e-9);
        assert_eq!(s.dsdma_domain.as_deref(), Some("moderation"));
        assert!((s.idma_k_eff.unwrap() - 1.42).abs() < 1e-9);
        assert_eq!(s.idma_fragility_flag, Some(false));
        assert_eq!(s.idma_phase.as_deref(), Some("stable"));
        assert_eq!(s.conscience_passed, Some(true));
        assert_eq!(s.action_was_overridden, Some(false));
        assert_eq!(s.entropy_passed, Some(true));
        assert_eq!(s.coherence_passed, Some(true));
        assert_eq!(s.optimization_veto_passed, Some(true));
        assert_eq!(s.epistemic_humility_passed, Some(true));
        assert_eq!(s.selected_action.as_deref(), Some("speak"));
        assert_eq!(s.action_success, Some(true));
        assert_eq!(s.llm_calls, Some(2));
        assert_eq!(s.tokens_total, Some(1500));
        assert!((s.cost_usd.unwrap() - 0.045).abs() < 1e-9);
    }

    /// §A: unknown trace_id returns None (not Err).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_a_get_trace_summary_unknown_returns_none() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let opt = backend
            .get_trace_summary("trace-does-not-exist-xyz-§a")
            .await
            .unwrap();
        assert!(opt.is_none());
    }

    /// §A: list newest-first ordering + cursor pagination correctness.
    /// Insert 5 traces with staggered started_at; page through with
    /// limit=2; assert no overlap, no gaps, terminates with
    /// next_cursor=None.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_a_list_cursor_pagination() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;

        // Use a unique agent_id_hash + agent_name + domain so the
        // fixture set is isolated from any other test data in the
        // shared DB. Filter on (agent_id_hash, agent_name) below.
        let aid = format!("agent-cursor-{}", uuid_like());
        let aname = format!("Cursor-{}", uuid_like());
        let dom = format!("dom-{}", uuid_like());
        let base = chrono::Utc::now() - chrono::Duration::hours(1);

        let mut tids: Vec<String> = Vec::new();
        for i in 0..5 {
            let tid = format!("trace-§a-cur-{}-{i}", uuid_like());
            // Stagger started_at by 1 minute each. i=0 oldest, i=4 newest.
            let started = base + chrono::Duration::minutes(i64::from(i));
            insert_section_a_fixture_trace(
                &backend,
                &tid,
                &aid,
                Some(&aname),
                Some(&dom),
                started,
                false,
                0.5,
                0.5,
                1.0,
            )
            .await;
            tids.push(tid);
        }
        // Newest-first order = reverse of insertion order.
        tids.reverse();

        let filter = crate::read::TraceFilter {
            agent_id_hash: Some(aid.clone()),
            ..Default::default()
        };

        // Page 1: limit=2 → first 2 newest.
        let p1 = backend
            .list_trace_summaries(filter.clone(), None, 2)
            .await
            .unwrap();
        assert_eq!(p1.items.len(), 2);
        assert_eq!(p1.items[0].trace_id, tids[0]);
        assert_eq!(p1.items[1].trace_id, tids[1]);
        let c1 = p1.next_cursor.clone().expect("cursor for page 2");

        // Page 2: limit=2 → next 2.
        let p2 = backend
            .list_trace_summaries(filter.clone(), Some(c1), 2)
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 2);
        assert_eq!(p2.items[0].trace_id, tids[2]);
        assert_eq!(p2.items[1].trace_id, tids[3]);
        let c2 = p2.next_cursor.clone().expect("cursor for page 3");

        // Page 3: limit=2 → 1 row remaining; next_cursor MUST be None
        // because items.len() < limit (cleanly signals end of stream).
        let p3 = backend
            .list_trace_summaries(filter.clone(), Some(c2), 2)
            .await
            .unwrap();
        assert_eq!(p3.items.len(), 1);
        assert_eq!(p3.items[0].trace_id, tids[4]);
        assert!(p3.next_cursor.is_none());

        // Across all 3 pages: union covers all 5 trace_ids exactly once.
        let mut seen: Vec<String> = Vec::new();
        for p in [p1, p2, p3] {
            for s in p.items {
                seen.push(s.trace_id);
            }
        }
        assert_eq!(seen.len(), 5);
        assert_eq!(seen, tids);
    }

    /// §A AV-9 invariant: agent_id_hash filter isolates traces. Two
    /// agents with overlapping `trace_id` numerals are distinguished
    /// strictly by agent_id_hash.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_a_agent_id_hash_isolation() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;

        let suffix = uuid_like();
        let aid_a = format!("agent-A-{suffix}");
        let aid_b = format!("agent-B-{suffix}");
        let started = chrono::Utc::now();

        let tid_a = format!("trace-§a-iso-A-{suffix}");
        let tid_b = format!("trace-§a-iso-B-{suffix}");
        insert_section_a_fixture_trace(
            &backend,
            &tid_a,
            &aid_a,
            Some(&format!("AgentA-{suffix}")),
            Some(&format!("dom-iso-{suffix}")),
            started,
            false,
            0.7,
            0.7,
            1.0,
        )
        .await;
        insert_section_a_fixture_trace(
            &backend,
            &tid_b,
            &aid_b,
            Some(&format!("AgentB-{suffix}")),
            Some(&format!("dom-iso-{suffix}")),
            started,
            false,
            0.7,
            0.7,
            1.0,
        )
        .await;

        // Filtering by aid_a returns only A's trace.
        let p_a = backend
            .list_trace_summaries(
                crate::read::TraceFilter {
                    agent_id_hash: Some(aid_a.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        let trace_ids_a: Vec<&String> = p_a.items.iter().map(|s| &s.trace_id).collect();
        assert!(trace_ids_a.contains(&&tid_a));
        assert!(!trace_ids_a.contains(&&tid_b));
        // AV-9: every returned summary carries agent_id_hash so
        // callers authorize at their layer.
        for s in &p_a.items {
            assert_eq!(s.agent_id_hash, aid_a);
        }
    }

    /// §A: limit boundaries — 0 rejects, 10001 rejects, 1 accepts.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_a_list_limit_boundaries() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let f = crate::read::TraceFilter::default();

        let too_low = backend
            .list_trace_summaries(f.clone(), None, 0)
            .await
            .unwrap_err();
        assert!(matches!(too_low, crate::read::Error::InvalidArgument(_)));

        let too_high = backend
            .list_trace_summaries(f.clone(), None, 10_001)
            .await
            .unwrap_err();
        assert!(matches!(too_high, crate::read::Error::InvalidArgument(_)));

        // limit=1 accepts (no error); result count depends on DB
        // state, just check it didn't error.
        let _ok = backend.list_trace_summaries(f, None, 1).await.unwrap();
    }

    // ─── ReadEngine §B tests (v0.5.0, CIRISPersist#23) ──────────────

    /// §B round-trip: insert a 5-component fixture trace + 1 LLM
    /// call row; read detail; assert summary matches §A; components
    /// chronological; LLM calls present; envelope refs surface
    /// per-trace constants.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_b_get_trace_detail_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let tid = format!("trace-§b-rt-{}", uuid_like());
        let started = chrono::Utc::now();
        insert_section_a_fixture_trace(
            &backend,
            &tid,
            "agent-§b",
            Some("Scout-§b"),
            Some("moderation"),
            started,
            false,
            0.83,
            0.91,
            1.42,
        )
        .await;

        // Insert one LLM call row associated with the trace.
        let llm_row = crate::store::types::TraceLlmCallRow {
            trace_id: tid.clone(),
            thought_id: format!("th-{tid}"),
            task_id: Some(format!("task-{tid}")),
            parent_event_id: None,
            parent_event_type: ReasoningEventType::DmaResults,
            parent_attempt_index: 0,
            attempt_index: 0,
            ts: started + chrono::Duration::milliseconds(15),
            duration_ms: 1234.5,
            handler_name: "EthicalPDMA".into(),
            service_name: "openai".into(),
            model: Some("gpt-4o".into()),
            base_url: None,
            response_model: None,
            prompt_tokens: Some(800),
            completion_tokens: Some(150),
            prompt_bytes: None,
            completion_bytes: None,
            cost_usd: Some(0.024),
            status: crate::schema::LlmCallStatus::Ok,
            error_class: None,
            attempt_count: Some(1),
            retry_count: Some(0),
            prompt_hash: Some("hash-abcd".into()),
            prompt: None,
            response_text: None,
        };
        backend
            .insert_trace_llm_calls_batch(&[llm_row])
            .await
            .unwrap();

        let detail = backend
            .get_trace_detail(&tid)
            .await
            .unwrap()
            .expect("detail present");

        // Summary parity with §A.
        assert_eq!(detail.summary.trace_id, tid);
        assert_eq!(detail.summary.agent_id_hash, "agent-§b");
        assert_eq!(detail.summary.action_was_overridden, Some(false));

        // Components: 5 rows, chronological.
        assert_eq!(detail.components.len(), 5);
        assert_eq!(
            detail.components[0].event_type,
            ReasoningEventType::ThoughtStart
        );
        assert_eq!(
            detail.components[1].event_type,
            ReasoningEventType::DmaResults
        );
        assert_eq!(
            detail.components[2].event_type,
            ReasoningEventType::IdmaResult
        );
        assert_eq!(
            detail.components[3].event_type,
            ReasoningEventType::ConscienceResult
        );
        assert_eq!(
            detail.components[4].event_type,
            ReasoningEventType::ActionResult
        );
        // ts strictly ascending.
        for i in 1..detail.components.len() {
            assert!(
                detail.components[i].ts >= detail.components[i - 1].ts,
                "components must be chronological"
            );
        }
        // Component payload retained verbatim — DMA_RESULTS row carries
        // the canonical scoring fields.
        let dma = &detail.components[1];
        assert!(dma.payload.contains_key("csdma_plausibility_score"));
        assert!(dma.payload.contains_key("dsdma_domain_alignment"));

        // LLM calls: one row with the fields we inserted.
        assert_eq!(detail.llm_calls.len(), 1);
        let call = &detail.llm_calls[0];
        assert_eq!(call.trace_id, tid);
        assert_eq!(call.handler_name, "EthicalPDMA");
        assert_eq!(call.service_name, "openai");
        assert_eq!(call.model.as_deref(), Some("gpt-4o"));
        assert_eq!(call.prompt_tokens, Some(800));
        assert!(matches!(call.status, crate::schema::LlmCallStatus::Ok));

        // Envelope refs: per-trace constants from the fixture.
        assert_eq!(detail.envelope.signature, "AAAA");
        assert_eq!(detail.envelope.signature_key_id, "test-key");
        assert!(!detail.envelope.pii_scrubbed);
        assert!(detail.envelope.original_content_hash.is_none()); // fixture sets None
    }

    /// §B: unknown trace_id returns None (not Err).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_b_get_trace_detail_unknown_returns_none() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let opt = backend
            .get_trace_detail("trace-does-not-exist-§b-xyz")
            .await
            .unwrap();
        assert!(opt.is_none());
    }

    /// §B: trace with no LLM call rows still produces a TraceDetail
    /// with empty `llm_calls` (NOT None on the overall TraceDetail).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_b_no_llm_calls_returns_empty_vec() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let tid = format!("trace-§b-no-llm-{}", uuid_like());
        insert_section_a_fixture_trace(
            &backend,
            &tid,
            "agent-no-llm",
            Some("X"),
            Some("d"),
            chrono::Utc::now(),
            false,
            0.5,
            0.5,
            1.0,
        )
        .await;
        let detail = backend
            .get_trace_detail(&tid)
            .await
            .unwrap()
            .expect("detail present even without LLM calls");
        assert_eq!(detail.components.len(), 5);
        assert!(detail.llm_calls.is_empty());
    }

    // ─── ReadEngine §F tests (v0.5.0, CIRISPersist#23) ──────────────

    /// §F cross_agent_divergence — three agents in the same domain
    /// with different csdma_plausibility_score means; assert the
    /// outlier has the largest |z_score|; sample_count matches the
    /// fixture.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_f_cross_agent_divergence_csdma() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let suffix = uuid_like();
        let dom = format!("dom-§f-{suffix}");
        let now = chrono::Utc::now();
        let window = crate::read::TimeWindow {
            since: now - chrono::Duration::hours(1),
            until: now + chrono::Duration::hours(1),
        };

        // Three agents:
        //   agent-A: csdma=0.85 (close to peer mean)
        //   agent-B: csdma=0.85 (close to peer mean)
        //   agent-C: csdma=0.30 (outlier — much lower)
        for (aid, score) in [
            (format!("agent-§f-A-{suffix}"), 0.85_f64),
            (format!("agent-§f-B-{suffix}"), 0.85_f64),
            (format!("agent-§f-C-{suffix}"), 0.30_f64),
        ] {
            let tid = format!("trace-§f-{aid}");
            insert_section_a_fixture_trace(
                &backend,
                &tid,
                &aid,
                Some(&aid),
                Some(&dom),
                now,
                false,
                score,
                0.5,
                1.0,
            )
            .await;
        }

        let rows = backend
            .cross_agent_divergence(
                &dom,
                window,
                crate::read::DeviationMetric::CsdmaPlausibility,
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 3);
        // Most-divergent first: agent-C should top the list.
        assert!(rows[0].agent_id_hash.contains("agent-§f-C-"));
        assert!(rows[0].z_score.abs() > rows[1].z_score.abs());
        // sample_count matches the fixture (1 DMA_RESULTS row per agent).
        for r in &rows {
            assert_eq!(r.sample_count, 1);
            assert_eq!(
                r.deviation_metric,
                crate::read::DeviationMetric::CsdmaPlausibility
            );
        }
    }

    /// §F cross_agent_divergence — ConscienceOverrideRate metric.
    /// Agent-A overrides 1/3 of traces; agent-B overrides 0/3.
    /// A's z-score should be positive; B's negative.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_f_cross_agent_divergence_override_rate() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let suffix = uuid_like();
        let dom = format!("dom-§f-or-{suffix}");
        let now = chrono::Utc::now();
        let aid_a = format!("agent-§f-A-{suffix}");
        let aid_b = format!("agent-§f-B-{suffix}");

        // agent-A: 3 traces, 1 overridden (rate=1/3)
        for i in 0..3 {
            let tid = format!("trace-§f-A-{suffix}-{i}");
            insert_section_a_fixture_trace(
                &backend,
                &tid,
                &aid_a,
                Some(&aid_a),
                Some(&dom),
                now + chrono::Duration::seconds(i64::from(i)),
                i == 0, // first one overridden
                0.5,
                0.5,
                1.0,
            )
            .await;
        }
        // agent-B: 3 traces, 0 overridden (rate=0)
        for i in 0..3 {
            let tid = format!("trace-§f-B-{suffix}-{i}");
            insert_section_a_fixture_trace(
                &backend,
                &tid,
                &aid_b,
                Some(&aid_b),
                Some(&dom),
                now + chrono::Duration::seconds(i64::from(i)),
                false,
                0.5,
                0.5,
                1.0,
            )
            .await;
        }

        let window = crate::read::TimeWindow {
            since: now - chrono::Duration::hours(1),
            until: now + chrono::Duration::hours(1),
        };
        let rows = backend
            .cross_agent_divergence(
                &dom,
                window,
                crate::read::DeviationMetric::ConscienceOverrideRate,
            )
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        // agent-A has higher override rate → positive z; agent-B → negative.
        let a_row = rows.iter().find(|r| r.agent_id_hash == aid_a).unwrap();
        let b_row = rows.iter().find(|r| r.agent_id_hash == aid_b).unwrap();
        assert!(a_row.z_score > 0.0, "agent-A z-score must be positive");
        assert!(b_row.z_score < 0.0, "agent-B z-score must be negative");
        assert_eq!(a_row.sample_count, 3);
        assert_eq!(b_row.sample_count, 3);
    }

    /// §F temporal_drift — same agent, two windows with different
    /// csdma means; assert mean_shift = comp_mean - base_mean and
    /// significance has correct sign.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_f_temporal_drift() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let suffix = uuid_like();
        let aid = format!("agent-§f-td-{suffix}");
        let now = chrono::Utc::now();

        // Baseline window: 5 traces with csdma values varying around 0.8
        // (mean=0.8, non-zero variance). Comparison: 5 traces around 0.5
        // (mean=0.5, non-zero variance). mean_shift = -0.3; pooled_se >
        // 0; significance is well-defined and negative.
        let base_t = now - chrono::Duration::hours(2);
        let base_scores = [0.75, 0.78, 0.80, 0.82, 0.85];
        for (i, score) in base_scores.iter().enumerate() {
            let tid = format!("trace-§f-td-base-{suffix}-{i}");
            insert_section_a_fixture_trace(
                &backend,
                &tid,
                &aid,
                Some(&aid),
                Some("d"),
                base_t + chrono::Duration::minutes(i64::try_from(i).unwrap()),
                false,
                *score,
                0.5,
                1.0,
            )
            .await;
        }
        let comp_t = now - chrono::Duration::minutes(20);
        let comp_scores = [0.45, 0.48, 0.50, 0.52, 0.55];
        for (i, score) in comp_scores.iter().enumerate() {
            let tid = format!("trace-§f-td-comp-{suffix}-{i}");
            insert_section_a_fixture_trace(
                &backend,
                &tid,
                &aid,
                Some(&aid),
                Some("d"),
                comp_t + chrono::Duration::minutes(i64::try_from(i).unwrap()),
                false,
                *score,
                0.5,
                1.0,
            )
            .await;
        }

        let baseline = crate::read::TimeWindow {
            since: now - chrono::Duration::hours(3),
            until: now - chrono::Duration::hours(1),
        };
        let comparison = crate::read::TimeWindow {
            since: now - chrono::Duration::minutes(45),
            until: now + chrono::Duration::minutes(15),
        };
        let rows = backend
            .temporal_drift(&aid, baseline, comparison)
            .await
            .unwrap();
        // Find the CSDMA row.
        let csdma = rows
            .iter()
            .find(|r| r.deviation_metric == crate::read::DeviationMetric::CsdmaPlausibility)
            .expect("CSDMA drift row");
        assert!((csdma.mean_shift - (-0.3)).abs() < 1e-9);
        // significance has same sign as mean_shift (negative shift → negative z)
        assert!(csdma.significance < 0.0);
    }

    /// §F hash_chain_gaps — insert ACTION_RESULT rows with
    /// audit_sequence_number = 1, 2, 5, 6 (gap between 2 and 5);
    /// assert one detected gap with start=2, end=5.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_f_hash_chain_gaps() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let suffix = uuid_like();
        let aid = format!("agent-§f-gap-{suffix}");
        let now = chrono::Utc::now();

        // ACTION_RESULT rows directly via Backend insert with
        // audit_sequence_number set. Need to pass a TraceEventRow
        // with audit fields set; the existing fixture helper
        // doesn't take audit_sequence_number. Build inline.
        let mk = |seq: i64, ts_offset_min: i64| TraceEventRow {
            trace_id: format!("trace-§f-gap-{suffix}-{seq}"),
            thought_id: format!("th-{seq}"),
            task_id: None,
            step_point: None,
            event_type: ReasoningEventType::ActionResult,
            attempt_index: 0,
            ts: now + chrono::Duration::minutes(ts_offset_min),
            agent_name: Some(aid.clone()),
            agent_id_hash: aid.clone(),
            cognitive_state: Some("work".into()),
            trace_level: crate::schema::TraceLevel::Generic,
            payload: {
                let mut m = serde_json::Map::new();
                m.insert("audit_sequence_number".into(), seq.into());
                m.insert("audit_entry_hash".into(), "deadbeef".into());
                m.insert("audit_signature".into(), "BBBB".into());
                m
            },
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
            agent_role: None,
            agent_template: None,
            deployment_domain: None,
            deployment_type: None,
            deployment_region: None,
            deployment_trust_mode: None,
        };
        // Insert seqs 1,2,5,6 — single gap (3,4 missing).
        backend
            .insert_trace_events_batch(&[mk(1, 0), mk(2, 1), mk(5, 2), mk(6, 3)])
            .await
            .unwrap();

        let window = crate::read::TimeWindow {
            since: now - chrono::Duration::minutes(1),
            until: now + chrono::Duration::hours(1),
        };
        let gaps = backend.hash_chain_gaps(&aid, window).await.unwrap();
        assert_eq!(gaps.len(), 1);
        let g = &gaps[0];
        assert_eq!(g.gap_start_seq, 2);
        assert_eq!(g.gap_end_seq, 5);
        assert_eq!(g.agent_id_hash, aid);
    }

    /// §F conscience_override_rates — two agents in same domain:
    /// agent-A overrides 2/4 traces (rate=0.5); agent-B overrides 1/4
    /// (rate=0.25). Domain avg = (2+1)/(4+4) = 0.375. Multiples
    /// surface correctly.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_f_conscience_override_rates() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let suffix = uuid_like();
        let dom = format!("dom-§f-cor-{suffix}");
        let aid_a = format!("agent-§f-cor-A-{suffix}");
        let aid_b = format!("agent-§f-cor-B-{suffix}");
        let now = chrono::Utc::now();

        // agent-A: 4 traces, traces[0..2] overridden (2/4 = 0.5)
        for i in 0..4 {
            let tid = format!("trace-§f-cor-A-{suffix}-{i}");
            insert_section_a_fixture_trace(
                &backend,
                &tid,
                &aid_a,
                Some(&aid_a),
                Some(&dom),
                now + chrono::Duration::seconds(i64::from(i)),
                i < 2,
                0.5,
                0.5,
                1.0,
            )
            .await;
        }
        // agent-B: 4 traces, traces[0] overridden (1/4 = 0.25)
        for i in 0..4 {
            let tid = format!("trace-§f-cor-B-{suffix}-{i}");
            insert_section_a_fixture_trace(
                &backend,
                &tid,
                &aid_b,
                Some(&aid_b),
                Some(&dom),
                now + chrono::Duration::seconds(i64::from(i)),
                i == 0,
                0.5,
                0.5,
                1.0,
            )
            .await;
        }

        let window = crate::read::TimeWindow {
            since: now - chrono::Duration::hours(1),
            until: now + chrono::Duration::hours(1),
        };
        let rows = backend
            .conscience_override_rates(&dom, window)
            .await
            .unwrap();
        assert_eq!(rows.len(), 2);
        let a = rows.iter().find(|r| r.agent_id_hash == aid_a).unwrap();
        let b = rows.iter().find(|r| r.agent_id_hash == aid_b).unwrap();
        assert_eq!(a.override_count, 2);
        assert_eq!(a.trace_count, 4);
        assert!((a.override_rate - 0.5).abs() < 1e-9);
        assert_eq!(b.override_count, 1);
        assert_eq!(b.trace_count, 4);
        assert!((b.override_rate - 0.25).abs() < 1e-9);
        // Domain avg = 3/8 = 0.375; A's multiple = 0.5/0.375 ≈ 1.333.
        assert!((a.domain_avg_rate - 0.375).abs() < 1e-9);
        assert!((a.multiple_of_domain_avg - 1.333_333_333_333_333_3).abs() < 1e-6);
        // B's multiple = 0.25/0.375 ≈ 0.667.
        assert!((b.multiple_of_domain_avg - 0.666_666_666_666_666_7).abs() < 1e-6);
    }

    // ─── ReadEngine §E tests (v0.5.0, CIRISPersist#23) ──────────────

    /// §E aggregate_scoring_factors round-trip — fixture has 4 traces:
    /// 1 overridden (action=succeed → unsafe), 3 not overridden;
    /// assert all factor inputs surface correctly.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_e_aggregate_scoring_factors_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let suffix = uuid_like();
        let aid = format!("agent-§e-{suffix}");
        let now = chrono::Utc::now();

        // 4 traces: traces[0] overridden (will count as unsafe via
        // the action_succeeded BOOL_OR true at ACTION_RESULT) ;
        // traces[1..4] not overridden, normal.
        for i in 0..4 {
            let tid = format!("trace-§e-{suffix}-{i}");
            insert_section_a_fixture_trace(
                &backend,
                &tid,
                &aid,
                Some(&aid),
                Some("d"),
                now + chrono::Duration::seconds(i64::from(i)),
                i == 0, // overridden iff first
                0.5,
                0.5,
                1.0,
            )
            .await;
        }

        let window = crate::read::TimeWindow {
            since: now - chrono::Duration::hours(1),
            until: now + chrono::Duration::hours(1),
        };
        let agg = backend
            .aggregate_scoring_factors(&aid, window, None)
            .await
            .unwrap();

        assert_eq!(agg.agent_id_hash, aid);
        assert_eq!(agg.trace_count, 4);
        assert_eq!(agg.identity_changes, 0); // single agent_name
        assert_eq!(agg.conscience_overrides, 1); // trace 0
                                                 // Audit-chain: fixture doesn't populate audit_sequence_number,
                                                 // so audit_chain_total = 0.
        assert_eq!(agg.audit_chain_total, 0);
        assert_eq!(agg.audit_signed_total, 0);
        assert_eq!(agg.audit_chain_gaps, 0);
        // unsafe action: fixture's overridden trace has
        // action_was_overridden=true with conscience_passed=false
        // AND action_succeeded=true (the `success` field on
        // ACTION_RESULT is `!action_was_overridden` per fixture
        // helper, so when overridden the action shows success=false
        // — NOT unsafe). So unsafe_action_rate = 0 in this fixture.
        assert!((agg.unsafe_action_rate - 0.0).abs() < 1e-9);
        // No baseline → no drift z-score.
        assert!(agg.drift_z_score.is_none());
        // calibration_error always None for v0.5.0.
        assert!(agg.calibration_error.is_none());
        // Coherence series: at least one bucket point.
        assert!(!agg.coherence_decay_series.is_empty());
        // Recovery events: trace[0] overridden, trace[1] passes (not
        // overridden + coherence_passed=true) → 1 recovery event.
        assert_eq!(agg.recovery_events.len(), 1);
        let recovery = &agg.recovery_events[0];
        assert!(recovery.override_trace_id.contains("§e"));
        assert!(recovery.recovery_latency_seconds >= 0.0);
    }

    /// §E REGRESSION (v0.5.1 / CIRISPersist#24): `aggregate_scoring_factors`
    /// with an empty window MUST NOT panic. Pre-fix the SUM(CASE WHEN ...)
    /// aggregates returned NULL from an empty CTE, `Row::get::<_, i64>`
    /// panicked on the NULL, PyO3 propagated as `Fatal Python error:
    /// Aborted` → SIGABRT → every uvicorn worker died in parallel from
    /// concurrent §E baseline calls (prod wedge 2026-05-11 15:09-15:59
    /// UTC).
    ///
    /// Fix: COALESCE(SUM(...), 0) at the SQL layer + `try_get<Option<i64>>`
    /// at the Rust layer (belt-and-braces). This test exercises the
    /// empty-window code path explicitly; if it regresses, the test
    /// will panic with the same signature as prod did.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_e_aggregate_scoring_factors_empty_window_does_not_panic() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        // Agent that doesn't exist + window in the far past = empty CTE
        // = SUM returns NULL = pre-fix Row::get panics.
        let aid = format!("agent-§e-empty-{}", uuid_like());
        let window = crate::read::TimeWindow {
            since: chrono::Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap(),
            until: chrono::Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 0).unwrap(),
        };

        let agg = backend
            .aggregate_scoring_factors(&aid, window, None)
            .await
            .expect("MUST NOT panic on empty window");

        // Empty-window results: all counts are 0, all rates are 0.0,
        // all series/event lists are empty.
        assert_eq!(agg.agent_id_hash, aid);
        assert_eq!(agg.trace_count, 0);
        assert_eq!(agg.identity_changes, 0);
        assert_eq!(agg.conscience_overrides, 0);
        assert_eq!(agg.audit_chain_total, 0);
        assert_eq!(agg.audit_chain_gaps, 0);
        assert_eq!(agg.audit_signed_total, 0);
        assert!((agg.unsafe_action_rate - 0.0).abs() < 1e-9);
        assert!(agg.recovery_events.is_empty());
        assert!(agg.coherence_decay_series.is_empty());
        assert!(agg.drift_z_score.is_none());
        assert!(agg.calibration_error.is_none());
    }

    /// §E REGRESSION (v0.5.1 / CIRISPersist#24): same as above but with
    /// a baseline_window also empty. Pre-fix the baseline → main flow
    /// was the exact path that crashed prod (`?hours=24&baseline_hours=168`
    /// where the baseline window had no traces for Scout).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_e_aggregate_scoring_factors_empty_baseline_does_not_panic() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let suffix = uuid_like();
        let aid = format!("agent-§e-emptybase-{suffix}");
        let now = chrono::Utc::now();

        // Main window: has traces. Baseline window: empty (sparse-
        // baseline agent like Scout in prod).
        insert_section_a_fixture_trace(
            &backend,
            &format!("trace-§e-emptybase-{suffix}"),
            &aid,
            Some(&aid),
            Some("d"),
            now,
            false,
            0.5,
            0.5,
            1.0,
        )
        .await;
        let window = crate::read::TimeWindow {
            since: now - chrono::Duration::hours(1),
            until: now + chrono::Duration::hours(1),
        };
        let baseline = crate::read::TimeWindow {
            since: chrono::Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap(),
            until: chrono::Utc.with_ymd_and_hms(2020, 1, 2, 0, 0, 0).unwrap(),
        };

        let agg = backend
            .aggregate_scoring_factors(&aid, window, Some(baseline))
            .await
            .expect("MUST NOT panic on empty baseline");

        // Main window has data.
        assert_eq!(agg.trace_count, 1);
        // Baseline has no samples → drift_z_score is None (the
        // temporal_drift result has no row for csdma).
        assert!(agg.drift_z_score.is_none());
    }

    /// §E aggregate_scoring_factors_batch — empty input returns empty
    /// vec; non-empty returns one aggregate per agent in order.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_e_aggregate_scoring_factors_batch() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        // Empty input.
        let empty = backend
            .aggregate_scoring_factors_batch(
                &[],
                crate::read::TimeWindow {
                    since: chrono::Utc::now() - chrono::Duration::hours(1),
                    until: chrono::Utc::now(),
                },
                None,
            )
            .await
            .unwrap();
        assert!(empty.is_empty());

        // Two agents.
        let suffix = uuid_like();
        let aid_a = format!("agent-§e-batch-A-{suffix}");
        let aid_b = format!("agent-§e-batch-B-{suffix}");
        let now = chrono::Utc::now();
        for aid in [&aid_a, &aid_b] {
            insert_section_a_fixture_trace(
                &backend,
                &format!("trace-§e-batch-{aid}"),
                aid,
                Some(aid),
                Some("d"),
                now,
                false,
                0.5,
                0.5,
                1.0,
            )
            .await;
        }

        let window = crate::read::TimeWindow {
            since: now - chrono::Duration::hours(1),
            until: now + chrono::Duration::hours(1),
        };
        let aggs = backend
            .aggregate_scoring_factors_batch(&[aid_a.clone(), aid_b.clone()], window, None)
            .await
            .unwrap();
        assert_eq!(aggs.len(), 2);
        // Order matches input.
        assert_eq!(aggs[0].agent_id_hash, aid_a);
        assert_eq!(aggs[1].agent_id_hash, aid_b);
    }

    /// §E count_traces — agent_id_hash filter narrows correctly.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_e_count_traces() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let suffix = uuid_like();
        let aid = format!("agent-§e-count-{suffix}");
        let now = chrono::Utc::now();
        for i in 0..3 {
            insert_section_a_fixture_trace(
                &backend,
                &format!("trace-§e-count-{suffix}-{i}"),
                &aid,
                Some(&aid),
                Some("d"),
                now,
                false,
                0.5,
                0.5,
                1.0,
            )
            .await;
        }

        let n = backend
            .count_traces(crate::read::TraceFilter {
                agent_id_hash: Some(aid.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(n, 3);
    }

    /// §E count_overrides — distinct from count_traces; collapses
    /// recursive CONSCIENCE_RESULT correctly.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_e_count_overrides() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let suffix = uuid_like();
        let aid = format!("agent-§e-cor-{suffix}");
        let now = chrono::Utc::now();
        // 5 traces, traces[0..2] overridden (2/5)
        for i in 0..5 {
            insert_section_a_fixture_trace(
                &backend,
                &format!("trace-§e-cor-{suffix}-{i}"),
                &aid,
                Some(&aid),
                Some("d"),
                now,
                i < 2,
                0.5,
                0.5,
                1.0,
            )
            .await;
        }
        let n = backend
            .count_overrides(crate::read::TraceFilter {
                agent_id_hash: Some(aid),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(n, 2);
    }

    /// §E aggregate_audit_chain — fixture has no audit_sequence_number
    /// rows; verify zero counts. (audit fields are populated only on
    /// real ACTION_RESULT rows the agent actually emits with audit
    /// anchors; the §A fixture helper doesn't populate them.)
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_e_aggregate_audit_chain_no_audit_rows() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let suffix = uuid_like();
        let aid = format!("agent-§e-audit-{suffix}");
        let now = chrono::Utc::now();
        insert_section_a_fixture_trace(
            &backend,
            &format!("trace-§e-audit-{suffix}"),
            &aid,
            Some(&aid),
            Some("d"),
            now,
            false,
            0.5,
            0.5,
            1.0,
        )
        .await;

        let agg = backend
            .aggregate_audit_chain(crate::read::TraceFilter {
                agent_id_hash: Some(aid),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(agg.audit_total, 0);
        assert_eq!(agg.audit_signed, 0);
        assert_eq!(agg.audit_hashed, 0);
        assert_eq!(agg.gap_count, 0);
    }

    /// §A: invalid cursor version rejects with InvalidCursor.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_a_invalid_cursor_version_rejects() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        use crate::read::ReadEngine;
        let bad_cursor = crate::read::TraceCursor {
            version: "v99".into(),
            last_started_at: chrono::Utc::now(),
            last_trace_id: "x".into(),
        };
        let err = backend
            .list_trace_summaries(crate::read::TraceFilter::default(), Some(bad_cursor), 10)
            .await
            .unwrap_err();
        assert!(matches!(err, crate::read::Error::InvalidCursor(_)));
    }
}
