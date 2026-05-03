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
        // v0.2.1 — dual-read migration. Try federation_keys first
        // (the v0.2.0 federation directory), fall back to
        // accord_public_keys (legacy). Lens team's cutover path
        // requires this: writes flow to federation_keys via the
        // federation surface; this read site has to find them there.
        // Once the v0.4.0 read-path migration lands, the legacy
        // fallback is dropped.
        //
        // Filter: federation_keys has no revocation column directly
        // (revocations live in federation_revocations); for v0.2.x we
        // accept any unexpired federation_keys row. Strict consumers
        // can layer on the revocation check via revocations_for().
        // accord_public_keys retains its existing
        // revoked_at/expires_at filter (THREAT_MODEL.md AV-11).
        let client = self.get_client().await?;

        // Try federation_keys first.
        let fed_row = client
            .query_opt(
                "SELECT pubkey_ed25519_base64 FROM cirislens.federation_keys \
                 WHERE key_id = $1 \
                   AND (valid_until IS NULL OR valid_until > NOW())",
                &[&key_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("lookup_public_key (federation_keys): {e}")))?;
        if let Some(row) = fed_row {
            let b64: String = row.get(0);
            return decode_ed25519_b64(&b64).map(Some);
        }

        // Fall back to accord_public_keys (legacy).
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
        decode_ed25519_b64(&b64).map(Some)
    }

    async fn sample_public_keys(
        &self,
        limit: usize,
    ) -> Result<super::backend::PublicKeySample, Error> {
        // v0.1.17 — diagnostic for CIRISPersist#6 verify-unknown-key
        // breadcrumb. Same filter as `lookup_public_key`'s WHERE
        // (unrevoked + unexpired), so the sample reflects exactly
        // what the runtime lookup is querying against. ORDER BY
        // key_id for stable cross-call ordering.
        let client = self.get_client().await?;
        let count_row = client
            .query_one(
                "SELECT COUNT(*)::BIGINT FROM cirislens.accord_public_keys \
                 WHERE revoked_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > NOW())",
                &[],
            )
            .await
            .map_err(|e| Error::Backend(format!("count_public_keys: {e}")))?;
        let total: i64 = count_row.get(0);

        let lim = i64::try_from(limit).unwrap_or(i64::MAX);
        let rows = client
            .query(
                "SELECT key_id FROM cirislens.accord_public_keys \
                 WHERE revoked_at IS NULL \
                   AND (expires_at IS NULL OR expires_at > NOW()) \
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

        // Step 1: collect agent's trace_ids so we can join the LLM
        // call delete (trace_llm_calls has no agent_id_hash column;
        // FK is on trace_id alone).
        let trace_ids: Vec<String> = tx
            .query(
                "SELECT DISTINCT trace_id FROM cirislens.trace_events \
                 WHERE agent_id_hash = $1",
                &[&agent_id_hash],
            )
            .await
            .map_err(|e| Error::Backend(format!("collect trace_ids: {e}")))?
            .into_iter()
            .map(|row| row.get::<_, String>(0))
            .collect();

        // Step 2: delete LLM call rows joined by trace_id.
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

        // Step 3: delete trace_events rows.
        let trace_events_deleted = tx
            .execute(
                "DELETE FROM cirislens.trace_events WHERE agent_id_hash = $1",
                &[&agent_id_hash],
            )
            .await
            .map_err(|e| Error::Backend(format!("delete trace_events: {e}")))?;

        // Step 4 (optional): federation key cascade. Find target key_ids,
        // delete cascading attestation/revocation rows, then the keys.
        let mut federation_keys_deleted = 0u64;
        let mut federation_attestations_deleted = 0u64;
        let mut federation_revocations_deleted = 0u64;

        if include_federation_key {
            let target_key_ids: Vec<String> = tx
                .query(
                    "SELECT key_id FROM cirislens.federation_keys \
                     WHERE identity_type = 'agent' AND identity_ref = $1",
                    &[&agent_id_hash],
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
}
