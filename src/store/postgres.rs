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

/// v3.11.0 — count of embedded `migrations/postgres/lens/*` scripts
/// the backend ships. Public so the `av26_concurrent_boot_advisory_lock`
/// QA harness can assert on the live migration set instead of a
/// hardcoded number that drifts each release.
///
/// Returns the same count refinery walks at runtime —
/// `embedded::migrations::runner().get_migrations().len()` — and is
/// stable as long as the `embed_migrations!` macro stays sourced
/// from the same directory.
pub fn embedded_lens_migration_count() -> usize {
    embedded::migrations::runner().get_migrations().len()
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
    /// Optional local signer for the v1.5.0 Merkle transparency
    /// hook (`AuditService::record_entry` ingest path). When
    /// configured, every committed audit entry is appended to the
    /// tenant's `TransparencyLog<AuditLeaf>` and an STH is signed +
    /// stored. When `None`, the Merkle hook is a no-op — preserves
    /// behavior for deployments without a local identity loaded
    /// (CIRIS-RED hot-path peers, tests, etc.).
    ///
    /// Wired by the Engine layer at construction (Phase G/H); Phase
    /// C only adds the field + setter.
    #[cfg(feature = "cirisaudit")]
    merkle_signer: std::sync::RwLock<Option<std::sync::Arc<crate::signing::LocalSigner>>>,
    /// v2.3 (CIRISPersist#103) — inline-byte cap for the BlobStorage
    /// trait's `put_blob`. Defaults to
    /// [`crate::federation::DEFAULT_INLINE_BYTES_CAP`]; an Engine
    /// builder may override via [`PostgresBackend::with_inline_bytes_cap`].
    inline_bytes_cap: std::sync::atomic::AtomicUsize,
    /// v2.5.0 (CIRISPersist#102 Ask 4) — per-axis envelope-schema
    /// resolver. The default is
    /// [`crate::federation::NoOpSchemaResolver`], which makes the
    /// admission hook a no-op (existing `put_attestation` callers
    /// don't break). Override via
    /// [`PostgresBackend::with_schema_resolver`].
    schema_resolver: std::sync::RwLock<std::sync::Arc<dyn crate::federation::SchemaResolver>>,
    /// v2.5.0 (CIRISPersist#102 Ask 8) — hardware-attestation policy
    /// for accord-holder `put_public_key` admission. Defaults to
    /// [`crate::federation::HardwareAttestationPolicy::default`].
    /// Override via [`PostgresBackend::with_hardware_attestation_policy`].
    hardware_attestation_policy:
        std::sync::RwLock<std::sync::Arc<crate::federation::HardwareAttestationPolicy>>,
    /// v3.4.0 (CIRISPersist#123) — trust-weighted admission gate.
    /// `None` = no trust gate is installed (bootstrap-permissive — the
    /// historical pre-#123 behavior). Set via
    /// [`PostgresBackend::set_admission_gate`].
    admission_gate: std::sync::RwLock<Option<crate::federation::AdmissionGate>>,
    /// v3.6.0 (CIRISPersist#134) — perceptual-hash matcher for the
    /// `put_blob_signing` admission hook. `None` = no hook (default).
    perceptual_hash_matcher: std::sync::RwLock<Option<crate::federation::SharedMatcher>>,
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
            #[cfg(feature = "cirisaudit")]
            merkle_signer: std::sync::RwLock::new(None),
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

    /// v2.3 (CIRISPersist#103) — override the default inline-byte cap
    /// for the [`crate::federation::BlobStorage`] trait's `put_blob`.
    /// Callers larger than the cap on the `Inline` arm receive
    /// [`crate::federation::BlobError::InlineSizeExceeded`].
    pub fn with_inline_bytes_cap(self, cap: usize) -> Self {
        self.inline_bytes_cap
            .store(cap, std::sync::atomic::Ordering::Relaxed);
        self
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
            #[cfg(feature = "cirisaudit")]
            merkle_signer: std::sync::RwLock::new(None),
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
    /// `None` clears the gate (bootstrap-permissive). The four write
    /// paths (`put_blob`, `put_attestation`, `put_revocation`,
    /// `put_contribution`) consult the gate BEFORE any DB work; an
    /// unauthorized writer learns nothing about FK / schema /
    /// signature state past the gate's verdict.
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
    /// hook. Defaults to [`crate::federation::NoOpSchemaResolver`];
    /// override here for deployments that want envelope validation
    /// against per-axis JSON Schemas (FSD-002 §4.9.1).
    pub fn set_schema_resolver(
        &self,
        resolver: std::sync::Arc<dyn crate::federation::SchemaResolver>,
    ) {
        *self
            .schema_resolver
            .write()
            .unwrap_or_else(|p| p.into_inner()) = resolver;
    }

    /// Snapshot the currently-installed schema resolver. Returns the
    /// default no-op resolver when nothing's been wired.
    pub fn schema_resolver(&self) -> std::sync::Arc<dyn crate::federation::SchemaResolver> {
        self.schema_resolver
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// v2.5.0 (CIRISPersist#102 Ask 8) — install a custom
    /// hardware-attestation policy. Defaults to
    /// [`crate::federation::HardwareAttestationPolicy::default`].
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

    /// Install the Merkle-hook signer for v1.5.0 audit-service
    /// transparency. Engine layer wires this in at construction with
    /// `Arc::clone(&self.local_signer)`. Passing `None` disables
    /// the hook (no-op path). Idempotent — calling twice replaces
    /// the prior signer.
    ///
    /// # Phase C scope
    ///
    /// Only the field + setter are added in Phase C; Engine-layer
    /// wiring lands in Phase G/H.
    #[cfg(feature = "cirisaudit")]
    pub fn set_merkle_signer(&self, signer: Option<std::sync::Arc<crate::signing::LocalSigner>>) {
        // RwLock write — set-once at startup, but rwlock keeps the
        // surface flexible for live reconfigures (e.g. key rotation).
        let mut guard = self
            .merkle_signer
            .write()
            .unwrap_or_else(|p| p.into_inner());
        *guard = signer;
    }

    /// Snapshot the currently-installed Merkle signer (Phase C
    /// ingest path uses this to gate the hook).
    #[cfg(feature = "cirisaudit")]
    pub fn merkle_signer(&self) -> Option<std::sync::Arc<crate::signing::LocalSigner>> {
        let guard = self.merkle_signer.read().unwrap_or_else(|p| p.into_inner());
        guard.clone()
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
    /// v4.0 (CIRISPersist#160, FSD §4.4) — delegate to the
    /// `FederationDirectory` occurrence→identity lookup; `None` means
    /// the singleton-identity fallback (occurrence == identity).
    async fn resolve_identity_for_occurrence(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Option<String>, Error> {
        use crate::federation::FederationDirectory;
        let io = self
            .lookup_identity_for_occurrence(occurrence_key_id)
            .await
            .map_err(|e| Error::Backend(format!("resolve_identity_for_occurrence: {e}")))?;
        Ok(io.map(|o| o.identity_key_id))
    }

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
                            deployment_type, deployment_region, deployment_trust_mode, \
                            verification_source, cohort_scope, cohort_target_id";
        const N_COLS: usize = 36;

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
            // v2.0 verification_source column (V044, #91).
            params.push(Box::new(row.verification_source.as_wire_str().to_owned()));
            // v4.0 cohort_scope + target columns (V060, #160). The
            // ingest pipeline resolved the self-target already; persist
            // records the (scope, target) the §4.3 read-gate filters on.
            params.push(Box::new(row.cohort_scope.clone()));
            params.push(Box::new(row.cohort_target_id.clone()));
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

    /// v0.7.4 (CIRISPersist#19) — batch-UPDATE the V009
    /// `extracted_features` column for `(trace_id, thought_id)` pairs
    /// the post-ingest pipeline ran extract on. Called from
    /// `IngestPipeline::receive_and_persist` after the row INSERT.
    ///
    /// Bulk path uses `UNNEST` of three arrays — single round-trip
    /// regardless of batch size. Returns the affected-row count;
    /// caller uses for diagnostic / metrics purposes (count drift
    /// signals INSERT/UPDATE skew, not a hard failure).
    ///
    /// Idempotent: re-running with the same inputs replaces the JSONB
    /// value (UPDATE-by-equality, no Conflict surface).
    #[cfg(feature = "extract")]
    async fn update_features_batch(
        &self,
        updates: &[(String, String, crate::pipeline::extract::Features)],
    ) -> Result<u64, Error> {
        if updates.is_empty() {
            return Ok(0);
        }
        let trace_ids: Vec<&str> = updates.iter().map(|(t, _, _)| t.as_str()).collect();
        let thought_ids: Vec<&str> = updates.iter().map(|(_, th, _)| th.as_str()).collect();
        let features_json: Vec<serde_json::Value> = updates
            .iter()
            .map(|(_, _, f)| serde_json::to_value(f))
            .collect::<Result<_, _>>()
            .map_err(|e| Error::Backend(format!("features serialize: {e}")))?;

        let client = self.get_client().await?;
        let n = client
            .execute(
                "UPDATE cirislens.trace_events AS t \
                 SET extracted_features = u.features \
                 FROM (\
                     SELECT \
                         UNNEST($1::text[]) AS trace_id, \
                         UNNEST($2::text[]) AS thought_id, \
                         UNNEST($3::jsonb[]) AS features\
                 ) AS u \
                 WHERE t.trace_id = u.trace_id AND t.thought_id = u.thought_id",
                &[&trace_ids, &thought_ids, &features_json],
            )
            .await
            .map_err(|e| Error::Backend(format!("update_features_batch: {e}")))?;
        Ok(n)
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
                let b64: String = row.safe_get_with(0, Error::Backend)?;
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
        let total: i64 = count_row.safe_get_with(0, Error::Backend)?;

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
        let sample: Vec<String> = rows
            .iter()
            .map(|r| r.safe_get_with(0, Error::Backend))
            .collect::<Result<_, _>>()?;

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
        //
        // v3.12.x (CIRISPersist#156) — wrap the `run_async` call in
        // the migration-timing diagnostic. The diagnostic silently
        // no-ops without `CIRIS_PERSIST_MIGRATION_TIMING_LOG` set;
        // when set, it appends one JSON-Lines entry per migration
        // apply documenting total_wall_us + applied_count +
        // applied_versions. See `crate::store::migration_timing`.
        let migration_started = std::time::Instant::now();
        let report_result = embedded::migrations::runner()
            .set_migration_table_name("ciris_persist_schema_history")
            .run_async(&mut lock_client)
            .await;
        let elapsed = migration_started.elapsed();
        let migration_result = match report_result {
            Ok(report) => {
                let applied = report.applied_migrations();
                let applied_versions = applied
                    .iter()
                    .map(|m| m.version().to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                crate::store::migration_timing::append(
                    &crate::store::migration_timing::MigrationTiming {
                        backend: "postgres",
                        elapsed,
                        applied_count: applied.len(),
                        applied_versions,
                    },
                );
                Ok(())
            }
            Err(e) => Err(migration_error("migrations", e)),
        };

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
            .map(|row| row.safe_get_with::<String, _, _, _>(0, Error::Backend))
            .collect::<Result<_, _>>()?;

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
                .map(|row| row.safe_get_with::<String, _, _, _>(0, Error::Backend))
                .collect::<Result<_, _>>()?;

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
                            deployment_trust_mode, verification_source, \
                            cohort_scope, cohort_target_id \
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
                            deployment_trust_mode, verification_source, \
                            cohort_scope, cohort_target_id \
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

// ─── Pipeline read surface (v0.6.0-α5, CIRISPersist#19) ───────────
//
// Inherent methods on `PostgresBackend` for reading the V009
// pipeline JSONB columns (`extracted_features`, `classifications`).
// Not part of the `Backend` trait — pipeline reads are postgres-only
// for v0.6.0; memory + sqlite backends don't have to mirror this
// surface. Promote to a trait method in v0.6.1 if a sovereign-mode
// embedded pipeline emerges.

impl PostgresBackend {
    /// v0.6.0-α5 (CIRISPersist#19) — read typed [`Features`] for a
    /// `(trace_id, thought_id)` pair from
    /// `cirislens.trace_events.extracted_features` (V009 column).
    ///
    /// Returns `Ok(None)` when:
    /// - The trace/thought pair has no rows, OR
    /// - The pipeline hasn't yet run on those rows
    ///   (`extracted_features IS NULL` — pre-v0.6.0 or
    ///   pipeline-skipped ingest paths).
    ///
    /// Wire format: the JSONB column stores the serde-encoded
    /// `Features` type (V009 contract). Wire shape changes within
    /// v0.6.x are additive only; breaking shape changes get a new
    /// JSONB column + migration.
    #[cfg(feature = "extract")]
    pub async fn read_features(
        &self,
        trace_id: &str,
        thought_id: &str,
    ) -> Result<Option<crate::pipeline::extract::Features>, Error> {
        let client = self.get_client().await?;
        let row_opt = client
            .query_opt(
                "SELECT extracted_features \
                 FROM cirislens.trace_events \
                 WHERE trace_id = $1 AND thought_id = $2 \
                   AND extracted_features IS NOT NULL \
                 LIMIT 1",
                &[&trace_id, &thought_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("read_features: {e}")))?;
        match row_opt {
            None => Ok(None),
            Some(row) => {
                let v: serde_json::Value =
                    row.safe_get_with("extracted_features", Error::Backend)?;
                let features: crate::pipeline::extract::Features = serde_json::from_value(v)
                    .map_err(|e| Error::Backend(format!("extracted_features JSONB decode: {e}")))?;
                Ok(Some(features))
            }
        }
    }

    /// v0.6.0-α5 (CIRISPersist#19) — read per-component classification
    /// matches for a `(trace_id, thought_id)` pair from
    /// `cirislens.trace_events.classifications` (V009 column).
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
        let client = self.get_client().await?;
        let row_opt = client
            .query_opt(
                "SELECT classifications \
                 FROM cirislens.trace_events \
                 WHERE trace_id = $1 AND thought_id = $2 \
                   AND classifications IS NOT NULL \
                 LIMIT 1",
                &[&trace_id, &thought_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("read_classifications: {e}")))?;
        match row_opt {
            None => Ok(Vec::new()),
            Some(row) => {
                let v: serde_json::Value = row.safe_get_with("classifications", Error::Backend)?;
                let parsed: Vec<Vec<crate::pipeline::classify::ContentClassMatch>> =
                    serde_json::from_value(v).map_err(|e| {
                        Error::Backend(format!("classifications JSONB decode: {e}"))
                    })?;
                Ok(parsed)
            }
        }
    }

    /// v1.5.8 (CIRISPersist#57) — write the V009 `extracted_features`
    /// column for a `(trace_id, thought_id)` pair. Public write path
    /// for the agent's AdaptiveFilter output → persist round-trip.
    ///
    /// Caller contract: "set this if the row exists." If no
    /// `cirislens.trace_events` row matches `(trace_id, thought_id)`,
    /// the UPDATE affects 0 rows and we return `Ok(())` (matches the
    /// canonical pipeline classify-stage UPDATE semantics — the row
    /// must already be in the table; this method does not insert).
    #[cfg(feature = "extract")]
    pub async fn write_features(
        &self,
        trace_id: &str,
        thought_id: &str,
        features: &crate::pipeline::extract::Features,
    ) -> Result<(), Error> {
        let features_json = serde_json::to_value(features)
            .map_err(|e| Error::Backend(format!("write_features encode: {e}")))?;
        let client = self.get_client().await?;
        client
            .execute(
                "UPDATE cirislens.trace_events \
                 SET extracted_features = $1 \
                 WHERE trace_id = $2 AND thought_id = $3",
                &[&features_json, &trace_id, &thought_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("write_features: {e}")))?;
        Ok(())
    }

    /// v1.5.8 (CIRISPersist#57) — write the V009 `classifications`
    /// column for a `(trace_id, thought_id)` pair. Public write path
    /// for the agent's AdaptiveFilter output → persist round-trip.
    ///
    /// Caller contract: "set this if the row exists." If no
    /// `cirislens.trace_events` row matches `(trace_id, thought_id)`,
    /// the UPDATE affects 0 rows and we return `Ok(())` (matches the
    /// canonical pipeline classify-stage UPDATE semantics — the row
    /// must already be in the table; this method does not insert).
    #[cfg(feature = "classify")]
    pub async fn write_classifications(
        &self,
        trace_id: &str,
        thought_id: &str,
        classifications: &Vec<Vec<crate::pipeline::classify::ContentClassMatch>>,
    ) -> Result<(), Error> {
        let cls_json = serde_json::to_value(classifications)
            .map_err(|e| Error::Backend(format!("write_classifications encode: {e}")))?;
        let client = self.get_client().await?;
        client
            .execute(
                "UPDATE cirislens.trace_events \
                 SET classifications = $1 \
                 WHERE trace_id = $2 AND thought_id = $3",
                &[&cls_json, &trace_id, &thought_id],
            )
            .await
            .map_err(|e| Error::Backend(format!("write_classifications: {e}")))?;
        Ok(())
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

#[async_trait::async_trait]
impl crate::federation::FederationDirectory for PostgresBackend {
    async fn put_public_key(
        &self,
        record: crate::federation::SignedKeyRecord,
    ) -> Result<(), crate::federation::Error> {
        let mut row = record.record;

        // v2.5.0 (CIRISPersist#102 Ask 8) — hardware-attestation
        // admission gate for accord_holder rows. Runs BEFORE
        // persist_row_hash + INSERT so rejected rows leave no trace.
        // Non-accord-holder rows skip the gate (the column is
        // informational for them).
        if row.identity_type == crate::federation::types::identity_type::ACCORD_HOLDER {
            self.hardware_attestation_policy().check(
                &row.key_id,
                row.attestation_evidence.as_ref(),
                chrono::Utc::now(),
            )?;
        }

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
        //
        // v1.3.0 (CIRISPersist#46): write the roles list to the TEXT[]
        // column. Empty Vec maps to NULL via Option<&Vec<String>>.
        let roles_param: Option<&Vec<String>> = if row.roles.is_empty() {
            None
        } else {
            Some(&row.roles)
        };
        let result = client
            .execute(
                "INSERT INTO cirislens.federation_keys (\
                    key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                    identity_type, identity_ref, valid_from, valid_until, registration_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles, \
                    attestation_evidence\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) \
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
                    &roles_param,
                    &row.attestation_evidence,
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
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles, \
                    attestation_evidence \
                 FROM cirislens.federation_keys WHERE key_id = $1",
                &[&key_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("lookup federation_keys: {e}"))
            })?;
        row_opt.map(pg_row_to_key_record).transpose()
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
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles, \
                    attestation_evidence \
                 FROM cirislens.federation_keys WHERE identity_ref = $1",
                &[&identity_ref],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("lookup_keys_for_identity: {e}"))
            })?;
        rows.into_iter().map(pg_row_to_key_record).collect()
    }

    /// v2.6.0 (CIRISPersist#105) — enumerate `federation_keys` rows
    /// by `identity_type` column. `ORDER BY key_id` for stable lex
    /// order; V004's composite index
    /// `idx_federation_keys_identity_type_identity_ref` already
    /// covers the leftmost `WHERE identity_type = $1` predicate.
    async fn list_keys_by_identity_type(
        &self,
        identity_type: &str,
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
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles, \
                    attestation_evidence \
                 FROM cirislens.federation_keys WHERE identity_type = $1 \
                 ORDER BY key_id",
                &[&identity_type],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("list_keys_by_identity_type: {e}"))
            })?;
        rows.into_iter().map(pg_row_to_key_record).collect()
    }

    async fn put_attestation(
        &self,
        attestation: crate::federation::SignedAttestation,
    ) -> Result<(), crate::federation::Error> {
        let mut row = attestation.attestation;

        // v3.4.0 (CIRISPersist#123) — trust-threshold gate runs FIRST.
        if !row.attesting_key_id.is_empty() {
            if let Some(gate) = self.admission_gate() {
                gate.check_federation(&row.attesting_key_id).await?;
            }
        }

        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;

        // v2.4.0 (CIRISPersist#102 Ask 3) — admission gate. Look up
        // the attesting key's `identity_type` first; this also
        // turns a missing-FK case into a typed `InvalidArgument`
        // before the eventual FK violation. Runs BEFORE
        // persist_row_hash + INSERT so rejected rows leave no
        // trace.
        let attesting_row = client
            .query_opt(
                "SELECT identity_type FROM cirislens.federation_keys WHERE key_id = $1",
                &[&row.attesting_key_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("lookup attesting identity_type: {e}"))
            })?;
        let attesting_identity_type: String = match attesting_row {
            Some(r) => r.safe_get_with("identity_type", crate::federation::Error::Backend)?,
            None => {
                return Err(crate::federation::Error::InvalidArgument(format!(
                    "attesting_key_id {} does not exist in federation_keys",
                    row.attesting_key_id
                )));
            }
        };
        let dim = crate::federation::admission::envelope_dimension(&row.attestation_envelope);
        crate::federation::admission::DimensionAdmissionPolicy::default().check(
            &row.attestation_type,
            dim,
            &attesting_identity_type,
        )?;

        // v3.9.1 (CIRISPersist#150 Ask 3, CEG 0.4 §4.2.4) — cohort_scope
        // admission-gate validation. Rejects out-of-closed-set values
        // (notably `global`, a §8.1.8 feed-name, never a wire value)
        // BEFORE persist_row_hash + INSERT so rejected rows leave no
        // trace. The V056 CHECK constraint is the defense-in-depth
        // backstop for direct-SQL bypass.
        crate::federation::admission::check_cohort_scope(&row.cohort_scope)?;

        // v3.0.0 (CIRISPersist#116, CEG 0.2 §6.1) — structural-composer
        // dedup on `(references_attestation_id, attestation_type,
        // attesting_key_id)`. A second put with the same triple is a
        // silent no-op so structural composers are idempotent on
        // replay per §6.1. JSONB `->>` extracts the
        // references_attestation_id from the envelope for the WHERE
        // clause; the cost is one indexable scan per write but only
        // for structural composers (most traffic is `scores`).
        if crate::federation::precedence::is_structural_composer(&row.attestation_type) {
            if let Some(ref_id) =
                crate::federation::precedence::references_attestation_id_from_envelope(
                    &row.attestation_envelope,
                )
            {
                let exists = client
                    .query_opt(
                        "SELECT 1 AS one FROM cirislens.federation_attestations \
                         WHERE attestation_type = $1 \
                           AND attesting_key_id = $2 \
                           AND attestation_envelope->>'references_attestation_id' = $3 \
                         LIMIT 1",
                        &[&row.attestation_type, &row.attesting_key_id, &ref_id],
                    )
                    .await
                    .map_err(|e| {
                        crate::federation::Error::Backend(format!(
                            "dedup lookup structural composer: {e}"
                        ))
                    })?;
                if exists.is_some() {
                    return Ok(());
                }
            }
        }

        // v2.5.0 (CIRISPersist#102 Ask 4) — envelope-schema admission
        // hook. Runs AFTER the dimension gate; only fires on `scores`
        // attestations with a resolvable axis. Skipped on
        // `NoOpSchemaResolver` (the default) — existing callers
        // observe no behavior change.
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

        // v0.5.8 — parse attestation_id to uuid::Uuid before binding;
        // see put_revocation comment for context (the same `$1::uuid`
        // String-binding rejection applies here).
        let attestation_uuid = uuid::Uuid::parse_str(&row.attestation_id).map_err(|e| {
            crate::federation::Error::InvalidArgument(format!(
                "attestation_id is not a valid UUID: {e}"
            ))
        })?;

        // postgres-types has no built-in `f64`→`NUMERIC` conversion
        // (neither `Some(f64)` nor `None::<f64>` against a NUMERIC
        // column serialize — closes the long-standing bug exposed
        // when CIRISPersist#102's admission-gate tests first
        // exercised `put_attestation` in postgres end-to-end at
        // v2.4.0). Cast the bind via `$5::float8::numeric` so
        // postgres performs the conversion server-side; both
        // `Some(f64)` and `None` bind as `Option<f64>` against
        // `FLOAT8` (which DOES have a built-in serializer),
        // then PG widens to NUMERIC for storage.
        // v3.7.0 (CIRISPersist#146, CEG 0.6) — subject_key_ids JSONB +
        // withdraws_admission_rule SMALLINT (NULL on non-withdraws).
        let subject_key_ids_jsonb = serde_json::Value::Array(
            row.subject_key_ids
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect(),
        );
        let withdraws_admission_rule: Option<i16> = row.withdraws_admission_rule.map(|v| v as i16);
        client
            .execute(
                "INSERT INTO cirislens.federation_attestations (\
                    attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                    weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, \
                    subject_key_ids, withdraws_admission_rule, cohort_scope\
                 ) VALUES ($1, $2, $3, $4, $5::float8::numeric, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)",
                &[
                    &attestation_uuid,
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
                    &subject_key_ids_jsonb,
                    &withdraws_admission_rule,
                    &row.cohort_scope,
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
                // weight::float8 AS weight — tokio-postgres has no
                // built-in NUMERIC<->f64 deserializer, so the read
                // path mirrors the write-path `$5::float8::numeric`
                // cast. NUMERIC→FLOAT8 is the inverse hop;
                // pg_row_to_attestation reads weight as Option<f64>.
                "SELECT attestation_id::text, attesting_key_id, attested_key_id, attestation_type, \
                    weight::float8 AS weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope \
                 FROM cirislens.federation_attestations \
                 WHERE attested_key_id = $1 \
                 ORDER BY asserted_at DESC",
                &[&attested_key_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("list_attestations_for: {e}"))
            })?;
        rows.into_iter().map(pg_row_to_attestation).collect()
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
                // weight::float8 AS weight — see list_attestations_for.
                "SELECT attestation_id::text, attesting_key_id, attested_key_id, attestation_type, \
                    weight::float8 AS weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope \
                 FROM cirislens.federation_attestations \
                 WHERE attesting_key_id = $1 \
                 ORDER BY asserted_at DESC",
                &[&attesting_key_id],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("list_attestations_by: {e}")))?;
        rows.into_iter().map(pg_row_to_attestation).collect()
    }

    async fn put_revocation(
        &self,
        revocation: crate::federation::SignedRevocation,
    ) -> Result<(), crate::federation::Error> {
        let mut row = revocation.revocation;

        // v3.4.0 (CIRISPersist#123) — trust gate first.
        if !row.revoking_key_id.is_empty() {
            if let Some(gate) = self.admission_gate() {
                gate.check_federation(&row.revoking_key_id).await?;
            }
        }

        // v3.11.0 (CIRISPersist#143) — region closed-set gate +
        // anti-rollback monotonicity. Both run BEFORE persist_row_hash
        // is computed and BEFORE INSERT (same discipline as v3.9.1
        // cohort_scope admission).
        crate::federation::check_observed_region(&row.observed_region)?;
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        check_revocation_anti_rollback_postgres(&client, &row.revoked_key_id, row.scrub_timestamp)
            .await?;

        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;

        let original_content_hash = hex::decode(&row.original_content_hash).map_err(|e| {
            crate::federation::Error::InvalidArgument(format!(
                "original_content_hash hex decode: {e}"
            ))
        })?;

        // v0.5.8 — parse revocation_id to uuid::Uuid before binding.
        // Some tokio-postgres / postgres-types version combinations
        // refuse to serialize &String against a `$1::uuid` cast param
        // (driver's type-check sees the inferred UUID column type and
        // rejects String). Parsing to Uuid + binding via the
        // with-uuid-1 feature sidesteps the inference question.
        let revocation_uuid = uuid::Uuid::parse_str(&row.revocation_id).map_err(|e| {
            crate::federation::Error::InvalidArgument(format!(
                "revocation_id is not a valid UUID: {e}"
            ))
        })?;

        client
            .execute(
                "INSERT INTO cirislens.federation_revocations (\
                    revocation_id, revoked_key_id, revoking_key_id, reason, \
                    revoked_at, effective_at, revocation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, observed_region, \
                    persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
                &[
                    &revocation_uuid,
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
                    &row.observed_region,
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
                    scrub_key_id, scrub_timestamp, pqc_completed_at, observed_region, persist_row_hash \
                 FROM cirislens.federation_revocations \
                 WHERE revoked_key_id = $1 \
                 ORDER BY effective_at DESC",
                &[&revoked_key_id],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("revocations_for: {e}")))?;
        rows.into_iter().map(pg_row_to_revocation).collect()
    }

    // ── CEG 0.7 identity_occurrence + family (v3.12.0, #153) ───────

    async fn put_identity_occurrence(
        &self,
        occurrence: crate::federation::SignedIdentityOccurrence,
    ) -> Result<(), crate::federation::Error> {
        let mut row = occurrence.identity_occurrence;
        crate::federation::check_device_class(&row.device_class)?;
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        client
            .execute(
                "INSERT INTO cirislens.federation_identity_occurrences (\
                    identity_key_id, occurrence_key_id, device_class, \
                    hardware_attestation, asserted_at, valid_until, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &row.identity_key_id,
                    &row.occurrence_key_id,
                    &row.device_class,
                    &row.hardware_attestation,
                    &row.asserted_at,
                    &row.valid_until,
                    &row.persist_row_hash,
                ],
            )
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("foreign key") {
                    crate::federation::Error::InvalidArgument(format!(
                        "FK constraint violated on identity_occurrence insert: {msg}"
                    ))
                } else {
                    crate::federation::Error::Backend(format!("insert identity_occurrence: {msg}"))
                }
            })?;
        Ok(())
    }

    async fn list_identity_occurrences_for(
        &self,
        identity_key_id: &str,
    ) -> Result<Vec<crate::federation::IdentityOccurrence>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let rows = client
            .query(
                "SELECT identity_key_id, occurrence_key_id, device_class, \
                    hardware_attestation, asserted_at, valid_until, persist_row_hash \
                 FROM cirislens.federation_identity_occurrences \
                 WHERE identity_key_id = $1 \
                 ORDER BY occurrence_key_id ASC",
                &[&identity_key_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("list_identity_occurrences_for: {e}"))
            })?;
        rows.into_iter()
            .map(pg_row_to_identity_occurrence)
            .collect()
    }

    async fn lookup_identity_for_occurrence(
        &self,
        occurrence_key_id: &str,
    ) -> Result<Option<crate::federation::IdentityOccurrence>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let row_opt = client
            .query_opt(
                "SELECT identity_key_id, occurrence_key_id, device_class, \
                    hardware_attestation, asserted_at, valid_until, persist_row_hash \
                 FROM cirislens.federation_identity_occurrences \
                 WHERE occurrence_key_id = $1 LIMIT 1",
                &[&occurrence_key_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("lookup_identity_for_occurrence: {e}"))
            })?;
        row_opt.map(pg_row_to_identity_occurrence).transpose()
    }

    async fn put_family(
        &self,
        family: crate::federation::SignedFamily,
    ) -> Result<(), crate::federation::Error> {
        let mut row = family.family;
        crate::federation::check_consensus_protocol_form(&row.consensus_protocol)?;
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
        let members_value = serde_json::to_value(&row.members)
            .map_err(|e| crate::federation::Error::Backend(format!("members serialize: {e}")))?;
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        client
            .execute(
                "INSERT INTO cirislens.federation_families (\
                    family_key_id, family_name, members, founded_at, \
                    consensus_protocol, consensus_protocol_entrenched, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &row.family_key_id,
                    &row.family_name,
                    &members_value,
                    &row.founded_at,
                    &row.consensus_protocol,
                    &row.consensus_protocol_entrenched,
                    &row.persist_row_hash,
                ],
            )
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("foreign key") {
                    crate::federation::Error::InvalidArgument(format!(
                        "FK constraint violated on family insert: {msg}"
                    ))
                } else {
                    crate::federation::Error::Backend(format!("insert family: {msg}"))
                }
            })?;
        Ok(())
    }

    async fn lookup_family(
        &self,
        family_key_id: &str,
    ) -> Result<Option<crate::federation::Family>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let row_opt = client
            .query_opt(
                "SELECT family_key_id, family_name, members, founded_at, \
                    consensus_protocol, consensus_protocol_entrenched, persist_row_hash \
                 FROM cirislens.federation_families WHERE family_key_id = $1",
                &[&family_key_id],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("lookup_family: {e}")))?;
        row_opt.map(pg_row_to_family).transpose()
    }

    async fn list_families_for_member(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<crate::federation::Family>, crate::federation::Error> {
        // Uses the V059 GIN jsonb_path_ops index — the `@>` containment
        // operator is the matching shape (members @> [{"key_id": "X"}]).
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let containment = serde_json::json!([{ "key_id": member_identity_key_id }]);
        let rows = client
            .query(
                "SELECT family_key_id, family_name, members, founded_at, \
                    consensus_protocol, consensus_protocol_entrenched, persist_row_hash \
                 FROM cirislens.federation_families \
                 WHERE members @> $1 \
                 ORDER BY family_key_id ASC",
                &[&containment],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("list_families_for_member: {e}"))
            })?;
        rows.into_iter().map(pg_row_to_family).collect()
    }

    async fn put_community(
        &self,
        community: crate::federation::SignedCommunity,
    ) -> Result<(), crate::federation::Error> {
        let mut row = community.community;
        crate::federation::check_consensus_protocol_form(&row.consensus_protocol)?;
        row.persist_row_hash = crate::federation::types::compute_persist_row_hash(&row)?;
        let members_value = serde_json::to_value(&row.members)
            .map_err(|e| crate::federation::Error::Backend(format!("members serialize: {e}")))?;
        let policy_blob_value = row.policy_blob.clone();
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        client
            .execute(
                "INSERT INTO cirislens.federation_communities (\
                    community_key_id, community_name, members, founded_at, \
                    consensus_protocol, policy_blob, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &row.community_key_id,
                    &row.community_name,
                    &members_value,
                    &row.founded_at,
                    &row.consensus_protocol,
                    &policy_blob_value,
                    &row.persist_row_hash,
                ],
            )
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("foreign key") {
                    crate::federation::Error::InvalidArgument(format!(
                        "FK constraint violated on community insert: {msg}"
                    ))
                } else {
                    crate::federation::Error::Backend(format!("insert community: {msg}"))
                }
            })?;
        Ok(())
    }

    async fn lookup_community(
        &self,
        community_key_id: &str,
    ) -> Result<Option<crate::federation::Community>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let row_opt = client
            .query_opt(
                "SELECT community_key_id, community_name, members, founded_at, \
                    consensus_protocol, policy_blob, persist_row_hash \
                 FROM cirislens.federation_communities WHERE community_key_id = $1",
                &[&community_key_id],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("lookup_community: {e}")))?;
        row_opt.map(pg_row_to_community).transpose()
    }

    async fn list_communities_for_member(
        &self,
        member_identity_key_id: &str,
    ) -> Result<Vec<crate::federation::Community>, crate::federation::Error> {
        // Uses the V060 GIN index — the `@>` containment operator is the
        // matching shape (members @> [{"key_id": "X"}]).
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let containment = serde_json::json!([{ "key_id": member_identity_key_id }]);
        let rows = client
            .query(
                "SELECT community_key_id, community_name, members, founded_at, \
                    consensus_protocol, policy_blob, persist_row_hash \
                 FROM cirislens.federation_communities \
                 WHERE members @> $1 \
                 ORDER BY community_key_id ASC",
                &[&containment],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("list_communities_for_member: {e}"))
            })?;
        rows.into_iter().map(pg_row_to_community).collect()
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
                // weight::float8 AS weight — see list_attestations_for.
                "SELECT attestation_id::text, attesting_key_id, attested_key_id, attestation_type, \
                    weight::float8 AS weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope \
                 FROM cirislens.federation_attestations WHERE attestation_id = $1::uuid",
                &[&attestation_id],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("attach lookup: {e}")))?;
        let mut row = row_opt
            .map(pg_row_to_attestation)
            .transpose()?
            .ok_or_else(|| {
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
                    scrub_key_id, scrub_timestamp, pqc_completed_at, observed_region, persist_row_hash \
                 FROM cirislens.federation_revocations WHERE revocation_id = $1::uuid",
                &[&revocation_id],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("attach lookup: {e}")))?;
        let mut row = row_opt
            .map(pg_row_to_revocation)
            .transpose()?
            .ok_or_else(|| {
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
        rows.into_iter()
            .map(|row| {
                let mk_err = crate::federation::Error::Backend;
                Ok(crate::federation::HybridPendingRow {
                    id: row.safe_get_with("key_id", mk_err)?,
                    envelope: row.safe_get_with("registration_envelope", mk_err)?,
                    classical_sig_b64: row.safe_get_with("scrub_signature_classical", mk_err)?,
                })
            })
            .collect()
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
        rows.into_iter()
            .map(|row| {
                let mk_err = crate::federation::Error::Backend;
                Ok(crate::federation::HybridPendingRow {
                    id: row.safe_get_with("attestation_id", mk_err)?,
                    envelope: row.safe_get_with("attestation_envelope", mk_err)?,
                    classical_sig_b64: row.safe_get_with("scrub_signature_classical", mk_err)?,
                })
            })
            .collect()
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
        rows.into_iter()
            .map(|row| {
                let mk_err = crate::federation::Error::Backend;
                Ok(crate::federation::HybridPendingRow {
                    id: row.safe_get_with("revocation_id", mk_err)?,
                    envelope: row.safe_get_with("revocation_envelope", mk_err)?,
                    classical_sig_b64: row.safe_get_with("scrub_signature_classical", mk_err)?,
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
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let trust_type_str = grant.trust_type.as_str();
        let trust_relationship_str = grant.trust_relationship.as_str();
        // PG TEXT[] binds from `&Vec<String>` via postgres-types' built-in.
        let domains_owned: Vec<String> = grant.trust_domains.clone().unwrap_or_default();
        let domains_param: Option<&Vec<String>> = if grant.trust_domains.is_some() {
            Some(&domains_owned)
        } else {
            None
        };
        // UPSERT — overwrite trust columns, preserve everything else
        // (pubkey, signature envelope, etc.). `trusted_at = NOW()` on
        // the UPDATE branch so a re-grant refreshes the timestamp.
        // `expires_at` re-set on UPDATE so a re-grant clears any prior
        // soft-delete.
        let n = client
            .execute(
                "UPDATE cirislens.federation_keys \
                 SET trust_type = $2, \
                     trust_relationship = $3, \
                     trust_domains = $4, \
                     trusted_by = $5, \
                     trusted_at = NOW(), \
                     expires_at = $6 \
                 WHERE key_id = $1",
                &[
                    &grant.key,
                    &trust_type_str,
                    &trust_relationship_str,
                    &domains_param,
                    &grant.trusted_by,
                    &grant.expires_at,
                ],
            )
            .await
            .map_err(|e| {
                let msg = e.to_string();
                // V020 CHECK constraints (no self-trust /
                // registry-requires-domains) surface as `check_violation`
                // here — translate to InvalidArgument for parity with
                // the API-layer guards in `validate_trust_grant`.
                if msg.contains("federation_keys_no_self_trust")
                    || msg.contains("federation_keys_registry_requires_domains")
                    || msg.contains("violates check constraint")
                {
                    crate::federation::Error::InvalidArgument(format!(
                        "trust column CHECK violated: {msg}"
                    ))
                } else {
                    crate::federation::Error::Backend(format!("grant_trust UPDATE: {msg}"))
                }
            })?;
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
        // Idempotent: only set expires_at if the row isn't already
        // expired. UPDATE returning zero rows is fine (idempotent
        // no-op); only backend errors propagate.
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        client
            .execute(
                "UPDATE cirislens.federation_keys \
                 SET expires_at = NOW() \
                 WHERE key_id = $1 \
                   AND trusted_by IS NOT NULL \
                   AND (expires_at IS NULL OR expires_at > NOW())",
                &[&key],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("revoke_trust: {e}")))?;
        // `revoked_by` is logged in the audit chain by the caller —
        // not stored on the row directly (the row keeps the original
        // `trusted_by` for forensic continuity).
        let _ = revoked_by;
        Ok(())
    }

    async fn lookup_trust(
        &self,
        key: &str,
    ) -> Result<Option<crate::federation::TrustRow>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let row_opt = client
            .query_opt(
                "SELECT key_id, trust_type, trust_relationship, trust_domains, \
                        trusted_by, trusted_at, expires_at \
                 FROM cirislens.federation_keys \
                 WHERE key_id = $1 AND trusted_by IS NOT NULL",
                &[&key],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("lookup_trust: {e}")))?;
        row_opt.map(pg_row_to_trust_row).transpose()
    }

    async fn list_trusted_keys(
        &self,
        filter: crate::federation::TrustFilter,
    ) -> Result<Vec<crate::federation::TrustRow>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        // Build the parametric WHERE clause. Owned-string holders
        // keep references alive for the tokio_postgres ToSql binding.
        let mut where_parts: Vec<String> = vec!["trusted_by IS NOT NULL".to_owned()];
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if !filter.include_expired {
            where_parts.push("(expires_at IS NULL OR expires_at > NOW())".to_owned());
        }
        if let Some(t) = filter.trust_type {
            params.push(Box::new(t.as_str().to_owned()));
            where_parts.push(format!("trust_type = ${}", params.len()));
        }
        if let Some(rel) = filter.trust_relationship {
            params.push(Box::new(rel.as_str().to_owned()));
            where_parts.push(format!("trust_relationship = ${}", params.len()));
        }
        if let Some(domain) = filter.domain {
            params.push(Box::new(domain));
            where_parts.push(format!("${} = ANY(trust_domains)", params.len()));
        }
        let where_sql = where_parts.join(" AND ");
        let sql = format!(
            "SELECT key_id, trust_type, trust_relationship, trust_domains, \
                    trusted_by, trusted_at, expires_at \
             FROM cirislens.federation_keys \
             WHERE {where_sql} \
             ORDER BY trusted_at DESC, key_id DESC"
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("list_trusted_keys: {e}")))?;
        rows.into_iter().map(pg_row_to_trust_row).collect()
    }

    // ── Goals (v2.10.0, CIRISPersist#114) ──────────────────────────

    async fn put_goal(
        &self,
        goal: crate::federation::Goal,
    ) -> Result<(), crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let new_hash = crate::federation::types::compute_persist_row_hash(&goal)?;
        let canonical_text = crate::federation::canonicalize_goal_text(&goal.goal_text);
        let scope_kind = goal.scope.scope_kind_str();
        let scope_cohort_id = goal.scope.cohort_id().map(|s| s.to_owned());
        let meta_dimension = goal.meta_goal_alignment.dimension.as_str();
        let meta_deliberation_value: Option<serde_json::Value> =
            match &goal.meta_goal_alignment.deliberation_ref {
                Some(d) => Some(serde_json::to_value(d).map_err(|e| {
                    crate::federation::Error::Backend(format!("deliberation_ref serialize: {e}"))
                })?),
                None => None,
            };

        // Idempotent on (goal_id, persist_row_hash). ON CONFLICT DO
        // NOTHING — same shape as put_public_key. If the row exists
        // with a different hash we raise Conflict; otherwise the
        // INSERT is a no-op.
        let result = client
            .execute(
                "INSERT INTO cirislens.goals (\
                    goal_id, declared_by_key_id, declared_at, goal_text, \
                    goal_text_canonical, scope_kind, scope_cohort_id, \
                    meta_dimension, meta_rationale, meta_deliberation, \
                    retired_at, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
                 ON CONFLICT (goal_id) DO NOTHING",
                &[
                    &goal.goal_id,
                    &goal.declared_by_key_id,
                    &goal.declared_at,
                    &goal.goal_text,
                    &canonical_text,
                    &scope_kind,
                    &scope_cohort_id,
                    &meta_dimension,
                    &goal.meta_goal_alignment.rationale,
                    &meta_deliberation_value,
                    &goal.retired_at,
                    &new_hash,
                ],
            )
            .await
            .map_err(|e| {
                // tokio_postgres `Display` only shows "db error: ..."
                // at the top level; the structured SQLSTATE +
                // constraint name live on the DB-error payload.
                let sqlstate = e.as_db_error().map(|d| d.code().code().to_owned());
                let constraint = e
                    .as_db_error()
                    .and_then(|d| d.constraint().map(|s| s.to_owned()));
                let msg = e.to_string();
                match sqlstate.as_deref() {
                    // 23503 = foreign_key_violation
                    Some("23503") => crate::federation::Error::InvalidArgument(format!(
                        "FK constraint violated on put_goal: {msg}"
                    )),
                    // 23514 = check_violation — disambiguate by
                    // constraint name; goals_scope_cohort_discriminant
                    // and the column CHECKs both fire here.
                    Some("23514") => crate::federation::Error::InvalidArgument(format!(
                        "CHECK constraint violated on put_goal \
                         (constraint={:?}): {msg}",
                        constraint.as_deref().unwrap_or("?")
                    )),
                    _ => crate::federation::Error::Backend(format!("insert goal: {msg}")),
                }
            })?;

        if result == 0 {
            let existing: Option<String> = client
                .query_opt(
                    "SELECT persist_row_hash FROM cirislens.goals WHERE goal_id = $1",
                    &[&goal.goal_id],
                )
                .await
                .map_err(|e| {
                    crate::federation::Error::Backend(format!("put_goal conflict check: {e}"))
                })?
                .map(|r| r.get(0));
            if let Some(existing_hash) = existing {
                if existing_hash != new_hash {
                    return Err(crate::federation::Error::Conflict(format!(
                        "goal_id {} already exists with different content",
                        goal.goal_id
                    )));
                }
            }
        }
        Ok(())
    }

    async fn get_goal(
        &self,
        goal_id: uuid::Uuid,
    ) -> Result<Option<crate::federation::Goal>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let row_opt = client
            .query_opt(
                "SELECT goal_id, declared_by_key_id, declared_at, goal_text, \
                        scope_kind, scope_cohort_id, meta_dimension, meta_rationale, \
                        meta_deliberation, retired_at \
                 FROM cirislens.goals WHERE goal_id = $1",
                &[&goal_id],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("get_goal: {e}")))?;
        row_opt.map(pg_row_to_goal).transpose()
    }

    async fn list_goals(
        &self,
        filter: crate::federation::GoalsFilter,
    ) -> Result<Vec<crate::federation::Goal>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if !filter.include_retired {
            where_parts.push("retired_at IS NULL".to_owned());
        }
        if let Some(key) = filter.declared_by_key_id {
            params.push(Box::new(key));
            where_parts.push(format!("declared_by_key_id = ${}", params.len()));
        }
        if let Some(dim) = filter.m1_dimension {
            params.push(Box::new(dim.as_str().to_owned()));
            where_parts.push(format!("meta_dimension = ${}", params.len()));
        }
        if let Some(kind) = filter.scope_kind {
            params.push(Box::new(kind));
            where_parts.push(format!("scope_kind = ${}", params.len()));
        }
        if let Some(cohort) = filter.cohort_id {
            params.push(Box::new(cohort));
            where_parts.push(format!("scope_cohort_id = ${}", params.len()));
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
             FROM cirislens.goals \
             {where_sql} \
             ORDER BY declared_at, goal_id"
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("list_goals: {e}")))?;
        rows.into_iter().map(pg_row_to_goal).collect()
    }

    async fn retire_goal(
        &self,
        goal_id: uuid::Uuid,
        retired_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        // Idempotent: WHERE retired_at IS NULL gates double-retire.
        // Existence is established via a separate SELECT so a missing
        // row surfaces as InvalidArgument and not a silent no-op.
        let exists = client
            .query_opt(
                "SELECT 1 FROM cirislens.goals WHERE goal_id = $1",
                &[&goal_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("retire_goal existence: {e}"))
            })?;
        if exists.is_none() {
            return Err(crate::federation::Error::InvalidArgument(format!(
                "goal_id {goal_id} does not exist"
            )));
        }
        client
            .execute(
                "UPDATE cirislens.goals SET retired_at = $2 \
                 WHERE goal_id = $1 AND retired_at IS NULL",
                &[&goal_id, &retired_at],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("retire_goal update: {e}")))?;
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

        // Build the federation_keys row + its persist_row_hash up
        // front (same shape as put_public_key but without the
        // SignedKeyRecord scrub envelope — peer-add is operator-
        // authorized at the UniFFI layer, not via a peer-supplied
        // signed registration envelope).
        let now = chrono::Utc::now();
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
            // 32 bytes of zeros — placeholder sha; no signed envelope.
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

        let mut client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("begin tx: {e}")))?;

        // The federation_keys row — ON CONFLICT (key_id) DO NOTHING
        // (matches put_public_key semantics; conflict-with-different-
        // content is detected by re-reading the existing pubkey
        // below).
        let original_content_hash = hex::decode(&key.original_content_hash).map_err(|e| {
            crate::federation::Error::InvalidArgument(format!(
                "original_content_hash hex decode: {e}"
            ))
        })?;
        let roles_param: Option<&Vec<String>> = None;
        tx.execute(
            "INSERT INTO cirislens.federation_keys (\
                key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                identity_type, identity_ref, valid_from, valid_until, registration_envelope, \
                original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, roles, \
                attestation_evidence\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) \
             ON CONFLICT (key_id) DO NOTHING",
            &[
                &key.key_id,
                &key.pubkey_ed25519_base64,
                &key.pubkey_ml_dsa_65_base64,
                &key.algorithm,
                &key.identity_type,
                &key.identity_ref,
                &key.valid_from,
                &key.valid_until,
                &key.registration_envelope,
                &original_content_hash,
                &key.scrub_signature_classical,
                &key.scrub_signature_pqc,
                &key.scrub_key_id,
                &key.scrub_timestamp,
                &key.pqc_completed_at,
                &key.persist_row_hash,
                &roles_param,
                &key.attestation_evidence,
            ],
        )
        .await
        .map_err(|e| {
            crate::federation::Error::Backend(format!("add_peer_record federation_keys: {e}"))
        })?;

        // Conflict detection on federation_keys: if pubkey differs,
        // the operator is trying to re-add a peer with a different
        // pubkey under the same key_id → reject.
        let existing_pubkey: Option<String> = tx
            .query_opt(
                "SELECT pubkey_ed25519_base64 FROM cirislens.federation_keys WHERE key_id = $1",
                &[&key.key_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!(
                    "add_peer_record federation_keys conflict check: {e}"
                ))
            })?
            .map(|r| r.safe_get_with(0, crate::federation::Error::Backend))
            .transpose()?;
        if let Some(existing) = existing_pubkey {
            if existing != key.pubkey_ed25519_base64 {
                return Err(crate::federation::Error::Conflict(format!(
                    "key_id {} already exists with different pubkey",
                    key.key_id
                )));
            }
        }

        // The federation_peer_metadata row.
        // - Soft-removed re-add: clear removed_at + repopulate;
        // - Live row with matching transport: idempotent no-op;
        // - Live row with different transport: Conflict.
        let existing_meta: Option<tokio_postgres::Row> = tx
            .query_opt(
                "SELECT transport_identity, removed_at \
                 FROM cirislens.federation_peer_metadata WHERE key_id = $1",
                &[&key.key_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!(
                    "add_peer_record peer_metadata existence: {e}"
                ))
            })?;
        match existing_meta {
            Some(row) => {
                let existing_transport: Option<String> =
                    row.safe_get_with(0, crate::federation::Error::Backend)?;
                let existing_removed_at: Option<chrono::DateTime<chrono::Utc>> =
                    row.safe_get_with(1, crate::federation::Error::Backend)?;
                if existing_removed_at.is_some() {
                    // Re-add: replace with the new row.
                    tx.execute(
                        "UPDATE cirislens.federation_peer_metadata SET \
                            alias = NULL, trust = 'untrusted', notes = NULL, \
                            policy_blob = NULL, transport_identity = $2, \
                            removed_at = NULL, inserted_at = $3, updated_at = $3, \
                            persist_row_hash = $4 \
                         WHERE key_id = $1",
                        &[
                            &key.key_id,
                            &meta.transport_identity,
                            &now,
                            &meta.persist_row_hash,
                        ],
                    )
                    .await
                    .map_err(|e| {
                        crate::federation::Error::Backend(format!(
                            "add_peer_record peer_metadata re-add: {e}"
                        ))
                    })?;
                } else if existing_transport == transport_identity {
                    // Idempotent no-op.
                } else {
                    return Err(crate::federation::Error::Conflict(format!(
                        "peer_metadata row for key_id {} already exists with different transport_identity",
                        key.key_id
                    )));
                }
            }
            None => {
                tx.execute(
                    "INSERT INTO cirislens.federation_peer_metadata (\
                        key_id, alias, trust, notes, policy_blob, \
                        transport_identity, removed_at, inserted_at, updated_at, persist_row_hash\
                     ) VALUES ($1, NULL, 'untrusted', NULL, NULL, $2, NULL, $3, $3, $4)",
                    &[
                        &key.key_id,
                        &meta.transport_identity,
                        &now,
                        &meta.persist_row_hash,
                    ],
                )
                .await
                .map_err(|e| {
                    crate::federation::Error::Backend(format!(
                        "add_peer_record peer_metadata insert: {e}"
                    ))
                })?;
            }
        }

        tx.commit()
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("commit tx: {e}")))?;
        Ok(())
    }

    async fn remove_peer_record(
        &self,
        key_id: &str,
        hard: bool,
    ) -> Result<(), crate::federation::Error> {
        let mut client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("begin tx: {e}")))?;

        // PeerNotFound when no live metadata row.
        let meta_exists: Option<bool> = tx
            .query_opt(
                "SELECT removed_at IS NULL \
                 FROM cirislens.federation_peer_metadata WHERE key_id = $1",
                &[&key_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("remove_peer_record existence: {e}"))
            })?
            .map(|r| r.safe_get_with(0, crate::federation::Error::Backend))
            .transpose()?;
        match meta_exists {
            Some(true) => { /* live row — proceed */ }
            _ => {
                return Err(crate::federation::Error::PeerNotFound {
                    key_id: key_id.to_owned(),
                });
            }
        }

        if hard {
            // Defensive: count attestations that would be orphaned.
            let count_row = tx
                .query_one(
                    "SELECT COUNT(*)::BIGINT FROM cirislens.federation_attestations \
                     WHERE attesting_key_id = $1 OR attested_key_id = $1 OR scrub_key_id = $1",
                    &[&key_id],
                )
                .await
                .map_err(|e| {
                    crate::federation::Error::Backend(format!(
                        "remove_peer_record attestation count: {e}"
                    ))
                })?;
            let count: i64 = count_row.safe_get_with(0, crate::federation::Error::Backend)?;
            if count > 0 {
                return Err(crate::federation::Error::HardRemoveWithActiveAttestations {
                    key_id: key_id.to_owned(),
                    attestation_count: count as usize,
                });
            }
            // Cascade: DELETE federation_keys; ON DELETE CASCADE on
            // federation_peer_metadata.key_id picks up the sibling.
            tx.execute(
                "DELETE FROM cirislens.federation_keys WHERE key_id = $1",
                &[&key_id],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!(
                    "remove_peer_record federation_keys delete: {e}"
                ))
            })?;
        } else {
            // Soft-remove: bump removed_at + updated_at + recompute
            // persist_row_hash. We need to compute the new hash with
            // the new field values, which means fetching the current
            // row first (to populate the rest of the PeerMetadataRow
            // shape that the canonicalizer hashes).
            let row = tx
                .query_one(
                    "SELECT key_id, alias, trust, notes, policy_blob, \
                            transport_identity, inserted_at \
                     FROM cirislens.federation_peer_metadata WHERE key_id = $1",
                    &[&key_id],
                )
                .await
                .map_err(|e| {
                    crate::federation::Error::Backend(format!(
                        "remove_peer_record peer_metadata fetch: {e}"
                    ))
                })?;
            let now = chrono::Utc::now();
            let new_row = pg_row_to_peer_metadata_for_hash(&row, Some(now), now)?;
            let new_hash = crate::federation::types::compute_persist_row_hash(&new_row)?;
            tx.execute(
                "UPDATE cirislens.federation_peer_metadata SET \
                    removed_at = $2, updated_at = $2, persist_row_hash = $3 \
                 WHERE key_id = $1",
                &[&key_id, &now, &new_hash],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!(
                    "remove_peer_record peer_metadata update: {e}"
                ))
            })?;
        }

        tx.commit()
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("commit tx: {e}")))?;
        Ok(())
    }

    async fn update_peer_alias(
        &self,
        key_id: &str,
        alias: Option<String>,
    ) -> Result<(), crate::federation::Error> {
        pg_update_peer_field(self, key_id, PgPeerUpdate::Alias(alias)).await
    }

    async fn update_peer_trust(
        &self,
        key_id: &str,
        trust: crate::federation::TrustClass,
    ) -> Result<(), crate::federation::Error> {
        pg_update_peer_field(self, key_id, PgPeerUpdate::Trust(trust)).await
    }

    async fn update_peer_notes(
        &self,
        key_id: &str,
        notes: Option<String>,
    ) -> Result<(), crate::federation::Error> {
        pg_update_peer_field(self, key_id, PgPeerUpdate::Notes(notes)).await
    }

    async fn update_peer_policy(
        &self,
        key_id: &str,
        policy: crate::federation::PeerPolicyBlob,
    ) -> Result<(), crate::federation::Error> {
        pg_update_peer_field(self, key_id, PgPeerUpdate::Policy(policy)).await
    }

    // v3.4.1 (CIRISPersist#127) — read accessor; returns `None` for
    // non-existent or soft-removed peers.
    async fn peer_metadata_for(
        &self,
        key_id: &str,
    ) -> Result<Option<crate::federation::PeerMetadataRow>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let row_opt = client
            .query_opt(
                "SELECT key_id, alias, trust, notes, policy_blob, \
                        transport_identity, removed_at, inserted_at, updated_at, persist_row_hash \
                 FROM cirislens.federation_peer_metadata WHERE key_id = $1",
                &[&key_id],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("peer_metadata_for: {e}")))?;
        let Some(row) = row_opt else { return Ok(None) };
        let removed_at: Option<chrono::DateTime<chrono::Utc>> =
            row.safe_get_with("removed_at", crate::federation::Error::Backend)?;
        if removed_at.is_some() {
            return Ok(None);
        }
        let inserted_at: chrono::DateTime<chrono::Utc> =
            row.safe_get_with("inserted_at", crate::federation::Error::Backend)?;
        let updated_at: chrono::DateTime<chrono::Utc> =
            row.safe_get_with("updated_at", crate::federation::Error::Backend)?;
        let persist_row_hash: String =
            row.safe_get_with("persist_row_hash", crate::federation::Error::Backend)?;
        let mut meta = pg_row_to_peer_metadata_for_hash(&row, None, updated_at)?;
        meta.inserted_at = inserted_at;
        meta.updated_at = updated_at;
        meta.persist_row_hash = persist_row_hash;
        Ok(Some(meta))
    }
}

// ─── Peer-metadata update helpers (v3.1.0, CIRISPersist#117) ───────
//
// The four `update_peer_*` methods share the same shape: fetch the
// existing row, mutate one field, recompute persist_row_hash, write
// back inside a single transaction. Encapsulated as an enum + a
// shared helper so the SQL templates don't drift across the four
// methods.

enum PgPeerUpdate {
    Alias(Option<String>),
    Trust(crate::federation::TrustClass),
    Notes(Option<String>),
    Policy(crate::federation::PeerPolicyBlob),
}

/// Apply a peer-metadata field update under a single transaction.
/// Returns `Error::PeerNotFound` when the row is missing or
/// soft-removed (matches the v3.1.0 #117 contract — updates against
/// removed peers fail loudly, not silently).
async fn pg_update_peer_field(
    backend: &PostgresBackend,
    key_id: &str,
    update: PgPeerUpdate,
) -> Result<(), crate::federation::Error> {
    let mut client = backend
        .get_client()
        .await
        .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
    let tx = client
        .transaction()
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("begin tx: {e}")))?;

    // PeerNotFound if no live row.
    let row_opt = tx
        .query_opt(
            "SELECT key_id, alias, trust, notes, policy_blob, \
                    transport_identity, removed_at, inserted_at \
             FROM cirislens.federation_peer_metadata WHERE key_id = $1",
            &[&key_id],
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("update_peer_* fetch: {e}")))?;
    let row = match row_opt {
        None => {
            return Err(crate::federation::Error::PeerNotFound {
                key_id: key_id.to_owned(),
            });
        }
        Some(r) => r,
    };
    let removed_at: Option<chrono::DateTime<chrono::Utc>> =
        row.safe_get_with("removed_at", crate::federation::Error::Backend)?;
    if removed_at.is_some() {
        return Err(crate::federation::Error::PeerNotFound {
            key_id: key_id.to_owned(),
        });
    }

    // Hydrate the row, then mutate the targeted field. Recompute
    // persist_row_hash against the mutated shape.
    let inserted_at: chrono::DateTime<chrono::Utc> =
        row.safe_get_with("inserted_at", crate::federation::Error::Backend)?;
    let mut mut_row = pg_row_to_peer_metadata_for_hash(&row, None, chrono::Utc::now())?;
    mut_row.inserted_at = inserted_at;
    let now = chrono::Utc::now();
    mut_row.updated_at = now;

    match &update {
        PgPeerUpdate::Alias(v) => mut_row.alias = v.clone(),
        PgPeerUpdate::Trust(v) => mut_row.trust = *v,
        PgPeerUpdate::Notes(v) => mut_row.notes = v.clone(),
        PgPeerUpdate::Policy(v) => mut_row.policy_blob = Some(v.clone()),
    }
    let new_hash = crate::federation::types::compute_persist_row_hash(&mut_row)?;

    let sql = match update {
        PgPeerUpdate::Alias(_) => {
            "UPDATE cirislens.federation_peer_metadata SET \
                alias = $2, updated_at = $3, persist_row_hash = $4 WHERE key_id = $1"
        }
        PgPeerUpdate::Trust(_) => {
            "UPDATE cirislens.federation_peer_metadata SET \
                trust = $2, updated_at = $3, persist_row_hash = $4 WHERE key_id = $1"
        }
        PgPeerUpdate::Notes(_) => {
            "UPDATE cirislens.federation_peer_metadata SET \
                notes = $2, updated_at = $3, persist_row_hash = $4 WHERE key_id = $1"
        }
        PgPeerUpdate::Policy(_) => {
            "UPDATE cirislens.federation_peer_metadata SET \
                policy_blob = $2, updated_at = $3, persist_row_hash = $4 WHERE key_id = $1"
        }
    };

    // Bind the value for $2 based on which variant we have.
    let res = match &update {
        PgPeerUpdate::Alias(_) => {
            tx.execute(sql, &[&key_id, &mut_row.alias, &now, &new_hash])
                .await
        }
        PgPeerUpdate::Trust(_) => {
            let trust_wire = mut_row.trust.as_wire_str();
            tx.execute(sql, &[&key_id, &trust_wire, &now, &new_hash])
                .await
        }
        PgPeerUpdate::Notes(_) => {
            tx.execute(sql, &[&key_id, &mut_row.notes, &now, &new_hash])
                .await
        }
        PgPeerUpdate::Policy(_) => {
            // policy_blob is serde_json::Value (JSONB column).
            let value = mut_row
                .policy_blob
                .as_ref()
                .map(|p| p.as_value().clone())
                .unwrap_or(serde_json::Value::Null);
            tx.execute(sql, &[&key_id, &value, &now, &new_hash]).await
        }
    };
    res.map_err(|e| crate::federation::Error::Backend(format!("update_peer_* update: {e}")))?;

    tx.commit()
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("commit tx: {e}")))?;
    Ok(())
}

/// Hydrate a `federation_peer_metadata` row into a
/// [`crate::federation::PeerMetadataRow`] for the canonical-bytes
/// hash. `removed_at_override` lets the soft-remove path stamp the
/// new `removed_at` value without re-fetching after UPDATE.
fn pg_row_to_peer_metadata_for_hash(
    row: &tokio_postgres::Row,
    removed_at_override: Option<chrono::DateTime<chrono::Utc>>,
    updated_at: chrono::DateTime<chrono::Utc>,
) -> Result<crate::federation::PeerMetadataRow, crate::federation::Error> {
    let key_id: String = row.safe_get_with("key_id", crate::federation::Error::Backend)?;
    let alias: Option<String> = row.safe_get_with("alias", crate::federation::Error::Backend)?;
    let trust_str: String = row.safe_get_with("trust", crate::federation::Error::Backend)?;
    let trust = crate::federation::TrustClass::from_wire_str(&trust_str).ok_or_else(|| {
        crate::federation::Error::Backend(format!(
            "federation_peer_metadata.trust has unrecognized value {trust_str:?} \
             (CHECK constraint bypass — direct SQL write?)"
        ))
    })?;
    let notes: Option<String> = row.safe_get_with("notes", crate::federation::Error::Backend)?;
    let policy_value: Option<serde_json::Value> =
        row.safe_get_with("policy_blob", crate::federation::Error::Backend)?;
    let policy_blob = policy_value.map(crate::federation::PeerPolicyBlob);
    let transport_identity: Option<String> =
        row.safe_get_with("transport_identity", crate::federation::Error::Backend)?;
    let inserted_at: chrono::DateTime<chrono::Utc> = row
        .safe_get_with("inserted_at", crate::federation::Error::Backend)
        .unwrap_or(updated_at);
    let removed_at = if removed_at_override.is_some() {
        removed_at_override
    } else {
        row.try_get::<_, Option<chrono::DateTime<chrono::Utc>>>("removed_at")
            .unwrap_or(None)
    };
    Ok(crate::federation::PeerMetadataRow {
        key_id,
        alias,
        trust,
        notes,
        policy_blob,
        transport_identity,
        removed_at,
        inserted_at,
        updated_at,
        persist_row_hash: String::new(),
    })
}

// ─── BlobStorage impl (v2.3, CIRISPersist#103) ─────────────────────
//
// Content-addressable byte storage. See `crate::federation::blobs` for
// the trait + types. Postgres uses BYTEA for the sha256 PK + the
// optional bytes_inline column; the holder attestation is emitted via
// the existing `cirislens.federation_attestations` write path inside
// the same transaction so a holder-attestation FK violation rolls back
// the blob row too (atomic put_blob semantic).

impl crate::federation::BlobStorage for PostgresBackend {
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
        let attestation_uuid = uuid::Uuid::parse_str(&attestation.attestation_id).map_err(|e| {
            crate::federation::BlobError::InvalidArgument(format!(
                "attestation_id is not a valid UUID: {e}"
            ))
        })?;
        let original_content_hash =
            hex::decode(&attestation.original_content_hash_hex).map_err(|e| {
                crate::federation::BlobError::InvalidArgument(format!(
                    "original_content_hash hex decode: {e}"
                ))
            })?;

        let storage_kind = body.storage_kind();
        let size_bytes_i64 = i64::try_from(body.size_bytes()).map_err(|_| {
            crate::federation::BlobError::InvalidArgument(
                "size_bytes exceeds i64 — federation_blobs.size_bytes is BIGINT".into(),
            )
        })?;
        let (bytes_inline_opt, external_ref_opt) = match &body {
            crate::federation::BlobBody::Inline(b) => (Some(b.clone()), None),
            crate::federation::BlobBody::External(e) => (None, Some(e.uri.clone())),
        };

        // 3. Compose the holder attestation envelope. Attestation type
        //    + envelope shape are centralized in
        //    crate::federation::blobs so list_holders can recompose
        //    the same prefix string.
        let attestation_type = crate::federation::holds_bytes_attestation_type(sha256);
        let attestation_envelope = crate::federation::holds_bytes_attestation_envelope(sha256);
        let attestation_row = crate::federation::Attestation {
            attestation_id: attestation.attestation_id.clone(),
            attesting_key_id: attestation.attesting_key_id.clone(),
            // A holder attestation attests the *holder itself* — the
            // attester says "I (key_id=X) hold the bytes." No second
            // key is involved.
            attested_key_id: attestation.attesting_key_id.clone(),
            attestation_type: attestation_type.clone(),
            weight: None,
            asserted_at: attestation.scrub_timestamp,
            expires_at: None,
            attestation_envelope,
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
        let attestation_envelope_jsonb = attestation_row.attestation_envelope.clone();
        let persist_row_hash = crate::federation::types::compute_persist_row_hash(&attestation_row)
            .map_err(|e| crate::federation::BlobError::Backend(format!("persist_row_hash: {e}")))?;

        // 4. Atomic transaction: insert blob row (idempotent on PK)
        //    THEN insert holder attestation. If the attestation FK
        //    fails, the blob row is rolled back too — caller sees no
        //    half-written state.
        let mut client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::BlobError::Backend(e.to_string()))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| crate::federation::BlobError::Backend(format!("begin tx: {e}")))?;

        let sha_vec = sha256.to_vec();
        tx.execute(
            "INSERT INTO cirislens.federation_blobs (\
                sha256, storage_kind, bytes_inline, external_ref, size_bytes, media_type\
             ) VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (sha256) DO NOTHING",
            &[
                &sha_vec,
                &storage_kind,
                &bytes_inline_opt,
                &external_ref_opt,
                &size_bytes_i64,
                &media_type,
            ],
        )
        .await
        .map_err(|e| {
            crate::federation::BlobError::Backend(format!("insert federation_blobs: {e}"))
        })?;

        // Holder attestation. Insert is idempotent at the
        // (attestation_id) PK; the caller supplies a fresh UUID per
        // call so the same host re-attesting the same blob lands as
        // a new row (audit chain — every put_blob leaves a trace).
        //
        // weight + expires_at + pqc_completed_at are omitted from the
        // INSERT column list — the holder attestation has no weight /
        // expiry / pqc_completed_at semantics, and omitting them lets
        // Postgres apply the column NULL default (which is unambiguous
        // without forcing postgres-types to resolve the NULL bind type
        // — there's no f64→NUMERIC built-in, so `&None::<f64>` against
        // weight NUMERIC errors with "error serializing parameter").
        let expires_at_null: Option<chrono::DateTime<chrono::Utc>> = None;
        let pqc_completed_at_null: Option<chrono::DateTime<chrono::Utc>> = None;
        tx.execute(
            "INSERT INTO cirislens.federation_attestations (\
                attestation_id, attesting_key_id, attested_key_id, attestation_type, \
                asserted_at, expires_at, attestation_envelope, \
                original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash\
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            &[
                &attestation_uuid,
                &attestation.attesting_key_id,
                &attestation.attesting_key_id,
                &attestation_type,
                &attestation.scrub_timestamp,
                &expires_at_null,
                &attestation_envelope_jsonb,
                &original_content_hash,
                &attestation.scrub_signature_classical,
                &attestation.scrub_signature_pqc,
                &attestation.scrub_key_id,
                &attestation.scrub_timestamp,
                &pqc_completed_at_null,
                &persist_row_hash,
            ],
        )
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("foreign key") {
                crate::federation::BlobError::AttestationEmissionFailed(format!(
                    "FK violation on holds_bytes attestation: {msg}"
                ))
            } else if msg.contains("duplicate key") {
                // attestation_id PK collision — caller reused a UUID.
                crate::federation::BlobError::AttestationEmissionFailed(format!(
                    "attestation_id collision: {msg}"
                ))
            } else {
                crate::federation::BlobError::Backend(format!(
                    "insert holds_bytes attestation: {msg}"
                ))
            }
        })?;

        tx.commit().await.map_err(|e| {
            crate::federation::BlobError::Backend(format!("commit blob+attestation: {e}"))
        })?;

        Ok(())
    }

    // v3.9.2 (CIRISPersist#153 Ask 5, CEG 0.7 §10.1.4) — store blob
    // bytes WITHOUT a holds_bytes attestation (structural invisibility
    // for cohort_scope self/family). Same byte-validation as put_blob;
    // no attestation, no admission gate (local content is the
    // operator's own data — #149 anti-rec).
    async fn store_blob_local(
        &self,
        sha256: &[u8; 32],
        body: crate::federation::BlobBody,
        media_type: Option<&str>,
    ) -> Result<(), crate::federation::BlobError> {
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
        let storage_kind = body.storage_kind();
        let size_bytes_i64 = i64::try_from(body.size_bytes()).map_err(|_| {
            crate::federation::BlobError::InvalidArgument(
                "size_bytes exceeds i64 — federation_blobs.size_bytes is BIGINT".into(),
            )
        })?;
        let (bytes_inline_opt, external_ref_opt) = match &body {
            crate::federation::BlobBody::Inline(b) => (Some(b.clone()), None),
            crate::federation::BlobBody::External(e) => (None, Some(e.uri.clone())),
        };
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::BlobError::Backend(e.to_string()))?;
        let sha_vec = sha256.to_vec();
        client
            .execute(
                "INSERT INTO cirislens.federation_blobs (\
                    sha256, storage_kind, bytes_inline, external_ref, size_bytes, media_type\
                 ) VALUES ($1, $2, $3, $4, $5, $6) \
                 ON CONFLICT (sha256) DO NOTHING",
                &[
                    &sha_vec,
                    &storage_kind,
                    &bytes_inline_opt,
                    &external_ref_opt,
                    &size_bytes_i64,
                    &media_type,
                ],
            )
            .await
            .map_err(|e| {
                crate::federation::BlobError::Backend(format!("store_blob_local insert: {e}"))
            })?;
        Ok(())
    }

    async fn get_blob(
        &self,
        sha256: &[u8; 32],
    ) -> Result<Option<crate::federation::BlobBody>, crate::federation::BlobError> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::BlobError::Backend(e.to_string()))?;
        let sha_vec = sha256.to_vec();
        // v3.4.0 (CIRISPersist#123) — single UPDATE … RETURNING to
        // bump the access tracker AND fetch the row in one
        // round-trip. NULL row_opt = blob absent.
        let row_opt = client
            .query_opt(
                "UPDATE cirislens.federation_blobs \
                    SET access_count = access_count + 1, \
                        last_accessed_at = NOW() \
                  WHERE sha256 = $1 \
                  RETURNING storage_kind, bytes_inline, external_ref, size_bytes, media_type",
                &[&sha_vec],
            )
            .await
            .map_err(|e| {
                crate::federation::BlobError::Backend(format!("get_blob update+select: {e}"))
            })?;
        let Some(row) = row_opt else {
            return Ok(None);
        };
        let storage_kind: String =
            row.safe_get_with("storage_kind", crate::federation::BlobError::Backend)?;
        match storage_kind.as_str() {
            "inline" => {
                let bytes: Vec<u8> =
                    row.safe_get_with("bytes_inline", crate::federation::BlobError::Backend)?;
                Ok(Some(crate::federation::BlobBody::Inline(bytes)))
            }
            "s3" | "external_url" => {
                let uri: String =
                    row.safe_get_with("external_ref", crate::federation::BlobError::Backend)?;
                let size_bytes_i64: i64 =
                    row.safe_get_with("size_bytes", crate::federation::BlobError::Backend)?;
                let size_bytes = u64::try_from(size_bytes_i64).map_err(|_| {
                    crate::federation::BlobError::Backend(
                        "size_bytes column went negative — schema CHECK violated".into(),
                    )
                })?;
                let media_type: Option<String> =
                    row.safe_get_with("media_type", crate::federation::BlobError::Backend)?;
                Ok(Some(crate::federation::BlobBody::External(
                    crate::federation::ExternalRef {
                        uri,
                        size_bytes,
                        media_type,
                    },
                )))
            }
            other => Err(crate::federation::BlobError::Backend(format!(
                "unknown storage_kind: {other}"
            ))),
        }
    }

    async fn has_blob(&self, sha256: &[u8; 32]) -> Result<bool, crate::federation::BlobError> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::BlobError::Backend(e.to_string()))?;
        let sha_vec = sha256.to_vec();
        // v3.4.0 (CIRISPersist#123) — UPDATE … RETURNING also serves
        // as existence check. RETURNING 1 returns 0 rows when no row
        // matches; the access-count bump happens iff the row exists.
        let row_opt = client
            .query_opt(
                "UPDATE cirislens.federation_blobs \
                    SET access_count = access_count + 1, \
                        last_accessed_at = NOW() \
                  WHERE sha256 = $1 \
                  RETURNING 1::int4 AS one",
                &[&sha_vec],
            )
            .await
            .map_err(|e| crate::federation::BlobError::Backend(format!("has_blob query: {e}")))?;
        Ok(row_opt.is_some())
    }

    async fn list_holders(
        &self,
        sha256: &[u8; 32],
    ) -> Result<Vec<String>, crate::federation::BlobError> {
        // v3.0.0 (CIRISPersist#116, CEG 0.2 §10.1.2):
        // 1. server-side prefix filter on attestation_type
        //    ("holds_bytes:sha256:<8-hex>") — narrows the candidate
        //    set well below O(table) without an extra index.
        // 2. client-side full-SHA filter against
        //    attestation_envelope->'evidence_refs' — discriminates
        //    32-bit prefix collisions.
        // 3. TTL filter — DEFAULT_HOLDS_BYTES_TTL (24 hours) measured
        //    from `asserted_at`; expired rows are treated as stale per
        //    CEG §10.1.2.
        // 4. ContentMiss withdraws filter — drop rows whose attester
        //    emitted a `withdraws` against the holds_bytes row's
        //    attestation_id (CEG §10.1.2 ContentMiss feedback loop).
        //
        // The TTL window is applied via the WHERE clause with
        // `asserted_at + interval` so the index on asserted_at (if
        // present) can prune. The withdraws filter is a NOT EXISTS
        // subquery against the same table; the JSONB extraction
        // `->>'references_attestation_id'` matches the structural-
        // composer dedup query shape.
        // v3.6.4 (CIRISPersist#130 reopen): bypass TTL when blob is
        // locally present in `federation_blobs`. See the SQLite mirror
        // for full rationale; in short, the bytes are definitive proof
        // of holding so the freshness window doesn't apply.
        let attestation_type = crate::federation::holds_bytes_attestation_type(sha256);
        let full_hex = hex::encode(sha256);
        let now = chrono::Utc::now();
        let ttl_seconds: i64 = i64::try_from(
            crate::federation::blobs::DEFAULT_HOLDS_BYTES_TTL.as_secs(),
        )
        .map_err(|_| {
            crate::federation::BlobError::Backend("DEFAULT_HOLDS_BYTES_TTL out of i64 range".into())
        })?;
        let cutoff = now - chrono::Duration::seconds(ttl_seconds);

        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::BlobError::Backend(e.to_string()))?;

        // v3.6.4 local-truth gate.
        let blob_locally_held = client
            .query_opt(
                "SELECT 1 FROM cirislens.federation_blobs WHERE sha256 = $1",
                &[&sha256.to_vec()],
            )
            .await
            .map_err(|e| {
                crate::federation::BlobError::Backend(format!(
                    "list_holders local-truth probe: {e}"
                ))
            })?
            .is_some();

        // When locally held, drop the `asserted_at > cutoff` clause so
        // every un-withdrawn holds_bytes attestation lands. The
        // withdraws NOT EXISTS subquery stays in both branches — it's
        // the active eviction signal, not a freshness backstop.
        let sql = if blob_locally_held {
            "SELECT attestation_id::text, attesting_key_id, attestation_envelope \
             FROM cirislens.federation_attestations \
             WHERE attestation_type = $1 \
               AND NOT EXISTS ( \
                 SELECT 1 FROM cirislens.federation_attestations w \
                 WHERE w.attestation_type = $2 \
                   AND w.attesting_key_id = \
                       cirislens.federation_attestations.attesting_key_id \
                   AND w.attestation_envelope->>'references_attestation_id' = \
                       cirislens.federation_attestations.attestation_id::text \
               )"
        } else {
            "SELECT attestation_id::text, attesting_key_id, attestation_envelope \
             FROM cirislens.federation_attestations \
             WHERE attestation_type = $1 \
               AND asserted_at > $3 \
               AND NOT EXISTS ( \
                 SELECT 1 FROM cirislens.federation_attestations w \
                 WHERE w.attestation_type = $2 \
                   AND w.attesting_key_id = \
                       cirislens.federation_attestations.attesting_key_id \
                   AND w.attestation_envelope->>'references_attestation_id' = \
                       cirislens.federation_attestations.attestation_id::text \
               )"
        };
        let withdraws_type = crate::federation::types::attestation_type::WITHDRAWS;
        let rows = if blob_locally_held {
            client
                .query(sql, &[&attestation_type, &withdraws_type])
                .await
        } else {
            client
                .query(sql, &[&attestation_type, &withdraws_type, &cutoff])
                .await
        }
        .map_err(|e| crate::federation::BlobError::Backend(format!("list_holders query: {e}")))?;

        let mut holders: Vec<String> = Vec::with_capacity(rows.len());
        let mut seen = std::collections::HashSet::new();
        for row in rows {
            let envelope: serde_json::Value = row.safe_get_with(
                "attestation_envelope",
                crate::federation::BlobError::Backend,
            )?;
            let matches = envelope
                .get("evidence_refs")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().any(|v| v.as_str() == Some(full_hex.as_str())))
                .unwrap_or(false);
            if !matches {
                continue;
            }
            let key_id: String =
                row.safe_get_with("attesting_key_id", crate::federation::BlobError::Backend)?;
            if seen.insert(key_id.clone()) {
                holders.push(key_id);
            }
        }
        Ok(holders)
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
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::BlobError::Backend(e.to_string()))?;

        // Gate: blob must be locally present.
        let sha_vec = sha256.to_vec();
        let blob_present: bool = client
            .query_opt(
                "SELECT 1 FROM cirislens.federation_blobs WHERE sha256 = $1",
                &[&sha_vec],
            )
            .await
            .map_err(|e| {
                crate::federation::BlobError::Backend(format!(
                    "list_local_holders blob lookup: {e}"
                ))
            })?
            .is_some();
        if !blob_present {
            return Ok(Vec::new());
        }

        // Collect every holds_bytes attestation for this SHA prefix
        // — NO TTL filter. The withdraws filter (NOT EXISTS) is
        // applied inline same as list_holders.
        let rows = client
            .query(
                "SELECT attestation_id::text, attesting_key_id, attestation_envelope \
                 FROM cirislens.federation_attestations \
                 WHERE attestation_type = $1 \
                   AND NOT EXISTS ( \
                     SELECT 1 FROM cirislens.federation_attestations w \
                     WHERE w.attestation_type = $2 \
                       AND w.attesting_key_id = \
                           cirislens.federation_attestations.attesting_key_id \
                       AND w.attestation_envelope->>'references_attestation_id' = \
                           cirislens.federation_attestations.attestation_id::text \
                   )",
                &[
                    &attestation_type,
                    &crate::federation::types::attestation_type::WITHDRAWS,
                ],
            )
            .await
            .map_err(|e| {
                crate::federation::BlobError::Backend(format!("list_local_holders query: {e}"))
            })?;

        let mut holders: Vec<String> = Vec::with_capacity(rows.len());
        let mut seen = std::collections::HashSet::new();
        for row in rows {
            let envelope: serde_json::Value = row.safe_get_with(
                "attestation_envelope",
                crate::federation::BlobError::Backend,
            )?;
            let matches = envelope
                .get("evidence_refs")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().any(|v| v.as_str() == Some(full_hex.as_str())))
                .unwrap_or(false);
            if !matches {
                continue;
            }
            let key_id: String =
                row.safe_get_with("attesting_key_id", crate::federation::BlobError::Backend)?;
            if seen.insert(key_id.clone()) {
                holders.push(key_id);
            }
        }
        Ok(holders)
    }

    async fn list_held_by(
        &self,
        attesting_key_id: &str,
    ) -> Result<Vec<[u8; 32]>, crate::federation::BlobError> {
        // v3.5.0 (CIRISPersist#125) — inverse of list_holders.
        //
        // Same four-clause filter discipline as list_holders, but
        // pivoted on `attesting_key_id` instead of `attestation_type`
        // (the prefix-match shifts to a LIKE).
        let prefix = crate::federation::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX;
        let now = chrono::Utc::now();
        let ttl_seconds: i64 = i64::try_from(
            crate::federation::blobs::DEFAULT_HOLDS_BYTES_TTL.as_secs(),
        )
        .map_err(|_| {
            crate::federation::BlobError::Backend("DEFAULT_HOLDS_BYTES_TTL out of i64 range".into())
        })?;
        let cutoff = now - chrono::Duration::seconds(ttl_seconds);
        let like_pattern = format!("{prefix}%");

        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::BlobError::Backend(e.to_string()))?;
        let rows = client
            .query(
                "SELECT attestation_id::text, attestation_envelope \
                 FROM cirislens.federation_attestations \
                 WHERE attesting_key_id = $1 \
                   AND attestation_type LIKE $2 \
                   AND asserted_at > $3 \
                   AND NOT EXISTS ( \
                     SELECT 1 FROM cirislens.federation_attestations w \
                     WHERE w.attestation_type = $4 \
                       AND w.attesting_key_id = $1 \
                       AND w.attestation_envelope->>'references_attestation_id' = \
                           cirislens.federation_attestations.attestation_id::text \
                   )",
                &[
                    &attesting_key_id,
                    &like_pattern,
                    &cutoff,
                    &crate::federation::types::attestation_type::WITHDRAWS,
                ],
            )
            .await
            .map_err(|e| {
                crate::federation::BlobError::Backend(format!("list_held_by query: {e}"))
            })?;

        let mut out: Vec<[u8; 32]> = Vec::with_capacity(rows.len());
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        for row in rows {
            let envelope: serde_json::Value = row.safe_get_with(
                "attestation_envelope",
                crate::federation::BlobError::Backend,
            )?;
            let sha_hex = envelope
                .get("evidence_refs")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str());
            let Some(sha_hex) = sha_hex else { continue };
            let mut sha = [0u8; 32];
            if hex::decode_to_slice(sha_hex, &mut sha).is_err() {
                continue;
            }
            if seen.insert(sha) {
                out.push(sha);
            }
        }
        Ok(out)
    }

    async fn evict_actor(
        &self,
        attesting_key_id: &str,
        signer: &dyn ciris_keyring::HardwareSigner,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<crate::federation::EvictActorReport, crate::federation::BlobError> {
        // v3.5.0 (CIRISPersist#125) — per-actor eviction. Same shape as
        // the SQLite impl; backend asymmetry is in the row source, not
        // the orchestration.
        use crate::federation::FederationDirectory;

        let all = self
            .list_attestations_by(attesting_key_id)
            .await
            .map_err(|e| {
                crate::federation::BlobError::Backend(format!(
                    "evict_actor: list_attestations_by failed: {e}"
                ))
            })?;

        let prefix = crate::federation::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX;
        let holds_bytes_rows: Vec<crate::federation::Attestation> = all
            .into_iter()
            .filter(|a| a.attestation_type.starts_with(prefix))
            .collect();

        let mut report = crate::federation::EvictActorReport::default();
        for prior in holds_bytes_rows {
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

            let withdraws_outcome = crate::federation::blobs::emit_withdraws_attestation_helper(
                &prior,
                attesting_key_id,
                signer,
                self,
                now,
            )
            .await;

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

impl PostgresBackend {
    /// v3.4.0 (CIRISPersist#123) — fetch the next `limit` eviction
    /// candidates ordered ASC by the full decay-weighted score
    /// `(access_count + 1) * exp(-ln(2) * Δt_secs / half_life_secs)`.
    /// Postgres ships `exp()` and `ln()` in its math stdlib, so the
    /// full ranking lives in SQL — single round-trip, no Rust-side
    /// re-sort.
    ///
    /// The `+1` matches [`crate::federation::EvictionDecay::score`]
    /// so SQL- and Rust-side rankings agree on the same tie-break.
    pub async fn sweep_candidates(
        &self,
        limit: i64,
        half_life_days: f64,
    ) -> Result<Vec<crate::federation::EvictionCandidate>, crate::federation::BlobError> {
        let half_life_secs = half_life_days.max(f64::EPSILON) * 86_400.0;
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::BlobError::Backend(format!("pool get: {e}")))?;
        let rows = client
            .query(
                "SELECT sha256, size_bytes, access_count, last_accessed_at \
                 FROM cirislens.federation_blobs \
                 ORDER BY \
                   (access_count + 1)::float8 * \
                   exp(-ln(2.0) * \
                       EXTRACT(EPOCH FROM (NOW() - last_accessed_at))::float8 / $1::float8) \
                   ASC, \
                   last_accessed_at ASC \
                 LIMIT $2",
                &[&half_life_secs, &limit],
            )
            .await
            .map_err(|e| {
                crate::federation::BlobError::Backend(format!("sweep_candidates query: {e}"))
            })?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let sha_vec: Vec<u8> =
                row.safe_get_with("sha256", crate::federation::BlobError::Backend)?;
            if sha_vec.len() != 32 {
                continue;
            }
            let mut sha = [0u8; 32];
            sha.copy_from_slice(&sha_vec);
            let size_bytes: i64 =
                row.safe_get_with("size_bytes", crate::federation::BlobError::Backend)?;
            let access_count: i64 =
                row.safe_get_with("access_count", crate::federation::BlobError::Backend)?;
            let last_accessed_at: chrono::DateTime<chrono::Utc> =
                row.safe_get_with("last_accessed_at", crate::federation::BlobError::Backend)?;
            out.push(crate::federation::EvictionCandidate {
                sha256: sha,
                size_bytes: size_bytes.max(0) as u64,
                access_count: access_count.max(0) as u64,
                last_accessed_at,
            });
        }
        Ok(out)
    }

    /// v3.4.0 (CIRISPersist#123) — delete one `federation_blobs` row
    /// by SHA. Returns `true` iff a row was removed.
    pub async fn delete_blob(
        &self,
        sha256: &[u8; 32],
    ) -> Result<bool, crate::federation::BlobError> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::BlobError::Backend(format!("pool get: {e}")))?;
        let sha_vec = sha256.to_vec();
        let n = client
            .execute(
                "DELETE FROM cirislens.federation_blobs WHERE sha256 = $1",
                &[&sha_vec],
            )
            .await
            .map_err(|e| crate::federation::BlobError::Backend(format!("delete_blob: {e}")))?;
        Ok(n > 0)
    }
}

/// Convert a postgres row from the trust columns of
/// `cirislens.federation_keys` into a [`crate::federation::TrustRow`].
/// SELECT clause MUST include exactly the 7 trust columns in any
/// order (we read by name).
fn pg_row_to_trust_row(
    row: tokio_postgres::Row,
) -> Result<crate::federation::TrustRow, crate::federation::Error> {
    let mk_err = crate::federation::Error::Backend;
    let trust_type_str: String = row.safe_get_with("trust_type", mk_err)?;
    let trust_relationship_str: String = row.safe_get_with("trust_relationship", mk_err)?;
    let trust_type =
        crate::federation::TrustType::from_wire_str(&trust_type_str).ok_or_else(|| {
            crate::federation::Error::Backend(format!("unknown trust_type: {trust_type_str}"))
        })?;
    let trust_relationship = crate::federation::TrustRelationship::from_wire_str(
        &trust_relationship_str,
    )
    .ok_or_else(|| {
        crate::federation::Error::Backend(format!(
            "unknown trust_relationship: {trust_relationship_str}"
        ))
    })?;
    // `trusted_by` is NOT NULL on a trust row by construction (the
    // caller filters on `trusted_by IS NOT NULL`), but Postgres
    // schema still has it nullable; treat absent as Backend error.
    let trusted_by: Option<String> = row.safe_get_with("trusted_by", mk_err)?;
    let trusted_by = trusted_by.ok_or_else(|| {
        crate::federation::Error::Backend(
            "pg_row_to_trust_row: trusted_by IS NULL — filter contract violated".into(),
        )
    })?;
    Ok(crate::federation::TrustRow {
        key: row.safe_get_with("key_id", mk_err)?,
        trust_type,
        trust_relationship,
        trust_domains: row.safe_get_with("trust_domains", mk_err)?,
        trusted_by,
        trusted_at: row.safe_get_with("trusted_at", mk_err)?,
        expires_at: row.safe_get_with("expires_at", mk_err)?,
    })
}

// ─── BlackholeRules impl (v3.2.0, CIRISPersist#120) ────────────────
//
// Operator-driven per-Reticulum-identity deny-list. Sibling to the
// FederationDirectory + BlobStorage traits — different concern (a
// transport-address deny-list, not a cryptographic-identity directory),
// same backend pool.
//
// All five methods route every column read through
// `PgRowExt::safe_get_with` (pre-commit hook bans bare `row.get(`).
// `record_hit` is a single-statement UPDATE — no transaction wrap,
// commutative-counter semantic (a race between two writers is
// double-incrementing, which is the desired hot-path behavior; the
// counter is observation, not consensus).

#[async_trait::async_trait]
impl crate::federation::BlackholeRules for PostgresBackend {
    async fn blackhole_list(
        &self,
    ) -> Result<Vec<crate::federation::BlackholeRecord>, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let rows = client
            .query(
                "SELECT identity_hash, until, reason, added_at, hits, persist_row_hash \
                 FROM cirislens.blackhole_rules \
                 ORDER BY added_at ASC",
                &[],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("blackhole_list: {e}")))?;
        rows.into_iter().map(pg_row_to_blackhole_record).collect()
    }

    async fn blackhole_upsert(
        &self,
        identity_hash: &[u8],
        until: Option<chrono::DateTime<chrono::Utc>>,
        reason: Option<&str>,
    ) -> Result<(), crate::federation::Error> {
        crate::federation::blackhole::validate_identity_hash_len(identity_hash)?;
        let now = chrono::Utc::now();
        // Compute the would-be `persist_row_hash` for the FRESH-insert
        // arm (added_at = now). The conflict path recomputes against
        // the existing row's added_at; do that inside the SQL via a
        // RETURNING + second UPDATE? No — simpler: pre-fetch the
        // existing added_at within the same client (no transaction
        // needed since upserts are operator-scale, not hot-path).
        let mut client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let tx = client.transaction().await.map_err(|e| {
            crate::federation::Error::Backend(format!("blackhole_upsert begin tx: {e}"))
        })?;

        let identity_vec = identity_hash.to_vec();
        let existing_row = tx
            .query_opt(
                "SELECT added_at FROM cirislens.blackhole_rules \
                 WHERE identity_hash = $1",
                &[&identity_vec],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("blackhole_upsert existence: {e}"))
            })?;

        let reason_owned = reason.map(str::to_owned);
        let added_at = match &existing_row {
            Some(r) => r.safe_get_with("added_at", crate::federation::Error::Backend)?,
            None => now,
        };
        let new_hash = crate::federation::blackhole::compute_blackhole_row_hash(
            identity_hash,
            &until,
            &reason_owned,
            &added_at,
        )?;

        if existing_row.is_some() {
            tx.execute(
                "UPDATE cirislens.blackhole_rules SET \
                    until = $2, reason = $3, persist_row_hash = $4 \
                 WHERE identity_hash = $1",
                &[&identity_vec, &until, &reason_owned, &new_hash],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("blackhole_upsert update: {e}"))
            })?;
        } else {
            tx.execute(
                "INSERT INTO cirislens.blackhole_rules \
                    (identity_hash, until, reason, added_at, hits, persist_row_hash) \
                 VALUES ($1, $2, $3, $4, 0, $5)",
                &[&identity_vec, &until, &reason_owned, &added_at, &new_hash],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("blackhole_upsert insert: {e}"))
            })?;
        }
        tx.commit().await.map_err(|e| {
            crate::federation::Error::Backend(format!("blackhole_upsert commit: {e}"))
        })?;
        Ok(())
    }

    async fn blackhole_remove(&self, identity_hash: &[u8]) -> Result<(), crate::federation::Error> {
        crate::federation::blackhole::validate_identity_hash_len(identity_hash)?;
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let identity_vec = identity_hash.to_vec();
        client
            .execute(
                "DELETE FROM cirislens.blackhole_rules WHERE identity_hash = $1",
                &[&identity_vec],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("blackhole_remove: {e}")))?;
        Ok(())
    }

    async fn blackhole_record_hit(
        &self,
        identity_hash: &[u8],
    ) -> Result<(), crate::federation::Error> {
        crate::federation::blackhole::validate_identity_hash_len(identity_hash)?;
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let identity_vec = identity_hash.to_vec();
        // Single-statement UPDATE; no transaction wrap. When no row
        // exists the rows-affected count is 0 — silent no-op.
        client
            .execute(
                "UPDATE cirislens.blackhole_rules \
                 SET hits = hits + 1 \
                 WHERE identity_hash = $1",
                &[&identity_vec],
            )
            .await
            .map_err(|e| crate::federation::Error::Backend(format!("blackhole_record_hit: {e}")))?;
        Ok(())
    }

    async fn blackhole_prune_expired(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, crate::federation::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::federation::Error::Backend(e.to_string()))?;
        let n = client
            .execute(
                "DELETE FROM cirislens.blackhole_rules \
                 WHERE until IS NOT NULL AND until < $1",
                &[&now],
            )
            .await
            .map_err(|e| {
                crate::federation::Error::Backend(format!("blackhole_prune_expired: {e}"))
            })?;
        Ok(n)
    }
}

/// Hydrate a `cirislens.blackhole_rules` row into a
/// [`crate::federation::BlackholeRecord`].
fn pg_row_to_blackhole_record(
    row: tokio_postgres::Row,
) -> Result<crate::federation::BlackholeRecord, crate::federation::Error> {
    let mk_err = crate::federation::Error::Backend;
    Ok(crate::federation::BlackholeRecord {
        identity_hash: row.safe_get_with("identity_hash", mk_err)?,
        until: row.safe_get_with("until", mk_err)?,
        reason: row.safe_get_with("reason", mk_err)?,
        added_at: row.safe_get_with("added_at", mk_err)?,
        hits: row.safe_get_with("hits", mk_err)?,
        persist_row_hash: row.safe_get_with("persist_row_hash", mk_err)?,
    })
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
        row.safe_get_with(0, crate::outbound::Error::Backend)
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

        let mk_err = crate::outbound::Error::Backend;
        let attempt_count: i32 = row.safe_get_with(0, mk_err)?;
        let max_attempts: i32 = row.safe_get_with(1, mk_err)?;
        let enqueued_at: chrono::DateTime<chrono::Utc> = row.safe_get_with(2, mk_err)?;
        let ttl_seconds: i64 = row.safe_get_with(3, mk_err)?;

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
    // v0.5.4 (CIRISPersist#28) — typed NULL-safety via safe_get_with;
    // outbound::Error::Backend swallows the deserialize message.
    let mk_err = crate::outbound::Error::Backend;
    let status_str: String = row.safe_get_with("status", crate::outbound::Error::Backend)?;
    let status = OutboundStatus::from_wire_str(&status_str).ok_or_else(|| {
        crate::outbound::Error::Backend(format!(
            "unknown status in edge_outbound_queue: {status_str}"
        ))
    })?;
    let abandoned_reason_str: Option<String> =
        row.safe_get_with("abandoned_reason", crate::outbound::Error::Backend)?;
    let abandoned_reason = match abandoned_reason_str.as_deref() {
        Some(s) => Some(AbandonedReason::from_wire_str(s).ok_or_else(|| {
            crate::outbound::Error::Backend(format!("unknown abandoned_reason: {s}"))
        })?),
        None => None,
    };
    let body_sha256_vec: Vec<u8> =
        row.safe_get_with("body_sha256", crate::outbound::Error::Backend)?;
    if body_sha256_vec.len() != 32 {
        return Err(crate::outbound::Error::Backend(format!(
            "body_sha256 wrong length: {} (expected 32)",
            body_sha256_vec.len()
        )));
    }
    let mut body_sha256 = [0u8; 32];
    body_sha256.copy_from_slice(&body_sha256_vec);

    Ok(crate::outbound::OutboundRow {
        queue_id: row.safe_get_with("queue_id", mk_err)?,
        sender_key_id: row.safe_get_with("sender_key_id", mk_err)?,
        destination_key_id: row.safe_get_with("destination_key_id", mk_err)?,
        message_type: row.safe_get_with("message_type", mk_err)?,
        edge_schema_version: row.safe_get_with("edge_schema_version", mk_err)?,
        envelope_bytes: row.safe_get_with("envelope_bytes", mk_err)?,
        body_sha256,
        body_size_bytes: row.safe_get_with("body_size_bytes", mk_err)?,
        status,
        enqueued_at: row.safe_get_with("enqueued_at", mk_err)?,
        next_attempt_after: row.safe_get_with("next_attempt_after", mk_err)?,
        last_attempt_at: row.safe_get_with("last_attempt_at", mk_err)?,
        transport_delivered_at: row.safe_get_with("transport_delivered_at", mk_err)?,
        delivered_at: row.safe_get_with("delivered_at", mk_err)?,
        abandoned_at: row.safe_get_with("abandoned_at", mk_err)?,
        abandoned_reason,
        attempt_count: row.safe_get_with("attempt_count", mk_err)?,
        max_attempts: row.safe_get_with("max_attempts", mk_err)?,
        ttl_seconds: row.safe_get_with("ttl_seconds", mk_err)?,
        last_error_class: row.safe_get_with("last_error_class", mk_err)?,
        last_error_detail: row.safe_get_with("last_error_detail", mk_err)?,
        last_transport: row.safe_get_with("last_transport", mk_err)?,
        requires_ack: row.safe_get_with("requires_ack", mk_err)?,
        ack_timeout_seconds: row.safe_get_with("ack_timeout_seconds", mk_err)?,
        ack_envelope_bytes: row.safe_get_with("ack_envelope_bytes", mk_err)?,
        ack_received_at: row.safe_get_with("ack_received_at", mk_err)?,
        claimed_until: row.safe_get_with("claimed_until", mk_err)?,
        claimed_by: row.safe_get_with("claimed_by", mk_err)?,
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

// v0.5.4 (CIRISPersist#28) — three federation directory row decoders
// were infallible; bumped to Result<_, federation::Error> so a NULL in
// any column surfaces as a typed Backend error instead of a panic.
// Call sites collect via `::<Result<Vec<_>, _>>()`.
fn pg_row_to_key_record(
    row: tokio_postgres::Row,
) -> Result<crate::federation::KeyRecord, crate::federation::Error> {
    let mk_err = crate::federation::Error::Backend;
    let original_content_hash: Vec<u8> = row.safe_get_with("original_content_hash", mk_err)?;
    // v1.3.0 (CIRISPersist#46): `roles` column is TEXT[] on PG; NULL
    // / absent column maps to empty Vec. `safe_get_with` returns
    // Option<Vec<String>> via the schema column type — when the SELECT
    // didn't include `roles`, the column lookup errors, which we
    // swallow into an empty list. SELECT statements that need the
    // roles MUST include the column explicitly.
    let roles: Vec<String> = row
        .try_get::<_, Option<Vec<String>>>("roles")
        .ok()
        .flatten()
        .unwrap_or_default();
    // v2.5.0 (CIRISPersist#102 Ask 8): attestation_evidence is JSONB
    // NULL. `try_get::<_, Option<_>>` returns Ok(None) on NULL and
    // Err on missing-column; the outer `.ok().flatten()` collapses
    // both to `None`. Older SELECTs that didn't pull the column
    // (pre-v2.5.0 read paths) just see None.
    let attestation_evidence: Option<serde_json::Value> = row
        .try_get::<_, Option<serde_json::Value>>("attestation_evidence")
        .ok()
        .flatten();
    Ok(crate::federation::KeyRecord {
        key_id: row.safe_get_with("key_id", mk_err)?,
        pubkey_ed25519_base64: row.safe_get_with("pubkey_ed25519_base64", mk_err)?,
        pubkey_ml_dsa_65_base64: row.safe_get_with("pubkey_ml_dsa_65_base64", mk_err)?,
        algorithm: row.safe_get_with("algorithm", mk_err)?,
        identity_type: row.safe_get_with("identity_type", mk_err)?,
        identity_ref: row.safe_get_with("identity_ref", mk_err)?,
        valid_from: row.safe_get_with("valid_from", mk_err)?,
        valid_until: row.safe_get_with("valid_until", mk_err)?,
        registration_envelope: row.safe_get_with("registration_envelope", mk_err)?,
        original_content_hash: hex::encode(&original_content_hash),
        scrub_signature_classical: row.safe_get_with("scrub_signature_classical", mk_err)?,
        scrub_signature_pqc: row.safe_get_with("scrub_signature_pqc", mk_err)?,
        scrub_key_id: row.safe_get_with("scrub_key_id", mk_err)?,
        scrub_timestamp: row.safe_get_with("scrub_timestamp", mk_err)?,
        pqc_completed_at: row.safe_get_with("pqc_completed_at", mk_err)?,
        persist_row_hash: row.safe_get_with("persist_row_hash", mk_err)?,
        roles,
        attestation_evidence,
    })
}

fn pg_row_to_attestation(
    row: tokio_postgres::Row,
) -> Result<crate::federation::Attestation, crate::federation::Error> {
    let mk_err = crate::federation::Error::Backend;
    let original_content_hash: Vec<u8> = row.safe_get_with("original_content_hash", mk_err)?;
    // v3.7.0 (CIRISPersist#146, CEG 0.6) — subject_key_ids JSONB is
    // stored as a JSON array of strings; deserialize directly.
    let subject_key_ids: serde_json::Value = row.safe_get_with("subject_key_ids", mk_err)?;
    let subject_key_ids: Vec<String> = serde_json::from_value(subject_key_ids)
        .map_err(|e| crate::federation::Error::Backend(format!("subject_key_ids decode: {e}")))?;
    let withdraws_admission_rule: Option<i16> =
        row.safe_get_with("withdraws_admission_rule", mk_err)?;
    Ok(crate::federation::Attestation {
        attestation_id: row.safe_get_with("attestation_id", mk_err)?,
        attesting_key_id: row.safe_get_with("attesting_key_id", mk_err)?,
        attested_key_id: row.safe_get_with("attested_key_id", mk_err)?,
        attestation_type: row.safe_get_with("attestation_type", mk_err)?,
        weight: row.safe_get_with("weight", mk_err)?,
        asserted_at: row.safe_get_with("asserted_at", mk_err)?,
        expires_at: row.safe_get_with("expires_at", mk_err)?,
        attestation_envelope: row.safe_get_with("attestation_envelope", mk_err)?,
        original_content_hash: hex::encode(&original_content_hash),
        scrub_signature_classical: row.safe_get_with("scrub_signature_classical", mk_err)?,
        scrub_signature_pqc: row.safe_get_with("scrub_signature_pqc", mk_err)?,
        scrub_key_id: row.safe_get_with("scrub_key_id", mk_err)?,
        scrub_timestamp: row.safe_get_with("scrub_timestamp", mk_err)?,
        pqc_completed_at: row.safe_get_with("pqc_completed_at", mk_err)?,
        persist_row_hash: row.safe_get_with("persist_row_hash", mk_err)?,
        subject_key_ids,
        withdraws_admission_rule: withdraws_admission_rule.map(|v| v as u8),
        cohort_scope: row.safe_get_with("cohort_scope", mk_err)?,
    })
}

fn pg_row_to_revocation(
    row: tokio_postgres::Row,
) -> Result<crate::federation::Revocation, crate::federation::Error> {
    let mk_err = crate::federation::Error::Backend;
    let original_content_hash: Vec<u8> = row.safe_get_with("original_content_hash", mk_err)?;
    Ok(crate::federation::Revocation {
        revocation_id: row.safe_get_with("revocation_id", mk_err)?,
        revoked_key_id: row.safe_get_with("revoked_key_id", mk_err)?,
        revoking_key_id: row.safe_get_with("revoking_key_id", mk_err)?,
        reason: row.safe_get_with("reason", mk_err)?,
        revoked_at: row.safe_get_with("revoked_at", mk_err)?,
        effective_at: row.safe_get_with("effective_at", mk_err)?,
        revocation_envelope: row.safe_get_with("revocation_envelope", mk_err)?,
        original_content_hash: hex::encode(&original_content_hash),
        scrub_signature_classical: row.safe_get_with("scrub_signature_classical", mk_err)?,
        scrub_signature_pqc: row.safe_get_with("scrub_signature_pqc", mk_err)?,
        scrub_key_id: row.safe_get_with("scrub_key_id", mk_err)?,
        scrub_timestamp: row.safe_get_with("scrub_timestamp", mk_err)?,
        pqc_completed_at: row.safe_get_with("pqc_completed_at", mk_err)?,
        observed_region: row.safe_get_with("observed_region", mk_err)?,
        persist_row_hash: row.safe_get_with("persist_row_hash", mk_err)?,
    })
}

/// v3.12.0 (CIRISPersist#153 Ask 1) — Postgres row →
/// [`crate::federation::IdentityOccurrence`].
fn pg_row_to_identity_occurrence(
    row: tokio_postgres::Row,
) -> Result<crate::federation::IdentityOccurrence, crate::federation::Error> {
    let mk_err = crate::federation::Error::Backend;
    Ok(crate::federation::IdentityOccurrence {
        identity_key_id: row.safe_get_with("identity_key_id", mk_err)?,
        occurrence_key_id: row.safe_get_with("occurrence_key_id", mk_err)?,
        device_class: row.safe_get_with("device_class", mk_err)?,
        hardware_attestation: row.safe_get_with("hardware_attestation", mk_err)?,
        asserted_at: row.safe_get_with("asserted_at", mk_err)?,
        valid_until: row.safe_get_with("valid_until", mk_err)?,
        persist_row_hash: row.safe_get_with("persist_row_hash", mk_err)?,
    })
}

/// v3.12.0 (CIRISPersist#153 Ask 2) — Postgres row →
/// [`crate::federation::Family`]. `members` deserialized from JSONB
/// via serde.
fn pg_row_to_family(
    row: tokio_postgres::Row,
) -> Result<crate::federation::Family, crate::federation::Error> {
    let mk_err = crate::federation::Error::Backend;
    let members_value: serde_json::Value = row.safe_get_with("members", mk_err)?;
    let members: Vec<crate::federation::FamilyMember> = serde_json::from_value(members_value)
        .map_err(|e| crate::federation::Error::Backend(format!("members deserialize: {e}")))?;
    Ok(crate::federation::Family {
        family_key_id: row.safe_get_with("family_key_id", mk_err)?,
        family_name: row.safe_get_with("family_name", mk_err)?,
        members,
        founded_at: row.safe_get_with("founded_at", mk_err)?,
        consensus_protocol: row.safe_get_with("consensus_protocol", mk_err)?,
        consensus_protocol_entrenched: row
            .safe_get_with("consensus_protocol_entrenched", mk_err)?,
        persist_row_hash: row.safe_get_with("persist_row_hash", mk_err)?,
    })
}

fn pg_row_to_community(
    row: tokio_postgres::Row,
) -> Result<crate::federation::Community, crate::federation::Error> {
    let mk_err = crate::federation::Error::Backend;
    let members_value: serde_json::Value = row.safe_get_with("members", mk_err)?;
    let members: Vec<crate::federation::CommunityMember> = serde_json::from_value(members_value)
        .map_err(|e| crate::federation::Error::Backend(format!("members deserialize: {e}")))?;
    let policy_blob: Option<serde_json::Value> = row.safe_get_with("policy_blob", mk_err)?;
    Ok(crate::federation::Community {
        community_key_id: row.safe_get_with("community_key_id", mk_err)?,
        community_name: row.safe_get_with("community_name", mk_err)?,
        members,
        founded_at: row.safe_get_with("founded_at", mk_err)?,
        consensus_protocol: row.safe_get_with("consensus_protocol", mk_err)?,
        policy_blob,
        persist_row_hash: row.safe_get_with("persist_row_hash", mk_err)?,
    })
}

/// v3.11.0 (CIRISPersist#143, F-AV-ROLLBACK closure) — anti-rollback
/// admission check for postgres. Reads the latest `scrub_timestamp`
/// for the target `revoked_key_id`; rejects with
/// [`crate::federation::Error::RevocationRollback`] if `submitted_ts`
/// is not strictly later. First revocation against a target always
/// admits (no prior row → no rollback possible).
async fn check_revocation_anti_rollback_postgres(
    client: &deadpool_postgres::Object,
    revoked_key_id: &str,
    submitted_ts: chrono::DateTime<chrono::Utc>,
) -> Result<(), crate::federation::Error> {
    let row = client
        .query_opt(
            "SELECT scrub_timestamp FROM cirislens.federation_revocations \
             WHERE revoked_key_id = $1 ORDER BY scrub_timestamp DESC LIMIT 1",
            &[&revoked_key_id],
        )
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("anti-rollback lookup: {e}")))?;

    if let Some(r) = row {
        let existing: chrono::DateTime<chrono::Utc> = r.get(0);
        if submitted_ts <= existing {
            return Err(crate::federation::Error::RevocationRollback {
                revoked_key_id: revoked_key_id.to_owned(),
                existing_signed_timestamp: existing,
                submitted_signed_timestamp: submitted_ts,
            });
        }
    }
    Ok(())
}

/// v2.10.0 (CIRISPersist#114) — Postgres row → [`crate::federation::Goal`].
/// SELECT statements that consume this MUST include the typed
/// columns the converter pulls by name; the `persist_row_hash`
/// column is not part of the value (consumers recompute via
/// `compute_persist_row_hash` on demand).
fn pg_row_to_goal(
    row: tokio_postgres::Row,
) -> Result<crate::federation::Goal, crate::federation::Error> {
    let mk_err = crate::federation::Error::Backend;
    let goal_id: uuid::Uuid = row.safe_get_with("goal_id", mk_err)?;
    let declared_by_key_id: String = row.safe_get_with("declared_by_key_id", mk_err)?;
    let declared_at: chrono::DateTime<chrono::Utc> = row.safe_get_with("declared_at", mk_err)?;
    let goal_text: String = row.safe_get_with("goal_text", mk_err)?;
    let scope_kind: String = row.safe_get_with("scope_kind", mk_err)?;
    let scope_cohort_id: Option<String> = row.safe_get_with("scope_cohort_id", mk_err)?;
    let meta_dimension_text: String = row.safe_get_with("meta_dimension", mk_err)?;
    let meta_rationale: String = row.safe_get_with("meta_rationale", mk_err)?;
    let meta_deliberation: Option<serde_json::Value> =
        row.safe_get_with("meta_deliberation", mk_err)?;
    let retired_at: Option<chrono::DateTime<chrono::Utc>> =
        row.safe_get_with("retired_at", mk_err)?;

    let scope = match scope_kind.as_str() {
        "single_declarer" => crate::federation::GoalScope::SingleDeclarer,
        "federation" => crate::federation::GoalScope::Federation,
        "cohort" => {
            let cohort_id = scope_cohort_id.ok_or_else(|| {
                crate::federation::Error::Backend(
                    "scope_kind=cohort but scope_cohort_id IS NULL (CHECK bypass?)".into(),
                )
            })?;
            crate::federation::GoalScope::Cohort { cohort_id }
        }
        other => {
            return Err(crate::federation::Error::Backend(format!(
                "unknown scope_kind: {other}"
            )));
        }
    };
    let dimension = crate::federation::M1Dimension::from_wire_str(&meta_dimension_text)
        .ok_or_else(|| {
            crate::federation::Error::Backend(format!(
                "unknown meta_dimension: {meta_dimension_text}"
            ))
        })?;
    let deliberation_ref: Option<crate::federation::DeliberationRef> = match meta_deliberation {
        None => None,
        Some(serde_json::Value::Null) => None,
        Some(v) => Some(serde_json::from_value(v).map_err(|e| {
            crate::federation::Error::Backend(format!("deliberation_ref decode: {e}"))
        })?),
    };
    let alignment =
        crate::federation::MetaGoalAlignment::new(dimension, meta_rationale, deliberation_ref);
    let mut goal = crate::federation::Goal::new(
        goal_id,
        declared_by_key_id,
        declared_at,
        goal_text,
        scope,
        alignment,
    );
    goal.retired_at = retired_at;
    Ok(goal)
}

/// v0.3.5 (CIRISLens#8 ASK 3) — Convert a postgres row from
/// `cirislens.trace_events` to `(event_id, TraceEventRow)`. Used by
/// `Backend::fetch_trace_events_page`. Column order MUST match the
/// SELECT clause; we read by name here to make additions safer.
fn pg_row_to_event_row(row: tokio_postgres::Row) -> Result<(i64, TraceEventRow), Error> {
    use crate::schema::{ReasoningEventType, TraceLevel};
    // v0.5.4 (CIRISPersist#28) — every column read goes through
    // safe_get_with so NULL-on-deserialize becomes typed store::Error,
    // not a Rust panic. Same shape as v0.5.3's ReadEngine sweep,
    // adapted for store::Error::Backend.
    let event_type_str: String = row.safe_get_with("event_type", Error::Backend)?;
    let event_type = ReasoningEventType::from_wire_str(&event_type_str).ok_or_else(|| {
        Error::Backend(format!(
            "unknown event_type in trace_events row: {event_type_str}"
        ))
    })?;
    let trace_level_str: String = row.safe_get_with("trace_level", Error::Backend)?;
    let trace_level = match trace_level_str.as_str() {
        "generic" => TraceLevel::Generic,
        "detailed" => TraceLevel::Detailed,
        "full_traces" => TraceLevel::FullTraces,
        other => {
            return Err(Error::Backend(format!("unknown trace_level: {other}")));
        }
    };
    let verification_source_str: String =
        row.safe_get_with("verification_source", Error::Backend)?;
    let verification_source = crate::store::VerificationSource::from_wire_str(
        &verification_source_str,
    )
    .ok_or_else(|| {
        Error::Backend(format!(
            "unknown verification_source in trace_events row: {verification_source_str}"
        ))
    })?;
    let attempt_index_i32: i32 = row.safe_get_with("attempt_index", Error::Backend)?;
    let attempt_index = u32::try_from(attempt_index_i32).map_err(|_| {
        Error::Backend(format!(
            "attempt_index {attempt_index_i32} negative — schema CHECK should have rejected"
        ))
    })?;
    let payload_value: serde_json::Value = row.safe_get_with("payload", Error::Backend)?;
    let payload = match payload_value {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };

    let event_id: i64 = row.safe_get_with("event_id", Error::Backend)?;
    Ok((
        event_id,
        TraceEventRow {
            trace_id: row.safe_get_with("trace_id", Error::Backend)?,
            thought_id: row.safe_get_with("thought_id", Error::Backend)?,
            task_id: row.safe_get_with("task_id", Error::Backend)?,
            step_point: row.safe_get_with("step_point", Error::Backend)?,
            event_type,
            attempt_index,
            ts: row.safe_get_with("ts", Error::Backend)?,
            agent_name: row.safe_get_with("agent_name", Error::Backend)?,
            agent_id_hash: row.safe_get_with("agent_id_hash", Error::Backend)?,
            cognitive_state: row.safe_get_with("cognitive_state", Error::Backend)?,
            trace_level,
            payload,
            cost_llm_calls: row.safe_get_with("cost_llm_calls", Error::Backend)?,
            cost_tokens: row.safe_get_with("cost_tokens", Error::Backend)?,
            cost_usd: row.safe_get_with("cost_usd", Error::Backend)?,
            signature: row.safe_get_with("signature", Error::Backend)?,
            signing_key_id: row.safe_get_with("signing_key_id", Error::Backend)?,
            signature_verified: row.safe_get_with("signature_verified", Error::Backend)?,
            verification_source,
            schema_version: row.safe_get_with("schema_version", Error::Backend)?,
            pii_scrubbed: row.safe_get_with("pii_scrubbed", Error::Backend)?,
            original_content_hash: row.safe_get_with("original_content_hash", Error::Backend)?,
            scrub_signature: row.safe_get_with("scrub_signature", Error::Backend)?,
            scrub_key_id: row.safe_get_with("scrub_key_id", Error::Backend)?,
            scrub_timestamp: row.safe_get_with("scrub_timestamp", Error::Backend)?,
            agent_role: row.safe_get_with("agent_role", Error::Backend)?,
            agent_template: row.safe_get_with("agent_template", Error::Backend)?,
            deployment_domain: row.safe_get_with("deployment_domain", Error::Backend)?,
            deployment_type: row.safe_get_with("deployment_type", Error::Backend)?,
            deployment_region: row.safe_get_with("deployment_region", Error::Backend)?,
            deployment_trust_mode: row.safe_get_with("deployment_trust_mode", Error::Backend)?,
            // v4.0 (CIRISPersist#160, V060). cohort_scope is NOT NULL
            // DEFAULT 'federation' on the column; cohort_target_id is
            // nullable. Read both back so round-trips preserve the
            // §4.3 scope target.
            cohort_scope: row.safe_get_with("cohort_scope", Error::Backend)?,
            cohort_target_id: row.safe_get_with("cohort_target_id", Error::Backend)?,
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
// Sweep scope (v0.5.4 — CIRISPersist#28): every `tokio_postgres::Row`
// read in this file now goes through `safe_get` or `safe_get_with`.
// Includes the v0.5.0 ReadEngine impl (v0.5.3 baseline) plus the
// pre-v0.5.0 surface: `pg_row_to_event_row`, `pg_row_to_outbound_row`,
// `pg_row_to_key_record`, `pg_row_to_attestation`, `pg_row_to_revocation`,
// the federation pending lists, the outbound dequeue + DSAR scalar
// reads, and the read-engine count rollups. The CI gate (scripts/
// hooks/pre-commit) rejects new bare `row.get(` patterns in this file
// to prevent regression.

trait PgRowExt {
    /// Decode a column with typed-error propagation, returning
    /// [`crate::read::Error`] (ReadEngine layer). v0.5.3 surface.
    ///
    /// Generic over `RowIndex` so both `safe_get("col_name")` and
    /// `safe_get(0)` work uniformly. Matches `tokio_postgres::Row::
    /// try_get`'s signature.
    fn safe_get<'a, T, I>(&'a self, idx: I) -> Result<T, crate::read::Error>
    where
        T: tokio_postgres::types::FromSql<'a>,
        I: tokio_postgres::row::RowIndex + std::fmt::Display;

    /// Decode a column with caller-supplied error constructor.
    /// v0.5.4 (CIRISPersist#28) — used by non-ReadEngine layers
    /// (federation, outbound, derived, decompose) so each layer's
    /// `Backend(String)` variant can be plugged in directly:
    ///
    /// ```ignore
    /// let bytes: Vec<u8> = row
    ///     .safe_get_with("envelope_bytes", federation::Error::Backend)?;
    /// ```
    ///
    /// All four federation-side error enums (`federation::Error`,
    /// `outbound::Error`, `derived::Error`, `store::Error`, plus
    /// `read::Error`) define `Backend(String)` as a tuple variant,
    /// which Rust treats as `Fn(String) -> E` — usable as the
    /// constructor without a closure wrapper.
    fn safe_get_with<'a, T, I, E, F>(&'a self, idx: I, err: F) -> Result<T, E>
    where
        T: tokio_postgres::types::FromSql<'a>,
        I: tokio_postgres::row::RowIndex + std::fmt::Display,
        F: FnOnce(String) -> E;
}

impl PgRowExt for tokio_postgres::Row {
    fn safe_get<'a, T, I>(&'a self, idx: I) -> Result<T, crate::read::Error>
    where
        T: tokio_postgres::types::FromSql<'a>,
        I: tokio_postgres::row::RowIndex + std::fmt::Display,
    {
        let label = format!("{idx}");
        self.try_get(idx)
            .map_err(|e| crate::read::Error::Backend(format!("decode column {label}: {e}")))
    }

    fn safe_get_with<'a, T, I, E, F>(&'a self, idx: I, err: F) -> Result<T, E>
    where
        T: tokio_postgres::types::FromSql<'a>,
        I: tokio_postgres::row::RowIndex + std::fmt::Display,
        F: FnOnce(String) -> E,
    {
        let label = format!("{idx}");
        self.try_get(idx)
            .map_err(|e| err(format!("decode column {label}: {e}")))
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
            .safe_get::<Option<bool>, _>("signature_verified")?
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
                        deployment_trust_mode, verification_source, \
                        cohort_scope, cohort_target_id \
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
                .safe_get::<Option<bool>, _>("pii_scrubbed")?
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

    /// Section C: task-grouped listing.
    ///
    /// Two-query design:
    ///
    /// 1. **Task page** — `cirislens.trace_events` grouped by `task_id`,
    ///    yielding `(task_id, earliest_at, latest_at, initial_observation)`.
    ///    The `initial_observation` column is extracted server-side from
    ///    `MAX(payload->>'task_description') FILTER (WHERE event_type =
    ///    'THOUGHT_START')` so the derivation is canonical across
    ///    federation peers (CIRISPersist#23 §C requirement). The page
    ///    cursor predicate uses PostgreSQL tuple-compare on
    ///    `(earliest_at, task_id)`.
    /// 2. **Traces for the page** — once we have the page's `task_id`
    ///    list, re-run the §A summary SELECT against those task_ids
    ///    only (one round-trip; `task_id = ANY($1::text[])`). Group the
    ///    rows in Rust by `task_id`.
    ///
    /// Trace ordering within a task: `thought_depth ASC NULLS LAST`
    /// then `started_at ASC` — reasoning chain reads top-to-bottom.
    /// `TaskClass` is derived in Rust via [`crate::read::TaskClass::from_task_id`]
    /// after the SQL fetch so the mapping is single-source.
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
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        // Build WHERE clause matching task-level filter. task_id is
        // required to be non-null (a trace without task_id is not a
        // task; task-axis listing excludes it).
        let mut where_parts: Vec<String> = vec!["task_id IS NOT NULL".to_owned()];
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();

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
        // task_class derives from task_id prefix; translate the filter
        // to a SQL prefix-match. Keep the prefix list aligned with
        // TaskClass::from_task_id — change one, change the other.
        if let Some(tc) = filter.task_class {
            use crate::read::TaskClass;
            let predicate = match tc {
                TaskClass::QaEval => {
                    "(task_id LIKE 'qa\\_%' ESCAPE '\\' OR task_id LIKE 'qa-eval%')"
                }
                TaskClass::Discord => "task_id LIKE 'discord\\_%' ESCAPE '\\'",
                TaskClass::RealUserDiscord => {
                    "task_id LIKE 'real\\_user\\_discord\\_%' ESCAPE '\\'"
                }
                TaskClass::RealUserCli => "task_id LIKE 'real\\_user\\_cli\\_%' ESCAPE '\\'",
                TaskClass::RealUserApi => "task_id LIKE 'real\\_user\\_api\\_%' ESCAPE '\\'",
                TaskClass::WakeupRitual => "position('wakeup' in task_id) > 0",
                TaskClass::Other => {
                    // Inverse of every recognized prefix. Keep this in
                    // sync with TaskClass::from_task_id.
                    "(task_id NOT LIKE 'qa\\_%' ESCAPE '\\' \
                       AND task_id NOT LIKE 'qa-eval%' \
                       AND task_id NOT LIKE 'discord\\_%' ESCAPE '\\' \
                       AND task_id NOT LIKE 'real\\_user\\_discord\\_%' ESCAPE '\\' \
                       AND task_id NOT LIKE 'real\\_user\\_cli\\_%' ESCAPE '\\' \
                       AND task_id NOT LIKE 'real\\_user\\_api\\_%' ESCAPE '\\' \
                       AND position('wakeup' in task_id) = 0)"
                }
            };
            where_parts.push(predicate.to_owned());
        }

        let where_sql = format!("WHERE {}", where_parts.join(" AND "));

        // Cursor predicate uses HAVING because earliest_at is an
        // aggregate. Tuple compare: (MIN(ts), task_id) < (last_at, last_id).
        let having_sql = match &cursor {
            None => String::new(),
            Some(c) => {
                if c.version != "v1" {
                    return Err(crate::read::Error::InvalidCursor(format!(
                        "TaskCursor version {} unsupported; v0.5.5 ships v1",
                        c.version
                    )));
                }
                params.push(Box::new(c.last_earliest_at));
                let p_at = params.len();
                params.push(Box::new(c.last_task_id.clone()));
                let p_id = params.len();
                format!("HAVING (MIN(ts), task_id) < (${p_at}, ${p_id})")
            }
        };

        params.push(Box::new(limit));
        let p_limit = params.len();

        let task_page_sql = format!(
            "SELECT task_id, \
                    MIN(ts) AS earliest_at, \
                    MAX(ts) AS latest_at, \
                    MAX(payload->>'task_description') \
                        FILTER (WHERE event_type = 'THOUGHT_START') \
                        AS initial_observation \
             FROM cirislens.trace_events \
             {where_sql} \
             GROUP BY task_id \
             {having_sql} \
             ORDER BY earliest_at DESC, task_id DESC \
             LIMIT ${p_limit}"
        );

        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let task_rows = client
            .query(&task_page_sql, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("list_tasks page: {e}")))?;

        if task_rows.is_empty() {
            return Ok(crate::read::TaskListPage {
                items: Vec::new(),
                next_cursor: None,
            });
        }

        // Decode the page header rows (task_id, earliest_at, latest_at,
        // initial_observation) before reaching for the per-trace SELECT.
        struct TaskHeader {
            task_id: String,
            earliest_at: chrono::DateTime<chrono::Utc>,
            latest_at: chrono::DateTime<chrono::Utc>,
            initial_observation: Option<String>,
        }
        let mut headers: Vec<TaskHeader> = Vec::with_capacity(task_rows.len());
        for row in &task_rows {
            headers.push(TaskHeader {
                task_id: row.safe_get("task_id")?,
                earliest_at: row.safe_get("earliest_at")?,
                latest_at: row.safe_get("latest_at")?,
                initial_observation: row.safe_get("initial_observation")?,
            });
        }

        // Fetch trace summaries for every task_id on this page.
        // task_id = ANY($1::text[]) hits the task_id index;
        // sub-aggregation is over trace_id.
        let task_ids: Vec<String> = headers.iter().map(|h| h.task_id.clone()).collect();
        let traces_sql = format!(
            "SELECT MAX(task_id) AS _tg_task_id, \
                    {select}, \
                    MAX((payload->>'thought_depth')::int) \
                        FILTER (WHERE event_type = 'THOUGHT_START') AS _tg_depth \
             FROM cirislens.trace_events \
             WHERE task_id = ANY($1::text[]) \
             GROUP BY trace_id \
             ORDER BY _tg_task_id ASC, \
                      _tg_depth ASC NULLS LAST, \
                      started_at ASC",
            select = TRACE_SUMMARY_SELECT,
        );

        let trace_rows = client
            .query(&traces_sql, &[&task_ids])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("list_tasks traces: {e}")))?;

        // Bucket trace summaries by their group's task_id.
        let mut bucket: std::collections::HashMap<String, Vec<crate::read::TraceSummary>> =
            std::collections::HashMap::with_capacity(headers.len());
        for row in &trace_rows {
            let tg_task_id: String = row.safe_get("_tg_task_id")?;
            let summary = pg_row_to_trace_summary(row)?;
            bucket.entry(tg_task_id).or_default().push(summary);
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

        let next_cursor = if items.len() == limit as usize {
            let last = &items[items.len() - 1];
            Some(crate::read::TaskCursor::from_trailing(
                last.earliest_at,
                last.task_id.clone(),
            ))
        } else {
            None
        };

        Ok(crate::read::TaskListPage { items, next_cursor })
    }

    /// Section D: paged LLM call listing.
    ///
    /// Joins `cirislens.trace_llm_calls` to `cirislens.trace_events`
    /// on `(trace_id, parent_event_id)` so filters on agent_id_hash /
    /// agent_name / deployment_domain reach the parent event's
    /// columns. Newest-first by `(ts, trace_id, attempt_index)`.
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
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        let (join_sql, where_sql, params) = build_llm_filter_sql(&filter)?;
        let mut params = params;

        // Cursor predicate uses tuple compare. NULL parent_event_id
        // doesn't matter — attempt_index disambiguates within trace.
        let cursor_clause = match &cursor {
            None => String::new(),
            Some(c) => {
                if c.version != "v1" {
                    return Err(crate::read::Error::InvalidCursor(format!(
                        "LlmCallCursor version {} unsupported; v0.5.5 ships v1",
                        c.version
                    )));
                }
                params.push(Box::new(c.last_ts));
                let p_ts = params.len();
                params.push(Box::new(c.last_trace_id.clone()));
                let p_tid = params.len();
                let attempt_i32 = i32::try_from(c.last_attempt_index).map_err(|_| {
                    crate::read::Error::InvalidCursor(format!(
                        "last_attempt_index {} out of i32 range",
                        c.last_attempt_index
                    ))
                })?;
                params.push(Box::new(attempt_i32));
                let p_ai = params.len();
                let prefix = if where_sql.is_empty() { "WHERE" } else { "AND" };
                format!(
                    "{prefix} (lc.ts, lc.trace_id, lc.attempt_index) < (${p_ts}, ${p_tid}, ${p_ai})"
                )
            }
        };

        params.push(Box::new(limit));
        let p_limit = params.len();

        let sql = format!(
            "SELECT lc.trace_id, lc.thought_id, lc.task_id, lc.parent_event_id, \
                    lc.parent_event_type, lc.parent_attempt_index, lc.attempt_index, lc.ts, \
                    lc.duration_ms, lc.handler_name, lc.service_name, lc.model, lc.base_url, \
                    lc.response_model, lc.prompt_tokens, lc.completion_tokens, lc.prompt_bytes, \
                    lc.completion_bytes, lc.cost_usd, lc.status, lc.error_class, lc.attempt_count, \
                    lc.retry_count, lc.prompt_hash, lc.prompt, lc.response_text \
             FROM cirislens.trace_llm_calls lc \
             {join_sql} \
             {where_sql} {cursor_clause} \
             ORDER BY lc.ts DESC, lc.trace_id DESC, lc.attempt_index DESC \
             LIMIT ${p_limit}"
        );

        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("list_llm_calls: {e}")))?;

        let mut items: Vec<crate::store::types::TraceLlmCallRow> = Vec::with_capacity(rows.len());
        for row in &rows {
            items.push(pg_row_to_llm_call_row(row)?);
        }

        let next_cursor = if items.len() == limit as usize {
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
    }

    /// Section D: rolled-up LLM cost aggregate.
    ///
    /// Four GROUP BY passes share the same WHERE filter — by_model,
    /// by_agent, by_domain, and window totals. Each `SUM` is
    /// `COALESCE`'d to 0 so empty-window inputs return zeros rather
    /// than NULL (v0.5.1 / CIRISPersist#24 hygiene applied
    /// proactively). Aggregates use the join-once CTE shape so the
    /// trace_events ↔ trace_llm_calls join only runs once per call.
    async fn aggregate_llm_costs(
        &self,
        filter: crate::read::LlmCallFilter,
    ) -> Result<crate::read::LlmCostAggregate, crate::read::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        let (join_sql, where_sql, params) = build_llm_filter_sql(&filter)?;
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();

        // Per-model rollup. Group on model; rows where model IS NULL
        // get bucketed into "<unknown>".
        let sql_model = format!(
            "SELECT COALESCE(lc.model, '<unknown>') AS k, \
                    COUNT(*)::bigint AS call_count, \
                    COALESCE(SUM(lc.prompt_tokens), 0)::bigint AS prompt_tokens, \
                    COALESCE(SUM(lc.completion_tokens), 0)::bigint AS completion_tokens, \
                    COALESCE(SUM(lc.cost_usd), 0)::float8 AS cost_usd, \
                    COUNT(*) FILTER (WHERE lc.status != 'ok')::bigint AS error_count \
             FROM cirislens.trace_llm_calls lc \
             {join_sql} {where_sql} \
             GROUP BY k"
        );
        let model_rows = client
            .query(&sql_model, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("agg_llm_costs by_model: {e}")))?;
        let mut by_model: std::collections::HashMap<String, crate::read::ModelCostStats> =
            std::collections::HashMap::with_capacity(model_rows.len());
        for row in &model_rows {
            let k: String = row.safe_get("k")?;
            by_model.insert(
                k.clone(),
                crate::read::ModelCostStats {
                    model: k,
                    call_count: row.safe_get("call_count")?,
                    prompt_tokens: row.safe_get("prompt_tokens")?,
                    completion_tokens: row.safe_get("completion_tokens")?,
                    cost_usd: row.safe_get("cost_usd")?,
                    error_count: row.safe_get("error_count")?,
                },
            );
        }

        // Per-agent rollup. Requires the parent-event join (otherwise
        // agent_id_hash isn't visible on the LLM call row).
        let join_for_agg = if join_sql.is_empty() {
            // Force-join trace_events so agent_id_hash/deployment_domain
            // are reachable even when the caller's filter doesn't
            // already require it.
            "JOIN cirislens.trace_events e \
               ON e.trace_id = lc.trace_id AND e.event_id = lc.parent_event_id"
                .to_owned()
        } else {
            join_sql.clone()
        };

        let sql_agent = format!(
            "SELECT e.agent_id_hash AS k, \
                    MAX(e.agent_name) AS agent_name, \
                    COUNT(*)::bigint AS call_count, \
                    COALESCE(SUM(lc.prompt_tokens), 0)::bigint AS prompt_tokens, \
                    COALESCE(SUM(lc.completion_tokens), 0)::bigint AS completion_tokens, \
                    COALESCE(SUM(lc.cost_usd), 0)::float8 AS cost_usd \
             FROM cirislens.trace_llm_calls lc \
             {join_for_agg} {where_sql} \
             GROUP BY k"
        );
        let agent_rows = client
            .query(&sql_agent, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("agg_llm_costs by_agent: {e}")))?;
        let mut by_agent: std::collections::HashMap<String, crate::read::AgentCostStats> =
            std::collections::HashMap::with_capacity(agent_rows.len());
        for row in &agent_rows {
            let k: String = row.safe_get("k")?;
            by_agent.insert(
                k.clone(),
                crate::read::AgentCostStats {
                    agent_id_hash: k,
                    agent_name: row.safe_get("agent_name")?,
                    call_count: row.safe_get("call_count")?,
                    prompt_tokens: row.safe_get("prompt_tokens")?,
                    completion_tokens: row.safe_get("completion_tokens")?,
                    cost_usd: row.safe_get("cost_usd")?,
                },
            );
        }

        // Per-domain rollup.
        let sql_domain = format!(
            "SELECT COALESCE(e.deployment_domain, '<unknown>') AS k, \
                    COUNT(*)::bigint AS call_count, \
                    COALESCE(SUM(lc.cost_usd), 0)::float8 AS cost_usd \
             FROM cirislens.trace_llm_calls lc \
             {join_for_agg} {where_sql} \
             GROUP BY k"
        );
        let domain_rows = client
            .query(&sql_domain, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("agg_llm_costs by_domain: {e}")))?;
        let mut by_domain: std::collections::HashMap<String, crate::read::DomainCostStats> =
            std::collections::HashMap::with_capacity(domain_rows.len());
        for row in &domain_rows {
            let k: String = row.safe_get("k")?;
            by_domain.insert(
                k.clone(),
                crate::read::DomainCostStats {
                    deployment_domain: k,
                    call_count: row.safe_get("call_count")?,
                    cost_usd: row.safe_get("cost_usd")?,
                },
            );
        }

        // Window totals. No GROUP BY — collapses to one row.
        let sql_totals = format!(
            "SELECT COUNT(*)::bigint AS call_count, \
                    COALESCE(SUM(lc.prompt_tokens), 0)::bigint AS prompt_tokens, \
                    COALESCE(SUM(lc.completion_tokens), 0)::bigint AS completion_tokens, \
                    COALESCE(SUM(lc.cost_usd), 0)::float8 AS cost_usd, \
                    COUNT(*) FILTER (WHERE lc.status != 'ok')::bigint AS error_count \
             FROM cirislens.trace_llm_calls lc \
             {join_sql} {where_sql}"
        );
        let totals_row = client
            .query_one(&sql_totals, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("agg_llm_costs totals: {e}")))?;
        let totals = crate::read::TotalCostStats {
            call_count: totals_row.safe_get("call_count")?,
            prompt_tokens: totals_row.safe_get("prompt_tokens")?,
            completion_tokens: totals_row.safe_get("completion_tokens")?,
            cost_usd: totals_row.safe_get("cost_usd")?,
            error_count: totals_row.safe_get("error_count")?,
        };

        Ok(crate::read::LlmCostAggregate {
            time_window: filter.time_window,
            by_model,
            by_agent,
            by_domain,
            totals,
        })
    }

    /// Section G: corpus shape rollup.
    ///
    /// Six GROUP BY passes share the same trace-set CTE (the distinct
    /// `trace_id`s matching the filter within the window). Each
    /// bucket map is computed at SQL layer (no client-side regex /
    /// aggregation pass) so the rollup is deterministic across
    /// federation peers. `stationarity_z_score` is reserved for the
    /// future baseline-comparison API extension; v0.5.5 returns None.
    async fn corpus_shape(
        &self,
        filter: crate::read::CorpusShapeFilter,
    ) -> Result<crate::read::CorpusShape, crate::read::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        // Build WHERE on trace_events. Window is required.
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        let mut where_parts: Vec<String> = Vec::new();
        params.push(Box::new(filter.time_window.since));
        where_parts.push(format!("ts >= ${}", params.len()));
        params.push(Box::new(filter.time_window.until));
        where_parts.push(format!("ts < ${}", params.len()));
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
        let where_sql = format!("WHERE {}", where_parts.join(" AND "));
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();

        // Total distinct traces + by_task_class breakdown via task_id
        // prefix matching. Each LIKE predicate aligns with
        // TaskClass::from_task_id — keep them in sync.
        let sql_totals = format!(
            "WITH traces AS ( \
                 SELECT DISTINCT trace_id, MAX(task_id) AS task_id, \
                        MAX(agent_name) AS agent_name, \
                        MAX(agent_template) AS agent_template, \
                        MAX(deployment_region) AS deployment_region \
                 FROM cirislens.trace_events {where_sql} \
                 GROUP BY trace_id \
             ) \
             SELECT COUNT(*)::bigint AS total_traces, \
                    COUNT(*) FILTER ( \
                        WHERE task_id LIKE 'qa\\_%' ESCAPE '\\' \
                           OR task_id LIKE 'qa-eval%' \
                    )::bigint AS c_qa, \
                    COUNT(*) FILTER ( \
                        WHERE task_id LIKE 'real\\_user\\_discord\\_%' ESCAPE '\\' \
                    )::bigint AS c_rud, \
                    COUNT(*) FILTER ( \
                        WHERE task_id LIKE 'real\\_user\\_cli\\_%' ESCAPE '\\' \
                    )::bigint AS c_ruc, \
                    COUNT(*) FILTER ( \
                        WHERE task_id LIKE 'real\\_user\\_api\\_%' ESCAPE '\\' \
                    )::bigint AS c_rua, \
                    COUNT(*) FILTER ( \
                        WHERE position('wakeup' in task_id) > 0 \
                          AND task_id NOT LIKE 'real\\_user\\_%' ESCAPE '\\' \
                    )::bigint AS c_wakeup, \
                    COUNT(*) FILTER ( \
                        WHERE task_id LIKE 'discord\\_%' ESCAPE '\\' \
                    )::bigint AS c_discord, \
                    COUNT(*) FILTER ( \
                        WHERE task_id IS NOT NULL \
                          AND task_id NOT LIKE 'qa\\_%' ESCAPE '\\' \
                          AND task_id NOT LIKE 'qa-eval%' \
                          AND task_id NOT LIKE 'discord\\_%' ESCAPE '\\' \
                          AND task_id NOT LIKE 'real\\_user\\_discord\\_%' ESCAPE '\\' \
                          AND task_id NOT LIKE 'real\\_user\\_cli\\_%' ESCAPE '\\' \
                          AND task_id NOT LIKE 'real\\_user\\_api\\_%' ESCAPE '\\' \
                          AND position('wakeup' in task_id) = 0 \
                    )::bigint AS c_other \
             FROM traces"
        );
        let totals_row = client
            .query_one(&sql_totals, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("corpus_shape totals: {e}")))?;
        let total_traces: i64 = totals_row.safe_get("total_traces")?;
        let mut by_task_class: std::collections::HashMap<crate::read::TaskClass, i64> =
            std::collections::HashMap::new();
        for (tc, col) in [
            (crate::read::TaskClass::QaEval, "c_qa"),
            (crate::read::TaskClass::RealUserDiscord, "c_rud"),
            (crate::read::TaskClass::RealUserCli, "c_ruc"),
            (crate::read::TaskClass::RealUserApi, "c_rua"),
            (crate::read::TaskClass::WakeupRitual, "c_wakeup"),
            (crate::read::TaskClass::Discord, "c_discord"),
            (crate::read::TaskClass::Other, "c_other"),
        ] {
            let n: i64 = totals_row.safe_get(col)?;
            if n > 0 {
                by_task_class.insert(tc, n);
            }
        }

        // QA breakdowns — extract language + question_num from
        // qa_<lang>_<num> or qa-eval-<lang>-<num>. Reject malformed
        // matches via NULL filter.
        let sql_qa = format!(
            "WITH traces AS ( \
                 SELECT trace_id, MAX(task_id) AS task_id \
                 FROM cirislens.trace_events {where_sql} \
                 GROUP BY trace_id \
             ) \
             SELECT substring(task_id from '^qa[_-](?:eval[_-])?([a-z]+)[_-]') AS lang, \
                    NULLIF(substring(task_id from '^qa[_-](?:eval[_-])?[a-z]+[_-]([0-9]+)'), '')::int \
                        AS qnum, \
                    COUNT(*)::bigint AS n \
             FROM traces \
             WHERE task_id LIKE 'qa\\_%' ESCAPE '\\' OR task_id LIKE 'qa-eval%' \
             GROUP BY lang, qnum"
        );
        let qa_rows = client
            .query(&sql_qa, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("corpus_shape qa: {e}")))?;
        let mut by_qa_language: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();
        let mut by_qa_question_num: std::collections::HashMap<i32, i64> =
            std::collections::HashMap::new();
        for row in &qa_rows {
            let lang: Option<String> = row.safe_get("lang")?;
            let qnum: Option<i32> = row.safe_get("qnum")?;
            let n: i64 = row.safe_get("n")?;
            if let Some(lang) = lang {
                *by_qa_language.entry(lang).or_insert(0) += n;
            }
            if let Some(q) = qnum {
                *by_qa_question_num.entry(q).or_insert(0) += n;
            }
        }

        // by_agent_name + by_agent_version (= agent_template) +
        // by_deployment_region: shared CTE, per-bucket GROUP BY.
        let sql_agent = format!(
            "WITH traces AS ( \
                 SELECT trace_id, \
                        MAX(agent_name) AS agent_name, \
                        MAX(agent_template) AS agent_template, \
                        MAX(deployment_region) AS deployment_region \
                 FROM cirislens.trace_events {where_sql} \
                 GROUP BY trace_id \
             ) \
             SELECT 'an' AS k, agent_name AS v, COUNT(*)::bigint AS n FROM traces \
                 WHERE agent_name IS NOT NULL GROUP BY agent_name \
             UNION ALL \
             SELECT 'av', agent_template, COUNT(*) FROM traces \
                 WHERE agent_template IS NOT NULL GROUP BY agent_template \
             UNION ALL \
             SELECT 'dr', deployment_region, COUNT(*) FROM traces \
                 WHERE deployment_region IS NOT NULL GROUP BY deployment_region"
        );
        let agent_rows = client
            .query(&sql_agent, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("corpus_shape agent: {e}")))?;
        let mut by_agent_name: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();
        let mut by_agent_version: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();
        let mut by_deployment_region: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();
        for row in &agent_rows {
            let k: String = row.safe_get("k")?;
            let v: String = row.safe_get("v")?;
            let n: i64 = row.safe_get("n")?;
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

        // by_primary_model: for each trace in the window, find the
        // model with the most LLM calls; count traces per model.
        // Inline the where clause as a sub-CTE to scope LLM calls to
        // the matching trace set.
        let sql_model = format!(
            "WITH traces AS ( \
                 SELECT DISTINCT trace_id FROM cirislens.trace_events {where_sql} \
             ), \
             tm AS ( \
                 SELECT lc.trace_id, lc.model, COUNT(*) AS n_calls \
                 FROM cirislens.trace_llm_calls lc \
                 JOIN traces t ON lc.trace_id = t.trace_id \
                 WHERE lc.model IS NOT NULL \
                 GROUP BY lc.trace_id, lc.model \
             ), \
             primary_model AS ( \
                 SELECT DISTINCT ON (trace_id) trace_id, model \
                 FROM tm \
                 ORDER BY trace_id, n_calls DESC, model ASC \
             ) \
             SELECT model AS k, COUNT(*)::bigint AS n FROM primary_model GROUP BY model"
        );
        let model_rows = client
            .query(&sql_model, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("corpus_shape model: {e}")))?;
        let mut by_primary_model: std::collections::HashMap<String, i64> =
            std::collections::HashMap::new();
        for row in &model_rows {
            let k: String = row.safe_get("k")?;
            let n: i64 = row.safe_get("n")?;
            by_primary_model.insert(k, n);
        }

        Ok(crate::read::CorpusShape {
            window: filter.time_window,
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
    }

    /// Section H: scrub-stats aggregate. Two GROUP BY passes — total
    /// envelopes scrubbed + per-trace_level counts. Fields requiring
    /// v0.6.0's post-ingest classification pipeline
    /// (fields_scrubbed_total + by_entity_type) return zero/empty.
    async fn aggregate_scrub_stats(
        &self,
        window: crate::read::TimeWindow,
    ) -> Result<crate::read::ScrubAggregate, crate::read::Error> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        let sql = "WITH traces AS ( \
                       SELECT trace_id, \
                              BOOL_OR(pii_scrubbed) AS scrubbed, \
                              MAX(trace_level) AS trace_level \
                       FROM cirislens.trace_events \
                       WHERE ts >= $1 AND ts < $2 \
                       GROUP BY trace_id \
                   ) \
                   SELECT COUNT(*) FILTER (WHERE scrubbed)::bigint AS total_scrubbed, \
                          COUNT(*) FILTER (WHERE scrubbed AND trace_level = 'generic')::bigint \
                              AS c_generic, \
                          COUNT(*) FILTER (WHERE scrubbed AND trace_level = 'detailed')::bigint \
                              AS c_detailed, \
                          COUNT(*) FILTER (WHERE scrubbed AND trace_level = 'full_traces')::bigint \
                              AS c_full \
                   FROM traces";

        let row = client
            .query_one(sql, &[&window.since, &window.until])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("aggregate_scrub_stats: {e}")))?;

        let envelopes_scrubbed: i64 = row.safe_get("total_scrubbed")?;
        let mut by_trace_level: std::collections::HashMap<crate::schema::TraceLevel, i64> =
            std::collections::HashMap::new();
        for (lvl, col) in [
            (crate::schema::TraceLevel::Generic, "c_generic"),
            (crate::schema::TraceLevel::Detailed, "c_detailed"),
            (crate::schema::TraceLevel::FullTraces, "c_full"),
        ] {
            let n: i64 = row.safe_get(col)?;
            if n > 0 {
                by_trace_level.insert(lvl, n);
            }
        }

        Ok(crate::read::ScrubAggregate {
            window,
            envelopes_scrubbed,
            // v0.5.5 limitation — see ScrubAggregate doc comment.
            fields_scrubbed_total: 0,
            by_entity_type: std::collections::HashMap::new(),
            by_trace_level,
        })
    }

    /// Section I: list federation_keys with filter + cursor pagination.
    /// Newest-first by `(valid_from, key_id)`.
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
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(h) = &filter.agent_id_hash {
            params.push(Box::new(h.clone()));
            where_parts.push(format!(
                "(identity_type = 'agent' AND identity_ref = ${})",
                params.len()
            ));
        }
        if let Some(a) = &filter.algorithm {
            params.push(Box::new(a.clone()));
            where_parts.push(format!("algorithm = ${}", params.len()));
        }
        if let Some(revoked) = filter.revoked {
            let op = if revoked { "EXISTS" } else { "NOT EXISTS" };
            where_parts.push(format!(
                "{op} (SELECT 1 FROM cirislens.federation_revocations r \
                     WHERE r.revoked_key_id = cirislens.federation_keys.key_id)"
            ));
        }
        if let Some(pqc) = filter.pqc_completed {
            where_parts.push(if pqc {
                "pqc_completed_at IS NOT NULL".to_owned()
            } else {
                "pqc_completed_at IS NULL".to_owned()
            });
        }
        // v3.9.3 (CIRISPersist#151) — peer-level cohort_scope membership.
        // EXISTS-join the sibling federation_peer_metadata row, matching
        // the policy_blob JSONB `cohort_scope` slot; exclude soft-removed
        // peers (removed_at IS NULL — membership is a live property).
        if let Some(cs) = &filter.cohort_scope {
            params.push(Box::new(cs.clone()));
            where_parts.push(format!(
                "EXISTS (SELECT 1 FROM cirislens.federation_peer_metadata pm \
                     WHERE pm.key_id = cirislens.federation_keys.key_id \
                       AND pm.removed_at IS NULL \
                       AND pm.policy_blob->>'cohort_scope' = ${})",
                params.len()
            ));
        }
        if let Some(c) = &cursor {
            if c.version != "v1" {
                return Err(crate::read::Error::InvalidCursor(format!(
                    "FederationKeyCursor version {} unsupported; v0.5.5 ships v1",
                    c.version
                )));
            }
            params.push(Box::new(c.last_valid_from));
            let p_at = params.len();
            params.push(Box::new(c.last_key_id.clone()));
            let p_id = params.len();
            where_parts.push(format!("(valid_from, key_id) < (${p_at}, ${p_id})"));
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };
        params.push(Box::new(limit));
        let p_limit = params.len();
        let sql = format!(
            "SELECT key_id, pubkey_ed25519_base64, pubkey_ml_dsa_65_base64, algorithm, \
                    identity_type, identity_ref, valid_from, valid_until, registration_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, \
                    attestation_evidence \
             FROM cirislens.federation_keys \
             {where_sql} \
             ORDER BY valid_from DESC, key_id DESC \
             LIMIT ${p_limit}"
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("list_federation_keys: {e}")))?;
        let items: Result<Vec<crate::federation::KeyRecord>, crate::federation::Error> =
            rows.into_iter().map(pg_row_to_key_record).collect();
        let items =
            items.map_err(|e| crate::read::Error::Backend(format!("decode KeyRecord: {e}")))?;

        let next_cursor = if items.len() == limit as usize {
            let last = &items[items.len() - 1];
            Some(crate::read::FederationKeyCursor::from_trailing(
                last.valid_from,
                last.key_id.clone(),
            ))
        } else {
            None
        };
        Ok(crate::read::FederationKeyListPage { items, next_cursor })
    }

    /// Section I: list federation_attestations.
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
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(k) = &filter.attesting_key_id {
            params.push(Box::new(k.clone()));
            where_parts.push(format!("attesting_key_id = ${}", params.len()));
        }
        if let Some(k) = &filter.attested_key_id {
            params.push(Box::new(k.clone()));
            where_parts.push(format!("attested_key_id = ${}", params.len()));
        }
        if let Some(t) = &filter.attestation_type {
            params.push(Box::new(t.clone()));
            where_parts.push(format!("attestation_type = ${}", params.len()));
        }
        if let Some(pqc) = filter.pqc_completed {
            where_parts.push(if pqc {
                "pqc_completed_at IS NOT NULL".to_owned()
            } else {
                "pqc_completed_at IS NULL".to_owned()
            });
        }
        if let Some(c) = &cursor {
            if c.version != "v1" {
                return Err(crate::read::Error::InvalidCursor(format!(
                    "AttestationCursor version {} unsupported; v0.5.5 ships v1",
                    c.version
                )));
            }
            params.push(Box::new(c.last_asserted_at));
            let p_at = params.len();
            params.push(Box::new(c.last_attestation_id.clone()));
            let p_id = params.len();
            where_parts.push(format!(
                "(asserted_at, attestation_id::text) < (${p_at}, ${p_id})"
            ));
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };
        params.push(Box::new(limit));
        let p_limit = params.len();
        let sql = format!(
            // weight::float8 AS weight — see list_attestations_for.
            "SELECT attestation_id::text AS attestation_id, attesting_key_id, attested_key_id, \
                    attestation_type, weight::float8 AS weight, asserted_at, expires_at, attestation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope \
             FROM cirislens.federation_attestations \
             {where_sql} \
             ORDER BY asserted_at DESC, attestation_id DESC \
             LIMIT ${p_limit}"
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("list_attestations: {e}")))?;
        let items: Result<Vec<crate::federation::Attestation>, crate::federation::Error> =
            rows.into_iter().map(pg_row_to_attestation).collect();
        let items =
            items.map_err(|e| crate::read::Error::Backend(format!("decode Attestation: {e}")))?;
        let next_cursor = if items.len() == limit as usize {
            let last = &items[items.len() - 1];
            Some(crate::read::AttestationCursor::from_trailing(
                last.asserted_at,
                last.attestation_id.clone(),
            ))
        } else {
            None
        };
        Ok(crate::read::AttestationListPage { items, next_cursor })
    }

    /// Section I: list federation_revocations.
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
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| crate::read::Error::Backend(format!("pool: {e}")))?;

        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(k) = &filter.revoked_key_id {
            params.push(Box::new(k.clone()));
            where_parts.push(format!("revoked_key_id = ${}", params.len()));
        }
        if let Some(k) = &filter.revoking_key_id {
            params.push(Box::new(k.clone()));
            where_parts.push(format!("revoking_key_id = ${}", params.len()));
        }
        if let Some(pqc) = filter.pqc_completed {
            where_parts.push(if pqc {
                "pqc_completed_at IS NOT NULL".to_owned()
            } else {
                "pqc_completed_at IS NULL".to_owned()
            });
        }
        if let Some(c) = &cursor {
            if c.version != "v1" {
                return Err(crate::read::Error::InvalidCursor(format!(
                    "RevocationCursor version {} unsupported; v0.5.5 ships v1",
                    c.version
                )));
            }
            params.push(Box::new(c.last_revoked_at));
            let p_at = params.len();
            params.push(Box::new(c.last_revocation_id.clone()));
            let p_id = params.len();
            where_parts.push(format!(
                "(revoked_at, revocation_id::text) < (${p_at}, ${p_id})"
            ));
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };
        params.push(Box::new(limit));
        let p_limit = params.len();
        let sql = format!(
            "SELECT revocation_id::text AS revocation_id, revoked_key_id, revoking_key_id, reason, \
                    revoked_at, effective_at, revocation_envelope, \
                    original_content_hash, scrub_signature_classical, scrub_signature_pqc, \
                    scrub_key_id, scrub_timestamp, pqc_completed_at, observed_region, persist_row_hash \
             FROM cirislens.federation_revocations \
             {where_sql} \
             ORDER BY revoked_at DESC, revocation_id DESC \
             LIMIT ${p_limit}"
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| crate::read::Error::Backend(format!("list_revocations: {e}")))?;
        let items: Result<Vec<crate::federation::Revocation>, crate::federation::Error> =
            rows.into_iter().map(pg_row_to_revocation).collect();
        let items =
            items.map_err(|e| crate::read::Error::Backend(format!("decode Revocation: {e}")))?;
        let next_cursor = if items.len() == limit as usize {
            let last = &items[items.len() - 1];
            Some(crate::read::RevocationCursor::from_trailing(
                last.revoked_at,
                last.revocation_id.clone(),
            ))
        } else {
            None
        };
        Ok(crate::read::RevocationListPage { items, next_cursor })
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
                z_score: row.safe_get::<f64, _>("z_score")?,
                deviation_metric: metric,
                sample_count: row.safe_get::<i64, _>("sample_count")?,
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
            let bm: f64 = row.safe_get::<Option<f64>, _>("base_m")?.unwrap_or(0.0);
            let cm: f64 = row.safe_get::<Option<f64>, _>("comp_m")?.unwrap_or(0.0);
            let bv: f64 = row.safe_get::<Option<f64>, _>("base_v")?.unwrap_or(0.0);
            let cv: f64 = row.safe_get::<Option<f64>, _>("comp_v")?.unwrap_or(0.0);

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
        row.safe_get::<i64, _>("n")
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
        row.safe_get::<i64, _>("n")
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
        row.safe_get::<i64, _>("n")
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
            g_row.safe_get::<i64, _>("gap_count")?
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
/// v0.5.5 (CIRISPersist#23 §D) — build the JOIN + WHERE clauses + param
/// vec for [`crate::read::LlmCallFilter`]. Filters that need parent
/// trace_events columns (agent_id_hash / agent_name /
/// deployment_domain) force a JOIN to `cirislens.trace_events` on
/// `(trace_id, event_id)`. Returns `(join_sql, where_sql, params)`.
/// `where_sql` is either empty or starts with `"WHERE "`.
#[allow(clippy::type_complexity)]
fn build_llm_filter_sql(
    filter: &crate::read::LlmCallFilter,
) -> Result<
    (
        String,
        String,
        Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>>,
    ),
    crate::read::Error,
> {
    let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
    let mut where_parts: Vec<String> = Vec::new();

    let needs_join = filter.agent_id_hash.is_some()
        || filter.agent_name.is_some()
        || filter.deployment_domain.is_some();

    if let Some(w) = filter.time_window {
        params.push(Box::new(w.since));
        where_parts.push(format!("lc.ts >= ${}", params.len()));
        params.push(Box::new(w.until));
        where_parts.push(format!("lc.ts < ${}", params.len()));
    }
    if let Some(h) = &filter.agent_id_hash {
        params.push(Box::new(h.clone()));
        where_parts.push(format!("e.agent_id_hash = ${}", params.len()));
    }
    if let Some(n) = &filter.agent_name {
        params.push(Box::new(n.clone()));
        where_parts.push(format!("e.agent_name = ${}", params.len()));
    }
    if let Some(d) = &filter.deployment_domain {
        params.push(Box::new(d.clone()));
        where_parts.push(format!("e.deployment_domain = ${}", params.len()));
    }
    if let Some(m) = &filter.model {
        params.push(Box::new(m.clone()));
        where_parts.push(format!("lc.model = ${}", params.len()));
    }
    if let Some(s) = filter.status {
        let tok = match s {
            crate::schema::LlmCallStatus::Ok => "ok",
            crate::schema::LlmCallStatus::Timeout => "timeout",
            crate::schema::LlmCallStatus::RateLimited => "rate_limited",
            crate::schema::LlmCallStatus::ModelNotAvailable => "model_not_available",
            crate::schema::LlmCallStatus::InstructorRetry => "instructor_retry",
            crate::schema::LlmCallStatus::OtherError => "other_error",
        };
        params.push(Box::new(tok.to_owned()));
        where_parts.push(format!("lc.status = ${}", params.len()));
    }
    if let Some(t) = &filter.trace_id {
        params.push(Box::new(t.clone()));
        where_parts.push(format!("lc.trace_id = ${}", params.len()));
    }
    if let Some(t) = &filter.thought_id {
        params.push(Box::new(t.clone()));
        where_parts.push(format!("lc.thought_id = ${}", params.len()));
    }

    let join_sql = if needs_join {
        "JOIN cirislens.trace_events e \
           ON e.trace_id = lc.trace_id AND e.event_id = lc.parent_event_id"
            .to_owned()
    } else {
        String::new()
    };

    let where_sql = if where_parts.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_parts.join(" AND "))
    };
    Ok((join_sql, where_sql, params))
}

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

    // v3.1.1 (CIRISPersist#118) — admission for
    // `cirislens.edge_detection_events` (V020). Idempotent on
    // `detection_id` collision when persist_row_hash matches; raises
    // Conflict on collision with differing hash. detection_id is
    // UUID-typed on the PG side; subject_key_id FK to federation_keys.
    async fn put_edge_detection_event(
        &self,
        event: crate::derived::EdgeDetectionEvent,
    ) -> Result<(), crate::derived::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::derived::Error::Backend(e.to_string()))?;

        let detection_uuid = uuid::Uuid::parse_str(&event.detection_id).map_err(|e| {
            crate::derived::Error::InvalidArgument(format!(
                "detection_id must be a UUID (got {}): {e}",
                event.detection_id
            ))
        })?;

        let result = client
            .execute(
                "INSERT INTO cirislens.edge_detection_events (\
                    detection_id, tenant_id, detector_kind, subject_key_id, \
                    observed_at, evidence, severity, signature, signing_key_id, \
                    signature_verified, persist_row_hash\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) \
                 ON CONFLICT (detection_id) DO NOTHING",
                &[
                    &detection_uuid,
                    &event.tenant_id,
                    &event.detector_kind,
                    &event.subject_key_id,
                    &event.observed_at,
                    &event.evidence,
                    &event.severity,
                    &event.signature,
                    &event.signing_key_id,
                    &event.signature_verified,
                    &event.persist_row_hash,
                ],
            )
            .await
            .map_err(|e| {
                crate::derived::Error::Backend(format!("insert edge_detection_events: {e}"))
            })?;

        if result == 0 {
            let existing: Option<String> = client
                .query_opt(
                    "SELECT persist_row_hash FROM cirislens.edge_detection_events \
                     WHERE detection_id = $1",
                    &[&detection_uuid],
                )
                .await
                .map_err(|e| crate::derived::Error::Backend(format!("conflict check: {e}")))?
                .and_then(|r| {
                    r.safe_get_with("persist_row_hash", crate::derived::Error::Backend)
                        .ok()
                });
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
    }

    // v2.13.0 (CIRISPersist#113) — read facade over
    // `cirislens.edge_detection_events` (V020). Stable ORDER BY
    // `(tenant_id ASC, observed_at ASC, detection_id ASC)` — the
    // change-feed polling cursor in
    // [`crate::Engine::subscribe_detection_events`] depends on
    // monotone ASC ordering to advance without re-yielding rows.
    async fn get_edge_detection_events(
        &self,
        filter: crate::derived::EdgeEventFilter,
    ) -> Result<Vec<crate::derived::EdgeDetectionEvent>, crate::derived::Error> {
        let client = self
            .get_client()
            .await
            .map_err(|e| crate::derived::Error::Backend(e.to_string()))?;

        let mut query = String::from(
            "SELECT detection_id, tenant_id, detector_kind, subject_key_id, \
                observed_at, evidence, severity, signature, signing_key_id, \
                signature_verified, persist_row_hash \
             FROM cirislens.edge_detection_events WHERE 1 = 1",
        );
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(t) = filter.tenant_id {
            params.push(Box::new(t));
            query.push_str(&format!(" AND tenant_id = ${}", params.len()));
        }
        if let Some(p) = filter.peer_key_id {
            params.push(Box::new(p));
            query.push_str(&format!(" AND subject_key_id = ${}", params.len()));
        }
        if let Some(k) = filter.event_type {
            params.push(Box::new(k));
            query.push_str(&format!(" AND detector_kind = ${}", params.len()));
        }
        if let Some(after) = filter.recorded_after {
            // Strict `>` for the change-feed polling cursor — a re-poll
            // at the same cursor must NOT yield the row that advanced
            // the cursor.
            params.push(Box::new(after));
            query.push_str(&format!(" AND observed_at > ${}", params.len()));
        }
        let limit: i64 = filter
            .limit
            .map(|n| i64::try_from(n).unwrap_or(i64::MAX))
            .unwrap_or(1000);
        query.push_str(&format!(
            " ORDER BY tenant_id ASC, observed_at ASC, detection_id ASC LIMIT {limit}"
        ));

        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client.query(&query, &params_ref[..]).await.map_err(|e| {
            crate::derived::Error::Backend(format!("select edge_detection_events: {e}"))
        })?;

        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let mk_err = crate::derived::Error::Backend;
            // detection_id is UUID in PG; surface as TEXT to match
            // the public type (which has to bridge SQLite's TEXT id
            // anyway).
            let detection_id_uuid: uuid::Uuid = r.safe_get_with("detection_id", mk_err)?;
            out.push(crate::derived::EdgeDetectionEvent {
                detection_id: detection_id_uuid.to_string(),
                tenant_id: r.safe_get_with("tenant_id", mk_err)?,
                detector_kind: r.safe_get_with("detector_kind", mk_err)?,
                subject_key_id: r.safe_get_with("subject_key_id", mk_err)?,
                observed_at: r.safe_get_with("observed_at", mk_err)?,
                evidence: r.safe_get_with("evidence", mk_err)?,
                severity: r.safe_get_with("severity", mk_err)?,
                signature: r.safe_get_with("signature", mk_err)?,
                signing_key_id: r.safe_get_with("signing_key_id", mk_err)?,
                signature_verified: r.safe_get_with("signature_verified", mk_err)?,
                persist_row_hash: r.safe_get_with("persist_row_hash", mk_err)?,
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
            verification_source: crate::store::VerificationSource::Persist,
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
            cohort_scope: "federation".to_string(),
            cohort_target_id: None,
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
                verification_source: crate::store::VerificationSource::Persist,
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
                cohort_scope: "federation".to_string(),
                cohort_target_id: None,
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

    // ─── ReadEngine §C tests (v0.5.5, CIRISPersist#23) ──────────────

    /// Insert a fixture trace whose task_id is explicit. Reuses §A's
    /// fixture builder but overrides task_id post-insert via a second
    /// path: we can't customize task_id in
    /// `insert_section_a_fixture_trace` (it hard-codes `task-<trace_id>`),
    /// so this helper inserts directly with the explicit task_id.
    #[allow(clippy::too_many_arguments)]
    async fn insert_section_c_fixture_trace(
        backend: &PostgresBackend,
        trace_id: &str,
        task_id: &str,
        agent_id_hash: &str,
        agent_name: Option<&str>,
        deployment_domain: Option<&str>,
        started_at: chrono::DateTime<chrono::Utc>,
        thought_depth: i32,
        task_description: Option<&str>,
    ) -> String {
        let mk_row = |event_type: ReasoningEventType,
                      ts_offset_ms: i64,
                      payload: serde_json::Value|
         -> TraceEventRow {
            let payload_map: serde_json::Map<String, serde_json::Value> = match payload {
                serde_json::Value::Object(m) => m.into_iter().collect(),
                _ => serde_json::Map::new(),
            };
            TraceEventRow {
                trace_id: trace_id.to_owned(),
                thought_id: format!("th-{trace_id}"),
                task_id: Some(task_id.to_owned()),
                step_point: None,
                event_type,
                attempt_index: 0,
                ts: started_at + chrono::Duration::milliseconds(ts_offset_ms),
                agent_name: agent_name.map(str::to_owned),
                agent_id_hash: agent_id_hash.to_owned(),
                cognitive_state: Some("work".into()),
                trace_level: crate::schema::TraceLevel::Generic,
                payload: payload_map,
                cost_llm_calls: None,
                cost_tokens: None,
                cost_usd: None,
                signature: "AAAA".into(),
                signing_key_id: "test-key".into(),
                signature_verified: true,
                verification_source: crate::store::VerificationSource::Persist,
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
                cohort_scope: "federation".to_string(),
                cohort_target_id: None,
            }
        };

        let ts_payload = match task_description {
            Some(d) => serde_json::json!({
                "thought_type": "standard",
                "thought_depth": thought_depth,
                "task_description": d,
            }),
            None => serde_json::json!({
                "thought_type": "standard",
                "thought_depth": thought_depth,
            }),
        };

        let rows = vec![
            mk_row(ReasoningEventType::ThoughtStart, 0, ts_payload),
            mk_row(
                ReasoningEventType::ActionResult,
                10,
                serde_json::json!({"action_executed": "speak", "success": true}),
            ),
        ];
        backend.insert_trace_events_batch(&rows).await.unwrap();
        trace_id.to_owned()
    }

    /// §C: TaskClass derivation table — verify each prefix maps to the
    /// expected class. Pure-Rust unit; no DB.
    #[test]
    fn read_section_c_task_class_derivation() {
        use crate::read::TaskClass;
        assert_eq!(
            TaskClass::from_task_id("qa_eng_001"),
            TaskClass::QaEval,
            "qa_ prefix"
        );
        assert_eq!(
            TaskClass::from_task_id("qa-eval-batch-7"),
            TaskClass::QaEval,
            "qa-eval prefix"
        );
        assert_eq!(
            TaskClass::from_task_id("discord_msg_42"),
            TaskClass::Discord,
            "discord_ prefix"
        );
        assert_eq!(
            TaskClass::from_task_id("real_user_discord_abc"),
            TaskClass::RealUserDiscord,
            "real_user_discord_"
        );
        assert_eq!(
            TaskClass::from_task_id("real_user_cli_xyz"),
            TaskClass::RealUserCli,
            "real_user_cli_"
        );
        assert_eq!(
            TaskClass::from_task_id("real_user_api_post_/v1/agent"),
            TaskClass::RealUserApi,
            "real_user_api_"
        );
        assert_eq!(
            TaskClass::from_task_id("wakeup_2026_03_01T00_00_00Z"),
            TaskClass::WakeupRitual,
            "wakeup_ prefix"
        );
        assert_eq!(
            TaskClass::from_task_id("startup_wakeup_pre_op"),
            TaskClass::WakeupRitual,
            "wakeup substring (non-prefix)"
        );
        assert_eq!(
            TaskClass::from_task_id("random-task-id-xyz"),
            TaskClass::Other,
            "no prefix → Other"
        );
    }

    /// §C round-trip: insert three traces in three task_ids — one
    /// qa_eval, one wakeup_ritual, one other. Read back via list_tasks;
    /// verify shape, ordering, and task_class derivation.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_c_list_tasks_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        let aid = format!("agent-§c-rt-{}", uuid_like());
        let base = chrono::Utc::now() - chrono::Duration::hours(1);

        let qa_task = format!("qa_eng_{}", uuid_like());
        let wakeup_task = format!("wakeup_{}", uuid_like());
        let other_task = format!("rand-{}", uuid_like());

        insert_section_c_fixture_trace(
            &backend,
            &format!("tr-{}-1", uuid_like()),
            &qa_task,
            &aid,
            Some("Scout"),
            Some("moderation"),
            base,
            0,
            Some("hello world"),
        )
        .await;
        insert_section_c_fixture_trace(
            &backend,
            &format!("tr-{}-2", uuid_like()),
            &wakeup_task,
            &aid,
            Some("Scout"),
            Some("moderation"),
            base + chrono::Duration::minutes(1),
            0,
            Some("startup self-check"),
        )
        .await;
        insert_section_c_fixture_trace(
            &backend,
            &format!("tr-{}-3", uuid_like()),
            &other_task,
            &aid,
            Some("Scout"),
            Some("moderation"),
            base + chrono::Duration::minutes(2),
            0,
            None,
        )
        .await;

        let filter = crate::read::TaskFilter {
            agent_id_hash: Some(aid.clone()),
            ..Default::default()
        };
        let page = backend.list_tasks(filter, None, 100).await.unwrap();
        assert_eq!(page.items.len(), 3, "three tasks for this agent");

        // Newest-first ordering: other_task (latest) → wakeup → qa.
        assert_eq!(page.items[0].task_id, other_task);
        assert_eq!(page.items[0].task_class, crate::read::TaskClass::Other);
        assert_eq!(page.items[0].initial_observation, None);
        assert_eq!(page.items[1].task_id, wakeup_task);
        assert_eq!(
            page.items[1].task_class,
            crate::read::TaskClass::WakeupRitual
        );
        assert_eq!(
            page.items[1].initial_observation.as_deref(),
            Some("startup self-check")
        );
        assert_eq!(page.items[2].task_id, qa_task);
        assert_eq!(page.items[2].task_class, crate::read::TaskClass::QaEval);
        assert_eq!(
            page.items[2].initial_observation.as_deref(),
            Some("hello world")
        );

        // Each task carries its one trace summary.
        for tg in &page.items {
            assert_eq!(tg.traces.len(), 1, "one trace per task in this fixture");
            assert_eq!(tg.traces[0].agent_id_hash, aid);
        }

        // No more pages (items < limit → no cursor).
        assert!(page.next_cursor.is_none());
    }

    /// §C cursor pagination: 5 tasks, limit=2, walk pages 1/2/3, no
    /// overlap, no gaps, terminates with None.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_c_list_tasks_cursor_pagination() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        let aid = format!("agent-§c-cur-{}", uuid_like());
        let base = chrono::Utc::now() - chrono::Duration::hours(1);

        let mut task_ids: Vec<String> = Vec::new();
        for i in 0..5 {
            let task_id = format!("qa_seq_{}-{i}", uuid_like());
            insert_section_c_fixture_trace(
                &backend,
                &format!("tr-{}-{i}", uuid_like()),
                &task_id,
                &aid,
                None,
                None,
                base + chrono::Duration::minutes(i64::from(i)),
                0,
                None,
            )
            .await;
            task_ids.push(task_id);
        }
        // Newest-first = reverse insertion.
        task_ids.reverse();

        let filter = crate::read::TaskFilter {
            agent_id_hash: Some(aid.clone()),
            ..Default::default()
        };

        let p1 = backend.list_tasks(filter.clone(), None, 2).await.unwrap();
        assert_eq!(p1.items.len(), 2);
        assert_eq!(p1.items[0].task_id, task_ids[0]);
        assert_eq!(p1.items[1].task_id, task_ids[1]);
        let c1 = p1.next_cursor.expect("cursor for page 2");

        let p2 = backend
            .list_tasks(filter.clone(), Some(c1), 2)
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 2);
        assert_eq!(p2.items[0].task_id, task_ids[2]);
        assert_eq!(p2.items[1].task_id, task_ids[3]);
        let c2 = p2.next_cursor.expect("cursor for page 3");

        let p3 = backend
            .list_tasks(filter.clone(), Some(c2), 2)
            .await
            .unwrap();
        assert_eq!(p3.items.len(), 1);
        assert_eq!(p3.items[0].task_id, task_ids[4]);
        assert!(p3.next_cursor.is_none(), "items < limit → no further pages");
    }

    /// §C: task_class filter — filter for QaEval, assert only qa-
    /// prefixed tasks come back.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_c_list_tasks_task_class_filter() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        let aid = format!("agent-§c-tcf-{}", uuid_like());
        let base = chrono::Utc::now() - chrono::Duration::hours(1);

        let qa_a = format!("qa_a_{}", uuid_like());
        let qa_b = format!("qa-eval-b-{}", uuid_like());
        let wakeup = format!("wakeup_{}", uuid_like());
        let discord = format!("discord_{}", uuid_like());

        for (i, tid) in [&qa_a, &qa_b, &wakeup, &discord].iter().enumerate() {
            insert_section_c_fixture_trace(
                &backend,
                &format!("tr-{}-{i}", uuid_like()),
                tid,
                &aid,
                None,
                None,
                base + chrono::Duration::minutes(i as i64),
                0,
                None,
            )
            .await;
        }

        // Filter for QaEval: should return qa_a + qa_b only.
        let filter = crate::read::TaskFilter {
            agent_id_hash: Some(aid.clone()),
            task_class: Some(crate::read::TaskClass::QaEval),
            ..Default::default()
        };
        let page = backend.list_tasks(filter, None, 100).await.unwrap();
        assert_eq!(page.items.len(), 2, "only QaEval tasks");
        let ids: Vec<&str> = page.items.iter().map(|t| t.task_id.as_str()).collect();
        assert!(ids.contains(&qa_a.as_str()));
        assert!(ids.contains(&qa_b.as_str()));
        for item in &page.items {
            assert_eq!(item.task_class, crate::read::TaskClass::QaEval);
        }

        // Filter for Discord: should return discord only.
        let filter = crate::read::TaskFilter {
            agent_id_hash: Some(aid.clone()),
            task_class: Some(crate::read::TaskClass::Discord),
            ..Default::default()
        };
        let page = backend.list_tasks(filter, None, 100).await.unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].task_id, discord);

        // Filter for Other: should return nothing (every fixture is
        // recognized).
        let filter = crate::read::TaskFilter {
            agent_id_hash: Some(aid),
            task_class: Some(crate::read::TaskClass::Other),
            ..Default::default()
        };
        let page = backend.list_tasks(filter, None, 100).await.unwrap();
        assert!(page.items.is_empty(), "no Other tasks in fixture");
    }

    /// §C: limit validation — out-of-range limit returns InvalidArgument.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_c_list_tasks_limit_validation() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        let res = backend
            .list_tasks(crate::read::TaskFilter::default(), None, 0)
            .await;
        assert!(matches!(res, Err(crate::read::Error::InvalidArgument(_))));

        let res = backend
            .list_tasks(crate::read::TaskFilter::default(), None, 10_001)
            .await;
        assert!(matches!(res, Err(crate::read::Error::InvalidArgument(_))));
    }

    // ─── ReadEngine §D tests (v0.5.5, CIRISPersist#23) ──────────────

    /// Insert a parent trace + one trace_llm_calls row pointing at the
    /// DMA_RESULTS event. Returns the trace_id.
    #[allow(clippy::too_many_arguments)]
    async fn insert_section_d_fixture_llm(
        backend: &PostgresBackend,
        trace_id: &str,
        agent_id_hash: &str,
        agent_name: Option<&str>,
        deployment_domain: Option<&str>,
        started: chrono::DateTime<chrono::Utc>,
        model: &str,
        cost_usd: f64,
        prompt_tokens: i32,
        completion_tokens: i32,
        status: crate::schema::LlmCallStatus,
    ) -> String {
        insert_section_a_fixture_trace(
            backend,
            trace_id,
            agent_id_hash,
            agent_name,
            deployment_domain,
            started,
            false,
            0.83,
            0.91,
            1.42,
        )
        .await;

        let client = backend.pool.get().await.unwrap();
        let row = client
            .query_one(
                "SELECT event_id FROM cirislens.trace_events \
                 WHERE trace_id = $1 AND event_type = 'DMA_RESULTS' LIMIT 1",
                &[&trace_id],
            )
            .await
            .unwrap();
        let event_id: i64 = row.safe_get("event_id").unwrap();

        let llm_row = crate::store::types::TraceLlmCallRow {
            trace_id: trace_id.to_owned(),
            thought_id: format!("th-{trace_id}"),
            task_id: Some(format!("task-{trace_id}")),
            parent_event_id: Some(event_id),
            parent_event_type: ReasoningEventType::DmaResults,
            parent_attempt_index: 0,
            attempt_index: 0,
            ts: started + chrono::Duration::milliseconds(15),
            duration_ms: 1234.5,
            handler_name: "EthicalPDMA".into(),
            service_name: "openai".into(),
            model: Some(model.to_owned()),
            base_url: None,
            response_model: None,
            prompt_tokens: Some(prompt_tokens),
            completion_tokens: Some(completion_tokens),
            prompt_bytes: None,
            completion_bytes: None,
            cost_usd: Some(cost_usd),
            status,
            error_class: if matches!(status, crate::schema::LlmCallStatus::Ok) {
                None
            } else {
                Some("error".to_owned())
            },
            attempt_count: Some(1),
            retry_count: Some(0),
            prompt_hash: Some("hash-§d".into()),
            prompt: None,
            response_text: None,
        };
        backend
            .insert_trace_llm_calls_batch(&[llm_row])
            .await
            .unwrap();
        trace_id.to_owned()
    }

    /// §D list_llm_calls round-trip: insert one LLM call, list it back,
    /// fields match the fixture.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_d_list_llm_calls_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        let aid = format!("agent-§d-rt-{}", uuid_like());
        let tid = format!("trace-§d-rt-{}", uuid_like());
        let started = chrono::Utc::now() - chrono::Duration::minutes(30);
        insert_section_d_fixture_llm(
            &backend,
            &tid,
            &aid,
            Some("Scout-D"),
            Some("moderation"),
            started,
            "gpt-4o",
            0.024,
            800,
            150,
            crate::schema::LlmCallStatus::Ok,
        )
        .await;

        let filter = crate::read::LlmCallFilter {
            agent_id_hash: Some(aid.clone()),
            ..Default::default()
        };
        let page = backend.list_llm_calls(filter, None, 100).await.unwrap();
        assert_eq!(page.items.len(), 1);
        let r = &page.items[0];
        assert_eq!(r.trace_id, tid);
        assert_eq!(r.model.as_deref(), Some("gpt-4o"));
        assert_eq!(r.prompt_tokens, Some(800));
        assert_eq!(r.completion_tokens, Some(150));
        assert!((r.cost_usd.unwrap() - 0.024).abs() < 1e-9);
        assert!(matches!(r.status, crate::schema::LlmCallStatus::Ok));
        assert!(page.next_cursor.is_none(), "single row → no cursor");
    }

    /// §D cursor pagination: insert 5 LLM calls across 5 traces; page
    /// through with limit=2; assert no gaps + newest-first.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_d_list_llm_calls_cursor_pagination() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        let aid = format!("agent-§d-cur-{}", uuid_like());
        let base = chrono::Utc::now() - chrono::Duration::hours(1);
        let mut tids: Vec<String> = Vec::new();
        for i in 0..5 {
            let tid = format!("trace-§d-{}-{i}", uuid_like());
            insert_section_d_fixture_llm(
                &backend,
                &tid,
                &aid,
                None,
                None,
                base + chrono::Duration::minutes(i64::from(i)),
                "gpt-4o",
                0.01,
                100,
                50,
                crate::schema::LlmCallStatus::Ok,
            )
            .await;
            tids.push(tid);
        }
        tids.reverse(); // newest-first

        let filter = crate::read::LlmCallFilter {
            agent_id_hash: Some(aid.clone()),
            ..Default::default()
        };

        let p1 = backend
            .list_llm_calls(filter.clone(), None, 2)
            .await
            .unwrap();
        assert_eq!(p1.items.len(), 2);
        assert_eq!(p1.items[0].trace_id, tids[0]);
        let c1 = p1.next_cursor.expect("page 2 cursor");

        let p2 = backend
            .list_llm_calls(filter.clone(), Some(c1), 2)
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 2);
        assert_eq!(p2.items[0].trace_id, tids[2]);
        let c2 = p2.next_cursor.expect("page 3 cursor");

        let p3 = backend.list_llm_calls(filter, Some(c2), 2).await.unwrap();
        assert_eq!(p3.items.len(), 1);
        assert_eq!(p3.items[0].trace_id, tids[4]);
        assert!(p3.next_cursor.is_none());
    }

    /// §D aggregate_llm_costs: 3 calls split across 2 models, 2 agents,
    /// 2 domains, 1 failure. Every breakdown bucket + totals match.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_d_aggregate_llm_costs() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        let aid_a = format!("agent-§d-agg-A-{}", uuid_like());
        let aid_b = format!("agent-§d-agg-B-{}", uuid_like());
        let dom = format!("dom-§d-{}", uuid_like());
        let other_dom = format!("dom-§d-other-{}", uuid_like());
        let base = chrono::Utc::now() - chrono::Duration::hours(2);
        let until = chrono::Utc::now();
        let window =
            crate::read::TimeWindow::new(base - chrono::Duration::minutes(1), until).unwrap();

        // Three calls:
        // (A, gpt-4o, dom, 0.024, 800/150, Ok)
        // (A, gpt-4o, dom, 0.030, 1000/200, Timeout)
        // (B, claude-3-5-sonnet, other_dom, 0.045, 1200/300, Ok)
        insert_section_d_fixture_llm(
            &backend,
            &format!("trA1-{}", uuid_like()),
            &aid_a,
            Some("Scout-A"),
            Some(&dom),
            base,
            "gpt-4o",
            0.024,
            800,
            150,
            crate::schema::LlmCallStatus::Ok,
        )
        .await;
        insert_section_d_fixture_llm(
            &backend,
            &format!("trA2-{}", uuid_like()),
            &aid_a,
            Some("Scout-A"),
            Some(&dom),
            base + chrono::Duration::minutes(5),
            "gpt-4o",
            0.030,
            1000,
            200,
            crate::schema::LlmCallStatus::Timeout,
        )
        .await;
        insert_section_d_fixture_llm(
            &backend,
            &format!("trB-{}", uuid_like()),
            &aid_b,
            Some("Scout-B"),
            Some(&other_dom),
            base + chrono::Duration::minutes(10),
            "claude-3-5-sonnet",
            0.045,
            1200,
            300,
            crate::schema::LlmCallStatus::Ok,
        )
        .await;

        // Aggregate scoped to the two agents we inserted (otherwise
        // the assertions might race with other test data).
        let filter = crate::read::LlmCallFilter {
            time_window: Some(window),
            ..Default::default()
        };
        // narrow to one agent at a time to isolate the bucket math
        let only_a = crate::read::LlmCallFilter {
            time_window: Some(window),
            agent_id_hash: Some(aid_a.clone()),
            ..Default::default()
        };
        let agg = backend.aggregate_llm_costs(only_a).await.unwrap();
        assert_eq!(agg.totals.call_count, 2);
        assert_eq!(agg.totals.prompt_tokens, 1800);
        assert_eq!(agg.totals.completion_tokens, 350);
        assert!((agg.totals.cost_usd - 0.054).abs() < 1e-9);
        assert_eq!(agg.totals.error_count, 1, "one Timeout call");

        let m_gpt = agg.by_model.get("gpt-4o").expect("gpt-4o bucket");
        assert_eq!(m_gpt.call_count, 2);
        assert!((m_gpt.cost_usd - 0.054).abs() < 1e-9);
        assert_eq!(m_gpt.error_count, 1);

        let a_a = agg.by_agent.get(&aid_a).expect("agent A bucket");
        assert_eq!(a_a.call_count, 2);
        assert!((a_a.cost_usd - 0.054).abs() < 1e-9);

        // Same scope but filter on agent B; assert independent rollup.
        let only_b = crate::read::LlmCallFilter {
            time_window: Some(window),
            agent_id_hash: Some(aid_b),
            ..Default::default()
        };
        let agg_b = backend.aggregate_llm_costs(only_b).await.unwrap();
        assert_eq!(agg_b.totals.call_count, 1);
        let _ = filter; // touch to silence unused-var lint on the broader filter
    }

    /// §D empty-window aggregate: no rows match → every bucket map is
    /// empty AND totals are all zero (no NULL hazard, COALESCE
    /// hygiene from v0.5.1 / CIRISPersist#24 applied).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_d_aggregate_llm_costs_empty_window() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        // Far-future window guaranteed to be empty.
        let since = chrono::Utc::now() + chrono::Duration::days(365);
        let until = since + chrono::Duration::hours(1);
        let filter = crate::read::LlmCallFilter {
            time_window: Some(crate::read::TimeWindow::new(since, until).unwrap()),
            ..Default::default()
        };
        let agg = backend.aggregate_llm_costs(filter).await.unwrap();
        assert_eq!(agg.totals.call_count, 0);
        assert_eq!(agg.totals.prompt_tokens, 0);
        assert_eq!(agg.totals.completion_tokens, 0);
        assert_eq!(agg.totals.cost_usd, 0.0);
        assert_eq!(agg.totals.error_count, 0);
        assert!(agg.by_model.is_empty());
        assert!(agg.by_agent.is_empty());
        assert!(agg.by_domain.is_empty());
    }

    // ─── ReadEngine §G tests (v0.5.5, CIRISPersist#23) ──────────────

    /// §G corpus_shape: insert traces across multiple task_classes,
    /// agent_names, agent_templates, deployment_regions, and primary
    /// models; assert every bucket reflects the fixture.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_g_corpus_shape_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        let aid = format!("agent-§g-rt-{}", uuid_like());
        let base = chrono::Utc::now() - chrono::Duration::hours(1);
        let until = chrono::Utc::now() + chrono::Duration::minutes(1);
        let window =
            crate::read::TimeWindow::new(base - chrono::Duration::minutes(1), until).unwrap();

        // QA-eval English question 1 + 2 + Spanish question 1.
        let qa_en1 = format!("qa_eng_1_{}", uuid_like());
        let qa_en2 = format!("qa_eng_2_{}", uuid_like());
        let qa_es1 = format!("qa_spa_1_{}", uuid_like());
        // Wakeup ritual.
        let wakeup = format!("wakeup_{}", uuid_like());
        // Other (random).
        let other = format!("misc-{}", uuid_like());

        for (i, tid) in [&qa_en1, &qa_en2, &qa_es1, &wakeup, &other]
            .iter()
            .enumerate()
        {
            insert_section_c_fixture_trace(
                &backend,
                &format!("tr-§g-{}-{i}", uuid_like()),
                tid,
                &aid,
                Some("Scout-G"),
                Some("moderation"),
                base + chrono::Duration::minutes(i as i64),
                0,
                None,
            )
            .await;
        }

        let shape = backend
            .corpus_shape(crate::read::CorpusShapeFilter {
                time_window: window,
                agent_id_hash: Some(aid),
                agent_name: None,
                deployment_domain: None,
            })
            .await
            .unwrap();

        assert_eq!(shape.total_traces, 5, "five fixture traces");

        // task_class buckets.
        assert_eq!(
            shape.by_task_class.get(&crate::read::TaskClass::QaEval),
            Some(&3i64)
        );
        assert_eq!(
            shape
                .by_task_class
                .get(&crate::read::TaskClass::WakeupRitual),
            Some(&1)
        );
        assert_eq!(
            shape.by_task_class.get(&crate::read::TaskClass::Other),
            Some(&1)
        );
        assert!(!shape
            .by_task_class
            .contains_key(&crate::read::TaskClass::Discord));

        // QA language: 2 eng + 1 spa.
        assert_eq!(shape.by_qa_language.get("eng"), Some(&2i64));
        assert_eq!(shape.by_qa_language.get("spa"), Some(&1));
        // QA question_num: 2 → q1 (eng_1 + spa_1), 1 → q2 (eng_2).
        assert_eq!(shape.by_qa_question_num.get(&1), Some(&2i64));
        assert_eq!(shape.by_qa_question_num.get(&2), Some(&1));

        // agent_name + agent_version (= agent_template).
        assert_eq!(shape.by_agent_name.get("Scout-G"), Some(&5i64));
        assert_eq!(shape.by_agent_version.get("ally-v3-default"), Some(&5i64));
        assert_eq!(shape.by_deployment_region.get("US"), Some(&5i64));

        // No LLM calls in §C fixtures → empty primary_model map.
        assert!(shape.by_primary_model.is_empty());

        assert!(
            shape.stationarity_z_score.is_none(),
            "v0.5.5 returns None for stationarity (no baseline arg)"
        );
    }

    /// §G empty window: total_traces=0 + every map empty (no NULL hazard).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_g_corpus_shape_empty_window() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        let since = chrono::Utc::now() + chrono::Duration::days(365);
        let until = since + chrono::Duration::hours(1);
        let shape = backend
            .corpus_shape(crate::read::CorpusShapeFilter {
                time_window: crate::read::TimeWindow::new(since, until).unwrap(),
                agent_id_hash: None,
                agent_name: None,
                deployment_domain: None,
            })
            .await
            .unwrap();
        assert_eq!(shape.total_traces, 0);
        assert!(shape.by_task_class.is_empty());
        assert!(shape.by_qa_language.is_empty());
        assert!(shape.by_qa_question_num.is_empty());
        assert!(shape.by_agent_name.is_empty());
        assert!(shape.by_agent_version.is_empty());
        assert!(shape.by_primary_model.is_empty());
        assert!(shape.by_deployment_region.is_empty());
    }

    /// §G primary_model: insert two traces, one with mostly gpt-4o,
    /// one with mostly claude-3-5-sonnet; assert by_primary_model
    /// reflects the per-trace most-frequent model.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_g_corpus_shape_primary_model() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        let aid = format!("agent-§g-pm-{}", uuid_like());
        let base = chrono::Utc::now() - chrono::Duration::hours(1);
        let until = chrono::Utc::now() + chrono::Duration::minutes(1);
        let window =
            crate::read::TimeWindow::new(base - chrono::Duration::minutes(1), until).unwrap();

        // Trace 1: 2 gpt-4o + 1 claude → primary = gpt-4o
        let t1 = format!("tr-§g-pm1-{}", uuid_like());
        insert_section_d_fixture_llm(
            &backend,
            &t1,
            &aid,
            Some("Scout"),
            Some("dom"),
            base,
            "gpt-4o",
            0.01,
            100,
            50,
            crate::schema::LlmCallStatus::Ok,
        )
        .await;
        // Add a second gpt-4o + a claude row by directly inserting
        // additional LLM calls referencing the same trace.
        let client = backend.pool.get().await.unwrap();
        let parent_event_id: i64 = client
            .query_one(
                "SELECT event_id FROM cirislens.trace_events \
                 WHERE trace_id = $1 AND event_type = 'DMA_RESULTS' LIMIT 1",
                &[&t1],
            )
            .await
            .unwrap()
            .safe_get("event_id")
            .unwrap();
        let extra_rows = [("gpt-4o", 1u32), ("claude-3-5-sonnet", 2u32)];
        for (model, ai) in extra_rows.iter() {
            let r = crate::store::types::TraceLlmCallRow {
                trace_id: t1.clone(),
                thought_id: format!("th-{t1}"),
                task_id: Some(format!("task-{t1}")),
                parent_event_id: Some(parent_event_id),
                parent_event_type: ReasoningEventType::DmaResults,
                parent_attempt_index: 0,
                attempt_index: *ai,
                ts: base + chrono::Duration::milliseconds(20 + i64::from(*ai)),
                duration_ms: 100.0,
                handler_name: "EthicalPDMA".into(),
                service_name: "openai".into(),
                model: Some((*model).to_owned()),
                base_url: None,
                response_model: None,
                prompt_tokens: Some(100),
                completion_tokens: Some(50),
                prompt_bytes: None,
                completion_bytes: None,
                cost_usd: Some(0.005),
                status: crate::schema::LlmCallStatus::Ok,
                error_class: None,
                attempt_count: Some(1),
                retry_count: Some(0),
                prompt_hash: Some("hash".into()),
                prompt: None,
                response_text: None,
            };
            backend.insert_trace_llm_calls_batch(&[r]).await.unwrap();
        }

        // Trace 2: 1 claude call → primary = claude
        let t2 = format!("tr-§g-pm2-{}", uuid_like());
        insert_section_d_fixture_llm(
            &backend,
            &t2,
            &aid,
            Some("Scout"),
            Some("dom"),
            base + chrono::Duration::minutes(5),
            "claude-3-5-sonnet",
            0.02,
            100,
            50,
            crate::schema::LlmCallStatus::Ok,
        )
        .await;

        let shape = backend
            .corpus_shape(crate::read::CorpusShapeFilter {
                time_window: window,
                agent_id_hash: Some(aid),
                agent_name: None,
                deployment_domain: None,
            })
            .await
            .unwrap();
        assert_eq!(shape.total_traces, 2);
        assert_eq!(shape.by_primary_model.get("gpt-4o"), Some(&1i64));
        assert_eq!(shape.by_primary_model.get("claude-3-5-sonnet"), Some(&1i64));
    }

    // ─── ReadEngine §H tests (v0.5.5, CIRISPersist#23) ──────────────

    /// Insert a single-event trace with controllable pii_scrubbed +
    /// trace_level. Lighter than the 5-component §A fixture; §H only
    /// cares about pii_scrubbed + trace_level.
    async fn insert_section_h_fixture_scrubbed_trace(
        backend: &PostgresBackend,
        trace_id: &str,
        agent_id_hash: &str,
        started: chrono::DateTime<chrono::Utc>,
        pii_scrubbed: bool,
        trace_level: crate::schema::TraceLevel,
    ) {
        let row = TraceEventRow {
            trace_id: trace_id.to_owned(),
            thought_id: format!("th-{trace_id}"),
            task_id: Some(format!("task-{trace_id}")),
            step_point: None,
            event_type: ReasoningEventType::ThoughtStart,
            attempt_index: 0,
            ts: started,
            agent_name: Some("Scout-H".into()),
            agent_id_hash: agent_id_hash.to_owned(),
            cognitive_state: Some("work".into()),
            trace_level,
            payload: serde_json::Map::new(),
            cost_llm_calls: None,
            cost_tokens: None,
            cost_usd: None,
            signature: "AAAA".into(),
            signing_key_id: "test-key".into(),
            signature_verified: true,
            verification_source: crate::store::VerificationSource::Persist,
            schema_version: "2.7.0".into(),
            pii_scrubbed,
            original_content_hash: None,
            scrub_signature: None,
            scrub_key_id: None,
            scrub_timestamp: None,
            agent_role: Some("ally".into()),
            agent_template: Some("ally-v3-default".into()),
            deployment_domain: Some("moderation".into()),
            deployment_type: Some("production".into()),
            deployment_region: Some("US".into()),
            deployment_trust_mode: Some("federated_peer".into()),
            cohort_scope: "federation".to_string(),
            cohort_target_id: None,
        };
        backend.insert_trace_events_batch(&[row]).await.unwrap();
    }

    /// §H round-trip: insert 3 scrubbed traces (1 Generic, 2 Detailed)
    /// + 1 unscrubbed; assert envelopes_scrubbed=3 and by_trace_level
    /// reflects the levels.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_h_aggregate_scrub_stats_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        let aid = format!("agent-§h-{}", uuid_like());
        let base = chrono::Utc::now() - chrono::Duration::hours(1);
        let until = chrono::Utc::now() + chrono::Duration::minutes(1);
        let window =
            crate::read::TimeWindow::new(base - chrono::Duration::minutes(1), until).unwrap();

        insert_section_h_fixture_scrubbed_trace(
            &backend,
            &format!("tr-h-g-{}", uuid_like()),
            &aid,
            base,
            true,
            crate::schema::TraceLevel::Generic,
        )
        .await;
        insert_section_h_fixture_scrubbed_trace(
            &backend,
            &format!("tr-h-d1-{}", uuid_like()),
            &aid,
            base + chrono::Duration::minutes(1),
            true,
            crate::schema::TraceLevel::Detailed,
        )
        .await;
        insert_section_h_fixture_scrubbed_trace(
            &backend,
            &format!("tr-h-d2-{}", uuid_like()),
            &aid,
            base + chrono::Duration::minutes(2),
            true,
            crate::schema::TraceLevel::Detailed,
        )
        .await;
        insert_section_h_fixture_scrubbed_trace(
            &backend,
            &format!("tr-h-u-{}", uuid_like()),
            &aid,
            base + chrono::Duration::minutes(3),
            false,
            crate::schema::TraceLevel::Generic,
        )
        .await;

        // Note: aggregate_scrub_stats(window) doesn't filter by agent —
        // it's a global window aggregate. So we need to assert "at least
        // these counts", not "exactly these counts" (other tests may
        // share the window). Tighten by clamping the window to just our
        // fixture range.
        let agg = backend.aggregate_scrub_stats(window).await.unwrap();
        assert!(
            agg.envelopes_scrubbed >= 3,
            "at least 3 scrubbed; got {}",
            agg.envelopes_scrubbed
        );
        assert!(
            agg.by_trace_level
                .get(&crate::schema::TraceLevel::Detailed)
                .copied()
                .unwrap_or(0)
                >= 2
        );
        assert!(
            agg.by_trace_level
                .get(&crate::schema::TraceLevel::Generic)
                .copied()
                .unwrap_or(0)
                >= 1
        );

        // v0.5.5 limitations: until v0.6.0 ships the classification
        // pipeline, these MUST be 0/empty.
        assert_eq!(agg.fields_scrubbed_total, 0);
        assert!(agg.by_entity_type.is_empty());
    }

    /// §H empty window: zeroes + empty maps.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_h_aggregate_scrub_stats_empty_window() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        let since = chrono::Utc::now() + chrono::Duration::days(365);
        let until = since + chrono::Duration::hours(1);
        let window = crate::read::TimeWindow::new(since, until).unwrap();
        let agg = backend.aggregate_scrub_stats(window).await.unwrap();
        assert_eq!(agg.envelopes_scrubbed, 0);
        assert_eq!(agg.fields_scrubbed_total, 0);
        assert!(agg.by_entity_type.is_empty());
        assert!(agg.by_trace_level.is_empty());
    }

    // ─── ReadEngine §I tests (v0.5.5, CIRISPersist#23) ──────────────

    /// Build a federation KeyRecord with controllable valid_from /
    /// pqc_completed.
    fn fix_section_i_key(
        key_id: &str,
        identity_ref: &str,
        valid_from: chrono::DateTime<chrono::Utc>,
        pqc_completed: bool,
    ) -> crate::federation::KeyRecord {
        crate::federation::KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: crate::federation::types::identity_type::AGENT.into(),
            identity_ref: identity_ref.into(),
            valid_from,
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: if pqc_completed {
                Some("c2ln".into())
            } else {
                None
            },
            scrub_key_id: key_id.into(),
            scrub_timestamp: valid_from,
            pqc_completed_at: if pqc_completed {
                Some(valid_from)
            } else {
                None
            },
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
        }
    }

    /// V060 community substrate round-trip on Postgres — parity with
    /// the sqlite `community_round_trip` test. Gated on a live test PG
    /// (skips when `CIRIS_PERSIST_TEST_PG_URL` is unset), same as every
    /// other postgres test.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn community_round_trip_pg() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;

        let now = chrono::Utc::now();
        let suffix = uuid_like();
        let coop = format!("acme-coop-{suffix}");
        let alice = format!("alice-root-{suffix}");
        let bob = format!("bob-root-{suffix}");
        let carol = format!("carol-root-{suffix}");
        for kid in [&coop, &alice, &bob, &carol] {
            backend
                .put_public_key(crate::federation::SignedKeyRecord {
                    record: fix_section_i_key(kid, "acme", now, true),
                })
                .await
                .unwrap();
        }

        let policy = serde_json::json!({ "cohort_scope": "community" });
        backend
            .put_community(crate::federation::SignedCommunity {
                community: crate::federation::Community {
                    community_key_id: coop.clone(),
                    community_name: "Acme Co-op".into(),
                    members: [&alice, &bob, &carol]
                        .iter()
                        .map(|k| crate::federation::CommunityMember {
                            key_id: (*k).clone(),
                            joined_at: now,
                            role: None,
                        })
                        .collect(),
                    founded_at: now,
                    consensus_protocol: "majority".into(),
                    policy_blob: Some(policy.clone()),
                    persist_row_hash: String::new(),
                },
            })
            .await
            .unwrap();

        let got = backend
            .lookup_community(&coop)
            .await
            .unwrap()
            .expect("community exists");
        assert_eq!(got.community_name, "Acme Co-op");
        assert_eq!(got.members.len(), 3);
        assert_eq!(got.consensus_protocol, "majority");
        assert_eq!(got.policy_blob.as_ref(), Some(&policy));
        assert_eq!(got.persist_row_hash.len(), 64);

        // Membership GIN/@> fan-out returns the community for each member.
        for member in [&alice, &bob, &carol] {
            let communities = backend.list_communities_for_member(member).await.unwrap();
            assert_eq!(communities.len(), 1, "for member {member}");
            assert_eq!(&communities[0].community_key_id, &coop);
        }
        let none = backend
            .list_communities_for_member(&format!("nobody-{suffix}"))
            .await
            .unwrap();
        assert!(none.is_empty());
    }

    /// §I list_federation_keys round-trip + cursor pagination.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_i_list_federation_keys_cursor() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        use crate::read::ReadEngine;

        // Build 4 distinct keys for one identity_ref so the filter
        // narrows to our fixture set. valid_from staggered so cursor
        // ordering is deterministic.
        let identity = format!("agent-§i-{}", uuid_like());
        let base = chrono::Utc::now() - chrono::Duration::hours(2);
        let mut key_ids: Vec<String> = Vec::new();
        for i in 0..4 {
            let kid = format!("k-§i-{}-{i}", uuid_like());
            let key = fix_section_i_key(
                &kid,
                &identity,
                base + chrono::Duration::minutes(i64::from(i)),
                i % 2 == 0, // alternate pqc_completed
            );
            backend
                .put_public_key(crate::federation::SignedKeyRecord { record: key })
                .await
                .unwrap();
            key_ids.push(kid);
        }
        key_ids.reverse(); // newest-first

        let filter = crate::read::FederationKeyFilter {
            agent_id_hash: Some(identity.clone()),
            ..Default::default()
        };

        // Page 1
        let p1 = backend
            .list_federation_keys(filter.clone(), None, 2)
            .await
            .unwrap();
        assert_eq!(p1.items.len(), 2);
        assert_eq!(p1.items[0].key_id, key_ids[0]);
        assert_eq!(p1.items[1].key_id, key_ids[1]);
        let c1 = p1.next_cursor.expect("page 2 cursor");

        // Page 2 — exact-fill (2 remaining items, limit=2). The
        // pagination contract (matching §A) is "next_cursor is None
        // only when items.len() < limit"; an exact-match page returns
        // Some(cursor) and the consumer fetches one more page that
        // yields zero items. Page 3 below is the empty-tail probe.
        let p2 = backend
            .list_federation_keys(filter.clone(), Some(c1), 2)
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 2);
        assert_eq!(p2.items[0].key_id, key_ids[2]);
        assert_eq!(p2.items[1].key_id, key_ids[3]);
        let c2 = p2.next_cursor.expect("page 3 cursor (exact-fill page)");

        // Page 3 — empty tail, cursor None.
        let p3 = backend
            .list_federation_keys(filter.clone(), Some(c2), 2)
            .await
            .unwrap();
        assert!(p3.items.is_empty(), "no more items past 4-key fixture");
        assert!(p3.next_cursor.is_none(), "empty page → no cursor");

        // PQC filter: should return only 2 keys (i=0, i=2 had pqc=true,
        // i.e. key_ids[3] and key_ids[1] after reverse).
        let pqc_filter = crate::read::FederationKeyFilter {
            agent_id_hash: Some(identity.clone()),
            pqc_completed: Some(true),
            ..Default::default()
        };
        let pqc_page = backend
            .list_federation_keys(pqc_filter, None, 100)
            .await
            .unwrap();
        assert_eq!(pqc_page.items.len(), 2, "two pqc-complete keys");
        for k in &pqc_page.items {
            assert!(k.pqc_completed_at.is_some());
        }
    }

    /// §I list_revocations round-trip.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_i_list_revocations_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        use crate::read::ReadEngine;

        let identity = format!("agent-§i-rev-{}", uuid_like());
        let now = chrono::Utc::now();

        // Need attesting key + revoking key + a target key for the
        // revocation FK shape.
        let revoking_id = format!("revoke-§i-{}", uuid_like());
        let revoked_id = format!("victim-§i-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(&revoking_id, &identity, now, false),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(
                    &revoked_id,
                    &identity,
                    now - chrono::Duration::minutes(1),
                    false,
                ),
            })
            .await
            .unwrap();

        // revocation_id column is `::uuid` cast in put_revocation —
        // must be a valid UUID string, not the uuid_like() hex token.
        let rev_id = uuid::Uuid::new_v4().to_string();
        let rev = crate::federation::Revocation {
            revocation_id: rev_id.clone(),
            revoked_key_id: revoked_id.clone(),
            revoking_key_id: revoking_id.clone(),
            reason: Some("test".into()),
            revoked_at: now,
            effective_at: now,
            revocation_envelope: serde_json::json!({"id": rev_id}),
            // sha256-shaped placeholder hex — persist's revocation
            // path runs hex-decode on original_content_hash and rejects
            // odd-length strings. Use a full 64-char hex string.
            original_content_hash:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: revoking_id.clone(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            observed_region: crate::federation::verify_coord::region::US.into(),
            persist_row_hash: String::new(),
        };
        backend
            .put_revocation(crate::federation::SignedRevocation { revocation: rev })
            .await
            .unwrap();

        let page = backend
            .list_revocations(
                crate::read::RevocationFilter {
                    revoked_key_id: Some(revoked_id.clone()),
                    ..Default::default()
                },
                None,
                100,
            )
            .await
            .unwrap();
        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].revoked_key_id, revoked_id);
        assert_eq!(page.items[0].revoking_key_id, revoking_id);
    }

    /// §I limit validation.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn read_section_i_limit_validation() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::read::ReadEngine;

        for limit in [0i64, -1, 10_001] {
            let res = backend
                .list_federation_keys(crate::read::FederationKeyFilter::default(), None, limit)
                .await;
            assert!(
                matches!(res, Err(crate::read::Error::InvalidArgument(_))),
                "limit={limit} should be rejected"
            );
        }
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
            verification_source: crate::store::VerificationSource::Persist,
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
            cohort_scope: "federation".to_string(),
            cohort_target_id: None,
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

    // ─── Pipeline read tests (v0.6.0-α5, CIRISPersist#19) ───────────

    /// Insert a fixture trace + UPDATE extracted_features +
    /// classifications, then read back via the new inherent
    /// methods. Round-trip verifies V009 JSONB ↔ serde wire shapes.
    #[cfg(all(feature = "extract", feature = "classify"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pipeline_read_features_and_classifications_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let aid = format!("agent-pipe-rd-{}", uuid_like());
        let tid = format!("tr-pipe-{}", uuid_like());
        let thid = format!("th-{tid}");
        let started = chrono::Utc::now();

        // Build a minimal trace row carrying the (trace_id, thought_id)
        // pair we'll write features for.
        insert_section_a_fixture_trace(
            &backend,
            &tid,
            &aid,
            Some("Pipe"),
            Some("moderation"),
            started,
            false,
            0.5,
            0.5,
            1.0,
        )
        .await;

        // Build a Features value via the extract module + write it
        // into the V009 column directly. (Pipeline orchestration
        // lands in a follow-up alpha; this exercises the round-trip
        // wire shape only.)
        let declared = crate::pipeline::extract::DeclaredCohortAxes {
            agent_role: Some("ally".into()),
            agent_template: Some("ally-v3-default".into()),
            deployment_domain: Some("moderation".into()),
            deployment_type: Some("production".into()),
            deployment_region: Some("US".into()),
            deployment_trust_mode: Some("federated_peer".into()),
        };
        let features = crate::pipeline::extract::extract_features(
            &serde_json::json!({"components": []}),
            declared,
        );
        let features_json = serde_json::to_value(&features).unwrap();

        let cls: Vec<Vec<crate::pipeline::classify::ContentClassMatch>> =
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
            }]];
        let cls_json = serde_json::to_value(&cls).unwrap();

        // UPDATE the (trace_id, thought_id) rows we just inserted so
        // every row carries the pipeline JSONB.
        let client = backend.pool.get().await.unwrap();
        let n = client
            .execute(
                "UPDATE cirislens.trace_events \
                 SET extracted_features = $1, classifications = $2 \
                 WHERE trace_id = $3 AND thought_id = $4",
                &[&features_json, &cls_json, &tid, &thid],
            )
            .await
            .unwrap();
        assert!(n > 0, "pipeline UPDATE touched at least one row");

        let f_read = backend
            .read_features(&tid, &thid)
            .await
            .unwrap()
            .expect("features present");
        assert_eq!(
            f_read.declared.deployment_domain.as_deref(),
            Some("moderation")
        );

        let c_read = backend.read_classifications(&tid, &thid).await.unwrap();
        assert_eq!(c_read.len(), 1, "one component classified");
        assert_eq!(c_read[0].len(), 1, "one match in that component");
        assert_eq!(
            c_read[0][0].class,
            crate::pipeline::classify::ContentClass::EmailAddress
        );
        assert_eq!(c_read[0][0].matcher_id, "regex:email_v1");
    }

    /// v1.5.8 (CIRISPersist#57) — write_classifications + write_features
    /// round-trip through the V009 columns. Public write surface for
    /// the agent's AdaptiveFilter output (parity with SQLite V023).
    #[cfg(all(feature = "extract", feature = "classify"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pipeline_write_features_and_classifications_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let aid = format!("agent-pipe-wr-{}", uuid_like());
        let tid = format!("tr-pipe-wr-{}", uuid_like());
        let thid = format!("th-{tid}");
        let started = chrono::Utc::now();
        insert_section_a_fixture_trace(
            &backend,
            &tid,
            &aid,
            Some("PipeW"),
            Some("moderation"),
            started,
            false,
            0.5,
            0.5,
            1.0,
        )
        .await;

        let declared = crate::pipeline::extract::DeclaredCohortAxes {
            agent_role: Some("ally".into()),
            agent_template: Some("ally-v3-default".into()),
            deployment_domain: Some("moderation".into()),
            deployment_type: Some("production".into()),
            deployment_region: Some("US".into()),
            deployment_trust_mode: Some("federated_peer".into()),
        };
        let features = crate::pipeline::extract::extract_features(
            &serde_json::json!({"components": []}),
            declared,
        );
        backend
            .write_features(&tid, &thid, &features)
            .await
            .unwrap();

        let cls: Vec<Vec<crate::pipeline::classify::ContentClassMatch>> =
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
            }]];
        backend
            .write_classifications(&tid, &thid, &cls)
            .await
            .unwrap();

        let f_read = backend
            .read_features(&tid, &thid)
            .await
            .unwrap()
            .expect("features present");
        assert_eq!(
            f_read.declared.deployment_domain.as_deref(),
            Some("moderation")
        );
        let c_read = backend.read_classifications(&tid, &thid).await.unwrap();
        assert_eq!(c_read.len(), 1);
        assert_eq!(c_read[0][0].matcher_id, "regex:email_v1");
    }

    /// v1.5.8 (CIRISPersist#57) — write_classifications on a missing
    /// (trace_id, thought_id) is a no-op (UPDATE affects 0 rows),
    /// returns Ok(()). Caller contract: "set this if the row exists."
    #[cfg(feature = "classify")]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pipeline_write_classifications_missing_row_is_noop() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let cls: Vec<Vec<crate::pipeline::classify::ContentClassMatch>> = vec![];
        let tid = format!("tr-missing-{}", uuid_like());
        let thid = format!("th-{tid}");
        backend
            .write_classifications(&tid, &thid, &cls)
            .await
            .unwrap();
        let got = backend.read_classifications(&tid, &thid).await.unwrap();
        assert!(got.is_empty());
    }

    /// v0.7.4 (CIRISPersist#19) — `Backend::update_features_batch`
    /// UPDATEs the V009 `extracted_features` column via UNNEST'd
    /// arrays in a single round-trip. This is the post-insert path
    /// that `IngestPipeline::receive_and_persist` calls.
    ///
    /// Test: insert 2 fixture traces → batch-update both with
    /// distinct Features → read_features returns the right value
    /// per trace. Also covers empty-update fast-path (returns 0
    /// without hitting the DB).
    #[cfg(all(feature = "extract", feature = "classify"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn update_features_batch_round_trip() {
        use crate::store::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let aid = format!("agent-uf-{}", uuid_like());
        let tid_a = format!("tr-uf-a-{}", uuid_like());
        let thid_a = format!("th-{tid_a}");
        let tid_b = format!("tr-uf-b-{}", uuid_like());
        let thid_b = format!("th-{tid_b}");
        let started = chrono::Utc::now();
        for tid in [&tid_a, &tid_b] {
            insert_section_a_fixture_trace(
                &backend,
                tid,
                &aid,
                Some("UF"),
                Some("moderation"),
                started,
                false,
                0.5,
                0.5,
                1.0,
            )
            .await;
        }

        // Empty fast-path: returns 0, doesn't error.
        let zero = backend.update_features_batch(&[]).await.unwrap();
        assert_eq!(zero, 0);

        let declared_a = crate::pipeline::extract::DeclaredCohortAxes {
            agent_role: Some("ally".into()),
            agent_template: Some("ally-v3-default".into()),
            deployment_domain: Some("moderation".into()),
            deployment_type: Some("production".into()),
            deployment_region: Some("US".into()),
            deployment_trust_mode: Some("federated_peer".into()),
        };
        let declared_b = crate::pipeline::extract::DeclaredCohortAxes {
            agent_role: Some("scout".into()),
            agent_template: Some("scout-v1".into()),
            deployment_domain: Some("research".into()),
            deployment_type: Some("staging".into()),
            deployment_region: Some("EU".into()),
            deployment_trust_mode: Some("sovereign".into()),
        };
        let features_a = crate::pipeline::extract::extract_features(
            &serde_json::json!({"components": []}),
            declared_a,
        );
        let features_b = crate::pipeline::extract::extract_features(
            &serde_json::json!({"components": []}),
            declared_b,
        );

        let n = backend
            .update_features_batch(&[
                (tid_a.clone(), thid_a.clone(), features_a),
                (tid_b.clone(), thid_b.clone(), features_b),
            ])
            .await
            .unwrap();
        // Each (trace_id, thought_id) maps to N component rows in
        // the fixture; the UPDATE touches every matching row.
        assert!(n >= 2, "expected at least one row per trace, got {n}");

        let f_a = backend
            .read_features(&tid_a, &thid_a)
            .await
            .unwrap()
            .expect("features_a present");
        assert_eq!(
            f_a.declared.deployment_domain.as_deref(),
            Some("moderation")
        );
        let f_b = backend
            .read_features(&tid_b, &thid_b)
            .await
            .unwrap()
            .expect("features_b present");
        assert_eq!(f_b.declared.deployment_domain.as_deref(), Some("research"));
        assert_eq!(f_b.declared.agent_role.as_deref(), Some("scout"));
    }

    /// Pre-pipeline rows return None / empty (V009 columns are
    /// nullable and stay NULL until the pipeline writes them).
    #[cfg(all(feature = "extract", feature = "classify"))]
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pipeline_read_returns_none_for_pre_pipeline_row() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();

        let aid = format!("agent-pipe-null-{}", uuid_like());
        let tid = format!("tr-pipe-null-{}", uuid_like());
        let thid = format!("th-{tid}");
        let started = chrono::Utc::now();
        insert_section_a_fixture_trace(
            &backend, &tid, &aid, None, None, started, false, 0.5, 0.5, 1.0,
        )
        .await;

        // No UPDATE → extracted_features stays NULL.
        let f = backend.read_features(&tid, &thid).await.unwrap();
        assert!(f.is_none(), "pre-pipeline row → None");

        let c = backend.read_classifications(&tid, &thid).await.unwrap();
        assert!(c.is_empty(), "pre-pipeline row → empty Vec");
    }

    // ─── Trust hierarchy tests (v1.3.0, CIRISPersist#46+#47) ───────
    //
    // PG-side counterparts to the SQLite trust tests. Validates the
    // V020 column additions + CHECK constraints + UPSERT semantics
    // against a real Postgres deployment. Gated on
    // CIRIS_PERSIST_TEST_PG_URL like the rest of this test module.

    async fn trust_steward(backend: &PostgresBackend) -> String {
        let kid = format!("trust-steward-{}", uuid_like());
        use crate::federation::FederationDirectory;
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(&kid, "registry", chrono::Utc::now(), false),
            })
            .await
            .unwrap();
        kid
    }

    /// Trust shape 1+2+3: round-trip + self-trust reject + Registry-
    /// without-domains reject (run as one composed test because pg
    /// runs are serialized and each does its own connect+migrate).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn trust_pg_grant_lookup_and_validation() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;

        let steward = trust_steward(&backend).await;
        let key_id = format!("trust-k-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(&key_id, "primitive", chrono::Utc::now(), false),
            })
            .await
            .unwrap();

        // Shape 1: round-trip.
        let grant = crate::federation::TrustGrant {
            key: key_id.clone(),
            trust_type: crate::federation::TrustType::Partnered,
            trust_relationship: crate::federation::TrustRelationship::Direct,
            trust_domains: None,
            trusted_by: steward.clone(),
            expires_at: None,
        };
        backend.grant_trust(grant).await.unwrap();
        let row = backend.lookup_trust(&key_id).await.unwrap().unwrap();
        assert_eq!(row.key, key_id);
        assert_eq!(row.trust_type, crate::federation::TrustType::Partnered);
        assert_eq!(
            row.trust_relationship,
            crate::federation::TrustRelationship::Direct
        );
        assert_eq!(row.trusted_by, steward);

        // Shape 2: self-trust is rejected at the API surface.
        let bad_self = crate::federation::TrustGrant {
            key: key_id.clone(),
            trust_type: crate::federation::TrustType::Temporary,
            trust_relationship: crate::federation::TrustRelationship::Direct,
            trust_domains: None,
            trusted_by: key_id.clone(),
            expires_at: None,
        };
        let err = backend.grant_trust(bad_self).await.unwrap_err();
        assert!(matches!(err, crate::federation::Error::InvalidArgument(_)));

        // Shape 3: Registry without domains is rejected at the API
        // surface (also at the V020 PG CHECK constraint).
        let bad_registry = crate::federation::TrustGrant {
            key: key_id.clone(),
            trust_type: crate::federation::TrustType::Temporary,
            trust_relationship: crate::federation::TrustRelationship::Registry,
            trust_domains: None,
            trusted_by: steward.clone(),
            expires_at: None,
        };
        let err = backend.grant_trust(bad_registry).await.unwrap_err();
        assert!(matches!(err, crate::federation::Error::InvalidArgument(_)));
    }

    /// Trust shape 4+6: revoke idempotent + include_expired filter.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn trust_pg_revoke_idempotent_and_filter_expired() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;

        let steward = trust_steward(&backend).await;
        let key_id = format!("trust-revoke-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(&key_id, "primitive", chrono::Utc::now(), false),
            })
            .await
            .unwrap();
        let grant = crate::federation::TrustGrant {
            key: key_id.clone(),
            trust_type: crate::federation::TrustType::Temporary,
            trust_relationship: crate::federation::TrustRelationship::Direct,
            trust_domains: None,
            trusted_by: steward.clone(),
            expires_at: None,
        };
        backend.grant_trust(grant).await.unwrap();
        backend.revoke_trust(&key_id, &steward).await.unwrap();
        // Second revoke MUST succeed (idempotent).
        backend.revoke_trust(&key_id, &steward).await.unwrap();
        let row = backend.lookup_trust(&key_id).await.unwrap().unwrap();
        assert!(row.expires_at.is_some());

        // include_expired=false → row excluded; include_expired=true → included.
        let active = backend
            .list_trusted_keys(crate::federation::TrustFilter::default())
            .await
            .unwrap();
        assert!(active.iter().all(|r| r.key != key_id));
        let all = backend
            .list_trusted_keys(crate::federation::TrustFilter {
                include_expired: true,
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(all.iter().any(|r| r.key == key_id));
    }

    /// Trust shape 5: relationship + domain filter scoped to Registry.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn trust_pg_list_filter_relationship_and_domain() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;

        let steward = trust_steward(&backend).await;
        let domain = format!("alpha-{}", uuid_like());
        let k_direct = format!("trust-d-{}", uuid_like());
        let k_registry = format!("trust-r-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(&k_direct, "primitive", chrono::Utc::now(), false),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(&k_registry, "primitive", chrono::Utc::now(), false),
            })
            .await
            .unwrap();
        backend
            .grant_trust(crate::federation::TrustGrant {
                key: k_direct.clone(),
                trust_type: crate::federation::TrustType::Temporary,
                trust_relationship: crate::federation::TrustRelationship::Direct,
                trust_domains: None,
                trusted_by: steward.clone(),
                expires_at: None,
            })
            .await
            .unwrap();
        backend
            .grant_trust(crate::federation::TrustGrant {
                key: k_registry.clone(),
                trust_type: crate::federation::TrustType::Temporary,
                trust_relationship: crate::federation::TrustRelationship::Registry,
                trust_domains: Some(vec![domain.clone()]),
                trusted_by: steward.clone(),
                expires_at: None,
            })
            .await
            .unwrap();

        let registry_only = backend
            .list_trusted_keys(crate::federation::TrustFilter {
                trust_relationship: Some(crate::federation::TrustRelationship::Registry),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(registry_only.iter().any(|r| r.key == k_registry));
        assert!(registry_only.iter().all(|r| r.key != k_direct));

        let in_domain = backend
            .list_trusted_keys(crate::federation::TrustFilter {
                trust_relationship: Some(crate::federation::TrustRelationship::Registry),
                domain: Some(domain.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(in_domain.iter().any(|r| r.key == k_registry));
    }

    // ─── BlobStorage tests (v2.3, CIRISPersist#103) ────────────────
    //
    // PG parity for the SQLite tests in store/sqlite.rs. Each test is
    // serialized via `serial_test::serial(postgres)` because the
    // shared test DB doesn't isolate writes per-test; rows from one
    // test would otherwise leak into another's `list_holders`. The
    // SHA prefix is randomized via `uuid_like()` so leaked attestation
    // rows still can't accidentally match.

    fn pg_sha256_of(bytes: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let d = Sha256::digest(bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    /// Mix a per-test random suffix into the byte payload so the
    /// derived SHA differs from any other test's blob. Avoids
    /// cross-test interference on the shared PG test DB.
    fn pg_blob_payload(prefix: &str) -> Vec<u8> {
        format!("{prefix}-{}", uuid_like()).into_bytes()
    }

    async fn pg_blob_bootstrap_host(backend: &PostgresBackend, host_key_id: &str) {
        use crate::federation::FederationDirectory;
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(host_key_id, host_key_id, chrono::Utc::now(), false),
            })
            .await
            .unwrap();
    }

    fn pg_blob_attestation(
        attesting_key_id: &str,
        scrub_key_id: &str,
    ) -> crate::federation::PutBlobAttestation {
        crate::federation::PutBlobAttestation {
            attesting_key_id: attesting_key_id.into(),
            attestation_id: uuid::Uuid::new_v4().to_string(),
            original_content_hash_hex: "deadbeef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp: chrono::Utc::now(),
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blob_pg_inline_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobStorage};
        let host = format!("blob-host-inline-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        let bytes = pg_blob_payload("inline");
        let sha = pg_sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes.clone()),
                Some("application/octet-stream"),
                pg_blob_attestation(&host, &host),
            )
            .await
            .expect("put inline");
        let got = backend.get_blob(&sha).await.expect("get").expect("present");
        assert_eq!(got, BlobBody::Inline(bytes));
    }

    /// v3.9.2 (CIRISPersist#153 Ask 5) — store_blob_local persists the
    /// bytes but emits NO holds_bytes attestation (structural
    /// invisibility for cohort_scope self/family). Parity with the
    /// sqlite `store_blob_local_persists_bytes_without_announcing` test.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blob_pg_store_blob_local_persists_without_announcing() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobStorage};
        let bytes = pg_blob_payload("local-only");
        let sha = pg_sha256_of(&bytes);
        backend
            .store_blob_local(&sha, BlobBody::Inline(bytes.clone()), None)
            .await
            .expect("store_blob_local");
        // Bytes readable locally.
        let got = backend.get_blob(&sha).await.expect("get").expect("present");
        assert_eq!(got, BlobBody::Inline(bytes));
        // Nothing announced — no holds_bytes attestation.
        assert!(
            backend.list_holders(&sha).await.unwrap().is_empty(),
            "self/family content must emit no holds_bytes attestation"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blob_pg_external_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobStorage, ExternalRef};
        let host = format!("blob-host-ext-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        // Random SHA for the external case (we trust the caller's
        // SHA; no bytes to verify against).
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut sha = [0u8; 32];
        sha[..16].copy_from_slice(&nanos.to_be_bytes());
        sha[16..].copy_from_slice(&nanos.to_be_bytes());
        let ext = ExternalRef {
            uri: format!("s3://bucket/{}", uuid_like()),
            size_bytes: 99_999_999,
            media_type: Some("video/mp4".into()),
        };
        backend
            .put_blob(
                &sha,
                BlobBody::External(ext.clone()),
                Some("video/mp4"),
                pg_blob_attestation(&host, &host),
            )
            .await
            .unwrap();
        let got = backend.get_blob(&sha).await.unwrap().unwrap();
        assert_eq!(got, BlobBody::External(ext));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blob_pg_hash_mismatch_rejected() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobError, BlobStorage};
        let host = format!("blob-host-mm-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        let bytes = pg_blob_payload("mismatch");
        let mut wrong = pg_sha256_of(&bytes);
        wrong[0] ^= 0xff;
        let err = backend
            .put_blob(
                &wrong,
                BlobBody::Inline(bytes),
                None,
                pg_blob_attestation(&host, &host),
            )
            .await
            .expect_err("must reject");
        assert!(matches!(err, BlobError::HashMismatch { .. }));
        assert_eq!(err.kind(), "blob_hash_mismatch");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blob_pg_inline_size_cap_rejected() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobError, BlobStorage};
        let host = format!("blob-host-cap-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        let bytes = vec![0u8; 2 * 1024 * 1024];
        let sha = pg_sha256_of(&bytes);
        let err = backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                pg_blob_attestation(&host, &host),
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
    #[serial_test::serial(postgres)]
    async fn blob_pg_has_blob_existence_check() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobStorage};
        let host = format!("blob-host-has-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        let bytes = pg_blob_payload("has");
        let sha = pg_sha256_of(&bytes);
        assert!(!backend.has_blob(&sha).await.unwrap());
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                pg_blob_attestation(&host, &host),
            )
            .await
            .unwrap();
        assert!(backend.has_blob(&sha).await.unwrap());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blob_pg_list_holders_two_writers() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobStorage};
        let host_a = format!("blob-host-a-{}", uuid_like());
        let host_b = format!("blob-host-b-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host_a).await;
        pg_blob_bootstrap_host(&backend, &host_b).await;
        let bytes = pg_blob_payload("two-writers");
        let sha = pg_sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes.clone()),
                None,
                pg_blob_attestation(&host_a, &host_a),
            )
            .await
            .unwrap();
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                pg_blob_attestation(&host_b, &host_b),
            )
            .await
            .unwrap();
        let mut holders = backend.list_holders(&sha).await.unwrap();
        holders.sort();
        let mut expected = vec![host_a, host_b];
        expected.sort();
        assert_eq!(holders, expected);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blob_pg_idempotent_put_same_writer() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobStorage};
        let host = format!("blob-host-idem-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        let bytes = pg_blob_payload("idem");
        let sha = pg_sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes.clone()),
                None,
                pg_blob_attestation(&host, &host),
            )
            .await
            .unwrap();
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                pg_blob_attestation(&host, &host),
            )
            .await
            .unwrap();
        let holders = backend.list_holders(&sha).await.unwrap();
        assert_eq!(holders, vec![host]);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blob_pg_conflicting_storage_kind_first_write_wins() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobStorage, ExternalRef};
        let host_a = format!("blob-host-cf-a-{}", uuid_like());
        let host_b = format!("blob-host-cf-b-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host_a).await;
        pg_blob_bootstrap_host(&backend, &host_b).await;
        let bytes = pg_blob_payload("conflict");
        let sha = pg_sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes.clone()),
                None,
                pg_blob_attestation(&host_a, &host_a),
            )
            .await
            .unwrap();
        backend
            .put_blob(
                &sha,
                BlobBody::External(ExternalRef {
                    uri: "s3://mirror/key".into(),
                    size_bytes: bytes.len() as u64,
                    media_type: None,
                }),
                None,
                pg_blob_attestation(&host_b, &host_b),
            )
            .await
            .unwrap();
        let got = backend.get_blob(&sha).await.unwrap().unwrap();
        match got {
            BlobBody::Inline(b) => assert_eq!(b, bytes),
            other => panic!("expected Inline (first-write-wins), got {other:?}"),
        }
        let mut holders = backend.list_holders(&sha).await.unwrap();
        holders.sort();
        let mut expected = vec![host_a, host_b];
        expected.sort();
        assert_eq!(holders, expected);
    }

    // ─── Admission-gate tests (v2.4.0, CIRISPersist#102 Ask 3) ──────

    /// Build a federation KeyRecord with parameterized identity_type
    /// — covers the `accord_holder` vs `steward` distinction the
    /// admission gate switches on for `accord:*` dimensions.
    /// v2.5.0 (CIRISPersist#102 Ask 8): when `identity_type =
    /// accord_holder` the helper auto-fills a valid hardware-
    /// attestation evidence value so the new admission gate
    /// doesn't reject the fixture.
    fn pg_admission_key(
        key_id: &str,
        identity_ref: &str,
        identity_type: &str,
    ) -> crate::federation::KeyRecord {
        let mut k = fix_section_i_key(key_id, identity_ref, chrono::Utc::now(), false);
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

    fn pg_scores_attestation(
        attesting: &str,
        attested: &str,
        scrub_key_id: &str,
        dimension: &str,
    ) -> crate::federation::Attestation {
        // attestation_id is `::uuid`-cast on the postgres write
        // path — needs a real UUID per `project_test_fixtures_uuid_vs_uuid_like`.
        // weight: Some(1.0) exercises the `$5::float8::numeric` cast
        // that put_attestation uses to handle f64→NUMERIC.
        crate::federation::Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: attesting.into(),
            attested_key_id: attested.into(),
            attestation_type: crate::federation::types::attestation_type::SCORES.into(),
            weight: Some(1.0),
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": dimension,
                "score": 1.0,
                "confidence": 0.9,
            }),
            original_content_hash: "abc123".into(),
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

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_rejects_accord_dimension_from_steward() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let steward = format!("pg-steward-§102-{}", uuid_like());
        let agent_k = format!("pg-agent-§102-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-a",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();
        let att = pg_scores_attestation(&steward, &agent_k, &steward, "accord:human_dignity:v1");
        let err = backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::federation::Error::AccordDimensionRequiresAccordHolder { .. }
        ));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_accepts_accord_dimension_from_accord_holder() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let holder = format!("pg-holder-§102-{}", uuid_like());
        let agent_k = format!("pg-aa-§102-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &holder,
                    "humanity-accord-1",
                    crate::federation::types::identity_type::ACCORD_HOLDER,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-aa",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();
        let att = pg_scores_attestation(&holder, &agent_k, &holder, "accord:human_dignity:v1");
        backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap();
        let rows = backend.list_attestations_for(&agent_k).await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_rejects_morally_charged_dimension() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let steward = format!("pg-bad-stw-§102-{}", uuid_like());
        let agent_k = format!("pg-bad-agt-§102-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-bad",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();
        let att = pg_scores_attestation(&steward, &agent_k, &steward, "emergent_deception:v1");
        let err = backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::DimensionRejected { reason, .. } => {
                assert_eq!(reason, "morally_charged_stem");
            }
            other => panic!("expected DimensionRejected, got {other:?}"),
        }
    }

    /// v3.9.1 (CIRISPersist#150 Ask 3) — the cohort_scope admission
    /// gate rejects an out-of-closed-set value (`global`) with the
    /// typed `CohortScopeRejected`, leaving no row behind.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_rejects_invalid_cohort_scope() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let steward = format!("pg-cs-bad-stw-§150-{}", uuid_like());
        let agent_k = format!("pg-cs-bad-agt-§150-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-cs-bad",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();
        let mut att = pg_scores_attestation(&steward, &agent_k, &steward, "identity_binding:v1");
        att.cohort_scope = "global".to_string();
        let err = backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::CohortScopeRejected { ref cohort_scope } => {
                assert_eq!(cohort_scope, "global");
                assert_eq!(err.kind(), "federation_cohort_scope_rejected");
            }
            other => panic!("expected CohortScopeRejected, got {other:?}"),
        }
        // Rejected before INSERT — no row leaked through.
        assert!(backend
            .list_attestations_for(&agent_k)
            .await
            .unwrap()
            .is_empty());
    }

    /// v3.9.1 (CIRISPersist#150 Ask 3) — a valid narrow cohort_scope
    /// (`self`) is admitted and round-trips through the read path.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_accepts_self_cohort_scope() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let steward = format!("pg-cs-self-stw-§150-{}", uuid_like());
        let agent_k = format!("pg-cs-self-agt-§150-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-cs-self",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();
        let mut att = pg_scores_attestation(&steward, &agent_k, &steward, "identity_binding:v1");
        att.cohort_scope = crate::federation::types::cohort_scope::SELF.to_string();
        backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap();
        let rows = backend.list_attestations_for(&agent_k).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].cohort_scope, "self");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_rejects_versionless_dimension() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let steward = format!("pg-vless-stw-§102-{}", uuid_like());
        let agent_k = format!("pg-vless-agt-§102-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-vless",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();
        let att = pg_scores_attestation(&steward, &agent_k, &steward, "rights_asymmetry");
        let err = backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
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
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_accepts_correlated_action_v1() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let steward = format!("pg-good-stw-§102-{}", uuid_like());
        let agent_k = format!("pg-good-agt-§102-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-good",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();
        let att = pg_scores_attestation(
            &steward,
            &agent_k,
            &steward,
            "detection:correlated_action:rights_asymmetry:v1",
        );
        backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap();
        let rows = backend.list_attestations_for(&agent_k).await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_exempts_structural_rename_chain() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let steward = format!("pg-ren-stw-§102-{}", uuid_like());
        let agent_k = format!("pg-ren-agt-§102-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-ren",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();
        let mut att = pg_scores_attestation(
            &steward,
            &agent_k,
            &steward,
            "delegates_to:correlated_action_v2:from:emergent_deception_v1",
        );
        att.attestation_type = crate::federation::types::attestation_type::DELEGATES_TO.into();
        backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap();
        let rows = backend.list_attestations_for(&agent_k).await.unwrap();
        assert_eq!(rows.len(), 1);
    }

    // ─── v3.0.0 (CIRISPersist#116, CEG 0.2 §6.1) — structural-composer ──
    //     dedup + precedence (postgres backend).

    fn pg_structural_composer(
        attester: &str,
        ty: &str,
        references_attestation_id: &str,
        asserted_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::federation::Attestation {
        crate::federation::Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: attester.into(),
            attested_key_id: attester.into(),
            attestation_type: ty.into(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "references_attestation_id": references_attestation_id,
                "withdrawal_reason": "test",
            }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.into(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_structural_dedup_silent_noop_on_replay() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let steward = format!("pg-dedup-stw-§116-{}", uuid_like());
        let upstream = uuid::Uuid::new_v4().to_string();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        let w1 = pg_structural_composer(
            &steward,
            crate::federation::types::attestation_type::WITHDRAWS,
            &upstream,
            chrono::Utc::now(),
        );
        let w1_id = w1.attestation_id.clone();
        let mut w2 = w1.clone();
        w2.attestation_id = uuid::Uuid::new_v4().to_string();
        w2.asserted_at += chrono::Duration::seconds(60);
        w2.scrub_timestamp = w2.asserted_at;
        backend
            .put_attestation(crate::federation::SignedAttestation { attestation: w1 })
            .await
            .unwrap();
        backend
            .put_attestation(crate::federation::SignedAttestation { attestation: w2 })
            .await
            .unwrap();
        let rows = backend.list_attestations_by(&steward).await.unwrap();
        let withdraws_for_upstream: Vec<_> = rows
            .iter()
            .filter(|r| {
                r.attestation_type == crate::federation::types::attestation_type::WITHDRAWS
                    && crate::federation::precedence::references_attestation_id_from_envelope(
                        &r.attestation_envelope,
                    ) == Some(upstream.as_str())
            })
            .collect();
        assert_eq!(
            withdraws_for_upstream.len(),
            1,
            "duplicate triple should be silent no-op"
        );
        assert_eq!(withdraws_for_upstream[0].attestation_id, w1_id);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_precedence_recants_wins_over_withdraws() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::precedence::{
            is_structural_composer, precedence_winner, references_attestation_id_from_envelope,
        };
        use crate::federation::FederationDirectory;
        let steward = format!("pg-prec-stw-§116-{}", uuid_like());
        let upstream = uuid::Uuid::new_v4().to_string();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        let now = chrono::Utc::now();
        let recants = pg_structural_composer(
            &steward,
            crate::federation::types::attestation_type::RECANTS,
            &upstream,
            now,
        );
        let recants_id = recants.attestation_id.clone();
        let withdraws_later = pg_structural_composer(
            &steward,
            crate::federation::types::attestation_type::WITHDRAWS,
            &upstream,
            now + chrono::Duration::hours(1),
        );
        backend
            .put_attestation(crate::federation::SignedAttestation {
                attestation: recants,
            })
            .await
            .unwrap();
        backend
            .put_attestation(crate::federation::SignedAttestation {
                attestation: withdraws_later,
            })
            .await
            .unwrap();
        let all = backend.list_attestations_by(&steward).await.unwrap();
        let group: Vec<_> = all
            .iter()
            .filter(|r| {
                is_structural_composer(&r.attestation_type)
                    && references_attestation_id_from_envelope(&r.attestation_envelope)
                        == Some(upstream.as_str())
            })
            .collect();
        let winner = precedence_winner(&group).expect("non-empty");
        // recants wins regardless of signed_at.
        assert_eq!(winner.attestation_id, recants_id);
        assert_eq!(
            winner.attestation_type,
            crate::federation::types::attestation_type::RECANTS
        );
    }

    // ─── v3.0.0 (CIRISPersist#116, CEG 0.2 §7.0) — reserved-prefix ──

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_rejects_system_prefix_from_agent() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let steward = format!("pg-rp-stw-§116-{}", uuid_like());
        let agent_k = format!("pg-rp-agt-§116-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-rp",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();
        let att = pg_scores_attestation(
            &steward,
            &agent_k,
            &steward,
            "system:health:n_eff_measurable:v1",
        );
        let err = backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
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
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_accepts_system_prefix_from_substrate_persist() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let persist_self = format!("pg-self-§116-{}", uuid_like());
        let agent_k = format!("pg-rp-ok-agt-§116-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &persist_self,
                    "persist",
                    crate::federation::types::identity_type::SUBSTRATE_PERSIST,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-rp-ok",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();
        let att = pg_scores_attestation(
            &persist_self,
            &agent_k,
            &persist_self,
            "system:health:n_eff_measurable:v1",
        );
        backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_admits_deprecated_attestation_ladder_in_transition() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let steward = format!("pg-dep-stw-§116-{}", uuid_like());
        let agent_k = format!("pg-dep-agt-§116-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-dep",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();
        // Deprecated 0.1 shape — admitted during transition without
        // `:v[0-9]+` segment.
        let att = pg_scores_attestation(&steward, &agent_k, &steward, "attestation:l1:self_verify");
        backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap();
        // Canonical 0.2 shape.
        let att = pg_scores_attestation(&steward, &agent_k, &steward, "attestation:self_verify");
        backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    // ─── v3.0.0 (CIRISPersist#116, CEG 0.2 §10.1.2) — holds_bytes ──
    //     24-hour TTL + ContentMiss feedback (postgres backend).

    fn pg_blob_attestation_at(
        attesting_key_id: &str,
        scrub_key_id: &str,
        scrub_timestamp: chrono::DateTime<chrono::Utc>,
    ) -> crate::federation::PutBlobAttestation {
        crate::federation::PutBlobAttestation {
            attesting_key_id: attesting_key_id.into(),
            attestation_id: uuid::Uuid::new_v4().to_string(),
            original_content_hash_hex: "deadbeef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: scrub_key_id.into(),
            scrub_timestamp,
        }
    }

    // ── v3.5.2 (CIRISPersist#130) — list_local_holders PG parity ─

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_blob_list_local_holders_includes_stale_local_holding() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobStorage};
        let host = format!("pg-blob-localtruth-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        let bytes = pg_blob_payload("local-truth-stale");
        let sha = pg_sha256_of(&bytes);
        let backdated = chrono::Utc::now()
            - chrono::Duration::from_std(crate::federation::blobs::DEFAULT_HOLDS_BYTES_TTL)
                .unwrap()
            - chrono::Duration::hours(1);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                pg_blob_attestation_at(&host, &host, backdated),
            )
            .await
            .unwrap();
        // v3.6.4 (#130 reopen): BOTH methods report the holder when
        // the blob is locally held — TTL bypass on local-truth applies
        // to list_holders as well as list_local_holders.
        let federation_holders = backend.list_holders(&sha).await.unwrap();
        assert_eq!(federation_holders, vec![host.clone()]);
        let local_holders = backend.list_local_holders(&sha).await.unwrap();
        assert_eq!(local_holders, vec![host]);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_blob_list_local_holders_returns_empty_when_blob_absent() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::BlobStorage;
        let sha = pg_sha256_of(b"not-locally-held-pg");
        let holders = backend.list_local_holders(&sha).await.unwrap();
        assert!(holders.is_empty());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_blob_list_holders_locally_held_bypasses_ttl() {
        // v3.6.4 (CIRISPersist#130 reopen) — PG mirror of the SQLite
        // local-truth bypass test. See sqlite test for full rationale.
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobStorage};
        let host = format!("pg-blob-ttl-§116-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        let bytes = pg_blob_payload("ttl-expired");
        let sha = pg_sha256_of(&bytes);
        let backdated = chrono::Utc::now()
            - chrono::Duration::from_std(crate::federation::blobs::DEFAULT_HOLDS_BYTES_TTL)
                .unwrap()
            - chrono::Duration::hours(1);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                pg_blob_attestation_at(&host, &host, backdated),
            )
            .await
            .unwrap();
        let holders = backend.list_holders(&sha).await.unwrap();
        assert_eq!(
            holders,
            vec![host.clone()],
            "locally-held blob reports holder regardless of attestation age, got {holders:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_blob_list_holders_includes_fresh_ttl() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobStorage};
        let host = format!("pg-blob-fresh-§116-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        let bytes = pg_blob_payload("ttl-fresh");
        let sha = pg_sha256_of(&bytes);
        let fresh = chrono::Utc::now() - chrono::Duration::hours(1);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                pg_blob_attestation_at(&host, &host, fresh),
            )
            .await
            .unwrap();
        let holders = backend.list_holders(&sha).await.unwrap();
        assert_eq!(holders, vec![host]);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_blob_list_holders_drops_withdrawn_via_content_miss() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::{BlobBody, BlobStorage, FederationDirectory};
        let host = format!("pg-blob-miss-§116-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        let bytes = pg_blob_payload("content-miss");
        let sha = pg_sha256_of(&bytes);
        let holds_bytes_attestation = pg_blob_attestation_at(
            &host,
            &host,
            chrono::Utc::now() - chrono::Duration::hours(1),
        );
        let holds_bytes_attestation_id = holds_bytes_attestation.attestation_id.clone();
        backend
            .put_blob(&sha, BlobBody::Inline(bytes), None, holds_bytes_attestation)
            .await
            .unwrap();
        // Present before withdraws.
        assert_eq!(
            backend.list_holders(&sha).await.unwrap(),
            vec![host.clone()]
        );

        // host emits the WITHDRAWS referencing the holds_bytes row.
        let withdraws = pg_structural_composer(
            &host,
            crate::federation::types::attestation_type::WITHDRAWS,
            &holds_bytes_attestation_id,
            chrono::Utc::now(),
        );
        backend
            .put_attestation(crate::federation::SignedAttestation {
                attestation: withdraws,
            })
            .await
            .unwrap();
        let holders = backend.list_holders(&sha).await.unwrap();
        assert!(
            holders.is_empty(),
            "expected withdrawn holder filtered, got {holders:?}"
        );
    }

    // ─── v2.5.0 (CIRISPersist#102 Ask 4) — schema-resolver tests ────

    fn pg_accord_holder_key_with_evidence(
        key_id: &str,
        evidence: Option<serde_json::Value>,
    ) -> crate::federation::KeyRecord {
        let mut k = pg_admission_key(
            key_id,
            "humanity-accord-x",
            crate::federation::types::identity_type::ACCORD_HOLDER,
        );
        k.attestation_evidence = evidence;
        k
    }

    fn pg_android_strongbox_evidence(
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
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_with_schema_accepts_valid_envelope() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = std::sync::Arc::new(PostgresBackend::connect(&dsn).await.unwrap());
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let steward = format!("pg-sch-stw-§102-{}", uuid_like());
        let agent_k = format!("pg-sch-agt-§102-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-sch",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();

        // Schema requires score+confidence+evidence_refs.
        let schema = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["dimension", "score", "confidence", "evidence_refs"],
        });
        let schema_bytes = serde_json::to_vec(&schema).unwrap();
        let schema_sha: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&schema_bytes).into()
        };
        use crate::federation::BlobStorage;
        let put_att = crate::federation::PutBlobAttestation {
            attesting_key_id: steward.clone(),
            attestation_id: uuid::Uuid::new_v4().to_string(),
            original_content_hash_hex: hex::encode([0xab; 32]),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: steward.clone(),
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
        axis_index.insert("rights_asymmetry".into(), schema_sha);
        let resolver = std::sync::Arc::new(crate::federation::BlobBackedSchemaResolver::new(
            axis_index,
            backend.clone(),
        ));
        backend.set_schema_resolver(resolver);

        let mut att = pg_scores_attestation(
            &steward,
            &agent_k,
            &steward,
            "detection:correlated_action:rights_asymmetry:v1",
        );
        att.attestation_envelope = serde_json::json!({
            "dimension": "detection:correlated_action:rights_asymmetry:v1",
            "score": 0.42,
            "confidence": 0.9,
            "evidence_refs": [hex::encode(schema_sha)],
        });
        backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_attestation_rejects_envelope_missing_required_field() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = std::sync::Arc::new(PostgresBackend::connect(&dsn).await.unwrap());
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let steward = format!("pg-bsch-stw-§102-{}", uuid_like());
        let agent_k = format!("pg-bsch-agt-§102-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    "registry",
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &agent_k,
                    "primitive-bsch",
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();

        let schema = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["dimension", "score", "confidence", "evidence_refs"],
        });
        let schema_bytes = serde_json::to_vec(&schema).unwrap();
        let schema_sha: [u8; 32] = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&schema_bytes).into()
        };
        use crate::federation::BlobStorage;
        let put_att = crate::federation::PutBlobAttestation {
            attesting_key_id: steward.clone(),
            attestation_id: uuid::Uuid::new_v4().to_string(),
            original_content_hash_hex: hex::encode([0xab; 32]),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: steward.clone(),
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
        axis_index.insert("rights_asymmetry".into(), schema_sha);
        let resolver = std::sync::Arc::new(crate::federation::BlobBackedSchemaResolver::new(
            axis_index,
            backend.clone(),
        ));
        backend.set_schema_resolver(resolver);

        let mut att = pg_scores_attestation(
            &steward,
            &agent_k,
            &steward,
            "detection:correlated_action:rights_asymmetry:v1",
        );
        att.attestation_envelope = serde_json::json!({
            "dimension": "detection:correlated_action:rights_asymmetry:v1",
            "score": 0.42,
            "confidence": 0.9,
        });
        let err = backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap_err();
        match err {
            crate::federation::Error::EnvelopeSchemaViolation { axis, .. } => {
                assert_eq!(axis, "rights_asymmetry");
            }
            other => panic!("expected EnvelopeSchemaViolation, got {other:?}"),
        }
    }

    // ─── v2.5.0 (CIRISPersist#102 Ask 8) — hardware-attestation tests ─

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_public_key_rejects_accord_holder_without_evidence() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let key_id = format!("pg-ah-noev-§102-{}", uuid_like());
        let key = pg_accord_holder_key_with_evidence(&key_id, None);
        let err = backend
            .put_public_key(crate::federation::SignedKeyRecord { record: key })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::federation::Error::AccordHolderRequiresAttestationEvidence { .. }
        ));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_public_key_rejects_accord_holder_software_only() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let key_id = format!("pg-ah-sw-§102-{}", uuid_like());
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
        let key = pg_accord_holder_key_with_evidence(&key_id, Some(ev));
        let err = backend
            .put_public_key(crate::federation::SignedKeyRecord { record: key })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::federation::Error::HardwareTypeNotAccepted { .. }
        ));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_public_key_rejects_accord_holder_tpm_missing_pcr() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let key_id = format!("pg-ah-tpm-nopcr-§102-{}", uuid_like());
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
        let key = pg_accord_holder_key_with_evidence(&key_id, Some(ev));
        let err = backend
            .put_public_key(crate::federation::SignedKeyRecord { record: key })
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
    #[serial_test::serial(postgres)]
    async fn pg_put_public_key_rejects_accord_holder_stale_nonce() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let key_id = format!("pg-ah-stale-§102-{}", uuid_like());
        let captured = chrono::Utc::now() - chrono::Duration::hours(48);
        let ev = pg_android_strongbox_evidence(captured);
        let key = pg_accord_holder_key_with_evidence(&key_id, Some(ev));
        let err = backend
            .put_public_key(crate::federation::SignedKeyRecord { record: key })
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            crate::federation::Error::AttestationEvidenceStale { .. }
        ));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_public_key_accepts_accord_holder_android_strongbox() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let key_id = format!("pg-ah-ok-§102-{}", uuid_like());
        let ev = pg_android_strongbox_evidence(chrono::Utc::now());
        let key = pg_accord_holder_key_with_evidence(&key_id, Some(ev));
        backend
            .put_public_key(crate::federation::SignedKeyRecord { record: key })
            .await
            .unwrap();
        let read = crate::federation::FederationDirectory::lookup_public_key(&backend, &key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read.identity_type, "accord_holder");
        assert!(read.attestation_evidence.is_some());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_public_key_accepts_non_accord_holder_without_evidence() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;
        let key_id = format!("pg-non-ah-§102-{}", uuid_like());
        let key = pg_admission_key(
            &key_id,
            "registry",
            crate::federation::types::identity_type::STEWARD,
        );
        backend
            .put_public_key(crate::federation::SignedKeyRecord { record: key })
            .await
            .unwrap();
        let read = crate::federation::FederationDirectory::lookup_public_key(&backend, &key_id)
            .await
            .unwrap()
            .unwrap();
        assert!(read.attestation_evidence.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_check_constraint_catches_direct_sql_bypass() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let client = backend
            .pool()
            .get()
            .await
            .map_err(|e| e.to_string())
            .unwrap();
        let key_id = format!("pg-ah-direct-§102-{}", uuid_like());
        let err = client
            .execute(
                "INSERT INTO cirislens.federation_keys (\
                    key_id, pubkey_ed25519_base64, algorithm, identity_type, identity_ref, \
                    valid_from, registration_envelope, original_content_hash, \
                    scrub_signature_classical, scrub_key_id, scrub_timestamp, persist_row_hash) \
                 VALUES ($1, 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', 'hybrid', \
                    'accord_holder', 'x', NOW(), '{}', E'\\\\xaa', 's', $1, NOW(), 'h')",
                &[&key_id],
            )
            .await
            .unwrap_err();
        // CHECK violation surfaces as SQL error containing the
        // named constraint. tokio_postgres' Display impl trims the
        // body; consult the DbError source to inspect the constraint
        // name + sqlstate.
        let dbe = err.as_db_error();
        let constraint = dbe.and_then(|e| e.constraint()).unwrap_or("");
        let sqlstate = dbe.map(|e| e.code().code()).unwrap_or("");
        assert_eq!(
            constraint, "federation_keys_accord_holder_requires_attestation",
            "expected CHECK fire (sqlstate={sqlstate}), got err={err:?}"
        );
    }

    /// v2.6.0 (CIRISPersist#105) — class-based enumeration via
    /// `list_keys_by_identity_type` on Postgres. Two `steward` rows +
    /// one `primitive` row scoped under a unique identity_ref token
    /// (so concurrent CI runs don't see each other's fixtures), then
    /// filter by identity_ref to isolate. ORDER BY key_id stable
    /// lex sort holds across both class predicates. Composite index
    /// `idx_federation_keys_identity_type_identity_ref` from V004
    /// covers the WHERE predicate — no new migration required.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_list_keys_by_identity_type_round_trip() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;

        // Unique token to isolate this test's rows from any concurrent
        // fixture on the shared CI schema. `identity_type` is shared
        // global vocabulary, so we filter the assertion set by checking
        // each fixture row by `key_id`.
        let tok = uuid_like();
        let s_alpha = format!("§105-s-alpha-{tok}");
        let s_bravo = format!("§105-s-bravo-{tok}");
        let prim_1 = format!("§105-p-{tok}");
        // Insert in reverse lex order to confirm ORDER BY key_id sort.
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &s_bravo,
                    &s_bravo,
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &s_alpha,
                    &s_alpha,
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &prim_1,
                    &prim_1,
                    crate::federation::types::identity_type::PRIMITIVE,
                ),
            })
            .await
            .unwrap();

        // Filter to the test-scoped rows (the shared schema may carry
        // other steward rows from prior fixtures). Pick exact key_ids.
        let stewards = backend
            .list_keys_by_identity_type(crate::federation::types::identity_type::STEWARD)
            .await
            .unwrap();
        let mut ours: Vec<&str> = stewards
            .iter()
            .map(|k| k.key_id.as_str())
            .filter(|k| k == &s_alpha.as_str() || k == &s_bravo.as_str())
            .collect();
        // Already in ORDER BY key_id sort from the SQL; preserve as
        // returned to assert the lex order.
        assert_eq!(ours.len(), 2, "expected both fixture stewards");
        // Both are in s_*-tok namespace; alpha < bravo lex.
        assert!(ours[0] < ours[1], "ORDER BY key_id holds: {ours:?}");
        assert_eq!(ours.remove(0), s_alpha);
        assert_eq!(ours.remove(0), s_bravo);

        let prims = backend
            .list_keys_by_identity_type(crate::federation::types::identity_type::PRIMITIVE)
            .await
            .unwrap();
        let prim_hits: Vec<_> = prims.iter().filter(|k| k.key_id == prim_1).collect();
        assert_eq!(prim_hits.len(), 1);

        // Unknown identity_type returns empty Vec.
        let none = backend
            .list_keys_by_identity_type("nonexistent_identity_type_§105")
            .await
            .unwrap();
        assert!(none.is_empty());
    }

    /// v2.6.0 (CIRISPersist#108) — confirm `persist_row_hash` is
    /// surfaced on the Postgres federation read paths. The column
    /// has existed since V001+; this test asserts that the row-type
    /// field is populated (server-computed on insert) and stable
    /// across reads so CIRISVerify v3.2.0+ can bind it into
    /// `FederationProvenance::persist_row_hash`.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_persist_row_hash_surfaces_on_federation_reads() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        use crate::federation::FederationDirectory;

        let tok = uuid_like();
        let steward = format!("§108-stw-{tok}");
        let target = format!("§108-tgt-{tok}");
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &steward,
                    &steward,
                    crate::federation::types::identity_type::STEWARD,
                ),
            })
            .await
            .unwrap();
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: pg_admission_key(
                    &target,
                    &target,
                    crate::federation::types::identity_type::AGENT,
                ),
            })
            .await
            .unwrap();
        backend
            .put_attestation(crate::federation::SignedAttestation {
                attestation: pg_scores_attestation(
                    &steward,
                    &target,
                    &steward,
                    "identity_binding:v1",
                ),
            })
            .await
            .unwrap();
        // Revocation row — exercise the third row-type's row_hash
        // surface. `revocation_id` is ::uuid-cast per the project
        // test-fixtures memory: must be a real UUID.
        let rev_id = uuid::Uuid::new_v4().to_string();
        backend
            .put_revocation(crate::federation::SignedRevocation {
                revocation: crate::federation::Revocation {
                    revocation_id: rev_id.clone(),
                    revoked_key_id: target.clone(),
                    revoking_key_id: steward.clone(),
                    reason: Some("test".into()),
                    revoked_at: chrono::Utc::now(),
                    effective_at: chrono::Utc::now(),
                    revocation_envelope: serde_json::json!({"id": rev_id}),
                    original_content_hash: "abc123".into(),
                    scrub_signature_classical: "c2ln".into(),
                    scrub_signature_pqc: None,
                    scrub_key_id: steward.clone(),
                    scrub_timestamp: chrono::Utc::now(),
                    pqc_completed_at: None,
                    observed_region: crate::federation::verify_coord::region::US.into(),
                    persist_row_hash: String::new(),
                },
            })
            .await
            .unwrap();

        // Keys.
        let k1 = FederationDirectory::lookup_public_key(&backend, &target)
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(k1.persist_row_hash.len(), 64, "row hash is 64 hex chars");
        let k2 = FederationDirectory::lookup_public_key(&backend, &target)
            .await
            .unwrap()
            .expect("row exists");
        assert_eq!(k1.persist_row_hash, k2.persist_row_hash);

        // Attestations.
        let att1 = backend.list_attestations_for(&target).await.unwrap();
        assert_eq!(att1.len(), 1);
        assert_eq!(att1[0].persist_row_hash.len(), 64);
        let att2 = backend.list_attestations_for(&target).await.unwrap();
        assert_eq!(att1[0].persist_row_hash, att2[0].persist_row_hash);

        // Revocations.
        let rev1 = backend.revocations_for(&target).await.unwrap();
        assert_eq!(rev1.len(), 1);
        assert_eq!(rev1[0].persist_row_hash.len(), 64);
        let rev2 = backend.revocations_for(&target).await.unwrap();
        assert_eq!(rev1[0].persist_row_hash, rev2[0].persist_row_hash);
    }

    // ─── #104 topology aggregate-query tests (Postgres parity) ──────

    /// Build a topology-test attestation. Sibling of the SQLite
    /// `topo_attestation` helper — kept distinct so each backend
    /// owns its own fixture path (no cross-module test dep).
    #[allow(clippy::too_many_arguments)]
    fn pg_topo_attestation(
        attesting: &str,
        attested: &str,
        atype: &str,
        dimension: Option<&str>,
        scope: Option<&str>,
        evidence: &[&str],
        weight: Option<f64>,
        asserted_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::federation::Attestation {
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
        crate::federation::Attestation {
            // attestation_id is `::uuid`-cast on the PG write path —
            // needs a real UUID (project_test_fixtures_uuid_vs_uuid_like).
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

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn federation_directory_query_topology_direct_pg() {
        use crate::federation::types::attestation_type;
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let suffix = uuid_like();
        let granter = format!("topo-pg-granter-{suffix}");
        let grantee = format!("topo-pg-grantee-{suffix}");
        for (k, ident) in [(&granter, "agent-a"), (&grantee, "agent-b")] {
            backend
                .put_public_key(crate::federation::SignedKeyRecord {
                    record: fix_section_i_key(k, ident, chrono::Utc::now(), false),
                })
                .await
                .unwrap();
        }
        let when = chrono::Utc::now();
        backend
            .put_attestation(crate::federation::SignedAttestation {
                attestation: pg_topo_attestation(
                    &granter,
                    &grantee,
                    attestation_type::SCORES,
                    Some("identity_binding:v1"),
                    None,
                    &[],
                    Some(3.0),
                    when,
                ),
            })
            .await
            .unwrap();
        let topo = crate::federation::build_trust_topology(
            &backend,
            &crate::federation::FederationDirectoryFilter {
                granter_key: Some(granter.clone()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(topo.edges.len(), 1);
        assert_eq!(topo.edges[0].edge_type, crate::federation::EdgeType::Direct);
        assert_eq!(topo.edges[0].from_key, grantee);
        assert_eq!(topo.edges[0].to_key, granter);
        assert!((topo.edges[0].weight - 3.0).abs() < 1e-9);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn federation_directory_query_empty_pg() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let topo = crate::federation::build_trust_topology(
            &backend,
            &crate::federation::FederationDirectoryFilter {
                granter_key: Some(format!("missing-{}", uuid_like())),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(topo.edges.is_empty());
        assert!(topo.nodes.is_empty());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn delegates_to_graph_one_level_pg() {
        use crate::federation::types::attestation_type;
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let suffix = uuid_like();
        let root = format!("del-pg-root-{suffix}");
        let child = format!("del-pg-child-{suffix}");
        for (k, ident) in [(&root, "agent-a"), (&child, "agent-b")] {
            backend
                .put_public_key(crate::federation::SignedKeyRecord {
                    record: fix_section_i_key(k, ident, chrono::Utc::now(), false),
                })
                .await
                .unwrap();
        }
        let when = chrono::Utc::now();
        backend
            .put_attestation(crate::federation::SignedAttestation {
                attestation: pg_topo_attestation(
                    &root,
                    &child,
                    attestation_type::DELEGATES_TO,
                    None,
                    Some("manifest:bundle-pg"),
                    &["sha256:abcd1234"],
                    None,
                    when,
                ),
            })
            .await
            .unwrap();
        let graph = crate::federation::build_delegation_graph(&backend, &root, 4)
            .await
            .unwrap();
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].scope, "manifest:bundle-pg");
        assert_eq!(graph.edges[0].depth, 1);
        assert_eq!(graph.edges[0].evidence_refs, vec!["sha256:abcd1234"]);
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn delegates_to_graph_empty_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let suffix = uuid_like();
        let root = format!("solo-pg-{suffix}");
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(&root, "agent-a", chrono::Utc::now(), false),
            })
            .await
            .unwrap();
        let graph = crate::federation::build_delegation_graph(&backend, &root, 4)
            .await
            .unwrap();
        assert!(graph.edges.is_empty());
    }

    // ── v2.10.0 (CIRISPersist#114) — typed Goal primitive tests ────

    fn fixture_pg_goal(
        declared_by_key_id: &str,
        scope: crate::federation::GoalScope,
        dimension: crate::federation::M1Dimension,
        declared_at: chrono::DateTime<chrono::Utc>,
    ) -> crate::federation::Goal {
        crate::federation::Goal::new(
            uuid::Uuid::new_v4(),
            declared_by_key_id.into(),
            declared_at,
            format!("goal text for {declared_by_key_id}"),
            scope,
            crate::federation::MetaGoalAlignment::new(dimension, "pg rationale".into(), None),
        )
    }

    /// v2.10.0 (#114) — put + get_goal round-trip is byte-exact on PG.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn put_get_goal_round_trip_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let kid = format!("k-goal-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(&kid, "agent-goal", chrono::Utc::now(), false),
            })
            .await
            .unwrap();
        let when: chrono::DateTime<chrono::Utc> = "2026-05-28T12:00:00Z".parse().unwrap();
        let goal = fixture_pg_goal(
            &kid,
            crate::federation::GoalScope::SingleDeclarer,
            crate::federation::M1Dimension::Plurality,
            when,
        );
        backend.put_goal(goal.clone()).await.unwrap();
        let fetched = backend.get_goal(goal.goal_id).await.unwrap();
        assert_eq!(fetched, Some(goal));
    }

    /// v2.10.0 (#114) — list_goals filter combinations preserve
    /// stable lex order by (declared_at, goal_id) on PG.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_goals_filters_and_order_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let suffix = uuid_like();
        let k_a = format!("k-a-{suffix}");
        let k_b = format!("k-b-{suffix}");
        for (kid, ident) in [(&k_a, "agent-a"), (&k_b, "agent-b")] {
            backend
                .put_public_key(crate::federation::SignedKeyRecord {
                    record: fix_section_i_key(kid, ident, chrono::Utc::now(), false),
                })
                .await
                .unwrap();
        }
        let t0: chrono::DateTime<chrono::Utc> = "2026-05-28T12:00:00Z".parse().unwrap();
        let t1: chrono::DateTime<chrono::Utc> = "2026-05-28T13:00:00Z".parse().unwrap();
        let g_a_plurality = fixture_pg_goal(
            &k_a,
            crate::federation::GoalScope::SingleDeclarer,
            crate::federation::M1Dimension::Plurality,
            t0,
        );
        let cohort_name = format!("stewards-{suffix}");
        let g_a_justice = fixture_pg_goal(
            &k_a,
            crate::federation::GoalScope::Cohort {
                cohort_id: cohort_name.clone(),
            },
            crate::federation::M1Dimension::Justice,
            t1,
        );
        let g_b_plurality = fixture_pg_goal(
            &k_b,
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
        let by_key = backend
            .list_goals(crate::federation::GoalsFilter {
                declared_by_key_id: Some(k_a.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_key.len(), 2);
        assert!(by_key.iter().all(|g| g.declared_by_key_id == k_a));
        assert!(by_key[0].declared_at <= by_key[1].declared_at);
        let by_cohort = backend
            .list_goals(crate::federation::GoalsFilter {
                scope_kind: Some("cohort".into()),
                cohort_id: Some(cohort_name.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(by_cohort.len(), 1);
        assert_eq!(by_cohort[0].goal_id, g_a_justice.goal_id);
    }

    /// v2.10.0 (#114) — all 7 M1Dimension variants round-trip on PG.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn all_m1_dimension_variants_round_trip_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let kid = format!("k-all-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(&kid, "agent-all", chrono::Utc::now(), false),
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
            let g = fixture_pg_goal(
                &kid,
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

    /// v2.10.0 (#114) — Cohort scope round-trip + the
    /// goals_scope_cohort_discriminant CHECK constraint rejects a
    /// direct-SQL bypass.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn cohort_scope_round_trip_and_check_rejects_bypass_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let kid = format!("k-c-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(&kid, "agent-c", chrono::Utc::now(), false),
            })
            .await
            .unwrap();
        let when: chrono::DateTime<chrono::Utc> = "2026-05-28T12:00:00Z".parse().unwrap();
        let g = fixture_pg_goal(
            &kid,
            crate::federation::GoalScope::Cohort {
                cohort_id: format!("cohort-{}", uuid_like()),
            },
            crate::federation::M1Dimension::Plurality,
            when,
        );
        backend.put_goal(g.clone()).await.unwrap();
        let got = backend.get_goal(g.goal_id).await.unwrap().expect("present");
        assert!(matches!(
            got.scope,
            crate::federation::GoalScope::Cohort { .. }
        ));

        // Direct-SQL bypass attempt: scope_kind='cohort' with
        // scope_cohort_id NULL must hit the CHECK constraint.
        let client = backend.get_client().await.unwrap();
        let bypass_id = uuid::Uuid::new_v4();
        let when_pg = chrono::Utc::now();
        let res = client
            .execute(
                "INSERT INTO cirislens.goals (\
                    goal_id, declared_by_key_id, declared_at, goal_text, \
                    goal_text_canonical, scope_kind, scope_cohort_id, \
                    meta_dimension, meta_rationale, meta_deliberation, \
                    retired_at, persist_row_hash\
                 ) VALUES ($1, $2, $3, 'x', 'x', 'cohort', NULL, \
                          'plurality', 'r', NULL, NULL, 'h')",
                &[&bypass_id, &kid, &when_pg],
            )
            .await;
        assert!(
            res.is_err(),
            "schema CHECK must reject scope_kind='cohort' with NULL scope_cohort_id"
        );
    }

    /// v2.10.0 (#114) — retire_goal hides from default list;
    /// include_retired=true includes it; second retire is idempotent.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn retire_goal_hides_from_default_list_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let kid = format!("k-r-{}", uuid_like());
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_section_i_key(&kid, "agent-r", chrono::Utc::now(), false),
            })
            .await
            .unwrap();
        let when: chrono::DateTime<chrono::Utc> = "2026-05-28T12:00:00Z".parse().unwrap();
        let g = fixture_pg_goal(
            &kid,
            crate::federation::GoalScope::SingleDeclarer,
            crate::federation::M1Dimension::Wonder,
            when,
        );
        backend.put_goal(g.clone()).await.unwrap();
        let retired_at = when + chrono::Duration::hours(1);
        backend.retire_goal(g.goal_id, retired_at).await.unwrap();
        // Default list filtered by declarer should not include the
        // retired goal.
        let live = backend
            .list_goals(crate::federation::GoalsFilter {
                declared_by_key_id: Some(kid.clone()),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(live.iter().all(|x| x.goal_id != g.goal_id));
        // include_retired=true includes it.
        let all = backend
            .list_goals(crate::federation::GoalsFilter {
                declared_by_key_id: Some(kid.clone()),
                include_retired: true,
                ..Default::default()
            })
            .await
            .unwrap();
        let found = all.iter().find(|x| x.goal_id == g.goal_id).expect("found");
        let original_retired_at = found.retired_at.expect("retired");
        // Idempotent second retire.
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

    /// v2.10.0 (#114) — put_goal rejects with InvalidArgument when
    /// declared_by_key_id is not in federation_keys (FK enforcement).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn put_goal_rejects_unknown_declarer_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let when: chrono::DateTime<chrono::Utc> = "2026-05-28T12:00:00Z".parse().unwrap();
        let g = fixture_pg_goal(
            &format!("ghost-{}", uuid_like()),
            crate::federation::GoalScope::SingleDeclarer,
            crate::federation::M1Dimension::Coherence,
            when,
        );
        let err = backend.put_goal(g).await.expect_err("FK must reject");
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(_)),
            "got: {err:?}"
        );
    }

    /// v2.10.0 (#114) — retire_goal against unknown goal_id rejects
    /// with InvalidArgument (not a silent no-op).
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn retire_goal_unknown_id_rejects_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let when = chrono::Utc::now();
        let err = backend
            .retire_goal(uuid::Uuid::new_v4(), when)
            .await
            .expect_err("missing goal_id must reject");
        assert!(
            matches!(err, crate::federation::Error::InvalidArgument(_)),
            "got: {err:?}"
        );
    }

    // ── v3.1.0 (CIRISPersist#117) — peer-mutation surface ──────────

    async fn pg_peek_peer(
        backend: &PostgresBackend,
        key_id: &str,
    ) -> Option<(
        Option<String>,
        String,
        Option<String>,
        Option<serde_json::Value>,
        Option<String>,
        Option<chrono::DateTime<chrono::Utc>>,
    )> {
        let client = backend.get_client().await.ok()?;
        let row = client
            .query_opt(
                "SELECT alias, trust, notes, policy_blob, transport_identity, removed_at \
                 FROM cirislens.federation_peer_metadata WHERE key_id = $1",
                &[&key_id],
            )
            .await
            .ok()??;
        Some((
            row.safe_get_with("alias", crate::federation::Error::Backend)
                .ok()?,
            row.safe_get_with("trust", crate::federation::Error::Backend)
                .ok()?,
            row.safe_get_with("notes", crate::federation::Error::Backend)
                .ok()?,
            row.safe_get_with("policy_blob", crate::federation::Error::Backend)
                .ok()?,
            row.safe_get_with("transport_identity", crate::federation::Error::Backend)
                .ok()?,
            row.safe_get_with("removed_at", crate::federation::Error::Backend)
                .ok()?,
        ))
    }

    async fn pg_peek_key_exists(backend: &PostgresBackend, key_id: &str) -> bool {
        let client = backend.get_client().await.unwrap();
        client
            .query_opt(
                "SELECT 1 FROM cirislens.federation_keys WHERE key_id = $1",
                &[&key_id],
            )
            .await
            .unwrap()
            .is_some()
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn add_peer_record_creates_both_rows_atomically_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("peer-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", Some("rns://abc".into()))
            .await
            .unwrap();
        assert!(pg_peek_key_exists(&backend, &key_id).await);
        let meta = pg_peek_peer(&backend, &key_id).await.expect("row");
        assert_eq!(meta.1, "untrusted");
        assert_eq!(meta.4.as_deref(), Some("rns://abc"));
        assert!(meta.5.is_none());
    }

    /// v3.9.3 (CIRISPersist#151) — bulk peer-level cohort_scope filter
    /// on list_federation_keys. Parity with the sqlite test; uses a
    /// per-run unique cohort label so the shared PG DB's leftover peers
    /// can't bleed into the assertions.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_federation_keys_filters_by_cohort_scope_pg() {
        use crate::federation::FederationDirectory;
        use crate::read::{FederationKeyFilter, ReadEngine};
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let cohort = format!("family-{}", uuid_like());
        let other_cohort = format!("community-{}", uuid_like());
        let fam_a = format!("peer-fam-a-{}", uuid_like());
        let fam_b = format!("peer-fam-b-{}", uuid_like());
        let other = format!("peer-other-{}", uuid_like());
        for id in [&fam_a, &fam_b] {
            backend
                .add_peer_record(id, "AAAA", "agent", None)
                .await
                .unwrap();
            backend
                .update_peer_policy(
                    id,
                    crate::federation::PeerPolicyBlob(serde_json::json!({"cohort_scope": cohort})),
                )
                .await
                .unwrap();
        }
        backend
            .add_peer_record(&other, "BBBB", "agent", None)
            .await
            .unwrap();
        backend
            .update_peer_policy(
                &other,
                crate::federation::PeerPolicyBlob(
                    serde_json::json!({"cohort_scope": other_cohort}),
                ),
            )
            .await
            .unwrap();

        let mk = |scope: &str| FederationKeyFilter {
            cohort_scope: Some(scope.to_string()),
            ..Default::default()
        };

        // Empty match (a cohort nobody is in).
        let none = backend
            .list_federation_keys(mk(&format!("nope-{}", uuid_like())), None, 100)
            .await
            .unwrap();
        assert!(none.items.is_empty());

        // Multi match: exactly the two peers in this run's cohort.
        let fam_all = backend
            .list_federation_keys(mk(&cohort), None, 100)
            .await
            .unwrap();
        let mut ids: Vec<&str> = fam_all.items.iter().map(|k| k.key_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, vec![fam_a.as_str(), fam_b.as_str()]);

        // Multi-page: limit=1 → page + cursor + distinct second page.
        let p1 = backend
            .list_federation_keys(mk(&cohort), None, 1)
            .await
            .unwrap();
        assert_eq!(p1.items.len(), 1);
        let cursor = p1.next_cursor.clone().expect("next_cursor");
        let p2 = backend
            .list_federation_keys(mk(&cohort), Some(cursor), 1)
            .await
            .unwrap();
        assert_eq!(p2.items.len(), 1);
        assert_ne!(p1.items[0].key_id, p2.items[0].key_id);

        // Soft-removed peers drop out.
        backend.remove_peer_record(&fam_b, false).await.unwrap();
        let fam_live = backend
            .list_federation_keys(mk(&cohort), None, 100)
            .await
            .unwrap();
        assert_eq!(
            fam_live
                .items
                .iter()
                .map(|k| k.key_id.as_str())
                .collect::<Vec<_>>(),
            vec![fam_a.as_str()],
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn add_peer_record_duplicate_key_id_rejects_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("peer-dup-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", None)
            .await
            .unwrap();
        let err = backend
            .add_peer_record(&key_id, "BBBB", "agent", None)
            .await
            .expect_err("must reject pubkey conflict");
        assert!(
            matches!(err, crate::federation::Error::Conflict(_)),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn remove_peer_record_soft_marks_removed_at_and_hides_from_reads_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("peer-soft-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", None)
            .await
            .unwrap();
        backend.remove_peer_record(&key_id, false).await.unwrap();
        let meta = pg_peek_peer(&backend, &key_id).await.expect("preserved");
        assert!(meta.5.is_some(), "removed_at set");
        assert!(pg_peek_key_exists(&backend, &key_id).await, "key preserved");
        let err = backend
            .update_peer_alias(&key_id, Some("nope".into()))
            .await
            .expect_err("must reject");
        assert!(matches!(err, crate::federation::Error::PeerNotFound { .. }));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn remove_peer_record_hard_with_active_attestations_rejects_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let a = format!("peer-att-a-{}", uuid_like());
        let b = format!("peer-att-b-{}", uuid_like());
        backend
            .add_peer_record(&a, "AAAA", "agent", None)
            .await
            .unwrap();
        backend
            .add_peer_record(&b, "BBBB", "agent", None)
            .await
            .unwrap();
        // Build attestation referencing key a as attesting. Use a
        // dimension that passes the v2.4.0 admission gate.
        let att = crate::federation::Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: a.clone(),
            attested_key_id: b.clone(),
            attestation_type: crate::federation::types::attestation_type::SCORES.into(),
            weight: Some(1.0),
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": "identity_binding:v1",
                "score": 1.0,
                "confidence": 0.9,
            }),
            original_content_hash: hex::encode([0u8; 32]),
            scrub_signature_classical: "sig".into(),
            scrub_signature_pqc: None,
            scrub_key_id: a.clone(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
        };
        backend
            .put_attestation(crate::federation::SignedAttestation { attestation: att })
            .await
            .unwrap();

        let err = backend
            .remove_peer_record(&a, true)
            .await
            .expect_err("must reject orphaning");
        assert!(matches!(
            err,
            crate::federation::Error::HardRemoveWithActiveAttestations { .. }
        ));
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn remove_peer_record_hard_with_no_attestations_cascades_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("peer-hard-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", None)
            .await
            .unwrap();
        backend.remove_peer_record(&key_id, true).await.unwrap();
        assert!(!pg_peek_key_exists(&backend, &key_id).await);
        assert!(pg_peek_peer(&backend, &key_id).await.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn update_peer_alias_round_trip_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("peer-alias-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", None)
            .await
            .unwrap();
        backend
            .update_peer_alias(&key_id, Some("home".into()))
            .await
            .unwrap();
        let meta = pg_peek_peer(&backend, &key_id).await.unwrap();
        assert_eq!(meta.0.as_deref(), Some("home"));
        backend.update_peer_alias(&key_id, None).await.unwrap();
        let meta = pg_peek_peer(&backend, &key_id).await.unwrap();
        assert!(meta.0.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn update_peer_trust_round_trip_each_variant_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("peer-trust-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", None)
            .await
            .unwrap();
        for variant in [
            crate::federation::TrustClass::Trusted,
            crate::federation::TrustClass::Restricted,
            crate::federation::TrustClass::Blocked,
            crate::federation::TrustClass::Untrusted,
        ] {
            backend.update_peer_trust(&key_id, variant).await.unwrap();
            let meta = pg_peek_peer(&backend, &key_id).await.unwrap();
            assert_eq!(meta.1, variant.as_wire_str());
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn update_peer_notes_round_trip_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("peer-notes-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", None)
            .await
            .unwrap();
        let meta = pg_peek_peer(&backend, &key_id).await.unwrap();
        assert!(meta.2.is_none());
        backend
            .update_peer_notes(&key_id, Some("ops".into()))
            .await
            .unwrap();
        let meta = pg_peek_peer(&backend, &key_id).await.unwrap();
        assert_eq!(meta.2.as_deref(), Some("ops"));
        backend.update_peer_notes(&key_id, None).await.unwrap();
        let meta = pg_peek_peer(&backend, &key_id).await.unwrap();
        assert!(meta.2.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn update_peer_policy_round_trip_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("peer-policy-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", None)
            .await
            .unwrap();
        let blob = crate::federation::PeerPolicyBlob(serde_json::json!({
            "rate": 60, "tags": ["x", "y"],
        }));
        backend
            .update_peer_policy(&key_id, blob.clone())
            .await
            .unwrap();
        let meta = pg_peek_peer(&backend, &key_id).await.unwrap();
        assert_eq!(meta.3.expect("policy set"), blob.0);
    }

    // ── v3.4.1 (CIRISPersist#127) — peer_metadata_for read accessor ──

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn peer_metadata_for_returns_full_row_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("peer-read-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", Some("rns://abc".into()))
            .await
            .unwrap();
        let blob = crate::federation::PeerPolicyBlob(serde_json::json!({
            "cohort_scope": "federation",
        }));
        backend.update_peer_policy(&key_id, blob).await.unwrap();
        let meta = backend
            .peer_metadata_for(&key_id)
            .await
            .unwrap()
            .expect("active peer must surface");
        assert_eq!(meta.key_id, key_id);
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
    #[serial_test::serial(postgres)]
    async fn peer_metadata_for_returns_none_unknown_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let got = backend
            .peer_metadata_for(&format!("ghost-{}", uuid_like()))
            .await
            .unwrap();
        assert!(got.is_none());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn peer_metadata_for_returns_none_soft_removed_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("peer-gone-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", None)
            .await
            .unwrap();
        backend.remove_peer_record(&key_id, false).await.unwrap();
        let got = backend.peer_metadata_for(&key_id).await.unwrap();
        assert!(got.is_none(), "soft-removed peer must read as None");
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn update_peer_unknown_key_id_rejects_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let err = backend
            .update_peer_alias(&format!("ghost-{}", uuid_like()), None)
            .await
            .expect_err("must reject");
        assert!(matches!(err, crate::federation::Error::PeerNotFound { .. }));
    }

    // ── v3.1.1 (CIRISPersist#118) — put_edge_detection_event ──────

    fn ed_fixture_pg(
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
    #[serial_test::serial(postgres)]
    async fn put_edge_detection_event_idempotent_pg() {
        use crate::derived::DerivedSchema;
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("edge-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", None)
            .await
            .unwrap();
        let did = uuid::Uuid::new_v4();
        let ev = ed_fixture_pg(&did, &key_id);
        backend.put_edge_detection_event(ev.clone()).await.unwrap();
        backend.put_edge_detection_event(ev).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn put_edge_detection_event_conflict_on_differing_row_hash_pg() {
        use crate::derived::DerivedSchema;
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("edge-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", None)
            .await
            .unwrap();
        let did = uuid::Uuid::new_v4();
        let ev_a = ed_fixture_pg(&did, &key_id);
        let mut ev_b = ev_a.clone();
        ev_b.persist_row_hash = "row-hash-B-different".into();
        backend.put_edge_detection_event(ev_a).await.unwrap();
        let err = backend.put_edge_detection_event(ev_b).await.unwrap_err();
        assert!(
            matches!(err, crate::derived::Error::Conflict(_)),
            "expected Conflict; got: {err:?}"
        );
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn put_edge_detection_event_bad_uuid_rejects_pg() {
        use crate::derived::DerivedSchema;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let mut ev = ed_fixture_pg(&uuid::Uuid::new_v4(), "irrelevant");
        ev.detection_id = "not-a-uuid".into();
        let err = backend.put_edge_detection_event(ev).await.unwrap_err();
        assert!(
            matches!(err, crate::derived::Error::InvalidArgument(_)),
            "expected InvalidArgument; got: {err:?}"
        );
    }

    /// V051 CHECK constraint catches direct-SQL bypass — a value
    /// outside the closed-set vocabulary must fail at the DB layer.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn peer_metadata_trust_check_rejects_direct_sql_bypass_pg() {
        use crate::federation::FederationDirectory;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let key_id = format!("peer-check-{}", uuid_like());
        backend
            .add_peer_record(&key_id, "AAAA", "agent", None)
            .await
            .unwrap();
        let client = backend.get_client().await.unwrap();
        let res = client
            .execute(
                "UPDATE cirislens.federation_peer_metadata SET trust = 'mystery' WHERE key_id = $1",
                &[&key_id],
            )
            .await;
        assert!(
            res.is_err(),
            "direct-SQL bypass of trust CHECK must fail; got: {res:?}"
        );
    }

    // ── BlackholeRules tests (v3.2.0, CIRISPersist#120) ────────────
    //
    // Each test uses a deterministically-unique 16-byte identity_hash
    // built from `uuid_like()` so concurrent test runs (and re-runs
    // against the persisted test DB) don't collide on PK.

    fn pg_unique_id16(prefix: u8) -> Vec<u8> {
        let tag = uuid_like();
        let mut out = vec![prefix; 16];
        let tag_bytes = tag.as_bytes();
        let n = tag_bytes.len().min(15);
        out[1..=n].copy_from_slice(&tag_bytes[..n]);
        out
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blackhole_upsert_then_list_round_trip_pg() {
        use crate::federation::BlackholeRules;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = pg_unique_id16(0xA0);
        backend
            .blackhole_upsert(&id, None, Some("noisy"))
            .await
            .unwrap();
        let rows = backend.blackhole_list().await.unwrap();
        let found = rows
            .iter()
            .find(|r| r.identity_hash == id)
            .expect("row landed");
        assert!(found.until.is_none());
        assert_eq!(found.reason.as_deref(), Some("noisy"));
        assert_eq!(found.hits, 0);
        assert!(!found.persist_row_hash.is_empty());
        backend.blackhole_remove(&id).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blackhole_upsert_with_until_round_trip_pg() {
        use crate::federation::BlackholeRules;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = pg_unique_id16(0xA1);
        let future = chrono::Utc::now() + chrono::Duration::hours(1);
        backend
            .blackhole_upsert(&id, Some(future), Some("temp"))
            .await
            .unwrap();
        let rows = backend.blackhole_list().await.unwrap();
        let found = rows.iter().find(|r| r.identity_hash == id).unwrap();
        let stored = found.until.unwrap();
        assert!(
            (stored.timestamp_millis() - future.timestamp_millis()).abs() < 1000,
            "stored {stored:?} vs expected {future:?}"
        );
        backend.blackhole_remove(&id).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blackhole_upsert_idempotent_preserves_hits_pg() {
        use crate::federation::BlackholeRules;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = pg_unique_id16(0xA2);
        backend
            .blackhole_upsert(&id, None, Some("first"))
            .await
            .unwrap();
        for _ in 0..3 {
            backend.blackhole_record_hit(&id).await.unwrap();
        }
        let before = backend.blackhole_list().await.unwrap();
        let before_row = before.iter().find(|r| r.identity_hash == id).unwrap();
        assert_eq!(before_row.hits, 3);
        let added_at_before = before_row.added_at;

        backend
            .blackhole_upsert(&id, None, Some("second"))
            .await
            .unwrap();
        let after = backend.blackhole_list().await.unwrap();
        let after_row = after.iter().find(|r| r.identity_hash == id).unwrap();
        assert_eq!(after_row.hits, 3, "hits preserved across re-upsert");
        assert_eq!(after_row.reason.as_deref(), Some("second"));
        assert_eq!(
            after_row.added_at.timestamp_millis(),
            added_at_before.timestamp_millis(),
            "added_at preserved"
        );
        backend.blackhole_remove(&id).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blackhole_upsert_invalid_hash_length_rejects_pg() {
        use crate::federation::BlackholeRules;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
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
    #[serial_test::serial(postgres)]
    async fn blackhole_remove_unknown_silent_ok_pg() {
        use crate::federation::BlackholeRules;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        // Use a unique id that has NOT been upserted.
        let id = pg_unique_id16(0xA3);
        backend.blackhole_remove(&id).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blackhole_remove_idempotent_pg() {
        use crate::federation::BlackholeRules;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = pg_unique_id16(0xA4);
        backend.blackhole_upsert(&id, None, None).await.unwrap();
        backend.blackhole_remove(&id).await.unwrap();
        backend.blackhole_remove(&id).await.unwrap(); // 2nd call: silent ok
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blackhole_record_hit_increments_pg() {
        use crate::federation::BlackholeRules;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let id = pg_unique_id16(0xA5);
        backend.blackhole_upsert(&id, None, None).await.unwrap();
        for _ in 0..5 {
            backend.blackhole_record_hit(&id).await.unwrap();
        }
        let rows = backend.blackhole_list().await.unwrap();
        let found = rows.iter().find(|r| r.identity_hash == id).unwrap();
        assert_eq!(found.hits, 5);
        backend.blackhole_remove(&id).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blackhole_record_hit_unknown_silent_ok_pg() {
        use crate::federation::BlackholeRules;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        // Hit a hash that has no rule. Must be silent OK.
        backend
            .blackhole_record_hit(&pg_unique_id16(0xA6))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blackhole_prune_expired_drops_only_expired_pg() {
        use crate::federation::BlackholeRules;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let now = chrono::Utc::now();
        let expired = pg_unique_id16(0xA7);
        let permanent = pg_unique_id16(0xA8);
        backend
            .blackhole_upsert(&expired, Some(now - chrono::Duration::hours(1)), None)
            .await
            .unwrap();
        backend
            .blackhole_upsert(&permanent, None, None)
            .await
            .unwrap();
        let dropped = backend.blackhole_prune_expired(now).await.unwrap();
        assert!(
            dropped >= 1,
            "expected at least 1 drop (this test's expired); got {dropped}"
        );
        let rows = backend.blackhole_list().await.unwrap();
        assert!(
            rows.iter().any(|r| r.identity_hash == permanent),
            "permanent rule must remain"
        );
        assert!(
            rows.iter().all(|r| r.identity_hash != expired),
            "expired rule must be gone"
        );
        backend.blackhole_remove(&permanent).await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn blackhole_prune_expired_with_no_expired_returns_zero_pg() {
        use crate::federation::BlackholeRules;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        // Ensure baseline: no expired rules sneak in by pruning first.
        backend
            .blackhole_prune_expired(chrono::Utc::now())
            .await
            .unwrap();
        let now = chrono::Utc::now();
        let permanent = pg_unique_id16(0xA9);
        let future = pg_unique_id16(0xAB);
        backend
            .blackhole_upsert(&permanent, None, None)
            .await
            .unwrap();
        backend
            .blackhole_upsert(&future, Some(now + chrono::Duration::hours(1)), None)
            .await
            .unwrap();
        let dropped = backend.blackhole_prune_expired(now).await.unwrap();
        assert_eq!(dropped, 0, "no expired rules → zero drops");
        backend.blackhole_remove(&permanent).await.unwrap();
        backend.blackhole_remove(&future).await.unwrap();
    }

    // ─── v3.4.0 (CIRISPersist#123) — Postgres parity for #123 ──────

    struct PgFixedTrustScoring(std::collections::HashMap<String, f64>);

    #[async_trait::async_trait]
    impl crate::federation::TrustScoring for PgFixedTrustScoring {
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

    fn pg_gate(pairs: &[(&str, f64)], threshold: f64) -> crate::federation::AdmissionGate {
        let mut map = std::collections::HashMap::new();
        for (k, v) in pairs {
            map.insert((*k).to_owned(), *v);
        }
        crate::federation::AdmissionGate::new(
            std::sync::Arc::new(PgFixedTrustScoring(map)),
            threshold,
            0,
        )
    }

    /// V053 migration applied — access tracking columns exist.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn v053_pg_access_columns_present() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let client = backend.pool().get().await.unwrap();
        let row = client
            .query_one(
                "SELECT column_name FROM information_schema.columns \
                 WHERE table_schema = 'cirislens' AND table_name = 'federation_blobs' \
                   AND column_name = 'last_accessed_at'",
                &[],
            )
            .await
            .expect("last_accessed_at exists");
        let _: String = row
            .safe_get_with("column_name", crate::federation::Error::Backend)
            .expect("column_name present");
        let row = client
            .query_one(
                "SELECT column_name FROM information_schema.columns \
                 WHERE table_schema = 'cirislens' AND table_name = 'federation_blobs' \
                   AND column_name = 'access_count'",
                &[],
            )
            .await
            .expect("access_count exists");
        let _: String = row
            .safe_get_with("column_name", crate::federation::Error::Backend)
            .expect("column_name present");
    }

    /// PG put_blob honors admission gate + admission ordering.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_put_blob_trust_rejection_beats_inline_size() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        use crate::federation::{BlobBody, BlobError, BlobStorage};
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let host = format!("trust-gate-host-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        backend.set_admission_gate(Some(pg_gate(&[(&host, 0.1)], 0.5)));
        let huge = vec![0u8; crate::federation::DEFAULT_INLINE_BYTES_CAP + 1];
        let sha = pg_sha256_of(&huge);
        let err = backend
            .put_blob(
                &sha,
                BlobBody::Inline(huge),
                None,
                pg_blob_attestation(&host, &host),
            )
            .await
            .expect_err("trust beats size");
        // Clear gate so we don't poison subsequent tests on shared DB.
        backend.set_admission_gate(None);
        match err {
            BlobError::TrustBelowThreshold { key_id, .. } => assert_eq!(key_id, host),
            other => panic!("expected TrustBelowThreshold, got {other:?}"),
        }
    }

    /// PG get_blob bumps access tracking via UPDATE … RETURNING.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn pg_get_blob_bumps_access_count() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        use crate::federation::{BlobBody, BlobStorage};
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let host = format!("access-host-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        let bytes = pg_blob_payload("access");
        let sha = pg_sha256_of(&bytes);
        backend
            .put_blob(
                &sha,
                BlobBody::Inline(bytes),
                None,
                pg_blob_attestation(&host, &host),
            )
            .await
            .unwrap();
        let _ = backend.get_blob(&sha).await.unwrap();
        let _ = backend.get_blob(&sha).await.unwrap();
        // has_blob also bumps.
        assert!(backend.has_blob(&sha).await.unwrap());
        let client = backend.pool().get().await.unwrap();
        let row = client
            .query_one(
                "SELECT access_count FROM cirislens.federation_blobs WHERE sha256 = $1",
                &[&sha.to_vec()],
            )
            .await
            .unwrap();
        let count: i64 = row
            .safe_get_with("access_count", crate::federation::Error::Backend)
            .expect("access_count column present");
        assert_eq!(count, 3);
    }

    // ─── v3.4.0 (CIRISPersist#123) — PG sweeper parity ─────────────

    /// PG parity for `sweeper_idle_when_below_watermark_sqlite`.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn sweeper_idle_when_below_watermark_pg() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        use crate::federation::BlobBody;
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        // Seed key + a handful of small blobs.
        let host = format!("idle-host-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &host).await;
        let mut shas = Vec::new();
        for i in 0..3 {
            let bytes = vec![(i + 1) as u8; 256];
            let sha = pg_sha256_of(&bytes);
            use crate::federation::BlobStorage;
            backend
                .put_blob(
                    &sha,
                    BlobBody::Inline(bytes),
                    None,
                    pg_blob_attestation(&host, &host),
                )
                .await
                .unwrap();
            shas.push(sha);
        }
        // Compose an Engine view over this backend so we can drive
        // sweep_evictions_once with a high budget.
        use crate::signing::LocalSigner;
        use ed25519_dalek::SigningKey;
        let signer = std::sync::Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x9A; 32]),
            host.clone(),
            None,
            None,
        ));
        let cfg = crate::federation::ReplicationConfig {
            storage_budget_bytes: 100_000_000, // 100 MB — far above seeded.
            steady_state_utilization: 0.92,
            ..Default::default()
        };
        let engine = crate::Engine::with_replication_config(signer, &dsn, cfg)
            .await
            .unwrap();
        let report = engine.sweep_evictions_once().await.expect("sweep");
        assert_eq!(report.rows_evicted, 0);
        assert_eq!(report.withdraws_emitted, 0);
        // Cleanup: caller-managed (shared PG DB).
        for sha in &shas {
            let _ = backend.delete_blob(sha).await;
        }
    }

    /// PG parity for `sweeper_emits_withdraws_on_eviction_sqlite`.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn sweeper_emits_withdraws_on_eviction_pg() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        use crate::signing::LocalSigner;
        use ed25519_dalek::SigningKey;
        // Each run uses a freshly-seeded host_key_id so the
        // list_attestations_by query is scoped to this test only,
        // even on the shared PG database.
        let host = format!("evict-host-{}", uuid_like());
        let host_for_signer = host.clone();
        let signer = std::sync::Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x8B; 32]),
            host_for_signer,
            None,
            None,
        ));
        let cfg = crate::federation::ReplicationConfig {
            // Very tight budget so eviction is forced.
            storage_budget_bytes: 1024,
            steady_state_utilization: 0.5,
            eviction_decay_half_life_days: 365.0,
            ..Default::default()
        };
        let engine = crate::Engine::with_replication_config(signer.clone(), &dsn, cfg)
            .await
            .unwrap();
        // Seed the federation_keys row for the signer (FK target for
        // withdraws attestations).
        let pg = engine.postgres_backend().expect("pg").clone();
        pg_blob_bootstrap_host(&pg, &host).await;
        // Seed 5 × 1 KiB blobs via the Engine's put_blob_signing path
        // so each lands a holds_bytes attestation owned by the
        // signer.
        use crate::federation::BlobBody;
        let mut shas = Vec::new();
        for i in 0..5 {
            let bytes = vec![(i + 1) as u8; 1024];
            let sha = pg_sha256_of(&bytes);
            engine
                .put_blob_signing(
                    &sha,
                    BlobBody::Inline(bytes),
                    None,
                    &host,
                    chrono::Utc::now(),
                    uuid::Uuid::new_v4(),
                )
                .await
                .unwrap();
            shas.push(sha);
        }

        let report = engine.sweep_evictions_once().await.expect("sweep");
        assert!(report.rows_evicted > 0);
        // On a shared PG database the sweeper may evict blobs left
        // behind by other tests (they have no holds_bytes from THIS
        // signer); for those the withdraws emission is silently
        // skipped per architect's contract. So we assert the
        // emission count covers AT LEAST the blobs WE inserted
        // (whose prior holds_bytes IS owned by `host`).
        assert!(
            report.withdraws_emitted >= 1,
            "withdraws_emitted must be ≥1 since we seeded holds_bytes \
             attestations under this host"
        );
        assert!(
            report.withdraws_emitted <= report.rows_evicted,
            "withdraws_emitted ≤ rows_evicted invariant"
        );

        // Confirm at least one withdraws row exists in PG
        // federation_attestations for this signer.
        let directory = engine.federation_directory();
        let atts = directory.list_attestations_by(&host).await.unwrap();
        let withdraws_count = atts
            .iter()
            .filter(|a| a.attestation_type == crate::federation::types::attestation_type::WITHDRAWS)
            .count();
        assert!(
            withdraws_count >= report.withdraws_emitted as usize,
            "PG must have ≥{} withdraws rows for this signer; got {}",
            report.withdraws_emitted,
            withdraws_count
        );

        // Cleanup: drop any surviving blobs so concurrent tests
        // aren't impacted by per-budget bytes-budget accumulation
        // across runs (shared PG DB).
        for sha in &shas {
            let _ = pg.delete_blob(sha).await;
        }
    }

    /// PG parity for `sweeper_evicts_lowest_score_first_sqlite`.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn sweeper_evicts_lowest_score_first_pg() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        use crate::federation::{BlobBody, BlobStorage};
        use crate::signing::LocalSigner;
        use ed25519_dalek::SigningKey;
        let host = format!("score-host-{}", uuid_like());
        let signer = std::sync::Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x7C; 32]),
            host.clone(),
            None,
            None,
        ));
        let cfg = crate::federation::ReplicationConfig {
            storage_budget_bytes: 4 * 1024,
            steady_state_utilization: 0.9,
            eviction_decay_half_life_days: 365.0,
            ..Default::default()
        };
        let engine = crate::Engine::with_replication_config(signer, &dsn, cfg)
            .await
            .unwrap();
        let pg = engine.postgres_backend().expect("pg").clone();
        pg_blob_bootstrap_host(&pg, &host).await;
        let mut shas = Vec::new();
        for i in 0..5 {
            let bytes = vec![(i + 10) as u8; 1024];
            let sha = pg_sha256_of(&bytes);
            engine
                .put_blob_signing(
                    &sha,
                    BlobBody::Inline(bytes),
                    None,
                    &host,
                    chrono::Utc::now(),
                    uuid::Uuid::new_v4(),
                )
                .await
                .unwrap();
            shas.push(sha);
        }
        // Bump access_count on the OLDEST three so they outrank.
        for sha in &shas[..3] {
            for _ in 0..3 {
                let _ = pg.get_blob(sha).await.unwrap();
            }
        }
        let report = engine.sweep_evictions_once().await.expect("sweep");
        assert!(report.rows_evicted > 0);
        // Hot blobs must survive.
        for sha in &shas[..3] {
            assert!(
                pg.has_blob(sha).await.unwrap(),
                "PG: hot blob must survive eviction"
            );
        }
        // Cleanup.
        for sha in &shas {
            let _ = pg.delete_blob(sha).await;
        }
    }

    /// PG parity for `list_holders_filters_evicted_rows_sqlite`.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_holders_filters_evicted_rows_pg() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        use crate::federation::{BlobBody, BlobStorage};
        use crate::signing::LocalSigner;
        use ed25519_dalek::SigningKey;
        let host = format!("list-holders-host-{}", uuid_like());
        let signer = std::sync::Arc::new(LocalSigner::from_parts(
            SigningKey::from_bytes(&[0x6D; 32]),
            host.clone(),
            None,
            None,
        ));
        let cfg = crate::federation::ReplicationConfig {
            storage_budget_bytes: 1024,
            steady_state_utilization: 0.5,
            eviction_decay_half_life_days: 365.0,
            ..Default::default()
        };
        let engine = crate::Engine::with_replication_config(signer, &dsn, cfg)
            .await
            .unwrap();
        let pg = engine.postgres_backend().expect("pg").clone();
        pg_blob_bootstrap_host(&pg, &host).await;
        let mut shas = Vec::new();
        for i in 0..3 {
            let bytes = vec![(i + 20) as u8; 1024];
            let sha = pg_sha256_of(&bytes);
            engine
                .put_blob_signing(
                    &sha,
                    BlobBody::Inline(bytes),
                    None,
                    &host,
                    chrono::Utc::now(),
                    uuid::Uuid::new_v4(),
                )
                .await
                .unwrap();
            shas.push(sha);
        }
        // Before sweep: each blob has this signer as holder.
        for sha in &shas {
            let holders = pg.list_holders(sha).await.unwrap();
            assert!(holders.contains(&host));
        }
        let report = engine.sweep_evictions_once().await.expect("sweep");
        assert!(report.rows_evicted > 0);
        // Count how many of OUR test's blobs got evicted (others may
        // have been swept up from concurrent-test pollution on the
        // shared PG DB — those have no prior holds_bytes from our
        // signer so their withdraws emission is silently skipped per
        // architect's contract).
        let mut my_evicted_count = 0usize;
        for sha in &shas {
            if !pg.has_blob(sha).await.unwrap() {
                my_evicted_count += 1;
            }
        }
        assert!(
            my_evicted_count >= 1,
            "at least one of our blobs must have been evicted"
        );
        // For each of OUR evicted blobs, the host is no longer a
        // listed holder (because the withdraws covers it).
        for sha in &shas {
            if pg.has_blob(sha).await.unwrap() {
                continue;
            }
            let holders = pg.list_holders(sha).await.unwrap();
            assert!(
                !holders.contains(&host),
                "evicted blob must have host removed from holders"
            );
        }
        for sha in &shas {
            let _ = pg.delete_blob(sha).await;
        }
    }

    // ─── v3.5.0 (CIRISPersist#125) — list_held_by + evict_actor ────

    /// A signer whose `sign` always errors — exercises the
    /// `evict_actor` `withdraws_failed` path. All other methods
    /// delegate to a real adapter so PG schema FKs stay satisfied
    /// (`current_alias` in particular).
    struct PgAlwaysFailingSigner {
        inner: std::sync::Arc<crate::signing::LocalSignerHardwareAdapter>,
    }

    #[async_trait::async_trait]
    impl ciris_keyring::HardwareSigner for PgAlwaysFailingSigner {
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
                reason: "pg test signer always fails".into(),
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

    fn pg_test_signer_for(
        alias: &str,
    ) -> std::sync::Arc<crate::signing::LocalSignerHardwareAdapter> {
        use crate::signing::{LocalSigner, LocalSignerHardwareAdapter};
        use ed25519_dalek::SigningKey;
        // Deterministic per-alias seed so signers across tests don't
        // collide on a shared DB.
        let mut seed = [0u8; 32];
        for (i, b) in alias.as_bytes().iter().enumerate() {
            seed[i % 32] ^= *b;
        }
        let signing_key = SigningKey::from_bytes(&seed);
        let local = std::sync::Arc::new(LocalSigner::from_parts(
            signing_key,
            alias.to_owned(),
            None,
            None,
        ));
        std::sync::Arc::new(LocalSignerHardwareAdapter::new(local))
    }

    /// Seed `n` blobs from `actor` via the trait `put_blob_signing`
    /// path; each payload is uniquified with `uuid_like()` so PG SHAs
    /// don't collide across concurrent tests on the shared DB.
    async fn pg_seed_blobs_for_actor(
        backend: &PostgresBackend,
        actor: &str,
        signer: &dyn ciris_keyring::HardwareSigner,
        n: usize,
        tag: &str,
    ) -> Vec<[u8; 32]> {
        use crate::federation::{BlobBody, BlobStorage};
        let mut shas = Vec::with_capacity(n);
        for i in 0..n {
            let bytes = format!("{actor}-{tag}-{i}-{}", uuid_like()).into_bytes();
            let sha = pg_sha256_of(&bytes);
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
    #[serial_test::serial(postgres)]
    async fn list_held_by_returns_actor_shas_pg() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let actor_a = format!("evict-A-{}", uuid_like());
        let actor_b = format!("evict-B-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &actor_a).await;
        pg_blob_bootstrap_host(&backend, &actor_b).await;
        let signer_a = pg_test_signer_for(&actor_a);
        let signer_b = pg_test_signer_for(&actor_b);
        let shas_a = pg_seed_blobs_for_actor(&backend, &actor_a, &*signer_a, 3, "main").await;
        let shas_b = pg_seed_blobs_for_actor(&backend, &actor_b, &*signer_b, 2, "main").await;

        use crate::federation::BlobStorage;
        let mut held_a = backend.list_held_by(&actor_a).await.unwrap();
        held_a.sort();
        let mut expected_a = shas_a.clone();
        expected_a.sort();
        assert_eq!(held_a, expected_a, "A's holdings");

        let mut held_b = backend.list_held_by(&actor_b).await.unwrap();
        held_b.sort();
        let mut expected_b = shas_b.clone();
        expected_b.sort();
        assert_eq!(held_b, expected_b, "B's holdings");

        // Cleanup.
        for sha in shas_a.iter().chain(shas_b.iter()) {
            let _ = backend.delete_blob(sha).await;
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn list_held_by_filters_withdrawn_pg() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let actor = format!("evict-W-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &actor).await;
        let signer = pg_test_signer_for(&actor);
        let shas = pg_seed_blobs_for_actor(&backend, &actor, &*signer, 1, "withdrawn").await;

        use crate::federation::FederationDirectory;
        let atts = backend.list_attestations_by(&actor).await.unwrap();
        let holds_bytes = atts
            .into_iter()
            .find(|a| {
                a.attestation_type
                    .starts_with(crate::federation::HOLDS_BYTES_ATTESTATION_TYPE_PREFIX)
            })
            .expect("holds_bytes from actor");
        let withdraws = crate::federation::Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: actor.clone(),
            attested_key_id: actor.clone(),
            attestation_type: crate::federation::types::attestation_type::WITHDRAWS.to_owned(),
            weight: None,
            asserted_at: chrono::Utc::now(),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "kind": "withdraws",
                "references_attestation_id": holds_bytes.attestation_id,
                "references_attestation_type": holds_bytes.attestation_type,
            }),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: actor.clone(),
            scrub_timestamp: chrono::Utc::now(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
        };
        backend
            .put_attestation(crate::federation::SignedAttestation {
                attestation: withdraws,
            })
            .await
            .unwrap();

        use crate::federation::BlobStorage;
        let held = backend.list_held_by(&actor).await.unwrap();
        assert!(
            !held.contains(&shas[0]),
            "withdrawn blob must be excluded, got {held:?}"
        );

        for sha in &shas {
            let _ = backend.delete_blob(sha).await;
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn evict_actor_evicts_blobs_and_emits_withdraws_pg() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let actor_a = format!("evict-go-A-{}", uuid_like());
        let actor_b = format!("evict-go-B-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &actor_a).await;
        pg_blob_bootstrap_host(&backend, &actor_b).await;
        let signer_a = pg_test_signer_for(&actor_a);
        let signer_b = pg_test_signer_for(&actor_b);
        let shas_a = pg_seed_blobs_for_actor(&backend, &actor_a, &*signer_a, 3, "evict").await;
        let shas_b = pg_seed_blobs_for_actor(&backend, &actor_b, &*signer_b, 2, "evict").await;

        use crate::federation::BlobStorage;
        let report = backend
            .evict_actor(&actor_a, &*signer_a, chrono::Utc::now())
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

        for sha in &shas_b {
            let _ = backend.delete_blob(sha).await;
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn evict_actor_no_holdings_returns_zero_report_pg() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let actor = format!("evict-empty-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &actor).await;
        let signer = pg_test_signer_for(&actor);

        use crate::federation::BlobStorage;
        let report = backend
            .evict_actor(&actor, &*signer, chrono::Utc::now())
            .await
            .unwrap();
        assert_eq!(report, crate::federation::EvictActorReport::default());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn evict_actor_returns_correct_report_under_partial_failure_pg() {
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let actor = format!("evict-partial-{}", uuid_like());
        pg_blob_bootstrap_host(&backend, &actor).await;
        let real_signer = pg_test_signer_for(&actor);
        let shas = pg_seed_blobs_for_actor(&backend, &actor, &*real_signer, 1, "partial").await;

        let failing = PgAlwaysFailingSigner {
            inner: real_signer.clone(),
        };
        use crate::federation::BlobStorage;
        let report = backend
            .evict_actor(&actor, &failing, chrono::Utc::now())
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

    // ── v3.6.0 (CIRISPersist#134, CEG 0.3 §11.5.3) — trusted-publisher chain ──

    fn fix_trusted_publisher_key(
        key_id: &str,
        identity_type: &str,
    ) -> crate::federation::KeyRecord {
        crate::federation::KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
            pubkey_ml_dsa_65_base64: None,
            algorithm: crate::federation::types::algorithm::HYBRID.into(),
            identity_type: identity_type.into(),
            identity_ref: key_id.into(),
            valid_from: "2026-05-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": key_id}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            roles: Vec::new(),
            attestation_evidence: None,
        }
    }

    fn fix_content_rating_attestation(
        att_id: &str,
        attester: &str,
        dimension: &str,
        sha_hex: &str,
    ) -> crate::federation::Attestation {
        crate::federation::Attestation {
            attestation_id: att_id.into(),
            attesting_key_id: attester.into(),
            attested_key_id: attester.into(),
            attestation_type: crate::federation::types::attestation_type::SCORES.into(),
            weight: Some(1.0),
            asserted_at: "2026-05-01T00:00:00Z".parse().unwrap(),
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": dimension,
                "score": 1.0,
                "confidence": 0.9,
                "evidence_refs": [sha_hex],
            }),
            original_content_hash: "abc123".into(),
            scrub_signature_classical: "c2ln".into(),
            scrub_signature_pqc: None,
            scrub_key_id: attester.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn lookup_trusted_publisher_chain_returns_empty_for_unblessed_content_pg() {
        use crate::federation::FederationDirectory;
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        // SHA that no trusted_publisher has rated — must yield empty.
        let sha_hex = format!(
            "e{}",
            uuid::Uuid::new_v4().as_simple().to_string().repeat(2)
        );
        // Truncate / pad to 64 chars hex.
        let sha_hex = sha_hex.chars().take(64).collect::<String>();
        let sha_hex = format!("{:0<64}", sha_hex);
        let chain = backend
            .lookup_trusted_publisher_chain(&sha_hex)
            .await
            .unwrap();
        assert!(chain.is_empty());
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn lookup_trusted_publisher_chain_returns_chain_when_trusted_publisher_attests_pg() {
        use crate::federation::FederationDirectory;
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        // Unique-per-run publisher + att IDs so reruns against the
        // shared PG DB don't pollute (mirrors the existing
        // feedback_hundred_percent_green discipline).
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let publisher_key = format!("pub-{}", &nonce[..16]);
        // PG attestation_id column is UUID; use a fresh UUID here.
        let att_id = uuid::Uuid::new_v4().to_string();
        let sha_hex = format!("{:0<64}", nonce);
        let sha_hex = sha_hex.chars().take(64).collect::<String>();
        // Seed publisher key as trusted_publisher identity_type.
        backend
            .put_public_key(crate::federation::SignedKeyRecord {
                record: fix_trusted_publisher_key(
                    &publisher_key,
                    crate::federation::types::identity_type::TRUSTED_PUBLISHER,
                ),
            })
            .await
            .unwrap();
        // Seed a content_rating attestation referencing the SHA.
        backend
            .put_attestation(crate::federation::SignedAttestation {
                attestation: fix_content_rating_attestation(
                    &att_id,
                    &publisher_key,
                    "content_rating:mpa:pg13:v1",
                    &sha_hex,
                ),
            })
            .await
            .unwrap();
        let chain = backend
            .lookup_trusted_publisher_chain(&sha_hex)
            .await
            .unwrap();
        assert!(
            chain.iter().any(|a| a.attestation_id == att_id),
            "chain must include the seeded attestation: {chain:?}"
        );
        for att in &chain {
            let dim = att
                .attestation_envelope
                .get("dimension")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            assert!(
                dim.starts_with("content_rating:"),
                "every chain entry must be content_rating:* — got {dim:?}"
            );
        }
    }
}
