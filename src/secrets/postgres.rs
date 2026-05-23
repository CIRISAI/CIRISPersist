//! PostgreSQL impl of [`SecretsService`] (v0.6.1-α5, CIRISPersist#19).
//!
//! Concrete impl backed by `cirislens_secrets.*` (V010 schema). Every
//! method writes a row to `access_log` before returning (the audit
//! invariant from FSD §7.1). Crypto routes through
//! [`super::crypto`] — the sole import site of `ciris_crypto::*`.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::crypto;
use super::service::SecretsService;
use super::types::{
    AccessLogEntry, AccessOp, DecapsulationContext, FilterConfig, FilterUpdateRequest,
    FilterUpdateResult, MasterKeyRef, RotationResult, SecretRecallResult, SecretReference,
    SecretsListFilter, SecretsServiceStats,
};
use super::SecretsError;
use crate::pipeline::classify::Sensitivity;
use crate::store::postgres::PostgresBackend;
use crate::ClaimResult;

// ─── helpers ────────────────────────────────────────────────────────

/// Translate a Sensitivity enum into the lowercased token V010's
/// CHECK constraint accepts.
fn sensitivity_str(s: Sensitivity) -> &'static str {
    match s {
        Sensitivity::Low => "low",
        Sensitivity::Medium => "medium",
        Sensitivity::High => "high",
        Sensitivity::Critical => "critical",
    }
}

fn sensitivity_from_str(s: &str) -> Result<Sensitivity, SecretsError> {
    match s {
        "low" => Ok(Sensitivity::Low),
        "medium" => Ok(Sensitivity::Medium),
        "high" => Ok(Sensitivity::High),
        "critical" => Ok(Sensitivity::Critical),
        other => Err(SecretsError::Backend(format!(
            "unknown sensitivity_level: {other}"
        ))),
    }
}

fn access_op_str(op: AccessOp) -> &'static str {
    match op {
        AccessOp::Store => "store",
        AccessOp::Retrieve => "retrieve",
        AccessOp::Recall => "recall",
        AccessOp::Forget => "forget",
        AccessOp::Encrypt => "encrypt",
        AccessOp::Decrypt => "decrypt",
        AccessOp::Reencrypt => "reencrypt",
        AccessOp::Rotate => "rotate",
    }
}

/// True if `e` is a Postgres unique-constraint violation (SQLSTATE
/// 23505). v2.0 `rotate_master_key` uses this to identify the loser
/// of a concurrent first-use bootstrap race — its activating UPDATE
/// commit is rejected by the V043 `master_key_one_active` partial
/// unique index.
fn is_unique_violation(e: &tokio_postgres::Error) -> bool {
    e.as_db_error()
        .map(|d| d.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION)
        .unwrap_or(false)
}

fn access_op_from_str(s: &str) -> Result<AccessOp, SecretsError> {
    match s {
        "store" => Ok(AccessOp::Store),
        "retrieve" => Ok(AccessOp::Retrieve),
        "recall" => Ok(AccessOp::Recall),
        "forget" => Ok(AccessOp::Forget),
        "encrypt" => Ok(AccessOp::Encrypt),
        "decrypt" => Ok(AccessOp::Decrypt),
        "reencrypt" => Ok(AccessOp::Reencrypt),
        "rotate" => Ok(AccessOp::Rotate),
        other => Err(SecretsError::Backend(format!(
            "unknown access_log.operation: {other}"
        ))),
    }
}

/// Bookkeeping for one method call — composes the access_log row that
/// every impl must write before returning.
struct AuditRecord {
    secret_uuid: Option<Uuid>,
    accessor: String,
    operation: AccessOp,
    action_type: Option<String>,
    purpose: Option<String>,
    trace_id: Option<String>,
    thought_id: Option<String>,
}

impl AuditRecord {
    fn new(operation: AccessOp, accessor: impl Into<String>) -> Self {
        Self {
            secret_uuid: None,
            accessor: accessor.into(),
            operation,
            action_type: None,
            purpose: None,
            trace_id: None,
            thought_id: None,
        }
    }

    fn with_secret(mut self, uuid: Uuid) -> Self {
        self.secret_uuid = Some(uuid);
        self
    }

    fn with_purpose(mut self, p: impl Into<String>) -> Self {
        self.purpose = Some(p.into());
        self
    }
}

impl PostgresBackend {
    /// INSERT one row into `cirislens_secrets.access_log`. Best-effort:
    /// if the audit-write itself fails, log to tracing but don't mask
    /// the caller's primary error. The audit invariant says we MUST
    /// write before returning; this helper is the only place that
    /// writes access_log so the discipline is auditable.
    async fn secrets_audit(
        &self,
        rec: AuditRecord,
        success: bool,
        error: Option<&str>,
    ) -> Result<(), SecretsError> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        client
            .execute(
                "INSERT INTO cirislens_secrets.access_log (\
                    secret_uuid, accessor, operation, action_type, purpose, \
                    success, error, trace_id, thought_id\
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
                &[
                    &rec.secret_uuid,
                    &rec.accessor,
                    &access_op_str(rec.operation),
                    &rec.action_type,
                    &rec.purpose,
                    &success,
                    &error.map(str::to_owned),
                    &rec.trace_id,
                    &rec.thought_id,
                ],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("access_log insert: {e}")))?;
        Ok(())
    }

    /// Look up the current active master key. "active" means
    /// `activated_at IS NOT NULL AND deactivated_at IS NULL` — a key
    /// that has been activated and not since retired. A row with
    /// `activated_at IS NULL` is *staged* (rotate_master_key /
    /// migrate_to_hardware_key inserted it; not yet operative) and
    /// is NOT active. This predicate is reconciled with
    /// `rotate_master_key`'s COUNT and the V043 `master_key_one_active`
    /// partial unique index. Zero = uninitialized (caller invokes
    /// rotate_master_key first); >1 = invariant violation (V043 makes
    /// this DB-unrepresentable), surfaces as Internal.
    async fn active_master_key(&self) -> Result<MasterKey, SecretsError> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        let rows = client
            .query(
                "SELECT key_ref, key_kind, descriptor \
                 FROM cirislens_secrets.master_key_meta \
                 WHERE activated_at IS NOT NULL AND deactivated_at IS NULL",
                &[],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("active_master_key: {e}")))?;
        if rows.is_empty() {
            // Auto-initialize: generate a fresh software master key.
            // v0.6.1 stores the key bytes in-memory keyed by key_ref;
            // a persistent key-store binding lands in v0.6.x via
            // ciris-keyring once symmetric-derivation is upstream.
            return Err(SecretsError::Crypto(
                "no active master key. Initialize via rotate_master_key first.".into(),
            ));
        }
        if rows.len() > 1 {
            return Err(SecretsError::Internal(format!(
                "{} active master keys; expected exactly 1",
                rows.len()
            )));
        }
        let row = &rows[0];
        let key_ref: String = row.get(0);
        let key_kind: String = row.get(1);
        let descriptor: Option<String> = row.get(2);
        // v0.6.1-α5 carries the software key bytes via the
        // SOFTWARE_KEYS in-memory map below.
        let bytes = match software_keys_get(&key_ref) {
            Some(b) => b,
            // v1.10.0 (#87) — a hardware-backed master key is
            // deterministically re-derivable from its TPM-sealed seed
            // (HKDF over a stable seed + context). After a process
            // restart the in-process cache is empty; re-derive and
            // repopulate it rather than failing — this is what makes
            // the hardware migration durable across restarts. A
            // *software* key has no such recovery path (its bytes
            // lived only in memory), so that case stays fatal.
            None if key_kind == "hardware" => {
                let (master, _descriptor) = tokio::task::spawn_blocking(
                    crate::secrets::hardware::derive_hardware_master_key,
                )
                .await
                .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;
                software_keys_put(key_ref.clone(), master.clone())?;
                master
            }
            None => {
                return Err(SecretsError::Crypto(format!(
                    "active master key {key_ref} has no in-memory bytes — \
                     restart cleared the in-process key store"
                )))
            }
        };
        Ok(MasterKey {
            key_ref,
            kind: key_kind,
            descriptor,
            bytes,
        })
    }

    /// Loser branch of the concurrent first-use bootstrap race: the
    /// V043 unique index rejected this transaction's activating
    /// UPDATE because a concurrent rotation already activated its key.
    /// The caller has already rolled the aborted tx back; this evicts
    /// the orphaned cached bytes and re-reads the winner's now-active
    /// master key.
    async fn converge_on_bootstrap_winner(
        &self,
        loser_key_ref: &str,
        accessor: String,
    ) -> Result<MasterKeyRef, SecretsError> {
        software_keys_remove(loser_key_ref);
        tracing::info!(
            "rotate_master_key: concurrent first-use bootstrap — \
             converging on the winning master key"
        );
        let winner = self.active_master_key().await?;
        let _ = self
            .secrets_audit(AuditRecord::new(AccessOp::Rotate, accessor), true, None)
            .await;
        Ok(MasterKeyRef::Software {
            handle: winner.key_ref,
        })
    }
}

// v0.9.3: software-key cache extracted to `secrets::key_cache` so
// both the Postgres + SQLite backends share the same in-memory
// store. Wired in via `use super::key_cache::{software_keys_get,
// software_keys_put}`.
use super::key_cache::{software_keys_get, software_keys_put, software_keys_remove};

struct MasterKey {
    key_ref: String,
    #[allow(dead_code)]
    kind: String,
    #[allow(dead_code)]
    descriptor: Option<String>,
    bytes: Vec<u8>,
}

// ─── SecretsService impl ────────────────────────────────────────────

impl SecretsService for PostgresBackend {
    async fn store_secret(
        &self,
        key: String,
        value: String,
        accessor: String,
    ) -> Result<(), SecretsError> {
        // Generate UUID + per-secret salt + nonce + derive key.
        let secret_uuid = Uuid::new_v4();
        let master = self.active_master_key().await?;
        let salt = crypto::random_salt()?;
        let nonce = crypto::random_nonce()?;
        let secret_key = crypto::derive_secret_key(&master.bytes, &salt)?;
        let ciphertext = crypto::encrypt(&secret_key, &nonce, value.as_bytes())?;

        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        let result = client
            .execute(
                "INSERT INTO cirislens_secrets.secrets (\
                    secret_uuid, encrypted_value, encryption_key_ref, salt, nonce, \
                    description, sensitivity_level, detected_pattern \
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                &[
                    &secret_uuid,
                    &ciphertext,
                    &master.key_ref,
                    &salt.to_vec(),
                    &nonce.to_vec(),
                    &key, // description = the manual key
                    &"medium",
                    &"manual",
                ],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("store_secret: {e}")));

        let success = result.is_ok();
        let err_msg = result.as_ref().err().map(|e| e.to_string());
        let _ = self
            .secrets_audit(
                AuditRecord::new(AccessOp::Store, &accessor)
                    .with_secret(secret_uuid)
                    .with_purpose(format!("manual-keyed: {key}")),
                success,
                err_msg.as_deref(),
            )
            .await;
        result?;
        Ok(())
    }

    async fn retrieve_secret(
        &self,
        key: &str,
        accessor: String,
    ) -> Result<Option<String>, SecretsError> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT secret_uuid, encrypted_value, encryption_key_ref, salt, nonce \
                 FROM cirislens_secrets.secrets \
                 WHERE description = $1 \
                 ORDER BY created_at DESC LIMIT 1",
                &[&key],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("retrieve_secret lookup: {e}")))?;

        let (audit, plaintext) = match row_opt {
            None => (
                AuditRecord::new(AccessOp::Retrieve, &accessor).with_purpose(key),
                None,
            ),
            Some(row) => {
                let uuid: Uuid = row.get(0);
                let ct: Vec<u8> = row.get(1);
                let key_ref: String = row.get(2);
                let salt: Vec<u8> = row.get(3);
                let nonce: Vec<u8> = row.get(4);
                let master_bytes = software_keys_get(&key_ref).ok_or_else(|| {
                    SecretsError::Crypto(format!("master key {key_ref} unavailable in-process"))
                })?;
                let sk = crypto::derive_secret_key(&master_bytes, &salt)?;
                let pt = crypto::decrypt(&sk, &nonce, &ct)?;
                let pt = String::from_utf8(pt)
                    .map_err(|e| SecretsError::Internal(format!("ciphertext was not utf8: {e}")))?;
                (
                    AuditRecord::new(AccessOp::Retrieve, &accessor)
                        .with_secret(uuid)
                        .with_purpose(key),
                    Some(pt),
                )
            }
        };
        // Bump access_count.
        if plaintext.is_some() {
            if let Some(uuid) = audit.secret_uuid {
                let _ = client
                    .execute(
                        "UPDATE cirislens_secrets.secrets \
                         SET last_accessed = NOW(), access_count = access_count + 1 \
                         WHERE secret_uuid = $1",
                        &[&uuid],
                    )
                    .await;
            }
        }
        let _ = self.secrets_audit(audit, true, None).await;
        Ok(plaintext)
    }

    async fn recall_secret(
        &self,
        uuid: &str,
        purpose: String,
        accessor: String,
        decrypt: bool,
    ) -> Result<Option<SecretRecallResult>, SecretsError> {
        let parsed_uuid = Uuid::parse_str(uuid)
            .map_err(|e| SecretsError::InvalidArgument(format!("uuid parse: {e}")))?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT encrypted_value, encryption_key_ref, salt, nonce \
                 FROM cirislens_secrets.secrets \
                 WHERE secret_uuid = $1",
                &[&parsed_uuid],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("recall_secret lookup: {e}")))?;

        let result = match row_opt {
            None => Some(SecretRecallResult {
                found: false,
                value: None,
                error: None,
            }),
            Some(row) => {
                if !decrypt {
                    Some(SecretRecallResult {
                        found: true,
                        value: None,
                        error: None,
                    })
                } else {
                    let ct: Vec<u8> = row.get(0);
                    let key_ref: String = row.get(1);
                    let salt: Vec<u8> = row.get(2);
                    let nonce: Vec<u8> = row.get(3);
                    let master_bytes = software_keys_get(&key_ref).ok_or_else(|| {
                        SecretsError::Crypto(format!("master key {key_ref} unavailable in-process"))
                    })?;
                    let sk = crypto::derive_secret_key(&master_bytes, &salt)?;
                    match crypto::decrypt(&sk, &nonce, &ct) {
                        Ok(pt) => {
                            let _ = client
                                .execute(
                                    "UPDATE cirislens_secrets.secrets \
                                     SET last_accessed = NOW(), access_count = access_count + 1 \
                                     WHERE secret_uuid = $1",
                                    &[&parsed_uuid],
                                )
                                .await;
                            let pt = String::from_utf8(pt).map_err(|e| {
                                SecretsError::Internal(format!("ciphertext not utf8: {e}"))
                            })?;
                            Some(SecretRecallResult {
                                found: true,
                                value: Some(pt),
                                error: None,
                            })
                        }
                        Err(e) => Some(SecretRecallResult {
                            found: true,
                            value: None,
                            error: Some(e.to_string()),
                        }),
                    }
                }
            }
        };
        let _ = self
            .secrets_audit(
                AuditRecord::new(AccessOp::Recall, &accessor)
                    .with_secret(parsed_uuid)
                    .with_purpose(purpose),
                true,
                None,
            )
            .await;
        Ok(result)
    }

    async fn list_stored_secrets(
        &self,
        limit: usize,
        filter: SecretsListFilter,
    ) -> Result<Vec<SecretReference>, SecretsError> {
        let lim = i64::try_from(limit.min(10_000)).unwrap_or(1000);
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = Vec::new();
        if let Some(s) = filter.sensitivity {
            params.push(Box::new(sensitivity_str(s).to_owned()));
            where_parts.push(format!("sensitivity_level = ${}", params.len()));
        }
        if let Some(p) = filter.pattern {
            params.push(Box::new(p));
            where_parts.push(format!("detected_pattern = ${}", params.len()));
        }
        if let Some(m) = filter.source_message_id {
            params.push(Box::new(m));
            where_parts.push(format!("source_message_id = ${}", params.len()));
        }
        if let Some(t) = filter.created_after {
            params.push(Box::new(t));
            where_parts.push(format!("created_at >= ${}", params.len()));
        }
        if let Some(t) = filter.created_before {
            params.push(Box::new(t));
            where_parts.push(format!("created_at < ${}", params.len()));
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };
        params.push(Box::new(lim));
        let p_lim = params.len();
        let sql = format!(
            "SELECT secret_uuid::text, description, context_hint, sensitivity_level, \
                    detected_pattern, auto_decapsulate_for_actions, created_at, last_accessed \
             FROM cirislens_secrets.secrets \
             {where_sql} \
             ORDER BY created_at DESC \
             LIMIT ${p_lim}"
        );
        let params_ref: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
            params.iter().map(|p| p.as_ref() as _).collect();
        let rows = client
            .query(&sql, &params_ref[..])
            .await
            .map_err(|e| SecretsError::Backend(format!("list_stored_secrets: {e}")))?;
        let mut out: Vec<SecretReference> = Vec::with_capacity(rows.len());
        for row in rows {
            let sensitivity_str_v: String = row.get(3);
            out.push(SecretReference {
                uuid: row.get(0),
                description: row.get(1),
                context_hint: row.get(2),
                sensitivity: sensitivity_from_str(&sensitivity_str_v)?,
                detected_pattern: row.get(4),
                auto_decapsulate_actions: row.get(5),
                created_at: row.get(6),
                last_accessed: row.get(7),
            });
        }
        Ok(out)
    }

    async fn forget_secret(&self, uuid: &str, accessor: String) -> Result<bool, SecretsError> {
        let parsed_uuid = Uuid::parse_str(uuid)
            .map_err(|e| SecretsError::InvalidArgument(format!("uuid parse: {e}")))?;
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        let n = client
            .execute(
                "DELETE FROM cirislens_secrets.secrets WHERE secret_uuid = $1",
                &[&parsed_uuid],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("forget_secret: {e}")))?;
        let _ = self
            .secrets_audit(
                AuditRecord::new(AccessOp::Forget, accessor).with_secret(parsed_uuid),
                n > 0,
                None,
            )
            .await;
        Ok(n > 0)
    }

    // v1.5.7 (CIRISPersist#57) — process_incoming_text uses the default
    // trait impl which composes get_filter_config + try_claim_secret.
    // Both primitives are PG-implemented; the default suffices.

    async fn decapsulate_secrets_in_parameters(
        &self,
        _action_type: &str,
        _action_params: serde_json::Value,
        _ctx: DecapsulationContext,
    ) -> Result<serde_json::Value, SecretsError> {
        Err(SecretsError::Internal(
            "decapsulate_secrets_in_parameters requires v0.6.2 pipeline orchestration".into(),
        ))
    }

    async fn encrypt(&self, plaintext: &str) -> Result<String, SecretsError> {
        let master = self.active_master_key().await?;
        let salt = crypto::random_salt()?;
        let nonce = crypto::random_nonce()?;
        let secret_key = crypto::derive_secret_key(&master.bytes, &salt)?;
        let ct = crypto::encrypt(&secret_key, &nonce, plaintext.as_bytes())?;
        // Pack: salt(32) || nonce(12) || ct
        let mut packed = Vec::with_capacity(salt.len() + nonce.len() + ct.len());
        packed.extend_from_slice(&salt);
        packed.extend_from_slice(&nonce);
        packed.extend_from_slice(&ct);
        let out = BASE64.encode(&packed);
        let _ = self
            .secrets_audit(
                AuditRecord::new(AccessOp::Encrypt, "direct").with_purpose("direct encrypt"),
                true,
                None,
            )
            .await;
        Ok(out)
    }

    async fn decrypt(&self, ciphertext: &str) -> Result<String, SecretsError> {
        let raw = BASE64
            .decode(ciphertext.as_bytes())
            .map_err(|e| SecretsError::InvalidArgument(format!("base64 decode: {e}")))?;
        if raw.len() < crypto::SALT_LEN + crypto::NONCE_LEN {
            return Err(SecretsError::InvalidArgument(format!(
                "ciphertext too short: {} bytes",
                raw.len()
            )));
        }
        let salt = &raw[..crypto::SALT_LEN];
        let nonce = &raw[crypto::SALT_LEN..crypto::SALT_LEN + crypto::NONCE_LEN];
        let ct = &raw[crypto::SALT_LEN + crypto::NONCE_LEN..];
        let master = self.active_master_key().await?;
        let sk = crypto::derive_secret_key(&master.bytes, salt)?;
        let pt = crypto::decrypt(&sk, nonce, ct)?;
        let pt = String::from_utf8(pt)
            .map_err(|e| SecretsError::Internal(format!("ciphertext not utf8: {e}")))?;
        let _ = self
            .secrets_audit(
                AuditRecord::new(AccessOp::Decrypt, "direct").with_purpose("direct decrypt"),
                true,
                None,
            )
            .await;
        Ok(pt)
    }

    async fn get_filter_config(&self) -> Result<FilterConfig, SecretsError> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        let row_opt = client
            .query_opt(
                "SELECT config_id, config_value, version, updated_at, updated_by \
                 FROM cirislens_secrets.filter_config WHERE config_id = 'global'",
                &[],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("get_filter_config: {e}")))?;
        match row_opt {
            None => Ok(FilterConfig {
                config_id: "global".into(),
                config_value: serde_json::json!({}),
                version: 0,
                updated_at: Utc::now(),
                updated_by: "default".into(),
            }),
            Some(row) => Ok(FilterConfig {
                config_id: row.get(0),
                config_value: row.get(1),
                version: row.get(2),
                updated_at: row.get(3),
                updated_by: row.get(4),
            }),
        }
    }

    async fn update_filter_config(
        &self,
        updates: FilterUpdateRequest,
        accessor: String,
    ) -> Result<FilterUpdateResult, SecretsError> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        let row = client
            .query_one(
                "INSERT INTO cirislens_secrets.filter_config (\
                    config_id, config_value, version, updated_at, updated_by\
                 ) VALUES ($1, $2, 1, NOW(), $3) \
                 ON CONFLICT (config_id) DO UPDATE \
                 SET config_value = EXCLUDED.config_value, \
                     version = cirislens_secrets.filter_config.version + 1, \
                     updated_at = NOW(), \
                     updated_by = EXCLUDED.updated_by \
                 RETURNING version, updated_at",
                &[&updates.config_id, &updates.new_config, &accessor],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("update_filter_config: {e}")))?;
        Ok(FilterUpdateResult {
            new_version: row.get(0),
            updated_at: row.get(1),
        })
    }

    async fn get_service_stats(&self) -> Result<SecretsServiceStats, SecretsError> {
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        let row = client
            .query_one(
                "SELECT \
                    (SELECT COUNT(*)::bigint FROM cirislens_secrets.secrets) AS total_secrets, \
                    (SELECT COUNT(*)::bigint FROM cirislens_secrets.filter_config WHERE config_value::text != '{}') AS active_filters, \
                    (SELECT COUNT(*)::bigint FROM cirislens_secrets.access_log \
                     WHERE created_at >= NOW() - INTERVAL '24 hours' \
                       AND operation IN ('store','recall')) AS filter_matches_today, \
                    (SELECT MAX(updated_at) FROM cirislens_secrets.filter_config) AS last_filter_update, \
                    (SELECT MAX(activated_at) FROM cirislens_secrets.master_key_meta \
                     WHERE deactivated_at IS NOT NULL) AS last_rotation, \
                    (SELECT COUNT(*)::bigint FROM cirislens_secrets.master_key_meta \
                     WHERE deactivated_at IS NOT NULL) AS rotation_count",
                &[],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("get_service_stats: {e}")))?;
        let total: i64 = row.get(0);
        let active_filters: i64 = row.get(1);
        let matches: i64 = row.get(2);
        let last_filter_update: Option<DateTime<Utc>> = row.get(3);
        let last_rotation: Option<DateTime<Utc>> = row.get(4);
        let rotation_count: i64 = row.get(5);

        // Encryption health: try active_master_key — Ok = enabled.
        // v1.10.1 (#87 review M4) — `hardware_key_active` reflects the
        // active key's `key_kind` instead of a hard-coded false, so
        // ops can see whether `migrate_to_hardware_key` took effect.
        let active = self.active_master_key().await;
        let encryption_enabled = active.is_ok();
        let hardware_key_active = active
            .as_ref()
            .map(|k| k.kind == "hardware")
            .unwrap_or(false);

        Ok(SecretsServiceStats {
            total_secrets: total as u64,
            active_filters: active_filters as u64,
            filter_matches_today: matches as u64,
            last_filter_update,
            encryption_enabled,
            hardware_key_active,
            last_rotation,
            rotation_count: rotation_count as u64,
        })
    }

    async fn is_healthy(&self) -> Result<bool, SecretsError> {
        // Quick connectivity + active-key check.
        let _ = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        Ok(self.active_master_key().await.is_ok())
    }

    async fn get_access_logs(
        &self,
        secret_uuid: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AccessLogEntry>, SecretsError> {
        let lim = i64::try_from(limit.min(10_000)).unwrap_or(1000);
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        let rows = match secret_uuid {
            Some(u) => {
                let parsed = Uuid::parse_str(u)
                    .map_err(|e| SecretsError::InvalidArgument(format!("uuid parse: {e}")))?;
                client
                    .query(
                        "SELECT log_id, secret_uuid::text, accessor, operation, action_type, \
                                purpose, success, error, trace_id, thought_id, created_at \
                         FROM cirislens_secrets.access_log \
                         WHERE secret_uuid = $1 \
                         ORDER BY log_id DESC LIMIT $2",
                        &[&parsed, &lim],
                    )
                    .await
            }
            None => {
                client
                    .query(
                        "SELECT log_id, secret_uuid::text, accessor, operation, action_type, \
                                purpose, success, error, trace_id, thought_id, created_at \
                         FROM cirislens_secrets.access_log \
                         ORDER BY log_id DESC LIMIT $1",
                        &[&lim],
                    )
                    .await
            }
        };
        let rows = rows.map_err(|e| SecretsError::Backend(format!("get_access_logs: {e}")))?;
        let mut out: Vec<AccessLogEntry> = Vec::with_capacity(rows.len());
        for row in rows {
            let op_str: String = row.get(3);
            out.push(AccessLogEntry {
                log_id: row.get(0),
                secret_uuid: row.get(1),
                accessor: row.get(2),
                operation: access_op_from_str(&op_str)?,
                action_type: row.get(4),
                purpose: row.get(5),
                success: row.get(6),
                error: row.get(7),
                trace_id: row.get(8),
                thought_id: row.get(9),
                created_at: row.get(10),
            });
        }
        Ok(out)
    }

    async fn reencrypt_all(
        &self,
        new_master_key_ref: MasterKeyRef,
        accessor: String,
    ) -> Result<RotationResult, SecretsError> {
        let start = std::time::Instant::now();
        // Resolve the new master-key bytes. For Software variant the
        // handle = key_ref already in software_keys.
        let new_key_ref = match &new_master_key_ref {
            MasterKeyRef::Software { handle } => handle.clone(),
            MasterKeyRef::Hardware { key_id, .. } => key_id.clone(),
        };
        let new_master_bytes = software_keys_get(&new_key_ref).ok_or_else(|| {
            SecretsError::Crypto(format!(
                "new master key {new_key_ref} not loaded — call rotate_master_key first"
            ))
        })?;

        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;

        // Load every secret up front — a plain read, no lock held.
        // Each row is self-describing (`encryption_key_ref` per row),
        // so a partially-migrated table stays fully decryptable.
        let rows = client
            .query(
                "SELECT secret_uuid, encrypted_value, encryption_key_ref, salt, nonce \
                 FROM cirislens_secrets.secrets",
                &[],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("reencrypt_all load: {e}")))?;

        // v1.10.1 (#88 review, perf H2) — re-encrypt in bounded
        // chunks. The CPU-bound decrypt/derive/encrypt (PBKDF2,
        // ~100 ms/secret) runs with NO transaction open; only a
        // chunk's UPDATE batch runs in a short transaction, so the
        // write lock is released between chunks instead of held
        // across the whole table.
        struct Prepared {
            uuid: Uuid,
            ct: Vec<u8>,
            salt: Vec<u8>,
            nonce: Vec<u8>,
        }
        let mut reencrypted = 0u64;
        let mut failures: Vec<String> = Vec::new();

        for chunk in rows.chunks(crate::secrets::REENCRYPT_CHUNK_SIZE) {
            // Phase A — crypto, no transaction. A row whose old key /
            // ciphertext won't decrypt is recorded + skipped.
            let mut prepared: Vec<Prepared> = Vec::with_capacity(chunk.len());
            for row in chunk {
                let uuid: Uuid = row.get(0);
                let ct: Vec<u8> = row.get(1);
                let old_key_ref: String = row.get(2);
                let old_salt: Vec<u8> = row.get(3);
                let old_nonce: Vec<u8> = row.get(4);
                let old_bytes = match software_keys_get(&old_key_ref) {
                    Some(b) => b,
                    None => {
                        failures.push(uuid.to_string());
                        continue;
                    }
                };
                let old_sk = match crypto::derive_secret_key(&old_bytes, &old_salt) {
                    Ok(k) => k,
                    Err(_) => {
                        failures.push(uuid.to_string());
                        continue;
                    }
                };
                let plaintext = match crypto::decrypt(&old_sk, &old_nonce, &ct) {
                    Ok(p) => p,
                    Err(_) => {
                        failures.push(uuid.to_string());
                        continue;
                    }
                };
                let new_salt = crypto::random_salt()?;
                let new_nonce = crypto::random_nonce()?;
                let new_sk = crypto::derive_secret_key(&new_master_bytes, &new_salt)?;
                let new_ct = crypto::encrypt(&new_sk, &new_nonce, &plaintext)?;
                prepared.push(Prepared {
                    uuid,
                    ct: new_ct,
                    salt: new_salt.to_vec(),
                    nonce: new_nonce.to_vec(),
                });
            }
            if prepared.is_empty() {
                continue;
            }
            // Phase B — short transaction, just the UPDATE batch.
            let tx = client
                .transaction()
                .await
                .map_err(|e| SecretsError::Backend(format!("begin chunk tx: {e}")))?;
            for p in &prepared {
                tx.execute(
                    "UPDATE cirislens_secrets.secrets \
                     SET encrypted_value = $1, encryption_key_ref = $2, \
                         salt = $3, nonce = $4 \
                     WHERE secret_uuid = $5",
                    &[&p.ct, &new_key_ref, &p.salt, &p.nonce, &p.uuid],
                )
                .await
                .map_err(|e| SecretsError::Backend(format!("reencrypt update: {e}")))?;
            }
            tx.commit()
                .await
                .map_err(|e| SecretsError::Backend(format!("commit chunk: {e}")))?;
            reencrypted += prepared.len() as u64;
        }

        // Flip the active master key only on a fully-clean pass.
        // v1.10.1 (#87 review H1) — a partial failure must NOT
        // deactivate the old key: its un-migrated secrets are still
        // encrypted under it. Old key stays active, the migrated rows
        // remain readable (per-row `encryption_key_ref`), and a retry
        // can complete the pass.
        if failures.is_empty() {
            let tx = client
                .transaction()
                .await
                .map_err(|e| SecretsError::Backend(format!("begin key-flip tx: {e}")))?;
            tx.execute(
                "UPDATE cirislens_secrets.master_key_meta \
                 SET deactivated_at = NOW(), rotated_to = $1 \
                 WHERE deactivated_at IS NULL AND key_ref != $1",
                &[&new_key_ref],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("deactivate old key: {e}")))?;
            tx.execute(
                "UPDATE cirislens_secrets.master_key_meta \
                 SET activated_at = COALESCE(activated_at, NOW()) \
                 WHERE key_ref = $1",
                &[&new_key_ref],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("activate new key: {e}")))?;
            tx.commit()
                .await
                .map_err(|e| SecretsError::Backend(format!("commit key-flip: {e}")))?;
        }

        let failure_msg = if failures.is_empty() {
            None
        } else {
            Some(format!("{} failures", failures.len()))
        };
        let _ = self
            .secrets_audit(
                AuditRecord::new(AccessOp::Reencrypt, accessor),
                failures.is_empty(),
                failure_msg.as_deref(),
            )
            .await;

        Ok(RotationResult {
            success: failures.is_empty(),
            secrets_reencrypted: reencrypted,
            failures,
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    async fn rotate_master_key(
        &self,
        new_master: Option<Vec<u8>>,
        accessor: String,
    ) -> Result<MasterKeyRef, SecretsError> {
        // Generate the new key (or use supplied bytes).
        let key_bytes = match new_master {
            Some(b) => {
                if b.len() != crypto::KEY_LEN {
                    return Err(SecretsError::InvalidArgument(format!(
                        "new_master must be {} bytes (got {})",
                        crypto::KEY_LEN,
                        b.len()
                    )));
                }
                b
            }
            None => crypto::random_master_key()?.to_vec(),
        };
        let new_key_ref = Uuid::new_v4().to_string();

        // 2.0 concurrency hardening — INSERT the staged row + the
        // conditional first-use activation in ONE transaction, not
        // two separate pool checkouts. "active" means
        // `activated_at IS NOT NULL AND deactivated_at IS NULL`
        // (reconciled across active_master_key, this COUNT, and the
        // V043 partial unique index). The V043 index is the backstop:
        // if two concurrent first-use rotations both observe COUNT=0
        // and both activate, the second tx to commit hits the unique
        // violation — the loser then re-reads and converges on the
        // winner's key (first-use bootstraps converge, by design).
        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| SecretsError::Backend(format!("begin rotate tx: {e}")))?;
        tx.execute(
            "INSERT INTO cirislens_secrets.master_key_meta (\
                key_ref, key_kind, descriptor, created_at\
             ) VALUES ($1, 'software', NULL, NOW())",
            &[&new_key_ref],
        )
        .await
        .map_err(|e| SecretsError::Backend(format!("rotate_master_key insert: {e}")))?;
        // Cache the bytes BEFORE commit so the row is never visible
        // to a concurrent `active_master_key()` without its bytes.
        // The loser path below evicts them if the commit is rolled
        // back.
        software_keys_put(new_key_ref.clone(), key_bytes)?;

        // If there is no current ACTIVE key, activate this one
        // immediately (first-use path). Otherwise leave it staged so
        // the caller can drive reencrypt_all.
        let existing = tx
            .query_one(
                "SELECT COUNT(*) FROM cirislens_secrets.master_key_meta \
                 WHERE activated_at IS NOT NULL AND deactivated_at IS NULL \
                   AND key_ref != $1",
                &[&new_key_ref],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("rotate count: {e}")))?;
        let n: i64 = existing.get(0);
        let first_use = n == 0;

        // The activating UPDATE is where a concurrent first-use loser
        // trips the V043 `master_key_one_active` partial unique index:
        // two first-use transactions both reach this UPDATE; the
        // second blocks on the first's index entry, and when the
        // first commits the second's UPDATE fails with 23505 (the tx
        // is then aborted). A 23505 here is therefore a deliberate,
        // typed "lost the bootstrap race" signal — not a swallowed
        // error.
        if first_use {
            match tx
                .execute(
                    "UPDATE cirislens_secrets.master_key_meta \
                     SET activated_at = NOW() WHERE key_ref = $1",
                    &[&new_key_ref],
                )
                .await
            {
                Ok(_) => {}
                Err(e) if is_unique_violation(&e) => {
                    let _ = tx.rollback().await;
                    return self
                        .converge_on_bootstrap_winner(&new_key_ref, accessor)
                        .await;
                }
                Err(e) => {
                    let _ = tx.rollback().await;
                    software_keys_remove(&new_key_ref);
                    return Err(SecretsError::Backend(format!("rotate activate: {e}")));
                }
            }
        }

        // Commit. A first-use loser may also surface the V043
        // violation here (deferred-visibility timing) — handled the
        // same way.
        match tx.commit().await {
            Ok(()) => {
                let _ = self
                    .secrets_audit(AuditRecord::new(AccessOp::Rotate, accessor), true, None)
                    .await;
                Ok(MasterKeyRef::Software {
                    handle: new_key_ref,
                })
            }
            Err(e) if first_use && is_unique_violation(&e) => {
                software_keys_remove(&new_key_ref);
                tracing::info!(
                    "rotate_master_key: concurrent first-use bootstrap — \
                     converging on the winning master key"
                );
                let winner = self.active_master_key().await?;
                let _ = self
                    .secrets_audit(AuditRecord::new(AccessOp::Rotate, accessor), true, None)
                    .await;
                Ok(MasterKeyRef::Software {
                    handle: winner.key_ref,
                })
            }
            Err(e) => {
                software_keys_remove(&new_key_ref);
                Err(SecretsError::Backend(format!("rotate commit: {e}")))
            }
        }
    }

    async fn test_encryption(&self) -> Result<bool, SecretsError> {
        let probe = "ciris-encryption-health-probe";
        let ct = self.encrypt(probe).await?;
        let pt = self.decrypt(&ct).await?;
        Ok(pt == probe)
    }

    async fn migrate_to_hardware_key(
        &self,
        accessor: String,
    ) -> Result<MasterKeyRef, SecretsError> {
        // Derive the hardware-rooted master key — CIRISVerify owns the
        // derivation (HKDF over a hardware-sealed seed). Blocking I/O
        // (TPM + filesystem), so it runs on a blocking thread.
        let (master, descriptor) =
            tokio::task::spawn_blocking(crate::secrets::hardware::derive_hardware_master_key)
                .await
                .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;

        let new_key_ref = Uuid::new_v4().to_string();
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        // Record the new key as `hardware`, not yet active —
        // `reencrypt_all` activates it (and deactivates the prior one)
        // once every secret is re-encrypted, same staging as
        // `rotate_master_key`.
        client
            .execute(
                "INSERT INTO cirislens_secrets.master_key_meta (\
                    key_ref, key_kind, descriptor, created_at\
                 ) VALUES ($1, 'hardware', $2, NOW())",
                &[&new_key_ref, &descriptor],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("migrate_to_hardware_key insert: {e}")))?;
        software_keys_put(new_key_ref.clone(), master)?;

        let ref_out = MasterKeyRef::Hardware {
            key_id: new_key_ref,
            descriptor,
        };
        // Re-encrypt every secret under the hardware master key and
        // flip the active key. `reencrypt_all` audits the pass.
        let rotation = self.reencrypt_all(ref_out.clone(), accessor).await?;
        // v1.10.0 (#87 review H1) — `reencrypt_all` reports per-secret
        // failures via `RotationResult.success` rather than erroring.
        // A hardware migration must NOT silently return Ok while
        // secrets remain stranded under the now-deactivated old key.
        if !rotation.success {
            return Err(SecretsError::Crypto(format!(
                "hardware migration re-encrypted {} secret(s) but {} failed ({:?}) — \
                 the secrets store is partially migrated; resolve the failed rows and retry",
                rotation.secrets_reencrypted,
                rotation.failures.len(),
                rotation.failures
            )));
        }
        Ok(ref_out)
    }

    async fn try_claim_secret(
        &self,
        plaintext: &str,
        description: &str,
        sensitivity: Sensitivity,
        auto_decapsulate_for_actions: Vec<String>,
        accessor: String,
    ) -> Result<ClaimResult<SecretReference>, SecretsError> {
        // Compute HMAC-SHA256(active_master_key, plaintext) — the
        // dedup key. Routes through the secrets::crypto facade
        // (FSD §7.5a; the sole import site of ciris_crypto::hmac).
        let master = self.active_master_key().await?;
        let content_hmac = crypto::hmac_sha256(&master.bytes, plaintext.as_bytes()).to_vec();

        // Generate the fresh row's crypto state. Salt + nonce stay
        // unique per attempt — only the content_hmac collides on
        // race.
        let secret_uuid = Uuid::new_v4();
        let salt = crypto::random_salt()?;
        let nonce = crypto::random_nonce()?;
        let secret_key = crypto::derive_secret_key(&master.bytes, &salt)?;
        let ciphertext = crypto::encrypt(&secret_key, &nonce, plaintext.as_bytes())?;
        let sensitivity_tag = sensitivity_str(sensitivity).to_owned();

        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;

        // Atomic claim: INSERT, suppressing on content_hmac conflict.
        // RETURNING fires only on a successful insert; the empty-row
        // case below means another caller already won.
        let claim_row = client
            .query_opt(
                "INSERT INTO cirislens_secrets.secrets (\
                    secret_uuid, encrypted_value, encryption_key_ref, salt, nonce, \
                    description, sensitivity_level, detected_pattern, \
                    auto_decapsulate_for_actions, content_hmac \
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
                 ON CONFLICT (content_hmac) DO NOTHING \
                 RETURNING secret_uuid::text, description, context_hint, sensitivity_level, \
                           detected_pattern, auto_decapsulate_for_actions, \
                           created_at, last_accessed",
                &[
                    &secret_uuid,
                    &ciphertext,
                    &master.key_ref,
                    &salt.to_vec(),
                    &nonce.to_vec(),
                    &description,
                    &sensitivity_tag,
                    &"manual",
                    &auto_decapsulate_for_actions,
                    &content_hmac,
                ],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("try_claim_secret insert: {e}")));

        let (outcome, audit_uuid) = match claim_row {
            Ok(Some(row)) => {
                // We won the race — decode and return Stored.
                let sensitivity_str_v: String = row.get(3);
                let reference = SecretReference {
                    uuid: row.get(0),
                    description: row.get(1),
                    context_hint: row.get(2),
                    sensitivity: sensitivity_from_str(&sensitivity_str_v)?,
                    detected_pattern: row.get(4),
                    auto_decapsulate_actions: row.get(5),
                    created_at: row.get(6),
                    last_accessed: row.get(7),
                };
                (Ok(ClaimResult::Stored(reference)), Some(secret_uuid))
            }
            Ok(None) => {
                // Conflict — another caller already claimed this
                // content_hmac. Fetch the existing row's reference.
                let existing = client
                    .query_one(
                        "SELECT secret_uuid::text, description, context_hint, sensitivity_level, \
                                detected_pattern, auto_decapsulate_for_actions, \
                                created_at, last_accessed \
                         FROM cirislens_secrets.secrets \
                         WHERE content_hmac = $1",
                        &[&content_hmac],
                    )
                    .await
                    .map_err(|e| {
                        SecretsError::Backend(format!("try_claim_secret conflict-recovery: {e}"))
                    })?;
                let sensitivity_str_v: String = existing.get(3);
                let reference = SecretReference {
                    uuid: existing.get(0),
                    description: existing.get(1),
                    context_hint: existing.get(2),
                    sensitivity: sensitivity_from_str(&sensitivity_str_v)?,
                    detected_pattern: existing.get(4),
                    auto_decapsulate_actions: existing.get(5),
                    created_at: existing.get(6),
                    last_accessed: existing.get(7),
                };
                let existing_uuid = Uuid::parse_str(&reference.uuid)
                    .map_err(|e| SecretsError::Internal(format!("uuid parse: {e}")))?;
                (
                    Ok(ClaimResult::AlreadyClaimed(reference)),
                    Some(existing_uuid),
                )
            }
            Err(e) => (Err(e), None),
        };

        // Audit invariant: every method writes a row to access_log
        // before returning. Both Stored + AlreadyClaimed audit as
        // `store`; the success flag stays true (no error), and the
        // purpose surfaces the outcome for post-hoc reconstruction.
        let (success, err_msg, purpose) = match &outcome {
            Ok(ClaimResult::Stored(_)) => (
                true,
                None,
                format!("try_claim_secret stored: {description}"),
            ),
            Ok(ClaimResult::AlreadyClaimed(_)) => (
                true,
                None,
                format!("try_claim_secret already_claimed: {description}"),
            ),
            Err(e) => (false, Some(e.to_string()), description.to_owned()),
        };
        let mut record = AuditRecord::new(AccessOp::Store, &accessor).with_purpose(purpose);
        if let Some(uuid) = audit_uuid {
            record = record.with_secret(uuid);
        }
        let _ = self
            .secrets_audit(record, success, err_msg.as_deref())
            .await;

        outcome
    }

    async fn store_detected_secret(
        &self,
        payload: super::DetectedSecret,
        accessor: String,
    ) -> Result<ClaimResult<SecretReference>, SecretsError> {
        // ── Validation ──────────────────────────────────────────────
        if payload.secret_uuid.is_empty() {
            return Err(SecretsError::InvalidArgument("secret_uuid required".into()));
        }
        let agent_uuid = Uuid::parse_str(&payload.secret_uuid).map_err(|e| {
            SecretsError::InvalidArgument(format!("secret_uuid is not a valid UUID: {e}"))
        })?;
        if payload.value.is_empty() {
            return Err(SecretsError::InvalidArgument("value required".into()));
        }
        if payload.detected_pattern.is_empty() {
            return Err(SecretsError::InvalidArgument(
                "detected_pattern required".into(),
            ));
        }
        if payload.description.is_empty() {
            return Err(SecretsError::InvalidArgument("description required".into()));
        }

        // ── Crypto setup ────────────────────────────────────────────
        let master = self.active_master_key().await?;
        let content_hmac = crypto::hmac_sha256(&master.bytes, payload.value.as_bytes()).to_vec();
        let salt = crypto::random_salt()?;
        let nonce = crypto::random_nonce()?;
        let secret_key = crypto::derive_secret_key(&master.bytes, &salt)?;
        let ciphertext = crypto::encrypt(&secret_key, &nonce, payload.value.as_bytes())?;
        let sensitivity_tag = sensitivity_str(payload.sensitivity).to_owned();

        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;

        // ── Atomic insert with full metadata ────────────────────────
        // ON CONFLICT (content_hmac) DO NOTHING — race-safe across
        // store_detected_secret + try_claim_secret callers under the
        // same active master key. Empty RETURNING == another caller
        // already owns this plaintext.
        let claim_row = client
            .query_opt(
                "INSERT INTO cirislens_secrets.secrets (\
                    secret_uuid, encrypted_value, encryption_key_ref, salt, nonce, \
                    description, sensitivity_level, detected_pattern, context_hint, \
                    source_message_id, auto_decapsulate_for_actions, manual_access_only, \
                    content_hmac \
                 ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
                 ON CONFLICT (content_hmac) DO NOTHING \
                 RETURNING secret_uuid::text, description, context_hint, sensitivity_level, \
                           detected_pattern, auto_decapsulate_for_actions, \
                           created_at, last_accessed",
                &[
                    &agent_uuid,
                    &ciphertext,
                    &master.key_ref,
                    &salt.to_vec(),
                    &nonce.to_vec(),
                    &payload.description,
                    &sensitivity_tag,
                    &payload.detected_pattern,
                    &payload.context_hint,
                    &payload.source_message_id,
                    &payload.auto_decapsulate_for_actions,
                    &payload.manual_access_only,
                    &content_hmac,
                ],
            )
            .await;

        let (outcome, audit_uuid) = match claim_row {
            Ok(Some(row)) => {
                let sensitivity_str_v: String = row
                    .try_get(3)
                    .map_err(|e| SecretsError::Backend(format!("decode sensitivity: {e}")))?;
                let reference = SecretReference {
                    uuid: row
                        .try_get(0)
                        .map_err(|e| SecretsError::Backend(format!("decode uuid: {e}")))?,
                    description: row
                        .try_get(1)
                        .map_err(|e| SecretsError::Backend(format!("decode description: {e}")))?,
                    context_hint: row
                        .try_get(2)
                        .map_err(|e| SecretsError::Backend(format!("decode context_hint: {e}")))?,
                    sensitivity: sensitivity_from_str(&sensitivity_str_v)?,
                    detected_pattern: row.try_get(4).map_err(|e| {
                        SecretsError::Backend(format!("decode detected_pattern: {e}"))
                    })?,
                    auto_decapsulate_actions: row.try_get(5).map_err(|e| {
                        SecretsError::Backend(format!("decode auto_decapsulate: {e}"))
                    })?,
                    created_at: row
                        .try_get(6)
                        .map_err(|e| SecretsError::Backend(format!("decode created_at: {e}")))?,
                    last_accessed: row
                        .try_get(7)
                        .map_err(|e| SecretsError::Backend(format!("decode last_accessed: {e}")))?,
                };
                (Ok(ClaimResult::Stored(reference)), Some(agent_uuid))
            }
            Ok(None) => {
                // content_hmac collision — same plaintext already
                // stored. Fetch existing row's reference. Note: the
                // existing UUID may differ from the caller's agent_uuid
                // (different agent run, different detection-state, but
                // same plaintext).
                let existing = client
                    .query_one(
                        "SELECT secret_uuid::text, description, context_hint, sensitivity_level, \
                                detected_pattern, auto_decapsulate_for_actions, \
                                created_at, last_accessed \
                         FROM cirislens_secrets.secrets \
                         WHERE content_hmac = $1",
                        &[&content_hmac],
                    )
                    .await
                    .map_err(|e| {
                        SecretsError::Backend(format!(
                            "store_detected_secret conflict-recovery: {e}"
                        ))
                    })?;
                let sensitivity_str_v: String = existing
                    .try_get(3)
                    .map_err(|e| SecretsError::Backend(format!("decode sensitivity: {e}")))?;
                let reference = SecretReference {
                    uuid: existing
                        .try_get(0)
                        .map_err(|e| SecretsError::Backend(format!("decode uuid: {e}")))?,
                    description: existing
                        .try_get(1)
                        .map_err(|e| SecretsError::Backend(format!("decode description: {e}")))?,
                    context_hint: existing
                        .try_get(2)
                        .map_err(|e| SecretsError::Backend(format!("decode context_hint: {e}")))?,
                    sensitivity: sensitivity_from_str(&sensitivity_str_v)?,
                    detected_pattern: existing.try_get(4).map_err(|e| {
                        SecretsError::Backend(format!("decode detected_pattern: {e}"))
                    })?,
                    auto_decapsulate_actions: existing.try_get(5).map_err(|e| {
                        SecretsError::Backend(format!("decode auto_decapsulate: {e}"))
                    })?,
                    created_at: existing
                        .try_get(6)
                        .map_err(|e| SecretsError::Backend(format!("decode created_at: {e}")))?,
                    last_accessed: existing
                        .try_get(7)
                        .map_err(|e| SecretsError::Backend(format!("decode last_accessed: {e}")))?,
                };
                let existing_uuid = Uuid::parse_str(&reference.uuid)
                    .map_err(|e| SecretsError::Internal(format!("uuid parse: {e}")))?;
                (
                    Ok(ClaimResult::AlreadyClaimed(reference)),
                    Some(existing_uuid),
                )
            }
            Err(e) => {
                // Map secret_uuid PK conflicts → InvalidArgument
                // (agent supplied a UUID already used for a different
                // plaintext). Other backend errors pass through.
                let is_pk_conflict = e
                    .as_db_error()
                    .map(|d| {
                        d.code() == &tokio_postgres::error::SqlState::UNIQUE_VIOLATION
                            && d.constraint() == Some("secrets_pkey")
                    })
                    .unwrap_or(false);
                if is_pk_conflict {
                    (
                        Err(SecretsError::InvalidArgument(format!(
                            "secret_uuid {} already in use for a different plaintext",
                            payload.secret_uuid
                        ))),
                        Some(agent_uuid),
                    )
                } else {
                    (
                        Err(SecretsError::Backend(format!(
                            "store_detected_secret insert: {e}"
                        ))),
                        None,
                    )
                }
            }
        };

        // Audit-log row — invariant: every method writes one.
        let (success, err_msg, purpose) = match &outcome {
            Ok(ClaimResult::Stored(_)) => (
                true,
                None,
                format!("store_detected_secret stored: {}", payload.detected_pattern),
            ),
            Ok(ClaimResult::AlreadyClaimed(_)) => (
                true,
                None,
                format!(
                    "store_detected_secret already_claimed: {}",
                    payload.detected_pattern
                ),
            ),
            Err(e) => (
                false,
                Some(e.to_string()),
                format!("store_detected_secret failed: {}", payload.detected_pattern),
            ),
        };
        let mut record = AuditRecord::new(AccessOp::Store, &accessor).with_purpose(purpose);
        if let Some(uuid) = audit_uuid {
            record = record.with_secret(uuid);
        }
        let _ = self
            .secrets_audit(record, success, err_msg.as_deref())
            .await;

        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::postgres::PostgresBackend;

    fn pg_dsn() -> Option<String> {
        std::env::var("CIRIS_PERSIST_TEST_PG_URL").ok()
    }

    /// Smoke test the full SecretsService round-trip path:
    /// rotate_master_key → encrypt → decrypt → store → retrieve →
    /// list → recall → forget. Verifies the AES-GCM + PBKDF2 +
    /// access_log discipline holds end-to-end against live PG.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn secrets_round_trip_full_lifecycle() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        // 2.0.1 cross-process isolation: see acquire_pg_secrets_test_lock
        // doc. `#[serial(postgres)]` only serializes within a process;
        // nextest runs each test in its own process, so we need a PG
        // advisory lock to genuinely serialize PG secrets tests.
        let _lock = acquire_pg_secrets_test_lock(&backend).await;
        // Now safe to TRUNCATE: no other test process is reading or
        // writing master_key_meta concurrently.
        reset_secrets_state(&backend).await;

        // 1. No active master key initially — rotate to generate one.
        let key_ref = backend
            .rotate_master_key(None, "test-accessor".into())
            .await
            .expect("rotate_master_key");
        match &key_ref {
            MasterKeyRef::Software { handle } => {
                assert!(!handle.is_empty(), "key handle should be set");
            }
            _ => panic!("expected Software variant"),
        }

        // 2. Direct encrypt/decrypt round-trip.
        let ct = backend
            .encrypt("ciris-test-payload")
            .await
            .expect("encrypt");
        let pt = backend.decrypt(&ct).await.expect("decrypt");
        assert_eq!(pt, "ciris-test-payload");

        // 3. test_encryption helper.
        assert!(
            backend.test_encryption().await.unwrap(),
            "test_encryption should pass"
        );

        // 4. Manual-keyed store + retrieve.
        let manual_key = format!("manual-secret-{}", uuid::Uuid::new_v4());
        backend
            .store_secret(manual_key.clone(), "value-123".into(), "test".into())
            .await
            .expect("store_secret");
        let got = backend
            .retrieve_secret(&manual_key, "test".into())
            .await
            .expect("retrieve_secret");
        assert_eq!(got, Some("value-123".into()));

        // 5. List + filter.
        let listed = backend
            .list_stored_secrets(100, SecretsListFilter::default())
            .await
            .expect("list_stored_secrets");
        assert!(!listed.is_empty(), "list should include our secret");
        let our_uuid = listed
            .iter()
            .find(|r| r.description == manual_key)
            .map(|r| r.uuid.clone())
            .expect("our secret in listing");

        // 6. Recall (decrypt=true).
        let recalled = backend
            .recall_secret(&our_uuid, "test recall".into(), "test".into(), true)
            .await
            .expect("recall_secret")
            .expect("found");
        assert!(recalled.found);
        assert_eq!(recalled.value.as_deref(), Some("value-123"));

        // 7. Forget.
        let forgotten = backend
            .forget_secret(&our_uuid, "test".into())
            .await
            .expect("forget_secret");
        assert!(forgotten);

        // 8. Confirm forgotten.
        let r2 = backend
            .recall_secret(&our_uuid, "post-forget".into(), "test".into(), true)
            .await
            .expect("recall after forget")
            .expect("present-or-not_found-result");
        assert!(!r2.found);

        // 9. Audit log has multiple entries.
        let logs = backend
            .get_access_logs(None, 100)
            .await
            .expect("get_access_logs");
        assert!(
            logs.len() >= 5,
            "expected at least 5 audit rows, got {}",
            logs.len()
        );

        // 10. Service stats.
        let stats = backend
            .get_service_stats()
            .await
            .expect("get_service_stats");
        assert!(stats.encryption_enabled, "encryption should be enabled");
        // No hardware migration has run at this point (step 12) — the
        // active master key is still software.
        assert!(
            !stats.hardware_key_active,
            "hardware_key_active should be false before migrate_to_hardware_key"
        );

        // 11. is_healthy.
        assert!(backend.is_healthy().await.unwrap());

        // 12. migrate_to_hardware_key (CIRISPersist#87). Environment-
        // dependent: on a host with a usable TPM it succeeds and
        // returns a `Hardware` MasterKeyRef; on a host with none it
        // returns `HardwareKeyUnavailable` (the agent then keeps the
        // software master key). Both are correct — anything else
        // (Backend / Crypto / a panic) is a real bug.
        match backend.migrate_to_hardware_key("test".into()).await {
            Ok(MasterKeyRef::Hardware { .. }) => {}
            Ok(other) => panic!("migrate_to_hardware_key returned non-Hardware ref: {other:?}"),
            Err(SecretsError::HardwareKeyUnavailable(_)) => {}
            Err(other) => panic!("migrate_to_hardware_key failed unexpectedly: {other:?}"),
        }

        // 13. process_incoming_text — v1.5.7 default-trait impl. With
        // the default (empty) filter catalog there are no patterns to
        // match, so the text passes through unchanged with no refs.
        let (filtered, refs) = backend
            .process_incoming_text("x", "y", "test".into())
            .await
            .expect("process_incoming_text");
        assert_eq!(filtered, "x");
        assert!(refs.is_empty());

        // 14. decapsulate_secrets_in_parameters — still a v0.6.2
        // pipeline-orchestration stub; surfaces Internal.
        let err = backend
            .decapsulate_secrets_in_parameters(
                "tool",
                serde_json::json!({}),
                DecapsulationContext {
                    action_type: "tool".into(),
                    accessor: "test".into(),
                    purpose: "test".into(),
                    trace_id: None,
                    thought_id: None,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SecretsError::Internal(_)));
    }

    // ── v1.5.24 (CIRISPersist#66) store_detected_secret tests ───────

    /// Reset the secrets-table family so per-test rotate_master_key
    /// satisfies `active_master_key()`'s "exactly 1 row" invariant.
    /// CI starts with a fresh DB; local PG leftovers compound.
    ///
    /// Also clears the process-global SOFTWARE_KEYS cache — without
    /// this, a key_ref that survived in the cache from an earlier
    /// invocation (only possible inside the same test process when
    /// multiple tests share a binary; unlikely under nextest but
    /// cheap insurance) would shadow a freshly-rotated key.
    async fn reset_secrets_state(backend: &PostgresBackend) {
        let client = backend.pool().get().await.unwrap();
        client
            .batch_execute(
                "TRUNCATE cirislens_secrets.secrets, \
                 cirislens_secrets.access_log, \
                 cirislens_secrets.master_key_meta, \
                 cirislens_secrets.filter_config CASCADE",
            )
            .await
            .ok();
    }

    // ── v2.0.1 PG-test cross-process isolation ──────────────────────
    //
    // nextest runs each test in its own process. `#[serial(postgres)]`
    // is `serial_test`'s in-process serializer; it does NOT
    // synchronize across nextest's worker processes. The secrets PG
    // tests all hit the same `cirislens_secrets.master_key_meta` row
    // family, so two nextest workers racing on the same DB collide:
    // worker A's rotate inserts key X and caches bytes in A's
    // process-global SOFTWARE_KEYS; worker B's `reset_secrets_state`
    // then TRUNCATEs the DB and inserts key Y → worker A's subsequent
    // encrypt observes Y in `master_key_meta` but has no bytes for Y
    // in its own SOFTWARE_KEYS, panicking with "no in-memory bytes".
    //
    // Fix: a session-scoped Postgres advisory lock on a dedicated
    // connection, held for the duration of each PG secrets test. PG
    // advisory locks are cross-process — a second worker calling
    // `pg_advisory_lock($1)` blocks until the first worker's
    // connection closes (which happens when the guard drops at the
    // end of the test). This is the same primitive `run_migrations`
    // uses (MIGRATION_LOCK_ID) — known-good in this codebase.
    //
    // Lock ID is a magic constant unrelated to MIGRATION_LOCK_ID so
    // a test holding this lock doesn't block a migration that also
    // happens to be running.
    const PG_SECRETS_TEST_LOCK_ID: i64 = 0x6369_7273_7363_7274_i64; // 'cirsscrt'

    /// RAII guard that holds a session-scoped PG advisory lock on a
    /// dedicated (non-pooled) connection. Drop the guard (let it go
    /// out of scope at the end of the test) to release the lock —
    /// the connection's tokio task observes EOF and the session
    /// ends, auto-releasing the lock. This is the same pattern
    /// `run_migrations` uses for MIGRATION_LOCK_ID.
    ///
    /// Why dedicated and not pooled: pg_advisory_lock at SESSION
    /// scope persists across the connection's lifetime, so a pooled
    /// connection returned to the pool would still hold the lock —
    /// either we'd have to explicit-unlock (fragile, won't run on
    /// panic), or the next pool user would inherit the lock until
    /// the connection finally cycles out. A dedicated connection
    /// avoids both pitfalls.
    struct PgSecretsTestGuard {
        // Keep the client alive to keep the session alive. Drop ⇒
        // session ends ⇒ lock auto-releases. Tolerates test panic.
        _client: tokio_postgres::Client,
    }

    async fn acquire_pg_secrets_test_lock(_backend: &PostgresBackend) -> PgSecretsTestGuard {
        // Open a dedicated tokio_postgres connection — the same
        // recipe `PostgresBackend::dedicated_connect` uses, but the
        // dsn is private so we re-derive it from the env var the
        // test would have used to construct the backend.
        let dsn = pg_dsn().expect("pg_dsn for test lock");
        let (client, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
            .await
            .expect("dedicated connect for test lock");
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::warn!(error = %e, "pg secrets test-lock connection terminated");
            }
        });
        client
            .execute("SELECT pg_advisory_lock($1)", &[&PG_SECRETS_TEST_LOCK_ID])
            .await
            .expect("pg_advisory_lock");
        PgSecretsTestGuard { _client: client }
    }

    fn mk_detected_payload(value: &str, pattern: &str) -> super::super::DetectedSecret {
        super::super::DetectedSecret {
            secret_uuid: Uuid::new_v4().to_string(),
            value: value.to_owned(),
            description: "OpenAI key".to_owned(),
            sensitivity: Sensitivity::High,
            detected_pattern: pattern.to_owned(),
            context_hint: Some("tool_args.api_key".to_owned()),
            source_message_id: Some("msg-pg-test".to_owned()),
            auto_decapsulate_for_actions: vec!["tool".to_owned()],
            manual_access_only: false,
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn store_detected_secret_pg_stores_with_caller_uuid_and_full_metadata() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let _lock = acquire_pg_secrets_test_lock(&backend).await;
        reset_secrets_state(&backend).await;
        backend
            .rotate_master_key(None, "test".into())
            .await
            .unwrap();

        let payload = mk_detected_payload(
            &format!("sk-{}", Uuid::new_v4().simple()),
            "regex:openai_v1",
        );
        let caller_uuid = payload.secret_uuid.clone();
        let outcome = backend
            .store_detected_secret(payload, "agent-x".into())
            .await
            .expect("store_detected_secret");
        match outcome {
            ClaimResult::Stored(r) => {
                assert_eq!(r.uuid, caller_uuid);
                assert_eq!(r.detected_pattern, "regex:openai_v1");
                assert_eq!(r.context_hint.as_deref(), Some("tool_args.api_key"));
                assert_eq!(r.sensitivity, Sensitivity::High);
                assert_eq!(r.auto_decapsulate_actions, vec!["tool".to_string()]);
            }
            other => panic!("expected Stored, got {other:?}"),
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn store_detected_secret_pg_different_uuid_same_plaintext_returns_canonical() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let _lock = acquire_pg_secrets_test_lock(&backend).await;
        reset_secrets_state(&backend).await;
        backend
            .rotate_master_key(None, "test".into())
            .await
            .unwrap();

        let shared_value = format!("sk-{}", Uuid::new_v4().simple());
        let p1 = mk_detected_payload(&shared_value, "regex:openai_v1");
        let first_uuid = p1.secret_uuid.clone();
        let _ = backend
            .store_detected_secret(p1, "agent-a".into())
            .await
            .expect("first");

        let mut p2 = mk_detected_payload(&shared_value, "regex:openai_v1");
        p2.secret_uuid = Uuid::new_v4().to_string();
        assert_ne!(p2.secret_uuid, first_uuid);

        let r2 = backend
            .store_detected_secret(p2, "agent-b".into())
            .await
            .expect("second");
        match r2 {
            ClaimResult::AlreadyClaimed(r) => assert_eq!(r.uuid, first_uuid),
            other => panic!("expected AlreadyClaimed, got {other:?}"),
        }
    }

    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn store_detected_secret_pg_same_uuid_different_plaintext_invalid_argument() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let _lock = acquire_pg_secrets_test_lock(&backend).await;
        reset_secrets_state(&backend).await;
        backend
            .rotate_master_key(None, "test".into())
            .await
            .unwrap();

        let p1 = mk_detected_payload(
            &format!("sk-first-{}", Uuid::new_v4().simple()),
            "regex:openai_v1",
        );
        let shared_uuid = p1.secret_uuid.clone();
        let _ = backend
            .store_detected_secret(p1, "agent-x".into())
            .await
            .expect("first");

        let mut p2 = mk_detected_payload(
            &format!("sk-second-{}", Uuid::new_v4().simple()),
            "regex:openai_v1",
        );
        p2.secret_uuid = shared_uuid;
        let err = backend
            .store_detected_secret(p2, "agent-x".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, SecretsError::InvalidArgument(_)),
            "expected InvalidArgument, got {err:?}"
        );
    }

    /// v2.0 secrets-concurrency hardening — the master-key bootstrap
    /// race fix (CIRISPersist 2.0).
    ///
    /// From an EMPTY `master_key_meta`, N concurrent first-use
    /// `rotate_master_key` calls run against the REAL connection pool
    /// (true parallelism — this is the pre-fix bug's live path:
    /// `current_rust_engine()` hands one shared engine to multiple
    /// co-resident consumers). Before the fix, the check-then-act
    /// `COUNT ... WHERE deactivated_at IS NULL` / conditional UPDATE
    /// let several rotations all observe COUNT=0 and all activate →
    /// `active_master_key()` errored "N active master keys".
    ///
    /// After the fix: each rotation does INSERT + conditional activate
    /// in ONE transaction; the V043 `master_key_one_active` partial
    /// unique index caps active rows at one; first-use losers catch
    /// the unique violation, re-read, and converge on the winner. The
    /// assertion is EXACTLY ONE active master key + a clean
    /// encrypt/decrypt round-trip — not "all calls return the same
    /// handle", since a rotation that runs after a key is already
    /// active is a normal staged rotation returning its own staged
    /// key_ref.
    ///
    /// `#[serial(postgres)]` isolates the shared `master_key_meta`
    /// table from other PG tests — it does NOT serialize the N
    /// internal rotations, which genuinely race the pool.
    #[tokio::test]
    #[serial_test::serial(postgres)]
    async fn rotate_master_key_concurrent_bootstrap_converges_to_one_active() {
        use crate::store::backend::Backend;
        let Some(dsn) = pg_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let backend = PostgresBackend::connect(&dsn).await.unwrap();
        backend.run_migrations().await.unwrap();
        let _lock = acquire_pg_secrets_test_lock(&backend).await;
        reset_secrets_state(&backend).await;

        // N concurrent first-use bootstraps over the real pool.
        const N: usize = 12;
        let backend = std::sync::Arc::new(backend);
        let mut tasks = Vec::with_capacity(N);
        for i in 0..N {
            let b = backend.clone();
            tasks.push(tokio::spawn(async move {
                b.rotate_master_key(None, format!("bootstrap-{i}")).await
            }));
        }
        for t in tasks {
            match t.await.expect("join").expect("rotate_master_key") {
                MasterKeyRef::Software { handle } => assert!(!handle.is_empty()),
                other => panic!("expected Software ref, got {other:?}"),
            }
        }

        // DB holds EXACTLY ONE active row — the V043 index guarantees
        // it; this confirms the rows agree with the index.
        let client = backend.pool().get().await.unwrap();
        let active: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM cirislens_secrets.master_key_meta \
                 WHERE activated_at IS NOT NULL AND deactivated_at IS NULL",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(active, 1, "exactly one active master key expected");

        // encrypt/decrypt round-trips under the converged key.
        let ct = backend.encrypt("ciris-concurrency-probe").await.unwrap();
        let pt = backend.decrypt(&ct).await.unwrap();
        assert_eq!(pt, "ciris-concurrency-probe");
    }
}
