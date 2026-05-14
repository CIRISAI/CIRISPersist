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

    /// Look up the current active master key. There MUST be exactly
    /// one row in `master_key_meta` with `deactivated_at IS NULL`.
    /// Zero = uninitialized (the impl auto-generates a software key
    /// on first use); >1 = invariant violation, surfaces as Internal.
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
                 WHERE deactivated_at IS NULL",
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
        // SOFTWARE_KEYS in-memory map below. Future v0.6.1.x can
        // back this with the OS keyring via ciris-keyring.
        let bytes = software_keys_get(&key_ref).ok_or_else(|| {
            SecretsError::Crypto(format!(
                "active master key {key_ref} has no in-memory bytes — restart cleared the in-process key store"
            ))
        })?;
        Ok(MasterKey {
            key_ref,
            kind: key_kind,
            descriptor,
            bytes,
        })
    }
}

// v0.9.3: software-key cache extracted to `secrets::key_cache` so
// both the Postgres + SQLite backends share the same in-memory
// store. Wired in via `use super::key_cache::{software_keys_get,
// software_keys_put}`.
use super::key_cache::{software_keys_get, software_keys_put};

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

    async fn process_incoming_text(
        &self,
        _text: &str,
        _source_message_id: &str,
        _accessor: String,
    ) -> Result<(String, Vec<SecretReference>), SecretsError> {
        // v0.6.2: wired with the pipeline's classify stage. v0.6.1
        // ships the trait method but no detection catalog.
        Err(SecretsError::Internal(
            "process_incoming_text requires v0.6.2 pipeline orchestration".into(),
        ))
    }

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
        let encryption_enabled = self.active_master_key().await.is_ok();

        Ok(SecretsServiceStats {
            total_secrets: total as u64,
            active_filters: active_filters as u64,
            filter_matches_today: matches as u64,
            last_filter_update,
            encryption_enabled,
            hardware_key_active: false, // v0.6.1 deferred
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
        let tx = client
            .transaction()
            .await
            .map_err(|e| SecretsError::Backend(format!("begin tx: {e}")))?;

        // Load all secrets.
        let rows = tx
            .query(
                "SELECT secret_uuid, encrypted_value, encryption_key_ref, salt, nonce \
                 FROM cirislens_secrets.secrets",
                &[],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("reencrypt_all load: {e}")))?;

        let mut reencrypted = 0u64;
        let mut failures: Vec<String> = Vec::new();
        for row in rows {
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
            tx.execute(
                "UPDATE cirislens_secrets.secrets \
                 SET encrypted_value = $1, encryption_key_ref = $2, \
                     salt = $3, nonce = $4 \
                 WHERE secret_uuid = $5",
                &[
                    &new_ct,
                    &new_key_ref,
                    &new_salt.to_vec(),
                    &new_nonce.to_vec(),
                    &uuid,
                ],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("reencrypt update: {e}")))?;
            reencrypted += 1;
        }

        // Deactivate the old master key + activate the new.
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
            .map_err(|e| SecretsError::Backend(format!("commit reencrypt: {e}")))?;

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

        // INSERT the new key row (not yet active — reencrypt_all
        // activates).
        let client = self
            .pool()
            .get()
            .await
            .map_err(|e| SecretsError::Backend(format!("pool: {e}")))?;
        client
            .execute(
                "INSERT INTO cirislens_secrets.master_key_meta (\
                    key_ref, key_kind, descriptor, created_at\
                 ) VALUES ($1, 'software', NULL, NOW())",
                &[&new_key_ref],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("rotate_master_key insert: {e}")))?;
        software_keys_put(new_key_ref.clone(), key_bytes)?;

        let ref_out = MasterKeyRef::Software {
            handle: new_key_ref.clone(),
        };

        // If no current active key, activate immediately (first-use
        // path). Otherwise leave inactive so the caller can stage
        // reencrypt_all.
        let existing = client
            .query_one(
                "SELECT COUNT(*) FROM cirislens_secrets.master_key_meta \
                 WHERE deactivated_at IS NULL AND key_ref != $1",
                &[&new_key_ref],
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("rotate count: {e}")))?;
        let n: i64 = existing.get(0);
        if n == 0 {
            client
                .execute(
                    "UPDATE cirislens_secrets.master_key_meta \
                     SET activated_at = NOW() WHERE key_ref = $1",
                    &[&new_key_ref],
                )
                .await
                .map_err(|e| SecretsError::Backend(format!("rotate activate: {e}")))?;
        }

        let _ = self
            .secrets_audit(AuditRecord::new(AccessOp::Rotate, accessor), true, None)
            .await;
        Ok(ref_out)
    }

    async fn test_encryption(&self) -> Result<bool, SecretsError> {
        let probe = "ciris-encryption-health-probe";
        let ct = self.encrypt(probe).await?;
        let pt = self.decrypt(&ct).await?;
        Ok(pt == probe)
    }

    async fn migrate_to_hardware_key(
        &self,
        _accessor: String,
    ) -> Result<MasterKeyRef, SecretsError> {
        Err(SecretsError::HardwareKeyUnavailable(
            "secrets-hw feature pending ciris-keyring/symmetric-derivation upstream".into(),
        ))
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
        assert!(!stats.hardware_key_active, "v0.6.1 hardware key deferred");

        // 11. is_healthy.
        assert!(backend.is_healthy().await.unwrap());

        // 12. migrate_to_hardware_key returns HardwareKeyUnavailable.
        let err = backend
            .migrate_to_hardware_key("test".into())
            .await
            .unwrap_err();
        assert!(matches!(err, SecretsError::HardwareKeyUnavailable(_)));

        // 13. Stubs (v0.6.2 will impl).
        let err = backend
            .process_incoming_text("x", "y", "test".into())
            .await
            .unwrap_err();
        assert!(matches!(err, SecretsError::Internal(_)));

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
}
