// Five callsites with multi-tuple SELECT projections that lint hot
// under clippy 1.95's `type_complexity`. Pre-existing v0.9.3 shape;
// extracting type aliases is invasive across the closure boundaries
// (each query_row closure binds the tuple locally). Silenced module-
// wide for now; type-alias refactor tracked as cleanup work.
#![allow(clippy::type_complexity)]

//! SQLite impl of [`SecretsService`] (v0.9.3, CIRISPersist#39).
//!
//! Mirrors v0.6.1-α5 Postgres impl with SQLite-dialect translations:
//! BYTEA → BLOB for ciphertext / salt / nonce; JSONB → TEXT canonical
//! JSON for filter_config.config_value; TEXT[] →
//! TEXT (JSON-array string) for auto_decapsulate_for_actions;
//! TIMESTAMPTZ → RFC 3339 TEXT for created_at / last_accessed /
//! activated_at / deactivated_at; BIGSERIAL log_id → INTEGER PRIMARY
//! KEY AUTOINCREMENT. UUIDs ride as 36-char hyphenated TEXT.
//!
//! The crypto facade ([`super::crypto`]) is dialect-agnostic — every
//! call into it ports verbatim, byte-for-byte identically to the
//! Postgres backend. The software-key cache lives in
//! [`super::key_cache`] and is shared by both backends.
//!
//! # Per-call serialization under SQLite
//!
//! Postgres uses `SELECT … FOR UPDATE` to serialize concurrent
//! mutators within a single transaction. SQLite uses BEGIN IMMEDIATE
//! which acquires the database-level RESERVED lock immediately —
//! coarser than per-row locking but adequate for v0.9.3's
//! single-process / single-writer sovereign-mode deployments. The
//! `reencrypt_all` rotation is the only multi-statement transaction
//! and uses BEGIN IMMEDIATE accordingly.
//!
//! # Audit invariant
//!
//! Every method writes a row to `cirislens_secrets_access_log`
//! before returning (success OR failure). Same shape as the Postgres
//! impl; the `AuditRecord` builder is duplicated locally per FSD
//! §7.1's "audit-write is the load-bearing accountability surface"
//! discipline — the builder is independent of backend.

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::{DateTime, Utc};
use rusqlite::{params, params_from_iter, types::Value as SqlValue, Connection, OptionalExtension};
use tokio::sync::Mutex;
use uuid::Uuid;

use super::crypto;
use super::key_cache::{software_keys_get, software_keys_put};
use super::service::SecretsService;
use super::types::{
    AccessLogEntry, AccessOp, DecapsulationContext, FilterConfig, FilterUpdateRequest,
    FilterUpdateResult, MasterKeyRef, RotationResult, SecretRecallResult, SecretReference,
    SecretsListFilter, SecretsServiceStats,
};
use super::SecretsError;
use crate::pipeline::classify::Sensitivity;
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

/// Translate a rusqlite::Error into a SecretsError variant. By
/// convention constraint violations become `Conflict`-style backend
/// errors (we don't have a dedicated Conflict variant in
/// SecretsError — we surface as `Backend(_)` carrying the
/// constraint detail, matching Postgres impl behavior).
fn map_sqlite_error(e: rusqlite::Error, op: &str) -> SecretsError {
    SecretsError::Backend(format!("{op}: {e}"))
}

/// Parse an RFC 3339 TEXT timestamp (with or without 'T'). Mirrors
/// the helper in `audit/sqlite.rs` and `incident/sqlite.rs`.
fn parse_datetime(s: &str) -> Result<DateTime<Utc>, SecretsError> {
    let normalized = if s.contains('T') {
        s.to_owned()
    } else {
        format!("{}+00:00", s.replacen(' ', "T", 1))
    };
    DateTime::parse_from_rfc3339(&normalized)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| SecretsError::Backend(format!("datetime parse: {e} (raw={s})")))
}

/// Format a UTC DateTime as RFC 3339 with microsecond precision.
fn fmt_datetime(dt: DateTime<Utc>) -> String {
    dt.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
}

/// Parse the JSON-array TEXT representation of
/// auto_decapsulate_for_actions back into a Vec<String>. Empty array
/// is the default per V010.
fn parse_actions(s: &str) -> Result<Vec<String>, SecretsError> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<String>>(s).map_err(|e| {
        SecretsError::Backend(format!(
            "auto_decapsulate_for_actions JSON decode: {e} (raw={s})"
        ))
    })
}

/// Bookkeeping for one method call — composes the access_log row
/// that every impl must write before returning. Duplicated from the
/// Postgres impl; backend-independent.
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

/// In-memory bundle resolved from `cirislens_secrets_master_key_meta`.
struct MasterKey {
    key_ref: String,
    #[allow(dead_code)]
    kind: String,
    #[allow(dead_code)]
    descriptor: Option<String>,
    bytes: Vec<u8>,
}

// ─── backend ────────────────────────────────────────────────────────

/// SQLite-backed [`SecretsService`] impl. Wraps an
/// `Arc<Mutex<Connection>>` shared with
/// [`crate::store::sqlite::SqliteBackend`] so the secrets writes ride
/// the same WAL + PRAGMA settings as the trace-ingest path.
pub struct SqliteSecretsBackend {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteSecretsBackend {
    /// Construct from a shared connection handle (typically
    /// `SqliteBackend::conn_handle()`).
    pub fn new(conn: Arc<Mutex<Connection>>) -> Self {
        Self { conn }
    }

    /// INSERT one row into `cirislens_secrets_access_log`. Best-
    /// effort: if the audit-write itself fails, the caller's primary
    /// error is preserved. This helper is the only place that writes
    /// access_log so the discipline is auditable.
    async fn secrets_audit(
        &self,
        rec: AuditRecord,
        success: bool,
        error: Option<&str>,
    ) -> Result<(), SecretsError> {
        let conn = self.conn.clone();
        let secret_uuid_str = rec.secret_uuid.map(|u| u.to_string());
        let accessor = rec.accessor;
        let op = access_op_str(rec.operation).to_owned();
        let action_type = rec.action_type;
        let purpose = rec.purpose;
        let error = error.map(str::to_owned);
        let trace_id = rec.trace_id;
        let thought_id = rec.thought_id;
        let success_int: i64 = if success { 1 } else { 0 };
        tokio::task::spawn_blocking(move || -> Result<(), SecretsError> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO cirislens_secrets_access_log (\
                        secret_uuid, accessor, operation, action_type, purpose, \
                        success, error, trace_id, thought_id\
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                    params![
                        secret_uuid_str,
                        accessor,
                        op,
                        action_type,
                        purpose,
                        success_int,
                        error,
                        trace_id,
                        thought_id,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "access_log insert"))?;
            Ok(())
        })
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))?
    }

    /// Look up the current active master key. There MUST be at most
    /// one row in `master_key_meta` with `deactivated_at IS NULL`.
    /// Zero = uninitialized (caller invokes rotate_master_key first);
    /// >1 = invariant violation, surfaces as Internal.
    async fn active_master_key(&self) -> Result<MasterKey, SecretsError> {
        let conn = self.conn.clone();
        let (key_ref, key_kind, descriptor) = tokio::task::spawn_blocking(
            move || -> Result<(String, String, Option<String>), SecretsError> {
                let guard = conn.blocking_lock();
                let mut stmt = guard
                    .prepare(
                        "SELECT key_ref, key_kind, descriptor \
                         FROM cirislens_secrets_master_key_meta \
                         WHERE deactivated_at IS NULL \
                         ORDER BY activated_at IS NULL, activated_at DESC \
                         LIMIT 2",
                    )
                    .map_err(|e| map_sqlite_error(e, "active_master_key prepare"))?;
                let mut rows = stmt
                    .query([])
                    .map_err(|e| map_sqlite_error(e, "active_master_key query"))?;
                let first = rows
                    .next()
                    .map_err(|e| map_sqlite_error(e, "active_master_key next"))?;
                let row = match first {
                    None => {
                        return Err(SecretsError::Crypto(
                            "no active master key. Initialize via rotate_master_key first.".into(),
                        ));
                    }
                    Some(r) => r,
                };
                let key_ref: String = row
                    .get(0)
                    .map_err(|e| map_sqlite_error(e, "decode key_ref"))?;
                let key_kind: String = row
                    .get(1)
                    .map_err(|e| map_sqlite_error(e, "decode key_kind"))?;
                let descriptor: Option<String> = row
                    .get(2)
                    .map_err(|e| map_sqlite_error(e, "decode descriptor"))?;
                // Guard against >1 active rows.
                let second = rows
                    .next()
                    .map_err(|e| map_sqlite_error(e, "active_master_key next2"))?;
                if second.is_some() {
                    return Err(SecretsError::Internal(
                        "more than one active master key; expected exactly 1".into(),
                    ));
                }
                Ok((key_ref, key_kind, descriptor))
            },
        )
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;

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

// ─── SecretsService impl ────────────────────────────────────────────

impl SecretsService for SqliteSecretsBackend {
    async fn store_secret(
        &self,
        key: String,
        value: String,
        accessor: String,
    ) -> Result<(), SecretsError> {
        let secret_uuid = Uuid::new_v4();
        let master = self.active_master_key().await?;
        let salt = crypto::random_salt()?;
        let nonce = crypto::random_nonce()?;
        let secret_key = crypto::derive_secret_key(&master.bytes, &salt)?;
        let ciphertext = crypto::encrypt(&secret_key, &nonce, value.as_bytes())?;

        let conn = self.conn.clone();
        let secret_uuid_str = secret_uuid.to_string();
        let key_for_desc = key.clone();
        let key_ref = master.key_ref.clone();
        let salt_vec = salt.to_vec();
        let nonce_vec = nonce.to_vec();
        let result = tokio::task::spawn_blocking(move || -> Result<(), SecretsError> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO cirislens_secrets_secrets (\
                        secret_uuid, encrypted_value, encryption_key_ref, salt, nonce, \
                        description, sensitivity_level, detected_pattern \
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        secret_uuid_str,
                        ciphertext,
                        key_ref,
                        salt_vec,
                        nonce_vec,
                        key_for_desc,
                        "medium",
                        "manual",
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "store_secret"))?;
            Ok(())
        })
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))?;

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
        let conn = self.conn.clone();
        let key_owned = key.to_owned();
        let row_opt = tokio::task::spawn_blocking(
            move || -> Result<Option<(String, Vec<u8>, String, Vec<u8>, Vec<u8>)>, SecretsError> {
                let guard = conn.blocking_lock();
                guard
                    .query_row(
                        "SELECT secret_uuid, encrypted_value, encryption_key_ref, salt, nonce \
                         FROM cirislens_secrets_secrets \
                         WHERE description = ?1 \
                         ORDER BY created_at DESC LIMIT 1",
                        params![key_owned],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, Vec<u8>>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, Vec<u8>>(3)?,
                                row.get::<_, Vec<u8>>(4)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|e| map_sqlite_error(e, "retrieve_secret lookup"))
            },
        )
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;

        let (audit, plaintext) = match row_opt {
            None => (
                AuditRecord::new(AccessOp::Retrieve, &accessor).with_purpose(key),
                None,
            ),
            Some((uuid_str, ct, key_ref, salt, nonce)) => {
                let uuid = Uuid::parse_str(&uuid_str)
                    .map_err(|e| SecretsError::Internal(format!("uuid parse: {e}")))?;
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
        // Bump access_count when we returned plaintext.
        if plaintext.is_some() {
            if let Some(uuid) = audit.secret_uuid {
                let conn = self.conn.clone();
                let uuid_str = uuid.to_string();
                let now = fmt_datetime(Utc::now());
                let _ = tokio::task::spawn_blocking(move || -> Result<(), SecretsError> {
                    let guard = conn.blocking_lock();
                    guard
                        .execute(
                            "UPDATE cirislens_secrets_secrets \
                             SET last_accessed = ?1, access_count = access_count + 1 \
                             WHERE secret_uuid = ?2",
                            params![now, uuid_str],
                        )
                        .map_err(|e| map_sqlite_error(e, "retrieve bump access_count"))?;
                    Ok(())
                })
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
        let conn = self.conn.clone();
        let uuid_str = parsed_uuid.to_string();
        let row_opt = tokio::task::spawn_blocking(
            move || -> Result<Option<(Vec<u8>, String, Vec<u8>, Vec<u8>)>, SecretsError> {
                let guard = conn.blocking_lock();
                guard
                    .query_row(
                        "SELECT encrypted_value, encryption_key_ref, salt, nonce \
                         FROM cirislens_secrets_secrets \
                         WHERE secret_uuid = ?1",
                        params![uuid_str],
                        |row| {
                            Ok((
                                row.get::<_, Vec<u8>>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Vec<u8>>(2)?,
                                row.get::<_, Vec<u8>>(3)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|e| map_sqlite_error(e, "recall_secret lookup"))
            },
        )
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;

        let result = match row_opt {
            None => Some(SecretRecallResult {
                found: false,
                value: None,
                error: None,
            }),
            Some((ct, key_ref, salt, nonce)) => {
                if !decrypt {
                    Some(SecretRecallResult {
                        found: true,
                        value: None,
                        error: None,
                    })
                } else {
                    let master_bytes = software_keys_get(&key_ref).ok_or_else(|| {
                        SecretsError::Crypto(format!("master key {key_ref} unavailable in-process"))
                    })?;
                    let sk = crypto::derive_secret_key(&master_bytes, &salt)?;
                    match crypto::decrypt(&sk, &nonce, &ct) {
                        Ok(pt) => {
                            // Bump access_count.
                            let conn = self.conn.clone();
                            let uuid_str_inner = parsed_uuid.to_string();
                            let now = fmt_datetime(Utc::now());
                            let _ =
                                tokio::task::spawn_blocking(move || -> Result<(), SecretsError> {
                                    let guard = conn.blocking_lock();
                                    guard
                                        .execute(
                                            "UPDATE cirislens_secrets_secrets \
                                             SET last_accessed = ?1, \
                                                 access_count = access_count + 1 \
                                             WHERE secret_uuid = ?2",
                                            params![now, uuid_str_inner],
                                        )
                                        .map_err(|e| {
                                            map_sqlite_error(e, "recall bump access_count")
                                        })?;
                                    Ok(())
                                })
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

        let mut where_parts: Vec<String> = Vec::new();
        let mut params: Vec<SqlValue> = Vec::new();
        if let Some(s) = filter.sensitivity {
            params.push(SqlValue::Text(sensitivity_str(s).to_owned()));
            where_parts.push("sensitivity_level = ?".to_string());
        }
        if let Some(p) = filter.pattern {
            params.push(SqlValue::Text(p));
            where_parts.push("detected_pattern = ?".to_string());
        }
        if let Some(m) = filter.source_message_id {
            params.push(SqlValue::Text(m));
            where_parts.push("source_message_id = ?".to_string());
        }
        if let Some(t) = filter.created_after {
            params.push(SqlValue::Text(fmt_datetime(t)));
            where_parts.push("created_at >= ?".to_string());
        }
        if let Some(t) = filter.created_before {
            params.push(SqlValue::Text(fmt_datetime(t)));
            where_parts.push("created_at < ?".to_string());
        }
        let where_sql = if where_parts.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_parts.join(" AND "))
        };
        params.push(SqlValue::Integer(lim));
        let sql = format!(
            "SELECT secret_uuid, description, context_hint, sensitivity_level, \
                    detected_pattern, auto_decapsulate_for_actions, created_at, last_accessed \
             FROM cirislens_secrets_secrets \
             {where_sql} \
             ORDER BY created_at DESC \
             LIMIT ?"
        );

        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<SecretReference>, SecretsError> {
            let guard = conn.blocking_lock();
            let mut stmt = guard
                .prepare(&sql)
                .map_err(|e| map_sqlite_error(e, "list_stored_secrets prepare"))?;
            let rows_iter = stmt
                .query_map(params_from_iter(params.iter()), |row| {
                    let sensitivity_str_v: String = row.get(3)?;
                    let actions_str: String = row.get(5)?;
                    let created_at_str: String = row.get(6)?;
                    let last_accessed_opt: Option<String> = row.get(7)?;
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        sensitivity_str_v,
                        row.get::<_, String>(4)?,
                        actions_str,
                        created_at_str,
                        last_accessed_opt,
                    ))
                })
                .map_err(|e| map_sqlite_error(e, "list_stored_secrets query"))?;
            let mut out: Vec<SecretReference> = Vec::new();
            for r in rows_iter {
                let (
                    uuid,
                    description,
                    context_hint,
                    sensitivity_str_v,
                    detected_pattern,
                    actions_str,
                    created_at_str,
                    last_accessed_str,
                ) = r.map_err(|e| map_sqlite_error(e, "list_stored_secrets row"))?;
                let sensitivity = sensitivity_from_str(&sensitivity_str_v)?;
                let auto_decapsulate_actions = parse_actions(&actions_str)?;
                let created_at = parse_datetime(&created_at_str)?;
                let last_accessed = match last_accessed_str {
                    Some(s) => Some(parse_datetime(&s)?),
                    None => None,
                };
                out.push(SecretReference {
                    uuid,
                    description,
                    context_hint,
                    sensitivity,
                    detected_pattern,
                    auto_decapsulate_actions,
                    created_at,
                    last_accessed,
                });
            }
            Ok(out)
        })
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))?
    }

    async fn forget_secret(&self, uuid: &str, accessor: String) -> Result<bool, SecretsError> {
        let parsed_uuid = Uuid::parse_str(uuid)
            .map_err(|e| SecretsError::InvalidArgument(format!("uuid parse: {e}")))?;
        let conn = self.conn.clone();
        let uuid_str = parsed_uuid.to_string();
        let n = tokio::task::spawn_blocking(move || -> Result<usize, SecretsError> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "DELETE FROM cirislens_secrets_secrets WHERE secret_uuid = ?1",
                    params![uuid_str],
                )
                .map_err(|e| map_sqlite_error(e, "forget_secret"))
        })
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;

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
    // Both primitives are SQLite-implemented; the default suffices.

    async fn decapsulate_secrets_in_parameters(
        &self,
        _action_type: &str,
        _action_params: serde_json::Value,
        _ctx: DecapsulationContext,
    ) -> Result<serde_json::Value, SecretsError> {
        Err(SecretsError::Internal(
            "v0.9.3 SQLite: pipeline orchestration deferred to v0.9.x.y; matches postgres.rs v0.6.1-α5 stub behavior".into(),
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
        let conn = self.conn.clone();
        let row_opt = tokio::task::spawn_blocking(
            move || -> Result<Option<(String, String, i32, String, String)>, SecretsError> {
                let guard = conn.blocking_lock();
                guard
                    .query_row(
                        "SELECT config_id, config_value, version, updated_at, updated_by \
                         FROM cirislens_secrets_filter_config WHERE config_id = 'global'",
                        [],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, i32>(2)?,
                                row.get::<_, String>(3)?,
                                row.get::<_, String>(4)?,
                            ))
                        },
                    )
                    .optional()
                    .map_err(|e| map_sqlite_error(e, "get_filter_config"))
            },
        )
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;
        match row_opt {
            None => Ok(FilterConfig {
                config_id: "global".into(),
                config_value: serde_json::json!({}),
                version: 0,
                updated_at: Utc::now(),
                updated_by: "default".into(),
            }),
            Some((config_id, config_value_str, version, updated_at_str, updated_by)) => {
                let config_value: serde_json::Value = serde_json::from_str(&config_value_str)
                    .map_err(|e| {
                        SecretsError::Backend(format!(
                            "config_value JSON decode: {e} (raw={config_value_str})"
                        ))
                    })?;
                let updated_at = parse_datetime(&updated_at_str)?;
                Ok(FilterConfig {
                    config_id,
                    config_value,
                    version,
                    updated_at,
                    updated_by,
                })
            }
        }
    }

    async fn update_filter_config(
        &self,
        updates: FilterUpdateRequest,
        accessor: String,
    ) -> Result<FilterUpdateResult, SecretsError> {
        let config_value_str = serde_json::to_string(&updates.new_config)
            .map_err(|e| SecretsError::Internal(format!("config_value serialize: {e}")))?;
        let now = fmt_datetime(Utc::now());

        let conn = self.conn.clone();
        let config_id = updates.config_id.clone();
        let (new_version, updated_at_str) =
            tokio::task::spawn_blocking(move || -> Result<(i32, String), SecretsError> {
                let guard = conn.blocking_lock();
                guard
                    .query_row(
                        "INSERT INTO cirislens_secrets_filter_config (\
                            config_id, config_value, version, updated_at, updated_by\
                         ) VALUES (?1, ?2, 1, ?3, ?4) \
                         ON CONFLICT (config_id) DO UPDATE \
                         SET config_value = excluded.config_value, \
                             version = cirislens_secrets_filter_config.version + 1, \
                             updated_at = excluded.updated_at, \
                             updated_by = excluded.updated_by \
                         RETURNING version, updated_at",
                        params![config_id, config_value_str, now, accessor],
                        |row| Ok((row.get::<_, i32>(0)?, row.get::<_, String>(1)?)),
                    )
                    .map_err(|e| map_sqlite_error(e, "update_filter_config"))
            })
            .await
            .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;
        let updated_at = parse_datetime(&updated_at_str)?;
        Ok(FilterUpdateResult {
            new_version,
            updated_at,
        })
    }

    async fn get_service_stats(&self) -> Result<SecretsServiceStats, SecretsError> {
        let conn = self.conn.clone();
        let (total, active_filters, matches, last_filter_update, last_rotation, rotation_count) =
            tokio::task::spawn_blocking(
                move || -> Result<
                    (
                        i64,
                        i64,
                        i64,
                        Option<String>,
                        Option<String>,
                        i64,
                    ),
                    SecretsError,
                > {
                    let guard = conn.blocking_lock();
                    let total: i64 = guard
                        .query_row(
                            "SELECT COUNT(*) FROM cirislens_secrets_secrets",
                            [],
                            |row| row.get(0),
                        )
                        .map_err(|e| map_sqlite_error(e, "stats total_secrets"))?;
                    let active_filters: i64 = guard
                        .query_row(
                            "SELECT COUNT(*) FROM cirislens_secrets_filter_config \
                             WHERE config_value != '{}'",
                            [],
                            |row| row.get(0),
                        )
                        .map_err(|e| map_sqlite_error(e, "stats active_filters"))?;
                    let matches: i64 = guard
                        .query_row(
                            "SELECT COUNT(*) FROM cirislens_secrets_access_log \
                             WHERE created_at >= datetime('now', '-24 hours') \
                               AND operation IN ('store','recall')",
                            [],
                            |row| row.get(0),
                        )
                        .map_err(|e| map_sqlite_error(e, "stats matches"))?;
                    let last_filter_update: Option<String> = guard
                        .query_row(
                            "SELECT MAX(updated_at) FROM cirislens_secrets_filter_config",
                            [],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(|e| map_sqlite_error(e, "stats last_filter_update"))?
                        .flatten();
                    let last_rotation: Option<String> = guard
                        .query_row(
                            "SELECT MAX(activated_at) FROM cirislens_secrets_master_key_meta \
                             WHERE deactivated_at IS NOT NULL",
                            [],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(|e| map_sqlite_error(e, "stats last_rotation"))?
                        .flatten();
                    let rotation_count: i64 = guard
                        .query_row(
                            "SELECT COUNT(*) FROM cirislens_secrets_master_key_meta \
                             WHERE deactivated_at IS NOT NULL",
                            [],
                            |row| row.get(0),
                        )
                        .map_err(|e| map_sqlite_error(e, "stats rotation_count"))?;
                    Ok((
                        total,
                        active_filters,
                        matches,
                        last_filter_update,
                        last_rotation,
                        rotation_count,
                    ))
                },
            )
            .await
            .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;

        let last_filter_update = match last_filter_update {
            Some(s) => Some(parse_datetime(&s)?),
            None => None,
        };
        let last_rotation = match last_rotation {
            Some(s) => Some(parse_datetime(&s)?),
            None => None,
        };

        // Encryption health: try active_master_key — Ok = enabled.
        let encryption_enabled = self.active_master_key().await.is_ok();

        Ok(SecretsServiceStats {
            total_secrets: total as u64,
            active_filters: active_filters as u64,
            filter_matches_today: matches as u64,
            last_filter_update,
            encryption_enabled,
            hardware_key_active: false, // v0.9.3 deferred (same as v0.6.1 PG)
            last_rotation,
            rotation_count: rotation_count as u64,
        })
    }

    async fn is_healthy(&self) -> Result<bool, SecretsError> {
        // Quick connectivity probe + active-key check.
        let conn = self.conn.clone();
        let probed = tokio::task::spawn_blocking(move || -> Result<(), SecretsError> {
            let guard = conn.blocking_lock();
            guard
                .query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                .map_err(|e| map_sqlite_error(e, "is_healthy probe"))?;
            Ok(())
        })
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))?;
        probed?;
        Ok(self.active_master_key().await.is_ok())
    }

    async fn get_access_logs(
        &self,
        secret_uuid: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AccessLogEntry>, SecretsError> {
        let lim = i64::try_from(limit.min(10_000)).unwrap_or(1000);
        let secret_uuid_str = match secret_uuid {
            Some(u) => Some(
                Uuid::parse_str(u)
                    .map_err(|e| SecretsError::InvalidArgument(format!("uuid parse: {e}")))?
                    .to_string(),
            ),
            None => None,
        };
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> Result<Vec<AccessLogEntry>, SecretsError> {
            let guard = conn.blocking_lock();
            let mut rows_out: Vec<AccessLogEntry> = Vec::new();
            if let Some(uuid_filter) = secret_uuid_str {
                let mut stmt = guard
                    .prepare(
                        "SELECT log_id, secret_uuid, accessor, operation, action_type, \
                                purpose, success, error, trace_id, thought_id, created_at \
                         FROM cirislens_secrets_access_log \
                         WHERE secret_uuid = ?1 \
                         ORDER BY log_id DESC LIMIT ?2",
                    )
                    .map_err(|e| map_sqlite_error(e, "get_access_logs prepare (uuid)"))?;
                let iter = stmt
                    .query_map(params![uuid_filter, lim], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, Option<String>>(7)?,
                            row.get::<_, Option<String>>(8)?,
                            row.get::<_, Option<String>>(9)?,
                            row.get::<_, String>(10)?,
                        ))
                    })
                    .map_err(|e| map_sqlite_error(e, "get_access_logs query (uuid)"))?;
                for r in iter {
                    let (
                        log_id,
                        secret_uuid,
                        accessor,
                        op_str,
                        action_type,
                        purpose,
                        success_int,
                        error,
                        trace_id,
                        thought_id,
                        created_at_str,
                    ) = r.map_err(|e| map_sqlite_error(e, "get_access_logs row (uuid)"))?;
                    rows_out.push(AccessLogEntry {
                        log_id,
                        secret_uuid,
                        accessor,
                        operation: access_op_from_str(&op_str)?,
                        action_type,
                        purpose,
                        success: success_int != 0,
                        error,
                        trace_id,
                        thought_id,
                        created_at: parse_datetime(&created_at_str)?,
                    });
                }
            } else {
                let mut stmt = guard
                    .prepare(
                        "SELECT log_id, secret_uuid, accessor, operation, action_type, \
                                purpose, success, error, trace_id, thought_id, created_at \
                         FROM cirislens_secrets_access_log \
                         ORDER BY log_id DESC LIMIT ?1",
                    )
                    .map_err(|e| map_sqlite_error(e, "get_access_logs prepare"))?;
                let iter = stmt
                    .query_map(params![lim], |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, Option<String>>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, i64>(6)?,
                            row.get::<_, Option<String>>(7)?,
                            row.get::<_, Option<String>>(8)?,
                            row.get::<_, Option<String>>(9)?,
                            row.get::<_, String>(10)?,
                        ))
                    })
                    .map_err(|e| map_sqlite_error(e, "get_access_logs query"))?;
                for r in iter {
                    let (
                        log_id,
                        secret_uuid,
                        accessor,
                        op_str,
                        action_type,
                        purpose,
                        success_int,
                        error,
                        trace_id,
                        thought_id,
                        created_at_str,
                    ) = r.map_err(|e| map_sqlite_error(e, "get_access_logs row"))?;
                    rows_out.push(AccessLogEntry {
                        log_id,
                        secret_uuid,
                        accessor,
                        operation: access_op_from_str(&op_str)?,
                        action_type,
                        purpose,
                        success: success_int != 0,
                        error,
                        trace_id,
                        thought_id,
                        created_at: parse_datetime(&created_at_str)?,
                    });
                }
            }
            Ok(rows_out)
        })
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))?
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

        let conn = self.conn.clone();
        let new_key_ref_for_tx = new_key_ref.clone();
        let now_for_tx = fmt_datetime(Utc::now());
        let (reencrypted, failures) =
            tokio::task::spawn_blocking(move || -> Result<(u64, Vec<String>), SecretsError> {
                let mut guard = conn.blocking_lock();
                let tx = guard
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .map_err(|e| map_sqlite_error(e, "reencrypt_all begin tx"))?;

                // Load all rows up front (we then mutate inside the
                // same tx — rusqlite doesn't allow active statements
                // and mutating prepared statements to coexist).
                let rows: Vec<(String, Vec<u8>, String, Vec<u8>, Vec<u8>)> = {
                    let mut stmt = tx
                        .prepare(
                            "SELECT secret_uuid, encrypted_value, encryption_key_ref, \
                                    salt, nonce \
                             FROM cirislens_secrets_secrets",
                        )
                        .map_err(|e| map_sqlite_error(e, "reencrypt_all prepare load"))?;
                    let iter = stmt
                        .query_map([], |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, Vec<u8>>(1)?,
                                row.get::<_, String>(2)?,
                                row.get::<_, Vec<u8>>(3)?,
                                row.get::<_, Vec<u8>>(4)?,
                            ))
                        })
                        .map_err(|e| map_sqlite_error(e, "reencrypt_all query load"))?;
                    let mut acc = Vec::new();
                    for r in iter {
                        acc.push(r.map_err(|e| map_sqlite_error(e, "reencrypt_all row"))?);
                    }
                    acc
                };

                let mut reencrypted: u64 = 0;
                let mut failures: Vec<String> = Vec::new();
                for (uuid_str, ct, old_key_ref, old_salt, old_nonce) in rows {
                    let old_bytes = match software_keys_get(&old_key_ref) {
                        Some(b) => b,
                        None => {
                            failures.push(uuid_str);
                            continue;
                        }
                    };
                    let old_sk = match crypto::derive_secret_key(&old_bytes, &old_salt) {
                        Ok(k) => k,
                        Err(_) => {
                            failures.push(uuid_str);
                            continue;
                        }
                    };
                    let plaintext = match crypto::decrypt(&old_sk, &old_nonce, &ct) {
                        Ok(p) => p,
                        Err(_) => {
                            failures.push(uuid_str);
                            continue;
                        }
                    };
                    let new_salt = crypto::random_salt()?;
                    let new_nonce = crypto::random_nonce()?;
                    let new_sk = crypto::derive_secret_key(&new_master_bytes, &new_salt)?;
                    let new_ct = crypto::encrypt(&new_sk, &new_nonce, &plaintext)?;
                    tx.execute(
                        "UPDATE cirislens_secrets_secrets \
                         SET encrypted_value = ?1, encryption_key_ref = ?2, \
                             salt = ?3, nonce = ?4 \
                         WHERE secret_uuid = ?5",
                        params![
                            new_ct,
                            new_key_ref_for_tx,
                            new_salt.to_vec(),
                            new_nonce.to_vec(),
                            uuid_str,
                        ],
                    )
                    .map_err(|e| map_sqlite_error(e, "reencrypt update"))?;
                    reencrypted += 1;
                }

                // Deactivate the old master key + activate the new.
                tx.execute(
                    "UPDATE cirislens_secrets_master_key_meta \
                     SET deactivated_at = ?1, rotated_to = ?2 \
                     WHERE deactivated_at IS NULL AND key_ref != ?2",
                    params![now_for_tx, new_key_ref_for_tx],
                )
                .map_err(|e| map_sqlite_error(e, "deactivate old key"))?;
                tx.execute(
                    "UPDATE cirislens_secrets_master_key_meta \
                     SET activated_at = COALESCE(activated_at, ?1) \
                     WHERE key_ref = ?2",
                    params![now_for_tx, new_key_ref_for_tx],
                )
                .map_err(|e| map_sqlite_error(e, "activate new key"))?;

                tx.commit()
                    .map_err(|e| map_sqlite_error(e, "commit reencrypt"))?;
                Ok((reencrypted, failures))
            })
            .await
            .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;

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

        let conn = self.conn.clone();
        let new_key_ref_for_db = new_key_ref.clone();
        let now = fmt_datetime(Utc::now());
        let now_clone = now.clone();
        tokio::task::spawn_blocking(move || -> Result<(), SecretsError> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO cirislens_secrets_master_key_meta (\
                        key_ref, key_kind, descriptor, created_at\
                     ) VALUES (?1, 'software', NULL, ?2)",
                    params![new_key_ref_for_db, now_clone],
                )
                .map_err(|e| map_sqlite_error(e, "rotate_master_key insert"))?;
            Ok(())
        })
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;
        software_keys_put(new_key_ref.clone(), key_bytes)?;

        let ref_out = MasterKeyRef::Software {
            handle: new_key_ref.clone(),
        };

        // If no current active key, activate immediately (first-use
        // path). Otherwise leave inactive so the caller can stage
        // reencrypt_all.
        let conn2 = self.conn.clone();
        let new_key_ref_check = new_key_ref.clone();
        let now_for_activate = now.clone();
        tokio::task::spawn_blocking(move || -> Result<(), SecretsError> {
            let guard = conn2.blocking_lock();
            let n: i64 = guard
                .query_row(
                    "SELECT COUNT(*) FROM cirislens_secrets_master_key_meta \
                     WHERE deactivated_at IS NULL AND key_ref != ?1",
                    params![new_key_ref_check],
                    |row| row.get(0),
                )
                .map_err(|e| map_sqlite_error(e, "rotate count"))?;
            if n == 0 {
                guard
                    .execute(
                        "UPDATE cirislens_secrets_master_key_meta \
                         SET activated_at = ?1 WHERE key_ref = ?2",
                        params![now_for_activate, new_key_ref_check],
                    )
                    .map_err(|e| map_sqlite_error(e, "rotate activate"))?;
            }
            Ok(())
        })
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;

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
        let conn = self.conn.clone();
        let new_key_ref_for_db = new_key_ref.clone();
        let descriptor_for_db = descriptor.clone();
        let now = fmt_datetime(Utc::now());
        // Record the new key as `hardware`, not yet active —
        // `reencrypt_all` activates it once every secret is
        // re-encrypted (same staging as `rotate_master_key`).
        tokio::task::spawn_blocking(move || -> Result<(), SecretsError> {
            let guard = conn.blocking_lock();
            guard
                .execute(
                    "INSERT INTO cirislens_secrets_master_key_meta (\
                        key_ref, key_kind, descriptor, created_at\
                     ) VALUES (?1, 'hardware', ?2, ?3)",
                    params![new_key_ref_for_db, descriptor_for_db, now],
                )
                .map_err(|e| map_sqlite_error(e, "migrate_to_hardware_key insert"))?;
            Ok(())
        })
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;
        software_keys_put(new_key_ref.clone(), master)?;

        let ref_out = MasterKeyRef::Hardware {
            key_id: new_key_ref,
            descriptor,
        };
        // Re-encrypt every secret under the hardware master key and
        // flip the active key. `reencrypt_all` audits the pass.
        self.reencrypt_all(ref_out.clone(), accessor).await?;
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
        // Dedup key (FSD §7.5a — facade routing).
        let master = self.active_master_key().await?;
        let content_hmac = crypto::hmac_sha256(&master.bytes, plaintext.as_bytes()).to_vec();

        // Fresh per-attempt crypto state. salt + nonce stay unique
        // per call; only content_hmac collides on race.
        let secret_uuid = Uuid::new_v4();
        let salt = crypto::random_salt()?;
        let nonce = crypto::random_nonce()?;
        let secret_key = crypto::derive_secret_key(&master.bytes, &salt)?;
        let ciphertext = crypto::encrypt(&secret_key, &nonce, plaintext.as_bytes())?;
        let sensitivity_tag = sensitivity_str(sensitivity).to_owned();
        let actions_json = serde_json::to_string(&auto_decapsulate_for_actions)
            .map_err(|e| SecretsError::Internal(format!("actions serialize: {e}")))?;

        let conn = self.conn.clone();
        let secret_uuid_str = secret_uuid.to_string();
        let key_ref = master.key_ref.clone();
        let salt_vec = salt.to_vec();
        let nonce_vec = nonce.to_vec();
        let description_owned = description.to_owned();
        let content_hmac_for_tx = content_hmac.clone();

        // Atomic claim: INSERT OR IGNORE — SQLite suppresses the
        // INSERT on UNIQUE conflict and reports 0 changes. The
        // follow-up SELECT fetches the existing row (whether ours
        // or another caller's) by content_hmac.
        type ClaimRow = (
            String,
            String,
            Option<String>,
            String,
            String,
            String,
            String,
            Option<String>,
        );
        let (won, row): (bool, ClaimRow) =
            tokio::task::spawn_blocking(move || -> Result<(bool, ClaimRow), SecretsError> {
                let guard = conn.blocking_lock();
                let changed = guard
                    .execute(
                        "INSERT OR IGNORE INTO cirislens_secrets_secrets (\
                            secret_uuid, encrypted_value, encryption_key_ref, salt, nonce, \
                            description, sensitivity_level, detected_pattern, \
                            auto_decapsulate_for_actions, content_hmac \
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                        params![
                            secret_uuid_str,
                            ciphertext,
                            key_ref,
                            salt_vec,
                            nonce_vec,
                            description_owned,
                            sensitivity_tag,
                            "manual",
                            actions_json,
                            content_hmac_for_tx,
                        ],
                    )
                    .map_err(|e| map_sqlite_error(e, "try_claim_secret insert"))?;
                let won = changed > 0;
                let row = guard
                    .query_row(
                        "SELECT secret_uuid, description, context_hint, sensitivity_level, \
                                detected_pattern, auto_decapsulate_for_actions, \
                                created_at, last_accessed \
                         FROM cirislens_secrets_secrets \
                         WHERE content_hmac = ?1",
                        params![content_hmac_for_tx],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<String>>(2)?,
                                row.get::<_, String>(3)?,
                                row.get::<_, String>(4)?,
                                row.get::<_, String>(5)?,
                                row.get::<_, String>(6)?,
                                row.get::<_, Option<String>>(7)?,
                            ))
                        },
                    )
                    .map_err(|e| map_sqlite_error(e, "try_claim_secret conflict-recovery"))?;
                Ok((won, row))
            })
            .await
            .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;

        let (uuid_str, desc, ctx_hint, sens_str, pattern, actions_str, created_str, accessed_str) =
            row;
        let last_accessed = match accessed_str {
            Some(s) => Some(parse_datetime(&s)?),
            None => None,
        };
        let reference = SecretReference {
            uuid: uuid_str.clone(),
            description: desc,
            context_hint: ctx_hint,
            sensitivity: sensitivity_from_str(&sens_str)?,
            detected_pattern: pattern,
            auto_decapsulate_actions: parse_actions(&actions_str)?,
            created_at: parse_datetime(&created_str)?,
            last_accessed,
        };
        let row_uuid = Uuid::parse_str(&uuid_str)
            .map_err(|e| SecretsError::Internal(format!("uuid parse: {e}")))?;

        let outcome = if won {
            ClaimResult::Stored(reference.clone())
        } else {
            ClaimResult::AlreadyClaimed(reference.clone())
        };

        let purpose = if won {
            format!("try_claim_secret stored: {description}")
        } else {
            format!("try_claim_secret already_claimed: {description}")
        };
        let _ = self
            .secrets_audit(
                AuditRecord::new(AccessOp::Store, &accessor)
                    .with_secret(row_uuid)
                    .with_purpose(purpose),
                true,
                None,
            )
            .await;

        Ok(outcome)
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
        let actions_json = serde_json::to_string(&payload.auto_decapsulate_for_actions)
            .map_err(|e| SecretsError::Internal(format!("actions serialize: {e}")))?;

        let conn = self.conn.clone();
        let secret_uuid_str = agent_uuid.to_string();
        let key_ref = master.key_ref.clone();
        let salt_vec = salt.to_vec();
        let nonce_vec = nonce.to_vec();
        let description_owned = payload.description.clone();
        let detected_pattern_owned = payload.detected_pattern.clone();
        let context_hint_owned = payload.context_hint.clone();
        let source_message_id_owned = payload.source_message_id.clone();
        let manual_access_only_int: i64 = if payload.manual_access_only { 1 } else { 0 };
        let content_hmac_for_tx = content_hmac.clone();

        // Three possible outcomes:
        //   inserted=1 (won), uuid==caller's      → Stored
        //   inserted=0, existing row by content   → AlreadyClaimed
        //   inserted=0 + no existing by content   → UUID PK conflict
        //                                            (caller bug)
        type ClaimRow = (
            String,
            String,
            Option<String>,
            String,
            String,
            String,
            String,
            Option<String>,
        );
        enum Outcome {
            Stored(ClaimRow),
            AlreadyClaimed(ClaimRow),
            UuidConflict,
        }
        let outcome_enum = tokio::task::spawn_blocking(move || -> Result<Outcome, SecretsError> {
            let guard = conn.blocking_lock();
            let changed = guard
                .execute(
                    "INSERT OR IGNORE INTO cirislens_secrets_secrets (\
                        secret_uuid, encrypted_value, encryption_key_ref, salt, nonce, \
                        description, sensitivity_level, detected_pattern, context_hint, \
                        source_message_id, auto_decapsulate_for_actions, manual_access_only, \
                        content_hmac \
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                    params![
                        secret_uuid_str,
                        ciphertext,
                        key_ref,
                        salt_vec,
                        nonce_vec,
                        description_owned,
                        sensitivity_tag,
                        detected_pattern_owned,
                        context_hint_owned,
                        source_message_id_owned,
                        actions_json,
                        manual_access_only_int,
                        content_hmac_for_tx,
                    ],
                )
                .map_err(|e| map_sqlite_error(e, "store_detected_secret insert"))?;
            if changed > 0 {
                // Won — re-read our row for the canonical reference.
                let row = guard
                    .query_row(
                        "SELECT secret_uuid, description, context_hint, sensitivity_level, \
                                detected_pattern, auto_decapsulate_for_actions, \
                                created_at, last_accessed \
                         FROM cirislens_secrets_secrets WHERE secret_uuid = ?1",
                        params![secret_uuid_str],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<String>>(2)?,
                                row.get::<_, String>(3)?,
                                row.get::<_, String>(4)?,
                                row.get::<_, String>(5)?,
                                row.get::<_, String>(6)?,
                                row.get::<_, Option<String>>(7)?,
                            ))
                        },
                    )
                    .map_err(|e| map_sqlite_error(e, "store_detected_secret readback"))?;
                return Ok(Outcome::Stored(row));
            }
            // INSERT OR IGNORE failed silently — could be content_hmac
            // collision (same plaintext under any caller path) or
            // secret_uuid PK collision (caller reuse with a *different*
            // plaintext). Look up by content_hmac first.
            let by_hmac: Option<ClaimRow> = guard
                .query_row(
                    "SELECT secret_uuid, description, context_hint, sensitivity_level, \
                            detected_pattern, auto_decapsulate_for_actions, \
                            created_at, last_accessed \
                     FROM cirislens_secrets_secrets WHERE content_hmac = ?1",
                    params![content_hmac_for_tx],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, String>(4)?,
                            row.get::<_, String>(5)?,
                            row.get::<_, String>(6)?,
                            row.get::<_, Option<String>>(7)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| map_sqlite_error(e, "store_detected_secret conflict-recovery"))?;
            match by_hmac {
                Some(row) => Ok(Outcome::AlreadyClaimed(row)),
                None => Ok(Outcome::UuidConflict),
            }
        })
        .await
        .map_err(|e| SecretsError::Backend(format!("spawn_blocking join: {e}")))??;

        let (result, audit_uuid) = match outcome_enum {
            Outcome::Stored(row) => {
                let (
                    uuid_str,
                    desc,
                    ctx_hint,
                    sens_str,
                    pattern,
                    actions_str,
                    created_str,
                    accessed_str,
                ) = row;
                let last_accessed = match accessed_str {
                    Some(s) => Some(parse_datetime(&s)?),
                    None => None,
                };
                let reference = SecretReference {
                    uuid: uuid_str,
                    description: desc,
                    context_hint: ctx_hint,
                    sensitivity: sensitivity_from_str(&sens_str)?,
                    detected_pattern: pattern,
                    auto_decapsulate_actions: parse_actions(&actions_str)?,
                    created_at: parse_datetime(&created_str)?,
                    last_accessed,
                };
                (Ok(ClaimResult::Stored(reference)), Some(agent_uuid))
            }
            Outcome::AlreadyClaimed(row) => {
                let (
                    uuid_str,
                    desc,
                    ctx_hint,
                    sens_str,
                    pattern,
                    actions_str,
                    created_str,
                    accessed_str,
                ) = row;
                let last_accessed = match accessed_str {
                    Some(s) => Some(parse_datetime(&s)?),
                    None => None,
                };
                let reference = SecretReference {
                    uuid: uuid_str.clone(),
                    description: desc,
                    context_hint: ctx_hint,
                    sensitivity: sensitivity_from_str(&sens_str)?,
                    detected_pattern: pattern,
                    auto_decapsulate_actions: parse_actions(&actions_str)?,
                    created_at: parse_datetime(&created_str)?,
                    last_accessed,
                };
                let existing_uuid = Uuid::parse_str(&uuid_str)
                    .map_err(|e| SecretsError::Internal(format!("uuid parse: {e}")))?;
                (
                    Ok(ClaimResult::AlreadyClaimed(reference)),
                    Some(existing_uuid),
                )
            }
            Outcome::UuidConflict => (
                Err(SecretsError::InvalidArgument(format!(
                    "secret_uuid {} already in use for a different plaintext",
                    payload.secret_uuid
                ))),
                Some(agent_uuid),
            ),
        };

        // Audit row.
        let (success, err_msg, purpose) = match &result {
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

        result
    }
}

#[cfg(test)]
#[allow(missing_docs)]
mod tests {
    use super::*;
    use crate::store::sqlite::SqliteBackend;
    use crate::store::Backend;

    async fn fresh_backend() -> (SqliteBackend, SqliteSecretsBackend) {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let secrets = SqliteSecretsBackend::new(backend.conn_handle());
        (backend, secrets)
    }

    /// v0.9.3 SQLite parity: same lifecycle as the v0.6.1-α5 Postgres
    /// secrets test, run against in-memory SQLite. Covers
    /// rotate_master_key → encrypt → decrypt → store → retrieve →
    /// list → recall → forget + access-log readback +
    /// filter_config CRUD + is_healthy + the deferred-stub
    /// behavior of process_incoming_text /
    /// decapsulate_secrets_in_parameters / migrate_to_hardware_key.
    #[tokio::test]
    async fn secrets_sqlite_round_trip_full_lifecycle() {
        let (_b, secrets) = fresh_backend().await;

        // 1. rotate_master_key generates the first software key.
        let key_ref = secrets
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
        let ct = secrets
            .encrypt("ciris-test-payload")
            .await
            .expect("encrypt");
        let pt = secrets.decrypt(&ct).await.expect("decrypt");
        assert_eq!(pt, "ciris-test-payload");

        // 3. test_encryption helper.
        assert!(
            secrets.test_encryption().await.unwrap(),
            "test_encryption should pass"
        );

        // 4. Manual-keyed store + retrieve.
        let manual_key = format!("manual-secret-{}", Uuid::new_v4());
        secrets
            .store_secret(manual_key.clone(), "value-123".into(), "test".into())
            .await
            .expect("store_secret");
        let got = secrets
            .retrieve_secret(&manual_key, "test".into())
            .await
            .expect("retrieve_secret");
        assert_eq!(got, Some("value-123".into()));

        // 5. List + filter.
        let listed = secrets
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
        let recalled = secrets
            .recall_secret(&our_uuid, "test recall".into(), "test".into(), true)
            .await
            .expect("recall_secret")
            .expect("found");
        assert!(recalled.found);
        assert_eq!(recalled.value.as_deref(), Some("value-123"));

        // 7. Forget.
        let forgotten = secrets
            .forget_secret(&our_uuid, "test".into())
            .await
            .expect("forget_secret");
        assert!(forgotten);

        // 8. Confirm forgotten.
        let r2 = secrets
            .recall_secret(&our_uuid, "post-forget".into(), "test".into(), true)
            .await
            .expect("recall after forget")
            .expect("present-or-not_found-result");
        assert!(!r2.found);

        // 9. Filter config CRUD.
        let initial = secrets
            .get_filter_config()
            .await
            .expect("get_filter_config");
        assert_eq!(initial.version, 0, "default version is 0");

        let upd = secrets
            .update_filter_config(
                FilterUpdateRequest {
                    config_id: "global".into(),
                    new_config: serde_json::json!({"patterns": ["api_key"]}),
                },
                "test".into(),
            )
            .await
            .expect("update_filter_config");
        assert_eq!(upd.new_version, 1);

        let again = secrets
            .get_filter_config()
            .await
            .expect("get_filter_config");
        assert_eq!(again.version, 1);
        assert_eq!(
            again.config_value,
            serde_json::json!({"patterns": ["api_key"]})
        );

        // 10. Audit log readback — multiple entries.
        let logs = secrets
            .get_access_logs(None, 100)
            .await
            .expect("get_access_logs");
        assert!(
            logs.len() >= 5,
            "expected at least 5 audit rows, got {}",
            logs.len()
        );

        // 11. Service stats + is_healthy.
        let stats = secrets
            .get_service_stats()
            .await
            .expect("get_service_stats");
        assert!(stats.encryption_enabled, "encryption should be enabled");
        assert!(!stats.hardware_key_active, "v0.9.3 hardware key deferred");
        assert!(secrets.is_healthy().await.unwrap());

        // 12. migrate_to_hardware_key (CIRISPersist#87). Environment-
        // dependent: a usable TPM → `Ok(Hardware{..})`; none →
        // `HardwareKeyUnavailable`. Both are correct; anything else
        // (Backend / Crypto / panic) is a real bug.
        match secrets.migrate_to_hardware_key("test".into()).await {
            Ok(MasterKeyRef::Hardware { .. }) => {}
            Ok(other) => panic!("migrate_to_hardware_key returned non-Hardware ref: {other:?}"),
            Err(SecretsError::HardwareKeyUnavailable(_)) => {}
            Err(other) => panic!("migrate_to_hardware_key failed unexpectedly: {other:?}"),
        }

        // 13. Stubs return Internal (matches v0.6.1 PG behavior).
        let err = secrets
            .process_incoming_text("x", "y", "test".into())
            .await
            .unwrap_err();
        assert!(matches!(err, SecretsError::Internal(_)));

        let err = secrets
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

    /// v1.0.0 (CIRISAgent#756 #2): two concurrent `try_claim_secret`
    /// calls on the same plaintext resolve to one `Stored` + one
    /// `AlreadyClaimed` carrying the same `SecretReference`, with
    /// exactly one row landing in the table.
    #[tokio::test]
    async fn try_claim_secret_race_dedups_to_one_row() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let conn_handle = backend.conn_handle();

        // Two SqliteSecretsBackend instances sharing the same
        // Arc<Mutex<Connection>> — they race against the SAME
        // sqlite database, which is the production sharing model.
        let a = std::sync::Arc::new(SqliteSecretsBackend::new(conn_handle.clone()));
        let b = std::sync::Arc::new(SqliteSecretsBackend::new(conn_handle.clone()));

        // Bootstrap an active master key. Master-key rotation drives
        // the HMAC dedup key — without it `try_claim_secret` returns
        // Crypto(no active master key).
        a.rotate_master_key(None, "test".into()).await.unwrap();

        const PLAINTEXT: &str = "shared-envelope-plaintext-v1";
        const DESCRIPTION: &str = "racing-workers-test";

        let a2 = a.clone();
        let b2 = b.clone();
        let fut_a = async move {
            a2.try_claim_secret(
                PLAINTEXT,
                DESCRIPTION,
                Sensitivity::Medium,
                vec!["tool".into()],
                "worker-a".into(),
            )
            .await
        };
        let fut_b = async move {
            b2.try_claim_secret(
                PLAINTEXT,
                DESCRIPTION,
                Sensitivity::Medium,
                vec!["tool".into()],
                "worker-b".into(),
            )
            .await
        };

        let (r_a, r_b) = tokio::join!(fut_a, fut_b);
        let r_a = r_a.expect("a try_claim_secret");
        let r_b = r_b.expect("b try_claim_secret");

        // Exactly one Stored + one AlreadyClaimed; both reference
        // the same UUID (the winning row).
        let stored_count = [&r_a, &r_b]
            .iter()
            .filter(|r| matches!(r, ClaimResult::Stored(_)))
            .count();
        let claimed_count = [&r_a, &r_b]
            .iter()
            .filter(|r| matches!(r, ClaimResult::AlreadyClaimed(_)))
            .count();
        assert_eq!(stored_count, 1, "exactly one Stored expected");
        assert_eq!(claimed_count, 1, "exactly one AlreadyClaimed expected");
        assert_eq!(
            r_a.reference().uuid,
            r_b.reference().uuid,
            "both outcomes must reference the same row"
        );

        // The table has exactly one row matching this description
        // (and one row matching the content_hmac, but description
        // is the user-visible projection).
        let listed = a
            .list_stored_secrets(
                100,
                SecretsListFilter {
                    pattern: None,
                    sensitivity: None,
                    source_message_id: None,
                    created_after: None,
                    created_before: None,
                },
            )
            .await
            .expect("list_stored_secrets");
        let our_rows: Vec<_> = listed
            .iter()
            .filter(|r| r.description == DESCRIPTION)
            .collect();
        assert_eq!(
            our_rows.len(),
            1,
            "exactly one row expected, found {}",
            our_rows.len()
        );
    }

    /// v1.5.7 (CIRISPersist#57) — process_incoming_text composes
    /// get_filter_config + try_claim_secret as a default trait impl.
    /// SQLite inherits it automatically. Verifies the full
    /// detection→encrypt→store→placeholder→dedup pipeline.
    #[tokio::test]
    async fn process_incoming_text_detects_encrypts_and_replaces_via_default_impl() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let secrets = SqliteSecretsBackend::new(backend.conn_handle());

        secrets
            .rotate_master_key(None, "test".into())
            .await
            .expect("rotate master key");

        // Seed a filter config with two patterns.
        secrets
            .update_filter_config(
                FilterUpdateRequest {
                    config_id: "global".into(),
                    new_config: serde_json::json!({
                        "patterns": [
                            {
                                "pattern_id": "aws_access_key",
                                "regex": "AKIA[0-9A-Z]{16}",
                                "description": "AWS access key",
                                "sensitivity": "high",
                                "auto_decapsulate_for_actions": ["tool"]
                            },
                            {
                                "pattern_id": "github_pat",
                                "regex": "ghp_[A-Za-z0-9]{20,}",
                                "description": "GitHub PAT",
                                "sensitivity": "high",
                                "auto_decapsulate_for_actions": []
                            }
                        ]
                    }),
                },
                "test".into(),
            )
            .await
            .expect("seed filter config");

        let text = "send AKIAEXAMPLEABCDEFGH12 and ghp_ABCDEFghijklmnopqrstuvwxyz0123 \
                    to the deploy bot please";
        let (filtered, refs) = secrets
            .process_incoming_text(text, "msg-1", "agent-x".into())
            .await
            .expect("process_incoming_text");

        // Both secrets land as SecretReferences.
        assert_eq!(refs.len(), 2, "expected 2 refs, got {refs:?}");
        let descriptions: Vec<_> = refs.iter().map(|r| r.description.as_str()).collect();
        assert!(descriptions.contains(&"AWS access key"));
        assert!(descriptions.contains(&"GitHub PAT"));

        // Filtered text carries the placeholders, NOT the plaintexts.
        assert!(
            !filtered.contains("AKIAEXAMPLEABCDEFGH12"),
            "plaintext leaked: {filtered}"
        );
        assert!(
            !filtered.contains("ghp_ABCDEFghijklmnopqrstuvwxyz0123"),
            "plaintext leaked: {filtered}"
        );
        assert!(filtered.contains("{SECRET:"), "no placeholder: {filtered}");
        for r in &refs {
            let placeholder = format!("{{SECRET:{}:{}}}", r.uuid, r.description);
            assert!(
                filtered.contains(&placeholder),
                "missing placeholder {placeholder} in {filtered}"
            );
        }

        // Idempotency / dedup: re-running on the same text replays through
        // try_claim_secret which hmac-dedups; the refs returned are the
        // same UUIDs (AlreadyClaimed under the covers).
        let (_, refs2) = secrets
            .process_incoming_text(text, "msg-2", "agent-x".into())
            .await
            .expect("process_incoming_text 2");
        assert_eq!(refs2.len(), 2);
        let uuids_a: std::collections::HashSet<_> = refs.iter().map(|r| &r.uuid).collect();
        let uuids_b: std::collections::HashSet<_> = refs2.iter().map(|r| &r.uuid).collect();
        assert_eq!(
            uuids_a, uuids_b,
            "dedup should yield same UUIDs across runs"
        );
    }

    // ── v1.5.24 (CIRISPersist#66) store_detected_secret tests ───────

    fn mk_payload(value: &str, pattern: &str) -> super::super::DetectedSecret {
        super::super::DetectedSecret {
            secret_uuid: Uuid::new_v4().to_string(),
            value: value.to_owned(),
            description: "GitHub PAT".to_owned(),
            sensitivity: Sensitivity::High,
            detected_pattern: pattern.to_owned(),
            context_hint: Some("found in tool_args.token".to_owned()),
            source_message_id: Some("msg-123".to_owned()),
            auto_decapsulate_for_actions: vec!["tool".to_owned()],
            manual_access_only: false,
        }
    }

    #[tokio::test]
    async fn store_detected_secret_stores_with_caller_uuid_and_full_metadata() {
        let (_b, secrets) = fresh_backend().await;
        secrets
            .rotate_master_key(None, "test".into())
            .await
            .unwrap();

        let payload = mk_payload("ghp_TESTPAT_ABCDEFG", "regex:github_pat_v1");
        let caller_uuid = payload.secret_uuid.clone();

        let outcome = secrets
            .store_detected_secret(payload, "agent-x".into())
            .await
            .expect("store_detected_secret");
        match outcome {
            ClaimResult::Stored(r) => {
                assert_eq!(r.uuid, caller_uuid, "caller UUID must be preserved");
                assert_eq!(r.description, "GitHub PAT");
                assert_eq!(r.detected_pattern, "regex:github_pat_v1");
                assert_eq!(r.context_hint.as_deref(), Some("found in tool_args.token"));
                assert_eq!(r.sensitivity, Sensitivity::High);
                assert_eq!(r.auto_decapsulate_actions, vec!["tool".to_string()]);
            }
            other => panic!("expected Stored, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_detected_secret_same_uuid_same_plaintext_idempotent() {
        let (_b, secrets) = fresh_backend().await;
        secrets
            .rotate_master_key(None, "test".into())
            .await
            .unwrap();

        let mut payload = mk_payload("ghp_TESTPAT_IDEMPOTENT", "regex:github_pat_v1");
        let caller_uuid = payload.secret_uuid.clone();
        let _ = secrets
            .store_detected_secret(payload.clone(), "agent-x".into())
            .await
            .expect("first store");

        // Re-store with the SAME UUID and SAME plaintext — should be
        // AlreadyClaimed (content_hmac collision; the row already
        // exists with the caller's UUID).
        let payload2 = payload.clone();
        payload.description = "rev2".into(); // unused; metadata is sticky on conflict
        let _ = payload;
        let r2 = secrets
            .store_detected_secret(payload2, "agent-x".into())
            .await
            .expect("second store");
        match r2 {
            ClaimResult::AlreadyClaimed(r) => assert_eq!(r.uuid, caller_uuid),
            other => panic!("expected AlreadyClaimed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_detected_secret_different_uuid_same_plaintext_returns_canonical() {
        let (_b, secrets) = fresh_backend().await;
        secrets
            .rotate_master_key(None, "test".into())
            .await
            .unwrap();

        let p1 = mk_payload("ghp_SHARED_PLAINTEXT", "regex:github_pat_v1");
        let first_uuid = p1.secret_uuid.clone();
        let _ = secrets
            .store_detected_secret(p1, "agent-a".into())
            .await
            .expect("first");

        // Second agent supplies a DIFFERENT UUID for the same
        // plaintext. content_hmac collision → AlreadyClaimed with
        // the FIRST UUID (canonical).
        let mut p2 = mk_payload("ghp_SHARED_PLAINTEXT", "regex:github_pat_v1");
        p2.secret_uuid = Uuid::new_v4().to_string();
        let second_caller_uuid = p2.secret_uuid.clone();
        assert_ne!(first_uuid, second_caller_uuid);

        let r2 = secrets
            .store_detected_secret(p2, "agent-b".into())
            .await
            .expect("second");
        match r2 {
            ClaimResult::AlreadyClaimed(r) => {
                assert_eq!(r.uuid, first_uuid);
                assert_ne!(r.uuid, second_caller_uuid);
            }
            other => panic!("expected AlreadyClaimed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn store_detected_secret_same_uuid_different_plaintext_invalid_argument() {
        let (_b, secrets) = fresh_backend().await;
        secrets
            .rotate_master_key(None, "test".into())
            .await
            .unwrap();

        let p1 = mk_payload("ghp_FIRST_PT", "regex:github_pat_v1");
        let shared_uuid = p1.secret_uuid.clone();
        let _ = secrets
            .store_detected_secret(p1, "agent-x".into())
            .await
            .expect("first");

        let mut p2 = mk_payload("ghp_SECOND_PT_DIFFERENT", "regex:github_pat_v1");
        p2.secret_uuid = shared_uuid;
        let err = secrets
            .store_detected_secret(p2, "agent-x".into())
            .await
            .unwrap_err();
        assert!(
            matches!(err, SecretsError::InvalidArgument(_)),
            "expected InvalidArgument (UUID reused for different plaintext), got {err:?}"
        );
    }

    #[tokio::test]
    async fn store_detected_secret_empty_fields_rejected() {
        let (_b, secrets) = fresh_backend().await;
        secrets
            .rotate_master_key(None, "test".into())
            .await
            .unwrap();

        // empty UUID
        let mut p = mk_payload("v", "regex:p1");
        p.secret_uuid = String::new();
        assert!(matches!(
            secrets
                .store_detected_secret(p, "a".into())
                .await
                .unwrap_err(),
            SecretsError::InvalidArgument(_)
        ));

        // malformed UUID
        let mut p = mk_payload("v", "regex:p1");
        p.secret_uuid = "not-a-uuid".into();
        assert!(matches!(
            secrets
                .store_detected_secret(p, "a".into())
                .await
                .unwrap_err(),
            SecretsError::InvalidArgument(_)
        ));

        // empty value
        let mut p = mk_payload("v", "regex:p1");
        p.value = String::new();
        assert!(matches!(
            secrets
                .store_detected_secret(p, "a".into())
                .await
                .unwrap_err(),
            SecretsError::InvalidArgument(_)
        ));

        // empty detected_pattern
        let mut p = mk_payload("v", "regex:p1");
        p.detected_pattern = String::new();
        assert!(matches!(
            secrets
                .store_detected_secret(p, "a".into())
                .await
                .unwrap_err(),
            SecretsError::InvalidArgument(_)
        ));

        // empty description
        let mut p = mk_payload("v", "regex:p1");
        p.description = String::new();
        assert!(matches!(
            secrets
                .store_detected_secret(p, "a".into())
                .await
                .unwrap_err(),
            SecretsError::InvalidArgument(_)
        ));
    }

    #[tokio::test]
    async fn store_detected_secret_recall_round_trips_value_and_metadata() {
        let (_b, secrets) = fresh_backend().await;
        secrets
            .rotate_master_key(None, "test".into())
            .await
            .unwrap();

        let payload = mk_payload("ghp_RECALL_TEST_VALUE", "regex:github_pat_v1");
        let caller_uuid = payload.secret_uuid.clone();
        let _ = secrets
            .store_detected_secret(payload, "agent-x".into())
            .await
            .expect("store");

        let recalled = secrets
            .recall_secret(&caller_uuid, "test-recall".into(), "agent-x".into(), true)
            .await
            .expect("recall_secret")
            .expect("recalled row exists");
        assert!(recalled.found);
        assert_eq!(recalled.value.as_deref(), Some("ghp_RECALL_TEST_VALUE"));
    }

    /// v1.5.7 — empty filter catalog returns the text untouched.
    #[tokio::test]
    async fn process_incoming_text_empty_catalog_passthrough() {
        let backend = SqliteBackend::open_in_memory().await.unwrap();
        backend.run_migrations().await.unwrap();
        let secrets = SqliteSecretsBackend::new(backend.conn_handle());
        secrets
            .rotate_master_key(None, "test".into())
            .await
            .expect("rotate master key");

        // Default filter config (version=0, empty value) — no patterns
        // → text passes through unchanged, no refs.
        let text = "nothing sensitive here";
        let (filtered, refs) = secrets
            .process_incoming_text(text, "msg-1", "agent-x".into())
            .await
            .expect("process_incoming_text");
        assert_eq!(filtered, text);
        assert!(refs.is_empty());
    }
}
