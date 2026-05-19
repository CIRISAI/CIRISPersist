//! Federation-stable wire types for the SecretsService surface
//! (v0.6.1+, CIRISPersist#19; FSD `POST_INGEST_FILTER_PIPELINE.md` §7.2).
//!
//! These types cross the PyO3 boundary (JSON-encoded), the HTTP API
//! boundary (axum + serde), and the persistence boundary (postgres
//! JSONB columns). Wire shape changes within v0.6.x are additive only;
//! breaking changes require a `record_schema_version` bump (the only
//! field for which version-discriminated parsing is implemented).
//!
//! # Bytes vs Vec<u8>
//!
//! The FSD spec uses `bytes::Bytes` for ciphertext / salt / nonce /
//! HMAC fields. To avoid adding a `bytes` direct dep + keep serde
//! straightforward, this port uses `Vec<u8>` (serde encodes
//! identically — base64 via serde-aware adapters when crossing JSON,
//! or BYTEA when crossing postgres). No wire-shape difference vs the
//! FSD spec.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::pipeline::classify::Sensitivity;

/// Full encrypted-secret row as stored in `cirislens_secrets.secrets`.
/// Returned by the `read_secret_record` internal path; consumers
/// see this type via `SecretReference` (metadata) or the recall path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretRecord {
    /// UUID v4 — the federation-stable key for this secret.
    pub secret_uuid: String,

    /// AES-256-GCM ciphertext (with auth tag).
    pub encrypted_value: Vec<u8>,

    /// Per-secret key-derivation reference. Points into
    /// `cirislens_secrets.master_key_meta.key_ref`. The KDF input
    /// is `(master_key, salt)`; this column tells the recall path
    /// which master key was active at encrypt time.
    pub encryption_key_ref: String,

    /// PBKDF2 salt (32 bytes per `crypto.rs` `SALT_LEN`).
    pub salt: Vec<u8>,

    /// AES-GCM nonce (12 bytes per `crypto.rs` `NONCE_LEN`).
    pub nonce: Vec<u8>,

    /// Human-readable description shown in metadata listings.
    pub description: String,

    /// Sensitivity level (controls auto-decapsulate default).
    pub sensitivity_level: Sensitivity,

    /// Detected pattern matcher_id (e.g. `"regex:api_key_v1"`).
    /// Stable across federation peers per FSD §6.3 convention.
    pub detected_pattern: String,

    /// Optional context hint (e.g. `"in tool_args.api_key"`).
    pub context_hint: Option<String>,

    /// Lifecycle timestamps.
    pub created_at: DateTime<Utc>,
    /// Last access wall-clock. `None` if the secret has never been
    /// recalled / retrieved since creation.
    pub last_accessed: Option<DateTime<Utc>>,
    /// Total successful recalls + retrievals.
    pub access_count: u64,

    /// Source message id (when the secret was detected via
    /// `process_incoming_text`). `None` for direct
    /// `store_secret` calls.
    pub source_message_id: Option<String>,

    /// Whitelist of action_type tokens that may auto-decapsulate
    /// this secret. Empty array = manual recall only.
    pub auto_decapsulate_for_actions: Vec<String>,

    /// Hard manual-access override. When `true`, the secret is
    /// NEVER auto-decapsulated regardless of action whitelist.
    pub manual_access_only: bool,

    /// Wire shape version. v1.0 today. Bumped when the column set
    /// changes; consumers skip rows whose version they don't
    /// recognize.
    pub record_schema_version: String,
}

/// Encrypted record wrapper carrying an optional edge-side HMAC for
/// integrity-attestation. Edge writes; persist verifies before
/// insert (when `secrets-server` is on and the HMAC is present).
/// HMAC absence is acceptable in embedded mode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptedSecretRecord {
    /// The encrypted record.
    pub record: SecretRecord,
    /// Optional federation-internal HMAC over the canonical(record)
    /// bytes. Edge populates via `hmac_sha256(edge_signing_key,
    /// canonical(record))`. Persist verifies via the same key
    /// (registered as a federation peer in `federation_keys`).
    pub edge_hmac: Option<Vec<u8>>,
}

/// Metadata-only reference (no ciphertext, no key refs). Used in
/// `list_stored_secrets` results + the
/// `(filtered_text, refs)` return tuple of
/// `process_incoming_text`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretReference {
    /// UUID v4 — matches `SecretRecord::secret_uuid`.
    pub uuid: String,
    /// Human-readable description.
    pub description: String,
    /// Optional context hint.
    pub context_hint: Option<String>,
    /// Sensitivity level.
    pub sensitivity: Sensitivity,
    /// Detected pattern matcher_id.
    pub detected_pattern: String,
    /// Auto-decapsulate action whitelist.
    pub auto_decapsulate_actions: Vec<String>,
    /// Lifecycle timestamps.
    pub created_at: DateTime<Utc>,
    /// Last access wall-clock.
    pub last_accessed: Option<DateTime<Utc>>,
}

/// Result of a `recall_secret` operation. Carries the decrypted
/// value (when `decrypt=true` was requested and authorization
/// passed) or an error message explaining why decryption was
/// skipped / refused.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretRecallResult {
    /// True if a secret with the supplied UUID exists.
    pub found: bool,
    /// Plaintext when `decrypt=true` + authorization passed.
    /// `None` otherwise.
    pub value: Option<String>,
    /// Operator-visible error message when `found=true` but
    /// `value=None` (e.g. `"authorization denied"`).
    pub error: Option<String>,
}

/// Context for the `decapsulate_secrets_in_parameters` operation
/// (called by the agent's action dispatcher before executing a
/// secret-bearing action). Used to populate audit-log rows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecapsulationContext {
    /// Action type token (e.g. `"tool"`, `"speak"`, `"memorize"`).
    /// Compared against each secret's `auto_decapsulate_for_actions`
    /// whitelist.
    pub action_type: String,
    /// Caller-supplied accessor token (action handler id).
    pub accessor: String,
    /// Free-form purpose string for audit reconstruction.
    pub purpose: String,
    /// Optional cross-link into the trace_events corpus.
    pub trace_id: Option<String>,
    /// Optional cross-link to the thought.
    pub thought_id: Option<String>,
}

/// Stable wire-side tokens for `cirislens_secrets.access_log.operation`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessOp {
    /// `store_secret` — manually-keyed.
    Store,
    /// `retrieve_secret` — manually-keyed retrieval.
    Retrieve,
    /// `recall_secret` — UUID-keyed (the detection path).
    Recall,
    /// `forget_secret` — audited delete.
    Forget,
    /// `encrypt` — direct AES-GCM encrypt; no row stored.
    Encrypt,
    /// `decrypt` — direct AES-GCM decrypt.
    Decrypt,
    /// `reencrypt_all` — master-key rotation re-encrypt.
    Reencrypt,
    /// `rotate_master_key` — rotation event itself.
    Rotate,
}

/// One row from `cirislens_secrets.access_log`. Surfaced by
/// `get_access_logs`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessLogEntry {
    /// BIGSERIAL primary key.
    pub log_id: i64,
    /// UUID of the secret accessed. `None` for direct encrypt /
    /// decrypt ops (no specific row referenced).
    pub secret_uuid: Option<String>,
    /// Who/what performed the operation.
    pub accessor: String,
    /// Operation tag.
    pub operation: AccessOp,
    /// Action context (populated on recall/decapsulate paths).
    pub action_type: Option<String>,
    /// Free-form purpose string.
    pub purpose: Option<String>,
    /// Operation outcome.
    pub success: bool,
    /// Error message when `success=false`.
    pub error: Option<String>,
    /// Optional cross-link into trace_events.
    pub trace_id: Option<String>,
    /// Optional cross-link to thought.
    pub thought_id: Option<String>,
    /// Wall-clock at which the operation ran.
    pub created_at: DateTime<Utc>,
}

/// Caller-supplied detected-secret payload (v1.5.24, CIRISPersist#66).
///
/// Carries an agent-assigned UUID + the full Python-side
/// `DetectedSecret` metadata bundle. Stored verbatim into
/// `cirislens_secrets.secrets` via
/// [`super::SecretsService::store_detected_secret`].
///
/// Distinct from the
/// [`super::SecretsService::try_claim_secret`] / [`super::SecretsService::store_secret`]
/// paths:
///
/// - `store_secret(key, value)` — manually-keyed, persist generates
///   the UUID, stores under `detected_pattern = "manual"`, with
///   defaulted sensitivity. No `context_hint`, no
///   `source_message_id`, no `auto_decapsulate_for_actions`, no
///   `manual_access_only`.
/// - `try_claim_secret(plaintext, description, sensitivity, ...)` —
///   race-safe dedup by `content_hmac`; persist generates the UUID;
///   supports a subset of metadata.
/// - **`store_detected_secret`** — agent owns the UUID, supplies the
///   full metadata bundle. Race-safe by `content_hmac` (same plaintext
///   under any caller path resolves to the existing row).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectedSecret {
    /// Agent-assigned UUID v4 — becomes the row's `secret_uuid` PK
    /// on clean insert. Caller must supply a valid UUID string;
    /// persist does NOT regenerate.
    pub secret_uuid: String,
    /// Plaintext to encrypt and store.
    pub value: String,
    /// Human-readable description (e.g. `"OpenAI API key"`).
    pub description: String,
    /// Sensitivity tier.
    pub sensitivity: Sensitivity,
    /// Detected-pattern matcher id (e.g. `"regex:openai_key_v1"`).
    /// Required (cannot be empty) — distinguishes from
    /// `store_secret`'s `"manual"` sentinel.
    pub detected_pattern: String,
    /// Surrounding-text snippet for operator context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_hint: Option<String>,
    /// Where the detection fired (message id, trace id, etc.).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_message_id: Option<String>,
    /// Whitelist of action_type tokens that may auto-decapsulate.
    #[serde(default)]
    pub auto_decapsulate_for_actions: Vec<String>,
    /// Hard manual-access override. `true` blocks all auto-
    /// decapsulation regardless of `auto_decapsulate_for_actions`.
    #[serde(default)]
    pub manual_access_only: bool,
}

/// Filter for `list_stored_secrets` — every field optional;
/// composes AND-style.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecretsListFilter {
    /// Narrow to a specific sensitivity tier.
    pub sensitivity: Option<Sensitivity>,
    /// Match exact detected_pattern matcher_id.
    pub pattern: Option<String>,
    /// Filter to secrets created from a specific source_message_id.
    pub source_message_id: Option<String>,
    /// Filter to secrets created at or after this wall-clock.
    pub created_after: Option<DateTime<Utc>>,
    /// Filter to secrets created before this wall-clock.
    pub created_before: Option<DateTime<Utc>>,
}

/// SecretsService health + observability summary. Surfaced by
/// `get_service_stats`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecretsServiceStats {
    /// Total rows in `cirislens_secrets.secrets`.
    pub total_secrets: u64,
    /// Number of `filter_config` rows with `enabled=true`.
    pub active_filters: u64,
    /// Filter-pattern matches today (rolling 24h window from now).
    pub filter_matches_today: u64,
    /// Most recent `filter_config` update.
    pub last_filter_update: Option<DateTime<Utc>>,
    /// `false` only when the active master key is missing / corrupt.
    pub encryption_enabled: bool,
    /// `true` when the active master key is hardware-backed (TPM /
    /// Keystore). Always `false` in v0.6.1 until `secrets-hw` lands.
    pub hardware_key_active: bool,
    /// Most recent master-key rotation event.
    pub last_rotation: Option<DateTime<Utc>>,
    /// Total master-key rotations in the lifetime of this store.
    pub rotation_count: u64,
}

/// Result of `reencrypt_all` (master-key rotation).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RotationResult {
    /// `true` when every secret re-encrypted successfully.
    pub success: bool,
    /// Count of secrets re-encrypted under the new master key.
    pub secrets_reencrypted: u64,
    /// UUIDs that failed to re-encrypt (corrupt rows / missing
    /// keys). Empty list when `success = true`.
    pub failures: Vec<String>,
    /// Wall-clock duration of the rotation pass (milliseconds).
    pub duration_ms: u64,
}

/// Reference to a master key — software (in-process bytes) or
/// hardware (CIRISVerify TPM/Keystore handle).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value")]
pub enum MasterKeyRef {
    /// Software-stored. `handle` is the
    /// `cirislens_secrets.master_key_meta.key_ref` (random UUID at
    /// generation time).
    Software {
        /// Opaque software-key handle.
        handle: String,
    },
    /// Hardware-stored. `key_id` is the CIRISVerify keystore key id;
    /// `descriptor` is the TPM/Keystore storage descriptor.
    /// Activated only when the `secrets-hw` feature is on (deferred
    /// in v0.6.1).
    Hardware {
        /// CIRISVerify key id.
        key_id: String,
        /// Storage descriptor (TPM handle / Keystore alias / etc.).
        descriptor: String,
    },
}

/// Patch shape for `update_filter_config`. The CRUD surface for the
/// pattern catalog; matches CIRISAgent `FilterConfig` semantics.
///
/// v0.6.1 keeps the patch surface minimal — operators submit
/// whole-config replaces. Field-level deltas are a v0.6.x follow-up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilterUpdateRequest {
    /// Target config_id (e.g. `"global"` or per-deployment id).
    pub config_id: String,
    /// New config payload. Replaces the existing value entirely.
    pub new_config: serde_json::Value,
}

/// Result of `update_filter_config` — surfaces the new version
/// number so the caller can detect concurrent writes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilterUpdateResult {
    /// New `version` field on the row (monotonic).
    pub new_version: i32,
    /// Wall-clock at which the update was applied.
    pub updated_at: DateTime<Utc>,
}

/// Read shape for `get_filter_config`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilterConfig {
    /// `config_id` PRIMARY KEY of the `filter_config` row.
    pub config_id: String,
    /// JSON-encoded config payload.
    pub config_value: serde_json::Value,
    /// Monotonic version.
    pub version: i32,
    /// Last update wall-clock.
    pub updated_at: DateTime<Utc>,
    /// Last updater (audit attribution).
    pub updated_by: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn master_key_ref_software_round_trip() {
        let r = MasterKeyRef::Software {
            handle: "abc-123".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(s, r#"{"kind":"Software","value":{"handle":"abc-123"}}"#);
        let back: MasterKeyRef = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn master_key_ref_hardware_round_trip() {
        let r = MasterKeyRef::Hardware {
            key_id: "tpm-1".into(),
            descriptor: "tpm://0x81000001".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: MasterKeyRef = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn access_op_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&AccessOp::Reencrypt).unwrap(),
            r#""reencrypt""#
        );
        let back: AccessOp = serde_json::from_str(r#""rotate""#).unwrap();
        assert_eq!(back, AccessOp::Rotate);
    }

    #[test]
    fn secret_reference_round_trip() {
        let r = SecretReference {
            uuid: "11111111-2222-3333-4444-555555555555".into(),
            description: "GitHub PAT".into(),
            context_hint: Some("found in tool_args.token".into()),
            sensitivity: Sensitivity::High,
            detected_pattern: "regex:github_token_v1".into(),
            auto_decapsulate_actions: vec!["tool".into()],
            created_at: chrono::Utc::now(),
            last_accessed: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: SecretReference = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn secret_recall_result_serde() {
        let ok = SecretRecallResult {
            found: true,
            value: Some("hunter2".into()),
            error: None,
        };
        let denied = SecretRecallResult {
            found: true,
            value: None,
            error: Some("authorization denied".into()),
        };
        let s_ok = serde_json::to_string(&ok).unwrap();
        let s_denied = serde_json::to_string(&denied).unwrap();
        assert!(s_ok.contains("\"value\":\"hunter2\""));
        assert!(s_denied.contains("\"error\":\"authorization denied\""));
    }

    #[test]
    fn secrets_list_filter_default_empty() {
        let f = SecretsListFilter::default();
        assert!(f.sensitivity.is_none());
        let s = serde_json::to_string(&f).unwrap();
        let back: SecretsListFilter = serde_json::from_str(&s).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn filter_update_request_carries_json_payload() {
        let req = FilterUpdateRequest {
            config_id: "global".into(),
            new_config: json!({"patterns": ["foo", "bar"], "enabled": true}),
        };
        let s = serde_json::to_string(&req).unwrap();
        let back: FilterUpdateRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(back, req);
    }
}
