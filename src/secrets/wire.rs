//! v1.1.0 (CIRISPersist#33 part 4a): HTTP wire types for the
//! federated SecretsService surface.
//!
//! These structs are the stable serde shape exposed by the
//! `secrets-server` axum routes (`src/server/secrets.rs`) and
//! consumed by the federated client (`src/secrets/client.rs` —
//! deferred to a separate task). Distinct from the
//! [`crate::secrets::types`] module which holds the trait-level
//! `SecretsService` inputs/outputs: those carry `&str` / `Vec<u8>` /
//! enum shapes that don't serialize cleanly across an HTTP boundary
//! (binary keys in particular need base64 framing).
//!
//! # Why a separate wire layer?
//!
//! The [`crate::secrets::SecretsService`] trait uses owned `String`
//! and borrowed `&str` parameters intermixed (e.g.
//! `store_secret(key: String, value: String, accessor: String)` vs
//! `retrieve_secret(key: &str, accessor: String)`). HTTP request
//! bodies always deserialize into owned types — the trait's
//! borrowing convenience doesn't translate. Likewise, `Vec<u8>`
//! master-key bytes serde-encode as JSON arrays by default; the
//! wire shape standardizes on base64 strings instead. Concentrating
//! those decisions here gives consumers (the federated client) one
//! stable serde shape to bind against.
//!
//! # Wire-stability scope
//!
//! Field additions are additive within `v1.1.x` (serde `default`-able
//! shape). Field removals or renames require a `wire_schema_version`
//! bump (none today — every shape is `v1.1.0`).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::types::{
    AccessLogEntry, FilterConfig, FilterUpdateRequest, FilterUpdateResult, MasterKeyRef,
    RotationResult, SecretRecallResult, SecretReference, SecretsListFilter, SecretsServiceStats,
};
use crate::pipeline::classify::Sensitivity;

// ── Request shapes ──────────────────────────────────────────────────

/// `POST /api/v1/secrets/store` request body.
///
/// The trait surface is `store_secret(key, value, accessor)` —
/// manually-keyed store where `key` is the human-facing
/// identifier. The HTTP shape adds explicit metadata fields
/// matching the v0.6.1 CIRISAgent SecretsServiceProtocol so
/// federated callers can supply description + sensitivity +
/// auto-decapsulate whitelists when they have them. Today's PG /
/// SQLite impls hardcode `description = key`, `sensitivity =
/// medium`, `detected_pattern = "manual"`, and ignore the extras;
/// v1.1.x persister-side consumption is a follow-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreSecretRequest {
    /// Plaintext payload to encrypt and store.
    pub plaintext: String,
    /// Human-readable description / manual key.
    pub description: String,
    /// Caller-supplied accessor for audit attribution.
    pub accessor: String,
    /// Sensitivity tier; defaults to `Medium` when omitted (matches
    /// the trait's hardcoded shape).
    #[serde(default = "default_sensitivity")]
    pub sensitivity: Sensitivity,
    /// Optional auto-decapsulate action whitelist. Empty = manual.
    #[serde(default)]
    pub auto_decapsulate_for_actions: Vec<String>,
}

fn default_sensitivity() -> Sensitivity {
    Sensitivity::Medium
}

/// `POST /api/v1/secrets/try_claim` request body. Same payload
/// shape as [`StoreSecretRequest`]; semantics differ at the
/// backend (atomic-claim via content_hmac, returns
/// [`ClaimResultWire`]).
pub type TryClaimSecretRequest = StoreSecretRequest;

/// `POST /api/v1/secrets/{uuid}/recall` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallSecretRequest {
    /// Free-form purpose string for audit.
    pub purpose: String,
    /// Caller-supplied accessor.
    pub accessor: String,
    /// When `true`, returns the decrypted plaintext (audited as
    /// `recall` op). When `false`, returns metadata only.
    #[serde(default)]
    pub decrypt: bool,
}

/// `GET /api/v1/secrets/{uuid}` query parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrieveSecretQuery {
    /// Caller-supplied accessor for audit attribution.
    pub accessor: String,
}

/// `DELETE /api/v1/secrets/{uuid}` query parameters.
pub type ForgetSecretQuery = RetrieveSecretQuery;

/// `GET /api/v1/secrets` query parameters. Mirrors
/// [`SecretsListFilter`] flattened for axum's query extractor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListSecretsQuery {
    /// Page size; defaults to 100, clamped server-side to 10,000.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Optional sensitivity filter.
    #[serde(default)]
    pub sensitivity: Option<Sensitivity>,
    /// Optional detected_pattern filter.
    #[serde(default)]
    pub pattern: Option<String>,
    /// Optional source_message_id filter.
    #[serde(default)]
    pub source_message_id: Option<String>,
    /// Optional created_at lower bound.
    #[serde(default)]
    pub created_after: Option<DateTime<Utc>>,
    /// Optional created_at upper bound.
    #[serde(default)]
    pub created_before: Option<DateTime<Utc>>,
}

fn default_limit() -> usize {
    100
}

impl ListSecretsQuery {
    /// Project into the trait-level filter.
    pub fn into_filter(self) -> (usize, SecretsListFilter) {
        (
            self.limit,
            SecretsListFilter {
                sensitivity: self.sensitivity,
                pattern: self.pattern,
                source_message_id: self.source_message_id,
                created_after: self.created_after,
                created_before: self.created_before,
            },
        )
    }
}

/// `POST /api/v1/secrets/encrypt` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptRequest {
    /// Plaintext to encrypt under the active master key.
    pub plaintext: String,
}

/// `POST /api/v1/secrets/decrypt` request body. Ciphertext is the
/// base64 string the matching `encrypt` call returned —
/// equivalent to passing it through the trait's `decrypt(&str)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequest {
    /// Base64-encoded ciphertext (matches the [`EncryptResponse`]
    /// `ciphertext` field shape).
    pub ciphertext: String,
}

/// `GET /api/v1/secrets/access_logs` query parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccessLogsQuery {
    /// Page size; defaults to 100, clamped to 10,000.
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Optional secret_uuid filter (narrows to one secret's
    /// history).
    #[serde(default)]
    pub secret_uuid: Option<String>,
    /// Optional accessor filter — applied client-side after fetch
    /// today; the trait method doesn't yet expose accessor
    /// narrowing. Persister-side push-down is a v1.1.x follow-up.
    #[serde(default)]
    pub accessor: Option<String>,
    /// Optional created_at lower bound — client-side filter today
    /// (same rationale as `accessor`).
    #[serde(default)]
    pub since: Option<DateTime<Utc>>,
    /// Optional created_at upper bound — client-side filter today.
    #[serde(default)]
    pub until: Option<DateTime<Utc>>,
}

/// `POST /api/v1/secrets/reencrypt_all` request body. Carries the
/// new master key bytes (base64) so the route can hand them to
/// the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReencryptAllRequest {
    /// Base64-encoded raw bytes of the new master key (typically
    /// 32 bytes for AES-256). The route decodes + hands the bytes
    /// to [`crate::secrets::SecretsService::reencrypt_all`]'s
    /// [`MasterKeyRef`] argument.
    pub new_master_key_bytes_b64: String,
    /// Caller-supplied accessor.
    pub accessor: String,
    /// Optional preferred software-key handle. When omitted, the
    /// backend generates one.
    #[serde(default)]
    pub new_master_handle: Option<String>,
}

/// `POST /api/v1/secrets/rotate_master_key` request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateMasterKeyRequest {
    /// Optional base64-encoded new master key bytes. When omitted,
    /// the backend generates a fresh random key.
    #[serde(default)]
    pub new_master_b64: Option<String>,
    /// Caller-supplied accessor.
    pub accessor: String,
}

// ── Response shapes ─────────────────────────────────────────────────

/// `POST /api/v1/secrets/store` response.
///
/// The trait method returns `()`; the route surfaces the
/// description + accessor echo so clients can correlate without an
/// immediate `list` follow-up.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreSecretResponse {
    /// Description echoed back (acts as the manual-key identifier
    /// for `retrieve_secret`).
    pub description: String,
    /// Sensitivity tier as the server interpreted the request.
    pub sensitivity: Sensitivity,
    /// Status token, always `"stored"` on the 200 path.
    pub status: String,
}

/// `POST /api/v1/secrets/try_claim` response.
///
/// Surfaces the [`crate::ClaimResult`] variant + the embedded
/// [`SecretReference`]. The `outcome` field is `"stored"` or
/// `"already_claimed"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimResultWire {
    /// `"stored"` when THIS caller's INSERT landed,
    /// `"already_claimed"` on conflict.
    pub outcome: String,
    /// Reference to the row (newly inserted OR pre-existing).
    pub reference: SecretReference,
}

/// `GET /api/v1/secrets/{uuid}` response when the secret exists.
///
/// The trait method is `retrieve_secret(key, accessor)` keyed by
/// the description; this route is keyed by UUID for federation
/// addressability — it delegates to `recall_secret` under the
/// hood with `decrypt=true`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetrieveSecretResponse {
    /// UUID echoed back.
    pub uuid: String,
    /// Decrypted plaintext.
    pub value: String,
}

/// `POST /api/v1/secrets/{uuid}/recall` response.
pub type RecallSecretResponse = SecretRecallResult;

/// `GET /api/v1/secrets` response — list page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListSecretsResponse {
    /// Page of metadata-only references.
    pub items: Vec<SecretReference>,
}

/// `DELETE /api/v1/secrets/{uuid}` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgetSecretResponse {
    /// `true` if a row was deleted; `false` if no matching row
    /// existed (no-op).
    pub deleted: bool,
}

/// `POST /api/v1/secrets/encrypt` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResponse {
    /// Base64-encoded `salt || nonce || ciphertext` blob — same
    /// shape the trait method returns.
    pub ciphertext: String,
}

/// `POST /api/v1/secrets/decrypt` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptResponse {
    /// Decrypted plaintext.
    pub plaintext: String,
}

/// `GET /api/v1/secrets/filter_config` response.
pub type FilterConfigResponse = FilterConfig;

/// `PUT /api/v1/secrets/filter_config` request + response.
pub type FilterConfigUpdateRequest = FilterUpdateRequest;
/// Response shape for the filter-config update route.
pub type FilterConfigUpdateResponse = FilterUpdateResult;

/// `GET /api/v1/secrets/stats` response.
pub type StatsResponse = SecretsServiceStats;

/// `GET /api/v1/secrets/health` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Per-trait health probe outcome.
    pub is_healthy: bool,
}

/// `GET /api/v1/secrets/access_logs` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessLogsResponse {
    /// Page of access log entries.
    pub items: Vec<AccessLogEntry>,
}

/// `POST /api/v1/secrets/reencrypt_all` response.
pub type ReencryptAllResponse = RotationResult;

/// `POST /api/v1/secrets/rotate_master_key` response.
pub type RotateMasterKeyResponse = MasterKeyRef;

// ── Error shape ─────────────────────────────────────────────────────

/// Typed JSON error body returned by the secrets routes. The
/// `kind` token mirrors
/// [`crate::secrets::SecretsError::kind`] for consumer parsing
/// (THREAT_MODEL.md AV-15).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsErrorResponse {
    /// Stable AV-15 token (e.g. `"secrets_not_found"`).
    pub kind: String,
    /// Variant-specific detail string.
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_secret_request_defaults() {
        // Defaults: sensitivity = Medium, actions = [].
        let s = r#"{"plaintext":"x","description":"k","accessor":"a"}"#;
        let r: StoreSecretRequest = serde_json::from_str(s).unwrap();
        assert!(matches!(r.sensitivity, Sensitivity::Medium));
        assert!(r.auto_decapsulate_for_actions.is_empty());
    }

    #[test]
    fn list_secrets_query_default_limit() {
        let s = r#"{}"#;
        let q: ListSecretsQuery = serde_json::from_str(s).unwrap();
        assert_eq!(q.limit, 100);
    }

    #[test]
    fn claim_result_wire_round_trip() {
        let r = ClaimResultWire {
            outcome: "stored".into(),
            reference: SecretReference {
                uuid: "11111111-2222-3333-4444-555555555555".into(),
                description: "k".into(),
                context_hint: None,
                sensitivity: Sensitivity::High,
                detected_pattern: "regex:test".into(),
                auto_decapsulate_actions: vec![],
                created_at: chrono::Utc::now(),
                last_accessed: None,
            },
        };
        let s = serde_json::to_string(&r).unwrap();
        let back: ClaimResultWire = serde_json::from_str(&s).unwrap();
        assert_eq!(back.outcome, "stored");
        assert_eq!(back.reference.uuid, r.reference.uuid);
    }
}
