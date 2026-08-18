//! v1.1.0 (CIRISPersist#33 part 4b): consumer-side HTTP client for
//! the secrets-server API. Mirrors the [`SecretsService`] trait
//! surface so federation peers (CIRISEdge, sovereign agents over
//! Reticulum, lens-core in-process — though in-process callers
//! should prefer direct backend access) can call persist's secrets
//! HTTP API and get the same shape they'd get from an in-process
//! backend.
//!
//! # Wire shape
//!
//! Request / response types defined in [`crate::secrets::wire`].
//! Hybrid sign-verify per the FSD §7 + §8 contract: every request
//! body is hybrid-signed (Ed25519 + optional ML-DSA-65) by the
//! caller's steward key. The server's response carries no signature
//! today — the transport-level mTLS or equivalent is the integrity
//! gate on responses; future iterations may add response signatures.
//!
//! # Authentication
//!
//! Caller passes an [`Arc<LocalSigner>`] at construction; the
//! client signs every request body via
//! [`LocalSigner::sign_hybrid`] when PQC is configured, falling
//! back to [`LocalSigner::sign_ed25519`] when not. Headers
//! emitted:
//!
//! - `X-Ciris-Signing-Key-Id: <local-key-id>`
//! - `X-Ciris-Signature-Ed25519: <base64>`
//! - `X-Ciris-Signature-MlDsa-65: <base64>` (when PQC is configured)
//!
//! # Out-of-scope methods
//!
//! [`SecretsService::process_incoming_text`] /
//! [`SecretsService::decapsulate_secrets_in_parameters`] are
//! pipeline-stage internals; they return [`SecretsError::Internal`]
//! (no HTTP analogue). [`SecretsService::test_encryption`] and
//! [`SecretsService::migrate_to_hardware_key`] also stay local —
//! agents that need them call the in-process backend directly.
//!
//! # retrieve_secret divergence
//!
//! The server's `GET /api/v1/secrets/{uuid}` route is UUID-keyed
//! (federation addressability) and calls [`SecretsService::recall_secret`]
//! under the hood with `decrypt=true`. The client's
//! [`SecretsService::retrieve_secret`] impl interprets the `key`
//! argument as a UUID (matching the server divergence) and routes
//! to the recall HTTP path. Consumers wiring against the in-process
//! backend will key by description; consumers wiring against this
//! client must key by UUID.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use reqwest::Client as HttpClient;
use reqwest::Method;
use reqwest::StatusCode;
use url::Url;

use crate::pipeline::classify::Sensitivity;
use crate::secrets::types::{
    AccessLogEntry, DecapsulationContext, FilterConfig, FilterUpdateRequest, FilterUpdateResult,
    MasterKeyRef, RotationResult, SecretRecallResult, SecretReference, SecretsListFilter,
    SecretsServiceStats,
};
use crate::secrets::wire::{
    AccessLogsQuery, AccessLogsResponse, ClaimResultWire, DecryptRequest, DecryptResponse,
    EncryptRequest, EncryptResponse, FilterConfigResponse, FilterConfigUpdateRequest,
    FilterConfigUpdateResponse, ForgetSecretResponse, HealthResponse, ListSecretsQuery,
    ListSecretsResponse, RecallSecretRequest, RecallSecretResponse, ReencryptAllRequest,
    ReencryptAllResponse, RetrieveSecretResponse, RotateMasterKeyRequest, RotateMasterKeyResponse,
    SecretsErrorResponse, StatsResponse, StoreSecretRequest, StoreSecretResponse,
    TryClaimSecretRequest,
};
use crate::secrets::{SecretsError, SecretsService};
use crate::signing::LocalSigner;
use crate::ClaimResult;

/// Header carrying the local signer's `federation_keys.key_id`.
const HEADER_KEY_ID: &str = "X-Ciris-Signing-Key-Id";
/// Header carrying the Ed25519 signature (base64) over the request
/// body bytes.
const HEADER_ED25519: &str = "X-Ciris-Signature-Ed25519";
/// Header carrying the ML-DSA-65 signature (base64). Optional —
/// emitted only when the configured [`LocalSigner`] has PQC.
const HEADER_ML_DSA_65: &str = "X-Ciris-Signature-MlDsa-65";

/// HTTP client mirroring the [`SecretsService`] trait surface.
///
/// Constructed once at deployment startup, shared across worker
/// tasks behind an [`Arc`]. All methods take `&self`.
pub struct FederatedSecretsClient {
    base_url: Url,
    client: HttpClient,
    signer: Arc<LocalSigner>,
}

impl std::fmt::Debug for FederatedSecretsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FederatedSecretsClient")
            .field("base_url", &self.base_url.as_str())
            .field("local_key_id", &self.signer.key_id())
            .finish()
    }
}

impl FederatedSecretsClient {
    /// Construct a new client.
    ///
    /// `base_url` is the persist server's origin (e.g.,
    /// `https://persist.example.com`). The `signer` is used to
    /// hybrid-sign every request body.
    ///
    /// Default reqwest settings: 30s connection timeout, 60s request
    /// timeout, gzip-on. Callers needing finer control construct via
    /// [`Self::from_parts`].
    pub fn new(base_url: Url, signer: Arc<LocalSigner>) -> Result<Self, SecretsError> {
        let client = HttpClient::builder()
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .gzip(true)
            .build()
            .map_err(|e| SecretsError::Backend(format!("reqwest client build: {e}")))?;
        Ok(Self {
            base_url,
            client,
            signer,
        })
    }

    /// Construct from a pre-built reqwest [`HttpClient`]. Useful for
    /// tests that wire a mock-transport client or production
    /// deployments needing custom TLS / proxy / connection-pool
    /// settings.
    pub fn from_parts(base_url: Url, client: HttpClient, signer: Arc<LocalSigner>) -> Self {
        Self {
            base_url,
            client,
            signer,
        }
    }

    /// Sign a request body with the configured local signer and
    /// emit the signature headers.
    ///
    /// Returns the hybrid signature (Ed25519 + ML-DSA-65). **PQC is
    /// REQUIRED as of v37.0.0.**
    ///
    /// Through v36.x this fell back to an Ed25519-only signature when the
    /// signer had no PQC configured, because the server verified under
    /// `HybridPolicy::Ed25519Fallback`. That server-side policy flipped to
    /// [`HybridPolicy::Strict`](crate::verify::HybridPolicy::Strict) in the
    /// v37.0.0 break, so the fallback could now only ever build a request
    /// the server is guaranteed to refuse with
    /// `verify_hybrid_pending_rejected`.
    ///
    /// Rather than ship a doomed request and surface the cause as a remote
    /// 401 — which reads as a credential problem — this fails HERE, where
    /// the actual cause (this signer has no PQC key) is known and can be
    /// named. Configure the local signer's ML-DSA-65 half; see
    /// [`crate::signing`].
    async fn sign_body(&self, body: &[u8]) -> Result<Vec<(&'static str, String)>, SecretsError> {
        // Hybrid is the only acceptable shape as of v37.0.0. The signer
        // returns PqcNotConfigured if PQC isn't wired; that is now a
        // hard, locally-diagnosed failure rather than a silent downgrade.
        match self.signer.sign_hybrid(body).await {
            Ok(hybrid) => {
                let ed25519_b64 = BASE64.encode(&hybrid.classical.signature);
                let ml_dsa_65_b64 = BASE64.encode(&hybrid.pqc.signature);
                Ok(vec![
                    (HEADER_KEY_ID, self.signer.key_id().to_owned()),
                    (HEADER_ED25519, ed25519_b64),
                    (HEADER_ML_DSA_65, ml_dsa_65_b64),
                ])
            }
            Err(crate::signing::LocalSignerError::PqcNotConfigured) => {
                Err(SecretsError::Internal(format!(
                    "local sign: signer {:?} has no ML-DSA-65 key configured, \
                     and v37.0.0 secrets routes verify under \
                     HybridPolicy::Strict — an Ed25519-only signature is \
                     refused server-side (verify_hybrid_pending_rejected). \
                     Through v36.x this downgraded silently; it now fails \
                     here instead of arriving as a remote 401. Configure the \
                     signer's PQC half.",
                    self.signer.key_id()
                )))
            }
            Err(e) => Err(SecretsError::Internal(format!("local sign: {e}"))),
        }
    }

    /// Join a path against the configured base URL. Failure is a
    /// programmer error (constants are static strings).
    fn url(&self, path: &str) -> Result<Url, SecretsError> {
        self.base_url
            .join(path)
            .map_err(|e| SecretsError::Internal(format!("URL join {path:?}: {e}")))
    }

    /// Issue an HTTP request with the supplied method + URL + body.
    /// Signs the body (empty for GET / DELETE), attaches headers,
    /// sends, and routes errors through [`map_error_response`].
    async fn issue<T>(
        &self,
        method: Method,
        url: Url,
        body: Option<Vec<u8>>,
    ) -> Result<T, SecretsError>
    where
        T: serde::de::DeserializeOwned,
    {
        let body_bytes = body.as_deref().unwrap_or(&[]);
        let headers = self.sign_body(body_bytes).await?;
        let mut req = self.client.request(method, url);
        for (k, v) in headers {
            req = req.header(k, v);
        }
        if let Some(b) = body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| SecretsError::Backend(format!("HTTP: {e}")))?;
        let status = resp.status();
        if status.is_success() {
            resp.json::<T>()
                .await
                .map_err(|e| SecretsError::Internal(format!("decode response: {e}")))
        } else {
            Err(map_error_response(resp).await)
        }
    }
}

impl SecretsService for FederatedSecretsClient {
    async fn store_secret(
        &self,
        key: String,
        value: String,
        accessor: String,
    ) -> Result<(), SecretsError> {
        let req = StoreSecretRequest {
            plaintext: value,
            description: key,
            accessor,
            sensitivity: Sensitivity::Medium,
            auto_decapsulate_for_actions: Vec::new(),
        };
        let body = serde_json::to_vec(&req)
            .map_err(|e| SecretsError::Internal(format!("serialize: {e}")))?;
        let url = self.url("/api/v1/secrets/store")?;
        let _: StoreSecretResponse = self.issue(Method::POST, url, Some(body)).await?;
        Ok(())
    }

    /// HTTP override: keyed by UUID (federation addressability),
    /// not by description. Calls the same route as
    /// [`Self::recall_secret`] with `decrypt=true`. See module docs
    /// for the divergence rationale.
    async fn retrieve_secret(
        &self,
        key: &str,
        accessor: String,
    ) -> Result<Option<String>, SecretsError> {
        let path = format!("/api/v1/secrets/{key}");
        let mut url = self.url(&path)?;
        // Pass the accessor via the URL query — matches the
        // server's RetrieveSecretQuery extractor.
        url.query_pairs_mut().append_pair("accessor", &accessor);
        let resp = self
            .issue::<RetrieveSecretResponse>(Method::GET, url, None)
            .await;
        match resp {
            Ok(r) => Ok(Some(r.value)),
            Err(SecretsError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn recall_secret(
        &self,
        uuid: &str,
        purpose: String,
        accessor: String,
        decrypt: bool,
    ) -> Result<Option<SecretRecallResult>, SecretsError> {
        let req = RecallSecretRequest {
            purpose,
            accessor,
            decrypt,
        };
        let body = serde_json::to_vec(&req)
            .map_err(|e| SecretsError::Internal(format!("serialize: {e}")))?;
        let path = format!("/api/v1/secrets/{uuid}/recall");
        let url = self.url(&path)?;
        let resp = self
            .issue::<RecallSecretResponse>(Method::POST, url, Some(body))
            .await;
        match resp {
            Ok(r) => Ok(Some(r)),
            Err(SecretsError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn list_stored_secrets(
        &self,
        limit: usize,
        filter: SecretsListFilter,
    ) -> Result<Vec<SecretReference>, SecretsError> {
        let q = ListSecretsQuery {
            limit,
            sensitivity: filter.sensitivity,
            pattern: filter.pattern,
            source_message_id: filter.source_message_id,
            created_after: filter.created_after,
            created_before: filter.created_before,
        };
        let qs = serde_urlencoded_query(&q)?;
        let mut url = self.url("/api/v1/secrets")?;
        url.set_query(Some(&qs));
        let resp: ListSecretsResponse = self.issue(Method::GET, url, None).await?;
        Ok(resp.items)
    }

    async fn forget_secret(&self, uuid: &str, accessor: String) -> Result<bool, SecretsError> {
        let path = format!("/api/v1/secrets/{uuid}");
        let mut url = self.url(&path)?;
        url.query_pairs_mut().append_pair("accessor", &accessor);
        let resp: ForgetSecretResponse = self.issue(Method::DELETE, url, None).await?;
        Ok(resp.deleted)
    }

    /// In-process pipeline stage. No HTTP analogue —
    /// `process_incoming_text` walks the configured filter catalog
    /// against caller text + stores detected secrets in one pass;
    /// federation peers wanting that behavior compose the pipeline
    /// locally and call the federated `store_secret` /
    /// `try_claim_secret` paths for the individual stores.
    async fn process_incoming_text(
        &self,
        _text: &str,
        _source_message_id: &str,
        _accessor: String,
    ) -> Result<(String, Vec<SecretReference>), SecretsError> {
        Err(SecretsError::Internal(
            "process_incoming_text has no HTTP analogue; compose pipeline locally".into(),
        ))
    }

    /// In-process pipeline stage. No HTTP analogue. See
    /// [`Self::process_incoming_text`].
    async fn decapsulate_secrets_in_parameters(
        &self,
        _action_type: &str,
        _action_params: serde_json::Value,
        _ctx: DecapsulationContext,
    ) -> Result<serde_json::Value, SecretsError> {
        Err(SecretsError::Internal(
            "decapsulate_secrets_in_parameters has no HTTP analogue; compose pipeline locally"
                .into(),
        ))
    }

    async fn encrypt(&self, plaintext: &str) -> Result<String, SecretsError> {
        let req = EncryptRequest {
            plaintext: plaintext.to_owned(),
        };
        let body = serde_json::to_vec(&req)
            .map_err(|e| SecretsError::Internal(format!("serialize: {e}")))?;
        let url = self.url("/api/v1/secrets/encrypt")?;
        let resp: EncryptResponse = self.issue(Method::POST, url, Some(body)).await?;
        Ok(resp.ciphertext)
    }

    async fn decrypt(&self, ciphertext: &str) -> Result<String, SecretsError> {
        let req = DecryptRequest {
            ciphertext: ciphertext.to_owned(),
        };
        let body = serde_json::to_vec(&req)
            .map_err(|e| SecretsError::Internal(format!("serialize: {e}")))?;
        let url = self.url("/api/v1/secrets/decrypt")?;
        let resp: DecryptResponse = self.issue(Method::POST, url, Some(body)).await?;
        Ok(resp.plaintext)
    }

    async fn get_filter_config(&self) -> Result<FilterConfig, SecretsError> {
        let url = self.url("/api/v1/secrets/filter_config")?;
        let resp: FilterConfigResponse = self.issue(Method::GET, url, None).await?;
        Ok(resp)
    }

    async fn update_filter_config(
        &self,
        updates: FilterUpdateRequest,
        _accessor: String,
    ) -> Result<FilterUpdateResult, SecretsError> {
        let req: FilterConfigUpdateRequest = updates;
        let body = serde_json::to_vec(&req)
            .map_err(|e| SecretsError::Internal(format!("serialize: {e}")))?;
        let url = self.url("/api/v1/secrets/filter_config")?;
        let resp: FilterConfigUpdateResponse = self.issue(Method::PUT, url, Some(body)).await?;
        Ok(resp)
    }

    async fn get_service_stats(&self) -> Result<SecretsServiceStats, SecretsError> {
        let url = self.url("/api/v1/secrets/stats")?;
        let resp: StatsResponse = self.issue(Method::GET, url, None).await?;
        Ok(resp)
    }

    async fn is_healthy(&self) -> Result<bool, SecretsError> {
        // Health endpoint is unsigned on the server side (matches
        // the top-level `GET /health` convention). We still go
        // through `issue` for consistency; sign_body emits headers
        // but the server ignores them.
        let url = self.url("/api/v1/secrets/health")?;
        let resp: HealthResponse = self.issue(Method::GET, url, None).await?;
        Ok(resp.is_healthy)
    }

    async fn get_access_logs(
        &self,
        secret_uuid: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AccessLogEntry>, SecretsError> {
        let q = AccessLogsQuery {
            limit,
            secret_uuid: secret_uuid.map(|s| s.to_owned()),
            accessor: None,
            since: None,
            until: None,
        };
        let qs = serde_urlencoded_query(&q)?;
        let mut url = self.url("/api/v1/secrets/access_logs")?;
        url.set_query(Some(&qs));
        let resp: AccessLogsResponse = self.issue(Method::GET, url, None).await?;
        Ok(resp.items)
    }

    async fn reencrypt_all(
        &self,
        new_master_key_ref: MasterKeyRef,
        accessor: String,
    ) -> Result<RotationResult, SecretsError> {
        // The server-side route takes raw bytes + optional handle.
        // The trait's MasterKeyRef carries the handle but no raw
        // bytes — we encode an empty bytes blob and let the
        // backend handle the resolution (matches the server's
        // current "trust the backend to load the bytes out of band"
        // behavior — see secrets.rs::post_reencrypt_all docstring).
        let handle = match new_master_key_ref {
            MasterKeyRef::Software { handle } => Some(handle),
            MasterKeyRef::Hardware { .. } => {
                return Err(SecretsError::HardwareKeyUnavailable(
                    "reencrypt_all with Hardware MasterKeyRef not yet supported over HTTP".into(),
                ));
            }
        };
        let req = ReencryptAllRequest {
            new_master_key_bytes_b64: BASE64.encode([]),
            accessor,
            new_master_handle: handle,
        };
        let body = serde_json::to_vec(&req)
            .map_err(|e| SecretsError::Internal(format!("serialize: {e}")))?;
        let url = self.url("/api/v1/secrets/reencrypt_all")?;
        let resp: ReencryptAllResponse = self.issue(Method::POST, url, Some(body)).await?;
        Ok(resp)
    }

    async fn rotate_master_key(
        &self,
        new_master: Option<Vec<u8>>,
        accessor: String,
    ) -> Result<MasterKeyRef, SecretsError> {
        let req = RotateMasterKeyRequest {
            new_master_b64: new_master.map(|b| BASE64.encode(b)),
            accessor,
        };
        let body = serde_json::to_vec(&req)
            .map_err(|e| SecretsError::Internal(format!("serialize: {e}")))?;
        let url = self.url("/api/v1/secrets/rotate_master_key")?;
        let resp: RotateMasterKeyResponse = self.issue(Method::POST, url, Some(body)).await?;
        Ok(resp)
    }

    /// In-process health probe. No HTTP analogue — the federated
    /// caller can probe round-trip behavior via the encrypt/decrypt
    /// HTTP routes if needed. Returns [`SecretsError::Internal`].
    async fn test_encryption(&self) -> Result<bool, SecretsError> {
        Err(SecretsError::Internal(
            "test_encryption has no HTTP analogue; call /encrypt and /decrypt directly".into(),
        ))
    }

    /// In-process hardware-key migration. No HTTP analogue —
    /// hardware-key migration is host-local (TPM / Keystore handle
    /// resolution can't traverse the federation boundary). Returns
    /// [`SecretsError::HardwareKeyUnavailable`].
    async fn migrate_to_hardware_key(
        &self,
        _accessor: String,
    ) -> Result<MasterKeyRef, SecretsError> {
        Err(SecretsError::HardwareKeyUnavailable(
            "migrate_to_hardware_key is host-local; no HTTP analogue".into(),
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
        let req = TryClaimSecretRequest {
            plaintext: plaintext.to_owned(),
            description: description.to_owned(),
            accessor,
            sensitivity,
            auto_decapsulate_for_actions,
        };
        let body = serde_json::to_vec(&req)
            .map_err(|e| SecretsError::Internal(format!("serialize: {e}")))?;
        let url = self.url("/api/v1/secrets/try_claim")?;
        let resp: ClaimResultWire = self.issue(Method::POST, url, Some(body)).await?;
        match resp.outcome.as_str() {
            "stored" => Ok(ClaimResult::Stored(resp.reference)),
            "already_claimed" => Ok(ClaimResult::AlreadyClaimed(resp.reference)),
            other => Err(SecretsError::Internal(format!(
                "unknown try_claim outcome: {other}"
            ))),
        }
    }
}

/// Encode a serde-Serialize query struct to a URL-encoded query
/// string.
///
/// We don't pull `serde_urlencoded` in as a direct dep — fall back
/// to a JSON-walk encoder that covers the (small, flat) query
/// shapes the secrets API uses. Every field of the query struct
/// must serialize to a scalar (string / number / bool / null) or be
/// `None`. The secrets API queries all satisfy this: limit /
/// sensitivity / pattern / source_message_id / created_after /
/// created_before / accessor / since / until / secret_uuid are all
/// scalar-or-None.
fn serde_urlencoded_query<T: serde::Serialize>(value: &T) -> Result<String, SecretsError> {
    let v = serde_json::to_value(value)
        .map_err(|e| SecretsError::Internal(format!("query serialize: {e}")))?;
    let obj = v
        .as_object()
        .ok_or_else(|| SecretsError::Internal("query value must be an object".into()))?;
    let mut pairs: Vec<(String, String)> = Vec::with_capacity(obj.len());
    for (k, val) in obj {
        match val {
            serde_json::Value::Null => {}
            serde_json::Value::String(s) => pairs.push((k.clone(), s.clone())),
            serde_json::Value::Number(n) => pairs.push((k.clone(), n.to_string())),
            serde_json::Value::Bool(b) => pairs.push((k.clone(), b.to_string())),
            other => {
                return Err(SecretsError::Internal(format!(
                    "non-scalar query field {k:?}: {other}"
                )));
            }
        }
    }
    let mut out = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in &pairs {
        out.append_pair(k, v);
    }
    Ok(out.finish())
}

/// Map an HTTP error response to a typed [`SecretsError`]. Falls
/// back to [`SecretsError::Backend`] when the body isn't a
/// parseable [`SecretsErrorResponse`].
async fn map_error_response(resp: reqwest::Response) -> SecretsError {
    let status = resp.status();
    let body: Result<SecretsErrorResponse, _> = resp.json().await;
    if let Ok(err) = body {
        match err.kind.as_str() {
            "secrets_not_found" => SecretsError::NotFound(err.detail),
            "secrets_invalid_argument" | "secrets_invalid_body" => {
                SecretsError::InvalidArgument(err.detail)
            }
            "secrets_not_authorized"
            | "secrets_signature_missing"
            | "secrets_signature_invalid"
            | "secrets_signature_unknown_key" => SecretsError::NotAuthorized(err.detail),
            "secrets_crypto" => SecretsError::Crypto(err.detail),
            "secrets_rotation_conflict" => SecretsError::RotationConflict(err.detail),
            "secrets_hw_unavailable" => SecretsError::HardwareKeyUnavailable(err.detail),
            "secrets_internal" => SecretsError::Internal(err.detail),
            "secrets_backend" => SecretsError::Backend(err.detail),
            _ => SecretsError::Backend(format!("HTTP {status}: {} {}", err.kind, err.detail)),
        }
    } else {
        // Surface unparseable bodies. Map known status families.
        match status {
            StatusCode::NOT_FOUND => SecretsError::NotFound(format!("HTTP {status}")),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                SecretsError::NotAuthorized(format!("HTTP {status}"))
            }
            StatusCode::CONFLICT => SecretsError::RotationConflict(format!("HTTP {status}")),
            _ => SecretsError::Backend(format!("HTTP {status}: <unparseable body>")),
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{LocalSigner, LocalSignerConfig};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_seed(seed: &[u8; 32]) -> NamedTempFile {
        let mut f = NamedTempFile::new().expect("tempfile");
        f.write_all(seed).expect("write seed");
        f.flush().expect("flush");
        f
    }

    fn make_signer() -> Arc<LocalSigner> {
        let seed = [0x5Au8; 32];
        let f = write_seed(&seed);
        Arc::new(
            LocalSigner::from_config(&LocalSignerConfig {
                key_id: "test-steward".into(),
                key_path: f.path().to_path_buf(),
                pqc_key_id: None,
                pqc_key_path: None,
            })
            .expect("load signer"),
        )
    }

    #[test]
    fn client_construct_succeeds_with_default_settings() {
        let signer = make_signer();
        let url = Url::parse("https://persist.example.com").unwrap();
        let client = FederatedSecretsClient::new(url, signer).expect("construct");
        // Debug shape exposes base_url + local_key_id; no secrets.
        let dbg = format!("{client:?}");
        assert!(dbg.contains("persist.example.com"));
        assert!(dbg.contains("test-steward"));
    }

    /// `sign_body` emits the two signature headers (Ed25519-only
    /// when PQC isn't configured).
    #[tokio::test]
    async fn sign_body_ed25519_only_when_no_pqc() {
        let signer = make_signer();
        let url = Url::parse("https://persist.example.com").unwrap();
        let client = FederatedSecretsClient::new(url, signer).expect("construct");
        let headers = client.sign_body(b"hello").await.expect("sign");
        assert_eq!(headers.len(), 2);
        assert_eq!(headers[0].0, HEADER_KEY_ID);
        assert_eq!(headers[0].1, "test-steward");
        assert_eq!(headers[1].0, HEADER_ED25519);
        // Decoded sig should be 64 bytes (Ed25519 sig length).
        let sig = BASE64.decode(&headers[1].1).expect("base64 decode");
        assert_eq!(sig.len(), 64);
    }

    /// `url(path)` joins paths correctly off the base URL.
    #[test]
    fn url_join_paths() {
        let signer = make_signer();
        let url = Url::parse("https://persist.example.com/").unwrap();
        let client = FederatedSecretsClient::new(url, signer).expect("construct");
        let u = client.url("/api/v1/secrets/store").expect("join");
        assert_eq!(
            u.as_str(),
            "https://persist.example.com/api/v1/secrets/store"
        );
    }

    /// Server returns 404 + secrets_not_found → client maps to
    /// `SecretsError::NotFound`. `retrieve_secret` swallows the
    /// 404 into `Ok(None)` (matching the trait shape).
    #[tokio::test]
    async fn error_response_maps_to_typed_secrets_error() {
        // Spin up a one-shot HTTP server using std::net + handle
        // one request, returning a typed error body. This avoids
        // adding wiremock / mockito as a dev-dep.
        use std::io::Read as _;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();

        // Server task — responds with 404 + secrets_not_found.
        let server = tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).ok();
            let body = serde_json::to_string(&SecretsErrorResponse {
                kind: "secrets_not_found".into(),
                detail: "no such secret".into(),
            })
            .unwrap();
            let response = format!(
                "HTTP/1.1 404 Not Found\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            use std::io::Write as _;
            sock.write_all(response.as_bytes()).ok();
        });

        let signer = make_signer();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let client = FederatedSecretsClient::new(url, signer).expect("construct");
        let res = client
            .retrieve_secret("00000000-0000-0000-0000-000000000000", "test".into())
            .await;
        server.await.ok();
        // retrieve_secret swallows NotFound → None.
        assert!(matches!(res, Ok(None)), "got: {res:?}");
    }

    /// Server returns 409 + secrets_rotation_conflict → client
    /// maps to `SecretsError::RotationConflict`.
    #[tokio::test]
    async fn rotation_conflict_maps_to_typed_error() {
        use std::io::Read as _;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf).ok();
            let body = serde_json::to_string(&SecretsErrorResponse {
                kind: "secrets_rotation_conflict".into(),
                detail: "concurrent rotation".into(),
            })
            .unwrap();
            let response = format!(
                "HTTP/1.1 409 Conflict\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            use std::io::Write as _;
            sock.write_all(response.as_bytes()).ok();
        });

        let signer = make_signer();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let client = FederatedSecretsClient::new(url, signer).expect("construct");
        let res = client.rotate_master_key(None, "test".into()).await;
        server.await.ok();
        assert!(
            matches!(res, Err(SecretsError::RotationConflict(_))),
            "got: {res:?}"
        );
    }

    /// Round-trip a `store_secret` call: assert the client sends
    /// the signed request body + headers correctly + parses the
    /// 200 response.
    #[tokio::test]
    async fn store_secret_round_trip_against_mock_server() {
        use std::io::Read as _;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();

        // Capture the request the client sent so we can assert on
        // it.
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let server = tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).expect("read");
            buf.truncate(n);
            tx.send(buf).ok();
            let body = serde_json::to_string(&StoreSecretResponse {
                description: "k".into(),
                sensitivity: Sensitivity::Medium,
                status: "stored".into(),
            })
            .unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            use std::io::Write as _;
            sock.write_all(response.as_bytes()).ok();
        });

        let signer = make_signer();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let client = FederatedSecretsClient::new(url, signer).expect("construct");
        client
            .store_secret("k".into(), "v".into(), "a".into())
            .await
            .expect("store ok");
        let raw = rx.recv().expect("server captured the request");
        server.await.ok();

        let text = String::from_utf8_lossy(&raw);
        // Method + path.
        assert!(
            text.starts_with("POST /api/v1/secrets/store"),
            "got: {text}"
        );
        // Signature headers present.
        assert!(
            text.to_ascii_lowercase()
                .contains("x-ciris-signing-key-id: test-steward"),
            "missing key-id header in: {text}"
        );
        assert!(
            text.to_ascii_lowercase()
                .contains("x-ciris-signature-ed25519:"),
            "missing ed25519 header in: {text}"
        );
        // Body carries the wire shape.
        assert!(text.contains("\"plaintext\":\"v\""));
        assert!(text.contains("\"description\":\"k\""));
        assert!(text.contains("\"accessor\":\"a\""));
    }

    /// Try-claim round trip: server returns `already_claimed`
    /// outcome with a 200 status (matches the server's
    /// `post_try_claim` shape — both variants are 200 + the
    /// outcome distinguishes).
    #[tokio::test]
    async fn try_claim_returns_already_claimed_outcome() {
        use std::io::Read as _;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::task::spawn_blocking(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut buf = vec![0u8; 8192];
            let _ = sock.read(&mut buf).ok();
            let reference = SecretReference {
                uuid: "11111111-2222-3333-4444-555555555555".into(),
                description: "k".into(),
                context_hint: None,
                sensitivity: Sensitivity::Medium,
                detected_pattern: "manual".into(),
                auto_decapsulate_actions: vec![],
                created_at: chrono::Utc::now(),
                last_accessed: None,
            };
            let body = serde_json::to_string(&ClaimResultWire {
                outcome: "already_claimed".into(),
                reference,
            })
            .unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            use std::io::Write as _;
            sock.write_all(response.as_bytes()).ok();
        });

        let signer = make_signer();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let client = FederatedSecretsClient::new(url, signer).expect("construct");
        let res = client
            .try_claim_secret("p", "k", Sensitivity::Medium, vec![], "a".into())
            .await
            .expect("try_claim ok");
        server.await.ok();
        assert!(matches!(res, ClaimResult::AlreadyClaimed(_)));
        assert_eq!(res.reference().uuid, "11111111-2222-3333-4444-555555555555");
    }

    /// In-process-only methods return `Internal` /
    /// `HardwareKeyUnavailable` without making an HTTP call.
    #[tokio::test]
    async fn local_only_methods_return_typed_errors() {
        let signer = make_signer();
        let url = Url::parse("https://nowhere.invalid/").unwrap();
        let client = FederatedSecretsClient::new(url, signer).expect("construct");
        assert!(matches!(
            client.process_incoming_text("x", "y", "z".into()).await,
            Err(SecretsError::Internal(_))
        ));
        assert!(matches!(
            client
                .decapsulate_secrets_in_parameters(
                    "tool",
                    serde_json::json!({}),
                    DecapsulationContext {
                        action_type: "tool".into(),
                        accessor: "a".into(),
                        purpose: "p".into(),
                        trace_id: None,
                        thought_id: None,
                    },
                )
                .await,
            Err(SecretsError::Internal(_))
        ));
        assert!(matches!(
            client.test_encryption().await,
            Err(SecretsError::Internal(_))
        ));
        assert!(matches!(
            client.migrate_to_hardware_key("a".into()).await,
            Err(SecretsError::HardwareKeyUnavailable(_))
        ));
    }
}
