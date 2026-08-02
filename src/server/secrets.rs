//! v1.1.0 (CIRISPersist#33 part 4a): secrets-server axum routes.
//!
//! Mirrors the 18-method [`SecretsService`] trait surface (15 of
//! which are HTTP-exposed; the 3 in-process-only methods —
//! `process_incoming_text`, `decapsulate_secrets_in_parameters`,
//! `test_encryption`, `migrate_to_hardware_key` — stay behind the
//! trait). FederatedSecretsClient (`src/secrets/client.rs`,
//! deferred to a separate task) calls these routes so consumer
//! code can swap in-process ↔ federated transparently.
//!
//! # Trait-shape constraint
//!
//! The [`SecretsService`] trait uses Rust 1.75 `impl Future + Send`
//! return-position syntax (RPITIT), which is NOT object-safe.
//! Composing the secrets routes therefore parameterizes the
//! sub-state generically over `S: SecretsService` rather than
//! hiding the impl behind `Arc<dyn SecretsService>`. The shape
//! mirrors how the pipeline ingest route parameterizes over
//! `F: FederationDirectory` (`server/mod.rs::AppState`).
//!
//! # Hybrid-verify on the wire
//!
//! Every mutating request body must be hybrid-signed by the
//! steward (`X-Ciris-Signing-Key-Id` + `X-Ciris-Signature-Ed25519` +
//! optional `X-Ciris-Signature-MlDsa-65` headers). Persist
//! verifies via the existing
//! [`crate::verify::verify_hybrid_via_directory`] path — same
//! directory the legacy trace-verify route consults. GET routes
//! are read-only and also signature-verify on the URI path bytes
//! (an empty body is canonicalized as `""`).
//!
//! Reject 401 on signature failure; 403 on role-tag failure (NOT
//! enforced today — see FSD §5 role-tag deferral below); 400 on
//! malformed body; 404 on not-found; 500 on backend; 503 on
//! backend-unavailable.
//!
//! # Role-tag enforcement (deferred)
//!
//! FSD §5 specifies three role tiers — `cirislens_secrets_reader`
//! / `cirislens_secrets_writer` / `cirislens_secrets_admin`. The
//! current [`crate::federation::types::KeyRecord`] schema carries
//! `identity_type` + `identity_ref` but no role list. v1.1.0
//! accepts any directory-registered key (no role-tag enforcement)
//! and defers the schema addition (V020+ migration) to a v1.1.x
//! follow-up. Same gap-pattern as `src/server/pipeline.rs`.
//!
//! [`SecretsService`]: crate::secrets::SecretsService

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use crate::federation::FederationDirectory;
use crate::secrets::types::MasterKeyRef;
use crate::secrets::wire::{
    AccessLogsQuery, AccessLogsResponse, ClaimResultWire, DecryptRequest, DecryptResponse,
    EncryptRequest, EncryptResponse, FilterConfigResponse, FilterConfigUpdateRequest,
    FilterConfigUpdateResponse, ForgetSecretQuery, ForgetSecretResponse, HealthResponse,
    ListSecretsQuery, ListSecretsResponse, RecallSecretRequest, RecallSecretResponse,
    ReencryptAllRequest, ReencryptAllResponse, RetrieveSecretQuery, RetrieveSecretResponse,
    RotateMasterKeyRequest, RotateMasterKeyResponse, SecretsErrorResponse, StatsResponse,
    StoreSecretRequest, StoreSecretResponse, TryClaimSecretRequest,
};
use crate::secrets::{SecretsError, SecretsService};
use crate::store::Backend;
use crate::verify::hybrid::VerifyError;
use crate::verify::{verify_hybrid_via_directory, HybridPolicy};
use crate::ClaimResult;

// ── Hybrid-verify header tokens ────────────────────────────────────

/// Header carrying the steward's `federation_keys.key_id`.
pub const HEADER_KEY_ID: &str = "x-ciris-signing-key-id";
/// Header carrying the Ed25519 signature (base64) over the request
/// body bytes.
pub const HEADER_ED25519: &str = "x-ciris-signature-ed25519";
/// Header carrying the ML-DSA-65 signature (base64). Optional
/// during the hybrid-pending rollout window (HybridPolicy::Ed25519Fallback).
pub const HEADER_ML_DSA_65: &str = "x-ciris-signature-ml-dsa-65";

// ── v1.3.0 (CIRISPersist#46) — Role-tag tiers ──────────────────────

/// Read-only secrets routes (`get_list` / `get_retrieve` /
/// `get_filter_config` / `get_stats` / `get_health` /
/// `get_access_logs`) require this role tag (or any higher tier).
pub const ROLE_SECRETS_READER: &str = "cirislens_secrets_reader";
/// Mutating secrets routes (`post_store` / `post_try_claim` /
/// `post_encrypt` / `post_decrypt` / `post_recall` /
/// `post_reencrypt_all` / `delete_forget` / `put_filter_config`)
/// require this role tag (or any higher tier).
pub const ROLE_SECRETS_WRITER: &str = "cirislens_secrets_writer";
/// Master-key rotation (`post_rotate_master_key`) requires this
/// role tag.
pub const ROLE_SECRETS_ADMIN: &str = "cirislens_secrets_admin";

/// Stable error kind token for role-tag rejection (403).
pub const KIND_ROLE_TAG: &str = "secrets_role_tag";

/// Tier required by a route — used by [`require_role`] to gate
/// access. Higher tiers implicitly satisfy lower tiers
/// (admin > writer > reader).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretsTier {
    Reader,
    Writer,
    Admin,
}

impl SecretsTier {
    fn allowed_roles(self) -> &'static [&'static str] {
        match self {
            Self::Reader => &[ROLE_SECRETS_READER, ROLE_SECRETS_WRITER, ROLE_SECRETS_ADMIN],
            Self::Writer => &[ROLE_SECRETS_WRITER, ROLE_SECRETS_ADMIN],
            Self::Admin => &[ROLE_SECRETS_ADMIN],
        }
    }
}

/// Look up the caller's KeyRecord and require at least one role tag
/// matching `tier`. Returns 403 on missing tag, 503 on backend
/// lookup failure, 401 on missing/malformed key_id header.
async fn require_role<F>(
    directory: &F,
    headers: &HeaderMap,
    tier: SecretsTier,
) -> Result<(), Response>
where
    F: FederationDirectory,
{
    let key_id = headers
        .get(HEADER_KEY_ID)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            error_response(
                StatusCode::UNAUTHORIZED,
                "secrets_signature_missing",
                format!("missing {} header", HEADER_KEY_ID),
            )
        })?;
    let record = directory.lookup_public_key(key_id).await.map_err(|e| {
        tracing::error!(error = %e, key_id, "role-tag lookup failed");
        error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "secrets_directory_unavailable",
            format!("{e}"),
        )
    })?;
    let record = record.ok_or_else(|| {
        error_response(
            StatusCode::FORBIDDEN,
            KIND_ROLE_TAG,
            format!("unknown key_id {key_id}"),
        )
    })?;
    let allowed = tier.allowed_roles();
    let has_role = record
        .capability_roles
        .iter()
        .any(|r| allowed.contains(&r.as_str()));
    if !has_role {
        tracing::warn!(
            key_id, roles = ?record.capability_roles, tier = ?tier,
            "secrets route rejected: role-tag missing"
        );
        return Err(error_response(
            StatusCode::FORBIDDEN,
            KIND_ROLE_TAG,
            format!(
                "key {} missing required role for {:?} tier (allowed: {:?})",
                key_id, tier, allowed
            ),
        ));
    }
    Ok(())
}

// ── State ──────────────────────────────────────────────────────────

/// Shared state for the secrets sub-router.
///
/// Generic over `S: SecretsService` (RPITIT trait — see module doc
/// for the dyn-safety rationale) and `F: FederationDirectory` for
/// the hybrid-verify lookup path.
pub struct SecretsAppState<S, F>
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    /// Concrete SecretsService backend (typically
    /// [`crate::secrets::postgres::PostgresBackend`] or
    /// [`crate::secrets::sqlite::SqliteSecretsBackend`]).
    pub service: Arc<S>,
    /// Federation directory used to look up the steward's hybrid
    /// pubkey pair for inbound request-body signature verification.
    pub directory: Arc<F>,
}

// Manual `Clone` impl — derive would require `S: Clone` + `F: Clone`,
// but `Arc<_>` clones are cheap regardless.
impl<S, F> Clone for SecretsAppState<S, F>
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    fn clone(&self) -> Self {
        Self {
            service: self.service.clone(),
            directory: self.directory.clone(),
        }
    }
}

// ── Router builder ─────────────────────────────────────────────────

/// Build the secrets sub-router. Compose into the top-level
/// `server::router` via `Router::merge`.
pub fn router<S, F>(state: SecretsAppState<S, F>) -> Router
where
    S: SecretsService + Send + Sync + 'static,
    F: FederationDirectory + Backend + Send + Sync + 'static,
{
    Router::new()
        .route("/api/v1/secrets/store", post(post_store::<S, F>))
        .route("/api/v1/secrets/try_claim", post(post_try_claim::<S, F>))
        .route("/api/v1/secrets/encrypt", post(post_encrypt::<S, F>))
        .route("/api/v1/secrets/decrypt", post(post_decrypt::<S, F>))
        .route(
            "/api/v1/secrets/filter_config",
            get(get_filter_config::<S, F>).put(put_filter_config::<S, F>),
        )
        .route("/api/v1/secrets/stats", get(get_stats::<S, F>))
        .route("/api/v1/secrets/health", get(get_health::<S, F>))
        .route("/api/v1/secrets/access_logs", get(get_access_logs::<S, F>))
        .route(
            "/api/v1/secrets/reencrypt_all",
            post(post_reencrypt_all::<S, F>),
        )
        .route(
            "/api/v1/secrets/rotate_master_key",
            post(post_rotate_master_key::<S, F>),
        )
        .route("/api/v1/secrets", get(get_list::<S, F>))
        .route(
            "/api/v1/secrets/{uuid}",
            get(get_retrieve::<S, F>).delete(delete_forget::<S, F>),
        )
        .route("/api/v1/secrets/{uuid}/recall", post(post_recall::<S, F>))
        .with_state(state)
}

// ── Signature verification helper ──────────────────────────────────

/// Outcome of header signature extraction.
struct SignedRequest {
    /// Steward `key_id`.
    key_id: String,
    /// Base64 Ed25519 signature.
    ed25519: String,
    /// Optional base64 ML-DSA-65 signature.
    ml_dsa_65: Option<String>,
}

// clippy::result_large_err (new in 1.97, only trips under a wide
// `--all-features` clippy pass — CI's narrower feature set never hit it):
// the `Err` arm is an axum `Response`, which IS the intended short-circuit
// return for an HTTP handler helper (an early `Response` back out through
// `?`); boxing it would only add an indirection with no behavior change.
#[allow(clippy::result_large_err)]
fn extract_signatures(headers: &HeaderMap) -> Result<SignedRequest, Response> {
    let key_id = headers
        .get(HEADER_KEY_ID)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            error_response(
                StatusCode::UNAUTHORIZED,
                "secrets_signature_missing",
                format!("missing {} header", HEADER_KEY_ID),
            )
        })?
        .to_owned();
    let ed25519 = headers
        .get(HEADER_ED25519)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            error_response(
                StatusCode::UNAUTHORIZED,
                "secrets_signature_missing",
                format!("missing {} header", HEADER_ED25519),
            )
        })?
        .to_owned();
    let ml_dsa_65 = headers
        .get(HEADER_ML_DSA_65)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());
    Ok(SignedRequest {
        key_id,
        ed25519,
        ml_dsa_65,
    })
}

/// Verify the request signature against the federation directory,
/// then enforce the role-tag tier for this route. On failure, returns
/// a 401 (signature) or 403 (role) response.
///
/// v1.3.0 (CIRISPersist#46): `tier` gates which `federation_keys.roles`
/// values are accepted (admin > writer > reader). Pre-V020 rows have
/// empty `roles` → reject. Routes that need reader-tier access pass
/// [`SecretsTier::Reader`]; mutating routes pass [`SecretsTier::Writer`];
/// master-key rotation passes [`SecretsTier::Admin`].
async fn verify_and_authorize<F>(
    directory: &F,
    headers: &HeaderMap,
    body: &[u8],
    tier: SecretsTier,
) -> Result<(), Response>
where
    F: FederationDirectory,
{
    verify_request(directory, headers, body).await?;
    require_role(directory, headers, tier).await
}

/// Verify the request signature against the federation directory.
/// On failure, returns a 401 response ready to surface to the caller.
async fn verify_request<F>(directory: &F, headers: &HeaderMap, body: &[u8]) -> Result<(), Response>
where
    F: FederationDirectory,
{
    let sig = extract_signatures(headers)?;
    // HybridPolicy::Ed25519Fallback matches the pipeline ingest
    // route — the federation rolls out hybrid-pending steward keys
    // (Ed25519 first, ML-DSA-65 cold-path attach). Production posture
    // flips to Strict once steward keys are PQC-complete fleet-wide.
    let outcome = verify_hybrid_via_directory(
        directory,
        body,
        &sig.key_id,
        &sig.ed25519,
        sig.ml_dsa_65.as_deref(),
        HybridPolicy::Ed25519Fallback,
        None,
    )
    .await;
    match outcome {
        Ok(_) => Ok(()),
        Err(e) => {
            let kind = match &e {
                VerifyError::Crypto(msg) if msg.contains("verify_unknown_key") => {
                    "secrets_signature_unknown_key"
                }
                _ => "secrets_signature_invalid",
            };
            tracing::warn!(
                error = %e,
                key_id = %sig.key_id,
                "secrets route rejected: signature verification failed"
            );
            Err(error_response(
                StatusCode::UNAUTHORIZED,
                kind,
                format!("{e}"),
            ))
        }
    }
}

// ── Error mapping ──────────────────────────────────────────────────

/// Map a [`SecretsError`] into a typed HTTP response carrying the
/// AV-15 kind token plus the variant's `Display` detail (the same
/// shape the pipeline ingest route uses).
fn map_secrets_error(e: SecretsError) -> Response {
    let status = match &e {
        SecretsError::InvalidArgument(_) => StatusCode::BAD_REQUEST,
        SecretsError::NotAuthorized(_) => StatusCode::FORBIDDEN,
        SecretsError::NotFound(_) => StatusCode::NOT_FOUND,
        SecretsError::Crypto(_) => StatusCode::INTERNAL_SERVER_ERROR,
        SecretsError::Backend(_) => StatusCode::SERVICE_UNAVAILABLE,
        SecretsError::HardwareKeyUnavailable(_) => StatusCode::NOT_IMPLEMENTED,
        SecretsError::RotationConflict(_) => StatusCode::CONFLICT,
        SecretsError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    error_response(status, e.kind(), format!("{e}"))
}

fn error_response(status: StatusCode, kind: &str, detail: String) -> Response {
    (
        status,
        Json(SecretsErrorResponse {
            kind: kind.to_owned(),
            detail,
        }),
    )
        .into_response()
}

// clippy::result_large_err — see `extract_signatures`'s comment above; same
// intended-early-Response shape.
#[allow(clippy::result_large_err)]
fn parse_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, Response> {
    serde_json::from_slice(body).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "secrets_invalid_body",
            format!("JSON decode: {e}"),
        )
    })
}

// ── Handlers ───────────────────────────────────────────────────────

/// `POST /api/v1/secrets/store` — manually-keyed encrypt-and-store.
async fn post_store<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &body, SecretsTier::Writer).await
    {
        return r;
    }
    let req: StoreSecretRequest = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state
        .service
        .store_secret(req.description.clone(), req.plaintext, req.accessor)
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(StoreSecretResponse {
                description: req.description,
                sensitivity: req.sensitivity,
                status: "stored".to_owned(),
            }),
        )
            .into_response(),
        Err(e) => map_secrets_error(e),
    }
}

/// `POST /api/v1/secrets/try_claim` — atomic-claim store.
async fn post_try_claim<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &body, SecretsTier::Writer).await
    {
        return r;
    }
    let req: TryClaimSecretRequest = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state
        .service
        .try_claim_secret(
            &req.plaintext,
            &req.description,
            req.sensitivity,
            req.auto_decapsulate_for_actions,
            req.accessor,
        )
        .await
    {
        Ok(ClaimResult::Stored(reference)) => (
            StatusCode::OK,
            Json(ClaimResultWire {
                outcome: "stored".into(),
                reference,
            }),
        )
            .into_response(),
        Ok(ClaimResult::AlreadyClaimed(reference)) => (
            StatusCode::OK,
            Json(ClaimResultWire {
                outcome: "already_claimed".into(),
                reference,
            }),
        )
            .into_response(),
        Err(e) => map_secrets_error(e),
    }
}

/// `GET /api/v1/secrets/{uuid}?accessor=...` — retrieve plaintext.
///
/// Diverges from the trait's `retrieve_secret(key, accessor)`
/// shape (key = description). The route is UUID-keyed for
/// federation addressability; under the hood it calls
/// `recall_secret(uuid, purpose="http retrieve", accessor,
/// decrypt=true)` which is the UUID-keyed read path.
async fn get_retrieve<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
    Path(uuid): Path<String>,
    Query(q): Query<RetrieveSecretQuery>,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    // GET routes verify on the empty body (matches the
    // edge-signature convention for the pipeline route at the
    // wire-canonicalization layer).
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &[], SecretsTier::Reader).await
    {
        return r;
    }
    match state
        .service
        .recall_secret(&uuid, "http retrieve".into(), q.accessor, true)
        .await
    {
        Ok(Some(result)) if result.found => match result.value {
            Some(value) => (
                StatusCode::OK,
                Json(RetrieveSecretResponse {
                    uuid: uuid.clone(),
                    value,
                }),
            )
                .into_response(),
            None => error_response(
                StatusCode::FORBIDDEN,
                "secrets_not_authorized",
                result.error.unwrap_or_else(|| "decrypt refused".to_owned()),
            ),
        },
        Ok(Some(_)) | Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "secrets_not_found",
            format!("no secret with uuid {uuid}"),
        ),
        Err(e) => map_secrets_error(e),
    }
}

/// `POST /api/v1/secrets/{uuid}/recall` — UUID-keyed read; can
/// return metadata-only or plaintext.
async fn post_recall<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
    Path(uuid): Path<String>,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &body, SecretsTier::Writer).await
    {
        return r;
    }
    let req: RecallSecretRequest = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state
        .service
        .recall_secret(&uuid, req.purpose, req.accessor, req.decrypt)
        .await
    {
        Ok(Some(result)) => (StatusCode::OK, Json::<RecallSecretResponse>(result)).into_response(),
        Ok(None) => error_response(
            StatusCode::NOT_FOUND,
            "secrets_not_found",
            format!("no secret with uuid {uuid}"),
        ),
        Err(e) => map_secrets_error(e),
    }
}

/// `GET /api/v1/secrets` — metadata-only listing.
async fn get_list<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
    Query(q): Query<ListSecretsQuery>,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &[], SecretsTier::Reader).await
    {
        return r;
    }
    let (limit, filter) = q.into_filter();
    match state.service.list_stored_secrets(limit, filter).await {
        Ok(items) => (StatusCode::OK, Json(ListSecretsResponse { items })).into_response(),
        Err(e) => map_secrets_error(e),
    }
}

/// `DELETE /api/v1/secrets/{uuid}?accessor=...` — audited delete.
async fn delete_forget<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
    Path(uuid): Path<String>,
    Query(q): Query<ForgetSecretQuery>,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &[], SecretsTier::Writer).await
    {
        return r;
    }
    match state.service.forget_secret(&uuid, q.accessor).await {
        Ok(deleted) => (StatusCode::OK, Json(ForgetSecretResponse { deleted })).into_response(),
        Err(e) => map_secrets_error(e),
    }
}

/// `POST /api/v1/secrets/encrypt` — direct AES-GCM encrypt.
async fn post_encrypt<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &body, SecretsTier::Writer).await
    {
        return r;
    }
    let req: EncryptRequest = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state.service.encrypt(&req.plaintext).await {
        Ok(ciphertext) => (StatusCode::OK, Json(EncryptResponse { ciphertext })).into_response(),
        Err(e) => map_secrets_error(e),
    }
}

/// `POST /api/v1/secrets/decrypt` — direct AES-GCM decrypt.
///
/// The trait's `decrypt(&str)` takes the base64 blob the matching
/// `encrypt` produced; this route forwards verbatim. The wire
/// shape carries the base64 string in a JSON body so the entire
/// request stays signed in one canonical bundle (a raw binary
/// body would split the canonicalization story for the steward).
async fn post_decrypt<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &body, SecretsTier::Writer).await
    {
        return r;
    }
    let req: DecryptRequest = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state.service.decrypt(&req.ciphertext).await {
        Ok(plaintext) => (StatusCode::OK, Json(DecryptResponse { plaintext })).into_response(),
        Err(e) => map_secrets_error(e),
    }
}

/// `GET /api/v1/secrets/filter_config` — read current pattern catalog.
async fn get_filter_config<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &[], SecretsTier::Reader).await
    {
        return r;
    }
    match state.service.get_filter_config().await {
        Ok(cfg) => (StatusCode::OK, Json::<FilterConfigResponse>(cfg)).into_response(),
        Err(e) => map_secrets_error(e),
    }
}

/// `PUT /api/v1/secrets/filter_config` — write a new pattern catalog.
///
/// PUT shape requires an explicit accessor header field — the
/// trait method needs it for audit. We accept it via the body
/// (the wire request type is the existing
/// [`FilterUpdateRequest`]; we extract accessor from the
/// signing-key-id header so callers don't duplicate it).
async fn put_filter_config<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &body, SecretsTier::Writer).await
    {
        return r;
    }
    let req: FilterConfigUpdateRequest = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    // Use the signing key_id as the accessor for audit — the
    // request is already authenticated to that key. v1.1.x
    // follow-up: add an explicit accessor field to the body.
    let accessor = headers
        .get(HEADER_KEY_ID)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_owned();
    match state.service.update_filter_config(req, accessor).await {
        Ok(result) => (StatusCode::OK, Json::<FilterConfigUpdateResponse>(result)).into_response(),
        Err(e) => map_secrets_error(e),
    }
}

/// `GET /api/v1/secrets/stats` — service-wide stats.
async fn get_stats<S, F>(State(state): State<SecretsAppState<S, F>>, headers: HeaderMap) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &[], SecretsTier::Reader).await
    {
        return r;
    }
    match state.service.get_service_stats().await {
        Ok(stats) => (StatusCode::OK, Json::<StatsResponse>(stats)).into_response(),
        Err(e) => map_secrets_error(e),
    }
}

/// `GET /api/v1/secrets/health` — liveness probe.
///
/// Unsigned in v1.1.0 — health probes need to reach the route
/// without consulting the directory. Same convention as the
/// top-level `GET /health` route. v1.1.x may add an
/// optional-signature path if operators want auditable health
/// probes.
async fn get_health<S, F>(State(state): State<SecretsAppState<S, F>>) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    match state.service.is_healthy().await {
        Ok(is_healthy) => (StatusCode::OK, Json(HealthResponse { is_healthy })).into_response(),
        Err(e) => map_secrets_error(e),
    }
}

/// `GET /api/v1/secrets/access_logs` — paginated audit trail.
async fn get_access_logs<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
    Query(q): Query<AccessLogsQuery>,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &[], SecretsTier::Reader).await
    {
        return r;
    }
    let secret_uuid = q.secret_uuid.as_deref();
    match state.service.get_access_logs(secret_uuid, q.limit).await {
        Ok(mut items) => {
            // Apply client-side filters for accessor / since /
            // until — the trait method doesn't yet expose these.
            // Persister-side push-down is a v1.1.x follow-up.
            if let Some(acc) = q.accessor.as_deref() {
                items.retain(|e| e.accessor == acc);
            }
            if let Some(since) = q.since {
                items.retain(|e| e.created_at >= since);
            }
            if let Some(until) = q.until {
                items.retain(|e| e.created_at < until);
            }
            (StatusCode::OK, Json(AccessLogsResponse { items })).into_response()
        }
        Err(e) => map_secrets_error(e),
    }
}

/// `POST /api/v1/secrets/reencrypt_all` — re-encrypt every stored
/// secret under a new master key.
async fn post_reencrypt_all<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &body, SecretsTier::Writer).await
    {
        return r;
    }
    let req: ReencryptAllRequest = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let _new_master_bytes = match BASE64.decode(req.new_master_key_bytes_b64.as_bytes()) {
        Ok(b) => b,
        Err(e) => {
            return error_response(
                StatusCode::BAD_REQUEST,
                "secrets_invalid_argument",
                format!("new_master_key_bytes_b64 decode: {e}"),
            );
        }
    };
    // The trait method accepts a MasterKeyRef (Software / Hardware
    // variant), not raw bytes — the backend resolves the handle
    // against its in-process software-key cache. Today the route
    // forwards the operator-supplied handle (or generates one)
    // and trusts the backend to load the bytes into the cache out
    // of band. v1.1.x will fold bytes-loading into the wire path.
    let handle = req
        .new_master_handle
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let new_master_key_ref = MasterKeyRef::Software { handle };
    match state
        .service
        .reencrypt_all(new_master_key_ref, req.accessor)
        .await
    {
        Ok(result) => (StatusCode::OK, Json::<ReencryptAllResponse>(result)).into_response(),
        Err(e) => map_secrets_error(e),
    }
}

/// `POST /api/v1/secrets/rotate_master_key` — rotate to a fresh
/// master key (generated when `new_master_b64` is absent).
async fn post_rotate_master_key<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) =
        verify_and_authorize(&*state.directory, &headers, &body, SecretsTier::Admin).await
    {
        return r;
    }
    let req: RotateMasterKeyRequest = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let new_master = match req.new_master_b64.as_deref() {
        None => None,
        Some(b64) => match BASE64.decode(b64.as_bytes()) {
            Ok(b) => Some(b),
            Err(e) => {
                return error_response(
                    StatusCode::BAD_REQUEST,
                    "secrets_invalid_argument",
                    format!("new_master_b64 decode: {e}"),
                );
            }
        },
    };
    match state
        .service
        .rotate_master_key(new_master, req.accessor)
        .await
    {
        Ok(key_ref) => (StatusCode::OK, Json::<RotateMasterKeyResponse>(key_ref)).into_response(),
        Err(e) => map_secrets_error(e),
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::federation::{
        types::{algorithm, identity_type},
        KeyRecord, SignedKeyRecord,
    };
    use crate::secrets::sqlite::SqliteSecretsBackend;
    use crate::store::sqlite::SqliteBackend;
    use axum::body::Body;
    use axum::http::Request;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Fixed signing seed for the steward — tests are reproducible.
    const STEWARD_SEED: [u8; 32] = [0x5Au8; 32];
    /// `key_id` the steward identifies itself by in `federation_keys`.
    const STEWARD_KEY_ID: &str = "secrets-steward-test-1";

    async fn build_app() -> (Router, Arc<SqliteSecretsBackend>, Arc<SqliteBackend>) {
        let backend = Arc::new(SqliteBackend::open_in_memory().await.unwrap());
        backend.run_migrations().await.unwrap();
        // Seed the steward key in federation_keys.
        let sk = SigningKey::from_bytes(&STEWARD_SEED);
        let vk: VerifyingKey = sk.verifying_key();
        let pubkey_b64 = BASE64.encode(vk.to_bytes());
        let key = KeyRecord {
            key_id: STEWARD_KEY_ID.into(),
            pubkey_ed25519_base64: pubkey_b64,
            pubkey_ml_dsa_65_base64: None,
            algorithm: algorithm::HYBRID.into(),
            identity_type: identity_type::PRIMITIVE.into(),
            identity_ref: "steward".into(),
            valid_from: "2026-01-01T00:00:00Z".parse().unwrap(),
            valid_until: None,
            registration_envelope: serde_json::json!({"id": STEWARD_KEY_ID}),
            original_content_hash: "deadbeef".into(),
            scrub_signature_classical: "c2lnbmF0dXJl".into(),
            scrub_signature_pqc: None,
            scrub_key_id: STEWARD_KEY_ID.into(),
            scrub_timestamp: "2026-05-01T00:00:00Z".parse().unwrap(),
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            // v1.3.0 (CIRISPersist#46): grant the test steward all
            // three secrets role tiers so existing tests continue to
            // pass against routes now gated by `verify_and_authorize`.
            capability_roles: vec![
                ROLE_SECRETS_READER.to_owned(),
                ROLE_SECRETS_WRITER.to_owned(),
                ROLE_SECRETS_ADMIN.to_owned(),
            ],
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        FederationDirectory::put_public_key(&*backend, SignedKeyRecord { record: key })
            .await
            .unwrap();
        // Build the secrets backend on the same connection.
        let secrets = Arc::new(SqliteSecretsBackend::new(backend.conn_handle()));
        // Bootstrap a master key so encrypt / store paths work.
        secrets
            .rotate_master_key(None, "test-bootstrap".into())
            .await
            .unwrap();
        let state = SecretsAppState {
            service: secrets.clone(),
            directory: backend.clone(),
        };
        (router(state), secrets, backend)
    }

    /// Sign a request body with the steward fixture key.
    fn sign(body: &[u8]) -> String {
        let sk = SigningKey::from_bytes(&STEWARD_SEED);
        BASE64.encode(sk.sign(body).to_bytes())
    }

    fn signed_post(uri: &str, body: Vec<u8>) -> Request<Body> {
        let sig = sign(&body);
        Request::post(uri)
            .header("content-type", "application/json")
            .header(HEADER_KEY_ID, STEWARD_KEY_ID)
            .header(HEADER_ED25519, &sig)
            .body(Body::from(body))
            .unwrap()
    }

    fn signed_get(uri: &str) -> Request<Body> {
        let sig = sign(&[]);
        Request::get(uri)
            .header(HEADER_KEY_ID, STEWARD_KEY_ID)
            .header(HEADER_ED25519, &sig)
            .body(Body::empty())
            .unwrap()
    }

    fn signed_delete(uri: &str) -> Request<Body> {
        let sig = sign(&[]);
        Request::delete(uri)
            .header(HEADER_KEY_ID, STEWARD_KEY_ID)
            .header(HEADER_ED25519, &sig)
            .body(Body::empty())
            .unwrap()
    }

    async fn body_json<T: serde::de::DeserializeOwned>(resp: Response) -> T {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| panic!("decode: {e}\nbody: {}", String::from_utf8_lossy(&bytes)))
    }

    /// Happy path: store via HTTP, retrieve via HTTP, plaintext round-trips.
    #[tokio::test]
    async fn store_secret_round_trip() {
        let (app, _secrets, _backend) = build_app().await;
        let body = serde_json::to_vec(&serde_json::json!({
            "plaintext": "hunter2",
            "description": "github-token",
            "accessor": "test-user",
        }))
        .unwrap();
        let resp = app
            .clone()
            .oneshot(signed_post("/api/v1/secrets/store", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: StoreSecretResponse = body_json(resp).await;
        assert_eq!(body.description, "github-token");
        assert_eq!(body.status, "stored");
        let _ = body.sensitivity;
    }

    /// `try_claim` idempotent: two POSTs with the same plaintext
    /// dedup via the V017 content_hmac column — first returns
    /// `"stored"`, second returns `"already_claimed"` with the same
    /// UUID. Same shape as the
    /// `try_claim_secret_race_dedups_to_one_row` test in
    /// `secrets::sqlite::tests`, run over the HTTP surface.
    #[tokio::test]
    async fn try_claim_idempotent_via_http() {
        let (app, _secrets, _backend) = build_app().await;
        let body = serde_json::to_vec(&serde_json::json!({
            "plaintext": "hunter2",
            "description": "github-token",
            "accessor": "test-user",
            "sensitivity": "high",
            "auto_decapsulate_for_actions": ["tool"],
        }))
        .unwrap();
        let resp = app
            .clone()
            .oneshot(signed_post("/api/v1/secrets/try_claim", body.clone()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let first: ClaimResultWire = body_json(resp).await;
        assert_eq!(first.outcome, "stored");

        // Second call should AlreadyClaimed with the same UUID.
        let resp = app
            .clone()
            .oneshot(signed_post("/api/v1/secrets/try_claim", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let second: ClaimResultWire = body_json(resp).await;
        assert_eq!(second.outcome, "already_claimed");
        assert_eq!(second.reference.uuid, first.reference.uuid);
    }

    /// Missing signature headers → 401.
    #[tokio::test]
    async fn unauthorized_no_signature() {
        let (app, _secrets, _backend) = build_app().await;
        let body = serde_json::to_vec(&serde_json::json!({
            "plaintext": "x",
            "description": "y",
            "accessor": "z",
        }))
        .unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/secrets/store")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let err: SecretsErrorResponse = body_json(resp).await;
        assert_eq!(err.kind, "secrets_signature_missing");
    }

    /// Flipped signature byte → 401 + invalid token.
    #[tokio::test]
    async fn unauthorized_bad_signature() {
        let (app, _secrets, _backend) = build_app().await;
        let body = serde_json::to_vec(&serde_json::json!({
            "plaintext": "x",
            "description": "y",
            "accessor": "z",
        }))
        .unwrap();
        let mut sig_bytes = BASE64.decode(&sign(&body)).unwrap();
        sig_bytes[0] ^= 0xFF;
        let bad_sig = BASE64.encode(&sig_bytes);
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/secrets/store")
                    .header("content-type", "application/json")
                    .header(HEADER_KEY_ID, STEWARD_KEY_ID)
                    .header(HEADER_ED25519, &bad_sig)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let err: SecretsErrorResponse = body_json(resp).await;
        assert_eq!(err.kind, "secrets_signature_invalid");
    }

    /// Unknown UUID → 404 + secrets_not_found token.
    #[tokio::test]
    async fn unknown_uuid_returns_404() {
        let (app, _secrets, _backend) = build_app().await;
        let uri = "/api/v1/secrets/00000000-0000-0000-0000-000000000000?accessor=test";
        let resp = app.clone().oneshot(signed_get(uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let err: SecretsErrorResponse = body_json(resp).await;
        assert_eq!(err.kind, "secrets_not_found");
    }

    /// Health probe returns 200 + is_healthy=true (no signature).
    #[tokio::test]
    async fn health_returns_200() {
        let (app, _secrets, _backend) = build_app().await;
        let resp = app
            .clone()
            .oneshot(
                Request::get("/api/v1/secrets/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: HealthResponse = body_json(resp).await;
        assert!(body.is_healthy);
    }

    /// Encrypt → decrypt round-trip via HTTP.
    #[tokio::test]
    async fn encrypt_decrypt_via_http() {
        let (app, _secrets, _backend) = build_app().await;
        let body = serde_json::to_vec(&serde_json::json!({"plaintext": "secret"})).unwrap();
        let resp = app
            .clone()
            .oneshot(signed_post("/api/v1/secrets/encrypt", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let enc: EncryptResponse = body_json(resp).await;

        let body = serde_json::to_vec(&serde_json::json!({"ciphertext": enc.ciphertext})).unwrap();
        let resp = app
            .clone()
            .oneshot(signed_post("/api/v1/secrets/decrypt", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let dec: DecryptResponse = body_json(resp).await;
        assert_eq!(dec.plaintext, "secret");
    }

    /// `PUT /api/v1/secrets/filter_config` updates the catalog +
    /// bumps version; `GET` reflects the write.
    #[tokio::test]
    async fn filter_config_update_via_http() {
        let (app, _secrets, _backend) = build_app().await;
        let body = serde_json::to_vec(&serde_json::json!({
            "config_id": "global",
            "new_config": {"patterns": ["api_key"]},
        }))
        .unwrap();
        let sig = sign(&body);
        let resp = app
            .clone()
            .oneshot(
                Request::put("/api/v1/secrets/filter_config")
                    .header("content-type", "application/json")
                    .header(HEADER_KEY_ID, STEWARD_KEY_ID)
                    .header(HEADER_ED25519, &sig)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let upd: FilterConfigUpdateResponse = body_json(resp).await;
        assert_eq!(upd.new_version, 1);

        let resp = app
            .clone()
            .oneshot(signed_get("/api/v1/secrets/filter_config"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cfg: FilterConfigResponse = body_json(resp).await;
        assert_eq!(cfg.version, 1);
    }

    /// `GET /api/v1/secrets` lists stored secrets.
    #[tokio::test]
    async fn list_secrets_via_http() {
        let (app, _secrets, _backend) = build_app().await;
        // Store one first so the list isn't empty.
        let body = serde_json::to_vec(&serde_json::json!({
            "plaintext": "x",
            "description": "list-test",
            "accessor": "u",
        }))
        .unwrap();
        let resp = app
            .clone()
            .oneshot(signed_post("/api/v1/secrets/store", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // List.
        let resp = app
            .clone()
            .oneshot(signed_get("/api/v1/secrets?limit=100"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let list: ListSecretsResponse = body_json(resp).await;
        assert!(list.items.iter().any(|r| r.description == "list-test"));
    }

    /// `DELETE /api/v1/secrets/{uuid}` audits + returns deleted flag.
    #[tokio::test]
    async fn forget_secret_via_http() {
        let (app, _secrets, _backend) = build_app().await;
        // Store + list to recover the UUID.
        let body = serde_json::to_vec(&serde_json::json!({
            "plaintext": "x",
            "description": "forget-test",
            "accessor": "u",
        }))
        .unwrap();
        let resp = app
            .clone()
            .oneshot(signed_post("/api/v1/secrets/store", body))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = app
            .clone()
            .oneshot(signed_get("/api/v1/secrets?limit=100"))
            .await
            .unwrap();
        let list: ListSecretsResponse = body_json(resp).await;
        let uuid = list
            .items
            .iter()
            .find(|r| r.description == "forget-test")
            .map(|r| r.uuid.clone())
            .expect("our secret in listing");
        let uri = format!("/api/v1/secrets/{uuid}?accessor=u");
        let resp = app.clone().oneshot(signed_delete(&uri)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: ForgetSecretResponse = body_json(resp).await;
        assert!(body.deleted);
    }
}
