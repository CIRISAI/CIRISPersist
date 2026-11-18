//! v1.1.0 (CIRISPersist#33 part 4a): secrets-server axum routes.
//!
//! Mirrors the 18-method [`SecretsService`] trait surface (15 of
//! which are HTTP-exposed; the 3 in-process-only methods —
//! `process_incoming_text`, `decapsulate_secrets_in_parameters`,
//! `test_encryption`, `migrate_to_hardware_key` — stay behind the
//! trait). FederatedSecretsClient (`src/secrets/client.rs`) calls these
//! routes so consumer code can swap in-process ↔ federated transparently.
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
//! # v62.0.0 — who may call, and how a request is signed
//!
//! The secrets API is this node's **LOCAL plane** (v62 RULINGS, "Planes").
//! Every route but `GET /api/v1/secrets/health` runs [`authorize_request`]:
//!
//! 1. **One composite signature.** The request carries
//!    [`HEADER_KEY_ID`] (the caller's edition-2 identity-ref) and
//!    [`HEADER_SIGNATURE`] (base64 of ONE CC 2.6.1.7 ML-DSA-65-Ed25519
//!    composite, 3373 bytes) over
//!    [`canonical_request`](crate::secrets::wire::canonical_request)`(method,
//!    path_and_query, body)`. It is verified under the composite key of the
//!    caller's **live** edition-2 `key:record` (the key plane's own reading,
//!    `edition2::liveness`, at this node's clock): a revoked, lapsed or
//!    unknown key authenticates nothing. The two component headers of the
//!    earlier form (`x-ciris-signature-ed25519` /
//!    `x-ciris-signature-ml-dsa-65`) are refused by name
//!    ([`KIND_SIGNATURE_EARLIER_FORM`]): the composite rule admits no
//!    standalone component signer.
//! 2. **A delegated capability.** Each route needs one scope —
//!    `secrets:reader`, `secrets:writer` or `secrets:admin`
//!    ([`SecretsTier::scope`]) — conferred on the caller's key by a live
//!    `self:delegates_to` row from **this node's owner**
//!    ([`admission::owner_of`], the kernel's owner seat; the node's
//!    cosignature is required). The predicate is
//!    `trust_root::owner_granted_scope`, the one the serve tier's
//!    owner-grant rung reads (tombstones, expiry, envelope `valid_until`,
//!    federation tier), never a second spelling of it. A withdrawn grant
//!    confers nothing.
//!
//! **No tier covers another**: the three tokens are siblings under the
//! scope grammar (`admission::scope_covers` is a `:`-narrowing), so an owner
//! that wants a key to read and write grants both. **No authority is read
//! from the caller's own record**: neither its `identity_type` nor any role
//! list (CC 3.4.7, "No key declares itself into a duty"). The earlier form's
//! `capability_roles` (`cirislens_secrets_reader` / `_writer` / `_admin`) is
//! gone.
//!
//! Status codes: 401 for a signature that is missing, earlier-form, invalid,
//! or made by a key that is not held or not live; 403 for a capability not
//! delegated or a conferrer that cannot be resolved (no node identity, no
//! owner, an ambiguous owner); 503 when the directory cannot be read; then
//! 400 / 404 / 500 / 503 from the service as before.
//!
//! [`SecretsService`]: crate::secrets::SecretsService

use std::sync::Arc;

use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use crate::federation::edition2::ingest::{held_keys_for_kid, kid_of_identity_ref};
use crate::federation::edition2::liveness::Liveness;
use crate::federation::types::delegation_scope;
use crate::federation::{admission, trust_root, FederationDirectory};
use crate::secrets::types::MasterKeyRef;
pub use crate::secrets::wire::{
    canonical_request, EARLIER_FORM_SIGNATURE_HEADERS, HEADER_KEY_ID, HEADER_SIGNATURE,
};
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
use crate::ClaimResult;

// ── v62.0.0 refusal tokens (AV-15 `kind`) ──────────────────────────

/// 401 — [`HEADER_KEY_ID`] or [`HEADER_SIGNATURE`] is absent.
pub const KIND_SIGNATURE_MISSING: &str = "secrets_signature_missing";
/// 401 — the request carries an earlier-form component-signature header
/// ([`EARLIER_FORM_SIGNATURE_HEADERS`]). Refused before any key is read.
pub const KIND_SIGNATURE_EARLIER_FORM: &str = "secrets_signature_earlier_form";
/// 401 — the composite does not verify over the canonical request under the
/// caller's live key, or the header is not base64 of a 3373-byte composite.
pub const KIND_SIGNATURE_INVALID: &str = "secrets_signature_invalid";
/// 401 — [`HEADER_KEY_ID`] is not an edition-2 identity-ref, or this node
/// holds no valid `key:record` for it.
pub const KIND_SIGNATURE_UNKNOWN_KEY: &str = "secrets_signature_unknown_key";
/// 401 — the caller's key is held but not live at this node's clock: revoked,
/// outside its record's window, or waiting on a key this node does not hold.
pub const KIND_SIGNER_NOT_LIVE: &str = "secrets_signer_not_live";
/// 403 — no live `self:delegates_to` from this node's owner confers the
/// route's scope on the caller's key. Replaces the earlier form's
/// `secrets_role_tag`.
pub const KIND_NOT_DELEGATED: &str = "secrets_capability_not_delegated";
/// 403 — the conferrer cannot be resolved: this node has no identity
/// (`FederationDirectory::node_key_id`), no live owner, or more than one.
/// Fails closed: no owner, no grant.
pub const KIND_CONFERRER_UNRESOLVED: &str = "secrets_conferrer_unresolved";
/// 503 — the directory could not be read while authorizing.
pub const KIND_DIRECTORY_UNAVAILABLE: &str = "secrets_directory_unavailable";

// ── v62.0.0 — the three capabilities ───────────────────────────────

/// The capability a route requires. Each maps to ONE delegation scope
/// ([`Self::scope`]); no tier implies another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretsTier {
    /// Read routes: list, retrieve, filter config read, stats, access logs.
    Reader,
    /// Mutating routes: store, try_claim, encrypt, decrypt, recall, forget,
    /// filter config write, reencrypt_all.
    Writer,
    /// Master-key rotation.
    Admin,
}

impl SecretsTier {
    /// The `self:delegates_to` scope token this tier requires.
    #[must_use]
    pub fn scope(self) -> &'static str {
        match self {
            Self::Reader => delegation_scope::SECRETS_READER,
            Self::Writer => delegation_scope::SECRETS_WRITER,
            Self::Admin => delegation_scope::SECRETS_ADMIN,
        }
    }
}

// ── State ──────────────────────────────────────────────────────────

/// Shared state for the secrets sub-router.
///
/// Generic over `S: SecretsService` (RPITIT trait — see module doc
/// for the dyn-safety rationale) and `F: FederationDirectory` for
/// the key plane and the owner's grants.
pub struct SecretsAppState<S, F>
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    /// Concrete SecretsService backend (typically
    /// [`crate::secrets::postgres::PostgresBackend`] or
    /// [`crate::secrets::sqlite::SqliteSecretsBackend`]).
    pub service: Arc<S>,
    /// Federation directory: the caller's edition-2 key records, this
    /// node's identity and owner, and the owner's `self:delegates_to`
    /// grants. Its `node_key_id` must be set, or every signed route is
    /// refused ([`KIND_CONFERRER_UNRESOLVED`]).
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

// ── v62.0.0: authentication + authorization ────────────────────────

/// The origin-form request target (`/path?query`) of `uri`, as the client
/// sent it: the `path_and_query` input of
/// [`canonical_request`](crate::secrets::wire::canonical_request).
fn path_and_query(uri: &axum::http::Uri) -> &str {
    uri.path_and_query()
        .map_or_else(|| uri.path(), axum::http::uri::PathAndQuery::as_str)
}

/// 503 for a directory read that failed while authorizing.
fn directory_unavailable(e: &crate::federation::Error, what: &str) -> Response {
    tracing::error!(error = %e, what, "secrets authorization: directory read failed");
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        KIND_DIRECTORY_UNAVAILABLE,
        format!("{what}: {e}"),
    )
}

/// **Who signed this request?** Verify the ONE composite signature over
/// [`canonical_request`](crate::secrets::wire::canonical_request)`(method,
/// path_and_query, body)` under the caller's LIVE edition-2 key, and return
/// the caller's identity-ref.
///
/// The earlier-form component headers are refused by name first, before
/// any key is read. A key id that is not an identity-ref names no edition-2
/// key: it is unknown, never looked up in the earlier-form read model.
///
/// # Errors
/// The ready 401 / 503 [`Response`].
// clippy::result_large_err — the `Err` arm is an axum `Response`, the
// intended early return of a handler helper.
#[allow(clippy::result_large_err)]
pub async fn authenticate_request<F>(
    directory: &F,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<String, Response>
where
    F: FederationDirectory + ?Sized,
{
    if let Some(h) = EARLIER_FORM_SIGNATURE_HEADERS
        .iter()
        .find(|h| headers.contains_key(**h))
    {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            KIND_SIGNATURE_EARLIER_FORM,
            format!(
                "the request carries the earlier-form component-signature header {h:?}. \
                 v62.0.0: a secrets request is signed with ONE composite \
                 (ML-DSA-65-Ed25519) signature over canonical_request(method, \
                 path_and_query, body), sent in {HEADER_SIGNATURE}; the composite rule \
                 admits no standalone component signer. Not a key-validity problem."
            ),
        ));
    }
    let missing = |name: &str| {
        error_response(
            StatusCode::UNAUTHORIZED,
            KIND_SIGNATURE_MISSING,
            format!("missing {name} header"),
        )
    };
    let key_id = headers
        .get(HEADER_KEY_ID)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| missing(HEADER_KEY_ID))?
        .to_owned();
    let sig_b64 = headers
        .get(HEADER_SIGNATURE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| missing(HEADER_SIGNATURE))?;
    let sig = BASE64.decode(sig_b64.trim()).map_err(|e| {
        error_response(
            StatusCode::UNAUTHORIZED,
            KIND_SIGNATURE_INVALID,
            format!("{HEADER_SIGNATURE} is not base64: {e}"),
        )
    })?;
    let Some(kid) = kid_of_identity_ref(&key_id) else {
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            KIND_SIGNATURE_UNKNOWN_KEY,
            format!(
                "{HEADER_KEY_ID} {key_id:?} is not an edition-2 identity-ref \
                 (urn:ietf:params:oauth:ckt:sha-256:…); v62.0.0 authenticates only \
                 edition-2 keys"
            ),
        ));
    };
    let held = held_keys_for_kid(directory, &kid)
        .await
        .map_err(|e| directory_unavailable(&e, "caller key records"))?;
    let now = crate::host::clock::now();
    let at = u64::try_from(now.timestamp_millis()).unwrap_or(0);
    let record = match held.liveness(&kid, at) {
        Liveness::Live(record) => record,
        Liveness::NotHeld | Liveness::Invalid => {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                KIND_SIGNATURE_UNKNOWN_KEY,
                format!("this node holds no valid key:record for {key_id}"),
            ));
        }
        Liveness::Revoked => {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                KIND_SIGNER_NOT_LIVE,
                format!("{key_id} is revoked"),
            ));
        }
        Liveness::NotCovered => {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                KIND_SIGNER_NOT_LIVE,
                format!("no record of {key_id} covers this node's clock ({now})"),
            ));
        }
        Liveness::Waiting(keys) => {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                KIND_SIGNER_NOT_LIVE,
                format!(
                    "{key_id}'s record waits on {} key(s) this node does not hold",
                    keys.len()
                ),
            ));
        }
    };
    let message = canonical_request(method.as_str(), path_and_query(uri), body);
    if let Err(e) = record.key.verify(&message, &sig) {
        tracing::warn!(
            error = %e,
            key_id = %key_id,
            "secrets route rejected: composite signature failed"
        );
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            KIND_SIGNATURE_INVALID,
            format!(
                "the composite signature does not verify over \
                 canonical_request({}, {:?}, <{} body bytes>) under {key_id}'s live key: {e}",
                method.as_str(),
                path_and_query(uri),
                body.len()
            ),
        ));
    }
    Ok(key_id)
}

/// **May `caller` use `tier`?** True iff this node's owner
/// ([`admission::owner_of`] over [`FederationDirectory::node_key_id`]) holds
/// a live `self:delegates_to` to `caller` bearing [`SecretsTier::scope`]
/// (`trust_root::owner_granted_scope`). Nothing about `caller`'s own record
/// is read.
///
/// # Errors
/// The ready 403 / 503 [`Response`].
#[allow(clippy::result_large_err)]
pub async fn authorize_caller<F>(
    directory: &F,
    caller: &str,
    tier: SecretsTier,
) -> Result<(), Response>
where
    F: FederationDirectory + ?Sized,
{
    let scope = tier.scope();
    let Some(node) = directory.node_key_id() else {
        return Err(error_response(
            StatusCode::FORBIDDEN,
            KIND_CONFERRER_UNRESOLVED,
            "this node has no identity (node_key_id unset), so no owner can confer \
             a secrets capability"
                .to_owned(),
        ));
    };
    // v62.0.0 (wave GC2; G0 v3) — this request catches the ambiguity and
    // answers it itself, so it reads the seat unmarked (no fold mark leaks).
    let owner = match admission::owner_of_unmarked(directory, &node).await {
        Ok(Some(owner)) => owner,
        Ok(None) => {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                KIND_CONFERRER_UNRESOLVED,
                format!("node {node} has no live owner, so no owner can confer {scope}"),
            ));
        }
        Err(e @ crate::federation::Error::AmbiguousNodeOwner { .. }) => {
            return Err(error_response(
                StatusCode::FORBIDDEN,
                KIND_CONFERRER_UNRESOLVED,
                format!("{e} — no single owner confers {scope}; refused (fail closed)"),
            ));
        }
        Err(e) => return Err(directory_unavailable(&e, "node owner")),
    };
    match trust_root::owner_granted_scope(directory, caller, &owner, scope).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            tracing::warn!(
                caller, owner = %owner, scope,
                "secrets route rejected: capability not delegated"
            );
            Err(error_response(
                StatusCode::FORBIDDEN,
                KIND_NOT_DELEGATED,
                format!(
                    "{caller} holds no live self:delegates_to from this node's owner \
                     {owner} bearing scope {scope:?} (scopes do not cover one another: \
                     grant each tier the key needs)"
                ),
            ))
        }
        Err(e) => Err(directory_unavailable(&e, "owner's delegations")),
    }
}

/// [`authenticate_request`] then [`authorize_caller`]: the gate every signed
/// route runs. Returns the caller's identity-ref.
///
/// # Errors
/// The ready 401 / 403 / 503 [`Response`].
#[allow(clippy::result_large_err)]
pub async fn authorize_request<F>(
    directory: &F,
    method: &Method,
    uri: &axum::http::Uri,
    headers: &HeaderMap,
    body: &[u8],
    tier: SecretsTier,
) -> Result<String, Response>
where
    F: FederationDirectory + ?Sized,
{
    let caller = authenticate_request(directory, method, uri, headers, body).await?;
    authorize_caller(directory, &caller, tier).await?;
    Ok(caller)
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
        // v59.1.2 — a starved pool: transient, as the backend arm it was
        // carved from.
        SecretsError::PoolExhausted { .. } => StatusCode::SERVICE_UNAVAILABLE,
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

// clippy::result_large_err — see `authenticate_request`'s comment above; same
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &body,
        SecretsTier::Writer,
    )
    .await
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &body,
        SecretsTier::Writer,
    )
    .await
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
    method: Method,
    OriginalUri(uri): OriginalUri,
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
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &[],
        SecretsTier::Reader,
    )
    .await
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(uuid): Path<String>,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &body,
        SecretsTier::Writer,
    )
    .await
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Query(q): Query<ListSecretsQuery>,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &[],
        SecretsTier::Reader,
    )
    .await
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(uuid): Path<String>,
    Query(q): Query<ForgetSecretQuery>,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &[],
        SecretsTier::Writer,
    )
    .await
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &body,
        SecretsTier::Writer,
    )
    .await
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &body,
        SecretsTier::Writer,
    )
    .await
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &[],
        SecretsTier::Reader,
    )
    .await
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    // The authenticated caller (its edition-2 identity-ref) is the accessor
    // for audit: the request is signed by that key and authorized for it.
    let accessor = match authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &body,
        SecretsTier::Writer,
    )
    .await
    {
        Ok(caller) => caller,
        Err(r) => return r,
    };
    let req: FilterConfigUpdateRequest = match parse_body(&body) {
        Ok(v) => v,
        Err(r) => return r,
    };
    match state.service.update_filter_config(req, accessor).await {
        Ok(result) => (StatusCode::OK, Json::<FilterConfigUpdateResponse>(result)).into_response(),
        Err(e) => map_secrets_error(e),
    }
}

/// `GET /api/v1/secrets/stats` — service-wide stats.
async fn get_stats<S, F>(
    State(state): State<SecretsAppState<S, F>>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &[],
        SecretsTier::Reader,
    )
    .await
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Query(q): Query<AccessLogsQuery>,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &[],
        SecretsTier::Reader,
    )
    .await
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &body,
        SecretsTier::Writer,
    )
    .await
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
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response
where
    S: SecretsService + 'static,
    F: FederationDirectory + Backend + 'static,
{
    if let Err(r) = authorize_request(
        &*state.directory,
        &method,
        &uri,
        &headers,
        &body,
        SecretsTier::Admin,
    )
    .await
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

// v62.0.0 (P6) — the authorization witnesses (I3200–I3210), sqlite AND
// postgres, through the router. Apart from `tests` below (its owner rewrites
// those against this door).
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod authz_invariants;

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::authz_invariants::{self as authz, STEWARD};
    use super::*;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::secrets::sqlite::SqliteSecretsBackend;
    use crate::store::sqlite::SqliteBackend;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// v62.0.0 (P6) — this node (`authz::NODE`) is owned by `authz::OWNER`,
    /// who grants [`STEWARD`] (an edition-2 `agent` key) all three secrets
    /// scopes with one `self:delegates_to`. The earlier form seeded a JSON
    /// `KeyRecord` carrying `capability_roles`; an edition-2 key carries no
    /// roles, and the door reads none.
    async fn build_app() -> (Router, Arc<SqliteSecretsBackend>, Arc<SqliteBackend>) {
        let backend = Arc::new(SqliteBackend::open_in_memory().await.unwrap());
        backend.run_migrations().await.unwrap();
        backend.set_node_key_id(e2::kid(authz::NODE));
        authz::seat_steward(&*backend).await;
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

    /// v62.0.0 — ONE composite over `canonical_request("POST", uri, body)`.
    async fn signed_post(uri: &str, body: Vec<u8>) -> Request<Body> {
        authz::signed("POST", uri, body, STEWARD)
    }

    async fn signed_get(uri: &str) -> Request<Body> {
        authz::signed("GET", uri, Vec::new(), STEWARD)
    }

    async fn signed_delete(uri: &str) -> Request<Body> {
        authz::signed("DELETE", uri, Vec::new(), STEWARD)
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
            .oneshot(signed_post("/api/v1/secrets/store", body).await)
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
            .oneshot(signed_post("/api/v1/secrets/try_claim", body.clone()).await)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let first: ClaimResultWire = body_json(resp).await;
        assert_eq!(first.outcome, "stored");

        // Second call should AlreadyClaimed with the same UUID.
        let resp = app
            .clone()
            .oneshot(signed_post("/api/v1/secrets/try_claim", body).await)
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

    /// Flipped composite byte → 401 + invalid token.
    #[tokio::test]
    async fn unauthorized_bad_signature() {
        let (app, _secrets, _backend) = build_app().await;
        let body = serde_json::to_vec(&serde_json::json!({
            "plaintext": "x",
            "description": "y",
            "accessor": "z",
        }))
        .unwrap();
        let mut sig = e2::signing_key(STEWARD)
            .sign(&canonical_request("POST", "/api/v1/secrets/store", &body))
            .expect("composite sign");
        sig[0] ^= 0xFF;
        let resp = app
            .clone()
            .oneshot(authz::request(
                "POST",
                "/api/v1/secrets/store",
                body,
                &e2::kid(STEWARD),
                &BASE64.encode(&sig),
            ))
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
        let resp = app.clone().oneshot(signed_get(uri).await).await.unwrap();
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
            .oneshot(signed_post("/api/v1/secrets/encrypt", body).await)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let enc: EncryptResponse = body_json(resp).await;

        let body = serde_json::to_vec(&serde_json::json!({"ciphertext": enc.ciphertext})).unwrap();
        let resp = app
            .clone()
            .oneshot(signed_post("/api/v1/secrets/decrypt", body).await)
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
        let resp = app
            .clone()
            .oneshot(authz::signed(
                "PUT",
                "/api/v1/secrets/filter_config",
                body,
                STEWARD,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let upd: FilterConfigUpdateResponse = body_json(resp).await;
        assert_eq!(upd.new_version, 1);

        let resp = app
            .clone()
            .oneshot(signed_get("/api/v1/secrets/filter_config").await)
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
            .oneshot(signed_post("/api/v1/secrets/store", body).await)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // List.
        let resp = app
            .clone()
            .oneshot(signed_get("/api/v1/secrets?limit=100").await)
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
            .oneshot(signed_post("/api/v1/secrets/store", body).await)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp = app
            .clone()
            .oneshot(signed_get("/api/v1/secrets?limit=100").await)
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
        let resp = app
            .clone()
            .oneshot(signed_delete(&uri).await)
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: ForgetSecretResponse = body_json(resp).await;
        assert!(body.deleted);
    }
}
