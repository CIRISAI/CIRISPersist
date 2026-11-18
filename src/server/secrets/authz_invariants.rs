//! v62.0.0 (P6) — **the secrets API's authorization**, witnessed on sqlite
//! AND postgres through the real router (I3200–I3210).
//!
//! The ruling these pin (`server::secrets` module docs):
//!
//! - a request is signed with ONE composite over
//!   `canonical_request(method, path_and_query, body)`, verified under the
//!   caller's LIVE edition-2 key;
//! - each route needs its own `secrets:{reader,writer,admin}` scope,
//!   conferred by a live `self:delegates_to` from THIS node's owner;
//! - nothing the caller's own record says about itself confers anything.
//!
//! The fixture: a `node` key (this node's identity), a `user` owner whose
//! owner binding over the node carries the node's voice (the kernel's owner
//! seat requires it), agent callers, and the owner's grants. Every row is
//! signed NOW-relative (E0 v1.11: node/agent keys' rows lapse with their
//! records).

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use http_body_util::BodyExt;
use tower::ServiceExt;

use super::{
    router, SecretsAppState, SecretsTier, EARLIER_FORM_SIGNATURE_HEADERS, HEADER_KEY_ID,
    HEADER_SIGNATURE, KIND_NOT_DELEGATED, KIND_SIGNATURE_EARLIER_FORM, KIND_SIGNATURE_INVALID,
    KIND_SIGNATURE_UNKNOWN_KEY,
};
use crate::federation::edition2::fixture_switch as e2;
use crate::federation::tier_ingest::test_support as ts;
use crate::federation::types::{attestation_type, delegation_scope as ds};
use crate::federation::{admission, Attestation, FederationDirectory};
use crate::secrets::wire::{canonical_request, SecretsErrorResponse};

/// This node's identity key (seed). `pub(super)`: the `tests` module's
/// `build_app` sets `set_node_key_id(e2::kid(NODE))`.
pub(super) const NODE: &str = "p6-node";
/// The node's owner (seed): a `user` key, the only conferrer.
pub(super) const OWNER: &str = "p6-owner";
/// A caller the owner grants ALL THREE scopes (seed). `pub(super)`: the
/// `tests` module signs as this key.
pub(super) const STEWARD: &str = "secrets-steward-test-1";
/// A caller the owner grants `secrets:reader`, and nothing else.
const READER: &str = "p6-reader";
/// A caller nobody grants anything; its own record DECLARES the earlier
/// form's admin role tag as a key type.
const STRANGER: &str = "p6-stranger";
/// A `user` key that is NOT the node's owner.
const OTHER_USER: &str = "p6-other-user";
/// A caller granted `secrets:reader` by OTHER_USER, who is not the owner.
const BY_OTHER: &str = "p6-by-other";
/// A seed whose key is never put: a well-formed identity-ref this node does
/// not hold.
const NEVER_HELD: &str = "p6-never-held";

/// The read route every reader witness calls.
const LIST: &str = "/api/v1/secrets?limit=10";
/// A second read route, for the cross-route replay witness.
const STATS: &str = "/api/v1/secrets/stats";
/// A writer route.
const ENCRYPT: &str = "/api/v1/secrets/encrypt";
/// The admin route.
const ROTATE: &str = "/api/v1/secrets/rotate_master_key";
/// A second writer route (I3210's round trip).
const DECRYPT: &str = "/api/v1/secrets/decrypt";

/// The owner's binding over the node, with the node's voice, re-dated to
/// now (the builder's fixed instant predates the node key's window).
pub(super) async fn seat_owner<D: FederationDirectory + ?Sized>(d: &D) {
    e2::put_key(d, NODE, &["node"]).await;
    e2::put_key(d, OWNER, &["user"]).await;
    let mut binding = ts::owner_binding_attestation(&uuid::Uuid::new_v4().to_string(), OWNER, NODE);
    let at = crate::host::clock::now() - chrono::Duration::minutes(5);
    binding.asserted_at = at;
    binding.scrub_timestamp = at;
    ts::reseal(&mut binding);
    e2::put_signed(d, &binding)
        .await
        .expect("fixture: the owner's binding over the node is admitted");
    let st = e2::carried_statement(&binding).expect("a flipped binding carries its statement");
    e2::put_statement(d, &e2::voice_of(&st, NODE))
        .await
        .expect("fixture: the node's voice on its owner binding is admitted");
    assert_eq!(
        admission::owner_of(d, &e2::kid(NODE))
            .await
            .expect("owner_of reads"),
        Some(e2::kid(OWNER)),
        "fixture: the owner holds the node's owner seat, else every leg below is vacuous"
    );
}

/// [`seat_owner`], then [`STEWARD`] (an `agent` key) with the owner's grant
/// of all three scopes (`delegation_scope::SECRETS`). The directory's
/// `node_key_id` must already be `e2::kid(NODE)`. Returns the steward's
/// identity-ref.
pub(super) async fn seat_steward<D: FederationDirectory + ?Sized>(d: &D) -> String {
    seat_owner(d).await;
    let steward = e2::put_key(d, STEWARD, &["agent"]).await;
    grant(d, OWNER, STEWARD, ds::SECRETS).await;
    steward
}

/// `granter`'s live `self:delegates_to` to `grantee` bearing `scopes`.
pub(super) async fn grant<D: FederationDirectory + ?Sized>(
    d: &D,
    granter: &str,
    grantee: &str,
    scopes: &[&str],
) -> Attestation {
    let mut row = ts::bare_attestation(
        "p6-grant",
        granter,
        grantee,
        &serde_json::json!({ "kind": "delegates_to", "scope": scopes }),
    );
    row.attestation_type = attestation_type::DELEGATES_TO.to_owned();
    let row = e2::row_of(&row, granter);
    assert_eq!(
        e2::family_of(&row),
        "self:delegates_to",
        "fixture: a capability grant is a self:delegates_to row (v62 RULINGS)"
    );
    e2::put_signed(d, &row)
        .await
        .expect("fixture: the grant is admitted");
    row
}

/// A request signed by `seed` with ONE composite over
/// `canonical_request(method, uri, body)`. `uri` is the origin-form target
/// (`/api/v1/secrets?limit=10`).
pub(super) fn signed(method: &str, uri: &str, body: Vec<u8>, seed: &str) -> Request<Body> {
    let sig = e2::signing_key(seed)
        .sign(&canonical_request(method, uri, &body))
        .expect("composite sign");
    request(method, uri, body, &e2::kid(seed), &BASE64.encode(sig))
}

/// A request carrying exactly the given key id and signature header.
pub(super) fn request(
    method: &str,
    uri: &str,
    body: Vec<u8>,
    key_id: &str,
    sig_b64: &str,
) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(uri)
        .header(HEADER_KEY_ID, key_id)
        .header(HEADER_SIGNATURE, sig_b64);
    if !body.is_empty() {
        b = b.header("content-type", "application/json");
    }
    b.body(Body::from(body)).expect("request builds")
}

/// The status and, for a refusal, its `kind` token (`""` on success).
async fn call(app: &Router, req: Request<Body>) -> (StatusCode, String) {
    let resp = app.clone().oneshot(req).await.expect("router answers");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("body reads")
        .to_bytes();
    if status.is_success() {
        return (status, String::new());
    }
    let err: SecretsErrorResponse = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        panic!(
            "a refusal carries a SecretsErrorResponse ({e}): {}",
            String::from_utf8_lossy(&bytes)
        )
    });
    (status, err.kind)
}

/// The status and the raw response body.
async fn call_body(app: &Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
    let resp = app.clone().oneshot(req).await.expect("router answers");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("body reads")
        .to_bytes();
    (status, bytes.to_vec())
}

fn encrypt_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "plaintext": "x" })).expect("json")
}

fn rotate_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({ "accessor": "p6" })).expect("json")
}

async fn witnesses<D: FederationDirectory + ?Sized>(app: Router, d: &D) {
    seat_steward(d).await;
    e2::put_key(d, READER, &["agent"]).await;
    // Sorted: Verify's key-record check takes the set sorted.
    e2::put_key(d, STRANGER, &["agent", "cirislens_secrets_admin"]).await;
    e2::put_key(d, OTHER_USER, &["user"]).await;
    e2::put_key(d, BY_OTHER, &["agent"]).await;
    let reader_grant = grant(d, OWNER, READER, &[ds::SECRETS_READER]).await;
    // The same grant, from a user who is not the node's owner.
    let _stray = grant(d, OTHER_USER, BY_OTHER, &[ds::SECRETS_READER]).await;

    // I3200 — a key the owner delegated `secrets:reader` READS.
    let (st, kind) = call(&app, signed("GET", LIST, Vec::new(), READER)).await;
    assert_eq!(
        st,
        StatusCode::OK,
        "I3200: the delegated reader reads ({kind})"
    );

    // I3201 — ... and does NOT write, nor rotate: no tier covers another.
    let (st, kind) = call(&app, signed("POST", ENCRYPT, encrypt_body(), READER)).await;
    assert_eq!(
        (st, kind.as_str()),
        (StatusCode::FORBIDDEN, KIND_NOT_DELEGATED),
        "I3201: secrets:reader confers no {}",
        SecretsTier::Writer.scope()
    );
    let (st, kind) = call(&app, signed("POST", ROTATE, rotate_body(), READER)).await;
    assert_eq!(
        (st, kind.as_str()),
        (StatusCode::FORBIDDEN, KIND_NOT_DELEGATED),
        "I3201: secrets:reader confers no {}",
        SecretsTier::Admin.scope()
    );

    // I3202 — an undelegated key is refused, though its own record declares
    // the earlier form's admin role as a key type (CC 3.4.7: no key declares
    // itself into a duty).
    let (st, kind) = call(&app, signed("GET", LIST, Vec::new(), STRANGER)).await;
    assert_eq!(
        (st, kind.as_str()),
        (StatusCode::FORBIDDEN, KIND_NOT_DELEGATED),
        "I3202: no delegation, no read"
    );
    let (st, kind) = call(&app, signed("POST", ROTATE, rotate_body(), STRANGER)).await;
    assert_eq!(
        (st, kind.as_str()),
        (StatusCode::FORBIDDEN, KIND_NOT_DELEGATED),
        "I3202: a self-declared role confers nothing"
    );

    // I3203 — a grant from a key that is not the node's owner confers
    // nothing.
    let (st, kind) = call(&app, signed("GET", LIST, Vec::new(), BY_OTHER)).await;
    assert_eq!(
        (st, kind.as_str()),
        (StatusCode::FORBIDDEN, KIND_NOT_DELEGATED),
        "I3203: only the owner confers"
    );

    // I3204 — a bad composite is refused: one flipped byte in each half.
    for at in [0usize, 3_372] {
        let mut sig = e2::signing_key(READER)
            .sign(&canonical_request("GET", LIST, &[]))
            .expect("composite sign");
        sig[at] ^= 0x01;
        let (st, kind) = call(
            &app,
            request(
                "GET",
                LIST,
                Vec::new(),
                &e2::kid(READER),
                &BASE64.encode(&sig),
            ),
        )
        .await;
        assert_eq!(
            (st, kind.as_str()),
            (StatusCode::UNAUTHORIZED, KIND_SIGNATURE_INVALID),
            "I3204: a composite with byte {at} flipped is refused"
        );
    }

    // I3205 — a valid composite for ANOTHER route does not authorize this
    // one (the method and request target are signed, not only the body).
    let other = e2::signing_key(READER)
        .sign(&canonical_request("GET", STATS, &[]))
        .expect("composite sign");
    let (st, kind) = call(
        &app,
        request(
            "GET",
            LIST,
            Vec::new(),
            &e2::kid(READER),
            &BASE64.encode(&other),
        ),
    )
    .await;
    assert_eq!(
        (st, kind.as_str()),
        (StatusCode::UNAUTHORIZED, KIND_SIGNATURE_INVALID),
        "I3205: a signature over GET {STATS} does not open GET {LIST}"
    );

    // I3206 — the earlier form's component headers are refused by name,
    // even beside a valid composite.
    for h in EARLIER_FORM_SIGNATURE_HEADERS {
        let mut req = signed("GET", LIST, Vec::new(), READER);
        req.headers_mut()
            .insert(h, axum::http::HeaderValue::from_static("c2lnbmF0dXJl"));
        let (st, kind) = call(&app, req).await;
        assert_eq!(
            (st, kind.as_str()),
            (StatusCode::UNAUTHORIZED, KIND_SIGNATURE_EARLIER_FORM),
            "I3206: {h} is refused by name"
        );
    }

    // I3207 — a key this node does not hold authenticates nothing, though
    // its composite verifies under its own key.
    let (st, kind) = call(&app, signed("GET", LIST, Vec::new(), NEVER_HELD)).await;
    assert_eq!(
        (st, kind.as_str()),
        (StatusCode::UNAUTHORIZED, KIND_SIGNATURE_UNKNOWN_KEY),
        "I3207: an unheld key is unknown"
    );

    // I3208 — a WITHDRAWN delegation is refused. The reader read above
    // (I3200); after the owner's `withdraws` it does not.
    let withdraws = e2::composer_of("withdraws", &reader_grant, OWNER);
    e2::put_signed(d, &withdraws)
        .await
        .expect("fixture: the owner's withdraws is admitted");
    let (st, kind) = call(&app, signed("GET", LIST, Vec::new(), READER)).await;
    assert_eq!(
        (st, kind.as_str()),
        (StatusCode::FORBIDDEN, KIND_NOT_DELEGATED),
        "I3208: a withdrawn grant confers nothing"
    );

    // I3210 — a key granted all three scopes uses each: it rotates the
    // master key (admin; this also bootstraps the first key), then
    // encrypts and decrypts (writer), then reads (reader).
    let (st, kind) = call(&app, signed("POST", ROTATE, rotate_body(), STEWARD)).await;
    assert_eq!(st, StatusCode::OK, "I3210: secrets:admin rotates ({kind})");
    let (st, bytes) = call_body(&app, signed("POST", ENCRYPT, encrypt_body(), STEWARD)).await;
    assert_eq!(st, StatusCode::OK, "I3210: secrets:writer encrypts");
    let enc: crate::secrets::wire::EncryptResponse =
        serde_json::from_slice(&bytes).expect("encrypt response");
    let body =
        serde_json::to_vec(&serde_json::json!({ "ciphertext": enc.ciphertext })).expect("json");
    let (st, bytes) = call_body(&app, signed("POST", DECRYPT, body, STEWARD)).await;
    assert_eq!(st, StatusCode::OK, "I3210: secrets:writer decrypts");
    let dec: crate::secrets::wire::DecryptResponse =
        serde_json::from_slice(&bytes).expect("decrypt response");
    assert_eq!(dec.plaintext, "x", "I3210: the round trip");
    let (st, kind) = call(&app, signed("GET", LIST, Vec::new(), STEWARD)).await;
    assert_eq!(st, StatusCode::OK, "I3210: secrets:reader reads ({kind})");
}

/// I3200–I3208, I3210 on sqlite.
#[cfg(feature = "sqlite")]
#[tokio::test]
async fn i3200_i3208_secrets_authorization_sqlite() {
    use crate::store::Backend as _;
    let b = Arc::new(
        crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .expect("sqlite opens"),
    );
    b.run_migrations().await.expect("migrations");
    b.set_node_key_id(e2::kid(NODE));
    let service = Arc::new(crate::secrets::sqlite::SqliteSecretsBackend::new(
        b.conn_handle(),
    ));
    let app = router(SecretsAppState {
        service,
        directory: b.clone(),
    });
    Box::pin(witnesses(app, &*b)).await;
}

/// I3200–I3208, I3210 on postgres.
#[cfg(feature = "postgres")]
#[tokio::test]
async fn i3200_i3208_secrets_authorization_postgres() {
    use crate::store::Backend as _;
    let Some(dsn) = crate::test_pg::empty_dsn() else {
        return;
    };
    let b = Arc::new(
        crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .expect("postgres connects"),
    );
    b.run_migrations().await.expect("migrations");
    b.set_node_key_id(e2::kid(NODE));
    let app = router(SecretsAppState {
        service: b.clone(),
        directory: b.clone(),
    });
    Box::pin(witnesses(app, &*b)).await;
}

/// I3209 — `canonical_request` is injective over its three parts: moving a
/// byte between the method, the target and the body changes the bytes, and
/// the domain tag opens them.
#[test]
fn i3209_canonical_request_separates_its_parts() {
    let a = canonical_request("GET", "/a", b"b");
    assert!(a.starts_with(crate::secrets::wire::REQUEST_SIGNATURE_CONTEXT));
    assert_ne!(a, canonical_request("GET", "/ab", b""));
    assert_ne!(a, canonical_request("GET/", "a", b"b"));
    assert_ne!(
        canonical_request("GET", LIST, &[]),
        canonical_request("DELETE", LIST, &[])
    );
    assert_eq!(a, canonical_request("GET", "/a", b"b"), "deterministic");
}
