//! v62.0.0 (JSON-cut slice D, CC 2.6.1, 2.6.1.12) — the edition-2 HTTP
//! surface: statement ingest, the serve listing, and the bundles in force.
//!
//! # Composition (opt-in, like the secrets routes)
//!
//! These routes are NOT part of [`super::router`]. A deployment merges them
//! explicitly, so no existing deployment grows a write surface on upgrade:
//!
//! ```ignore
//! let app = ciris_persist::server::router(app_state)
//!     .merge(ciris_persist::server::edition2::router(edition2_state.clone()))
//!     // Only behind the deployment's peer authentication: see below.
//!     .merge(ciris_persist::server::edition2::serve_router(edition2_state));
//! ```
//!
//! **The serve listing is OFF** (ruling, 2026-11-18): it must not serve
//! without an audience filter, and the serving path
//! (`edition2_statements_since`, which cut B's replication reads too)
//! filters nothing yet. [`Edition2State::new`] leaves it off and its `GET`
//! answers 403 `serve_listing_disabled`. TODO(json-cut): wire the route
//! through the audience-filtered serving path once one exists, then drop
//! [`Edition2State::serve_listing_unfiltered`].
//!
//! - [`router`]: `POST` [`STATEMENTS_PATH`] (ingest) and `GET`
//!   [`BUNDLES_IN_FORCE_PATH`]. A statement is self-authenticating: the
//!   edition-2 door verifies its composite signature against the held key
//!   plane and runs every gate the JSON door ran, so the route needs no
//!   request authentication of its own (the same posture as
//!   `POST /api/v1/accord/events`, whose persister verifies). The bundles in
//!   force are the genesis roster, which the trust-root route already
//!   serves publicly.
//! - [`serve_router`]: `GET` [`STATEMENTS_PATH`], every held statement in
//!   admission order (OFF by default, above). It applies NO audience or
//!   withholding filter (the store listing does not), so it is a separate
//!   router a deployment would mount only behind its own peer
//!   authentication.
//!
//! # Limits
//!
//! A request body is capped at [`MAX_STATEMENT_BODY_BYTES`] (413 above it,
//! before the door runs); one statement per request; a page is at most the
//! store's [`crate::federation::edition2::store::MAX_PAGE`].
//!
//! # Status codes
//!
//! - 200: admitted, unchanged, or (replicated) refused as a policy outcome;
//! - 400: a malformed query (`row_id`, `after`);
//! - 403: the serve listing while it is off (`serve_listing_disabled`);
//! - 413: body over the cap;
//! - 422: a terminal refusal, with its stable `kind` (and `plane` / `reason`
//!   for `federation_malformed_row`, e.g. `earlier_form_object`);
//! - 424: a WAIT (`federation::Error::is_wait`, CC 2.7), `retryable: true`:
//!   something the answer depends on is not held yet — the signer's key
//!   record (`federation_attester_key_unknown`), a row the statement names
//!   (`federation_link_not_held`, with its `plane`), a roster's protocol, a
//!   delegation edge. Re-offer the same bytes after it lands;
//! - 500: a storage failure (detail logged, not served).

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::federation::attestation_apply::AttestationRefusalReason;
use crate::federation::edition2::ingest::{
    apply_replicated_statement, put_statement, ReplicatedStatementOutcome, StatementOutcome,
    INGEST_TIER,
};
use crate::federation::edition2::store::StatementCursor;
use crate::federation::{Error, FederationDirectory};

/// `POST`: ingest one statement; `GET`: the serve listing ([`serve_router`]).
pub const STATEMENTS_PATH: &str = "/v1/edition2/statements";
/// `GET`: the bundles in force (CC 2.6.1.11, 2.7.8).
pub const BUNDLES_IN_FORCE_PATH: &str = "/v1/edition2/bundles-in-force";
/// The largest request body the edition-2 routes read: one statement. A
/// composite signature is under 4 KiB and a row's payload is CDE text, so
/// 1 MiB is generous; larger bodies are 413 before the door runs.
pub const MAX_STATEMENT_BODY_BYTES: usize = 1024 * 1024;
/// The page size when `limit` is absent.
pub const DEFAULT_PAGE: u32 = 100;

/// State shared by the edition-2 handlers: the directory the door runs over.
///
/// `F` may be unsized, so an `Arc<dyn FederationDirectory>` composes too.
pub struct Edition2State<F>
where
    F: FederationDirectory + ?Sized + 'static,
{
    /// The directory every route reads and writes.
    pub directory: Arc<F>,
    /// The serve listing answers only when this is `true`. It serves with NO
    /// audience filter, so it is off by default ([`Self::new`]) and is turned
    /// on only by a test until the filtered serving path exists.
    pub serve_listing_unfiltered: bool,
}

impl<F> Edition2State<F>
where
    F: FederationDirectory + ?Sized + 'static,
{
    /// The state over `directory`, with the serve listing OFF.
    #[must_use]
    pub fn new(directory: Arc<F>) -> Self {
        Self {
            directory,
            serve_listing_unfiltered: false,
        }
    }
}

// Manual `Clone`: only the `Arc` clones.
impl<F> Clone for Edition2State<F>
where
    F: FederationDirectory + ?Sized + 'static,
{
    fn clone(&self) -> Self {
        Self {
            directory: self.directory.clone(),
            serve_listing_unfiltered: self.serve_listing_unfiltered,
        }
    }
}

/// The ingest route and the bundles-in-force read. See the module docs.
pub fn router<F>(state: Edition2State<F>) -> Router
where
    F: FederationDirectory + ?Sized + 'static,
{
    Router::new()
        .route(STATEMENTS_PATH, post(post_statement::<F>))
        .route(BUNDLES_IN_FORCE_PATH, get(get_bundles_in_force::<F>))
        .layer(DefaultBodyLimit::max(MAX_STATEMENT_BODY_BYTES))
        .with_state(state)
}

/// The serve listing: OFF unless [`Edition2State::serve_listing_unfiltered`]
/// (403 `serve_listing_disabled`). It serves every held statement with no
/// audience filter.
pub fn serve_router<F>(state: Edition2State<F>) -> Router
where
    F: FederationDirectory + ?Sized + 'static,
{
    Router::new()
        .route(STATEMENTS_PATH, get(get_statements_since::<F>))
        .layer(DefaultBodyLimit::max(MAX_STATEMENT_BODY_BYTES))
        .with_state(state)
}

// ── wire bodies ──────────────────────────────────────────────────────

/// What the ingest route did with a statement (200).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementResponse {
    /// `admitted`, `unchanged`, or `refused` (replicated only).
    pub outcome: String,
    /// `key_plane`, `voice`, `row` or `pending` (a counted row short of its
    /// count: held, waiting for its voices); absent when refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plane: Option<String>,
    /// The row id THIS node computed, lowercase hex; absent when refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_id: Option<String>,
    /// Was the statement new here (PyO3's `new`); absent when refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<bool>,
    /// Why a replicated statement was refused (a policy outcome).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<AttestationRefusalReason>,
    /// v62.0.0 (wave GC4; CC 2.7.3) — for a `pending` row (held, concluding
    /// nothing): the fold's reason token (`edition2::fold::reason`), e.g.
    /// `count_short`, `link_unheld`. Absent for every other plane, and when
    /// the store records no reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held_reason: Option<String>,
}

/// A failure body (400 / 422 / 424 / 500).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Edition2ErrorBody {
    /// The stable error kind (`federation_malformed_row`, ...), or
    /// `bad_request` for a malformed query.
    pub kind: String,
    /// The door, for `federation_malformed_row`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plane: Option<String>,
    /// The stable reason token, for `federation_malformed_row`
    /// (`earlier_form_object`, `row_id_mismatch`, ...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Human-readable detail (generic for a 500).
    pub detail: String,
    /// May a later re-offer succeed?
    pub retryable: bool,
}

/// One served statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PagedStatement {
    /// Its position ([`encode_cursor`]); pass the last one back as `after`.
    pub cursor: String,
    /// The statement's bytes as received (CC 2.6.1.2), lowercase hex.
    pub statement: String,
}

/// A page of the serve listing (200).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementPage {
    /// The statements, in this node's admission order.
    pub statements: Vec<PagedStatement>,
    /// The cursor to resume after; `None` when the page is empty.
    pub next: Option<String>,
}

/// One bundle in force: the shape PyO3's `bundles_in_force_json` serves
/// (one entry per tip; two are a fork).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleInForceJson {
    /// The bundle's object id, lowercase hex.
    pub object_id: String,
    /// `version`.
    pub version: u32,
    /// `refs.prev`, lowercase hex, on a later bundle.
    pub prev: Option<String>,
    /// `asserted_at`, POSIX ms.
    pub asserted_at: u64,
    /// The accord's name.
    pub family_key_id: String,
    /// The roster's identity-refs, in `holders` order.
    pub holders: Vec<String>,
    /// The seats' identity-refs, in `serve_nodes` order.
    pub serve_nodes: Vec<String>,
    /// The identity-refs whose statements counted, sorted.
    pub counted: Vec<String>,
}

impl From<&crate::federation::edition2::genesis::GenesisPlacement> for BundleInForceJson {
    fn from(t: &crate::federation::edition2::genesis::GenesisPlacement) -> Self {
        Self {
            object_id: hex::encode(t.object_id),
            version: t.version,
            prev: t.prev.as_ref().map(hex::encode),
            asserted_at: t.asserted_at,
            family_key_id: t.family_key_id.clone(),
            holders: t.holders.iter().map(|h| h.identity_ref.clone()).collect(),
            serve_nodes: t.seats.iter().map(|x| x.identity_ref.clone()).collect(),
            counted: t.counted.clone(),
        }
    }
}

/// The edition-2 trust-root body (CC 5.3.4): every named row of every valid
/// held bundle, then every held voice of those bundles, in lineage order, as
/// received, lowercase hex. Fed to `put_genesis_bundle` on a fresh node with
/// the right anchor, it reproduces the lineage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustRootStatements {
    /// The statements.
    pub statements: Vec<String>,
}

// ── queries ──────────────────────────────────────────────────────────

/// `POST` [`STATEMENTS_PATH`] query.
#[derive(Debug, Default, Deserialize)]
pub struct IngestQuery {
    /// The row id a peer offers the statement as (64 hex). Present: the
    /// replicated door ([`apply_replicated_statement`]); absent: the local
    /// door ([`put_statement`]).
    pub row_id: Option<String>,
}

/// `GET` [`STATEMENTS_PATH`] query.
#[derive(Debug, Default, Deserialize)]
pub struct SinceQuery {
    /// Resume after this cursor ([`encode_cursor`]); absent: from the first.
    pub after: Option<String>,
    /// At most this many (default [`DEFAULT_PAGE`]; the store clamps).
    pub limit: Option<u32>,
}

// ── cursor / digest text ─────────────────────────────────────────────

/// A cursor as text: `"{admitted_us}:{statement_id hex}"` (the form PyO3's
/// `edition2_statements_since` hands out).
#[must_use]
pub fn encode_cursor(c: &StatementCursor) -> String {
    format!("{}:{}", c.admitted_us, hex::encode(c.statement_id))
}

/// The inverse of [`encode_cursor`]; `None` for anything else.
#[must_use]
pub fn parse_cursor(s: &str) -> Option<StatementCursor> {
    let (us, id) = s.split_once(':')?;
    Some(StatementCursor {
        admitted_us: us.parse().ok()?,
        statement_id: parse_digest(id)?,
    })
}

/// 64 hex characters as 32 bytes; `None` for anything else.
#[must_use]
pub fn parse_digest(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let v = hex::decode(s).ok()?;
    <[u8; 32]>::try_from(v.as_slice()).ok()
}

// ── handlers ─────────────────────────────────────────────────────────

fn bad_request(detail: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(Edition2ErrorBody {
            kind: "bad_request".to_owned(),
            plane: None,
            reason: None,
            detail: detail.to_owned(),
            retryable: false,
        }),
    )
        .into_response()
}

/// An [`Error`] as its status and typed body. A storage failure's detail is
/// logged, not served.
fn error_response(e: &Error) -> Response {
    match e {
        Error::Backend(_) | Error::Unsupported { .. } => {
            tracing::warn!(kind = e.kind(), error = %e, "edition-2 route failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Edition2ErrorBody {
                    kind: e.kind().to_owned(),
                    plane: None,
                    reason: None,
                    detail: "edition-2 store unavailable".to_owned(),
                    retryable: true,
                }),
            )
                .into_response()
        }
        // v62.0.0 (CC 2.7) — every WAIT (`Error::is_wait`, the one
        // classification the capsule and Python read too) is 424 with
        // `retryable: true`: something the answer depends on is not held
        // here yet, nothing was stored, and the same statement re-offered
        // after it lands can be admitted. Before v62 only
        // `federation_attester_key_unknown` answered this; every other wait
        // (`federation_link_not_held`, `federation_withdraws_target_unheld`,
        // `federation_roster_change_not_landed`, …) answered 422 terminal.
        _ if e.is_wait() => (
            StatusCode::FAILED_DEPENDENCY,
            Json(Edition2ErrorBody {
                kind: e.kind().to_owned(),
                plane: match e {
                    Error::LinkNotHeld { plane, .. } => Some((*plane).to_owned()),
                    _ => None,
                },
                reason: None,
                detail: e.to_string(),
                retryable: true,
            }),
        )
            .into_response(),
        Error::MalformedRow {
            plane,
            reason,
            message,
        } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(Edition2ErrorBody {
                kind: e.kind().to_owned(),
                plane: Some((*plane).to_owned()),
                reason: Some((*reason).to_owned()),
                detail: message.clone(),
                retryable: false,
            }),
        )
            .into_response(),
        other => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(Edition2ErrorBody {
                kind: other.kind().to_owned(),
                plane: None,
                reason: None,
                detail: other.to_string(),
                retryable: false,
            }),
        )
            .into_response(),
    }
}

fn kept(outcome: &str, o: &StatementOutcome) -> StatementResponse {
    let (plane, row_id) = match o {
        StatementOutcome::KeyPlane { row_id, .. } => ("key_plane", row_id),
        StatementOutcome::Voice { row_id, .. } => ("voice", row_id),
        StatementOutcome::Row { row_id, .. } => ("row", row_id),
        StatementOutcome::Pending { row_id, .. } => ("pending", row_id),
    };
    StatementResponse {
        outcome: outcome.to_owned(),
        plane: Some(plane.to_owned()),
        row_id: Some(row_id.hex()),
        new: Some(is_new(o)),
        reason: None,
        held_reason: None,
    }
}

/// v62.0.0 (wave GC4; CC 2.7.3) — [`kept`], with a `pending` row's fold
/// reason read back (`edition2::fold::why_held`). A failed read leaves it
/// absent: the row is held either way.
async fn kept_held<F>(dir: &F, outcome: &str, o: &StatementOutcome) -> StatementResponse
where
    F: FederationDirectory + ?Sized,
{
    let mut r = kept(outcome, o);
    if let StatementOutcome::Pending { row_id, .. } = o {
        r.held_reason = crate::federation::edition2::fold::why_held(dir, row_id)
            .await
            .ok()
            .flatten()
            .map(|h| h.reason);
    }
    r
}

fn is_new(o: &StatementOutcome) -> bool {
    match o {
        StatementOutcome::KeyPlane { new, .. }
        | StatementOutcome::Voice { new, .. }
        | StatementOutcome::Row { new, .. }
        | StatementOutcome::Pending { new, .. } => *new,
    }
}

/// `POST` [`STATEMENTS_PATH`]: one `COSE_Sign1` statement as the body.
async fn post_statement<F>(
    State(state): State<Edition2State<F>>,
    Query(q): Query<IngestQuery>,
    body: Bytes,
) -> Response
where
    F: FederationDirectory + ?Sized + 'static,
{
    let dir: &F = &state.directory;
    match q.row_id.as_deref() {
        Some(text) => {
            let Some(offered) = parse_digest(text) else {
                return bad_request("row_id: 64 hex characters");
            };
            match Box::pin(apply_replicated_statement(dir, &body, &offered)).await {
                Ok(ReplicatedStatementOutcome::Admitted(o)) => {
                    (StatusCode::OK, Json(kept_held(dir, "admitted", &o).await)).into_response()
                }
                Ok(ReplicatedStatementOutcome::Unchanged(o)) => {
                    (StatusCode::OK, Json(kept_held(dir, "unchanged", &o).await)).into_response()
                }
                Ok(ReplicatedStatementOutcome::Refused { reason }) => (
                    StatusCode::OK,
                    Json(StatementResponse {
                        outcome: "refused".to_owned(),
                        plane: None,
                        row_id: None,
                        new: None,
                        reason: Some(reason),
                        held_reason: None,
                    }),
                )
                    .into_response(),
                Err(e) => error_response(&e),
            }
        }
        None => match Box::pin(put_statement(dir, &body, None, INGEST_TIER)).await {
            Ok(o) => {
                let outcome = if is_new(&o) { "admitted" } else { "unchanged" };
                (StatusCode::OK, Json(kept_held(dir, outcome, &o).await)).into_response()
            }
            Err(e) => error_response(&e),
        },
    }
}

/// `GET` [`STATEMENTS_PATH`]: a page of the serve listing.
async fn get_statements_since<F>(
    State(state): State<Edition2State<F>>,
    Query(q): Query<SinceQuery>,
) -> Response
where
    F: FederationDirectory + ?Sized + 'static,
{
    if !state.serve_listing_unfiltered {
        return (
            StatusCode::FORBIDDEN,
            Json(Edition2ErrorBody {
                kind: "serve_listing_disabled".to_owned(),
                plane: None,
                reason: None,
                detail: "the edition-2 serve listing is off: it needs an audience filter"
                    .to_owned(),
                retryable: false,
            }),
        )
            .into_response();
    }
    let cursor = match q.after.as_deref() {
        None => None,
        Some(text) => match parse_cursor(text) {
            Some(c) => Some(c),
            None => return bad_request("after: {admitted_us}:{64 hex}"),
        },
    };
    let limit = q.limit.unwrap_or(DEFAULT_PAGE);
    match state
        .directory
        .edition2_statements_since(cursor.as_ref(), limit)
        .await
    {
        Ok(served) => {
            let next = served.last().map(|s| encode_cursor(&s.cursor));
            let statements = served
                .into_iter()
                .map(|s| PagedStatement {
                    cursor: encode_cursor(&s.cursor),
                    statement: hex::encode(&s.bytes),
                })
                .collect();
            (StatusCode::OK, Json(StatementPage { statements, next })).into_response()
        }
        Err(e) => error_response(&e),
    }
}

/// `GET` [`BUNDLES_IN_FORCE_PATH`].
async fn get_bundles_in_force<F>(State(state): State<Edition2State<F>>) -> Response
where
    F: FederationDirectory + ?Sized + 'static,
{
    let dir: &F = &state.directory;
    match Box::pin(crate::federation::edition2::genesis::bundles_in_force(dir)).await {
        Ok(tips) => {
            let body: Vec<BundleInForceJson> = tips.iter().map(BundleInForceJson::from).collect();
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(e) => error_response(&e),
    }
}

/// v62.0.0 (JSON-cut slice D, CC 5.3.4) — the trust-root body once the
/// earlier-form doors are shut: what
/// [`crate::federation::edition2::genesis::genesis_statements`] reads (every
/// named row, then every voice, of each valid held bundle, as received). A
/// node that holds no bundle serves an empty set, honestly.
///
/// # Errors
/// Directory read failures.
pub(crate) async fn trust_root_statements<F>(dir: &F) -> Result<TrustRootStatements, Error>
where
    F: FederationDirectory + ?Sized,
{
    let held = Box::pin(crate::federation::edition2::genesis::genesis_statements(
        dir,
    ))
    .await?;
    Ok(TrustRootStatements {
        statements: held.iter().map(hex::encode).collect(),
    })
}

/// v62.0.0 (JSON-cut slice D) — the edition-2 routes' witnesses.
///
/// - **I2490 (local ingest).** `POST` a `key:record` → 200 `admitted`,
///   `key_plane`, the row id this node computes; the same bytes again →
///   `unchanged`.
/// - **I2491 (an earlier-form object at the edition-2 route).** A JSON body
///   → 422 `federation_malformed_row` / `earlier_form_object`, not retryable.
/// - **I2492 (replicated ingest).** `?row_id=` the bytes do not name → 422
///   `row_id_mismatch`; the computed id → `admitted`, then `unchanged`; a
///   malformed `row_id` → 400.
/// - **I2493 (the cap).** A body over [`MAX_STATEMENT_BODY_BYTES`] → 413.
/// - **I2494 (the serve listing).** Paging by `after` with `limit=1` serves
///   each held statement once, as received (hex), in strictly increasing
///   positions, and `next` is null after the last; a malformed `after` →
///   400; the listing is not on [`router`] (405, so a deployment that merges
///   only `router` serves nothing).
/// - **I2495 (bundles in force).** 200 `[]` with none held.
/// - **I2497 (the serve listing is off by default).** [`Edition2State::new`]
///   leaves it off: `GET` answers 403 `serve_listing_disabled`, serving
///   nothing, until an audience filter exists.
/// - **I2496 (the trust-root route follows the switch).** With the
///   earlier-form doors forced shut, `GET /v1/trust-root/bundle` serves the
///   edition-2 body (`{"statements": [...]}`), never the earlier-form
///   bundle; with the switch off it serves the earlier-form body as before.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use ciris_crypto::composite::CompositeSigningKey;
    use ciris_verify_core::cde::{self, Value};
    use ciris_verify_core::edition2::{cose_key, identity_ref, sign_row_statement, thumbprint};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use crate::federation::edition2::names::RowId;

    fn key(n: u8) -> CompositeSigningKey {
        CompositeSigningKey::from_seeds(&[n; 32], &[n.wrapping_add(100); 32])
    }

    fn iref(k: &CompositeSigningKey) -> String {
        identity_ref(&thumbprint(k.public_key()))
    }

    fn map(mut m: Vec<(&str, Value)>) -> Value {
        let t = |s: &str| Value::Text(s.into());
        m.sort_by_key(|(k, _)| cde::encode(&t(k)));
        Value::Map(m.into_iter().map(|(k, v)| (t(k), v)).collect())
    }

    /// A self-signed `key:record` of the key seeded `n` (signed before any
    /// await: no signing key crosses one).
    fn key_record(n: u8, at: u64) -> Vec<u8> {
        let k = key(n);
        let payload = map(vec![
            ("key", cose_key(k.public_key())),
            (
                "identity_type",
                Value::Array(vec![Value::Text("user".into())]),
            ),
            ("asserted_at", Value::Uint(at)),
            ("author", Value::Text(iref(&k))),
        ]);
        sign_row_statement(
            &k,
            &iref(&k),
            &iref(&k),
            "scores",
            "key:record",
            &payload,
            vec![],
        )
        .expect("sign a key:record")
    }

    fn rid_hex(statement: &[u8]) -> String {
        RowId::of_statement(statement)
            .expect("a row statement")
            .hex()
    }

    async fn send(app: &Router, req: Request<Body>) -> (StatusCode, Vec<u8>) {
        let resp = app.clone().oneshot(req).await.expect("infallible");
        let status = resp.status();
        let body = resp
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes()
            .to_vec();
        (status, body)
    }

    fn post(uri: &str, body: Vec<u8>) -> Request<Body> {
        Request::post(uri)
            .header("Content-Type", "application/cose")
            .body(Body::from(body))
            .expect("request")
    }

    fn get(uri: &str) -> Request<Body> {
        Request::get(uri).body(Body::empty()).expect("request")
    }

    /// I2490–I2495 over one migrated, EMPTY store.
    async fn body(dir: Arc<dyn FederationDirectory>) {
        let s1 = key_record(91, 1_000);
        let s2 = key_record(92, 2_000);
        let state = Edition2State::new(dir.clone());
        let app = router(state.clone());
        // I2497: off by default, refused by name.
        let (st, b) = send(&serve_router(state.clone()), get(STATEMENTS_PATH)).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "I2497: the listing is off");
        let e: Edition2ErrorBody = serde_json::from_slice(&b).expect("I2497: body");
        assert_eq!(e.kind, "serve_listing_disabled", "I2497");
        let serve = serve_router(Edition2State {
            serve_listing_unfiltered: true,
            ..state
        });

        // ── I2490 ──
        for want in ["admitted", "unchanged"] {
            let (st, b) = send(&app, post(STATEMENTS_PATH, s1.clone())).await;
            assert_eq!(st, StatusCode::OK, "I2490: {}", String::from_utf8_lossy(&b));
            let r: StatementResponse = serde_json::from_slice(&b).expect("I2490: body");
            assert_eq!(r.outcome, want, "I2490");
            assert_eq!(r.plane.as_deref(), Some("key_plane"), "I2490");
            assert_eq!(r.row_id, Some(rid_hex(&s1)), "I2490: the node-computed id");
            assert_eq!(r.new, Some(want == "admitted"), "I2490: new");
        }

        // ── I2491 ──
        let json = br#"{"attestation":{"attestation_id":"a","attesting_key_id":"k"}}"#.to_vec();
        let (st, b) = send(&app, post(STATEMENTS_PATH, json)).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "I2491");
        let e: Edition2ErrorBody = serde_json::from_slice(&b).expect("I2491: body");
        assert_eq!(e.kind, "federation_malformed_row", "I2491");
        assert_eq!(e.reason.as_deref(), Some("earlier_form_object"), "I2491");
        assert!(!e.retryable, "I2491: terminal");

        // ── I2492 ──
        let wrong = format!("{STATEMENTS_PATH}?row_id={}", "5a".repeat(32));
        let (st, b) = send(&app, post(&wrong, s2.clone())).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "I2492");
        let e: Edition2ErrorBody = serde_json::from_slice(&b).expect("I2492: body");
        assert_eq!(e.reason.as_deref(), Some("row_id_mismatch"), "I2492");
        let (st, _) = send(
            &app,
            post(&format!("{STATEMENTS_PATH}?row_id=xyz"), s2.clone()),
        )
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "I2492: a malformed row_id");
        let right = format!("{STATEMENTS_PATH}?row_id={}", rid_hex(&s2));
        for want in ["admitted", "unchanged"] {
            let (st, b) = send(&app, post(&right, s2.clone())).await;
            assert_eq!(st, StatusCode::OK, "I2492: {}", String::from_utf8_lossy(&b));
            let r: StatementResponse = serde_json::from_slice(&b).expect("I2492: body");
            assert_eq!(r.outcome, want, "I2492: the replicated door");
            assert_eq!(r.row_id, Some(rid_hex(&s2)), "I2492");
        }

        // ── I2493 ──
        let (st, _) = send(
            &app,
            post(STATEMENTS_PATH, vec![0u8; MAX_STATEMENT_BODY_BYTES + 1]),
        )
        .await;
        assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE, "I2493");

        // ── I2494 ──
        let (st, _) = send(&app, get(STATEMENTS_PATH)).await;
        assert_eq!(
            st,
            StatusCode::METHOD_NOT_ALLOWED,
            "I2494: the listing is not on the ingest router"
        );
        let mut served: Vec<PagedStatement> = Vec::new();
        let mut after: Option<String> = None;
        loop {
            let uri = match &after {
                None => format!("{STATEMENTS_PATH}?limit=1"),
                Some(c) => format!("{STATEMENTS_PATH}?limit=1&after={c}"),
            };
            let (st, b) = send(&serve, get(&uri)).await;
            assert_eq!(st, StatusCode::OK, "I2494: {}", String::from_utf8_lossy(&b));
            let page: StatementPage = serde_json::from_slice(&b).expect("I2494: body");
            assert!(page.statements.len() <= 1, "I2494: the limit");
            if page.statements.is_empty() {
                assert_eq!(page.next, None, "I2494: no next after the last");
                break;
            }
            assert_eq!(
                page.next,
                page.statements.last().map(|s| s.cursor.clone()),
                "I2494: next is the last served"
            );
            after = page.next.clone();
            served.extend(page.statements);
        }
        let positions: Vec<StatementCursor> = served
            .iter()
            .map(|s| parse_cursor(&s.cursor).expect("I2494: a cursor round-trips"))
            .collect();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "I2494: strictly increasing positions"
        );
        for s in [&s1, &s2] {
            assert_eq!(
                served
                    .iter()
                    .filter(|x| x.statement == hex::encode(s))
                    .count(),
                1,
                "I2494: each held statement once, as received"
            );
        }
        let (st, _) = send(&serve, get(&format!("{STATEMENTS_PATH}?after=nope"))).await;
        assert_eq!(st, StatusCode::BAD_REQUEST, "I2494: a malformed cursor");

        // ── I2495 ──
        let (st, b) = send(&app, get(BUNDLES_IN_FORCE_PATH)).await;
        assert_eq!(st, StatusCode::OK, "I2495");
        let tips: Vec<BundleInForceJson> = serde_json::from_slice(&b).expect("I2495: body");
        assert!(tips.is_empty(), "I2495: none held");
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2490_to_i2495_edition2_routes_sqlite() {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .expect("open sqlite");
        b.run_migrations().await.expect("migrate");
        Box::pin(body(Arc::new(b))).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2490_to_i2495_edition2_routes_pg() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .expect("connect");
        b.run_migrations().await.expect("migrate");
        Box::pin(body(Arc::new(b))).await;
    }

    /// The trust-root route over `b`, under the forced switch and not.
    async fn trust_root_follows_the_switch<F>(b: Arc<F>)
    where
        F: FederationDirectory + crate::store::Backend + 'static,
    {
        use crate::queue::{spawn_persister, DEFAULT_QUEUE_DEPTH};
        use crate::scrub::NullScrubber;
        use crate::verify::PythonJsonDumpsCanonicalizer;
        use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner};
        let tmp = tempfile::tempdir().expect("tempdir");
        let journal = Arc::new(crate::journal::Journal::open(tmp.path().join("j.redb")).unwrap());
        std::mem::forget(tmp); // the detached persister outlives this fn
        let mut signer = Ed25519SoftwareSigner::new("i2496-signer");
        signer.import_key(&[0xA6u8; 32]).expect("import_key");
        let signer: Arc<dyn HardwareSigner> = Arc::new(signer);
        let (handle, persister) = spawn_persister(
            DEFAULT_QUEUE_DEPTH,
            b.clone(),
            Arc::new(PythonJsonDumpsCanonicalizer),
            Arc::new(NullScrubber),
            journal.clone(),
            signer,
            "i2496-signer".to_owned(),
        );
        std::mem::forget(persister);
        let app = crate::server::router(crate::server::AppState {
            handle,
            journal,
            directory: b,
        });
        let shut = crate::federation::edition2::door::with_earlier_form_doors_shut(send(
            &app,
            get(crate::server::TRUST_ROOT_BUNDLE_PATH),
        ))
        .await;
        assert_eq!(shut.0, StatusCode::OK, "I2496");
        let v: serde_json::Value = serde_json::from_slice(&shut.1).expect("I2496: body");
        assert_eq!(
            v,
            serde_json::json!({ "statements": [] }),
            "I2496: the edition-2 body, nothing held"
        );
        let (st, b) = send(&app, get(crate::server::TRUST_ROOT_BUNDLE_PATH)).await;
        assert_eq!(st, StatusCode::OK, "I2496: switch off");
        let v: serde_json::Value = serde_json::from_slice(&b).expect("I2496: body");
        assert!(
            v.get("bundle").is_some() && v.get("statements").is_none(),
            "I2496: the earlier-form body while the switch is off: {v}"
        );
    }

    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2496_trust_root_route_follows_the_switch_sqlite() {
        Box::pin(trust_root_follows_the_switch(Arc::new(
            crate::store::test_backend::test_backend(),
        )))
        .await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test(flavor = "multi_thread")]
    async fn i2496_trust_root_route_follows_the_switch_pg() {
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            eprintln!("skipping: CIRIS_PERSIST_TEST_PG_URL unset");
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .expect("connect");
        b.run_migrations().await.expect("migrate");
        Box::pin(trust_root_follows_the_switch(Arc::new(b))).await;
    }

    /// The cursor text round-trips and refuses other text.
    #[test]
    fn i2494_cursor_text_round_trips() {
        let c = StatementCursor {
            admitted_us: 1_700_000_000_000_001,
            statement_id: [0xab; 32],
        };
        assert_eq!(parse_cursor(&encode_cursor(&c)), Some(c));
        let short = format!("1:{}", "ab".repeat(31));
        let dotted = format!("1.{}", "ab".repeat(32));
        for bad in [
            "",
            "1",
            "1:",
            ":ab",
            "x:abab",
            short.as_str(),
            dotted.as_str(),
        ] {
            assert_eq!(parse_cursor(bad), None, "I2494: {bad:?}");
        }
    }
}

/// v62.0.0 (CC 2.7, wave P9) — **I3606: the HTTP status follows
/// `Error::is_wait`.** Every wait arm answers `424` with `retryable: true` and
/// its own kind (a `federation_link_not_held` also names its `plane`); a
/// malformed row answers `422`, `retryable: false`, with its plane and
/// reason; another terminal refusal `422`, `retryable: false`; a storage
/// failure `500`. Before v62 only `federation_attester_key_unknown` was a
/// retryable 424: every other wait answered 422 terminal, so an adopter on
/// HTTP could not tell a wait from a refusal.
#[cfg(test)]
mod wait_status_tests {
    use super::*;
    use http_body_util::BodyExt;

    async fn answer(e: &Error) -> (StatusCode, Edition2ErrorBody) {
        let resp = error_response(e);
        let status = resp.status();
        let bytes = resp.into_body().collect().await.expect("body").to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).expect("an Edition2ErrorBody"),
        )
    }

    #[tokio::test]
    async fn i3606_every_wait_is_a_retryable_424() {
        let s = |x: &str| x.to_owned();
        let waits = [
            Error::AttesterKeyUnknown {
                attesting_key_id: s("k"),
                plane: "attestation",
            },
            Error::link_not_held("family", "insert family: FOREIGN KEY constraint failed"),
            Error::WithdrawsTargetUnheld {
                attestation_id: s("w"),
                target_attestation_id: s("t"),
            },
            Error::RosterChangeNotLanded {
                group_key_id: s("g"),
                member_key_id: s("m"),
                direction: "removal",
                quorum_key: s("q"),
                signers: 1,
            },
            Error::LicensureShortOfAuthorityQuorum {
                attesting_key_id: s("k"),
                authority_id: s("a"),
                signers: 0,
            },
            Error::Relayed {
                kind: "federation_withdraws_target_unheld",
                wait: true,
                message: s("relayed"),
            },
        ];
        for e in &waits {
            assert!(e.is_wait(), "I3606: the table holds waits only");
            let (st, body) = answer(e).await;
            assert_eq!(st, StatusCode::FAILED_DEPENDENCY, "I3606: {}", e.kind());
            assert_eq!(body.kind, e.kind(), "I3606: the kind");
            assert!(body.retryable, "I3606: {} is retryable", e.kind());
        }
        let (_, body) = answer(&waits[1]).await;
        assert_eq!(
            body.plane.as_deref(),
            Some("family"),
            "I3606: the link's plane"
        );

        let malformed = Error::malformed_row(
            "attestation",
            crate::federation::malformed_row::EDITION2_EARLIER_FORM_OBJECT,
            "a JSON object at the statement door",
        );
        let (st, body) = answer(&malformed).await;
        assert_eq!(st, StatusCode::UNPROCESSABLE_ENTITY, "I3606: malformed");
        assert!(!body.retryable, "I3606: malformed is terminal");
        assert_eq!(body.plane.as_deref(), Some("attestation"), "I3606");
        assert_eq!(
            body.reason.as_deref(),
            Some(crate::federation::malformed_row::EDITION2_EARLIER_FORM_OBJECT),
            "I3606"
        );

        for terminal in [
            Error::InvalidArgument(s("bad")),
            Error::Relayed {
                kind: "federation_malformed_row",
                wait: false,
                message: s("relayed"),
            },
        ] {
            let (st, body) = answer(&terminal).await;
            assert_eq!(
                st,
                StatusCode::UNPROCESSABLE_ENTITY,
                "I3606: {}",
                terminal.kind()
            );
            assert!(!body.retryable, "I3606: {} is terminal", terminal.kind());
        }

        let (st, body) = answer(&Error::Backend(s("database is locked"))).await;
        assert_eq!(st, StatusCode::INTERNAL_SERVER_ERROR, "I3606: storage");
        assert_eq!(body.kind, "federation_backend", "I3606");
    }
}
