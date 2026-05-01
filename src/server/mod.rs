//! axum HTTP listener — Phase 1.1 deployment shape (FSD §1).
//!
//! # Mission alignment (MISSION.md §2 — `server/`)
//!
//! The network edge. Verification is meaningless if the wire edge is
//! exploitable. Memory-safe parsing of untrusted bytes is the
//! recurring CVE class for federation services; Rust's static
//! guarantees are the answer.
//!
//! Constraint: bounded queue; backpressure via 429, never via dropping
//! bytes silently. Every error response is a defined type, not an
//! opportunistic string.
//!
//! Endpoints (TRACE_WIRE_FORMAT.md §1):
//!   - `POST /api/v1/accord/events` — submit a batch envelope.
//!   - `GET /health` — liveness + queue depth + journal pending count.
//!
//! Status codes (TRACE_WIRE_FORMAT.md §1, §12 + FSD §3.4 #5):
//!   - 200 — accepted (queued for persistence).
//!   - 422 — schema-version / required-field / shape failure.
//!   - 429 — queue full (mission backpressure; agent retries).
//!   - 503 — persister closed (lens shutting down).

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::journal::Journal;
use crate::queue::{IngestHandle, QueueError};

/// Server state shared across handlers.
#[derive(Clone)]
pub struct AppState {
    pub handle: IngestHandle,
    pub journal: Arc<Journal>,
}

/// Maximum body size for `POST /api/v1/accord/events`.
///
/// THREAT_MODEL.md AV-7: 8 MiB caps the largest legitimate
/// production fixture (a `full_traces` 16-component trace lands
/// at ~3 MB) with 2.6× headroom. Larger bodies hit
/// `413 Payload Too Large` before reaching the queue or backend.
/// The lens deployment-edge proxy can also enforce a body cap;
/// this is defense-in-depth at the crate level.
pub const MAX_INGEST_BODY_BYTES: usize = 8 * 1024 * 1024;

/// Build the axum router with the Phase-1 endpoints. Caller is
/// responsible for binding the listener and serving.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/accord/events", post(post_events))
        .route("/health", get(get_health))
        .layer(DefaultBodyLimit::max(MAX_INGEST_BODY_BYTES))
        .with_state(state)
}

/// Health response (TRACE_WIRE_FORMAT.md §1 doesn't formalize this;
/// we follow the convention CIRISLens already uses).
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    pub status: &'static str,
    pub queue_capacity_remaining: usize,
    pub journal_pending: u64,
    pub schema_versions_supported: &'static [&'static str],
}

/// Owned variant for tests (deserialization).
#[cfg(test)]
#[derive(Debug, Clone, Deserialize)]
pub struct HealthOwned {
    pub status: String,
    pub queue_capacity_remaining: usize,
    pub journal_pending: u64,
    pub schema_versions_supported: Vec<String>,
}

async fn get_health(State(state): State<AppState>) -> impl IntoResponse {
    let pending = state.journal.pending_count().unwrap_or(0);
    Json(Health {
        status: "ok",
        queue_capacity_remaining: state.handle.capacity_remaining(),
        journal_pending: pending,
        schema_versions_supported: crate::schema::SUPPORTED_VERSIONS,
    })
}

/// Submit a batch envelope.
///
/// The handler owns the bytes briefly to enqueue them on the bounded
/// channel; the persister task is the single consumer that does
/// schema/verify/scrub/decompose/store. Mission constraint: 429 on
/// full queue, never silent drop.
async fn post_events(State(state): State<AppState>, body: axum::body::Bytes) -> Response {
    // We *could* parse + verify here on the request thread before
    // queuing, to fail-fast on malformed bodies. Phase 1 keeps the
    // handler thin: queue first, persister handles the typed
    // pipeline. This keeps backpressure honest — schema-malformed
    // bodies land in the journal with the rest, surfaced via
    // operations rather than blocking the request thread.
    //
    // Two trade-offs here:
    //   * thin handler: simple, easy to audit, no double-parse.
    //   * fat handler: 422 surfaces immediately on malformed bodies.
    //
    // We chose thin for Phase 1; the schema check inside the
    // persister still produces a typed error and is logged.
    let bytes = body.to_vec();
    match state.handle.try_submit(bytes) {
        Ok(()) => (StatusCode::OK, Json(AcceptedResponse { status: "ok" })).into_response(),
        Err(QueueError::Full) => {
            // 429 + Retry-After per FSD §3.4 #5.
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    detail: "queue full",
                    retry_after_seconds: Some(1),
                }),
            )
                .into_response();
            resp.headers_mut()
                .insert("Retry-After", HeaderValue::from_static("1"));
            resp
        }
        Err(QueueError::Closed) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                detail: "persister closed",
                retry_after_seconds: Some(5),
            }),
        )
            .into_response(),
        Err(QueueError::Journal(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                detail: Box::leak(e.to_string().into_boxed_str()),
                retry_after_seconds: None,
            }),
        )
            .into_response(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AcceptedResponse {
    status: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ErrorResponse {
    detail: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::{spawn_persister, DEFAULT_QUEUE_DEPTH};
    use crate::scrub::NullScrubber;
    use crate::store::MemoryBackend;
    use crate::verify::PythonJsonDumpsCanonicalizer;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn temp_journal() -> (tempfile::TempDir, Arc<Journal>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j.redb");
        let j = Journal::open(&path).unwrap();
        (dir, Arc::new(j))
    }

    fn build_app(queue_depth: usize) -> (Router, Arc<MemoryBackend>) {
        use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner};
        let backend = Arc::new(MemoryBackend::new());
        let (_dir, journal) = temp_journal();
        std::mem::forget(_dir); // keep tempdir alive for test duration
        let mut signer = Ed25519SoftwareSigner::new("server-test-signer");
        signer.import_key(&[0xA5u8; 32]).expect("import_key");
        let signer_arc: Arc<dyn HardwareSigner> = Arc::new(signer);
        let (handle, persister) = spawn_persister(
            queue_depth,
            backend.clone(),
            Arc::new(PythonJsonDumpsCanonicalizer),
            Arc::new(NullScrubber),
            journal.clone(),
            signer_arc,
            "server-test-signer".to_owned(),
        );
        // Detach the persister handle from the test's lifetime;
        // graceful-shutdown coverage lives in queue::tests.
        std::mem::forget(persister);
        (router(AppState { handle, journal }), backend)
    }

    /// Mission category §4 "Backpressure": the agent's POST flow
    /// returns 200 on success, 429 on saturation. Both must be
    /// reachable from the same wire shape.
    #[tokio::test]
    async fn health_endpoint_returns_supported_versions() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH);
        let resp = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let h: HealthOwned = serde_json::from_slice(&body).unwrap();
        assert_eq!(h.status, "ok");
        assert_eq!(h.schema_versions_supported, vec!["2.7.0"]);
        assert!(h.queue_capacity_remaining > 0);
    }

    #[tokio::test]
    async fn post_events_accepts_well_formed_batch() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH);
        let body = serde_json::json!({
            "events": [{
                "event_type": "complete_trace",
                "trace_level": "generic",
                "trace": {
                    "trace_id": "trace-x", "thought_id": "th-x",
                    "task_id": null, "agent_id_hash": "deadbeef",
                    "started_at": "2026-04-30T00:00:00Z",
                    "completed_at": "2026-04-30T00:01:00Z",
                    "trace_level": "generic",
                    "trace_schema_version": "2.7.0",
                    "components": [],
                    "signature": "AAAA",
                    "signature_key_id": "test-key"
                }
            }],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0"
        });
        let resp = app
            .oneshot(
                Request::post("/api/v1/accord/events")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // Accepted into the queue (verify will then reject because no
        // key registered; that's logged but not a 200 vs 422 issue).
        // Mission constraint: thin handler accepts, persister
        // rejects-and-logs.
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// THREAT_MODEL.md AV-7 regression: bodies above
    /// MAX_INGEST_BODY_BYTES are rejected with 413 before reaching
    /// the queue.
    #[tokio::test]
    async fn oversized_body_returns_413() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH);
        // 9 MiB body — over the 8 MiB cap.
        let big = vec![b'x'; 9 * 1024 * 1024];
        let resp = app
            .oneshot(
                Request::post("/api/v1/accord/events")
                    .header("Content-Type", "application/octet-stream")
                    .body(Body::from(big))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Mission category §4 "Backpressure": queue saturation surfaces
    /// 429 + Retry-After.
    #[tokio::test]
    async fn full_queue_returns_429_with_retry_after() {
        // queue_depth=1; the persister runs but we'll race-fill it.
        let (app, _backend) = build_app(1);
        // Send several requests rapidly to saturate.
        let mut got_429 = false;
        for _ in 0..200 {
            let resp = app
                .clone()
                .oneshot(
                    Request::post("/api/v1/accord/events")
                        .header("Content-Type", "application/json")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                let retry = resp
                    .headers()
                    .get("Retry-After")
                    .map(|v| v.to_str().unwrap().to_string());
                assert_eq!(retry.as_deref(), Some("1"), "Retry-After header set");
                got_429 = true;
                break;
            }
        }
        assert!(got_429, "expected 429 at some point");
    }
}
