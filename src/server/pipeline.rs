//! v1.1.0 (CIRISPersist#33 part 3) — `POST /api/v1/pipeline/ingest`
//! route.
//!
//! # What this route does (FSD §4.3)
//!
//! Accepts a federation-internal [`PipelineEnvelope`] from a CIRISLens
//! edge: a typed sidecar carrying pre-computed classify / extract /
//! encrypt-and-store outputs, wrapped around the agent's original
//! (now scrubbed) [`BatchEnvelope`]. The edge is a federation peer
//! registered in `federation_keys`; the wrapper is signed with the
//! edge's hybrid (Ed25519 + ML-DSA-65) key.
//!
//! Pipeline (FSD §4.3 invariants 1-7):
//!
//! 1. `pipeline_schema_version` in
//!    [`PipelineEnvelope::SCHEMA_VERSION_V1`] — reject unknown with 422.
//! 2. Verify `edge_signature` against the directory via
//!    [`verify_hybrid_via_directory`]. Reject with 422.
//! 3. Verify EACH inner [`CompleteTrace`]'s agent signature. Defense-
//!    in-depth: the edge could be compromised; the agent's signature
//!    is the ground-truth for content authenticity. Reject with 422.
//! 4. `pii_scrubbed == true` whenever `stages_executed` contains
//!    `"scrub"`. Reject with 422.
//! 5. `sidecar.classifications.len() == sum(components per event)`.
//!    Reject with 422.
//! 6. Each `encrypted_secret.secret_uuid` appears at least once in
//!    the scrubbed envelope as `{SECRET:uuid:description}`. Reject
//!    with 422.
//! 7. `pipeline_metadata.fields_modified` is non-decreasing across
//!    replays. NOT enforced at the route (requires prior state);
//!    persister dedupes.
//!
//! On success: submit the inner [`BatchEnvelope`] bytes + sidecar to
//! the ingest queue via [`IngestHandle::try_submit_with_sidecar`].
//! Backpressure shape matches `POST /api/v1/accord/events`:
//! `200 OK` accepted, `429` queue full, `503` persister closed.
//!
//! # Persister-side sidecar consumption (open question)
//!
//! The route handler verifies edge signature + every FSD §4.3 invariant
//! BEFORE submitting; downstream the persister TRUSTS the sidecar. But
//! today's persister still runs its own in-process pipeline on every
//! [`BatchEnvelope`] (via `IngestPipeline::receive_and_persist`'s
//! inline extract). If the [`PipelineEnvelope`] arrives with a sidecar
//! that ALREADY has classifications / features / encrypted_secrets
//! filled, the persister should NOT re-run those stages — it should
//! consume the edge-signed sidecar instead. Persister-side sidecar
//! consumption (writing classifications / features / encrypted secrets
//! rows in the same transaction as the BatchEnvelope decompose) is a
//! v1.1.x follow-up. For now the sidecar is plumbed through the queue
//! and logged at debug level. The persister re-running the pipeline
//! today is wasted work but not incorrect: the sidecar's stages are
//! deterministic, and re-running them yields the same outputs.
//!
//! [`PipelineEnvelope`]: crate::pipeline::types::PipelineEnvelope
//! [`BatchEnvelope`]: crate::schema::BatchEnvelope
//! [`CompleteTrace`]: crate::schema::CompleteTrace
//! [`verify_hybrid_via_directory`]: crate::verify::verify_hybrid_via_directory
//! [`IngestHandle::try_submit_with_sidecar`]: crate::queue::IngestHandle::try_submit_with_sidecar

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::federation::FederationDirectory;
use crate::ingest::IngestError;
use crate::pipeline::types::PipelineEnvelope;
use crate::queue::QueueError;
use crate::schema::BatchEvent;
use crate::server::AppState;
use crate::store::Backend;
use crate::verify::{
    canonical::PythonJsonDumpsCanonicalizer, ed25519::verify_trace, verify_hybrid_via_directory,
    Canonicalizer, HybridPolicy,
};

// ── Stable error kind tokens (THREAT_MODEL.md AV-15) ─────────────────

/// `pipeline_schema_version` not in the allowed set.
pub const KIND_SCHEMA_VERSION: &str = "pipeline_invariant_schema_version";
/// Edge hybrid signature failed verify (or edge key not in directory).
pub const KIND_EDGE_SIGNATURE: &str = "pipeline_invariant_edge_signature";
/// Inner agent CompleteTrace signature failed verify.
pub const KIND_INNER_SIGNATURE: &str = "pipeline_invariant_inner_signature";
/// `pii_scrubbed=false` despite `stages_executed.contains("scrub")`.
pub const KIND_PII_SCRUBBED: &str = "pipeline_invariant_pii_scrubbed";
/// `sidecar.classifications.len()` != inner envelope component count.
pub const KIND_CLASSIFICATIONS_COUNT: &str = "pipeline_invariant_classifications_count";
/// An `encrypted_secret.secret_uuid` doesn't appear as
/// `{SECRET:uuid:description}` anywhere in the scrubbed envelope.
pub const KIND_ORPHAN_SECRET: &str = "pipeline_invariant_orphan_secret";
/// v1.3.0 (CIRISPersist#46) — Edge key doesn't carry a writer role
/// tag in `federation_keys.roles`. Reject with 403.
pub const KIND_ROLE_TAG: &str = "pipeline_invariant_role_tag";

/// Role tag required for the pipeline ingest writer (v1.3.0 #46).
const ROLE_PIPELINE_WRITER: &str = "cirislens_pipeline_writer";
/// Alternate role tag accepted for the pipeline ingest writer
/// (overlaps the secrets writer privilege tier).
const ROLE_SECRETS_WRITER: &str = "cirislens_secrets_writer";

// ── Route handler ────────────────────────────────────────────────────

/// `POST /api/v1/pipeline/ingest` — accept a [`PipelineEnvelope`] from
/// a CIRISLens edge. See module-level doc for the full pipeline.
pub async fn post_pipeline_ingest<F>(
    State(state): State<AppState<F>>,
    Json(envelope): Json<PipelineEnvelope>,
) -> Response
where
    F: FederationDirectory + Backend + 'static,
{
    // 1. Schema version gate (FSD §4.3 invariant 1).
    if envelope.pipeline_schema_version != PipelineEnvelope::SCHEMA_VERSION_V1 {
        return invariant_response(
            KIND_SCHEMA_VERSION,
            format!(
                "expected {}, got {}",
                PipelineEnvelope::SCHEMA_VERSION_V1,
                envelope.pipeline_schema_version
            ),
        );
    }

    // 2. Edge hybrid signature (FSD §4.3 invariant 2).
    //
    // Canonicalize the envelope minus `edge_signature` — the edge
    // signed over `canonical(envelope || sidecar)` excluding its own
    // signature block (else the hash would depend on itself). Persist
    // owns the strip rule; the edge mirrors it.
    let canonical_bytes = match canonicalize_for_edge_signing(&envelope) {
        Ok(b) => b,
        Err(detail) => return invariant_response(KIND_EDGE_SIGNATURE, detail),
    };
    // Policy: Ed25519Fallback for now — the federation rolls out
    // hybrid-pending edge keys per the writer contract (Ed25519 first,
    // ML-DSA-65 cold-path attach). Production posture flips to Strict
    // once edge keys are PQC-complete across the fleet; until then
    // Fallback accepts Ed25519-only verification. row_age is not
    // applicable for write-path verifies (the edge_signature is
    // computed fresh per request).
    let policy = HybridPolicy::Ed25519Fallback;
    let edge_sig_outcome = verify_hybrid_via_directory(
        &*state.directory,
        &canonical_bytes,
        &envelope.edge_key_id,
        &envelope.edge_signature.ed25519,
        envelope.edge_signature.ml_dsa_65.as_deref(),
        policy,
        None,
    )
    .await;
    if let Err(e) = edge_sig_outcome {
        tracing::warn!(
            error = %e,
            kind = e.kind(),
            edge_key_id = %envelope.edge_key_id,
            "pipeline ingest rejected: edge signature failed verify"
        );
        return invariant_response(KIND_EDGE_SIGNATURE, format!("{e}"));
    }

    // 2b. Role-tag enforcement (v1.3.0, CIRISPersist#46). After the
    //     edge signature verifies, fetch the edge's KeyRecord and
    //     require a writer role tag — `cirislens_pipeline_writer`
    //     OR `cirislens_secrets_writer` (the secrets-writer tier
    //     overlaps because secrets-writers send pipeline traffic
    //     too). Reject with 403 if no writer role is present.
    let edge_record = match FederationDirectory::lookup_public_key(
        &*state.directory,
        &envelope.edge_key_id,
    )
    .await
    {
        Ok(Some(rec)) => rec,
        Ok(None) => {
            return invariant_response(
                KIND_EDGE_SIGNATURE,
                format!("edge key not in directory: {}", envelope.edge_key_id),
            );
        }
        Err(e) => {
            tracing::error!(error = %e, "edge key lookup failed during role-tag check");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    kind: "store_lookup_failed",
                    detail: format!("{e}"),
                    retry_after_seconds: Some(5),
                }),
            )
                .into_response();
        }
    };
    let has_writer_role = edge_record
        .roles
        .iter()
        .any(|r| r == ROLE_PIPELINE_WRITER || r == ROLE_SECRETS_WRITER);
    if !has_writer_role {
        tracing::warn!(
            edge_key_id = %envelope.edge_key_id,
            roles = ?edge_record.roles,
            "pipeline ingest rejected: edge key has no writer role tag"
        );
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                kind: KIND_ROLE_TAG,
                detail: format!(
                    "edge key {} missing required role ({} or {})",
                    envelope.edge_key_id, ROLE_PIPELINE_WRITER, ROLE_SECRETS_WRITER
                ),
                retry_after_seconds: None,
            }),
        )
            .into_response();
    }

    // 3. Inner agent signature verify (FSD §4.3 invariant 3 — defense-
    //    in-depth). Same path the persister uses; running it pre-queue
    //    fails fast on a compromised-edge / forged-inner-trace path.
    for event in &envelope.envelope.events {
        let BatchEvent::CompleteTrace { trace, .. } = event;
        let key = match Backend::lookup_public_key(&*state.directory, &trace.signature_key_id).await
        {
            Ok(Some(k)) => k,
            Ok(None) => {
                return invariant_response(
                    KIND_INNER_SIGNATURE,
                    format!("unknown agent key {}", trace.signature_key_id),
                );
            }
            Err(e) => {
                // Backend lookup failure — 503 is the conventional
                // shape for "transient infra" elsewhere on the route.
                tracing::error!(error = %e, "agent key lookup failed");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorResponse {
                        kind: "store_lookup_failed",
                        detail: format!("{e}"),
                        retry_after_seconds: Some(5),
                    }),
                )
                    .into_response();
            }
        };
        if let Err(e) = verify_trace(trace, &PythonJsonDumpsCanonicalizer, &key) {
            return invariant_response(
                KIND_INNER_SIGNATURE,
                format!("agent signature failed verify: {e}"),
            );
        }
    }

    // 4. pii_scrubbed consistency (FSD §4.3 invariant 4).
    let scrubbed_stage_ran = envelope
        .sidecar
        .pipeline_metadata
        .stages_executed
        .iter()
        .any(|s| s == "scrub");
    if scrubbed_stage_ran && !envelope.sidecar.pipeline_metadata.pii_scrubbed {
        return invariant_response(
            KIND_PII_SCRUBBED,
            "stages_executed contains 'scrub' but pii_scrubbed=false".to_string(),
        );
    }

    // 5. classifications length matches component count (FSD §4.3
    //    invariant 5). Only meaningful when the `classify` feature is
    //    compiled in.
    #[cfg(feature = "classify")]
    {
        let component_count: usize = envelope
            .envelope
            .events
            .iter()
            .map(|e| {
                let BatchEvent::CompleteTrace { trace, .. } = e;
                trace.components.len()
            })
            .sum();
        if envelope.sidecar.classifications.len() != component_count {
            return invariant_response(
                KIND_CLASSIFICATIONS_COUNT,
                format!(
                    "classifications.len()={}, component_count={}",
                    envelope.sidecar.classifications.len(),
                    component_count
                ),
            );
        }
    }

    // 6. Orphan-secret check (FSD §4.3 invariant 6). Each encrypted
    //    secret's UUID MUST appear at least once in the scrubbed
    //    envelope as `{SECRET:uuid:...}` — case-insensitive on uuid.
    //    Only meaningful when the `secrets` feature is compiled in.
    #[cfg(feature = "secrets")]
    {
        if !envelope.sidecar.encrypted_secrets.is_empty() {
            let haystack_lower = serde_json::to_string(&envelope.envelope)
                .unwrap_or_default()
                .to_lowercase();
            for rec in &envelope.sidecar.encrypted_secrets {
                // Search for `{SECRET:<uuid>` prefix, case-insensitive
                // on uuid. The full marker shape is
                // `{SECRET:uuid:description}` — we anchor on the
                // prefix to avoid forcing a specific description
                // format here.
                let needle = format!("{{secret:{}", rec.record.secret_uuid.to_lowercase());
                if !haystack_lower.contains(&needle) {
                    return invariant_response(
                        KIND_ORPHAN_SECRET,
                        format!(
                            "encrypted secret {} not referenced in scrubbed envelope",
                            rec.record.secret_uuid
                        ),
                    );
                }
            }
        }
    }

    // 7. Submit the INNER BatchEnvelope bytes + sidecar to the queue.
    //
    // Serialize the inner envelope as JSON bytes — same shape the
    // persister already deserializes for the legacy
    // `/api/v1/accord/events` route. The sidecar rides alongside the
    // bytes on the queue message envelope; the persister logs it at
    // debug level today and lands the persister-side consumption in a
    // v1.1.x follow-up (see module doc).
    let inner_bytes = match serde_json::to_vec(&envelope.envelope) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "inner BatchEnvelope serialize failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    kind: "serialize_inner",
                    detail: format!("{e}"),
                    retry_after_seconds: None,
                }),
            )
                .into_response();
        }
    };
    match state
        .handle
        .try_submit_with_sidecar(inner_bytes, envelope.sidecar)
    {
        Ok(()) => (StatusCode::OK, Json(AcceptedResponse { status: "ok" })).into_response(),
        Err(QueueError::Full) => {
            let mut resp = (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    kind: "queue_full",
                    detail: "queue full".to_string(),
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
                kind: "persister_closed",
                detail: "persister closed".to_string(),
                retry_after_seconds: Some(5),
            }),
        )
            .into_response(),
        Err(QueueError::Journal(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                kind: "journal",
                detail: format!("{e}"),
                retry_after_seconds: None,
            }),
        )
            .into_response(),
    }
}

// ── Helpers ──────────────────────────────────────────────────────────

/// Build a 422 response carrying a stable kind token + detail. The
/// shape matches [`IngestError::PipelineInvariant`] — the wire body
/// is the AV-15-safe surface lens consumers parse.
fn invariant_response(kind: &'static str, detail: String) -> Response {
    tracing::warn!(kind = %kind, detail = %detail, "pipeline ingest rejected");
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(ErrorResponse {
            kind,
            detail,
            retry_after_seconds: None,
        }),
    )
        .into_response()
}

/// Canonicalize the envelope minus `edge_signature` — the bytes the
/// edge actually signed. Mirrors
/// [`crate::verify::canonicalize_envelope_for_signing`]'s strip rule
/// adapted for the pipeline-envelope wire shape (the federation-
/// internal wrapper carries `edge_signature`, not `signature`).
fn canonicalize_for_edge_signing(envelope: &PipelineEnvelope) -> Result<Vec<u8>, String> {
    let mut value = serde_json::to_value(envelope)
        .map_err(|e| format!("serialize envelope for canonicalize: {e}"))?;
    if let Some(obj) = value.as_object_mut() {
        obj.remove("edge_signature");
    }
    PythonJsonDumpsCanonicalizer
        .canonicalize_value(&value)
        .map_err(|e| format!("canonicalize: {e}"))
}

// ── Wire shapes ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AcceptedResponse {
    status: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ErrorResponse {
    /// Stable kind token — same surface as [`IngestError::kind`].
    kind: &'static str,
    /// Variant-specific detail string.
    detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_seconds: Option<u32>,
}

// ── IngestError convenience constructors ─────────────────────────────
//
// Crate-internal: build a `PipelineInvariant` error from a kind token
// + detail without callers repeating the struct-literal shape.

impl IngestError {
    /// v1.1.0 (CIRISPersist#33 part 3) — construct a typed
    /// `PipelineInvariant` error. Wrap-up for the route handler so the
    /// invariant arms don't repeat the struct-literal shape.
    pub fn pipeline_invariant(kind: &'static str, detail: impl Into<String>) -> Self {
        IngestError::PipelineInvariant {
            kind,
            detail: detail.into(),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::Journal;
    use crate::pipeline::types::{
        HybridSignatureBlock, PipelineEnvelope, PipelineMetadata, PipelineSidecar,
    };
    use crate::queue::{spawn_persister, DEFAULT_QUEUE_DEPTH};
    use crate::schema::{
        BatchEnvelope, BatchEvent, CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion,
        TraceComponent, TraceLevel,
    };
    use crate::scrub::NullScrubber;
    use crate::store::MemoryBackend;
    use crate::verify::ed25519::canonical_payload_value;
    use crate::verify::PythonJsonDumpsCanonicalizer;
    use axum::body::Body;
    use axum::http::Request;
    use axum::Router;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Fixed seed for the edge signing key — tests are reproducible.
    const EDGE_SEED: [u8; 32] = [0xE1; 32];
    /// Fixed seed for the inner agent signing key.
    const AGENT_SEED: [u8; 32] = [0x42; 32];
    /// `key_id` the edge identifies itself by in `federation_keys`.
    const EDGE_KEY_ID: &str = "cirislens-edge-test-1";
    /// `signature_key_id` on the inner agent trace.
    const AGENT_KEY_ID: &str = "ciris-agent-key:pipeline-test";

    fn temp_journal() -> (tempfile::TempDir, Arc<Journal>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j.redb");
        let j = Journal::open(&path).unwrap();
        (dir, Arc::new(j))
    }

    fn build_app(queue_depth: usize) -> (Router, Arc<MemoryBackend>) {
        use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner};
        let backend = Arc::new(MemoryBackend::new());
        // Register the edge fixture key + agent fixture key in the
        // directory so verify can resolve them.
        let edge_sk = SigningKey::from_bytes(&EDGE_SEED);
        backend.add_public_key(EDGE_KEY_ID, edge_sk.verifying_key());
        // v1.3.0 (CIRISPersist#46): edge keys need a writer role to
        // pass the role-tag invariant gate. Pipeline tests grant
        // `cirislens_pipeline_writer`; the alternate
        // `cirislens_secrets_writer` would also pass.
        backend.set_roles(EDGE_KEY_ID, vec!["cirislens_pipeline_writer".to_owned()]);
        let agent_sk = SigningKey::from_bytes(&AGENT_SEED);
        backend.add_public_key(AGENT_KEY_ID, agent_sk.verifying_key());

        let (_dir, journal) = temp_journal();
        std::mem::forget(_dir);
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
        std::mem::forget(persister);
        (
            crate::server::router(AppState {
                handle,
                journal,
                directory: backend.clone(),
            }),
            backend,
        )
    }

    /// Build a signed agent CompleteTrace + outer BatchEnvelope. The
    /// trace has `component_count` components so we can exercise the
    /// classifications-count invariant.
    fn make_signed_batch(component_count: usize) -> BatchEnvelope {
        let sk = SigningKey::from_bytes(&AGENT_SEED);
        let components: Vec<TraceComponent> = (0..component_count)
            .map(|i| {
                let mut data = serde_json::Map::new();
                data.insert("attempt_index".into(), 0.into());
                if i == 0 {
                    // First component carries the audit anchor block —
                    // matches the existing ingest tests' shape.
                    data.insert("audit_sequence_number".into(), 1.into());
                    data.insert("audit_entry_hash".into(), "deadbeef".into());
                    data.insert("audit_signature".into(), "AAAA".into());
                }
                TraceComponent {
                    component_type: ComponentType::Observation,
                    event_type: ReasoningEventType::ThoughtStart,
                    timestamp: "2026-04-30T00:15:53.123Z".parse().unwrap(),
                    data,
                    agent_id_hash: None,
                }
            })
            .collect();
        let mut trace = CompleteTrace {
            trace_id: "trace-pipeline-1".into(),
            thought_id: "th-pipeline-1".into(),
            task_id: None,
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123456Z".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789012Z".parse().unwrap(),
            trace_level: TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components,
            deployment_profile: None,
            signature: String::new(),
            signature_key_id: AGENT_KEY_ID.into(),
        };
        let payload = canonical_payload_value(&trace);
        let bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload)
            .unwrap();
        let sig = sk.sign(&bytes);
        trace.signature = BASE64.encode(sig.to_bytes());
        BatchEnvelope {
            events: vec![BatchEvent::CompleteTrace {
                trace,
                trace_level: TraceLevel::Generic,
            }],
            batch_timestamp: "2026-04-30T15:00:00+00:00".parse().unwrap(),
            consent_timestamp: "2025-01-01T00:00:00Z".parse().unwrap(),
            trace_level: TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            correlation_metadata: None,
        }
    }

    /// Build a PipelineEnvelope around the given BatchEnvelope, with
    /// classification-count matching components, no encrypted secrets,
    /// and a valid edge signature.
    fn make_signed_pipeline_envelope(batch: BatchEnvelope) -> PipelineEnvelope {
        #[cfg(feature = "classify")]
        let component_count: usize = batch
            .events
            .iter()
            .map(|e| {
                let BatchEvent::CompleteTrace { trace, .. } = e;
                trace.components.len()
            })
            .sum();
        let sidecar = PipelineSidecar {
            #[cfg(feature = "classify")]
            classifications: vec![Vec::new(); component_count],
            #[cfg(feature = "extract")]
            features: None,
            #[cfg(feature = "secrets")]
            encrypted_secrets: Vec::new(),
            pipeline_metadata: PipelineMetadata {
                stages_executed: vec!["classify".into(), "scrub".into(), "extract".into()],
                fields_modified: 0,
                pii_scrubbed: true,
                secrets_encrypted: 0,
                pipeline_duration_ms: 1,
                edge_build_id: "test-edge-build".into(),
            },
        };
        let signed_at = "2026-05-14T00:00:00Z".parse().unwrap();
        let mut envelope = PipelineEnvelope {
            pipeline_schema_version: PipelineEnvelope::SCHEMA_VERSION_V1.to_string(),
            envelope: batch,
            sidecar,
            edge_signature: HybridSignatureBlock {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at,
            },
            edge_key_id: EDGE_KEY_ID.into(),
            edge_pqc_key_id: None,
        };
        // Compute canonical bytes (envelope minus edge_signature).
        let canonical = canonicalize_for_edge_signing(&envelope).expect("canonicalize");
        let edge_sk = SigningKey::from_bytes(&EDGE_SEED);
        let sig = edge_sk.sign(&canonical);
        envelope.edge_signature.ed25519 = BASE64.encode(sig.to_bytes());
        envelope
    }

    async fn post_envelope(app: &Router, env: &PipelineEnvelope) -> (StatusCode, ErrorOrAccepted) {
        let body = serde_json::to_vec(env).unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/pipeline/ingest")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed = if status == StatusCode::OK {
            ErrorOrAccepted::Accepted
        } else {
            ErrorOrAccepted::Error(serde_json::from_slice(&body_bytes).unwrap_or_else(|_| {
                ErrorResponseOwned {
                    kind: "<unparseable>".into(),
                    detail: String::from_utf8_lossy(&body_bytes).to_string(),
                    retry_after_seconds: None,
                }
            }))
        };
        (status, parsed)
    }

    #[derive(Debug, Clone, Deserialize)]
    struct ErrorResponseOwned {
        kind: String,
        #[allow(dead_code)]
        detail: String,
        #[serde(default)]
        #[allow(dead_code)]
        retry_after_seconds: Option<u32>,
    }

    #[derive(Debug, Clone)]
    enum ErrorOrAccepted {
        Accepted,
        Error(ErrorResponseOwned),
    }

    impl ErrorOrAccepted {
        fn expect_error(&self) -> &ErrorResponseOwned {
            match self {
                ErrorOrAccepted::Error(e) => e,
                ErrorOrAccepted::Accepted => panic!("expected error, got 200 OK"),
            }
        }
    }

    /// Happy path: well-formed envelope flows through every gate.
    #[tokio::test]
    async fn pipeline_ingest_accepts_well_formed_envelope() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH);
        let batch = make_signed_batch(2);
        let env = make_signed_pipeline_envelope(batch);
        let (status, _) = post_envelope(&app, &env).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// FSD §4.3 invariant 1: unknown schema version rejected.
    #[tokio::test]
    async fn pipeline_ingest_rejects_unknown_schema_version() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH);
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch);
        env.pipeline_schema_version = "99.0".into();
        let (status, body) = post_envelope(&app, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.expect_error().kind, KIND_SCHEMA_VERSION);
    }

    /// FSD §4.3 invariant 4: stages_executed contains "scrub" but
    /// pii_scrubbed=false. Re-sign after the mutation so we hit the
    /// invariant gate, not the edge-signature gate.
    #[tokio::test]
    async fn pipeline_ingest_rejects_pii_scrubbed_inconsistency() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH);
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch);
        env.sidecar.pipeline_metadata.pii_scrubbed = false;
        // Re-sign — the metadata change invalidates the edge sig.
        let canonical = canonicalize_for_edge_signing(&env).unwrap();
        let edge_sk = SigningKey::from_bytes(&EDGE_SEED);
        env.edge_signature.ed25519 = BASE64.encode(edge_sk.sign(&canonical).to_bytes());
        let (status, body) = post_envelope(&app, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.expect_error().kind, KIND_PII_SCRUBBED);
    }

    /// FSD §4.3 invariant 5: classifications.len() must equal
    /// component count. Only runs when `classify` is compiled in (the
    /// sidecar `classifications` field is feature-gated).
    #[cfg(feature = "classify")]
    #[tokio::test]
    async fn pipeline_ingest_rejects_classifications_count_mismatch() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH);
        let batch = make_signed_batch(2);
        let mut env = make_signed_pipeline_envelope(batch);
        // 2 components but 3 classifications.
        env.sidecar.classifications.push(Vec::new());
        // Re-sign.
        let canonical = canonicalize_for_edge_signing(&env).unwrap();
        let edge_sk = SigningKey::from_bytes(&EDGE_SEED);
        env.edge_signature.ed25519 = BASE64.encode(edge_sk.sign(&canonical).to_bytes());
        let (status, body) = post_envelope(&app, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.expect_error().kind, KIND_CLASSIFICATIONS_COUNT);
    }

    /// FSD §4.3 invariant 6: every encrypted_secret's UUID must appear
    /// in the scrubbed envelope. Only runs when `secrets` is compiled
    /// in.
    #[cfg(feature = "secrets")]
    #[tokio::test]
    async fn pipeline_ingest_rejects_orphan_secret() {
        use crate::pipeline::classify::Sensitivity;
        use crate::secrets::types::{EncryptedSecretRecord, SecretRecord};
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH);
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch);
        // Inject an "encrypted secret" whose UUID DOESN'T appear in
        // the scrubbed envelope. The scrubbed envelope has no
        // {SECRET:...} markers, so any UUID is orphan.
        let orphan = EncryptedSecretRecord {
            record: SecretRecord {
                secret_uuid: "11111111-1111-1111-1111-111111111111".into(),
                encrypted_value: vec![0u8; 16],
                encryption_key_ref: "master-v1".into(),
                salt: vec![0u8; 32],
                nonce: vec![0u8; 12],
                description: "orphan".into(),
                sensitivity_level: Sensitivity::Medium,
                detected_pattern: "regex:test".into(),
                context_hint: None,
                created_at: chrono::Utc::now(),
                last_accessed: None,
                access_count: 0,
                source_message_id: None,
                auto_decapsulate_for_actions: Vec::new(),
                manual_access_only: false,
                record_schema_version: "1.0".into(),
            },
            edge_hmac: None,
        };
        env.sidecar.encrypted_secrets.push(orphan);
        env.sidecar.pipeline_metadata.secrets_encrypted = 1;
        // Re-sign.
        let canonical = canonicalize_for_edge_signing(&env).unwrap();
        let edge_sk = SigningKey::from_bytes(&EDGE_SEED);
        env.edge_signature.ed25519 = BASE64.encode(edge_sk.sign(&canonical).to_bytes());
        let (status, body) = post_envelope(&app, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.expect_error().kind, KIND_ORPHAN_SECRET);
    }

    /// FSD §4.3 invariant 2: edge signature must verify. Flip a byte
    /// in `edge_signature.ed25519` and assert the route rejects.
    #[tokio::test]
    async fn pipeline_ingest_rejects_bad_edge_signature() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH);
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch);
        // Decode, flip byte 0, re-encode — base64-clean and produces
        // a still-64-byte signature that won't verify.
        let mut sig_bytes = BASE64.decode(&env.edge_signature.ed25519).unwrap();
        sig_bytes[0] ^= 0xFF;
        env.edge_signature.ed25519 = BASE64.encode(&sig_bytes);
        let (status, body) = post_envelope(&app, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.expect_error().kind, KIND_EDGE_SIGNATURE);
    }

    /// Mission constraint (MISSION.md §3 anti-pattern #7) — full
    /// queue surfaces 429 + Retry-After on the new route too.
    #[tokio::test]
    async fn pipeline_ingest_429_on_full_queue() {
        let (app, _backend) = build_app(1);
        // Saturate the queue with rapid valid-envelope submissions.
        // The persister drains one at a time; with queue_depth=1 the
        // second-in-flight submission lands 429.
        let mut got_429 = false;
        for _ in 0..200 {
            let batch = make_signed_batch(1);
            let env = make_signed_pipeline_envelope(batch);
            let body = serde_json::to_vec(&env).unwrap();
            let resp = app
                .clone()
                .oneshot(
                    Request::post("/api/v1/pipeline/ingest")
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                let retry = resp
                    .headers()
                    .get("Retry-After")
                    .and_then(|v| v.to_str().ok().map(|s| s.to_string()));
                assert_eq!(retry.as_deref(), Some("1"), "Retry-After header set");
                got_429 = true;
                break;
            }
        }
        assert!(got_429, "expected 429 at some point under saturation");
    }
}
