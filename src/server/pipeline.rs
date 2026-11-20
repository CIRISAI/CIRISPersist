//! v1.1.0 (CIRISPersist#33 part 3) — `POST /api/v1/pipeline/ingest`
//! route.
//!
//! # What this route does (FSD §4.3)
//!
//! Accepts a federation-internal [`PipelineEnvelope`] from a CIRISLens
//! edge: a typed sidecar carrying pre-computed classify / extract /
//! encrypt-and-store outputs, wrapped around the agent's original
//! (now scrubbed) [`BatchEnvelope`]. The edge is a federation peer
//! holding a live edition-2 `key:record`; the wrapper is signed with ONE
//! composite (ML-DSA-65-Ed25519) signature by that key (v62.0.0, F0-cp5).
//!
//! Pipeline (FSD §4.3 invariants 1-7):
//!
//! 1. `pipeline_schema_version` in
//!    [`PipelineEnvelope::SCHEMA_VERSION_V1`] — reject unknown with 422.
//! 2. Verify `edge_signature.composite` under `edge_key_id`'s LIVE
//!    edition-2 key via [`verify_composite_via_directory`]. Reject with 422
//!    (a key not held yet, or a record that waits, is the 424 wait). The
//!    earlier `{ed25519, ml_dsa_65}` pair is refused by name
//!    (`verify_component_signature`).
//! 3. Each inner [`CompleteTrace`] carries its `trace:complete:v1` statement
//!    (the agent's composite), checked by the edition-2 statement door when
//!    the persister ingests the batch; one without is the earlier form,
//!    refused `earlier_form_object` with 422 (v62.0.0).
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
//! `200 OK` accepted, `429` queue full, `503` persister closed. v62.0.0
//! (CC 2.7): an edge or agent key this node does not hold yet is `424`
//! [`KIND_KEY_NOT_HELD`] (`verify_unknown_key`) with `retry_after_seconds`,
//! a wait, never the terminal 422.
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
//! # Deploy ordering (v62.0.0) — the composite flag day
//!
//! v62.0.0 (JSON-cut slice F, F0-cp5; RULINGS "composite signatures only")
//! changes what invariant 2 accepts. The edge signs the same bytes as
//! before ([`canonicalize_raw_for_edge_signing`]: the envelope less
//! `edge_signature`, under CEG-produce/JCS, the v37.0.0 re-pin of
//! CIRISPersist#716), but with ONE composite signature by its edition-2 key,
//! named by its identity-ref in `edge_key_id`. The two-field form is refused
//! by name on every request from the instant v62 serves traffic; there is no
//! window. Roll the edge's composite signer with (or before) persist v62.
//!
//! Nothing re-verifies from storage on this plane — `edge_signature` is
//! checked once at admission — so the outage is bounded to in-flight
//! requests from edges still on the earlier form.
//!
//! [`PipelineEnvelope`]: crate::pipeline::types::PipelineEnvelope
//! [`BatchEnvelope`]: crate::schema::BatchEnvelope
//! [`CompleteTrace`]: crate::schema::CompleteTrace
//! [`verify_composite_via_directory`]: crate::federation::edition2::composite_verify::verify_composite_via_directory
//! [`IngestHandle::try_submit_with_sidecar`]: crate::queue::IngestHandle::try_submit_with_sidecar

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::federation::edition2::composite_verify::{
    now_ms, verify_composite_via_directory, CompositeVerifyError, VERIFY_COMPONENT_SIGNATURE,
};
use crate::federation::FederationDirectory;
use crate::ingest::IngestError;
use crate::pipeline::types::PipelineEnvelope;
use crate::queue::QueueError;
use crate::schema::BatchEvent;
use crate::server::AppState;
use crate::store::Backend;
use crate::verify::canonical::ceg_produce_canonicalize;

// ── Stable error kind tokens (THREAT_MODEL.md AV-15) ─────────────────

/// `pipeline_schema_version` not in the allowed set.
pub const KIND_SCHEMA_VERSION: &str = "pipeline_invariant_schema_version";
/// Edge composite signature refused (v62.0.0: the refusal's own token leads
/// the detail).
pub const KIND_EDGE_SIGNATURE: &str = "pipeline_invariant_edge_signature";
/// v62.0.0 (wave P7) — the body is not JSON, or not a `PipelineEnvelope`
/// (once any row-form trace event is expanded).
pub const KIND_ENVELOPE_MALFORMED: &str = "pipeline_invariant_envelope_malformed";
/// `pii_scrubbed=false` despite `stages_executed.contains("scrub")`.
pub const KIND_PII_SCRUBBED: &str = "pipeline_invariant_pii_scrubbed";
/// `sidecar.classifications.len()` != inner envelope component count.
pub const KIND_CLASSIFICATIONS_COUNT: &str = "pipeline_invariant_classifications_count";
/// An `encrypted_secret.secret_uuid` doesn't appear as
/// `{SECRET:uuid:description}` anywhere in the scrubbed envelope.
pub const KIND_ORPHAN_SECRET: &str = "pipeline_invariant_orphan_secret";
/// v62.0.0 (F0-cp5b; the lead's ruling) — the edge holds no LIVE
/// `self:delegates_to` from this node's owner bearing
/// [`INFRA_PIPELINE_WRITER`](crate::federation::types::delegation_scope::INFRA_PIPELINE_WRITER)
/// (a grant not yet seated with the edge's voice is not live). `403`. It
/// replaces the earlier role-tag kind (`pipeline_invariant_role_tag`).
pub const KIND_WRITER_NOT_DELEGATED: &str = "pipeline_writer_not_delegated";
/// v62.0.0 (F0-cp5b) — this node has no identity, no live owner, or more than
/// one: no owner can confer the writer scope. `403`, fail closed.
pub const KIND_CONFERRER_UNRESOLVED: &str = "pipeline_conferrer_unresolved";

/// v62.0.0 (CC 2.7) — the edge's or the agent's key record is not held
/// here YET: a WAIT, answered `424 Failed Dependency` with
/// `retry_after_seconds`, never the terminal 422. The token is the ingest
/// path's own for the same fact ([`crate::verify::Error::UnknownKey`]'s
/// `kind()`), so a lens edge reads one token on both doors. Re-send the
/// same envelope after the key plane catches up.
pub const KIND_KEY_NOT_HELD: &str = "verify_unknown_key";

/// How long a sender waits before re-offering an envelope whose key was not
/// held (the route's other retryable answers use the same).
const KEY_NOT_HELD_RETRY_AFTER_SECONDS: u32 = 5;

/// v62.0.0 (F0-cp5b) — why [`authorize_pipeline_writer`] refused an edge.
#[derive(Debug)]
pub enum WriterRefusal {
    /// This node has no identity (`node_key_id` unset).
    NoNodeIdentity,
    /// This node has no live owner.
    NoOwner(String),
    /// More than one live owner holds the seat (fail closed).
    AmbiguousOwner(String),
    /// The edge holds no live owner grant bearing the scope.
    NotDelegated {
        /// The edge's identity-ref.
        edge: String,
        /// The node's owner.
        owner: String,
    },
    /// A directory read failed (retryable).
    Directory(crate::federation::Error),
}

impl WriterRefusal {
    /// The stable kind token.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NoNodeIdentity | Self::NoOwner(_) | Self::AmbiguousOwner(_) => {
                KIND_CONFERRER_UNRESOLVED
            }
            Self::NotDelegated { .. } => KIND_WRITER_NOT_DELEGATED,
            Self::Directory(_) => "store_lookup_failed",
        }
    }
}

impl std::fmt::Display for WriterRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use crate::federation::types::delegation_scope::INFRA_PIPELINE_WRITER as S;
        match self {
            Self::NoNodeIdentity => write!(
                f,
                "this node has no identity (node_key_id unset), so no owner can confer {S}"
            ),
            Self::NoOwner(node) => {
                write!(
                    f,
                    "node {node} has no live owner, so no owner can confer {S}"
                )
            }
            Self::AmbiguousOwner(e) => {
                write!(
                    f,
                    "{e} — no single owner confers {S}; refused (fail closed)"
                )
            }
            Self::NotDelegated { edge, owner } => write!(
                f,
                "{edge} holds no live self:delegates_to from this node's owner {owner} bearing \
                 scope {S:?} (a grant counts once the edge's own voice seats it; \
                 secrets:writer does not cover it)"
            ),
            Self::Directory(e) => write!(f, "{e}"),
        }
    }
}

/// v62.0.0 (F0-cp5b; the lead's ruling) — **may `edge` write a pipeline
/// envelope?** True iff this node's owner (`admission::owner_of_unmarked`
/// over `node_key_id`) holds a LIVE `self:delegates_to` to `edge` bearing
/// [`INFRA_PIPELINE_WRITER`](crate::federation::types::delegation_scope::INFRA_PIPELINE_WRITER)
/// (`trust_root::owner_granted_scope`, the predicate P6's secrets door uses).
/// Nothing the edge's own key record says about itself confers anything.
///
/// # Errors
/// [`WriterRefusal`].
pub async fn authorize_pipeline_writer<F>(directory: &F, edge: &str) -> Result<(), WriterRefusal>
where
    F: FederationDirectory + ?Sized,
{
    use crate::federation::types::delegation_scope::INFRA_PIPELINE_WRITER;
    let Some(node) = directory.node_key_id() else {
        return Err(WriterRefusal::NoNodeIdentity);
    };
    let owner = match crate::federation::admission::owner_of_unmarked(directory, &node).await {
        Ok(Some(owner)) => owner,
        Ok(None) => return Err(WriterRefusal::NoOwner(node)),
        Err(e @ crate::federation::Error::AmbiguousNodeOwner { .. }) => {
            return Err(WriterRefusal::AmbiguousOwner(e.to_string()));
        }
        Err(e) => return Err(WriterRefusal::Directory(e)),
    };
    match crate::federation::trust_root::owner_granted_scope(
        directory,
        edge,
        &owner,
        INFRA_PIPELINE_WRITER,
    )
    .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(WriterRefusal::NotDelegated {
            edge: edge.to_owned(),
            owner,
        }),
        Err(e) => Err(WriterRefusal::Directory(e)),
    }
}

// ── Route handler ────────────────────────────────────────────────────

/// `POST /api/v1/pipeline/ingest` — accept a [`PipelineEnvelope`] from
/// a CIRISLens edge. See module-level doc for the full pipeline.
pub async fn post_pipeline_ingest<F>(
    State(state): State<AppState<F>>,
    body: axum::body::Bytes,
) -> Response
where
    F: FederationDirectory + Backend + 'static,
{
    // 0. v62.0.0 (wave P7) — the body as sent. The edge signs these bytes'
    //    JSON (less `edge_signature`), and an inner event may carry its trace
    //    as a `trace:complete:v1` row plus the trace blob (`statement` +
    //    `trace_blob`, no inline `trace`): the typed envelope is parsed from
    //    a copy with each such blob expanded into its `trace`
    //    (`ingest::expand_trace_blobs`, the persister's own step 1), while
    //    the edge signature is checked over, and the queue receives, the
    //    envelope EXACTLY as sent.
    let raw: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return invariant_response(
                KIND_ENVELOPE_MALFORMED,
                format!("the body is not JSON: {e}"),
            )
        }
    };
    // v62.0.0 (F0-cp5) — the earlier two-field edge signature is refused by
    // name before the typed parse (which would only say a member is missing).
    if let Some(sig) = raw.get("edge_signature").and_then(|v| v.as_object()) {
        if let Some(half) = ["ed25519", "ml_dsa_65"]
            .into_iter()
            .find(|h| sig.contains_key(*h))
        {
            return invariant_response(
                KIND_EDGE_SIGNATURE,
                format!(
                    "{VERIFY_COMPONENT_SIGNATURE}: edge_signature carries the earlier \
                     component member {half:?}. v62.0.0: the edge signs ONE composite \
                     (ML-DSA-65-Ed25519) over the same canonical bytes, sent as \
                     edge_signature.composite, by its edition-2 identity-ref; the \
                     composite rule admits no standalone component signer"
                ),
            );
        }
    }
    let mut typed_value = raw.clone();
    if let Some(inner) = raw.get("envelope") {
        let inner_bytes = serde_json::to_vec(inner).unwrap_or_default();
        match crate::ingest::expand_trace_blobs(&inner_bytes) {
            Ok(Some(crate::ingest::ExpandedBatch {
                rewritten: Some(rewritten),
                ..
            })) => match serde_json::from_slice(&rewritten) {
                Ok(v) => typed_value["envelope"] = v,
                Err(e) => {
                    return invariant_response(
                        KIND_ENVELOPE_MALFORMED,
                        format!("expanded inner envelope: {e}"),
                    )
                }
            },
            Ok(_) => {}
            Err(e) => return invariant_response(e.kind(), format!("{e}")),
        }
    }
    let envelope: PipelineEnvelope = match serde_json::from_value(typed_value) {
        Ok(env) => env,
        Err(e) => {
            return invariant_response(
                KIND_ENVELOPE_MALFORMED,
                format!("not a PipelineEnvelope: {e}"),
            )
        }
    };
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
    let canonical_bytes = match canonicalize_raw_for_edge_signing(&raw) {
        Ok(b) => b,
        Err(detail) => return invariant_response(KIND_EDGE_SIGNATURE, detail),
    };
    // v62.0.0 (F0-cp5) — ONE composite under the edge's LIVE edition-2 key
    // (the shared `verify_composite_via_directory`).
    let sig = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        envelope.edge_signature.composite.trim(),
    ) {
        Ok(b) => b,
        Err(e) => {
            return invariant_response(
                KIND_EDGE_SIGNATURE,
                format!("edge_signature.composite is not base64: {e}"),
            )
        }
    };
    if let Err(e) = verify_composite_via_directory(
        &*state.directory,
        &canonical_bytes,
        &envelope.edge_key_id,
        &sig,
        now_ms(),
    )
    .await
    {
        tracing::warn!(
            error = %e,
            kind = e.token(),
            edge_key_id = %envelope.edge_key_id,
            "pipeline ingest rejected: edge signature refused"
        );
        return edge_signature_refusal(&e);
    }

    // 2b. v62.0.0 (F0-cp5b; the lead's ruling) — the writer capability:
    //     a live `self:delegates_to` from this node's owner to the edge
    //     bearing `infra:pipeline_writer`, seated with the edge's voice. It
    //     replaces the earlier `capability_roles` tags (a key's own claim).
    if let Err(refusal) = authorize_pipeline_writer(&*state.directory, &envelope.edge_key_id).await
    {
        tracing::warn!(
            edge_key_id = %envelope.edge_key_id,
            kind = refusal.kind(),
            "pipeline ingest rejected: {refusal}"
        );
        let (status, retry) = match &refusal {
            WriterRefusal::Directory(_) => (StatusCode::SERVICE_UNAVAILABLE, Some(5)),
            _ => (StatusCode::FORBIDDEN, None),
        };
        return (
            status,
            Json(ErrorResponse {
                kind: refusal.kind(),
                detail: refusal.to_string(),
                retry_after_seconds: retry,
            }),
        )
            .into_response();
    }

    // 3. The inner traces (FSD §4.3 invariant 3). v62.0.0 (wave P7; CC
    //    3.1.5) — an inner trace carrying its `trace:complete:v1` row is
    //    verified by the edition-2 statement door when the persister ingests
    //    the batch (`ingest::admit_trace_statement`, before anything of the
    //    trace is written). One without is the earlier form: refused by name.
    //    v62.0.0 (F0-cp6d) — the earlier-form verify that followed the
    //    refusal (an agent key read + `verify_trace`) is deleted; the route
    //    refuses even were the switch open (fail closed: it never queues an
    //    unverified inner trace).
    for event in &envelope.envelope.events {
        let BatchEvent::CompleteTrace { statement, .. } = event;
        if statement.is_some() {
            continue;
        }
        let detail = match crate::federation::edition2::door::refuse_earlier_form(
            crate::ingest::TRACE_PLANE,
        ) {
            Err(e) => e.to_string(),
            Ok(()) => "an inline trace with no trace:complete:v1 statement is the earlier \
                           form; this route admits only the row form"
                .to_owned(),
        };
        return invariant_response(
            crate::federation::edition2::token::EARLIER_FORM_OBJECT,
            detail,
        );
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
    // v62.0.0 (wave P7) — the inner envelope as SENT (a row-form event keeps
    // its `statement` and `trace_blob`; the persister checks the blob's
    // bytes against the row, so they must reach it unchanged).
    let inner_bytes = match serde_json::to_vec(&raw["envelope"]) {
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
/// v62.0.0 (F0-cp5) — the answer to an edge signature
/// [`verify_composite_via_directory`] refused. A key not held yet, a record
/// that waits on a key, and an instant no record covers are the WAIT (`424`,
/// [`KIND_KEY_NOT_HELD`], CC 2.7); a failed directory read is `503`; every
/// other refusal is the terminal `422` [`KIND_EDGE_SIGNATURE`], its detail
/// led by the refusal's own token.
fn edge_signature_refusal(e: &CompositeVerifyError) -> Response {
    match e {
        CompositeVerifyError::UnknownKey(_)
        | CompositeVerifyError::Waiting { .. }
        | CompositeVerifyError::NotCovered { .. } => key_not_held_response(format!("{e}")),
        CompositeVerifyError::Directory(inner) => {
            tracing::error!(error = %inner, "edge key read failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    kind: "store_lookup_failed",
                    detail: format!("{e}"),
                    retry_after_seconds: Some(5),
                }),
            )
                .into_response()
        }
        CompositeVerifyError::NotIdentityRef(_)
        | CompositeVerifyError::Revoked(_)
        | CompositeVerifyError::ComponentSignature { .. }
        | CompositeVerifyError::Invalid(_) => {
            invariant_response(KIND_EDGE_SIGNATURE, format!("{e}"))
        }
    }
}

/// v62.0.0 (CC 2.7) — the WAIT: `424`, [`KIND_KEY_NOT_HELD`], with
/// `retry_after_seconds`.
fn key_not_held_response(detail: String) -> Response {
    tracing::info!(kind = KIND_KEY_NOT_HELD, detail = %detail, "pipeline ingest waits");
    (
        StatusCode::FAILED_DEPENDENCY,
        Json(ErrorResponse {
            kind: KIND_KEY_NOT_HELD,
            detail,
            retry_after_seconds: Some(KEY_NOT_HELD_RETRY_AFTER_SECONDS),
        }),
    )
        .into_response()
}

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
///
/// # v37.0.0 (CIRISPersist#716) — routed through the produce gate
///
/// From the v4.15.0 JCS produce flip to v36.x this function hand-built
/// `PythonJsonDumpsCanonicalizer` (V1Python) while every other persist
/// signing/admission surface re-canonicalized through
/// [`ceg_produce_canonicalize`] (V2Jcs). It was the second instance of
/// the [#714] class and was left standing there **deliberately**: unlike
/// #714's subject, the signer here is another repo's deployed fleet
/// (CIRISEdge), so persist could not flip it alone.
///
/// v37.0.0 is the operator-declared flag day, so it flips. Same strip
/// rule (`edge_signature` only — the federation-internal wrapper's
/// analogue of the `signature`/`signature_pqc` strip), now over the gate.
///
/// **This changes the verified bytes** — but only for payloads on which
/// the two rules actually diverge (non-ASCII, or non-ES float tokens).
/// The two canonicalizations are byte-identical for plain-ASCII payloads,
/// so an un-re-pinned edge fails at invariant 2 on its first DIVERGENT
/// envelope, not necessarily on its first envelope. Unlike the audit
/// plane — which #714
/// PINNED to V1 because it re-verifies STORED rows — nothing here
/// re-verifies from storage: `edge_signature` is checked once, at
/// admission, against bytes rebuilt from the request. So the blast radius
/// is bounded to in-flight requests from un-re-pinned peers, and it ends
/// when the peer rolls forward. No stored corpus goes dark.
///
/// [#714]: https://github.com/CIRISAI/CIRISPersist/issues/714
#[cfg(test)]
fn canonicalize_for_edge_signing(envelope: &PipelineEnvelope) -> Result<Vec<u8>, String> {
    let value = serde_json::to_value(envelope)
        .map_err(|e| format!("serialize envelope for canonicalize: {e}"))?;
    canonicalize_raw_for_edge_signing(&value)
}

/// v62.0.0 (wave P7) — [`canonicalize_for_edge_signing`] over the envelope
/// JSON as received: the route checks the edge signature over what the edge
/// sent (a row-form trace event's `statement` / `trace_blob` included), never
/// over a re-serialisation of the typed struct. For an envelope that is a
/// serialised `PipelineEnvelope` the two agree byte for byte.
fn canonicalize_raw_for_edge_signing(envelope: &serde_json::Value) -> Result<Vec<u8>, String> {
    let mut value = envelope.clone();
    if let Some(obj) = value.as_object_mut() {
        obj.remove("edge_signature");
    }
    ceg_produce_canonicalize(&value).map_err(|e| format!("canonicalize: {e}"))
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

// v62.0.0 (P7-fix5, P7-fix7) — every backend gets the door: EVERY route
// witness runs on sqlite AND postgres (one backend-generic `*_on` body, a
// sqlite runner and a `_postgres` runner over `build_pg_app`); the one pure
// witness runs in either build. The allow covers any helper a postgres-only
// build leaves unused.
#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
#[cfg_attr(not(feature = "sqlite"), allow(dead_code, unused_imports))]
mod tests {
    use super::*;
    use crate::federation::edition2::fixture_switch as e2;
    use crate::journal::Journal;
    use crate::pipeline::types::{
        CompositeSignatureBlock, PipelineEnvelope, PipelineMetadata, PipelineSidecar,
    };
    use crate::queue::{spawn_persister, DEFAULT_QUEUE_DEPTH};
    use crate::schema::{
        BatchEnvelope, BatchEvent, CompleteTrace, ComponentType, ReasoningEventType, SchemaVersion,
        TraceComponent, TraceLevel,
    };
    use crate::scrub::NullScrubber;
    #[cfg(feature = "sqlite")]
    use crate::store::sqlite::SqliteBackend;
    use crate::verify::ed25519::canonical_payload_value;
    use crate::verify::{Canonicalizer, PythonJsonDumpsCanonicalizer};
    use axum::body::Body;
    use axum::http::Request;
    use axum::Router;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine as _;
    use ed25519_dalek::{Signer, SigningKey};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// v62.0.0 (F0-cp5) — the edge's edition-2 key (a fixture seed): the
    /// envelope names it by its identity-ref (`e2::kid(EDGE)`).
    const EDGE: &str = "f0-cp5-lens-edge";
    /// Fixed seed for the inner agent signing key.
    const AGENT_SEED: [u8; 32] = [0x42; 32];
    /// `signature_key_id` on the inner agent trace.
    const AGENT_KEY_ID: &str = "ciris-agent-key:pipeline-test";

    /// ONE composite by [`EDGE`] over `bytes`, base64.
    fn edge_composite(bytes: &[u8]) -> String {
        BASE64.encode(e2::signing_key(EDGE).sign(bytes).expect("composite sign"))
    }

    /// v62.0.0 (F0-cp5) — sign `envelope` the way an edge does: canonicalize
    /// through the produce gate, then ONE composite over those bytes.
    ///
    /// Every fixture goes through here so there is exactly one place that
    /// knows the edge signing shape; the witnesses that must deviate from
    /// it (V1 bytes, a lone half) do so explicitly and say why.
    async fn sign_edge(envelope: &mut PipelineEnvelope) {
        let canonical = canonicalize_for_edge_signing(envelope).expect("canonicalize");
        envelope.edge_signature.composite = edge_composite(&canonical);
    }

    fn temp_journal() -> (tempfile::TempDir, Arc<Journal>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j.redb");
        let j = Journal::open(&path).unwrap();
        (dir, Arc::new(j))
    }

    /// v62.0.0 (P7-fix5) — a backend the route's witnesses run on: the
    /// store traits the router and the persister need, and the inherent
    /// "this node is" setter the writer grant's fixture reads (I2889).
    trait RouteBackend:
        crate::store::Backend + crate::federation::FederationDirectory + 'static
    {
        fn tell_node(&self, key_id: String);
    }

    #[cfg(feature = "sqlite")]
    impl RouteBackend for SqliteBackend {
        fn tell_node(&self, key_id: String) {
            self.set_node_key_id(key_id);
        }
    }

    #[cfg(feature = "postgres")]
    impl RouteBackend for crate::store::postgres::PostgresBackend {
        fn tell_node(&self, key_id: String) {
            self.set_node_key_id(key_id);
        }
    }

    /// v62.0.0 (P7-fix5) — the pipeline app over ANY [`RouteBackend`]: the
    /// edge's live edition-2 key, this node's owner seated and the edge
    /// granted `infra:pipeline_writer` (F0-cp5b, I2889's fixture), the
    /// persister and the router.
    async fn app_on<B: RouteBackend>(backend: Arc<B>, queue_depth: usize) -> Router {
        use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner};
        // v62.0.0 (F0-cp5) — the edge holds a live edition-2 key.
        e2::put_key(&*backend, EDGE, &["node"]).await;
        // v62.0.0 (F0-cp5b) — the writer capability: this node's owner grants
        // the edge `infra:pipeline_writer`, seated with the edge's voice
        // (I2889's fixture).
        {
            use crate::server::pipeline_writer_invariants as w;
            backend.tell_node(e2::kid(w::NODE));
            w::seat_owner(&*backend).await;
            w::grant(
                &*backend,
                EDGE,
                &[crate::federation::types::delegation_scope::INFRA_PIPELINE_WRITER],
                true,
            )
            .await;
        }

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
        crate::server::router(AppState {
            handle,
            journal,
            directory: backend,
        })
    }

    #[cfg(feature = "sqlite")]
    async fn build_app(queue_depth: usize) -> (Router, Arc<SqliteBackend>) {
        // v62.0.0 (P7-fix7) — no earlier-form key seam: with the doors shut
        // nothing reads an inner earlier-form signer (row-form traces are the
        // statement door's; an inline trace is refused before any key read).
        let backend = Arc::new(crate::store::test_backend::test_backend());
        let app = app_on(backend.clone(), queue_depth).await;
        (app, backend)
    }

    /// v62.0.0 (P7-fix5) — [`build_app`] on a fresh, migrated postgres
    /// database; `None` (the twin returns) when no test DSN is set.
    #[cfg(feature = "postgres")]
    async fn build_pg_app(
        queue_depth: usize,
    ) -> Option<(Router, Arc<crate::store::postgres::PostgresBackend>)> {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let backend = Arc::new(
            crate::store::postgres::PostgresBackend::connect(&dsn)
                .await
                .expect("connect the test database"),
        );
        backend.run_migrations().await.expect("migrations");
        let app = app_on(backend.clone(), queue_depth).await;
        Some((app, backend))
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
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: String::new(),
            signature_key_id: AGENT_KEY_ID.into(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
            run_kind: None,
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
                statement: None,
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
    async fn make_signed_pipeline_envelope(batch: BatchEnvelope) -> PipelineEnvelope {
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
            edge_signature: CompositeSignatureBlock {
                composite: String::new(),
                signed_at,
            },
            edge_key_id: e2::kid(EDGE),
        };
        sign_edge(&mut envelope).await;
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

    /// v62.0.0 (CC 2.7, wave P9) — **I3609: a key this node does not hold yet
    /// is a retryable wait at the pipeline route**, the ingest path's token
    /// (`verify_unknown_key`) at `424` with `retry_after_seconds`, never the
    /// terminal 422: an edge key not registered. (P7-fix4: the agent leg is
    /// deleted; a row-form trace's signer is the persister's statement door's
    /// to judge, retryable `federation_attester_key_unknown`.)
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i3609_a_key_not_held_is_a_retryable_424() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(i3609_a_key_not_held_is_a_retryable_424_on(&app, &*backend)).await;
    }

    /// [`i3609_a_key_not_held_is_a_retryable_424`] on postgres (P7-fix7: every backend gets the door).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3609_a_key_not_held_is_a_retryable_424_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(i3609_a_key_not_held_is_a_retryable_424_on(&app, &*backend)).await;
    }

    async fn i3609_a_key_not_held_is_a_retryable_424_on<B: RouteBackend>(
        app: &Router,
        _backend: &B,
    ) {
        // v62.0.0 (P7-fix4) — the agent leg (an inline inner trace whose
        // earlier-form signer key is not held) is deleted: the route no
        // longer checks an inner earlier-form signature (the doors are shut,
        // so an inline inner trace is refused `earlier_form_object`), and a
        // row-form trace's signer is judged by the persister's statement door
        // (`federation_attester_key_unknown`, retryable: P7 I3474 / fix2).
        let mut env = make_signed_pipeline_envelope(make_signed_batch(1)).await;
        env.edge_key_id = e2::kid("f0-cp5-lens-edge-not-held-here");
        sign_edge(&mut env).await;
        let (status, body) = post_envelope(app, &env).await;
        assert_eq!(
            status,
            StatusCode::FAILED_DEPENDENCY,
            "I3609 edge: {body:?}"
        );
        let e = body.expect_error();
        assert_eq!(e.kind, KIND_KEY_NOT_HELD, "I3609 edge");
        assert!(e.retry_after_seconds.is_some(), "I3609 edge: retryable");
    }

    /// v62.0.0 (F0-cp5b) — **I2889 (route): an edge whose composite verifies
    /// but who holds no owner grant of `infra:pipeline_writer` is refused by
    /// name**, `403` `pipeline_writer_not_delegated`, final (no
    /// `retry_after_seconds`): never the 424 key wait that cannot clear.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2889_an_ungranted_edge_is_refused_by_name() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(i2889_an_ungranted_edge_is_refused_by_name_on(
            &app, &*backend,
        ))
        .await;
    }

    /// [`i2889_an_ungranted_edge_is_refused_by_name`] on postgres (P7-fix5: every backend gets the door).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2889_an_ungranted_edge_is_refused_by_name_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(i2889_an_ungranted_edge_is_refused_by_name_on(
            &app, &*backend,
        ))
        .await;
    }

    async fn i2889_an_ungranted_edge_is_refused_by_name_on<B: RouteBackend>(
        app: &Router,
        backend: &B,
    ) {
        const UNGRANTED: &str = "f0-cp5b-lens-edge-ungranted";
        let who = e2::put_key(backend, UNGRANTED, &["node"]).await;
        let mut env = make_signed_pipeline_envelope(make_signed_batch(1)).await;
        env.edge_key_id = who;
        let canonical = canonicalize_for_edge_signing(&env).unwrap();
        env.edge_signature.composite = BASE64.encode(
            e2::signing_key(UNGRANTED)
                .sign(&canonical)
                .expect("composite sign"),
        );
        let (status, body) = post_envelope(app, &env).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "I2889: {body:?}");
        let e = body.expect_error();
        assert_eq!(e.kind, KIND_WRITER_NOT_DELEGATED, "I2889");
        assert!(e.retry_after_seconds.is_none(), "I2889: final");
    }

    /// Happy path: well-formed envelope flows through every gate.
    ///
    /// v62.0.0 (P7-fix4) — on the v62 trace wire: the inner trace as its row
    /// + blob ([`to_row_form`]).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn pipeline_ingest_accepts_well_formed_envelope() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(pipeline_ingest_accepts_well_formed_envelope_on(
            &app, &*backend,
        ))
        .await;
    }

    /// [`pipeline_ingest_accepts_well_formed_envelope`] on postgres (P7-fix5: every backend gets the door).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn pipeline_ingest_accepts_well_formed_envelope_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(pipeline_ingest_accepts_well_formed_envelope_on(
            &app, &*backend,
        ))
        .await;
    }

    async fn pipeline_ingest_accepts_well_formed_envelope_on<B: RouteBackend>(
        app: &Router,
        backend: &B,
    ) {
        let batch = make_signed_batch(2);
        let env = make_signed_pipeline_envelope(batch).await;
        let (status, body) = post_row_form(app, backend, &env).await;
        assert_eq!(status, StatusCode::OK, "{body:?}");
    }

    /// v62.0.0 (wave P7) — sign a RAW envelope value the way the edge does
    /// (the route checks the signature over the body as sent).
    async fn sign_edge_raw(value: &mut serde_json::Value) {
        let canonical = canonicalize_raw_for_edge_signing(value).expect("canonicalize");
        value["edge_signature"]["composite"] = serde_json::json!(edge_composite(&canonical));
    }

    async fn post_raw(app: &Router, value: &serde_json::Value) -> (StatusCode, String) {
        let resp = app
            .clone()
            .oneshot(
                Request::post("/api/v1/pipeline/ingest")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(value).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        (status, String::from_utf8_lossy(&bytes).to_string())
    }

    /// v62.0.0 (P7-fix4; P7-fix5) — the inner agent's edition-2 key (a
    /// fixture seed), put as an **`agent`** key: a trace is authored by the
    /// agent (the `trace:{form}:{version}` family's authorship, CC 3.4.5:
    /// self-emitted; whether the door also refuses other signer kinds waits
    /// on CC, P7-fix6). An agent record ends (at most 365 days), so
    /// the row-form trace is dated from the key's own window
    /// (`key_window_start_ms` + `OWNER_BINDING_OFFSET_DAYS`, K2's owner-binding
    /// rule), never the wall clock nor the batch fixture's fixed dates.
    const ROW_AGENT: &str = "p7-fix4-pipeline-agent";

    /// v62.0.0 (P7-fix4) — **`env` as an edge sends it on the v62 trace
    /// wire**: every inner event in the ROW form (P7): `statement` (the
    /// agent's `trace:complete:v1` row, one composite under [`ROW_AGENT`]'s
    /// live key) + `trace_blob` (the trace's JCS bytes, no signature
    /// members), and no inline `trace`; then the edge's composite over the
    /// body as sent ([`sign_edge_raw`]). The typed envelope's sidecar (the
    /// mutations a test made) is carried unchanged. With the earlier-form
    /// doors shut, an inline inner trace is refused at the route, so every
    /// fixture that must pass the inner gate goes through here.
    async fn to_row_form(kid: &str, env: &PipelineEnvelope) -> serde_json::Value {
        let mut value = serde_json::to_value(env).unwrap();
        row_form_events(kid, &mut value);
        sign_edge_raw(&mut value).await;
        value
    }

    /// Put [`ROW_AGENT`]'s live key on `backend` (ONCE per test: the record
    /// is signed, so a second put is a second row); its identity-ref.
    async fn row_agent<D: crate::federation::FederationDirectory + ?Sized>(backend: &D) -> String {
        e2::put_key(backend, ROW_AGENT, &["agent"]).await
    }

    /// The inner events of a raw envelope, rewritten to the row form in place
    /// under `kid` ([`row_agent`]); the edge signature is NOT recomputed.
    fn row_form_events(kid: &str, value: &mut serde_json::Value) {
        let events = value["envelope"]["events"]
            .as_array_mut()
            .expect("the inner events");
        // Dated from the agent key's OWN window (K2's rule, the one the owner
        // bindings use): its start plus a fixed offset, never the wall clock.
        let offset_days =
            u64::try_from(crate::federation::tier_ingest::test_support::OWNER_BINDING_OFFSET_DAYS)
                .expect("a positive day count");
        let completed_ms = e2::key_window_start_ms(ROW_AGENT) + offset_days * 86_400_000;
        let completed = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            i64::try_from(completed_ms).expect("ms fits i64"),
        )
        .expect("a valid instant");
        let started = completed - chrono::Duration::seconds(19);
        let stamp = |t: chrono::DateTime<chrono::Utc>| {
            serde_json::json!(t.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
        };
        for event in events.iter_mut() {
            let mut trace = event["trace"].clone();
            trace["started_at"] = stamp(started);
            trace["completed_at"] = stamp(completed);
            let blob = crate::ingest::canonical_trace_blob(&trace).expect("a trace object");
            let parsed: CompleteTrace =
                serde_json::from_slice(&blob).expect("the blob is a CompleteTrace");
            let payload =
                crate::ingest::trace_row_payload(&parsed, &blob, kid).expect("the row payload");
            let statement = ciris_verify_core::edition2::sign_row_statement(
                &e2::signing_key(ROW_AGENT),
                kid,
                kid,
                crate::ingest::TRACE_ROW_TYPE,
                crate::ingest::TRACE_FAMILY_ID,
                &payload,
                vec![],
            )
            .expect("sign the trace row");
            let obj = event.as_object_mut().expect("an event object");
            obj.remove("trace");
            obj.insert(
                "statement".into(),
                serde_json::json!(BASE64.encode(statement)),
            );
            obj.insert("trace_blob".into(), serde_json::json!(BASE64.encode(blob)));
        }
    }

    /// POST a raw envelope, read back as [`post_envelope`] does.
    async fn post_value(app: &Router, value: &serde_json::Value) -> (StatusCode, ErrorOrAccepted) {
        let (status, text) = post_raw(app, value).await;
        let parsed = if status == StatusCode::OK {
            ErrorOrAccepted::Accepted
        } else {
            ErrorOrAccepted::Error(serde_json::from_str(&text).unwrap_or_else(|_| {
                ErrorResponseOwned {
                    kind: "<unparseable>".into(),
                    detail: text.clone(),
                    retry_after_seconds: None,
                }
            }))
        };
        (status, parsed)
    }

    /// [`to_row_form`] then [`post_value`].
    async fn post_row_form<D: crate::federation::FederationDirectory + ?Sized>(
        app: &Router,
        backend: &D,
        env: &PipelineEnvelope,
    ) -> (StatusCode, ErrorOrAccepted) {
        let kid = row_agent(backend).await;
        post_value(app, &to_row_form(&kid, env).await).await
    }

    /// The well-formed envelope with its first event in the ROW form:
    /// `statement` + `trace_blob` (the trace's bytes), no inline `trace`.
    /// `blob_of` builds the blob from the trace object.
    async fn row_form_envelope(
        blob_of: impl FnOnce(&serde_json::Value) -> Vec<u8>,
    ) -> serde_json::Value {
        let env = make_signed_pipeline_envelope(make_signed_batch(2)).await;
        let mut value = serde_json::to_value(&env).unwrap();
        let event = &mut value["envelope"]["events"][0];
        let trace = event["trace"].clone();
        let obj = event.as_object_mut().unwrap();
        obj.remove("trace");
        obj.insert(
            "statement".into(),
            serde_json::json!(BASE64.encode(b"a statement the persister checks")),
        );
        obj.insert(
            "trace_blob".into(),
            serde_json::json!(BASE64.encode(blob_of(&trace))),
        );
        sign_edge_raw(&mut value).await;
        value
    }

    /// **I3484** (v62.0.0, wave P7) — the Lens route accepts a row-form trace
    /// event (`statement` + `trace_blob`, no inline `trace`): it parses, the
    /// edge signature is checked over the body as sent, and the batch is
    /// queued with the event unchanged (the persister's statement door checks
    /// the row against the blob's bytes).
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i3484_pipeline_ingest_accepts_the_row_form() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(i3484_pipeline_ingest_accepts_the_row_form_on(
            &app, &*backend,
        ))
        .await;
    }

    /// [`i3484_pipeline_ingest_accepts_the_row_form`] on postgres (P7-fix7: every backend gets the door).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3484_pipeline_ingest_accepts_the_row_form_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(i3484_pipeline_ingest_accepts_the_row_form_on(
            &app, &*backend,
        ))
        .await;
    }

    async fn i3484_pipeline_ingest_accepts_the_row_form_on<B: RouteBackend>(
        app: &Router,
        _backend: &B,
    ) {
        let value = row_form_envelope(|t| crate::ingest::canonical_trace_blob(t).unwrap()).await;
        let (status, body) = post_raw(app, &value).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "I3484: the row form is accepted: {body}"
        );
    }

    /// **I3485** (v62.0.0, wave P7) — a row-form event whose blob carries a
    /// signature member of its own is refused at the route by name.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i3485_pipeline_ingest_refuses_a_signed_blob() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(i3485_pipeline_ingest_refuses_a_signed_blob_on(
            &app, &*backend,
        ))
        .await;
    }

    /// [`i3485_pipeline_ingest_refuses_a_signed_blob`] on postgres (P7-fix7: every backend gets the door).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3485_pipeline_ingest_refuses_a_signed_blob_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(i3485_pipeline_ingest_refuses_a_signed_blob_on(
            &app, &*backend,
        ))
        .await;
    }

    async fn i3485_pipeline_ingest_refuses_a_signed_blob_on<B: RouteBackend>(
        app: &Router,
        _backend: &B,
    ) {
        let value = row_form_envelope(|t| serde_json::to_vec(t).unwrap()).await;
        let (status, body) = post_raw(app, &value).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "I3485: {body}");
        assert!(
            body.contains(crate::ingest::TRACE_BLOB_CARRIES_SIGNATURE),
            "I3485: refused by name: {body}"
        );
    }

    /// FSD §4.3 invariant 1: unknown schema version rejected.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn pipeline_ingest_rejects_unknown_schema_version() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(pipeline_ingest_rejects_unknown_schema_version_on(
            &app, &*backend,
        ))
        .await;
    }

    /// [`pipeline_ingest_rejects_unknown_schema_version`] on postgres (P7-fix7: every backend gets the door).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn pipeline_ingest_rejects_unknown_schema_version_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(pipeline_ingest_rejects_unknown_schema_version_on(
            &app, &*backend,
        ))
        .await;
    }

    async fn pipeline_ingest_rejects_unknown_schema_version_on<B: RouteBackend>(
        app: &Router,
        _backend: &B,
    ) {
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch).await;
        env.pipeline_schema_version = "99.0".into();
        let (status, body) = post_envelope(app, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.expect_error().kind, KIND_SCHEMA_VERSION);
    }

    /// FSD §4.3 invariant 4: stages_executed contains "scrub" but
    /// pii_scrubbed=false. Re-sign after the mutation so we hit the
    /// invariant gate, not the edge-signature gate.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn pipeline_ingest_rejects_pii_scrubbed_inconsistency() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(pipeline_ingest_rejects_pii_scrubbed_inconsistency_on(
            &app, &*backend,
        ))
        .await;
    }

    /// [`pipeline_ingest_rejects_pii_scrubbed_inconsistency`] on postgres (P7-fix5: every backend gets the door).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn pipeline_ingest_rejects_pii_scrubbed_inconsistency_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(pipeline_ingest_rejects_pii_scrubbed_inconsistency_on(
            &app, &*backend,
        ))
        .await;
    }

    async fn pipeline_ingest_rejects_pii_scrubbed_inconsistency_on<B: RouteBackend>(
        app: &Router,
        backend: &B,
    ) {
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch).await;
        env.sidecar.pipeline_metadata.pii_scrubbed = false;
        // v62.0.0 (P7-fix4) — the row form, re-signed by the edge over the
        // body as sent (the metadata change invalidated the old signature).
        let (status, body) = post_row_form(app, backend, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.expect_error().kind, KIND_PII_SCRUBBED);
    }

    /// FSD §4.3 invariant 5: classifications.len() must equal
    /// component count. Only runs when `classify` is compiled in (the
    /// sidecar `classifications` field is feature-gated).
    #[cfg(feature = "classify")]
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn pipeline_ingest_rejects_classifications_count_mismatch() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(pipeline_ingest_rejects_classifications_count_mismatch_on(
            &app, &*backend,
        ))
        .await;
    }

    /// [`pipeline_ingest_rejects_classifications_count_mismatch`] on postgres (P7-fix5: every backend gets the door).
    #[cfg(feature = "classify")]
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn pipeline_ingest_rejects_classifications_count_mismatch_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(pipeline_ingest_rejects_classifications_count_mismatch_on(
            &app, &*backend,
        ))
        .await;
    }

    #[cfg(feature = "classify")]
    async fn pipeline_ingest_rejects_classifications_count_mismatch_on<B: RouteBackend>(
        app: &Router,
        backend: &B,
    ) {
        let batch = make_signed_batch(2);
        let mut env = make_signed_pipeline_envelope(batch).await;
        // 2 components but 3 classifications.
        env.sidecar.classifications.push(Vec::new());
        // v62.0.0 (P7-fix4) — the row form (the blob carries the same 2
        // components), re-signed by the edge.
        let (status, body) = post_row_form(app, backend, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.expect_error().kind, KIND_CLASSIFICATIONS_COUNT);
    }

    /// FSD §4.3 invariant 6: every encrypted_secret's UUID must appear
    /// in the scrubbed envelope. Only runs when `secrets` is compiled
    /// in.
    #[cfg(feature = "secrets")]
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn pipeline_ingest_rejects_orphan_secret() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(pipeline_ingest_rejects_orphan_secret_on(&app, &*backend)).await;
    }

    /// [`pipeline_ingest_rejects_orphan_secret`] on postgres (P7-fix5: every backend gets the door).
    #[cfg(feature = "secrets")]
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn pipeline_ingest_rejects_orphan_secret_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(pipeline_ingest_rejects_orphan_secret_on(&app, &*backend)).await;
    }

    #[cfg(feature = "secrets")]
    async fn pipeline_ingest_rejects_orphan_secret_on<B: RouteBackend>(app: &Router, backend: &B) {
        use crate::pipeline::classify::Sensitivity;
        use crate::secrets::types::{EncryptedSecretRecord, SecretRecord};
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch).await;
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
        // v62.0.0 (P7-fix4) — the row form, re-signed by the edge. The route
        // searches the expanded (typed) envelope, whose trace is the blob's.
        let (status, body) = post_row_form(app, backend, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.expect_error().kind, KIND_ORPHAN_SECRET);
    }

    /// FSD §4.3 invariant 2: edge signature must verify. Flip a byte
    /// in `edge_signature.composite` and assert the route rejects.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn pipeline_ingest_rejects_bad_edge_signature() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(pipeline_ingest_rejects_bad_edge_signature_on(
            &app, &*backend,
        ))
        .await;
    }

    /// [`pipeline_ingest_rejects_bad_edge_signature`] on postgres (P7-fix7: every backend gets the door).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn pipeline_ingest_rejects_bad_edge_signature_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(pipeline_ingest_rejects_bad_edge_signature_on(
            &app, &*backend,
        ))
        .await;
    }

    async fn pipeline_ingest_rejects_bad_edge_signature_on<B: RouteBackend>(
        app: &Router,
        _backend: &B,
    ) {
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch).await;
        // Decode, flip byte 0, re-encode — base64-clean and produces
        // a still-composite-length signature that won't verify.
        let mut sig_bytes = BASE64.decode(&env.edge_signature.composite).unwrap();
        sig_bytes[0] ^= 0xFF;
        env.edge_signature.composite = BASE64.encode(&sig_bytes);
        let (status, body) = post_envelope(app, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let err = body.expect_error();
        assert_eq!(err.kind, KIND_EDGE_SIGNATURE);
        assert!(
            err.detail.starts_with(
                crate::federation::edition2::composite_verify::VERIFY_COMPOSITE_INVALID
            ),
            "{}",
            err.detail
        );
    }

    /// v62.0.0 (F0-cp5) — **I2882: the earlier edge signature is refused by
    /// name at the route.** The two-field `{ed25519, ml_dsa_65}` block (both
    /// halves, or the Ed25519 half alone) is refused
    /// `verify_component_signature` before the typed parse; a lone Ed25519
    /// half sent AS the composite is refused by its length; an edge named by
    /// a label, not an identity-ref, is refused `verify_not_identity_ref`.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i2882_the_earlier_edge_signature_is_refused_by_name() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(i2882_the_earlier_edge_signature_is_refused_by_name_on(
            &app, &*backend,
        ))
        .await;
    }

    /// [`i2882_the_earlier_edge_signature_is_refused_by_name`] on postgres (P7-fix7: every backend gets the door).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i2882_the_earlier_edge_signature_is_refused_by_name_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(i2882_the_earlier_edge_signature_is_refused_by_name_on(
            &app, &*backend,
        ))
        .await;
    }

    async fn i2882_the_earlier_edge_signature_is_refused_by_name_on<B: RouteBackend>(
        app: &Router,
        _backend: &B,
    ) {
        use crate::federation::edition2::composite_verify::VERIFY_NOT_IDENTITY_REF;
        let env = make_signed_pipeline_envelope(make_signed_batch(1)).await;
        let canonical = canonicalize_for_edge_signing(&env).unwrap();
        let ed_half = BASE64.encode(
            SigningKey::from_bytes(&[0xE1; 32])
                .sign(&canonical)
                .to_bytes(),
        );
        for block in [
            serde_json::json!({"ed25519": ed_half, "ml_dsa_65": "AAAA", "signed_at": "2026-05-14T00:00:00Z"}),
            serde_json::json!({"ed25519": ed_half, "signed_at": "2026-05-14T00:00:00Z"}),
            serde_json::json!({"composite": env.edge_signature.composite, "ed25519": ed_half,
                               "signed_at": "2026-05-14T00:00:00Z"}),
        ] {
            let mut value = serde_json::to_value(&env).unwrap();
            value["edge_signature"] = block.clone();
            let (status, body) = post_raw(app, &value).await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "I2882 {block}: {body}"
            );
            assert!(
                body.contains(KIND_EDGE_SIGNATURE) && body.contains(VERIFY_COMPONENT_SIGNATURE),
                "I2882 {block}: refused by name: {body}"
            );
        }

        let mut lone = env.clone();
        lone.edge_signature.composite = ed_half;
        let (status, body) = post_envelope(app, &lone).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "I2882 lone half");
        assert!(
            body.expect_error()
                .detail
                .starts_with(VERIFY_COMPONENT_SIGNATURE),
            "I2882 lone half: {body:?}"
        );

        let mut label = env.clone();
        label.edge_key_id = "cirislens-edge-test-1".into();
        sign_edge(&mut label).await;
        let (status, body) = post_envelope(app, &label).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "I2882 label");
        assert!(
            body.expect_error()
                .detail
                .starts_with(VERIFY_NOT_IDENTITY_REF),
            "I2882 label: {body:?}"
        );
    }

    // ── v37.0.0 canonicalizer witnesses ──────────────────────────────
    //
    // CIRISPersist#716 — `canonicalize_for_edge_signing` re-pinned from
    // V1Python to CEG-produce/JCS. (The v37 Strict-policy witnesses are
    // deleted with the two-field signature, v62.0.0 F0-cp5; I2882 above.)
    //
    // Each gets a witness that asserts the NEW behaviour against a
    // HAND-WRITTEN expectation. None of them derive the expected value by
    // calling the code under test — a test that recomputes its
    // expectation through `canonicalize_for_edge_signing` would stay
    // green under either canonicalizer and prove only determinism.

    /// v37.0.0 (CIRISPersist#716) — the edge-signing canonicalizer emits
    /// CEG-produce/JCS bytes, NOT V1Python bytes.
    ///
    /// The two rules differ on non-ASCII: `PythonJsonDumpsCanonicalizer`
    /// is `ensure_ascii=True` and escapes every code point >= 0x80 as
    /// `\uXXXX` (non-BMP as an escaped UTF-16 surrogate pair), while RFC
    /// 8785 JCS emits raw UTF-8. That is the axis this flip moves, so the
    /// expectations below are written as literal bytes on that axis and
    /// are mutually exclusive: no single canonicalizer can satisfy both
    /// the "present" and the "absent" assertion.
    // P7-fix7 — pure (no backend, no app): runs in every backend build.
    #[tokio::test]
    async fn edge_signing_canonicalizes_under_ceg_produce_jcs() {
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch).await;
        // A build id carrying BMP non-ASCII (é) and non-BMP (🔑).
        env.sidecar.pipeline_metadata.edge_build_id = "caf\u{e9}-\u{1f511}-build".into();
        let bytes = canonicalize_for_edge_signing(&env).expect("canonicalize");
        let text = String::from_utf8(bytes).expect("JCS output is UTF-8");

        // HAND-WRITTEN: what RFC 8785 JCS produces — raw UTF-8, verbatim.
        assert!(
            text.contains("\"edge_build_id\":\"caf\u{e9}-\u{1f511}-build\""),
            "expected raw-UTF-8 JCS rendering of edge_build_id; got: {text}"
        );
        // HAND-WRITTEN: what V1Python would have produced instead. é is
        // U+00E9 -> \u00e9; 🔑 is U+1F511 -> surrogate pair \ud83d\udd11.
        // Its ABSENCE is what pins the flip.
        assert!(
            !text.contains("caf\\u00e9"),
            "V1Python \\u00e9 escape present — canonicalizer did NOT flip to JCS"
        );
        assert!(
            !text.contains("\\ud83d\\udd11"),
            "V1Python surrogate-pair escape present — canonicalizer did NOT flip to JCS"
        );
        // HAND-WRITTEN: the strip rule survives the re-pin — the
        // signature block never appears in the bytes it signs.
        assert!(
            !text.contains("\"edge_signature\""),
            "edge_signature must be stripped from its own signed bytes"
        );
    }

    /// v37.0.0 (CIRISPersist#716) — THE FLAG DAY, asserted.
    ///
    /// An envelope signed over V1Python bytes — exactly what a CIRISEdge
    /// that has not re-pinned still produces — is REJECTED. The key is
    /// valid, registered, hybrid-complete and role-tagged; only the
    /// canonicalization is stale.
    ///
    /// **The payload here carries non-ASCII deliberately.** The two rules
    /// agree byte-for-byte on plain-ASCII, ES-float-clean payloads, so a
    /// V1-signed all-ASCII envelope still verifies after the flip (pinned
    /// by [`v1_canonicalized_ascii_envelope_still_verifies`]). The break
    /// is payload-DEPENDENT, which is the operationally dangerous part —
    /// an un-re-pinned edge appears healthy until the first divergent
    /// payload. This witness pins the divergent half.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn v1_canonicalized_edge_signature_is_rejected() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(v1_canonicalized_edge_signature_is_rejected_on(
            &app, &*backend,
        ))
        .await;
    }

    /// [`v1_canonicalized_edge_signature_is_rejected`] on postgres (P7-fix7: every backend gets the door).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn v1_canonicalized_edge_signature_is_rejected_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(v1_canonicalized_edge_signature_is_rejected_on(
            &app, &*backend,
        ))
        .await;
    }

    async fn v1_canonicalized_edge_signature_is_rejected_on<B: RouteBackend>(
        app: &Router,
        _backend: &B,
    ) {
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch).await;
        // Non-ASCII — the axis on which V1Python (\uXXXX escapes) and
        // JCS (raw UTF-8) actually differ.
        env.sidecar.pipeline_metadata.edge_build_id = "edge-caf\u{e9}-build".into();

        // Re-sign over V1Python bytes: the pre-v37 rule, hand-built here
        // precisely because the production path no longer offers it.
        let mut value = serde_json::to_value(&env).unwrap();
        value.as_object_mut().unwrap().remove("edge_signature");
        let v1_bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&value)
            .unwrap();
        env.edge_signature.composite = edge_composite(&v1_bytes);

        let (status, body) = post_envelope(app, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let err = body.expect_error();
        assert_eq!(err.kind, KIND_EDGE_SIGNATURE);
        // v62.0.0 (F0-cp5) — the composite does not verify over the bytes
        // this build rebuilds, refused by its token.
        assert!(
            err.detail.starts_with(
                crate::federation::edition2::composite_verify::VERIFY_COMPOSITE_INVALID
            ),
            "{}",
            err.detail
        );
    }

    /// v37.0.0 (CIRISPersist#716) — the OTHER half of the flag day's real
    /// semantics: a V1-signed **all-ASCII** envelope STILL VERIFIES.
    ///
    /// `PythonJsonDumpsCanonicalizer` and RFC 8785 JCS agree byte-for-byte
    /// on payloads with no non-ASCII and no divergent float tokens, so the
    /// re-pin is NOT a clean break — an un-re-pinned edge keeps working
    /// for ASCII traffic and fails only on the first divergent payload.
    ///
    /// This is asserted, not assumed, because it is the single most
    /// important fact for scheduling the cutover: "we deployed and
    /// nothing broke" is NOT evidence that the edge re-pinned. Anyone
    /// planning the window on the belief that the break is immediate and
    /// total is planning against behaviour this test contradicts.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn v1_canonicalized_ascii_envelope_still_verifies() {
        let (app, backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        Box::pin(v1_canonicalized_ascii_envelope_still_verifies_on(
            &app, &*backend,
        ))
        .await;
    }

    /// [`v1_canonicalized_ascii_envelope_still_verifies`] on postgres (P7-fix5: every backend gets the door).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn v1_canonicalized_ascii_envelope_still_verifies_postgres() {
        let Some((app, backend)) = build_pg_app(DEFAULT_QUEUE_DEPTH).await else {
            return;
        };
        Box::pin(v1_canonicalized_ascii_envelope_still_verifies_on(
            &app, &*backend,
        ))
        .await;
    }

    async fn v1_canonicalized_ascii_envelope_still_verifies_on<B: RouteBackend>(
        app: &Router,
        backend: &B,
    ) {
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch).await;
        // Pure ASCII — the fixture's default shape.
        env.sidecar.pipeline_metadata.edge_build_id = "edge-ascii-build".into();

        // v62.0.0 (P7-fix4) — the body as sent on the v62 trace wire (the
        // inner trace as its row + blob: base64 text, still pure ASCII).
        let mut sent = serde_json::to_value(&env).unwrap();
        row_form_events(&row_agent(backend).await, &mut sent);
        let mut value = sent.clone();
        value.as_object_mut().unwrap().remove("edge_signature");
        let v1_bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&value)
            .unwrap();
        // HAND-WRITTEN: on an ASCII payload the two rules coincide, so
        // the V1 bytes ARE the bytes this build rebuilds.
        assert_eq!(
            v1_bytes,
            canonicalize_raw_for_edge_signing(&sent).unwrap(),
            "V1Python and JCS must coincide on an all-ASCII payload"
        );
        sent["edge_signature"]["composite"] = serde_json::json!(edge_composite(&v1_bytes));

        let (status, _) = post_value(app, &sent).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an ASCII payload signed under V1 still verifies — the re-pin \
             is payload-dependent, not a clean break"
        );
    }

    /// Mission constraint (MISSION.md §3 anti-pattern #7) — full
    /// queue surfaces 429 + Retry-After on the new route too.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn pipeline_ingest_429_on_full_queue() {
        let (app, backend) = build_app(1).await;
        Box::pin(pipeline_ingest_429_on_full_queue_on(&app, &*backend)).await;
    }

    /// [`pipeline_ingest_429_on_full_queue`] on postgres (P7-fix5: every backend gets the door).
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn pipeline_ingest_429_on_full_queue_postgres() {
        let Some((app, backend)) = build_pg_app(1).await else {
            return;
        };
        Box::pin(pipeline_ingest_429_on_full_queue_on(&app, &*backend)).await;
    }

    async fn pipeline_ingest_429_on_full_queue_on<B: RouteBackend>(app: &Router, backend: &B) {
        let kid = row_agent(backend).await;
        // Saturate the queue with rapid valid-envelope submissions.
        // The persister drains one at a time; with queue_depth=1 the
        // second-in-flight submission lands 429. The envelopes are signed
        // first and submitted together: one at a time, each handler's awaits
        // (the SQLite test backend's reads yield, v60.0.0 #1002) let the
        // persister drain every one, so the queue never filled.
        let mut bodies = Vec::with_capacity(200);
        for _ in 0..200 {
            let batch = make_signed_batch(1);
            let env = make_signed_pipeline_envelope(batch).await;
            // v62.0.0 (P7-fix4) — each body on the v62 trace wire.
            bodies.push(serde_json::to_vec(&to_row_form(&kid, &env).await).unwrap());
        }
        // Submitted concurrently: each handler runs to its first await, so
        // many reach the queue while the persister holds the one slot.
        let mut set = tokio::task::JoinSet::new();
        for body in bodies {
            set.spawn(
                app.clone().oneshot(
                    Request::post("/api/v1/pipeline/ingest")
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                ),
            );
        }
        let resps = set.join_all().await;
        let mut got_429 = false;
        for resp in resps {
            let resp = resp.unwrap();
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
