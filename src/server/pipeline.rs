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
//! # Deploy ordering (v37.0.0) — READ BEFORE ROLLING THIS OUT
//!
//! v37.0.0 changes what invariant 2 accepts, in two independent ways.
//! Both are flag days shared with CIRISEdge; neither is negotiable at
//! runtime (no env var, no per-peer epoch — the operator declared a hard
//! break).
//!
//! 1. **Canonicalization re-pin (CIRISPersist#716).**
//!    [`canonicalize_for_edge_signing`] now rebuilds the edge-signed
//!    bytes through
//!    [`ceg_produce_canonicalize`](crate::verify::canonical::ceg_produce_canonicalize)
//!    (V2Jcs) instead of hand-building the V1Python canonicalizer. An
//!    edge still signing V1Python bytes is refused.
//! 2. **PQC posture (`HybridPolicy::Strict`).** The edge signature must
//!    now carry BOTH halves. An Ed25519-only `edge_signature` — accepted
//!    through v36.x — is refused, and the edge's ML-DSA-65 pubkey must be
//!    registered in `federation_keys`.
//!
//! **The two breaks have DIFFERENT shapes. Do not plan for one shape.**
//!
//! * **(2) PQC/Strict is immediate and total.** Any edge whose
//!   `federation_keys` row lacks `pubkey_ml_dsa_65`, or that sends no
//!   `ml_dsa_65` half, is refused on EVERY request from the instant v37
//!   serves traffic. Payload-independent. This is the break that decides
//!   the deploy window.
//! * **(1) The canonicalizer re-pin is PAYLOAD-DEPENDENT.** V1Python and
//!   RFC 8785 JCS produce byte-IDENTICAL output for payloads with no
//!   non-ASCII characters and no divergent float tokens (`1e-05` vs
//!   `1e-5`). An un-re-pinned edge sending all-ASCII envelopes therefore
//!   KEEPS VERIFYING against v37, and fails only when a payload first
//!   contains non-ASCII. Both halves of this are pinned as witnesses
//!   (`v1_canonicalized_edge_signature_is_rejected` and
//!   `v1_canonicalized_ascii_envelope_still_verifies`) because the
//!   asymmetry is easy to get wrong in exactly the expensive direction.
//!
//! **The trap:** "we deployed v37 and edge ingest kept working" is NOT
//! evidence that the edge re-pinned its canonicalizer. It is evidence
//! that recent traffic happened to be ASCII. The latent failure then
//! arrives later, detached from the deploy, looking like data corruption
//! or a key problem. Verify the edge's canonicalizer by BUILD, not by
//! observed success.
//!
//! **Ordering: cut both in the same window; if you must sequence, roll
//! PERSIST FIRST.** Persist-first is strictly better for diagnosis: a v37
//! persist refusing an un-re-pinned edge answers with
//! [`edge_signature_rejection_detail`]'s message — which names the
//! canonicalizer re-pin and the Strict flip explicitly, and rules out the
//! key — in the 422 body the edge itself receives. A v36 persist refusing
//! a re-pinned edge answers with a bare "ed25519 signature mismatch",
//! indistinguishable from a credential problem. Both orderings drop the
//! same traffic; only one of them explains itself.
//!
//! Nothing re-verifies from storage on this plane — `edge_signature` is
//! checked once at admission — so the outage is bounded to in-flight
//! requests and ends the moment both sides are on v37. No stored corpus
//! goes dark (contrast the audit plane, PINNED by #714 for exactly that
//! reason).
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
use crate::verify::hybrid::VerifyError;
use crate::verify::{
    canonical::ceg_produce_canonicalize, ed25519::verify_trace, verify_hybrid_via_directory,
    HybridPolicy,
};

// ── Stable error kind tokens (THREAT_MODEL.md AV-15) ─────────────────

/// `pipeline_schema_version` not in the allowed set.
pub const KIND_SCHEMA_VERSION: &str = "pipeline_invariant_schema_version";
/// Edge hybrid signature failed verify (or edge key not in directory).
pub const KIND_EDGE_SIGNATURE: &str = "pipeline_invariant_edge_signature";
/// Inner agent CompleteTrace signature failed verify.
pub const KIND_INNER_SIGNATURE: &str = "pipeline_invariant_inner_signature";
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
/// v1.3.0 (CIRISPersist#46) — Edge key doesn't carry a writer role
/// tag in `federation_keys.roles`. Reject with 403.
pub const KIND_ROLE_TAG: &str = "pipeline_invariant_role_tag";

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
    // v37.0.0 — Strict. This was Ed25519Fallback from v1.1.0, waiting on
    // "once edge keys are PQC-complete across the fleet". That wait is
    // over: `HybridPolicy`'s own doc says Ed25519Fallback is a
    // development / sovereign-mode posture and NOT for federation
    // production, and this is the edge ingest WRITE path — the most
    // production plane persist serves. An Ed25519-only edge_signature is
    // now refused (`VerifyError::HybridPendingRejected`), matching the
    // #465 tightening `root_binding` already took on the provenance
    // plane. row_age is still not applicable for write-path verifies (the
    // edge_signature is computed fresh per request), and it is inert
    // under Strict regardless.
    let policy = HybridPolicy::Strict;
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
        // v37.0.0 — the detail names the flag-day cause. Both v37 breaks
        // (the #716 canonicalizer re-pin and the Strict flip above) land
        // here looking like a bad key; `edge_signature_rejection_detail`
        // is what stops an operator from re-issuing keys to fix a
        // canonicalization change. It goes to BOTH the log and the 422
        // body, so the un-re-pinned peer reads its own cause on the wire.
        let detail = edge_signature_rejection_detail(&e);
        tracing::warn!(
            error = %e,
            kind = e.kind(),
            edge_key_id = %envelope.edge_key_id,
            detail = %detail,
            "pipeline ingest rejected: edge signature failed verify"
        );
        // v62.0.0 (CC 2.7) — an edge key this node does not hold yet is a
        // wait, not a bad signature.
        if is_unknown_key(&e) {
            return key_not_held_response(detail);
        }
        return invariant_response(KIND_EDGE_SIGNATURE, detail);
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
        // v62.0.0 (CC 2.7) — the key was dropped between the verify and
        // this read: not held, a wait.
        Ok(None) => {
            return key_not_held_response(format!(
                "edge key not in directory: {}",
                envelope.edge_key_id
            ));
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
        .capability_roles
        .iter()
        .any(|r| r == ROLE_PIPELINE_WRITER || r == ROLE_SECRETS_WRITER);
    if !has_writer_role {
        tracing::warn!(
            edge_key_id = %envelope.edge_key_id,
            roles = ?edge_record.capability_roles,
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
        let BatchEvent::CompleteTrace {
            trace, statement, ..
        } = event;
        // v62.0.0 (wave P7; CC 3.1.5) — an inner trace carrying its
        // `trace:complete:v1` row is verified by the edition-2 statement door
        // when the persister ingests the batch (`ingest::admit_trace_statement`,
        // before anything of the trace is written); there is no component
        // signature to check here. One without is the earlier form: refused by
        // name once the earlier-form doors are shut, else checked as before.
        if statement.is_some() {
            continue;
        }
        if let Err(e) =
            crate::federation::edition2::door::refuse_earlier_form(crate::ingest::TRACE_PLANE)
        {
            return invariant_response(
                crate::federation::edition2::token::EARLIER_FORM_OBJECT,
                format!("{e}"),
            );
        }
        let key = match Backend::lookup_public_key(&*state.directory, &trace.signature_key_id).await
        {
            Ok(Some(k)) => k,
            // v62.0.0 (CC 2.7) — the agent's key record has not reached
            // this node yet: a wait, as on the ingest path.
            Ok(None) => {
                return key_not_held_response(format!(
                    "unknown agent key {}",
                    trace.signature_key_id
                ));
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
        // v4.6 (#176) — select the canonicalizer by the trace's SIGNED
        // schema epoch (Python-compat for 1.x/2.x, JCS for 3.x+). Signed-
        // bytes-bound: not caller-selectable.
        let canon = crate::verify::canonical::canonicalizer_for(
            crate::verify::ed25519::canon_version_for_trace_schema(
                trace.trace_schema_version.as_str(),
            ),
        );
        if let Err(e) = verify_trace(trace, canon, &key) {
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
/// v62.0.0 (CC 2.7) — is this verify failure "the key is not held here"?
/// `verify_hybrid_via_directory` reports it as
/// `VerifyError::Crypto("verify_unknown_key")`.
fn is_unknown_key(e: &VerifyError) -> bool {
    matches!(e, VerifyError::Crypto(msg) if msg.contains(KIND_KEY_NOT_HELD))
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
/// envelope, not necessarily on its first envelope. See
/// [`edge_signature_rejection_detail`] for the operator-facing message
/// that names the cause, and the module `# Deploy ordering (v37.0.0)`
/// note for why that asymmetry is a trap. Unlike the audit plane — which #714
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

/// v37.0.0 (CIRISPersist#716 + the #465-class PQC tightening) — render an
/// edge-signature [`VerifyError`] into a detail string that names the
/// **flag-day cause**, not just the symptom.
///
/// Both v37.0.0 breaks surface here as a signature that "just doesn't
/// verify", and both look exactly like a key/registration problem to an
/// operator reading a log line. That misdiagnosis is the expensive
/// outcome — it sends someone to re-register keys for a canonicalizer
/// re-pin. So each one states its own cause and its own remedy:
///
/// * `Crypto` (Ed25519 mismatch) — most likely the #716 canonicalizer
///   re-pin: this build rebuilds the signed bytes under CEG-produce/JCS,
///   so a V1Python-signed envelope will not verify no matter how correct
///   the key is. The message also states that the two rules AGREE on
///   plain ASCII, because that is what makes an un-re-pinned edge look
///   healthy right up until the payload that breaks it.
/// * `HybridPendingRejected` — the [`HybridPolicy::Strict`] flip: the
///   signer's `federation_keys` row is classical-only and it sent no
///   `ml_dsa_65` half, which v36 and earlier accepted.
/// * `PqcFieldsMustBeBoth` — the sig/pubkey pairing: exactly one of the
///   envelope's `ml_dsa_65` half and the row's `pubkey_ml_dsa_65` is
///   present. Distinct from the above so an operator can tell "this edge
///   never registered PQC" from "the PQC half went missing in flight".
///
/// The detail reaches the peer: [`invariant_response`] serializes it into
/// the 422 body's `detail` field, so the signer sees the cause on the
/// wire and not only in persist's logs.
fn edge_signature_rejection_detail(e: &VerifyError) -> String {
    match e {
        VerifyError::Crypto(msg) if msg.contains("verify_unknown_key") => {
            format!("{e} — edge_key_id is not registered in federation_keys")
        }
        VerifyError::Crypto(_) => format!(
            "{e} — NOTE (v37.0.0 flag day, CIRISPersist#716): this build \
             canonicalizes the edge-signed bytes under CEG-produce/JCS \
             (V2Jcs). An envelope signed over the previous V1Python \
             canonicalization WILL NOT VERIFY here even with a correct, \
             correctly-registered key. The two rules diverge on non-ASCII \
             text (JCS emits raw UTF-8; V1Python escaped it as \\uXXXX) and \
             on float tokens — they agree on plain ASCII, so an \
             un-re-pinned signer can appear healthy until its first \
             non-ASCII payload, which is likely what just happened. \
             Re-pin the signer to CEG-produce/JCS and re-sign; this is not \
             a key problem."
        ),
        VerifyError::HybridPendingRejected => format!(
            "{e} — NOTE (v37.0.0 flag day): the edge signature policy is \
             now HybridPolicy::Strict. An Ed25519-only edge_signature was \
             accepted through v36.x and is REFUSED here: send the ml_dsa_65 \
             half and register the edge's ML-DSA-65 pubkey in \
             federation_keys. This is not a key-validity problem."
        ),
        VerifyError::PqcFieldsMustBeBoth => format!(
            "{e} — the envelope's ml_dsa_65 signature half and this \
             edge_key_id's federation_keys.pubkey_ml_dsa_65 must BOTH be \
             present or BOTH absent, and exactly one of them is. Either the \
             envelope omitted the half for a PQC-registered edge (v37.0.0: \
             send it — HybridPolicy::Strict requires it), or it sent the \
             half for an edge with no registered PQC pubkey (register the \
             edge's ML-DSA-65 pubkey). Not a key-validity problem."
        ),
        _ => format!("{e}"),
    }
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

#[cfg(all(test, feature = "sqlite"))]
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

    /// Fixed seed for the edge signing key — tests are reproducible.
    const EDGE_SEED: [u8; 32] = [0xE1; 32];
    /// Fixed seed for the inner agent signing key.
    const AGENT_SEED: [u8; 32] = [0x42; 32];
    /// `key_id` the edge identifies itself by in `federation_keys`.
    const EDGE_KEY_ID: &str = "cirislens-edge-test-1";
    /// `signature_key_id` on the inner agent trace.
    const AGENT_KEY_ID: &str = "ciris-agent-key:pipeline-test";
    /// v37.0.0 — fixed seed for the edge's ML-DSA-65 half. The edge
    /// signature policy is now `HybridPolicy::Strict`, so a fixture edge
    /// key without a PQC half can no longer sign an acceptable envelope.
    const EDGE_PQC_SEED: [u8; 32] = [0xE9; 32];
    /// `pqc_key_id` the edge stamps on the envelope.
    const EDGE_PQC_KEY_ID: &str = "cirislens-edge-test-1-pqc";

    fn edge_mldsa() -> ciris_keyring::MlDsa65SoftwareSigner {
        ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&EDGE_PQC_SEED, EDGE_PQC_KEY_ID)
            .expect("deterministic ML-DSA-65 keypair from seed")
    }

    /// v37.0.0 — sign `envelope` the way a re-pinned CIRISEdge does:
    /// canonicalize through the produce gate, Ed25519-sign those bytes,
    /// then ML-DSA-65-sign `(canonical || ed25519_sig)` — the bound form
    /// `verify_hybrid` reconstructs. Sets BOTH halves.
    ///
    /// Every fixture goes through here so there is exactly one place that
    /// knows the edge signing shape; the witnesses that must deviate from
    /// it (V1 bytes, PQC omitted) do so explicitly and say why.
    async fn sign_edge(envelope: &mut PipelineEnvelope) {
        use ciris_keyring::PqcSigner as _;
        let canonical = canonicalize_for_edge_signing(envelope).expect("canonicalize");
        let ed_sig = SigningKey::from_bytes(&EDGE_SEED)
            .sign(&canonical)
            .to_bytes();
        let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
        bound.extend_from_slice(&canonical);
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = edge_mldsa().sign(&bound).await.expect("ml-dsa sign");
        envelope.edge_signature.ed25519 = BASE64.encode(ed_sig);
        envelope.edge_signature.ml_dsa_65 = Some(BASE64.encode(&pqc_sig));
    }

    fn temp_journal() -> (tempfile::TempDir, Arc<Journal>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("j.redb");
        let j = Journal::open(&path).unwrap();
        (dir, Arc::new(j))
    }

    async fn build_app(queue_depth: usize) -> (Router, Arc<SqliteBackend>) {
        use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, PqcSigner as _};
        let backend = Arc::new(crate::store::test_backend::test_backend());
        // Register the edge fixture key + agent fixture key in the
        // directory so verify can resolve them.
        let edge_sk = SigningKey::from_bytes(&EDGE_SEED);
        backend.add_public_key(EDGE_KEY_ID, edge_sk.verifying_key());
        // v1.3.0 (CIRISPersist#46): edge keys need a writer role to
        // pass the role-tag invariant gate. Pipeline tests grant
        // `cirislens_pipeline_writer`; the alternate
        // `cirislens_secrets_writer` would also pass.
        backend.set_roles(EDGE_KEY_ID, vec!["cirislens_pipeline_writer".to_owned()]);
        // v37.0.0 — the edge key must be hybrid-COMPLETE now that the
        // route verifies under `HybridPolicy::Strict`. `add_public_key`
        // alone writes a hybrid-pending row (pubkey_ml_dsa_65 = None),
        // which Strict refuses.
        let edge_pqc_pk = edge_mldsa().public_key().await.expect("ml-dsa pk");
        backend.set_pqc_pubkey(EDGE_KEY_ID, &BASE64.encode(&edge_pqc_pk));
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
            edge_signature: HybridSignatureBlock {
                ed25519: String::new(),
                ml_dsa_65: None,
                signed_at,
            },
            edge_key_id: EDGE_KEY_ID.into(),
            edge_pqc_key_id: Some(EDGE_PQC_KEY_ID.into()),
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
    /// terminal 422: an agent key not registered (the envelope re-signed by
    /// the edge, so the edge gate passes), and an edge key not registered.
    #[tokio::test]
    async fn i3609_a_key_not_held_is_a_retryable_424() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH).await;

        let mut env = make_signed_pipeline_envelope(make_signed_batch(1)).await;
        for event in &mut env.envelope.events {
            let BatchEvent::CompleteTrace { trace, .. } = event;
            trace.signature_key_id = "ciris-agent-key:not-held-here".into();
        }
        sign_edge(&mut env).await;
        let (status, body) = post_envelope(&app, &env).await;
        assert_eq!(
            status,
            StatusCode::FAILED_DEPENDENCY,
            "I3609 agent: {body:?}"
        );
        let e = body.expect_error();
        assert_eq!(e.kind, KIND_KEY_NOT_HELD, "I3609 agent");
        assert!(e.retry_after_seconds.is_some(), "I3609 agent: retryable");

        let mut env = make_signed_pipeline_envelope(make_signed_batch(1)).await;
        env.edge_key_id = "cirislens-edge-not-held-here".into();
        sign_edge(&mut env).await;
        let (status, body) = post_envelope(&app, &env).await;
        assert_eq!(
            status,
            StatusCode::FAILED_DEPENDENCY,
            "I3609 edge: {body:?}"
        );
        let e = body.expect_error();
        assert_eq!(e.kind, KIND_KEY_NOT_HELD, "I3609 edge");
        assert!(e.retry_after_seconds.is_some(), "I3609 edge: retryable");
    }

    /// Happy path: well-formed envelope flows through every gate.
    #[tokio::test]
    async fn pipeline_ingest_accepts_well_formed_envelope() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        let batch = make_signed_batch(2);
        let env = make_signed_pipeline_envelope(batch).await;
        let (status, _) = post_envelope(&app, &env).await;
        assert_eq!(status, StatusCode::OK);
    }

    /// v62.0.0 (wave P7) — sign a RAW envelope value the way the edge does
    /// (the route checks the signature over the body as sent).
    async fn sign_edge_raw(value: &mut serde_json::Value) {
        use ciris_keyring::PqcSigner as _;
        let canonical = canonicalize_raw_for_edge_signing(value).expect("canonicalize");
        let ed_sig = SigningKey::from_bytes(&EDGE_SEED)
            .sign(&canonical)
            .to_bytes();
        let mut bound = Vec::with_capacity(canonical.len() + ed_sig.len());
        bound.extend_from_slice(&canonical);
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = edge_mldsa().sign(&bound).await.expect("ml-dsa sign");
        value["edge_signature"]["ed25519"] = serde_json::json!(BASE64.encode(ed_sig));
        value["edge_signature"]["ml_dsa_65"] = serde_json::json!(BASE64.encode(&pqc_sig));
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
    #[tokio::test]
    async fn i3484_pipeline_ingest_accepts_the_row_form() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        let value = row_form_envelope(|t| crate::ingest::canonical_trace_blob(t).unwrap()).await;
        let (status, body) = post_raw(&app, &value).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "I3484: the row form is accepted: {body}"
        );
    }

    /// **I3485** (v62.0.0, wave P7) — a row-form event whose blob carries a
    /// signature member of its own is refused at the route by name.
    #[tokio::test]
    async fn i3485_pipeline_ingest_refuses_a_signed_blob() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        let value = row_form_envelope(|t| serde_json::to_vec(t).unwrap()).await;
        let (status, body) = post_raw(&app, &value).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "I3485: {body}");
        assert!(
            body.contains(crate::ingest::TRACE_BLOB_CARRIES_SIGNATURE),
            "I3485: refused by name: {body}"
        );
    }

    /// FSD §4.3 invariant 1: unknown schema version rejected.
    #[tokio::test]
    async fn pipeline_ingest_rejects_unknown_schema_version() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch).await;
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
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch).await;
        env.sidecar.pipeline_metadata.pii_scrubbed = false;
        // Re-sign — the metadata change invalidates the edge sig.
        sign_edge(&mut env).await;
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
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        let batch = make_signed_batch(2);
        let mut env = make_signed_pipeline_envelope(batch).await;
        // 2 components but 3 classifications.
        env.sidecar.classifications.push(Vec::new());
        // Re-sign.
        sign_edge(&mut env).await;
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
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
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
        // Re-sign.
        sign_edge(&mut env).await;
        let (status, body) = post_envelope(&app, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.expect_error().kind, KIND_ORPHAN_SECRET);
    }

    /// FSD §4.3 invariant 2: edge signature must verify. Flip a byte
    /// in `edge_signature.ed25519` and assert the route rejects.
    #[tokio::test]
    async fn pipeline_ingest_rejects_bad_edge_signature() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch).await;
        // Decode, flip byte 0, re-encode — base64-clean and produces
        // a still-64-byte signature that won't verify.
        let mut sig_bytes = BASE64.decode(&env.edge_signature.ed25519).unwrap();
        sig_bytes[0] ^= 0xFF;
        env.edge_signature.ed25519 = BASE64.encode(&sig_bytes);
        let (status, body) = post_envelope(&app, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body.expect_error().kind, KIND_EDGE_SIGNATURE);
    }

    // ── v37.0.0 flag-day witnesses ───────────────────────────────────
    //
    // Two independent breaks land on invariant 2 in this cut:
    //   * CIRISPersist#716 — `canonicalize_for_edge_signing` re-pinned
    //     from V1Python to CEG-produce/JCS.
    //   * The `HybridPolicy::Ed25519Fallback` -> `Strict` flip.
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
    #[tokio::test]
    async fn v1_canonicalized_edge_signature_is_rejected() {
        use ciris_keyring::PqcSigner as _;
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
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
        let ed_sig = SigningKey::from_bytes(&EDGE_SEED)
            .sign(&v1_bytes)
            .to_bytes();
        let mut bound = Vec::with_capacity(v1_bytes.len() + ed_sig.len());
        bound.extend_from_slice(&v1_bytes);
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = edge_mldsa().sign(&bound).await.unwrap();
        env.edge_signature.ed25519 = BASE64.encode(ed_sig);
        env.edge_signature.ml_dsa_65 = Some(BASE64.encode(&pqc_sig));

        let (status, body) = post_envelope(&app, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let err = body.expect_error();
        assert_eq!(err.kind, KIND_EDGE_SIGNATURE);
        // LOUD + SELF-EXPLAINING: the detail must send the operator to
        // the canonicalizer, not to the key. A bare "signature failed
        // verify" here is the outcome this witness exists to prevent.
        assert!(
            err.detail.contains("CEG-produce/JCS") && err.detail.contains("V1Python"),
            "rejection detail must name the canonicalization re-pin; got: {}",
            err.detail
        );
        assert!(
            err.detail.contains("CIRISPersist#716"),
            "rejection detail must cite the issue; got: {}",
            err.detail
        );
        assert!(
            err.detail.contains("not a key problem"),
            "rejection detail must rule OUT the key, the likeliest misdiagnosis; got: {}",
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
    #[tokio::test]
    async fn v1_canonicalized_ascii_envelope_still_verifies() {
        use ciris_keyring::PqcSigner as _;
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch).await;
        // Pure ASCII — the fixture's default shape.
        env.sidecar.pipeline_metadata.edge_build_id = "edge-ascii-build".into();

        let mut value = serde_json::to_value(&env).unwrap();
        value.as_object_mut().unwrap().remove("edge_signature");
        let v1_bytes = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&value)
            .unwrap();
        // HAND-WRITTEN: on an ASCII payload the two rules coincide, so
        // the V1 bytes ARE the bytes this build rebuilds.
        assert_eq!(
            v1_bytes,
            canonicalize_for_edge_signing(&env).unwrap(),
            "V1Python and JCS must coincide on an all-ASCII payload"
        );
        let ed_sig = SigningKey::from_bytes(&EDGE_SEED)
            .sign(&v1_bytes)
            .to_bytes();
        let mut bound = Vec::with_capacity(v1_bytes.len() + ed_sig.len());
        bound.extend_from_slice(&v1_bytes);
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = edge_mldsa().sign(&bound).await.unwrap();
        env.edge_signature.ed25519 = BASE64.encode(ed_sig);
        env.edge_signature.ml_dsa_65 = Some(BASE64.encode(&pqc_sig));

        let (status, _) = post_envelope(&app, &env).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an ASCII payload signed under V1 still verifies — the re-pin \
             is payload-dependent, not a clean break"
        );
    }

    /// v37.0.0 — a hybrid-COMPLETE key that omits the PQC signature half
    /// is refused as `PqcFieldsMustBeBoth`, not `HybridPendingRejected`.
    ///
    /// The row carries a PQC pubkey and the SENDER dropped the half — a
    /// downgrade against a hybrid-capable identity — so it must refuse with
    /// the both-or-neither detail. (v62.0.0: the classical-only key-row
    /// sibling witnessed a hybrid-pending row, an earlier-form state, and is
    /// deleted.)
    #[tokio::test]
    async fn pqc_sig_omitted_against_hybrid_complete_key_is_rejected() {
        let (app, _backend) = build_app(DEFAULT_QUEUE_DEPTH).await;
        let batch = make_signed_batch(1);
        let mut env = make_signed_pipeline_envelope(batch).await;
        env.edge_signature.ml_dsa_65 = None;

        let (status, body) = post_envelope(&app, &env).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        let err = body.expect_error();
        assert_eq!(err.kind, KIND_EDGE_SIGNATURE);
        assert!(
            err.detail
                .contains("PQC signature without pubkey (or vice versa)"),
            "expected the both-or-neither refusal; got: {}",
            err.detail
        );
        assert!(
            err.detail.contains("HybridPolicy::Strict requires it"),
            "detail must state the remedy for the omitted-half direction; got: {}",
            err.detail
        );
        assert!(
            err.detail.contains("Not a key-validity problem"),
            "detail must rule OUT the key; got: {}",
            err.detail
        );
    }

    /// v37.0.0 — the two flag-day failures must NOT read alike. An
    /// operator triaging one must not be handed the other's remedy.
    #[tokio::test]
    async fn flag_day_rejection_details_are_distinguishable() {
        use crate::verify::hybrid::VerifyError;
        let canon = edge_signature_rejection_detail(&VerifyError::Crypto(
            "ed25519 signature mismatch".to_string(),
        ));
        let strict = edge_signature_rejection_detail(&VerifyError::HybridPendingRejected);
        let unknown =
            edge_signature_rejection_detail(&VerifyError::Crypto("verify_unknown_key".to_string()));

        assert!(canon.contains("CIRISPersist#716") && canon.contains("Re-pin the signer"));
        assert!(!canon.contains("HybridPolicy::Strict"));

        assert!(strict.contains("HybridPolicy::Strict"));
        assert!(!strict.contains("CIRISPersist#716"));

        // The genuine key problem still reads as one — the loud
        // canonicalizer note must not swallow it.
        assert!(unknown.contains("not registered in federation_keys"));
        assert!(!unknown.contains("CIRISPersist#716"));
    }

    /// Mission constraint (MISSION.md §3 anti-pattern #7) — full
    /// queue surfaces 429 + Retry-After on the new route too.
    #[tokio::test]
    async fn pipeline_ingest_429_on_full_queue() {
        let (app, _backend) = build_app(1).await;
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
            bodies.push(serde_json::to_vec(&env).unwrap());
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
