//! Ingest pipeline — the public entry point the lens (and Phase 2 the
//! agent) call.
//!
//! # Mission alignment
//!
//! This module composes every layer of the FSD §3.3 pipeline:
//!
//! ```text
//! bytes → schema parse → verify → scrub → decompose → backend insert → BatchSummary
//! ```
//!
//! Each step is a typed boundary. Failure at any step short-circuits
//! with a typed [`IngestError`] variant; the lens turns that into the
//! structured 422 / 401 / 429 / 500 response the wire-format spec
//! (TRACE_WIRE_FORMAT.md §1) requires.
//!
//! Mission constraint (MISSION.md §3 anti-pattern #2): verify-before-
//! persist. Mission constraint (anti-pattern #7): every test asserts
//! a *mission-aligned outcome*, not just absence of error.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ciris_keyring::HardwareSigner;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::schema::TraceLevel;
use crate::schema::{BatchEnvelope, BatchEvent, CompleteTrace, Error as SchemaError};
use crate::scrub::{ScrubError, Scrubber};
use crate::store::{Backend, Error as StoreError, InsertReport};
use crate::verify::{canonical::Canonicalizer, Error as VerifyError};

/// v18.0.0 (CIRISPersist#473) — the dimension every envelope-native trace
/// attestation carries. A trace is not a new object kind: it is a `scores`
/// attestation on this dimension (owner doctrine: "everything persist saves
/// is a CEG-native object put in an envelope"). Namespace flagged for CC
/// ratification alongside the CC#38 size discipline.
pub const TRACE_ATTESTATION_DIMENSION: &str = "trace:complete:v1";

/// v21.0.0 (CIRISPersist#501) — the INBOUND projection: reconstruct
/// `trace_events` rows from a replicated `trace:complete:v1` attestation by
/// re-running the SAME [`crate::store::decompose::decompose`] the ingest
/// path uses — so the projection is a FEATURE of writing the claim, never a
/// hand-duplicated second surface (the divergence that left the corpus leg
/// dark: replication carried the attestation surface but not the
/// `trace_events` read surface, so `list_trace_summaries` saw nothing and
/// the scorer's `n_summaries=0` forever).
///
/// Returns the decomposed rows for the INLINE form (`envelope["trace"]`);
/// `None` for the manifest form (payload on the fountain plane, not in the
/// envelope — that reassembly is the P3 fountain-fetch follow-up) or a
/// non-trace / unparseable envelope. Idempotent at the insert (the
/// `trace_events` dedup index), so a replayed replication is a no-op.
pub fn project_trace_events_from_attestation(
    envelope: &serde_json::Value,
) -> Option<crate::store::decompose::Decomposed> {
    if crate::federation::admission::envelope_dimension(envelope)
        != Some(TRACE_ATTESTATION_DIMENSION)
    {
        return None;
    }
    let trace_value = envelope.get("trace")?;
    let trace: crate::schema::CompleteTrace = serde_json::from_value(trace_value.clone()).ok()?;
    crate::store::decompose::decompose(&trace).ok()
}

/// v18.0.0/#473 (single-sourced v20.1.0 for the #478 backfill) — the
/// DETERMINISTIC trace-attestation id: sha256("ciris:trace-attestation:v1:"
/// ‖ trace_id) folded into a UUID (pg's attestation_id is ::uuid-cast). The
/// live mint and the backfill derive the SAME id, so they converge: whichever
/// runs second no-ops on the funnels' conflict-ignore.
pub fn trace_attestation_id(trace_id: &str) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(b"ciris:trace-attestation:v1:");
    h.update(trace_id.as_bytes());
    let digest = h.finalize();
    let mut b = [0u8; 16];
    b.copy_from_slice(&digest[..16]);
    uuid::Uuid::from_bytes(b).to_string()
}

/// What the ingest pipeline did with one `events[]` body.
///
/// Mission constraint (MISSION.md §3 anti-pattern #7): a successful
/// ingest reports concrete numbers, not a bare `Ok(())`. The lens
/// surfaces these to its operations dashboard so a deployment-time
/// regression (e.g. a per-event drop) is visible immediately.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchSummary {
    /// Count of `events[]` envelope items processed (each may be a
    /// CompleteTrace with N components).
    pub envelopes_processed: usize,
    /// Count of `trace_events` rows that landed (excluding ON
    /// CONFLICT skips).
    pub trace_events_inserted: usize,
    /// v18.0.0 (#473) — envelope-native trace attestations minted this
    /// batch (one local-tier `scores` attestation per verified trace; a
    /// replayed trace re-derives the same deterministic id and counts here
    /// as minted-idempotent).
    pub trace_attestations_minted: usize,
    /// v18.0.0 (#473) — traces whose attestation mint was SKIPPED (warn
    /// logged): typically the attesting key is not in this node's directory
    /// (relay `TrustPreVerified` ingest of a not-yet-federated producer).
    /// The projection rows still land; the mint self-heals on replay once
    /// the key federates.
    pub trace_attestations_skipped: usize,
    /// Count of `trace_events` ON CONFLICT skips.
    pub trace_events_conflicted: usize,
    /// Count of `trace_llm_calls` rows that landed.
    pub trace_llm_calls_inserted: usize,
    /// Number of fields the scrubber modified (for telemetry).
    pub scrubbed_fields: usize,
    /// Number of CompleteTrace envelopes whose signature verified.
    pub signatures_verified: usize,
}

/// Errors the ingest pipeline can return.
///
/// Mission constraint (MISSION.md §3 anti-pattern #4): typed errors
/// per layer. Each variant maps to a specific lens HTTP response shape.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    /// Schema-layer failure (malformed JSON, schema-version mismatch,
    /// unknown trace_level, missing required field). Lens → HTTP 422.
    #[error("schema: {0}")]
    Schema(#[from] SchemaError),

    /// Verify-layer failure (signature mismatch, unknown key,
    /// malformed signature). Lens → HTTP 401 (signature) or 422
    /// (malformed).
    #[error("verify: {0}")]
    Verify(#[from] VerifyError),

    /// Scrubber failure. Lens → HTTP 500 (scrubber bug) or 422
    /// (scrubber rejected schema-altering result).
    #[error("scrub: {0}")]
    Scrub(#[from] ScrubError),

    /// v32.0.0 (CIRISPersist#690) — **the treatment does not match the label.**
    ///
    /// A `full_traces` batch whose scrubber reports `ner_ran: false` is refused
    /// rather than stored. Without this the envelope's new fields would be an
    /// observation nobody acts on, which is #685 all over again: a fact that is
    /// stored, verifiable, and never consulted by the reader that matters.
    ///
    /// The honest path for a node with no model loaded is not to store
    /// `full_traces` unscrubbed — it is to scrub at `detailed` and RELABEL, so
    /// the claim matches the treatment. This refusal is what makes that the only
    /// path.
    ///
    /// Lens → HTTP 422: the sender must downgrade the level or load a model.
    /// v32.3.0 (CIRISPersist#701) — **carries what DISCRIMINATES, not two
    /// copies of the same constant.**
    ///
    /// The v32.0.0 shape had `label` and `treated`, and the guard's own
    /// condition had already established they were equal — so every occurrence
    /// rendered `label=full_traces treated_as=full_traces`, and the one field
    /// that decides the operator's next move, `ner_ran`, was never printed. A
    /// reader saw two identical values and could not tell whether the label was
    /// wrong, the treatment was wrong, or something else entirely. Reported
    /// from a staged QA run: ten of these, zero traces persisted, and nothing
    /// in the message said why.
    ///
    /// `model_digest` is the field that genuinely varies, and it separates two
    /// different situations that would otherwise look identical: no model
    /// staged at all, versus a model that ran and still reported no
    /// named-entity pass (which is a scrubber bug, not a configuration gap).
    #[error(
        "scrub treatment does not match label: this batch is labelled \
         `{treated_as}`, which requires a named-entity pass, and none ran \
         (ner_ran={ner_ran}, model={model_digest:?}). Either stage a model on \
         this node, or have the scrubber treat the content at `detailed` and \
         REPORT that level — from Python, return the 5-tuple \
         `(scrubbed, count, ner_ran, model_digest, applied_trace_level)` \
         (CIRISPersist#690, #701)"
    )]
    ScrubTreatmentMismatch {
        /// The level the content was treated at — which, at this door, is also
        /// the level it is labelled.
        treated_as: String,
        /// Whether a named-entity pass ran. **This is the discriminating
        /// fact**, and the reason this refusal exists.
        ner_ran: bool,
        /// Digest of the model that ran, if any. `None` = nothing staged.
        model_digest: Option<String>,
    },

    /// Backend write failure (DB unreachable, IO, etc.). Lens → HTTP
    /// 503 + Retry-After (the lens's bounded-queue layer also kicks
    /// in here for the journal-replay path; FSD §3.4 #2).
    #[error("store: {0}")]
    Store(#[from] StoreError),

    /// THREAT_MODEL.md AV-24/25: ciris-keyring sign failure during
    /// step 3.5. Hardware-backed signers can fail (TPM unavailable,
    /// keyring locked, etc.); software fallback can fail (key file
    /// IO error, etc.). Either way, refuse to persist — the FSD
    /// §3.4 #7 contract is "every row signed."
    #[error("sign: {0}")]
    Sign(String),

    /// v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — AV-45 write-path
    /// cohort_scope admission refusal. The trace claimed a
    /// `(cohort_scope, cohort_target_id)` the verified writer is not a
    /// member of (a visibility-downgrade attempt — e.g. stamping
    /// `community: C` for a community the writer doesn't belong to). The
    /// gate runs AFTER the step-2 verify gate and BEFORE the insert; a
    /// refusal means ZERO rows persist for the whole batch (mirrors the
    /// verify-rejection discipline, MISSION §1.6). Lens → HTTP 403.
    ///
    /// Carries the structured [`ScopeRefusalReason`](crate::scope::ScopeRefusalReason);
    /// `kind()` surfaces the stable per-reason token
    /// (`scope_no_family_membership` / `scope_no_community_membership` /
    /// `scope_invalid_cohort_scope`).
    #[error("scope: {0}")]
    ScopeRefused(#[from] crate::scope::ScopeRefusalReason),

    /// v54.1.0 — a trace the substrate refuses to admit on a NAMED ground,
    /// before anything is written (zero rows for the whole batch):
    /// `trace_run_kind_mock` (CIRISPersist#1040, CIRISConstitution#166 — a
    /// trace whose signed `run_kind` is `mock`, offered to
    /// a node holding the `canonical` role, the federation corpus) or
    /// `purge_tombstoned` (CIRISPersist#1046 — a trace a steward purge
    /// tombstoned). Lens → HTTP 422.
    #[error("trace refused {kind}: {detail}")]
    TraceRefused {
        /// The stable refusal token.
        kind: &'static str,
        /// The trace id and the ground (closed-set; never payload bytes).
        detail: String,
    },

    /// v1.1.0 (CIRISPersist#33 part 3) — `PipelineEnvelope` failed one
    /// of the FSD §4.3 wire-shape / consistency invariants. Lens →
    /// HTTP 422. Each invariant carries a stable kind token so
    /// downstream consumers can distinguish "edge dropped the scrub
    /// stage" from "edge shipped orphan encrypted secrets" without
    /// string-parsing the detail blob.
    #[error("pipeline invariant {kind}: {detail}")]
    PipelineInvariant {
        /// Stable token identifying WHICH invariant fired. See
        /// [`IngestError::kind`] for the full enumeration. Mirrors
        /// the rest of persist's error-token convention
        /// (THREAT_MODEL.md AV-15).
        kind: &'static str,
        /// Human-readable detail (closed-set / operator-configurable;
        /// never raw user-payload bytes).
        detail: String,
    },
}

impl IngestError {
    /// Stable string-token identifying the error variant.
    /// THREAT_MODEL.md AV-15: HTTP / PyO3 sanitization. The verbose
    /// `Display` form goes to tracing logs only; the kind is what
    /// the lens surfaces in HTTP error bodies.
    pub fn kind(&self) -> &'static str {
        match self {
            IngestError::Schema(e) => e.kind(),
            IngestError::Verify(e) => e.kind(),
            IngestError::Scrub(e) => e.kind(),
            IngestError::Store(e) => e.kind(),
            IngestError::Sign(_) => "sign_keyring",
            // AV-15: the single stable boundary token for the write-side
            // cohort_scope refusal. The per-reason detail (which membership
            // failed) is available via the inner `ScopeRefusalReason::kind`.
            IngestError::ScopeRefused(_) => "write_scope_refused",
            IngestError::PipelineInvariant { kind, .. } => kind,
            IngestError::TraceRefused { kind, .. } => kind,
            // v32.0.0 (#690) — its own token, not folded into `scrub`. A
            // scrubber BUG and a batch whose treatment does not match its label
            // are different conditions with different remedies: the first is
            // ours to fix, the second the sender fixes by downgrading the level
            // or loading a model. A shared token would make the lens report
            // "scrubber broken" for a correctly-functioning refusal.
            IngestError::ScrubTreatmentMismatch { .. } => "scrub_treatment_mismatch",
        }
    }

    /// v0.4.6 (CIRISPersist#22) — Variant-specific detail string.
    ///
    /// `kind()` returns the stable enum-discriminant token
    /// (e.g. `"schema_missing_field"`); `detail()` returns the
    /// variant's dynamic content (e.g. the field name
    /// `"attempt_index"`) so callers can surface "WHICH field" /
    /// "WHICH version" / etc. to operators without source-diving
    /// persist.
    ///
    /// Currently delegates to the schema error's `detail()`; the
    /// other variants don't yet carry a typed inner detail surface
    /// (verify / scrub / store / sign return `None`). Adding more
    /// is a follow-up — the schema arm covers the
    /// missing-field-name case the bridge team flagged in #22.
    ///
    /// AV-15-safe: same boundary discipline as `kind()`. The
    /// returned string is closed-set or operator-configurable
    /// (never raw user-payload bytes).
    pub fn detail(&self) -> Option<String> {
        match self {
            IngestError::Schema(e) => e.detail(),
            IngestError::PipelineInvariant { detail, .. } => Some(detail.clone()),
            IngestError::TraceRefused { detail, .. } => Some(detail.clone()),
            // The per-reason machine token (e.g. `scope_no_community_membership`)
            // is the actionable detail for a write-scope refusal.
            IngestError::ScopeRefused(r) => Some(r.kind().to_string()),
            // AV-15-safe: both values are closed-vocabulary trace levels, never
            // user payload — and the sender needs to know WHICH level it was
            // treated at to decide whether to relabel or load a model.
            // v32.3.0 (#701) — report what DISCRIMINATES. The old form printed
            // `label=X treated_as=X`, two copies of one constant the guard had
            // already proven equal, and omitted `ner_ran` — the field that
            // decides whether the operator stages a model or relabels.
            // AV-15-safe: levels are a closed vocabulary and the digest is a
            // hash, never user payload.
            IngestError::ScrubTreatmentMismatch {
                treated_as,
                ner_ran,
                model_digest,
            } => Some(format!(
                "treated_as={treated_as} ner_ran={ner_ran} model={}",
                model_digest.as_deref().unwrap_or("none")
            )),
            IngestError::Verify(_)
            | IngestError::Scrub(_)
            | IngestError::Store(_)
            | IngestError::Sign(_) => None,
        }
    }
}

/// Per-component scrub envelope produced by step 3.5.
///
/// THREAT_MODEL.md AV-24: cryptographic proof that *this deployment*
/// processed *this payload* at *this time*. Same shape as the four
/// columns on `trace_events` (FSD §3.7). Carried alongside the
/// component during decompose so the row writer doesn't need to
/// re-sign.
#[derive(Debug, Clone)]
pub struct ScrubEnvelope {
    /// sha256(canonical(component.data_pre_scrub)) — proves what the
    /// scrubber input was without retaining the original bytes.
    pub original_content_hash: String,
    /// base64(ed25519_sign([`scrub_preimage`])) — **the whole envelope**, not
    /// the payload alone (v32.0.0, CIRISPersist#690).
    ///
    /// This used to be `sign(canonical(data_post_scrub))`: a signature over the
    /// CONTENT and nothing else, which left every field beside it — the input
    /// hash, the key id, the timestamp — unsigned metadata a relay could
    /// rewrite while the signature still verified. That is #643 on this plane,
    /// where the attestation signature covered the envelope only and left the
    /// verb an unsigned column.
    ///
    /// The content is still bound, through `post_content_sha256` inside the
    /// preimage. What changed is that the statements ABOUT the content are now
    /// bound too.
    pub scrub_signature: String,
    /// Identifier for the deployment's signing key.
    pub scrub_key_id: String,
    /// When the scrub+sign happened.
    pub scrub_timestamp: chrono::DateTime<chrono::Utc>,
    /// **Did a named-entity pass actually run?** (#690)
    ///
    /// `NullScrubber` is a pass-through and produced a perfectly valid envelope,
    /// byte-indistinguishable in shape from a full NER pass — so a receiver
    /// could not tell an NER-scrubbed `full_traces` trace from one that was
    /// never scrubbed. It can now, and the claim is signed rather than asserted.
    pub ner_ran: bool,
    /// The trace level the content was **actually treated at**, after any
    /// downgrade — which may differ from the level the trace is labelled with
    /// upstream.
    ///
    /// A node with no model loaded scrubs at `detailed` and relabels the trace
    /// `detailed`, so the claim matches the treatment. Binding the level as well
    /// as the flag is what forbids the remaining lie: content labelled
    /// `full_traces` that received Detailed handling, with an honest `ner_ran`
    /// beside it.
    pub trace_level: String,
    /// **Digest of the NER model that ran**, `None` when none did (#690).
    ///
    /// `ner_ran: true` says a pass happened; it does not say what that pass
    /// could catch. Two models disagree about what counts as PII, so a receiver
    /// enforcing "properly scrubbed" needs to know WHICH instrument was used.
    /// The difference is between *"a scrub ran"*, *"an NER scrub ran"*, and *"an
    /// NER scrub ran with a model I accept"* — and only the last is enforceable.
    pub scrubber_model_digest: Option<String>,
}

/// **The bytes a scrub signature covers** (v32.0.0, CIRISPersist#690).
///
/// One function, used by the signer and by any verifier, so the two cannot
/// drift — the CIRISVerify `authorization_digest` lesson (#398): a preimage with
/// two implementations is a preimage with two answers.
///
/// Deliberately over a HASH of the post-scrub content rather than the content
/// itself. The signed input stays a fixed size regardless of trace size, which
/// is the #398 failure that stopped a hardware token mid-ceremony when a
/// widened preimage reached 83 KB.
///
/// v61 (CC 2.6.2) — the `ciris.scrub_envelope.v2` domain: a `domain`
/// member names the preimage, and `scrub_timestamp` is written `.sssZ` (the
/// signer truncates it to the millisecond first; this function truncates
/// again, so the bytes always name an instant the form can carry). The v1
/// preimage ([`scrub_preimage_v1`]: no `domain`, `to_rfc3339()`) still
/// verifies as v1; persist signs only v2.
#[must_use]
pub fn scrub_preimage(
    post_content_sha256: &str,
    original_content_hash: &str,
    ner_ran: bool,
    trace_level: &str,
    scrubber_model_digest: Option<&str>,
    scrub_key_id: &str,
    scrub_timestamp: chrono::DateTime<chrono::Utc>,
) -> Vec<u8> {
    // JCS via serde_json's ordered map: keys serialize lexicographically, which
    // is what both sides canonicalize to.
    let v = serde_json::json!({
        "domain": SCRUB_PREIMAGE_DOMAIN_V2,
        "post_content_sha256": post_content_sha256,
        "original_content_hash": original_content_hash,
        "ner_ran": ner_ran,
        "trace_level": trace_level,
        "scrubber_model_digest": scrubber_model_digest,
        "scrub_key_id": scrub_key_id,
        "scrub_timestamp": crate::federation::admission::render_signed_instant(scrub_timestamp),
    });
    // The house canonicalizer, not a second JCS implementation — #398's lesson
    // is that a preimage with two implementations is a preimage with two
    // answers. `ceg_produce_canonicalize` is what every other signed shape in
    // this crate goes through.
    crate::verify::canonical::ceg_produce_canonicalize(&v).unwrap_or_default()
}

/// v61 — the `domain` member of the v2 scrub preimage ([`scrub_preimage`]).
pub const SCRUB_PREIMAGE_DOMAIN_V2: &str = "ciris.scrub_envelope.v2";

/// The v32.0.0 (CIRISPersist#690) scrub preimage: no `domain` member and
/// `scrub_timestamp` written by `to_rfc3339()` (`+00:00`, chrono's fractional
/// digits). Persist no longer signs it; a verifier of a pre-v61 envelope
/// rebuilds it with this.
#[must_use]
pub fn scrub_preimage_v1(
    post_content_sha256: &str,
    original_content_hash: &str,
    ner_ran: bool,
    trace_level: &str,
    scrubber_model_digest: Option<&str>,
    scrub_key_id: &str,
    scrub_timestamp: chrono::DateTime<chrono::Utc>,
) -> Vec<u8> {
    let v = serde_json::json!({
        "post_content_sha256": post_content_sha256,
        "original_content_hash": original_content_hash,
        "ner_ran": ner_ran,
        "trace_level": trace_level,
        "scrubber_model_digest": scrubber_model_digest,
        "scrub_key_id": scrub_key_id,
        "scrub_timestamp": scrub_timestamp.to_rfc3339(),
    });
    crate::verify::canonical::ceg_produce_canonicalize(&v).unwrap_or_default()
}

/// Whether [`IngestPipeline::receive_and_persist`] runs its own
/// per-trace signature verification (step 2).
///
/// # Safety contract (CIRISPersist#91)
///
/// This is an **opt-in** knob and the decision lives at the call site
/// — the deployer knows the federation topology (same principle as
/// CIRISPersist#89's caller-supplied scrubber). Picking the wrong
/// variant is a security misconfiguration the type system cannot
/// catch, so the constraints below are non-negotiable:
///
/// - The lens **direct-ingest** path (untrusted agent input) MUST
///   stay [`VerifyMode::Full`] — that is the default and must never
///   be changed for that path.
/// - [`VerifyMode::TrustPreVerified`] is legitimate **only** for a
///   relay that already holds an Edge `verify_outcome` for the batch
///   (CIRISLensCore#10 / AV-9: "never re-verify what Edge verified").
///   It does not weaken authenticity — it asserts the gate already
///   passed upstream and persist should not redundantly re-do the
///   federation-directory `lookup_public_key` on the relay hot path.
///
/// Persisted rows record WHO established authenticity in
/// [`TraceEventRow::verification_source`](crate::store::TraceEventRow::verification_source):
/// `Full` → [`VerificationSource::Persist`](crate::store::VerificationSource::Persist),
/// `TrustPreVerified` → [`VerificationSource::Edge`](crate::store::VerificationSource::Edge).
/// `signature_verified` stays `true` in both modes — the trace is
/// authentic either way (Edge attested the skip-verify path).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerifyMode {
    /// Verify every `CompleteTrace` signature against the federation
    /// key directory (today's behavior; the only safe mode for
    /// untrusted direct-ingest input). The default. Persisted rows
    /// carry `verification_source = 'persist'`.
    #[default]
    Full,
    /// Skip per-trace signature verification: the caller attests the
    /// batch arrived already Edge-verified (it holds the Edge
    /// `verify_outcome`). Every other pipeline step — schema parse,
    /// scrub, decompose, store, ordering — is unchanged. Persisted
    /// rows carry `verification_source = 'edge'`, honestly recording
    /// that an upstream Edge verifier — not persist — established
    /// authenticity.
    TrustPreVerified,
}

/// Composition of dependencies for one ingest call.
///
/// Mission constraint (MISSION.md §2 — `store/`, `verify/`, `scrub/`):
/// each is a trait, each is injected here. Different deployment
/// shapes (lens server, agent in-process, iOS bundled) compose the
/// same pipeline with different impls.
///
/// The Backend doubles as the public-key directory (its
/// `lookup_public_key` async method is the only path) — mission
/// constraint (MISSION.md §3 anti-pattern #3): one path for key
/// lookup; the lens has no side-channel that bypasses the
/// persistence-layer key directory.
pub struct IngestPipeline<'a, B, C, S>
where
    B: Backend + ?Sized,
    C: Canonicalizer + ?Sized,
    S: Scrubber + ?Sized,
{
    /// Storage backend (Postgres / SQLite / in-memory).
    pub backend: &'a B,
    /// Canonicalization strategy (Python-compat or RFC 8785 JCS).
    pub canonicalizer: &'a C,
    /// PII-scrubbing pass (NullScrubber for tests; lens-side
    /// scrubber callable in production).
    pub scrubber: &'a S,
    /// v0.1.3: scrub-signing key. UNCONDITIONAL — always present,
    /// every row signed (FSD §3.4 robustness primitive #7;
    /// THREAT_MODEL.md AV-24). Use ciris-keyring's
    /// `get_platform_signer(alias)` for production (hardware-backed
    /// where available); `Ed25519SoftwareSigner` for tests.
    pub signer: &'a dyn HardwareSigner,
    /// Stable identifier for the signer (matches what the deployment
    /// publishes to the registry). Carried into the scrub_key_id
    /// column on every row.
    pub signer_key_id: &'a str,
}

impl<'a, B, C, S> IngestPipeline<'a, B, C, S>
where
    // v18.0.0 (CIRISPersist#473) — `FederationDirectory` joined the bound:
    // the ENVELOPE-NATIVE doctrine ("everything persist saves is a CEG
    // object in an envelope") makes the ingest pipeline mint each verified
    // trace as a local-tier `scores` attestation — the trace's canonical
    // home — via `attestation_insert_local`; `trace_events` rows are the
    // read-optimized projection.
    B: Backend + crate::federation::FederationDirectory + ?Sized,
    C: Canonicalizer + ?Sized,
    S: Scrubber + ?Sized,
{
    /// v54.1.0 (CIRISPersist#1040, #1046) — step 2b of
    /// [`receive_and_persist_with`](Self::receive_and_persist_with): refuse a
    /// tombstoned trace on every node, and a trace whose signed `run_kind` is
    /// `mock` (CC 3.1.5, CIRISConstitution#166) on a node holding the
    /// `canonical` role (its OWN verified role, re-derived from its own
    /// directory; a node with no identity set is not the canonical).
    /// `run_kind` is the trace's SIGNED member (verified in step 2 when it is
    /// present).
    async fn refuse_named_traces(&self, env: &BatchEnvelope) -> Result<(), IngestError> {
        let refused =
            |kind: &'static str, detail: String| IngestError::TraceRefused { kind, detail };
        let mut canonical: Option<bool> = None;
        for event in &env.events {
            let BatchEvent::CompleteTrace { trace, .. } = event;
            // v62.0.0 (wave GC2; CC rc21 ruling 8, CC 4.5.3) — a tombstone is a
            // deletion duty while it STANDS: one an admitted reversal lifted
            // declines nothing, and the re-offered trace is taken again
            // (`takedown_tombstone::standing_tombstone`).
            match crate::federation::takedown_tombstone::standing_tombstone(
                self.backend.as_dyn_directory(),
                crate::federation::steward_purge::PurgePlane::Trace.as_str(),
                &trace.trace_id,
            )
            .await
            {
                // v62.0.0 (P7-fix6; CC ruling (a): a trace is authored by its
                // agent, CC 3.1.5 / signer_kind.tsv / key_roles R4) — the
                // INTERIM person exemption (Codex round 4 on PR #1057: "a trace
                // a PROVEN person signed is not purgeable") is DELETED (ruling
                // 4): no person trace exists, the trace door refuses a non-agent
                // signer (`trace_signer_not_agent`), and the exemption read the
                // earlier-form `signature_key_id` only. A standing tombstone
                // declines the trace.
                Ok(Some(notice_id)) => {
                    return Err(refused(
                        crate::federation::steward_purge::token::TOMBSTONED,
                        format!("trace_id={} notice_id={notice_id}", trace.trace_id),
                    ));
                }
                Ok(None) | Err(crate::federation::Error::Unsupported { .. }) => {}
                Err(e) => return Err(IngestError::Store(StoreError::Backend(e.to_string()))),
            }
            // v56.0.0 (#1089) — the signed run_kind from either place it is
            // signed (top level, or `deployment_profile.run_kind` at v2.8.0).
            if trace.signed_run_kind() != Some(crate::federation::steward_purge::RUN_KIND_MOCK) {
                continue;
            }
            let is_canonical = match canonical {
                Some(c) => c,
                None => {
                    let c = match self.backend.node_key_id() {
                        Some(node) => crate::federation::is_canonical_effective(
                            self.backend.as_dyn_directory(),
                            &node,
                        )
                        .await
                        .map_err(|e| IngestError::Store(StoreError::Backend(e.to_string())))?,
                        None => false,
                    };
                    canonical = Some(c);
                    c
                }
            };
            if is_canonical {
                return Err(refused(
                    crate::federation::steward_purge::TRACE_RUN_KIND_MOCK,
                    format!("trace_id={} run_kind=mock", trace.trace_id),
                ));
            }
        }
        Ok(())
    }

    /// Run the FSD §3.3 pipeline over a raw HTTP body.
    ///
    /// Step ordering is load-bearing — schema first (fail fast on
    /// malformed input), verify second (no mutation before
    /// authenticity gate), scrub third (verify is over the
    /// agent-shipped bytes; scrub mutates after), decompose fourth,
    /// store last.
    ///
    /// Always runs [`VerifyMode::Full`] — the only safe mode for
    /// untrusted direct-ingest input (the lens direct-ingest path).
    /// A relay that holds an Edge `verify_outcome` and wants to skip
    /// the redundant per-trace federation-directory lookup calls
    /// [`receive_and_persist_with`](Self::receive_and_persist_with)
    /// with [`VerifyMode::TrustPreVerified`] instead — see that
    /// method and [`VerifyMode`] for the CIRISPersist#91 safety
    /// contract.
    pub async fn receive_and_persist(&self, bytes: &[u8]) -> Result<BatchSummary, IngestError> {
        self.receive_and_persist_with(bytes, VerifyMode::Full).await
    }

    /// v2.0 (CIRISPersist#91) — [`receive_and_persist`](Self::receive_and_persist)
    /// with an explicit [`VerifyMode`].
    ///
    /// `VerifyMode::Full` is byte-identical to `receive_and_persist`.
    /// `VerifyMode::TrustPreVerified` skips **only** step 2 (the
    /// per-`CompleteTrace` signature verification + its federation-
    /// directory `lookup_public_key`); every other step — schema
    /// parse, pre-scrub hashing, scrub, scrub-envelope signing,
    /// decompose, insert, and the ordering between them — is
    /// unchanged.
    ///
    /// # Safety
    ///
    /// `VerifyMode::TrustPreVerified` is opt-in and legitimate **only**
    /// for a relay holding an Edge `verify_outcome` for the batch
    /// (CIRISLensCore#10 / AV-9). The decision lives at the call site;
    /// the lens direct-ingest path MUST NOT use it. See [`VerifyMode`].
    ///
    /// # Honest row state under skip-verify
    ///
    /// In `TrustPreVerified` mode persist does **not** run
    /// `verify_trace` itself, so the persisted rows carry
    /// [`verification_source = Edge`](crate::store::VerificationSource::Edge)
    /// — honestly recording that an upstream Edge verifier, not
    /// persist, established authenticity. `signature_verified` stays
    /// `true`: the trace IS authentic (Edge attested it). A consumer
    /// that needs persist-attested verification specifically filters
    /// `verification_source = 'persist'`. `BatchSummary::signatures_verified`
    /// is `0` — persist itself verified zero signatures.
    pub async fn receive_and_persist_with(
        &self,
        bytes: &[u8],
        verify_mode: VerifyMode,
    ) -> Result<BatchSummary, IngestError> {
        // 1. Schema parse — typed envelope. Schema-version gate fires
        //    here.
        // v33.0.0 (#705) — no longer `mut`: the scrub works on a copy now, so
        // nothing mutates the envelope that becomes the stored record. The
        // compiler noticing this is the change being real.
        // v62.0.0 (wave P7) — a statement-carrying event's `trace_blob` (the
        // trace's exact bytes, base64) is decoded and parsed into its `trace`;
        // `carried[i]` keeps the statement and the bytes as received.
        //    A SEALED row-form event (a `self` / `family` trace, its blob an
        //    at-rest envelope) carries no readable trace: it is taken out of
        //    the typed batch, its row half checked here, and admitted with the
        //    others in step 2 (its projection waits for this node's DEK).
        let ExpandedBatch {
            rewritten,
            carried,
            sealed,
            sealed_only,
        } = expand_trace_blobs(bytes)?.unwrap_or_default();
        for (statement, blob) in &sealed {
            check_trace_row_shape(statement, blob)?;
        }
        if sealed_only {
            let mut signatures_verified = 0usize;
            for (statement, blob) in &sealed {
                admit_trace_statement(self.backend, None, statement, blob).await?;
                signatures_verified += 1;
            }
            return Ok(BatchSummary {
                envelopes_processed: sealed.len(),
                signatures_verified,
                ..BatchSummary::default()
            });
        }
        let env = BatchEnvelope::from_json(rewritten.as_deref().unwrap_or(bytes))?;

        // 2. Verify each CompleteTrace signature. Mission constraint
        //    (MISSION.md §3 anti-pattern #2): verify before any
        //    mutation; verification is over the agent-shipped bytes.
        //
        //    CIRISPersist#91: in `VerifyMode::TrustPreVerified` the
        //    caller (a relay) attests the batch arrived already
        //    Edge-verified, so persist skips this step entirely —
        //    no per-trace `lookup_public_key`. `signatures_verified`
        //    stays 0 because *persist* verified nothing; the
        //    persisted rows are flagged accordingly (see step 6).
        let mut signatures_verified = 0usize;
        // v62.0.0 (wave P7; CC 3.1.5; the rulings "a replicating trace is a
        // forward-form row" and "the manifest form is the only form") — a
        // trace carrying its `trace:complete:v1` statement arrives as the
        // statement plus the trace BLOB's exact bytes (`trace_blob`), already
        // expanded into the typed envelope above. It is admitted by the
        // edition-2 statement door in EITHER mode (the door verifies whoever
        // relayed it) and counts as a verified signature. A trace without one
        // is the earlier form: verified (VerifyMode::Full) behind the
        // earlier-form switch, or, under `TrustPreVerified`, kept LOCAL and
        // never served (`refuse_unsigned_trace_crossing`).
        //
        // Every pure check (each statement's content binding, each
        // earlier-form verify) runs over the whole batch BEFORE the first
        // statement is offered to the door, which writes the row: a batch with
        // a malformed event writes nothing. A door refusal of a later
        // statement leaves the earlier rows admitted (each is a valid row on
        // its own; a replay finds them held).
        for (i, event) in env.events.iter().enumerate() {
            let BatchEvent::CompleteTrace { trace, .. } = event;
            match carried.get(i).and_then(Option::as_ref) {
                Some((statement, blob)) => {
                    check_trace_statement_binding(statement, trace, blob)?;
                    // v62.0.0 (P7-fix8) — a trace that cannot DECOMPOSE (an
                    // `attempt_index` past `MAX_ATTEMPT_INDEX`, AV-17; a
                    // missing field) is refused here, under its schema token,
                    // with the batch's other pure checks: before any blob is
                    // stored or row written. The row's own write would refuse
                    // it at the projection (`trace_projection_of`), but only
                    // after the blob plane had kept its bytes.
                    crate::store::decompose(trace).map_err(|e| match e {
                        crate::store::Error::Schema(s) => IngestError::Schema(s),
                        other => IngestError::Store(other),
                    })?;
                }
                None => {
                    // v62.0.0 (F0-cp5b) — a statement-less trace is the
                    // earlier form: refused by name under `Full`. Under
                    // `TrustPreVerified` it is kept LOCAL and never served
                    // (`refuse_unsigned_trace_crossing`; I3482).
                    if verify_mode == VerifyMode::Full {
                        refuse_earlier_form_trace()?;
                        signatures_verified += 1;
                    }
                }
            }
        }
        for (statement, blob) in &sealed {
            admit_trace_statement(self.backend, None, statement, blob).await?;
            signatures_verified += 1;
        }
        let mut statement_signers: Vec<Option<String>> = vec![None; env.events.len()];
        for (i, event) in env.events.iter().enumerate() {
            let BatchEvent::CompleteTrace { trace, .. } = event;
            if let Some((statement, blob)) = carried.get(i).and_then(Option::as_ref) {
                let (iss, _held) =
                    admit_trace_statement(self.backend, Some(trace), statement, blob).await?;
                statement_signers[i] = Some(iss);
                signatures_verified += 1;
            }
        }
        let env = with_statement_signers(env, &statement_signers);

        // 2b. v54.1.0 — refusals on a NAMED ground, before any write.
        //     (CIRISPersist#1046) a trace a steward purge tombstoned is never
        //     re-admitted — the tombstone outlives the rows it removed.
        //     (CIRISPersist#1040, CIRISConstitution#166) a node holding the
        //     `canonical` role is the federation corpus: a trace whose signed
        //     `run_kind` is `mock` attests nothing and is refused there. Every
        //     other node (an agent's own store, a QA node) keeps it.
        self.refuse_named_traces(&env).await?;

        // 3. Capture pre-scrub canonical bytes for every component.
        //    FSD §3.3 step 3.5: original_content_hash is sha256 of
        //    canonical(component.data_pre_scrub) — must be computed
        //    BEFORE scrub mutates `data`. One Vec<u8>-per-component
        //    held briefly; dropped after step 3.5.
        let pre_scrub_hashes = self.compute_pre_scrub_hashes(&env)?;

        // 4. Scrub — ON A COPY, for the PUBLISHABLE artifact only.
        //
        // v33.0.0 (CIRISPersist#705, CIRISServer#418) — **the node's own record
        // is never redacted.** Scrubbing is an EGRESS act, which persist's own
        // doctrine already said (`scrub/mod.rs`: "at the sender's egress") while
        // the code did it at rest. `receive_and_persist` is how an agent
        // captures ITS OWN traces, so scrubbing `env` in place destroyed the
        // original — Server wired a real scrubber, watched self-scoped content
        // change under it, and reverted.
        //
        // What actually leaves this node is the ATTESTATION. `trace_events` is a
        // LOCAL projection (`replication_policy::Projection::TraceEvents` —
        // "trace_events from a trace:complete:v1 attestation"), derived on a
        // receiver from an admitted attestation and never replicated itself.
        // The attestation embeds the whole trace, and it is the wire object.
        //
        // So the split is exactly the privacy boundary:
        //   * `env`          — untouched, becomes the stored rows. The record.
        //   * `scrubbed_env` — the copy the attestation is minted from. Derived,
        //                      transient, and the only thing that ships.
        //
        // The scrubbed copy is not retained separately; it lives inside the
        // attestation envelope and nowhere else.
        let mut scrubbed_env = env.clone();
        let scrub_outcome = self.scrubber.scrub_batch(&mut scrubbed_env)?;
        let scrubbed_fields = scrub_outcome.fields_modified;

        // 4a. v32.0.0 (#690) — REFUSE a full_traces batch that did not get a
        //     named-entity pass. The envelope now carries the treatment, and a
        //     carried fact nobody enforces is the #685 shape: stored,
        //     verifiable, unconsulted.
        //
        //     Checked against the level the scrubber says it TREATED the content
        //     at, not the incoming label, so a node that downgrades to
        //     `detailed` and relabels passes honestly while one that keeps the
        //     `full_traces` label without the pass does not.
        // v33.0.0 (#705) — this gates PUBLICATION, not storage. Refusing to
        // store a node's own record was always the wrong lever; refusing to mint
        // a publishable artifact from untreated content is the right one.
        if scrub_outcome.applied_trace_level == TraceLevel::FullTraces.as_str()
            && !scrub_outcome.ner_ran
        {
            return Err(IngestError::ScrubTreatmentMismatch {
                treated_as: scrub_outcome.applied_trace_level.clone(),
                ner_ran: scrub_outcome.ner_ran,
                model_digest: scrub_outcome.scrubber_model_digest.clone(),
            });
        }

        // 5. Step 3.5 — sign per-component scrub envelope. UNCONDITIONAL
        //    (FSD §3.3 step 3.5; §3.4 robustness primitive #7).
        //    Same key signs every component on every trace level.
        let envelopes = self
            .sign_scrub_envelopes(&env, &pre_scrub_hashes, &scrub_outcome)
            .await?;

        // 6. Decompose each CompleteTrace into row-shaped writes.
        //    Envelope columns get attached to each row by index.
        let mut events_to_insert = Vec::new();
        let mut llm_calls_to_insert = Vec::new();
        // v18.0.0 (#473) — one envelope-native attestation mint per trace.
        let mut trace_attestation_inputs: Vec<crate::federation::types::LocalAttestationInput> =
            Vec::new();
        let mut env_idx = 0usize;
        // v4.0 (FSD §4.6) — write-path cohort_scope gate: resolved
        // writer admission, keyed on the signer (`scrub_key_id`). Built
        // lazily on the first family/community row so all-self / all-broad
        // / all-federation batches pay no admission reads. Same signer
        // signs every component of a batch in this pipeline, so the cache
        // is hit for every row after the first family/community one.
        let mut writer_admission_cache: Option<(String, crate::scope::CallerAdmission)> = None;
        for (i, event) in env.events.iter().enumerate() {
            match event {
                BatchEvent::CompleteTrace { trace, .. } => {
                    // v62.0.0 (wave P7) — a trace that arrived as its row: its
                    // `trace_events` were projected in the row's own write
                    // (`project_trace_row_from_held_blob`), never twice.
                    if matches!(statement_signers.get(i), Some(Some(_))) {
                        env_idx += trace.components.len();
                        continue;
                    }
                    // v0.4.6 (CIRISPersist#22) — typed Schema/Store
                    // split. `decompose` returns `store::Error`, which
                    // can be `Schema(SchemaError)` for missing/wrong
                    // fields — those are deterministic 4xx (lens 422),
                    // NOT Store (lens 503 + Retry-After). Pre-fix the
                    // blanket `map_err(IngestError::Store)` sent
                    // schema rejects through the 503 path, triggering
                    // hot agent retry loops on deterministic schema
                    // mismatches. Preserve the variant.
                    //
                    // The two `insert_*_batch` callsites below
                    // (lines ~265 / ~270) legitimately return
                    // `StoreError` from the backend write itself, so
                    // they correctly stay on the Store arm.
                    let mut d = crate::store::decompose(trace).map_err(|e| match e {
                        crate::store::Error::Schema(s) => IngestError::Schema(s),
                        other => IngestError::Store(other),
                    })?;
                    for row in &mut d.events {
                        let env_for_row = &envelopes[env_idx];
                        row.original_content_hash = Some(env_for_row.original_content_hash.clone());
                        row.scrub_signature = Some(env_for_row.scrub_signature.clone());
                        row.scrub_key_id = Some(env_for_row.scrub_key_id.clone());
                        row.scrub_timestamp = Some(env_for_row.scrub_timestamp);
                        // v32.0.0 (#690) — the treatment claims travel onto the
                        // row because they are INSIDE `scrub_signature`'s
                        // preimage. Persisting the signature without them
                        // yields a signature that verified once, at signing
                        // time, and can never be checked again.
                        row.scrub_ner_ran = Some(env_for_row.ner_ran);
                        row.scrub_applied_trace_level = Some(env_for_row.trace_level.clone());
                        row.scrub_model_digest = env_for_row.scrubber_model_digest.clone();
                        // CIRISPersist#91 — record WHO established
                        // authenticity. `signature_verified` keeps its
                        // plain meaning ("the signature is valid") and
                        // stays `true` for both modes — the trace IS
                        // authentic either way. `verification_source`
                        // records the attestor: `Full` mode = persist
                        // ran `verify_trace`; `TrustPreVerified` =
                        // delegated upstream to an Edge verifier (the
                        // relay carried the `verify_outcome`).
                        row.verification_source = match verify_mode {
                            VerifyMode::Full => crate::store::VerificationSource::Persist,
                            VerifyMode::TrustPreVerified => crate::store::VerificationSource::Edge,
                        };

                        // v4.0 (CIRISPersist#160, FSD §4.4 / §12.0 item 1)
                        // — self-target resolution. `decompose` copied
                        // the producer-declared (cohort_scope, target)
                        // from the verified CompleteTrace onto every row.
                        // For a `self`-scoped row the target is the OWNER
                        // IDENTITY, which the substrate MUST resolve from
                        // the verified signer (the scrub_key_id — the
                        // Ed25519-verified deployment key) and stamp
                        // itself; a caller-supplied self-target is NEVER
                        // trusted (the §4.6 write-gate lands in Commit F).
                        //
                        // Ordering: this runs in the decompose stage,
                        // strictly AFTER the step-2 verify gate
                        // (MISSION §4 verify-before-persist) and BEFORE
                        // the step-5 insert — no mutation is admitted
                        // until authenticity passed. Singleton-identity
                        // fallback (FSD §4.4): an occurrence key not yet
                        // bound as an IdentityOccurrence IS its own
                        // identity, so we stamp the signer key itself.
                        if row.cohort_scope == crate::federation::types::cohort_scope::SELF {
                            let signer = env_for_row.scrub_key_id.as_str();
                            let resolved = self
                                .backend
                                .resolve_identity_for_occurrence(signer)
                                .await
                                .map_err(IngestError::Store)?
                                .unwrap_or_else(|| signer.to_owned());
                            row.cohort_target_id = Some(resolved);
                        }

                        // v4.0 (CIRISPersist#160 comment 4, FSD §4.6) —
                        // AV-45 write-path cohort_scope admission gate.
                        // A writer claiming (cohort_scope, target) must be
                        // a MEMBER of the target it names. Symmetric to the
                        // §4.3 read-gate; same `CallerAdmission`, opposite
                        // direction.
                        //
                        // Ordering (load-bearing, MISSION §4): this runs
                        // strictly AFTER the step-2 verify gate and AFTER
                        // D2's self-target resolution, and BEFORE the
                        // step-5 insert. A refusal returns `Err` here, so
                        // `events_to_insert` is dropped without ever
                        // reaching `insert_trace_events_batch` — ZERO rows
                        // persist for the whole batch (mirrors the
                        // signature-mismatch zero-writes discipline).
                        //
                        // `self` + the broad belonging-tiers are no-op
                        // passes (the gate needs no membership set for
                        // them); only `family` / `community` consult the
                        // writer's resolved admission. We build that
                        // admission lazily — once per batch on first need
                        // — from the verified signer (`scrub_key_id`), so
                        // an all-`self`/all-broad/all-federation batch
                        // (every current producer) pays no extra reads.
                        let scope = row.cohort_scope.as_str();
                        // v47.0.0 (CIRISPersist#897) — "needs a roster" is
                        // the classifier's answer. The local
                        // `FAMILY || COMMUNITY` spelling here let an
                        // `affiliations` trace through with no membership
                        // check at all.
                        if let Some(plane) =
                            crate::federation::types::cohort_scope::target_plane(scope)
                        {
                            let admission = self
                                .writer_admission(
                                    &mut writer_admission_cache,
                                    env_for_row.scrub_key_id.as_str(),
                                )
                                .await?;
                            if let Err(mut reason) = crate::federation::admission::DimensionAdmissionPolicy::check_write_cohort_scope(
                                admission,
                                scope,
                                row.cohort_target_id.as_deref(),
                            ) {
                                // v47.0.0 (CIRISPersist#797) — the same
                                // unresolved/terminal split as the
                                // attestation put door, looked up only on the
                                // refusal path so an admitted batch pays
                                // nothing: a roster this node does not HOLD
                                // is retryable, not "not a member".
                                if let Some(target) = row.cohort_target_id.as_deref() {
                                    use crate::federation::types::cohort_scope::TargetPlane;
                                    let held = match plane {
                                        TargetPlane::Family => crate::federation::FederationDirectory::lookup_family(self.backend, target).await.map(|f| f.is_some()),
                                        TargetPlane::Room => crate::federation::FederationDirectory::lookup_community(self.backend, target).await.map(|c| c.is_some()),
                                    }
                                    .map_err(|e| IngestError::Store(StoreError::Backend(format!("roster lookup: {e}"))))?;
                                    if !held {
                                        reason = crate::scope::ScopeRefusalReason::MembershipUnresolved;
                                    }
                                }
                                // v62.0.0 (wave GC2; lead ruling on row 35, CC 2.7.3) —
                                // "not a member" reads the roster (OTHER rows), so the
                                // batch door no longer refuses on it. The trace's
                                // edition-2 row (`trace:complete:v1`, through
                                // `put_statement`) is its concluded form, and the fold
                                // decides it there. Only the unresolved roster (a
                                // retryable wait for a roster not held) stays here.
                                if !matches!(
                                    reason,
                                    crate::scope::ScopeRefusalReason::MembershipUnresolved
                                ) {
                                    tracing::debug!(
                                        write_path = "trace_ingest",
                                        scope = %scope,
                                        reason = %reason.kind(),
                                        target = ?row.cohort_target_id,
                                        "ciris-persist: write-scope membership is the fold's (row 35)"
                                    );
                                    env_idx += 1;
                                    continue;
                                }
                                // §9.3 — Layer-1 write-side refusal counter.
                                tracing::warn!(
                                    metric = "persist_refused_write_scope_total",
                                    write_path = "trace_ingest",
                                    scope = %scope,
                                    reason = %reason.kind(),
                                    target = ?row.cohort_target_id,
                                    "ciris-persist: write-path cohort_scope refused (AV-45)"
                                );
                                return Err(IngestError::ScopeRefused(reason));
                            }
                        }

                        env_idx += 1;
                    }
                    // v18.0.0 (#473) — ENVELOPE-NATIVE: collect the trace's
                    // attestation mint (its canonical CEG home).
                    //
                    // v33.0.0 (#705) — minted from the SCRUBBED copy, while the
                    // rows above come from the original. This is the whole fix:
                    // the attestation is what crosses to federation, so it
                    // carries redacted content; `trace_events` is this node's
                    // own record and keeps full fidelity.
                    //
                    // Indexed rather than zipped because the scrubber's
                    // preservation gate guarantees `events[]` count and order
                    // are unchanged — a scrubber altering either is refused
                    // before this point, so index `i` is the same trace in both.
                    let scrubbed_trace = match scrubbed_env.events.get(i) {
                        Some(BatchEvent::CompleteTrace { trace: t, .. }) => t,
                        _ => {
                            return Err(IngestError::PipelineInvariant {
                                kind: "scrub_envelope_shape_drift",
                                detail: format!(
                                    "scrubbed copy lost the CompleteTrace at index {i}; the \
                                     preservation gate should have refused this scrubber"
                                ),
                            })
                        }
                    };
                    // v62.0.0 (wave P7) — a trace that arrived with its
                    // `trace:complete:v1` row has that row as its home
                    // (admitted in step 2); nothing is minted for it.
                    if !matches!(statement_signers.get(i), Some(Some(_))) {
                        trace_attestation_inputs
                            .push(self.build_trace_attestation_input(scrubbed_trace)?);
                    }
                    events_to_insert.extend(d.events);
                    llm_calls_to_insert.extend(d.llm_calls);
                }
            }
        }
        debug_assert_eq!(env_idx, envelopes.len(), "envelope index drift");

        // 4.9 (v18.0.0, #473) — mint the ENVELOPE-NATIVE trace attestations
        //    FIRST: the attestation is the trace's canonical home; the
        //    trace_events rows below are its projection. Deterministic ids +
        //    the funnels' conflict-ignore make replays idempotent. A mint
        //    failure (typically: attesting key not in this directory on a
        //    relay ingest) SKIPS with a warning — the projection still
        //    lands, and the mint self-heals on replay once the key exists.
        let mut trace_attestations_minted = 0usize;
        let mut trace_attestations_skipped = 0usize;
        for input in trace_attestation_inputs {
            let tid = input
                .attestation_envelope
                .extra
                .get("trace_id")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_owned();
            match self.backend.attestation_insert_local(input).await {
                Ok(_) => trace_attestations_minted += 1,
                Err(e) => {
                    // v31.0.0 (CIRISPersist#598) — LOG THE ERROR, NOT JUST ITS
                    // KIND. This warn used to carry `reason = e.kind()` alone,
                    // which for every admission refusal is the single token
                    // `federation_invalid_argument` — the gate's own sentence,
                    // the one that names the column and the issue, was
                    // discarded here.
                    //
                    // That mattered: when #598 made the local door refuse
                    // every durable mint, this skip-and-warn turned the entire
                    // trace-attestation plane dark — `minted` went 1 → 0 on
                    // every node — and the only operator-visible trace of it
                    // was a kind token shared with a dozen unrelated causes.
                    // The mint is the OWNER-DOCTRINE chokepoint (the
                    // attestation IS the trace's canonical home; `trace_events`
                    // is its projection), so a silent total failure here is the
                    // most expensive thing this pipeline can do quietly.
                    //
                    // The skip POSTURE is unchanged and still right — the #473
                    // reason (producer key not yet federated on a relay ingest)
                    // is genuinely transient and self-heals on replay. What
                    // changes is that a NON-transient refusal, which will never
                    // self-heal, now says what it was.
                    tracing::warn!(
                        write_path = "trace_ingest",
                        trace_id = %tid,
                        reason = %e.kind(),
                        error = %e,
                        "ciris-persist: trace attestation mint skipped (#473)"
                    );
                    trace_attestations_skipped += 1;
                }
            }
        }

        // 5. Insert. Postgres ON CONFLICT DO NOTHING handles
        //    idempotency at the dedup index (FSD §3.4 #4).
        let event_report: InsertReport = self
            .backend
            .insert_trace_events_batch(&events_to_insert)
            .await
            .map_err(IngestError::Store)?;

        let llm_inserted = self
            .backend
            .insert_trace_llm_calls_batch(&llm_calls_to_insert)
            .await
            .map_err(IngestError::Store)?;

        // 6. v0.7.4 (CIRISPersist#19) — post-insert: run the extract
        //    stage and batch-UPDATE the V009 `extracted_features`
        //    column for every (trace_id, thought_id) pair we just
        //    inserted. Feature-gated on `extract`; backends that
        //    don't have V009 (memory, sqlite) silently no-op via the
        //    Backend trait default impl. Failures here log + skip
        //    the UPDATE rather than failing the whole ingest: the
        //    canonical row already landed, and stale features are
        //    less bad than dropping verified testimony on the floor.
        //    (Pre-v0.7.4 production rows had this column NULL too,
        //    so the consumer contract handles None gracefully.)
        #[cfg(feature = "extract")]
        if !env.events.is_empty() {
            let mut updates: Vec<(String, String, crate::pipeline::extract::Features)> =
                Vec::with_capacity(env.events.len());
            for event in &env.events {
                match event {
                    BatchEvent::CompleteTrace { trace, .. } => {
                        let declared = trace
                            .deployment_profile
                            .as_ref()
                            .map(|p| crate::pipeline::extract::DeclaredCohortAxes {
                                agent_role: Some(p.agent_role.clone()),
                                agent_template: Some(p.agent_template.clone()),
                                deployment_domain: Some(p.deployment_domain.clone()),
                                deployment_type: Some(p.deployment_type.clone()),
                                deployment_region: p.deployment_region.clone(),
                                deployment_trust_mode: Some(p.deployment_trust_mode.clone()),
                            })
                            .unwrap_or_default();
                        // Non-fatal: serialize never realistically fails
                        // for a verified CompleteTrace, but if it does,
                        // skip extract for THIS trace rather than failing
                        // the whole batch (the row already landed).
                        let trace_json = match serde_json::to_value(trace) {
                            Ok(v) => v,
                            Err(e) => {
                                tracing::warn!(error = %e, trace_id = %trace.trace_id,
                                    "trace serialize for extract failed; skipping");
                                continue;
                            }
                        };
                        let features =
                            crate::pipeline::extract::extract_features(&trace_json, declared);
                        updates.push((trace.trace_id.clone(), trace.thought_id.clone(), features));
                    }
                }
            }
            // Non-fatal: log + continue on error. The trace_events row
            // already landed; an extract miss leaves the column NULL,
            // matching the pre-v0.7.4 production state.
            if let Err(e) = self.backend.update_features_batch(&updates).await {
                tracing::warn!(error = %e, count = updates.len(),
                    "pipeline extract UPDATE failed; rows landed with extracted_features=NULL");
            }
        }

        Ok(BatchSummary {
            envelopes_processed: env.events.len(),
            trace_events_inserted: event_report.inserted,
            trace_attestations_minted,
            trace_attestations_skipped,
            trace_events_conflicted: event_report.conflicted,
            trace_llm_calls_inserted: llm_inserted,
            scrubbed_fields,
            signatures_verified,
        })
    }

    /// Compute pre-scrub `original_content_hash` for every component
    /// across every CompleteTrace in the batch. Order is flat:
    /// envelopes[i] corresponds to the i-th component in document
    /// order across all events.
    ///
    /// Mission alignment (MISSION.md §2 — `verify/`): the hash is
    /// the bridge between the unscrubbed bytes (which we never
    /// retain) and the scrubbed payload that lands in storage. An
    /// auditor with the original content can verify it was the
    /// scrubbing input.
    fn compute_pre_scrub_hashes(&self, env: &BatchEnvelope) -> Result<Vec<String>, IngestError> {
        let mut hashes = Vec::new();
        for event in &env.events {
            match event {
                BatchEvent::CompleteTrace { trace, .. } => {
                    for component in &trace.components {
                        let value = serde_json::Value::Object(component.data.clone());
                        let bytes = self
                            .canonicalizer
                            .canonicalize_value(&value)
                            .map_err(IngestError::Verify)?;
                        let mut h = Sha256::new();
                        h.update(&bytes);
                        hashes.push(format!("sha256:{}", hex::encode(h.finalize())));
                    }
                }
            }
        }
        Ok(hashes)
    }

    /// v18.0.0 (CIRISPersist#473) — build the ENVELOPE-NATIVE attestation
    /// mint for one verified, post-scrub trace.
    ///
    /// The trace's canonical CEG home is a local-tier `scores` attestation:
    /// `attesting_key_id` = the trace's verified producer key
    /// (`signature_key_id`), `subject_key_ids` = [attester] (self-subject —
    /// a subjectless row is invisible to every V106 seek, the #461 lesson),
    /// `cohort_scope` = `self` (consent promotes `self → community` via
    /// `attestation_promote`; replication is pure CEG state). The
    /// `attestation_id` is DETERMINISTIC (sha256 of the trace_id, folded to
    /// a UUID) so a replayed batch re-mints the same id and the funnels'
    /// conflict-ignore deduplicates.
    ///
    /// Size discipline (CC#38 / `MAX_ATTESTATION_ENVELOPE_BYTES`): an
    /// envelope whose canonical bytes fit rides WHOLE (the scrubbed trace
    /// inline); an oversize trace gets a MANIFEST envelope (content hash +
    /// byte length + component count) — the payload stays queryable in the
    /// `trace_events` projection, and degradable-plane (fountain) retrieval
    /// is the tracked follow-up.
    ///
    /// # The stamp is not in these bytes (v31.0.0, CIRISPersist#653)
    ///
    /// This branch used to end "either way the attestation admits", and
    /// CIRISPersist#643/#598 made that promise conditional at the margin. The
    /// bytes measured here are the PRODUCER's envelope; the bytes actually
    /// stored are that envelope plus persist's own stamp — the
    /// [`RowMirror`](crate::federation::envelope::RowMirror) and the bound
    /// instants, written at the local write door because that is the last
    /// moment an unsigned local row's bytes are persist's to write. So a trace
    /// whose canonical form lands in the ~250 bytes below the cap takes the
    /// INLINE branch here and exceeds the cap once stamped.
    ///
    /// That is NOT resolved by reserving headroom here. Modelling the door's
    /// stamp in the producer would be a second spelling of that projection, and
    /// a second spelling that drifts is how a producer starts certifying rows
    /// no host can write — the class this whole substrate keeps single-sourcing
    /// away. It is resolved at the door, which now sizes the row as it will be
    /// STORED
    /// ([`check_envelope_size_admission`](crate::federation::admission::check_envelope_size_admission)
    /// runs again after the stamp at all three local write funnels).
    ///
    /// The consequence for THIS function is worth stating plainly, because it
    /// is a behaviour change and not merely a repaired invariant: such a trace
    /// is now REFUSED at the local door — loudly, naming the bytes and the cap
    /// — instead of being stored and refused later by every peer. It does not
    /// fall back to the MANIFEST form, because this function has already
    /// chosen the shape by the time the door sees it. Losing the mint visibly
    /// at the right door beats storing a row this node can never replicate;
    /// making the fallback itself margin-aware needs the producer to know the
    /// stamp's size, which is the coupling rejected above.
    fn build_trace_attestation_input(
        &self,
        trace: &crate::schema::CompleteTrace,
    ) -> Result<crate::federation::types::LocalAttestationInput, IngestError> {
        use crate::federation::admission::MAX_ATTESTATION_ENVELOPE_BYTES;

        let attestation_id = trace_attestation_id(&trace.trace_id);

        let attesting = trace.signature_key_id.clone();
        let trace_value = serde_json::to_value(trace)
            .map_err(|e| IngestError::Sign(format!("trace attestation serialize: {e}")))?;
        let mut envelope = serde_json::json!({
            "dimension": TRACE_ATTESTATION_DIMENSION,
            "trace_id": trace.trace_id,
            "agent_id_hash": trace.agent_id_hash,
            "trace": trace_value,
        });

        let canonical = self
            .canonicalizer
            .canonicalize_value(&envelope)
            .map_err(IngestError::Verify)?;
        if canonical.len() > MAX_ATTESTATION_ENVELOPE_BYTES {
            let mut mh = Sha256::new();
            mh.update(&canonical);
            let mut manifest = serde_json::json!({
                "schema": "trace_manifest:v1",
                "content_hash": format!("sha256:{}", hex::encode(mh.finalize())),
                "byte_len": canonical.len(),
                "component_count": trace.components.len(),
            });
            // v54.1.0 (Codex on PR #1057) — the manifest carries the trace's
            // signed `run_kind` (CC 3.1.5), so the federation-tier mock gate
            // reads it from either shape: without it an oversize local mock
            // trace promoted as a manifest crossed the tier unrefused. Absent
            // when the trace carries none (a pre-CIRISAgent#1249 trace), as in
            // the inline form; a manifest without it is the legacy shape.
            // v56.0.0 (#1089) — copied from wherever the trace signs it:
            // the top level, or `deployment_profile.run_kind` (v2.8.0).
            if let Some(kind) = trace.signed_run_kind() {
                manifest["run_kind"] = serde_json::json!(kind);
            }
            envelope = serde_json::json!({
                "dimension": TRACE_ATTESTATION_DIMENSION,
                "trace_id": trace.trace_id,
                "agent_id_hash": trace.agent_id_hash,
                "manifest": manifest,
            });
        }

        Ok(crate::federation::types::LocalAttestationInput {
            attestation_id: Some(attestation_id),
            attesting_key_id: attesting.clone(),
            attested_key_id: None,
            attestation_type: "scores".to_owned(),
            weight: None,
            expires_at: None,
            attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(envelope)
                .map_err(|e| {
                IngestError::Sign(format!("trace attestation envelope: {e}"))
            })?,
            subject_key_ids: vec![attesting],
            cohort_scope: crate::federation::types::cohort_scope::SELF.to_owned(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        })
    }

    /// Sign post-scrub canonical bytes per component. Returns one
    /// `ScrubEnvelope` per component, in the same flat order as
    /// `compute_pre_scrub_hashes`. THREAT_MODEL.md AV-24.
    async fn sign_scrub_envelopes(
        &self,
        env: &BatchEnvelope,
        pre_hashes: &[String],
        outcome: &crate::scrub::ScrubOutcome,
    ) -> Result<Vec<ScrubEnvelope>, IngestError> {
        use sha2::{Digest as _, Sha256};
        // v61 (CC 2.6.2) — the signed instant is at the millisecond, so
        // the envelope's `scrub_timestamp` is the instant the bytes name.
        let now = crate::federation::admission::truncate_to_substrate_resolution(
            crate::host::clock::now(),
        );
        let key_id = self.signer_key_id.to_owned();
        let mut envelopes = Vec::with_capacity(pre_hashes.len());
        let mut idx = 0usize;
        for event in &env.events {
            match event {
                BatchEvent::CompleteTrace { trace, .. } => {
                    for component in &trace.components {
                        let value = serde_json::Value::Object(component.data.clone());
                        let post_bytes = self
                            .canonicalizer
                            .canonicalize_value(&value)
                            .map_err(IngestError::Verify)?;
                        // v32.0.0 (#690) — the signature covers the ENVELOPE now,
                        // not the payload alone. The content is still bound, via
                        // its hash inside the preimage; what is new is that the
                        // statements ABOUT the content are bound with it.
                        let post_sha = hex::encode(Sha256::digest(&post_bytes));
                        let preimage = scrub_preimage(
                            &post_sha,
                            &pre_hashes[idx],
                            outcome.ner_ran,
                            &outcome.applied_trace_level,
                            outcome.scrubber_model_digest.as_deref(),
                            &key_id,
                            now,
                        );
                        let sig_bytes = self
                            .signer
                            .sign(&preimage)
                            .await
                            .map_err(|e| IngestError::Sign(format!("{e}")))?;
                        envelopes.push(ScrubEnvelope {
                            original_content_hash: pre_hashes[idx].clone(),
                            scrub_signature: BASE64.encode(&sig_bytes),
                            scrub_key_id: key_id.clone(),
                            scrub_timestamp: now,
                            ner_ran: outcome.ner_ran,
                            trace_level: outcome.applied_trace_level.clone(),
                            scrubber_model_digest: outcome.scrubber_model_digest.clone(),
                        });
                        idx += 1;
                    }
                }
            }
        }
        Ok(envelopes)
    }

    /// v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — resolve (and cache)
    /// the verified writer's [`CallerAdmission`](crate::scope::CallerAdmission)
    /// for the write-path cohort_scope gate.
    ///
    /// The writer's occurrence key is `signer` (the `scrub_key_id` — the
    /// Ed25519-verified deployment key). Resolution mirrors the read-side
    /// [`build_caller_admission`](crate::scope::build_caller_admission)
    /// but through the `Backend` admission fan-out methods (the ingest
    /// pipeline holds no `Engine`):
    ///
    /// 1. `signer → identity` via `resolve_identity_for_occurrence`
    ///    (singleton fallback: unbound occurrence IS its own identity,
    ///    FSD §4.4).
    /// 2. `identity → family_key_ids` / `community_key_ids` via the
    ///    `admission_*_key_ids` fan-out.
    ///
    /// Cached per batch on the signer string; same signer signs every
    /// component, so at most one resolution per batch.
    async fn writer_admission<'c>(
        &self,
        cache: &'c mut Option<(String, crate::scope::CallerAdmission)>,
        signer: &str,
    ) -> Result<&'c crate::scope::CallerAdmission, IngestError> {
        let needs_build = !matches!(cache, Some((k, _)) if k == signer);
        if needs_build {
            // THE PRINCIPAL FOLD (v38.3.0, #765): occurrence axis, then the
            // live owner-binding axis — a node's occurrence is
            // self-referential (#454), so without the second axis a
            // node-signed ingest exercised NO memberships. One spelling,
            // shared with the community write gate and AV-84.
            let identity =
                crate::federation::admission::admission_identity_for_writer(self.backend, signer)
                    .await
                    .map_err(|e| {
                        IngestError::Store(StoreError::Backend(format!("writer principal: {e}")))
                    })?;
            let families = self
                .backend
                .admission_family_key_ids(&identity)
                .await
                .map_err(IngestError::Store)?;
            let communities = self
                .backend
                .admission_community_key_ids(&identity)
                .await
                .map_err(IngestError::Store)?;
            let admission = crate::scope::CallerAdmission::from_resolved(
                signer.to_owned(),
                identity,
                families,
                communities,
            );
            *cache = Some((signer.to_owned(), admission));
        }
        // Safe: just populated above when the key didn't match.
        Ok(&cache.as_ref().expect("writer admission populated").1)
    }
}

/// v62.0.0 — the plane name a trace refusal carries (the `plane` of the
/// shared earlier-form refusals, [`crate::federation::edition2::door::refuse_earlier_form`]
/// and [`crate::federation::edition2::projection::refuse_edition2_signer`]).
pub const TRACE_PLANE: &str = "trace";

/// A federation refusal at the trace door as the ingest error it surfaces
/// as. A named refusal ([`crate::federation::Error::MalformedRow`]) keeps its
/// own token (`earlier_form_object`, `kid_not_of_iss`, ...) as
/// [`IngestError::TraceRefused`]'s `kind`; any other refusal keeps its
/// `kind()` token (`federation_trace_dimension_invalid`, the retryable
/// `federation_attester_key_unknown`, ...). Python `ValueError`,
/// `(kind, detail)`; lens HTTP 422. A directory or backend fault
/// (`federation_backend`, `federation_ops_proxy_unsupported`) is a store
/// error (`RuntimeError`, 5xx), never a refusal of the trace.
fn trace_refusal(e: crate::federation::Error) -> IngestError {
    match e {
        crate::federation::Error::MalformedRow {
            reason, message, ..
        } => IngestError::TraceRefused {
            kind: reason,
            detail: message,
        },
        e @ (crate::federation::Error::Backend(_)
        | crate::federation::Error::Unsupported { .. }) => {
            IngestError::Store(StoreError::Backend(format!("trace door: {e}")))
        }
        other => IngestError::TraceRefused {
            kind: other.kind(),
            detail: other.to_string(),
        },
    }
}

/// v62.0.0 (CC 2.6.1.12, RULINGS "composite signatures only") — **the
/// earlier-form gate of the trace door.** A trace that arrives with no
/// statement (the bound-hybrid form, or classical-only) is refused
/// `earlier_form_object` ([`crate::federation::edition2::door::refuse_earlier_form`],
/// the one switch every door reads) before any key read or verify. It is the
/// whole of `Engine.verify_trace`, the dry run, and of ingest's
/// [`VerifyMode::Full`] step for such a trace. v62.0.0 (F0-cp5b): the
/// bound-hybrid verify behind it (`verify_trace_hybrid`, the `pqc_key_id`
/// read, the #225 / #789 refusals) and the edition-2-signer arm are deleted;
/// with the doors shut neither was reachable.
///
/// # Errors
/// [`IngestError::TraceRefused`] with the token.
pub(crate) fn refuse_earlier_form_trace() -> Result<(), IngestError> {
    crate::federation::edition2::door::refuse_earlier_form(TRACE_PLANE).map_err(trace_refusal)
}

/// v62.0.0 (wave P7; CC 3.1.5) — the family id a trace row's header names
/// (-70002): the registry prefix `trace:{form}:{version}` with each `{name}`
/// written `.name`. The row's `dimension` (`trace:complete:v1`) resolves to it.
pub const TRACE_FAMILY_ID: &str = "trace:.form:.version";

/// v62.0.0 — the row type of a trace row (header -70001).
pub const TRACE_ROW_TYPE: &str = "scores";

/// v62.0.0 — the dimension of the canonical trace leaf.
pub const TRACE_COMPLETE_DIMENSION: &str = "trace:complete:v1";

/// v62.0.0 — the media type a trace blob is stored under.
pub const TRACE_BLOB_MEDIA_TYPE: &str = "application/json";

/// v62.0.0 — the earlier form's signature members. A forward trace blob
/// carries none of them (CC ruling: the row's statement signs the manifest
/// and `content_hash` binds the blob).
pub const TRACE_SIGNATURE_MEMBERS: [&str; 5] = [
    "signature",
    "signature_key_id",
    "signature_ml_dsa_65",
    "pubkey_ml_dsa_65",
    "pqc_key_id",
];

/// v62.0.0 — refusal: the batch event's `statement` or `trace_blob` is not
/// base64; the statement is not a `COSE_Sign1` trace row (header family
/// `trace:.form:.version`, row type `scores`) or is not admitted as a row; an
/// event carries a statement without its `trace_blob`, or both a
/// `trace_blob` and an inline `trace`; or the blob is not a JSON object.
pub const TRACE_STATEMENT_INVALID: &str = "trace_statement_invalid";

/// v62.0.0 — refusal: the row does not commit to the blob beside it: the
/// SHA-256 of the blob's bytes AS RECEIVED is not `manifest.content_hash` /
/// in `evidence_refs`, its length is not `byte_len`, or a payload member
/// (`dimension`, `trace_id`, `agent_id_hash`, `asserted_at`, `cohort_scope`,
/// the cohort target, `component_count`, `run_kind`) disagrees with the
/// blob's trace.
pub const TRACE_STATEMENT_CONTENT_MISMATCH: &str = "trace_statement_content_mismatch";

/// v62.0.0 — refusal: a forward trace blob carries a signature member of its
/// own ([`TRACE_SIGNATURE_MEMBERS`]); the row's statement is its only
/// signature.
pub const TRACE_BLOB_CARRIES_SIGNATURE: &str = "trace_blob_carries_signature";

/// v62.0.0 (P7-fix6; CC 3.1.5, `signer_kind.tsv` `trace:{form}:{version}` =
/// agent / agent_own, key_roles R4: the agent key signs agent-only uses and
/// nothing else signs them) — refusal: a `trace:complete:v1` row whose
/// signer's live key is not an agent's (its `identity_type` set lacks
/// `agent`, or names a person). A fault in the row and its signer's key
/// plane, so a refusal by name, never a hold.
pub const TRACE_SIGNER_NOT_AGENT: &str = "trace_signer_not_agent";

/// v62.0.0 (P7-fix6) — refusal at the PRODUCER: `Engine::seal_trace` found no
/// agent-kind signer among the keys it holds (or the named one is not one of
/// them, or is not an agent's). Never a silent fallback to the host's key.
pub const TRACE_AGENT_SIGNER_NOT_HELD: &str = "trace_agent_signer_not_held";

/// v62.0.0 (P7-fix6) — refusal at the PRODUCER: the Engine holds MORE than
/// one agent-kind signer and the caller named none (`Engine::seal_trace_as`).
pub const TRACE_AGENT_SIGNER_AMBIGUOUS: &str = "trace_agent_signer_ambiguous";

/// v62.0.0 (P7-fix6; CC ruling (a)) — **the trace family's signer kind**:
/// the signer's comma-joined `identity_type` names `agent` and no person
/// (`user`). The ONE predicate the attestation door
/// ([`check_trace_signer_kind`]), the batch pre-check
/// ([`admit_trace_statement`]) and the producer's signer selection
/// (`Engine::seal_trace`) read.
#[must_use]
pub fn trace_signer_is_agent(identity_type: &str) -> bool {
    use crate::federation::types::identity_type::AGENT;
    identity_type.split(',').any(|t| t.trim() == AGENT)
        && !crate::federation::steward_purge::identity_type_is_person(identity_type)
}

/// v62.0.0 (P7-fix6) — **the attestation door's trace signer rule**: a row
/// of the trace families (`trace:*`, `trace_summary:*`: CC 3.1.5,
/// `signer_kind.tsv` attest / withdraw = agent / agent_own), named by
/// `family` (the row's family token in either form,
/// [`crate::federation::admission::trace_family_token`]), is admitted only
/// from a signer [`trace_signer_is_agent`]. Every other row passes.
/// `identity_type` is the set the door resolved for the signer (its live
/// edition-2 `key:record` for a statement-carrying row).
///
/// # Errors
/// [`TRACE_SIGNER_NOT_AGENT`] as a named `federation_malformed_row` on plane
/// [`TRACE_PLANE`].
pub fn check_trace_signer_kind(
    family: Option<&str>,
    signer: &str,
    identity_type: &str,
) -> Result<(), crate::federation::Error> {
    use crate::federation::admission::{TRACE_DIMENSION_PREFIX, TRACE_SUMMARY_DIMENSION_PREFIX};
    let Some(family) = family.filter(|f| {
        f.starts_with(TRACE_DIMENSION_PREFIX) || f.starts_with(TRACE_SUMMARY_DIMENSION_PREFIX)
    }) else {
        return Ok(());
    };
    if trace_signer_is_agent(identity_type) {
        return Ok(());
    }
    Err(crate::federation::Error::malformed_row(
        TRACE_PLANE,
        TRACE_SIGNER_NOT_AGENT,
        format!(
            "{family} is authored by its agent (CC 3.1.5, key_roles R4): signer {signer} is \
             identity_type {identity_type:?}, not an agent's key"
        ),
    ))
}

/// v62.0.0 (CC ruling, the lead's relay) — refusal: a `trace:*` row with no
/// edition-2 statement (an unsigned or earlier-form trace kept local-tier by
/// `VerifyMode::TrustPreVerified` ingest) offered to the mesh. Such a trace
/// stays local: CC lets a trace keep its own form only while nothing on the
/// mesh verifies it. Only a trace with its `trace:complete:v1` statement
/// crosses.
pub const TRACE_UNSIGNED_LOCAL_ONLY: &str = "trace_unsigned_local_only";

fn trace_statement_refused(kind: &'static str, detail: String) -> IngestError {
    IngestError::TraceRefused { kind, detail }
}

/// v62.0.0 — **a producer's convenience, never a reader's step**: the RFC
/// 8785 JCS of a trace JSON object less [`TRACE_SIGNATURE_MEMBERS`]. It does
/// NOT scrub: persist's own producer calls it only on the scrubber's output
/// ([`scrubbed_trace_blob`]). CC leaves the
/// blob's encoding to the producer; a reader hashes the bytes it receives and
/// never re-canonicalises, so ingest never calls this.
///
/// # Errors
/// [`TRACE_STATEMENT_INVALID`] when `trace` is not a JSON object; the
/// canonicalizer's error.
pub fn canonical_trace_blob(trace: &serde_json::Value) -> Result<Vec<u8>, IngestError> {
    let Some(obj) = trace.as_object() else {
        return Err(trace_statement_refused(
            TRACE_STATEMENT_INVALID,
            "a trace is a JSON object".to_owned(),
        ));
    };
    let mut content = obj.clone();
    for member in TRACE_SIGNATURE_MEMBERS {
        content.remove(member);
    }
    crate::verify::canonical::JcsCanonicalizer
        .canonicalize_value(&serde_json::Value::Object(content))
        .map_err(IngestError::Verify)
}

/// Decode a base64 batch member: standard, or URL-safe (padded or not).
fn decode_b64_member(member: &str, b64: &str) -> Result<Vec<u8>, IngestError> {
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    let t = b64.trim();
    BASE64
        .decode(t)
        .or_else(|_| URL_SAFE_NO_PAD.decode(t))
        .or_else(|_| URL_SAFE.decode(t))
        .map_err(|e| {
            trace_statement_refused(
                TRACE_STATEMENT_INVALID,
                format!("the event's {member} is not base64: {e}"),
            )
        })
}

/// v62.0.0 — a trace blob's bytes parsed as the JSON object they hold,
/// refused when they carry a signature member.
///
/// # Errors
/// [`TRACE_STATEMENT_INVALID`] for bytes that are no JSON object;
/// [`TRACE_BLOB_CARRIES_SIGNATURE`].
pub fn parse_trace_blob(blob: &[u8]) -> Result<serde_json::Value, IngestError> {
    let v: serde_json::Value = serde_json::from_slice(blob).map_err(|e| {
        trace_statement_refused(
            TRACE_STATEMENT_INVALID,
            format!("the trace blob is not JSON: {e}"),
        )
    })?;
    let Some(obj) = v.as_object() else {
        return Err(trace_statement_refused(
            TRACE_STATEMENT_INVALID,
            "the trace blob is not a JSON object".to_owned(),
        ));
    };
    if let Some(m) = TRACE_SIGNATURE_MEMBERS
        .iter()
        .find(|m| obj.contains_key(**m))
    {
        return Err(trace_statement_refused(
            TRACE_BLOB_CARRIES_SIGNATURE,
            format!(
                "the trace blob carries {m:?}: a forward trace is signed by its \
                 trace:complete:v1 statement only"
            ),
        ));
    }
    Ok(v)
}

/// v62.0.0 (wave P7) — refusal: a trace row's cohort and its blob's form
/// disagree. A `self` / `family` trace blob is SEALED (an at-rest envelope,
/// `Engine::seal_trace`), and any other trace blob is plaintext JSON.
pub const TRACE_BLOB_SEAL_MISMATCH: &str = "trace_blob_seal_mismatch";

/// v62.0.0 (wave P7; G0's fold) — HELD reason: a trace row whose blob this
/// node does not hold yet concludes nothing (no `trace_events`); it re-folds
/// when the blob lands (`fold::blob_slot`).
pub const TRACE_BLOB_NOT_HELD: &str = "trace_blob_not_held";

/// v62.0.0 (wave P7; G0's fold) — HELD reason: a SEALED trace blob this node
/// holds but cannot open (no at-rest grant for it: no DEK). The binding and
/// the projection wait; the row re-folds when a grant for the blob lands
/// (`put_at_rest_grant(s)`) or the blob is re-stored.
pub const TRACE_DEK_NOT_HELD: &str = "trace_dek_not_held";

/// Is `blob` a sealed at-rest envelope (its magic prefix)?
#[must_use]
pub fn is_sealed_trace_blob(blob: &[u8]) -> bool {
    blob.starts_with(&crate::federation::at_rest_cascade::AT_REST_ENVELOPE_MAGIC)
}

/// Does `cohort_scope` seal its blobs (`self`, `family`: the floor never
/// records them plaintext)?
pub(crate) fn cohort_seals(cohort_scope: &str) -> bool {
    use crate::federation::types::cohort_scope::CryptoTier;
    crate::federation::StorageFloor::resolved(CryptoTier::Plaintext)
        .check_scope(cohort_scope)
        .is_err()
}

/// v62.0.0 (wave P7) — what [`expand_trace_blobs`] made of a raw batch.
#[derive(Debug, Default)]
pub(crate) struct ExpandedBatch {
    /// The batch with each PLAINTEXT row-form event's blob parsed into its
    /// `trace`, and every SEALED row-form event removed; `None` when nothing
    /// was rewritten.
    pub(crate) rewritten: Option<Vec<u8>>,
    /// Per remaining event: `(statement, blob)` when it is in the row form.
    pub(crate) carried: Vec<Option<(Vec<u8>, Vec<u8>)>>,
    /// The sealed row-form events: `(statement, envelope bytes)`. They carry
    /// no readable trace; the statement door admits each, and its projection
    /// waits for this node's DEK (`trace_dek_not_held`).
    pub(crate) sealed: Vec<(Vec<u8>, Vec<u8>)>,
    /// No event is left for the typed envelope (every event was sealed).
    pub(crate) sealed_only: bool,
}

/// v62.0.0 (wave P7) — the row-form events of a raw batch. Each event with a
/// `statement` must carry its `trace_blob` (base64 of the blob's exact bytes)
/// and no inline `trace`.
/// - A plaintext blob is parsed (no signature members) and put in place as
///   the event's `trace`, so the typed envelope parses as before.
/// - A sealed blob (an at-rest envelope) cannot be read here: the event is
///   taken out of the batch and returned in `sealed`.
///
/// `None` when no event is in the row form (the batch is untouched).
///
/// # Errors
/// [`TRACE_STATEMENT_INVALID`], [`TRACE_BLOB_CARRIES_SIGNATURE`]; a batch
/// that is not JSON as [`IngestError::Schema`].
pub(crate) fn expand_trace_blobs(bytes: &[u8]) -> Result<Option<ExpandedBatch>, IngestError> {
    let mentions = |needle: &[u8]| bytes.windows(needle.len()).any(|w| w == needle);
    if !mentions(b"\"statement\"") && !mentions(b"\"trace_blob\"") {
        return Ok(None);
    }
    let mut raw: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| IngestError::Schema(e.into()))?;
    let Some(events) = raw
        .get_mut("events")
        .and_then(serde_json::Value::as_array_mut)
    else {
        return Ok(None);
    };
    let mut out = ExpandedBatch::default();
    let mut kept: Vec<serde_json::Value> = Vec::with_capacity(events.len());
    let mut any = false;
    for (i, mut event) in std::mem::take(events).into_iter().enumerate() {
        let Some(obj) = event.as_object_mut() else {
            out.carried.push(None);
            kept.push(event);
            continue;
        };
        let statement = obj
            .get("statement")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let blob = obj
            .get("trace_blob")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        match (statement, blob) {
            (None, None) => {
                out.carried.push(None);
                kept.push(event);
            }
            (None, Some(_)) => {
                return Err(trace_statement_refused(
                    TRACE_STATEMENT_INVALID,
                    format!("event {i} carries a trace_blob but no statement"),
                ))
            }
            (Some(_), None) => {
                return Err(trace_statement_refused(
                    TRACE_STATEMENT_INVALID,
                    format!(
                        "event {i} carries a statement but no trace_blob: a trace row's \
                         content travels as the blob's exact bytes"
                    ),
                ))
            }
            (Some(st), Some(b)) => {
                if obj.contains_key("trace") {
                    return Err(trace_statement_refused(
                        TRACE_STATEMENT_INVALID,
                        format!("event {i} carries both a trace_blob and an inline trace"),
                    ));
                }
                let statement = decode_b64_member("statement", &st)?;
                let blob = decode_b64_member("trace_blob", &b)?;
                any = true;
                if is_sealed_trace_blob(&blob) {
                    out.sealed.push((statement, blob));
                    continue;
                }
                let trace = parse_trace_blob(&blob)?;
                obj.remove("trace_blob");
                obj.insert("trace".to_owned(), trace);
                out.carried.push(Some((statement, blob)));
                kept.push(event);
            }
        }
    }
    if !any {
        return Ok(None);
    }
    out.sealed_only = kept.is_empty();
    *events = kept;
    out.rewritten = Some(serde_json::to_vec(&raw).map_err(|e| IngestError::Schema(e.into()))?);
    Ok(Some(out))
}

/// v62.0.0 (wave P7) — **the row half of the content binding**, pure: the
/// statement is a trace row, and its manifest and `evidence_refs` name
/// `blob`, the blob's bytes EXACTLY as received (for a sealed trace, the
/// at-rest envelope). Its cohort and the blob's form agree: a `self` /
/// `family` row names a sealed blob, any other row a plaintext one. Returns
/// `(iss, payload)`.
///
/// # Errors
/// [`TRACE_STATEMENT_INVALID`] for a statement that is no trace row;
/// [`TRACE_STATEMENT_CONTENT_MISMATCH`]; [`TRACE_BLOB_SEAL_MISMATCH`].
pub fn check_trace_row_shape(
    statement: &[u8],
    blob: &[u8],
) -> Result<(String, ciris_verify_core::cde::Value), IngestError> {
    use ciris_verify_core::cde::Value;
    let invalid = |why: &str| trace_statement_refused(TRACE_STATEMENT_INVALID, why.to_owned());
    let (protected, payload) = crate::federation::edition2::liveness::statement_parts(statement)
        .ok_or_else(|| {
            invalid("the statement is not a COSE_Sign1 with a decodable header and payload")
        })?;
    if protected.get_int(-70002).and_then(Value::as_text) != Some(TRACE_FAMILY_ID) {
        return Err(invalid(
            "the statement's family (-70002) is not trace:.form:.version",
        ));
    }
    if protected.get_int(-70001).and_then(Value::as_text) != Some(TRACE_ROW_TYPE) {
        return Err(invalid("the statement's row type (-70001) is not scores"));
    }
    let iss = protected
        .get_int(15)
        .and_then(|claims| claims.get_int(1))
        .and_then(Value::as_text)
        .ok_or_else(|| invalid("the statement carries no iss"))?
        .to_owned();
    let trace_id = payload
        .get_text("trace_id")
        .and_then(Value::as_text)
        .unwrap_or("?")
        .to_owned();
    let mismatch = |member: &str, detail: String| {
        trace_statement_refused(
            TRACE_STATEMENT_CONTENT_MISMATCH,
            format!("trace_id={trace_id} {member}: {detail}"),
        )
    };
    let dimension = payload.get_text("dimension").and_then(Value::as_text);
    if dimension != Some(TRACE_COMPLETE_DIMENSION) {
        return Err(mismatch(
            "dimension",
            format!("{dimension:?}, not {TRACE_COMPLETE_DIMENSION}"),
        ));
    }
    let scope = payload
        .get_text("cohort_scope")
        .and_then(Value::as_text)
        .unwrap_or("federation");
    if cohort_seals(scope) != is_sealed_trace_blob(blob) {
        return Err(trace_statement_refused(
            TRACE_BLOB_SEAL_MISMATCH,
            format!(
                "trace_id={trace_id}: a {scope:?} trace's blob must be {} (a self/family \
                 trace is sealed through Engine::seal_trace)",
                if cohort_seals(scope) {
                    "a sealed at-rest envelope"
                } else {
                    "plaintext"
                }
            ),
        ));
    }
    // The bytes as received: hashed, never re-canonicalised (CC ruling).
    let digest: [u8; 32] = Sha256::digest(blob).into();
    let Some(manifest) = payload.get_text("manifest") else {
        return Err(mismatch("manifest", "absent".to_owned()));
    };
    let m_text = |member: &str| manifest.get_text(member).and_then(Value::as_text);
    let m_uint = |member: &str| manifest.get_text(member).and_then(Value::as_u64);
    if m_text("schema") != Some("trace_manifest:v1") {
        return Err(mismatch(
            "manifest.schema",
            format!("{:?}", m_text("schema")),
        ));
    }
    let want_hash = format!("sha256:{}", hex::encode(digest));
    if m_text("content_hash") != Some(want_hash.as_str()) {
        return Err(mismatch(
            "manifest.content_hash",
            format!(
                "{:?}; the blob's bytes hash to {want_hash}",
                m_text("content_hash")
            ),
        ));
    }
    if m_uint("byte_len") != u64::try_from(blob.len()).ok() {
        return Err(mismatch(
            "manifest.byte_len",
            format!("{:?} vs {}", m_uint("byte_len"), blob.len()),
        ));
    }
    let names_content = payload
        .get_text("evidence_refs")
        .and_then(Value::as_array)
        .is_some_and(|refs| {
            refs.iter().any(|r| match r.as_array() {
                Some([alg, d]) => {
                    alg.as_i64() == Some(-16) && d.as_bytes() == Some(digest.as_slice())
                }
                _ => false,
            })
        });
    if !names_content {
        return Err(mismatch(
            "evidence_refs",
            format!("no [-16, {}] entry", hex::encode(digest)),
        ));
    }
    Ok((iss, payload))
}

/// v62.0.0 (wave P7) — **the trace half of the content binding**, pure: the
/// row's payload members agree with `trace`, the blob's (opened) parse.
///
/// # Errors
/// [`TRACE_STATEMENT_CONTENT_MISMATCH`] naming the first member that
/// disagrees.
pub fn check_trace_row_members(
    payload: &ciris_verify_core::cde::Value,
    trace: &CompleteTrace,
) -> Result<(), IngestError> {
    use ciris_verify_core::cde::Value;
    let mismatch = |member: &str, detail: String| {
        trace_statement_refused(
            TRACE_STATEMENT_CONTENT_MISMATCH,
            format!("trace_id={} {member}: {detail}", trace.trace_id),
        )
    };
    let text = |member: &str| payload.get_text(member).and_then(Value::as_text);
    if text("trace_id") != Some(trace.trace_id.as_str()) {
        return Err(mismatch("trace_id", format!("{:?}", text("trace_id"))));
    }
    if text("agent_id_hash") != Some(trace.agent_id_hash.as_str()) {
        return Err(mismatch(
            "agent_id_hash",
            format!("{:?} vs {}", text("agent_id_hash"), trace.agent_id_hash),
        ));
    }
    let completed_ms = u64::try_from(trace.completed_at.parsed().timestamp_millis()).ok();
    let asserted_at = payload.get_text("asserted_at").and_then(Value::as_u64);
    if asserted_at.is_none() || asserted_at != completed_ms {
        return Err(mismatch(
            "asserted_at",
            format!(
                "{asserted_at:?} is not completed_at {} in ms",
                trace.completed_at.wire()
            ),
        ));
    }
    let scope = text("cohort_scope").unwrap_or("federation");
    if scope != trace.cohort_scope {
        return Err(mismatch(
            "cohort_scope",
            format!("{scope} vs the trace's {}", trace.cohort_scope),
        ));
    }
    let target = text("community_id").or_else(|| text("family_id"));
    if target != trace.cohort_target_id.as_deref() {
        return Err(mismatch(
            "community_id/family_id",
            format!(
                "{target:?} vs cohort_target_id {:?}",
                trace.cohort_target_id
            ),
        ));
    }
    let manifest = payload.get_text("manifest");
    let m_text = |member: &str| {
        manifest
            .and_then(|m| m.get_text(member))
            .and_then(Value::as_text)
    };
    let component_count = manifest
        .and_then(|m| m.get_text("component_count"))
        .and_then(Value::as_u64);
    if component_count != u64::try_from(trace.components.len()).ok() {
        return Err(mismatch(
            "manifest.component_count",
            format!("{component_count:?} vs {}", trace.components.len()),
        ));
    }
    if m_text("run_kind") != trace.signed_run_kind() {
        return Err(mismatch(
            "manifest.run_kind",
            format!("{:?} vs {:?}", m_text("run_kind"), trace.signed_run_kind()),
        ));
    }
    Ok(())
}

/// v62.0.0 (wave P7) — **the content binding of a PLAINTEXT trace**, pure
/// (no key read, no verify; the statement door verifies the same bytes
/// next): [`check_trace_row_shape`] then [`check_trace_row_members`], with
/// `trace` the parse of `blob`. Returns the statement's `iss`.
///
/// # Errors
/// As the two halves.
pub fn check_trace_statement_binding(
    statement: &[u8],
    trace: &CompleteTrace,
    blob: &[u8],
) -> Result<String, IngestError> {
    let (iss, payload) = check_trace_row_shape(statement, blob)?;
    check_trace_row_members(&payload, trace)?;
    Ok(iss)
}

/// v62.0.0 (wave P7; CC 2.6.1, 3.1.5; the rulings "a replicating trace is a
/// forward-form row", "the manifest form is the only form", option A for
/// sealed traces) — **admit a trace's `trace:complete:v1` row and keep its
/// blob.**
///
/// 1. The row half of the binding ([`check_trace_row_shape`], pure); for a
///    plaintext blob also the trace half ([`check_trace_row_members`]
///    against `trace`).
/// 2. The blob's bytes, exactly as received, go to the blob plane under
///    their SHA-256 ([`Backend::store_trace_blob`]; a sealed envelope is
///    stored verbatim at the sealed floor) BEFORE the row, so the row's own
///    write can project from them.
/// 3. **The edition-2 statement door** (`put_statement`, tier `federation`):
///    Verify's reader (the key-of-issuer check), the key plane's liveness at
///    the row's own `asserted_at`, every attestation gate, and the trace
///    projection ([`project_trace_row_from_held_blob`]: the row's
///    `trace_events` in its own write; a sealed blob this node cannot open
///    holds the row `trace_dek_not_held`).
///
/// Returns `(iss, held)`: `held` when the door kept the row concluding
/// nothing (G0's `Pending`).
///
/// # Errors
/// [`TRACE_STATEMENT_INVALID`], [`TRACE_STATEMENT_CONTENT_MISMATCH`],
/// [`TRACE_BLOB_SEAL_MISMATCH`], the door's refusals ([`trace_refusal`]); a
/// blob-plane failure as [`IngestError::Store`].
pub(crate) async fn admit_trace_statement<B>(
    backend: &B,
    trace: Option<&CompleteTrace>,
    statement: &[u8],
    blob: &[u8],
) -> Result<(String, bool), IngestError>
where
    B: Backend + crate::federation::FederationDirectory + ?Sized,
{
    use crate::federation::edition2::ingest::{put_statement, StatementOutcome, INGEST_TIER};
    use ciris_verify_core::cde::Value;
    let (iss, payload) = check_trace_row_shape(statement, blob)?;
    if let Some(t) = trace {
        check_trace_row_members(&payload, t)?;
    }
    // v62.0.0 (P7-fix6) — the signer kind, BEFORE the blob is stored: a row
    // the door will refuse `trace_signer_not_agent` leaves no blob behind.
    // Read from the signer's live `key:record` at the row's own instant; a
    // signer not live there is the door's to name (retryable), so it passes
    // here.
    if let Some(at) = payload.get_text("asserted_at").and_then(Value::as_u64) {
        use crate::federation::edition2::liveness::Liveness;
        let held = crate::federation::edition2::ingest::held_keys_for(backend, statement)
            .await
            .map_err(trace_refusal)?;
        if let Some(kid) = crate::federation::edition2::ingest::statement_kid(statement) {
            if let Liveness::Live(r) = held.liveness(&kid, at) {
                check_trace_signer_kind(
                    Some(TRACE_COMPLETE_DIMENSION),
                    &iss,
                    &r.identity_type.join(","),
                )
                .map_err(trace_refusal)?;
            }
        }
    }
    let text = |member: &str| payload.get_text(member).and_then(Value::as_text);
    let cohort_scope = text("cohort_scope").unwrap_or("federation").to_owned();
    // The group the blob row names: the family, the room, or for a `self`
    // trace its owner, the agent's identity (`iss`).
    let group = text("family_id")
        .or_else(|| text("community_id"))
        .map(str::to_owned)
        .or_else(|| (cohort_scope == "self").then(|| iss.clone()));
    let digest: [u8; 32] = Sha256::digest(blob).into();
    backend
        .store_trace_blob(
            &digest,
            blob.to_vec(),
            &cohort_scope,
            group.as_deref(),
            &iss,
        )
        .await
        .map_err(IngestError::Store)?;
    let outcome = Box::pin(put_statement(backend, statement, None, INGEST_TIER))
        .await
        .map_err(trace_refusal)?;
    match outcome {
        StatementOutcome::Row { .. } | StatementOutcome::Voice { .. } => Ok((iss, false)),
        StatementOutcome::Pending { .. } => Ok((iss, true)),
        StatementOutcome::KeyPlane { .. } => Err(trace_statement_refused(
            TRACE_STATEMENT_INVALID,
            "the statement was admitted as a key-plane statement, not a trace row".to_owned(),
        )),
    }
}

/// v62.0.0 (wave P7) — the blob-plane write of a trace blob lives in
/// [`crate::federation::trace_blob_floor`], the one module I14 admits as a
/// floor caller beside the cascades.
pub(crate) use crate::federation::trace_blob_floor::store_trace_blob_on;

/// v62.0.0 (CC ruling: unsigned ⇒ local, never served) — **the crossing gate
/// for traces**: a `trace:*` / `trace_summary:*` row that carries no edition-2
/// statement never enters the mesh. `crossing::plan_enter_mesh` asks it
/// before anything else, so `Engine::enter_mesh` and every backend's
/// `enter_mesh` refuse such a row by name. A trace crosses only as its
/// `trace:complete:v1` statement, which is federation-tier from its door.
///
/// # Errors
/// [`TRACE_UNSIGNED_LOCAL_ONLY`] (`federation_malformed_row`, plane `trace`).
pub fn refuse_unsigned_trace_crossing(
    row: &crate::federation::types::Attestation,
) -> Result<(), crate::federation::Error> {
    let is_trace = row
        .attestation_envelope
        .get("dimension")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|d| {
            d.starts_with(crate::federation::admission::TRACE_DIMENSION_PREFIX)
                || d.starts_with("trace_summary:")
        });
    let carries_statement = row
        .attestation_envelope
        .get(crate::federation::edition2::ingest::STATEMENT_MEMBER)
        .is_some();
    if is_trace && !carries_statement {
        return Err(crate::federation::Error::malformed_row(
            TRACE_PLANE,
            TRACE_UNSIGNED_LOCAL_ONLY,
            format!(
                "row {} is a trace with no trace:complete:v1 statement: it was kept local \
                 (an unsigned trace stays local while nothing on the mesh verifies it) and \
                 never crosses; offer the agent-signed statement instead",
                row.attestation_id
            ),
        ));
    }
    Ok(())
}

/// v62.0.0 (wave P7; CC 3.1.5) — **the payload of a trace's
/// `trace:complete:v1` row** (the manifest form, the only form; P7.md
/// "Server/lens-core adoption" is its spec). `blob` is the trace blob's
/// exact bytes (no signature members inside); `trace` their typed parse;
/// `iss` the signer's identity-ref (also `author` and the one
/// `subject_key_ids` entry: a trace is self-emitted, CC 3.4.5).
/// [`check_trace_statement_binding`] accepts exactly what this builds.
///
/// # Errors
/// [`TRACE_STATEMENT_INVALID`] for a `completed_at` before the epoch.
pub fn trace_row_payload(
    trace: &CompleteTrace,
    blob: &[u8],
    iss: &str,
) -> Result<ciris_verify_core::cde::Value, IngestError> {
    use ciris_verify_core::cde::Value;
    let digest: [u8; 32] = Sha256::digest(blob).into();
    let asserted_at =
        u64::try_from(trace.completed_at.parsed().timestamp_millis()).map_err(|_| {
            trace_statement_refused(
                TRACE_STATEMENT_INVALID,
                format!(
                    "trace_id={}: completed_at is before the epoch",
                    trace.trace_id
                ),
            )
        })?;
    let t = |s: &str| Value::Text(s.to_owned());
    let mut manifest = vec![
        (t("schema"), t("trace_manifest:v1")),
        (
            t("content_hash"),
            Value::Text(format!("sha256:{}", hex::encode(digest))),
        ),
        (
            t("byte_len"),
            Value::Uint(u64::try_from(blob.len()).unwrap_or(u64::MAX)),
        ),
        (
            t("component_count"),
            Value::Uint(u64::try_from(trace.components.len()).unwrap_or(u64::MAX)),
        ),
    ];
    if let Some(kind) = trace.signed_run_kind() {
        manifest.push((t("run_kind"), t(kind)));
    }
    let mut payload = vec![
        (t("asserted_at"), Value::Uint(asserted_at)),
        (t("author"), t(iss)),
        (t("dimension"), t(TRACE_COMPLETE_DIMENSION)),
        (t("trace_id"), t(&trace.trace_id)),
        (t("agent_id_hash"), t(&trace.agent_id_hash)),
        (t("subject_key_ids"), Value::Array(vec![t(iss)])),
        (
            t("evidence_refs"),
            Value::Array(vec![ciris_verify_core::edition2::hash_digest_value(
                &digest,
            )]),
        ),
        (t("manifest"), Value::Map(manifest)),
    ];
    if trace.cohort_scope != "federation" {
        payload.push((t("cohort_scope"), t(&trace.cohort_scope)));
    }
    if let Some(target) = trace.cohort_target_id.as_deref() {
        let member = if trace.cohort_scope == "family" {
            "family_id"
        } else {
            "community_id"
        };
        payload.push((t(member), t(target)));
    }
    Ok(Value::Map(payload))
}

/// v62.0.0 (wave P7) — what [`seal_trace_row`] returns: the row's
/// `COSE_Sign1` statement and the trace blob it names. Send both as the
/// batch event's `statement` and `trace_blob` (base64), and store and serve
/// `trace_blob` exactly as returned: the row binds these bytes, and only
/// these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedTrace {
    /// The `trace:complete:v1` row statement.
    pub statement: Vec<u8>,
    /// The SCRUBBED trace's bytes (JCS, no signature members).
    pub trace_blob: Vec<u8>,
}

/// v62.0.0 (wave P7; "the substrate absorbs complexity") — **the only bytes a
/// sealed trace blob can hold**: `trace` less [`TRACE_SIGNATURE_MEMBERS`],
/// run through persist's own scrubber
/// ([`crate::pipeline::scrub::scrub_trace`]) at `level`, then JCS. Nothing
/// unscrubbed reaches the hash: the scrubber's output is the only input to
/// the canonicaliser. A trace that states a `trace_level` other than `level`
/// is refused, so a trace cannot be sealed under a lighter scrub than its own
/// label.
///
/// # Errors
/// [`TRACE_STATEMENT_INVALID`] (not an object; a `trace_level` mismatch);
/// the scrubber's refusal under its own token (`scrub_ner_not_configured`
/// for `full_traces` without NER, `scrub_year_residue`, ...).
#[cfg(feature = "scrub")]
pub fn scrubbed_trace_blob(
    trace: &serde_json::Value,
    level: TraceLevel,
) -> Result<Vec<u8>, IngestError> {
    let Some(obj) = trace.as_object() else {
        return Err(trace_statement_refused(
            TRACE_STATEMENT_INVALID,
            "a trace is a JSON object".to_owned(),
        ));
    };
    if let Some(stated) = obj.get("trace_level") {
        if stated.as_str() != Some(level.as_str()) {
            return Err(trace_statement_refused(
                TRACE_STATEMENT_INVALID,
                format!(
                    "the trace states trace_level {stated}, but is sealed at {}",
                    level.as_str()
                ),
            ));
        }
    }
    let mut content = obj.clone();
    for member in TRACE_SIGNATURE_MEMBERS {
        content.remove(member);
    }
    let scrubbed = crate::pipeline::scrub::scrub_trace(serde_json::Value::Object(content), level)
        .map_err(|e| {
        trace_statement_refused(e.kind(), format!("seal: scrub at {}: {e}", level.as_str()))
    })?;
    canonical_trace_blob(&scrubbed.value)
}

/// v62.0.0 (wave P7) — [`seal_trace_row`] up to the signature, pure: the
/// scrubbed blob ([`scrubbed_trace_blob`]) and the row payload over it
/// ([`trace_row_payload`]) for `iss`. A producer that signs elsewhere signs
/// `payload` as a `scores` row of family [`TRACE_FAMILY_ID`] with `sub` =
/// `iss`.
///
/// # Errors
/// As [`scrubbed_trace_blob`]; [`IngestError::Schema`] for a scrubbed trace
/// that is no `CompleteTrace`; [`trace_row_payload`]'s.
#[cfg(feature = "scrub")]
pub fn prepare_trace_row(
    trace: &serde_json::Value,
    level: TraceLevel,
    iss: &str,
) -> Result<(Vec<u8>, ciris_verify_core::cde::Value), IngestError> {
    let blob = scrubbed_trace_blob(trace, level)?;
    let parsed: CompleteTrace =
        serde_json::from_slice(&blob).map_err(|e| IngestError::Schema(e.into()))?;
    // Option A: a self/family trace is sealed before it is signed, which
    // needs the node's DEK machinery: only `Engine::seal_trace` does that.
    if cohort_seals(&parsed.cohort_scope) {
        return Err(trace_statement_refused(
            TRACE_BLOB_SEAL_MISMATCH,
            format!(
                "trace_id={}: a {:?} trace is sealed through Engine::seal_trace \
                 (Engine.seal_trace_statement), never signed over plaintext",
                parsed.trace_id, parsed.cohort_scope
            ),
        ));
    }
    let payload = trace_row_payload(&parsed, &blob, iss)?;
    Ok((blob, payload))
}

/// v62.0.0 (wave P7) — **persist's trace producer**: scrub `trace` at
/// `level` with persist's own scrubber, then seal the SCRUBBED bytes as the
/// trace's `trace:complete:v1` row, signed once by `signer`'s composite key
/// ([`crate::federation::edition2::produce::sign_row`]; `iss` = `sub` = the
/// signer's own identity-ref). It is structurally impossible to seal an
/// unscrubbed trace through it: the only bytes hashed and returned are the
/// scrubber's output ([`prepare_trace_row`]).
///
/// `iss` is the signer key's own identity-ref: an agent signing with a
/// rotated key (whose `iss` is its genesis key) is not served here.
///
/// # Errors
/// [`prepare_trace_row`]'s; [`IngestError::Sign`] when the signer has no
/// composite (no PQC half) or a half fails.
#[cfg(feature = "scrub")]
pub async fn seal_trace_row(
    signer: &crate::signing::LocalSigner,
    trace: &serde_json::Value,
    level: TraceLevel,
) -> Result<SealedTrace, IngestError> {
    let (_, iss) = crate::federation::edition2::produce::signer_identity(signer)
        .await
        .map_err(|e| IngestError::Sign(format!("trace row signer: {e}")))?;
    let (trace_blob, payload) = prepare_trace_row(trace, level, &iss)?;
    let statement = crate::federation::edition2::produce::sign_row(
        signer,
        &iss,
        TRACE_ROW_TYPE,
        TRACE_FAMILY_ID,
        &payload,
    )
    .await
    .map_err(|e| IngestError::Sign(format!("trace row: {e}")))?;
    Ok(SealedTrace {
        statement,
        trace_blob,
    })
}

/// v62.0.0 (wave P7) — the inline bytes of the blob `sha256` if this node
/// holds it (a trace blob is stored inline), `None` otherwise.
///
/// # Errors
/// A blob-plane read failure, as `federation_backend`.
pub(crate) async fn held_inline_blob<T>(
    store: &T,
    sha256: &[u8; 32],
) -> Result<Option<Vec<u8>>, crate::federation::Error>
where
    T: crate::federation::BlobStorage + Sync,
{
    match store
        .get_blob(sha256)
        .await
        .map_err(|e| crate::federation::Error::Backend(format!("trace blob read: {e}")))?
    {
        Some(crate::federation::BlobBody::Inline(bytes)) => Ok(Some(bytes)),
        _ => Ok(None),
    }
}

/// v62.0.0 (wave P7) — what this node can read of a trace blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TraceBlobOpen {
    /// Not held here (yet).
    NotHeld,
    /// Held; `stored` is the bytes as held (hashed by the row), `plaintext`
    /// the trace JSON (equal to `stored` for a plaintext blob).
    Open {
        /// The bytes as stored and served.
        stored: Vec<u8>,
        /// The trace JSON.
        plaintext: Vec<u8>,
    },
    /// Held, sealed, and this node holds no grant to open it.
    NoDek(String),
}

/// v62.0.0 (wave P7) — **open a trace blob as this node**, shared by the
/// sqlite and postgres `AttestationStore::open_trace_blob` impls. A sealed
/// blob opens through the one viewer read
/// (`at_rest_cascade::orchestrate::read_any_for_viewer`) as this node's own
/// key (`node_key_id`); `NotGranted` (no at-rest grant: no DEK) and a node
/// with no key are [`TraceBlobOpen::NoDek`].
///
/// # Errors
/// A blob-plane read failure other than a missing grant.
pub(crate) async fn open_trace_blob_on<T>(
    store: &T,
    sha256: &[u8; 32],
) -> Result<TraceBlobOpen, crate::federation::Error>
where
    T: crate::federation::BlobStorage + crate::federation::FederationDirectory + Sync,
{
    let Some(stored) = held_inline_blob(store, sha256).await? else {
        return Ok(TraceBlobOpen::NotHeld);
    };
    if !is_sealed_trace_blob(&stored) {
        return Ok(TraceBlobOpen::Open {
            plaintext: stored.clone(),
            stored,
        });
    }
    let Some(viewer) = crate::federation::FederationDirectory::node_key_id(store) else {
        return Ok(TraceBlobOpen::NoDek(
            "this node has no key to open a sealed trace blob as".to_owned(),
        ));
    };
    match crate::federation::at_rest_cascade::orchestrate::read_any_for_viewer(
        store, sha256, &viewer, None,
    )
    .await
    {
        Ok(plaintext) => Ok(TraceBlobOpen::Open { stored, plaintext }),
        Err(e @ crate::federation::BlobError::NotGranted { .. }) => {
            Ok(TraceBlobOpen::NoDek(e.to_string()))
        }
        Err(e) => Err(crate::federation::Error::Backend(format!(
            "sealed trace blob open: {e}"
        ))),
    }
}

/// The blob digest a stored trace row names (`evidence_refs[0]`, in the
/// payload's `[-16, hex]` form or as 64 hex).
fn trace_row_digest(envelope: &serde_json::Value) -> Option<[u8; 32]> {
    let first = envelope.get("evidence_refs")?.as_array()?.first()?;
    let text = match first {
        serde_json::Value::String(s) => s.as_str(),
        serde_json::Value::Array(a) if a.len() == 2 && a[0].as_i64() == Some(-16) => {
            a[1].as_str()?
        }
        _ => return None,
    };
    <[u8; 32]>::try_from(hex::decode(text).ok()?.as_slice()).ok()
}

/// v62.0.0 (wave P7) — **a trace row's `trace_events`, from its blob**, pure:
/// the row half of the binding over `stored` (the bytes the row names), the
/// opened `plaintext` parsed (no signature members), the trace half against
/// it, the signer set to the row's attester, then the SAME
/// [`crate::store::decompose::decompose`] the ingest path runs.
///
/// # Errors
/// The binding's refusal as a named `federation_malformed_row` on plane
/// `trace`.
fn trace_projection_of(
    statement: &[u8],
    stored: &[u8],
    plaintext: &[u8],
    signer: &str,
) -> Result<crate::store::decompose::Decomposed, crate::federation::Error> {
    let named = |e: IngestError| match e {
        IngestError::TraceRefused { kind, detail } => {
            crate::federation::Error::malformed_row(TRACE_PLANE, kind, detail)
        }
        other => crate::federation::Error::malformed_row(
            TRACE_PLANE,
            TRACE_STATEMENT_INVALID,
            other.to_string(),
        ),
    };
    let (_, payload) = check_trace_row_shape(statement, stored).map_err(named)?;
    let raw = parse_trace_blob(plaintext).map_err(named)?;
    let mut trace: CompleteTrace = serde_json::from_value(raw).map_err(|e| {
        crate::federation::Error::malformed_row(
            TRACE_PLANE,
            TRACE_STATEMENT_INVALID,
            format!("the trace blob is no CompleteTrace: {e}"),
        )
    })?;
    check_trace_row_members(&payload, &trace).map_err(named)?;
    trace.signature_key_id = signer.to_owned();
    crate::store::decompose::decompose(&trace).map_err(|e| {
        crate::federation::Error::malformed_row(
            TRACE_PLANE,
            TRACE_STATEMENT_INVALID,
            format!("the trace blob does not decompose: {e}"),
        )
    })
}

/// v62.0.0 (wave P7; G0's fold, option A) — **the trace projection at the
/// attestation door**, inside the row's fold attempt (every edition-2 row
/// door: the local statement door, `apply_replicated_statement`, tier
/// ingest, and G0's re-fold).
///
/// - The blob is held and opens: the binding is checked HERE, before the
///   write (a blob that does not bind refuses the row by name), and the
///   row's `trace_events` are inserted in its own write.
/// - The blob is not held: the row is HELD `trace_blob_not_held`, reading
///   `fold::blob_slot(sha)`; it re-folds when the blob lands
///   ([`refold_trace_blob`]).
/// - The blob is sealed and this node holds no grant for it: the row is HELD
///   `trace_dek_not_held`, reading the same slot; it re-folds when a grant
///   for the blob lands (`put_at_rest_grant(s)` re-fold the slot).
///
/// Never admitted with a warning: a held row concludes nothing until it
/// re-folds.
///
/// # Errors
/// The binding's refusal; the hold (G0 keeps the voice); a read failure.
pub(crate) async fn project_trace_row_from_held_blob<D>(
    dir: &D,
    row: &crate::federation::types::Attestation,
) -> Result<Option<crate::store::decompose::Decomposed>, crate::federation::Error>
where
    D: crate::federation::attestation_admit::AttestationStore,
{
    use crate::federation::edition2::fold;
    let env = &row.attestation_envelope;
    if env.get("dimension").and_then(serde_json::Value::as_str) != Some(TRACE_COMPLETE_DIMENSION) {
        return Ok(None);
    }
    let Some(statement_hex) = env
        .get(crate::federation::edition2::ingest::STATEMENT_MEMBER)
        .and_then(serde_json::Value::as_str)
    else {
        return Ok(None);
    };
    let Some(sha) = trace_row_digest(env) else {
        return Ok(None);
    };
    let statement = hex::decode(statement_hex).map_err(|e| {
        crate::federation::Error::malformed_row(
            TRACE_PLANE,
            TRACE_STATEMENT_INVALID,
            format!("the row's statement is not hex: {e}"),
        )
    })?;
    fold::reads(fold::Dep::key(&fold::blob_slot(&sha)));
    match dir.open_trace_blob(&sha).await? {
        TraceBlobOpen::Open { stored, plaintext } => {
            trace_projection_of(&statement, &stored, &plaintext, &row.attesting_key_id).map(Some)
        }
        TraceBlobOpen::NotHeld => Err(fold::hold(
            TRACE_BLOB_NOT_HELD,
            crate::federation::Error::malformed_row(
                TRACE_PLANE,
                TRACE_BLOB_NOT_HELD,
                format!(
                    "trace row {}: its blob {} is not held here yet",
                    row.attestation_id,
                    hex::encode(sha)
                ),
            ),
        )),
        TraceBlobOpen::NoDek(why) => Err(fold::hold(
            TRACE_DEK_NOT_HELD,
            crate::federation::Error::malformed_row(
                TRACE_PLANE,
                TRACE_DEK_NOT_HELD,
                format!(
                    "trace row {}: its sealed blob {} does not open here: {why}",
                    row.attestation_id,
                    hex::encode(sha)
                ),
            ),
        )),
    }
}

/// v62.0.0 (wave P7; G0's fold) — **a trace blob's bytes or keys changed
/// here**: re-fold every row that read its slot (`fold::blob_slot(sha)`): a
/// trace row held `trace_blob_not_held` or `trace_dek_not_held` concludes
/// now, in its own write, with its `trace_events`. Called after a trace blob
/// lands on any blob door (`store_trace_blob`, `put_blob`,
/// `store_plaintext_local`, `adopt_sealed_blob`) and after an at-rest grant
/// lands (`put_at_rest_grant(s)`). A re-fold failure never fails the write
/// that called it: it is logged by name, and `refold_all` repairs.
pub(crate) async fn refold_trace_blob<F>(dir: &F, sha256: &[u8; 32])
where
    F: crate::federation::FederationDirectory + ?Sized,
{
    use crate::federation::edition2::fold;
    let touched: std::collections::BTreeSet<String> =
        std::iter::once(fold::Dep::key(&fold::blob_slot(sha256)).read_key()).collect();
    if let Err(e) = fold::isolated(fold::refold_touched(dir, touched)).await {
        tracing::warn!(
            sha256 = %hex::encode(sha256),
            reason = %e.kind(),
            error = %e,
            "ciris-persist: re-fold on a trace blob's slot failed (refold_all repairs)"
        );
    }
}

/// v62.0.0 (wave P7) — the batch with each statement-carrying trace's
/// `signature_key_id` set to the `iss` its admitted row names (the verified
/// signer), so step 2b's tombstone check, the write-scope gate and the
/// projection rows read the signer the door checked.
fn with_statement_signers(mut env: BatchEnvelope, signers: &[Option<String>]) -> BatchEnvelope {
    for (event, signer) in env.events.iter_mut().zip(signers) {
        if let (BatchEvent::CompleteTrace { trace, .. }, Some(iss)) = (event, signer) {
            trace.signature_key_id.clone_from(iss);
        }
    }
    env
}

#[cfg(all(test, any(feature = "sqlite", feature = "postgres")))]
mod trace_statement_invariants;

/// v62.0.0 (P7-fix8; the adopters' ask) — test-anchor helpers: sign a
/// trace's edition-2 row under an agent key and admit it through the real
/// door. Never in a production build; re-exported from `prelude`.
#[cfg(any(test, feature = "test-anchor"))]
pub mod trace_anchor;

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;
    use crate::schema::SchemaVersion;
    use crate::scrub::NullScrubber;
    use crate::store::{decompose, SqliteBackend};
    use crate::verify::PythonJsonDumpsCanonicalizer;
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use ed25519_dalek::{Signer, SigningKey};

    /// Build a deterministic Ed25519 software signer for tests.
    /// Per the user's "use the direct trait" call: returns
    /// `Box<dyn HardwareSigner>` directly, no wrapper. The seed is
    /// fixed so test runs are reproducible.
    async fn make_test_signer() -> (Box<dyn HardwareSigner>, String) {
        use ciris_keyring::Ed25519SoftwareSigner;
        let key_id = "test-scrub-key-v1".to_owned();
        let mut signer = Ed25519SoftwareSigner::new(&key_id);
        // Deterministic 32-byte seed for reproducibility.
        let seed = [0xA5u8; 32];
        signer
            .import_key(&seed)
            .expect("import_key on Ed25519SoftwareSigner");
        (Box::new(signer) as Box<dyn HardwareSigner>, key_id)
    }

    /// v7.2.0 (CIRISPersist#225) — hybrid-sign a trace's canonical bytes
    /// for the test fixtures, so they satisfy the Full-mode hybrid hard
    /// cut. Produces the Ed25519 sig (over `canonical`) plus the
    /// producer's ML-DSA-65 half (the `verify_hybrid` bound input
    /// `canonical || ed25519_sig`) and the asserted ML-DSA-65 pubkey.
    /// Mutates `trace` in place: sets `signature`, `signature_ml_dsa_65`,
    /// `pubkey_ml_dsa_65`, `pqc_key_id`. Deterministic seeds.
    async fn hybrid_sign_trace(trace: &mut CompleteTrace, ed_sk: &SigningKey) {
        use ciris_keyring::PqcSigner;
        let canonical =
            crate::verify::ed25519::canonical_bytes_for_trace(trace, &PythonJsonDumpsCanonicalizer)
                .expect("canonicalize for hybrid test signing");

        // Classical half.
        let ed_sig = ed_sk.sign(&canonical);
        let ed_sig_bytes = ed_sig.to_bytes();

        // PQC half over the bound input (canonical || classical_sig).
        let mldsa =
            ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[0x77; 32], "test-mldsa")
                .expect("ml-dsa seed");
        let mut bound = Vec::with_capacity(canonical.len() + ed_sig_bytes.len());
        bound.extend_from_slice(&canonical);
        bound.extend_from_slice(&ed_sig_bytes);
        let pqc_sig = mldsa.sign(&bound).await.expect("ml-dsa sign");
        let pqc_pk = mldsa.public_key().await.expect("ml-dsa pk");

        trace.signature = BASE64.encode(ed_sig_bytes);
        trace.signature_ml_dsa_65 = Some(BASE64.encode(&pqc_sig));
        trace.pubkey_ml_dsa_65 = Some(BASE64.encode(&pqc_pk));
        trace.pqc_key_id = Some("test-mldsa".to_owned());
    }

    /// CIRISPersist#789 — put the producer's ML-DSA-65 key in the directory.
    ///
    /// Since #789, admission resolves the PQC pubkey from `federation_keys` by
    /// `pqc_key_id` and refuses when it is absent — the payload's own copy is
    /// no longer trusted, because a key the submitter nominates proves nothing
    /// about who they are. The fleet is 100% PQC, so a registered PQC key is
    /// the normal state of the world and a fixture without one was modelling a
    /// world that does not exist.
    ///
    /// Deterministic seed, matching the signer the trace fixtures use.
    async fn seed_test_pqc_key(backend: &SqliteBackend) {
        use ciris_keyring::PqcSigner;
        let mldsa =
            ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(&[0x77; 32], "test-mldsa")
                .expect("ml-dsa seed");
        let pk = mldsa.public_key().await.expect("ml-dsa pk");
        backend.add_pqc_public_key("test-mldsa", &BASE64.encode(&pk));
    }

    async fn make_signed_batch_bytes() -> (Vec<u8>, String, ed25519_dalek::VerifyingKey) {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let key_id = "ciris-agent-key:test";

        let mut trace = CompleteTrace {
            trace_id: "trace-pipeline-1".into(),
            thought_id: "th-1".into(),
            task_id: Some("task-1".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123456Z".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789012Z".parse().unwrap(),
            trace_level: crate::schema::TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![
                crate::schema::TraceComponent {
                    component_type: crate::schema::ComponentType::Observation,
                    event_type: crate::schema::ReasoningEventType::ThoughtStart,
                    timestamp: "2026-04-30T00:15:53.123Z".parse().unwrap(),
                    data: {
                        let mut m = serde_json::Map::new();
                        m.insert("attempt_index".into(), 0.into());
                        m
                    },
                    agent_id_hash: None,
                },
                crate::schema::TraceComponent {
                    component_type: crate::schema::ComponentType::Action,
                    event_type: crate::schema::ReasoningEventType::ActionResult,
                    timestamp: "2026-04-30T00:16:12.789Z".parse().unwrap(),
                    data: {
                        let mut m = serde_json::Map::new();
                        m.insert("attempt_index".into(), 0.into());
                        m.insert("audit_sequence_number".into(), 42.into());
                        m.insert("audit_entry_hash".into(), "abcd".into());
                        m.insert("audit_signature".into(), "BBBB".into());
                        m.insert("llm_calls".into(), 0.into());
                        m.insert("tokens_total".into(), 100.into());
                        m.insert("cost_cents".into(), serde_json::json!(0.1));
                        m
                    },
                    agent_id_hash: None,
                },
            ],
            deployment_profile: None,
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: String::new(),
            signature_key_id: key_id.into(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
            run_kind: None,
        };
        // v7.2.0 (#225) — hybrid-sign so the Full-mode hard cut admits.
        hybrid_sign_trace(&mut trace, &sk).await;

        let trace_json = serde_json::to_value(&trace).unwrap();
        let envelope = serde_json::json!({
            "events": [{
                "event_type": "complete_trace",
                "trace_level": "generic",
                "trace": trace_json,
            }],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0",
        });
        (
            envelope.to_string().into_bytes(),
            key_id.to_owned(),
            sk.verifying_key(),
        )
    }

    /// v4.0 (CIRISPersist#160) — sign a one-component batch carrying a
    /// producer-declared `(cohort_scope, cohort_target_id)`. Because
    /// cohort_scope is NOT in the signed canonical allowlist
    /// (`canonical_payload_value`), the same Ed25519 signature verifies
    /// regardless of the cohort values — proving the canonical-bytes
    /// invariant end-to-end through the ingest path.
    async fn make_signed_batch_bytes_with_cohort(
        cohort_scope: &str,
        cohort_target_id: Option<&str>,
    ) -> (Vec<u8>, String, ed25519_dalek::VerifyingKey) {
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let key_id = "ciris-agent-key:test";

        let mut trace = CompleteTrace {
            trace_id: "trace-cohort-1".into(),
            thought_id: "th-1".into(),
            task_id: None,
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123456Z".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789012Z".parse().unwrap(),
            trace_level: crate::schema::TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![crate::schema::TraceComponent {
                component_type: crate::schema::ComponentType::Observation,
                event_type: crate::schema::ReasoningEventType::ThoughtStart,
                timestamp: "2026-04-30T00:15:53.123Z".parse().unwrap(),
                data: {
                    let mut m = serde_json::Map::new();
                    m.insert("attempt_index".into(), 0.into());
                    m
                },
                agent_id_hash: None,
            }],
            deployment_profile: None,
            cohort_scope: cohort_scope.to_owned(),
            cohort_target_id: cohort_target_id.map(str::to_owned),
            signature: String::new(),
            signature_key_id: key_id.into(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
            run_kind: None,
        };
        // Sign over the canonical allowlist — cohort fields excluded.
        // v7.2.0 (#225) — hybrid-sign so the Full-mode hard cut admits;
        // the cohort fields are still outside the signed canonical, so
        // both halves verify regardless of the cohort values.
        hybrid_sign_trace(&mut trace, &sk).await;

        let trace_json = serde_json::to_value(&trace).unwrap();
        let envelope = serde_json::json!({
            "events": [{
                "event_type": "complete_trace",
                "trace_level": "generic",
                "trace": trace_json,
            }],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0",
        });
        (
            envelope.to_string().into_bytes(),
            key_id.to_owned(),
            sk.verifying_key(),
        )
    }

    /// v4.0 (CIRISPersist#160, FSD §4.3 + §4.6) — a `community`-scoped
    /// trace whose writer IS a member of the named community lands with
    /// that exact (cohort_scope, cohort_target_id) on every row. The
    /// Commit-F write-gate passes (membership held); the substrate
    /// records the producer's target verbatim.
    #[tokio::test]
    async fn cohort_community_target_round_trips() {
        let (bytes, key_id, vkey) =
            make_signed_batch_bytes_with_cohort("community", Some("community-key:lens-alpha"))
                .await;
        let backend = crate::store::test_backend::test_backend();
        backend.add_public_key(&key_id, vkey);
        seed_test_pqc_key(&backend).await;

        let (signer, signer_key_id) = make_test_signer().await;
        // FSD §4.6 — make the verified WRITER (the signer; unbound, so
        // identity == occurrence == signer_key_id) a member of the named
        // community so the write-gate admits the row.
        backend.add_community_membership("community-key:lens-alpha", &[signer_key_id.as_str()]);
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        let summary = pipeline.receive_and_persist(&bytes).await.unwrap();
        assert_eq!(summary.signatures_verified, 1, "signature still verifies");

        let snap = backend.snapshot_events();
        assert!(!snap.is_empty());
        for row in &snap {
            assert_eq!(row.cohort_scope, "community");
            assert_eq!(
                row.cohort_target_id.as_deref(),
                Some("community-key:lens-alpha"),
                "producer-supplied community target is recorded verbatim"
            );
        }
    }

    /// v62.0.0 (wave GC2; lead ruling on row 35, CC 2.7.3) — I3716: a
    /// writer that stamps `cohort_scope: community` for a community it is NOT
    /// a member of is no longer refused by the BATCH door: "not a member"
    /// reads the roster (other rows), and the trace's edition-2 row
    /// (`trace:complete:v1` through `put_statement`) is its concluded form,
    /// where the fold decides it. (Was v4.0's AV-45 batch refusal, #160.)
    /// The roster is HELD here (the community exists with another member),
    /// so this is the terminal "not a member" case, not the retryable
    /// `MembershipUnresolved` wait, which still refuses. Sqlite and postgres.
    async fn i3716_body<D>(d: &D)
    where
        D: Backend + crate::federation::FederationDirectory + Sync,
    {
        let comm = format!("i3716-not-mine-{}", uuid::Uuid::new_v4().simple());
        crate::federation::doors_takedown_invariants::bodies::community_of(
            d.as_dyn_directory(),
            &comm,
            "i3716-someone-else",
        )
        .await;
        assert!(
            crate::federation::FederationDirectory::lookup_community(d, &comm)
                .await
                .unwrap()
                .is_some(),
            "I3716 precondition: the roster is held (not the unresolved wait)"
        );
        let (bytes, _key_id, _vkey) =
            make_signed_batch_bytes_with_cohort("community", Some(&comm)).await;
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: d,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        // I3716: no batch-door write-scope refusal for "not a member".
        if let Err(IngestError::ScopeRefused(r)) = pipeline
            .receive_and_persist_with(&bytes, VerifyMode::TrustPreVerified)
            .await
        {
            panic!("I3716: the batch door refused on membership: {r:?}");
        }
    }

    #[tokio::test]
    async fn i3716_batch_door_does_not_refuse_a_non_member_community_sqlite() {
        let backend = crate::store::test_backend::test_backend();
        Box::pin(i3716_body(&backend)).await;
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i3716_batch_door_does_not_refuse_a_non_member_community_postgres() {
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Box::pin(i3716_body(&b)).await;
    }

    /// v47.0.0 (CIRISPersist#797) — a trace naming a community whose roster
    /// this node does NOT HOLD is refused (fail-secure, zero writes) as
    /// `MembershipUnresolved`: retryable, the roster may not have arrived.
    /// Same split as the attestation put door (I147).
    #[tokio::test]
    async fn write_gate_unresolved_roster_is_retryable_797() {
        let (bytes, key_id, vkey) =
            make_signed_batch_bytes_with_cohort("community", Some("community-key:unseen")).await;
        let backend = crate::store::test_backend::test_backend();
        backend.add_public_key(&key_id, vkey);
        seed_test_pqc_key(&backend).await;
        let (signer, signer_key_id) = make_test_signer().await;
        backend.add_community_membership("community-key:mine", &[signer_key_id.as_str()]);
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        let err = pipeline.receive_and_persist(&bytes).await.unwrap_err();
        assert!(
            matches!(
                err,
                IngestError::ScopeRefused(crate::scope::ScopeRefusalReason::MembershipUnresolved)
            ),
            "an absent roster is unresolved, not 'not a member': {err:?}"
        );
        assert_eq!(err.kind(), "write_scope_refused");
        assert_eq!(err.detail().as_deref(), Some("scope_membership_unresolved"));
        assert!(
            backend.snapshot_events().is_empty(),
            "fail-secure: an unresolved membership still writes nothing"
        );
    }

    /// v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — AV-45 write-gate
    /// pass case: a verified writer that IS a member of the claimed
    /// community persists normally (companion to the refusal test).
    #[tokio::test]
    async fn write_gate_admits_member_community_persists() {
        let (bytes, key_id, vkey) =
            make_signed_batch_bytes_with_cohort("community", Some("community-key:mine")).await;
        let backend = crate::store::test_backend::test_backend();
        backend.add_public_key(&key_id, vkey);
        seed_test_pqc_key(&backend).await;

        let (signer, signer_key_id) = make_test_signer().await;
        backend.add_community_membership("community-key:mine", &[signer_key_id.as_str()]);
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        let summary = pipeline.receive_and_persist(&bytes).await.unwrap();
        assert_eq!(summary.signatures_verified, 1);
        let snap = backend.snapshot_events();
        assert!(
            !snap.is_empty(),
            "member-claimed community row must persist"
        );
        for row in &snap {
            assert_eq!(row.cohort_scope, "community");
            assert_eq!(row.cohort_target_id.as_deref(), Some("community-key:mine"));
        }
    }

    /// v4.0 (CIRISPersist#160, FSD §4.4 / §12.0 item 1) — a `self`-scoped
    /// trace's target is RESOLVED FROM THE VERIFIED SIGNER, not trusted
    /// from the caller. Here the scrub signer key is not bound as an
    /// IdentityOccurrence, so the singleton-identity fallback applies:
    /// the substrate stamps the signer key itself as the owner identity.
    /// Critically, a caller-supplied bogus self-target is OVERWRITTEN.
    #[tokio::test]
    async fn cohort_self_target_resolved_from_signer_singleton() {
        // Caller tries to claim someone else's identity as the self
        // target — the substrate must ignore it and stamp the signer.
        let (bytes, key_id, vkey) =
            make_signed_batch_bytes_with_cohort("self", Some("victim-identity-forged")).await;
        let backend = crate::store::test_backend::test_backend();
        backend.add_public_key(&key_id, vkey);
        seed_test_pqc_key(&backend).await;

        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        pipeline.receive_and_persist(&bytes).await.unwrap();

        let snap = backend.snapshot_events();
        assert!(!snap.is_empty());
        for row in &snap {
            assert_eq!(row.cohort_scope, "self");
            // Resolved from the verified signer (the scrub_key_id),
            // NOT the caller-supplied "victim-identity-forged".
            assert_eq!(
                row.cohort_target_id.as_deref(),
                Some(signer_key_id.as_str()),
                "self-target must be resolved from the verified signer (singleton fallback), \
                 never trusting the caller-supplied value"
            );
            assert_ne!(
                row.cohort_target_id.as_deref(),
                Some("victim-identity-forged"),
                "caller-supplied self-target must be overwritten"
            );
            // The signer is the scrub envelope's key — the verified
            // deployment key.
            assert_eq!(row.scrub_key_id.as_deref(), Some(signer_key_id.as_str()));
        }
    }

    /// v4.0 (CIRISPersist#160, FSD §12.0 item 1) — BACKWARD-COMPAT: a
    /// trace that carries NO cohort fields (every current producer)
    /// lands as 'federation' / NULL, preserving pre-v4.0 behavior.
    #[tokio::test]
    async fn cohort_absent_defaults_to_federation() {
        // make_signed_batch_bytes builds a federation/None trace whose
        // JSON omits the cohort keys (skip_serializing_if).
        let (bytes, key_id, vkey) = make_signed_batch_bytes().await;
        // Confirm the wire body really has no cohort keys.
        let body = String::from_utf8(bytes.clone()).unwrap();
        assert!(
            !body.contains("cohort_scope") && !body.contains("cohort_target_id"),
            "fixture must omit cohort fields on the wire"
        );

        let backend = crate::store::test_backend::test_backend();
        backend.add_public_key(&key_id, vkey);
        seed_test_pqc_key(&backend).await;
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        pipeline.receive_and_persist(&bytes).await.unwrap();

        let snap = backend.snapshot_events();
        assert!(!snap.is_empty());
        for row in &snap {
            assert_eq!(
                row.cohort_scope, "federation",
                "absent cohort_scope lands as the federation default"
            );
            assert_eq!(
                row.cohort_target_id, None,
                "absent cohort_target_id lands as NULL"
            );
        }
    }

    #[tokio::test]
    async fn happy_path_full_pipeline() {
        // Mission category §4: end-to-end across schema + verify +
        // scrub (null) + decompose + backend (memory). Every layer
        // must succeed with mission-aligned outcome counts.
        let (bytes, key_id, vkey) = make_signed_batch_bytes().await;
        let backend = crate::store::test_backend::test_backend();
        backend.add_public_key(&key_id, vkey);
        seed_test_pqc_key(&backend).await;

        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        let summary = pipeline
            .receive_and_persist(&bytes)
            .await
            .expect("happy path must succeed");

        assert_eq!(summary.envelopes_processed, 1);
        assert_eq!(summary.signatures_verified, 1);
        assert_eq!(
            summary.trace_events_inserted, 2,
            "two components → two rows"
        );
        assert_eq!(summary.trace_events_conflicted, 0);
        assert_eq!(summary.trace_llm_calls_inserted, 0);
        assert_eq!(summary.scrubbed_fields, 0);

        // Snapshot: ACTION_RESULT row carries the audit anchor (FSD §3.2).
        let snap = backend.snapshot_events();
        let action = snap
            .iter()
            .find(|e| e.event_type == crate::schema::ReasoningEventType::ActionResult)
            .unwrap();
        assert_eq!(action.cost_llm_calls, Some(0));
        assert_eq!(action.cost_tokens, Some(100));

        // THREAT_MODEL.md AV-24 regression: every row carries a
        // populated scrub envelope. Always present; key never null.
        for row in &snap {
            assert!(
                row.original_content_hash.is_some(),
                "every v0.1.3+ row populates original_content_hash"
            );
            assert!(row.scrub_signature.is_some(), "scrub_signature populated");
            assert_eq!(
                row.scrub_key_id.as_deref(),
                Some(signer_key_id.as_str()),
                "scrub_key_id matches the signer's id"
            );
            assert!(row.scrub_timestamp.is_some(), "scrub_timestamp populated");
            // CIRISPersist#91 — Full-mode rows attribute authenticity
            // to persist's own `verify_trace`.
            assert!(row.signature_verified, "Full-mode row is verified");
            assert_eq!(
                row.verification_source,
                crate::store::VerificationSource::Persist,
                "Full-mode rows attribute authenticity to persist"
            );
        }

        // THREAT_MODEL.md AV-24 verification: ed25519_verify the first row's
        // scrub_signature against the signer's public key — proving a peer with
        // the published public key can verify the deployment's attestation.
        //
        // v17.7.0 (#470 arc, crypto-DRY closure) — strict-verify through the
        // canonical `ciris_crypto::Ed25519Verifier::verify_strict` (v10.4.0)
        // instead of reaching for `ed25519_dalek` directly: ONE Ed25519
        // acceptance rule in the repo, not two.
        //
        // v32.0.0 (CIRISPersist#690) — **the preimage is rebuilt from the
        // STORED ROW**, not from the envelope the pipeline just handed us.
        //
        // That distinction is the entire value of this test, and it is what
        // caught the defect this version fixes. #690 widened the preimage from
        // `canonical(post_scrub)` to the whole envelope, and initially shipped
        // WITHOUT the three treatment columns — so `scrub_signature` covered
        // three values that were persisted nowhere. It verified once, at
        // signing time, and was unverifiable by anyone forever after: strictly
        // worse than the ambiguity #690 set out to remove.
        //
        // A test that rebuilt the preimage from the in-memory envelope would
        // have passed throughout, because the envelope holds fields the row
        // does not. Reading only what a peer can read is what makes this an
        // instrument rather than a restatement.
        let pubkey_bytes = signer.public_key().await.expect("signer.public_key");

        let row0 = &snap[0];
        let payload_value = serde_json::Value::Object(row0.payload.clone());
        let canonical = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload_value)
            .unwrap();
        let post_sha = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(&canonical));

        // Every component of the preimage comes off the row. If any of these is
        // `None`, this `expect` fires and names the column — which is the
        // failure mode worth having, because the alternative is a signature
        // that silently cannot be checked.
        let preimage = scrub_preimage(
            &post_sha,
            row0.original_content_hash
                .as_deref()
                .expect("original_content_hash persisted"),
            row0.scrub_ner_ran
                .expect("scrub_ner_ran persisted — it is inside the signature preimage"),
            row0.scrub_applied_trace_level
                .as_deref()
                .expect("scrub_applied_trace_level persisted — inside the preimage"),
            row0.scrub_model_digest.as_deref(),
            row0.scrub_key_id
                .as_deref()
                .expect("scrub_key_id persisted"),
            row0.scrub_timestamp.expect("scrub_timestamp persisted"),
        );

        let sig_b64 = row0.scrub_signature.as_ref().unwrap();
        let sig_bytes = BASE64.decode(sig_b64).expect("base64 decode");
        let verified = ciris_crypto::Ed25519Verifier
            .verify_strict(&pubkey_bytes, &preimage, &sig_bytes)
            .expect("verify_strict parse");
        assert!(
            verified,
            "scrub_signature must verify against a preimage rebuilt ENTIRELY \
             from persisted columns — if it does not, some field of the \
             preimage is not being stored and no peer can ever check this \
             signature"
        );

        // And the treatment claims are the ones the pipeline actually made,
        // not defaults that happen to hash correctly. This batch is `generic`,
        // which by design carries no content text (TRACE_WIRE_FORMAT.md §7), so
        // the honest triple is "treated at generic, no NER pass, no model" —
        // and the #690 door does not refuse it, because the label and the
        // treatment agree.
        assert_eq!(
            row0.scrub_applied_trace_level.as_deref(),
            Some("generic"),
            "the level TREATED is persisted, and for a generic batch that is \
             `generic` — not the pipeline's default and not the label of some \
             other batch"
        );
        assert_eq!(
            row0.scrub_ner_ran,
            Some(false),
            "Some(false) — a CLAIM that no pass ran, which is not the same as \
             None (a pre-v32.0.0 row that made no claim at all). Collapsing \
             those two is how an unscrubbed row would read as attested"
        );
        assert!(
            row0.scrub_model_digest.is_none(),
            "no model ran, so none may be named"
        );
    }

    /// **CIRISPersist#705 / CIRISServer#418 — the record keeps what the wire
    /// does not.**
    ///
    /// #690 scrubbed inside `receive_and_persist`, which is how an agent
    /// captures ITS OWN traces — so the original was redacted before it was
    /// ever stored and the unscrubbed record existed nowhere. Server wired a
    /// real scrubber, watched self-scoped content change under it, reverted,
    /// and held their pin.
    ///
    /// The privacy boundary is not ingest. `trace_events` is a LOCAL
    /// projection (`Projection::TraceEvents` — derived on a receiver from an
    /// admitted attestation) and is never replicated; the ATTESTATION embeds
    /// the whole trace and is the wire object. So the stored rows come from the
    /// original envelope and the attestation is minted from a scrubbed copy.
    ///
    /// **The assertion is the DISAGREEMENT between them.** Checking only the
    /// row would pass on a no-op scrubber; checking only the attestation would
    /// pass on the old both-scrubbed behaviour. Only the pair distinguishes
    /// this fix from either.
    #[tokio::test]
    async fn the_record_keeps_what_the_wire_does_not_705() {
        const MARKER: &str = "SECRET-MARKER-705";

        /// Redacts the marker and honestly claims a pass, so the #690
        /// publication gate is satisfied and this test isolates WHERE the
        /// scrub lands rather than whether the gate fires.
        struct MarkerScrubber;
        impl crate::scrub::Scrubber for MarkerScrubber {
            fn scrub_batch(
                &self,
                env: &mut BatchEnvelope,
            ) -> Result<crate::scrub::ScrubOutcome, crate::scrub::ScrubError> {
                let mut n = 0usize;
                for event in &mut env.events {
                    // `BatchEvent` is single-variant today; an `else` arm
                    // would be unreachable, so this destructures directly and
                    // will fail to compile if a variant is ever added — which
                    // is the right prompt to decide what a scrubber does with it.
                    let BatchEvent::CompleteTrace { trace, .. } = event;
                    for c in &mut trace.components {
                        // Stamps a sentinel instead of redacting a planted one:
                        // planting would require re-signing the fixture, and the
                        // property under test is "the copy differs from the
                        // record", which a stamp witnesses exactly as well.
                        c.data
                            .insert(MARKER.to_owned(), serde_json::Value::Bool(true));
                        n += 1;
                    }
                }
                let lvl = env.trace_level.as_str().to_owned();
                Ok(crate::scrub::ScrubOutcome {
                    fields_modified: n,
                    ner_ran: true,
                    applied_trace_level: lvl,
                    scrubber_model_digest: Some("test-model-705".to_owned()),
                })
            }
        }

        let (bytes, key_id, vkey) = make_signed_batch_bytes().await;
        let backend = crate::store::test_backend::test_backend();
        backend.add_public_key(&key_id, vkey);
        seed_test_pqc_key(&backend).await;
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &MarkerScrubber,
            signer: signer.as_ref(),
            signer_key_id: &signer_key_id,
        };
        pipeline
            .receive_and_persist(&bytes)
            .await
            .expect("ingest succeeds");

        // THE RECORD: the stored row still carries the marker. This is the node's
        // own capture and must retain full fidelity.
        let rows = backend.snapshot_events();
        let stored = serde_json::to_string(&rows).expect("serialize rows");
        assert!(
            !stored.contains(MARKER),
            "the STORED row must be the UNTOUCHED original — if the scrubber's \
             mark is here, ingest is still redacting the node's own record, \
             which is exactly what CIRISServer#418 reverted over"
        );

        // THE WIRE: the minted attestation does not.
        // The mint lands local-tier; this is the only reader for it, and it is
        // the same one `promote_consented_backlog` walks before publishing.
        let atts = {
            use crate::federation::FederationDirectory as _;
            backend
                .list_local_tier_attestations(None, 64)
                .await
                .expect("list local-tier attestations")
        };
        let published = serde_json::to_string(&atts).expect("serialize attestations");
        assert!(
            !published.is_empty(),
            "a trace attestation must be minted, or this test proves nothing"
        );
        assert!(
            published.contains(MARKER),
            "the ATTESTATION is the wire object and must carry the SCRUBBED \
             copy — if the scrubber's mark is absent here, nothing was \
             scrubbed on the way out and unredacted content ships to federation"
        );
    }

    #[tokio::test]
    async fn idempotent_replay() {
        // Mission category §4 "Idempotency": replaying the same batch
        // bytes results in 0 inserts + N conflicts the second time.
        let (bytes, key_id, vkey) = make_signed_batch_bytes().await;
        let backend = crate::store::test_backend::test_backend();
        backend.add_public_key(&key_id, vkey);
        seed_test_pqc_key(&backend).await;

        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        let s1 = pipeline.receive_and_persist(&bytes).await.unwrap();
        assert_eq!(s1.trace_events_inserted, 2);
        let s2 = pipeline.receive_and_persist(&bytes).await.unwrap();
        assert_eq!(s2.trace_events_inserted, 0);
        assert_eq!(s2.trace_events_conflicted, 2);
    }

    /// v18.0.0 (CIRISPersist#473) — ENVELOPE-NATIVE witness: an ingested
    /// trace's canonical home is a local-tier `scores` attestation, visible
    /// through the REALIZED consumer read (`list_scores`, tier=Local), with
    /// a deterministic id making replays idempotent.
    #[tokio::test]
    async fn envelope_native_trace_mints_scores_attestation_and_replays_idempotently() {
        use crate::federation::FederationDirectory as _;
        let (bytes, key_id, vkey) = make_signed_batch_bytes().await;
        let backend = crate::store::test_backend::test_backend();
        backend.add_public_key(&key_id, vkey);
        seed_test_pqc_key(&backend).await;

        // NOTE: memory's `add_public_key` seeds BOTH the legacy verify
        // store AND a minimal federation_keys row — the mint's FK holds.

        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        // First ingest: events land AND the attestation mints.
        let s1 = pipeline.receive_and_persist(&bytes).await.unwrap();
        assert_eq!(s1.trace_attestations_minted, 1, "one trace, one mint");
        assert_eq!(s1.trace_attestations_skipped, 0);

        // The realized consumer read: list_scores, tier=Local, exact dimension.
        let filter: crate::read::AttestationFilter = serde_json::from_value(serde_json::json!({
            "dimension_exact": TRACE_ATTESTATION_DIMENSION,
            "tier": "Local",
        }))
        .unwrap();
        let page = backend
            .list_scores(&key_id, filter.clone(), None, 10)
            .await
            .expect("list_scores");
        assert_eq!(page.items.len(), 1, "the trace IS a scores attestation");
        let att = &page.items[0];
        assert_eq!(att.attesting_key_id, key_id);
        assert_eq!(
            att.subject_key_ids,
            vec![key_id.clone()],
            "self-subject (#461)"
        );
        assert_eq!(
            att.attestation_envelope
                .get("dimension")
                .and_then(|v| v.as_str()),
            Some(TRACE_ATTESTATION_DIMENSION)
        );
        assert!(
            att.attestation_envelope.get("trace").is_some(),
            "small trace rides WHOLE (inline envelope, no manifest)"
        );
        let minted_id = att.attestation_id.clone();

        // Replay: same bytes → same deterministic id → still exactly ONE row.
        let s2 = pipeline.receive_and_persist(&bytes).await.unwrap();
        assert_eq!(
            s2.trace_events_inserted, 0,
            "events dedup (pre-18 behavior)"
        );
        assert_eq!(s2.trace_attestations_minted, 1, "mint is replay-idempotent");
        let page2 = backend
            .list_scores(&key_id, filter, None, 10)
            .await
            .unwrap();
        assert_eq!(page2.items.len(), 1, "NO duplicate attestation on replay");
        assert_eq!(
            page2.items[0].attestation_id, minted_id,
            "same deterministic id"
        );
    }

    // v62 (E4, wave 5): `replicated_trace_attestation_materializes_scorer_corpus_501`
    // is DELETED. It re-signed a minted trace attestation under the agent's
    // Ed25519-only trace key and replicated it as an earlier-form row; in v62
    // every key is composite and no classical-only key exists (RULINGS,
    // "Composite signatures only"), and a trace is one composite statement
    // (CC trace ruling; P7 builds the composite trace ingest). Rewrite it as
    // a composite trace replication once P7 publishes.

    /// v18.0.0 (#473) — an UNREGISTERED producer (the relay
    /// `TrustPreVerified` shape) skips the mint with honest accounting;
    /// the projection rows still land.
    #[tokio::test]
    async fn envelope_native_mint_skips_honestly_when_producer_unregistered() {
        let (bytes, _key_id, _vkey) = make_signed_batch_bytes().await;
        let backend = crate::store::test_backend::test_backend();
        // NO key registered anywhere — the true relay shape: authenticity was
        // established upstream (TrustPreVerified skips the lookup), and the
        // producer has not yet federated to THIS node's directory.

        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        let s = pipeline
            .receive_and_persist_with(&bytes, VerifyMode::TrustPreVerified)
            .await
            .unwrap();
        assert!(s.trace_events_inserted > 0, "projection rows still land");
        assert_eq!(s.trace_attestations_minted, 0);
        assert_eq!(s.trace_attestations_skipped, 1, "honest skip accounting");
    }

    #[tokio::test]
    async fn malformed_json_is_typed_error() {
        let backend = crate::store::test_backend::test_backend();
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        let err = pipeline
            .receive_and_persist(b"{not valid json")
            .await
            .unwrap_err();
        assert!(matches!(err, IngestError::Schema(_)));
    }

    #[tokio::test]
    async fn schema_version_mismatch_rejected() {
        // FSD §3.4 robustness primitive #3.
        let body = serde_json::json!({
            "events": [],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "9.9.9"
        });
        let backend = crate::store::test_backend::test_backend();
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        let err = pipeline
            .receive_and_persist(body.to_string().as_bytes())
            .await
            .unwrap_err();
        match err {
            IngestError::Schema(SchemaError::UnsupportedSchemaVersion { got, .. }) => {
                assert_eq!(got, "9.9.9");
            }
            other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
        }
    }

    /// v2.0 (CIRISPersist#91) — `VerifyMode::TrustPreVerified` skips
    /// step 2's signature verification (and its directory lookup):
    /// the batch persists even though NO public key is registered for
    /// the trace's `signature_key_id`. In `Full` mode that same batch
    /// is rejected `UnknownKey` (asserted at the end), so a clean
    /// persist here proves the `lookup_public_key` was bypassed.
    #[tokio::test]
    async fn skip_verify_persists_without_directory_lookup() {
        let (bytes, key_id, _vkey) = make_signed_batch_bytes().await;
        let backend = crate::store::test_backend::test_backend();
        // Intentionally register NO public key: a `Full`-mode ingest
        // would fail at step 2 with `UnknownKey`.

        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        let summary = pipeline
            .receive_and_persist_with(&bytes, VerifyMode::TrustPreVerified)
            .await
            .expect("skip-verify ingest persists without a registered key");

        // Every non-verify step still ran: schema parse → scrub →
        // decompose → store, same row counts as the happy path.
        assert_eq!(summary.envelopes_processed, 1);
        assert_eq!(
            summary.trace_events_inserted, 2,
            "two components → two rows"
        );
        assert_eq!(summary.trace_events_conflicted, 0);
        // Persist verified zero signatures itself.
        assert_eq!(summary.signatures_verified, 0);

        // Honest row state (CIRISPersist#91): the trace IS authentic
        // (`signature_verified == true`), and `verification_source`
        // records that an upstream Edge verifier — not persist —
        // established that authenticity.
        let snap = backend.snapshot_events();
        assert_eq!(snap.len(), 2);
        for row in &snap {
            assert!(
                row.signature_verified,
                "the trace is authentic — signature_verified stays true"
            );
            assert_eq!(
                row.verification_source,
                crate::store::VerificationSource::Edge,
                "skip-verify rows attribute authenticity to Edge"
            );
            // Other steps unchanged — scrub envelope still populated.
            assert!(row.original_content_hash.is_some());
            assert!(row.scrub_signature.is_some());
        }

        // Control: the SAME batch in `Full` mode is rejected because
        // no key is registered — proving skip-mode genuinely bypassed
        // the directory lookup rather than the key being optional.
        let err = pipeline
            .receive_and_persist_with(&bytes, VerifyMode::Full)
            .await
            .unwrap_err();
        match err {
            IngestError::Verify(VerifyError::UnknownKey(id)) => assert_eq!(id, key_id),
            other => panic!("expected UnknownKey in Full mode, got {other:?}"),
        }
    }

    /// v0.4.6 (CIRISPersist#22) — decompose's schema-layer rejects
    /// MUST surface as `IngestError::Schema` (lens 422), not
    /// `IngestError::Store` (lens 503 + Retry-After). Pre-fix the
    /// blanket `map_err(IngestError::Store)` triggered hot agent
    /// retry loops on deterministic schema mismatches — agents saw
    /// 503+Retry-After and hammered the lens forever. The fix
    /// preserves the variant via a typed `match` on `store::Error`.
    #[tokio::test]
    async fn decompose_schema_error_routes_to_schema_variant() {
        // Build a 2.7.9 trace that parses cleanly + verifies + then
        // fails at decompose because `data.attempt_index` is missing
        // on a component (2.7.9 strict gate). Note: deployment_profile
        // is required by BatchEnvelope::from_json at 2.7.9.
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let key_id = "ciris-agent-key:test-22";

        let mut trace = CompleteTrace {
            trace_id: "trace-22-schema-route".into(),
            thought_id: "th-1".into(),
            task_id: None,
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123456Z".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789012Z".parse().unwrap(),
            trace_level: crate::schema::TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.9").unwrap(),
            components: vec![crate::schema::TraceComponent {
                component_type: crate::schema::ComponentType::Observation,
                event_type: crate::schema::ReasoningEventType::ThoughtStart,
                timestamp: "2026-04-30T00:15:53.123Z".parse().unwrap(),
                // Empty data → no attempt_index → 2.7.9 strict gate fires.
                data: serde_json::Map::new(),
                // 2.7.9 requires per-component agent_id_hash locked-equal
                // to the envelope.
                agent_id_hash: Some("deadbeef".into()),
            }],
            // 2.7.9 envelope gate requires deployment_profile.
            deployment_profile: Some(crate::schema::DeploymentProfile {
                agent_role: "ally".into(),
                agent_template: "ally-v3-default".into(),
                deployment_domain: "moderation".into(),
                deployment_type: "production".into(),
                deployment_region: Some("US".into()),
                deployment_trust_mode: "federated_peer".into(),
                run_kind: None,
                trace_format_version: None,
                calibration_version: None,
                pipeline_metadata: None,
            }),
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: String::new(),
            signature_key_id: key_id.into(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
            run_kind: None,
        };
        // Hybrid-sign the 2.7.9 canonical (per-component agent_id_hash
        // included; deployment_profile in the envelope alpha-position).
        // v7.2.0 (#225): MUST be hybrid so it passes the Full-mode hard
        // cut and reaches decompose — proving the schema reject lands at
        // decompose, strictly AFTER the verify gate (ordering invariant).
        hybrid_sign_trace(&mut trace, &sk).await;

        let trace_json = serde_json::to_value(&trace).unwrap();
        let envelope = serde_json::json!({
            "events": [{
                "event_type": "complete_trace",
                "trace_level": "generic",
                "trace": trace_json,
            }],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.9",
        });

        let backend = crate::store::test_backend::test_backend();
        backend.add_public_key(key_id, sk.verifying_key());
        seed_test_pqc_key(&backend).await;
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        let err = pipeline
            .receive_and_persist(envelope.to_string().as_bytes())
            .await
            .unwrap_err();

        // The whole point of the fix: this must be Schema, NOT Store.
        match err {
            IngestError::Schema(SchemaError::MissingField("attempt_index")) => {}
            IngestError::Store(_) => panic!(
                "REGRESSION (CIRISPersist#22): decompose schema reject \
                 misclassified as Store — would trigger 503+Retry-After \
                 hot retry loop on a deterministic 4xx mismatch"
            ),
            other => panic!("expected Schema(MissingField(attempt_index)), got {other:?}"),
        }

        // Backend received zero rows — the schema reject must short-circuit
        // before any insert.
        assert!(backend.snapshot_events().is_empty());
    }

    /// v0.4.6 (CIRISPersist#22) — `IngestError::detail()` surfaces the
    /// dynamic field name for `MissingField`. Lens consumers read
    /// `e.args[1]` (or `e.detail()` on the Rust side) instead of
    /// source-diving persist to find which field was missing.
    #[test]
    fn ingest_error_detail_surfaces_missing_field_name() {
        let e = IngestError::Schema(SchemaError::MissingField("attempt_index"));
        assert_eq!(e.kind(), "schema_missing_field");
        assert_eq!(e.detail(), Some("attempt_index".to_string()));

        let e = IngestError::Schema(SchemaError::MissingField("data.parent_event_type"));
        assert_eq!(e.kind(), "schema_missing_field");
        assert_eq!(e.detail(), Some("data.parent_event_type".to_string()));

        // Non-schema variants → None today (verify/scrub/store/sign
        // don't yet expose detail; expanding is a follow-up).
        let e = IngestError::Sign("keyring locked".into());
        assert_eq!(e.kind(), "sign_keyring");
        assert_eq!(e.detail(), None);
    }

    #[tokio::test]
    async fn empty_events_array_rejected() {
        // FSD §3.3 step 1; MISSION.md §3 anti-pattern #7.
        let body = serde_json::json!({
            "events": [],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0"
        });
        let backend = crate::store::test_backend::test_backend();
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        let err = pipeline
            .receive_and_persist(body.to_string().as_bytes())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            IngestError::Schema(SchemaError::MissingField("events"))
        ));
    }

    /// Sanity: pure-function decompose remains the path inside the
    /// pipeline; nothing in ingest mutates the decomposition results.
    #[test]
    fn pipeline_decompose_is_pure() {
        let trace = CompleteTrace {
            trace_id: "t-1".into(),
            thought_id: "th-1".into(),
            task_id: None,
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:00:00Z".parse().unwrap(),
            completed_at: "2026-04-30T00:01:00Z".parse().unwrap(),
            trace_level: crate::schema::TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![],
            deployment_profile: None,
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: "AAAA".into(),
            signature_key_id: "k".into(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
            run_kind: None,
        };
        let d1 = decompose(&trace).unwrap();
        let d2 = decompose(&trace).unwrap();
        assert_eq!(d1, d2);
    }

    /// (c) A `TrustPreVerified` (legacy / `2.7.legacy`) classical-only
    /// import is ADMITTED — the carve-out. Historical provenance imports
    /// are attested by import provenance, not re-admitted against the
    /// hybrid gate; the hard cut applies to NEW federation writes only.
    #[tokio::test]
    async fn legacy_pre_verified_classical_only_import_admitted() {
        // Same classical-only shape as (b), but imported under
        // VerifyMode::TrustPreVerified — the gate MUST NOT fire.
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let key_id = "ciris-agent-key:legacy-import";
        let mut trace = CompleteTrace {
            trace_id: "trace-legacy-import".into(),
            thought_id: "th-1".into(),
            task_id: None,
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53.123456Z".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12.789012Z".parse().unwrap(),
            trace_level: crate::schema::TraceLevel::Generic,
            // The legacy provenance dialect.
            trace_schema_version: serde_json::from_str("\"2.7.legacy\"").unwrap(),
            components: vec![crate::schema::TraceComponent {
                component_type: crate::schema::ComponentType::Observation,
                event_type: crate::schema::ReasoningEventType::ThoughtStart,
                timestamp: "2026-04-30T00:15:53.123Z".parse().unwrap(),
                data: {
                    let mut m = serde_json::Map::new();
                    m.insert("attempt_index".into(), 0.into());
                    m
                },
                agent_id_hash: None,
            }],
            deployment_profile: None,
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: String::new(),
            signature_key_id: key_id.into(),
            // Classical-only — the original 1.9.x Ed25519 sig as
            // provenance. No PQC half, and that is LEGITIMATE here.
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
            run_kind: None,
        };
        let canonical = crate::verify::ed25519::canonical_bytes_for_trace(
            &trace,
            &PythonJsonDumpsCanonicalizer,
        )
        .unwrap();
        trace.signature = BASE64.encode(sk.sign(&canonical).to_bytes());

        let envelope = serde_json::json!({
            "events": [{
                "event_type": "complete_trace",
                "trace_level": "generic",
                "trace": serde_json::to_value(&trace).unwrap(),
            }],
            "batch_timestamp": "2026-04-30T15:00:00+00:00",
            "consent_timestamp": "2025-01-01T00:00:00Z",
            "trace_level": "generic",
            "trace_schema_version": "2.7.legacy",
        });

        let backend = crate::store::test_backend::test_backend();
        // Intentionally register NO key — TrustPreVerified skips lookup
        // AND the hybrid gate; a clean persist proves the carve-out.
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        let summary = pipeline
            .receive_and_persist_with(
                envelope.to_string().as_bytes(),
                VerifyMode::TrustPreVerified,
            )
            .await
            .expect("legacy pre-verified classical-only import MUST be admitted (carve-out)");
        assert_eq!(summary.trace_events_inserted, 1);
        let snap = backend.snapshot_events();
        assert_eq!(snap.len(), 1);
        // Honest row state: classical-only (no PQC half), attributed to
        // Edge — the import provenance, not a persist hybrid verify.
        assert!(snap[0].signature_ml_dsa_65.is_none());
        assert_eq!(
            snap[0].verification_source,
            crate::store::VerificationSource::Edge
        );
    }
}
