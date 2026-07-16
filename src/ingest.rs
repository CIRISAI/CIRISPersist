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

use crate::schema::{BatchEnvelope, BatchEvent, CompleteTrace, Error as SchemaError};
use crate::scrub::{ScrubError, Scrubber};
use crate::store::{Backend, Error as StoreError, InsertReport};
use crate::verify::{canonical::Canonicalizer, Error as VerifyError};

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
            // The per-reason machine token (e.g. `scope_no_community_membership`)
            // is the actionable detail for a write-scope refusal.
            IngestError::ScopeRefused(r) => Some(r.kind().to_string()),
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
    /// base64(ed25519_sign(canonical(component.data_post_scrub))).
    pub scrub_signature: String,
    /// Identifier for the deployment's signing key.
    pub scrub_key_id: String,
    /// When the scrub+sign happened.
    pub scrub_timestamp: chrono::DateTime<chrono::Utc>,
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
    B: Backend + ?Sized,
    C: Canonicalizer + ?Sized,
    S: Scrubber + ?Sized,
{
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
        // v0.1.18 — wire-body sha256 for the SignatureMismatch
        // breadcrumb, computed once per call so the lens-side
        // body_sha256_prefix in their POST-receipt log joins
        // persist's verify-failure log on the same hex prefix.
        // Cheap (microseconds for a typical batch); only used in
        // the diagnostic warn, not the hot verify path.
        let body_sha256 = hex::encode(sha2::Sha256::digest(bytes));

        // 1. Schema parse — typed envelope. Schema-version gate fires
        //    here.
        let mut env = BatchEnvelope::from_json(bytes)?;

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
        match verify_mode {
            VerifyMode::Full => {
                for event in &env.events {
                    match event {
                        BatchEvent::CompleteTrace { trace, .. } => {
                            self.verify_complete_trace(trace, &body_sha256).await?;
                            signatures_verified += 1;
                        }
                    }
                }
            }
            VerifyMode::TrustPreVerified => {}
        }

        // 3. Capture pre-scrub canonical bytes for every component.
        //    FSD §3.3 step 3.5: original_content_hash is sha256 of
        //    canonical(component.data_pre_scrub) — must be computed
        //    BEFORE scrub mutates `data`. One Vec<u8>-per-component
        //    held briefly; dropped after step 3.5.
        let pre_scrub_hashes = self.compute_pre_scrub_hashes(&env)?;

        // 4. Scrub. By the time we get here every signature has been
        //    accepted, so we know the bytes are real agent testimony.
        let scrubbed_fields = self.scrubber.scrub_batch(&mut env)?;

        // 5. Step 3.5 — sign per-component scrub envelope. UNCONDITIONAL
        //    (FSD §3.3 step 3.5; §3.4 robustness primitive #7).
        //    Same key signs every component on every trace level.
        let envelopes = self.sign_scrub_envelopes(&env, &pre_scrub_hashes).await?;

        // 6. Decompose each CompleteTrace into row-shaped writes.
        //    Envelope columns get attached to each row by index.
        let mut events_to_insert = Vec::new();
        let mut llm_calls_to_insert = Vec::new();
        let mut env_idx = 0usize;
        // v4.0 (FSD §4.6) — write-path cohort_scope gate: resolved
        // writer admission, keyed on the signer (`scrub_key_id`). Built
        // lazily on the first family/community row so all-self / all-broad
        // / all-federation batches pay no admission reads. Same signer
        // signs every component of a batch in this pipeline, so the cache
        // is hit for every row after the first family/community one.
        let mut writer_admission_cache: Option<(String, crate::scope::CallerAdmission)> = None;
        for event in &env.events {
            match event {
                BatchEvent::CompleteTrace { trace, .. } => {
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
                        if scope == crate::federation::types::cohort_scope::FAMILY
                            || scope == crate::federation::types::cohort_scope::COMMUNITY
                        {
                            let admission = self
                                .writer_admission(
                                    &mut writer_admission_cache,
                                    env_for_row.scrub_key_id.as_str(),
                                )
                                .await?;
                            if let Err(reason) = crate::federation::admission::DimensionAdmissionPolicy::check_write_cohort_scope(
                                admission,
                                scope,
                                row.cohort_target_id.as_deref(),
                            ) {
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
                    events_to_insert.extend(d.events);
                    llm_calls_to_insert.extend(d.llm_calls);
                }
            }
        }
        debug_assert_eq!(env_idx, envelopes.len(), "envelope index drift");

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

    /// Sign post-scrub canonical bytes per component. Returns one
    /// `ScrubEnvelope` per component, in the same flat order as
    /// `compute_pre_scrub_hashes`. THREAT_MODEL.md AV-24.
    async fn sign_scrub_envelopes(
        &self,
        env: &BatchEnvelope,
        pre_hashes: &[String],
    ) -> Result<Vec<ScrubEnvelope>, IngestError> {
        let now = chrono::Utc::now();
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
                        let sig_bytes = self
                            .signer
                            .sign(&post_bytes)
                            .await
                            .map_err(|e| IngestError::Sign(format!("{e}")))?;
                        envelopes.push(ScrubEnvelope {
                            original_content_hash: pre_hashes[idx].clone(),
                            scrub_signature: BASE64.encode(&sig_bytes),
                            scrub_key_id: key_id.clone(),
                            scrub_timestamp: now,
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
            let identity = self
                .backend
                .resolve_identity_for_occurrence(signer)
                .await
                .map_err(IngestError::Store)?
                .unwrap_or_else(|| signer.to_owned());
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

    async fn verify_complete_trace(
        &self,
        trace: &CompleteTrace,
        body_sha256: &str,
    ) -> Result<(), IngestError> {
        let key_id = &trace.signature_key_id;
        let lookup = self
            .backend
            .lookup_public_key(key_id)
            .await
            .map_err(IngestError::Store)?;

        let key = match lookup {
            Some(k) => k,
            None => {
                // v0.1.17 — verify-unknown-key breadcrumb
                // (CIRISPersist#6). When the backend reports
                // `Ok(None)` for a key the agent claims to have
                // signed under, surface lookup-time observables.
                let sample = self.backend.sample_public_keys(5).await.ok();
                tracing::warn!(
                    envelope_signer_id = %key_id,
                    looked_up_id_bytes_hex = %hex::encode(key_id.as_bytes()),
                    looked_up_id_byte_len = key_id.len(),
                    wire_body_sha256 = %body_sha256,
                    accord_public_keys_size = ?sample.as_ref().map(|s| s.size),
                    accord_public_keys_sample = ?sample.as_ref().map(|s| &s.sample),
                    "ciris-persist: verify_unknown_key — lookup miss"
                );
                return Err(IngestError::Verify(VerifyError::UnknownKey(key_id.clone())));
            }
        };

        // v0.1.18 — verify_signature_mismatch breadcrumb. Mirrors
        // the v0.1.17 unknown-key breadcrumb on the canonicalization-
        // failure branch. Both 9-field spec AND 2-field legacy were
        // tried in `verify_trace` and neither verified. Surfaces:
        //
        // - wire_body_sha256: joins lens-side body_sha256_prefix
        // - canonical_9field_sha256 / canonical_2field_sha256: hex
        //   sha256 of each canonical-bytes shape persist computed
        // - canonical_*_bytes_len: length, easy eyeball
        // - signature_b64_prefix: first 16 chars of the agent's
        //   signature for cross-correlation against capture logs
        //
        // The diagnostic computation is best-effort. If
        // canonicalization itself fails (which is essentially
        // impossible — same code path verify_trace just exercised
        // and bubbled SignatureMismatch from), we still emit the
        // warn with `None` for the canonical fields and return
        // the typed SignatureMismatch error.
        // v4.6 (#176) — select the canonicalizer by the trace's SIGNED
        // schema epoch (Python-compat 1.x/2.x, JCS 3.x+), not the
        // struct's injected default. Signed-bytes-bound, not
        // caller-selectable. (The injected `self.canonicalizer` remains
        // the best-effort diagnostic canonicalizer below; in production
        // it equals the gate's V1 result for current 1.x/2.x traffic.)
        let canon = crate::verify::canonical::canonicalizer_for(
            crate::verify::ed25519::canon_version_for_trace_schema(
                trace.trace_schema_version.as_str(),
            ),
        );
        // v7.2.0 (CIRISPersist#225) — the trace-tier hybrid HARD CUT.
        // This method only runs for VerifyMode::Full (the
        // TrustPreVerified / `2.7.legacy` carve-out skips step 2 entirely
        // upstream in `receive_and_persist_with`). We verify BOTH halves
        // via `verify_trace_hybrid` under `HybridPolicy::Strict`: a
        // classical-only trace (`signature_ml_dsa_65 == None`) is
        // REJECTED AT ADMISSION — no `require_hybrid: false` posture
        // (CEG 1.0-RC7 §10.1.5.1.1 + CIRISVerify#75; HNDL forge-later on
        // the durable, replicated, kept-for-posterity corpus).
        //
        // The Ed25519 pubkey came from `accord_public_keys`
        // (`lookup_public_key` above); that directory is Ed25519-only, so
        // the producer's ML-DSA-65 pubkey rides the trace envelope
        // (`trace.pubkey_ml_dsa_65`) and is bound into the hybrid verify.
        //
        // Ordering invariant (MISSION §4, AV-9): this is step 2,
        // verify-before-mutation; it MUST NOT be reordered behind dedup
        // (dedup-first would be a suppression/probe oracle). The
        // throughput lever is the per-batch verify loop, NOT dedup-first.
        let ed25519_pubkey_b64 = BASE64.encode(key.to_bytes());
        match crate::verify::ed25519::verify_trace_hybrid(
            trace,
            canon,
            &ed25519_pubkey_b64,
            crate::verify::HybridPolicy::Strict,
        ) {
            Ok(_outcome) => Ok(()),
            Err(crate::verify::HybridVerifyError::HybridPendingRejected) => {
                // The hard cut: a Full-mode trace arrived classical-only.
                tracing::warn!(
                    envelope_signer_id = %key_id,
                    wire_body_sha256 = %body_sha256,
                    trace_id = %trace.trace_id,
                    "ciris-persist: verify_hybrid_required — Full-mode classical-only trace REJECTED at admission (#225 trace-tier hard cut)"
                );
                Err(IngestError::Verify(VerifyError::HybridRequired))
            }
            Err(e) => {
                // Cryptographic mismatch on a half, or a malformed PQC
                // field. Emit the same canonical-shape diagnostic the
                // Ed25519-only path emitted, plus the hybrid error token.
                let diag =
                    crate::verify::ed25519::canonical_payload_sha256s(trace, self.canonicalizer)
                        .ok();
                let sig_b64_prefix: String = trace.signature.chars().take(16).collect();
                tracing::warn!(
                    envelope_signer_id = %key_id,
                    wire_body_sha256 = %body_sha256,
                    hybrid_error = %e.kind(),
                    canonical_9field_sha256 = ?diag.as_ref().map(|d| &d.nine_field_sha256),
                    canonical_2field_sha256 = ?diag.as_ref().map(|d| &d.two_field_sha256),
                    canonical_9field_bytes_len = ?diag.as_ref().map(|d| d.nine_field_bytes.len()),
                    canonical_2field_bytes_len = ?diag.as_ref().map(|d| d.two_field_bytes.len()),
                    signature_b64_prefix = %sig_b64_prefix,
                    "ciris-persist: verify_hybrid_failed — hybrid (Ed25519 + ML-DSA-65) verify rejected the trace"
                );
                Err(IngestError::Verify(VerifyError::HybridVerify(
                    e.kind().to_owned(),
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SchemaVersion;
    use crate::scrub::NullScrubber;
    use crate::store::{decompose, MemoryBackend};
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
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, vkey);

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

    /// v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — AV-45 write-gate:
    /// a verified writer that stamps `cohort_scope: community` for a
    /// community it is NOT a member of is REFUSED, and ZERO rows persist
    /// (mirrors `signature_mismatch_rejected_no_writes`). This is the
    /// visibility-downgrade attempt the gate exists to block.
    #[tokio::test]
    async fn write_gate_refuses_non_member_community_zero_writes() {
        let (bytes, key_id, vkey) =
            make_signed_batch_bytes_with_cohort("community", Some("community-key:not-mine")).await;
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, vkey);

        let (signer, signer_key_id) = make_test_signer().await;
        // The writer (signer) is a member of a DIFFERENT community —
        // not the one the trace claims.
        backend.add_community_membership("community-key:mine", &[signer_key_id.as_str()]);
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        let err = pipeline.receive_and_persist(&bytes).await.unwrap_err();
        match err {
            IngestError::ScopeRefused(crate::scope::ScopeRefusalReason::NoCommunityMembership) => {}
            other => panic!("expected ScopeRefused(NoCommunityMembership), got {other:?}"),
        }
        // Stable boundary token + per-reason detail.
        assert_eq!(err.kind(), "write_scope_refused");
        assert_eq!(
            err.detail().as_deref(),
            Some("scope_no_community_membership")
        );
        // Zero writes — the refusal short-circuits before the insert.
        assert!(
            backend.snapshot_events().is_empty(),
            "a refused cohort_scope downgrade must produce zero rows"
        );
    }

    /// v4.0 (CIRISPersist#160 comment 4, FSD §4.6) — AV-45 write-gate
    /// pass case: a verified writer that IS a member of the claimed
    /// community persists normally (companion to the refusal test).
    #[tokio::test]
    async fn write_gate_admits_member_community_persists() {
        let (bytes, key_id, vkey) =
            make_signed_batch_bytes_with_cohort("community", Some("community-key:mine")).await;
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, vkey);

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
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, vkey);

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

        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, vkey);
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
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, vkey);

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

        // THREAT_MODEL.md AV-24 verification: ed25519_verify the
        // first row's scrub_signature against signer's public key
        // and the canonical(post-scrub) bytes — proves a peer with
        // the published public key can verify the deployment's
        // attestation.
        //
        // v17.7.0 (#470 arc, crypto-DRY closure) — strict-verify through the
        // canonical `ciris_crypto::Ed25519Verifier::verify_strict` (v10.4.0)
        // instead of reaching for `ed25519_dalek` directly: ONE Ed25519
        // acceptance rule in the repo, not two.
        let pubkey_bytes = signer.public_key().await.expect("signer.public_key");

        let row0 = &snap[0];
        let payload_value = serde_json::Value::Object(row0.payload.clone());
        let canonical = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload_value)
            .unwrap();
        let sig_b64 = row0.scrub_signature.as_ref().unwrap();
        let sig_bytes = BASE64.decode(sig_b64).expect("base64 decode");
        let verified = ciris_crypto::Ed25519Verifier
            .verify_strict(&pubkey_bytes, &canonical, &sig_bytes)
            .expect("verify_strict parse");
        assert!(
            verified,
            "scrub_signature verifies against canonical(post-scrub)"
        );
    }

    #[tokio::test]
    async fn idempotent_replay() {
        // Mission category §4 "Idempotency": replaying the same batch
        // bytes results in 0 inserts + N conflicts the second time.
        let (bytes, key_id, vkey) = make_signed_batch_bytes().await;
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, vkey);

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

    #[tokio::test]
    async fn malformed_json_is_typed_error() {
        let backend = MemoryBackend::new();
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
        let backend = MemoryBackend::new();
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

    #[tokio::test]
    async fn unknown_signing_key_rejected() {
        let (bytes, key_id, _vkey) = make_signed_batch_bytes().await;
        let backend = MemoryBackend::new();
        // No key registered → verify must reject with UnknownKey.
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        let err = pipeline.receive_and_persist(&bytes).await.unwrap_err();
        match err {
            IngestError::Verify(VerifyError::UnknownKey(id)) => assert_eq!(id, key_id),
            other => panic!("expected UnknownKey, got {other:?}"),
        }
        // Backend received zero rows.
        assert!(backend.snapshot_events().is_empty());
    }

    #[tokio::test]
    async fn signature_mismatch_rejected_no_writes() {
        // Mission constraint (MISSION.md §3 anti-pattern #2): unverified
        // bytes never touch persistence.
        let (bytes, key_id, _vkey) = make_signed_batch_bytes().await;
        // Wire a *different* key for the same key_id.
        let other_sk = SigningKey::from_bytes(&[0x99; 32]);
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, other_sk.verifying_key());

        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        let err = pipeline.receive_and_persist(&bytes).await.unwrap_err();
        // v7.2.0 (#225): the fixture is now hybrid-signed (both halves
        // present), but the directory advertises a DIFFERENT Ed25519 key,
        // so the classical half of the bound hybrid verify fails. The
        // hard-cut gate surfaces this as HybridVerify (a crypto mismatch
        // on a half), not the legacy Ed25519-only SignatureMismatch.
        assert!(
            matches!(err, IngestError::Verify(VerifyError::HybridVerify(_))),
            "got {err:?}"
        );
        assert!(
            backend.snapshot_events().is_empty(),
            "rejected traces must produce zero rows"
        );
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
        let backend = MemoryBackend::new();
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

    /// v2.0 (CIRISPersist#91) — `VerifyMode::Full` (and the
    /// `receive_and_persist` default) is unchanged: it still verifies
    /// every trace and still rejects a bad signature with zero writes.
    #[tokio::test]
    async fn full_mode_unchanged_still_rejects_bad_signature() {
        let (bytes, key_id, _vkey) = make_signed_batch_bytes().await;
        // Register a *different* key for the same key_id → mismatch.
        let other_sk = SigningKey::from_bytes(&[0x99; 32]);
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, other_sk.verifying_key());

        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };

        // Explicit `Full` mode rejects the bad signature. v7.2.0 (#225):
        // the hybrid-signed fixture's classical half doesn't match the
        // wrong key the directory advertises → HybridVerify (crypto
        // mismatch on a half), the hard-cut gate's wrapping of the legacy
        // Ed25519-only SignatureMismatch.
        let err = pipeline
            .receive_and_persist_with(&bytes, VerifyMode::Full)
            .await
            .unwrap_err();
        assert!(
            matches!(err, IngestError::Verify(VerifyError::HybridVerify(_))),
            "got {err:?}"
        );
        // The `receive_and_persist` convenience (Full-by-default)
        // behaves identically.
        let err2 = pipeline.receive_and_persist(&bytes).await.unwrap_err();
        assert!(
            matches!(err2, IngestError::Verify(VerifyError::HybridVerify(_))),
            "got {err2:?}"
        );
        assert!(
            backend.snapshot_events().is_empty(),
            "Full mode still writes zero rows for a bad signature"
        );
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
            }),
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: String::new(),
            signature_key_id: key_id.into(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
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

        let backend = MemoryBackend::new();
        backend.add_public_key(key_id, sk.verifying_key());
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
        let backend = MemoryBackend::new();
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
        };
        let d1 = decompose(&trace).unwrap();
        let d2 = decompose(&trace).unwrap();
        assert_eq!(d1, d2);
    }

    // ───────────────────────────────────────────────────────────────
    // v7.2.0 (CIRISPersist#225) — the trace-tier hybrid hard cut.
    // CEG 1.0-RC7 §10.1.5.1.1 + CIRISVerify#75. These four tests prove
    // the cut against the MemoryBackend; the PG + SQLite mirror lives in
    // tests/trace_hybrid_hard_cut.rs (both backends, V083 round-trip).
    // ───────────────────────────────────────────────────────────────

    /// (a) A Full-mode trace with a VALID hybrid signature is ADMITTED,
    /// both halves are STORED, and the row round-trips.
    #[tokio::test]
    async fn full_mode_hybrid_trace_admitted_and_both_halves_stored() {
        let (bytes, key_id, vkey) = make_signed_batch_bytes().await;
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, vkey);

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
            .expect("valid hybrid trace MUST be admitted under the hard cut");
        assert_eq!(
            summary.signatures_verified, 1,
            "persist verified the hybrid"
        );
        assert_eq!(summary.trace_events_inserted, 2);

        let snap = backend.snapshot_events();
        assert_eq!(snap.len(), 2);
        for row in &snap {
            assert!(
                row.signature_ml_dsa_65.is_some(),
                "the ML-DSA-65 half MUST be stored on every row"
            );
            assert!(
                row.pubkey_ml_dsa_65.is_some(),
                "the producer ML-DSA-65 pubkey MUST be stored"
            );
            assert_eq!(row.pqc_key_id.as_deref(), Some("test-mldsa"));
            assert!(!row.signature.is_empty(), "classical half still stored");
        }
    }

    /// (b) A Full-mode CLASSICAL-ONLY trace is REJECTED at admission —
    /// the hard cut. No `require_hybrid: false` posture. Zero rows land.
    #[tokio::test]
    async fn full_mode_classical_only_trace_rejected_at_admission() {
        // Build a classical-only (Ed25519-only) signed trace — exactly
        // the pre-#225 shape. It must be REJECTED, not warned.
        let sk = SigningKey::from_bytes(&[0x42; 32]);
        let key_id = "ciris-agent-key:classical-only";
        let mut trace = CompleteTrace {
            trace_id: "trace-classical-only".into(),
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
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: String::new(),
            signature_key_id: key_id.into(),
            // The hard cut: NO ML-DSA-65 half.
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
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
            "trace_schema_version": "2.7.0",
        });

        let backend = MemoryBackend::new();
        backend.add_public_key(key_id, sk.verifying_key());
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
            .expect_err("a Full-mode classical-only trace MUST be rejected (the hard cut)");
        assert!(
            matches!(err, IngestError::Verify(VerifyError::HybridRequired)),
            "the classical-only reject MUST be the HybridRequired hard cut, got {err:?}"
        );
        assert_eq!(err.kind(), "verify_hybrid_required");
        assert!(
            backend.snapshot_events().is_empty(),
            "a rejected classical-only trace MUST write zero rows (verify-before-mutation)"
        );
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

        let backend = MemoryBackend::new();
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

    /// (d) The stored hybrid signature VERIFIES (both halves) on read.
    /// Pull the persisted row back, reconstruct the canonical bytes, and
    /// re-run `verify_hybrid` in Strict mode against the stored halves.
    #[tokio::test]
    async fn stored_hybrid_signature_verifies_both_halves_on_read() {
        let (bytes, key_id, vkey) = make_signed_batch_bytes().await;
        let backend = MemoryBackend::new();
        backend.add_public_key(&key_id, vkey);
        let (signer, signer_key_id) = make_test_signer().await;
        let pipeline = IngestPipeline {
            backend: &backend,
            canonicalizer: &PythonJsonDumpsCanonicalizer,
            scrubber: &NullScrubber,
            signer: &*signer,
            signer_key_id: &signer_key_id,
        };
        pipeline.receive_and_persist(&bytes).await.expect("admit");

        // Reconstruct the producer's CompleteTrace from the wire so the
        // canonical bytes match what was signed, then verify_hybrid
        // against the halves stored on the row.
        let env: serde_json::Value = serde_json::from_slice(&bytes).expect("envelope json");
        let trace_json = &env["events"][0]["trace"];
        let trace: CompleteTrace = serde_json::from_value(trace_json.clone()).expect("trace");

        let snap = backend.snapshot_events();
        let row = &snap[0];
        let ed25519_pubkey_b64 = BASE64.encode(vkey.to_bytes());
        let canonical = crate::verify::ed25519::canonical_bytes_for_trace(
            &trace,
            &PythonJsonDumpsCanonicalizer,
        )
        .unwrap();
        let outcome = crate::verify::verify_hybrid(
            &canonical,
            &row.signature,
            row.signature_ml_dsa_65.as_deref(),
            &ed25519_pubkey_b64,
            row.pubkey_ml_dsa_65.as_deref(),
            crate::verify::HybridPolicy::Strict,
            None,
        )
        .expect("the STORED hybrid signature must verify both halves on read");
        assert_eq!(outcome, crate::verify::VerifyOutcome::HybridVerified);
    }
}
