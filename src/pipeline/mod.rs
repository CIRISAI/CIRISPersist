//! Post-ingest filter pipeline (v0.6.0+, CIRISPersist#19).
//!
//! # Mission alignment (FSD `POST_INGEST_FILTER_PIPELINE.md`)
//!
//! Persist owns the **wire-to-storage boundary**:
//! `Engine.receive_and_persist` parses, verifies, and decomposes a
//! hybrid-signed `BatchEnvelope` into rows. The pipeline is the
//! between-verify-and-store hook for the four post-verify
//! transformations:
//!
//! - **classify** — typed content-class matches per component
//!   (PII / secrets / structural / patterns).
//! - **scrub** — redact matched spans in the BatchEnvelope payload.
//! - **encrypt-and-store** — replace `{SECRET:uuid:desc}` placeholders
//!   for sensitive matches, archive the cleartext encrypted via
//!   `crate::secrets::SecretsService`. *(v0.6.1, gated on `secrets`
//!   feature.)*
//! - **extract** — populate the typed `Features` projection consumers
//!   read for scoring + corpus drift.
//!
//! These are one substrate concern at four layers of granularity
//! (classify → scrub → extract → encrypt-and-store), sharing inputs
//! (the verified BatchEnvelope), output shape (per-component
//! classifications + per-trace features), and trust boundary (the
//! persist-side hybrid-signed sidecar).
//!
//! # Scope per release
//!
//! - **v0.6.0** — Classify (taxonomy + light matchers) + scrub lift
//!   from CIRISLens (cirislens-core) + extract typed `Features` +
//!   `Stage` trait + `Pipeline` orchestration. PyO3 surface for
//!   `get_features` / `get_classifications`. V007 migration adds
//!   `extracted_features` / `classifications` / `pipeline_metadata`
//!   JSONB columns to `cirislens.trace_events`. NER/ORT lift gated
//!   behind heavy ML deps for production lens deployments.
//! - **v0.6.1** — `crate::secrets::SecretsService` (18-method trait)
//!   plus V010 migration (`cirislens_secrets` schema, 4 tables) plus
//!   HTTP API plus crypto facade (`secrets/crypto.rs`).
//! - **v0.6.x+** — adaptive matcher catalog + per-deployment policy
//!   bundles + federation-stable matcher distribution.
//!
//! # Feature gating (`Cargo.toml [features]`)
//!
//! See FSD §2.4. Sovereign / Pi-class deployments build with
//! `default-sovereign-light` (regex-only scrubber, no ML deps).
//! Production federated deployments build with `default-pipeline-ml`
//! (full multilingual NER pipeline).

#[cfg(feature = "classify")]
pub mod classify;

#[cfg(feature = "extract")]
pub mod extract;

#[cfg(feature = "scrub")]
pub mod scrub;

pub mod inline_text;
pub mod types;
pub mod wire_envelope;

pub use inline_text::InlineTextEnvelope;
pub use types::{HybridSignatureBlock, PipelineEnvelope, PipelineMetadata, PipelineSidecar};
pub use wire_envelope::{MatchAddress, WireEnvelope};

#[cfg(feature = "classify")]
pub use classify::{
    Action, ContentClass, ContentClassMatch, DetectionMethod, LearningState, Sensitivity,
};

#[cfg(feature = "extract")]
pub use extract::{
    extract_features, DeclaredCohortAxes, Features, ModelClass, ObservationWeights, StepTimestamps,
};

#[cfg(feature = "scrub")]
pub use scrub::{scrub_trace, scrub_traces_batch, ScrubError, ScrubStats, ScrubbedTrace};

// ─── Pipeline orchestration scaffolding (v0.6.0-α2 lands real stages) ──

use std::future::Future;

// BatchEnvelope is used by the ExtractStage impl (extract feature),
// the inbound/minimal pipeline factories, and the test fixtures —
// but every test that uses it is itself feature-gated, so the import
// needs to fire only on the features (not on `cfg(test)`) to avoid
// the unused-imports warning under the CI's `-D warnings` for builds
// without any pipeline feature.
#[cfg(any(feature = "extract", feature = "classify", feature = "scrub"))]
#[allow(unused_imports)] // re-exported under test+feature; the `use` line
// also pulls the type into scope for doc-references.
use crate::schema::BatchEnvelope;

// v1.1.0 (CIRISPersist#33): `WireEnvelope` is the trait the generic
// pipeline operates over. `BatchEnvelope` impls it (one body per
// component); `InlineTextEnvelope` impls it (single body) for SPEAK
// / LLM-prompt / WBD / DSAR flows. `ExtractStage` stays
// BatchEnvelope-specific (Features projection is structurally
// trace-coupled per FSD §5.1).

/// Pipeline-layer errors — typed surface for stage failures.
///
/// Mission constraint (FSD §3.3 step 3, MISSION.md §4 "Mission
/// rejection"): a stage that fails MUST fail ingest. Partial pipeline
/// runs leak the assumption that the rest of the stages ran cleanly.
/// Every variant maps to a stable `kind()` token for HTTP / PyO3
/// sanitization (THREAT_MODEL.md AV-15).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A stage rejected the envelope (invariant violation — schema-altered
    /// scrub output, scrubber returned wrong event count, etc.).
    #[error("stage rejected envelope: {stage}: {reason}")]
    StageRejected {
        /// Stage name as returned by [`Stage::name`].
        stage: &'static str,
        /// Human-readable rejection reason (free-form, NOT a token).
        reason: String,
    },

    /// A stage's external dependency raised (Python callback, model
    /// inference, regex compile failure during dynamic catalog load).
    #[error("stage external: {stage}: {reason}")]
    StageExternal {
        /// Stage name.
        stage: &'static str,
        /// Verbatim upstream error message.
        reason: String,
    },

    /// Internal serialization / type-conversion issue. Indicates a bug
    /// in persist's own pipeline glue — operators should file an issue.
    #[error("pipeline internal: {0}")]
    Internal(String),

    /// Stage dependency was declared but its output is missing in
    /// [`PipelineState`] (mis-built pipeline, or a `Stage::run` skipped
    /// without populating its output).
    #[error("missing dependency: {required_by} requires {missing}")]
    MissingDependency {
        /// Stage that declared the dependency.
        required_by: &'static str,
        /// Name of the upstream stage whose output is missing.
        missing: &'static str,
    },
}

impl Error {
    /// Stable string-token for telemetry / structured logging.
    pub fn kind(&self) -> &'static str {
        match self {
            Error::StageRejected { .. } => "pipeline_rejected",
            Error::StageExternal { .. } => "pipeline_external",
            Error::Internal(_) => "pipeline_internal",
            Error::MissingDependency { .. } => "pipeline_missing_dep",
        }
    }
}

/// Accumulator passed between stages — typed outputs of prior stages
/// + per-run counters for observability.
///
/// v0.6.0-α scaffolding: classifications + fields_modified + stages_executed
/// are populated by the classify / scrub stages. `features` is populated
/// by the extract stage (lifted in v0.6.0-α3). `encrypted_secrets` is
/// reserved for v0.6.1's encrypt-and-store stage.
#[derive(Debug, Default)]
pub struct PipelineState {
    /// Classify output. Outer vec is per-component in BatchEnvelope
    /// order; inner vec is per-span-match within that component.
    /// Empty until the classify stage runs.
    #[cfg(feature = "classify")]
    pub classifications: Vec<Vec<classify::ContentClassMatch>>,

    /// Typed features. v0.7.5: populated by the [`ExtractStage`]
    /// once it runs (FSD §5.1 shape). None if extract didn't run.
    #[cfg(feature = "extract")]
    pub features: Option<extract::Features>,

    /// Encrypted secret records produced by the `encrypt_and_store`
    /// stage. Reserved for the FSD §5.2 stage cut; empty in v0.7.5
    /// (no concrete EncryptAndStoreStage yet).
    #[cfg(feature = "secrets")]
    pub encrypted_secrets: Vec<crate::secrets::types::EncryptedSecretRecord>,

    /// Total field-modifications applied by scrub stages this run.
    /// Aggregated across every Scrubber call site for batch-level
    /// metrics. Lens dashboards read this.
    pub fields_modified: usize,

    /// Whether at least one scrub stage mutated payload (FSD §4.3
    /// invariant 4). Set to true by any ScrubStage that reports
    /// `fields_modified > 0`.
    pub pii_scrubbed: bool,

    /// Ordered list of stage names that ran. Populated as each stage
    /// completes; consumers can detect "stage X was skipped" via
    /// absence here. v0.7.5: switched to `String` (was `&'static str`)
    /// so wire-format [`types::PipelineMetadata::stages_executed`]
    /// can carry the same values without converting.
    pub stages_executed: Vec<String>,
}

/// A pipeline stage — atomic post-verify transformation on a
/// [`WireEnvelope`].
///
/// v1.1.0 (CIRISPersist#33): generic over `E: WireEnvelope` so the
/// pipeline composes uniformly over `BatchEnvelope` (ingest path)
/// AND [`InlineTextEnvelope`] (SPEAK / LLM-prompt / WBD / DSAR
/// outbound paths).
///
/// Lifecycle: the orchestrator calls [`Stage::run`] in dependency
/// order (defined by [`Stage::dependencies`]). The stage may:
///
/// - Mutate `env` in place via [`WireEnvelope::mutate_body`] (e.g.
///   scrub redacting spans).
/// - Append to `state` (e.g. classify adding to `classifications`).
///
/// Mission alignment (FSD §3.3 step 3): a stage that errors MUST
/// short-circuit the pipeline — the orchestrator propagates the
/// `Error` and rejects the batch. There is no partial-success path.
pub trait Stage<E: WireEnvelope>: Send + Sync {
    /// Stable identifier — used for logs, dependency declarations,
    /// observability. Must be unique within a pipeline. Lowercase
    /// snake_case convention.
    fn name(&self) -> &'static str;

    /// Stage names this stage's output depends on. Default: none.
    /// The orchestrator validates against this list before running
    /// the stage — a missing dependency aborts the pipeline build
    /// (NOT a runtime error).
    fn dependencies(&self) -> &'static [&'static str] {
        &[]
    }

    /// Apply the stage's transformation. `env` is the in-flight
    /// envelope (post-verify, pre-store / pre-emit); `state`
    /// accumulates side-channel outputs from this + prior stages.
    fn run<'a>(
        &'a self,
        env: &'a mut E,
        state: &'a mut PipelineState,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'a;
}

// ─── v0.7.5 (CIRISPersist#33): orchestrator surface ─────────────────

/// Object-safe shim around [`Stage`] for dyn-dispatch in the
/// [`Pipeline`] builder. The `Stage` trait uses an `impl Future`
/// return type for ergonomic direct calls; that form isn't
/// object-safe, so we project to a boxed future here. Auto-impl'd
/// for every concrete `T: Stage<E>`.
pub trait ErasedStage<E: WireEnvelope>: Send + Sync {
    /// See [`Stage::name`].
    fn name(&self) -> &'static str;
    /// See [`Stage::dependencies`].
    fn dependencies(&self) -> &'static [&'static str];
    /// Run the stage. Returns a boxed future so the orchestrator can
    /// hold a `Vec<Box<dyn ErasedStage<E>>>`.
    fn run_erased<'a>(
        &'a self,
        env: &'a mut E,
        state: &'a mut PipelineState,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;
}

impl<E: WireEnvelope, T: Stage<E>> ErasedStage<E> for T {
    fn name(&self) -> &'static str {
        Stage::<E>::name(self)
    }
    fn dependencies(&self) -> &'static [&'static str] {
        Stage::<E>::dependencies(self)
    }
    fn run_erased<'a>(
        &'a self,
        env: &'a mut E,
        state: &'a mut PipelineState,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>> {
        Box::pin(self.run(env, state))
    }
}

/// Orchestrator that composes registered [`Stage`] impls in
/// declaration order and runs them sequentially per FSD §5.2 +
/// §2.3. Build via [`PipelineBuilder`]; consume via
/// [`Pipeline::run`].
///
/// v1.1.0 (CIRISPersist#33): generic over `E: WireEnvelope` so the
/// same composition machinery wires both the inbound ingest path
/// (`Pipeline<BatchEnvelope>`) and the outbound SPEAK / LLM-prompt
/// path (`Pipeline<InlineTextEnvelope>`).
///
/// # Stage ordering
///
/// Stages run in the order they were added to the builder. The
/// orchestrator validates [`Stage::dependencies`] at build time —
/// every named dependency must have been added EARLIER in the
/// declaration order, else [`PipelineBuilder::build`] returns
/// [`Error::MissingDependency`].
///
/// # Failure semantics (FSD §3.3 step 3)
///
/// A stage that returns `Err` short-circuits the pipeline; the
/// orchestrator propagates the error to the caller and the rest
/// of the stages don't run. There is no partial-success path.
///
/// # Replay semantics (FSD §4.3 invariant 7)
///
/// `Pipeline::run` is idempotent on `state.fields_modified` ONLY
/// when every registered stage is itself idempotent — the
/// orchestrator does not deduplicate stage effects. Replay-safety
/// is a per-stage concern.
pub struct Pipeline<E: WireEnvelope> {
    stages: Vec<Box<dyn ErasedStage<E>>>,
}

impl<E: WireEnvelope> std::fmt::Debug for Pipeline<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline")
            .field("stages", &self.stage_names())
            .finish()
    }
}

impl<E: WireEnvelope> Pipeline<E> {
    /// Returns the registered stage names in declaration order.
    /// Useful for tests + observability dashboards.
    pub fn stage_names(&self) -> Vec<&'static str> {
        self.stages.iter().map(|s| s.name()).collect()
    }

    /// Run every registered stage in declaration order against
    /// `env`, accumulating side-channel outputs into `state`. On
    /// the first stage error, the orchestrator returns immediately;
    /// `env` and `state` may have partial mutations applied by
    /// prior stages.
    pub async fn run(&self, env: &mut E, state: &mut PipelineState) -> Result<(), Error> {
        for stage in &self.stages {
            stage.run_erased(env, state).await?;
        }
        Ok(())
    }
}

/// Builder for [`Pipeline`]. Validates [`Stage::dependencies`] on
/// [`PipelineBuilder::build`] — a stage whose declared dependency
/// wasn't added earlier in declaration order causes build to fail
/// with [`Error::MissingDependency`] (no runtime surprise).
pub struct PipelineBuilder<E: WireEnvelope> {
    stages: Vec<Box<dyn ErasedStage<E>>>,
}

impl<E: WireEnvelope> PipelineBuilder<E> {
    /// Start an empty builder.
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    /// Append `stage` to the pipeline. Stages run in the order they
    /// were added.
    pub fn add_stage<S: Stage<E> + 'static>(mut self, stage: S) -> Self {
        self.stages.push(Box::new(stage));
        self
    }

    /// Validate stage dependencies + freeze into a [`Pipeline`].
    /// Returns [`Error::MissingDependency`] when any stage's declared
    /// dependency wasn't added earlier in declaration order.
    pub fn build(self) -> Result<Pipeline<E>, Error> {
        let mut seen: Vec<&'static str> = Vec::new();
        for stage in &self.stages {
            for dep in stage.dependencies() {
                if !seen.contains(dep) {
                    return Err(Error::MissingDependency {
                        required_by: stage.name(),
                        missing: dep,
                    });
                }
            }
            seen.push(stage.name());
        }
        Ok(Pipeline {
            stages: self.stages,
        })
    }
}

impl<E: WireEnvelope> Default for PipelineBuilder<E> {
    fn default() -> Self {
        Self::new()
    }
}

// ─── v0.7.5: concrete `ExtractStage` ───────────────────────────────

/// Concrete [`Stage`] wrapping the v0.6.0 `extract_features` walker.
/// Populates `state.features` with the typed [`Features`](extract::Features)
/// projection from the FIRST `CompleteTrace` in `env.events` (FSD
/// §5.1 shape — sidecar carries `Option<Features>` per envelope,
/// not per-trace). For multi-trace batches in the embedded
/// receive_and_persist path, the per-trace path in
/// `IngestPipeline::receive_and_persist` (v0.7.4) remains
/// authoritative.
///
/// # When to use
///
/// - Pipeline-orchestrated path: edge or sovereign-mode embedded
///   builds a `PipelineEnvelope` and runs `Pipeline::run(...)`.
/// - The legacy inline path (`IngestPipeline::receive_and_persist`)
///   continues to call `pipeline::extract::extract_features` directly.
///   The two paths produce the same `Features` shape from the same
///   walker.
#[cfg(feature = "extract")]
pub struct ExtractStage;

#[cfg(feature = "extract")]
impl ExtractStage {
    /// Construct a stage with default extractor settings (v0.6.0
    /// `extract_features` walker, no per-tenant overrides).
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "extract")]
impl Default for ExtractStage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "extract")]
impl Stage<BatchEnvelope> for ExtractStage {
    fn name(&self) -> &'static str {
        "extract"
    }

    // `impl Future + Send + 'a` keeps the explicit Send bound — needed
    // for `ErasedStage`'s `Box<dyn Future<...> + Send>` adapter. The
    // `async fn` form doesn't auto-name the Send bound; suppressing
    // the lint is the documented escape hatch for this pattern.
    #[allow(clippy::manual_async_fn)]
    fn run<'a>(
        &'a self,
        env: &'a mut BatchEnvelope,
        state: &'a mut PipelineState,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'a {
        async move {
            // FSD §5.1: sidecar.features is Option<Features>; FSD
            // §4.3 PipelineEnvelope carries one envelope per pipeline
            // run. Multi-trace batches in the legacy inline path
            // use per-trace extract instead (v0.7.4).
            let first_trace = env
                .events
                .iter()
                .find(|e| matches!(e, crate::schema::BatchEvent::CompleteTrace { .. }))
                .map(|e| {
                    let crate::schema::BatchEvent::CompleteTrace { trace, .. } = e;
                    trace
                });
            let Some(trace) = first_trace else {
                // Empty batch — record the stage ran (no-op), don't
                // populate features. (FSD §3.3 step 3: stage that
                // produces no output is fine; rejection requires
                // explicit Err.)
                state.stages_executed.push("extract".to_string());
                return Ok(());
            };
            let declared = trace
                .deployment_profile
                .as_ref()
                .map(|p| extract::DeclaredCohortAxes {
                    agent_role: Some(p.agent_role.clone()),
                    agent_template: Some(p.agent_template.clone()),
                    deployment_domain: Some(p.deployment_domain.clone()),
                    deployment_type: Some(p.deployment_type.clone()),
                    deployment_region: p.deployment_region.clone(),
                    deployment_trust_mode: Some(p.deployment_trust_mode.clone()),
                })
                .unwrap_or_default();
            let trace_json = serde_json::to_value(trace).map_err(|e| {
                Error::Internal(format!("ExtractStage: trace serialize failed: {e}"))
            })?;
            let features = extract::extract_features(&trace_json, declared);
            state.features = Some(features);
            state.stages_executed.push("extract".to_string());
            Ok(())
        }
    }
}

// ─── v1.0.0 (CIRISPersist#33): ClassifyStage ──────────────────────────

/// Concrete [`Stage`] for content-class classification.
///
/// # Status (v1.0.0)
///
/// The `crate::pipeline::classify` module ships the full **taxonomy**
/// (D1–D5 types per FSD §6.1) but no concrete matcher functions —
/// regex / length / count / frequency / NER matcher impls are scoped
/// to v0.6.x post-#33. This stage therefore **records that classify
/// ran** but populates one empty `Vec<ContentClassMatch>` per
/// component (the FSD §4.3 invariant 5 shape: outer-vec length =
/// component count). Downstream stages still see well-formed state.
///
/// When matcher impls land, the inner loop here is the single edit
/// site — swap the empty-vec push for a per-body dispatch into
/// the matcher catalog.
///
/// # v1.1.0 (CIRISPersist#33) genericity
///
/// Generic over `E: WireEnvelope` so the same stage instance composes
/// into `Pipeline<BatchEnvelope>` (inbound) and
/// `Pipeline<InlineTextEnvelope>` (outbound SPEAK / LLM-prompt /
/// WBD / DSAR). The classify run iterates
/// [`WireEnvelope::text_bodies`] and pushes one inner classification
/// vec per body. For `BatchEnvelope` the outer-vec length still
/// equals the component count (FSD §4.3 invariant 5); for
/// `InlineTextEnvelope` it equals 1 (FSD §4.3 invariant 5 extended:
/// outer-vec length equals [`WireEnvelope::body_count`]).
#[cfg(feature = "classify")]
pub struct ClassifyStage;

#[cfg(feature = "classify")]
impl ClassifyStage {
    /// Construct a stage with the default (v1.0.0: empty) matcher
    /// catalog.
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "classify")]
impl Default for ClassifyStage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "classify")]
impl<E: WireEnvelope> Stage<E> for ClassifyStage {
    fn name(&self) -> &'static str {
        "classify"
    }

    // See `ExtractStage::run` for the `impl Future + Send + 'a`
    // pattern + the `manual_async_fn` lint suppression rationale.
    #[allow(clippy::manual_async_fn)]
    fn run<'a>(
        &'a self,
        env: &'a mut E,
        state: &'a mut PipelineState,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'a {
        async move {
            // FSD §4.3 invariant 5 (v1.1.0 extension): outer-vec
            // length MUST equal env.body_count(). Push one empty vec
            // per body so downstream invariant-checkers see the
            // correct outer-vec length even when no matchers fired
            // (matcher catalog is empty in v1.0.0).
            for (_addr, _body) in env.text_bodies() {
                // TODO(post-#33): dispatch into the matcher catalog —
                // `classify::run_matchers(&body, addr)` — and push
                // the returned `Vec<ContentClassMatch>`. The matcher
                // catalog stamps `ContentClassMatch.address` from
                // `addr` directly (no per-stage address construction).
                state.classifications.push(Vec::new());
            }
            state.stages_executed.push("classify".to_string());
            Ok(())
        }
    }
}

// ─── v1.0.0 (CIRISPersist#33): ScrubStage ────────────────────────────

/// Concrete [`Stage`] wrapping the v0.6.0 `scrub_trace` walker.
///
/// Runs the configured scrub pass (regex catalog + walker + optional
/// NER per `scrub-ner` feature) over every `CompleteTrace` inside
/// the in-flight [`BatchEnvelope`]. Mutates the envelope in place;
/// totals scrub stats into `state.fields_modified` and flips
/// `state.pii_scrubbed = true` if any field was modified.
///
/// # Trace-level handling
///
/// The underlying [`scrub_trace`](scrub::scrub_trace) routes by
/// [`crate::schema::TraceLevel`]:
/// - `Generic`     → pass-through (no scrub).
/// - `Detailed`    → regex + walker pass.
/// - `FullTraces`  → regex + walker + NER (fails loud without NER).
///
/// # Failure semantics
///
/// Any [`ScrubError`](scrub::ScrubError) surfaces as
/// [`Error::StageExternal`] — the orchestrator short-circuits the
/// pipeline (FSD §3.3 step 3 — partial scrubs MUST fail ingest).
#[cfg(feature = "scrub")]
pub struct ScrubStage;

#[cfg(feature = "scrub")]
impl ScrubStage {
    /// Construct a stage with default scrubber settings.
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "scrub")]
impl Default for ScrubStage {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "scrub")]
impl<E: WireEnvelope> Stage<E> for ScrubStage {
    fn name(&self) -> &'static str {
        "scrub"
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["classify"]
    }

    // v1.1.0 (CIRISPersist#33): generic over `E: WireEnvelope`.
    // Iterates `env.text_bodies()` and scrubs each body
    // independently, writing the scrubbed text back through
    // [`WireEnvelope::mutate_body`]. The scrub level comes from
    // [`WireEnvelope::scrub_level`] — `BatchEnvelope` returns its
    // `trace_level`, `InlineTextEnvelope` returns `Detailed`.
    //
    // Per-body scrub semantics: each body is parsed as JSON (the
    // BatchComponent body is a serialized JSON Object; the
    // InlineText body is plain text → wrapped as `Value::String`).
    // `scrub_trace` walks the JSON and applies regex (always) plus
    // NER (FullTraces only). For BatchEnvelope this preserves the
    // pre-v1.1.0 walker semantics: every nested string under the
    // component's `data` dict is regex-scrubbed.
    #[allow(clippy::manual_async_fn)]
    fn run<'a>(
        &'a self,
        env: &'a mut E,
        state: &'a mut PipelineState,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'a {
        async move {
            let level = env.scrub_level();
            // Collect (addr, body) snapshots first so we can mutate
            // through `mutate_body` without holding an iterator borrow.
            let snapshots: Vec<(MatchAddress, String)> = env.text_bodies().collect();
            for (addr, body) in snapshots {
                // Parse body as JSON when possible (BatchComponent
                // bodies are serialized JSON Objects); otherwise wrap
                // as `Value::String` (InlineText bodies are plain
                // text).
                let (input_value, was_object) =
                    match serde_json::from_str::<serde_json::Value>(&body) {
                        Ok(v @ serde_json::Value::Object(_)) => (v, true),
                        Ok(v @ serde_json::Value::Array(_)) => (v, true),
                        _ => (serde_json::Value::String(body.clone()), false),
                    };
                let scrubbed =
                    scrub::scrub_trace(input_value, level).map_err(|e| Error::StageExternal {
                        stage: "scrub",
                        reason: e.to_string(),
                    })?;
                state.fields_modified += scrubbed.stats.fields_modified;
                let new_body = if was_object {
                    serde_json::to_string(&scrubbed.value).map_err(|e| {
                        Error::Internal(format!(
                            "ScrubStage: scrubbed body re-serialize failed: {e}"
                        ))
                    })?
                } else {
                    // unwrap to the inner string; preserves the
                    // plain-text contract on the InlineText path.
                    match scrubbed.value {
                        serde_json::Value::String(s) => s,
                        other => other.to_string(),
                    }
                };
                env.mutate_body(&addr, &mut |s: &mut String| {
                    *s = new_body.clone();
                });
            }
            if state.fields_modified > 0 {
                state.pii_scrubbed = true;
            }
            state.stages_executed.push("scrub".to_string());
            Ok(())
        }
    }
}

// ─── v1.0.0 (CIRISPersist#33): EncryptAndStoreStage ─────────────────

/// Concrete [`Stage`] that walks `state.classifications` for matches
/// tagged `Action::EncryptAndStore`, calls
/// [`SecretsService::store_secret`](crate::secrets::SecretsService::store_secret)
/// on each, replaces the matched span in the envelope with the
/// canonical `{SECRET:uuid:description}` placeholder, and records
/// the resulting [`EncryptedSecretRecord`](crate::secrets::types::EncryptedSecretRecord)
/// in `state.encrypted_secrets`.
///
/// # Status (v1.0.0)
///
/// **Stubbed.** [`ContentClassMatch`](classify::ContentClassMatch)
/// does not currently carry the pre-scrub cleartext span content —
/// only `(address, span)`. By the time this stage runs (per FSD
/// §2.3 + §5.2 canonical order: Classify → Scrub → EncryptAndStore
/// → Extract), the scrub pass has already replaced the span with
/// `[REDACTED]` markers, so we can't recover the cleartext to
/// encrypt it.
///
/// Resolution (post-v1.0.0): teach the classify matcher catalog to
/// capture the pre-scrub cleartext into `ContentClassMatch` (new
/// field, additive). This stage's body then walks classifications
/// for `Action::EncryptAndStore` and calls
/// `secrets.store_secret(...)` per match.
///
/// For v1.0.0, the stage:
/// - Records itself in `state.stages_executed`.
/// - Iterates `state.classifications` and observes zero
///   `Action::EncryptAndStore` matches (classify is stubbed in
///   v1.0.0 — empty per-component vecs).
/// - Leaves `state.encrypted_secrets` empty.
///
/// The agent team ships against the stub: pipeline composition is
/// valid; the encrypt path activates the moment classify + cleartext
/// capture land.
#[cfg(all(feature = "secrets", feature = "scrub"))]
pub struct EncryptAndStoreStage<S: crate::secrets::SecretsService, E: WireEnvelope> {
    secrets: std::sync::Arc<S>,
    actor_id: String,
    _envelope: std::marker::PhantomData<fn() -> E>,
}

#[cfg(all(feature = "secrets", feature = "scrub"))]
impl<S: crate::secrets::SecretsService, E: WireEnvelope> EncryptAndStoreStage<S, E> {
    /// Construct an EncryptAndStoreStage with a shared
    /// [`SecretsService`](crate::secrets::SecretsService) handle and
    /// an actor id (audit-log attribution — typically
    /// `"pipeline:edge"` for edge-mode or `"pipeline:embedded"` for
    /// sovereign-mode embedded).
    ///
    /// v1.1.0 (CIRISPersist#33): generic over the envelope type `E`
    /// so the same stage struct composes into `Pipeline<BatchEnvelope>`
    /// (inbound ingest) and `Pipeline<InlineTextEnvelope>` (outbound
    /// SPEAK / LLM-prompt — agent responses CAN contain secrets that
    /// need encrypting + replacing with placeholders before they
    /// leave the agent).
    pub fn new(secrets: std::sync::Arc<S>, actor_id: impl Into<String>) -> Self {
        Self {
            secrets,
            actor_id: actor_id.into(),
            _envelope: std::marker::PhantomData,
        }
    }
}

#[cfg(all(feature = "secrets", feature = "scrub"))]
impl<S: crate::secrets::SecretsService + Send + Sync + 'static, E: WireEnvelope> Stage<E>
    for EncryptAndStoreStage<S, E>
{
    fn name(&self) -> &'static str {
        "encrypt_and_store"
    }

    fn dependencies(&self) -> &'static [&'static str] {
        &["scrub"]
    }

    #[allow(clippy::manual_async_fn)]
    fn run<'a>(
        &'a self,
        _env: &'a mut E,
        state: &'a mut PipelineState,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'a {
        async move {
            // v1.0.0: stub. ContentClassMatch doesn't yet carry the
            // pre-scrub cleartext, so even if classify had matches
            // tagged Action::EncryptAndStore, we couldn't recover
            // the plaintext to encrypt.
            //
            // Walk for any future-shape matches and surface a clear
            // error if one appears (defensive — should never fire
            // until classify learns cleartext capture).
            let mut encrypt_count = 0usize;
            for per_component in &state.classifications {
                for m in per_component {
                    if matches!(m.action, classify::Action::EncryptAndStore) {
                        encrypt_count += 1;
                    }
                }
            }
            if encrypt_count > 0 {
                // Touch `self` so the unused-field lint doesn't fire
                // on `secrets` + `actor_id` before the path activates.
                let _ = (&self.secrets, &self.actor_id);
                return Err(Error::Internal(format!(
                    "EncryptAndStoreStage: ContentClassMatch cleartext capture not yet \
                     wired in v1.0.0; deferred until ClassifyStage carries pre-scrub spans \
                     (observed {encrypt_count} EncryptAndStore-tagged matches)"
                )));
            }
            state.stages_executed.push("encrypt_and_store".to_string());
            Ok(())
        }
    }
}

// ─── v0.7.5: default pipeline factories ─────────────────────────────

/// Minimal pipeline factory — wires the stages persist has concrete
/// implementations for in v0.7.5. Currently: `extract` only.
///
/// The full FSD §5.2 inbound factory wiring Classify → Scrub →
/// EncryptAndStore → Extract is in [`default_inbound_pipeline`]
/// when all four features are enabled. The SPEAK-side scan/swap
/// factory is [`default_outbound_pipeline`] (Classify + Scrub only
/// — see its doc for the asymmetric stage set).
///
/// Use `minimal_pipeline` for unit tests + sovereign-mode embedded
/// contexts where only extract is needed.
#[cfg(feature = "extract")]
pub fn minimal_pipeline() -> Pipeline<BatchEnvelope> {
    PipelineBuilder::<BatchEnvelope>::new()
        .add_stage(ExtractStage::new())
        .build()
        .expect("minimal_pipeline: ExtractStage has no dependencies, build must succeed")
}

/// FSD §5.2 default pipeline — Classify → Scrub → EncryptAndStore →
/// Extract. Closes CIRISPersist#33 parts 1-2 for v1.0.0.
///
/// Requires the full feature set (`classify`, `scrub`, `extract`,
/// `secrets`). Pass a shared [`SecretsService`](crate::secrets::SecretsService)
/// handle for the encrypt-and-store stage's `store_secret` calls;
/// `actor_id` is the audit-log accessor token (typically
/// `"pipeline:edge"` or `"pipeline:embedded"`).
///
/// # v1.0.0 caveats
///
/// - `ClassifyStage` populates empty per-component classification
///   vecs (the matcher catalog ships post-#33).
/// - `EncryptAndStoreStage` records itself but does not write any
///   secrets (`ContentClassMatch` doesn't yet carry pre-scrub
///   cleartext — see the stage's doc comment).
/// - `ScrubStage` + `ExtractStage` are live and produce real output.
///
/// # Direction
///
/// Inbound: envelope received from network → verified → pipelined
/// → stored. Use [`default_outbound_pipeline`] for the SPEAK-side
/// scan/swap path that runs before the agent emits an envelope to
/// the network (CIRISAgent#756 concern #1).
#[cfg(all(
    feature = "classify",
    feature = "scrub",
    feature = "extract",
    feature = "secrets"
))]
pub fn default_inbound_pipeline<S>(
    secrets: std::sync::Arc<S>,
    actor_id: impl Into<String>,
) -> Pipeline<BatchEnvelope>
where
    S: crate::secrets::SecretsService + Send + Sync + 'static,
{
    PipelineBuilder::<BatchEnvelope>::new()
        .add_stage(ClassifyStage::new())
        .add_stage(ScrubStage::new())
        .add_stage(EncryptAndStoreStage::<S, BatchEnvelope>::new(
            secrets, actor_id,
        ))
        .add_stage(ExtractStage::new())
        .build()
        .expect(
            "default_inbound_pipeline: Classify → Scrub → EncryptAndStore → Extract \
             dependency chain is valid",
        )
}

/// Outbound SPEAK-side scan/swap pipeline factory (CIRISAgent#756
/// concern #1, FSD §5.2 bidirectional).
///
/// Runs Classify + Scrub only — the asymmetric set versus
/// [`default_inbound_pipeline`]:
///
/// - **No EncryptAndStore.** Outbound envelopes are emitted to the
///   network; storing secrets the agent is *speaking* would be
///   contradictory (the recipient would still see the cleartext on
///   the wire if we encrypted-and-substituted, and storing the
///   secret locally invites later leakage). Outbound policy is
///   detect-and-scrub-or-block; never detect-and-store.
/// - **No Extract.** Features are stored alongside inbound traces
///   for corpus + drift detection. Outbound envelopes aren't corpus
///   rows; the agent's own VisibilityService handles outbound
///   observability separately.
///
/// What runs:
///
/// - `ClassifyStage` populates `state.classifications` with detected
///   spans so the agent's policy layer (AdaptiveFilterService policy
///   side) can decide whether to send / block / redact / defer.
/// - `ScrubStage` redacts payload spans in-place (`fields_modified`
///   counted, `pii_scrubbed` flag set). On a successful run the
///   envelope is safe to emit; the agent reads the sidecar to
///   decide whether to gate the send.
///
/// Requires the `classify` + `scrub` features (not `secrets` or
/// `extract`). Use this on the SPEAK path BEFORE handing the
/// envelope to the outbound adapter.
#[cfg(all(feature = "classify", feature = "scrub"))]
pub fn default_outbound_pipeline<E: WireEnvelope + 'static>() -> Pipeline<E> {
    PipelineBuilder::<E>::new()
        .add_stage(ClassifyStage::new())
        .add_stage(ScrubStage::new())
        .build()
        .expect("default_outbound_pipeline: Classify → Scrub dependency chain is valid")
}

/// v1.1.0 (CIRISPersist#33): SPEAK / LLM-prompt outbound factory —
/// Classify + Scrub + EncryptAndStore over an
/// [`InlineTextEnvelope`].
///
/// # Why this stage set?
///
/// Agent SPEAK responses (CIRISAgent#756 concern #1) and LLM prompts
/// CAN contain secrets the agent needs to encrypt-and-store BEFORE
/// they leave the agent boundary. Unlike outbound trace envelopes
/// (which never store — see [`default_outbound_pipeline`]),
/// inline-text outbound CAN substitute cleartext with
/// `{SECRET:uuid:description}` placeholders pre-emit and stash the
/// recoverable cleartext via the [`SecretsService`](crate::secrets::SecretsService).
///
/// No Extract — outbound inline text isn't a corpus row.
#[cfg(all(feature = "classify", feature = "scrub", feature = "secrets"))]
pub fn default_speak_pipeline<S>(
    secrets: std::sync::Arc<S>,
    actor_id: impl Into<String>,
) -> Pipeline<InlineTextEnvelope>
where
    S: crate::secrets::SecretsService + Send + Sync + 'static,
{
    PipelineBuilder::<InlineTextEnvelope>::new()
        .add_stage(ClassifyStage::new())
        .add_stage(ScrubStage::new())
        .add_stage(EncryptAndStoreStage::<S, InlineTextEnvelope>::new(
            secrets, actor_id,
        ))
        .build()
        .expect(
            "default_speak_pipeline: Classify → Scrub → EncryptAndStore dependency \
             chain is valid",
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_kind_tokens_stable() {
        assert_eq!(
            Error::StageRejected {
                stage: "scrub",
                reason: "x".into(),
            }
            .kind(),
            "pipeline_rejected"
        );
        assert_eq!(
            Error::StageExternal {
                stage: "scrub",
                reason: "x".into(),
            }
            .kind(),
            "pipeline_external"
        );
        assert_eq!(Error::Internal("x".into()).kind(), "pipeline_internal");
        assert_eq!(
            Error::MissingDependency {
                required_by: "extract",
                missing: "classify",
            }
            .kind(),
            "pipeline_missing_dep"
        );
    }

    #[test]
    fn pipeline_state_default_empty() {
        let s = PipelineState::default();
        assert!(s.stages_executed.is_empty());
        assert_eq!(s.fields_modified, 0);
        #[cfg(feature = "classify")]
        assert!(s.classifications.is_empty());
        #[cfg(feature = "extract")]
        assert!(s.features.is_none());
    }

    /// v0.7.5: orchestrator dependency validation runs at build
    /// time, not run time. A stage that declares a dependency on a
    /// stage that wasn't added earlier fails [`PipelineBuilder::build`]
    /// with `MissingDependency`.
    #[cfg(feature = "extract")]
    #[test]
    fn pipeline_builder_rejects_missing_dependency() {
        struct DependsOnClassify;
        impl Stage<BatchEnvelope> for DependsOnClassify {
            fn name(&self) -> &'static str {
                "depends_on_classify"
            }
            fn dependencies(&self) -> &'static [&'static str] {
                &["classify"]
            }
            #[allow(clippy::manual_async_fn)]
            fn run<'a>(
                &'a self,
                _env: &'a mut BatchEnvelope,
                _state: &'a mut PipelineState,
            ) -> impl Future<Output = Result<(), Error>> + Send + 'a {
                async { Ok(()) }
            }
        }
        let err = PipelineBuilder::<BatchEnvelope>::new()
            .add_stage(DependsOnClassify)
            .build()
            .unwrap_err();
        match err {
            Error::MissingDependency {
                required_by,
                missing,
            } => {
                assert_eq!(required_by, "depends_on_classify");
                assert_eq!(missing, "classify");
            }
            other => panic!("expected MissingDependency, got {other:?}"),
        }
    }

    /// v0.7.5: stage_names reports the registered stages in
    /// declaration order, useful for tests and dashboards.
    #[cfg(feature = "extract")]
    #[test]
    fn pipeline_stage_names_in_declaration_order() {
        let p = PipelineBuilder::<BatchEnvelope>::new()
            .add_stage(ExtractStage::new())
            .build()
            .unwrap();
        assert_eq!(p.stage_names(), vec!["extract"]);
    }

    /// v0.7.5: minimal_pipeline factory wires ExtractStage. Caller
    /// runs against an empty BatchEnvelope and asserts the stage
    /// records its name in stages_executed without populating
    /// features (no traces to extract from).
    #[cfg(feature = "extract")]
    #[tokio::test]
    async fn minimal_pipeline_runs_extract_on_empty_batch() {
        let p = minimal_pipeline();
        assert_eq!(p.stage_names(), vec!["extract"]);

        let mut env = BatchEnvelope {
            events: Vec::new(),
            batch_timestamp: chrono::Utc::now(),
            consent_timestamp: chrono::Utc::now(),
            trace_level: crate::schema::TraceLevel::Generic,
            trace_schema_version: crate::schema::SchemaVersion::parse("2.7.9").unwrap(),
            correlation_metadata: None,
        };
        let mut state = PipelineState::default();
        p.run(&mut env, &mut state).await.unwrap();
        assert_eq!(state.stages_executed, vec!["extract".to_string()]);
        assert!(state.features.is_none(), "empty batch has no features");
    }

    // ── v1.0.0 (CIRISPersist#33): test helpers for the new stages ──

    /// Build a BatchEnvelope carrying one CompleteTrace with one
    /// component whose payload contains both a regex-detectable PII
    /// span (email) and a year (also caught by the regex pass —
    /// stresses ScrubStage's residue check).
    #[cfg(any(feature = "classify", feature = "scrub"))]
    fn fixture_envelope_with_pii(level: crate::schema::TraceLevel) -> BatchEnvelope {
        let mut data = serde_json::Map::new();
        data.insert(
            "task_description".to_string(),
            serde_json::Value::String(
                "Contact alice@example.com about the 1989 incident.".to_string(),
            ),
        );
        let component = crate::schema::TraceComponent {
            component_type: crate::schema::ComponentType::Conscience,
            event_type: crate::schema::ReasoningEventType::ThoughtStart,
            timestamp: "2026-04-30T00:16:00Z".parse().unwrap(),
            data,
            agent_id_hash: None,
        };
        let trace = crate::schema::CompleteTrace {
            trace_id: "trace-test".into(),
            thought_id: "th_test".into(),
            task_id: Some("task_test".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: "2026-04-30T00:15:53Z".parse().unwrap(),
            completed_at: "2026-04-30T00:16:12Z".parse().unwrap(),
            trace_level: level,
            trace_schema_version: crate::schema::SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![component],
            deployment_profile: None,
            cohort_scope: "federation".into(),
            cohort_target_id: None,
            signature: "AAAA".into(),
            signature_key_id: "ciris-agent-key:dead".into(),
            signature_ml_dsa_65: None,
            pubkey_ml_dsa_65: None,
            pqc_key_id: None,
        };
        BatchEnvelope {
            events: vec![crate::schema::BatchEvent::CompleteTrace {
                trace,
                trace_level: level,
            }],
            batch_timestamp: chrono::Utc::now(),
            consent_timestamp: chrono::Utc::now(),
            trace_level: level,
            trace_schema_version: crate::schema::SchemaVersion::parse("2.7.0").unwrap(),
            correlation_metadata: None,
        }
    }

    /// v1.0.0: ClassifyStage runs and records its name, populating
    /// one (empty in v1.0.0 — matcher catalog ships post-#33)
    /// per-component classification vec. FSD §4.3 invariant 5:
    /// outer-vec length equals component count.
    #[cfg(feature = "classify")]
    #[tokio::test]
    async fn classify_stage_populates_classifications() {
        let p = PipelineBuilder::<BatchEnvelope>::new()
            .add_stage(ClassifyStage::new())
            .build()
            .unwrap();
        let mut env = fixture_envelope_with_pii(crate::schema::TraceLevel::Generic);
        let mut state = PipelineState::default();
        p.run(&mut env, &mut state).await.unwrap();
        assert_eq!(state.stages_executed, vec!["classify".to_string()]);
        // One CompleteTrace with one component → one outer entry.
        assert_eq!(state.classifications.len(), 1);
        // Inner vec is empty until matcher catalog lands post-#33.
        assert!(state.classifications[0].is_empty());
    }

    /// v1.0.0: ScrubStage runs after ClassifyStage, mutates the
    /// envelope in place, and flips `pii_scrubbed` once the regex
    /// pass catches the embedded email + year. `fields_modified`
    /// must be > 0.
    #[cfg(all(feature = "classify", feature = "scrub"))]
    #[tokio::test]
    async fn scrub_stage_mutates_envelope_and_sets_pii_scrubbed() {
        let p = PipelineBuilder::<BatchEnvelope>::new()
            .add_stage(ClassifyStage::new())
            .add_stage(ScrubStage::new())
            .build()
            .unwrap();
        let mut env = fixture_envelope_with_pii(crate::schema::TraceLevel::Detailed);
        let mut state = PipelineState::default();
        p.run(&mut env, &mut state).await.unwrap();
        assert_eq!(
            state.stages_executed,
            vec!["classify".to_string(), "scrub".to_string()]
        );
        assert!(state.fields_modified > 0, "regex pass should have fired");
        assert!(
            state.pii_scrubbed,
            "pii_scrubbed must follow fields_modified > 0"
        );
        // The original text must no longer appear; redaction marker
        // must be present.
        let crate::schema::BatchEvent::CompleteTrace { trace, .. } = &env.events[0];
        let text = trace.components[0].data["task_description"]
            .as_str()
            .unwrap();
        assert!(!text.contains("alice@example.com"));
        assert!(!text.contains("1989"));
        assert!(text.contains("[EMAIL]") || text.contains("[YEAR]"));
    }

    /// Tiny in-test [`crate::secrets::SecretsService`] — every method
    /// returns either Ok of a stubbed value or NotImplemented. Only
    /// present so EncryptAndStoreStage has something to hold; v1.0.0
    /// stub never actually calls into it.
    #[cfg(all(feature = "secrets", feature = "scrub"))]
    struct MockSecrets;

    #[cfg(all(feature = "secrets", feature = "scrub"))]
    impl crate::secrets::SecretsService for MockSecrets {
        fn store_secret(
            &self,
            _key: String,
            _value: String,
            _accessor: String,
        ) -> impl Future<Output = Result<(), crate::secrets::SecretsError>> + Send {
            async { Ok(()) }
        }
        fn retrieve_secret(
            &self,
            _key: &str,
            _accessor: String,
        ) -> impl Future<Output = Result<Option<String>, crate::secrets::SecretsError>> + Send
        {
            async { Ok(None) }
        }
        fn recall_secret(
            &self,
            _uuid: &str,
            _purpose: String,
            _accessor: String,
            _decrypt: bool,
        ) -> impl Future<
            Output = Result<
                Option<crate::secrets::types::SecretRecallResult>,
                crate::secrets::SecretsError,
            >,
        > + Send {
            async { Ok(None) }
        }
        fn list_stored_secrets(
            &self,
            _limit: usize,
            _filter: crate::secrets::types::SecretsListFilter,
        ) -> impl Future<
            Output = Result<
                Vec<crate::secrets::types::SecretReference>,
                crate::secrets::SecretsError,
            >,
        > + Send {
            async { Ok(Vec::new()) }
        }
        fn forget_secret(
            &self,
            _uuid: &str,
            _accessor: String,
        ) -> impl Future<Output = Result<bool, crate::secrets::SecretsError>> + Send {
            async { Ok(false) }
        }
        fn process_incoming_text(
            &self,
            _text: &str,
            _source_message_id: &str,
            _accessor: String,
        ) -> impl Future<
            Output = Result<
                (String, Vec<crate::secrets::types::SecretReference>),
                crate::secrets::SecretsError,
            >,
        > + Send {
            async { Err(crate::secrets::SecretsError::Internal("mock".into())) }
        }
        fn decapsulate_secrets_in_parameters(
            &self,
            _action_type: &str,
            params: serde_json::Value,
            _ctx: crate::secrets::types::DecapsulationContext,
        ) -> impl Future<Output = Result<serde_json::Value, crate::secrets::SecretsError>> + Send
        {
            async move { Ok(params) }
        }
        fn encrypt(
            &self,
            _plaintext: &str,
        ) -> impl Future<Output = Result<String, crate::secrets::SecretsError>> + Send {
            async { Ok(String::new()) }
        }
        fn decrypt(
            &self,
            _ciphertext: &str,
        ) -> impl Future<Output = Result<String, crate::secrets::SecretsError>> + Send {
            async { Ok(String::new()) }
        }
        fn get_filter_config(
            &self,
        ) -> impl Future<
            Output = Result<crate::secrets::types::FilterConfig, crate::secrets::SecretsError>,
        > + Send {
            async {
                Err(crate::secrets::SecretsError::Internal(
                    "mock filter config".into(),
                ))
            }
        }
        fn update_filter_config(
            &self,
            _updates: crate::secrets::types::FilterUpdateRequest,
            _accessor: String,
        ) -> impl Future<
            Output = Result<
                crate::secrets::types::FilterUpdateResult,
                crate::secrets::SecretsError,
            >,
        > + Send {
            async {
                Err(crate::secrets::SecretsError::Internal(
                    "mock filter update".into(),
                ))
            }
        }
        fn get_service_stats(
            &self,
        ) -> impl Future<
            Output = Result<
                crate::secrets::types::SecretsServiceStats,
                crate::secrets::SecretsError,
            >,
        > + Send {
            async { Err(crate::secrets::SecretsError::Internal("mock stats".into())) }
        }
        fn is_healthy(
            &self,
        ) -> impl Future<Output = Result<bool, crate::secrets::SecretsError>> + Send {
            async { Ok(true) }
        }
        fn get_access_logs(
            &self,
            _secret_uuid: Option<&str>,
            _limit: usize,
        ) -> impl Future<
            Output = Result<
                Vec<crate::secrets::types::AccessLogEntry>,
                crate::secrets::SecretsError,
            >,
        > + Send {
            async { Ok(Vec::new()) }
        }
        fn reencrypt_all(
            &self,
            _new_master_key_ref: crate::secrets::types::MasterKeyRef,
            _accessor: String,
        ) -> impl Future<
            Output = Result<crate::secrets::types::RotationResult, crate::secrets::SecretsError>,
        > + Send {
            async {
                Err(crate::secrets::SecretsError::Internal(
                    "mock reencrypt".into(),
                ))
            }
        }
        fn rotate_master_key(
            &self,
            _new_master: Option<Vec<u8>>,
            _accessor: String,
        ) -> impl Future<
            Output = Result<crate::secrets::types::MasterKeyRef, crate::secrets::SecretsError>,
        > + Send {
            async { Err(crate::secrets::SecretsError::Internal("mock rotate".into())) }
        }
        fn test_encryption(
            &self,
        ) -> impl Future<Output = Result<bool, crate::secrets::SecretsError>> + Send {
            async { Ok(true) }
        }
        fn migrate_to_hardware_key(
            &self,
            _accessor: String,
        ) -> impl Future<
            Output = Result<crate::secrets::types::MasterKeyRef, crate::secrets::SecretsError>,
        > + Send {
            async {
                Err(crate::secrets::SecretsError::HardwareKeyUnavailable(
                    "mock".into(),
                ))
            }
        }
    }

    /// v1.0.0: default_inbound_pipeline factory wires all four stages
    /// in canonical order. The EncryptAndStoreStage is stubbed
    /// (cleartext capture deferred — see stage doc) so encrypted_secrets
    /// stays empty, but the stage still records itself.
    #[cfg(all(
        feature = "classify",
        feature = "scrub",
        feature = "extract",
        feature = "secrets"
    ))]
    #[tokio::test]
    async fn default_inbound_pipeline_runs_all_four_stages() {
        let secrets = std::sync::Arc::new(MockSecrets);
        let p = default_inbound_pipeline(secrets, "pipeline:test");
        assert_eq!(
            p.stage_names(),
            vec!["classify", "scrub", "encrypt_and_store", "extract"]
        );

        let mut env = fixture_envelope_with_pii(crate::schema::TraceLevel::Detailed);
        let mut state = PipelineState::default();
        p.run(&mut env, &mut state).await.unwrap();

        assert_eq!(
            state.stages_executed,
            vec![
                "classify".to_string(),
                "scrub".to_string(),
                "encrypt_and_store".to_string(),
                "extract".to_string()
            ]
        );
        // v1.0.0 stub: no encrypted secrets land.
        assert!(state.encrypted_secrets.is_empty());
        // Scrub + extract are real — should have produced output.
        assert!(state.pii_scrubbed);
        assert!(state.features.is_some());
    }

    /// v1.0.0: default_outbound_pipeline wires Classify + Scrub only
    /// — the asymmetric SPEAK-side stage set per CIRISAgent#756
    /// concern #1. No EncryptAndStore (outbound never stores
    /// secrets) and no Extract (outbound isn't a corpus row).
    #[cfg(all(feature = "classify", feature = "scrub"))]
    #[tokio::test]
    async fn default_outbound_pipeline_runs_classify_then_scrub_only() {
        let p = default_outbound_pipeline::<BatchEnvelope>();
        assert_eq!(p.stage_names(), vec!["classify", "scrub"]);

        let mut env = fixture_envelope_with_pii(crate::schema::TraceLevel::Detailed);
        let mut state = PipelineState::default();
        p.run(&mut env, &mut state).await.unwrap();

        assert_eq!(
            state.stages_executed,
            vec!["classify".to_string(), "scrub".to_string()]
        );
        // Scrub is live — should have redacted.
        assert!(state.pii_scrubbed);
        // No extract ran — features stays None.
        #[cfg(feature = "extract")]
        assert!(state.features.is_none());
        // No encrypt_and_store ran — encrypted_secrets stays empty.
        #[cfg(feature = "secrets")]
        assert!(state.encrypted_secrets.is_empty());
    }

    // ── v1.1.0 (CIRISPersist#33): InlineTextEnvelope + speak path ──

    /// v1.1.0: ClassifyStage runs over an `InlineTextEnvelope`,
    /// pushes one (empty in v1.0.0) inner classification vec —
    /// outer-vec length equals `body_count()` (1 for inline).
    #[cfg(feature = "classify")]
    #[tokio::test]
    async fn classify_stage_runs_over_inline_text_envelope() {
        let p = PipelineBuilder::<InlineTextEnvelope>::new()
            .add_stage(ClassifyStage::new())
            .build()
            .unwrap();
        let mut env = InlineTextEnvelope::new("Contact alice@example.com about 1989.");
        let mut state = PipelineState::default();
        p.run(&mut env, &mut state).await.unwrap();
        assert_eq!(state.stages_executed, vec!["classify".to_string()]);
        // One body for inline → one outer-vec entry.
        assert_eq!(state.classifications.len(), 1);
        assert!(state.classifications[0].is_empty());
    }

    /// v1.1.0: ScrubStage runs over an `InlineTextEnvelope`,
    /// regex-scrubs the inline text in place, flips `pii_scrubbed`.
    #[cfg(all(feature = "classify", feature = "scrub"))]
    #[tokio::test]
    async fn scrub_stage_redacts_inline_text_envelope() {
        let p = PipelineBuilder::<InlineTextEnvelope>::new()
            .add_stage(ClassifyStage::new())
            .add_stage(ScrubStage::new())
            .build()
            .unwrap();
        let mut env = InlineTextEnvelope::new("Contact alice@example.com about 1989.");
        let mut state = PipelineState::default();
        p.run(&mut env, &mut state).await.unwrap();
        assert_eq!(
            state.stages_executed,
            vec!["classify".to_string(), "scrub".to_string()]
        );
        assert!(state.fields_modified > 0);
        assert!(state.pii_scrubbed);
        assert!(!env.text.contains("alice@example.com"));
        assert!(!env.text.contains("1989"));
        assert!(env.text.contains("[EMAIL]") || env.text.contains("[YEAR]"));
    }

    /// v1.1.0: `default_outbound_pipeline` is generic — can be
    /// instantiated for `InlineTextEnvelope` (SPEAK scan-only path,
    /// no EncryptAndStore).
    #[cfg(all(feature = "classify", feature = "scrub"))]
    #[tokio::test]
    async fn default_outbound_pipeline_inline_text_runs_classify_scrub() {
        let p = default_outbound_pipeline::<InlineTextEnvelope>();
        assert_eq!(p.stage_names(), vec!["classify", "scrub"]);
        let mut env = InlineTextEnvelope::new("Reach me at alice@example.com.");
        let mut state = PipelineState::default();
        p.run(&mut env, &mut state).await.unwrap();
        assert!(state.pii_scrubbed);
        assert!(env.text.contains("[EMAIL]"));
    }

    /// v1.1.0: `default_speak_pipeline` factory wires Classify +
    /// Scrub + EncryptAndStore over `InlineTextEnvelope`. The
    /// EncryptAndStoreStage stub records itself but doesn't write
    /// any secrets (matcher catalog stubbed).
    #[cfg(all(feature = "classify", feature = "scrub", feature = "secrets"))]
    #[tokio::test]
    async fn default_speak_pipeline_runs_all_three_stages() {
        let secrets = std::sync::Arc::new(MockSecrets);
        let p = default_speak_pipeline(secrets, "pipeline:speak");
        assert_eq!(
            p.stage_names(),
            vec!["classify", "scrub", "encrypt_and_store"]
        );
        let mut env = InlineTextEnvelope::new("My email is alice@example.com.");
        let mut state = PipelineState::default();
        p.run(&mut env, &mut state).await.unwrap();
        assert_eq!(
            state.stages_executed,
            vec![
                "classify".to_string(),
                "scrub".to_string(),
                "encrypt_and_store".to_string(),
            ]
        );
        assert!(state.pii_scrubbed);
        // No real encrypt path — encrypted_secrets stays empty.
        assert!(state.encrypted_secrets.is_empty());
        assert!(env.text.contains("[EMAIL]"));
    }
}
