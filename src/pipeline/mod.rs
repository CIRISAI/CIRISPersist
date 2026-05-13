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

pub mod types;

pub use types::{HybridSignatureBlock, PipelineEnvelope, PipelineMetadata, PipelineSidecar};

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

use crate::schema::BatchEnvelope;

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
/// `BatchEnvelope`.
///
/// Lifecycle: the orchestrator calls [`Stage::run`] in dependency
/// order (defined by [`Stage::dependencies`]). The stage may:
///
/// - Mutate `env` in place (e.g. scrub redacting spans).
/// - Append to `prior` (e.g. classify adding to `classifications`).
/// - Return its own typed `Output` (consumed only by the orchestrator
///   for stage-specific bookkeeping; downstream stages read via
///   `prior`).
///
/// Mission alignment (FSD §3.3 step 3): a stage that errors MUST
/// short-circuit the pipeline — the orchestrator propagates the
/// `Error` and rejects the batch. There is no partial-success path.
///
/// v0.6.0-α: scaffolding-only; concrete stages land with the scrub
/// (α2) and extract (α3) lifts.
pub trait Stage: Send + Sync {
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

    /// Apply the stage's transformation. `env` is the in-flight batch
    /// (post-verify, pre-store); `state` accumulates side-channel
    /// outputs from this + prior stages.
    fn run<'a>(
        &'a self,
        env: &'a mut BatchEnvelope,
        state: &'a mut PipelineState,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'a;
}

// ─── v0.7.5 (CIRISPersist#33): orchestrator surface ─────────────────

/// Object-safe shim around [`Stage`] for dyn-dispatch in the
/// [`Pipeline`] builder. The `Stage` trait uses an `impl Future`
/// return type for ergonomic direct calls; that form isn't
/// object-safe, so we project to a boxed future here. Auto-impl'd
/// for every concrete `T: Stage`.
pub trait ErasedStage: Send + Sync {
    /// See [`Stage::name`].
    fn name(&self) -> &'static str;
    /// See [`Stage::dependencies`].
    fn dependencies(&self) -> &'static [&'static str];
    /// Run the stage. Returns a boxed future so the orchestrator can
    /// hold a `Vec<Box<dyn ErasedStage>>`.
    fn run_erased<'a>(
        &'a self,
        env: &'a mut BatchEnvelope,
        state: &'a mut PipelineState,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<(), Error>> + Send + 'a>>;
}

impl<T: Stage> ErasedStage for T {
    fn name(&self) -> &'static str {
        Stage::name(self)
    }
    fn dependencies(&self) -> &'static [&'static str] {
        Stage::dependencies(self)
    }
    fn run_erased<'a>(
        &'a self,
        env: &'a mut BatchEnvelope,
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
pub struct Pipeline {
    stages: Vec<Box<dyn ErasedStage>>,
}

impl std::fmt::Debug for Pipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pipeline")
            .field("stages", &self.stage_names())
            .finish()
    }
}

impl Pipeline {
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
    pub async fn run(
        &self,
        env: &mut BatchEnvelope,
        state: &mut PipelineState,
    ) -> Result<(), Error> {
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
pub struct PipelineBuilder {
    stages: Vec<Box<dyn ErasedStage>>,
}

impl PipelineBuilder {
    /// Start an empty builder.
    pub fn new() -> Self {
        Self { stages: Vec::new() }
    }

    /// Append `stage` to the pipeline. Stages run in the order they
    /// were added.
    pub fn add_stage<S: Stage + 'static>(mut self, stage: S) -> Self {
        self.stages.push(Box::new(stage));
        self
    }

    /// Validate stage dependencies + freeze into a [`Pipeline`].
    /// Returns [`Error::MissingDependency`] when any stage's declared
    /// dependency wasn't added earlier in declaration order.
    pub fn build(self) -> Result<Pipeline, Error> {
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

impl Default for PipelineBuilder {
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
impl Stage for ExtractStage {
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

// ─── v0.7.5: default pipeline factories ─────────────────────────────

/// Minimal pipeline factory — wires the stages persist has concrete
/// implementations for in v0.7.5. Currently: `extract` only.
///
/// The full FSD §5.2 `default_pipeline(secrets)` factory wiring
/// Classify → Scrub → EncryptAndStore → Extract waits on:
/// - **Classify**: ClassifyStage + matcher catalog (regex + NER
///   matchers are types-only in v0.7.5; matcher impls are
///   downstream of CIRISPersist#33).
/// - **Scrub**: ScrubStage adapter over the existing
///   [`crate::scrub::Scrubber`] trait (the v0.6.0 lift). Plumbing
///   layered onto the existing scrub_batch path.
/// - **EncryptAndStore**: requires a [`SecretsService`](crate::secrets::SecretsService)
///   handle plus orphan-secret invariant glue.
///
/// Use this for unit tests + sovereign-mode embedded contexts
/// where only extract is needed.
#[cfg(feature = "extract")]
pub fn minimal_pipeline() -> Pipeline {
    PipelineBuilder::new()
        .add_stage(ExtractStage::new())
        .build()
        .expect("minimal_pipeline: ExtractStage has no dependencies, build must succeed")
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
        impl Stage for DependsOnClassify {
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
        let err = PipelineBuilder::new()
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
        let p = PipelineBuilder::new()
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
}
