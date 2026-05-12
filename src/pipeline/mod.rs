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

#[cfg(feature = "scrub")]
pub mod scrub;

#[cfg(feature = "classify")]
pub use classify::{
    Action, ContentClass, ContentClassMatch, DetectionMethod, LearningState, Sensitivity,
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

    /// Total field-modifications applied by scrub stages this run.
    /// Aggregated across every Scrubber call site for batch-level
    /// metrics. Lens dashboards read this.
    pub fields_modified: usize,

    /// Ordered list of stage names that ran. Populated as each stage
    /// completes; consumers can detect "stage X was skipped" via
    /// absence here.
    pub stages_executed: Vec<&'static str>,
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
    }
}
