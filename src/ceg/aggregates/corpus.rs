//! Section G — Corpus shape primitive.
//!
//! Moved from `src/read/corpus.rs` in v4.0 (FSD §3.3).
//!
//! Drives `scripts/corpus_shape.py` and federation-side cohort
//! dashboards. Persist owns the derivation (task_id → task_class,
//! qa_* → language / question_num, primary model per trace) so every
//! federation peer sees the same shape for the same corpus window.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::ceg::list::tasks::TaskClass;
use crate::ceg::types::TimeWindow;

/// Filter for [`crate::ceg::ReadEngine::corpus_shape`].
///
/// `time_window` is required (corpus shape is inherently windowed —
/// without a window the rollup is unbounded and not comparable to
/// stationarity baselines). Other filters are optional and compose
/// AND-style with the window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusShapeFilter {
    /// Window on `ts`. Required.
    pub time_window: TimeWindow,

    /// Filter by `agent_id_hash`. AV-9: caller authorizes.
    pub agent_id_hash: Option<String>,

    /// Filter by `agent_name`.
    pub agent_name: Option<String>,

    /// Filter by `deployment_domain`.
    pub deployment_domain: Option<String>,
}

/// Corpus-shape rollup for a window. Every breakdown counts
/// **distinct traces** (not events) so the bucket totals reflect
/// trace-axis distribution.
///
/// Empty rollups: a window with no traces returns `total_traces = 0`
/// and every map empty (NOT a NULL hazard — COALESCE'd at SQL layer
/// per v0.5.1 / CIRISPersist#24 hygiene).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CorpusShape {
    /// The window the rollup covers.
    pub window: TimeWindow,

    /// Total distinct traces in the window matching the filter.
    pub total_traces: i64,

    /// Distinct-trace count per [`TaskClass`] (derived via
    /// [`TaskClass::from_task_id`]).
    pub by_task_class: HashMap<TaskClass, i64>,

    /// Distinct-trace count per QA-eval language token. Populated only
    /// for traces whose `task_id` matches the canonical
    /// `qa_<lang>_<question_num>` shape; non-QA traces are absent.
    pub by_qa_language: HashMap<String, i64>,

    /// Distinct-trace count per QA-eval question number (extracted
    /// from `qa_<lang>_<question_num>`). Non-QA traces absent.
    pub by_qa_question_num: HashMap<i32, i64>,

    /// Distinct-trace count per `agent_name`.
    pub by_agent_name: HashMap<String, i64>,

    /// Distinct-trace count per `agent_template` (the federation-
    /// stable agent identity-version tag — e.g. "ally-v3-default").
    /// Spec calls this `by_agent_version`; persist surfaces the
    /// template tag since agents don't carry a separate "version"
    /// column and `agent_template` is the closest invariant.
    pub by_agent_version: HashMap<String, i64>,

    /// Distinct-trace count per primary model. A trace's "primary
    /// model" is the model with the most LLM calls in that trace
    /// (ties broken by alphabetical order of model id). Traces with
    /// no LLM calls are absent from this map.
    pub by_primary_model: HashMap<String, i64>,

    /// Distinct-trace count per `deployment_region`.
    pub by_deployment_region: HashMap<String, i64>,

    /// Window-vs-tail stationarity signal. Reserved for a future
    /// API extension that takes a `baseline_window`; v0.5.5 returns
    /// `None` because corpus_shape's input shape doesn't carry a
    /// baseline. Lens can compute its own stationarity z-score by
    /// calling `corpus_shape` twice (window vs. tail) and comparing
    /// the distributions.
    pub stationarity_z_score: Option<f64>,
}
