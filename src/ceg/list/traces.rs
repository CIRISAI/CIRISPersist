//! Section A + B types — trace listing + trace detail.
//!
//! CEG 0.4 trace wire-format; lens / lens-core / sovereign-agent read
//! surface (CIRISPersist#23 §A/§B). Moved from `src/read/trace.rs` in
//! v4.0 (FSD §3.3) — the section-F Coherence-Ratchet scoring rows that
//! previously shared `read/trace.rs` now live in
//! `src/ceg/aggregates/scoring.rs`.
//!
//! These structs cross both the rlib path (Rust-public) and the PyO3
//! path (typed dicts on the Python side; field shape identical). Wire-
//! stable: serde JSON shape is the contract.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ceg::types::TraceCursor;
use crate::schema::{ReasoningEventType, TraceLevel};

// ─── Section A — Trace listing ─────────────────────────────────────

/// One trace summary row — denormalized DMA / conscience / action /
/// cost fields synthesized from the trace's component rows.
///
/// The summary covers ALL component rows of the trace; the per-event
/// detail lives in [`TraceDetail`] (section B).
///
/// AV-9: every summary carries `agent_id_hash`. Callers authorize
/// per-trace reads against this at their layer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceSummary {
    /// Stable trace identifier.
    pub trace_id: String,
    /// Thought-iteration identifier within the trace.
    pub thought_id: String,
    /// Optional originating task identifier.
    pub task_id: Option<String>,

    /// SHA-256 digest of the agent's identity tuple. AV-9 dedup-key
    /// prefix.
    pub agent_id_hash: String,
    /// Optional human-readable agent name.
    pub agent_name: Option<String>,
    /// Agent persona role (from `deployment_profile.agent_role`).
    pub agent_role: Option<String>,
    /// Deployment domain (`healthcare` / `legal` / etc.).
    pub deployment_domain: Option<String>,
    /// Deployment lifecycle stage (`production` / `staging` / etc.).
    pub deployment_type: Option<String>,

    /// First-component timestamp.
    pub started_at: DateTime<Utc>,
    /// Last-component timestamp.
    pub completed_at: DateTime<Utc>,

    /// Trace verbosity level.
    pub trace_level: TraceLevel,
    /// Wire-format schema version the trace was emitted under.
    pub schema_version: String,
    /// True after verify pass succeeded for the trace's components.
    pub signature_verified: bool,
    /// Cognitive-state tag (`work` / `wakeup` / `dream` / etc.).
    pub cognitive_state: Option<String>,
    /// Thought type extracted from `THOUGHT_START.payload.thought_type`.
    pub thought_type: Option<String>,
    /// Thought depth extracted from
    /// `THOUGHT_START.payload.thought_depth`.
    pub thought_depth: Option<i32>,

    // ── DMA scores (extracted from DMA_RESULTS.payload) ──
    /// Common Sense DMA plausibility score.
    pub csdma_plausibility_score: Option<f64>,
    /// Domain-Specific DMA domain-alignment score.
    pub dsdma_domain_alignment: Option<f64>,
    /// Domain-Specific DMA matched domain identifier.
    pub dsdma_domain: Option<String>,
    /// Identity DMA effective-K coefficient.
    pub idma_k_eff: Option<f64>,
    /// Identity DMA correlation-risk metric.
    pub idma_correlation_risk: Option<f64>,
    /// Identity DMA fragility flag.
    pub idma_fragility_flag: Option<bool>,
    /// Identity DMA phase tag.
    pub idma_phase: Option<String>,

    // ── Conscience (extracted from CONSCIENCE_RESULT.payload) ──
    /// True if conscience checks passed.
    pub conscience_passed: Option<bool>,
    /// True if the agent's chosen action was overridden.
    pub action_was_overridden: Option<bool>,
    /// Per-conscience-axis pass flag — entropy bound.
    pub entropy_passed: Option<bool>,
    /// Per-conscience-axis pass flag — coherence bound.
    pub coherence_passed: Option<bool>,
    /// Per-conscience-axis pass flag — optimization-veto bound.
    pub optimization_veto_passed: Option<bool>,
    /// Per-conscience-axis pass flag — epistemic-humility bound.
    pub epistemic_humility_passed: Option<bool>,

    // ── Action (extracted from ACTION_RESULT.payload) ──
    /// The action the agent selected (`speak` / `tool` / `defer` /
    /// etc.).
    pub selected_action: Option<String>,
    /// True if action execution succeeded.
    pub action_success: Option<bool>,

    // ── Cost aggregates (denormalized columns on ACTION_RESULT row) ──
    /// LLM call count summed over the trace.
    pub llm_calls: Option<i32>,
    /// LLM tokens summed over the trace's LLM calls.
    pub tokens_total: Option<i32>,
    /// USD cost summed over the trace's LLM calls.
    pub cost_usd: Option<f64>,
}

/// One page of trace summaries. The cursor is forward-only; paging
/// yields traces in `started_at DESC, trace_id DESC` order
/// (newest-first triage).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceListPage {
    /// Trace summaries ordered newest-first.
    pub items: Vec<TraceSummary>,
    /// Cursor for the next page; `None` when there are no more rows.
    pub next_cursor: Option<TraceCursor>,
}

// ─── Section B — Trace detail ──────────────────────────────────────

/// Full trace reconstruction — summary + all per-component data +
/// LLM calls + envelope-level scrub / signature refs.
///
/// One round-trip per trace; not paged (a single trace fits per spec —
/// production traces top out around 30 components plus a handful of
/// LLM calls).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceDetail {
    /// The summary view (same shape as section A).
    pub summary: TraceSummary,
    /// Component rows in `ts ASC` (chronological) order.
    pub components: Vec<TraceComponentRow>,
    /// LLM call rows in `ts ASC` (chronological) order.
    pub llm_calls: Vec<crate::store::types::TraceLlmCallRow>,
    /// Envelope-level signature + scrub envelope refs.
    pub envelope: TraceEnvelopeRefs,
}

/// One component row in [`TraceDetail::components`]. Subset of
/// [`crate::store::types::TraceEventRow`] — drops the per-row
/// signature / scrub fields that are folded into [`TraceEnvelopeRefs`]
/// (those are envelope-constants across the trace).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceComponentRow {
    /// Step-point tag derived from event_type / payload.
    pub step_point: Option<String>,
    /// Typed event kind.
    pub event_type: ReasoningEventType,
    /// Per-`(thought_id, event_type)` attempt counter.
    pub attempt_index: u32,
    /// Wall-clock at which the event happened.
    pub ts: DateTime<Utc>,
    /// Verbatim component data dict (post-scrub). The agent's
    /// testimony, kept verbatim.
    pub payload: serde_json::Map<String, serde_json::Value>,
}

/// Envelope-level constants for the trace — one set per `trace_id`.
/// AV-24/25 scrub-envelope columns + the agent's signature + key id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceEnvelopeRefs {
    /// Per-trace agent signature.
    pub signature: String,
    /// Agent's signing-key id (resolves through `federation_keys`).
    pub signature_key_id: String,
    /// sha256(canonical(component.data_pre_scrub)).
    pub original_content_hash: Option<String>,
    /// base64(ed25519_sign(canonical(component.data_post_scrub))).
    pub scrub_signature: Option<String>,
    /// Deployment's signing-key id (lens-scrub-v1, etc.).
    pub scrub_key_id: Option<String>,
    /// When the scrub+sign happened.
    pub scrub_timestamp: Option<DateTime<Utc>>,
    /// True after the scrubber pass ran.
    pub pii_scrubbed: bool,
}
