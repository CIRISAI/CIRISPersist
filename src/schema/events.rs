//! Per-event types and typed accessors over the component `data` blob.
//!
//! # Mission alignment (MISSION.md §2 — `schema/`)
//!
//! The wire format §4 says: `data` is event-type-specific JSON; the
//! lens stores it verbatim as JSONB (FSD §3.3 step 4 +
//! `context/lens_027_trace_events.sql` line 26). What the lens *needs
//! to type* is the extracted shape: `attempt_index` (the dedup key
//! tail per FSD §3.3 step 5; TRACE_WIRE_FORMAT.md §6), the audit
//! anchor on `ACTION_RESULT` (FSD §3.2), the cost summary on
//! `ACTION_RESULT` (denormalized columns in the SQL), the
//! `LLM_CALL` shape (parent linkage and the `trace_llm_calls`
//! sibling-table fields per FSD §3.3 step 4 +
//! TRACE_EVENT_LOG_PERSISTENCE.md §5.2).
//!
//! Each accessor returns a typed `Option<T>` or `Result<T,
//! schema::Error>`; absence is meaningful at lower trace levels per
//! TRACE_WIRE_FORMAT.md §7 (the `_strip_empty` rule), so callers
//! handle absence as "not emitted at this trace level," not "missing."

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// `component_type` enum (TRACE_WIRE_FORMAT.md §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentType {
    /// Passive observation of agent state.
    Observation,
    /// Context snapshot — operating environment.
    Context,
    /// Rationale step in the reasoning chain.
    Rationale,
    /// Conscience evaluation step.
    Conscience,
    /// Selected action (the verb).
    Action,
    /// Second-pass evaluation of a verb.
    VerbSecondPass,
    /// Individual LLM call (sibling-table candidate).
    LlmCall,
    /// Forward-compat fallback for unrecognized component types.
    Unknown,
}

/// `event_type` enum (TRACE_WIRE_FORMAT.md §4 + §5).
///
/// Discriminant for the dedup key
/// `(trace_id, thought_id, event_type, attempt_index)` (FSD §3.3 step
/// 5; SQL migration `trace_events_lookup` index in
/// `context/lens_027_trace_events.sql`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReasoningEventType {
    /// §5.1 — once per thought.
    ThoughtStart,
    /// §5.2 — once per thought (or absent on follow-up thoughts).
    SnapshotAndContext,
    /// §5.3 — once per thought.
    DmaResults,
    /// §5.4 — once per thought.
    IdmaResult,
    /// §5.5 — fires multiple times if conscience overrides trigger
    /// recursive retries; `attempt_index` increments.
    AspdmaResult,
    /// §5.6 — deprecated in 2.7.8; the agent still emits it during
    /// the transition window. Lens prefers `VerbSecondPassResult`;
    /// this variant exists so we don't reject incoming traffic.
    /// Mission (MISSION.md §3): no silent rejection of in-spec
    /// payloads.
    TsaspdmaResult,
    /// §5.7 — fires once per thought when the selected verb has a
    /// registered second-pass evaluator.
    VerbSecondPassResult,
    /// §5.8 — fires multiple times per thought (initial + recursive
    /// retries + finalization).
    ConscienceResult,
    /// §5.9 — fires once per thought; **seals the trace**. Carries
    /// the audit anchor (FSD §3.2).
    ActionResult,
    /// §5.10 — fires N times per thought (every individual provider
    /// invocation, success or failure). Sibling-table candidate per
    /// FSD §3.3 step 4 / TRACE_EVENT_LOG_PERSISTENCE.md §5.2.
    LlmCall,
    /// Used by the agent's `attempt_index` semantics (§6) discussion
    /// even though it doesn't appear in the §4 type table; carry the
    /// variant so we can ingest if/when the agent ships it. Marked
    /// dead-code suppress until that lands.
    #[allow(dead_code)]
    RoundComplete,
}

impl ReasoningEventType {
    /// `event_type.value` representation matching the agent's emitter
    /// (`runtime_control.py`, `accord_metrics/services.py`).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ThoughtStart => "THOUGHT_START",
            Self::SnapshotAndContext => "SNAPSHOT_AND_CONTEXT",
            Self::DmaResults => "DMA_RESULTS",
            Self::IdmaResult => "IDMA_RESULT",
            Self::AspdmaResult => "ASPDMA_RESULT",
            Self::TsaspdmaResult => "TSASPDMA_RESULT",
            Self::VerbSecondPassResult => "VERB_SECOND_PASS_RESULT",
            Self::ConscienceResult => "CONSCIENCE_RESULT",
            Self::ActionResult => "ACTION_RESULT",
            Self::LlmCall => "LLM_CALL",
            Self::RoundComplete => "ROUND_COMPLETE",
        }
    }

    /// v0.3.5 (CIRISLens#8 ASK 3) — Inverse of `as_str`. Used by
    /// backend row→struct conversions in `fetch_trace_events_page`.
    /// Returns `None` for unknown wire strings; callers surface as
    /// a typed `Error::Backend` rather than panic.
    pub fn from_wire_str(s: &str) -> Option<Self> {
        match s {
            "THOUGHT_START" => Some(Self::ThoughtStart),
            "SNAPSHOT_AND_CONTEXT" => Some(Self::SnapshotAndContext),
            "DMA_RESULTS" => Some(Self::DmaResults),
            "IDMA_RESULT" => Some(Self::IdmaResult),
            "ASPDMA_RESULT" => Some(Self::AspdmaResult),
            "TSASPDMA_RESULT" => Some(Self::TsaspdmaResult),
            "VERB_SECOND_PASS_RESULT" => Some(Self::VerbSecondPassResult),
            "CONSCIENCE_RESULT" => Some(Self::ConscienceResult),
            "ACTION_RESULT" => Some(Self::ActionResult),
            "LLM_CALL" => Some(Self::LlmCall),
            "ROUND_COMPLETE" => Some(Self::RoundComplete),
            _ => None,
        }
    }
}

/// Audit anchor extracted from an `ACTION_RESULT` component
/// (TRACE_WIRE_FORMAT.md §5.9; FSD §3.2 — three new columns on
/// `trace_events` for the `ACTION_RESULT` row).
///
/// Mission (MISSION.md §2 — `verify/`): the anchor lets a peer
/// recompute the per-action chain link without dragging the full
/// audit log across the wire. Phase 1 captures it; Phase 2's
/// peer-replicate validates it against the agent's local chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditAnchor {
    /// Per-agent monotonic sequence number identifying this audit
    /// chain link.
    pub audit_sequence_number: i64,
    /// sha256 of the agent's audit log entry — the chain link itself.
    pub audit_entry_hash: String,
    /// Optional in practice — the production agent (release/2.7.8)
    /// ships `audit_sequence_number` + `audit_entry_hash` on
    /// ACTION_RESULT but not always `audit_signature` (the chain
    /// link is recomputable from the agent-side audit_log when
    /// peer-replicate lands; FSD §4.5). Spec §5.9 lists it as
    /// present; production fixtures show it omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_signature: Option<String>,
    /// Optional per spec — the agent's `audit_log.entry_id` for
    /// cross-reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_entry_id: Option<String>,
}

/// Cost denormalization extracted from an `ACTION_RESULT` component
/// (TRACE_WIRE_FORMAT.md §5.9; SQL columns `cost_llm_calls`,
/// `cost_tokens`, `cost_usd` per `lens_027_trace_events.sql`).
///
/// Mission: PoB §2.4's N_eff measurement and CIRISLens scoring both
/// query against denormalized cost; keeping it typed at extract time
/// prevents drift from the per-LLM-call ground truth.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct CostSummary {
    /// Aggregate LLM call count for the thought
    /// (`ACTION_RESULT.llm_calls`).
    pub llm_calls: Option<i32>,
    /// Total tokens (input + output) for the thought
    /// (`ACTION_RESULT.tokens_total`).
    pub tokens_total: Option<i32>,
    /// Cost in USD (the wire format ships `cost_cents` *and*
    /// `cost_usd` may appear at the LLM_CALL level — for
    /// `ACTION_RESULT` we look at `cost_cents` and convert).
    pub cost_usd: Option<f64>,
    /// Carbon grams attribution if the agent shipped it.
    pub carbon_grams: Option<f64>,
}

/// `LLM_CALL.status` (TRACE_WIRE_FORMAT.md §5.10 — closed enum of
/// six values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmCallStatus {
    /// Provider returned a usable completion.
    Ok,
    /// Call timed out at the client.
    Timeout,
    /// Provider returned 429 / explicit rate-limit signal.
    RateLimited,
    /// Provider does not have the requested model available.
    ModelNotAvailable,
    /// `instructor` library retried due to schema-validation failure.
    InstructorRetry,
    /// Catch-all error class for un-typed provider failures.
    OtherError,
}

/// Typed projection of an `LLM_CALL` component's `data`, for landing
/// on the `trace_llm_calls` sibling table
/// (`lens_027_trace_events.sql` lines 58-103;
/// TRACE_EVENT_LOG_PERSISTENCE.md §5.2).
///
/// Mission (MISSION.md §2 — `schema/`): typed at parse time so the
/// SQL writer cannot accidentally drop a column. Extra fields on the
/// wire are tolerated (`#[serde(default)]`); missing fields surface
/// as `None`, not as a panic.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmCallSummary {
    /// Agent handler that issued the call.
    pub handler_name: String,
    /// Provider service identifier (e.g. "openai", "anthropic").
    pub service_name: String,
    /// Optional in production: spec §5.10 lists `timestamp` inside
    /// `data`, but `release/2.7.8` only emits it at the component
    /// level (TraceComponent.timestamp). Decomposition pulls from
    /// the component-level timestamp when this is None.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<DateTime<Utc>>,

    /// Wall-clock; ≥ 0.
    pub duration_ms: f64,

    /// Closed-enum status per §5.10.
    pub status: LlmCallStatus,

    /// Model identifier returned by the provider.
    pub model: Option<String>,
    /// Provider base URL (when non-default).
    pub base_url: Option<String>,
    /// Provider's response_model identifier (instructor).
    pub response_model: Option<String>,

    /// Token count for the prompt side.
    pub prompt_tokens: Option<i32>,
    /// Token count for the completion side.
    pub completion_tokens: Option<i32>,
    /// UTF-8 byte length of the prompt.
    pub prompt_bytes: Option<i32>,
    /// UTF-8 byte length of the completion.
    pub completion_bytes: Option<i32>,
    /// USD cost as reported by the provider.
    pub cost_usd: Option<f64>,

    /// Provider-specific error class on failure.
    pub error_class: Option<String>,
    /// Total attempt count across retries.
    pub attempt_count: Option<i32>,
    /// Number of retries that fired.
    pub retry_count: Option<i32>,

    /// Monotonic per `(thought_id, event_type)` — TRACE_WIRE_FORMAT.md §6.
    pub attempt_index: u32,

    /// v0.3.3 (CIRISPersist#12) — Parent event type (the upstream
    /// trace step that issued this LLM call). REQUIRED at
    /// `trace_schema_version >= 2.7.9` per
    /// `CIRISAgent/FSD/TRACE_WIRE_FORMAT.md @ v2.7.9-stable §5.10`;
    /// `None` for legacy 2.7.0 traces (no transition window — the
    /// agent emits both fields starting at 2.7.9).
    ///
    /// Stored on `trace_llm_calls.parent_event_type`. v0.3.0–v0.3.2
    /// silently substituted the outer component's `event_type`
    /// (always `LLM_CALL`) into the column when the wire didn't
    /// carry the field; v0.3.3 reads the wire-provided value at
    /// 2.7.9 and rejects the trace when it's missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_event_type: Option<ReasoningEventType>,

    /// v0.3.3 (CIRISPersist#12) — Parent event's `attempt_index`.
    /// REQUIRED at `trace_schema_version >= 2.7.9`. See
    /// `parent_event_type` for the semantics + spec citation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_attempt_index: Option<u32>,

    /// DETAILED+: SHA-256 hex of the prompt (for dedup analysis).
    pub prompt_hash: Option<String>,
    /// FULL only: full prompt verbatim.
    pub prompt: Option<String>,
    /// FULL only: full completion verbatim.
    pub response_text: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_round_trip() {
        for &(et, s) in &[
            (ReasoningEventType::ThoughtStart, "THOUGHT_START"),
            (
                ReasoningEventType::SnapshotAndContext,
                "SNAPSHOT_AND_CONTEXT",
            ),
            (ReasoningEventType::DmaResults, "DMA_RESULTS"),
            (ReasoningEventType::IdmaResult, "IDMA_RESULT"),
            (ReasoningEventType::AspdmaResult, "ASPDMA_RESULT"),
            (ReasoningEventType::TsaspdmaResult, "TSASPDMA_RESULT"),
            (
                ReasoningEventType::VerbSecondPassResult,
                "VERB_SECOND_PASS_RESULT",
            ),
            (ReasoningEventType::ConscienceResult, "CONSCIENCE_RESULT"),
            (ReasoningEventType::ActionResult, "ACTION_RESULT"),
            (ReasoningEventType::LlmCall, "LLM_CALL"),
        ] {
            assert_eq!(et.as_str(), s, "as_str matches wire token");
            let json = serde_json::to_string(&et).unwrap();
            assert_eq!(json, format!(r#""{s}""#), "serializes as wire token");
            let back: ReasoningEventType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, et, "round-trips");
        }
    }

    #[test]
    fn component_type_wire_tokens() {
        // Spelling matches TRACE_WIRE_FORMAT.md §4 verbatim. A typo
        // here silently mis-routes events at ingest.
        assert_eq!(
            serde_json::to_string(&ComponentType::Observation).unwrap(),
            r#""observation""#
        );
        assert_eq!(
            serde_json::to_string(&ComponentType::Context).unwrap(),
            r#""context""#
        );
        assert_eq!(
            serde_json::to_string(&ComponentType::Rationale).unwrap(),
            r#""rationale""#
        );
        assert_eq!(
            serde_json::to_string(&ComponentType::Conscience).unwrap(),
            r#""conscience""#
        );
        assert_eq!(
            serde_json::to_string(&ComponentType::Action).unwrap(),
            r#""action""#
        );
        assert_eq!(
            serde_json::to_string(&ComponentType::VerbSecondPass).unwrap(),
            r#""verb_second_pass""#
        );
        assert_eq!(
            serde_json::to_string(&ComponentType::LlmCall).unwrap(),
            r#""llm_call""#
        );
        assert_eq!(
            serde_json::to_string(&ComponentType::Unknown).unwrap(),
            r#""unknown""#
        );
    }

    #[test]
    fn llm_call_status_wire_tokens() {
        // §5.10 closed enum — six values.
        for &(st, s) in &[
            (LlmCallStatus::Ok, "ok"),
            (LlmCallStatus::Timeout, "timeout"),
            (LlmCallStatus::RateLimited, "rate_limited"),
            (LlmCallStatus::ModelNotAvailable, "model_not_available"),
            (LlmCallStatus::InstructorRetry, "instructor_retry"),
            (LlmCallStatus::OtherError, "other_error"),
        ] {
            assert_eq!(
                serde_json::to_string(&st).unwrap(),
                format!(r#""{s}""#),
                "{:?} → {:?}",
                st,
                s
            );
        }
    }

    /// Parity test placeholder — the typed accessor on a component
    /// data blob extracts the audit anchor only when present
    /// (i.e., on the `ACTION_RESULT` row), and surfaces a structured
    /// error if shape is wrong. Implementation lives in
    /// `trace::TraceComponent` (next file); this is the spec.
    #[test]
    fn audit_anchor_round_trip() {
        // Mission category §4 "Schema parity": the three audit-anchor
        // fields the FSD §3.2 calls out land on a typed value.
        let json = serde_json::json!({
            "audit_sequence_number": 42,
            "audit_entry_hash": "abcd",
            "audit_signature": "BBBB",
            "audit_entry_id": "audit-xyz"
        });
        let a: AuditAnchor = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(a.audit_sequence_number, 42);
        assert_eq!(a.audit_entry_hash, "abcd");
        assert_eq!(a.audit_signature.as_deref(), Some("BBBB"));
        assert_eq!(a.audit_entry_id.as_deref(), Some("audit-xyz"));

        // entry_id absent is fine.
        let json2 = serde_json::json!({
            "audit_sequence_number": 1,
            "audit_entry_hash": "x",
            "audit_signature": "y"
        });
        let a2: AuditAnchor = serde_json::from_value(json2).unwrap();
        assert!(a2.audit_entry_id.is_none());
    }
}
