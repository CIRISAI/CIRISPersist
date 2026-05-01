//! Decompose a verified `CompleteTrace` into row-shaped writes.
//!
//! # Mission alignment (MISSION.md §2 — `store/`)
//!
//! Per FSD §3.3 step 4: each `CompleteTrace.components[i]` becomes
//! one `trace_events` row keyed by
//! `(trace_id, thought_id, event_type, attempt_index)`. `LLM_CALL`
//! components additionally produce a `trace_llm_calls` sibling row
//! linked via `parent_event_id` (set after parent insert returns).
//!
//! This module is pure transformation — no I/O, no async, no
//! storage. The caller (lens ingest pipeline) verifies first
//! (MISSION.md §3 anti-pattern #2), then decomposes, then writes via
//! the Backend trait.

use chrono::{DateTime, Utc};

use super::types::{TraceEventRow, TraceLlmCallRow};
use super::Error;
use crate::schema::{CompleteTrace, ReasoningEventType, TraceComponent};

/// Output of a successful decomposition.
///
/// `events.len()` always equals `trace.components.len()` (one row per
/// component, no exceptions). `llm_calls.len()` equals the count of
/// `LLM_CALL` components inside.
#[derive(Debug, Clone, PartialEq)]
pub struct Decomposed {
    /// One [`TraceEventRow`] per component in the source trace.
    pub events: Vec<TraceEventRow>,
    /// Sibling-table rows extracted from `LLM_CALL` components.
    pub llm_calls: Vec<TraceLlmCallRow>,
}

/// Decompose a verified `CompleteTrace` into row-shaped writes.
///
/// Caller invariant: `trace` has already passed
/// [`crate::verify::verify_trace`]. The `signature_verified` field on
/// every produced row is set to `true`; we never produce rows for
/// unverified bytes (MISSION.md §3 anti-pattern #2).
///
/// `agent_name` and `cognitive_state` are pulled from the per-component
/// `data` blobs where present (the `SNAPSHOT_AND_CONTEXT` event ships
/// them at GENERIC trace level per TRACE_WIRE_FORMAT.md §5.2). For
/// rows where they're absent, leave `None` — the SQL columns are
/// nullable.
///
/// The returned `TraceLlmCallRow.parent_event_id` is `None` until the
/// parent `trace_events` insert returns the row's PK; the Backend
/// impl is responsible for backfilling that linkage.
pub fn decompose(trace: &CompleteTrace) -> Result<Decomposed, Error> {
    // Pull per-trace constants once.
    let agent_name = pluck_string_from_first(trace, "agent_name");
    let cognitive_state = pluck_string_from_first(trace, "cognitive_state");

    let mut events = Vec::with_capacity(trace.components.len());
    let mut llm_calls = Vec::new();

    for component in &trace.components {
        let attempt_index = component.attempt_index().map_err(Error::Schema)?;

        let cost = component.cost_summary();

        let step_point = component
            .data
            .get("step_point")
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        let event_row = TraceEventRow {
            trace_id: trace.trace_id.clone(),
            thought_id: trace.thought_id.clone(),
            task_id: trace.task_id.clone(),
            step_point,
            event_type: component.event_type,
            attempt_index,
            // v0.1.8 — component.timestamp is now WireDateTime
            // (preserves wire bytes for verify); the row stores a
            // chrono::DateTime<Utc> for time-series queries.
            ts: component.timestamp.parsed(),
            agent_name: agent_name.clone(),
            agent_id_hash: trace.agent_id_hash.clone(),
            cognitive_state: cognitive_state.clone(),
            trace_level: trace.trace_level,
            payload: component.data.clone(),
            cost_llm_calls: cost.llm_calls,
            cost_tokens: cost.tokens_total,
            cost_usd: cost.cost_usd,
            signature: trace.signature.clone(),
            signing_key_id: trace.signature_key_id.clone(),
            signature_verified: true,
            schema_version: trace.trace_schema_version.as_str().to_owned(),
            pii_scrubbed: false,
            // FSD §3.7 envelope fields. decompose itself doesn't sign;
            // the IngestPipeline (step 3.5) populates these per-row
            // after this function returns. Pure-decomposition callers
            // (tests, sovereign-mode tools) get None and can fill in
            // their own envelopes if needed.
            original_content_hash: None,
            scrub_signature: None,
            scrub_key_id: None,
            scrub_timestamp: None,
        };
        events.push(event_row);

        // LLM_CALL → sibling row.
        if component.event_type == ReasoningEventType::LlmCall {
            if let Some(call) = component.llm_call().map_err(Error::Schema)? {
                let row = build_llm_call_row(trace, component, &call, attempt_index);
                llm_calls.push(row);
            }
        }
    }

    Ok(Decomposed { events, llm_calls })
}

fn build_llm_call_row(
    trace: &CompleteTrace,
    component: &TraceComponent,
    call: &crate::schema::LlmCallSummary,
    attempt_index: u32,
) -> TraceLlmCallRow {
    TraceLlmCallRow {
        trace_id: trace.trace_id.clone(),
        thought_id: trace.thought_id.clone(),
        task_id: trace.task_id.clone(),
        parent_event_id: None,
        parent_event_type: component.event_type,
        parent_attempt_index: attempt_index,
        attempt_index: call.attempt_index,
        // Spec §5.10 puts timestamp inside data; release/2.7.8 emits
        // it at the component level only. Fall back to the component
        // timestamp when data.timestamp is absent.
        ts: call
            .timestamp
            .unwrap_or_else(|| component.timestamp.parsed()),
        duration_ms: call.duration_ms,
        handler_name: call.handler_name.clone(),
        service_name: call.service_name.clone(),
        model: call.model.clone(),
        base_url: call.base_url.clone(),
        response_model: call.response_model.clone(),
        prompt_tokens: call.prompt_tokens,
        completion_tokens: call.completion_tokens,
        prompt_bytes: call.prompt_bytes,
        completion_bytes: call.completion_bytes,
        cost_usd: call.cost_usd,
        status: call.status,
        error_class: call.error_class.clone(),
        attempt_count: call.attempt_count,
        retry_count: call.retry_count,
        prompt_hash: call.prompt_hash.clone(),
        prompt: call.prompt.clone(),
        response_text: call.response_text.clone(),
    }
}

/// Pluck a string field from the first component whose `data`
/// contains it. Used for trace-level constants like `agent_name` and
/// `cognitive_state` that are emitted on `SNAPSHOT_AND_CONTEXT` at
/// GENERIC trace level (TRACE_WIRE_FORMAT.md §5.2).
fn pluck_string_from_first(trace: &CompleteTrace, key: &str) -> Option<String> {
    trace
        .components
        .iter()
        .find_map(|c| c.data.get(key).and_then(|v| v.as_str()).map(str::to_owned))
}

/// Build the
/// `(agent_id_hash, trace_id, thought_id, event_type, attempt_index)`
/// dedup tuple for a row.
///
/// THREAT_MODEL.md AV-9: agent_id_hash is the dedup-key prefix so a
/// malicious agent reusing another agent's trace_id/thought_id
/// shape cannot DOS the victim's traces. Matches the SQL UNIQUE
/// index `trace_events_dedup` in V001.
pub fn dedup_key(row: &TraceEventRow) -> (String, String, String, ReasoningEventType, u32) {
    (
        row.agent_id_hash.clone(),
        row.trace_id.clone(),
        row.thought_id.clone(),
        row.event_type,
        row.attempt_index,
    )
}

/// Best-effort `_:_:_:_` synthetic timestamp helper for tests.
#[allow(dead_code)]
fn parse_iso(s: &str) -> DateTime<Utc> {
    s.parse().expect("valid ISO-8601")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{ComponentType, SchemaVersion, TraceLevel};

    fn ts(s: &str) -> crate::schema::WireDateTime {
        s.parse().unwrap()
    }

    fn component(
        event_type: ReasoningEventType,
        attempt_index: u32,
        extra: serde_json::Value,
    ) -> TraceComponent {
        let mut data = serde_json::Map::new();
        data.insert(
            "attempt_index".to_owned(),
            serde_json::Value::Number(attempt_index.into()),
        );
        if let serde_json::Value::Object(more) = extra {
            for (k, v) in more {
                data.insert(k, v);
            }
        }
        TraceComponent {
            component_type: match event_type {
                ReasoningEventType::ThoughtStart => ComponentType::Observation,
                ReasoningEventType::SnapshotAndContext => ComponentType::Context,
                ReasoningEventType::DmaResults
                | ReasoningEventType::IdmaResult
                | ReasoningEventType::AspdmaResult
                | ReasoningEventType::TsaspdmaResult => ComponentType::Rationale,
                ReasoningEventType::VerbSecondPassResult => ComponentType::VerbSecondPass,
                ReasoningEventType::ConscienceResult => ComponentType::Conscience,
                ReasoningEventType::ActionResult => ComponentType::Action,
                ReasoningEventType::LlmCall => ComponentType::LlmCall,
                ReasoningEventType::RoundComplete => ComponentType::Unknown,
            },
            event_type,
            timestamp: ts("2026-04-30T00:16:00Z"),
            data,
        }
    }

    fn fixture_trace() -> CompleteTrace {
        CompleteTrace {
            trace_id: "trace-x-1".into(),
            thought_id: "th-1".into(),
            task_id: Some("task-1".into()),
            agent_id_hash: "deadbeef".into(),
            started_at: ts("2026-04-30T00:15:53.123Z"),
            completed_at: ts("2026-04-30T00:16:12.789Z"),
            trace_level: TraceLevel::Generic,
            trace_schema_version: SchemaVersion::parse("2.7.0").unwrap(),
            components: vec![
                component(
                    ReasoningEventType::ThoughtStart,
                    0,
                    serde_json::json!({"thought_type": "standard"}),
                ),
                component(
                    ReasoningEventType::LlmCall,
                    0,
                    serde_json::json!({
                        "handler_name": "EthicalPDMA",
                        "service_name": "OpenAICompatibleLLM",
                        "timestamp": "2026-04-30T00:15:54.012Z",
                        "duration_ms": 90000.0,
                        "status": "ok",
                        "prompt_tokens": 8192,
                        "completion_tokens": 512
                    }),
                ),
                component(
                    ReasoningEventType::ConscienceResult,
                    0,
                    serde_json::json!({"conscience_passed": true}),
                ),
                component(
                    ReasoningEventType::ConscienceResult,
                    1,
                    serde_json::json!({"is_recursive": true}),
                ),
                component(
                    ReasoningEventType::ActionResult,
                    0,
                    serde_json::json!({
                        "action_executed": "speak",
                        "audit_sequence_number": 42,
                        "audit_entry_hash": "abcd",
                        "audit_signature": "BBBB",
                        "llm_calls": 13,
                        "tokens_total": 28000,
                        "cost_cents": 27.6,
                        "step_point": "perform_action"
                    }),
                ),
            ],
            signature: "AAAA".into(),
            signature_key_id: "ciris-agent-key:dead".into(),
        }
    }

    #[test]
    fn one_event_row_per_component() {
        let trace = fixture_trace();
        let d = decompose(&trace).unwrap();
        assert_eq!(d.events.len(), trace.components.len());
    }

    #[test]
    fn llm_calls_extracted_for_llm_components() {
        let trace = fixture_trace();
        let d = decompose(&trace).unwrap();
        // Exactly one LLM_CALL in the fixture → one llm_calls row.
        assert_eq!(d.llm_calls.len(), 1);
        let call = &d.llm_calls[0];
        assert_eq!(call.handler_name, "EthicalPDMA");
        assert_eq!(call.parent_event_type, ReasoningEventType::LlmCall);
        // Linkage backfilled by Backend impl on insert; pre-insert is None.
        assert!(call.parent_event_id.is_none());
    }

    #[test]
    fn dedup_keys_unique_for_repeated_event_types() {
        // Mission category §4 "Idempotency": two CONSCIENCE_RESULT
        // attempts must produce two distinct dedup keys.
        let trace = fixture_trace();
        let d = decompose(&trace).unwrap();
        let keys: Vec<_> = d.events.iter().map(dedup_key).collect();
        let unique: std::collections::HashSet<_> = keys.iter().cloned().collect();
        assert_eq!(unique.len(), keys.len(), "all dedup keys must be unique");
    }

    #[test]
    fn cost_denormalization_only_on_action_result() {
        let trace = fixture_trace();
        let d = decompose(&trace).unwrap();
        for ev in &d.events {
            match ev.event_type {
                ReasoningEventType::ActionResult => {
                    assert_eq!(ev.cost_llm_calls, Some(13));
                    assert_eq!(ev.cost_tokens, Some(28000));
                    assert!((ev.cost_usd.unwrap() - 0.276).abs() < 1e-9);
                }
                _ => {
                    assert!(
                        ev.cost_llm_calls.is_none(),
                        "{:?} → cost columns must be None",
                        ev.event_type
                    );
                    assert!(ev.cost_tokens.is_none());
                    assert!(ev.cost_usd.is_none());
                }
            }
        }
    }

    #[test]
    fn step_point_extracted_when_present() {
        let trace = fixture_trace();
        let d = decompose(&trace).unwrap();
        let action = d
            .events
            .iter()
            .find(|e| e.event_type == ReasoningEventType::ActionResult)
            .unwrap();
        assert_eq!(action.step_point.as_deref(), Some("perform_action"));
    }

    #[test]
    fn signature_verified_set_true_on_decomposed_rows() {
        // MISSION.md §3 anti-pattern #2: only verified bytes produce
        // rows; the persistence path never has signature_verified=false
        // for stored data. Decomposition asserts that contract.
        let trace = fixture_trace();
        let d = decompose(&trace).unwrap();
        assert!(d.events.iter().all(|e| e.signature_verified));
    }

    #[test]
    fn payload_preserves_original_data_blob() {
        // Mission constraint: the agent's data dict is stored
        // verbatim; typed extracts are denormalized adjacent columns,
        // not destructive transforms.
        let trace = fixture_trace();
        let d = decompose(&trace).unwrap();
        let action = d
            .events
            .iter()
            .find(|e| e.event_type == ReasoningEventType::ActionResult)
            .unwrap();
        // Audit anchor fields still present in payload after extraction.
        assert!(action.payload.contains_key("audit_sequence_number"));
        assert!(action.payload.contains_key("audit_entry_hash"));
        assert!(action.payload.contains_key("audit_signature"));
        // step_point also kept in payload (denormalized as a column,
        // not removed from the blob).
        assert!(action.payload.contains_key("step_point"));
    }

    #[test]
    fn missing_attempt_index_is_typed_error() {
        // Mission category §4: malformed agent data surfaces as a
        // typed schema error, not a panic. Decompose propagates.
        let mut trace = fixture_trace();
        // Strip attempt_index from the first component — should fail.
        trace.components[0].data.remove("attempt_index");
        let err = decompose(&trace).unwrap_err();
        match err {
            Error::Schema(crate::schema::Error::MissingField("attempt_index")) => {}
            other => panic!("expected MissingField(attempt_index), got {other:?}"),
        }
    }
}
