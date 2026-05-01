//! `CompleteTrace` + `TraceComponent` (TRACE_WIRE_FORMAT.md §3 + §4).
//!
//! Mission alignment (MISSION.md §2 — `schema/`): typed envelope, typed
//! accessors over `data`. The `data` blob is opaque JSONB at storage
//! time; reasoning over it without a typed accessor would be the
//! anti-pattern.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::events::{AuditAnchor, ComponentType, CostSummary, LlmCallSummary, ReasoningEventType};
use super::version::SchemaVersion;
use super::Error;

/// One element of `CompleteTrace.components` (TRACE_WIRE_FORMAT.md §4).
///
/// `data` is retained as a typed JSON object (`serde_json::Map`) for
/// JSONB persistence — the wire-format spec explicitly says the lens
/// stores the agent's `data` dict verbatim
/// (`context/lens_027_trace_events.sql` line 26: `payload JSONB NOT
/// NULL -- the component.data dict`).
///
/// Typed access into `data` goes through the helpers below; raw
/// `data` access is intentionally allowed for the JSONB write path.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TraceComponent {
    /// Logical category of the component (observation / rationale /
    /// conscience / etc.).
    pub component_type: ComponentType,
    /// Specific event-type discriminant within that category.
    pub event_type: ReasoningEventType,
    /// Wall-clock at which this component was emitted.
    pub timestamp: DateTime<Utc>,
    /// The agent's `data` dict, kept verbatim for JSONB storage. Use
    /// the typed accessors below to extract specific fields with
    /// schema validation.
    pub data: serde_json::Map<String, serde_json::Value>,
}

impl TraceComponent {
    /// Extract `attempt_index` per TRACE_WIRE_FORMAT.md §6.
    ///
    /// Mission (MISSION.md §3 anti-pattern #4): typed error on absence
    /// or shape mismatch; the dedup key downstream
    /// (`(trace_id, thought_id, event_type, attempt_index)`) cannot
    /// silently default to 0 because that would collapse multiple
    /// retry rows into one — exactly the data loss FSD §1 calls out.
    ///
    /// Returns `Err(MissingField)` if absent; `Err(NegativeAttemptIndex)`
    /// if negative (the agent's invariant); otherwise the value.
    pub fn attempt_index(&self) -> Result<u32, Error> {
        let v = self
            .data
            .get("attempt_index")
            .ok_or(Error::MissingField("attempt_index"))?;
        let n = v.as_i64().ok_or_else(|| Error::FieldTypeMismatch {
            field: "attempt_index",
            expected: "integer",
            got: json_type_name(v),
        })?;
        if n < 0 {
            return Err(Error::NegativeAttemptIndex(n));
        }
        // THREAT_MODEL.md AV-17 (v0.1.3): bounded conversion, no
        // silent truncation. MAX_ATTEMPT_INDEX is generous over
        // the production agent's retry budget (~5); values above
        // that bound are adversarial.
        let max = super::MAX_ATTEMPT_INDEX;
        if n > i64::from(max) {
            return Err(Error::AttemptIndexOutOfRange { got: n, max });
        }
        // Now safe: 0 <= n <= MAX_ATTEMPT_INDEX (= 1024) fits in u32.
        Ok(u32::try_from(n).expect("range-checked above"))
    }

    /// Extract the audit anchor from an `ACTION_RESULT` component
    /// (FSD §3.2; TRACE_WIRE_FORMAT.md §5.9).
    ///
    /// `Ok(None)` if this is not an `ACTION_RESULT` component or the
    /// audit fields are absent (older agents). `Ok(Some(_))` when the
    /// agent shipped them. `Err` if the fields are present but
    /// malformed (an in-spec agent never produces this; a malformed
    /// payload here is signal worth surfacing).
    pub fn audit_anchor(&self) -> Result<Option<AuditAnchor>, Error> {
        if self.event_type != ReasoningEventType::ActionResult {
            return Ok(None);
        }
        // Three required fields per FSD §3.2; all-or-nothing per the
        // ACTION_RESULT payload shape.
        let has_seq = self.data.contains_key("audit_sequence_number");
        let has_hash = self.data.contains_key("audit_entry_hash");
        let has_sig = self.data.contains_key("audit_signature");
        if !has_seq && !has_hash && !has_sig {
            return Ok(None);
        }
        // Re-parse the relevant subset as a typed AuditAnchor. We
        // intentionally re-serialize a new object so that downstream
        // `data` JSONB storage is untouched.
        let mut subset = serde_json::Map::new();
        for k in [
            "audit_sequence_number",
            "audit_entry_hash",
            "audit_signature",
            "audit_entry_id",
        ] {
            if let Some(v) = self.data.get(k) {
                subset.insert(k.to_owned(), v.clone());
            }
        }
        let anchor: AuditAnchor =
            serde_json::from_value(serde_json::Value::Object(subset)).map_err(Error::Json)?;
        Ok(Some(anchor))
    }

    /// Extract the cost summary from an `ACTION_RESULT` component
    /// (TRACE_WIRE_FORMAT.md §5.9).
    ///
    /// Other event types return `CostSummary::default()`. The wire
    /// format ships `cost_cents` (a float in cents) plus optional
    /// `cost_usd`-style fields elsewhere; we accept both names and
    /// normalize to USD.
    pub fn cost_summary(&self) -> CostSummary {
        if self.event_type != ReasoningEventType::ActionResult {
            return CostSummary::default();
        }
        let llm_calls = self
            .data
            .get("llm_calls")
            .and_then(|v| v.as_i64())
            .map(|n| n as i32);
        let tokens_total = self
            .data
            .get("tokens_total")
            .and_then(|v| v.as_i64())
            .map(|n| n as i32);
        let cost_usd = self
            .data
            .get("cost_usd")
            .and_then(|v| v.as_f64())
            .or_else(|| {
                self.data
                    .get("cost_cents")
                    .and_then(|v| v.as_f64())
                    .map(|c| c / 100.0)
            });
        let carbon_grams = self.data.get("carbon_grams").and_then(|v| v.as_f64());
        CostSummary {
            llm_calls,
            tokens_total,
            cost_usd,
            carbon_grams,
        }
    }

    /// Extract the typed `LLM_CALL` summary, for landing on the
    /// `trace_llm_calls` sibling table (FSD §3.3 step 4;
    /// `lens_027_trace_events.sql` lines 58-103).
    ///
    /// `Ok(None)` if this is not an `LLM_CALL` component. `Err` if
    /// it is an `LLM_CALL` but `data` is malformed — that is real
    /// signal: the wire format §5.10 fields are required by spec for
    /// every emission.
    pub fn llm_call(&self) -> Result<Option<LlmCallSummary>, Error> {
        if self.event_type != ReasoningEventType::LlmCall {
            return Ok(None);
        }
        let summary: LlmCallSummary =
            serde_json::from_value(serde_json::Value::Object(self.data.clone()))
                .map_err(Error::Json)?;
        Ok(Some(summary))
    }
}

/// `CompleteTrace` envelope (TRACE_WIRE_FORMAT.md §3).
///
/// Mission alignment (MISSION.md §2 — `verify/`): the signature is
/// over the canonical bytes of this struct (TRACE_WIRE_FORMAT.md §8).
/// Field order, optionality, and types here directly affect what the
/// `verify::canonical` module can reproduce. Changing this struct's
/// shape invalidates every existing recorded signature — version-bump
/// schema and write a migrator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompleteTrace {
    /// Stable trace identifier.
    pub trace_id: String,
    /// Thought-iteration identifier within the trace.
    pub thought_id: String,
    /// Optional per spec: not all internal thoughts (system probes)
    /// have parent tasks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// SHA-256 digest of the agent's identity tuple.
    pub agent_id_hash: String,

    /// When the trace started.
    pub started_at: DateTime<Utc>,
    /// When the trace was sealed (`ACTION_RESULT` emitted).
    pub completed_at: DateTime<Utc>,

    /// Privacy / bandwidth tier of the trace.
    pub trace_level: super::envelope::TraceLevel,
    /// Wire-format schema version this trace was emitted under.
    pub trace_schema_version: SchemaVersion,

    /// Sequence of components making up the trace.
    pub components: Vec<TraceComponent>,

    /// Base64-encoded Ed25519 signature over the canonical bytes
    /// (TRACE_WIRE_FORMAT.md §8).
    pub signature: String,
    /// Key identifier for verification lookup.
    pub signature_key_id: String,
}

/// JSON-type-name for error messages.
fn json_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::super::events::LlmCallStatus;
    use super::*;

    fn component(
        component_type: ComponentType,
        event_type: ReasoningEventType,
        data: serde_json::Value,
    ) -> TraceComponent {
        let serde_json::Value::Object(map) = data else {
            panic!("data must be a JSON object")
        };
        TraceComponent {
            component_type,
            event_type,
            timestamp: "2026-04-30T00:16:00Z".parse().unwrap(),
            data: map,
        }
    }

    /// Mission category §4 "Schema parity": typed accessor extracts
    /// `attempt_index` byte-for-byte. Negative attempt_index is
    /// rejected — the dedup key cannot silently fold rows.
    #[test]
    fn attempt_index_extracts_typed() {
        let c = component(
            ComponentType::Conscience,
            ReasoningEventType::ConscienceResult,
            serde_json::json!({"attempt_index": 3}),
        );
        assert_eq!(c.attempt_index().unwrap(), 3);
    }

    #[test]
    fn attempt_index_missing_is_typed_error() {
        let c = component(
            ComponentType::Conscience,
            ReasoningEventType::ConscienceResult,
            serde_json::json!({}),
        );
        let err = c.attempt_index().unwrap_err();
        assert!(
            matches!(err, Error::MissingField("attempt_index")),
            "got {err:?}"
        );
    }

    #[test]
    fn attempt_index_negative_rejected() {
        // Mission (MISSION.md §3 anti-pattern #9): malformed agent
        // data surfaces as a typed error. A negative attempt_index
        // would pretend a retry never happened.
        let c = component(
            ComponentType::Conscience,
            ReasoningEventType::ConscienceResult,
            serde_json::json!({"attempt_index": -1}),
        );
        let err = c.attempt_index().unwrap_err();
        assert!(
            matches!(err, Error::NegativeAttemptIndex(-1)),
            "got {err:?}"
        );
    }

    /// THREAT_MODEL.md AV-17 regression (v0.1.3): values above
    /// MAX_ATTEMPT_INDEX are rejected with a typed error rather
    /// than silently truncating via `as u32` to collide with a
    /// legitimate retry-0 row on the dedup tuple.
    #[test]
    fn attempt_index_above_max_rejected() {
        // 2^32 — would have wrapped to 0 under the pre-fix `as u32`.
        let c = component(
            ComponentType::Conscience,
            ReasoningEventType::ConscienceResult,
            serde_json::json!({"attempt_index": 4_294_967_296i64}),
        );
        let err = c.attempt_index().unwrap_err();
        match err {
            Error::AttemptIndexOutOfRange { got, max } => {
                assert_eq!(got, 4_294_967_296);
                assert_eq!(max, super::super::MAX_ATTEMPT_INDEX);
            }
            other => panic!("expected AttemptIndexOutOfRange, got {other:?}"),
        }
    }

    /// THREAT_MODEL.md AV-17: just above the bound also rejects;
    /// MAX_ATTEMPT_INDEX itself is accepted.
    #[test]
    fn attempt_index_max_plus_one_rejected_max_accepted() {
        let max = super::super::MAX_ATTEMPT_INDEX;
        // Accepted at the bound:
        let c_ok = component(
            ComponentType::Conscience,
            ReasoningEventType::ConscienceResult,
            serde_json::json!({"attempt_index": max}),
        );
        assert_eq!(c_ok.attempt_index().unwrap(), max);

        // Rejected one above:
        let c_bad = component(
            ComponentType::Conscience,
            ReasoningEventType::ConscienceResult,
            serde_json::json!({"attempt_index": (max as i64) + 1}),
        );
        assert!(matches!(
            c_bad.attempt_index(),
            Err(Error::AttemptIndexOutOfRange { .. })
        ));
    }

    #[test]
    fn attempt_index_wrong_type_rejected() {
        let c = component(
            ComponentType::Conscience,
            ReasoningEventType::ConscienceResult,
            serde_json::json!({"attempt_index": "not a number"}),
        );
        let err = c.attempt_index().unwrap_err();
        assert!(matches!(
            err,
            Error::FieldTypeMismatch {
                field: "attempt_index",
                ..
            }
        ));
    }

    /// Mission category §4 "Schema parity": audit anchor extracted
    /// only on ACTION_RESULT; absent on other components by design
    /// (FSD §3.2 — populated only on the `ACTION_RESULT` row).
    #[test]
    fn audit_anchor_only_on_action_result() {
        // Anchor present + ACTION_RESULT → Some
        let c = component(
            ComponentType::Action,
            ReasoningEventType::ActionResult,
            serde_json::json!({
                "attempt_index": 0,
                "audit_sequence_number": 42,
                "audit_entry_hash": "abcd",
                "audit_signature": "BBBB",
            }),
        );
        let a = c
            .audit_anchor()
            .unwrap()
            .expect("ACTION_RESULT should expose anchor");
        assert_eq!(a.audit_sequence_number, 42);

        // Anchor present but on a non-ACTION_RESULT component → None
        // (MDD: types prevent the wrong field from leaking into the
        // wrong row).
        let c2 = component(
            ComponentType::Conscience,
            ReasoningEventType::ConscienceResult,
            serde_json::json!({
                "audit_sequence_number": 999,
            }),
        );
        assert!(c2.audit_anchor().unwrap().is_none());

        // ACTION_RESULT but no anchor fields (older agent) → None,
        // not error.
        let c3 = component(
            ComponentType::Action,
            ReasoningEventType::ActionResult,
            serde_json::json!({"attempt_index": 0}),
        );
        assert!(c3.audit_anchor().unwrap().is_none());
    }

    #[test]
    fn cost_summary_handles_cost_cents_to_usd() {
        // §5.9 ships `cost_cents`; we normalize to USD.
        let c = component(
            ComponentType::Action,
            ReasoningEventType::ActionResult,
            serde_json::json!({
                "attempt_index": 0,
                "llm_calls": 13,
                "tokens_total": 28000,
                "cost_cents": 27.6,
            }),
        );
        let cs = c.cost_summary();
        assert_eq!(cs.llm_calls, Some(13));
        assert_eq!(cs.tokens_total, Some(28000));
        assert!((cs.cost_usd.unwrap() - 0.276).abs() < 1e-9);
    }

    #[test]
    fn cost_summary_only_on_action_result() {
        let c = component(
            ComponentType::LlmCall,
            ReasoningEventType::LlmCall,
            serde_json::json!({"attempt_index": 0, "cost_usd": 0.05}),
        );
        let cs = c.cost_summary();
        // LLM_CALL costs are *per-call* and live on trace_llm_calls,
        // not denormalized on the parent event row.
        assert!(cs.cost_usd.is_none());
    }

    #[test]
    fn llm_call_summary_round_trip() {
        let c = component(
            ComponentType::LlmCall,
            ReasoningEventType::LlmCall,
            serde_json::json!({
                "handler_name": "EthicalPDMA",
                "service_name": "OpenAICompatibleLLM",
                "timestamp": "2026-04-30T00:15:54.012Z",
                "model": "google/gemma-4-31B-it",
                "base_url": "https://api.together.xyz/v1",
                "duration_ms": 90000.0,
                "status": "ok",
                "prompt_tokens": 8192,
                "completion_tokens": 512,
                "attempt_count": 1,
                "retry_count": 0,
                "attempt_index": 4
            }),
        );
        let summary = c.llm_call().unwrap().expect("LLM_CALL → Some");
        assert_eq!(summary.handler_name, "EthicalPDMA");
        assert_eq!(summary.status, LlmCallStatus::Ok);
        assert_eq!(summary.duration_ms, 90000.0);
        assert_eq!(summary.attempt_index, 4);
    }

    #[test]
    fn complete_trace_parses_with_components() {
        // Pulled from TRACE_WIRE_FORMAT.md §11 (worked example),
        // stripped to the minimum to exercise the typed shape.
        let json = serde_json::json!({
            "trace_id": "trace-th_std_abc-20260430001553",
            "thought_id": "th_std_abc",
            "task_id": "ACCEPT_INCOMPLETENESS_xyz",
            "agent_id_hash": "deadbeef",
            "started_at": "2026-04-30T00:15:53.123456+00:00",
            "completed_at": "2026-04-30T00:16:12.789012+00:00",
            "trace_level": "generic",
            "trace_schema_version": "2.7.0",
            "components": [
                {
                    "component_type": "observation",
                    "event_type": "THOUGHT_START",
                    "timestamp": "2026-04-30T00:15:53.123Z",
                    "data": {"attempt_index": 0, "thought_type": "standard"}
                },
                {
                    "component_type": "action",
                    "event_type": "ACTION_RESULT",
                    "timestamp": "2026-04-30T00:16:12.789Z",
                    "data": {
                        "attempt_index": 0,
                        "audit_sequence_number": 42,
                        "audit_entry_hash": "abcd",
                        "audit_signature": "BBBB",
                        "llm_calls": 13,
                        "tokens_total": 28000,
                        "cost_cents": 27.6
                    }
                }
            ],
            "signature": "AAAA",
            "signature_key_id": "ciris-agent-key:dead"
        });
        let trace: CompleteTrace = serde_json::from_value(json).unwrap();
        assert_eq!(trace.components.len(), 2);

        let first = &trace.components[0];
        assert_eq!(first.event_type, ReasoningEventType::ThoughtStart);
        assert_eq!(first.attempt_index().unwrap(), 0);
        assert!(
            first.audit_anchor().unwrap().is_none(),
            "anchor only on ACTION_RESULT"
        );

        let last = &trace.components[1];
        assert_eq!(last.event_type, ReasoningEventType::ActionResult);
        let anchor = last.audit_anchor().unwrap().expect("anchor present");
        assert_eq!(anchor.audit_sequence_number, 42);
        let cs = last.cost_summary();
        assert_eq!(cs.llm_calls, Some(13));
    }

    /// Mission category §4 "Idempotency": the dedup key
    /// `(agent_id_hash, trace_id, thought_id, event_type, attempt_index)`
    /// is derivable from typed values (THREAT_MODEL.md AV-9).
    #[test]
    fn dedup_key_components_typed() {
        let agent_id_hash = "deadbeef";
        let trace_id = "trace-x";
        let thought_id = "th_x";
        let c = component(
            ComponentType::Conscience,
            ReasoningEventType::ConscienceResult,
            serde_json::json!({"attempt_index": 2}),
        );
        let attempt = c.attempt_index().unwrap();
        // The five-tuple lands as concrete typed values, never as
        // serde_json::Value.
        let dedup_key = (
            agent_id_hash.to_owned(),
            trace_id.to_owned(),
            thought_id.to_owned(),
            c.event_type,
            attempt,
        );
        assert_eq!(dedup_key.3, ReasoningEventType::ConscienceResult);
        assert_eq!(dedup_key.4, 2);
    }
}
