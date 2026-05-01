//! Integration tests against real `trace_schema_version: "2.7.0"`
//! fixtures captured from CIRISAgent `release/2.7.8` at d6b740ee6.
//!
//! Mission alignment (MISSION.md §4 categories): "Schema parity" and
//! "Verify rejection" are the two we exercise here. The fixtures are
//! the source of truth — anything that breaks them indicates either
//! the wire format moved (then update fixtures + update SUPPORTED_VERSIONS)
//! or our deserializer drifted (regression).
//!
//! Note: signature verification on these fixtures requires the
//! agent's actual public key, which isn't checked into the repo. We
//! assert here on what we *can* check without the key:
//!
//! 1. CompleteTrace deserializes cleanly.
//! 2. Every component has a typed event_type discriminant.
//! 3. attempt_index extraction works for every component.
//! 4. ACTION_RESULT carries the audit anchor (FSD §3.2).
//! 5. LLM_CALL components produce typed LlmCallSummary.
//! 6. Decomposition produces one row per component.
//! 7. Canonicalization is consistent (same fixture → same bytes
//!    twice).

use ciris_persist::schema::{CompleteTrace, ReasoningEventType};
use ciris_persist::store::decompose;
use ciris_persist::verify::{
    canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer},
    ed25519::canonical_payload_value,
};

const FIXTURES: &[(&str, usize, usize)] = &[
    // (filename, expected_components, expected_llm_calls)
    // Verified 2026-04-30 against the captured fixtures —
    // counts derived directly from data, not from spec.
    ("generic_0afd50b2.json", 12, 5),
    ("detailed_ed713366.json", 16, 9),
];

fn load_fixture(name: &str) -> CompleteTrace {
    let path = format!(
        "{}/tests/fixtures/wire/2.7.0/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let bytes = std::fs::read(&path).expect("read fixture");
    serde_json::from_slice::<CompleteTrace>(&bytes).expect("CompleteTrace deserialize")
}

#[test]
fn fixtures_deserialize_cleanly() {
    // Mission category §4 "Schema parity": the typed deserializer
    // accepts every recorded component shape without panicking or
    // silently coercing.
    for (name, expected_components, _) in FIXTURES {
        let trace = load_fixture(name);
        assert_eq!(
            trace.components.len(),
            *expected_components,
            "{name} component count"
        );
        assert_eq!(trace.trace_schema_version.as_str(), "2.7.0");
        assert!(!trace.signature.is_empty(), "{name} missing signature");
        assert!(
            trace.signature_key_id.starts_with("agent-"),
            "{name} key_id format"
        );
    }
}

#[test]
fn every_component_has_typed_event_type() {
    // Mission category §4 "Schema parity": no
    // ReasoningEventType::Unknown (we don't have that variant) →
    // every event_type on the wire matches a typed enum case.
    for (name, _, _) in FIXTURES {
        let trace = load_fixture(name);
        for c in &trace.components {
            // Round-trip through serde to confirm the discriminant
            // resolves both ways.
            let s = serde_json::to_string(&c.event_type).expect("serialize");
            let _: ReasoningEventType = serde_json::from_str(&s).expect("deserialize");
        }
    }
}

#[test]
fn attempt_index_extracts_for_every_component() {
    // Mission category §4 "Schema parity" + dedup-key derivation.
    // attempt_index is the dedup-tuple tail; every component must
    // carry it (TRACE_WIRE_FORMAT.md §6).
    for (name, _, _) in FIXTURES {
        let trace = load_fixture(name);
        for (i, c) in trace.components.iter().enumerate() {
            c.attempt_index().unwrap_or_else(|e| {
                panic!("{name} component {i} ({:?}): {e}", c.event_type)
            });
        }
    }
}

#[test]
fn action_result_carries_audit_anchor() {
    // Mission constraint (FSD §3.2): the agent's audit chain anchor
    // lands on the ACTION_RESULT row.
    for (name, _, _) in FIXTURES {
        let trace = load_fixture(name);
        let action = trace
            .components
            .iter()
            .find(|c| c.event_type == ReasoningEventType::ActionResult)
            .unwrap_or_else(|| panic!("{name} missing ACTION_RESULT"));
        let anchor = action
            .audit_anchor()
            .unwrap_or_else(|e| panic!("{name} audit_anchor: {e}"))
            .unwrap_or_else(|| panic!("{name} ACTION_RESULT must carry audit anchor"));
        assert!(
            anchor.audit_sequence_number > 0,
            "{name} audit_sequence_number must be positive"
        );
        assert!(
            !anchor.audit_entry_hash.is_empty(),
            "{name} audit_entry_hash empty"
        );
        // audit_signature is Optional (production agent omits it; the
        // chain link is recomputable from agent-side audit_log when
        // peer-replicate lands per FSD §4.5). When present it is
        // non-empty.
        if let Some(sig) = &anchor.audit_signature {
            assert!(!sig.is_empty(), "{name} audit_signature empty when present");
        }
    }
}

#[test]
fn llm_calls_decompose_to_typed_summaries() {
    // Mission category §4 "Schema parity": per-LLM-call rows.
    for (name, _, expected_llm_calls) in FIXTURES {
        let trace = load_fixture(name);
        let mut count = 0;
        for c in &trace.components {
            if c.event_type == ReasoningEventType::LlmCall {
                let summary = c
                    .llm_call()
                    .unwrap_or_else(|e| panic!("{name} llm_call decode: {e}"))
                    .unwrap_or_else(|| panic!("{name} LLM_CALL → llm_call() must produce Some"));
                assert!(
                    summary.duration_ms >= 0.0,
                    "{name} duration_ms non-negative"
                );
                assert!(!summary.handler_name.is_empty(), "{name} handler_name set");
                assert!(!summary.service_name.is_empty(), "{name} service_name set");
                count += 1;
            }
        }
        assert_eq!(
            count, *expected_llm_calls,
            "{name} LLM_CALL count"
        );
    }
}

#[test]
fn decompose_produces_one_row_per_component() {
    // FSD §3.3 step 4 contract: every component → one trace_events
    // row; LLM_CALL also → one trace_llm_calls row.
    for (name, expected_components, expected_llm_calls) in FIXTURES {
        let trace = load_fixture(name);
        let d = decompose(&trace).unwrap_or_else(|e| panic!("{name} decompose: {e}"));
        assert_eq!(d.events.len(), *expected_components, "{name} events count");
        assert_eq!(
            d.llm_calls.len(),
            *expected_llm_calls,
            "{name} llm_calls count"
        );
        // Mission constraint (MISSION.md §3 anti-pattern #2):
        // signature_verified=true on every produced row (we haven't
        // actually verified yet — but decompose's contract is that
        // it never emits signature_verified=false).
        assert!(d.events.iter().all(|e| e.signature_verified));
    }
}

#[test]
fn canonicalization_is_deterministic() {
    // Mission category §4 "Canonicalization parity": same trace,
    // canonicalized twice, must produce the same bytes. Drift here
    // breaks signature verification.
    for (name, _, _) in FIXTURES {
        let trace = load_fixture(name);
        let payload = canonical_payload_value(&trace);
        let b1 = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload)
            .unwrap();
        let b2 = PythonJsonDumpsCanonicalizer
            .canonicalize_value(&payload)
            .unwrap();
        assert_eq!(b1, b2, "{name} canonicalization deterministic");
    }
}

#[test]
fn dedup_keys_unique_within_each_trace() {
    // Mission category §4 "Idempotency": every component within a
    // CompleteTrace produces a distinct
    // (trace_id, thought_id, event_type, attempt_index) tuple.
    // Repeated event_types use attempt_index to discriminate.
    for (name, _, _) in FIXTURES {
        let trace = load_fixture(name);
        let mut seen = std::collections::HashSet::new();
        for c in &trace.components {
            let key = (
                trace.trace_id.clone(),
                trace.thought_id.clone(),
                c.event_type,
                c.attempt_index().unwrap(),
            );
            assert!(
                seen.insert(key.clone()),
                "{name} duplicate dedup key: {:?}",
                key
            );
        }
    }
}

#[test]
fn fixture_set_covers_all_phase1_event_types() {
    // Every Phase 1 trace event variant the FSD §3.1 schema/ module
    // declares is exercised by at least one fixture (except
    // VERB_SECOND_PASS_RESULT and TSASPDMA_RESULT and ROUND_COMPLETE
    // per the README).
    let mut seen = std::collections::HashSet::new();
    for (name, _, _) in FIXTURES {
        let trace = load_fixture(name);
        for c in &trace.components {
            seen.insert(c.event_type);
        }
    }
    let required = [
        ReasoningEventType::ThoughtStart,
        ReasoningEventType::SnapshotAndContext,
        ReasoningEventType::DmaResults,
        ReasoningEventType::IdmaResult,
        ReasoningEventType::AspdmaResult,
        ReasoningEventType::ConscienceResult,
        ReasoningEventType::ActionResult,
        ReasoningEventType::LlmCall,
    ];
    for r in &required {
        assert!(
            seen.contains(r),
            "fixture set must cover {:?} — captured set is missing it",
            r
        );
    }
}
