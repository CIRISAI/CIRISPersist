//! Static-coded feature extraction.
//!
//! Lifted verbatim from CIRISLensCore `src/extract/static_extract.rs`
//! (v0.6.0-α3). Walks a trace body and populates the typed
//! [`Features`] struct.
//!
//! # Adaptation from legacy
//!
//! Legacy returned `HashMap<String, String>` keyed by `db_column`,
//! with `unwrap_or_default()` on missing fields and `log::warn!` on
//! required-missing. This port returns a typed [`Features`] struct
//! and propagates "missing" as `Option::None` — Phase 1 lens-core
//! treats missing inputs as "feature not available," not "feature
//! is 0." Detector code consuming `None` decides whether to flag
//! `IndeterminateReason::InferredCohortAmbiguous` or to score with
//! reduced features; this module does not silently default.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde_json::Value;

use super::features::{
    DeclaredCohortAxes, Features, ModelClass, ObservationWeights, StepTimestamps,
};

/// Per-event_type list of "store this component as a full JSON blob."
const FULL_BLOB_EVENT_TYPES: &[&str] = &[
    "DMA_RESULTS",
    "ASPDMA_RESULT",
    "IDMA_RESULT",
    "TSASPDMA_RESULT",
    "CONSCIENCE_RESULT",
    "ACTION_RESULT",
];

/// Walk a trace body and populate the typed [`Features`] struct.
///
/// `trace` is the trace JSON body (post-scrub, pre-detector).
/// `declared` is supplied by the caller from the envelope's
/// `deployment_profile` block (V006 denormalized fields); not parsed
/// from the body since it lives at envelope level, not component
/// level.
pub fn extract_features(trace: &Value, declared: DeclaredCohortAxes) -> Features {
    let mut step_timestamps = StepTimestamps::default();
    let mut observation_weights = ObservationWeights::default();
    let mut component_blobs: HashMap<String, Value> = HashMap::new();
    let mut models_used: Vec<String> = Vec::new();

    let components = trace
        .get("components")
        .and_then(|c| c.as_array())
        .map(Vec::as_slice)
        .unwrap_or(&[]);

    for component in components {
        let event_type = component
            .get("event_type")
            .and_then(|e| e.as_str())
            .unwrap_or("");

        let data = component.get("data").unwrap_or(component);

        // Concern #1 — step timestamps.
        if let Some(ts_str) = component.get("timestamp").and_then(|t| t.as_str()) {
            if let Some(parsed) = parse_iso8601(ts_str) {
                set_step_timestamp(&mut step_timestamps, event_type, parsed);
            }
        }

        // Concern #2 — observation weights.
        extract_observation_weights(&mut observation_weights, event_type, data);

        // models_used (cost-feature input for LC-AV-2).
        if let Some(models) = data.get("models_used").and_then(|m| m.as_array()) {
            for m in models {
                if let Some(s) = m.as_str() {
                    models_used.push(s.to_string());
                }
            }
        }

        // Concern #4 — full-component blobs. Specific extraction
        // takes precedence — legacy guards against overwriting with
        // `if !metadata.contains_key`. We mirror that by inserting
        // only-if-absent.
        if let Some(key) = blob_key_for(event_type) {
            component_blobs
                .entry(key.to_owned())
                .or_insert_with(|| data.clone());
        }
    }

    let total_tokens = derive_total_tokens(&observation_weights);
    let model_class = derive_model_class(&models_used);

    Features {
        declared,
        step_timestamps,
        observation_weights,
        models_used,
        component_blobs,
        // P0 LC-AV-2 cost feature. Computation requires the
        // RATCHET-delivered cost_rates table; until that lands, the
        // placeholder is 0.0 and detectors that depend on cost
        // should treat 0.0 as "unavailable."
        cost_estimate: 0.0,
        total_tokens,
        model_class,
    }
}

/// Map event_type to the matching [`StepTimestamps`] field.
fn set_step_timestamp(ts: &mut StepTimestamps, event_type: &str, parsed: DateTime<Utc>) {
    match event_type {
        "THOUGHT_START" => ts.thought_start = Some(parsed),
        "SNAPSHOT_AND_CONTEXT" => ts.snapshot = Some(parsed),
        "DMA_RESULTS" => ts.dma_results = Some(parsed),
        "ASPDMA_RESULT" => ts.aspdma = Some(parsed),
        "IDMA_RESULT" => ts.idma = Some(parsed),
        "TSASPDMA_RESULT" => ts.tsaspdma = Some(parsed),
        "CONSCIENCE_RESULT" => ts.conscience = Some(parsed),
        "ACTION_RESULT" => ts.action_result = Some(parsed),
        _ => {}
    }
}

/// Per-event_type observation-weight extraction. Multi-fallback field
/// names preserved verbatim — the legacy crate observed varied wire
/// shapes across agent versions and accepted whichever was present.
fn extract_observation_weights(weights: &mut ObservationWeights, event_type: &str, data: &Value) {
    match event_type {
        "SNAPSHOT_AND_CONTEXT" => {
            if let Some(memories) = data.get("relevant_memories").and_then(|m| m.as_array()) {
                weights.memory_count = Some(memories.len() as u32);
            }

            // Token count: explicit `context_tokens` → `total_tokens`
            // → estimated from `gathered_context.len() / 4`.
            let tokens = data
                .get("context_tokens")
                .and_then(|t| t.as_i64())
                .or_else(|| data.get("total_tokens").and_then(|t| t.as_i64()))
                .or_else(|| {
                    data.get("gathered_context")
                        .and_then(|c| c.as_str())
                        .map(|s| (s.len() / 4) as i64)
                });
            if let Some(t) = tokens {
                if t >= 0 {
                    weights.context_tokens = Some(t as u32);
                }
            }

            if let Some(history) = data.get("conversation_history").and_then(|h| h.as_array()) {
                weights.conversation_turns = Some(history.len() as u32);
            }
        }
        "ASPDMA_RESULT" => {
            // Three fallback names: action_options →
            // evaluated_actions → alternatives.
            let alternatives = data
                .get("action_options")
                .and_then(|a| a.as_array())
                .or_else(|| data.get("evaluated_actions").and_then(|a| a.as_array()))
                .or_else(|| data.get("alternatives").and_then(|a| a.as_array()));
            if let Some(arr) = alternatives {
                weights.alternatives_considered = Some(arr.len() as u32);
            }
        }
        "CONSCIENCE_RESULT" => {
            // Three fallback array names → fall through to per-flag
            // counting if none present.
            let checks = data
                .get("checks")
                .and_then(|c| c.as_array())
                .or_else(|| data.get("ethical_checks").and_then(|c| c.as_array()))
                .or_else(|| data.get("check_results").and_then(|c| c.as_array()));
            if let Some(arr) = checks {
                weights.conscience_checks_count = Some(arr.len() as u32);
            } else {
                let mut count = 0u32;
                for key in [
                    "entropy_passed",
                    "coherence_passed",
                    "optimization_veto_passed",
                    "epistemic_humility_passed",
                    "integrity_check_passed",
                ] {
                    if data.get(key).is_some() {
                        count += 1;
                    }
                }
                if count > 0 {
                    weights.conscience_checks_count = Some(count);
                }
            }
        }
        _ => {}
    }
}

/// Map event_type to the static blob-key string. Returns `None` for
/// event_types that don't store a full-component blob.
fn blob_key_for(event_type: &str) -> Option<&'static str> {
    if !FULL_BLOB_EVENT_TYPES.contains(&event_type) {
        return None;
    }
    Some(match event_type {
        "DMA_RESULTS" => "dma_results",
        "ASPDMA_RESULT" => "aspdma_result",
        "IDMA_RESULT" => "idma_result",
        "TSASPDMA_RESULT" => "tsaspdma_result",
        "CONSCIENCE_RESULT" => "conscience_result",
        "ACTION_RESULT" => "action_result",
        _ => unreachable!("guarded by FULL_BLOB_EVENT_TYPES"),
    })
}

/// Derive `total_tokens: u64` from observation weights. Phase 1:
/// take the `SNAPSHOT_AND_CONTEXT.context_tokens` reading; 0 if
/// absent.
fn derive_total_tokens(weights: &ObservationWeights) -> u64 {
    weights.context_tokens.map(u64::from).unwrap_or(0)
}

/// Derive a coarse [`ModelClass`] from the observed `models_used`.
/// Phase 1: take the first observed model name.
fn derive_model_class(models_used: &[String]) -> ModelClass {
    match models_used.first() {
        Some(name) => ModelClass::Named(name.clone()),
        None => ModelClass::Unknown,
    }
}

/// ISO-8601 timestamp parsing. Returns `None` on malformed input —
/// matches legacy's "missing/malformed → no timestamp recorded"
/// behavior.
fn parse_iso8601(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn declared_default() -> DeclaredCohortAxes {
        DeclaredCohortAxes::default()
    }

    #[test]
    fn empty_trace_extracts_empty_features() {
        let trace = json!({"components": []});
        let f = extract_features(&trace, declared_default());
        assert!(f.models_used.is_empty());
        assert!(f.component_blobs.is_empty());
        assert!(f.step_timestamps.thought_start.is_none());
        assert_eq!(f.total_tokens, 0);
        assert!(matches!(f.model_class, ModelClass::Unknown));
    }

    #[test]
    fn step_timestamps_populated() {
        let trace = json!({
            "components": [
                {"event_type": "THOUGHT_START", "timestamp": "2026-05-03T12:00:00Z", "data": {}},
                {"event_type": "SNAPSHOT_AND_CONTEXT", "timestamp": "2026-05-03T12:00:01Z", "data": {}},
                {"event_type": "ACTION_RESULT", "timestamp": "2026-05-03T12:00:05Z", "data": {}},
            ]
        });
        let f = extract_features(&trace, declared_default());
        assert!(f.step_timestamps.thought_start.is_some());
        assert!(f.step_timestamps.snapshot.is_some());
        assert!(f.step_timestamps.action_result.is_some());
        assert!(f.step_timestamps.dma_results.is_none());
    }

    #[test]
    fn observation_weights_snapshot() {
        let trace = json!({
            "components": [{
                "event_type": "SNAPSHOT_AND_CONTEXT",
                "data": {
                    "relevant_memories": ["a", "b", "c"],
                    "conversation_history": [{"role":"user"}, {"role":"assistant"}],
                    "context_tokens": 1500
                }
            }]
        });
        let f = extract_features(&trace, declared_default());
        assert_eq!(f.observation_weights.memory_count, Some(3));
        assert_eq!(f.observation_weights.conversation_turns, Some(2));
        assert_eq!(f.observation_weights.context_tokens, Some(1500));
        assert_eq!(f.total_tokens, 1500);
    }

    #[test]
    fn conscience_per_flag_fallback() {
        let trace = json!({
            "components": [{
                "event_type": "CONSCIENCE_RESULT",
                "data": {
                    "entropy_passed": true,
                    "coherence_passed": true,
                    "optimization_veto_passed": false,
                }
            }]
        });
        let f = extract_features(&trace, declared_default());
        assert_eq!(f.observation_weights.conscience_checks_count, Some(3));
    }

    #[test]
    fn full_blob_storage_first_wins() {
        let trace = json!({
            "components": [
                {"event_type": "DMA_RESULTS", "data": {"first": 1}},
                {"event_type": "DMA_RESULTS", "data": {"second": 2}},
            ]
        });
        let f = extract_features(&trace, declared_default());
        let blob = f.component_blobs.get("dma_results").unwrap();
        assert_eq!(blob.get("first"), Some(&json!(1)));
        assert!(blob.get("second").is_none());
    }

    #[test]
    fn models_used_collected_across_components() {
        let trace = json!({
            "components": [
                {"event_type": "ACTION_RESULT", "data": {"models_used": ["claude-3-opus"]}},
                {"event_type": "DMA_RESULTS", "data": {"models_used": ["gpt-4o"]}},
            ]
        });
        let f = extract_features(&trace, declared_default());
        assert_eq!(f.models_used, vec!["claude-3-opus", "gpt-4o"]);
        match f.model_class {
            ModelClass::Named(ref n) => assert_eq!(n, "claude-3-opus"),
            _ => panic!("expected Named"),
        }
    }

    #[test]
    fn features_serde_round_trip() {
        // V009 stores Features in trace_events.extracted_features JSONB.
        // Round-trip through serde to verify wire stability.
        let trace = json!({
            "components": [{
                "event_type": "SNAPSHOT_AND_CONTEXT",
                "timestamp": "2026-05-03T12:00:01Z",
                "data": {"relevant_memories": ["a"], "context_tokens": 100}
            }]
        });
        let f = extract_features(&trace, declared_default());
        let s = serde_json::to_string(&f).unwrap();
        let back: Features = serde_json::from_str(&s).unwrap();
        assert_eq!(back.total_tokens, f.total_tokens);
        assert_eq!(
            back.observation_weights.memory_count,
            f.observation_weights.memory_count
        );
    }
}
