//! JSON subtree walker — collects NER-eligible strings during a
//! read-only pass, runs batched NER once across the whole trace,
//! then re-walks to inject the scrubbed strings and apply the
//! global regex pass.
//!
//! Lifted verbatim from CIRISLens `cirislens-core/src/scrubber/walker.rs`.
//!
//! Why two passes: NER inference is the expensive step. A trace
//! typically has 5–10 SCRUB_FIELDS-eligible string fields. Sequencing
//! those means the model runs 5–10 forward passes back-to-back;
//! batching them into a single padded forward pass is 5–10× faster
//! on CPU and ~30–50× on GPU.
//!
//! Contract preserved from v1 walker:
//!
//! - When a key in SCRUB_FIELDS is encountered, every string in that
//!   subtree is NER-scrubbed (regardless of nesting).
//! - Regex passes apply to every string in the trace, in or out of
//!   scope, so the year-residue invariant holds.

use serde_json::{Map, Value};
use std::collections::HashSet;

use super::regex::scrub_string;
use super::{ScrubError, ScrubStats};

const MAX_DEPTH: usize = 30;

/// Walk and scrub a trace's JSON. NER calls (when enabled) are
/// batched across the full trace into a single forward pass.
pub fn walk(
    value: Value,
    scrub_fields: &HashSet<&'static str>,
    stats: &mut ScrubStats,
    run_ner: bool,
) -> Result<Value, ScrubError> {
    if !run_ner {
        // Fast path: no NER. One pass, regex on every string.
        return walk_regex_only(value, stats, 0);
    }

    // Phase 1: read-only walk to collect NER-eligible strings.
    let mut ner_inputs: Vec<String> = Vec::new();
    collect_ner_inputs(&value, scrub_fields, false, &mut ner_inputs, 0)?;

    // Phase 2: batched NER call. Empty input → no-op.
    let ner_outputs = if ner_inputs.is_empty() {
        Vec::new()
    } else {
        super::ner::scrub_batch(&ner_inputs, stats)?
    };

    // Phase 3: rebuild walk that pulls NER outputs in collection
    // order and applies regex on every string.
    let mut iter = ner_outputs.into_iter();
    let out = inject_walk(value, scrub_fields, false, stats, &mut iter, 0)?;

    debug_assert!(
        iter.next().is_none(),
        "phase 1 collected more strings than phase 3 consumed",
    );
    Ok(out)
}

/// Walk and scrub a *batch* of traces in one go. Collects NER inputs
/// across **all** traces, runs ONE batched forward pass over the
/// concatenation, then injects per-trace. Amortises tokenizer +
/// model setup costs across the whole batch.
pub fn walk_batch(
    values: Vec<Value>,
    scrub_fields: &HashSet<&'static str>,
    stats: &mut ScrubStats,
    run_ner: bool,
) -> Result<Vec<Value>, ScrubError> {
    if !run_ner {
        // No NER → no batching benefit. Per-trace regex pass.
        return values
            .into_iter()
            .map(|v| walk_regex_only(v, stats, 0))
            .collect();
    }

    // Phase 1: collect per trace, recording boundary indices.
    let mut ner_inputs: Vec<String> = Vec::new();
    let mut boundaries: Vec<usize> = Vec::with_capacity(values.len() + 1);
    boundaries.push(0);
    for v in &values {
        collect_ner_inputs(v, scrub_fields, false, &mut ner_inputs, 0)?;
        boundaries.push(ner_inputs.len());
    }

    // Phase 2: ONE batched NER call across the entire batch.
    let ner_outputs = if ner_inputs.is_empty() {
        Vec::new()
    } else {
        super::ner::scrub_batch(&ner_inputs, stats)?
    };

    // Phase 3: per trace, slice the outputs Vec and inject in order.
    let mut out: Vec<Value> = Vec::with_capacity(values.len());
    for (i, v) in values.into_iter().enumerate() {
        let slice = ner_outputs[boundaries[i]..boundaries[i + 1]].to_vec();
        let mut iter = slice.into_iter();
        let scrubbed = inject_walk(v, scrub_fields, false, stats, &mut iter, 0)?;
        debug_assert!(iter.next().is_none(), "trace {i} consumed != collected");
        out.push(scrubbed);
    }
    Ok(out)
}

// ─── Phase 1: collect ───

/// Heuristic: skip NER on strings that look like programmatic labels
/// (`"string"`, `"object"`, `"completed"`, `"agent_001"`, …). No
/// uppercase, no whitespace, ASCII-only, short — a single-word
/// snake_case/lowercase token is overwhelmingly a schema label or
/// internal identifier, not a phrase that contains a named entity.
/// The regex pass still applies to these strings, so emails / years
/// / IPs / phones in a label-shaped string still get caught.
///
/// CJK / Arabic / Cyrillic strings are NOT subject to this skip — the
/// "no uppercase" condition only applies to ASCII text.
fn looks_like_schema_label(s: &str) -> bool {
    if s.len() > 24 {
        return false;
    }
    let mut all_ascii = true;
    let mut has_upper = false;
    let mut has_ws = false;
    for c in s.chars() {
        if !c.is_ascii() {
            all_ascii = false;
            break;
        }
        if c.is_ascii_uppercase() {
            has_upper = true;
        }
        if c.is_ascii_whitespace() {
            has_ws = true;
        }
    }
    all_ascii && !has_upper && !has_ws
}

fn collect_ner_inputs(
    value: &Value,
    scrub_fields: &HashSet<&'static str>,
    in_scope: bool,
    inputs: &mut Vec<String>,
    depth: usize,
) -> Result<(), ScrubError> {
    if depth > MAX_DEPTH {
        return Err(ScrubError::WalkerDepthExceeded(depth));
    }
    match value {
        Value::String(s) if in_scope && !s.trim().is_empty() && !looks_like_schema_label(s) => {
            inputs.push(s.clone());
        }
        Value::String(_) => {}
        Value::Array(arr) => {
            for item in arr {
                collect_ner_inputs(item, scrub_fields, in_scope, inputs, depth + 1)?;
            }
        }
        Value::Object(obj) => {
            for (key, val) in obj {
                let child_in_scope = in_scope || scrub_fields.contains(key.as_str());
                collect_ner_inputs(val, scrub_fields, child_in_scope, inputs, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ─── Phase 3: inject + regex ───

fn inject_walk(
    value: Value,
    scrub_fields: &HashSet<&'static str>,
    in_scope: bool,
    stats: &mut ScrubStats,
    ner_outputs: &mut std::vec::IntoIter<String>,
    depth: usize,
) -> Result<Value, ScrubError> {
    if depth > MAX_DEPTH {
        return Err(ScrubError::WalkerDepthExceeded(depth));
    }
    if depth > stats.walker_max_depth {
        stats.walker_max_depth = depth;
    }

    match value {
        Value::String(s) => {
            let after_ner = if in_scope && !s.trim().is_empty() && !looks_like_schema_label(&s) {
                ner_outputs.next().unwrap_or(s)
            } else {
                s
            };
            let scrubbed = if after_ner.trim().is_empty() {
                after_ner
            } else {
                scrub_string(&after_ner, stats)
            };
            stats.fields_modified += 1;
            Ok(Value::String(scrubbed))
        }
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(inject_walk(
                    item,
                    scrub_fields,
                    in_scope,
                    stats,
                    ner_outputs,
                    depth + 1,
                )?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(obj) => {
            let mut out = Map::with_capacity(obj.len());
            for (key, val) in obj {
                let child_in_scope = in_scope || scrub_fields.contains(key.as_str());
                let scrubbed_val = inject_walk(
                    val,
                    scrub_fields,
                    child_in_scope,
                    stats,
                    ner_outputs,
                    depth + 1,
                )?;
                out.insert(key, scrubbed_val);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other),
    }
}

// ─── No-NER fast path ───

fn walk_regex_only(
    value: Value,
    stats: &mut ScrubStats,
    depth: usize,
) -> Result<Value, ScrubError> {
    if depth > MAX_DEPTH {
        return Err(ScrubError::WalkerDepthExceeded(depth));
    }
    if depth > stats.walker_max_depth {
        stats.walker_max_depth = depth;
    }

    match value {
        Value::String(s) => {
            if s.trim().is_empty() {
                return Ok(Value::String(s));
            }
            let scrubbed = scrub_string(&s, stats);
            if scrubbed != s {
                stats.fields_modified += 1;
            }
            Ok(Value::String(scrubbed))
        }
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                out.push(walk_regex_only(item, stats, depth + 1)?);
            }
            Ok(Value::Array(out))
        }
        Value::Object(obj) => {
            let mut out = Map::with_capacity(obj.len());
            for (key, val) in obj {
                out.insert(key, walk_regex_only(val, stats, depth + 1)?);
            }
            Ok(Value::Object(out))
        }
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fields() -> HashSet<&'static str> {
        let mut s = HashSet::new();
        s.insert("flags");
        s.insert("source_ids");
        s.insert("task_description");
        s
    }

    #[test]
    fn list_of_strings_under_matched_key_scrubbed() {
        let trace = json!({
            "dma_results": {
                "csdma": {
                    "flags": ["Event in 1989", "user_query_1989_topic"]
                }
            }
        });
        let mut stats = ScrubStats::default();
        let out = walk(trace, &fields(), &mut stats, false).unwrap();
        let flags = out["dma_results"]["csdma"]["flags"].as_array().unwrap();
        assert_eq!(flags[0].as_str().unwrap(), "Event in [YEAR]");
        assert_eq!(flags[1].as_str().unwrap(), "[IDENTIFIER]");
    }

    #[test]
    fn regex_applies_globally_even_outside_scrub_fields() {
        let trace = json!({
            "metadata": {
                "non_scrub_field": "Year 1989 ought to be redacted"
            }
        });
        let mut stats = ScrubStats::default();
        let out = walk(trace, &fields(), &mut stats, false).unwrap();
        let scrubbed = out["metadata"]["non_scrub_field"].as_str().unwrap();
        assert!(!scrubbed.contains("1989"), "year leaked: {scrubbed}");
        assert!(
            scrubbed.contains("[YEAR]"),
            "year placeholder missing: {scrubbed}"
        );
    }

    #[test]
    fn nested_dict_under_matched_key_scrubbed() {
        let trace = json!({
            "task_description": {
                "primary": "see 1989 event",
                "alt": ["also 1989"]
            }
        });
        let mut stats = ScrubStats::default();
        let out = walk(trace, &fields(), &mut stats, false).unwrap();
        assert!(!out.to_string().contains("1989"));
    }

    #[test]
    fn depth_limit_enforced() {
        let mut v = Value::String("payload".to_string());
        for _ in 0..40 {
            v = json!({"x": v});
        }
        let mut stats = ScrubStats::default();
        let result = walk(v, &fields(), &mut stats, false);
        assert!(matches!(result, Err(ScrubError::WalkerDepthExceeded(_))));
    }

    #[test]
    fn scrub_stats_tracks_modifications() {
        let trace = json!({
            "task_description": "Event in 1989"
        });
        let mut stats = ScrubStats::default();
        walk(trace, &fields(), &mut stats, false).unwrap();
        assert_eq!(stats.fields_modified, 1);
        assert_eq!(stats.regex_redactions, 1);
    }
}
