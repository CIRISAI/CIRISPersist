//! Canonicalization throughput — Python-compat vs RFC 8785 JCS.
//!
//! The canonicalizer is on every row's hot path twice — once to
//! sha256 the pre-scrub bytes (`original_content_hash`), once to
//! produce the bytes signed for `scrub_signature`. SECURITY_AUDIT
//! §3.4 named per-batch latency as a v0.2.x track item; this bench
//! gives us the data to make that decision quantitatively.
//!
//! Two implementations:
//! - PythonJsonDumpsCanonicalizer — production default; matches
//!   `json.dumps(..., sort_keys=True, ensure_ascii=False)` used by
//!   the agent's wire-format §8 signature input.
//! - Rfc8785Canonicalizer — JCS (test-only today). Bench here so we
//!   know the cost-of-correctness if a future spec moves to JCS.

use ciris_persist::verify::canonical::{Canonicalizer, PythonJsonDumpsCanonicalizer};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use serde_json::json;

fn payload_small() -> serde_json::Value {
    json!({
        "attempt_index": 0,
        "step_point": "PERFORM_DMAS",
        "rationale": "selecting the first plausible action",
        "scores": [0.81, 0.72, 0.65],
    })
}

fn payload_typical() -> serde_json::Value {
    let mut data = serde_json::Map::new();
    for i in 0..16 {
        data.insert(format!("k{i:02}"), json!(format!("value-{i:02}")));
    }
    data.insert("attempt_index".into(), json!(0));
    data.insert(
        "rationale".into(),
        json!("a short rationale text fragment of typical length"),
    );
    data.insert(
        "scores".into(),
        json!([0.81, 0.72, 0.65, 0.59, 0.42, 0.31, 0.18]),
    );
    serde_json::Value::Object(data)
}

fn payload_large() -> serde_json::Value {
    // Approximate a FULL trace-level LLM_CALL row with full prompt.
    let mut data = serde_json::Map::new();
    for i in 0..32 {
        data.insert(
            format!("field_{i:02}"),
            json!(format!("the quick brown fox jumps over the lazy dog {i}")),
        );
    }
    data.insert(
        "prompt".into(),
        json!("System: you are a helpful assistant\n\nUser: explain...".repeat(20)),
    );
    serde_json::Value::Object(data)
}

fn canonicalize_python(c: &mut Criterion) {
    let mut group = c.benchmark_group("canonicalize_python");
    let canon = PythonJsonDumpsCanonicalizer;
    for (label, payload) in [
        ("small", payload_small()),
        ("typical", payload_typical()),
        ("large", payload_large()),
    ] {
        group.bench_with_input(BenchmarkId::from_parameter(label), &payload, |b, p| {
            b.iter(|| {
                let bytes = canon.canonicalize_value(black_box(p)).unwrap();
                black_box(bytes);
            });
        });
    }
    group.finish();
}

#[cfg(test)]
mod _disabled_jcs {
    // Rfc8785Canonicalizer is `#[cfg(test)]` per
    // SECURITY_AUDIT_v0.1.2.md §4 — keeping the bench here as a
    // marker so we can wire it up the moment the JCS variant moves
    // out of test-only.
}

criterion_group!(benches, canonicalize_python);
criterion_main!(benches);
