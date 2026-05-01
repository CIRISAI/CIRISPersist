//! Decompose + dedup-key construction throughput.
//!
//! The dedup tuple
//! `(agent_id_hash, trace_id, thought_id, event_type, attempt_index)`
//! (THREAT_MODEL.md AV-9) is computed once per persisted row. A
//! large batch pushes hundreds of these into the in-memory dedup
//! HashMap or the Postgres ON CONFLICT lookup; regression here would
//! flow through to ingest throughput.
//!
//! Bench measures full decompose path (verified CompleteTrace →
//! `Vec<TraceEventRow>` + dedup_key extraction) on a typical batch.

use ciris_persist::schema::CompleteTrace;
use ciris_persist::store::{decompose, dedup_key};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

#[path = "common.rs"]
mod common;

fn build_trace(n_components: usize) -> CompleteTrace {
    let sk = common::make_signing_key(0xAB);
    let bytes = common::build_signed_batch(
        &sk,
        "agent-bench",
        "hash-bench",
        "trace-bench",
        "th-bench",
        n_components,
    );
    let env: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let trace_v = env["events"][0]["trace"].clone();
    serde_json::from_value(trace_v).unwrap()
}

fn decompose_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompose");
    for &n in &[1usize, 6, 16, 64] {
        let trace = build_trace(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &trace, |b, t| {
            b.iter(|| {
                let d = decompose(black_box(t)).unwrap();
                black_box(d);
            });
        });
    }
    group.finish();
}

fn dedup_key_only(c: &mut Criterion) {
    // Once decomposed, every row's dedup key is built per insert.
    // Strip the bench down to the key-construction path alone.
    let trace = build_trace(16);
    let decomposed = decompose(&trace).unwrap();

    c.bench_function("dedup_key_per_row", |b| {
        b.iter(|| {
            for row in &decomposed.events {
                let k = dedup_key(black_box(row));
                black_box(k);
            }
        });
    });
}

criterion_group!(benches, decompose_throughput, dedup_key_only);
criterion_main!(benches);
