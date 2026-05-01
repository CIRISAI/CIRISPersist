//! End-to-end ingest pipeline throughput against MemoryBackend.
//!
//! The full path: bytes-in → schema parse → verify → scrub → sign →
//! decompose → backend insert. SECURITY_AUDIT_v0.1.4.md §3.4 named
//! per-batch latency as observable from this number; QA scenario A
//! exercises 768 rows in ~9 ms (release mode), this bench gives the
//! per-batch unit cost across component-count sweeps.
//!
//! Sweep is 1 / 6 / 16 / 64 components — covers single-step traces,
//! typical thoughts, full thoughts with all H3ERE steps, and stress.

use ciris_keyring::HardwareSigner;
use ciris_persist::ingest::IngestPipeline;
use ciris_persist::scrub::NullScrubber;
use ciris_persist::store::MemoryBackend;
use ciris_persist::verify::PythonJsonDumpsCanonicalizer;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

#[path = "common.rs"]
mod common;

fn ingest_pipeline_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("ingest_pipeline");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    // Belt-and-suspenders runtime guard — IngestPipeline doesn't
    // call tokio::spawn directly in v0.1.7, but
    // `Backend::insert_trace_events_batch` may in future backends,
    // and `cargo test --all-targets` runs bench bins in smoke mode
    // outside any runtime context. See benches/queue.rs comment.
    let _guard = runtime.enter();

    for &n_components in &[1usize, 6, 16, 64] {
        // Pre-build the request body for each iteration; we re-use
        // the same agent_id_hash / signing key but vary trace_id per
        // iter so the dedup tuple doesn't conflict and we measure
        // the success path (not the ON CONFLICT short-circuit).
        let sk = common::make_signing_key(0xBE);
        // One canonical batch — we measure pipeline throughput on
        // identical batches to keep the variable isolated to
        // component count. To avoid dedup short-circuit we rebuild
        // the backend each iteration.
        let bytes = common::build_signed_batch(
            &sk,
            "agent-bench",
            "hash-bench",
            "trace-bench-fixed",
            "th-bench-fixed",
            n_components,
        );

        group.throughput(Throughput::Elements(n_components as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(n_components),
            &bytes,
            |b, body| {
                b.iter_with_setup(
                    || {
                        // Setup: fresh backend per iteration so dedup
                        // doesn't short-circuit. The MemoryBackend
                        // constructor is cheap (one Mutex per Vec).
                        let backend = MemoryBackend::new();
                        backend.add_public_key("agent-bench", sk.verifying_key());
                        backend
                    },
                    |backend| {
                        runtime.block_on(async {
                            let signer = common::test_signer();
                            let signer_ref: &dyn HardwareSigner = signer.as_ref();
                            let pipeline = IngestPipeline {
                                backend: &backend,
                                canonicalizer: &PythonJsonDumpsCanonicalizer,
                                scrubber: &NullScrubber,
                                signer: signer_ref,
                                signer_key_id: "bench-signer",
                            };
                            let summary =
                                pipeline.receive_and_persist(black_box(body)).await.unwrap();
                            black_box(summary);
                        });
                    },
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, ingest_pipeline_sweep);
criterion_main!(benches);
