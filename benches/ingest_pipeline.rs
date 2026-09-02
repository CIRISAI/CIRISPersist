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

use base64::Engine as _;
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
        // The pipeline runs `VerifyMode::Full`, so the per-trace hybrid
        // hard cut (#225) requires the ML-DSA-65 half — a classical-only
        // batch is rejected at admission. Build a hybrid batch (async
        // PQC sign driven on the bench runtime).
        let bytes = runtime.block_on(common::build_signed_batch_hybrid(
            &sk,
            "agent-bench",
            "hash-bench",
            "trace-bench-fixed",
            "th-bench-fixed",
            n_components,
        ));

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
                        // CIRISPersist#789 — admission resolves the producer's
                        // ML-DSA-65 pubkey from `federation_keys` by
                        // `pqc_key_id` and refuses when it is absent. The
                        // bench signs with `bench-mldsa` (common.rs), so that
                        // key has to be in the directory or every iteration
                        // measures a rejection instead of the pipeline.
                        runtime.block_on(async {
                            use ciris_keyring::PqcSigner as _;
                            let m = ciris_keyring::MlDsa65SoftwareSigner::from_seed_bytes(
                                &[0x77; 32],
                                "bench-mldsa",
                            )
                            .expect("ml-dsa seed");
                            let pk = m.public_key().await.expect("ml-dsa pk");
                            backend.add_pqc_public_key(
                                "bench-mldsa",
                                &base64::engine::general_purpose::STANDARD.encode(&pk),
                            );
                        });
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
