//! Bounded ingest queue throughput.
//!
//! `spawn_persister` returns an `IngestHandle` over a tokio mpsc.
//! AV-19 graceful shutdown depends on this queue draining cleanly;
//! this bench measures submit throughput on a fresh queue with the
//! persister actually consuming. Regression here would mean either
//! producer-side contention (mutex bouncing in mpsc) or consumer
//! starvation (slow backend draining the queue).

use std::sync::Arc;
use std::time::Duration;

use ciris_keyring::HardwareSigner;
use ciris_persist::scrub::NullScrubber;
use ciris_persist::store::MemoryBackend;
use ciris_persist::verify::PythonJsonDumpsCanonicalizer;
use ciris_persist::{spawn_persister, Journal, DEFAULT_QUEUE_DEPTH};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

#[path = "common.rs"]
mod common;

fn queue_submit_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("queue_submit");
    let runtime = tokio::runtime::Runtime::new().unwrap();

    for &batch_count in &[8usize, 32, 128] {
        let sk = common::make_signing_key(0xCC);
        // Pre-build batches; submit cost should not include
        // construction. Use distinct trace_ids so they don't
        // dedup-conflict downstream (we measure submit + drain end
        // to end).
        let bodies: Vec<Vec<u8>> = (0..batch_count)
            .map(|i| {
                common::build_signed_batch(
                    &sk,
                    "agent-bench",
                    "hash-bench",
                    &format!("trace-q-{i:04}"),
                    &format!("th-q-{i:04}"),
                    4,
                )
            })
            .collect();

        group.throughput(Throughput::Elements(batch_count as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(batch_count),
            &bodies,
            |b, batches| {
                b.iter_with_setup(
                    || {
                        // Fresh backend + journal + persister per
                        // iteration. Using tempfile dir for the
                        // journal — redb opens fast (~ms).
                        let dir = tempfile::tempdir().unwrap();
                        let journal = Arc::new(Journal::open(dir.path().join("j.redb")).unwrap());
                        let backend = Arc::new(MemoryBackend::new());
                        backend.add_public_key("agent-bench", sk.verifying_key());
                        let signer = Arc::<dyn HardwareSigner>::from(common::test_signer());
                        let (handle, persister) = spawn_persister(
                            DEFAULT_QUEUE_DEPTH,
                            backend,
                            Arc::new(PythonJsonDumpsCanonicalizer),
                            Arc::new(NullScrubber),
                            journal,
                            signer,
                            "bench-signer".to_owned(),
                        );
                        (handle, persister, dir)
                    },
                    |(handle, persister, _dir)| {
                        runtime.block_on(async {
                            for body in batches {
                                handle
                                    .submit_with_timeout(
                                        black_box(body.clone()),
                                        Duration::from_secs(2),
                                    )
                                    .await
                                    .unwrap();
                            }
                            drop(handle);
                            persister
                                .shutdown_with_timeout(Duration::from_secs(15))
                                .await
                                .unwrap();
                        });
                    },
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, queue_submit_throughput);
criterion_main!(benches);
