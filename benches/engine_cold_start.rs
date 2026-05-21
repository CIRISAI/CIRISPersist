//! In-memory SQLite engine cold-start cost (v1.10.x bench-coverage
//! cut).
//!
//! Measures the full `SqliteBackend::open_in_memory()` +
//! `run_migrations()` round trip — the entire V001–V0xx migration
//! chain run end to end on a fresh `:memory:` connection. Sovereign-
//! mode / Pi-class deployments (FSD §7 #7) pay this on every process
//! start, and every SQLite integration test pays it once per test —
//! so a regression here multiplies across the whole test suite.
//!
//! Each iteration is expensive (the migration runner replays the full
//! schema), so `sample_size` is lowered to 20 to keep CI time bounded.

use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend;
use criterion::{black_box, criterion_group, criterion_main, Criterion, SamplingMode};

fn engine_cold_start(c: &mut Criterion) {
    // One runtime for the whole bench; the measured work is the
    // async open + migrate, driven via `block_on`.
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("engine_cold_start");
    // Each iter opens a connection and replays every migration —
    // multi-ms. 20 samples is enough signal without burning CI time.
    group.sample_size(20);
    // Flat sampling — the open+migrate round trip is ~12 ms; flat
    // sampling is criterion's recommended mode for slow benchmarks
    // and keeps the cold-start number tight enough to baseline.
    group.sampling_mode(SamplingMode::Flat);

    group.bench_function("sqlite_open_and_migrate", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let backend = SqliteBackend::open_in_memory().await.unwrap();
                backend.run_migrations().await.unwrap();
                // Hold the backend to the end of the closure so the
                // connection isn't dropped mid-measurement.
                black_box(&backend);
            });
        });
    });
    group.finish();
}

criterion_group!(benches, engine_cold_start);
criterion_main!(benches);
