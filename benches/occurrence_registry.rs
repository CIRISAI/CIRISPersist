//! Occurrence-registry substrate latency (v1.10.x bench-coverage cut).
//!
//! Benches the three hot `OccurrenceService` methods against an
//! in-memory SQLite backend:
//!
//! - `register_occurrence` — UPSERT one registry row.
//! - `heartbeat_occurrence` — UPDATE `last_heartbeat` / `expires_at`.
//! - `list_live_occurrences` — `WHERE expires_at > now` scan, swept
//!   over registry size (10 / 100 / 1000 live rows).
//!
//! The node layer calls `list_live_occurrences` on every "which
//! endpoints are reachable" query; the size sweep catches a scan that
//! degrades as the registry fills up.
//!
//! # Expected curve
//!
//! `register_occurrence` / `heartbeat_occurrence` are flat single-row
//! UPSERT/UPDATE latencies (~150–215 µs, dominated by the
//! `spawn_blocking` hop + connection-mutex acquire). `list_live_
//! occurrences` is a **linear scan** over the identity's rows —
//! measured 15.7 µs / 80 µs / 777 µs at 10 / 100 / 1000 live rows, a
//! clean ~10× step per 10× size (the /10 point is overhead-bound).
//! A super-linear slope there would mean the `(identity, expires_at)`
//! index regressed into a full-table scan.

use std::sync::Arc;

use ciris_persist::occurrence::sqlite::SqliteOccurrenceBackend;
use ciris_persist::occurrence::OccurrenceService;
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};

/// Live-registry sizes to sweep `list_live_occurrences` over.
const REGISTRY_SIZES: &[usize] = &[10, 100, 1_000];

/// Fresh migrated in-memory backend + occurrence service.
async fn fresh_occ_backend() -> (SqliteBackend, Arc<SqliteOccurrenceBackend>) {
    let backend = SqliteBackend::open_in_memory().await.unwrap();
    backend.run_migrations().await.unwrap();
    let svc = Arc::new(SqliteOccurrenceBackend::new(backend.conn_handle()));
    (backend, svc)
}

/// Backend pre-seeded with `n` live occurrences under one identity
/// (TTL well in the future so every row passes the liveness filter).
async fn seeded_occ_backend(
    identity: &str,
    n: usize,
) -> (SqliteBackend, Arc<SqliteOccurrenceBackend>) {
    let (backend, svc) = fresh_occ_backend().await;
    for i in 0..n {
        svc.register_occurrence(&format!("occ-{i:05}"), identity, 3600, None)
            .await
            .unwrap();
    }
    (backend, svc)
}

fn occurrence_registry(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("occurrence_registry");
    // Flat sampling — register/heartbeat are sub-ms and list_live at
    // 1000 rows is ~1 ms; flat sampling keeps the size-sweep curve
    // tight enough that an O(n²) scan regression stands out.
    group.sampling_mode(SamplingMode::Flat);

    // register_occurrence — single-row UPSERT latency. Fresh backend
    // per batch (built in setup) so the row count stays at one and the
    // UPSERT measures the insert path, not a growing-table cost.
    group.bench_function("register_occurrence", |b| {
        b.iter_batched(
            || runtime.block_on(fresh_occ_backend()),
            |(_backend, svc)| {
                runtime.block_on(async {
                    svc.register_occurrence(
                        black_box("occ-bench"),
                        black_box("identity-bench"),
                        3600,
                        None,
                    )
                    .await
                    .unwrap();
                });
            },
            criterion::BatchSize::PerIteration,
        );
    });

    // heartbeat_occurrence — UPDATE latency on an already-registered
    // row. The row is registered in setup; only the heartbeat UPDATE
    // is measured.
    group.bench_function("heartbeat_occurrence", |b| {
        b.iter_batched(
            || {
                runtime.block_on(async {
                    let (backend, svc) = fresh_occ_backend().await;
                    svc.register_occurrence("occ-bench", "identity-bench", 3600, None)
                        .await
                        .unwrap();
                    (backend, svc)
                })
            },
            |(_backend, svc)| {
                runtime.block_on(async {
                    let bumped = svc
                        .heartbeat_occurrence(black_box("occ-bench"), 3600)
                        .await
                        .unwrap();
                    black_box(bumped);
                });
            },
            criterion::BatchSize::PerIteration,
        );
    });

    // list_live_occurrences — swept over registry size. The seeded
    // backend is reused read-only across samples (the list is a pure
    // read; no per-iteration mutation), so it is built once per size
    // outside the measured closure.
    for &size in REGISTRY_SIZES {
        let identity = "identity-bench";
        let (backend, svc) = runtime.block_on(seeded_occ_backend(identity, size));
        group.bench_with_input(
            BenchmarkId::new("list_live_occurrences", size),
            &size,
            |b, _| {
                b.iter(|| {
                    runtime.block_on(async {
                        let live = svc
                            .list_live_occurrences(black_box(identity))
                            .await
                            .unwrap();
                        black_box(live);
                    });
                });
            },
        );
        // Hold the backend until after the bench for this size runs.
        drop(backend);
    }

    group.finish();
}

criterion_group!(benches, occurrence_registry);
criterion_main!(benches);
