//! Async-wrapper cost decomposition (v1.10.x bench-coverage cut).
//!
//! Every persist DB call on the SQLite backend pays a fixed
//! async-wrapper tax before any SQL runs: the `block_on` entry (every
//! PyO3 method drives the async core through `runtime.block_on`), then
//! a `spawn_blocking` hop so the blocking rusqlite call cannot stall
//! the tokio reactor. The substrate benches (`sequence_contention`,
//! `occurrence_registry`, …) measure storage **+** wrapper together —
//! and on a contended box the wrapper dominates, which makes their
//! absolute numbers an async-overhead measurement, not a storage one.
//!
//! This bench decomposes the cost so each layer is tracked on the
//! dashboard independently:
//!
//! - `block_on_noop`       — `runtime.block_on(async {})`. The
//!   `block_on` entry cost, alone.
//! - `spawn_blocking_noop` — `block_on(spawn_blocking(|| {}))`. Adds
//!   the blocking-pool hop. *(this minus `block_on_noop` = the
//!   `spawn_blocking` cost.)*
//! - `raw_sqlite_write`    — a synchronous in-memory SQLite UPSERT, no
//!   tokio at all. The **storage floor** — what SQLite itself costs.
//! - `next_sequence_full`  — the real `SequenceService::next_sequence`
//!   call: `block_on` + `spawn_blocking` + connection lock + UPSERT.
//!
//! # Reading it
//!
//! If `next_sequence_full ≈ spawn_blocking_noop` (and both ≫
//! `raw_sqlite_write`), the **wrapper, not the storage, is the cost** —
//! and the wrapper is the thing to optimise. The honest substrate
//! latency is `raw_sqlite_write`; the honest tax is
//! `next_sequence_full − raw_sqlite_write`.

use std::sync::Arc;

use ciris_persist::sequence::sqlite::SqliteSequenceBackend;
use ciris_persist::sequence::SequenceService;
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// Multi-thread runtime — the production shape (every `Engine` builds
/// a multi-thread runtime); a current-thread runtime would understate
/// the `spawn_blocking` worker-wake cost.
fn multi_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

fn storage_floor(c: &mut Criterion) {
    let runtime = multi_thread_runtime();

    // One migrated in-memory backend, reused across all probes — this
    // is a latency decomposition, not a scaling sweep, so the SUT is
    // built once outside every measured closure.
    let backend = runtime.block_on(async {
        let b = SqliteBackend::open_in_memory().await.unwrap();
        b.run_migrations().await.unwrap();
        b
    });
    let conn = backend.conn_handle();
    let seq = Arc::new(SqliteSequenceBackend::new(backend.conn_handle()));

    // Dedicated single-row table for the raw-SQL storage-floor probe —
    // its own table so it never drifts against a substrate's schema.
    {
        let guard = conn.lock();
        guard
            .execute(
                "CREATE TABLE bench_floor (k TEXT PRIMARY KEY, v INTEGER NOT NULL)",
                [],
            )
            .unwrap();
    }

    let mut group = c.benchmark_group("storage_floor");

    // block_on entry cost — a trivial future driven to completion.
    group.bench_function("block_on_noop", |b| {
        b.iter(|| runtime.block_on(async { black_box(0u8) }));
    });

    // + the spawn_blocking hop (blocking-pool dispatch + worker wake).
    group.bench_function("spawn_blocking_noop", |b| {
        b.iter(|| {
            runtime.block_on(async {
                black_box(
                    tokio::task::spawn_blocking(|| black_box(0u8))
                        .await
                        .unwrap(),
                )
            })
        });
    });

    // The storage floor — a synchronous in-memory SQLite UPSERT, no
    // tokio in the path at all.
    group.bench_function("raw_sqlite_write", |b| {
        b.iter(|| {
            let guard = conn.lock();
            guard
                .execute(
                    "INSERT INTO bench_floor (k, v) VALUES ('probe', 1) \
                     ON CONFLICT (k) DO UPDATE SET v = v + 1",
                    [],
                )
                .unwrap();
        });
    });

    // The real call: block_on + spawn_blocking + lock + UPSERT.
    group.bench_function("next_sequence_full", |b| {
        b.iter(|| {
            runtime.block_on(async {
                black_box(
                    seq.next_sequence("floor-identity", "floor-stream")
                        .await
                        .unwrap(),
                )
            })
        });
    });

    group.finish();
}

criterion_group!(benches, storage_floor);
criterion_main!(benches);
