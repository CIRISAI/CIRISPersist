//! Atomic sequence-counter contention (v1.10.x bench-coverage cut).
//!
//! `SequenceService::next_sequence` is a single
//! `INSERT … ON CONFLICT … DO UPDATE … RETURNING` UPSERT — correct
//! under concurrent callers, but the cost profile under fan-in is the
//! question. Under the one-key model (`sequence/mod.rs`) every
//! in-process consumer + agent occurrence issues against the *same*
//! `(identity, stream)` row; this bench sweeps N concurrent tasks all
//! issuing against one row.
//!
//! # Expected curve
//!
//! `sequence_contention_sqlite/next_sequence/{1,2,8,32}` is a single
//! series — on SQLite, *every* write serializes through one
//! `Mutex<Connection>`, so same-row vs distinct-row contention is
//! indistinguishable (a distinct-identity series measured identically
//! in testing: 347≈424 / 587≈533 / 948≈990 µs). Splitting it would be
//! two copies of one curve. The shape is two-regime: per-call cost
//! *falls* from N=1→8 as the connection-mutex pipeline amortizes
//! per-spawn overhead, then total time grows ~linearly N=8→32 once
//! the mutex is saturated. A regression shows as the whole curve
//! shifting up.
//!
//! Note this measures *fan-in* — each task is a `tokio::spawn`, so
//! even the `N=1` point includes a task-spawn hop and is **not** the
//! single-call latency. For the un-spawned, decomposed per-call cost
//! (`block_on` + `spawn_blocking` + UPSERT ≈ 10 µs) see
//! `benches/storage_floor.rs`.
//!
//! The contended-vs-distinct distinction is real only on **Postgres**
//! (true row-level locks inside `ON CONFLICT DO UPDATE`, not a process
//! mutex) — `sequence_contention_postgres` is the meaningful
//! contention test. It is gated behind the `postgres` feature AND
//! `CIRIS_PERSIST_TEST_PG_URL`, and skips cleanly when unset (the
//! case on bench.yml's runner — no Postgres service).

use std::sync::Arc;

use ciris_persist::sequence::sqlite::SqliteSequenceBackend;
use ciris_persist::sequence::SequenceService;
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend;
use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};

/// Build a multi-thread tokio runtime for the bench. A current-thread
/// runtime would serialize the "concurrent" tasks onto one OS thread
/// and measure cooperative scheduling, not contention; the
/// multi-thread runtime lets the `spawn_blocking` UPSERTs actually
/// race for the connection mutex.
fn multi_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap()
}

/// Fresh migrated in-memory backend + a `SqliteSequenceBackend` over
/// its shared connection handle.
async fn fresh_seq_backend() -> (SqliteBackend, Arc<SqliteSequenceBackend>) {
    let backend = SqliteBackend::open_in_memory().await.unwrap();
    backend.run_migrations().await.unwrap();
    let svc = Arc::new(SqliteSequenceBackend::new(backend.conn_handle()));
    (backend, svc)
}

/// Spawn `n` tasks each calling `next_sequence` once on the shared
/// `(identity, stream)` row, join all. One row is the one-key-model
/// case (`sequence/mod.rs`); on SQLite the connection mutex serializes
/// every UPSERT regardless of row, so a distinct-row variant would
/// measure identically — see the module docs.
async fn issue_n(svc: &Arc<SqliteSequenceBackend>, n: usize) {
    let mut handles = Vec::with_capacity(n);
    for _ in 0..n {
        let svc = svc.clone();
        handles.push(tokio::spawn(async move {
            svc.next_sequence("shared-identity", "stream-bench")
                .await
                .unwrap()
        }));
    }
    for h in handles {
        black_box(h.await.unwrap());
    }
}

fn sequence_contention_sqlite(c: &mut Criterion) {
    let runtime = multi_thread_runtime();

    let mut group = c.benchmark_group("sequence_contention_sqlite");
    // Flat sampling — each measured unit is N spawned UPSERT tasks
    // joining (hundreds of µs to low ms); flat sampling keeps the
    // fan-in curve tight enough to read against, instead of drowning
    // it in linear-sampling jitter.
    group.sampling_mode(SamplingMode::Flat);
    for &n in &[1usize, 2, 8, 32] {
        group.throughput(Throughput::Elements(n as u64));
        // One series: N tasks fan in on the shared row. The backend is
        // rebuilt per iteration in setup so the counter state stays
        // deterministic and isn't part of the timed closure.
        group.bench_with_input(BenchmarkId::new("next_sequence", n), &n, |b, &n| {
            b.iter_batched(
                || runtime.block_on(fresh_seq_backend()),
                |(_backend, svc)| {
                    runtime.block_on(issue_n(&svc, n));
                },
                criterion::BatchSize::PerIteration,
            );
        });
    }
    group.finish();
}

/// Postgres contention path — the truer test (real row-level locks
/// inside `ON CONFLICT DO UPDATE`, not a process-side mutex).
/// `SequenceService` is implemented directly on `PostgresBackend`.
/// Skipped cleanly when `CIRIS_PERSIST_TEST_PG_URL` is unset, which is
/// the case on bench.yml's runner (no Postgres service).
#[cfg(feature = "postgres")]
fn sequence_contention_postgres(c: &mut Criterion) {
    use ciris_persist::store::postgres::PostgresBackend;

    let Ok(url) = std::env::var("CIRIS_PERSIST_TEST_PG_URL") else {
        eprintln!("sequence_contention: CIRIS_PERSIST_TEST_PG_URL unset — skipping Postgres path");
        return;
    };
    let runtime = multi_thread_runtime();

    // Connect + migrate once, outside the measured loop.
    let backend = match runtime.block_on(PostgresBackend::connect(&url)) {
        Ok(b) => Arc::new(b),
        Err(e) => {
            eprintln!("sequence_contention: Postgres connect failed ({e}) — skipping");
            return;
        }
    };
    runtime.block_on(backend.run_migrations()).unwrap();

    let mut group = c.benchmark_group("sequence_contention_postgres");
    group.sampling_mode(SamplingMode::Flat);
    for &n in &[1usize, 2, 8, 32] {
        group.throughput(Throughput::Elements(n as u64));
        group.bench_with_input(BenchmarkId::new("contended", n), &n, |b, &n| {
            b.iter(|| {
                runtime.block_on(async {
                    // Unique identity per iteration so the counter
                    // doesn't grow unboundedly across the run.
                    let identity = format!("bench-{}", uuid::Uuid::new_v4().simple());
                    let mut handles = Vec::with_capacity(n);
                    for _ in 0..n {
                        let backend = backend.clone();
                        let id = identity.clone();
                        handles.push(tokio::spawn(async move {
                            SequenceService::next_sequence(backend.as_ref(), &id, "stream-bench")
                                .await
                                .unwrap()
                        }));
                    }
                    for h in handles {
                        black_box(h.await.unwrap());
                    }
                });
            });
        });
    }
    group.finish();
}

#[cfg(feature = "postgres")]
criterion_group!(
    benches,
    sequence_contention_sqlite,
    sequence_contention_postgres
);
#[cfg(not(feature = "postgres"))]
criterion_group!(benches, sequence_contention_sqlite);
criterion_main!(benches);
