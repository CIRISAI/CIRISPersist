//! v2.12.0 — Calibration bench for runner-noise normalization
//! (CIRISPersist#116). Anchor for the bench workflow's normalization
//! step in `.github/workflows/bench.yml`.
//!
//! ## Why this exists
//!
//! `benchmark-action/github-action-benchmark` raises regression alerts
//! based on absolute `ns/iter` values. On shared GitHub Actions
//! runners, neighbor-tenant load variation between consecutive runs
//! produces uniform 1.4×–2.5× swings across every bench in the suite.
//! The 2.11.0 vs 2.10.0 push (a 15-line PyCapsule + a verify pin bump
//! that touches nothing in any benched hot path) tripped 40
//! performance alerts solely from runner noise — exactly the false
//! positive class normalization solves.
//!
//! ## Two anchors — CPU + DRAM
//!
//! v2.12.0 shipped a single CPU-bound anchor ([`bench_calibration_splitmix`]).
//! v3.3.1 (CIRISPersist#122) adds the DRAM-bound companion
//! ([`bench_calibration_dram_walk`]) after v3.3.0's bench run
//! flagged `read_engine_analytics/aggregate_llm_costs/*` as 1.10–1.48×
//! regressed on a commit that touched no read-engine code. Diagnosis:
//! the CPU anchor (`splitmix64_10m`) doesn't normalize the
//! memory/cache axis — a runner where CPU is fast but neighbor-tenant
//! memory bandwidth contention is high produces CPU-anchored norm
//! values that look like regressions for memory-bound benches but
//! aren't.
//!
//! The workflow classifies each bench by name prefix and divides by
//! the appropriate anchor:
//! - Memory-bound prefixes (`read_engine_analytics`, `dedup_key`,
//!   `occurrence_registry`) → DRAM walk anchor
//! - Default → SplitMix64 CPU anchor
//!
//! ## Do not modify the inner loops without bumping the baseline
//!
//! The trend chart's historical points are anchored to THESE workloads.
//! Changing iteration counts, constants, the inner loop shapes, or the
//! buffer size silently invalidates the calibration baselines — the
//! gh-pages history would compare apples to oranges. If a real upgrade
//! is needed, treat it as a new metric (rename the bench function) and
//! let the trend chart reset.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// SplitMix64 — Sebastiano Vigna's reference implementation. Tight,
/// branchless, deterministic, no allocator/IO. Hardware-portable: pure
/// 64-bit integer arithmetic + multiplies, both of which every modern
/// x86_64/aarch64 CPU executes at roughly the same per-cycle
/// throughput regardless of microarchitecture.
#[inline(always)]
fn splitmix64(z: &mut u64) -> u64 {
    *z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut x = *z;
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

fn bench_calibration_splitmix(c: &mut Criterion) {
    // 10 million inner iterations. Sized so each Criterion sample
    // takes ~20-50ms on a typical runner — enough work for the
    // measurement to dominate harness overhead, short enough that 20
    // samples fit comfortably in the default 5s/group budget.
    const ITERATIONS: usize = 10_000_000;

    c.bench_function("calibration/splitmix64_10m", |b| {
        b.iter(|| {
            let mut z: u64 = 0xCAFE_BABE_DEAD_BEEF;
            for _ in 0..ITERATIONS {
                z = black_box(splitmix64(&mut z));
            }
            z
        });
    });
}

/// v3.3.1 (CIRISPersist#122) — DRAM-bound calibration anchor for
/// memory/cache-axis runner-noise normalization.
///
/// Walks a 64MB buffer (well past any L1/L2/L3 on Actions runners —
/// largest GHA L3 observed is ~36MB on the newer `ubuntu-24.04` AMD
/// EPYC images) via a deterministic LCG-driven index sequence that
/// defeats the hardware prefetcher. Each access misses cache and
/// goes to DRAM, so the bench measures the runner's effective
/// DRAM latency + bandwidth-under-contention.
///
/// Pairs with [`bench_calibration_splitmix`] (pure CPU); the workflow
/// applies whichever anchor matches each bench's bottleneck.
fn bench_calibration_dram_walk(c: &mut Criterion) {
    // 64MB buffer of u64. Sized to exceed L3 on every runner we'll
    // realistically encounter (Azure Actions runner specs cap at
    // 36MB shared L3 for the newest AMD image).
    const BUF_ELEMS: usize = 8 * 1024 * 1024;
    // 500k random reads per iteration. With ~100ns DRAM-miss
    // latency, each Criterion sample takes ~50ms — fits 20 samples
    // in the default 5s budget with margin.
    const N_ACCESSES: usize = 500_000;

    // Allocate + init once outside the bench loop (allocation cost
    // isn't what we want to measure). Sequential fill so dead-code
    // elimination can't drop the buffer.
    let buf: Vec<u64> = (0..BUF_ELEMS as u64).collect();

    c.bench_function("calibration/dram_random_walk_500k", |b| {
        b.iter(|| {
            // Numerical-Recipes LCG — `idx = a * idx + c (mod 2^64)`
            // produces a stream the hardware prefetcher can't pattern-
            // match. Each step is ~3 cycles; the DRAM miss dominates.
            let mut idx: u64 = 0x1234_5678_DEAD_BEEF;
            let mut sum: u64 = 0;
            for _ in 0..N_ACCESSES {
                idx = idx
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                // Use the high bits — they have better randomness
                // than the low bits for an LCG.
                let i = (idx >> 32) as usize % BUF_ELEMS;
                sum = sum.wrapping_add(buf[i]);
            }
            black_box(sum)
        });
    });
}

criterion_group!(
    benches,
    bench_calibration_splitmix,
    bench_calibration_dram_walk,
);
criterion_main!(benches);
