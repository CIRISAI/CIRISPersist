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
//! ## What this measures
//!
//! A fixed-iteration SplitMix64 loop. Pure 64-bit integer arithmetic
//! plus multiplies — no IO, no allocator pressure, no syscalls, and
//! no hardware-acceleration variance (no SHA-NI / AES-NI / RDRAND
//! path — those vary by runner image and bias the calibration).
//!
//! The bench workflow extracts this bench's `ns/iter` and divides
//! every other bench's `ns/iter` by it (scaled), so the published
//! values are in "calibration units" — the wall-time cost relative
//! to a deterministic CPU primitive. Runner-load shifts cancel:
//! every bench's `ns/iter` scales with the runner's CPU availability;
//! so does the calibration's. The ratio is runner-independent.
//!
//! ## Do not modify the inner loop without bumping the baseline
//!
//! The trend chart's historical points are anchored to THIS workload.
//! Changing the iteration count, the splitmix constants, or the inner
//! loop shape silently invalidates the calibration baseline — the
//! gh-pages history would compare apples to oranges. If a real
//! upgrade is needed, treat it as a new metric (rename the bench
//! function) and let the trend chart reset.

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

criterion_group!(benches, bench_calibration_splitmix);
criterion_main!(benches);
