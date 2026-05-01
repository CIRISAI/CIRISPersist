//! Ed25519 signing latency.
//!
//! Measures the per-call cost of `Ed25519SoftwareSigner::sign`. The
//! production hot path signs once per row (FSD §3.3 step 3.5; v0.1.3
//! scrub-signing), so this latency × component count = the
//! signing-tax-per-batch operators see in deployment logs.
//!
//! SECURITY_AUDIT_v0.1.4.md §3.4 cited "~30 µs hardware / ~100 µs
//! software" as the operational distinction; this bench is the
//! source of truth for the software side. Hardware-backed signers
//! aren't available in CI runners.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[path = "common.rs"]
mod common;

fn sign_short(c: &mut Criterion) {
    // Realistic small payload — a typical canonicalised
    // `data_post_scrub` blob ranges 200-500 bytes.
    let payload = vec![0xABu8; 256];
    let signer = common::test_signer();
    let runtime = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("sign_256_bytes", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let sig = signer.sign(black_box(&payload)).await.unwrap();
                black_box(sig);
            })
        });
    });
}

fn sign_typical(c: &mut Criterion) {
    // Production component sizes hover around 1-2 KiB for `detailed`
    // trace level on action_result rows. Sample at 1 KiB.
    let payload = vec![0xCDu8; 1024];
    let signer = common::test_signer();
    let runtime = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("sign_1024_bytes", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let sig = signer.sign(black_box(&payload)).await.unwrap();
                black_box(sig);
            })
        });
    });
}

fn sign_large(c: &mut Criterion) {
    // FULL trace level can ship LLM_CALL prompts verbatim — push a
    // 16 KiB sample to bound the long tail.
    let payload = vec![0xEFu8; 16 * 1024];
    let signer = common::test_signer();
    let runtime = tokio::runtime::Runtime::new().unwrap();

    c.bench_function("sign_16384_bytes", |b| {
        b.iter(|| {
            runtime.block_on(async {
                let sig = signer.sign(black_box(&payload)).await.unwrap();
                black_box(sig);
            })
        });
    });
}

criterion_group!(benches, sign_short, sign_typical, sign_large);
criterion_main!(benches);
