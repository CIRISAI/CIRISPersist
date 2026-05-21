//! Secrets crypto facade single-call latency (v1.10.x bench-coverage
//! cut).
//!
//! `crypto::encrypt` / `crypto::decrypt` (AES-256-GCM via the
//! `ciris_crypto` facade — `src/secrets/crypto.rs`) sit on the
//! `store_secret` / `get_secret` hot paths. This bench measures the
//! per-call cost at a few plaintext sizes; AES-GCM is roughly linear
//! in plaintext length, so the size sweep makes a throughput
//! regression (a slower GCM backend, an extra copy) visible.
//!
//! No DB — needs only the `secrets` feature. PBKDF2 key derivation is
//! deliberately NOT benched here: it runs once at SecretsService init
//! (600k iterations, intentionally slow) and is not a per-call cost.

use ciris_persist::secrets::crypto;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

/// Plaintext sizes (bytes): a typical short secret (API token), a
/// medium config blob, and a large bundled credential file.
const SIZES: &[usize] = &[64, 1_024, 16_384];

fn secrets_crypto(c: &mut Criterion) {
    // Fixed key + nonce — key/nonce generation is its own RNG cost and
    // not what this bench isolates. 32-byte key, 12-byte nonce per the
    // facade's KEY_LEN / NONCE_LEN.
    let key = [0x11u8; crypto::KEY_LEN];
    let nonce = [0x22u8; crypto::NONCE_LEN];

    let mut enc_group = c.benchmark_group("secrets_encrypt");
    for &size in SIZES {
        let plaintext = vec![0xABu8; size];
        enc_group.throughput(Throughput::Bytes(size as u64));
        enc_group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &plaintext,
            |b, plaintext| {
                b.iter(|| {
                    let ct =
                        crypto::encrypt(black_box(&key), black_box(&nonce), black_box(plaintext))
                            .unwrap();
                    black_box(ct);
                });
            },
        );
    }
    enc_group.finish();

    let mut dec_group = c.benchmark_group("secrets_decrypt");
    for &size in SIZES {
        let plaintext = vec![0xABu8; size];
        // Pre-encrypt outside the measured closure so the bench times
        // decrypt alone, not an encrypt+decrypt round trip.
        let ciphertext = crypto::encrypt(&key, &nonce, &plaintext).unwrap();
        dec_group.throughput(Throughput::Bytes(size as u64));
        dec_group.bench_with_input(
            BenchmarkId::from_parameter(size),
            &ciphertext,
            |b, ciphertext| {
                b.iter(|| {
                    let pt =
                        crypto::decrypt(black_box(&key), black_box(&nonce), black_box(ciphertext))
                            .unwrap();
                    black_box(pt);
                });
            },
        );
    }
    dec_group.finish();
}

criterion_group!(benches, secrets_crypto);
criterion_main!(benches);
