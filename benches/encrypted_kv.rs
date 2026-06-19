//! `EncryptedKVStore` cold-boot + per-op overhead vs a plaintext rusqlite
//! baseline (v9.2.0, CIRISPersist#243 part 3).
//!
//! The app-layer XChaCha20-Poly1305 seal/open + the HKDF/HMAC blinding sit
//! on every `get`/`put`. This bench isolates two things CIRISEdge cares
//! about for the openmls `StorageProvider` it layers on top:
//!
//! 1. **Cold-boot open** — the one-time `XChaChaKvStore::open` cost
//!    (key-hierarchy HKDF derivation + the `__verifier__` AEAD check) vs a
//!    bare `rusqlite::Connection::open` + `CREATE TABLE`.
//! 2. **Per-op put/get** — sealed vs plaintext rows, so the AEAD + blinding
//!    tax is visible against the raw sqlite floor.
//!
//! Both stores use the SAME bundled rusqlite (the encrypted store seals at
//! the application layer — no SQLCipher, no C-dep change), so the delta is
//! purely the crypto, not a different storage engine.

use std::hint::black_box;

use ciris_persist::encrypted_kv::{EncryptedKVStore, XChaChaKvStore};
use criterion::{criterion_group, criterion_main, Criterion};
use rusqlite::Connection;

const PASS: &[u8] = b"bench-passphrase-correct-horse-battery-staple";
const NS: &str = "openmls-storage";
const VALUE: &[u8] = b"a-typical-mls-ratchet-secret-blob-payload-32+bytes";

/// A tokio current-thread runtime to drive the async KV surface.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn cold_boot(c: &mut Criterion) {
    let mut g = c.benchmark_group("encrypted_kv_cold_boot");

    // Encrypted store: open() = HKDF key hierarchy + verifier AEAD.
    g.bench_function("xchacha_open_in_memory", |b| {
        b.iter(|| {
            let s = XChaChaKvStore::open_in_memory(black_box(PASS)).unwrap();
            black_box(&s);
        });
    });

    // Plaintext baseline: bare rusqlite connection + table create.
    g.bench_function("plaintext_open_in_memory", |b| {
        b.iter(|| {
            let conn = Connection::open_in_memory().unwrap();
            conn.execute(
                "CREATE TABLE kv (ns TEXT, k BLOB, v BLOB, PRIMARY KEY (ns, k))",
                [],
            )
            .unwrap();
            black_box(&conn);
        });
    });

    g.finish();
}

fn per_op(c: &mut Criterion) {
    let rt = rt();
    let mut g = c.benchmark_group("encrypted_kv_per_op");

    // --- encrypted put/get ---
    let enc = rt.block_on(async { XChaChaKvStore::open_in_memory(PASS).unwrap() });
    g.bench_function("xchacha_put", |b| {
        b.iter(|| {
            rt.block_on(async {
                enc.put(NS, black_box(b"mls/group/key"), black_box(VALUE))
                    .await
                    .unwrap();
            });
        });
    });
    rt.block_on(async { enc.put(NS, b"mls/group/key", VALUE).await.unwrap() });
    g.bench_function("xchacha_get", |b| {
        b.iter(|| {
            rt.block_on(async {
                let v = enc.get(NS, black_box(b"mls/group/key")).await.unwrap();
                black_box(v);
            });
        });
    });

    // --- plaintext rusqlite baseline (same bundled engine) ---
    let conn = Connection::open_in_memory().unwrap();
    conn.execute(
        "CREATE TABLE kv (ns TEXT, k BLOB, v BLOB, PRIMARY KEY (ns, k))",
        [],
    )
    .unwrap();
    g.bench_function("plaintext_put", |b| {
        b.iter(|| {
            conn.execute(
                "INSERT INTO kv (ns, k, v) VALUES (?1, ?2, ?3) \
                     ON CONFLICT(ns, k) DO UPDATE SET v = excluded.v",
                rusqlite::params![NS, black_box(&b"mls/group/key"[..]), black_box(VALUE)],
            )
            .unwrap();
        });
    });
    conn.execute(
        "INSERT OR REPLACE INTO kv (ns, k, v) VALUES (?1, ?2, ?3)",
        rusqlite::params![NS, &b"mls/group/key"[..], VALUE],
    )
    .unwrap();
    g.bench_function("plaintext_get", |b| {
        b.iter(|| {
            let v: Vec<u8> = conn
                .query_row(
                    "SELECT v FROM kv WHERE ns = ?1 AND k = ?2",
                    rusqlite::params![NS, black_box(&b"mls/group/key"[..])],
                    |row| row.get(0),
                )
                .unwrap();
            black_box(v);
        });
    });

    g.finish();
}

criterion_group!(benches, cold_boot, per_op);
criterion_main!(benches);
