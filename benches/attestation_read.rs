//! v62.0.0 (WASM_NODE FSD §6.4, the readiness audit's P10) — the 1000-row
//! attestation page at 1k / 16k / 100k rows.
//!
//! The FSD measured the browser node's read of one attester's exact
//! dimension at 513 ms on 100k rows: `SEARCH … USING INDEX
//! federation_attestations_attester_dimension_citation`, then `USE TEMP
//! B-TREE FOR ORDER BY` over about 60k rows of 11 KB, to keep 1000. The
//! corpus here has those proportions: 11 KB envelopes, and 60% of the rows
//! are the page's (attester, dimension) slice.
//!
//! Arms, each a 1000-row page:
//!
//! - `door_exact_dimension` — `list_attestations(attester, dimension_exact)`:
//!   V216's `(attesting_key_id, dimension, asserted_at DESC, attestation_id
//!   DESC)`, one statement, no sort. Expected FLAT across corpus size.
//! - `door_dimension_prefix` — `list_attestations(attester,
//!   dimension_prefixes)`: no index orders a dimension range, so the
//!   two-phase read sorts `(asserted_at, attestation_id, rowid)` keys and
//!   fetches the page by rowid. Grows with the slice, but sorts keys only.
//! - `v61_4_1_exact_dimension` / `v61_4_1_dimension_prefix` — the
//!   v61.4.1 statement shape on the same store: the predicate's core (key,
//!   dimension, tier, cohort), every column selected, one `ORDER BY …
//!   LIMIT 1000`, the exact-dimension form pinned to the V180 seek the FSD
//!   measured. The "before" curve.
//!
//! File-backed (a tempdir), because 100k × 11 KB does not belong in memory,
//! and seeded once per size: the reads do not mutate.

use chrono::{TimeZone, Utc};
use ciris_persist::read::{AttestationFilter, ReadEngine};
use ciris_persist::scope::CallerScope;
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};

const SIZES: &[usize] = &[1_000, 16_000, 100_000];
const PAGE: i64 = 1000;
const PAD: usize = 11 * 1024;
const ATTESTER: &str = "bench-att-a";
const OTHER: &str = "bench-att-b";
const DIM: &str = "bench:config:v1";

const COLS: &str = "attestation_id, attesting_key_id, attested_key_id, attestation_type, weight, \
    asserted_at, expires_at, attestation_envelope, original_content_hash, \
    scrub_signature_classical, scrub_signature_pqc, scrub_key_id, scrub_timestamp, \
    pqc_completed_at, persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope, \
    tier, promoted_at, additional_scrubs";

/// `n` rows: four in five by `ATTESTER`, three in four of those on `DIM`
/// (60% of the corpus is the exact slice), the rest on `bench:other:v1`;
/// ids permuted against insertion order, twelve rows to an instant. Raw SQL
/// in one transaction (the scores_read.rs precedent): the public write path
/// verifies every envelope, which would dominate the seed.
async fn seed(dir: &std::path::Path, n: usize) -> SqliteBackend {
    let path = dir.join(format!("attestation_read_{n}.db"));
    let backend = SqliteBackend::open(path.to_string_lossy().to_string())
        .await
        .unwrap();
    backend.run_migrations().await.unwrap();
    let base = Utc.with_ymd_and_hms(2026, 6, 1, 0, 0, 0).unwrap();
    let pad = "p".repeat(PAD);
    let handle = backend.conn_handle();
    let conn = handle.lock();
    conn.execute_batch("BEGIN").unwrap();
    for k in [ATTESTER, OTHER] {
        conn.execute(
            "INSERT INTO federation_keys (key_id, pubkey_ed25519_base64, algorithm, \
               identity_type, identity_ref, valid_from, registration_envelope, \
               original_content_hash, scrub_signature_classical, scrub_key_id, \
               scrub_timestamp, persist_row_hash, admitted_at) \
             VALUES (?1, 'cA==', 'hybrid', 'agent', ?1, '2026-01-01T00:00:00+00:00', '{}', \
               x'', 's', ?1, '2026-01-01T00:00:00+00:00', '0', '2026-01-01T00:00:00+00:00')",
            [k],
        )
        .unwrap();
    }
    {
        let mut st = conn
            .prepare(
                "INSERT INTO federation_attestations (attestation_id, attesting_key_id, \
                   attested_key_id, attestation_type, weight, asserted_at, expires_at, \
                   attestation_envelope, original_content_hash, scrub_signature_classical, \
                   scrub_signature_pqc, scrub_key_id, scrub_timestamp, pqc_completed_at, \
                   persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope, \
                   tier, promoted_at, admitted_at) \
                 VALUES (?1, ?2, ?2, 'scores', 1.0, ?3, NULL, ?4, x'', 's', NULL, ?2, ?3, NULL, \
                   ?5, '[]', NULL, 'federation', 'federation', NULL, ?3)",
            )
            .unwrap();
        for i in 0..n {
            let attester = if i % 5 == 4 { OTHER } else { ATTESTER };
            let dim = if i % 5 == 3 || i % 5 == 4 {
                "bench:other:v1"
            } else {
                DIM
            };
            let id = format!("bench-{:08}", (i * 7919) % n);
            let ts = (base - chrono::Duration::seconds((i / 12) as i64)).to_rfc3339();
            let env = serde_json::json!({ "dimension": dim, "score": 1.0, "pad": pad }).to_string();
            st.execute(rusqlite::params![id, attester, ts, env, format!("h-{i}")])
                .unwrap();
        }
    }
    conn.execute_batch("COMMIT; ANALYZE;").unwrap();
    drop(conn);
    backend
}

fn exact() -> AttestationFilter {
    let mut f = AttestationFilter::default();
    f.attesting_key_id = Some(ATTESTER.into());
    f.dimension_exact = Some(DIM.into());
    f
}

fn prefix() -> AttestationFilter {
    let mut f = AttestationFilter::default();
    f.attesting_key_id = Some(ATTESTER.into());
    f.dimension_prefixes = vec!["bench:".into()];
    f
}

/// The v61.4.1 one-statement shape: every column, sorted, then limited;
/// the envelope decoded per row as the door does.
fn v61_4_1(backend: &SqliteBackend, sql: &str, binds: &[&str]) -> usize {
    let handle = backend.conn_handle();
    let conn = handle.lock();
    let mut st = conn.prepare_cached(sql).unwrap();
    let rows = st
        .query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            let env: String = r.get("attestation_envelope")?;
            Ok(serde_json::from_str::<serde_json::Value>(&env).unwrap())
        })
        .unwrap()
        .count();
    rows
}

fn attestation_read(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut group = c.benchmark_group("attestation_read");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    let v61_exact = format!(
        "SELECT {COLS} FROM federation_attestations \
           INDEXED BY federation_attestations_attester_dimension_citation \
         WHERE attesting_key_id = ?1 AND dimension = ?2 AND tier = 'federation' \
           AND cohort_scope = 'federation' \
         ORDER BY asserted_at DESC, attestation_id DESC LIMIT {PAGE}"
    );
    let v61_prefix = format!(
        "SELECT {COLS} FROM federation_attestations \
         WHERE attesting_key_id = ?1 AND dimension >= ?2 AND dimension < ?3 \
           AND tier = 'federation' AND cohort_scope = 'federation' \
         ORDER BY asserted_at DESC, attestation_id DESC LIMIT {PAGE}"
    );

    for &size in SIZES {
        let backend = runtime.block_on(seed(dir.path(), size));
        let want = (size as i64 * 3 / 5).min(PAGE) as usize;
        let read = |f: AttestationFilter| {
            let page = runtime
                .block_on(backend.list_attestations(f, None, PAGE, CallerScope::Unauthenticated))
                .unwrap();
            page.items.len()
        };
        assert_eq!(read(exact()), want, "exact page");
        assert_eq!(v61_4_1(&backend, &v61_exact, &[ATTESTER, DIM]), want);

        group.bench_with_input(
            BenchmarkId::new("door_exact_dimension", size),
            &size,
            |b, _| {
                b.iter(|| black_box(read(exact())));
            },
        );
        group.bench_with_input(
            BenchmarkId::new("v61_4_1_exact_dimension", size),
            &size,
            |b, _| b.iter(|| black_box(v61_4_1(&backend, &v61_exact, &[ATTESTER, DIM]))),
        );
        group.bench_with_input(
            BenchmarkId::new("door_dimension_prefix", size),
            &size,
            |b, _| b.iter(|| black_box(read(prefix()))),
        );
        group.bench_with_input(
            BenchmarkId::new("v61_4_1_dimension_prefix", size),
            &size,
            |b, _| {
                b.iter(|| {
                    black_box(v61_4_1(
                        &backend,
                        &v61_prefix,
                        &[ATTESTER, "bench:", "bench;"],
                    ))
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, attestation_read);
criterion_main!(benches);
