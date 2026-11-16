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
//! Arms, each a 1000-row page, on two stores seeded identically: v62's,
//! and v61.4.1's (V216 dropped, re-analyzed):
//!
//! - `door_*` — `list_attestations` through the public door (decode,
//!   observation and all): the number a caller sees.
//! - `v62_*` — the door's own statements, raw, with one light decode
//!   (the envelope parsed): exact dimension is one V216 seek; the prefix is
//!   the two-phase read (phase one's rowids, then each row by rowid).
//! - `v61_4_1_*` — the v61.4.1 statements (`attestation_read_sql.rs`,
//!   generated from the builder: lifecycle and scope predicates included)
//!   on the v61.4.1 store, with the same decode. `v62_*` against
//!   `v61_4_1_*` is the change, like for like.
//!
//! Each arm's EXPLAIN QUERY PLAN is printed per size.
//!
//! File-backed (a tempdir), because 100k × 11 KB does not belong in memory,
//! and seeded once per size: the reads do not mutate.

use chrono::{TimeZone, Utc};
use ciris_persist::read::{AttestationFilter, ReadEngine};
use ciris_persist::scope::CallerScope;
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend;
#[path = "attestation_read_sql.rs"]
mod sql;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};

const SIZES: &[usize] = &[1_000, 16_000, 100_000];
const PAGE: i64 = 1000;
const PAD: usize = 11 * 1024;
const ATTESTER: &str = "bench-att-a";
const OTHER: &str = "bench-att-b";
const DIM: &str = "bench:config:v1";

/// `n` rows: four in five by `ATTESTER`, three in four of those on `DIM`
/// (60% of the corpus is the exact slice), the rest on `bench:other:v1`;
/// ids permuted against insertion order, twelve rows to an instant. Raw SQL
/// in one transaction (the scores_read.rs precedent): the public write path
/// verifies every envelope, which would dominate the seed.
async fn seed(dir: &std::path::Path, n: usize, tag: &str) -> SqliteBackend {
    let path = dir.join(format!("attestation_read_{tag}_{n}.db"));
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
/// `binds` as SQL values: the last is the LIMIT, an integer.
fn values(binds: &[&str]) -> Vec<rusqlite::types::Value> {
    let (limit, text) = binds.split_last().unwrap();
    text.iter()
        .map(|b| rusqlite::types::Value::Text((*b).to_owned()))
        .chain([rusqlite::types::Value::Integer(limit.parse().unwrap())])
        .collect()
}

/// `EXPLAIN QUERY PLAN` of `sql`, one line per node.
fn plan(backend: &SqliteBackend, sql: &str, binds: &[&str]) -> Vec<String> {
    let handle = backend.conn_handle();
    let conn = handle.lock();
    let mut st = conn.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    let rows = st
        .query_map(rusqlite::params_from_iter(values(binds)), |r| {
            r.get::<_, String>(3)
        })
        .unwrap()
        .map(Result::unwrap)
        .filter(|l| l.contains("federation_attestations") || l.contains("TEMP"))
        .collect();
    rows
}

fn v61_4_1(backend: &SqliteBackend, sql: &str, binds: &[&str]) -> usize {
    let handle = backend.conn_handle();
    let conn = handle.lock();
    let mut st = conn.prepare_cached(sql).unwrap();
    let rows = st
        .query_map(rusqlite::params_from_iter(values(binds)), |r| {
            let env: String = r.get("attestation_envelope")?;
            Ok(serde_json::from_str::<serde_json::Value>(&env).unwrap())
        })
        .unwrap()
        .count();
    rows
}

/// The v62 two-phase read, raw: phase one's rowids in page order, then each
/// row by rowid, decoded as [`v61_4_1`] decodes.
fn v62_two_phase(backend: &SqliteBackend, phase_one: &str, binds: &[&str]) -> usize {
    let handle = backend.conn_handle();
    let conn = handle.lock();
    let tx = conn.unchecked_transaction().unwrap();
    let rowids: Vec<i64> = {
        let mut st = tx.prepare_cached(phase_one).unwrap();
        let v = st
            .query_map(rusqlite::params_from_iter(values(binds)), |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        v
    };
    let mut st = tx
        .prepare_cached("SELECT attestation_envelope FROM federation_attestations WHERE rowid = ?1")
        .unwrap();
    let mut n = 0;
    for id in rowids {
        let env: String = st.query_row([id], |r| r.get(0)).unwrap();
        black_box(serde_json::from_str::<serde_json::Value>(&env).unwrap());
        n += 1;
    }
    n
}

fn attestation_read(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let mut group = c.benchmark_group("attestation_read");
    group.sample_size(10);
    group.sampling_mode(SamplingMode::Flat);

    let exact_binds = [ATTESTER, DIM, "supersedes", "withdraws", "recants", "1000"];
    let prefix_binds = [
        ATTESTER,
        "bench:",
        "bench;",
        "supersedes",
        "withdraws",
        "recants",
        "1000",
    ];

    for &size in SIZES {
        // Two stores from one seed: v62's (V216), and v61.4.1's (V216
        // dropped, re-analyzed), so the "before" plans are v61.4.1's own.
        let backend = runtime.block_on(seed(dir.path(), size, "v62"));
        let before = runtime.block_on(seed(dir.path(), size, "v61"));
        before
            .conn_handle()
            .lock()
            .execute_batch(
                "DROP INDEX federation_attestations_attester_dimension_asserted; \
                 DROP INDEX federation_attestations_attested_dimension_asserted; ANALYZE;",
            )
            .unwrap();
        let want = (size as i64 * 3 / 5).min(PAGE) as usize;
        let want_prefix = (size as i64 * 4 / 5).min(PAGE) as usize;
        let read = |f: AttestationFilter| {
            let page = runtime
                .block_on(backend.list_attestations(f, None, PAGE, CallerScope::Unauthenticated))
                .unwrap();
            page.items.len()
        };
        for (arm, store, stmt, binds) in [
            (
                "v62_exact_dimension",
                &backend,
                sql::DOOR_EXACT,
                &exact_binds[..],
            ),
            (
                "v61_4_1_exact_dimension",
                &before,
                sql::V61_4_1_EXACT,
                &exact_binds[..],
            ),
            (
                "v62_dimension_prefix (phase one)",
                &backend,
                sql::DOOR_PREFIX_PHASE_ONE,
                &prefix_binds[..],
            ),
            (
                "v61_4_1_dimension_prefix",
                &before,
                sql::V61_4_1_PREFIX,
                &prefix_binds[..],
            ),
        ] {
            eprintln!("PLAN {size} {arm}: {:?}", plan(store, stmt, binds));
        }
        assert_eq!(read(exact()), want, "exact page");
        assert_eq!(read(prefix()), want_prefix, "prefix page");
        assert_eq!(v61_4_1(&backend, sql::DOOR_EXACT, &exact_binds), want);
        assert_eq!(v61_4_1(&before, sql::V61_4_1_EXACT, &exact_binds), want);
        assert_eq!(
            v62_two_phase(&backend, sql::DOOR_PREFIX_PHASE_ONE, &prefix_binds),
            want_prefix
        );
        assert_eq!(
            v61_4_1(&before, sql::V61_4_1_PREFIX, &prefix_binds),
            want_prefix
        );

        let id = |arm: &str| BenchmarkId::new(arm.to_owned(), size);
        group.bench_function(id("door_exact_dimension"), |b| {
            b.iter(|| black_box(read(exact())))
        });
        group.bench_function(id("v62_exact_dimension"), |b| {
            b.iter(|| black_box(v61_4_1(&backend, sql::DOOR_EXACT, &exact_binds)))
        });
        group.bench_function(id("v61_4_1_exact_dimension"), |b| {
            b.iter(|| black_box(v61_4_1(&before, sql::V61_4_1_EXACT, &exact_binds)))
        });
        group.bench_function(id("door_dimension_prefix"), |b| {
            b.iter(|| black_box(read(prefix())))
        });
        group.bench_function(id("v62_dimension_prefix"), |b| {
            b.iter(|| {
                black_box(v62_two_phase(
                    &backend,
                    sql::DOOR_PREFIX_PHASE_ONE,
                    &prefix_binds,
                ))
            })
        });
        group.bench_function(id("v61_4_1_dimension_prefix"), |b| {
            b.iter(|| black_box(v61_4_1(&before, sql::V61_4_1_PREFIX, &prefix_binds)))
        });
    }
    group.finish();
}

criterion_group!(benches, attestation_read);
criterion_main!(benches);
