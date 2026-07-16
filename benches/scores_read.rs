//! v17.4.0/v17.5.0 scores-read-surface scaling (FSD-005 Appendix C).
//!
//! Seeds an in-memory `SqliteBackend` `federation_attestations` +
//! `attestation_subjects` (V106 projection) corpus at parameterized row
//! counts, then benches the three `FederationDirectory` read handles that
//! shipped in v17.4.0 (#454) / v17.5.0 (#455/#456) with zero bench coverage:
//!
//! - `list_scores` — subject+dimension ordered seek, fixed page.
//! - `resolve_scores` — the Appendix C.3 verdict fold, candidate sweep
//!   CROSSING `RESOLVE_CANDIDATE_CAP`.
//! - `list_attestation_log` — owner-scope full walk + subject-seek page.
//!
//! # Expected curve
//!
//! - `list_scores` and `list_attestation_log(subject)` ride the V106
//!   `attestation_subjects_seek` index with a fixed LIMIT — the curve across
//!   the 1k→16k corpus sweep should be FLAT (page-bounded, not
//!   corpus-bounded). A slope here means the ordered seek regressed to a
//!   scan (index dropped / query shape broke) — the same invariant
//!   `tests/scores_shape_witness.rs` gates on in CI; this bench makes the
//!   magnitude visible on the trend chart.
//! - `list_attestation_log(full)` is a LIMITed newest-first walk of the base
//!   table; also expected flat across corpus size.
//! - `resolve_scores` grows with candidate count UP TO
//!   `RESOLVE_CANDIDATE_CAP` (4096) and must PLATEAU past it — the 8192
//!   point should match the 4096 point (the #456 fold-input bound). A slope
//!   in the 4096→8192 segment means the cap is gone.
//!
//! # Deviation from `read_engine_analytics.rs` (documented)
//!
//! The model bench reseeds per iteration (`iter_batched` /
//! `BatchSize::PerIteration`) because its primitives run in
//! milliseconds-to-hundreds-of-ms, so iteration counts stay tiny. The
//! handles here are PAGE reads in the microsecond range — criterion runs
//! thousands of iterations per sample, so a per-iteration 16k-row reseed
//! would blow the bench job's budget by orders of magnitude. The reads are
//! non-mutating, so each size is seeded ONCE and shared across samples;
//! `SamplingMode::Flat` + bounded `sample_size` are kept from the model.

use chrono::{TimeZone, Utc};
use ciris_persist::federation::scores::RESOLVE_CANDIDATE_CAP;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::read::AttestationFilter;
use ciris_persist::store::sqlite::SqliteBackend;
use ciris_persist::store::Backend;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};

/// Corpus sizes for the page-read handles (`list_scores`,
/// `list_attestation_log`). The flat-curve claim needs the asymptotic end
/// (16k) to be visibly larger than the small end (1k).
const LIST_SIZES: &[usize] = &[1_000, 4_000, 16_000];

/// Candidate counts (rows on ONE subject/dimension) for `resolve_scores`.
/// Deliberately CROSSES `RESOLVE_CANDIDATE_CAP` (4096): the 8192 point
/// witnesses the #456 plateau — fold input is capped at the newest 4096.
const RESOLVE_SIZES: &[usize] = &[256, 1_024, 4_096, 8_192];

/// Seed `n_rows` federation-tier `scores` rows spread over
/// `n_subjects × n_dims` (subject, dimension) cells, one DISTINCT attester
/// per row (the worst case for the per-attester latest-wins fold), plus the
/// V106 `attestation_subjects` projection row each read handle seeks on.
///
/// Raw-SQL seeding (same shape as the in-module v17.4.0 sqlite tests): the
/// public `put_attestation` path hybrid-verifies every envelope, which at
/// bench scale would dominate the seed by orders of magnitude and measures
/// the wrong thing. One transaction + prepared statements keeps a 16k-row
/// seed in the tens of milliseconds.
async fn seed_corpus(n_rows: usize, n_subjects: usize, n_dims: usize) -> SqliteBackend {
    let backend = SqliteBackend::open_in_memory().await.unwrap();
    backend.run_migrations().await.unwrap();
    let base = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
    let handle = backend.conn_handle();
    let conn = handle.lock();
    conn.execute_batch("BEGIN").unwrap();
    {
        let mut key_stmt = conn
            .prepare_cached(
                "INSERT INTO federation_keys (key_id, pubkey_ed25519_base64, algorithm, \
                   identity_type, identity_ref, valid_from, registration_envelope, \
                   original_content_hash, scrub_signature_classical, scrub_key_id, \
                   scrub_timestamp, persist_row_hash) \
                 VALUES (?1, 'cA==', 'hybrid', 'agent', ?1, '2026-01-01T00:00:00+00:00', '{}', \
                   x'', 's', ?1, '2026-01-01T00:00:00+00:00', '0')",
            )
            .unwrap();
        let mut att_stmt = conn
            .prepare_cached(
                "INSERT INTO federation_attestations (attestation_id, attesting_key_id, \
                   attested_key_id, attestation_type, weight, asserted_at, expires_at, \
                   attestation_envelope, original_content_hash, scrub_signature_classical, \
                   scrub_signature_pqc, scrub_key_id, scrub_timestamp, pqc_completed_at, \
                   persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope, \
                   tier, promoted_at) \
                 VALUES (?1, ?2, ?2, 'scores', 1.0, ?3, NULL, ?4, x'', 's', NULL, ?2, ?3, \
                   NULL, '0', ?5, NULL, 'federation', 'federation', NULL)",
            )
            .unwrap();
        let mut proj_stmt = conn
            .prepare_cached(
                "INSERT INTO attestation_subjects (subject_key_id, dimension, asserted_at, \
                   attestation_id, tier, cohort_scope) \
                 VALUES (?1, ?2, ?3, ?4, 'federation', 'federation')",
            )
            .unwrap();
        for i in 0..n_rows {
            let attester = format!("att-{i:06}");
            let att_id = format!("score-{i:06}");
            let subject = format!("subj-{:02}", i % n_subjects);
            let dimension = format!("trust:bench{}:v1", (i / n_subjects) % n_dims);
            let ts = (base + chrono::Duration::seconds(i as i64)).to_rfc3339();
            let score = 0.5 + (((i % 9) as f64) - 4.0) * 0.1;
            let envelope = serde_json::json!({
                "dimension": dimension, "score": score, "confidence": 1.0,
                "epistemic_mode": "observed",
            })
            .to_string();
            let subjects_json = serde_json::json!([subject]).to_string();
            key_stmt.execute(rusqlite::params![attester]).unwrap();
            att_stmt
                .execute(rusqlite::params![
                    att_id,
                    attester,
                    ts,
                    envelope,
                    subjects_json
                ])
                .unwrap();
            proj_stmt
                .execute(rusqlite::params![subject, dimension, ts, att_id])
                .unwrap();
        }
    }
    conn.execute_batch("COMMIT").unwrap();
    drop(conn);
    backend
}

/// The `list_scores` filter under bench: exact (subject, dimension) cell —
/// the V106 ordered-seek hot path. Built field-by-field: `AttestationFilter`
/// is `#[non_exhaustive]`, so external targets cannot use a struct literal.
fn seek_filter() -> AttestationFilter {
    let mut f = AttestationFilter::default();
    f.subject_key_id = Some("subj-00".into());
    f.dimension_exact = Some("trust:bench0:v1".into());
    f
}

fn scores_read(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();

    let mut group = c.benchmark_group("scores_read");
    // Bounded sample count + flat sampling (see read_engine_analytics.rs):
    // flat mode keeps per-point CIs tight so the plateau/flat-curve claims
    // are readable on the trend chart.
    group.sample_size(20);
    group.sampling_mode(SamplingMode::Flat);

    // ── page reads over a corpus sweep: expected FLAT curves ──
    for &size in LIST_SIZES {
        let backend = runtime.block_on(seed_corpus(size, 8, 4));

        // list_scores — subject+dimension ordered seek, fixed page limit 10.
        group.bench_with_input(BenchmarkId::new("list_scores_seek", size), &size, |b, _| {
            b.iter(|| {
                runtime.block_on(async {
                    let page = backend
                        .list_scores("", seek_filter(), None, 10)
                        .await
                        .unwrap();
                    black_box(page);
                });
            });
        });

        // list_attestation_log — subject-seek page (rides V106).
        group.bench_with_input(
            BenchmarkId::new("list_attestation_log_subject_seek", size),
            &size,
            |b, _| {
                b.iter(|| {
                    runtime.block_on(async {
                        let page = backend
                            .list_attestation_log(Some("subj-00"), None, 100)
                            .await
                            .unwrap();
                        black_box(page);
                    });
                });
            },
        );

        // list_attestation_log — full-walk page (anti-entropy shape; base
        // table newest-first, no subject seek).
        group.bench_with_input(
            BenchmarkId::new("list_attestation_log_full_walk", size),
            &size,
            |b, _| {
                b.iter(|| {
                    runtime.block_on(async {
                        let page = backend.list_attestation_log(None, None, 100).await.unwrap();
                        black_box(page);
                    });
                });
            },
        );
    }

    // ── resolve_scores — candidate sweep crossing RESOLVE_CANDIDATE_CAP ──
    assert!(
        RESOLVE_SIZES
            .iter()
            .any(|&n| n as i64 > RESOLVE_CANDIDATE_CAP),
        "sweep must cross RESOLVE_CANDIDATE_CAP to witness the plateau"
    );
    for &n in RESOLVE_SIZES {
        // ONE (subject, dimension) cell, n candidate rows, distinct attesters.
        let backend = runtime.block_on(seed_corpus(n, 1, 1));
        let filter = seek_filter();
        group.bench_with_input(BenchmarkId::new("resolve_scores_fold", n), &n, |b, _| {
            b.iter(|| {
                runtime.block_on(async {
                    let verdict = backend
                        .resolve_scores(
                            "",
                            filter.clone(),
                            "cc-4.4.2-signed-mean".to_string(),
                            false,
                        )
                        .await
                        .unwrap();
                    black_box(verdict);
                });
            });
        });
    }

    group.finish();
}

criterion_group!(benches, scores_read);
criterion_main!(benches);
