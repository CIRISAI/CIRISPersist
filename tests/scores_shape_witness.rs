//! Scores-read-surface SHAPE witness (v17.4.0/#454 + v17.5.0/#456).
//!
//! Philosophy (CIRISVerify `alloc_stability.rs`): not a timing bench — a
//! deterministic COUNTING harness that CAN FAIL CI. Timing benches drift with
//! runner load and only alert on the trend chart; these tests pin the two
//! DESIGN invariants of the scores read surface as hard pass/fail:
//!
//! 1. **`resolve_scores` fold input plateaus at `RESOLVE_CANDIDATE_CAP`**
//!    (#456). The admission-path verdict fold fetches at most the newest
//!    `RESOLVE_CANDIDATE_CAP` (4096) candidate rows; a corpus past the cap
//!    surfaces `"candidates_truncated": true` in the open trace, and the
//!    trace's per-row `inputs` / `contributor_count` accounting must NOT
//!    grow when the corpus doubles past the cap. Remove the `LIMIT` and the
//!    `inputs` length tracks corpus size → these assertions fail.
//!
//! 2. **`list_scores` work is bounded by the PAGE, not the corpus** (V106).
//!    A fixed `limit=10` page over the same newest rows must be byte-
//!    identical (items + cursor) at a 1k corpus and after growing it to 16k
//!    with older rows, and the SQL shape's driving access path must be the
//!    V106 `attestation_subjects_seek` ordered seek (witnessed via
//!    `EXPLAIN QUERY PLAN` on a raw connection), never a table scan. Drop
//!    the V106 index and the plan witness fails; drop the LIMIT and the
//!    page-size assertion fails.
//!
//! Seeding is raw SQL through `SqliteBackend::conn_handle()` (the same shape
//! the in-module v17.4.0 sqlite tests use for gate-bypass rows): the public
//! `put_attestation` path hybrid-verifies every envelope, which at 12k–16k
//! rows would push this witness far past its CI budget while exercising
//! nothing the invariants are about.

#![cfg(feature = "sqlite")]

use chrono::{TimeZone, Utc};
use ciris_persist::federation::scores::RESOLVE_CANDIDATE_CAP;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::read::AttestationFilter;
use ciris_persist::store::{Backend, SqliteBackend};

/// Fixed corpus epoch — all asserted_at values derive from it, so both
/// tests are fully deterministic.
fn base_ts() -> chrono::DateTime<chrono::Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}

/// Seed `n` federation-tier `scores` rows on ONE (subject, dimension) cell,
/// one DISTINCT attester per row (so `contributor_count` counts fold inputs
/// 1:1), with `asserted_at = base + (ts_offset_secs + i)` — the offset lets
/// a second phase seed strictly NEWER or strictly OLDER rows. `id_offset`
/// keeps attestation ids / attester key ids unique across phases.
fn seed_scores_rows(
    backend: &SqliteBackend,
    subject: &str,
    dimension: &str,
    n: usize,
    id_offset: usize,
    ts_offset_secs: i64,
) {
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
        for i in 0..n {
            let seq = id_offset + i;
            let attester = format!("att-{subject}-{seq:06}");
            let att_id = format!("score-{subject}-{seq:06}");
            let ts =
                (base_ts() + chrono::Duration::seconds(ts_offset_secs + i as i64)).to_rfc3339();
            let envelope = serde_json::json!({
                "dimension": dimension, "score": 0.5, "confidence": 1.0,
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
}

/// Exact (subject, dimension) cell filter. Built field-by-field:
/// `AttestationFilter` is `#[non_exhaustive]`, so external targets cannot
/// use a struct literal.
fn cell_filter(subject: &str, dimension: &str) -> AttestationFilter {
    let mut f = AttestationFilter::default();
    f.subject_key_id = Some(subject.into());
    f.dimension_exact = Some(dimension.into());
    f
}

/// Invariant 1 (#456): the `resolve_scores` fold input is BOUNDED at
/// `RESOLVE_CANDIDATE_CAP` — the trace flags truncation, and doubling the
/// corpus past the cap does not grow the candidate/contributor accounting.
#[tokio::test]
async fn resolve_scores_fold_input_plateaus_at_candidate_cap() {
    let cap = RESOLVE_CANDIDATE_CAP as usize;
    let backend = SqliteBackend::open_in_memory().await.unwrap();
    backend.run_migrations().await.unwrap();

    // Control cell WELL BELOW the cap: no truncation, accounting == corpus.
    seed_scores_rows(&backend, "ctl", "trust:witness:v1", 100, 0, 0);
    let v = backend
        .resolve_scores(
            "",
            cell_filter("ctl", "trust:witness:v1"),
            "cc-4.4.2-signed-mean".into(),
            true,
        )
        .await
        .unwrap();
    let trace = v.trace.expect("trace requested");
    assert_eq!(
        trace["candidates_truncated"], false,
        "below-cap candidate set must NOT be flagged truncated"
    );
    assert_eq!(
        trace["inputs"].as_array().expect("inputs array").len(),
        100,
        "below the cap the fold sees the whole candidate set"
    );
    assert_eq!(v.contributor_count, 100);

    // Phase 1: one cell with 6000 rows (> 4096 cap), distinct attesters.
    let over = cap + cap / 2; // 6144 — comfortably past the cap
    seed_scores_rows(&backend, "subj", "trust:witness:v1", over, 0, 0);
    let v1 = backend
        .resolve_scores(
            "",
            cell_filter("subj", "trust:witness:v1"),
            "cc-4.4.2-signed-mean".into(),
            true,
        )
        .await
        .unwrap();
    let t1 = v1.trace.expect("trace requested");
    assert_eq!(
        t1["candidates_truncated"], true,
        "a past-cap candidate set MUST surface candidates_truncated in the trace"
    );
    let inputs1 = t1["inputs"].as_array().expect("inputs array").len();
    assert_eq!(
        inputs1, cap,
        "fold input must be exactly the newest RESOLVE_CANDIDATE_CAP rows, \
         not the {over}-row corpus — the #456 LIMIT is gone if this grew"
    );
    assert_eq!(
        v1.contributor_count as usize, cap,
        "distinct-attester corpus ⇒ contributor accounting == bounded fold input"
    );

    // Phase 2: DOUBLE the cell (strictly newer rows). The verdict re-derives
    // over the newest cap rows — accounting must NOT grow past the cap.
    seed_scores_rows(
        &backend,
        "subj",
        "trust:witness:v1",
        over,
        over,
        over as i64,
    );
    let v2 = backend
        .resolve_scores(
            "",
            cell_filter("subj", "trust:witness:v1"),
            "cc-4.4.2-signed-mean".into(),
            true,
        )
        .await
        .unwrap();
    let t2 = v2.trace.expect("trace requested");
    assert_eq!(t2["candidates_truncated"], true);
    let inputs2 = t2["inputs"].as_array().expect("inputs array").len();
    assert_eq!(
        inputs2, inputs1,
        "2x corpus past the cap must NOT grow the fold input (plateau)"
    );
    assert_eq!(
        v2.contributor_count, v1.contributor_count,
        "contributor accounting plateaus with the fold input"
    );
    assert_eq!(
        t2["contributor_count"]
            .as_u64()
            .expect("trace contributor_count") as usize,
        cap,
        "trace-side contributor accounting pinned at the cap"
    );
}

/// Invariant 2 (V106): `list_scores` page work is bounded by the PAGE, not
/// the corpus — identical page + cursor at 1k vs 16k, and the SQL shape's
/// driving access path is the `attestation_subjects_seek` ordered seek.
#[tokio::test]
async fn list_scores_page_bounded_by_page_not_corpus() {
    let backend = SqliteBackend::open_in_memory().await.unwrap();
    backend.run_migrations().await.unwrap();
    let subject = "subj";
    let dimension = "trust:witness:v1";

    // Phase 1 — 1k corpus holding the NEWEST rows (large ts offset), so
    // growing the corpus with OLDER rows can never change the newest page.
    seed_scores_rows(&backend, subject, dimension, 1_000, 0, 10_000_000);

    let (ids1_small, cur_small, ids2_small, cur2_small) =
        page_walk(&backend, subject, dimension).await;
    assert_eq!(ids1_small.len(), 10, "fixed limit=10 page — LIMIT intact");
    assert_eq!(ids2_small.len(), 10);

    // Phase 2 — grow to 16k with 15k strictly OLDER rows.
    seed_scores_rows(&backend, subject, dimension, 15_000, 1_000, 0);

    let (ids1_big, cur_big, ids2_big, cur2_big) = page_walk(&backend, subject, dimension).await;
    assert_eq!(
        ids1_small, ids1_big,
        "page 1 must be identical at 1k vs 16k corpus (page-bounded read)"
    );
    assert_eq!(
        (
            cur_small.last_asserted_at,
            cur_small.last_attestation_id.clone()
        ),
        (
            cur_big.last_asserted_at,
            cur_big.last_attestation_id.clone()
        ),
        "cursor after page 1 identical across corpus sizes"
    );
    assert_eq!(ids2_small, ids2_big, "cursor-resumed page 2 identical too");
    assert_eq!(
        cur2_small.map(|c| (c.last_asserted_at, c.last_attestation_id)),
        cur2_big.map(|c| (c.last_asserted_at, c.last_attestation_id)),
    );

    // ── plan witness: the seek must ride the V106 index, never a scan ──
    //
    // NOTE: the backend's generated SQL string is not reachable through the
    // public surface, so this EXPLAIN runs the same DRIVING shape (the
    // s-seek + join + newest-first ORDER BY + LIMIT) minus the caller-scope
    // and lifecycle predicates — those bind on `fa` columns and cannot
    // change which index drives the `attestation_subjects` access. If the
    // V106 `attestation_subjects_seek` index is dropped, SQLite falls back
    // to the projection PK / a scan and this assertion fails.
    let handle = backend.conn_handle();
    let conn = handle.lock();
    let mut stmt = conn
        .prepare(
            "EXPLAIN QUERY PLAN \
             SELECT DISTINCT fa.attestation_id \
             FROM attestation_subjects s \
             JOIN federation_attestations fa ON fa.attestation_id = s.attestation_id \
             WHERE s.subject_key_id = ?1 AND s.dimension = ?2 AND fa.tier = 'federation' \
             ORDER BY fa.asserted_at DESC, fa.attestation_id DESC LIMIT 10",
        )
        .unwrap();
    let details: Vec<String> = stmt
        .query_map(rusqlite::params![subject, dimension], |r| {
            r.get::<_, String>(3)
        })
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let plan = details.join("\n");
    assert!(
        plan.contains("attestation_subjects_seek"),
        "the subject+dimension read must be driven by the V106 \
         attestation_subjects_seek index; plan was:\n{plan}"
    );
    assert!(
        !details
            .iter()
            .any(|d| d.starts_with("SCAN s") || d.starts_with("SCAN attestation_subjects")),
        "the projection access must be a SEARCH (ordered seek), never a full \
         SCAN; plan was:\n{plan}"
    );
}

/// Walk the first two `limit=10` pages of the (subject, dimension) cell and
/// return `(page1 ids, page1 cursor, page2 ids, page2 cursor)` — the values
/// the corpus-growth comparison pins.
async fn page_walk(
    be: &SqliteBackend,
    subject: &str,
    dimension: &str,
) -> (
    Vec<String>,
    ciris_persist::read::AttestationCursor,
    Vec<String>,
    Option<ciris_persist::read::AttestationCursor>,
) {
    let f = cell_filter(subject, dimension);
    let p1 = be.list_scores("", f.clone(), None, 10).await.unwrap();
    let c1 = p1.next_cursor.clone().expect("full page ⇒ cursor");
    let p2 = be
        .list_scores("", f.clone(), Some(c1.clone()), 10)
        .await
        .unwrap();
    let ids1: Vec<String> = p1.items.iter().map(|a| a.attestation_id.clone()).collect();
    let ids2: Vec<String> = p2.items.iter().map(|a| a.attestation_id.clone()).collect();
    (ids1, c1, ids2, p2.next_cursor)
}
