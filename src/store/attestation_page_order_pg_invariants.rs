//! v62.0.0 (WASM_NODE FSD §6.4, the readiness audit's P10) — the attestation
//! page in its order, postgres. I1813 / I1814; the sqlite twins (I1810–I1812)
//! sit beside the I531 two-phase precedent in `sqlite.rs`'s tests.
//!
//! The corpus is the sqlite twins': two attesters (`a` writes three rows in
//! four) over two subjects and three dimensions, twelve rows to an instant,
//! ids permuted against insertion order, every row visible to an
//! unauthenticated reader.

// Test-only, as a block the from-disk gates read (family_rules' prefix
// closure among them).
#[cfg(all(test, feature = "postgres"))]
mod witnesses {
    use crate::read::ReadEngine as _;
    use crate::store::postgres::{pg_list_attestations_sql, PostgresBackend};
    use crate::store::Backend as _;

    const ATT_A: &str = "p10-att-a";
    const ATT_B: &str = "p10-att-b";

    type Row = (
        String,
        String,
        String,
        String,
        chrono::DateTime<chrono::Utc>,
    );
    type Params<'a> = Vec<&'a (dyn tokio_postgres::types::ToSql + Sync)>;

    async fn seed(b: &PostgresBackend, n: i64) {
        let (pk, _) = crate::federation::tier_ingest::test_support::hybrid_pubkeys("p10-pg");
        let client = b.get_client().await.unwrap();
        for k in [ATT_A, ATT_B] {
            client
                .execute(
                    "INSERT INTO cirislens.federation_keys (key_id, pubkey_ed25519_base64, algorithm, \
                       identity_type, identity_ref, valid_from, registration_envelope, \
                       original_content_hash, scrub_signature_classical, scrub_key_id, \
                       scrub_timestamp, persist_row_hash, admitted_at) \
                     VALUES ($1, $2, 'hybrid', 'agent', $1, '2026-01-01T00:00:00Z', '{}', '\\x00', \
                       'sig', $1, '2026-01-01T00:00:01Z', 'h', '2026-01-01T00:00:01Z')",
                    &[&k, &pk],
                )
                .await
                .unwrap();
        }
        let inserted = client
            .execute(
                "INSERT INTO cirislens.federation_attestations (attestation_id, attesting_key_id, \
                   attested_key_id, attestation_type, weight, asserted_at, expires_at, \
                   attestation_envelope, original_content_hash, scrub_signature_classical, \
                   scrub_signature_pqc, scrub_key_id, scrub_timestamp, pqc_completed_at, \
                   persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope, tier, \
                   promoted_at, additional_scrubs, admitted_at) \
                 SELECT 'p10-' || lpad(((n * 7919) % $1)::text, 7, '0'), k, 'p10-subj-' || (n % 2), \
                   'scores', 1.0, ts, NULL, \
                   json_build_object('dimension', CASE n % 3 WHEN 0 THEN 'p10:x:v1' \
                                      WHEN 1 THEN 'p10:y:v1' ELSE 'p10:z:v1' END)::text, \
                   '\\x00'::bytea, 'sig', NULL, k, ts, NULL, 'p10-h-' || n, '[]', NULL, \
                   'federation', 'federation', NULL, '[]', ts \
                 FROM (SELECT n, CASE WHEN n % 4 = 3 THEN 'p10-att-b' ELSE 'p10-att-a' END AS k, \
                              '2026-06-01T00:00:00Z'::timestamptz \
                                - make_interval(mins => (n / 12)::int) AS ts \
                       FROM generate_series(0::bigint, $1::bigint - 1) AS n) r",
                &[&n],
            )
            .await
            .unwrap();
        assert_eq!(inserted as i64, n, "the corpus landed");
    }

    /// `n` rows by a third attester on another dimension, all NEWER than the
    /// corpus: walked in time order (V212), a corpus slice sits behind them.
    async fn seed_noise(b: &PostgresBackend, n: i64) {
        let (pk, _) = crate::federation::tier_ingest::test_support::hybrid_pubkeys("p10-pg-noise");
        let client = b.get_client().await.unwrap();
        client
            .execute(
                "INSERT INTO cirislens.federation_keys (key_id, pubkey_ed25519_base64, algorithm, \
                   identity_type, identity_ref, valid_from, registration_envelope, \
                   original_content_hash, scrub_signature_classical, scrub_key_id, \
                   scrub_timestamp, persist_row_hash, admitted_at) \
                 VALUES ('p10-att-noise', $1, 'hybrid', 'agent', 'p10-att-noise', \
                   '2026-01-01T00:00:00Z', '{}', '\\x00', 'sig', 'p10-att-noise', \
                   '2026-01-01T00:00:01Z', 'h', '2026-01-01T00:00:01Z')",
                &[&pk],
            )
            .await
            .unwrap();
        client
            .execute(
                "INSERT INTO cirislens.federation_attestations (attestation_id, attesting_key_id, \
                   attested_key_id, attestation_type, weight, asserted_at, expires_at, \
                   attestation_envelope, original_content_hash, scrub_signature_classical, \
                   scrub_signature_pqc, scrub_key_id, scrub_timestamp, pqc_completed_at, \
                   persist_row_hash, subject_key_ids, withdraws_admission_rule, cohort_scope, tier, \
                   promoted_at, additional_scrubs, admitted_at) \
                 SELECT 'p10-noise-' || lpad(n::text, 7, '0'), 'p10-att-noise', 'p10-subj-noise', \
                   'scores', 1.0, ts, NULL, \
                   json_build_object('dimension', 'p10:noise:v1')::text, \
                   '\\x00'::bytea, 'sig', NULL, 'p10-att-noise', ts, NULL, 'p10-noise-h-' || n, \
                   '[]', NULL, 'federation', 'federation', NULL, '[]', ts \
                 FROM (SELECT n, '2026-07-01T00:00:00Z'::timestamptz \
                                - make_interval(secs => n::double precision) AS ts \
                       FROM generate_series(0::bigint, $1::bigint - 1) AS n) r",
                &[&n],
            )
            .await
            .unwrap();
    }

    async fn all_rows(b: &PostgresBackend) -> Vec<Row> {
        let client = b.get_client().await.unwrap();
        client
            .query(
                "SELECT attestation_id::text, attesting_key_id, attested_key_id, dimension, \
                 asserted_at FROM cirislens.federation_attestations",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
            .collect()
    }

    #[allow(clippy::type_complexity)]
    fn shapes() -> Vec<(
        &'static str,
        crate::read::AttestationFilter,
        fn(&Row) -> bool,
    )> {
        let f = crate::read::AttestationFilter::default;
        vec![
            (
                "attester + exact dimension",
                crate::read::AttestationFilter {
                    attesting_key_id: Some(ATT_A.into()),
                    dimension_exact: Some("p10:x:v1".into()),
                    ..f()
                },
                |r| r.1 == ATT_A && r.3 == "p10:x:v1",
            ),
            (
                "subject + exact dimension",
                crate::read::AttestationFilter {
                    attested_key_id: Some("p10-subj-1".into()),
                    dimension_exact: Some("p10:y:v1".into()),
                    ..f()
                },
                |r| r.2 == "p10-subj-1" && r.3 == "p10:y:v1",
            ),
            (
                "attester + dimension prefix",
                crate::read::AttestationFilter {
                    attesting_key_id: Some(ATT_A.into()),
                    dimension_prefixes: vec!["p10:".into()],
                    ..f()
                },
                |r| r.1 == ATT_A && r.3.starts_with("p10:"),
            ),
            (
                "two attesters + exact dimension",
                crate::read::AttestationFilter {
                    attesting_key_ids: vec![ATT_A.into(), ATT_B.into()],
                    dimension_exact: Some("p10:z:v1".into()),
                    ..f()
                },
                |r| r.3 == "p10:z:v1",
            ),
            (
                "attester only",
                crate::read::AttestationFilter {
                    attesting_key_id: Some(ATT_B.into()),
                    ..f()
                },
                |r| r.1 == ATT_B,
            ),
            (
                "exact dimension only",
                crate::read::AttestationFilter {
                    dimension_exact: Some("p10:x:v1".into()),
                    ..f()
                },
                |r| r.3 == "p10:x:v1",
            ),
            ("no key", f(), |_| true),
        ]
    }

    /// The ids `keep` selects in page order (`asserted_at DESC, attestation_id
    /// DESC`; the ids differ only in digits, so every collation agrees).
    fn oracle(rows: &[Row], keep: fn(&Row) -> bool) -> Vec<String> {
        let mut v: Vec<&Row> = rows.iter().filter(|r| keep(r)).collect();
        v.sort_by(|x, y| (&y.4, &y.0).cmp(&(&x.4, &x.0)));
        v.into_iter().map(|r| r.0.clone()).collect()
    }

    async fn walk(
        b: &PostgresBackend,
        filter: &crate::read::AttestationFilter,
        page: i64,
    ) -> Vec<String> {
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let p = b
                .list_attestations(
                    filter.clone(),
                    cursor,
                    page,
                    crate::scope::CallerScope::Unauthenticated,
                )
                .await
                .unwrap();
            out.extend(p.items.into_iter().map(|a| a.attestation_id));
            match p.next_cursor {
                Some(c) => cursor = Some(c),
                None => return out,
            }
        }
    }

    /// `EXPLAIN (FORMAT JSON)` of `sql`: every `(Node Type, Index Name)`, depth
    /// first.
    async fn plan(
        client: &deadpool_postgres::Object,
        sql: &str,
        params: &Params<'_>,
    ) -> Vec<(String, Option<String>)> {
        fn walk(n: &serde_json::Value, out: &mut Vec<(String, Option<String>)>) {
            out.push((
                n["Node Type"].as_str().unwrap_or("?").to_owned(),
                n["Index Name"].as_str().map(str::to_owned),
            ));
            for c in n["Plans"].as_array().into_iter().flatten() {
                walk(c, out);
            }
        }
        let row = client
            .query_one(&format!("EXPLAIN (FORMAT JSON) {sql}"), &params[..])
            .await
            .unwrap();
        let v: serde_json::Value = row.get(0);
        let mut out = Vec::new();
        walk(&v[0]["Plan"], &mut out);
        out
    }

    /// Report only: the min of three `EXPLAIN (ANALYZE, FORMAT JSON)`
    /// execution times of `sql`, in ms, and its top plan nodes.
    async fn timed(
        client: &deadpool_postgres::Object,
        sql: &str,
        params: &Params<'_>,
    ) -> (f64, Vec<String>) {
        let mut best = f64::MAX;
        let mut nodes = Vec::new();
        for _ in 0..3 {
            let row = client
                .query_one(
                    &format!("EXPLAIN (ANALYZE, FORMAT JSON) {sql}"),
                    &params[..],
                )
                .await
                .unwrap();
            let v: serde_json::Value = row.get(0);
            best = best.min(v[0]["Execution Time"].as_f64().unwrap());
            nodes.clear();
            fn walk(n: &serde_json::Value, out: &mut Vec<String>, depth: usize) {
                if depth > 5 {
                    return;
                }
                out.push(format!(
                    "{}{}",
                    n["Node Type"].as_str().unwrap_or("?"),
                    n["Index Name"]
                        .as_str()
                        .map(|i| format!("({i})"))
                        .unwrap_or_default()
                ));
                for c in n["Plans"].as_array().into_iter().flatten().take(1) {
                    walk(c, out, depth + 1);
                }
            }
            walk(&v[0]["Plan"], &mut nodes, 0);
        }
        (best, nodes)
    }

    /// The v61.4.1 spelling of a statement: a single key bound `= ANY`.
    fn v61_4_1_spelling(sql: &str) -> String {
        sql.replacen(
            "attesting_key_id = $1 ",
            "attesting_key_id = ANY(ARRAY[$1::text]) ",
            1,
        )
        .replacen(
            "attested_key_id = $1 ",
            "attested_key_id = ANY(ARRAY[$1::text]) ",
            1,
        )
    }

    /// Report only (the FSD §6.4 numbers on postgres): every keyed shape's
    /// 1000-row page, the door's statement with V216 against the v61.4.1
    /// spelling without it.
    async fn report_pages(client: &deadpool_postgres::Object, leg: &str) {
        for (tag, filter, _) in shapes().iter().take(4) {
            let (sql, params) = pg_list_attestations_sql(
                filter,
                None,
                1000,
                &crate::scope::CallerScope::Unauthenticated,
            )
            .unwrap();
            let sql = if leg == "v61.4.1" {
                v61_4_1_spelling(&sql)
            } else {
                sql
            };
            let refs: Params<'_> = params.iter().map(|p| p.as_ref() as _).collect();
            let (ms, nodes) = timed(client, &sql, &refs).await;
            eprintln!("I1813 REPORT [{leg}] {tag}, page 1000: {ms:.2} ms, plan {nodes:?}");
        }
    }

    /// **I1813 (postgres) — one key and an exact dimension read in page order,
    /// no sort.** The adverse corpus (the FSD's proportions): 40,000 corpus rows,
    /// so one (key, dimension) slice holds 10,000, behind 200,000 newer rows of a
    /// third attester, analyzed. The attester and the subject shape each
    /// scan V216's `(key, dimension COLLATE "C", asserted_at DESC,
    /// attestation_id DESC)` under the LIMIT, page one and at a cursor: no Sort
    /// node, no Seq Scan. A single key binds as equality: `= ANY` of a
    /// one-element array does not let the planner use the index's order. With
    /// V216 dropped, the same statements sort (the corpus is the defect's).
    #[tokio::test]
    async fn i1813_one_key_exact_dimension_reads_in_page_order_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: no test postgres");
            return;
        };
        let b = PostgresBackend::connect(&dsn).await.unwrap();
        b.run_migrations().await.unwrap();
        seed(&b, 40_000).await;
        seed_noise(&b, 200_000).await;
        let client = b.get_client().await.unwrap();
        client
            .batch_execute("ANALYZE cirislens.federation_attestations")
            .await
            .unwrap();
        let cursor = crate::read::AttestationCursor::from_trailing(
            "2026-05-31T23:00:00Z".parse().unwrap(),
            "p10-0001000".into(),
        );
        for ((tag, filter, _), index) in shapes().iter().take(2).zip([
            "federation_attestations_attester_dimension_asserted",
            "federation_attestations_attested_dimension_asserted",
        ]) {
            for c in [None, Some(&cursor)] {
                let (sql, params) = pg_list_attestations_sql(
                    filter,
                    c,
                    64,
                    &crate::scope::CallerScope::Unauthenticated,
                )
                .unwrap();
                let refs: Params<'_> = params.iter().map(|p| p.as_ref() as _).collect();
                let nodes = plan(&client, &sql, &refs).await;
                let what = format!("I1813 {tag} cursor={}", c.is_some());
                eprintln!("{what} plan: {nodes:?}");
                assert!(
                    nodes.iter().any(|(t, i)| matches!(
                        t.as_str(),
                        "Index Scan" | "Index Only Scan"
                    ) && i.as_deref() == Some(index)),
                    "{what}: scans {index} in order: {nodes:?}"
                );
                assert!(
                    !nodes
                        .iter()
                        .any(|(t, _)| t == "Sort" || t == "Incremental Sort"),
                    "{what}: no sort: {nodes:?}"
                );
                assert!(
                    !nodes.iter().any(|(t, _)| t == "Seq Scan"),
                    "{what}: no table scan: {nodes:?}"
                );
            }
        }
        report_pages(&client, "v62 (V216)").await;
        // The control: without V216 the same statements sort (measured: V004's
        // attester history walked with an Incremental Sort, or V180 and a Sort).
        client
            .batch_execute(
                "DROP INDEX cirislens.federation_attestations_attester_dimension_asserted; \
                 DROP INDEX cirislens.federation_attestations_attested_dimension_asserted",
            )
            .await
            .unwrap();
        for (tag, filter, _) in shapes().iter().take(2) {
            let (sql, params) = pg_list_attestations_sql(
                filter,
                None,
                64,
                &crate::scope::CallerScope::Unauthenticated,
            )
            .unwrap();
            let refs: Params<'_> = params.iter().map(|p| p.as_ref() as _).collect();
            let nodes = plan(&client, &sql, &refs).await;
            eprintln!("I1813 control (no V216) {tag} plan: {nodes:?}");
            assert!(
                nodes
                    .iter()
                    .any(|(t, _)| t == "Sort" || t == "Incremental Sort"),
                "I1813 control {tag}: without V216 the read sorts: {nodes:?}"
            );
        }
        report_pages(&client, "v61.4.1").await;
    }

    /// **I1814 (postgres) — the same rows in the same order, ties included.**
    /// Every read shape, walked to its end through the door's cursor at a page
    /// of 7 and read as one 1000-row page, equals the ids an independent oracle
    /// selects and orders from the whole table.
    #[tokio::test]
    async fn i1814_the_page_is_the_oracles_rows_in_its_order_postgres() {
        let Some(dsn) = crate::test_pg::isolated_dsn() else {
            eprintln!("skipping: no test postgres");
            return;
        };
        let b = PostgresBackend::connect(&dsn).await.unwrap();
        b.run_migrations().await.unwrap();
        seed(&b, 2_400).await;
        let rows = all_rows(&b).await;
        assert_eq!(rows.len(), 2_400);
        for (tag, filter, keep) in shapes() {
            let want = oracle(&rows, keep);
            assert!(
                want.len() > 100,
                "I1814 {tag}: a real slice ({})",
                want.len()
            );
            assert_eq!(
                walk(&b, &filter, 7).await,
                want,
                "I1814 {tag}: walked at 7 a page"
            );
            let one: Vec<String> = b
                .list_attestations(
                    filter.clone(),
                    None,
                    1000,
                    crate::scope::CallerScope::Unauthenticated,
                )
                .await
                .unwrap()
                .items
                .into_iter()
                .map(|a| a.attestation_id)
                .collect();
            assert_eq!(
                one,
                want[..want.len().min(1000)],
                "I1814 {tag}: one 1000-row page"
            );
        }
    }
}
