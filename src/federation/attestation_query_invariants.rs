//! v56.0.0 (CIRISPersist#1001) — **I900–I904: the typed bounded read.**
//!
//! - **I900** every query shape pages to exactly the rows its predicate
//!   admits, in `(asserted_at, attestation_id)` order (newest or oldest
//!   first), across asserted-at ties, on memory, sqlite and postgres. The
//!   oracle is the fixture's own row list filtered here by hand, not the
//!   query's [`AttestationQuery::admits`].
//! - **I901** every page holds at most its limit; the cursor is `Some`
//!   exactly when another row exists (no empty trailing page); the probe
//!   records ONE read per page, carrying the query that ran.
//! - **I902** the wrapper refuses an executor that returns more than one
//!   row past the page (a backend that dropped its LIMIT), a query that pins
//!   no key, a page above [`MAX_PAGE`], and an unknown cursor version.
//! - **I903** (sqlite) every shape's statement SEEKS an index and never
//!   scans `federation_attestations`; (postgres) every statement's plan
//!   tops out in a `Limit` node.
//!
//! [`AttestationQuery::admits`]: super::attestation_query::AttestationQuery::admits
//! [`MAX_PAGE`]: super::attestation_query::MAX_PAGE

#[cfg(test)]
pub(crate) mod bodies {
    use std::num::NonZeroU32;

    use crate::federation::attestation_query::{
        AttestationQuery, AttestationQueryExec, AttestationReads, QueryRows, QueryTier,
    };
    use crate::federation::read_probe;
    use crate::federation::tier_ingest::test_support as ts;
    use crate::federation::types::attestation_type;
    use crate::federation::{Attestation, Error, FederationDirectory, SignedAttestation};

    /// One fixture row as the oracle sees it.
    #[derive(Debug, Clone)]
    pub struct Row {
        pub id: String,
        pub by: String,
        pub to: String,
        pub kind: String,
        pub dimension: Option<String>,
        pub at: chrono::DateTime<chrono::Utc>,
        pub local: bool,
    }

    /// The corpus: three keys, every type/dimension shape a query narrows
    /// on, asserted-at ties, and one local-tier row.
    pub struct Corpus {
        pub a: String,
        pub b: String,
        pub c: String,
        pub rows: Vec<Row>,
    }

    fn base() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    async fn put_scores(
        d: &dyn FederationDirectory,
        by: &str,
        to: &str,
        dimension: &str,
        minute: i64,
    ) -> Row {
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({ "dimension": dimension, "id": id });
        let mut r = ts::bare_attestation(&id, by, to, &env);
        r.attestation_type = attestation_type::SCORES.into();
        r.weight = None;
        r.asserted_at = base() + chrono::Duration::minutes(minute);
        r.scrub_timestamp = r.asserted_at;
        ts::seal_row_in_place(by, &mut r);
        land(d, r, false).await
    }

    async fn land(d: &dyn FederationDirectory, r: Attestation, local: bool) -> Row {
        let row = Row {
            id: r.attestation_id.clone(),
            by: r.attesting_key_id.clone(),
            to: r.attested_key_id.clone(),
            kind: r.attestation_type.clone(),
            dimension: crate::federation::admission::envelope_dimension(&r.attestation_envelope)
                .map(str::to_owned),
            at: r.asserted_at,
            local,
        };
        d.put_attestation(SignedAttestation { attestation: r })
            .await
            .expect("I900 fixture row lands");
        row
    }

    /// Seed the corpus on `d`; `s` keeps keys unique per run (postgres
    /// shares a database across the runners).
    pub async fn seed(d: &dyn FederationDirectory, s: &str) -> Corpus {
        let a = format!("i900-a-{s}");
        let b = format!("i900-b-{s}");
        let c = format!("i900-c-{s}");
        for k in [&a, &b, &c] {
            ts::register_hybrid_key(d, k).await;
        }
        let mut rows = Vec::new();
        // One live row per (subject, leaf): a second needs a `supersedes`.
        // A about A: three config:a* leaves (two tied), two config:b*
        // leaves (one tied with an A→B row), other:x.
        rows.push(put_scores(d, &a, &a, "config:a:v1", -60).await);
        rows.push(put_scores(d, &a, &a, "config:a2:v1", -50).await);
        rows.push(put_scores(d, &a, &a, "config:a3:v1", -50).await);
        rows.push(put_scores(d, &a, &a, "config:b:v1", -40).await);
        rows.push(put_scores(d, &a, &a, "config:b2:v1", -30).await);
        rows.push(put_scores(d, &a, &a, "other:x:v1", -20).await);
        // A about B and C, one tied with A's config:b2.
        rows.push(put_scores(d, &a, &b, "config:a:v1", -30).await);
        rows.push(put_scores(d, &a, &b, "config:ab:v1", -10).await);
        rows.push(put_scores(d, &a, &c, "config:a:v1", -25).await);
        // B about A.
        rows.push(put_scores(d, &b, &a, "config:c:v1", -45).await);
        rows.push(put_scores(d, &b, &a, "config:c2:v1", -5).await);
        // C noise.
        for (leaf, m) in [
            ("config:a:v1", -55),
            ("config:a2:v1", -35),
            ("config:a3:v1", -15),
        ] {
            rows.push(put_scores(d, &c, &c, leaf, m).await);
        }
        // A withdraws its oldest config:a row: a composer with no dimension.
        let target = rows[0].id.clone();
        let id = uuid::Uuid::new_v4().to_string();
        let env = serde_json::json!({ "id": id, "references_attestation_id": target });
        let mut w = ts::bare_attestation(&id, &a, &a, &env);
        w.attestation_type = attestation_type::WITHDRAWS.into();
        w.asserted_at = base() - chrono::Duration::minutes(1);
        w.scrub_timestamp = w.asserted_at;
        ts::seal_row_in_place(&a, &mut w);
        rows.push(land(d, w, false).await);
        // One local-tier row by A.
        let local_id = d
            .attestation_insert_local(crate::federation::types::LocalAttestationInput {
                attestation_id: None,
                attesting_key_id: a.clone(),
                attested_key_id: None,
                attestation_type: attestation_type::SCORES.to_owned(),
                weight: None,
                expires_at: None,
                attestation_envelope: crate::federation::envelope::EnvelopeCore::from_value(
                    serde_json::json!({ "dimension": "config:a:v1" }),
                )
                .unwrap(),
                subject_key_ids: vec![],
                cohort_scope: crate::federation::types::cohort_scope::SELF.to_owned(),
                scrub_signature_classical: None,
                scrub_signature_pqc: None,
            })
            .await
            .expect("I900 local row lands");
        // The local row's instant is the door's; read it back through the
        // query itself (the only by-A local row) so the oracle orders it.
        let local = d
            .query_attestations(&AttestationQuery::by(&a, NonZeroU32::MIN).tier(QueryTier::Local))
            .await
            .expect("local read")
            .rows;
        assert_eq!(local.len(), 1, "I900 one local row");
        assert_eq!(local[0].attestation_id, local_id);
        rows.push(Row {
            id: local_id,
            by: a.clone(),
            to: a.clone(),
            kind: attestation_type::SCORES.into(),
            dimension: Some("config:a:v1".into()),
            at: local[0].asserted_at,
            local: true,
        });
        let _ = read_probe::take();
        Corpus { a, b, c, rows }
    }

    /// The oracle: a hand-written filter per shape, then the order.
    fn expect(corpus: &Corpus, keep: impl Fn(&Row) -> bool, oldest_first: bool) -> Vec<String> {
        let mut rows: Vec<&Row> = corpus.rows.iter().filter(|r| keep(r)).collect();
        rows.sort_by(|x, y| (x.at, x.id.as_str()).cmp(&(y.at, y.id.as_str())));
        if !oldest_first {
            rows.reverse();
        }
        rows.into_iter().map(|r| r.id.clone()).collect()
    }

    /// Every shape the plane migrations use, with its oracle.
    pub fn shapes(corpus: &Corpus) -> Vec<(&'static str, AttestationQuery, Vec<String>)> {
        let (a, b) = (corpus.a.as_str(), corpus.b.as_str());
        let lim = NonZeroU32::MIN;
        let fed = |r: &Row| !r.local;
        let dim = |r: &Row, p: &str| r.dimension.as_deref().is_some_and(|d| d.starts_with(p));
        let mut out = Vec::new();
        for oldest in [false, true] {
            let o = |q: AttestationQuery| if oldest { q.oldest_first() } else { q };
            out.push((
                "by A",
                o(AttestationQuery::by(a, lim)),
                expect(corpus, |r| fed(r) && r.by == a, oldest),
            ));
            out.push((
                "to A",
                o(AttestationQuery::to(a, lim)),
                expect(corpus, |r| fed(r) && r.to == a, oldest),
            ));
            out.push((
                "by A, prefix config:",
                o(AttestationQuery::by(a, lim).dimension_prefix("config:")),
                expect(corpus, |r| fed(r) && r.by == a && dim(r, "config:"), oldest),
            ));
            out.push((
                "by A, exact config:a:v1",
                o(AttestationQuery::by(a, lim).dimension("config:a:v1")),
                expect(
                    corpus,
                    |r| fed(r) && r.by == a && r.dimension.as_deref() == Some("config:a:v1"),
                    oldest,
                ),
            ));
            out.push((
                "to A authored by B",
                o(AttestationQuery::to(a, lim).authored_by(b)),
                expect(corpus, |r| fed(r) && r.to == a && r.by == b, oldest),
            ));
            out.push((
                "by A, withdraws",
                o(AttestationQuery::by(a, lim).types(&[attestation_type::WITHDRAWS])),
                expect(
                    corpus,
                    |r| fed(r) && r.by == a && r.kind == attestation_type::WITHDRAWS,
                    oldest,
                ),
            ));
            out.push((
                "by A, withdraws+scores excluding config:a:v1",
                o(AttestationQuery::by(a, lim)
                    .types(&[attestation_type::SCORES, attestation_type::WITHDRAWS])
                    .excluding_dimensions(&["config:a:v1"])),
                expect(
                    corpus,
                    |r| fed(r) && r.by == a && r.dimension.as_deref() != Some("config:a:v1"),
                    oldest,
                ),
            ));
            out.push((
                "by A excluding config:a:v1 (no type)",
                o(AttestationQuery::by(a, lim).excluding_dimensions(&["config:a:v1"])),
                expect(
                    corpus,
                    |r| fed(r) && r.by == a && r.dimension.as_deref() != Some("config:a:v1"),
                    oldest,
                ),
            ));
            out.push((
                "to B by A prefix config:a",
                o(AttestationQuery::to(b, lim)
                    .authored_by(a)
                    .dimension_prefix("config:a")),
                expect(
                    corpus,
                    |r| fed(r) && r.to == b && r.by == a && dim(r, "config:a"),
                    oldest,
                ),
            ));
            out.push((
                "local by A",
                o(AttestationQuery::by(a, lim).tier(QueryTier::Local)),
                expect(corpus, |r| r.local && r.by == a, oldest),
            ));
        }
        out
    }

    /// Page `q` through `d` with page size `limit`, asserting the page
    /// contract on the way; returns the ids in order.
    async fn page_through(
        d: &dyn FederationDirectory,
        mut q: AttestationQuery,
        limit: u32,
        want: usize,
        tag: &str,
    ) -> Vec<String> {
        q.limit = NonZeroU32::new(limit).unwrap();
        let mut got = Vec::new();
        // A cursor the backend ignored would repeat page one forever.
        let guard = want / limit as usize + 2;
        for i in 0.. {
            assert!(
                i < guard,
                "I901 {tag}: more pages than rows allow (cursor ignored?)"
            );
            let _ = read_probe::take();
            let page = d.query_attestations(&q).await.expect("page");
            let log = read_probe::take();
            assert!(
                page.rows.len() <= limit as usize,
                "I901 {tag}: page of {} over limit {limit}",
                page.rows.len()
            );
            assert_eq!(log.len(), 1, "I901 {tag}: one probe read per page: {log:?}");
            assert_eq!(
                log[0].query.as_ref().map(|q| q.limit.get()),
                Some(limit),
                "I901 {tag}: the probe carries the query that ran"
            );
            assert_eq!(log[0].rows, page.rows.len());
            got.extend(page.rows.iter().map(|r| r.attestation_id.clone()));
            match page.next {
                Some(c) => {
                    assert!(
                        got.len() < want,
                        "I901 {tag}: a cursor after the last row (empty trailing page)"
                    );
                    q.after = Some(c);
                }
                None => break,
            }
        }
        got
    }

    /// **I900 + I901** — every shape, page sizes 1..=4 and one page holding
    /// everything, both orders.
    pub async fn i900_every_shape_pages_to_its_oracle(d: &dyn FederationDirectory, s: &str) {
        let corpus = seed(d, s).await;
        let shapes = shapes(&corpus);
        assert!(
            shapes.iter().all(|(_, _, w)| !w.is_empty()),
            "I900 no empty shape"
        );
        for (tag, q, want) in &shapes {
            for limit in [1, 2, 3, 4, 50] {
                let got = page_through(d, q.clone(), limit, want.len(), tag).await;
                assert_eq!(&got, want, "I900 {tag} (limit {limit}, {:?})", q.order);
            }
        }
        // The narrowing is a real narrowing: the C noise and the B slice are
        // never in A's pages.
        let all_a = page_through(
            d,
            AttestationQuery::by(&corpus.a, NonZeroU32::MIN),
            50,
            99,
            "x",
        )
        .await;
        for r in corpus.rows.iter().filter(|r| r.by != corpus.a) {
            assert!(!all_a.contains(&r.id), "I900 {} is not A's", r.id);
        }
        let _ = &corpus.c;
    }

    /// An executor that returns one more row than the page allows past the
    /// fetch: a backend that dropped its LIMIT.
    struct Overreturning<'a>(&'a dyn FederationDirectory);

    #[async_trait::async_trait]
    impl AttestationQueryExec for Overreturning<'_> {
        async fn run_attestation_query(&self, q: &AttestationQuery) -> Result<QueryRows, Error> {
            let mut wide = q.clone();
            wide.limit = NonZeroU32::new(q.limit.get() + 5).unwrap();
            self.0.execute_attestation_query(&wide).await
        }
    }

    /// **I902** — the wrapper's refusals.
    pub async fn i902_the_wrapper_refuses_what_no_backend_may_run(
        d: &dyn FederationDirectory,
        s: &str,
    ) {
        let corpus = seed(d, s).await;
        let q = AttestationQuery::by(&corpus.a, NonZeroU32::MIN);
        match Overreturning(d).query_attestations(&q).await {
            Err(Error::Backend(m)) => assert!(m.contains("past its page"), "{m}"),
            other => panic!("I902 an over-returning executor is refused, got {other:?}"),
        }
        let mut unpinned = q.clone();
        unpinned.by = None;
        assert!(matches!(
            d.query_attestations(&unpinned).await,
            Err(Error::InvalidArgument(_))
        ));
        let mut huge = q.clone();
        huge.limit = NonZeroU32::new(crate::federation::attestation_query::MAX_PAGE + 1).unwrap();
        assert!(matches!(
            d.query_attestations(&huge).await,
            Err(Error::InvalidArgument(_))
        ));
        let page = d.query_attestations(&q).await.unwrap();
        let mut c = page.next.expect("A has more than one row");
        c.version = "v0".into();
        assert!(matches!(
            d.query_attestations(&q.clone().after(Some(c))).await,
            Err(Error::InvalidArgument(_))
        ));
    }
}

#[cfg(test)]
mod runners {
    fn suffix() -> String {
        uuid::Uuid::new_v4().simple().to_string()[..12].to_owned()
    }

    macro_rules! runners {
        ($modname:ident, $fresh:expr) => {
            mod $modname {
                use super::suffix;
                use crate::federation::FederationDirectory;
                #[tokio::test]
                async fn i900_every_shape_pages_to_its_oracle() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i900_every_shape_pages_to_its_oracle(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
                #[tokio::test]
                async fn i902_the_wrapper_refuses_what_no_backend_may_run() {
                    let Some(d) = $fresh.await else { return };
                    super::super::bodies::i902_the_wrapper_refuses_what_no_backend_may_run(
                        &d as &dyn FederationDirectory,
                        &suffix(),
                    )
                    .await
                }
            }
        };
    }

    runners!(memory, async {
        Some(crate::store::memory::MemoryBackend::new())
    });

    #[cfg(feature = "sqlite")]
    runners!(sqlite, async {
        use crate::store::Backend as _;
        let b = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    #[cfg(feature = "postgres")]
    runners!(postgres, async {
        use crate::store::Backend as _;
        let dsn = crate::test_pg::empty_dsn()?;
        let b = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        b.run_migrations().await.unwrap();
        Some(b)
    });

    /// **I903** (sqlite) — every shape's statement seeks an index; none
    /// scans the table.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn i903_sqlite_every_shape_seeks_an_index() {
        use crate::federation::attestation_query::{render_sql, Bind, Dialect};
        use crate::store::Backend as _;
        let d = crate::store::sqlite::SqliteBackend::open_in_memory()
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        let corpus = super::bodies::seed(&d, &suffix()).await;
        let mut shapes = super::bodies::shapes(&corpus);
        // And one with a cursor.
        let mut q = shapes[0].1.clone();
        q.after = Some(
            crate::ceg::list::federation::AttestationCursor::from_trailing(
                chrono::Utc::now(),
                "x".into(),
            ),
        );
        shapes.push(("cursor", q, vec![]));
        for (tag, q, _) in shapes {
            let stmt = render_sql(
                &q,
                Dialect::Sqlite,
                "federation_attestations",
                "attestation_id",
            );
            assert!(
                stmt.sql.contains(" LIMIT ?"),
                "I903 {tag}: one LIMIT: {}",
                stmt.sql
            );
            let binds: Vec<rusqlite::types::Value> = stmt
                .binds
                .into_iter()
                .map(|b| match b {
                    Bind::Text(t) => rusqlite::types::Value::Text(t),
                    Bind::Time(t) => rusqlite::types::Value::Text(t.to_rfc3339()),
                    Bind::Int(n) => rusqlite::types::Value::Integer(n),
                })
                .collect();
            let sql = format!("EXPLAIN QUERY PLAN {}", stmt.sql);
            let plan: Vec<String> = d
                .read(move |conn| -> Vec<String> {
                    let mut st = conn.prepare(&sql).unwrap();
                    st.query_map(rusqlite::params_from_iter(binds.iter()), |r| {
                        r.get::<_, String>(3)
                    })
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
                })
                .await;
            assert!(
                plan.iter()
                    .any(|l| l.starts_with("SEARCH federation_attestations USING INDEX")),
                "I903 {tag}: seeks an index: {plan:?}"
            );
            assert!(
                !plan
                    .iter()
                    .any(|l| l.starts_with("SCAN federation_attestations")),
                "I903 {tag}: never scans the table: {plan:?}"
            );
            // A narrowed shape seeks the narrow index, not the key's
            // asserted_at-ordered slice.
            if q.seeks_narrow_index() {
                assert!(
                    !plan
                        .iter()
                        .any(|l| l.contains("federation_attestations_attesting (")
                            || l.contains("federation_attestations_attested (")),
                    "I903 {tag}: a narrowed shape does not walk the key's whole slice: {plan:?}"
                );
            }
        }
    }

    /// **I903** (postgres) — every shape's plan is topped by a `Limit`.
    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn i903_postgres_every_shape_is_limited() {
        use crate::federation::attestation_query::{render_sql, Bind, Dialect};
        use crate::store::Backend as _;
        let Some(dsn) = crate::test_pg::empty_dsn() else {
            return;
        };
        let d = crate::store::postgres::PostgresBackend::connect(&dsn)
            .await
            .unwrap();
        d.run_migrations().await.unwrap();
        let corpus = super::bodies::seed(&d, &suffix()).await;
        let client = d.get_client().await.unwrap();
        for (tag, q, _) in super::bodies::shapes(&corpus) {
            let stmt = render_sql(
                &q,
                Dialect::Postgres,
                "cirislens.federation_attestations",
                "attestation_id::text",
            );
            let params: Vec<Box<dyn tokio_postgres::types::ToSql + Sync + Send>> = stmt
                .binds
                .into_iter()
                .map(|b| -> Box<dyn tokio_postgres::types::ToSql + Sync + Send> {
                    match b {
                        Bind::Text(t) => Box::new(t),
                        Bind::Time(t) => Box::new(t),
                        Bind::Int(n) => Box::new(n),
                    }
                })
                .collect();
            let refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
                params.iter().map(|p| p.as_ref() as _).collect();
            let plan: Vec<String> = client
                .query(&format!("EXPLAIN {}", stmt.sql), &refs[..])
                .await
                .unwrap()
                .iter()
                .map(|r| r.get::<_, String>(0))
                .collect();
            assert!(
                plan.first().is_some_and(|l| l.starts_with("Limit")),
                "I903 {tag}: the plan is limited: {plan:?}"
            );
        }
    }
}
